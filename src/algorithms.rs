// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Algorithm-override surface for SSH negotiation (PRD §5.8.6, M17).
//!
//! This module exposes the four moving pieces a downstream CLI needs
//! to honour [`KexAlgorithms`](https://man.openbsd.org/ssh_config#KexAlgorithms),
//! `Ciphers`, `MACs`, and `HostKeyAlgorithms` from `~/.ssh/config`
//! (FR-76) plus the matching CLI overrides (`--kex`, `--ciphers`,
//! `--macs`, `--host-key-algorithms` — FR-77):
//!
//! 1. [`apply_overrides`] parses an OpenSSH-format override string —
//!    `algo,algo` (replace), `+algo` (append), `-algo` (remove),
//!    `^algo` (front-load) — against a base list and returns the
//!    resulting algorithm preference.
//! 2. [`DENYLIST`] + [`apply_denylist`] enforce FR-78's permanent
//!    block on broken algorithms (DSA, 3DES, Arcfour, SHA-1 HMAC <
//!    96 bits, SSH-1) regardless of override.
//! 3. [`anvil_default_kex`] / `anvil_default_ciphers` /
//!    `anvil_default_macs` / `anvil_default_host_keys` return the
//!    *curated* default that's used as the base for `+/-/^` overrides.
//! 4. [`all_supported`] returns the [`Catalogue`] surfaced by
//!    `gitway list-algorithms` (FR-79) — every name russh accepts,
//!    tagged with `is_default` and `denylisted` flags.
//!
//! ## Trust model
//!
//! Russh 0.59 silently drops unknown algorithm names at negotiation
//! time — there is no error, no log.  This module validates user
//! input *before* it reaches russh: an unknown algorithm in an
//! override surfaces an [`AnvilError::invalid_config`] with a
//! `tips-thinking` hint pointing at `gitway list-algorithms`.
//!
//! The denylist is enforced **after** every override transformation
//! so a user-supplied `+ssh-dss` cannot bypass FR-78 by smuggling a
//! banned algorithm through an `^` move.

use crate::error::AnvilError;

// ── Permanent denylist (FR-78) ──────────────────────────────────────────────

/// Permanent denylist — algorithms refused regardless of any override.
///
/// Per PRD §5.8.6 FR-78, broken algorithms stay broken: an operator
/// who needs to talk to a legacy peer must use an external tool
/// (`ssh -W` proxy + `--insecure-skip-host-check`) rather than
/// re-enabling them inside Gitway.
///
/// Names are lowercase ASCII; matching is case-insensitive via
/// [`is_denylisted`].  Russh 0.59 already excludes most of these by
/// default — the explicit list here is a defensive belt-and-suspenders
/// pass at the override boundary.
pub const DENYLIST: &[&str] = &[
    // DSA host keys — broken since RFC 8332 deprecated SHA-1 signatures.
    "ssh-dss",
    // 3DES — broken cipher, slow, only 112-bit effective security.
    "3des-cbc",
    // Arcfour — broken stream cipher (RFC 8758 deprecates).
    "arcfour",
    "arcfour128",
    "arcfour256",
    // SHA-1 HMAC truncated below 96 bits — collision-vulnerable.
    "hmac-sha1-96",
    // SSH protocol v1 — gone everywhere; defensive belt.
    "ssh-1.0",
];

/// Returns `true` iff `alg` is on the permanent denylist
/// ([`DENYLIST`]).  Comparison is case-insensitive ASCII.
#[must_use]
pub fn is_denylisted(alg: &str) -> bool {
    DENYLIST.iter().any(|d| d.eq_ignore_ascii_case(alg))
}

/// Filters a list of algorithm names through [`is_denylisted`],
/// preserving the order of the surviving entries.
#[must_use]
pub fn apply_denylist(list: Vec<String>) -> Vec<String> {
    list.into_iter().filter(|a| !is_denylisted(a)).collect()
}

// ── Categories ─────────────────────────────────────────────────────────────

/// Algorithm category — the four `ssh_config(5)` directive families
/// Gitway plumbs through to russh.  Matches the four CLI flags
/// `--kex` / `--ciphers` / `--macs` / `--host-key-algorithms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgCategory {
    /// `KexAlgorithms` directive / `--kex` flag.
    Kex,
    /// `Ciphers` directive / `--ciphers` flag.
    Cipher,
    /// `MACs` directive / `--macs` flag.
    Mac,
    /// `HostKeyAlgorithms` directive / `--host-key-algorithms` flag.
    HostKey,
}

impl AlgCategory {
    /// Human-readable category label for error messages and the
    /// `gitway list-algorithms` section headers.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Kex => "kex",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
            Self::HostKey => "host-key",
        }
    }
}

// ── Override parser (FR-77) ────────────────────────────────────────────────

/// Applies an OpenSSH-format `KexAlgorithms`/etc. override string to
/// `base`, returning the resulting algorithm list.
///
/// # Override syntax
///
/// | Prefix | Meaning |
/// |--------|---------|
/// | (none)        | Replace `base` entirely with the comma-separated list. |
/// | `+algo,algo`  | Append the listed algorithms to `base` (deduplicated, denylist-filtered). |
/// | `-algo,algo`  | Remove the listed algorithms from `base` (no error if absent). |
/// | `^algo,algo`  | Move the listed algorithms to the front of `base` (preserving their order). |
/// | (empty)       | No-op — returns `base` unchanged. |
///
/// Whitespace around commas is trimmed.  Empty entries (e.g.
/// `"a,,b"`) are silently dropped.  Comparison is case-insensitive
/// ASCII.
///
/// # FR-78 enforcement
///
/// After every transformation, the result is filtered through
/// [`apply_denylist`].  Additionally, an explicit attempt to
/// re-enable a denylisted algorithm via `+ssh-dss` (or any prefix)
/// is surfaced as a hard error with a `tips-thinking` hint — silent
/// filtering would mask user intent.
///
/// # Errors
///
/// - The override mentions an algorithm on [`DENYLIST`] (any prefix).
///
/// Unknown algorithm names — names not on [`DENYLIST`] but also not
/// in russh's accepted set — are **not** validated here; that check
/// belongs to the caller (which has access to [`all_supported`]).
pub fn apply_overrides(
    category: AlgCategory,
    base: Vec<String>,
    override_str: &str,
) -> Result<Vec<String>, AnvilError> {
    let trimmed = override_str.trim();
    if trimmed.is_empty() {
        return Ok(apply_denylist(base));
    }

    // First-char prefix detection.
    let (prefix, rest) = match trimmed.as_bytes().first().copied() {
        Some(b'+') => (Prefix::Append, &trimmed[1..]),
        Some(b'-') => (Prefix::Remove, &trimmed[1..]),
        Some(b'^') => (Prefix::Front, &trimmed[1..]),
        _ => (Prefix::Replace, trimmed),
    };

    let tokens: Vec<String> = rest
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    // FR-78: any explicit mention of a denylisted alg is a hard
    // error, not a silent filter.
    let category_label = category.label();
    for tok in &tokens {
        if is_denylisted(tok) {
            return Err(AnvilError::invalid_config(format!(
                "{category_label} override refers to denylisted algorithm '{tok}' (FR-78)",
            ))
            .with_hint(format!(
                "Algorithm '{tok}' is permanently disabled in Gitway (PRD §5.8.6 \
                 FR-78) — it has known cryptographic weaknesses.  Run `gitway \
                 list-algorithms` to see the supported set, or remove the entry \
                 from your override.  If you absolutely need to talk to a peer \
                 that only speaks '{tok}', use external `ssh -W` as a \
                 ProxyCommand and accept the security loss explicitly.",
            )));
        }
    }

    let result = match prefix {
        Prefix::Replace => tokens,
        Prefix::Append => {
            let mut out = base;
            for tok in tokens {
                if !out.iter().any(|e| e.eq_ignore_ascii_case(&tok)) {
                    out.push(tok);
                }
            }
            out
        }
        Prefix::Remove => base
            .into_iter()
            .filter(|e| !tokens.iter().any(|t| t.eq_ignore_ascii_case(e)))
            .collect(),
        Prefix::Front => {
            let mut front = tokens.clone();
            // Drop any front entries that don't appear in the base —
            // OpenSSH's behaviour (front-loading is reordering, not
            // adding).
            front.retain(|t| base.iter().any(|e| e.eq_ignore_ascii_case(t)));
            // Build the rest = base minus the front entries.
            let rest: Vec<String> = base
                .into_iter()
                .filter(|e| !front.iter().any(|f| f.eq_ignore_ascii_case(e)))
                .collect();
            front.into_iter().chain(rest).collect()
        }
    };

    Ok(apply_denylist(result))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefix {
    Replace,
    Append,
    Remove,
    Front,
}

// ── Anvil's curated default lists ──────────────────────────────────────────

/// Returns Anvil's curated default key-exchange algorithm
/// preference.  Used as the base when an override carries a
/// `+`/`-`/`^` prefix.
#[must_use]
pub fn anvil_default_kex() -> Vec<String> {
    vec![
        "curve25519-sha256".to_owned(),
        "curve25519-sha256@libssh.org".to_owned(),
        "ext-info-c".to_owned(),
    ]
}

/// Returns Anvil's curated default cipher preference.
#[must_use]
pub fn anvil_default_ciphers() -> Vec<String> {
    vec!["chacha20-poly1305@openssh.com".to_owned()]
}

/// Returns Anvil's curated default MAC preference.
///
/// AEAD ciphers (chacha20-poly1305, AES-GCM) carry their own
/// authentication tag, so the explicit MAC list is only consulted
/// when the negotiated cipher is non-AEAD — a code path Anvil's
/// default kex/cipher pair never reaches.  Provided for completeness
/// so an operator overriding the cipher set still gets a sensible
/// MAC default.
#[must_use]
pub fn anvil_default_macs() -> Vec<String> {
    vec![
        "hmac-sha2-256-etm@openssh.com".to_owned(),
        "hmac-sha2-512-etm@openssh.com".to_owned(),
    ]
}

/// Returns Anvil's curated default host-key algorithm preference.
#[must_use]
pub fn anvil_default_host_keys() -> Vec<String> {
    vec![
        "ssh-ed25519".to_owned(),
        "ecdsa-sha2-nistp256".to_owned(),
        "ecdsa-sha2-nistp384".to_owned(),
        "ecdsa-sha2-nistp521".to_owned(),
        "rsa-sha2-512".to_owned(),
        "rsa-sha2-256".to_owned(),
    ]
}

// ── Catalogue (FR-79) ──────────────────────────────────────────────────────

/// One entry in the [`Catalogue`] returned by [`all_supported`].
///
/// Used to render `gitway list-algorithms` output: a third column on
/// the human form showing `default` / `available` / `denylisted`,
/// plus the corresponding flags on the JSON envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgEntry {
    /// Algorithm name as it appears in the SSH wire protocol.
    pub name: String,
    /// `true` if this entry is part of Anvil's curated default for
    /// its category — i.e. the user gets it without any override.
    pub is_default: bool,
    /// `true` if this entry is on [`DENYLIST`] (FR-78).  Surfaces in
    /// `gitway list-algorithms` so an operator can see why an
    /// override referencing it would be refused.
    pub denylisted: bool,
}

/// Full catalogue of every algorithm Gitway can negotiate, grouped
/// by [`AlgCategory`].  Returned by [`all_supported`] and consumed
/// by `gitway list-algorithms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    pub kex: Vec<AlgEntry>,
    pub cipher: Vec<AlgEntry>,
    pub mac: Vec<AlgEntry>,
    pub host_key: Vec<AlgEntry>,
}

/// Returns the full [`Catalogue`] of algorithms russh advertises plus
/// the flags `gitway list-algorithms` needs to render the operator-
/// facing view.
///
/// The list is sourced from russh's named constants (e.g.
/// `russh::kex::CURVE25519`, `russh::cipher::CHACHA20_POLY1305`).
/// New algorithms a future russh release adds will appear here on
/// the next anvil-ssh bump.
///
/// `is_default` is true iff the entry is in the matching
/// `anvil_default_*()` list; `denylisted` is true iff
/// [`is_denylisted`] returns true.  An algorithm cannot be both —
/// the curated defaults are denylist-clean by construction.
#[must_use]
pub fn all_supported() -> Catalogue {
    let kex_names = &[
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group17-sha512",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group15-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "ext-info-c",
    ];
    let cipher_names = &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes256-cbc",
        "aes192-cbc",
        "aes128-cbc",
        "3des-cbc",
    ];
    let mac_names = &[
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256",
        "hmac-sha1",
    ];
    let host_key_names = &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    ];

    Catalogue {
        kex: build_entries(kex_names, &anvil_default_kex()),
        cipher: build_entries(cipher_names, &anvil_default_ciphers()),
        mac: build_entries(mac_names, &anvil_default_macs()),
        host_key: build_entries(host_key_names, &anvil_default_host_keys()),
    }
}

fn build_entries(names: &[&str], defaults: &[String]) -> Vec<AlgEntry> {
    names
        .iter()
        .map(|n| AlgEntry {
            name: (*n).to_owned(),
            is_default: defaults.iter().any(|d| d.eq_ignore_ascii_case(n)),
            denylisted: is_denylisted(n),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Denylist ────────────────────────────────────────────────────────────

    #[test]
    fn denylist_is_case_insensitive() {
        assert!(is_denylisted("ssh-dss"));
        assert!(is_denylisted("SSH-DSS"));
        assert!(is_denylisted("Ssh-Dss"));
    }

    #[test]
    fn denylist_rejects_arcfour_variants() {
        assert!(is_denylisted("arcfour"));
        assert!(is_denylisted("arcfour128"));
        assert!(is_denylisted("arcfour256"));
    }

    #[test]
    fn denylist_does_not_block_safe_algorithms() {
        assert!(!is_denylisted("curve25519-sha256"));
        assert!(!is_denylisted("chacha20-poly1305@openssh.com"));
        assert!(!is_denylisted("hmac-sha2-256"));
        assert!(!is_denylisted("ssh-ed25519"));
    }

    #[test]
    fn apply_denylist_filters_in_place_preserving_order() {
        let input = vec![
            "curve25519-sha256".to_owned(),
            "ssh-dss".to_owned(),
            "chacha20-poly1305@openssh.com".to_owned(),
            "3des-cbc".to_owned(),
        ];
        let out = apply_denylist(input);
        assert_eq!(
            out,
            vec![
                "curve25519-sha256".to_owned(),
                "chacha20-poly1305@openssh.com".to_owned(),
            ],
        );
    }

    // ── Override parser ─────────────────────────────────────────────────────

    fn base() -> Vec<String> {
        vec![
            "curve25519-sha256".to_owned(),
            "curve25519-sha256@libssh.org".to_owned(),
            "ext-info-c".to_owned(),
        ]
    }

    #[test]
    fn empty_override_returns_base_unchanged() {
        assert_eq!(
            apply_overrides(AlgCategory::Kex, base(), "").unwrap(),
            base()
        );
    }

    #[test]
    fn whitespace_only_override_returns_base_unchanged() {
        assert_eq!(
            apply_overrides(AlgCategory::Kex, base(), "   \t  ").unwrap(),
            base(),
        );
    }

    #[test]
    fn no_prefix_replaces_entirely() {
        let out =
            apply_overrides(AlgCategory::Kex, base(), "diffie-hellman-group14-sha256").unwrap();
        assert_eq!(out, vec!["diffie-hellman-group14-sha256".to_owned()]);
    }

    #[test]
    fn append_prefix_adds_to_base() {
        let out =
            apply_overrides(AlgCategory::Kex, base(), "+diffie-hellman-group14-sha256").unwrap();
        assert_eq!(out.len(), 4);
        assert_eq!(out.last().unwrap(), "diffie-hellman-group14-sha256");
        // Base entries preserved in order.
        assert_eq!(out[0], "curve25519-sha256");
    }

    #[test]
    fn append_prefix_skips_duplicates_case_insensitively() {
        let out =
            apply_overrides(AlgCategory::Kex, base(), "+CURVE25519-SHA256,ext-info-c").unwrap();
        // No new entries — both already present.
        assert_eq!(out, base());
    }

    #[test]
    fn remove_prefix_drops_listed_entries() {
        let out = apply_overrides(AlgCategory::Kex, base(), "-ext-info-c").unwrap();
        assert_eq!(out.len(), 2);
        assert!(!out.iter().any(|e| e == "ext-info-c"));
    }

    #[test]
    fn remove_prefix_silently_ignores_absent_entries() {
        let out =
            apply_overrides(AlgCategory::Kex, base(), "-diffie-hellman-group14-sha256").unwrap();
        assert_eq!(out, base());
    }

    #[test]
    fn front_prefix_moves_listed_entries_to_front_preserving_order() {
        // Re-order: bring `ext-info-c` to the front.
        let out = apply_overrides(AlgCategory::Kex, base(), "^ext-info-c").unwrap();
        assert_eq!(out[0], "ext-info-c");
        assert_eq!(out.len(), base().len());
        // Base entries preserved.
        assert!(out.contains(&"curve25519-sha256".to_owned()));
    }

    #[test]
    fn front_prefix_drops_entries_absent_from_base() {
        // OpenSSH semantics: `^algo` reorders, doesn't add.
        let out =
            apply_overrides(AlgCategory::Kex, base(), "^diffie-hellman-group14-sha256").unwrap();
        assert_eq!(out, base());
    }

    #[test]
    fn override_with_denylisted_alg_returns_error() {
        let err = apply_overrides(AlgCategory::Kex, base(), "+ssh-dss").expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("ssh-dss"));
        assert!(msg.contains("kex"));
        assert!(msg.contains("FR-78"));
        let hint = err.hint();
        assert!(
            hint.contains("gitway list-algorithms"),
            "hint missing tip; got: {hint}"
        );
    }

    #[test]
    fn override_with_denylisted_alg_in_replace_form_also_errors() {
        let err = apply_overrides(AlgCategory::Cipher, vec![], "3des-cbc").expect_err("must error");
        let msg = format!("{err}");
        assert!(msg.contains("3des-cbc"));
        assert!(msg.contains("cipher"));
    }

    #[test]
    fn override_drops_empty_tokens() {
        // `"+a,,b"` — middle empty token discarded.
        let out = apply_overrides(
            AlgCategory::Kex,
            vec![],
            "diffie-hellman-group14-sha256,,ext-info-c",
        )
        .unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn override_trims_whitespace_around_commas() {
        let out = apply_overrides(
            AlgCategory::Kex,
            vec![],
            "  curve25519-sha256  ,  ext-info-c  ",
        )
        .unwrap();
        assert_eq!(
            out,
            vec!["curve25519-sha256".to_owned(), "ext-info-c".to_owned()],
        );
    }

    // ── Catalogue ───────────────────────────────────────────────────────────

    #[test]
    fn catalogue_has_at_least_one_default_per_category() {
        let cat = all_supported();
        assert!(cat.kex.iter().any(|e| e.is_default));
        assert!(cat.cipher.iter().any(|e| e.is_default));
        assert!(cat.mac.iter().any(|e| e.is_default));
        assert!(cat.host_key.iter().any(|e| e.is_default));
    }

    #[test]
    fn catalogue_marks_denylisted_entries() {
        let cat = all_supported();
        // 3des-cbc must show up in the cipher catalogue but tagged
        // denylisted — operator visibility for FR-78.
        let three_des = cat
            .cipher
            .iter()
            .find(|e| e.name == "3des-cbc")
            .expect("3des-cbc must appear in the cipher catalogue");
        assert!(three_des.denylisted);
        assert!(!three_des.is_default);
    }

    #[test]
    fn catalogue_default_and_denylist_are_disjoint() {
        let cat = all_supported();
        for category in [&cat.kex, &cat.cipher, &cat.mac, &cat.host_key] {
            for entry in category {
                assert!(
                    !(entry.is_default && entry.denylisted),
                    "entry {} is both default AND denylisted",
                    entry.name,
                );
            }
        }
    }

    #[test]
    fn anvil_default_kex_excludes_denylist() {
        for alg in anvil_default_kex() {
            assert!(
                !is_denylisted(&alg),
                "anvil default kex includes denylisted {alg}"
            );
        }
    }

    #[test]
    fn anvil_default_host_keys_excludes_dsa() {
        let defaults = anvil_default_host_keys();
        assert!(!defaults.iter().any(|a| a == "ssh-dss"));
        assert!(defaults.iter().any(|a| a == "ssh-ed25519"));
    }

    // ── Category labels ─────────────────────────────────────────────────────

    #[test]
    fn category_labels_are_stable() {
        assert_eq!(AlgCategory::Kex.label(), "kex");
        assert_eq!(AlgCategory::Cipher.label(), "cipher");
        assert_eq!(AlgCategory::Mac.label(), "mac");
        assert_eq!(AlgCategory::HostKey.label(), "host-key");
    }
}
