// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `@cert-authority` and `@revoked` markers in `known_hosts`-style files
//! (PRD §5.8.3 / FR-60, FR-64).
//!
//! M14 ships the *parsing* surface plus the M14.2 revoked-key
//! enforcement in [`crate::session::AnvilSession::check_server_key`].
//! The actual cert-during-handshake verification (FR-61, FR-62, FR-63)
//! is deferred until russh exposes the server's certificate to the
//! `check_server_key` callback — russh 0.59's KEX negotiation does not
//! advertise `*-cert-v01@openssh.com` as a host-key algorithm, so the
//! callback only ever sees plain public keys. See the M14 plan for the
//! upstream blocker.
//!
//! # File format
//!
//! Three line shapes are recognized:
//!
//! ```text
//! # Direct fingerprint (Anvil convention, predates M14):
//! github.com SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
//!
//! # Cert-authority CA pubkey (OpenSSH convention):
//! @cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZD... ca-key
//!
//! # Revoked specific key (Anvil shorthand: SHA256: form):
//! @revoked example.com SHA256:abcd...
//! ```
//!
//! Multiple comma-separated host patterns on one line are split into
//! multiple entries.  Comment lines (`#`) and blanks are skipped.
//!
//! ## Hashed-host support (M19, FR-84)
//!
//! OpenSSH's `HashKnownHosts yes` setting replaces the plaintext host
//! column with `|1|<base64-salt>|<base64-hmac-sha1>` so that an attacker
//! who reads the file cannot enumerate which hosts the user has
//! connected to.  Anvil parses these into [`HashedHost`] values and
//! stores them on [`KnownHostsFile::hashed`]; the per-entry
//! [`HashedHost::matches`] method runs HMAC-SHA1 against a candidate
//! hostname to test for membership at lookup time.  HMAC-SHA1 here is
//! a *privacy* primitive (file-readable enumeration resistance), not a
//! *security* primitive — SHA-1 collisions don't matter because the
//! salt is per-line and 160 bits, the input is a low-entropy hostname,
//! and the threat model is exactly OpenSSH's: hide the hostname list
//! from a casual file reader.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use russh::keys::{ssh_key::PublicKey, HashAlg};
use sha1::Sha1;

use crate::error::AnvilError;

/// One `@cert-authority` line: a CA public key plus the host pattern
/// it applies to.
///
/// Comma-separated patterns on the source line produce one
/// [`CertAuthority`] per pattern, sharing the underlying pubkey blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertAuthority {
    /// Raw glob pattern from the `known_hosts` line, e.g. `*.example.com`
    /// or `bastion`.  Compared with [`crate::ssh_config::lexer::wildcard_match`]
    /// at lookup time.
    pub host_pattern: String,
    /// Algorithm string ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", …).
    pub algorithm: String,
    /// SHA-256 fingerprint of the CA pubkey, in OpenSSH format
    /// (`SHA256:base64...`).  Surfaces in `gitway config show --json`
    /// for audit and acts as the canonical identity of the CA.
    pub fingerprint: String,
    /// Re-serialised OpenSSH public key string (`algorithm AAAA...
    /// comment`).  Preserved verbatim so downstream cert-validation
    /// (deferred to russh upstream) can re-parse without round-tripping
    /// through a wire-format blob.
    pub openssh: String,
}

/// One `@revoked` line: a specific key fingerprint blocklisted for the
/// matching host pattern.
///
/// The Anvil shorthand uses the `SHA256:...` fingerprint form rather
/// than the full OpenSSH pubkey blob — this matches the rest of the
/// `known_hosts` file's existing convention.  OpenSSH's full
/// pubkey-blob form (`@revoked host algorithm AAAA...`) is documented
/// as a follow-up if users ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedEntry {
    /// Raw glob pattern.  `*` to revoke unconditionally.
    pub host_pattern: String,
    /// Fingerprint string, e.g. `SHA256:uNiVztksCs...`.  Compared
    /// case-sensitively against the presented key's fingerprint.
    pub fingerprint: String,
}

/// One direct host-fingerprint pin (`host SHA256:fp`).  Predates M14;
/// kept here so [`parse_known_hosts`] can return everything in one
/// pass instead of forcing the caller to re-iterate the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectHostKey {
    pub host_pattern: String,
    pub fingerprint: String,
}

/// One `HashKnownHosts yes` entry (M19, FR-84).
///
/// OpenSSH replaces the plaintext host column with `|1|salt|hash` so a
/// casual reader of the `known_hosts` file cannot enumerate connected
/// hosts.  The salt is 20 random bytes (matching HMAC-SHA1's output
/// width); the hash is `HMAC-SHA1(key=salt, data=hostname)`.  Use
/// [`HashedHost::matches`] to test a candidate hostname against the
/// stored hash.
///
/// Multiple comma-separated `|1|...` tokens on one source line produce
/// one [`HashedHost`] per token, all sharing the same `fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedHost {
    /// Per-line random salt used as the HMAC-SHA1 key.  Always 20 bytes.
    pub salt: [u8; 20],
    /// `HMAC-SHA1(salt, hostname)` for the hostname this entry covers.
    /// Always 20 bytes.
    pub hash: [u8; 20],
    /// Fingerprint of the host key, e.g. `SHA256:uNiVztksCs...`.
    /// Shared across every [`HashedHost`] derived from the same source
    /// line.
    pub fingerprint: String,
}

impl HashedHost {
    /// Returns `true` iff `host` is the hostname this entry encodes.
    ///
    /// Runs `HMAC-SHA1(self.salt, host.as_bytes())` and compares against
    /// the stored hash with constant-time equality (via `HMAC::verify`,
    /// which uses [`subtle`] internally).  False on mismatch — never
    /// errors.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let Ok(mut mac) = <Hmac<Sha1>>::new_from_slice(&self.salt) else {
            // `new_from_slice` only fails on key-length restrictions
            // that HMAC-SHA1 does not enforce, so this branch is
            // effectively dead.  Defensive return rather than panic.
            return false;
        };
        mac.update(host.as_bytes());
        mac.verify_slice(&self.hash).is_ok()
    }
}

/// Fully-parsed view of one `known_hosts`-style file.
///
/// Returned by [`parse_known_hosts`].  Empty vectors are the natural
/// state when a file contains no entries of that class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHostsFile {
    pub direct: Vec<DirectHostKey>,
    pub cert_authorities: Vec<CertAuthority>,
    pub revoked: Vec<RevokedEntry>,
    /// Hashed direct entries (M19, FR-84).  Use
    /// [`HashedHost::matches`] to query by candidate hostname; the
    /// vector itself preserves source order.
    pub hashed: Vec<HashedHost>,
}

/// Parses `content` (the contents of a `known_hosts`-style file) into
/// the three classes of entries Anvil understands.
///
/// Errors only on hard malformation — a `@cert-authority` line whose
/// pubkey string cannot be parsed as OpenSSH format.  Direct-fingerprint
/// lines that do not split into `host fingerprint` are silently skipped
/// (matches the pre-M14 lenient parser).
///
/// # Errors
/// [`AnvilError::invalid_config`] when a `@cert-authority` pubkey
/// string fails to parse as OpenSSH (e.g. unknown algorithm, malformed
/// base64).
pub fn parse_known_hosts(content: &str) -> Result<KnownHostsFile, AnvilError> {
    let mut out = KnownHostsFile::default();

    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_no = idx + 1;

        if let Some(rest) = strip_marker_ci(line, "@cert-authority") {
            parse_cert_authority_line(rest, line_no, &mut out)?;
            continue;
        }
        if let Some(rest) = strip_marker_ci(line, "@revoked") {
            parse_revoked_line(rest, line_no, &mut out);
            continue;
        }

        // Direct line (plaintext or hashed): `host[,host2,…] SHA256:fp`.
        // Each comma-separated host token is classified independently
        // — `|1|salt|hash` tokens land in `hashed`, others in `direct`.
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(host_part) = parts.next() else {
            continue;
        };
        let Some(fp_part) = parts.next() else {
            continue;
        };
        let fp = fp_part.trim();
        if fp.is_empty() {
            continue;
        }
        for host_token in split_host_patterns(host_part) {
            if host_token.starts_with("|1|") {
                match parse_hashed_token(&host_token) {
                    Some((salt, hash)) => {
                        out.hashed.push(HashedHost {
                            salt,
                            hash,
                            fingerprint: fp.to_owned(),
                        });
                    }
                    None => {
                        log::warn!(
                            "known_hosts: line {line_no}: malformed hashed token '{host_token}'; \
                             skipping (expected '|1|<base64-salt>|<base64-hash>')",
                        );
                    }
                }
            } else {
                out.direct.push(DirectHostKey {
                    host_pattern: host_token,
                    fingerprint: fp.to_owned(),
                });
            }
        }
    }

    Ok(out)
}

/// Decodes a single `|1|<base64-salt>|<base64-hash>` token into its
/// 20-byte salt + 20-byte hash components.
///
/// Returns `None` for any deviation from the expected form: missing
/// `|1|` prefix, missing inner `|` separator, base64 decode failure,
/// or wrong byte length.  Callers log + skip on `None`.
fn parse_hashed_token(token: &str) -> Option<([u8; 20], [u8; 20])> {
    let rest = token.strip_prefix("|1|")?;
    let (salt_b64, hash_b64) = rest.split_once('|')?;
    let salt_bytes = BASE64.decode(salt_b64.as_bytes()).ok()?;
    let hash_bytes = BASE64.decode(hash_b64.as_bytes()).ok()?;
    let salt: [u8; 20] = salt_bytes.try_into().ok()?;
    let hash: [u8; 20] = hash_bytes.try_into().ok()?;
    Some((salt, hash))
}

/// Returns the rest of `line` after `marker`, but only if `marker`
/// appears at the start of `line` followed by whitespace
/// (case-insensitive on the marker itself, matching OpenSSH).
fn strip_marker_ci<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    if line.len() <= marker.len() {
        return None;
    }
    let head = line.get(..marker.len())?;
    if !head.eq_ignore_ascii_case(marker) {
        return None;
    }
    let rest = &line[marker.len()..];
    let trimmed = rest.trim_start();
    if !rest.starts_with(char::is_whitespace) || trimmed.is_empty() {
        // `@cert-authorityFOO ...` — must be `@cert-authority<space>...`.
        return None;
    }
    Some(trimmed)
}

/// Parses the body of a `@cert-authority` line (everything after the
/// marker token + whitespace).  Format: `host_pattern[s] algorithm
/// AAAA... [comment]`.
fn parse_cert_authority_line(
    rest: &str,
    line_no: usize,
    out: &mut KnownHostsFile,
) -> Result<(), AnvilError> {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let Some(host_part) = parts.next() else {
        return Err(AnvilError::invalid_config(format!(
            "known_hosts:{line_no}: @cert-authority line missing host pattern",
        )));
    };
    let Some(key_part) = parts.next() else {
        return Err(AnvilError::invalid_config(format!(
            "known_hosts:{line_no}: @cert-authority line missing pubkey",
        )));
    };

    let key_part = key_part.trim();
    let pk = PublicKey::from_openssh(key_part).map_err(|e| {
        AnvilError::invalid_config(format!(
            "known_hosts:{line_no}: failed to parse @cert-authority pubkey: {e}",
        ))
    })?;
    let algorithm = pk.algorithm().as_str().to_owned();
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    for host in split_host_patterns(host_part) {
        out.cert_authorities.push(CertAuthority {
            host_pattern: host,
            algorithm: algorithm.clone(),
            fingerprint: fingerprint.clone(),
            openssh: key_part.to_owned(),
        });
    }
    Ok(())
}

/// Parses the body of a `@revoked` line.  Format:
/// `host_pattern[s] SHA256:fingerprint`.
fn parse_revoked_line(rest: &str, line_no: usize, out: &mut KnownHostsFile) {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let Some(host_part) = parts.next() else {
        log::warn!("known_hosts:{line_no}: @revoked line missing host pattern");
        return;
    };
    let Some(fp_part) = parts.next() else {
        log::warn!("known_hosts:{line_no}: @revoked line missing fingerprint");
        return;
    };
    let fp = fp_part.trim();
    if fp.is_empty() {
        log::warn!("known_hosts:{line_no}: @revoked line has empty fingerprint");
        return;
    }
    for host in split_host_patterns(host_part) {
        out.revoked.push(RevokedEntry {
            host_pattern: host,
            fingerprint: fp.to_owned(),
        });
    }
}

/// Splits a comma-separated host-pattern column into individual
/// patterns, trimming whitespace and skipping empties.
fn split_host_patterns(column: &str) -> Vec<String> {
    column
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_default() {
        let parsed = parse_known_hosts("").expect("empty");
        assert_eq!(parsed, KnownHostsFile::default());
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let parsed = parse_known_hosts(
            "# top comment\n\
             \n\
             # another\n",
        )
        .expect("parse");
        assert_eq!(parsed, KnownHostsFile::default());
    }

    #[test]
    fn direct_fingerprint_line() {
        let parsed =
            parse_known_hosts("github.com SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s\n")
                .expect("parse");
        assert_eq!(parsed.direct.len(), 1);
        assert_eq!(parsed.direct[0].host_pattern, "github.com");
        assert_eq!(
            parsed.direct[0].fingerprint,
            "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
        );
        assert!(parsed.cert_authorities.is_empty());
        assert!(parsed.revoked.is_empty());
    }

    #[test]
    fn comma_separated_hosts_split_into_multiple_entries() {
        let parsed =
            parse_known_hosts("github.com,gitlab.com,codeberg.org SHA256:abcd\n").expect("parse");
        assert_eq!(parsed.direct.len(), 3);
        let hosts: Vec<&str> = parsed
            .direct
            .iter()
            .map(|d| d.host_pattern.as_str())
            .collect();
        assert_eq!(hosts, vec!["github.com", "gitlab.com", "codeberg.org"]);
    }

    #[test]
    fn cert_authority_line_parsed() {
        // Real ed25519 pubkey blob (32-byte point base64-encoded with the
        // "ssh-ed25519" header).  Doubles as a roundtrip check that
        // ssh_key::PublicKey accepts the input we emit.
        let parsed = parse_known_hosts(
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca-key\n",
        )
        .expect("parse");
        assert_eq!(parsed.cert_authorities.len(), 1);
        let ca = &parsed.cert_authorities[0];
        assert_eq!(ca.host_pattern, "*.example.com");
        assert_eq!(ca.algorithm, "ssh-ed25519");
        assert!(
            ca.fingerprint.starts_with("SHA256:"),
            "expected SHA256 fp, got: {}",
            ca.fingerprint,
        );
        assert!(parsed.direct.is_empty());
        assert!(parsed.revoked.is_empty());
    }

    #[test]
    fn cert_authority_marker_case_insensitive() {
        let parsed = parse_known_hosts(
            "@CERT-AUTHORITY *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti\n",
        )
        .expect("parse");
        assert_eq!(parsed.cert_authorities.len(), 1);
    }

    #[test]
    fn cert_authority_invalid_pubkey_errors() {
        let err = parse_known_hosts("@cert-authority *.example.com ssh-ed25519 not-base64-data\n")
            .expect_err("malformed pubkey");
        let msg = format!("{err}");
        assert!(
            msg.contains("@cert-authority"),
            "expected error to mention @cert-authority, got: {msg}",
        );
    }

    #[test]
    fn revoked_line_parsed() {
        let parsed =
            parse_known_hosts("@revoked example.com SHA256:abcdefghijklmnop\n").expect("parse");
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.revoked[0].host_pattern, "example.com");
        assert_eq!(parsed.revoked[0].fingerprint, "SHA256:abcdefghijklmnop");
        assert!(parsed.direct.is_empty());
        assert!(parsed.cert_authorities.is_empty());
    }

    #[test]
    fn revoked_marker_case_insensitive() {
        let parsed = parse_known_hosts("@REVOKED * SHA256:a\n").expect("parse");
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.revoked[0].host_pattern, "*");
    }

    #[test]
    fn revoked_with_comma_hosts() {
        let parsed =
            parse_known_hosts("@revoked a.example.com,b.example.com SHA256:abc\n").expect("parse");
        assert_eq!(parsed.revoked.len(), 2);
        assert_eq!(parsed.revoked[0].host_pattern, "a.example.com");
        assert_eq!(parsed.revoked[1].host_pattern, "b.example.com");
    }

    #[test]
    fn revoked_missing_fingerprint_logged_and_skipped() {
        // Truncated `@revoked example.com` (no fingerprint) — soft-skip
        // with a warn rather than error: matches the leniency of the
        // existing direct-fingerprint parser.
        let parsed = parse_known_hosts("@revoked example.com\n").expect("parse");
        assert!(parsed.revoked.is_empty());
    }

    #[test]
    fn hashed_entry_skipped_silently() {
        let parsed = parse_known_hosts(
            "|1|abcdef==|fedcba== ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti\n",
        )
        .expect("parse");
        // We don't try to decode hashed entries; they just don't
        // contribute.  Documented as a follow-up.
        assert!(parsed.direct.is_empty());
        assert!(parsed.cert_authorities.is_empty());
    }

    #[test]
    fn mixed_file_three_classes() {
        let parsed = parse_known_hosts(
            "# header\n\
             github.com SHA256:fp1\n\
             @cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca\n\
             @revoked github.com SHA256:bad-fp\n\
             gitlab.com SHA256:fp2\n",
        )
        .expect("parse");
        assert_eq!(parsed.direct.len(), 2);
        assert_eq!(parsed.cert_authorities.len(), 1);
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.direct[0].host_pattern, "github.com");
        assert_eq!(parsed.direct[1].host_pattern, "gitlab.com");
        assert_eq!(parsed.cert_authorities[0].host_pattern, "*.example.com");
        assert_eq!(parsed.revoked[0].host_pattern, "github.com");
    }

    #[test]
    fn marker_without_trailing_space_not_treated_as_marker() {
        // `@cert-authoritySomething` should NOT match the marker — the
        // marker requires whitespace after.  Such a line is treated as
        // a malformed direct line and silently skipped.
        let parsed = parse_known_hosts("@cert-authoritynot-a-marker\n").expect("parse");
        assert_eq!(parsed, KnownHostsFile::default());
    }

    #[test]
    fn whitespace_around_fields_tolerated() {
        let parsed = parse_known_hosts("  github.com\tSHA256:fp\n").expect("parse");
        assert_eq!(parsed.direct.len(), 1);
        assert_eq!(parsed.direct[0].host_pattern, "github.com");
        assert_eq!(parsed.direct[0].fingerprint, "SHA256:fp");
    }
}
