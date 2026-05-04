// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! SSH host-key fingerprint pinning for well-known Git hosting services (FR-6, FR-7).
//!
//! Gitway embeds the published SHA-256 fingerprints for GitHub, GitLab, and
//! Codeberg.  On every connection the server's presented key is hashed and the
//! resulting fingerprint is compared against the embedded list for that host.
//! Any mismatch aborts the connection immediately.
//!
//! # Custom / self-hosted instances
//!
//! Fingerprints for any host not listed below can be added via a
//! `known_hosts`-style file at `~/.config/gitway/known_hosts` (FR-7).
//! Each non-comment line must follow the format:
//!
//! ```text
//! hostname SHA256:<base64-encoded-fingerprint>
//! ```
//!
//! # Fingerprint sources
//!
//! - GitHub:   <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
//! - GitLab:   <https://docs.gitlab.com/ee/user/gitlab_com/index.html#ssh-host-keys-fingerprints>
//! - Codeberg: <https://docs.codeberg.org/security/ssh-fingerprint/>
//!
//! Last verified: 2026-04-11

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;

use crate::cert_authority::{parse_known_hosts, CertAuthority, KnownHostsFile, RevokedEntry};
use crate::error::AnvilError;
use crate::ssh_config::lexer::wildcard_match;

// ── Well-known host constants ─────────────────────────────────────────────────

/// Primary GitHub SSH host (FR-1).
pub const DEFAULT_GITHUB_HOST: &str = "github.com";

/// Fallback GitHub SSH host when port 22 is unavailable (FR-1).
///
/// GitHub routes SSH traffic through HTTPS port 443 on this hostname.
pub const GITHUB_FALLBACK_HOST: &str = "ssh.github.com";

/// Primary GitLab SSH host.
pub const DEFAULT_GITLAB_HOST: &str = "gitlab.com";

/// Fallback GitLab SSH host when port 22 is unavailable.
///
/// GitLab routes SSH traffic through HTTPS port 443 on this hostname.
pub const GITLAB_FALLBACK_HOST: &str = "altssh.gitlab.com";

/// Primary Codeberg SSH host.
pub const DEFAULT_CODEBERG_HOST: &str = "codeberg.org";

/// Default SSH port used by all providers.
///
/// Changing to a value below 1024 requires elevated privileges on most
/// POSIX systems; only override this when using a self-hosted instance
/// with a non-standard port.
pub const DEFAULT_PORT: u16 = 22;

/// HTTPS-port fallback for providers that support it (GitHub, GitLab).
pub const FALLBACK_PORT: u16 = 443;

// ── Legacy alias kept for backward compatibility ──────────────────────────────

/// Alias for [`GITHUB_FALLBACK_HOST`]; retained so existing callers that
/// reference the old name continue to compile.
#[deprecated(since = "0.2.0", note = "use GITHUB_FALLBACK_HOST instead")]
pub const FALLBACK_HOST: &str = GITHUB_FALLBACK_HOST;

// ── Embedded fingerprints ─────────────────────────────────────────────────────

/// GitHub's published SSH host-key fingerprints (SHA-256, FR-6).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If GitHub rotates its keys, update this constant and cut a patch release.**
pub const GITHUB_FINGERPRINTS: &[&str] = &[
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", // Ed25519
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", // ECDSA-SHA2-nistp256
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", // RSA
];

/// GitLab.com's published SSH host-key fingerprints (SHA-256).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If GitLab rotates its keys, update this constant and cut a patch release.**
pub const GITLAB_FINGERPRINTS: &[&str] = &[
    "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8", // Ed25519
    "SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw", // ECDSA-SHA2-nistp256
    "SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ", // RSA
];

/// Codeberg.org's published SSH host-key fingerprints (SHA-256).
///
/// Contains one entry per key type in `SHA256:<base64>` format:
/// - Ed25519  (index 0)
/// - ECDSA    (index 1)
/// - RSA      (index 2)
///
/// **If Codeberg rotates its keys, update this constant and cut a patch release.**
pub const CODEBERG_FINGERPRINTS: &[&str] = &[
    "SHA256:mIlxA9k46MmM6qdJOdMnAQpzGxF4WIVVL+fj+wZbw0g", // Ed25519
    "SHA256:T9FYDEHELhVkulEKKwge5aVhVTbqCW0MIRwAfpARs/E", // ECDSA-SHA2-nistp256
    "SHA256:6QQmYi4ppFS4/+zSZ5S4IU+4sa6rwvQ4PbhCtPEBekQ", // RSA
];

// ── Known-hosts parser for custom / GHE support ───────────────────────────────

/// Parses a known-hosts file and returns all fingerprints for `hostname`.
///
/// Lines starting with `#` and blank lines are ignored. Each valid line has
/// the form `hostname SHA256:<fp>`.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
fn fingerprints_from_known_hosts(path: &Path, hostname: &str) -> Result<Vec<String>, AnvilError> {
    let content = std::fs::read_to_string(path)?;
    let mut fps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let Some(host_part) = parts.next() else {
            continue;
        };
        let Some(fp_part) = parts.next() else {
            continue;
        };
        if host_part == hostname {
            fps.push(fp_part.trim().to_owned());
        }
    }

    Ok(fps)
}

/// Returns the default known-hosts path: `~/.config/gitway/known_hosts`
/// (or the platform-equivalent `dirs::config_dir()` location).
///
/// Returns `None` when `dirs::config_dir()` cannot resolve a config
/// directory (extremely rare — typically only on misconfigured CI
/// runners with no `HOME` / `XDG_CONFIG_HOME` and no fallback).
///
/// Promoted from crate-private to public in M19 (PRD §5.8.8) so the
/// `gitway hosts` subcommand family can target the same path the
/// rest of Anvil reads from by default.
#[must_use]
pub fn default_known_hosts_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("gitway").join("known_hosts"))
}

// ── Public verifier ───────────────────────────────────────────────────────────

/// Collects all expected fingerprints for `host`.
///
/// For well-known hosts (GitHub, GitLab, Codeberg and their fallback
/// hostnames) the embedded fingerprint set is returned.  For any other host
/// the custom known-hosts file is consulted; if it provides entries those are
/// used, otherwise the connection is refused with an actionable error.
///
/// # Errors
///
/// Returns an error if `custom_path` is specified but cannot be read, or if
/// no fingerprints can be found for the given host.
pub fn fingerprints_for_host(
    host: &str,
    custom_path: &Option<std::path::PathBuf>,
) -> Result<Vec<String>, AnvilError> {
    // Start with the embedded set for the well-known hosted services.
    let mut fps: Vec<String> = match host {
        "github.com" | "ssh.github.com" => {
            GITHUB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "gitlab.com" | "altssh.gitlab.com" => {
            GITLAB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "codeberg.org" => CODEBERG_FINGERPRINTS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        _ => Vec::new(),
    };

    // Consult the known-hosts file (user-supplied path or the default location)
    // to allow custom / self-hosted instances and to let users extend or
    // override the embedded sets.
    let known_hosts_path = custom_path.clone().or_else(default_known_hosts_path);

    if let Some(ref path) = known_hosts_path {
        if path.exists() {
            let extras = fingerprints_from_known_hosts(path, host)?;
            fps.extend(extras);
        }
    }

    // No fingerprints at all → refuse the connection with a clear message.
    if fps.is_empty() {
        return Err(
            AnvilError::invalid_config(format!("no fingerprints known for host '{host}'"))
                .with_hint(format!(
                    "Gitway refuses to connect to hosts whose SSH fingerprint it can't \
             verify (no trust-on-first-use). Either you typed the hostname \
             wrong, or this is a self-hosted server and you need to pin its \
             fingerprint: fetch it from the provider's docs (GitHub, GitLab, \
             Codeberg publish them) and append one line to \
             ~/.config/gitway/known_hosts:\n\
             \n\
                 {host} SHA256:<base64-fingerprint>\n\
             \n\
             As a last resort, re-run with --insecure-skip-host-check (not \
             recommended — this disables MITM protection)."
                )),
        );
    }

    Ok(fps)
}

// ── M14: combined trust view (FR-60, FR-64) ──────────────────────────────────

/// Combined view of every `known_hosts` entry that bears on the
/// connection target.
///
/// Returned by [`host_key_trust`].  A connection target's effective
/// trust is the union of:
///
/// - `fingerprints` — direct SHA-256 pins (embedded + custom-file).
///   Identical to what [`fingerprints_for_host`] returns.
/// - `cert_authorities` — `@cert-authority` entries whose host pattern
///   matches the target.  Live cert verification (FR-61, FR-62, FR-63)
///   is deferred until russh exposes the server's certificate; the
///   field is populated today so `gitway config show --json` and
///   audit tooling can surface CA identities.
/// - `revoked` — `@revoked` entries whose host pattern matches.
///   Enforced first in
///   [`crate::session::AnvilSession::connect`]'s host-key check: any
///   presented key whose fingerprint hits one of these is rejected
///   regardless of `StrictHostKeyChecking` policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostKeyTrust {
    pub fingerprints: Vec<String>,
    pub cert_authorities: Vec<CertAuthority>,
    pub revoked: Vec<RevokedEntry>,
}

/// Returns the [`HostKeyTrust`] for `host`, combining the embedded
/// fingerprint set, any direct pins / `@cert-authority` / `@revoked`
/// lines from the user-supplied or default `known_hosts` file, and
/// pattern-matching for the cert-authority + revoked classes.
///
/// Unlike [`fingerprints_for_host`], an empty trust set is **not** an
/// error — the caller decides whether the absence is fatal (the
/// `StrictHostKeyChecking::AcceptNew` path tolerates an empty set; the
/// `Yes` path does not).
///
/// # Errors
/// [`AnvilError::invalid_config`] when the known-hosts file exists but
/// fails to parse (a malformed `@cert-authority` line, for instance).
/// File-not-found is silently treated as no entries.
pub fn host_key_trust(
    host: &str,
    custom_path: &Option<std::path::PathBuf>,
) -> Result<HostKeyTrust, AnvilError> {
    let mut trust = HostKeyTrust {
        fingerprints: embedded_fingerprints(host),
        cert_authorities: Vec::new(),
        revoked: Vec::new(),
    };

    let known_hosts_path = custom_path.clone().or_else(default_known_hosts_path);
    let Some(path) = known_hosts_path else {
        return Ok(trust);
    };
    if !path.exists() {
        return Ok(trust);
    }

    let content = std::fs::read_to_string(&path).map_err(|e| {
        AnvilError::invalid_config(format!(
            "could not read known_hosts {}: {e}",
            path.display(),
        ))
    })?;
    let parsed: KnownHostsFile = parse_known_hosts(&content)?;

    for direct in parsed.direct {
        if wildcard_match(&direct.host_pattern, host) {
            trust.fingerprints.push(direct.fingerprint);
        }
    }
    for ca in parsed.cert_authorities {
        if wildcard_match(&ca.host_pattern, host) {
            trust.cert_authorities.push(ca);
        }
    }
    for rev in parsed.revoked {
        if wildcard_match(&rev.host_pattern, host) {
            trust.revoked.push(rev);
        }
    }

    Ok(trust)
}

/// Returns the embedded SHA-256 fingerprints for the listed
/// well-known hosts.  Internal helper used by both
/// [`fingerprints_for_host`] and [`host_key_trust`].
fn embedded_fingerprints(host: &str) -> Vec<String> {
    match host {
        "github.com" | "ssh.github.com" => {
            GITHUB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "gitlab.com" | "altssh.gitlab.com" => {
            GITLAB_FINGERPRINTS.iter().map(|&s| s.to_owned()).collect()
        }
        "codeberg.org" => CODEBERG_FINGERPRINTS
            .iter()
            .map(|&s| s.to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

/// Appends `host SHA256:<fingerprint>` as a new plaintext line to
/// the `known_hosts` file at `path`, creating the file (and any
/// missing parent directories) if needed.
///
/// Promoted from crate-private to public in M19 (PRD §5.8.8 FR-85)
/// so the `gitway hosts add` verb can drive the write side without a
/// re-export shim.  Used internally by
/// [`crate::ssh_config::StrictHostKeyChecking::AcceptNew`] for the
/// first-connection TOFU path.
///
/// File locking and duplicate-detection are deferred to a post-M19
/// polish pass — see PRD §5.8.8 risks.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, the
/// file cannot be opened for append, or the write fails.
pub fn append_known_host(path: &Path, host: &str, fingerprint: &str) -> Result<(), AnvilError> {
    use std::io::Write;

    ensure_parent_exists(path)?;

    let line = format!("{host} {fingerprint}\n");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not open known_hosts {} for append: {e}",
                path.display(),
            ))
        })?;
    file.write_all(line.as_bytes()).map_err(|e| {
        AnvilError::invalid_config(format!(
            "could not write to known_hosts {}: {e}",
            path.display(),
        ))
    })?;

    Ok(())
}

/// Appends `|1|<base64-salt>|<base64-hmac-sha1> SHA256:<fingerprint>`
/// to the `known_hosts` file at `path`, generating a fresh 20-byte
/// random salt for this entry.
///
/// This is the M19 (PRD §5.8.8 FR-84) write-side counterpart to
/// [`crate::cert_authority::HashedHost::matches`].  The encoding is
/// bit-for-bit identical to what `ssh-keygen -H` would write — see
/// the `tests/test_hostkey_writes.rs` round-trip test that proves it
/// re-parses through [`crate::cert_authority::parse_known_hosts`] +
/// [`crate::cert_authority::HashedHost::matches(host)`] cleanly.
///
/// `host` is what gets HMAC-SHA1'd; pass exactly the hostname the
/// caller wants the hash to match (no implicit lower-casing — that
/// policy lives in the caller, mirroring OpenSSH's
/// `hostfile.c::lowercase` flag handling).
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, the
/// file cannot be opened for append, or the write fails.
pub fn append_known_host_hashed(
    path: &Path,
    host: &str,
    fingerprint: &str,
) -> Result<(), AnvilError> {
    use std::io::Write;

    ensure_parent_exists(path)?;

    // Fresh 20-byte salt per entry, sourced from the OS RNG.
    let mut salt = [0u8; 20];
    OsRng.fill_bytes(&mut salt);

    let mut mac = <Hmac<Sha1>>::new_from_slice(&salt).map_err(|_e| {
        // `_e` is the InvalidLength variant; HMAC-SHA1 does not
        // enforce key-length restrictions in practice, so this
        // branch is effectively dead.  Discarded by design.
        AnvilError::invalid_config(
            "HMAC-SHA1 init failed unexpectedly; refusing to write hashed entry".to_owned(),
        )
    })?;
    mac.update(host.as_bytes());
    let hash = mac.finalize().into_bytes();

    let line = format!(
        "|1|{}|{} {fingerprint}\n",
        BASE64.encode(salt),
        BASE64.encode(hash.as_slice()),
    );
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not open known_hosts {} for append: {e}",
                path.display(),
            ))
        })?;
    file.write_all(line.as_bytes()).map_err(|e| {
        AnvilError::invalid_config(format!(
            "could not write to known_hosts {}: {e}",
            path.display(),
        ))
    })?;

    Ok(())
}

/// Prepends `@revoked <host_pattern> <fingerprint>` to the
/// `known_hosts` file at `path`, atomically via a sibling tempfile +
/// rename.  Creates the file (and missing parents) if it does not
/// yet exist.
///
/// M19 (PRD §5.8.8 FR-86): the `@revoked` line is written **first**
/// in the file so it surfaces ahead of any direct pin during
/// human inspection.  The trust-merger ([`host_key_trust`])
/// already treats `@revoked` as a hard reject regardless of position,
/// so the prepend is purely a readability convention.
///
/// # Atomicity
///
/// Reads the existing file into memory (capped at 1 MiB), prepends
/// the new line, writes to `<path>.tmp.<random>`, then
/// [`std::fs::rename`] over the original.  POSIX `rename` is atomic
/// within a filesystem; on Windows, `MoveFileEx` with
/// `MOVEFILE_REPLACE_EXISTING` is the closest equivalent and is what
/// `std::fs::rename` uses.  A crash mid-rename leaves either the old
/// file or the new one — never a torn write.
///
/// # Errors
///
/// Returns an error if the file is larger than 1 MiB, the parent
/// directory cannot be created, the tempfile cannot be opened, or
/// the rename fails.
pub fn prepend_revoked(
    path: &Path,
    host_pattern: &str,
    fingerprint: &str,
) -> Result<(), AnvilError> {
    use std::io::Write;

    const MAX_FILE_BYTES: u64 = 1024 * 1024;

    ensure_parent_exists(path)?;

    // Read the existing file (or treat missing as empty).
    let existing: Vec<u8> = if path.exists() {
        let metadata = std::fs::metadata(path).map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not stat known_hosts {} for revoke: {e}",
                path.display(),
            ))
        })?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(AnvilError::invalid_config(format!(
                "known_hosts {} is larger than {MAX_FILE_BYTES} bytes; refusing to load \
                 entire file into memory for revoke. Split the file or pass --known-hosts \
                 to point at a smaller one.",
                path.display(),
            )));
        }
        std::fs::read(path).map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not read known_hosts {} for revoke: {e}",
                path.display(),
            ))
        })?
    } else {
        Vec::new()
    };

    // Build the temp path with a random suffix so concurrent revokes
    // don't collide on the same temp name.
    let mut suffix_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut suffix_bytes);
    let suffix = BASE64
        .encode(suffix_bytes)
        .replace('/', "_")
        .replace('+', "-");
    let tmp_path = path.with_extension(format!("revoke.{suffix}.tmp"));

    let mut tmp = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| {
            AnvilError::invalid_config(format!(
                "could not create temp file {} for revoke: {e}",
                tmp_path.display(),
            ))
        })?;

    let new_line = format!("@revoked {host_pattern} {fingerprint}\n");
    tmp.write_all(new_line.as_bytes())
        .map_err(|e| AnvilError::invalid_config(format!("could not write revoke header: {e}")))?;
    tmp.write_all(&existing).map_err(|e| {
        AnvilError::invalid_config(format!("could not copy existing known_hosts contents: {e}"))
    })?;
    tmp.sync_all().map_err(|e| {
        AnvilError::invalid_config(format!("could not fsync temp file before rename: {e}"))
    })?;
    drop(tmp);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        // Best-effort cleanup of the orphaned tempfile; ignore the
        // result because we're already in an error path.
        let _ = std::fs::remove_file(&tmp_path);
        AnvilError::invalid_config(format!(
            "could not rename {} -> {}: {e}",
            tmp_path.display(),
            path.display(),
        ))
    })?;

    Ok(())
}

/// Returns the embedded fingerprint catalogue as `(host, fingerprint,
/// algorithm)` triples for surfacing in `gitway hosts list`.
///
/// The algorithm tag is one of `"ed25519"`, `"ecdsa"`, `"rsa"` —
/// matches the per-index ordering inside [`GITHUB_FINGERPRINTS`],
/// [`GITLAB_FINGERPRINTS`], and [`CODEBERG_FINGERPRINTS`].
#[must_use]
pub fn all_embedded() -> Vec<(String, String, &'static str)> {
    const ALGS: [&str; 3] = ["ed25519", "ecdsa", "rsa"];
    let mut out = Vec::with_capacity(9);
    for (host, fps) in [
        ("github.com", GITHUB_FINGERPRINTS),
        ("gitlab.com", GITLAB_FINGERPRINTS),
        ("codeberg.org", CODEBERG_FINGERPRINTS),
    ] {
        for (idx, fp) in fps.iter().enumerate() {
            let alg = ALGS.get(idx).copied().unwrap_or("unknown");
            out.push((host.to_owned(), (*fp).to_owned(), alg));
        }
    }
    out
}

/// Per-file format detected by [`detect_hash_mode`].  Drives whether
/// `gitway hosts add` should emit a hashed or plaintext entry by
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashMode {
    /// File does not exist, or contains no recognizable host lines.
    Empty,
    /// At least one direct line uses the plaintext `host SHA256:fp`
    /// shape; no hashed entries seen.  New entries default to
    /// plaintext.
    Plaintext,
    /// At least one direct line uses the `|1|salt|hash SHA256:fp`
    /// shape.  New entries default to hashed.
    Hashed,
}

/// Inspects the existing `known_hosts` file at `path` and decides
/// whether new entries should be hashed (matches OpenSSH's
/// `HashKnownHosts yes` behaviour) or plaintext.
///
/// - Returns [`HashMode::Empty`] if the file does not exist or is
///   empty / contains only comments + `@`-marker lines.
/// - Returns [`HashMode::Hashed`] if **any** non-comment direct line
///   starts with `|1|` (matches OpenSSH's `_ssh_host_hashed_p` check).
/// - Returns [`HashMode::Plaintext`] otherwise.
///
/// Cheap — reads the file once line-by-line and short-circuits on
/// the first hashed token seen.
///
/// # Errors
///
/// Returns an error only if the file exists but cannot be read.
pub fn detect_hash_mode(path: &Path) -> Result<HashMode, AnvilError> {
    if !path.exists() {
        return Ok(HashMode::Empty);
    }
    let content = std::fs::read_to_string(path).map_err(|e| {
        AnvilError::invalid_config(format!(
            "could not read known_hosts {} for hash-mode detect: {e}",
            path.display(),
        ))
    })?;
    let mut saw_plaintext = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        // Direct line.  Inspect the first whitespace-delimited token.
        let host_token = line.split_whitespace().next().unwrap_or("");
        if host_token.starts_with("|1|") {
            return Ok(HashMode::Hashed);
        }
        saw_plaintext = true;
    }
    if saw_plaintext {
        Ok(HashMode::Plaintext)
    } else {
        Ok(HashMode::Empty)
    }
}

/// Internal helper — `mkdir -p` for the parent of `path`.  Used by
/// every M19 writer so they share the same error-message shape.
fn ensure_parent_exists(path: &Path) -> Result<(), AnvilError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AnvilError::invalid_config(format!(
                    "could not create known_hosts parent {}: {e}",
                    parent.display(),
                ))
            })?;
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_com_returns_three_fingerprints() {
        let fps = fingerprints_for_host("github.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn ssh_github_com_returns_same_fingerprints() {
        let fps = fingerprints_for_host("ssh.github.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn gitlab_com_returns_three_fingerprints() {
        let fps = fingerprints_for_host("gitlab.com", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn altssh_gitlab_com_returns_same_fingerprints_as_gitlab() {
        let primary = fingerprints_for_host("gitlab.com", &None).unwrap();
        let fallback = fingerprints_for_host("altssh.gitlab.com", &None).unwrap();
        assert_eq!(primary, fallback);
    }

    #[test]
    fn codeberg_org_returns_three_fingerprints() {
        let fps = fingerprints_for_host("codeberg.org", &None).unwrap();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn all_github_fingerprints_start_with_sha256_prefix() {
        for fp in GITHUB_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn all_gitlab_fingerprints_start_with_sha256_prefix() {
        for fp in GITLAB_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn all_codeberg_fingerprints_start_with_sha256_prefix() {
        for fp in CODEBERG_FINGERPRINTS {
            assert!(fp.starts_with("SHA256:"), "malformed fingerprint: {fp}");
        }
    }

    #[test]
    fn unknown_host_without_known_hosts_is_error() {
        let result = fingerprints_for_host("git.example.com", &None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("git.example.com"));
    }

    // ── M14: host_key_trust ──────────────────────────────────────────────────

    /// Helper: write `content` to a fresh temp file and return its path.
    fn write_known_hosts(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, content).expect("write");
        (dir, path)
    }

    #[test]
    fn host_key_trust_embeds_well_known_fingerprints() {
        let trust = host_key_trust("github.com", &None).expect("trust");
        assert_eq!(trust.fingerprints.len(), 3);
        assert!(trust.cert_authorities.is_empty());
        assert!(trust.revoked.is_empty());
    }

    #[test]
    fn host_key_trust_pattern_matches_cert_authority() {
        let (_g, path) = write_known_hosts(
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca\n",
        );
        let trust = host_key_trust("foo.example.com", &Some(path)).expect("trust");
        assert_eq!(trust.cert_authorities.len(), 1);
        assert_eq!(trust.cert_authorities[0].host_pattern, "*.example.com");
    }

    #[test]
    fn host_key_trust_pattern_excludes_non_match() {
        let (_g, path) = write_known_hosts(
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca\n",
        );
        let trust = host_key_trust("other.org", &Some(path)).expect("trust");
        assert!(trust.cert_authorities.is_empty());
    }

    #[test]
    fn host_key_trust_revoked_pattern_matches() {
        let (_g, path) = write_known_hosts(
            "@revoked *.example.com SHA256:revokedfp\n\
             @revoked unrelated.com SHA256:other\n",
        );
        let trust = host_key_trust("foo.example.com", &Some(path)).expect("trust");
        assert_eq!(trust.revoked.len(), 1);
        assert_eq!(trust.revoked[0].fingerprint, "SHA256:revokedfp");
    }

    #[test]
    fn host_key_trust_combines_direct_and_embedded() {
        let (_g, path) = write_known_hosts("github.com SHA256:extra-pin\n");
        let trust = host_key_trust("github.com", &Some(path)).expect("trust");
        // Three embedded + one extra direct.
        assert_eq!(trust.fingerprints.len(), 4);
        assert!(trust.fingerprints.contains(&"SHA256:extra-pin".to_owned()));
    }

    #[test]
    fn host_key_trust_missing_file_returns_embedded_only() {
        let trust = host_key_trust(
            "github.com",
            &Some(std::path::PathBuf::from("/this/path/does/not/exist")),
        )
        .expect("trust");
        assert_eq!(trust.fingerprints.len(), 3);
        assert!(trust.cert_authorities.is_empty());
        assert!(trust.revoked.is_empty());
    }

    #[test]
    fn host_key_trust_empty_for_unknown_host_no_file() {
        // Unlike `fingerprints_for_host`, `host_key_trust` does NOT
        // error on an empty trust set — that is the caller's policy
        // call.  This is the path the AcceptNew policy relies on.
        let trust = host_key_trust("git.example.com", &None).expect("trust");
        assert!(trust.fingerprints.is_empty());
        assert!(trust.cert_authorities.is_empty());
        assert!(trust.revoked.is_empty());
    }
}
