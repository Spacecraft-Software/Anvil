// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! End-to-end coverage of the M19.2 write-side `hostkey` API:
//! [`anvil_ssh::hostkey::append_known_host`],
//! [`anvil_ssh::hostkey::append_known_host_hashed`],
//! [`anvil_ssh::hostkey::prepend_revoked`],
//! [`anvil_ssh::hostkey::detect_hash_mode`], and
//! [`anvil_ssh::hostkey::all_embedded`].
//!
//! Hermetic — every test runs against a fresh `tempfile::TempDir`,
//! no network, no russh.

use std::io::Read;

use anvil_ssh::cert_authority::parse_known_hosts;
use anvil_ssh::hostkey::{
    all_embedded, append_known_host, append_known_host_hashed, default_known_hosts_path,
    detect_hash_mode, prepend_revoked, HashMode,
};

/// Helper: read a file's contents as a string.  Panics on read
/// failure — these tests don't try to be robust to disk quirks; if
/// the tempfile can't be read, something is very wrong.
fn read_file(path: &std::path::Path) -> String {
    let mut f = std::fs::File::open(path).expect("open tempfile");
    let mut s = String::new();
    f.read_to_string(&mut s).expect("read tempfile");
    s
}

// ── append_known_host (plaintext) ───────────────────────────────────────────

#[test]
fn append_known_host_creates_file_and_writes_plaintext_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested").join("known_hosts");
    append_known_host(&path, "github.com", "SHA256:abc").expect("append");
    assert!(path.exists());
    let content = read_file(&path);
    assert_eq!(content, "github.com SHA256:abc\n");
}

#[test]
fn append_known_host_appends_to_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, "old.example SHA256:old\n").expect("seed");
    append_known_host(&path, "new.example", "SHA256:new").expect("append");
    let content = read_file(&path);
    assert_eq!(content, "old.example SHA256:old\nnew.example SHA256:new\n",);
}

// ── append_known_host_hashed ────────────────────────────────────────────────

#[test]
fn append_known_host_hashed_writes_round_trippable_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    append_known_host_hashed(&path, "github.com", "SHA256:abc").expect("append");
    let content = read_file(&path);
    // The line must start with `|1|` and end with the fingerprint.
    assert!(
        content.starts_with("|1|"),
        "expected hashed prefix; got: {content:?}",
    );
    assert!(content.contains("SHA256:abc"));
    // Round-trip: parse + match should recover "github.com".
    let parsed = parse_known_hosts(&content).expect("parse");
    assert_eq!(parsed.hashed.len(), 1);
    assert_eq!(parsed.hashed[0].fingerprint, "SHA256:abc");
    assert!(parsed.hashed[0].matches("github.com"));
    assert!(!parsed.hashed[0].matches("gitlab.com"));
}

#[test]
fn append_known_host_hashed_uses_distinct_salt_per_call() {
    // Two appends for the same host MUST produce two different
    // `|1|salt|hash` tokens — anything else means the salt isn't
    // freshly drawn from the OS RNG and the privacy property of
    // `HashKnownHosts yes` is broken.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    append_known_host_hashed(&path, "github.com", "SHA256:abc").expect("append 1");
    append_known_host_hashed(&path, "github.com", "SHA256:abc").expect("append 2");
    let content = read_file(&path);
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_ne!(
        lines[0], lines[1],
        "two appends of the same host MUST use distinct salts (got identical lines: {lines:?})",
    );
    // Both lines still match `github.com`.
    let parsed = parse_known_hosts(&content).expect("parse");
    assert_eq!(parsed.hashed.len(), 2);
    assert!(parsed.hashed[0].matches("github.com"));
    assert!(parsed.hashed[1].matches("github.com"));
}

// ── prepend_revoked ─────────────────────────────────────────────────────────

#[test]
fn prepend_revoked_creates_file_when_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    prepend_revoked(&path, "*.evil.example", "SHA256:bad").expect("revoke");
    let content = read_file(&path);
    assert_eq!(content, "@revoked *.evil.example SHA256:bad\n");
}

#[test]
fn prepend_revoked_atomically_prepends_before_existing_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    let original = "# header\ngood.example SHA256:good\n";
    std::fs::write(&path, original).expect("seed");
    prepend_revoked(&path, "bad.example", "SHA256:bad").expect("revoke");
    let content = read_file(&path);
    assert_eq!(
        content,
        format!("@revoked bad.example SHA256:bad\n{original}"),
    );
}

#[test]
fn prepend_revoked_refuses_oversized_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    // Synthesize a 2 MiB file — over the 1 MiB cap.
    let big = "a".repeat(2 * 1024 * 1024);
    std::fs::write(&path, &big).expect("seed");
    let err = prepend_revoked(&path, "bad", "SHA256:bad").expect_err("must refuse");
    let msg = format!("{err}");
    assert!(
        msg.contains("larger than"),
        "expected oversize error message, got: {msg}",
    );
}

// ── detect_hash_mode ────────────────────────────────────────────────────────

#[test]
fn detect_hash_mode_empty_when_file_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("does_not_exist");
    assert_eq!(detect_hash_mode(&path).expect("detect"), HashMode::Empty);
}

#[test]
fn detect_hash_mode_empty_when_only_comments_and_markers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    std::fs::write(
        &path,
        "# comment\n@cert-authority *.example.com ssh-ed25519 AAAA ca\n",
    )
    .expect("seed");
    // No direct lines → Empty (the @cert-authority is an `@`-marker line
    // and skipped; no plaintext, no hashed direct entries).
    assert_eq!(detect_hash_mode(&path).expect("detect"), HashMode::Empty);
}

#[test]
fn detect_hash_mode_plaintext_when_only_plaintext_direct_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, "github.com SHA256:abc\n").expect("seed");
    assert_eq!(
        detect_hash_mode(&path).expect("detect"),
        HashMode::Plaintext,
    );
}

#[test]
fn detect_hash_mode_hashed_short_circuits_on_first_hashed_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, "github.com SHA256:abc\n|1|salt=|hash= SHA256:def\n").expect("seed");
    assert_eq!(detect_hash_mode(&path).expect("detect"), HashMode::Hashed);
}

// ── all_embedded ────────────────────────────────────────────────────────────

#[test]
fn all_embedded_returns_three_per_well_known_host() {
    let entries = all_embedded();
    // 3 hosts × 3 algorithms each = 9 entries.
    assert_eq!(entries.len(), 9);
    let github_count = entries.iter().filter(|(h, _, _)| h == "github.com").count();
    let gitlab_count = entries.iter().filter(|(h, _, _)| h == "gitlab.com").count();
    let codeberg_count = entries
        .iter()
        .filter(|(h, _, _)| h == "codeberg.org")
        .count();
    assert_eq!(github_count, 3);
    assert_eq!(gitlab_count, 3);
    assert_eq!(codeberg_count, 3);
    // Algorithms come back tagged ed25519 / ecdsa / rsa.
    let algs: std::collections::BTreeSet<&'static str> =
        entries.iter().map(|(_, _, a)| *a).collect();
    assert_eq!(
        algs,
        ["ecdsa", "ed25519", "rsa"]
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
    );
}

// ── default_known_hosts_path ────────────────────────────────────────────────

#[test]
fn default_known_hosts_path_ends_with_gitway_known_hosts() {
    let p = default_known_hosts_path().expect("default path resolves on this platform");
    let s = p.to_string_lossy();
    assert!(s.ends_with("gitway/known_hosts") || s.ends_with(r"gitway\known_hosts"));
}
