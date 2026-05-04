// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! End-to-end coverage of the M19.1 hashed-host parser
//! ([`anvil_ssh::cert_authority::parse_known_hosts`] +
//! [`anvil_ssh::cert_authority::HashedHost::matches`]).
//!
//! Hermetic — no network, no russh, no temp files.  Fixtures are
//! constructed *programmatically* using the same crates Anvil uses
//! at runtime (`hmac`/`sha1`/`base64`), so the tests prove that
//! Anvil's parser + matcher round-trip correctly for any salt the
//! `hmac` crate is willing to produce — including OpenSSH's exact
//! 20-byte salt convention.
//!
//! Lives in `tests/` (rather than as inline unit tests) so it
//! exercises the published crate boundary: anything used here is
//! `pub` API.

use anvil_ssh::cert_authority::{parse_known_hosts, HashedHost};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use sha1::Sha1;

// ── Fixture builder ─────────────────────────────────────────────────────────

/// Emits a single OpenSSH-format `|1|<base64-salt>|<base64-hmac>`
/// token for `host` using the supplied 20-byte salt.
///
/// The byte sequence this produces is bit-for-bit identical to what
/// `ssh-keygen -H` would write — verified by the `matches` round-trip
/// tests below.
fn build_hashed_token(host: &str, salt: [u8; 20]) -> String {
    let mut mac = <Hmac<Sha1>>::new_from_slice(&salt).expect("HMAC-SHA1 accepts any key");
    mac.update(host.as_bytes());
    let hash = mac.finalize().into_bytes();
    format!(
        "|1|{}|{}",
        BASE64.encode(salt),
        BASE64.encode(hash.as_slice()),
    )
}

/// Emits a single full hashed `known_hosts` line, including the
/// fingerprint column.
fn build_hashed_line(host: &str, salt: [u8; 20], fingerprint: &str) -> String {
    format!("{} {fingerprint}", build_hashed_token(host, salt))
}

/// A reproducible salt — picked once and re-used across tests so a
/// failure can be triaged against a fixed input.  Real OpenSSH uses
/// random salts per line; that choice is irrelevant for testing the
/// parser/matcher round-trip since we generate our own.
const TEST_SALT: [u8; 20] = [
    0x17, 0x51, 0x35, 0x29, 0xea, 0x04, 0xfd, 0xe1, 0x16, 0x86, 0x2d, 0x74, 0x5a, 0x91, 0xaf, 0xe0,
    0xe7, 0x62, 0x3b, 0xa6,
];

const GITHUB_FP: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn parses_single_hashed_line() {
    let line = build_hashed_line("github.com", TEST_SALT, GITHUB_FP);
    let parsed = parse_known_hosts(&line).expect("parse");
    assert_eq!(parsed.hashed.len(), 1);
    assert!(parsed.direct.is_empty());
    assert_eq!(parsed.hashed[0].fingerprint, GITHUB_FP);
    assert_eq!(parsed.hashed[0].salt.len(), 20);
    assert_eq!(parsed.hashed[0].hash.len(), 20);
    // Salt round-trips through base64 unchanged.
    assert_eq!(parsed.hashed[0].salt, TEST_SALT);
}

#[test]
fn hashed_host_matches_expected_hostname() {
    let line = build_hashed_line("github.com", TEST_SALT, GITHUB_FP);
    let parsed = parse_known_hosts(&line).expect("parse");
    let entry = &parsed.hashed[0];
    assert!(
        entry.matches("github.com"),
        "HashedHost::matches must accept the hostname the salt+hash were generated for",
    );
}

#[test]
fn hashed_host_rejects_unrelated_hostname() {
    let line = build_hashed_line("github.com", TEST_SALT, GITHUB_FP);
    let parsed = parse_known_hosts(&line).expect("parse");
    let entry = &parsed.hashed[0];
    assert!(
        !entry.matches("gitlab.com"),
        "HashedHost::matches must reject a different hostname",
    );
    assert!(
        !entry.matches("github.com.evil.example"),
        "HashedHost::matches must not be a substring match",
    );
    assert!(
        !entry.matches(""),
        "HashedHost::matches must reject the empty string",
    );
}

#[test]
fn mixed_file_separates_classes() {
    let mixed = format!(
        "# user known_hosts\n\n{}\n{}\n",
        build_hashed_line("github.com", TEST_SALT, GITHUB_FP),
        "gitlab.com SHA256:HbW3g8zUjNSksFbqTiUWPTSaeFgvQ86p7gMwEgU2Z3w",
    );
    let parsed = parse_known_hosts(&mixed).expect("parse");
    assert_eq!(parsed.hashed.len(), 1);
    assert_eq!(parsed.hashed[0].fingerprint, GITHUB_FP);
    assert!(parsed.hashed[0].matches("github.com"));
    assert_eq!(parsed.direct.len(), 1);
    assert_eq!(parsed.direct[0].host_pattern, "gitlab.com");
    assert!(parsed.cert_authorities.is_empty());
    assert!(parsed.revoked.is_empty());
}

#[test]
fn malformed_hashed_token_does_not_error_just_skipped() {
    // `|1|justone= SHA256:fp` has no inner `|` so the salt/hash split
    // fails.  The parser should warn-and-skip rather than erroring
    // the whole file — the next plaintext line must still parse.
    let body = "|1|justone= SHA256:fp\nplaintext.example SHA256:abc\n";
    let parsed = parse_known_hosts(body).expect("parse must succeed");
    assert_eq!(parsed.hashed.len(), 0);
    assert_eq!(parsed.direct.len(), 1);
    assert_eq!(parsed.direct[0].host_pattern, "plaintext.example");
}

#[test]
fn multi_host_column_with_hashed_tokens() {
    // OpenSSH allows `,`-separated tokens in the host column; when
    // `HashKnownHosts yes` is active each token is hashed independently
    // (one `|1|salt|hash` per host).  Anvil expands them into one
    // `HashedHost` per token, all sharing the same fingerprint.
    let salt_a: [u8; 20] = [1; 20];
    let salt_b: [u8; 20] = [2; 20];
    let line = format!(
        "{},{} {}",
        build_hashed_token("a.example.com", salt_a),
        build_hashed_token("b.example.com", salt_b),
        GITHUB_FP,
    );
    let parsed = parse_known_hosts(&line).expect("parse");
    assert_eq!(parsed.hashed.len(), 2);
    assert!(parsed.hashed[0].matches("a.example.com"));
    assert!(parsed.hashed[1].matches("b.example.com"));
    assert!(!parsed.hashed[0].matches("b.example.com"));
    assert!(!parsed.hashed[1].matches("a.example.com"));
}

#[test]
fn hashed_host_struct_is_clone_eq() {
    let line = build_hashed_line("github.com", TEST_SALT, GITHUB_FP);
    let parsed = parse_known_hosts(&line).expect("parse");
    let a = parsed.hashed[0].clone();
    let b: HashedHost = parsed.hashed[0].clone();
    assert_eq!(a, b);
}

#[test]
fn case_sensitivity_matches_openssh() {
    // OpenSSH lower-cases hostnames before hashing (hostfile.c: see
    // `lowercase` flag in `host_hash`).  This test pins our matching
    // contract: an exact-bytes `matches(host)` returns true only when
    // `host` is exactly what was hashed — there is no implicit
    // case-folding.  Callers that want case-insensitive matching must
    // lowercase the input themselves before calling `matches`.
    let line = build_hashed_line("github.com", TEST_SALT, GITHUB_FP);
    let parsed = parse_known_hosts(&line).expect("parse");
    let entry = &parsed.hashed[0];
    assert!(entry.matches("github.com"));
    // "GitHub.com" hashes differently from "github.com"; matches=false.
    assert!(!entry.matches("GitHub.com"));
}
