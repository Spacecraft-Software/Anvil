// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! End-to-end coverage of the M14 `known_hosts` extensions
//! ([`anvil_ssh::cert_authority::parse_known_hosts`] +
//! [`anvil_ssh::hostkey::host_key_trust`]).
//!
//! Hermetic — no network, no russh server.  Lives in
//! `tests/` (rather than as inline unit tests) so it exercises the
//! published crate boundary: anything used here is `pub` API.

use anvil_ssh::cert_authority::parse_known_hosts;
use anvil_ssh::hostkey::host_key_trust;

/// Helper: write `body` to a fresh temp `known_hosts` file.  The
/// returned `TempDir` must outlive the path.
fn write_known_hosts(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, body).expect("write known_hosts");
    (dir, path)
}

#[test]
fn parses_three_classes_in_one_file() {
    let parsed = parse_known_hosts(
        "# header\n\
         my-target SHA256:directpin\n\
         @cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca\n\
         @revoked unrelated.com SHA256:badfp\n",
    )
    .expect("parse");

    assert_eq!(parsed.direct.len(), 1);
    assert_eq!(parsed.direct[0].host_pattern, "my-target");
    assert_eq!(parsed.direct[0].fingerprint, "SHA256:directpin");

    assert_eq!(parsed.cert_authorities.len(), 1);
    assert_eq!(parsed.cert_authorities[0].host_pattern, "*.example.com");
    assert_eq!(parsed.cert_authorities[0].algorithm, "ssh-ed25519");
    assert!(
        parsed.cert_authorities[0]
            .fingerprint
            .starts_with("SHA256:"),
        "expected SHA256-prefixed fp, got {}",
        parsed.cert_authorities[0].fingerprint,
    );

    assert_eq!(parsed.revoked.len(), 1);
    assert_eq!(parsed.revoked[0].host_pattern, "unrelated.com");
    assert_eq!(parsed.revoked[0].fingerprint, "SHA256:badfp");
}

#[test]
fn host_key_trust_filters_by_host_pattern() {
    let (_g, path) = write_known_hosts(
        "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca\n\
         @cert-authority other.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti ca2\n\
         @revoked *.example.com SHA256:revoked-example\n\
         @revoked unrelated.net SHA256:revoked-other\n",
    );

    let trust = host_key_trust("foo.example.com", &Some(path.clone())).expect("trust");
    assert_eq!(trust.cert_authorities.len(), 1);
    assert_eq!(trust.cert_authorities[0].host_pattern, "*.example.com");
    assert_eq!(trust.revoked.len(), 1);
    assert_eq!(trust.revoked[0].fingerprint, "SHA256:revoked-example");

    // A host that doesn't match either pattern picks up neither.
    let trust = host_key_trust("third-party.io", &Some(path)).expect("trust");
    assert!(trust.cert_authorities.is_empty());
    assert!(trust.revoked.is_empty());
}

#[test]
fn host_key_trust_reports_well_known_embedded_set() {
    // No custom file: github.com still has its three embedded
    // fingerprints from the M11.5-era pin set.  Confirms the M14.2
    // refactor preserved the embedded path.
    let trust = host_key_trust("github.com", &None).expect("trust");
    assert_eq!(trust.fingerprints.len(), 3);
    for fp in &trust.fingerprints {
        assert!(fp.starts_with("SHA256:"), "well-known fp shape: {fp}");
    }
}

#[test]
fn malformed_cert_authority_pubkey_errors_with_clear_message() {
    let err = parse_known_hosts("@cert-authority *.example.com ssh-ed25519 not-base64-data\n")
        .expect_err("malformed pubkey should error");
    let msg = format!("{err}");
    assert!(
        msg.contains("@cert-authority"),
        "error should reference the failing marker, got: {msg}",
    );
}
