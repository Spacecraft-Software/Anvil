// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Walks every YAML in `tests/ssh_config_matrix/` and asserts that
//! [`anvil_ssh::ssh_config::resolve`] produces the expected resolved
//! values.  M12.4 ships the harness with three seed fixtures; M12.9
//! expands the matrix to cover every directive in PRD §5.8.1.
//!
//! Each fixture is a single document with the shape:
//!
//! ```yaml
//! description: "human-readable name"
//! config: |
//!   <ssh_config text>
//! host: "<host string passed to resolve>"
//! expected:
//!   hostname: "..."     # any subset of the keys below
//!   user: "..."
//!   port: 2222
//!   ...
//! ```
//!
//! Only the keys present in `expected` are checked; missing keys mean
//! "don't care".  Keys map to fields of [`anvil_ssh::ResolvedSshConfig`].

use std::fs;
use std::path::Path;

use anvil_ssh::ssh_config::{resolve, SshConfigPaths};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    description: String,
    config: String,
    host: String,
    #[serde(default)]
    expected: Expected,
}

/// Subset of [`anvil_ssh::ResolvedSshConfig`] whose values can be
/// directly compared from a YAML literal.  All fields are optional —
/// missing keys mean "the test does not assert anything about this
/// field."
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Expected {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_files: Option<Vec<String>>,
    proxy_command: Option<String>,
    proxy_jump: Option<String>,
    connect_timeout_secs: Option<u64>,
    connection_attempts: Option<u32>,
}

#[test]
fn matrix_walks_pass() {
    let matrix_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ssh_config_matrix");
    let entries = fs::read_dir(&matrix_dir)
        .unwrap_or_else(|e| panic!("failed to read matrix dir {}: {e}", matrix_dir.display(),));

    let mut fixture_count: u32 = 0;
    for entry in entries {
        let entry = entry.expect("read fixture entry");
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yaml") {
            continue;
        }
        run_fixture(&path);
        fixture_count += 1;
    }
    assert!(
        fixture_count > 0,
        "no YAML fixtures discovered under {}",
        matrix_dir.display(),
    );
}

fn run_fixture(path: &Path) {
    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fixture: Fixture = serde_yml::from_str(&content)
        .unwrap_or_else(|e| panic!("parse YAML {}: {e}", path.display()));

    // Write the inline config to a temp file so the resolver reads it
    // through the normal file-IO path (covers the read + tokenize +
    // include + parse pipeline end-to-end).
    let dir = tempfile::tempdir().expect("tempdir for fixture");
    let conf = dir.path().join("config");
    fs::write(&conf, &fixture.config).expect("write fixture config");

    let paths = SshConfigPaths {
        user: Some(conf),
        system: None,
    };
    let resolved = resolve(&fixture.host, &paths).unwrap_or_else(|e| {
        panic!(
            "resolve in {} ({}): {e}",
            path.display(),
            fixture.description
        )
    });

    let label = format!("{} ({})", path.display(), fixture.description);
    let exp = &fixture.expected;

    if let Some(expected_hostname) = &exp.hostname {
        assert_eq!(
            resolved.hostname.as_deref(),
            Some(expected_hostname.as_str()),
            "hostname mismatch in {label}",
        );
    }
    if let Some(expected_user) = &exp.user {
        assert_eq!(
            resolved.user.as_deref(),
            Some(expected_user.as_str()),
            "user mismatch in {label}",
        );
    }
    if let Some(expected_port) = exp.port {
        assert_eq!(
            resolved.port,
            Some(expected_port),
            "port mismatch in {label}",
        );
    }
    if let Some(expected_files) = &exp.identity_files {
        let actual: Vec<String> = resolved
            .identity_files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &actual, expected_files,
            "identity_files mismatch in {label}",
        );
    }
    if let Some(expected_proxy) = &exp.proxy_command {
        assert_eq!(
            resolved.proxy_command.as_deref(),
            Some(expected_proxy.as_str()),
            "proxy_command mismatch in {label}",
        );
    }
    if let Some(expected_jump) = &exp.proxy_jump {
        assert_eq!(
            resolved.proxy_jump.as_deref(),
            Some(expected_jump.as_str()),
            "proxy_jump mismatch in {label}",
        );
    }
    if let Some(expected_secs) = exp.connect_timeout_secs {
        assert_eq!(
            resolved.connect_timeout.map(|d| d.as_secs()),
            Some(expected_secs),
            "connect_timeout_secs mismatch in {label}",
        );
    }
    if let Some(expected_attempts) = exp.connection_attempts {
        assert_eq!(
            resolved.connection_attempts,
            Some(expected_attempts),
            "connection_attempts mismatch in {label}",
        );
    }

    // Sanity: an explicit `expected.user: null` (the YAML literal `null`)
    // and a *missing* `user:` key both currently mean "don't care" — the
    // serde Default + Option<String> shape collapses them.  Negative
    // assertions ("field must NOT be set") live in inline unit tests.
}
