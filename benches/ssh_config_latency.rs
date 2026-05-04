// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! NFR-15 latency benchmark for `anvil_ssh::ssh_config::resolve()`.
//!
//! Asserts that resolving a typical user `ssh_config(5)` (≤100 directives,
//! no `Include`s) completes in ≤ 5 ms cold per [Gitway PRD §10 NFR-15].
//! Hard-fails via `panic!` if the median exceeds the budget so the
//! regression shows up in CI as a build failure rather than a noisy
//! Criterion print.
//!
//! # Running
//!
//! ```sh
//! cargo bench --bench ssh_config_latency
//! ```
//!
//! No environment variables required — the benchmark is fully hermetic
//! (writes its fixture to a [`tempfile::TempDir`] and tears it down on
//! drop).
//!
//! # Why a separate bench harness
//!
//! `cargo test` measures correctness; this measures *speed*.  We want
//! the latency budget enforced on every release, but we do not want it
//! gated on `GITWAY_INTEGRATION_TESTS=1` the way the throughput bench
//! is — the resolver path involves zero network I/O.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anvil_ssh::ssh_config::{resolve, SshConfigPaths};
use criterion::{criterion_group, criterion_main, Criterion};
use tempfile::TempDir;

/// NFR-15 budget: ≤ 5 ms cold per resolve call.
const LATENCY_BUDGET: Duration = Duration::from_millis(5);

/// Builds a representative `ssh_config(5)` covering the directives Anvil
/// understands today plus a handful of additional `Host` blocks so the
/// matcher actually walks more than one section.
fn write_typical_config(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("config");
    let body = "\
# Global defaults — apply to every host.
User defaultuser
ServerAliveInterval 30

Host gh
    HostName github.com
    User git
    Port 22
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
    KexAlgorithms curve25519-sha256
    Ciphers chacha20-poly1305@openssh.com
    MACs hmac-sha2-256-etm@openssh.com
    ConnectTimeout 30
    ConnectionAttempts 3

Host gl
    HostName gitlab.com
    User git
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host *.work.example.com
    User work
    ProxyJump bastion.work.example.com

Host bastion.work.example.com
    User bastion
    ProxyCommand ssh -W %h:%p jump.work.example.com

Host work
    HostName work.example.com
    User worker
    Port 2222

Host !legacy *
    PreferredAuthentications publickey
";
    fs::write(&path, body).expect("write fixture");
    path
}

fn bench_resolve_typical(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let conf = write_typical_config(&dir);
    let paths = SshConfigPaths {
        user: Some(conf),
        system: None,
    };

    c.bench_function("resolve_typical_user_config", |b| {
        b.iter(|| {
            // The resolver re-reads the file each call; that is intentional
            // — NFR-15 is about cold latency and the hot-path mtime cache
            // listed as a fallback in PRD §10 has not been implemented.
            resolve("gh", &paths).expect("resolve")
        });
    });

    // Hard-fail enforcement: re-measure outside Criterion's statistical
    // pipeline and panic if the median exceeds the budget.  Criterion's
    // own threshold detection emits warnings but does not fail the run.
    enforce_budget(&paths);
}

fn bench_resolve_no_match(c: &mut Criterion) {
    // Worst-case path within a single-file config: walk every Host block
    // and find no match, so the resolver returns just the Global block's
    // directives.
    let dir = tempfile::tempdir().expect("tempdir");
    let conf = write_typical_config(&dir);
    let paths = SshConfigPaths {
        user: Some(conf),
        system: None,
    };

    c.bench_function("resolve_no_match", |b| {
        b.iter(|| resolve("nothing-matches.example.org", &paths).expect("resolve"));
    });
}

/// Median of 32 cold runs must stay under the NFR-15 budget; hard-fail
/// otherwise.  Runs after the Criterion measurement so the panic appears
/// after the per-bench summary in stdout.
fn enforce_budget(paths: &SshConfigPaths) {
    const RUNS: usize = 32;
    let mut measurements: Vec<Duration> = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = std::time::Instant::now();
        let _ = resolve("gh", paths).expect("resolve");
        measurements.push(start.elapsed());
    }
    measurements.sort();
    let median = measurements[RUNS / 2];

    eprintln!(
        "ssh_config_latency: median resolve() = {} µs (budget = {} µs)",
        median.as_micros(),
        LATENCY_BUDGET.as_micros(),
    );

    assert!(
        median <= LATENCY_BUDGET,
        "ssh_config_latency: NFR-15 budget exceeded — median {} µs > {} µs. \
         If this is intentional (e.g. richer matrix coverage), bump the \
         budget in benches/ssh_config_latency.rs.",
        median.as_micros(),
        LATENCY_BUDGET.as_micros(),
    );
}

criterion_group!(benches, bench_resolve_typical, bench_resolve_no_match);
criterion_main!(benches);
