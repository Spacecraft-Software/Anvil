// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Structured tracing categories + log/tracing bridge installer
//! ([FR-65](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md),
//! FR-69 of Gitway PRD §5.8.4).
//!
//! Anvil emits `tracing::*!` events with per-category `target` strings
//! so a consumer (Gitway's CLI, downstream tooling, integration tests)
//! can install one [`tracing_subscriber::EnvFilter`] like
//! `anvil_ssh::kex=trace,anvil_ssh::auth=debug` and get exactly the
//! depth they want in each category — without parsing message text.
//!
//! The categories are stable strings exported here so call sites at
//! `anvil_ssh::session`, `anvil_ssh::auth`, etc. stay typo-free, and
//! a downstream `--debug-categories=kex,auth` flag can validate user
//! input against [`CATEGORIES`] cheaply.
//!
//! ## Bridging existing `log!()` calls
//!
//! Anvil 0.5.x and its dependencies (russh, ssh-key) emit via the
//! `log` crate.  M15.1 introduces the [`install_log_bridge`] entry
//! point that funnels every `log::*!` call through the active
//! `tracing` subscriber, so a consumer who installs a single
//! tracing-subscriber sees both the new structured events AND the
//! ~59 legacy `log::*!` call sites without rewriting them.  The
//! migration to native `tracing::*!` calls inside Anvil is post-1.0
//! housekeeping; the bridge stays in place permanently for russh
//! and other reverse-deps that stay on `log`.
//!
//! Anvil **never installs a subscriber itself** — the library cannot
//! know whether the consumer wants human-formatted, JSONL,
//! file-rotated, or OTLP output.  See the Gitway CLI for the
//! reference subscriber install (M15.4).
//!
//! ## Example
//!
//! ```no_run
//! // Once, at process startup, BEFORE any `log::*!` or `tracing::*!`
//! // call is made (so clap-emitted parse errors aren't lost):
//! anvil_ssh::log::install_log_bridge().expect("bridge already installed?");
//!
//! // Then install your tracing subscriber...
//! // tracing_subscriber::fmt().init();
//! ```

/// `target =` string for the SSH key-exchange category.  Events at
/// this target dump offered + accepted KEX algorithms, ciphers,
/// MACs, host-key algorithms, and compression algorithms (FR-66).
///
/// Matches the [`tracing::Metadata::target`] convention of using
/// the `crate_name::module` form so an `EnvFilter` directive like
/// `anvil_ssh::kex=trace` reads naturally.
pub const CAT_KEX: &str = "anvil_ssh::kex";

/// `target =` string for the authentication category.  Events at
/// this target record every identity tried with `path`, `fp`,
/// `alg`, and `verdict=accepted|rejected` structured fields
/// (FR-66).
pub const CAT_AUTH: &str = "anvil_ssh::auth";

/// `target =` string for the channel + protocol-message category.
/// Events at this target record every channel `open` / `close`
/// with channel ID, plus every protocol message type and size
/// (FR-66).
pub const CAT_CHANNEL: &str = "anvil_ssh::channel";

/// `target =` string for the `~/.ssh/config` resolver category.
/// Events at this target record every directive applied with its
/// source `file` and `line` number (FR-66).
pub const CAT_CONFIG: &str = "anvil_ssh::config";

/// `target =` string for the connection-retry / timeout category
/// (M18, FR-83).  Events at this target record each retry attempt
/// with `attempt`, `reason`, `elapsed_ms`, and (on terminal failure)
/// a `disposition` field of `fatal` / `exhausted`.
pub const CAT_RETRY: &str = "anvil_ssh::retry";

/// All Anvil-defined categories, in declaration order.  Used by
/// downstream CLIs (e.g. Gitway's `--debug-categories` flag) to
/// validate user-supplied category names before building an
/// `EnvFilter`.  Does not include `russh` — that's a synthetic
/// passthrough recognized by the consumer's filter, not an Anvil
/// category.
pub const CATEGORIES: &[&str] = &[CAT_KEX, CAT_AUTH, CAT_CHANNEL, CAT_CONFIG, CAT_RETRY];

/// Installs the `log` → `tracing` bridge.
///
/// After this call, every `log::debug!` / `log::info!` / `log::warn!` /
/// `log::error!` / `log::trace!` invocation — from Anvil itself,
/// from `russh`, from `ssh-key`, from any reverse-dep that uses the
/// `log` crate — is forwarded to the active `tracing` subscriber as
/// a `tracing::Event` at the matching level.
///
/// # Idempotency
///
/// `tracing_log::LogTracer::init` returns
/// [`tracing_log::log_tracer::SetLoggerError`] if a `log` logger is
/// already installed (whether by a prior call here, by `env_logger`,
/// or by anything else).  This wrapper preserves that error so the
/// caller can decide what to do — Gitway's CLI swallows it because
/// double-init in tests is harmless; a stricter consumer can panic.
///
/// # Ordering
///
/// Call this **before** any code that may emit a `log::*!` event,
/// including `clap`'s `Cli::parse()` (which emits `log::warn!` on
/// unrecognized flags).  Putting it as the first statement in
/// `main()` is the safe default.
///
/// # Errors
///
/// Returns the underlying `SetLoggerError` if a `log` logger has
/// already been installed in this process.
pub fn install_log_bridge() -> Result<(), tracing_log::log_tracer::SetLoggerError> {
    tracing_log::LogTracer::init()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_constants_have_anvil_prefix() {
        for cat in CATEGORIES {
            assert!(
                cat.starts_with("anvil_ssh::"),
                "category {cat} must use the `anvil_ssh::` target prefix",
            );
        }
    }

    #[test]
    fn categories_slice_matches_individual_constants() {
        assert_eq!(
            CATEGORIES,
            &[CAT_KEX, CAT_AUTH, CAT_CHANNEL, CAT_CONFIG, CAT_RETRY],
        );
    }

    #[test]
    fn category_constants_are_distinct() {
        let mut seen: Vec<&&str> = CATEGORIES.iter().collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), CATEGORIES.len(), "CATEGORIES has duplicates");
    }

    #[test]
    fn install_log_bridge_is_idempotent_after_first_call() {
        // First install in this test process may succeed or fail
        // depending on test execution order — `cargo test` runs
        // tests in parallel and another test (or `env_logger`) may
        // have installed first.  Either outcome is acceptable; what
        // we require is that a SECOND call returns the same error
        // shape (`SetLoggerError`), not panic, not silently change
        // global state.
        let _ = install_log_bridge();
        let second = install_log_bridge();
        // The second call MUST fail because a logger is now set.
        assert!(
            second.is_err(),
            "second install_log_bridge call should fail with SetLoggerError",
        );
    }
}
