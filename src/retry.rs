// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Connection retry, backoff, and timeouts (PRD §5.8.7, M18).
//!
//! Three pieces:
//!
//! 1. [`RetryPolicy`] — caller-tunable knobs: attempt count, base /
//!    factor / cap on exponential backoff, max wall-clock window,
//!    per-attempt connect timeout.  Mirrors OpenSSH's
//!    `ConnectionAttempts` + `ConnectTimeout` semantics with a
//!    Gitway-specific cap on total elapsed time.
//! 2. [`classify`] / [`Disposition`] — FR-82's transient-vs-fatal
//!    error classifier.  Network noise (ECONNREFUSED, ETIMEDOUT,
//!    EHOSTUNREACH, DNS NXDOMAIN) is `Retry`; everything else
//!    (auth failure, host-key mismatch, protocol error, signing
//!    error) is `Fatal`.
//! 3. [`run`] — the loop driver.  Calls the supplied async op,
//!    sleeps with jittered exponential backoff between attempts,
//!    captures a [`RetryAttempt`] history for FR-83's `--test
//!    --json` envelope, and emits a `tracing::warn!` event at
//!    [`crate::log::CAT_RETRY`] per failed attempt.
//!
//! ## Trust model
//!
//! `run` is timeout-agnostic — its job is the loop + classifier +
//! jitter + history.  The per-attempt `tokio::time::timeout` wrap
//! lives at the call site (currently `session.rs::connect`) so the
//! same loop driver can be reused for non-network operations
//! (agent reconnects, key-load retries) without forcing every
//! caller to think about timeouts.
//!
//! ## Why russh-handshake failures are NOT retried
//!
//! Once the TCP socket is up, any failure is either a fatal
//! user-input error (auth rejected, host-key mismatch) or an
//! in-flight protocol error mid-handshake.  Re-driving an in-flight
//! handshake is unsafe (the server may have already consumed our
//! key-exchange contribution) and the failure modes are server-side
//! — surfacing them clearly is more useful than silently retrying.
//! [`classify`] returns `Fatal` for every `russh::Error` variant
//! for this reason.

use std::future::Future;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::error::AnvilError;

// ── RetryPolicy ─────────────────────────────────────────────────────────────

/// Caller-tunable retry knobs (PRD §5.8.7 FR-80, FR-81).
///
/// Use [`Default`] for the values PRD §5.8.7 specifies (`attempts =
/// 3`, `base = 250 ms`, `factor = 2`, `cap = 8 s`, `max_window = 30 s`,
/// `connect_timeout = None`).  The builder-style setters return `Self`
/// so a CLI dispatcher can chain overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total number of attempts (initial + retries).  Must be ≥ 1.
    /// `1` disables retry entirely; default `3`.
    pub attempts: u32,
    /// Base delay before the first retry.  Default 250 ms.
    pub base: Duration,
    /// Multiplier on each successive retry.  Default `2`.
    pub factor: u32,
    /// Cap on a single backoff interval (excluding jitter).  Default 8 s.
    pub cap: Duration,
    /// Hard ceiling on total elapsed wall-clock time across all
    /// attempts.  Default 30 s.  When the cap is reached the loop
    /// returns the most-recent error rather than starting another
    /// attempt.
    pub max_window: Duration,
    /// Per-attempt TCP connect timeout.  `None` = no timeout
    /// (matches OpenSSH's "no `ConnectTimeout`" semantics).
    /// Default `None`.
    pub connect_timeout: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            base: Duration::from_millis(250),
            factor: 2,
            cap: Duration::from_secs(8),
            max_window: Duration::from_secs(30),
            connect_timeout: None,
        }
    }
}

impl RetryPolicy {
    /// Builder setter for [`Self::attempts`].
    #[must_use]
    pub fn attempts(mut self, n: u32) -> Self {
        self.attempts = n;
        self
    }

    /// Builder setter for [`Self::base`].
    #[must_use]
    pub fn base(mut self, d: Duration) -> Self {
        self.base = d;
        self
    }

    /// Builder setter for [`Self::factor`].
    #[must_use]
    pub fn factor(mut self, f: u32) -> Self {
        self.factor = f;
        self
    }

    /// Builder setter for [`Self::cap`].
    #[must_use]
    pub fn cap(mut self, d: Duration) -> Self {
        self.cap = d;
        self
    }

    /// Builder setter for [`Self::max_window`].
    #[must_use]
    pub fn max_window(mut self, d: Duration) -> Self {
        self.max_window = d;
        self
    }

    /// Builder setter for [`Self::connect_timeout`].
    #[must_use]
    pub fn connect_timeout(mut self, d: Option<Duration>) -> Self {
        self.connect_timeout = d;
        self
    }
}

// ── Classifier (FR-82) ─────────────────────────────────────────────────────

/// What [`run`] should do with an [`AnvilError`] from a single attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Transient error — retry after backoff.
    Retry,
    /// Fatal error — return immediately.
    Fatal,
}

/// Classifies an [`AnvilError`] as transient or fatal per FR-82.
///
/// Transient (returns [`Disposition::Retry`]):
///
/// - I/O errors with `io::ErrorKind` ∈ {`ConnectionRefused`,
///   `TimedOut`, `HostUnreachable`, `NetworkUnreachable`, `NotFound`
///   (DNS NXDOMAIN on Linux), `AddrNotAvailable`}
///
/// Fatal (returns [`Disposition::Fatal`]):
///
/// - Authentication failure / host-key mismatch / no-key-found /
///   invalid-config / signing / signature-invalid (user-input
///   errors).
/// - Russh protocol errors — re-driving an in-flight handshake is
///   unsafe; see the module-level docs.
/// - Other I/O kinds (e.g. `PermissionDenied`, `Interrupted`) —
///   conservative default; these are unlikely to recover on retry.
///
/// **HTTP 429/503 detection** (PRD FR-82 also mentions these) is
/// out of scope: Anvil speaks raw SSH; HTTP statuses only surface
/// in `ProxyCommand` subprocess output, which Anvil doesn't parse.
/// A future ProxyCommand-HTTP-CONNECT milestone may extend this
/// classifier to handle them.
#[must_use]
pub fn classify(err: &AnvilError) -> Disposition {
    if err.is_authentication_failed()
        || err.is_host_key_mismatch()
        || err.is_no_key_found()
        || err.is_key_encrypted()
    {
        return Disposition::Fatal;
    }

    if err.is_io() {
        if let Some(kind) = err.io_kind() {
            return classify_io_kind(kind);
        }
    }

    Disposition::Fatal
}

/// Inner classifier — split out so it's testable without
/// constructing full `AnvilError`s.
fn classify_io_kind(kind: std::io::ErrorKind) -> Disposition {
    use std::io::ErrorKind as K;
    match kind {
        K::ConnectionRefused
        | K::TimedOut
        | K::HostUnreachable
        | K::NetworkUnreachable
        | K::NotFound
        | K::AddrNotAvailable => Disposition::Retry,
        _ => Disposition::Fatal,
    }
}

// ── RetryAttempt history (FR-83) ───────────────────────────────────────────

/// One failed attempt's record, captured during [`run`] for surfacing
/// via [`crate::session::AnvilSession::retry_history`] and
/// `gitway --test --json`'s `data.retry_attempts` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAttempt {
    /// 1-indexed attempt number.  An attempt that succeeds is **not**
    /// recorded here; the history vector contains only failures that
    /// triggered a retry (or the final failure when the loop bails).
    pub attempt: u32,
    /// Stable error code from [`AnvilError::error_code`].
    pub reason: String,
    /// Wall-clock elapsed since the loop started, at the moment this
    /// attempt failed.
    pub elapsed: Duration,
}

// ── Loop driver (FR-81 + FR-83) ────────────────────────────────────────────

/// Drives the retry loop for the supplied async operation.
///
/// On success returns `Ok((value, history))` where `history` is the
/// list of failed attempts (empty if the first try succeeded).  On
/// terminal failure (fatal classification or attempt-count /
/// max-window exhaustion) returns the most-recent error.
///
/// Sleep duration between attempt `n` and `n+1` is
/// `min(base * factor^(n-1), cap) + uniform_jitter([0, base/2])`.
/// Jitter is sourced from [`OsRng`] so concurrent processes recovering
/// from a shared outage don't dogpile.
///
/// # Errors
///
/// Returns the underlying `AnvilError` from the last failed attempt
/// when the loop exits without success.
pub async fn run<F, Fut, T>(
    policy: &RetryPolicy,
    mut op: F,
) -> Result<(T, Vec<RetryAttempt>), AnvilError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AnvilError>>,
{
    let started_at = Instant::now();
    let mut history: Vec<RetryAttempt> = Vec::new();
    let attempts = policy.attempts.max(1);

    for attempt in 1..=attempts {
        if attempt > 1 {
            // Sleep before retrying (jittered exponential backoff).
            let delay = backoff_delay(policy, attempt - 1);
            // Bail if max_window would be exceeded.
            if started_at.elapsed() + delay > policy.max_window {
                if let Some(last) = history.last() {
                    tracing::warn!(
                        target: crate::log::CAT_RETRY,
                        attempt = last.attempt,
                        reason = %last.reason,
                        elapsed_ms = u64::try_from(last.elapsed.as_millis()).unwrap_or(u64::MAX),
                        max_window_ms = u64::try_from(policy.max_window.as_millis()).unwrap_or(u64::MAX),
                        "retry max_window exhausted; giving up",
                    );
                }
                return Err(history_to_terminal_error(&history));
            }
            tokio::time::sleep(delay).await;
        }

        match op().await {
            Ok(value) => return Ok((value, history)),
            Err(e) => {
                let reason = e.error_code().to_owned();
                let elapsed = started_at.elapsed();
                let disposition = classify(&e);

                if disposition == Disposition::Fatal || attempt == attempts {
                    // Record the terminal attempt before returning so
                    // the caller can still see why we gave up.
                    history.push(RetryAttempt {
                        attempt,
                        reason: reason.clone(),
                        elapsed,
                    });
                    tracing::warn!(
                        target: crate::log::CAT_RETRY,
                        attempt,
                        reason = %reason,
                        elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                        disposition = if disposition == Disposition::Fatal { "fatal" } else { "exhausted" },
                        "retry loop terminating",
                    );
                    return Err(e);
                }

                history.push(RetryAttempt {
                    attempt,
                    reason: reason.clone(),
                    elapsed,
                });
                tracing::warn!(
                    target: crate::log::CAT_RETRY,
                    attempt,
                    reason = %reason,
                    elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                    "retrying after transient error",
                );
            }
        }
    }

    // Unreachable in practice (the loop body returns on every path),
    // but the type system can't prove it.
    Err(history_to_terminal_error(&history))
}

/// Returns the backoff delay for the `step`-th retry (1-indexed).
fn backoff_delay(policy: &RetryPolicy, step: u32) -> Duration {
    let base_ms = u64::try_from(policy.base.as_millis()).unwrap_or(u64::MAX);
    let exponent_ms = base_ms.saturating_mul(u64::from(policy.factor).saturating_pow(step - 1));
    let cap_ms = u64::try_from(policy.cap.as_millis()).unwrap_or(u64::MAX);
    let core_ms = exponent_ms.min(cap_ms);

    // Jitter: uniform on [0, base / 2] to avoid dogpile.  Drawn from
    // OsRng for cryptographic-grade unpredictability — overkill for
    // backoff but cheap and consistent with the rest of the crate.
    let jitter_max_ms = base_ms / 2;
    let jitter_ms = if jitter_max_ms == 0 {
        0
    } else {
        let mut buf = [0u8; 8];
        OsRng.fill_bytes(&mut buf);
        let raw = u64::from_le_bytes(buf);
        raw % (jitter_max_ms + 1)
    };

    Duration::from_millis(core_ms.saturating_add(jitter_ms))
}

/// Synthesizes an `AnvilError` from an exhausted retry history when
/// the loop bails on `max_window` before any op-call has the chance
/// to fail in the current iteration.  The history's last entry is
/// the actual cause — we surface that as an `invalid_config` since
/// we don't have the original `AnvilError` instance to clone.
fn history_to_terminal_error(history: &[RetryAttempt]) -> AnvilError {
    let last = history.last().map_or("unknown", |a| a.reason.as_str());
    AnvilError::invalid_config(format!(
        "retry exhausted (max_window reached); last error: {last}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RetryPolicy defaults ───────────────────────────────────────────────

    #[test]
    fn default_policy_matches_prd() {
        let p = RetryPolicy::default();
        assert_eq!(p.attempts, 3);
        assert_eq!(p.base, Duration::from_millis(250));
        assert_eq!(p.factor, 2);
        assert_eq!(p.cap, Duration::from_secs(8));
        assert_eq!(p.max_window, Duration::from_secs(30));
        assert_eq!(p.connect_timeout, None);
    }

    #[test]
    fn builder_setters_are_chainable() {
        let p = RetryPolicy::default()
            .attempts(5)
            .base(Duration::from_millis(100))
            .factor(3)
            .cap(Duration::from_secs(2))
            .max_window(Duration::from_secs(10))
            .connect_timeout(Some(Duration::from_secs(5)));
        assert_eq!(p.attempts, 5);
        assert_eq!(p.base, Duration::from_millis(100));
        assert_eq!(p.factor, 3);
        assert_eq!(p.cap, Duration::from_secs(2));
        assert_eq!(p.max_window, Duration::from_secs(10));
        assert_eq!(p.connect_timeout, Some(Duration::from_secs(5)));
    }

    // ── Classifier matrix (FR-82) ─────────────────────────────────────────

    #[test]
    fn auth_failure_is_fatal() {
        let err = AnvilError::authentication_failed();
        assert_eq!(classify(&err), Disposition::Fatal);
    }

    #[test]
    fn host_key_mismatch_is_fatal() {
        let err = AnvilError::host_key_mismatch("SHA256:abc");
        assert_eq!(classify(&err), Disposition::Fatal);
    }

    #[test]
    fn no_key_found_is_fatal() {
        let err = AnvilError::no_key_found();
        assert_eq!(classify(&err), Disposition::Fatal);
    }

    #[test]
    fn io_connection_refused_is_retry() {
        assert_eq!(
            classify_io_kind(std::io::ErrorKind::ConnectionRefused),
            Disposition::Retry,
        );
    }

    #[test]
    fn io_timed_out_is_retry() {
        assert_eq!(
            classify_io_kind(std::io::ErrorKind::TimedOut),
            Disposition::Retry,
        );
    }

    #[test]
    fn io_not_found_is_retry_for_dns_nxdomain() {
        assert_eq!(
            classify_io_kind(std::io::ErrorKind::NotFound),
            Disposition::Retry,
        );
    }

    #[test]
    fn io_permission_denied_is_fatal() {
        assert_eq!(
            classify_io_kind(std::io::ErrorKind::PermissionDenied),
            Disposition::Fatal,
        );
    }

    // ── Loop driver ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_succeeds_on_first_try_with_empty_history() {
        let p = RetryPolicy::default().attempts(3);
        let (value, history) = run(&p, || async { Ok::<_, AnvilError>(42_u32) })
            .await
            .expect("must succeed");
        assert_eq!(value, 42);
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn run_bails_immediately_on_fatal() {
        let p = RetryPolicy::default().attempts(5);
        let (err_count, _) = run_count_calls(&p, |_n| {
            futures::future::ready::<Result<u32, AnvilError>>(Err(
                AnvilError::authentication_failed(),
            ))
        })
        .await;
        // Fatal error → 1 attempt, no retry.
        assert_eq!(err_count, 1);
    }

    #[tokio::test]
    async fn run_retries_transient_errors_and_records_history() {
        let p = RetryPolicy::default()
            .attempts(3)
            .base(Duration::from_millis(1))
            .cap(Duration::from_millis(2))
            .max_window(Duration::from_secs(60));

        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: Result<(u32, Vec<RetryAttempt>), AnvilError> = run(&p, || async {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 2 {
                Err(AnvilError::new(crate::error::AnvilErrorKind::Io(
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                )))
            } else {
                Ok::<_, AnvilError>(99)
            }
        })
        .await;

        let (value, history) = result.expect("third attempt must succeed");
        assert_eq!(value, 99);
        // Two failures recorded, third succeeded.
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].attempt, 1);
        assert_eq!(history[1].attempt, 2);
        // I/O errors map to AnvilError::error_code() == "GENERAL_ERROR"
        // per the error-code table in error.rs.
        for entry in &history {
            assert_eq!(
                entry.reason, "GENERAL_ERROR",
                "expected GENERAL_ERROR (io variant), got: {}",
                entry.reason,
            );
        }
    }

    #[tokio::test]
    async fn run_attempts_caps_after_exhausting_count() {
        let p = RetryPolicy::default()
            .attempts(2)
            .base(Duration::from_millis(1))
            .cap(Duration::from_millis(1))
            .max_window(Duration::from_secs(60));

        let result: Result<(u32, Vec<RetryAttempt>), AnvilError> = run(&p, || async {
            Err(AnvilError::new(crate::error::AnvilErrorKind::Io(
                std::io::Error::from(std::io::ErrorKind::TimedOut),
            )))
        })
        .await;

        // Both attempts must run; result is the last error.
        let err = result.expect_err("must exhaust");
        assert!(err.is_io());
    }

    /// Helper: counts how many times `op` was called before `run`
    /// returned, regardless of success / failure.
    async fn run_count_calls<F, Fut>(
        policy: &RetryPolicy,
        mut op: F,
    ) -> (u32, Result<u32, AnvilError>)
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<u32, AnvilError>>,
    {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: Result<(u32, Vec<RetryAttempt>), AnvilError> = run(policy, || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            op(n)
        })
        .await;
        let count = calls.load(std::sync::atomic::Ordering::SeqCst);
        let final_result = result.map(|(v, _)| v);
        (count, final_result)
    }

    // ── Backoff curve ──────────────────────────────────────────────────────

    #[test]
    fn backoff_delay_grows_exponentially_until_cap() {
        let p = RetryPolicy::default()
            .base(Duration::from_millis(10))
            .factor(2)
            .cap(Duration::from_millis(40));
        // Step 1: 10ms (+ jitter ≤ 5ms)
        // Step 2: 20ms (+ jitter ≤ 5ms)
        // Step 3: 40ms (+ jitter ≤ 5ms) — capped
        // Step 4: 40ms (+ jitter ≤ 5ms) — still capped
        let d1 = backoff_delay(&p, 1);
        let d2 = backoff_delay(&p, 2);
        let d3 = backoff_delay(&p, 3);
        let d4 = backoff_delay(&p, 4);
        assert!(d1.as_millis() >= 10 && d1.as_millis() <= 15);
        assert!(d2.as_millis() >= 20 && d2.as_millis() <= 25);
        assert!(d3.as_millis() >= 40 && d3.as_millis() <= 45);
        assert!(d4.as_millis() >= 40 && d4.as_millis() <= 45);
    }

    #[test]
    fn backoff_jitter_stays_within_documented_window() {
        // 1000 draws with base = 10ms, factor = 1, cap = 10ms ⇒ all
        // sleeps are exactly 10ms + jitter([0, 5ms]).
        let p = RetryPolicy::default()
            .base(Duration::from_millis(10))
            .factor(1)
            .cap(Duration::from_millis(10));
        for _ in 0..1000 {
            let d = backoff_delay(&p, 1);
            let ms = d.as_millis();
            assert!(
                (10..=15).contains(&ms),
                "delay {ms}ms outside [10,15]ms jitter window",
            );
        }
    }
}
