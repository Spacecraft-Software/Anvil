// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
// Updated 2026-04-12: added error_code(), exit_code(), hint() for SFRS Rule 2/5
//! Error types for `anvil-ssh`.
//!
//! # Examples
//!
//! ```rust
//! use anvil_ssh::GitwayError;
//!
//! fn handle(err: &GitwayError) {
//!     if err.is_host_key_mismatch() {
//!         eprintln!("Possible MITM — host key does not match pinned fingerprints.");
//!     }
//! }
//! ```

use std::backtrace::Backtrace;
use std::fmt;

// ── Inner error kind ──────────────────────────────────────────────────────────

/// Internal discriminant for [`GitwayError`].
///
/// Not part of the public API; callers use the `is_*` predicate methods.
#[derive(Debug)]
pub(crate) enum GitwayErrorKind {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// russh protocol-level error.
    Ssh(russh::Error),
    /// russh key loading / parsing error.
    Keys(russh::keys::Error),
    /// The server's host key did not match any pinned fingerprint.
    ///
    /// `fingerprint` is the SHA-256 fingerprint that was actually received
    /// (formatted as `"SHA256:<base64>"`).
    HostKeyMismatch { fingerprint: String },
    /// Public-key authentication was rejected by the server.
    AuthenticationFailed,
    /// No usable identity key was found on any search path or agent.
    NoKeyFound,
    /// Configuration is logically invalid.
    InvalidConfig { message: String },
    /// SSH signature production failed (bad key, I/O, encoding).
    Signing { message: String },
    /// SSH signature verification failed (tampering, wrong signer, namespace mismatch).
    SignatureInvalid { reason: String },
}

impl fmt::Display for GitwayErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Ssh(e) => write!(f, "SSH protocol error: {e}"),
            Self::Keys(e) => write!(f, "SSH key error: {e}"),
            Self::HostKeyMismatch { fingerprint } => {
                write!(
                    f,
                    "host key mismatch — received fingerprint {fingerprint} \
                     does not match any pinned fingerprint"
                )
            }
            Self::AuthenticationFailed => write!(f, "public-key authentication failed"),
            Self::NoKeyFound => {
                write!(f, "no SSH identity key found on any search path or agent")
            }
            Self::InvalidConfig { message } => write!(f, "invalid configuration: {message}"),
            Self::Signing { message } => write!(f, "SSH signing failed: {message}"),
            Self::SignatureInvalid { reason } => {
                write!(f, "SSH signature verification failed: {reason}")
            }
        }
    }
}

// ── Public error type ─────────────────────────────────────────────────────────

/// The single error type returned by all `anvil-ssh` operations.
///
/// Provides `is_*` predicate methods so callers can branch on error categories
/// without depending on internal representation. A [`Backtrace`] is captured
/// automatically; it is rendered via [`std::fmt::Display`] when
/// `RUST_BACKTRACE=1` is set.
///
/// # Predicates
///
/// | Method | Condition |
/// |---|---|
/// | [`is_io`](GitwayError::is_io) | Underlying I/O failure |
/// | [`is_host_key_mismatch`](GitwayError::is_host_key_mismatch) | Server key does not match pinned fingerprints |
/// | [`is_authentication_failed`](GitwayError::is_authentication_failed) | Server rejected our key |
/// | [`is_no_key_found`](GitwayError::is_no_key_found) | No identity key available |
/// | [`is_key_encrypted`](GitwayError::is_key_encrypted) | Key file needs a passphrase |
#[derive(Debug)]
pub struct GitwayError {
    kind: GitwayErrorKind,
    /// Optional per-instance hint override.  When set, [`hint`](GitwayError::hint)
    /// returns this string instead of the static default chosen from
    /// [`GitwayErrorKind`].
    ///
    /// Context-specific hints fire much more precisely than the kind-level
    /// defaults: an `InvalidConfig` error from the `-E` flag parser can
    /// say "pass `sha256` or `sha512` to `-E`", while an `InvalidConfig`
    /// error from the sign path can say "load the key into the agent".
    /// The kind-level default stays as the catch-all fallback.
    custom_hint: Option<String>,
    backtrace: Backtrace,
}

impl GitwayError {
    /// Constructs a new [`GitwayError`] capturing the current backtrace.
    pub(crate) fn new(kind: GitwayErrorKind) -> Self {
        Self {
            kind,
            custom_hint: None,
            backtrace: Backtrace::capture(),
        }
    }

    /// Attaches a context-specific hint that supersedes the kind-level
    /// default returned by [`hint`](GitwayError::hint).
    ///
    /// Use this at call sites where the caller knows exactly what the
    /// user should do next — much more useful than a generic "run
    /// `gitway --help`".
    ///
    /// # Example
    ///
    /// ```rust
    /// use anvil_ssh::GitwayError;
    ///
    /// let e = GitwayError::invalid_config("no such host: github.com.invalid")
    ///     .with_hint("Check the hostname for typos, or run `gitway --test <host>` to confirm reachability");
    /// assert!(e.hint().contains("typos"));
    /// ```
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.custom_hint = Some(hint.into());
        self
    }

    // ── Constructors for common variants ─────────────────────────────────────

    pub fn host_key_mismatch(fingerprint: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::HostKeyMismatch {
            fingerprint: fingerprint.into(),
        })
    }

    #[must_use]
    pub fn authentication_failed() -> Self {
        Self::new(GitwayErrorKind::AuthenticationFailed)
    }

    #[must_use]
    pub fn no_key_found() -> Self {
        Self::new(GitwayErrorKind::NoKeyFound)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::InvalidConfig {
            message: message.into(),
        })
    }

    /// Signals that SSH signature production failed.
    ///
    /// Mapped to exit code 1 (`GENERAL_ERROR`).
    pub fn signing(message: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::Signing {
            message: message.into(),
        })
    }

    /// Signals that SSH signature verification failed.
    ///
    /// Mapped to exit code 4 (`PERMISSION_DENIED`) to match git's treatment
    /// of a non-zero `ssh-keygen -Y verify` as an authentication-class failure.
    pub fn signature_invalid(reason: impl Into<String>) -> Self {
        Self::new(GitwayErrorKind::SignatureInvalid {
            reason: reason.into(),
        })
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    /// Returns `true` if this error originated from an I/O failure.
    #[must_use]
    pub fn is_io(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::Io(_))
    }

    /// Returns `true` if the server's host key did not match any pinned fingerprint.
    #[must_use]
    pub fn is_host_key_mismatch(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::HostKeyMismatch { .. })
    }

    /// Returns `true` if the server rejected our public-key authentication attempt.
    #[must_use]
    pub fn is_authentication_failed(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::AuthenticationFailed)
    }

    /// Returns `true` if no usable identity key was found.
    #[must_use]
    pub fn is_no_key_found(&self) -> bool {
        matches!(self.kind, GitwayErrorKind::NoKeyFound)
    }

    /// Returns `true` if a key file was found but requires a passphrase to decrypt.
    #[must_use]
    pub fn is_key_encrypted(&self) -> bool {
        matches!(
            self.kind,
            GitwayErrorKind::Keys(russh::keys::Error::KeyIsEncrypted)
        )
    }

    /// Returns the path at which an encrypted key was found, if applicable.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        match &self.kind {
            GitwayErrorKind::HostKeyMismatch { fingerprint } => Some(fingerprint),
            _ => None,
        }
    }

    /// Returns an upper-snake-case error code for structured JSON output (SFRS Rule 5).
    ///
    /// | Code | Exit code | Condition |
    /// |------|-----------|-----------|
    /// | `GENERAL_ERROR` | 1 | I/O, SSH protocol, or key-parsing failure |
    /// | `USAGE_ERROR` | 2 | Invalid configuration or bad arguments |
    /// | `NOT_FOUND` | 3 | No identity key found |
    /// | `PERMISSION_DENIED` | 4 | Host key mismatch or authentication failure |
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match &self.kind {
            GitwayErrorKind::InvalidConfig { .. } => "USAGE_ERROR",
            GitwayErrorKind::NoKeyFound => "NOT_FOUND",
            GitwayErrorKind::HostKeyMismatch { .. }
            | GitwayErrorKind::AuthenticationFailed
            | GitwayErrorKind::SignatureInvalid { .. } => "PERMISSION_DENIED",
            GitwayErrorKind::Io(_)
            | GitwayErrorKind::Ssh(_)
            | GitwayErrorKind::Keys(_)
            | GitwayErrorKind::Signing { .. } => "GENERAL_ERROR",
        }
    }

    /// Returns the numeric process exit code for this error (SFRS Rule 2).
    ///
    /// | Code | Meaning |
    /// |------|---------|
    /// | 1 | General / unexpected error |
    /// | 2 | Usage error (bad arguments, invalid configuration) |
    /// | 3 | Not found (no identity key, unknown host) |
    /// | 4 | Permission denied (authentication failure, host key mismatch) |
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match &self.kind {
            GitwayErrorKind::InvalidConfig { .. } => 2,
            GitwayErrorKind::NoKeyFound => 3,
            GitwayErrorKind::HostKeyMismatch { .. }
            | GitwayErrorKind::AuthenticationFailed
            | GitwayErrorKind::SignatureInvalid { .. } => 4,
            GitwayErrorKind::Io(_)
            | GitwayErrorKind::Ssh(_)
            | GitwayErrorKind::Keys(_)
            | GitwayErrorKind::Signing { .. } => 1,
        }
    }

    /// Returns a short "what to do next" line for the user.
    ///
    /// Call-site-specific hints attached via [`with_hint`](Self::with_hint)
    /// take priority.  Otherwise the kind-level default is returned —
    /// these are deliberately phrased in plain English and prescriptive
    /// voice (tell the reader what to type, not what went wrong; the
    /// [`Display`](std::fmt::Display) output already says what went wrong).
    ///
    /// Emitted on stderr after the error message in human mode, and
    /// carried as the `hint` field in `--json` output (SFRS Rule 5).
    #[must_use]
    pub fn hint(&self) -> &str {
        if let Some(h) = self.custom_hint.as_deref() {
            return h;
        }
        match &self.kind {
            GitwayErrorKind::HostKeyMismatch { .. } => {
                "The server's SSH fingerprint doesn't match what gitway trusts. \
                 This is either a routine key rotation by the provider or a \
                 possible man-in-the-middle attack. Compare the received \
                 fingerprint against the provider's official list; if you \
                 trust it, add it to ~/.config/gitway/known_hosts."
            }
            GitwayErrorKind::AuthenticationFailed => {
                "The server rejected your SSH key. Two things to check: the \
                 public key is registered in the provider's account settings, \
                 and the private key is loaded (run `gitway-add ~/.ssh/id_ed25519`)."
            }
            GitwayErrorKind::NoKeyFound => {
                "No SSH key was found. Generate one with `gitway keygen ed25519 \
                 --out ~/.ssh/id_ed25519`, or point gitway at an existing key \
                 via `--identity <path>`."
            }
            GitwayErrorKind::InvalidConfig { .. } => {
                "Something in your command or config is off. Run `gitway --help` \
                 to see accepted flags, or re-read the error message above — \
                 it usually names the exact argument to fix."
            }
            GitwayErrorKind::Signing { .. } => {
                "Signing the commit failed. If the key is encrypted, either \
                 load it into the agent (`gitway-add <key>`) so signing can \
                 use it without a passphrase, or set SSH_ASKPASS to a GUI \
                 helper so you can type the passphrase in a dialog."
            }
            GitwayErrorKind::SignatureInvalid { .. } => {
                "The signature doesn't match. Either the signed data was \
                 changed after signing, a different key produced it, or the \
                 namespace (usually `git`) is different."
            }
            GitwayErrorKind::Io(_) | GitwayErrorKind::Ssh(_) | GitwayErrorKind::Keys(_) => {
                "Something broke before the SSH session was fully set up. \
                 Run `gitway --test --verbose <host>` to see where it fails."
            }
        }
    }
}

// ── Trait implementations ─────────────────────────────────────────────────────

impl fmt::Display for GitwayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        let bt = self.backtrace.to_string();
        if !bt.is_empty() && bt != "disabled backtrace" {
            write!(f, "\n\nstack backtrace:\n{bt}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GitwayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            GitwayErrorKind::Io(e) => Some(e),
            GitwayErrorKind::Ssh(e) => Some(e),
            GitwayErrorKind::Keys(e) => Some(e),
            _ => None,
        }
    }
}

impl From<russh::Error> for GitwayError {
    fn from(e: russh::Error) -> Self {
        Self::new(GitwayErrorKind::Ssh(e))
    }
}

impl From<russh::keys::Error> for GitwayError {
    fn from(e: russh::keys::Error) -> Self {
        Self::new(GitwayErrorKind::Keys(e))
    }
}

impl From<std::io::Error> for GitwayError {
    fn from(e: std::io::Error) -> Self {
        Self::new(GitwayErrorKind::Io(e))
    }
}

impl From<russh::AgentAuthError> for GitwayError {
    fn from(e: russh::AgentAuthError) -> Self {
        match e {
            russh::AgentAuthError::Send(_) => {
                Self::new(GitwayErrorKind::Ssh(russh::Error::SendError))
            }
            russh::AgentAuthError::Key(k) => Self::new(GitwayErrorKind::Keys(k)),
        }
    }
}
