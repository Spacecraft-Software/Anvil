// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-04-05
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! # anvil-ssh
//!
//! Pure-Rust SSH library for Git: transport, keys, signing, agent.
//!
//! Built on [`russh`](https://docs.rs/russh) v0.59, it replaces the
//! general-purpose `ssh` binary in the Git transport pipeline, plus the
//! subset of `ssh-keygen`, `ssh-add`, and `ssh-agent` that day-to-day Git
//! workflows need.  Works against GitHub, GitLab, Codeberg, AUR, sourcehut,
//! and self-hosted Git instances.
//!
//! ## Quick start
//!
//! ```no_run
//! use anvil_ssh::{AnvilConfig, AnvilSession};
//!
//! # async fn doc() -> Result<(), anvil_ssh::AnvilError> {
//! // GitHub
//! let config = AnvilConfig::github();
//! // GitLab
//! let config = AnvilConfig::gitlab();
//! // Codeberg
//! let config = AnvilConfig::codeberg();
//!
//! let mut session = AnvilSession::connect(&config).await?;
//! session.authenticate_best(&config).await?;
//!
//! let exit_code = session.exec("git-upload-pack 'user/repo.git'").await?;
//! session.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design principles
//!
//! - **Pinned host keys** — SHA-256 fingerprints for GitHub, GitLab, and
//!   Codeberg are embedded; no TOFU (Trust On First Use) for known hosts.
//! - **Narrow scope** — only exec channels; no PTY, SFTP, or port forwarding.
//! - **Post-quantum ready** — uses `aws-lc-rs` for cryptography.
//! - **Metric / SI / ISO 8601** throughout all timestamps and measurements.

pub mod agent;
pub mod allowed_signers;
pub mod auth;
pub mod cert_authority;
pub mod config;
pub mod diagnostic;
pub mod error;
pub mod hostkey;
pub mod keygen;
pub mod proxy;
pub mod relay;
pub mod session;
pub mod sshsig;
pub mod time;

// `ssh_config(5)` parser and resolver.  Public API is re-exported below;
// the sub-modules (lexer, parser, include, matcher, resolver) themselves
// are crate-private.
pub mod ssh_config;

// ── Flat re-exports (FR-23) ───────────────────────────────────────────────────

pub use config::AnvilConfig;
pub use error::AnvilError;
pub use session::AnvilSession;
pub use ssh_config::{
    AlgList, DirectiveSource, ResolvedSshConfig, SshConfigPaths, StrictHostKeyChecking,
};

// ── Deprecated 0.1.x compatibility aliases ────────────────────────────────────
//
// Re-export the renamed types under their legacy `Gitway*` names so that
// crates which depended on `anvil-ssh = "0.1"` (or the `gitway-lib` shim
// that re-exports `anvil_ssh::*`) continue to compile after the 0.2.0
// rename.  These aliases emit a `#[deprecated]` warning on use; remove
// them in 1.0 per Gitway PRD §7.4.

#[deprecated(since = "0.2.0", note = "renamed to `AnvilSession`")]
pub use AnvilSession as GitwaySession;

#[deprecated(since = "0.2.0", note = "renamed to `AnvilConfig`")]
pub use AnvilConfig as GitwayConfig;

#[deprecated(since = "0.2.0", note = "renamed to `AnvilError`")]
pub use AnvilError as GitwayError;
