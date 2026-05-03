// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Configuration builder for an [`AnvilSession`](crate::AnvilSession).
//!
//! # 0.3.0 API break
//!
//! Two fields changed shape in 0.3.0 to align with `ssh_config(5)`:
//!
//! - `identity_file: Option<PathBuf>` -> `identity_files: Vec<PathBuf>`.
//!   OpenSSH allows multiple `IdentityFile` directives; the resolver and
//!   the auth path now honour the full list in order.  Reads of the old
//!   single-path getter still work via the `#[deprecated]` shim.
//! - `skip_host_check: bool` -> `strict_host_key_checking:
//!   StrictHostKeyChecking`.  The new enum encodes `Yes` / `No` /
//!   `AcceptNew`, matching `ssh_config(5)`.  The old boolean getter and
//!   builder method continue to work via deprecation shims.
//!
//! # Examples
//!
//! ```rust
//! use anvil_ssh::AnvilConfig;
//! use std::time::Duration;
//!
//! // Connect to GitHub (default):
//! let config = AnvilConfig::github();
//!
//! // Connect to GitLab:
//! let config = AnvilConfig::gitlab();
//!
//! // Connect to Codeberg:
//! let config = AnvilConfig::codeberg();
//!
//! // Connect to any host with a custom port:
//! let config = AnvilConfig::builder("git.example.com")
//!     .port(22)
//!     .username("git")
//!     .inactivity_timeout(Duration::from_secs(60))
//!     .build();
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::hostkey::{
    DEFAULT_CODEBERG_HOST, DEFAULT_GITHUB_HOST, DEFAULT_GITLAB_HOST, DEFAULT_PORT, FALLBACK_PORT,
    GITHUB_FALLBACK_HOST, GITLAB_FALLBACK_HOST,
};
use crate::ssh_config::{ResolvedSshConfig, StrictHostKeyChecking};

// ── Public config type ────────────────────────────────────────────────────────

/// Immutable configuration for an [`AnvilSession`](crate::AnvilSession).
///
/// Construct via [`AnvilConfig::builder`], or use one of the convenience
/// constructors ([`github`](Self::github), [`gitlab`](Self::gitlab),
/// [`codeberg`](Self::codeberg)) for the most common targets.
#[derive(Debug, Clone)]
pub struct AnvilConfig {
    /// Primary SSH host (e.g. `github.com`, `gitlab.com`, `codeberg.org`).
    pub host: String,
    /// Primary SSH port (default: 22).
    pub port: u16,
    /// Remote username (always `git` for hosted services; FR-13).
    pub username: String,
    /// Ordered list of identity-file paths.  Tried in source order during
    /// authentication; an empty list falls through to the default search
    /// path (`~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`).  Populated by
    /// `IdentityFile` directives from `ssh_config`, by the
    /// [`AnvilConfigBuilder::add_identity_file`] /
    /// [`AnvilConfigBuilder::identity_files`] builder methods, and (for
    /// 0.2.x compatibility) by the deprecated
    /// [`AnvilConfigBuilder::identity_file`] method.
    pub identity_files: Vec<PathBuf>,
    /// OpenSSH certificate path supplied via `--cert` (FR-12).
    pub cert_file: Option<PathBuf>,
    /// Host-key verification policy.  Defaults to
    /// [`StrictHostKeyChecking::Yes`].
    pub strict_host_key_checking: StrictHostKeyChecking,
    /// Inactivity timeout for the SSH session (FR-5).
    ///
    /// GitHub's idle threshold is around 60 s; this is the configured
    /// client-side inactivity timeout, not a per-packet deadline.
    pub inactivity_timeout: Duration,
    /// Path to a `known_hosts`-style file for custom or self-hosted instances
    /// (FR-7).  Format: one `hostname SHA256:<fp>` entry per line.
    pub custom_known_hosts: Option<PathBuf>,
    /// Enable verbose debug logging when `true`.
    pub verbose: bool,
    /// Optional fallback host when port 22 is unavailable (FR-1).
    ///
    /// GitHub: `ssh.github.com:443`. GitLab: `altssh.gitlab.com:443`.
    /// Codeberg has no published port-443 fallback.
    pub fallback: Option<(String, u16)>,
}

impl AnvilConfig {
    /// Begin building a config targeting `host`.
    ///
    /// All optional fields default to sensible values. No fallback host is
    /// set by default; use the provider-specific convenience constructors
    /// ([`github`](Self::github), [`gitlab`](Self::gitlab)) if you want the
    /// port-443 fallback pre-configured.
    pub fn builder(host: impl Into<String>) -> AnvilConfigBuilder {
        AnvilConfigBuilder::new(host.into())
    }

    /// Convenience constructor for the default GitHub target (`github.com:22`).
    ///
    /// Includes the `ssh.github.com:443` fallback pre-configured.
    #[must_use]
    pub fn github() -> Self {
        Self::builder(DEFAULT_GITHUB_HOST)
            .fallback(Some((GITHUB_FALLBACK_HOST.to_owned(), FALLBACK_PORT)))
            .build()
    }

    /// Convenience constructor for the default GitLab target (`gitlab.com:22`).
    ///
    /// Includes the `altssh.gitlab.com:443` fallback pre-configured.
    #[must_use]
    pub fn gitlab() -> Self {
        Self::builder(DEFAULT_GITLAB_HOST)
            .fallback(Some((GITLAB_FALLBACK_HOST.to_owned(), FALLBACK_PORT)))
            .build()
    }

    /// Convenience constructor for Codeberg (`codeberg.org:22`).
    ///
    /// Codeberg has no published port-443 SSH fallback; no fallback is set.
    #[must_use]
    pub fn codeberg() -> Self {
        Self::builder(DEFAULT_CODEBERG_HOST).build()
    }

    /// First identity-file path, or `None` if [`Self::identity_files`] is
    /// empty.  Provided as a 0.2.x compatibility shim — new code should
    /// read [`Self::identity_files`] directly.
    #[deprecated(since = "0.3.0", note = "read `identity_files` directly")]
    #[must_use]
    pub fn identity_file(&self) -> Option<&Path> {
        self.identity_files.first().map(PathBuf::as_path)
    }

    /// `true` when [`Self::strict_host_key_checking`] is
    /// [`StrictHostKeyChecking::No`].  Provided as a 0.2.x compatibility
    /// shim — new code should read [`Self::strict_host_key_checking`]
    /// directly.
    #[deprecated(since = "0.3.0", note = "read `strict_host_key_checking` directly")]
    #[must_use]
    pub fn skip_host_check(&self) -> bool {
        matches!(self.strict_host_key_checking, StrictHostKeyChecking::No)
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`AnvilConfig`].
///
/// Obtained via [`AnvilConfig::builder`].
#[derive(Debug)]
#[must_use]
pub struct AnvilConfigBuilder {
    host: String,
    port: u16,
    username: String,
    identity_files: Vec<PathBuf>,
    cert_file: Option<PathBuf>,
    strict_host_key_checking: StrictHostKeyChecking,
    inactivity_timeout: Duration,
    custom_known_hosts: Option<PathBuf>,
    verbose: bool,
    fallback: Option<(String, u16)>,
}

impl AnvilConfigBuilder {
    fn new(host: String) -> Self {
        Self {
            host,
            port: DEFAULT_PORT,
            username: "git".to_owned(),
            identity_files: Vec::new(),
            cert_file: None,
            strict_host_key_checking: StrictHostKeyChecking::Yes,
            // 60 seconds — large enough to survive slow host responses.
            // Changing this below ~10 s risks spurious timeouts on congested
            // links.
            inactivity_timeout: Duration::from_secs(60),
            custom_known_hosts: None,
            verbose: false,
            // No fallback by default; provider-specific convenience
            // constructors set this when a known fallback exists.
            fallback: None,
        }
    }

    /// Override the target SSH port (default: 22, FR-1).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the remote username (default: `"git"`, FR-13).
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Append `path` to the ordered identity-file list (FR-9).
    ///
    /// Use this to add CLI-supplied keys; ssh_config-supplied keys flow
    /// in through [`Self::apply_ssh_config`].  Both can coexist; auth
    /// tries them in the order they were added.
    pub fn add_identity_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_files.push(path.into());
        self
    }

    /// Replace the entire identity-file list with `paths`.  Existing
    /// entries are discarded.
    pub fn identity_files(mut self, paths: Vec<PathBuf>) -> Self {
        self.identity_files = paths;
        self
    }

    /// Set a single identity-file path, replacing any existing entries.
    ///
    /// 0.2.x compatibility shim.  New code should use
    /// [`Self::add_identity_file`] (additive) or [`Self::identity_files`]
    /// (replace-all) for clarity.
    #[deprecated(
        since = "0.3.0",
        note = "use `add_identity_file` or `identity_files` for the multi-key API"
    )]
    pub fn identity_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_files.clear();
        self.identity_files.push(path.into());
        self
    }

    /// Set an OpenSSH certificate path (FR-12).
    pub fn cert_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_file = Some(path.into());
        self
    }

    /// Set the host-key verification policy (FR-8).
    pub fn strict_host_key_checking(mut self, policy: StrictHostKeyChecking) -> Self {
        self.strict_host_key_checking = policy;
        self
    }

    /// Disable host-key verification.  **Use only for emergencies** (FR-8).
    ///
    /// `true` maps to [`StrictHostKeyChecking::No`]; `false` to
    /// [`StrictHostKeyChecking::Yes`].  Lossless from the 0.2.x boolean
    /// shape (which only encoded those two states).
    #[deprecated(
        since = "0.3.0",
        note = "use `strict_host_key_checking(StrictHostKeyChecking::No)` for clarity"
    )]
    pub fn skip_host_check(mut self, skip: bool) -> Self {
        self.strict_host_key_checking = if skip {
            StrictHostKeyChecking::No
        } else {
            StrictHostKeyChecking::Yes
        };
        self
    }

    /// Override the session inactivity timeout (FR-5).
    pub fn inactivity_timeout(mut self, timeout: Duration) -> Self {
        self.inactivity_timeout = timeout;
        self
    }

    /// Path to a custom `known_hosts`-style file for self-hosted instances
    /// (FR-7).
    pub fn custom_known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.custom_known_hosts = Some(path.into());
        self
    }

    /// Enable verbose debug logging.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Override the fallback host/port.  Pass `None` to disable fallback.
    pub fn fallback(mut self, fallback: Option<(String, u16)>) -> Self {
        self.fallback = fallback;
        self
    }

    /// Layer values from a [`ResolvedSshConfig`] into this builder.
    ///
    /// Provides ssh_config-derived defaults that subsequent builder calls
    /// can still override (call this *before* CLI-derived overrides if
    /// you want CLI to win).  The following mappings are applied:
    ///
    /// | `ssh_config` directive | Builder field |
    /// |---|---|
    /// | `HostName` | `host` (overridden) |
    /// | `Port` | `port` (overridden) |
    /// | `User` | `username` (overridden) |
    /// | `IdentityFile` (multi) | `identity_files` (extended) |
    /// | `StrictHostKeyChecking` | `strict_host_key_checking` (overridden) |
    /// | `UserKnownHostsFile` (first) | `custom_known_hosts` (filled if `None`) |
    ///
    /// Algorithm directives (`HostKeyAlgorithms`, `KexAlgorithms`,
    /// `Ciphers`, `MACs`) and `ConnectTimeout` / `ConnectionAttempts` are
    /// not yet plumbed through to the session builder; they are recorded
    /// in [`ResolvedSshConfig`] for `gitway config show` but consumption
    /// is deferred to M17 / M18.
    pub fn apply_ssh_config(mut self, resolved: &ResolvedSshConfig) -> Self {
        if let Some(hostname) = &resolved.hostname {
            self.host.clone_from(hostname);
        }
        if let Some(port) = resolved.port {
            self.port = port;
        }
        if let Some(user) = &resolved.user {
            self.username.clone_from(user);
        }
        self.identity_files
            .extend(resolved.identity_files.iter().cloned());
        if let Some(policy) = resolved.strict_host_key_checking {
            self.strict_host_key_checking = policy;
        }
        if self.custom_known_hosts.is_none() {
            if let Some(p) = resolved.user_known_hosts_files.first() {
                self.custom_known_hosts = Some(p.clone());
            }
        }
        self
    }

    /// Finalise and return the [`AnvilConfig`].
    #[must_use]
    pub fn build(self) -> AnvilConfig {
        AnvilConfig {
            host: self.host,
            port: self.port,
            username: self.username,
            identity_files: self.identity_files,
            cert_file: self.cert_file,
            strict_host_key_checking: self.strict_host_key_checking,
            inactivity_timeout: self.inactivity_timeout,
            custom_known_hosts: self.custom_known_hosts,
            verbose: self.verbose,
            fallback: self.fallback,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_yes_strict_host_check() {
        let cfg = AnvilConfig::builder("h").build();
        assert_eq!(cfg.strict_host_key_checking, StrictHostKeyChecking::Yes);
        assert!(cfg.identity_files.is_empty());
    }

    #[test]
    fn add_identity_file_accumulates() {
        let cfg = AnvilConfig::builder("h")
            .add_identity_file(PathBuf::from("/a"))
            .add_identity_file(PathBuf::from("/b"))
            .build();
        assert_eq!(
            cfg.identity_files,
            vec![PathBuf::from("/a"), PathBuf::from("/b")],
        );
    }

    #[test]
    fn identity_files_replaces_list() {
        let cfg = AnvilConfig::builder("h")
            .add_identity_file(PathBuf::from("/old"))
            .identity_files(vec![PathBuf::from("/new1"), PathBuf::from("/new2")])
            .build();
        assert_eq!(
            cfg.identity_files,
            vec![PathBuf::from("/new1"), PathBuf::from("/new2")],
        );
    }

    #[test]
    #[allow(deprecated, reason = "exercising the deprecated shim")]
    fn deprecated_identity_file_shim_clears_then_pushes() {
        let cfg = AnvilConfig::builder("h")
            .add_identity_file(PathBuf::from("/should_be_cleared"))
            .identity_file(PathBuf::from("/single"))
            .build();
        assert_eq!(cfg.identity_files, vec![PathBuf::from("/single")]);
        // The deprecated accessor returns the first identity file.
        assert_eq!(cfg.identity_file(), Some(Path::new("/single")));
    }

    #[test]
    #[allow(deprecated, reason = "exercising the deprecated shim")]
    fn deprecated_skip_host_check_maps_to_enum() {
        let cfg_skip = AnvilConfig::builder("h").skip_host_check(true).build();
        assert_eq!(cfg_skip.strict_host_key_checking, StrictHostKeyChecking::No);
        assert!(cfg_skip.skip_host_check());

        let cfg_check = AnvilConfig::builder("h").skip_host_check(false).build();
        assert_eq!(
            cfg_check.strict_host_key_checking,
            StrictHostKeyChecking::Yes,
        );
        assert!(!cfg_check.skip_host_check());
    }

    #[test]
    fn strict_host_key_checking_accepts_all_three() {
        for policy in [
            StrictHostKeyChecking::Yes,
            StrictHostKeyChecking::No,
            StrictHostKeyChecking::AcceptNew,
        ] {
            let cfg = AnvilConfig::builder("h")
                .strict_host_key_checking(policy)
                .build();
            assert_eq!(cfg.strict_host_key_checking, policy);
        }
    }

    #[test]
    fn apply_ssh_config_layers_resolved_values() {
        let resolved = ResolvedSshConfig {
            hostname: Some("real.example.com".to_owned()),
            user: Some("alice".to_owned()),
            port: Some(2222),
            identity_files: vec![PathBuf::from("/cfg/key")],
            strict_host_key_checking: Some(StrictHostKeyChecking::AcceptNew),
            user_known_hosts_files: vec![PathBuf::from("/cfg/known_hosts")],
            ..ResolvedSshConfig::default()
        };
        let cfg = AnvilConfig::builder("alias")
            .apply_ssh_config(&resolved)
            .build();
        assert_eq!(cfg.host, "real.example.com");
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.identity_files, vec![PathBuf::from("/cfg/key")]);
        assert_eq!(
            cfg.strict_host_key_checking,
            StrictHostKeyChecking::AcceptNew,
        );
        assert_eq!(
            cfg.custom_known_hosts,
            Some(PathBuf::from("/cfg/known_hosts"))
        );
    }

    #[test]
    fn apply_ssh_config_extends_identity_files_does_not_replace() {
        let resolved = ResolvedSshConfig {
            identity_files: vec![PathBuf::from("/cfg/a")],
            ..ResolvedSshConfig::default()
        };
        let cfg = AnvilConfig::builder("h")
            .add_identity_file(PathBuf::from("/cli/first"))
            .apply_ssh_config(&resolved)
            .build();
        // CLI ones come first, ssh_config appends after.
        assert_eq!(
            cfg.identity_files,
            vec![PathBuf::from("/cli/first"), PathBuf::from("/cfg/a")],
        );
    }

    #[test]
    fn apply_ssh_config_does_not_overwrite_explicit_known_hosts() {
        let resolved = ResolvedSshConfig {
            user_known_hosts_files: vec![PathBuf::from("/from/cfg")],
            ..ResolvedSshConfig::default()
        };
        let cfg = AnvilConfig::builder("h")
            .custom_known_hosts(PathBuf::from("/from/cli"))
            .apply_ssh_config(&resolved)
            .build();
        assert_eq!(cfg.custom_known_hosts, Some(PathBuf::from("/from/cli")));
    }
}
