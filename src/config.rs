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
    /// Key-exchange algorithm preference (PRD §5.8.6 FR-76).
    ///
    /// `None` selects [`crate::algorithms::anvil_default_kex`] — the
    /// curated default.  `Some(list)` overrides; the list has
    /// already passed through
    /// [`crate::algorithms::apply_overrides`] (so any `+`/`-`/`^`
    /// prefix has been resolved and the FR-78 denylist applied).
    pub kex_algorithms: Option<Vec<String>>,
    /// Cipher preference (PRD §5.8.6 FR-76).  `None` → curated default.
    pub ciphers: Option<Vec<String>>,
    /// MAC preference (PRD §5.8.6 FR-76).  `None` → curated default.
    /// Mostly cosmetic for AEAD ciphers (chacha20-poly1305, AES-GCM)
    /// since they carry their own auth tag.
    pub macs: Option<Vec<String>>,
    /// Host-key algorithm preference (PRD §5.8.6 FR-76).  `None` →
    /// curated default.
    pub host_key_algorithms: Option<Vec<String>>,
    /// Per-attempt TCP connect timeout (PRD §5.8.7 FR-80).  `None`
    /// disables the timeout (matches OpenSSH's "no `ConnectTimeout`"
    /// semantics).
    pub connect_timeout: Option<Duration>,
    /// Total number of connection attempts including the initial one
    /// (PRD §5.8.7 FR-80).  `None` selects the curated default
    /// ([`crate::retry::RetryPolicy`]'s `attempts = 3`).
    pub connection_attempts: Option<u32>,
    /// Hard ceiling on total elapsed wall-clock time across all
    /// retry attempts (PRD §5.8.7 FR-81).  `None` selects the
    /// curated default (30 s).  CLI-only — not part of OpenSSH's
    /// `ssh_config(5)` grammar.
    pub max_retry_window: Option<Duration>,
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
    kex_algorithms: Option<Vec<String>>,
    ciphers: Option<Vec<String>>,
    macs: Option<Vec<String>>,
    host_key_algorithms: Option<Vec<String>>,
    connect_timeout: Option<Duration>,
    connection_attempts: Option<u32>,
    max_retry_window: Option<Duration>,
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
            // Algorithm preferences default to None (= use the
            // curated `algorithms::anvil_default_*` lists at session
            // build time).  M17.4 CLI flags overwrite these via the
            // four setters below.
            kex_algorithms: None,
            ciphers: None,
            macs: None,
            host_key_algorithms: None,
            // Retry / timeout knobs default to None.  At session
            // build time, None falls through to
            // `crate::retry::RetryPolicy::default()` (3 attempts,
            // 250 ms base, 30 s max_window, no connect timeout) —
            // matches OpenSSH's defaults except for the new
            // max_window cap which is Gitway-specific.
            connect_timeout: None,
            connection_attempts: None,
            max_retry_window: None,
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

    /// Override the key-exchange algorithm preference (PRD §5.8.6 FR-76).
    ///
    /// Pass `None` to keep the curated default
    /// ([`crate::algorithms::anvil_default_kex`]).  The list is
    /// expected to have already passed through
    /// [`crate::algorithms::apply_overrides`] so any
    /// `+`/`-`/`^` prefix is resolved and the FR-78 denylist applied.
    pub fn kex_algorithms(mut self, list: Option<Vec<String>>) -> Self {
        self.kex_algorithms = list;
        self
    }

    /// Override the cipher preference (PRD §5.8.6 FR-76).
    pub fn ciphers(mut self, list: Option<Vec<String>>) -> Self {
        self.ciphers = list;
        self
    }

    /// Override the MAC preference (PRD §5.8.6 FR-76).
    pub fn macs(mut self, list: Option<Vec<String>>) -> Self {
        self.macs = list;
        self
    }

    /// Override the host-key algorithm preference (PRD §5.8.6 FR-76).
    pub fn host_key_algorithms(mut self, list: Option<Vec<String>>) -> Self {
        self.host_key_algorithms = list;
        self
    }

    /// Override the per-attempt TCP connect timeout (PRD §5.8.7
    /// FR-80).  `None` disables the timeout.  CLI overrides this
    /// AFTER `apply_ssh_config` so flags beat config (matches
    /// OpenSSH precedence).
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the total connection-attempt count (PRD §5.8.7
    /// FR-80).  `None` selects the curated default (3).
    pub fn connection_attempts(mut self, attempts: Option<u32>) -> Self {
        self.connection_attempts = attempts;
        self
    }

    /// Override the wall-clock cap on total retry time (PRD
    /// §5.8.7 FR-81).  `None` selects the curated default (30 s).
    /// Not part of OpenSSH's `ssh_config(5)` grammar — CLI-only.
    pub fn max_retry_window(mut self, window: Option<Duration>) -> Self {
        self.max_retry_window = window;
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
    /// `Ciphers`, `MACs`) are honored as of M17 (PRD §5.8.6 FR-76):
    /// each parsed `AlgList` is fed through
    /// [`crate::algorithms::apply_overrides`] against the matching
    /// curated default, so an `ssh_config` value of `+algo,algo`
    /// appends to Anvil's defaults rather than replacing them.
    /// `ConnectTimeout` / `ConnectionAttempts` remain deferred to
    /// M18.
    ///
    /// # Errors
    ///
    /// This method is infallible by signature, but a malformed
    /// algorithm list (denylisted entry referenced by an override)
    /// is logged at `warn` level and silently dropped — the
    /// connection then falls back to the curated default.  Callers
    /// who want strict validation should run the same value
    /// through [`crate::algorithms::apply_overrides`] explicitly
    /// before calling here.
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
        // M17 / FR-76: plumb algorithm directives through the
        // `+`/`-`/`^` parser against Anvil's curated defaults.  CLI
        // overrides applied AFTER `apply_ssh_config` win over the
        // ssh_config-derived value (matches OpenSSH precedence).
        self.apply_alg_directive(
            crate::algorithms::AlgCategory::Kex,
            resolved.kex_algorithms.as_ref(),
            crate::algorithms::anvil_default_kex,
            |b, v| b.kex_algorithms = Some(v),
        );
        self.apply_alg_directive(
            crate::algorithms::AlgCategory::Cipher,
            resolved.ciphers.as_ref(),
            crate::algorithms::anvil_default_ciphers,
            |b, v| b.ciphers = Some(v),
        );
        self.apply_alg_directive(
            crate::algorithms::AlgCategory::Mac,
            resolved.macs.as_ref(),
            crate::algorithms::anvil_default_macs,
            |b, v| b.macs = Some(v),
        );
        self.apply_alg_directive(
            crate::algorithms::AlgCategory::HostKey,
            resolved.host_key_algorithms.as_ref(),
            crate::algorithms::anvil_default_host_keys,
            |b, v| b.host_key_algorithms = Some(v),
        );

        // M18 / FR-80: ConnectTimeout + ConnectionAttempts from
        // ssh_config flow through to the retry-policy fields.  CLI
        // overrides applied AFTER apply_ssh_config win over these
        // (matches OpenSSH precedence).  Don't clobber a value
        // already set on the builder — that's how the CLI-wins
        // precedence is achieved.
        if self.connect_timeout.is_none() {
            if let Some(d) = resolved.connect_timeout {
                self.connect_timeout = Some(d);
            }
        }
        if self.connection_attempts.is_none() {
            if let Some(n) = resolved.connection_attempts {
                self.connection_attempts = Some(n);
            }
        }
        self
    }

    /// Internal helper for `apply_ssh_config`.  Reads one algorithm
    /// directive from the resolved config, runs it through
    /// `apply_overrides` against the curated default, and stores the
    /// result via `setter`.  Malformed values (denylisted entries)
    /// log a warning and leave the field on its `None` default so
    /// the curated list is used at session-build time.
    fn apply_alg_directive(
        &mut self,
        category: crate::algorithms::AlgCategory,
        directive: Option<&crate::ssh_config::AlgList>,
        default_fn: fn() -> Vec<String>,
        setter: fn(&mut Self, Vec<String>),
    ) {
        let Some(crate::ssh_config::AlgList(value)) = directive else {
            return;
        };
        match crate::algorithms::apply_overrides(category, default_fn(), value) {
            Ok(list) => setter(self, list),
            Err(e) => {
                log::warn!(
                    "ssh_config {category} directive '{value}' rejected: {e} \
                     (falling back to Anvil curated default)",
                    category = category.label(),
                );
            }
        }
    }

    // (Unhonored-directives warning helper lives below `impl` block.)

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
            kex_algorithms: self.kex_algorithms,
            ciphers: self.ciphers,
            macs: self.macs,
            host_key_algorithms: self.host_key_algorithms,
            connect_timeout: self.connect_timeout,
            connection_attempts: self.connection_attempts,
            max_retry_window: self.max_retry_window,
        }
    }
}

// Note: the `warn_unhonored_directives` helper that lived here from
// M12.6 → M17.2 → M18.2 was removed in M18.2.  Every `ssh_config(5)`
// directive Anvil's resolver parses today is now consumed by
// `apply_ssh_config` (HostKeyAlgorithms / KexAlgorithms / Ciphers /
// MACs landed in M17; ConnectTimeout / ConnectionAttempts in M18).
// Future deferral warnings should reintroduce a similar helper if a
// new milestone parses-but-doesn't-yet-consume a directive.

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
