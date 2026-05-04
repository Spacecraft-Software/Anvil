// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
// Updated 2026-04-12: added verified_fingerprint tracking for SFRS JSON output
//! SSH session management (FR-1 through FR-5, FR-9 through FR-17).
//!
//! [`AnvilSession`] wraps a russh [`client::Handle`] and exposes the
//! operations Gitway needs: connect, authenticate, exec, and close.
//!
//! Host-key verification is performed inside [`GitwayHandler::check_server_key`]
//! using the fingerprints collected by [`crate::hostkey`].

use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::{cipher, kex, Disconnect, Preferred};

use std::path::PathBuf;

use crate::config::AnvilConfig;
use crate::error::{AnvilError, AnvilErrorKind};
use crate::hostkey;
use crate::relay;
use crate::ssh_config::StrictHostKeyChecking;

// ── Handler ───────────────────────────────────────────────────────────────────

/// russh client event handler.
///
/// Validates the server host key (FR-6, FR-7, FR-8) and captures any
/// authentication banner the server sends before confirming the session.
struct GitwayHandler {
    /// Expected SHA-256 fingerprints for the target host.  May be empty
    /// in [`StrictHostKeyChecking::AcceptNew`] mode for an unknown host
    /// — the handler will record the first fingerprint it sees in that
    /// case.
    fingerprints: Vec<String>,
    /// SHA-256 fingerprints explicitly revoked for this host (M14, FR-64).
    /// Checked **before** the policy and fingerprint paths: a presented
    /// key that hits one of these is rejected unconditionally — even
    /// [`StrictHostKeyChecking::No`] cannot override a `@revoked`
    /// entry.
    revoked: Vec<String>,
    /// Host-key verification policy (FR-8).
    policy: StrictHostKeyChecking,
    /// Hostname being connected to — needed by the
    /// [`StrictHostKeyChecking::AcceptNew`] write path so the new
    /// fingerprint line can be labelled with the right host.
    host: String,
    /// Path to the user-configured `known_hosts` file, if any.  Required
    /// for [`StrictHostKeyChecking::AcceptNew`] writes; if `None`, the
    /// handler downgrades to [`StrictHostKeyChecking::Yes`] semantics
    /// with a warning.
    custom_known_hosts: Option<PathBuf>,
    /// Buffer for the last authentication banner received from the server.
    ///
    /// GitHub sends "Hi <user>! You've successfully authenticated…" here.
    auth_banner: Arc<Mutex<Option<String>>>,
    /// The SHA-256 fingerprint of the server key that passed verification.
    ///
    /// Set during `check_server_key`; exposed via
    /// [`AnvilSession::verified_fingerprint`] for structured JSON output.
    verified_fingerprint: Arc<Mutex<Option<String>>>,
}

impl fmt::Debug for GitwayHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitwayHandler")
            .field("fingerprints", &self.fingerprints)
            .field("revoked", &self.revoked)
            .field("policy", &self.policy)
            .field("host", &self.host)
            .field("custom_known_hosts", &self.custom_known_hosts)
            .field("auth_banner", &self.auth_banner)
            .field("verified_fingerprint", &self.verified_fingerprint)
            .finish()
    }
}

impl client::Handler for GitwayHandler {
    type Error = AnvilError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        log::debug!("session: checking server host key {fp}");

        // M14 / FR-64: a `@revoked` entry beats every other policy —
        // even `StrictHostKeyChecking::No` cannot override an explicit
        // revocation.  This runs first so a compromised key can't be
        // accepted via the insecure-skip path.
        if self.revoked.iter().any(|r| r == &fp) {
            return Err(AnvilError::host_key_mismatch(fp.clone()).with_hint(format!(
                "{fp} is listed in a @revoked entry for {} in the known_hosts \
                 file (M14, FR-64). Refusing the connection unconditionally — \
                 the key has been explicitly blocklisted. Remove the @revoked \
                 line if the revocation was a mistake, or rotate the upstream \
                 host key.",
                self.host,
            )));
        }

        // StrictHostKeyChecking=No: accept any key.  Equivalent to the
        // 0.2.x `--insecure-skip-host-check` path.  Reached only after
        // the `@revoked` check above.
        if matches!(self.policy, StrictHostKeyChecking::No) {
            log::warn!("host-key verification skipped (StrictHostKeyChecking=No)");
            if let Ok(mut guard) = self.verified_fingerprint.lock() {
                *guard = Some(fp);
            }
            return Ok(true);
        }

        // Match against the pinned/known set first.  This path is
        // identical for `Yes` and `AcceptNew`: a verified existing
        // fingerprint always passes.
        if self.fingerprints.iter().any(|f| f == &fp) {
            log::debug!("session: host key verified: {fp}");
            if let Ok(mut guard) = self.verified_fingerprint.lock() {
                *guard = Some(fp);
            }
            return Ok(true);
        }

        // No match.  In `AcceptNew` mode with a fully-unknown host (no
        // existing fingerprints at all) AND a writable
        // `custom_known_hosts` path, record the new fingerprint and
        // accept.  Any other case is a hard mismatch.
        if matches!(self.policy, StrictHostKeyChecking::AcceptNew) && self.fingerprints.is_empty() {
            if let Some(path) = &self.custom_known_hosts {
                hostkey::append_known_host(path, &self.host, &fp)?;
                log::info!(
                    "host-key first-use accepted: {} -> {} (recorded in {})",
                    self.host,
                    fp,
                    path.display(),
                );
                if let Ok(mut guard) = self.verified_fingerprint.lock() {
                    *guard = Some(fp);
                }
                return Ok(true);
            }
            log::warn!(
                "StrictHostKeyChecking=accept-new requested but no \
                 custom_known_hosts path is set; downgrading to Yes \
                 semantics for {}",
                self.host,
            );
        }

        Err(AnvilError::host_key_mismatch(fp))
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let trimmed = banner.trim().to_owned();
        log::info!("server banner: {banner}");
        if let Ok(mut guard) = self.auth_banner.lock() {
            *guard = Some(trimmed);
        }
        Ok(())
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// An active SSH session connected to a GitHub (or GHE) host.
///
/// # Typical Usage
///
/// ```no_run
/// use anvil_ssh::{AnvilConfig, AnvilSession};
///
/// # async fn doc() -> Result<(), anvil_ssh::AnvilError> {
/// let config = AnvilConfig::github();
/// let mut session = AnvilSession::connect(&config).await?;
/// // authenticate, exec, close…
/// # Ok(())
/// # }
/// ```
pub struct AnvilSession {
    handle: client::Handle<GitwayHandler>,
    /// Authentication banner received from the server, if any.
    auth_banner: Arc<Mutex<Option<String>>>,
    /// SHA-256 fingerprint of the server key that passed verification, if any.
    verified_fingerprint: Arc<Mutex<Option<String>>>,
}

/// Manual Debug impl because `client::Handle<H>` does not implement `Debug`.
impl fmt::Debug for AnvilSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnvilSession").finish_non_exhaustive()
    }
}

/// The pre-handshake state every constructor on [`AnvilSession`]
/// builds before driving russh.  Factoring it out keeps `connect`,
/// `connect_via_proxy_command`, and `connect_via_jump_hosts` (M13.4)
/// in lock-step on host-key handling and the `auth_banner` /
/// `verified_fingerprint` mutexes the public getters expose.
struct HandlerPieces {
    russh_cfg: Arc<client::Config>,
    handler: GitwayHandler,
    auth_banner: Arc<Mutex<Option<String>>>,
    verified_fingerprint: Arc<Mutex<Option<String>>>,
}

impl AnvilSession {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Builds the russh config + handler used by every constructor.
    ///
    /// Centralises host-key fingerprint lookup (with the
    /// [`StrictHostKeyChecking::AcceptNew`] tolerance for unknown hosts
    /// when a writable `custom_known_hosts` path is set) and the shared
    /// `auth_banner` / `verified_fingerprint` mutex pair.
    fn build_handler_pieces(config: &AnvilConfig) -> Result<HandlerPieces, AnvilError> {
        let russh_cfg = Arc::new(build_russh_config(config.inactivity_timeout));
        // M14: pull the trust view (direct fingerprints + revoked
        // entries) in one pass.  For
        // `StrictHostKeyChecking::AcceptNew` with a writable
        // `custom_known_hosts` path an empty fingerprint set is
        // tolerated — the handler will record the first fingerprint
        // it sees.  Every other policy (Yes / No) treats a fully-
        // empty trust set as fatal, with the long-form hint copied
        // from `fingerprints_for_host`.
        let trust = hostkey::host_key_trust(&config.host, &config.custom_known_hosts)?;
        let revoked: Vec<String> = trust.revoked.into_iter().map(|r| r.fingerprint).collect();

        let fingerprints = if !trust.fingerprints.is_empty() {
            trust.fingerprints
        } else if matches!(
            config.strict_host_key_checking,
            StrictHostKeyChecking::AcceptNew
        ) && config.custom_known_hosts.is_some()
        {
            log::info!(
                "session: no fingerprints known for {}; \
                 accept-new will record on first connection",
                config.host,
            );
            Vec::new()
        } else {
            return Err(AnvilError::invalid_config(format!(
                "no fingerprints known for host '{}'",
                config.host
            ))
            .with_hint(format!(
                "Gitway refuses to connect to hosts whose SSH fingerprint it can't \
                         verify (no trust-on-first-use). Either you typed the hostname wrong, \
                         or this is a self-hosted server and you need to pin its fingerprint: \
                         fetch it from the provider's docs (GitHub, GitLab, Codeberg publish \
                         them) and append one line to ~/.config/gitway/known_hosts:\n\
                         \n\
                             {} SHA256:<base64-fingerprint>\n\
                         \n\
                         As a last resort, re-run with --insecure-skip-host-check (not \
                         recommended — this disables MITM protection).",
                config.host,
            )));
        };

        let auth_banner = Arc::new(Mutex::new(None));
        let verified_fingerprint = Arc::new(Mutex::new(None));

        let handler = GitwayHandler {
            fingerprints,
            revoked,
            policy: config.strict_host_key_checking,
            host: config.host.clone(),
            custom_known_hosts: config.custom_known_hosts.clone(),
            auth_banner: Arc::clone(&auth_banner),
            verified_fingerprint: Arc::clone(&verified_fingerprint),
        };

        Ok(HandlerPieces {
            russh_cfg,
            handler,
            auth_banner,
            verified_fingerprint,
        })
    }

    /// Establishes a TCP connection to the host in `config` and completes the
    /// SSH handshake (including host-key verification).
    ///
    /// Does **not** authenticate; call [`authenticate`](Self::authenticate) or
    /// [`authenticate_best`](Self::authenticate_best) after this.
    ///
    /// # Errors
    ///
    /// Returns an error on network failure or if the server's host key does not
    /// match any pinned fingerprint.
    pub async fn connect(config: &AnvilConfig) -> Result<Self, AnvilError> {
        let pieces = Self::build_handler_pieces(config)?;

        log::debug!("session: connecting to {}:{}", config.host, config.port);

        let handle = client::connect(
            pieces.russh_cfg,
            (config.host.as_str(), config.port),
            pieces.handler,
        )
        .await?;

        log::debug!("session: SSH handshake complete with {}", config.host);

        Ok(Self {
            handle,
            auth_banner: pieces.auth_banner,
            verified_fingerprint: pieces.verified_fingerprint,
        })
    }

    /// Establishes the SSH session through a chain of `ProxyJump`
    /// bastion hops (FR-56).
    ///
    /// For each hop in `jumps`:
    ///
    /// 1. Build a per-hop [`AnvilConfig`] from the [`JumpHost`] fields,
    ///    inheriting `strict_host_key_checking`, `custom_known_hosts`,
    ///    and `verbose` from the primary `config`.  Per-hop user and
    ///    `identity_files` come from the [`JumpHost`] when set, else
    ///    from the primary config.
    /// 2. Connect: the *first* hop uses [`russh::client::connect`] over
    ///    TCP; subsequent hops use the *previous* hop's
    ///    `direct-tcpip` channel as the underlying transport via
    ///    [`russh::client::connect_stream`].
    /// 3. Run host-key verification — every hop runs the full
    ///    [`GitwayHandler::check_server_key`] path independently
    ///    (NFR-17: failure at hop `n+1` aborts the entire chain;
    ///    no partial-success path).
    /// 4. Authenticate the hop with [`AnvilSession::authenticate_best`]
    ///    so the chain can open `direct-tcpip` to the next hop.
    ///
    /// After the loop, the *last* bastion's handle is used to open
    /// `direct-tcpip` to the primary `config.host` / `config.port`,
    /// and the resulting [`ChannelStream`] becomes the SSH transport
    /// for the final session this method returns.
    ///
    /// # Per-hop `ssh_config`
    ///
    /// This method does NOT re-resolve `ssh_config` per hop — that
    /// requires the caller's [`SshConfigPaths`], which the session
    /// module deliberately does not depend on.  The CLI dispatcher
    /// (M13.6) is responsible for populating
    /// [`JumpHost::identity_files`] (and any other per-hop overrides)
    /// from per-hop [`crate::ssh_config::resolve`] calls before
    /// invoking this method.
    ///
    /// # Errors
    /// Returns the first error encountered.  An empty `jumps` slice is
    /// rejected with a clear message — callers should use
    /// [`Self::connect`] when no chain is in play.  Authentication
    /// failures at any intermediate hop terminate the whole chain.
    /// `ChannelStream`-based transport errors propagate via the
    /// usual russh / [`AnvilError`] mapping.
    ///
    /// # Panics
    /// Does not panic.  An internal `expect` fires only on a logic bug
    /// (the empty-`jumps` check at the top of the function would have
    /// already returned).
    pub async fn connect_via_jump_hosts(
        config: &AnvilConfig,
        jumps: &[crate::proxy::JumpHost],
    ) -> Result<Self, AnvilError> {
        if jumps.is_empty() {
            return Err(AnvilError::invalid_config(
                "ProxyJump: empty jump-host list; call AnvilSession::connect instead",
            ));
        }

        log::debug!(
            "session: connecting to {}:{} via {} bastion hop(s)",
            config.host,
            config.port,
            jumps.len(),
        );

        let mut prev_handle: Option<client::Handle<GitwayHandler>> = None;

        for (idx, hop) in jumps.iter().enumerate() {
            let hop_config = jump_to_config(hop, config);
            let pieces = Self::build_handler_pieces(&hop_config)?;

            log::debug!(
                "session: bastion hop {}/{}: connecting to {}:{}",
                idx + 1,
                jumps.len(),
                hop.host,
                hop.port,
            );

            let handle = match prev_handle.take() {
                None => {
                    // First hop: regular TCP connect.
                    client::connect(
                        pieces.russh_cfg,
                        (hop.host.as_str(), hop.port),
                        pieces.handler,
                    )
                    .await?
                }
                Some(prev) => {
                    // Subsequent hop: open `direct-tcpip` on the
                    // previous bastion, treat the channel as the
                    // transport for the next session.
                    let channel = prev
                        .channel_open_direct_tcpip(
                            hop.host.clone(),
                            u32::from(hop.port),
                            "127.0.0.1",
                            0_u32,
                        )
                        .await?;
                    client::connect_stream(pieces.russh_cfg, channel.into_stream(), pieces.handler)
                        .await?
                }
            };

            // Authenticate this bastion so we can open the next hop's
            // direct-tcpip channel through it.  Wrap in a temporary
            // AnvilSession to reuse the existing auth surface.
            let mut hop_session = Self {
                handle,
                auth_banner: pieces.auth_banner,
                verified_fingerprint: pieces.verified_fingerprint,
            };
            hop_session
                .authenticate_best(&hop_config)
                .await
                .map_err(|e| {
                    e.with_hint(format!(
                        "ProxyJump: authentication failed at bastion hop {}/{} ({}:{})",
                        idx + 1,
                        jumps.len(),
                        hop.host,
                        hop.port,
                    ))
                })?;

            prev_handle = Some(hop_session.handle);
        }

        // Final hop: open `direct-tcpip` from the last bastion to the
        // target, run the SSH handshake over that channel.
        let prev = prev_handle
            .expect("loop body ran at least once because jumps is non-empty (checked above)");

        let target_pieces = Self::build_handler_pieces(config)?;

        log::debug!(
            "session: connecting to target {}:{} via last bastion",
            config.host,
            config.port,
        );

        let channel = prev
            .channel_open_direct_tcpip(
                config.host.clone(),
                u32::from(config.port),
                "127.0.0.1",
                0_u32,
            )
            .await?;
        let final_handle = client::connect_stream(
            target_pieces.russh_cfg,
            channel.into_stream(),
            target_pieces.handler,
        )
        .await?;

        log::debug!(
            "session: SSH handshake complete with {} (via {} bastion hop(s))",
            config.host,
            jumps.len(),
        );

        Ok(Self {
            handle: final_handle,
            auth_banner: target_pieces.auth_banner,
            verified_fingerprint: target_pieces.verified_fingerprint,
        })
    }

    /// Establishes the SSH session over a child process spawned from a
    /// `ProxyCommand` template (FR-55).
    ///
    /// `proxy_command_template` is the raw template (typically from
    /// [`crate::ssh_config::ResolvedSshConfig::proxy_command`] or a CLI
    /// override).  `%h`, `%p`, `%r`, `%n`, and `%%` are expanded against
    /// `config.host`, `config.port`, `config.username`, and `alias`
    /// respectively before the platform shell (`sh -c` / `cmd /C`)
    /// spawns the command.  The child's stdin/stdout become the SSH
    /// transport via [`russh::client::connect_stream`].
    ///
    /// `alias` is the original argument the user typed before
    /// `HostName` resolution — it powers the `%n` token.  Pass
    /// `config.host` if you do not track the alias separately.
    ///
    /// The literal value `"none"` (case-insensitive) is recognized as
    /// the FR-59 disable sentinel: this method returns an error
    /// directing the caller to use [`Self::connect`] instead.  In
    /// practice the caller's dispatcher should never invoke this
    /// method in that case, but the guard keeps the spawn path safe
    /// against accidental "none" input.
    ///
    /// # Errors
    /// Returns an error on shell-spawn failure, on a host-key
    /// mismatch, or on any russh handshake failure.
    pub async fn connect_via_proxy_command(
        config: &AnvilConfig,
        proxy_command_template: &str,
        alias: &str,
    ) -> Result<Self, AnvilError> {
        if proxy_command_template.eq_ignore_ascii_case("none") {
            return Err(AnvilError::invalid_config(
                "ProxyCommand=none is the disable sentinel; \
                 call AnvilSession::connect instead",
            ));
        }

        let pieces = Self::build_handler_pieces(config)?;

        log::debug!(
            "session: connecting to {} via ProxyCommand template `{proxy_command_template}`",
            config.host,
        );

        let stream = crate::proxy::command::spawn_proxy_command(
            proxy_command_template,
            &config.host,
            config.port,
            &config.username,
            alias,
        )?;

        let handle = client::connect_stream(pieces.russh_cfg, stream, pieces.handler).await?;

        log::debug!(
            "session: SSH handshake complete with {} (via ProxyCommand)",
            config.host,
        );

        Ok(Self {
            handle,
            auth_banner: pieces.auth_banner,
            verified_fingerprint: pieces.verified_fingerprint,
        })
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// Authenticates with an explicit key.
    ///
    /// Use [`authenticate_best`] to let the library discover the key
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns an error on SSH protocol failures.  Returns
    /// [`AnvilError::is_authentication_failed`] when the server accepts the
    /// exchange but rejects the key.
    pub async fn authenticate(
        &mut self,
        username: &str,
        key: PrivateKeyWithHashAlg,
    ) -> Result<(), AnvilError> {
        log::debug!("session: authenticating as {username}");

        let result = self.handle.authenticate_publickey(username, key).await?;

        if result.success() {
            log::debug!("session: authentication succeeded for {username}");
            Ok(())
        } else {
            Err(AnvilError::authentication_failed())
        }
    }

    /// Authenticates with a private key and an accompanying OpenSSH certificate
    /// (FR-12).
    ///
    /// The certificate is presented to the server in place of the raw public
    /// key.  This is typically used with organisation-issued certificates that
    /// grant access without requiring the public key to be listed in
    /// `authorized_keys`.
    ///
    /// # Errors
    ///
    /// Returns an error on SSH protocol failures or if the server rejects the
    /// certificate.
    pub async fn authenticate_with_cert(
        &mut self,
        username: &str,
        key: russh::keys::PrivateKey,
        cert: russh::keys::Certificate,
    ) -> Result<(), AnvilError> {
        log::debug!("session: authenticating as {username} with OpenSSH certificate");

        let result = self
            .handle
            .authenticate_openssh_cert(username, Arc::new(key), cert)
            .await?;

        if result.success() {
            log::debug!("session: certificate authentication succeeded for {username}");
            Ok(())
        } else {
            Err(AnvilError::authentication_failed())
        }
    }

    /// Discovers the best available key and authenticates using it.
    ///
    /// Priority order (FR-9):
    /// 1. Explicit `--identity` path from config.
    /// 2. Default `.ssh` paths (`id_ed25519` → `id_ecdsa` → `id_rsa`).
    /// 3. SSH agent via `$SSH_AUTH_SOCK` (Unix only).
    ///
    /// If a certificate path is configured in `config.cert_file`, certificate
    /// authentication (FR-12) is used instead of raw public-key authentication
    /// for file-based keys.
    ///
    /// When the chosen key requires a passphrase this method returns an error
    /// whose [`is_key_encrypted`](AnvilError::is_key_encrypted) predicate is
    /// `true`; the caller (CLI layer) should then prompt and call
    /// [`authenticate_with_passphrase`](Self::authenticate_with_passphrase).
    ///
    /// # Errors
    ///
    /// Returns [`AnvilError::is_no_key_found`] when no key is available via
    /// any discovery method.
    pub async fn authenticate_best(&mut self, config: &AnvilConfig) -> Result<(), AnvilError> {
        use crate::auth::{find_identity, wrap_key, IdentityResolution};

        let resolution = find_identity(config)?;

        match resolution {
            IdentityResolution::Found { key, .. } => {
                return self.auth_key_or_cert(config, key).await;
            }
            IdentityResolution::Encrypted { path } => {
                log::debug!(
                    "session: key at {} is passphrase-protected; trying SSH agent first",
                    path.display()
                );
                // Try the agent before asking for a passphrase.  The key may
                // already be loaded via `ssh-add`, and a passphrase prompt is
                // impossible when gitway is spawned by Git without a terminal.
                #[cfg(unix)]
                {
                    use crate::auth::connect_agent;
                    if let Some(conn) = connect_agent().await? {
                        match self.authenticate_with_agent(&config.username, conn).await {
                            Ok(()) => return Ok(()),
                            Err(e) if e.is_authentication_failed() => {
                                log::debug!(
                                    "session: agent could not authenticate; \
                                     will request passphrase for {}",
                                    path.display()
                                );
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                return Err(AnvilError::new(AnvilErrorKind::Keys(
                    russh::keys::Error::KeyIsEncrypted,
                )));
            }
            IdentityResolution::NotFound => {
                // Fall through to agent (below).
            }
        }

        // Priority 3: SSH agent — reached only when no file-based key exists (FR-9).
        #[cfg(unix)]
        {
            use crate::auth::connect_agent;
            if let Some(conn) = connect_agent().await? {
                return self.authenticate_with_agent(&config.username, conn).await;
            }
        }

        // For RSA keys, ask the server which hash algorithm it prefers (FR-11).
        // This branch is only reached when we must still try a key via wrap_key
        // after exhausting the above — currently unused, but kept for clarity.
        let _ = wrap_key; // suppress unused-import warning on non-Unix builds
        Err(AnvilError::no_key_found())
    }

    /// Loads an encrypted key with `passphrase` and authenticates.
    ///
    /// Call this after [`authenticate_best`] returns an encrypted-key error
    /// and the CLI has collected the passphrase from the terminal.
    ///
    /// If `config.cert_file` is set, certificate authentication is used
    /// (FR-12).
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is wrong or authentication fails.
    pub async fn authenticate_with_passphrase(
        &mut self,
        config: &AnvilConfig,
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<(), AnvilError> {
        use crate::auth::load_encrypted_key;

        let key = load_encrypted_key(path, passphrase)?;
        self.auth_key_or_cert(config, key).await
    }

    /// Tries each identity held in `conn` until one succeeds or all are
    /// exhausted.
    ///
    /// On Unix this is called automatically by [`authenticate_best`] when no
    /// file-based key is found.  For plain public-key identities the signing
    /// challenge is forwarded to the agent; for certificate identities the
    /// full certificate is presented alongside the agent-signed challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AnvilError::is_authentication_failed`] if all identities are
    /// rejected, or [`AnvilError::is_no_key_found`] if the agent was empty.
    #[cfg(unix)]
    pub async fn authenticate_with_agent(
        &mut self,
        username: &str,
        mut conn: crate::auth::AgentConnection,
    ) -> Result<(), AnvilError> {
        use russh::keys::agent::AgentIdentity;

        for identity in conn.identities.clone() {
            let result = match &identity {
                AgentIdentity::PublicKey { key, .. } => {
                    let hash_alg = if key.algorithm().is_rsa() {
                        self.handle
                            .best_supported_rsa_hash()
                            .await?
                            .flatten()
                            // Fall back to SHA-256 when the server offers no guidance (FR-11).
                            .or(Some(HashAlg::Sha256))
                    } else {
                        None
                    };
                    self.handle
                        .authenticate_publickey_with(
                            username,
                            key.clone(),
                            hash_alg,
                            &mut conn.client,
                        )
                        .await
                        .map_err(AnvilError::from)
                }
                AgentIdentity::Certificate { certificate, .. } => self
                    .handle
                    .authenticate_certificate_with(
                        username,
                        certificate.clone(),
                        None,
                        &mut conn.client,
                    )
                    .await
                    .map_err(AnvilError::from),
            };

            match result? {
                r if r.success() => {
                    log::debug!("session: agent authentication succeeded");
                    return Ok(());
                }
                _ => {
                    log::debug!("session: agent identity rejected; trying next");
                }
            }
        }

        Err(AnvilError::no_key_found())
    }

    // ── Exec / relay ──────────────────────────────────────────────────────────

    /// Opens a session channel, executes `command`, and relays stdio
    /// bidirectionally until the remote process exits.
    ///
    /// Returns the remote exit code (FR-16).  Exit-via-signal returns
    /// `128 + signal_number` (FR-17).
    ///
    /// # Errors
    ///
    /// Returns an error on channel open failure or SSH protocol errors.
    pub async fn exec(&mut self, command: &str) -> Result<u32, AnvilError> {
        log::debug!("session: opening exec channel for '{command}'");

        let channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let exit_code = relay::relay_channel(channel).await?;

        log::debug!("session: command '{command}' exited with code {exit_code}");

        Ok(exit_code)
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Sends a graceful `SSH_MSG_DISCONNECT` and closes the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the disconnect message cannot be sent.
    pub async fn close(self) -> Result<(), AnvilError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the authentication banner last received from the server (if any).
    ///
    /// For GitHub.com this contains the "Hi <user>!" welcome message.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned, which can only occur if another
    /// thread panicked while holding the lock — a programming error.
    #[must_use]
    pub fn auth_banner(&self) -> Option<String> {
        self.auth_banner
            .lock()
            .expect("auth_banner lock is not poisoned")
            .clone()
    }

    /// Returns the SHA-256 fingerprint of the server key that was verified.
    ///
    /// Available after a successful [`connect`](Self::connect).  Returns `None`
    /// when host-key verification was skipped (`--insecure-skip-host-check`).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned — a programming error.
    #[must_use]
    pub fn verified_fingerprint(&self) -> Option<String> {
        self.verified_fingerprint
            .lock()
            .expect("verified_fingerprint lock is not poisoned")
            .clone()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Authenticates with `key`, using certificate auth if `config.cert_file`
    /// is set (FR-12), otherwise plain public-key auth (FR-11).
    async fn auth_key_or_cert(
        &mut self,
        config: &AnvilConfig,
        key: russh::keys::PrivateKey,
    ) -> Result<(), AnvilError> {
        use crate::auth::{load_cert, wrap_key};

        if let Some(ref cert_path) = config.cert_file {
            let cert = load_cert(cert_path)?;
            return self
                .authenticate_with_cert(&config.username, key, cert)
                .await;
        }

        // For RSA keys, ask the server which hash algorithm it prefers (FR-11).
        let rsa_hash = if key.algorithm().is_rsa() {
            self.handle
                .best_supported_rsa_hash()
                .await?
                .flatten()
                .or(Some(HashAlg::Sha256))
        } else {
            None
        };

        let wrapped = wrap_key(key, rsa_hash);
        self.authenticate(&config.username, wrapped).await
    }
}

// ── russh config builder ──────────────────────────────────────────────────────

/// Constructs a russh [`client::Config`] with Gitway's preferred algorithms.
///
/// Algorithm preferences (FR-2, FR-3, FR-4):
/// - Key exchange: `curve25519-sha256` (RFC 8731) with
///   `curve25519-sha256@libssh.org` as fallback.
/// - Cipher: `chacha20-poly1305@openssh.com`.
/// - `ext-info-c` advertises server-sig-algs extension support.
fn build_russh_config(inactivity_timeout: Duration) -> client::Config {
    client::Config {
        // 60 s matches GitHub's server-side idle threshold.
        // Lowering below ~10 s risks spurious timeouts on high-latency links.
        inactivity_timeout: Some(inactivity_timeout),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                kex::CURVE25519,                  // curve25519-sha256 (RFC 8731)
                kex::CURVE25519_PRE_RFC_8731,     // curve25519-sha256@libssh.org
                kex::EXTENSION_SUPPORT_AS_CLIENT, // ext-info-c (FR-4)
            ]),
            cipher: Cow::Owned(vec![
                cipher::CHACHA20_POLY1305, // chacha20-poly1305@openssh.com (FR-3)
            ]),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ── Jump-host helper (M13.4) ─────────────────────────────────────────────────

/// Builds the per-hop [`AnvilConfig`] used inside
/// `AnvilSession::connect_via_jump_hosts`.
///
/// Inherits security knobs — `strict_host_key_checking`,
/// `custom_known_hosts`, `verbose` — from the *primary* config so a
/// user's connection-wide policy (e.g. `--insecure-skip-host-check`)
/// applies to every hop.  Per-hop fields (`user`, `identity_files`)
/// come from the [`crate::proxy::JumpHost`] when set, else from the
/// primary config: a CLI `--user alice` thus propagates to every
/// bastion that did not override the user in its own `Host` block.
fn jump_to_config(hop: &crate::proxy::JumpHost, primary: &AnvilConfig) -> AnvilConfig {
    let mut builder = AnvilConfig::builder(&hop.host)
        .port(hop.port)
        .strict_host_key_checking(primary.strict_host_key_checking)
        .verbose(primary.verbose);

    let username = hop.user.clone().unwrap_or_else(|| primary.username.clone());
    builder = builder.username(username);

    let identity_files: Vec<_> = if hop.identity_files.is_empty() {
        primary.identity_files.clone()
    } else {
        hop.identity_files.clone()
    };
    builder = builder.identity_files(identity_files);

    if let Some(p) = &primary.custom_known_hosts {
        builder = builder.custom_known_hosts(p.clone());
    }

    builder.build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NFR-6: legacy algorithm exclusion ────────────────────────────────────

    /// 3DES-CBC must never appear in the negotiated cipher list (NFR-6).
    ///
    /// Our explicit cipher override contains only chacha20-poly1305, so 3DES
    /// cannot be selected even if the server offers it.
    #[test]
    fn config_cipher_excludes_3des() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config
            .preferred
            .cipher
            .iter()
            .any(|c| c.as_ref() == "3des-cbc");
        assert!(
            !found,
            "3DES-CBC must not appear in the cipher list (NFR-6)"
        );
    }

    /// DSA must never appear in the key-algorithm list (NFR-6).
    ///
    /// russh's `Preferred::DEFAULT` already omits DSA; this test locks that
    /// invariant so a russh upgrade cannot silently re-introduce it.
    #[test]
    fn config_key_algorithms_exclude_dsa() {
        use russh::keys::Algorithm;

        let config = build_russh_config(Duration::from_secs(60));
        assert!(
            !config.preferred.key.contains(&Algorithm::Dsa),
            "DSA must not appear in the key-algorithm list (NFR-6)"
        );
    }

    // ── FR-2 / FR-3 positive assertions ─────────────────────────────────────

    /// curve25519-sha256 must be in the kex list (FR-2).
    #[test]
    fn config_kex_includes_curve25519() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config
            .preferred
            .kex
            .iter()
            .any(|k| k.as_ref() == "curve25519-sha256");
        assert!(found, "curve25519-sha256 must be in the kex list (FR-2)");
    }

    /// chacha20-poly1305@openssh.com must be in the cipher list (FR-3).
    #[test]
    fn config_cipher_includes_chacha20_poly1305() {
        let config = build_russh_config(Duration::from_secs(60));
        let found = config
            .preferred
            .cipher
            .iter()
            .any(|c| c.as_ref() == "chacha20-poly1305@openssh.com");
        assert!(
            found,
            "chacha20-poly1305@openssh.com must be in the cipher list (FR-3)"
        );
    }
}
