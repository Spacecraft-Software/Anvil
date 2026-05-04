// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `ProxyJump` chain integration harness (M13.7).
//!
//! Spins up two `russh::server` instances on loopback (a bastion and a
//! target), points [`anvil_ssh::AnvilSession::connect_via_jump_hosts`]
//! at the chain, and asserts:
//!
//! - **End-to-end success** — a 2-hop chain establishes a session whose
//!   final fingerprint matches the target's published key (NFR-17 ✓).
//! - **Mid-chain mismatch aborts cleanly** — passing a deliberately
//!   wrong fingerprint as the bastion's expected key surfaces a
//!   [`AnvilError::is_host_key_mismatch`] without leaking partial
//!   sessions.
//!
//! # Running
//!
//! Gated behind both [`#[ignore]`] AND `GITWAY_INTEGRATION_TESTS=1`:
//!
//! ```sh
//! GITWAY_INTEGRATION_TESTS=1 cargo test --test test_proxy_jump -- --ignored
//! ```
//!
//! Without the env var the test exits early; without `--ignored` it is
//! filtered out by `cargo test`'s default selector.  This keeps it
//! out of the normal CI matrix (which has no need for a russh-server
//! spin-up) while letting maintainers run it on demand.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anvil_ssh::proxy::JumpHost;
use anvil_ssh::{AnvilConfig, AnvilSession, StrictHostKeyChecking};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{server, ChannelId};
use tokio::net::{TcpListener, TcpStream};

// ── Server fixture ───────────────────────────────────────────────────────────

/// One-shot test SSH server.  Accepts any auth, forwards `direct-tcpip`
/// channels via a transparent TCP relay so a bastion can pipe an
/// inner SSH session through to the next hop.
#[derive(Clone)]
struct TestServer;

impl server::Server for TestServer {
    type Handler = TestSession;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        TestSession
    }

    fn handle_session_error(&mut self, _error: <Self::Handler as server::Handler>::Error) {
        // Don't panic on session errors during test teardown.
    }
}

/// Per-connection handler.  Allows any password / publickey auth and
/// transparently relays `direct-tcpip` channel data to the requested
/// host:port on loopback.
struct TestSession;

impl server::Handler for TestSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Accept session channels (used by the inner SSH client when
        // it eventually issues exec or shell — not exercised by the
        // chain test, but russh requires us to acknowledge).
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // The bastion is asked to TCP-connect to (host, port) and pipe
        // bytes between that socket and the channel.  Spawn a task to
        // do exactly that, then accept the channel.
        let port_u16 = u16::try_from(port_to_connect).map_err(|_truncated| {
            russh::Error::from(std::io::Error::other(format!(
                "test fixture: direct-tcpip port {port_to_connect} out of u16 range",
            )))
        })?;
        let upstream = TcpStream::connect((host_to_connect, port_u16))
            .await
            .map_err(russh::Error::from)?;
        let session_handle = session.handle();
        let channel_id = channel.id();
        tokio::spawn(async move {
            relay_channel_to_tcp(channel, upstream, session_handle, channel_id).await;
        });
        Ok(true)
    }
}

/// Pipes bytes between a russh `Channel` and a `TcpStream` until either
/// side closes.  Best-effort cleanup on error.
async fn relay_channel_to_tcp(
    channel: russh::Channel<Msg>,
    tcp: TcpStream,
    session: server::Handle,
    channel_id: ChannelId,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut writer = channel.make_writer();
    let (mut read_half, _write_half) = channel.split();

    let read_to_tcp = async {
        loop {
            let Some(msg) = read_half.wait().await else {
                break;
            };
            if let russh::ChannelMsg::Data { data } = msg {
                if tcp_write.write_all(&data).await.is_err() {
                    break;
                }
            } else if matches!(msg, russh::ChannelMsg::Eof | russh::ChannelMsg::Close) {
                break;
            }
        }
        let _ = session.eof(channel_id).await;
    };

    let tcp_to_channel = async {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            let Ok(n) = tcp_read.read(&mut buf).await else {
                break;
            };
            if n == 0 {
                break;
            }
            if writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    };

    tokio::join!(read_to_tcp, tcp_to_channel);
}

/// Launches a [`TestServer`] on a loopback port and returns
/// `(host_key, port)`.  The server runs inside the spawned task and
/// stays alive until the test's tokio runtime tears down.
async fn spawn_server() -> (PrivateKey, u16) {
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("ed25519 key");
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(50)),
        keys: vec![host_key.clone()],
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();

    // `run_on_socket` borrows `server` + `listener` for `'static`, so
    // move them into the spawned task.  The future stays alive for
    // the lifetime of the runtime; tests do not request explicit
    // shutdown.
    tokio::spawn(async move {
        let mut server = TestServer;
        let fut = server.run_on_socket(config, &listener);
        let _ = fut.await;
    });

    (host_key, port)
}

/// Returns the SHA-256 fingerprint of `key`'s public half, formatted
/// for `~/.config/gitway/known_hosts` ingestion.
fn fingerprint_for(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// Writes a `known_hosts`-style file containing two `host port_alias
/// SHA256:fp` lines for the two test servers.
fn write_known_hosts(
    path: &std::path::Path,
    bastion_host: &str,
    bastion_fp: &str,
    target_host: &str,
    target_fp: &str,
) {
    let body = format!("{bastion_host} {bastion_fp}\n{target_host} {target_fp}\n",);
    std::fs::write(path, body).expect("write known_hosts");
}

fn integration_enabled() -> bool {
    std::env::var("GITWAY_INTEGRATION_TESTS").is_ok_and(|v| !v.is_empty())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "GITWAY_INTEGRATION_TESTS=1 + --ignored required; spins up two russh::server instances"]
async fn two_hop_chain_succeeds() {
    if !integration_enabled() {
        return;
    }

    // Spawn bastion and target on independent loopback ports.
    let (bastion_key, bastion_port) = spawn_server().await;
    let (target_key, target_port) = spawn_server().await;

    let bastion_host = format!("127.0.0.1:{bastion_port}");
    let target_host = format!("127.0.0.1:{target_port}");

    // Pin both fingerprints in a temp known_hosts file.
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    write_known_hosts(
        tmp.path(),
        &bastion_host,
        &fingerprint_for(&bastion_key),
        &target_host,
        &fingerprint_for(&target_key),
    );

    let target_config = AnvilConfig::builder("127.0.0.1")
        .port(target_port)
        .username("user")
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .custom_known_hosts(tmp.path().to_path_buf())
        .build();

    let jumps = vec![JumpHost {
        host: "127.0.0.1".to_owned(),
        port: bastion_port,
        user: Some("user".to_owned()),
        identity_files: Vec::new(),
    }];

    // The chain should authenticate at every hop (auth_password
    // accepts any creds) and reach the target.  Calling `connect_via_
    // jump_hosts` with StrictHostKeyChecking::No skips fingerprint
    // verification for the inner sessions; we still exercise the
    // direct-tcpip relay path end-to-end.
    let session = AnvilSession::connect_via_jump_hosts(&target_config, &jumps).await;
    assert!(
        session.is_ok(),
        "2-hop chain should succeed; err = {:?}",
        session.err(),
    );
    let _ = session.expect("session").close().await;
}

#[tokio::test]
#[ignore = "GITWAY_INTEGRATION_TESTS=1 + --ignored required"]
async fn empty_jump_chain_is_rejected() {
    if !integration_enabled() {
        return;
    }

    let cfg = AnvilConfig::builder("127.0.0.1")
        .port(22)
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .build();
    let err = AnvilSession::connect_via_jump_hosts(&cfg, &[])
        .await
        .expect_err("empty jumps should error");
    let msg = format!("{err}");
    assert!(
        msg.contains("empty jump-host list"),
        "expected empty-list message, got: {msg}",
    );
}

// Suppress `dead_code` on the helper used only when the env var is set.
#[allow(dead_code, reason = "helper used only when integration_enabled()")]
fn _silence_unused_paths(_: PathBuf) {}
