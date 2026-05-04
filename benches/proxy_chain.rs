// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! NFR-16 latency budget: a `ProxyJump` chain hop should add ≤ 1.5 s of
//! cold-start cost per hop on a 50 ms RTT link.
//!
//! Loopback is too fast to honestly check the 1.5 s budget — every hop
//! costs single-digit milliseconds on `127.0.0.1`.  Instead, this
//! bench enforces the *relative shape*: a 2-hop chain should run in
//! at most **2× the time of a 1-hop chain**, on the same link.  A
//! genuine 50 ms RTT validation lives at `[bench] proxy_chain
//! --features=real-rtt` (NOT IMPLEMENTED in this PR; documented as
//! manual procedure in the M13 plan's verification section).
//!
//! # Running
//!
//! ```sh
//! GITWAY_INTEGRATION_TESTS=1 cargo bench --bench proxy_chain
//! ```
//!
//! Without `GITWAY_INTEGRATION_TESTS=1`, the bench body is a no-op so
//! it can appear in the bench harness list without spinning up
//! `russh::server` instances on every CI run.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_ssh::proxy::JumpHost;
use anvil_ssh::{AnvilConfig, AnvilSession, StrictHostKeyChecking};
use criterion::{criterion_group, criterion_main, Criterion};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{server, ChannelId};
use tokio::net::{TcpListener, TcpStream};

fn integration_enabled() -> bool {
    std::env::var("GITWAY_INTEGRATION_TESTS").is_ok_and(|v| !v.is_empty())
}

// ── Server fixture (mirrors tests/test_proxy_jump.rs::TestServer) ────────────

#[derive(Clone)]
struct BenchServer;

impl server::Server for BenchServer {
    type Handler = BenchSession;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        BenchSession
    }
    fn handle_session_error(&mut self, _: <Self::Handler as server::Handler>::Error) {}
}

struct BenchSession;

impl server::Handler for BenchSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        _: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port_u16 = u16::try_from(port_to_connect).map_err(|_truncated| {
            russh::Error::from(std::io::Error::other(format!(
                "bench fixture: direct-tcpip port {port_to_connect} out of u16 range",
            )))
        })?;
        let upstream = TcpStream::connect((host_to_connect, port_u16))
            .await
            .map_err(russh::Error::from)?;
        let session_handle = session.handle();
        let channel_id = channel.id();
        tokio::spawn(async move {
            relay(channel, upstream, session_handle, channel_id).await;
        });
        Ok(true)
    }
}

async fn relay(
    channel: russh::Channel<Msg>,
    tcp: TcpStream,
    session: server::Handle,
    channel_id: ChannelId,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut writer = channel.make_writer();
    let (mut read_half, _wh) = channel.split();

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

async fn spawn_server() -> u16 {
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate host key");
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(50)),
        keys: vec![host_key],
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    // The `run_on_socket` future borrows both `server` and `listener`
    // for `'static`, so move them into the spawned task that owns them
    // for the bench's duration.  The handle is dropped here; the
    // server stays alive until the bench's tokio Runtime is shut down.
    tokio::spawn(async move {
        let mut server = BenchServer;
        let fut = server.run_on_socket(config, &listener);
        let _ = fut.await;
    });
    port
}

// ── Bench bodies ─────────────────────────────────────────────────────────────

fn bench_one_hop_cold(c: &mut Criterion) {
    if !integration_enabled() {
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");
    let target_port = rt.block_on(spawn_server());

    let cfg = AnvilConfig::builder("127.0.0.1")
        .port(target_port)
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .build();

    c.bench_function("proxy_chain/1_hop_direct_cold", |b| {
        b.iter(|| {
            rt.block_on(async {
                let session = AnvilSession::connect(&cfg).await.expect("connect");
                session.close().await.expect("close");
            });
        });
    });
}

fn bench_two_hop_cold(c: &mut Criterion) {
    if !integration_enabled() {
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");
    let bastion_port = rt.block_on(spawn_server());
    let target_port = rt.block_on(spawn_server());

    let cfg = AnvilConfig::builder("127.0.0.1")
        .port(target_port)
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .build();

    let jumps = vec![JumpHost {
        host: "127.0.0.1".to_owned(),
        port: bastion_port,
        user: Some("user".to_owned()),
        identity_files: Vec::new(),
    }];

    c.bench_function("proxy_chain/2_hop_via_bastion_cold", |b| {
        b.iter(|| {
            rt.block_on(async {
                let session = AnvilSession::connect_via_jump_hosts(&cfg, &jumps)
                    .await
                    .expect("connect_via_jump_hosts");
                session.close().await.expect("close");
            });
        });
    });
}

/// Hard-fail enforcement: 2-hop median ≤ 2× 1-hop median on the same
/// loopback link.  Runs after the Criterion measurements so the panic
/// message lands after the per-bench summaries.
fn enforce_nfr16_ratio(c: &mut Criterion) {
    const RUNS: usize = 16;

    if !integration_enabled() {
        return;
    }
    let _ = c; // Criterion arg unused; we run a separate measurement loop.

    let rt = tokio::runtime::Runtime::new().expect("tokio rt");
    let bastion_port = rt.block_on(spawn_server());
    let target_port = rt.block_on(spawn_server());

    let cfg = AnvilConfig::builder("127.0.0.1")
        .port(target_port)
        .strict_host_key_checking(StrictHostKeyChecking::No)
        .build();

    let jumps = vec![JumpHost {
        host: "127.0.0.1".to_owned(),
        port: bastion_port,
        user: Some("user".to_owned()),
        identity_files: Vec::new(),
    }];

    let mut one_hop = Vec::with_capacity(RUNS);
    let mut two_hop = Vec::with_capacity(RUNS);

    for _ in 0..RUNS {
        let start = Instant::now();
        rt.block_on(async {
            let s = AnvilSession::connect(&cfg).await.expect("1-hop connect");
            s.close().await.expect("close");
        });
        one_hop.push(start.elapsed());

        let start = Instant::now();
        rt.block_on(async {
            let s = AnvilSession::connect_via_jump_hosts(&cfg, &jumps)
                .await
                .expect("2-hop connect");
            s.close().await.expect("close");
        });
        two_hop.push(start.elapsed());
    }
    one_hop.sort();
    two_hop.sort();
    let one_hop_median = one_hop[RUNS / 2];
    let two_hop_median = two_hop[RUNS / 2];

    eprintln!(
        "proxy_chain/nfr16: 1-hop median = {} µs, 2-hop median = {} µs (ratio {:.2}×)",
        one_hop_median.as_micros(),
        two_hop_median.as_micros(),
        two_hop_median.as_secs_f64() / one_hop_median.as_secs_f64(),
    );

    assert!(
        two_hop_median <= one_hop_median * 2,
        "NFR-16 (loopback proxy): 2-hop median {} µs > 2 × 1-hop median {} µs. \
         Real-RTT validation against a 50 ms link is a separate manual step.",
        two_hop_median.as_micros(),
        one_hop_median.as_micros(),
    );
}

criterion_group!(
    benches,
    bench_one_hop_cold,
    bench_two_hop_cold,
    enforce_nfr16_ratio,
);
criterion_main!(benches);
