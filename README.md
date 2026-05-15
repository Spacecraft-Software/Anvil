# Anvil

**Pure-Rust SSH stack for Git tooling — transport, keys, signing, agent.**

Anvil is the foundation library extracted from [Spacecraft-Software/Gitway](https://github.com/Spacecraft-Software/gitway). It packages everything Git needs from SSH, and nothing it doesn't: pinned-host transport, key generation, SSHSIG commit signing, and an SSH agent (client + daemon). Pure Rust end to end. No C runtime at link time. `#![forbid(unsafe_code)]` in project-owned code.

## Status

**`v1.0.0`** — first stable release.  Public API frozen under SemVer
through the 1.x line.  Full release notes in [CHANGELOG.md](CHANGELOG.md);
roadmap context in the [Gitway PRD](https://github.com/Spacecraft-Software/Gitway/blob/main/Gitway-PRD-v1.0.md).

**MSRV:** Rust 1.88.

## Use

```toml
[dependencies]
anvil-ssh = "1.0"
```

```rust,no_run
use anvil_ssh::{AnvilConfig, AnvilSession};

#[tokio::main]
async fn main() -> Result<(), anvil_ssh::AnvilError> {
    let config = AnvilConfig::github();
    let mut session = AnvilSession::connect(&config).await?;
    session.authenticate_best(&config).await?;
    let exit_code = session.exec("git-upload-pack 'Spacecraft-Software/gitway.git'").await?;
    session.close().await?;
    Ok(())
}
```

The flat re-exports `AnvilSession` / `AnvilConfig` / `AnvilError`
were renamed in `0.2.0` from the legacy `GitwaySession` /
`GitwayConfig` / `GitwayError`.  The legacy names remain available
as `#[deprecated]` re-exports through the entire 1.x line; removal
is scheduled for 2.0.0.  Migration is mechanical — `s/Gitway/Anvil/g`
in your `use anvil_ssh::*;` imports.

## Feature matrix (v1.0)

| Area | What's supported | What's deferred |
| ---- | ---------------- | --------------- |
| **Transport** | SSH-2 connect, exec channel, pinned host-key verification (SHA-256 fingerprints for GitHub, GitLab, Codeberg), `aws-lc-rs` crypto | None for v1.0 |
| **`ssh_config(5)`** | Lexer/parser/resolver, `Include`, `Host`, `HostName`, `Port`, `User`, `IdentityFile`, `IdentityAgent`, `IdentitiesOnly`, `CertificateFile`, `StrictHostKeyChecking`, `UserKnownHostsFile`, `ProxyCommand` (incl. `=none` sentinel), `ProxyJump`, `KexAlgorithms`/`Ciphers`/`MACs`/`HostKeyAlgorithms`, `ConnectTimeout`, `ConnectionAttempts` | Full `Match` block semantics (parsed; never matches; deferred to 1.x minor) |
| **Proxies** | `ProxyCommand` token expansion (`%h %p %r %n %%`); `ProxyJump` chains up to 8 hops; independent host-key verification at every hop | Per-hop retry semantics (single-attempt fallback for proxy paths) |
| **`@cert-authority` host CA** | Parsing, surfacing in audit logs, `@revoked` blocklist with policy-overriding semantics | Live cert validation during KEX (FR-61/62/63 — blocked on russh upstream; will land in 1.x) |
| **Connection retry** | Exponential backoff with jitter, fatal-vs-transient classifier, per-attempt timeout, max-retry-window, retry history accessor | HTTP 429/503 (no HTTP layer in transport path) |
| **Algorithm overrides** | OpenSSH `+/-/^/replace` syntax, denylist (DSA / 3DES / RC4 / hmac-sha1-96 / SSH-1) | None for v1.0 |
| **`known_hosts`** | Parse and write hashed (`HashKnownHosts yes`) entries via HMAC-SHA1; `@cert-authority`, direct, and `@revoked` lines; embedded fingerprint catalogue | None for v1.0 |
| **Keys** | Ed25519 / ECDSA-P256/P384/P521 / RSA generation in OpenSSH format; passphrase encryption + change | FIDO2 / `sk-ssh-*` hardware-backed keys (deferred to 1.x; see Gitway PRD §5.8.5 / M16) |
| **Signing** | SSHSIG produce / verify / `find-principals` / `check-novalidate`; `allowed_signers` file parser | None for v1.0 |
| **Agent** | Cross-platform client (Unix domain socket on Unix; named pipe on Windows interoperable with `\\.\pipe\openssh-ssh-agent`); async daemon (Unix `setsid(2)` + Windows foreground modes) | Background-mode `gitway agent start` without `-D` is Unix-only; Windows requires foreground (`-D` plus a launcher) |
| **Tracing** | Per-category targets (`CAT_KEX`, `CAT_AUTH`, `CAT_CHANNEL`, `CAT_CONFIG`, `CAT_RETRY`); `tracing_log` bridge for legacy `log::*!` callers; structured events at every host-key check, auth attempt, applied directive, and ProxyJump hop | None for v1.0 |

## What this is NOT

- **Not a general-purpose SSH library.**  Anvil targets the SSH
  surface that Git needs — exec channels, key management, signing,
  agent.  No PTY, no SFTP, no port forwarding, no SCP.
- **Not a TLS or HTTP toolkit.**  SSH only.
- **Not a runtime.**  Anvil exposes async APIs but doesn't install
  a tracing subscriber or pick an executor for you.  Consumers
  (typically [Gitway](https://github.com/Spacecraft-Software/Gitway)) own the
  runtime/subscriber policy.
- **Not a TOFU implementation.**  The known-host fingerprints for
  GitHub, GitLab, and Codeberg are pinned at build time.  Adding
  a new provider is a code change, reviewed and shipped in a
  minor release.

## Modules

| Module                | Purpose                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `session`             | russh-backed SSH session lifecycle (connect, retry-wrapped)      |
| `config`              | `AnvilConfig` builder; convenience constructors per provider     |
| `error`               | `AnvilError` and the unified error taxonomy                      |
| `auth`                | Identity discovery (CLI flag → `~/.ssh` paths → SSH agent)       |
| `hostkey`             | Pinned host fingerprints; `host_key_trust` audit-log API         |
| `cert_authority`      | `@cert-authority` / `@revoked` parser + `HashedHost` (M19)       |
| `ssh_config`          | OpenSSH `ssh_config(5)` lexer / parser / matcher / resolver       |
| `proxy`               | `ProxyCommand` token expansion + `ProxyJump` chains              |
| `algorithms`          | KEX/cipher/MAC/host-key catalogue + override syntax + denylist   |
| `retry`               | `RetryPolicy` + classifier + jittered exponential-backoff loop   |
| `relay`               | Bidirectional stdin/stdout/stderr relay over an exec channel     |
| `keygen`              | Ed25519 / ECDSA / RSA keypair generation in OpenSSH format       |
| `sshsig`              | SSHSIG sign / verify / `find-principals` / `check-novalidate`    |
| `allowed_signers`     | Parser for git's `allowed_signers` file format                   |
| `agent::client`       | Cross-platform SSH agent client (`ssh-add` equivalent)           |
| `agent::daemon`       | SSH agent server (`ssh-agent` equivalent)                        |
| `agent::askpass`      | `$SSH_ASKPASS`-driven interactive confirmation                   |
| `log`                 | Tracing-category constants + `install_log_bridge()`              |
| `diagnostic`          | Single-line stderr failure diagnostic helper                     |
| `time`                | ISO 8601 timestamp helpers (no `chrono` / `time` crate dep)      |

## Crypto backends

Anvil layers two pure-Rust crypto stacks:

- **Transport** — [`russh`](https://github.com/warp-tech/russh) with the `aws-lc-rs` backend (post-quantum-ready; no CMake on non-FIPS builds).
- **Keys + signing** — RustCrypto (`ed25519-dalek`, `rsa`, `p256/384/521`) via [`ssh-key`](https://github.com/RustCrypto/SSH).

`PrivateKey` values never cross the boundary between the two stacks.

## Build

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`perl` is required by `aws-lc-rs` for assembly pre-processing on every platform; `nasm` is also required on Windows MSVC.

## Security

See [Gitway's `docs/security.md`](https://github.com/Spacecraft-Software/Gitway/blob/main/docs/security.md) for the full threat model.  TL;DR: Anvil defends against active network attackers (pinned fingerprints, algorithm denylist, `@revoked` enforcement) and memory-safety classes (`#![forbid(unsafe_code)]` everywhere).  One known residual risk is documented:

- **RUSTSEC-2023-0071** — Marvin Attack on the `rsa` crate.  No upstream patch yet; we use `rsa` only for local keygen + SSHSIG signing (transport crypto is `aws-lc-rs`, constant-time).  The default key type is Ed25519, which is unaffected.

Disclosure policy: [Gitway's `SECURITY.md`](https://github.com/Spacecraft-Software/Gitway/blob/main/SECURITY.md).

## License

GPL-3.0-or-later. Copyright © 2026 Mohamed Hammad. See [LICENSE](LICENSE).

## Related

- [Spacecraft-Software/Gitway](https://github.com/Spacecraft-Software/gitway) — primary consumer; the full Git-over-SSH toolkit (`gitway`, `gitway-keygen`, `gitway-add` binaries) built on top of Anvil.
