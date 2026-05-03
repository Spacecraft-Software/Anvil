# Anvil

**Pure-Rust SSH stack for Git tooling — transport, keys, signing, agent.**

Anvil is the foundation library extracted from [Steelbore/Gitway](https://github.com/steelbore/gitway). It packages everything Git needs from SSH, and nothing it doesn't: pinned-host transport, key generation, SSHSIG commit signing, and an SSH agent (client + daemon). Pure Rust end to end. No C runtime at link time. `#![forbid(unsafe_code)]` in project-owned code.

## Status

`v0.1.0` — initial cold-start extraction from Steelbore/Gitway @ `28abee6`. Pre-1.0; the public type names will rename in `0.2.0` (see [CHANGELOG](CHANGELOG.md)). Full v1.0 scope and roadmap live in the [Gitway PRD](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md).

## Use

```toml
[dependencies]
anvil-ssh = "0.1"
```

```rust,no_run
use anvil_ssh::{GitwayConfig, GitwaySession};

#[tokio::main]
async fn main() -> Result<(), anvil_ssh::GitwayError> {
    let config = GitwayConfig::github();
    let mut session = GitwaySession::connect(&config).await?;
    session.authenticate_best(&config).await?;
    let exit_code = session.exec("git-upload-pack 'steelbore/gitway.git'").await?;
    session.close().await?;
    Ok(())
}
```

The type names (`GitwaySession`, `GitwayConfig`, `GitwayError`) are inherited from the source crate. They will be renamed to `AnvilSession` / `AnvilConfig` / `AnvilError` in `0.2.0` with `#[deprecated]` aliases for one major version.

## Modules

| Module                | Purpose                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `session`             | russh-backed SSH session lifecycle                               |
| `auth`                | Identity discovery (CLI flag → `~/.ssh` paths → SSH agent)       |
| `hostkey`             | Pinned host fingerprints (GitHub, GitLab, Codeberg)              |
| `relay`               | Bidirectional stdin/stdout/stderr relay over an exec channel     |
| `keygen`              | Ed25519 / ECDSA / RSA keypair generation in OpenSSH format       |
| `sshsig`              | SSHSIG sign / verify / `find-principals` / `check-novalidate`    |
| `allowed_signers`     | Parser for git's `allowed_signers` file format                   |
| `agent::client`       | Blocking SSH agent client (`ssh-add` equivalent)                 |
| `agent::daemon`       | Async SSH agent server (`ssh-agent` equivalent)                  |
| `agent::askpass`      | `$SSH_ASKPASS`-driven interactive confirmation                   |
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

## License

GPL-3.0-or-later. Copyright © 2026 Mohamed Hammad. See [LICENSE](LICENSE).

## Related

- [Steelbore/Gitway](https://github.com/steelbore/gitway) — primary consumer; the full Git-over-SSH toolkit (`gitway`, `gitway-keygen`, `gitway-add` binaries) built on top of Anvil.
