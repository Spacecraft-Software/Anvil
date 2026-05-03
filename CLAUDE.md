# CLAUDE.md — Anvil

Anvil is a pure-Rust SSH stack for Git tooling: transport, keys, signing, agent.  Extracted from [Steelbore/Gitway](https://github.com/steelbore/gitway) at commit `28abee6`.  Primary consumer is the Gitway CLI binaries (`gitway`, `gitway-keygen`, `gitway-add`).

## Layout

```
src/
  session.rs           russh-backed transport
  auth.rs              key discovery + agent-auth
  hostkey.rs           pinned fingerprints (GitHub / GitLab / Codeberg)
  relay.rs             bidirectional stdin/stdout/stderr relay
  config.rs            transport config builder
  error.rs             unified error + SFRS exit codes
  keygen.rs            Ed25519/ECDSA/RSA keygen
  sshsig.rs            SSHSIG sign/verify/check-novalidate/find-principals
  allowed_signers.rs   git allowed_signers parser
  diagnostic.rs        single-line stderr diagnostic helper
  time.rs              ISO 8601 timestamp helpers
  agent/
    askpass.rs         $SSH_ASKPASS-driven interactive confirm
    client.rs          blocking SSH-agent client
    daemon.rs          async SSH-agent server (Session trait impl)
tests/
  test_connection.rs   gated real-network tests
  test_clone.rs        end-to-end git clone
benches/
  throughput.rs        criterion throughput benchmark
```

## Build and test

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
GITWAY_INTEGRATION_TESTS=1 cargo test -- --ignored   # network tests
```

`perl` is required by `aws-lc-rs` (assembly pre-processing) on every platform; `nasm` is also required on Windows MSVC.  On Linux, `musl-tools` is needed for the static target used in CI release builds.

## Key invariants

- **`#![forbid(unsafe_code)]`** — no unsafe in project-owned code.
- **Pinned host keys** — SHA-256 fingerprints for GitHub, GitLab, and Codeberg are embedded in `src/hostkey.rs`.  Update them by fetching the official fingerprint pages and running `cargo test` to verify.
- **stdout stays clean** — diagnostic output goes to stderr.  The library deliberately exposes no stdout-touching APIs; output framing is the consumer's concern.
- **Passphrase zeroization** — any `String` holding a passphrase must be wrapped in `Zeroizing<String>`.
- **Exit codes (when consumed via Gitway's SFRS error mapping):**
  - `0` — success
  - `1` — general / unexpected error
  - `2` — usage error (bad arguments, invalid configuration)
  - `3` — not found (no key, unknown host)
  - `4` — permission denied (auth failed, host key mismatch)

## SSH fingerprint rotation procedure

When a hosting provider rotates its host key:

1. Fetch the new fingerprint from the provider's official documentation page.
2. Update the constant in `src/hostkey.rs`.
3. Run `cargo test` to ensure the embedded tests still pass.
4. Open a PR; the CI pipeline validates all targets.  Downstream consumers (Gitway, etc.) bump their `anvil-ssh` pin on next release.

Provider fingerprint pages:

- GitHub: <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
- GitLab: <https://docs.gitlab.com/ee/user/gitlab_com/#ssh-host-keys-fingerprints>
- Codeberg: <https://codeberg.org/Codeberg/Community/issues/1192>

## Security invariants

- `SSH_ASKPASS` must be an absolute path (enforced in `agent::askpass::try_askpass`).
- World-writable `SSH_ASKPASS` programs are rejected on Unix.
- `from_utf8_lossy` is forbidden on passphrase data; use `from_utf8` and reject non-UTF-8 output.
- The raw stdout buffer from `SSH_ASKPASS` is zeroized on every exit path (success, error, and early return).

## Crypto backend

`russh` is configured with the `aws-lc-rs` backend (non-FIPS, no CMake needed).  Do not switch to `ring` — `aws-lc-rs` provides post-quantum algorithm support that `ring` lacks.  On Windows, `nasm` is required for the build (handled in CI).

The `ssh-key` RustCrypto stack (`ed25519-dalek` 2.x, `rsa` 0.9, `p256`/`p384`/`p521`) is used only for keygen and SSHSIG blob formatting.  `PrivateKey` values never cross the boundary between the two stacks.

## Type rename roadmap

- `v0.1.x` — types stay `GitwaySession` / `GitwayConfig` / `GitwayError`.  Doc-comments and `use` paths reference `anvil_ssh::` (Rust module path), but the type names retain their `Gitway*` prefix.
- `v0.2.0` — rename types to `Anvil*` with `#[deprecated]` aliases for one major version.
- `v1.0.0` — stabilization (concurrent with Gitway 1.0.0).

## Related

- [Steelbore/Gitway](https://github.com/steelbore/gitway) — primary consumer.
- [Gitway PRD v1.0](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md) — full v1.0 scope and roadmap.
