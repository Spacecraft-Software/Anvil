# Changelog

All notable changes to Anvil are documented here.  Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.6.0] — 2026-05-04

### Added

- **`tracing` infrastructure for the M15 verbose / JSONL debug surface** — the M15 chapter of [Gitway PRD §5.8.4](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md).  Anvil now emits structured `tracing::*!` events at per-category targets so a downstream consumer (Gitway CLI, integration tests, log aggregators) can install one [`tracing_subscriber::EnvFilter`] and get exactly the depth they want in each category — without scraping log lines.
  - **New `anvil_ssh::log` module** — public surface: `pub const CAT_KEX = "anvil_ssh::kex"` (and `CAT_AUTH`, `CAT_CHANNEL`, `CAT_CONFIG`); `pub const CATEGORIES: &[&str]` for downstream input validation; `pub fn install_log_bridge() -> Result<(), tracing_log::log_tracer::SetLoggerError>` wraps `tracing_log::LogTracer::init()` with documented idempotency + ordering semantics.  The bridge funnels every existing `log::*!` call (Anvil, russh, ssh-key) through the consumer's `tracing` subscriber, so M15.4 (Gitway CLI) sees one event stream regardless of macro flavor.  Anvil itself does not install a subscriber — that policy belongs to the consumer.
  - **FR-66 instrumentation across `session.rs`, `auth.rs`, `ssh_config/resolver.rs`, `proxy/jump.rs`, `hostkey.rs`** — every host-key check, every authentication attempt, every applied `~/.ssh/config` directive (with `(file, line, directive, value)`), and every ProxyJump hop now emits a structured `tracing::*!` event.  Same `{host, fp, verdict, …}` shape across all five `check_server_key` outcome paths so a JSONL consumer can group / count.

### Changed

- **`anvil-ssh` minor bump** 0.5.0 → 0.6.0 to signal the new `anvil_ssh::log` module + new public dependency on `tracing` and `tracing-log`.  Pre-1.0 SemVer: 0.5.x consumers must explicitly opt in.
- **New transitive deps** — `tracing = "0.1"`, `tracing-log = "0.2"`.  Both are MSRV-1.88-clean.

### Notes

- **No subscriber is installed by the library.**  The consumer (Gitway CLI in M15.4) builds an `EnvFilter` from its `-v`/`-vv`/`-vvv` count + `--debug-format` + `--debug-categories` flags and chooses the layer (`fmt::layer()` for human, `fmt::layer().json()` for JSONL).  Library users in test contexts can install `tracing_subscriber::fmt::init()` for a default human formatter.
- **Existing `log::*!` call sites preserved verbatim.**  ~59 sites across Anvil + russh + ssh-key keep working through the bridge; rewriting them to native `tracing::*!` macros is post-1.0 housekeeping, not an M15 concern.
- **Public-API additions only** — no breaking changes from 0.5.x.

## [0.5.0] — 2026-05-04

### Added

- **`@cert-authority` parser and `host_key_trust` API** — the M14 chapter of [Gitway PRD §5.8.3](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md), partial.  Anvil now parses the OpenSSH `@cert-authority` and `@revoked` markers in `known_hosts`-style files, exposes the parsed view as a public type, and enforces `@revoked` as a policy-overriding blocklist during `check_server_key`.  Live cert validation against `@cert-authority` lines during the SSH handshake (FR-61, FR-62, FR-63) is **deferred** — see Notes.
  - **New `cert_authority` module** — `anvil_ssh::cert_authority::parse_known_hosts(content) -> Result<KnownHostsFile, AnvilError>`.  Public types: `CertAuthority` (host pattern + algorithm + SHA-256 fingerprint + raw OpenSSH text), `RevokedEntry` (host pattern + fingerprint), `DirectHostKey` (existing `host SHA256:fp` line), `KnownHostsFile` (the three vectors).  Markers are recognized case-insensitively per OpenSSH; comma-separated host patterns split into multiple entries; OpenSSH-format `algorithm AAAA... comment` pubkeys parse via `ssh_key::PublicKey::from_openssh` for fingerprint computation; hashed entries (`|1|...|...`) are skipped with a debug log; malformed `@revoked` lines warn-and-skip so an operator typo doesn't brick the connection.
  - **`anvil_ssh::hostkey::host_key_trust(host, custom_path) -> Result<HostKeyTrust, AnvilError>`** — new public fn returning the combined view: embedded fingerprints (GitHub / GitLab / Codeberg) + matching direct pins + matching `@cert-authority` entries + matching `@revoked` entries, all resolved in one `known_hosts` pass.  Reuses `ssh_config::lexer::wildcard_match` from M12 for pattern matching.  Unlike `fingerprints_for_host`, an empty trust set is **not** an error — the caller's policy decides.
  - **`@revoked` enforcement in `check_server_key`** (FR-64) — `GitwayHandler` gains a `revoked: Vec<String>` field; revoked fingerprints are checked **first**, before the `StrictHostKeyChecking::No` bypass and the fingerprint match path.  A presented key whose SHA-256 fingerprint matches a revoked entry is rejected with `host_key_mismatch` and a hint mentioning the `@revoked` entry — no policy can override.

### Changed

- **`AnvilSession::connect` internal refactor (continued from 0.4.0)** — `build_handler_pieces` now sources its host-key trust set from `host_key_trust` instead of `fingerprints_for_host`, so direct pins, revocations, and cert authorities flow through one pass.  The empty-fingerprint branch reproduces the long-form actionable hint that `fingerprints_for_host` previously emitted.  No public-API change.
- **`anvil-ssh` minor bump** 0.4.0 → 0.5.0 to signal the new `cert_authority` module + new public `host_key_trust` API.  Pre-1.0 SemVer: 0.4.x consumers must explicitly opt in.

### Notes

- **FR-61, FR-62, FR-63 deferred to a russh-upstream follow-up.** Russh 0.59's `Preferred::DEFAULT.key` host-key algorithm list contains only plain algorithms (`Algorithm::Ed25519`, `Ecdsa`, `Rsa`); the `*-cert-v01@openssh.com` variants are absent.  A server presenting its host key as a certificate falls back to a plain key during KEX, and Anvil's `check_server_key` callback never sees the certificate, so live cert validation against an `@cert-authority` line cannot run today.  The follow-up will land the validation step the moment russh exposes either an extended `Preferred::DEFAULT.key` with cert variants or a new `Handler::check_server_certificate(&Certificate)` hook.  See [Gitway PRD §10](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md) for the upstream-blocker risk row.
- **Public-API additions only** — no breaking changes from 0.4.x.  Existing `fingerprints_for_host(host, custom_path)` keeps its `Vec<String>` shape.
- **Negated host patterns** (`!host`) and **hashed host names** (`|1|...|...`) in `@cert-authority` entries are pre-existing limitations carried into M14 — documented as follow-ups.

### Tests

- 15 new unit tests in `cert_authority::tests` covering empty input, comments + blanks, direct lines, comma-separated hosts, `@cert-authority` parse + case-insensitive marker + invalid pubkey error, `@revoked` parse + case-insensitive + comma hosts + missing fingerprint, hashed-entry skip, marker-without-space negative case, mixed three-class file, whitespace tolerance.
- 7 new unit tests in `hostkey::tests` covering `host_key_trust` embedded-set seeding, cert-authority pattern match by host glob (positive + negative), `@revoked` pattern match, direct-pin combination with embedded set, missing custom-path tolerance, and the unknown-host-empty path that the `AcceptNew` flow relies on.
- 4 new hermetic integration tests in `tests/test_known_hosts_cert.rs` exercising the published crate boundary (`parse_known_hosts` + `host_key_trust`) — multi-class parser smoke, host-pattern filtering with positive + negative cases, embedded-set preservation across the M14.2 refactor, and parser error-message clarity.
- Total: 207 lib tests + 4 integration tests, 0 failures, 5 ignored (pre-existing).

## [0.4.0] — 2026-05-04

### Added

- **`ProxyCommand` and `ProxyJump` consumers** — the M13 chapter of [Gitway PRD §5.8.2](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md). Anvil now actually consumes the directives M12 captured into `ResolvedSshConfig`:
  - **`AnvilSession::connect_via_proxy_command(config, template, alias)`** (FR-55) — token-expands `%h %p %r %n %%` against `config.host` / `config.port` / `config.username` / `alias`, spawns the resulting command line through the platform shell (`sh -c` on Unix, `cmd /C` on Windows), and uses the child's stdin/stdout as the SSH transport via `russh::client::connect_stream`. The literal `none` (case-insensitive) is rejected as the FR-59 disable sentinel.
  - **`AnvilSession::connect_via_jump_hosts(config, jumps)`** (FR-56, FR-57, NFR-17) — chains through up to `MAX_JUMP_HOPS = 8` bastions via russh `direct-tcpip` channels, with **independent host-key verification at every hop** (failure at hop n+1 aborts the entire chain — no partial-success path). Each bastion is authenticated via `authenticate_best` so the next hop's `direct-tcpip` channel can be opened through it.
- **New `proxy` module** — public surface:
  - `proxy::expand_proxy_tokens(template, host, port, user, alias) -> String` — `%h %p %r %n %%` substitution.
  - `proxy::parse_jump_chain(raw) -> Result<Vec<JumpHost>, AnvilError>` — `[user@]host[:port]` comma-separated parser.
  - `proxy::JumpHost` and `proxy::MAX_JUMP_HOPS`.
- **`ProxyCommand=none` honored** in the `ssh_config` resolver (FR-59) — preserves the literal `"none"` so first-occurrence-wins shields it from a later wildcard, and `gitway config show` mirrors `ssh -G`'s output.

### Changed

- **`AnvilSession::connect` internal refactor** — host-key fingerprint lookup, handler construction, and `auth_banner` / `verified_fingerprint` mutex setup now flow through a private `build_handler_pieces` helper shared by `connect`, `connect_via_proxy_command`, and `connect_via_jump_hosts`. No public-API change.
- **`anvil-ssh` minor bump** 0.3.1 → 0.4.0 to signal the new `proxy` chapter. Pre-1.0 SemVer: 0.3.x consumers must explicitly opt in.

### Notes

- The `proxy::stdio::ChildStdio` adapter is `pub(crate)` for now; promote to public if/when downstream consumers need to wire russh through arbitrary `tokio::process::Child` stdio outside of Anvil's own session constructors.
- Two unix-only round-trip tests (`round_trips_data_through_cat`, `spawns_through_shell_with_token_expansion`) are gated `#[ignore]` due to a `read_to_end`/`shutdown` interaction with `tokio::process::Child` stdio piping observed to hang in CI runners. The full pipeline is covered by the upcoming M13.7 integration test against a `russh::server`. Run the gated tests locally with `cargo test -- --ignored stdio`.

## [0.3.1] — 2026-05-04

### Added

- New `diagnostic::emit_for_with_config_sources(&AnvilError, &[PathBuf])` entry point for the M12.8 NFR-24 wiring.  Emits the standard `gitway diag` line plus a `config_source=path1,path2` field listing the `ssh_config(5)` files that were consulted during the failing invocation.  An empty slice produces output identical to [`emit_for`].  Existing `emit` / `emit_for` continue to work unchanged.

## [0.3.0] — 2026-05-04

### Added

- **`ssh_config(5)` parser and resolver** — `anvil_ssh::ssh_config::resolve(host, paths)` returns a `ResolvedSshConfig` containing every directive from [Gitway PRD §5.8.1](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md): `HostName`, `User`, `Port`, `IdentityFile` (multi), `IdentitiesOnly`, `IdentityAgent`, `CertificateFile` (multi), `ProxyCommand`, `ProxyJump`, `UserKnownHostsFile` (multi), `StrictHostKeyChecking`, `HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs`, `ConnectTimeout`, `ConnectionAttempts`. Per-directive provenance is preserved for `gitway diag` (NFR-24) and `gitway config show`. `Match` blocks are recognized for correct directive grouping but never match a host — full `Match` semantics are deferred to v1.1 per PRD §12 Q1.
- New flat re-exports at the crate root: `AlgList`, `DirectiveSource`, `ResolvedSshConfig`, `SshConfigPaths`, `StrictHostKeyChecking`. The `resolve` free function lives at `anvil_ssh::ssh_config::resolve` to keep the top-level namespace uncluttered.
- New builder method `AnvilConfigBuilder::apply_ssh_config(&ResolvedSshConfig)` layers ssh_config-derived defaults into the builder. CLI-supplied values still win — call `apply_ssh_config()` *before* CLI overrides.
- `AnvilConfigBuilder::add_identity_file()` and `AnvilConfigBuilder::identity_files()` for the multi-key API.
- `AnvilConfigBuilder::strict_host_key_checking(StrictHostKeyChecking)` builder method.
- Minimal `accept-new` write path: when `StrictHostKeyChecking::AcceptNew` is set *and* `custom_known_hosts` is provided, the first-seen fingerprint of an otherwise-unknown host is recorded to that file. Without `custom_known_hosts` set the connect downgrades to `Yes` semantics with a warning. Full TOFU UX (interactive prompt, fingerprint display) is post-M12 polish.

### Changed

- **Breaking (with deprecated shims):** `AnvilConfig.identity_file: Option<PathBuf>` is replaced by `AnvilConfig.identity_files: Vec<PathBuf>`. OpenSSH allows multiple `IdentityFile` directives; the resolver and the auth path now honour the full list in source order. The deprecated accessor `AnvilConfig::identity_file()` returns `identity_files.first().map(PathBuf::as_path)`. The deprecated builder method `AnvilConfigBuilder::identity_file(path)` clears the list and pushes the single path.
- **Breaking (with deprecated shims):** `AnvilConfig.skip_host_check: bool` is replaced by `AnvilConfig.strict_host_key_checking: StrictHostKeyChecking` (the OpenSSH-style enum: `Yes` / `No` / `AcceptNew`). The deprecated accessor `AnvilConfig::skip_host_check()` returns `true` iff the policy is `No`. The deprecated builder method `skip_host_check(true)` maps to `StrictHostKeyChecking::No`; `skip_host_check(false)` to `StrictHostKeyChecking::Yes`. Lossless across the two states the boolean shape encoded.

### Migration (0.2.x → 0.3.0)

```rust
// 0.2.x
let cfg = AnvilConfig::builder("example.com")
    .identity_file("/path/to/key")
    .skip_host_check(true)
    .build();
let key = cfg.identity_file.as_deref();
let skip = cfg.skip_host_check;

// 0.3.0
use anvil_ssh::StrictHostKeyChecking;
let cfg = AnvilConfig::builder("example.com")
    .add_identity_file("/path/to/key")              // or .identity_files(vec![...])
    .strict_host_key_checking(StrictHostKeyChecking::No)
    .build();
let key = cfg.identity_files.first().map(PathBuf::as_path);
let no_check = matches!(cfg.strict_host_key_checking, StrictHostKeyChecking::No);
```

The deprecated 0.2.x methods continue to compile (with deprecation warnings) until they are removed in 1.0.

## [0.2.0] — 2026-05-03

### Changed

- **Breaking (with deprecated aliases):** the three flat re-exports at the crate root were renamed to drop the inherited `Gitway*` prefix:
  - `GitwaySession` → `AnvilSession`
  - `GitwayConfig` → `AnvilConfig`
  - `GitwayError` → `AnvilError`

  The legacy names remain available as `#[deprecated]` re-exports for one major version (per [Gitway PRD §7.4](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md)), so consumers that depended on `anvil-ssh = "0.1"` continue to compile with a deprecation warning until they migrate.  Migration is mechanical:

  ```rust
  // before
  use anvil_ssh::{GitwayConfig, GitwaySession, GitwayError};
  // after
  use anvil_ssh::{AnvilConfig, AnvilSession, AnvilError};
  ```

  The deprecated aliases will be removed in `1.0.0`.

- The `GitwayConfigBuilder` type returned by `AnvilConfig::builder()` is also renamed to `AnvilConfigBuilder`.  It is reachable via `anvil_ssh::config::AnvilConfigBuilder`; no flat re-export at the crate root in either 0.1 or 0.2 (consumers typically obtain it through `AnvilConfig::builder()`).

### Notes

- All internal references in `src/` (struct definitions, doc-comments, tests) have been updated to the new names.  `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all pass on the renamed source.
- Downstream tracking issue: the [Steelbore/Gitway](https://github.com/Steelbore/Gitway) workspace bumps its `anvil-ssh` pin to `0.2.0` in a follow-up PR and renames its in-source `GitwaySession`/`Config`/`Error` references to drop the deprecation warnings.

## [0.1.0] — 2026-05-03

### Added

- Initial cold-start extraction from [Steelbore/Gitway](https://github.com/steelbore/gitway) at commit [`28abee6fef3fb1a0ba3a69af9c78e27d842763db`](https://github.com/steelbore/gitway/commit/28abee6fef3fb1a0ba3a69af9c78e27d842763db).
- Pure-Rust SSH stack covering everything Git needs:
  - SSH transport over `russh` with the `aws-lc-rs` backend (post-quantum-ready).
  - Pinned host-key verification for GitHub, GitLab, and Codeberg.
  - Ed25519 / ECDSA (P-256, P-384, P-521) / RSA (2048–16384) key generation in OpenSSH format.
  - SSHSIG signing, verification, `check-novalidate`, `find-principals`.
  - `allowed_signers` parser (git format).
  - Blocking SSH agent client over `$SSH_AUTH_SOCK` (Unix) and named pipes (Windows).
  - Async SSH agent daemon with in-memory zeroizing key store, TTL eviction, SIGTERM shutdown, and `$SSH_ASKPASS`-driven confirm prompts.

### Notes

- Type names carried forward from the source crate as `GitwaySession` / `GitwayConfig` / `GitwayError` to keep the lift-and-shift extraction zero-rename.  These were superseded in 0.2.0 (see above); the legacy names remain available as `#[deprecated]` re-exports for one major version per [Gitway PRD §7.4](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md).
- This is a *cold-start* extraction: the new repo's git history starts here.  Per-commit history of the original library remains in [steelbore/gitway](https://github.com/steelbore/gitway) — `git blame` and historical context for any line of code can be found there.
