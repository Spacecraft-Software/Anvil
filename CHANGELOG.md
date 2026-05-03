# Changelog

All notable changes to Anvil are documented here.  Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

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
