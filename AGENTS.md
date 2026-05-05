# AGENTS.md — Anvil

Guidelines for AI agents working in the Anvil codebase.

## What Anvil is

Pure-Rust SSH stack for Git tooling: transport, keys, signing, agent.  Foundation library extracted from [Steelbore/Gitway](https://github.com/steelbore/gitway); primary consumer is the Gitway CLI binaries (`gitway`, `gitway-keygen`, `gitway-add`).

## Rust coding conventions

- Follow the **Steelbore Rust Guidelines** (invoke `/rust-guidelines` skill before any Rust edit).
- All new Rust files must begin with `// SPDX-License-Identifier: GPL-3.0-or-later`.
- All public types must implement `Debug` (derive or custom).
- Use `#[expect(..., reason = "...")]` instead of `#[allow(...)]` for lint suppression.
- Comments must be in American English.
- Passphrase-holding strings must always use `Zeroizing<String>`.

## Forbidden patterns

- **No `unsafe` code.**  The crate enforces `#![forbid(unsafe_code)]`.
- **No `from_utf8_lossy` on passphrase data** — use `from_utf8` and return an error on non-UTF-8 output.
- **No relative `SSH_ASKPASS` paths** — the code already enforces absolute paths; do not relax this check.
- **No new panic sites** unless the invariant is genuinely unreachable (document why).
- **No TOFU (Trust On First Use)** for host key verification of known providers.

## Adding a new Git hosting provider

1. Find the provider's official SSH host key fingerprint documentation page.
2. Add `const DEFAULT_<PROVIDER>_HOST: &str` and `const <PROVIDER>_FINGERPRINTS` to `src/hostkey.rs`.
3. Add a `fingerprints_for_host` match arm covering the new host constant.
4. Add a `AnvilConfig::<provider>()` convenience constructor in `src/config.rs`.
5. Add tests for the new provider in `hostkey.rs`.
6. Update `CLAUDE.md` with the new fingerprint rotation URL.
7. Open a PR; downstream consumers (Gitway and friends) bump their pinned `anvil-ssh` version on next release.

## Dependency policy

- No new crates without discussion.  The dependency tree is intentionally narrow.
- `serde` (with derive) is intentionally absent — JSON output is the consumer's concern, not the library's.
- `chrono` and `time` are intentionally absent — ISO 8601 timestamps use the dependency-free helpers in `time.rs`.
- Do not switch the russh crypto backend from `aws-lc-rs` to `ring`.

## Tests

- Unit tests live inline in each module.
- Integration tests in `tests/`:
  - `test_connection.rs` — gated network test (`GITWAY_INTEGRATION_TESTS=1`)
  - `test_clone.rs` — full git clone end-to-end (also network-gated)
- Run hermetic tests with `cargo test`; network tests with `GITWAY_INTEGRATION_TESTS=1 cargo test -- --ignored`.

## Type rename roadmap

- `v0.1.x` — types carried over from the source crate as `GitwaySession` / `GitwayConfig` / `GitwayError` to keep the lift-and-shift extraction zero-rename.
- `v0.2.0` — types renamed to `AnvilSession` / `AnvilConfig` / `AnvilError`. Legacy `Gitway*` names retained as `#[deprecated]` re-exports.
- `v1.0.0` (current) — stabilization, cut concurrently with Gitway 1.0.0.  Deprecated `Gitway*` aliases **kept** through the 1.x line.  This is a deliberate softening of the original roadmap (which had proposed removing them at 1.0): the corresponding `gitway-lib` shim re-exports `anvil_ssh::*` glob-style and is preserved through Gitway 1.x per Gitway's `docs/migration-from-v0.9.md`.  Removing the upstream aliases at 1.0 would silently break that shim.
- `v2.0.0` (planned) — deprecated `Gitway*` aliases removed.

## Versioning

SemVer.  As of v1.0.0, the public API is **frozen under SemVer**:

- **Patch bumps** (`1.0.x`) are bug fixes only — no API additions.
- **Minor bumps** (`1.x.0`) may add new public symbols; existing
  ones never change shape or behavior.
- **Major bumps** (`x.0.0`) are reserved for breaking changes and
  are coordinated with downstream consumers (primarily Gitway).

See `CHANGELOG.md` for the cumulative record.
