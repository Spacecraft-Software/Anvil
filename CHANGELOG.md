# Changelog

All notable changes to Anvil are documented here.  Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

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

- Type names (`GitwaySession`, `GitwayConfig`, `GitwayError`) carry forward from the source crate unchanged.  They will be renamed to `AnvilSession` / `AnvilConfig` / `AnvilError` in `0.2.0` with `#[deprecated]` aliases.  See [Gitway PRD §7.4](https://github.com/steelbore/gitway/blob/main/Gitway-PRD-v1.0.md) for the extraction plan.
- This is a *cold-start* extraction: the new repo's git history starts here.  Per-commit history of the original library remains in [steelbore/gitway](https://github.com/steelbore/gitway) — `git blame` and historical context for any line of code can be found there.
