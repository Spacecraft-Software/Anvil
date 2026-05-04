# Changelog

All notable changes to Anvil are documented here.  Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.9.0] — 2026-05-04

### Added

- **Connection retry, backoff, and timeouts** — the M18 chapter of [Gitway PRD §5.8.7](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md), FR-80..FR-83.  Closes the M12.6 `ConnectTimeout` / `ConnectionAttempts` deferral loop.
  - **New `anvil_ssh::retry` module** — public surface: `RetryPolicy { attempts, base, factor, cap, max_window, connect_timeout }` with builder setters; `Disposition { Retry, Fatal }` + `classify(err)` (FR-82); `RetryAttempt { attempt, reason, elapsed }`; `async fn run<F, Fut, T>(policy, op) -> (T, Vec<RetryAttempt>)` (FR-81, FR-83) — drives a jittered exponential backoff loop with `OsRng` jitter, bails on `max_window` exhaustion, emits a `tracing::warn!` event at the new `CAT_RETRY` category per failed attempt.  `run` is timeout-agnostic — the per-attempt `tokio::time::timeout` wrap lives at the call site.  Default policy: 3 attempts, 250 ms base, ×2 factor, 8 s cap, 30 s max_window, no connect_timeout.
  - **New `anvil_ssh::log::CAT_RETRY = "anvil_ssh::retry"`** appended to `CATEGORIES` for downstream `--debug-categories` validators.
  - **`AnvilError::io_kind()`** returns `Option<std::io::ErrorKind>` for the `Io` variant — used by the FR-82 classifier and useful for downstream consumers inspecting failure categories.
  - **`AnvilError::is_transient()`** wraps the classifier as a single-call predicate.
  - **Three new public `AnvilConfig` fields** — `connect_timeout: Option<Duration>`, `connection_attempts: Option<u32>`, `max_retry_window: Option<Duration>` — and matching `AnvilConfigBuilder` setters.  Each `None` falls through to `RetryPolicy::default()` at session-build time.
  - **`apply_ssh_config` consumes `connect_timeout` + `connection_attempts`** from the parsed `ssh_config` (only when the builder field is `None` — preserves CLI-wins precedence).  `max_retry_window` is CLI-only — not in OpenSSH's grammar.
  - **`AnvilSession::connect` wrapped in `retry::run`** — each attempt rebuilds `HandlerPieces` (russh consumes the handler), calls `client::connect` inside `tokio::time::timeout` when `connect_timeout` is `Some`, surfaces `Elapsed` as `Io(TimedOut)` so the FR-82 classifier retries it.  Auth / host-key / protocol errors are fatal and surface immediately.
  - **`AnvilSession::retry_history()`** accessor returns `&[RetryAttempt]` — empty when first attempt succeeded, otherwise the per-attempt history captured during connect.  Surfaces in `gitway --test --json`'s `data.retry_attempts` envelope (FR-83).

### Changed

- **`anvil-ssh` minor bump** 0.8.0 → 0.9.0 to signal the new public `retry` module + three new `AnvilConfig` fields + `AnvilSession::retry_history` accessor.  Pre-1.0 SemVer: 0.8.x consumers must explicitly opt in.
- **`config.rs::warn_unhonored_directives` removed.**  Every `ssh_config(5)` directive Anvil's resolver parses today is now consumed: `HostKeyAlgorithms` / `KexAlgorithms` / `Ciphers` / `MACs` landed in M17; `ConnectTimeout` / `ConnectionAttempts` in M18.

### Notes

- **HTTP 429/503 detection** (FR-82's defensive wording) is out of scope — Anvil speaks raw SSH.  HTTP statuses only appear in `ProxyCommand` subprocess output that Anvil doesn't parse; a future ProxyCommand-HTTP-CONNECT milestone may extend `classify` to handle them.
- **Russh-handshake failures are NOT retried.**  Once the TCP socket is up, every failure is either a fatal user-input error (auth, host-key) or an in-flight protocol error mid-handshake.  `classify` returns `Fatal` for every `russh::Error` variant.
- **Scope-narrowing for the proxy / jump paths.**  `connect_via_proxy_command` and `connect_via_jump_hosts` (per-hop + final) construct `AnvilSession` with empty `retry_history` — the ProxyCommand subprocess lifecycle and per-hop `direct-tcpip` channels make retry semantics murkier than the primary path; deferred to a follow-up sub-milestone.  `gitway --test` against a direct target host gets the full FR-80..FR-83 coverage today.
- **Public-API additions only** — no breaking changes from 0.8.x.

### Tests

- 15 new unit tests in `retry::tests` covering: default-policy values, builder chainability, classifier matrix (auth-fatal / host-key-fatal / no-key-fatal / io-connection-refused-retry / io-timed-out-retry / io-not-found-retry / io-permission-denied-fatal), run loop (success-first / bail-on-fatal / retry-record-history / exhaust-count), backoff curve (exponential growth, cap enforcement, 1000-draw jitter window).
- Existing 207 lib + integration tests still green; M11–M17 surface unchanged.

## [0.8.0] — 2026-05-04

### Added

- **Algorithm overrides** — the M17 chapter of [Gitway PRD §5.8.6](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md), FR-76..FR-79.  Closes the M12.6 algorithm-override loop: `KexAlgorithms` / `Ciphers` / `MACs` / `HostKeyAlgorithms` directives from `~/.ssh/config` (and the matching CLI overrides M17.4 will land in Gitway 1.0.0-rc.8) now flow through to russh's `Preferred` set instead of being parsed and discarded.
  - **New `anvil_ssh::algorithms` module** — public surface: `pub const DENYLIST: &[&str]` (DSA, 3DES, Arcfour variants, hmac-sha1-96, ssh-1.0); `pub fn is_denylisted` / `apply_denylist`; `pub enum AlgCategory { Kex, Cipher, Mac, HostKey }`; `pub fn apply_overrides(category, base, override_str)` implementing OpenSSH's `+algo` (append) / `-algo` (remove) / `^algo` (front-load) / `algo,algo` (replace) syntax; `pub fn anvil_default_kex` / `anvil_default_ciphers` / `anvil_default_macs` / `anvil_default_host_keys` returning the curated default base for `+/-/^` overrides; `pub struct Catalogue { kex, cipher, mac, host_key }` of `pub struct AlgEntry { name, is_default, denylisted }` and `pub fn all_supported() -> Catalogue` for `gitway list-algorithms` (FR-79).
  - **New `AnvilConfig` fields**: `kex_algorithms`, `ciphers`, `macs`, `host_key_algorithms` (each `Option<Vec<String>>`).  `None` selects the curated default; `Some` is a list already filtered through `apply_overrides`.  Matching `AnvilConfigBuilder` setters added.
  - **`apply_ssh_config` consumption**: `KexAlgorithms` / `Ciphers` / `MACs` / `HostKeyAlgorithms` directives are now plumbed through `apply_overrides` against the curated default and stored on the builder.  The M17 deferral warning that pointed at this work has been removed.
  - **`build_russh_config(&AnvilConfig)`**: signature changed (was `(Duration)`).  Now consumes the four config fields, falling back to `anvil_default_*()` when each `Option` is `None`.  Three new private lookups (`russh_kex_name` / `russh_cipher_name` / `russh_mac_name`) map user strings to russh's `&'static str`-backed `Name` constants; unknown names are silently dropped (russh's `Name` types only accept `'static`).  Host-key field uses the existing `russh::keys::Algorithm::FromStr` impl.
  - **FR-66 / M15 instrumentation**: new `tracing::trace!` event at `CAT_KEX` listing the four offered preference vectors before `client::connect` — answers "what did Gitway TRY to negotiate?" alongside M15.2's `check_server_key` event.

### Changed

- **`anvil-ssh` minor bump** 0.7.0 → 0.8.0 to signal the new `algorithms` module + four new public `AnvilConfig` fields + the `build_russh_config` signature change.  Pre-1.0 SemVer: 0.7.x consumers must explicitly opt in.

### Notes

- **FR-78 enforcement** is deliberate.  Russh 0.59 already excludes most denylisted algorithms by default; the explicit list in `algorithms::DENYLIST` is a defensive belt-and-suspenders pass at the override boundary.  Operators who genuinely need to reach a legacy peer that only speaks DSA / 3DES / Arcfour / SHA-1 HMAC <96-bit must use external `ssh -W` as a `ProxyCommand` and accept the security loss explicitly.
- **HMAC-SHA1 caveat** (M19 inheritance): the privacy-only HMAC-SHA1 used for `HashKnownHosts` is unrelated to the FR-78 `hmac-sha1-96` denylist entry.  The denylist targets MAC negotiation in the SSH protocol, not the privacy-preserving hostname hash.
- **Public-API additions only** — no breaking changes from 0.7.x for downstream consumers (the `build_russh_config` signature change is crate-private).

### Tests

- 23 new unit tests in `algorithms::tests` covering: denylist case-insensitivity, every prefix branch (none / + / - / ^ / empty), case-insensitive dedup on append, silent skip on remove of absent, OpenSSH front-load semantics (reorder-not-add), denylisted-token rejection in any prefix form, error-hint shape, whitespace trim + empty-token drop, catalogue invariants (≥1 default per category, default+denylisted disjoint, ssh-dss tagged), curated-defaults exclude denylist, host-key default excludes ssh-dss / includes ssh-ed25519, category-label stability.
- Existing `session::tests` updated to construct an `AnvilConfig` for the new `build_russh_config` signature.

## [0.7.0] — 2026-05-04

### Added

- **`HashKnownHosts yes` round-trip support** — the M19 chapter of [Gitway PRD §5.8.8](https://github.com/Steelbore/Gitway/blob/main/Gitway-PRD-v1.0.md), FR-84.  Anvil now parses, matches, and emits OpenSSH's privacy-preserving `|1|<base64-salt>|<base64-hmac-sha1>` host-column format so a `known_hosts` file generated by `ssh-keygen -H` round-trips through Anvil cleanly and so Anvil-generated entries are readable by stock OpenSSH.
  - **New `cert_authority::HashedHost { salt: [u8;20], hash: [u8;20], fingerprint: String }`** with `pub fn matches(&self, host: &str) -> bool` running HMAC-SHA1(salt, host) and comparing in constant time via `Hmac::verify_slice`.  Skip-with-warn behaviour from M14.1's `|1|...|...` stub is replaced with real per-token parsing — comma-separated host columns can now mix hashed and plaintext tokens, each classified independently.
  - **New `KnownHostsFile.hashed: Vec<HashedHost>`** field — additive, no breaking change for consumers that destructure the existing three vectors.
  - **New `hostkey::append_known_host_hashed(path, host, fp)`** — emits a freshly-salted hashed line; round-trippable through `parse_known_hosts` + `HashedHost::matches`.
- **`@revoked` write helper** (FR-86) — new `pub fn hostkey::prepend_revoked(path, host_pattern, fp)` does atomic prepend via tempfile + `std::fs::rename`.  1 MiB file-size cap with a clear error message on overrun.
- **`hostkey::all_embedded() -> Vec<(String, String, &'static str)>`** — exposes the embedded GitHub / GitLab / Codeberg fingerprint catalogue tagged by algorithm (`ed25519`/`ecdsa`/`rsa`) so `gitway hosts list` (M19.4) can render the embedded section without hard-coding.
- **`hostkey::HashMode` + `detect_hash_mode(path)`** — inspects an existing `known_hosts` file and decides whether new entries should be hashed or plaintext, matching OpenSSH's per-file convention.

### Changed

- **Promoted to `pub`:** `hostkey::default_known_hosts_path()` (was crate-private) and `hostkey::append_known_host()` (was `pub(crate)`) so the `gitway hosts` verb family in M19.4 can drive the write side without a re-export shim.
- **`anvil-ssh` minor bump** 0.6.0 → 0.7.0 to signal the new `HashedHost` type, the new write-side helpers, and the visibility promotions.  Pre-1.0 SemVer: 0.6.x consumers must explicitly opt in.
- **New deps:** `hmac = "0.12"`, `sha1 = "0.10"`, `base64 = "0.22"`.  All three were already pulled transitively via `ssh-key` / `russh`; declaring them directly keeps intent legible in `cargo tree` and prevents a future minor bump from silently dropping them.

### Notes

- HMAC-SHA1 here is a **privacy** primitive (file-readable host enumeration resistance), **not** a security primitive.  SHA-1 collisions don't matter — the salt is per-line and 160 bits, the input is a low-entropy hostname, and the threat model is exactly OpenSSH's: hide the host list from a casual file reader.  Documented inline in `cert_authority.rs`.
- File locking and duplicate-detection are still deferred (PRD §5.8.8 risks).
- Public-API additions only — no breaking changes from 0.6.x.

### Tests

- 8 new hermetic integration tests in `tests/test_hashed_hosts.rs` exercising the full parse → match → reject pipeline with programmatically-constructed fixtures (no pre-generated golden bytes).  Covers single-line parse, mismatch / empty / substring rejection, mixed file with hashed + plaintext, malformed-token warn-and-skip, multi-host column with one hash per token, Clone+Eq derive stability, and case-sensitivity-by-design.
- 13 new hermetic integration tests in `tests/test_hostkey_writes.rs` covering plaintext + hashed append round-trips, distinct-salt-per-call (privacy property), revoke prepend position + oversize refusal, hash-mode detection across all four file states (empty / missing / plaintext / hashed), embedded-catalogue completeness, and the default-path platform check.

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
