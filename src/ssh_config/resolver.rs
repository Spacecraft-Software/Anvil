// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Public `resolve()` entry point and the [`ResolvedSshConfig`] result.
//!
//! Wires the lexer, include resolver, parser, and host matcher together
//! into one call and applies "first occurrence wins" semantics across the
//! matched directives, mirroring `ssh_config(5)` and OpenSSH's
//! `read_config_file` flow.
//!
//! This is the only module in `ssh_config` whose surface is publicly
//! re-exported from the crate root; the rest are crate-private building
//! blocks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::include::expand_includes;
use super::lexer::{expand_env, expand_tilde, tokenize};
use super::matcher::directives_for_host;
use super::parser::{parse, Directive, HostBlock};
use crate::error::AnvilError;

/// Locations of the `ssh_config` files to read during a [`resolve`] call.
///
/// Both fields are optional so callers can disable either tier (e.g.
/// `gitway --no-config`) or supply an isolated config file for testing.
///
/// Paths are expected to be absolute or already tilde-expanded; relative
/// paths are read relative to the current working directory.  The leading
/// `~` is expanded automatically as a courtesy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfigPaths {
    /// User-level config, typically `~/.ssh/config` on Unix and
    /// `%USERPROFILE%\.ssh\config` on Windows.  `None` skips reading it.
    pub user: Option<PathBuf>,

    /// System-level config, typically `/etc/ssh/ssh_config` on Unix and
    /// `%PROGRAMDATA%\ssh\ssh_config` on Windows.  `None` skips reading.
    pub system: Option<PathBuf>,
}

impl SshConfigPaths {
    /// Returns the platform-default paths.
    ///
    /// On Unix: `~/.ssh/config` (user) and `/etc/ssh/ssh_config` (system).
    /// On Windows: `%USERPROFILE%\.ssh\config` (user) and
    /// `%PROGRAMDATA%\ssh\ssh_config` (system, if `%PROGRAMDATA%` is set).
    /// On other platforms: user only, system `None`.
    #[must_use]
    pub fn default_paths() -> Self {
        let user = dirs::home_dir().map(|h| h.join(".ssh").join("config"));
        let system = if cfg!(unix) {
            Some(PathBuf::from("/etc/ssh/ssh_config"))
        } else if cfg!(windows) {
            std::env::var_os("ProgramData").map(|pd| {
                let mut p = PathBuf::from(pd);
                p.push("ssh");
                p.push("ssh_config");
                p
            })
        } else {
            None
        };
        Self { user, system }
    }

    /// Disables both tiers — reads no config files.  Equivalent to the
    /// `--no-config` CLI flag wired up by Gitway in M12.7.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// `StrictHostKeyChecking` directive value.
///
/// `ask` — OpenSSH's default that prompts the user — is folded into
/// [`StrictHostKeyChecking::Yes`] because Anvil never prompts; the
/// strict-no-unknown semantics are equivalent for our purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    /// `yes` (or `ask`): refuse unknown hosts; refuse mismatches.
    Yes,
    /// `no` (or `off`): accept any host key.  Insecure; primarily useful
    /// for ephemeral test infrastructure.
    No,
    /// `accept-new`: accept new host keys (writing to `known_hosts`)
    /// but refuse mismatches against already-known keys.  M12.5 wires
    /// the minimal write path; full TOFU UX is post-M12 polish.
    AcceptNew,
}

/// A list of algorithm names from a `ssh_config` directive
/// (`HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs`).
///
/// The raw, comma-separated source value is preserved verbatim.  M17
/// adds the OpenSSH `+`/`-`/`^` modifier semantics on top, plumbed
/// through to russh's preference list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgList(pub String);

/// Provenance for one resolved directive — which file and line it came
/// from.  Used by the `gitway diag` line (NFR-24) and `gitway config
/// show` to attribute each value back to its source.
#[derive(Debug, Clone)]
pub struct DirectiveSource {
    /// Lower-cased directive keyword (`identityfile`, `port`, ...).
    pub directive: String,
    /// The source file the directive was read from (post-Include).
    pub file: PathBuf,
    /// 1-indexed line number within `file`.
    pub line: u32,
}

/// Fully-resolved `ssh_config` for one host.
///
/// Every field is optional or a vector — the resolver applies `Some(_)`
/// or appends only when it sees a directive whose keyword maps onto the
/// field; otherwise the field stays at its [`Default`] value.
///
/// "First occurrence wins" applies to all single-valued fields per
/// `ssh_config(5)`.  Multi-valued fields (`identity_files`,
/// `certificate_files`, `user_known_hosts_files`) accumulate every
/// occurrence in source order, again matching OpenSSH.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSshConfig {
    /// `HostName` — the real hostname to connect to (may differ from the
    /// alias the user typed).
    pub hostname: Option<String>,
    /// `User` — login name on the remote.
    pub user: Option<String>,
    /// `Port` — TCP port.
    pub port: Option<u16>,
    /// `IdentityFile` — every `IdentityFile` directive contributes one
    /// entry here, in source order.
    pub identity_files: Vec<PathBuf>,
    /// `IdentitiesOnly` — when `true`, restrict authentication to keys
    /// listed in `identity_files` (no agent-supplied keys).
    pub identities_only: Option<bool>,
    /// `IdentityAgent` — path to a non-default agent socket.
    pub identity_agent: Option<PathBuf>,
    /// `CertificateFile` — every entry contributes one path, in source order.
    pub certificate_files: Vec<PathBuf>,
    /// `ProxyCommand` — captured raw (joined with single spaces);
    /// M13 parses and spawns it.
    pub proxy_command: Option<String>,
    /// `ProxyJump` — captured raw; M13 parses the chain.
    pub proxy_jump: Option<String>,
    /// `UserKnownHostsFile` — every entry contributes one path.
    pub user_known_hosts_files: Vec<PathBuf>,
    /// `StrictHostKeyChecking`.
    pub strict_host_key_checking: Option<StrictHostKeyChecking>,
    /// `HostKeyAlgorithms` — raw spec; M17 plumbs through to russh.
    pub host_key_algorithms: Option<AlgList>,
    /// `KexAlgorithms` — raw spec; M17 plumbs through.
    pub kex_algorithms: Option<AlgList>,
    /// `Ciphers` — raw spec; M17 plumbs through.
    pub ciphers: Option<AlgList>,
    /// `MACs` — raw spec; M17 plumbs through.
    pub macs: Option<AlgList>,
    /// `ConnectTimeout` — measured in seconds in the source file,
    /// stored here as a [`Duration`].
    pub connect_timeout: Option<Duration>,
    /// `ConnectionAttempts`.
    pub connection_attempts: Option<u32>,
    /// One [`DirectiveSource`] entry per directive that contributed to a
    /// known field, in the order applied.  Preserves provenance for
    /// `gitway config show` and the `config_source=` diag-line field.
    pub provenance: Vec<DirectiveSource>,
}

/// Resolves the effective `ssh_config` for `host` against the files
/// listed in `paths`.
///
/// Reads the user file first, then the system file (per `ssh_config(5)`:
/// "first obtained value for each parameter is used").  Within each file,
/// `Include` directives are recursively expanded (see
/// [`super::include::expand_includes`]) before host matching.
///
/// Missing files are silently skipped — only failures to *read* an
/// existing file (permission denied, malformed UTF-8, etc.) bubble up
/// as errors.
///
/// # Errors
/// Returns [`AnvilError::invalid_config`] when:
/// - A read of an existing file fails for reasons other than "not found".
/// - The file is not valid UTF-8.
/// - The file is malformed (unterminated quote, `Host` with no patterns,
///   Include cycle, depth overflow).
/// - A directive's argument fails to parse (e.g. `Port abc`).
pub fn resolve(host: &str, paths: &SshConfigPaths) -> Result<ResolvedSshConfig, AnvilError> {
    let mut all_blocks: Vec<HostBlock> = Vec::new();

    if let Some(user) = &paths.user {
        let path = expand_path_for_read(user);
        all_blocks.extend(read_and_parse(&path)?);
    }
    if let Some(system) = &paths.system {
        let path = expand_path_for_read(system);
        all_blocks.extend(read_and_parse(&path)?);
    }

    let mut resolved = ResolvedSshConfig::default();
    if all_blocks.is_empty() {
        return Ok(resolved);
    }

    for d in directives_for_host(&all_blocks, host) {
        apply_directive(d, &mut resolved)?;
    }

    Ok(resolved)
}

/// Tilde-expands the path so callers may pass `~/.ssh/config` literally.
fn expand_path_for_read(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    PathBuf::from(expand_tilde(&s))
}

/// Reads, tokenizes, expands Includes, and parses one config file.
/// Missing files yield an empty block list (no error).
fn read_and_parse(path: &Path) -> Result<Vec<HostBlock>, AnvilError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(AnvilError::invalid_config(format!(
                "ssh_config: failed to read {}: {e}",
                path.display(),
            )));
        }
    };
    let tokens = tokenize(&content, path)?;
    let expanded = expand_includes(path, tokens)?;
    parse(expanded)
}

/// Applies one directive to `resolved` with first-occurrence-wins
/// semantics, recording provenance for every recognized directive.
#[allow(
    clippy::too_many_lines,
    reason = "directive dispatch is intentionally one big match for clarity \
              and easy review; each arm is a few lines and there is no \
              meaningful sub-grouping"
)]
fn apply_directive(d: &Directive, resolved: &mut ResolvedSshConfig) -> Result<(), AnvilError> {
    let mut recorded = true;

    match d.keyword.as_str() {
        "hostname" => {
            if resolved.hostname.is_none() {
                resolved.hostname = Some(first_arg_required(d)?);
            }
        }
        "user" => {
            if resolved.user.is_none() {
                resolved.user = Some(first_arg_required(d)?);
            }
        }
        "port" => {
            if resolved.port.is_none() {
                let s = first_arg_required(d)?;
                resolved.port = Some(s.parse::<u16>().map_err(|e| {
                    AnvilError::invalid_config(format!(
                        "ssh_config: invalid Port '{s}' at {}:{}: {e}",
                        d.file.display(),
                        d.line_no,
                    ))
                })?);
            }
        }
        "identityfile" => {
            require_at_least_one(d)?;
            for arg in &d.args {
                resolved.identity_files.push(expand_path_value(arg));
            }
        }
        "identitiesonly" => {
            if resolved.identities_only.is_none() {
                resolved.identities_only = Some(parse_yes_no(d)?);
            }
        }
        "identityagent" => {
            if resolved.identity_agent.is_none() {
                let s = first_arg_required(d)?;
                resolved.identity_agent = Some(expand_path_value(&s));
            }
        }
        "certificatefile" => {
            require_at_least_one(d)?;
            for arg in &d.args {
                resolved.certificate_files.push(expand_path_value(arg));
            }
        }
        "proxycommand" => {
            if resolved.proxy_command.is_none() {
                if d.args.is_empty() {
                    return Err(missing_value_err(d));
                }
                // ProxyCommand takes the rest of the line as a shell
                // command; the lexer split it on whitespace so we re-join.
                resolved.proxy_command = Some(d.args.join(" "));
            }
        }
        "proxyjump" => {
            if resolved.proxy_jump.is_none() {
                resolved.proxy_jump = Some(first_arg_required(d)?);
            }
        }
        "userknownhostsfile" => {
            require_at_least_one(d)?;
            for arg in &d.args {
                resolved.user_known_hosts_files.push(expand_path_value(arg));
            }
        }
        "stricthostkeychecking" => {
            if resolved.strict_host_key_checking.is_none() {
                let s = first_arg_required(d)?;
                let v = match s.to_ascii_lowercase().as_str() {
                    // OpenSSH `ask` defaults to interactive prompt; we
                    // fold to Yes since this crate never prompts.
                    "yes" | "ask" => StrictHostKeyChecking::Yes,
                    "no" | "off" => StrictHostKeyChecking::No,
                    "accept-new" => StrictHostKeyChecking::AcceptNew,
                    other => {
                        return Err(AnvilError::invalid_config(format!(
                            "ssh_config: invalid StrictHostKeyChecking '{other}' at {}:{}",
                            d.file.display(),
                            d.line_no,
                        )));
                    }
                };
                resolved.strict_host_key_checking = Some(v);
            }
        }
        "hostkeyalgorithms" => {
            if resolved.host_key_algorithms.is_none() {
                resolved.host_key_algorithms = Some(AlgList(first_arg_required(d)?));
            }
        }
        "kexalgorithms" => {
            if resolved.kex_algorithms.is_none() {
                resolved.kex_algorithms = Some(AlgList(first_arg_required(d)?));
            }
        }
        "ciphers" => {
            if resolved.ciphers.is_none() {
                resolved.ciphers = Some(AlgList(first_arg_required(d)?));
            }
        }
        "macs" => {
            if resolved.macs.is_none() {
                resolved.macs = Some(AlgList(first_arg_required(d)?));
            }
        }
        "connecttimeout" => {
            if resolved.connect_timeout.is_none() {
                let s = first_arg_required(d)?;
                let secs: u64 = s.parse().map_err(|e| {
                    AnvilError::invalid_config(format!(
                        "ssh_config: invalid ConnectTimeout '{s}' at {}:{}: {e}",
                        d.file.display(),
                        d.line_no,
                    ))
                })?;
                resolved.connect_timeout = Some(Duration::from_secs(secs));
            }
        }
        "connectionattempts" => {
            if resolved.connection_attempts.is_none() {
                let s = first_arg_required(d)?;
                resolved.connection_attempts = Some(s.parse::<u32>().map_err(|e| {
                    AnvilError::invalid_config(format!(
                        "ssh_config: invalid ConnectionAttempts '{s}' at {}:{}: {e}",
                        d.file.display(),
                        d.line_no,
                    ))
                })?);
            }
        }
        _ => {
            // Unknown / unhandled directive — silently skip.  Many
            // ssh_config(5) directives are out of scope for Anvil; logging
            // every one would be noisy.  Trace level only.
            log::trace!(
                "ssh_config: ignoring unhandled directive '{}' at {}:{}",
                d.keyword,
                d.file.display(),
                d.line_no,
            );
            recorded = false;
        }
    }

    if recorded {
        resolved.provenance.push(DirectiveSource {
            directive: d.keyword.clone(),
            file: d.file.clone(),
            line: d.line_no,
        });
    }

    Ok(())
}

fn first_arg_required(d: &Directive) -> Result<String, AnvilError> {
    d.args.first().cloned().ok_or_else(|| missing_value_err(d))
}

fn require_at_least_one(d: &Directive) -> Result<(), AnvilError> {
    if d.args.is_empty() {
        Err(missing_value_err(d))
    } else {
        Ok(())
    }
}

fn missing_value_err(d: &Directive) -> AnvilError {
    AnvilError::invalid_config(format!(
        "ssh_config: directive '{}' at {}:{} has no value",
        d.keyword,
        d.file.display(),
        d.line_no,
    ))
}

fn parse_yes_no(d: &Directive) -> Result<bool, AnvilError> {
    let s = first_arg_required(d)?;
    match s.to_ascii_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        other => Err(AnvilError::invalid_config(format!(
            "ssh_config: expected yes/no for '{}' at {}:{}, got '{other}'",
            d.keyword,
            d.file.display(),
            d.line_no,
        ))),
    }
}

/// Tilde + env expansion for path-shaped directive values.
fn expand_path_value(value: &str) -> PathBuf {
    PathBuf::from(expand_tilde(&expand_env(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Writes `content` to a fresh temp config file and returns the path
    /// + the [`tempfile::TempDir`] guard (drop the guard last).
    fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("config");
        fs::write(&path, content).expect("write config");
        (dir, path)
    }

    fn paths_user_only(p: PathBuf) -> SshConfigPaths {
        SshConfigPaths {
            user: Some(p),
            system: None,
        }
    }

    #[test]
    fn empty_paths_returns_default() {
        let resolved = resolve("anyhost", &SshConfigPaths::none()).expect("resolve with no files");
        assert_eq!(resolved.hostname, None);
        assert!(resolved.identity_files.is_empty());
        assert!(resolved.provenance.is_empty());
    }

    #[test]
    fn missing_file_is_silently_ignored() {
        let paths = SshConfigPaths {
            user: Some(PathBuf::from("/this/path/definitely/does/not/exist")),
            system: None,
        };
        let resolved = resolve("anyhost", &paths).expect("resolve");
        assert_eq!(resolved.hostname, None);
    }

    #[test]
    fn resolves_basic_block() {
        let (_g, conf) = write_config("Host gh\n  HostName github.com\n  User git\n  Port 2222\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.hostname.as_deref(), Some("github.com"));
        assert_eq!(resolved.user.as_deref(), Some("git"));
        assert_eq!(resolved.port, Some(2222));
        assert_eq!(resolved.provenance.len(), 3);
    }

    #[test]
    fn first_occurrence_wins_for_single_valued_fields() {
        // Two Host blocks both match `gh` (`gh` and `*`).  The earlier
        // block's value should win.
        let (_g, conf) = write_config(
            "Host gh\n  HostName specific.example.com\nHost *\n  HostName fallback.example.com\n",
        );
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.hostname.as_deref(), Some("specific.example.com"));
    }

    #[test]
    fn multiple_identity_files_accumulate() {
        let (_g, conf) =
            write_config("Host gh\n  IdentityFile ~/.ssh/id_a\n  IdentityFile ~/.ssh/id_b\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.identity_files.len(), 2);
        // Tilde was expanded.
        assert!(!resolved.identity_files[0]
            .to_string_lossy()
            .starts_with('~'));
    }

    #[test]
    fn identityfile_one_line_multiple_args_accumulates() {
        // `IdentityFile a b c` expands to three entries (per OpenSSH).
        let (_g, conf) = write_config("Host gh\n  IdentityFile a b c\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.identity_files.len(), 3);
    }

    #[test]
    fn invalid_port_errors() {
        let (_g, conf) = write_config("Host gh\n  Port not_a_number\n");
        let err = resolve("gh", &paths_user_only(conf)).expect_err("invalid Port");
        let msg = format!("{err}");
        assert!(msg.contains("invalid Port"), "got: {msg}");
    }

    #[test]
    fn strict_host_key_checking_variants() {
        let cases = &[
            ("yes", StrictHostKeyChecking::Yes),
            ("ask", StrictHostKeyChecking::Yes), // folded
            ("no", StrictHostKeyChecking::No),
            ("off", StrictHostKeyChecking::No),
            ("accept-new", StrictHostKeyChecking::AcceptNew),
        ];
        for (raw, expected) in cases {
            let (_g, conf) = write_config(&format!("Host gh\n  StrictHostKeyChecking {raw}\n"));
            let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
            assert_eq!(
                resolved.strict_host_key_checking,
                Some(*expected),
                "case `{raw}`",
            );
        }
    }

    #[test]
    fn algorithm_directives_captured_raw() {
        let (_g, conf) = write_config(
            "Host gh\n  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512\n  KexAlgorithms curve25519-sha256\n",
        );
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(
            resolved.host_key_algorithms,
            Some(AlgList("ssh-ed25519,rsa-sha2-512".to_owned())),
        );
        assert_eq!(
            resolved.kex_algorithms,
            Some(AlgList("curve25519-sha256".to_owned())),
        );
    }

    #[test]
    fn connect_timeout_parses_to_duration() {
        let (_g, conf) = write_config("Host gh\n  ConnectTimeout 30\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.connect_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn connection_attempts_parses() {
        let (_g, conf) = write_config("Host gh\n  ConnectionAttempts 5\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.connection_attempts, Some(5));
    }

    #[test]
    fn proxy_command_joined_with_spaces() {
        let (_g, conf) = write_config("Host gh\n  ProxyCommand ssh -W %h:%p bastion\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        // The lexer split on whitespace; the resolver re-joined with one space.
        assert_eq!(
            resolved.proxy_command.as_deref(),
            Some("ssh -W %h:%p bastion"),
        );
    }

    #[test]
    fn proxy_jump_captured() {
        let (_g, conf) = write_config("Host gh\n  ProxyJump bastion.example.com\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("bastion.example.com"),);
    }

    #[test]
    fn user_known_hosts_files_accumulate() {
        let (_g, conf) = write_config(
            "Host gh\n  UserKnownHostsFile /etc/known\n  UserKnownHostsFile /home/u/known\n",
        );
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.user_known_hosts_files.len(), 2);
    }

    #[test]
    fn user_known_hosts_files_one_line_multi_args() {
        let (_g, conf) = write_config("Host gh\n  UserKnownHostsFile /a /b /c\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.user_known_hosts_files.len(), 3);
    }

    #[test]
    fn unknown_directives_ignored() {
        let (_g, conf) = write_config("Host gh\n  ServerAliveInterval 60\n  User git\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        // Unknown directive ignored; recognized directive still applied.
        assert_eq!(resolved.user.as_deref(), Some("git"));
        assert_eq!(resolved.provenance.len(), 1);
    }

    #[test]
    fn provenance_records_file_and_line() {
        let (_g, conf) = write_config("# header\nHost gh\n  User git\n");
        let resolved = resolve("gh", &paths_user_only(conf.clone())).expect("resolve");
        assert_eq!(resolved.provenance.len(), 1);
        let prov = &resolved.provenance[0];
        assert_eq!(prov.directive, "user");
        assert_eq!(prov.line, 3);
        // The provenance file matches the read path (post-canonicalize via include).
        // It may be canonicalized; compare canonical-or-as-is.
        let prov_canon = prov.file.canonicalize().unwrap_or(prov.file.clone());
        let conf_canon = conf.canonicalize().unwrap_or(conf);
        assert_eq!(prov_canon, conf_canon);
    }

    #[test]
    fn user_then_system_first_wins() {
        let dir = tempdir().expect("tempdir");
        let user_path = dir.path().join("user_config");
        let sys_path = dir.path().join("sys_config");
        fs::write(&user_path, "Host gh\n  User from_user\n").expect("write user");
        fs::write(&sys_path, "Host gh\n  User from_system\n").expect("write sys");

        let paths = SshConfigPaths {
            user: Some(user_path),
            system: Some(sys_path),
        };
        let resolved = resolve("gh", &paths).expect("resolve");
        assert_eq!(resolved.user.as_deref(), Some("from_user"));
    }

    #[test]
    fn no_match_yields_empty_resolved() {
        let (_g, conf) = write_config("Host other\n  User unrelated\n");
        let resolved = resolve("gh", &paths_user_only(conf)).expect("resolve");
        assert_eq!(resolved.user, None);
        assert!(resolved.provenance.is_empty());
    }
}
