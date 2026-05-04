// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `ProxyJump` chain parser + per-hop type.
//!
//! M13.3 adds the parser and the [`JumpHost`] type; M13.4 wires both
//! into [`crate::session::AnvilSession::connect_via_jump_hosts`] (which
//! drives russh's `direct-tcpip` channel for each chained hop).
//!
//! # Jump-string grammar
//!
//! OpenSSH's `ProxyJump` directive (and `-J` flag) accepts a comma-
//! separated list of hops, each in the form:
//!
//! ```text
//! [user@]host[:port]
//! ```
//!
//! Whitespace around commas is ignored.  Trailing commas and empty
//! entries are rejected with [`AnvilError::invalid_config`].  The chain
//! length is capped at [`MAX_JUMP_HOPS`] = 8 (matches OpenSSH's
//! `READCONF_MAX_DEPTH` for `ProxyJump` chains).
//!
//! Per-hop `IdentityFile` selection is **not** done here — that
//! requires re-running [`crate::ssh_config::resolve`] against each
//! hop's hostname, which the chain manager (M13.4) does because it
//! has access to the `SshConfigPaths`.  This module's job is purely
//! syntactic: turn the raw string into a structured list of hops.

use std::path::PathBuf;

use crate::error::AnvilError;

/// Hard cap on chain length, matching OpenSSH.  Any chain longer than
/// this is refused at parse time with a clear error.
pub const MAX_JUMP_HOPS: usize = 8;

/// One hop in a [`ProxyJump`] chain.
///
/// Constructed by [`parse_jump_chain`].  M13.4's chain manager reads
/// `host` and `port` to drive `direct-tcpip`; `user` and
/// `identity_files` are layered into the per-hop [`crate::AnvilConfig`]
/// before the inner SSH handshake.
///
/// `identity_files` is empty after parsing — the chain manager fills
/// it in by resolving each hop's name against the user's `ssh_config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpHost {
    /// Bare hostname to connect to.
    pub host: String,
    /// SSH port.  Defaults to 22 when the jump-string omits it.
    pub port: u16,
    /// Remote username, or `None` when the jump-string omits the
    /// `user@` prefix.  The chain manager falls back to `ssh_config`'s
    /// `User` for the hop, then to the inherited username, then to
    /// the `AnvilConfig` builder default (`git`).
    pub user: Option<String>,
    /// Identity files for this hop.  Empty after [`parse_jump_chain`]
    /// returns; M13.4's chain manager populates this by resolving the
    /// hop's `Host` block.
    pub identity_files: Vec<PathBuf>,
}

/// Parses a comma-separated `ProxyJump` chain into ordered [`JumpHost`]s.
///
/// Accepts the `-J` / `ProxyJump` syntax: ``[user@]host[:port][,…]``.
/// Whitespace around commas is ignored.  The literal `none` (single
/// element, case-insensitive) is rejected here — callers that
/// recognize `none` as the FR-59 disable sentinel should detect it
/// before calling this function and fall back to a direct connection.
///
/// # Errors
/// - The string is empty or contains only commas / whitespace.
/// - An entry has an empty host (`@`, `:22`, or just whitespace).
/// - An entry has an empty user-portion (`@host`).
/// - The port portion is not parseable as `u16`.
/// - The chain length exceeds [`MAX_JUMP_HOPS`].
/// - The literal `none` is used (callers should handle this before
///   calling).
pub fn parse_jump_chain(raw: &str) -> Result<Vec<JumpHost>, AnvilError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AnvilError::invalid_config(
            "ProxyJump: empty jump-host string",
        ));
    }
    // Reject `none` here so callers cannot accidentally treat the FR-59
    // sentinel as a real chain.
    if trimmed.eq_ignore_ascii_case("none") {
        return Err(AnvilError::invalid_config(
            "ProxyJump=none is the disable sentinel; \
             callers should detect this before parsing",
        ));
    }

    let mut hops: Vec<JumpHost> = Vec::new();
    for piece in trimmed.split(',') {
        let entry = piece.trim();
        if entry.is_empty() {
            return Err(AnvilError::invalid_config(format!(
                "ProxyJump: empty entry in `{raw}` (trailing or repeated commas)",
            )));
        }
        hops.push(parse_one(entry)?);
    }

    if hops.len() > MAX_JUMP_HOPS {
        return Err(AnvilError::invalid_config(format!(
            "ProxyJump: chain length {} exceeds the {MAX_JUMP_HOPS}-hop limit",
            hops.len(),
        )));
    }

    Ok(hops)
}

/// Parses one `[user@]host[:port]` entry.
fn parse_one(entry: &str) -> Result<JumpHost, AnvilError> {
    // Split off the optional `user@` prefix.
    let (user, host_port) = match entry.split_once('@') {
        Some((u, hp)) => {
            if u.is_empty() {
                return Err(AnvilError::invalid_config(format!(
                    "ProxyJump: empty user in `{entry}` (`@host` without name)",
                )));
            }
            (Some(u.to_owned()), hp)
        }
        None => (None, entry),
    };

    // Split off the optional `:port` suffix.  IPv6 literals would need
    // `[v6]:port` handling; OpenSSH supports that but PRD §5.8.2
    // doesn't call it out as a hard requirement.  Keep it simple for
    // M13 and document as a follow-up if a user complains.
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            // `host:port` — h is the host, p is the port.
            let port: u16 = p.parse().map_err(|e| {
                AnvilError::invalid_config(format!(
                    "ProxyJump: invalid port `{p}` in `{entry}`: {e}",
                ))
            })?;
            (h.to_owned(), port)
        }
        _ => (host_port.to_owned(), 22),
    };

    if host.is_empty() {
        return Err(AnvilError::invalid_config(format!(
            "ProxyJump: empty host in `{entry}`",
        )));
    }

    Ok(JumpHost {
        host,
        port,
        user,
        identity_files: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_hop_bare_host() {
        let chain = parse_jump_chain("bastion.example.com").expect("parse");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].host, "bastion.example.com");
        assert_eq!(chain[0].port, 22);
        assert_eq!(chain[0].user, None);
        assert!(chain[0].identity_files.is_empty());
    }

    #[test]
    fn single_hop_user_host_port() {
        let chain = parse_jump_chain("alice@bastion.example.com:2222").expect("parse");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].host, "bastion.example.com");
        assert_eq!(chain[0].port, 2222);
        assert_eq!(chain[0].user.as_deref(), Some("alice"));
    }

    #[test]
    fn two_hops_comma_separated() {
        let chain = parse_jump_chain("b1.example.com,alice@b2.example.com:2222").expect("parse");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].host, "b1.example.com");
        assert_eq!(chain[0].port, 22);
        assert_eq!(chain[1].host, "b2.example.com");
        assert_eq!(chain[1].port, 2222);
        assert_eq!(chain[1].user.as_deref(), Some("alice"));
    }

    #[test]
    fn whitespace_around_commas_tolerated() {
        let chain = parse_jump_chain("b1 , b2:2222 , c@b3").expect("parse");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].host, "b1");
        assert_eq!(chain[1].host, "b2");
        assert_eq!(chain[1].port, 2222);
        assert_eq!(chain[2].host, "b3");
        assert_eq!(chain[2].user.as_deref(), Some("c"));
    }

    #[test]
    fn empty_string_rejected() {
        let err = parse_jump_chain("").expect_err("empty");
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn whitespace_only_rejected() {
        let err = parse_jump_chain("   ").expect_err("whitespace only");
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn trailing_comma_rejected() {
        let err = parse_jump_chain("b1,").expect_err("trailing comma");
        assert!(format!("{err}").contains("empty entry"));
    }

    #[test]
    fn double_comma_rejected() {
        let err = parse_jump_chain("b1,,b2").expect_err("double comma");
        assert!(format!("{err}").contains("empty entry"));
    }

    #[test]
    fn empty_user_at_host_rejected() {
        let err = parse_jump_chain("@bastion").expect_err("empty user");
        assert!(format!("{err}").contains("empty user"));
    }

    #[test]
    fn empty_host_rejected() {
        let err = parse_jump_chain("alice@").expect_err("empty host");
        assert!(format!("{err}").contains("empty host"));
    }

    #[test]
    fn invalid_port_rejected() {
        let err = parse_jump_chain("bastion:not_a_number").expect_err("bad port");
        let msg = format!("{err}");
        assert!(msg.contains("invalid port"), "got: {msg}");
    }

    #[test]
    fn port_out_of_range_rejected() {
        let err = parse_jump_chain("bastion:99999").expect_err("port > u16::MAX");
        assert!(format!("{err}").contains("invalid port"));
    }

    #[test]
    fn none_literal_rejected_with_clear_message() {
        for raw in ["none", "NONE", "None"] {
            let err = parse_jump_chain(raw).expect_err("none sentinel");
            assert!(
                format!("{err}").contains("disable sentinel"),
                "case `{raw}`: expected disable-sentinel error",
            );
        }
    }

    #[test]
    fn chain_at_max_hops_accepted() {
        let raw = (1..=MAX_JUMP_HOPS)
            .map(|i| format!("b{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let chain = parse_jump_chain(&raw).expect("parse 8 hops");
        assert_eq!(chain.len(), MAX_JUMP_HOPS);
    }

    #[test]
    fn chain_over_max_hops_rejected() {
        let raw = (1..=(MAX_JUMP_HOPS + 1))
            .map(|i| format!("b{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let err = parse_jump_chain(&raw).expect_err("9 hops");
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains(&format!("{MAX_JUMP_HOPS}-hop")),
            "got: {msg}",
        );
    }

    #[test]
    fn jump_host_struct_round_trip() {
        let h = JumpHost {
            host: "bastion".to_owned(),
            port: 22,
            user: Some("git".to_owned()),
            identity_files: vec![PathBuf::from("/home/u/.ssh/id_ed25519")],
        };
        // Sanity: PartialEq + Clone work for the chain manager's needs.
        assert_eq!(h.clone(), h);
    }
}
