// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `ProxyCommand` and `ProxyJump` consumers (PRD §5.8.2, M13).
//!
//! M12 captured `proxy_command` and `proxy_jump` losslessly into
//! [`super::ssh_config::ResolvedSshConfig`] so `gitway config show`
//! mirrors `ssh -G`.  This module is what M13 uses to actually *consume*
//! those values when establishing the underlying SSH transport:
//!
//! - [`tokens::expand_proxy_tokens`] expands `%h %p %r %n %%` in a
//!   `ProxyCommand` template.
//! - [`stdio::ChildStdio`] wraps a [`tokio::process::Child`]'s stdio in
//!   the [`AsyncRead + AsyncWrite + Unpin + Send`] surface that
//!   [`russh::client::connect_stream`] expects.
//! - [`command::spawn_proxy_command`] glues the two together: token-
//!   expand the template, spawn through the platform shell (`sh -c` on
//!   Unix, `cmd /C` on Windows), capture stdio.
//!
//! Higher-level wiring — [`super::session::AnvilSession::connect_via_proxy_command`]
//! and `connect_via_jump_hosts` — lands in M13.2 and M13.4.  The
//! jump-string parser and chain manager (`jump.rs`) land alongside
//! M13.3 and M13.4.

pub(crate) mod command;
pub(crate) mod stdio;
pub mod tokens;

pub use tokens::expand_proxy_tokens;
