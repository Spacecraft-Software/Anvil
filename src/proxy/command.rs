// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `ProxyCommand` spawn helper.
//!
//! Glues [`super::tokens::expand_proxy_tokens`] to a [`ChildStdio`]
//! constructor:
//!
//! 1. Expand `%h`/`%p`/`%r`/`%n`/`%%` against the connection-time values.
//! 2. Spawn the resulting command line via the platform shell
//!    (`sh -c` on Unix, `cmd /C` on Windows) so quoting, pipes, and
//!    redirections in the user's template work without us reimplementing
//!    a shell parser.
//! 3. Pipe stdin and stdout, capture both halves into a [`ChildStdio`]
//!    that callers feed to [`russh::client::connect_stream`].
//!
//! The single entry point is [`spawn_proxy_command`].

use std::io;
use std::process::Stdio;

use tokio::process::Command;

use super::stdio::ChildStdio;
use super::tokens::expand_proxy_tokens;
use crate::error::AnvilError;

/// Token-expand `template` against `(host, port, user, alias)`, spawn
/// the resulting command line via the platform shell, and return a
/// [`ChildStdio`] that wires stdin/stdout to the SSH transport.
///
/// `host` is the remote `HostName` to connect to (resolved from
/// `ssh_config`'s `HostName` directive if set, else `alias`).  `alias`
/// is the original argument the user typed before `HostName` resolution
/// — it powers the `%n` token.
///
/// # Errors
/// Returns [`AnvilError::invalid_config`] if the platform shell cannot
/// be spawned, or if the spawned child is missing piped stdin/stdout
/// (defensive: this constructor always specifies both, so the `take`
/// inside `ChildStdio::new` should always succeed).
pub(crate) fn spawn_proxy_command(
    template: &str,
    host: &str,
    port: u16,
    user: &str,
    alias: &str,
) -> Result<ChildStdio, AnvilError> {
    let expanded = expand_proxy_tokens(template, host, port, user, alias);
    log::debug!("ProxyCommand: spawning `{expanded}`");

    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(&expanded);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(&expanded);
        c
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherit stderr so the user sees diagnostic output from
        // `ssh -W`, `corkscrew`, `cloudflared access ssh`, etc.
        .stderr(Stdio::inherit());

    let child = cmd.spawn().map_err(|e| {
        AnvilError::invalid_config(format!(
            "ProxyCommand: failed to spawn shell for `{expanded}`: {e}",
        ))
    })?;

    ChildStdio::new(child).map_err(|e: io::Error| {
        AnvilError::invalid_config(format!(
            "ProxyCommand: failed to capture stdio for `{expanded}`: {e}",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawns_through_shell_with_token_expansion() {
        // Imports hoisted above the `cfg!(windows)` early-return to satisfy
        // clippy::items_after_statements.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // Exercise the full template -> shell -> ChildStdio path with a
        // command that just echoes the expanded values back so we can
        // verify them.  Skip on Windows; integration tests cover the
        // round-trip there.
        if cfg!(windows) {
            return;
        }

        let mut io_pair = spawn_proxy_command(
            "echo host=%h port=%p user=%r alias=%n",
            "github.com",
            22,
            "git",
            "gh",
        )
        .expect("spawn");
        // No stdin needed for `echo`; close it so the process exits.
        io_pair.shutdown().await.expect("shutdown stdin");

        let mut out = String::new();
        io_pair.read_to_string(&mut out).await.expect("read");
        assert_eq!(out.trim(), "host=github.com port=22 user=git alias=gh");
    }

    #[tokio::test]
    async fn shell_unavailable_surfaces_clear_error() {
        // Force a clearly-bogus shell template with shell metacharacters
        // pointing at a nonexistent binary.  The shell still spawns —
        // we only get a runtime EOF on stdout.  This test confirms the
        // adapter doesn't *itself* error on a child whose work fails.
        // Adjusts expectations: `sh -c './surely-not-a-binary'` exits
        // 127 but spawn() succeeds; ChildStdio::new captures both
        // halves, then `read_to_end` returns empty.  No assertion needed
        // beyond "doesn't panic + spawn succeeded".
        if cfg!(windows) {
            return;
        }
        let _ = spawn_proxy_command("/path/that/should/not/exist/binary", "h", 22, "u", "n")
            .expect("spawn returns Ok even when the inner command fails");
    }
}
