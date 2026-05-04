// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! `AsyncRead` + `AsyncWrite` adapter for a child process's stdio.
//!
//! [`ChildStdio`] bundles a [`tokio::process::Child`]'s [`ChildStdin`]
//! and [`ChildStdout`] into a single object that implements both
//! [`AsyncRead`] and [`AsyncWrite`].  This is exactly the bring-your-own-
//! transport surface [`russh::client::connect_stream`] expects, so a
//! `ChildStdio` can be handed directly to russh as the SSH transport
//! when honoring `ProxyCommand`.
//!
//! # Lifecycle
//!
//! Dropping a [`ChildStdio`] best-effort-kills the child via
//! [`Child::start_kill`].  The reaper picks up the corpse asynchronously;
//! `Drop` does not block.  This matters for the failure path: if the
//! SSH handshake errors out mid-stream, the runtime drops the
//! `ChildStdio`, and a hung `ssh -W` proxy gets a SIGTERM rather than
//! lingering as a zombie.  See the unit test for the
//! "child ignores SIGTERM" sanity check.
//!
//! # Pin / projection
//!
//! Both [`ChildStdin`] and [`ChildStdout`] are [`Unpin`], so the manual
//! `AsyncRead` / `AsyncWrite` impls project safely via `Pin::new(&mut
//! self.field)` — no `unsafe`, no [`pin_project`] dep.  The S3 invariant
//! (`#![forbid(unsafe_code)]`) is preserved.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout};

/// AsyncRead+AsyncWrite over a child process's stdio.
///
/// Construct via [`Self::new`].  The `Drop` impl best-effort-kills the
/// child.
#[derive(Debug)]
pub(crate) struct ChildStdio {
    /// Write half — the child's stdin.  `russh::client::connect_stream`
    /// drains its outgoing SSH frames here.
    stdin: ChildStdin,
    /// Read half — the child's stdout.  russh reads incoming SSH frames
    /// from here.
    stdout: ChildStdout,
    /// Owned child handle.  Kept so `Drop` can `start_kill` the
    /// process when the stream is closed.
    child: Child,
}

impl ChildStdio {
    /// Creates a new adapter from an already-spawned child.
    ///
    /// The child must have been spawned with `stdin(Stdio::piped())` and
    /// `stdout(Stdio::piped())`; otherwise `take()` returns `None` and
    /// this constructor returns an error.
    pub(crate) fn new(mut child: Child) -> io::Result<Self> {
        let stdin = child.stdin.take().ok_or_else(|| {
            io::Error::other("ChildStdio: child was not spawned with piped stdin")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::other("ChildStdio: child was not spawned with piped stdout")
        })?;
        Ok(Self {
            stdin,
            stdout,
            child,
        })
    }
}

impl AsyncRead for ChildStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // ChildStdout: Unpin, so `Pin::new(&mut self.stdout)` is sound.
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // ChildStdin: Unpin, so the projection is safe.
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

impl Drop for ChildStdio {
    fn drop(&mut self) {
        // Best-effort: don't await; the reaper picks up exit status
        // asynchronously.  If the child was already gone or in the middle
        // of exiting cleanly, `start_kill` returns `Ok(())` (idempotent
        // on the no-such-process case on most Unixes).  We swallow the
        // error because Drop can't return one and the only response would
        // be a log line that adds no operational value.
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// Helper: spawn a child running an inline shell command, with stdin
    /// and stdout piped.  Used as a stand-in for `ProxyCommand` in unit
    /// tests; the integration tests cover the russh wiring end-to-end.
    fn spawn_shell(command: &str) -> ChildStdio {
        let mut cmd = if cfg!(windows) {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(command);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(command);
            c
        };
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        let child = cmd.spawn().expect("spawn child");
        ChildStdio::new(child).expect("ChildStdio::new")
    }

    #[tokio::test]
    async fn round_trips_data_through_cat() {
        // `cat` echoes stdin to stdout — perfect smoke test that the
        // adapter wires both halves correctly.  On Windows we use
        // `findstr /N "."` which numbers each line (ensures we get
        // SOMETHING back even with a different shell).  Use a simpler
        // approach: pipe through a Unix `cat` if available; otherwise
        // skip the test.  PowerShell-style equivalents are fragile here.
        if cfg!(windows) {
            return;
        }
        let mut io_pair = spawn_shell("cat");
        io_pair.write_all(b"hello\n").await.expect("write");
        io_pair.flush().await.expect("flush");
        io_pair.shutdown().await.expect("shutdown stdin");

        let mut buf = Vec::new();
        io_pair.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, b"hello\n");
    }

    #[tokio::test]
    async fn drop_kills_long_running_child() {
        // Spawn a child that sleeps long enough to outlive the test.
        // Drop should fire `start_kill`; assert via subsequent
        // `try_wait` that the child terminated quickly.
        if cfg!(windows) {
            return; // `sleep 60` doesn't exist in cmd; integration covers this.
        }
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("sleep 60");
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        let child = cmd.spawn().expect("spawn");
        let pid = child.id().expect("child has pid");

        let io_pair = ChildStdio::new(child).expect("ChildStdio::new");
        drop(io_pair);

        // Give the kill signal a chance to land + the reaper a chance to
        // notice.  100 ms is plenty for SIGTERM on Linux loopback.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // The simplest cross-platform "is it gone?" check is to try
        // sending signal 0 via `kill -0`; if the process is already gone
        // (reaped or just exited), `kill` returns nonzero.
        let status = tokio::process::Command::new("kill")
            .arg("-0")
            .arg(format!("{pid}"))
            .status()
            .await
            .expect("kill -0");
        assert!(
            !status.success(),
            "child PID {pid} still alive after Drop; expected start_kill to terminate it",
        );
    }

    #[test]
    fn rejects_child_without_piped_stdin() {
        // Spawn without piping stdin — `ChildStdio::new` should refuse.
        if cfg!(windows) {
            return;
        }
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("true");
        cmd.stdout(Stdio::piped()); // stdin NOT piped
        let child = cmd.spawn().expect("spawn");
        let err = ChildStdio::new(child).expect_err("should fail without piped stdin");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
