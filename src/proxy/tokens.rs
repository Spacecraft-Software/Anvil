// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Percent-token expansion for `ProxyCommand` templates.
//!
//! OpenSSH's `ssh_config(5)` defines a TOKENS section listing the `%X`
//! sequences that a `ProxyCommand` template may use.  Anvil supports the
//! subset that has well-defined meanings without a control-path concept:
//!
//! | Token | Expansion                                                  |
//! |-------|------------------------------------------------------------|
//! | `%h`  | The hostname `ProxyCommand` is connecting to (`HostName`). |
//! | `%p`  | The port (decimal).                                        |
//! | `%r`  | The remote user.                                           |
//! | `%n`  | The original alias the user typed (pre-`HostName`).        |
//! | `%%`  | A literal `%` character.                                   |
//!
//! All other `%X` sequences are preserved verbatim with one
//! [`log::warn!`] per occurrence so the user can grep for unsupported
//! template uses.  `%C` (control-path SHA-1) and `%L` (local hostname)
//! are intentionally out of scope for M13 — `%C` would require a
//! control-path concept Anvil does not have, and `%L` is rarely used.
//!
//! This is a hand-rolled single-pass scanner; no regex.

/// Expand `%h`, `%p`, `%r`, `%n`, and `%%` in `template`.
///
/// `host` substitutes for `%h`, `port` for `%p` (decimal), `user` for
/// `%r`, `alias` for `%n`.  `%%` becomes a literal `%`.  Unknown
/// `%X` sequences are preserved verbatim and a warning is logged for
/// each.  A trailing `%` (with no follow-on character) is preserved
/// verbatim with no warning — matches OpenSSH.
#[must_use]
pub fn expand_proxy_tokens(
    template: &str,
    host: &str,
    port: u16,
    user: &str,
    alias: &str,
) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(host),
            Some('p') => {
                use std::fmt::Write as _;
                // Writing a u16 to a String never fails.
                let _ = write!(&mut out, "{port}");
            }
            Some('r') => out.push_str(user),
            Some('n') => out.push_str(alias),
            Some(other) => {
                log::warn!(
                    "ProxyCommand: unsupported token `%{other}` preserved verbatim; \
                     supported tokens are %h %p %r %n %%",
                );
                out.push('%');
                out.push(other);
            }
            None => {
                // Trailing `%` at end-of-string — preserve.
                out.push('%');
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tokens_unchanged() {
        assert_eq!(
            expand_proxy_tokens("ssh -W bastion:22", "h", 22, "u", "n"),
            "ssh -W bastion:22",
        );
    }

    #[test]
    fn simple_substitutions() {
        assert_eq!(
            expand_proxy_tokens("ssh -W %h:%p bastion", "github.com", 22, "git", "gh"),
            "ssh -W github.com:22 bastion",
        );
    }

    #[test]
    fn remote_user_token() {
        assert_eq!(
            expand_proxy_tokens("auth %r@%h:%p", "host", 2222, "alice", "alias"),
            "auth alice@host:2222",
        );
    }

    #[test]
    fn alias_token_separate_from_hostname() {
        // `%n` is the original user-typed alias, not the resolved HostName.
        assert_eq!(
            expand_proxy_tokens("connect %n via %h", "real.example.com", 22, "git", "gh"),
            "connect gh via real.example.com",
        );
    }

    #[test]
    fn double_percent_is_literal() {
        assert_eq!(
            expand_proxy_tokens("100%% throughput on %h", "h", 22, "u", "n"),
            "100% throughput on h",
        );
    }

    #[test]
    fn unknown_token_preserved_verbatim() {
        // `%C` and `%L` aren't supported in M13; preserve the text and
        // emit a warning (covered by log assertions, not here).
        assert_eq!(
            expand_proxy_tokens("ssh -S %C %h", "host", 22, "u", "n"),
            "ssh -S %C host",
        );
    }

    #[test]
    fn trailing_percent_preserved() {
        assert_eq!(expand_proxy_tokens("hello %", "h", 22, "u", "n"), "hello %",);
    }

    #[test]
    fn multiple_substitutions_one_pass() {
        assert_eq!(
            expand_proxy_tokens("%n %h %p %r %% %h", "host.example.com", 22, "git", "gh",),
            "gh host.example.com 22 git % host.example.com",
        );
    }

    #[test]
    fn empty_template() {
        assert_eq!(expand_proxy_tokens("", "h", 22, "u", "n"), "");
    }

    #[test]
    fn host_with_special_chars_passes_through() {
        // Token expansion treats the value as opaque; quoting is the
        // shell's job.
        assert_eq!(
            expand_proxy_tokens("connect %h", "weird;host name", 22, "u", "n"),
            "connect weird;host name",
        );
    }

    #[test]
    fn port_is_decimal() {
        assert_eq!(expand_proxy_tokens("p=%p", "h", 65535, "u", "n"), "p=65535",);
        assert_eq!(expand_proxy_tokens("p=%p", "h", 0, "u", "n"), "p=0");
    }
}
