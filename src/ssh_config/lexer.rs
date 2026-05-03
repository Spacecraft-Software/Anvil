// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Line-oriented tokenizer for OpenSSH `ssh_config(5)` files.
//!
//! Strips line comments (`#` to end-of-line, outside quotes), joins
//! continuation lines (`\` immediately preceding the newline), and splits
//! each logical line into a directive keyword plus zero or more arguments.
//!
//! The first token on a line is the keyword.  OpenSSH compares directive
//! names case-insensitively, so the lexer lower-cases the keyword once
//! here and downstream code can compare with `==`.  Argument case is
//! preserved.
//!
//! Quoting rules match OpenSSH:
//!
//! - Double-quoted runs (`"..."`) preserve interior whitespace.
//! - Inside a quoted run, `\"` and `\\` are recognized as escapes.
//! - Other backslashes inside quotes are preserved literally (matches
//!   `man ssh_config(5)`'s "an argument may optionally be enclosed in
//!   double quotes").
//! - The `keyword=value` and `keyword = value` forms are accepted: `=`
//!   is treated as whitespace outside of quoted runs.
//!
//! On malformed input (an unterminated quoted run) the lexer returns
//! [`AnvilError::invalid_config`] with the file path and line number.
//!
//! Provenance — the file path and 1-based line number — is preserved on
//! every emitted [`TokenLine`] so resolver-stage errors can attribute a
//! decision back to its source (NFR-24, the `config_source=` field on
//! `gitway diag` lines).

use std::path::{Path, PathBuf};

use crate::error::AnvilError;

/// One tokenized directive line, with its source location.
#[derive(Debug, Clone)]
pub(crate) struct TokenLine {
    /// Lower-cased directive keyword (`host`, `identityfile`, ...).
    pub(crate) keyword: String,

    /// Arguments in source order.  Original case and interior whitespace
    /// (within quoted runs) are preserved; the argument vector itself
    /// excludes whitespace separators.
    pub(crate) args: Vec<String>,

    /// File the directive was read from.  Used as the source label for
    /// diagnostics; never opened by the lexer itself.
    pub(crate) file: PathBuf,

    /// 1-indexed line number of the *first* physical line that contributed
    /// to this logical line.  For continuation-joined lines, this is the
    /// line containing the keyword, not the trailing argument's line.
    pub(crate) line_no: u32,
}

/// Tokenizes the contents of a single `ssh_config` file.
///
/// `content` is the file's bytes interpreted as UTF-8.  `file` labels the
/// origin for diagnostics and provenance; the lexer does no I/O.
///
/// # Errors
/// Returns [`AnvilError::invalid_config`] when a quoted argument is not
/// terminated within a logical line.
pub(crate) fn tokenize(content: &str, file: &Path) -> Result<Vec<TokenLine>, AnvilError> {
    let mut tokens = Vec::new();
    let mut accum = String::new();
    let mut accum_line: u32 = 0;

    for (idx, raw_line) in content.lines().enumerate() {
        // `str::lines()` skips both `\n` and `\r\n`, so we never see those.
        // 1-based line number; `idx + 1` cannot overflow u32 for any
        // realistic config file (limit checked once via try_from).
        let line_no = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        let trimmed_end = raw_line.trim_end();

        // Continuation: a single `\` at the very end of the line (after
        // trimming trailing whitespace) joins with the next line.
        if let Some(stripped) = trimmed_end.strip_suffix('\\') {
            if accum.is_empty() {
                accum_line = line_no;
            }
            accum.push_str(stripped);
            accum.push(' '); // collapse the join-point to a single space
            continue;
        }

        if accum.is_empty() {
            accum_line = line_no;
        }
        accum.push_str(raw_line);
        let logical_line = std::mem::take(&mut accum);
        let start_line = accum_line;

        if let Some(token) = tokenize_line(&logical_line, file, start_line)? {
            tokens.push(token);
        }
    }

    // A trailing backslash continuation that runs off the end of the file
    // still contributes a final logical line.
    if !accum.is_empty() {
        if let Some(token) = tokenize_line(&accum, file, accum_line)? {
            tokens.push(token);
        }
    }

    Ok(tokens)
}

/// Tokenizes a single already-line-joined logical line.
///
/// Returns `Ok(None)` for empty or comment-only lines.
fn tokenize_line(line: &str, file: &Path, line_no: u32) -> Result<Option<TokenLine>, AnvilError> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut have_token = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if !in_quotes && c == '#' {
            // `#` outside quotes starts a comment that runs to end-of-line.
            break;
        }

        if c == '"' {
            in_quotes = !in_quotes;
            // An empty `""` still counts as a present (empty) argument.
            have_token = true;
            continue;
        }

        if in_quotes {
            // Recognize `\"` and `\\` escapes inside quotes; other
            // backslashes are preserved literally.
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == '"' || next == '\\' {
                        current.push(next);
                        chars.next();
                        continue;
                    }
                }
            }
            current.push(c);
            have_token = true;
            continue;
        }

        // Outside quotes: whitespace and `=` separate tokens.  OpenSSH
        // accepts both `Keyword value` and `Keyword=value`; treating `=`
        // as a separator covers both spellings.
        if c.is_whitespace() || c == '=' {
            if have_token {
                args.push(std::mem::take(&mut current));
                have_token = false;
            }
            continue;
        }

        current.push(c);
        have_token = true;
    }

    if in_quotes {
        return Err(AnvilError::invalid_config(format!(
            "ssh_config: unterminated quoted string at {}:{}",
            file.display(),
            line_no,
        )));
    }
    if have_token {
        args.push(current);
    }

    if args.is_empty() {
        // Empty line or comment-only line.
        return Ok(None);
    }

    let keyword = args.remove(0).to_ascii_lowercase();
    Ok(Some(TokenLine {
        keyword,
        args,
        file: file.to_path_buf(),
        line_no,
    }))
}

// ── Argument-level helpers (used by include.rs and resolver.rs) ──────────────
//
// These operate on already-tokenized argument strings.  They live here next
// to the lexer because they round out the "string-level" toolkit (alongside
// quoting and comment stripping); applying them per directive is the
// resolver's job, not the lexer's.

/// Expands a leading `~/` or `~` in a path-shaped value to the current
/// user's home directory.
///
/// `~user/...` is *not* expanded — it is preserved verbatim with a warning,
/// matching Windows OpenSSH behavior across all platforms (per-user home
/// lookup would require an additional `getpwnam`-equivalent dep that this
/// crate does not pull in).  If [`dirs::home_dir`] returns `None`, the
/// value is returned unchanged.
///
/// Tilde *only* at the very beginning of `value` is recognized; embedded
/// `~` characters are preserved (e.g. `/path/~name` is unchanged).
pub(crate) fn expand_tilde(value: &str) -> String {
    if value == "~" {
        return dirs::home_dir()
            .map_or_else(|| value.to_owned(), |h| h.to_string_lossy().into_owned());
    }
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            let mut p = home;
            p.push(rest);
            return p.to_string_lossy().into_owned();
        }
        return value.to_owned();
    }
    if value.starts_with('~') {
        // `~user/...` form — log once per call site and leave literal.
        log::warn!("ssh_config: `~user/` syntax is not supported; treating literally: {value}",);
    }
    value.to_owned()
}

/// Expands `${VAR}` and `$VAR` references in a value against the process
/// environment.
///
/// Recognized forms:
/// - `${IDENT}` — braced, where `IDENT` is `[A-Za-z_][A-Za-z0-9_]*`.
/// - `$IDENT` — unbraced, same identifier rule.
/// - A bare `$` (followed by EOF or a non-identifier character) is preserved
///   verbatim.  An unterminated `${...` is also preserved.
///
/// Unknown variables expand to the empty string, matching POSIX shell
/// behavior and OpenSSH's `ssh_config(5)` env-expansion rules.
pub(crate) fn expand_env(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }

        match chars.peek().copied() {
            Some('{') => {
                chars.next();
                let mut name = String::new();
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        closed = true;
                        break;
                    }
                    name.push(inner);
                }
                if closed {
                    if let Ok(val) = std::env::var(&name) {
                        out.push_str(&val);
                    }
                    // Unknown variable -> empty (matches POSIX / OpenSSH).
                } else {
                    // Unterminated `${VAR` — preserve verbatim.
                    out.push('$');
                    out.push('{');
                    out.push_str(&name);
                }
            }
            Some(next) if next.is_ascii_alphabetic() || next == '_' => {
                let mut name = String::new();
                while let Some(&peek) = chars.peek() {
                    if peek.is_ascii_alphanumeric() || peek == '_' {
                        name.push(peek);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Ok(val) = std::env::var(&name) {
                    out.push_str(&val);
                }
            }
            _ => out.push('$'),
        }
    }

    out
}

/// Shell-style wildcard match.
///
/// Supports:
/// - `*` — matches any sequence of characters, including empty.
/// - `?` — matches any single character.
///
/// Character classes (`[abc]`, `[!abc]`) are *not* supported in this
/// initial implementation; they are extremely uncommon in `ssh_config`
/// usage.  Adding them is a follow-up if the matrix demands it.
///
/// Iterative with star-backtracking — O(`pat.len()` * `val.len()`) worst
/// case, no recursion, no allocation beyond the char buffers.
pub(crate) fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let val: Vec<char> = value.chars().collect();
    let mut i = 0_usize;
    let mut j = 0_usize;
    let mut star_i: Option<usize> = None;
    let mut match_j: usize = 0;

    while j < val.len() {
        if i < pat.len() && (pat[i] == '?' || pat[i] == val[j]) {
            i += 1;
            j += 1;
        } else if i < pat.len() && pat[i] == '*' {
            star_i = Some(i);
            match_j = j;
            i += 1;
        } else if let Some(si) = star_i {
            i = si + 1;
            match_j += 1;
            j = match_j;
        } else {
            return false;
        }
    }

    while i < pat.len() && pat[i] == '*' {
        i += 1;
    }

    i == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> PathBuf {
        PathBuf::from("test")
    }

    #[test]
    fn simple_directive() {
        let toks = tokenize("Host github.com", &p()).expect("tokenize");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].keyword, "host");
        assert_eq!(toks[0].args, vec!["github.com"]);
        assert_eq!(toks[0].line_no, 1);
    }

    #[test]
    fn keyword_lowercased() {
        let toks = tokenize("HOSTname Example.COM", &p()).expect("tokenize");
        assert_eq!(toks[0].keyword, "hostname");
        // Argument case preserved.
        assert_eq!(toks[0].args, vec!["Example.COM"]);
    }

    #[test]
    fn strips_comments() {
        let input = "# leading\n  # indented\nHost gh # trailing\n";
        let toks = tokenize(input, &p()).expect("tokenize");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].args, vec!["gh"]);
        assert_eq!(toks[0].line_no, 3);
    }

    #[test]
    fn line_continuation_joins_next_line() {
        let input = "Host \\\n    gh1 gh2\n";
        let toks = tokenize(input, &p()).expect("tokenize");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].keyword, "host");
        assert_eq!(toks[0].args, vec!["gh1", "gh2"]);
        // Provenance is the line of the keyword, not of the joined arg.
        assert_eq!(toks[0].line_no, 1);
    }

    #[test]
    fn line_continuation_at_eof() {
        // No trailing newline; line ends with `\`.
        let toks = tokenize("Host gh \\", &p()).expect("tokenize");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].args, vec!["gh"]);
    }

    #[test]
    fn quoted_argument_preserves_spaces() {
        let toks = tokenize(r#"ProxyCommand "ssh -W %h:%p bastion""#, &p()).expect("tokenize");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].keyword, "proxycommand");
        assert_eq!(toks[0].args, vec!["ssh -W %h:%p bastion"]);
    }

    #[test]
    fn quoted_argument_handles_escapes() {
        // `"with \"quote\""` -> `with "quote"`.
        let toks = tokenize(r#"Host "with \"quote\"""#, &p()).expect("tokenize");
        assert_eq!(toks[0].args, vec![r#"with "quote""#]);
    }

    #[test]
    fn keyword_equals_value_form() {
        let toks = tokenize("Port=2222", &p()).expect("tokenize");
        assert_eq!(toks[0].keyword, "port");
        assert_eq!(toks[0].args, vec!["2222"]);
    }

    #[test]
    fn keyword_equals_with_spaces() {
        let toks = tokenize("Port = 2222", &p()).expect("tokenize");
        assert_eq!(toks[0].args, vec!["2222"]);
    }

    #[test]
    fn unterminated_quote_errors() {
        let err = tokenize(r#"Host "unclosed"#, &p()).expect_err("should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("unterminated"),
            "expected message about unterminated quote, got: {msg}"
        );
    }

    #[test]
    fn empty_input_yields_no_tokens() {
        let toks = tokenize("", &p()).expect("tokenize");
        assert!(toks.is_empty());
    }

    #[test]
    fn blank_and_comment_lines_yield_no_tokens() {
        let toks = tokenize("\n# c\n   \n# more\n", &p()).expect("tokenize");
        assert!(toks.is_empty());
    }

    #[test]
    fn multiple_arguments() {
        let toks = tokenize("Host alpha beta gamma", &p()).expect("tokenize");
        assert_eq!(toks[0].args, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn comment_inside_quotes_is_preserved() {
        // `#` inside a quoted run is a literal character, not a comment.
        let toks = tokenize(r#"ProxyCommand "echo #not-a-comment""#, &p()).expect("tokenize");
        assert_eq!(toks[0].args, vec!["echo #not-a-comment"]);
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let toks = tokenize("Host gh\r\nUser git\r\n", &p()).expect("tokenize");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].keyword, "host");
        assert_eq!(toks[1].keyword, "user");
        assert_eq!(toks[1].line_no, 2);
    }

    #[test]
    fn line_numbers_track_per_logical_line() {
        let input = "Host a\n\n# c\nHost b\n";
        let toks = tokenize(input, &p()).expect("tokenize");
        assert_eq!(toks.len(), 2);
        assert_eq!(toks[0].line_no, 1);
        assert_eq!(toks[1].line_no, 4);
    }

    #[test]
    fn empty_quoted_argument_is_present() {
        let toks = tokenize(r#"User """#, &p()).expect("tokenize");
        // The empty quoted run still produces an (empty) argument.
        assert_eq!(toks[0].keyword, "user");
        assert_eq!(toks[0].args, vec![""]);
    }

    // ── expand_tilde ─────────────────────────────────────────────────────────

    #[test]
    fn expand_tilde_replaces_leading_slash_form() {
        let home = dirs::home_dir().expect("home dir available in test env");
        let expected = home.join(".ssh").join("config");
        // Compare as paths so Windows' mixed `/` vs `\` separators (the
        // input retains its forward slashes when pushed) compare equal
        // to the platform-native form.
        let actual = expand_tilde("~/.ssh/config");
        assert_eq!(Path::new(&actual), expected);
    }

    #[test]
    fn expand_tilde_alone_replaces_to_home() {
        let home = dirs::home_dir().expect("home dir available in test env");
        assert_eq!(expand_tilde("~"), home.to_string_lossy().into_owned());
    }

    #[test]
    fn expand_tilde_in_middle_unchanged() {
        assert_eq!(expand_tilde("/path/~name"), "/path/~name");
    }

    #[test]
    fn expand_tilde_user_form_treated_literally() {
        // `~user/...` is not supported on any platform; preserved verbatim.
        assert_eq!(expand_tilde("~root/foo"), "~root/foo");
    }

    #[test]
    fn expand_tilde_no_tilde_unchanged() {
        assert_eq!(expand_tilde("/etc/ssh/ssh_config"), "/etc/ssh/ssh_config");
        assert_eq!(expand_tilde(""), "");
    }

    // ── expand_env ───────────────────────────────────────────────────────────

    #[test]
    fn expand_env_braced_known_var() {
        // PATH is set in every reasonable test environment.
        let result = expand_env("${PATH}");
        let path = std::env::var("PATH").expect("PATH set in test env");
        assert_eq!(result, path);
    }

    #[test]
    fn expand_env_unbraced_known_var() {
        let result = expand_env("$PATH");
        let path = std::env::var("PATH").expect("PATH set in test env");
        assert_eq!(result, path);
    }

    #[test]
    fn expand_env_braced_unknown_var_is_empty() {
        // Use an extremely unlikely name to avoid accidental collisions.
        assert_eq!(expand_env("${ANVIL_DEFINITELY_UNSET_XYZZY_42}"), "");
        assert_eq!(expand_env("a-${ANVIL_DEFINITELY_UNSET_XYZZY_42}-b"), "a--b",);
    }

    #[test]
    fn expand_env_dollar_alone_preserved() {
        assert_eq!(expand_env("price: $"), "price: $");
        // Digit isn't a valid identifier start, so `$5` is preserved.
        assert_eq!(expand_env("$5 dollars"), "$5 dollars");
    }

    #[test]
    fn expand_env_unterminated_brace_preserved() {
        // No closing `}` — preserve the partial sequence verbatim.
        assert_eq!(expand_env("${UNCLOSED"), "${UNCLOSED");
    }

    #[test]
    fn expand_env_no_dollar_unchanged() {
        assert_eq!(expand_env("/etc/ssh/ssh_config"), "/etc/ssh/ssh_config");
    }

    // ── wildcard_match ───────────────────────────────────────────────────────

    #[test]
    fn wildcard_match_exact() {
        assert!(wildcard_match("github.com", "github.com"));
        assert!(!wildcard_match("github.com", "gitlab.com"));
    }

    #[test]
    fn wildcard_match_star_anything() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn wildcard_match_star_suffix() {
        assert!(wildcard_match("*.com", "github.com"));
        assert!(wildcard_match("*.com", ".com"));
        assert!(!wildcard_match("*.com", "github.org"));
    }

    #[test]
    fn wildcard_match_question() {
        assert!(wildcard_match("git?ub.com", "github.com"));
        assert!(!wildcard_match("g?", "github"));
        assert!(wildcard_match("g?", "gh"));
    }

    #[test]
    fn wildcard_match_combined() {
        assert!(wildcard_match("*.example.???", "foo.example.com"));
        assert!(!wildcard_match("*.example.???", "foo.example.online"));
        assert!(wildcard_match("a*b*c", "axxxbyyyc"));
    }

    #[test]
    fn wildcard_match_empty() {
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "x"));
        assert!(!wildcard_match("x", ""));
    }

    #[test]
    fn wildcard_match_consecutive_stars_collapse() {
        // `**` is treated as `*` (greedy match) — same observable behavior.
        assert!(wildcard_match("**", "anything"));
        assert!(wildcard_match("a**b", "ab"));
        assert!(wildcard_match("a**b", "axyzb"));
    }
}
