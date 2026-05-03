// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Groups [`TokenLine`]s into ordered Host blocks.
//!
//! `ssh_config(5)` is a sequence of sections.  Directives that appear
//! before the first `Host` (or `Match`) line apply globally to every
//! host, equivalent to being inside `Host *`.  We model this as an
//! implicit leading block.
//!
//! `Host` introduces a new section whose patterns are a list of
//! whitespace-separated globs (with optional `!`-prefixed negations).
//! `Match` is recognized so directive grouping stays correct after a
//! `Match` line, but Match-block bodies are deferred to v1.1 per
//! PRD §12 Q1 and never match a real host in M12.
//!
//! The parser does no I/O and no semantic validation beyond what's
//! needed to group directives — argument *types* (parsing a port number,
//! a path, a duration) are validated by the resolver in M12.4 where
//! per-directive errors can be attributed cleanly.

use super::lexer::TokenLine;
use crate::error::AnvilError;

/// A single host pattern from a `Host` line.
///
/// `Host !work *` produces two patterns: one negated (`work`) and one
/// positive (`*`).  Glob-character expansion (`*`, `?`) lives in the
/// matcher (M12.3); the parser only records the textual pattern and
/// whether it was prefixed with `!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostPattern {
    /// The pattern text *without* the leading `!` if `negated` is set.
    pub(crate) pattern: String,
    /// `true` if the source pattern was prefixed with `!`.
    pub(crate) negated: bool,
}

impl HostPattern {
    /// Parses one whitespace-separated token from a `Host` argument list.
    pub(crate) fn parse(token: &str) -> Self {
        if let Some(rest) = token.strip_prefix('!') {
            Self {
                pattern: rest.to_owned(),
                negated: true,
            }
        } else {
            Self {
                pattern: token.to_owned(),
                negated: false,
            }
        }
    }
}

/// Discriminator between block kinds.
///
/// Distinguishing Host from Match (and from the implicit leading global
/// section) keeps the matcher (M12.3) honest: it can match Host blocks
/// and explicitly skip Match blocks without rebuilding their semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockKind {
    /// Implicit section before any `Host` or `Match` line.  Behaves as
    /// if the file opened with `Host *`.
    Global,

    /// `Host` section.  Carries one or more patterns (negated or not).
    Host(Vec<HostPattern>),

    /// `Match` section.  Recognized for correct directive grouping but
    /// never matches in M12 per PRD §12 Q1.
    Match,
}

/// One directive within a block, with provenance preserved.
#[derive(Debug, Clone)]
pub(crate) struct Directive {
    /// Lower-cased keyword (e.g. `identityfile`, `port`).
    pub(crate) keyword: String,
    /// Arguments in order.
    pub(crate) args: Vec<String>,
    /// File the directive came from.
    pub(crate) file: std::path::PathBuf,
    /// 1-indexed line number.
    pub(crate) line_no: u32,
}

/// A section of an `ssh_config` file: kind discriminator plus its directives.
#[derive(Debug, Clone)]
pub(crate) struct HostBlock {
    pub(crate) kind: BlockKind,
    pub(crate) directives: Vec<Directive>,
}

/// Parses tokenized lines into ordered Host/Match/Global blocks.
///
/// The first block in the returned vector is always the implicit
/// [`BlockKind::Global`] section, even if the file is empty or starts
/// directly with `Host`.  Subsequent blocks appear in source order.
///
/// # Errors
/// Returns [`AnvilError::invalid_config`] for malformed `Host`/`Match`
/// lines (e.g. `Host` with zero patterns).
pub(crate) fn parse(tokens: Vec<TokenLine>) -> Result<Vec<HostBlock>, AnvilError> {
    let mut blocks: Vec<HostBlock> = vec![HostBlock {
        kind: BlockKind::Global,
        directives: Vec::new(),
    }];

    for tok in tokens {
        match tok.keyword.as_str() {
            "host" => {
                if tok.args.is_empty() {
                    return Err(AnvilError::invalid_config(format!(
                        "ssh_config: `Host` directive at {}:{} has no patterns",
                        tok.file.display(),
                        tok.line_no,
                    )));
                }
                let patterns: Vec<HostPattern> =
                    tok.args.iter().map(|s| HostPattern::parse(s)).collect();
                blocks.push(HostBlock {
                    kind: BlockKind::Host(patterns),
                    directives: Vec::new(),
                });
            }
            "match" => {
                // `Match` body semantics (host/user/exec/all) are deferred
                // to v1.1 per PRD §12 Q1.  We still consume the section so
                // any directives between this `Match` and the next
                // section header are correctly attributed to the (ignored)
                // Match block instead of leaking into the previous block.
                log::warn!(
                    "ssh_config: `Match` blocks are deferred to v1.1; ignoring section at {}:{}",
                    tok.file.display(),
                    tok.line_no,
                );
                blocks.push(HostBlock {
                    kind: BlockKind::Match,
                    directives: Vec::new(),
                });
            }
            _ => {
                // Append to the most recent block.  `blocks` always has
                // at least one element (the implicit Global), so the
                // unwrap is structurally guaranteed.
                let last = blocks
                    .last_mut()
                    .expect("blocks invariant: at least one block exists");
                last.directives.push(Directive {
                    keyword: tok.keyword,
                    args: tok.args,
                    file: tok.file,
                    line_no: tok.line_no,
                });
            }
        }
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_config::lexer::tokenize;
    use std::path::PathBuf;

    fn parse_str(input: &str) -> Vec<HostBlock> {
        let tokens = tokenize(input, &PathBuf::from("test")).expect("tokenize");
        parse(tokens).expect("parse")
    }

    #[test]
    fn empty_input_yields_only_global_block() {
        let blocks = parse_str("");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, BlockKind::Global);
        assert!(blocks[0].directives.is_empty());
    }

    #[test]
    fn directives_before_first_host_go_to_global() {
        let input = "User defaultuser\nIdentityFile ~/.ssh/global_id\n";
        let blocks = parse_str(input);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, BlockKind::Global);
        assert_eq!(blocks[0].directives.len(), 2);
        assert_eq!(blocks[0].directives[0].keyword, "user");
    }

    #[test]
    fn host_block_starts_new_section() {
        let input = "Host gh\n  HostName github.com\n  User git\n";
        let blocks = parse_str(input);
        assert_eq!(blocks.len(), 2);
        assert!(matches!(blocks[1].kind, BlockKind::Host(_)));
        assert_eq!(blocks[1].directives.len(), 2);
        assert_eq!(blocks[1].directives[0].keyword, "hostname");
    }

    #[test]
    fn host_pattern_negation() {
        let input = "Host !work *\n";
        let blocks = parse_str(input);
        assert_eq!(blocks.len(), 2);
        let BlockKind::Host(patterns) = &blocks[1].kind else {
            panic!("expected Host kind");
        };
        assert_eq!(patterns.len(), 2);
        assert_eq!(
            patterns[0],
            HostPattern {
                pattern: "work".to_owned(),
                negated: true,
            },
        );
        assert_eq!(
            patterns[1],
            HostPattern {
                pattern: "*".to_owned(),
                negated: false,
            },
        );
    }

    #[test]
    fn multiple_host_blocks_in_order() {
        let input = "Host a\n  User u1\nHost b\n  User u2\n";
        let blocks = parse_str(input);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[1].directives[0].args, vec!["u1"]);
        assert_eq!(blocks[2].directives[0].args, vec!["u2"]);
    }

    #[test]
    fn host_with_no_arguments_is_an_error() {
        let tokens = tokenize("Host\n", &PathBuf::from("t")).expect("tokenize");
        let err = parse(tokens).expect_err("should fail");
        assert!(format!("{err}").contains("no patterns"));
    }

    #[test]
    fn match_block_is_recognized_but_ignored() {
        let input = "Match host gh\n  User x\nHost y\n  User y\n";
        let blocks = parse_str(input);
        // Global, Match, Host(y).
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[1].kind, BlockKind::Match);
        // Match body still groups its directives so they don't leak into
        // the next block.
        assert_eq!(blocks[1].directives.len(), 1);
        assert_eq!(blocks[1].directives[0].args, vec!["x"]);
        // The directive after `Host y` lands in the Host block, not the
        // Match block.
        let BlockKind::Host(_) = &blocks[2].kind else {
            panic!("expected Host kind for blocks[2]");
        };
        assert_eq!(blocks[2].directives[0].args, vec!["y"]);
    }

    #[test]
    fn directive_provenance_is_preserved() {
        let input = "# header\nHost gh\n  User git\n";
        let blocks = parse_str(input);
        assert_eq!(blocks[1].directives[0].line_no, 3);
        assert_eq!(blocks[1].directives[0].file, PathBuf::from("test"));
    }
}
