// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Host pattern matcher: select the directives that apply to a hostname.
//!
//! Walks an ordered list of [`HostBlock`]s and returns every directive
//! that should be considered when resolving config for a given host.
//! The resolver (M12.4) takes that flat directive list and applies the
//! "first occurrence wins" rule per `ssh_config(5)`.
//!
//! Block-by-block matching rules:
//!
//! - [`BlockKind::Global`] always applies.  Anything before the first
//!   `Host`/`Match` line is treated as if it lived inside `Host *`.
//! - [`BlockKind::Host`] applies when at least one *positive* pattern in
//!   the block matches the host AND no *negated* (`!`-prefixed) pattern
//!   matches.  Per `ssh_config(5)`: "If a negated entry is matched, then
//!   the Host entry is ignored, regardless of whether any other patterns
//!   on the line match."
//! - [`BlockKind::Match`] is *never* matched in M12.  Match-block
//!   semantics (host/user/exec/all) are deferred to v1.1 per PRD §12 Q1.
//!
//! Hostname comparisons are case-insensitive (matches DNS rules and
//! OpenSSH's `match_pattern`, which lower-cases both sides).
//!
//! Glob syntax in patterns is the subset shared with the file-include
//! glob implementation: `*` matches zero-or-more characters, `?` matches
//! exactly one.  See [`super::lexer::wildcard_match`] for the underlying
//! algorithm.

use super::lexer::wildcard_match;
use super::parser::{BlockKind, Directive, HostBlock, HostPattern};

/// Flattens `blocks` into the directives that apply to `host`, in source
/// order: global directives first, then directives from each matching
/// `Host` block in source order.
///
/// The returned slice references borrow from `blocks` for `'a`; the
/// caller must keep `blocks` alive for the duration of use.
///
/// `Match` blocks are silently skipped (deferred to v1.1).  Their
/// directives never appear in the output.
pub(crate) fn directives_for_host<'a>(blocks: &'a [HostBlock], host: &str) -> Vec<&'a Directive> {
    let mut out: Vec<&'a Directive> = Vec::new();
    for block in blocks {
        let applies = match &block.kind {
            BlockKind::Global => true,
            BlockKind::Host(patterns) => host_block_matches(patterns, host),
            BlockKind::Match => false,
        };
        if applies {
            out.extend(block.directives.iter());
        }
    }
    out
}

/// Returns `true` iff `patterns` should cause its containing `Host` block
/// to apply to `host`.
///
/// Both sides are lower-cased for the wildcard comparison (case-insensitive
/// per OpenSSH).
fn host_block_matches(patterns: &[HostPattern], host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    let mut positive_match = false;
    for p in patterns {
        let pat_lc = p.pattern.to_ascii_lowercase();
        if wildcard_match(&pat_lc, &host_lc) {
            if p.negated {
                // OpenSSH: a negated match overrides everything else on
                // the line — block is skipped entirely.
                return false;
            }
            positive_match = true;
        }
    }
    positive_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_config::lexer::tokenize;
    use crate::ssh_config::parser::parse;
    use std::path::PathBuf;

    fn parse_str(input: &str) -> Vec<HostBlock> {
        let tokens = tokenize(input, &PathBuf::from("test")).expect("tokenize");
        parse(tokens).expect("parse")
    }

    #[test]
    fn global_directives_always_apply() {
        let blocks = parse_str("User globaluser\nHost gh\n  User ghuser\n");
        let dirs = directives_for_host(&blocks, "anything.example.com");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].keyword, "user");
        assert_eq!(dirs[0].args, vec!["globaluser"]);
    }

    #[test]
    fn exact_host_match() {
        let blocks = parse_str("Host gh\n  User git\n");
        let dirs = directives_for_host(&blocks, "gh");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].keyword, "user");
    }

    #[test]
    fn no_match_yields_only_global() {
        let blocks = parse_str("User defaultuser\nHost gh\n  User git\n");
        let dirs = directives_for_host(&blocks, "other");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].args, vec!["defaultuser"]);
    }

    #[test]
    fn star_pattern_matches_anything() {
        let blocks = parse_str("Host *\n  User wild\n");
        let dirs = directives_for_host(&blocks, "anything");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].args, vec!["wild"]);
    }

    #[test]
    fn suffix_glob_matches() {
        let blocks = parse_str("Host *.example.com\n  User suf\n");
        assert_eq!(directives_for_host(&blocks, "host.example.com").len(), 1);
        assert_eq!(directives_for_host(&blocks, "host.example.org").len(), 0);
    }

    #[test]
    fn question_pattern_matches_one_char() {
        let blocks = parse_str("Host gh?\n  User q\n");
        assert_eq!(directives_for_host(&blocks, "gh1").len(), 1);
        assert_eq!(directives_for_host(&blocks, "gh").len(), 0);
        assert_eq!(directives_for_host(&blocks, "gh12").len(), 0);
    }

    #[test]
    fn multiple_patterns_in_one_host_line() {
        let blocks = parse_str("Host alpha beta gamma\n  User multi\n");
        assert_eq!(directives_for_host(&blocks, "alpha").len(), 1);
        assert_eq!(directives_for_host(&blocks, "beta").len(), 1);
        assert_eq!(directives_for_host(&blocks, "gamma").len(), 1);
        assert_eq!(directives_for_host(&blocks, "delta").len(), 0);
    }

    #[test]
    fn negation_excludes_match() {
        // `Host * !work` — everything except "work".
        let blocks = parse_str("Host * !work\n  User general\n");
        assert_eq!(directives_for_host(&blocks, "github.com").len(), 1);
        assert_eq!(directives_for_host(&blocks, "work").len(), 0);
    }

    #[test]
    fn negation_overrides_positive_match() {
        // `Host *.com !evil.com` — *.com except evil.com.
        let blocks = parse_str("Host *.com !evil.com\n  User any_com\n");
        assert_eq!(directives_for_host(&blocks, "good.com").len(), 1);
        assert_eq!(directives_for_host(&blocks, "evil.com").len(), 0);
    }

    #[test]
    fn only_negated_patterns_never_apply() {
        // Without any positive pattern, the block can't apply.  Matches
        // OpenSSH behavior — `Host !work` is a no-op block.
        let blocks = parse_str("Host !work\n  User noop\n");
        assert_eq!(directives_for_host(&blocks, "anything").len(), 0);
        assert_eq!(directives_for_host(&blocks, "work").len(), 0);
    }

    #[test]
    fn case_insensitive_match() {
        let blocks = parse_str("Host GitHub.COM\n  User upper\n");
        assert_eq!(directives_for_host(&blocks, "github.com").len(), 1);
        assert_eq!(directives_for_host(&blocks, "GITHUB.COM").len(), 1);
        assert_eq!(directives_for_host(&blocks, "GitHub.com").len(), 1);
    }

    #[test]
    fn case_insensitive_with_wildcard() {
        let blocks = parse_str("Host *.GITHUB.com\n  User u\n");
        assert_eq!(directives_for_host(&blocks, "host.github.com").len(), 1);
        assert_eq!(directives_for_host(&blocks, "host.GITHUB.COM").len(), 1);
    }

    #[test]
    fn directives_concatenated_across_matching_blocks() {
        let input = "User globaluser\n\
                     Host gh\n\
                     \x20\x20IdentityFile ~/.ssh/gh\n\
                     \x20\x20User ghuser\n\
                     Host *\n\
                     \x20\x20User wilduser\n";
        let blocks = parse_str(input);
        let dirs = directives_for_host(&blocks, "gh");
        // Global User + Host gh's IdentityFile + Host gh's User + Host *'s User.
        assert_eq!(dirs.len(), 4);
        let kws: Vec<&str> = dirs.iter().map(|d| d.keyword.as_str()).collect();
        assert_eq!(kws, vec!["user", "identityfile", "user", "user"]);
    }

    #[test]
    fn match_blocks_never_match_in_m12() {
        // Match-block bodies must not leak into any host's resolved set.
        let input = "Match host gh\n\
                     \x20\x20User matched\n\
                     Host gh\n\
                     \x20\x20User direct\n";
        let blocks = parse_str(input);
        let dirs = directives_for_host(&blocks, "gh");
        // Only the Host block's User directive applies.
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].args, vec!["direct"]);
    }

    #[test]
    fn provenance_carried_through_match() {
        let input = "Host gh\n  User u\n";
        let blocks = parse_str(input);
        let dirs = directives_for_host(&blocks, "gh");
        // The directive's source location is preserved through matching.
        assert_eq!(dirs[0].line_no, 2);
        assert_eq!(dirs[0].file, PathBuf::from("test"));
    }

    #[test]
    fn empty_blocks_yields_empty_for_unknown_host() {
        // A pure-Global config with no directives.
        let blocks = parse_str("");
        assert!(directives_for_host(&blocks, "anyhost").is_empty());
    }
}
