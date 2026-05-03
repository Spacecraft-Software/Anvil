// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
#![allow(
    dead_code,
    reason = "M12.1-M12.3 land the lexer / parser / matcher as crate-private \
              building blocks; the public `resolve()` consumer wires them up \
              in M12.4. Remove this allow at that time."
)]
//! `ssh_config(5)` parser and resolver for Anvil.
//!
//! Implements the subset of OpenSSH `ssh_config` directives required by
//! Gitway PRD §5.8.1.  Layered as:
//!
//! - [`lexer`] — line-oriented tokenizer.  Strips comments, joins
//!   continuation lines, splits on whitespace honoring quoted arguments,
//!   recognizes the `keyword=value` form.  Also exposes argument-level
//!   helpers ([`lexer::expand_tilde`], [`lexer::expand_env`],
//!   [`lexer::wildcard_match`]) used by include resolution and (later)
//!   the directive resolver.
//! - [`parser`] — groups token lines into Host blocks, handling implicit
//!   global directives (before the first `Host`) and the `Match` keyword.
//! - [`include`] — recursively resolves `Include` directives, with
//!   tilde/env expansion, glob matching on the final component, a 16-deep
//!   nesting limit, and cycle detection by canonicalized path.
//! - [`matcher`] — flattens parsed blocks to the directives that apply
//!   to a given host, honoring positive/negated patterns and case-
//!   insensitive comparison.  `Match` blocks are silently skipped per
//!   PRD §12 Q1.
//!
//! The public `resolve()` entry point lands in M12.4.  `Match` blocks
//! are explicitly deferred to v1.1 per PRD §12 Q1; they are recognized
//! at parse time so directive grouping stays correct, but never match
//! a host.
//!
//! All types in this module are crate-private until the public API ships
//! in M12.4.

pub(crate) mod include;
pub(crate) mod lexer;
pub(crate) mod matcher;
pub(crate) mod parser;
