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
//!   recognizes the `keyword=value` form.
//! - [`parser`] — groups token lines into Host blocks, handling implicit
//!   global directives (before the first `Host`) and the `Match` keyword.
//!
//! The matcher, `Include` resolver, tilde/env expansion, and the public
//! `resolve()` entry point land in subsequent sub-milestones (M12.2-M12.4).
//! `Match` blocks are explicitly deferred to v1.1 per PRD §12 Q1; they are
//! recognized at parse time so directive grouping stays correct, but never
//! match a host.
//!
//! All types in this module are crate-private until the public API ships
//! in M12.4.

pub(crate) mod lexer;
pub(crate) mod parser;
