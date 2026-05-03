// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Recursive `Include` directive resolution for `ssh_config(5)`.
//!
//! `Include` is recognized at parse time but treated specially: each
//! `Include path...` line is replaced in the token stream by the contents
//! of every file the path expands to.  Expansion is the composition of:
//!
//! 1. `${VAR}` / `$VAR` env-variable substitution (see [`super::lexer::expand_env`])
//! 2. Leading `~/` tilde expansion (see [`super::lexer::expand_tilde`])
//! 3. Filesystem glob expansion in the *final* path component
//!    (`*` and `?` only — character classes are not supported).
//!
//! The maximum nesting depth is fixed at 16, matching OpenSSH.  Cycle
//! detection uses [`Path::canonicalize`] so symlinked aliases collapse to
//! the same key; siblings (the same file Included twice through different
//! call paths) are *not* a cycle and are processed both times, again
//! matching OpenSSH.
//!
//! Missing files referenced by literal-path Includes are silently skipped
//! (also matching OpenSSH); a glob that matches nothing is likewise a
//! no-op.  Only true cycles and depth overflow are hard errors.
//!
//! # I/O boundary
//! Unlike the lexer (which is pure), this module *does* read files from
//! disk.  Callers pass in the primary file's already-tokenized form and
//! its directory; this module recursively reads + tokenizes any Included
//! files and inlines their token streams in place.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::lexer::{expand_env, expand_tilde, tokenize, wildcard_match, TokenLine};
use crate::error::AnvilError;

/// Maximum nesting depth for `Include` directives.  Matches OpenSSH's
/// hard-coded limit (`READCONF_MAX_DEPTH` in `readconf.c`).
const MAX_INCLUDE_DEPTH: u8 = 16;

/// Recursively expands `Include` directives in `tokens`, inlining the
/// tokens of every included file at the point of inclusion.
///
/// `primary_path` is the canonical-or-best-effort path to the file the
/// caller is processing.  It is used both to seed the cycle-detection
/// `visited` set (so a file cannot Include itself transitively) and as
/// the base directory for resolving relative Include paths.
///
/// Non-`Include` token lines are passed through unchanged.
///
/// # Errors
/// Returns [`AnvilError::invalid_config`] when:
/// - An Include resolves to a file that is already on the active include
///   stack (cycle), or
/// - The nesting depth would exceed [`MAX_INCLUDE_DEPTH`].
///
/// Missing literal-path files and zero-match globs do *not* error;
/// they expand to no tokens, matching OpenSSH.
pub(crate) fn expand_includes(
    primary_path: &Path,
    tokens: Vec<TokenLine>,
) -> Result<Vec<TokenLine>, AnvilError> {
    let canonical = primary_path
        .canonicalize()
        .unwrap_or_else(|_| primary_path.to_path_buf());
    let base_dir = canonical
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut visited: HashSet<PathBuf> = HashSet::new();
    visited.insert(canonical);
    expand_inner(tokens, &base_dir, 0, &mut visited)
}

fn expand_inner(
    tokens: Vec<TokenLine>,
    base_dir: &Path,
    depth: u8,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<TokenLine>, AnvilError> {
    let mut out: Vec<TokenLine> = Vec::with_capacity(tokens.len());

    for tok in tokens {
        if tok.keyword != "include" {
            out.push(tok);
            continue;
        }

        if depth >= MAX_INCLUDE_DEPTH {
            return Err(AnvilError::invalid_config(format!(
                "ssh_config: Include nesting depth would exceed {} at {}:{}",
                MAX_INCLUDE_DEPTH,
                tok.file.display(),
                tok.line_no,
            )));
        }

        // OpenSSH allows multiple paths per Include line, separated by
        // whitespace.  Each may itself be a glob.
        for arg in &tok.args {
            let expanded = expand_tilde(&expand_env(arg));
            let candidate = if Path::new(&expanded).is_absolute() {
                PathBuf::from(&expanded)
            } else {
                base_dir.join(&expanded)
            };

            for resolved in expand_glob(&candidate)? {
                // Missing file: silently skip (matches OpenSSH).
                let Ok(canonical) = resolved.canonicalize() else {
                    continue;
                };

                if !visited.insert(canonical.clone()) {
                    return Err(AnvilError::invalid_config(format!(
                        "ssh_config: Include cycle at {}:{} -> {}",
                        tok.file.display(),
                        tok.line_no,
                        canonical.display(),
                    )));
                }

                // Race between canonicalize and read: behave like a
                // missing file and drop from `visited` so a sibling
                // Include of the same path can still be tried.
                let Ok(content) = std::fs::read_to_string(&canonical) else {
                    visited.remove(&canonical);
                    continue;
                };

                let inner_tokens = tokenize(&content, &canonical)?;
                let inner_base = canonical
                    .parent()
                    .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
                let expanded_inner = expand_inner(inner_tokens, &inner_base, depth + 1, visited)?;
                out.extend(expanded_inner);

                // Pop after successful processing so a *sibling* Include of
                // the same file doesn't false-positive as a cycle.  Real
                // cycles (where the same file appears twice on the active
                // stack at the same time) are still caught above.
                visited.remove(&canonical);
            }
        }
    }

    Ok(out)
}

/// Expands the final path component of `path` against the filesystem if
/// it contains `*` or `?`, returning the matching files in sorted order.
///
/// Multi-component globs (wildcards in directory components, not just the
/// filename) are *not* supported; they produce an
/// [`AnvilError::invalid_config`].  A path with no wildcards is returned
/// unchanged in a single-element vector.
///
/// Wildcard detection iterates [`Path::components`] and inspects only
/// [`std::path::Component::Normal`] segments — that way the `\\?\`
/// Windows extended-length prefix (which contains a literal `?`) does
/// not trigger the multi-component-glob rejection.
fn expand_glob(path: &Path) -> Result<Vec<PathBuf>, AnvilError> {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        // No final component (e.g. `/`): nothing to glob, return as-is.
        return Ok(vec![path.to_path_buf()]);
    };

    let file_has_wildcard = file_name.contains('*') || file_name.contains('?');

    // Walk parent's `Components` and inspect only `Normal` segments so we
    // skip the Windows `\\?\` `Prefix` (which contains a literal `?`).
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_has_wildcard = parent.components().any(|component| {
        if let std::path::Component::Normal(seg) = component {
            let s = seg.to_string_lossy();
            s.contains('*') || s.contains('?')
        } else {
            false
        }
    });

    if parent_has_wildcard {
        return Err(AnvilError::invalid_config(format!(
            "ssh_config: Include path has wildcards outside the final \
             component (not supported): {}",
            path.display(),
        )));
    }

    if !file_has_wildcard {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut matches: Vec<PathBuf> = Vec::new();
    // Missing directory: no matches (same as zero-match glob).
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Ok(matches);
    };

    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if wildcard_match(file_name, name) {
            matches.push(entry.path());
        }
    }

    matches.sort();
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Helper: tokenize the content of `path` from disk for use with
    /// [`expand_includes`].
    fn tokenize_file(path: &Path) -> Vec<TokenLine> {
        let content = fs::read_to_string(path).expect("read primary file");
        tokenize(&content, path).expect("tokenize primary file")
    }

    #[test]
    fn simple_literal_include_inlines_tokens() {
        let dir = tempdir().expect("tempdir");
        let included = dir.path().join("inner.conf");
        fs::write(&included, "User innerguy\n").expect("write inner");

        let primary = dir.path().join("config");
        fs::write(
            &primary,
            format!("Host gh\nInclude {}\n", included.display()),
        )
        .expect("write primary");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");

        // Expected: Host gh, then User innerguy.  The Include line itself
        // disappears.
        let kws: Vec<&str> = expanded.iter().map(|t| t.keyword.as_str()).collect();
        assert_eq!(kws, vec!["host", "user"]);
        assert_eq!(expanded[1].args, vec!["innerguy"]);
    }

    #[test]
    fn relative_include_resolved_against_primary_dir() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("inner.conf"), "User rel\n").expect("write inner");

        let primary = dir.path().join("config");
        fs::write(&primary, "Include inner.conf\n").expect("write primary");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].keyword, "user");
        assert_eq!(expanded[0].args, vec!["rel"]);
    }

    #[test]
    fn missing_literal_include_is_silently_skipped() {
        let dir = tempdir().expect("tempdir");
        let primary = dir.path().join("config");
        fs::write(
            &primary,
            "Host gh\nInclude does_not_exist.conf\nUser later\n",
        )
        .expect("write primary");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        // The Include line drops out; neighbors remain.
        let kws: Vec<&str> = expanded.iter().map(|t| t.keyword.as_str()).collect();
        assert_eq!(kws, vec!["host", "user"]);
    }

    #[test]
    fn glob_include_matches_alphabetical() {
        let dir = tempdir().expect("tempdir");
        let conf_dir = dir.path().join("conf.d");
        fs::create_dir(&conf_dir).expect("mkdir");
        fs::write(conf_dir.join("10-a.conf"), "User a\n").expect("write a");
        fs::write(conf_dir.join("20-b.conf"), "User b\n").expect("write b");
        fs::write(conf_dir.join("30-c.conf"), "User c\n").expect("write c");
        fs::write(conf_dir.join("ignored.txt"), "User skipped\n").expect("write txt");

        let primary = dir.path().join("config");
        fs::write(&primary, "Include conf.d/*.conf\n").expect("write primary");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        let users: Vec<&str> = expanded
            .iter()
            .filter(|t| t.keyword == "user")
            .flat_map(|t| t.args.iter().map(String::as_str))
            .collect();
        // Alphabetical by filename: 10-a, 20-b, 30-c.  ignored.txt skipped.
        assert_eq!(users, vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_glob_is_silent_no_op() {
        let dir = tempdir().expect("tempdir");
        let conf_dir = dir.path().join("empty.d");
        fs::create_dir(&conf_dir).expect("mkdir");
        let primary = dir.path().join("config");
        fs::write(&primary, "Host gh\nInclude empty.d/*.conf\n").expect("write");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        let kws: Vec<&str> = expanded.iter().map(|t| t.keyword.as_str()).collect();
        assert_eq!(kws, vec!["host"]);
    }

    #[test]
    fn self_include_is_a_cycle_error() {
        let dir = tempdir().expect("tempdir");
        let primary = dir.path().join("config");
        // The path-based cycle check uses `canonicalize`, so self-Include
        // by name still resolves to the same canonical path.
        fs::write(&primary, "Include config\n").expect("write");

        let tokens = tokenize_file(&primary);
        let err = expand_includes(&primary, tokens).expect_err("self-include should cycle");
        let msg = format!("{err}");
        assert!(msg.contains("cycle"), "expected cycle error, got: {msg}");
    }

    #[test]
    fn mutual_include_is_a_cycle_error() {
        let dir = tempdir().expect("tempdir");
        let a = dir.path().join("a.conf");
        let b = dir.path().join("b.conf");
        fs::write(&a, "Include b.conf\n").expect("write a");
        fs::write(&b, "Include a.conf\n").expect("write b");

        let tokens = tokenize_file(&a);
        let err = expand_includes(&a, tokens).expect_err("mutual cycle");
        assert!(format!("{err}").contains("cycle"));
    }

    #[test]
    fn sibling_includes_are_not_a_cycle() {
        // A includes B then C; neither cycles back.  Both must process.
        let dir = tempdir().expect("tempdir");
        let b = dir.path().join("b.conf");
        let c = dir.path().join("c.conf");
        fs::write(&b, "User from_b\n").expect("write b");
        fs::write(&c, "User from_c\n").expect("write c");

        let primary = dir.path().join("a.conf");
        fs::write(&primary, "Include b.conf\nInclude c.conf\n").expect("write a");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        let users: Vec<&str> = expanded
            .iter()
            .flat_map(|t| t.args.iter().map(String::as_str))
            .collect();
        assert_eq!(users, vec!["from_b", "from_c"]);
    }

    #[test]
    fn nested_includes_inline_in_order() {
        // A includes B; B includes C.  Tokens flatten depth-first.
        let dir = tempdir().expect("tempdir");
        let c = dir.path().join("c.conf");
        let b = dir.path().join("b.conf");
        let a = dir.path().join("a.conf");
        fs::write(&c, "User c\n").expect("write c");
        fs::write(&b, format!("User b\nInclude {}\n", c.display())).expect("write b");
        fs::write(&a, format!("User a\nInclude {}\n", b.display())).expect("write a");

        let tokens = tokenize_file(&a);
        let expanded = expand_includes(&a, tokens).expect("expand");
        let users: Vec<&str> = expanded
            .iter()
            .flat_map(|t| t.args.iter().map(String::as_str))
            .collect();
        // a's directives, then b's, then c's (depth-first).
        assert_eq!(users, vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond_include_processes_target_twice() {
        // A includes B and C; both include D.  D is processed twice
        // (matches OpenSSH; not memoized).
        let dir = tempdir().expect("tempdir");
        let d = dir.path().join("d.conf");
        let b = dir.path().join("b.conf");
        let c = dir.path().join("c.conf");
        let a = dir.path().join("a.conf");
        fs::write(&d, "User d\n").expect("write d");
        fs::write(&b, format!("Include {}\n", d.display())).expect("write b");
        fs::write(&c, format!("Include {}\n", d.display())).expect("write c");
        fs::write(
            &a,
            format!("Include {}\nInclude {}\n", b.display(), c.display()),
        )
        .expect("write a");

        let tokens = tokenize_file(&a);
        let expanded = expand_includes(&a, tokens).expect("expand");
        let users: Vec<&str> = expanded
            .iter()
            .flat_map(|t| t.args.iter().map(String::as_str))
            .collect();
        // d appears twice: once via b, once via c.  Sibling-include
        // semantics (not a cycle).
        assert_eq!(users, vec!["d", "d"]);
    }

    #[test]
    fn multiple_paths_per_include_line() {
        let dir = tempdir().expect("tempdir");
        let x = dir.path().join("x.conf");
        let y = dir.path().join("y.conf");
        fs::write(&x, "User x\n").expect("write x");
        fs::write(&y, "User y\n").expect("write y");

        let primary = dir.path().join("config");
        fs::write(&primary, "Include x.conf y.conf\n").expect("write");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        let users: Vec<&str> = expanded
            .iter()
            .flat_map(|t| t.args.iter().map(String::as_str))
            .collect();
        assert_eq!(users, vec!["x", "y"]);
    }

    #[test]
    fn include_preserves_provenance_of_inner_directives() {
        let dir = tempdir().expect("tempdir");
        let inner = dir.path().join("inner.conf");
        fs::write(&inner, "# header line\nUser provtest\n").expect("write inner");

        let primary = dir.path().join("config");
        fs::write(&primary, format!("Include {}\n", inner.display())).expect("write primary");

        let tokens = tokenize_file(&primary);
        let expanded = expand_includes(&primary, tokens).expect("expand");
        assert_eq!(expanded.len(), 1);
        // The directive's `file` and `line_no` come from the *included*
        // file (resolver-stage diagnostics need the real source location).
        assert_eq!(expanded[0].line_no, 2);
        assert_eq!(
            expanded[0]
                .file
                .canonicalize()
                .unwrap_or(expanded[0].file.clone()),
            inner.canonicalize().unwrap_or(inner.clone()),
        );
    }

    #[test]
    fn multi_component_glob_is_a_clear_error() {
        // `~/.ssh/*/config` — wildcard in a non-final component is rejected.
        let dir = tempdir().expect("tempdir");
        let primary = dir.path().join("config");
        fs::write(&primary, "Include sub*/inner.conf\n").expect("write");

        let tokens = tokenize_file(&primary);
        let err = expand_includes(&primary, tokens).expect_err("multi-component glob");
        let msg = format!("{err}");
        assert!(
            msg.contains("final component"),
            "expected final-component error, got: {msg}",
        );
    }
}
