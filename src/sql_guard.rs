//! Shared read-only SQL statement guard for the SQL-ish backends.
//!
//! A conservative, parser-free classifier used when a binding declares
//! `read_only: true`. The statement text is ALWAYS operator-fixed config (a
//! caller only supplies bound parameters, never SQL), so this is a
//! defense-in-depth check, not an injection boundary — and it fails closed: an
//! operator who genuinely needs writes sets `read_only: false`.
//!
//! A statement is accepted only when ALL hold:
//! 1. its leading keyword is a read-only opener (`SELECT`/`WITH`/`SHOW`/
//!    `DESCRIBE`/`DESC`/`EXPLAIN`),
//! 2. it contains no write/DDL/privilege keyword as a bare token anywhere —
//!    which is what catches data-modifying CTEs (`WITH x AS (INSERT …) …`) and
//!    `EXPLAIN ANALYZE` (whose inner statement executes; `ANALYZE` is a write
//!    token), and
//! 3. it is a single statement (no `;` followed by more SQL — blocks stacked
//!    writes like `SELECT 1; DELETE …`).
//!
//! The keyword scan runs over a "skeleton" with comments stripped and string /
//! quoted-identifier literals blanked, so a literal value like
//! `WHERE name = 'DROP TABLE t'` never trips the guard. Whole-word matching on
//! identifier boundaries means a column such as `update_time` is one token and
//! does NOT match `UPDATE`; only an unquoted identifier spelled exactly like a
//! write keyword would (rare — quote it or set `read_only: false`).

/// Leading keywords that open a read-only statement.
const READ_ONLY_LEADERS: &[&str] = &["SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXPLAIN"];

/// Write / DDL / privilege / session-mutation keywords that must not appear as
/// a bare token in a read-only statement. `ANALYZE` is included so
/// `EXPLAIN ANALYZE` (which executes) is rejected while plain `EXPLAIN` passes.
const WRITE_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "REPLACE", "TRUNCATE", "CREATE", "DROP",
    "ALTER", "RENAME", "GRANT", "REVOKE", "COMMENT", "INTO", "CALL", "EXEC", "EXECUTE", "COPY",
    "LOAD", "UNLOAD", "PUT", "REMOVE", "ATTACH", "DETACH", "INSTALL", "PRAGMA", "VACUUM",
    "ANALYZE", "OPTIMIZE",
];

/// Enforce that `statement` is read-only. `Ok(())` when read-only, else an
/// operator-facing `Err` naming the offending construct.
pub fn enforce_read_only(statement: &str) -> Result<(), String> {
    let skeleton = sql_skeleton(statement);
    let trimmed = skeleton.trim();
    if trimmed.is_empty() {
        return Err("read-only guard: empty statement".to_owned());
    }

    // (3) single statement only — a `;` with anything after it is a second
    // statement. A lone trailing `;` is fine.
    if let Some(idx) = trimmed.find(';')
        && !trimmed[idx + 1..].trim().is_empty()
    {
        return Err(
            "read-only guard: multiple statements are not allowed under read_only \
             (set read_only=false to allow writes)"
                .to_owned(),
        );
    }

    // (1) leading keyword.
    let first = trimmed
        .split(|c: char| !is_ident_char(c))
        .find(|t| !t.is_empty())
        .unwrap_or("");
    let first_upper = first.to_ascii_uppercase();
    if !READ_ONLY_LEADERS.contains(&first_upper.as_str()) {
        return Err(format!(
            "read-only guard: statement starts with `{first}`, not a read-only keyword \
             (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN); set read_only=false to allow writes"
        ));
    }

    // (2) no write keyword as a bare token anywhere (catches write-CTEs,
    // EXPLAIN ANALYZE, and anything the leading-keyword check alone misses).
    for token in trimmed.split(|c: char| !is_ident_char(c)) {
        if token.is_empty() {
            continue;
        }
        let upper = token.to_ascii_uppercase();
        if WRITE_KEYWORDS.contains(&upper.as_str()) {
            return Err(format!(
                "read-only guard: statement contains the write keyword `{upper}` \
                 (e.g. a data-modifying CTE or EXPLAIN ANALYZE); set read_only=false \
                 to allow writes"
            ));
        }
    }

    Ok(())
}

/// SQL identifier character (used for whole-word token boundaries). Treats
/// `_`, `$`, and `#` as identifier chars so names like `update_time` or
/// `v$session` stay single tokens.
fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '#'
}

/// Produce a scan skeleton: strip `--` line comments and `/* */` block
/// comments, and blank the contents of single-quoted strings, double-quoted
/// identifiers, and backtick identifiers (so literal/identifier text never
/// contributes keyword tokens). Quote bodies become empty; the delimiters are
/// dropped. Doubled quotes inside a string (`''`) are handled as escapes.
fn sql_skeleton(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            // line comment
            '-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // block comment
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                out.push(' ');
            }
            // quoted regions: skip the body, keep a space so adjacent tokens
            // stay separated.
            '\'' | '"' | '`' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        // doubled quote = escaped literal quote, stay inside.
                        if i + 1 < bytes.len() && bytes[i + 1] == quote {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(' ');
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_reads() {
        for s in [
            "SELECT * FROM t",
            "  select 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SHOW TABLES",
            "DESCRIBE t",
            "DESC t",
            "EXPLAIN SELECT * FROM t",
            "SELECT * FROM t WHERE name = 'DROP TABLE evil'", // write word in a literal
            "SELECT update_time, created_at FROM t", // write word as a substring of an identifier
            "/* c */ SELECT 1 -- trailing",
            "SELECT * FROM v$session",
            "SELECT 1;", // lone trailing semicolon
        ] {
            assert!(enforce_read_only(s).is_ok(), "should accept: {s}");
        }
    }

    #[test]
    fn rejects_leading_writes() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x=1",
            "DELETE FROM t",
            "DROP TABLE t",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    #[test]
    fn rejects_write_cte() {
        // Leading keyword is WITH (passes the old allowlist) but it writes.
        let s = "WITH moved AS (INSERT INTO archive SELECT * FROM live RETURNING *) SELECT * FROM moved";
        assert!(enforce_read_only(s).is_err());
    }

    #[test]
    fn rejects_explain_analyze() {
        // EXPLAIN passes the leading check; ANALYZE executes the inner stmt.
        assert!(enforce_read_only("EXPLAIN ANALYZE SELECT * FROM t").is_err());
        assert!(enforce_read_only("explain analyze delete from t").is_err());
        // plain EXPLAIN still allowed.
        assert!(enforce_read_only("EXPLAIN SELECT * FROM t").is_ok());
    }

    #[test]
    fn rejects_stacked_statements() {
        assert!(enforce_read_only("SELECT 1; DROP TABLE t").is_err());
        assert!(enforce_read_only("SELECT 1 ; DELETE FROM t").is_err());
        // a `;` inside a string literal is not a statement separator.
        assert!(enforce_read_only("SELECT ';' AS sep FROM t").is_ok());
    }

    #[test]
    fn rejects_select_into_and_calls() {
        assert!(enforce_read_only("SELECT * INTO new_t FROM t").is_err());
        assert!(enforce_read_only("CALL do_write()").is_err());
        assert!(enforce_read_only("COPY t TO 's3://x'").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(enforce_read_only("   ").is_err());
        assert!(enforce_read_only("/* only a comment */").is_err());
    }
}
