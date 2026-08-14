//! SQL statement redaction and table extraction.
//!
//! The SQL uprobes copy raw statement text out of the client process, which
//! can contain literal values: passwords in `SET`, PII in `WHERE` clauses,
//! card numbers in `INSERT`. That text is useful for identifying *which tables*
//! a process touched, and useless — actively harmful — to keep afterwards.
//!
//! So the flow is: redact first, derive second. [`redact_statement`] replaces
//! every literal with `?`, and [`extract_tables`] then reads table names off
//! the redacted form. Nothing in this module returns raw statement text, and
//! the raw buffer is dropped at ring-buffer decode time.
//!
//! The parser is deliberately shallow — a keyword scanner, not a SQL grammar.
//! It aims to be right on the common shapes and to fail closed (emit nothing)
//! rather than guess, because a wrong table name in a policy decision is worse
//! than a missing one.

/// Max bytes of comma-joined table names retained per event.
pub const SQL_TABLES_LEN: usize = 64;

/// Replace literal values in a statement with `?` placeholders.
///
/// Handles single-quoted strings (including both `''` and `\'` escapes),
/// Postgres dollar-quoted strings, and bare numeric literals. Double-quoted and
/// backtick-quoted identifiers are preserved — they name columns and tables,
/// not values. Comments are dropped entirely rather than redacted, because
/// their free-form text can carry both PII and the keywords
/// [`extract_tables`] keys on. Whitespace is collapsed so the same statement
/// shape yields a stable result.
pub fn redact_statement(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    let mut last_was_space = false;

    while i < bytes.len() {
        let c = bytes[i];

        match c {
            // Single-quoted string literal -> always a value, always redacted.
            b'\'' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        // MySQL treats `\'` as an escaped quote; Postgres with
                        // standard_conforming_strings does not. We assume the
                        // escape on both, because the failure modes are not
                        // symmetric: assuming it wrongly over-consumes to the
                        // next quote and merges two literals into one `?`,
                        // while not assuming it spills literal text out of a
                        // MySQL string. Over-redaction is the safe direction.
                        b'\\' => i += 2,
                        // `''` is an escaped quote, not the end of the literal.
                        b'\'' if bytes.get(i + 1) == Some(&b'\'') => i += 2,
                        b'\'' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                out.push('?');
                last_was_space = false;
            }
            // Postgres dollar-quoted string (`$$body$$`, `$tag$body$tag$`) ->
            // a value like any other literal, and the form most likely to hold
            // a credential, since it is what `SET PASSWORD` examples reach for.
            b'$' => match dollar_delimiter_len(bytes, i) {
                Some(delim_len) => {
                    let delim = &bytes[i..i + delim_len];
                    let mut j = i + delim_len;
                    while j < bytes.len() && !bytes[j..].starts_with(delim) {
                        j += 1;
                    }
                    // An unterminated body (statement truncated at capture) is
                    // consumed to the end rather than emitted.
                    i = if j < bytes.len() {
                        j + delim_len
                    } else {
                        bytes.len()
                    };
                    out.push('?');
                    last_was_space = false;
                }
                // Not a dollar quote — a `$1` placeholder or a `$` in a name.
                None => {
                    out.push('$');
                    last_was_space = false;
                    i += 1;
                }
            },
            // Comments are dropped, not redacted. Their text is free-form and
            // can carry both PII and introducer keywords, so leaving one in
            // place lets `-- update alice_ssn_1234` surface as a table name.
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                push_separator(&mut out, &mut last_was_space);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                // Block comments nest in Postgres, so track depth.
                let mut depth = 1usize;
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                push_separator(&mut out, &mut last_was_space);
            }
            // Quoted identifiers name schema objects, so they survive.
            b'"' | b'`' => {
                let quote = c;
                out.push(c as char);
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                if i < bytes.len() {
                    out.push(quote as char);
                    i += 1;
                }
                last_was_space = false;
            }
            // Numeric literal, but only when it starts a token: `t1` and
            // `col2` are identifiers, not numbers.
            b'0'..=b'9' if !last_char_is_ident(&out) => {
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'e')
                {
                    i += 1;
                }
                out.push('?');
                last_was_space = false;
            }
            _ if c.is_ascii_whitespace() => {
                push_separator(&mut out, &mut last_was_space);
                i += 1;
            }
            _ => {
                out.push(c as char);
                last_was_space = false;
                i += 1;
            }
        }
    }

    out.trim_end().to_string()
}

/// Append one collapsed separator space, so a dropped comment cannot fuse the
/// tokens on either side of it into a single word.
fn push_separator(out: &mut String, last_was_space: &mut bool) {
    if !*last_was_space && !out.is_empty() {
        out.push(' ');
    }
    *last_was_space = true;
}

/// Length of the `$tag$` opening delimiter at `start`, or `None` if no
/// dollar-quote begins there.
///
/// Postgres tags follow identifier rules, so a `$1` parameter placeholder is
/// rejected rather than read as an opening quote — mistaking one for a literal
/// would swallow the rest of the statement.
fn dollar_delimiter_len(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != b'$' {
        let c = bytes[i];
        let valid_tag_char = if i == start + 1 {
            c.is_ascii_alphabetic() || c == b'_'
        } else {
            c.is_ascii_alphanumeric() || c == b'_'
        };
        if !valid_tag_char {
            return None;
        }
        i += 1;
    }
    // Ran off the end without closing the delimiter -> not a dollar quote.
    (i < bytes.len()).then_some(i + 1 - start)
}

/// True when the last emitted char could be part of an identifier, meaning a
/// following digit continues that identifier rather than starting a literal.
fn last_char_is_ident(out: &str) -> bool {
    out.chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

/// A table reference, split into optional qualifier and bare name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRef {
    /// Schema/database qualifier from a dotted name (`analytics.users`).
    pub qualifier: Option<String>,
    /// Bare table name.
    pub name: String,
}

/// Extract table references from a redacted statement.
///
/// Recognizes the keywords that introduce a table: `FROM`, `JOIN`, `INTO`,
/// `UPDATE`, and `TABLE` (for DDL). Subqueries after `FROM (` and anything
/// that does not look like an identifier are skipped rather than guessed at.
pub fn extract_tables(redacted: &str) -> Vec<TableRef> {
    const INTRODUCERS: &[&str] = &["FROM", "JOIN", "INTO", "UPDATE", "TABLE"];

    let tokens: Vec<&str> = redacted.split_whitespace().collect();
    let mut out: Vec<TableRef> = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        let keyword = token.trim_matches(|c: char| !c.is_alphanumeric());
        if !INTRODUCERS.iter().any(|k| keyword.eq_ignore_ascii_case(k)) {
            continue;
        }

        let Some(raw_next) = tokens.get(idx + 1) else {
            continue;
        };

        // `CREATE TABLE IF NOT EXISTS t` — step over the guard clause.
        let mut next = *raw_next;
        if next.eq_ignore_ascii_case("IF") {
            match tokens.get(idx + 4) {
                Some(t) => next = t,
                None => continue,
            }
        }

        let Some(reference) = parse_table_token(next) else {
            continue;
        };
        if !out.contains(&reference) {
            out.push(reference);
        }
    }

    out
}

/// Parse one token into a table reference, or `None` if it is not a plain
/// identifier (a subquery paren, a placeholder, a keyword-like token).
fn parse_table_token(token: &str) -> Option<TableRef> {
    let cleaned = token.trim_matches(|c: char| {
        c == '(' || c == ')' || c == ',' || c == ';' || c == '"' || c == '`'
    });

    if cleaned.is_empty() || cleaned == "?" {
        return None;
    }
    // A SELECT after FROM means a subquery, not a table.
    if cleaned.eq_ignore_ascii_case("SELECT") {
        return None;
    }
    if !cleaned
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$')
    {
        return None;
    }
    // A bare number is a placeholder artifact, not a name.
    if cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    match cleaned.rsplit_once('.') {
        Some((qualifier, name)) if !qualifier.is_empty() && !name.is_empty() => Some(TableRef {
            qualifier: Some(qualifier.to_string()),
            name: name.to_string(),
        }),
        _ => Some(TableRef {
            qualifier: None,
            name: cleaned.to_string(),
        }),
    }
}

/// Pack table names into the fixed-size, comma-separated form carried on the
/// hot path. Truncates on a name boundary so a partial name is never emitted.
pub fn pack_tables(tables: &[TableRef]) -> [u8; SQL_TABLES_LEN] {
    let mut out = [0u8; SQL_TABLES_LEN];
    let mut used = 0usize;

    for table in tables {
        let rendered = match table.qualifier.as_deref() {
            Some(q) => format!("{q}.{}", table.name),
            None => table.name.clone(),
        };
        let needed = if used == 0 {
            rendered.len()
        } else {
            rendered.len() + 1
        };
        // Leave the final byte as a NUL terminator.
        if used + needed > SQL_TABLES_LEN - 1 {
            break;
        }
        if used > 0 {
            out[used] = b',';
            used += 1;
        }
        out[used..used + rendered.len()].copy_from_slice(rendered.as_bytes());
        used += rendered.len();
    }

    out
}

/// The packed table list, split back into the shape consumers report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnpackedTables {
    /// Database/schema qualifier, when the statement names exactly one.
    pub database: Option<String>,
    /// Bare table names, qualifier stripped.
    pub tables: Vec<String>,
}

/// Reverse [`pack_tables`]: split `db.table,db.other` into a database name and
/// bare table names.
///
/// A database is only reported when every qualified reference agrees on it — a
/// cross-database join has no single answer, and guessing one would be worse
/// than reporting none.
///
/// This is the one place the packed form is interpreted. Both the outbound
/// `DbQueryEvent` and the rule-engine `sql.database`/`sql.tables` fields read
/// it, so a rule cannot match on a name that differs from the one stored.
pub fn unpack_tables(packed: &str) -> UnpackedTables {
    let mut tables = Vec::new();
    let mut qualifiers = Vec::new();

    for entry in packed.split(',').filter(|s| !s.is_empty()) {
        match entry.rsplit_once('.') {
            Some((qualifier, name)) if !qualifier.is_empty() && !name.is_empty() => {
                qualifiers.push(qualifier.to_string());
                tables.push(name.to_string());
            }
            _ => tables.push(entry.to_string()),
        }
    }

    let database = match qualifiers.first() {
        Some(first) if qualifiers.iter().all(|q| q == first) => Some(first.clone()),
        _ => None,
    };

    UnpackedTables { database, tables }
}

/// [`unpack_tables`] over the fixed-size buffer [`pack_tables`] produces,
/// stopping at the NUL terminator.
pub fn unpack_tables_bytes(packed: &[u8]) -> UnpackedTables {
    let end = packed.iter().position(|b| *b == 0).unwrap_or(packed.len());
    match core::str::from_utf8(&packed[..end]) {
        Ok(text) => unpack_tables(text),
        // Table names are ASCII identifiers by construction, so invalid UTF-8
        // means the buffer is not what we packed. Report nothing rather than
        // a salvaged fragment.
        Err(_) => UnpackedTables::default(),
    }
}

/// FNV-1a over the redacted statement, so the same statement shape with
/// different literal values yields one stable fingerprint.
pub fn normalized_fingerprint(redacted: &str) -> u32 {
    // No text, no fingerprint. This happens when a prepared statement executes
    // without its prepare having been seen, and hashing the empty string would
    // give every such execution one plausible-looking value — grouping
    // unrelated queries under a fingerprint indistinguishable from a real one.
    // Zero is the sentinel the sender already reads as "not normalized".
    if redacted.is_empty() {
        return 0;
    }

    let mut hash: u32 = 0x811C_9DC5;
    for b in redacted.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables_of(sql: &str) -> Vec<String> {
        extract_tables(&redact_statement(sql))
            .into_iter()
            .map(|t| match t.qualifier {
                Some(q) => format!("{q}.{}", t.name),
                None => t.name,
            })
            .collect()
    }

    #[test]
    fn redacts_string_and_numeric_literals() {
        let out = redact_statement("SELECT * FROM users WHERE email = 'bob@x.io' AND age = 42");
        assert_eq!(out, "SELECT * FROM users WHERE email = ? AND age = ?");
        assert!(!out.contains("bob@x.io"), "literal must not survive");
        assert!(!out.contains("42"));
    }

    #[test]
    fn redacts_escaped_quotes_without_leaking_the_tail() {
        // The `''` escape must not terminate the literal early, which would
        // leave the rest of the value in the output.
        let out = redact_statement("SELECT * FROM t WHERE name = 'O''Brien secret'");
        assert_eq!(out, "SELECT * FROM t WHERE name = ?");
        assert!(!out.contains("Brien"));
        assert!(!out.contains("secret"));
    }

    #[test]
    fn redacts_credentials_in_admin_statements() {
        let out = redact_statement("SET PASSWORD = 'hunter2'");
        assert!(!out.contains("hunter2"));
    }

    /// MySQL escapes an embedded quote as `\'`. Reading that as the end of the
    /// literal leaves the remainder of the value in the output — this leaked
    /// `s SSN 123-45-6789` before the escape was handled.
    #[test]
    fn redacts_backslash_escaped_quotes_in_mysql_strings() {
        let out = redact_statement(r#"SELECT * FROM t WHERE n = 'alice\'s SSN 123-45-6789'"#);
        assert_eq!(out, "SELECT * FROM t WHERE n = ?");
        assert!(!out.contains("SSN"));
        assert!(!out.contains("123"));
    }

    /// A trailing backslash with no closing quote (statement truncated at the
    /// capture boundary) must consume to the end rather than spill the tail.
    #[test]
    fn redacts_unterminated_string_literals() {
        let out = redact_statement("INSERT INTO t VALUES ('secret value cut off");
        assert!(!out.contains("secret"));
        assert_eq!(out, "INSERT INTO t VALUES (?");
    }

    #[test]
    fn redacts_postgres_dollar_quoted_strings() {
        assert_eq!(redact_statement("SET p = $$hunter2$$"), "SET p = ?");
        assert_eq!(redact_statement("SET p = $tag$hunter2$tag$"), "SET p = ?");
        assert!(!redact_statement("SET p = $$hunter2$$").contains("hunter2"));
    }

    /// `$1`/`$2` are parameter placeholders, not dollar quotes. Treating one as
    /// an opening delimiter would swallow the rest of the statement.
    #[test]
    fn leaves_postgres_parameter_placeholders_intact() {
        let out = redact_statement("SELECT * FROM t WHERE a = $1 AND b = $2");
        assert_eq!(
            tables_of("SELECT * FROM t WHERE a = $1 AND b = $2"),
            vec!["t"]
        );
        assert!(
            out.contains("AND"),
            "placeholder swallowed the statement: {out}"
        );
    }

    /// Comment text is free-form: it can hold PII *and* an introducer keyword,
    /// which previously promoted the comment's contents to a table name.
    #[test]
    fn drops_comments_so_they_cannot_become_table_names() {
        assert_eq!(
            tables_of("SELECT 1 -- update alice_ssn_123456789"),
            Vec::<String>::new()
        );
        assert_eq!(
            tables_of("SELECT * FROM t /* from prod_secret_dump */"),
            vec!["t"]
        );

        let out = redact_statement("SELECT 1 -- update alice_ssn_123456789");
        assert!(
            !out.contains("alice_ssn_123456789"),
            "comment survived: {out}"
        );
    }

    /// Dropping a comment must not fuse the tokens on either side of it.
    #[test]
    fn dropped_comments_leave_a_token_separator() {
        assert_eq!(tables_of("SELECT * FROM/**/users"), vec!["users"]);
    }

    /// A `--` inside a string literal is data, not a comment introducer.
    #[test]
    fn does_not_treat_dashes_inside_literals_as_comments() {
        let out = redact_statement("SELECT * FROM t WHERE n = '-- not a comment' AND id = 1");
        assert_eq!(out, "SELECT * FROM t WHERE n = ? AND id = ?");
    }

    #[test]
    fn keeps_identifiers_that_contain_digits() {
        let out = redact_statement("SELECT col2 FROM table1 WHERE id = 7");
        assert_eq!(out, "SELECT col2 FROM table1 WHERE id = ?");
    }

    #[test]
    fn preserves_quoted_identifiers() {
        let out = redact_statement(r#"SELECT "user id" FROM "my table""#);
        assert_eq!(out, r#"SELECT "user id" FROM "my table""#);
    }

    #[test]
    fn collapses_whitespace_for_stable_shapes() {
        let a = redact_statement("SELECT *\n  FROM   users\tWHERE id = 1");
        let b = redact_statement("SELECT * FROM users WHERE id = 999");
        assert_eq!(a, b);
        assert_eq!(normalized_fingerprint(&a), normalized_fingerprint(&b));
    }

    #[test]
    fn extracts_tables_from_common_statement_shapes() {
        assert_eq!(tables_of("SELECT * FROM users"), vec!["users"]);
        assert_eq!(
            tables_of("INSERT INTO events (a) VALUES ('x')"),
            vec!["events"]
        );
        assert_eq!(tables_of("UPDATE accounts SET b = 1"), vec!["accounts"]);
        assert_eq!(
            tables_of("DELETE FROM sessions WHERE id = 3"),
            vec!["sessions"]
        );
        assert_eq!(tables_of("DROP TABLE archive"), vec!["archive"]);
        assert_eq!(
            tables_of("CREATE TABLE IF NOT EXISTS ledger (id int)"),
            vec!["ledger"]
        );
    }

    #[test]
    fn extracts_both_sides_of_a_join() {
        assert_eq!(
            tables_of("SELECT * FROM orders JOIN customers ON orders.cid = customers.id"),
            vec!["orders", "customers"]
        );
    }

    #[test]
    fn splits_qualified_names_into_database_and_table() {
        let refs = extract_tables(&redact_statement("SELECT * FROM finance.ledger"));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].qualifier.as_deref(), Some("finance"));
        assert_eq!(refs[0].name, "ledger");
    }

    #[test]
    fn skips_subqueries_rather_than_guessing() {
        // `FROM (SELECT ...)` has no table name at that position; the inner
        // FROM supplies the real one.
        assert_eq!(
            tables_of("SELECT * FROM (SELECT id FROM inner_t) x"),
            vec!["inner_t"]
        );
    }

    #[test]
    fn deduplicates_repeated_references() {
        assert_eq!(tables_of("SELECT * FROM t JOIN t ON t.a = t.b"), vec!["t"]);
    }

    #[test]
    fn pack_truncates_on_a_name_boundary() {
        let many: Vec<TableRef> = (0..40)
            .map(|i| TableRef {
                qualifier: None,
                name: format!("table_number_{i}"),
            })
            .collect();
        let packed = pack_tables(&many);

        let end = packed.iter().position(|b| *b == 0).unwrap_or(packed.len());
        let text = std::str::from_utf8(&packed[..end]).expect("utf8");
        assert!(text.len() < SQL_TABLES_LEN);
        // Every retained entry is whole — no trailing partial name.
        for name in text.split(',') {
            assert!(many.iter().any(|t| t.name == name), "partial name: {name}");
        }
    }

    /// A prepared statement executing without an observed prepare arrives with
    /// no text. It must not be handed a fingerprint that looks real, or every
    /// unresolvable execution groups together under one convincing hash.
    #[test]
    fn absent_statement_text_has_no_fingerprint() {
        assert_eq!(normalized_fingerprint(""), 0);
        assert_ne!(normalized_fingerprint("SELECT ?"), 0);
    }

    #[test]
    fn empty_and_garbage_input_yield_no_tables() {
        assert!(tables_of("").is_empty());
        assert!(tables_of("SELECT 1").is_empty());
        assert!(tables_of("FROM").is_empty());
    }
}
