use std::collections::{HashMap, HashSet};

// Stage-0 prelude context injected into semantic passes.
//
// Why this exists:
// - stdlib symbols (predicates/sets) should be globally available
// - resolver/type-checker should not read stdlib files directly
// - compile() loads prelude once, then passes structured data forward

/// Stage-0 stdlib prelude context.
#[derive(Debug, Clone, Default)]
pub struct PreludeContext {
    // Predicate names available globally without `use`.
    pub builtin_predicates: HashSet<String>,
    // Set names available globally without `use`.
    pub builtin_sets: HashSet<String>,
    // Callable symbols available globally without `use` (e.g. baseline.image).
    pub builtin_callables: HashSet<String>,
    // Optional callable return signatures used by type-checker.
    // Example: baseline.image -> BaselineProfile
    pub builtin_callable_signatures: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PreludeError {
    // Line/column are 1-based and point into the prelude source file.
    pub line: usize,
    pub col: usize,
    pub message: String,
}

/// Parse built-in predicate declarations from stdlib OIL source.
pub fn parse_builtin_predicates(source: &str) -> Result<HashSet<String>, Vec<PreludeError>> {
    let mut out = HashSet::new();
    let mut errs = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        // Ignore blank/comment-only lines.
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        // Minimal header parse:
        // predicate <name>(...) = ...
        if let Some(rest) = trimmed.strip_prefix("predicate ") {
            if let Some(name) = rest.split('(').next() {
                let name = name.trim();
                if !name.is_empty() {
                    out.insert(name.to_string());
                    continue;
                }
            }
            errs.push(PreludeError {
                line: line_no,
                col: 1,
                message: "invalid predicate declaration header".to_string(),
            });
        }
    }

    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs)
    }
}

/// Parse globally available set declarations from stdlib builtins source.
pub fn parse_builtin_sets(source: &str) -> Result<HashSet<String>, Vec<PreludeError>> {
    let mut out = HashSet::new();
    let mut errs = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        // Minimal header parse:
        // set <name> = ...
        if let Some(rest) = trimmed.strip_prefix("set ") {
            let name = rest
                .split('=')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(name) = name {
                if is_valid_ident(name) {
                    out.insert(name.to_string());
                } else {
                    errs.push(PreludeError {
                        line: line_no,
                        col: 1,
                        message: format!("invalid set name '{name}'"),
                    });
                }
            } else {
                errs.push(PreludeError {
                    line: line_no,
                    col: 1,
                    message: "invalid set declaration header".to_string(),
                });
            }
        }
    }

    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs)
    }
}

/// Parse globally available callable declarations from stdlib callables source.
pub fn parse_builtin_callables(source: &str) -> Result<HashSet<String>, Vec<PreludeError>> {
    let mut out = HashSet::new();
    let mut errs = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("callable ") {
            match parse_callable_decl(rest.trim()) {
                Ok((name, _returns)) => {
                    out.insert(name);
                }
                Err(msg) => errs.push(PreludeError {
                    line: line_no,
                    col: 1,
                    message: msg,
                }),
            }
        }
    }

    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs)
    }
}

/// Parse typed callable signatures from stdlib callables source.
/// Supported forms:
/// - callable baseline.image
/// - callable baseline.image -> BaselineProfile
pub fn parse_builtin_callable_signatures(
    source: &str,
) -> Result<HashMap<String, String>, Vec<PreludeError>> {
    let mut out = HashMap::new();
    let mut errs = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("callable ") {
            match parse_callable_decl(rest.trim()) {
                Ok((name, returns)) => {
                    if let Some(entity) = returns {
                        out.insert(name, entity);
                    }
                }
                Err(msg) => errs.push(PreludeError {
                    line: line_no,
                    col: 1,
                    message: msg,
                }),
            }
        }
    }

    if errs.is_empty() { Ok(out) } else { Err(errs) }
}

// Keep identifier policy simple and ASCII for stdlib symbol names.
fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_valid_dotted_ident(s: &str) -> bool {
    s.split('.').all(is_valid_ident)
}

fn parse_callable_decl(rest: &str) -> Result<(String, Option<String>), String> {
    if rest.is_empty() {
        return Err("invalid callable declaration header".to_string());
    }

    let (name, returns) = if let Some((lhs, rhs)) = rest.split_once("->") {
        (lhs.trim(), Some(rhs.trim()))
    } else {
        (rest, None)
    };

    if name.is_empty() || !is_valid_dotted_ident(name) {
        return Err(format!("invalid callable name '{name}'"));
    }

    let returns = if let Some(entity) = returns {
        if entity.is_empty() || !is_valid_ident(entity) {
            return Err(format!("invalid callable return type '{entity}'"));
        }
        Some(entity.to_string())
    } else {
        None
    };

    Ok((name.to_string(), returns))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_predicate_names() {
        let src = r#"
predicate a(x) = x == 1
predicate b(y, z) = y == z
"#;
        let set = parse_builtin_predicates(src).expect("prelude parse");
        assert!(set.contains("a"));
        assert!(set.contains("b"));
    }

    #[test]
    fn parses_set_names() {
        let src = r#"
set shells = ["bash"]
set c2_ports = [4444]
"#;
        let set = parse_builtin_sets(src).expect("prelude set parse");
        assert!(set.contains("shells"));
        assert!(set.contains("c2_ports"));
    }

    #[test]
    fn parses_callable_names() {
        let src = r#"
callable baseline.image
callable baseline.workload
"#;
        let set = parse_builtin_callables(src).expect("prelude callable parse");
        assert!(set.contains("baseline.image"));
        assert!(set.contains("baseline.workload"));
    }

    #[test]
    fn parses_typed_callable_signatures() {
        let src = r#"
callable baseline.image -> BaselineProfile
callable baseline.workload -> BaselineProfile
"#;
        let sigs = parse_builtin_callable_signatures(src).expect("prelude callable sig parse");
        assert_eq!(sigs.get("baseline.image"), Some(&"BaselineProfile".to_string()));
        assert_eq!(sigs.get("baseline.workload"), Some(&"BaselineProfile".to_string()));
    }
}
