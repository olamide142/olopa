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
    // Typed callable contracts used by type-checker.
    // Example: baseline.image(image_id: Str) -> BaselineProfile
    pub builtin_callable_signatures: HashMap<String, CallableSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallableSignature {
    pub params: Vec<CallableParam>,
    pub returns: Option<CallableTypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallableParam {
    pub name: String,
    pub ty: CallableTypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallableTypeRef {
    Str,
    Int,
    Float,
    Bool,
    Duration,
    Path,
    IpAddr,
    Entity(String),
    Set(Box<CallableTypeRef>),
    Nullable(Box<CallableTypeRef>),
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
                Ok((name, _sig)) => {
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
/// - callable baseline.image(image_id: Str) -> BaselineProfile
pub fn parse_builtin_callable_signatures(
    source: &str,
) -> Result<HashMap<String, CallableSignature>, Vec<PreludeError>> {
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
                Ok((name, sig)) => {
                    out.insert(name, sig);
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

fn parse_callable_decl(rest: &str) -> Result<(String, CallableSignature), String> {
    if rest.is_empty() {
        return Err("invalid callable declaration header".to_string());
    }

    let (header, returns) = if let Some((lhs, rhs)) = rest.split_once("->") {
        (lhs.trim(), Some(rhs.trim()))
    } else {
        (rest, None)
    };

    let (name, params) = parse_callable_header(header)?;

    if name.is_empty() || !is_valid_dotted_ident(name) {
        return Err(format!("invalid callable name '{name}'"));
    }

    let returns = if let Some(ret_ty) = returns {
        Some(parse_callable_type_ref(ret_ty)?)
    } else {
        None
    };

    Ok((name.to_string(), CallableSignature { params, returns }))
}

fn parse_callable_header(header: &str) -> Result<(&str, Vec<CallableParam>), String> {
    if let Some((name, tail)) = header.split_once('(') {
        let name = name.trim();
        if name.is_empty() || !is_valid_dotted_ident(name) {
            return Err(format!("invalid callable name '{name}'"));
        }
        if !tail.ends_with(')') {
            return Err("expected ')' to close callable parameter list".to_string());
        }

        let params_raw = tail[..tail.len() - 1].trim();
        if params_raw.is_empty() {
            return Ok((name, Vec::new()));
        }

        let mut params = Vec::new();
        for raw in params_raw.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err("invalid callable parameter declaration".to_string());
            }
            let (param_name, param_ty) = raw
                .split_once(':')
                .ok_or_else(|| format!("expected ':' in callable parameter '{raw}'"))?;
            let param_name = param_name.trim();
            let param_ty = param_ty.trim();
            if !is_valid_ident(param_name) {
                return Err(format!("invalid callable parameter name '{param_name}'"));
            }
            let ty = parse_callable_type_ref(param_ty)?;
            params.push(CallableParam {
                name: param_name.to_string(),
                ty,
            });
        }
        Ok((name, params))
    } else {
        if header.contains(')') {
            return Err("invalid callable declaration header".to_string());
        }
        let name = header.trim();
        if name.is_empty() || !is_valid_dotted_ident(name) {
            return Err(format!("invalid callable name '{name}'"));
        }
        Ok((name, Vec::new()))
    }
}

fn parse_callable_type_ref(raw: &str) -> Result<CallableTypeRef, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("invalid callable parameter type ''".to_string());
    }

    if let Some(inner) = raw.strip_suffix('?') {
        let inner = parse_callable_type_ref(inner.trim())?;
        return Ok(CallableTypeRef::Nullable(Box::new(inner)));
    }

    if let Some(inner) = raw.strip_prefix("Set<").and_then(|s| s.strip_suffix('>')) {
        let inner = parse_callable_type_ref(inner.trim())?;
        return Ok(CallableTypeRef::Set(Box::new(inner)));
    }

    if let Some(inner) = raw
        .strip_prefix("Nullable<")
        .and_then(|s| s.strip_suffix('>'))
    {
        let inner = parse_callable_type_ref(inner.trim())?;
        return Ok(CallableTypeRef::Nullable(Box::new(inner)));
    }

    match raw {
        "Str" => Ok(CallableTypeRef::Str),
        "Int" => Ok(CallableTypeRef::Int),
        "Float" => Ok(CallableTypeRef::Float),
        "Bool" => Ok(CallableTypeRef::Bool),
        "Duration" => Ok(CallableTypeRef::Duration),
        "Path" => Ok(CallableTypeRef::Path),
        "IpAddr" => Ok(CallableTypeRef::IpAddr),
        other if is_valid_ident(other) => Ok(CallableTypeRef::Entity(other.to_string())),
        _ => Err(format!("invalid callable parameter type '{raw}'")),
    }
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
callable baseline.image(image_id: Str) -> BaselineProfile
callable baseline.workload(namespace: Str, name: Str) -> BaselineProfile
callable baseline.flags(tags: Set<Str>, host: Nullable<Host>, maybe_path: Path?) -> BaselineProfile
"#;
        let sigs = parse_builtin_callable_signatures(src).expect("prelude callable sig parse");
        let image_sig = sigs.get("baseline.image").expect("image sig");
        assert_eq!(
            image_sig.returns,
            Some(CallableTypeRef::Entity("BaselineProfile".to_string()))
        );
        assert_eq!(image_sig.params.len(), 1);
        assert_eq!(image_sig.params[0].name, "image_id");
        assert_eq!(image_sig.params[0].ty, CallableTypeRef::Str);

        let workload_sig = sigs.get("baseline.workload").expect("workload sig");
        assert_eq!(
            workload_sig.returns,
            Some(CallableTypeRef::Entity("BaselineProfile".to_string()))
        );
        assert_eq!(workload_sig.params.len(), 2);
        assert_eq!(workload_sig.params[0].name, "namespace");
        assert_eq!(workload_sig.params[1].name, "name");

        let flags_sig = sigs.get("baseline.flags").expect("flags sig");
        assert_eq!(flags_sig.params.len(), 3);
        assert_eq!(
            flags_sig.params[0].ty,
            CallableTypeRef::Set(Box::new(CallableTypeRef::Str))
        );
        assert_eq!(
            flags_sig.params[1].ty,
            CallableTypeRef::Nullable(Box::new(CallableTypeRef::Entity("Host".to_string())))
        );
        assert_eq!(
            flags_sig.params[2].ty,
            CallableTypeRef::Nullable(Box::new(CallableTypeRef::Path))
        );
    }
}
