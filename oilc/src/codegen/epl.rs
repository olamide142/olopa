use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::ast::{ArithOp, CmpOp, Expr};
use crate::mid::{MirExpr, MirProgram};

#[derive(Debug, Clone, Default)]
pub struct EplProgram {
    pub artifacts: Vec<EplArtifact>,
}

#[derive(Debug, Clone)]
pub struct EplArtifact {
    pub rule_name: String,
    pub function_name: String,
    pub source: String,
    pub shared_object_path: Option<String>,
    pub compile_error: Option<String>,
}

pub fn emit_epl_program(mir: &MirProgram) -> EplProgram {
    let artifacts = mir
        .rules
        .iter()
        .map(|rule| {
            let slug = sanitize_name(&rule.name);
            let function_name = format!("rule_{slug}");
            let eval_fn_name = format!("eval_rule_{slug}");
            let source = emit_rule_source(&eval_fn_name, &function_name, rule);
            let (shared_object_path, compile_error) =
                compile_shared_object(&slug, &source, &function_name);

            EplArtifact {
                rule_name: rule.name.clone(),
                function_name,
                source,
                shared_object_path,
                compile_error,
            }
        })
        .collect();

    EplProgram { artifacts }
}

fn emit_rule_source(eval_fn_name: &str, ffi_fn_name: &str, rule: &crate::mid::MirRule) -> String {
    let mut source = String::new();
    source.push_str("// Auto-generated EPL backend source\n");
    source.push_str("use std::collections::BTreeMap;\n\n");
    source.push_str("pub type OlopaEvent = BTreeMap<String, String>;\n");
    source.push_str("#[derive(Default, Debug, Clone)]\n");
    source.push_str("pub struct Alert;\n\n");
    source.push_str("fn field(event: &OlopaEvent, key: &str) -> String {\n");
    source.push_str("    event.get(key).cloned().unwrap_or_default()\n");
    source.push_str("}\n\n");
    source.push_str("fn to_f64(v: &str) -> f64 {\n");
    source.push_str("    v.parse::<f64>().unwrap_or(0.0)\n");
    source.push_str("}\n\n");
    source.push_str(&format!(
        "pub fn {eval_fn_name}(event: &OlopaEvent) -> Option<Alert> {{\n"
    ));

    for pred in &rule.predicates {
        source.push_str(&format!(
            "    // predicate\n    if !({}) {{ return None; }}\n",
            emit_expr(&pred.expr)
        ));
    }

    source.push_str("    // score + response wiring will be expanded in later passes\n");
    source.push_str("    Some(Alert::default())\n");
    source.push_str("}\n\n");

    source.push_str("#[no_mangle]\n");
    source.push_str(&format!(
        "pub extern \"C\" fn {ffi_fn_name}(event_json_ptr: *const u8, event_json_len: usize) -> i32 {{\n"
    ));
    source.push_str("    if event_json_ptr.is_null() {\n");
    source.push_str("        return 0;\n");
    source.push_str("    }\n");
    source.push_str("    let _payload = unsafe { std::slice::from_raw_parts(event_json_ptr, event_json_len) };\n");
    source.push_str("    // TODO: decode runtime payload into typed event map.\n");
    source.push_str("    let event = OlopaEvent::new();\n");
    source.push_str(&format!(
        "    if {eval_fn_name}(&event).is_some() {{ 1 }} else {{ 0 }}\n"
    ));
    source.push_str("}\n");
    source
}

fn compile_shared_object(slug: &str, source: &str, function_name: &str) -> (Option<String>, Option<String>) {
    let base_dir = std::env::temp_dir().join("oilc_epl_backend");
    if let Err(e) = fs::create_dir_all(&base_dir) {
        return (None, Some(format!("failed to create backend dir: {e}")));
    }

    let src_path = base_dir.join(format!("{slug}.rs"));
    if let Err(e) = fs::write(&src_path, source) {
        return (None, Some(format!("failed to write generated source: {e}")));
    }

    let so_path = base_dir.join(format!("lib{function_name}.so"));
    let default_args = vec![
        "--crate-name".to_string(),
        format!("oilc_rule_{slug}"),
        "--crate-type".to_string(),
        "cdylib".to_string(),
        "--edition".to_string(),
        "2021".to_string(),
        src_path.to_string_lossy().to_string(),
        "-o".to_string(),
        so_path.to_string_lossy().to_string(),
    ];

    match run_rustc(&default_args) {
        Ok(()) => (Some(path_to_string(so_path)), None),
        Err(primary_err) => {
            // Retry with an explicit linker override. Some environments have
            // rust-lld instability for ad-hoc cdylib linking.
            let mut fallback_args = default_args;
            fallback_args.extend_from_slice(&[
                "-C".to_string(),
                "link-arg=-fuse-ld=bfd".to_string(),
            ]);

            match run_rustc(&fallback_args) {
                Ok(()) => (Some(path_to_string(so_path)), None),
                Err(fallback_err) => (
                    None,
                    Some(format!(
                        "default linker failed:\n{primary_err}\n\nfallback linker failed:\n{fallback_err}"
                    )),
                ),
            }
        }
    }
}

fn run_rustc(args: &[String]) -> Result<(), String> {
    let output = Command::new("rustc").args(args).output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).to_string()),
        Err(e) => Err(format!("failed to execute rustc: {e}")),
    }
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn emit_expr(expr: &MirExpr) -> String {
    match expr {
        MirExpr::Raw(ast) => emit_bool_expr(ast),
    }
}

fn emit_bool_expr(expr: &Expr) -> String {
    match expr {
        Expr::BoolLit(v) => {
            if *v { "true".to_string() } else { "false".to_string() }
        }
        Expr::And(lhs, rhs) => {
            format!(
                "({}) && ({})",
                emit_bool_expr(&lhs.node),
                emit_bool_expr(&rhs.node)
            )
        }
        Expr::Or(lhs, rhs) => {
            format!(
                "({}) || ({})",
                emit_bool_expr(&lhs.node),
                emit_bool_expr(&rhs.node)
            )
        }
        Expr::Not(inner) => format!("!({})", emit_bool_expr(&inner.node)),
        Expr::Cmp { op, lhs, rhs } => {
            let op = match op {
                CmpOp::Eq => "==",
                CmpOp::Ne => "!=",
                CmpOp::Lt => "<",
                CmpOp::Gt => ">",
                CmpOp::Le => "<=",
                CmpOp::Ge => ">=",
            };
            format!(
                "(to_f64(&{}) {} to_f64(&{}))",
                emit_value_expr(&lhs.node),
                op,
                emit_value_expr(&rhs.node)
            )
        }
        Expr::In { lhs, rhs } => {
            if let Expr::List(items) = &rhs.node {
                let values = items
                    .iter()
                    .map(|v| emit_value_expr(&v.node))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}].contains(&{})", values, emit_value_expr(&lhs.node))
            } else {
                "false".to_string()
            }
        }
        Expr::NotIn { lhs, rhs } => format!("!({})", emit_bool_expr(&Expr::In {
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        })),
        Expr::StartsWith { lhs, rhs } => {
            format!(
                "{}.starts_with(&{})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::EndsWith { lhs, rhs } => {
            format!(
                "{}.ends_with(&{})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::Contains { lhs, rhs } => {
            format!(
                "{}.contains(&{})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::Matches { .. } => "false".to_string(),
        Expr::Under { path, prefix } => {
            format!(
                "{}.starts_with(&{})",
                emit_value_expr(&path.node),
                emit_value_expr(&prefix.node)
            )
        }
        Expr::Between { val, lo, hi } => format!(
            "(to_f64(&{}) >= to_f64(&{}) && to_f64(&{}) <= to_f64(&{}))",
            emit_value_expr(&val.node),
            emit_value_expr(&lo.node),
            emit_value_expr(&val.node),
            emit_value_expr(&hi.node)
        ),
        _ => "true".to_string(),
    }
}

fn emit_value_expr(expr: &Expr) -> String {
    match expr {
        Expr::StrLit(s) => format!("{s:?}.to_string()"),
        Expr::IntLit(n) => format!("{n}.to_string()"),
        Expr::FloatLit(n) => format!("{n}.to_string()"),
        Expr::BoolLit(v) => {
            if *v { "\"true\".to_string()".to_string() } else { "\"false\".to_string()".to_string() }
        }
        Expr::Path(parts) => format!("field(event, \"{}\")", parts.join(".")),
        Expr::Ident(name) => format!("field(event, \"{name}\")"),
        Expr::Member { base, field } => {
            format!("format!(\"{{}}.{field}\", {})", emit_value_expr(&base.node))
        }
        Expr::BinOp { op, lhs, rhs } => {
            let op = match op {
                ArithOp::Add => "+",
                ArithOp::Sub => "-",
                ArithOp::Mul => "*",
                ArithOp::Div => "/",
            };
            format!(
                "(to_f64(&{}) {} to_f64(&{})).to_string()",
                emit_value_expr(&lhs.node),
                op,
                emit_value_expr(&rhs.node)
            )
        }
        Expr::DurationLit(d) => format!("{}.to_string()", d.value),
        Expr::Call { .. } => "\"\".to_string()".to_string(),
        Expr::List(_) => "\"\".to_string()".to_string(),
        Expr::Null => "\"\".to_string()".to_string(),
        Expr::UnaryMinus(inner) => format!("(-to_f64(&{})).to_string()", emit_value_expr(&inner.node)),
        Expr::And(_, _)
        | Expr::Or(_, _)
        | Expr::Not(_)
        | Expr::Cmp { .. }
        | Expr::In { .. }
        | Expr::NotIn { .. }
        | Expr::StartsWith { .. }
        | Expr::EndsWith { .. }
        | Expr::Contains { .. }
        | Expr::Matches { .. }
        | Expr::Under { .. }
        | Expr::Between { .. }
        | Expr::UnusualFor { .. }
        | Expr::Rare(_)
        | Expr::Count(_)
        | Expr::Max(_)
        | Expr::Min(_)
        | Expr::Sum(_)
        | Expr::Avg(_)
        | Expr::Distinct(_) => format!(
            "(if {} {{ \"true\".to_string() }} else {{ \"false\".to_string() }})",
            emit_bool_expr(expr)
        ),
    }
}

fn sanitize_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '_' || ch == '-' || ch == ' ' {
            out.push('_');
        }
    }
    if out.is_empty() {
        "rule".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile, CompilerConfig};
    use crate::lexer::Lexer;
    use crate::mid::lower_program;
    use crate::parser::Parser;

    #[test]
    fn emits_artifact_per_rule() {
        let src = r#"
rule "r1" {
  from endpoint.process
  correlate process.spawn as p
  where p.name == "bash"
  respond alert high
}
rule "r2" {
  from endpoint.process
  correlate process.spawn as p
  respond alert low
}
"#;
        let toks = Lexer::new(src).tokenize().expect("lex");
        let mut p = Parser::new(toks);
        let program = p.parse().expect("parse");
        let mir = lower_program(&program);
        let epl = emit_epl_program(&mir);
        assert_eq!(epl.artifacts.len(), 2);
        assert!(epl.artifacts[0].function_name.contains("rule_r1"));
    }

    #[test]
    fn compile_pipeline_produces_epl_codegen_output() {
        let src = r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  respond alert high
}
"#;
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        assert_eq!(codegen.epl.artifacts.len(), 1);
    }

    #[test]
    fn snapshot_tmp_exec_rule_epl_output() {
        let src = include_str!("../rules/stress_test/tmp_exec.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        let artifact = codegen
            .epl
            .artifacts
            .first()
            .expect("epl artifact for tmp_exec");

        assert_eq!(artifact.rule_name, "tmp_exec");
        assert_eq!(artifact.function_name, "rule_tmp_exec");
        assert!(
            artifact
                .source
                .contains("pub extern \"C\" fn rule_tmp_exec(event_json_ptr: *const u8, event_json_len: usize) -> i32"),
            "snapshot mismatch (ffi signature): {}",
            artifact.source
        );
        assert!(
            artifact
                .source
                .contains("if !(field(event, \"p.binary.path\").starts_with(&\"/tmp\".to_string()))"),
            "snapshot mismatch (predicate emission): {}",
            artifact.source
        );
        assert!(
            artifact.source.contains("#[no_mangle]"),
            "snapshot mismatch (export symbol): {}",
            artifact.source
        );
    }

    #[test]
    fn snapshot_showcase_rule_epl_output() {
        let src = include_str!("../rules/showcase.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        let artifact = codegen
            .epl
            .artifacts
            .first()
            .expect("epl artifact for showcase");

        assert_eq!(
            artifact.rule_name,
            "container_shell_credential_access_and_egress"
        );
        assert_eq!(
            artifact.function_name,
            "rule_container_shell_credential_access_and_egress"
        );
        assert!(
            artifact
                .source
                .contains("pub extern \"C\" fn rule_container_shell_credential_access_and_egress("),
            "snapshot mismatch (ffi function signature): {}",
            artifact.source
        );
        assert!(
            artifact.source.contains("if !("),
            "snapshot mismatch (predicate shape): {}",
            artifact.source
        );
    }

    #[test]
    fn generated_epl_shared_object_is_built() {
        let src = include_str!("../rules/stress_test/tmp_exec.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let artifact = out
            .codegen
            .expect("codegen")
            .epl
            .artifacts
            .into_iter()
            .next()
            .expect("artifact");
        assert!(
            artifact.compile_error.is_none(),
            "unexpected epl compile error: {:?}",
            artifact.compile_error
        );
        let path = artifact.shared_object_path.expect("shared object path");
        assert!(
            std::path::Path::new(&path).exists(),
            "expected generated shared object at {path}"
        );
    }
}
