use crate::mid::{MirExpr, MirProgram};

#[derive(Debug, Clone, Default)]
pub struct CypherProgram {
    pub artifacts: Vec<CypherArtifact>,
}

#[derive(Debug, Clone)]
pub struct CypherArtifact {
    pub rule_name: String,
    pub trigger_name: String,
    pub cypher: String,
}

pub fn emit_cypher_program(mir: &MirProgram) -> CypherProgram {
    let artifacts = mir
        .rules
        .iter()
        .map(|rule| {
            let slug = sanitize_name(&rule.name);
            let trigger_name = format!("oilc_{slug}_trigger");

            let where_clause = if rule.predicates.is_empty() {
                String::new()
            } else {
                let pred = rule
                    .predicates
                    .iter()
                    .map(|p| emit_expr(&p.expr))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                format!("WHERE {pred}")
            };

            let cypher = format!(
                "CREATE TRIGGER {trigger_name}\n\
                 ON CREATE BEFORE COMMIT EXECUTE\n\
                 MATCH (e:Event)\n\
                 {where_clause}\n\
                 RETURN e;"
            );

            CypherArtifact {
                rule_name: rule.name.clone(),
                trigger_name,
                cypher,
            }
        })
        .collect();
    CypherProgram { artifacts }
}

fn emit_expr(expr: &MirExpr) -> String {
    emit_bool_expr(expr)
}

fn emit_bool_expr(expr: &MirExpr) -> String {
    match expr {
        MirExpr::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        MirExpr::And { lhs, rhs } => {
            format!("({}) AND ({})", emit_bool_expr(lhs), emit_bool_expr(rhs))
        }
        MirExpr::Or { lhs, rhs } => {
            format!("({}) OR ({})", emit_bool_expr(lhs), emit_bool_expr(rhs))
        }
        MirExpr::Not { expr } => format!("NOT ({})", emit_bool_expr(expr)),
        MirExpr::Eq { lhs, rhs } => {
            format!("({} = {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::Ne { lhs, rhs } => {
            format!("({} <> {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::Lt { lhs, rhs } => {
            format!("({} < {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::Gt { lhs, rhs } => {
            format!("({} > {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::Le { lhs, rhs } => {
            format!("({} <= {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::Ge { lhs, rhs } => {
            format!("({} >= {})", emit_value_expr(lhs), emit_value_expr(rhs))
        }
        MirExpr::In { lhs, rhs } => {
            let items = rhs
                .iter()
                .map(emit_value_expr)
                .collect::<Vec<_>>()
                .join(", ");
            format!("({} IN [{}])", emit_value_expr(lhs), items)
        }
        MirExpr::StartsWith { lhs, rhs } => {
            format!(
                "({} STARTS WITH {})",
                emit_value_expr(lhs),
                emit_value_expr(rhs)
            )
        }
        MirExpr::EndsWith { lhs, rhs } => {
            format!(
                "({} ENDS WITH {})",
                emit_value_expr(lhs),
                emit_value_expr(rhs)
            )
        }
        MirExpr::Contains { lhs, rhs } => {
            format!(
                "({} CONTAINS {})",
                emit_value_expr(lhs),
                emit_value_expr(rhs)
            )
        }
        MirExpr::Unsupported { .. } => "true".to_string(),
        _ => format!("({})", emit_value_expr(expr)),
    }
}

fn emit_value_expr(expr: &MirExpr) -> String {
    match expr {
        MirExpr::Str(s) => quote_cypher_str(s),
        MirExpr::Int(n) => n.to_string(),
        MirExpr::Float(n) => n.to_string(),
        MirExpr::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        MirExpr::Null => "null".to_string(),
        MirExpr::Field { path } => emit_field_path(path),
        MirExpr::List(items) => {
            let items = items
                .iter()
                .map(emit_value_expr)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{items}]")
        }
        MirExpr::And { .. }
        | MirExpr::Or { .. }
        | MirExpr::Not { .. }
        | MirExpr::Eq { .. }
        | MirExpr::Ne { .. }
        | MirExpr::Lt { .. }
        | MirExpr::Gt { .. }
        | MirExpr::Le { .. }
        | MirExpr::Ge { .. }
        | MirExpr::In { .. }
        | MirExpr::StartsWith { .. }
        | MirExpr::EndsWith { .. }
        | MirExpr::Contains { .. } => format!("({})", emit_bool_expr(expr)),
        MirExpr::Unsupported { .. } => "null".to_string(),
    }
}

fn emit_field_path(path: &str) -> String {
    format!("e.{}", path.replace('.', "_"))
}

fn quote_cypher_str(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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
    use crate::lexer::Lexer;
    use crate::mid::lower_program;
    use crate::parser::Parser;
    use crate::{compile, CompilerConfig};

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
        let cypher = emit_cypher_program(&mir);
        assert_eq!(cypher.artifacts.len(), 2);
        assert!(cypher.artifacts[0].trigger_name.contains("oilc_r1_trigger"));
    }

    #[test]
    fn compile_pipeline_produces_cypher_codegen_output() {
        let src = r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  respond alert high
}
"#;
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        assert_eq!(codegen.cypher.artifacts.len(), 1);
    }

    #[test]
    fn snapshot_tmp_exec_rule_cypher_output() {
        let src = include_str!("../rules/stress_test/tmp_exec.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        let artifact = codegen
            .cypher
            .artifacts
            .first()
            .expect("cypher artifact for tmp_exec");

        assert_eq!(artifact.rule_name, "tmp_exec");
        assert_eq!(artifact.trigger_name, "oilc_tmp_exec_trigger");
        assert!(
            artifact
                .cypher
                .contains("CREATE TRIGGER oilc_tmp_exec_trigger"),
            "snapshot mismatch (trigger header): {}",
            artifact.cypher
        );
        assert!(
            artifact.cypher.contains("MATCH (e:Event)"),
            "snapshot mismatch (match clause): {}",
            artifact.cypher
        );
        assert!(
            artifact
                .cypher
                .contains("WHERE (e.p_binary_path STARTS WITH '/tmp')"),
            "snapshot mismatch (where clause): {}",
            artifact.cypher
        );
        assert!(
            artifact.cypher.trim_end().ends_with("RETURN e;"),
            "snapshot mismatch (return clause): {}",
            artifact.cypher
        );
    }

    #[test]
    fn snapshot_showcase_rule_cypher_output() {
        let src = include_str!("../rules/showcase.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let codegen = out.codegen.expect("codegen output");
        let artifact = codegen
            .cypher
            .artifacts
            .first()
            .expect("cypher artifact for showcase");

        assert_eq!(
            artifact.rule_name,
            "container_shell_credential_access_and_egress"
        );
        assert_eq!(
            artifact.trigger_name,
            "oilc_container_shell_credential_access_and_egress_trigger"
        );
        assert!(
            artifact.cypher.contains(
                "CREATE TRIGGER oilc_container_shell_credential_access_and_egress_trigger"
            ),
            "snapshot mismatch (trigger header): {}",
            artifact.cypher
        );
        assert!(
            artifact.cypher.contains("WHERE ("),
            "snapshot mismatch (where clause shape): {}",
            artifact.cypher
        );
        assert!(
            artifact.cypher.contains("e.p_name"),
            "snapshot mismatch (predicate path): {}",
            artifact.cypher
        );
    }

    #[test]
    fn generated_cypher_does_not_use_debug_ast_rendering() {
        let src = include_str!("../rules/showcase.oil");
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let artifact = out
            .codegen
            .expect("codegen")
            .cypher
            .artifacts
            .into_iter()
            .next()
            .expect("artifact");
        assert!(
            !artifact.cypher.contains("Spanned {"),
            "cypher output should not include debug AST nodes: {}",
            artifact.cypher
        );
        assert!(
            !artifact.cypher.contains("Path(["),
            "cypher output should not include debug path dumps: {}",
            artifact.cypher
        );
    }
}
