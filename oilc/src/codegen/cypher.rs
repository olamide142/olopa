use crate::ast::{ArithOp, CmpOp, Expr};
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
                "({}) AND ({})",
                emit_bool_expr(&lhs.node),
                emit_bool_expr(&rhs.node)
            )
        }
        Expr::Or(lhs, rhs) => {
            format!(
                "({}) OR ({})",
                emit_bool_expr(&lhs.node),
                emit_bool_expr(&rhs.node)
            )
        }
        Expr::Not(inner) => format!("NOT ({})", emit_bool_expr(&inner.node)),
        Expr::Cmp { op, lhs, rhs } => {
            let op = match op {
                CmpOp::Eq => "=",
                CmpOp::Ne => "<>",
                CmpOp::Lt => "<",
                CmpOp::Gt => ">",
                CmpOp::Le => "<=",
                CmpOp::Ge => ">=",
            };
            format!(
                "({} {} {})",
                emit_value_expr(&lhs.node),
                op,
                emit_value_expr(&rhs.node)
            )
        }
        Expr::In { lhs, rhs } => {
            format!(
                "({} IN {})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::NotIn { lhs, rhs } => {
            format!(
                "(NOT ({} IN {}))",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::StartsWith { lhs, rhs } => {
            format!(
                "({} STARTS WITH {})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::EndsWith { lhs, rhs } => {
            format!(
                "({} ENDS WITH {})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::Contains { lhs, rhs } => {
            format!(
                "({} CONTAINS {})",
                emit_value_expr(&lhs.node),
                emit_value_expr(&rhs.node)
            )
        }
        Expr::Matches { lhs, pattern } => {
            format!(
                "({} =~ {})",
                emit_value_expr(&lhs.node),
                quote_cypher_str(pattern)
            )
        }
        Expr::Under { path, prefix } => {
            format!(
                "({} STARTS WITH {})",
                emit_value_expr(&path.node),
                emit_value_expr(&prefix.node)
            )
        }
        Expr::Between { val, lo, hi } => {
            format!(
                "({} >= {} AND {} <= {})",
                emit_value_expr(&val.node),
                emit_value_expr(&lo.node),
                emit_value_expr(&val.node),
                emit_value_expr(&hi.node)
            )
        }
        Expr::Rare(inner)
        | Expr::Count(inner)
        | Expr::Max(inner)
        | Expr::Min(inner)
        | Expr::Sum(inner)
        | Expr::Avg(inner)
        | Expr::Distinct(inner)
        | Expr::UnaryMinus(inner) => emit_bool_expr(&inner.node),
        // For non-boolean expressions in predicate slots, fall back to true.
        _ => "true".to_string(),
    }
}

fn emit_value_expr(expr: &Expr) -> String {
    match expr {
        Expr::StrLit(s) => quote_cypher_str(s),
        Expr::IntLit(n) => n.to_string(),
        Expr::FloatLit(n) => n.to_string(),
        Expr::BoolLit(v) => {
            if *v { "true".to_string() } else { "false".to_string() }
        }
        Expr::Null => "null".to_string(),
        Expr::Path(parts) => format!("e.{}", parts.join("_")),
        Expr::Ident(name) => format!("e.{name}"),
        Expr::List(items) => {
            let items = items
                .iter()
                .map(|i| emit_value_expr(&i.node))
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{items}]")
        }
        Expr::Member { base, field } => format!("{}.{}", emit_value_expr(&base.node), field),
        Expr::Call { .. } => "null".to_string(),
        Expr::BinOp { op, lhs, rhs } => {
            let op = match op {
                ArithOp::Add => "+",
                ArithOp::Sub => "-",
                ArithOp::Mul => "*",
                ArithOp::Div => "/",
            };
            format!("({} {} {})", emit_value_expr(&lhs.node), op, emit_value_expr(&rhs.node))
        }
        Expr::DurationLit(d) => d.value.to_string(),
        Expr::UnaryMinus(inner) => format!("(-{})", emit_value_expr(&inner.node)),
        Expr::UnusualFor { val, .. } => emit_value_expr(&val.node),
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
        | Expr::Rare(_)
        | Expr::Count(_)
        | Expr::Max(_)
        | Expr::Min(_)
        | Expr::Sum(_)
        | Expr::Avg(_)
        | Expr::Distinct(_) => format!("({})", emit_bool_expr(expr)),
    }
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
            artifact.cypher.contains("WHERE (e.p_binary_path STARTS WITH '/tmp')"),
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

        assert_eq!(artifact.rule_name, "container_shell_credential_access_and_egress");
        assert_eq!(
            artifact.trigger_name,
            "oilc_container_shell_credential_access_and_egress_trigger"
        );
        assert!(
            artifact
                .cypher
                .contains("CREATE TRIGGER oilc_container_shell_credential_access_and_egress_trigger"),
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
