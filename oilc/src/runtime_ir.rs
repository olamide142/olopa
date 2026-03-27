use serde::{Deserialize, Serialize};

use crate::ast::Expr;
use crate::mid::{MirExpr, MirProgram};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeProgram {
    pub version: u32,
    pub rules: Vec<RuntimeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRule {
    pub id: String,
    pub name: String,
    pub predicates: Vec<RuntimeExpr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuntimeExpr {
    Bool { value: bool },
    Int { value: i64 },
    Float { value: f64 },
    Str { value: String },
    Field { path: String },
    And { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Or { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Not { expr: Box<RuntimeExpr> },
    Eq { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Ne { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Lt { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Gt { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Le { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Ge { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    In { lhs: Box<RuntimeExpr>, rhs: Vec<RuntimeExpr> },
    StartsWith { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    EndsWith { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Contains { lhs: Box<RuntimeExpr>, rhs: Box<RuntimeExpr> },
    Unsupported { kind: String },
}

pub fn lower_runtime_program(mir: &MirProgram) -> RuntimeProgram {
    RuntimeProgram {
        version: 1,
        rules: mir
            .rules
            .iter()
            .map(|rule| RuntimeRule {
                id: rule.id.0.clone(),
                name: rule.name.clone(),
                predicates: rule
                    .predicates
                    .iter()
                    .map(|p| lower_mir_expr(&p.expr))
                    .collect(),
            })
            .collect(),
    }
}

fn lower_mir_expr(expr: &MirExpr) -> RuntimeExpr {
    match expr {
        MirExpr::Raw(ast) => lower_expr(ast),
    }
}

fn lower_expr(expr: &Expr) -> RuntimeExpr {
    match expr {
        Expr::BoolLit(value) => RuntimeExpr::Bool { value: *value },
        Expr::IntLit(value) => RuntimeExpr::Int { value: *value },
        Expr::FloatLit(value) => RuntimeExpr::Float { value: *value },
        Expr::StrLit(value) => RuntimeExpr::Str {
            value: value.clone(),
        },
        Expr::Path(parts) => RuntimeExpr::Field {
            path: parts.join("."),
        },
        Expr::Ident(name) => RuntimeExpr::Field { path: name.clone() },
        Expr::And(lhs, rhs) => RuntimeExpr::And {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Or(lhs, rhs) => RuntimeExpr::Or {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Not(inner) => RuntimeExpr::Not {
            expr: Box::new(lower_expr(&inner.node)),
        },
        Expr::Cmp { op, lhs, rhs } => {
            let lhs = Box::new(lower_expr(&lhs.node));
            let rhs = Box::new(lower_expr(&rhs.node));
            match op {
                crate::ast::CmpOp::Eq => RuntimeExpr::Eq { lhs, rhs },
                crate::ast::CmpOp::Ne => RuntimeExpr::Ne { lhs, rhs },
                crate::ast::CmpOp::Lt => RuntimeExpr::Lt { lhs, rhs },
                crate::ast::CmpOp::Gt => RuntimeExpr::Gt { lhs, rhs },
                crate::ast::CmpOp::Le => RuntimeExpr::Le { lhs, rhs },
                crate::ast::CmpOp::Ge => RuntimeExpr::Ge { lhs, rhs },
            }
        }
        Expr::In { lhs, rhs } => {
            let rhs_items = if let Expr::List(items) = &rhs.node {
                items.iter().map(|item| lower_expr(&item.node)).collect()
            } else {
                vec![lower_expr(&rhs.node)]
            };
            RuntimeExpr::In {
                lhs: Box::new(lower_expr(&lhs.node)),
                rhs: rhs_items,
            }
        }
        Expr::NotIn { lhs, rhs } => RuntimeExpr::Not {
            expr: Box::new(RuntimeExpr::In {
                lhs: Box::new(lower_expr(&lhs.node)),
                rhs: if let Expr::List(items) = &rhs.node {
                    items.iter().map(|item| lower_expr(&item.node)).collect()
                } else {
                    vec![lower_expr(&rhs.node)]
                },
            }),
        },
        Expr::StartsWith { lhs, rhs } => RuntimeExpr::StartsWith {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::EndsWith { lhs, rhs } => RuntimeExpr::EndsWith {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Contains { lhs, rhs } => RuntimeExpr::Contains {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Under { path, prefix } => RuntimeExpr::StartsWith {
            lhs: Box::new(lower_expr(&path.node)),
            rhs: Box::new(lower_expr(&prefix.node)),
        },
        Expr::Between { val, lo, hi } => RuntimeExpr::And {
            lhs: Box::new(RuntimeExpr::Ge {
                lhs: Box::new(lower_expr(&val.node)),
                rhs: Box::new(lower_expr(&lo.node)),
            }),
            rhs: Box::new(RuntimeExpr::Le {
                lhs: Box::new(lower_expr(&val.node)),
                rhs: Box::new(lower_expr(&hi.node)),
            }),
        },
        other => RuntimeExpr::Unsupported {
            kind: format!("{other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::mid::lower_program;
    use crate::parser::Parser;

    #[test]
    fn lowers_rule_predicates_into_runtime_ir() {
        let src = r#"
rule "runtime_ir" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 1 and p.name starts_with "bash"
  respond alert high
}
"#;
        let tokens = Lexer::new(src).tokenize().expect("lex");
        let mut parser = Parser::new(tokens);
        let program = parser.parse().expect("parse");
        let mir = lower_program(&program);
        let runtime = lower_runtime_program(&mir);

        assert_eq!(runtime.version, 1);
        assert_eq!(runtime.rules.len(), 1);
        assert_eq!(runtime.rules[0].name, "runtime_ir");
        assert_eq!(runtime.rules[0].predicates.len(), 1);
    }
}
