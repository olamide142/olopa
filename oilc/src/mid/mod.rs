use crate::ast::{
    ActionStmt, CorrelateJoin, Expr, OilDuration, Program, RuleBody, RuleDecl, SourceSpec,
};
use std::collections::HashSet;

/// MIR (mid-level IR) root.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MirProgram {
    pub rules: Vec<MirRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MirRuleId(pub String);

#[derive(Debug, Clone, PartialEq)]
pub struct MirRule {
    pub id: MirRuleId,
    pub name: String,
    pub class: RuleClass,
    pub sources: Vec<MirSource>,
    pub predicates: Vec<MirPredicate>,
    pub joins: Vec<MirJoin>,
    pub window: Option<OilDuration>,
    pub require: Vec<MirRequire>,
    pub lets: Vec<MirLet>,
    pub score: MirScore,
    pub verify: Vec<MirVerify>,
    pub emit: Vec<MirEmit>,
    pub respond: MirRespondPlan,
}

/// Execution class used by later planning/codegen stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleClass {
    HotPath,
    Temporal,
    Graph,
    Around,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirSource {
    pub domain: String,
    pub event: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirPredicate {
    pub expr: MirExpr,
    pub cost: PredicateCost,
    pub nullable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateCost {
    Constant,
    FieldLookup,
    StringOp,
    SetLookup,
    GraphLookup,
    ExternalCall,
    MlInference,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirJoin {
    pub left_alias: String,
    pub right_alias: String,
    pub on: Option<MirExpr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirRequire {
    pub expr: MirExpr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirLet {
    pub name: String,
    pub value: MirExpr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirScore {
    pub base: i32,
    pub modifiers: Vec<MirScoreModifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirScoreModifier {
    pub delta: i32,
    pub condition: Option<MirExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirVerify {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirEmit {
    pub fact_name: String,
    pub args: Vec<MirExpr>,
    pub expires: Option<OilDuration>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MirRespondPlan {
    pub branches: Vec<MirBranch>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MirBranch {
    pub condition: Option<MirExpr>,
    pub actions: Vec<MirAction>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MirAction {
    Raw(ActionStmt),
}

/// Expression carrier for MIR phase-1.
///
/// Stage 3.1 focuses on defining the data model; later lowering passes can
/// split this into richer low-level op variants.
#[derive(Debug, Clone, PartialEq)]
pub enum MirExpr {
    Raw(Expr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirValidationSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirValidationKind {
    RuleIdDuplicate,
    RuleNameEmpty,
    SourceMalformed,
    JoinMalformed,
    RespondMalformed,
    EmitMalformed,
    VerifyMalformed,
    ScoreOutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirValidationDiagnostic {
    pub kind: MirValidationKind,
    pub severity: MirValidationSeverity,
    pub rule: Option<String>,
    pub message: String,
}

pub fn classify_rule(rule: &RuleDecl) -> RuleClass {
    match &rule.body.node {
        RuleBody::Match(m) if m.steps.len() <= 1 => RuleClass::HotPath,
        RuleBody::Match(_) | RuleBody::Correlate(_) => RuleClass::Temporal,
        RuleBody::Graph(_) => RuleClass::Graph,
        RuleBody::Around(_) => RuleClass::Around,
    }
}

/// Build MIR from AST.
///
/// This stage performs structural lowering only (no optimization/rewrite).
pub fn lower_program(program: &Program) -> MirProgram {
    let mut rules = Vec::with_capacity(program.rules.len());
    for (idx, rule) in program.rules.iter().enumerate() {
        rules.push(lower_rule(rule, idx));
    }
    MirProgram { rules }
}

/// Backward-compatible alias while downstream code migrates.
pub fn define_mir_skeleton(program: &Program) -> MirProgram {
    lower_program(program)
}

pub fn validate_program(program: &MirProgram) -> Vec<MirValidationDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut seen_rule_ids: HashSet<&str> = HashSet::new();

    for rule in &program.rules {
        let rule_name = Some(rule.name.clone());
        if rule.id.0.trim().is_empty() {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RuleNameEmpty,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR rule id must not be empty".to_string(),
            });
        } else if !seen_rule_ids.insert(rule.id.0.as_str()) {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RuleIdDuplicate,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: format!("duplicate MIR rule id '{}'", rule.id.0),
            });
        }

        if rule.name.trim().is_empty() {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RuleNameEmpty,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR rule name must not be empty".to_string(),
            });
        }

        for src in &rule.sources {
            if src.domain.trim().is_empty() || src.event.trim().is_empty() {
                diagnostics.push(MirValidationDiagnostic {
                    kind: MirValidationKind::SourceMalformed,
                    severity: MirValidationSeverity::Error,
                    rule: rule_name.clone(),
                    message: "MIR source must have non-empty domain and event".to_string(),
                });
            }
        }

        for join in &rule.joins {
            if join.left_alias.trim().is_empty() || join.right_alias.trim().is_empty() {
                diagnostics.push(MirValidationDiagnostic {
                    kind: MirValidationKind::JoinMalformed,
                    severity: MirValidationSeverity::Error,
                    rule: rule_name.clone(),
                    message: "MIR join aliases must be non-empty".to_string(),
                });
            }
            if join.left_alias == join.right_alias {
                diagnostics.push(MirValidationDiagnostic {
                    kind: MirValidationKind::JoinMalformed,
                    severity: MirValidationSeverity::Error,
                    rule: rule_name.clone(),
                    message: format!(
                        "MIR join aliases must differ (got '{}')",
                        join.left_alias
                    ),
                });
            }
        }

        if rule.respond.branches.is_empty() {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RespondMalformed,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR respond plan must contain at least one branch".to_string(),
            });
        } else if rule
            .respond
            .branches
            .iter()
            .any(|b| b.actions.is_empty())
        {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RespondMalformed,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR respond branches must contain at least one action".to_string(),
            });
        }

        for emit in &rule.emit {
            if emit.fact_name.trim().is_empty() {
                diagnostics.push(MirValidationDiagnostic {
                    kind: MirValidationKind::EmitMalformed,
                    severity: MirValidationSeverity::Error,
                    rule: rule_name.clone(),
                    message: "MIR emit fact name must not be empty".to_string(),
                });
            }
        }

        for verify in &rule.verify {
            if verify.path.trim().is_empty() {
                diagnostics.push(MirValidationDiagnostic {
                    kind: MirValidationKind::VerifyMalformed,
                    severity: MirValidationSeverity::Error,
                    rule: rule_name.clone(),
                    message: "MIR verify path must not be empty".to_string(),
                });
            }
        }

        if !(0..=100).contains(&rule.score.base) {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::ScoreOutOfRange,
                severity: MirValidationSeverity::Warning,
                rule: rule_name,
                message: format!(
                    "MIR score base {} is outside recommended range [0, 100]",
                    rule.score.base
                ),
            });
        }
    }

    diagnostics
}

fn lower_rule(rule: &RuleDecl, idx: usize) -> MirRule {
    let (joins, window) = lower_body(&rule.body.node, rule.within.as_ref().map(|w| w.node));
    MirRule {
        id: MirRuleId(format!("rule:{idx}:{}", rule.name.node)),
        name: rule.name.node.clone(),
        class: classify_rule(rule),
        sources: rule.sources.iter().map(lower_source).collect(),
        predicates: rule
            .where_
            .as_ref()
            .map(|w| {
                vec![MirPredicate {
                    expr: MirExpr::Raw(w.node.clone()),
                    cost: PredicateCost::FieldLookup,
                    nullable: false,
                }]
            })
            .unwrap_or_default(),
        joins,
        window,
        require: rule
            .require
            .as_ref()
            .map(|r| {
                r.node
                    .requirements
                    .iter()
                    .map(|req| MirRequire {
                        expr: MirExpr::Raw(req.node.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        lets: rule
            .lets
            .iter()
            .map(|b| MirLet {
                name: b.name.node.clone(),
                value: MirExpr::Raw(b.value.node.clone()),
            })
            .collect(),
        score: rule
            .score
            .as_ref()
            .map(|s| MirScore {
                base: s.node.base.node,
                modifiers: s
                    .node
                    .modifiers
                    .iter()
                    .map(|m| MirScoreModifier {
                        delta: m.delta,
                        condition: m.condition.as_ref().map(|c| MirExpr::Raw(c.node.clone())),
                    })
                    .collect(),
            })
            .unwrap_or(MirScore {
                base: 0,
                modifiers: Vec::new(),
            }),
        verify: rule
            .verify
            .as_ref()
            .map(|v| {
                v.requirements
                    .iter()
                    .map(|r| MirVerify {
                        path: r.node.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        emit: rule
            .emit
            .iter()
            .map(|e| MirEmit {
                fact_name: e.fact_name.node.clone(),
                args: e.args.iter().map(|a| MirExpr::Raw(a.node.clone())).collect(),
                expires: e.expires.as_ref().map(|x| x.node),
            })
            .collect(),
        respond: MirRespondPlan {
            branches: rule
                .respond
                .node
                .arms
                .iter()
                .map(|arm| MirBranch {
                    condition: arm.condition.as_ref().map(|c| MirExpr::Raw(c.node.clone())),
                    actions: arm
                        .actions
                        .iter()
                        .map(|a| MirAction::Raw(a.node.clone()))
                        .collect(),
                })
                .collect(),
        },
    }
}

fn lower_body(body: &RuleBody, within: Option<OilDuration>) -> (Vec<MirJoin>, Option<OilDuration>) {
    match body {
        RuleBody::Correlate(c) => {
            let mut joins = Vec::new();
            if c.arms.len() >= 2 {
                for idx in 1..c.arms.len() {
                    let left = &c.arms[idx - 1];
                    let right = &c.arms[idx];
                    let on = match &right.join {
                        CorrelateJoin::OnPredicate(expr) => Some(MirExpr::Raw(expr.node.clone())),
                        CorrelateJoin::ByVariable(v) => Some(MirExpr::Raw(Expr::Ident(v.node.clone()))),
                        CorrelateJoin::None => None,
                    };
                    joins.push(MirJoin {
                        left_alias: left.alias.node.clone(),
                        right_alias: right.alias.node.clone(),
                        on,
                    });
                }
            }
            (joins, within)
        }
        RuleBody::Match(m) => {
            let mut joins = Vec::new();
            if m.steps.len() >= 2 {
                for idx in 1..m.steps.len() {
                    let Some(right_alias) = m.steps[idx].alias.as_ref().map(|a| a.node.clone()) else {
                        continue;
                    };
                    let Some(left_alias) = m.steps[idx - 1]
                        .alias
                        .as_ref()
                        .map(|a| a.node.clone())
                    else {
                        continue;
                    };
                    let on = m.steps[idx]
                        .by
                        .as_ref()
                        .map(|b| MirExpr::Raw(Expr::Ident(b.node.clone())));
                    joins.push(MirJoin {
                        left_alias,
                        right_alias,
                        on,
                    });
                }
            }
            (joins, within)
        }
        RuleBody::Around(a) => (Vec::new(), Some(a.window.node)),
        RuleBody::Graph(_) => (Vec::new(), within),
    }
}

fn lower_source(src: &SourceSpec) -> MirSource {
    MirSource {
        domain: src.domain.clone(),
        event: src.event.clone(),
        alias: src.alias.as_ref().map(|a| a.node.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn parse_program(src: &str) -> Program {
        let toks = Lexer::new(src).tokenize().expect("lex");
        let mut p = Parser::new(toks);
        p.parse().expect("parse")
    }

    #[test]
    fn classify_single_step_match_as_hot_path() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  match process.spawn as p
  where p.name == "bash"
  respond alert high
}
"#,
        );
        let class = classify_rule(&program.rules[0]);
        assert_eq!(class, RuleClass::HotPath);
    }

    #[test]
    fn define_skeleton_preserves_clause_shapes() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  require score >= 50
  verify require p.hash
  emit fact host.signal(host.id) expires 1h
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        assert_eq!(mir.rules.len(), 1);
        let r = &mir.rules[0];
        assert_eq!(r.require.len(), 1);
        assert_eq!(r.verify.len(), 1);
        assert_eq!(r.emit.len(), 1);
        assert_eq!(r.respond.branches.len(), 1);
    }

    #[test]
    fn lower_correlate_builds_joins() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process, network.flow
  correlate
    process.spawn as p
    with network.connect as n on n.process_id == p.id
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let r = &mir.rules[0];
        assert_eq!(r.joins.len(), 1);
        assert_eq!(r.joins[0].left_alias, "p");
        assert_eq!(r.joins[0].right_alias, "n");
        assert!(r.joins[0].on.is_some());
    }

    #[test]
    fn lower_around_uses_body_window() {
        let rule = RuleDecl {
            meta: None,
            name: crate::ast::Spanned::new("a".to_string(), 0..1),
            sources: vec![],
            body: crate::ast::Spanned::new(
                RuleBody::Around(crate::ast::AroundBlock {
                    entity: crate::ast::Spanned::new("host".to_string(), 0..1),
                    window: crate::ast::Spanned::new(
                        OilDuration {
                            value: 5,
                            unit: crate::ast::DurationUnit::M,
                        },
                        0..1,
                    ),
                    arms: vec![],
                }),
                0..1,
            ),
            where_: None,
            within: None,
            require: None,
            lets: vec![],
            score: None,
            verify: None,
            emit: vec![],
            respond: crate::ast::Spanned::new(
                crate::ast::RespondBlock { arms: vec![] },
                0..1,
            ),
        };
        let program = Program {
            rules: vec![rule],
            ..Program::default()
        };
        let mir = lower_program(&program);
        assert_eq!(mir.rules[0].window.unwrap().value, 5);
    }

    #[test]
    fn validate_program_accepts_lowered_rule() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let diagnostics = validate_program(&mir);
        assert!(
            diagnostics.is_empty(),
            "did not expect MIR validation diagnostics, got: {:?}",
            diagnostics
        );
    }

    #[test]
    fn validate_program_reports_structural_errors() {
        let bad = MirProgram {
            rules: vec![MirRule {
                id: MirRuleId("".to_string()),
                name: "".to_string(),
                class: RuleClass::Temporal,
                sources: vec![MirSource {
                    domain: "".to_string(),
                    event: "process".to_string(),
                    alias: Some("p".to_string()),
                }],
                predicates: vec![],
                joins: vec![MirJoin {
                    left_alias: "p".to_string(),
                    right_alias: "p".to_string(),
                    on: None,
                }],
                window: None,
                require: vec![],
                lets: vec![],
                score: MirScore {
                    base: -1,
                    modifiers: vec![],
                },
                verify: vec![MirVerify {
                    path: "".to_string(),
                }],
                emit: vec![MirEmit {
                    fact_name: "".to_string(),
                    args: vec![],
                    expires: None,
                }],
                respond: MirRespondPlan {
                    branches: vec![MirBranch {
                        condition: None,
                        actions: vec![],
                    }],
                },
            }],
        };

        let diagnostics = validate_program(&bad);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.kind == MirValidationKind::RuleNameEmpty),
            "expected rule-name/id diagnostics, got: {:?}",
            diagnostics
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.kind == MirValidationKind::RespondMalformed),
            "expected respond diagnostics, got: {:?}",
            diagnostics
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.kind == MirValidationKind::ScoreOutOfRange),
            "expected score-range warning, got: {:?}",
            diagnostics
        );
    }
}
