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
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Null,
    Duration(OilDuration),
    Field {
        path: String,
    },
    Call {
        name: String,
        args: Vec<MirExpr>,
    },
    Add {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Sub {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Mul {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Div {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    List(Vec<MirExpr>),
    And {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Or {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Not {
        expr: Box<MirExpr>,
    },
    Eq {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Ne {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Lt {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Gt {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Le {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Ge {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    In {
        lhs: Box<MirExpr>,
        rhs: Vec<MirExpr>,
    },
    StartsWith {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    EndsWith {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Contains {
        lhs: Box<MirExpr>,
        rhs: Box<MirExpr>,
    },
    Matches {
        lhs: Box<MirExpr>,
        pattern: String,
    },
    Unsupported {
        kind: String,
    },
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
    UnsupportedExpression,
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

/// Run structural sanity checks on lowered MIR before runtime IR emission.
///
/// The goal here is to catch malformed compiler output early with actionable,
/// per-rule diagnostics, while keeping the checks fast and deterministic.
pub fn validate_program(program: &MirProgram) -> Vec<MirValidationDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut seen_rule_ids: HashSet<&str> = HashSet::new();

    for rule in &program.rules {
        let rule_name = Some(rule.name.clone());
        // Rule ids must exist and be unique so downstream artifacts can
        // reliably map detections/remediations back to source rules.
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

        // Human-readable names are required for operator-facing telemetry.
        if rule.name.trim().is_empty() {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RuleNameEmpty,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR rule name must not be empty".to_string(),
            });
        }

        // Source bindings must specify both event domain and event name.
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

        // Joins require two distinct aliases to avoid ambiguous/self joins.
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
                    message: format!("MIR join aliases must differ (got '{}')", join.left_alias),
                });
            }
        }

        // Respond plans must be executable: at least one branch and at least
        // one action per branch.
        if rule.respond.branches.is_empty() {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RespondMalformed,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR respond plan must contain at least one branch".to_string(),
            });
        } else if rule.respond.branches.iter().any(|b| b.actions.is_empty()) {
            diagnostics.push(MirValidationDiagnostic {
                kind: MirValidationKind::RespondMalformed,
                severity: MirValidationSeverity::Error,
                rule: rule_name.clone(),
                message: "MIR respond branches must contain at least one action".to_string(),
            });
        }

        // Emitted fact names are part of the runtime contract; empty names are
        // treated as malformed output.
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

        // Verify paths must be non-empty to avoid silent "no-op verify" blocks.
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

        // Keep score range as a warning (not error) to preserve flexibility for
        // experiments while still flagging suspicious values.
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

        // Hard gate: unsupported MIR expressions must not flow into runtime IR.
        for (idx, pred) in rule.predicates.iter().enumerate() {
            validate_expr_unsupported(
                &pred.expr,
                &format!("predicate[{idx}]"),
                &rule.name,
                &mut diagnostics,
            );
        }
        for (idx, join) in rule.joins.iter().enumerate() {
            if let Some(on) = &join.on {
                validate_expr_unsupported(
                    on,
                    &format!("join[{idx}].on"),
                    &rule.name,
                    &mut diagnostics,
                );
            }
        }
        for (idx, req) in rule.require.iter().enumerate() {
            validate_expr_unsupported(
                &req.expr,
                &format!("require[{idx}]"),
                &rule.name,
                &mut diagnostics,
            );
        }
        for (idx, binding) in rule.lets.iter().enumerate() {
            validate_expr_unsupported(
                &binding.value,
                &format!("let[{idx}].value"),
                &rule.name,
                &mut diagnostics,
            );
        }
        for (idx, modifier) in rule.score.modifiers.iter().enumerate() {
            if let Some(cond) = &modifier.condition {
                validate_expr_unsupported(
                    cond,
                    &format!("score.modifier[{idx}].condition"),
                    &rule.name,
                    &mut diagnostics,
                );
            }
        }
        for (emit_idx, emit) in rule.emit.iter().enumerate() {
            for (arg_idx, arg) in emit.args.iter().enumerate() {
                validate_expr_unsupported(
                    arg,
                    &format!("emit[{emit_idx}].arg[{arg_idx}]"),
                    &rule.name,
                    &mut diagnostics,
                );
            }
        }
        for (branch_idx, branch) in rule.respond.branches.iter().enumerate() {
            if let Some(cond) = &branch.condition {
                validate_expr_unsupported(
                    cond,
                    &format!("respond.branch[{branch_idx}].condition"),
                    &rule.name,
                    &mut diagnostics,
                );
            }
        }
    }

    diagnostics
}

fn validate_expr_unsupported(
    expr: &MirExpr,
    path: &str,
    rule_name: &str,
    diagnostics: &mut Vec<MirValidationDiagnostic>,
) {
    match expr {
        MirExpr::Unsupported { kind } => diagnostics.push(MirValidationDiagnostic {
            kind: MirValidationKind::UnsupportedExpression,
            severity: MirValidationSeverity::Error,
            rule: Some(rule_name.to_string()),
            message: format!("unsupported expression in {path}: {kind}"),
        }),
        MirExpr::List(items) => {
            for (idx, item) in items.iter().enumerate() {
                validate_expr_unsupported(
                    item,
                    &format!("{path}.list_item[{idx}]"),
                    rule_name,
                    diagnostics,
                );
            }
        }
        MirExpr::And { lhs, rhs }
        | MirExpr::Or { lhs, rhs }
        | MirExpr::Eq { lhs, rhs }
        | MirExpr::Ne { lhs, rhs }
        | MirExpr::Lt { lhs, rhs }
        | MirExpr::Gt { lhs, rhs }
        | MirExpr::Le { lhs, rhs }
        | MirExpr::Ge { lhs, rhs }
        | MirExpr::Add { lhs, rhs }
        | MirExpr::Sub { lhs, rhs }
        | MirExpr::Mul { lhs, rhs }
        | MirExpr::Div { lhs, rhs }
        | MirExpr::StartsWith { lhs, rhs }
        | MirExpr::EndsWith { lhs, rhs }
        | MirExpr::Contains { lhs, rhs } => {
            validate_expr_unsupported(lhs, &format!("{path}.lhs"), rule_name, diagnostics);
            validate_expr_unsupported(rhs, &format!("{path}.rhs"), rule_name, diagnostics);
        }
        MirExpr::Not { expr } => {
            validate_expr_unsupported(expr, &format!("{path}.expr"), rule_name, diagnostics);
        }
        MirExpr::In { lhs, rhs } => {
            validate_expr_unsupported(lhs, &format!("{path}.lhs"), rule_name, diagnostics);
            for (idx, item) in rhs.iter().enumerate() {
                validate_expr_unsupported(
                    item,
                    &format!("{path}.rhs[{idx}]"),
                    rule_name,
                    diagnostics,
                );
            }
        }
        MirExpr::Call { name: _, args } => {
            for (idx, arg) in args.iter().enumerate() {
                validate_expr_unsupported(
                    arg,
                    &format!("{path}.arg[{idx}]"),
                    rule_name,
                    diagnostics,
                );
            }
        }
        MirExpr::Matches { lhs, pattern: _ } => {
            validate_expr_unsupported(lhs, &format!("{path}.lhs"), rule_name, diagnostics);
        }
        MirExpr::Bool(_)
        | MirExpr::Int(_)
        | MirExpr::Float(_)
        | MirExpr::Str(_)
        | MirExpr::Null
        | MirExpr::Duration(_)
        | MirExpr::Field { .. } => {}
    }
}

fn lower_rule(rule: &RuleDecl, idx: usize) -> MirRule {
    let (joins, window) = lower_body(&rule.body.node, rule.within.as_ref().map(|w| w.node));
    MirRule {
        id: MirRuleId(format!("rule:{idx}:{}", rule.name.node)),
        name: rule.name.node.clone(),
        class: classify_rule(rule),
        sources: lower_rule_sources(rule),
        predicates: rule
            .where_
            .as_ref()
            .map(|w| {
                vec![MirPredicate {
                    expr: lower_expr(&w.node),
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
                        expr: lower_expr(&req.node),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        lets: rule
            .lets
            .iter()
            .map(|b| MirLet {
                name: b.name.node.clone(),
                value: lower_expr(&b.value.node),
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
                        condition: m.condition.as_ref().map(|c| lower_expr(&c.node)),
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
                args: e.args.iter().map(|a| lower_expr(&a.node)).collect(),
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
                    condition: arm.condition.as_ref().map(|c| lower_expr(&c.node)),
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
                        CorrelateJoin::OnPredicate(expr) => Some(lower_expr(&expr.node)),
                        CorrelateJoin::ByVariable(v) => Some(MirExpr::Field {
                            path: v.node.clone(),
                        }),
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
                    let Some(right_alias) = m.steps[idx].alias.as_ref().map(|a| a.node.clone())
                    else {
                        continue;
                    };
                    let Some(left_alias) = m.steps[idx - 1].alias.as_ref().map(|a| a.node.clone())
                    else {
                        continue;
                    };
                    let on = m.steps[idx].by.as_ref().map(|b| MirExpr::Field {
                        path: b.node.clone(),
                    });
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

fn lower_rule_sources(rule: &RuleDecl) -> Vec<MirSource> {
    if !rule.sources.is_empty() {
        return rule.sources.iter().map(lower_source).collect();
    }

    match &rule.body.node {
        RuleBody::Match(m) => m
            .steps
            .iter()
            .map(|step| MirSource {
                domain: step.event.node.domain.clone(),
                event: step.event.node.kind.clone(),
                alias: step.alias.as_ref().map(|a| a.node.clone()),
            })
            .collect(),
        RuleBody::Correlate(c) => c
            .arms
            .iter()
            .map(|arm| MirSource {
                domain: arm.event.node.domain.clone(),
                event: arm.event.node.kind.clone(),
                alias: Some(arm.alias.node.clone()),
            })
            .collect(),
        RuleBody::Around(a) => a
            .arms
            .iter()
            .map(|arm| MirSource {
                domain: arm.event.node.domain.clone(),
                event: arm.event.node.kind.clone(),
                alias: Some(arm.alias.node.clone()),
            })
            .collect(),
        RuleBody::Graph(g) => vec![lower_source(&g.source)],
    }
}

fn lower_expr(expr: &Expr) -> MirExpr {
    match expr {
        Expr::BoolLit(v) => MirExpr::Bool(*v),
        Expr::IntLit(v) => MirExpr::Int(*v),
        Expr::FloatLit(v) => MirExpr::Float(*v),
        Expr::StrLit(v) => MirExpr::Str(v.clone()),
        Expr::Null => MirExpr::Null,
        Expr::DurationLit(v) => MirExpr::Duration(*v),
        Expr::Path(parts) => MirExpr::Field {
            path: parts.join("."),
        },
        Expr::Ident(name) => MirExpr::Field { path: name.clone() },
        Expr::Call { name, args } => MirExpr::Call {
            name: name.clone(),
            args: args.iter().map(|a| lower_expr(&a.node)).collect(),
        },
        Expr::Member { base, field } => match lower_expr(&base.node) {
            MirExpr::Field { path } => MirExpr::Field {
                path: format!("{path}.{field}"),
            },
            MirExpr::Call { name, args } if can_project_call_to_field(&name, &args) => {
                MirExpr::Field {
                    path: format!("{name}.{field}"),
                }
            }
            _ => MirExpr::Unsupported {
                kind: format!("{expr:?}"),
            },
        },
        Expr::List(items) => MirExpr::List(items.iter().map(|i| lower_expr(&i.node)).collect()),
        Expr::And(lhs, rhs) => MirExpr::And {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Or(lhs, rhs) => MirExpr::Or {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Not(inner) => MirExpr::Not {
            expr: Box::new(lower_expr(&inner.node)),
        },
        Expr::UnaryMinus(inner) => MirExpr::Sub {
            lhs: Box::new(MirExpr::Int(0)),
            rhs: Box::new(lower_expr(&inner.node)),
        },
        Expr::BinOp { op, lhs, rhs } => {
            let lhs = Box::new(lower_expr(&lhs.node));
            let rhs = Box::new(lower_expr(&rhs.node));
            match op {
                crate::ast::ArithOp::Add => MirExpr::Add { lhs, rhs },
                crate::ast::ArithOp::Sub => MirExpr::Sub { lhs, rhs },
                crate::ast::ArithOp::Mul => MirExpr::Mul { lhs, rhs },
                crate::ast::ArithOp::Div => MirExpr::Div { lhs, rhs },
            }
        }
        Expr::Cmp { op, lhs, rhs } => {
            let lhs = Box::new(lower_expr(&lhs.node));
            let rhs = Box::new(lower_expr(&rhs.node));
            match op {
                crate::ast::CmpOp::Eq => MirExpr::Eq { lhs, rhs },
                crate::ast::CmpOp::Ne => MirExpr::Ne { lhs, rhs },
                crate::ast::CmpOp::Lt => MirExpr::Lt { lhs, rhs },
                crate::ast::CmpOp::Gt => MirExpr::Gt { lhs, rhs },
                crate::ast::CmpOp::Le => MirExpr::Le { lhs, rhs },
                crate::ast::CmpOp::Ge => MirExpr::Ge { lhs, rhs },
            }
        }
        Expr::In { lhs, rhs } => {
            let rhs_items = if let MirExpr::List(items) = lower_expr(&rhs.node) {
                items
            } else {
                vec![lower_expr(&rhs.node)]
            };
            MirExpr::In {
                lhs: Box::new(lower_expr(&lhs.node)),
                rhs: rhs_items,
            }
        }
        Expr::NotIn { lhs, rhs } => {
            let rhs_items = if let MirExpr::List(items) = lower_expr(&rhs.node) {
                items
            } else {
                vec![lower_expr(&rhs.node)]
            };
            MirExpr::Not {
                expr: Box::new(MirExpr::In {
                    lhs: Box::new(lower_expr(&lhs.node)),
                    rhs: rhs_items,
                }),
            }
        }
        Expr::StartsWith { lhs, rhs } => MirExpr::StartsWith {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::EndsWith { lhs, rhs } => MirExpr::EndsWith {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Contains { lhs, rhs } => MirExpr::Contains {
            lhs: Box::new(lower_expr(&lhs.node)),
            rhs: Box::new(lower_expr(&rhs.node)),
        },
        Expr::Rare(inner) => MirExpr::Call {
            name: "rare".to_string(),
            args: vec![lower_expr(&inner.node)],
        },
        Expr::UnusualFor { val, entity } => MirExpr::Call {
            name: "unusual_for".to_string(),
            args: vec![lower_expr(&val.node), MirExpr::Str(entity.clone())],
        },
        Expr::Matches { lhs, pattern } => MirExpr::Matches {
            lhs: Box::new(lower_expr(&lhs.node)),
            pattern: pattern.clone(),
        },
        Expr::Under { path, prefix } => MirExpr::StartsWith {
            lhs: Box::new(lower_expr(&path.node)),
            rhs: Box::new(lower_expr(&prefix.node)),
        },
        Expr::Between { val, lo, hi } => {
            let val_expr = lower_expr(&val.node);
            MirExpr::And {
                lhs: Box::new(MirExpr::Ge {
                    lhs: Box::new(val_expr.clone()),
                    rhs: Box::new(lower_expr(&lo.node)),
                }),
                rhs: Box::new(MirExpr::Le {
                    lhs: Box::new(val_expr),
                    rhs: Box::new(lower_expr(&hi.node)),
                }),
            }
        }
        other => MirExpr::Unsupported {
            kind: format!("{other:?}"),
        },
    }
}

fn can_project_call_to_field(name: &str, _args: &[MirExpr]) -> bool {
    !name.trim().is_empty()
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
    fn lower_matches_expression_into_typed_mir() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where p.name matches "ba*"
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let expr = &mir.rules[0].predicates[0].expr;
        match expr {
            MirExpr::Matches { lhs, pattern } => {
                assert!(matches!(lhs.as_ref(), MirExpr::Field { .. }));
                assert_eq!(pattern, "ba*");
            }
            other => panic!("expected MirExpr::Matches, got {other:?}"),
        }
    }

    #[test]
    fn lower_call_expression_into_typed_mir() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where is_shell(p)
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let expr = &mir.rules[0].predicates[0].expr;
        match expr {
            MirExpr::Call { name, args } => {
                assert_eq!(name, "is_shell");
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0], MirExpr::Field { .. }));
            }
            other => panic!("expected MirExpr::Call, got {other:?}"),
        }
    }

    #[test]
    fn lower_member_chain_on_call_into_field_path() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where host(p.host_id).baseline.domains == null
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let expr = &mir.rules[0].predicates[0].expr;
        match expr {
            MirExpr::Eq { lhs, rhs: _ } => match lhs.as_ref() {
                MirExpr::Field { path } => assert_eq!(path, "host.baseline.domains"),
                other => panic!("expected MirExpr::Field on lhs, got {other:?}"),
            },
            other => panic!("expected MirExpr::Eq, got {other:?}"),
        }
    }

    #[test]
    fn lower_duration_literal_into_typed_mir() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid > 5m
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let expr = &mir.rules[0].predicates[0].expr;
        match expr {
            MirExpr::Gt { lhs: _, rhs } => match rhs.as_ref() {
                MirExpr::Duration(d) => {
                    assert_eq!(d.value, 5);
                    assert_eq!(d.unit, crate::ast::DurationUnit::M);
                }
                other => panic!("expected rhs to be MirExpr::Duration, got {other:?}"),
            },
            other => panic!("expected MirExpr::Gt, got {other:?}"),
        }
    }

    #[test]
    fn lower_arithmetic_expressions_into_typed_mir() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where (p.pid + 2) * 3 > 9 and -p.uid < 0
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        let expr = &mir.rules[0].predicates[0].expr;
        match expr {
            MirExpr::And { lhs, rhs } => {
                match lhs.as_ref() {
                    MirExpr::Gt { lhs, rhs } => {
                        assert!(matches!(lhs.as_ref(), MirExpr::Mul { .. }));
                        assert!(matches!(rhs.as_ref(), MirExpr::Int(9)));
                    }
                    other => panic!("expected MirExpr::Gt on lhs, got {other:?}"),
                }
                match rhs.as_ref() {
                    MirExpr::Lt { lhs, rhs } => {
                        assert!(matches!(lhs.as_ref(), MirExpr::Sub { .. }));
                        assert!(matches!(rhs.as_ref(), MirExpr::Int(0)));
                    }
                    other => panic!("expected MirExpr::Lt on rhs, got {other:?}"),
                }
            }
            other => panic!("expected MirExpr::And, got {other:?}"),
        }
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
            respond: crate::ast::Spanned::new(crate::ast::RespondBlock { arms: vec![] }, 0..1),
        };
        let program = Program {
            rules: vec![rule],
            ..Program::default()
        };
        let mir = lower_program(&program);
        assert_eq!(mir.rules[0].window.unwrap().value, 5);
    }

    #[test]
    fn lower_around_derives_sources_from_arms_when_from_clause_absent() {
        let program = parse_program(
            r#"
rule "around_sources" {
  around host.id within 5m {
    process.spawn as p
    network.connect as n
  }
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        assert_eq!(mir.rules[0].sources.len(), 2);
        assert_eq!(mir.rules[0].sources[0].domain, "process");
        assert_eq!(mir.rules[0].sources[0].event, "spawn");
        assert_eq!(mir.rules[0].sources[0].alias.as_deref(), Some("p"));
        assert_eq!(mir.rules[0].sources[1].domain, "network");
        assert_eq!(mir.rules[0].sources[1].event, "connect");
        assert_eq!(mir.rules[0].sources[1].alias.as_deref(), Some("n"));
    }

    #[test]
    fn lower_graph_derives_sources_from_graph_block_when_from_clause_absent() {
        let program = parse_program(
            r#"
rule "graph_sources" {
  graph endpoint.process as p {
    process as proc
  }
  respond alert high
}
"#,
        );
        let mir = lower_program(&program);
        assert_eq!(mir.rules[0].sources.len(), 1);
        assert_eq!(mir.rules[0].sources[0].domain, "endpoint");
        assert_eq!(mir.rules[0].sources[0].event, "process");
        assert_eq!(mir.rules[0].sources[0].alias.as_deref(), Some("p"));
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

    #[test]
    fn validate_program_blocks_unsupported_expressions() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 1
  respond alert high
}
"#,
        );
        let mut mir = lower_program(&program);
        mir.rules[0].predicates[0].expr = MirExpr::And {
            lhs: Box::new(MirExpr::Field {
                path: "p.pid".to_string(),
            }),
            rhs: Box::new(MirExpr::Unsupported {
                kind: "binop_add".to_string(),
            }),
        };
        mir.rules[0].score.modifiers.push(MirScoreModifier {
            delta: 10,
            condition: Some(MirExpr::Unsupported {
                kind: "call_expr".to_string(),
            }),
        });

        let diagnostics = validate_program(&mir);
        let unsupported = diagnostics
            .iter()
            .filter(|d| d.kind == MirValidationKind::UnsupportedExpression)
            .collect::<Vec<_>>();
        assert!(
            unsupported.len() >= 2,
            "expected unsupported-expression diagnostics, got: {:?}",
            diagnostics
        );
        assert!(
            unsupported
                .iter()
                .all(|d| d.severity == MirValidationSeverity::Error),
            "expected unsupported-expression diagnostics to be errors, got: {:?}",
            unsupported
        );
        assert!(
            unsupported
                .iter()
                .any(|d| d.message.contains("predicate[0].rhs")),
            "expected predicate-path diagnostic context, got: {:?}",
            unsupported
        );
        assert!(
            unsupported
                .iter()
                .any(|d| d.message.contains("score.modifier[0].condition")),
            "expected score-condition diagnostic context, got: {:?}",
            unsupported
        );
    }
}
