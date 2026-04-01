use serde::{Deserialize, Serialize};

use crate::ast::{
    ActionStmt, AuthKind, ChallengeKind, DurationUnit, IsolateKind, OilDuration, RevokeKind,
    Severity, SnapshotKind,
};
use crate::mid::{MirAction, MirExpr, MirProgram, RuleClass};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeProgram {
    pub version: u32,
    pub rules: Vec<RuntimeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub class: RuntimeRuleClass,
    #[serde(default)]
    pub sources: Vec<RuntimeSource>,
    pub predicates: Vec<RuntimeExpr>,
    #[serde(default)]
    pub joins: Vec<RuntimeJoin>,
    #[serde(default)]
    pub window: Option<RuntimeDuration>,
    #[serde(default)]
    pub require: Vec<RuntimeExpr>,
    #[serde(default)]
    pub lets: Vec<RuntimeLet>,
    #[serde(default)]
    pub score: RuntimeScore,
    #[serde(default)]
    pub verify: Vec<String>,
    #[serde(default)]
    pub emit: Vec<RuntimeEmit>,
    #[serde(default)]
    pub respond: RuntimeRespondPlan,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRuleClass {
    HotPath,
    #[default]
    Temporal,
    Graph,
    Around,
    Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSource {
    pub domain: String,
    pub event: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeJoin {
    pub left_alias: String,
    pub right_alias: String,
    pub on: Option<RuntimeExpr>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDuration {
    pub value: u64,
    pub unit: RuntimeDurationUnit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDurationUnit {
    Ns,
    Us,
    Ms,
    S,
    M,
    H,
    D,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeLet {
    pub name: String,
    pub value: RuntimeExpr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuntimeScore {
    pub base: i32,
    pub modifiers: Vec<RuntimeScoreModifier>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeScoreModifier {
    pub delta: i32,
    pub condition: Option<RuntimeExpr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEmit {
    pub fact_name: String,
    pub args: Vec<RuntimeExpr>,
    pub expires: Option<RuntimeDuration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuntimeRespondPlan {
    pub branches: Vec<RuntimeRespondBranch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRespondBranch {
    pub condition: Option<RuntimeExpr>,
    pub actions: Vec<RuntimeAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RuntimeAction {
    Alert {
        severity: String,
        message: Option<String>,
    },
    Isolate {
        isolate_kind: String,
        target: String,
    },
    Revoke {
        revoke_kind: String,
        target: String,
    },
    Snapshot {
        snapshot_kind: String,
        targets: Vec<String>,
    },
    OpenCase {
        title: String,
    },
    Challenge {
        challenge_kind: String,
    },
    RequireAuth {
        auth_kind: String,
        for_: String,
    },
    Quarantine {
        path: String,
    },
    BlockEgress {
        target: String,
    },
    Notify {
        message: String,
    },
    Throttle {
        target: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuntimeExpr {
    Bool {
        value: bool,
    },
    Int {
        value: i64,
    },
    Float {
        value: f64,
    },
    Str {
        value: String,
    },
    Field {
        path: String,
    },
    And {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Or {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Not {
        expr: Box<RuntimeExpr>,
    },
    Eq {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Ne {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Lt {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Gt {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Le {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Ge {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    In {
        lhs: Box<RuntimeExpr>,
        rhs: Vec<RuntimeExpr>,
    },
    StartsWith {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    EndsWith {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Contains {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Matches {
        lhs: Box<RuntimeExpr>,
        pattern: String,
    },
    Unsupported {
        kind: String,
    },
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
                class: lower_rule_class(rule.class),
                sources: rule
                    .sources
                    .iter()
                    .map(|s| RuntimeSource {
                        domain: s.domain.clone(),
                        event: s.event.clone(),
                        alias: s.alias.clone(),
                    })
                    .collect(),
                predicates: rule
                    .predicates
                    .iter()
                    .map(|p| lower_mir_expr(&p.expr))
                    .collect(),
                joins: rule
                    .joins
                    .iter()
                    .map(|j| RuntimeJoin {
                        left_alias: j.left_alias.clone(),
                        right_alias: j.right_alias.clone(),
                        on: j.on.as_ref().map(lower_mir_expr),
                    })
                    .collect(),
                window: rule.window.map(lower_duration),
                require: rule
                    .require
                    .iter()
                    .map(|r| lower_mir_expr(&r.expr))
                    .collect(),
                lets: rule
                    .lets
                    .iter()
                    .map(|b| RuntimeLet {
                        name: b.name.clone(),
                        value: lower_mir_expr(&b.value),
                    })
                    .collect(),
                score: RuntimeScore {
                    base: rule.score.base,
                    modifiers: rule
                        .score
                        .modifiers
                        .iter()
                        .map(|m| RuntimeScoreModifier {
                            delta: m.delta,
                            condition: m.condition.as_ref().map(lower_mir_expr),
                        })
                        .collect(),
                },
                verify: rule.verify.iter().map(|v| v.path.clone()).collect(),
                emit: rule
                    .emit
                    .iter()
                    .map(|e| RuntimeEmit {
                        fact_name: e.fact_name.clone(),
                        args: e.args.iter().map(lower_mir_expr).collect(),
                        expires: e.expires.map(lower_duration),
                    })
                    .collect(),
                respond: RuntimeRespondPlan {
                    branches: rule
                        .respond
                        .branches
                        .iter()
                        .map(|b| RuntimeRespondBranch {
                            condition: b.condition.as_ref().map(lower_mir_expr),
                            actions: b.actions.iter().map(lower_action).collect(),
                        })
                        .collect(),
                },
            })
            .collect(),
    }
}

fn lower_rule_class(class: RuleClass) -> RuntimeRuleClass {
    match class {
        RuleClass::HotPath => RuntimeRuleClass::HotPath,
        RuleClass::Temporal => RuntimeRuleClass::Temporal,
        RuleClass::Graph => RuntimeRuleClass::Graph,
        RuleClass::Around => RuntimeRuleClass::Around,
        RuleClass::Policy => RuntimeRuleClass::Policy,
    }
}

fn lower_duration(d: OilDuration) -> RuntimeDuration {
    RuntimeDuration {
        value: d.value,
        unit: lower_duration_unit(d.unit),
    }
}

fn lower_duration_unit(unit: DurationUnit) -> RuntimeDurationUnit {
    match unit {
        DurationUnit::Ns => RuntimeDurationUnit::Ns,
        DurationUnit::Us => RuntimeDurationUnit::Us,
        DurationUnit::Ms => RuntimeDurationUnit::Ms,
        DurationUnit::S => RuntimeDurationUnit::S,
        DurationUnit::M => RuntimeDurationUnit::M,
        DurationUnit::H => RuntimeDurationUnit::H,
        DurationUnit::D => RuntimeDurationUnit::D,
    }
}

fn lower_mir_expr(expr: &MirExpr) -> RuntimeExpr {
    match expr {
        MirExpr::Bool(value) => RuntimeExpr::Bool { value: *value },
        MirExpr::Int(value) => RuntimeExpr::Int { value: *value },
        MirExpr::Float(value) => RuntimeExpr::Float { value: *value },
        MirExpr::Str(value) => RuntimeExpr::Str {
            value: value.clone(),
        },
        MirExpr::Field { path } => RuntimeExpr::Field { path: path.clone() },
        MirExpr::And { lhs, rhs } => RuntimeExpr::And {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Or { lhs, rhs } => RuntimeExpr::Or {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Not { expr } => RuntimeExpr::Not {
            expr: Box::new(lower_mir_expr(expr)),
        },
        MirExpr::Eq { lhs, rhs } => RuntimeExpr::Eq {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Ne { lhs, rhs } => RuntimeExpr::Ne {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Lt { lhs, rhs } => RuntimeExpr::Lt {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Gt { lhs, rhs } => RuntimeExpr::Gt {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Le { lhs, rhs } => RuntimeExpr::Le {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Ge { lhs, rhs } => RuntimeExpr::Ge {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::In { lhs, rhs } => RuntimeExpr::In {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: rhs.iter().map(lower_mir_expr).collect(),
        },
        MirExpr::StartsWith { lhs, rhs } => RuntimeExpr::StartsWith {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::EndsWith { lhs, rhs } => RuntimeExpr::EndsWith {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Contains { lhs, rhs } => RuntimeExpr::Contains {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Matches { lhs, pattern } => RuntimeExpr::Matches {
            lhs: Box::new(lower_mir_expr(lhs)),
            pattern: pattern.clone(),
        },
        MirExpr::List(_) => RuntimeExpr::Unsupported {
            kind: "list_literal".to_string(),
        },
        MirExpr::Null => RuntimeExpr::Unsupported {
            kind: "null_literal".to_string(),
        },
        MirExpr::Unsupported { kind } => RuntimeExpr::Unsupported { kind: kind.clone() },
    }
}

fn lower_action(action: &MirAction) -> RuntimeAction {
    match action {
        MirAction::Raw(stmt) => lower_raw_action(stmt),
    }
}

fn lower_raw_action(stmt: &ActionStmt) -> RuntimeAction {
    match stmt {
        ActionStmt::Alert { severity, message } => RuntimeAction::Alert {
            severity: severity_name(*severity).to_string(),
            message: message.clone(),
        },
        ActionStmt::Isolate { kind, target } => RuntimeAction::Isolate {
            isolate_kind: isolate_kind_name(*kind).to_string(),
            target: target.node.clone(),
        },
        ActionStmt::Revoke { kind, target } => RuntimeAction::Revoke {
            revoke_kind: revoke_kind_name(*kind).to_string(),
            target: target.node.clone(),
        },
        ActionStmt::Snapshot { targets, kind } => RuntimeAction::Snapshot {
            snapshot_kind: snapshot_kind_name(*kind).to_string(),
            targets: targets.iter().map(|t| t.node.clone()).collect(),
        },
        ActionStmt::OpenCase { title } => RuntimeAction::OpenCase {
            title: title.clone(),
        },
        ActionStmt::Challenge { kind } => RuntimeAction::Challenge {
            challenge_kind: challenge_kind_name(*kind).to_string(),
        },
        ActionStmt::RequireAuth { kind, for_ } => RuntimeAction::RequireAuth {
            auth_kind: auth_kind_name(*kind).to_string(),
            for_: for_.node.clone(),
        },
        ActionStmt::Quarantine { path } => RuntimeAction::Quarantine {
            path: path.node.clone(),
        },
        ActionStmt::BlockEgress { target } => RuntimeAction::BlockEgress {
            target: target.node.clone(),
        },
        ActionStmt::Notify { message } => RuntimeAction::Notify {
            message: message.clone(),
        },
        ActionStmt::Throttle { target } => RuntimeAction::Throttle {
            target: target.node.clone(),
        },
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
    }
}

fn isolate_kind_name(k: IsolateKind) -> &'static str {
    match k {
        IsolateKind::Host => "host",
        IsolateKind::Network => "network",
        IsolateKind::Process => "process",
    }
}

fn revoke_kind_name(k: RevokeKind) -> &'static str {
    match k {
        RevokeKind::Session => "session",
        RevokeKind::Token => "token",
        RevokeKind::Credential => "credential",
    }
}

fn snapshot_kind_name(k: SnapshotKind) -> &'static str {
    match k {
        SnapshotKind::Entities => "entities",
        SnapshotKind::AttackGraph => "attack_graph",
        SnapshotKind::HostTimeline => "host_timeline",
        SnapshotKind::ProcessTree => "process_tree",
    }
}

fn challenge_kind_name(k: ChallengeKind) -> &'static str {
    match k {
        ChallengeKind::Mfa => "mfa",
    }
}

fn auth_kind_name(k: AuthKind) -> &'static str {
    match k {
        AuthKind::Reauthentication => "reauthentication",
        AuthKind::StepUp => "step_up",
        AuthKind::Approval => "approval",
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
        assert_eq!(runtime.rules[0].class, RuntimeRuleClass::Temporal);
        assert_eq!(runtime.rules[0].sources.len(), 1);
        assert_eq!(runtime.rules[0].predicates.len(), 1);
        assert_eq!(runtime.rules[0].respond.branches.len(), 1);
        assert_eq!(runtime.rules[0].respond.branches[0].actions.len(), 1);
    }

    #[test]
    fn lowers_showcase_shape_beyond_predicates() {
        let src = include_str!("rules/showcase.oil");
        let tokens = Lexer::new(src).tokenize().expect("lex");
        let mut parser = Parser::new(tokens);
        let program = parser.parse().expect("parse");
        let mir = lower_program(&program);
        let runtime = lower_runtime_program(&mir);
        let rule = &runtime.rules[0];

        assert_eq!(rule.name, "container_shell_credential_access_and_egress");
        assert_eq!(rule.sources.len(), 5);
        assert_eq!(rule.joins.len(), 4);
        assert_eq!(
            rule.window,
            Some(RuntimeDuration {
                value: 15,
                unit: RuntimeDurationUnit::M
            })
        );
        assert_eq!(rule.lets.len(), 4);
        assert_eq!(rule.score.base, 70);
        assert_eq!(rule.score.modifiers.len(), 4);
        assert_eq!(rule.emit.len(), 1);
        assert_eq!(rule.respond.branches.len(), 2);
    }

    #[test]
    fn lowers_matches_operator_into_runtime_ir() {
        let src = r#"
rule "runtime_ir_matches" {
  from endpoint.process
  correlate process.spawn as p
  where p.name matches "ba*"
  respond alert high
}
"#;
        let tokens = Lexer::new(src).tokenize().expect("lex");
        let mut parser = Parser::new(tokens);
        let program = parser.parse().expect("parse");
        let mir = lower_program(&program);
        let runtime = lower_runtime_program(&mir);
        let pred = &runtime.rules[0].predicates[0];
        match pred {
            RuntimeExpr::Matches { lhs, pattern } => {
                assert!(matches!(lhs.as_ref(), RuntimeExpr::Field { .. }));
                assert_eq!(pattern, "ba*");
            }
            other => panic!("expected RuntimeExpr::Matches, got {other:?}"),
        }
    }
}
