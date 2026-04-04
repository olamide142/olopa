use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ActionStmt, AuthKind, ChallengeKind, DurationUnit, IsolateKind, OilDuration, RevokeKind,
    Severity, SnapshotKind,
};
use crate::mid::{MirAction, MirExpr, MirProgram, RuleClass};
use crate::schema::{FieldType, PrimitiveType, SchemaRegistry};

/// Serialized payload sent from the compiler to the runtime evaluator.
/// Treat this as a wire contract between `oilc` and `agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeProgram {
    /// Runtime schema version for compatibility checks.
    pub version: u32,
    /// Runtime field metadata derived from compiler schema/context.
    #[serde(default)]
    pub fields: Vec<RuntimeField>,
    pub rules: Vec<RuntimeRule>,
}

/// Typed field metadata consumed by runtime evaluators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeField {
    /// Canonical dotted path (for example `process.pid`).
    pub canonical: String,
    /// Runtime scalar type classification.
    pub value_type: RuntimeFieldType,
    /// Optional aliases accepted by runtime field resolution.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Whether this field comes from wall-clock derived context.
    #[serde(default)]
    pub is_time_context: bool,
}

/// Runtime value-type tags shared with evaluator field resolution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFieldType {
    Bool,
    Number,
    String,
    Ip,
    List,
}

/// A single executable rule after MIR lowering.
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

/// Scheduling/evaluation hint used by the runtime planner.
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

/// Event source subscription (domain + event) with optional alias binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSource {
    pub domain: String,
    pub event: String,
    pub alias: Option<String>,
}

/// Join relation between two aliases within the same rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeJoin {
    pub left_alias: String,
    pub right_alias: String,
    pub on: Option<RuntimeExpr>,
}

/// Runtime window/expiry duration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDuration {
    pub value: u64,
    pub unit: RuntimeDurationUnit,
}

/// Canonical duration units used in serialized runtime plans.
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

/// Let-binding materialized at runtime for reuse in expressions/actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeLet {
    pub name: String,
    pub value: RuntimeExpr,
}

/// Additive scoring model used before threshold decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuntimeScore {
    pub base: i32,
    pub modifiers: Vec<RuntimeScoreModifier>,
}

/// A conditional score delta.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeScoreModifier {
    pub delta: i32,
    pub condition: Option<RuntimeExpr>,
}

/// Fact emission plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEmit {
    pub fact_name: String,
    pub args: Vec<RuntimeExpr>,
    pub expires: Option<RuntimeDuration>,
}

/// Ordered response branches emitted by compiler for runtime evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuntimeRespondPlan {
    pub branches: Vec<RuntimeRespondBranch>,
}

/// One condition + action list in the response plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRespondBranch {
    pub condition: Option<RuntimeExpr>,
    pub actions: Vec<RuntimeAction>,
}

/// Concrete runtime actions serialized as tagged enums for wire stability.
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

/// Runtime expression tree evaluated by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuntimeExpr {
    Bool {
        value: bool,
    },
    Null,
    List {
        items: Vec<RuntimeExpr>,
    },
    Int {
        value: i64,
    },
    Float {
        value: f64,
    },
    Duration {
        value: u64,
        unit: RuntimeDurationUnit,
    },
    Str {
        value: String,
    },
    Field {
        path: String,
    },
    Call {
        name: String,
        args: Vec<RuntimeExpr>,
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
    Add {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Sub {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Mul {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Div {
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
    /// Carries syntax accepted upstream but not yet executable at runtime.
    Unsupported {
        kind: String,
    },
}

const MAX_ENTITY_VISITS_PER_PATH: usize = 2;
const TIME_ROOT: &str = "time";

/// Synthetic runtime-only fields not represented in stdlib schema.
const SYNTHETIC_RUNTIME_FIELDS: &[(&str, RuntimeFieldType, bool)] = &[
    ("event.ts_ns", RuntimeFieldType::Number, false),
    ("event.event_type", RuntimeFieldType::Number, false),
    ("event.vertex_id", RuntimeFieldType::Number, false),
    ("event.dst_vertex_id", RuntimeFieldType::Number, false),
    ("event.comm_id", RuntimeFieldType::Number, false),
    ("event.risk_score", RuntimeFieldType::Number, false),
];

/// Build runtime field metadata from stdlib schema (+ runtime synthetic fields).
pub fn runtime_fields_from_schema(schema: &SchemaRegistry) -> Vec<RuntimeField> {
    let mut by_canonical: BTreeMap<String, (RuntimeFieldType, bool)> = BTreeMap::new();

    for (root_name, root) in &schema.roots {
        let mut visits: HashMap<String, usize> = HashMap::new();
        collect_runtime_fields_for_entity(
            schema,
            &root.entity,
            root_name,
            root_name == TIME_ROOT,
            &mut visits,
            &mut by_canonical,
        );
    }

    for (canonical, value_type, is_time_context) in SYNTHETIC_RUNTIME_FIELDS {
        by_canonical
            .entry((*canonical).to_string())
            .or_insert((*value_type, *is_time_context));
    }

    let mut alias_counts: HashMap<String, usize> = HashMap::new();
    for canonical in by_canonical.keys() {
        for alias in canonical_suffix_aliases(canonical) {
            *alias_counts.entry(alias).or_insert(0) += 1;
        }
    }

    let mut out = Vec::with_capacity(by_canonical.len());
    for (canonical, (value_type, is_time_context)) in by_canonical {
        let mut aliases = canonical_suffix_aliases(&canonical)
            .into_iter()
            .filter(|alias| alias_counts.get(alias).copied() == Some(1))
            .collect::<Vec<_>>();
        aliases.extend(
            runtime_field_compatibility_aliases(&canonical)
                .iter()
                .map(|alias| (*alias).to_string()),
        );
        aliases.sort();
        aliases.dedup();
        aliases.retain(|alias| alias != &canonical);

        out.push(RuntimeField {
            canonical,
            value_type,
            aliases,
            is_time_context,
        });
    }
    out
}

fn collect_runtime_fields_for_entity(
    schema: &SchemaRegistry,
    entity_name: &str,
    prefix: &str,
    is_time_context: bool,
    visits: &mut HashMap<String, usize>,
    out: &mut BTreeMap<String, (RuntimeFieldType, bool)>,
) {
    let Some(entity) = schema.entities.get(entity_name) else {
        return;
    };

    let count = visits.entry(entity_name.to_string()).or_insert(0);
    if *count >= MAX_ENTITY_VISITS_PER_PATH {
        return;
    }
    *count += 1;

    for field in entity.fields.values() {
        let canonical = format!("{prefix}.{}", field.name);
        if let Some(value_type) = runtime_field_type_from_schema_type(&field.ty) {
            out.entry(canonical)
                .or_insert((value_type, is_time_context));
            continue;
        }

        if let Some(child_entity) = schema_entity_type_name(&field.ty) {
            collect_runtime_fields_for_entity(
                schema,
                child_entity,
                &canonical,
                is_time_context,
                visits,
                out,
            );
        }
    }

    if let Some(c) = visits.get_mut(entity_name) {
        *c = c.saturating_sub(1);
    }
}

fn schema_entity_type_name(ty: &FieldType) -> Option<&str> {
    match ty {
        FieldType::Entity(name) => Some(name.as_str()),
        FieldType::Nullable(inner) => schema_entity_type_name(inner),
        _ => None,
    }
}

fn runtime_field_type_from_schema_type(ty: &FieldType) -> Option<RuntimeFieldType> {
    match ty {
        FieldType::Primitive(p) => runtime_field_type_from_primitive(*p),
        FieldType::Nullable(inner) => runtime_field_type_from_schema_type(inner),
        FieldType::Set(inner) => {
            runtime_field_type_from_schema_type(inner).map(|_| RuntimeFieldType::List)
        }
        FieldType::Entity(_) => None,
    }
}

fn runtime_field_type_from_primitive(ty: PrimitiveType) -> Option<RuntimeFieldType> {
    match ty {
        PrimitiveType::Bool => Some(RuntimeFieldType::Bool),
        PrimitiveType::Int | PrimitiveType::Float | PrimitiveType::Duration => {
            Some(RuntimeFieldType::Number)
        }
        PrimitiveType::Str | PrimitiveType::Path => Some(RuntimeFieldType::String),
        PrimitiveType::IpAddr => Some(RuntimeFieldType::Ip),
    }
}

fn canonical_suffix_aliases(canonical: &str) -> Vec<String> {
    let parts: Vec<&str> = canonical.split('.').collect();
    if parts.len() < 2 {
        return Vec::new();
    }

    (1..parts.len()).map(|idx| parts[idx..].join(".")).collect()
}

fn runtime_field_compatibility_aliases(canonical: &str) -> &'static [&'static str] {
    match canonical {
        "time.weekday" => &["weekday", "day_of_week", "time.day_of_week"],
        "time.hour" => &["hour"],
        "time.minute" => &["minute"],
        "time.is_business_hour" => &["is_business_hour", "business_hours", "time.business_hours"],
        "event.ts_ns" => &["ts_ns"],
        "process.pid" => &["pid", "process_id", "process.id"],
        "process.uid" => &["uid", "user.uid"],
        "event.event_type" => &["event_type", "event.type"],
        "event.vertex_id" => &["vertex_id", "event.src_vertex_id"],
        "event.dst_vertex_id" => &["dst_vertex_id", "event.dst_vertex_id"],
        "process.name" => &["name", "comm", "process.comm"],
        "event.comm_id" => &["comm_id", "process.comm_id"],
        "event.risk_score" => &["risk_score", "score"],
        "network.direction" => &["direction"],
        "network.dest.domain" => &["domain", "dest.domain"],
        "network.dest.ip" => &["dst_ip", "ip", "dest.ip"],
        "network.dest.port" => &["dst_port", "port", "dest.port"],
        _ => &[],
    }
}

/// Lower MIR to runtime IR while preserving semantics 1:1.
/// Validation/inference should already be completed by prior stages.
pub fn lower_runtime_program(mir: &MirProgram) -> RuntimeProgram {
    RuntimeProgram {
        version: 1,
        fields: Vec::new(),
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

/// Direct mapping from MIR class to runtime class.
fn lower_rule_class(class: RuleClass) -> RuntimeRuleClass {
    match class {
        RuleClass::HotPath => RuntimeRuleClass::HotPath,
        RuleClass::Temporal => RuntimeRuleClass::Temporal,
        RuleClass::Graph => RuntimeRuleClass::Graph,
        RuleClass::Around => RuntimeRuleClass::Around,
        RuleClass::Policy => RuntimeRuleClass::Policy,
    }
}

/// Normalize duration node into runtime format.
fn lower_duration(d: OilDuration) -> RuntimeDuration {
    RuntimeDuration {
        value: d.value,
        unit: lower_duration_unit(d.unit),
    }
}

/// Direct mapping from AST duration units to runtime units.
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

/// Structural lowering for expression trees.
/// Unsupported nodes are preserved instead of dropped for debuggability.
fn lower_mir_expr(expr: &MirExpr) -> RuntimeExpr {
    match expr {
        MirExpr::Bool(value) => RuntimeExpr::Bool { value: *value },
        MirExpr::Null => RuntimeExpr::Null,
        MirExpr::List(items) => RuntimeExpr::List {
            items: items.iter().map(lower_mir_expr).collect(),
        },
        MirExpr::Int(value) => RuntimeExpr::Int { value: *value },
        MirExpr::Float(value) => RuntimeExpr::Float { value: *value },
        MirExpr::Duration(value) => RuntimeExpr::Duration {
            value: value.value,
            unit: lower_duration_unit(value.unit),
        },
        MirExpr::Str(value) => RuntimeExpr::Str {
            value: value.clone(),
        },
        MirExpr::Field { path } => RuntimeExpr::Field { path: path.clone() },
        MirExpr::Call { name, args } => RuntimeExpr::Call {
            name: name.clone(),
            args: args.iter().map(lower_mir_expr).collect(),
        },
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
        MirExpr::Add { lhs, rhs } => RuntimeExpr::Add {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Sub { lhs, rhs } => RuntimeExpr::Sub {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Mul { lhs, rhs } => RuntimeExpr::Mul {
            lhs: Box::new(lower_mir_expr(lhs)),
            rhs: Box::new(lower_mir_expr(rhs)),
        },
        MirExpr::Div { lhs, rhs } => RuntimeExpr::Div {
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
        MirExpr::Unsupported { kind } => RuntimeExpr::Unsupported { kind: kind.clone() },
    }
}

/// Convert MIR action wrapper into concrete runtime action.
fn lower_action(action: &MirAction) -> RuntimeAction {
    match action {
        MirAction::Raw(stmt) => lower_raw_action(stmt),
    }
}

/// Convert parsed action statements to stable runtime action payloads.
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
    use crate::schema::parse_schema;

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

    #[test]
    fn lowers_call_expression_into_runtime_ir_call_expr() {
        let src = r#"
rule "runtime_ir_call" {
  from endpoint.process
  correlate process.spawn as p
  where is_shell(p)
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
            RuntimeExpr::Call { name, args } => {
                assert_eq!(name, "is_shell");
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0], RuntimeExpr::Field { .. }));
            }
            other => panic!("expected RuntimeExpr::Call, got {other:?}"),
        }
    }

    #[test]
    fn lowers_null_literal_into_runtime_ir_null_expr() {
        let src = r#"
rule "runtime_ir_null" {
  from endpoint.process
  correlate process.spawn as p
  where p.name == null
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
            RuntimeExpr::Eq { lhs: _, rhs } => {
                assert!(matches!(rhs.as_ref(), RuntimeExpr::Null));
            }
            other => panic!("expected RuntimeExpr::Eq, got {other:?}"),
        }
    }

    #[test]
    fn lowers_duration_literal_into_runtime_ir_duration_expr() {
        let src = r#"
rule "runtime_ir_duration" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid > 5m
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
            RuntimeExpr::Gt { lhs: _, rhs } => match rhs.as_ref() {
                RuntimeExpr::Duration { value, unit } => {
                    assert_eq!(*value, 5);
                    assert_eq!(*unit, RuntimeDurationUnit::M);
                }
                other => panic!("expected RuntimeExpr::Duration on rhs, got {other:?}"),
            },
            other => panic!("expected RuntimeExpr::Gt, got {other:?}"),
        }
    }

    #[test]
    fn lowers_list_literal_into_runtime_ir_list_expr() {
        let src = r#"
rule "runtime_ir_list" {
  from endpoint.process
  correlate process.spawn as p
  where ["bash", "sh"] contains p.name
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
            RuntimeExpr::Contains { lhs, rhs: _ } => match lhs.as_ref() {
                RuntimeExpr::List { items } => assert_eq!(items.len(), 2),
                other => panic!("expected RuntimeExpr::List on contains lhs, got {other:?}"),
            },
            other => panic!("expected RuntimeExpr::Contains, got {other:?}"),
        }
    }

    #[test]
    fn lowers_arithmetic_expression_into_runtime_ir() {
        let src = r#"
rule "runtime_ir_arith" {
  from endpoint.process
  correlate process.spawn as p
  where (p.pid + 2) * 3 > 9
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
            RuntimeExpr::Gt { lhs, rhs } => {
                assert!(matches!(lhs.as_ref(), RuntimeExpr::Mul { .. }));
                assert!(matches!(rhs.as_ref(), RuntimeExpr::Int { value: 9 }));
            }
            other => panic!("expected RuntimeExpr::Gt, got {other:?}"),
        }
    }

    #[test]
    fn derives_runtime_field_metadata_from_schema_and_synthetic_fields() {
        let schema_src = include_str!("oil_stdlib/src/schema.oil");
        let schema = parse_schema(schema_src).expect("parse schema");
        let fields = runtime_fields_from_schema(&schema);

        let process_pid = fields
            .iter()
            .find(|f| f.canonical == "process.pid")
            .expect("process.pid metadata");
        assert_eq!(process_pid.value_type, RuntimeFieldType::Number);
        assert!(process_pid.aliases.iter().any(|a| a == "pid"));

        let ts = fields
            .iter()
            .find(|f| f.canonical == "event.ts_ns")
            .expect("event.ts_ns synthetic metadata");
        assert_eq!(ts.value_type, RuntimeFieldType::Number);
        assert!(!ts.is_time_context);

        let time_hour = fields
            .iter()
            .find(|f| f.canonical == "time.hour")
            .expect("time.hour metadata");
        assert_eq!(time_hour.value_type, RuntimeFieldType::Number);
        assert!(time_hour.is_time_context);
    }

    #[test]
    fn limits_recursive_schema_field_expansion() {
        let schema_src = include_str!("oil_stdlib/src/schema.oil");
        let schema = parse_schema(schema_src).expect("parse schema");
        let fields = runtime_fields_from_schema(&schema);

        assert!(fields.iter().any(|f| f.canonical == "process.parent.name"));
        assert!(!fields
            .iter()
            .any(|f| f.canonical == "process.parent.parent.name"));
    }
}
