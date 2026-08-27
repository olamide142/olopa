//! Runtime IR definitions for central multi-source and multi-agent correlation.
//!
//! Deserializes artifacts emitted by `oilc --emit-runtime-ir` and bundled multi-unit packs.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Serialized program payload emitted by `oilc`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeProgram {
    /// Runtime schema version (current: 1).
    pub version: u32,
    /// Compiler-emitted field metadata.
    #[serde(default)]
    pub fields: Vec<RuntimeField>,
    /// Callable contracts available when this artifact was compiled.
    #[serde(default)]
    pub callables: Vec<RuntimeCallable>,
    /// Rules compiled in this program.
    pub rules: Vec<RuntimeRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCallable {
    pub name: String,
    pub params: Vec<RuntimeCallableParam>,
    pub returns: Option<RuntimeCallableType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCallableParam {
    pub name: String,
    pub value_type: RuntimeCallableType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "of", rename_all = "snake_case")]
pub enum RuntimeCallableType {
    Any,
    Str,
    Int,
    Float,
    Bool,
    Duration,
    Path,
    IpAddr,
    Entity(String),
    Set(Box<RuntimeCallableType>),
    Nullable(Box<RuntimeCallableType>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeField {
    pub canonical: String,
    pub value_type: RuntimeFieldType,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub is_time_context: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFieldType {
    Bool,
    Number,
    String,
    Ip,
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub class: RuntimeRuleClass,
    #[serde(default)]
    pub sources: Vec<RuntimeSource>,
    #[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RuntimeSource {
    pub domain: String,
    pub event: String,
    pub alias: Option<String>,
}

impl RuntimeSource {
    pub fn effective_alias(&self) -> String {
        self.alias.clone().unwrap_or_else(|| {
            if !self.domain.is_empty() {
                format!("{}.{}", self.domain, self.event)
            } else {
                self.event.clone()
            }
        })
    }
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

impl RuntimeDuration {
    pub fn to_millis(&self) -> u64 {
        match self.unit {
            RuntimeDurationUnit::Ns => (self.value / 1_000_000).max(1),
            RuntimeDurationUnit::Us => (self.value / 1_000).max(1),
            RuntimeDurationUnit::Ms => self.value,
            RuntimeDurationUnit::S => self.value.saturating_mul(1_000),
            RuntimeDurationUnit::M => self.value.saturating_mul(60_000),
            RuntimeDurationUnit::H => self.value.saturating_mul(3_600_000),
            RuntimeDurationUnit::D => self.value.saturating_mul(86_400_000),
        }
    }

    pub fn to_nanos(&self) -> u64 {
        match self.unit {
            RuntimeDurationUnit::Ns => self.value,
            RuntimeDurationUnit::Us => self.value.saturating_mul(1_000),
            RuntimeDurationUnit::Ms => self.value.saturating_mul(1_000_000),
            RuntimeDurationUnit::S => self.value.saturating_mul(1_000_000_000),
            RuntimeDurationUnit::M => self.value.saturating_mul(60_000_000_000),
            RuntimeDurationUnit::H => self.value.saturating_mul(3_600_000_000_000),
            RuntimeDurationUnit::D => self.value.saturating_mul(86_400_000_000_000),
        }
    }
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
    #[serde(default)]
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
    #[serde(default)]
    pub args: Vec<RuntimeExpr>,
    pub expires: Option<RuntimeDuration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RuntimeRespondPlan {
    #[serde(default)]
    pub branches: Vec<RuntimeRespondBranch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRespondBranch {
    pub condition: Option<RuntimeExpr>,
    #[serde(default)]
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
    BlockQuery {
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
    Bool { value: bool },
    Null,
    List { items: Vec<RuntimeExpr> },
    Int { value: i64 },
    Float { value: f64 },
    Duration {
        value: u64,
        unit: RuntimeDurationUnit,
    },
    Str { value: String },
    Field { path: String },
    Call {
        name: String,
        args: Vec<RuntimeExpr>,
    },
    Project {
        base: Box<RuntimeExpr>,
        field: String,
    },
    And {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Or {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    Not { expr: Box<RuntimeExpr> },
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
    Unsupported {
        kind: String,
    },
}

#[derive(Debug, Deserialize)]
struct RuntimeArtifactMultiUnit {
    version: u32,
    units: Vec<RuntimeArtifactUnit>,
}

#[derive(Debug, Deserialize)]
struct RuntimeArtifactUnit {
    #[allow(dead_code)]
    id: String,
    program: RuntimeProgram,
}

/// Parse single-unit or multi-unit runtime IR JSON into a unified `RuntimeProgram`.
pub fn parse_runtime_program(content: &str) -> anyhow::Result<RuntimeProgram> {
    if let Ok(multi) = serde_json::from_str::<RuntimeArtifactMultiUnit>(content) {
        let mut merged_rules = Vec::new();
        let mut fields = Vec::new();
        let mut callables = Vec::new();
        let mut seen_fields = HashMap::new();
        let mut seen_callables = HashMap::new();

        for unit in multi.units {
            for f in unit.program.fields {
                if !seen_fields.contains_key(&f.canonical) {
                    seen_fields.insert(f.canonical.clone(), ());
                    fields.push(f);
                }
            }
            for c in unit.program.callables {
                if !seen_callables.contains_key(&c.name) {
                    seen_callables.insert(c.name.clone(), ());
                    callables.push(c);
                }
            }
            merged_rules.extend(unit.program.rules);
        }

        return Ok(RuntimeProgram {
            version: multi.version,
            fields,
            callables,
            rules: merged_rules,
        });
    }

    let program: RuntimeProgram = serde_json::from_str(content)?;
    Ok(program)
}
