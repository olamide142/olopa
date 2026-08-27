//! Runtime IR evaluator for userspace rule execution.
//!
//! This module loads the JSON artifact emitted by `oilc --emit-runtime-ir`
//! and evaluates each rule predicate against `IngestEvent`.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use log::{debug, log_enabled, warn, Level};
use serde::{Deserialize, Serialize};

use crate::agent::{IngestEvent, RuleMatch};
use crate::intel_store;

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
/// Cached DNS lookup map: domain -> (fetch_time, resolved_ipv4s).
type DnsCache = HashMap<String, (Instant, Vec<u32>)>;
/// Global DNS cache used by domain/IP comparison helpers.
static DOMAIN_IP_CACHE: OnceLock<Mutex<DnsCache>> = OnceLock::new();
/// Lower-bound heuristic for "looks like realtime epoch ns" timestamps.
const EPOCH_NS_MIN_2000: u64 = 946_684_800_000_000_000; // 2000-01-01T00:00:00Z

/// Startup wall-clock anchor used to map monotonic kernel time into realtime.
#[derive(Debug, Clone, Copy)]
struct ClockAnchor {
    /// Monotonic nanoseconds sampled at startup.
    monotonic_ns: u64,
    /// Realtime nanoseconds sampled at startup.
    realtime_ns: u64,
}

/// Optional global clock anchor cached on first use.
static CLOCK_ANCHOR: OnceLock<Option<ClockAnchor>> = OnceLock::new();

const DEFAULT_CALLABLE_STATE_MAX_ENTRIES: usize = 100_000;
const DEFAULT_CALLABLE_STATE_CHECKPOINT_EVERY: u64 = 128;

thread_local! {
    static CURRENT_CALLABLE_RULE: RefCell<String> = const { RefCell::new(String::new()) };
    static CURRENT_EVAL_BINDINGS: RefCell<HashMap<String, Value>> = RefCell::new(HashMap::new());
}

type RareStateKey = (String, String, String);
type UnusualStateKey = (String, String, String, String);
type RateStateKey = (String, String, String, u64);

#[derive(Debug, Clone)]
enum CallableStateKey {
    Rare(RareStateKey),
    Unusual(UnusualStateKey),
    Rate(RateStateKey),
}

#[derive(Debug)]
struct CallableEvalState {
    /// Compiler-emitted contracts used to validate values at the execution boundary.
    contracts: HashMap<String, Vec<RuntimeCallable>>,
    host_scope: String,
    max_entries: usize,
    checkpoint_every: u64,
    persistence_path: Option<PathBuf>,
    /// Immutable lookup data used by extension callables such as baseline/image.
    lookup_data: Option<Arc<RuntimeLookupArtifact>>,
    dirty_mutations: u64,
    state_order: VecDeque<CallableStateKey>,
    rare_counts: HashMap<RareStateKey, u64>,
    unusual_entity_value_counts: HashMap<UnusualStateKey, u64>,
    rate_observations: HashMap<RateStateKey, VecDeque<u64>>,
}

impl Default for CallableEvalState {
    fn default() -> Self {
        Self {
            contracts: HashMap::new(),
            host_scope: "agent-local".to_string(),
            max_entries: DEFAULT_CALLABLE_STATE_MAX_ENTRIES,
            checkpoint_every: DEFAULT_CALLABLE_STATE_CHECKPOINT_EVERY,
            persistence_path: None,
            lookup_data: None,
            dirty_mutations: 0,
            state_order: VecDeque::new(),
            rare_counts: HashMap::new(),
            unusual_entity_value_counts: HashMap::new(),
            rate_observations: HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CallableStateSnapshot {
    version: u32,
    host_scope: String,
    #[serde(default)]
    rare: Vec<(String, String, u64)>,
    #[serde(default)]
    unusual: Vec<(String, String, String, u64)>,
    #[serde(default)]
    rates: Vec<(String, String, u64, Vec<u64>)>,
}

/// Versioned local data source for lookup-backed runtime extensions.
///
/// Workloads are keyed as `namespace/name`. Host and user entries contain the
/// corresponding baseline object, while image/workload entries are baseline
/// profiles directly.
#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeLookupArtifact {
    version: u32,
    #[serde(default)]
    images: HashMap<String, RuntimeBaselineProfile>,
    #[serde(default)]
    workloads: HashMap<String, RuntimeBaselineProfile>,
    #[serde(default)]
    hosts: HashMap<String, RuntimeHostBaseline>,
    #[serde(default)]
    users: HashMap<String, RuntimeUserBaseline>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeBaselineProfile {
    #[serde(default)]
    allowed_processes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeHostBaseline {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    processes: Vec<String>,
    #[serde(default)]
    users: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeUserBaseline {
    #[serde(default)]
    countries: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    geos: Vec<String>,
    #[serde(default)]
    login_hours: Vec<i64>,
}

impl CallableEvalState {
    fn from_env(contracts: HashMap<String, Vec<RuntimeCallable>>) -> Result<Self> {
        let host_scope = std::env::var("OLOPA_INGEST_HOST_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "agent-local".to_string());
        let max_entries = env_usize(
            "OLOPA_CALLABLE_STATE_MAX_ENTRIES",
            DEFAULT_CALLABLE_STATE_MAX_ENTRIES,
        );
        let checkpoint_every = env_usize(
            "OLOPA_CALLABLE_STATE_CHECKPOINT_EVERY",
            DEFAULT_CALLABLE_STATE_CHECKPOINT_EVERY as usize,
        )
        .max(1) as u64;
        let persistence_path = std::env::var("OLOPA_CALLABLE_STATE_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let mut state = Self::with_config(
            contracts,
            host_scope,
            max_entries,
            checkpoint_every,
            persistence_path,
        )?;
        state.lookup_data = load_runtime_lookup_artifact_from_env()?;
        Ok(state)
    }

    fn with_config(
        contracts: HashMap<String, Vec<RuntimeCallable>>,
        host_scope: String,
        max_entries: usize,
        checkpoint_every: u64,
        persistence_path: Option<PathBuf>,
    ) -> Result<Self> {
        let mut state = Self {
            contracts,
            host_scope,
            max_entries,
            checkpoint_every: checkpoint_every.max(1),
            persistence_path,
            ..Self::default()
        };
        state.restore()?;
        Ok(state)
    }

    fn restore(&mut self) -> Result<()> {
        let Some(path) = self.persistence_path.as_ref() else {
            return Ok(());
        };
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read callable state: {}", path.display()))
            }
        };
        let snapshot: CallableStateSnapshot = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse callable state: {}", path.display()))?;
        if snapshot.version != 1 {
            bail!(
                "unsupported callable-state version {} in {}",
                snapshot.version,
                path.display()
            );
        }
        if snapshot.host_scope != self.host_scope {
            bail!(
                "callable-state host scope mismatch in {}: expected '{}', found '{}'",
                path.display(),
                self.host_scope,
                snapshot.host_scope
            );
        }

        for (rule, value, count) in snapshot.rare {
            let key = (self.host_scope.clone(), rule, value);
            self.rare_counts.insert(key.clone(), count);
            self.remember_state_key(CallableStateKey::Rare(key));
        }
        for (rule, entity, value, count) in snapshot.unusual {
            let key = (self.host_scope.clone(), rule, entity, value);
            self.unusual_entity_value_counts.insert(key.clone(), count);
            self.remember_state_key(CallableStateKey::Unusual(key));
        }
        for (rule, value, window_ns, observations) in snapshot.rates {
            let key = (self.host_scope.clone(), rule, value, window_ns);
            self.rate_observations
                .insert(key.clone(), observations.into());
            self.remember_state_key(CallableStateKey::Rate(key));
        }
        self.dirty_mutations = 0;
        Ok(())
    }

    fn remember_state_key(&mut self, key: CallableStateKey) {
        self.state_order.push_back(key);
        while self.state_len() > self.max_entries {
            let Some(expired) = self.state_order.pop_front() else {
                break;
            };
            match expired {
                CallableStateKey::Rare(key) => {
                    self.rare_counts.remove(&key);
                }
                CallableStateKey::Unusual(key) => {
                    self.unusual_entity_value_counts.remove(&key);
                }
                CallableStateKey::Rate(key) => {
                    self.rate_observations.remove(&key);
                }
            }
        }
    }

    fn state_len(&self) -> usize {
        self.rare_counts.len()
            + self.unusual_entity_value_counts.len()
            + self.rate_observations.len()
    }

    fn mark_mutation(&mut self) {
        self.dirty_mutations = self.dirty_mutations.saturating_add(1);
    }

    fn maybe_checkpoint(&mut self) -> Result<()> {
        if self.persistence_path.is_none()
            || self.dirty_mutations == 0
            || self.dirty_mutations < self.checkpoint_every
        {
            return Ok(());
        }
        self.checkpoint()
    }

    fn checkpoint(&mut self) -> Result<()> {
        let Some(path) = self.persistence_path.as_ref() else {
            self.dirty_mutations = 0;
            return Ok(());
        };
        let snapshot = CallableStateSnapshot {
            version: 1,
            host_scope: self.host_scope.clone(),
            rare: self
                .rare_counts
                .iter()
                .map(|((_, rule, value), count)| (rule.clone(), value.clone(), *count))
                .collect(),
            unusual: self
                .unusual_entity_value_counts
                .iter()
                .map(|((_, rule, entity, value), count)| {
                    (rule.clone(), entity.clone(), value.clone(), *count)
                })
                .collect(),
            rates: self
                .rate_observations
                .iter()
                .map(|((_, rule, value, window_ns), observations)| {
                    (
                        rule.clone(),
                        value.clone(),
                        *window_ns,
                        observations.iter().copied().collect(),
                    )
                })
                .collect(),
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create callable-state directory: {}",
                    parent.display()
                )
            })?;
        }
        let temp_path = path.with_extension("tmp");
        let encoded = serde_json::to_vec(&snapshot).context("serialize callable state")?;
        fs::write(&temp_path, encoded)
            .with_context(|| format!("failed to write callable state: {}", temp_path.display()))?;
        fs::rename(&temp_path, path)
            .with_context(|| format!("failed to install callable state: {}", path.display()))?;
        self.dirty_mutations = 0;
        Ok(())
    }
}

fn load_runtime_lookup_artifact_from_env() -> Result<Option<Arc<RuntimeLookupArtifact>>> {
    let Some(path) = std::env::var("OLOPA_RUNTIME_LOOKUP_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        return Ok(None);
    };
    load_runtime_lookup_artifact(&path).map(Some)
}

fn load_runtime_lookup_artifact(path: &Path) -> Result<Arc<RuntimeLookupArtifact>> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read runtime lookup data: {}", path.display()))?;
    let artifact: RuntimeLookupArtifact = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse runtime lookup data: {}", path.display()))?;
    if artifact.version != 1 {
        bail!(
            "unsupported runtime lookup version {} in {} (supported: 1)",
            artifact.version,
            path.display()
        );
    }
    Ok(Arc::new(artifact))
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeProgram {
    /// Runtime IR schema version. Current supported version: 1.
    pub version: u32,
    /// Compiler-emitted field metadata used for runtime field resolution.
    #[serde(default)]
    pub fields: Vec<RuntimeField>,
    /// Callable contracts available when the program was compiled.
    #[serde(default)]
    pub callables: Vec<RuntimeCallable>,
    /// Flat list of compiled rules.
    pub rules: Vec<RuntimeRule>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuntimeCallable {
    pub name: String,
    pub params: Vec<RuntimeCallableParam>,
    pub returns: Option<RuntimeCallableType>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuntimeCallableParam {
    pub name: String,
    pub value_type: RuntimeCallableType,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

/// Runtime field metadata entry emitted by compiler artifacts.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeField {
    /// Canonical dotted field path.
    pub canonical: String,
    /// Runtime value-type tag.
    pub value_type: RuntimeFieldType,
    /// Optional alias paths accepted by runtime lookup.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Wall-clock derived context marker.
    #[serde(default)]
    pub is_time_context: bool,
}

/// Wire value-type tags attached to runtime field metadata.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFieldType {
    Bool,
    Number,
    String,
    Ip,
    List,
}

/// Canonical duration units used in serialized runtime plans.
#[derive(Debug, Clone, Copy, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeRule {
    /// Stable rule identifier generated by the compiler.
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// All predicates must evaluate to true for a match.
    pub predicates: Vec<RuntimeExpr>,
    /// Optional response plan; present in enriched runtime-ir output.
    #[serde(default)]
    pub respond: RuntimeRespondPlan,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeRespondPlan {
    #[serde(default)]
    pub branches: Vec<RuntimeRespondBranch>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeRespondBranch {
    #[serde(default)]
    pub condition: Option<RuntimeExpr>,
    #[serde(default)]
    pub actions: Vec<RuntimeAction>,
}

#[derive(Debug, Clone, Deserialize)]
struct RuntimeLet {
    name: String,
    value: RuntimeExpr,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeScore {
    #[serde(default)]
    base: i32,
    #[serde(default)]
    modifiers: Vec<RuntimeScoreModifier>,
}

#[derive(Debug, Clone, Deserialize)]
struct RuntimeScoreModifier {
    delta: i32,
    #[serde(default)]
    condition: Option<RuntimeExpr>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeRuleExecution {
    #[serde(default)]
    require: Vec<RuntimeExpr>,
    #[serde(default)]
    lets: Vec<RuntimeLet>,
    #[serde(default)]
    score: RuntimeScore,
}

#[derive(Debug, Deserialize)]
struct RuntimeExecutionSingle {
    rules: Vec<RuntimeExecutionRuleWire>,
}

#[derive(Debug, Deserialize)]
struct RuntimeExecutionMulti {
    units: Vec<RuntimeExecutionUnit>,
}

#[derive(Debug, Deserialize)]
struct RuntimeExecutionUnit {
    program: RuntimeExecutionSingle,
}

#[derive(Debug, Deserialize)]
struct RuntimeExecutionRuleWire {
    id: String,
    #[serde(flatten)]
    execution: RuntimeRuleExecution,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeAction {
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuntimeExpr {
    /// Literal boolean.
    Bool { value: bool },
    /// Literal null.
    Null,
    /// Literal list.
    List { items: Vec<RuntimeExpr> },
    /// Literal integer.
    Int { value: i64 },
    /// Literal float.
    Float { value: f64 },
    /// Literal duration.
    Duration {
        value: u64,
        unit: RuntimeDurationUnit,
    },
    /// Literal string.
    Str { value: String },
    /// Event field path such as `pid` or `event.pid`.
    Field { path: String },
    /// Callable expression.
    Call {
        name: String,
        args: Vec<RuntimeExpr>,
    },
    /// Field projection from a structured callable result.
    Project {
        base: Box<RuntimeExpr>,
        field: String,
    },
    /// Logical conjunction.
    And {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Logical disjunction.
    Or {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Logical negation.
    Not { expr: Box<RuntimeExpr> },
    /// Equality.
    Eq {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Inequality.
    Ne {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Less than.
    Lt {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Greater than.
    Gt {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Less or equal.
    Le {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Greater or equal.
    Ge {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Numeric addition.
    Add {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Numeric subtraction.
    Sub {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Numeric multiplication.
    Mul {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Numeric division.
    Div {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Membership check.
    In {
        lhs: Box<RuntimeExpr>,
        rhs: Vec<RuntimeExpr>,
    },
    /// String prefix check.
    StartsWith {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// String suffix check.
    EndsWith {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// String contains check.
    Contains {
        lhs: Box<RuntimeExpr>,
        rhs: Box<RuntimeExpr>,
    },
    /// Pattern match check.
    Matches {
        lhs: Box<RuntimeExpr>,
        pattern: String,
    },
    /// Placeholder for operators not yet implemented in runtime.
    Unsupported { kind: String },
}

/// Runtime value type used during expression evaluation.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    /// Boolean value.
    Bool(bool),
    /// Numeric value (all ints/floats normalized to f64).
    Number(f64),
    /// String value.
    String(String),
    /// IPv4 value encoded as host-endian `u32`.
    Ip(u32),
    /// List value used by collection operators.
    List(Vec<Value>),
    /// Structured extension result used by callable field projection.
    Object(HashMap<String, Value>),
    /// Missing/unknown value.
    Null,
}

/// Stable value-type tag attached to field metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    Bool,
    Number,
    String,
    Ip,
    List,
}

/// Field lookup descriptor used by runtime evaluator.
///
/// The compiler emits canonical + alias metadata, while agent provides
/// extractor bindings for currently supported event fields.
#[derive(Debug, Clone)]
struct FieldSpec {
    /// Canonical schema-style field path (for diagnostics/docs).
    canonical: String,
    /// Value type expected for this field.
    value_type: FieldType,
    /// Allowed suffix aliases (matched on segment boundary).
    aliases: Vec<String>,
    /// Marks fields derived from wall-clock context.
    is_time_context: bool,
    /// Extract value from event.
    extract: Option<fn(&IngestEvent) -> Value>,
}

/// Backward-compatible field metadata used for older artifacts that do not
/// include compiler-emitted `fields` metadata.
struct FallbackFieldMetadata {
    canonical: &'static str,
    value_type: FieldType,
    aliases: &'static [&'static str],
    is_time_context: bool,
}

const FALLBACK_FIELD_METADATA: &[FallbackFieldMetadata] = &[
    FallbackFieldMetadata {
        canonical: "time.weekday",
        value_type: FieldType::String,
        aliases: &["weekday", "day_of_week", "time.day_of_week"],
        is_time_context: true,
    },
    FallbackFieldMetadata {
        canonical: "time.hour",
        value_type: FieldType::Number,
        aliases: &["hour"],
        is_time_context: true,
    },
    FallbackFieldMetadata {
        canonical: "time.minute",
        value_type: FieldType::Number,
        aliases: &["minute"],
        is_time_context: true,
    },
    FallbackFieldMetadata {
        canonical: "time.is_business_hour",
        value_type: FieldType::Bool,
        aliases: &["is_business_hour", "business_hours", "time.business_hours"],
        is_time_context: true,
    },
    FallbackFieldMetadata {
        canonical: "event.ts_ns",
        value_type: FieldType::Number,
        aliases: &["ts_ns"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.pid",
        value_type: FieldType::Number,
        aliases: &["pid", "process_id", "process.id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.ppid",
        value_type: FieldType::Number,
        aliases: &[
            "ppid",
            "parent_pid",
            "process.parent.pid",
            "process.parent.id",
            "parent.pid",
            "parent.id",
        ],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.uid",
        value_type: FieldType::Number,
        aliases: &["uid", "user.uid", "process.user.uid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.host_id",
        value_type: FieldType::String,
        aliases: &["host_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.secure_connect_session_id",
        value_type: FieldType::String,
        aliases: &["process.sc_session_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.elevated",
        value_type: FieldType::Bool,
        aliases: &["elevated", "is_root", "process.is_root"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.cgroup_id",
        value_type: FieldType::Number,
        aliases: &["cgroup_id", "process.cgroup.id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "container.cgroup_id",
        value_type: FieldType::Number,
        aliases: &["container.cgroup.id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "container.container_id",
        value_type: FieldType::String,
        aliases: &["container.id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "container.cgroup_path",
        value_type: FieldType::String,
        aliases: &["cgroup_path", "container.cgroup.path"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "container.pod_uid",
        value_type: FieldType::String,
        aliases: &["pod_uid", "container.pod.uid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "container.exists",
        value_type: FieldType::Bool,
        aliases: &["in_container"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "event.event_type",
        value_type: FieldType::Number,
        aliases: &["event_type", "event.type"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "event.vertex_id",
        value_type: FieldType::Number,
        aliases: &["vertex_id", "event.src_vertex_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "event.dst_vertex_id",
        value_type: FieldType::Number,
        aliases: &["dst_vertex_id", "event.dst_vertex_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "process.name",
        value_type: FieldType::String,
        aliases: &["name", "comm", "process.comm"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "event.comm_id",
        value_type: FieldType::Number,
        aliases: &["comm_id", "process.comm_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "event.risk_score",
        value_type: FieldType::Number,
        aliases: &["risk_score", "score"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "host.risk_score",
        value_type: FieldType::Number,
        aliases: &["host.risk_score", "host.rs"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "host.id",
        value_type: FieldType::String,
        aliases: &["host_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "host.hostname",
        value_type: FieldType::String,
        aliases: &["hostname"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "host.secure_connect_enabled",
        value_type: FieldType::Bool,
        aliases: &["secure_connect_enabled"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.process_id",
        value_type: FieldType::Number,
        aliases: &["network.process_id", "net.process_id", "net.proc_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.direction",
        value_type: FieldType::String,
        aliases: &["direction"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.tunneled",
        value_type: FieldType::Bool,
        aliases: &["tunneled"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.secure_connect_session_id",
        value_type: FieldType::String,
        aliases: &["network.sc_session_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.dest.domain",
        value_type: FieldType::Ip,
        aliases: &["domain", "dest.domain"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.dest.ip",
        value_type: FieldType::Ip,
        aliases: &["dst_ip", "ip", "dest.ip"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.dest.port",
        value_type: FieldType::Number,
        aliases: &["dst_port", "port", "dest.port"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "network.dest.is_internal",
        value_type: FieldType::Bool,
        aliases: &[
            "network.dest.is_internal",
            "dest.is_internal",
            "dest.internal",
            "is_internal",
        ],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "file.process_id",
        value_type: FieldType::Number,
        aliases: &["file.process_id", "file.proc_id"],
        is_time_context: false,
    },
    // SQL event fields (event_type == 4)
    FallbackFieldMetadata {
        canonical: "sql.query_hash",
        value_type: FieldType::Number,
        aliases: &["sql_query_hash"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sql.query_class",
        value_type: FieldType::Number,
        aliases: &["sql_query_class", "sql.class"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sql.db_port",
        value_type: FieldType::Number,
        aliases: &["sql_db_port"],
        is_time_context: false,
    },
    // Derived from the redacted statement, so a rule can name a table without
    // any literal value ever reaching the rule engine.
    FallbackFieldMetadata {
        canonical: "sql.tables",
        value_type: FieldType::List,
        aliases: &["sql_tables", "sql.table", "db.tables"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sql.database",
        value_type: FieldType::String,
        aliases: &["sql_database", "db.database", "sql.schema"],
        is_time_context: false,
    },
    // SSL/TLS event fields (event_type == 5)
    FallbackFieldMetadata {
        canonical: "ssl.pid",
        value_type: FieldType::Number,
        aliases: &["ssl_pid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "ssl.uid",
        value_type: FieldType::Number,
        aliases: &["ssl_uid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "ssl.process_name",
        value_type: FieldType::String,
        aliases: &["ssl_process_name"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "ssl.data_len",
        value_type: FieldType::Number,
        aliases: &["ssl_data_len", "ssl.bytes"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "ssl.operation",
        value_type: FieldType::Number,
        aliases: &["ssl_operation"],
        is_time_context: false,
    },
    // DNS resolution event fields (event_type == 6)
    FallbackFieldMetadata {
        canonical: "dns.pid",
        value_type: FieldType::Number,
        aliases: &["dns_pid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "dns.uid",
        value_type: FieldType::Number,
        aliases: &["dns_uid"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "dns.process_name",
        value_type: FieldType::String,
        aliases: &["dns_process_name"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "dns.domain.value",
        value_type: FieldType::String,
        aliases: &["dns_query", "dns.query", "dns.name"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "dns.query_hash",
        value_type: FieldType::Number,
        aliases: &["dns_query_hash"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "dns.domain.entropy",
        value_type: FieldType::Number,
        aliases: &["dns_entropy", "dns.entropy"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "secure_connect.id",
        value_type: FieldType::String,
        aliases: &["sc.id", "secure_connect.session_id"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "secure_connect.active",
        value_type: FieldType::Bool,
        aliases: &["sc.active"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "secure_connect.established",
        value_type: FieldType::Bool,
        aliases: &["sc.established"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "secure_connect.state",
        value_type: FieldType::String,
        aliases: &["sc.state"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sc_peer.latest_handshake_age",
        value_type: FieldType::Number,
        aliases: &["secure_connect.peer.latest_handshake_age"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sc_peer.rx_bytes",
        value_type: FieldType::Number,
        aliases: &["secure_connect.peer.rx_bytes"],
        is_time_context: false,
    },
    FallbackFieldMetadata {
        canonical: "sc_peer.tx_bytes",
        value_type: FieldType::Number,
        aliases: &["secure_connect.peer.tx_bytes"],
        is_time_context: false,
    },
];

fn build_field_specs(program: &RuntimeProgram) -> Vec<FieldSpec> {
    if program.fields.is_empty() {
        return FALLBACK_FIELD_METADATA
            .iter()
            .map(|field| {
                let canonical = normalize_field_path(field.canonical);
                let mut aliases = field
                    .aliases
                    .iter()
                    .map(|alias| normalize_field_path(alias))
                    .collect::<Vec<_>>();
                aliases.sort();
                aliases.dedup();
                aliases.retain(|alias| alias != &canonical);
                FieldSpec {
                    canonical: canonical.clone(),
                    value_type: field.value_type,
                    aliases,
                    is_time_context: field.is_time_context,
                    extract: lookup_field_extractor(&canonical),
                }
            })
            .collect();
    }

    program
        .fields
        .iter()
        .map(|field| {
            let canonical = normalize_field_path(&field.canonical);
            let mut aliases = field
                .aliases
                .iter()
                .map(|alias| normalize_field_path(alias))
                .collect::<Vec<_>>();
            aliases.sort();
            aliases.dedup();
            aliases.retain(|alias| alias != &canonical);

            FieldSpec {
                canonical: canonical.clone(),
                value_type: runtime_field_type_override(
                    &canonical,
                    runtime_field_type_to_internal(field.value_type),
                ),
                aliases,
                is_time_context: field.is_time_context,
                extract: lookup_field_extractor(&canonical),
            }
        })
        .collect()
}

fn runtime_field_type_to_internal(value_type: RuntimeFieldType) -> FieldType {
    match value_type {
        RuntimeFieldType::Bool => FieldType::Bool,
        RuntimeFieldType::Number => FieldType::Number,
        RuntimeFieldType::String => FieldType::String,
        RuntimeFieldType::Ip => FieldType::Ip,
        RuntimeFieldType::List => FieldType::List,
    }
}

/// Some schema-declared string fields are represented in-agent as IPv4 values.
fn runtime_field_type_override(canonical: &str, value_type: FieldType) -> FieldType {
    match canonical {
        "network.dest.domain" => FieldType::Ip,
        _ => value_type,
    }
}

fn lookup_field_extractor(canonical: &str) -> Option<fn(&IngestEvent) -> Value> {
    match canonical {
        "time.weekday" => Some(field_time_weekday),
        "time.hour" => Some(field_time_hour),
        "time.minute" => Some(field_time_minute),
        "time.is_business_hour" => Some(field_time_business_hour),
        "event.ts_ns" => Some(field_ts_ns),
        "process.id" => Some(field_process_id),
        "process.pid" => Some(field_pid),
        "process.ppid" => Some(field_process_ppid),
        "process.parent.id" | "process.parent.pid" => Some(field_process_parent_id),
        "process.uid" => Some(field_uid),
        "process.user.uid" | "user.uid" => Some(field_user_uid),
        "process.host_id" => Some(field_host_id),
        "process.secure_connect_session_id" => Some(field_secure_connect_id),
        "process.elevated" => Some(field_process_elevated),
        "process.cgroup_id" | "container.cgroup_id" => Some(field_cgroup_id),
        "process.container_id" | "container.container_id" => Some(field_container_id),
        "container.cgroup_path" => Some(field_container_cgroup_path),
        "container.pod_uid" => Some(field_container_pod_uid),
        "container.exists" => Some(field_container_exists),
        "host.risk_score" => Some(field_host_risk_score),
        "host.id" => Some(field_host_id),
        "host.hostname" => Some(field_hostname),
        "host.secure_connect_enabled" => Some(field_secure_connect_enabled),
        "event.event_type" => Some(field_event_type),
        "event.vertex_id" => Some(field_vertex_id),
        "event.dst_vertex_id" => Some(field_dst_vertex_id),
        "process.name" => Some(field_process_name),
        "event.comm_id" => Some(field_comm_id),
        "event.risk_score" => Some(field_risk_score),
        "network.process_id" => Some(field_network_process_id),
        "network.direction" => Some(field_network_direction),
        "network.tunneled" => Some(field_network_tunneled),
        "network.secure_connect_session_id" => Some(field_secure_connect_id),
        "network.dest.domain" | "network.dest.ip" => Some(field_network_dest_ip),
        "network.dest.port" => Some(field_network_dest_port),
        "network.dest.is_internal" => Some(field_network_dest_is_internal),
        "file.process_id" => Some(field_file_process_id),
        // SQL event fields.
        //
        // Both spellings are registered because the two paths into this
        // function disagree: the stdlib schema names the root `db`, so
        // oilc-emitted IR carries `db.*`, while FALLBACK_FIELD_METADATA — used
        // for hand-written IR — says `sql.*`. Registering only `sql.*` left
        // every compiled SQL rule without an extractor, evaluating to Null and
        // silently never firing.
        // Process identity on the SQL root. The extractors are event-type
        // agnostic, so `q.pid` means the pid of the process issuing the query.
        "db.pid" => Some(field_db_pid),
        "db.uid" => Some(field_db_uid),
        "db.process_name" => Some(field_db_process_name),
        "sql.query_hash" | "db.query_hash" => Some(field_sql_query_hash),
        "sql.query_class" | "db.query_class" => Some(field_sql_query_class),
        "sql.db_port" | "db.db_port" => Some(field_sql_db_port),
        "sql.tables" | "db.tables" => Some(field_sql_tables),
        "sql.database" | "db.database" => Some(field_sql_database),
        // SSL event fields
        "ssl.pid" => Some(field_ssl_pid),
        "ssl.uid" => Some(field_ssl_uid),
        "ssl.process_name" => Some(field_ssl_process_name),
        "ssl.data_len" => Some(field_ssl_data_len),
        "ssl.operation" => Some(field_ssl_operation),
        // DNS event fields
        "dns.pid" => Some(field_dns_pid),
        "dns.uid" => Some(field_dns_uid),
        "dns.process_name" => Some(field_dns_process_name),
        "dns.domain.value" => Some(field_dns_domain_value),
        "dns.query_hash" => Some(field_dns_query_hash),
        "dns.domain.entropy" => Some(field_dns_domain_entropy),
        // Secure Connect live session fields.
        "secure_connect.id" => Some(field_secure_connect_id),
        "secure_connect.active" => Some(field_secure_connect_active),
        "secure_connect.established" => Some(field_secure_connect_active),
        "secure_connect.state" => Some(field_secure_connect_state),
        "secure_connect.host_id" => Some(field_host_id),
        "sc_peer.latest_handshake_age" => Some(field_secure_connect_handshake_age),
        "sc_peer.rx_bytes" => Some(field_secure_connect_rx_bytes),
        "sc_peer.tx_bytes" => Some(field_secure_connect_tx_bytes),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeIrRuleEngine {
    /// Loaded, compiler-produced runtime program.
    program: RuntimeProgram,
    /// Runtime field metadata/extractor bindings used during evaluation.
    field_specs: Vec<FieldSpec>,
    /// Rule-local derived values, requirements, and score plan.
    rule_execution: HashMap<String, RuntimeRuleExecution>,
    /// Stateful memory used by novelty-oriented callables.
    callable_state: Arc<Mutex<CallableEvalState>>,
}

/// Multi-unit runtime artifact wrapper emitted by compiler in bundled mode.
#[derive(Debug, Clone, Deserialize)]
struct RuntimeArtifactMultiUnit {
    /// Artifact format version.
    version: u32,
    /// Unit list to merge.
    units: Vec<RuntimeArtifactUnit>,
}

/// One named rule unit in a multi-unit runtime artifact.
#[derive(Debug, Clone, Deserialize)]
struct RuntimeArtifactUnit {
    /// Unit id/name.
    id: String,
    /// Unit-local runtime program.
    program: RuntimeProgram,
}

impl RuntimeIrRuleEngine {
    /// Load runtime IR JSON from disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read runtime-ir file: {}", path.display()))?;
        let program = parse_runtime_program(&content).with_context(|| {
            format!(
                "failed to parse runtime-ir JSON (single or multi-unit): {}",
                path.display()
            )
        })?;
        let rule_execution = parse_runtime_rule_execution(&content).with_context(|| {
            format!(
                "failed to parse runtime rule execution plan: {}",
                path.display()
            )
        })?;
        if program.version != 1 {
            bail!(
                "unsupported runtime-ir version {} in {} (supported: 1)",
                program.version,
                path.display()
            );
        }
        validate_runtime_calls(&program, &rule_execution)?;
        let field_specs = build_field_specs(&program);
        let contracts = group_runtime_callables(&program.callables);
        let callable_state = CallableEvalState::from_env(contracts)?;
        Ok(Self {
            program,
            field_specs,
            rule_execution,
            callable_state: Arc::new(Mutex::new(callable_state)),
        })
    }

    /// Evaluate all rules for a single event and return every match.
    pub fn evaluate_matches(&self, event: &IngestEvent) -> Vec<RuleMatch> {
        // Version-gate execution so unknown schemas fail closed.
        if self.program.version != 1 {
            return Vec::new();
        }

        let mut out = Vec::new();
        for rule in &self.program.rules {
            let uses_time_context = rule_uses_time_context(rule, &self.field_specs);
            let (matched, enforce_block_egress, enforce_block_query) =
                with_rule_eval_scope(&rule.id, || {
                    let predicates_match = rule.predicates.iter().all(|pred| {
                        eval_bool(pred, event, &self.field_specs, &self.callable_state)
                    });
                    if !predicates_match {
                        return (false, false, false);
                    }

                    if let Some(execution) = self.rule_execution.get(&rule.id) {
                        evaluate_rule_derivations(
                            execution,
                            event,
                            &self.field_specs,
                            &self.callable_state,
                        );
                        if !execution.require.iter().all(|requirement| {
                            eval_bool(requirement, event, &self.field_specs, &self.callable_state)
                        }) {
                            return (false, false, false);
                        }
                    }

                    let (block_egress, block_query) = selected_branch_enforcement(
                        rule,
                        event,
                        &self.field_specs,
                        &self.callable_state,
                    );
                    (true, block_egress, block_query)
                });
            if should_debug_time_ir() && uses_time_context {
                debug_time_ir_eval(rule, event, matched);
            }
            if matched {
                out.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    enforce_block_egress,
                    enforce_block_query,
                });
            }
        }
        let checkpoint_result = self
            .callable_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .maybe_checkpoint();
        if let Err(error) = checkpoint_result {
            warn!("failed to checkpoint callable state: {error:#}");
        }
        out
    }

    pub fn rule_count(&self) -> usize {
        self.program.rules.len()
    }
}

fn with_callable_rule_scope<T>(rule_id: &str, evaluate: impl FnOnce() -> T) -> T {
    CURRENT_CALLABLE_RULE.with(|current| {
        let previous = current.replace(rule_id.to_string());
        let result = evaluate();
        current.replace(previous);
        result
    })
}

fn with_rule_eval_scope<T>(rule_id: &str, evaluate: impl FnOnce() -> T) -> T {
    with_callable_rule_scope(rule_id, || {
        CURRENT_EVAL_BINDINGS.with(|bindings| {
            let previous = std::mem::take(&mut *bindings.borrow_mut());
            let result = evaluate();
            *bindings.borrow_mut() = previous;
            result
        })
    })
}

fn current_callable_rule_scope() -> String {
    CURRENT_CALLABLE_RULE.with(|current| {
        let current = current.borrow();
        if current.is_empty() {
            "__direct__".to_string()
        } else {
            current.clone()
        }
    })
}

// Accept both:
// - single unit: {version, rules}
// - multi unit:  {version, units:[{id, program:{version, rules}}]}
/// Parse runtime program from single-unit or multi-unit JSON artifact.
fn parse_runtime_program(content: &str) -> Result<RuntimeProgram> {
    if let Ok(program) = serde_json::from_str::<RuntimeProgram>(content) {
        return Ok(program);
    }

    let multi: RuntimeArtifactMultiUnit = serde_json::from_str(content)?;
    let mut merged_rules = Vec::new();
    let mut merged_fields = Vec::new();
    let mut merged_callables = Vec::new();
    for unit in multi.units {
        // Keep `id` consumed intentionally; useful for future per-unit routing.
        let _unit_id = unit.id;
        merged_fields.extend(unit.program.fields);
        merged_callables.extend(unit.program.callables);
        merged_rules.extend(unit.program.rules);
    }

    Ok(RuntimeProgram {
        version: multi.version,
        fields: dedupe_runtime_fields(merged_fields),
        callables: dedupe_runtime_callables(merged_callables),
        rules: merged_rules,
    })
}

fn parse_runtime_rule_execution(content: &str) -> Result<HashMap<String, RuntimeRuleExecution>> {
    let rules = if let Ok(single) = serde_json::from_str::<RuntimeExecutionSingle>(content) {
        single.rules
    } else {
        serde_json::from_str::<RuntimeExecutionMulti>(content)?
            .units
            .into_iter()
            .flat_map(|unit| unit.program.rules)
            .collect()
    };
    Ok(rules
        .into_iter()
        .map(|rule| (rule.id, rule.execution))
        .collect())
}

fn dedupe_runtime_callables(callables: Vec<RuntimeCallable>) -> Vec<RuntimeCallable> {
    let mut merged = Vec::new();
    for callable in callables {
        if !merged.contains(&callable) {
            merged.push(callable);
        }
    }
    merged.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| format!("{:?}", a.params).cmp(&format!("{:?}", b.params)))
    });
    merged
}

fn group_runtime_callables(callables: &[RuntimeCallable]) -> HashMap<String, Vec<RuntimeCallable>> {
    let mut grouped: HashMap<String, Vec<RuntimeCallable>> = HashMap::new();
    for contract in callables {
        grouped
            .entry(contract.name.to_ascii_lowercase())
            .or_default()
            .push(contract.clone());
    }
    grouped
}

fn dedupe_runtime_fields(fields: Vec<RuntimeField>) -> Vec<RuntimeField> {
    let mut by_canonical: HashMap<String, RuntimeField> = HashMap::new();
    for field in fields {
        let canonical = normalize_field_path(&field.canonical);
        by_canonical.entry(canonical).or_insert(field);
    }
    let mut merged = by_canonical.into_values().collect::<Vec<_>>();
    merged.sort_by(|a, b| a.canonical.cmp(&b.canonical));
    merged
}

fn evaluate_rule_derivations(
    execution: &RuntimeRuleExecution,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) {
    for binding in &execution.lets {
        let value = eval_value(&binding.value, event, field_specs, callable_state);
        set_eval_binding(&binding.name, value);
    }

    let mut score = execution.score.base as f64;
    set_eval_binding("score", Value::Number(score));
    for modifier in &execution.score.modifiers {
        let applies = modifier
            .condition
            .as_ref()
            .is_none_or(|condition| eval_bool(condition, event, field_specs, callable_state));
        if applies {
            score += modifier.delta as f64;
            set_eval_binding("score", Value::Number(score));
        }
    }
}

fn set_eval_binding(name: &str, value: Value) {
    CURRENT_EVAL_BINDINGS.with(|bindings| {
        bindings
            .borrow_mut()
            .insert(normalize_field_path(name), value);
    });
}

fn lookup_eval_binding(path: &str) -> Option<Value> {
    let normalized = normalize_field_path(path);
    CURRENT_EVAL_BINDINGS.with(|bindings| bindings.borrow().get(&normalized).cloned())
}

/// Select the first matching response branch and inspect only its actions.
fn selected_branch_enforcement(
    rule: &RuntimeRule,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> (bool, bool) {
    rule.respond
        .branches
        .iter()
        .find(|branch| {
            branch
                .condition
                .as_ref()
                .is_none_or(|condition| eval_bool(condition, event, field_specs, callable_state))
        })
        .map(|branch| {
            let has = |name: &str| branch.actions.iter().any(|action| action.action == name);
            (has("block_egress"), has("block_query"))
        })
        .unwrap_or_default()
}

/// Determine whether verbose time-context debug logs are enabled.
fn should_debug_time_ir() -> bool {
    if !log_enabled!(Level::Debug) {
        return false;
    }
    match std::env::var("OLOPA_DEBUG_TIME_IR") {
        Ok(v) => {
            let flag = v.trim().to_ascii_lowercase();
            matches!(flag.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Emit detailed debug log for rules that reference time context.
fn debug_time_ir_eval(rule: &RuntimeRule, event: &IngestEvent, matched: bool) {
    if let Some(tm) = event_local_time(event) {
        debug!(
            "time-ir-check rule={} matched={} ts_ns={} weekday={} hour={} minute={} business_hours={}",
            rule.name,
            matched,
            event.ts_ns,
            weekday_name(tm.tm_wday),
            tm.tm_hour,
            tm.tm_min,
            is_business_hour(&tm)
        );
    } else {
        debug!(
            "time-ir-check rule={} matched={} ts_ns={} localtime=unavailable",
            rule.name, matched, event.ts_ns
        );
    }
}

/// Return true when any rule predicate references time-derived fields.
fn rule_uses_time_context(rule: &RuntimeRule, field_specs: &[FieldSpec]) -> bool {
    rule.predicates
        .iter()
        .any(|expr| expr_uses_time_context(expr, field_specs))
}

/// Recursively inspect expression tree for time-context field usage.
fn expr_uses_time_context(expr: &RuntimeExpr, field_specs: &[FieldSpec]) -> bool {
    match expr {
        RuntimeExpr::Field { path } => {
            lookup_field_spec(field_specs, path).is_some_and(|s| s.is_time_context)
        }
        RuntimeExpr::Call { name: _, args } => args
            .iter()
            .any(|arg| expr_uses_time_context(arg, field_specs)),
        RuntimeExpr::Project { base, .. } => expr_uses_time_context(base, field_specs),
        RuntimeExpr::And { lhs, rhs }
        | RuntimeExpr::Or { lhs, rhs }
        | RuntimeExpr::Eq { lhs, rhs }
        | RuntimeExpr::Ne { lhs, rhs }
        | RuntimeExpr::Lt { lhs, rhs }
        | RuntimeExpr::Gt { lhs, rhs }
        | RuntimeExpr::Le { lhs, rhs }
        | RuntimeExpr::Ge { lhs, rhs }
        | RuntimeExpr::Add { lhs, rhs }
        | RuntimeExpr::Sub { lhs, rhs }
        | RuntimeExpr::Mul { lhs, rhs }
        | RuntimeExpr::Div { lhs, rhs }
        | RuntimeExpr::StartsWith { lhs, rhs }
        | RuntimeExpr::EndsWith { lhs, rhs }
        | RuntimeExpr::Contains { lhs, rhs } => {
            expr_uses_time_context(lhs, field_specs) || expr_uses_time_context(rhs, field_specs)
        }
        RuntimeExpr::Matches { lhs, .. } => expr_uses_time_context(lhs, field_specs),
        RuntimeExpr::List { items } => items
            .iter()
            .any(|item| expr_uses_time_context(item, field_specs)),
        RuntimeExpr::In { lhs, rhs } => {
            expr_uses_time_context(lhs, field_specs)
                || rhs
                    .iter()
                    .any(|item| expr_uses_time_context(item, field_specs))
        }
        RuntimeExpr::Not { expr } => expr_uses_time_context(expr, field_specs),
        RuntimeExpr::Bool { .. }
        | RuntimeExpr::Null
        | RuntimeExpr::Int { .. }
        | RuntimeExpr::Float { .. }
        | RuntimeExpr::Duration { .. }
        | RuntimeExpr::Str { .. }
        | RuntimeExpr::Unsupported { .. } => false,
    }
}

// Evaluate expression in boolean context.
/// Evaluate an expression in boolean context.
fn eval_bool(
    expr: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> bool {
    match expr {
        RuntimeExpr::Bool { value } => *value,
        RuntimeExpr::Null => false,
        RuntimeExpr::List { .. } => false,
        RuntimeExpr::And { lhs, rhs } => {
            eval_bool(lhs, event, field_specs, callable_state)
                && eval_bool(rhs, event, field_specs, callable_state)
        }
        RuntimeExpr::Or { lhs, rhs } => {
            eval_bool(lhs, event, field_specs, callable_state)
                || eval_bool(rhs, event, field_specs, callable_state)
        }
        RuntimeExpr::Not { expr } => !eval_bool(expr, event, field_specs, callable_state),
        RuntimeExpr::Eq { lhs, rhs } => eval_eq(lhs, rhs, event, field_specs, callable_state),
        RuntimeExpr::Ne { lhs, rhs } => !eval_eq(lhs, rhs, event, field_specs, callable_state),
        RuntimeExpr::Lt { lhs, rhs } => {
            compare_ord(lhs, rhs, event, field_specs, callable_state, |a, b| a < b)
        }
        RuntimeExpr::Gt { lhs, rhs } => {
            compare_ord(lhs, rhs, event, field_specs, callable_state, |a, b| a > b)
        }
        RuntimeExpr::Le { lhs, rhs } => {
            compare_ord(lhs, rhs, event, field_specs, callable_state, |a, b| a <= b)
        }
        RuntimeExpr::Ge { lhs, rhs } => {
            compare_ord(lhs, rhs, event, field_specs, callable_state, |a, b| a >= b)
        }
        RuntimeExpr::In { lhs, rhs } => eval_in(lhs, rhs, event, field_specs, callable_state),
        RuntimeExpr::StartsWith { lhs, rhs } => {
            to_string(eval_value(lhs, event, field_specs, callable_state)).starts_with(&to_string(
                eval_value(rhs, event, field_specs, callable_state),
            ))
        }
        RuntimeExpr::EndsWith { lhs, rhs } => {
            to_string(eval_value(lhs, event, field_specs, callable_state)).ends_with(&to_string(
                eval_value(rhs, event, field_specs, callable_state),
            ))
        }
        RuntimeExpr::Contains { lhs, rhs } => {
            let lhs_value = eval_value(lhs, event, field_specs, callable_state);
            let rhs_value = eval_value(rhs, event, field_specs, callable_state);
            match lhs_value {
                Value::List(items) => items.iter().any(|item| values_equal(item, &rhs_value)),
                _ => to_string(lhs_value).contains(&to_string(rhs_value)),
            }
        }
        RuntimeExpr::Matches { lhs, pattern } => {
            value_matches_pattern(eval_value(lhs, event, field_specs, callable_state), pattern)
        }
        RuntimeExpr::Call { name, args } => {
            value_as_bool(eval_call(name, args, event, field_specs, callable_state))
        }
        RuntimeExpr::Field { path } => value_as_bool(lookup_field(field_specs, path, event)),
        RuntimeExpr::Project { .. } => {
            value_as_bool(eval_value(expr, event, field_specs, callable_state))
        }
        RuntimeExpr::Add { .. }
        | RuntimeExpr::Sub { .. }
        | RuntimeExpr::Mul { .. }
        | RuntimeExpr::Div { .. } => {
            to_number(eval_value(expr, event, field_specs, callable_state))
                .is_some_and(|value| value != 0.0)
        }
        RuntimeExpr::Unsupported { .. } => false,
        _ => false,
    }
}

/// Evaluate equality with typed coercion rules.
fn eval_eq(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> bool {
    let lhs_value = eval_value(lhs, event, field_specs, callable_state);
    let rhs_value = eval_value(rhs, event, field_specs, callable_state);
    values_equal(&lhs_value, &rhs_value)
}

/// Evaluate membership predicate (`lhs in rhs_list`).
///
/// Two evaluation paths:
/// 1. **External set reference** — when `rhs` is a single `Field` whose path
///    starts with `org.` or `intel.`, look the LHS value up in the global
///    `IntelStore` via O(1) `HashSet` lookup.  This is how rules like
///    `q.domain.value in org.threat_intel.c2_domains` work at runtime.
/// 2. **Inline list** — iterate over evaluated RHS items and compare pairwise
///    (existing behaviour for static literal lists).
fn eval_in(
    lhs: &RuntimeExpr,
    rhs: &[RuntimeExpr],
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> bool {
    // --- Path 1: external intel-store set reference --------------------------
    if let [RuntimeExpr::Field { path: set_name }] = rhs {
        if is_external_set_ref(set_name) {
            let lhs_value = eval_value(lhs, event, field_specs, callable_state);
            return intel_store_contains(set_name, &lhs_value);
        }
    }

    // --- Path 2: inline literal list -----------------------------------------
    let lhs_value = eval_value(lhs, event, field_specs, callable_state);
    rhs.iter().any(|item| {
        let rhs_value = eval_value(item, event, field_specs, callable_state);
        match rhs_value {
            Value::List(items) => items
                .iter()
                .any(|candidate| values_equal(&lhs_value, candidate)),
            other => values_equal(&lhs_value, &other),
        }
    })
}

/// Return `true` when `path` names an external threat-intelligence set.
///
/// Convention: paths starting with `org.` or `intel.` are external set
/// references populated by the intel-sync feed service, not event field paths.
#[inline]
fn is_external_set_ref(path: &str) -> bool {
    path.starts_with("org.") || path.starts_with("intel.")
}

/// Look up a runtime `Value` in the named intel-store set.
///
/// - `String` values are looked up in string sets (domains, hashes).
/// - `Ip` values are looked up in IP sets (malicious IPs).
/// - All other types return `false`.
#[inline]
fn intel_store_contains(set_name: &str, value: &Value) -> bool {
    match value {
        Value::String(s) => intel_store::contains_str(set_name, &s.to_lowercase()),
        Value::Ip(ip) => intel_store::contains_ip(set_name, *ip),
        Value::Number(n) => {
            // Allow matching numeric IPs stored as integers (e.g. from net events).
            let ip = *n as u32;
            intel_store::contains_ip(set_name, ip)
        }
        _ => false,
    }
}

// Core value equality with typed adapters.
// Keeps operators generic: `==` and `in` do not need per-field special cases.
fn values_equal(lhs: &Value, rhs: &Value) -> bool {
    match (value_as_ipv4(lhs), value_as_ipv4(rhs)) {
        (Some(a), Some(b)) => return a == b,
        _ => {}
    }

    match (lhs, rhs) {
        (Value::Ip(ip), Value::String(candidate)) | (Value::String(candidate), Value::Ip(ip)) => {
            if let Some(parsed_ip) = parse_ipv4_literal(candidate) {
                return *ip == parsed_ip;
            }
            if looks_like_domain_name(candidate) {
                return domain_matches_ip(candidate, *ip);
            }
            false
        }
        _ => lhs == rhs,
    }
}

/// Convert value into IPv4 integer when representable.
fn value_as_ipv4(value: &Value) -> Option<u32> {
    match value {
        Value::Ip(ip) => Some(*ip),
        Value::String(s) => parse_ipv4_literal(s),
        _ => None,
    }
}

/// Parse IPv4 literal into integer form.
fn parse_ipv4_literal(value: &str) -> Option<u32> {
    value.trim().parse::<Ipv4Addr>().ok().map(u32::from)
}

/// Heuristic domain-name detector used for typed comparisons.
fn looks_like_domain_name(value: &str) -> bool {
    let candidate = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.is_empty() {
        return false;
    }
    if parse_ipv4_literal(&candidate).is_some() {
        return false;
    }
    if candidate == "localhost" {
        return true;
    }
    if !candidate.contains('.') {
        return false;
    }
    candidate
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Resolve domain and test whether any A record equals target IP.
fn domain_matches_ip(domain: &str, ip: u32) -> bool {
    resolve_domain_ipv4_cached(domain)
        .into_iter()
        .any(|resolved| resolved == ip)
}

/// Resolve and cache domain A records with short TTL.
fn resolve_domain_ipv4_cached(domain: &str) -> Vec<u32> {
    let cache = DOMAIN_IP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();

    if let Ok(guard) = cache.lock() {
        if let Some((fetched_at, ips)) = guard.get(domain) {
            if now.duration_since(*fetched_at) <= DNS_CACHE_TTL {
                return ips.clone();
            }
        }
    }

    let mut resolved = Vec::new();
    if let Ok(addrs) = (domain, 0u16).to_socket_addrs() {
        for addr in addrs {
            if let IpAddr::V4(v4) = addr.ip() {
                let ip = u32::from(v4);
                if !resolved.contains(&ip) {
                    resolved.push(ip);
                }
            }
        }
    }

    if let Ok(mut guard) = cache.lock() {
        guard.insert(domain.to_string(), (Instant::now(), resolved.clone()));
    }

    resolved
}

// Compare two expressions after numeric coercion.
/// Compare two expressions as numbers after coercion.
fn compare_ord(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
    cmp: impl Fn(f64, f64) -> bool,
) -> bool {
    match (
        to_number(eval_value(lhs, event, field_specs, callable_state)),
        to_number(eval_value(rhs, event, field_specs, callable_state)),
    ) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Evaluate a binary arithmetic expression in numeric context.
fn eval_arithmetic(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
    op: impl Fn(f64, f64) -> Option<f64>,
) -> Value {
    let Some(lhs_num) = to_number(eval_value(lhs, event, field_specs, callable_state)) else {
        return Value::Null;
    };
    let Some(rhs_num) = to_number(eval_value(rhs, event, field_specs, callable_state)) else {
        return Value::Null;
    };
    op(lhs_num, rhs_num)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// Convert a duration literal to nanoseconds using checked arithmetic.
fn duration_to_ns(value: u64, unit: RuntimeDurationUnit) -> Option<u64> {
    let factor = match unit {
        RuntimeDurationUnit::Ns => 1u64,
        RuntimeDurationUnit::Us => 1_000u64,
        RuntimeDurationUnit::Ms => 1_000_000u64,
        RuntimeDurationUnit::S => 1_000_000_000u64,
        RuntimeDurationUnit::M => 60 * 1_000_000_000u64,
        RuntimeDurationUnit::H => 60 * 60 * 1_000_000_000u64,
        RuntimeDurationUnit::D => 24 * 60 * 60 * 1_000_000_000u64,
    };
    value.checked_mul(factor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuiltinCallable {
    Count,
    Len,
    Max,
    Min,
    Sum,
    Avg,
    Distinct,
    Rate,
    IsShell,
    Rare,
    UnusualFor,
    /// Collection-returning extension backed by the hot-reloaded intel store.
    IntelDomains,
    /// Profile lookup extensions backed by the versioned local lookup artifact.
    BaselineImage,
    BaselineWorkload,
    /// Entity lookup roots used by projected expressions such as host(...).baseline.domains.
    Host,
    User,
}

#[derive(Debug, Clone, Copy)]
struct BuiltinCallableSpec {
    canonical_name: &'static str,
    arity: usize,
    implementation: BuiltinCallable,
    contract_required: bool,
}

/// Resolve all runtime-executable callables through one registry.
fn builtin_callable_spec(name: &str) -> Option<BuiltinCallableSpec> {
    let normalized = name.trim().to_ascii_lowercase();
    let (canonical_name, arity, implementation, contract_required) = match normalized.as_str() {
        "count" => ("count", 1, BuiltinCallable::Count, true),
        "len" => ("len", 1, BuiltinCallable::Len, true),
        "max" => ("max", 1, BuiltinCallable::Max, true),
        "min" => ("min", 1, BuiltinCallable::Min, true),
        "sum" => ("sum", 1, BuiltinCallable::Sum, true),
        "avg" => ("avg", 1, BuiltinCallable::Avg, true),
        "distinct" => ("distinct", 1, BuiltinCallable::Distinct, true),
        "rate" => ("rate", 2, BuiltinCallable::Rate, true),
        "is_shell" => ("is_shell", 1, BuiltinCallable::IsShell, true),
        "rare" => ("rare", 1, BuiltinCallable::Rare, true),
        "unusual_for" | "unusualfor" => ("unusual_for", 2, BuiltinCallable::UnusualFor, true),
        "intel.domains" => ("intel.domains", 1, BuiltinCallable::IntelDomains, true),
        "baseline.image" => ("baseline.image", 1, BuiltinCallable::BaselineImage, true),
        "baseline.workload" => (
            "baseline.workload",
            2,
            BuiltinCallable::BaselineWorkload,
            true,
        ),
        // Entity roots come from the schema rather than `callables.oil`, so
        // they intentionally have no emitted callable contract.
        "host" => ("host", 1, BuiltinCallable::Host, false),
        "user" => ("user", 1, BuiltinCallable::User, false),
        _ => return None,
    };
    Some(BuiltinCallableSpec {
        canonical_name,
        arity,
        implementation,
        contract_required,
    })
}

/// Reject artifacts whose callable expressions cannot execute on this agent.
fn validate_runtime_calls(
    program: &RuntimeProgram,
    rule_execution: &HashMap<String, RuntimeRuleExecution>,
) -> Result<()> {
    for rule in &program.rules {
        for predicate in &rule.predicates {
            validate_expr_calls(predicate, &rule.name, &program.callables)?;
        }
        if let Some(execution) = rule_execution.get(&rule.id) {
            for requirement in &execution.require {
                validate_expr_calls(requirement, &rule.name, &program.callables)?;
            }
            for binding in &execution.lets {
                validate_expr_calls(&binding.value, &rule.name, &program.callables)?;
            }
            for modifier in &execution.score.modifiers {
                if let Some(condition) = &modifier.condition {
                    validate_expr_calls(condition, &rule.name, &program.callables)?;
                }
            }
        }
        for branch in &rule.respond.branches {
            if let Some(condition) = &branch.condition {
                validate_expr_calls(condition, &rule.name, &program.callables)?;
            }
        }
    }
    Ok(())
}

fn validate_expr_calls(
    expr: &RuntimeExpr,
    rule_name: &str,
    declared: &[RuntimeCallable],
) -> Result<()> {
    match expr {
        RuntimeExpr::Call { name, args } => {
            let Some(spec) = builtin_callable_spec(name) else {
                bail!("rule '{rule_name}' references unsupported runtime callable '{name}'");
            };
            if args.len() != spec.arity {
                bail!(
                    "rule '{rule_name}' callable '{}' expects {} argument(s), got {}",
                    spec.canonical_name,
                    spec.arity,
                    args.len()
                );
            }
            let contracts = declared
                .iter()
                .filter(|contract| contract.name.eq_ignore_ascii_case(spec.canonical_name))
                .collect::<Vec<_>>();
            if spec.contract_required && !declared.is_empty() && contracts.is_empty() {
                bail!(
                    "rule '{rule_name}' callable '{}' is missing from the compiler-emitted callable contract",
                    spec.canonical_name
                );
            }
            for contract in contracts {
                if contract.params.len() != spec.arity {
                    bail!(
                        "runtime callable contract mismatch for '{}': compiler declared {} argument(s), agent supports {}",
                        spec.canonical_name,
                        contract.params.len(),
                        spec.arity
                    );
                }
                for (index, param) in contract.params.iter().enumerate() {
                    if !builtin_param_contract_matches(
                        spec.implementation,
                        index,
                        &param.value_type,
                    ) {
                        bail!(
                            "runtime callable contract mismatch for '{}': parameter '{}' has unsupported type {:?}",
                            spec.canonical_name,
                            param.name,
                            param.value_type
                        );
                    }
                }
                if !builtin_return_contract_matches(spec.implementation, contract.returns.as_ref())
                {
                    bail!(
                        "runtime callable contract mismatch for '{}': unsupported return type {:?}",
                        spec.canonical_name,
                        contract.returns
                    );
                }
            }
            for arg in args {
                validate_expr_calls(arg, rule_name, declared)?;
            }
        }
        RuntimeExpr::List { items } => {
            for item in items {
                validate_expr_calls(item, rule_name, declared)?;
            }
        }
        RuntimeExpr::Project { base, .. } => {
            validate_expr_calls(base, rule_name, declared)?;
        }
        RuntimeExpr::And { lhs, rhs }
        | RuntimeExpr::Or { lhs, rhs }
        | RuntimeExpr::Eq { lhs, rhs }
        | RuntimeExpr::Ne { lhs, rhs }
        | RuntimeExpr::Lt { lhs, rhs }
        | RuntimeExpr::Gt { lhs, rhs }
        | RuntimeExpr::Le { lhs, rhs }
        | RuntimeExpr::Ge { lhs, rhs }
        | RuntimeExpr::Add { lhs, rhs }
        | RuntimeExpr::Sub { lhs, rhs }
        | RuntimeExpr::Mul { lhs, rhs }
        | RuntimeExpr::Div { lhs, rhs }
        | RuntimeExpr::StartsWith { lhs, rhs }
        | RuntimeExpr::EndsWith { lhs, rhs }
        | RuntimeExpr::Contains { lhs, rhs } => {
            validate_expr_calls(lhs, rule_name, declared)?;
            validate_expr_calls(rhs, rule_name, declared)?;
        }
        RuntimeExpr::In { lhs, rhs } => {
            validate_expr_calls(lhs, rule_name, declared)?;
            for item in rhs {
                validate_expr_calls(item, rule_name, declared)?;
            }
        }
        RuntimeExpr::Not { expr } | RuntimeExpr::Matches { lhs: expr, .. } => {
            validate_expr_calls(expr, rule_name, declared)?;
        }
        RuntimeExpr::Bool { .. }
        | RuntimeExpr::Null
        | RuntimeExpr::Int { .. }
        | RuntimeExpr::Float { .. }
        | RuntimeExpr::Duration { .. }
        | RuntimeExpr::Str { .. }
        | RuntimeExpr::Field { .. }
        | RuntimeExpr::Unsupported { .. } => {}
    }
    Ok(())
}

/// Ensure the compiler's callable declaration agrees with the concrete agent implementation.
fn builtin_param_contract_matches(
    implementation: BuiltinCallable,
    index: usize,
    value_type: &RuntimeCallableType,
) -> bool {
    match (implementation, index, value_type) {
        (BuiltinCallable::Count, 0, RuntimeCallableType::Any)
        | (BuiltinCallable::Len, 0, RuntimeCallableType::Str)
        | (BuiltinCallable::Rare, 0, RuntimeCallableType::Str)
        | (BuiltinCallable::Rate, 0, RuntimeCallableType::Str)
        | (BuiltinCallable::Rate, 1, RuntimeCallableType::Duration)
        | (BuiltinCallable::IntelDomains, 0, RuntimeCallableType::Str)
        | (BuiltinCallable::BaselineImage, 0, RuntimeCallableType::Str)
        | (BuiltinCallable::BaselineWorkload, 0 | 1, RuntimeCallableType::Str)
        | (BuiltinCallable::UnusualFor, 0 | 1, RuntimeCallableType::Str) => true,
        (BuiltinCallable::IsShell, 0, RuntimeCallableType::Entity(name)) => {
            name.eq_ignore_ascii_case("process")
        }
        (
            BuiltinCallable::Max
            | BuiltinCallable::Min
            | BuiltinCallable::Sum
            | BuiltinCallable::Avg,
            0,
            RuntimeCallableType::Set(inner),
        ) => matches!(inner.as_ref(), RuntimeCallableType::Int),
        (BuiltinCallable::Len, 0, RuntimeCallableType::Set(inner)) => {
            matches!(inner.as_ref(), RuntimeCallableType::Any)
        }
        (BuiltinCallable::Distinct, 0, RuntimeCallableType::Set(inner)) => {
            matches!(inner.as_ref(), RuntimeCallableType::Str)
        }
        _ => false,
    }
}

fn builtin_return_contract_matches(
    implementation: BuiltinCallable,
    value_type: Option<&RuntimeCallableType>,
) -> bool {
    match (implementation, value_type) {
        (
            BuiltinCallable::Count
            | BuiltinCallable::Len
            | BuiltinCallable::Max
            | BuiltinCallable::Min
            | BuiltinCallable::Sum
            | BuiltinCallable::Rate,
            Some(RuntimeCallableType::Int),
        )
        | (BuiltinCallable::Avg, Some(RuntimeCallableType::Float))
        | (
            BuiltinCallable::IsShell | BuiltinCallable::Rare | BuiltinCallable::UnusualFor,
            Some(RuntimeCallableType::Bool),
        ) => true,
        (BuiltinCallable::Distinct, Some(RuntimeCallableType::Set(inner))) => {
            matches!(inner.as_ref(), RuntimeCallableType::Str)
        }
        (BuiltinCallable::IntelDomains, Some(RuntimeCallableType::Set(inner))) => {
            matches!(inner.as_ref(), RuntimeCallableType::Str)
        }
        (
            BuiltinCallable::BaselineImage | BuiltinCallable::BaselineWorkload,
            Some(RuntimeCallableType::Entity(name)),
        ) => name.eq_ignore_ascii_case("baselineprofile"),
        // Schema entity lookup roots are not represented in `callables.oil`.
        (BuiltinCallable::Host | BuiltinCallable::User, None) => true,
        _ => false,
    }
}

fn eval_call(
    name: &str,
    args: &[RuntimeExpr],
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Value {
    let Some(spec) = builtin_callable_spec(name) else {
        return Value::Null;
    };
    if args.len() != spec.arity {
        return Value::Null;
    }
    let contract = callable_contract(callable_state, spec.canonical_name, args, field_specs);
    let result = match spec.implementation {
        BuiltinCallable::Count => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(value) = eval_typed_call_arg(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            match value {
                Value::List(items) => Value::Number(items.len() as f64),
                Value::Null => Value::Number(0.0),
                _ => Value::Number(1.0),
            }
        }
        BuiltinCallable::Len => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(value) = eval_typed_call_arg(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            match value {
                Value::String(value) => Value::Number(value.chars().count() as f64),
                Value::List(items) => Value::Number(items.len() as f64),
                Value::Null => Value::Null,
                _ => Value::Null,
            }
        }
        BuiltinCallable::Max => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(numbers) = eval_call_numeric_items(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            numbers
                .into_iter()
                .reduce(f64::max)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::Min => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(numbers) = eval_call_numeric_items(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            numbers
                .into_iter()
                .reduce(f64::min)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::Sum => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(numbers) = eval_call_numeric_items(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            Value::Number(numbers.into_iter().sum())
        }
        BuiltinCallable::Avg => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(numbers) = eval_call_numeric_items(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            if numbers.is_empty() {
                Value::Null
            } else {
                let total: f64 = numbers.iter().sum();
                Value::Number(total / numbers.len() as f64)
            }
        }
        BuiltinCallable::Distinct => {
            if args.len() != 1 {
                return Value::Null;
            }
            eval_call_distinct(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            )
        }
        BuiltinCallable::Rate => {
            if args.len() != 2 {
                return Value::Null;
            }
            let Some(value_key) = eval_call_arg_key(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Number(0.0);
            };
            let Some(window_ns) = eval_call_window_ns(
                spec.canonical_name,
                1,
                &args[1],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            let mut guard = match callable_state.lock() {
                Ok(guard) => guard,
                Err(_) => return Value::Number(0.0),
            };
            let key = (
                guard.host_scope.clone(),
                current_callable_rule_scope(),
                value_key,
                window_ns,
            );
            // Persist realtime timestamps so a restored window remains valid
            // across a host reboot (kernel monotonic time resets at boot).
            let observation_ns = event_realtime_ns(event.ts_ns).unwrap_or(event.ts_ns);
            let is_new = !guard.rate_observations.contains_key(&key);
            let count = {
                let observations = guard.rate_observations.entry(key.clone()).or_default();
                observations.push_back(observation_ns);
                let cutoff = observation_ns.saturating_sub(window_ns);
                while observations.front().is_some_and(|ts| *ts < cutoff) {
                    observations.pop_front();
                }
                observations.len()
            };
            if is_new {
                guard.remember_state_key(CallableStateKey::Rate(key));
            }
            guard.mark_mutation();
            Value::Number(count as f64)
        }
        BuiltinCallable::IsShell => {
            if args.len() != 1 {
                return Value::Null;
            }
            let candidate = eval_shell_candidate(
                spec.canonical_name,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            );
            let is_shell = matches!(
                candidate.as_deref(),
                Some("sh" | "bash" | "zsh" | "dash" | "fish")
            );
            Value::Bool(is_shell)
        }
        BuiltinCallable::Rare => {
            if args.len() != 1 {
                return Value::Null;
            }
            let Some(value_key) = eval_call_arg_key(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Bool(false);
            };
            let mut guard = match callable_state.lock() {
                Ok(guard) => guard,
                Err(_) => return Value::Bool(false),
            };
            let key = (
                guard.host_scope.clone(),
                current_callable_rule_scope(),
                value_key,
            );
            let prev = guard.rare_counts.get(&key).copied().unwrap_or(0);
            let is_new = prev == 0 && !guard.rare_counts.contains_key(&key);
            guard
                .rare_counts
                .insert(key.clone(), prev.saturating_add(1));
            if is_new {
                guard.remember_state_key(CallableStateKey::Rare(key));
            }
            guard.mark_mutation();
            Value::Bool(prev == 0)
        }
        BuiltinCallable::UnusualFor => {
            if args.len() != 2 {
                return Value::Null;
            }
            let Some(value_key) = eval_call_arg_key(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Bool(false);
            };
            let Some(entity_key) = eval_call_arg_key(
                spec.canonical_name,
                1,
                &args[1],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Bool(false);
            };
            let mut guard = match callable_state.lock() {
                Ok(guard) => guard,
                Err(_) => return Value::Bool(false),
            };
            let key = (
                guard.host_scope.clone(),
                current_callable_rule_scope(),
                entity_key,
                value_key,
            );
            let prev = guard
                .unusual_entity_value_counts
                .get(&key)
                .copied()
                .unwrap_or(0);
            let is_new = prev == 0 && !guard.unusual_entity_value_counts.contains_key(&key);
            guard
                .unusual_entity_value_counts
                .insert(key.clone(), prev.saturating_add(1));
            if is_new {
                guard.remember_state_key(CallableStateKey::Unusual(key));
            }
            guard.mark_mutation();
            Value::Bool(prev == 0)
        }
        BuiltinCallable::IntelDomains => {
            let Some(Value::String(feed)) = eval_typed_call_arg(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            resolve_intel_domain_feed(&feed)
                .map(|items| Value::List(items.into_iter().map(Value::String).collect()))
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::BaselineImage => {
            let Some(Value::String(image_id)) = eval_typed_call_arg(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            runtime_lookup_data(callable_state)
                .and_then(|lookup| lookup.images.get(image_id.trim()).cloned())
                .map(baseline_profile_value)
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::BaselineWorkload => {
            let Some(Value::String(namespace)) = eval_typed_call_arg(
                spec.canonical_name,
                0,
                &args[0],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            let Some(Value::String(name)) = eval_typed_call_arg(
                spec.canonical_name,
                1,
                &args[1],
                contract.as_ref(),
                event,
                field_specs,
                callable_state,
            ) else {
                return Value::Null;
            };
            let key = format!("{}/{}", namespace.trim(), name.trim());
            runtime_lookup_data(callable_state)
                .and_then(|lookup| lookup.workloads.get(&key).cloned())
                .map(baseline_profile_value)
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::Host => {
            let Some(key) = eval_lookup_key(&args[0], event, field_specs, callable_state) else {
                return Value::Null;
            };
            runtime_lookup_data(callable_state)
                .and_then(|lookup| lookup.hosts.get(&key).cloned())
                .map(host_lookup_value)
                .unwrap_or(Value::Null)
        }
        BuiltinCallable::User => {
            let Some(key) = eval_lookup_key(&args[0], event, field_specs, callable_state) else {
                return Value::Null;
            };
            runtime_lookup_data(callable_state)
                .and_then(|lookup| lookup.users.get(&key).cloned())
                .map(user_lookup_value)
                .unwrap_or(Value::Null)
        }
    };
    if let Some(expected) = contract
        .as_ref()
        .and_then(|contract| contract.returns.as_ref())
    {
        if !value_matches_callable_type(&result, None, expected, event, field_specs) {
            debug!(
                "runtime callable return type mismatch callable={} expected={:?} actual={:?}",
                spec.canonical_name, expected, result
            );
            return Value::Null;
        }
    }
    result
}

fn runtime_lookup_data(
    callable_state: &Mutex<CallableEvalState>,
) -> Option<Arc<RuntimeLookupArtifact>> {
    callable_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .lookup_data
        .clone()
}

fn eval_lookup_key(
    arg: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<String> {
    match eval_value(arg, event, field_specs, callable_state) {
        Value::String(value) => normalize_lookup_key(&value),
        Value::Number(value) if value.is_finite() => normalize_lookup_key(&value.to_string()),
        Value::Ip(value) => normalize_lookup_key(&Ipv4Addr::from(value).to_string()),
        _ => None,
    }
}

fn normalize_lookup_key(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn string_list_value(items: Vec<String>) -> Value {
    Value::List(items.into_iter().map(Value::String).collect())
}

fn baseline_profile_value(profile: RuntimeBaselineProfile) -> Value {
    Value::Object(HashMap::from([(
        "allowed_processes".to_string(),
        string_list_value(profile.allowed_processes),
    )]))
}

fn host_lookup_value(profile: RuntimeHostBaseline) -> Value {
    let baseline = Value::Object(HashMap::from([
        ("domains".to_string(), string_list_value(profile.domains)),
        ("ips".to_string(), string_list_value(profile.ips)),
        (
            "processes".to_string(),
            string_list_value(profile.processes),
        ),
        ("users".to_string(), string_list_value(profile.users)),
    ]));
    Value::Object(HashMap::from([("baseline".to_string(), baseline)]))
}

fn user_lookup_value(profile: RuntimeUserBaseline) -> Value {
    let baseline = Value::Object(HashMap::from([
        (
            "countries".to_string(),
            string_list_value(profile.countries),
        ),
        ("hosts".to_string(), string_list_value(profile.hosts)),
        ("geos".to_string(), string_list_value(profile.geos)),
        (
            "login_hours".to_string(),
            Value::List(
                profile
                    .login_hours
                    .into_iter()
                    .map(|value| Value::Number(value as f64))
                    .collect(),
            ),
        ),
    ]));
    Value::Object(HashMap::from([("baseline".to_string(), baseline)]))
}

fn resolve_intel_domain_feed(feed: &str) -> Option<Vec<String>> {
    let feed = feed.trim();
    if feed.is_empty() {
        return None;
    }
    [
        feed.to_string(),
        format!("intel.domains.{feed}"),
        format!("org.threat_intel.{feed}"),
    ]
    .into_iter()
    .find_map(|set_name| intel_store::string_set_items(&set_name))
}

fn callable_contract(
    callable_state: &Mutex<CallableEvalState>,
    canonical_name: &str,
    args: &[RuntimeExpr],
    field_specs: &[FieldSpec],
) -> Option<RuntimeCallable> {
    let contracts = callable_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contracts
        .get(canonical_name)
        .cloned()?;
    let mut best: Option<(&RuntimeCallable, usize)> = None;
    for contract in &contracts {
        let matches = contract.params.len() == args.len()
            && contract.params.iter().zip(args).all(|(param, arg)| {
                expr_matches_callable_type(arg, &param.value_type, field_specs, &contracts)
            });
        if !matches {
            continue;
        }
        let specificity = contract
            .params
            .iter()
            .map(|param| runtime_callable_type_specificity(&param.value_type))
            .sum();
        if best.is_none_or(|(_, best_specificity)| specificity > best_specificity) {
            best = Some((contract, specificity));
        }
    }
    best.map(|(contract, _)| contract.clone()).or_else(|| {
        contracts
            .iter()
            .find(|contract| contract.params.len() == args.len())
            .cloned()
    })
}

fn runtime_callable_type_specificity(value_type: &RuntimeCallableType) -> usize {
    match value_type {
        RuntimeCallableType::Any => 0,
        RuntimeCallableType::Set(inner) | RuntimeCallableType::Nullable(inner) => {
            1 + runtime_callable_type_specificity(inner)
        }
        _ => 4,
    }
}

fn expr_matches_callable_type(
    expr: &RuntimeExpr,
    value_type: &RuntimeCallableType,
    field_specs: &[FieldSpec],
    contracts: &[RuntimeCallable],
) -> bool {
    if matches!(value_type, RuntimeCallableType::Any) {
        return true;
    }
    if let RuntimeCallableType::Nullable(inner) = value_type {
        return matches!(expr, RuntimeExpr::Null)
            || expr_matches_callable_type(expr, inner, field_specs, contracts);
    }
    match expr {
        RuntimeExpr::Null => false,
        RuntimeExpr::Str { .. } => matches!(
            value_type,
            RuntimeCallableType::Str | RuntimeCallableType::Path | RuntimeCallableType::IpAddr
        ),
        RuntimeExpr::Int { .. } => matches!(
            value_type,
            RuntimeCallableType::Int | RuntimeCallableType::Float | RuntimeCallableType::Duration
        ),
        RuntimeExpr::Float { .. } => matches!(value_type, RuntimeCallableType::Float),
        RuntimeExpr::Duration { .. } => matches!(value_type, RuntimeCallableType::Duration),
        RuntimeExpr::Bool { .. }
        | RuntimeExpr::Eq { .. }
        | RuntimeExpr::Ne { .. }
        | RuntimeExpr::Lt { .. }
        | RuntimeExpr::Gt { .. }
        | RuntimeExpr::Le { .. }
        | RuntimeExpr::Ge { .. }
        | RuntimeExpr::In { .. }
        | RuntimeExpr::StartsWith { .. }
        | RuntimeExpr::EndsWith { .. }
        | RuntimeExpr::Contains { .. }
        | RuntimeExpr::Matches { .. }
        | RuntimeExpr::And { .. }
        | RuntimeExpr::Or { .. }
        | RuntimeExpr::Not { .. } => matches!(value_type, RuntimeCallableType::Bool),
        RuntimeExpr::List { items } => match value_type {
            RuntimeCallableType::Set(inner) => items
                .iter()
                .all(|item| expr_matches_callable_type(item, inner, field_specs, contracts)),
            _ => false,
        },
        RuntimeExpr::Field { path } => {
            lookup_field_spec(field_specs, path).is_some_and(|spec| {
                matches!(
                    (spec.value_type, value_type),
                    (FieldType::Bool, RuntimeCallableType::Bool)
                        | (FieldType::String, RuntimeCallableType::Str)
                        | (FieldType::String, RuntimeCallableType::Path)
                        | (FieldType::Number, RuntimeCallableType::Int)
                        | (FieldType::Number, RuntimeCallableType::Float)
                        | (FieldType::Number, RuntimeCallableType::Duration)
                        | (FieldType::Ip, RuntimeCallableType::IpAddr)
                        | (FieldType::List, RuntimeCallableType::Set(_))
                )
            }) || matches!(value_type, RuntimeCallableType::Entity(_))
        }
        RuntimeExpr::Call { name, .. } => contracts.iter().any(|contract| {
            contract.name.eq_ignore_ascii_case(name)
                && contract.returns.as_ref() == Some(value_type)
        }),
        // Projected result types are validated against the concrete value
        // after evaluation. The runtime artifact does not currently carry the
        // entity field schema needed to infer them here.
        RuntimeExpr::Project { .. } => true,
        RuntimeExpr::Add { .. }
        | RuntimeExpr::Sub { .. }
        | RuntimeExpr::Mul { .. }
        | RuntimeExpr::Div { .. } => matches!(
            value_type,
            RuntimeCallableType::Int | RuntimeCallableType::Float | RuntimeCallableType::Duration
        ),
        RuntimeExpr::Unsupported { .. } => false,
    }
}

fn eval_typed_call_arg(
    callable_name: &str,
    index: usize,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<Value> {
    let value = eval_value(arg, event, field_specs, callable_state);
    let Some(param) = contract.and_then(|contract| contract.params.get(index)) else {
        return Some(value);
    };
    if value_matches_callable_type(&value, Some(arg), &param.value_type, event, field_specs) {
        Some(value)
    } else {
        debug!(
            "runtime callable argument type mismatch callable={} parameter={} expected={:?} actual={:?}",
            callable_name, param.name, param.value_type, value
        );
        None
    }
}

fn value_matches_callable_type(
    value: &Value,
    expr: Option<&RuntimeExpr>,
    value_type: &RuntimeCallableType,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
) -> bool {
    match value_type {
        RuntimeCallableType::Any => true,
        RuntimeCallableType::Str | RuntimeCallableType::Path => {
            matches!(value, Value::String(_))
        }
        RuntimeCallableType::Int => {
            matches!(value, Value::Number(number) if number.is_finite() && number.fract() == 0.0)
        }
        RuntimeCallableType::Float => {
            matches!(value, Value::Number(number) if number.is_finite())
        }
        RuntimeCallableType::Bool => matches!(value, Value::Bool(_)),
        RuntimeCallableType::Duration => {
            matches!(value, Value::Number(number) if number.is_finite() && *number >= 0.0)
        }
        RuntimeCallableType::IpAddr => match value {
            Value::Ip(_) => true,
            Value::String(candidate) => parse_ipv4_literal(candidate).is_some(),
            _ => false,
        },
        RuntimeCallableType::Entity(name) => {
            matches!(value, Value::Object(_))
                || (name.eq_ignore_ascii_case("process")
                    && expr
                        .is_some_and(|expr| process_entity_is_available(expr, event, field_specs)))
        }
        RuntimeCallableType::Set(inner) => match value {
            Value::List(items) => items
                .iter()
                .all(|item| value_matches_callable_type(item, None, inner, event, field_specs)),
            _ => false,
        },
        RuntimeCallableType::Nullable(inner) => {
            matches!(value, Value::Null)
                || value_matches_callable_type(value, expr, inner, event, field_specs)
        }
    }
}

fn process_entity_is_available(
    expr: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
) -> bool {
    let RuntimeExpr::Field { path } = expr else {
        return false;
    };
    matches!(
        lookup_field(field_specs, &format!("{path}.name"), event),
        Value::String(name) if !name.trim().is_empty()
    )
}

fn eval_call_numeric_items(
    callable_name: &str,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<Vec<f64>> {
    let value = eval_typed_call_arg(
        callable_name,
        0,
        arg,
        contract,
        event,
        field_specs,
        callable_state,
    )?;
    match value {
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(num) = to_number(item) else {
                    return None;
                };
                out.push(num);
            }
            Some(out)
        }
        Value::Null => Some(Vec::new()),
        other => to_number(other).map(|num| vec![num]),
    }
}

fn eval_call_distinct(
    callable_name: &str,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Value {
    let Some(value) = eval_typed_call_arg(
        callable_name,
        0,
        arg,
        contract,
        event,
        field_specs,
        callable_state,
    ) else {
        return Value::Null;
    };
    match value {
        Value::List(items) => {
            let mut unique = Vec::with_capacity(items.len());
            for item in items {
                if !unique.contains(&item) {
                    unique.push(item);
                }
            }
            Value::List(unique)
        }
        Value::Null => Value::List(Vec::new()),
        other => Value::List(vec![other]),
    }
}

fn eval_call_window_ns(
    callable_name: &str,
    index: usize,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<u64> {
    let value = eval_typed_call_arg(
        callable_name,
        index,
        arg,
        contract,
        event,
        field_specs,
        callable_state,
    )?;
    let window_raw = to_number(value)?;
    if !window_raw.is_finite() || window_raw <= 0.0 || window_raw > u64::MAX as f64 {
        return None;
    }
    Some(window_raw.floor() as u64)
}

fn eval_call_arg_key(
    callable_name: &str,
    index: usize,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<String> {
    match eval_typed_call_arg(
        callable_name,
        index,
        arg,
        contract,
        event,
        field_specs,
        callable_state,
    )? {
        Value::Null => {
            if let RuntimeExpr::Field { path } = arg {
                let fallback_path = format!("{path}.name");
                if let Value::String(name) = lookup_field(field_specs, &fallback_path, event) {
                    return normalize_call_key(&name);
                }
            }
            None
        }
        Value::String(s) => normalize_call_key(&s),
        other => normalize_call_key(&to_string(other)),
    }
}

fn normalize_call_key(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn eval_shell_candidate(
    callable_name: &str,
    arg: &RuntimeExpr,
    contract: Option<&RuntimeCallable>,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Option<String> {
    match eval_typed_call_arg(
        callable_name,
        0,
        arg,
        contract,
        event,
        field_specs,
        callable_state,
    )? {
        Value::String(name) => return Some(name.to_ascii_lowercase()),
        Value::Null => {}
        other => {
            let rendered = to_string(other).trim().to_ascii_lowercase();
            if !rendered.is_empty() {
                return Some(rendered);
            }
        }
    }

    if let RuntimeExpr::Field { path } = arg {
        let name_path = format!("{path}.name");
        if let Value::String(name) = lookup_field(field_specs, &name_path, event) {
            let normalized = name.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                return Some(normalized);
            }
        }
    }

    None
}

fn value_as_bool(value: Value) -> bool {
    match value {
        Value::Bool(v) => v,
        Value::Number(v) => v != 0.0,
        Value::String(v) => !v.is_empty(),
        Value::Ip(v) => v != 0,
        Value::List(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
        Value::Null => false,
    }
}

// Evaluate expression in value context (bool/number/string/null).
/// Evaluate an expression in value context.
fn eval_value(
    expr: &RuntimeExpr,
    event: &IngestEvent,
    field_specs: &[FieldSpec],
    callable_state: &Mutex<CallableEvalState>,
) -> Value {
    match expr {
        RuntimeExpr::Bool { value } => Value::Bool(*value),
        RuntimeExpr::Null => Value::Null,
        RuntimeExpr::List { items } => Value::List(
            items
                .iter()
                .map(|item| eval_value(item, event, field_specs, callable_state))
                .collect(),
        ),
        RuntimeExpr::Int { value } => Value::Number(*value as f64),
        RuntimeExpr::Float { value } => Value::Number(*value),
        RuntimeExpr::Duration { value, unit } => duration_to_ns(*value, *unit)
            .map(|ns| Value::Number(ns as f64))
            .unwrap_or(Value::Null),
        RuntimeExpr::Str { value } => Value::String(value.clone()),
        RuntimeExpr::Field { path } => lookup_field(field_specs, path, event),
        RuntimeExpr::Call { name, args } => {
            eval_call(name, args, event, field_specs, callable_state)
        }
        RuntimeExpr::Project { base, field } => {
            match eval_value(base, event, field_specs, callable_state) {
                Value::Object(fields) => fields
                    .get(field)
                    .or_else(|| {
                        fields
                            .iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case(field))
                            .map(|(_, value)| value)
                    })
                    .cloned()
                    .unwrap_or(Value::Null),
                _ => Value::Null,
            }
        }
        RuntimeExpr::Add { lhs, rhs } => {
            eval_arithmetic(lhs, rhs, event, field_specs, callable_state, |a, b| {
                Some(a + b)
            })
        }
        RuntimeExpr::Sub { lhs, rhs } => {
            eval_arithmetic(lhs, rhs, event, field_specs, callable_state, |a, b| {
                Some(a - b)
            })
        }
        RuntimeExpr::Mul { lhs, rhs } => {
            eval_arithmetic(lhs, rhs, event, field_specs, callable_state, |a, b| {
                Some(a * b)
            })
        }
        RuntimeExpr::Div { lhs, rhs } => {
            eval_arithmetic(lhs, rhs, event, field_specs, callable_state, |a, b| {
                if b == 0.0 {
                    None
                } else {
                    Some(a / b)
                }
            })
        }
        RuntimeExpr::Eq { .. }
        | RuntimeExpr::Ne { .. }
        | RuntimeExpr::Lt { .. }
        | RuntimeExpr::Gt { .. }
        | RuntimeExpr::Le { .. }
        | RuntimeExpr::Ge { .. }
        | RuntimeExpr::In { .. }
        | RuntimeExpr::StartsWith { .. }
        | RuntimeExpr::EndsWith { .. }
        | RuntimeExpr::Contains { .. }
        | RuntimeExpr::Matches { .. }
        | RuntimeExpr::And { .. }
        | RuntimeExpr::Or { .. }
        | RuntimeExpr::Not { .. } => {
            Value::Bool(eval_bool(expr, event, field_specs, callable_state))
        }
        RuntimeExpr::Unsupported { .. } => Value::Null,
    }
}

// Resolve known event field names into runtime values.
/// Resolve field path aliases from `IngestEvent` into typed `Value`.
fn lookup_field(field_specs: &[FieldSpec], path: &str, event: &IngestEvent) -> Value {
    if let Some(value) = lookup_eval_binding(path) {
        return value;
    }
    if let Some(spec) = lookup_field_spec(field_specs, path) {
        let value = spec
            .extract
            .map(|extract| extract(event))
            .unwrap_or(Value::Null);
        debug_assert!(
            value_matches_field_type(&value, spec.value_type),
            "field '{}' produced value {:?} that mismatches declared type {:?}",
            spec.canonical,
            value,
            spec.value_type
        );
        value
    } else {
        Value::Null
    }
}

/// Resolve runtime field metadata by exact path or suffix alias.
fn lookup_field_spec<'a>(field_specs: &'a [FieldSpec], path: &str) -> Option<&'a FieldSpec> {
    let normalized = normalize_field_path(path);

    if let Some(exact) = field_specs.iter().find(|spec| spec.canonical == normalized) {
        return Some(exact);
    }

    field_specs
        .iter()
        .filter_map(|spec| {
            let best_alias_len = spec
                .aliases
                .iter()
                .filter(|alias| alias_matches_path(alias, &normalized))
                .map(|alias| alias.len())
                .max()?;
            Some((spec, best_alias_len))
        })
        .max_by(|(a_spec, a_len), (b_spec, b_len)| {
            a_len
                .cmp(b_len)
                .then_with(|| (a_spec.extract.is_some()).cmp(&(b_spec.extract.is_some())))
                .then_with(|| b_spec.canonical.cmp(&a_spec.canonical).reverse())
        })
        .map(|(spec, _)| spec)
}

/// Normalize incoming field path for case-insensitive matching.
fn normalize_field_path(path: &str) -> String {
    path.trim().to_ascii_lowercase()
}

/// Alias match that supports arbitrary source aliases (`p.pid`, `n.dest.port`).
fn alias_matches_path(alias: &str, normalized_path: &str) -> bool {
    if normalized_path == alias {
        return true;
    }
    if !normalized_path.ends_with(alias) {
        return false;
    }
    let boundary = normalized_path.len().saturating_sub(alias.len());
    boundary > 0 && normalized_path.as_bytes()[boundary - 1] == b'.'
}

/// Runtime debug helper that validates extracted value shape.
fn value_matches_field_type(value: &Value, value_type: FieldType) -> bool {
    matches!(
        (value, value_type),
        (Value::Bool(_), FieldType::Bool)
            | (Value::Number(_), FieldType::Number)
            | (Value::String(_), FieldType::String)
            | (Value::Ip(_), FieldType::Ip)
            | (Value::List(_), FieldType::List)
            | (Value::Null, _)
    )
}

fn field_ts_ns(event: &IngestEvent) -> Value {
    Value::Number(event.ts_ns as f64)
}

fn field_time_weekday(event: &IngestEvent) -> Value {
    event_local_time(event)
        .map(|t| Value::String(weekday_name(t.tm_wday).to_string()))
        .unwrap_or(Value::Null)
}

fn field_time_hour(event: &IngestEvent) -> Value {
    event_local_time(event)
        .map(|t| Value::Number(t.tm_hour as f64))
        .unwrap_or(Value::Null)
}

fn field_time_minute(event: &IngestEvent) -> Value {
    event_local_time(event)
        .map(|t| Value::Number(t.tm_min as f64))
        .unwrap_or(Value::Null)
}

fn field_time_business_hour(event: &IngestEvent) -> Value {
    event_local_time(event)
        .map(|t| Value::Bool(is_business_hour(&t)))
        .unwrap_or(Value::Bool(false))
}

fn field_pid(event: &IngestEvent) -> Value {
    Value::Number(event.pid as f64)
}

fn field_process_id(event: &IngestEvent) -> Value {
    Value::Number(event.pid as f64)
}

fn field_process_ppid(event: &IngestEvent) -> Value {
    if event.event_type == 1 {
        Value::Number(event.dst_vertex_id as f64)
    } else {
        Value::Null
    }
}

fn field_process_parent_id(event: &IngestEvent) -> Value {
    field_process_ppid(event)
}

fn field_uid(event: &IngestEvent) -> Value {
    Value::Number(event.uid as f64)
}

fn field_user_uid(event: &IngestEvent) -> Value {
    field_uid(event)
}

fn field_process_elevated(event: &IngestEvent) -> Value {
    Value::Bool(event.uid == 0)
}

fn field_cgroup_id(event: &IngestEvent) -> Value {
    if event.cgroup_id == 0 {
        Value::Null
    } else {
        Value::Number(event.cgroup_id as f64)
    }
}

fn field_container_id(event: &IngestEvent) -> Value {
    crate::cgroup::lookup(event.cgroup_id)
        .and_then(|metadata| metadata.container_id)
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn field_container_cgroup_path(event: &IngestEvent) -> Value {
    crate::cgroup::lookup(event.cgroup_id)
        .map(|metadata| Value::String(metadata.path))
        .unwrap_or(Value::Null)
}

fn field_container_pod_uid(event: &IngestEvent) -> Value {
    crate::cgroup::lookup(event.cgroup_id)
        .and_then(|metadata| metadata.pod_uid)
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn field_container_exists(event: &IngestEvent) -> Value {
    Value::Bool(
        crate::cgroup::lookup(event.cgroup_id)
            .and_then(|metadata| metadata.container_id)
            .is_some(),
    )
}

fn field_host_risk_score(event: &IngestEvent) -> Value {
    Value::Number(event.risk_score as f64)
}

fn field_host_id(_event: &IngestEvent) -> Value {
    Value::String(runtime_host_identity().0.clone())
}

fn field_hostname(_event: &IngestEvent) -> Value {
    Value::String(runtime_host_identity().1.clone())
}

fn runtime_host_identity() -> &'static (String, String) {
    static IDENTITY: OnceLock<(String, String)> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "agent-local".to_string());
        let host_id = std::env::var("OLOPA_INGEST_HOST_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| hostname.clone());
        (host_id, hostname)
    })
}

fn secure_connect_is_active(state: crate::secure_connect::SessionState) -> bool {
    matches!(
        state,
        crate::secure_connect::SessionState::Healthy
            | crate::secure_connect::SessionState::Elevated
            | crate::secure_connect::SessionState::Restricted
    )
}

fn field_secure_connect_enabled(_event: &IngestEvent) -> Value {
    Value::Bool(crate::secure_connect::current_health().enabled)
}

fn field_secure_connect_id(_event: &IngestEvent) -> Value {
    crate::secure_connect::current_health()
        .session_id
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn field_secure_connect_active(_event: &IngestEvent) -> Value {
    Value::Bool(secure_connect_is_active(
        crate::secure_connect::current_health().state,
    ))
}

fn field_secure_connect_state(_event: &IngestEvent) -> Value {
    let health = crate::secure_connect::current_health();
    if !health.enabled {
        return Value::Null;
    }
    Value::String(format!("{:?}", health.state).to_ascii_lowercase())
}

fn field_secure_connect_handshake_age(_event: &IngestEvent) -> Value {
    let handshake = crate::secure_connect::current_health().last_handshake_unix;
    if handshake == 0 {
        return Value::Null;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Value::Number(now.saturating_sub(handshake).saturating_mul(1_000_000_000) as f64)
}

fn field_secure_connect_rx_bytes(_event: &IngestEvent) -> Value {
    Value::Number(crate::secure_connect::current_health().bytes_rx as f64)
}

fn field_secure_connect_tx_bytes(_event: &IngestEvent) -> Value {
    Value::Number(crate::secure_connect::current_health().bytes_tx as f64)
}

fn field_event_type(event: &IngestEvent) -> Value {
    Value::Number(event.event_type as f64)
}

fn field_vertex_id(event: &IngestEvent) -> Value {
    Value::Number(event.vertex_id as f64)
}

fn field_dst_vertex_id(event: &IngestEvent) -> Value {
    Value::Number(event.dst_vertex_id as f64)
}

fn field_process_name(event: &IngestEvent) -> Value {
    Value::String(event_comm(event))
}

fn field_comm_id(event: &IngestEvent) -> Value {
    Value::Number(event.comm_id as f64)
}

fn field_risk_score(event: &IngestEvent) -> Value {
    Value::Number(event.risk_score as f64)
}

fn field_network_direction(event: &IngestEvent) -> Value {
    if matches!(event.event_type, 3 | 7) {
        Value::String("outbound".to_string())
    } else {
        Value::Null
    }
}

fn field_network_tunneled(event: &IngestEvent) -> Value {
    if !matches!(event.event_type, 3 | 7) {
        return Value::Null;
    }
    Value::Bool(secure_connect_is_active(
        crate::secure_connect::current_health().state,
    ))
}

fn field_network_process_id(event: &IngestEvent) -> Value {
    if matches!(event.event_type, 3 | 7) {
        Value::Number(event.pid as f64)
    } else {
        Value::Null
    }
}

fn field_network_dest_ip(event: &IngestEvent) -> Value {
    if matches!(event.event_type, 3 | 7) && event.net_dst_ip != 0 {
        Value::Ip(event.net_dst_ip)
    } else {
        Value::Null
    }
}

fn field_network_dest_port(event: &IngestEvent) -> Value {
    if matches!(event.event_type, 3 | 7) {
        Value::Number(event.net_dst_port as f64)
    } else {
        Value::Null
    }
}

fn field_network_dest_is_internal(event: &IngestEvent) -> Value {
    if !matches!(event.event_type, 3 | 7) || event.net_dst_ip == 0 {
        return Value::Null;
    }
    let ip = Ipv4Addr::from(event.net_dst_ip);
    Value::Bool(ip.is_private() || ip.is_loopback() || ip.is_link_local())
}

fn field_file_process_id(event: &IngestEvent) -> Value {
    if event.event_type == 2 {
        Value::Number(event.pid as f64)
    } else {
        Value::Null
    }
}

// SQL field extractors — only meaningful when event_type == 4.

fn field_db_pid(event: &IngestEvent) -> Value {
    event_family_number(event, 4, event.pid)
}

fn field_db_uid(event: &IngestEvent) -> Value {
    event_family_number(event, 4, event.uid)
}

fn field_db_process_name(event: &IngestEvent) -> Value {
    event_family_process_name(event, 4)
}

fn field_sql_query_hash(event: &IngestEvent) -> Value {
    if event.event_type == 4 {
        Value::Number(event.sql_query_hash as f64)
    } else {
        Value::Null
    }
}

fn field_sql_query_class(event: &IngestEvent) -> Value {
    if event.event_type == 4 {
        Value::Number(event.sql_query_class as f64)
    } else {
        Value::Null
    }
}

fn field_sql_db_port(event: &IngestEvent) -> Value {
    if event.event_type == 4 {
        Value::Number(event.sql_db_port as f64)
    } else {
        Value::Null
    }
}

/// Bare table names touched by the statement, for `sql.tables contains "x"`.
///
/// Names come from [`crate::sql_norm::unpack_tables`], the same split that
/// fills the outbound `DbQueryEvent`, so a rule matches exactly the name the
/// stored row shows. A statement whose tables could not be resolved yields an
/// empty list rather than `Null`: it is a SQL event with no tables, not a
/// missing field, and `contains` should simply not match it.
fn field_sql_tables(event: &IngestEvent) -> Value {
    if event.event_type != 4 {
        return Value::Null;
    }

    Value::List(
        crate::sql_norm::unpack_tables_bytes(&event.sql_tables)
            .tables
            .into_iter()
            .map(Value::String)
            .collect(),
    )
}

/// Database/schema the statement targets, when every qualified reference in it
/// agrees on one. A cross-database join yields `Null`.
fn field_sql_database(event: &IngestEvent) -> Value {
    if event.event_type != 4 {
        return Value::Null;
    }

    match crate::sql_norm::unpack_tables_bytes(&event.sql_tables).database {
        Some(database) => Value::String(database),
        None => Value::Null,
    }
}

// SSL field extractors — only meaningful when event_type == 5.

fn field_ssl_pid(event: &IngestEvent) -> Value {
    event_family_number(event, 5, event.pid)
}

fn field_ssl_uid(event: &IngestEvent) -> Value {
    event_family_number(event, 5, event.uid)
}

fn field_ssl_process_name(event: &IngestEvent) -> Value {
    event_family_process_name(event, 5)
}

fn field_ssl_data_len(event: &IngestEvent) -> Value {
    if event.event_type == 5 {
        Value::Number(event.ssl_data_len as f64)
    } else {
        Value::Null
    }
}

fn field_ssl_operation(event: &IngestEvent) -> Value {
    if event.event_type == 5 {
        Value::Number(event.ssl_operation as f64)
    } else {
        Value::Null
    }
}

// DNS field extractors — only meaningful when event_type == 6.

fn field_dns_pid(event: &IngestEvent) -> Value {
    event_family_number(event, 6, event.pid)
}

fn field_dns_uid(event: &IngestEvent) -> Value {
    event_family_number(event, 6, event.uid)
}

fn field_dns_process_name(event: &IngestEvent) -> Value {
    event_family_process_name(event, 6)
}

fn event_family_number(event: &IngestEvent, event_type: u8, value: u32) -> Value {
    if event.event_type == event_type {
        Value::Number(value as f64)
    } else {
        Value::Null
    }
}

fn event_family_process_name(event: &IngestEvent, event_type: u8) -> Value {
    if event.event_type == event_type {
        Value::String(event_comm(event))
    } else {
        Value::Null
    }
}

fn dns_query(event: &IngestEvent) -> Option<&str> {
    if event.event_type != 6 {
        return None;
    }

    let end = event
        .dns_query
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(event.dns_query.len());
    std::str::from_utf8(&event.dns_query[..end]).ok()
}

fn field_dns_domain_value(event: &IngestEvent) -> Value {
    match dns_query(event) {
        Some(query) => Value::String(query.to_string()),
        None => Value::Null,
    }
}

fn field_dns_query_hash(event: &IngestEvent) -> Value {
    if event.event_type == 6 {
        Value::Number(event.dns_query_hash as f64)
    } else {
        Value::Null
    }
}

/// Shannon entropy, in bits per byte, of the hostname captured by the DNS
/// uprobe. Empty or invalid hostnames have no meaningful entropy.
fn field_dns_domain_entropy(event: &IngestEvent) -> Value {
    let Some(query) = dns_query(event).filter(|query| !query.is_empty()) else {
        return Value::Null;
    };

    let mut counts = [0usize; 256];
    for byte in query.bytes() {
        counts[byte as usize] += 1;
    }

    let len = query.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum();
    Value::Number(entropy)
}

// Convert Value into number if possible.
/// Convert typed value into numeric representation when possible.
fn to_number(value: Value) -> Option<f64> {
    match value {
        Value::Number(v) => Some(v),
        Value::Bool(v) => Some(if v { 1.0 } else { 0.0 }),
        Value::String(v) => v.parse::<f64>().ok(),
        Value::Ip(v) => Some(v as f64),
        Value::List(_) => None,
        Value::Object(_) => None,
        Value::Null => None,
    }
}

// Convert Value into string for string operations.
/// Convert typed value into display/string form for string operators.
fn to_string(value: Value) -> String {
    match value {
        Value::String(v) => v,
        Value::Ip(v) => Ipv4Addr::from(v).to_string(),
        Value::Number(v) => v.to_string(),
        Value::Bool(v) => {
            if v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::List(items) => {
            let rendered = items
                .into_iter()
                .map(to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{rendered}]")
        }
        Value::Object(_) => String::new(),
        Value::Null => String::new(),
    }
}

/// Evaluate `matches` against a runtime value using a lightweight pattern engine.
///
/// Supported forms:
/// - wildcard literals: `*` (zero or more), `?` (single char)
/// - grouped alternation produced by parser list patterns: `(a|b|c)`
fn value_matches_pattern(value: Value, pattern: &str) -> bool {
    let candidate = to_string(value);
    pattern_matches(&candidate, pattern)
}

fn pattern_matches(candidate: &str, pattern: &str) -> bool {
    if let Some(parts) = parse_grouped_alternation(pattern) {
        return parts.iter().any(|p| wildcard_match(candidate, p));
    }
    wildcard_match(candidate, pattern)
}

/// Parse simple top-level alternation group `(a|b|c)` with `\` escaping.
fn parse_grouped_alternation(pattern: &str) -> Option<Vec<String>> {
    let trimmed = pattern.trim();
    if !(trimmed.starts_with('(') && trimmed.ends_with(')')) {
        return None;
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' => {
                parts.push(cur);
                cur = String::new();
            }
            _ => cur.push(ch),
        }
    }
    if escaped {
        cur.push('\\');
    }
    parts.push(cur);

    if parts.len() < 2 {
        return None;
    }

    Some(
        parts
            .into_iter()
            .map(|p| unescape_pattern_part(&p))
            .collect(),
    )
}

fn unescape_pattern_part(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
}

/// Glob-like wildcard matcher used by runtime `matches`.
fn wildcard_match(candidate: &str, pattern: &str) -> bool {
    wildcard_match_bytes(candidate.as_bytes(), pattern.as_bytes())
}

fn wildcard_match_bytes(candidate: &[u8], pattern: &[u8]) -> bool {
    let mut ci = 0usize;
    let mut pi = 0usize;
    let mut star_pat_idx: Option<usize> = None;
    let mut star_candidate_idx = 0usize;

    while ci < candidate.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                b'?' => {
                    ci += 1;
                    pi += 1;
                    continue;
                }
                b'*' => {
                    star_pat_idx = Some(pi);
                    star_candidate_idx = ci;
                    pi += 1;
                    continue;
                }
                b'\\' if pi + 1 < pattern.len() && pattern[pi + 1] == candidate[ci] => {
                    ci += 1;
                    pi += 2;
                    continue;
                }
                literal if literal == candidate[ci] => {
                    ci += 1;
                    pi += 1;
                    continue;
                }
                _ => {}
            }
        }

        if let Some(star_idx) = star_pat_idx {
            pi = star_idx + 1;
            star_candidate_idx += 1;
            ci = star_candidate_idx;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Decode null-terminated process `comm` bytes into UTF-8 string.
fn event_comm(event: &IngestEvent) -> String {
    let end = event
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(event.comm.len());
    String::from_utf8_lossy(&event.comm[..end]).to_string()
}

/// Convert event timestamp into local broken-down time.
fn event_local_time(event: &IngestEvent) -> Option<libc::tm> {
    let realtime_ns = event_realtime_ns(event.ts_ns)?;
    let secs = realtime_ns / 1_000_000_000;
    let mut epoch: libc::time_t = secs.try_into().ok()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: localtime_r initializes `tm` when non-null pointer is returned.
    let ok = unsafe { libc::localtime_r(&mut epoch, tm.as_mut_ptr()) };
    if ok.is_null() {
        None
    } else {
        // SAFETY: `localtime_r` returned non-null and populated `tm`.
        Some(unsafe { tm.assume_init() })
    }
}

// Kernel probes emit `bpf_ktime_get_ns()` (monotonic since boot).
// Convert that to wall-clock nanoseconds using a startup anchor so
// weekday/hour rules evaluate against real local time.
/// Convert probe timestamp to realtime nanoseconds.
fn event_realtime_ns(ts_ns: u64) -> Option<u64> {
    // If we already have epoch-like ns (e.g. tests or future probe change),
    // use it directly.
    if ts_ns >= EPOCH_NS_MIN_2000 {
        return Some(ts_ns);
    }

    let anchor = CLOCK_ANCHOR
        .get_or_init(capture_clock_anchor)
        .as_ref()
        .copied()?;
    let delta = ts_ns as i128 - anchor.monotonic_ns as i128;
    let realtime = anchor.realtime_ns as i128 + delta;
    if realtime <= 0 {
        None
    } else {
        Some(realtime as u64)
    }
}

/// Capture startup anchor used for monotonic->realtime conversion.
fn capture_clock_anchor() -> Option<ClockAnchor> {
    Some(ClockAnchor {
        monotonic_ns: read_clock_ns(libc::CLOCK_MONOTONIC)?,
        realtime_ns: read_clock_ns(libc::CLOCK_REALTIME)?,
    })
}

/// Read nanoseconds from specified Linux clock id.
fn read_clock_ns(clock_id: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes to provided valid pointer.
    let rc = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return None;
    }
    let sec_ns = (ts.tv_sec as u128).saturating_mul(1_000_000_000);
    let ns = sec_ns.saturating_add(ts.tv_nsec as u128);
    u64::try_from(ns).ok()
}

/// Map libc weekday integer to lowercase weekday name.
fn weekday_name(wday: libc::c_int) -> &'static str {
    match wday {
        0 => "sunday",
        1 => "monday",
        2 => "tuesday",
        3 => "wednesday",
        4 => "thursday",
        5 => "friday",
        6 => "saturday",
        _ => "unknown",
    }
}

/// True for Monday-Friday between 09:00 and 16:59 (local time).
fn is_business_hour(tm: &libc::tm) -> bool {
    // Monday-Friday + 09:00..16:59 local time.
    (1..=5).contains(&tm.tm_wday) && (9..17).contains(&tm.tm_hour)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_runtime_ir_path() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("olopa_runtime_ir_test_{ts}.json"))
    }

    fn temp_runtime_ir_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("olopa_runtime_ir_dir_{ts}"))
    }

    fn fallback_field_specs() -> Vec<FieldSpec> {
        build_field_specs(&RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: Vec::new(),
        })
    }

    fn engine_from_program(program: RuntimeProgram) -> RuntimeIrRuleEngine {
        let contracts = group_runtime_callables(&program.callables);
        RuntimeIrRuleEngine {
            field_specs: build_field_specs(&program),
            rule_execution: HashMap::new(),
            callable_state: Arc::new(Mutex::new(CallableEvalState {
                contracts,
                ..CallableEvalState::default()
            })),
            program,
        }
    }

    #[test]
    fn evaluates_numeric_rule() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r1".to_string(),
                name: "r1".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field {
                        path: "pid".to_string(),
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 42 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r1");
        assert!(!matches[0].enforce_block_egress);
    }

    #[test]
    fn evaluates_duration_literal_comparison_rule() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-duration".to_string(),
                name: "r-duration".to_string(),
                predicates: vec![RuntimeExpr::Gt {
                    lhs: Box::new(RuntimeExpr::Field {
                        path: "event.ts_ns".to_string(),
                    }),
                    rhs: Box::new(RuntimeExpr::Duration {
                        value: 1,
                        unit: RuntimeDurationUnit::S,
                    }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 2_000_000_000,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-duration");
    }

    #[test]
    fn evaluates_arithmetic_expression_rule() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-arith".to_string(),
                name: "r-arith".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Add {
                        lhs: Box::new(RuntimeExpr::Field {
                            path: "pid".to_string(),
                        }),
                        rhs: Box::new(RuntimeExpr::Int { value: 8 }),
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 50 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-arith");
    }

    #[test]
    fn evaluates_count_call_rule() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-count".to_string(),
                name: "r-count".to_string(),
                predicates: vec![RuntimeExpr::Gt {
                    lhs: Box::new(RuntimeExpr::Call {
                        name: "count".to_string(),
                        args: vec![RuntimeExpr::List {
                            items: vec![
                                RuntimeExpr::Str {
                                    value: "a".to_string(),
                                },
                                RuntimeExpr::Str {
                                    value: "b".to_string(),
                                },
                                RuntimeExpr::Str {
                                    value: "c".to_string(),
                                },
                            ],
                        }],
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 2 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-count");
    }

    #[test]
    fn evaluates_len_call_for_unicode_strings_and_lists() {
        let event = IngestEvent::default();
        let field_specs = fallback_field_specs();
        let state = Mutex::new(CallableEvalState::default());

        let string_len = eval_call(
            "len",
            &[RuntimeExpr::Str {
                value: "tést".to_string(),
            }],
            &event,
            &field_specs,
            &state,
        );
        assert_eq!(string_len, Value::Number(4.0));

        let list_len = eval_call(
            "len",
            &[RuntimeExpr::List {
                items: vec![RuntimeExpr::Int { value: 1 }, RuntimeExpr::Int { value: 2 }],
            }],
            &event,
            &field_specs,
            &state,
        );
        assert_eq!(list_len, Value::Number(2.0));
    }

    #[test]
    fn evaluates_numeric_aggregate_call_rules() {
        let aggregate_list = RuntimeExpr::List {
            items: vec![
                RuntimeExpr::Int { value: 1 },
                RuntimeExpr::Int { value: 3 },
                RuntimeExpr::Int { value: 2 },
            ],
        };
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![
                RuntimeRule {
                    id: "r-max".to_string(),
                    name: "r-max".to_string(),
                    predicates: vec![RuntimeExpr::Eq {
                        lhs: Box::new(RuntimeExpr::Call {
                            name: "max".to_string(),
                            args: vec![aggregate_list.clone()],
                        }),
                        rhs: Box::new(RuntimeExpr::Int { value: 3 }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "r-min".to_string(),
                    name: "r-min".to_string(),
                    predicates: vec![RuntimeExpr::Eq {
                        lhs: Box::new(RuntimeExpr::Call {
                            name: "min".to_string(),
                            args: vec![aggregate_list.clone()],
                        }),
                        rhs: Box::new(RuntimeExpr::Int { value: 1 }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "r-sum".to_string(),
                    name: "r-sum".to_string(),
                    predicates: vec![RuntimeExpr::Eq {
                        lhs: Box::new(RuntimeExpr::Call {
                            name: "sum".to_string(),
                            args: vec![aggregate_list.clone()],
                        }),
                        rhs: Box::new(RuntimeExpr::Int { value: 6 }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "r-avg".to_string(),
                    name: "r-avg".to_string(),
                    predicates: vec![RuntimeExpr::Eq {
                        lhs: Box::new(RuntimeExpr::Call {
                            name: "avg".to_string(),
                            args: vec![aggregate_list],
                        }),
                        rhs: Box::new(RuntimeExpr::Float { value: 2.0 }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
            ],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 4);
        assert!(matches.iter().any(|m| m.rule_id == "r-max"));
        assert!(matches.iter().any(|m| m.rule_id == "r-min"));
        assert!(matches.iter().any(|m| m.rule_id == "r-sum"));
        assert!(matches.iter().any(|m| m.rule_id == "r-avg"));
    }

    #[test]
    fn evaluates_distinct_call_with_count() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-distinct-count".to_string(),
                name: "r-distinct-count".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Call {
                        name: "count".to_string(),
                        args: vec![RuntimeExpr::Call {
                            name: "distinct".to_string(),
                            args: vec![RuntimeExpr::List {
                                items: vec![
                                    RuntimeExpr::Str {
                                        value: "bash".to_string(),
                                    },
                                    RuntimeExpr::Str {
                                        value: "bash".to_string(),
                                    },
                                    RuntimeExpr::Str {
                                        value: "sh".to_string(),
                                    },
                                ],
                            }],
                        }],
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 2 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 9000,
            uid: 0,
            event_type: 1,
            vertex_id: 9000,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-distinct-count");
    }

    #[test]
    fn evaluates_rate_call_over_sliding_window_by_key() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-rate".to_string(),
                name: "r-rate".to_string(),
                predicates: vec![RuntimeExpr::Ge {
                    lhs: Box::new(RuntimeExpr::Call {
                        name: "rate".to_string(),
                        args: vec![
                            RuntimeExpr::Field {
                                path: "p.name".to_string(),
                            },
                            RuntimeExpr::Duration {
                                value: 30,
                                unit: RuntimeDurationUnit::S,
                            },
                        ],
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 2 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let mut bash = [0u8; 16];
        bash[..4].copy_from_slice(b"bash");
        let mut sh = [0u8; 16];
        sh[..2].copy_from_slice(b"sh");

        let event1 = IngestEvent {
            ts_ns: 5_000_000_000,
            pid: 100,
            uid: 0,
            event_type: 1,
            vertex_id: 100,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: bash,
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        assert!(
            engine.evaluate_matches(&event1).is_empty(),
            "first key observation should be below threshold"
        );

        let event2 = IngestEvent {
            ts_ns: 10_000_000_000,
            comm: sh,
            ..event1
        };
        assert!(
            engine.evaluate_matches(&event2).is_empty(),
            "different key should maintain an independent rate bucket"
        );

        let event3 = IngestEvent {
            ts_ns: 20_000_000_000,
            comm: bash,
            ..event1
        };
        let matches3 = engine.evaluate_matches(&event3);
        assert_eq!(matches3.len(), 1);
        assert_eq!(matches3[0].rule_id, "r-rate");

        let event4 = IngestEvent {
            ts_ns: 70_000_000_000,
            comm: bash,
            ..event1
        };
        assert!(
            engine.evaluate_matches(&event4).is_empty(),
            "older observations should age out of the sliding window"
        );
    }

    #[test]
    fn evaluates_is_shell_call_rule_with_alias_argument() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: vec![RuntimeCallable {
                name: "is_shell".to_string(),
                params: vec![RuntimeCallableParam {
                    name: "process".to_string(),
                    value_type: RuntimeCallableType::Entity("Process".to_string()),
                }],
                returns: Some(RuntimeCallableType::Bool),
            }],
            rules: vec![RuntimeRule {
                id: "r-shell".to_string(),
                name: "r-shell".to_string(),
                predicates: vec![RuntimeExpr::Call {
                    name: "is_shell".to_string(),
                    args: vec![RuntimeExpr::Field {
                        path: "p".to_string(),
                    }],
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-shell");
    }

    #[test]
    fn evaluates_rare_call_as_first_seen_value_only() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-rare".to_string(),
                name: "r-rare".to_string(),
                predicates: vec![RuntimeExpr::Call {
                    name: "rare".to_string(),
                    args: vec![RuntimeExpr::Field {
                        path: "process.name".to_string(),
                    }],
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let first = IngestEvent {
            ts_ns: 0,
            pid: 1,
            uid: 0,
            event_type: 1,
            vertex_id: 1,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let first_matches = engine.evaluate_matches(&first);
        assert_eq!(first_matches.len(), 1);
        assert_eq!(first_matches[0].rule_id, "r-rare");

        let second_matches = engine.evaluate_matches(&first);
        assert!(
            second_matches.is_empty(),
            "second observation should not be rare"
        );
    }

    #[test]
    fn evaluates_unusual_for_as_entity_scoped_novelty() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-unusual-for".to_string(),
                name: "r-unusual-for".to_string(),
                predicates: vec![RuntimeExpr::Call {
                    name: "unusual_for".to_string(),
                    args: vec![
                        RuntimeExpr::Field {
                            path: "process.name".to_string(),
                        },
                        RuntimeExpr::Field {
                            path: "process.uid".to_string(),
                        },
                    ],
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let mut bash = [0u8; 16];
        bash[..4].copy_from_slice(b"bash");
        let first = IngestEvent {
            ts_ns: 0,
            pid: 1,
            uid: 1001,
            event_type: 1,
            vertex_id: 1,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: bash,
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };

        let first_matches = engine.evaluate_matches(&first);
        assert_eq!(first_matches.len(), 1);

        let second_matches = engine.evaluate_matches(&first);
        assert!(
            second_matches.is_empty(),
            "repeat value for same entity should not remain unusual"
        );

        let mut zsh = [0u8; 16];
        zsh[..3].copy_from_slice(b"zsh");
        let new_value_same_entity = IngestEvent { comm: zsh, ..first };
        let third_matches = engine.evaluate_matches(&new_value_same_entity);
        assert_eq!(
            third_matches.len(),
            1,
            "new value for same entity should be unusual"
        );
    }

    #[test]
    fn division_by_zero_evaluates_to_null() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-div-zero".to_string(),
                name: "r-div-zero".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Div {
                        lhs: Box::new(RuntimeExpr::Int { value: 1 }),
                        rhs: Box::new(RuntimeExpr::Int { value: 0 }),
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 0 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert!(matches.is_empty());
    }

    #[test]
    fn evaluates_null_literal_rule_against_missing_field() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "r-null".to_string(),
                name: "r-null".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field {
                        path: "unknown.field".to_string(),
                    }),
                    rhs: Box::new(RuntimeExpr::Null),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "r-null");
    }

    #[test]
    fn detects_time_context_usage_in_rule_predicates() {
        let field_specs = fallback_field_specs();
        let rule = RuntimeRule {
            id: "r1".to_string(),
            name: "time_rule".to_string(),
            predicates: vec![RuntimeExpr::And {
                lhs: Box::new(RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Field {
                        path: "time.weekday".to_string(),
                    }),
                    rhs: Box::new(RuntimeExpr::Str {
                        value: "monday".to_string(),
                    }),
                }),
                rhs: Box::new(RuntimeExpr::Ge {
                    lhs: Box::new(RuntimeExpr::Field {
                        path: "time.hour".to_string(),
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 9 }),
                }),
            }],
            respond: RuntimeRespondPlan::default(),
        };
        assert!(rule_uses_time_context(&rule, &field_specs));
    }

    #[test]
    fn does_not_flag_non_time_predicates_as_time_context() {
        let field_specs = fallback_field_specs();
        let rule = RuntimeRule {
            id: "r1".to_string(),
            name: "pid_rule".to_string(),
            predicates: vec![RuntimeExpr::Eq {
                lhs: Box::new(RuntimeExpr::Field {
                    path: "p.pid".to_string(),
                }),
                rhs: Box::new(RuntimeExpr::Int { value: 42 }),
            }],
            respond: RuntimeRespondPlan::default(),
        };
        assert!(!rule_uses_time_context(&rule, &field_specs));
    }

    #[test]
    fn loads_oilc_runtime_ir_json_file_and_matches_rule() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:pid_42",
      "name": "pid_42",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "pid" },
          "rhs": { "op": "int", "value": 42 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "rule:0:pid_42");
        assert_eq!(matches[0].rule_name, "pid_42");
        assert!(!matches[0].enforce_block_egress);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_multi_unit_runtime_ir_and_merges_rules() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "units": [
    {
      "id": "unit-a",
      "program": {
        "version": 1,
        "rules": [
          {
            "id": "rule:pid_42",
            "name": "pid_42",
            "predicates": [
              {
                "op": "eq",
                "lhs": { "op": "field", "path": "pid" },
                "rhs": { "op": "int", "value": 42 }
              }
            ]
          }
        ]
      }
    },
    {
      "id": "unit-b",
      "program": {
        "version": 1,
        "rules": [
          {
            "id": "rule:uid_7",
            "name": "uid_7",
            "predicates": [
              {
                "op": "eq",
                "lhs": { "op": "field", "path": "uid" },
                "rhs": { "op": "int", "value": 7 }
              }
            ]
          }
        ]
      }
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        assert_eq!(engine.rule_count(), 2);

        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 7,
            event_type: 1,
            vertex_id: 0,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].rule_id, "rule:pid_42");
        assert_eq!(matches[1].rule_id, "rule:uid_7");
        assert!(!matches[0].enforce_block_egress);
        assert!(!matches[1].enforce_block_egress);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_runtime_ir_emitted_by_oilc_cli_and_matches() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source_path = dir.join("rule.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");
        let src = r#"
rule "pid_42" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 42
  respond alert high
}
"#;
        fs::write(&source_path, src).expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root");
        let oilc_manifest = repo_root.join("oilc").join("Cargo.toml");

        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&oilc_manifest)
            .arg("--")
            .arg("--source")
            .arg(&source_path)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 1,
            vertex_id: 0,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "pid_42");
        assert!(!matches[0].enforce_block_egress);

        let _ = fs::remove_dir_all(dir);
    }

    /// SQL rules must survive the trip through the real compiler.
    ///
    /// The stdlib schema names the SQL root `db`, so oilc emits `db.query_class`
    /// and `db.tables` — not the `sql.*` spellings the agent's fallback metadata
    /// uses. When only `sql.*` had extractors, every compiled SQL rule resolved
    /// to Null and quietly never fired, which no unit test caught because they
    /// all fed hand-written IR. This one goes through `oilc` itself.
    #[test]
    fn oilc_compiled_sql_rules_resolve_their_fields_and_fire() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source_path = dir.join("sql.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");
        let src = r#"
rule "ddl_on_ledger" {
  from db.query
  correlate db.query as q
  where q.query_class == 3 and q.tables contains "ledger"
  respond alert high
}
"#;
        fs::write(&source_path, src).expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root");

        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(repo_root.join("oilc").join("Cargo.toml"))
            .arg("--")
            .arg("--source")
            .arg(&source_path)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");

        let mut hit = sql_event_for("DROP TABLE finance.ledger");
        hit.sql_query_class = 3;
        let matches = engine.evaluate_matches(&hit);
        assert_eq!(
            matches.len(),
            1,
            "compiled SQL rule did not fire — its fields resolved to Null"
        );
        assert_eq!(matches[0].rule_name, "ddl_on_ledger");

        // Right table, wrong statement class.
        let mut wrong_class = sql_event_for("SELECT * FROM finance.ledger");
        wrong_class.sql_query_class = 1;
        assert!(engine.evaluate_matches(&wrong_class).is_empty());

        // Right class, wrong table.
        let mut wrong_table = sql_event_for("DROP TABLE finance.invoices");
        wrong_table.sql_query_class = 3;
        assert!(engine.evaluate_matches(&wrong_table).is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    /// Process identity on the SQL root must resolve too. The shipped rules in
    /// `oilc/src/rules/sql_suspicious_ops.oil` correlate on `q.pid`, and
    /// `q.process_name` is the natural way to scope a rule to one client.
    #[test]
    fn sql_root_process_identity_fields_resolve() {
        for path in ["db.pid", "db.uid", "db.process_name"] {
            assert!(
                lookup_field_extractor(path).is_some(),
                "{path} has no extractor — a rule using it resolves to Null"
            );
        }

        let event = sql_event_for("SELECT * FROM finance.ledger");
        assert!(matches!(
            lookup_field_extractor("db.pid").expect("extractor")(&event),
            Value::Number(n) if n == event.pid as f64
        ));
        assert!(matches!(
            lookup_field_extractor("db.process_name").expect("extractor")(&event),
            Value::String(ref s) if s == "psql"
        ));
    }

    /// Compiler-emitted SSL and DNS paths must bind to their concrete event
    /// families. This also exercises fields used by the shipped detection
    /// rules (`s.pid`, `q.pid`, and `q.domain.entropy`).
    #[test]
    fn oilc_compiled_ssl_and_dns_fields_resolve_and_fire() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source_path = dir.join("ssl_dns.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");
        let src = r#"
rule "ssl_identity" {
  from ssl.event
  correlate ssl.event as s
  where s.pid == 4242 and s.uid == 7 and s.process_name == "openssl" and s.operation == 0 and s.data_len > 1024
  respond alert high
}

rule "dns_high_entropy" {
  from dns.query
  correlate dns.query as q
  where q.pid == 4242 and q.uid == 7 and q.process_name == "resolver" and q.query_hash == 99 and q.domain.entropy > 4.2 and len(q.domain.value) > 30
  respond alert high
}
"#;
        fs::write(&source_path, src).expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("repo root");
        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(repo_root.join("oilc").join("Cargo.toml"))
            .arg("--")
            .arg("--source")
            .arg(&source_path)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");
        assert!(engine
            .program
            .callables
            .iter()
            .any(|callable| callable.name == "len" && callable.params.len() == 1));

        let mut ssl_comm = [0u8; 16];
        ssl_comm[..7].copy_from_slice(b"openssl");
        let ssl_event = IngestEvent {
            pid: 4242,
            uid: 7,
            event_type: 5,
            comm: ssl_comm,
            ssl_data_len: 2048,
            ssl_operation: 0,
            ..Default::default()
        };
        let ssl_matches = engine.evaluate_matches(&ssl_event);
        assert_eq!(ssl_matches.len(), 1);
        assert_eq!(ssl_matches[0].rule_name, "ssl_identity");

        let mut dns_comm = [0u8; 16];
        dns_comm[..8].copy_from_slice(b"resolver");
        let mut dns_query = [0u8; 64];
        let high_entropy_query = b"abcdefghijklmnopqrstuvwxyz012345";
        dns_query[..high_entropy_query.len()].copy_from_slice(high_entropy_query);
        let dns_event = IngestEvent {
            pid: 4242,
            uid: 7,
            event_type: 6,
            comm: dns_comm,
            dns_query_hash: 99,
            dns_query,
            ..Default::default()
        };
        let dns_matches = engine.evaluate_matches(&dns_event);
        assert_eq!(dns_matches.len(), 1);
        assert_eq!(dns_matches[0].rule_name, "dns_high_entropy");

        // Root-specific identity fields must not leak across event families.
        let mut wrong_family = ssl_event;
        wrong_family.event_type = 1;
        assert!(engine.evaluate_matches(&wrong_family).is_empty());

        let mut low_entropy = dns_event;
        low_entropy.dns_query = [0; 64];
        low_entropy.dns_query[..14].copy_from_slice(b"aaaaaaaaaa.com");
        assert!(engine.evaluate_matches(&low_entropy).is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dns_entropy_is_null_for_missing_or_non_dns_queries() {
        let dns_event = IngestEvent {
            event_type: 6,
            ..Default::default()
        };
        assert!(matches!(field_dns_domain_entropy(&dns_event), Value::Null));

        let mut non_dns = dns_event;
        non_dns.event_type = 1;
        non_dns.dns_query[..4].copy_from_slice(b"abcd");
        assert!(matches!(field_dns_domain_entropy(&non_dns), Value::Null));
    }

    #[test]
    fn loads_multi_source_runtime_ir_emitted_by_oilc_cli_and_matches_both_rules() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let source_a = dir.join("rule_a.oil");
        let source_b = dir.join("rule_b.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");

        let src_a = r#"
rule "pid_42" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid == 42
  respond alert high
}
"#;
        let src_b = r#"
rule "uid_7" {
  from endpoint.process
  correlate process.spawn as p
  where p.uid == 7
  respond alert medium
}
"#;
        fs::write(&source_a, src_a).expect("write source a");
        fs::write(&source_b, src_b).expect("write source b");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root");
        let oilc_manifest = repo_root.join("oilc").join("Cargo.toml");

        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(&oilc_manifest)
            .arg("--")
            .arg("--source")
            .arg(&source_a)
            .arg("--source")
            .arg(&source_b)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 7,
            event_type: 1,
            vertex_id: 0,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|m| m.rule_name == "pid_42"));
        assert!(matches.iter().any(|m| m.rule_name == "uid_7"));
        assert!(!matches.iter().any(|m| m.enforce_block_egress));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn marks_block_egress_rules_for_enforcement() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:block_egress",
      "name": "block_egress",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "pid" },
          "rhs": { "op": "int", "value": 42 }
        }
      ],
      "respond": {
        "branches": [
          {
            "condition": null,
            "actions": [
              { "action": "alert", "severity": "critical" },
              { "action": "block_egress", "target": "n.dest.domain" }
            ]
          }
        ]
      }
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 42,
            uid: 0,
            event_type: 3,
            vertex_id: 42,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "block_egress");
        assert!(matches[0].enforce_block_egress);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn marks_block_query_rules_for_synchronous_enforcement() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:block_query",
      "name": "block_query",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "pid" },
          "rhs": { "op": "int", "value": 42 }
        }
      ],
      "respond": {
        "branches": [
          {
            "condition": null,
            "actions": [
              { "action": "alert", "severity": "critical" },
              { "action": "block_query", "target": "db.tables" }
            ]
          }
        ]
      }
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            pid: 42,
            event_type: 4,
            ..Default::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].enforce_block_query);
        assert!(!matches[0].enforce_block_egress);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn oilc_compiled_lets_score_require_and_response_branches_execute() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");
        let source_path = dir.join("derived_values.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");
        fs::write(
            &source_path,
            r#"
rule "score_branch" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid > 0
  let elevated = p.uid == 0
  score 20 +60 if elevated
  require score >= 20
  respond if score >= 80 {
    alert high
    block egress p.name
  } else {
    alert low
  }
}

rule "require_elevated" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid > 0
  let elevated = p.uid == 0
  require elevated
  respond alert medium
}

rule "stdlib_shell" {
  from endpoint.process
  correlate process.spawn as p
  where is_shell(p)
  respond alert medium
}
"#,
        )
        .expect("write oil source");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("repo root");
        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(repo_root.join("oilc").join("Cargo.toml"))
            .arg("--")
            .arg("--source")
            .arg(&source_path)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let root = IngestEvent {
            pid: 42,
            uid: 0,
            event_type: 1,
            comm,
            ..IngestEvent::default()
        };
        let root_matches = engine.evaluate_matches(&root);
        assert_eq!(
            root_matches.len(),
            3,
            "root matches: {:?}; execution keys: {:?}",
            root_matches
                .iter()
                .map(|matched| matched.rule_name.as_str())
                .collect::<Vec<_>>(),
            engine.rule_execution.keys().collect::<Vec<_>>()
        );
        assert!(
            root_matches
                .iter()
                .find(|matched| matched.rule_name == "score_branch")
                .expect("score branch match")
                .enforce_block_egress
        );

        let unprivileged = IngestEvent { uid: 1000, ..root };
        let unprivileged_matches = engine.evaluate_matches(&unprivileged);
        assert_eq!(unprivileged_matches.len(), 2);
        assert!(
            !unprivileged_matches
                .iter()
                .find(|matched| matched.rule_name == "score_branch")
                .expect("unprivileged score branch match")
                .enforce_block_egress
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn matches_domain_predicate_against_net_destination_ip() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:localhost_domain",
      "name": "localhost_domain",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "n.dest.domain" },
          "rhs": { "op": "str", "value": "localhost" }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 9001,
            uid: 0,
            event_type: 3,
            vertex_id: 9001,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "localhost_domain");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_domain_membership_predicate_against_net_destination_ip() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:localhost_domain_in_list",
      "name": "localhost_domain_in_list",
      "predicates": [
        {
          "op": "in",
          "lhs": { "op": "field", "path": "n.dest.domain" },
          "rhs": [
            { "op": "str", "value": "example.com" },
            { "op": "str", "value": "localhost" }
          ]
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 9002,
            uid: 0,
            event_type: 3,
            vertex_id: 9002,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "localhost_domain_in_list");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_domain_literal_against_ip_field_without_domain_specific_field_path() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:ip_field_vs_domain_literal",
      "name": "ip_field_vs_domain_literal",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "n.dest.ip" },
          "rhs": { "op": "str", "value": "localhost" }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 9004,
            uid: 0,
            event_type: 3,
            vertex_id: 9004,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "ip_field_vs_domain_literal");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_ip_membership_predicate_against_net_destination_ip() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:loopback_ip_in_list",
      "name": "loopback_ip_in_list",
      "predicates": [
        {
          "op": "in",
          "lhs": { "op": "field", "path": "n.dest.ip" },
          "rhs": [
            { "op": "str", "value": "10.10.10.10" },
            { "op": "str", "value": "127.0.0.1" }
          ]
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 9003,
            uid: 0,
            event_type: 3,
            vertex_id: 9003,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "loopback_ip_in_list");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_process_name_membership_predicate() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:process_name_in_list",
      "name": "process_name_in_list",
      "predicates": [
        {
          "op": "in",
          "lhs": { "op": "field", "path": "p.name" },
          "rhs": [
            { "op": "str", "value": "bash" },
            { "op": "str", "value": "sh" }
          ]
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 1337,
            uid: 0,
            event_type: 1,
            vertex_id: 1337,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "process_name_in_list");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_list_contains_predicate_against_process_name() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:list_contains_process_name",
      "name": "list_contains_process_name",
      "predicates": [
        {
          "op": "contains",
          "lhs": {
            "op": "list",
            "items": [
              { "op": "str", "value": "zsh" },
              { "op": "str", "value": "bash" }
            ]
          },
          "rhs": { "op": "field", "path": "p.name" }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 1338,
            uid: 0,
            event_type: 1,
            vertex_id: 1338,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "list_contains_process_name");

        let _ = fs::remove_file(path);
    }

    /// Build a SQL event the way the ring-buffer decoder does: redact the
    /// statement, derive tables from the redacted form, pack them.
    fn sql_event_for(statement: &str) -> IngestEvent {
        let redacted = crate::sql_norm::redact_statement(statement);
        let tables = crate::sql_norm::extract_tables(&redacted);
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"psql");

        IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 0,
            event_type: 4,
            vertex_id: 4242,
            comm,
            risk_score: 0.3,
            sql_query_class: 1,
            sql_db_port: 5432,
            sql_norm_hash: crate::sql_norm::normalized_fingerprint(&redacted),
            sql_tables: crate::sql_norm::pack_tables(&tables),
            ..Default::default()
        }
    }

    fn engine_for_rule(json: &str) -> (RuntimeIrRuleEngine, std::path::PathBuf) {
        let path = temp_runtime_ir_path();
        fs::write(&path, json).expect("write runtime ir json");
        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        (engine, path)
    }

    /// The point of table attribution: a rule can name a table and act on it.
    /// The rule never sees a literal — `sql.tables` is derived from the
    /// redacted statement, so the WHERE clause value cannot reach the engine.
    #[test]
    fn matches_sql_table_predicate_without_exposing_literals() {
        let (engine, path) = engine_for_rule(
            r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:touches_ledger",
      "name": "touches_ledger",
      "predicates": [
        {
          "op": "contains",
          "lhs": { "op": "field", "path": "sql.tables" },
          "rhs": { "op": "str", "value": "ledger" }
        }
      ]
    }
  ]
}"#,
        );

        let hit = sql_event_for("SELECT * FROM finance.ledger WHERE ssn = '123-45-6789'");
        let matches = engine.evaluate_matches(&hit);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "touches_ledger");

        // A different table must not match.
        let miss = sql_event_for("SELECT * FROM finance.invoices");
        assert!(engine.evaluate_matches(&miss).is_empty());

        let _ = fs::remove_file(path);
    }

    /// `sql.database` must agree with the database the stored row reports, or
    /// a rule and the dashboard disagree about the same event.
    #[test]
    fn matches_sql_database_predicate_and_agrees_with_stored_row() {
        let (engine, path) = engine_for_rule(
            r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:finance_access",
      "name": "finance_access",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "sql.database" },
          "rhs": { "op": "str", "value": "finance" }
        }
      ]
    }
  ]
}"#,
        );

        let event = sql_event_for("SELECT * FROM finance.ledger");
        assert_eq!(engine.evaluate_matches(&event).len(), 1);

        // Same source of truth as the outbound DbQueryEvent.
        let unpacked = crate::sql_norm::unpack_tables_bytes(&event.sql_tables);
        assert_eq!(unpacked.database.as_deref(), Some("finance"));
        assert_eq!(unpacked.tables, vec!["ledger"]);

        // A cross-database join has no single answer, so the rule must not fire.
        let joined = sql_event_for("SELECT * FROM finance.ledger JOIN hr.people ON a = b");
        assert!(engine.evaluate_matches(&joined).is_empty());

        let _ = fs::remove_file(path);
    }

    /// SQL fields must stay inert on other event families, or a table rule
    /// starts firing on process and network events.
    #[test]
    fn sql_table_fields_are_null_for_non_sql_events() {
        let mut event = sql_event_for("SELECT * FROM finance.ledger");
        event.event_type = 1;

        assert!(matches!(field_sql_tables(&event), Value::Null));
        assert!(matches!(field_sql_database(&event), Value::Null));
        assert!(matches!(field_db_pid(&event), Value::Null));
        assert!(matches!(field_db_uid(&event), Value::Null));
        assert!(matches!(field_db_process_name(&event), Value::Null));
    }

    /// An unresolvable statement is a SQL event with no tables, not a missing
    /// field: `contains` should simply fail to match rather than behave like
    /// an absent value.
    #[test]
    fn unresolved_sql_tables_yield_an_empty_list_not_null() {
        let event = sql_event_for("SELECT 1");

        match field_sql_tables(&event) {
            Value::List(items) => assert!(items.is_empty()),
            other => panic!("expected an empty list, got {other:?}"),
        }
    }

    #[test]
    fn matches_process_name_with_wildcard_pattern() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:process_name_matches_wildcard",
      "name": "process_name_matches_wildcard",
      "predicates": [
        {
          "op": "matches",
          "lhs": { "op": "field", "path": "p.name" },
          "pattern": "ba*"
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 2001,
            uid: 0,
            event_type: 1,
            vertex_id: 2001,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "process_name_matches_wildcard");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn matches_process_name_with_alternation_pattern() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:process_name_matches_alternation",
      "name": "process_name_matches_alternation",
      "predicates": [
        {
          "op": "matches",
          "lhs": { "op": "field", "path": "p.name" },
          "pattern": "(zsh|bash|sh)"
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 2002,
            uid: 0,
            event_type: 1,
            vertex_id: 2002,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "process_name_matches_alternation");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn resolves_prefixed_field_paths_via_field_specs() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:prefixed_paths",
      "name": "prefixed_paths",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "proc.pid" },
          "rhs": { "op": "int", "value": 4242 }
        },
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "wire.dest.port" },
          "rhs": { "op": "int", "value": 443 }
        },
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "wire.dest.ip" },
          "rhs": { "op": "str", "value": "127.0.0.1" }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 0,
            event_type: 3,
            vertex_id: 4242,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm,
            comm_id: 0,
            risk_score: 0.2,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "prefixed_paths");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn field_spec_boundary_match_avoids_partial_suffix_collisions() {
        let field_specs = fallback_field_specs();
        assert!(lookup_field_spec(&field_specs, "n.dest.port").is_some());
        assert!(lookup_field_spec(&field_specs, "proc.pid").is_some());
        assert!(lookup_field_spec(&field_specs, "proc.pid_extra").is_none());
        assert!(lookup_field_spec(&field_specs, "n.dest.port_suffix").is_none());
    }

    #[test]
    fn consumes_compiler_emitted_field_metadata_aliases() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "fields": [
    {
      "canonical": "process.pid",
      "value_type": "number",
      "aliases": ["identity.process_id"],
      "is_time_context": false
    }
  ],
  "rules": [
    {
      "id": "rule:0:metadata_alias",
      "name": "metadata_alias",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "identity.process_id" },
          "rhs": { "op": "int", "value": 1337 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 1337,
            uid: 0,
            event_type: 1,
            vertex_id: 1337,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "metadata_alias");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn consumes_compiler_domain_field_metadata_as_ip_backed_value() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "fields": [
    {
      "canonical": "network.dest.domain",
      "value_type": "string",
      "aliases": ["dest.domain"],
      "is_time_context": false
    }
  ],
  "rules": [
    {
      "id": "rule:0:domain_alias",
      "name": "domain_alias",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "n.dest.domain" },
          "rhs": { "op": "str", "value": "localhost" }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let event = IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 0,
            event_type: 3,
            vertex_id: 4242,
            dst_vertex_id: 0,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };

        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "domain_alias");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn consumes_additional_compiler_field_metadata_extractors() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "fields": [
    {
      "canonical": "process.id",
      "value_type": "number",
      "aliases": ["proc.identifier"],
      "is_time_context": false
    },
    {
      "canonical": "process.ppid",
      "value_type": "number",
      "aliases": ["proc.parent_pid"],
      "is_time_context": false
    },
    {
      "canonical": "process.elevated",
      "value_type": "bool",
      "aliases": ["proc.is_root"],
      "is_time_context": false
    },
    {
      "canonical": "network.process_id",
      "value_type": "number",
      "aliases": ["net.proc_id"],
      "is_time_context": false
    },
    {
      "canonical": "file.process_id",
      "value_type": "number",
      "aliases": ["file.proc_id"],
      "is_time_context": false
    }
  ],
  "rules": [
    {
      "id": "rule:0:process_fields",
      "name": "process_fields",
      "predicates": [
        {
          "op": "and",
          "lhs": {
            "op": "and",
            "lhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.identifier" }, "rhs": { "op": "int", "value": 4242 } },
            "rhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.parent_pid" }, "rhs": { "op": "int", "value": 313 } }
          },
          "rhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.is_root" }, "rhs": { "op": "bool", "value": true } }
        }
      ]
    },
    {
      "id": "rule:0:network_process",
      "name": "network_process",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "net.proc_id" },
          "rhs": { "op": "int", "value": 4242 }
        }
      ]
    },
    {
      "id": "rule:0:file_process",
      "name": "file_process",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "file.proc_id" },
          "rhs": { "op": "int", "value": 4242 }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");

        let exec_event = IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 0,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 313,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        let exec_matches = engine.evaluate_matches(&exec_event);
        assert!(exec_matches.iter().any(|m| m.rule_name == "process_fields"));
        assert!(!exec_matches
            .iter()
            .any(|m| m.rule_name == "network_process"));
        assert!(!exec_matches.iter().any(|m| m.rule_name == "file_process"));

        let net_event = IngestEvent {
            event_type: 3,
            ..exec_event
        };
        let net_matches = engine.evaluate_matches(&net_event);
        assert!(net_matches.iter().any(|m| m.rule_name == "network_process"));
        assert!(!net_matches.iter().any(|m| m.rule_name == "file_process"));

        let file_event = IngestEvent {
            event_type: 2,
            ..exec_event
        };
        let file_matches = engine.evaluate_matches(&file_event);
        assert!(file_matches.iter().any(|m| m.rule_name == "file_process"));
        assert!(!file_matches
            .iter()
            .any(|m| m.rule_name == "network_process"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn consumes_nested_and_derived_compiler_field_metadata_extractors() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "fields": [
    {
      "canonical": "host.risk_score",
      "value_type": "number",
      "aliases": ["host.rs"],
      "is_time_context": false
    },
    {
      "canonical": "user.uid",
      "value_type": "number",
      "aliases": ["usr.uid"],
      "is_time_context": false
    },
    {
      "canonical": "process.user.uid",
      "value_type": "number",
      "aliases": ["proc.user_uid"],
      "is_time_context": false
    },
    {
      "canonical": "process.parent.pid",
      "value_type": "number",
      "aliases": ["proc.parent_pid"],
      "is_time_context": false
    },
    {
      "canonical": "process.parent.id",
      "value_type": "number",
      "aliases": ["proc.parent_id"],
      "is_time_context": false
    },
    {
      "canonical": "network.dest.is_internal",
      "value_type": "bool",
      "aliases": ["net.dest.internal"],
      "is_time_context": false
    }
  ],
  "rules": [
    {
      "id": "rule:0:identity_fields",
      "name": "identity_fields",
      "predicates": [
        {
          "op": "and",
          "lhs": {
            "op": "and",
            "lhs": { "op": "eq", "lhs": { "op": "field", "path": "usr.uid" }, "rhs": { "op": "int", "value": 1001 } },
            "rhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.user_uid" }, "rhs": { "op": "int", "value": 1001 } }
          },
          "rhs": { "op": "eq", "lhs": { "op": "field", "path": "host.rs" }, "rhs": { "op": "float", "value": 0.75 } }
        }
      ]
    },
    {
      "id": "rule:0:parent_fields_exec_only",
      "name": "parent_fields_exec_only",
      "predicates": [
        {
          "op": "and",
          "lhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.parent_pid" }, "rhs": { "op": "int", "value": 313 } },
          "rhs": { "op": "eq", "lhs": { "op": "field", "path": "proc.parent_id" }, "rhs": { "op": "int", "value": 313 } }
        }
      ]
    },
    {
      "id": "rule:0:net_internal_only",
      "name": "net_internal_only",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "net.dest.internal" },
          "rhs": { "op": "bool", "value": true }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");

        let exec_event = IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 1001,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 313,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.75,
            ..Default::default()
        };
        let exec_matches = engine.evaluate_matches(&exec_event);
        assert!(exec_matches
            .iter()
            .any(|m| m.rule_name == "identity_fields"));
        assert!(exec_matches
            .iter()
            .any(|m| m.rule_name == "parent_fields_exec_only"));
        assert!(!exec_matches
            .iter()
            .any(|m| m.rule_name == "net_internal_only"));

        let net_event_internal = IngestEvent {
            event_type: 3,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            ..exec_event
        };
        let net_internal_matches = engine.evaluate_matches(&net_event_internal);
        assert!(net_internal_matches
            .iter()
            .any(|m| m.rule_name == "net_internal_only"));
        assert!(!net_internal_matches
            .iter()
            .any(|m| m.rule_name == "parent_fields_exec_only"));

        let net_event_external = IngestEvent {
            net_dst_ip: u32::from(Ipv4Addr::new(8, 8, 8, 8)),
            ..net_event_internal
        };
        let net_external_matches = engine.evaluate_matches(&net_event_external);
        assert!(!net_external_matches
            .iter()
            .any(|m| m.rule_name == "net_internal_only"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn fallback_metadata_resolves_parent_and_internal_fields_without_compiler_fields() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "id": "rule:0:fallback_parent",
      "name": "fallback_parent",
      "predicates": [
        {
          "op": "and",
          "lhs": { "op": "eq", "lhs": { "op": "field", "path": "p.parent.pid" }, "rhs": { "op": "int", "value": 313 } },
          "rhs": { "op": "eq", "lhs": { "op": "field", "path": "p.is_root" }, "rhs": { "op": "bool", "value": false } }
        }
      ]
    },
    {
      "id": "rule:0:fallback_internal",
      "name": "fallback_internal",
      "predicates": [
        {
          "op": "eq",
          "lhs": { "op": "field", "path": "n.dest.is_internal" },
          "rhs": { "op": "bool", "value": true }
        }
      ]
    }
  ]
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");

        let exec_event = IngestEvent {
            ts_ns: 0,
            pid: 4242,
            uid: 1001,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 313,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm: [0; 16],
            comm_id: 0,
            risk_score: 0.0,
            ..Default::default()
        };
        let exec_matches = engine.evaluate_matches(&exec_event);
        assert!(exec_matches
            .iter()
            .any(|m| m.rule_name == "fallback_parent"));
        assert!(!exec_matches
            .iter()
            .any(|m| m.rule_name == "fallback_internal"));

        let net_event = IngestEvent {
            event_type: 3,
            net_dst_ip: u32::from(Ipv4Addr::LOCALHOST),
            net_dst_port: 443,
            ..exec_event
        };
        let net_matches = engine.evaluate_matches(&net_event);
        assert!(net_matches
            .iter()
            .any(|m| m.rule_name == "fallback_internal"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn evaluates_time_context_fields() {
        let path = temp_runtime_ir_path();
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            ts_ns: 1_704_067_200_000_000_000, // 2024-01-08T12:00:00Z
            pid: 4242,
            uid: 0,
            event_type: 1,
            vertex_id: 4242,
            dst_vertex_id: 0,
            net_dst_ip: 0,
            net_dst_port: 0,
            comm,
            comm_id: 0,
            risk_score: 0.1,
            ..Default::default()
        };

        let local = event_local_time(&event).expect("local time conversion");
        let weekday = weekday_name(local.tm_wday);
        let hour = local.tm_hour as i64;
        let business = is_business_hour(&local);

        let json = format!(
            r#"{{
  "version": 1,
  "rules": [
    {{
      "id": "rule:0:time_context",
      "name": "time_context",
      "predicates": [
        {{
          "op": "and",
          "lhs": {{
            "op": "eq",
            "lhs": {{ "op": "field", "path": "time.weekday" }},
            "rhs": {{ "op": "str", "value": "{weekday}" }}
          }},
          "rhs": {{
            "op": "and",
            "lhs": {{
              "op": "eq",
              "lhs": {{ "op": "field", "path": "time.hour" }},
              "rhs": {{ "op": "int", "value": {hour} }}
            }},
            "rhs": {{
              "op": "eq",
              "lhs": {{ "op": "field", "path": "time.is_business_hour" }},
              "rhs": {{ "op": "bool", "value": {business} }}
            }}
          }}
        }}
      ]
    }}
  ]
}}"#
        );
        fs::write(&path, json).expect("write runtime ir json");

        let engine = RuntimeIrRuleEngine::from_file(&path).expect("load runtime ir");
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "time_context");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unsupported_runtime_ir_version_at_load() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 2,
  "rules": []
}"#;
        fs::write(&path, json).expect("write runtime ir json");

        let err = RuntimeIrRuleEngine::from_file(&path)
            .err()
            .expect("unsupported version should fail");
        assert!(
            err.to_string().contains("unsupported runtime-ir version"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unknown_or_wrong_arity_runtime_callables_at_load() {
        for (call, expected) in [
            (
                r#"{ "op": "call", "name": "missing", "args": [] }"#,
                "unsupported runtime callable 'missing'",
            ),
            (
                r#"{ "op": "call", "name": "len", "args": [] }"#,
                "callable 'len' expects 1 argument(s), got 0",
            ),
        ] {
            let path = temp_runtime_ir_path();
            let json = format!(
                r#"{{
  "version": 1,
  "rules": [{{
    "id": "rule:bad-call",
    "name": "bad-call",
    "predicates": [{call}]
  }}]
}}"#
            );
            fs::write(&path, json).expect("write runtime ir json");
            let err = RuntimeIrRuleEngine::from_file(&path)
                .expect_err("invalid callable should fail artifact loading");
            assert!(
                err.to_string().contains(expected),
                "unexpected error for {call}: {err}"
            );
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn rejects_calls_missing_from_a_non_legacy_callable_contract() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "callables": [
    {
      "name": "rare",
      "params": [{ "name": "value", "value_type": { "kind": "str" } }],
      "returns": { "kind": "bool" }
    }
  ],
  "rules": [{
    "id": "rule:missing-contract",
    "name": "missing-contract",
    "predicates": [{
      "op": "call",
      "name": "len",
      "args": [{ "op": "str", "value": "abc" }]
    }]
  }]
}"#;
        fs::write(&path, json).expect("write runtime ir json");
        let err = RuntimeIrRuleEngine::from_file(&path)
            .expect_err("missing callable contract should fail artifact loading");
        assert!(
            err.to_string()
                .contains("callable 'len' is missing from the compiler-emitted callable contract"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_builtin_parameter_and_return_contract_drift_at_load() {
        for (param_type, return_type, expected) in [
            (
                r#"{ "kind": "bool" }"#,
                r#"{ "kind": "int" }"#,
                "parameter 'value' has unsupported type Bool",
            ),
            (
                r#"{ "kind": "str" }"#,
                r#"{ "kind": "bool" }"#,
                "unsupported return type Some(Bool)",
            ),
        ] {
            let path = temp_runtime_ir_path();
            let json = format!(
                r#"{{
  "version": 1,
  "callables": [{{
    "name": "len",
    "params": [{{ "name": "value", "value_type": {param_type} }}],
    "returns": {return_type}
  }}],
  "rules": [{{
    "id": "rule:contract-drift",
    "name": "contract-drift",
    "predicates": [{{
      "op": "call",
      "name": "len",
      "args": [{{ "op": "str", "value": "abc" }}]
    }}]
  }}]
}}"#
            );
            fs::write(&path, json).expect("write runtime ir json");
            let err = RuntimeIrRuleEngine::from_file(&path)
                .expect_err("builtin contract drift should fail artifact loading");
            assert!(
                err.to_string().contains(expected),
                "unexpected error: {err}"
            );
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn callable_argument_values_are_checked_against_emitted_contracts() {
        let path = temp_runtime_ir_path();
        let json = r#"{
  "version": 1,
  "callables": [{
    "name": "len",
    "params": [{ "name": "value", "value_type": { "kind": "str" } }],
    "returns": { "kind": "int" }
  }],
  "rules": [{
    "id": "rule:bad-dynamic-arg",
    "name": "bad-dynamic-arg",
    "predicates": [{
      "op": "eq",
      "lhs": {
        "op": "call",
        "name": "len",
        "args": [{ "op": "int", "value": 42 }]
      },
      "rhs": { "op": "int", "value": 2 }
    }]
  }]
}"#;
        fs::write(&path, json).expect("write runtime ir json");
        let engine = RuntimeIrRuleEngine::from_file(&path)
            .expect("the builtin signature itself is compatible");

        assert!(
            engine.evaluate_matches(&IngestEvent::default()).is_empty(),
            "a value that violates the callable parameter contract must fail closed"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn nested_stateful_callable_arguments_are_evaluated_once() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: vec![
                RuntimeCallable {
                    name: "count".to_string(),
                    params: vec![RuntimeCallableParam {
                        name: "value".to_string(),
                        value_type: RuntimeCallableType::Any,
                    }],
                    returns: Some(RuntimeCallableType::Int),
                },
                RuntimeCallable {
                    name: "rare".to_string(),
                    params: vec![RuntimeCallableParam {
                        name: "value".to_string(),
                        value_type: RuntimeCallableType::Str,
                    }],
                    returns: Some(RuntimeCallableType::Bool),
                },
            ],
            rules: vec![RuntimeRule {
                id: "rule:nested-call".to_string(),
                name: "nested-call".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Call {
                        name: "count".to_string(),
                        args: vec![RuntimeExpr::Call {
                            name: "rare".to_string(),
                            args: vec![RuntimeExpr::Str {
                                value: "bash".to_string(),
                            }],
                        }],
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 1 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);

        assert_eq!(engine.evaluate_matches(&IngestEvent::default()).len(), 1);
        let state = engine.callable_state.lock().expect("callable state");
        assert_eq!(
            state.rare_counts.get(&(
                "agent-local".to_string(),
                "rule:nested-call".to_string(),
                "bash".to_string()
            )),
            Some(&1)
        );
    }

    #[test]
    fn rare_state_is_isolated_per_rule() {
        let rare_predicate = || RuntimeExpr::Call {
            name: "rare".to_string(),
            args: vec![RuntimeExpr::Str {
                value: "bash".to_string(),
            }],
        };
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![
                RuntimeRule {
                    id: "rule:a".to_string(),
                    name: "a".to_string(),
                    predicates: vec![rare_predicate()],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "rule:b".to_string(),
                    name: "b".to_string(),
                    predicates: vec![rare_predicate()],
                    respond: RuntimeRespondPlan::default(),
                },
            ],
        };
        let engine = engine_from_program(program);

        assert_eq!(engine.evaluate_matches(&IngestEvent::default()).len(), 2);
        assert!(engine.evaluate_matches(&IngestEvent::default()).is_empty());
    }

    #[test]
    fn callable_state_bound_evicts_oldest_key() {
        let field_specs = fallback_field_specs();
        let state = Mutex::new(
            CallableEvalState::with_config(HashMap::new(), "host-a".to_string(), 1, 1, None)
                .expect("callable state"),
        );
        let event = IngestEvent::default();
        let rare = |value: &str| {
            with_callable_rule_scope("rule:a", || {
                eval_call(
                    "rare",
                    &[RuntimeExpr::Str {
                        value: value.to_string(),
                    }],
                    &event,
                    &field_specs,
                    &state,
                )
            })
        };

        assert_eq!(rare("bash"), Value::Bool(true));
        assert_eq!(rare("zsh"), Value::Bool(true));
        assert_eq!(state.lock().expect("state").state_len(), 1);
        assert_eq!(rare("bash"), Value::Bool(true), "oldest key was evicted");
    }

    #[test]
    fn callable_state_checkpoint_survives_engine_restart() {
        let path = temp_runtime_ir_path();
        let make_program = || RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: Vec::new(),
            rules: vec![RuntimeRule {
                id: "rule:persisted-rare".to_string(),
                name: "persisted-rare".to_string(),
                predicates: vec![RuntimeExpr::Call {
                    name: "rare".to_string(),
                    args: vec![RuntimeExpr::Str {
                        value: "bash".to_string(),
                    }],
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let make_engine = || {
            let program = make_program();
            let state = CallableEvalState::with_config(
                HashMap::new(),
                "host-a".to_string(),
                16,
                1,
                Some(path.clone()),
            )
            .expect("load callable state");
            RuntimeIrRuleEngine {
                field_specs: build_field_specs(&program),
                rule_execution: HashMap::new(),
                callable_state: Arc::new(Mutex::new(state)),
                program,
            }
        };

        let first_engine = make_engine();
        assert_eq!(
            first_engine.evaluate_matches(&IngestEvent::default()).len(),
            1
        );
        drop(first_engine);

        let restored_engine = make_engine();
        assert!(
            restored_engine
                .evaluate_matches(&IngestEvent::default())
                .is_empty(),
            "restored first-seen state must suppress a repeat"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn selects_generic_collection_overload_at_runtime() {
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: vec![
                RuntimeCallable {
                    name: "len".to_string(),
                    params: vec![RuntimeCallableParam {
                        name: "value".to_string(),
                        value_type: RuntimeCallableType::Str,
                    }],
                    returns: Some(RuntimeCallableType::Int),
                },
                RuntimeCallable {
                    name: "len".to_string(),
                    params: vec![RuntimeCallableParam {
                        name: "value".to_string(),
                        value_type: RuntimeCallableType::Set(Box::new(RuntimeCallableType::Any)),
                    }],
                    returns: Some(RuntimeCallableType::Int),
                },
            ],
            rules: vec![RuntimeRule {
                id: "rule:list-len".to_string(),
                name: "list-len".to_string(),
                predicates: vec![RuntimeExpr::Eq {
                    lhs: Box::new(RuntimeExpr::Call {
                        name: "len".to_string(),
                        args: vec![RuntimeExpr::List {
                            items: vec![
                                RuntimeExpr::Str {
                                    value: "a".to_string(),
                                },
                                RuntimeExpr::Int { value: 2 },
                            ],
                        }],
                    }),
                    rhs: Box::new(RuntimeExpr::Int { value: 2 }),
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);
        assert_eq!(engine.evaluate_matches(&IngestEvent::default()).len(), 1);
    }

    #[test]
    fn runtime_overload_selection_prefers_concrete_signature_over_any() {
        let contracts = vec![
            RuntimeCallable {
                name: "example".to_string(),
                params: vec![RuntimeCallableParam {
                    name: "value".to_string(),
                    value_type: RuntimeCallableType::Any,
                }],
                returns: Some(RuntimeCallableType::Int),
            },
            RuntimeCallable {
                name: "example".to_string(),
                params: vec![RuntimeCallableParam {
                    name: "value".to_string(),
                    value_type: RuntimeCallableType::Str,
                }],
                returns: Some(RuntimeCallableType::Str),
            },
        ];
        let state = Mutex::new(CallableEvalState {
            contracts: HashMap::from([("example".to_string(), contracts)]),
            ..CallableEvalState::default()
        });
        let selected = callable_contract(
            &state,
            "example",
            &[RuntimeExpr::Str {
                value: "value".to_string(),
            }],
            &fallback_field_specs(),
        )
        .expect("selected overload");
        assert_eq!(selected.returns, Some(RuntimeCallableType::Str));
    }

    #[test]
    fn intel_domains_extension_returns_collection_for_membership() {
        crate::intel_store::install_test_string_set(
            "org.threat_intel.production",
            &["evil.example", "bad.example"],
        );
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: vec![RuntimeCallable {
                name: "intel.domains".to_string(),
                params: vec![RuntimeCallableParam {
                    name: "feed".to_string(),
                    value_type: RuntimeCallableType::Str,
                }],
                returns: Some(RuntimeCallableType::Set(Box::new(RuntimeCallableType::Str))),
            }],
            rules: vec![RuntimeRule {
                id: "rule:intel-extension".to_string(),
                name: "intel-extension".to_string(),
                predicates: vec![RuntimeExpr::In {
                    lhs: Box::new(RuntimeExpr::Str {
                        value: "evil.example".to_string(),
                    }),
                    rhs: vec![RuntimeExpr::Call {
                        name: "intel.domains".to_string(),
                        args: vec![RuntimeExpr::Str {
                            value: "production".to_string(),
                        }],
                    }],
                }],
                respond: RuntimeRespondPlan::default(),
            }],
        };
        let engine = engine_from_program(program);
        assert_eq!(engine.evaluate_matches(&IngestEvent::default()).len(), 1);
    }

    #[test]
    fn lookup_extensions_project_structured_results_without_losing_arguments() {
        let baseline_contract = |name: &str, params: &[&str]| RuntimeCallable {
            name: name.to_string(),
            params: params
                .iter()
                .map(|name| RuntimeCallableParam {
                    name: (*name).to_string(),
                    value_type: RuntimeCallableType::Str,
                })
                .collect(),
            returns: Some(RuntimeCallableType::Entity("BaselineProfile".to_string())),
        };
        let project = |base: RuntimeExpr, field: &str| RuntimeExpr::Project {
            base: Box::new(base),
            field: field.to_string(),
        };
        let call = |name: &str, args: Vec<RuntimeExpr>| RuntimeExpr::Call {
            name: name.to_string(),
            args,
        };
        let string = |value: &str| RuntimeExpr::Str {
            value: value.to_string(),
        };

        let image_processes = project(
            call("baseline.image", vec![string("sha256:abc")]),
            "allowed_processes",
        );
        let workload_processes = project(
            call("baseline.workload", vec![string("payments"), string("api")]),
            "allowed_processes",
        );
        let host_domains = project(
            project(call("host", vec![string("host-a")]), "baseline"),
            "domains",
        );
        let user_countries = project(
            project(call("user", vec![string("user-a")]), "baseline"),
            "countries",
        );
        let program = RuntimeProgram {
            version: 1,
            fields: Vec::new(),
            callables: vec![
                baseline_contract("baseline.image", &["image_id"]),
                baseline_contract("baseline.workload", &["namespace", "name"]),
            ],
            rules: vec![
                RuntimeRule {
                    id: "rule:image".to_string(),
                    name: "image".to_string(),
                    predicates: vec![RuntimeExpr::Contains {
                        lhs: Box::new(image_processes),
                        rhs: Box::new(RuntimeExpr::Field {
                            path: "process.name".to_string(),
                        }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "rule:workload".to_string(),
                    name: "workload".to_string(),
                    predicates: vec![RuntimeExpr::Contains {
                        lhs: Box::new(workload_processes),
                        rhs: Box::new(RuntimeExpr::Field {
                            path: "process.name".to_string(),
                        }),
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "rule:host".to_string(),
                    name: "host".to_string(),
                    predicates: vec![RuntimeExpr::In {
                        lhs: Box::new(string("corp.example")),
                        rhs: vec![host_domains],
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
                RuntimeRule {
                    id: "rule:user".to_string(),
                    name: "user".to_string(),
                    predicates: vec![RuntimeExpr::In {
                        lhs: Box::new(string("GB")),
                        rhs: vec![user_countries],
                    }],
                    respond: RuntimeRespondPlan::default(),
                },
            ],
        };
        validate_runtime_calls(&program, &HashMap::new()).expect("lookup call validation");
        let engine = engine_from_program(program);
        engine
            .callable_state
            .lock()
            .expect("callable state")
            .lookup_data = Some(Arc::new(RuntimeLookupArtifact {
            version: 1,
            images: HashMap::from([(
                "sha256:abc".to_string(),
                RuntimeBaselineProfile {
                    allowed_processes: vec!["bash".to_string()],
                },
            )]),
            workloads: HashMap::from([(
                "payments/api".to_string(),
                RuntimeBaselineProfile {
                    allowed_processes: vec!["bash".to_string()],
                },
            )]),
            hosts: HashMap::from([(
                "host-a".to_string(),
                RuntimeHostBaseline {
                    domains: vec!["corp.example".to_string()],
                    ..RuntimeHostBaseline::default()
                },
            )]),
            users: HashMap::from([(
                "user-a".to_string(),
                RuntimeUserBaseline {
                    countries: vec!["GB".to_string()],
                    ..RuntimeUserBaseline::default()
                },
            )]),
        }));
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let matches = engine.evaluate_matches(&IngestEvent {
            event_type: 1,
            comm,
            ..IngestEvent::default()
        });
        assert_eq!(matches.len(), 4);
    }

    #[test]
    fn oilc_compiled_baseline_projection_executes_with_lookup_artifact() {
        let dir = temp_runtime_ir_dir();
        fs::create_dir_all(&dir).expect("create temp dir");
        let source_path = dir.join("baseline.oil");
        let runtime_ir_path = dir.join("runtime-ir.json");
        let lookup_path = dir.join("lookups.json");
        fs::write(
            &source_path,
            r#"
rule "expected_image_process" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.image("sha256:abc").allowed_processes contains p.name
  respond alert high
}
"#,
        )
        .expect("write oil source");
        fs::write(
            &lookup_path,
            r#"{
  "version": 1,
  "images": {
    "sha256:abc": { "allowed_processes": ["bash", "sh"] }
  }
}"#,
        )
        .expect("write lookup artifact");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("repo root");
        let output = Command::new("cargo")
            .arg("run")
            .arg("--manifest-path")
            .arg(repo_root.join("oilc").join("Cargo.toml"))
            .arg("--")
            .arg("--source")
            .arg(&source_path)
            .arg("--emit-runtime-ir")
            .arg(&runtime_ir_path)
            .arg("--mode")
            .arg("check")
            .current_dir(repo_root)
            .output()
            .expect("run oilc cli");
        assert!(
            output.status.success(),
            "oilc cli failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let engine = RuntimeIrRuleEngine::from_file(&runtime_ir_path).expect("load runtime ir");
        engine
            .callable_state
            .lock()
            .expect("callable state")
            .lookup_data =
            Some(load_runtime_lookup_artifact(&lookup_path).expect("load runtime lookup artifact"));
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let event = IngestEvent {
            event_type: 1,
            comm,
            ..IngestEvent::default()
        };
        let matches = engine.evaluate_matches(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "expected_image_process");

        let mut miss = event;
        miss.comm = [0; 16];
        miss.comm[..3].copy_from_slice(b"zsh");
        assert!(engine.evaluate_matches(&miss).is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recognizes_epoch_like_nanoseconds_directly() {
        let ts_ns = 1_704_067_200_000_000_000u64; // 2024-01-08T12:00:00Z
        assert_eq!(event_realtime_ns(ts_ns), Some(ts_ns));
    }
}
