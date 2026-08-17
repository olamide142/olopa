//! In-process OIL compilation and execution-plan derivation.
//!
//! Command links the `oilc` crate directly instead of shelling out to the
//! binary or posting to the control plane. The stdlib schema and prelude are
//! embedded in that crate with `include_str!`, so OIL Studio is fully offline:
//! no server, no subprocess, no compiler installation to keep in sync.

use oilc::{compile, CompilerConfig, Diagnostic, RuntimeExpr, RuntimeProgram, RuntimeRule};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct OilDiagnostic {
    pub stage: String,
    pub severity: &'static str,
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

fn to_diagnostic(diagnostic: &Diagnostic, source: &str) -> OilDiagnostic {
    let (line, column) = diagnostic
        .span
        .as_ref()
        .map(|span| offset_to_line_col(source, span.start))
        .unwrap_or((None, None));
    OilDiagnostic {
        stage: diagnostic.stage.to_string(),
        severity: if diagnostic.is_error { "error" } else { "warning" },
        message: diagnostic.message.clone(),
        line,
        column,
    }
}

fn offset_to_line_col(source: &str, offset: usize) -> (Option<usize>, Option<usize>) {
    if offset > source.len() {
        return (None, None);
    }
    let line = source[..offset].matches('\n').count() + 1;
    let line_start = source[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    (Some(line), Some(offset - line_start + 1))
}

// -- Execution plan ------------------------------------------------------------

/// Which layer of the platform executes a plan step.
///
/// These are the tiers the OIL design distinguishes: predicates that reduce to
/// field comparisons can run on the hot path, anything needing history or
/// baselines needs warm state, and correlation needs the stream engine.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanEngine {
    Kernel,
    HotPath,
    WarmState,
    Stream,
    Scoring,
    Enforcement,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanStep {
    pub label: String,
    pub detail: String,
    pub engine: PlanEngine,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulePlan {
    pub id: String,
    pub name: String,
    pub class: String,
    pub sources: Vec<String>,
    pub window: Option<String>,
    pub score_base: i32,
    pub steps: Vec<PlanStep>,
    /// Callables that need state the simulator and hot path cannot supply.
    pub stateful_calls: Vec<String>,
    /// Constructs the compiler accepted but marked non-executable.
    pub unsupported: Vec<String>,
    pub actions: Vec<String>,
}

#[derive(Debug, Default)]
struct ExprFacts {
    calls: BTreeSet<String>,
    unsupported: BTreeSet<String>,
    fields: BTreeSet<String>,
}

impl ExprFacts {
    fn engine(&self) -> PlanEngine {
        if !self.unsupported.is_empty() {
            PlanEngine::Unsupported
        } else if !self.calls.is_empty() {
            PlanEngine::WarmState
        } else {
            PlanEngine::HotPath
        }
    }
}

fn walk(expr: &RuntimeExpr, facts: &mut ExprFacts) {
    match expr {
        RuntimeExpr::Field { path } => {
            facts.fields.insert(path.clone());
        }
        RuntimeExpr::Call { name, args } => {
            facts.calls.insert(name.clone());
            for arg in args {
                walk(arg, facts);
            }
        }
        RuntimeExpr::Unsupported { kind } => {
            facts.unsupported.insert(kind.clone());
        }
        RuntimeExpr::Project { base, .. } => walk(base, facts),
        RuntimeExpr::Not { expr } => walk(expr, facts),
        RuntimeExpr::List { items } => items.iter().for_each(|item| walk(item, facts)),
        RuntimeExpr::In { lhs, rhs } => {
            walk(lhs, facts);
            rhs.iter().for_each(|item| walk(item, facts));
        }
        RuntimeExpr::Matches { lhs, .. } => walk(lhs, facts),
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
            walk(lhs, facts);
            walk(rhs, facts);
        }
        RuntimeExpr::Bool { .. }
        | RuntimeExpr::Null
        | RuntimeExpr::Int { .. }
        | RuntimeExpr::Float { .. }
        | RuntimeExpr::Duration { .. }
        | RuntimeExpr::Str { .. } => {}
    }
}

/// Actions are tagged enums on the wire and their type lives in a private
/// module of `oilc`, so the tag is read from the serialized form.
fn describe_action<T: Serialize>(action: &T) -> String {
    serde_json::to_value(action)
        .ok()
        .and_then(|value| {
            value
                .get("action")
                .and_then(|tag| tag.as_str())
                .map(|tag| tag.to_string())
        })
        .unwrap_or_else(|| "action".to_string())
}

fn plan_for_rule(rule: &RuntimeRule) -> RulePlan {
    let mut steps = Vec::new();
    let mut stateful = BTreeSet::new();
    let mut unsupported = BTreeSet::new();

    let sources: Vec<String> = rule
        .sources
        .iter()
        .map(|source| match &source.alias {
            Some(alias) => format!("{}.{} as {alias}", source.domain, source.event),
            None => format!("{}.{}", source.domain, source.event),
        })
        .collect();
    if !sources.is_empty() {
        steps.push(PlanStep {
            label: "Subscribe".into(),
            detail: sources.join(", "),
            engine: PlanEngine::Kernel,
        });
    }

    for predicate in &rule.predicates {
        let mut facts = ExprFacts::default();
        walk(predicate, &mut facts);
        stateful.extend(facts.calls.iter().cloned());
        unsupported.extend(facts.unsupported.iter().cloned());
        let detail = if facts.fields.is_empty() {
            "constant predicate".to_string()
        } else {
            facts.fields.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        steps.push(PlanStep {
            label: "Filter".into(),
            detail,
            engine: facts.engine(),
        });
    }

    for join in &rule.joins {
        steps.push(PlanStep {
            label: "Correlate".into(),
            detail: format!("{} ⋈ {}", join.left_alias, join.right_alias),
            engine: PlanEngine::Stream,
        });
    }

    let window = rule.window.as_ref().map(|w| {
        let unit = serde_json::to_value(w.unit)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unit".into());
        format!("{} {unit}", w.value)
    });
    if let Some(window) = &window {
        steps.push(PlanStep {
            label: "Window".into(),
            detail: format!("retain correlated events for {window}"),
            engine: PlanEngine::Stream,
        });
    }

    if !rule.score.modifiers.is_empty() || rule.score.base != 0 {
        for modifier in &rule.score.modifiers {
            if let Some(condition) = &modifier.condition {
                let mut facts = ExprFacts::default();
                walk(condition, &mut facts);
                stateful.extend(facts.calls.iter().cloned());
                unsupported.extend(facts.unsupported.iter().cloned());
            }
        }
        steps.push(PlanStep {
            label: "Score".into(),
            detail: format!(
                "base {} with {} modifier(s)",
                rule.score.base,
                rule.score.modifiers.len()
            ),
            engine: PlanEngine::Scoring,
        });
    }

    if !rule.require.is_empty() {
        steps.push(PlanStep {
            label: "Require".into(),
            detail: format!("{} threshold gate(s)", rule.require.len()),
            engine: PlanEngine::Scoring,
        });
    }

    let mut actions = Vec::new();
    for branch in &rule.respond.branches {
        for action in &branch.actions {
            actions.push(describe_action(action));
        }
    }
    if !actions.is_empty() {
        steps.push(PlanStep {
            label: "Respond".into(),
            detail: actions.join(", "),
            engine: PlanEngine::Enforcement,
        });
    }

    RulePlan {
        id: rule.id.clone(),
        name: rule.name.clone(),
        class: serde_json::to_value(rule.class)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "temporal".into()),
        sources,
        window,
        score_base: rule.score.base,
        steps,
        stateful_calls: stateful.into_iter().collect(),
        unsupported: unsupported.into_iter().collect(),
        actions,
    }
}

// -- Compile -------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct CompileReport {
    pub ok: bool,
    pub diagnostics: Vec<OilDiagnostic>,
    pub token_count: usize,
    /// Debug renderings — the AST and MIR types are not serializable, and the
    /// same renderings are what `oilc --dump-ast` prints.
    pub ast: Option<String>,
    pub mir: Option<String>,
    pub runtime_ir: Option<serde_json::Value>,
    pub plans: Vec<RulePlan>,
}

/// Compile OIL source through the full pipeline and derive its execution plan.
pub fn compile_source(source: &str) -> CompileReport {
    let config = CompilerConfig::default();
    match compile(source, &config) {
        Err(fatal) => CompileReport {
            ok: false,
            diagnostics: fatal.iter().map(|d| to_diagnostic(d, source)).collect(),
            token_count: 0,
            ast: None,
            mir: None,
            runtime_ir: None,
            plans: Vec::new(),
        },
        Ok(output) => {
            let diagnostics: Vec<OilDiagnostic> = output
                .diagnostics
                .iter()
                .map(|d| to_diagnostic(d, source))
                .collect();
            let has_error = diagnostics.iter().any(|d| d.severity == "error");
            let plans = output
                .runtime_ir
                .as_ref()
                .map(|program: &RuntimeProgram| program.rules.iter().map(plan_for_rule).collect())
                .unwrap_or_default();
            CompileReport {
                ok: !has_error && output.runtime_ir.is_some(),
                diagnostics,
                token_count: output.tokens.len(),
                ast: output.program.as_ref().map(|p| format!("{p:#?}")),
                mir: output.mir.as_ref().map(|m| format!("{m:#?}")),
                runtime_ir: output
                    .runtime_ir
                    .as_ref()
                    .and_then(|ir| serde_json::to_value(ir).ok()),
                plans,
            }
        }
    }
}

/// Compile and return only the runtime program, for the simulator.
pub fn runtime_program(source: &str) -> Result<RuntimeProgram, Vec<OilDiagnostic>> {
    let config = CompilerConfig::default();
    match compile(source, &config) {
        Err(fatal) => Err(fatal.iter().map(|d| to_diagnostic(d, source)).collect()),
        Ok(output) => {
            let errors: Vec<OilDiagnostic> = output
                .diagnostics
                .iter()
                .filter(|d| d.is_error)
                .map(|d| to_diagnostic(d, source))
                .collect();
            if !errors.is_empty() {
                return Err(errors);
            }
            output.runtime_ir.ok_or_else(|| {
                vec![OilDiagnostic {
                    stage: "runtime-ir".into(),
                    severity: "error",
                    message: "compilation produced no runtime IR".into(),
                    line: None,
                    column: None,
                }]
            })
        }
    }
}
