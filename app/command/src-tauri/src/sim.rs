//! Runtime-IR simulator.
//!
//! Replays events through the *same* `RuntimeExpr` trees the agent evaluates —
//! the types come from `oilc`, so the simulator cannot drift from the compiler.
//!
//! What it deliberately does not do: joins, temporal windows, warm-state
//! callables (`unusual_for`, `rate`, baselines) and graph traversal need runtime
//! state a desktop replay does not have. Rather than approximating them and
//! reporting a confident wrong answer, rules that depend on them are reported as
//! `skipped` with the reason attached.

use crate::oil;
use oilc::{RuntimeExpr, RuntimeProgram, RuntimeRule};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

/// One synthetic or recorded event: a flat map of canonical field path to value.
pub type EventRow = serde_json::Map<String, Value>;

#[derive(Debug, Clone, Deserialize)]
pub struct SimulationRequest {
    pub source: String,
    pub events: Vec<EventRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimMatch {
    pub event_index: usize,
    pub rule_id: String,
    pub rule_name: String,
    pub score: i32,
    pub actions: Vec<String>,
    /// Field paths the predicates actually read for this event.
    pub matched_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleOutcome {
    pub id: String,
    pub name: String,
    pub class: String,
    pub evaluated: usize,
    pub matched: usize,
    /// Set when the rule needs runtime state the simulator cannot provide.
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationReport {
    pub ok: bool,
    pub diagnostics: Vec<oil::OilDiagnostic>,
    pub events_processed: usize,
    pub evaluations: usize,
    pub matches: Vec<SimMatch>,
    pub rules: Vec<RuleOutcome>,
    pub elapsed_ms: u64,
    /// Mean nanoseconds per rule evaluation over this run.
    pub ns_per_evaluation: u64,
}

/// Truthiness of a resolved value, mirroring the IR's boolean predicates.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn numeric(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn compare(lhs: &Value, rhs: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(a), Some(b)) = (numeric(lhs), numeric(rhs)) {
        return a.partial_cmp(&b);
    }
    match (lhs, rhs) {
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

fn as_str(value: &Value) -> Option<&str> {
    value.as_str()
}

/// Why a rule cannot be simulated, or None when it can.
fn unsupported_reason(rule: &RuntimeRule) -> Option<String> {
    if !rule.joins.is_empty() {
        return Some(format!(
            "correlates {} alias(es) — joins need the stream engine",
            rule.sources.len()
        ));
    }
    if rule.window.is_some() {
        return Some("uses a temporal window — needs windowed state".into());
    }
    let mut blockers: Vec<String> = Vec::new();
    for predicate in &rule.predicates {
        collect_blockers(predicate, &mut blockers);
    }
    for requirement in &rule.require {
        collect_blockers(requirement, &mut blockers);
    }
    for modifier in &rule.score.modifiers {
        if let Some(condition) = &modifier.condition {
            collect_blockers(condition, &mut blockers);
        }
    }
    if blockers.is_empty() {
        None
    } else {
        blockers.sort();
        blockers.dedup();
        Some(format!("needs runtime state: {}", blockers.join(", ")))
    }
}

fn collect_blockers(expr: &RuntimeExpr, out: &mut Vec<String>) {
    match expr {
        RuntimeExpr::Call { name, args } => {
            out.push(format!("{name}()"));
            args.iter().for_each(|arg| collect_blockers(arg, out));
        }
        RuntimeExpr::Unsupported { kind } => out.push(kind.clone()),
        RuntimeExpr::Project { base, .. } => collect_blockers(base, out),
        RuntimeExpr::Not { expr } => collect_blockers(expr, out),
        RuntimeExpr::List { items } => items.iter().for_each(|i| collect_blockers(i, out)),
        RuntimeExpr::In { lhs, rhs } => {
            collect_blockers(lhs, out);
            rhs.iter().for_each(|i| collect_blockers(i, out));
        }
        RuntimeExpr::Matches { lhs, .. } => collect_blockers(lhs, out),
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
            collect_blockers(lhs, out);
            collect_blockers(rhs, out);
        }
        _ => {}
    }
}

struct EvalCtx<'a> {
    event: &'a EventRow,
    /// Field paths read during this evaluation, for match explanation.
    touched: Vec<String>,
}

impl<'a> EvalCtx<'a> {
    /// Resolve a canonical field path.
    ///
    /// Recorded telemetry rarely carries fully-qualified paths, so a suffix
    /// match is accepted: `process.name` resolves against a row keyed `name`.
    fn field(&mut self, path: &str) -> Value {
        self.touched.push(path.to_string());
        if let Some(value) = self.event.get(path) {
            return value.clone();
        }
        if let Some(tail) = path.rsplit('.').next() {
            if let Some(value) = self.event.get(tail) {
                return value.clone();
            }
        }
        Value::Null
    }
}

fn eval(expr: &RuntimeExpr, ctx: &mut EvalCtx) -> Value {
    match expr {
        RuntimeExpr::Bool { value } => Value::Bool(*value),
        RuntimeExpr::Null => Value::Null,
        RuntimeExpr::Int { value } => Value::from(*value),
        RuntimeExpr::Float { value } => Value::from(*value),
        RuntimeExpr::Str { value } => Value::String(value.clone()),
        RuntimeExpr::Duration { value, .. } => Value::from(*value),
        RuntimeExpr::List { items } => {
            Value::Array(items.iter().map(|item| eval(item, ctx)).collect())
        }
        RuntimeExpr::Field { path } => ctx.field(path),
        RuntimeExpr::Project { base, field } => {
            let base = eval(base, ctx);
            base.get(field).cloned().unwrap_or(Value::Null)
        }
        RuntimeExpr::And { lhs, rhs } => {
            Value::Bool(truthy(&eval(lhs, ctx)) && truthy(&eval(rhs, ctx)))
        }
        RuntimeExpr::Or { lhs, rhs } => {
            Value::Bool(truthy(&eval(lhs, ctx)) || truthy(&eval(rhs, ctx)))
        }
        RuntimeExpr::Not { expr } => Value::Bool(!truthy(&eval(expr, ctx))),
        RuntimeExpr::Eq { lhs, rhs } => Value::Bool(eval(lhs, ctx) == eval(rhs, ctx)),
        RuntimeExpr::Ne { lhs, rhs } => Value::Bool(eval(lhs, ctx) != eval(rhs, ctx)),
        RuntimeExpr::Lt { lhs, rhs } => ordering(lhs, rhs, ctx, |o| o.is_lt()),
        RuntimeExpr::Gt { lhs, rhs } => ordering(lhs, rhs, ctx, |o| o.is_gt()),
        RuntimeExpr::Le { lhs, rhs } => ordering(lhs, rhs, ctx, |o| o.is_le()),
        RuntimeExpr::Ge { lhs, rhs } => ordering(lhs, rhs, ctx, |o| o.is_ge()),
        RuntimeExpr::Add { lhs, rhs } => arithmetic(lhs, rhs, ctx, |a, b| a + b),
        RuntimeExpr::Sub { lhs, rhs } => arithmetic(lhs, rhs, ctx, |a, b| a - b),
        RuntimeExpr::Mul { lhs, rhs } => arithmetic(lhs, rhs, ctx, |a, b| a * b),
        RuntimeExpr::Div { lhs, rhs } => {
            let (a, b) = (eval(lhs, ctx), eval(rhs, ctx));
            match (numeric(&a), numeric(&b)) {
                (Some(_), Some(divisor)) if divisor == 0.0 => Value::Null,
                (Some(a), Some(b)) => Value::from(a / b),
                _ => Value::Null,
            }
        }
        RuntimeExpr::In { lhs, rhs } => {
            let needle = eval(lhs, ctx);
            Value::Bool(rhs.iter().any(|item| eval(item, ctx) == needle))
        }
        RuntimeExpr::StartsWith { lhs, rhs } => string_test(lhs, rhs, ctx, |a, b| a.starts_with(b)),
        RuntimeExpr::EndsWith { lhs, rhs } => string_test(lhs, rhs, ctx, |a, b| a.ends_with(b)),
        RuntimeExpr::Contains { lhs, rhs } => string_test(lhs, rhs, ctx, |a, b| a.contains(b)),
        // `matches` is a regex predicate; the simulator does not link a regex
        // engine, so it declines rather than guessing.
        RuntimeExpr::Matches { .. } => Value::Null,
        RuntimeExpr::Call { .. } | RuntimeExpr::Unsupported { .. } => Value::Null,
    }
}

fn ordering(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    ctx: &mut EvalCtx,
    test: fn(std::cmp::Ordering) -> bool,
) -> Value {
    let (a, b) = (eval(lhs, ctx), eval(rhs, ctx));
    match compare(&a, &b) {
        Some(order) => Value::Bool(test(order)),
        None => Value::Bool(false),
    }
}

fn arithmetic(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    ctx: &mut EvalCtx,
    op: fn(f64, f64) -> f64,
) -> Value {
    let (a, b) = (eval(lhs, ctx), eval(rhs, ctx));
    match (numeric(&a), numeric(&b)) {
        (Some(a), Some(b)) => Value::from(op(a, b)),
        _ => Value::Null,
    }
}

fn string_test(
    lhs: &RuntimeExpr,
    rhs: &RuntimeExpr,
    ctx: &mut EvalCtx,
    test: fn(&str, &str) -> bool,
) -> Value {
    let (a, b) = (eval(lhs, ctx), eval(rhs, ctx));
    match (as_str(&a), as_str(&b)) {
        (Some(a), Some(b)) => Value::Bool(test(a, b)),
        _ => Value::Bool(false),
    }
}

fn score_for(rule: &RuntimeRule, ctx: &mut EvalCtx) -> i32 {
    let mut score = rule.score.base;
    for modifier in &rule.score.modifiers {
        let applies = match &modifier.condition {
            Some(condition) => truthy(&eval(condition, ctx)),
            None => true,
        };
        if applies {
            score += modifier.delta;
        }
    }
    score
}

fn actions_for(rule: &RuntimeRule, ctx: &mut EvalCtx) -> Vec<String> {
    let mut actions = Vec::new();
    for branch in &rule.respond.branches {
        let applies = match &branch.condition {
            Some(condition) => truthy(&eval(condition, ctx)),
            None => true,
        };
        if !applies {
            continue;
        }
        for action in &branch.actions {
            if let Some(tag) = serde_json::to_value(action)
                .ok()
                .and_then(|v| v.get("action").and_then(Value::as_str).map(str::to_string))
            {
                actions.push(tag);
            }
        }
        // Respond branches are ordered like if/else: the first match wins.
        break;
    }
    actions
}

/// Replay `events` through every simulatable rule in `program`.
pub fn run(program: &RuntimeProgram, events: &[EventRow]) -> SimulationReport {
    let started = Instant::now();
    let mut matches = Vec::new();
    let mut outcomes = Vec::new();
    let mut evaluations = 0usize;

    for rule in &program.rules {
        let class = serde_json::to_value(rule.class)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "temporal".into());

        if let Some(reason) = unsupported_reason(rule) {
            outcomes.push(RuleOutcome {
                id: rule.id.clone(),
                name: rule.name.clone(),
                class,
                evaluated: 0,
                matched: 0,
                skipped_reason: Some(reason),
            });
            continue;
        }

        let mut matched = 0usize;
        for (index, event) in events.iter().enumerate() {
            let mut ctx = EvalCtx {
                event,
                touched: Vec::new(),
            };
            evaluations += 1;
            let passes = rule
                .predicates
                .iter()
                .all(|predicate| truthy(&eval(predicate, &mut ctx)));
            if !passes {
                continue;
            }
            let score = score_for(rule, &mut ctx);
            let gated = rule
                .require
                .iter()
                .all(|requirement| truthy(&eval(requirement, &mut ctx)));
            if !gated {
                continue;
            }
            matched += 1;
            let mut touched = ctx.touched.clone();
            touched.sort();
            touched.dedup();
            let actions = actions_for(rule, &mut ctx);
            matches.push(SimMatch {
                event_index: index,
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                score,
                actions,
                matched_on: touched,
            });
        }

        outcomes.push(RuleOutcome {
            id: rule.id.clone(),
            name: rule.name.clone(),
            class,
            evaluated: events.len(),
            matched,
            skipped_reason: None,
        });
    }

    let elapsed = started.elapsed();
    SimulationReport {
        ok: true,
        diagnostics: Vec::new(),
        events_processed: events.len(),
        evaluations,
        matches,
        rules: outcomes,
        elapsed_ms: elapsed.as_millis() as u64,
        ns_per_evaluation: if evaluations == 0 {
            0
        } else {
            (elapsed.as_nanos() / evaluations as u128) as u64
        },
    }
}

/// Compile then simulate, reporting compile failures in the same envelope.
pub fn simulate(request: &SimulationRequest) -> SimulationReport {
    match oil::runtime_program(&request.source) {
        Err(diagnostics) => SimulationReport {
            ok: false,
            diagnostics,
            events_processed: 0,
            evaluations: 0,
            matches: Vec::new(),
            rules: Vec::new(),
            elapsed_ms: 0,
            ns_per_evaluation: 0,
        },
        Ok(program) => run(&program, &request.events),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pairs: &[(&str, Value)]) -> EventRow {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    const SHELL_RULE: &str = r#"
rule "shell_exec" {
  from endpoint.process

  where
    process.name in ["bash", "sh"]

  respond
    alert high
}
"#;

    #[test]
    fn matches_only_events_satisfying_the_predicate() {
        let program = oil::runtime_program(SHELL_RULE).expect("rule compiles");
        let events = vec![
            event(&[("process.name", Value::from("bash"))]),
            event(&[("process.name", Value::from("nginx"))]),
        ];
        let report = run(&program, &events);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].event_index, 0);
    }

    #[test]
    fn resolves_short_field_names_from_recorded_rows() {
        let program = oil::runtime_program(SHELL_RULE).expect("rule compiles");
        // Recorded ingest rows key this field `comm`/`name`, not the canonical path.
        let events = vec![event(&[("name", Value::from("sh"))])];
        assert_eq!(run(&program, &events).matches.len(), 1);
    }

    #[test]
    fn reports_compile_failure_instead_of_simulating() {
        let report = simulate(&SimulationRequest {
            source: "rule \"broken\" { not oil }".into(),
            events: vec![],
        });
        assert!(!report.ok);
        assert!(!report.diagnostics.is_empty());
    }
}
