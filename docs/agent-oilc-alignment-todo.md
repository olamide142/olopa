# Agent + OILC Alignment TODO

> **Status: superseded (2026-08-09).**
> The functional alignment work below has shipped: RuntimeIR is a versioned
> compiler/agent contract, `MirExpr::Raw` is gone, `oilc` emits runtime IR as a
> first-class artifact, and the agent evaluates per-rule matches in place of
> `SimpleRuleEngine`. Cross-project integration coverage lives in
> `agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime`. The proposed
> standalone throughput benchmark did not ship as part of this plan. This file
> is retained for historical context; active work is tracked in
> `docs/olopa-implementation-todo.md`.

Target plan to restore:
- `oilc` compiles OIL into an executable IR for a Rust runtime.
- `agent` evaluates every event against every compiled rule using that IR/runtime.

## Historical Gap Snapshot (Closed)

When this plan was written:

- `oilc` has MIR, but MIR expressions are still `MirExpr::Raw(Expr)` (AST wrapper), not a runtime-executable op graph.
- `oilc` codegen focuses on text artifacts (`Cypher`) instead of producing a stable runtime IR package.
- `agent` hot path calls a single `RuleEngineLike::evaluate(&event) -> bool`; current impl is `SimpleRuleEngine` (`risk_score >= 0.95`) rather than evaluating compiled rules.
- advanced legacy rule-engine files existed but were not wired into build/runtime path.

## P0 - Architecture Corrections

- [x] Define and version the `RuntimeIR` contract consumed by `oilc` and `agent`.
  - Must include: normalized predicate ops, field access ops, literals, set refs, score ops, action/emit metadata.
  - Location suggestion: new shared crate (`agent/common` or new `runtime_ir` crate).

- [x] Replace `MirExpr::Raw(Expr)` with lowered executable IR ops.
  - No AST passthrough in runtime-facing layer.
  - Add explicit lowering pass AST -> MIR -> RuntimeIR.

- [x] Stop treating backend text generation as the primary execution path for agent runtime.
  - Keep Cypher as an optional target.
  - Make RuntimeIR output first-class artifact from `oilc`.

## P1 - Runtime Integration

- [x] Add rule package loader in `agent` for RuntimeIR artifacts.
  - Load on startup and support hot reload.

- [x] Implement real rule evaluator over RuntimeIR.
  - Input: normalized event struct.
  - Output: per-rule match + score + response metadata.

- [x] Change hot path contract from boolean gate to per-rule evaluation result.
  - Replace `SimpleRuleEngine` in `agent/src/main.rs`.
  - Evaluate each event across active rule set (short-circuit optional, configurable).

- [x] Wire produced alerts/responses to sender path with rule metadata.
  - Include rule id/name, score, matched predicates, action plan.

## P2 - Correctness + Performance

- [x] Add cross-project integration tests (`oilc -> artifact -> agent eval`).
  - Golden tests: known event should match expected rule(s).
  - Negative tests: non-matching events.

- [x] Add ABI/format versioning for RuntimeIR.
  - Reject incompatible rule artifacts gracefully.

- [ ] Add benchmark harness for per-event per-rule throughput.
  - Baseline before optimization.
  - Not delivered under this historical plan; performance work belongs in the
    active implementation roadmap.


## Delivered First Slice

1. [x] Introduce versioned `RuntimeIR` types on the compiler and runtime sides.
2. [x] Emit RuntimeIR from `oilc` behind `--mode runtime-ir`.
3. [x] Build an in-process RuntimeIR evaluator in `agent` and replace `SimpleRuleEngine`.
4. [x] Add an end-to-end rule/event test proving the full loop.
