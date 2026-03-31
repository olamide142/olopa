# Agent + OILC Alignment TODO

Target plan to restore:
- `oilc` compiles OIL into an executable IR for a Rust runtime.
- `agent` evaluates every event against every compiled rule using that IR/runtime.

## Gap Snapshot (Current)

- `oilc` has MIR, but MIR expressions are still `MirExpr::Raw(Expr)` (AST wrapper), not a runtime-executable op graph.
- `oilc` codegen focuses on text artifacts (`Cypher`) instead of producing a stable runtime IR package.
- `agent` hot path calls a single `RuleEngineLike::evaluate(&event) -> bool`; current impl is `SimpleRuleEngine` (`risk_score >= 0.95`) rather than evaluating compiled rules.
- advanced legacy rule-engine files existed but were not wired into build/runtime path.

## P0 - Architecture Corrections

- [ ] Define and freeze `RuntimeIR` schema shared by `oilc` and `agent`.
  - Must include: normalized predicate ops, field access ops, literals, set refs, score ops, action/emit metadata.
  - Location suggestion: new shared crate (`agent/common` or new `runtime_ir` crate).

- [ ] Replace `MirExpr::Raw(Expr)` with lowered executable IR ops.
  - No AST passthrough in runtime-facing layer.
  - Add explicit lowering pass AST -> MIR -> RuntimeIR.

- [ ] Stop treating backend text generation as the primary execution path for agent runtime.
  - Keep Cypher as an optional target.
  - Make RuntimeIR output first-class artifact from `oilc`.

## P1 - Runtime Integration

- [ ] Add rule package loader in `agent` for RuntimeIR artifacts.
  - Load on startup and support hot reload.

- [ ] Implement real rule evaluator over RuntimeIR.
  - Input: normalized event struct.
  - Output: per-rule match + score + response metadata.

- [ ] Change hot path contract from boolean gate to per-rule evaluation result.
  - Replace `SimpleRuleEngine` in `agent/src/main.rs`.
  - Evaluate each event across active rule set (short-circuit optional, configurable).

- [ ] Wire produced alerts/responses to sender path with rule metadata.
  - Include rule id/name, score, matched predicates, action plan.

## P2 - Correctness + Performance

- [ ] Add cross-project integration tests (`oilc -> artifact -> agent eval`).
  - Golden tests: known event should match expected rule(s).
  - Negative tests: non-matching events.

- [ ] Add ABI/format versioning for RuntimeIR.
  - Reject incompatible rule artifacts gracefully.

- [ ] Add benchmark harness for per-event per-rule throughput.
  - Baseline before optimization.


## Immediate First Slice

1. Introduce shared `RuntimeIR` types.
2. Emit RuntimeIR from `oilc` behind `--mode runtime-ir`.
3. Build an in-process RuntimeIR evaluator in `agent` and replace `SimpleRuleEngine`.
4. Add one end-to-end test rule and event fixture proving full loop.
