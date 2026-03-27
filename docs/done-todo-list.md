# OILC Done / TODO List

Tracking progress for `oilc/` so we can ship features one by one.

## Done

- [x] CLI reads `.oil` from file/directory inputs.
- [x] Recursive source discovery for `.oil` files.
- [x] Lexer emits tokens with source spans.
- [x] Parser builds AST for core declarations:
  - [x] `use/import`
  - [x] `set`
  - [x] `rule`
  - [x] `predicate`
  - [x] `fact`
- [x] Resolver pass implemented:
  - [x] Local symbol collection
  - [x] Builtin/prelude symbol awareness
  - [x] Cross-file symbol merge (`compile_many`)
  - [x] Non-fatal diagnostics
- [x] Typechecker pass implemented for core expressions/clauses.
- [x] Schema parser and stdlib prelude loading wired into pipeline.
- [x] Human-readable diagnostics with file/line/column and carets.
- [x] Batch compile of `src/rules` currently succeeds (warnings only).

## TODO (In Order)

### 1) Parser completeness
- [ ] Finish full semantics and AST support for:
  - [x] `emit`
  - [x] `verify`
  - [x] `require`
- [x] Add parser error-recovery tests for `emit`/`verify`/`require`.

### 2) Type system hardening
- [x] Tighten nullable/member-chain handling to reduce noisy warnings.
- [x] Improve callable signature checks and argument arity/type diagnostics.
- [x] Decide warning vs error policy per typecheck diagnostic class.

### 3) MIR layer
- [x] Define MIR data model (`rule`, predicates, score/actions, windows).
- [x] Implement AST -> MIR lowering pass.
- [x] Add MIR validation invariants and tests.

### 4) Backends
- [x] Wire at least one backend into compile pipeline end-to-end.
- [x] Start with a single target (recommended: Cypher or stream EPL).
- [x] Add backend snapshot tests from sample `.oil` rules.
- [x] Make Cypher output semantically executable (remove debug AST rendering, map MIR to valid Cypher expressions).
- [x] Make EPL output compileable against runtime contracts (typed expression emitter + alert construction).
- [x] Add backend “compiles/runs” tests (not just snapshot shape).

### 5) Compiler config and output model
- [x] Replace placeholder `CompilerConfig` with real options.
- [x] Support output modes (`check`, `ast`, `mir`, target codegen).
- [x] Add machine-readable diagnostics output option (JSON).

### 6) Quality gates
- [x] Unit tests for lexer/parser/resolver/typecheck.
- [ ] Integration tests for multi-file compilation.
- [ ] CI command for deterministic compile/test.

### 7) Docs alignment
- [ ] Update `oilc/README.md` to match current implemented stages.
- [ ] Document supported OIL subset and known limitations.

## Current Next Task

- [ ] Task 6.2: add integration tests for multi-file compilation.
