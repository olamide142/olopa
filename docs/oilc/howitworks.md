# oilc: How It Works

This document is a code-accurate walkthrough of the `oilc` compiler as implemented today in `oilc/src`.

It is written for code-freeze review: what is actually on the execution path, what data flows between stages, and what is still partial or legacy.

For authoring and operational rollout, see `docs/oilc/rules-authoring-and-rollout.md`.

## 1) Mental Model

`oilc` is a multi-stage compiler for OIL rules:

1. Load stdlib schema and prelude symbols.
2. Lex source into tokens.
3. Parse tokens into AST.
4. Resolve names and paths.
5. Type-check expressions/clauses.
6. Lower AST to MIR.
7. Validate MIR shape.
8. Lower MIR to runtime IR.
9. Optionally generate backend artifacts (currently Cypher).
10. Normalize diagnostics for CLI/API output.

Core entrypoints:

- Library API: `oilc/src/lib.rs`
  - `compile(source, config)`
  - `compile_many(inputs, config)`
- CLI: `oilc/src/main.rs`

## 2) What Runs In Production Path

### 2.1 Stage 0: Schema + Prelude Load

Implemented in `load_stage0()` (`oilc/src/lib.rs`).

- Parses schema from `oilc/src/oil_stdlib/src/schema.oil`.
- Parses built-in predicates from `predicates.oil`.
- Parses built-in sets from `builtins.oil`.
- Parses callable names + typed signatures from `callables.oil`.

Outputs:

- `SchemaRegistry` (`oilc/src/schema/mod.rs`)
- `PreludeContext` (`oilc/src/prelude/mod.rs`)

### 2.2 Stage 1: Lexing

Implemented by Pest in `oilc/src/parser/oil.pest`, with the compatibility adapter
in `oilc/src/lexer/pest_lexer.rs`.

- Pest is the authoritative source recognizer/tokenizer; the former handwritten
  UTF-8 scanner has been removed.
- Emits `Token { kind, span }`.
- Preserves newlines as tokens for parser clause boundaries.
- Handles line (`#`, `//`) and block (`/* ... */`) comments.
- Supports durations (`500ms`, `10m`, `1h`, etc.).

The stable token representation is retained temporarily so the existing AST
construction and diagnostic recovery code can migrate grammar production by
grammar production without changing the compiler's public output.

### 2.3 Stage 2: Parsing

Implemented in `oilc/src/parser/mod.rs`.

- Pest owns source recognition; the current AST adapter consumes Pest-produced
  tokens and retains non-fatal error accumulation.
- Expression parsing uses Pratt precedence.
- Produces AST types from `oilc/src/ast/*`.

The stdlib schema is independently parsed by the typed Pest grammar in
`oilc/src/schema/schema.pest`; duplicate root/entity/field checks run after the
syntax parse.

Top-level declarations parsed today:

- `use` / `import`
- `set`
- `predicate`
- `fact`
- `rule`

Rule clauses parsed today:

- `from` / `source`
- `match`
- `correlate`
- `graph`
- `around`
- `where`
- `within`
- `let`
- `score`
- `require`
- `verify`
- `emit`
- `respond`

### 2.4 Stage 3: Resolver

Implemented in `oilc/src/resolver/mod.rs`.

- Builds symbol tables (sets, predicates, facts, imports, optional cross-file globals).
- Resolves identifiers and call names.
- Validates schema-backed dotted paths (`p.parent.name`, etc.).
- Emits non-fatal diagnostics for unknown identifiers/callables/fields.

Important behavior:

- `compile_many()` builds global symbol table first, then resolves each file with project-wide visibility.
- Emitted facts are included in symbols to support cross-file fact consumption.

### 2.5 Stage 4: Type Checker

Implemented in `oilc/src/typecheck/mod.rs`.

- Infers expression types (`Ty`) using schema + local scope.
- Checks bool contexts (`where`, `require`, score conditions, respond conditions).
- Checks operator compatibility (`in`, `contains`, comparisons, string/path ops).
- Checks callable signatures and root callable arity/types.
- Emits typed diagnostics with severity and kind.

### 2.6 Stage 5: MIR Lowering

Implemented in `oilc/src/mid/mod.rs`.

- Converts AST rules to `MirProgram`.
- Classifies rules (`HotPath`, `Temporal`, `Graph`, `Around`, `Policy`).
- Lowers predicates/joins/score/respond/emit/verify into MIR structs.
- Lowers expressions into `MirExpr` variants.

### 2.7 Stage 6: MIR Validation

Implemented in `validate_program()` (`oilc/src/mid/mod.rs`).

Checks for:

- duplicate/empty rule IDs
- malformed sources/joins/respond/emit/verify
- score base range warnings

### 2.8 Stage 7: Backend Codegen (Cypher)

Implemented in `oilc/src/codegen/mod.rs` and `oilc/src/codegen/cypher.rs`.

- Generates one Cypher trigger artifact per MIR rule.
- Converts MIR expressions into Cypher boolean/value expressions.
- Uses sanitized trigger names (`oilc_<rule>_trigger`).

### 2.9 Stage 8: Runtime IR Lowering

Implemented in `oilc/src/runtime_ir.rs`.

- Converts MIR into JSON-serializable `RuntimeProgram`.
- Normalizes action and enum values to runtime-friendly strings.
- Emits versioned payload (`version: 1`).

### 2.10 Stage 9: Diagnostic Normalization

In `finalize_unit()` (`oilc/src/lib.rs`), diagnostics from resolver/typecheck/MIR validation are mapped into a unified `Diagnostic` type for CLI and API consumers.

Renderer:

- `oilc/src/diagnostics/mod.rs` formats source snippets with line/column and carets.

## 3) Single-File vs Multi-File Compile

`compile(source, config)`:

- one source string
- no cross-file global symbol pass

`compile_many(inputs, config)`:

- lex/parse each unit first
- builds project symbol table (`set`, `predicate`, `fact`, emitted facts)
- resolves each unit with global visibility
- returns per-unit outputs + project diagnostics

This is the important freeze-time behavior for repo-scale rule packs.

## 4) CLI Behavior (`oilc/src/main.rs`)

The CLI:

- collects `.oil` files from file or directory inputs
- compiles in batch via `compile_many()`
- supports modes: `check`, `ast`, `mir`, `runtime-ir`, `cypher`, `codegen`
- supports JSON/text diagnostics
- can write runtime IR artifact with `--emit-runtime-ir`

Mode guardrails:

- `--mode mir|runtime-ir|cypher|codegen` requires MIR
- `--mode cypher|codegen` requires codegen

## 5) Data Structures Cheat Sheet

- AST: `oilc/src/ast/*`
  - syntax-level tree, spans attached via `Spanned<T>`
- MIR: `oilc/src/mid/mod.rs`
  - compiler-internal normalized representation
- Runtime IR: `oilc/src/runtime_ir.rs`
  - serialized contract for runtime evaluator
- Codegen artifacts: `oilc/src/codegen/*`
  - current backend: Cypher trigger text

## 6) Known Partial Areas (Intentional)

From implementation and in-code comments:

- Parser intentionally partial for some advanced language surfaces.
- Some AST variants exist ahead of parser coverage (future-facing model).
- MIR/Runtime lowering uses `Unsupported` expression fallbacks for unsupported forms.

This is not hidden behavior; it is explicitly represented in parser comments and IR enums.

## 7) Code-Freeze Audit Notes (AI-Slop Check)

### 7.1 Active Path Quality

The active compiler path (`lib.rs` pipeline + lexer/parser/resolver/typecheck/mid/runtime_ir/codegen + CLI) is coherent and tested.

Observed locally:

- `cargo test --manifest-path oilc/Cargo.toml` passed after the Pest migration.
- Tests cover parser recovery, resolver/typecheck semantics, MIR lowering, runtime IR shape, and Cypher snapshots.

No obvious "AI slop" patterns were found in active-path logic (for example: contradictory APIs, dead branches inside executed modules, or placeholder stubs being invoked).

### 7.2 Legacy / Out-of-Path Files To Treat Carefully

These files are present but not part of the active module graph exported by `lib.rs`:

- `oilc/src/type_checker.rs`
- `oilc/src/optimizer/constant_folding.rs`
- `oilc/src/optimizer/predicate_pushdown.rs`
- `oilc/src/optimizer/set_inlining.rs`

They read like draft/legacy code and should be considered non-authoritative during freeze unless intentionally wired in.

### 7.3 Freeze Recommendation

If this is a strict freeze, lock and review in this order:

1. `lib.rs` pipeline and config flags.
2. `parser/mod.rs` grammar surface and error recovery.
3. `resolver/mod.rs` and `typecheck/mod.rs` semantics.
4. `mid/mod.rs` and `runtime_ir.rs` contract stability.
5. `codegen/cypher.rs` only if Cypher backend is required in freeze scope.

Then explicitly mark legacy/out-of-path files as archived or move them to a `legacy/` location to reduce reviewer confusion.

## 8) Fast Trace: One Rule Through Compiler

Given one rule file:

1. Lexer emits token stream with spans.
2. Parser builds AST `Program` containing `RuleDecl`.
3. Resolver validates names and schema paths.
4. Type checker validates bool contexts, operators, and callable signatures.
5. MIR lowerer converts to `MirRule` + `MirExpr`.
6. Runtime lowerer converts to `RuntimeRule` + `RuntimeExpr` JSON model.
7. Optional Cypher codegen emits trigger text from MIR predicates.

That is the actual end-to-end execution path as of this freeze snapshot.
