# oilc

`oilc` compiles OIL source files into validated intermediate artifacts used by the Olopa runtime.

## Current Outputs

- `check`: run validation and diagnostics only.
- `ast`: print parsed AST.
- `mir`: print lowered MIR.
- `runtime-ir`: emit JSON runtime IR consumed by `olopa`.
- `cypher`: emit graph trigger text artifacts.
- `codegen`: print all enabled backend artifacts (currently Cypher).

## Runtime Path

The active execution path in this repository is:

1. Author rules in `.oil`.
2. Compile with `oilc --emit-runtime-ir ...`.
3. Load JSON runtime IR in `olopa` via `OLOPA_RUNTIME_IR`.
4. Evaluate events in the agent runtime evaluator.

## Quick Usage

```bash
cargo run -- --source src/rules --mode check
cargo run -- --source src/rules --mode runtime-ir --emit-runtime-ir /tmp/olopa-runtime-ir.json
```

## Notes

- Legacy compiled shared-object backend code has been removed from this repository.
- Grammar reference lives at `oilc/docs/grammar.md`.
