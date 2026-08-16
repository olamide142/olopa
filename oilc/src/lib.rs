// Pipeline entrypoint
// Top-level compilation pipeline
pub mod ast;
mod codegen;
pub mod diagnostics;
mod lexer;
pub mod mid;
mod parser;
mod prelude;
mod resolver;
mod runtime_ir;
mod schema;
mod typecheck;

use lexer::Lexer;
use std::collections::HashMap;
use std::ops::Range;

// Public exports for downstream consumers/tests.
pub use codegen::{generate_backends, CodegenOutput, CypherArtifact, CypherProgram};
pub use mid::{
    lower_program, validate_program, MirProgram, MirValidationDiagnostic, MirValidationKind,
    MirValidationSeverity,
};
pub use parser::{ParseError, Parser};
pub use prelude::{
    parse_builtin_callable_signatures, parse_builtin_callables, parse_builtin_predicates,
    parse_builtin_sets, CallableParam, CallableSignature, CallableSignatures, CallableTypeRef,
    PreludeContext, PreludeError,
};
pub use resolver::{
    resolve_program, resolve_program_with_globals, resolve_program_with_schema, ExternalRef,
    ExternalSymbolSource, ResolveOutput, ResolvedCall, ResolvedCallKind, SymbolTable,
};
pub use runtime_ir::{
    lower_runtime_program, runtime_callables_from_prelude, runtime_fields_from_schema,
    RuntimeCallable, RuntimeCallableParam, RuntimeCallableType, RuntimeExpr, RuntimeField,
    RuntimeFieldType, RuntimeProgram, RuntimeRule,
};
pub use schema::{
    parse_schema, EntitySchema, FieldSchema, FieldType, PrimitiveType, RootSchema, SchemaRegistry,
};
pub use typecheck::{typecheck_program, TypeDiagnostic, TypecheckOutput};
pub use typecheck::{TypeDiagnosticKind, TypeDiagnosticSeverity};

#[derive(Debug, Clone)]
pub struct CompilerConfig {
    pub run_resolver: bool,
    pub run_typecheck: bool,
    pub run_mir: bool,
    pub run_codegen: bool,
    pub fail_on_resolve_warning: bool,
    pub fail_on_type_warning: bool,
    pub fail_on_mir_warning: bool,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            run_resolver: true,
            run_typecheck: true,
            run_mir: true,
            run_codegen: true,
            fail_on_resolve_warning: false,
            fail_on_type_warning: false,
            fail_on_mir_warning: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    // Pipeline stage that emitted the diagnostic.
    pub stage: &'static str,
    // Whether this diagnostic should fail compilation for the unit.
    pub is_error: bool,
    pub message: String,
    // Optional source span (byte offsets in user source).
    pub span: Option<Range<usize>>,
}

#[derive(Debug, Clone, Default)]
pub struct CompileOutput {
    // Stage 1 output.
    pub tokens: Vec<lexer::Token>,
    // Stage 2 output.
    pub program: Option<ast::Program>,
    // Stage 0 schema prelude.
    pub schema: Option<SchemaRegistry>,
    // Stage 0 prelude symbol context.
    pub prelude: Option<PreludeContext>,
    // Stage 3 output.
    pub resolve: Option<ResolveOutput>,
    // Stage 4 output.
    pub typecheck: Option<TypecheckOutput>,
    // Stage 5 output.
    pub mir: Option<MirProgram>,
    // Stage 5b output (runtime executable IR).
    pub runtime_ir: Option<RuntimeProgram>,
    // Stage 6 output (backend generation).
    pub codegen: Option<CodegenOutput>,
    // Non-fatal diagnostics (currently resolver-focused).
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
pub struct CompileUnitInput {
    pub id: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct CompileUnitResult {
    pub id: String,
    pub output: Option<CompileOutput>,
    pub errors: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Default)]
pub struct CompileManyOutput {
    pub units: Vec<CompileUnitResult>,
    pub project_diagnostics: Vec<Diagnostic>,
}

pub fn compile(source: &str, config: &CompilerConfig) -> Result<CompileOutput, Vec<Diagnostic>> {
    let (schema, prelude) = load_stage0(config)?;
    let (tokens, program) = lex_and_parse(source)?;
    Ok(finalize_unit(
        tokens, program, schema, prelude, None, None, config,
    ))
}

pub fn compile_many(inputs: Vec<CompileUnitInput>, config: &CompilerConfig) -> CompileManyOutput {
    let (schema, prelude) = match load_stage0(config) {
        Ok(x) => x,
        Err(errs) => {
            return CompileManyOutput {
                units: inputs
                    .into_iter()
                    .map(|input| CompileUnitResult {
                        id: input.id,
                        output: None,
                        errors: errs.clone(),
                    })
                    .collect(),
                project_diagnostics: Vec::new(),
            };
        }
    };

    // Pass 1: lex/parse all units.
    let mut parsed_units: Vec<(String, Vec<lexer::Token>, ast::Program)> = Vec::new();
    let mut unit_results: Vec<CompileUnitResult> = Vec::new();

    for input in inputs {
        match lex_and_parse(&input.source) {
            Ok((tokens, program)) => {
                // Keep successfully parsed units for later multi-file passes
                // (global symbol collection + per-unit resolution/codegen).
                parsed_units.push((input.id, tokens, program));
            }
            Err(errors) => {
                // Parsing failed for this unit, so record a per-file failure now.
                // We still continue compiling other inputs that parsed correctly.
                unit_results.push(CompileUnitResult {
                    id: input.id,
                    output: None,
                    errors,
                });
            }
        }
    }

    // Pass 2: build cross-file declarations and duplicate diagnostics.
    let (global_symbols, mut project_diagnostics) = build_global_symbols(&parsed_units);
    let project_definitions = build_project_definitions(&parsed_units);

    // Pass 3: resolve each parsed unit against global + prelude + schema.
    for (id, tokens, program) in parsed_units {
        let output = finalize_unit(
            tokens,
            program,
            schema.clone(),
            prelude.clone(),
            Some(&global_symbols),
            Some(&project_definitions),
            config,
        );
        unit_results.push(CompileUnitResult {
            id,
            output: Some(output),
            errors: Vec::new(),
        });
    }

    // Stable order by unit id for deterministic CLI output.
    unit_results.sort_by(|a, b| a.id.cmp(&b.id));
    project_diagnostics.sort_by(|a, b| a.message.cmp(&b.message));

    CompileManyOutput {
        units: unit_results,
        project_diagnostics,
    }
}

fn load_stage0(
    _config: &CompilerConfig,
) -> Result<(SchemaRegistry, PreludeContext), Vec<Diagnostic>> {
    // Stage 0A: Load and parse stdlib schema prelude.
    let schema_src = include_str!("oil_stdlib/src/schema.oil");
    let schema = parse_schema(schema_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "schema",
                is_error: true,
                message: format!("schema.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;

    // Stage 0B: Load built-in predicate declarations.
    let builtin_predicates_src = include_str!("oil_stdlib/src/predicates.oil");
    let builtin_predicates = parse_builtin_predicates(builtin_predicates_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                is_error: true,
                message: format!("predicates.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;
    let (_, builtin_predicate_program) = lex_and_parse(builtin_predicates_src)?;

    // Stage 0C: Load built-in set declarations.
    let builtin_sets_src = include_str!("oil_stdlib/src/builtins.oil");
    let builtin_sets = parse_builtin_sets(builtin_sets_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                is_error: true,
                message: format!("builtins.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;
    let (_, builtin_set_program) = lex_and_parse(builtin_sets_src)?;
    // Stage 0D: Load built-in callable declarations.
    let builtin_callables_src = include_str!("oil_stdlib/src/callables.oil");
    let builtin_callables = parse_builtin_callables(builtin_callables_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                is_error: true,
                message: format!("callables.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;
    let builtin_callable_signatures = parse_builtin_callable_signatures(builtin_callables_src)
        .map_err(|errs| {
            errs.into_iter()
                .map(|e| Diagnostic {
                    stage: "prelude",
                    is_error: true,
                    message: format!("callables.oil:{}:{}: {}", e.line, e.col, e.message),
                    span: None,
                })
                .collect::<Vec<_>>()
        })?;

    let builtin_program = ast::Program {
        predicates: builtin_predicate_program.predicates,
        sets: builtin_set_program.sets,
        ..ast::Program::default()
    };

    Ok((
        schema,
        PreludeContext {
            builtin_program,
            builtin_predicates,
            builtin_sets,
            builtin_callables,
            builtin_callable_signatures,
        },
    ))
}

fn lex_and_parse(source: &str) -> Result<(Vec<lexer::Token>, ast::Program), Vec<Diagnostic>> {
    // Stage 1: Lexical analysis.
    let tokens = Lexer::new(source).tokenize().map_err(|e| {
        vec![Diagnostic {
            stage: "lex",
            is_error: true,
            message: e.to_string(),
            span: Some(e.span),
        }]
    })?;

    // Stage 2: Parse top-level program.
    let mut parser = Parser::new(tokens.clone());
    let program = parser.parse().map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "parse",
                is_error: true,
                message: e.message,
                span: Some(e.span),
            })
            .collect::<Vec<_>>()
    })?;

    Ok((tokens, program))
}

fn finalize_unit(
    tokens: Vec<lexer::Token>,
    program: ast::Program,
    schema: SchemaRegistry,
    prelude: PreludeContext,
    global_symbols: Option<&SymbolTable>,
    project_definitions: Option<&ast::Program>,
    config: &CompilerConfig,
) -> CompileOutput {
    // Stage 3: Name resolution using schema + prelude (+ optional global symbols).
    let resolve = if config.run_resolver {
        Some(resolve_program_with_globals(
            &program,
            &schema,
            &prelude.builtin_predicates,
            &prelude.builtin_sets,
            &prelude.builtin_callables,
            global_symbols,
        ))
    } else {
        None
    };

    // Stage 4: Typecheck semantic correctness (fact/set usage, callable signatures, etc.).
    let typecheck = if config.run_typecheck {
        Some(typecheck_program(
            &program,
            &schema,
            &prelude.builtin_callable_signatures,
        ))
    } else {
        None
    };

    // Stage 5: Lower AST into MIR when MIR consumers are enabled (validation/codegen/runtime IR).
    let mir = if config.run_mir || config.run_codegen {
        let mut lowering_program = prelude.builtin_program.clone();
        // Project and local definitions intentionally follow stdlib
        // definitions. Local declarations come last so a unit can override a
        // project/stdlib definition deterministically.
        if let Some(project) = project_definitions {
            lowering_program.sets.extend(project.sets.iter().cloned());
            lowering_program
                .predicates
                .extend(project.predicates.iter().cloned());
        }
        lowering_program.sets.extend(program.sets.iter().cloned());
        lowering_program
            .predicates
            .extend(program.predicates.iter().cloned());
        lowering_program.rules = program.rules.clone();
        Some(lower_program(&lowering_program))
    } else {
        None
    };

    // Stage 6: Validate MIR for structural/semantic issues emitted by lowering.
    // Run this whenever MIR exists so unsupported expression nodes cannot bypass
    // checks through alternate mode/config combinations.
    let mir_diagnostics = mir.as_ref().map(validate_program).unwrap_or_default();
    let mir_has_errors = mir_diagnostics
        .iter()
        .any(|d| matches!(d.severity, MirValidationSeverity::Error));

    // Stage 7: Generate backend artifacts (e.g., Cypher) from MIR when requested.
    let codegen = if config.run_codegen {
        mir.as_ref().map(generate_backends)
    } else {
        None
    };

    // Stage 8: Build runtime IR from MIR for downstream runtime execution/serialization.
    // Runtime IR is withheld on MIR errors to enforce the hard compile gate.
    let runtime_fields = runtime_ir::runtime_fields_from_schema(&schema);
    let runtime_callables =
        runtime_ir::runtime_callables_from_prelude(&prelude.builtin_callable_signatures);
    let runtime_ir = if mir_has_errors {
        None
    } else {
        mir.as_ref().map(|mir| {
            let mut program = lower_runtime_program(mir);
            program.fields = runtime_fields.clone();
            program.callables = runtime_callables.clone();
            program
        })
    };

    // Stage 9: Normalize diagnostics from each stage into a single CLI/API-friendly list.
    let mut diagnostics = Vec::new();
    if let Some(resolve) = &resolve {
        diagnostics.extend(resolve.diagnostics.iter().map(|d| Diagnostic {
            stage: "resolve",
            is_error: config.fail_on_resolve_warning,
            message: d.message.clone(),
            span: d.span.clone(),
        }));
    }
    if let Some(typecheck) = &typecheck {
        diagnostics.extend(typecheck.diagnostics.iter().map(|d| Diagnostic {
            stage: "typecheck",
            is_error: matches!(d.severity, TypeDiagnosticSeverity::Error)
                || config.fail_on_type_warning,
            message: d.message.clone(),
            span: d.span.clone(),
        }));
    }
    diagnostics.extend(mir_diagnostics.iter().map(|d| Diagnostic {
        stage: "mir",
        is_error: matches!(d.severity, MirValidationSeverity::Error) || config.fail_on_mir_warning,
        message: d.message.clone(),
        span: None,
    }));

    // Stage 10: Return all produced artifacts (plus diagnostics) for this compile unit.
    CompileOutput {
        tokens,
        program: Some(program),
        schema: Some(schema),
        prelude: Some(prelude),
        resolve,
        typecheck,
        mir,
        runtime_ir,
        codegen,
        diagnostics,
    }
}

/// Collect executable set/predicate bodies for cross-file MIR expansion.
///
/// The resolver's global symbol table only records names. Runtime lowering
/// needs the corresponding declaration bodies as well, otherwise a predicate
/// declared in one source unit remains an unknown runtime callable in another.
fn build_project_definitions(units: &[(String, Vec<lexer::Token>, ast::Program)]) -> ast::Program {
    let mut definitions = ast::Program::default();
    for (_id, _tokens, program) in units {
        definitions.sets.extend(program.sets.iter().cloned());
        definitions
            .predicates
            .extend(program.predicates.iter().cloned());
    }
    definitions
}

fn build_global_symbols(
    units: &[(String, Vec<lexer::Token>, ast::Program)],
) -> (SymbolTable, Vec<Diagnostic>) {
    let mut symbols = SymbolTable::default();
    let mut diagnostics = Vec::new();
    let mut fact_owner: HashMap<String, String> = HashMap::new();

    for (id, _tokens, program) in units {
        for set in &program.sets {
            let name = set.name.node.clone();
            // Local overrides for sets are allowed; project scope just needs
            // membership knowledge for cross-file resolution.
            symbols.sets.insert(name);
        }

        for pred in &program.predicates {
            let name = pred.name.node.clone();
            // Local overrides for predicates are allowed; project scope just needs
            // membership knowledge for cross-file resolution.
            symbols.predicates.insert(name);
        }

        for fact in &program.facts {
            let name = fact.name.node.clone();
            if let Some(prev) = fact_owner.get(&name) {
                diagnostics.push(Diagnostic {
                    stage: "project",
                    is_error: false,
                    message: format!("duplicate fact declaration '{name}' in '{id}' (first declared in '{prev}')"),
                    span: None,
                });
            } else {
                fact_owner.insert(name.clone(), id.clone());
            }
            symbols.facts.insert(name);
        }

        // Fact emissions contribute to the project fact model so facts emitted
        // in one file can be consumed in another without false unknown-callable
        // warnings during project compilation.
        for rule in &program.rules {
            for emit in &rule.emit {
                symbols.facts.insert(emit.fact_name.node.clone());
            }
        }
    }

    (symbols, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_emits_typed_callable_contracts() {
        let src = r#"
rule "long_dns_name" {
  from dns.query
  correlate dns.query as q
  where len(q.domain.value) > 40
  respond alert medium
}
"#;
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let runtime = out.runtime_ir.expect("runtime ir");
        let len_overloads = runtime
            .callables
            .iter()
            .filter(|callable| callable.name == "len")
            .collect::<Vec<_>>();
        assert_eq!(len_overloads.len(), 2);
        let len = len_overloads
            .iter()
            .find(|callable| callable.params[0].value_type == RuntimeCallableType::Str)
            .expect("string len callable contract");
        assert_eq!(len.params.len(), 1);
        assert_eq!(len.params[0].name, "value");
        assert_eq!(len.params[0].value_type, RuntimeCallableType::Str);
        assert_eq!(len.returns, Some(RuntimeCallableType::Int));

        let count = runtime
            .callables
            .iter()
            .find(|callable| callable.name == "count")
            .expect("count callable contract");
        assert_eq!(count.params[0].value_type, RuntimeCallableType::Any);

        let is_shell = runtime
            .callables
            .iter()
            .find(|callable| callable.name == "is_shell")
            .expect("is_shell callable contract");
        assert_eq!(
            is_shell.params[0].value_type,
            RuntimeCallableType::Entity("Process".to_string())
        );
    }

    #[test]
    fn compile_keeps_runtime_ir_for_unknown_callable_calls() {
        let src = r#"
rule "unsupported_expr_gate" {
  from endpoint.process
  correlate process.spawn as p
  where unknown_fn(p.pid) == true
  respond alert high
}
"#;
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        assert!(
            out.diagnostics.iter().any(|d| d.stage == "resolve"
                && !d.is_error
                && d.message.contains("unknown callable")),
            "expected resolve unknown-callable warning, got: {:?}",
            out.diagnostics
        );
        assert!(
            out.runtime_ir.is_some(),
            "runtime IR should still be emitted when resolver emits warnings only"
        );
    }

    #[test]
    fn compile_expands_stdlib_predicate_bodies_and_sets_for_runtime() {
        let src = r#"
rule "stdlib_shell" {
  from endpoint.process
  correlate process.spawn as p
  where is_shell(p)
  respond alert high
}
"#;
        let out = compile(src, &CompilerConfig::default()).expect("compile");
        let runtime = out.runtime_ir.expect("runtime ir");
        let RuntimeExpr::In { lhs, rhs } = &runtime.rules[0].predicates[0] else {
            panic!(
                "stdlib predicate should be expanded before runtime emission: {:?}",
                runtime.rules[0].predicates[0]
            );
        };
        assert!(matches!(lhs.as_ref(), RuntimeExpr::Field { path } if path == "process.name"));
        assert!(rhs.len() >= 10);
        assert!(rhs
            .iter()
            .any(|item| matches!(item, RuntimeExpr::Str { value } if value == "bash")));
    }

    #[test]
    fn compile_many_expands_predicates_and_sets_declared_in_another_unit() {
        let definitions = r#"
set approved_shells = ["bash", "zsh"]
predicate approved(proc) = proc.name in approved_shells
"#;
        let rule = r#"
rule "cross_file_predicate" {
  from endpoint.process
  correlate process.spawn as p
  where approved(p)
  respond alert high
}
"#;
        let output = compile_many(
            vec![
                CompileUnitInput {
                    id: "definitions".to_string(),
                    source: definitions.to_string(),
                },
                CompileUnitInput {
                    id: "rule".to_string(),
                    source: rule.to_string(),
                },
            ],
            &CompilerConfig::default(),
        );
        assert!(output.project_diagnostics.is_empty());
        let rule_unit = output
            .units
            .iter()
            .find(|unit| unit.id == "rule")
            .and_then(|unit| unit.output.as_ref())
            .expect("compiled rule unit");
        let runtime = rule_unit.runtime_ir.as_ref().expect("runtime ir");
        let RuntimeExpr::In { rhs, .. } = &runtime.rules[0].predicates[0] else {
            panic!("cross-file predicate should be expanded into membership");
        };
        assert_eq!(rhs.len(), 2);
        assert!(rhs
            .iter()
            .any(|item| matches!(item, RuntimeExpr::Str { value } if value == "bash")));
    }
}
