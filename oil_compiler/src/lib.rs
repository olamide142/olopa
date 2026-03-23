// Pipeline entrypoint
// Top-level compilation pipeline
mod lexer;
mod parser;
mod prelude;
mod resolver;
mod schema;
mod typecheck;
pub mod ast;
pub mod diagnostics;

use lexer::Lexer;
use std::collections::HashMap;
use std::ops::Range;

// Public exports for downstream consumers/tests.
pub use parser::{ParseError, Parser};
pub use prelude::{
    parse_builtin_callable_signatures, parse_builtin_callables, parse_builtin_predicates,
    parse_builtin_sets, PreludeContext, PreludeError,
};
pub use resolver::{
    resolve_program, resolve_program_with_globals, resolve_program_with_schema, ExternalRef, ExternalSymbolSource,
    ResolveOutput, ResolvedCall, ResolvedCallKind, SymbolTable,
};
pub use schema::{parse_schema, EntitySchema, FieldSchema, FieldType, PrimitiveType, RootSchema, SchemaRegistry};
pub use typecheck::{typecheck_program, TypeDiagnostic, TypecheckOutput};

#[derive(Debug, Clone, Default)]
pub struct CompilerConfig;

#[derive(Debug, Clone)]
pub struct Diagnostic {
    // Pipeline stage that emitted the diagnostic.
    pub stage: &'static str,
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
        tokens,
        program,
        schema,
        prelude,
        None,
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
                parsed_units.push((input.id, tokens, program));
            }
            Err(errors) => {
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

    // Pass 3: resolve each parsed unit against global + prelude + schema.
    for (id, tokens, program) in parsed_units {
        let output = finalize_unit(
            tokens,
            program,
            schema.clone(),
            prelude.clone(),
            Some(&global_symbols),
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

fn load_stage0(_config: &CompilerConfig) -> Result<(SchemaRegistry, PreludeContext), Vec<Diagnostic>> {
    // Stage 0A: Load and parse stdlib schema prelude.
    let schema_src = include_str!("oil_stdlib/src/schema.oil");
    let schema = parse_schema(schema_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "schema",
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
                message: format!("predicates.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;

    // Stage 0C: Load built-in set declarations.
    let builtin_sets_src = include_str!("oil_stdlib/src/builtins.oil");
    let builtin_sets = parse_builtin_sets(builtin_sets_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                message: format!("builtins.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;
    // Stage 0D: Load built-in callable declarations.
    let builtin_callables_src = include_str!("oil_stdlib/src/callables.oil");
    let builtin_callables = parse_builtin_callables(builtin_callables_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                message: format!("callables.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;
    let builtin_callable_signatures =
        parse_builtin_callable_signatures(builtin_callables_src).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                stage: "prelude",
                message: format!("callables.oil:{}:{}: {}", e.line, e.col, e.message),
                span: None,
            })
            .collect::<Vec<_>>()
    })?;

    Ok((
        schema,
        PreludeContext {
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
) -> CompileOutput {
    // Stage 3: Name resolution using schema + prelude (+ optional global symbols).
    let resolve = resolve_program_with_globals(
        &program,
        &schema,
        &prelude.builtin_predicates,
        &prelude.builtin_sets,
        &prelude.builtin_callables,
        global_symbols,
    );
    let typecheck = typecheck_program(&program, &schema, &prelude.builtin_callable_signatures);
    let mut diagnostics = Vec::new();
    diagnostics.extend(resolve.diagnostics.iter().map(|d| Diagnostic {
        stage: "resolve",
        message: d.message.clone(),
        span: d.span.clone(),
    }));
    diagnostics.extend(typecheck.diagnostics.iter().map(|d| Diagnostic {
        stage: "typecheck",
        message: d.message.clone(),
        span: d.span.clone(),
    }));

    CompileOutput {
        tokens,
        program: Some(program),
        schema: Some(schema),
        prelude: Some(prelude),
        resolve: Some(resolve),
        typecheck: Some(typecheck),
        diagnostics,
    }
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
