// Pipeline entrypoint
// Top-level compilation pipeline
mod lexer;
mod parser;
pub mod ast;

use lexer::Lexer;
use std::ops::Range;

pub use parser::{ParseError, Parser};

#[derive(Debug, Clone, Default)]
pub struct CompilerConfig;

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub stage: &'static str,
    pub message: String,
    pub span: Option<Range<usize>>,
}

#[derive(Debug, Clone, Default)]
pub struct CompileOutput {
    pub tokens: Vec<lexer::Token>,
    pub program: Option<ast::Program>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn compile(source: &str, config: &CompilerConfig) -> Result<CompileOutput, Vec<Diagnostic>> {
    let _ = config;

    // Stage 1: Lexical Analyzer
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

    // Stage 3+: type/mir/codegen are still under construction.
    Ok(CompileOutput {
        tokens,
        program: Some(program),
        diagnostics: Vec::new(),
    })
}
