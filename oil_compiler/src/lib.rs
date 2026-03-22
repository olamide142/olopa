// Pipeline entrypoint
// Top-level compilation pipeline
mod lexer;

use lexer::Lexer;
use std::ops::Range;

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

    // Stage 2+: parser/type/mir/codegen are still under construction.
    Ok(CompileOutput {
        tokens,
        diagnostics: Vec::new(),
    })
}
