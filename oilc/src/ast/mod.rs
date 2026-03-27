use std::ops::Range;

pub mod actions;
pub mod expr;
pub mod rule;

pub use actions::*;
pub use expr::*;
pub use rule::*;

/// Source span in byte offsets from the original source text.
pub type Span = Range<usize>;

/// Generic wrapper to attach source spans to AST nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }
}

/// Duration unit used by OIL literals like `15m` or `300s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationUnit {
    Ns,
    Us,
    Ms,
    S,
    M,
    H,
    D,
}

/// Strongly typed OIL duration literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OilDuration {
    pub value: u64,
    pub unit: DurationUnit,
}

/// Full top-level program AST.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Program {
    pub imports: Vec<ImportDecl>,
    pub sets: Vec<SetDecl>,
    pub predicates: Vec<PredicateDecl>,
    pub templates: Vec<TemplateDecl>,
    pub facts: Vec<FactDecl>,
    pub rules: Vec<RuleDecl>,
    pub policies: Vec<PolicyDecl>,
}

/// `use foo.bar` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportDecl {
    pub path: Spanned<Vec<String>>,
}

/// `set x = [...]` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct SetDecl {
    pub name: Spanned<String>,
    pub values: Vec<Spanned<Expr>>,
}

/// Named predicate declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct PredicateDecl {
    pub name: Spanned<String>,
    pub params: Vec<Spanned<String>>,
    pub body: Spanned<Expr>,
}

/// Template declaration placeholder for later phases.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateDecl {
    pub name: Spanned<String>,
}

/// Fact declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct FactDecl {
    pub name: Spanned<String>,
    pub params: Vec<Spanned<String>>,
    pub expires: Option<Spanned<OilDuration>>,
}

/// Policy declaration placeholder for later phases.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecl {
    pub name: Spanned<String>,
}
