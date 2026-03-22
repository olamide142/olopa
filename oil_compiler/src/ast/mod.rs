

use std::ops::Range;


/// Source span — byte offsets into source text
pub type Span = Range<usize>;


/// Every AST node carries a source span for diagnostics
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}


impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self { Self { node, span } }
}


/// Top-level program
#[derive(Debug, Clone)]
pub struct Program {
    pub imports:    Vec<ImportDecl>,
    pub sets:       Vec<SetDecl>,
    pub predicates: Vec<PredicateDecl>,
    pub templates:  Vec<TemplateDecl>,
    pub facts:      Vec<FactDecl>,
    pub rules:      Vec<RuleDecl>,
    pub policies:   Vec<PolicyDecl>,
}


/// import/use declaration
#[derive(Debug, Clone)]
pub struct ImportDecl {
    pub path: Spanned<Vec<String>>,  // ["intel", "malicious_domains"]
}


/// Named set of values
#[derive(Debug, Clone)]
pub struct SetDecl {
    pub name:    Spanned<String>,
    pub values:  Vec<Spanned<Expr>>,
}


/// Reusable predicate (named boolean function)
#[derive(Debug, Clone)]
pub struct PredicateDecl {
    pub name:    Spanned<String>,
    pub params:  Vec<Spanned<String>>,
    pub body:    Spanned<Expr>,
}


/// Fact type declaration
#[derive(Debug, Clone)]
pub struct FactDecl {
    pub name:    Spanned<String>,
    pub params:  Vec<Spanned<String>>,
    pub expires: Option<Spanned<Duration>>,
}
