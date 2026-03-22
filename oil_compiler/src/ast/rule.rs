use super::actions::{LetBinding, RespondBlock, ScoreExpr};
use super::expr::Expr;
use super::{OilDuration, Spanned};

/// Complete rule declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleDecl {
    pub meta: Option<MetaBlock>,
    pub name: Spanned<String>,
    pub sources: Vec<SourceSpec>,
    pub body: Spanned<RuleBody>,
    pub where_: Option<Spanned<Expr>>,
    pub within: Option<Spanned<OilDuration>>,
    pub require: Option<Spanned<RequireClause>>,
    pub lets: Vec<LetBinding>,
    pub score: Option<Spanned<ScoreExpr>>,
    pub verify: Option<VerifyClause>,
    pub emit: Vec<EmitStmt>,
    pub respond: Spanned<RespondBlock>,
}

/// Rule metadata block.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MetaBlock {
    pub severity: Option<String>,
    pub mitre: Vec<String>,
    pub tags: Vec<String>,
    pub description: Option<String>,
}

/// Event source reference, e.g. `endpoint.process as p`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceSpec {
    pub domain: String,
    pub event: String,
    pub alias: Option<Spanned<String>>,
}

/// Rule body variants.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleBody {
    Match(MatchBlock),
    Correlate(CorrelateBlock),
    Graph(GraphBlock),
    Around(AroundBlock),
}

/// Sequential event matching.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MatchBlock {
    pub steps: Vec<MatchStep>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchStep {
    pub event: Spanned<EventPattern>,
    pub alias: Option<Spanned<String>>,
    pub by: Option<Spanned<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventPattern {
    pub domain: String,
    pub kind: String,
}

/// Multi-stream correlation.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelateBlock {
    pub mode: CorrelateMode,
    pub arms: Vec<CorrelateArm>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelateMode {
    All,
    Any,
    AtLeast(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelateArm {
    pub event: Spanned<EventPattern>,
    pub alias: Spanned<String>,
    pub join: CorrelateJoin,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorrelateJoin {
    ByVariable(Spanned<String>),
    OnPredicate(Spanned<Expr>),
    None,
}

/// Graph structural block.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphBlock {
    pub source: SourceSpec,
    pub patterns: Vec<GraphPattern>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GraphPattern {
    pub entity_type: String,
    pub alias: Spanned<String>,
    pub edge_type: Option<String>,
}

/// Entity-anchored gather block.
#[derive(Debug, Clone, PartialEq)]
pub struct AroundBlock {
    pub entity: Spanned<String>,
    pub window: Spanned<OilDuration>,
    pub arms: Vec<GatherArm>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatherArm {
    pub event: Spanned<EventPattern>,
    pub alias: Spanned<String>,
}

/// Require clause placeholder.
#[derive(Debug, Clone, PartialEq)]
pub struct RequireClause {
    pub expr: Spanned<Expr>,
}

/// Verify clause placeholder.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyClause {
    pub expr: Spanned<Expr>,
}

/// Fact emission statement placeholder.
#[derive(Debug, Clone, PartialEq)]
pub struct EmitStmt {
    pub fact_name: Spanned<String>,
    pub args: Vec<Spanned<Expr>>,
    pub expires: Option<Spanned<OilDuration>>,
}
