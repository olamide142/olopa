// A complete detection or correlation rule

#[derive(Debug, Clone)]
pub struct RuleDecl {
    pub meta:     Option<MetaBlock>,
    pub name:     Spanned<String>,
    pub sources:  Vec<SourceSpec>,
    pub body:     Spanned<RuleBody>,
    pub where_:   Option<Spanned<Expr>>,
    pub within:   Option<Spanned<Duration>>,
    pub require:  Option<Spanned<RequireClause>>,
    pub lets:     Vec<LetBinding>,
    pub score:    Option<Spanned<ScoreExpr>>,
    pub verify:   Option<VerifyClause>,
    pub emit:     Vec<EmitStmt>,
    pub respond:  Spanned<RespondBlock>,
}


/// Meta information block
#[derive(Debug, Clone)]
pub struct MetaBlock {
    pub severity:    Option<String>,
    pub mitre:       Vec<String>,
    pub tags:        Vec<String>,
    pub description: Option<String>,
}


/// Event source reference
#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub domain: String,      // "endpoint"
    pub event:  String,      // "process"
    pub alias:  Option<Spanned<String>>,
}


/// Rule body — one of four correlation modes
#[derive(Debug, Clone)]
pub enum RuleBody {
    /// Single stream: match event [then event ...]
    Match(MatchBlock),
    /// Multi-stream: correlate A with B on join-key
    Correlate(CorrelateBlock),
    /// Graph: structural path pattern
    Graph(GraphBlock),
    /// Entity-anchored: gather events around an entity
    Around(AroundBlock),
}


/// Sequential event match
#[derive(Debug, Clone)]
pub struct MatchBlock {
    pub steps:   Vec<MatchStep>,  // connected by "then"
}


#[derive(Debug, Clone)]
pub struct MatchStep {
    pub event:   Spanned<EventPattern>,
    pub alias:   Option<Spanned<String>>,
    pub by:      Option<Spanned<String>>,  // bound variable (e.g. process p)
}


#[derive(Debug, Clone)]
pub struct EventPattern {
    pub domain: String,
    pub kind:   String,
}


/// Multi-stream correlation
#[derive(Debug, Clone)]
pub struct CorrelateBlock {
    pub mode:  CorrelateMode,
    pub arms:  Vec<CorrelateArm>,
}


#[derive(Debug, Clone)]
pub enum CorrelateMode {
    All,   // all arms must match
    Any,   // at least one arm must match
    AtLeast(usize), // N or more arms must match
}


#[derive(Debug, Clone)]
pub struct CorrelateArm {
    pub event:    Spanned<EventPattern>,
    pub alias:    Spanned<String>,
    pub join:     CorrelateJoin,
}


#[derive(Debug, Clone)]
pub enum CorrelateJoin {
    /// Implicit join by shared entity variable: "by user"
    ByVariable(Spanned<String>),
    /// Explicit join predicate: "on a.user_id == b.user_id"
    OnPredicate(Spanned<Expr>),
    /// No explicit join — time window correlation only
    None,
}


/// Graph structural pattern
#[derive(Debug, Clone)]
pub struct GraphBlock {
    pub source:   SourceSpec,
    pub patterns: Vec<GraphPattern>,
}


#[derive(Debug, Clone)]
pub struct GraphPattern {
    pub entity_type: String,
    pub alias:       Spanned<String>,
    pub edge_type:   Option<String>,  // if None, any edge
}


/// Entity-anchored gather block
#[derive(Debug, Clone)]
pub struct AroundBlock {
    pub entity:   Spanned<String>,
    pub window:   Spanned<Duration>,
    pub arms:     Vec<GatherArm>,
}


#[derive(Debug, Clone)]
pub struct GatherArm {
    pub event: Spanned<EventPattern>,
    pub alias: Spanned<String>,
}


