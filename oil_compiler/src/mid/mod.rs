/*
Lowering to MIR

The MIR (Mid-level Intermediate Representation) is a normalised, 
flat version of the AST — easier to optimise and easier to generate code from. 
The key transformations here: Classify the rule — decide which backend will execute it. 
This is what determines the codegen path:
 */

#[derive(Debug, Clone)]
pub struct MirProgram {
    pub rules: Vec<MirRule>,
}


#[derive(Debug, Clone)]
pub struct MirRule {
    pub id:          RuleId,
    pub name:        String,
    pub class:       RuleClass,
    pub sources:     Vec<SourceRef>,
    pub predicates:  Vec<MirPredicate>,   // flat list, ordered by cost
    pub joins:       Vec<MirJoin>,
    pub window:      Option<Duration>,
    pub require:     Vec<MirRequire>,
    pub lets:        Vec<MirLet>,
    pub score_fn:    MirScoreFn,
    pub emit_facts:  Vec<MirEmit>,
    pub respond:     MirRespondPlan,
}


/// Rule execution class — determines codegen target
#[derive(Debug, Clone, PartialEq)]
pub enum RuleClass {
    HotPath,   // single-event: compiled to EPL .so
    Temporal,  // sequential/correlate: Tokio stream operator
    Graph,     // structural: Memgraph Cypher trigger
    Policy,    // enforce: OPA Rego module
}


/// A single filter predicate with its estimated evaluation cost
#[derive(Debug, Clone)]
pub struct MirPredicate {
    pub expr:     MirExpr,
    pub cost:     PredicateCost,  // used for reordering by optimizer
    pub nullable: bool,
}


#[derive(Debug, Clone)]
pub enum PredicateCost {
    Constant,         // integer compare, boolean: ~0.5ns
    FieldLookup,      // BPF map lookup: ~5ns
    StringOp,         // string comparison/prefix: ~20ns
    SetLookup,        // hash set membership: ~5ns
    GraphLookup,      // 1-hop graph query: ~10ns
    ExternalCall,     // threat intel feed lookup: ~100ns
    MlInference,      // unusual_for / rare: ~500ns (batched)
}


/// Join condition between correlated streams
#[derive(Debug, Clone)]
pub struct MirJoin {
    pub left_stream:  usize,
    pub right_stream: usize,
    pub key_expr:     MirExpr,
}


/// Score function — evaluates to i32 in [0, 100]
#[derive(Debug, Clone)]
pub struct MirScoreFn {
    pub base:      i32,
    pub modifiers: Vec<MirScoreMod>,
}


#[derive(Debug, Clone)]
pub struct MirScoreMod {
    pub delta:     i32,
    pub condition: Option<MirExpr>,
}


/// Planned response — ordered action tree
#[derive(Debug, Clone)]
pub struct MirRespondPlan {
    pub branches: Vec<MirBranch>,
}


#[derive(Debug, Clone)]
pub struct MirBranch {
    pub condition: Option<MirExpr>,
    pub actions:   Vec<MirAction>,
}



pub fn classify(rule: &TypedRuleDecl) -> RuleClass {
    match &rule.body {
        RuleBody::Match(m) if m.steps.len() == 1 => {
            // Single event match — check if it needs graph or not
            if needs_graph_lookup(&rule.where_) {
                RuleClass::Temporal  // needs sliding window
            } else {
                RuleClass::HotPath   // pure EPL .so
            }
        }
        RuleBody::Match(_) | RuleBody::Correlate(_) | RuleBody::Around(_) => {
            RuleClass::Temporal
        }
        RuleBody::Graph(_) => RuleClass::Graph,
    }
}


/*
Flatten predicates — the where clause is a tree of And/Or/comparisons. 
For HotPath rules, you want a flat list sorted by cost, cheapest first
(integer compare before string compare before graph lookup):
 */
fn extract_predicates(expr: &TypedExpr) -> Vec<MirPredicate> {
    match expr {
        TypedExpr::And(lhs, rhs) => {
            // AND is conjunctive — both must be true — flatten into list
            let mut preds = extract_predicates(lhs);
            preds.extend(extract_predicates(rhs));
            preds
        }
        other => vec![MirPredicate {
            expr: lower_expr(other),
            cost: estimate_cost(other),
        }]
    }
}