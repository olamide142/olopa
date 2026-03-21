/*
Lowering to MIR

The MIR (Mid-level Intermediate Representation) is a normalised, 
flat version of the AST — easier to optimise and easier to generate code from. 
The key transformations here: Classify the rule — decide which backend will execute it. 
This is what determines the codegen path:
 */


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