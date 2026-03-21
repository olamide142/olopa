/*
    Code Generation: Now you walk the MIR and produce output. For OIL's three targets:
    
    EPL .so (HotPath rules): generate a Rust source file, compile it with rustc, produce a .so. 
    The generated Rust is straightforward — it's just the predicate chain turned into if !condition { return None; } guards:

*/


fn emit_epl(rule: &MirRule) -> String {
    let mut out = String::new();
    
    // Header
    out += r#"
use olopa_agent::prelude::*;
static RULE_ID: RuleId = /* ... */;
"#;
    
    // Precomputed integer sets from set inlining
    for set in &rule.precomputed_sets {
        out += &format!(
            "static {}: phf::Set<u32> = phf::phf_set!{{{}}};",
            set.name,
            set.ids.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
        );
    }
    
    // The exported function
    out += &format!(
        "#[no_mangle]\npub extern \"C\" fn rule_{}(event: &OlopaEvent, graph: &CsrGraph, ctx: &RuleContext) -> Option<Alert> {{",
        sanitize_name(&rule.name)
    );
    
    // Guards in cost order
    for pred in &rule.predicates {
        out += &format!("    if !({}) {{ return None; }}\n", emit_expr(&pred.expr));
    }
    
    // Score
    out += &format!("    let mut score: i32 = {};\n", rule.score_fn.base);
    for modifier in &rule.score_fn.modifiers {
        if let Some(cond) = &modifier.condition {
            out += &format!("    if {} {{ score += {}; }}\n", emit_expr(cond), modifier.delta);
        }
    }
    
    // Alert
    out += "    Some(Alert { rule_id: RULE_ID, severity: severity_from_score(score), .. })";
    out += "}";
    
    out
}



/*
    Cypher triggers (Graph rules): emit Memgraph trigger DDL. 
    The graph pattern becomes a MATCH clause, the where clause becomes 
    Cypher WHERE, the respond block becomes CALL olopa.emit_alert(...):
*/
fn emit_cypher_trigger(rule: &MirRule) -> String {
    let pattern = emit_graph_pattern(&rule.graph.patterns);
    let where_  = emit_cypher_where(&rule.predicates);
    
    format!(r#"
CREATE TRIGGER {name}_trigger
ON CREATE TO {trigger_edge}
AFTER COMMIT
EXECUTE
  MATCH {pattern}
  WHERE {where_}
  CALL olopa.emit_alert({{rule: '{name}', severity: '{severity}'}})
  YIELD done;
"#, name=rule.name, trigger_edge=rule.graph.trigger_edge, 
        pattern=pattern, where_=where_, severity=rule.meta.severity)
}