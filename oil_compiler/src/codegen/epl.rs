// Generates a Rust source file that compiles to a .so with a well-known symbol.
// The RuleEngine dlopen()s the .so and calls the exported function per event.


pub struct EplCodegen;


impl EplCodegen {
    pub fn generate(&self, rule: &MirRule) -> Result<String, CodegenError> {
        let mut src = String::new();


        // File header + imports
        src.push_str(RULE_HEADER);


        // Pre-computed integer sets (from SetInlining pass)
        for set in &rule.precomputed_sets {
            src.push_str(&self.emit_static_set(set));
        }


        // Main exported function — well-known ABI
        src.push_str(&format!(
            "#[no_mangle]\npub extern \"C\" fn rule_{}(\n",
            sanitize_name(&rule.name)
        ));
        src.push_str("    event: &OlopaEvent,\n");
        src.push_str("    graph: &CsrGraph,\n");
        src.push_str("    ctx:   &RuleContext,\n");
        src.push_str(") -> Option<Alert> {\n");


        // Emit predicates in cost order (cheapest first)
        for pred in &rule.predicates {
            src.push_str(&format!(
                "    if !({}) {{ return None; }}\n",
                self.emit_expr(&pred.expr)
            ));
        }


        // Emit score computation
        src.push_str(&self.emit_score_fn(&rule.score_fn));


        // Emit alert construction
        src.push_str(&self.emit_alert_builder(rule));


        src.push_str("}\n");
        Ok(src)
    }


    fn emit_expr(&self, expr: &MirExpr) -> String {
        match expr {
            MirExpr::Cmp { op: CmpOp::Eq, lhs, rhs } =>
                format!("({}) == ({})", self.emit_expr(lhs), self.emit_expr(rhs)),
            MirExpr::In { lhs, rhs: MirExpr::IntSet(ids) } =>
                format!("CONST_SET_{}.contains(&({}))", set_id, self.emit_expr(lhs)),
            MirExpr::Path(segments) =>
                format!("event.{}", segments.join(".")),
            MirExpr::IntLit(n) => n.to_string(),
            MirExpr::StrLit(s) => format!("ctx.intern({:?})", s),
            _ => unimplemented!("emit_expr: {:?}", expr),
        }
    }
}


// Generated output example for a simple rule:
// ─────────────────────────────────────────────────────────────────────────
// #[no_mangle]
// pub extern "C" fn rule_webshell_basic(
//     event: &OlopaEvent, graph: &CsrGraph, ctx: &RuleContext
// ) -> Option<Alert> {
//     // Predicate 0: COST=Constant — check event type first
//     if event.event_type != EventType::Exec { return None; }
//     // Predicate 1: COST=SetLookup — comm_id in compiled hash set
//     if !SHELL_IDS.contains(&event.comm_id) { return None; }
//     // Predicate 2: COST=GraphLookup — parent node lookup
//     let parent = graph.node_props(event.ppid_vertex)?;
//     if !WEBSERVER_IDS.contains(&parent.comm_id) { return None; }
//     // Score
//     let mut score: i32 = 70;
//     if event.uid == 0 { score += 15; }
//     Some(Alert { rule_id: RULE_ID, severity: severity_from_score(score), ... })
// }
