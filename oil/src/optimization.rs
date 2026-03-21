/*

    Optimization: 
        Three passes that matter for OIL specifically:

    Predicate reordering — 
        sort predicates by cost ascending. event.event_type == Exec 
        (integer compare, ~0.5ns) goes before p.parent.name in web_servers 
        (hash lookup, ~5ns) which goes before unusual_for(user, country) (ML call, ~500ns). 
        This is the biggest performance win and it's trivial to implement once you have the flat predicate list:

        rustrule.predicates.sort_by_key(|p| p.cost as u8);


    Set inlining — 
        replace p.name in shells with p.comm_id in {0x004A, 0x008B, ...} (pre-interned integer IDs). 
        This converts string membership tests (slow) into integer set lookups (fast). 
        Do this after name resolution when you have the string→integer registry:

        rustfn inline_sets(expr: &mut MirExpr, registry: &IdRegistry) {
            if let MirExpr::In { rhs, .. } = expr {
                if let MirExpr::Ident(set_name) = rhs.as_ref() {
                    if let Some(values) = global_sets.get(set_name) {
                        let ids: Vec<u32> = values.iter()
                            .map(|v| registry.get_or_assign(v))
                            .collect();
                        *rhs = Box::new(MirExpr::IntSet(ids));
                    }
                }
            }
        }

    
    Constant folding — 
        evaluate 50 + 10 + 20 at compile time so generated code has score = 80, not three additions.

*/

