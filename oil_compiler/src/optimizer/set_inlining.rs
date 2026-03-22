// Inlines named set references into hash sets computed at compile time.
// p.name in shell_names → p.comm_id in {0x004A, 0x008B, 0x00C1} (integer IDs)


pub struct SetInlining {
    global_sets: HashMap<String, Vec<MirExpr>>,
    id_registry: IntIdRegistry,
}


impl SetInlining {
    pub fn run(&self, mut mir: MirProgram) -> Result<MirProgram, CompileError> {
        for rule in &mut mir.rules {
            for pred in &mut rule.predicates {
                self.inline_sets_in_expr(&mut pred.expr);
            }
        }
        Ok(mir)
    }


    fn inline_sets_in_expr(&self, expr: &mut MirExpr) {
        if let MirExpr::In { rhs, .. } = expr {
            if let MirExpr::Ident(name) = rhs.as_ref() {
                if let Some(values) = self.global_sets.get(name) {
                    // Replace named set with computed integer hash set
                    let ids: Vec<u32> = values.iter()
                        .filter_map(|v| self.id_registry.lookup(v))
                        .collect();
                    *rhs = Box::new(MirExpr::IntSet(ids));
                }
            }
        }
    }
}

