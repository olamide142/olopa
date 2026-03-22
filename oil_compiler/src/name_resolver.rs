/*

This stage walks the AST and makes sure every identifier refers to something that was declared. 
You build a symbol table — a hashmap from name to declaration.
*/ 

pub struct NameResolver {
    // Things declared at the top level
    sets:       HashMap<String, SetDecl>,
    predicates: HashMap<String, PredicateDecl>,
    facts:      HashMap<String, FactDecl>,
}

impl NameResolver {
    pub fn resolve(&mut self, program: &mut Program) -> Result<(), Vec<NameError>> {
        // First pass: collect all top-level declarations
        for set in &program.sets       { self.sets.insert(set.name.clone(), set.clone()); }
        for pred in &program.predicates { self.predicates.insert(pred.name.clone(), pred.clone()); }
        
        // Second pass: walk rules, resolve all identifier references
        for rule in &mut program.rules {
            self.resolve_rule(rule)?;
        }
        Ok(())
    }
    
    fn resolve_rule(&self, rule: &mut RuleDecl) -> Result<(), NameError> {
        // Walk the where_ expression, check every Ident and Path
        if let Some(expr) = &rule.where_ {
            self.resolve_expr(expr, &rule.bound_aliases)?;
        }
        Ok(())
    }
    
    fn resolve_expr(&self, expr: &Expr, bound: &HashSet<String>) -> Result<(), NameError> {
        match expr {
            Expr::Ident(name) => {
                // Is this a set name, fact name, or bound alias?
                if !bound.contains(name) 
                   && !self.sets.contains_key(name) 
                   && !self.facts.contains_key(name) {
                    return Err(NameError::Unknown(name.clone()));
                }
            }
            Expr::And(lhs, rhs) => {
                self.resolve_expr(lhs, bound)?;
                self.resolve_expr(rhs, bound)?;
            }
            // ... recurse through all expression variants
            _ => {}
        }
        Ok(())
    }
}