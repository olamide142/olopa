pub struct TypeChecker {
    schema: EntitySchema,  // knows that Process.uid: Int, Process.name: Str, etc.
}

impl TypeChecker {
    pub fn infer_type(&self, expr: &Expr, scope: &TypeScope) -> Result<OilType, TypeError> {
        match expr {
            Expr::IntLit(_)      => Ok(OilType::Int),
            Expr::StrLit(_)      => Ok(OilType::Str),
            Expr::FloatLit(_)    => Ok(OilType::Float),
            Expr::DurationLit(_) => Ok(OilType::Duration),
            
            Expr::Path(segments) => {
                // Walk the schema: process.uid → Int
                self.schema.resolve_path(segments)
            }
            
            Expr::Cmp { op, lhs, rhs } => {
                let l = self.infer_type(lhs, scope)?;
                let r = self.infer_type(rhs, scope)?;
                if !types_compatible(&l, &r) {
                    return Err(TypeError::Mismatch { expected: l, got: r, span: expr.span() });
                }
                Ok(OilType::Bool)
            }
            
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                self.expect_bool(lhs, scope)?;
                self.expect_bool(rhs, scope)?;
                Ok(OilType::Bool)
            }
            
            Expr::In { lhs, rhs } => {
                let elem_type = self.infer_type(lhs, scope)?;
                let set_type  = self.infer_type(rhs, scope)?;
                match set_type {
                    OilType::Set(inner) if *inner == elem_type => Ok(OilType::Bool),
                    _ => Err(TypeError::NotASet { .. })
                }
            }
            // ...
        }
    }
}


// The entity schema is just a big registry of known fields
impl EntitySchema {
    fn resolve_path(&self, segments: &[String]) -> Result<OilType, TypeError> {
        // "process.uid" → segments = ["process", "uid"]
        // "process.parent.name" → segments = ["process", "parent", "name"]
        let entity = self.entities.get(&segments[0])
            .ok_or(TypeError::UnknownEntity(segments[0].clone()))?;
        
        let mut current_type = OilType::Entity(entity.clone());
        for seg in &segments[1..] {
            current_type = match current_type {
                OilType::Entity(e) => {
                    e.field(seg).ok_or(TypeError::UnknownField {
                        entity: e.name.clone(),
                        field: seg.clone(),
                    })?
                }
                _ => return Err(TypeError::CannotDotInto(current_type)),
            };
        }
        Ok(current_type)
    }
}