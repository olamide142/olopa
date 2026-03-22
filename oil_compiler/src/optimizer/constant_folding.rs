// Evaluates constant sub-expressions at compile time.
// score 50 + 10 + 20 if x → score 60 + 20 if x


pub struct ConstantFolding;


impl ConstantFolding {
    fn fold_expr(&self, expr: MirExpr) -> MirExpr {
        match expr {
            MirExpr::BinOp { op: ArithOp::Add, lhs, rhs }
                if is_constant(&lhs) && is_constant(&rhs) => {
                MirExpr::IntLit(eval_int(&lhs) + eval_int(&rhs))
            }
            other => other,
        }
    }
}
