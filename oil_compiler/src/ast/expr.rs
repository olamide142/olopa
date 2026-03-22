use super::{OilDuration, Spanned};

/// Unified expression tree used across where/let/score/respond contexts.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // Literals
    StrLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    DurationLit(OilDuration),
    Null,

    // Identifiers and field paths
    Path(Vec<String>),
    Ident(String),

    // Arithmetic
    BinOp {
        op: ArithOp,
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    UnaryMinus(Box<Spanned<Expr>>),

    // Boolean logic
    And(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Or(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Not(Box<Spanned<Expr>>),

    // Comparison
    Cmp {
        op: CmpOp,
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },

    // Membership and string ops
    In {
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    NotIn {
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    StartsWith {
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    EndsWith {
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    Contains {
        lhs: Box<Spanned<Expr>>,
        rhs: Box<Spanned<Expr>>,
    },
    Matches {
        lhs: Box<Spanned<Expr>>,
        pattern: String,
    },
    Under {
        path: Box<Spanned<Expr>>,
        prefix: Box<Spanned<Expr>>,
    },
    Between {
        val: Box<Spanned<Expr>>,
        lo: Box<Spanned<Expr>>,
        hi: Box<Spanned<Expr>>,
    },

    // Statistical / ML operators
    UnusualFor {
        val: Box<Spanned<Expr>>,
        entity: String,
    },
    Rare(Box<Spanned<Expr>>),

    // Aggregations
    Count(Box<Spanned<Expr>>),
    Max(Box<Spanned<Expr>>),
    Min(Box<Spanned<Expr>>),
    Sum(Box<Spanned<Expr>>),
    Avg(Box<Spanned<Expr>>),
    Distinct(Box<Spanned<Expr>>),

    // Calls and lists
    Call {
        name: String,
        args: Vec<Spanned<Expr>>,
    },
    List(Vec<Spanned<Expr>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}
