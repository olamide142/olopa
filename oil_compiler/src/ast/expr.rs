// Unified expression type — used in where, let, score, respond conditions

#[derive(Debug, Clone)]
pub enum Expr {
    
    // Literals
    StrLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    DurationLit(Duration),
    Null,


    // Identifiers & Paths
    Path(Vec<String>),               // process.parent.name → vec!["process","parent","name"]
    Ident(String),                   // bare identifier: set name, fact name, alias


    // Arithmetic 
    BinOp { op: ArithOp, lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    UnaryMinus(Box<Spanned<Expr>>),


    // Boolean Logic
    And(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Or(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Not(Box<Spanned<Expr>>),


    // Comparison
    Cmp { op: CmpOp, lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },


    // Membership & String
    In    { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    NotIn { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    StartsWith { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    EndsWith   { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    Contains   { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    Matches    { lhs: Box<Spanned<Expr>>, pattern: String },
    Under      { path: Box<Spanned<Expr>>, prefix: Box<Spanned<Expr>> },
    Between    { val: Box<Spanned<Expr>>, lo: Box<Spanned<Expr>>, hi: Box<Spanned<Expr>> },


    // Statistical / ML operators
    UnusualFor { val: Box<Spanned<Expr>>, entity: String },  // ML baseline check
    Rare(Box<Spanned<Expr>>),                                // global rarity < 1%


    // Aggregations (valid in around/gather context)
    Count(Box<Spanned<Expr>>),
    Max(Box<Spanned<Expr>>),
    Min(Box<Spanned<Expr>>),
    Sum(Box<Spanned<Expr>>),
    Avg(Box<Spanned<Expr>>),
    Distinct(Box<Spanned<Expr>>),


    // Function Calls
    Call { name: String, args: Vec<Spanned<Expr>> },


    // List Literal
    List(Vec<Spanned<Expr>>),
}


#[derive(Debug, Clone, PartialEq)]
pub enum ArithOp { Add, Sub, Mul, Div }


#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp   { Eq, Ne, Lt, Gt, Le, Ge }
