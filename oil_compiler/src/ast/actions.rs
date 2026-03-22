// Score expression — base value + conditional modifiers
#[derive(Debug, Clone)]
pub struct ScoreExpr {
    pub base:      Spanned<i32>,
    pub modifiers: Vec<ScoreModifier>,
}


#[derive(Debug, Clone)]
pub struct ScoreModifier {
    pub delta:     i32,      // signed: + or -
    pub condition: Option<Spanned<Expr>>,  // None = always applies
    pub multiply:  bool,     // if true, delta is a multiplier (e.g. * 0.5)
}


/// Let bindings — derived variables
#[derive(Debug, Clone)]
pub struct LetBinding {
    pub name:  Spanned<String>,
    pub value: Spanned<Expr>
}


/// Respond block — conditional action tree
#[derive(Debug, Clone)]
pub struct RespondBlock {
    pub arms: Vec<RespondArm>,
}


#[derive(Debug, Clone)]
pub struct RespondArm {
    pub condition: Option<Spanned<Expr>>,  // None = else / unconditional
    pub actions:   Vec<Spanned<ActionStmt>>,
}


/// Individual response action
#[derive(Debug, Clone)]
pub enum ActionStmt {
    Alert    { severity: Severity, message: Option<String> },
    Isolate  { kind: IsolateKind, target: Spanned<String> },
    Revoke   { kind: RevokeKind,  target: Spanned<String> },
    Snapshot { targets: Vec<Spanned<String>>, kind: SnapshotKind },
    OpenCase { title: String },
    Challenge { kind: ChallengeKind },
    RequireAuth { kind: AuthKind, for_: Spanned<String> },
    Quarantine { path: Spanned<String> },
    BlockEgress { target: Spanned<String> },
    Notify   { message: String },
    Throttle { target: Spanned<String> },
}


#[derive(Debug, Clone, PartialEq)]
pub enum Severity { Critical, High, Medium, Low, Informational }


#[derive(Debug, Clone)]
pub enum IsolateKind  { Host, Network, Process }


#[derive(Debug, Clone)]
pub enum RevokeKind   { Session, Token, Credential }


#[derive(Debug, Clone)]
pub enum SnapshotKind { Entities, AttackGraph, HostTimeline, ProcessTree }


#[derive(Debug, Clone)]
pub enum ChallengeKind { Mfa }


#[derive(Debug, Clone)]
pub enum AuthKind { Reauthentication, StepUp, Approval }


