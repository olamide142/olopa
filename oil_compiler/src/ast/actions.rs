use super::expr::Expr;
use super::Spanned;

/// Score expression: base + optional conditional modifiers.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreExpr {
    pub base: Spanned<i32>,
    pub modifiers: Vec<ScoreModifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoreModifier {
    pub delta: i32,
    pub condition: Option<Spanned<Expr>>,
    pub multiply: bool,
}

/// Let binding inside a rule.
#[derive(Debug, Clone, PartialEq)]
pub struct LetBinding {
    pub name: Spanned<String>,
    pub value: Spanned<Expr>,
}

/// Respond block action tree.
#[derive(Debug, Clone, PartialEq)]
pub struct RespondBlock {
    pub arms: Vec<RespondArm>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RespondArm {
    pub condition: Option<Spanned<Expr>>,
    pub actions: Vec<Spanned<ActionStmt>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionStmt {
    Alert {
        severity: Severity,
        message: Option<String>,
    },
    Isolate {
        kind: IsolateKind,
        target: Spanned<String>,
    },
    Revoke {
        kind: RevokeKind,
        target: Spanned<String>,
    },
    Snapshot {
        targets: Vec<Spanned<String>>,
        kind: SnapshotKind,
    },
    OpenCase {
        title: String,
    },
    Challenge {
        kind: ChallengeKind,
    },
    RequireAuth {
        kind: AuthKind,
        for_: Spanned<String>,
    },
    Quarantine {
        path: Spanned<String>,
    },
    BlockEgress {
        target: Spanned<String>,
    },
    Notify {
        message: String,
    },
    Throttle {
        target: Spanned<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolateKind {
    Host,
    Network,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeKind {
    Session,
    Token,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Entities,
    AttackGraph,
    HostTimeline,
    ProcessTree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Mfa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Reauthentication,
    StepUp,
    Approval,
}
