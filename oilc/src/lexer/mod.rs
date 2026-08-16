//! Pest-backed lexical compatibility layer.
//!
//! The AST parser historically consumes `Token` values. Pest now owns source
//! recognition and token boundaries, while this module preserves that stable
//! contract for semantic parsing and downstream tests.

use std::fmt;
use std::ops::Range;

mod pest_lexer;

pub mod enums;
pub use enums::{Keyword, TimeUnit, TokenKind};

/// Byte span in the original source string.
pub type Span = Range<usize>;

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

#[derive(Debug, Clone)]
pub struct LexError {
    pub message: String,
    pub span: Span,
    pub line: usize,
    pub col: usize,
}

impl LexError {
    pub(super) fn new(message: impl Into<String>, span: Span, line: usize, col: usize) -> Self {
        Self {
            message: message.into(),
            span,
            line,
            col,
        }
    }
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lex error at {}:{} (bytes {}..{}): {}",
            self.line, self.col, self.span.start, self.span.end, self.message
        )
    }
}

impl std::error::Error for LexError {}

/// Stateful facade retained for API compatibility with the old scanner.
pub struct Lexer<'src> {
    src: &'src str,
}

impl<'src> Lexer<'src> {
    pub fn new(src: &'src str) -> Self {
        Self { src }
    }

    /// Parse the complete source through the Pest grammar and emit the legacy
    /// token representation consumed by the AST builder.
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        pest_lexer::tokenize(self.src)
    }
}

pub(super) fn keyword_from(text: &str) -> Option<Keyword> {
    let keyword = match text {
        "rule" => Keyword::Rule,
        "predicate" => Keyword::Predicate,
        "set" => Keyword::Set,
        "fact" => Keyword::Fact,
        "use" => Keyword::Use,
        "import" => Keyword::Import,
        "from" => Keyword::From,
        "source" => Keyword::Source,
        "match" => Keyword::Match,
        "correlate" => Keyword::Correlate,
        "graph" => Keyword::Graph,
        "around" => Keyword::Around,
        "where" => Keyword::Where,
        "within" => Keyword::Within,
        "let" => Keyword::Let,
        "score" => Keyword::Score,
        "emit" => Keyword::Emit,
        "respond" => Keyword::Respond,
        "verify" => Keyword::Verify,
        "require" => Keyword::Require,
        "with" => Keyword::With,
        "on" => Keyword::On,
        "by" => Keyword::By,
        "then" => Keyword::Then,
        "and" => Keyword::And,
        "or" => Keyword::Or,
        "not" => Keyword::Not,
        "in" => Keyword::In,
        "starts_with" => Keyword::StartsWith,
        "ends_with" => Keyword::EndsWith,
        "contains" => Keyword::Contains,
        "matches" => Keyword::Matches,
        "under" => Keyword::Under,
        "true" => Keyword::True,
        "false" => Keyword::False,
        "null" => Keyword::Null,
        "alert" => Keyword::Alert,
        "isolate" => Keyword::Isolate,
        "revoke" => Keyword::Revoke,
        "snapshot" => Keyword::Snapshot,
        "open_case" => Keyword::OpenCase,
        "challenge" => Keyword::Challenge,
        "block" => Keyword::Block,
        "quarantine" => Keyword::Quarantine,
        "require_mfa" => Keyword::RequireMfa,
        "notify" => Keyword::Notify,
        "throttle" => Keyword::Throttle,
        "expires" => Keyword::Expires,
        "critical" => Keyword::Critical,
        "high" => Keyword::High,
        "medium" => Keyword::Medium,
        "low" => Keyword::Low,
        "informational" => Keyword::Informational,
        "if" => Keyword::If,
        "else" => Keyword::Else,
        _ => return None,
    };
    Some(keyword)
}
