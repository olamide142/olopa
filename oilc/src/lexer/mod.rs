use std::fmt;
use std::ops::Range;

pub mod enums;
pub use enums::{Keyword, TimeUnit, TokenKind};

// Byte-span in the original source string.
// We track byte offsets (not char indices) so slicing is O(1) and
// diagnostics can point exactly to the original source region.
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
    fn new(message: impl Into<String>, span: Span, line: usize, col: usize) -> Self {
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

// Stateful UTF-8 scanner.
// `pos` is a byte offset into `src`, while `line`/`col` are human-readable
// positions used in error reporting.
pub struct Lexer<'src> {
    src: &'src str,
    pos: usize,
    line: usize,
    col: usize,
}

impl<'src> Lexer<'src> {
    // Create a lexer at the beginning of the source buffer.
    pub fn new(src: &'src str) -> Self {
        Self {
            src,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    // Repeatedly scan one token at a time until we emit EOF.
    // This is the convenience API used by main().
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();

        loop {
            let token = self.next_token()?;
            let is_eof = matches!(token.kind, TokenKind::Eof);
            out.push(token);
            if is_eof {
                break;
            }
        }

        Ok(out)
    }

    // Scan the next token from the current cursor.
    // Order matters: we skip trivia first, then choose token kind by leading char.
    pub fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_whitespace_and_comments()?;

        let start = self.pos;
        let Some(ch) = self.current_char() else {
            return Ok(Token::new(TokenKind::Eof, start..start));
        };

        let tok = match ch {
            '\n' => {
                self.advance_char();
                Token::new(TokenKind::Newline, start..self.pos)
            }
            '"' => self.lex_string(start)?,
            '0'..='9' => self.lex_number(start)?,
            // Identifiers and keywords start with alpha/underscore.
            'a'..='z' | 'A'..='Z' | '_' => self.lex_ident_or_keyword(start),
            '/' => {
                self.advance_char();
                Token::new(TokenKind::Slash, start..self.pos)
            }
            '{' => {
                self.advance_char();
                Token::new(TokenKind::LBrace, start..self.pos)
            }
            '}' => {
                self.advance_char();
                Token::new(TokenKind::RBrace, start..self.pos)
            }
            '(' => {
                self.advance_char();
                Token::new(TokenKind::LParen, start..self.pos)
            }
            ')' => {
                self.advance_char();
                Token::new(TokenKind::RParen, start..self.pos)
            }
            '[' => {
                self.advance_char();
                Token::new(TokenKind::LBracket, start..self.pos)
            }
            ']' => {
                self.advance_char();
                Token::new(TokenKind::RBracket, start..self.pos)
            }
            ',' => {
                self.advance_char();
                Token::new(TokenKind::Comma, start..self.pos)
            }
            ':' => {
                self.advance_char();
                Token::new(TokenKind::Colon, start..self.pos)
            }
            ';' => {
                self.advance_char();
                Token::new(TokenKind::Semicolon, start..self.pos)
            }
            '@' => {
                self.advance_char();
                Token::new(TokenKind::At, start..self.pos)
            }
            '+' => {
                self.advance_char();
                Token::new(TokenKind::Plus, start..self.pos)
            }
            '*' => {
                self.advance_char();
                Token::new(TokenKind::Star, start..self.pos)
            }
            '-' => {
                self.advance_char();
                if self.current_char() == Some('>') {
                    self.advance_char();
                    Token::new(TokenKind::Arrow, start..self.pos)
                } else {
                    Token::new(TokenKind::Minus, start..self.pos)
                }
            }
            '.' => {
                self.advance_char();
                if self.current_char() == Some('.') {
                    self.advance_char();
                    Token::new(TokenKind::Range, start..self.pos)
                } else {
                    Token::new(TokenKind::Dot, start..self.pos)
                }
            }
            '=' => {
                self.advance_char();
                if self.current_char() == Some('=') {
                    self.advance_char();
                    Token::new(TokenKind::Eq, start..self.pos)
                } else if self.current_char() == Some('>') {
                    self.advance_char();
                    Token::new(TokenKind::FatArrow, start..self.pos)
                } else {
                    Token::new(TokenKind::Assign, start..self.pos)
                }
            }
            '!' => {
                self.advance_char();
                if self.current_char() == Some('=') {
                    self.advance_char();
                    Token::new(TokenKind::Ne, start..self.pos)
                } else {
                    return Err(self.lex_error("unexpected '!': expected '!='", start));
                }
            }
            '<' => {
                self.advance_char();
                if self.current_char() == Some('=') {
                    self.advance_char();
                    Token::new(TokenKind::Le, start..self.pos)
                } else {
                    Token::new(TokenKind::Lt, start..self.pos)
                }
            }
            '>' => {
                self.advance_char();
                if self.current_char() == Some('=') {
                    self.advance_char();
                    Token::new(TokenKind::Ge, start..self.pos)
                } else {
                    Token::new(TokenKind::Gt, start..self.pos)
                }
            }
            _ => {
                return Err(self.lex_error(
                    format!("unexpected character '{}': no matching token", ch),
                    start,
                ));
            }
        };

        Ok(tok)
    }

    // Skip non-semantic trivia:
    // - spaces/tabs/carriage returns
    // - line comments (# ... and // ...)
    // - block comments (/* ... */)
    // Newlines are intentionally NOT skipped because parser may care.
    fn skip_whitespace_and_comments(&mut self) -> Result<(), LexError> {
        loop {
            match self.current_char() {
                Some(' ' | '\t' | '\r') => {
                    self.advance_char();
                }
                Some('#') => {
                    self.skip_line_comment();
                }
                Some('/') if self.peek_char() == Some('/') => {
                    self.advance_char();
                    self.advance_char();
                    self.skip_line_comment();
                }
                Some('/') if self.peek_char() == Some('*') => {
                    let start = self.pos;
                    self.advance_char();
                    self.advance_char();
                    self.skip_block_comment(start)?;
                }
                _ => break,
            }
        }
        Ok(())
    }

    // Consume until end-of-line or EOF.
    fn skip_line_comment(&mut self) {
        while let Some(ch) = self.current_char() {
            if ch == '\n' {
                break;
            }
            self.advance_char();
        }
    }

    // Consume until closing "*/".
    // If EOF is reached first, report a precise unterminated-comment error.
    fn skip_block_comment(&mut self, start: usize) -> Result<(), LexError> {
        loop {
            match self.current_char() {
                Some('*') if self.peek_char() == Some('/') => {
                    self.advance_char();
                    self.advance_char();
                    return Ok(());
                }
                Some(_) => {
                    self.advance_char();
                }
                None => {
                    return Err(self.lex_error("unterminated block comment", start));
                }
            }
        }
    }

    // Lex a double-quoted string with common escape sequences.
    fn lex_string(&mut self, start: usize) -> Result<Token, LexError> {
        // Consume opening quote.
        self.advance_char();

        let mut out = String::new();
        while let Some(ch) = self.current_char() {
            if ch == '"' {
                self.advance_char();
                return Ok(Token::new(TokenKind::StrLit(out), start..self.pos));
            }

            if ch == '\\' {
                self.advance_char();
                let Some(esc) = self.current_char() else {
                    return Err(self.lex_error("unterminated escape sequence", start));
                };
                // Keep escape handling small and predictable for now.
                let decoded = match esc {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    '"' => '"',
                    other => other,
                };
                out.push(decoded);
                self.advance_char();
                continue;
            }

            out.push(ch);
            self.advance_char();
        }

        Err(self.lex_error("unterminated string literal", start))
    }

    // Lex:
    // - integer: 123
    // - float: 123.45
    // - duration: 15m, 300s, 24h, ...
    //
    // Duration is only recognized from integer prefix + unit suffix.
    fn lex_number(&mut self, start: usize) -> Result<Token, LexError> {
        self.consume_digits();

        let mut is_float = false;
        if self.current_char() == Some('.') {
            // Only treat '.' as float decimal point if a digit follows.
            // This avoids stealing ".." (range token).
            if matches!(self.peek_char(), Some('0'..='9')) {
                is_float = true;
                self.advance_char();
                self.consume_digits();
            }
        }

        let text = &self.src[start..self.pos];

        if !is_float {
            if let Some((unit, unit_len)) = self.read_duration_unit() {
                let value: u64 = text
                    .parse()
                    .map_err(|_| self.lex_error("invalid duration literal", start))?;
                for _ in 0..unit_len {
                    self.advance_char();
                }
                return Ok(Token::new(
                    TokenKind::DurationLit { value, unit },
                    start..self.pos,
                ));
            }

            let value: i64 = text
                .parse()
                .map_err(|_| self.lex_error("invalid integer literal", start))?;
            return Ok(Token::new(TokenKind::IntLit(value), start..self.pos));
        }

        let value: f64 = text
            .parse()
            .map_err(|_| self.lex_error("invalid float literal", start))?;
        Ok(Token::new(TokenKind::FloatLit(value), start..self.pos))
    }

    // Consume one or more ASCII digits.
    fn consume_digits(&mut self) {
        while matches!(self.current_char(), Some('0'..='9')) {
            self.advance_char();
        }
    }

    // Check whether the immediate suffix at current cursor is a valid duration unit.
    // Returns unit + byte length of the suffix to consume.
    fn read_duration_unit(&self) -> Option<(TimeUnit, usize)> {
        let tail = &self.src[self.pos..];

        if tail.starts_with("ns") {
            return Some((TimeUnit::Ns, 2));
        }
        if tail.starts_with("us") {
            return Some((TimeUnit::Us, 2));
        }
        if tail.starts_with("ms") {
            return Some((TimeUnit::Ms, 2));
        }

        match tail.as_bytes().first().copied().map(char::from) {
            Some('s') => Some((TimeUnit::S, 1)),
            Some('m') => Some((TimeUnit::M, 1)),
            Some('h') => Some((TimeUnit::H, 1)),
            Some('d') => Some((TimeUnit::D, 1)),
            _ => None,
        }
    }

    // Read an identifier-like sequence and classify it as keyword or identifier.
    fn lex_ident_or_keyword(&mut self, start: usize) -> Token {
        while matches!(
            self.current_char(),
            Some('a'..='z' | 'A'..='Z' | '0'..='9' | '_')
        ) {
            self.advance_char();
        }

        let text = &self.src[start..self.pos];
        let kind = keyword_from(text)
            .map(TokenKind::Kw)
            .unwrap_or_else(|| TokenKind::Ident(text.to_string()));

        Token::new(kind, start..self.pos)
    }

    // Current UTF-8 char at byte offset `pos`.
    fn current_char(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    // One-char lookahead.
    fn peek_char(&self) -> Option<char> {
        let mut it = self.src[self.pos..].chars();
        it.next()?;
        it.next()
    }

    // Move cursor forward by one UTF-8 codepoint and update line/column bookkeeping.
    fn advance_char(&mut self) -> Option<char> {
        let ch = self.current_char()?;
        self.pos += ch.len_utf8();

        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }

        Some(ch)
    }

    // Build a lexer error with a non-empty span for better diagnostics.
    fn lex_error(&self, message: impl Into<String>, start: usize) -> LexError {
        LexError::new(message, start..self.pos.max(start + 1), self.line, self.col)
    }
}

// Reserved-word table.
// If there is no keyword match, caller treats the text as a plain identifier.
fn keyword_from(text: &str) -> Option<Keyword> {
    let kw = match text {
        "rule" => Keyword::Rule,
        "policy" => Keyword::Policy,
        "predicate" => Keyword::Predicate,
        "template" => Keyword::Template,
        "set" => Keyword::Set,
        "fact" => Keyword::Fact,
        "use" => Keyword::Use,
        "import" => Keyword::Import,
        "from" => Keyword::From,
        "source" => Keyword::Source,
        "match" => Keyword::Match,
        "correlate" => Keyword::Correlate,
        "where" => Keyword::Where,
        "within" => Keyword::Within,
        "around" => Keyword::Around,
        "over" => Keyword::Over,
        "let" => Keyword::Let,
        "score" => Keyword::Score,
        "emit" => Keyword::Emit,
        "respond" => Keyword::Respond,
        "enforce" => Keyword::Enforce,
        "verify" => Keyword::Verify,
        "require" => Keyword::Require,
        "gather" => Keyword::Gather,
        "with" => Keyword::With,
        "on" => Keyword::On,
        "by" => Keyword::By,
        "then" => Keyword::Then,
        "at_least" => Keyword::AtLeast,
        "any" => Keyword::Any,
        "all" => Keyword::All,
        "window" => Keyword::Window,
        "and" => Keyword::And,
        "or" => Keyword::Or,
        "not" => Keyword::Not,
        "in" => Keyword::In,
        "not_in" => Keyword::NotIn,
        "starts_with" => Keyword::StartsWith,
        "ends_with" => Keyword::EndsWith,
        "contains" => Keyword::Contains,
        "matches" => Keyword::Matches,
        "under" => Keyword::Under,
        "between" => Keyword::Between,
        "unusual_for" => Keyword::UnusualFor,
        "rare" => Keyword::Rare,
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
        "annotate" => Keyword::Annotate,
        "redirect" => Keyword::Redirect,
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

    Some(kw)
}
