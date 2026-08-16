use pest::error::{InputLocation, LineColLocation};
use pest::Parser as _;
use pest_derive::Parser;

use super::{keyword_from, LexError, TimeUnit, Token, TokenKind};

#[derive(Parser)]
#[grammar = "parser/oil.pest"]
struct OilPestParser;

pub(super) fn tokenize(source: &str) -> Result<Vec<Token>, LexError> {
    let mut parsed = OilPestParser::parse(Rule::program, source)
        .map_err(|error| convert_error(source, error))?;
    let program = parsed.next().expect("Pest program pair");
    let mut tokens = Vec::new();
    for pair in program.into_inner() {
        let span = pair.as_span().start()..pair.as_span().end();
        let text = pair.as_str();
        let kind = match pair.as_rule() {
            Rule::newline => TokenKind::Newline,
            Rule::string => TokenKind::StrLit(decode_string(text)),
            Rule::duration => parse_duration(source, text, span.clone())?,
            Rule::float => TokenKind::FloatLit(
                text.parse()
                    .map_err(|_| lex_error_at(source, span.clone(), "invalid float literal"))?,
            ),
            Rule::integer => TokenKind::IntLit(
                text.parse()
                    .map_err(|_| lex_error_at(source, span.clone(), "invalid integer literal"))?,
            ),
            Rule::identifier => keyword_from(text)
                .map(TokenKind::Kw)
                .unwrap_or_else(|| TokenKind::Ident(text.to_string())),
            Rule::arrow => TokenKind::Arrow,
            Rule::fat_arrow => TokenKind::FatArrow,
            Rule::range => TokenKind::Range,
            Rule::assign => TokenKind::Assign,
            Rule::eq => TokenKind::Eq,
            Rule::ne => TokenKind::Ne,
            Rule::lt => TokenKind::Lt,
            Rule::gt => TokenKind::Gt,
            Rule::le => TokenKind::Le,
            Rule::ge => TokenKind::Ge,
            Rule::plus => TokenKind::Plus,
            Rule::minus => TokenKind::Minus,
            Rule::star => TokenKind::Star,
            Rule::slash => TokenKind::Slash,
            Rule::comma => TokenKind::Comma,
            Rule::colon => TokenKind::Colon,
            Rule::semicolon => TokenKind::Semicolon,
            Rule::at => TokenKind::At,
            Rule::dot => TokenKind::Dot,
            Rule::lbrace => TokenKind::LBrace,
            Rule::rbrace => TokenKind::RBrace,
            Rule::lparen => TokenKind::LParen,
            Rule::rparen => TokenKind::RParen,
            Rule::lbracket => TokenKind::LBracket,
            Rule::rbracket => TokenKind::RBracket,
            Rule::program | Rule::EOI => continue,
            unexpected => {
                return Err(lex_error_at(
                    source,
                    span,
                    format!("unexpected Pest token {unexpected:?}"),
                ));
            }
        };
        tokens.push(Token::new(kind, span));
    }
    tokens.push(Token::new(TokenKind::Eof, source.len()..source.len()));
    Ok(tokens)
}

fn decode_string(raw: &str) -> String {
    let inner = &raw[1..raw.len() - 1];
    let mut chars = inner.chars();
    let mut decoded = String::with_capacity(inner.len());
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            break;
        };
        decoded.push(match escaped {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            '"' => '"',
            other => other,
        });
    }
    decoded
}

fn parse_duration(
    source: &str,
    raw: &str,
    span: std::ops::Range<usize>,
) -> Result<TokenKind, LexError> {
    let (number, unit) = ["ns", "us", "ms", "s", "m", "h", "d"]
        .into_iter()
        .find_map(|unit| raw.strip_suffix(unit).map(|number| (number, unit)))
        .expect("duration grammar guarantees unit suffix");
    let value = number
        .parse::<u64>()
        .map_err(|_| lex_error_at(source, span.clone(), "invalid duration literal"))?;
    let unit = match unit {
        "ns" => TimeUnit::Ns,
        "us" => TimeUnit::Us,
        "ms" => TimeUnit::Ms,
        "s" => TimeUnit::S,
        "m" => TimeUnit::M,
        "h" => TimeUnit::H,
        "d" => TimeUnit::D,
        _ => unreachable!(),
    };
    Ok(TokenKind::DurationLit { value, unit })
}

fn convert_error(source: &str, error: pest::error::Error<Rule>) -> LexError {
    let (start, end) = match error.location {
        InputLocation::Pos(position) => (position, next_boundary(source, position)),
        InputLocation::Span((start, end)) => (start, end.max(next_boundary(source, start))),
    };
    let (line, col) = match error.line_col {
        LineColLocation::Pos(location) => location,
        LineColLocation::Span(start, _) => start,
    };
    LexError::new(error.to_string(), start..end, line, col)
}

fn lex_error_at(
    source: &str,
    span: std::ops::Range<usize>,
    message: impl Into<String>,
) -> LexError {
    let (line, col) = line_col(source, span.start);
    LexError::new(message, span, line, col)
}

fn next_boundary(source: &str, position: usize) -> usize {
    source
        .get(position..)
        .and_then(|tail| tail.chars().next())
        .map(|ch| position + ch.len_utf8())
        .unwrap_or(position)
}

fn line_col(source: &str, position: usize) -> (usize, usize) {
    let prefix = &source[..position.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let col = prefix
        .rsplit_once('\n')
        .map(|(_, tail)| tail.chars().count() + 1)
        .unwrap_or_else(|| prefix.chars().count() + 1);
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pest_tokenizes_comments_escapes_and_operators() {
        let tokens = tokenize("# comment\nwhere name == \"ba\\nsh\" and age >= 2h\n")
            .expect("Pest tokenization");
        assert!(matches!(tokens[0].kind, TokenKind::Newline));
        assert!(matches!(
            tokens[1].kind,
            TokenKind::Kw(super::super::Keyword::Where)
        ));
        assert!(tokens
            .iter()
            .any(|token| matches!(&token.kind, TokenKind::StrLit(value) if value == "ba\nsh")));
        assert!(tokens.iter().any(|token| matches!(
            token.kind,
            TokenKind::DurationLit {
                value: 2,
                unit: TimeUnit::H
            }
        )));
    }

    #[test]
    fn pest_rejects_unterminated_literals_and_comments() {
        assert!(tokenize("\"unterminated").is_err());
        assert!(tokenize("/* unterminated").is_err());
    }
}
