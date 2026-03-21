// The lexer reads raw text and produces a flat list of tokens. 
// It knows nothing about grammar — it just says "this chunk of characters 
// is a keyword, this one is an integer, this one is an identifier."

/*
# The tricky part in OIL specifically is duration literals. After you lex a number like 15, you need to peek ahead — if the next characters are m, s, ms, h, d, the whole thing is one DurationLit token, not an integer followed by an identifier. Handle this inside lex_number.
What you produce: Vec<Token> — a flat list.
Test it by: writing OIL source strings and asserting on the token list. No grammar knowledge needed yet.
 */

pub struct Lexer<'src> {
    src:  &'src str,
    pos:  usize,
}

impl<'src> Lexer<'src> {
    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace_and_comments();
        
        let start = self.pos;
        let ch = self.current_char();
        
        match ch {
            '"'              => self.lex_string(start),
            '0'..='9'        => self.lex_number(start),   // might be a duration too
            'a'..='z' |  
            'A'..='Z' | '_' => self.lex_ident_or_keyword(start),
            '{'              => { self.advance(); Token::new(LBrace, start..self.pos) }
            // ... punctuation
            _ => panic!("unexpected char"),
        }
    }
    
    fn lex_ident_or_keyword(&mut self, start: usize) -> Token {
        while self.current_char().is_alphanumeric() || self.current_char() == '_' {
            self.advance();
        }
        let text = &self.src[start..self.pos];
        
        // After reading the word, check if it's a keyword
        let kind = match text {
            "rule"      => Kw(Keyword::Rule),
            "where"     => Kw(Keyword::Where),
            "match"     => Kw(Keyword::Match),
            "respond"   => Kw(Keyword::Respond),
            "within"    => Kw(Keyword::Within),
            // ... etc
            _           => Ident(text.to_string()),
        };
        Token::new(kind, start..self.pos)
    }
}