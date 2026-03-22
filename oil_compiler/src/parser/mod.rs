/*
    The parser reads the token list and produces an Abstract Syntax Tree (AST) — a tree that reflects the grammatical structure of the program.
    The technique for OIL is recursive descent with Pratt parsing for expressions. These two techniques together handle essentially any grammar you'll encounter.
    Recursive descent for statements
    Each grammar rule becomes a function. The function peeks at the current token to decide what to do:


    Hand-written recursive descent parser with LALR(1) lookahead.
    Panic-free: all errors are collected, parsing continues for best-effort diagnostics.

*/


pub struct Parser {
    tokens:   Vec<Token>,
    pos:      usize,
    errors:   Vec<ParseError>,
}


impl Parser {

    fn parse_program(&mut self) -> Result<Program, Vec<ParseError>> {
        let mut program = Program::default;
        
        while !self.is_at_end() {
            match self.peek().kind {
                TokenKind::Kw(Keyword::Use)       => prog.imports.push(self.parse_import()),
                TokenKind::Kw(Keyword::Set)       => prog.sets.push(self.parse_set()),
                TokenKind::Kw(Keyword::Predicate) => prog.predicates.push(self.parse_predicate()),
                TokenKind::Kw(Keyword::Template)  => prog.templates.push(self.parse_template()),
                TokenKind::Kw(Keyword::Fact)      => prog.facts.push(self.parse_fact()),
                TokenKind::Kw(Keyword::Rule)      => prog.rules.push(self.parse_rule()),
                TokenKind::Kw(Keyword::Policy)    => prog.policies.push(self.parse_policy()),
                TokenKind::Kw(Keyword::Meta)      => self.parse_and_attach_meta(),
                _ => { self.emit_error("unexpected top-level token"); self.advance(); }
            }
        }
 
        if self.errors.is_empty() { Ok(prog) } else { Err(self.errors.clone()) }
    }


    fn parse_rule(&mut self) -> RuleDecl {
        self.expect(Kw(Keyword::Rule)); // consume "rule"
        let name = self.expect_string(); // consume the name string
        self.expect_lbrace(); // consume "{"

        let sources = if self.peek_keyword(Keyword::From) || self.peek_keyword(Keyword::Source)
            { self.parse_from_clause() } else { vec![] };
        
        // Parse clauses; each checks what's next
        let body = match self.peek().kind {
            TokenKind::Kw(Keyword::Match)     => RuleBody::Match(self.parse_match_block()),
            TokenKind::Kw(Keyword::Correlate) => RuleBody::Correlate(self.parse_correlate()),
            TokenKind::Kw(Keyword::Graph)     => RuleBody::Graph(self.parse_graph()),
            TokenKind::Kw(Keyword::Around)    => RuleBody::Around(self.parse_around()),
            _ => { self.emit_error("expected match/correlate/graph/around"); 
                   RuleBody::Match(MatchBlock { steps: vec![] }) }
        };

        let where_ = self.try_parse_where(); // optional
        let within = self.try_parse_within(); // optional
        let score = self.try_parse_score(); // optional
        let require = self.try_parse_require();
        let lets    = self.parse_let_bindings();
        let verify  = self.try_parse_verify();
        let emit    = self.parse_emit_stmts();
        let respond = self.parse_respond_block();

        self.expect_rbrace();
        
        
        RuleDecl { meta: None, name, sources, body: Spanned::new(body, self.current_span()),
                   where_, within, require, lets, score, verify, emit, respond }
    }

    /// Parse boolean expression with Pratt precedence climbing
    fn parse_expr(&mut self) -> Spanned<Expr> {
        self.parse_or_expr()    // lowest precedence
    }


    fn parse_or_expr(&mut self) -> Spanned<Expr> {
        let mut lhs = self.parse_and_expr();
        while self.peek_keyword(Keyword::Or) {
            self.advance();
            let rhs = self.parse_and_expr();
            let span = lhs.span.start..rhs.span.end;
            lhs = Spanned::new(Expr::Or(Box::new(lhs), Box::new(rhs)), span);
        }
        lhs
    }


    fn parse_and_expr(&mut self) -> Spanned<Expr> {
        let mut lhs = self.parse_unary();
        while self.peek_keyword(Keyword::And) {
            self.advance();
            let rhs = self.parse_unary();
            let span = lhs.span.start..rhs.span.end;
            lhs = Spanned::new(Expr::And(Box::new(lhs), Box::new(rhs)), span);
        }
        lhs
    }


    fn expect(&mut self, expected: TokenKind) -> Token {
        let tok = self.advance();
        if tok.kind != expected {
            self.errors.push(ParseError {
                msg: format!("expected {:?}, got {:?}", expected, tok.kind),
                span: tok.span,
            });
        }
        tok
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens[self.pos].clone();
        self.pos += 1;
        tok
    }

    fn try_parse_where(&mut self) -> Option<Expr> {
        if self.peek().kind == Kw(Keyword::Where) {
            self.advance();
            Some(self.parse_expr())
        } else {
            None
        }
    }

    fn parse_expr(&mut self) -> Expr {
        self.parse_expr_bp(0) // start at minimum binding power
    }

    fn parse_expr_bp(&mut self, min_bp: u8) -> Expr {
        // Parse the left-hand side (a literal, identifier, or prefix op)
        let mut lhs = match self.peek().kind {
            Kw(Keyword::Not) => {
                self.advance();
                let rhs = self.parse_expr_bp(PREFIX_BP_NOT);
                Expr::Not(Box::new(rhs))
            }
            IntLit(n) => {
                self.advance();
                Expr::IntLit(n)
            }
            FloatLit(f) => {
                self.advance();
                Expr::FloatLit(f)
            }
            Ident(_) | Path => self.parse_path_or_call(),
            _ => self.error("expected expression"),
        };

        // Now keep consuming infix operators as long as their binding
        // power is high enough
        loop {
            let op = match self.peek().kind {
                Kw(Keyword::Or) => InfixOp::Or,
                Kw(Keyword::And) => InfixOp::And,
                Eq => InfixOp::Eq,
                Ne => InfixOp::Ne,
                Lt => InfixOp::Lt,
                Gt => InfixOp::Gt,
                Kw(Keyword::In) => InfixOp::In,
                _ => break, // not an operator we know — stop
            };

            let (left_bp, right_bp) = infix_binding_power(op);
            if left_bp < min_bp {
                break;
            } // precedence too low — stop

            self.advance(); // consume the operator
            let rhs = self.parse_expr_bp(right_bp);
            lhs = Expr::BinOp {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }

        lhs
    }

    fn infix_binding_power(op: InfixOp) -> (u8, u8) {
        match op {
            InfixOp::Or => (1, 2), // lowest precedence, left-associative
            InfixOp::And => (3, 4),
            InfixOp::Eq | InfixOp::Ne | InfixOp::Lt | InfixOp::Gt => (5, 6),
            InfixOp::In => (7, 8), // highest precedence
        }
    }
}
