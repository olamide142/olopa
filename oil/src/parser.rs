/*
The parser reads the token list and produces an Abstract Syntax Tree (AST) — a tree that reflects the grammatical structure of the program.
The technique for OIL is recursive descent with Pratt parsing for expressions. These two techniques together handle essentially any grammar you'll encounter.
Recursive descent for statements
Each grammar rule becomes a function. The function peeks at the current token to decide what to do:

*/

impl Parser {
    fn parse_program(&mut self) -> Program {
        let mut rules = vec![];
        while !self.is_at_end() {
            match self.peek().kind {
                Kw(Keyword::Rule) => rules.push(self.parse_rule()),
                Kw(Keyword::Set) => { /* parse set decl */ }
                Kw(Keyword::Predicate) => { /* parse predicate */ }
                _ => self.error("unexpected token"),
            }
        }
        Program { rules, .. }
    }

    fn parse_rule(&mut self) -> RuleDecl {
        self.expect(Kw(Keyword::Rule)); // consume "rule"
        let name = self.expect_string(); // consume the name string
        self.expect(LBrace); // consume "{"

        // Now parse clauses — each checks what's next
        let body = match self.peek().kind {
            Kw(Keyword::Match) => self.parse_match_block(),
            Kw(Keyword::Correlate) => self.parse_correlate_block(),
            Kw(Keyword::Graph) => self.parse_graph_block(),
            Kw(Keyword::Around) => self.parse_around_block(),
            _ => self.error("expected match/correlate/graph/around"),
        };

        let where_ = self.try_parse_where(); // optional
        let within = self.try_parse_within(); // optional
        let score = self.try_parse_score(); // optional
        let respond = self.parse_respond(); // required

        self.expect(RBrace);
        RuleDecl {
            name,
            body,
            where_,
            within,
            score,
            respond,
            ..
        }
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
