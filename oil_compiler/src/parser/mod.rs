//! OIL parser (current stage)
//!
//! What this parser currently supports:
//! - top-level declarations: `use`/`import`, `set`, `rule`
//! - rule clauses: `from`, `match`, `correlate`, `where`, `within`, `let`, `score`, `respond`
//! - Pratt expression parsing for boolean/comparison/membership/string operators
//! - non-fatal error accumulation with synchronization and capped diagnostics
//!
//! What is intentionally still partial:
//! - full `emit`/`verify`/`require` semantics
//! - advanced call-chain expression forms beyond current AST coverage

use crate::ast::{
    ActionStmt, AuthKind, ChallengeKind, CorrelateArm, CorrelateBlock, CorrelateJoin,
    CorrelateMode, DurationUnit, EmitStmt, EventPattern, Expr, ImportDecl, IsolateKind,
    LetBinding, MatchBlock, MatchStep, OilDuration, Program, RequireClause, RespondArm,
    RespondBlock, RevokeKind, RuleBody, RuleDecl, ScoreExpr, ScoreModifier, SetDecl, Severity,
    SnapshotKind, SourceSpec, Spanned, VerifyClause,
};
use crate::lexer::{Keyword, Span, TimeUnit, Token, TokenKind};

const MAX_PARSE_ERRORS: usize = 100;

/// Non-fatal parser diagnostic.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

impl ParseError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

/// Recursive-descent parser state.
#[derive(Debug, Clone)]
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    errors: Vec<ParseError>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            errors: Vec::new(),
        }
    }

    /// Parse a full OIL program.
    pub fn parse(&mut self) -> Result<Program, Vec<ParseError>> {
        if self.tokens.is_empty() {
            self.error_at_end("empty token stream");
            return Err(self.errors.clone());
        }
        if !matches!(self.tokens.last().map(|t| &t.kind), Some(TokenKind::Eof)) {
            self.error_at_end("token stream must terminate with Eof");
            return Err(self.errors.clone());
        }

        let mut program = Program::default();

        while !self.is_at_end() {
            self.consume_newlines();
            if self.is_at_end() {
                break;
            }

            if self.peek_keyword(Keyword::Use) || self.peek_keyword(Keyword::Import) {
                match self.parse_import_decl() {
                    Some(decl) => program.imports.push(decl),
                    None => self.synchronize_top_level(),
                }
                continue;
            }

            if self.peek_keyword(Keyword::Set) {
                match self.parse_set_decl() {
                    Some(decl) => program.sets.push(decl),
                    None => self.synchronize_top_level(),
                }
                continue;
            }

            if self.peek_keyword(Keyword::Rule) {
                match self.parse_rule_decl() {
                    Some(decl) => program.rules.push(decl),
                    None => self.synchronize_top_level(),
                }
                continue;
            }

            // Top-level declarations we intentionally skip at this stage.
            if self.peek_keyword(Keyword::Predicate)
                || self.peek_keyword(Keyword::Template)
                || self.peek_keyword(Keyword::Fact)
                || self.peek_keyword(Keyword::Policy)
            {
                self.skip_unimplemented_top_level_decl();
                continue;
            }

            self.error_here("unexpected top-level token");
            self.synchronize_top_level();
        }

        if self.errors.is_empty() {
            Ok(program)
        } else {
            Err(self.errors.clone())
        }
    }

    // ---------------------------------------------------------------------
    // Top-level declarations
    // ---------------------------------------------------------------------

    fn parse_import_decl(&mut self) -> Option<ImportDecl> {
        self.advance(); // use/import
        let path = self.parse_dotted_path()?;
        Some(ImportDecl { path })
    }

    fn parse_set_decl(&mut self) -> Option<SetDecl> {
        self.advance(); // set

        let name_tok = self.expect_ident("expected set name")?.clone();
        let name = Spanned::new(self.ident_text(&name_tok)?, name_tok.span.clone());

        self.expect(&TokenKind::Assign, "expected '=' after set name")?;
        self.expect(&TokenKind::LBracket, "expected '[' to start set literal")?;

        let mut values = Vec::new();

        while !self.is_at_end() && !self.check(&TokenKind::RBracket) {
            self.consume_newlines();
            if self.check(&TokenKind::RBracket) {
                break;
            }

            match self.parse_set_value_expr() {
                Some(expr) => values.push(expr),
                None => {
                    self.error_here("invalid set value; expected scalar value");
                    self.synchronize_in_list();
                }
            }

            if self.match_kind(&TokenKind::Comma) {
                self.consume_newlines();
                continue;
            }

            self.consume_newlines();
            if self.check(&TokenKind::RBracket) {
                break;
            }

            self.error_here("expected ',' or ']' in set literal");
            self.synchronize_in_list();
        }

        self.expect(&TokenKind::RBracket, "expected closing ']' for set literal")?;
        Some(SetDecl { name, values })
    }

    fn parse_rule_decl(&mut self) -> Option<RuleDecl> {
        let rule_kw = self.advance().clone(); // rule

        let (name, name_span) = match self.peek().kind.clone() {
            TokenKind::StrLit(s) => {
                let span = self.advance().span.clone();
                (s, span)
            }
            TokenKind::Ident(s) => {
                let span = self.advance().span.clone();
                (s, span)
            }
            _ => {
                self.error_here("expected rule name after 'rule'");
                ("<error-rule-name>".to_string(), self.peek().span.clone())
            }
        };

        self.expect(&TokenKind::LBrace, "expected '{' to start rule body")?;

        let mut sources = Vec::new();
        let mut body = RuleBody::Match(MatchBlock::default());
        let mut where_ = None;
        let mut within = None;
        let mut require = None;
        let mut lets = Vec::new();
        let mut score = None;
        let mut verify = None;
        let mut emit = Vec::new();
        let mut respond = RespondBlock { arms: Vec::new() };

        while !self.is_at_end() && !self.check(&TokenKind::RBrace) {
            self.consume_newlines();
            if self.is_at_end() || self.check(&TokenKind::RBrace) {
                break;
            }

            if self.peek_keyword(Keyword::From) || self.peek_keyword(Keyword::Source) {
                match self.parse_from_clause() {
                    Some(s) => sources = s,
                    None => self.synchronize_rule_line(),
                }
                continue;
            }

            if self.peek_keyword(Keyword::Correlate) {
                match self.parse_correlate_block() {
                    Some(c) => body = RuleBody::Correlate(c),
                    None => self.synchronize_rule_line(),
                }
                continue;
            }

            if self.peek_keyword(Keyword::Match) {
                match self.parse_match_block() {
                    Some(m) => body = RuleBody::Match(m),
                    None => self.synchronize_rule_line(),
                }
                continue;
            }

            if self.peek_keyword(Keyword::Where) {
                where_ = self.parse_where_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Within) {
                within = self.parse_within_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Let) {
                lets.extend(self.parse_let_clause());
                continue;
            }

            if self.peek_keyword(Keyword::Score) {
                score = self.parse_score_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Require) {
                require = self.parse_require_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Verify) {
                verify = self.parse_verify_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Respond) {
                respond = self.parse_respond_clause();
                continue;
            }

            if self.peek_keyword(Keyword::Emit) {
                emit.extend(self.parse_emit_clause());
                continue;
            }

            // Unknown clause token: report and continue.
            self.error_here("unknown or unsupported rule clause");
            self.synchronize_rule_line();
        }

        let rbrace = self.expect(&TokenKind::RBrace, "expected closing '}' for rule body")?;
        let body_span = rule_kw.span.start..rbrace.span.end;

        Some(RuleDecl {
            meta: None,
            name: Spanned::new(name, name_span),
            sources,
            body: Spanned::new(body, body_span.clone()),
            where_,
            within,
            require,
            lets,
            score,
            verify,
            emit,
            respond: Spanned::new(respond, body_span),
        })
    }

    // ---------------------------------------------------------------------
    // Rule clauses
    // ---------------------------------------------------------------------

    fn parse_from_clause(&mut self) -> Option<Vec<SourceSpec>> {
        self.advance(); // from/source
        let mut out = Vec::new();

        let first = self.parse_source_spec()?;
        out.push(first);

        while self.match_kind(&TokenKind::Comma) {
            if let Some(spec) = self.parse_source_spec() {
                out.push(spec);
            } else {
                self.error_here("expected source spec after ','");
                self.synchronize_rule_line();
                break;
            }
        }

        Some(out)
    }

    fn parse_source_spec(&mut self) -> Option<SourceSpec> {
        let domain_tok = self.expect_ident("expected source domain")?.clone();
        let domain = self.ident_text(&domain_tok)?;
        self.expect(&TokenKind::Dot, "expected '.' in source spec")?;
        let event_tok = self.expect_ident("expected source event kind")?.clone();
        let event = self.ident_text(&event_tok)?;

        let alias = if self.match_ident_text("as") {
            let a = self.expect_ident("expected alias after 'as'")?.clone();
            Some(Spanned::new(self.ident_text(&a)?, a.span))
        } else {
            None
        };

        Some(SourceSpec {
            domain,
            event,
            alias,
        })
    }

    fn parse_match_block(&mut self) -> Option<MatchBlock> {
        self.advance(); // match
        self.consume_newlines();

        let mut steps = Vec::new();
        let first = self.parse_match_step()?;
        steps.push(first);

        loop {
            self.consume_newlines();
            if !self.peek_keyword(Keyword::Then) {
                break;
            }
            self.advance(); // then
            self.consume_newlines();
            if let Some(step) = self.parse_match_step() {
                steps.push(step);
            } else {
                self.synchronize_rule_line();
                break;
            }
        }

        Some(MatchBlock { steps })
    }

    fn parse_match_step(&mut self) -> Option<MatchStep> {
        let start = self.peek().span.start;
        let pattern = self.parse_event_pattern()?;
        let mut end = self.previous().map(|t| t.span.end).unwrap_or(start);

        let alias = if self.match_ident_text("as") {
            let t = self.expect_ident("expected alias after 'as'")?.clone();
            end = t.span.end;
            Some(Spanned::new(self.ident_text(&t)?, t.span))
        } else {
            None
        };

        let by = if self.peek_keyword(Keyword::By) {
            self.advance();
            let t = self.expect_ident("expected variable after 'by'")?.clone();
            end = t.span.end;

            let by_var = if self.match_ident_text("as") {
                let alias_tok = self.expect_ident("expected alias after 'as'")?.clone();
                end = alias_tok.span.end;
                Spanned::new(self.ident_text(&alias_tok)?, alias_tok.span)
            } else {
                Spanned::new(self.ident_text(&t)?, t.span)
            };

            Some(by_var)
        } else {
            None
        };

        Some(MatchStep {
            event: Spanned::new(pattern, start..end),
            alias,
            by,
        })
    }

    fn parse_correlate_block(&mut self) -> Option<CorrelateBlock> {
        self.advance(); // correlate
        self.consume_newlines();

        let mut arms = Vec::new();
        let first = self.parse_correlate_arm(false)?;
        arms.push(first);

        loop {
            self.consume_newlines();
            if !self.peek_keyword(Keyword::With) {
                break;
            }
            if let Some(arm) = self.parse_correlate_arm(true) {
                arms.push(arm);
            } else {
                self.synchronize_rule_line();
                break;
            }
        }

        Some(CorrelateBlock {
            mode: CorrelateMode::All,
            arms,
        })
    }

    fn parse_correlate_arm(&mut self, with_prefix: bool) -> Option<CorrelateArm> {
        if with_prefix {
            self.advance(); // with
        }
        self.consume_newlines();

        let start = self.peek().span.start;
        let pattern = self.parse_event_pattern()?;

        let alias = if self.match_ident_text("as") {
            let t = self.expect_ident("expected alias after 'as'")?.clone();
            Spanned::new(self.ident_text(&t)?, t.span.clone())
        } else {
            self.error_here("expected 'as <alias>' in correlate arm");
            Spanned::new("<missing_alias>".to_string(), self.peek().span.clone())
        };

        let join = if self.peek_keyword(Keyword::On) {
            self.advance(); // on
            match self.parse_expr() {
                Some(expr) => CorrelateJoin::OnPredicate(expr),
                None => {
                    self.error_here("expected expression after 'on'");
                    CorrelateJoin::None
                }
            }
        } else if self.peek_keyword(Keyword::By) {
            self.advance(); // by
            let t = self.expect_ident("expected variable after 'by'")?.clone();

            // Accept `by process as p` and prefer alias when provided.
            let by_var = if self.match_ident_text("as") {
                let alias_tok = self.expect_ident("expected alias after 'as'")?.clone();
                Spanned::new(self.ident_text(&alias_tok)?, alias_tok.span)
            } else {
                Spanned::new(self.ident_text(&t)?, t.span)
            };

            CorrelateJoin::ByVariable(by_var)
        } else {
            CorrelateJoin::None
        };

        let end = alias.span.end.max(start);
        Some(CorrelateArm {
            event: Spanned::new(pattern, start..end),
            alias,
            join,
        })
    }

    fn parse_where_clause(&mut self) -> Option<Spanned<Expr>> {
        self.advance(); // where
        self.parse_expr()
    }

    fn parse_within_clause(&mut self) -> Option<Spanned<OilDuration>> {
        let kw = self.advance().clone(); // within
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::DurationLit { value, unit } => {
                self.advance();
                Some(Spanned::new(
                    OilDuration {
                        value,
                        unit: map_duration_unit(unit),
                    },
                    kw.span.start..tok.span.end,
                ))
            }
            _ => {
                self.error_here("expected duration literal after 'within'");
                None
            }
        }
    }

    fn parse_let_clause(&mut self) -> Vec<LetBinding> {
        self.advance(); // let
        let mut bindings = Vec::new();

        loop {
            self.consume_newlines();
            if self.is_at_end() || self.check(&TokenKind::RBrace) || self.is_rule_clause_start() {
                break;
            }

            let name_tok = match self.expect_ident("expected let binding name") {
                Some(t) => t.clone(),
                None => {
                    self.synchronize_rule_line();
                    continue;
                }
            };

            if self.expect(&TokenKind::Assign, "expected '=' in let binding").is_none() {
                self.synchronize_rule_line();
                continue;
            }

            let value = match self.parse_expr() {
                Some(e) => e,
                None => {
                    self.error_here("expected expression in let binding");
                    self.synchronize_rule_line();
                    continue;
                }
            };

            bindings.push(LetBinding {
                name: Spanned::new(self.ident_text(&name_tok).unwrap_or_default(), name_tok.span),
                value,
            });

            self.synchronize_rule_line();
        }

        bindings
    }

    fn parse_score_clause(&mut self) -> Option<Spanned<ScoreExpr>> {
        let score_kw = self.advance().clone(); // score
        self.consume_newlines();

        let base_tok = self.peek().clone();
        let base = match base_tok.kind {
            TokenKind::IntLit(n) => {
                self.advance();
                Spanned::new(n as i32, base_tok.span.clone())
            }
            _ => {
                self.error_here("expected integer base score after 'score'");
                return None;
            }
        };

        let mut modifiers = Vec::new();

        loop {
            self.consume_newlines();

            let sign = if self.match_kind(&TokenKind::Plus) {
                1
            } else if self.match_kind(&TokenKind::Minus) {
                -1
            } else {
                break;
            };

            let delta_tok = self.peek().clone();
            let delta = match delta_tok.kind {
                TokenKind::IntLit(n) => {
                    self.advance();
                    sign * (n as i32)
                }
                _ => {
                    self.error_here("expected integer after '+'/'-' in score clause");
                    self.synchronize_rule_line();
                    continue;
                }
            };

            let condition = if self.peek_keyword(Keyword::If) {
                self.advance(); // if
                self.parse_expr()
            } else {
                None
            };

            modifiers.push(ScoreModifier {
                delta,
                condition,
                multiply: false,
            });

            // Do not force-skip to newline here: `parse_expr()` may already have
            // advanced to the next clause boundary, and synchronizing again can
            // accidentally consume the next clause header (e.g. `emit`).
        }

        let end = modifiers
            .last()
            .and_then(|m| m.condition.as_ref().map(|c| c.span.end))
            .unwrap_or(base.span.end);

        Some(Spanned::new(
            ScoreExpr { base, modifiers },
            score_kw.span.start..end,
        ))
    }

    fn parse_require_clause(&mut self) -> Option<Spanned<RequireClause>> {
        let kw = self.advance().clone();
        let expr = self.parse_expr()?;
        let span = kw.span.start..expr.span.end;
        Some(Spanned::new(RequireClause { expr }, span))
    }

    fn parse_verify_clause(&mut self) -> Option<VerifyClause> {
        self.advance(); // verify
        let expr = self.parse_expr()?;
        Some(VerifyClause { expr })
    }

    fn parse_respond_clause(&mut self) -> RespondBlock {
        self.advance(); // respond
        self.consume_newlines();

        let mut arms = Vec::new();

        // `if` / `else if` / `else` chain.
        if self.peek_keyword(Keyword::If) {
            loop {
                if self.peek_keyword(Keyword::If) {
                    self.advance();
                    let condition = self.parse_expr();
                    let actions = if self.expect(&TokenKind::LBrace, "expected '{' after respond if condition").is_some() {
                        self.parse_actions_block()
                    } else {
                        self.synchronize_rule_line();
                        Vec::new()
                    };

                    arms.push(RespondArm {
                        condition,
                        actions,
                    });

                    self.consume_newlines();
                    if self.peek_keyword(Keyword::Else) {
                        self.advance();
                        self.consume_newlines();
                        if self.peek_keyword(Keyword::If) {
                            continue;
                        }

                        // else { ... }
                        let actions = if self.expect(&TokenKind::LBrace, "expected '{' after else").is_some() {
                            self.parse_actions_block()
                        } else {
                            self.synchronize_rule_line();
                            Vec::new()
                        };
                        arms.push(RespondArm {
                            condition: None,
                            actions,
                        });
                    }
                    break;
                }
                break;
            }

            return RespondBlock { arms };
        }

        // Minimal inline form: `respond alert high`
        let inline_actions = self.parse_inline_actions_until_clause_boundary();
        if !inline_actions.is_empty() {
            arms.push(RespondArm {
                condition: None,
                actions: inline_actions,
            });
        }

        RespondBlock { arms }
    }

    fn parse_emit_clause(&mut self) -> Vec<EmitStmt> {
        self.advance(); // emit
        self.consume_newlines();

        let mut statements = Vec::new();

        // Parse emit body statements one line at a time. We currently support
        // `fact ...` forms and keep unknown emit forms as soft diagnostics.
        while !self.is_at_end() && !self.check(&TokenKind::RBrace) {
            if self.at_line_start() && self.is_rule_clause_start() {
                break;
            }

            // Current supported emit statement.
            if self.peek_keyword(Keyword::Fact) {
                if let Some(stmt) = self.parse_emit_fact_stmt() {
                    statements.push(stmt);
                } else {
                    self.synchronize_rule_line();
                }
                self.consume_newlines();
                continue;
            }

            self.error_here("unknown or unsupported emit statement");
            self.synchronize_rule_line();
            self.consume_newlines();
        }

        statements
    }

    fn parse_emit_fact_stmt(&mut self) -> Option<EmitStmt> {
        self.advance(); // fact
        let fact_name = self.parse_dotted_name("expected fact name after 'fact'")?;

        let args = if self.match_kind(&TokenKind::LParen) {
            let mut args = Vec::new();
            while !self.is_at_end() && !self.check(&TokenKind::RParen) {
                self.consume_newlines();
                if self.check(&TokenKind::RParen) {
                    break;
                }

                let expr = self.parse_expr()?;
                args.push(expr);

                if self.match_kind(&TokenKind::Comma) {
                    continue;
                }
                self.consume_newlines();
                if self.check(&TokenKind::RParen) {
                    break;
                }
                self.error_here("expected ',' or ')' in fact argument list");
                self.synchronize_expr();
            }
            let _ = self.expect(&TokenKind::RParen, "expected ')' after fact arguments");
            args
        } else {
            self.error_here("expected '(' after fact name");
            Vec::new()
        };

        let expires = if self.peek_keyword(Keyword::Expires) {
            let kw = self.advance().clone();
            match self.peek().kind {
                TokenKind::DurationLit { value, unit } => {
                    let tok = self.advance().clone();
                    Some(Spanned::new(
                        OilDuration {
                            value,
                            unit: map_duration_unit(unit),
                        },
                        kw.span.start..tok.span.end,
                    ))
                }
                _ => {
                    self.error_here("expected duration literal after 'expires'");
                    None
                }
            }
        } else {
            None
        };

        Some(EmitStmt {
            fact_name,
            args,
            expires,
        })
    }

    fn parse_actions_block(&mut self) -> Vec<Spanned<ActionStmt>> {
        let mut actions = Vec::new();

        while !self.is_at_end() && !self.check(&TokenKind::RBrace) {
            self.consume_newlines();
            if self.check(&TokenKind::RBrace) {
                break;
            }

            if let Some(action) = self.parse_action_stmt() {
                actions.push(action);
                continue;
            }

            self.error_here("unknown or unsupported respond action");
            self.synchronize_rule_line();
        }

        let _ = self.expect(&TokenKind::RBrace, "expected '}' to close respond arm");
        actions
    }

    fn parse_inline_actions_until_clause_boundary(&mut self) -> Vec<Spanned<ActionStmt>> {
        let mut actions = Vec::new();

        while !self.is_at_end() && !self.check(&TokenKind::RBrace) {
            self.consume_newlines();
            if self.check(&TokenKind::RBrace) {
                break;
            }
            if self.at_line_start() && self.is_rule_clause_start() {
                break;
            }

            if let Some(action) = self.parse_action_stmt() {
                actions.push(action);
                continue;
            }

            self.error_here("unknown or unsupported respond action");
            self.synchronize_rule_line();
        }

        actions
    }

    fn parse_action_stmt(&mut self) -> Option<Spanned<ActionStmt>> {
        if self.peek_keyword(Keyword::Alert) {
            return self.parse_alert_action();
        }
        if self.peek_keyword(Keyword::Isolate) {
            return self.parse_isolate_action();
        }
        if self.peek_keyword(Keyword::Revoke) {
            return self.parse_revoke_action();
        }
        if self.peek_keyword(Keyword::Snapshot) {
            return self.parse_snapshot_action();
        }
        if self.peek_keyword(Keyword::OpenCase) || self.is_open_case_pair() {
            return self.parse_open_case_action();
        }
        if self.peek_keyword(Keyword::Challenge) {
            return self.parse_challenge_action();
        }
        if self.peek_keyword(Keyword::RequireMfa) {
            return self.parse_require_mfa_action();
        }
        if self.peek_keyword(Keyword::Quarantine) {
            return self.parse_quarantine_action();
        }
        if self.peek_keyword(Keyword::Block) {
            return self.parse_block_egress_action();
        }
        if self.peek_keyword(Keyword::Notify) {
            return self.parse_notify_action();
        }
        if self.peek_keyword(Keyword::Throttle) {
            return self.parse_throttle_action();
        }
        None
    }

    fn parse_alert_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // alert

        let sev_tok = self.peek().clone();
        let severity = match sev_tok.kind {
            TokenKind::Kw(Keyword::Critical) => Severity::Critical,
            TokenKind::Kw(Keyword::High) => Severity::High,
            TokenKind::Kw(Keyword::Medium) => Severity::Medium,
            TokenKind::Kw(Keyword::Low) => Severity::Low,
            TokenKind::Kw(Keyword::Informational) => Severity::Informational,
            _ => {
                self.error_here("expected alert severity after 'alert'");
                return None;
            }
        };
        self.advance();

        let message = if let TokenKind::StrLit(s) = self.peek().kind.clone() {
            self.advance();
            Some(s)
        } else {
            None
        };

        let end = self.previous().map(|t| t.span.end).unwrap_or(start);
        Some(Spanned::new(
            ActionStmt::Alert { severity, message },
            start..end,
        ))
    }

    fn parse_isolate_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // isolate
        let target = self.expect_ident("expected isolate target kind")?.clone();
        let target_text = self.ident_text(&target)?;

        let kind = match target_text.as_str() {
            "host" => IsolateKind::Host,
            "network" => IsolateKind::Network,
            "process" => IsolateKind::Process,
            _ => {
                self.error_here("expected isolate target to be host/network/process");
                IsolateKind::Host
            }
        };

        let target = Spanned::new(target_text, target.span.clone());
        let end = target.span.end;
        Some(Spanned::new(
            ActionStmt::Isolate { kind, target },
            start..end,
        ))
    }

    fn parse_revoke_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // revoke
        let target = self.expect_ident("expected revoke target kind")?.clone();
        let target_text = self.ident_text(&target)?;

        let kind = match target_text.as_str() {
            "session" => RevokeKind::Session,
            "token" => RevokeKind::Token,
            "credential" => RevokeKind::Credential,
            _ => {
                self.error_here("expected revoke target to be session/token/credential");
                RevokeKind::Credential
            }
        };

        let target = Spanned::new(target_text, target.span.clone());
        let end = target.span.end;
        Some(Spanned::new(
            ActionStmt::Revoke { kind, target },
            start..end,
        ))
    }

    fn parse_snapshot_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // snapshot
        let mut targets = Vec::new();

        loop {
            self.consume_newlines();
            if self.check(&TokenKind::RBrace) || self.check(&TokenKind::Newline) {
                break;
            }

            if let Some(target) = self.parse_dotted_name("expected snapshot target") {
                targets.push(target);
            } else {
                self.synchronize_rule_line();
                break;
            }

            if self.match_kind(&TokenKind::Comma) {
                continue;
            }
            break;
        }

        let end = targets
            .last()
            .map(|t| t.span.end)
            .unwrap_or_else(|| self.previous().map(|t| t.span.end).unwrap_or(start));

        Some(Spanned::new(
            ActionStmt::Snapshot {
                targets,
                kind: SnapshotKind::Entities,
            },
            start..end,
        ))
    }

    fn parse_open_case_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.peek().span.start;

        if self.peek_keyword(Keyword::OpenCase) {
            self.advance();
        } else {
            // Support two-token DSL spelling: `open case "..."`
            self.advance(); // open
            if !self.match_ident_text("case") {
                self.error_here("expected 'case' after 'open'");
                return None;
            }
        }

        let title_tok = self.peek().clone();
        let title = match title_tok.kind {
            TokenKind::StrLit(s) => {
                self.advance();
                s
            }
            _ => {
                self.error_here("expected case title string");
                return None;
            }
        };

        Some(Spanned::new(
            ActionStmt::OpenCase { title },
            start..title_tok.span.end,
        ))
    }

    fn parse_challenge_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // challenge
        let tok = self.expect_ident("expected challenge kind")?.clone();
        let kind = match self.ident_text(&tok)?.as_str() {
            "mfa" => ChallengeKind::Mfa,
            _ => {
                self.error_here("expected challenge kind 'mfa'");
                ChallengeKind::Mfa
            }
        };

        Some(Spanned::new(
            ActionStmt::Challenge { kind },
            start..tok.span.end,
        ))
    }

    fn parse_require_mfa_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // require_mfa

        let for_ = if self.match_ident_text("for") {
            self.parse_dotted_name("expected target after 'for'")?
        } else if let Some(name) = self.parse_dotted_name("expected target for require_mfa") {
            name
        } else {
            Spanned::new("<missing>".to_string(), self.peek().span.clone())
        };

        Some(Spanned::new(
            ActionStmt::RequireAuth {
                kind: AuthKind::StepUp,
                for_,
            },
            start..self.previous().map(|t| t.span.end).unwrap_or(start),
        ))
    }

    fn parse_quarantine_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // quarantine
        let path = self.parse_dotted_name("expected quarantine path/target")?;
        let end = path.span.end;
        Some(Spanned::new(ActionStmt::Quarantine { path }, start..end))
    }

    fn parse_block_egress_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // block

        // Current supported form: `block egress <target>`
        if !self.match_ident_text("egress") {
            self.error_here("expected 'egress' after 'block'");
            return None;
        }

        let target = self.parse_dotted_name("expected block egress target")?;
        let end = target.span.end;
        Some(Spanned::new(
            ActionStmt::BlockEgress { target },
            start..end,
        ))
    }

    fn parse_notify_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // notify
        let msg_tok = self.peek().clone();
        let message = match msg_tok.kind {
            TokenKind::StrLit(s) => {
                self.advance();
                s
            }
            _ => {
                self.error_here("expected notify message string");
                return None;
            }
        };
        Some(Spanned::new(
            ActionStmt::Notify { message },
            start..msg_tok.span.end,
        ))
    }

    fn parse_throttle_action(&mut self) -> Option<Spanned<ActionStmt>> {
        let start = self.advance().span.start; // throttle
        let target = self.parse_dotted_name("expected throttle target")?;
        let end = target.span.end;
        Some(Spanned::new(
            ActionStmt::Throttle { target },
            start..end,
        ))
    }

    // ---------------------------------------------------------------------
    // Expression parser (Pratt)
    // ---------------------------------------------------------------------

    fn parse_expr(&mut self) -> Option<Spanned<Expr>> {
        self.parse_expr_bp(0)
    }

    fn parse_expr_bp(&mut self, min_bp: u8) -> Option<Spanned<Expr>> {
        self.consume_newlines();
        let mut lhs = self.parse_prefix_expr()?;

        loop {
            self.consume_newlines();
            let Some((op, l_bp, r_bp)) = self.peek_infix_op() else {
                break;
            };
            if l_bp < min_bp {
                break;
            }

            self.consume_infix_op(op);
            let rhs = match self.parse_expr_bp(r_bp) {
                Some(e) => e,
                None => {
                    self.error_here("expected expression after operator");
                    return Some(lhs);
                }
            };

            let span = lhs.span.start..rhs.span.end;
            let node = match op {
                InfixOp::Or => Expr::Or(Box::new(lhs), Box::new(rhs)),
                InfixOp::And => Expr::And(Box::new(lhs), Box::new(rhs)),
                InfixOp::Eq => Expr::Cmp {
                    op: crate::ast::CmpOp::Eq,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Ne => Expr::Cmp {
                    op: crate::ast::CmpOp::Ne,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Lt => Expr::Cmp {
                    op: crate::ast::CmpOp::Lt,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Gt => Expr::Cmp {
                    op: crate::ast::CmpOp::Gt,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Le => Expr::Cmp {
                    op: crate::ast::CmpOp::Le,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Ge => Expr::Cmp {
                    op: crate::ast::CmpOp::Ge,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::In => Expr::In {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::NotIn => Expr::NotIn {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Contains => Expr::Contains {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::StartsWith => Expr::StartsWith {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::EndsWith => Expr::EndsWith {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                },
                InfixOp::Under => Expr::Under {
                    path: Box::new(lhs),
                    prefix: Box::new(rhs),
                },
                InfixOp::Matches => {
                    let pattern = expr_to_pattern_string(&rhs.node);
                    Expr::Matches {
                        lhs: Box::new(lhs),
                        pattern,
                    }
                }
            };

            lhs = Spanned::new(node, span);
        }

        Some(lhs)
    }

    fn parse_prefix_expr(&mut self) -> Option<Spanned<Expr>> {
        self.consume_newlines();
        let tok = self.peek().clone();

        match tok.kind {
            TokenKind::IntLit(n) => {
                self.advance();
                Some(Spanned::new(Expr::IntLit(n), tok.span))
            }
            TokenKind::FloatLit(f) => {
                self.advance();
                Some(Spanned::new(Expr::FloatLit(f), tok.span))
            }
            TokenKind::StrLit(s) => {
                self.advance();
                Some(Spanned::new(Expr::StrLit(s), tok.span))
            }
            TokenKind::DurationLit { value, unit } => {
                self.advance();
                Some(Spanned::new(
                    Expr::DurationLit(OilDuration {
                        value,
                        unit: map_duration_unit(unit),
                    }),
                    tok.span,
                ))
            }
            TokenKind::Kw(Keyword::True) => {
                self.advance();
                Some(Spanned::new(Expr::BoolLit(true), tok.span))
            }
            TokenKind::Kw(Keyword::False) => {
                self.advance();
                Some(Spanned::new(Expr::BoolLit(false), tok.span))
            }
            TokenKind::Kw(Keyword::Null) => {
                self.advance();
                Some(Spanned::new(Expr::Null, tok.span))
            }
            TokenKind::Kw(Keyword::Not) => {
                self.advance();
                let rhs = self.parse_expr_bp(9)?;
                let span = tok.span.start..rhs.span.end;
                Some(Spanned::new(Expr::Not(Box::new(rhs)), span))
            }
            TokenKind::Minus => {
                self.advance();
                let rhs = self.parse_expr_bp(9)?;
                let span = tok.span.start..rhs.span.end;
                Some(Spanned::new(Expr::UnaryMinus(Box::new(rhs)), span))
            }
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_expr()?;
                let end_tok = self.expect(&TokenKind::RParen, "expected ')' after expression")?;
                Some(Spanned::new(inner.node, tok.span.start..end_tok.span.end))
            }
            TokenKind::LBracket => self.parse_list_literal(),
            TokenKind::Ident(_) => self.parse_ident_path_or_call(),
            // In condition contexts (`respond if score >= 75`), `score` behaves like a
            // readable value, but the lexer classifies it as a keyword globally.
            // Accept it here as an identifier-like expression node so rule conditions
            // can reference the computed score.
            TokenKind::Kw(Keyword::Score) => {
                self.advance();
                Some(Spanned::new(Expr::Ident("score".to_string()), tok.span))
            }
            _ => {
                self.error_here("expected expression");
                None
            }
        }
    }

    fn parse_ident_path_or_call(&mut self) -> Option<Spanned<Expr>> {
        let first = self.expect_ident("expected identifier")?.clone();
        let first_name = self.ident_text(&first)?;

        // function call: foo(...)
        if self.check(&TokenKind::LParen) {
            self.advance(); // '('
            let mut args = Vec::new();

            while !self.is_at_end() && !self.check(&TokenKind::RParen) {
                self.consume_newlines();
                if self.check(&TokenKind::RParen) {
                    break;
                }
                let arg = self.parse_expr()?;
                args.push(arg);

                if self.match_kind(&TokenKind::Comma) {
                    continue;
                }
                self.consume_newlines();
                if self.check(&TokenKind::RParen) {
                    break;
                }
                self.error_here("expected ',' or ')' in argument list");
                self.synchronize_expr();
            }

            let end_tok = self.expect(&TokenKind::RParen, "expected ')' to close call")?.clone();
            return Some(Spanned::new(
                Expr::Call {
                    name: first_name,
                    args,
                },
                first.span.start..end_tok.span.end,
            ));
        }

        // path: a.b.c
        let mut parts = vec![first_name];
        let mut end = first.span.end;
        while self.match_kind(&TokenKind::Dot) {
            let seg = self.expect_ident("expected identifier after '.'")?.clone();
            end = seg.span.end;
            parts.push(self.ident_text(&seg)?);
        }

        if parts.len() == 1 {
            Some(Spanned::new(Expr::Ident(parts[0].clone()), first.span))
        } else {
            Some(Spanned::new(Expr::Path(parts), first.span.start..end))
        }
    }

    fn parse_list_literal(&mut self) -> Option<Spanned<Expr>> {
        let start = self.advance().span.start; // '['
        let mut items = Vec::new();

        while !self.is_at_end() && !self.check(&TokenKind::RBracket) {
            self.consume_newlines();
            if self.check(&TokenKind::RBracket) {
                break;
            }

            let item = self.parse_expr()?;
            items.push(item);

            if self.match_kind(&TokenKind::Comma) {
                continue;
            }

            self.consume_newlines();
            if self.check(&TokenKind::RBracket) {
                break;
            }

            self.error_here("expected ',' or ']' in list literal");
            self.synchronize_expr();
        }

        let end = self.expect(&TokenKind::RBracket, "expected ']' to close list")?.span.end;
        Some(Spanned::new(Expr::List(items), start..end))
    }

    fn peek_infix_op(&self) -> Option<(InfixOp, u8, u8)> {
        // two-token operator: `not in`
        if self.peek_keyword(Keyword::Not)
            && self.peek_n(1)
                .map(|t| matches!(t.kind, TokenKind::Kw(Keyword::In)))
                .unwrap_or(false)
        {
            return Some((InfixOp::NotIn, 5, 6));
        }

        let op = match self.peek().kind {
            TokenKind::Kw(Keyword::Or) => InfixOp::Or,
            TokenKind::Kw(Keyword::And) => InfixOp::And,
            TokenKind::Eq => InfixOp::Eq,
            TokenKind::Ne => InfixOp::Ne,
            TokenKind::Lt => InfixOp::Lt,
            TokenKind::Gt => InfixOp::Gt,
            TokenKind::Le => InfixOp::Le,
            TokenKind::Ge => InfixOp::Ge,
            TokenKind::Kw(Keyword::In) => InfixOp::In,
            TokenKind::Kw(Keyword::Contains) => InfixOp::Contains,
            TokenKind::Kw(Keyword::StartsWith) => InfixOp::StartsWith,
            TokenKind::Kw(Keyword::EndsWith) => InfixOp::EndsWith,
            TokenKind::Kw(Keyword::Matches) => InfixOp::Matches,
            TokenKind::Kw(Keyword::Under) => InfixOp::Under,
            _ => return None,
        };

        let bp = match op {
            InfixOp::Or => (1, 2),
            InfixOp::And => (3, 4),
            InfixOp::Eq
            | InfixOp::Ne
            | InfixOp::Lt
            | InfixOp::Gt
            | InfixOp::Le
            | InfixOp::Ge
            | InfixOp::In
            | InfixOp::NotIn
            | InfixOp::Contains
            | InfixOp::StartsWith
            | InfixOp::EndsWith
            | InfixOp::Matches
            | InfixOp::Under => (5, 6),
        };
        Some((op, bp.0, bp.1))
    }

    fn consume_infix_op(&mut self, op: InfixOp) {
        match op {
            InfixOp::NotIn => {
                self.advance(); // not
                self.advance(); // in
            }
            _ => {
                self.advance();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Recovery + skipping helpers
    // ---------------------------------------------------------------------

    fn synchronize_top_level(&mut self) {
        while !self.is_at_end() {
            if matches!(self.peek().kind, TokenKind::Newline) {
                self.advance();
                if self.peek_keyword(Keyword::Use)
                    || self.peek_keyword(Keyword::Import)
                    || self.peek_keyword(Keyword::Set)
                    || self.peek_keyword(Keyword::Rule)
                    || self.peek_keyword(Keyword::Predicate)
                    || self.peek_keyword(Keyword::Template)
                    || self.peek_keyword(Keyword::Fact)
                    || self.peek_keyword(Keyword::Policy)
                {
                    return;
                }
                continue;
            }
            self.advance();
        }
    }

    fn skip_unimplemented_top_level_decl(&mut self) {
        self.advance(); // declaration keyword

        let mut depth = 0usize;
        while !self.is_at_end() {
            match self.peek().kind {
                TokenKind::LBrace => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::RBrace => {
                    if depth == 0 {
                        return;
                    }
                    depth -= 1;
                    self.advance();
                    if depth == 0 {
                        return;
                    }
                }
                TokenKind::Newline if depth == 0 => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn synchronize_in_list(&mut self) {
        while !self.is_at_end() {
            if self.check(&TokenKind::Comma) || self.check(&TokenKind::RBracket) {
                return;
            }
            self.advance();
        }
    }

    fn synchronize_rule_line(&mut self) {
        while !self.is_at_end() {
            if self.check(&TokenKind::Newline) || self.check(&TokenKind::RBrace) {
                return;
            }
            self.advance();
        }
    }

    fn synchronize_expr(&mut self) {
        while !self.is_at_end() {
            if self.check(&TokenKind::Comma)
                || self.check(&TokenKind::Newline)
                || self.check(&TokenKind::RParen)
                || self.check(&TokenKind::RBracket)
                || self.check(&TokenKind::RBrace)
            {
                return;
            }
            self.advance();
        }
    }

    // ---------------------------------------------------------------------
    // Cursor + token helpers
    // ---------------------------------------------------------------------

    pub fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_n(&self, n: usize) -> Option<&Token> {
        self.tokens.get(self.pos + n)
    }

    pub fn previous(&self) -> Option<&Token> {
        if self.pos == 0 {
            None
        } else {
            self.tokens.get(self.pos - 1)
        }
    }

    pub fn is_at_end(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Eof)
    }

    pub fn advance(&mut self) -> &Token {
        if !self.is_at_end() {
            self.pos += 1;
        }
        self.previous().expect("advance always has previous token")
    }

    pub fn check(&self, kind: &TokenKind) -> bool {
        &self.peek().kind == kind
    }

    pub fn match_kind(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub fn peek_keyword(&self, kw: Keyword) -> bool {
        matches!(self.peek().kind, TokenKind::Kw(found) if found == kw)
    }

    fn consume_newlines(&mut self) {
        while self.match_kind(&TokenKind::Newline) {}
    }

    pub fn expect(&mut self, kind: &TokenKind, message: impl Into<String>) -> Option<&Token> {
        if self.check(kind) {
            Some(self.advance())
        } else {
            self.error_here(message);
            None
        }
    }

    pub fn expect_ident(&mut self, message: impl Into<String>) -> Option<&Token> {
        if matches!(self.peek().kind, TokenKind::Ident(_)) {
            Some(self.advance())
        } else {
            self.error_here(message);
            None
        }
    }

    fn match_ident_text(&mut self, expected: &str) -> bool {
        match &self.peek().kind {
            TokenKind::Ident(s) if s == expected => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn ident_text(&mut self, tok: &Token) -> Option<String> {
        match &tok.kind {
            TokenKind::Ident(s) => Some(s.clone()),
            _ => {
                self.push_error("expected identifier token", tok.span.clone());
                None
            }
        }
    }

    fn parse_dotted_path(&mut self) -> Option<Spanned<Vec<String>>> {
        let first = self.expect_ident("expected identifier in dotted path")?.clone();
        let mut parts = vec![self.ident_text(&first)?];
        let start = first.span.start;
        let mut end = first.span.end;

        while self.match_kind(&TokenKind::Dot) {
            let seg = self.expect_ident("expected identifier after '.'")?.clone();
            end = seg.span.end;
            parts.push(self.ident_text(&seg)?);
        }

        Some(Spanned::new(parts, start..end))
    }

    fn parse_dotted_name(&mut self, message: impl Into<String>) -> Option<Spanned<String>> {
        let message = message.into();
        let first = self.expect_ident(message)?.clone();
        let first_text = self.ident_text(&first)?;
        let start = first.span.start;
        let mut end = first.span.end;
        let mut out = first_text;

        while self.match_kind(&TokenKind::Dot) {
            let seg = self.expect_ident("expected identifier after '.'")?.clone();
            end = seg.span.end;
            out.push('.');
            out.push_str(&self.ident_text(&seg)?);
        }

        Some(Spanned::new(out, start..end))
    }

    fn is_open_case_pair(&self) -> bool {
        match (&self.peek().kind, self.peek_n(1).map(|t| &t.kind)) {
            (TokenKind::Ident(a), Some(TokenKind::Ident(b))) => a == "open" && b == "case",
            _ => false,
        }
    }

    fn parse_event_pattern(&mut self) -> Option<EventPattern> {
        let domain_tok = self.expect_ident("expected event domain")?.clone();
        let domain = self.ident_text(&domain_tok)?;
        self.expect(&TokenKind::Dot, "expected '.' in event pattern")?;
        let kind_tok = self.expect_ident("expected event kind")?.clone();
        let kind = self.ident_text(&kind_tok)?;
        Some(EventPattern { domain, kind })
    }

    fn parse_set_value_expr(&mut self) -> Option<Spanned<Expr>> {
        let tok = self.peek().clone();
        let span = tok.span.clone();

        let expr = match tok.kind {
            TokenKind::StrLit(s) => {
                self.advance();
                Expr::StrLit(s)
            }
            TokenKind::IntLit(n) => {
                self.advance();
                Expr::IntLit(n)
            }
            TokenKind::FloatLit(f) => {
                self.advance();
                Expr::FloatLit(f)
            }
            TokenKind::Ident(s) => {
                self.advance();
                Expr::Ident(s)
            }
            TokenKind::Kw(Keyword::True) => {
                self.advance();
                Expr::BoolLit(true)
            }
            TokenKind::Kw(Keyword::False) => {
                self.advance();
                Expr::BoolLit(false)
            }
            TokenKind::Kw(Keyword::Null) => {
                self.advance();
                Expr::Null
            }
            TokenKind::DurationLit { value, unit } => {
                self.advance();
                Expr::DurationLit(OilDuration {
                    value,
                    unit: map_duration_unit(unit),
                })
            }
            _ => return None,
        };

        Some(Spanned::new(expr, span))
    }

    fn is_rule_clause_start(&self) -> bool {
        self.peek_keyword(Keyword::From)
            || self.peek_keyword(Keyword::Source)
            || self.peek_keyword(Keyword::Match)
            || self.peek_keyword(Keyword::Correlate)
            || self.peek_keyword(Keyword::Where)
            || self.peek_keyword(Keyword::Within)
            || self.peek_keyword(Keyword::Let)
            || self.peek_keyword(Keyword::Score)
            || self.peek_keyword(Keyword::Require)
            || self.peek_keyword(Keyword::Verify)
            || self.peek_keyword(Keyword::Emit)
            || self.peek_keyword(Keyword::Respond)
    }

    fn at_line_start(&self) -> bool {
        if self.pos == 0 {
            return true;
        }
        matches!(
            self.tokens[self.pos - 1].kind,
            TokenKind::Newline | TokenKind::LBrace
        )
    }

    fn push_error(&mut self, message: impl Into<String>, span: Span) {
        if self.errors.len() >= MAX_PARSE_ERRORS {
            return;
        }
        self.errors.push(ParseError::new(message, span));
    }

    pub fn error_here(&mut self, message: impl Into<String>) {
        let span = self.peek().span.clone();
        self.push_error(message, span);
    }

    pub fn error_at_end(&mut self, message: impl Into<String>) {
        let span = self
            .tokens
            .last()
            .map(|t| t.span.clone())
            .unwrap_or(0..0);
        self.push_error(message, span);
    }

    pub fn errors(&self) -> &[ParseError] {
        &self.errors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfixOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Under,
}

fn map_duration_unit(unit: TimeUnit) -> DurationUnit {
    match unit {
        TimeUnit::Ns => DurationUnit::Ns,
        TimeUnit::Us => DurationUnit::Us,
        TimeUnit::Ms => DurationUnit::Ms,
        TimeUnit::S => DurationUnit::S,
        TimeUnit::M => DurationUnit::M,
        TimeUnit::H => DurationUnit::H,
        TimeUnit::D => DurationUnit::D,
    }
}

fn expr_to_pattern_string(expr: &Expr) -> String {
    match expr {
        Expr::StrLit(s) => s.clone(),
        Expr::Ident(s) => s.clone(),
        Expr::Path(parts) => parts.join("."),
        _ => format!("{:?}", expr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;

    fn parse_ok(src: &str) -> Program {
        let tokens = Lexer::new(src).tokenize().expect("lex should succeed");
        let mut p = Parser::new(tokens);
        p.parse().expect("parse should succeed")
    }

    #[test]
    fn set_parses_with_duplicates_and_trailing_comma_newlines() {
        let src = r#"
set shells = [
  "bash",
  "bash",
]
"#;
        let program = parse_ok(src);
        assert_eq!(program.sets.len(), 1);
        assert_eq!(program.sets[0].values.len(), 2);
    }

    #[test]
    fn parses_tmp_exec_rule_file() {
        let src = include_str!("../rules/stress_test/tmp_exec.oil");
        let program = parse_ok(src);
        assert_eq!(program.rules.len(), 1);
    }

    #[test]
    fn parses_shell_spawn_rule_file() {
        let src = include_str!("../rules/shell_spawn_in_container.oil");
        let program = parse_ok(src);
        assert_eq!(program.rules.len(), 1);
        let rule = &program.rules[0];
        assert_eq!(rule.emit.len(), 1);
        assert_eq!(rule.emit[0].fact_name.node, "container.interactive_shell");
        assert_eq!(rule.respond.node.arms.len(), 2);
        assert!(
            rule.respond.node.arms[0]
                .actions
                .iter()
                .any(|a| matches!(a.node, ActionStmt::Snapshot { .. }))
        );
        assert!(
            rule.respond.node.arms[0]
                .actions
                .iter()
                .any(|a| matches!(a.node, ActionStmt::OpenCase { .. }))
        );
    }

    #[test]
    fn parses_credential_access_rule_file() {
        let src = include_str!("../rules/credential_access_followed_by_egress.oil");
        let program = parse_ok(src);
        assert_eq!(program.rules.len(), 1);
        let rule = &program.rules[0];
        assert_eq!(rule.emit.len(), 1);
        assert_eq!(rule.emit[0].fact_name.node, "host.possible_credential_exfil");
        assert!(
            rule.respond.node.arms[0]
                .actions
                .iter()
                .any(|a| matches!(a.node, ActionStmt::Isolate { .. }))
        );
    }

    #[test]
    fn expression_precedence_and_over_or() {
        let src = r#"
rule "prec" {
  from endpoint.process
  match process.spawn as p
  where a == 1 or b == 2 and c == 3
  respond alert high
}
"#;
        let program = parse_ok(src);
        let where_expr = program.rules[0].where_.as_ref().expect("where parsed");
        match &where_expr.node {
            Expr::Or(_, rhs) => match &rhs.node {
                Expr::And(_, _) => {}
                other => panic!("expected rhs to be And, got {:?}", other),
            },
            other => panic!("expected top expr Or, got {:?}", other),
        }
    }

    #[test]
    fn broken_input_reports_errors_without_panicking() {
        let src = r#"
rule "broken" {
  from endpoint.process
  where a ==
  respond alert high
}
rule "second" {
  from endpoint.process
  match process.spawn as p
}
"#;

        let tokens = Lexer::new(src).tokenize().expect("lex should succeed");
        let mut p = Parser::new(tokens);
        let result = p.parse();
        assert!(result.is_err());
        assert!(!p.errors().is_empty());
        assert!(p.errors().len() <= MAX_PARSE_ERRORS);
    }
}
