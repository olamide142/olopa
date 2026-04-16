use std::collections::HashSet;
use std::ops::Range;

use crate::ast::{ActionStmt, Expr, MatchBlock, Program, RuleBody, RuleDecl, Spanned};
use crate::schema::{FieldType, SchemaRegistry};

type Span = Range<usize>;

/// Global symbol registry built from top-level declarations.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub sets: HashSet<String>,
    pub predicates: HashSet<String>,
    pub facts: HashSet<String>,
    pub external_symbols: HashSet<String>,
    pub external_namespaces: HashSet<String>,
}

/// Source category for externally managed symbols imported via `use`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalSymbolSource {
    Intel,
    Org,
    Other,
}

/// Best-effort categorization of function-like calls after resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedCallKind {
    FactRef,
    PredicateCall,
    Unknown,
}

/// Resolver output sidecar that can be surfaced by the compiler.
#[derive(Debug, Clone, Default)]
pub struct ResolveOutput {
    pub symbols: SymbolTable,
    pub external_refs: Vec<ExternalRef>,
    pub calls: Vec<ResolvedCall>,
    pub diagnostics: Vec<ResolveDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct ExternalRef {
    pub source: ExternalSymbolSource,
    pub full_path: String,
    pub symbol: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ResolvedCall {
    pub name: String,
    pub kind: ResolvedCallKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ResolveDiagnostic {
    pub message: String,
    pub span: Option<Span>,
}

/// Resolve names in a parsed program.
pub fn resolve_program(program: &Program) -> ResolveOutput {
    let empty_schema = SchemaRegistry::default();
    let empty_builtin_predicates = HashSet::new();
    let empty_builtin_sets = HashSet::new();
    let empty_builtin_callables = HashSet::new();
    resolve_program_with_schema(
        program,
        &empty_schema,
        &empty_builtin_predicates,
        &empty_builtin_sets,
        &empty_builtin_callables,
    )
}

pub fn resolve_program_with_schema(
    program: &Program,
    schema: &SchemaRegistry,
    builtin_predicates: &HashSet<String>,
    builtin_sets: &HashSet<String>,
    builtin_callables: &HashSet<String>,
) -> ResolveOutput {
    resolve_program_with_globals(
        program,
        schema,
        builtin_predicates,
        builtin_sets,
        builtin_callables,
        None,
    )
}

pub fn resolve_program_with_globals(
    program: &Program,
    schema: &SchemaRegistry,
    builtin_predicates: &HashSet<String>,
    builtin_sets: &HashSet<String>,
    builtin_callables: &HashSet<String>,
    global_symbols: Option<&SymbolTable>,
) -> ResolveOutput {
    // Resolver is intentionally a sidecar pass: it does not mutate AST,
    // it only classifies names/calls and emits diagnostics.
    let mut resolver = Resolver::new(
        schema,
        builtin_predicates,
        builtin_sets,
        builtin_callables,
        global_symbols,
    );
    resolver.collect_symbols(program);

    for rule in &program.rules {
        resolver.resolve_rule(rule);
    }

    ResolveOutput {
        symbols: resolver.symbols,
        external_refs: resolver.external_refs,
        calls: resolver.calls,
        diagnostics: resolver.diagnostics,
    }
}

#[derive(Debug)]
struct Resolver<'a> {
    // Typed schema loaded from stdlib schema.oil.
    schema: &'a SchemaRegistry,
    // Stage-0 prelude symbols available globally.
    builtin_predicates: &'a HashSet<String>,
    builtin_sets: &'a HashSet<String>,
    builtin_callables: &'a HashSet<String>,
    // Optional cross-file declarations from compile_many.
    global_symbols: Option<&'a SymbolTable>,
    // Symbols visible in the current resolution unit.
    symbols: SymbolTable,
    // Imported external refs (`intel.*`, `org.*`, ...).
    external_refs: Vec<ExternalRef>,
    // Every call expression seen in rules, with best-effort classification.
    calls: Vec<ResolvedCall>,
    // Non-fatal semantic diagnostics.
    diagnostics: Vec<ResolveDiagnostic>,
}

impl<'a> Resolver<'a> {
    fn new(
        schema: &'a SchemaRegistry,
        builtin_predicates: &'a HashSet<String>,
        builtin_sets: &'a HashSet<String>,
        builtin_callables: &'a HashSet<String>,
        global_symbols: Option<&'a SymbolTable>,
    ) -> Self {
        Self {
            schema,
            builtin_predicates,
            builtin_sets,
            builtin_callables,
            global_symbols,
            symbols: SymbolTable::default(),
            external_refs: Vec::new(),
            calls: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// Pass 1: build global declaration table.
    fn collect_symbols(&mut self, program: &Program) {
        // Imports register external namespaces/symbols that are treated as known.
        for import in &program.imports {
            if import.path.node.is_empty() {
                continue;
            }

            let full_path = import.path.node.join(".");
            let symbol = import
                .path
                .node
                .last()
                .cloned()
                .unwrap_or_else(|| full_path.clone());
            let namespace = import.path.node[0].clone();
            let source = classify_external_source(&namespace);

            self.symbols.external_namespaces.insert(namespace);
            self.symbols.external_symbols.insert(symbol.clone());
            self.external_refs.push(ExternalRef {
                source,
                full_path,
                symbol,
                span: import.path.span.clone(),
            });
        }

        // Local declarations.
        for set in &program.sets {
            if !self.symbols.sets.insert(set.name.node.clone()) {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!("duplicate set declaration: '{}'", set.name.node),
                    span: Some(set.name.span.clone()),
                });
            }
        }
        // Built-in stdlib sets are globally available.
        for set_name in self.builtin_sets {
            self.symbols.sets.insert(set_name.clone());
        }
        for pred in &program.predicates {
            if !self.symbols.predicates.insert(pred.name.node.clone()) {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!("duplicate predicate declaration: '{}'", pred.name.node),
                    span: Some(pred.name.span.clone()),
                });
            }
        }
        for fact in &program.facts {
            if !self.symbols.facts.insert(fact.name.node.clone()) {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!("duplicate fact declaration: '{}'", fact.name.node),
                    span: Some(fact.name.span.clone()),
                });
            }
        }
        // Local fact emissions should be visible in the same file.
        // This allows a file to emit+consume a fact without duplicate declarations.
        for rule in &program.rules {
            for emit in &rule.emit {
                self.symbols.facts.insert(emit.fact_name.node.clone());
            }
        }

        // Built-in stdlib predicates are globally available even when not
        // declared in the current compilation unit.
        for pred in self.builtin_predicates {
            self.symbols.predicates.insert(pred.clone());
        }

        // Global project symbols (from compile_many) are merged after local
        // collection so they do not trigger local duplicate diagnostics.
        if let Some(global) = self.global_symbols {
            self.symbols.sets.extend(global.sets.iter().cloned());
            self.symbols
                .predicates
                .extend(global.predicates.iter().cloned());
            self.symbols.facts.extend(global.facts.iter().cloned());
        }
    }

    /// Pass 2: resolve names used in rules against local scope + global table.
    fn resolve_rule(&mut self, rule: &RuleDecl) {
        let mut scope: HashSet<String> = HashSet::new();
        let mut alias_entity: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();

        // Source aliases are local bindings visible inside rule clauses.
        // We also record alias -> entity so path checks can use schema types.
        for src in &rule.sources {
            if let Some(alias) = &src.alias {
                scope.insert(alias.node.clone());
                if let Some(entity) = map_source_to_entity(&src.domain, &src.event) {
                    alias_entity.insert(alias.node.clone(), entity.to_string());
                }
            }
        }

        match &rule.body.node {
            RuleBody::Match(MatchBlock { steps }) => {
                for step in steps {
                    if let Some(alias) = &step.alias {
                        scope.insert(alias.node.clone());
                        if let Some(entity) =
                            map_event_to_entity(&step.event.node.domain, &step.event.node.kind)
                        {
                            alias_entity.insert(alias.node.clone(), entity.to_string());
                        }
                    }
                    if let Some(by) = &step.by {
                        scope.insert(by.node.clone());
                    }
                }
            }
            RuleBody::Correlate(c) => {
                for arm in &c.arms {
                    scope.insert(arm.alias.node.clone());
                    if let Some(entity) =
                        map_event_to_entity(&arm.event.node.domain, &arm.event.node.kind)
                    {
                        alias_entity.insert(arm.alias.node.clone(), entity.to_string());
                    }
                    if let crate::ast::CorrelateJoin::ByVariable(v) = &arm.join {
                        scope.insert(v.node.clone());
                    }
                    if let crate::ast::CorrelateJoin::OnPredicate(expr) = &arm.join {
                        self.resolve_expr(expr, &scope, &alias_entity);
                    }
                }
            }
            RuleBody::Graph(g) => {
                if let Some(alias) = &g.source.alias {
                    scope.insert(alias.node.clone());
                    if let Some(entity) = map_source_to_entity(&g.source.domain, &g.source.event) {
                        alias_entity.insert(alias.node.clone(), entity.to_string());
                    }
                }
                for pattern in &g.patterns {
                    scope.insert(pattern.alias.node.clone());
                    if let Some(entity) =
                        map_graph_entity_to_entity(self.schema, &pattern.entity_type)
                    {
                        alias_entity.insert(pattern.alias.node.clone(), entity);
                    }
                }
            }
            RuleBody::Around(a) => {
                for arm in &a.arms {
                    scope.insert(arm.alias.node.clone());
                    if let Some(entity) =
                        map_event_to_entity(&arm.event.node.domain, &arm.event.node.kind)
                    {
                        alias_entity.insert(arm.alias.node.clone(), entity.to_string());
                    }
                }
            }
        }

        // `score` can be referenced in respond conditions.
        scope.insert("score".to_string());

        if let Some(where_expr) = &rule.where_ {
            self.resolve_expr(where_expr, &scope, &alias_entity);
        }
        if let Some(req) = &rule.require {
            for requirement in &req.node.requirements {
                self.resolve_expr(requirement, &scope, &alias_entity);
            }
        }
        if let Some(verify) = &rule.verify {
            for requirement in &verify.requirements {
                let expr = Spanned::new(
                    Expr::Path(requirement.node.split('.').map(|s| s.to_string()).collect()),
                    requirement.span.clone(),
                );
                self.resolve_expr(&expr, &scope, &alias_entity);
            }
        }

        // Let bindings can refer to previous bindings; bind after resolving value.
        for binding in &rule.lets {
            self.resolve_expr(&binding.value, &scope, &alias_entity);
            scope.insert(binding.name.node.clone());
        }

        if let Some(score) = &rule.score {
            for modifier in &score.node.modifiers {
                if let Some(cond) = &modifier.condition {
                    self.resolve_expr(cond, &scope, &alias_entity);
                }
            }
        }

        for emit in &rule.emit {
            // Emit must target declared facts (or project/global discovered ones).
            if !self.symbols.facts.contains(&emit.fact_name.node) {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!(
                        "emitted fact '{}' is not declared in top-level facts",
                        emit.fact_name.node
                    ),
                    span: Some(emit.fact_name.span.clone()),
                });
            }
            for arg in &emit.args {
                self.resolve_expr(arg, &scope, &alias_entity);
            }
        }

        for arm in &rule.respond.node.arms {
            if let Some(cond) = &arm.condition {
                self.resolve_expr(cond, &scope, &alias_entity);
            }
            for action in &arm.actions {
                self.resolve_action(action, &scope, &alias_entity);
            }
        }
    }

    fn resolve_action(
        &mut self,
        action: &Spanned<ActionStmt>,
        scope: &HashSet<String>,
        alias_entity: &std::collections::BTreeMap<String, String>,
    ) {
        match &action.node {
            ActionStmt::Snapshot { targets, .. } => {
                for target in targets {
                    if target.node.contains('(') {
                        // Function-style snapshot selectors (e.g. process_tree(p))
                        // are action selectors, not identifier symbols.
                        continue;
                    }
                    self.resolve_name_like(&target.node, target.span.clone(), scope, alias_entity);
                }
            }
            // Isolate/Revoke are enum-like action selectors and should not be
            // treated as unresolved variable references.
            ActionStmt::Isolate { .. } | ActionStmt::Revoke { .. } => {}
            ActionStmt::RequireAuth { for_: target, .. }
            | ActionStmt::Quarantine { path: target }
            | ActionStmt::BlockEgress { target }
            | ActionStmt::Throttle { target } => {
                self.resolve_action_target(target, scope, alias_entity);
            }
            ActionStmt::Alert { .. }
            | ActionStmt::OpenCase { .. }
            | ActionStmt::Challenge { .. }
            | ActionStmt::Notify { .. } => {}
        }
    }

    fn resolve_action_target(
        &mut self,
        target: &Spanned<String>,
        scope: &HashSet<String>,
        alias_entity: &std::collections::BTreeMap<String, String>,
    ) {
        // Action targets are parsed as dotted-name strings. When dotted, resolve
        // them with the same root/path semantics as expression paths.
        if target.node.contains('.') {
            let parts: Vec<String> = target.node.split('.').map(|s| s.to_string()).collect();
            self.resolve_path_expr(&parts, target.span.clone(), scope, alias_entity);
            return;
        }

        self.resolve_name_like(&target.node, target.span.clone(), scope, alias_entity);
    }

    fn resolve_expr(
        &mut self,
        expr: &Spanned<Expr>,
        scope: &HashSet<String>,
        alias_entity: &std::collections::BTreeMap<String, String>,
    ) {
        match &expr.node {
            // Ident and Path are resolved differently:
            // - Ident: variable/set/external/root/builtin name lookup
            // - Path: schema-aware chain validation where possible
            Expr::Ident(name) => {
                self.resolve_name_like(name, expr.span.clone(), scope, alias_entity)
            }
            Expr::Path(parts) => {
                self.resolve_path_expr(parts, expr.span.clone(), scope, alias_entity)
            }
            // Member is currently produced for post-call chains
            // (e.g. host(id).baseline.domains). We recurse into base so call
            // resolution still runs; deeper member typing is handled in typecheck.
            Expr::Member { base, .. } => self.resolve_expr(base, scope, alias_entity),
            Expr::UnaryMinus(inner)
            | Expr::Not(inner)
            | Expr::Rare(inner)
            | Expr::Count(inner)
            | Expr::Max(inner)
            | Expr::Min(inner)
            | Expr::Sum(inner)
            | Expr::Avg(inner)
            | Expr::Distinct(inner) => self.resolve_expr(inner, scope, alias_entity),
            Expr::BinOp { lhs, rhs, .. }
            | Expr::And(lhs, rhs)
            | Expr::Or(lhs, rhs)
            | Expr::Cmp { lhs, rhs, .. }
            | Expr::In { lhs, rhs }
            | Expr::NotIn { lhs, rhs }
            | Expr::StartsWith { lhs, rhs }
            | Expr::EndsWith { lhs, rhs }
            | Expr::Contains { lhs, rhs }
            | Expr::Under {
                path: lhs,
                prefix: rhs,
            } => {
                self.resolve_expr(lhs, scope, alias_entity);
                self.resolve_expr(rhs, scope, alias_entity);
            }
            Expr::Matches { lhs, .. } => self.resolve_expr(lhs, scope, alias_entity),
            Expr::Between { val, lo, hi } => {
                self.resolve_expr(val, scope, alias_entity);
                self.resolve_expr(lo, scope, alias_entity);
                self.resolve_expr(hi, scope, alias_entity);
            }
            Expr::UnusualFor { val, .. } => self.resolve_expr(val, scope, alias_entity),
            Expr::Call { name, args } => {
                // Name-resolution classification:
                // fact call, predicate call, or unknown callable.
                let kind = if self.symbols.facts.contains(name) {
                    ResolvedCallKind::FactRef
                } else if self.symbols.predicates.contains(name) {
                    ResolvedCallKind::PredicateCall
                } else {
                    ResolvedCallKind::Unknown
                };

                self.calls.push(ResolvedCall {
                    name: name.clone(),
                    kind,
                    span: expr.span.clone(),
                });

                if kind == ResolvedCallKind::Unknown
                    && !is_builtin_call(name)
                    && !self.schema.is_root(name)
                    && !self.builtin_callables.contains(name)
                {
                    self.diagnostics.push(ResolveDiagnostic {
                        message: format!("unknown callable '{name}'"),
                        span: Some(expr.span.clone()),
                    });
                }

                for arg in args {
                    self.resolve_expr(arg, scope, alias_entity);
                }
            }
            Expr::List(items) => {
                for item in items {
                    self.resolve_expr(item, scope, alias_entity);
                }
            }
            Expr::StrLit(_)
            | Expr::IntLit(_)
            | Expr::FloatLit(_)
            | Expr::BoolLit(_)
            | Expr::DurationLit(_)
            | Expr::Null => {}
        }
    }

    fn resolve_path_expr(
        &mut self,
        parts: &[String],
        span: Span,
        scope: &HashSet<String>,
        alias_entity: &std::collections::BTreeMap<String, String>,
    ) {
        if parts.is_empty() {
            return;
        }

        let root = &parts[0];
        // If root is a bound alias or schema root, validate path by schema.
        if let Some(entity_name) = alias_entity
            .get(root)
            .cloned()
            .or_else(|| self.schema.roots.get(root).map(|r| r.entity.clone()))
        {
            self.validate_entity_path(parts, &entity_name, span);
            return;
        }

        // Otherwise fallback to generic name-like checks on the root symbol.
        self.resolve_name_like(root, span, scope, alias_entity);
    }

    fn validate_entity_path(&mut self, parts: &[String], start_entity: &str, span: Span) {
        let mut current_entity = start_entity.to_string();

        for (idx, seg) in parts.iter().enumerate().skip(1) {
            let Some(entity) = self.schema.entities.get(&current_entity) else {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!("unknown entity '{current_entity}'"),
                    span: Some(span.clone()),
                });
                return;
            };

            let Some(field) = entity.fields.get(seg) else {
                self.diagnostics.push(ResolveDiagnostic {
                    message: format!("unknown field '{seg}' on entity '{current_entity}'"),
                    span: Some(span.clone()),
                });
                return;
            };

            let is_last = idx == parts.len() - 1;
            match &field.ty {
                FieldType::Entity(next) => {
                    current_entity = next.clone();
                }
                FieldType::Nullable(inner) => match inner.as_ref() {
                    FieldType::Entity(next) => {
                        // Nullable entity deref is allowed in resolver; typecheck
                        // carries nullability through expression inference.
                        current_entity = next.clone();
                    }
                    _ => {
                        if !is_last {
                            self.diagnostics.push(ResolveDiagnostic {
                                message: format!(
                                    "invalid chain through non-entity field '{seg}' on '{current_entity}'"
                                ),
                                span: Some(span.clone()),
                            });
                            return;
                        }
                    }
                },
                FieldType::Primitive(_) | FieldType::Set(_) => {
                    if !is_last {
                        self.diagnostics.push(ResolveDiagnostic {
                            message: format!(
                                "invalid chain through non-entity field '{seg}' on '{current_entity}'"
                            ),
                            span: Some(span.clone()),
                        });
                    }
                    return;
                }
            }
        }
    }

    fn resolve_name_like(
        &mut self,
        name: &str,
        span: Span,
        scope: &HashSet<String>,
        alias_entity: &std::collections::BTreeMap<String, String>,
    ) {
        if scope.contains(name)
            || self.symbols.sets.contains(name)
            || self.symbols.external_symbols.contains(name)
            || self.symbols.external_namespaces.contains(name)
            || alias_entity.contains_key(name)
            || self.schema.is_root(name)
            || is_builtin_name(name)
        {
            return;
        }

        self.diagnostics.push(ResolveDiagnostic {
            message: format!("unknown identifier '{name}'"),
            span: Some(span),
        });
    }
}

fn is_builtin_call(name: &str) -> bool {
    matches!(name, "count" | "max" | "min" | "sum" | "avg" | "distinct")
}

fn is_builtin_name(name: &str) -> bool {
    // Runtime-provided roots and utility identifiers.
    matches!(name, "score")
}

fn classify_external_source(namespace: &str) -> ExternalSymbolSource {
    match namespace {
        "intel" => ExternalSymbolSource::Intel,
        "org" => ExternalSymbolSource::Org,
        _ => ExternalSymbolSource::Other,
    }
}

fn map_source_to_entity(domain: &str, event: &str) -> Option<&'static str> {
    match (domain, event) {
        ("endpoint", "process") => Some("Process"),
        ("endpoint", "file") => Some("FileEvent"),
        ("network", "flow") => Some("NetworkFlow"),
        ("container", "runtime") => Some("ContainerContext"),
        ("k8s", "workload") => Some("WorkloadInfo"),
        ("identity", "session") => Some("Session"),
        ("dns", "query") => Some("DnsQuery"),
        ("secure_connect", "session") => Some("SecureConnectSession"),
        ("secure_connect", "connect") => Some("SecureConnectSession"),
        ("secure_connect", "profile") => Some("SecureConnectProfile"),
        ("secure_connect", "gateway") => Some("SecureConnectGateway"),
        ("secure_connect", "peer") => Some("SecureConnectPeer"),
        ("db", "query") => Some("SqlEvent"),
        ("ssl", "event") => Some("SslEvent"),
        _ => None,
    }
}

fn map_event_to_entity(domain: &str, _kind: &str) -> Option<&'static str> {
    match (domain, _kind) {
        ("secure_connect", "profile") => Some("SecureConnectProfile"),
        ("secure_connect", "gateway") => Some("SecureConnectGateway"),
        ("secure_connect", "peer") => Some("SecureConnectPeer"),
        ("secure_connect", _) => Some("SecureConnectSession"),
        (domain, _) => match domain {
            "process" => Some("Process"),
            "file" => Some("FileEvent"),
            "network" => Some("NetworkFlow"),
            "container" => Some("ContainerContext"),
            "workload" => Some("WorkloadInfo"),
            "session" => Some("Session"),
            "dns" => Some("DnsQuery"),
            "db" => Some("SqlEvent"),
            "ssl" => Some("SslEvent"),
            _ => None,
        },
    }
}

fn map_graph_entity_to_entity(schema: &SchemaRegistry, entity_type: &str) -> Option<String> {
    if schema.entities.contains_key(entity_type) {
        return Some(entity_type.to_string());
    }
    map_event_to_entity(entity_type, entity_type).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;
    use crate::schema::parse_schema;
    use std::collections::HashSet;

    fn parse_program(src: &str) -> Program {
        let toks = Lexer::new(src).tokenize().expect("lex");
        let mut p = Parser::new(toks);
        p.parse().expect("parse")
    }

    #[test]
    fn external_import_symbol_resolves() {
        let program = parse_program(
            r#"
use intel.malicious_domains
rule "r" {
  from endpoint.process
  correlate process.exec as p
  where p.name in malicious_domains
  respond alert high
}
"#,
        );
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        let out = resolve_program_with_schema(
            &program,
            &schema,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(!out
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown identifier 'malicious_domains'")));
    }

    #[test]
    fn unknown_field_reports_schema_error() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.exec as p
  where p.nope == 1
  respond alert high
}
"#,
        );
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        let out = resolve_program_with_schema(
            &program,
            &schema,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(out.diagnostics.iter().any(|d| d
            .message
            .contains("unknown field 'nope' on entity 'Process'")));
    }

    #[test]
    fn nullable_entity_chain_does_not_emit_resolver_warning() {
        let program = parse_program(
            r#"
rule "r" {
  from endpoint.process
  correlate process.exec as p
  where p.parent.name == "bash"
  respond alert high
}
"#,
        );
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        let out = resolve_program_with_schema(
            &program,
            &schema,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.message.contains("invalid chain after nullable type")),
            "unexpected nullable-chain resolver diagnostic: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn graph_clause_aliases_resolve_in_where_predicate() {
        let program = parse_program(
            r#"
rule "graph_aliases" {
  graph endpoint.process as e {
    process as p,
    network as n -> connects_to
  }
  where e.pid > 0 and p.name == "bash" and n.dest.port > 0
  respond alert high
}
"#,
        );
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        let out = resolve_program_with_schema(
            &program,
            &schema,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.message.contains("unknown identifier")),
            "unexpected unknown-identifier diagnostics: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn around_clause_aliases_resolve_in_where_predicate() {
        let program = parse_program(
            r#"
rule "around_aliases" {
  around host.id within 5m {
    process.spawn as p,
    network.connect as n
  }
  where p.pid > 0 and n.dest.port > 0
  respond alert high
}
"#,
        );
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        let out = resolve_program_with_schema(
            &program,
            &schema,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
        );
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.message.contains("unknown identifier")),
            "unexpected unknown-identifier diagnostics: {:?}",
            out.diagnostics
        );
    }
}
