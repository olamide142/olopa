use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ops::Range;

use crate::ast::{CmpOp, Expr, Program, RuleBody, RuleDecl, Spanned};
use crate::prelude::{CallableSignature, CallableTypeRef};
use crate::schema::{FieldType, PrimitiveType, SchemaRegistry};

type Span = Range<usize>;

#[derive(Debug, Clone)]
pub struct TypeDiagnostic {
    pub kind: TypeDiagnosticKind,
    pub severity: TypeDiagnosticSeverity,
    pub message: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDiagnosticKind {
    BooleanContextMismatch,
    CallableContract,
    FieldAccessInvalid,
    OperatorTypeMismatch,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct TypecheckOutput {
    pub diagnostics: Vec<TypeDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ty {
    // Unknown means "not enough information yet"; checker should avoid
    // noisy hard errors in this case.
    Unknown,
    Null,
    Str,
    Int,
    Float,
    Bool,
    Duration,
    Path,
    IpAddr,
    Entity(String),
    Set(Box<Ty>),
    List(Box<Ty>),
    Nullable(Box<Ty>),
}

pub fn typecheck_program(
    program: &Program,
    schema: &SchemaRegistry,
    callable_signatures: &HashMap<String, CallableSignature>,
) -> TypecheckOutput {
    // Typechecker is non-fatal today: it emits diagnostics but does not fail compile.
    let mut tc = Typechecker {
        schema,
        callable_signatures,
        diagnostics: Vec::new(),
    };
    for rule in &program.rules {
        tc.check_rule(rule);
    }
    TypecheckOutput {
        diagnostics: tc.diagnostics,
    }
}

struct Typechecker<'a> {
    // Typed schema loaded at Stage-0.
    schema: &'a SchemaRegistry,
    // Callable return-type contracts loaded from stdlib prelude.
    callable_signatures: &'a HashMap<String, CallableSignature>,
    // Collected diagnostics for this compilation unit.
    diagnostics: Vec<TypeDiagnostic>,
}

impl<'a> Typechecker<'a> {
    fn check_rule(&mut self, rule: &RuleDecl) {
        // alias_entity maps rule aliases (p, n, c, ...) to schema entities.
        let mut alias_entity: BTreeMap<String, String> = BTreeMap::new();
        // value_scope tracks inferable value types for identifier expressions:
        // source aliases, rule-local let bindings, and synthetic names like score.
        let mut value_scope: BTreeMap<String, Ty> = BTreeMap::new();
        for src in &rule.sources {
            if let Some(alias) = &src.alias {
                if let Some(entity) = map_source_to_entity(&src.domain, &src.event) {
                    alias_entity.insert(alias.node.clone(), entity.to_string());
                    value_scope.insert(alias.node.clone(), Ty::Entity(entity.to_string()));
                }
            }
        }

        match &rule.body.node {
            RuleBody::Match(m) => {
                for step in &m.steps {
                    if let Some(alias) = &step.alias {
                        if let Some(entity) =
                            map_event_to_entity(&step.event.node.domain, &step.event.node.kind)
                        {
                            alias_entity.insert(alias.node.clone(), entity.to_string());
                            value_scope.insert(alias.node.clone(), Ty::Entity(entity.to_string()));
                        }
                    }
                }
            }
            RuleBody::Correlate(c) => {
                for arm in &c.arms {
                    if let Some(entity) =
                        map_event_to_entity(&arm.event.node.domain, &arm.event.node.kind)
                    {
                        alias_entity.insert(arm.alias.node.clone(), entity.to_string());
                        value_scope.insert(arm.alias.node.clone(), Ty::Entity(entity.to_string()));
                    }
                    if let crate::ast::CorrelateJoin::OnPredicate(expr) = &arm.join {
                        let t = self.infer_expr(expr, &alias_entity, &value_scope);
                        self.expect_bool(&t, expr.span.clone(), "correlate join predicate");
                    }
                }
            }
            RuleBody::Graph(g) => {
                if let Some(alias) = &g.source.alias {
                    if let Some(entity) = map_source_to_entity(&g.source.domain, &g.source.event) {
                        alias_entity.insert(alias.node.clone(), entity.to_string());
                        value_scope.insert(alias.node.clone(), Ty::Entity(entity.to_string()));
                    }
                }
                for pattern in &g.patterns {
                    if let Some(entity) =
                        map_graph_entity_to_entity(self.schema, &pattern.entity_type)
                    {
                        alias_entity.insert(pattern.alias.node.clone(), entity.clone());
                        value_scope.insert(pattern.alias.node.clone(), Ty::Entity(entity));
                    }
                }
            }
            RuleBody::Around(a) => {
                for arm in &a.arms {
                    if let Some(entity) =
                        map_event_to_entity(&arm.event.node.domain, &arm.event.node.kind)
                    {
                        alias_entity.insert(arm.alias.node.clone(), entity.to_string());
                        value_scope.insert(arm.alias.node.clone(), Ty::Entity(entity.to_string()));
                    }
                }
            }
        }

        if let Some(where_expr) = &rule.where_ {
            let t = self.infer_expr(where_expr, &alias_entity, &value_scope);
            self.expect_bool(&t, where_expr.span.clone(), "where clause");
        }
        if let Some(require) = &rule.require {
            for requirement in &require.node.requirements {
                let t = self.infer_expr(requirement, &alias_entity, &value_scope);
                self.expect_bool(&t, requirement.span.clone(), "require clause");
            }
        }

        for binding in &rule.lets {
            let binding_ty = self.infer_expr(&binding.value, &alias_entity, &value_scope);
            value_scope.insert(binding.name.node.clone(), binding_ty);
        }

        if let Some(score) = &rule.score {
            for modifier in &score.node.modifiers {
                if let Some(cond) = &modifier.condition {
                    let t = self.infer_expr(cond, &alias_entity, &value_scope);
                    self.expect_bool(&t, cond.span.clone(), "score modifier condition");
                }
            }
        }
        // score is available in respond branches as a numeric value.
        value_scope.insert("score".to_string(), Ty::Int);

        for arm in &rule.respond.node.arms {
            if let Some(cond) = &arm.condition {
                let t = self.infer_expr(cond, &alias_entity, &value_scope);
                self.expect_bool(&t, cond.span.clone(), "respond condition");
            }
        }
    }

    fn infer_expr(
        &mut self,
        expr: &Spanned<Expr>,
        alias_entity: &BTreeMap<String, String>,
        value_scope: &BTreeMap<String, Ty>,
    ) -> Ty {
        match &expr.node {
            Expr::StrLit(_) => Ty::Str,
            Expr::IntLit(_) => Ty::Int,
            Expr::FloatLit(_) => Ty::Float,
            Expr::BoolLit(_) => Ty::Bool,
            Expr::DurationLit(_) => Ty::Duration,
            Expr::Null => Ty::Null,
            Expr::Ident(name) => value_scope.get(name).cloned().unwrap_or(Ty::Unknown),
            Expr::Path(parts) => self.infer_path(parts, alias_entity, value_scope),
            Expr::Member { base, field } => {
                // Member access allows chains after calls:
                // host(id).baseline.domains
                let bt = self.infer_expr(base, alias_entity, value_scope);
                self.infer_member_field(&bt, field, expr.span.clone())
            }
            Expr::UnaryMinus(inner) => {
                let t = self.infer_expr(inner, alias_entity, value_scope);
                if !is_numeric(&t) && t != Ty::Unknown {
                    self.diag("unary '-' expects numeric operand", expr.span.clone());
                }
                if t == Ty::Float {
                    Ty::Float
                } else {
                    Ty::Int
                }
            }
            Expr::Not(inner) => {
                let t = self.infer_expr(inner, alias_entity, value_scope);
                self.expect_bool(&t, inner.span.clone(), "not operand");
                Ty::Bool
            }
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);
                self.expect_bool(&lt, lhs.span.clone(), "boolean operand");
                self.expect_bool(&rt, rhs.span.clone(), "boolean operand");
                Ty::Bool
            }
            Expr::Cmp { op, lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);
                // Comparisons produce bool; compatibility determines warning emission.
                self.check_cmp_types(*op, &lt, &rt, expr.span.clone());
                Ty::Bool
            }
            Expr::In { lhs, rhs } | Expr::NotIn { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);
                self.check_membership_types(&lt, &rt, expr.span.clone());
                Ty::Bool
            }
            Expr::StartsWith { lhs, rhs } | Expr::EndsWith { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);
                self.expect_string_like(&lt, lhs.span.clone(), "string operator lhs");
                self.expect_string_like(&rt, rhs.span.clone(), "string operator rhs");
                Ty::Bool
            }
            Expr::Contains { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);

                match &lt {
                    // Collection form: set/list contains element.
                    Ty::Set(inner) | Ty::List(inner) => {
                        if !type_compatible(inner, &rt) && rt != Ty::Unknown {
                            self.diag(
                                format!(
                                    "contains type mismatch: collection element={inner:?}, rhs={rt:?}"
                                ),
                                expr.span.clone(),
                            );
                        }
                    }
                    _ => {
                        // String/path substring form.
                        self.expect_string_like(&lt, lhs.span.clone(), "contains lhs");
                        self.expect_string_like(&rt, rhs.span.clone(), "contains rhs");
                    }
                }
                Ty::Bool
            }
            Expr::Matches { lhs, .. } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                self.expect_string_like(&lt, lhs.span.clone(), "matches lhs");
                Ty::Bool
            }
            Expr::Under { path, prefix } => {
                let pt = self.infer_expr(path, alias_entity, value_scope);
                let pr = self.infer_expr(prefix, alias_entity, value_scope);
                self.expect_path_like(&pt, path.span.clone(), "under lhs");
                if !(is_path_like(&pr) || matches!(pr, Ty::Set(_) | Ty::List(_) | Ty::Unknown)) {
                    self.diag(
                        "under rhs expects path/string/list/set",
                        prefix.span.clone(),
                    );
                }
                Ty::Bool
            }
            Expr::Between { val, lo, hi } => {
                let vt = self.infer_expr(val, alias_entity, value_scope);
                let lt = self.infer_expr(lo, alias_entity, value_scope);
                let ht = self.infer_expr(hi, alias_entity, value_scope);
                if !is_numeric(&vt) && vt != Ty::Unknown {
                    self.diag("between value must be numeric", val.span.clone());
                }
                if !is_numeric(&lt) && lt != Ty::Unknown {
                    self.diag("between lower bound must be numeric", lo.span.clone());
                }
                if !is_numeric(&ht) && ht != Ty::Unknown {
                    self.diag("between upper bound must be numeric", hi.span.clone());
                }
                Ty::Bool
            }
            Expr::UnusualFor { val, .. } => {
                let _ = self.infer_expr(val, alias_entity, value_scope);
                Ty::Bool
            }
            Expr::Rare(inner) => {
                let _ = self.infer_expr(inner, alias_entity, value_scope);
                Ty::Bool
            }
            Expr::Count(inner) => {
                let _ = self.infer_expr(inner, alias_entity, value_scope);
                Ty::Int
            }
            Expr::Max(inner) | Expr::Min(inner) | Expr::Sum(inner) | Expr::Avg(inner) => {
                let t = self.infer_expr(inner, alias_entity, value_scope);
                if !is_numeric(&t) && t != Ty::Unknown {
                    self.diag("aggregation expects numeric operand", inner.span.clone());
                }
                if matches!(expr.node, Expr::Avg(_)) {
                    Ty::Float
                } else {
                    t
                }
            }
            Expr::Distinct(inner) => {
                let _ = self.infer_expr(inner, alias_entity, value_scope);
                Ty::Unknown
            }
            Expr::Call { name, args } => {
                let mut arg_types = Vec::with_capacity(args.len());
                for a in args {
                    arg_types.push(self.infer_expr(a, alias_entity, value_scope));
                }
                // Minimal callable typing for now:
                // - count(...) -> Int
                // - root(entity_id) -> Entity(root target)
                // - others unknown until callable signatures are introduced
                if name == "count" {
                    Ty::Int
                } else if self.schema.roots.contains_key(name) {
                    if arg_types.len() != 1 {
                        self.diag(
                            format!(
                                "root callable '{}' expects exactly 1 argument, got {}",
                                name,
                                arg_types.len()
                            ),
                            expr.span.clone(),
                        );
                    }
                    if let Some(first_ty) = arg_types.first() {
                        if !is_root_lookup_key_ty(first_ty) && *first_ty != Ty::Unknown {
                            self.diag(
                                format!(
                                    "root callable '{}' expects string/path/ip/int lookup key, got {:?}",
                                    name, first_ty
                                ),
                                args[0].span.clone(),
                            );
                        }
                    }
                    if arg_types.len() > 1 {
                        for (idx, extra_arg) in args.iter().enumerate().skip(1) {
                            self.diag(
                                format!(
                                    "root callable '{}' does not accept argument #{}",
                                    name,
                                    idx + 1
                                ),
                                extra_arg.span.clone(),
                            );
                        }
                    }
                    Ty::Entity(self.schema.roots[name].entity.clone())
                } else if let Some(sig) = self.callable_signatures.get(name) {
                    if arg_types.len() != sig.params.len() {
                        self.diag(
                            format!(
                                "callable '{}' expects {} argument(s), got {}",
                                name,
                                sig.params.len(),
                                arg_types.len()
                            ),
                            expr.span.clone(),
                        );
                    }
                    if arg_types.len() < sig.params.len() {
                        let missing = sig.params[arg_types.len()..]
                            .iter()
                            .map(|p| p.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        self.diag(
                            format!(
                                "callable '{}' missing argument(s) for parameter(s): {}",
                                name, missing
                            ),
                            expr.span.clone(),
                        );
                    }
                    if arg_types.len() > sig.params.len() {
                        for (idx, extra_arg) in args.iter().enumerate().skip(sig.params.len()) {
                            self.diag(
                                format!("callable '{}' has unexpected argument #{}", name, idx + 1),
                                extra_arg.span.clone(),
                            );
                        }
                    }
                    let comparable_len = arg_types.len().min(sig.params.len());
                    for idx in 0..comparable_len {
                        let arg_ty = &arg_types[idx];
                        let param = &sig.params[idx];
                        if let Some(entity) =
                            unknown_entity_in_callable_type_ref(&param.ty, self.schema)
                        {
                            self.diag(
                                format!(
                                    "callable '{}' parameter '{}' references unknown entity type '{}'",
                                    name, param.name, entity
                                ),
                                expr.span.clone(),
                            );
                            continue;
                        }
                        let expected_ty = callable_type_ref_to_ty(&param.ty);
                        if !type_compatible(arg_ty, &expected_ty) && *arg_ty != Ty::Unknown {
                            self.diag(
                                format!(
                                    "callable '{}' argument '{}' expects {:?}, got {:?}",
                                    name, param.name, expected_ty, arg_ty
                                ),
                                args[idx].span.clone(),
                            );
                        }
                    }

                    if let Some(ret_ty) = &sig.returns {
                        if let Some(entity) =
                            unknown_entity_in_callable_type_ref(ret_ty, self.schema)
                        {
                            self.diag(
                                format!(
                                    "callable '{}' returns unknown entity type '{}'",
                                    name, entity
                                ),
                                expr.span.clone(),
                            );
                            Ty::Unknown
                        } else {
                            callable_type_ref_to_ty(ret_ty)
                        }
                    } else {
                        Ty::Unknown
                    }
                } else {
                    Ty::Unknown
                }
            }
            Expr::List(items) => {
                if items.is_empty() {
                    Ty::List(Box::new(Ty::Unknown))
                } else {
                    let first = self.infer_expr(&items[0], alias_entity, value_scope);
                    for item in &items[1..] {
                        let t = self.infer_expr(item, alias_entity, value_scope);
                        if !type_compatible(&first, &t) && t != Ty::Unknown && first != Ty::Unknown
                        {
                            self.diag("list elements have incompatible types", item.span.clone());
                        }
                    }
                    Ty::List(Box::new(first))
                }
            }
            Expr::BinOp { lhs, rhs, .. } => {
                let lt = self.infer_expr(lhs, alias_entity, value_scope);
                let rt = self.infer_expr(rhs, alias_entity, value_scope);
                if (!is_numeric(&lt) && lt != Ty::Unknown)
                    || (!is_numeric(&rt) && rt != Ty::Unknown)
                {
                    self.diag("arithmetic operands must be numeric", expr.span.clone());
                }
                if lt == Ty::Float || rt == Ty::Float {
                    Ty::Float
                } else {
                    Ty::Int
                }
            }
        }
    }

    fn infer_path(
        &mut self,
        parts: &[String],
        alias_entity: &BTreeMap<String, String>,
        value_scope: &BTreeMap<String, Ty>,
    ) -> Ty {
        if parts.is_empty() {
            return Ty::Unknown;
        }
        let root = &parts[0];
        let mut current_ty = if let Some(entity_name) = alias_entity
            .get(root)
            .cloned()
            .or_else(|| self.schema.roots.get(root).map(|r| r.entity.clone()))
        {
            Ty::Entity(entity_name)
        } else if let Some(scope_ty) = value_scope.get(root) {
            scope_ty.clone()
        } else {
            return Ty::Unknown;
        };

        // Walk the full chain through schema definitions (or let-bound entity
        // values, when the path root comes from value_scope).
        for field_name in parts.iter().skip(1) {
            current_ty = self.infer_member_field(&current_ty, field_name, 0..0);
        }

        current_ty
    }

    fn infer_member_field(&mut self, base: &Ty, field: &str, span: Span) -> Ty {
        match base {
            Ty::Entity(entity_name) => self.lookup_entity_field(entity_name, field),
            Ty::Nullable(inner) => {
                // Nullable entity deref keeps nullability in result type.
                let inner_ty = self.infer_member_field(inner, field, span.clone());
                if matches!(inner_ty, Ty::Unknown) {
                    Ty::Unknown
                } else {
                    Ty::Nullable(Box::new(inner_ty))
                }
            }
            Ty::Unknown => Ty::Unknown,
            _ => {
                if span.start != span.end {
                    self.diag(
                        format!("cannot access field '{field}' on non-entity type {base:?}"),
                        span,
                    );
                }
                Ty::Unknown
            }
        }
    }

    fn lookup_entity_field(&self, entity_name: &str, field: &str) -> Ty {
        let Some(entity) = self.schema.entities.get(entity_name) else {
            return Ty::Unknown;
        };
        let Some(field_schema) = entity.fields.get(field) else {
            return Ty::Unknown;
        };
        field_to_ty(&field_schema.ty)
    }

    fn check_cmp_types(&mut self, _op: CmpOp, lhs: &Ty, rhs: &Ty, span: Span) {
        // Avoid noisy diagnostics when either side is unknown or explicit null.
        if *lhs == Ty::Unknown || *rhs == Ty::Unknown || *lhs == Ty::Null || *rhs == Ty::Null {
            return;
        }
        if !type_compatible(lhs, rhs) {
            self.diag(
                format!("comparison type mismatch: lhs={lhs:?}, rhs={rhs:?}"),
                span,
            );
        }
    }

    fn check_membership_types(&mut self, lhs: &Ty, rhs: &Ty, span: Span) {
        if *lhs == Ty::Unknown || *rhs == Ty::Unknown {
            return;
        }
        match rhs {
            // Membership over set/list values.
            Ty::Set(inner) | Ty::List(inner) => {
                if !type_compatible(lhs, inner) {
                    self.diag(
                        format!("membership type mismatch: lhs={lhs:?}, rhs element={inner:?}"),
                        span,
                    );
                }
            }
            _ => self.diag("membership rhs must be set/list", span),
        }
    }

    fn expect_bool(&mut self, t: &Ty, span: Span, ctx: &str) {
        if *t != Ty::Bool && *t != Ty::Unknown {
            self.diag(format!("{ctx} expects bool, got {t:?}"), span);
        }
    }

    fn expect_string_like(&mut self, t: &Ty, span: Span, ctx: &str) {
        if !is_string_like(t) && *t != Ty::Unknown {
            self.diag(format!("{ctx} expects string/path, got {t:?}"), span);
        }
    }

    fn expect_path_like(&mut self, t: &Ty, span: Span, ctx: &str) {
        if !is_path_like(t) && *t != Ty::Unknown {
            self.diag(format!("{ctx} expects path/string, got {t:?}"), span);
        }
    }

    fn diag(&mut self, message: impl Into<String>, span: Span) {
        let message = message.into();
        let (kind, severity) = classify_type_diagnostic(&message);
        self.diagnostics.push(TypeDiagnostic {
            kind,
            severity,
            message,
            span: Some(span),
        });
    }
}

fn classify_type_diagnostic(message: &str) -> (TypeDiagnosticKind, TypeDiagnosticSeverity) {
    if message.contains("expects bool") {
        return (
            TypeDiagnosticKind::BooleanContextMismatch,
            TypeDiagnosticSeverity::Error,
        );
    }
    if message.contains("root callable")
        || (message.contains("callable '")
            && (message.contains("expects ")
                || message.contains("missing argument(s)")
                || message.contains("unexpected argument")
                || message.contains("argument '")
                || message.contains("parameter '")
                || message.contains("returns unknown entity type")))
    {
        return (
            TypeDiagnosticKind::CallableContract,
            TypeDiagnosticSeverity::Error,
        );
    }
    if message.contains("cannot access field") {
        return (
            TypeDiagnosticKind::FieldAccessInvalid,
            TypeDiagnosticSeverity::Error,
        );
    }
    if message.contains("type mismatch")
        || message.contains("expects numeric")
        || message.contains("expects string/path")
        || message.contains("expects path/string")
        || message.contains("membership rhs")
        || message.contains("arithmetic operands")
        || message.contains("list elements have incompatible types")
    {
        return (
            TypeDiagnosticKind::OperatorTypeMismatch,
            TypeDiagnosticSeverity::Warning,
        );
    }
    (TypeDiagnosticKind::Unknown, TypeDiagnosticSeverity::Warning)
}

fn field_to_ty(field: &FieldType) -> Ty {
    match field {
        FieldType::Primitive(p) => match p {
            PrimitiveType::Str => Ty::Str,
            PrimitiveType::Int => Ty::Int,
            PrimitiveType::Float => Ty::Float,
            PrimitiveType::Bool => Ty::Bool,
            PrimitiveType::Duration => Ty::Duration,
            PrimitiveType::Path => Ty::Path,
            PrimitiveType::IpAddr => Ty::IpAddr,
        },
        FieldType::Entity(e) => Ty::Entity(e.clone()),
        FieldType::Set(inner) => Ty::Set(Box::new(field_to_ty(inner))),
        FieldType::Nullable(inner) => Ty::Nullable(Box::new(field_to_ty(inner))),
    }
}

fn type_compatible(a: &Ty, b: &Ty) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        // Nullable wrappers are transparent for compatibility checks.
        (Ty::Nullable(x), y) => type_compatible(x, y),
        (x, Ty::Nullable(y)) => type_compatible(x, y),
        (Ty::Int, Ty::Float) | (Ty::Float, Ty::Int) => true,
        (Ty::Duration, Ty::Int)
        | (Ty::Int, Ty::Duration)
        | (Ty::Duration, Ty::Float)
        | (Ty::Float, Ty::Duration) => true,
        // In OIL rules, path constants are commonly expressed as string
        // literals, so Path and Str should be interoperable.
        (Ty::Path, Ty::Str) | (Ty::Str, Ty::Path) => true,
        _ => false,
    }
}

fn is_numeric(t: &Ty) -> bool {
    matches!(t, Ty::Int | Ty::Float | Ty::Duration)
}

fn is_string_like(t: &Ty) -> bool {
    match t {
        Ty::Str | Ty::Path => true,
        Ty::Nullable(inner) => is_string_like(inner),
        _ => false,
    }
}

fn is_path_like(t: &Ty) -> bool {
    match t {
        Ty::Path | Ty::Str => true,
        Ty::Nullable(inner) => is_path_like(inner),
        _ => false,
    }
}

fn is_root_lookup_key_ty(t: &Ty) -> bool {
    match t {
        Ty::Str | Ty::Path | Ty::IpAddr | Ty::Int => true,
        Ty::Nullable(inner) => is_root_lookup_key_ty(inner),
        _ => false,
    }
}

fn callable_type_ref_to_ty(t: &CallableTypeRef) -> Ty {
    match t {
        CallableTypeRef::Str => Ty::Str,
        CallableTypeRef::Int => Ty::Int,
        CallableTypeRef::Float => Ty::Float,
        CallableTypeRef::Bool => Ty::Bool,
        CallableTypeRef::Duration => Ty::Duration,
        CallableTypeRef::Path => Ty::Path,
        CallableTypeRef::IpAddr => Ty::IpAddr,
        CallableTypeRef::Entity(name) => Ty::Entity(name.clone()),
        CallableTypeRef::Set(inner) => Ty::Set(Box::new(callable_type_ref_to_ty(inner))),
        CallableTypeRef::Nullable(inner) => Ty::Nullable(Box::new(callable_type_ref_to_ty(inner))),
    }
}

fn unknown_entity_in_callable_type_ref(
    t: &CallableTypeRef,
    schema: &SchemaRegistry,
) -> Option<String> {
    match t {
        CallableTypeRef::Entity(name) => {
            if schema.entities.contains_key(name) {
                None
            } else {
                Some(name.clone())
            }
        }
        CallableTypeRef::Set(inner) | CallableTypeRef::Nullable(inner) => {
            unknown_entity_in_callable_type_ref(inner, schema)
        }
        CallableTypeRef::Str
        | CallableTypeRef::Int
        | CallableTypeRef::Float
        | CallableTypeRef::Bool
        | CallableTypeRef::Duration
        | CallableTypeRef::Path
        | CallableTypeRef::IpAddr => None,
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

    fn typecheck_source(src: &str) -> TypecheckOutput {
        typecheck_source_with_callables(src, HashMap::new())
    }

    fn typecheck_source_with_callables(
        src: &str,
        callables: HashMap<String, CallableSignature>,
    ) -> TypecheckOutput {
        let tokens = Lexer::new(src).tokenize().expect("lex");
        let mut parser = Parser::new(tokens);
        let program = parser.parse().expect("parse");
        let schema = parse_schema(include_str!("../oil_stdlib/src/schema.oil")).expect("schema");
        typecheck_program(&program, &schema, &callables)
    }

    #[test]
    fn let_bound_int_is_checked_in_respond_condition() {
        let out = typecheck_source(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p

  let
    threshold = 1

  respond
    if threshold {
      alert high
    } else {
      alert low
    }
}
"#,
        );

        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.message.contains("respond condition expects bool")),
            "expected bool-mismatch diagnostic for int let binding, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn let_bound_bool_is_accepted_in_respond_condition() {
        let out = typecheck_source(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p

  let
    is_root = p.uid == 0

  respond
    if is_root {
      alert high
    } else {
      alert low
    }
}
"#,
        );

        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.message.contains("respond condition expects bool")),
            "did not expect bool-mismatch diagnostic, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn around_clause_aliases_participate_in_type_inference() {
        let out = typecheck_source(
            r#"
rule "around_typed_alias" {
  around host.id within 5m {
    process.spawn as p
  }
  where p.pid starts_with "1"
  respond alert high
}
"#,
        );

        assert!(
            out.diagnostics.iter().any(|d| d
                .message
                .contains("string operator lhs expects string/path")),
            "expected starts_with type diagnostic from around alias field typing, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn graph_clause_aliases_participate_in_type_inference() {
        let out = typecheck_source(
            r#"
rule "graph_typed_alias" {
  graph endpoint.process as e {
    process as p
  }
  where p.pid starts_with "1"
  respond alert high
}
"#,
        );

        assert!(
            out.diagnostics.iter().any(|d| d
                .message
                .contains("string operator lhs expects string/path")),
            "expected starts_with type diagnostic from graph alias field typing, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn root_callable_enforces_single_lookup_arg() {
        let out = typecheck_source(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where host() != null
  respond alert high
}
"#,
        );

        assert!(
            out.diagnostics.iter().any(|d| d
                .message
                .contains("root callable 'host' expects exactly 1 argument")),
            "expected root callable arity diagnostic, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn callable_return_type_must_exist_in_schema() {
        let mut callables = HashMap::new();
        callables.insert(
            "baseline.image".to_string(),
            CallableSignature {
                params: vec![crate::prelude::CallableParam {
                    name: "image_id".to_string(),
                    ty: CallableTypeRef::Str,
                }],
                returns: Some(CallableTypeRef::Entity("NotAnEntity".to_string())),
            },
        );
        let out = typecheck_source_with_callables(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.image(p.name).allowed_processes contains "bash"
  respond alert high
}
"#,
            callables,
        );

        assert!(
            out.diagnostics.iter().any(|d| d
                .message
                .contains("returns unknown entity type 'NotAnEntity'")),
            "expected callable return-type diagnostic, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn callable_argument_arity_and_type_are_checked() {
        let mut callables = HashMap::new();
        callables.insert(
            "baseline.workload".to_string(),
            CallableSignature {
                params: vec![
                    crate::prelude::CallableParam {
                        name: "namespace".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                    crate::prelude::CallableParam {
                        name: "name".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                ],
                returns: Some(CallableTypeRef::Entity("BaselineProfile".to_string())),
            },
        );

        let out = typecheck_source_with_callables(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.workload(1).allowed_processes contains "bash"
  respond alert high
}
"#,
            callables,
        );

        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.message.contains("expects 2 argument(s), got 1")),
            "expected callable arity diagnostic, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn callable_argument_type_diagnostic_points_to_argument_span() {
        let mut callables = HashMap::new();
        callables.insert(
            "baseline.workload".to_string(),
            CallableSignature {
                params: vec![
                    crate::prelude::CallableParam {
                        name: "namespace".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                    crate::prelude::CallableParam {
                        name: "name".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                ],
                returns: Some(CallableTypeRef::Entity("BaselineProfile".to_string())),
            },
        );

        let src = r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.workload(111, p.name).allowed_processes contains "bash"
  respond alert high
}
"#;
        let out = typecheck_source_with_callables(src, callables);
        let literal_pos = src.find("111").expect("literal position");
        let diag = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("argument 'namespace' expects Str"))
            .expect("type mismatch diagnostic");
        let span = diag.span.as_ref().expect("diagnostic span");
        assert_eq!(span.start, literal_pos);
    }

    #[test]
    fn callable_can_return_non_entity_types() {
        let mut callables = HashMap::new();
        callables.insert(
            "intel.domains".to_string(),
            CallableSignature {
                params: vec![crate::prelude::CallableParam {
                    name: "feed".to_string(),
                    ty: CallableTypeRef::Str,
                }],
                returns: Some(CallableTypeRef::Set(Box::new(CallableTypeRef::Str))),
            },
        );

        let out = typecheck_source_with_callables(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where p.name in intel.domains("prod")
  respond alert high
}
"#,
            callables,
        );

        assert!(
            out.diagnostics.is_empty(),
            "did not expect diagnostics for Set<Str> callable return, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn callable_arity_mismatch_still_checks_overlapping_argument_types() {
        let mut callables = HashMap::new();
        callables.insert(
            "baseline.workload".to_string(),
            CallableSignature {
                params: vec![
                    crate::prelude::CallableParam {
                        name: "namespace".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                    crate::prelude::CallableParam {
                        name: "name".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                ],
                returns: Some(CallableTypeRef::Entity("BaselineProfile".to_string())),
            },
        );

        let out = typecheck_source_with_callables(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.workload(123).allowed_processes contains "bash"
  respond alert high
}
"#,
            callables,
        );

        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.message.contains("expects 2 argument(s), got 1")),
            "expected callable arity diagnostic, got: {:?}",
            out.diagnostics
        );
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.message.contains("argument 'namespace' expects Str")),
            "expected callable argument-type diagnostic even with arity mismatch, got: {:?}",
            out.diagnostics
        );
    }

    #[test]
    fn callable_missing_and_extra_arguments_are_reported() {
        let mut callables = HashMap::new();
        callables.insert(
            "baseline.workload".to_string(),
            CallableSignature {
                params: vec![
                    crate::prelude::CallableParam {
                        name: "namespace".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                    crate::prelude::CallableParam {
                        name: "name".to_string(),
                        ty: CallableTypeRef::Str,
                    },
                ],
                returns: Some(CallableTypeRef::Entity("BaselineProfile".to_string())),
            },
        );

        let out_missing = typecheck_source_with_callables(
            r#"
rule "r1" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.workload("prod").allowed_processes contains "bash"
  respond alert high
}
"#,
            callables.clone(),
        );
        assert!(
            out_missing.diagnostics.iter().any(|d| d
                .message
                .contains("missing argument(s) for parameter(s): name")),
            "expected missing-parameter diagnostic, got: {:?}",
            out_missing.diagnostics
        );

        let out_extra = typecheck_source_with_callables(
            r#"
rule "r2" {
  from endpoint.process
  correlate process.spawn as p
  where baseline.workload("prod", p.name, "extra").allowed_processes contains "bash"
  respond alert high
}
"#,
            callables,
        );
        assert!(
            out_extra
                .diagnostics
                .iter()
                .any(|d| d.message.contains("unexpected argument #3")),
            "expected extra-argument diagnostic, got: {:?}",
            out_extra.diagnostics
        );
    }

    #[test]
    fn bool_context_mismatch_is_classified_as_error() {
        let out = typecheck_source(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  respond if 1 { alert high } else { alert low }
}
"#,
        );

        let diag = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("respond condition expects bool"))
            .expect("expected bool context diagnostic");
        assert_eq!(diag.severity, TypeDiagnosticSeverity::Error);
        assert_eq!(diag.kind, TypeDiagnosticKind::BooleanContextMismatch);
    }

    #[test]
    fn operator_type_mismatch_is_classified_as_warning() {
        let out = typecheck_source(
            r#"
rule "r" {
  from endpoint.process
  correlate process.spawn as p
  where p.pid in 1
  respond alert high
}
"#,
        );

        let diag = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("membership rhs must be set/list"))
            .expect("expected membership diagnostic");
        assert_eq!(diag.severity, TypeDiagnosticSeverity::Warning);
        assert_eq!(diag.kind, TypeDiagnosticKind::OperatorTypeMismatch);
    }
}
