use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ops::Range;

use crate::ast::{CmpOp, Expr, Program, RuleBody, RuleDecl, Spanned};
use crate::schema::{FieldType, PrimitiveType, SchemaRegistry};

type Span = Range<usize>;

#[derive(Debug, Clone)]
pub struct TypeDiagnostic {
    pub message: String,
    pub span: Option<Span>,
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
    callable_signatures: &HashMap<String, String>,
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
    callable_signatures: &'a HashMap<String, String>,
    // Collected diagnostics for this compilation unit.
    diagnostics: Vec<TypeDiagnostic>,
}

impl<'a> Typechecker<'a> {
    fn check_rule(&mut self, rule: &RuleDecl) {
        // alias_entity maps rule aliases (p, n, c, ...) to schema entities.
        let mut alias_entity: BTreeMap<String, String> = BTreeMap::new();
        for src in &rule.sources {
            if let Some(alias) = &src.alias {
                if let Some(entity) = map_source_to_entity(&src.domain, &src.event) {
                    alias_entity.insert(alias.node.clone(), entity.to_string());
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
                    }
                    if let crate::ast::CorrelateJoin::OnPredicate(expr) = &arm.join {
                        let t = self.infer_expr(expr, &alias_entity);
                        self.expect_bool(&t, expr.span.clone(), "correlate join predicate");
                    }
                }
            }
            RuleBody::Graph(_) | RuleBody::Around(_) => {}
        }

        if let Some(where_expr) = &rule.where_ {
            let t = self.infer_expr(where_expr, &alias_entity);
            self.expect_bool(&t, where_expr.span.clone(), "where clause");
        }

        for binding in &rule.lets {
            let _ = self.infer_expr(&binding.value, &alias_entity);
        }

        if let Some(score) = &rule.score {
            for modifier in &score.node.modifiers {
                if let Some(cond) = &modifier.condition {
                    let t = self.infer_expr(cond, &alias_entity);
                    self.expect_bool(&t, cond.span.clone(), "score modifier condition");
                }
            }
        }

        for arm in &rule.respond.node.arms {
            if let Some(cond) = &arm.condition {
                let t = self.infer_expr(cond, &alias_entity);
                self.expect_bool(&t, cond.span.clone(), "respond condition");
            }
        }
    }

    fn infer_expr(&mut self, expr: &Spanned<Expr>, alias_entity: &BTreeMap<String, String>) -> Ty {
        match &expr.node {
            Expr::StrLit(_) => Ty::Str,
            Expr::IntLit(_) => Ty::Int,
            Expr::FloatLit(_) => Ty::Float,
            Expr::BoolLit(_) => Ty::Bool,
            Expr::DurationLit(_) => Ty::Duration,
            Expr::Null => Ty::Null,
            Expr::Ident(_) => Ty::Unknown,
            Expr::Path(parts) => self.infer_path(parts, alias_entity),
            Expr::Member { base, field } => {
                // Member access allows chains after calls:
                // host(id).baseline.domains
                let bt = self.infer_expr(base, alias_entity);
                self.infer_member_field(&bt, field, expr.span.clone())
            }
            Expr::UnaryMinus(inner) => {
                let t = self.infer_expr(inner, alias_entity);
                if !is_numeric(&t) && t != Ty::Unknown {
                    self.diag("unary '-' expects numeric operand", expr.span.clone());
                }
                if t == Ty::Float { Ty::Float } else { Ty::Int }
            }
            Expr::Not(inner) => {
                let t = self.infer_expr(inner, alias_entity);
                self.expect_bool(&t, inner.span.clone(), "not operand");
                Ty::Bool
            }
            Expr::And(lhs, rhs) | Expr::Or(lhs, rhs) => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);
                self.expect_bool(&lt, lhs.span.clone(), "boolean operand");
                self.expect_bool(&rt, rhs.span.clone(), "boolean operand");
                Ty::Bool
            }
            Expr::Cmp { op, lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);
                // Comparisons produce bool; compatibility determines warning emission.
                self.check_cmp_types(*op, &lt, &rt, expr.span.clone());
                Ty::Bool
            }
            Expr::In { lhs, rhs } | Expr::NotIn { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);
                self.check_membership_types(&lt, &rt, expr.span.clone());
                Ty::Bool
            }
            Expr::StartsWith { lhs, rhs } | Expr::EndsWith { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);
                self.expect_string_like(&lt, lhs.span.clone(), "string operator lhs");
                self.expect_string_like(&rt, rhs.span.clone(), "string operator rhs");
                Ty::Bool
            }
            Expr::Contains { lhs, rhs } => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);

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
                let lt = self.infer_expr(lhs, alias_entity);
                self.expect_string_like(&lt, lhs.span.clone(), "matches lhs");
                Ty::Bool
            }
            Expr::Under { path, prefix } => {
                let pt = self.infer_expr(path, alias_entity);
                let pr = self.infer_expr(prefix, alias_entity);
                self.expect_path_like(&pt, path.span.clone(), "under lhs");
                if !(is_path_like(&pr) || matches!(pr, Ty::Set(_) | Ty::List(_) | Ty::Unknown)) {
                    self.diag("under rhs expects path/string/list/set", prefix.span.clone());
                }
                Ty::Bool
            }
            Expr::Between { val, lo, hi } => {
                let vt = self.infer_expr(val, alias_entity);
                let lt = self.infer_expr(lo, alias_entity);
                let ht = self.infer_expr(hi, alias_entity);
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
                let _ = self.infer_expr(val, alias_entity);
                Ty::Bool
            }
            Expr::Rare(inner) => {
                let _ = self.infer_expr(inner, alias_entity);
                Ty::Bool
            }
            Expr::Count(inner) => {
                let _ = self.infer_expr(inner, alias_entity);
                Ty::Int
            }
            Expr::Max(inner) | Expr::Min(inner) | Expr::Sum(inner) | Expr::Avg(inner) => {
                let t = self.infer_expr(inner, alias_entity);
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
                let _ = self.infer_expr(inner, alias_entity);
                Ty::Unknown
            }
            Expr::Call { name, args } => {
                for a in args {
                    let _ = self.infer_expr(a, alias_entity);
                }
                // Minimal callable typing for now:
                // - count(...) -> Int
                // - root(entity_id) -> Entity(root target)
                // - others unknown until callable signatures are introduced
                if name == "count" {
                    Ty::Int
                } else if self.schema.roots.contains_key(name) {
                    Ty::Entity(self.schema.roots[name].entity.clone())
                } else if let Some(entity) = self.callable_signatures.get(name) {
                    // Use typed prelude call signatures when available.
                    Ty::Entity(entity.clone())
                } else {
                    Ty::Unknown
                }
            }
            Expr::List(items) => {
                if items.is_empty() {
                    Ty::List(Box::new(Ty::Unknown))
                } else {
                    let first = self.infer_expr(&items[0], alias_entity);
                    for item in &items[1..] {
                        let t = self.infer_expr(item, alias_entity);
                        if !type_compatible(&first, &t) && t != Ty::Unknown && first != Ty::Unknown {
                            self.diag("list elements have incompatible types", item.span.clone());
                        }
                    }
                    Ty::List(Box::new(first))
                }
            }
            Expr::BinOp { lhs, rhs, .. } => {
                let lt = self.infer_expr(lhs, alias_entity);
                let rt = self.infer_expr(rhs, alias_entity);
                if (!is_numeric(&lt) && lt != Ty::Unknown) || (!is_numeric(&rt) && rt != Ty::Unknown)
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

    fn infer_path(&mut self, parts: &[String], alias_entity: &BTreeMap<String, String>) -> Ty {
        if parts.is_empty() {
            return Ty::Unknown;
        }
        let root = &parts[0];
        let current = alias_entity
            .get(root)
            .cloned()
            .or_else(|| self.schema.roots.get(root).map(|r| r.entity.clone()));

        let Some(entity_name) = current else {
            return Ty::Unknown;
        };

        // Walk the full chain through schema definitions.
        let mut current_ty = Ty::Entity(entity_name);
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
        self.diagnostics.push(TypeDiagnostic {
            message: message.into(),
            span: Some(span),
        });
    }
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
        // In OIL rules, path constants are commonly expressed as string
        // literals, so Path and Str should be interoperable.
        (Ty::Path, Ty::Str) | (Ty::Str, Ty::Path) => true,
        _ => false,
    }
}

fn is_numeric(t: &Ty) -> bool {
    matches!(t, Ty::Int | Ty::Float)
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

fn map_source_to_entity(domain: &str, event: &str) -> Option<&'static str> {
    match (domain, event) {
        ("endpoint", "process") => Some("Process"),
        ("endpoint", "file") => Some("FileEvent"),
        ("network", "flow") => Some("NetworkFlow"),
        ("container", "runtime") => Some("ContainerContext"),
        ("k8s", "workload") => Some("WorkloadInfo"),
        ("identity", "session") => Some("Session"),
        ("dns", "query") => Some("DnsQuery"),
        _ => None,
    }
}

fn map_event_to_entity(domain: &str, _kind: &str) -> Option<&'static str> {
    match domain {
        "process" => Some("Process"),
        "file" => Some("FileEvent"),
        "network" => Some("NetworkFlow"),
        "container" => Some("ContainerContext"),
        "workload" => Some("WorkloadInfo"),
        "session" => Some("Session"),
        "dns" => Some("DnsQuery"),
        _ => None,
    }
}
