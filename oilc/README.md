text → tokens → AST → typed AST → MIR → output (.so / Cypher / Rust)

Current bootstrap status:
- `src/main.rs` reads an `.oil` source file and runs lexical analysis.
- `src/lexer/mod.rs` emits tokens (including durations like `15m`) plus spans.
- Parser/type/MIR/codegen layers are still in-progress.
- Implemented grammar reference: `docs/grammar.md` (tracks parser behavior in code).



OLOPA
Intent Language
OIL — Formal Language Specification
Grammar · AST Design · Compiler Architecture · Runtime Integration
Version
1.0 — Foundation Specification
Status
Engineering CONFIDENTIAL
Platform
Olopa Security Agent v2–5
Language
OIL — Olopa Intent Language
Compiler
Rust  ·  LALR(1) parser  ·  MIR codegen
Runtime
Tokio async  ·  eBPF hot path  ·  Memgraph



1. Vision & Design Philosophy
OIL (Olopa Intent Language) is a declarative, intent-driven security programming language designed as the unified policy and detection surface for the entire Olopa platform. It replaces four previously separate concerns — event filtering (Falco-style), graph correlation (Cypher), risk scoring (custom code), and response actions (manual playbooks) — with a single, coherent language that compiles to Olopa's multi-engine runtime.

The central design thesis: security engineers should express what they mean, not how the runtime should execute it. The compiler's job is to translate intent into an optimal execution plan across eBPF probes, the CSR graph engine, the Memgraph Cypher layer, and the GNN inference service.

1.1  The Five Language Pillars

Pillar
What it enables
Prior art replaced
Runtime target
Event filtering
Single-event detection with typed fields and semantic operators
Falco rule DSL
eBPF EPL compiled .so
Temporal correlation
Multi-step chains with ordering and time windows
SIEM correlation rules / EQL
Stream window engine
Graph traversal
Multi-hop structural pattern matching
Cypher / manual graph queries
Memgraph + CSR engine
Risk scoring
Composable weighted scoring with derived variables
Hand-coded thresholds
Compiled score function
Response & policy
Branching enforcement actions with adaptive escalation
Playbook YAML + code
Action executor / OPA


1.2  What OIL Is Not
Not a query language — rules are programs, not questions.
Not configuration YAML — OIL has a proper grammar, type system, and compiler.
Not a scripting language — execution is compiled and sandboxed, not interpreted.
Not Rego/OPA — OPA handles allow/deny; OIL handles temporal correlation, graph traversal, and scoring in the same syntax.

1.3  Language Design Goals


Performance Contract
Known-TTP rules compiled to EPL .so: ≤ 20ns evaluation per event on hot path.
Graph pattern queries fire as Memgraph event-driven triggers: ≤ 100ms from write to match.
Cross-engine fused alerts: ≤ 500ms end-to-end from kernel event to actionable alert.





Safety Contract
All OIL programs are statically type-checked before deployment.
Temporal windows are bounded — no unbounded state accumulation.
Response actions require explicit capability grants in the rule manifest.
Rules cannot access arbitrary system resources — only declared sources.



2. Lexical Structure
The OIL lexer operates on UTF-8 encoded source text. Whitespace (spaces, tabs, newlines) is insignificant except as a token separator. The lexer is whitespace-insensitive but indentation-aware for readability conventions.

2.1  Token Kinds

Token Kind
Examples / Pattern
KEYWORD
rule  policy  predicate  set  fact  use  from  match  where  within  let  score  emit  respond  enforce  correlate  with  on  by  then  and  or  not  in  not_in  starts_with  ends_with  contains  matches  under  between  require  verify  source  around  over  gather  at_least  any  all  emit  snapshot  expires  base  if  else
IDENT
[a-zA-Z_][a-zA-Z0-9_.]*   (e.g. process.name, user.baseline.countries)
STRING_LIT
"..."  with escape sequences  \"  \n  \t  \\
INT_LIT
[0-9]+  or  0x[0-9a-fA-F]+
FLOAT_LIT
[0-9]+\.[0-9]+  (e.g. 4.3, 0.01, 0.72)
DURATION_LIT
[0-9]+(ns|us|ms|s|m|h|d)  (e.g. 15m, 300s, 24h, 7d)
REGEX_LIT
/[^/]*/[imsg]*  (e.g. /^admin\//)
LIST_START / LIST_END
[   ]
BLOCK_START / BLOCK_END
{   }
PAREN_START / PAREN_END
(   )
ARROW
->
FAT_ARROW
=>
RANGE
..
ASSIGN
=
EQ
==
NEQ
!=
LT / GT / LTE / GTE
<  >  <=  >=
PLUS / MINUS / STAR / SLASH
+  -  *  /
COMMA
,
COLON
:
SEMICOLON
;
AT
@  (attribute prefix)
HASH
#  (comment start — line comment)
DOUBLE_SLASH
//  (alt comment start)
BLOCK_COMMENT
/* ... */


2.2  Reserved Words
The following identifiers are reserved and cannot be used as variable names. They are case-sensitive; OIL is a case-sensitive language.

  // OIL Reserved Words — olopa_intent_language/src/lexer/keywords.rs
// Structural keywords
rule    policy    predicate    template    set    fact    use    import


// Clause keywords
from    source    match    correlate    where    within    around    over
let     score     emit      respond     enforce   verify    require   gather
with    on        by        then        at_least  any       all       window


// Expression keywords
and     or        not       in          not_in    starts_with  ends_with
contains  matches  under    between     unusual_for  rare


// Literal keywords
true    false    null


// Action keywords
alert   isolate  revoke   snapshot   open_case   challenge   block
quarantine  require_mfa  notify   throttle   annotate   redirect


// Fact lifecycle
expires


// Severity levels
critical  high  medium  low  informational



2.3  Identifier Paths
OIL uses dot-separated paths to reference event fields, entity attributes, and contextual functions. A path like process.parent.name is a first-class syntactic construct — not string manipulation. The compiler resolves paths against a typed schema at compile time, producing a hard error for unknown fields.

  // Path examples
// Path resolution examples
process.name             // field access: process entity, name attribute
process.parent.name      // nested path: parent process name
user.baseline.countries  // user entity, baseline sub-object, countries set
host(p.host_id).risk     // function call returning typed entity
user(a.user_id).session  // parameterized lookup returning User entity
proc.prevalence.global   // compound field: global prevalence score
session.age              // computed field: duration since session start



3. Formal Grammar — EBNF
The following grammar is specified in Extended Backus-Naur Form (EBNF). The OIL parser is an LALR(1) parser generated from this grammar. Terminals are written in UPPER_CASE or as quoted strings. Non-terminals are in lower_case. Optional elements are enclosed in [ ]. Repetition is denoted with { }. Alternatives are separated by |.

3.1  Top-Level Program
  // Grammar — Top Level
program            ::= { import_decl | set_decl | predicate_decl
                        | template_decl | fact_decl | rule_decl | policy_decl }


import_decl        ::= "use" path_expr NEWLINE


path_expr          ::= IDENT { "." IDENT }



3.2  Declarations
  // Grammar — Declarations
// ─── Set Declaration ───────────────────────────────────────────────────
set_decl           ::= "set" IDENT "=" list_expr


list_expr          ::= "[" [ expr { "," expr } ] "]"




// ─── Predicate Declaration ─────────────────────────────────────────────
predicate_decl     ::= "predicate" IDENT "(" param_list ")" "=" bool_expr


param_list         ::= [ IDENT { "," IDENT } ]




// ─── Template Declaration ──────────────────────────────────────────────
template_decl      ::= "template" IDENT "(" param_list ")" "{" match_clause where_clause "}"




// ─── Fact Declaration ──────────────────────────────────────────────────
fact_decl          ::= "fact" IDENT "(" param_list ")" [ "expires" duration_lit ]




// ─── Meta Block ────────────────────────────────────────────────────────
meta_block         ::= "meta" "{" { IDENT "=" (STRING_LIT | list_expr) } "}"



3.3  Rule Declaration
  // Grammar — Rule Declaration
rule_decl          ::= [ meta_block ]
                       "rule" STRING_LIT "{"
                           [ from_clause ]
                           ( match_block | correlate_block | graph_block | around_block )
                           [ where_clause ]
                           [ within_clause ]
                           [ require_clause ]
                           [ let_clause ]
                           [ score_clause ]
                           [ verify_clause ]
                           [ emit_clause ]
                           respond_clause
                       "}"




// ─── From Clause (Source Declaration) ──────────────────────────────────
from_clause        ::= "from" source_spec { "," source_spec }
                     | "source" source_spec { "," source_spec }


source_spec        ::= domain_path [ "as" IDENT ]


domain_path        ::= IDENT "." IDENT    // e.g. endpoint.process, identity.session




// ─── Match Block (Single-Stream) ────────────────────────────────────────
match_block        ::= "match" match_expr { "then" match_expr }


match_expr         ::= event_pattern [ "as" IDENT ] [ "by" IDENT ]


event_pattern      ::= domain_path    // e.g. process.exec, file.write, dns.query




// ─── Correlate Block (Multi-Stream) ─────────────────────────────────────
correlate_block    ::= "correlate" [ "any" | "all" ]
                           correlate_arm { "with" correlate_arm }


correlate_arm      ::= event_pattern "as" IDENT [ "by" correlate_join ]
                     | event_pattern "as" IDENT "on" join_pred


correlate_join     ::= IDENT    // shared entity variable
                     | "(" IDENT { "," IDENT } ")"


join_pred          ::= bool_expr




// ─── Graph Block (Structural Pattern) ───────────────────────────────────
graph_block        ::= "graph" domain_path
                       "match" graph_pattern { "->" graph_pattern }


graph_pattern      ::= "node" IDENT "as" IDENT
                     | entity_type "as" IDENT
                     | event_pattern "as" IDENT


entity_type        ::= IDENT    // Process, File, NetworkEndpoint, User, etc.




// ─── Around Block (Entity-Anchored) ─────────────────────────────────────
around_block       ::= "around" IDENT "over" duration_lit
                       "gather" gather_arm { gather_arm }


gather_arm         ::= event_pattern "as" IDENT



3.4  Clauses
  // Grammar — Clauses
// ─── Where Clause ──────────────────────────────────────────────────────
where_clause       ::= "where" bool_expr { bool_expr }




// ─── Within Clause (Time Window) ────────────────────────────────────────
within_clause      ::= "within" duration_lit




// ─── Require Clause ─────────────────────────────────────────────────────
require_clause     ::= "require" require_expr { "and" require_expr }


require_expr       ::= "count" "(" IDENT ")" cmp_op INT_LIT
                     | "at_least" INT_LIT "signals"
                     | IDENT    // fact name




// ─── Let Clause ────────────────────────────────────────────────────────
let_clause         ::= "let" { let_binding }


let_binding        ::= IDENT "=" expr




// ─── Score Clause ──────────────────────────────────────────────────────
score_clause       ::= "score" score_expr { score_modifier }


score_expr         ::= INT_LIT
                     | "base" INT_LIT
                     | FLOAT_LIT


score_modifier     ::= "+" INT_LIT "if" bool_expr
                     | "-" INT_LIT "if" bool_expr
                     | "+" IDENT           // add named variable
                     | "*" FLOAT_LIT "if" bool_expr




// ─── Verify Clause ──────────────────────────────────────────────────────
verify_clause      ::= "verify" { "require" path_expr }




// ─── Emit Clause ────────────────────────────────────────────────────────
emit_clause        ::= "emit" { "fact" IDENT "(" expr_list ")" [ "expires" duration_lit ] }




// ─── Respond Clause ─────────────────────────────────────────────────────
respond_clause     ::= "respond" "{" respond_body "}"
                     | "respond" respond_body


respond_body       ::= respond_arm { respond_arm }


respond_arm        ::= "if" bool_expr "{" action_list "}"
                     | "else" "if" bool_expr "{" action_list "}"
                     | "else" "{" action_list "}"
                     | action_list




// ─── Policy Declaration ──────────────────────────────────────────────────
policy_decl        ::= [ meta_block ]
                       "policy" STRING_LIT "{"
                           from_clause
                           "when" event_pattern "as" IDENT
                           "where" bool_expr
                           "evaluate" { score_modifier }
                           "enforce" enforce_block
                       "}"


enforce_block      ::= { enforce_arm }
enforce_arm        ::= "allow" "if" bool_expr
                     | "challenge" action_name "if" bool_expr
                     | "block" "if" bool_expr
                     | "require" action_name "if" bool_expr
                     | severity_action "if" bool_expr



3.5  Expressions
  // Grammar — Expressions
// ─── Boolean Expressions ─────────────────────────────────────────────────
bool_expr          ::= bool_term { "or" bool_term }


bool_term          ::= bool_factor { "and" bool_factor }


bool_factor        ::= "not" bool_factor
                     | "(" bool_expr ")"
                     | comparison_expr
                     | membership_expr
                     | call_expr       // predicate call
                     | IDENT           // fact reference (bool context)




// ─── Comparison ─────────────────────────────────────────────────────────
comparison_expr    ::= expr cmp_op expr


cmp_op             ::= "==" | "!=" | "<" | ">" | "<=" | ">="




// ─── Membership & String Operators ───────────────────────────────────────
membership_expr    ::= expr "in" expr
                     | expr "not_in" expr
                     | expr "not" "in" expr
                     | expr "starts_with" expr
                     | expr "ends_with" expr
                     | expr "contains" expr
                     | expr "matches" REGEX_LIT
                     | expr "under" expr     // path prefix match
                     | expr "between" expr ".." expr
                     | expr "unusual_for" IDENT   // ML-assisted baseline check
                     | expr "rare"               // global rarity < 1%




// ─── Arithmetic ─────────────────────────────────────────────────────────
expr               ::= term { ("+" | "-") term }


term               ::= factor { ("*" | "/") factor }


factor             ::= "-" factor
                     | "(" expr ")"
                     | call_expr
                     | path_expr
                     | literal




// ─── Calls & Lookups ─────────────────────────────────────────────────────
call_expr          ::= IDENT "(" [ expr_list ] ")"
                     | IDENT "(" expr_list ")" "." IDENT    // method call


expr_list          ::= expr { "," expr }




// ─── Literals ────────────────────────────────────────────────────────────
literal            ::= STRING_LIT | INT_LIT | FLOAT_LIT | duration_lit
                     | IDENT         // set name or enum value
                     | "true" | "false" | "null"


duration_lit       ::= INT_LIT ("ns" | "us" | "ms" | "s" | "m" | "h" | "d")



3.6  Actions
  // Grammar — Actions
action_list        ::= action_stmt { "," action_stmt }
                     | action_stmt { NEWLINE action_stmt }


action_stmt        ::= "alert" severity_level
                     | "alert" severity_level STRING_LIT
                     | "isolate" ("host" | "network" | "process") IDENT
                     | "revoke" ("session" | "token" | "credential") IDENT
                     | "snapshot" IDENT { "," IDENT }
                     | "snapshot" "attack_graph"
                     | "snapshot" "host_timeline"
                     | "snapshot" "process_tree" "(" IDENT ")"
                     | "open_case" STRING_LIT
                     | "challenge" "mfa"
                     | "require" "reauthentication" "for" IDENT
                     | "require" "step_up_auth" "for" IDENT
                     | "quarantine" "file" path_expr
                     | "block" "egress" IDENT
                     | "notify" STRING_LIT
                     | "throttle" IDENT
                     | "annotate" IDENT STRING_LIT


severity_level     ::= "critical" | "high" | "medium" | "low" | "informational"


action_name        ::= "mfa" | "browser_reauth" | "step_up" | "approval"



4. Type System
OIL uses a structural, gradual type system. All event field paths are resolved against a global schema at compile time. Mismatched comparisons (e.g. comparing a duration to a string) are hard compile errors. The type system is designed to be helpful, not pedantic — it uses inference widely and requires explicit annotations only at declaration boundaries.

4.1  Primitive Types

Type
Description & examples
Str
UTF-8 string. Used for process names, paths, domains. Interned to integer IDs at eBPF layer.
Int
Signed 64-bit integer. UIDs, ports, byte counts, counters.
Float
64-bit float. Risk scores, entropy values, percentages.
Bool
true or false. Flags, binary attributes.
Duration
Typed time value: 15m, 300s, 24h, 7d. Compared to session.age, delta fields.
IpAddr
IPv4 or IPv6 address. Supports prefix operations like is_internal, geo lookups.
Regex
Compiled regular expression. Used with matches operator.
Set<T>
Unique set of T. Used for in / not_in membership. Named sets are singleton symbols.
List<T>
Ordered list of T. Used in gather / correlate result accumulation.
Path
Filesystem path. Supports under (prefix match) and sensitivity_label lookup.
Fact
A named boolean runtime assertion with optional expiry. Emitted by rules, consumed by others.
Entity<K>
A typed graph node: Process, User, Host, File, NetworkEndpoint, Secret, Container.
EventStream<E>
Typed event source handle. The from clause binds stream sources to this type.
Score
Semantic score value over Int, constrained to [0, 100]. Implicitly created by score clause and maps to severity levels.

Type-system notes:
- `Fact` is resolved as a symbol/declaration kind (not a field primitive).
- `EventStream<E>` is a clause/context type produced by `from`/`source` bindings.
- `Score` is represented as integer-like in expressions, with additional semantic range checks.


4.2  Entity Schema — Built-in Types
  // OIL Standard Entity Schema — oil_stdlib/src/schema.oil
// Entity schemas are defined in the OIL standard library.
// Field accesses are type-checked against these schemas at compile time.


entity Process {
    id:             Int,
    pid:            Int,
    ppid:           Int,
    name:           Str,      // also: comm
    filename:       Path,
    argv_hash:      Str,
    uid:            Int,
    gid:            Int,
    elevated:       Bool,     // uid == 0 or has privilege caps
    signed:         Bool,
    hash:           Str,      // binary hash
    risk_score:     Float,
    prevalence:     Prevalence,
    parent:         Process,  // recursive — resolved lazily
    host_id:        Str,
    container_id:   Str?,     // nullable
    command_line:   Str,
}


entity Prevalence {
    global:         Float,    // fraction of fleet that has seen this binary
    tenant:         Float,    // fraction within this tenant
}


entity User {
    id:             Str,
    uid:            Int,
    name:           Str,
    groups:         Set<Str>,
    trust_score:    Float,
    baseline:       UserBaseline,
    last_known_device: Str,
}


entity UserBaseline {
    countries:      Set<Str>,
    hosts:          Set<Str>,
    geos:           Set<Str>,
    login_hours:    Set<Int>,
}


entity NetworkEndpoint {
    ip:             IpAddr,
    port:           Int,
    proto:          Str,
    is_internal:    Bool,
    threat_score:   Float,
    geo_country:    Str,
    asn:            Str,
    reputation:     Str,    // "clean" | "suspicious" | "malicious"
    domain:         Str?,
}


entity File {
    path:           Path,
    sensitivity_label: Str,
    inode:          Int,
    last_modified:  Duration,
}


entity Secret {
    type:           Str,    // "api_key" | "certificate" | "password" | "token"
    source_path:    Path,
    sensitivity:    Str,
}


entity Session {
    id:             Str,
    user_id:        Str,
    device_id:      Str,
    country:        Str,
    mfa_present:    Bool,
    age:            Duration,
    token:          Token,
}



4.3  Type Inference Rules
Expression
Inferred Type
Notes
process.uid == 0
Bool
LHS: Int, RHS: Int, result: Bool
proc.risk_score + 20
Float
Float + Int → Float (widening)
n.dest.reputation in ["suspicious", "malicious"]
Bool
Str in Set<Str> → Bool
session.age > 12h
Bool
Duration > Duration → Bool
p.prevalence.global < 0.01
Bool
Float < Float → Bool
proc.parent.name
Str
Process.parent.name path resolution
count(d) >= 20
Bool
Aggregation over bound event stream
max(n.bytes_out)
Int
Aggregation on Int field
user(a.user_id)
Entity<User>
Lookup function returns typed entity
host(p.host_id).risk
Float
Chained entity lookup + field access
"bash" in [...]
Bool
String literal in list literal
score >= 80
Bool
Score (Int) compared to Int literal


5. Abstract Syntax Tree — Rust Implementation
The OIL compiler is implemented in Rust. The AST is a recursive enum structure, with each node carrying a span (source location) for precise error reporting. All AST nodes are heap-allocated via Box<T> to support arbitrary nesting depth without stack overflow in the recursive descent parser.

5.1  Core AST Node Types
  // oil_compiler/src/ast/mod.rs
// oil_compiler/src/ast/mod.rs


use std::ops::Range;


/// Source span — byte offsets into source text
pub type Span = Range<usize>;


/// Every AST node carries a source span for diagnostics
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}


impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self { Self { node, span } }
}


/// Top-level program
#[derive(Debug, Clone)]
pub struct Program {
    pub imports:    Vec<ImportDecl>,
    pub sets:       Vec<SetDecl>,
    pub predicates: Vec<PredicateDecl>,
    pub templates:  Vec<TemplateDecl>,
    pub facts:      Vec<FactDecl>,
    pub rules:      Vec<RuleDecl>,
    pub policies:   Vec<PolicyDecl>,
}


/// import/use declaration
#[derive(Debug, Clone)]
pub struct ImportDecl {
    pub path: Spanned<Vec<String>>,  // ["intel", "malicious_domains"]
}


/// Named set of values
#[derive(Debug, Clone)]
pub struct SetDecl {
    pub name:    Spanned<String>,
    pub values:  Vec<Spanned<Expr>>,
}


/// Reusable predicate (named boolean function)
#[derive(Debug, Clone)]
pub struct PredicateDecl {
    pub name:    Spanned<String>,
    pub params:  Vec<Spanned<String>>,
    pub body:    Spanned<Expr>,
}


/// Fact type declaration
#[derive(Debug, Clone)]
pub struct FactDecl {
    pub name:    Spanned<String>,
    pub params:  Vec<Spanned<String>>,
    pub expires: Option<Spanned<Duration>>,
}



5.2  Rule AST
  // oil_compiler/src/ast/rule.rs
/// A complete detection or correlation rule
#[derive(Debug, Clone)]
pub struct RuleDecl {
    pub meta:     Option<MetaBlock>,
    pub name:     Spanned<String>,
    pub sources:  Vec<SourceSpec>,
    pub body:     Spanned<RuleBody>,
    pub where_:   Option<Spanned<Expr>>,
    pub within:   Option<Spanned<Duration>>,
    pub require:  Option<Spanned<RequireClause>>,
    pub lets:     Vec<LetBinding>,
    pub score:    Option<Spanned<ScoreExpr>>,
    pub verify:   Option<VerifyClause>,
    pub emit:     Vec<EmitStmt>,
    pub respond:  Spanned<RespondBlock>,
}


/// Meta information block
#[derive(Debug, Clone)]
pub struct MetaBlock {
    pub severity:    Option<String>,
    pub mitre:       Vec<String>,
    pub tags:        Vec<String>,
    pub description: Option<String>,
}


/// Event source reference
#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub domain: String,      // "endpoint"
    pub event:  String,      // "process"
    pub alias:  Option<Spanned<String>>,
}


/// Rule body — one of four correlation modes
#[derive(Debug, Clone)]
pub enum RuleBody {
    /// Single stream: match event [then event ...]
    Match(MatchBlock),
    /// Multi-stream: correlate A with B on join-key
    Correlate(CorrelateBlock),
    /// Graph: structural path pattern
    Graph(GraphBlock),
    /// Entity-anchored: gather events around an entity
    Around(AroundBlock),
}


/// Sequential event match
#[derive(Debug, Clone)]
pub struct MatchBlock {
    pub steps:   Vec<MatchStep>,  // connected by "then"
}


#[derive(Debug, Clone)]
pub struct MatchStep {
    pub event:   Spanned<EventPattern>,
    pub alias:   Option<Spanned<String>>,
    pub by:      Option<Spanned<String>>,  // bound variable (e.g. process p)
}


#[derive(Debug, Clone)]
pub struct EventPattern {
    pub domain: String,
    pub kind:   String,
}


/// Multi-stream correlation
#[derive(Debug, Clone)]
pub struct CorrelateBlock {
    pub mode:  CorrelateMode,
    pub arms:  Vec<CorrelateArm>,
}


#[derive(Debug, Clone)]
pub enum CorrelateMode {
    All,   // all arms must match
    Any,   // at least one arm must match
    AtLeast(usize), // N or more arms must match
}


#[derive(Debug, Clone)]
pub struct CorrelateArm {
    pub event:    Spanned<EventPattern>,
    pub alias:    Spanned<String>,
    pub join:     CorrelateJoin,
}


#[derive(Debug, Clone)]
pub enum CorrelateJoin {
    /// Implicit join by shared entity variable: "by user"
    ByVariable(Spanned<String>),
    /// Explicit join predicate: "on a.user_id == b.user_id"
    OnPredicate(Spanned<Expr>),
    /// No explicit join — time window correlation only
    None,
}


/// Graph structural pattern
#[derive(Debug, Clone)]
pub struct GraphBlock {
    pub source:   SourceSpec,
    pub patterns: Vec<GraphPattern>,
}


#[derive(Debug, Clone)]
pub struct GraphPattern {
    pub entity_type: String,
    pub alias:       Spanned<String>,
    pub edge_type:   Option<String>,  // if None, any edge
}


/// Entity-anchored gather block
#[derive(Debug, Clone)]
pub struct AroundBlock {
    pub entity:   Spanned<String>,
    pub window:   Spanned<Duration>,
    pub arms:     Vec<GatherArm>,
}


#[derive(Debug, Clone)]
pub struct GatherArm {
    pub event: Spanned<EventPattern>,
    pub alias: Spanned<String>,
}



5.3  Score & Response AST
  // oil_compiler/src/ast/actions.rs
/// Score expression — base value + conditional modifiers
#[derive(Debug, Clone)]
pub struct ScoreExpr {
    pub base:      Spanned<i32>,
    pub modifiers: Vec<ScoreModifier>,
}


#[derive(Debug, Clone)]
pub struct ScoreModifier {
    pub delta:     i32,      // signed: + or -
    pub condition: Option<Spanned<Expr>>,  // None = always applies
    pub multiply:  bool,     // if true, delta is a multiplier (e.g. * 0.5)
}


/// Let bindings — derived variables
#[derive(Debug, Clone)]
pub struct LetBinding {
    pub name:  Spanned<String>,
    pub value: Spanned<Expr>
}


/// Respond block — conditional action tree
#[derive(Debug, Clone)]
pub struct RespondBlock {
    pub arms: Vec<RespondArm>,
}


#[derive(Debug, Clone)]
pub struct RespondArm {
    pub condition: Option<Spanned<Expr>>,  // None = else / unconditional
    pub actions:   Vec<Spanned<ActionStmt>>,
}


/// Individual response action
#[derive(Debug, Clone)]
pub enum ActionStmt {
    Alert    { severity: Severity, message: Option<String> },
    Isolate  { kind: IsolateKind, target: Spanned<String> },
    Revoke   { kind: RevokeKind,  target: Spanned<String> },
    Snapshot { targets: Vec<Spanned<String>>, kind: SnapshotKind },
    OpenCase { title: String },
    Challenge { kind: ChallengeKind },
    RequireAuth { kind: AuthKind, for_: Spanned<String> },
    Quarantine { path: Spanned<String> },
    BlockEgress { target: Spanned<String> },
    Notify   { message: String },
    Throttle { target: Spanned<String> },
}


#[derive(Debug, Clone, PartialEq)]
pub enum Severity { Critical, High, Medium, Low, Informational }


#[derive(Debug, Clone)]
pub enum IsolateKind  { Host, Network, Process }


#[derive(Debug, Clone)]
pub enum RevokeKind   { Session, Token, Credential }


#[derive(Debug, Clone)]
pub enum SnapshotKind { Entities, AttackGraph, HostTimeline, ProcessTree }


#[derive(Debug, Clone)]
pub enum ChallengeKind { Mfa }


#[derive(Debug, Clone)]
pub enum AuthKind { Reauthentication, StepUp, Approval }



5.4  Expression AST
  // oil_compiler/src/ast/expr.rs
/// Unified expression type — used in where, let, score, respond conditions
#[derive(Debug, Clone)]
pub enum Expr {
    // ── Literals ──────────────────────────────────────────────────────
    StrLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    DurationLit(Duration),
    Null,


    // ── Identifiers & Paths ───────────────────────────────────────────
    Path(Vec<String>),               // process.parent.name → vec!["process","parent","name"]
    Ident(String),                   // bare identifier: set name, fact name, alias


    // ── Arithmetic ────────────────────────────────────────────────────
    BinOp { op: ArithOp, lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    UnaryMinus(Box<Spanned<Expr>>),


    // ── Boolean Logic ─────────────────────────────────────────────────
    And(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Or(Box<Spanned<Expr>>, Box<Spanned<Expr>>),
    Not(Box<Spanned<Expr>>),


    // ── Comparison ────────────────────────────────────────────────────
    Cmp { op: CmpOp, lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },


    // ── Membership & String ───────────────────────────────────────────
    In    { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    NotIn { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    StartsWith { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    EndsWith   { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    Contains   { lhs: Box<Spanned<Expr>>, rhs: Box<Spanned<Expr>> },
    Matches    { lhs: Box<Spanned<Expr>>, pattern: String },
    Under      { path: Box<Spanned<Expr>>, prefix: Box<Spanned<Expr>> },
    Between    { val: Box<Spanned<Expr>>, lo: Box<Spanned<Expr>>, hi: Box<Spanned<Expr>> },


    // ── Statistical / ML operators ────────────────────────────────────
    UnusualFor { val: Box<Spanned<Expr>>, entity: String },  // ML baseline check
    Rare(Box<Spanned<Expr>>),                                // global rarity < 1%


    // ── Aggregations (valid in around/gather context) ─────────────────
    Count(Box<Spanned<Expr>>),
    Max(Box<Spanned<Expr>>),
    Min(Box<Spanned<Expr>>),
    Sum(Box<Spanned<Expr>>),
    Avg(Box<Spanned<Expr>>),
    Distinct(Box<Spanned<Expr>>),


    // ── Function Calls ────────────────────────────────────────────────
    Call { name: String, args: Vec<Spanned<Expr>> },


    // ── List Literal ─────────────────────────────────────────────────
    List(Vec<Spanned<Expr>>),
}


#[derive(Debug, Clone, PartialEq)]
pub enum ArithOp { Add, Sub, Mul, Div }


#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp   { Eq, Ne, Lt, Gt, Le, Ge }



6. Compiler Architecture
The OIL compiler is a multi-stage pipeline implemented entirely in Rust. It takes OIL source text and produces one of three output artefacts depending on the rule type: a compiled EPL shared object (.so) for hot-path single-stream rules, a Memgraph Cypher trigger for event-driven graph rules, and a Tokio async stream operator for temporal correlation rules.

6.1  Compiler Pipeline Overview
  // oil_compiler/src/lib.rs — pipeline entry point
// oil_compiler/src/lib.rs — Top-level compilation pipeline


pub fn compile(source: &str, config: &CompilerConfig) -> Result<CompileOutput, Vec<Diagnostic>> {
    // Stage 1: Lex
    let tokens  = Lexer::new(source).tokenize()?;


    // Stage 2: Parse → AST
    let program = Parser::new(tokens).parse_program()?;


    // Stage 3: Name resolution — resolve identifiers to declarations
    let program = NameResolver::new().resolve(program)?;


    // Stage 4: Type checking — validate field paths, operator types
    let typed   = TypeChecker::new().check(program)?;


    // Stage 5: Semantic analysis — window bounds, join key validity
    let sem     = SemanticAnalyzer::new().analyze(typed)?;


    // Stage 6: Lowering → MIR (Mid-level IR)
    let mir     = Lowerer::new().lower(sem)?;


    // Stage 7: Optimisation passes on MIR
    let mir     = PredicatePushdown::new().run(mir)?;
    let mir     = ConstantFolding::new().run(mir)?;
    let mir     = SetInlining::new().run(mir)?;
    let mir     = JoinKeyOptimizer::new().run(mir)?;


    // Stage 8: Code generation — target-specific output
    let output  = match mir.rule_class() {
        RuleClass::HotPath   => EplCodegen::new().generate(mir)?,
        RuleClass::Temporal  => StreamCodegen::new().generate(mir)?,
        RuleClass::Graph     => CypherCodegen::new().generate(mir)?,
        RuleClass::Policy    => OpaCodegen::new().generate(mir)?,
    };


    Ok(output)
}



6.2  Stage 1 — Lexer
  // oil_compiler/src/lexer/mod.rs
// oil_compiler/src/lexer/mod.rs


#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Literals
    StrLit(String), IntLit(i64), FloatLit(f64),
    DurationLit { value: u64, unit: TimeUnit },
    RegexLit(String),


    // Identifiers
    Ident(String),


    // Keywords — one variant per reserved word
    Kw(Keyword),


    // Operators & Punctuation
    Arrow, FatArrow, Range, Assign, Eq, Ne,
    Lt, Gt, Le, Ge, Plus, Minus, Star, Slash,
    Comma, Colon, Semicolon, At, Dot,
    LBrace, RBrace, LParen, RParen, LBracket, RBracket,


    // Special
    Newline, Eof,
}


#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}


pub struct Lexer<'src> {
    src:  &'src str,
    pos:  usize,
    line: usize,
    col:  usize,
}


impl<'src> Lexer<'src> {
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.src.len() {
                tokens.push(Token { kind: TokenKind::Eof, span: self.pos..self.pos });
                break;
            }
            let tok = self.next_token()?;
            tokens.push(tok);
        }
        Ok(tokens)
    }


    fn next_token(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let ch = self.current_char();
        match ch {
            '"' => self.lex_string(start),
            '/' if self.peek() == '/' => self.lex_regex_or_comment(start),
            '0'..='9' => self.lex_number(start),
            'a'..='z' | 'A'..='Z' | '_' => self.lex_ident_or_keyword(start),
            _ => self.lex_punctuation(start),
        }
    }
}



6.3  Stage 2 — Parser (LALR(1))
  // oil_compiler/src/parser/mod.rs
// oil_compiler/src/parser/mod.rs
// Hand-written recursive descent parser with LALR(1) lookahead.
// Panic-free: all errors are collected, parsing continues for best-effort diagnostics.


pub struct Parser {
    tokens:   Vec<Token>,
    pos:      usize,
    errors:   Vec<ParseError>,
}


impl Parser {
    pub fn parse_program(&mut self) -> Result<Program, Vec<ParseError>> {
        let mut prog = Program::default();
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
        self.expect(Keyword::Rule);
        let name = self.expect_string();
        self.expect_lbrace();


        let sources = if self.peek_keyword(Keyword::From) || self.peek_keyword(Keyword::Source)
            { self.parse_from_clause() } else { vec![] };


        let body = match self.peek().kind {
            TokenKind::Kw(Keyword::Match)     => RuleBody::Match(self.parse_match_block()),
            TokenKind::Kw(Keyword::Correlate) => RuleBody::Correlate(self.parse_correlate()),
            TokenKind::Kw(Keyword::Graph)     => RuleBody::Graph(self.parse_graph()),
            TokenKind::Kw(Keyword::Around)    => RuleBody::Around(self.parse_around()),
            _ => { self.emit_error("expected match/correlate/graph/around"); 
                   RuleBody::Match(MatchBlock { steps: vec![] }) }
        };


        let where_  = self.try_parse_where();
        let within  = self.try_parse_within();
        let require = self.try_parse_require();
        let lets    = self.parse_let_bindings();
        let score   = self.try_parse_score();
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
}



6.4  Mid-Level Intermediate Representation (MIR)
  // oil_compiler/src/mir/mod.rs
// oil_compiler/src/mir/mod.rs
// MIR is a normalised, typed representation optimised for code generation.
// It separates concerns: filter predicates, join conditions, score computation,
// and action emission are separate, independently optimisable components.


#[derive(Debug, Clone)]
pub struct MirProgram {
    pub rules: Vec<MirRule>,
}


#[derive(Debug, Clone)]
pub struct MirRule {
    pub id:          RuleId,
    pub name:        String,
    pub class:       RuleClass,
    pub sources:     Vec<SourceRef>,
    pub predicates:  Vec<MirPredicate>,   // flat list, ordered by cost
    pub joins:       Vec<MirJoin>,
    pub window:      Option<Duration>,
    pub require:     Vec<MirRequire>,
    pub lets:        Vec<MirLet>,
    pub score_fn:    MirScoreFn,
    pub emit_facts:  Vec<MirEmit>,
    pub respond:     MirRespondPlan,
}


/// Rule execution class — determines codegen target
#[derive(Debug, Clone, PartialEq)]
pub enum RuleClass {
    HotPath,   // single-event: compiled to EPL .so
    Temporal,  // sequential/correlate: Tokio stream operator
    Graph,     // structural: Memgraph Cypher trigger
    Policy,    // enforce: OPA Rego module
}


/// A single filter predicate with its estimated evaluation cost
#[derive(Debug, Clone)]
pub struct MirPredicate {
    pub expr:     MirExpr,
    pub cost:     PredicateCost,  // used for reordering by optimizer
    pub nullable: bool,
}


#[derive(Debug, Clone)]
pub enum PredicateCost {
    Constant,         // integer compare, boolean: ~0.5ns
    FieldLookup,      // BPF map lookup: ~5ns
    StringOp,         // string comparison/prefix: ~20ns
    SetLookup,        // hash set membership: ~5ns
    GraphLookup,      // 1-hop graph query: ~10ns
    ExternalCall,     // threat intel feed lookup: ~100ns
    MlInference,      // unusual_for / rare: ~500ns (batched)
}


/// Join condition between correlated streams
#[derive(Debug, Clone)]
pub struct MirJoin {
    pub left_stream:  usize,
    pub right_stream: usize,
    pub key_expr:     MirExpr,
}


/// Score function — evaluates to i32 in [0, 100]
#[derive(Debug, Clone)]
pub struct MirScoreFn {
    pub base:      i32,
    pub modifiers: Vec<MirScoreMod>,
}


#[derive(Debug, Clone)]
pub struct MirScoreMod {
    pub delta:     i32,
    pub condition: Option<MirExpr>,
}


/// Planned response — ordered action tree
#[derive(Debug, Clone)]
pub struct MirRespondPlan {
    pub branches: Vec<MirBranch>,
}


#[derive(Debug, Clone)]
pub struct MirBranch {
    pub condition: Option<MirExpr>,
    pub actions:   Vec<MirAction>,
}



6.5  Optimisation Passes
  // oil_compiler/src/optimizer/
// oil_compiler/src/optimizer/predicate_pushdown.rs
// Reorders predicates by cost (cheapest first) and pushes cheap filters
// as close to the event source as possible — ideally into eBPF XDP hook.


pub struct PredicatePushdown;


impl PredicatePushdown {
    pub fn run(&self, mut mir: MirProgram) -> Result<MirProgram, CompileError> {
        for rule in &mut mir.rules {
            // Sort predicates ascending by cost — constant checks first
            rule.predicates.sort_by_key(|p| p.cost as u8);


            // Mark predicates that can run in eBPF (no string ops, no ML)
            for pred in &mut rule.predicates {
                pred.ebpf_eligible = matches!(
                    pred.cost,
                    PredicateCost::Constant | PredicateCost::FieldLookup | PredicateCost::SetLookup
                );
            }
        }
        Ok(mir)
    }
}




// oil_compiler/src/optimizer/set_inlining.rs
// Inlines named set references into hash sets computed at compile time.
// p.name in shell_names → p.comm_id in {0x004A, 0x008B, 0x00C1} (integer IDs)


pub struct SetInlining {
    global_sets: HashMap<String, Vec<MirExpr>>,
    id_registry: IntIdRegistry,
}


impl SetInlining {
    pub fn run(&self, mut mir: MirProgram) -> Result<MirProgram, CompileError> {
        for rule in &mut mir.rules {
            for pred in &mut rule.predicates {
                self.inline_sets_in_expr(&mut pred.expr);
            }
        }
        Ok(mir)
    }


    fn inline_sets_in_expr(&self, expr: &mut MirExpr) {
        if let MirExpr::In { rhs, .. } = expr {
            if let MirExpr::Ident(name) = rhs.as_ref() {
                if let Some(values) = self.global_sets.get(name) {
                    // Replace named set with computed integer hash set
                    let ids: Vec<u32> = values.iter()
                        .filter_map(|v| self.id_registry.lookup(v))
                        .collect();
                    *rhs = Box::new(MirExpr::IntSet(ids));
                }
            }
        }
    }
}




// oil_compiler/src/optimizer/constant_folding.rs
// Evaluates constant sub-expressions at compile time.
// score 50 + 10 + 20 if x → score 60 + 20 if x


pub struct ConstantFolding;


impl ConstantFolding {
    fn fold_expr(&self, expr: MirExpr) -> MirExpr {
        match expr {
            MirExpr::BinOp { op: ArithOp::Add, lhs, rhs }
                if is_constant(&lhs) && is_constant(&rhs) => {
                MirExpr::IntLit(eval_int(&lhs) + eval_int(&rhs))
            }
            other => other,
        }
    }
}



7. Code Generation — Three Backends
OIL compiles to three fundamentally different execution backends depending on the rule class. The compiler classifies each rule during semantic analysis and routes it to the appropriate code generator. A single OIL source file may produce artefacts for multiple backends.

Backend
Target / Output
EPL Compiled
Rust .so shared object — loaded at runtime by RuleEngine via dlopen. Evaluation: ~15–20ns per event. Used for HotPath rules: single-stream, no temporal state.
Stream Operator
Tokio async Rust code compiled into the Olopa agent binary. Maintains sliding window state. Used for Temporal rules: sequential chains, correlate blocks, around/gather.
Cypher Trigger
Memgraph AFTER COMMIT trigger + optional BEFORE COMMIT blocker. Event-driven, fires on graph write. Used for Graph rules and cross-layer joins.
OPA Module
Rego policy module for the OPA engine. Used for Policy declarations with enforce semantics. Integrates with the Agentic Firewall.


7.1  EPL Codegen — Hot-Path Compiled Rules
  // oil_compiler/src/codegen/epl.rs
// oil_compiler/src/codegen/epl.rs
// Generates a Rust source file that compiles to a .so with a well-known symbol.
// The RuleEngine dlopen()s the .so and calls the exported function per event.


pub struct EplCodegen;


impl EplCodegen {
    pub fn generate(&self, rule: &MirRule) -> Result<String, CodegenError> {
        let mut src = String::new();


        // File header + imports
        src.push_str(RULE_HEADER);


        // Pre-computed integer sets (from SetInlining pass)
        for set in &rule.precomputed_sets {
            src.push_str(&self.emit_static_set(set));
        }


        // Main exported function — well-known ABI
        src.push_str(&format!(
            "#[no_mangle]\npub extern \"C\" fn rule_{}(\n",
            sanitize_name(&rule.name)
        ));
        src.push_str("    event: &OlopaEvent,\n");
        src.push_str("    graph: &CsrGraph,\n");
        src.push_str("    ctx:   &RuleContext,\n");
        src.push_str(") -> Option<Alert> {\n");


        // Emit predicates in cost order (cheapest first)
        for pred in &rule.predicates {
            src.push_str(&format!(
                "    if !({}) {{ return None; }}\n",
                self.emit_expr(&pred.expr)
            ));
        }


        // Emit score computation
        src.push_str(&self.emit_score_fn(&rule.score_fn));


        // Emit alert construction
        src.push_str(&self.emit_alert_builder(rule));


        src.push_str("}\n");
        Ok(src)
    }


    fn emit_expr(&self, expr: &MirExpr) -> String {
        match expr {
            MirExpr::Cmp { op: CmpOp::Eq, lhs, rhs } =>
                format!("({}) == ({})", self.emit_expr(lhs), self.emit_expr(rhs)),
            MirExpr::In { lhs, rhs: MirExpr::IntSet(ids) } =>
                format!("CONST_SET_{}.contains(&({}))", set_id, self.emit_expr(lhs)),
            MirExpr::Path(segments) =>
                format!("event.{}", segments.join(".")),
            MirExpr::IntLit(n) => n.to_string(),
            MirExpr::StrLit(s) => format!("ctx.intern({:?})", s),
            _ => unimplemented!("emit_expr: {:?}", expr),
        }
    }
}


// Generated output example for a simple rule:
// ─────────────────────────────────────────────────────────────────────────
// #[no_mangle]
// pub extern "C" fn rule_webshell_basic(
//     event: &OlopaEvent, graph: &CsrGraph, ctx: &RuleContext
// ) -> Option<Alert> {
//     // Predicate 0: COST=Constant — check event type first
//     if event.event_type != EventType::Exec { return None; }
//     // Predicate 1: COST=SetLookup — comm_id in compiled hash set
//     if !SHELL_IDS.contains(&event.comm_id) { return None; }
//     // Predicate 2: COST=GraphLookup — parent node lookup
//     let parent = graph.node_props(event.ppid_vertex)?;
//     if !WEBSERVER_IDS.contains(&parent.comm_id) { return None; }
//     // Score
//     let mut score: i32 = 70;
//     if event.uid == 0 { score += 15; }
//     Some(Alert { rule_id: RULE_ID, severity: severity_from_score(score), ... })
// }



7.2  Stream Codegen — Temporal Correlation Rules
  // oil_compiler/src/codegen/stream.rs
// oil_compiler/src/codegen/stream.rs
// Generates a Tokio async stream operator for temporal/correlate rules.
// The operator is compiled directly into the olopa-agent binary.


// Generated operator structure:
//   - A stateful struct holding the sliding window buffers per stream
//   - An async fn process_event() called on every event
//   - A join engine that runs after each event to check for matches


pub fn emit_correlate_operator(rule: &MirRule) -> String {
    // ... generates code like:
    format!(r#"
/// Auto-generated stream operator: {name}
pub struct Op{id} {{
    window: Duration,
    // One sliding window buffer per correlated stream
    buf_0:  SlidingWindow<ProcessExecEvent>,
    buf_1:  SlidingWindow<CookieReadEvent>,
    buf_2:  SlidingWindow<NetworkConnEvent>,
    buf_3:  SlidingWindow<IdentitySessionEvent>,
}}


impl Op{id} {{
    pub fn new() -> Self {{
        Self {{
            window: Duration::from_secs({window_secs}),
            buf_0: SlidingWindow::new({window_secs}),
            buf_1: SlidingWindow::new({window_secs}),
            buf_2: SlidingWindow::new({window_secs}),
            buf_3: SlidingWindow::new({window_secs}),
        }}
    }}


    pub fn ingest(&mut self, event: &AnyEvent) -> Vec<Alert> {{
        // Route event to correct stream buffer
        match event {{
            AnyEvent::ProcessExec(e)  if {filter_0} => self.buf_0.push(e.clone()),
            AnyEvent::CookieRead(e)   if {filter_1} => self.buf_1.push(e.clone()),
            AnyEvent::NetworkConnect(e) if {filter_2} => self.buf_2.push(e.clone()),
            AnyEvent::Session(e)      if {filter_3} => self.buf_3.push(e.clone()),
            _ => return vec![],
        }}
        self.run_join()
    }}


    fn run_join(&self) -> Vec<Alert> {{
        let mut alerts = vec![];
        // Nested join — for each p in buf_0, find matching events in other buffers
        for p in self.buf_0.iter() {{
            for c in self.buf_1.iter().filter(|c| c.process_id == p.id) {{
                for n in self.buf_2.iter().filter(|n| n.process_id == p.id) {{
                    for s in self.buf_3.iter().filter(|s| s.user_id == p.user_id) {{
                        if {where_predicate} {{
                            let score = {score_expr};
                            alerts.push(self.build_alert(score, p, c, n, s));
                        }}
                    }}
                }}
            }}
        }}
        alerts
    }}
}}
"#, name=rule.name, id=rule.id, ...)
}



7.3  Cypher Codegen — Graph Trigger Rules
  // oil_compiler/src/codegen/cypher.rs
// oil_compiler/src/codegen/cypher.rs
// Generates Memgraph AFTER COMMIT triggers for graph structural rules.
// Each rule produces: one trigger definition + one detection procedure.


pub fn emit_cypher_trigger(rule: &MirRule) -> CypherOutput {
    let trigger_name = sanitize_name(&rule.name);
    let proc_name = format!("detect.{}", trigger_name);


    // Determine which edge write should fire the trigger
    let trigger_pattern = emit_trigger_pattern(&rule.graph.patterns);


    // The Cypher MATCH query for structural detection
    let detection_query = emit_detection_query(&rule.graph.patterns, &rule.predicates);


    CypherOutput {
        // The AFTER COMMIT trigger — fires instantly on matching graph write
        trigger: format!(r#"
CREATE TRIGGER {trigger_name}_trigger
ON CREATE TO {trigger_pattern}
AFTER COMMIT
EXECUTE
    CALL {proc_name}(createdEdges) YIELD alert
    CALL olopa.emit_alert(alert);
        "#, trigger_name=trigger_name, trigger_pattern=trigger_pattern, proc_name=proc_name),


        // The detection procedure body
        procedure: format!(r#"
// Detection procedure: {name}
{detection_query}
RETURN
    {return_fields}
ORDER BY timestamp DESC
        "#, name=rule.name, detection_query=detection_query, ...),
    }
}


// ─── Example Cypher output for "webshell_chain" rule ─────────────────
// Trigger:
// CREATE TRIGGER webshell_chain_trigger
// ON CREATE TO ()-[:SPAWNED]->(:Process {comm: "bash"})
// AFTER COMMIT
// EXECUTE
//     CALL detect.webshell_chain(createdEdges) YIELD alert
//     CALL olopa.emit_alert(alert);
//
// Procedure:
// MATCH path = (web:Process)-[:SPAWNED*1..3]->(shell:Process)
//              -[:CONNECTED_TO]->(ext:NetworkEndpoint)
// WHERE web.comm IN ["nginx","apache2","httpd","gunicorn"]
//   AND shell.comm IN ["bash","sh","zsh","python3"]
//   AND NOT ext.is_internal
// RETURN web.host_id, shell.comm, ext.ip, length(path) AS depth
// ORDER BY ext.threat_intel_score DESC



8. Complete OIL Rule Examples
This section presents complete, production-ready OIL rules covering all four rule classes, demonstrating how the grammar, type system, and compiler backend selection work together.

8.1  Hot-Path Rule — Single-Stream EPL
This rule compiles to an EPL .so. It evaluates in ~15ns per event on the eBPF ring buffer consumer, zero state, zero allocation.
  // Example 1: Hot-Path EPL rule — compiles to .so, ~15ns evaluation
meta {
    severity    = "critical"
    mitre       = ["T1059", "T1190"]
    tags        = ["webshell", "endpoint", "epl"]
    description = "Web server process spawning a shell interpreter — classic webshell indicator."
}


set web_servers = ["nginx", "apache2", "httpd", "gunicorn", "uvicorn", "caddy", "lighttpd"]
set shells      = ["bash", "sh", "zsh", "fish", "python3", "perl", "ruby", "node"]


rule "webshell_spawn_detect" {
    from endpoint.process


    match process.exec as p


    where
        p.name in shells
        and p.parent.name in web_servers
        and p.parent.uid in [33, 48, 1000]   // www-data, apache


    score
        base 70
        +15 if p.elevated
        +10 if p.signed == false
        +10 if p.parent.prevalence.global < 0.05
        -10 if p.command_line contains "--version"  // reduce FP for health checks


    respond {
        if score >= 85 {
            alert critical "Web shell spawn detected"
            isolate network p.host_id
            snapshot process_tree(p)
            open_case "Possible webshell compromise"
        }
        else if score >= 70 {
            alert high
            snapshot p, p.parent
        }
        else {
            alert medium
        }
    }
}



8.2  Temporal Correlation Rule — Stream Operator
This rule correlates four event streams within a 15-minute window. It compiles to a Tokio async stream operator maintaining sliding window state per key.
  // Example 2: Temporal correlation rule — Tokio stream operator, 4 joined streams
use intel.malicious_domains
use org.sensitive_credential_paths


predicate unusual_country(user, country) =
    country not_in user.baseline.countries


meta {
    severity    = "critical"
    mitre       = ["T1552", "T1041", "T1078"]
    tags        = ["credential-access", "exfiltration", "identity", "temporal"]
}


rule "credential_access_exfil_chain" {
    from endpoint.file, endpoint.process, network.flow, identity.session


    correlate
        file.read as f by process p
        with network.connect as n by p
        with session.use as s by user u on u.id == p.user_id


    where
        f.path in sensitive_credential_paths
        and n.dest.reputation in ["suspicious", "malicious"]
        and unusual_country(u, s.country)


    within 15m


    let
        rare_binary    = p.prevalence.global < 0.01
        high_vol_exfil = n.bytes_out > 500_000
        headless       = p.command_line contains "--headless"
        stealthy       = rare_binary or headless
        risky_session  = s.mfa_present == false


    score
        base 65
        +20 if stealthy
        +15 if high_vol_exfil
        +10 if p.elevated
        +15 if risky_session
        +10 if n.dest.domain in malicious_domains


    verify
        require p.hash
        require n.dest.ip
        require s.id


    emit
        fact host.compromised(p.host_id) expires 7d
        fact user.session_risky(u.id) expires 6h


    respond {
        if score >= 90 {
            alert critical "Credential access and exfiltration chain confirmed"
            revoke session s
            isolate host p.host_id
            snapshot attack_graph
            open_case "Credential exfiltration — full containment triggered"
        }
        else if score >= 75 {
            alert high
            require_reauthentication for u
            snapshot p, f, n, s
        }
        else {
            alert medium
            snapshot p, n
        }
    }
}



8.3  Graph Rule — Memgraph Cypher Trigger
This rule compiles to a Memgraph AFTER COMMIT trigger. It fires in < 100ms from the graph write — no polling.
  // Example 3: Graph rule — Memgraph trigger, structural multi-hop pattern
meta {
    severity    = "critical"
    mitre       = ["T1021", "T1078"]
    tags        = ["lateral-movement", "graph", "cypher-trigger"]
}


rule "lateral_movement_multi_hop" {
    graph endpoint.activity


    match
        node Process as origin
        -> node Secret as cred
        -> node Host as target_host
        -> node Process as remote_proc


    where
        origin.uid in [0, 1000]
        and cred.type in ["ntlm_hash", "ssh_key", "kerberos_ticket", "token"]
        and target_host.host_id != origin.host_id
        and remote_proc.name not in ["sshd", "systemd", "kubelet"]


    score
        base 80
        +15 if origin.risk_score > 0.7
        +10 if cred.type == "ntlm_hash"


    respond {
        alert critical "Multi-hop lateral movement via stolen credentials"
        isolate network target_host.host_id
        snapshot attack_graph
        open_case "Lateral movement — credential-based host pivot"
    }
}



8.4  Cross-Correlation Rule — Full Signal Fusion
The most powerful OIL rule type: fuses process, browser, network, and identity signals across a time window with a rich scoring model and adaptive response tree.
  // Example 4: Full cross-correlation rule — all four signal sources
use intel.active_c2_domains
use org.allowed_admins


set auth_cookie_classes = ["session_token", "access_token", "oauth_bearer"]


predicate unusual_device(user, device_id) =
    device_id != user.last_known_device


meta {
    severity    = "critical"
    mitre       = ["T1539", "T1567", "T1078"]
    tags        = ["session-hijack", "exfil", "browser", "cross-signal"]
}


rule "possible_session_hijack_and_exfil" {
    from browser.cookie, endpoint.process, network.flow, identity.session


    correlate
        cookie.read as c by process as p
        with network.connect as n on n.process_id == p.id
        with session.use as s on s.user_id == p.user_id


    where
        c.cookie.classification in auth_cookie_classes
        and p.name in ["python", "node", "chrome", "powershell", "curl"]
        and n.dest.reputation in ["suspicious", "malicious"]
        and unusual_device(user(p.user_id), s.device_id)
        and s.country not_in user(p.user_id).baseline.countries


    within 12m


    let
        stealthy    = p.command_line contains "--headless"
                      or p.command_line contains "eval("
                      or p.signed == false
        high_exfil  = n.bytes_out > 250_000
                      or n.proto in ["https", "wss"]
        rare_proc   = p.prevalence.global < 0.01
        weak_session = s.mfa_present == false
        c2_dest     = n.dest.domain in active_c2_domains


    score
        base 55
        +20 if stealthy
        +15 if high_exfil
        +15 if weak_session
        +10 if rare_proc
        +15 if c2_dest
        +10 if p.elevated


    emit
        fact user.session_risky(s.user_id) expires 6h
        fact host.compromised(p.host_id)   expires 7d


    respond {
        if score >= 90 {
            alert critical "Session hijack and exfiltration — high confidence"
            revoke session s
            isolate host p.host_id
            snapshot attack_graph
            open_case "Session hijack with external exfiltration"
        }
        else if score >= 75 {
            alert high "Session hijack indicator — step-up auth required"
            require_reauthentication for user(p.user_id)
            snapshot p, c, n, s
        }
        else if score >= 60 {
            alert medium
            challenge mfa
            snapshot p, n
        }
        else {
            alert low
        }
    }
}



8.5  Policy Declaration — Adaptive Access Control
A Policy is not a detection rule. It evaluates continuously on access events and enforces decisions in real time, replacing static RBAC with risk-based adaptive policy.
  // Example 5: Policy declaration — adaptive enforcement, compiles to OPA Rego
use assets.sensitive_repos
use org.trusted_browsers


meta {
    severity    = "medium"
    tags        = ["access-control", "adaptive-policy", "repo-protection"]
}


policy "sensitive_repo_adaptive_access" {
    from browser, identity, device, network


    when repo.clone as r


    where
        r.repo.name in sensitive_repos


    evaluate
        base 0
        +30 if device.disk_encrypted == false
        +20 if device.trust < 60
        +25 if r.country not_in user(r.user_id).baseline.countries
        +15 if identity.session.mfa_present == false
        +20 if browser.name not_in trusted_browsers
        +15 if identity.session.age > 8h
        +10 if network.is_vpn == false and network.is_internal == false


    enforce
        allow if risk < 20
        challenge mfa if risk between 20..49
        require approval if risk between 50..79
        block if risk >= 80
}



8.6  Around/Gather Rule — Entity-Anchored Correlation
Around rules anchor correlation on a specific entity (host, user, container) and gather events into count-based thresholds, replacing many SIEM rules that fire on single high-volume events.
  // Example 6: Around/gather rule — entity-anchored, aggregation-based
meta {
    severity    = "high"
    mitre       = ["T1071", "T1048"]
    tags        = ["dns-tunneling", "c2", "dga", "around"]
}


rule "dns_tunnel_candidate" {
    from endpoint.dns, endpoint.process, network.flow


    around host over 5m


    gather
        dns.query  as q
        process.exec as p
        network.connect as n


    where
        q.length > 120
        and q.entropy > 4.2
        and q.subdomain.count > 3
        and q.domain not_in host.baseline.resolved_domains
        and n.dest.port not in [80, 443, 53, 22]
        and p.name not in ["systemd-resolved", "dnsmasq", "named"]


    require
        count(q) >= 30
        and count(n) >= 5


    score
        base 60
        +20 if max(q.entropy) > 5.0
        +15 if count(q) > 100
        +15 if distinct(q.domain) > 10
        +10 if p.elevated


    respond {
        if score >= 85 {
            alert critical "DNS tunneling detected — high query entropy and volume"
            block egress n.dest
            snapshot host_timeline
            open_case "DNS C2 tunneling suspected"
        }
        else {
            alert high
            snapshot q, p, n
        }
    }
}



9. Runtime Integration — Olopa Platform
OIL rules compile to artefacts that integrate with four distinct Olopa runtime components. This section describes how each compiled artefact is loaded, managed, and executed by the Olopa agent daemon and backend platform.

9.1  Rule Engine — EPL Hot Path
  // olopa-agent/src/rule_engine.rs
// olopa-agent/src/rule_engine.rs
// Loads compiled EPL .so files at startup and calls them per event.
// Zero query parsing. Zero string matching. Function pointer dispatch only.


pub struct RuleEngine {
    // Loaded shared objects — kept alive for the lifetime of the engine
    _libs:     Vec<libloading::Library>,
    // Function pointers — one per loaded rule
    rule_fns:  Vec<RuleFn>,
    // Metrics
    hit_count: Vec<CachePadded<AtomicU64>>,
}


type RuleFn = unsafe extern "C" fn(*const OlopaEvent, *const CsrGraph, *const RuleContext)
                                   -> *mut Alert;


impl RuleEngine {
    pub fn load_rule(&mut self, so_path: &Path) -> Result<()> {
        let lib = unsafe { libloading::Library::new(so_path)? };
        // Find the exported function — name is rule_<sanitized_name>
        let sym_name = extract_rule_symbol_name(so_path)?;
        let func: RuleFn = unsafe { *lib.get(sym_name.as_bytes())? };
        self._libs.push(lib);
        self.rule_fns.push(func);
        self.hit_count.push(CachePadded::new(AtomicU64::new(0)));
        Ok(())
    }


    /// HOT PATH — called 15M+ times per second per core
    /// No allocation, no lock, pure function pointer dispatch
    #[inline(always)]
    pub fn evaluate(&self, event: &OlopaEvent, graph: &CsrGraph, ctx: &RuleContext)
                    -> Option<Alert> {
        for (i, rule_fn) in self.rule_fns.iter().enumerate() {
            let alert_ptr = unsafe { rule_fn(event, graph, ctx) };
            if !alert_ptr.is_null() {
                self.hit_count[i].fetch_add(1, Ordering::Relaxed);
                return Some(unsafe { *Box::from_raw(alert_ptr) });
            }
        }
        None
    }


    /// Hot-reload: swap a .so without restarting the agent
    pub fn reload_rule(&mut self, rule_id: usize, new_so_path: &Path) -> Result<()> {
        let lib = unsafe { libloading::Library::new(new_so_path)? };
        let sym_name = extract_rule_symbol_name(new_so_path)?;
        let func: RuleFn = unsafe { *lib.get(sym_name.as_bytes())? };
        // Atomic swap — readers see either old or new, never nothing
        self._libs[rule_id] = lib;
        self.rule_fns[rule_id] = func;
        Ok(())
    }
}



9.2  Stream Engine — Temporal Operator Registry
  // olopa-agent/src/stream_engine.rs
// olopa-agent/src/stream_engine.rs
// Manages registered temporal operators — one per compiled correlate/match rule.


pub struct StreamEngine {
    operators: Vec<Box<dyn TemporalOperator + Send>>,
}


pub trait TemporalOperator {
    fn ingest(&mut self, event: &AnyEvent) -> Vec<Alert>;
    fn rule_name(&self) -> &str;
    fn evict_expired(&mut self);  // call every 5s to GC old window state
}


impl StreamEngine {
    pub fn register(&mut self, op: Box<dyn TemporalOperator + Send>) {
        self.operators.push(op);
    }


    /// Fan-out: send event to all temporal operators
    pub fn process_event(&mut self, event: &AnyEvent) -> Vec<Alert> {
        self.operators.iter_mut()
            .flat_map(|op| op.ingest(event))
            .collect()
    }


    /// Background task — call every 5s to expire stale window state
    pub async fn maintenance_loop(&mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            for op in &mut self.operators {
                op.evict_expired();
            }
        }
    }
}



9.3  Fact Store — Cross-Rule Memory
  // olopa-agent/src/fact_store.rs
// olopa-agent/src/fact_store.rs
// Shared fact store — rules emit facts, other rules consume them.
// Thread-safe with DashMap. Automatic expiry via TTL.


use dashmap::DashMap;


pub struct FactStore {
    facts: DashMap<FactKey, FactEntry>,
}


#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FactKey {
    pub fact_name: String,
    pub args:      Vec<String>,  // e.g. ["host-07"]
}


pub struct FactEntry {
    pub value:      bool,
    pub expires_at: Instant,
    pub source_rule: String,
}


impl FactStore {
    /// Called by rule emit clause: emit fact host.compromised(host_id) expires 7d
    pub fn set(&self, fact: FactKey, expires: Duration, source: &str) {
        self.facts.insert(fact, FactEntry {
            value: true,
            expires_at: Instant::now() + expires,
            source_rule: source.to_string(),
        });
    }


    /// Called in where clause or respond condition
    pub fn is_set(&self, fact: &FactKey) -> bool {
        self.facts.get(fact).map_or(false, |e| {
            e.value && e.expires_at > Instant::now()
        })
    }


    /// Background task — call every 60s to purge expired facts
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.facts.retain(|_, v| v.expires_at > now);
    }
}



9.4  Deployment Model — Rule Lifecycle

Stage
Trigger
Mechanism
Downtime
Initial deploy
Agent startup
Load all .so from /etc/olopa/rules/. Register stream operators. Install Cypher triggers.
None
New rule hot-load
olopa rule deploy <file>
Compile OIL → artefact. Drop artefact in /etc/olopa/rules/. Agent inotify watches directory. dlopen new .so.
None
Rule update
olopa rule deploy --replace
Compile new .so. Atomic function pointer swap in RuleEngine. Old .so stays until last reference released.
None
Rule disable
olopa rule disable <name>
Remove function pointer. Cypher trigger dropped. Stream operator deregistered. No agent restart.
None
Rule rollback
olopa rule rollback <name>
Previous .so version re-loaded. Matches versioned artefact store.
None
Emergency kill
olopa rule kill-all
All EPL fns cleared. All stream operators paused. Cypher triggers removed. Agent continues collecting.
None


10. Diagnostics & Error Messages
The OIL compiler produces structured, actionable error messages. Every error includes the source location, the problematic span highlighted, a human-readable message, and where possible a suggested fix. The compiler collects all errors before reporting — a single compilation attempt surfaces all issues.

10.1  Error Categories

Error Code
Category
Description
OIL-L001
Lexer
Unexpected character in source text
OIL-L002
Lexer
Unterminated string literal
OIL-L003
Lexer
Invalid duration unit (use ns/us/ms/s/m/h/d)
OIL-P001
Parser
Unexpected token — expected keyword or expression
OIL-P002
Parser
Missing closing brace or bracket
OIL-P003
Parser
respond clause is required but missing
OIL-P004
Parser
correlate requires at least one "with" arm
OIL-N001
Name resolution
Unknown identifier — not declared as set, predicate, alias, or fact
OIL-N002
Name resolution
Undefined event alias in expression (declared in match but not bound)
OIL-N003
Name resolution
Duplicate rule name in program
OIL-T001
Type checker
Field path does not exist on entity type
OIL-T002
Type checker
Type mismatch: comparing incompatible types
OIL-T003
Type checker
Duration comparison requires both sides to be Duration type
OIL-T004
Type checker
in operator requires right-hand side to be a Set or List type
OIL-T005
Type checker
Aggregation function (count/max/sum) only valid in around or gather context
OIL-S001
Semantic
Temporal rule missing "within" clause — unbounded correlation is not allowed
OIL-S002
Semantic
Graph rule references entity type not in Olopa schema
OIL-S003
Semantic
Score clause modifier out of range (must be in [-100, 100])
OIL-S004
Semantic
Policy "enforce" block missing required severity branch
OIL-S005
Semantic
Isolate action requires a host or network entity — process.id is not valid
OIL-S006
Semantic
Fact expiry must be positive duration
OIL-C001
Codegen
EPL codegen: predicate references graph lookup — use graph rule class instead
OIL-C002
Codegen
Cypher trigger: ML operator (unusual_for) not supported in graph rules


10.2  Example Error Output
  // Compiler diagnostic output examples
// OIL compiler error output — structured, actionable, with source context


error[OIL-T001]: unknown field `process.reputatoin`
  --> rules/webshell.oil:18:9
   |
17 |     where
18 |         p.reputatoin in ["clean", "unknown"]
   |         ^^^^^^^^^^^^ field `reputatoin` does not exist on type Process
   |
   = note: did you mean `p.binary.reputation`?
   = help: available fields on Process: name, uid, elevated, signed, hash,
             risk_score, prevalence, parent, host_id, command_line, container_id




error[OIL-S001]: temporal rule `credential_chain` is missing a `within` clause
  --> rules/cred_chain.oil:5:1
   |
 5 | rule "credential_chain" {
   | ^^^^ correlate rules must declare a time window to prevent unbounded state
   |
   = help: add `within 15m` (or another duration) after the `where` clause
   = note: without a window bound, the stream operator accumulates state forever




error[OIL-T002]: type mismatch in comparison
  --> rules/dns_detect.oil:24:9
   |
24 |         and session.age == "12h"
   |             ^^^^^^^^^^^    ^^^^^ expected Duration, found Str
   |
   = help: remove the quotes: `session.age > 12h`
   = note: duration literals are written without quotes: 15m, 300s, 7d




warning[OIL-W001]: unused alias `n2` in correlate block
  --> rules/exfil.oil:12:8
   |
12 |         with network.connect as n2 on n2.process_id == p.id
   |                              ^^ alias `n2` is never referenced in where or respond
   |
   = note: this may indicate a missing condition; remove the alias or add a predicate



11. OIL Standard Library
The OIL standard library (oil_stdlib) provides pre-declared sets, predicates, and entity schemas that are available to all rules without explicit import. It also provides the built-in function library for path operations, aggregations, and entity lookups.

11.1  Built-in Sets (oil_stdlib/builtins.oil)
  // oil_stdlib/builtins.oil — globally available, no import required
// These sets are globally available — no "use" declaration needed.


// ─── Process classification ──────────────────────────────────────────────
set shells          = ["bash", "sh", "zsh", "fish", "dash", "tcsh",
                       "python3", "python", "perl", "ruby", "node", "php",
                       "powershell", "pwsh", "cmd.exe"]


set web_servers     = ["nginx", "apache2", "httpd", "lighttpd", "gunicorn",
                       "uvicorn", "caddy", "haproxy", "envoy", "traefik"]


set db_servers      = ["postgres", "mysqld", "mongod", "redis-server",
                       "cassandra", "elasticsearch", "clickhouse-server"]


set recon_tools     = ["nmap", "masscan", "ncrack", "hydra", "medusa",
                       "nuclei", "gobuster", "ffuf", "nikto", "sqlmap"]


set exfil_tools     = ["curl", "wget", "nc", "netcat", "socat", "rclone",
                       "rsync", "scp", "ftp", "tftp"]


set sensitive_procs = ["lsass.exe", "winlogon.exe", "csrss.exe", "svchost.exe",
                       "gpg-agent", "ssh-agent", "gpg", "pass"]




// ─── File path sets ──────────────────────────────────────────────────────
set credential_paths = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "~/.aws/credentials", "~/.aws/config",
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys",
    "~/.gnupg/", "/proc/*/mem", "/proc/*/maps"
]


set sensitive_dirs   = ["/etc", "/root", "/proc/1", "/sys/kernel",
                        "/var/shadow", "C:\\Windows\\System32\\config"]


set tmp_dirs         = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm",
                        "C:\\Windows\\Temp", "C:\\Users\\Public"]




// ─── Network port sets ───────────────────────────────────────────────────
set c2_ports         = [4444, 4445, 1337, 31337, 8081, 8082, 9001, 1080]


set well_known_ports = [80, 443, 22, 21, 25, 53, 110, 143, 389, 636,
                        3306, 5432, 6379, 27017, 9200, 8080, 8443]




// ─── Reputation / risk levels ────────────────────────────────────────────
set malicious_reputation  = ["malicious", "known_bad", "blacklisted"]
set suspicious_reputation = ["suspicious", "unknown", "newly_registered"]
set bad_reputation        = ["malicious", "suspicious", "known_bad", "blacklisted"]



11.2  Built-in Predicates (oil_stdlib/predicates.oil)
  // oil_stdlib/predicates.oil — globally available built-in predicates
// ─── Geographic / session predicates ────────────────────────────────────
predicate unusual_country(user, country) =
    country not_in user.baseline.countries


predicate impossible_travel(user, country, ts) =
    unusual_country(user, country)
    and user.last_seen_country != country
    and (ts - user.last_login_ts) < 2h


predicate unusual_host(user, host_id) =
    host_id not_in user.baseline.hosts


predicate unusual_hour(user, ts) =
    ts.hour not_in user.baseline.login_hours




// ─── Process predicates ──────────────────────────────────────────────────
predicate from_tmp(proc) =
    proc.filename under tmp_dirs


predicate unsigned_from_tmp(proc) =
    from_tmp(proc) and proc.signed == false


predicate privileged_shell(proc) =
    proc.name in shells and proc.uid == 0


predicate living_off_the_land(proc) =
    proc.name in recon_tools
    or proc.name in exfil_tools
    or (proc.name in shells and proc.parent.name not_in web_servers)




// ─── Network predicates ──────────────────────────────────────────────────
predicate external_c2(endpoint) =
    endpoint.is_internal == false
    and (endpoint.port in c2_ports or endpoint.reputation in malicious_reputation)


predicate unexpected_external(proc, endpoint) =
    endpoint.is_internal == false
    and endpoint.domain not_in host(proc.host_id).baseline.domains




// ─── Secret / credential predicates ─────────────────────────────────────
predicate sensitive_file(file) =
    file.path in credential_paths
    or file.sensitivity_label in ["crown_jewel", "critical", "sensitive"]


predicate credential_access(proc, file) =
    sensitive_file(file)
    and proc.uid != file.expected_reader_uid



11.3  Built-in Functions

Function
Signature & description
user(id)
user(id: Str) → Entity<User>  — look up a User entity by ID
host(id)
host(id: Str) → Entity<Host>  — look up a Host entity by ID
process(pid, host_id)
process(pid: Int, host_id: Str) → Entity<Process>  — graph lookup
count(alias)
count(alias: EventAlias) → Int  — count events matched in gather/around context
max(field)
max(field: Numeric) → Numeric  — maximum field value across gathered events
min(field)
min(field: Numeric) → Numeric  — minimum field value
sum(field)
sum(field: Numeric) → Numeric  — sum of field values
avg(field)
avg(field: Numeric) → Float  — average field value
distinct(field)
distinct(field) → Int  — count distinct values
first(alias)
first(alias) → Event  — earliest event in window by timestamp
last(alias)
last(alias) → Event  — latest event in window by timestamp
severity_from_score(score)
severity_from_score(score: Int) → Severity  — maps 0-100 to severity level
hash_of(path)
hash_of(path: Path) → Str  — compute file hash (uses cached value if available)
is_canary(entity)
is_canary(entity) → Bool  — true if entity is a graph canary node
process_tree(proc)
process_tree(proc: Entity<Process>) → List<Process>  — ancestor chain


12. Integration with Olopa Platform Architecture
OIL is the unified policy surface for all five Olopa subsystems. This section maps each OIL construct to its runtime location and execution path within the full Olopa stack described in the architecture documents.

12.1  Cross-Stack Execution Map

OIL Construct
Olopa Subsystem
Execution Layer
Latency Budget
EPL hot-path rule (match)
eBPF/XDP + Ring buffer consumer
Compiled .so in eBPF ring consumer on isolated core
15–20ns per event
Temporal correlate rule
Rust agent daemon (Tokio)
Async stream operator in agent; sliding window in RAM
< 50ms from last matched event
Graph structural rule
Memgraph graph DB
AFTER COMMIT trigger; fires on graph write, not polled
< 100ms from graph write
Graph algorithm (PageRank)
Memgraph GDS
Scheduled job every 5–30 min
5min cycle
Policy declaration
Agentic Firewall + OPA
Synchronous policy evaluation per tool call
< 5ms per evaluation
Fact emit
Fact Store (DashMap)
Inline in rule respond block; async write to DashMap
< 1µs
Fact consume (where clause)
Fact Store
Looked up in both EPL rules and stream operators
< 1µs (hash lookup)
Score → severity mapping
Detection Orchestrator
In-process after rule fires; routes to alert pipeline
Inline
Actions: alert/snapshot
Backend via gRPC
Async fan-out via Tokio channel to gRPC sender
< 500ms end-to-end
Actions: isolate/revoke
Response Executor
OPA policy + K8s NetworkPolicy / identity provider API
< 2s end-to-end


12.2  OIL in the Data Flow
  // Olopa platform — OIL execution point annotations
// Olopa full data flow — annotated with OIL execution points


// ────────────────────────────────────────────────────────────────────────
// STAGE 1: Kernel Event Capture (eBPF tracepoints)
//   No OIL here — this is ground truth from the kernel.
//   Events: execve, openat, connect, accept, fork
// ────────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────────
// STAGE 2: XDP / Ring Buffer Consumer
//   OIL EXECUTION POINT: EPL hot-path rules (.so)
//   - "match process.exec" rules evaluate here
//   - Cost budget: 20ns per event
//   - Output: Alert (if fired) or None
// ────────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────────
// STAGE 3: Event Normalisation + OR Scheduler
//   OIL EXECUTION POINT: Temporal stream operators
//   - Normalised events fan-out to all registered stream operators
//   - "correlate" and "match...then" rules run here
//   - "around ... gather" rules accumulate state here
//   - Cost budget: < 50ms per correlation window completion
// ────────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────────
// STAGE 4: Graph Write (Memgraph + CSR)
//   OIL EXECUTION POINT: Cypher triggers
//   - Every new graph edge fires applicable AFTER COMMIT triggers
//   - "graph ... match ... ->" rules execute here
//   - Cost budget: < 100ms from graph write to alert
// ────────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────────
// STAGE 5: Agentic Firewall (Tool Call Interception)
//   OIL EXECUTION POINT: Policy declarations (OPA Rego)
//   - Each tool call evaluates all applicable "policy" declarations
//   - enforce block determines: ALLOW / CHALLENGE / BLOCK
//   - Cost budget: < 5ms synchronous, per tool call
// ────────────────────────────────────────────────────────────────────────


// ────────────────────────────────────────────────────────────────────────
// STAGE 6: Detection Orchestrator (Backend)
//   OIL EXECUTION POINT: Cross-engine alert fusion
//   - Combines EPL alert + stream alert + Cypher alert into one fused alert
//   - GNN inference triggered on flagged subgraphs (not per event)
//   - Fact store updated from emit clauses
//   - Response actions dispatched to action executor
// ────────────────────────────────────────────────────────────────────────



12.3  MITRE ATT&CK Coverage via OIL

MITRE Technique
OIL Rule Class
Detection Mechanism
Example Rule
T1059 — Command & Scripting
EPL HotPath
Shell spawn from trusted process — EPL .so
webshell_spawn_detect
T1021 — Lateral Movement
Graph
Multi-hop credential + LATERAL_MOVE edges
lateral_movement_multi_hop
T1548 — Privilege Escalation
EPL / Graph
uid change to 0 + network connect
priv_esc_then_network
T1552 — Credential Access
Temporal / Graph
Credential file read → exfil chain
credential_access_exfil_chain
T1071 — C2 via DNS
Around/Gather
High-entropy DNS + volume threshold
dns_tunnel_candidate
T1539 — Session Hijacking
Temporal Correlate
Cookie read + network + unusual session
session_hijack_and_exfil
T1567 — Data Exfiltration
Temporal / Graph
Internal file → agent session → external
agentic_exfil_chain
T1611 — Container Escape
Graph
Namespace change edge in graph
container_escape_attempt
LLM01 — Prompt Injection
EPL / Temporal
Untrusted retrieval + denied tool call
prompt_injection_tool_abuse
LLM06 — Excessive Agency
Policy
Tool scope exceeds declared session scope
agent_excessive_scope


13. Implementation Roadmap
The OIL compiler and runtime are designed for phased delivery, aligned with the existing Olopa platform roadmap. Each phase delivers immediate value while building toward the full language capability.

Phase
Timeline
OIL Deliverables
Backend Deliverables
Phase 1 — Lexer + Parser
Weeks 1–4
Complete EBNF grammar. Hand-written lexer. Recursive descent parser. Full AST implementation. Round-trip parse/pretty-print. Comprehensive diagnostic messages.
Unit test harness. OIL playground CLI (parse → print AST). Grammar fuzzer (cargo-fuzz).
Phase 2 — Type Checker + Name Resolution
Weeks 5–8
Entity schema registry. Field path resolution and type inference. Predicate type checking. Set/fact name resolution. All OIL-T* and OIL-N* errors.
Schema definition for all 10 Olopa entity types. Schema versioning. Cross-version type compatibility.
Phase 3 — MIR + EPL Codegen
Weeks 9–13
MIR lowering from typed AST. Predicate pushdown optimizer. Set inlining pass. EPL Rust codegen. Compiled .so hot-load integration with RuleEngine.
First OIL rules in production: webshell, credential_paths, priv_esc hot-path rules. Integration test: OIL source → .so → alert.
Phase 4 — Stream Codegen + Temporal
Weeks 14–18
Stream operator codegen. SlidingWindow<T> generic implementation. Correlate join engine. Around/gather aggregation engine. Temporal MIR optimiser (join key analysis).
Temporal rule deployment. Cross-session correlation replacing manual detection SQL. Fact store integration.
Phase 5 — Cypher Codegen + Graph Rules
Weeks 19–23
Cypher trigger codegen. Graph pattern to Memgraph AFTER COMMIT trigger. Graph schema validation. Cross-layer entity resolution in OIL.
Graph rules replace scheduled detection queries. Kill chain reconstruction via OIL graph rules. Lateral movement detections.
Phase 6 — Policy Codegen + OPA
Weeks 24–27
OPA Rego codegen from Policy declarations. Agentic firewall OIL integration. Policy hot-reload without firewall restart.
OIL policies replace hard-coded Agentic Firewall rules. OWASP LLM Top 10 encoded as OIL policies. Adaptive access control.
Phase 7 — Optimisers + Production
Weeks 28–32
Full optimizer suite: constant folding, dead code elimination, join key hoisting, predicate selectivity estimation. Rule dependency graph (fact emit → consume). Bundle compilation (multiple rules, one .so).
OIL rule marketplace / library. LSP plugin (syntax highlighting, autocomplete, hover docs). VS Code extension. Rule testing framework (replay historical events against OIL rules).


14. OIL vs. Competing Approaches
Security teams have used various DSLs and rule languages to express detection logic. This section positions OIL against each, showing precisely what OIL does that existing approaches cannot.

Approach
What it does
What it cannot do
OIL advantage
Falco / YAML rules
Single-event detection. Field comparisons. Output formatting.
Temporal correlation. Graph traversal. Risk scoring. Response actions. Compiled execution.
OIL supports all Falco patterns plus all the above. And compiles to ~15ns vs ~500ns Falco evaluation.
Sigma rules
Vendor-agnostic detection specification. Converts to SIEM queries.
Graph relationships. Time windows. Risk scoring. Response. Runtime execution.
OIL is executable, not a specification. Sigma is a format. OIL is a compiler.
SIEM correlation rules (Splunk SPL / Elastic EQL)
SQL-like querying over stored event data. Time-based aggregations.
Graph traversal. Sub-50ms latency. Kernel-level observation. Response actions.
OIL evaluates at event ingestion (< 1ms) not after database ingestion (minutes). And it traverses the live graph.
OPA / Rego
Structured allow/deny policy evaluation. Constraint checking.
Temporal event sequences. Graph traversal. Risk scoring. Telemetry correlation.
OIL compiles to Rego for the agentic firewall layer, but adds temporal + graph + scoring on top.
KQL / Kusto
Powerful analytics query language for Microsoft Sentinel.
Real-time evaluation. Graph traversal. Response actions. Non-Microsoft telemetry.
OIL is vendor-neutral, real-time, and produces enforcement actions — not just query results.
YARA
Pattern matching for file/memory signatures.
Behavioural sequences. Network events. Process lineage. Risk scoring. Response.
YARA matches bytes. OIL matches behaviour across time, graph, and multiple signal sources.
DeepTempo log LM
Sequence anomaly scoring over log text.
Graph structure. Deterministic TTP rules. Low latency. Explainability. Action enforcement.
OIL combines deterministic rules + scoring + graph + actions. DeepTempo is a detector only.




The Unification Thesis
OIL is the first language to unify all five concerns in a single compiled artefact:
  (1) Deterministic event filtering — replaces Falco / Sigma / KQL
  (2) Temporal event correlation — replaces SIEM correlation rules
  (3) Graph structural detection — replaces raw Cypher / GDS scripting
  (4) Risk scoring — replaces hand-coded scoring logic
  (5) Enforcement actions — replaces manual playbook YAML

No existing security DSL does more than two of these. OIL does all five.
The compiler handles the routing — security engineers write intent once.




OLOPA Intent Language (OIL) — Formal Specification v1.0  |  CONFIDENTIAL — Engineering
