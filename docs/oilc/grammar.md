# OIL Grammar (Implemented in `oilc` Today)

This document describes the grammar currently accepted by the Rust parser in:

- `src/parser/mod.rs`
- `src/lexer/mod.rs`
- `src/lexer/enums.rs`

It is intentionally the **implemented subset**, not the broader language vision.

## Lexical Notes

- Identifiers: `foo`, `process`, `network.flow`, `user_id`
- Strings: `"text"` (supports escapes like `\"`, `\n`, `\t`)
- Numbers: `123`, `45.6`
- Durations: `15m`, `300s`, `1h`, `7d` (`ns|us|ms|s|m|h|d`)
- Comments:
  - `# line comment`
  - `// line comment`
  - `/* block comment */`

## EBNF (Implemented Subset)

```ebnf
program         = { newline | top_decl } EOF ;

top_decl        = import_decl
                | set_decl
                | predicate_decl
                | fact_decl
                | rule_decl ;

import_decl     = ("use" | "import") dotted_path ;

set_decl        = "set" ident "=" "[" [ set_value { "," set_value } ] "]" ;
set_value       = string | int | float | ident | bool | "null" | duration ;

predicate_decl  = "predicate" dotted_name "(" [ param_list ] ")" "=" expr ;
fact_decl       = "fact" dotted_name "(" [ param_list ] ")" [ "expires" duration ] ;
param_list      = ident { "," ident } ;

rule_decl       = "rule" (string | ident) "{" { rule_clause } "}" ;

rule_clause     = from_clause
                | match_clause
                | correlate_clause
                | graph_clause
                | around_clause
                | where_clause
                | within_clause
                | let_clause
                | score_clause
                | require_clause
                | verify_clause
                | emit_clause
                | respond_clause ;

from_clause     = ("from" | "source") source_spec { "," source_spec } ;
source_spec     = event_pattern [ "as" ident ] ;

match_clause    = "match" match_step { "then" match_step } ;
match_step      = event_pattern
                  [ "as" ident ]
                  [ "by" ident [ "as" ident ] ] ;

correlate_clause= "correlate" correlate_arm { "with" correlate_arm } ;
correlate_arm   = event_pattern "as" ident [ correlate_join ] ;
correlate_join  = "on" expr | "by" ident [ "as" ident ] ;

graph_clause    = "graph" source_spec "{"
                  { graph_pattern [ "," ] }
                  "}" ;
graph_pattern   = name_atom "as" ident [ "->" name_atom ] ;

around_clause   = "around" dotted_name [ "within" ] duration "{"
                  { gather_arm [ "," ] }
                  "}" ;
gather_arm      = event_pattern "as" ident ;

where_clause    = "where" expr ;
within_clause   = "within" duration ;

let_clause      = "let" { ident "=" expr } ;

score_clause    = "score" int { ("+" | "-") int [ "if" expr ] } ;

require_clause  = "require" expr { [ "and" ] expr } ;

verify_clause   = "verify"
                  "require" dotted_name
                  { [ "," ] "require" dotted_name } ;

emit_clause     = "emit" emit_stmt { [ "," ] emit_stmt } ;
emit_stmt       = [ "fact" ] dotted_name "(" [ expr { "," expr } ] ")"
                  [ "expires" duration ] ;

respond_clause  = "respond" (respond_if_chain | inline_actions) ;
respond_if_chain= "if" expr "{" actions "}"
                  { "else" "if" expr "{" actions "}" }
                  [ "else" "{" actions "}" ] ;
inline_actions  = action_stmt { action_stmt } ;
actions         = { action_stmt } ;

action_stmt     = alert_action
                | isolate_action
                | revoke_action
                | snapshot_action
                | open_case_action
                | challenge_action
                | require_mfa_action
                | quarantine_action
                | block_egress_action
                | notify_action
                | throttle_action ;

alert_action    = "alert" severity [ string ] ;
severity        = "critical" | "high" | "medium" | "low" | "informational" ;

isolate_action  = "isolate" ("host" | "network" | "process") ;
revoke_action   = "revoke" ("session" | "token" | "credential") ;
snapshot_action = "snapshot" snapshot_target { "," snapshot_target } ;
snapshot_target = dotted_name [ "(" [ expr { "," expr } ] ")" ] ;
open_case_action= "open_case" string | "open" "case" string ;
challenge_action= "challenge" "mfa" ;
require_mfa_action = "require_mfa" [ "for" ] dotted_name ;
quarantine_action  = "quarantine" dotted_name ;
block_egress_action= "block" "egress" dotted_name ;
notify_action      = "notify" string ;
throttle_action    = "throttle" dotted_name ;

event_pattern   = name_atom "." name_atom ;
name_atom       = ident | "use" ;

dotted_path     = ident { "." ident } ;
dotted_name     = ident { "." ident } ;

expr            = or_expr ;
or_expr         = and_expr { "or" and_expr } ;
and_expr        = cmp_expr { "and" cmp_expr } ;
cmp_expr        = add_expr { cmp_op add_expr } ;
add_expr        = mul_expr { ("+" | "-") mul_expr } ;
mul_expr        = unary_expr { ("*" | "/") unary_expr } ;
cmp_op          = "==" | "!=" | "<" | ">" | "<=" | ">="
                | "in" | "not" "in"
                | "contains" | "starts_with" | "ends_with"
                | "matches" | "under" ;

unary_expr      = [ "not" | "-" ] unary_expr | primary_expr ;
primary_expr    = int | float | string | duration | bool | "null"
                | list_expr
                | call_or_path
                | "(" expr ")" ;

list_expr       = "[" [ expr { "," expr } ] "]" ;

call_or_path    = ident_path [ call_suffix ] ;
ident_path      = ident { "." ident } ;
call_suffix     = "(" [ expr { "," expr } ] ")" { "." ident } ;

bool            = "true" | "false" ;
duration        = int ("ns" | "us" | "ms" | "s" | "m" | "h" | "d") ;
```

## Clause and Keyword Reference

This section explains what each implemented clause/keyword does in practice.

### Top-level declarations

| Keyword / Clause | What it means | Example |
|---|---|---|
| `use`, `import` | Import a dotted path reference into the compilation unit. | `use std.lib.security` |
| `set` | Define a named literal set you can use in membership checks. | `set blocked_domains = ["evil.com", "bad.io"]` |
| `predicate` | Define a reusable expression with parameters. | `predicate suspicious(p) = p.name starts_with "bash"` |
| `fact` | Define a fact signature (optionally with expiry metadata). | `fact process.risky(pid) expires 1h` |
| `rule` | Define one detection/enforcement unit with clauses and actions. | `rule "outbound_guard" { ... }` |

### Rule body clauses

| Keyword / Clause | What it means | Example |
|---|---|---|
| `from`, `source` | Declare event source(s) used by the rule. | `from endpoint.process, network.flow` |
| `match` | Define an ordered sequence of event-pattern steps. | `match process.spawn as p then network.connect as n` |
| `then` | Link additional `match` steps in order. | `... then network.connect as n` |
| `correlate` | Define multi-arm correlation logic. | `correlate process.spawn as p with network.connect as n ...` |
| `graph` | Define graph-shaped rule body with a root source and entity pattern list. | `graph endpoint.process as p { process as proc }` |
| `around` | Define an entity-anchored temporal gather body. | `around host.id within 5m { process.spawn as p }` |
| `with` | Add another correlate arm. | `with network.connect as n` |
| `as` | Alias an event/variable for later references. | `process.spawn as p` |
| `on` | Provide explicit join predicate between correlate arms. | `... with network.connect as n on p.pid == n.pid` |
| `by` | Join/correlate by a variable identifier. | `... by pid` |
| `where` | Main boolean filter predicate. | `where n.direction == "outbound"` |
| `within` | Bound temporal window for chain/correlation. | `within 5m` |
| `let` | Define local computed bindings inside rule scope. | `let burst = n.bytes > 500000` |
| `score` | Define base score and conditional modifiers. | `score 60 + 20 if burst` |
| `if` | Conditional branch in score modifiers or respond branches. | `+ 10 if p.uid == 0` |
| `require` | Add required conditions (currently parser/runtime subset). | `require p.uid != 0 and p.name != "systemd"` |
| `verify` | Declare required verification paths (e.g., `require x.y`). | `verify require user.device.trusted` |
| `emit` | Emit fact statements from a matched rule. | `emit fact process.risky(p.pid) expires 1h` |
| `fact` (inside `emit`) | Optional prefix for emitted fact statement. | `emit fact auth.anomaly(u.id)` |
| `expires` | Attach expiry duration to fact declarations/emits. | `expires 24h` |
| `respond` | Define response actions (inline or branch-based). | `respond alert high` |
| `else` | Alternate branch in `respond if/else` chains. | `else { alert medium }` |

### Response action keywords

| Keyword / Clause | What it means | Example |
|---|---|---|
| `alert` | Raise an alert with a severity (optional message). | `alert critical "web shell"` |
| `critical`, `high`, `medium`, `low`, `informational` | Alert severities accepted by parser/runtime. | `alert high` |
| `isolate` | Isolate a target kind. | `isolate host` |
| `revoke` | Revoke auth material type. | `revoke token` |
| `snapshot` | Capture one or more snapshot targets. | `snapshot process.tree(p.pid)` |
| `open_case` / `open case` | Open a case with title text. | `open_case "Credential abuse"` |
| `challenge` | Challenge flow (currently `mfa`). | `challenge mfa` |
| `require_mfa` | Require step-up auth for a target. | `require_mfa for user.account` |
| `quarantine` | Quarantine path/target. | `quarantine file.path` |
| `block egress` | Block outbound path/target. | `block egress n.dest.domain` |
| `notify` | Send notification text. | `notify "SOC page now"` |
| `throttle` | Throttle a target path. | `throttle process.pid` |

### Expression keywords and literals

| Keyword / Clause | What it means | Example |
|---|---|---|
| `and`, `or` | Boolean combinators. | `a and b or c` |
| `not` | Unary negation and part of `not in`. | `not trusted` / `x not in ["a"]` |
| `in`, `not in` | Membership checks. | `domain in blocked_domains` |
| `contains` | Substring or collection containment check. | `p.cmdline contains "curl"` |
| `starts_with` | Prefix check. | `p.path starts_with "/tmp"` |
| `ends_with` | Suffix check. | `file.path ends_with ".sh"` |
| `matches` | Pattern match operator (runtime supports wildcard `*`/`?` and grouped alternation like `(a|b|c)`). | `p.name matches "ba*"` |
| `under` | Path/prefix ancestry-style check. | `file.path under "/etc"` |
| `true`, `false` | Boolean literals. | `where is_admin == true` |
| `null` | Null literal. | `where maybe_value == null` |
| duration units `ns/us/ms/s/m/h/d` | Duration suffixes for time literals. | `within 10m`, `expires 24h` |

## Operator Precedence

Highest to lowest:

1. Prefix: `not`, unary `-`
2. Multiplicative: `*`, `/`
3. Additive: `+`, `-`
4. Comparison/membership/string operators:
   - `== != < > <= >=`
   - `in`, `not in`
   - `contains`, `starts_with`, `ends_with`, `matches`, `under`
5. `and`
6. `or`
