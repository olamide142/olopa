# SQL Semantic Enforcement

Olopa blocks SQL at the client-library boundary, before the real PostgreSQL or
MySQL function is called. Kernel uprobes remain the zero-configuration
visibility path; they cannot safely cancel a query after userspace evaluation.

## Supported path

The `olopa-sql-guard` preload library covers:

- PostgreSQL `PQexec`, `PQexecParams`, `PQsendQuery`, `PQsendQueryParams`,
  `PQexecPrepared`, and `PQsendQueryPrepared`.
- MySQL `mysql_query`, `mysql_real_query`, and `mysql_stmt_execute`.
- Prepared statement text captured by `PQprepare` and `mysql_stmt_prepare`, then
  evaluated once per execution.

The guard sends a bounded request to `/run/olopa/sql-policy.sock`. The agent
authenticates the process using Unix peer credentials, redacts the statement,
derives database/table fields, evaluates normal runtime-IR, records telemetry,
and returns an allow or block verdict. Raw statement text is never logged or
persisted.

## Build

```bash
cargo build --manifest-path agent/Cargo.toml -p olopa-sql-guard
cargo run --manifest-path oilc/Cargo.toml -- \
  --source oilc/src/rules/sql_finance_guard.oil \
  --emit-runtime-ir /tmp/sql-finance-runtime-ir.json \
  --mode runtime-ir
```

The preload library is written to:

```text
agent/target/debug/libolopa_sql_guard.so
```

## Observe first

Start the agent without SQL uprobes for processes using the guard. Enabling
both mechanisms records guarded allowed queries twice.

```bash
sudo env \
  OLOPA_RUNTIME_IR=/tmp/sql-finance-runtime-ir.json \
  OLOPA_SQL_POLICY_ENABLED=1 \
  OLOPA_SQL_POLICY_MODE=observe \
  OLOPA_SQL_POLICY_SOCKET=/run/olopa/sql-policy.sock \
  agent/target/debug/olopa --iface lo --probe-events fork,exec,file,net
```

Launch the protected process with the guard:

```bash
LD_PRELOAD="$PWD/agent/target/debug/libolopa_sql_guard.so" \
OLOPA_SQL_POLICY_SOCKET=/run/olopa/sql-policy.sock \
untrusted-worker
```

Observe mode returns allow but records `sql_policy_verdict=would_block` when a
selected response branch contains `block query`. Queries without that action
record `sql_policy_verdict=allowed`.

## Enforce

After validating matches, restart the agent with:

```bash
OLOPA_SQL_POLICY_MODE=enforce
```

The same compiled policy now returns a denial before the real client function.
Blocked PostgreSQL calls return `NULL`; blocked asynchronous PostgreSQL calls
return `0`; blocked MySQL calls return a nonzero result. Telemetry records
`sql_policy_verdict=blocked`.

The guard defaults to fail open if the agent socket is absent, saturated, or
times out. Workloads that must stop during a policy outage can set:

```bash
OLOPA_SQL_GUARD_FAIL_CLOSED=1
```

Use fail closed only after proving agent availability and application error
handling. A prepared execution whose prepare happened before the guard loaded
is treated as a policy error and follows this same fail-open/fail-closed choice.

## Policy example

`oilc/src/rules/sql_finance_guard.oil` demonstrates the new action:

```oil
respond if score >= 90 {
  alert critical "Untrusted process attempted to read the finance ledger"
  block query q.tables
}
```

Only the first selected response branch controls enforcement, matching the
existing runtime response semantics.

## Operations and security

- The socket is created with mode `0660`. Set `OLOPA_SQL_POLICY_GID` to the
  numeric group ID shared by protected workloads, or set ownership as part of
  service startup.
- Keep the socket local. Do not expose it through TCP or a world-writable shared
  mount.
- Requests are capped at 8 KiB and the service uses a bounded queue and worker
  count.
- `OLOPA_SQL_POLICY_WORKERS`, `OLOPA_SQL_POLICY_QUEUE_CAPACITY`, and
  `OLOPA_SQL_POLICY_TIMEOUT_MS` tune the agent service.
- `OLOPA_SQL_GUARD_TIMEOUT_MS` tunes the client-side deadline where the host
  permits socket timeouts.
- `make sql-guard-smoke` proves that denials skip the real function across the
  supported API families.

## Limits

- This release supports dynamically linked native libpq and MySQL clients on
  Linux. Static binaries, musl binaries, JDBC, Go native drivers, and clients
  that bypass these APIs remain observe-only unless separately integrated.
- PostgreSQL returns the documented null failure shape, but the guard does not
  fabricate a server error message. Applications must already handle client
  failures.
- The bounded prepared-statement cache is process-local. It is not shared across
  forks and is cleared when the process exits.
- Real PostgreSQL and MySQL integration validation remains required for each
  distribution/client version placed on the production support matrix.
