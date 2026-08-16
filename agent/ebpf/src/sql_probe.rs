//! SQL query uprobes — hooks on the libpq and libmysqlclient entry points that
//! carry statement text.
//!
//! Each uprobe fires on entry, reads the query string, computes an FNV-1a hash,
//! classifies the statement type by leading keyword, and emits a SqlEvent to the
//! shared ring buffer.
//!
//! Entry points carrying statement text directly, by argument position:
//!
//!   arg 1  PQexec(PGconn *, const char *query)
//!          PQexecParams(PGconn *, const char *query, int nParams, ...)
//!          mysql_real_query(MYSQL *, const char *stmt_str, unsigned long len)
//!
//! # Why the `PQsend*` family is deliberately not hooked
//!
//! libpq implements each synchronous call on top of its async twin — `PQexec`
//! runs `PQsendQuery`, `PQexecParams` runs `PQsendQueryParams`. Those internal
//! calls land on the same function entry a uprobe watches, so hooking both
//! layers reports one application query twice and inflates every rate-based
//! rule. Only the top-level API an application calls is hooked. The cost is
//! that a caller using libpq's async API directly is not seen; that is the
//! lesser error, because a missing event is visible while a doubled one is not.
//!
//! The same reasoning excludes `mysql_query`, which delegates to
//! `mysql_real_query`.
//!
//! # Prepared statements
//!
//! A prepared statement splits its text and its executions across two calls:
//!
//!   PQprepare(PGconn *, const char *stmtName, const char *query, ...)
//!   PQexecPrepared(PGconn *, const char *stmtName, ...)
//!   mysql_stmt_prepare(MYSQL_STMT *, const char *stmt_str, unsigned long len)
//!   mysql_stmt_execute(MYSQL_STMT *)
//!
//! Only the prepare sees the SQL, and only the execute is a query actually
//! running. So prepare records the text in `PREPARED_STATEMENTS` without
//! emitting, and execute emits an event carrying the recorded text. Every
//! execution is then counted once and attributed to its tables, and an
//! application that prepares once and executes a thousand times reads as a
//! thousand queries rather than one.
//!
//! The record is keyed by connection handle as well as name, because a
//! statement name is scoped to a connection: two connections in one process
//! may prepare different SQL under the same name.
//!
//! Query classification (query_class):
//!   0 = other / unknown
//!   1 = SELECT (read-only query)
//!   2 = DML (INSERT / UPDATE / DELETE / REPLACE)
//!   3 = DDL (CREATE / DROP / ALTER / TRUNCATE)
//!   4 = ADMIN (GRANT / REVOKE / SET / CALL / EXEC)
//!
//! VERIFIER RULE: after bpf_ringbuf_reserve() succeeds, every exit path must
//! call entry.submit(0) or entry.discard(0). Never use ? after reservation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, uprobe},
    maps::LruHashMap,
    programs::ProbeContext,
};
use olopa_common::{SqlEvent, EVENT_KIND_SQL, SQL_QUERY_LEN};

use crate::EVENTS;

// Scratch buffer size for query text hashing/classification.
// 128 bytes captures enough of most queries while staying stack-friendly.
const QUERY_BUF_LEN: usize = SQL_QUERY_LEN;

/// Bytes of prepared-statement name read for keying. Names are short by
/// convention — drivers emit things like `S_1` or `stmt_17`.
const STMT_NAME_BUF_LEN: usize = 64;

/// Identifies one prepared statement.
///
/// The handle is what makes this precise: a statement name is scoped to a
/// connection, so two connections in one process can prepare different SQL
/// under the same name. `PQprepare`/`PQexecPrepared` both take the `PGconn *`
/// and `mysql_stmt_prepare`/`mysql_stmt_execute` both take the `MYSQL_STMT *`,
/// so each pair agrees on a handle without any extra bookkeeping.
#[repr(C)]
#[derive(Clone, Copy)]
struct PreparedKey {
    pid: u32,
    _pad: u32,
    /// `PGconn *` or `MYSQL_STMT *`.
    handle: u64,
    /// FNV-1a of the statement name. Zero for MySQL, where the handle alone
    /// identifies the statement.
    name_hash: u64,
}

/// Statement text captured at prepare time so an execute can replay it.
#[repr(C)]
#[derive(Clone, Copy)]
struct PreparedStatement {
    query_hash: u32,
    query_class: u8,
    _pad: [u8; 3],
    query: [u8; QUERY_BUF_LEN],
}

/// Prepare-time statement text, keyed by connection and name.
///
/// LRU rather than a plain hash: entries belong to connections that close
/// without notice, so there is no reliable moment to delete one. Eviction
/// under pressure costs table attribution on the evicted statement, which is
/// the acceptable failure — the alternative is insertion failing silently once
/// the map fills and never recovering.
#[map]
static PREPARED_STATEMENTS: LruHashMap<PreparedKey, PreparedStatement> =
    LruHashMap::with_max_entries(8192, 0);

/// Uprobe for libpq entry points whose statement text is argument 1.
/// Attached to `PQexec` and `PQexecParams`.
#[uprobe]
pub fn uprobe_pqexec(ctx: ProbeContext) -> u32 {
    unsafe { try_sql_query(&ctx, 1_usize, 5432) }
}

/// Uprobe for libpq `PQprepare(conn, stmtName, query, ...)`.
///
/// Records the statement instead of emitting an event — the query runs at
/// `PQexecPrepared`, and reporting it here too would count it twice.
#[uprobe]
pub fn uprobe_pqprepare(ctx: ProbeContext) -> u32 {
    unsafe { try_prepare(&ctx, 0_usize, Some(1_usize), 2_usize) }
}

/// Uprobe for libpq `PQexecPrepared(conn, stmtName, ...)`, which carries only
/// the statement's name — its text comes from the prepare-time record.
#[uprobe]
pub fn uprobe_pqexecprepared(ctx: ProbeContext) -> u32 {
    unsafe { try_execute_prepared(&ctx, 0_usize, Some(1_usize), 5432) }
}

/// Uprobe for libmysqlclient `mysql_real_query`, whose text is argument 1.
#[uprobe]
pub fn uprobe_mysql_query(ctx: ProbeContext) -> u32 {
    unsafe { try_sql_query(&ctx, 1_usize, 3306) }
}

/// Uprobe for `mysql_stmt_prepare(stmt, stmt_str, length)`. The `MYSQL_STMT *`
/// handle identifies the statement, so no name is read.
#[uprobe]
pub fn uprobe_mysql_stmt_prepare(ctx: ProbeContext) -> u32 {
    unsafe { try_prepare(&ctx, 0_usize, None, 1_usize) }
}

/// Uprobe for `mysql_stmt_execute(stmt)`.
#[uprobe]
pub fn uprobe_mysql_stmt_execute(ctx: ProbeContext) -> u32 {
    unsafe { try_execute_prepared(&ctx, 0_usize, None, 3306) }
}

/// Build the map key identifying a prepared statement.
///
/// `name_arg` is `None` for MySQL, whose statement handle is already unique.
unsafe fn prepared_key(
    ctx: &ProbeContext,
    handle_arg: usize,
    name_arg: Option<usize>,
) -> Option<PreparedKey> {
    let handle: u64 = ctx.arg(handle_arg)?;
    if handle == 0 {
        return None;
    }

    let name_hash = match name_arg {
        Some(arg) => {
            let name_ptr: u64 = ctx.arg(arg)?;
            if name_ptr == 0 {
                // libpq's unnamed prepared statement passes "" rather than
                // NULL, so a null pointer here is a malformed call.
                return None;
            }
            let mut name = [0u8; STMT_NAME_BUF_LEN];
            let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut name);
            fnv1a_hash64(&name)
        }
        None => 0,
    };

    Some(PreparedKey {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        _pad: 0,
        handle,
        name_hash,
    })
}

/// Record a prepared statement's text for replay at execute time.
///
/// Emits nothing: a prepare is a round trip to the server but not a query
/// execution, and reporting it as one would inflate every operation count.
unsafe fn try_prepare(
    ctx: &ProbeContext,
    handle_arg: usize,
    name_arg: Option<usize>,
    query_arg: usize,
) -> u32 {
    let key = match prepared_key(ctx, handle_arg, name_arg) {
        Some(k) => k,
        None => return 1,
    };

    let query_ptr: u64 = match ctx.arg(query_arg) {
        Some(p) if p != 0 => p,
        _ => return 1,
    };

    let mut value = PreparedStatement {
        query_hash: 0,
        query_class: 0,
        _pad: [0; 3],
        query: [0u8; QUERY_BUF_LEN],
    };
    let _ = bpf_probe_read_user_str_bytes(query_ptr as *const u8, &mut value.query);
    value.query_hash = fnv1a_hash(&value.query);
    value.query_class = classify_query(&value.query);

    let _ = PREPARED_STATEMENTS.insert(&key, &value, 0);
    0
}

/// Emit an event for a prepared-statement execution, filling in the text
/// recorded at prepare time.
///
/// A lookup miss still emits. The execution happened and the process, engine
/// and port are all known; only the statement text is not. Dropping the event
/// would hide real database activity, so it goes out with empty text and
/// userspace resolves no tables for it — which is exactly what an unresolvable
/// statement should look like. Misses are expected whenever the agent starts
/// after an application has already prepared its statements, as connection
/// pools do.
unsafe fn try_execute_prepared(
    ctx: &ProbeContext,
    handle_arg: usize,
    name_arg: Option<usize>,
    default_port: u16,
) -> u32 {
    let key = match prepared_key(ctx, handle_arg, name_arg) {
        Some(k) => k,
        None => return 1,
    };

    let mut entry = match EVENTS.reserve::<SqlEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After reservation every exit path must submit or discard.
    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_SQL;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();
    (*event).pid = key.pid;
    (*event).uid = bpf_get_current_uid_gid() as u32;
    (*event).db_port = default_port;
    (*event)._pad = 0;
    (*event).query = [0u8; QUERY_BUF_LEN];

    (*event).comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    match PREPARED_STATEMENTS.get(&key) {
        Some(stored) => {
            (*event).query = stored.query;
            (*event).query_hash = stored.query_hash;
            (*event).query_class = stored.query_class;
        }
        None => {
            (*event).query_hash = 0;
            (*event).query_class = 0;
        }
    }

    entry.submit(0);
    0
}

/// Common handler for SQL client uprobes that carry statement text directly.
///
/// # Arguments
/// * `query_arg` — zero-based index of the `const char *query` argument.
/// * `default_port` — well-known port for the DB type (used as `db_port`).
unsafe fn try_sql_query(ctx: &ProbeContext, query_arg: usize, default_port: u16) -> u32 {
    let mut entry = match EVENTS.reserve::<SqlEvent>(0) {
        Some(e) => e,
        None => return 1,
    };

    // After reservation every exit path must submit or discard.
    let event = entry.as_mut_ptr();

    (*event).kind = EVENT_KIND_SQL;
    (*event).ts_ns = bpf_ktime_get_ns();
    (*event).cgroup_id = bpf_get_current_cgroup_id();

    let pid_tgid = bpf_get_current_pid_tgid();
    (*event).pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    (*event).uid = uid_gid as u32;

    (*event).comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            entry.discard(0);
            return 1;
        }
    };

    // Read the query string pointer from the function argument list.
    let query_ptr: u64 = match ctx.arg(query_arg) {
        Some(p) => p,
        None => {
            entry.discard(0);
            return 1;
        }
    };

    if query_ptr == 0 {
        entry.discard(0);
        return 1;
    }

    // Copy statement text straight into the ring-buffer slot: userspace needs
    // it to resolve table names, and reading it here avoids a second stack
    // buffer. The text is raw and may contain literals — userspace redacts it
    // at decode time and never forwards it.
    //
    // Zero first: a failed read leaves the slot holding whatever the ring
    // buffer last had there, which would ship stale bytes from another event.
    (*event).query = [0u8; QUERY_BUF_LEN];
    let _ = bpf_probe_read_user_str_bytes(query_ptr as *const u8, &mut (*event).query);

    // Borrow the slot rather than copying it — a by-value read would put a
    // second QUERY_BUF_LEN buffer on the 512-byte verifier stack, which is the
    // cost this in-place read exists to avoid.
    let buf = &(*event).query;
    (*event).query_hash = fnv1a_hash(buf);
    (*event).query_class = classify_query(buf);
    (*event).db_port = default_port;
    (*event)._pad = 0;

    entry.submit(0);
    0
}

/// FNV-1a 64-bit hash of a prepared statement name.
///
/// 64-bit rather than 32-bit because this one feeds a map key: a collision
/// would replay the wrong statement's text under another statement's name,
/// producing a confidently wrong table list. That is worse than no answer, so
/// the width is chosen to make it not happen.
#[inline(always)]
fn fnv1a_hash64(buf: &[u8; STMT_NAME_BUF_LEN]) -> u64 {
    const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;

    let mut hash = OFFSET_BASIS;
    let mut i = 0usize;

    // Bounded loop — verifier sees at most STMT_NAME_BUF_LEN iterations.
    while i < STMT_NAME_BUF_LEN {
        let b = buf[i];
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

/// FNV-1a 32-bit hash over a fixed-size byte slice.
///
/// Only hashes bytes up to the first NUL terminator so that padding bytes
/// do not influence the result.
#[inline(always)]
fn fnv1a_hash(buf: &[u8; QUERY_BUF_LEN]) -> u32 {
    const OFFSET_BASIS: u32 = 2_166_136_261;
    const PRIME: u32 = 16_777_619;

    let mut hash = OFFSET_BASIS;
    let mut i = 0usize;

    // Bounded loop — verifier sees at most QUERY_BUF_LEN iterations.
    while i < QUERY_BUF_LEN {
        let b = buf[i];
        if b == 0 {
            break;
        }
        hash ^= b as u32;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

/// Classify query by the ASCII value of the first non-whitespace character,
/// with a secondary check on bytes 1-5 to distinguish DDL from DML.
///
/// Returns:
///   0 = other, 1 = select, 2 = dml, 3 = ddl, 4 = admin
#[inline(always)]
fn classify_query(buf: &[u8; QUERY_BUF_LEN]) -> u8 {
    // Skip leading whitespace to find the first keyword character.
    let mut start = 0usize;
    while start < QUERY_BUF_LEN {
        let b = buf[start];
        if b != b' ' && b != b'\t' && b != b'\n' && b != b'\r' {
            break;
        }
        start += 1;
    }

    if start >= QUERY_BUF_LEN {
        return 0;
    }

    // Normalise to uppercase for case-insensitive comparison.
    let first = buf[start] & 0xDF; // ASCII upper via bit-mask

    match first {
        // S → SELECT
        b'S' => 1,
        // I → INSERT, U → UPDATE, D → DELETE / DROP
        b'I' | b'U' => 2,
        // D — could be DELETE (DML) or DROP (DDL).
        // Peek at byte start+1: 'R' means DROP.
        b'D' => {
            if start + 1 < QUERY_BUF_LEN {
                let second = buf[start + 1] & 0xDF;
                if second == b'R' {
                    3 // DROP
                } else {
                    2 // DELETE
                }
            } else {
                2
            }
        }
        // C → CREATE, A → ALTER
        b'C' | b'A' => 3,
        // T → TRUNCATE (DDL)
        b'T' => 3,
        // G → GRANT, R → REVOKE, E → EXEC/EXECUTE
        b'G' | b'R' | b'E' => 4,
        _ => 0,
    }
}
