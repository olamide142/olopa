//! SQL query uprobes — hooks on the libpq and libmysqlclient entry points that
//! carry statement text.
//!
//! Each uprobe fires on entry, reads the query string, computes an FNV-1a hash,
//! classifies the statement type by leading keyword, and emits a SqlEvent to the
//! shared ring buffer.
//!
//! There are two handlers, differing only in which argument holds the statement:
//!
//!   arg 1  PQexec(PGconn *, const char *query)
//!          PQexecParams(PGconn *, const char *query, int nParams, ...)
//!          mysql_real_query(MYSQL *, const char *stmt_str, unsigned long len)
//!          mysql_stmt_prepare(MYSQL_STMT *, const char *stmt_str, unsigned long len)
//!   arg 2  PQprepare(PGconn *, const char *stmtName, const char *query, ...)
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
//! `PQprepare` and `mysql_stmt_prepare` are hooked, so a prepared statement's
//! tables are attributed at prepare time. The matching execute calls
//! (`PQexecPrepared`, `mysql_stmt_execute`) carry only a statement name or
//! handle, so they are not yet hooked: counting them needs prepare-time state
//! keyed by that name. Table visibility is therefore correct for prepared
//! statements while execution counts are not.
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
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::uprobe,
    programs::ProbeContext,
};
use olopa_common::{SqlEvent, EVENT_KIND_SQL, SQL_QUERY_LEN};

use crate::EVENTS;

// Scratch buffer size for query text hashing/classification.
// 128 bytes captures enough of most queries while staying stack-friendly.
const QUERY_BUF_LEN: usize = SQL_QUERY_LEN;

/// Uprobe for libpq entry points whose statement text is argument 1.
/// Attached to `PQexec` and `PQexecParams`.
#[uprobe]
pub fn uprobe_pqexec(ctx: ProbeContext) -> u32 {
    unsafe { try_sql_query(&ctx, 1_usize, 5432) }
}

/// Uprobe for libpq `PQprepare`, whose statement text is argument 2 —
/// argument 1 is the prepared statement's name.
#[uprobe]
pub fn uprobe_pqprepare(ctx: ProbeContext) -> u32 {
    unsafe { try_sql_query(&ctx, 2_usize, 5432) }
}

/// Uprobe for libmysqlclient entry points whose statement text is argument 1.
/// Attached to `mysql_real_query` and `mysql_stmt_prepare`.
#[uprobe]
pub fn uprobe_mysql_query(ctx: ProbeContext) -> u32 {
    unsafe { try_sql_query(&ctx, 1_usize, 3306) }
}

/// Common handler for every SQL client uprobe.
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
