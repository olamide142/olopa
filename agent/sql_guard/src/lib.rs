//! `LD_PRELOAD` guard for PostgreSQL libpq and MySQL client APIs.
//!
//! Every execution asks the local Olopa agent for a synchronous policy verdict
//! before forwarding to the real client function. A block returns the native
//! API's failure shape and never calls the next symbol. Prepared statement text
//! is cached at prepare time and rechecked on every execution.

use std::cell::Cell;
use std::collections::HashMap;
use std::env;
use std::ffi::{c_char, c_int, c_ulong, c_void, CStr};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use olopa_common::{
    SQL_POLICY_ENGINE_MYSQL, SQL_POLICY_ENGINE_POSTGRES, SQL_POLICY_FLAG_PREPARED,
    SQL_POLICY_MAX_QUERY_LEN, SQL_POLICY_REQUEST_HEADER_LEN, SQL_POLICY_REQUEST_MAGIC,
    SQL_POLICY_RESPONSE_LEN, SQL_POLICY_RESPONSE_MAGIC, SQL_POLICY_VERDICT_ALLOW,
    SQL_POLICY_VERDICT_BLOCK,
};

const DEFAULT_SOCKET_PATH: &str = "/run/olopa/sql-policy.sock";
const DEFAULT_TIMEOUT_MS: u64 = 250;
const MAX_PREPARED_STATEMENTS: usize = 8192;

type PgConn = c_void;
type PgResult = c_void;
type Mysql = c_void;
type MysqlStmt = c_void;
type Oid = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Block,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct PgPreparedKey {
    connection: usize,
    name: Vec<u8>,
}

static PG_PREPARED: OnceLock<Mutex<HashMap<PgPreparedKey, Vec<u8>>>> = OnceLock::new();
static MYSQL_PREPARED: OnceLock<Mutex<HashMap<usize, Vec<u8>>>> = OnceLock::new();

thread_local! {
    /// Prevent a public client function called by another wrapped function
    /// from producing a second policy request.
    static FORWARDING: Cell<bool> = const { Cell::new(false) };
}

fn pg_prepared() -> &'static Mutex<HashMap<PgPreparedKey, Vec<u8>>> {
    PG_PREPARED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn mysql_prepared() -> &'static Mutex<HashMap<usize, Vec<u8>>> {
    MYSQL_PREPARED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_forwarding<T>(call: impl FnOnce() -> T) -> T {
    FORWARDING.with(|forwarding| {
        let previous = forwarding.replace(true);
        let output = call();
        forwarding.set(previous);
        output
    })
}

fn is_forwarding() -> bool {
    FORWARDING.with(Cell::get)
}

fn policy_decision(engine: u8, flags: u8, query: &[u8]) -> Decision {
    match request_verdict(&socket_path(), engine, flags, query, timeout()) {
        Ok(decision) => decision,
        Err(_) if fail_closed() => Decision::Block,
        Err(_) => Decision::Allow,
    }
}

fn request_verdict(
    socket: &Path,
    engine: u8,
    flags: u8,
    query: &[u8],
    timeout: Duration,
) -> Result<Decision, &'static str> {
    let stream = UnixStream::connect(socket).map_err(|_| "connect")?;
    exchange_verdict(stream, engine, flags, query, timeout)
}

fn exchange_verdict(
    mut stream: UnixStream,
    engine: u8,
    flags: u8,
    query: &[u8],
    timeout: Duration,
) -> Result<Decision, &'static str> {
    let request = encode_request(engine, flags, query)?;
    // Some sandboxed runtimes reject SO_RCVTIMEO/SO_SNDTIMEO even for a
    // connected local socket. The agent-side deadline remains authoritative;
    // use kernel socket deadlines where the host permits them.
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream.write_all(&request).map_err(|_| "write request")?;

    let mut response = [0u8; SQL_POLICY_RESPONSE_LEN];
    stream
        .read_exact(&mut response)
        .map_err(|_| "read response")?;
    decode_response(&response)
}

fn encode_request(engine: u8, flags: u8, query: &[u8]) -> Result<Vec<u8>, &'static str> {
    if query.is_empty() || query.len() > SQL_POLICY_MAX_QUERY_LEN {
        return Err("query length");
    }
    let mut request = vec![0u8; SQL_POLICY_REQUEST_HEADER_LEN + query.len()];
    request[..8].copy_from_slice(&SQL_POLICY_REQUEST_MAGIC);
    request[8] = engine;
    request[9] = flags;
    request[12..16].copy_from_slice(&(query.len() as u32).to_le_bytes());
    request[SQL_POLICY_REQUEST_HEADER_LEN..].copy_from_slice(query);
    Ok(request)
}

fn decode_response(response: &[u8; SQL_POLICY_RESPONSE_LEN]) -> Result<Decision, &'static str> {
    if response[..8] != SQL_POLICY_RESPONSE_MAGIC {
        return Err("response magic");
    }
    match response[8] {
        SQL_POLICY_VERDICT_ALLOW => Ok(Decision::Allow),
        SQL_POLICY_VERDICT_BLOCK => Ok(Decision::Block),
        _ => Err("response verdict"),
    }
}

fn socket_path() -> PathBuf {
    env::var("OLOPA_SQL_POLICY_SOCKET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH))
}

fn timeout() -> Duration {
    let milliseconds = env::var("OLOPA_SQL_GUARD_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .max(1);
    Duration::from_millis(milliseconds)
}

fn fail_closed() -> bool {
    env::var("OLOPA_SQL_GUARD_FAIL_CLOSED").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

unsafe fn c_string<'a>(pointer: *const c_char) -> Option<&'a [u8]> {
    (!pointer.is_null()).then(|| CStr::from_ptr(pointer).to_bytes())
}

unsafe fn counted_bytes<'a>(pointer: *const c_char, length: usize) -> Option<&'a [u8]> {
    if pointer.is_null() || length == 0 {
        None
    } else {
        Some(slice::from_raw_parts(pointer.cast::<u8>(), length))
    }
}

unsafe fn next_symbol<T: Copy>(name: &'static [u8]) -> Option<T> {
    let pointer = libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast());
    if pointer.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy::<*mut c_void, T>(&pointer))
    }
}

fn remember_pg(connection: *mut PgConn, name: &[u8], query: &[u8]) {
    if query.len() > SQL_POLICY_MAX_QUERY_LEN {
        return;
    }
    let mut cache = pg_prepared()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.len() >= MAX_PREPARED_STATEMENTS {
        cache.clear();
    }
    cache.insert(
        PgPreparedKey {
            connection: connection as usize,
            name: name.to_vec(),
        },
        query.to_vec(),
    );
}

fn lookup_pg(connection: *mut PgConn, name: &[u8]) -> Option<Vec<u8>> {
    pg_prepared()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&PgPreparedKey {
            connection: connection as usize,
            name: name.to_vec(),
        })
        .cloned()
}

fn remember_mysql(statement: *mut MysqlStmt, query: &[u8]) {
    if query.len() > SQL_POLICY_MAX_QUERY_LEN {
        return;
    }
    let mut cache = mysql_prepared()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.len() >= MAX_PREPARED_STATEMENTS {
        cache.clear();
    }
    cache.insert(statement as usize, query.to_vec());
}

fn lookup_mysql(statement: *mut MysqlStmt) -> Option<Vec<u8>> {
    mysql_prepared()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&(statement as usize))
        .cloned()
}

type PqExecFn = unsafe extern "C" fn(*mut PgConn, *const c_char) -> *mut PgResult;

#[no_mangle]
pub unsafe extern "C" fn PQexec(connection: *mut PgConn, query: *const c_char) -> *mut PgResult {
    let Some(real) = next_symbol::<PqExecFn>(b"PQexec\0") else {
        return std::ptr::null_mut();
    };
    if !is_forwarding()
        && c_string(query).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_POSTGRES, 0, statement) == Decision::Block
        })
    {
        return std::ptr::null_mut();
    }
    with_forwarding(|| real(connection, query))
}

type PqExecParamsFn = unsafe extern "C" fn(
    *mut PgConn,
    *const c_char,
    c_int,
    *const Oid,
    *const *const c_char,
    *const c_int,
    *const c_int,
    c_int,
) -> *mut PgResult;

#[no_mangle]
pub unsafe extern "C" fn PQexecParams(
    connection: *mut PgConn,
    command: *const c_char,
    parameter_count: c_int,
    parameter_types: *const Oid,
    parameter_values: *const *const c_char,
    parameter_lengths: *const c_int,
    parameter_formats: *const c_int,
    result_format: c_int,
) -> *mut PgResult {
    let Some(real) = next_symbol::<PqExecParamsFn>(b"PQexecParams\0") else {
        return std::ptr::null_mut();
    };
    if !is_forwarding()
        && c_string(command).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_POSTGRES, 0, statement) == Decision::Block
        })
    {
        return std::ptr::null_mut();
    }
    with_forwarding(|| {
        real(
            connection,
            command,
            parameter_count,
            parameter_types,
            parameter_values,
            parameter_lengths,
            parameter_formats,
            result_format,
        )
    })
}

type PqSendQueryFn = unsafe extern "C" fn(*mut PgConn, *const c_char) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn PQsendQuery(connection: *mut PgConn, query: *const c_char) -> c_int {
    let Some(real) = next_symbol::<PqSendQueryFn>(b"PQsendQuery\0") else {
        return 0;
    };
    if !is_forwarding()
        && c_string(query).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_POSTGRES, 0, statement) == Decision::Block
        })
    {
        return 0;
    }
    with_forwarding(|| real(connection, query))
}

type PqSendQueryParamsFn = unsafe extern "C" fn(
    *mut PgConn,
    *const c_char,
    c_int,
    *const Oid,
    *const *const c_char,
    *const c_int,
    *const c_int,
    c_int,
) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn PQsendQueryParams(
    connection: *mut PgConn,
    command: *const c_char,
    parameter_count: c_int,
    parameter_types: *const Oid,
    parameter_values: *const *const c_char,
    parameter_lengths: *const c_int,
    parameter_formats: *const c_int,
    result_format: c_int,
) -> c_int {
    let Some(real) = next_symbol::<PqSendQueryParamsFn>(b"PQsendQueryParams\0") else {
        return 0;
    };
    if !is_forwarding()
        && c_string(command).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_POSTGRES, 0, statement) == Decision::Block
        })
    {
        return 0;
    }
    with_forwarding(|| {
        real(
            connection,
            command,
            parameter_count,
            parameter_types,
            parameter_values,
            parameter_lengths,
            parameter_formats,
            result_format,
        )
    })
}

type PqPrepareFn = unsafe extern "C" fn(
    *mut PgConn,
    *const c_char,
    *const c_char,
    c_int,
    *const Oid,
) -> *mut PgResult;

#[no_mangle]
pub unsafe extern "C" fn PQprepare(
    connection: *mut PgConn,
    statement_name: *const c_char,
    query: *const c_char,
    parameter_count: c_int,
    parameter_types: *const Oid,
) -> *mut PgResult {
    let Some(real) = next_symbol::<PqPrepareFn>(b"PQprepare\0") else {
        return std::ptr::null_mut();
    };
    if let (Some(name), Some(statement)) = (c_string(statement_name), c_string(query)) {
        remember_pg(connection, name, statement);
    }
    with_forwarding(|| {
        real(
            connection,
            statement_name,
            query,
            parameter_count,
            parameter_types,
        )
    })
}

type PqExecPreparedFn = unsafe extern "C" fn(
    *mut PgConn,
    *const c_char,
    c_int,
    *const *const c_char,
    *const c_int,
    *const c_int,
    c_int,
) -> *mut PgResult;

#[no_mangle]
pub unsafe extern "C" fn PQexecPrepared(
    connection: *mut PgConn,
    statement_name: *const c_char,
    parameter_count: c_int,
    parameter_values: *const *const c_char,
    parameter_lengths: *const c_int,
    parameter_formats: *const c_int,
    result_format: c_int,
) -> *mut PgResult {
    let Some(real) = next_symbol::<PqExecPreparedFn>(b"PQexecPrepared\0") else {
        return std::ptr::null_mut();
    };
    let blocked = if is_forwarding() {
        false
    } else {
        c_string(statement_name)
            .and_then(|name| lookup_pg(connection, name))
            .map_or_else(fail_closed, |query| {
                policy_decision(SQL_POLICY_ENGINE_POSTGRES, SQL_POLICY_FLAG_PREPARED, &query)
                    == Decision::Block
            })
    };
    if blocked {
        return std::ptr::null_mut();
    }
    with_forwarding(|| {
        real(
            connection,
            statement_name,
            parameter_count,
            parameter_values,
            parameter_lengths,
            parameter_formats,
            result_format,
        )
    })
}

type PqSendQueryPreparedFn = unsafe extern "C" fn(
    *mut PgConn,
    *const c_char,
    c_int,
    *const *const c_char,
    *const c_int,
    *const c_int,
    c_int,
) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn PQsendQueryPrepared(
    connection: *mut PgConn,
    statement_name: *const c_char,
    parameter_count: c_int,
    parameter_values: *const *const c_char,
    parameter_lengths: *const c_int,
    parameter_formats: *const c_int,
    result_format: c_int,
) -> c_int {
    let Some(real) = next_symbol::<PqSendQueryPreparedFn>(b"PQsendQueryPrepared\0") else {
        return 0;
    };
    let blocked = if is_forwarding() {
        false
    } else {
        c_string(statement_name)
            .and_then(|name| lookup_pg(connection, name))
            .map_or_else(fail_closed, |query| {
                policy_decision(SQL_POLICY_ENGINE_POSTGRES, SQL_POLICY_FLAG_PREPARED, &query)
                    == Decision::Block
            })
    };
    if blocked {
        return 0;
    }
    with_forwarding(|| {
        real(
            connection,
            statement_name,
            parameter_count,
            parameter_values,
            parameter_lengths,
            parameter_formats,
            result_format,
        )
    })
}

type MysqlRealQueryFn = unsafe extern "C" fn(*mut Mysql, *const c_char, c_ulong) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn mysql_real_query(
    connection: *mut Mysql,
    query: *const c_char,
    length: c_ulong,
) -> c_int {
    let Some(real) = next_symbol::<MysqlRealQueryFn>(b"mysql_real_query\0") else {
        return 1;
    };
    if !is_forwarding()
        && counted_bytes(query, length as usize).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_MYSQL, 0, statement) == Decision::Block
        })
    {
        return 1;
    }
    with_forwarding(|| real(connection, query, length))
}

type MysqlQueryFn = unsafe extern "C" fn(*mut Mysql, *const c_char) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn mysql_query(connection: *mut Mysql, query: *const c_char) -> c_int {
    let Some(real) = next_symbol::<MysqlQueryFn>(b"mysql_query\0") else {
        return 1;
    };
    if !is_forwarding()
        && c_string(query).map_or_else(fail_closed, |statement| {
            policy_decision(SQL_POLICY_ENGINE_MYSQL, 0, statement) == Decision::Block
        })
    {
        return 1;
    }
    with_forwarding(|| real(connection, query))
}

type MysqlStmtPrepareFn = unsafe extern "C" fn(*mut MysqlStmt, *const c_char, c_ulong) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn mysql_stmt_prepare(
    statement: *mut MysqlStmt,
    query: *const c_char,
    length: c_ulong,
) -> c_int {
    let Some(real) = next_symbol::<MysqlStmtPrepareFn>(b"mysql_stmt_prepare\0") else {
        return 1;
    };
    let query_copy = counted_bytes(query, length as usize).map(Vec::from);
    let result = with_forwarding(|| real(statement, query, length));
    if result == 0 {
        if let Some(query) = query_copy {
            remember_mysql(statement, &query);
        }
    }
    result
}

type MysqlStmtExecuteFn = unsafe extern "C" fn(*mut MysqlStmt) -> c_int;

#[no_mangle]
pub unsafe extern "C" fn mysql_stmt_execute(statement: *mut MysqlStmt) -> c_int {
    let Some(real) = next_symbol::<MysqlStmtExecuteFn>(b"mysql_stmt_execute\0") else {
        return 1;
    };
    let blocked = if is_forwarding() {
        false
    } else {
        lookup_mysql(statement).map_or_else(fail_closed, |query| {
            policy_decision(SQL_POLICY_ENGINE_MYSQL, SQL_POLICY_FLAG_PREPARED, &query)
                == Decision::Block
        })
    };
    if blocked {
        return 1;
    }
    with_forwarding(|| real(statement))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_requests_and_accepts_allow_and_block_verdicts() {
        let request = encode_request(SQL_POLICY_ENGINE_POSTGRES, 0, b"select * from finance")
            .expect("valid request");
        assert_eq!(&request[..8], &SQL_POLICY_REQUEST_MAGIC);
        assert_eq!(request[8], SQL_POLICY_ENGINE_POSTGRES);
        assert_eq!(
            &request[SQL_POLICY_REQUEST_HEADER_LEN..],
            b"select * from finance"
        );

        for (wire, expected) in [
            (SQL_POLICY_VERDICT_ALLOW, Decision::Allow),
            (SQL_POLICY_VERDICT_BLOCK, Decision::Block),
        ] {
            let mut response = [0u8; SQL_POLICY_RESPONSE_LEN];
            response[..8].copy_from_slice(&SQL_POLICY_RESPONSE_MAGIC);
            response[8] = wire;
            let decision = decode_response(&response).expect("valid verdict");
            assert_eq!(decision, expected);
        }
    }

    #[test]
    fn prepared_cache_is_scoped_by_connection_and_name() {
        let first = 1usize as *mut PgConn;
        let second = 2usize as *mut PgConn;
        remember_pg(first, b"stmt", b"select * from alpha");
        remember_pg(second, b"stmt", b"select * from beta");
        assert_eq!(lookup_pg(first, b"stmt").unwrap(), b"select * from alpha");
        assert_eq!(lookup_pg(second, b"stmt").unwrap(), b"select * from beta");
    }
}
