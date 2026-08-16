//! Durable acceptance log and persistent idempotency state.

use crate::telemetry::IngestBatchRequest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const WAL_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct BatchKey {
    pub tenant_id: String,
    pub host_id: String,
    pub batch_id: String,
}

impl BatchKey {
    pub fn from_batch(batch: &IngestBatchRequest) -> Option<Self> {
        batch.batch_id.as_deref().and_then(|batch_id| {
            let batch_id = batch_id.trim();
            (!batch_id.is_empty()).then(|| Self {
                tenant_id: batch.tenant_id.clone(),
                host_id: batch.host_id.clone(),
                batch_id: batch_id.to_string(),
            })
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum WalRecord {
    Accept {
        version: u32,
        sequence: u64,
        batch: IngestBatchRequest,
    },
    Commit {
        version: u32,
        sequences: Vec<u64>,
    },
    Abort {
        version: u32,
        sequence: u64,
    },
    Forget {
        version: u32,
        key: BatchKey,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct DedupeSnapshot {
    version: u32,
    keys: Vec<BatchKey>,
}

#[derive(Default)]
struct DedupeState {
    seen: HashSet<BatchKey>,
    order: VecDeque<BatchKey>,
}

impl DedupeState {
    fn contains(&self, key: &BatchKey) -> bool {
        self.seen.contains(key)
    }

    fn remember(&mut self, key: BatchKey, max_entries: usize) -> Vec<BatchKey> {
        if max_entries == 0 || !self.seen.insert(key.clone()) {
            return Vec::new();
        }
        self.order.push_back(key);
        let mut evicted = Vec::new();
        while self.seen.len() > max_entries {
            if let Some(expired) = self.order.pop_front() {
                if self.seen.remove(&expired) {
                    evicted.push(expired);
                }
            }
        }
        evicted
    }

    fn forget(&mut self, key: &BatchKey) {
        if self.seen.remove(key) {
            self.order.retain(|candidate| candidate != key);
        }
    }
}

struct WalState {
    file: File,
    next_sequence: u64,
    pending: BTreeMap<u64, IngestBatchRequest>,
    dedupe: DedupeState,
    commits_since_compaction: usize,
    healthy: bool,
}

pub(crate) enum AcceptOutcome {
    Accepted(u64),
    Duplicate,
    QueueFull,
    QueueClosed,
}

/// A batch is acknowledged only after its `accept` record reaches stable storage.
pub(crate) struct DurableAcceptance {
    wal_path: PathBuf,
    dedupe_path: PathBuf,
    dedupe_max_entries: usize,
    compact_after_commits: usize,
    state: Mutex<WalState>,
}

impl DurableAcceptance {
    pub fn open(
        wal_path: impl Into<PathBuf>,
        dedupe_path: impl Into<PathBuf>,
        dedupe_max_entries: usize,
        compact_after_commits: usize,
    ) -> Result<Self, String> {
        let wal_path = wal_path.into();
        let dedupe_path = dedupe_path.into();
        ensure_parent(&wal_path).map_err(|err| format!("create WAL directory: {err}"))?;
        ensure_parent(&dedupe_path).map_err(|err| format!("create dedupe directory: {err}"))?;

        let mut dedupe = load_dedupe_snapshot(&dedupe_path, dedupe_max_entries)?;
        let (pending, next_sequence) = replay_wal(&wal_path, &mut dedupe, dedupe_max_entries)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&wal_path)
            .map_err(|err| format!("open WAL {}: {err}", wal_path.display()))?;

        Ok(Self {
            wal_path,
            dedupe_path,
            dedupe_max_entries,
            compact_after_commits: compact_after_commits.max(1),
            state: Mutex::new(WalState {
                file,
                next_sequence,
                pending,
                dedupe,
                commits_since_compaction: 0,
                healthy: true,
            }),
        })
    }

    pub fn recovered(&self) -> Vec<(u64, IngestBatchRequest)> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .pending
            .iter()
            .map(|(sequence, batch)| (*sequence, batch.clone()))
            .collect()
    }

    /// Atomically perform dedupe check, durable append, and queue insertion.
    pub fn accept<F>(&self, batch: IngestBatchRequest, enqueue: F) -> Result<AcceptOutcome, String>
    where
        F: FnOnce(u64, IngestBatchRequest) -> Result<(), bool>,
    {
        let key = BatchKey::from_batch(&batch);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if key
            .as_ref()
            .is_some_and(|candidate| state.dedupe.contains(candidate))
        {
            return Ok(AcceptOutcome::Duplicate);
        }

        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        append_record(
            &mut state.file,
            &WalRecord::Accept {
                version: WAL_VERSION,
                sequence,
                batch: batch.clone(),
            },
        )?;
        state.pending.insert(sequence, batch.clone());

        let evicted = key
            .as_ref()
            .map(|key| state.dedupe.remember(key.clone(), self.dedupe_max_entries))
            .unwrap_or_default();
        for expired in evicted {
            append_record(
                &mut state.file,
                &WalRecord::Forget {
                    version: WAL_VERSION,
                    key: expired,
                },
            )?;
        }
        state.file.sync_data().map_err(|err| {
            state.healthy = false;
            format!("fsync WAL acceptance: {err}")
        })?;

        match enqueue(sequence, batch) {
            Ok(()) => Ok(AcceptOutcome::Accepted(sequence)),
            Err(closed) => {
                append_record(
                    &mut state.file,
                    &WalRecord::Abort {
                        version: WAL_VERSION,
                        sequence,
                    },
                )?;
                state
                    .file
                    .sync_data()
                    .map_err(|err| format!("fsync WAL abort: {err}"))?;
                state.pending.remove(&sequence);
                if let Some(key) = key {
                    state.dedupe.forget(&key);
                }
                Ok(if closed {
                    AcceptOutcome::QueueClosed
                } else {
                    AcceptOutcome::QueueFull
                })
            }
        }
    }

    pub fn commit(&self, sequences: &[u64]) -> Result<(), String> {
        if sequences.is_empty() {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        append_record(
            &mut state.file,
            &WalRecord::Commit {
                version: WAL_VERSION,
                sequences: sequences.to_vec(),
            },
        )?;
        state.file.sync_data().map_err(|err| {
            state.healthy = false;
            format!("fsync WAL commit: {err}")
        })?;
        for sequence in sequences {
            state.pending.remove(sequence);
        }
        state.commits_since_compaction = state
            .commits_since_compaction
            .saturating_add(sequences.len());
        if state.commits_since_compaction >= self.compact_after_commits {
            if let Err(err) = self.compact_locked(&mut state) {
                state.healthy = false;
                tracing::error!(error = %err, "ingest WAL compaction failed; append log remains authoritative");
            }
        }
        Ok(())
    }

    pub fn compact(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.compact_locked(&mut state)
    }

    fn compact_locked(&self, state: &mut WalState) -> Result<(), String> {
        write_dedupe_snapshot(&self.dedupe_path, &state.dedupe)?;

        let temp = temp_path(&self.wal_path);
        let mut replacement = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(|err| format!("create compacted WAL {}: {err}", temp.display()))?;
        for (sequence, batch) in &state.pending {
            write_record(
                &mut replacement,
                &WalRecord::Accept {
                    version: WAL_VERSION,
                    sequence: *sequence,
                    batch: batch.clone(),
                },
            )?;
        }
        replacement
            .sync_all()
            .map_err(|err| format!("fsync compacted WAL: {err}"))?;
        fs::rename(&temp, &self.wal_path)
            .map_err(|err| format!("replace WAL {}: {err}", self.wal_path.display()))?;
        sync_parent(&self.wal_path)?;
        state.file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.wal_path)
            .map_err(|err| format!("reopen compacted WAL: {err}"))?;
        state.commits_since_compaction = 0;
        state.healthy = true;
        Ok(())
    }

    pub fn pending_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .len()
    }

    pub fn is_healthy(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .healthy
    }
}

fn replay_wal(
    path: &Path,
    dedupe: &mut DedupeState,
    max_entries: usize,
) -> Result<(BTreeMap<u64, IngestBatchRequest>, u64), String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeMap::new(), 1));
        }
        Err(err) => return Err(format!("open WAL for replay {}: {err}", path.display())),
    };
    let mut pending = BTreeMap::new();
    let mut next_sequence = 1u64;
    let ends_with_newline = bytes.ends_with(b"\n");
    let records = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    for (index, line) in records.iter().enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record = match serde_json::from_slice::<WalRecord>(line) {
            Ok(record) => record,
            Err(_err) if index + 1 == records.len() && !ends_with_newline => {
                // A power loss may leave one torn tail record. Earlier fsynced lines remain valid.
                break;
            }
            Err(err) => {
                return Err(format!(
                    "corrupt WAL record {} in {}: {err}",
                    index + 1,
                    path.display()
                ));
            }
        };
        match record {
            WalRecord::Accept {
                version,
                sequence,
                batch,
            } if version == WAL_VERSION => {
                next_sequence = next_sequence.max(sequence.saturating_add(1));
                if let Some(key) = BatchKey::from_batch(&batch) {
                    let _ = dedupe.remember(key, max_entries);
                }
                pending.insert(sequence, batch);
            }
            WalRecord::Commit { version, sequences } if version == WAL_VERSION => {
                for sequence in sequences {
                    pending.remove(&sequence);
                }
            }
            WalRecord::Abort { version, sequence } if version == WAL_VERSION => {
                if let Some(batch) = pending.remove(&sequence) {
                    if let Some(key) = BatchKey::from_batch(&batch) {
                        dedupe.forget(&key);
                    }
                }
            }
            WalRecord::Forget { version, key } if version == WAL_VERSION => dedupe.forget(&key),
            _ => return Err("unsupported ingest WAL version".to_string()),
        }
    }
    Ok((pending, next_sequence))
}

fn load_dedupe_snapshot(path: &Path, max_entries: usize) -> Result<DedupeState, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(DedupeState::default()),
        Err(err) => return Err(format!("read dedupe snapshot {}: {err}", path.display())),
    };
    let snapshot: DedupeSnapshot = serde_json::from_slice(&bytes)
        .map_err(|err| format!("parse dedupe snapshot {}: {err}", path.display()))?;
    if snapshot.version != WAL_VERSION {
        return Err(format!(
            "unsupported dedupe snapshot version {}",
            snapshot.version
        ));
    }
    let mut state = DedupeState::default();
    for key in snapshot.keys {
        let _ = state.remember(key, max_entries);
    }
    Ok(state)
}

fn write_dedupe_snapshot(path: &Path, state: &DedupeState) -> Result<(), String> {
    let temp = temp_path(path);
    let bytes = serde_json::to_vec(&DedupeSnapshot {
        version: WAL_VERSION,
        keys: state.order.iter().cloned().collect(),
    })
    .map_err(|err| format!("serialize dedupe snapshot: {err}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)
        .map_err(|err| format!("create dedupe snapshot {}: {err}", temp.display()))?;
    file.write_all(&bytes)
        .map_err(|err| format!("write dedupe snapshot: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("fsync dedupe snapshot: {err}"))?;
    fs::rename(&temp, path)
        .map_err(|err| format!("replace dedupe snapshot {}: {err}", path.display()))?;
    sync_parent(path)
}

fn append_record(file: &mut File, record: &WalRecord) -> Result<(), String> {
    write_record(file, record)
}

fn write_record(file: &mut File, record: &WalRecord) -> Result<(), String> {
    serde_json::to_writer(&mut *file, record)
        .map_err(|err| format!("serialize WAL record: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("append WAL delimiter: {err}"))
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    PathBuf::from(name)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| format!("fsync directory {}: {err}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{IngestBatchRequest, ProcessExecEvent};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn paths() -> (PathBuf, PathBuf) {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "olopa-ingest-wal-{}-{id}-{nonce}",
            std::process::id()
        ));
        (base.with_extension("wal"), base.with_extension("dedupe"))
    }

    fn batch(id: &str) -> IngestBatchRequest {
        IngestBatchRequest {
            tenant_id: "acme".into(),
            host_id: "host".into(),
            schema_version: 1,
            batch_id: Some(id.into()),
            process_exec_events: vec![ProcessExecEvent {
                pid: 1,
                tgid: 1,
                ppid: 0,
                uid: 0,
                gid: 0,
                comm: "sh".into(),
                filename: "/bin/sh".into(),
                attrs: HashMap::new(),
            }],
            file_events: Vec::new(),
            net_events: Vec::new(),
            db_query_events: Vec::new(),
            agent_heartbeats: Vec::new(),
        }
    }

    #[test]
    fn replays_uncommitted_and_persists_dedupe_after_compaction() {
        let (wal, dedupe) = paths();
        let durable = DurableAcceptance::open(&wal, &dedupe, 10, 1).expect("open");
        let first = durable.accept(batch("one"), |_, _| Ok(())).expect("accept");
        let AcceptOutcome::Accepted(first_sequence) = first else {
            panic!("expected acceptance")
        };
        durable.accept(batch("two"), |_, _| Ok(())).expect("accept");
        durable.commit(&[first_sequence]).expect("commit");
        drop(durable);

        let reopened = DurableAcceptance::open(&wal, &dedupe, 10, 1).expect("reopen");
        assert_eq!(reopened.recovered().len(), 1);
        assert!(matches!(
            reopened.accept(batch("one"), |_, _| Ok(())),
            Ok(AcceptOutcome::Duplicate)
        ));
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(dedupe);
    }

    #[test]
    fn torn_tail_does_not_discard_prior_fsynced_records() {
        let (wal, dedupe) = paths();
        let durable = DurableAcceptance::open(&wal, &dedupe, 10, 100).expect("open");
        durable.accept(batch("one"), |_, _| Ok(())).expect("accept");
        drop(durable);
        let mut file = OpenOptions::new().append(true).open(&wal).expect("wal");
        file.write_all(b"{\"op\":\"accept\"").expect("torn tail");
        file.sync_all().expect("sync");

        let reopened = DurableAcceptance::open(&wal, &dedupe, 10, 100).expect("reopen");
        assert_eq!(reopened.recovered().len(), 1);
        let _ = fs::remove_file(wal);
    }

    #[test]
    fn corrupt_complete_record_fails_startup_instead_of_skipping_data() {
        let (wal, dedupe) = paths();
        let durable = DurableAcceptance::open(&wal, &dedupe, 10, 100).expect("open");
        durable.accept(batch("one"), |_, _| Ok(())).expect("accept");
        drop(durable);
        let mut file = OpenOptions::new().append(true).open(&wal).expect("wal");
        file.write_all(b"not-json\n").expect("corruption");
        file.sync_all().expect("sync");

        let result = DurableAcceptance::open(&wal, &dedupe, 10, 100);
        assert!(result.is_err());
        let _ = fs::remove_file(wal);
    }
}
