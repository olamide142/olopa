//! Vectorized and columnar batch filtering utilities for high-throughput rule dispatch.

use crate::telemetry::IngestBatchRequest;
use super::event::{resolve_event_ts, EventDataRef, EventFamily, UnifiedEventRef};

/// Bitset mask representing active/matching rows in a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterMask {
    words: Vec<u64>,
    len: usize,
}

impl FilterMask {
    pub fn all_set(len: usize) -> Self {
        let num_words = (len + 63) / 64;
        let mut words = vec![!0u64; num_words];
        if len % 64 != 0 {
            let rem = len % 64;
            words[num_words - 1] = (1u64 << rem) - 1;
        }
        Self { words, len }
    }

    pub fn all_clear(len: usize) -> Self {
        let num_words = (len + 63) / 64;
        Self {
            words: vec![0u64; num_words],
            len,
        }
    }

    #[inline]
    pub fn set(&mut self, idx: usize, val: bool) {
        if idx >= self.len {
            return;
        }
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        if val {
            self.words[word_idx] |= 1u64 << bit_idx;
        } else {
            self.words[word_idx] &= !(1u64 << bit_idx);
        }
    }

    #[inline]
    pub fn is_set(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    #[inline]
    pub fn and_with(&mut self, other: &FilterMask) {
        let n = self.words.len().min(other.words.len());
        for i in 0..n {
            self.words[i] &= other.words[i];
        }
    }

    #[inline]
    pub fn or_with(&mut self, other: &FilterMask) {
        let n = self.words.len().min(other.words.len());
        for i in 0..n {
            self.words[i] |= other.words[i];
        }
    }

    #[inline]
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    /// Fast iterator over set indices without per-element branch penalty.
    pub fn iter_indices<'a>(&'a self) -> FilterMaskIter<'a> {
        FilterMaskIter {
            mask: self,
            word_idx: 0,
            current_word: self.words.first().copied().unwrap_or(0),
        }
    }
}

pub struct FilterMaskIter<'a> {
    mask: &'a FilterMask,
    word_idx: usize,
    current_word: u64,
}

impl<'a> Iterator for FilterMaskIter<'a> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.current_word == 0 {
            self.word_idx += 1;
            if self.word_idx >= self.mask.words.len() {
                return None;
            }
            self.current_word = self.mask.words[self.word_idx];
        }

        let trailing_zeros = self.current_word.trailing_zeros();
        let idx = self.word_idx * 64 + (trailing_zeros as usize);
        self.current_word &= self.current_word - 1; // Clear lowest set bit

        if idx < self.mask.len {
            Some(idx)
        } else {
            None
        }
    }
}

/// Contiguous columnar index over a single `IngestBatchRequest`.
pub struct BatchColumnIndex<'a> {
    pub events: Vec<UnifiedEventRef<'a>>,
    pub families: Vec<EventFamily>,
    pub pids: Vec<u32>,
    pub uids: Vec<u32>,
    pub len: usize,
    /// Events that fell back to arrival time because the agent sent no usable
    /// stamp. Surfaced as a stat so a skewed or outdated fleet is visible.
    pub ts_fallback_count: usize,
}

impl<'a> BatchColumnIndex<'a> {
    /// Build a columnar view of a batch.
    ///
    /// `arrival_ms` is the batch's ingest time, used as the fallback event time
    /// for senders that do not stamp their own.
    pub fn build(batch: &'a IngestBatchRequest, arrival_ms: u64) -> Self {
        let total_rows = batch.process_exec_events.len()
            + batch.file_events.len()
            + batch.net_events.len()
            + batch.db_query_events.len()
            + batch.agent_heartbeats.len();

        let mut events = Vec::with_capacity(total_rows);
        let mut families = Vec::with_capacity(total_rows);
        let mut pids = Vec::with_capacity(total_rows);
        let mut uids = Vec::with_capacity(total_rows);
        let mut ts_fallback_count = 0usize;

        let tenant_id = &batch.tenant_id;
        let host_id = &batch.host_id;
        let batch_id = batch.batch_id.as_deref();

        for p in &batch.process_exec_events {
            let (ts_unix_ms, ts_fallback) = resolve_event_ts(p.ts_unix_ms, arrival_ms);
            if ts_fallback {
                ts_fallback_count += 1;
            }
            events.push(UnifiedEventRef {
                tenant_id,
                host_id,
                batch_id,
                ts_unix_ms,
                kind: EventFamily::ProcessExec,
                data: EventDataRef::Process(p),
            });
            families.push(EventFamily::ProcessExec);
            pids.push(p.pid);
            uids.push(p.uid);
        }

        for f in &batch.file_events {
            let (ts_unix_ms, ts_fallback) = resolve_event_ts(f.ts_unix_ms, arrival_ms);
            if ts_fallback {
                ts_fallback_count += 1;
            }
            events.push(UnifiedEventRef {
                tenant_id,
                host_id,
                batch_id,
                ts_unix_ms,
                kind: EventFamily::File,
                data: EventDataRef::File(f),
            });
            families.push(EventFamily::File);
            pids.push(f.pid);
            uids.push(f.uid);
        }

        for n in &batch.net_events {
            let (ts_unix_ms, ts_fallback) = resolve_event_ts(n.ts_unix_ms, arrival_ms);
            if ts_fallback {
                ts_fallback_count += 1;
            }
            events.push(UnifiedEventRef {
                tenant_id,
                host_id,
                batch_id,
                ts_unix_ms,
                kind: EventFamily::Net,
                data: EventDataRef::Net(n),
            });
            families.push(EventFamily::Net);
            pids.push(n.pid);
            uids.push(n.uid);
        }

        for q in &batch.db_query_events {
            let (ts_unix_ms, ts_fallback) = resolve_event_ts(q.ts_unix_ms, arrival_ms);
            if ts_fallback {
                ts_fallback_count += 1;
            }
            events.push(UnifiedEventRef {
                tenant_id,
                host_id,
                batch_id,
                ts_unix_ms,
                kind: EventFamily::DbQuery,
                data: EventDataRef::DbQuery(q),
            });
            families.push(EventFamily::DbQuery);
            pids.push(q.pid);
            uids.push(q.uid);
        }

        for h in &batch.agent_heartbeats {
            let (ts_unix_ms, ts_fallback) = resolve_event_ts(h.ts_unix_ms, arrival_ms);
            if ts_fallback {
                ts_fallback_count += 1;
            }
            events.push(UnifiedEventRef {
                tenant_id,
                host_id,
                batch_id,
                ts_unix_ms,
                kind: EventFamily::AgentHeartbeat,
                data: EventDataRef::Heartbeat(h),
            });
            families.push(EventFamily::AgentHeartbeat);
            pids.push(0);
            uids.push(0);
        }

        Self {
            events,
            families,
            pids,
            uids,
            len: total_rows,
            ts_fallback_count,
        }
    }

    /// Fast vectorized family filtering mask.
    pub fn mask_for_family(&self, target_family: EventFamily) -> FilterMask {
        let mut mask = FilterMask::all_clear(self.len);
        for (i, fam) in self.families.iter().enumerate() {
            if *fam == target_family {
                mask.set(i, true);
            }
        }
        mask
    }

    /// Fast vectorized PID filter.
    pub fn mask_for_pid(&self, pid: u32) -> FilterMask {
        let mut mask = FilterMask::all_clear(self.len);
        for (i, p) in self.pids.iter().enumerate() {
            if *p == pid {
                mask.set(i, true);
            }
        }
        mask
    }

    /// Fast vectorized UID filter (e.g. root detection: uid == 0).
    pub fn mask_for_uid(&self, uid: u32) -> FilterMask {
        let mut mask = FilterMask::all_clear(self.len);
        for (i, u) in self.uids.iter().enumerate() {
            if *u == uid {
                mask.set(i, true);
            }
        }
        mask
    }
}
