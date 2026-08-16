//! Crash-safe FIFO spool used by the active HTTP ingest transport.
//!
//! Records are appended before the transport accepts an outbound payload. A
//! separate cursor file records acknowledgements, so an agent restart replays
//! every record that was not durably acknowledged by the ingest service.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const RECORD_HEADER_LEN: u64 = 4;
const COMPACT_MIN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct DurableSpool {
    path: PathBuf,
    cursor_path: PathBuf,
    file: File,
    read_offset: u64,
    write_offset: u64,
    max_bytes: u64,
}

impl DurableSpool {
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if max_bytes < RECORD_HEADER_LEN + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool capacity must hold at least one record",
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        let cursor_path = path.with_extension("cursor");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let write_offset = file.metadata()?.len();
        let read_offset = read_cursor(&cursor_path)?.min(write_offset);

        let mut spool = Self {
            path: path.to_path_buf(),
            cursor_path,
            file,
            read_offset,
            write_offset,
            max_bytes,
        };
        spool.recover_tail()?;
        Ok(spool)
    }

    /// Append and synchronize one opaque record before returning success.
    pub fn append(&mut self, record: &[u8]) -> io::Result<()> {
        let len = u32::try_from(record.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "spool record exceeds u32 length",
            )
        })?;
        let required = RECORD_HEADER_LEN + u64::from(len);
        if self.pending_bytes().saturating_add(required) > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "HTTP spool full: pending={} required={} capacity={}",
                    self.pending_bytes(),
                    required,
                    self.max_bytes
                ),
            ));
        }

        self.compact_if_useful(required)?;
        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(record)?;
        self.file.sync_data()?;
        self.write_offset = self.write_offset.saturating_add(required);
        Ok(())
    }

    /// Read the oldest unacknowledged record without advancing the cursor.
    pub fn peek(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.read_offset >= self.write_offset {
            return Ok(None);
        }
        self.file.seek(SeekFrom::Start(self.read_offset))?;
        let mut len_bytes = [0u8; 4];
        self.file.read_exact(&mut len_bytes)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut record = vec![0u8; len];
        self.file.read_exact(&mut record)?;
        Ok(Some(record))
    }

    /// Durably acknowledge the current head record.
    pub fn acknowledge(&mut self) -> io::Result<()> {
        if self.read_offset >= self.write_offset {
            return Ok(());
        }
        self.file.seek(SeekFrom::Start(self.read_offset))?;
        let mut len_bytes = [0u8; 4];
        self.file.read_exact(&mut len_bytes)?;
        let next = self
            .read_offset
            .saturating_add(RECORD_HEADER_LEN)
            .saturating_add(u64::from(u32::from_be_bytes(len_bytes)));
        if next > self.write_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spool acknowledgement crosses file boundary",
            ));
        }
        write_cursor_atomic(&self.cursor_path, next)?;
        self.read_offset = next;

        if self.read_offset == self.write_offset {
            self.reset_empty()?;
        } else {
            self.compact_if_useful(0)?;
        }
        Ok(())
    }

    pub fn pending_bytes(&self) -> u64 {
        self.write_offset.saturating_sub(self.read_offset)
    }

    fn recover_tail(&mut self) -> io::Result<()> {
        let mut offset = 0u64;
        while offset < self.write_offset {
            if self.write_offset - offset < RECORD_HEADER_LEN {
                break;
            }
            self.file.seek(SeekFrom::Start(offset))?;
            let mut len_bytes = [0u8; 4];
            self.file.read_exact(&mut len_bytes)?;
            let next = offset
                .saturating_add(RECORD_HEADER_LEN)
                .saturating_add(u64::from(u32::from_be_bytes(len_bytes)));
            if next > self.write_offset {
                break;
            }
            offset = next;
        }
        if offset != self.write_offset {
            self.file.set_len(offset)?;
            self.file.sync_data()?;
            self.write_offset = offset;
            self.read_offset = self.read_offset.min(offset);
            write_cursor_atomic(&self.cursor_path, self.read_offset)?;
        }
        Ok(())
    }

    fn compact_if_useful(&mut self, incoming: u64) -> io::Result<()> {
        if self.read_offset == 0 {
            return Ok(());
        }
        let needs_space = self
            .write_offset
            .saturating_add(incoming)
            .saturating_sub(self.read_offset)
            <= self.max_bytes
            && self.write_offset.saturating_add(incoming) > self.max_bytes;
        let worthwhile = self.read_offset >= COMPACT_MIN_BYTES
            && self.read_offset.saturating_mul(2) >= self.write_offset;
        if !needs_space && !worthwhile {
            return Ok(());
        }

        let temp_path = self.path.with_extension("compact.tmp");
        self.file.seek(SeekFrom::Start(self.read_offset))?;
        let mut temp = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)?;
        io::copy(&mut self.file, &mut temp)?;
        temp.sync_all()?;
        drop(temp);
        fs::rename(&temp_path, &self.path)?;
        sync_parent(&self.path)?;

        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        self.write_offset = self.write_offset.saturating_sub(self.read_offset);
        self.read_offset = 0;
        write_cursor_atomic(&self.cursor_path, 0)?;
        Ok(())
    }

    fn reset_empty(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.sync_data()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.read_offset = 0;
        self.write_offset = 0;
        write_cursor_atomic(&self.cursor_path, 0)
    }
}

fn read_cursor(path: &Path) -> io::Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP spool cursor")),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err),
    }
}

fn write_cursor_atomic(path: &Path, offset: u64) -> io::Result<()> {
    let temp_path = path.with_extension("cursor.tmp");
    {
        let mut temp = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)?;
        write!(temp, "{offset}\n")?;
        temp.sync_all()?;
    }
    fs::rename(&temp_path, path)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("olopa-{label}-{nonce}.spool"))
    }

    #[test]
    fn replays_unacknowledged_records_after_reopen() {
        let path = temp_path("replay");
        {
            let mut spool = DurableSpool::open(&path, 4096).expect("open");
            spool.append(b"one").expect("append one");
            spool.append(b"two").expect("append two");
            assert_eq!(spool.peek().expect("peek"), Some(b"one".to_vec()));
            spool.acknowledge().expect("ack one");
        }
        {
            let mut spool = DurableSpool::open(&path, 4096).expect("reopen");
            assert_eq!(spool.peek().expect("peek"), Some(b"two".to_vec()));
            spool.acknowledge().expect("ack two");
            assert_eq!(spool.peek().expect("empty"), None);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("cursor"));
    }

    #[test]
    fn rejects_records_beyond_capacity_without_evicting_pending_data() {
        let path = temp_path("capacity");
        let mut spool = DurableSpool::open(&path, 12).expect("open");
        spool.append(b"12345678").expect("first record fits");
        let err = spool.append(b"x").expect_err("spool must be full");
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(spool.peek().expect("peek"), Some(b"12345678".to_vec()));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("cursor"));
    }
}
