//! Runtime budget controller for telemetry scheduling.
//!
//! This module provides a lightweight PI control loop that periodically reads
//! process-level utilization from `/proc` and adjusts multi-resource budgets
//! consumed by the scheduler/batcher path.
//!
//! Current state:
//! - CPU and memory utilization are measured from live `/proc` counters.
//! - IO/NET/BW feedback channels are scaffolded and currently held at zero.
//! - The exported `BudgetSnapshot` is the single budget contract used by
//!   runtime components.

use std::fs;
use std::io;
use std::time::Instant;

// Number of resource dimensions tracked by the controller.
// Every resource array in this file must have exactly this length.
pub const N_RESOURCES: usize = 5;

// Stable indexes for each resource dimension.
// These indexes are intentionally public so scheduler/batcher code can
// reference the same dimensions without copying enum definitions.
pub const CPU: usize = 0;
pub const MEM: usize = 1;
pub const IO: usize = 2;
pub const NET: usize = 3;
pub const BW: usize = 4;

// Startup total budgets before feedback adaptation kicks in.
// Units:
// - CPU: microseconds budget per scheduling window
// - MEM: bytes
// - IO: bytes
// - NET: packet budget
// - BW: wire bytes budget
const DEFAULT_TOTAL_BUDGETS: [f32; N_RESOURCES] = [
    5_000.0,      // CPU
    52_428_800.0, // MEM
    10_485_760.0, // IO
    500.0,        // NET
    5_242_880.0,  // BW
];

// Relative importance used by downstream cost functions.
const DEFAULT_WEIGHTS: [f32; N_RESOURCES] = [0.20, 0.15, 0.15, 0.20, 0.30];

// Target utilization setpoints for PI control.
// Example: CPU target 0.70 means "run near 70% of configured CPU budget".
const DEFAULT_TARGET_UTILIZATION: [f32; N_RESOURCES] = [0.70, 0.70, 0.60, 0.60, 0.70];

#[derive(Clone, Debug)]
pub struct BudgetSnapshot {
    // Maximum permitted amount per dimension in the current control window.
    pub total: [f32; N_RESOURCES],
    // Remaining amount after applying measured/estimated utilization.
    pub remaining: [f32; N_RESOURCES],
    // Relative importance of dimensions when composing costs.
    pub weights: [f32; N_RESOURCES],
}

impl BudgetSnapshot {
    // Create a default snapshot used at boot and fallback paths.
    pub fn default_budgets() -> Self {
        Self {
            total: DEFAULT_TOTAL_BUDGETS,
            remaining: DEFAULT_TOTAL_BUDGETS,
            weights: DEFAULT_WEIGHTS,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcSample {
    // Process CPU jiffies (utime + stime) sampled from /proc/self/stat.
    proc_jiffies: u64,
    // Host total CPU jiffies sampled from /proc/stat cpu line.
    sys_jiffies: u64,
    // Process resident set size in bytes sampled from /proc/self/status.
    rss_bytes: u64,
    // Wall-clock capture time for delta computations/diagnostics.
    at: Instant,
}

pub struct BudgetTracker {
    // Current PI-adjusted budget snapshot.
    current: BudgetSnapshot,
    // Controller setpoints (desired utilization levels).
    target: [f32; N_RESOURCES],
    // PI proportional/integral gains per resource.
    kp: [f32; N_RESOURCES],
    ki: [f32; N_RESOURCES],
    // Integral accumulator per resource (with anti-windup clamp).
    integral: [f32; N_RESOURCES],
    // Previous sample used to compute deltas.
    last: Option<ProcSample>,
}

impl BudgetTracker {
    // Construct tracker with defaults and empty previous sample.
    pub fn new() -> Self {
        Self {
            current: BudgetSnapshot::default_budgets(),
            target: DEFAULT_TARGET_UTILIZATION,
            kp: [0.35, 0.25, 0.20, 0.20, 0.25],
            ki: [0.06, 0.05, 0.04, 0.04, 0.05],
            integral: [0.0; N_RESOURCES],
            last: None,
        }
    }

    // Cheap clone used by scheduler loop (every 500ms).
    pub fn snapshot(&self) -> BudgetSnapshot {
        self.current.clone()
    }

    // Run one control step (typically every 5s housekeeping tick):
    // 1) read /proc counters
    // 2) compute current utilization
    // 3) apply PI adjustment to budgets
    // 4) return fresh snapshot
    pub fn update(&mut self) -> io::Result<BudgetSnapshot> {
        let now = read_proc_sample()?;
        let utilization = self.compute_utilization(now);
        self.apply_pi(utilization);
        self.last = Some(now);
        Ok(self.current.clone())
    }

    // Convert raw sample deltas into normalized utilization [0.0, 1.0].
    fn compute_utilization(&self, now: ProcSample) -> [f32; N_RESOURCES] {
        let mut out = [0.0f32; N_RESOURCES];

        // First tick has no baseline, so report zeros and let loop warm up.
        let Some(last) = self.last else {
            return out;
        };

        // CPU = process_jiffies_delta / system_jiffies_delta over interval.
        let proc_delta = now.proc_jiffies.saturating_sub(last.proc_jiffies);
        let sys_delta = now.sys_jiffies.saturating_sub(last.sys_jiffies).max(1);
        let cpu_util = (proc_delta as f32 / sys_delta as f32).clamp(0.0, 1.0);
        out[CPU] = cpu_util;

        // Memory = current RSS / configured memory budget cap.
        let mem_cap = self.current.total[MEM].max(1.0);
        out[MEM] = (now.rss_bytes as f32 / mem_cap).clamp(0.0, 1.0);

        // IO/NET/BW are placeholders until those readers are wired.
        // Keeping these at zero avoids unstable fake feedback.
        out[IO] = 0.0;
        out[NET] = 0.0;
        out[BW] = 0.0;

        // `at` is currently diagnostic-only; keep read to avoid stale field confusion.
        let _dt = now.at.duration_since(last.at);

        out
    }

    // PI update per resource dimension.
    fn apply_pi(&mut self, actual: [f32; N_RESOURCES]) {
        for i in 0..N_RESOURCES {
            // Error is positive when we are below target utilization.
            let error = self.target[i] - actual[i];

            // Integral with anti-windup clamp.
            self.integral[i] = (self.integral[i] + error).clamp(-1.0, 1.0);

            // PI control signal.
            let control = self.kp[i] * error + self.ki[i] * self.integral[i];

            // Adjust budget multiplicatively, constrained to sane bounds.
            let base = self.current.total[i];
            let adjusted = (base * (1.0 + control)).clamp(base * 0.5, base * 1.5);

            self.current.total[i] = adjusted;

            // Remaining budget derived from adjusted total and observed utilization.
            self.current.remaining[i] = (adjusted * (1.0 - actual[i])).max(0.0);
        }
    }
}

// Read all /proc inputs needed for one controller sample.
fn read_proc_sample() -> io::Result<ProcSample> {
    let proc_stat = fs::read_to_string("/proc/self/stat")?;
    let sys_stat = fs::read_to_string("/proc/stat")?;
    let status = fs::read_to_string("/proc/self/status")?;

    let proc_jiffies = parse_proc_self_jiffies(&proc_stat)?;
    let sys_jiffies = parse_proc_total_jiffies(&sys_stat)?;
    let rss_bytes = parse_rss_bytes(&status)?;

    Ok(ProcSample {
        proc_jiffies,
        sys_jiffies,
        rss_bytes,
        at: Instant::now(),
    })
}

// Parse process CPU jiffies from /proc/self/stat.
// /proc/self/stat format is tricky because `comm` sits inside parentheses
// and may contain spaces. We split after ") " first, then index fields.
fn parse_proc_self_jiffies(stat_line: &str) -> io::Result<u64> {
    let right = stat_line
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc/self/stat"))?
        .1;

    let fields: Vec<&str> = right.split_whitespace().collect();
    if fields.len() <= 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short /proc/self/stat fields",
        ));
    }

    // utime/stime positions relative to `right` segment.
    let utime: u64 = fields[11].parse().map_err(invalid_data)?;
    let stime: u64 = fields[12].parse().map_err(invalid_data)?;
    Ok(utime + stime)
}

// Parse host total CPU jiffies from first "cpu " line in /proc/stat.
fn parse_proc_total_jiffies(stat: &str) -> io::Result<u64> {
    let cpu = stat
        .lines()
        .find(|l| l.starts_with("cpu "))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing cpu line"))?;

    let mut sum = 0u64;
    for tok in cpu.split_whitespace().skip(1) {
        sum = sum.saturating_add(tok.parse::<u64>().map_err(invalid_data)?);
    }
    Ok(sum)
}

// Parse VmRSS in kB from /proc/self/status and convert to bytes.
fn parse_rss_bytes(status: &str) -> io::Result<u64> {
    let line = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing VmRSS"))?;

    let kb = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad VmRSS"))?
        .parse::<u64>()
        .map_err(invalid_data)?;

    Ok(kb.saturating_mul(1024))
}

// Convert parsing failures into InvalidData io::Error.
fn invalid_data<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
