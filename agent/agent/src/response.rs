use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::Ebpf;

/// Poll violation counters and optionally apply process-kill response.
pub fn process_violations(bpf: &mut Ebpf, threshold: u64, kill_on_violation: bool) -> Result<()> {
    let mut to_clear = Vec::new();
    let mut violations: HashMap<_, u32, u64> = HashMap::try_from(
        bpf.map_mut("VIOLATION_COUNTS")
            .context("missing VIOLATION_COUNTS map")?,
    )?;

    for key_result in violations.keys() {
        let tgid = match key_result {
            Ok(v) => v,
            Err(err) => {
                eprintln!("failed reading violation key: {err}");
                continue;
            }
        };

        let count = match violations.get(&tgid, 0) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("failed reading violation count for {tgid}: {err}");
                continue;
            }
        };

        if count >= threshold {
            eprintln!("runtime violation threshold reached for tgid={tgid}, count={count}");
            if kill_on_violation {
                // Best-effort local response; ignore ESRCH race (process already gone).
                unsafe {
                    libc::kill(tgid as i32, libc::SIGKILL);
                }
                eprintln!("sent SIGKILL to tgid={tgid}");
            }
            to_clear.push(tgid);
        }
    }

    for tgid in to_clear {
        let _ = violations.remove(&tgid);
    }
    Ok(())
}

