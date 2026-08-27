//! Log access and diagnostic bundles.

use crate::agent;
use crate::settings::{self, Settings};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::Command as Proc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogReply {
    pub source: String,
    pub available: bool,
    pub note: Option<String>,
    pub lines: Vec<LogLine>,
}

fn classify(line: &str) -> &'static str {
    let upper = line.to_uppercase();
    if upper.contains("ERROR") || upper.contains("PANIC") {
        "error"
    } else if upper.contains("WARN") {
        "warn"
    } else if upper.contains("DEBUG") || upper.contains("TRACE") {
        "debug"
    } else {
        "info"
    }
}

/// Split a journald line into its timestamp prefix and message body.
fn split_line(raw: &str) -> LogLine {
    let level = classify(raw).to_string();
    // journalctl short format: "Mon DD HH:MM:SS host unit[pid]: message"
    let mut parts = raw.splitn(4, ' ');
    let stamp: String = (0..3)
        .filter_map(|_| parts.next())
        .collect::<Vec<_>>()
        .join(" ");
    let rest = parts.next().unwrap_or("").to_string();
    if rest.is_empty() {
        LogLine {
            timestamp: String::new(),
            level,
            message: raw.to_string(),
        }
    } else {
        LogLine {
            timestamp: stamp,
            level,
            message: rest,
        }
    }
}

/// Tail the agent's journal. Falls back with an explanation when journald is
/// absent or the unit is not readable by this user.
pub fn agent_logs(settings: &Settings, lines: usize) -> LogReply {
    let unit = settings.agent_service_name.trim().to_string();
    let count = lines.clamp(20, 2000).to_string();
    let source = format!("journalctl -u {unit}");

    let output = Proc::new("journalctl")
        .args([
            "--no-pager",
            "-u",
            &unit,
            "-n",
            &count,
            "-o",
            "short",
        ])
        .output();

    match output {
        Err(err) => LogReply {
            source,
            available: false,
            note: Some(format!("journalctl unavailable: {err}")),
            lines: Vec::new(),
        },
        Ok(output) if !output.status.success() => LogReply {
            source,
            available: false,
            note: Some(
                String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .chars()
                    .take(300)
                    .collect(),
            ),
            lines: Vec::new(),
        },
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            let parsed: Vec<LogLine> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(split_line)
                .collect();
            let note = parsed
                .is_empty()
                .then(|| format!("no journal entries for unit '{unit}'"));
            LogReply {
                source,
                available: true,
                note,
                lines: parsed,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleReport {
    pub path: String,
    pub files: Vec<String>,
    pub warnings: Vec<String>,
}

/// Write a support bundle of everything Command can see locally.
///
/// Only operator-visible artefacts are collected: snapshots, logs, host facts
/// and settings *without* the credential value.
pub fn export_bundle(settings: &Settings) -> Result<BundleReport, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir: PathBuf = std::env::temp_dir().join(format!("olopa-command-diagnostics-{stamp}"));
    fs::create_dir_all(&dir).map_err(|err| format!("create {}: {err}", dir.display()))?;

    let mut files = Vec::new();
    let mut warnings = Vec::new();

    let write = |name: &str, body: String, files: &mut Vec<String>, warnings: &mut Vec<String>| {
        let path = dir.join(name);
        match fs::write(&path, body) {
            Ok(()) => files.push(path.display().to_string()),
            Err(err) => warnings.push(format!("{name}: {err}")),
        }
    };

    let status = agent::agent_status(settings);
    write(
        "agent-status.json",
        serde_json::to_string_pretty(&status).unwrap_or_default(),
        &mut files,
        &mut warnings,
    );

    let secure_connect = agent::secure_connect_status(settings);
    write(
        "secure-connect.json",
        serde_json::to_string_pretty(&secure_connect).unwrap_or_default(),
        &mut files,
        &mut warnings,
    );

    write(
        "host.json",
        serde_json::to_string_pretty(&agent::host_facts()).unwrap_or_default(),
        &mut files,
        &mut warnings,
    );

    let logs = agent_logs(settings, 2000);
    let rendered = logs
        .lines
        .iter()
        .map(|line| format!("{} {} {}", line.timestamp, line.level, line.message))
        .collect::<Vec<_>>()
        .join("\n");
    write("agent.log", rendered, &mut files, &mut warnings);
    if let Some(note) = logs.note {
        warnings.push(format!("logs: {note}"));
    }

    // The credential is deliberately redacted: bundles get attached to tickets.
    let mut redacted = settings.clone();
    redacted.credential_value = if redacted.credential_value.is_empty() {
        String::new()
    } else {
        "[redacted]".into()
    };
    write(
        "settings.json",
        serde_json::to_string_pretty(&redacted).unwrap_or_default(),
        &mut files,
        &mut warnings,
    );

    write(
        "environment.txt",
        format!(
            "settings file: {}\ncommand version: {}\n",
            settings::location(),
            env!("CARGO_PKG_VERSION")
        ),
        &mut files,
        &mut warnings,
    );

    Ok(BundleReport {
        path: dir.display().to_string(),
        files,
        warnings,
    })
}
