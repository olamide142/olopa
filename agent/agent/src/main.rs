//! Olopa agent userspace entrypoint.
//!
//! Responsibilities in this file:
//! - Parse runtime CLI options.
//! - Bootstrap eBPF probe attachment.
//! - Wire concrete implementations into the orchestrator traits.
//! - Start the long-running `OlopaAgent::run(...)` loop.

mod agent;
mod budget_tracker;
mod cgroup;
mod data;
mod intel_store;
mod probe_manager;
mod runtime_ir;
mod secure_connect;
mod sql_norm;
mod sql_policy;
mod transport;

use anyhow::{bail, Context, Result};
use aya::maps::HashMap as BpfHashMap;
use clap::{ArgAction, Args, Parser, Subcommand};
use log::{info, warn};
use olopa_common::{
    TcEgressPolicyKey, TcRateLimitConfig, TC_POLICY_ACTION_ALLOW, TC_POLICY_ACTION_DENY,
    TC_POLICY_ACTION_RATE_LIMIT,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::agent::{
    BatcherLike, BatcherPush, EventStoreLike, GraphLike, IngestEvent, MetricAggregatorLike,
    OlopaAgent, RelevanceScorerLike, RuleEngineLike, RuleMatch, SchedulerLike,
};
use crate::budget_tracker::{BudgetSnapshot as RuntimeBudgetSnapshot, BudgetTracker};
use crate::data::batcher_compressor::{
    Batcher as CompressorBatcher, PushResult as CompressorPushResult,
};
use crate::data::csr_graph::{CsrGraph, EdgeKind, EdgeProps, NodeLabel};
use crate::data::event_store::{ColdEvent, EventStore, HotEvent};
use crate::data::mdkp_scheduler::{
    BudgetSnapshot as SchedulerBudgetSnapshot, Scheduler, SolverTier, TelemetryItem, N_RESOURCES,
};
use crate::data::metric_aggregator::{MetricAggregator, MetricSummary};
use crate::data::relevance_scorer::RelevanceScorer;
use crate::probe_manager::{ProbeManager, ProbeSelection};
use crate::runtime_ir::RuntimeIrRuleEngine;
use crate::transport::http_sender::HttpIngestSender;

const DEFAULT_RUNTIME_IR_PATH: &str = "/etc/olopa/runtime-ir.json";
const DEFAULT_INTEL_PATH: &str = "/etc/olopa/intel.json";
const DEFAULT_INGEST_URL: &str = "http://127.0.0.1:8000/api/v1/ingest/batches";
const DEFAULT_INGEST_TENANT_ID: &str = "default";
const DEFAULT_INGEST_HOST_ID: &str = "agent-local";
const DEFAULT_STATUS_PATH: &str = "/tmp/olopa/agent/status.json";

/// CLI enum for selecting which probe groups to attach at startup.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProbeEventArg {
    Fork,
    Exec,
    File,
    Net,
    Xdp,
    Tc,
    Sql,
    Ssl,
    Dns,
}

impl ProbeEventArg {
    /// Map CLI arg variant to probe manager selection enum.
    fn as_selection(self) -> ProbeSelection {
        match self {
            ProbeEventArg::Fork => ProbeSelection::Fork,
            ProbeEventArg::Exec => ProbeSelection::Exec,
            ProbeEventArg::File => ProbeSelection::File,
            ProbeEventArg::Net => ProbeSelection::Net,
            ProbeEventArg::Xdp => ProbeSelection::Xdp,
            ProbeEventArg::Tc => ProbeSelection::Tc,
            ProbeEventArg::Sql => ProbeSelection::Sql,
            ProbeEventArg::Ssl => ProbeSelection::Ssl,
            ProbeEventArg::Dns => ProbeSelection::Dns,
        }
    }
}

/// Command line options for userspace agent runtime.
#[derive(Debug, Parser)]
#[command(
    name = "olopa",
    about = "Olopa kernel security agent",
    after_help = "Examples:\n  olopa status --verbose\n  olopa --iface eth0 --probe-events exec,net\n  olopa --runtime-ir /etc/olopa/runtime-ir.json --ingest-url http://127.0.0.1:8000/api/v1/ingest/batches\n  olopa --print-effective-config"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    run: RunOpt,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show runtime status from local agent snapshot.
    Status(StatusOpt),
}

#[derive(Debug, Args)]
struct StatusOpt {
    /// Show full detailed view instead of compact summary.
    #[arg(long, action = ArgAction::SetTrue)]
    verbose: bool,
    /// Disable ANSI colors.
    #[arg(long, action = ArgAction::SetTrue)]
    no_color: bool,
    /// Hide mascot bitmap banner.
    #[arg(long, action = ArgAction::SetTrue)]
    no_mascot: bool,
    /// Status snapshot path written by running agent.
    #[arg(long)]
    status_path: Option<String>,
}

#[derive(Debug, Args)]
struct RunOpt {
    /// Network interface used by attach helpers.
    #[arg(short, long)]
    iface: Option<String>,
    /// Comma-separated probe groups to attach (fork,exec,file,net,xdp,tc).
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_values_t = [
            ProbeEventArg::Fork,
            ProbeEventArg::Exec,
            ProbeEventArg::File,
            ProbeEventArg::Net
        ]
    )]
    probe_events: Vec<ProbeEventArg>,
    /// Disable userspace graph JSON dumps entirely.
    #[arg(long, action = ArgAction::SetTrue)]
    no_graph_dump: bool,
    /// Output file path for userspace graph JSON dumps.
    #[arg(long, default_value = "/tmp/olopa_graph.json")]
    graph_dump_path: String,
    /// Minimum interval between graph dump writes in milliseconds.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    graph_dump_interval_ms: u64,
    /// Path to runtime-ir artifact JSON.
    #[arg(long)]
    runtime_ir: Option<String>,
    /// Permit simple fallback matcher if runtime-ir fails to load.
    #[arg(long, action = ArgAction::SetTrue)]
    allow_simple_rule_fallback: bool,
    /// Override ingest endpoint URL.
    #[arg(long)]
    ingest_url: Option<String>,
    /// Override ingest tenant id used in sender payloads.
    #[arg(long)]
    ingest_tenant_id: Option<String>,
    /// Override ingest host id used in sender payloads.
    #[arg(long)]
    ingest_host_id: Option<String>,
    /// Ingest auth bearer token (sent as Authorization: Bearer <token>).
    #[arg(long)]
    ingest_api_token: Option<String>,
    /// Ingest auth API key (sent as x-api-key: <key>).
    #[arg(long)]
    ingest_api_key: Option<String>,
    /// Print effective startup config and exit.
    #[arg(long, action = ArgAction::SetTrue)]
    print_effective_config: bool,
    /// Path where runtime status snapshots are written.
    #[arg(long)]
    status_path: Option<String>,
}

/// Agent process entrypoint.
///
/// Initializes runtime dependencies, attaches selected probes, and
/// delegates control to the long-running orchestrator loop.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Some(Command::Status(status_opt)) = cli.command {
        return print_status(status_opt);
    }

    let opt = cli.run;
    apply_cli_env_overrides(&opt);
    let iface = resolve_iface(opt.iface.as_deref());
    let probe_selections = normalize_probe_selections(&opt.probe_events);
    std::env::set_var("OLOPA_ACTIVE_IFACE", &iface);
    std::env::set_var(
        "OLOPA_PROBE_EVENTS_ACTIVE",
        expand_probe_status_tokens(&probe_selections).join(","),
    );

    if opt.print_effective_config {
        let cfg = EffectiveCliConfig::from_runtime_inputs(&opt, &iface, &probe_selections);
        println!(
            "{}",
            serde_json::to_string_pretty(&cfg).context("serialize effective CLI config")?
        );
        return Ok(());
    }

    info!("olopa starting | iface={}", iface);

    // 0) Initialise threat-intelligence store (non-fatal if file absent).
    let intel_path = std::env::var("OLOPA_INTEL_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_INTEL_PATH.to_string());
    intel_store::init(std::path::Path::new(&intel_path));
    cgroup::init();

    // 1) Load eBPF object and attach selected probes.
    let mut agent = OlopaAgent::new()?;
    let mut probe_manager = ProbeManager::new();
    probe_manager.attach_selected(agent.bpf_mut(), &iface, &probe_selections)?;
    if probe_selections.contains(&ProbeSelection::Xdp) {
        install_xdp_blocklist_from_env(agent.bpf_mut())?;
    } else if std::env::var("OLOPA_XDP_BLOCK_IPS").is_ok() {
        warn!("OLOPA_XDP_BLOCK_IPS is set but xdp probe was not selected");
    }
    if probe_selections.contains(&ProbeSelection::Tc) {
        install_tc_deny_rules_from_env(agent.bpf_mut())?;
    } else if std::env::var("OLOPA_TC_DENY_RULES").is_ok()
        || std::env::var("OLOPA_TC_POLICY_RULES").is_ok()
    {
        warn!("TC policy environment is set but tc probe was not selected; rules are not enforced");
    }
    info!(
        "olopa initialized and probes attached | probe_events={}",
        format_probe_selections(&probe_selections)
    );

    // 2) Wire concrete runtime components (adapters + default implementations).
    let mut relevance_scorer = RealRelevanceScorer::default();
    let mut event_store = RealEventStore::default();
    let mut graph = if opt.no_graph_dump {
        info!("graph dumps disabled (--no-graph-dump)");
        RealGraph::default()
    } else {
        info!(
            "graph dumps enabled | path={} interval_ms={}",
            opt.graph_dump_path, opt.graph_dump_interval_ms
        );
        RealGraph::with_dump(
            PathBuf::from(&opt.graph_dump_path),
            Duration::from_millis(opt.graph_dump_interval_ms),
        )
    };
    let mut metric_aggregator = RealMetricAggregator::default();
    let mut rule_engine = ActiveRuleEngine::from_env()?;
    let sql_policy = sql_policy::spawn_from_env()?;
    if sql_policy.is_some() && probe_selections.contains(&ProbeSelection::Sql) {
        warn!(
            "SQL policy guard and SQL uprobes are both enabled; guarded queries will be duplicated"
        );
    }
    let mut scheduler = RealScheduler::default();
    let mut batcher = RealBatcher::default();
    let mut sender = HttpIngestSender::from_env().context("initialize durable HTTP sender")?;
    let mut budget_tracker = BudgetTracker::new();

    // Secure Connect runs beside the sensor loop and shares the durable spool
    // so tunnel/posture events reach ingest over the existing transport.
    secure_connect::spawn_from_env(Some(sender.handle()));

    // 3) Main runtime loops live inside agent.run(...).
    agent
        .run(
            &mut relevance_scorer,
            &mut event_store,
            &mut graph,
            &mut metric_aggregator,
            &mut rule_engine,
            &mut scheduler,
            &mut batcher,
            &mut sender,
            &mut budget_tracker,
            sql_policy.as_ref(),
        )
        .await
}

#[derive(Debug, Serialize)]
struct EffectiveCliConfig {
    iface: String,
    probe_events: Vec<String>,
    graph_dump_enabled: bool,
    graph_dump_path: Option<String>,
    graph_dump_interval_ms: Option<u64>,
    runtime_ir_path: String,
    allow_simple_rule_fallback: bool,
    ingest_url: String,
    ingest_tenant_id: String,
    ingest_host_id: String,
    ingest_auth: &'static str,
    status_path: String,
    secure_connect_enabled: bool,
    secure_connect_control_url: Option<String>,
    secure_connect_interface: String,
    sql_policy_enabled: bool,
    sql_policy_mode: String,
    sql_policy_socket: String,
}

impl EffectiveCliConfig {
    fn from_runtime_inputs(opt: &RunOpt, iface: &str, probes: &[ProbeSelection]) -> Self {
        let graph_dump_enabled = !opt.no_graph_dump;
        let runtime_ir_path = env_non_empty("OLOPA_RUNTIME_IR")
            .unwrap_or_else(|| DEFAULT_RUNTIME_IR_PATH.to_string());
        let ingest_url =
            env_non_empty("OLOPA_INGEST_URL").unwrap_or_else(|| DEFAULT_INGEST_URL.to_string());
        let ingest_tenant_id = env_non_empty("OLOPA_INGEST_TENANT_ID")
            .unwrap_or_else(|| DEFAULT_INGEST_TENANT_ID.to_string());
        let ingest_host_id = env_non_empty("OLOPA_INGEST_HOST_ID")
            .or_else(|| env_non_empty("HOSTNAME"))
            .unwrap_or_else(|| DEFAULT_INGEST_HOST_ID.to_string());
        let status_path =
            env_non_empty("OLOPA_STATUS_PATH").unwrap_or_else(|| DEFAULT_STATUS_PATH.to_string());
        let ingest_auth = if env_non_empty("OLOPA_INGEST_API_TOKEN").is_some() {
            "bearer"
        } else if env_non_empty("OLOPA_INGEST_API_KEY").is_some() {
            "x-api-key"
        } else {
            "none"
        };

        Self {
            iface: iface.to_string(),
            probe_events: probes
                .iter()
                .map(|selection| probe_selection_name(*selection).to_string())
                .collect(),
            graph_dump_enabled,
            graph_dump_path: graph_dump_enabled.then(|| opt.graph_dump_path.clone()),
            graph_dump_interval_ms: graph_dump_enabled.then_some(opt.graph_dump_interval_ms),
            runtime_ir_path,
            allow_simple_rule_fallback: env_flag("OLOPA_ALLOW_SIMPLE_RULE_FALLBACK"),
            ingest_url,
            ingest_tenant_id,
            ingest_host_id,
            ingest_auth,
            status_path,
            secure_connect_enabled: env_flag("OLOPA_SC_ENABLED"),
            secure_connect_control_url: env_non_empty("OLOPA_SC_CONTROL_URL"),
            secure_connect_interface: env_non_empty("OLOPA_SC_INTERFACE")
                .unwrap_or_else(|| "olopa0".to_string()),
            sql_policy_enabled: env_flag("OLOPA_SQL_POLICY_ENABLED"),
            sql_policy_mode: env_non_empty("OLOPA_SQL_POLICY_MODE")
                .unwrap_or_else(|| "observe".to_string()),
            sql_policy_socket: env_non_empty("OLOPA_SQL_POLICY_SOCKET")
                .unwrap_or_else(|| "/run/olopa/sql-policy.sock".to_string()),
        }
    }
}

fn apply_cli_env_overrides(opt: &RunOpt) {
    if let Some(v) = trimmed_non_empty(opt.runtime_ir.as_deref()) {
        std::env::set_var("OLOPA_RUNTIME_IR", v);
    }
    if opt.allow_simple_rule_fallback {
        std::env::set_var("OLOPA_ALLOW_SIMPLE_RULE_FALLBACK", "1");
    }
    if let Some(v) = trimmed_non_empty(opt.ingest_url.as_deref()) {
        std::env::set_var("OLOPA_INGEST_URL", v);
    }
    if let Some(v) = trimmed_non_empty(opt.ingest_tenant_id.as_deref()) {
        std::env::set_var("OLOPA_INGEST_TENANT_ID", v);
    }
    if let Some(v) = trimmed_non_empty(opt.ingest_host_id.as_deref()) {
        std::env::set_var("OLOPA_INGEST_HOST_ID", v);
    }
    if let Some(v) = trimmed_non_empty(opt.ingest_api_token.as_deref()) {
        std::env::set_var("OLOPA_INGEST_API_TOKEN", v);
    }
    if let Some(v) = trimmed_non_empty(opt.ingest_api_key.as_deref()) {
        std::env::set_var("OLOPA_INGEST_API_KEY", v);
    }
    if let Some(v) = trimmed_non_empty(opt.status_path.as_deref()) {
        std::env::set_var("OLOPA_STATUS_PATH", v);
    }
}

fn normalize_probe_selections(args: &[ProbeEventArg]) -> Vec<ProbeSelection> {
    let mut out = Vec::with_capacity(args.len());
    let mut seen = HashSet::new();
    for arg in args {
        let selection = arg.as_selection();
        if seen.insert(selection) {
            out.push(selection);
        }
    }
    out
}

fn resolve_iface(cli_iface: Option<&str>) -> String {
    if let Some(iface) = trimmed_non_empty(cli_iface) {
        return iface.to_string();
    }
    if let Some(iface) = env_non_empty("OLOPA_IFACE") {
        return iface;
    }
    if let Some(iface) = detect_default_route_iface() {
        return iface;
    }
    "lo".to_string()
}

fn detect_default_route_iface() -> Option<String> {
    let raw = fs::read_to_string("/proc/net/route").ok()?;
    for line in raw.lines().skip(1) {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 4 {
            continue;
        }
        let iface = cols[0];
        let destination = cols[1];
        let flags_hex = cols[3];
        if destination != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(flags_hex, 16).ok()?;
        if (flags & 0x2) == 0 {
            continue;
        }
        return Some(iface.to_string());
    }
    None
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn trimmed_non_empty(raw: Option<&str>) -> Option<&str> {
    raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeStatusSnapshot {
    pid: u32,
    running: bool,
    #[serde(default)]
    probes: Vec<String>,
    #[serde(default)]
    backend: RuntimeBackendStatus,
    #[serde(default)]
    resources: RuntimeResourceStatus,
    #[serde(default)]
    window_5s: RuntimeWindowStatus,
    #[serde(default)]
    firewall: RuntimeFirewallStatus,
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeBackendStatus {
    reachable: bool,
    rtt_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeResourceStatus {
    cpu_pct: f32,
    cpu_budget_pct: f32,
    mem_mb: f32,
    mem_ceiling_mb: f32,
    bw_mb_s: f32,
    bw_limit_pct: f32,
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeWindowStatus {
    captured: u64,
    transmitted: u64,
    dropped_budget: u64,
}

#[derive(Debug, Deserialize, Default)]
struct RuntimeFirewallStatus {
    allow: u64,
    deny: u64,
    approve: u64,
}

fn print_status(opt: StatusOpt) -> Result<()> {
    let color = !opt.no_color;
    let status_path = opt
        .status_path
        .or_else(|| env_non_empty("OLOPA_STATUS_PATH"))
        .unwrap_or_else(|| DEFAULT_STATUS_PATH.to_string());
    let path = PathBuf::from(&status_path);

    let snapshot = match fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<RuntimeStatusSnapshot>(&raw) {
            Ok(v) => v,
            Err(err) => {
                println!(
                    "{} status snapshot parse error at {}: {}",
                    glyph_error(color),
                    path.display(),
                    err
                );
                return Ok(());
            }
        },
        Err(_) => {
            println!(
                "{} agent not running (status file not found: {})",
                glyph_error(color),
                path.display()
            );
            return Ok(());
        }
    };

    let pid_alive = snapshot.pid > 0 && PathBuf::from(format!("/proc/{}", snapshot.pid)).exists();
    let running = snapshot.running && pid_alive;

    if !opt.no_mascot {
        print_mascot_bitmap(color);
    }

    if running {
        println!("{} agent running pid={}", glyph_ok(color), snapshot.pid);
    } else {
        if snapshot.pid > 0 && !pid_alive {
            println!(
                "{} agent stopped (stale status snapshot, last pid={})",
                glyph_error(color),
                snapshot.pid
            );
        } else {
            println!(
                "{} agent stopped (last pid={})",
                glyph_error(color),
                snapshot.pid
            );
        }
    }

    if snapshot.pid > 0 && !pid_alive {
        println!(
            "{} status snapshot is stale; start olopa to refresh live metrics",
            glyph_warn(color)
        );
        return Ok(());
    }

    if snapshot.backend.reachable {
        let rtt = snapshot
            .backend
            .rtt_ms
            .map(|v| format!("{v}ms"))
            .unwrap_or_else(|| "unknown".to_string());
        println!("{} backend reachable {} rtt", glyph_ok(color), rtt);
    } else {
        println!("{} backend unreachable", glyph_warn(color));
    }

    if !opt.verbose {
        return Ok(());
    }

    println!("{}", separator(color));
    println!(
        "cpu {}% / budget {}%",
        format_f32_trim(snapshot.resources.cpu_pct, 1),
        format_f32_trim(snapshot.resources.cpu_budget_pct, 1)
    );
    println!(
        "mem {} MB / ceiling {}MB",
        format_f32_trim(snapshot.resources.mem_mb, 1),
        format_f32_trim(snapshot.resources.mem_ceiling_mb, 1)
    );
    println!(
        "bw {} MB/s / limit {}%",
        format_f32_trim(snapshot.resources.bw_mb_s, 2),
        format_f32_trim(snapshot.resources.bw_limit_pct, 1)
    );

    println!("{}", separator(color));
    println!("{}", heading(color, "probes attached"));
    if snapshot.probes.is_empty() {
        println!("none");
    } else {
        for chunk in snapshot.probes.chunks(3) {
            println!("{}", chunk.join(" "));
        }
    }

    println!("{}", separator(color));
    println!("{}", heading(color, "events / 5s window"));
    println!(
        "{} captured",
        format_u64_grouped(snapshot.window_5s.captured)
    );
    println!(
        "{} transmitted",
        format_u64_grouped(snapshot.window_5s.transmitted)
    );
    println!(
        "{} dropped (budget)",
        format_u64_grouped(snapshot.window_5s.dropped_budget)
    );

    println!("{}", separator(color));
    println!("{}", heading(color, "firewall verdicts / lifetime"));
    println!(
        "{} {}",
        verdict_allow_label(color),
        format_u64_grouped(snapshot.firewall.allow)
    );
    println!(
        "{} {}",
        verdict_deny_label(color),
        format_u64_grouped(snapshot.firewall.deny)
    );
    println!(
        "{} {}",
        verdict_approve_label(color),
        format_u64_grouped(snapshot.firewall.approve)
    );

    println!("{}", separator(color));
    println!("{}", heading(color, "secure connect"));
    match secure_connect::read_health_from_env() {
        Some(health) if health.enabled => {
            println!("state {:?}", health.state);
            println!(
                "device {} session {} interface {}",
                health.device_id.as_deref().unwrap_or("unassigned"),
                health.session_id.as_deref().unwrap_or("none"),
                health.interface.as_deref().unwrap_or("none")
            );
            println!(
                "profile v{} handshake={} rx={} tx={} reconnects={}",
                health.profile_version,
                health.last_handshake_unix,
                format_u64_grouped(health.bytes_rx),
                format_u64_grouped(health.bytes_tx),
                format_u64_grouped(health.reconnect_count)
            );
            println!(
                "apply={}ms revoke={}ms kill-switch={}ms",
                health.policy_apply_ms, health.revoke_apply_ms, health.kill_switch_apply_ms
            );
            if let Some(error) = health.last_error {
                println!("{} {}", glyph_warn(color), error);
            }
        }
        _ => println!("disabled"),
    }

    Ok(())
}

fn print_mascot_bitmap(color: bool) {
    // Keep banner in a dedicated asset file so updates do not require code edits.
    const ASCII_ART: &str = include_str!("assets/ascii_art.txt");
    if !color {
        for row in ASCII_ART.lines() {
            println!("{row}");
        }
        return;
    }

    for row in ASCII_ART.lines() {
        println!("{}", themed_ascii_row(row));
    }
}

fn themed_ascii_row(row: &str) -> String {
    const BLUE: &str = "\x1b[38;5;25m";
    const YELLOW: &str = "\x1b[38;5;220m";
    const RESET: &str = "\x1b[0m";

    let mut out = String::with_capacity(row.len() * 8);
    for ch in row.chars() {
        if ch == ' ' {
            out.push(' ');
            continue;
        }

        // Police-theme split: body text in blue, strokes/highlights in yellow.
        let tone = if matches!(ch, '$' | '/' | '\\' | '_' | '-') {
            YELLOW
        } else {
            BLUE
        };
        out.push_str(tone);
        out.push(ch);
        out.push_str(RESET);
    }
    out
}

fn separator(color: bool) -> String {
    if color {
        "\x1b[2m─────────────────────────────\x1b[0m".to_string()
    } else {
        "─────────────────────────────".to_string()
    }
}

fn heading(color: bool, label: &str) -> String {
    if color {
        format!("\x1b[1;36m{}\x1b[0m", label)
    } else {
        label.to_string()
    }
}

fn verdict_allow_label(color: bool) -> String {
    if color {
        "\x1b[1;32mALLOW\x1b[0m".to_string()
    } else {
        "ALLOW".to_string()
    }
}

fn verdict_deny_label(color: bool) -> String {
    if color {
        "\x1b[1;31mDENY\x1b[0m".to_string()
    } else {
        "DENY".to_string()
    }
}

fn verdict_approve_label(color: bool) -> String {
    if color {
        "\x1b[1;33mAPPROVE\x1b[0m".to_string()
    } else {
        "APPROVE".to_string()
    }
}

fn format_f32_trim(value: f32, precision: usize) -> String {
    let mut out = format!("{value:.*}", precision);
    while out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out
}

fn glyph_ok(color: bool) -> String {
    if color {
        "\x1b[32m●\x1b[0m".to_string()
    } else {
        "●".to_string()
    }
}

fn glyph_warn(color: bool) -> String {
    if color {
        "\x1b[33m●\x1b[0m".to_string()
    } else {
        "●".to_string()
    }
}

fn glyph_error(color: bool) -> String {
    if color {
        "\x1b[31m●\x1b[0m".to_string()
    } else {
        "●".to_string()
    }
}

fn format_u64_grouped(value: u64) -> String {
    let s = value.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

// --- Concrete adapters for orchestrator traits ---

#[derive(Default)]
/// Adapter around `RelevanceScorer` that tracks synthetic event ids.
struct RealRelevanceScorer {
    inner: RelevanceScorer,
    // Monotonic synthetic event id passed into scorer state machine.
    next_event_id: usize,
}

impl Default for RelevanceScorer {
    fn default() -> Self {
        RelevanceScorer::with_default_epsilon()
    }
}

impl RelevanceScorerLike for RealRelevanceScorer {
    /// Score one event and update its `risk_score` with computed relevance.
    fn score(&mut self, event: &mut IngestEvent) {
        // Current bridge passes core numeric fields only; richer context wiring
        // can be layered later without changing orchestrator contract.
        let scored = self.inner.score(
            self.next_event_id,
            event.vertex_id,
            event.risk_score,
            event.ts_ns,
            0,
        );
        self.next_event_id = self.next_event_id.saturating_add(1);

        // Map scorer output back into event risk used downstream.
        event.risk_score = scored.map(|s| s.relevance).unwrap_or(0.0);
    }
}

/// Adapter around persistent hot/cold event storage.
struct RealEventStore {
    inner: EventStore,
    events: Vec<IngestEvent>,
}

impl Default for RealEventStore {
    fn default() -> Self {
        Self::with_capacity(1_000_000)
    }
}

impl RealEventStore {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: EventStore::with_capacity(capacity),
            events: Vec::with_capacity(capacity),
        }
    }
}

impl EventStoreLike for RealEventStore {
    /// Persist one event and return the assigned event id.
    fn push(&mut self, event: IngestEvent) -> Option<usize> {
        // Split event into hot/cold representations expected by EventStore.
        let hot = HotEvent {
            ts_ns: event.ts_ns,
            pid: event.pid,
            risk_score: event.risk_score,
        };
        let cold = ColdEvent {
            argv_hash: [0; 32],
            path_hash: [0; 32],
            env_hash: [0; 32],
            ppid: event.dst_vertex_id,
            uid: event.uid,
            gid: 0,
            comm_id: event.comm_id,
            _pad: [0; 16],
        };

        let id = self.inner.push(hot, cold)?;
        debug_assert_eq!(id, self.events.len());
        self.events.push(event);
        info!(
            "ingest->store event_id={} type={} pid={} risk={:.3}",
            id, event.event_type, event.pid, event.risk_score
        );
        Some(id)
    }

    /// Serialize one stored event into transport-ready bytes.
    fn serialize_event(&self, event_id: usize) -> Option<Vec<u8>> {
        crate::agent::encode_telemetry_payload(self.events.get(event_id)?)
    }

    /// Return event ids that have not yet been scheduled.
    fn unscheduled_event_ids(&self, from: usize) -> Vec<usize> {
        (from..self.inner.hot_events().len()).collect()
    }

    /// Return last valid event id.
    fn last_event_id(&self) -> usize {
        self.inner.hot_events().len().saturating_sub(1)
    }
}

#[cfg(test)]
mod event_store_transport_tests {
    use super::*;

    #[test]
    fn real_event_store_keeps_family_fields_for_scheduler_serialization() {
        let mut tables = [0u8; crate::sql_norm::SQL_TABLES_LEN];
        tables[..14].copy_from_slice(b"finance.ledger");
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"psql");
        let event = IngestEvent {
            event_type: 4,
            pid: 4242,
            uid: 1001,
            comm,
            sql_query_hash: 0x1111_2222,
            sql_query_class: 3,
            sql_db_port: 5432,
            sql_norm_hash: 0xaabb_ccdd,
            sql_tables: tables,
            ..Default::default()
        };

        let mut store = RealEventStore::with_capacity(4);
        let event_id = store.push(event).expect("store event");
        let encoded = store.serialize_event(event_id).expect("serialize event");
        let json = std::str::from_utf8(&encoded)
            .expect("utf8 wire record")
            .strip_prefix("event_v2 ")
            .expect("typed wire prefix");
        let decoded: crate::agent::TelemetryWireEvent =
            serde_json::from_str(json).expect("decode typed wire event");

        assert_eq!(decoded.event_type, 4);
        assert_eq!(decoded.comm, "psql");
        assert_eq!(decoded.sql_query_class, 3);
        assert_eq!(decoded.sql_db_port, 5432);
        assert_eq!(decoded.sql_tables, "finance.ledger");
        assert_eq!(decoded.sql_norm_hash, 0xaabb_ccdd);
    }
}

/// Adapter around RCU CSR graph plus optional periodic graph dump writer.
struct RealGraph {
    inner: Arc<CsrGraph>,
    graph_dumper: Option<GraphDumpWriter>,
    recent_events: VecDeque<GraphDumpEvent>,
    last_span_by_pid: HashMap<u32, u64>,
    vertex_index: HashMap<(NodeLabel, u32), u32>,
    next_vertex_id: u32,
    max_nodes: u32,
    capacity_warning_emitted: bool,
    next_span_id: u64,
}

impl Default for RealGraph {
    fn default() -> Self {
        Self {
            inner: Arc::new(CsrGraph::new(0, 262_144)),
            graph_dumper: None,
            recent_events: VecDeque::with_capacity(MAX_DUMP_EVENTS),
            last_span_by_pid: HashMap::new(),
            vertex_index: HashMap::new(),
            next_vertex_id: 0,
            max_nodes: graph_max_nodes(),
            capacity_warning_emitted: false,
            next_span_id: 1,
        }
    }
}

impl RealGraph {
    /// Construct graph adapter with JSON dump support enabled.
    fn with_dump(path: PathBuf, min_interval: Duration) -> Self {
        Self {
            inner: Arc::new(CsrGraph::new(0, 262_144)),
            graph_dumper: Some(GraphDumpWriter::new(path, min_interval)),
            recent_events: VecDeque::with_capacity(MAX_DUMP_EVENTS),
            last_span_by_pid: HashMap::new(),
            vertex_index: HashMap::new(),
            next_vertex_id: 0,
            max_nodes: graph_max_nodes(),
            capacity_warning_emitted: false,
            next_span_id: 1,
        }
    }

    fn resolve_vertex(
        &mut self,
        label: NodeLabel,
        raw_id: u32,
        ts_ns: u64,
        risk_score: f32,
        is_internal: bool,
    ) -> Option<u32> {
        let key = (label, raw_id);
        if let Some(id) = self.vertex_index.get(&key).copied() {
            self.inner.update_risk(id, risk_score, ts_ns);
            return Some(id);
        }
        if self.next_vertex_id >= self.max_nodes {
            if !self.capacity_warning_emitted {
                warn!(
                    "graph compact vertex allocator reached OLOPA_GRAPH_MAX_NODES={} (new entities will be skipped)",
                    self.max_nodes
                );
                self.capacity_warning_emitted = true;
            }
            return None;
        }
        let id = self.next_vertex_id;
        self.next_vertex_id = self.next_vertex_id.saturating_add(1);
        self.vertex_index.insert(key, id);
        self.inner.write_node(
            id,
            crate::data::csr_graph::NodeProps {
                first_seen_ns: ts_ns,
                last_seen_ns: ts_ns,
                risk_score,
                page_rank: 0.0,
                label,
                is_internal,
                is_canary: false,
                community_id: 0,
                _pad: [0; 4],
            },
        );
        Some(id)
    }

    /// Cache an event for graph dump rendering and event lineage visualization.
    fn record_event(&mut self, event: &IngestEvent, graph_source_id: u32, graph_target_id: u32) {
        let span_id = self.next_span_id;
        self.next_span_id = self.next_span_id.saturating_add(1);
        let parent_span_id = self.last_span_by_pid.insert(event.pid, span_id);

        self.recent_events.push_back(GraphDumpEvent {
            event_id: span_id,
            ts_ns: event.ts_ns,
            event_type: event_type_name(event.event_type).to_string(),
            event_type_code: event.event_type,
            span_id,
            parent_span_id,
            parent_id: event.dst_vertex_id,
            graph_parent_id: graph_target_id,
            pid: event.pid,
            uid: event.uid,
            source_id: event.vertex_id,
            target_id: event.dst_vertex_id,
            graph_source_id,
            graph_target_id,
            comm: event_comm_to_string(&event.comm),
            comm_id: event.comm_id,
            risk_score: event.risk_score,
        });
        while self.recent_events.len() > MAX_DUMP_EVENTS {
            self.recent_events.pop_front();
        }
    }
}

impl GraphLike for RealGraph {
    /// Insert graph edge for one event and trigger optional dump write.
    fn write_edge(&mut self, event: &IngestEvent) {
        // Map lightweight event discriminator to graph edge kind.
        let kind = match event.event_type {
            1 => EdgeKind::Spawned,
            2 => EdgeKind::ReadFile,
            3 => EdgeKind::ConnectedTo,
            4 => EdgeKind::DataFlow,
            5 => EdgeKind::ConnectedTo,
            6 => EdgeKind::ResolvedDns,
            _ => EdgeKind::DataFlow,
        };

        let props = EdgeProps {
            ts_ns: event.ts_ns,
            kind,
            causal: true,
            risk_weight: (event.risk_score.clamp(0.0, 1.0) * 255.0) as u8,
            _pad: 0,
            bytes: 0,
        };

        let target_label = match event.event_type {
            1 => NodeLabel::Process,
            2 => NodeLabel::File,
            3 | 5 | 7 => NodeLabel::NetworkEndpoint,
            4 => NodeLabel::Host,
            6 => NodeLabel::DomainName,
            _ => NodeLabel::Host,
        };
        let target_raw_id = match event.event_type {
            3 | 5 | 7 if event.net_dst_ip != 0 => event.net_dst_ip,
            4 if event.sql_query_hash != 0 => event.sql_query_hash,
            6 if event.dns_query_hash != 0 => event.dns_query_hash,
            _ => event.dst_vertex_id,
        };
        let target_internal = match event.event_type {
            3 | 5 | 7 if event.net_dst_ip != 0 => {
                let ip = Ipv4Addr::from(event.net_dst_ip);
                ip.is_private() || ip.is_loopback() || ip.is_link_local()
            }
            _ => true,
        };
        let source = self.resolve_vertex(
            NodeLabel::Process,
            event.pid,
            event.ts_ns,
            event.risk_score,
            true,
        );
        let target = self.resolve_vertex(
            target_label,
            target_raw_id,
            event.ts_ns,
            event.risk_score,
            target_internal,
        );
        if let (Some(source), Some(target)) = (source, target) {
            self.inner.write_edge(source, target, props);
            self.record_event(event, source, target);
        }
        if let Some(dumper) = self.graph_dumper.as_mut() {
            if let Err(err) = dumper.maybe_dump(&self.inner, &self.recent_events) {
                warn!("graph dump write failed: {}", err);
            }
        }
    }

    /// Merge queued graph deltas into new snapshot and optionally dump.
    fn merge_deltas(&mut self) {
        self.inner.merge_deltas();
        if let Some(dumper) = self.graph_dumper.as_mut() {
            if let Err(err) = dumper.maybe_dump(&self.inner, &self.recent_events) {
                warn!("graph dump write failed: {}", err);
            }
        }
    }
}

/// Adapter around userspace metric aggregator.
struct RealMetricAggregator {
    inner: MetricAggregator,
}

impl Default for RealMetricAggregator {
    fn default() -> Self {
        Self {
            inner: MetricAggregator::new(5_000),
        }
    }
}

impl MetricAggregatorLike for RealMetricAggregator {
    /// Record one event into metric aggregates.
    fn record(&mut self, event: &IngestEvent) {
        // Risk metric keyed by comm_id to preserve low cardinality.
        self.inner.record_risk(event.comm_id, event.risk_score);
    }

    /// Flush metric summaries and serialize each summary into payload bytes.
    fn flush(&mut self) -> Vec<Vec<u8>> {
        self.inner
            .flush()
            .into_iter()
            .map(serialize_metric_summary)
            .collect()
    }
}

/// Adapter around MDKP scheduler.
struct RealScheduler {
    inner: Scheduler,
}

impl Default for RealScheduler {
    fn default() -> Self {
        Self {
            inner: Scheduler::new(SchedulerBudgetSnapshot::default_budgets()),
        }
    }
}

impl SchedulerLike for RealScheduler {
    /// Apply latest budget snapshot to scheduler.
    fn update_budget(&mut self, snapshot: RuntimeBudgetSnapshot) {
        // Convert runtime tracker snapshot into scheduler-local budget type.
        let converted = SchedulerBudgetSnapshot {
            total: snapshot.total,
            remaining: snapshot.remaining,
            weights: snapshot.weights,
        };
        self.inner.update_budget(converted);
    }

    /// Enqueue one event id as scheduler candidate.
    fn enqueue(&mut self, event_id: usize) {
        // Placeholder relevance/cost mapping until full scorer->scheduler bridge is wired.
        let item = TelemetryItem::new(event_id, 0.5, [1.0; N_RESOURCES]);
        self.inner.enqueue(item);
    }

    /// Solve scheduling window and return selected event ids.
    fn solve(&mut self) -> Vec<usize> {
        let selected = self.inner.solve(SolverTier::Greedy).event_ids;
        info!("scheduler.solve selected={} events", selected.len());
        selected
    }
}

// --- Bootstrap components for rule engine, batching, and transport ---

/// Extremely small fallback matcher used only when explicitly enabled.
struct SimpleRuleEngine;

impl RuleEngineLike for SimpleRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
        if event.risk_score >= 0.95 {
            vec![RuleMatch {
                rule_id: "simple:fallback".to_string(),
                rule_name: "simple_fallback_threshold".to_string(),
                enforce_block_egress: false,
                enforce_block_query: false,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Concrete rule engine currently serving evaluations.
enum RuleEngineMode {
    // Compiler-emitted runtime IR evaluator.
    RuntimeIr(RuntimeIrRuleEngine),
    // Minimal fallback matcher when runtime IR cannot be loaded.
    Simple(SimpleRuleEngine),
}

/// Reloadable rule engine wrapper. New artifacts are fully parsed and contract
/// validated before the active evaluator is swapped, so a partial or invalid
/// deployment cannot interrupt the last known-good policy.
struct ActiveRuleEngine {
    current: RuleEngineMode,
    previous: Option<(RuntimeIrRuleEngine, u64)>,
    path: PathBuf,
    /// Fingerprint of the evaluator currently serving traffic.
    fingerprint: Option<u64>,
    /// Last successfully loaded on-disk fingerprint; used to avoid undoing an
    /// explicit rollback until a genuinely new artifact is deployed.
    observed_fingerprint: Option<u64>,
    generation: u64,
    last_check: Instant,
    check_interval: Duration,
    rollback_signal: PathBuf,
    status_path: PathBuf,
}

#[derive(Serialize)]
struct RuleDeploymentStatus<'a> {
    version: u8,
    generation: u64,
    artifact_path: &'a str,
    artifact_fingerprint: Option<String>,
    rule_count: usize,
    fallback_active: bool,
    previous_available: bool,
    updated_at_unix_ms: u64,
    last_error: Option<&'a str>,
}

impl ActiveRuleEngine {
    /// Load runtime-ir rule engine from disk with optional fallback behavior.
    fn from_env() -> Result<Self> {
        // Explicit env var overrides default deployment path.
        let path = std::env::var("OLOPA_RUNTIME_IR")
            .unwrap_or_else(|_| DEFAULT_RUNTIME_IR_PATH.to_string());
        let allow_simple_fallback = env_flag("OLOPA_ALLOW_SIMPLE_RULE_FALLBACK");

        match RuntimeIrRuleEngine::from_file(std::path::Path::new(&path)) {
            Ok(engine) => {
                info!(
                    "rule engine loaded runtime-ir from {} (rules={})",
                    path,
                    engine.rule_count()
                );
                let fingerprint = artifact_fingerprint(std::path::Path::new(&path)).ok();
                let active = Self {
                    current: RuleEngineMode::RuntimeIr(engine),
                    previous: None,
                    path: PathBuf::from(path),
                    fingerprint,
                    observed_fingerprint: fingerprint,
                    generation: 1,
                    last_check: Instant::now(),
                    check_interval: Duration::from_millis(
                        env_parse_or("OLOPA_RUNTIME_IR_RELOAD_MS", 1_000u64).max(100),
                    ),
                    rollback_signal: env_non_empty("OLOPA_RUNTIME_IR_ROLLBACK_SIGNAL")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/var/lib/olopa/runtime-ir.rollback")),
                    status_path: env_non_empty("OLOPA_RULE_STATUS_PATH")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/rules.json")),
                };
                active.write_rule_status(None);
                Ok(active)
            }
            Err(e) => {
                if allow_simple_fallback {
                    warn!("failed to load runtime-ir from {}: {}", path, e);
                    warn!(
                        "rule engine using SimpleRuleEngine fallback (OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1)"
                    );
                    let active = Self {
                        current: RuleEngineMode::Simple(SimpleRuleEngine),
                        previous: None,
                        path: PathBuf::from(path),
                        fingerprint: None,
                        observed_fingerprint: None,
                        generation: 1,
                        last_check: Instant::now(),
                        check_interval: Duration::from_millis(
                            env_parse_or("OLOPA_RUNTIME_IR_RELOAD_MS", 1_000u64).max(100),
                        ),
                        rollback_signal: env_non_empty("OLOPA_RUNTIME_IR_ROLLBACK_SIGNAL")
                            .map(PathBuf::from)
                            .unwrap_or_else(|| PathBuf::from("/var/lib/olopa/runtime-ir.rollback")),
                        status_path: env_non_empty("OLOPA_RULE_STATUS_PATH")
                            .map(PathBuf::from)
                            .unwrap_or_else(|| PathBuf::from("/tmp/olopa/agent/rules.json")),
                    };
                    active.write_rule_status(Some(&e.to_string()));
                    Ok(active)
                } else {
                    bail!(
                        "failed to load runtime-ir from {} (set OLOPA_ALLOW_SIMPLE_RULE_FALLBACK=1 to force simple fallback): {}",
                        path,
                        e
                    );
                }
            }
        }
    }

    fn maybe_reload(&mut self) {
        if self.last_check.elapsed() < self.check_interval {
            return;
        }
        self.last_check = Instant::now();

        if self.rollback_signal.exists() {
            if let Some((previous, previous_fingerprint)) = self.previous.take() {
                let displaced =
                    match std::mem::replace(&mut self.current, RuleEngineMode::RuntimeIr(previous))
                    {
                        RuleEngineMode::RuntimeIr(engine) => {
                            self.fingerprint.map(|fingerprint| (engine, fingerprint))
                        }
                        RuleEngineMode::Simple(_) => None,
                    };
                self.previous = displaced;
                self.generation = self.generation.saturating_add(1);
                self.fingerprint = Some(previous_fingerprint);
                info!(
                    "rule engine rollback activated generation={}",
                    self.generation
                );
                self.write_rule_status(None);
            } else {
                warn!("rule rollback requested but no previous artifact is available");
                self.write_rule_status(Some("rollback requested without previous artifact"));
            }
            if let Err(err) = fs::remove_file(&self.rollback_signal) {
                warn!(
                    "failed removing rule rollback signal {}: {}",
                    self.rollback_signal.display(),
                    err
                );
            }
            return;
        }

        let fingerprint = match artifact_fingerprint(&self.path) {
            Ok(fingerprint) => fingerprint,
            Err(err) => {
                self.write_rule_status(Some(&err.to_string()));
                return;
            }
        };
        if self.observed_fingerprint == Some(fingerprint) {
            return;
        }

        match RuntimeIrRuleEngine::from_file(&self.path) {
            Ok(next) => {
                let next_count = next.rule_count();
                let displaced =
                    std::mem::replace(&mut self.current, RuleEngineMode::RuntimeIr(next));
                self.previous = match displaced {
                    RuleEngineMode::RuntimeIr(engine) => self
                        .fingerprint
                        .map(|previous_fingerprint| (engine, previous_fingerprint)),
                    RuleEngineMode::Simple(_) => None,
                };
                self.fingerprint = Some(fingerprint);
                self.observed_fingerprint = Some(fingerprint);
                self.generation = self.generation.saturating_add(1);
                info!(
                    "rule engine hot reload activated generation={} rules={} fingerprint={:016x}",
                    self.generation, next_count, fingerprint
                );
                self.write_rule_status(None);
            }
            Err(err) => {
                warn!(
                    "rule engine rejected replacement artifact {}; keeping generation {}: {}",
                    self.path.display(),
                    self.generation,
                    err
                );
                self.write_rule_status(Some(&err.to_string()));
            }
        }
    }

    fn write_rule_status(&self, last_error: Option<&str>) {
        let (rule_count, fallback_active) = match &self.current {
            RuleEngineMode::RuntimeIr(engine) => (engine.rule_count(), false),
            RuleEngineMode::Simple(_) => (1, true),
        };
        let artifact_path = self.path.to_string_lossy();
        let fingerprint = self.fingerprint.map(|value| format!("{value:016x}"));
        let status = RuleDeploymentStatus {
            version: 1,
            generation: self.generation,
            artifact_path: &artifact_path,
            artifact_fingerprint: fingerprint,
            rule_count,
            fallback_active,
            previous_available: self.previous.is_some(),
            updated_at_unix_ms: now_unix_ns() / 1_000_000,
            last_error,
        };
        if let Some(parent) = self.status_path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                warn!("failed creating rule status directory: {}", err);
                return;
            }
        }
        let temp = self.status_path.with_extension("tmp");
        let body = match serde_json::to_vec_pretty(&status) {
            Ok(body) => body,
            Err(err) => {
                warn!("failed serializing rule status: {}", err);
                return;
            }
        };
        if let Err(err) = fs::write(&temp, body).and_then(|_| fs::rename(&temp, &self.status_path))
        {
            warn!(
                "failed writing rule status {}: {}",
                self.status_path.display(),
                err
            );
        }
    }
}

fn artifact_fingerprint(path: &std::path::Path) -> Result<u64> {
    let bytes = fs::read(path)
        .with_context(|| format!("read runtime artifact fingerprint from {}", path.display()))?;
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(hash)
}

fn env_parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    env_non_empty(key)
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

/// Read permissive boolean environment flag values (`1/true/yes/on`).
fn env_flag(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let value = v.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Populate the XDP exact IPv4 source blocklist.
///
/// `OLOPA_XDP_BLOCK_IPS` is a comma-separated list such as
/// `198.51.100.10,203.0.113.7`. Invalid values fail startup so a partially
/// applied threat policy is never mistaken for complete enforcement.
fn install_xdp_blocklist_from_env(bpf: &mut aya::Ebpf) -> Result<()> {
    let raw = match std::env::var("OLOPA_XDP_BLOCK_IPS") {
        Ok(raw) => raw,
        Err(_) => return Ok(()),
    };
    let mut addresses = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        addresses.push(
            token
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid IPv4 '{}' in OLOPA_XDP_BLOCK_IPS", token))?,
        );
    }
    if addresses.is_empty() {
        return Ok(());
    }

    let map_data = bpf
        .map_mut("XDP_BLOCKLIST_V4")
        .context("XDP_BLOCKLIST_V4 map not found in loaded eBPF object")?;
    let mut blocklist: BpfHashMap<_, u32, u8> =
        BpfHashMap::try_from(map_data).context("failed to open XDP_BLOCKLIST_V4 map")?;
    for address in addresses {
        blocklist
            .insert(u32::from(address), 1, 0)
            .with_context(|| format!("failed to insert XDP block IP {}", address))?;
        info!("xdp-policy deny installed source_ip={}", address);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
/// Parsed userspace representation of one deny rule from `OLOPA_TC_DENY_RULES`.
struct TcDenyRule {
    /// Process id to match in TC enforcement key.
    pid: u32,
    /// Stable cgroup id to match; zero is a wildcard.
    cgroup_id: u64,
    /// Canonical IPv4 `u32` form (`u32::from(Ipv4Addr)`).
    dst_ip: u32,
    /// Host-order destination port.
    dst_port: u16,
    /// Layer-4 protocol number (6=tcp, 17=udp).
    proto: u8,
    action: u8,
    rate: Option<TcRateLimitConfig>,
}

impl TcDenyRule {
    /// Convert parsed userspace rule into shared map key format.
    fn as_policy_key(self) -> TcEgressPolicyKey {
        TcEgressPolicyKey {
            cgroup_id: self.cgroup_id,
            pid: self.pid,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port,
            proto: self.proto,
            _pad: 0,
        }
    }
}

/// Load deny policy rules from environment into the kernel TC policy map.
///
/// Env format:
/// - `OLOPA_TC_DENY_RULES='pid=123,ip=1.2.3.4,port=443;cgroup=9981,ip=8.8.8.8,port=53,proto=udp'`
///
/// Behavior:
/// - Missing env var: no-op.
/// - Parse errors: startup fails loudly to avoid silently partial policy.
/// - Successful parse: each rule inserted with deny action byte.
fn install_tc_deny_rules_from_env(bpf: &mut aya::Ebpf) -> Result<()> {
    let mut rules = match std::env::var("OLOPA_TC_DENY_RULES") {
        Ok(raw) => parse_tc_deny_rules(&raw)?,
        Err(_) => Vec::new(),
    };
    if let Ok(raw) = std::env::var("OLOPA_TC_POLICY_RULES") {
        rules.extend(parse_tc_policy_rules(&raw)?);
    }
    if rules.is_empty() {
        return Ok(());
    }

    let map_data = bpf
        .map_mut("TC_EGRESS_POLICY")
        .context("TC_EGRESS_POLICY map not found in loaded eBPF object")?;
    let mut policy_map: BpfHashMap<_, TcEgressPolicyKey, u8> =
        BpfHashMap::try_from(map_data).context("failed to open TC_EGRESS_POLICY map")?;

    for rule in &rules {
        let key = rule.as_policy_key();
        policy_map.insert(key, rule.action, 0).with_context(|| {
            format!(
                "failed to insert tc deny rule pid={} cgroup={} dst_ip={} dst_port={} proto={}",
                rule.pid,
                rule.cgroup_id,
                Ipv4Addr::from(rule.dst_ip),
                rule.dst_port,
                rule.proto
            )
        })?;
        info!(
            "tc-policy action={} installed pid={} cgroup={} dst={}:{} proto={}",
            tc_action_name(rule.action),
            rule.pid,
            rule.cgroup_id,
            Ipv4Addr::from(rule.dst_ip),
            rule.dst_port,
            rule.proto
        );
    }
    drop(policy_map);

    let rate_rules = rules
        .iter()
        .filter_map(|rule| rule.rate.map(|rate| (rule, rate)));
    let mut rate_map = if rules.iter().any(|rule| rule.rate.is_some()) {
        Some(
            BpfHashMap::<_, TcEgressPolicyKey, TcRateLimitConfig>::try_from(
                bpf.map_mut("TC_EGRESS_RATE_CONFIG")
                    .context("TC_EGRESS_RATE_CONFIG map not found in loaded eBPF object")?,
            )
            .context("failed to open TC_EGRESS_RATE_CONFIG map")?,
        )
    } else {
        None
    };
    if let Some(rate_map) = rate_map.as_mut() {
        for (rule, rate) in rate_rules {
            rate_map
                .insert(rule.as_policy_key(), rate, 0)
                .with_context(|| {
                    format!(
                        "failed to insert tc rate limit pid={} cgroup={} pps={} burst={}",
                        rule.pid, rule.cgroup_id, rate.packets_per_second, rate.burst
                    )
                })?;
        }
    }

    Ok(())
}

/// Parse deny rule spec string into normalized rule structs.
///
/// Grammar (semicolon-separated entries):
/// - entry = `[pid=<u32>|cgroup=<u64>],ip=<ipv4>,port=<u16>[,proto=<tcp|udp|6|17>]`
/// - supported key aliases: `dst_ip`, `dst_port`
///
/// Notes:
/// - `proto` defaults to tcp (`6`) when omitted.
/// - unknown keys and missing required keys are treated as hard errors.
fn parse_tc_deny_rules(raw: &str) -> Result<Vec<TcDenyRule>> {
    parse_tc_rules(raw, false)
}

/// Parse allow/deny/rate-limit rules from `OLOPA_TC_POLICY_RULES`.
/// Rate entries require `action=rate,pps=<n>` and optionally `burst=<n>`.
fn parse_tc_policy_rules(raw: &str) -> Result<Vec<TcDenyRule>> {
    parse_tc_rules(raw, true)
}

fn parse_tc_rules(raw: &str, extended: bool) -> Result<Vec<TcDenyRule>> {
    let mut out = Vec::new();
    for (idx, entry_raw) in raw.split(';').enumerate() {
        let entry = entry_raw.trim();
        if entry.is_empty() {
            continue;
        }

        let mut pid: Option<u32> = None;
        let mut cgroup_id: Option<u64> = None;
        let mut dst_ip: Option<u32> = None;
        let mut dst_port: Option<u16> = None;
        let mut proto: Option<u8> = None;
        let mut action = TC_POLICY_ACTION_DENY;
        let mut packets_per_second: Option<u32> = None;
        let mut burst: Option<u32> = None;

        for part in entry.split(',') {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            let Some((k, v)) = token.split_once('=') else {
                bail!(
                    "invalid TC deny rule token '{}': expected key=value format in rule '{}'",
                    token,
                    entry
                );
            };
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim();
            match key.as_str() {
                "pid" => {
                    pid = Some(value.parse::<u32>().with_context(|| {
                        format!("invalid pid '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "cgroup" | "cgroup_id" => {
                    cgroup_id = Some(value.parse::<u64>().with_context(|| {
                        format!("invalid cgroup id '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "ip" | "dst_ip" => {
                    let ip = value.parse::<Ipv4Addr>().with_context(|| {
                        format!("invalid IPv4 '{}' in TC deny rule '{}'", value, entry)
                    })?;
                    dst_ip = Some(u32::from(ip));
                }
                "port" | "dst_port" => {
                    dst_port = Some(value.parse::<u16>().with_context(|| {
                        format!("invalid port '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "proto" => {
                    proto = Some(parse_l4_proto(value).with_context(|| {
                        format!("invalid proto '{}' in TC deny rule '{}'", value, entry)
                    })?);
                }
                "action" if extended => {
                    action = match value.to_ascii_lowercase().as_str() {
                        "allow" => TC_POLICY_ACTION_ALLOW,
                        "deny" => TC_POLICY_ACTION_DENY,
                        "rate" | "rate_limit" => TC_POLICY_ACTION_RATE_LIMIT,
                        _ => bail!("invalid TC policy action '{}' in rule '{}'", value, entry),
                    };
                }
                "pps" | "packets_per_second" if extended => {
                    packets_per_second = Some(value.parse::<u32>().with_context(|| {
                        format!(
                            "invalid packets-per-second '{}' in TC policy rule '{}'",
                            value, entry
                        )
                    })?);
                }
                "burst" if extended => {
                    burst = Some(value.parse::<u32>().with_context(|| {
                        format!("invalid burst '{}' in TC policy rule '{}'", value, entry)
                    })?);
                }
                _ => {
                    bail!(
                        "unsupported key '{}' in TC deny rule '{}' (supported: pid, cgroup, ip, port, proto)",
                        key,
                        entry
                    );
                }
            }
        }

        if pid.is_none() && cgroup_id.is_none() {
            bail!("missing pid or cgroup in TC deny rule '{}'", entry);
        }
        let pid = pid.unwrap_or(0);
        let cgroup_id = cgroup_id.unwrap_or(0);
        let dst_ip = dst_ip.with_context(|| format!("missing ip in TC deny rule '{}'", entry))?;
        let dst_port =
            dst_port.with_context(|| format!("missing port in TC deny rule '{}'", entry))?;
        let proto = proto.unwrap_or(6);
        let rate = if action == TC_POLICY_ACTION_RATE_LIMIT {
            let packets_per_second = packets_per_second
                .filter(|value| *value > 0)
                .with_context(|| format!("rate policy requires pps>0 in rule '{}'", entry))?;
            Some(TcRateLimitConfig {
                packets_per_second,
                burst: burst.unwrap_or(packets_per_second).max(1),
            })
        } else {
            if packets_per_second.is_some() || burst.is_some() {
                bail!(
                    "pps/burst require action=rate in TC policy rule '{}'",
                    entry
                );
            }
            None
        };

        out.push(TcDenyRule {
            pid,
            cgroup_id,
            dst_ip,
            dst_port,
            proto,
            action,
            rate,
        });

        if out.len() > 32_768 {
            bail!(
                "too many TC deny rules parsed (>{}) at rule index {}",
                32_768,
                idx
            );
        }
    }

    Ok(out)
}

fn tc_action_name(action: u8) -> &'static str {
    match action {
        TC_POLICY_ACTION_ALLOW => "allow",
        TC_POLICY_ACTION_DENY => "deny",
        TC_POLICY_ACTION_RATE_LIMIT => "rate_limit",
        _ => "unknown",
    }
}

/// Parse protocol string token into numeric protocol id used by TC map keys.
fn parse_l4_proto(raw: &str) -> Result<u8> {
    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "tcp" | "6" => Ok(6),
        "udp" | "17" => Ok(17),
        _ => bail!("unsupported proto '{}', expected tcp|udp|6|17", raw),
    }
}

#[cfg(test)]
mod tc_policy_tests {
    use super::*;

    #[test]
    fn parse_tc_deny_rules_accepts_valid_entries() {
        let spec = "pid=123,ip=1.2.3.4,port=443,proto=tcp;pid=7,ip=8.8.8.8,port=53,proto=17";
        let rules = parse_tc_deny_rules(spec).expect("valid tc deny rule spec should parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pid, 123);
        assert_eq!(rules[0].dst_ip, u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(rules[0].dst_port, 443);
        assert_eq!(rules[0].proto, 6);
        assert_eq!(rules[1].proto, 17);
    }

    #[test]
    fn parse_tc_deny_rules_rejects_missing_required_fields() {
        let spec = "pid=123,port=443,proto=tcp";
        let err = parse_tc_deny_rules(spec).expect_err("missing ip should fail");
        assert!(
            err.to_string().contains("missing ip"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_l4_proto_supports_names_and_numbers() {
        assert_eq!(parse_l4_proto("tcp").expect("tcp should parse"), 6);
        assert_eq!(parse_l4_proto("17").expect("17 should parse"), 17);
        assert!(parse_l4_proto("icmp").is_err());
    }

    #[test]
    fn parse_tc_policy_rules_supports_cgroup_allow_and_rate_limit() {
        let rules = parse_tc_policy_rules(
            "cgroup=42,ip=10.0.0.4,port=443,action=allow;cgroup=42,ip=8.8.8.8,port=53,proto=udp,action=rate,pps=100,burst=25",
        )
        .expect("valid TC policy rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, TC_POLICY_ACTION_ALLOW);
        assert_eq!(rules[0].cgroup_id, 42);
        assert_eq!(rules[1].action, TC_POLICY_ACTION_RATE_LIMIT);
        let rate = rules[1].rate.expect("rate config");
        assert_eq!(rate.packets_per_second, 100);
        assert_eq!(rate.burst, 25);
    }

    #[test]
    fn parse_tc_policy_rules_rejects_rate_without_pps() {
        let err = parse_tc_policy_rules("pid=1,ip=1.1.1.1,port=443,action=rate")
            .expect_err("rate policy without pps must fail");
        assert!(err.to_string().contains("requires pps"));
    }
}

impl RuleEngineLike for ActiveRuleEngine {
    fn evaluate(&mut self, event: &IngestEvent) -> Vec<RuleMatch> {
        self.maybe_reload();
        match &mut self.current {
            RuleEngineMode::RuntimeIr(engine) => engine.evaluate_matches(event),
            RuleEngineMode::Simple(engine) => engine.evaluate(event),
        }
    }
}

/// Adapter around compression batcher.
struct RealBatcher {
    inner: CompressorBatcher,
}

impl Default for RealBatcher {
    fn default() -> Self {
        let agent_id = std::env::var("OLOPA_AGENT_ID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        Self {
            inner: CompressorBatcher::new(agent_id, 4_096),
        }
    }
}

impl BatcherLike for RealBatcher {
    /// Push one event payload into compression batcher.
    fn push(&mut self, serialized_event: &[u8], _budget: &RuntimeBudgetSnapshot) -> BatcherPush {
        let budget = SchedulerBudgetSnapshot {
            total: _budget.total,
            remaining: _budget.remaining,
            weights: _budget.weights,
        };

        match self.inner.push(serialized_event, &budget) {
            CompressorPushResult::Ok => BatcherPush::Ok,
            CompressorPushResult::FlushNeeded | CompressorPushResult::QueueFull => {
                BatcherPush::FlushNeeded
            }
        }
    }

    /// Force flush currently buffered payloads.
    fn flush(&mut self) -> Option<Vec<u8>> {
        self.inner.flush().map(|batch| batch.payload.to_vec())
    }

    /// Flush only if time-based trigger has elapsed.
    fn flush_if_time_triggered(&mut self) -> Option<Vec<u8>> {
        self.inner
            .flush_if_ready()
            .map(|batch| batch.payload.to_vec())
    }
}

/// Encode metric summary in current text wire format.
fn serialize_metric_summary(s: MetricSummary) -> Vec<u8> {
    // Bootstrap text wire format for metric snapshots.
    format!(
        "metric comm_id={} count={} min={:.4} max={:.4} mean={:.4} p50={:.4} p95={:.4} p99={:.4}",
        s.comm_id, s.count, s.min, s.max, s.mean, s.p50, s.p95, s.p99
    )
    .into_bytes()
}

/// JSON node model for graph dumps consumed by UI/debug tools.
#[derive(Serialize)]
struct GraphDumpNode {
    id: u32,
    display_label: String,
    kind: String,
    risk_score: f32,
    is_internal: bool,
    is_canary: bool,
    out_degree: u32,
}

/// JSON edge model for graph dumps.
#[derive(Serialize)]
struct GraphDumpEdge {
    source: u32,
    target: u32,
    kind: String,
    edge_origin: String,
    risk_weight: u8,
    ts_ns: u64,
    causal: bool,
    bytes: u32,
    event_type: Option<String>,
    span_id: Option<u64>,
    parent_span_id: Option<u64>,
}

/// Top-level graph dump payload persisted by userspace runtime.
#[derive(Serialize)]
struct GraphDumpPayload {
    generated_at_unix_ns: u64,
    total_nodes: u32,
    total_edges: u32,
    graph_edges: usize,
    event_edges: usize,
    snapshot_nodes: u32,
    snapshot_edges: u32,
    total_events: usize,
    nodes: Vec<GraphDumpNode>,
    edges: Vec<GraphDumpEdge>,
    events: Vec<GraphDumpEvent>,
}

/// Recent event record embedded alongside graph topology in dumps.
#[derive(Serialize, Clone)]
struct GraphDumpEvent {
    event_id: u64,
    ts_ns: u64,
    event_type: String,
    event_type_code: u8,
    span_id: u64,
    parent_span_id: Option<u64>,
    parent_id: u32,
    graph_parent_id: u32,
    pid: u32,
    uid: u32,
    source_id: u32,
    target_id: u32,
    graph_source_id: u32,
    graph_target_id: u32,
    comm: String,
    comm_id: u32,
    risk_score: f32,
}

/// File writer responsible for periodic graph snapshot dumps.
struct GraphDumpWriter {
    path: PathBuf,
    min_interval: Duration,
    last_dump_at: Option<Instant>,
}

impl GraphDumpWriter {
    /// Create dump writer bound to output file and rate limit interval.
    fn new(path: PathBuf, min_interval: Duration) -> Self {
        Self {
            path,
            min_interval,
            last_dump_at: None,
        }
    }

    /// Persist graph dump only when minimum interval has elapsed.
    fn maybe_dump(
        &mut self,
        graph: &CsrGraph,
        recent_events: &VecDeque<GraphDumpEvent>,
    ) -> Result<()> {
        if let Some(last_dump_at) = self.last_dump_at {
            if last_dump_at.elapsed() < self.min_interval {
                return Ok(());
            }
        }

        let payload = build_graph_dump_payload(graph, recent_events);
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp_path = self.path.with_extension("tmp");
        let body = serde_json::to_vec_pretty(&payload)?;
        fs::write(&tmp_path, body)?;
        fs::rename(&tmp_path, &self.path)?;

        self.last_dump_at = Some(Instant::now());
        Ok(())
    }
}

/// Build a dump payload by combining graph snapshot + recent events.
fn build_graph_dump_payload(
    graph: &CsrGraph,
    recent_events: &VecDeque<GraphDumpEvent>,
) -> GraphDumpPayload {
    let snapshot = graph.snapshot();
    let mut active_nodes = HashSet::new();
    let mut latest_comm_by_graph_pid: HashMap<u32, String> = HashMap::new();

    let mut graph_edge_count = 0usize;
    let mut edges = Vec::with_capacity(snapshot.num_edges as usize);
    for src in 0..snapshot.num_nodes {
        let neighbors = snapshot.neighbors(src);
        let props = snapshot.neighbor_props(src);
        for (idx, &dst) in neighbors.iter().enumerate() {
            active_nodes.insert(src);
            active_nodes.insert(dst);
            let p = props[idx];
            edges.push(GraphDumpEdge {
                source: src,
                target: dst,
                kind: edge_kind_name(p.kind).to_string(),
                edge_origin: "graph".to_string(),
                risk_weight: p.risk_weight,
                ts_ns: p.ts_ns,
                causal: p.causal,
                bytes: p.bytes,
                event_type: None,
                span_id: None,
                parent_span_id: None,
            });
            graph_edge_count = graph_edge_count.saturating_add(1);
        }
    }

    for event in recent_events {
        active_nodes.insert(event.graph_source_id);
        active_nodes.insert(event.graph_target_id);
        active_nodes.insert(event.graph_parent_id);
        latest_comm_by_graph_pid
            .entry(event.graph_source_id)
            .or_insert_with(|| event.comm.clone());

        edges.push(GraphDumpEdge {
            source: event.graph_source_id,
            target: event.graph_target_id,
            kind: format!("event.{}", event.event_type),
            edge_origin: "event".to_string(),
            risk_weight: (event.risk_score.clamp(0.0, 1.0) * 255.0) as u8,
            ts_ns: event.ts_ns,
            causal: true,
            bytes: 0,
            event_type: Some(event.event_type.clone()),
            span_id: Some(event.span_id),
            parent_span_id: event.parent_span_id,
        });
    }
    let event_edge_count = edges.len().saturating_sub(graph_edge_count);

    let mut ordered_nodes = active_nodes.into_iter().collect::<Vec<_>>();
    ordered_nodes.sort_unstable();

    let mut nodes = Vec::with_capacity(ordered_nodes.len());
    for id in ordered_nodes {
        let n = snapshot.node(id);
        let display_label = if n.label == NodeLabel::Process {
            if let Some(comm) = latest_comm_by_graph_pid.get(&id) {
                if !comm.is_empty() {
                    format!("Process {} (#{})", comm, id)
                } else {
                    format!("Process #{}", id)
                }
            } else {
                format!("Process #{}", id)
            }
        } else {
            format!("{} #{}", node_label_name(n.label), id)
        };

        nodes.push(GraphDumpNode {
            id,
            display_label,
            kind: node_label_name(n.label).to_string(),
            risk_score: n.risk_score,
            is_internal: n.is_internal,
            is_canary: n.is_canary,
            out_degree: snapshot.degree(id),
        });
    }

    GraphDumpPayload {
        generated_at_unix_ns: now_unix_ns(),
        total_nodes: nodes.len() as u32,
        total_edges: edges.len() as u32,
        graph_edges: graph_edge_count,
        event_edges: event_edge_count,
        snapshot_nodes: snapshot.num_nodes,
        snapshot_edges: snapshot.num_edges,
        total_events: recent_events.len(),
        nodes,
        edges,
        events: recent_events.iter().cloned().collect(),
    }
}

/// Current wall-clock timestamp in nanoseconds since UNIX epoch.
fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// Render node label as human-readable name.
fn node_label_name(label: NodeLabel) -> &'static str {
    match label {
        NodeLabel::Process => "Process",
        NodeLabel::File => "File",
        NodeLabel::NetworkEndpoint => "NetworkEndpoint",
        NodeLabel::User => "User",
        NodeLabel::Host => "Host",
        NodeLabel::Secret => "Secret",
        NodeLabel::AgentSession => "AgentSession",
        NodeLabel::ToolCall => "ToolCall",
        NodeLabel::Container => "Container",
        NodeLabel::DomainName => "DomainName",
    }
}

/// Render edge kind as human-readable name.
fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Spawned => "Spawned",
        EdgeKind::ReadFile => "ReadFile",
        EdgeKind::WroteFile => "WroteFile",
        EdgeKind::ConnectedTo => "ConnectedTo",
        EdgeKind::AccessedSecret => "AccessedSecret",
        EdgeKind::LateralMove => "LateralMove",
        EdgeKind::RanAs => "RanAs",
        EdgeKind::DataFlow => "DataFlow",
        EdgeKind::CalledTool => "CalledTool",
        EdgeKind::ResolvedDns => "ResolvedDns",
        EdgeKind::ExecIn => "ExecIn",
        EdgeKind::HasProcess => "HasProcess",
    }
}

/// Render numeric event type to stable string label.
fn event_type_name(event_type: u8) -> &'static str {
    match event_type {
        1 => "exec",
        2 => "file",
        3 => "net",
        4 => "sql",
        5 => "ssl",
        6 => "dns",
        _ => "unknown",
    }
}

/// Convert 16-byte null-terminated comm buffer into UTF-8 string.
fn event_comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    std::str::from_utf8(&comm[..end]).unwrap_or("").to_string()
}

/// Maximum number of recent events retained in dump payload.
const MAX_DUMP_EVENTS: usize = 10_000;
/// Maximum dense vertex count. The compact allocator prevents raw kernel ids
/// from forcing sparse multi-gigabyte arrays while avoiding modulo collisions.
fn graph_max_nodes() -> u32 {
    std::env::var("OLOPA_GRAPH_MAX_NODES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1_000_000)
        .max(1_024)
}

/// Format attached probe selections for startup logs.
fn format_probe_selections(selections: &[ProbeSelection]) -> String {
    selections
        .iter()
        .map(|selection| probe_selection_name(*selection))
        .collect::<Vec<_>>()
        .join(",")
}

/// Render one probe selection as CLI-style token.
fn probe_selection_name(selection: ProbeSelection) -> &'static str {
    match selection {
        ProbeSelection::Fork => "fork",
        ProbeSelection::Exec => "exec",
        ProbeSelection::File => "file",
        ProbeSelection::Net => "net",
        ProbeSelection::Xdp => "xdp",
        ProbeSelection::Tc => "tc",
        ProbeSelection::Sql => "sql",
        ProbeSelection::Ssl => "ssl",
        ProbeSelection::Dns => "dns",
    }
}

fn expand_probe_status_tokens(selections: &[ProbeSelection]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for selection in selections {
        match selection {
            ProbeSelection::Fork => out.push("fork"),
            ProbeSelection::Exec => out.push("execve"),
            ProbeSelection::File => {
                out.push("openat");
                out.push("write");
            }
            ProbeSelection::Net => {
                out.push("connect");
                out.push("accept");
            }
            ProbeSelection::Xdp => out.push("xdp"),
            ProbeSelection::Tc => out.push("tc"),
            ProbeSelection::Sql => {
                out.push("pqexec");
                out.push("mysql_real_query");
            }
            ProbeSelection::Ssl => {
                out.push("evp_encrypt_update");
                out.push("evp_decrypt_update");
            }
            ProbeSelection::Dns => out.push("getaddrinfo"),
        }
    }
    out
}

#[cfg(test)]
mod graph_adapter_tests {
    use super::*;

    #[test]
    fn compact_allocator_avoids_old_modulo_and_entity_type_collisions() {
        let mut graph = RealGraph::default();
        let first = IngestEvent {
            pid: 7,
            vertex_id: 7,
            dst_vertex_id: 99,
            event_type: 2,
            ..Default::default()
        };
        let second = IngestEvent {
            pid: 65_543,
            vertex_id: 65_543,
            dst_vertex_id: 99,
            event_type: 3,
            net_dst_ip: u32::from(Ipv4Addr::new(203, 0, 113, 7)),
            net_dst_port: 443,
            ..Default::default()
        };
        graph.write_edge(&first);
        graph.write_edge(&second);
        graph.merge_deltas();

        let process_a = graph.vertex_index[&(NodeLabel::Process, 7)];
        let process_b = graph.vertex_index[&(NodeLabel::Process, 65_543)];
        let file = graph.vertex_index[&(NodeLabel::File, 99)];
        let endpoint = graph.vertex_index[&(
            NodeLabel::NetworkEndpoint,
            u32::from(Ipv4Addr::new(203, 0, 113, 7)),
        )];
        assert_ne!(process_a, process_b);
        assert_ne!(file, endpoint);
        assert_eq!(graph.inner.snapshot().num_edges, 2);
    }
}
