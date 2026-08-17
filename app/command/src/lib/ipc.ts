/**
 * Typed bridge to the Rust backend.
 *
 * Every type here mirrors a `#[derive(Serialize)]` struct in `src-tauri/src`.
 * Nothing in the UI talks HTTP directly: remote reads go through `http_request`
 * so the operator's credential stays in Rust and neither server needs CORS.
 */
import { invoke } from "@tauri-apps/api/core";

// -- Settings ------------------------------------------------------------------

export type CredentialKind = "none" | "bearer" | "api-key" | "dev-token";

export interface Settings {
  agent_status_path: string;
  secure_connect_status_path: string;
  ingest_base_url: string;
  control_base_url: string;
  agent_service_name: string;
  credential_kind: CredentialKind;
  credential_value: string;
  tenant_id: string;
}

// -- Agent ---------------------------------------------------------------------

export interface AgentSnapshot {
  version: number;
  generated_at_unix_ms: number;
  pid: number;
  running: boolean;
  iface: string;
  probes: string[];
  backend: { reachable: boolean; rtt_ms: number | null };
  resources: {
    cpu_pct: number;
    cpu_budget_pct: number;
    mem_mb: number;
    mem_ceiling_mb: number;
    bw_mb_s: number;
    bw_limit_pct: number;
  };
  window_5s: { captured: number; transmitted: number; dropped_budget: number };
  firewall: { allow: number; deny: number; approve: number };
}

export interface SecureConnectHealth {
  enabled: boolean;
  state: string;
  device_id: string | null;
  session_id: string | null;
  interface: string | null;
  profile_version: number;
  last_heartbeat_unix: number;
  last_handshake_unix: number;
  bytes_tx: number;
  bytes_rx: number;
  reconnect_count: number;
  policy_apply_ms: number;
  revoke_apply_ms: number;
  kill_switch_apply_ms: number;
  posture_updated_unix: number;
  last_error: string | null;
}

export interface SnapshotReport<T> {
  path: string;
  present: boolean;
  stale: boolean;
  age_ms: number | null;
  snapshot: T | null;
  error: string | null;
}

export interface CommandOutcome {
  command: string;
  ok: boolean;
  exit_code: number | null;
  stdout: string;
  stderr: string;
}

export interface HostFacts {
  hostname: string;
  kernel: string;
  os: string;
  uptime_secs: number;
}

export type AgentAction = "start" | "stop" | "restart" | "status";

// -- eBPF ----------------------------------------------------------------------

export interface BpfProgram {
  id: number;
  name: string;
  kind: string;
  tag: string;
  run_time_ns: number;
  run_count: number;
  map_ids: number[];
  attributed_to_agent: boolean;
}

export interface BpfMap {
  id: number;
  name: string;
  kind: string;
  max_entries: number;
  bytes_key: number;
  bytes_value: number;
  bytes_memlock: number;
}

export interface BpfInventory {
  available: boolean;
  note: string | null;
  programs: BpfProgram[];
  maps: BpfMap[];
  agent_probes: string[];
}

// -- OIL -----------------------------------------------------------------------

export interface OilDiagnostic {
  stage: string;
  severity: "error" | "warning";
  message: string;
  line: number | null;
  column: number | null;
}

export type PlanEngine =
  | "kernel"
  | "hot-path"
  | "warm-state"
  | "stream"
  | "scoring"
  | "enforcement"
  | "unsupported";

export interface PlanStep {
  label: string;
  detail: string;
  engine: PlanEngine;
}

export interface RulePlan {
  id: string;
  name: string;
  class: string;
  sources: string[];
  window: string | null;
  score_base: number;
  steps: PlanStep[];
  stateful_calls: string[];
  unsupported: string[];
  actions: string[];
}

export interface CompileReport {
  ok: boolean;
  diagnostics: OilDiagnostic[];
  token_count: number;
  ast: string | null;
  mir: string | null;
  runtime_ir: unknown | null;
  plans: RulePlan[];
}

// -- Simulator -----------------------------------------------------------------

export type EventRow = Record<string, unknown>;

export interface SimMatch {
  event_index: number;
  rule_id: string;
  rule_name: string;
  score: number;
  actions: string[];
  matched_on: string[];
}

export interface RuleOutcome {
  id: string;
  name: string;
  class: string;
  evaluated: number;
  matched: number;
  skipped_reason: string | null;
}

export interface SimulationReport {
  ok: boolean;
  diagnostics: OilDiagnostic[];
  events_processed: number;
  evaluations: number;
  matches: SimMatch[];
  rules: RuleOutcome[];
  elapsed_ms: number;
  ns_per_evaluation: number;
}

// -- Remote --------------------------------------------------------------------

export type RemoteTarget = "ingest" | "control";

export interface HttpReply<T = unknown> {
  ok: boolean;
  status: number;
  latency_ms: number;
  body: T | null;
  error: string | null;
}

// -- Diagnostics ---------------------------------------------------------------

export interface LogLine {
  timestamp: string;
  level: string;
  message: string;
}

export interface LogReply {
  source: string;
  available: boolean;
  note: string | null;
  lines: LogLine[];
}

export interface BundleReport {
  path: string;
  files: string[];
  warnings: string[];
}

// -- Commands ------------------------------------------------------------------

export const ipc = {
  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (next: Settings) => invoke<Settings>("set_settings", { next }),
  settingsLocation: () => invoke<string>("settings_location"),

  agentStatus: () => invoke<SnapshotReport<AgentSnapshot>>("agent_status"),
  secureConnectStatus: () => invoke<SnapshotReport<SecureConnectHealth>>("secure_connect_status"),
  hostFacts: () => invoke<HostFacts>("host_facts"),
  agentControl: (action: AgentAction) => invoke<CommandOutcome>("agent_control", { action }),
  agentCliStatus: () => invoke<CommandOutcome>("agent_cli_status"),

  ebpfInventory: () => invoke<BpfInventory>("ebpf_inventory"),

  oilCompile: (source: string) => invoke<CompileReport>("oil_compile", { source }),
  oilSimulate: (source: string, events: EventRow[]) =>
    invoke<SimulationReport>("oil_simulate", { request: { source, events } }),

  http: <T = unknown>(target: RemoteTarget, method: "GET" | "POST", path: string, body?: unknown) =>
    invoke<HttpReply<T>>("http_request", { target, method, path, body: body ?? null }),

  agentLogs: (lines: number) => invoke<LogReply>("agent_logs", { lines }),
  exportDiagnostics: () => invoke<BundleReport>("export_diagnostics"),
};

// -- Ingest wire types (mirror app/ingest_server/src/telemetry.rs) --------------

export interface IngestStats {
  queued: number;
  max_queue: number;
  accepted_total: number;
  rejected_total: number;
  flushed_total: number;
  failed_flush_total: number;
  last_flush_at_unix_ms?: number | null;
}

export interface IngestSummary {
  total_rows: number;
  by_kind: Record<string, number>;
  by_tenant: Record<string, number>;
  by_host: Record<string, number>;
}

export interface RecentRow {
  tenant_id: string;
  host_id: string;
  batch_id: string | null;
  event_kind: string;
  ingested_at_unix_ms: number;
  event: Record<string, unknown> & { attrs?: Record<string, string> };
}

export interface RecentResponse {
  total_available: number;
  returned: number;
  rows: RecentRow[];
}
