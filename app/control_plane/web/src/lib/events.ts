import type { RecentRow, RawEvent } from "./api";
import { formatClock } from "./utils";

export type Severity = "crit" | "high" | "med" | "low";

export interface DisplayEvent {
  ts: string;
  host: string;
  desc: string;
  sev: Severity;
  engine: string;
  kind: string;
  rule: string;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  crit: "CRIT",
  high: "HIGH",
  med: "MED",
  low: "LOW",
};

function ruleName(ev: RawEvent): string {
  const attrs = ev.attrs ?? {};
  return attrs.rule_name || attrs.rule_id || "";
}

function riskScore(ev: RawEvent): number {
  const v = parseFloat(ev.attrs?.risk_score ?? "0");
  return Number.isFinite(v) ? v : 0;
}

function engineFor(ev: RawEvent): string {
  return ev.attrs?.wire === "alert_binary" ? "RuntimeIR" : "eBPF";
}

/** Map a raw ingest row to a display row with derived severity + description. */
export function toDisplayEvent(row: RecentRow): DisplayEvent {
  const ev = row.event ?? {};
  const ts = formatClock(row.ingested_at_unix_ms);
  const host = row.host_id || "-";
  const rule = ruleName(ev);

  if (rule) {
    const risk = riskScore(ev);
    return {
      ts,
      host,
      desc: `rule ${rule} matched (pid=${ev.pid ?? "n/a"})`,
      sev: risk >= 0.8 ? "crit" : risk >= 0.4 ? "high" : "med",
      engine: "RuntimeIR",
      kind: "rule",
      rule,
    };
  }

  if (row.event_kind === "net") {
    const dst = ev.dst_ip ? `${ev.dst_ip}${ev.dst_port ? ":" + ev.dst_port : ""}` : "unknown-dst";
    return {
      ts,
      host,
      desc: `${ev.comm || "proc"} ${ev.direction || "net"} ${dst}`,
      sev: "med",
      engine: engineFor(ev),
      kind: "net",
      rule: "",
    };
  }

  if (row.event_kind === "file") {
    const path = ev.path || "";
    const high = /shadow|authorized_keys|id_rsa/i.test(path);
    return {
      ts,
      host,
      desc: `${ev.comm || "proc"} ${ev.operation || "file_op"} ${path}`.trim(),
      sev: high ? "high" : "low",
      engine: engineFor(ev),
      kind: "file",
      rule: "",
    };
  }

  if (row.event_kind === "db_query") {
    const target = [ev.db_engine, ev.database].filter(Boolean).join("/") || "db";
    const tables = Array.isArray(ev.tables) && ev.tables.length ? ` on ${ev.tables.join(", ")}` : "";
    // DDL and admin statements are the ones worth surfacing by default.
    const op = ev.operation || "query";
    return {
      ts,
      host,
      desc: `${ev.comm || "proc"} ${op} ${target}${tables}`.trim(),
      sev: op === "ddl" || op === "admin" ? "high" : "med",
      engine: engineFor(ev),
      kind: "db_query",
      rule: "",
    };
  }

  if (row.event_kind === "process_exec") {
    return {
      ts,
      host,
      desc: `${ev.comm || "proc"} exec ${ev.filename || ""}`.trim(),
      sev: "low",
      engine: engineFor(ev),
      kind: "process_exec",
      rule: "",
    };
  }

  return {
    ts,
    host,
    desc: `heartbeat read=${ev.events_read_total || 0} dropped=${ev.events_dropped_total || 0}`,
    sev: "low",
    engine: "Agent",
    kind: "heartbeat",
    rule: "",
  };
}

export function isAlert(row: RecentRow): boolean {
  return !!ruleName(row.event ?? {});
}
