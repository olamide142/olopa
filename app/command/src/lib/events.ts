import type { EventRow, RecentRow } from "@/lib/ipc";

/**
 * Convert an ingest row into a simulator event.
 *
 * The simulator resolves an IR field path by its last segment, so a row must
 * carry keys that match those segments: `process.name` looks for `name`,
 * `network.dest.ip` looks for `ip`. The wire format uses `comm` and `dst_ip`,
 * so both the original and the segment-shaped alias are emitted.
 */
export function toEventRow(row: RecentRow): EventRow {
  const event = row.event ?? {};
  const out: EventRow = { ...event };

  out.event_kind = row.event_kind;
  out.host_id = row.host_id;

  const alias = (from: string, to: string) => {
    if (event[from] !== undefined && out[to] === undefined) out[to] = event[from];
  };

  alias("comm", "name");
  alias("filename", "path");
  alias("dst_ip", "ip");
  alias("dst_port", "port");
  alias("db_engine", "engine");

  // Direction is implicit for egress rows the net probe reports.
  if (row.event_kind === "net" && out.direction === undefined) {
    out.direction = "outbound";
  }
  // Flatten attrs so `attrs.verdict` is reachable as `verdict`.
  const attrs = event.attrs;
  if (attrs && typeof attrs === "object") {
    for (const [key, value] of Object.entries(attrs)) {
      if (out[key] === undefined) out[key] = value;
    }
  }
  return out;
}

/** A small, readable synthetic corpus for exercising a rule with no backend. */
export const SYNTHETIC_EVENTS: EventRow[] = [
  { event_kind: "process_exec", name: "bash", comm: "bash", pid: 8121, path: "/bin/bash" },
  { event_kind: "process_exec", name: "nginx", comm: "nginx", pid: 991, path: "/usr/sbin/nginx" },
  { event_kind: "process_exec", name: "sh", comm: "sh", pid: 8122, path: "/bin/sh" },
  {
    event_kind: "net",
    name: "bash",
    comm: "bash",
    pid: 8121,
    ip: "185.199.108.153",
    dst_ip: "185.199.108.153",
    port: 4444,
    dst_port: 4444,
    direction: "outbound",
    protocol: "tcp",
  },
  {
    event_kind: "net",
    name: "python",
    comm: "python",
    pid: 4410,
    ip: "140.82.121.4",
    dst_ip: "140.82.121.4",
    port: 443,
    dst_port: 443,
    direction: "outbound",
    protocol: "tcp",
  },
  {
    event_kind: "file",
    name: "bash",
    comm: "bash",
    pid: 8121,
    path: "/etc/shadow",
    operation: "read",
  },
];
