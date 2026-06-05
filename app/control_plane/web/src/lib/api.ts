/**
 * Typed client for the control-plane API.
 *
 * The console is served same-origin (console.olopa.io), so relative paths hit
 * the FastAPI control plane, which proxies the Rust ingest endpoints.
 * An override base can be supplied via ?api=... for local development.
 */

function resolveApiBase(): string {
  const params = new URLSearchParams(window.location.search);
  const fromQuery = params.get("api")?.replace(/\/+$/, "");
  if (fromQuery) {
    try {
      localStorage.setItem("olopa_api_base", fromQuery);
    } catch {
      /* ignore */
    }
    return fromQuery;
  }
  try {
    const stored = localStorage.getItem("olopa_api_base")?.replace(/\/+$/, "");
    if (stored) return stored;
  } catch {
    /* ignore */
  }
  return window.location.origin;
}

export const API_BASE = resolveApiBase();

export interface ApiResult<T> {
  data: T;
  latencyMs: number;
}

export async function fetchJson<T>(path: string, signal?: AbortSignal): Promise<ApiResult<T>> {
  const start = performance.now();
  const resp = await fetch(`${API_BASE}${path}`, { cache: "no-store", signal });
  if (!resp.ok) throw new Error(`${path} -> HTTP ${resp.status}`);
  const data = (await resp.json()) as T;
  return { data, latencyMs: Math.round(performance.now() - start) };
}

// -- Wire types (mirror app/ingest_server/src/telemetry.rs) -------------------

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

export type EventKind = "process_exec" | "file" | "net" | "agent_heartbeat";

export interface RecentRow {
  tenant_id: string;
  host_id: string;
  batch_id: string | null;
  event_kind: EventKind | string;
  ingested_at_unix_ms: number;
  event: RawEvent;
}

export interface RawEvent {
  pid?: number;
  comm?: string;
  filename?: string;
  operation?: string;
  path?: string;
  direction?: string;
  protocol?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  // heartbeat fields
  agent_version?: string;
  kernel_version?: string;
  events_read_total?: number;
  events_dropped_total?: number;
  queue_depth?: number;
  attrs?: Record<string, string>;
}

export interface RecentResponse {
  total_available: number;
  returned: number;
  rows: RecentRow[];
}

export const ingestApi = {
  stats: (signal?: AbortSignal) => fetchJson<IngestStats>("/api/v1/ingest/stats", signal),
  summary: (signal?: AbortSignal) => fetchJson<IngestSummary>("/api/v1/ingest/summary", signal),
  recent: (limit: number, signal?: AbortSignal) =>
    fetchJson<RecentResponse>(`/api/v1/ingest/recent?limit=${limit}`, signal),
};
