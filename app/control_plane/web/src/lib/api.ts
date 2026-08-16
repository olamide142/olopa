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

// -- Credentials ---------------------------------------------------------------

/**
 * The control plane accepts exactly one credential per request
 * (see control_server/auth.py::get_request_context) and rejects requests that
 * present more than one, so the console stores a single active credential.
 */
export type CredentialKind = "none" | "bearer" | "api-key" | "dev-token";

export interface Credential {
  kind: CredentialKind;
  /** Token value; ignored when kind is "none". */
  value: string;
  /** Optional explicit tenant. Must match the token's tenant or the API 403s. */
  tenantId: string;
}

const CREDENTIAL_KEY = "olopa_credential";

export const EMPTY_CREDENTIAL: Credential = { kind: "none", value: "", tenantId: "" };

export function loadCredential(): Credential {
  try {
    const raw = localStorage.getItem(CREDENTIAL_KEY);
    if (!raw) return EMPTY_CREDENTIAL;
    const parsed = JSON.parse(raw) as Partial<Credential>;
    const kind = parsed.kind;
    if (kind !== "bearer" && kind !== "api-key" && kind !== "dev-token") return EMPTY_CREDENTIAL;
    return {
      kind,
      value: typeof parsed.value === "string" ? parsed.value : "",
      tenantId: typeof parsed.tenantId === "string" ? parsed.tenantId : "",
    };
  } catch {
    return EMPTY_CREDENTIAL;
  }
}

let activeCredential: Credential = loadCredential();

export function getCredential(): Credential {
  return activeCredential;
}

/** Set the credential used by every subsequent request, persisting it locally. */
export function setCredential(credential: Credential): void {
  activeCredential = credential;
  try {
    if (credential.kind === "none" || !credential.value) {
      localStorage.removeItem(CREDENTIAL_KEY);
    } else {
      localStorage.setItem(CREDENTIAL_KEY, JSON.stringify(credential));
    }
  } catch {
    /* ignore */
  }
}

function credentialHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  const { kind, value, tenantId } = activeCredential;
  if (kind !== "none" && value) {
    if (kind === "bearer") headers.Authorization = `Bearer ${value}`;
    else if (kind === "api-key") headers["x-api-key"] = value;
    else headers["x-dev-token"] = value;
  }
  if (tenantId) headers["x-tenant-id"] = tenantId;
  return headers;
}

// -- Transport -----------------------------------------------------------------

export interface ApiResult<T> {
  data: T;
  latencyMs: number;
}

export interface DiagnosticItem {
  severity: string;
  code: string;
  message: string;
  line?: number | null;
  column?: number | null;
}

/** An error carrying the control plane's structured `detail` envelope. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly diagnostics: DiagnosticItem[];

  constructor(status: number, code: string, message: string, diagnostics: DiagnosticItem[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.diagnostics = diagnostics;
  }

  /** True when the request failed because of missing or rejected credentials. */
  get isAuthError(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

interface ErrorDetail {
  code?: unknown;
  message?: unknown;
  diagnostics?: unknown;
}

function parseDiagnostics(raw: unknown): DiagnosticItem[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const d = item as Record<string, unknown>;
    return [
      {
        severity: typeof d.severity === "string" ? d.severity : "error",
        code: typeof d.code === "string" ? d.code : "DIAGNOSTIC",
        message: typeof d.message === "string" ? d.message : String(d.message ?? ""),
        line: typeof d.line === "number" ? d.line : null,
        column: typeof d.column === "number" ? d.column : null,
      },
    ];
  });
}

/**
 * Turn a non-2xx response into an ApiError. FastAPI's `detail` is a string for
 * plain HTTPExceptions, an object for the control plane's coded errors, and a
 * list for request-validation failures — all three are flattened here.
 */
async function toApiError(path: string, resp: Response): Promise<ApiError> {
  let detail: unknown;
  try {
    const body = (await resp.json()) as { detail?: unknown };
    detail = body?.detail;
  } catch {
    detail = undefined;
  }

  if (typeof detail === "string" && detail.trim()) {
    return new ApiError(resp.status, `HTTP_${resp.status}`, detail);
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (item && typeof item === "object" ? String((item as { msg?: unknown }).msg ?? "") : ""))
      .filter(Boolean);
    return new ApiError(
      resp.status,
      "VALIDATION_ERROR",
      messages.join("; ") || `${path} -> HTTP ${resp.status}`,
    );
  }
  if (detail && typeof detail === "object") {
    const d = detail as ErrorDetail;
    return new ApiError(
      resp.status,
      typeof d.code === "string" ? d.code : `HTTP_${resp.status}`,
      typeof d.message === "string" ? d.message : `${path} -> HTTP ${resp.status}`,
      parseDiagnostics(d.diagnostics),
    );
  }
  return new ApiError(resp.status, `HTTP_${resp.status}`, `${path} -> HTTP ${resp.status}`);
}

interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<ApiResult<T>> {
  const { method = "GET", body, signal } = options;
  const headers: Record<string, string> = { ...credentialHeaders() };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const start = performance.now();
  const resp = await fetch(`${API_BASE}${path}`, {
    method,
    cache: "no-store",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!resp.ok) throw await toApiError(path, resp);
  const data = (await resp.json()) as T;
  return { data, latencyMs: Math.round(performance.now() - start) };
}

export function fetchJson<T>(path: string, signal?: AbortSignal): Promise<ApiResult<T>> {
  return request<T>(path, { signal });
}

export function postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<ApiResult<T>> {
  return request<T>(path, { method: "POST", body, signal });
}

/** Best-effort human message for anything thrown by this module. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
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

export type EventKind = "process_exec" | "file" | "net" | "db_query" | "agent_heartbeat";

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
  // db_query fields
  db_engine?: string;
  db_server?: string | null;
  database?: string | null;
  tables?: string[];
  statement_fingerprint?: string;
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

// -- Identity (mirror control_server/routers/auth.py) --------------------------

export interface WhoAmI {
  user_id: string;
  tenant_id: string;
  roles: string[];
  token_type: string;
  request_id: string;
  permissions: string[];
}

export const authApi = {
  whoami: (signal?: AbortSignal) => fetchJson<WhoAmI>("/api/v1/auth/whoami", signal),
};

// -- Control status (mirror control_server/main.py) ----------------------------

export interface ControlStatus {
  control_plane: { status: string };
  rust_ingest: { status: string; base_url: string };
  compiler: {
    oilc_manifest_path: string;
    manifest_exists: boolean;
    oilc_binary_path: string | null;
    binary_exists: boolean;
  };
}

export const controlApi = {
  status: (signal?: AbortSignal) => fetchJson<ControlStatus>("/api/v1/control/status", signal),
};

// -- Rules (mirror control_server/routers/rules.py) ----------------------------

export interface RuleVersion {
  id: string;
  rule_id: string;
  version: number;
  content: string;
  content_hash: string;
  author: string;
  changelog: string | null;
  compiled_ir: Record<string, unknown> | null;
  diagnostics: DiagnosticItem[];
  created_at: string | null;
}

export interface Rule {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  owner: string;
  created_at: string | null;
  updated_at: string | null;
  version_count: number;
  latest_version: RuleVersion | null;
}

export interface ValidateRuleResponse {
  valid: boolean;
  diagnostics: DiagnosticItem[];
  ast?: Record<string, unknown> | null;
  compiled_ir?: Record<string, unknown> | null;
}

export interface RuleTestFixture {
  event_type: string;
  pid: number;
  comm: string;
  filename?: string | null;
  net_dst_ip?: string | null;
  net_dst_port?: number | null;
  attrs: Record<string, string>;
}

export interface RuleTestMatch {
  fixture_index: number;
  event_type: string;
  matched_rule: string;
  risk_score: number;
}

export interface TestRuleResponse {
  matched: boolean;
  match_count: number;
  diagnostics: DiagnosticItem[];
  matches: RuleTestMatch[];
}

export const rulesApi = {
  list: (signal?: AbortSignal) => fetchJson<Rule[]>("/api/v1/rules", signal),
  get: (ruleId: string, signal?: AbortSignal) => fetchJson<Rule>(`/api/v1/rules/${ruleId}`, signal),
  getVersion: (ruleId: string, version: number, signal?: AbortSignal) =>
    fetchJson<RuleVersion>(`/api/v1/rules/${ruleId}/versions/${version}`, signal),
  create: (
    body: { name: string; description?: string | null; content: string; changelog?: string },
    signal?: AbortSignal,
  ) => postJson<Rule>("/api/v1/rules", body, signal),
  createVersion: (ruleId: string, body: { content: string; changelog?: string }, signal?: AbortSignal) =>
    postJson<RuleVersion>(`/api/v1/rules/${ruleId}/versions`, body, signal),
  validate: (content: string, signal?: AbortSignal) =>
    postJson<ValidateRuleResponse>("/api/v1/rules/validate", { content }, signal),
  test: (content: string, fixtures: RuleTestFixture[], signal?: AbortSignal) =>
    postJson<TestRuleResponse>("/api/v1/rules/test", { content, fixtures }, signal),
};

// -- Deployments (mirror control_server/routers/deployments.py) -----------------

/** Mirrors models/deployment.py::DeploymentStrategy. */
export type DeploymentStrategy = "direct" | "canary";

/** Mirrors models/deployment.py::DeploymentStatus. */
export const DEPLOYMENT_STATUSES = ["pending", "deploying", "active", "rolled_back", "failed"] as const;
export type DeploymentStatus = (typeof DEPLOYMENT_STATUSES)[number];

export interface Deployment {
  id: string;
  tenant_id: string;
  environment: string;
  rule_version_id: string;
  status: string;
  strategy: string;
  idempotency_key: string | null;
  created_by: string;
  message: string | null;
  details: Record<string, unknown>;
  created_at: string | null;
  updated_at: string | null;
}

export const deploymentsApi = {
  list: (filters: { environment?: string; status?: string } = {}, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    if (filters.environment) params.set("environment", filters.environment);
    if (filters.status) params.set("status", filters.status);
    const query = params.toString();
    return fetchJson<Deployment[]>(`/api/v1/deployments${query ? `?${query}` : ""}`, signal);
  },
  create: (
    body: {
      rule_version_id: string;
      environment: string;
      strategy: DeploymentStrategy;
      idempotency_key?: string;
    },
    signal?: AbortSignal,
  ) => postJson<Deployment>("/api/v1/deployments", body, signal),
  rollback: (deploymentId: string, signal?: AbortSignal) =>
    postJson<Deployment>(`/api/v1/deployments/${deploymentId}/rollback`, {}, signal),
};

// -- Compiler (mirror control_server/main.py::compile_oil) ---------------------

export const COMPILER_MODES = ["check", "ast", "mir", "runtime-ir", "cypher", "codegen"] as const;
export type CompilerMode = (typeof COMPILER_MODES)[number];

export interface CompileResponse {
  ok: boolean;
  exit_code: number;
  command: string[];
  stdout: string;
  stderr: string;
  stdout_json: Record<string, unknown> | null;
  runtime_ir: Record<string, unknown> | null;
}

export const compilerApi = {
  compile: (source: string, mode: CompilerMode, signal?: AbortSignal) =>
    postJson<CompileResponse>("/api/v1/control/compiler/compile", { source, mode }, signal),
};
