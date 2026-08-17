import type { RecentRow } from "@/lib/ipc";

/**
 * Hand-off slot for "create a detection from this event".
 *
 * Telemetry writes a generated rule here and navigates to Studio, which picks
 * it up once. sessionStorage keeps it across the route change and a reload,
 * without leaking a half-written rule into the next launch.
 */
const KEY = "olopa_command_draft";

export function setDraft(source: string): void {
  try {
    sessionStorage.setItem(KEY, source);
  } catch {
    /* private mode — the in-session navigation still works */
  }
}

/** Read and clear the pending draft. */
export function takeDraft(): string | null {
  try {
    const value = sessionStorage.getItem(KEY);
    if (value) sessionStorage.removeItem(KEY);
    return value;
  } catch {
    return null;
  }
}

function slug(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned.toLowerCase() || "event";
}

function quote(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`;
}

/**
 * Generate a starter OIL rule from a telemetry row.
 *
 * The output is intentionally a *starting point*: it pins the fields that
 * identify this specific event so the operator can widen it, and it always
 * compiles against the shipped schema.
 */
export function ruleFromEvent(row: RecentRow): string {
  const event = row.event ?? {};
  const text = (key: string) => (typeof event[key] === "string" ? (event[key] as string) : "");
  const number = (key: string) =>
    typeof event[key] === "number" ? (event[key] as number) : undefined;

  const comm = text("comm");
  const conditions: string[] = [];
  let source = "endpoint.process";
  let name = `${slug(comm || row.event_kind)}_activity`;

  switch (row.event_kind) {
    case "net": {
      source = "network.flow";
      name = `${slug(comm || "process")}_egress`;
      const dst = text("dst_ip");
      const port = number("dst_port");
      if (comm) conditions.push(`process.name == ${quote(comm)}`);
      if (dst) conditions.push(`network.dest.ip == ${quote(dst)}`);
      if (port) conditions.push(`network.dest.port == ${port}`);
      break;
    }
    case "file": {
      source = "endpoint.file";
      name = `${slug(comm || "process")}_file_access`;
      const path = text("path") || text("filename");
      if (comm) conditions.push(`process.name == ${quote(comm)}`);
      if (path) conditions.push(`file.path == ${quote(path)}`);
      break;
    }
    case "db_query": {
      source = "endpoint.process";
      name = `${slug(text("db_engine") || "db")}_query`;
      if (comm) conditions.push(`process.name == ${quote(comm)}`);
      break;
    }
    default: {
      const filename = text("filename");
      if (comm) conditions.push(`process.name == ${quote(comm)}`);
      if (filename) conditions.push(`process.binary.path == ${quote(filename)}`);
    }
  }

  if (conditions.length === 0) conditions.push(`process.name != ""`);

  return `// Drafted in Olopa Command from a ${row.event_kind} event on ${row.host_id}.
// Widen these conditions before deploying — they currently match one observation.
rule ${quote(name)} {
  from ${source}

  where
    ${conditions.join("\n    and ")}

  respond
    alert medium
}
`;
}
