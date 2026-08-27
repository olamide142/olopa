import type { RecentRow } from "@/lib/ipc";

/**
 * A tiny filter language for the telemetry explorer.
 *
 * Supported: `field == "v"`, `!=`, `>`, `<`, `>=`, `<=`, `~` (contains),
 * combined with `and`. Anything that is not a comparison is treated as a
 * free-text term matched against the whole row. Parse failures degrade to
 * free text rather than throwing — an operator mid-keystroke should still see
 * results, not an error.
 */

type Op = "==" | "!=" | ">" | "<" | ">=" | "<=" | "~";

interface Clause {
  field: string;
  op: Op;
  value: string;
}

interface Parsed {
  clauses: Clause[];
  terms: string[];
}

const CLAUSE = /^([A-Za-z_][A-Za-z0-9_.]*)\s*(==|!=|>=|<=|>|<|~)\s*(.+)$/;

export function parseFilter(input: string): Parsed {
  const parsed: Parsed = { clauses: [], terms: [] };
  const parts = input
    .split(/\s+and\s+/i)
    .map((part) => part.trim())
    .filter(Boolean);

  for (const part of parts) {
    const match = CLAUSE.exec(part);
    if (!match) {
      parsed.terms.push(part.toLowerCase());
      continue;
    }
    const [, field, op, rawValue] = match;
    parsed.clauses.push({
      field,
      op: op as Op,
      value: rawValue.trim().replace(/^["']|["']$/g, ""),
    });
  }
  return parsed;
}

/** Flatten a row so `event.comm`, `comm` and `host_id` all resolve. */
function readField(row: RecentRow, field: string): unknown {
  const direct = (row as unknown as Record<string, unknown>)[field];
  if (direct !== undefined) return direct;

  const event = row.event ?? {};
  const stripped = field.startsWith("event.") ? field.slice(6) : field;
  if (stripped in event) return event[stripped];

  const attrs = event.attrs ?? {};
  if (stripped in attrs) return attrs[stripped];

  // `process.name`, `net.dst_ip` → last segment against the event map.
  const tail = stripped.split(".").pop() ?? stripped;
  if (tail in event) return event[tail];
  if (tail in attrs) return attrs[tail];
  // Common aliases between OIL field names and the ingest wire format.
  const aliases: Record<string, string> = {
    name: "comm",
    process: "comm",
    ip: "dst_ip",
    port: "dst_port",
    kind: "event_kind",
  };
  const alias = aliases[tail];
  if (alias) {
    if (alias in event) return event[alias];
    const aliased = (row as unknown as Record<string, unknown>)[alias];
    if (aliased !== undefined) return aliased;
  }
  return undefined;
}

function compare(actual: unknown, op: Op, expected: string): boolean {
  if (actual === undefined || actual === null) return false;

  if (op === "~") return String(actual).toLowerCase().includes(expected.toLowerCase());
  if (op === "==") return String(actual).toLowerCase() === expected.toLowerCase();
  if (op === "!=") return String(actual).toLowerCase() !== expected.toLowerCase();

  const left = typeof actual === "number" ? actual : Number(actual);
  const right = Number(expected);
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
  switch (op) {
    case ">":
      return left > right;
    case "<":
      return left < right;
    case ">=":
      return left >= right;
    case "<=":
      return left <= right;
  }
}

export function matchesFilter(row: RecentRow, parsed: Parsed): boolean {
  for (const clause of parsed.clauses) {
    if (!compare(readField(row, clause.field), clause.op, clause.value)) return false;
  }
  if (parsed.terms.length > 0) {
    const haystack = JSON.stringify(row).toLowerCase();
    if (!parsed.terms.every((term) => haystack.includes(term))) return false;
  }
  return true;
}

/** Field names offered as filter hints in the UI. */
export const FILTER_HINTS = [
  "event_kind",
  "host_id",
  "comm",
  "pid",
  "filename",
  "path",
  "dst_ip",
  "dst_port",
  "protocol",
  "db_engine",
];
