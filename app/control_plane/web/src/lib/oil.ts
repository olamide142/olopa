import type { DiagnosticItem } from "@/lib/api";

/**
 * Starter rule shown in an empty editor. Kept close to the shipped examples in
 * `oilc/src/rules/` so it compiles against the current schema and prelude.
 */
export const STARTER_RULE = `rule "outbound_from_shell" {
  from endpoint.process, network.flow

  correlate
    process.spawn as p
    with network.connect as n on n.process_id == p.id

  where
    n.direction == "outbound"
    and p.name in ["bash", "sh", "zsh"]

  respond
    alert high
    snapshot p, n
}
`;

/** Rule name as written in `rule "<name>" { ... }`, used to prefill the save form. */
export function extractRuleName(source: string): string | null {
  const quoted = source.match(/\brule\s+"([^"]+)"/);
  if (quoted) return quoted[1];
  const bare = source.match(/\brule\s+([A-Za-z_][A-Za-z0-9_]*)/);
  return bare ? bare[1] : null;
}

interface CompilerSpan {
  start?: number;
  end?: number;
}

interface RawCompilerDiagnostic {
  stage?: string;
  message?: string;
  is_error?: boolean;
  span?: CompilerSpan | null;
}

interface CompilerUnit {
  diagnostics?: RawCompilerDiagnostic[];
}

export interface CompilerReport {
  summary?: { succeeded?: number; failed?: number; mode?: string };
  project_diagnostics?: RawCompilerDiagnostic[];
  units?: CompilerUnit[];
}

/** Translate a byte offset into 1-based line/column against the source text. */
function offsetToPosition(source: string, start: number | undefined): { line: number | null; column: number | null } {
  if (typeof start !== "number" || start < 0 || start > source.length) return { line: null, column: null };
  const line = source.slice(0, start).split("\n").length;
  const lineStart = source.lastIndexOf("\n", start - 1);
  return { line, column: start - lineStart };
}

/**
 * Flatten an oilc `--diagnostics-format json` report into the same shape the
 * control plane returns from /api/v1/rules/validate, so both paths render
 * through one component.
 */
export function extractCompilerDiagnostics(report: CompilerReport | null, source: string): DiagnosticItem[] {
  if (!report) return [];
  const raw: RawCompilerDiagnostic[] = [
    ...(report.project_diagnostics ?? []),
    ...(report.units ?? []).flatMap((unit) => unit.diagnostics ?? []),
  ];
  return raw.map((item) => {
    const { line, column } = offsetToPosition(source, item.span?.start);
    return {
      severity: item.is_error ? "error" : "warning",
      code: `OILC_${String(item.stage ?? "compiler").toUpperCase()}`,
      message: item.message ?? "Compiler diagnostic",
      line,
      column,
    };
  });
}

/** Count diagnostics whose severity blocks persistence or deployment. */
export function countErrors(diagnostics: DiagnosticItem[]): number {
  return diagnostics.filter((d) => d.severity.toLowerCase() === "error").length;
}
