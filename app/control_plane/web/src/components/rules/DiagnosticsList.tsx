import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";
import type { DiagnosticItem } from "@/lib/api";
import { cn } from "@/lib/utils";

const ICONS = {
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
} as const;

const TONES = {
  error: "text-danger",
  warning: "text-warning",
  info: "text-muted-foreground",
} as const;

type Severity = keyof typeof ICONS;

function normalize(severity: string): Severity {
  const s = severity.toLowerCase();
  return s === "error" || s === "warning" ? s : "info";
}

interface DiagnosticsListProps {
  diagnostics: DiagnosticItem[];
  /** Message shown when the list is empty; omit to render nothing. */
  emptyLabel?: string;
  className?: string;
}

/** Compiler diagnostics from validate, test, or a raw compile run. */
export function DiagnosticsList({ diagnostics, emptyLabel, className }: DiagnosticsListProps) {
  if (diagnostics.length === 0) {
    if (!emptyLabel) return null;
    return (
      <div className={cn("flex items-center gap-2 text-xs text-success", className)}>
        <CheckCircle2 className="h-3.5 w-3.5" />
        {emptyLabel}
      </div>
    );
  }

  return (
    <ul className={cn("space-y-1.5", className)}>
      {diagnostics.map((d, i) => {
        const severity = normalize(d.severity);
        const Icon = ICONS[severity];
        return (
          <li
            key={`${d.code}-${i}`}
            className="flex items-start gap-2 rounded-md border border-border bg-muted/30 px-2.5 py-2"
          >
            <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", TONES[severity])} />
            <div className="min-w-0 flex-1">
              <p className="break-words text-xs">{d.message}</p>
              <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                {d.code}
                {d.line ? ` · line ${d.line}${d.column ? `:${d.column}` : ""}` : ""}
              </p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
