import { useMemo, useState } from "react";
import { Download } from "lucide-react";
import type { RecentRow } from "@/lib/api";
import { toDisplayEvent, SEVERITY_LABEL, type DisplayEvent, type Severity } from "@/lib/events";
import { Input, Select } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const SEV_TONE: Record<Severity, "danger" | "warning" | "default" | "muted"> = {
  crit: "danger",
  high: "warning",
  med: "default",
  low: "muted",
};

const KIND_OPTIONS = [
  { value: "all", label: "Kind: all" },
  { value: "rule", label: "Kind: rule" },
  { value: "process_exec", label: "Kind: process" },
  { value: "file", label: "Kind: file" },
  { value: "net", label: "Kind: net" },
  { value: "heartbeat", label: "Kind: heartbeat" },
];

function csvEscape(v: string): string {
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

function exportCsv(rows: DisplayEvent[]) {
  if (!rows.length) return;
  const header = ["timestamp", "host", "description", "severity", "engine", "kind", "rule"];
  const lines = [header.join(",")];
  rows.forEach((e) =>
    lines.push(
      [e.ts, e.host, e.desc, SEVERITY_LABEL[e.sev], e.engine, e.kind, e.rule]
        .map((c) => csvEscape(String(c ?? "")))
        .join(","),
    ),
  );
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = `olopa-events-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(href), 0);
}

export function EventsTable({ rows }: { rows: RecentRow[] }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [kind, setKind] = useState("all");
  const [alertsOnly, setAlertsOnly] = useState(false);

  const display = useMemo(() => rows.map(toDisplayEvent), [rows]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return display.filter((e) => {
      if (alertsOnly && !e.rule) return false;
      if (severity !== "all" && e.sev !== severity) return false;
      if (kind !== "all" && e.kind !== kind) return false;
      if (!q) return true;
      return `${e.ts} ${e.host} ${e.desc} ${e.engine} ${e.kind} ${e.rule}`.toLowerCase().includes(q);
    });
  }, [display, search, severity, kind, alertsOnly]);

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
        <Input
          className="h-8 w-64"
          placeholder="Search host, description, engine, rule"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Select className="h-8" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">Severity: all</option>
          <option value="crit">Crit</option>
          <option value="high">High</option>
          <option value="med">Med</option>
          <option value="low">Low</option>
        </Select>
        <Select className="h-8" value={kind} onChange={(e) => setKind(e.target.value)}>
          {KIND_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={alertsOnly}
            onChange={(e) => setAlertsOnly(e.target.checked)}
            className="accent-[var(--primary)]"
          />
          alerts only
        </label>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            setSearch("");
            setSeverity("all");
            setKind("all");
            setAlertsOnly(false);
          }}
        >
          Clear
        </Button>
        <span className="ml-auto text-xs text-muted-foreground tabular-nums">
          {filtered.length} / {display.length} shown
        </span>
        <Button size="sm" variant="outline" onClick={() => exportCsv(filtered)}>
          <Download className="h-3.5 w-3.5" />
          CSV
        </Button>
      </div>

      <div className="grid grid-cols-[80px_140px_1fr_70px_90px] gap-2 border-b border-border px-4 py-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        <span>Time</span>
        <span>Host</span>
        <span>Description</span>
        <span>Sev</span>
        <span>Engine</span>
      </div>

      <div className="max-h-[420px] overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-muted-foreground">
            {display.length === 0 ? "No execution rows yet" : "No rows match current filters"}
          </div>
        ) : (
          filtered.map((e, i) => (
            <div
              key={i}
              className={cn(
                "grid grid-cols-[80px_140px_1fr_70px_90px] items-center gap-2 px-4 py-1.5 text-xs",
                "border-b border-border/50 hover:bg-accent/50",
              )}
            >
              <span className="font-mono tabular-nums text-muted-foreground">{e.ts}</span>
              <span className="truncate font-mono">{e.host}</span>
              <span className="truncate">{e.desc}</span>
              <span>
                <Badge tone={SEV_TONE[e.sev]}>{SEVERITY_LABEL[e.sev]}</Badge>
              </span>
              <span className="truncate text-muted-foreground">{e.engine}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
