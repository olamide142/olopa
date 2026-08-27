import { useMemo, useState } from "react";
import { Download, Pause, Play, ScrollText, Search } from "lucide-react";
import {
  Button,
  Chip,
  Empty,
  Input,
  Notice,
  Panel,
  PageHead,
  Select,
  Tabs,
  type Tone,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc, type BundleReport } from "@/lib/ipc";
import { cn } from "@/lib/format";

const LEVEL_TONE: Record<string, Tone> = {
  error: "danger",
  warn: "warn",
  info: "info",
  debug: "muted",
};

const LEVEL_TEXT: Record<string, string> = {
  error: "text-danger",
  warn: "text-warn",
  info: "text-fg",
  debug: "text-fg-faint",
};

type Level = "all" | "error" | "warn" | "info" | "debug";

export function LogsPanel() {
  const [lines, setLines] = useState(200);
  const [level, setLevel] = useState<Level>("all");
  const [query, setQuery] = useState("");
  const [following, setFollowing] = useState(true);
  const [bundle, setBundle] = useState<BundleReport | null>(null);
  const [bundleError, setBundleError] = useState<string | null>(null);

  const logs = usePolling(() => ipc.agentLogs(lines), following ? 4000 : 0, following);
  const data = logs.data;

  const filtered = useMemo(() => {
    const rows = data?.lines ?? [];
    const needle = query.toLowerCase().trim();
    return rows.filter((row) => {
      if (level !== "all" && row.level !== level) return false;
      if (needle && !row.message.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data, level, query]);

  const counts = useMemo(() => {
    const rows = data?.lines ?? [];
    return {
      error: rows.filter((r) => r.level === "error").length,
      warn: rows.filter((r) => r.level === "warn").length,
    };
  }, [data]);

  const exportBundle = async () => {
    setBundleError(null);
    try {
      setBundle(await ipc.exportDiagnostics());
    } catch (err) {
      setBundleError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="space-y-3">
      <PageHead
        title="Logs & Diagnostics"
        subtitle={data?.source ?? "reading the agent journal"}
        actions={
          <div className="flex items-center gap-2">
            <Select value={String(lines)} onChange={(event) => setLines(Number(event.target.value))}>
              <option value="100">100 lines</option>
              <option value="200">200 lines</option>
              <option value="500">500 lines</option>
              <option value="1000">1000 lines</option>
            </Select>
            <Button
              variant={following ? "default" : "primary"}
              onClick={() => setFollowing(!following)}
            >
              {following ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
              {following ? "Following" : "Paused"}
            </Button>
            <Button onClick={() => void exportBundle()}>
              <Download className="h-3 w-3" />
              Export bundle
            </Button>
          </div>
        }
      />

      {data?.note && <Notice tone={data.available ? "muted" : "danger"}>{data.note}</Notice>}
      {bundleError && <Notice tone="danger">{bundleError}</Notice>}
      {bundle && (
        <Notice tone="ok">
          Bundle written to <span className="selectable font-mono">{bundle.path}</span> (
          {bundle.files.length} files, credential redacted).
          {bundle.warnings.length > 0 && ` Warnings: ${bundle.warnings.join("; ")}`}
        </Notice>
      )}

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-2.5 py-2">
          <Search className="h-3.5 w-3.5 shrink-0 text-fg-faint" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="filter messages"
            className="max-w-sm font-mono"
          />
          <Tabs
            items={[
              { value: "all", label: "All" },
              { value: "error", label: "Error", hint: counts.error || "" },
              { value: "warn", label: "Warn", hint: counts.warn || "" },
              { value: "info", label: "Info" },
              { value: "debug", label: "Debug" },
            ]}
            value={level}
            onChange={setLevel}
          />
          <span className="ml-auto font-mono text-[10px] text-fg-faint">
            {filtered.length} / {data?.lines.length ?? 0} lines
          </span>
        </div>

        {filtered.length === 0 ? (
          <Empty
            icon={ScrollText}
            title={data?.available ? "No matching lines" : "No journal access"}
            detail={
              data?.available
                ? "Nothing in the current buffer matches. Widen the filter or increase the line count."
                : "Command reads the agent's journal with journalctl. Check the unit name in Settings."
            }
          />
        ) : (
          <div className="max-h-[32rem] overflow-auto">
            {filtered.map((line, index) => (
              <div
                key={index}
                className="flex items-start gap-2 border-b border-border/30 px-3 py-0.5 last:border-0"
              >
                <span className="shrink-0 font-mono text-[10px] tabular-nums text-fg-faint">
                  {line.timestamp}
                </span>
                <Chip tone={LEVEL_TONE[line.level] ?? "muted"} className="shrink-0">
                  {line.level}
                </Chip>
                <span
                  className={cn(
                    "selectable whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed",
                    LEVEL_TEXT[line.level] ?? "text-fg",
                  )}
                >
                  {line.message}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
