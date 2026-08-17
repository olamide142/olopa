import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Filter, Pause, Play, Radio, Wand2 } from "lucide-react";
import {
  Button,
  Chip,
  Empty,
  Input,
  Json,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Select,
  Tabs,
  Td,
  Th,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc, type RecentResponse, type RecentRow } from "@/lib/ipc";
import { FILTER_HINTS, matchesFilter, parseFilter } from "@/lib/filter";
import { ruleFromEvent, setDraft } from "@/lib/draft";
import { num, since } from "@/lib/format";

const KINDS = ["all", "process_exec", "file", "net", "db_query", "agent_heartbeat"] as const;
type Kind = (typeof KINDS)[number];

const KIND_TONE: Record<string, "info" | "violet" | "warn" | "ok" | "muted"> = {
  process_exec: "info",
  file: "violet",
  net: "warn",
  db_query: "ok",
  agent_heartbeat: "muted",
};

function summarize(row: RecentRow): string {
  const event = row.event ?? {};
  const text = (key: string) => (typeof event[key] === "string" ? (event[key] as string) : "");
  const number = (key: string) =>
    typeof event[key] === "number" ? (event[key] as number) : undefined;

  switch (row.event_kind) {
    case "process_exec":
      return `${text("comm")} exec ${text("filename")}`;
    case "file":
      return `${text("comm")} ${text("operation") || "access"} ${text("path") || text("filename")}`;
    case "net": {
      const port = number("dst_port");
      return `${text("comm")} → ${text("dst_ip")}${port ? `:${port}` : ""} ${text("protocol")}`;
    }
    case "db_query": {
      const tables = Array.isArray(event.tables) ? (event.tables as string[]).join(", ") : "";
      return `${text("db_engine")} ${text("database")} ${tables}`.trim();
    }
    case "agent_heartbeat":
      return `agent ${text("agent_version")} kernel ${text("kernel_version")}`;
    default:
      return text("comm");
  }
}

export function TelemetryPanel() {
  const navigate = useNavigate();
  const [paused, setPaused] = useState(false);
  const [limit, setLimit] = useState(200);
  const [kind, setKind] = useState<Kind>("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<RecentRow | null>(null);
  const [detailTab, setDetailTab] = useState<"event" | "raw">("event");

  const feed = usePolling(
    () => ipc.http<RecentResponse>("ingest", "GET", `/api/v1/ingest/recent?limit=${limit}`),
    paused ? 0 : 2000,
    !paused,
  );

  const rows = useMemo(() => feed.data?.body?.rows ?? [], [feed.data]);
  const parsed = useMemo(() => parseFilter(query), [query]);
  const filtered = useMemo(
    () =>
      rows.filter(
        (row) => (kind === "all" || row.event_kind === kind) && matchesFilter(row, parsed),
      ),
    [rows, kind, parsed],
  );

  const draftRule = (row: RecentRow) => {
    setDraft(ruleFromEvent(row));
    navigate("/studio");
  };

  const transportError = feed.data?.error ?? feed.error;

  return (
    <div className="space-y-3">
      <PageHead
        title="Telemetry"
        subtitle="Events the agent shipped to ingest — filter them, then turn one into a detection."
        actions={
          <div className="flex items-center gap-2">
            <Select value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value="100">100 rows</option>
              <option value="200">200 rows</option>
              <option value="500">500 rows</option>
              <option value="1000">1000 rows</option>
            </Select>
            <Button variant={paused ? "primary" : "default"} onClick={() => setPaused(!paused)}>
              {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
              {paused ? "Resume" : "Pause"}
            </Button>
          </div>
        }
      />

      {transportError && <Notice tone="danger">{transportError}</Notice>}

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-2.5 py-2">
          <Filter className="h-3.5 w-3.5 shrink-0 text-fg-faint" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={`comm == "python" and dst_port == 443`}
            className="max-w-lg font-mono"
          />
          <Tabs
            items={KINDS.map((k) => ({ value: k, label: k === "all" ? "all" : k.split("_")[0] }))}
            value={kind}
            onChange={setKind}
          />
          <span className="ml-auto font-mono text-[10px] text-fg-faint">
            {num(filtered.length)} / {num(rows.length)} rows
            {feed.data?.body ? ` · ${num(feed.data.body.total_available)} available` : ""}
          </span>
        </div>

        {query === "" && (
          <div className="flex flex-wrap items-center gap-1 border-b border-border px-2.5 py-1.5">
            <span className="text-[10px] text-fg-faint">fields:</span>
            {FILTER_HINTS.map((hint) => (
              <button
                key={hint}
                type="button"
                onClick={() => setQuery(`${hint} == `)}
                className="rounded border border-border px-1 font-mono text-[10px] text-fg-muted hover:border-border-strong hover:text-fg"
              >
                {hint}
              </button>
            ))}
          </div>
        )}

        {filtered.length === 0 ? (
          <Empty
            icon={Radio}
            title={rows.length === 0 ? "No telemetry" : "No rows match this filter"}
            detail={
              rows.length === 0
                ? "Nothing has been ingested yet. Check the ingest endpoint in Settings, or confirm the agent is shipping."
                : "Clear the filter or widen the comparison."
            }
          />
        ) : (
          <div className="max-h-[26rem] overflow-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th className="w-20">Time</Th>
                  <Th className="w-28">Kind</Th>
                  <Th className="w-16">PID</Th>
                  <Th>Summary</Th>
                  <Th className="w-32">Host</Th>
                  <Th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((row, index) => {
                  const alert = row.event?.attrs?.wire === "alert_binary";
                  return (
                    <tr
                      key={`${row.batch_id}-${index}`}
                      onClick={() => setSelected(row)}
                      className={
                        "cursor-pointer border-b border-border/40 hover:bg-surface-2 " +
                        (selected === row ? "bg-surface-2" : "")
                      }
                    >
                      <Td className="font-mono text-fg-faint">
                        {new Date(row.ingested_at_unix_ms).toTimeString().slice(0, 8)}
                      </Td>
                      <Td>
                        <Chip tone={alert ? "danger" : KIND_TONE[row.event_kind] ?? "muted"}>
                          {alert ? "alert" : row.event_kind}
                        </Chip>
                      </Td>
                      <Td className="font-mono text-fg-muted">
                        {typeof row.event?.pid === "number" ? row.event.pid : "—"}
                      </Td>
                      <Td className="max-w-0 truncate font-mono text-fg">{summarize(row)}</Td>
                      <Td className="font-mono text-fg-faint">{row.host_id.slice(0, 16)}</Td>
                      <Td>
                        <button
                          type="button"
                          title="Create detection from this event"
                          onClick={(event) => {
                            event.stopPropagation();
                            draftRule(row);
                          }}
                          className="text-fg-faint transition-colors hover:text-primary"
                        >
                          <Wand2 className="h-3 w-3" />
                        </button>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected && (
        <Panel>
          <PanelHead
            title="Event detail"
            hint={`${selected.event_kind} · ${selected.host_id} · ${since(
              selected.ingested_at_unix_ms,
            )}`}
            actions={
              <>
                <Tabs
                  items={[
                    { value: "event", label: "Event" },
                    { value: "raw", label: "Row" },
                  ]}
                  value={detailTab}
                  onChange={setDetailTab}
                />
                <Button variant="primary" onClick={() => draftRule(selected)}>
                  <Wand2 className="h-3 w-3" />
                  Create detection
                </Button>
              </>
            }
          />
          <Json
            value={detailTab === "event" ? selected.event : selected}
            className="max-h-72"
          />
        </Panel>
      )}
    </div>
  );
}
