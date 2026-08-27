import { Link } from "react-router-dom";
import { AlertTriangle, ArrowUpRight, Radio, ShieldOff } from "lucide-react";
import {
  Chip,
  Dot,
  Empty,
  Field,
  Meter,
  Notice,
  Panel,
  PanelHead,
  PageHead,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc, type RecentResponse, type RecentRow } from "@/lib/ipc";
import { bytes, duration, num, pct, since } from "@/lib/format";
import { useSystem } from "@/state/system";

const POSTURE = {
  protected: { label: "PROTECTED", tone: "ok" },
  degraded: { label: "DEGRADED", tone: "warn" },
  down: { label: "NO AGENT", tone: "danger" },
  unknown: { label: "UNKNOWN", tone: "muted" },
} as const;

/** Render one telemetry row as a single readable activity line. */
function activityLine(row: RecentRow): { verb: string; tone: "ok" | "warn" | "danger" | "muted"; text: string } {
  const event = row.event ?? {};
  const str = (key: string) => (typeof event[key] === "string" ? (event[key] as string) : "");
  const numeric = (key: string) => (typeof event[key] === "number" ? (event[key] as number) : undefined);
  const comm = str("comm") || "?";

  if (row.event_kind === "process_exec") {
    return { verb: "EXEC", tone: "muted", text: `${comm} → ${str("filename") || "?"}` };
  }
  if (row.event_kind === "file") {
    return { verb: "FILE", tone: "muted", text: `${comm} → ${str("path") || str("filename") || "?"}` };
  }
  if (row.event_kind === "net") {
    const port = numeric("dst_port");
    const verdict = event.attrs?.verdict;
    const denied = verdict === "deny" || verdict === "drop";
    return {
      verb: denied ? "DENY" : "NET",
      tone: denied ? "danger" : "muted",
      text: `${comm} → ${str("dst_ip") || "?"}${port ? `:${port}` : ""}`,
    };
  }
  if (row.event_kind === "db_query") {
    const tables = Array.isArray(event.tables) ? (event.tables as string[]).join(",") : "";
    return { verb: "SQL", tone: "muted", text: `${str("db_engine") || "db"} ${tables || str("database") || ""}` };
  }
  if (row.event_kind === "agent_heartbeat") {
    return { verb: "BEAT", tone: "muted", text: `agent ${str("agent_version") || ""}` };
  }
  return { verb: row.event_kind.toUpperCase().slice(0, 5), tone: "muted", text: comm };
}

function isAlert(row: RecentRow): boolean {
  return row.event?.attrs?.wire === "alert_binary";
}

export function OverviewPanel() {
  const { agent, host, secureConnect, posture, live } = useSystem();
  const snapshot = agent?.snapshot ?? null;

  // Live activity comes from ingest, which is where the agent ships events.
  const feed = usePolling(
    () => ipc.http<RecentResponse>("ingest", "GET", "/api/v1/ingest/recent?limit=40"),
    3000,
  );
  const rows = feed.data?.body?.rows ?? [];
  const alerts = rows.filter(isAlert);
  const state = POSTURE[posture];

  const captured = snapshot?.window_5s.captured ?? 0;
  const transmitted = snapshot?.window_5s.transmitted ?? 0;

  return (
    <div className="space-y-4">
      <PageHead
        title="Overview"
        subtitle={
          host
            ? `${host.hostname} · ${host.os} · kernel ${host.kernel}`
            : "reading host facts…"
        }
        actions={
          <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface px-2 py-1">
            <Dot tone={state.tone} pulse={live} />
            <span className="font-mono text-[11px] tracking-wider text-fg">{state.label}</span>
          </div>
        }
      />

      {agent?.error && <Notice tone={agent.stale ? "warn" : "danger"}>{agent.error}</Notice>}

      <div className="grid gap-3 lg:grid-cols-4">
        <Panel>
          <PanelHead title="Agent" />
          <div className="px-3 py-2">
            <Field
              label="Daemon"
              value={live ? "running" : "not running"}
              tone={live ? "ok" : "danger"}
              mono={false}
            />
            <Field label="PID" value={snapshot?.pid ?? "—"} />
            <Field label="Interface" value={snapshot?.iface || "—"} />
            <Field label="Uptime" value={duration(host?.uptime_secs)} />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Pipeline" hint="5s window" />
          <div className="px-3 py-2">
            <Field label="Captured" value={num(captured)} />
            <Field label="Transmitted" value={num(transmitted)} />
            <Field
              label="Dropped (budget)"
              value={num(snapshot?.window_5s.dropped_budget)}
              tone={(snapshot?.window_5s.dropped_budget ?? 0) > 0 ? "warn" : undefined}
            />
            <Field
              label="Backend"
              value={
                snapshot?.backend.reachable ? `${snapshot.backend.rtt_ms ?? 0} ms` : "unreachable"
              }
              tone={snapshot?.backend.reachable ? "ok" : "danger"}
            />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Enforcement" hint="agentic firewall" />
          <div className="px-3 py-2">
            <Field label="Allow" value={num(snapshot?.firewall.allow)} tone="ok" />
            <Field
              label="Deny"
              value={num(snapshot?.firewall.deny)}
              tone={(snapshot?.firewall.deny ?? 0) > 0 ? "danger" : undefined}
            />
            <Field label="Approve" value={num(snapshot?.firewall.approve)} tone="warn" />
            <Field label="Probes" value={snapshot?.probes.length ?? 0} />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Budgets" hint="resource-aware scheduler" />
          <div className="space-y-2.5 px-3 py-2.5">
            <Meter
              label="CPU"
              value={snapshot?.resources.cpu_pct ?? 0}
              limit={snapshot?.resources.cpu_budget_pct ?? 0}
              render={(v) => pct(v)}
            />
            <Meter
              label="Memory"
              value={snapshot?.resources.mem_mb ?? 0}
              limit={snapshot?.resources.mem_ceiling_mb ?? 0}
              render={(v) => `${v.toFixed(0)} MB`}
            />
            <Meter
              label="Bandwidth"
              value={snapshot?.resources.bw_mb_s ?? 0}
              limit={snapshot?.resources.bw_limit_pct ?? 0}
              render={(v) => `${v.toFixed(2)} MB/s`}
            />
          </div>
        </Panel>
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHead
            title="Live activity"
            hint={
              feed.data?.body
                ? `${rows.length} of ${num(feed.data.body.total_available)} rows · ingest`
                : "ingest"
            }
            actions={
              <Link
                to="/telemetry"
                className="flex items-center gap-1 text-[11px] text-fg-muted hover:text-fg"
              >
                explore <ArrowUpRight className="h-3 w-3" />
              </Link>
            }
          />
          {rows.length === 0 ? (
            <Empty
              icon={Radio}
              title="No telemetry"
              detail={
                feed.data?.error ??
                "The ingest server returned no rows. Check the endpoint in Settings, or start the agent."
              }
            />
          ) : (
            <div className="max-h-72 overflow-y-auto">
              {rows.slice(0, 40).map((row, index) => {
                const line = activityLine(row);
                const alert = isAlert(row);
                return (
                  <div
                    key={`${row.batch_id}-${index}`}
                    className="flex items-center gap-2 border-b border-border/50 px-3 py-1 last:border-0"
                  >
                    <span className="font-mono text-[10px] tabular-nums text-fg-faint">
                      {new Date(row.ingested_at_unix_ms).toTimeString().slice(0, 8)}
                    </span>
                    <Chip tone={alert ? "danger" : line.tone === "danger" ? "danger" : "muted"}>
                      {alert ? "ALERT" : line.verb}
                    </Chip>
                    <span className="truncate font-mono text-[11px] text-fg-muted">
                      {line.text}
                    </span>
                    <span className="ml-auto shrink-0 font-mono text-[10px] text-fg-faint">
                      {row.host_id.slice(0, 12)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <div className="space-y-3">
          <Panel>
            <PanelHead title="Alerts" hint="rule matches in the current window" />
            {alerts.length === 0 ? (
              <div className="px-3 py-4 text-[11px] text-fg-muted">
                No rule matches in the last {rows.length} rows.
              </div>
            ) : (
              <div className="max-h-40 overflow-y-auto">
                {alerts.slice(0, 12).map((row, index) => (
                  <div
                    key={index}
                    className="flex items-center gap-2 border-b border-border/50 px-3 py-1.5 last:border-0"
                  >
                    <AlertTriangle className="h-3 w-3 shrink-0 text-danger" />
                    <span className="truncate font-mono text-[11px] text-fg">
                      {row.event.attrs?.rule ?? row.event.attrs?.rule_name ?? "rule match"}
                    </span>
                    <span className="ml-auto font-mono text-[10px] text-fg-faint">
                      {since(row.ingested_at_unix_ms)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel>
            <PanelHead title="Secure Connect" />
            {secureConnect?.snapshot?.enabled ? (
              <div className="px-3 py-2">
                <Field
                  label="State"
                  value={secureConnect.snapshot.state}
                  tone={secureConnect.snapshot.state === "healthy" ? "ok" : "warn"}
                  mono={false}
                />
                <Field label="Interface" value={secureConnect.snapshot.interface ?? "—"} />
                <Field
                  label="Transfer"
                  value={`${bytes(secureConnect.snapshot.bytes_tx)} ↑ ${bytes(
                    secureConnect.snapshot.bytes_rx,
                  )} ↓`}
                />
                <Field
                  label="Handshake"
                  value={
                    secureConnect.snapshot.last_handshake_unix
                      ? since(secureConnect.snapshot.last_handshake_unix * 1000)
                      : "never"
                  }
                />
              </div>
            ) : (
              <Empty
                icon={ShieldOff}
                title="Tunnel not enabled"
                detail="The agent publishes no Secure Connect health, so OLOPA_SC_ENABLED is off on this host."
              />
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
