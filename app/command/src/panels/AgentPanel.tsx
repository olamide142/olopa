import { useState } from "react";
import { Play, RefreshCw, RotateCcw, Square, Terminal } from "lucide-react";
import {
  Button,
  Chip,
  Code,
  Field,
  Meter,
  Notice,
  Panel,
  PanelHead,
  PageHead,
} from "@/components/ui/primitives";
import { ipc, type AgentAction, type CommandOutcome } from "@/lib/ipc";
import { duration, num, pct, since } from "@/lib/format";
import { useSystem } from "@/state/system";

const LIFECYCLE: { action: AgentAction; label: string; icon: typeof Play; danger?: boolean }[] = [
  { action: "start", label: "Start", icon: Play },
  { action: "restart", label: "Restart", icon: RotateCcw },
  { action: "stop", label: "Stop", icon: Square, danger: true },
];

export function AgentPanel() {
  const { agent, host, refresh, live } = useSystem();
  const snapshot = agent?.snapshot ?? null;
  const [pending, setPending] = useState<AgentAction | null>(null);
  const [outcome, setOutcome] = useState<CommandOutcome | null>(null);
  const [confirm, setConfirm] = useState<AgentAction | null>(null);

  const runLifecycle = async (action: AgentAction) => {
    if (confirm !== action) {
      setConfirm(action);
      return;
    }
    setConfirm(null);
    setPending(action);
    try {
      setOutcome(await ipc.agentControl(action));
      refresh();
    } finally {
      setPending(null);
    }
  };

  const runCli = async () => {
    setPending("status");
    try {
      setOutcome(await ipc.agentCliStatus());
    } finally {
      setPending(null);
    }
  };

  return (
    <div className="space-y-4">
      <PageHead
        title="Agent"
        subtitle={
          <>
            Command is a client. The agent is an independent privileged daemon — closing this
            window never stops protection.
          </>
        }
        actions={
          <Button onClick={() => refresh()}>
            <RefreshCw className="h-3 w-3" />
            Refresh
          </Button>
        }
      />

      {agent && !agent.present && (
        <Notice tone="danger">
          No snapshot at <span className="font-mono">{agent.path}</span>. The agent writes this file
          every 5 seconds while running; set a different path in Settings if yours is elsewhere.
        </Notice>
      )}
      {agent?.stale && <Notice tone="warn">{agent.error}</Notice>}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel>
          <PanelHead title="Identity" />
          <div className="px-3 py-2">
            <Field label="Host" value={host?.hostname || "—"} />
            <Field label="Kernel" value={host?.kernel || "—"} />
            <Field label="OS" value={host?.os || "—"} mono={false} />
            <Field label="Host uptime" value={duration(host?.uptime_secs)} />
            <Field label="Snapshot version" value={snapshot?.version ?? "—"} />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Runtime" />
          <div className="px-3 py-2">
            <Field
              label="Daemon"
              value={live ? "running" : "stopped"}
              tone={live ? "ok" : "danger"}
              mono={false}
            />
            <Field label="PID" value={snapshot?.pid ?? "—"} />
            <Field label="Interface" value={snapshot?.iface || "—"} />
            <Field
              label="Snapshot age"
              value={snapshot ? since(snapshot.generated_at_unix_ms) : "—"}
              tone={agent?.stale ? "warn" : undefined}
            />
            <Field label="Path" value={agent?.path ?? "—"} />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Backend" hint="telemetry transport" />
          <div className="px-3 py-2">
            <Field
              label="Reachable"
              value={snapshot?.backend.reachable ? "yes" : "no"}
              tone={snapshot?.backend.reachable ? "ok" : "danger"}
              mono={false}
            />
            <Field label="RTT" value={snapshot?.backend.rtt_ms != null ? `${snapshot.backend.rtt_ms} ms` : "—"} />
            <Field label="Captured / 5s" value={num(snapshot?.window_5s.captured)} />
            <Field label="Transmitted / 5s" value={num(snapshot?.window_5s.transmitted)} />
            <Field
              label="Dropped by budget"
              value={num(snapshot?.window_5s.dropped_budget)}
              tone={(snapshot?.window_5s.dropped_budget ?? 0) > 0 ? "warn" : undefined}
            />
          </div>
        </Panel>
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel className="lg:col-span-1">
          <PanelHead
            title="Resource budgets"
            hint="the scheduler maximises signal under these limits"
          />
          <div className="space-y-3 px-3 py-3">
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

        <Panel className="lg:col-span-2">
          <PanelHead
            title="Attached probes"
            hint={`${snapshot?.probes.length ?? 0} probe group(s) reported by the agent`}
          />
          <div className="flex flex-wrap gap-1.5 px-3 py-3">
            {(snapshot?.probes ?? []).length === 0 ? (
              <span className="text-[11px] text-fg-muted">
                The snapshot lists no probes. The agent publishes this from
                <span className="font-mono"> OLOPA_PROBE_EVENTS_ACTIVE</span>.
              </span>
            ) : (
              snapshot?.probes.map((probe) => (
                <Chip key={probe} tone="primary">
                  {probe}
                </Chip>
              ))
            )}
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHead
          title="Lifecycle"
          hint="drives systemd directly — privileged actions fail with systemd's own message"
          actions={
            <Button onClick={() => void runCli()} disabled={pending !== null}>
              <Terminal className="h-3 w-3" />
              olopa status --verbose
            </Button>
          }
        />
        <div className="flex flex-wrap items-center gap-2 px-3 py-3">
          {LIFECYCLE.map(({ action, label, icon: Icon, danger }) => (
            <Button
              key={action}
              variant={confirm === action ? "primary" : danger ? "danger" : "default"}
              onClick={() => void runLifecycle(action)}
              disabled={pending !== null}
            >
              <Icon className="h-3 w-3" />
              {confirm === action ? `Confirm ${label.toLowerCase()}` : label}
              {pending === action && "…"}
            </Button>
          ))}
          {confirm && (
            <span className="text-[11px] text-warn">
              This changes a privileged daemon. Click again to confirm.
            </span>
          )}
        </div>

        {outcome && (
          <div className="border-t border-border">
            <div className="flex items-center gap-2 px-3 py-1.5">
              <Chip tone={outcome.ok ? "ok" : "danger"}>
                exit {outcome.exit_code ?? "—"}
              </Chip>
              <span className="selectable font-mono text-[10px] text-fg-faint">
                {outcome.command}
              </span>
            </div>
            <Code
              content={outcome.stdout || outcome.stderr}
              className="max-h-64 border-t border-border"
              empty="command produced no output"
            />
          </div>
        )}
      </Panel>
    </div>
  );
}
