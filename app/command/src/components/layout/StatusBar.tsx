import { useEffect, useState } from "react";
import { Dot } from "@/components/ui/primitives";
import { bytes, num, since } from "@/lib/format";
import { useSystem } from "@/state/system";

function Item({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-wider text-fg-faint">{label}</span>
      <span className={`font-mono text-[11px] tabular-nums ${tone ?? "text-fg"}`}>{value}</span>
    </div>
  );
}

/** Always-visible instrument strip: the facts an operator glances at. */
export function StatusBar() {
  const { agent, secureConnect, live } = useSystem();
  const [now, setNow] = useState(() => new Date().toTimeString().slice(0, 8));

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date().toTimeString().slice(0, 8)), 1000);
    return () => clearInterval(timer);
  }, []);

  const snapshot = agent?.snapshot ?? null;
  const window5s = snapshot?.window_5s;
  // The agent reports a 5s capture window; events/sec is derived from it.
  const eps = window5s ? window5s.captured / 5 : 0;
  const sc = secureConnect?.snapshot ?? null;

  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-border bg-rail px-3">
      <div className="flex items-center gap-1.5">
        <Dot tone={live ? "ok" : "danger"} pulse={live} />
        <span className="text-[11px] text-fg-muted">
          {live ? `agent pid ${snapshot?.pid ?? "—"}` : "agent offline"}
        </span>
      </div>

      <Item
        label="backend"
        value={
          snapshot?.backend.reachable
            ? `${snapshot.backend.rtt_ms ?? 0} ms`
            : "unreachable"
        }
        tone={snapshot?.backend.reachable ? "text-ok" : "text-danger"}
      />
      <Item label="eps" value={num(eps)} />
      <Item label="iface" value={snapshot?.iface || "—"} />
      <Item
        label="deny"
        value={num(snapshot?.firewall.deny)}
        tone={(snapshot?.firewall.deny ?? 0) > 0 ? "text-warn" : undefined}
      />
      <Item
        label="dropped"
        value={num(window5s?.dropped_budget)}
        tone={(window5s?.dropped_budget ?? 0) > 0 ? "text-warn" : undefined}
      />

      {sc?.enabled && (
        <Item
          label="tunnel"
          value={`${sc.state} · ${bytes(sc.bytes_tx + sc.bytes_rx)}`}
          tone={sc.state === "healthy" ? "text-ok" : "text-warn"}
        />
      )}

      <div className="ml-auto flex items-center gap-4">
        <span className="text-[10px] text-fg-faint">
          snapshot {agent?.snapshot ? since(agent.snapshot.generated_at_unix_ms) : "—"}
        </span>
        <span className="font-mono text-[11px] tabular-nums text-fg-muted">{now}</span>
      </div>
    </footer>
  );
}
