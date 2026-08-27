import { createContext, useContext, useMemo, type ReactNode } from "react";
import { usePolling } from "@/hooks/usePolling";
import {
  ipc,
  type AgentSnapshot,
  type HostFacts,
  type SecureConnectHealth,
  type SnapshotReport,
} from "@/lib/ipc";

/**
 * One poller for the agent's local snapshots, shared by every panel.
 *
 * The agent rewrites its status file every 5s, so polling faster than that only
 * burns cycles; 2s keeps the UI feeling live without reading the same bytes
 * many times over.
 */
const POLL_MS = 2000;

export type Posture = "protected" | "degraded" | "down" | "unknown";

interface SystemValue {
  agent: SnapshotReport<AgentSnapshot> | null;
  secureConnect: SnapshotReport<SecureConnectHealth> | null;
  host: HostFacts | null;
  posture: Posture;
  /** True when the agent snapshot is fresh and reports a running daemon. */
  live: boolean;
  refresh: () => void;
}

const SystemContext = createContext<SystemValue | null>(null);

export function SystemProvider({ children }: { children: ReactNode }) {
  const agent = usePolling(() => ipc.agentStatus(), POLL_MS);
  const secureConnect = usePolling(() => ipc.secureConnectStatus(), POLL_MS * 2);
  // Host facts are effectively static; read once.
  const host = usePolling(() => ipc.hostFacts(), 0);

  const value = useMemo<SystemValue>(() => {
    const report = agent.data;
    const snapshot = report?.snapshot ?? null;
    const live = Boolean(snapshot?.running && report && !report.stale);

    let posture: Posture = "unknown";
    if (!report || !report.present) posture = "down";
    else if (report.stale || !snapshot?.running) posture = "down";
    else if (!snapshot.backend.reachable) posture = "degraded";
    else posture = "protected";

    return {
      agent: report,
      secureConnect: secureConnect.data,
      host: host.data,
      posture,
      live,
      refresh: () => {
        void agent.refresh();
        void secureConnect.refresh();
      },
    };
  }, [agent, secureConnect, host.data]);

  return <SystemContext.Provider value={value}>{children}</SystemContext.Provider>;
}

export function useSystem(): SystemValue {
  const value = useContext(SystemContext);
  if (!value) throw new Error("useSystem must be used inside SystemProvider");
  return value;
}
