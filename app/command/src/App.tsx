import { useCallback, useEffect, useMemo, useState } from "react";
import { Route, Routes, useNavigate } from "react-router-dom";
import { Sidebar, NAV } from "@/components/layout/Sidebar";
import { StatusBar } from "@/components/layout/StatusBar";
import { CommandPalette, type PaletteAction } from "@/components/CommandPalette";
import { OverviewPanel } from "@/panels/OverviewPanel";
import { AgentPanel } from "@/panels/AgentPanel";
import { TelemetryPanel } from "@/panels/TelemetryPanel";
import { EbpfPanel } from "@/panels/EbpfPanel";
import { StudioPanel } from "@/panels/StudioPanel";
import { SimulatorPanel } from "@/panels/SimulatorPanel";
import { RegistryPanel } from "@/panels/RegistryPanel";
import { SecureConnectPanel } from "@/panels/SecureConnectPanel";
import { LogsPanel } from "@/panels/LogsPanel";
import { SettingsPanel } from "@/panels/SettingsPanel";
import { Toasts, type Toast } from "@/components/Toasts";
import { ipc, type AgentAction } from "@/lib/ipc";
import { useTheme } from "@/hooks/useTheme";
import { SystemProvider, useSystem } from "@/state/system";
import { OilProvider } from "@/state/oil";

function Workspace({ onOpenPalette }: { onOpenPalette: () => void }) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar onOpenPalette={onOpenPalette} />
      <div className="flex min-w-0 flex-1 flex-col">
        <main className="flex-1 overflow-y-auto p-4">
          <Routes>
            <Route path="/" element={<OverviewPanel />} />
            <Route path="/agent" element={<AgentPanel />} />
            <Route path="/telemetry" element={<TelemetryPanel />} />
            <Route path="/ebpf" element={<EbpfPanel />} />
            <Route path="/studio" element={<StudioPanel />} />
            <Route path="/simulator" element={<SimulatorPanel />} />
            <Route path="/registry" element={<RegistryPanel />} />
            <Route path="/secure-connect" element={<SecureConnectPanel />} />
            <Route path="/logs" element={<LogsPanel />} />
            <Route path="/settings" element={<SettingsPanel />} />
          </Routes>
        </main>
        <StatusBar />
      </div>
    </div>
  );
}

function Chrome() {
  const navigate = useNavigate();
  const { refresh } = useSystem();
  const { theme, toggle: toggleTheme } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((toast: Omit<Toast, "id">) => {
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setToasts((prev) => [...prev, { ...toast, id }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 6000);
  }, []);

  // ⌘K / Ctrl+K anywhere, including from inside inputs.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const runAgentAction = useCallback(
    async (action: AgentAction) => {
      const outcome = await ipc.agentControl(action);
      push({
        tone: outcome.ok ? "ok" : "danger",
        title: `${action} agent`,
        detail: outcome.ok
          ? outcome.stdout || `systemctl ${action} succeeded`
          : outcome.stderr || `exit ${outcome.exit_code ?? "?"}`,
      });
      refresh();
    },
    [push, refresh],
  );

  const actions = useMemo<PaletteAction[]>(() => {
    const navigation: PaletteAction[] = NAV.flatMap((section) =>
      section.entries.map((entry) => ({
        id: `go:${entry.to}`,
        group: "Go to",
        label: entry.label,
        keywords: `${section.heading} navigate open`,
        run: () => navigate(entry.to),
      })),
    );

    const lifecycle: PaletteAction[] = (["start", "restart", "stop"] as AgentAction[]).map(
      (action) => ({
        id: `agent:${action}`,
        group: "Agent",
        label: `${action[0].toUpperCase()}${action.slice(1)} agent`,
        hint: `systemctl ${action}`,
        keywords: "daemon service systemctl lifecycle",
        destructive: true,
        run: () => runAgentAction(action),
      }),
    );

    return [
      ...navigation,
      ...lifecycle,
      {
        id: "view:theme",
        group: "View",
        label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme",
        keywords: "dark light appearance colour color contrast",
        run: () => toggleTheme(),
      },
      {
        id: "agent:refresh",
        group: "Agent",
        label: "Refresh snapshots",
        keywords: "reload poll status",
        run: () => refresh(),
      },
      {
        id: "agent:cli",
        group: "Agent",
        label: "Run olopa status --verbose",
        keywords: "cli diagnose",
        run: async () => {
          const outcome = await ipc.agentCliStatus();
          push({
            tone: outcome.ok ? "ok" : "warn",
            title: "olopa status",
            detail: (outcome.ok ? outcome.stdout : outcome.stderr).slice(0, 400) || "no output",
          });
        },
      },
      {
        id: "diag:bundle",
        group: "Diagnostics",
        label: "Export diagnostic bundle",
        keywords: "support zip logs snapshot",
        run: async () => {
          try {
            const bundle = await ipc.exportDiagnostics();
            push({
              tone: "ok",
              title: "Diagnostic bundle written",
              detail: bundle.path,
            });
          } catch (err) {
            push({
              tone: "danger",
              title: "Bundle failed",
              detail: err instanceof Error ? err.message : String(err),
            });
          }
        },
      },
    ];
  }, [navigate, refresh, runAgentAction, push]);

  return (
    <>
      <Workspace onOpenPalette={() => setPaletteOpen(true)} />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        actions={actions}
      />
      <Toasts toasts={toasts} onDismiss={(id) => setToasts((p) => p.filter((t) => t.id !== id))} />
    </>
  );
}

export default function App() {
  return (
    <SystemProvider>
      <OilProvider>
        <Chrome />
      </OilProvider>
    </SystemProvider>
  );
}
