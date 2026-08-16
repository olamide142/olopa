import { Routes, Route } from "react-router-dom";
import { Server, ShieldAlert, Network, Download } from "lucide-react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { MetricsPanel } from "@/components/panels/MetricsPanel";
import { OilEditorPanel } from "@/components/panels/OilEditorPanel";
import { CompilerPanel } from "@/components/panels/CompilerPanel";
import { RulesPanel } from "@/components/panels/RulesPanel";
import { DeploymentsPanel } from "@/components/panels/DeploymentsPanel";
import { Placeholder } from "@/components/panels/Placeholder";
import { useIngestFeed } from "@/hooks/useIngestFeed";

export default function App() {
  const { state, setPaused, setWindow, setPollMs } = useIngestFeed();

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar feed={state} />
        <main className="flex-1 overflow-y-auto p-5">
          <Routes>
            <Route
              path="/"
              element={
                <MetricsPanel feed={state} setPaused={setPaused} setWindow={setWindow} setPollMs={setPollMs} />
              }
            />
            <Route
              path="/fleet"
              element={
                <Placeholder
                  title="Fleet"
                  icon={Server}
                  description="Per-agent health: version, kernel, queue depth, drop rate and last-seen. Wires to the planned /api/v1/ingest/agents endpoint."
                />
              }
            />
            <Route
              path="/incidents"
              element={
                <Placeholder
                  title="Incidents"
                  icon={ShieldAlert}
                  description="Live rule matches grouped into incidents, with suppression and triage."
                />
              }
            />
            <Route
              path="/graph"
              element={
                <Placeholder
                  title="Provenance Graph"
                  icon={Network}
                  description="Process / network / file provenance graph built from recent telemetry."
                />
              }
            />
            <Route path="/oil" element={<OilEditorPanel />} />
            <Route path="/compiler" element={<CompilerPanel />} />
            <Route path="/rules" element={<RulesPanel />} />
            <Route path="/deployments" element={<DeploymentsPanel />} />
            <Route
              path="/install"
              element={
                <Placeholder
                  title="Install Agent"
                  icon={Download}
                  description="Download the agent binary and installer script for your hosts."
                />
              }
            />
          </Routes>
        </main>
      </div>
    </div>
  );
}
