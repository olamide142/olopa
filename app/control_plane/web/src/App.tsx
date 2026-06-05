import { Routes, Route } from "react-router-dom";
import { Server, ShieldAlert, Network, FileCode2, Cpu, Download } from "lucide-react";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { MetricsPanel } from "@/components/panels/MetricsPanel";
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
            <Route
              path="/oil"
              element={
                <Placeholder
                  title="OIL Editor"
                  icon={FileCode2}
                  description="Author and check OIL detection rules against the compiler."
                />
              }
            />
            <Route
              path="/compiler"
              element={
                <Placeholder
                  title="Compiler"
                  icon={Cpu}
                  description="Run the oilc pipeline: AST, MIR, runtime-IR and codegen with diagnostics."
                />
              }
            />
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
