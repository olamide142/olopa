import { useMemo, useState } from "react";
import { Cpu, RefreshCw } from "lucide-react";
import {
  Button,
  Chip,
  Empty,
  Field,
  Meter,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Tabs,
  Td,
  Th,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc, type BpfMap, type BpfProgram } from "@/lib/ipc";
import { bytes, nanos, num } from "@/lib/format";
import { useSystem } from "@/state/system";

type View = "programs" | "maps";

/** Per-run cost, which is what actually matters on the hot path. */
function costPerRun(program: BpfProgram): number {
  if (!program.run_count) return 0;
  return program.run_time_ns / program.run_count;
}

export function EbpfPanel() {
  const { agent } = useSystem();
  const inventory = usePolling(() => ipc.ebpfInventory(), 5000);
  const [view, setView] = useState<View>("programs");
  const [selectedProgram, setSelectedProgram] = useState<BpfProgram | null>(null);
  const [selectedMap, setSelectedMap] = useState<BpfMap | null>(null);

  const data = inventory.data;
  const programs = useMemo(
    () =>
      [...(data?.programs ?? [])].sort(
        (a, b) => Number(b.attributed_to_agent) - Number(a.attributed_to_agent) || b.run_count - a.run_count,
      ),
    [data],
  );
  const maps = data?.maps ?? [];
  const olopaPrograms = programs.filter((p) => p.attributed_to_agent);
  const mapsById = useMemo(() => new Map(maps.map((m) => [m.id, m])), [maps]);

  const totalMapBytes = maps.reduce((sum, map) => sum + map.bytes_memlock, 0);
  const agentProbes = agent?.snapshot?.probes ?? [];

  return (
    <div className="space-y-3">
      <PageHead
        title="eBPF"
        subtitle="The kernel's own view, read through bpftool and correlated with the probes the agent reports."
        actions={
          <Button onClick={() => void inventory.refresh()}>
            <RefreshCw className="h-3 w-3" />
            Rescan
          </Button>
        }
      />

      {data?.note && <Notice tone={data.available ? "warn" : "danger"}>{data.note}</Notice>}

      <div className="grid gap-3 lg:grid-cols-4">
        <Panel>
          <PanelHead title="Programs" />
          <div className="px-3 py-2">
            <Field label="Loaded (kernel)" value={num(programs.length)} />
            <Field
              label="Attributed to Olopa"
              value={num(olopaPrograms.length)}
              tone={olopaPrograms.length > 0 ? "primary" : undefined}
            />
            <Field label="Agent probe groups" value={num(agentProbes.length)} />
          </div>
        </Panel>
        <Panel>
          <PanelHead title="Maps" />
          <div className="px-3 py-2">
            <Field label="Loaded" value={num(maps.length)} />
            <Field label="Locked memory" value={bytes(totalMapBytes)} />
          </div>
        </Panel>
        <Panel className="lg:col-span-2">
          <PanelHead title="Probe groups" hint="reported by the agent snapshot" />
          <div className="flex flex-wrap gap-1.5 px-3 py-2.5">
            {agentProbes.length === 0 ? (
              <span className="text-[11px] text-fg-muted">
                The agent snapshot lists no active probe groups.
              </span>
            ) : (
              agentProbes.map((probe) => (
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
          title="Kernel objects"
          hint={data?.available ? "bpftool -j" : "bpftool unavailable"}
          actions={
            <Tabs
              items={[
                { value: "programs", label: "Programs", hint: programs.length },
                { value: "maps", label: "Maps", hint: maps.length },
              ]}
              value={view}
              onChange={setView}
            />
          }
        />

        {!data?.available ? (
          <Empty
            icon={Cpu}
            title="No kernel visibility"
            detail="Command reads programs and maps with bpftool. Install it and run with CAP_BPF (or as root) to inspect the kernel."
          />
        ) : view === "programs" ? (
          <div className="max-h-96 overflow-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th className="w-14">ID</Th>
                  <Th>Name</Th>
                  <Th className="w-32">Type</Th>
                  <Th className="w-24 text-right">Runs</Th>
                  <Th className="w-24 text-right">Per run</Th>
                  <Th className="w-16 text-right">Maps</Th>
                </tr>
              </thead>
              <tbody>
                {programs.map((program) => (
                  <tr
                    key={program.id}
                    onClick={() => setSelectedProgram(program)}
                    className={
                      "cursor-pointer border-b border-border/40 hover:bg-surface-2 " +
                      (selectedProgram?.id === program.id ? "bg-surface-2" : "")
                    }
                  >
                    <Td className="font-mono text-fg-faint">{program.id}</Td>
                    <Td>
                      <span className="flex items-center gap-1.5">
                        <span className="font-mono text-fg">{program.name || "—"}</span>
                        {program.attributed_to_agent && <Chip tone="primary">olopa</Chip>}
                      </span>
                    </Td>
                    <Td className="font-mono text-fg-muted">{program.kind}</Td>
                    <Td className="text-right font-mono tabular-nums text-fg-muted">
                      {num(program.run_count)}
                    </Td>
                    <Td className="text-right font-mono tabular-nums text-fg">
                      {program.run_count ? nanos(costPerRun(program)) : "—"}
                    </Td>
                    <Td className="text-right font-mono text-fg-faint">
                      {program.map_ids.length}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="max-h-96 overflow-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th className="w-14">ID</Th>
                  <Th>Name</Th>
                  <Th className="w-36">Type</Th>
                  <Th className="w-28 text-right">Capacity</Th>
                  <Th className="w-24 text-right">Entry size</Th>
                  <Th className="w-24 text-right">Memory</Th>
                </tr>
              </thead>
              <tbody>
                {maps.map((map) => (
                  <tr
                    key={map.id}
                    onClick={() => setSelectedMap(map)}
                    className={
                      "cursor-pointer border-b border-border/40 hover:bg-surface-2 " +
                      (selectedMap?.id === map.id ? "bg-surface-2" : "")
                    }
                  >
                    <Td className="font-mono text-fg-faint">{map.id}</Td>
                    <Td className="font-mono text-fg">{map.name || "—"}</Td>
                    <Td className="font-mono text-fg-muted">{map.kind}</Td>
                    <Td className="text-right font-mono tabular-nums text-fg-muted">
                      {num(map.max_entries)}
                    </Td>
                    <Td className="text-right font-mono tabular-nums text-fg-faint">
                      {map.bytes_key + map.bytes_value} B
                    </Td>
                    <Td className="text-right font-mono tabular-nums text-fg">
                      {bytes(map.bytes_memlock)}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {view === "programs" && selectedProgram && (
        <Panel>
          <PanelHead
            title={selectedProgram.name || `program ${selectedProgram.id}`}
            hint={`${selectedProgram.kind} · tag ${selectedProgram.tag || "—"}`}
          />
          <div className="grid gap-4 px-3 py-3 md:grid-cols-2">
            <div>
              <Field label="Program ID" value={selectedProgram.id} />
              <Field label="Type" value={selectedProgram.kind} />
              <Field label="Total runs" value={num(selectedProgram.run_count)} />
              <Field label="Total time" value={nanos(selectedProgram.run_time_ns)} />
              <Field
                label="Mean per run"
                value={selectedProgram.run_count ? nanos(costPerRun(selectedProgram)) : "—"}
                tone={costPerRun(selectedProgram) > 1000 ? "warn" : "ok"}
              />
            </div>
            <div className="space-y-2">
              <div className="text-[11px] text-fg-muted">
                Attached maps ({selectedProgram.map_ids.length})
              </div>
              {selectedProgram.map_ids.length === 0 ? (
                <p className="text-[11px] text-fg-faint">This program uses no maps.</p>
              ) : (
                selectedProgram.map_ids.map((id) => {
                  const map = mapsById.get(id);
                  if (!map) {
                    return (
                      <div key={id} className="text-[11px] text-fg-faint">
                        map {id} (not visible)
                      </div>
                    );
                  }
                  return (
                    <div key={id} className="rounded border border-border bg-bg px-2 py-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-fg">{map.name || id}</span>
                        <Chip tone="muted">{map.kind}</Chip>
                        <span className="ml-auto font-mono text-[10px] text-fg-faint">
                          {bytes(map.bytes_memlock)}
                        </span>
                      </div>
                      <div className="mt-1.5">
                        <Meter
                          label="capacity"
                          value={map.max_entries}
                          limit={map.max_entries}
                          render={(v) => num(v)}
                          tone="info"
                        />
                      </div>
                    </div>
                  );
                })
              )}
              <p className="pt-1 text-[10px] leading-relaxed text-fg-faint">
                The kernel exposes map capacity but not live occupancy, so utilisation is not shown
                here rather than being guessed at.
              </p>
            </div>
          </div>
        </Panel>
      )}

      {view === "maps" && selectedMap && (
        <Panel>
          <PanelHead title={selectedMap.name || `map ${selectedMap.id}`} hint={selectedMap.kind} />
          <div className="grid gap-x-8 px-3 py-3 md:grid-cols-2">
            <div>
              <Field label="Map ID" value={selectedMap.id} />
              <Field label="Type" value={selectedMap.kind} />
              <Field label="Max entries" value={num(selectedMap.max_entries)} />
            </div>
            <div>
              <Field label="Key size" value={`${selectedMap.bytes_key} B`} />
              <Field label="Value size" value={`${selectedMap.bytes_value} B`} />
              <Field label="Locked memory" value={bytes(selectedMap.bytes_memlock)} />
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
