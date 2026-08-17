import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CircleSlash, Download, FlaskConical, Gauge, Play, Target } from "lucide-react";
import {
  Button,
  Chip,
  Empty,
  Field,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Tabs,
  Td,
  Th,
} from "@/components/ui/primitives";
import { OilEditor } from "@/components/OilEditor";
import { ipc, type EventRow, type RecentResponse, type SimulationReport } from "@/lib/ipc";
import { SYNTHETIC_EVENTS, toEventRow } from "@/lib/events";
import { nanos, num } from "@/lib/format";
import { SIMPLE_RULE, useOil } from "@/state/oil";

type Corpus = "synthetic" | "recorded";

export function SimulatorPanel() {
  const navigate = useNavigate();
  const { source, setSource } = useOil();
  const [corpus, setCorpus] = useState<Corpus>("synthetic");
  const [events, setEvents] = useState<EventRow[]>(SYNTHETIC_EVENTS);
  const [report, setReport] = useState<SimulationReport | null>(null);
  const [running, setRunning] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadRecorded = useCallback(async () => {
    setLoadError(null);
    const reply = await ipc.http<RecentResponse>(
      "ingest",
      "GET",
      "/api/v1/ingest/recent?limit=1000",
    );
    if (!reply.ok || !reply.body) {
      setLoadError(reply.error ?? `ingest returned HTTP ${reply.status}`);
      setEvents([]);
      return;
    }
    setEvents(reply.body.rows.map(toEventRow));
  }, []);

  const pickCorpus = (next: Corpus) => {
    setCorpus(next);
    setReport(null);
    if (next === "synthetic") {
      setEvents(SYNTHETIC_EVENTS);
      setLoadError(null);
    } else {
      void loadRecorded();
    }
  };

  const run = async () => {
    setRunning(true);
    try {
      setReport(await ipc.oilSimulate(source, events));
    } finally {
      setRunning(false);
    }
  };

  const skipped = useMemo(() => (report?.rules ?? []).filter((r) => r.skipped_reason), [report]);
  const executed = useMemo(() => (report?.rules ?? []).filter((r) => !r.skipped_reason), [report]);

  return (
    <div className="space-y-3">
      <PageHead
        title="Simulator"
        subtitle="Replays events through the same runtime-IR trees the agent evaluates — no fleet, no deploy."
        actions={
          <div className="flex items-center gap-2">
            <Tabs
              items={[
                { value: "synthetic", label: "Synthetic" },
                { value: "recorded", label: "Recorded" },
              ]}
              value={corpus}
              onChange={(next) => pickCorpus(next as Corpus)}
            />
            <Button onClick={() => void loadRecorded()} disabled={corpus !== "recorded"}>
              <Download className="h-3 w-3" />
              Reload
            </Button>
            <Button variant="primary" onClick={() => void run()} disabled={running || events.length === 0}>
              <Play className="h-3 w-3" />
              {running ? "Running…" : `Run ${num(events.length)} events`}
            </Button>
          </div>
        }
      />

      {loadError && <Notice tone="danger">{loadError}</Notice>}
      {report && !report.ok && (
        <Notice tone="danger">
          {report.diagnostics[0]?.message ?? "The rule did not compile."}
        </Notice>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="space-y-3">
          <Panel className="overflow-hidden">
            <PanelHead
              title="Policy under test"
              hint="shared with Studio"
              actions={
                <>
                  <Button size="xs" onClick={() => setSource(SIMPLE_RULE)}>
                    Load example
                  </Button>
                  <Button size="xs" onClick={() => navigate("/studio")}>
                    Open in Studio
                  </Button>
                </>
              }
            />
            <OilEditor value={source} onChange={setSource} className="h-64 rounded-none border-0" />
          </Panel>

          <Panel>
            <PanelHead
              title="Corpus"
              hint={
                corpus === "synthetic"
                  ? `${SYNTHETIC_EVENTS.length} handwritten events`
                  : `${num(events.length)} rows from ingest`
              }
            />
            <div className="max-h-52 overflow-auto">
              {events.length === 0 ? (
                <Empty
                  icon={FlaskConical}
                  title="No events loaded"
                  detail="Switch to the synthetic corpus, or check that ingest has rows."
                />
              ) : (
                <table className="w-full">
                  <thead>
                    <tr>
                      <Th className="w-10">#</Th>
                      <Th className="w-28">Kind</Th>
                      <Th>Fields</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 200).map((event, index) => (
                      <tr key={index} className="border-b border-border/40">
                        <Td className="font-mono text-fg-faint">{index}</Td>
                        <Td>
                          <Chip tone="muted">{String(event.event_kind ?? "event")}</Chip>
                        </Td>
                        <Td className="max-w-0 truncate font-mono text-fg-muted">
                          {Object.entries(event)
                            .filter(([key]) => key !== "event_kind" && key !== "attrs")
                            .slice(0, 6)
                            .map(([key, value]) => `${key}=${String(value)}`)
                            .join("  ")}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Panel>
              <PanelHead title="Throughput" />
              <div className="px-3 py-2">
                <Field label="Events" value={num(report?.events_processed)} />
                <Field label="Rule evaluations" value={num(report?.evaluations)} />
                <Field label="Wall time" value={report ? `${report.elapsed_ms} ms` : "—"} />
                <Field
                  label="Mean per evaluation"
                  value={report ? nanos(report.ns_per_evaluation) : "—"}
                  tone="primary"
                />
              </div>
            </Panel>
            <Panel>
              <PanelHead title="Outcome" />
              <div className="px-3 py-2">
                <Field
                  label="Matches"
                  value={num(report?.matches.length)}
                  tone={(report?.matches.length ?? 0) > 0 ? "danger" : "ok"}
                />
                <Field label="Rules executed" value={num(executed.length)} />
                <Field
                  label="Rules skipped"
                  value={num(skipped.length)}
                  tone={skipped.length > 0 ? "warn" : undefined}
                />
              </div>
            </Panel>
          </div>

          <Panel>
            <PanelHead title="Matches" hint="first match branch decides the response" />
            {!report ? (
              <Empty
                icon={Gauge}
                title="Not run yet"
                detail="Run the policy against the corpus to see which events it would fire on."
              />
            ) : report.matches.length === 0 ? (
              <Empty
                icon={Target}
                title="No matches"
                detail="No event in this corpus satisfies the rule's predicates."
              />
            ) : (
              <div className="max-h-56 overflow-auto">
                <table className="w-full">
                  <thead>
                    <tr>
                      <Th className="w-12">Event</Th>
                      <Th>Rule</Th>
                      <Th className="w-16 text-right">Score</Th>
                      <Th className="w-40">Response</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.matches.map((match, index) => (
                      <tr key={index} className="border-b border-border/40">
                        <Td className="font-mono text-fg-faint">#{match.event_index}</Td>
                        <Td className="font-mono text-fg">{match.rule_name}</Td>
                        <Td className="text-right font-mono tabular-nums text-warn">
                          {match.score}
                        </Td>
                        <Td>
                          <span className="flex flex-wrap gap-1">
                            {match.actions.length === 0 ? (
                              <span className="text-fg-faint">—</span>
                            ) : (
                              match.actions.map((action) => (
                                <Chip key={action} tone="danger">
                                  {action}
                                </Chip>
                              ))
                            )}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {skipped.length > 0 && (
            <Panel>
              <PanelHead
                title="Not simulated"
                hint="these need runtime state a desktop replay does not have"
              />
              <ul className="px-3 py-2">
                {skipped.map((rule) => (
                  <li key={rule.id} className="flex items-start gap-2 py-1">
                    <CircleSlash className="mt-0.5 h-3 w-3 shrink-0 text-warn" />
                    <div>
                      <span className="font-mono text-[11px] text-fg">{rule.name}</span>
                      <p className="text-[10px] leading-relaxed text-fg-muted">
                        {rule.skipped_reason}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
