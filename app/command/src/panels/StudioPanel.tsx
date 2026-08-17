import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Info,
  Layers,
  Play,
  Upload,
  XCircle,
} from "lucide-react";
import { OilEditor } from "@/components/OilEditor";
import {
  Button,
  Chip,
  Code,
  Input,
  Json,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Tabs,
  type Tone,
} from "@/components/ui/primitives";
import { ipc, type CompileReport, type OilDiagnostic, type PlanEngine, type RulePlan } from "@/lib/ipc";
import { useDraftPickup, useOil } from "@/state/oil";

type OutputTab = "diagnostics" | "plan" | "ir" | "ast" | "mir";

const ENGINE_TONE: Record<PlanEngine, Tone> = {
  kernel: "primary",
  "hot-path": "ok",
  "warm-state": "info",
  stream: "violet",
  scoring: "warn",
  enforcement: "danger",
  unsupported: "muted",
};

const ENGINE_LABEL: Record<PlanEngine, string> = {
  kernel: "eBPF",
  "hot-path": "hot path",
  "warm-state": "warm state",
  stream: "stream",
  scoring: "scoring",
  enforcement: "enforcement",
  unsupported: "unsupported",
};

function DiagnosticRow({ diagnostic }: { diagnostic: OilDiagnostic }) {
  const isError = diagnostic.severity === "error";
  const Icon = isError ? XCircle : AlertTriangle;
  return (
    <li className="flex items-start gap-2 border-b border-border/40 px-3 py-2 last:border-0">
      <Icon className={`mt-0.5 h-3 w-3 shrink-0 ${isError ? "text-danger" : "text-warn"}`} />
      <div className="min-w-0 flex-1">
        <p className="selectable break-words text-[11px] text-fg">{diagnostic.message}</p>
        <p className="mt-0.5 font-mono text-[10px] text-fg-faint">
          {diagnostic.stage}
          {diagnostic.line ? ` · line ${diagnostic.line}:${diagnostic.column ?? 0}` : ""}
        </p>
      </div>
    </li>
  );
}

/** Vertical plan: the compiler's own decisions about where each step runs. */
function PlanView({ plan }: { plan: RulePlan }) {
  return (
    <div className="border-b border-border last:border-0">
      <div className="flex flex-wrap items-center gap-2 bg-surface-2/50 px-3 py-1.5">
        <span className="font-mono text-[11px] font-semibold text-fg">{plan.name}</span>
        <Chip tone="violet">{plan.class}</Chip>
        {plan.window && <Chip tone="muted">window {plan.window}</Chip>}
        {plan.score_base !== 0 && <Chip tone="warn">base {plan.score_base}</Chip>}
      </div>

      <div className="px-3 py-2">
        {plan.steps.map((step, index) => (
          <div key={index} className="flex items-start gap-2 py-1">
            <div className="flex w-4 shrink-0 flex-col items-center">
              <div className="mt-1 h-1.5 w-1.5 rounded-full bg-border-strong" />
              {index < plan.steps.length - 1 && (
                <div className="mt-0.5 h-full min-h-4 w-px flex-1 bg-border" />
              )}
            </div>
            <div className="min-w-0 flex-1 pb-1">
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-medium text-fg">{step.label}</span>
                <Chip tone={ENGINE_TONE[step.engine]}>{ENGINE_LABEL[step.engine]}</Chip>
              </div>
              <p className="selectable truncate font-mono text-[10px] text-fg-muted">
                {step.detail}
              </p>
            </div>
          </div>
        ))}
      </div>

      {(plan.stateful_calls.length > 0 || plan.unsupported.length > 0) && (
        <div className="space-y-1 border-t border-border px-3 py-2">
          {plan.stateful_calls.length > 0 && (
            <p className="flex items-start gap-1.5 text-[10px] text-info">
              <Info className="mt-px h-3 w-3 shrink-0" />
              Needs warm state: {plan.stateful_calls.join(", ")} — evaluated against history, not a
              single event.
            </p>
          )}
          {plan.unsupported.length > 0 && (
            <p className="flex items-start gap-1.5 text-[10px] text-warn">
              <CircleSlash className="mt-px h-3 w-3 shrink-0" />
              Accepted by the parser but not executable at runtime:{" "}
              {plan.unsupported.join(", ")}.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function StudioPanel() {
  const navigate = useNavigate();
  const { source, setSource } = useOil();
  useDraftPickup(setSource);

  const [report, setReport] = useState<CompileReport | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [tab, setTab] = useState<OutputTab>("diagnostics");
  const [publishName, setPublishName] = useState("");
  const [publishState, setPublishState] = useState<{ tone: Tone; text: string } | null>(null);
  const timer = useRef<number | null>(null);

  const compile = useCallback(async (text: string) => {
    setCompiling(true);
    try {
      setReport(await ipc.oilCompile(text));
    } finally {
      setCompiling(false);
    }
  }, []);

  // Compile on a keystroke pause: the compiler is in-process, so this is cheap
  // enough to run continuously and gives feedback without a build step.
  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => void compile(source), 400);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [source, compile]);

  const diagnostics = report?.diagnostics ?? [];
  const errorLines = useMemo(
    () =>
      diagnostics
        .filter((d) => d.severity === "error" && d.line)
        .map((d) => d.line as number),
    [diagnostics],
  );
  const warnLines = useMemo(
    () =>
      diagnostics
        .filter((d) => d.severity === "warning" && d.line)
        .map((d) => d.line as number),
    [diagnostics],
  );
  const errorCount = errorLines.length;

  const publish = async () => {
    const name = publishName.trim();
    if (!name) {
      setPublishState({ tone: "warn", text: "A rule name is required." });
      return;
    }
    setPublishState({ tone: "muted", text: "Publishing…" });
    const reply = await ipc.http("control", "POST", "/api/v1/rules", {
      name,
      content: source,
      changelog: "Published from Olopa Command",
    });
    setPublishState(
      reply.ok
        ? { tone: "ok", text: `Published “${name}” — the control plane recompiled and stored v1.` }
        : { tone: "danger", text: reply.error ?? `HTTP ${reply.status}` },
    );
  };

  return (
    <div className="space-y-3">
      <PageHead
        title="OIL Studio"
        subtitle="The compiler is linked into Command — this compiles locally, with no server and no oilc binary."
        actions={
          <div className="flex items-center gap-2">
            {report && (
              <Chip tone={report.ok ? "ok" : "danger"}>
                {report.ok
                  ? `compiles · ${report.token_count} tokens`
                  : `${errorCount} error${errorCount === 1 ? "" : "s"}`}
              </Chip>
            )}
            <Button onClick={() => navigate("/simulator")} disabled={!report?.ok}>
              <Layers className="h-3 w-3" />
              Simulate
            </Button>
            <Button variant="primary" onClick={() => void compile(source)} disabled={compiling}>
              <Play className="h-3 w-3" />
              {compiling ? "Compiling…" : "Compile"}
            </Button>
          </div>
        }
      />

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="space-y-3">
          <OilEditor
            value={source}
            onChange={setSource}
            errorLines={errorLines}
            warnLines={warnLines}
            className="h-[30rem]"
          />

          <Panel>
            <PanelHead title="Publish to registry" hint="POST /api/v1/rules on the control plane" />
            <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
              <Input
                value={publishName}
                onChange={(event) => setPublishName(event.target.value)}
                placeholder="rule name"
                className="max-w-56"
              />
              <Button onClick={() => void publish()} disabled={!report?.ok}>
                <Upload className="h-3 w-3" />
                Publish
              </Button>
              {!report?.ok && (
                <span className="text-[11px] text-fg-muted">
                  Only a rule that compiles can be published.
                </span>
              )}
            </div>
            {publishState && (
              <div className="px-3 pb-2.5">
                <Notice tone={publishState.tone}>{publishState.text}</Notice>
              </div>
            )}
          </Panel>
        </div>

        <Panel className="flex h-[30rem] flex-col overflow-hidden">
          <PanelHead
            title="Compiler output"
            actions={
              <Tabs
                items={[
                  {
                    value: "diagnostics",
                    label: "Diagnostics",
                    hint: diagnostics.length || "",
                  },
                  { value: "plan", label: "Plan", hint: report?.plans.length || "" },
                  { value: "ir", label: "Runtime IR" },
                  { value: "ast", label: "AST" },
                  { value: "mir", label: "MIR" },
                ]}
                value={tab}
                onChange={setTab}
              />
            }
          />

          <div className="min-h-0 flex-1 overflow-auto">
            {tab === "diagnostics" &&
              (diagnostics.length === 0 ? (
                <div className="flex items-center gap-2 px-3 py-4 text-[11px] text-ok">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  {report?.ok
                    ? "Compiles cleanly — no diagnostics."
                    : "Waiting for the first compile…"}
                </div>
              ) : (
                <ul>
                  {diagnostics.map((diagnostic, index) => (
                    <DiagnosticRow key={index} diagnostic={diagnostic} />
                  ))}
                </ul>
              ))}

            {tab === "plan" &&
              (report?.plans.length ? (
                report.plans.map((plan) => <PlanView key={plan.id} plan={plan} />)
              ) : (
                <div className="px-3 py-4 text-[11px] text-fg-muted">
                  No execution plan — the rule must compile to runtime IR first.
                </div>
              ))}

            {tab === "ir" && <Json value={report?.runtime_ir ?? null} />}
            {tab === "ast" && <Code content={report?.ast ?? ""} empty="no AST produced" />}
            {tab === "mir" && <Code content={report?.mir ?? ""} empty="no MIR produced" />}
          </div>
        </Panel>
      </div>
    </div>
  );
}
