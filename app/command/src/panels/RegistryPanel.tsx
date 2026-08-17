import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Boxes, FileCode2, RefreshCw, Rocket, Undo2 } from "lucide-react";
import {
  Button,
  Chip,
  Code,
  Empty,
  Field,
  Json,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Select,
  Tabs,
  Td,
  Th,
  type Tone,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc } from "@/lib/ipc";
import { since } from "@/lib/format";
import { useOil } from "@/state/oil";

interface RuleVersion {
  id: string;
  rule_id: string;
  version: number;
  content: string;
  content_hash: string;
  author: string;
  changelog: string | null;
  compiled_ir: unknown;
  created_at: string | null;
}

interface Rule {
  id: string;
  name: string;
  description: string | null;
  owner: string;
  updated_at: string | null;
  version_count: number;
  latest_version: RuleVersion | null;
}

interface Deployment {
  id: string;
  environment: string;
  rule_version_id: string;
  status: string;
  strategy: string;
  created_by: string;
  updated_at: string | null;
  created_at: string | null;
}

const STATUS_TONE: Record<string, Tone> = {
  active: "ok",
  deploying: "info",
  pending: "muted",
  rolled_back: "warn",
  failed: "danger",
};

const ENVIRONMENTS = ["production", "staging", "canary"];

function timestamp(iso: string | null): number | undefined {
  if (!iso) return undefined;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function RegistryPanel() {
  const navigate = useNavigate();
  const { setSource } = useOil();
  const [selected, setSelected] = useState<Rule | null>(null);
  const [tab, setTab] = useState<"source" | "ir">("source");
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [action, setAction] = useState<{ tone: Tone; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const rules = usePolling(() => ipc.http<Rule[]>("control", "GET", "/api/v1/rules"), 0);
  const deployments = usePolling(
    () => ipc.http<Deployment[]>("control", "GET", "/api/v1/deployments"),
    0,
  );

  const ruleList = useMemo(() => rules.data?.body ?? [], [rules.data]);
  const deploymentList = useMemo(() => deployments.data?.body ?? [], [deployments.data]);
  const active = selected ?? ruleList[0] ?? null;
  const version = active?.latest_version ?? null;

  const refreshAll = useCallback(() => {
    void rules.refresh();
    void deployments.refresh();
  }, [rules, deployments]);

  const deploy = async () => {
    if (!version) return;
    setBusy(true);
    setAction(null);
    const reply = await ipc.http<Deployment>("control", "POST", "/api/v1/deployments", {
      rule_version_id: version.id,
      environment,
      strategy: "direct",
    });
    setAction(
      reply.ok && reply.body
        ? { tone: "ok", text: `Deployment ${reply.body.id.slice(0, 8)} is ${reply.body.status}.` }
        : { tone: "danger", text: reply.error ?? `HTTP ${reply.status}` },
    );
    setBusy(false);
    void deployments.refresh();
  };

  const rollback = async (deployment: Deployment) => {
    setBusy(true);
    setAction(null);
    const reply = await ipc.http<Deployment>(
      "control",
      "POST",
      `/api/v1/deployments/${deployment.id}/rollback`,
    );
    setAction(
      reply.ok
        ? { tone: "warn", text: `Deployment ${deployment.id.slice(0, 8)} rolled back.` }
        : { tone: "danger", text: reply.error ?? `HTTP ${reply.status}` },
    );
    setBusy(false);
    void deployments.refresh();
  };

  const transportError = rules.data?.error ?? deployments.data?.error;

  return (
    <div className="space-y-3">
      <PageHead
        title="OIL Registry"
        subtitle="Rules and deployments held by the control plane — the fleet's source of truth, read from this workstation."
        actions={
          <Button onClick={refreshAll}>
            <RefreshCw className="h-3 w-3" />
            Refresh
          </Button>
        }
      />

      {transportError && <Notice tone="danger">{transportError}</Notice>}
      {action && <Notice tone={action.tone}>{action.text}</Notice>}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel className="overflow-hidden">
          <PanelHead title="Rules" hint={`${ruleList.length} in tenant`} />
          {ruleList.length === 0 ? (
            <Empty
              icon={Boxes}
              title="No rules"
              detail="Nothing is registered, or the control plane is unreachable. Publish one from Studio."
            />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              {ruleList.map((rule) => (
                <button
                  key={rule.id}
                  type="button"
                  onClick={() => setSelected(rule)}
                  className={
                    "w-full border-b border-border/40 px-3 py-2 text-left transition-colors hover:bg-surface-2 " +
                    (active?.id === rule.id ? "bg-surface-2" : "")
                  }
                >
                  <div className="flex items-center gap-2">
                    <span className="truncate font-mono text-[11px] text-fg">{rule.name}</span>
                    <Chip tone="muted" className="ml-auto">
                      v{rule.version_count}
                    </Chip>
                  </div>
                  <p className="truncate text-[10px] text-fg-faint">
                    {rule.owner} · {since(timestamp(rule.updated_at))}
                  </p>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="lg:col-span-2">
          <PanelHead
            title={active ? active.name : "Rule"}
            hint={
              version
                ? `v${version.version} · sha ${version.content_hash.slice(0, 12)} · ${version.author}`
                : "select a rule"
            }
            actions={
              <>
                <Tabs
                  items={[
                    { value: "source", label: "Source" },
                    { value: "ir", label: "Runtime IR" },
                  ]}
                  value={tab}
                  onChange={setTab}
                />
                <Button
                  size="xs"
                  onClick={() => {
                    if (version) {
                      setSource(version.content);
                      navigate("/studio");
                    }
                  }}
                  disabled={!version}
                >
                  <FileCode2 className="h-3 w-3" />
                  Edit locally
                </Button>
              </>
            }
          />
          {!version ? (
            <Empty icon={FileCode2} title="No version selected" />
          ) : tab === "source" ? (
            <Code content={version.content} className="max-h-72" />
          ) : (
            <Json value={version.compiled_ir} className="max-h-72" />
          )}

          {version && (
            <div className="flex flex-wrap items-center gap-2 border-t border-border px-3 py-2.5">
              <Select value={environment} onChange={(event) => setEnvironment(event.target.value)}>
                {ENVIRONMENTS.map((env) => (
                  <option key={env} value={env}>
                    {env}
                  </option>
                ))}
              </Select>
              <Button variant="primary" onClick={() => void deploy()} disabled={busy}>
                <Rocket className="h-3 w-3" />
                Deploy v{version.version}
              </Button>
              <span className="text-[10px] text-fg-faint">
                The control plane records the deployment; delivery to hosts is out of band today.
              </span>
            </div>
          )}
        </Panel>
      </div>

      <Panel>
        <PanelHead title="Deployments" hint={`${deploymentList.length} recorded`} />
        {deploymentList.length === 0 ? (
          <Empty icon={Rocket} title="No deployments" detail="Deploy a version to see it here." />
        ) : (
          <div className="max-h-72 overflow-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th className="w-24">ID</Th>
                  <Th className="w-28">Environment</Th>
                  <Th className="w-24">Version</Th>
                  <Th className="w-24">Status</Th>
                  <Th className="w-24">Strategy</Th>
                  <Th className="w-28">Updated</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {deploymentList.map((deployment) => (
                  <tr key={deployment.id} className="border-b border-border/40">
                    <Td className="font-mono text-fg-faint" title={deployment.id}>
                      {deployment.id.slice(0, 8)}
                    </Td>
                    <Td className="text-fg">{deployment.environment}</Td>
                    <Td className="font-mono text-fg-faint" title={deployment.rule_version_id}>
                      {deployment.rule_version_id.slice(0, 8)}
                    </Td>
                    <Td>
                      <Chip tone={STATUS_TONE[deployment.status] ?? "muted"}>
                        {deployment.status}
                      </Chip>
                    </Td>
                    <Td className="text-fg-muted">{deployment.strategy}</Td>
                    <Td className="text-fg-faint">
                      {since(timestamp(deployment.updated_at ?? deployment.created_at))}
                    </Td>
                    <Td className="text-right">
                      {deployment.status === "active" && (
                        <Button size="xs" onClick={() => void rollback(deployment)} disabled={busy}>
                          <Undo2 className="h-3 w-3" />
                          Roll back
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {active && (
        <Panel>
          <PanelHead title="Rule metadata" />
          <div className="grid gap-x-8 px-3 py-2 md:grid-cols-3">
            <Field label="Rule ID" value={active.id} />
            <Field label="Owner" value={active.owner} />
            <Field label="Versions" value={active.version_count} />
            <Field label="Description" value={active.description || "—"} mono={false} />
            <Field label="Changelog" value={version?.changelog || "—"} mono={false} />
            <Field label="Created" value={since(timestamp(version?.created_at ?? null))} />
          </div>
        </Panel>
      )}
    </div>
  );
}
