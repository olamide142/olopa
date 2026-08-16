import { useEffect, useState } from "react";
import { FileCode2, RefreshCw, Rocket } from "lucide-react";
import { DiagnosticsList } from "@/components/rules/DiagnosticsList";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { CodeBlock, JsonBlock } from "@/components/ui/code-block";
import { EmptyState } from "@/components/ui/empty-state";
import { Tabs } from "@/components/ui/tabs";
import { useRules } from "@/hooks/useRules";
import {
  deploymentsApi,
  errorMessage,
  rulesApi,
  type DeploymentStrategy,
  type Rule,
  type RuleVersion,
} from "@/lib/api";
import { cn, relativeAge } from "@/lib/utils";

type DetailTab = "source" | "ir" | "diagnostics";

const ENVIRONMENTS = ["production", "staging", "canary"];
const STRATEGIES: DeploymentStrategy[] = ["direct", "canary"];

function timestampMs(iso: string | null): number | undefined {
  if (!iso) return undefined;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Registry of persisted rules with immutable version history and deploy actions. */
export function RulesPanel() {
  const { rules, loading, error, refresh } = useRules();
  const [selected, setSelected] = useState<Rule | null>(null);
  const [version, setVersion] = useState<RuleVersion | null>(null);
  const [versionNumber, setVersionNumber] = useState<number | null>(null);
  const [tab, setTab] = useState<DetailTab>("source");

  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [strategy, setStrategy] = useState<DeploymentStrategy>("direct");
  const [deploying, setDeploying] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Default the selection to the most recently updated rule.
  useEffect(() => {
    if (!selected && rules.length > 0) {
      setSelected(rules[0]);
      setVersion(rules[0].latest_version);
      setVersionNumber(rules[0].latest_version?.version ?? null);
    }
  }, [rules, selected]);

  const selectRule = (rule: Rule) => {
    setSelected(rule);
    setVersion(rule.latest_version);
    setVersionNumber(rule.latest_version?.version ?? null);
    setNotice(null);
    setActionError(null);
  };

  const loadVersion = async (next: number) => {
    if (!selected) return;
    setVersionNumber(next);
    setActionError(null);
    try {
      const { data } = await rulesApi.getVersion(selected.id, next);
      setVersion(data);
    } catch (err) {
      setActionError(errorMessage(err));
    }
  };

  const deploy = async () => {
    if (!version) return;
    setDeploying(true);
    setNotice(null);
    setActionError(null);
    try {
      const { data } = await deploymentsApi.create({
        rule_version_id: version.id,
        environment,
        strategy,
      });
      setNotice(`Deployment ${data.id.slice(0, 8)} is ${data.status} in ${data.environment}.`);
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-lg font-semibold">Rules</h1>
          <p className="text-xs text-muted-foreground">
            {loading ? "loading registry…" : `${rules.length} rule${rules.length === 1 ? "" : "s"} in this tenant`}
          </p>
        </div>
        <Button size="sm" variant="outline" className="ml-auto" onClick={() => void refresh()} disabled={loading}>
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {error && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>
      )}

      {!loading && !error && rules.length === 0 ? (
        <Card>
          <EmptyState
            icon={FileCode2}
            title="No rules yet"
            description="Author a rule in the OIL editor and save it — the control plane compiles it and stores version 1."
          />
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <Card className="overflow-hidden lg:col-span-1">
            <ul className="divide-y divide-border">
              {rules.map((rule) => (
                <li key={rule.id}>
                  <button
                    type="button"
                    onClick={() => selectRule(rule)}
                    className={cn(
                      "w-full px-3 py-2.5 text-left transition-colors hover:bg-accent",
                      selected?.id === rule.id && "bg-primary/10",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium">{rule.name}</span>
                      <Badge tone="muted" className="ml-auto shrink-0">
                        v{rule.version_count}
                      </Badge>
                    </div>
                    <p className="mt-0.5 truncate text-xs text-muted-foreground">
                      {rule.description || rule.owner} · {relativeAge(timestampMs(rule.updated_at))}
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          </Card>

          <div className="space-y-3 lg:col-span-2">
            {selected && (
              <Card>
                <CardHeader>
                  <CardTitle>{selected.name}</CardTitle>
                  <div className="flex items-center gap-2">
                    <Select
                      className="h-8 text-xs"
                      value={versionNumber ?? ""}
                      onChange={(e) => void loadVersion(Number(e.target.value))}
                      aria-label="Rule version"
                    >
                      {Array.from({ length: selected.version_count }, (_, i) => selected.version_count - i).map(
                        (v) => (
                          <option key={v} value={v}>
                            v{v}
                          </option>
                        ),
                      )}
                    </Select>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span>author {version?.author ?? selected.owner}</span>
                    {version?.content_hash && (
                      <span className="font-mono">sha {version.content_hash.slice(0, 12)}</span>
                    )}
                    <span>{relativeAge(timestampMs(version?.created_at ?? selected.created_at))}</span>
                    {version?.changelog && <span className="italic">“{version.changelog}”</span>}
                  </div>

                  <Tabs
                    items={[
                      { value: "source", label: "Source" },
                      { value: "ir", label: "Runtime IR" },
                      {
                        value: "diagnostics",
                        label: "Diagnostics",
                        hint: version?.diagnostics?.length ? String(version.diagnostics.length) : undefined,
                      },
                    ]}
                    value={tab}
                    onChange={setTab}
                  />

                  {tab === "source" && <CodeBlock content={version?.content ?? ""} emptyLabel="No stored source" />}
                  {tab === "ir" && (
                    <JsonBlock value={version?.compiled_ir ?? null} emptyLabel="This version has no compiled IR" />
                  )}
                  {tab === "diagnostics" && (
                    <DiagnosticsList
                      diagnostics={version?.diagnostics ?? []}
                      emptyLabel="Compiled cleanly at save time."
                    />
                  )}
                </CardContent>
              </Card>
            )}

            {selected && (
              <Card>
                <CardHeader>
                  <CardTitle>Deploy version {versionNumber ? `v${versionNumber}` : ""}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Select
                      value={environment}
                      onChange={(e) => setEnvironment(e.target.value)}
                      aria-label="Environment"
                    >
                      {ENVIRONMENTS.map((env) => (
                        <option key={env} value={env}>
                          {env}
                        </option>
                      ))}
                    </Select>
                    <Select
                      value={strategy}
                      onChange={(e) => setStrategy(e.target.value as DeploymentStrategy)}
                      aria-label="Strategy"
                    >
                      {STRATEGIES.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </Select>
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => void deploy()}
                      disabled={deploying || !version?.compiled_ir}
                    >
                      <Rocket className="h-3.5 w-3.5" />
                      {deploying ? "Deploying…" : "Deploy"}
                    </Button>
                  </div>
                  {!version?.compiled_ir && (
                    <p className="text-xs text-muted-foreground">
                      This version has no compiled runtime IR, so the control plane will refuse to deploy it.
                    </p>
                  )}
                  {notice && <p className="text-xs text-success">{notice}</p>}
                  {actionError && <p className="text-xs text-danger">{actionError}</p>}
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
