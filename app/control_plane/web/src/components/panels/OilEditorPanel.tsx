import { useMemo, useState } from "react";
import { CheckCircle2, FlaskConical, PlayCircle, Rocket, Save, ShieldCheck } from "lucide-react";
import { OilEditor } from "@/components/rules/OilEditor";
import { FixtureEditor, newFixture } from "@/components/rules/FixtureEditor";
import { DiagnosticsList } from "@/components/rules/DiagnosticsList";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input, Select } from "@/components/ui/input";
import { JsonBlock } from "@/components/ui/code-block";
import { Tabs } from "@/components/ui/tabs";
import { useRules } from "@/hooks/useRules";
import {
  deploymentsApi,
  errorMessage,
  rulesApi,
  type DeploymentStrategy,
  type DiagnosticItem,
  type RuleTestFixture,
  type TestRuleResponse,
  type ValidateRuleResponse,
} from "@/lib/api";
import { STARTER_RULE, countErrors, extractRuleName } from "@/lib/oil";

type OutputTab = "diagnostics" | "runtime-ir" | "test";

const ENVIRONMENTS = ["production", "staging", "canary"];
const STRATEGIES: DeploymentStrategy[] = ["direct", "canary"];

interface SavedVersion {
  id: string;
  ruleId: string;
  ruleName: string;
  version: number;
}

/**
 * Author-to-deploy surface for OIL rules: edit, validate against the compiler,
 * exercise fixtures, persist an immutable version, then deploy that version.
 */
export function OilEditorPanel() {
  const { rules, refresh: refreshRules } = useRules();

  const [source, setSource] = useState(STARTER_RULE);
  const [tab, setTab] = useState<OutputTab>("diagnostics");

  const [validation, setValidation] = useState<ValidateRuleResponse | null>(null);
  const [validating, setValidating] = useState(false);

  const [fixtures, setFixtures] = useState<RuleTestFixture[]>([newFixture()]);
  const [testResult, setTestResult] = useState<TestRuleResponse | null>(null);
  const [testing, setTesting] = useState(false);

  const [targetRuleId, setTargetRuleId] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [description, setDescription] = useState("");
  const [changelog, setChangelog] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<SavedVersion | null>(null);

  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [strategy, setStrategy] = useState<DeploymentStrategy>("direct");
  const [deploying, setDeploying] = useState(false);
  const [deployedId, setDeployedId] = useState<string | null>(null);

  const [error, setError] = useState<string | null>(null);

  const diagnostics: DiagnosticItem[] = validation?.diagnostics ?? [];
  const errorLines = useMemo(
    () =>
      diagnostics
        .filter((d) => d.severity.toLowerCase() === "error" && typeof d.line === "number")
        .map((d) => d.line as number),
    [diagnostics],
  );
  const matchedIndices = useMemo(
    () => new Set((testResult?.matches ?? []).map((m) => m.fixture_index)),
    [testResult],
  );

  // Any edit invalidates the compile result the save/deploy actions depend on.
  const onSourceChange = (next: string) => {
    setSource(next);
    setValidation(null);
    setTestResult(null);
    setSaved(null);
    setDeployedId(null);
    setError(null);
  };

  const runValidate = async () => {
    setValidating(true);
    setError(null);
    try {
      const { data } = await rulesApi.validate(source);
      setValidation(data);
      setTab("diagnostics");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setValidating(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setError(null);
    try {
      const { data } = await rulesApi.test(source, fixtures);
      setTestResult(data);
      setTab("test");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setTesting(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      if (targetRuleId) {
        const rule = rules.find((r) => r.id === targetRuleId);
        const { data } = await rulesApi.createVersion(targetRuleId, {
          content: source,
          changelog: changelog || "Updated rule logic",
        });
        setSaved({
          id: data.id,
          ruleId: data.rule_id,
          ruleName: rule?.name ?? data.rule_id,
          version: data.version,
        });
      } else {
        const name = ruleName.trim() || extractRuleName(source) || "";
        if (!name) {
          setError("A rule name is required to create a new rule.");
          return;
        }
        const { data } = await rulesApi.create({
          name,
          description: description.trim() || null,
          content: source,
          changelog: changelog || "Initial rule version",
        });
        if (!data.latest_version) {
          setError("Rule was created but the API returned no version to deploy.");
          return;
        }
        setSaved({
          id: data.latest_version.id,
          ruleId: data.id,
          ruleName: data.name,
          version: data.latest_version.version,
        });
      }
      setDeployedId(null);
      await refreshRules();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const deploy = async () => {
    if (!saved) return;
    setDeploying(true);
    setError(null);
    try {
      const { data } = await deploymentsApi.create({
        rule_version_id: saved.id,
        environment,
        strategy,
      });
      setDeployedId(data.id);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setDeploying(false);
    }
  };

  const errorCount = countErrors(diagnostics);
  const compiles = validation?.valid === true;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-lg font-semibold">OIL Editor</h1>
          <p className="text-xs text-muted-foreground">
            Author a detection, compile it through <span className="font-mono">oilc</span>, then persist and
            deploy the version.
          </p>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {validation && (
            <Badge tone={compiles ? "success" : "danger"}>
              {compiles ? "compiles" : `${errorCount} error${errorCount === 1 ? "" : "s"}`}
            </Badge>
          )}
          <Button size="sm" variant="outline" onClick={() => void runTest()} disabled={testing}>
            <FlaskConical className="h-3.5 w-3.5" />
            {testing ? "Testing…" : "Test"}
          </Button>
          <Button size="sm" variant="primary" onClick={() => void runValidate()} disabled={validating}>
            <PlayCircle className="h-3.5 w-3.5" />
            {validating ? "Validating…" : "Validate"}
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <OilEditor value={source} onChange={onSourceChange} errorLines={errorLines} className="h-[26rem]" />

          <Card>
            <CardHeader>
              <CardTitle>Save version</CardTitle>
              {saved && (
                <Badge tone="success">
                  {saved.ruleName} · v{saved.version}
                </Badge>
              )}
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-2 sm:grid-cols-2">
                <Select
                  value={targetRuleId}
                  onChange={(e) => setTargetRuleId(e.target.value)}
                  aria-label="Target rule"
                >
                  <option value="">New rule…</option>
                  {rules.map((rule) => (
                    <option key={rule.id} value={rule.id}>
                      {rule.name} (v{rule.version_count})
                    </option>
                  ))}
                </Select>
                <Input
                  placeholder="Changelog"
                  value={changelog}
                  onChange={(e) => setChangelog(e.target.value)}
                />
                {!targetRuleId && (
                  <>
                    <Input
                      placeholder={extractRuleName(source) ?? "Rule name"}
                      value={ruleName}
                      onChange={(e) => setRuleName(e.target.value)}
                    />
                    <Input
                      placeholder="Description (optional)"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={() => void save()} disabled={saving}>
                  <Save className="h-3.5 w-3.5" />
                  {saving ? "Saving…" : targetRuleId ? "Save new version" : "Create rule"}
                </Button>
                <p className="text-xs text-muted-foreground">
                  The control plane recompiles on save and rejects rules without deployable runtime IR.
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Deploy</CardTitle>
              {deployedId && <Badge tone="success">active</Badge>}
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <Select value={environment} onChange={(e) => setEnvironment(e.target.value)} aria-label="Environment">
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
                <Button size="sm" variant="primary" onClick={() => void deploy()} disabled={!saved || deploying}>
                  <Rocket className="h-3.5 w-3.5" />
                  {deploying ? "Deploying…" : "Deploy version"}
                </Button>
              </div>
              {!saved && (
                <p className="text-xs text-muted-foreground">Save a version first — deployments reference a version ID.</p>
              )}
              {deployedId && (
                <p className="flex items-center gap-1.5 text-xs text-success">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Deployment <span className="font-mono">{deployedId.slice(0, 8)}</span> is active in {environment}.
                </p>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Tabs
            items={[
              { value: "diagnostics", label: "Diagnostics", hint: diagnostics.length ? String(diagnostics.length) : undefined },
              { value: "runtime-ir", label: "Runtime IR" },
              { value: "test", label: "Fixtures", hint: String(fixtures.length) },
            ]}
            value={tab}
            onChange={setTab}
            className="w-full"
          />

          {tab === "diagnostics" && (
            <Card>
              <CardContent className="pt-4">
                {validation ? (
                  <DiagnosticsList diagnostics={diagnostics} emptyLabel="Compiles cleanly — no diagnostics." />
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Run <span className="font-medium">Validate</span> to compile this source and see diagnostics.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {tab === "runtime-ir" && (
            <Card>
              <CardContent className="pt-4">
                <JsonBlock
                  value={validation?.compiled_ir ?? null}
                  emptyLabel="No runtime IR yet — validate a rule that compiles."
                />
              </CardContent>
            </Card>
          )}

          {tab === "test" && (
            <Card>
              <CardContent className="space-y-3 pt-4">
                {testResult && (
                  <div className="flex items-center gap-2 text-xs">
                    <ShieldCheck className={testResult.matched ? "h-4 w-4 text-success" : "h-4 w-4 text-muted-foreground"} />
                    <span>
                      {testResult.match_count} of {fixtures.length} fixture
                      {fixtures.length === 1 ? "" : "s"} matched
                    </span>
                  </div>
                )}
                <FixtureEditor fixtures={fixtures} onChange={setFixtures} matchedIndices={matchedIndices} />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
