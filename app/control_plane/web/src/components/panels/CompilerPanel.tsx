import { useMemo, useState } from "react";
import { Cpu, Terminal } from "lucide-react";
import { OilEditor } from "@/components/rules/OilEditor";
import { DiagnosticsList } from "@/components/rules/DiagnosticsList";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { CodeBlock, JsonBlock } from "@/components/ui/code-block";
import { Tabs } from "@/components/ui/tabs";
import {
  COMPILER_MODES,
  compilerApi,
  errorMessage,
  type CompileResponse,
  type CompilerMode,
} from "@/lib/api";
import { STARTER_RULE, extractCompilerDiagnostics, type CompilerReport } from "@/lib/oil";

type OutputTab = "diagnostics" | "artifact" | "stdout" | "stderr";

/**
 * Direct access to the server-side `oilc` pipeline via
 * POST /api/v1/control/compiler/compile — the same compiler the rules API uses,
 * but with every stage output exposed for debugging a rule.
 */
export function CompilerPanel() {
  const [source, setSource] = useState(STARTER_RULE);
  const [mode, setMode] = useState<CompilerMode>("runtime-ir");
  const [result, setResult] = useState<CompileResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<OutputTab>("diagnostics");

  const diagnostics = useMemo(
    () => extractCompilerDiagnostics((result?.stdout_json as CompilerReport | null) ?? null, source),
    [result, source],
  );
  const errorLines = useMemo(
    () =>
      diagnostics
        .filter((d) => d.severity === "error" && typeof d.line === "number")
        .map((d) => d.line as number),
    [diagnostics],
  );

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      const { data } = await compilerApi.compile(source, mode);
      setResult(data);
      setTab(data.ok && data.runtime_ir ? "artifact" : "diagnostics");
    } catch (err) {
      setResult(null);
      setError(errorMessage(err));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-lg font-semibold">Compiler</h1>
          <p className="text-xs text-muted-foreground">
            Run the <span className="font-mono">oilc</span> pipeline server-side and inspect every stage.
          </p>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {result && (
            <Badge tone={result.ok ? "success" : "danger"}>
              exit {result.exit_code}
            </Badge>
          )}
          <Select value={mode} onChange={(e) => setMode(e.target.value as CompilerMode)} aria-label="Compiler mode">
            {COMPILER_MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </Select>
          <Button size="sm" variant="primary" onClick={() => void run()} disabled={running}>
            <Cpu className="h-3.5 w-3.5" />
            {running ? "Compiling…" : "Compile"}
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <OilEditor value={source} onChange={setSource} errorLines={errorLines} className="h-[30rem]" />

        <div className="space-y-3">
          <Tabs
            items={[
              {
                value: "diagnostics",
                label: "Diagnostics",
                hint: diagnostics.length ? String(diagnostics.length) : undefined,
              },
              { value: "artifact", label: "Runtime IR" },
              { value: "stdout", label: "stdout" },
              { value: "stderr", label: "stderr" },
            ]}
            value={tab}
            onChange={setTab}
          />

          <Card>
            <CardContent className="pt-4">
              {!result && (
                <p className="text-xs text-muted-foreground">
                  Compile to see diagnostics, the runtime-IR artifact and raw compiler output.
                </p>
              )}

              {result && tab === "diagnostics" && (
                <DiagnosticsList
                  diagnostics={diagnostics}
                  emptyLabel={
                    result.stdout_json
                      ? "No diagnostics reported."
                      : "Compiler returned no JSON report for this mode — see stdout."
                  }
                />
              )}
              {result && tab === "artifact" && (
                <JsonBlock
                  value={result.runtime_ir}
                  emptyLabel="No artifact — only the runtime-ir mode emits one, and only on success."
                />
              )}
              {result && tab === "stdout" && <CodeBlock content={result.stdout} emptyLabel="stdout was empty" />}
              {result && tab === "stderr" && <CodeBlock content={result.stderr} emptyLabel="stderr was empty" />}
            </CardContent>
          </Card>

          {result && (
            <div className="flex items-start gap-2 rounded-md border border-border bg-muted/30 px-2.5 py-2">
              <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <code className="min-w-0 flex-1 break-all font-mono text-[10px] text-muted-foreground">
                {result.command.join(" ")}
              </code>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
