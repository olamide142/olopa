import { useState } from "react";
import { RefreshCw, Rocket, Undo2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/empty-state";
import { useDeployments } from "@/hooks/useDeployments";
import { DEPLOYMENT_STATUSES, deploymentsApi, errorMessage, type Deployment } from "@/lib/api";
import { cn, relativeAge } from "@/lib/utils";

const STATUS_TONES: Record<string, "success" | "warning" | "danger" | "muted" | "default"> = {
  active: "success",
  deploying: "default",
  pending: "muted",
  rolled_back: "warning",
  failed: "danger",
};

function timestampMs(iso: string | null): number | undefined {
  if (!iso) return undefined;
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Deployment history with the one-call rollback the control plane exposes. */
export function DeploymentsPanel() {
  const [environment, setEnvironment] = useState("");
  const [status, setStatus] = useState("");
  const { deployments, loading, error, refresh } = useDeployments({
    environment: environment || undefined,
    status: status || undefined,
  });

  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const rollback = async (deployment: Deployment) => {
    setBusyId(deployment.id);
    setActionError(null);
    try {
      await deploymentsApi.rollback(deployment.id);
      await refresh();
    } catch (err) {
      setActionError(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-lg font-semibold">Deployments</h1>
          <p className="text-xs text-muted-foreground">
            {loading
              ? "loading…"
              : `${deployments.length} deployment${deployments.length === 1 ? "" : "s"}`}
          </p>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <Input
            className="h-9 w-36"
            placeholder="environment"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          />
          <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
            <option value="">all statuses</option>
            {DEPLOYMENT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
          <Button size="sm" variant="outline" onClick={() => void refresh()} disabled={loading}>
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{error}</div>
      )}
      {actionError && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
          {actionError}
        </div>
      )}

      <Card className="overflow-hidden p-0">
        {deployments.length === 0 && !loading ? (
          <EmptyState
            icon={Rocket}
            title="No deployments"
            description="Deploy a rule version from the Rules panel or straight from the OIL editor."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border bg-muted/40 text-left text-[10px] uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Deployment</th>
                  <th className="px-3 py-2 font-medium">Environment</th>
                  <th className="px-3 py-2 font-medium">Version</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Strategy</th>
                  <th className="px-3 py-2 font-medium">Updated</th>
                  <th className="px-3 py-2 font-medium">By</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {deployments.map((d) => (
                  <tr key={d.id} className="hover:bg-accent/40">
                    <td className="px-3 py-2 font-mono text-xs" title={d.id}>
                      {d.id.slice(0, 8)}
                    </td>
                    <td className="px-3 py-2 text-xs">{d.environment}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground" title={d.rule_version_id}>
                      {d.rule_version_id.slice(0, 8)}
                    </td>
                    <td className="px-3 py-2">
                      <Badge tone={STATUS_TONES[d.status] ?? "muted"}>{d.status}</Badge>
                    </td>
                    <td className="px-3 py-2 text-xs">{d.strategy}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {relativeAge(timestampMs(d.updated_at ?? d.created_at))}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{d.created_by}</td>
                    <td className="px-3 py-2 text-right">
                      {d.status === "active" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void rollback(d)}
                          disabled={busyId === d.id}
                        >
                          <Undo2 className="h-3.5 w-3.5" />
                          {busyId === d.id ? "Rolling back…" : "Roll back"}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
