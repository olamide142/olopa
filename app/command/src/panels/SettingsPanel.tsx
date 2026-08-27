import { useEffect, useState } from "react";
import { Check, Plug, Save } from "lucide-react";
import {
  Button,
  Chip,
  Field,
  Input,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Select,
  type Tone,
} from "@/components/ui/primitives";
import { useSettings } from "@/hooks/useSettings";
import { ipc, type CredentialKind, type Settings } from "@/lib/ipc";

interface ProbeResult {
  tone: Tone;
  text: string;
}

const CREDENTIAL_KINDS: { value: CredentialKind; label: string }[] = [
  { value: "none", label: "None" },
  { value: "bearer", label: "Bearer JWT" },
  { value: "api-key", label: "Service API key" },
  { value: "dev-token", label: "Dev token" },
];

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 border-b border-border/40 px-3 py-2.5 last:border-0 md:grid-cols-[13rem_1fr] md:items-center md:gap-4">
      <div>
        <div className="text-[11px] text-fg">{label}</div>
        {hint && <div className="text-[10px] leading-relaxed text-fg-faint">{hint}</div>}
      </div>
      {children}
    </div>
  );
}

export function SettingsPanel() {
  const { settings, save, saving, error } = useSettings();
  const [draft, setDraft] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [location, setLocation] = useState("");
  const [ingestProbe, setIngestProbe] = useState<ProbeResult | null>(null);
  const [controlProbe, setControlProbe] = useState<ProbeResult | null>(null);

  useEffect(() => {
    if (settings && !draft) setDraft(settings);
  }, [settings, draft]);

  useEffect(() => {
    ipc.settingsLocation().then(setLocation).catch(() => setLocation(""));
  }, []);

  if (!draft) {
    return (
      <div className="space-y-3">
        <PageHead title="Settings" />
        <Notice tone="muted">Loading settings…</Notice>
      </div>
    );
  }

  const patch = (next: Partial<Settings>) => {
    setDraft({ ...draft, ...next });
    setSaved(false);
  };

  const persist = async () => {
    if (await save(draft)) {
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    }
  };

  // Probing uses saved settings, so save before testing a changed endpoint.
  const probeIngest = async () => {
    setIngestProbe({ tone: "muted", text: "probing…" });
    const reply = await ipc.http("ingest", "GET", "/api/v1/ingest/stats");
    setIngestProbe(
      reply.ok
        ? { tone: "ok", text: `reachable in ${reply.latency_ms} ms` }
        : { tone: "danger", text: reply.error ?? `HTTP ${reply.status}` },
    );
  };

  const probeControl = async () => {
    setControlProbe({ tone: "muted", text: "probing…" });
    const reply = await ipc.http<{ user_id: string; tenant_id: string; roles: string[] }>(
      "control",
      "GET",
      "/api/v1/auth/whoami",
    );
    setControlProbe(
      reply.ok && reply.body
        ? {
            tone: "ok",
            text: `${reply.body.user_id} @ ${reply.body.tenant_id} · ${reply.body.roles.join(", ")}`,
          }
        : { tone: "danger", text: reply.error ?? `HTTP ${reply.status}` },
    );
  };

  return (
    <div className="space-y-3">
      <PageHead
        title="Settings"
        subtitle={location ? `Stored at ${location}` : "Local to this workstation"}
        actions={
          <Button variant="primary" onClick={() => void persist()} disabled={saving}>
            {saved ? <Check className="h-3 w-3" /> : <Save className="h-3 w-3" />}
            {saved ? "Saved" : saving ? "Saving…" : "Save"}
          </Button>
        }
      />

      {error && <Notice tone="danger">{error}</Notice>}

      <Panel>
        <PanelHead title="Local agent" hint="paths the agent writes; Command only reads them" />
        <Row
          label="Status snapshot"
          hint="OLOPA_STATUS_PATH on the agent, rewritten every 5 seconds"
        >
          <Input
            value={draft.agent_status_path}
            onChange={(event) => patch({ agent_status_path: event.target.value })}
            className="font-mono"
          />
        </Row>
        <Row label="Secure Connect health" hint="OLOPA_SC_STATUS_PATH">
          <Input
            value={draft.secure_connect_status_path}
            onChange={(event) => patch({ secure_connect_status_path: event.target.value })}
            className="font-mono"
          />
        </Row>
        <Row label="systemd unit" hint="used by the lifecycle actions and the log reader">
          <Input
            value={draft.agent_service_name}
            onChange={(event) => patch({ agent_service_name: event.target.value })}
            className="max-w-xs font-mono"
          />
        </Row>
      </Panel>

      <Panel>
        <PanelHead title="Endpoints" hint="requests are made from Rust, so no CORS is required" />
        <Row label="Ingest server" hint="Rust telemetry hot path">
          <div className="flex items-center gap-2">
            <Input
              value={draft.ingest_base_url}
              onChange={(event) => patch({ ingest_base_url: event.target.value })}
              className="font-mono"
            />
            <Button onClick={() => void probeIngest()}>
              <Plug className="h-3 w-3" />
              Test
            </Button>
          </div>
        </Row>
        {ingestProbe && (
          <div className="px-3 pb-2">
            <Notice tone={ingestProbe.tone}>{ingestProbe.text}</Notice>
          </div>
        )}
        <Row label="Control plane" hint="Python orchestration API">
          <div className="flex items-center gap-2">
            <Input
              value={draft.control_base_url}
              onChange={(event) => patch({ control_base_url: event.target.value })}
              className="font-mono"
            />
            <Button onClick={() => void probeControl()}>
              <Plug className="h-3 w-3" />
              whoami
            </Button>
          </div>
        </Row>
        {controlProbe && (
          <div className="px-3 pb-2">
            <Notice tone={controlProbe.tone}>{controlProbe.text}</Notice>
          </div>
        )}
      </Panel>

      <Panel>
        <PanelHead
          title="Credential"
          hint="exactly one is sent — the control plane rejects ambiguous combinations"
        />
        <Row label="Type">
          <Select
            value={draft.credential_kind}
            onChange={(event) => patch({ credential_kind: event.target.value as CredentialKind })}
            className="max-w-xs"
          >
            {CREDENTIAL_KINDS.map((kind) => (
              <option key={kind.value} value={kind.value}>
                {kind.label}
              </option>
            ))}
          </Select>
        </Row>
        {draft.credential_kind !== "none" && (
          <Row label="Token" hint="held in the Rust process; never handed to page JavaScript">
            <Input
              type="password"
              value={draft.credential_value}
              onChange={(event) => patch({ credential_value: event.target.value })}
              className="max-w-lg font-mono"
            />
          </Row>
        )}
        <Row label="Tenant" hint="sent as x-tenant-id; must match the token's tenant">
          <Input
            value={draft.tenant_id}
            onChange={(event) => patch({ tenant_id: event.target.value })}
            className="max-w-xs font-mono"
            placeholder="optional"
          />
        </Row>
      </Panel>

      <Panel>
        <PanelHead title="About" />
        <div className="grid gap-x-8 px-3 py-2 md:grid-cols-2">
          <Field label="Application" value="Olopa Command" mono={false} />
          <Field label="OIL compiler" value="linked in-process (oilc)" mono={false} />
          <Field label="Settings file" value={location || "—"} />
          <Field
            label="Agent coupling"
            value={<Chip tone="ok">read-only client</Chip>}
            mono={false}
          />
        </div>
      </Panel>
    </div>
  );
}
