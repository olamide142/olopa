import { useMemo } from "react";
import { Globe2, RefreshCw, ShieldOff, Wifi } from "lucide-react";
import {
  Button,
  Chip,
  Dot,
  Empty,
  Field,
  Notice,
  Panel,
  PanelHead,
  PageHead,
  Td,
  Th,
  type Tone,
} from "@/components/ui/primitives";
import { usePolling } from "@/hooks/usePolling";
import { ipc } from "@/lib/ipc";
import { bytes, num, sinceUnixSecs } from "@/lib/format";
import { useSystem } from "@/state/system";

interface ScSession {
  id: string;
  device_id: string;
  state: string;
  gateway_id: string;
  assigned_address: string;
  profile_version: number;
  host_id: string | null;
  started_at: string | null;
}

interface ScDevice {
  id: string;
  host_id: string;
  user_id: string | null;
  state: string;
  device_fingerprint: string;
}

interface ScGateway {
  id: string;
  name: string;
  region: string;
  status: string;
  public_endpoint: string;
  capacity: number;
}

/**
 * The endpoint's own access state, which the agent enforces locally, and the
 * orchestrator's fleet view. The local half works with no control plane at all.
 */
const STATE_TONE: Record<string, Tone> = {
  healthy: "ok",
  elevated: "info",
  restricted: "warn",
  quarantined: "danger",
  terminated: "danger",
  connecting: "info",
  enrolling: "info",
  degraded: "warn",
};

export function SecureConnectPanel() {
  const { secureConnect, refresh } = useSystem();
  const health = secureConnect?.snapshot ?? null;

  const sessions = usePolling(
    () => ipc.http<ScSession[]>("control", "GET", "/api/v1/secure-connect/sessions"),
    0,
  );
  const devices = usePolling(
    () => ipc.http<ScDevice[]>("control", "GET", "/api/v1/secure-connect/devices"),
    0,
  );
  const gateways = usePolling(
    () => ipc.http<ScGateway[]>("control", "GET", "/api/v1/secure-connect/gateways"),
    0,
  );

  const sessionList = useMemo(() => sessions.data?.body ?? [], [sessions.data]);
  const deviceList = useMemo(() => devices.data?.body ?? [], [devices.data]);
  const gatewayList = useMemo(() => gateways.data?.body ?? [], [gateways.data]);
  const fleetError = sessions.data?.error;

  const refreshAll = () => {
    refresh();
    void sessions.refresh();
    void devices.refresh();
    void gateways.refresh();
  };

  return (
    <div className="space-y-3">
      <PageHead
        title="Secure Connect"
        subtitle="Kernel evidence on this host drives its network access — the tunnel state below is enforced locally."
        actions={
          <Button onClick={refreshAll}>
            <RefreshCw className="h-3 w-3" />
            Refresh
          </Button>
        }
      />

      {health?.last_error && <Notice tone="warn">{health.last_error}</Notice>}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel>
          <PanelHead
            title="This device"
            hint={secureConnect?.path}
            actions={
              health?.enabled ? (
                <span className="flex items-center gap-1.5">
                  <Dot tone={STATE_TONE[health.state] ?? "muted"} pulse={health.state === "healthy"} />
                  <span className="font-mono text-[10px] uppercase text-fg-muted">
                    {health.state}
                  </span>
                </span>
              ) : null
            }
          />
          {!health?.enabled ? (
            <Empty
              icon={ShieldOff}
              title="Tunnel not enabled"
              detail="No Secure Connect health file is published, so OLOPA_SC_ENABLED is off for this agent."
            />
          ) : (
            <div className="px-3 py-2">
              <Field label="Interface" value={health.interface ?? "—"} />
              <Field label="Session" value={health.session_id?.slice(0, 12) ?? "—"} />
              <Field label="Device" value={health.device_id?.slice(0, 12) ?? "—"} />
              <Field label="Profile version" value={health.profile_version} />
              <Field label="Last handshake" value={sinceUnixSecs(health.last_handshake_unix)} />
              <Field label="Last heartbeat" value={sinceUnixSecs(health.last_heartbeat_unix)} />
              <Field label="Reconnects" value={num(health.reconnect_count)} />
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHead title="Tunnel" hint="counters read from wg" />
          <div className="px-3 py-2">
            <Field label="Sent" value={bytes(health?.bytes_tx ?? 0)} />
            <Field label="Received" value={bytes(health?.bytes_rx ?? 0)} />
            <Field label="Posture reported" value={sinceUnixSecs(health?.posture_updated_unix)} />
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Enforcement latency" hint="how fast access changes take effect" />
          <div className="px-3 py-2">
            <Field
              label="Policy apply"
              value={health ? `${health.policy_apply_ms} ms` : "—"}
              tone="ok"
            />
            <Field
              label="Revoke apply"
              value={health ? `${health.revoke_apply_ms} ms` : "—"}
              tone="warn"
            />
            <Field
              label="Kill switch apply"
              value={health ? `${health.kill_switch_apply_ms} ms` : "—"}
              tone="danger"
            />
            <p className="pt-1.5 text-[10px] leading-relaxed text-fg-faint">
              The kill switch is an nftables policy that drops egress except the tunnel and its
              bypass set; quarantine is the same policy with the tunnel rule removed.
            </p>
          </div>
        </Panel>
      </div>

      {fleetError && (
        <Notice tone="muted">
          Fleet view unavailable: {fleetError}. The device state above is read locally and does not
          need the control plane.
        </Notice>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel>
          <PanelHead title="Sessions" hint={`${sessionList.length} live`} />
          {sessionList.length === 0 ? (
            <Empty icon={Wifi} title="No sessions" detail="No live sessions are recorded for this tenant." />
          ) : (
            <div className="max-h-64 overflow-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <Th className="w-20">Session</Th>
                    <Th className="w-24">State</Th>
                    <Th className="w-28">Address</Th>
                    <Th>Host</Th>
                  </tr>
                </thead>
                <tbody>
                  {sessionList.map((session) => (
                    <tr key={session.id} className="border-b border-border/40">
                      <Td className="font-mono text-fg-faint">{session.id.slice(0, 8)}</Td>
                      <Td>
                        <Chip tone={STATE_TONE[session.state] ?? "muted"}>{session.state}</Chip>
                      </Td>
                      <Td className="font-mono text-fg">{session.assigned_address}</Td>
                      <Td className="truncate font-mono text-fg-muted">
                        {session.host_id ?? session.device_id.slice(0, 12)}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHead title="Gateways" hint={`${gatewayList.length} registered`} />
          {gatewayList.length === 0 ? (
            <Empty icon={Globe2} title="No gateways" detail="No WireGuard gateways are registered." />
          ) : (
            <div className="max-h-64 overflow-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <Th>Name</Th>
                    <Th className="w-24">Region</Th>
                    <Th className="w-24">Status</Th>
                    <Th className="w-20 text-right">Capacity</Th>
                  </tr>
                </thead>
                <tbody>
                  {gatewayList.map((gateway) => (
                    <tr key={gateway.id} className="border-b border-border/40">
                      <Td className="font-mono text-fg">{gateway.name}</Td>
                      <Td className="text-fg-muted">{gateway.region || "—"}</Td>
                      <Td>
                        <Chip tone={gateway.status === "online" ? "ok" : "warn"}>
                          {gateway.status}
                        </Chip>
                      </Td>
                      <Td className="text-right font-mono tabular-nums text-fg-muted">
                        {num(gateway.capacity)}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      {deviceList.length > 0 && (
        <Panel>
          <PanelHead title="Devices" hint={`${deviceList.length} enrolled`} />
          <div className="max-h-56 overflow-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th className="w-24">Device</Th>
                  <Th>Host</Th>
                  <Th className="w-32">User</Th>
                  <Th className="w-24">State</Th>
                </tr>
              </thead>
              <tbody>
                {deviceList.map((device) => (
                  <tr key={device.id} className="border-b border-border/40">
                    <Td className="font-mono text-fg-faint">{device.id.slice(0, 8)}</Td>
                    <Td className="font-mono text-fg">{device.host_id}</Td>
                    <Td className="text-fg-muted">{device.user_id ?? "—"}</Td>
                    <Td>
                      <Chip tone={device.state === "active" ? "ok" : "warn"}>{device.state}</Chip>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
