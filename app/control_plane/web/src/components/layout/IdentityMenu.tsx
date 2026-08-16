import { useEffect, useRef, useState } from "react";
import { KeyRound, LogOut, ShieldCheck, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input, Select } from "@/components/ui/input";
import { useIdentity } from "@/hooks/useIdentity";
import { EMPTY_CREDENTIAL, type CredentialKind } from "@/lib/api";

const KIND_LABELS: Record<Exclude<CredentialKind, "none">, string> = {
  bearer: "Bearer JWT",
  "api-key": "Service API key",
  "dev-token": "Dev token",
};

/**
 * Identity chip plus credential entry.
 *
 * Rule authoring and deployment require analyst/operator roles, so the console
 * needs a credential whenever the control plane runs with auth enabled. Exactly
 * one credential is sent per request — the API rejects ambiguous combinations.
 */
export function IdentityMenu() {
  const { whoami, loading, unauthorized, error, credential, updateCredential } = useIdentity();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<Exclude<CredentialKind, "none">>(
    credential.kind === "none" ? "bearer" : credential.kind,
  );
  const [value, setValue] = useState(credential.value);
  const [tenantId, setTenantId] = useState(credential.tenantId);
  const containerRef = useRef<HTMLDivElement>(null);

  // Dismiss the popover on any outside click.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  const apply = async () => {
    await updateCredential({ kind, value: value.trim(), tenantId: tenantId.trim() });
    setOpen(false);
  };

  const clear = async () => {
    setValue("");
    setTenantId("");
    await updateCredential(EMPTY_CREDENTIAL);
  };

  const label = loading
    ? "checking…"
    : whoami
      ? `${whoami.user_id} · ${whoami.tenant_id}`
      : unauthorized
        ? "Not authenticated"
        : "Identity unavailable";

  return (
    <div className="relative" ref={containerRef}>
      <Button
        size="sm"
        variant={unauthorized ? "outline" : "ghost"}
        onClick={() => setOpen((prev) => !prev)}
        className={unauthorized ? "border-danger/40 text-danger" : undefined}
      >
        {unauthorized ? <ShieldX className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
        <span className="max-w-[16rem] truncate">{label}</span>
      </Button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-2 w-80 space-y-3 rounded-lg border border-border bg-popover p-3 text-popover-foreground shadow-lg">
          <div className="space-y-1">
            <p className="text-xs font-medium">Session</p>
            {whoami ? (
              <div className="flex flex-wrap items-center gap-1.5">
                {whoami.roles.map((role) => (
                  <Badge key={role} tone="default">
                    {role}
                  </Badge>
                ))}
                <Badge tone="muted">{whoami.token_type}</Badge>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">{error ?? "No identity resolved."}</p>
            )}
          </div>

          <div className="space-y-2 border-t border-border pt-3">
            <p className="text-xs font-medium">Credential</p>
            <Select
              className="h-8 w-full text-xs"
              value={kind}
              onChange={(e) => setKind(e.target.value as Exclude<CredentialKind, "none">)}
              aria-label="Credential type"
            >
              {(Object.keys(KIND_LABELS) as Array<keyof typeof KIND_LABELS>).map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </Select>
            <Input
              className="h-8 font-mono text-xs"
              type="password"
              placeholder="token value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <Input
              className="h-8 text-xs"
              placeholder="tenant id (optional)"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
            />
            <div className="flex items-center gap-2">
              <Button size="sm" variant="primary" onClick={() => void apply()} disabled={!value.trim()}>
                <KeyRound className="h-3.5 w-3.5" />
                Use credential
              </Button>
              <Button size="sm" variant="ghost" onClick={() => void clear()}>
                <LogOut className="h-3.5 w-3.5" />
                Clear
              </Button>
            </div>
            <p className="text-[10px] leading-relaxed text-muted-foreground">
              Stored in this browser only. A tenant id is sent as <span className="font-mono">x-tenant-id</span> and
              must match the token's tenant.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
