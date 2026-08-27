import { X } from "lucide-react";
import { cn } from "@/lib/format";
import type { Tone } from "@/components/ui/primitives";

export interface Toast {
  id: string;
  tone: Tone;
  title: string;
  detail?: string;
}

const BORDER: Partial<Record<Tone, string>> = {
  ok: "border-ok/40",
  warn: "border-warn/40",
  danger: "border-danger/40",
  info: "border-info/40",
};

const TEXT: Partial<Record<Tone, string>> = {
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  info: "text-info",
};

/** Transient results for actions the operator triggered explicitly. */
export function Toasts({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-10 right-3 z-40 flex w-80 flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={cn(
            "pointer-events-auto rounded-md border bg-surface p-2.5 shadow-xl",
            BORDER[toast.tone] ?? "border-border-strong",
          )}
        >
          <div className="flex items-start gap-2">
            <div className="min-w-0 flex-1">
              <p className={cn("text-[11px] font-semibold", TEXT[toast.tone] ?? "text-fg")}>
                {toast.title}
              </p>
              {toast.detail && (
                <p className="selectable mt-0.5 max-h-24 overflow-y-auto whitespace-pre-wrap break-words font-mono text-[10px] leading-relaxed text-fg-muted">
                  {toast.detail}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="text-fg-faint transition-colors hover:text-fg"
              aria-label="Dismiss"
            >
              <X className="h-3 w-3" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
