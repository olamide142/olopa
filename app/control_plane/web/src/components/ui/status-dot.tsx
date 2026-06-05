import { cn } from "@/lib/utils";

type Tone = "ok" | "warn" | "down";

const tones: Record<Tone, string> = {
  ok: "bg-success",
  warn: "bg-warning",
  down: "bg-danger",
};

/** A small colored status indicator, optionally pulsing when live. */
export function StatusDot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return (
    <span className="relative inline-flex h-2 w-2">
      {pulse && (
        <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-60", tones[tone])} />
      )}
      <span className={cn("relative inline-flex h-2 w-2 rounded-full", tones[tone])} />
    </span>
  );
}
