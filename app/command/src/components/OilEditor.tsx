import { useMemo, useRef, type KeyboardEvent, type UIEvent } from "react";
import { cn } from "@/lib/format";

const INDENT = "  ";

/**
 * OIL editor: a textarea with a synced gutter.
 *
 * Deliberately not a syntax-highlighting editor. Authoritative feedback comes
 * from the real compiler on every keystroke pause — client-side highlighting
 * would be a second, drifting model of the grammar.
 */
export function OilEditor({
  value,
  onChange,
  errorLines = [],
  warnLines = [],
  className,
}: {
  value: string;
  onChange: (next: string) => void;
  errorLines?: number[];
  warnLines?: number[];
  className?: string;
}) {
  const gutterRef = useRef<HTMLDivElement>(null);
  const errors = useMemo(() => new Set(errorLines), [errorLines]);
  const warns = useMemo(() => new Set(warnLines), [warnLines]);
  const lines = useMemo(() => value.split("\n").length, [value]);

  const onScroll = (event: UIEvent<HTMLTextAreaElement>) => {
    if (gutterRef.current) gutterRef.current.scrollTop = event.currentTarget.scrollTop;
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== "Tab") return;
    event.preventDefault();
    const target = event.currentTarget;
    const { selectionStart, selectionEnd } = target;
    onChange(value.slice(0, selectionStart) + INDENT + value.slice(selectionEnd));
    requestAnimationFrame(() => {
      target.selectionStart = target.selectionEnd = selectionStart + INDENT.length;
    });
  };

  return (
    <div className={cn("flex overflow-hidden rounded-lg border border-border bg-bg", className)}>
      <div
        ref={gutterRef}
        aria-hidden
        className="w-10 shrink-0 overflow-hidden border-r border-border bg-surface py-2 font-mono text-[11px] leading-[1.6] text-fg-faint"
      >
        {Array.from({ length: lines }, (_, i) => i + 1).map((line) => (
          <div
            key={line}
            className={cn(
              "px-1.5 text-right tabular-nums",
              errors.has(line) && "bg-danger/20 font-semibold text-danger",
              !errors.has(line) && warns.has(line) && "bg-warn/15 text-warn",
            )}
          >
            {line}
          </div>
        ))}
      </div>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={onScroll}
        onKeyDown={onKeyDown}
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        placeholder="Write an OIL rule…"
        className="selectable flex-1 resize-none bg-transparent px-2.5 py-2 font-mono text-[11px] leading-[1.6] text-fg placeholder:text-fg-faint focus:outline-none"
      />
    </div>
  );
}
