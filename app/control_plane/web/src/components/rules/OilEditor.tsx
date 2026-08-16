import { useMemo, useRef, type ChangeEvent, type KeyboardEvent, type UIEvent } from "react";
import { cn } from "@/lib/utils";

interface OilEditorProps {
  value: string;
  onChange: (value: string) => void;
  /** 1-based lines to mark in the gutter, typically from error diagnostics. */
  errorLines?: number[];
  className?: string;
  readOnly?: boolean;
}

const INDENT = "  ";

/**
 * Plain-textarea OIL editor with a synced line-number gutter.
 *
 * Deliberately not a full code editor: the console ships no editor dependency,
 * and authoritative syntax feedback comes from the compiler via /rules/validate
 * rather than from client-side highlighting that could drift from the grammar.
 */
export function OilEditor({ value, onChange, errorLines = [], className, readOnly }: OilEditorProps) {
  const gutterRef = useRef<HTMLDivElement>(null);
  const errorSet = useMemo(() => new Set(errorLines), [errorLines]);
  const lineCount = useMemo(() => value.split("\n").length, [value]);

  // Keep the gutter aligned with the textarea's own scrolling.
  const onScroll = (e: UIEvent<HTMLTextAreaElement>) => {
    if (gutterRef.current) gutterRef.current.scrollTop = e.currentTarget.scrollTop;
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key !== "Tab") return;
    e.preventDefault();
    const target = e.currentTarget;
    const { selectionStart, selectionEnd } = target;
    const next = value.slice(0, selectionStart) + INDENT + value.slice(selectionEnd);
    onChange(next);
    requestAnimationFrame(() => {
      target.selectionStart = target.selectionEnd = selectionStart + INDENT.length;
    });
  };

  return (
    <div className={cn("flex overflow-hidden rounded-md border border-input bg-background", className)}>
      <div
        ref={gutterRef}
        className="w-12 shrink-0 overflow-hidden border-r border-border bg-muted/40 py-3 font-mono text-xs leading-relaxed text-muted-foreground"
        aria-hidden
      >
        {Array.from({ length: lineCount }, (_, i) => i + 1).map((line) => (
          <div
            key={line}
            className={cn(
              "px-2 text-right tabular-nums",
              errorSet.has(line) && "bg-danger/15 font-semibold text-danger",
            )}
          >
            {line}
          </div>
        ))}
      </div>
      <textarea
        value={value}
        onChange={(e: ChangeEvent<HTMLTextAreaElement>) => onChange(e.target.value)}
        onScroll={onScroll}
        onKeyDown={onKeyDown}
        readOnly={readOnly}
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        className="flex-1 resize-none bg-transparent px-3 py-3 font-mono text-xs leading-relaxed focus-visible:outline-none"
        placeholder="Write an OIL rule..."
      />
    </div>
  );
}
