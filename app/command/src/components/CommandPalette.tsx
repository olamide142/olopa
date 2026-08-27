import { useEffect, useMemo, useRef, useState } from "react";
import { CornerDownLeft, Search } from "lucide-react";
import { cn } from "@/lib/format";

export interface PaletteAction {
  id: string;
  label: string;
  group: string;
  hint?: string;
  /** Extra words to match against, so "restart" finds "Restart Agent". */
  keywords?: string;
  /** Mutating actions are confirmed once before running. */
  destructive?: boolean;
  run: () => void | Promise<void>;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
}

function score(action: PaletteAction, query: string): number {
  if (!query) return 1;
  const haystack = `${action.label} ${action.group} ${action.keywords ?? ""}`.toLowerCase();
  const needle = query.toLowerCase().trim();
  if (haystack.includes(needle)) return 100 - haystack.indexOf(needle);
  // Fall back to subsequence matching so "rsa" finds "Restart Agent".
  let cursor = 0;
  for (const char of needle) {
    cursor = haystack.indexOf(char, cursor);
    if (cursor === -1) return 0;
    cursor += 1;
  }
  return 1;
}

export function CommandPalette({ open, onClose, actions }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const [confirming, setConfirming] = useState<PaletteAction | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      setConfirming(null);
      // Focus after the dialog paints, or the keystroke that opened it is lost.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const results = useMemo(() => {
    return actions
      .map((action) => ({ action, rank: score(action, query) }))
      .filter((item) => item.rank > 0)
      .sort((a, b) => b.rank - a.rank)
      .slice(0, 40)
      .map((item) => item.action);
  }, [actions, query]);

  useEffect(() => {
    if (cursor >= results.length) setCursor(0);
  }, [results, cursor]);

  if (!open) return null;

  const execute = async (action: PaletteAction) => {
    if (action.destructive && confirming?.id !== action.id) {
      setConfirming(action);
      return;
    }
    onClose();
    await action.run();
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault();
      if (confirming) setConfirming(null);
      else onClose();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setCursor((c) => Math.min(c + 1, results.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const action = results[cursor];
      if (action) void execute(action);
    }
  };

  let lastGroup = "";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[12vh]"
      onMouseDown={onClose}
    >
      <div
        className="w-[34rem] overflow-hidden rounded-lg border border-border-strong bg-surface shadow-2xl"
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="h-3.5 w-3.5 text-fg-faint" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setConfirming(null);
            }}
            placeholder="Run a command…"
            className="h-10 flex-1 bg-transparent text-[13px] text-fg placeholder:text-fg-faint focus:outline-none"
          />
          <kbd className="rounded border border-border-strong px-1 font-mono text-[9px] text-fg-faint">
            ESC
          </kbd>
        </div>

        {confirming && (
          <div className="border-b border-warn/30 bg-warn/10 px-3 py-2 text-[11px] text-warn">
            <span className="font-medium">{confirming.label}</span> changes a privileged daemon.
            Press Enter again to confirm.
          </div>
        )}

        <div className="max-h-[22rem] overflow-y-auto py-1">
          {results.length === 0 && (
            <div className="px-3 py-6 text-center text-[11px] text-fg-faint">
              nothing matches “{query}”
            </div>
          )}
          {results.map((action, index) => {
            const groupChanged = action.group !== lastGroup;
            lastGroup = action.group;
            return (
              <div key={action.id}>
                {groupChanged && (
                  <div className="px-3 pb-0.5 pt-2 text-[9px] font-semibold uppercase tracking-[0.16em] text-fg-faint">
                    {action.group}
                  </div>
                )}
                <button
                  type="button"
                  onMouseEnter={() => setCursor(index)}
                  onClick={() => void execute(action)}
                  className={cn(
                    "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs",
                    index === cursor ? "bg-surface-2 text-fg" : "text-fg-muted",
                  )}
                >
                  <span className={cn(action.destructive && "text-warn")}>{action.label}</span>
                  {action.hint && (
                    <span className="ml-auto font-mono text-[10px] text-fg-faint">
                      {action.hint}
                    </span>
                  )}
                  {index === cursor && (
                    <CornerDownLeft className="h-3 w-3 shrink-0 text-fg-faint" />
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
