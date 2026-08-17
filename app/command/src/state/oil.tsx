import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { takeDraft } from "@/lib/draft";

/** Shipped example, close to `oilc/src/rules/` so it compiles as-is. */
export const STARTER_RULE = `rule "outbound_from_shell" {
  from endpoint.process, network.flow

  correlate
    process.spawn as p
    with network.connect as n on n.process_id == p.id

  where
    n.direction == "outbound"
    and p.name in ["bash", "sh", "zsh"]

  respond
    alert high
    snapshot p, n
}
`;

/** A single-source rule the simulator can execute end to end. */
export const SIMPLE_RULE = `rule "shell_exec" {
  from endpoint.process

  where
    process.name in ["bash", "sh", "zsh"]

  score
    40
    +30 if process.user.name != "root"

  respond
    alert medium
}
`;

const STORAGE_KEY = "olopa_command_source";

interface OilValue {
  source: string;
  setSource: (next: string) => void;
  /** Replace the buffer and remember it across launches. */
  reset: () => void;
}

const OilContext = createContext<OilValue | null>(null);

/**
 * The OIL buffer shared by Studio and the Simulator.
 *
 * Keeping one buffer means "send to simulator" is a navigation, not a copy, and
 * the operator never simulates a stale version of what they are editing.
 */
export function OilProvider({ children }: { children: ReactNode }) {
  const [source, setSourceState] = useState<string>(() => {
    const drafted = takeDraft();
    if (drafted) return drafted;
    try {
      return localStorage.getItem(STORAGE_KEY) || STARTER_RULE;
    } catch {
      return STARTER_RULE;
    }
  });

  // A rule in progress should survive a restart of the app.
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, source);
    } catch {
      /* storage unavailable — in-memory only */
    }
  }, [source]);

  const setSource = useCallback((next: string) => setSourceState(next), []);
  const reset = useCallback(() => setSourceState(STARTER_RULE), []);

  const value = useMemo(() => ({ source, setSource, reset }), [source, setSource, reset]);
  return <OilContext.Provider value={value}>{children}</OilContext.Provider>;
}

export function useOil(): OilValue {
  const value = useContext(OilContext);
  if (!value) throw new Error("useOil must be used inside OilProvider");
  return value;
}

/**
 * Pick up a rule drafted from a telemetry event.
 *
 * The provider consumes any draft that exists at mount; this hook covers the
 * case where Command is already running and the operator drafts a new one.
 */
export function useDraftPickup(setSource: (next: string) => void) {
  useEffect(() => {
    const drafted = takeDraft();
    if (drafted) setSource(drafted);
  }, [setSource]);
}
