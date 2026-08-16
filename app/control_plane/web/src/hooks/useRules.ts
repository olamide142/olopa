import { useCallback, useEffect, useState } from "react";
import { errorMessage, rulesApi, type Rule } from "@/lib/api";

export interface RulesState {
  rules: Rule[];
  loading: boolean;
  error: string | null;
}

/** Load the tenant's rule registry, with a manual refresh for post-mutation reloads. */
export function useRules() {
  const [state, setState] = useState<RulesState>({ rules: [], loading: true, error: null });

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setState((prev) => ({ ...prev, loading: true }));
    try {
      const { data } = await rulesApi.list(signal);
      setState({ rules: data, loading: false, error: null });
    } catch (err) {
      if ((err as Error)?.name === "AbortError") return;
      setState({ rules: [], loading: false, error: errorMessage(err) });
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  return { ...state, refresh };
}
