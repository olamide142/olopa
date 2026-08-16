import { useCallback, useEffect, useState } from "react";
import { deploymentsApi, errorMessage, type Deployment } from "@/lib/api";

export interface DeploymentFilters {
  environment?: string;
  status?: string;
}

export interface DeploymentsState {
  deployments: Deployment[];
  loading: boolean;
  error: string | null;
}

/** Load deployments for the tenant, re-fetching whenever the filters change. */
export function useDeployments(filters: DeploymentFilters) {
  const { environment, status } = filters;
  const [state, setState] = useState<DeploymentsState>({
    deployments: [],
    loading: true,
    error: null,
  });

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      setState((prev) => ({ ...prev, loading: true }));
      try {
        const { data } = await deploymentsApi.list({ environment, status }, signal);
        setState({ deployments: data, loading: false, error: null });
      } catch (err) {
        if ((err as Error)?.name === "AbortError") return;
        setState({ deployments: [], loading: false, error: errorMessage(err) });
      }
    },
    [environment, status],
  );

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  return { ...state, refresh };
}
