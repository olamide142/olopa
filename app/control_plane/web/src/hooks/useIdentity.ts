import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  authApi,
  errorMessage,
  getCredential,
  setCredential as persistCredential,
  type Credential,
  type WhoAmI,
} from "@/lib/api";

export interface IdentityState {
  credential: Credential;
  whoami: WhoAmI | null;
  loading: boolean;
  /** Set when the control plane rejected the credential (401/403). */
  unauthorized: boolean;
  error: string | null;
}

/**
 * Resolve the caller's identity from /api/v1/auth/whoami.
 *
 * When the control plane runs with CONTROL_AUTH_REQUIRED disabled it answers
 * without a credential (token_type "disabled"); otherwise the console needs a
 * bearer JWT, service API key, or dev token before the rule and deployment
 * endpoints will accept it.
 */
export function useIdentity() {
  const [state, setState] = useState<IdentityState>({
    credential: getCredential(),
    whoami: null,
    loading: true,
    unauthorized: false,
    error: null,
  });

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setState((prev) => ({ ...prev, loading: true }));
    try {
      const { data } = await authApi.whoami(signal);
      setState({
        credential: getCredential(),
        whoami: data,
        loading: false,
        unauthorized: false,
        error: null,
      });
    } catch (err) {
      if ((err as Error)?.name === "AbortError") return;
      const unauthorized = err instanceof ApiError && err.isAuthError;
      setState({
        credential: getCredential(),
        whoami: null,
        loading: false,
        unauthorized,
        error: errorMessage(err),
      });
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  /** Persist a credential and immediately re-resolve identity with it. */
  const updateCredential = useCallback(
    async (credential: Credential) => {
      persistCredential(credential);
      setState((prev) => ({ ...prev, credential }));
      await refresh();
    },
    [refresh],
  );

  const hasRole = useCallback(
    (role: "viewer" | "analyst" | "operator" | "admin"): boolean => {
      const weights = { viewer: 10, analyst: 20, operator: 30, admin: 40 };
      const roles = state.whoami?.roles ?? [];
      const held = Math.max(0, ...roles.map((r) => weights[r as keyof typeof weights] ?? 0));
      return held >= weights[role];
    },
    [state.whoami],
  );

  return { ...state, refresh, updateCredential, hasRole };
}
