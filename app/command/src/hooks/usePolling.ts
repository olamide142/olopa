import { useCallback, useEffect, useRef, useState } from "react";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Wall-clock ms of the last successful read. */
  updatedAt: number | null;
}

/**
 * Poll a backend command on an interval.
 *
 * The fetcher is held in a ref so a caller can pass an inline closure without
 * re-arming the timer on every render, and an in-flight read is never allowed
 * to overlap the next tick.
 */
export function usePolling<T>(fetcher: () => Promise<T>, intervalMs: number, enabled = true) {
  const [state, setState] = useState<PollState<T>>({
    data: null,
    error: null,
    loading: true,
    updatedAt: null,
  });
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const inFlight = useRef(false);
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const data = await fetcherRef.current();
      if (mounted.current) {
        setState({ data, error: null, loading: false, updatedAt: Date.now() });
      }
    } catch (err) {
      if (mounted.current) {
        setState((prev) => ({
          ...prev,
          error: err instanceof Error ? err.message : String(err),
          loading: false,
        }));
      }
    } finally {
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    if (!enabled) return () => { mounted.current = false; };
    void refresh();
    if (intervalMs <= 0) return () => { mounted.current = false; };
    const timer = setInterval(() => void refresh(), intervalMs);
    return () => {
      mounted.current = false;
      clearInterval(timer);
    };
  }, [refresh, intervalMs, enabled]);

  return { ...state, refresh };
}
