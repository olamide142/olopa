import { useCallback, useEffect, useRef, useState } from "react";
import { ingestApi, type IngestStats, type IngestSummary, type RecentRow } from "@/lib/api";
import { isAlert } from "@/lib/events";

export type SparkWindow = "5m" | "1h";

export interface FeedSeries {
  eps: number[];
  acceptRate: number[];
  net: number[];
  alerts: number[];
}

export interface FeedState {
  connected: boolean;
  paused: boolean;
  latencyMs: number;
  eps: number;
  alertCount: number;
  stats: IngestStats | null;
  summary: IngestSummary | null;
  rows: RecentRow[];
  series: FeedSeries;
  window: SparkWindow;
  pollMs: number;
  rowCount: number;
}

const MAX_POINTS: Record<SparkWindow, number> = { "5m": 120, "1h": 600 };
const RECENT_LIMIT: Record<SparkWindow, number> = { "5m": 240, "1h": 600 };

function emptySeries(): FeedSeries {
  return { eps: [], acceptRate: [], net: [], alerts: [] };
}

/**
 * Poll the ingest endpoints and expose a live, smoothed view model.
 * Handles EPS derivation, sparkline series, pause, poll interval and window.
 */
export function useIngestFeed() {
  const [state, setState] = useState<FeedState>({
    connected: false,
    paused: false,
    latencyMs: 0,
    eps: 0,
    alertCount: 0,
    stats: null,
    summary: null,
    rows: [],
    series: emptySeries(),
    window: "5m",
    pollMs: 2000,
    rowCount: 0,
  });

  // Mutable refs avoid re-creating the polling loop on every tick.
  const pausedRef = useRef(false);
  const windowRef = useRef<SparkWindow>("5m");
  const lastTotalRef = useRef<number | null>(null);
  const lastPollRef = useRef<number | null>(null);
  const epsSmoothRef = useRef<number | null>(null);

  const smoothEps = useCallback((raw: number): number => {
    const r = Number.isFinite(raw) ? Math.max(0, raw) : 0;
    const prev = epsSmoothRef.current;
    if (prev === null) {
      epsSmoothRef.current = r;
      return Math.round(r);
    }
    const target = r === 0 && prev > 0 ? prev * 0.82 : r;
    const next = 0.28 * target + 0.72 * prev;
    epsSmoothRef.current = next;
    return Math.round(next);
  }, []);

  const tick = useCallback(
    async (signal: AbortSignal) => {
      if (pausedRef.current) return;
      const win = windowRef.current;
      try {
        const [stats, summary, recent] = await Promise.all([
          ingestApi.stats(signal),
          ingestApi.summary(signal),
          ingestApi.recent(RECENT_LIMIT[win], signal),
        ]);

        const nowMs = Date.now();
        const total = summary.data.total_rows || 0;
        let rawEps = 0;
        if (lastTotalRef.current !== null && lastPollRef.current !== null) {
          const deltaRows = Math.max(0, total - lastTotalRef.current);
          const deltaSec = Math.max(0.001, (nowMs - lastPollRef.current) / 1000);
          rawEps = deltaRows / deltaSec;
        }
        lastTotalRef.current = total;
        lastPollRef.current = nowMs;
        const eps = smoothEps(rawEps);

        const rows = recent.data.rows || [];
        const alertCount = rows.filter(isAlert).length;
        const accepted = stats.data.accepted_total || 0;
        const rejected = stats.data.rejected_total || 0;
        const acceptRate = accepted + rejected > 0 ? Math.round((accepted * 100) / (accepted + rejected)) : 100;
        const net = summary.data.by_kind?.net || 0;
        const cap = MAX_POINTS[win];

        setState((prev) => {
          const push = (arr: number[], v: number) => {
            const out = [...arr, v];
            while (out.length > cap) out.shift();
            return out;
          };
          return {
            ...prev,
            connected: true,
            latencyMs: stats.latencyMs,
            eps,
            alertCount,
            stats: stats.data,
            summary: summary.data,
            rows,
            rowCount: total,
            series: {
              eps: push(prev.series.eps, eps),
              acceptRate: push(prev.series.acceptRate, acceptRate),
              net: push(prev.series.net, net),
              alerts: push(prev.series.alerts, alertCount),
            },
          };
        });
      } catch (err) {
        if ((err as Error)?.name === "AbortError") return;
        setState((prev) => ({ ...prev, connected: false, rows: [] }));
      }
    },
    [smoothEps],
  );

  // Drive the polling loop. Re-arms whenever the poll interval changes.
  useEffect(() => {
    const controller = new AbortController();
    void tick(controller.signal);
    const timer = setInterval(() => void tick(controller.signal), state.pollMs);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [tick, state.pollMs]);

  const setPaused = useCallback((paused: boolean) => {
    pausedRef.current = paused;
    setState((p) => ({ ...p, paused }));
  }, []);

  const setWindow = useCallback((win: SparkWindow) => {
    windowRef.current = win;
    setState((p) => {
      const cap = MAX_POINTS[win];
      const trim = (arr: number[]) => arr.slice(-cap);
      return {
        ...p,
        window: win,
        series: {
          eps: trim(p.series.eps),
          acceptRate: trim(p.series.acceptRate),
          net: trim(p.series.net),
          alerts: trim(p.series.alerts),
        },
      };
    });
  }, []);

  const setPollMs = useCallback((ms: number) => {
    if (!Number.isFinite(ms) || ms < 250) return;
    setState((p) => ({ ...p, pollMs: ms }));
  }, []);

  return { state, setPaused, setWindow, setPollMs };
}
