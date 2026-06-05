import { Pause, Play } from "lucide-react";
import { StatCard } from "@/components/metrics/StatCard";
import { EventsTable } from "@/components/metrics/EventsTable";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/input";
import { formatNumber } from "@/lib/utils";
import type { FeedState, SparkWindow } from "@/hooks/useIngestFeed";

interface MetricsPanelProps {
  feed: FeedState;
  setPaused: (p: boolean) => void;
  setWindow: (w: SparkWindow) => void;
  setPollMs: (ms: number) => void;
}

const COLORS = {
  eps: "#3b82f6",
  accept: "#22c55e",
  net: "#f59e0b",
  alerts: "#ef4444",
};

export function MetricsPanel({ feed, setPaused, setWindow, setPollMs }: MetricsPanelProps) {
  const acceptRate = feed.series.acceptRate.at(-1) ?? 100;
  const net = feed.summary?.by_kind?.net ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-lg font-semibold">Live Telemetry</h1>
          <p className="text-xs text-muted-foreground">
            {feed.connected
              ? `streaming · ${formatNumber(feed.rowCount)} rows · window ${feed.window}`
              : "backend offline · telemetry paused"}
          </p>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-border">
            {(["5m", "1h"] as SparkWindow[]).map((w) => (
              <button
                key={w}
                onClick={() => setWindow(w)}
                className={
                  "px-3 py-1.5 text-xs font-medium transition-colors " +
                  (feed.window === w
                    ? "bg-primary text-primary-foreground"
                    : "bg-card text-muted-foreground hover:bg-accent")
                }
              >
                {w}
              </button>
            ))}
          </div>

          <Select
            className="h-8"
            value={String(feed.pollMs)}
            onChange={(e) => setPollMs(Number(e.target.value))}
          >
            <option value="1000">1s</option>
            <option value="2000">2s</option>
            <option value="5000">5s</option>
            <option value="10000">10s</option>
          </Select>

          <Button size="sm" variant={feed.paused ? "primary" : "outline"} onClick={() => setPaused(!feed.paused)}>
            {feed.paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {feed.paused ? "Resume" : "Pause"}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Events / sec" value={formatNumber(feed.eps)} series={feed.series.eps} color={COLORS.eps} />
        <StatCard
          label="Accept rate"
          value={String(acceptRate)}
          unit="%"
          series={feed.series.acceptRate}
          color={COLORS.accept}
          accent="success"
        />
        <StatCard label="Network ev." value={formatNumber(net)} series={feed.series.net} color={COLORS.net} accent="warning" />
        <StatCard
          label="Alerts"
          value={formatNumber(feed.alertCount)}
          series={feed.series.alerts}
          color={COLORS.alerts}
          accent={feed.alertCount > 0 ? "danger" : "primary"}
        />
      </div>

      <Card className="p-0">
        <EventsTable rows={feed.rows} />
      </Card>
    </div>
  );
}
