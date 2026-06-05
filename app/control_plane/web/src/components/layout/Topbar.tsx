import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusDot } from "@/components/ui/status-dot";
import { useTheme } from "@/hooks/useTheme";
import type { FeedState } from "@/hooks/useIngestFeed";
import { formatNumber } from "@/lib/utils";

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className={tone ?? "font-medium tabular-nums"}>{value}</span>
    </div>
  );
}

export function Topbar({ feed }: { feed: FeedState }) {
  const { theme, toggle } = useTheme();
  const [clock, setClock] = useState(() => new Date().toTimeString().slice(0, 8));

  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toTimeString().slice(0, 8)), 1000);
    return () => clearInterval(id);
  }, []);

  const connected = feed.connected;

  return (
    <header className="flex h-14 shrink-0 items-center gap-5 border-b border-border bg-background/80 px-5 backdrop-blur">
      <div className="flex items-center gap-2">
        <StatusDot tone={connected ? "ok" : "down"} pulse={connected && !feed.paused} />
        <span className="text-sm font-medium">{connected ? "Backend online" : "Backend offline"}</span>
        {connected && <span className="text-xs text-muted-foreground">· {feed.latencyMs} ms</span>}
      </div>

      <div className="hidden items-center gap-5 md:flex">
        <Stat label="EPS" value={formatNumber(feed.eps)} />
        <Stat
          label="Alerts"
          value={formatNumber(feed.alertCount)}
          tone={feed.alertCount > 0 ? "font-semibold text-warning tabular-nums" : "font-medium tabular-nums"}
        />
        <Stat label="Rows" value={formatNumber(feed.rowCount)} />
      </div>

      <div className="ml-auto flex items-center gap-3">
        <span className="font-mono text-xs tabular-nums text-muted-foreground">{clock}</span>
        <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
    </header>
  );
}
