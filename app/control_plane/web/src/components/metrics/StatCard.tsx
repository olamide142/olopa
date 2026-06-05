import { Card } from "@/components/ui/card";
import { Sparkline } from "./Sparkline";
import { cn } from "@/lib/utils";

interface StatCardProps {
  label: string;
  value: string;
  unit?: string;
  series: number[];
  color: string;
  accent?: "primary" | "success" | "warning" | "danger";
}

const accentText: Record<NonNullable<StatCardProps["accent"]>, string> = {
  primary: "text-foreground",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
};

export function StatCard({ label, value, unit, series, color, accent = "primary" }: StatCardProps) {
  return (
    <Card className="overflow-hidden">
      <div className="px-4 pt-3">
        <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className="mt-1 flex items-baseline gap-1">
          <span className={cn("text-2xl font-semibold tabular-nums", accentText[accent])}>{value}</span>
          {unit && <span className="text-xs text-muted-foreground">{unit}</span>}
        </div>
      </div>
      <div className="mt-1 px-1">
        <Sparkline data={series} color={color} />
      </div>
    </Card>
  );
}
