import type { LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface PlaceholderProps {
  title: string;
  icon: LucideIcon;
  description: string;
}

/** Routed stub for panels not yet ported from the legacy console. */
export function Placeholder({ title, icon: Icon, description }: PlaceholderProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h1 className="text-lg font-semibold">{title}</h1>
        <Badge tone="muted">Coming soon</Badge>
      </div>
      <Card className="flex flex-col items-center justify-center gap-3 py-20 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-muted text-muted-foreground">
          <Icon className="h-6 w-6" />
        </div>
        <p className="max-w-md text-sm text-muted-foreground">{description}</p>
      </Card>
    </div>
  );
}
