import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

/** Centered placeholder for panels whose collection is empty. */
export function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-16 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-muted text-muted-foreground">
        <Icon className="h-5 w-5" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">{title}</p>
        {description && <p className="max-w-md text-xs text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  );
}
