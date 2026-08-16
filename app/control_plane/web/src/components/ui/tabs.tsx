import { cn } from "@/lib/utils";

export interface TabItem<T extends string> {
  value: T;
  label: string;
  /** Optional trailing count or status hint. */
  hint?: string;
}

interface TabsProps<T extends string> {
  items: readonly TabItem<T>[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
}

/** Segmented control used for switching between output views. */
export function Tabs<T extends string>({ items, value, onChange, className }: TabsProps<T>) {
  return (
    <div className={cn("flex overflow-hidden rounded-md border border-border", className)}>
      {items.map((item) => (
        <button
          key={item.value}
          type="button"
          onClick={() => onChange(item.value)}
          className={cn(
            "px-3 py-1.5 text-xs font-medium transition-colors",
            item.value === value
              ? "bg-primary text-primary-foreground"
              : "bg-card text-muted-foreground hover:bg-accent",
          )}
        >
          {item.label}
          {item.hint ? <span className="ml-1.5 opacity-70 tabular-nums">{item.hint}</span> : null}
        </button>
      ))}
    </div>
  );
}
