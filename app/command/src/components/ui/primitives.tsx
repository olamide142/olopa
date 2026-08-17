import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/format";

// -- Surfaces ------------------------------------------------------------------

export function Panel({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-lg border border-border bg-surface", className)}
      {...props}
    />
  );
}

export function PanelHead({
  title,
  hint,
  actions,
  className,
}: {
  title: React.ReactNode;
  hint?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-3 border-b border-border px-3 py-2",
        className,
      )}
    >
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-fg-muted">
          {title}
        </div>
        {hint && <div className="truncate text-[11px] text-fg-faint">{hint}</div>}
      </div>
      {actions && <div className="ml-auto flex shrink-0 items-center gap-1.5">{actions}</div>}
    </div>
  );
}

/** Page-level heading used at the top of every panel. */
export function PageHead({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end gap-3">
      <div>
        <h1 className="text-[15px] font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[11px] text-fg-muted">{subtitle}</p>}
      </div>
      {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
    </div>
  );
}

// -- Controls ------------------------------------------------------------------

type Variant = "default" | "primary" | "ghost" | "danger";
type Size = "xs" | "sm" | "md" | "icon";

const VARIANTS: Record<Variant, string> = {
  default: "bg-surface-2 text-fg border border-border-strong hover:border-fg-faint",
  primary: "bg-primary text-primary-foreground border border-transparent hover:opacity-90 font-semibold",
  ghost: "bg-transparent text-fg-muted border border-transparent hover:bg-surface-2 hover:text-fg",
  danger: "bg-transparent text-danger border border-danger/40 hover:bg-danger/10",
};

const SIZES: Record<Size, string> = {
  xs: "h-6 px-2 text-[11px]",
  sm: "h-7 px-2.5 text-[11px]",
  md: "h-8 px-3 text-xs",
  icon: "h-7 w-7",
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "sm", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        "inline-flex select-none items-center justify-center gap-1.5 rounded-md transition-colors",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary",
        "disabled:pointer-events-none disabled:opacity-40",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-7 w-full rounded-md border border-border-strong bg-bg px-2 text-xs text-fg",
        "placeholder:text-fg-faint focus-visible:border-primary focus-visible:outline-none",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export const Select = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, ...props }, ref) => (
  <select
    ref={ref}
    className={cn(
      "h-7 rounded-md border border-border-strong bg-bg px-1.5 text-xs text-fg",
      "focus-visible:border-primary focus-visible:outline-none",
      className,
    )}
    {...props}
  />
));
Select.displayName = "Select";

// -- Signals -------------------------------------------------------------------

export type Tone = "ok" | "warn" | "danger" | "info" | "muted" | "primary" | "violet";

const TONE_TEXT: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  info: "text-info",
  muted: "text-fg-muted",
  primary: "text-primary",
  violet: "text-violet",
};

const TONE_CHIP: Record<Tone, string> = {
  ok: "bg-ok/10 text-ok border-ok/25",
  warn: "bg-warn/10 text-warn border-warn/25",
  danger: "bg-danger/10 text-danger border-danger/25",
  info: "bg-info/10 text-info border-info/25",
  muted: "bg-surface-2 text-fg-muted border-border-strong",
  primary: "bg-primary/10 text-primary border-primary/25",
  violet: "bg-violet/10 text-violet border-violet/25",
};

const TONE_BG: Record<Tone, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  danger: "bg-danger",
  info: "bg-info",
  muted: "bg-fg-faint",
  primary: "bg-primary",
  violet: "bg-violet",
};

export function Chip({
  tone = "muted",
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-px font-mono text-[10px] uppercase tracking-wide",
        TONE_CHIP[tone],
        className,
      )}
      {...props}
    />
  );
}

export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return (
    <span className="relative inline-flex h-1.5 w-1.5 shrink-0">
      {pulse && (
        <span className={cn("pulse-ring absolute inset-0 rounded-full", TONE_BG[tone])} />
      )}
      <span className={cn("relative h-1.5 w-1.5 rounded-full", TONE_BG[tone])} />
    </span>
  );
}

/** Label / value row used throughout the instrument panels. */
export function Field({
  label,
  value,
  tone,
  mono = true,
}: {
  label: string;
  value: React.ReactNode;
  tone?: Tone;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="text-[11px] text-fg-muted">{label}</span>
      <span
        className={cn(
          "truncate text-right text-xs",
          mono && "font-mono tabular-nums",
          tone ? TONE_TEXT[tone] : "text-fg",
        )}
      >
        {value}
      </span>
    </div>
  );
}

/** Horizontal budget meter: used vs a hard ceiling. */
export function Meter({
  label,
  value,
  limit,
  render,
  tone = "primary",
}: {
  label: string;
  value: number;
  limit: number;
  render: (value: number) => string;
  tone?: Tone;
}) {
  const filled = limit > 0 ? Math.max(0, Math.min(1, value / limit)) : 0;
  const over = filled > 0.85;
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between">
        <span className="text-[11px] text-fg-muted">{label}</span>
        <span className="font-mono text-[11px] tabular-nums text-fg">
          {render(value)}
          <span className="text-fg-faint"> / {render(limit)}</span>
        </span>
      </div>
      <div className="h-1 overflow-hidden rounded-full bg-surface-2">
        <div
          className={cn("h-full rounded-full transition-all", TONE_BG[over ? "warn" : tone])}
          style={{ width: `${filled * 100}%` }}
        />
      </div>
    </div>
  );
}

// -- Data display --------------------------------------------------------------

export function Empty({
  icon: Icon,
  title,
  detail,
  action,
}: {
  icon: LucideIcon;
  title: string;
  detail?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 px-6 py-12 text-center">
      <Icon className="h-5 w-5 text-fg-faint" />
      <div className="space-y-1">
        <p className="text-xs font-medium text-fg">{title}</p>
        {detail && <p className="max-w-md text-[11px] leading-relaxed text-fg-muted">{detail}</p>}
      </div>
      {action}
    </div>
  );
}

export function Notice({ tone = "danger", children }: { tone?: Tone; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "rounded-md border px-2.5 py-1.5 text-[11px] leading-relaxed",
        TONE_CHIP[tone],
      )}
    >
      {children}
    </div>
  );
}

export function Code({
  content,
  className,
  empty = "no output",
}: {
  content: string;
  className?: string;
  empty?: string;
}) {
  if (!content) {
    return <div className={cn("px-3 py-4 text-[11px] text-fg-faint", className)}>{empty}</div>;
  }
  return (
    <pre
      className={cn(
        "selectable overflow-auto whitespace-pre px-3 py-2.5 font-mono text-[11px] leading-relaxed text-fg",
        className,
      )}
    >
      {content}
    </pre>
  );
}

export function Json({ value, className }: { value: unknown; className?: string }) {
  const text = value === null || value === undefined ? "" : JSON.stringify(value, null, 2);
  return <Code content={text} className={className} empty="nothing to show" />;
}

export function Tabs<T extends string>({
  items,
  value,
  onChange,
  className,
}: {
  items: readonly { value: T; label: string; hint?: string | number }[];
  value: T;
  onChange: (next: T) => void;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-0.5 rounded-md bg-surface-2 p-0.5", className)}>
      {items.map((item) => (
        <button
          key={item.value}
          type="button"
          onClick={() => onChange(item.value)}
          className={cn(
            "rounded px-2 py-1 text-[11px] transition-colors",
            item.value === value
              ? "bg-bg text-fg shadow-sm"
              : "text-fg-muted hover:text-fg",
          )}
        >
          {item.label}
          {item.hint !== undefined && item.hint !== "" && (
            <span className="ml-1 font-mono tabular-nums text-fg-faint">{item.hint}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Th({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "sticky top-0 z-10 whitespace-nowrap border-b border-border bg-surface px-2.5 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wider text-fg-faint",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("whitespace-nowrap px-2.5 py-1 text-[11px]", className)} {...props} />;
}
