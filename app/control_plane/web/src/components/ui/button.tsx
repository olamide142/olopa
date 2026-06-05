import * as React from "react";
import { cn } from "@/lib/utils";

type Variant = "default" | "primary" | "ghost" | "outline";
type Size = "sm" | "md" | "icon";

const variants: Record<Variant, string> = {
  default:
    "bg-card text-card-foreground border border-border hover:bg-accent hover:text-accent-foreground",
  primary: "bg-primary text-primary-foreground hover:opacity-90 border border-transparent",
  ghost: "bg-transparent hover:bg-accent hover:text-accent-foreground border border-transparent",
  outline: "bg-transparent border border-border hover:bg-accent",
};

const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-xs",
  md: "h-9 px-4 text-sm",
  icon: "h-9 w-9",
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  active?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "md", active, ...props }, ref) => (
    <button
      ref={ref}
      data-active={active ? "" : undefined}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        active && "bg-primary text-primary-foreground border-transparent hover:opacity-90",
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";
