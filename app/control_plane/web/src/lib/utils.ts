import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge conditional class names, de-duplicating conflicting Tailwind utilities. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format an integer with locale grouping (1234 -> "1,234"). */
export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "0";
  return Math.round(n).toLocaleString();
}

/** Render a UNIX-ms timestamp as HH:MM:SS. */
export function formatClock(unixMs: number | undefined): string {
  const d = new Date(unixMs ?? Date.now());
  return d.toTimeString().slice(0, 8);
}

/** Human relative age, e.g. "4s ago", "2m ago". */
export function relativeAge(unixMs: number | undefined): string {
  if (!unixMs) return "never";
  const secs = Math.max(0, Math.round((Date.now() - unixMs) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}
