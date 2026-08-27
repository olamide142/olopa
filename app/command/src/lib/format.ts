import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function num(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return value.toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

/** Compact byte rendering: 1536 -> "1.5 KB". */
export function bytes(value: number | null | undefined): string {
  if (!value || !Number.isFinite(value)) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** Duration from seconds: 66900 -> "18h 35m". */
export function duration(seconds: number | null | undefined): string {
  if (!seconds || seconds < 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${Math.floor(seconds % 60)}s`;
  return `${Math.floor(seconds)}s`;
}

export function clock(unixMs: number | null | undefined): string {
  if (!unixMs) return "—";
  return new Date(unixMs).toTimeString().slice(0, 8);
}

/** "4s ago" / "2m ago"; accepts milliseconds. */
export function since(unixMs: number | null | undefined): string {
  if (!unixMs) return "never";
  const secs = Math.max(0, Math.round((Date.now() - unixMs) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** Seconds-precision unix timestamps as used by the Secure Connect health file. */
export function sinceUnixSecs(unixSecs: number | null | undefined): string {
  if (!unixSecs) return "never";
  return since(unixSecs * 1000);
}

export function nanos(value: number | null | undefined): string {
  if (!value || !Number.isFinite(value)) return "—";
  if (value < 1000) return `${Math.round(value)} ns`;
  if (value < 1_000_000) return `${(value / 1000).toFixed(1)} µs`;
  return `${(value / 1_000_000).toFixed(2)} ms`;
}

export function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

/** Ratio of used to limit, clamped to 0..1 for meters. */
export function ratio(used: number, limit: number): number {
  if (!limit || !Number.isFinite(limit) || limit <= 0) return 0;
  return Math.max(0, Math.min(1, used / limit));
}
