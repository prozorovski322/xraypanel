import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** cn merges class names, letting a later Tailwind class override an earlier one. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

const byteUnits = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

/**
 * formatBytes renders a byte count in binary units.
 *
 * Binary, because that is what the panel stores and what an operator types into a limit
 * field: "100 GiB" as 107374182400. Mixing decimal and binary units on one screen makes a
 * user who is exactly at their limit look seven percent under it.
 */
export function formatBytes(bytes: number | undefined | null, digits = 1): string {
  if (bytes === undefined || bytes === null || !Number.isFinite(bytes)) return "—";
  if (bytes === 0) return "0 B";

  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < byteUnits.length - 1) {
    value /= 1024;
    unit++;
  }
  const sign = bytes < 0 ? "-" : "";
  const shown = unit === 0 ? value.toFixed(0) : value.toFixed(digits);
  return `${sign}${shown} ${byteUnits[unit]}`;
}

/** parseBytes reads "100 GiB", "512MiB" or a plain number of bytes. Returns null if unreadable. */
export function parseBytes(input: string): number | null {
  const match = /^\s*(\d+(?:\.\d+)?)\s*([KMGTP]i?B|B)?\s*$/i.exec(input);
  if (!match) return null;

  const amount = Number(match[1]);
  const unit = (match[2] ?? "B").toUpperCase();
  const powers: Record<string, number> = {
    B: 0,
    KB: 1,
    KIB: 1,
    MB: 2,
    MIB: 2,
    GB: 3,
    GIB: 3,
    TB: 4,
    TIB: 4,
    PB: 5,
    PIB: 5,
  };
  const power = powers[unit];
  if (power === undefined) return null;
  // Everything is binary: an operator typing "100 GB" into a limit means the same thing as
  // the "100 GiB" the panel will show back to them.
  return Math.round(amount * 1024 ** power);
}

const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const dateOnly = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });

/** formatDateTime shows an instant in the viewer's own timezone. */
export function formatDateTime(value: string | undefined | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : dateTime.format(date);
}

export function formatDate(value: string | undefined | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : dateOnly.format(date);
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** formatRelative renders "3 minutes ago" or "in 2 days". */
export function formatRelative(value: string | undefined | null, now = Date.now()): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";

  const seconds = Math.round((then - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return relative.format(seconds, "second");
  if (abs < 45 * 60) return relative.format(Math.round(seconds / 60), "minute");
  if (abs < 22 * 3600) return relative.format(Math.round(seconds / 3600), "hour");
  if (abs < 26 * 86400) return relative.format(Math.round(seconds / 86400), "day");
  if (abs < 320 * 86400) return relative.format(Math.round(seconds / (30 * 86400)), "month");
  return relative.format(Math.round(seconds / (365 * 86400)), "year");
}

/** percent of used against a limit; null when there is no limit. */
export function usageRatio(used: number | undefined, limit: number | undefined): number | null {
  if (!limit || limit <= 0) return null;
  return Math.min(1, Math.max(0, (used ?? 0) / limit));
}
