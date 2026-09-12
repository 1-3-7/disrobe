import type { ReactElement } from "react";
import { cn } from "@/lib/utils";

export type StatusTone = "neutral" | "accent" | "warn" | "danger" | "muted";

const TONE_CLASS: Readonly<Record<StatusTone, string>> = {
  neutral: "border-hairline text-ink-muted",
  accent: "border-accent/40 text-accent",
  warn: "border-warn/40 text-warn",
  danger: "border-danger/45 text-danger",
  muted: "border-hairline text-ink-faint",
};

const DOT_CLASS: Readonly<Record<StatusTone, string>> = {
  neutral: "bg-ink-faint",
  accent: "bg-accent",
  warn: "bg-warn",
  danger: "bg-danger",
  muted: "bg-ink-faint",
};

export interface StatusChipProps {
  readonly label: string;
  readonly tone?: StatusTone;
  readonly dot?: boolean;
  readonly className?: string;
}

export function StatusChip({
  label,
  tone = "neutral",
  dot = false,
  className,
}: StatusChipProps): ReactElement {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-xs border px-2 py-0.5 font-mono text-[11px] leading-none tracking-normal",
        TONE_CLASS[tone],
        className,
      )}
    >
      {dot ? <span aria-hidden="true" className={cn("size-1.5 rounded-full", DOT_CLASS[tone])} /> : null}
      <span className="min-w-0 truncate">{label}</span>
    </span>
  );
}
