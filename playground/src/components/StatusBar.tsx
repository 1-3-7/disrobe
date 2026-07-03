import type { ReactElement } from "react";
import { cn } from "@/lib/utils";

export type StatusBarTone = "accent" | "warn" | "danger";

export interface StatusBarField {
  readonly label: string;
  readonly value: string;
}

export interface StatusBarProps {
  readonly fields: readonly StatusBarField[];
  readonly tone: StatusBarTone;
}

const DOT_CLASS: Readonly<Record<StatusBarTone, string>> = {
  accent: "bg-accent",
  warn: "bg-warn",
  danger: "bg-danger",
};

export function StatusBar({ fields, tone }: StatusBarProps): ReactElement {
  return (
    <div className="flex shrink-0 items-center gap-4 border-t border-hairline bg-surface px-4 py-1.5">
      <span
        aria-hidden="true"
        className={cn("size-1.5 shrink-0 rounded-full", DOT_CLASS[tone])}
      />
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-0.5">
        {fields.map((field: StatusBarField): ReactElement => (
          <span key={field.label} className="flex items-center gap-1.5 whitespace-nowrap">
            <span className="font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">
              {field.label}
            </span>
            <span className="min-w-0 truncate font-mono text-[11px] text-ink-muted">
              {field.value}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}
