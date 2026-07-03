import type { ReactElement } from "react";

export interface MetricProps {
  readonly label: string;
  readonly value: string;
}

export function Metric({ label, value }: MetricProps): ReactElement {
  return (
    <div className="min-w-0 bg-inset px-3 py-2.5">
      <span className="block truncate font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">
        {label}
      </span>
      <span className="mt-1 block min-w-0 break-words font-mono text-sm text-ink">{value}</span>
    </div>
  );
}
