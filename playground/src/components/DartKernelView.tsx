import { useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import type { DartKernelResult, KernelSource } from "@/wasm/types";

function sourceFilename(uri: string, index: number): string {
  const basename: string = uri.split(/[\\/]/u).at(-1) ?? "";
  return /^[\w.-]+\.dart$/u.test(basename) ? basename : `source-${index + 1}.dart`;
}

export function DartKernelView({ result }: { readonly result: DartKernelResult }): ReactElement {
  const { kernel } = result;
  const firstSource: number = Math.max(0, kernel.sources.findIndex((source) => source.text.length > 0));
  const [sourceIndex, setSourceIndex] = useState<number>(firstSource);
  const [showReport, setShowReport] = useState<boolean>(false);
  const selectedIndex: number = kernel.sources[sourceIndex] === undefined ? firstSource : sourceIndex;
  const source: KernelSource | undefined = kernel.sources[selectedIndex];
  const hasSource: boolean = kernel.sources.some((entry) => entry.text.length > 0);

  return (
    <div className="flex min-w-0 flex-col gap-2 sm:gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label={`Kernel ${kernel.format_version}`} />
        <StatusChip label={hasSource ? "Embedded source recovered" : "No embedded source recovered"} tone={hasSource ? "accent" : "warn"} />
      </div>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">
        <Metric label="Source files" value={String(kernel.sources.length)} />
        <Metric label="Libraries" value={String(kernel.libraries.length)} />
        <Metric label="Classes" value={String(kernel.class_count)} />
        <Metric label="Procedures" value={String(kernel.procedure_count)} />
      </div>
      {kernel.sources.length > 0 ? (
        <label className="flex min-w-0 flex-col gap-1 font-sans text-xs text-ink-dim">
          Source file
          <select className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={selectedIndex} disabled={showReport} onChange={(event): void => setSourceIndex(Number(event.currentTarget.value))}>
            {kernel.sources.map((entry, index): ReactElement => <option key={index} value={index}>{entry.uri || `Source ${index + 1}`}</option>)}
          </select>
        </label>
      ) : null}
      <div role="group" aria-label="Dart Kernel output format" className="flex flex-wrap gap-2">
        <Button aria-pressed={!showReport && source !== undefined} disabled={source === undefined} onClick={(): void => setShowReport(false)}>Dart source</Button>
        <Button aria-pressed={showReport || source === undefined} onClick={(): void => setShowReport(true)}>JSON report</Button>
      </div>
      {showReport || source === undefined ? (
        <CodeEditor code={JSON.stringify(result, null, 2)} label="complete Dart Kernel report" language="json" downloadName="dart-kernel-report.json" />
      ) : (
        <>
          {source.text.length === 0 ? <p role="status" className="font-sans text-sm text-ink-dim">This source entry is empty.</p> : null}
          <CodeEditor code={source.text} label="embedded Dart source" language="dart" downloadName={sourceFilename(source.uri, selectedIndex)} />
        </>
      )}
    </div>
  );
}
