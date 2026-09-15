import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import type { EditorLanguage } from "@/lib/editor";
import type { HermesFunction, HermesResult } from "@/wasm/types";

type OutputKind = "source" | "bytecode" | "report";

interface HermesOutput {
  readonly code: string;
  readonly language: EditorLanguage;
  readonly label: string;
  readonly filename: string;
}

export function HermesView({ result }: { readonly result: HermesResult }): ReactElement {
  const [functionIndex, setFunctionIndex] = useState<number | null>(null);
  const [outputKind, setOutputKind] = useState<OutputKind>("source");
  const selected: HermesFunction | undefined = result.report.functions.find((fn) => fn.index === functionIndex);
  const selectedIndex: number | null = selected?.index ?? null;
  const output: HermesOutput = useMemo((): HermesOutput => {
    if (outputKind === "report") {
      return {
        code: JSON.stringify(result, null, 2),
        language: "json",
        label: "complete Hermes report",
        filename: "hermes-report.json",
      };
    }
    if (outputKind === "bytecode") {
      const code: string = result.disassembly
        .filter((fn) => selectedIndex === null || fn.index === selectedIndex)
        .map((fn): string => `function ${fn.index}\n${fn.listing}`)
        .join("\n\n");
      return {
        code,
        language: "disasm",
        label: "Hermes instructions",
        filename: selectedIndex === null ? "hermes-bytecode.txt" : `hermes-function-${selectedIndex}.txt`,
      };
    }
    const code: string = result.report.functions
      .filter((fn) => selectedIndex === null || fn.index === selectedIndex)
      .map((fn): string => fn.source)
      .join("\n\n");
    return {
      code,
      language: "javascript",
      label: "recovered pseudo-JavaScript",
      filename: selectedIndex === null ? "hermes-recovered.js" : `hermes-function-${selectedIndex}.js`,
    };
  }, [outputKind, result, selectedIndex]);
  const incomplete: number = result.report.total_fallback_ops + result.report.total_unaccounted_ops;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label={`Hermes ${result.header.version}`} />
        <StatusChip label={!result.report.lift_supported ? "JavaScript unavailable" : incomplete > 0 ? "partial recovery" : "operations modeled"} tone={!result.report.lift_supported || incomplete > 0 ? "warn" : "accent"} />
      </div>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">
        <Metric label="Functions" value={String(result.header.function_count)} />
        <Metric label="Recovered ops" value={String(result.report.total_reconstructed_ops)} />
        <Metric label="Fallback ops" value={String(result.report.total_fallback_ops)} />
        <Metric label="Unaccounted ops" value={String(result.report.total_unaccounted_ops)} />
      </div>
      {incomplete > 0 ? <p className="font-sans text-sm text-ink-dim">Some instructions remain as bytecode operations. The report records recovery counts for each function.</p> : null}
      <label className="flex flex-col gap-2 font-sans text-xs text-ink-dim">
        Function
        <select className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={selectedIndex ?? "all"} disabled={outputKind === "report"} onChange={(event): void => {
          setFunctionIndex(result.report.functions.find((fn) => String(fn.index) === event.currentTarget.value)?.index ?? null);
        }}>
          <option value="all">All functions</option>
          {result.report.functions.map((fn): ReactElement => <option key={fn.index} value={fn.index}>{fn.index}: {fn.name}</option>)}
        </select>
      </label>
      <div role="group" aria-label="Hermes output format" className="flex flex-wrap gap-2">
        {(["source", "bytecode", "report"] as const).map((kind): ReactElement => (
          <Button key={kind} aria-pressed={outputKind === kind} onClick={(): void => setOutputKind(kind)}>{kind === "source" ? "JavaScript" : kind === "bytecode" ? "Bytecode" : "JSON report"}</Button>
        ))}
      </div>
      {outputKind === "source" && !result.report.lift_supported ? <p role="status" className="font-sans text-sm text-ink-dim">JavaScript recovery is unavailable for this bytecode version. Choose Bytecode or JSON report to inspect the bundle.</p> : (
        <CodeEditor code={output.code} label={output.label} language={output.language} downloadName={output.filename} />
      )}
    </div>
  );
}
