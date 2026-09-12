import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor, type CodeEditorProps } from "@/components/CodeEditor";
import { Metric, type MetricProps } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import type { MrubyAnalysis, RubyDetectResult, YarvAnalysis } from "@/wasm/types";

type OutputKind = "source" | "bytecode" | "report";

export function RubyView({ result }: { readonly result: RubyDetectResult }): ReactElement {
  const [selectedKind, setSelectedKind] = useState<OutputKind>("source");
  const yarv: YarvAnalysis | null = result.analysis.yarv;
  const mruby: MrubyAnalysis | null = result.analysis.mruby;
  const source: string | undefined = yarv?.decompiled.source ?? mruby?.decompiled.source;
  const hasBody: boolean = yarv !== null ? yarv.decompiled.fidelity !== "literal-pool-only" : mruby?.decompiled.has_body === true;
  const hasBytecode: boolean = yarv !== null && yarv.ibf.recovered_instruction_count > 0;
  const outputKind: OutputKind = source === undefined ? "report" : selectedKind === "bytecode" && !hasBytecode ? "source" : selectedKind;
  const status: string = yarv !== null
    ? { lossy: "Lossy recovery", "structural-only": "Structural recovery", "literal-pool-only": "Literals only" }[yarv.decompiled.fidelity]
    : mruby !== null ? !hasBody ? "Source unavailable" : mruby.decompiled.unmodeled_opcodes > 0 ? "Partial recovery" : "Operations modeled" : "Format identified";
  const metrics: readonly MetricProps[] = yarv !== null ? [
    { label: "ISEQs", value: String(yarv.ibf.iseq_offsets.length) },
    { label: "Decoded ops", value: String(yarv.ibf.recovered_instruction_count) },
    { label: "Statements", value: String(yarv.decompiled.statement_count) },
    { label: "Literals", value: String(yarv.ibf.recovered_literal_count) },
  ] : mruby !== null ? [
    { label: "IREPs", value: String(mruby.decompiled.irep_count) },
    { label: "Instruction bytes", value: String(mruby.decompiled.instruction_count) },
    { label: "Modeled ops", value: `${mruby.decompiled.modeled_opcodes} / ${mruby.decompiled.lifted_opcodes}` },
    { label: "Unmodeled ops", value: String(mruby.decompiled.unmodeled_opcodes) },
  ] : [];
  const output: CodeEditorProps = useMemo((): CodeEditorProps => {
    if (outputKind === "report") {
      return { code: JSON.stringify(result, null, 2), language: "json", label: "complete Ruby report", downloadName: "ruby-report.json" };
    }
    if (outputKind === "bytecode" && yarv !== null) {
      const code: string = yarv.ibf.iseqs.map((iseq): string => {
        const instructions: string = iseq.instructions.map((instruction): string => {
          const operands: string = instruction.operands.map((operand): string => JSON.stringify(operand)).join(" ");
          return `${instruction.pc.toString().padStart(4, "0")}  ${instruction.mnemonic}${operands.length > 0 ? ` ${operands}` : ""}`;
        }).join("\n");
        return `ISEQ ${iseq.index}\n${instructions}`;
      }).join("\n\n");
      return { code, language: "disasm", label: "YARV instructions", downloadName: "ruby-yarv-instructions.txt" };
    }
    return { code: source ?? "", language: hasBody ? "ruby" : "text", label: hasBody ? "recovered Ruby source" : "Ruby recovery details", downloadName: hasBody ? "ruby-recovered.rb" : "ruby-recovery-details.txt" };
  }, [hasBody, outputKind, result, source, yarv]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label={yarv !== null ? `YARV ${yarv.version.major}.${yarv.version.minor}` : result.analysis.flavor} />
        <StatusChip label={status} tone={source !== undefined ? "warn" : "muted"} />
      </div>
      {metrics.length > 0 ? <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">{metrics.map((metric): ReactElement => <Metric key={metric.label} {...metric} />)}</div> : null}
      {yarv?.decompiled.fidelity === "structural-only" ? <p className="font-sans text-sm text-ink-dim">Classes and methods are recovered structurally. Some operations may remain unresolved.</p> : null}
      {source !== undefined ? <div role="group" aria-label="Ruby output format" className="flex flex-wrap gap-2">
        <Button aria-pressed={outputKind === "source"} onClick={(): void => setSelectedKind("source")}>{hasBody ? "Ruby source" : "Recovery details"}</Button>
        {hasBytecode ? <Button aria-pressed={outputKind === "bytecode"} onClick={(): void => setSelectedKind("bytecode")}>Bytecode</Button> : null}
        <Button aria-pressed={outputKind === "report"} onClick={(): void => setSelectedKind("report")}>JSON report</Button>
      </div> : null}
      <CodeEditor {...output} />
    </div>
  );
}
