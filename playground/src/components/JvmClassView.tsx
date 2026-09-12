import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { downloadBlob } from "@/lib/download";
import { downloadMetaFor, type EditorLanguage } from "@/lib/editor";
import type { JvmClassResult, JvmInstruction, JvmMethod, JvmOperands } from "@/wasm/types";

type Section = "java" | "bytecode" | "metadata";
const PREVIEW_LIMIT: number = 64 * 1024;

function operandsText(operands: JvmOperands, pc: number): string {
  if (operands === "None") return "";
  if ("Byte" in operands) return String(operands.Byte);
  if ("Short" in operands) return String(operands.Short);
  if ("Local" in operands) return String(operands.Local);
  if ("Branch" in operands) return String(pc + operands.Branch);
  if ("ConstPool" in operands) return `cp[${operands.ConstPool}]`;
  if ("Iinc" in operands) return `${operands.Iinc.index}, ${operands.Iinc.delta}`;
  if ("NewArray" in operands) return String(operands.NewArray);
  if ("InvokeInterface" in operands) return `cp[${operands.InvokeInterface.index}], ${operands.InvokeInterface.count}`;
  if ("InvokeDynamic" in operands) return `cp[${operands.InvokeDynamic}]`;
  if ("MultiANewArray" in operands) return `cp[${operands.MultiANewArray.index}], ${operands.MultiANewArray.dimensions}`;
  if ("TableSwitch" in operands) {
    const table = operands.TableSwitch;
    return `${table.offsets.map((offset, index): string => `${table.low + index}: ${pc + offset}`).join(", ")}; default: ${pc + table.default}`;
  }
  if ("LookupSwitch" in operands) {
    return `${operands.LookupSwitch.pairs.map(([key, offset]): string => `${key}: ${pc + offset}`).join(", ")}; default: ${pc + operands.LookupSwitch.default}`;
  }
  const unreachable: never = operands;
  return unreachable;
}

function instructionText(instruction: JvmInstruction): string {
  const operands: string = operandsText(instruction.operands, instruction.pc);
  const reference: string = instruction.reference === null ? "" : `  ; ${instruction.reference}`;
  return `${String(instruction.pc).padStart(4, "0")}: ${instruction.mnemonic}${operands.length === 0 ? "" : ` ${operands}`}${reference}`;
}

export function JvmClassView({ result }: { readonly result: JvmClassResult }): ReactElement {
  const [section, setSection] = useState<Section>("java");
  const [methodIndex, setMethodIndex] = useState<number>(0);
  const method: JvmMethod | undefined = result.methods[methodIndex] ?? result.methods[0];
  const className: string = result.name.replaceAll("/", ".");
  const basename: string = result.name.split("/").at(-1)?.replace(/[^\w$.-]/gu, "_") || "RecoveredClass";
  const language: EditorLanguage = section === "java" ? "java" : section === "bytecode" ? "disasm" : "json";
  const text: string = useMemo((): string => {
    if (section === "java") return result.decompiled.source;
    if (section === "metadata") return JSON.stringify(result, null, 2);
    return method?.code.state === "available" ? method.code.instructions.map(instructionText).join("\n") : "";
  }, [section, result, method]);
  const filename: string = section === "java" ? result.source_filename : section === "metadata" ? `${basename}.json` : `${basename}-method-${methodIndex + 1}.txt`;
  const shortened: boolean = text.length > PREVIEW_LIMIT;
  const decompiled = result.decompiled;
  const partial: boolean = decompiled.fallback_methods > 0 || decompiled.decode_error_count > 0;

  return <div className="flex min-w-0 flex-col gap-1 sm:gap-4">
    <div className="flex min-w-0 flex-col gap-2">
      <h3 className="break-all font-sans text-lg font-semibold tracking-tight text-ink">{className}</h3>
      <div className="flex flex-wrap gap-2">
        <StatusChip label={`Class ${result.major_version}.${result.minor_version}`} />
        <StatusChip label={partial ? "Partial source recovery" : "Source recovered"} tone={partial ? "warn" : "accent"} />
      </div>
    </div>
    <details>
      <summary className="cursor-pointer py-1 font-sans text-xs leading-[18px] text-ink-dim">Recovery details</summary>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">
      <Metric label="Methods" value={String(result.methods.length)} />
      <Metric label="Lifted bodies" value={String(decompiled.fully_lifted_methods)} />
      <Metric label="Fallback bodies" value={String(decompiled.fallback_methods)} />
      <Metric label="Decode errors" value={String(decompiled.decode_error_count)} />
      </div>
    </details>
    {partial ? <p className="font-sans text-sm text-ink-dim">Some methods could not be fully recovered. Inspect their bytecode and the method details in Metadata.</p> : null}
    <div role="group" aria-label="JVM class output" className="flex flex-wrap gap-2">
      {([["java", "Java"], ["bytecode", "Bytecode"], ["metadata", "Metadata"]] as const).map(([key, label]): ReactElement => <Button key={key} aria-pressed={section === key} onClick={(): void => setSection(key)}>{label}</Button>)}
    </div>
    {section === "metadata" ? <dl className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 font-sans text-sm">
      <dt className="text-ink-dim">Superclass</dt><dd className="break-all text-ink">{result.superclass?.replaceAll("/", ".") ?? "None"}</dd>
      <dt className="text-ink-dim">Interfaces</dt><dd className="break-all text-ink">{result.interfaces.map((name): string => name.replaceAll("/", ".")).join(", ") || "None"}</dd>
      <dt className="text-ink-dim">Fields</dt><dd className="text-ink">{result.fields.length}</dd>
      <dt className="text-ink-dim">Constants</dt><dd className="text-ink">{result.constant_pool_entries}</dd>
    </dl> : null}
    {section === "bytecode" ? <>
      {result.methods.length > 0 ? <label className="flex min-w-0 flex-col gap-2 font-sans text-xs text-ink-dim">
        Method
        <select aria-label="Method" className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={methodIndex} onChange={(event): void => setMethodIndex(Number(event.currentTarget.value))}>
          {result.methods.map((entry, index): ReactElement => <option key={index} value={index}>{entry.name}{entry.descriptor}</option>)}
        </select>
      </label> : <p role="status" className="font-sans text-sm text-ink-dim">This class declares no methods.</p>}
      {method?.code.state === "absent" ? <p role="status" className="font-sans text-sm text-ink-dim">This method has no Code attribute. Abstract and native methods do not store bytecode in the class file.</p> : null}
      {method?.code.state === "invalid" ? <p role="status" className="break-words font-sans text-sm text-ink-dim">Bytecode unavailable: {method.code.error}</p> : null}
      {method?.code.state === "available" ? <div className="flex flex-wrap gap-2">
        <StatusChip label={`${method.code.instructions.length} instructions`} />
        <StatusChip label={`Stack ${method.code.max_stack} · locals ${method.code.max_locals}`} />
        {method.code.dropped_exceptions > 0 ? <StatusChip label={`${method.code.dropped_exceptions} invalid exception entries`} tone="warn" /> : null}
      </div> : null}
    </> : null}
    {text.length > 0 ? <>
      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={(): void => downloadBlob(filename, new Blob([text], { type: downloadMetaFor(language).mime }))}>{section === "java" ? "Download Java" : section === "bytecode" ? "Download bytecode" : "Download JSON"}</Button>
        {shortened ? <span className="font-sans text-xs text-ink-dim">Preview shortened. Download includes the complete output.</span> : null}
      </div>
      <CodeEditor code={text.slice(0, PREVIEW_LIMIT)} language={language} label={section === "java" ? "recovered Java source" : section === "bytecode" ? "JVM instructions" : "complete JVM class report"} downloadName={shortened ? `preview-${filename}` : filename} />
    </> : null}
  </div>;
}
