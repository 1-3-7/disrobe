import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { downloadBlob } from "@/lib/download";
import { downloadMetaFor, type EditorLanguage } from "@/lib/editor";
import type { DotnetMethod, DotnetMethodCode, DotnetResult, DotnetSource } from "@/wasm/types";

type SourceLanguage = "csharp" | "fsharp" | "vbnet";
type Section = "source" | "cil" | "metadata";
const SECTIONS = [["csharp", "C#"], ["fsharp", "F#"], ["vbnet", "VB"], ["cil", "CIL"], ["metadata", "Metadata"]] as const;
const PREVIEW_LIMIT: number = 64 * 1024;

export function DotnetView({ result }: { readonly result: DotnetResult }): ReactElement {
  const [section, setSection] = useState<Section>("source");
  const [sourceLanguage, setSourceLanguage] = useState<SourceLanguage>("csharp");
  const [methodToken, setMethodToken] = useState<number | null>(null);
  const methods: readonly { readonly type: string; readonly method: DotnetMethod }[] = useMemo(() => result.model.types.flatMap((ty) => ty.methods.map((method) => ({ type: ty.full_name, method }))), [result.model.types]);
  const selected = methods.find((entry) => entry.method.token === methodToken) ?? methods[0];
  const token: number | undefined = selected?.method.token;
  const source: DotnetSource = result[sourceLanguage];
  const recovered = source.methods.find((method) => method.token === token);
  const code: DotnetMethodCode | undefined = result.bytecode.find((entry) => entry.token === token)?.code;
  const language: EditorLanguage = section === "cil" ? "disasm" : section === "metadata" ? "json" : sourceLanguage;
  const text: string = useMemo((): string => {
    if (section === "metadata") return JSON.stringify(result, null, 2);
    if (section === "cil") return code?.state === "available" ? code.instructions.map((instruction): string => `${String(instruction.offset).padStart(4, "0")}: ${instruction.name}${instruction.operand.length === 0 ? "" : ` ${instruction.operand}`}${instruction.reference === null ? "" : `  ; ${instruction.reference}`}`).join("\n") : "";
    return recovered?.body ?? "";
  }, [section, result, code, recovered]);
  const sourceLabel: string = sourceLanguage === "csharp" ? "C#" : sourceLanguage === "fsharp" ? "F#" : "Visual Basic";
  const downloadLabel: string = section === "metadata" ? "JSON" : section === "cil" ? "CIL" : sourceLabel;
  const filename: string = section === "metadata" ? "dotnet-report.json" : `method-${(token ?? 0).toString(16)}.${downloadMetaFor(language).extension}`;
  const shortened: boolean = text.length > PREVIEW_LIMIT;

  return <div className="flex min-w-0 flex-col gap-1 sm:gap-4">
    <h3 className="break-all font-sans text-base font-semibold tracking-tight text-ink sm:text-lg">{result.model.assembly_name ?? result.model.module_name}</h3>
    <div className="flex flex-wrap gap-2"><StatusChip label={result.bitness === "Pe32" ? "PE32" : "PE32+"} /><StatusChip label={result.runtime} /></div>
    <details>
      <summary className="cursor-pointer py-1 font-sans text-xs leading-[18px] text-ink-dim">Recovery details</summary>
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">
        <Metric label="Methods" value={String(methods.length)} />
        <Metric label="Emitted methods" value={String(source.methods_decompiled)} />
        <Metric label="Bodyless" value={String(source.methods_bodyless)} />
        <Metric label="Failed" value={String(source.methods_failed)} />
      </div>
      <p className="py-2 font-sans text-xs text-ink-dim">Counts reflect {sourceLabel} output. Compiler-generated methods may be folded into another method.</p>
    </details>
    {source.methods_failed > 0 ? <p className="font-sans text-sm text-ink-dim">Some methods could not be recovered in {sourceLabel}. Inspect their CIL and the complete metadata report.</p> : null}
    {methods.length > 0 ? <label className="flex min-w-0 flex-col gap-1 font-sans text-xs text-ink-dim">
      <span className="sr-only">Method</span>
      <select aria-label="Method" className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={token} disabled={section === "metadata"} onChange={(event): void => setMethodToken(Number(event.currentTarget.value))}>
        {methods.map((entry): ReactElement => <option key={entry.method.token} value={entry.method.token}>{entry.type}.{entry.method.name} · 0x{entry.method.token.toString(16)}</option>)}
      </select>
    </label> : <p role="status" className="font-sans text-sm text-ink-dim">This assembly declares no methods.</p>}
    <div role="group" aria-label=".NET output" className="flex flex-wrap gap-1.5">
      {SECTIONS.map(([key, label]): ReactElement => <Button className="px-2" key={key} aria-label={key === "vbnet" ? "Visual Basic" : label} aria-pressed={section === key || (section === "source" && sourceLanguage === key)} onClick={(): void => {
        if (key === "cil" || key === "metadata") setSection(key);
        else { setSourceLanguage(key); setSection("source"); }
      }}>{label}</Button>)}
    </div>
    {section === "metadata" ? <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 font-sans text-sm">
      <dt className="text-ink-dim">Module</dt><dd className="break-all text-ink">{result.model.module_name}</dd>
      <dt className="text-ink-dim">Types</dt><dd className="text-ink">{result.model.types.length}</dd>
      <dt className="text-ink-dim">Fields</dt><dd className="text-ink">{result.model.field_count}</dd>
    </dl> : null}
    {section === "cil" && code?.state === "available" ? <div className="flex flex-wrap gap-2"><StatusChip label={`${code.instructions.length} instructions`} /><StatusChip label={`Stack ${code.max_stack}`} /><StatusChip label={`${code.exceptions.length} exception regions`} /></div> : null}
    {section === "cil" && code?.state === "invalid" ? <p role="status" className="break-words font-sans text-sm text-ink-dim">CIL unavailable: {code.error}</p> : null}
    {section !== "metadata" && text.length === 0 && !(section === "cil" && code?.state === "invalid") ? <p role="status" className="font-sans text-sm text-ink-dim">{code?.state === "absent" ? "This method has no stored body. Abstract, native and imported methods may be bodyless." : code?.state === "invalid" ? `Source unavailable: ${code.error}` : "No separate source was emitted for this method. Inspect CIL or the complete metadata report."}</p> : null}
    {text.length > 0 ? <>
      {shortened ? <div className="flex flex-wrap items-center gap-2">
        <Button onClick={(): void => downloadBlob(filename, new Blob([text], { type: downloadMetaFor(language).mime }))}>Download {downloadLabel}</Button>
        <span className="font-sans text-xs text-ink-dim">Preview shortened. Download includes the complete output.</span>
      </div> : null}
      <CodeEditor code={text.slice(0, PREVIEW_LIMIT)} language={language} label={section === "metadata" ? "complete .NET report" : section === "cil" ? "CIL instructions" : `recovered ${sourceLabel} method`} downloadName={shortened ? `preview-${filename}` : filename} downloadLabel={shortened ? "Download preview" : `Download ${downloadLabel}`} />
    </> : null}
  </div>;
}
