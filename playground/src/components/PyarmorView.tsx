import { useMemo, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";
import { downloadBlob as download } from "@/lib/download";
import type { PyarmorModuleResult } from "@/wasm/types";

const PREVIEW_LIMIT: number = 64 * 1024;

export function PyarmorView({ result }: { readonly result: PyarmorModuleResult }): ReactElement {
  const text: string = useMemo((): string => {
    const { bytes: _bytes, ...metadata } = result;
    return JSON.stringify(metadata, null, 2);
  }, [result]);
  const shortened: boolean = text.length > PREVIEW_LIMIT;
  return <section aria-label="PyArmor module" className="flex min-w-0 flex-col gap-2 sm:gap-4">
    <div className="flex flex-wrap gap-2">
      <StatusChip label={`Runtime format ${result.runtime_format}`} />
      <StatusChip label={`Python ${result.python_version}`} />
      <StatusChip label="Marshal code object parsed" tone="accent" />
    </div>
    <p className="font-sans text-xs text-ink-dim">Downloads contain the outer module and its marshal payload. Inner bytecode is unchanged.</p>
    <div className="grid grid-cols-2 gap-2">
      <Button className="px-2 text-xs" onClick={(): void => download("pyarmor-module.marshal", new Blob([result.bytes.slice(result.marshal_offset)], { type: "application/octet-stream" }))}>Download marshal</Button>
      <Button className="px-2 text-xs" onClick={(): void => download("pyarmor-module.bin", new Blob([result.bytes], { type: "application/octet-stream" }))}>Download module</Button>
    </div>
    <details className="rounded-sm border border-hairline bg-inset px-3 py-2">
      <summary className="cursor-pointer font-sans text-xs text-ink">Module details</summary>
      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 font-sans text-xs text-ink-dim">
        {[["Runtime architecture", result.runtime_arch], ["Module size", formatBytes(result.bytes.byteLength)], ["Marshal offset", String(result.marshal_offset)], ["Code objects", String(result.code_objects)], ["Names", String(result.names.length)], ["Strings", String(result.strings.length)]].map(([label, value]): ReactElement => <div key={label} className="min-w-0"><dt>{label}</dt><dd className="mt-1 break-all font-mono text-ink">{value}</dd></div>)}
      </dl>
    </details>
    <details className="min-w-0 rounded-sm border border-hairline bg-surface p-3">
      <summary className="cursor-pointer font-sans text-xs text-ink">JSON report</summary>
      <div className="mt-3 flex min-w-0 flex-col gap-3">
        {shortened ? <p className="font-sans text-xs text-ink-dim">Excerpt shown. Download includes full JSON.</p> : null}
        <Button className="self-start" onClick={(): void => download("pyarmor-module.json", new Blob([text], { type: "application/json" }))}>Download JSON</Button>
        <CodeEditor code={shortened ? text.slice(0, PREVIEW_LIMIT) : text} language="json" label={shortened ? "module metadata excerpt" : "module metadata"} />
      </div>
    </details>
  </section>;
}
