import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { downloadBlob } from "@/lib/download";
import { languageForSourcePath } from "@/lib/editor";
import type { SourceMapFile, SourceMapResult } from "@/wasm/types";

const PREVIEW_LIMIT: number = 64 * 1024;

export function SourceMapView({ result }: { readonly result: SourceMapResult }): ReactElement {
  const [selectedPath, setSelectedPath] = useState<string>("");
  const [query, setQuery] = useState<string>("");
  const [showReport, setShowReport] = useState<boolean>(false);
  const report: string = useMemo((): string => JSON.stringify(result, null, 2), [result]);
  if (result.state === "external-reference") return (
    <section aria-label="Source map reference" className="flex min-w-0 flex-col gap-3">
      <StatusChip label="Map file required" tone="warn" />
      <p className="font-sans text-sm text-ink-dim">Upload the referenced map to recover its embedded sources.</p>
      <code className="break-all rounded-sm border border-hairline bg-inset p-3 font-mono text-xs text-ink">{result.url}</code>
    </section>
  );
  if (result.state === "no-map") return (
    <section aria-label="Source map result" className="flex flex-col gap-3">
      <StatusChip label="No source map found" />
      <p className="font-sans text-sm text-ink-dim">Upload a source map, or JavaScript containing an inline source map.</p>
    </section>
  );
  const matches: readonly SourceMapFile[] = result.files.filter((file): boolean => file.path.toLowerCase().includes(query.trim().toLowerCase()));
  const selected: SourceMapFile | undefined = matches.find((file): boolean => file.path === selectedPath) ?? matches[0];
  const reportSelected: boolean = showReport || result.files.length === 0;
  const text: string = reportSelected ? report : selected?.source ?? "";
  const shortened: boolean = text.length > PREVIEW_LIMIT;
  return (
    <section aria-label="Recovered source map" className="flex min-w-0 flex-col gap-1 sm:gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label={`${result.embedded_sources} of ${result.total_sources} ${result.total_sources === 1 ? "original" : "originals"} recovered`} tone={result.embedded_sources === result.total_sources ? "accent" : "warn"} />
        {result.generated_file === null ? null : <span className="min-w-0 break-all font-mono text-xs text-ink-dim">{result.generated_file}</span>}
      </div>
      {result.files.length === 0 ? <p role="status" className="font-sans text-sm text-ink-dim">This map contains no original source text.</p> : (
        <div className="flex min-w-0 flex-col gap-2">
          <details className="font-sans text-xs text-ink-dim">
            <summary className="cursor-pointer py-1">{query.trim().length === 0 ? "Find files" : `Find files (${matches.length} ${matches.length === 1 ? "match" : "matches"})`}</summary>
            <input type="search" aria-label="Filter recovered files" placeholder="Find a source file" value={query} onChange={(event): void => setQuery(event.currentTarget.value)} className="mt-1 w-full min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 font-sans text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" />
          </details>
          <label className="flex min-w-0 flex-col gap-1 font-sans text-xs text-ink-dim">
            Source file
            <select disabled={matches.length === 0} value={selected?.path ?? ""} onChange={(event): void => setSelectedPath(event.currentTarget.value)} className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink">
              {matches.length === 0 ? <option value="">No matching files</option> : matches.map((file): ReactElement => <option key={file.path} value={file.path}>{file.path}</option>)}
            </select>
          </label>
        </div>
      )}
      <div role="group" aria-label="Source map output format" className="flex flex-wrap gap-2">
        <Button className="px-2 text-xs" disabled={selected === undefined} aria-pressed={!reportSelected} onClick={(): void => setShowReport(false)}>Source</Button>
        <Button className="px-2 text-xs" aria-label="JSON report" aria-pressed={reportSelected} onClick={(): void => setShowReport(true)}>JSON</Button>
        <Button className="px-2 text-xs" aria-label={reportSelected ? "Download JSON" : "Download source"} disabled={!reportSelected && selected === undefined} onClick={(): void => {
          if (reportSelected) downloadBlob("source-map-report.json", new Blob([report], { type: "application/json" }));
          else if (selected !== undefined) downloadBlob(selected.path.split("/").at(-1) ?? "source.txt", new Blob([selected.source], { type: "text/plain;charset=utf-8" }));
        }}>Download</Button>
      </div>
      {!showReport && selected?.ignored === true ? <StatusChip label="Listed in ignoreList" /> : null}
      {!showReport && selected?.source.length === 0 ? <p role="status" className="font-sans text-sm text-ink-dim">This original file is empty. Its download is zero bytes.</p> : null}
      {shortened ? <p className="font-sans text-xs text-ink-dim">Preview shortened. Downloads contain the complete output.</p> : null}
      {!reportSelected && selected === undefined ? <p role="status" className="font-sans text-sm text-ink-dim">No files match this search.</p> : <CodeEditor code={shortened ? text.slice(0, PREVIEW_LIMIT) : text} language={reportSelected ? "json" : languageForSourcePath(selected?.path ?? "")} label={reportSelected ? "source map report" : "recovered original source"} />}
      {result.missing_sources.length === 0 ? null : <details className="rounded-sm border border-hairline bg-inset px-3 py-2">
        <summary className="cursor-pointer font-sans text-xs text-ink">Sources without embedded content ({result.missing_sources.length})</summary>
        {result.source_root === null || result.source_root.length === 0 ? null : <p className="mt-2 break-all font-sans text-xs text-ink-dim">Source root: <code>{result.source_root}</code></p>}
        <ul className="mt-2 max-h-48 overflow-auto font-mono text-xs text-ink-dim">{result.missing_sources.map((path, index): ReactElement => <li key={index} className="break-all py-1">{path || "Unnamed source"}</li>)}</ul>
      </details>}
    </section>
  );
}
