import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { downloadBlob } from "@/lib/download";
import { languageForSourcePath } from "@/lib/editor";
import type { BundleModule, BundleResult } from "@/wasm/types";

const PREVIEW_LIMIT: number = 64 * 1024;
type ModuleChoice = { readonly module: BundleModule; readonly index: number };
const BUNDLERS: Readonly<Record<string, string>> = {
  webpack4: "Webpack 4", webpack5: "Webpack 5", vite: "Vite", rollup: "Rollup",
  rolldown: "Rolldown", esbuild: "esbuild", turbopack: "Turbopack", bun: "Bun",
  browserify: "Browserify", parcel: "Parcel", systemjs: "SystemJS", amd: "AMD",
};

export function BundleView({ result }: { readonly result: BundleResult }): ReactElement {
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [query, setQuery] = useState<string>("");
  const [showReport, setShowReport] = useState<boolean>(false);
  const report: string = useMemo((): string => JSON.stringify(result, null, 2), [result]);
  const modules: readonly BundleModule[] = result.state === "recognized" ? result.modules : [];
  const filter: string = query.trim().toLowerCase();
  const matches: readonly ModuleChoice[] = modules.map((module, index): ModuleChoice => ({ module, index })).filter(({ module }): boolean => `${module.id} ${module.chunk_id ?? ""}`.toLowerCase().includes(filter));
  const selected: ModuleChoice | undefined = matches.find(({ index }): boolean => index === selectedIndex) ?? matches[0];
  const reportSelected: boolean = showReport || modules.length === 0;
  const source: string = reportSelected ? report : selected?.module.source ?? "";
  const shortened: boolean = source.length > PREVIEW_LIMIT;
  const bundler: string = result.state === "recognized" ? BUNDLERS[result.bundler] ?? result.bundler : "";
  return (
    <section aria-label="JavaScript bundle" className="flex min-w-0 flex-col gap-1 sm:gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label={result.state === "unrecognized" ? "No supported bundle found" : modules.length === 0 ? `${bundler} detected` : `${bundler} · ${modules.length} ${modules.length === 1 ? "module" : "modules"} extracted`} tone={modules.length === 0 ? "neutral" : "accent"} />
      </div>
      {modules.length === 0 ? <p role="status" className="font-sans text-sm text-ink-dim">{result.state === "recognized" ? "Bundle markers were found, but no module bodies could be extracted. A source map may contain the original files." : "Upload a JavaScript bundle with module tables or named exports."}</p> : (
        <div className="flex min-w-0 flex-col gap-2">
          <details className="font-sans text-xs text-ink-dim">
            <summary className="cursor-pointer py-1">{filter.length === 0 ? "Find modules" : `Find modules (${matches.length} ${matches.length === 1 ? "match" : "matches"})`}</summary>
            <input type="search" aria-label="Filter modules" placeholder="Find a module or chunk" value={query} onChange={(event): void => setQuery(event.currentTarget.value)} className="mt-1 w-full min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 font-sans text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" />
          </details>
          <label className="flex min-w-0 flex-col gap-1 font-sans text-xs text-ink-dim">
            Module
            <select disabled={matches.length === 0} value={selected?.index ?? ""} onChange={(event): void => setSelectedIndex(Number(event.currentTarget.value))} className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink">
              {matches.length === 0 ? <option value="">No matching modules</option> : matches.map(({ module, index }): ReactElement => <option key={index} value={index}>{module.id || "Unnamed module"}{module.chunk_id === null ? "" : ` · ${module.chunk_id}`}</option>)}
            </select>
          </label>
        </div>
      )}
      <div role="group" aria-label="Bundle output format" className="flex flex-wrap gap-2">
        <Button className="px-2 text-xs" disabled={selected === undefined} aria-pressed={!reportSelected} onClick={(): void => setShowReport(false)}>Source</Button>
        <Button className="px-2 text-xs" aria-label="JSON report" aria-pressed={reportSelected} onClick={(): void => setShowReport(true)}>JSON</Button>
        <Button className="px-2 text-xs" aria-label={reportSelected ? "Download JSON" : "Download module"} disabled={!reportSelected && selected === undefined} onClick={(): void => {
          if (reportSelected) downloadBlob("bundle-report.json", new Blob([report], { type: "application/json" }));
          else if (selected !== undefined) {
            const basename: string = selected.module.id.split(/[\\/]/u).at(-1) || `module-${selected.index}`;
            downloadBlob(/\.[cm]?[jt]sx?$/iu.test(basename) ? basename : `${basename}.js`, new Blob([selected.module.source], { type: "text/plain;charset=utf-8" }));
          }
        }}>Download</Button>
      </div>
      {shortened ? <p className="font-sans text-xs text-ink-dim">Preview shortened. Downloads contain the complete output.</p> : null}
      {!reportSelected && selected === undefined ? <p role="status" className="font-sans text-sm text-ink-dim">No modules match this search.</p> : <CodeEditor code={shortened ? source.slice(0, PREVIEW_LIMIT) : source} language={reportSelected ? "json" : languageForSourcePath(selected?.module.id ?? "", "javascript")} label={reportSelected ? "bundle report" : "extracted module source"} />}
      {result.state === "recognized" && result.markers.length > 0 ? <details className="rounded-sm border border-hairline bg-inset px-3 py-2">
        <summary className="cursor-pointer font-sans text-xs text-ink">Detection markers</summary>
        <ul className="mt-2 font-mono text-xs text-ink-dim">{result.markers.map((marker, index): ReactElement => <li key={index} className="break-all py-1">{marker}</li>)}</ul>
      </details> : null}
    </section>
  );
}
