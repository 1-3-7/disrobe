import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import type { GoFunction, GoResult, GoType } from "@/wasm/types";

type Section = "functions" | "types" | "build" | "report";
const PAGE_SIZE: number = 20;
const PREVIEW_LIMIT: number = 128 * 1024;

function JsonOutput({ value, filename, label }: {
  readonly value: GoResult | GoType | NonNullable<GoResult["build_info"]>;
  readonly filename: string;
  readonly label: string;
}): ReactElement {
  const text: string = useMemo((): string => JSON.stringify(value, null, 2), [value]);
  const shortened: boolean = text.length > PREVIEW_LIMIT;
  function download(): void {
    const url: string = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const anchor: HTMLAnchorElement = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }
  return <div className="flex min-w-0 flex-col gap-3">
    <div className="flex flex-wrap items-center justify-between gap-2">
      {shortened ? <p className="font-sans text-xs text-ink-dim">Excerpt shown. Download includes full JSON.</p> : null}
      <Button aria-label="Download output" onClick={download}>Download JSON</Button>
    </div>
    <CodeEditor code={shortened ? text.slice(0, PREVIEW_LIMIT) : text} language="json" label={shortened ? `${label} · excerpt` : label} />
  </div>;
}

function RecordList<T extends { readonly name: string | null }>({ records, noun, onSelect, selected }: {
  readonly records: readonly T[];
  readonly noun: "function" | "type";
  readonly onSelect: (record: T) => void;
  readonly selected: T | undefined;
}): ReactElement {
  const [query, setQuery] = useState<string>("");
  const [page, setPage] = useState<number>(0);
  const matches: readonly T[] = useMemo((): readonly T[] => {
    const term: string = query.trim().toLowerCase();
    return term === "" ? records : records.filter((record): boolean => (record.name ?? "").toLowerCase().includes(term));
  }, [query, records]);
  const lastPage: number = Math.max(0, Math.ceil(matches.length / PAGE_SIZE) - 1);
  const currentPage: number = Math.min(page, lastPage);
  const start: number = currentPage * PAGE_SIZE;
  return <div className="flex min-w-0 flex-col gap-2">
    <label className="flex flex-col gap-2 font-sans text-xs text-ink-dim">
      Find a {noun}
      <input type="search" value={query} onChange={(event): void => { setQuery(event.currentTarget.value); setPage(0); }} className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" />
    </label>
    <div className="max-h-72 overflow-y-auto rounded-sm border border-hairline" role="group" aria-label={noun === "function" ? "Go functions" : "Go types"}>
      {matches.slice(start, start + PAGE_SIZE).map((record, index): ReactElement => <button key={start + index} type="button" aria-pressed={selected === record} onClick={(): void => onSelect(record)} className="block w-full break-all border-b border-hairline bg-surface px-3 py-2 text-left font-mono text-xs text-ink last:border-b-0 hover:bg-hover aria-pressed:bg-inset focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ink">{record.name ?? "Unnamed type"}</button>)}
      {matches.length === 0 ? <p role="status" className="px-3 py-4 font-sans text-sm text-ink-dim">No matching {noun === "function" ? "functions" : "types"}.</p> : null}
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="font-mono text-xs text-ink-dim">{matches.length === 0 ? "0" : `${start + 1}–${Math.min(start + PAGE_SIZE, matches.length)}`} of {matches.length}</span>
      <div className="flex gap-2">
        <Button aria-label={`Previous ${noun} page`} disabled={currentPage === 0} onClick={(): void => setPage(currentPage - 1)}>Previous</Button>
        <Button aria-label={`Next ${noun} page`} disabled={currentPage === lastPage} onClick={(): void => setPage(currentPage + 1)}>Next</Button>
      </div>
    </div>
  </div>;
}

function Details({ rows }: { readonly rows: readonly (readonly [string, string])[] }): ReactElement {
  return <dl className="grid min-w-0 grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-3 gap-y-2 rounded-sm border border-hairline bg-inset p-3 text-xs">
    {rows.map(([label, value]): ReactElement => <div key={label} className="contents">
      <dt className="font-sans text-ink-dim">{label}</dt><dd className="m-0 break-all font-mono text-ink">{value}</dd>
    </div>)}
  </dl>;
}

const NO_FUNCTIONS: readonly GoFunction[] = [];
const NO_TYPES: readonly GoType[] = [];

export function GoView({ result }: { readonly result: GoResult }): ReactElement {
  const [section, setSection] = useState<Section>(result.symbols === null ? "build" : "functions");
  const [selectedFunction, setSelectedFunction] = useState<GoFunction>();
  const [selectedType, setSelectedType] = useState<GoType>();
  const functions: readonly GoFunction[] = result.symbols?.functions ?? NO_FUNCTIONS;
  const types: readonly GoType[] = result.types?.types ?? NO_TYPES;
  const fn: GoFunction | undefined = selectedFunction ?? functions.find((record): boolean => record.name === "main.main") ?? functions[0];
  const ty: GoType | undefined = selectedType ?? types[0];
  const build = result.build_info;
  return <section aria-label="Go metadata" className="flex min-w-0 flex-col gap-1 sm:gap-4">
    <div className="flex flex-wrap gap-2">
      <StatusChip label={build?.go_version ?? "Go version unavailable"} />
      <StatusChip label={`${result.container} · ${result.pointer_width}-bit`} tone="muted" />
    </div>
    <div className="grid grid-cols-3 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline">
      <Metric label="Functions" value={result.symbols === null ? "Not found" : String(functions.length)} />
      <Metric label="Types" value={result.types === null ? "Not found" : String(types.length)} />
      <Metric label="Packages" value={result.symbols === null ? "Not found" : String(result.symbols.packages.length)} />
    </div>
    <div role="group" aria-label="Go output" className="flex flex-wrap gap-2">
      {([["functions", "Functions"], ["types", "Types"], ["build", "Build info"], ["report", "JSON report"]] as const).map(([key, label]): ReactElement => <Button key={key} aria-pressed={section === key} onClick={(): void => setSection(key)}>{label}</Button>)}
    </div>
    {section === "functions" ? result.symbols === null ? <p role="status" className="font-sans text-sm text-ink-dim">No Go function table was found. Build information is available separately.</p> : <>
      <RecordList key="functions" records={functions} noun="function" selected={fn} onSelect={setSelectedFunction} />
      {fn !== undefined ? <Details rows={[
        ["Function", fn.name],
        ["Address", fn.address ?? "Unavailable"],
        ["Table entry", fn.entry],
        ["Table end", fn.end],
        ["Source", fn.file === null ? "Unavailable" : `${fn.file}${fn.start_line === null ? "" : `:${fn.start_line}`}`],
        ["Linker symbol", fn.linker_symbol ?? "Unavailable"],
        ["ABI0 wrapper", fn.abi0 ? "Yes" : "No"],
      ]} /> : null}
    </> : null}
    {section === "types" ? result.types === null ? <p role="status" className="font-sans text-sm text-ink-dim">Runtime type metadata was not located.</p> : <>
      {result.types.traversal_limit_reached ? <p role="status" className="font-sans text-sm text-ink-dim">The 16,384-type traversal limit was reached.</p> : null}
      <RecordList key="types" records={types} noun="type" selected={ty} onSelect={setSelectedType} />
      {ty !== undefined ? <>
        <Details rows={[["Type", ty.name ?? "Unnamed"], ["Kind", ty.kind_label ?? "Unknown"], ["Address", ty.address], ["Fields", String(ty.fields.length)], ["Methods", String(ty.methods.length + ty.interface_methods.length)]]} />
        {ty.fields_rejected || ty.interface_methods_rejected ? <p role="status" className="font-sans text-sm text-ink-dim">Some field or interface records were rejected. Their rejection flags are preserved in the report.</p> : null}
        <JsonOutput value={ty} label="selected Go type" filename="go-type.json" />
        <p className="font-sans text-xs text-ink-dim">Method address 0x0 means unavailable. The complete report includes interface tables and generic instantiations.</p>
      </> : null}
    </> : null}
    {section === "build" ? build === null ? <p role="status" className="font-sans text-sm text-ink-dim">No Go build information was found.</p> : <>
      <Details rows={[["Import path", build.path ?? "Unavailable"], ["Main module", build.main?.path ?? "Unavailable"], ["Module version", build.main?.version ?? "Unavailable"], ["Target", [build.settings?.GOOS, build.settings?.GOARCH].filter(Boolean).join("/") || "Unavailable"], ["Dependencies", String(build.deps?.length ?? 0)], ["Runtime module", result.module?.source === undefined || result.module.source === "None" ? "Not located" : "Located"]]} />
      <JsonOutput value={build} label="Go build information" filename="go-build.json" />
    </> : null}
    {section === "report" ? <JsonOutput value={result} label="complete Go metadata" filename="go-metadata.json" /> : null}
  </section>;
}
