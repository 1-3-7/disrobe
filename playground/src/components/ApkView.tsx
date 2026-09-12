import { useMemo, useState, type ReactElement } from "react";
import { CodeEditor, type CodeEditorProps } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import type { ApkManifest, ApkResult } from "@/wasm/types";

type OutputKind = "manifest" | "resources" | "report";

interface ResourceFile {
  readonly id: string;
  readonly path: string;
  readonly xml: string;
}

export function ApkView({ result }: { readonly result: ApkResult }): ReactElement {
  const [outputKind, setOutputKind] = useState<OutputKind>("manifest");
  const [resourceId, setResourceId] = useState<string>("");
  const manifest: ApkManifest = result.report.manifest;
  const files: readonly ResourceFile[] = useMemo((): readonly ResourceFile[] => [
    ...result.report.resources_decoded.decoded_xml.map((file): ResourceFile => ({ id: `xml:${file.path}`, path: file.path, xml: file.xml })),
    ...result.report.resources_decoded.values_files.map((file): ResourceFile => ({ id: `values:${file.virtual_path}`, path: file.virtual_path, xml: file.xml })),
  ], [result]);
  const selected: ResourceFile | undefined = files.find((file) => file.id === resourceId) ?? files[0];
  const output: CodeEditorProps | null = useMemo((): CodeEditorProps | null => {
    if (outputKind === "report") {
      return { code: JSON.stringify(result, null, 2), language: "json", label: "complete APK report", downloadName: "apk-report.json" };
    }
    if (outputKind === "resources") {
      if (selected === undefined) return null;
      return {
        code: selected.xml,
        language: "xml",
        label: selected.path,
        downloadName: selected.path.split("/").at(-1) ?? "resource.xml",
      };
    }
    return { code: result.report.manifest_xml, language: "xml", label: "AndroidManifest.xml", downloadName: "AndroidManifest.xml" };
  }, [outputKind, result, selected]);
  const xmlCount: number = result.report.resources_decoded.decoded_xml.length;

  return (
    <div className="flex flex-col gap-1 sm:gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label="Android APK" />
        <StatusChip label={`Resource table ${result.resource_table_status}`} tone={result.resource_table_status === "undecoded" ? "warn" : "muted"} />
        {result.report.signing.schemes.map(({ scheme }): ReactElement => <StatusChip key={scheme} label={`Signing ${scheme.replace("-", ".")}`} />)}
      </div>
      {result.report.signing.signing_block_present ? <p className="font-sans text-xs text-ink-dim">Signatures are parsed, not verified.</p> : null}
      <div role="group" aria-label="APK output format" className="flex flex-wrap gap-2">
        <Button className="px-2 sm:px-3" aria-pressed={outputKind === "manifest"} onClick={(): void => setOutputKind("manifest")}>Manifest</Button>
        <Button className="px-2 sm:px-3" aria-pressed={outputKind === "resources"} onClick={(): void => setOutputKind("resources")}>Resources</Button>
        <Button className="px-2 sm:px-3" aria-pressed={outputKind === "report"} onClick={(): void => setOutputKind("report")}>JSON report</Button>
      </div>
      <details className="rounded-sm border border-hairline bg-inset px-3 py-1 sm:py-2">
        <summary className="cursor-pointer break-all font-mono text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink">
          <span>{manifest.package}</span>
        </summary>
        <p className="my-3 font-sans text-xs text-ink-dim">Version {manifest.version_name ?? manifest.version_code ?? "unspecified"} · Minimum SDK {manifest.min_sdk_version ?? "unspecified"} · Target SDK {manifest.target_sdk_version ?? "unspecified"}</p>
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline sm:grid-cols-4">
          <Metric label="Archive entries" value={String(result.entry_count)} />
          <Metric label="Permissions" value={String(manifest.permissions.length)} />
          <Metric label="Resource XML" value={`${xmlCount} / ${result.resource_xml_entries}`} />
          <Metric label="Native libraries" value={String(result.report.native_libraries.length)} />
        </div>
      </details>
      {xmlCount < result.resource_xml_entries ? <p role="status" className="font-sans text-sm text-ink-dim">{result.resource_xml_entries - xmlCount} resource XML entries could not be decoded. Recovered files remain available.</p> : null}
      {result.resource_table_status === "undecoded" ? <p role="status" className="font-sans text-sm text-ink-dim">The resource table could not be decoded. Resource names and values may remain unresolved.</p> : null}
      {outputKind === "resources" && selected !== undefined ? <label className="flex flex-col gap-2 font-sans text-xs text-ink-dim">
        Resource file
        <select className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={selected.id} onChange={(event): void => setResourceId(event.currentTarget.value)}>
          {files.map((file): ReactElement => <option key={file.id} value={file.id}>{file.path}</option>)}
        </select>
      </label> : null}
      {output === null ? <p role="status" className="font-sans text-sm text-ink-dim">No resource XML files were recovered from this package.</p> : <CodeEditor {...output} />}
    </div>
  );
}
