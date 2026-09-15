import { useRef, useState, type ReactElement } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";
import { cancel, extractPhar } from "@/wasm/disrobe";
import type { Outcome, PharArtifact, PharMember, PharResult } from "@/wasm/types";

type Extraction =
  | { readonly status: "idle" | "loading" }
  | { readonly status: "error"; readonly message: string }
  | { readonly status: "done"; readonly bytes: ArrayBuffer };

function memberFilename(name: string): string {
  const basename: string = name.split(/[\\/]/u).at(-1) ?? "";
  const cleaned: string = basename.replace(/[<>:"|?*\u0000-\u001f]/gu, "_").replace(/[. ]+$/u, "");
  return cleaned || "phar-member.bin";
}

function downloadMember(name: string, bytes: ArrayBuffer): void {
  const url: string = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const link: HTMLAnchorElement = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function PharView({ result, input, onUseInput }: {
  readonly result: PharResult;
  readonly input: Uint8Array;
  readonly onUseInput: (name: string, bytes: Uint8Array) => void;
}): ReactElement {
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [showReport, setShowReport] = useState<boolean>(false);
  const [extraction, setExtraction] = useState<Extraction>({ status: "idle" });
  const tokenRef = useRef<number>(0);
  const member: PharMember | undefined = result.entries[selectedIndex];
  const busy: boolean = extraction.status === "loading";
  const name: string = memberFilename(member?.name ?? "");

  async function extract(): Promise<void> {
    if (member === undefined) return;
    const token: number = ++tokenRef.current;
    setExtraction({ status: "loading" });
    try {
      const outcome: Outcome<PharArtifact> = await extractPhar(input, member.index);
      if (token !== tokenRef.current) return;
      setExtraction(outcome.ok ? { status: "done", bytes: outcome.bytes } : { status: "error", message: outcome.error });
    } catch (cause: unknown) {
      if (token !== tokenRef.current) return;
      setExtraction({ status: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }

  return (
    <div className="flex min-w-0 flex-col gap-2 sm:gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip label="PHAR archive" />
        <span className="font-sans text-xs text-ink-dim">Extract one member at a time, up to {formatBytes(result.member_limit_bytes)}.</span>
      </div>
      <div className="grid grid-cols-3 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline">
        <Metric label="Members" value={String(result.entries.length)} />
        <Metric label="Stored" value={formatBytes(result.entries.reduce((total, entry) => total + entry.stored_size, 0))} />
        <Metric label="Metadata" value={formatBytes(result.metadata_bytes)} />
      </div>
      {member === undefined ? <p role="status" className="font-sans text-sm text-ink-dim">This archive contains no members.</p> : (
        <>
          <label className="flex min-w-0 flex-col gap-1 font-sans text-xs text-ink-dim">
            Archive member
            <select className="min-w-0 rounded-sm border border-hairline bg-surface px-3 py-2 text-sm text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink" value={selectedIndex} disabled={busy} onChange={(event): void => {
              setSelectedIndex(Number(event.currentTarget.value));
              setExtraction({ status: "idle" });
            }}>
              {result.entries.map((entry): ReactElement => <option key={entry.index} value={entry.index}>{entry.name}</option>)}
            </select>
          </label>
          <p className="font-sans text-xs text-ink-dim">{member.compression === "None" ? "Uncompressed" : member.compression} · {formatBytes(member.stored_size)} stored · {formatBytes(member.uncompressed_size)} declared output</p>
          <div className="flex flex-wrap gap-2">
            {busy ? <Button onClick={(): void => {
              ++tokenRef.current;
              cancel();
              setExtraction({ status: "idle" });
            }}>Cancel extraction</Button> : extraction.status !== "done" ? <Button disabled={!member.extractable} onClick={(): void => { void extract(); }}>Extract member</Button> : null}
            {extraction.status === "done" ? (
              <>
                <Button onClick={(): void => downloadMember(name, extraction.bytes)}>Download member</Button>
                <Button onClick={(): void => onUseInput(name, new Uint8Array(extraction.bytes))}>Use as input</Button>
              </>
            ) : null}
          </div>
          {!member.extractable ? <p role="status" className="font-sans text-sm text-ink-dim">This member exceeds the browser extraction limit. Use the CLI to extract it.</p> : null}
          {busy ? <p role="status" className="font-sans text-sm text-ink-dim">Extracting member…</p> : null}
          {extraction.status === "done" ? <p role="status" className="font-sans text-sm text-ink-dim">{formatBytes(extraction.bytes.byteLength)} extracted. Download the file or use it as input for another pass.</p> : null}
          {extraction.status === "error" ? <p role="alert" className="font-sans text-sm text-danger">{extraction.message}</p> : null}
        </>
      )}
      <details onToggle={(event): void => setShowReport(event.currentTarget.open)}>
        <summary className="cursor-pointer py-2 font-sans text-xs text-ink-dim">JSON report</summary>
        <p className="mb-2 font-sans text-xs text-ink-dim">Checksums and flags are archive metadata. Extraction does not verify the archive signature.</p>
        {showReport ? <CodeEditor code={JSON.stringify(result, null, 2)} label="complete PHAR report" language="json" downloadName="phar-report.json" /> : null}
      </details>
    </div>
  );
}
