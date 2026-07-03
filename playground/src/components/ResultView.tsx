import { ArrowRight } from "lucide-react";
import type { ReactElement, ReactNode } from "react";
import { CodeEditor } from "@/components/CodeEditor";
import { Metric } from "@/components/Metric";
import { StatusChip, type StatusTone } from "@/components/StatusChip";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";
import { type Mode, modeByEntry } from "@/lib/modes";
import { cn } from "@/lib/utils";
import type {
  AntiAnalysisResult,
  As3Result,
  AutoRouteResult,
  BeamResult,
  BehaviorResult,
  EntropyResult,
  IocResult,
  MobileResult,
  ScriptLangResult,
  ShellResult,
  LuaDecompileResult,
  LuaDetectResult,
  PhpDetectResult,
  PickleDecompileResult,
  PickleDisasmResult,
  PicklePolyglotResult,
  PickleSafetyResult,
  PickleTraceResult,
  PyDecompileResult,
  PyDisasmResult,
  RubyDetectResult,
  SecretsResult,
  Severity,
  StringsResult,
  WasmAnalyzeResult,
  WasmCfgResult,
  WasmComponentResult,
  WasmDetectResult,
  WasmEhResult,
  WasmGcTypesResult,
  WasmHighLevelResult,
  WasmMemoriesResult,
  WasmMemoryRecord,
  WasmPreludesResult,
  WasmSignaturesResult,
  WasmSourceMapResult,
  WasmWatResult,
  YaraGenResult,
} from "@/wasm/types";

const SEVERITY_TONE: Readonly<Record<Severity, "accent" | "warn" | "danger">> = {
  benign: "accent",
  suspicious: "warn",
  overtly_malicious: "danger",
};

export interface ResultViewProps {
  readonly mode: Mode;
  readonly data: unknown;
  readonly onJumpToEntry?: (entry: string) => void;
}

function severityLabel(severity: Severity): string {
  return severity.replace(/_/g, " ");
}

function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2) ?? String(value);
}

function fidelityTone(fidelity: string): StatusTone {
  if (fidelity === "Lossless") {
    return "accent";
  }
  if (fidelity === "Lossy") {
    return "warn";
  }
  return "muted";
}

function entropyBarColor(entropy: number): string {
  if (entropy >= 7.0) {
    return "bg-danger";
  }
  if (entropy >= 5.5) {
    return "bg-warn";
  }
  return "bg-accent";
}

function MetricGrid({
  children,
  columns = "sm:grid-cols-3",
}: {
  readonly children: ReactNode;
  readonly columns?: string;
}): ReactElement {
  return (
    <div className={cn("grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline", columns)}>
      {children}
    </div>
  );
}

function ChipRow({ children, className }: { readonly children: ReactNode; readonly className?: string }): ReactElement {
  return <div className={cn("flex flex-wrap items-center gap-1.5", className)}>{children}</div>;
}

function NoteList({ title, notes }: { readonly title: string; readonly notes: readonly string[] }): ReactElement | null {
  if (notes.length === 0) {
    return null;
  }
  return (
    <div className="flex flex-col gap-2">
      <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">{title}</span>
      <ul className="flex flex-col gap-1">
        {notes.map((note: string, index: number): ReactElement => (
          <li
            key={`${title}-${index}`}
            className="rounded-sm border border-hairline bg-inset px-3 py-2 font-mono text-[12px] text-ink-muted"
          >
            {note}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ResultView({ mode, data, onJumpToEntry }: ResultViewProps): ReactElement {
  if (mode.render === "python") {
    if (mode.entry === "py_decompile") {
      const result: PyDecompileResult = data as PyDecompileResult;
      return (
        <div className="flex flex-col gap-4">
          <ChipRow>
            <StatusChip label={`CPython ${result.python_version}`} tone="muted" />
            {result.recovered_directly ? (
              <StatusChip dot label="recovered" tone="accent" />
            ) : (
              <StatusChip dot label="partial fallback" tone="warn" />
            )}
          </ChipRow>
          {result.fallback_reason !== null ? (
            <p className="rounded-sm border border-warn/35 bg-warn/[0.04] px-3 py-2 font-mono text-[12px] text-ink-muted">
              {result.fallback_reason}
            </p>
          ) : null}
          <CodeEditor badge="python" code={result.source} downloadName="recovered.py" label="recovered source" language="python" />
        </div>
      );
    }
    const result: PyDisasmResult = data as PyDisasmResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip label={`CPython ${result.python_version}`} tone="muted" />
          <StatusChip label={`${result.instruction_count} instructions`} tone="muted" />
        </ChipRow>
        <CodeEditor badge="dis" code={result.listing} downloadName="disassembly.txt" label="bytecode disassembly" language="disasm" />
      </div>
    );
  }

  if (mode.render === "pickle") {
    if (mode.entry === "pickle_safety") {
      const result: PickleSafetyResult = data as PickleSafetyResult;
      const tone: "accent" | "warn" | "danger" = SEVERITY_TONE[result.severity];
      return (
        <div className="flex flex-col gap-4">
          <div
            className={cn(
              "flex flex-wrap items-center gap-x-4 gap-y-2 rounded-sm border bg-inset px-4 py-3",
              tone === "danger" ? "border-danger/45" : tone === "warn" ? "border-warn/40" : "border-accent/40",
            )}
          >
            <StatusChip dot label={severityLabel(result.severity)} tone={tone} />
            <StatusChip label={`protocol ${result.protocol}`} tone="muted" />
            <StatusChip
              label={`${result.finding_count} findings`}
              tone={result.finding_count > 0 ? tone : "muted"}
            />
            {result.report.reduce_count > 0 ? (
              <StatusChip label={`${result.report.reduce_count} reduce`} tone="muted" />
            ) : null}
          </div>
          {result.report.findings.length > 0 ? (
            <div className="flex flex-col gap-2">
              <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">findings</span>
              <ul className="flex flex-col gap-1.5">
                {result.report.findings.map((finding, index: number): ReactElement => (
                  <li key={`${finding.category}-${index}`} className="rounded-sm border border-hairline bg-inset px-3 py-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-2">
                        <StatusChip dot label={severityLabel(finding.severity)} tone={SEVERITY_TONE[finding.severity]} />
                        <span className="min-w-0 truncate font-mono text-[12px] text-ink-muted">{finding.category}</span>
                      </div>
                      {finding.offset !== null ? (
                        <span className="font-mono text-[11px] text-ink-faint">@ {finding.offset}</span>
                      ) : null}
                    </div>
                    <p className="mt-1.5 font-mono text-[12.5px] leading-relaxed text-ink">{finding.detail}</p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {result.report.imports.length > 0 ? (
            <div className="flex flex-col gap-2">
              <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">resolved imports</span>
              <ChipRow>
                {result.report.imports.map((importName: string): ReactElement => (
                  <StatusChip key={importName} label={importName} tone="muted" />
                ))}
              </ChipRow>
            </div>
          ) : null}
        </div>
      );
    }
    const result: PickleDisasmResult = data as PickleDisasmResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip label={`protocol ${result.protocol}`} tone="muted" />
          <StatusChip label={`${result.opcode_count} opcodes`} tone="muted" />
        </ChipRow>
        <CodeEditor badge="pickle" code={result.listing} downloadName="pickle-disassembly.txt" label="pickletools disassembly" language="disasm" />
      </div>
    );
  }

  if (mode.render === "pickle-decompile") {
    const result: PickleDecompileResult = data as PickleDecompileResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip label={`protocol ${result.protocol}`} tone="muted" />
          {result.reduce_count > 0 ? (
            <StatusChip dot label={`${result.reduce_count} reduce`} tone="warn" />
          ) : (
            <StatusChip dot label="no reductions" tone="accent" />
          )}
        </ChipRow>
        <CodeEditor badge="python" code={result.assignment} downloadName="reconstructed.py" label="reconstructed object" language="python" />
      </div>
    );
  }

  if (mode.render === "pickle-trace") {
    const result: PickleTraceResult = data as PickleTraceResult;
    return (
      <div className="flex flex-col gap-4">
        <MetricGrid columns="sm:grid-cols-4">
          <Metric label="protocol" value={String(result.protocol)} />
          <Metric label="memo" value={String(result.memo_count)} />
          <Metric label="max stack" value={String(result.max_stack_depth)} />
          <Metric label="reduce" value={String(result.reduce_count)} />
        </MetricGrid>
        <CodeEditor badge="json" code={prettyJson(result.trace)} downloadName="vm-trace.json" label="symbolic vm trace" language="json" />
      </div>
    );
  }

  if (mode.render === "pickle-polyglot") {
    const result: PicklePolyglotResult = data as PicklePolyglotResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.report.is_pickle ? "pickle" : "not pickle"} tone={result.report.is_pickle ? "accent" : "muted"} />
          {result.report.is_polyglot ? <StatusChip dot label="polyglot" tone="warn" /> : null}
        </ChipRow>
        {result.report.kinds.length > 0 ? (
          <ChipRow>
            {result.report.kinds.map((kind: string): ReactElement => (
              <StatusChip key={kind} label={kind} tone="muted" />
            ))}
          </ChipRow>
        ) : null}
        <NoteList notes={result.report.notes} title="notes" />
        {result.report.notes.length === 0 ? (
          <p className="font-mono text-[12px] text-ink-faint">no polyglot framing detected.</p>
        ) : null}
      </div>
    );
  }

  if (mode.render === "wasm") {
    const result: WasmAnalyzeResult = data as WasmAnalyzeResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={result.detection.obfuscator === "None" ? "no obfuscator" : result.detection.obfuscator}
            tone={result.detection.obfuscator === "None" ? "accent" : "warn"}
          />
          <StatusChip
            label={result.summary.names.module_name ? "name section" : "stripped names"}
            tone={result.detection.has_name_section ? "muted" : "warn"}
          />
          {result.summary.has_dwarf ? <StatusChip label="DWARF" tone="muted" /> : null}
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="functions" value={String(result.summary.func_count)} />
          <Metric label="types" value={String(result.summary.type_count)} />
          <Metric label="imports" value={String(result.summary.imports.length)} />
          <Metric label="exports" value={String(result.summary.exports.length)} />
          <Metric label="memories" value={String(result.summary.memory_count)} />
          <Metric label="globals" value={String(result.summary.global_count)} />
          <Metric label="data segs" value={String(result.summary.data_segments)} />
          <Metric label="elem segs" value={String(result.summary.element_segments)} />
          <Metric label="code size" value={formatBytes(result.summary.code_size_bytes)} />
        </MetricGrid>
        {result.summary.exports.length > 0 ? (
          <div className="flex flex-col gap-2">
            <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">exports</span>
            <ChipRow>
              {result.summary.exports.map((name: string): ReactElement => (
                <StatusChip key={name} label={name} tone="muted" />
              ))}
            </ChipRow>
          </div>
        ) : null}
      </div>
    );
  }

  if (mode.render === "wasm-detect") {
    const result: WasmDetectResult = data as WasmDetectResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={result.detection.obfuscator === "None" ? "no obfuscator" : result.detection.obfuscator}
            tone={result.detection.obfuscator === "None" ? "accent" : "warn"}
          />
          <StatusChip label={`confidence ${(result.detection.confidence * 100).toFixed(0)}%`} tone="muted" />
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="functions" value={String(result.detection.function_count)} />
          <Metric label="exports" value={String(result.detection.export_count)} />
          <Metric label="imports" value={String(result.detection.import_count)} />
          <Metric label="name section" value={result.detection.has_name_section ? "yes" : "no"} />
          <Metric label="dwarf" value={result.detection.has_dwarf ? "yes" : "no"} />
        </MetricGrid>
        {result.detection.markers.length > 0 ? (
          <ChipRow>
            {result.detection.markers.map((marker: string, index: number): ReactElement => (
              <StatusChip key={`${marker}-${index}`} label={marker} tone="muted" />
            ))}
          </ChipRow>
        ) : null}
      </div>
    );
  }

  if (mode.render === "wasm-wat") {
    const result: WasmWatResult = data as WasmWatResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.variant} tone="accent" />
          <StatusChip label={`${result.function_count} functions`} tone="muted" />
        </ChipRow>
        <CodeEditor badge="wat" code={result.wat} downloadName="module.wat" label="lifted WebAssembly text" language="wasm" />
      </div>
    );
  }

  if (mode.render === "wasm-highlevel") {
    const result: WasmHighLevelResult = data as WasmHighLevelResult;
    const language: "rust" | "typescript" | "c" =
      result.target === "c" ? "c" : result.target === "rust" ? "rust" : "typescript";
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.target} tone="accent" />
          <StatusChip label={`${result.function_count} functions`} tone="muted" />
        </ChipRow>
        <CodeEditor badge={result.target} code={result.source} downloadName="lifted" label="lifted high-level source" language={language} />
      </div>
    );
  }

  if (mode.render === "wasm-cfg") {
    const result: WasmCfgResult = data as WasmCfgResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`${result.function_count} functions`} tone="accent" />
        </ChipRow>
        {result.functions.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.functions.map((fn): ReactElement => (
              <li key={fn.function_index} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-sm border border-hairline bg-inset px-3 py-2">
                <StatusChip label={`fn #${fn.function_index}`} tone="muted" />
                <span className="font-mono text-[12px] text-ink-muted">{fn.block_count} blocks</span>
                <span className="font-mono text-[12px] text-ink-muted">{fn.edge_count} edges</span>
                <span className="ml-auto font-mono text-[11px] text-ink-faint">entry b{fn.entry}</span>
              </li>
            ))}
          </ul>
        ) : null}
        <CodeEditor badge="json" code={prettyJson(result.functions)} downloadName="wasm-cfg.json" label="per-function control-flow graph" language="json" />
      </div>
    );
  }

  if (mode.render === "wasm-gc-types") {
    const result: WasmGcTypesResult = data as WasmGcTypesResult;
    return (
      <div className="flex flex-col gap-4">
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="structs" value={String(result.struct_count)} />
          <Metric label="arrays" value={String(result.array_count)} />
          <Metric label="abstract refs" value={String(result.abstract_ref_count)} />
        </MetricGrid>
        <CodeEditor badge="rust" code={result.hir.rust_source} downloadName="gc-types" label="reconstructed Rust types" language="rust" />
        <CodeEditor badge="ts" code={result.hir.ts_source} downloadName="gc-types" label="reconstructed TypeScript types" language="typescript" />
      </div>
    );
  }

  if (mode.render === "wasm-eh") {
    const result: WasmEhResult = data as WasmEhResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={result.uses_exception_handling ? "uses EH" : "no EH"}
            tone={result.uses_exception_handling ? "warn" : "accent"}
          />
          {result.uses_modern_eh ? <StatusChip label="modern try_table" tone="muted" /> : null}
          {result.uses_legacy_eh ? <StatusChip label="legacy try" tone="muted" /> : null}
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-2">
          <Metric label="tags" value={String(result.tag_section_count)} />
          <Metric label="functions" value={String(result.function_count)} />
        </MetricGrid>
        <CodeEditor badge="json" code={prettyJson(result.summary)} downloadName="wasm-eh.json" label="exception-handling summary" language="json" />
      </div>
    );
  }

  if (mode.render === "wasm-component") {
    const result: WasmComponentResult = data as WasmComponentResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.classification} tone="accent" />
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="world imports" value={String(result.world_import_count)} />
          <Metric label="world exports" value={String(result.world_export_count)} />
          <Metric label="adapter funcs" value={String(result.adapter_func_count)} />
          <Metric label="embedded modules" value={String(result.embedded_module_count)} />
          <Metric label="embedded comps" value={String(result.embedded_component_count)} />
          <Metric label="world" value={result.bindings.world_name} />
        </MetricGrid>
        <CodeEditor badge="wit" code={result.bindings.wit_source} downloadName="world" label="reconstructed WIT world" language="text" />
        <CodeEditor badge="rust" code={result.bindings.rust_source} downloadName="bindings" label="Rust bindings" language="rust" />
      </div>
    );
  }

  if (mode.render === "wasm-memories") {
    const result: WasmMemoriesResult = data as WasmMemoriesResult;
    const records: readonly WasmMemoryRecord[] = Object.values(result.report.memories);
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`${result.memory_count} memories`} tone={result.memory_count > 1 ? "warn" : "accent"} />
          {result.report.uses_memory64 ? <StatusChip label="memory64" tone="muted" /> : null}
          {result.report.multi_memory ? <StatusChip label="multi-memory" tone="muted" /> : null}
        </ChipRow>
        {records.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {records.map((record): ReactElement => (
              <li key={record.index} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-sm border border-hairline bg-inset px-3 py-2">
                <StatusChip label={`mem #${record.index}`} tone="muted" />
                <span className="font-mono text-[12px] text-ink-muted">{record.memory64 ? "i64" : "i32"} index</span>
                <span className="font-mono text-[12px] text-ink-muted">initial {record.initial}</span>
                <span className="font-mono text-[12px] text-ink-muted">max {record.maximum ?? "none"}</span>
                {record.shared ? <StatusChip label="shared" tone="muted" /> : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no linear memories declared.</p>
        )}
      </div>
    );
  }

  if (mode.render === "wasm-signatures") {
    const result: WasmSignaturesResult = data as WasmSignaturesResult;
    return (
      <div className="flex flex-col gap-4">
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="defined fns" value={String(result.defined_function_count)} />
          <Metric label="imported fns" value={String(result.imported_function_count)} />
          <Metric label="exports" value={String(result.summary.exports.length)} />
          <Metric label="memories" value={String(result.summary.memory_count)} />
          <Metric label="globals" value={String(result.summary.global_count)} />
          <Metric label="code size" value={formatBytes(result.summary.code_size_bytes)} />
        </MetricGrid>
        {result.defined.length > 0 ? (
          <div className="flex flex-col gap-2">
            <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">function signatures</span>
            <ChipRow>
              {result.defined.map((sig, index: number): ReactElement => (
                <StatusChip key={`${sig.name}-${index}`} label={sig.name} tone={sig.exported ? "accent" : "muted"} />
              ))}
            </ChipRow>
          </div>
        ) : null}
        <CodeEditor badge="json" code={prettyJson(result.recovery)} downloadName="wasm-recovery.json" label="recovery report" language="json" />
      </div>
    );
  }

  if (mode.render === "wasm-preludes") {
    const result: WasmPreludesResult = data as WasmPreludesResult;
    return (
      <div className="flex flex-col gap-4">
        <CodeEditor badge="rust" code={result.rust} downloadName="prelude" label="Rust runtime prelude" language="rust" />
        <CodeEditor badge="c" code={result.c} downloadName="prelude" label="C runtime prelude" language="c" />
        <CodeEditor badge="ts" code={result.typescript} downloadName="prelude" label="TypeScript runtime prelude" language="typescript" />
      </div>
    );
  }

  if (mode.render === "wasm-sourcemap") {
    const result: WasmSourceMapResult = data as WasmSourceMapResult;
    return (
      <div className="flex flex-col gap-4">
        <MetricGrid columns="sm:grid-cols-4">
          <Metric label="version" value={String(result.version)} />
          <Metric label="sources" value={String(result.source_count)} />
          <Metric label="names" value={String(result.name_count)} />
          <Metric label="segments" value={String(result.segment_count)} />
        </MetricGrid>
        <CodeEditor badge="json" code={prettyJson(result.source_map)} downloadName="source-map.json" label="parsed source map" language="json" />
      </div>
    );
  }

  if (mode.render === "lua-decompile") {
    const result: LuaDecompileResult = data as LuaDecompileResult;
    const lineCount: number = result.chunk.source.split("\n").length;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip label={result.dialect} tone="muted" />
          <StatusChip dot label={result.fidelity.toLowerCase()} tone={fidelityTone(result.fidelity)} />
          <StatusChip label={`${lineCount} lines`} tone="muted" />
          {result.warning_count > 0 ? <StatusChip label={`${result.warning_count} warnings`} tone="warn" /> : null}
        </ChipRow>
        <CodeEditor badge="lua" code={result.chunk.source} downloadName="recovered.lua" label="recovered source" language="lua" />
      </div>
    );
  }

  if (mode.render === "lua-detect") {
    const result: LuaDetectResult = data as LuaDetectResult;
    return (
      <ChipRow>
        <StatusChip dot label={`dialect: ${result.dialect}`} tone="accent" />
        {result.obfuscator !== null ? (
          <StatusChip dot label={`obfuscator: ${result.obfuscator.kind}`} tone="warn" />
        ) : (
          <StatusChip label="no obfuscator" tone="muted" />
        )}
      </ChipRow>
    );
  }

  if (mode.render === "ruby") {
    const result: RubyDetectResult = data as RubyDetectResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`flavor: ${result.analysis.flavor}`} tone="accent" />
          <StatusChip label={`${result.analysis.input_len} bytes`} tone="muted" />
        </ChipRow>
        <CodeEditor badge="json" code={prettyJson(result.analysis)} downloadName="ruby-analysis.json" label="ruby analysis" language="json" />
      </div>
    );
  }

  if (mode.render === "php") {
    const result: PhpDetectResult = data as PhpDetectResult;
    const recoveredPhp: boolean = result.recovery.output.length > 0;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`kind: ${result.detection.kind}`} tone="accent" />
          <StatusChip label={`confidence: ${result.detection.confidence}`} tone="muted" />
          {result.detection.has_halt_compiler ? <StatusChip label="__HALT_COMPILER" tone="warn" /> : null}
          <StatusChip label={`stage: ${result.recovery.stage}`} tone="muted" />
          {result.recovery.encoder !== null ? (
            <StatusChip label={`encoder: ${result.recovery.encoder}`} tone="warn" />
          ) : null}
        </ChipRow>
        <NoteList notes={result.recovery.notes} title="notes" />
        {recoveredPhp ? (
          <CodeEditor badge="php" code={result.recovery.output} downloadName="recovered.php" label="recovered source" language="php" />
        ) : (
          <CodeEditor badge="json" code={prettyJson(result.recovery)} downloadName="php-recovery.json" label="recovery report" language="json" />
        )}
      </div>
    );
  }

  if (mode.render === "strings") {
    const result: StringsResult = data as StringsResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`${result.report.total} strings`} tone="accent" />
          <StatusChip label={`min len ${result.report.min_len}`} tone="muted" />
          <StatusChip label={formatBytes(result.report.byte_len)} tone="muted" />
        </ChipRow>
        <ul className="flex flex-col gap-1">
          {result.report.strings.slice(0, 200).map((item, index: number): ReactElement => (
            <li key={`${item.offset}-${index}`} className="flex min-w-0 items-center gap-3 rounded-sm border border-hairline bg-inset px-3 py-1.5">
              <span className="shrink-0 font-mono text-[11px] text-ink-faint">
                {item.offset.toString(16).padStart(6, "0")}
              </span>
              <span className="min-w-0 truncate font-mono text-[12.5px] text-ink">{item.value}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  if (mode.render === "ioc") {
    const result: IocResult = data as IocResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`${result.report.total} indicators`} tone={result.report.total > 0 ? "warn" : "muted"} />
        </ChipRow>
        {result.report.total > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.report.indicators.map((indicator, index: number): ReactElement => (
              <li key={`${indicator.kind}-${indicator.offset}-${index}`} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 rounded-sm border border-hairline bg-inset px-3 py-2">
                <StatusChip label={indicator.kind} tone="muted" />
                <span className="min-w-0 break-all font-mono text-[12.5px] text-ink">{indicator.value}</span>
                <span className="ml-auto font-mono text-[11px] text-ink-faint">@ {indicator.offset}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no indicators found.</p>
        )}
      </div>
    );
  }

  if (mode.render === "behavior") {
    const result: BehaviorResult = data as BehaviorResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={`${result.report.categories.length} categories`}
            tone={result.report.categories.length > 0 ? "warn" : "accent"}
          />
          <StatusChip label={formatBytes(result.report.byte_len)} tone="muted" />
        </ChipRow>
        {result.report.categories.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.report.categories.map((category, index: number): ReactElement => (
              <li key={`${category.category}-${index}`} className="rounded-sm border border-hairline bg-inset px-3 py-2.5">
                <span className="font-mono text-[12.5px] text-ink">{category.category}</span>
                <span className="ml-2 font-mono text-[11px] text-ink-faint">{category.evidence.length} hits</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no behavior categories matched.</p>
        )}
      </div>
    );
  }

  if (mode.render === "secrets") {
    const result: SecretsResult = data as SecretsResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={`${result.report.findings.length} findings`}
            tone={result.report.findings.length > 0 ? "danger" : "accent"}
          />
        </ChipRow>
        {result.report.findings.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.report.findings.map((finding, index: number): ReactElement => (
              <li key={`${finding.kind}-${index}`} className="flex items-center gap-3 rounded-sm border border-hairline bg-inset px-3 py-2">
                <StatusChip dot label={finding.kind} tone="danger" />
                <span className="font-mono text-[12px] text-ink-muted">{finding.severity}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no secrets detected.</p>
        )}
      </div>
    );
  }

  if (mode.render === "anti-analysis") {
    const result: AntiAnalysisResult = data as AntiAnalysisResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip
            dot
            label={`${result.report.findings.length} techniques`}
            tone={result.report.findings.length > 0 ? "warn" : "accent"}
          />
        </ChipRow>
        {result.report.findings.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.report.findings.map((finding, index: number): ReactElement => (
              <li key={`${finding.technique}-${index}`} className="rounded-sm border border-hairline bg-inset px-3 py-2 font-mono text-[12.5px] text-ink">
                {finding.technique}
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no anti-analysis markers found.</p>
        )}
      </div>
    );
  }

  if (mode.render === "yara") {
    const result: YaraGenResult = data as YaraGenResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.rule.rule.name} tone="accent" />
          <StatusChip label={`${result.rule.rule.condition}`} tone="muted" />
        </ChipRow>
        <CodeEditor badge="yara" code={result.rule.source} downloadName={result.rule.rule.name} label="generated rule" language="yara" />
      </div>
    );
  }

  if (mode.render === "entropy") {
    const result: EntropyResult = data as EntropyResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip label={`overall ${result.overall.toFixed(2)} bits`} tone="muted" />
          <StatusChip dot label={`${result.high_block_count} high blocks`} tone={result.high_block_count > 0 ? "warn" : "accent"} />
          <StatusChip label={formatBytes(result.byte_len)} tone="muted" />
        </ChipRow>
        <div className="flex flex-col gap-1">
          {result.blocks.map((block, index: number): ReactElement => (
            <div key={`${block.offset}-${index}`} className="flex items-center gap-3">
              <span className="w-16 shrink-0 font-mono text-[11px] text-ink-faint">
                {block.offset.toString(16).padStart(6, "0")}
              </span>
              <div className="h-3 flex-1 overflow-hidden rounded-xs bg-inset">
                <div
                  className={cn("h-full", entropyBarColor(block.entropy))}
                  style={{ width: `${Math.min(100, (block.entropy / 8) * 100)}%` }}
                />
              </div>
              <span className="w-12 shrink-0 text-right font-mono text-[11px] text-ink-muted">
                {block.entropy.toFixed(2)}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (mode.render === "route") {
    const result: AutoRouteResult = data as AutoRouteResult;
    const primaryTarget: Mode | undefined =
      result.primary !== null ? modeByEntry(result.primary.mode) : undefined;
    return (
      <div className="flex flex-col gap-4">
        {result.primary !== null ? (
          <div className="flex flex-col gap-3 rounded-sm border border-accent/35 bg-accent/[0.05] px-4 py-3">
            <ChipRow>
              <StatusChip dot label={`route: ${result.primary.ecosystem}`} tone="accent" />
              <StatusChip label={result.primary.mode} tone="muted" />
            </ChipRow>
            <p className="font-mono text-[12.5px] text-ink">{result.primary.detail}</p>
            {primaryTarget !== undefined && onJumpToEntry !== undefined ? (
              <div>
                <Button
                  aria-label={`Run in ${primaryTarget.label}`}
                  variant="accent"
                  onClick={(): void => {
                    if (primaryTarget.entry !== null) {
                      onJumpToEntry(primaryTarget.entry);
                    }
                  }}
                >
                  <span>{`run in ${primaryTarget.label}`}</span>
                  <ArrowRight aria-hidden="true" className="size-3.5" />
                </Button>
              </div>
            ) : null}
          </div>
        ) : null}
        {result.candidates.length > 0 ? (
          <div className="flex flex-col gap-1.5">
            <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">all candidates</span>
            <ul className="flex flex-col gap-1.5">
              {result.candidates.map((candidate, index: number): ReactElement => {
                const target: Mode | undefined = modeByEntry(candidate.mode);
                return (
                  <li
                    key={`${candidate.ecosystem}-${candidate.mode}-${index}`}
                    className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5 rounded-sm border border-hairline bg-inset px-3 py-2"
                  >
                    <StatusChip label={candidate.ecosystem} tone="muted" />
                    <span className="font-mono text-[12px] text-ink-muted">{candidate.mode}</span>
                    <span className="min-w-0 break-words font-mono text-[12px] text-ink-faint">{candidate.detail}</span>
                    {target !== undefined && onJumpToEntry !== undefined ? (
                      <Button
                        aria-label={`Open ${target.label}`}
                        className="ml-auto"
                        size="sm"
                        variant="ghost"
                        onClick={(): void => {
                          if (target.entry !== null) {
                            onJumpToEntry(target.entry);
                          }
                        }}
                      >
                        <span>open</span>
                        <ArrowRight aria-hidden="true" className="size-3.5" />
                      </Button>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </div>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no matching ecosystem detected.</p>
        )}
      </div>
    );
  }

  if (mode.render === "beam") {
    const result: BeamResult = data as BeamResult;
    const elixir: BeamResult["elixir"] = result.elixir;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.module} tone="accent" />
          <StatusChip label={result.recovered_from} tone="muted" />
          {elixir !== null ? <StatusChip dot label="elixir" tone="accent" /> : null}
        </ChipRow>
        {elixir !== null ? (
          <CodeEditor badge="elixir" code={elixir.source} downloadName="recovered.ex" label="recovered Elixir source" language="text" />
        ) : null}
        <CodeEditor badge="erlang" code={result.erlang_source} downloadName="recovered.erl" label="recovered Erlang source" language="text" />
      </div>
    );
  }

  if (mode.render === "as3") {
    const result: As3Result = data as As3Result;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`${result.class_count} classes`} tone="accent" />
          <StatusChip label={`${result.method_body_count} method bodies`} tone="muted" />
          {result.obfuscation.tools.map((tool: string): ReactElement => (
            <StatusChip key={tool} dot label={tool} tone="warn" />
          ))}
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="printable str %" value={String(result.obfuscation.printable_string_ratio_percent)} />
          <Metric label="mangled id %" value={String(result.obfuscation.identifier_mangle_ratio_percent)} />
          <Metric label="cff density %" value={String(result.obfuscation.control_flow_jump_density_percent)} />
        </MetricGrid>
        <CodeEditor badge="as3" code={result.program} downloadName="recovered.as" label="decompiled ActionScript 3" language="typescript" />
      </div>
    );
  }

  if (mode.render === "scriptlang") {
    const result: ScriptLangResult = data as ScriptLangResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`lang: ${result.artifact.lang}`} tone="accent" />
          {result.classified !== null ? <StatusChip label={result.classified} tone="muted" /> : null}
        </ChipRow>
        <CodeEditor badge="json" code={prettyJson(result.artifact)} downloadName="scriptlang.json" label="recovered artifact" language="json" />
      </div>
    );
  }

  if (mode.render === "shell") {
    const result: ShellResult = data as ShellResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={`dialect: ${result.detection.dialect}`} tone="accent" />
          <StatusChip label={`family: ${result.detection.family}`} tone={result.detection.family === "Plain" ? "muted" : "warn"} />
          <StatusChip label={`confidence ${(result.detection.confidence * 100).toFixed(0)}%`} tone="muted" />
        </ChipRow>
        <MetricGrid columns="sm:grid-cols-3">
          <Metric label="loops unrolled" value={String(result.batch.for_loops_unrolled)} />
          <Metric label="branches folded" value={String(result.batch.if_branches_folded)} />
          <Metric label="cmds emulated" value={String(result.batch.commands_emulated)} />
        </MetricGrid>
        {result.detection.markers.length > 0 ? (
          <ChipRow>
            {result.detection.markers.map((marker: string, index: number): ReactElement => (
              <StatusChip key={`${marker}-${index}`} label={marker} tone="muted" />
            ))}
          </ChipRow>
        ) : null}
        <CodeEditor badge="batch" code={result.batch.output} downloadName="deobfuscated.bat" label="deobfuscated script" language="text" />
      </div>
    );
  }

  if (mode.render === "mobile") {
    const result: MobileResult = data as MobileResult;
    return (
      <div className="flex flex-col gap-4">
        <ChipRow>
          <StatusChip dot label={result.kind} tone={result.kind === "Unknown" ? "muted" : "accent"} />
          <StatusChip label={`${result.child_count} children`} tone="muted" />
        </ChipRow>
        {result.children.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {result.children.map((child, index: number): ReactElement => (
              <li key={`${child.name}-${index}`} className="flex min-w-0 items-center gap-3 rounded-sm border border-hairline bg-inset px-3 py-2">
                <span className="min-w-0 truncate font-mono text-[12.5px] text-ink">{child.name}</span>
                <span className="ml-auto shrink-0 font-mono text-[11px] text-ink-faint">{formatBytes(child.byte_len)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="font-mono text-[12px] text-ink-faint">no extractable top-level children.</p>
        )}
      </div>
    );
  }

  return <CodeEditor badge="json" code={prettyJson(data)} downloadName="result.json" label="result" language="json" />;
}
