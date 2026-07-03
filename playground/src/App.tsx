import { ExternalLink, FileCode2, Loader2, Play, RotateCcw, Terminal, Upload } from "lucide-react";
import {
  Suspense,
  lazy,
  useEffect,
  useReducer,
  useRef,
  type ChangeEvent,
  type DragEvent,
  type ReactElement,
} from "react";
import { AboutView } from "@/components/AboutView";
import { ModePicker } from "@/components/ModePicker";
import { ResultBoundary } from "@/components/ResultBoundary";
import { Sidebar } from "@/components/Sidebar";
import { StatusBar } from "@/components/StatusBar";
import { StatusChip } from "@/components/StatusChip";
import { ThemePicker } from "@/components/ThemePicker";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";
import {
  ALL_MODES,
  DEFAULT_MODE_ID,
  ECOSYSTEMS,
  type Mode,
  modeByEntry,
  modeById,
} from "@/lib/modes";
import { resolveSample, type Sample } from "@/lib/samples";
import { usePersistentBoolean } from "@/lib/utils";
import { preload, run } from "@/wasm/disrobe";
import type { ErrorResult, Outcome } from "@/wasm/types";

const SIDEBAR_COLLAPSED_KEY: string = "disrobe.sidebar.collapsed";

const CodeEditor = lazy(
  async (): Promise<{ default: typeof import("@/components/CodeEditor").CodeEditor }> => {
    const mod = await import("@/components/CodeEditor");
    return { default: mod.CodeEditor };
  },
);
const HexViewer = lazy(
  async (): Promise<{ default: typeof import("@/components/HexViewer").HexViewer }> => {
    const mod = await import("@/components/HexViewer");
    return { default: mod.HexViewer };
  },
);
const ResultView = lazy(
  async (): Promise<{ default: typeof import("@/components/ResultView").ResultView }> => {
    const mod = await import("@/components/ResultView");
    return { default: mod.ResultView };
  },
);

type RunState =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "error"; readonly message: string }
  | { readonly status: "done"; readonly data: unknown };

interface WorkbenchState {
  readonly modeId: string;
  readonly inputBytes: Uint8Array;
  readonly inputName: string;
  readonly textBuffer: string;
  readonly binaryInput: boolean;
  readonly run: RunState;
}

type Action =
  | { readonly type: "select_mode"; readonly modeId: string }
  | { readonly type: "load_sample"; readonly input: LoadedInput }
  | { readonly type: "load_file"; readonly input: LoadedInput }
  | { readonly type: "edit_text"; readonly text: string }
  | { readonly type: "run_started" }
  | { readonly type: "run_done"; readonly data: unknown }
  | { readonly type: "run_error"; readonly message: string };

interface LoadedInput {
  readonly bytes: Uint8Array;
  readonly name: string;
  readonly text: string;
  readonly binary: boolean;
}

const decoder: TextDecoder = new TextDecoder("utf-8", { fatal: false });
const encoder: TextEncoder = new TextEncoder();

function fallbackMode(): Mode {
  const mode: Mode | undefined = ALL_MODES[0];
  if (mode === undefined) {
    throw new Error("playground has no analysis modes");
  }
  return mode;
}

function initialModeId(): string {
  const requested: string | null = new URLSearchParams(window.location.search).get("mode");
  return requested !== null && modeById(requested) !== undefined ? requested : DEFAULT_MODE_ID;
}

function initialState(): WorkbenchState {
  return {
    modeId: initialModeId(),
    inputBytes: new Uint8Array(0),
    inputName: "",
    textBuffer: "",
    binaryInput: false,
    run: { status: "idle" },
  };
}

function reducer(state: WorkbenchState, action: Action): WorkbenchState {
  switch (action.type) {
    case "select_mode":
      return { ...state, modeId: action.modeId, run: { status: "idle" } };
    case "load_sample":
    case "load_file":
      return {
        ...state,
        inputBytes: action.input.bytes,
        inputName: action.input.name,
        textBuffer: action.input.text,
        binaryInput: action.input.binary,
      };
    case "edit_text":
      return { ...state, textBuffer: action.text };
    case "run_started":
      return { ...state, run: { status: "loading" } };
    case "run_done":
      return { ...state, run: { status: "done", data: action.data } };
    case "run_error":
      return { ...state, run: { status: "error", message: action.message } };
  }
}

async function loadSample(sample: Sample): Promise<LoadedInput> {
  const bytes: Uint8Array = await resolveSample(sample);
  if (sample.source.kind === "text") {
    return { bytes, name: sample.label, text: sample.source.text, binary: false };
  }
  return { bytes, name: sample.label, text: "", binary: true };
}

function activeEcosystemId(modeId: string): string {
  for (const ecosystem of ECOSYSTEMS) {
    if (ecosystem.modes.some((mode: Mode): boolean => mode.id === modeId)) {
      return ecosystem.id;
    }
  }
  return ECOSYSTEMS[0]?.id ?? "triage";
}

function statusLabel(state: RunState): string {
  switch (state.status) {
    case "done":
      return "ready";
    case "loading":
      return "running";
    case "error":
      return "error";
    case "idle":
      return "idle";
  }
}

function isErrorOutcome(outcome: Outcome<unknown>): outcome is ErrorResult {
  return (
    typeof outcome === "object" &&
    outcome !== null &&
    (outcome as { ok?: unknown }).ok === false
  );
}

function App(): ReactElement {
  const [state, dispatch] = useReducer(reducer, undefined, initialState);
  const [sidebarCollapsed, setSidebarCollapsed] = usePersistentBoolean(SIDEBAR_COLLAPSED_KEY, false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const runTokenRef = useRef<number>(0);
  const initializedRef = useRef<boolean>(false);

  const activeMode: Mode = modeById(state.modeId) ?? fallbackMode();
  const ecosystemId: string = activeEcosystemId(state.modeId);
  const currentBytes: Uint8Array = state.binaryInput
    ? state.inputBytes
    : encoder.encode(state.textBuffer);
  const inputSize: number = currentBytes.byteLength;
  const runStateLabel: string = statusLabel(state.run);

  async function executeBytes(mode: Mode, bytes: Uint8Array): Promise<void> {
    const token: number = runTokenRef.current + 1;
    runTokenRef.current = token;
    dispatch({ type: "run_started" });
    if (mode.entry === null) {
      dispatch({
        type: "run_error",
        message: `${mode.label} is a reference page, not a runnable pass.`,
      });
      return;
    }
    try {
      const outcome: Outcome<unknown> = await run<unknown>(mode.entry, bytes);
      if (token !== runTokenRef.current) {
        return;
      }
      if (isErrorOutcome(outcome)) {
        dispatch({ type: "run_error", message: outcome.error });
        return;
      }
      dispatch({ type: "run_done", data: outcome });
    } catch (cause: unknown) {
      if (token !== runTokenRef.current) {
        return;
      }
      dispatch({
        type: "run_error",
        message: cause instanceof Error ? cause.message : "analysis failed",
      });
    }
  }

  function execute(): void {
    void executeBytes(activeMode, currentBytes);
  }

  async function selectMode(id: string): Promise<void> {
    const mode: Mode | undefined = modeById(id);
    if (mode === undefined) {
      return;
    }
    dispatch({ type: "select_mode", modeId: id });
    if (mode.reference || mode.entry === null || mode.sample === undefined) {
      return;
    }
    const sample: Sample = mode.sample;
    try {
      const loaded: LoadedInput = await loadSample(sample);
      dispatch({ type: "load_sample", input: loaded });
      await executeBytes(mode, loaded.binary ? loaded.bytes : encoder.encode(loaded.text));
    } catch (cause: unknown) {
      dispatch({
        type: "run_error",
        message: cause instanceof Error ? cause.message : "could not load sample",
      });
    }
  }

  useEffect((): void => {
    void preload().catch((): void => {});
  }, []);

  useEffect((): void => {
    if (initializedRef.current) {
      return;
    }
    initializedRef.current = true;
    void selectMode(state.modeId);
  }, [state.modeId]);

  useEffect((): void => {
    const url: URL = new URL(window.location.href);
    url.searchParams.set("mode", state.modeId);
    window.history.replaceState(null, "", url);
  }, [state.modeId]);

  function ingestFile(file: File): void {
    void file
      .arrayBuffer()
      .then((buffer: ArrayBuffer): void => {
        const bytes: Uint8Array = new Uint8Array(buffer);
        if (activeMode.inputKind === "text") {
          const decoded: string = decoder.decode(bytes);
          dispatch({
            type: "load_file",
            input: { bytes, name: file.name, text: decoded, binary: false },
          });
          void executeBytes(activeMode, encoder.encode(decoded));
          return;
        }
        dispatch({
          type: "load_file",
          input: { bytes, name: file.name, text: "", binary: true },
        });
        void executeBytes(activeMode, bytes);
      })
      .catch((cause: unknown): void => {
        dispatch({
          type: "run_error",
          message: cause instanceof Error ? cause.message : "could not read file",
        });
      });
  }

  function onFilePicked(event: ChangeEvent<HTMLInputElement>): void {
    const target: HTMLInputElement = event.currentTarget;
    const file: File | undefined = target.files?.[0];
    target.value = "";
    if (file !== undefined) {
      ingestFile(file);
    }
  }

  function onDrop(event: DragEvent<HTMLElement>): void {
    event.preventDefault();
    const file: File | undefined = event.dataTransfer.files[0];
    if (file !== undefined) {
      ingestFile(file);
    }
  }

  function onDragOver(event: DragEvent<HTMLElement>): void {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }

  function chooseMode(id: string): void {
    void selectMode(id);
  }

  function jumpToEntry(entry: string): void {
    const target: Mode | undefined = modeByEntry(entry);
    if (target === undefined) {
      return;
    }
    dispatch({ type: "select_mode", modeId: target.id });
    void executeBytes(target, currentBytes);
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-canvas text-ink">
      <header className="shrink-0 border-b border-hairline bg-canvas px-4 py-3 md:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-4">
            <span className="font-mono text-[17px] font-bold tracking-tight text-ink">
              disrobe
            </span>
            <div className="hidden items-center gap-1.5 sm:flex">
              <StatusChip label={ecosystemId} tone="muted" />
              <StatusChip
                dot
                label={runStateLabel}
                tone={
                  state.run.status === "error"
                    ? "danger"
                    : state.run.status === "loading"
                      ? "warn"
                      : "accent"
                }
              />
              <StatusChip label={formatBytes(inputSize)} tone="muted" />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ThemePicker />
            <a
              className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-sm border border-hairline bg-surface px-2.5 font-sans text-[12px] text-ink-muted transition-[border-color,background-color,color] hover:border-hairline-strong hover:bg-inset hover:text-ink"
              href="https://github.com/1-3-7/disrobe"
              rel="noreferrer"
              target="_blank"
            >
              <ExternalLink aria-hidden="true" className="size-3.5" />
              <span>github</span>
            </a>
          </div>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <Sidebar
          activeModeId={state.modeId}
          collapsed={sidebarCollapsed}
          ecosystems={ECOSYSTEMS}
          onSelect={chooseMode}
          onToggle={(): void => {
            setSidebarCollapsed(!sidebarCollapsed);
          }}
        />

        <main className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="shrink-0 border-b border-hairline px-4 py-3 lg:hidden">
            <ModePicker activeMode={activeMode} activeModeId={state.modeId} onSelect={chooseMode} />
          </div>

          {activeMode.reference ? (
            <div className="panel-scroll min-h-0 flex-1 overflow-auto">
              <AboutView />
            </div>
          ) : (
            <div className="grid min-h-0 flex-1 grid-cols-1 xl:grid-cols-[minmax(360px,480px)_minmax(0,1fr)]">
            <section
              className="flex min-h-0 flex-col border-b border-hairline xl:border-b-0 xl:border-r"
              onDragOver={onDragOver}
              onDrop={onDrop}
            >
              <div className="border-b border-hairline px-4 py-3">
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <FileCode2 aria-hidden="true" className="size-4 shrink-0 text-accent" />
                    <h1 className="min-w-0 truncate font-sans text-[14px] font-semibold tracking-tight text-ink">
                      {activeMode.label}
                    </h1>
                  </div>
                  <p className="mt-1 max-w-[62ch] font-sans text-[12.5px] leading-relaxed text-ink-muted">
                    {activeMode.blurb}
                  </p>
                </div>
              </div>

              <div className="panel-scroll flex min-h-0 flex-1 flex-col gap-4 overflow-auto p-4">
                <input
                  ref={fileInputRef}
                  className="sr-only"
                  tabIndex={-1}
                  type="file"
                  onChange={onFilePicked}
                />

                <div className="grid grid-cols-3 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline">
                  <div className="bg-inset px-3 py-2">
                    <span className="block font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">sample</span>
                    <span className="mt-1 block truncate font-mono text-[12px] text-ink">{state.inputName || "input"}</span>
                  </div>
                  <div className="bg-inset px-3 py-2">
                    <span className="block font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">size</span>
                    <span className="mt-1 block font-mono text-[12px] text-ink">{formatBytes(inputSize)}</span>
                  </div>
                  <div className="bg-inset px-3 py-2">
                    <span className="block font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">state</span>
                    <span className="mt-1 block font-mono text-[12px] text-ink">{runStateLabel}</span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    aria-label="Run analysis"
                    disabled={state.run.status === "loading"}
                    variant="accent"
                    onClick={execute}
                  >
                    {state.run.status === "loading" ? (
                      <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
                    ) : (
                      <Play aria-hidden="true" className="size-3.5" />
                    )}
                    <span>run</span>
                  </Button>
                  <Button
                    aria-label="Load sample"
                    onClick={(): void => {
                      chooseMode(state.modeId);
                    }}
                  >
                    <RotateCcw aria-hidden="true" className="size-3.5" />
                    <span>sample</span>
                  </Button>
                  <Button
                    aria-label="Upload file"
                    onClick={(): void => {
                      fileInputRef.current?.click();
                    }}
                  >
                    <Upload aria-hidden="true" className="size-3.5" />
                    <span>upload</span>
                  </Button>
                </div>

                {state.binaryInput ? (
                  <div className="flex min-h-0 flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">binary input</span>
                      <StatusChip label="drop a file to load" tone="muted" />
                    </div>
                    <ResultBoundary>
                      <Suspense fallback={<EditorFallback />}>
                        <HexViewer bytes={currentBytes} name={state.inputName || "loaded bytes"} />
                      </Suspense>
                    </ResultBoundary>
                  </div>
                ) : (
                  <div className="flex min-h-0 flex-1 flex-col gap-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">input</span>
                      <StatusChip label="drop a file or Ctrl+Enter to run" tone="muted" />
                    </div>
                    <ResultBoundary>
                      <Suspense fallback={<EditorFallback />}>
                        <CodeEditor
                          editable
                          fill
                          code={state.textBuffer}
                          label={state.inputName || "source"}
                          language={activeMode.inputLanguage}
                          placeholder={`${activeMode.label} input`}
                          onChange={(value: string): void => {
                            dispatch({ type: "edit_text", text: value });
                          }}
                          onRun={execute}
                        />
                      </Suspense>
                    </ResultBoundary>
                  </div>
                )}
              </div>
            </section>

            <section className="flex min-h-0 flex-col">
              <div className="flex items-center justify-between gap-3 border-b border-hairline px-4 py-3">
                <div className="flex items-center gap-2">
                  <Terminal aria-hidden="true" className="size-4 text-accent" />
                  <h2 className="font-sans text-[12px] font-semibold uppercase tracking-wide text-ink-muted">output</h2>
                </div>
                {state.run.status === "done" ? <StatusChip dot label={activeMode.entry ?? activeMode.id} tone="accent" /> : null}
              </div>

              <div className="panel-scroll flex min-h-0 flex-1 flex-col overflow-auto p-4">
                {state.run.status === "idle" ? (
                  <div className="m-auto flex max-w-xs flex-col items-center gap-3 px-6 text-center">
                    <Terminal aria-hidden="true" className="size-6 text-ink-faint/70" />
                    <p className="font-sans text-[13px] leading-relaxed text-ink-muted">
                      Load an artifact or run the current sample to see recovered output here.
                    </p>
                  </div>
                ) : null}

                {state.run.status === "loading" ? (
                  <div aria-busy="true" aria-live="polite" className="flex w-full flex-col gap-3">
                    <div className="h-7 w-44 animate-pulse rounded-sm bg-inset" />
                    <div className="h-28 w-full animate-pulse rounded-sm bg-inset" />
                    <div className="h-44 w-full animate-pulse rounded-sm bg-inset" />
                  </div>
                ) : null}

                {state.run.status === "error" ? (
                  <div className="m-auto w-full max-w-2xl rounded-sm border border-danger/45 bg-danger/[0.05] px-4 py-3" role="alert">
                    <div className="flex items-center gap-2">
                      <span aria-hidden="true" className="size-2 rounded-full bg-danger" />
                      <span className="font-sans text-[12px] font-semibold uppercase tracking-wide text-danger">error</span>
                    </div>
                    <p className="mt-2 break-words font-mono text-[12.5px] leading-relaxed text-ink">
                      {state.run.message}
                    </p>
                  </div>
                ) : null}

                {state.run.status === "done" ? (
                  <div className="w-full rounded-sm border border-hairline bg-surface p-3">
                    <ResultBoundary>
                      <Suspense fallback={<EditorFallback />}>
                        <ResultView data={state.run.data} mode={activeMode} onJumpToEntry={jumpToEntry} />
                      </Suspense>
                    </ResultBoundary>
                  </div>
                ) : null}
              </div>

              <StatusBar
                fields={[
                  { label: "pass", value: activeMode.entry ?? activeMode.id },
                  { label: "in", value: formatBytes(inputSize) },
                  { label: "state", value: runStateLabel },
                ]}
                tone={
                  state.run.status === "error"
                    ? "danger"
                    : state.run.status === "loading"
                      ? "warn"
                      : "accent"
                }
              />
            </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function EditorFallback(): ReactElement {
  return <div aria-hidden="true" className="h-40 w-full animate-pulse rounded-sm bg-inset" />;
}

export default App;
