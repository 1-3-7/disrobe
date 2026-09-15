import { ExternalLink, FileCode2, Loader2, Play, RotateCcw, Square, Terminal, Upload } from "lucide-react";
import {
  Suspense,
  lazy,
  useEffect,
  useEffectEvent,
  useReducer,
  useRef,
  type ChangeEvent,
  type DragEvent,
  type ReactElement,
} from "react";
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
import { cancel, MAX_INPUT_BYTES, MAX_PYARMOR_RUNTIME_BYTES, PYARMOR_RUNTIME_LIMIT_MESSAGE, inputLimit, preload, run } from "@/wasm/disrobe";
import type { ErrorResult, Outcome } from "@/wasm/types";

const SIDEBAR_COLLAPSED_KEY: string = "disrobe.sidebar.collapsed";

const AboutView = lazy(
  async (): Promise<{ default: typeof import("@/components/AboutView").AboutView }> => {
    const mod = await import("@/components/AboutView");
    return { default: mod.AboutView };
  },
);
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

interface RuntimeInput {
  readonly bytes: Uint8Array;
  readonly name: string;
  readonly origin: "sample" | "file";
}

interface WorkbenchState {
  readonly modeId: string;
  readonly inputBytes: Uint8Array;
  readonly inputName: string;
  readonly textBuffer: string;
  readonly binaryInput: boolean;
  readonly inputOrigin: "sample" | "file" | "edited";
  readonly run: RunState;
  readonly runtime: RuntimeInput | null;
}

type Action =
  | { readonly type: "select_mode"; readonly modeId: string }
  | { readonly type: "load_sample"; readonly input: LoadedInput; readonly runtime: RuntimeInput | null }
  | { readonly type: "load_runtime"; readonly runtime: RuntimeInput | null }
  | { readonly type: "load_file"; readonly input: LoadedInput }
  | { readonly type: "edit_text"; readonly text: string }
  | { readonly type: "run_started" }
  | { readonly type: "run_stopped" }
  | { readonly type: "run_done"; readonly data: unknown }
  | { readonly type: "run_error"; readonly message: string };

interface LoadedInput {
  readonly bytes: Uint8Array;
  readonly name: string;
  readonly text: string;
  readonly binary: boolean;
}

const decoder: TextDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
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
    inputOrigin: "sample",
    runtime: null,
    run: { status: "idle" },
  };
}

function pushModeUrl(id: string): void {
  const url: URL = new URL(window.location.href);
  if (url.searchParams.get("mode") === id) return;
  url.searchParams.set("mode", id);
  window.history.pushState(null, "", url);
}

function reducer(state: WorkbenchState, action: Action): WorkbenchState {
  switch (action.type) {
    case "select_mode": {
      const input: LoadedInput = fileInput(state.inputBytes, state.inputName, modeById(action.modeId)?.inputKind ?? "bytes");
      return { ...state, modeId: action.modeId, textBuffer: input.text, binaryInput: input.binary, runtime: action.modeId === state.modeId ? state.runtime : null, run: { status: "idle" } };
    }
    case "load_sample":
    case "load_file":
      return {
        ...state,
        inputBytes: action.input.bytes,
        inputName: action.input.name,
        textBuffer: action.input.text,
        binaryInput: action.input.binary,
        inputOrigin: action.type === "load_sample" ? "sample" : "file",
        runtime: action.type === "load_sample" ? action.runtime : state.runtime?.origin === "file" ? state.runtime : null,
        run: { status: "idle" },
      };
    case "load_runtime":
      return { ...state, runtime: action.runtime, run: { status: "idle" } };
    case "edit_text":
      return { ...state, runtime: state.runtime?.origin === "file" ? state.runtime : null, textBuffer: action.text, inputBytes: encoder.encode(action.text), inputOrigin: "edited", run: { status: "idle" } };
    case "run_started":
      return { ...state, run: { status: "loading" } };
    case "run_stopped":
      return { ...state, run: { status: "idle" } };
    case "run_done":
      return { ...state, run: { status: "done", data: action.data } };
    case "run_error":
      return { ...state, run: { status: "error", message: action.message } };
  }
}

function fileInput(bytes: Uint8Array, name: string, inputKind: Mode["inputKind"]): LoadedInput {
  if (inputKind === "text") {
    try {
      const text: string = decoder.decode(bytes);
      if (!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(text)) {
        return { bytes, name, text, binary: false };
      }
    } catch (cause: unknown) {
      if (!(cause instanceof TypeError)) throw cause;
    }
  }
  return { bytes, name, text: "", binary: true };
}

async function loadSample(sample: Sample, signal: AbortSignal, inputKind: Mode["inputKind"], maxBytes: number = MAX_INPUT_BYTES): Promise<LoadedInput> {
  const bytes: Uint8Array = await resolveSample(sample, signal, maxBytes);
  if (sample.source.kind === "text") {
    return { bytes, name: sample.label, text: sample.source.text, binary: false };
  }
  return fileInput(bytes, sample.label, inputKind);
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
  const runtimeInputRef = useRef<HTMLInputElement | null>(null);
  const pendingWrapperRef = useRef<Promise<LoadedInput> | null>(null);
  const pendingRuntimeRef = useRef<Promise<RuntimeInput> | null>(null);
  const operationTokenRef = useRef<number>(0);
  const sampleControllerRef = useRef<AbortController | null>(null);
  const initializedRef = useRef<boolean>(false);

  const activeMode: Mode = modeById(state.modeId) ?? fallbackMode();
  const ecosystemId: string = activeEcosystemId(state.modeId);
  const currentBytes: Uint8Array = state.inputBytes;
  const inputSize: number = currentBytes.byteLength;
  const runStateLabel: string = statusLabel(state.run);
  const needsRuntime: boolean = activeMode.entry === "pyarmor_unpack";
  const awaitingPair: boolean = needsRuntime && (state.runtime === null || inputSize === 0);

  function cancelWork(): void {
    sampleControllerRef.current?.abort();
    sampleControllerRef.current = null;
    cancel();
  }

  async function executeBytes(mode: Mode, bytes: Uint8Array, runtime: RuntimeInput | null = null): Promise<void> {
    pendingWrapperRef.current = null;
    pendingRuntimeRef.current = null;
    const token: number = ++operationTokenRef.current;
    cancelWork();
    if (mode.entry === "pyarmor_unpack" && (runtime === null || bytes.byteLength === 0)) {
      dispatch({ type: "run_stopped" });
      return;
    }
    dispatch({ type: "run_started" });
    if (mode.entry === null) {
      dispatch({
        type: "run_error",
        message: `${mode.label} is a reference page, not a runnable pass.`,
      });
      return;
    }
    try {
      const outcome: Outcome<unknown> = await run(mode.entry, bytes, runtime?.bytes);
      if (token !== operationTokenRef.current) {
        return;
      }
      if (isErrorOutcome(outcome)) {
        dispatch({ type: "run_error", message: outcome.error });
        return;
      }
      dispatch({ type: "run_done", data: outcome });
    } catch (cause: unknown) {
      if (token !== operationTokenRef.current) {
        return;
      }
      dispatch({
        type: "run_error",
        message: cause instanceof Error ? cause.message : "analysis failed",
      });
    }
  }

  function execute(): void {
    void executeBytes(activeMode, currentBytes, state.runtime);
  }

  async function selectMode(id: string, input: "current" | "sample" = "current"): Promise<void> {
    const mode: Mode | undefined = modeById(id);
    if (mode === undefined) {
      return;
    }
    const token: number = ++operationTokenRef.current;
    cancelWork();
    pendingWrapperRef.current = null;
    pendingRuntimeRef.current = null;
    dispatch({ type: "select_mode", modeId: id });
    if (mode.reference || mode.entry === null) {
      return;
    }
    if (input === "current" && state.inputOrigin !== "sample") {
      await executeBytes(mode, currentBytes, id === state.modeId ? state.runtime : null);
      return;
    }
    if (mode.sample === undefined) return;
    const sample: Sample = mode.sample;
    const controller: AbortController = new AbortController();
    sampleControllerRef.current = controller;
    dispatch({ type: "run_started" });
    try {
      const [loaded, runtimeBytes]: [LoadedInput, Uint8Array | null, void] = await Promise.all([
        loadSample(sample, controller.signal, mode.inputKind, inputLimit(mode.entry).bytes),
        mode.runtimeSample === undefined ? Promise.resolve(null) : resolveSample(mode.runtimeSample, controller.signal, MAX_PYARMOR_RUNTIME_BYTES),
        preload(),
      ]);
      const runtime: RuntimeInput | null = runtimeBytes === null || mode.runtimeSample === undefined ? null : { bytes: runtimeBytes, name: mode.runtimeSample.label, origin: "sample" };
      if (token !== operationTokenRef.current) {
        return;
      }
      dispatch({ type: "load_sample", input: loaded, runtime });
      await executeBytes(mode, loaded.bytes, runtime);
    } catch (cause: unknown) {
      if (token !== operationTokenRef.current) {
        return;
      }
      cancelWork();
      dispatch({
        type: "run_error",
        message: cause instanceof Error ? cause.message : "could not load sample",
      });
    }
  }

  useEffect((): void => {
    if (initializedRef.current) {
      return;
    }
    initializedRef.current = true;
    void selectMode(state.modeId);
  }, [state.modeId]);

  const restoreMode = useEffectEvent((): void => {
    const modeId: string = initialModeId();
    if (modeId !== state.modeId) void selectMode(modeId);
  });

  useEffect((): (() => void) => {
    const url: URL = new URL(window.location.href);
    url.searchParams.set("mode", initialModeId());
    window.history.replaceState(null, "", url);
    window.addEventListener("popstate", restoreMode);
    return (): void => { window.removeEventListener("popstate", restoreMode); };
  }, []);

  function ingestFile(file: File): void {
    const token: number = ++operationTokenRef.current;
    cancelWork();
    const runtime: RuntimeInput | null = state.runtime?.origin === "file" ? state.runtime : null;
    if (needsRuntime) {
      pendingWrapperRef.current = null;
      dispatch({ type: "load_file", input: fileInput(new Uint8Array(0), file.name, activeMode.inputKind) });
    }
    const limit = inputLimit(activeMode.entry);
    if (file.size > limit.bytes) {
      dispatch({ type: "run_error", message: limit.message });
      return;
    }
    dispatch({ type: "run_started" });
    if (needsRuntime) {
      const reading: Promise<LoadedInput> = file.arrayBuffer().then((buffer: ArrayBuffer): LoadedInput => fileInput(new Uint8Array(buffer), file.name, activeMode.inputKind)).catch((cause: unknown): never => {
        if (pendingWrapperRef.current === reading) pendingWrapperRef.current = null;
        throw cause;
      });
      pendingWrapperRef.current = reading;
      const runtimeReading: Promise<RuntimeInput | null> = pendingRuntimeRef.current ?? Promise.resolve(runtime);
      void Promise.all([reading, runtimeReading]).then(([input, pairedRuntime]: [LoadedInput, RuntimeInput | null]): void => {
        if (token !== operationTokenRef.current) return;
        dispatch({ type: "load_file", input });
        dispatch({ type: "load_runtime", runtime: pairedRuntime });
        void executeBytes(activeMode, input.bytes, pairedRuntime);
      }).catch((cause: unknown): void => {
        if (token !== operationTokenRef.current) return;
        dispatch({ type: "run_error", message: cause instanceof Error ? cause.message : "Could not read the PyArmor wrapper." });
      });
      return;
    }
    void file
      .arrayBuffer()
      .then((buffer: ArrayBuffer): void => {
        if (token !== operationTokenRef.current) {
          return;
        }
        const bytes: Uint8Array = new Uint8Array(buffer);
        dispatch({
          type: "load_file",
          input: fileInput(bytes, file.name, activeMode.inputKind),
        });
        void executeBytes(activeMode, bytes, runtime);
      })
      .catch((cause: unknown): void => {
        if (token !== operationTokenRef.current) {
          return;
        }
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

  function onRuntimePicked(event: ChangeEvent<HTMLInputElement>): void {
    const target: HTMLInputElement = event.currentTarget;
    const file: File | undefined = target.files?.[0];
    target.value = "";
    if (file === undefined) return;
    const token: number = ++operationTokenRef.current;
    cancelWork();
    pendingRuntimeRef.current = null;
    dispatch({ type: "load_runtime", runtime: null });
    if (file.size === 0 || file.size > MAX_PYARMOR_RUNTIME_BYTES) {
      dispatch({ type: "run_error", message: file.size === 0 ? "The PyArmor runtime is empty. Choose the matching runtime file." : PYARMOR_RUNTIME_LIMIT_MESSAGE });
      return;
    }
    dispatch({ type: "run_started" });
    const reading: Promise<RuntimeInput> = file.arrayBuffer().then((buffer: ArrayBuffer): RuntimeInput => ({ bytes: new Uint8Array(buffer), name: file.name, origin: "file" })).catch((cause: unknown): never => {
      if (pendingRuntimeRef.current === reading) pendingRuntimeRef.current = null;
      throw cause;
    });
    pendingRuntimeRef.current = reading;
    const pendingWrapper: Promise<LoadedInput> | null = pendingWrapperRef.current;
    const wrapperReading: Promise<LoadedInput> = pendingWrapper ?? Promise.resolve(fileInput(currentBytes, state.inputName, activeMode.inputKind));
    void Promise.all([reading, wrapperReading]).then(([runtime, input]: [RuntimeInput, LoadedInput]): void => {
      if (token !== operationTokenRef.current) return;
      if (pendingWrapper !== null) dispatch({ type: "load_file", input });
      dispatch({ type: "load_runtime", runtime });
      void executeBytes(activeMode, input.bytes, runtime);
    }).catch((cause: unknown): void => {
      if (token !== operationTokenRef.current) return;
      dispatch({ type: "run_error", message: cause instanceof Error ? cause.message : "Could not read the PyArmor runtime." });
    });
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
    pushModeUrl(id);
    void selectMode(id);
  }

  function jumpToEntry(entry: string): void {
    const target: Mode | undefined = modeByEntry(entry);
    if (target === undefined) {
      return;
    }
    pushModeUrl(target.id);
    dispatch({ type: "select_mode", modeId: target.id });
    void executeBytes(target, currentBytes);
  }

  function useArtifact(name: string, bytes: Uint8Array): void {
    const target: Mode | undefined = modeByEntry("auto_route");
    if (target === undefined) throw new Error("Auto Route is missing");
    pushModeUrl(target.id);
    dispatch({ type: "load_file", input: fileInput(bytes, name, target.inputKind) });
    dispatch({ type: "select_mode", modeId: target.id });
    void executeBytes(target, bytes);
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-canvas text-ink">
      <a className="sr-only z-50 rounded-sm bg-canvas px-4 py-3 text-sm text-ink focus:not-sr-only focus:absolute focus:left-4 focus:top-4" href="#analysis">Skip to analysis</a>
      <header className="shrink-0 border-b border-hairline bg-canvas px-4 py-3 md:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-4">
            <a className="brand-lockup" href="https://1-3-7.github.io/disrobe/" aria-label="disrobe documentation">
              <span className="brand-symbol" aria-hidden="true" />
              <span className="brand-wordmark">disrobe</span>
            </a>
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

        <main className="flex min-h-0 min-w-0 flex-1 flex-col" id="analysis" tabIndex={-1}>
          <div className="shrink-0 border-b border-hairline px-4 py-3 lg:hidden">
            <ModePicker activeMode={activeMode} onSelect={chooseMode} />
          </div>

          {activeMode.reference ? (
            <div className="panel-scroll min-h-0 flex-1 overflow-auto">
              <ResultBoundary>
                <Suspense fallback={<EditorFallback />}>
                  <AboutView />
                </Suspense>
              </ResultBoundary>
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
                  aria-label="Choose an input file"
                  className="sr-only"
                  tabIndex={-1}
                  type="file"
                  onChange={onFilePicked}
                />

                <div className="grid shrink-0 grid-cols-3 gap-px overflow-hidden rounded-sm border border-hairline bg-hairline" data-testid="input-metadata">
                  <div className="bg-inset px-3 py-2">
                    <span className="block font-sans text-[10px] font-medium uppercase tracking-wide text-ink-faint">{state.inputOrigin === "sample" ? "sample" : "input"}</span>
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
                  {state.run.status === "loading" ? (
                    <Button
                      aria-label="Stop analysis"
                      onClick={(): void => {
                        operationTokenRef.current += 1;
                        pendingWrapperRef.current = null;
                        pendingRuntimeRef.current = null;
                        cancelWork();
                        dispatch({ type: "run_stopped" });
                      }}
                    >
                      <Square aria-hidden="true" className="size-3.5" />
                      <span>stop</span>
                    </Button>
                  ) : null}
                  <Button
                    aria-label="Run analysis"
                    disabled={state.run.status === "loading" || awaitingPair}
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
                      void selectMode(state.modeId, "sample");
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

                {needsRuntime ? <div className="flex min-w-0 shrink-0 flex-col gap-2 rounded-sm border border-hairline bg-inset p-3">
                  <input ref={runtimeInputRef} aria-label="Choose PyArmor runtime" className="sr-only" tabIndex={-1} type="file" onChange={onRuntimePicked} />
                  <div className="flex min-w-0 items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="block font-sans text-xs text-ink-dim">PyArmor runtime</span>
                      <span className="mt-1 block truncate font-mono text-xs text-ink" title={state.runtime?.name}>{state.runtime?.name ?? "Matching runtime required"}</span>
                    </div>
                    {state.runtime !== null ? <span className="shrink-0 font-mono text-xs text-ink-dim">{formatBytes(state.runtime.bytes.byteLength)}</span> : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button className="px-2 text-xs" onClick={(): void => runtimeInputRef.current?.click()}>Choose runtime</Button>
                    {state.runtime !== null ? <Button className="px-2 text-xs" onClick={(): void => {
                      operationTokenRef.current += 1;
                      pendingWrapperRef.current = null;
                      pendingRuntimeRef.current = null;
                      cancelWork();
                      dispatch({ type: "load_runtime", runtime: null });
                    }}>Clear runtime</Button> : null}
                  </div>
                  <p className="font-sans text-xs text-ink-dim">Limits: wrapper 1 MiB; runtime 16 MiB.</p>
                </div> : null}

                {state.binaryInput ? (
                  <div className="flex min-h-0 shrink-0 flex-col gap-2">
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
                  <div className={needsRuntime ? "flex min-h-64 flex-1 shrink-0 flex-col gap-2" : "flex min-h-0 flex-1 flex-col gap-2"}>
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
                            operationTokenRef.current += 1;
                            pendingWrapperRef.current = null;
                            pendingRuntimeRef.current = null;
                            cancelWork();
                            dispatch({ type: "edit_text", text: value });
                          }}
                          onRun={(value: string): void => {
                            const runtime: RuntimeInput | null = value === state.textBuffer || state.runtime?.origin === "file" ? state.runtime : null;
                            void executeBytes(activeMode, encoder.encode(value), runtime);
                          }}
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
                  <h2 id="output-heading" className="font-sans text-[12px] font-semibold uppercase tracking-wide text-ink-muted">output</h2>
                </div>
                {state.run.status === "done" ? <StatusChip dot label={activeMode.entry ?? activeMode.id} tone="accent" /> : null}
              </div>

              <div aria-labelledby="output-heading" className="panel-scroll flex min-h-0 flex-1 flex-col overflow-auto p-4" role="region" tabIndex={0}>
                {state.run.status === "idle" ? (
                  <div className="m-auto flex max-w-xs flex-col items-center gap-3 px-6 text-center">
                    <Terminal aria-hidden="true" className="size-6 text-ink-faint/70" />
                    <p className="font-sans text-[13px] leading-relaxed text-ink-muted">
                      {needsRuntime ? awaitingPair ? "Choose a wrapper and its matching runtime, or load the paired sample, to unpack the module." : "Run the current pair to inspect the module." : "Load an artifact or run the current sample to see recovered output here."}
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
                    <p className="mt-2 whitespace-pre-wrap break-words font-mono text-[12.5px] leading-relaxed text-ink">
                      {state.run.message}
                    </p>
                  </div>
                ) : null}

                {state.run.status === "done" ? (
                  <div className="w-full rounded-sm border border-hairline bg-surface p-3">
                    <ResultBoundary>
                      <Suspense fallback={<EditorFallback />}>
                        <ResultView data={state.run.data} mode={activeMode} onJumpToEntry={jumpToEntry} input={currentBytes} onUseInput={useArtifact} />
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
