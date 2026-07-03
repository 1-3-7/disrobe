import { expose } from "comlink";
import wasmUrl from "./disrobe_wasm.wasm?url";
import type { ErrorResult, Outcome } from "./types";

export type EntryName =
  | "detect"
  | "auto_route"
  | "py_disasm"
  | "py_decompile"
  | "pickle_disasm"
  | "pickle_safety"
  | "pickle_decompile"
  | "pickle_trace"
  | "pickle_polyglot"
  | "wasm_analyze"
  | "wasm_detect"
  | "wasm_decompile_wat"
  | "wasm_faithful_wat"
  | "wasm_lift_rust"
  | "wasm_lift_ts"
  | "wasm_lift_c"
  | "wasm_cfg"
  | "wasm_gc_types"
  | "wasm_eh"
  | "wasm_component"
  | "wasm_memories"
  | "wasm_signatures"
  | "wasm_preludes"
  | "wasm_source_map"
  | "lua_detect"
  | "lua_decompile"
  | "ruby_detect"
  | "php_detect"
  | "beam_recover"
  | "as3_analyze"
  | "scriptlang_analyze"
  | "shell_deob"
  | "mobile_detect"
  | "strings"
  | "ioc"
  | "behavior"
  | "secrets"
  | "anti_analysis"
  | "yara_gen"
  | "entropy";

type EntryFn = (ptr: number, len: number) => number;

interface DisrobeExports {
  readonly memory: WebAssembly.Memory;
  readonly disrobe_alloc: (len: number) => number;
  readonly disrobe_free: (ptr: number, len: number) => void;
  readonly disrobe_result_len: (ptr: number) => number;
  readonly disrobe_result_free: (ptr: number) => void;
}

interface LoadedModule {
  readonly core: DisrobeExports;
  readonly entries: Readonly<Record<EntryName, EntryFn>>;
}

const ENTRY_NAMES: readonly EntryName[] = [
  "detect",
  "auto_route",
  "py_disasm",
  "py_decompile",
  "pickle_disasm",
  "pickle_safety",
  "pickle_decompile",
  "pickle_trace",
  "pickle_polyglot",
  "wasm_analyze",
  "wasm_detect",
  "wasm_decompile_wat",
  "wasm_faithful_wat",
  "wasm_lift_rust",
  "wasm_lift_ts",
  "wasm_lift_c",
  "wasm_cfg",
  "wasm_gc_types",
  "wasm_eh",
  "wasm_component",
  "wasm_memories",
  "wasm_signatures",
  "wasm_preludes",
  "wasm_source_map",
  "lua_detect",
  "lua_decompile",
  "ruby_detect",
  "php_detect",
  "beam_recover",
  "as3_analyze",
  "scriptlang_analyze",
  "shell_deob",
  "mobile_detect",
  "strings",
  "ioc",
  "behavior",
  "secrets",
  "anti_analysis",
  "yara_gen",
  "entropy",
];

const CORE_EXPORTS: readonly string[] = [
  "memory",
  "disrobe_alloc",
  "disrobe_free",
  "disrobe_result_len",
  "disrobe_result_free",
];

const RESULT_HEADER_LEN: number = 4;
const textDecoder: TextDecoder = new TextDecoder("utf-8", { fatal: false });

function hasCoreExports(value: WebAssembly.Exports): value is WebAssembly.Exports & DisrobeExports {
  return CORE_EXPORTS.every((name: string): boolean => name in value);
}

function entryOf(value: WebAssembly.Exports, name: EntryName): EntryFn {
  const candidate: unknown = (value as Record<string, unknown>)[name];
  if (typeof candidate !== "function") {
    throw new Error(`wasm module is missing the ${name} export`);
  }
  return candidate as EntryFn;
}

let instancePromise: Promise<LoadedModule> | null = null;

async function load(): Promise<LoadedModule> {
  const { instance }: WebAssembly.WebAssemblyInstantiatedSource =
    await WebAssembly.instantiateStreaming(fetch(wasmUrl), {});
  if (!hasCoreExports(instance.exports)) {
    throw new Error("wasm module is missing one or more disrobe core exports");
  }
  const entries: Record<EntryName, EntryFn> = {} as Record<EntryName, EntryFn>;
  for (const name of ENTRY_NAMES) {
    entries[name] = entryOf(instance.exports, name);
  }
  return { core: instance.exports, entries };
}

function moduleHandle(): Promise<LoadedModule> {
  instancePromise ??= load();
  return instancePromise;
}

function invoke<T>(mod: LoadedModule, entry: EntryName, input: Uint8Array): Outcome<T> {
  const len: number = input.byteLength;
  const inputPtr: number = mod.core.disrobe_alloc(len);
  if (inputPtr === 0 && len !== 0) {
    return { ok: false, error: "wasm allocation failed" } satisfies ErrorResult;
  }
  let resultPtr: number = 0;
  try {
    new Uint8Array(mod.core.memory.buffer, inputPtr, len).set(input);
    resultPtr = mod.entries[entry](inputPtr, len);
    if (resultPtr === 0) {
      return { ok: false, error: "wasm entry returned a null result" } satisfies ErrorResult;
    }
    const payloadLen: number = mod.core.disrobe_result_len(resultPtr);
    const jsonBytes: Uint8Array = new Uint8Array(
      mod.core.memory.buffer,
      resultPtr + RESULT_HEADER_LEN,
      payloadLen,
    ).slice();
    const json: string = textDecoder.decode(jsonBytes);
    return JSON.parse(json) as Outcome<T>;
  } catch (cause: unknown) {
    const reason: string = cause instanceof Error ? cause.message : String(cause);
    return { ok: false, error: `marshalling failed: ${reason}` } satisfies ErrorResult;
  } finally {
    if (resultPtr !== 0) {
      mod.core.disrobe_result_free(resultPtr);
    }
    mod.core.disrobe_free(inputPtr, len);
  }
}

export interface DisrobeWorkerApi {
  preload(): Promise<void>;
  run(entry: EntryName, input: ArrayBuffer): Promise<Outcome<unknown>>;
}

const api: DisrobeWorkerApi = {
  async preload(): Promise<void> {
    await moduleHandle();
  },
  async run(entry: EntryName, input: ArrayBuffer): Promise<Outcome<unknown>> {
    return invoke<unknown>(await moduleHandle(), entry, new Uint8Array(input));
  },
};

expose(api);
