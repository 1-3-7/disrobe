import { expose, transfer } from "comlink";
import wasmUrl from "./disrobe_wasm.wasm?url";
import { formatSource, isSourceFormatEntry, type SourceFormatEntry } from "./source-format";
import type { ErrorResult, Outcome, PharArtifact, PyarmorModuleMetadata, PyarmorModuleResult } from "./types";

export type EntryName =
  | SourceFormatEntry
  | "js_unbundle"
  | "source_map_recover"
  | "detect"
  | "auto_route"
  | "py_disasm"
  | "py_decompile"
  | "pyarmor_detect"
  | "pyarmor_classify"
  | "pyarmor_unpack"
  | "swift_objc"
  | "hermes_analyze"
  | "apk_analyze"
  | "dart_kernel"
  | "go_metadata"
  | "jvm_class"
  | "dotnet_analyze"
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
  | "phar_list"
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

type SingleInputEntry = Exclude<EntryName, "pyarmor_unpack" | SourceFormatEntry>;
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
  readonly entries: Readonly<Record<SingleInputEntry, EntryFn>>;
  readonly pharExtract: (ptr: number, len: number, index: number) => number;
  readonly pyarmorUnpack: (ptr: number, len: number, runtimePtr: number, runtimeLen: number) => number;
}

const ENTRY_NAMES: readonly SingleInputEntry[] = [
  "js_unbundle",
  "source_map_recover",
  "detect",
  "auto_route",
  "py_disasm",
  "py_decompile",
  "pyarmor_detect",
  "pyarmor_classify",
  "swift_objc",
  "hermes_analyze",
  "apk_analyze",
  "dart_kernel",
  "go_metadata",
  "jvm_class",
  "dotnet_analyze",
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
  "phar_list",
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
  const entries: Record<SingleInputEntry, EntryFn> = {} as Record<SingleInputEntry, EntryFn>;
  for (const name of ENTRY_NAMES) {
    entries[name] = entryOf(instance.exports, name);
  }
  const pharExtract: unknown = instance.exports["phar_extract"];
  if (typeof pharExtract !== "function") throw new Error("wasm module is missing the phar_extract export");
  const pyarmorUnpack: unknown = instance.exports["pyarmor_unpack"];
  if (typeof pyarmorUnpack !== "function") throw new Error("wasm module is missing the pyarmor_unpack export");
  return { core: instance.exports, entries, pharExtract: pharExtract as LoadedModule["pharExtract"], pyarmorUnpack: pyarmorUnpack as LoadedModule["pyarmorUnpack"] };
}

function moduleHandle(): Promise<LoadedModule> {
  instancePromise ??= load();
  return instancePromise;
}

function invoke<T>(mod: LoadedModule, entry: SingleInputEntry, input: Uint8Array): Outcome<T> {
  return invokePayload(mod, input, mod.entries[entry], (payload): Outcome<T> => JSON.parse(textDecoder.decode(payload)) as Outcome<T>);
}

function invokePayload<T>(mod: LoadedModule, input: Uint8Array, call: EntryFn, decode: (payload: Uint8Array) => T): T {
  const len: number = input.byteLength;
  try {
    const inputPtr: number = mod.core.disrobe_alloc(len);
    if (inputPtr === 0 && len !== 0) {
      throw new Error("wasm allocation failed");
    }
    new Uint8Array(mod.core.memory.buffer, inputPtr, len).set(input);
    const resultPtr: number = call(inputPtr, len);
    if (resultPtr === 0) {
      throw new Error("wasm entry returned a null result");
    }
    const payloadLen: number = mod.core.disrobe_result_len(resultPtr);
    if (payloadLen > 64 * 1024 * 1024) throw new Error("wasm result exceeds 64 MiB");
    const jsonBytes: Uint8Array = new Uint8Array(
      mod.core.memory.buffer,
      resultPtr + RESULT_HEADER_LEN,
      payloadLen,
    );
    const result: T = decode(jsonBytes);
    mod.core.disrobe_result_free(resultPtr);
    mod.core.disrobe_free(inputPtr, len);
    return result;
  } catch (cause: unknown) {
    const reason: string = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`Analysis engine stopped: ${reason}. Try a smaller input or use the CLI.`, {
      cause,
    });
  }
}

function isPyarmorMetadata(value: unknown): value is PyarmorModuleMetadata {
  if (typeof value !== "object" || value === null) return false;
  return "ok" in value && value.ok === true
    && "format" in value && value.format === "pyarmor-module"
    && "runtime_format" in value && (value.runtime_format === "8" || value.runtime_format === "9")
    && "python_version" in value && typeof value.python_version === "string" && value.python_version.length > 0 && value.python_version.length <= 32
    && "runtime_arch" in value && typeof value.runtime_arch === "string" && value.runtime_arch.length > 0 && value.runtime_arch.length <= 128
    && "marshal_offset" in value && typeof value.marshal_offset === "number" && Number.isSafeInteger(value.marshal_offset) && value.marshal_offset >= 0
    && "code_objects" in value && typeof value.code_objects === "number" && Number.isSafeInteger(value.code_objects) && value.code_objects > 0 && value.code_objects <= 65_536
    && "names" in value && Array.isArray(value.names) && value.names.length <= 65_536 && value.names.every((item: unknown): item is string => typeof item === "string")
    && "strings" in value && Array.isArray(value.strings) && value.strings.length <= 65_536 && value.strings.every((item: unknown): item is string => typeof item === "string");
}

function decodePyarmor(payload: Uint8Array): Outcome<PyarmorModuleResult> {
  if (payload.byteLength > 9 * 1024 * 1024 + 5) throw new Error("PyArmor response exceeds its size limit");
  if (payload[0] !== 0) {
    const error: unknown = JSON.parse(textDecoder.decode(payload));
    if (typeof error !== "object" || error === null || !("ok" in error) || error.ok !== false || !("error" in error) || typeof error.error !== "string") throw new Error("Invalid PyArmor error response");
    return { ok: false, error: error.error };
  }
  if (payload.byteLength < 5) throw new Error("Truncated PyArmor response");
  const metadataLength: number = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1, true);
  if (metadataLength > 8 * 1024 * 1024 || metadataLength > payload.byteLength - 5) throw new Error("Invalid PyArmor metadata length");
  const metadata: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(5, 5 + metadataLength)));
  const module: Uint8Array = payload.subarray(5 + metadataLength);
  if (!isPyarmorMetadata(metadata) || module.byteLength > 1024 * 1024 || metadata.marshal_offset >= module.byteLength || ![0x63, 0x43].includes((module[metadata.marshal_offset] ?? 0) & 0x7f)) throw new Error("Invalid PyArmor module metadata");
  const bytes: ArrayBuffer = new ArrayBuffer(module.byteLength);
  new Uint8Array(bytes).set(module);
  return { ...metadata, bytes };
}

export interface DisrobeWorkerApi {
  preload(): Promise<void>;
  run(entry: EntryName, input: ArrayBuffer, runtime?: ArrayBuffer): Promise<Outcome<unknown>>;
  extractPhar(input: ArrayBuffer, index: number): Promise<Outcome<PharArtifact>>;
}

const api: DisrobeWorkerApi = {
  async preload(): Promise<void> {
    await moduleHandle();
  },
  async run(entry: EntryName, input: ArrayBuffer, runtime?: ArrayBuffer): Promise<Outcome<unknown>> {
    if (isSourceFormatEntry(entry)) return formatSource(entry, new Uint8Array(input));
    if (entry === "jvm_class" && input.byteLength > 8 * 1024 * 1024) return { ok: false, error: "JVM class recovery accepts files up to 8 MiB." };
    if (entry === "dotnet_analyze" && input.byteLength > 8 * 1024 * 1024) return { ok: false, error: ".NET recovery accepts assemblies up to 8 MiB." };
    if (entry === "js_unbundle" && input.byteLength > 1024 * 1024) return { ok: false, error: "JavaScript unbundling accepts inputs up to 1 MiB." };
    if (entry === "source_map_recover" && input.byteLength > 1024 * 1024) return { ok: false, error: "Source-map recovery accepts inputs up to 1 MiB." };
    if (entry === "pyarmor_unpack") {
      if (input.byteLength > 1024 * 1024) return { ok: false, error: "PyArmor wrappers must be at most 1 MiB." };
      if (runtime === undefined || runtime.byteLength === 0) return { ok: false, error: "Choose the matching PyArmor runtime." };
      if (runtime.byteLength > 16 * 1024 * 1024) return { ok: false, error: "PyArmor runtimes must be at most 16 MiB." };
      const mod: LoadedModule = await moduleHandle();
      const result: Outcome<PyarmorModuleResult> = invokePayload(mod, new Uint8Array(input), (ptr, len): number => {
        const runtimePtr: number = mod.core.disrobe_alloc(runtime.byteLength);
        if (runtimePtr === 0) throw new Error("wasm runtime allocation failed");
        new Uint8Array(mod.core.memory.buffer, runtimePtr, runtime.byteLength).set(new Uint8Array(runtime));
        const resultPtr: number = mod.pyarmorUnpack(ptr, len, runtimePtr, runtime.byteLength);
        mod.core.disrobe_free(runtimePtr, runtime.byteLength);
        return resultPtr;
      }, decodePyarmor);
      return result.ok ? transfer(result, [result.bytes]) : result;
    }
    return invoke<unknown>(await moduleHandle(), entry, new Uint8Array(input));
  },
  async extractPhar(input: ArrayBuffer, index: number): Promise<Outcome<PharArtifact>> {
    if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) return { ok: false, error: "PHAR member index is out of range" };
    const mod: LoadedModule = await moduleHandle();
    const result: Outcome<PharArtifact> = invokePayload(mod, new Uint8Array(input), (ptr, len) => mod.pharExtract(ptr, len, index), (payload): Outcome<PharArtifact> => {
      if (payload[0] === 0) {
        if (payload.byteLength > 32 * 1024 * 1024 + 1) throw new Error("PHAR member exceeds 32 MiB");
        const bytes: ArrayBuffer = new ArrayBuffer(payload.byteLength - 1);
        new Uint8Array(bytes).set(payload.subarray(1));
        return { ok: true, bytes };
      }
      const error: unknown = JSON.parse(textDecoder.decode(payload));
      if (typeof error !== "object" || error === null || !("ok" in error) || error.ok !== false || !("error" in error) || typeof error.error !== "string") {
        throw new Error("Invalid PHAR extraction response");
      }
      return { ok: false, error: error.error } satisfies ErrorResult;
    });
    return result.ok ? transfer(result, [result.bytes]) : result;
  },
};

expose(api);
