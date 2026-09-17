import { type Remote, transfer, wrap } from "comlink";
import type { DisrobeWorkerApi, EntryName } from "./disrobe.worker";
import { FORMAT_INPUT_BYTES, FORMAT_INPUT_MESSAGE, isSourceFormatEntry } from "./source-format";
import type { Outcome, PharArtifact } from "./types";

export type { EntryName };

export const MAX_INPUT_BYTES: number = 64 * 1024 * 1024;
export const INPUT_LIMIT_MESSAGE: string = "The playground accepts inputs up to 64 MiB. Use the CLI for larger files.";
export const MAX_PYARMOR_WRAPPER_BYTES: number = 1024 * 1024;
export const MAX_PYARMOR_RUNTIME_BYTES: number = 16 * 1024 * 1024;
export const PYARMOR_WRAPPER_LIMIT_MESSAGE: string = "PyArmor wrappers must be at most 1 MiB.";
export const PYARMOR_RUNTIME_LIMIT_MESSAGE: string = "PyArmor runtimes must be at most 16 MiB.";
const REQUEST_TIMEOUT_MS: number = 30_000;

export function inputLimit(entry: EntryName | null): { readonly bytes: number; readonly message: string } {
  if (isSourceFormatEntry(entry)) return { bytes: FORMAT_INPUT_BYTES, message: FORMAT_INPUT_MESSAGE };
  if (entry === "jvm_class") return { bytes: 8 * 1024 * 1024, message: "JVM class recovery accepts files up to 8 MiB." };
  if (entry === "dotnet_analyze") return { bytes: 8 * 1024 * 1024, message: ".NET recovery accepts assemblies up to 8 MiB." };
  if (entry === "js_unbundle") return { bytes: 1024 * 1024, message: "JavaScript unbundling accepts inputs up to 1 MiB." };
  if (entry === "pyarmor_unpack") return { bytes: MAX_PYARMOR_WRAPPER_BYTES, message: PYARMOR_WRAPPER_LIMIT_MESSAGE };
  if (entry === "source_map_recover") return { bytes: 1024 * 1024, message: "Source-map recovery accepts inputs up to 1 MiB." };
  return { bytes: MAX_INPUT_BYTES, message: INPUT_LIMIT_MESSAGE };
}

interface WorkerSession {
  readonly worker: Worker;
  readonly remote: Remote<DisrobeWorkerApi>;
  readonly pending: Set<(reason: Error) => void>;
}

let currentSession: WorkerSession | null = null;

function terminate(session: WorkerSession, reason: Error): void {
  if (currentSession === session) currentSession = null;
  session.worker.terminate();
  for (const reject of session.pending) reject(reason);
  session.pending.clear();
}

function session(): WorkerSession {
  if (currentSession === null) {
    const worker: Worker = new Worker(new URL("./disrobe.worker.ts", import.meta.url), {
      type: "module",
    });
    const created: WorkerSession = { worker, remote: wrap<DisrobeWorkerApi>(worker), pending: new Set() };
    worker.addEventListener("error", (event: ErrorEvent): void => {
      event.preventDefault();
      terminate(created, new Error(event.message || "The analysis engine could not start. Load a sample to retry."));
    });
    worker.addEventListener("messageerror", (): void => {
      terminate(created, new Error("The analysis engine returned an unreadable response. Load a sample to retry."));
    });
    currentSession = created;
  }
  return currentSession;
}

function request<T>(operation: (remote: Remote<DisrobeWorkerApi>) => Promise<T>): Promise<T> {
  const owner: WorkerSession = session();
  return new Promise<T>((resolve, reject): void => {
    const fail = (reason: Error): void => {
      window.clearTimeout(timer);
      owner.pending.delete(fail);
      reject(reason);
    };
    const timer: number = window.setTimeout((): void => {
      terminate(owner, new Error("Analysis exceeded 30 seconds. Try a smaller input or use the CLI."));
    }, REQUEST_TIMEOUT_MS);
    owner.pending.add(fail);
    void Promise.resolve().then((): Promise<T> => operation(owner.remote)).then((value: T): void => {
      window.clearTimeout(timer);
      owner.pending.delete(fail);
      resolve(value);
    }, (cause: unknown): void => {
      terminate(owner, cause instanceof Error ? cause : new Error(String(cause)));
    });
  });
}

export function cancel(): void {
  if (currentSession !== null && currentSession.pending.size > 0) {
    terminate(currentSession, new Error("Analysis stopped."));
  }
}

function toTransferable(input: Uint8Array): ArrayBuffer {
  const buffer: ArrayBuffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(buffer).set(input);
  return buffer;
}

export async function run(entry: EntryName, input: Uint8Array, runtime?: Uint8Array): Promise<Outcome<unknown>> {
  const limit = inputLimit(entry);
  if (input.byteLength > limit.bytes) return { ok: false, error: limit.message };
  if (entry === "pyarmor_unpack") {
    if (runtime === undefined || runtime.byteLength === 0) return { ok: false, error: "Choose the matching PyArmor runtime." };
    if (runtime.byteLength > MAX_PYARMOR_RUNTIME_BYTES) return { ok: false, error: PYARMOR_RUNTIME_LIMIT_MESSAGE };
    const wrapperBuffer: ArrayBuffer = toTransferable(input);
    const runtimeBuffer: ArrayBuffer = toTransferable(runtime);
    return request((remote): Promise<Outcome<unknown>> => remote.run(entry, transfer(wrapperBuffer, [wrapperBuffer]), transfer(runtimeBuffer, [runtimeBuffer])));
  }
  const buffer: ArrayBuffer = toTransferable(input);
  return request((remote): Promise<Outcome<unknown>> => remote.run(entry, transfer(buffer, [buffer])));
}

export function preload(): Promise<void> {
  return request((remote): Promise<void> => remote.preload());
}

export async function extractPhar(input: Uint8Array, index: number): Promise<Outcome<PharArtifact>> {
  if (input.byteLength > MAX_INPUT_BYTES) return { ok: false, error: INPUT_LIMIT_MESSAGE };
  const buffer: ArrayBuffer = toTransferable(input);
  return request((remote): Promise<Outcome<PharArtifact>> => remote.extractPhar(transfer(buffer, [buffer]), index));
}
