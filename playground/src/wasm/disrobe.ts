import { type Remote, transfer, wrap } from "comlink";
import type { DisrobeWorkerApi, EntryName } from "./disrobe.worker";
import type { Outcome } from "./types";

export type { EntryName };

let workerApi: Remote<DisrobeWorkerApi> | null = null;

function api(): Remote<DisrobeWorkerApi> {
  if (workerApi === null) {
    const worker: Worker = new Worker(new URL("./disrobe.worker.ts", import.meta.url), {
      type: "module",
    });
    workerApi = wrap<DisrobeWorkerApi>(worker);
  }
  return workerApi;
}

function toTransferable(input: Uint8Array): ArrayBuffer {
  const buffer: ArrayBuffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(buffer).set(input);
  return buffer;
}

export async function run<T>(entry: EntryName, input: Uint8Array): Promise<Outcome<T>> {
  const buffer: ArrayBuffer = toTransferable(input);
  return api().run(entry, transfer(buffer, [buffer])) as Promise<Outcome<T>>;
}

export function preload(): Promise<void> {
  return api().preload();
}
