import type { Readable } from "node:stream";
import { type Buffer } from "node:buffer";

export type ChunkSink = (chunk: Buffer) => void;

export function attachSink(stream: Readable, sink: ChunkSink): void {
    stream.on("data", sink);
}

export interface RuntimeShape {
    readonly attach: typeof attachSink;
}

export const runtime: RuntimeShape = { attach: attachSink };
export type { Readable };
