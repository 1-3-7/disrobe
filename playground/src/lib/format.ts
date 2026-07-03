export function formatBytes(byteLength: number): string {
  if (byteLength < 1024) {
    return `${byteLength} B`;
  }
  const units: readonly string[] = ["KiB", "MiB", "GiB"];
  let value: number = byteLength / 1024;
  let unitIndex: number = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const unit: string = units[unitIndex] ?? "B";
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${unit}`;
}

export function toHexDump(bytes: Uint8Array, maxBytes: number = 1024): string {
  const limit: number = Math.min(bytes.byteLength, maxBytes);
  const lines: string[] = [];
  for (let offset: number = 0; offset < limit; offset += 16) {
    const slice: Uint8Array = bytes.subarray(offset, Math.min(offset + 16, limit));
    const hex: string = Array.from(slice, (b: number): string =>
      b.toString(16).padStart(2, "0"),
    ).join(" ");
    const ascii: string = Array.from(slice, (b: number): string =>
      b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".",
    ).join("");
    const address: string = offset.toString(16).padStart(8, "0");
    lines.push(`${address}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  if (bytes.byteLength > limit) {
    lines.push(`... ${bytes.byteLength - limit} more bytes`);
  }
  return lines.join("\n");
}

const HEX_PAIR: RegExp = /^[0-9a-fA-F]{2}$/;

export function parseHexInput(text: string): Uint8Array | null {
  const cleaned: string = text
    .replace(/0x/gi, " ")
    .replace(/[,;]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (cleaned.length === 0) {
    return new Uint8Array(0);
  }
  const tokens: readonly string[] = cleaned.split(" ");
  const compact: boolean = tokens.length === 1 && tokens[0] !== undefined && tokens[0].length > 2;
  if (compact) {
    const single: string = tokens[0] ?? "";
    if (single.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(single)) {
      return null;
    }
    const out: Uint8Array = new Uint8Array(single.length / 2);
    for (let i: number = 0; i < out.length; i += 1) {
      out[i] = Number.parseInt(single.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  const out: number[] = [];
  for (const token of tokens) {
    if (!HEX_PAIR.test(token)) {
      return null;
    }
    out.push(Number.parseInt(token, 16));
  }
  return Uint8Array.from(out);
}

export function looksLikeHex(text: string): boolean {
  const trimmed: string = text.trim();
  if (trimmed.length === 0) {
    return false;
  }
  return /^(0x)?[0-9a-fA-F\s,;]+$/.test(trimmed) && /[0-9a-fA-F]/.test(trimmed);
}
