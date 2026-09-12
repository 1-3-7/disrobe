import type { FormatResult, Outcome } from "./types";

const LANGUAGES = { js_format: "js", jsx_format: "jsx", ts_format: "ts", tsx_format: "tsx" } as const;
export type SourceFormatEntry = keyof typeof LANGUAGES;
export const FORMAT_INPUT_BYTES: number = 1024 * 1024;
export const FORMAT_INPUT_MESSAGE: string = "Source formatting accepts inputs up to 1 MiB.";
const OUTPUT_BYTES: number = 8 * 1024 * 1024;

export function isSourceFormatEntry(entry: string | null): entry is SourceFormatEntry {
  return entry !== null && Object.hasOwn(LANGUAGES, entry);
}

export async function formatSource(entry: SourceFormatEntry, bytes: Uint8Array): Promise<Outcome<FormatResult>> {
  if (bytes.byteLength > FORMAT_INPUT_BYTES) return { ok: false, error: FORMAT_INPUT_MESSAGE };
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error: unknown) {
    if (error instanceof TypeError) return { ok: false, error: "Source formatting requires UTF-8 text." };
    throw error;
  }
  const language: FormatResult["language"] = LANGUAGES[entry];
  const typed: boolean = language === "ts" || language === "tsx";
  const [prettier, estree, syntax] = await Promise.all([
    import("prettier/standalone"),
    import("prettier/plugins/estree"),
    typed ? import("prettier/plugins/typescript") : import("prettier/plugins/babel"),
  ]);
  let formatted: string;
  try {
    formatted = await prettier.format(source, {
      parser: typed ? "typescript" : "babel",
      filepath: `input.${language}`,
      plugins: [syntax, estree],
      embeddedLanguageFormatting: "off",
    });
  } catch (error: unknown) {
    if (error instanceof SyntaxError) return { ok: false, error: `Invalid source syntax: ${error.message.slice(0, 1024)}` };
    if (error instanceof RangeError) throw new Error("The source is too deeply nested to format. Reduce nesting and retry.", { cause: error });
    throw error;
  }
  if (formatted.length > OUTPUT_BYTES || new TextEncoder().encode(formatted).byteLength > OUTPUT_BYTES) return { ok: false, error: "Formatted source exceeds the 8 MiB output limit." };
  return { ok: true, format: "formatted-source", language, source: formatted };
}
