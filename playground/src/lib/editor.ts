import { HighlightStyle, StreamLanguage, type StreamParser } from "@codemirror/language";
import type { Extension } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { tags } from "@lezer/highlight";

export type EditorLanguage =
  | "python"
  | "javascript"
  | "typescript"
  | "rust"
  | "c"
  | "json"
  | "wasm"
  | "disasm"
  | "lua"
  | "ruby"
  | "php"
  | "yara"
  | "binary"
  | "text";

export interface DownloadMeta {
  readonly extension: string;
  readonly mime: string;
}

const DOWNLOAD_META: Readonly<Record<EditorLanguage, DownloadMeta>> = {
  python: { extension: "py", mime: "text/x-python;charset=utf-8" },
  javascript: { extension: "js", mime: "text/javascript;charset=utf-8" },
  typescript: { extension: "ts", mime: "text/typescript;charset=utf-8" },
  rust: { extension: "rs", mime: "text/rust;charset=utf-8" },
  c: { extension: "c", mime: "text/x-csrc;charset=utf-8" },
  json: { extension: "json", mime: "application/json;charset=utf-8" },
  wasm: { extension: "wat", mime: "text/plain;charset=utf-8" },
  disasm: { extension: "txt", mime: "text/plain;charset=utf-8" },
  lua: { extension: "lua", mime: "text/x-lua;charset=utf-8" },
  ruby: { extension: "rb", mime: "text/x-ruby;charset=utf-8" },
  php: { extension: "php", mime: "application/x-httpd-php;charset=utf-8" },
  yara: { extension: "yar", mime: "text/plain;charset=utf-8" },
  binary: { extension: "bin", mime: "application/octet-stream" },
  text: { extension: "txt", mime: "text/plain;charset=utf-8" },
};

export function downloadMetaFor(language: EditorLanguage): DownloadMeta {
  return DOWNLOAD_META[language];
}

const THEME_FALLBACK: Readonly<Record<string, string>> = {
  "--color-ink": "#c8d0e8",
  "--color-ink-muted": "#8b93ad",
  "--color-ink-faint": "#76809a",
  "--color-inset": "#0d111b",
  "--color-hairline": "#1e2433",
  "--color-accent": "#86a8f0",
  "--color-danger": "#e08c8c",
  "--syntax-keyword": "#86a8f0",
  "--syntax-string": "#9fbfa0",
  "--syntax-number": "#e0af7e",
  "--syntax-function": "#7fb8d9",
  "--syntax-type": "#b79cd6",
  "--syntax-comment": "#76809a",
  "--syntax-operator": "#8b93ad",
  "--syntax-variable": "#c8d0e8",
  "--syntax-meta": "#c79bb6",
};

const THEME_FALLBACK_DEFAULT: string = "#c8d0e8";

function themeColor(name: string): string {
  const fallback: string = THEME_FALLBACK[name] ?? THEME_FALLBACK_DEFAULT;
  if (typeof document === "undefined") {
    return fallback;
  }
  const value: string = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return value.length > 0 ? value : fallback;
}

export function buildEditorTheme(): ReturnType<typeof EditorView.theme> {
  const ink: string = themeColor("--color-ink");
  const inkMuted: string = themeColor("--color-ink-muted");
  const gutterInk: string = themeColor("--syntax-comment");
  const inset: string = themeColor("--color-inset");
  const hairline: string = themeColor("--color-hairline");
  const accent: string = themeColor("--color-accent");
  return EditorView.theme(
    {
      "&": {
        color: ink,
        backgroundColor: inset,
        fontSize: "12.5px",
      },
      "&.cm-focused": {
        outline: "none",
      },
      ".cm-scroller": {
        fontFamily:
          '"JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace',
        lineHeight: "1.65",
      },
      ".cm-content": {
        caretColor: accent,
        padding: "12px 0",
      },
      ".cm-line": {
        padding: "0 14px",
      },
      ".cm-gutters": {
        backgroundColor: inset,
        color: gutterInk,
        border: "none",
        borderRight: `1px solid ${hairline}`,
      },
      ".cm-lineNumbers .cm-gutterElement": {
        padding: "0 10px 0 14px",
        minWidth: "2.25rem",
      },
      ".cm-foldGutter": {
        display: "none",
      },
      ".cm-cursor, .cm-dropCursor": {
        borderLeftColor: accent,
      },
      ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection": {
        backgroundColor: `color-mix(in srgb, ${accent} 24%, transparent)`,
      },
      ".cm-activeLine": {
        backgroundColor: "transparent",
      },
      ".cm-activeLineGutter": {
        backgroundColor: "transparent",
        color: inkMuted,
      },
    },
    { dark: true },
  );
}

export function buildHighlightStyle(): HighlightStyle {
  const keyword: string = themeColor("--syntax-keyword");
  const str: string = themeColor("--syntax-string");
  const num: string = themeColor("--syntax-number");
  const fn: string = themeColor("--syntax-function");
  const type: string = themeColor("--syntax-type");
  const comment: string = themeColor("--syntax-comment");
  const operator: string = themeColor("--syntax-operator");
  const variable: string = themeColor("--syntax-variable");
  const meta: string = themeColor("--syntax-meta");
  const red: string = themeColor("--color-danger");
  return HighlightStyle.define([
    { tag: [tags.keyword, tags.controlKeyword, tags.operatorKeyword, tags.modifier], color: keyword },
    { tag: [tags.moduleKeyword, tags.definitionKeyword], color: keyword },
    { tag: [tags.string, tags.special(tags.string), tags.docString], color: str },
    { tag: tags.regexp, color: str },
    { tag: tags.escape, color: meta },
    { tag: [tags.number, tags.integer, tags.float, tags.literal], color: num },
    { tag: [tags.bool, tags.null, tags.atom, tags.constant(tags.variableName)], color: num },
    { tag: [tags.comment, tags.lineComment, tags.blockComment], color: comment, fontStyle: "italic" },
    { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: fn },
    { tag: [tags.definition(tags.function(tags.variableName)), tags.macroName], color: fn },
    { tag: tags.definition(tags.variableName), color: variable },
    { tag: tags.variableName, color: variable },
    { tag: tags.propertyName, color: operator },
    { tag: [tags.className, tags.typeName, tags.namespace], color: type },
    { tag: [tags.self, tags.special(tags.variableName)], color: meta, fontStyle: "italic" },
    { tag: [tags.operator, tags.derefOperator, tags.compareOperator, tags.logicOperator, tags.arithmeticOperator], color: operator },
    { tag: [tags.punctuation, tags.separator], color: operator },
    { tag: [tags.bracket, tags.brace, tags.paren, tags.squareBracket, tags.angleBracket], color: comment },
    { tag: [tags.meta, tags.annotation, tags.attributeName], color: meta },
    { tag: tags.labelName, color: type },
    { tag: tags.invalid, color: red },
  ]);
}

interface DisasmStreamState {
  seenMnemonic: boolean;
}

const REGISTER_PATTERN: RegExp =
  /^(?:r[0-9]+[dwb]?|[er]?[abcd]x|[er]?(?:si|di|bp|sp)|[abcd][lh]|spl|bpl|sil|dil|[xwq][0-9]+|[vsdhb][0-9]+|[er]?ip|[xyz]mm[0-9]+|st[0-9]+|cr[0-9]+|dr[0-9]+|[cdefgs]s|fp|lr|pc|sp|wzr|xzr|wsp|cpsr|spsr|pstate)\b/i;

const HEX_NUMBER_PATTERN: RegExp = /^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]+h|#-?[0-9]+|[0-9]+)\b/;

const ADDRESS_PATTERN: RegExp = /^[0-9a-fA-F]{4,16}(?=[:\s])/;

const LABEL_PATTERN: RegExp = /^[.$@A-Za-z_][\w.$@]*:/;

const MNEMONIC_PATTERN: RegExp = /^[A-Za-z][\w.]*/;

const disasmParser: StreamParser<DisasmStreamState> = {
  name: "disasm",
  startState(): DisasmStreamState {
    return { seenMnemonic: false };
  },
  token(stream, state: DisasmStreamState): string | null {
    if (stream.sol()) {
      state.seenMnemonic = false;
    }
    if (stream.eatSpace()) {
      return null;
    }
    const ch: string = stream.peek() ?? "";
    if (ch === ";" || ch === "#" || (ch === "/" && stream.string.charAt(stream.pos + 1) === "/")) {
      stream.skipToEnd();
      return "comment";
    }
    if (ch === '"' || ch === "'") {
      stream.next();
      let escaped: boolean = false;
      let next: string | void;
      while ((next = stream.next()) !== undefined) {
        if (next === ch && !escaped) {
          break;
        }
        escaped = !escaped && next === "\\";
      }
      return "string";
    }
    if (stream.sol() && stream.match(ADDRESS_PATTERN, false) !== null) {
      stream.match(ADDRESS_PATTERN);
      return "literal";
    }
    if (stream.match(LABEL_PATTERN) !== null) {
      return "labelName";
    }
    if (stream.match(HEX_NUMBER_PATTERN) !== null) {
      return "number";
    }
    if (stream.match(REGISTER_PATTERN) !== null) {
      return "variableName";
    }
    if (!state.seenMnemonic && stream.match(MNEMONIC_PATTERN) !== null) {
      state.seenMnemonic = true;
      return "keyword";
    }
    if (stream.match(MNEMONIC_PATTERN) !== null) {
      return "propertyName";
    }
    stream.next();
    return null;
  },
};

export const disasmLanguage: StreamLanguage<DisasmStreamState> =
  StreamLanguage.define(disasmParser);

export async function loadLanguage(language: EditorLanguage): Promise<readonly Extension[]> {
  switch (language) {
    case "python": {
      const { python } = await import("@codemirror/lang-python");
      return [python()];
    }
    case "javascript": {
      const { javascript } = await import("@codemirror/lang-javascript");
      return [javascript()];
    }
    case "typescript": {
      const { javascript } = await import("@codemirror/lang-javascript");
      return [javascript({ typescript: true })];
    }
    case "rust": {
      const { rust } = await import("@codemirror/legacy-modes/mode/rust");
      return [StreamLanguage.define(rust)];
    }
    case "c": {
      const { c } = await import("@codemirror/legacy-modes/mode/clike");
      return [StreamLanguage.define(c)];
    }
    case "json": {
      const { json } = await import("@codemirror/lang-json");
      return [json()];
    }
    case "wasm": {
      const { wast } = await import("@codemirror/lang-wast");
      return [wast()];
    }
    case "lua": {
      const { lua } = await import("@codemirror/legacy-modes/mode/lua");
      return [StreamLanguage.define(lua)];
    }
    case "ruby": {
      const { ruby } = await import("@codemirror/legacy-modes/mode/ruby");
      return [StreamLanguage.define(ruby)];
    }
    case "php": {
      const { php } = await import("@codemirror/lang-php");
      return [php()];
    }
    case "disasm":
      return [disasmLanguage];
    case "yara":
    case "binary":
    case "text":
      return [];
  }
}
