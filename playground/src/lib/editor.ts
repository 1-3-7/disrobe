import { HighlightStyle, StreamLanguage, type LanguageSupport, type StreamParser } from "@codemirror/language";
import type { Extension } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { currentTheme } from "@/lib/theme";

export type EditorLanguage =
  | "python"
  | "javascript"
  | "typescript"
  | "jsx"
  | "tsx"
  | "rust"
  | "c"
  | "java"
  | "csharp"
  | "fsharp"
  | "vbnet"
  | "json"
  | "xml"
  | "wasm"
  | "disasm"
  | "lua"
  | "ruby"
  | "dart"
  | "php"
  | "yara"
  | "elixir"
  | "erlang"
  | "batch"
  | "shell"
  | "as3"
  | "wit"
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
  jsx: { extension: "jsx", mime: "text/javascript;charset=utf-8" },
  tsx: { extension: "tsx", mime: "text/typescript;charset=utf-8" },
  rust: { extension: "rs", mime: "text/rust;charset=utf-8" },
  c: { extension: "c", mime: "text/x-csrc;charset=utf-8" },
  java: { extension: "java", mime: "text/x-java-source;charset=utf-8" },
  csharp: { extension: "cs", mime: "text/x-csharp;charset=utf-8" },
  fsharp: { extension: "fs", mime: "text/x-fsharp;charset=utf-8" },
  vbnet: { extension: "vb", mime: "text/x-vb;charset=utf-8" },
  json: { extension: "json", mime: "application/json;charset=utf-8" },
  xml: { extension: "xml", mime: "application/xml;charset=utf-8" },
  wasm: { extension: "wat", mime: "text/plain;charset=utf-8" },
  disasm: { extension: "txt", mime: "text/plain;charset=utf-8" },
  lua: { extension: "lua", mime: "text/x-lua;charset=utf-8" },
  ruby: { extension: "rb", mime: "text/x-ruby;charset=utf-8" },
  dart: { extension: "dart", mime: "text/x-dart;charset=utf-8" },
  php: { extension: "php", mime: "application/x-httpd-php;charset=utf-8" },
  yara: { extension: "yar", mime: "text/plain;charset=utf-8" },
  elixir: { extension: "ex", mime: "text/plain;charset=utf-8" },
  erlang: { extension: "erl", mime: "text/plain;charset=utf-8" },
  batch: { extension: "bat", mime: "text/plain;charset=utf-8" },
  shell: { extension: "sh", mime: "text/x-shellscript;charset=utf-8" },
  as3: { extension: "as", mime: "text/plain;charset=utf-8" },
  wit: { extension: "wit", mime: "text/plain;charset=utf-8" },
  binary: { extension: "bin", mime: "application/octet-stream" },
  text: { extension: "txt", mime: "text/plain;charset=utf-8" },
};

export function downloadMetaFor(language: EditorLanguage): DownloadMeta {
  return DOWNLOAD_META[language];
}

export function languageForSourcePath(path: string, fallback: EditorLanguage = "text"): EditorLanguage {
  switch (path.split(".").at(-1)?.toLowerCase()) {
    case "tsx": return "tsx";
    case "jsx": return "jsx";
    case "ts": case "mts": case "cts": return "typescript";
    case "js": case "mjs": case "cjs": return "javascript";
    case "json": return "json";
    default: return fallback;
  }
}

function themeColor(name: string): string {
  const value: string = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  if (value.length === 0) {
    throw new Error(`Editor theme is missing ${name}; reload the playground assets.`);
  }
  return value;
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
    { dark: currentTheme().mode === "dark" },
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
    { tag: [tags.moduleKeyword, tags.definitionKeyword, tags.tagName], color: keyword },
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

type LexicalLanguage = "yara" | "elixir" | "batch" | "wit";

const KEYWORDS: Readonly<Record<LexicalLanguage, ReadonlySet<string>>> = {
  yara: new Set("rule private global meta strings condition and or not all any of them at in for filesize entrypoint true false ascii wide nocase fullword xor base64 base64wide import include matches contains startswith endswith defined".split(" ")),
  elixir: new Set("defmodule def defp defmacro defmacrop do end fn when if else unless case cond with for receive after try rescue catch raise throw import require alias use quote unquote and or not in true false nil".split(" ")),
  batch: new Set("echo set setlocal endlocal if else for in do goto call exit shift rem exist defined errorlevel not equ neq lss leq gtr geq enableextensions enabledelayedexpansion off on".split(" ")),
  wit: new Set("package world interface import export use include with type record flags enum variant resource constructor static func async borrow own list option result tuple future stream string bool u8 u16 u32 u64 s8 s16 s32 s64 f32 f64 char".split(" ")),
};

interface LexicalState {
  blockDepth: number;
  heredoc: string | null;
}

function lexicalLanguage(language: LexicalLanguage): StreamLanguage<LexicalState> {
  return StreamLanguage.define({
    name: language,
    startState: (): LexicalState => ({ blockDepth: 0, heredoc: null }),
    token(stream, state: LexicalState): string | null {
      if (state.blockDepth > 0) {
        while (!stream.eol()) {
          if (language === "wit" && stream.match("/*")) state.blockDepth += 1;
          else if (stream.match("*/")) {
            state.blockDepth -= 1;
            if (state.blockDepth === 0) break;
          } else stream.next();
        }
        return "comment";
      }
      if (state.heredoc !== null) {
        if (stream.skipTo(state.heredoc)) {
          stream.match(state.heredoc);
          state.heredoc = null;
        } else stream.skipToEnd();
        return "string";
      }
      if (stream.eatSpace()) return null;
      if ((language === "elixir" && stream.match("#")) ||
          (language === "batch" && /(?:^|[&|()])\s*@?$/.test(stream.string.slice(0, stream.pos)) && stream.match(/^(?:rem\b|::)/i)) ||
          ((language === "yara" || language === "wit") && stream.match("//"))) {
        stream.skipToEnd();
        return "comment";
      }
      if ((language === "yara" || language === "wit") && stream.match("/*")) {
        state.blockDepth = 1;
        return "comment";
      }
      if (language === "elixir") {
        for (const delimiter of ['"""', "'''"]) {
          if (stream.match(delimiter)) {
            state.heredoc = delimiter;
            return "string";
          }
        }
      }
      const quote: string | undefined = stream.peek();
      if (quote === '"' || (language === "elixir" && quote === "'")) {
        stream.next();
        let escaped: boolean = false;
        for (let next: string | void = stream.next(); next !== undefined; next = stream.next()) {
          if (next === quote && !escaped) break;
          escaped = next === "\\" && !escaped;
        }
        return "string";
      }
      if (language === "batch" && stream.match(/^(?:%[^%\s]+%|![^!\s]+!|%%?[A-Za-z0-9])/)) return "variableName";
      if (language === "yara" && stream.match(/^[$#@!][A-Za-z_]\w*/)) return "variableName";
      if (language === "elixir" && stream.match(/^:[A-Za-z_]\w*[!?]?/)) return "atom";
      if (stream.match(/^(?:0x[\da-f]+|\d+(?:\.\d+)?)\b/i)) return "number";
      const word: RegExpMatchArray | boolean | null = stream.match(/^[A-Za-z_][\w-]*[!?]?/);
      if (Array.isArray(word)) {
        const name: string = word[0];
        if (KEYWORDS[language].has(language === "batch" ? name.toLowerCase() : name)) return "keyword";
        return /^[A-Z]/.test(name) ? "typeName" : "variableName";
      }
      if (stream.match(/^[{}()[\],.;:]/)) return "punctuation";
      stream.next();
      return "operator";
    },
  });
}

interface PhpLanguages {
  readonly plain: readonly [LanguageSupport];
  readonly template: readonly [LanguageSupport];
}

let phpLanguages: Promise<PhpLanguages> | null = null;

export async function loadLanguage(language: EditorLanguage, phpSource: string = ""): Promise<readonly Extension[]> {
  switch (language) {
    case "shell": {
      const { shell } = await import("@codemirror/legacy-modes/mode/shell");
      return [StreamLanguage.define(shell)];
    }
    case "python": {
      const { python } = await import("@codemirror/lang-python");
      return [python()];
    }
    case "javascript": {
      const { javascript } = await import("@codemirror/lang-javascript");
      return [javascript()];
    }
    case "jsx":
    case "tsx": {
      const { javascript } = await import("@codemirror/lang-javascript");
      return [javascript({ jsx: true, typescript: language === "tsx" })];
    }
    case "as3":
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
    case "java": {
      const { java } = await import("@codemirror/legacy-modes/mode/clike");
      return [StreamLanguage.define(java)];
    }
    case "csharp": {
      const { csharp } = await import("@codemirror/legacy-modes/mode/clike");
      return [StreamLanguage.define(csharp)];
    }
    case "fsharp": {
      const { fSharp } = await import("@codemirror/legacy-modes/mode/mllike");
      return [StreamLanguage.define(fSharp)];
    }
    case "vbnet": {
      const { vb } = await import("@codemirror/legacy-modes/mode/vb");
      return [StreamLanguage.define(vb)];
    }
    case "json": {
      const { json } = await import("@codemirror/lang-json");
      return [json()];
    }
    case "xml": {
      const { xml } = await import("@codemirror/legacy-modes/mode/xml");
      return [StreamLanguage.define(xml)];
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
    case "dart": {
      const { dart } = await import("@codemirror/legacy-modes/mode/clike");
      return [StreamLanguage.define(dart)];
    }
    case "php": {
      phpLanguages ??= import("@codemirror/lang-php").then(({ php }): PhpLanguages => ({
        plain: [php({ plain: true })],
        template: [php()],
      }));
      const languages: PhpLanguages = await phpLanguages;
      const openingTag: RegExpExecArray | null = /<\?(?:php\b|=)/i.exec(phpSource);
      if (openingTag === null) return languages.plain;
      const end: number = openingTag.index + openingTag[0].length;
      const parsing = languages.plain[0].language.parser.startParse(phpSource);
      parsing.stopAt(end);
      let tree = parsing.advance();
      while (tree === null) tree = parsing.advance();
      const cursor = tree.cursor();
      do {
        if (cursor.type.isError && cursor.from < end) return languages.template;
      } while (cursor.next());
      return languages.plain;
    }
    case "erlang": {
      const { erlang } = await import("@codemirror/legacy-modes/mode/erlang");
      return [StreamLanguage.define(erlang)];
    }
    case "disasm":
      return [disasmLanguage];
    case "yara":
    case "elixir":
    case "batch":
    case "wit":
      return [lexicalLanguage(language)];
    case "binary":
    case "text":
      return [];
  }
}
