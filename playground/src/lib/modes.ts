import type { EditorLanguage } from "@/lib/editor";
import type { EntryName } from "@/wasm/disrobe";
import {
  ANTI_ANALYSIS_SAMPLE,
  BATCH_OBF_SAMPLE,
  BEHAVIOR_SAMPLE,
  fileSample,
  inlineSample,
  IOC_SAMPLE,
  PHP_EVAL_SAMPLE,
  RUBY_SOURCE_SAMPLE,
  type Sample,
  SECRETS_SAMPLE,
  STRINGS_SAMPLE,
  WASM_SOURCE_MAP_SAMPLE,
  YARA_SAMPLE,
} from "@/lib/samples";

export type RenderKind =
  | "python"
  | "pickle"
  | "pickle-decompile"
  | "pickle-trace"
  | "pickle-polyglot"
  | "wasm"
  | "wasm-detect"
  | "wasm-wat"
  | "wasm-highlevel"
  | "wasm-cfg"
  | "wasm-gc-types"
  | "wasm-eh"
  | "wasm-component"
  | "wasm-memories"
  | "wasm-signatures"
  | "wasm-preludes"
  | "wasm-sourcemap"
  | "pyarmor"
  | "lua-detect"
  | "lua-decompile"
  | "ruby"
  | "php"
  | "beam"
  | "as3"
  | "scriptlang"
  | "shell"
  | "swift-objc"
  | "mobile"
  | "strings"
  | "ioc"
  | "behavior"
  | "secrets"
  | "anti-analysis"
  | "yara"
  | "entropy"
  | "route"
  | "json";

export interface Mode {
  readonly id: string;
  readonly label: string;
  readonly blurb: string;
  readonly entry: EntryName | null;
  readonly inputKind: "bytes" | "text";
  readonly render: RenderKind;
  readonly sample?: Sample;
  readonly inputLanguage: EditorLanguage;
  readonly reference?: boolean;
}

export interface Ecosystem {
  readonly id: string;
  readonly label: string;
  readonly modes: readonly Mode[];
}

export const ECOSYSTEMS: readonly Ecosystem[] = [
  {
    id: "triage",
    label: "Triage",
    modes: [
      {
        id: "auto-route",
        label: "Auto Route",
        blurb: "Fingerprint the bytes and route them to the matching recovery pass.",
        entry: "auto_route",
        inputKind: "bytes",
        render: "route",
        sample: fileSample("hello.pyc", "CPython 3.12 bytecode", "hello.pyc"),
        inputLanguage: "text",
      },
      {
        id: "strings",
        label: "Strings",
        blurb: "ASCII and UTF-16 runs, plus XOR / ROT / base64 decoded candidates.",
        entry: "strings",
        inputKind: "text",
        render: "strings",
        sample: inlineSample("loader strings", "mixed printable runs", STRINGS_SAMPLE),
        inputLanguage: "text",
      },
      {
        id: "ioc",
        label: "IOCs",
        blurb: "URLs, IPs, domains, emails, paths, registry keys, and crypto addresses.",
        entry: "ioc",
        inputKind: "text",
        render: "ioc",
        sample: inlineSample("beacon config", "c2 + wallet indicators", IOC_SAMPLE, "danger"),
        inputLanguage: "text",
      },
      {
        id: "behavior",
        label: "Behavior",
        blurb: "Capability categories inferred from API names and string evidence.",
        entry: "behavior",
        inputKind: "text",
        render: "behavior",
        sample: inlineSample("api surface", "process + network + crypto", BEHAVIOR_SAMPLE, "danger"),
        inputLanguage: "text",
      },
      {
        id: "anti-analysis",
        label: "Anti-Analysis",
        blurb: "Debugger, VM, sandbox, and timing evasion markers.",
        entry: "anti_analysis",
        inputKind: "text",
        render: "anti-analysis",
        sample: inlineSample("evasion markers", "debugger + vm probes", ANTI_ANALYSIS_SAMPLE, "danger"),
        inputLanguage: "text",
      },
      {
        id: "secrets",
        label: "Secrets",
        blurb: "Cloud keys, tokens, JWTs, and high-entropy credentials.",
        entry: "secrets",
        inputKind: "text",
        render: "secrets",
        sample: inlineSample("leaked config", "aws / github / stripe", SECRETS_SAMPLE, "danger"),
        inputLanguage: "text",
      },
      {
        id: "entropy",
        label: "Entropy",
        blurb: "Windowed Shannon entropy to locate packed or encrypted regions.",
        entry: "entropy",
        inputKind: "bytes",
        render: "entropy",
        sample: fileSample("reduce_os_system.pkl", "compact pickle payload", "reduce_os_system.pkl"),
        inputLanguage: "text",
      },
      {
        id: "yara",
        label: "YARA Gen",
        blurb: "Generate a candidate YARA rule from the most distinctive strings.",
        entry: "yara_gen",
        inputKind: "text",
        render: "yara",
        sample: inlineSample("loader artifact", "distinctive markers", YARA_SAMPLE),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "python",
    label: "Python",
    modes: [
      {
        id: "py-decompile",
        label: "Decompile .pyc",
        blurb: "Recover Python source from CPython bytecode.",
        entry: "py_decompile",
        inputKind: "bytes",
        render: "python",
        sample: fileSample("hello.pyc", "CPython 3.12 bytecode", "hello.pyc"),
        inputLanguage: "text",
      },
      {
        id: "py-disasm",
        label: "Disassemble .pyc",
        blurb: "Decode the bytecode into an annotated instruction listing.",
        entry: "py_disasm",
        inputKind: "bytes",
        render: "python",
        sample: fileSample("hello.pyc", "CPython 3.12 bytecode", "hello.pyc"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "pickle",
    label: "Pickle",
    modes: [
      {
        id: "pickle-safety",
        label: "Safety Scan",
        blurb: "Symbolically execute the opcode stream and flag dangerous reductions.",
        entry: "pickle_safety",
        inputKind: "bytes",
        render: "pickle",
        sample: fileSample(
          "reduce_os_system.pkl",
          "os.system reduce (malicious)",
          "reduce_os_system.pkl",
          "danger",
        ),
        inputLanguage: "text",
      },
      {
        id: "pickle-disasm",
        label: "Disassemble",
        blurb: "Decode the pickle protocol opcodes with stack effects.",
        entry: "pickle_disasm",
        inputKind: "bytes",
        render: "pickle",
        sample: fileSample("benign_list.pkl", "plain list pickle", "benign_list.pkl"),
        inputLanguage: "text",
      },
      {
        id: "pickle-decompile",
        label: "Decompile",
        blurb: "Reconstruct the Python object the pickle rebuilds.",
        entry: "pickle_decompile",
        inputKind: "bytes",
        render: "pickle-decompile",
        sample: fileSample("benign_list.pkl", "plain list pickle", "benign_list.pkl"),
        inputLanguage: "text",
      },
      {
        id: "pickle-trace",
        label: "VM Trace",
        blurb: "Inspect the symbolic VM trace: memo, stack depth, reductions.",
        entry: "pickle_trace",
        inputKind: "bytes",
        render: "pickle-trace",
        sample: fileSample(
          "reduce_os_system.pkl",
          "os.system reduce (malicious)",
          "reduce_os_system.pkl",
          "danger",
        ),
        inputLanguage: "text",
      },
      {
        id: "pickle-polyglot",
        label: "Polyglot",
        blurb: "Detect pickle-in-container framings (torch zip, npy, tar).",
        entry: "pickle_polyglot",
        inputKind: "bytes",
        render: "pickle-polyglot",
        sample: fileSample("benign_list.pkl", "plain list pickle", "benign_list.pkl"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "wasm",
    label: "WebAssembly",
    modes: [
      {
        id: "wasm-analyze",
        label: "Analyze Module",
        blurb: "Summarize sections, imports, exports, and debug info.",
        entry: "wasm_analyze",
        inputKind: "bytes",
        render: "wasm",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-detect",
        label: "Detect Obfuscator",
        blurb: "Fingerprint wasm obfuscators and name-section stripping.",
        entry: "wasm_detect",
        inputKind: "bytes",
        render: "wasm-detect",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-decompile-wat",
        label: "Decompile to WAT",
        blurb: "Lift every function body back to real WebAssembly text.",
        entry: "wasm_decompile_wat",
        inputKind: "bytes",
        render: "wasm-wat",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-faithful-wat",
        label: "Faithful WAT",
        blurb: "Reconstruct a full, re-assemblable module: types, imports, tables, data.",
        entry: "wasm_faithful_wat",
        inputKind: "bytes",
        render: "wasm-wat",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-lift-rust",
        label: "Lift to Rust",
        blurb: "Reloop the SSA into structured, typed Rust pseudo-source.",
        entry: "wasm_lift_rust",
        inputKind: "bytes",
        render: "wasm-highlevel",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-lift-ts",
        label: "Lift to TypeScript",
        blurb: "Reloop the SSA into structured TypeScript pseudo-source.",
        entry: "wasm_lift_ts",
        inputKind: "bytes",
        render: "wasm-highlevel",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-lift-c",
        label: "Lift to C",
        blurb: "Reloop the SSA into structured C pseudo-source.",
        entry: "wasm_lift_c",
        inputKind: "bytes",
        render: "wasm-highlevel",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-cfg",
        label: "Control-Flow Graph",
        blurb: "Recover the per-function basic-block CFG with terminators and edges.",
        entry: "wasm_cfg",
        inputKind: "bytes",
        render: "wasm-cfg",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-signatures",
        label: "Module Summary",
        blurb: "Extract function signatures, export aliases, and run the recovery pass.",
        entry: "wasm_signatures",
        inputKind: "bytes",
        render: "wasm-signatures",
        sample: fileSample("arith4.wasm", "5-function arith module", "arith4.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-gc-types",
        label: "GC Type Graph",
        blurb: "Recover the WasmGC struct / array / ref type graph and lift it to typed source.",
        entry: "wasm_gc_types",
        inputKind: "bytes",
        render: "wasm-gc-types",
        sample: fileSample("gc_shapes.wasm", "WasmGC struct + array module", "gc_shapes.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-eh",
        label: "Exception Handling",
        blurb: "Summarize try_table / catch / throw / rethrow exception-handling use.",
        entry: "wasm_eh",
        inputKind: "bytes",
        render: "wasm-eh",
        sample: fileSample("eh_try_table.wasm", "modern try_table EH module", "eh_try_table.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-memories",
        label: "Multi-Memory",
        blurb: "List every linear memory: index type, shared, initial / max pages.",
        entry: "wasm_memories",
        inputKind: "bytes",
        render: "wasm-memories",
        sample: fileSample("multi_memory.wasm", "two-memory module", "multi_memory.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-component",
        label: "Component Manifest",
        blurb: "Parse a Component Model envelope and lift its world to Rust / TS / WIT bindings.",
        entry: "wasm_component",
        inputKind: "bytes",
        render: "wasm-component",
        sample: fileSample("add_component.wasm", "component model envelope", "add_component.wasm"),
        inputLanguage: "text",
      },
      {
        id: "wasm-source-map",
        label: "Source Map",
        blurb: "Parse a source-map v3 document into sources, names, and VLQ segments.",
        entry: "wasm_source_map",
        inputKind: "text",
        render: "wasm-sourcemap",
        sample: inlineSample("source map v3", "names + VLQ mappings", WASM_SOURCE_MAP_SAMPLE),
        inputLanguage: "json",
      },
      {
        id: "wasm-preludes",
        label: "Runtime Preludes",
        blurb: "The C, Rust, and TypeScript runtime preludes that back the lifted output.",
        entry: "wasm_preludes",
        inputKind: "bytes",
        render: "wasm-preludes",
        sample: fileSample("arith4.wasm", "any module (preludes are static)", "arith4.wasm"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "lua",
    label: "Lua",
    modes: [
      {
        id: "lua-decompile",
        label: "Decompile",
        blurb: "Lift Lua / LuaJIT / Luau bytecode back to readable source.",
        entry: "lua_decompile",
        inputKind: "bytes",
        render: "lua-decompile",
        sample: fileSample("greet.luac", "Lua 5.1 compiled chunk", "greet.luac"),
        inputLanguage: "text",
      },
      {
        id: "lua-detect",
        label: "Detect",
        blurb: "Identify the Lua dialect and any known obfuscator.",
        entry: "lua_detect",
        inputKind: "bytes",
        render: "lua-detect",
        sample: fileSample("greet.luac", "Lua 5.1 compiled chunk", "greet.luac"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "php",
    label: "PHP",
    modes: [
      {
        id: "php-detect",
        label: "Detect & Peel",
        blurb: "Classify PHP source / phar and peel base64+eval encoder chains.",
        entry: "php_detect",
        inputKind: "text",
        render: "php",
        sample: inlineSample("eval chain", "base64_decode + eval", PHP_EVAL_SAMPLE),
        inputLanguage: "php",
      },
    ],
  },
  {
    id: "ruby",
    label: "Ruby",
    modes: [
      {
        id: "ruby-detect",
        label: "Detect & Analyze",
        blurb: "Classify the Ruby flavor (MRI source, YARV, mruby, wrappers).",
        entry: "ruby_detect",
        inputKind: "text",
        render: "ruby",
        sample: inlineSample("ruby source", "MRI source snippet", RUBY_SOURCE_SAMPLE),
        inputLanguage: "ruby",
      },
    ],
  },
  {
    id: "beam",
    label: "BEAM",
    modes: [
      {
        id: "beam-recover",
        label: "Recover Source",
        blurb: "Lift Erlang or Elixir source back out of a compiled BEAM module.",
        entry: "beam_recover",
        inputKind: "bytes",
        render: "beam",
        sample: fileSample("beam_hello.beam", "compiled Elixir module", "beam_hello.beam"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "as3",
    label: "Flash / AS3",
    modes: [
      {
        id: "as3-analyze",
        label: "Decompile ABC",
        blurb: "Extract the DoABC block from a SWF and decompile ActionScript 3 classes.",
        entry: "as3_analyze",
        inputKind: "bytes",
        render: "as3",
        sample: fileSample("as3_haxe.swf", "SWF with ActionScript 3", "as3_haxe.swf"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "scriptlang",
    label: "Scripted Langs",
    modes: [
      {
        id: "scriptlang-analyze",
        label: "Analyze Artifact",
        blurb: "Classify and recover Perl, R, Tcl, Haxe, and Windows-script artifacts.",
        entry: "scriptlang_analyze",
        inputKind: "bytes",
        render: "scriptlang",
        sample: fileSample(
          "script_perl_concise.txt",
          "Perl B::Concise dump",
          "script_perl_concise.txt",
        ),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "shell",
    label: "Shell / Batch",
    modes: [
      {
        id: "shell-deob",
        label: "Detect & Deobfuscate",
        blurb: "Fingerprint the dialect and fold batch var-indirection, loops, and branches.",
        entry: "shell_deob",
        inputKind: "text",
        render: "shell",
        sample: inlineSample("batch loader", "set-indirection + loop", BATCH_OBF_SAMPLE),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "mobile",
    label: "Mobile",
    modes: [
      {
        id: "mobile-detect",
        label: "Detect Bundle",
        blurb: "Classify the mobile bundle and list its top-level Android children.",
        entry: "mobile_detect",
        inputKind: "bytes",
        render: "mobile",
        sample: fileSample("android_app.apk", "Android DEX APK", "android_app.apk"),
        inputLanguage: "text",
      },
    ],
  },
  {
    id: "reference",
    label: "Reference",
    modes: [
      {
        id: "about",
        label: "About / CLI",
        blurb: "What disrobe is, how the CLI works, and what runs only outside the browser.",
        entry: null,
        inputKind: "text",
        render: "json",
        inputLanguage: "text",
        reference: true,
      },
    ],
  },
];

export const ALL_MODES: readonly Mode[] = ECOSYSTEMS.flatMap(
  (eco: Ecosystem): readonly Mode[] => eco.modes,
);

export function modeById(id: string): Mode | undefined {
  return ALL_MODES.find((mode: Mode): boolean => mode.id === id);
}

export function modeByEntry(entry: string): Mode | undefined {
  return ALL_MODES.find((mode: Mode): boolean => mode.entry === entry);
}

export const DEFAULT_MODE_ID: string = "py-decompile";
