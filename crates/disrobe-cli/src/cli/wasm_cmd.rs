use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

#[derive(Subcommand, Debug)]
pub(crate) enum WasmCmd {
    #[command(
        about = "decompile a WebAssembly module to JSON summary, Rust, TypeScript, WAT, or C pseudo-source"
    )]
    Decompile {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output path")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = WasmTarget::Wat,
            help = "wat (default) lifts every function body to real WebAssembly text; rust / ts / c lift via SSA + structured reloop; json emits the analyzer summary only"
        )]
        target: WasmTarget,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report (non-applicable kinds are written as stubs)"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "deobfuscate a WebAssembly module: transforms 3 families (Jscrambler-WASM, Wobfuscator, Wasmixer); Tigress -> Emscripten classify-only; wasm-name-obfuscator classify-only"
    )]
    Deob {
        #[arg(help = ".wasm input module")]
        input: Option<PathBuf>,
        #[arg(short, long, help = "output path for the lifted WAT source")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "also write the recovered .wasm module (MBA-folded, opaque-predicate stripped, call_indirect resolved, control-flow unflattened, decrypt stubs run) to this path"
        )]
        emit_wasm: Option<PathBuf>,
        #[arg(
            long,
            help = "list WebAssembly obfuscators and whether they transform or classify only, then exit"
        )]
        list: bool,
    },
    #[command(
        about = "parse a WebAssembly Component Model envelope and emit its world / adapter manifest"
    )]
    Component {
        #[arg(help = ".wasm component input")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the component manifest JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "recover the WebAssembly GC type graph (struct / array / ref types) from a module"
    )]
    Types {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the GC type graph JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "lift the WebAssembly GC type graph to reconstructed high-level struct / array types and emit typed Rust + TypeScript source"
    )]
    LiftGc {
        #[arg(help = ".wasm input module")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-gc-hir)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "emit the reconstructed GC HIR as machine-clean JSON to stdout (no human-readable summary, no file output)"
        )]
        json: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WasmTarget {
    Json,
    Rust,
    Ts,
    Wat,
    C,
}
