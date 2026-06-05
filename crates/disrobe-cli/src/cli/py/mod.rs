#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

mod decompile;
mod deob;
mod disasm;
mod extract;

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use super::llm::LlmFlags;

#[derive(Subcommand, Debug)]
pub(crate) enum PyCmd {
    #[command(
        about = "peel a Python obfuscator wrapper (hyperion, kramer, berserker, jawbreaker, blankobf, plusobf, wodx, oxyry, pyminifier, manglify, pyobfuscate.com, ...) & optionally clean up with a ruff-AST pass"
    )]
    Deob {
        #[arg(help = "obfuscated Python source file")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the deobfuscated source")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "run ruff-AST constant-fold + dead-branch elimination after peel"
        )]
        cleanup: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report (non-applicable kinds are written as stubs)"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "decrypt a sourcedefender .pye envelope (filename-derived password + AES + msgpack)"
    )]
    Sourcedefender {
        #[arg(help = ".pye envelope to decrypt")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the decrypted msgpack payload")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "disassemble a .pyc into a per-instruction trace (CPython 1.0 .. 3.15 + PyPy + MicroPython + Jython + IronPython + Brython)"
    )]
    Disasm {
        #[arg(help = ".pyc input file")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the disassembly text")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "decompile a .pyc back to readable Python source (default: in-tree native engine supporting CPython 1.0..3.15 with frame-tree + per-version opcode dispatch + round-trip verification)"
    )]
    Decompile {
        #[arg(help = ".pyc input file")]
        input: PathBuf,
        #[arg(short, long, help = "output directory")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = DecompileBackend::Native,
            help = "decompiler backend: `native` (in-tree CPython 1.0..3.15 engine; the only supported value)"
        )]
        backend: DecompileBackend,
        #[arg(
            long,
            help = "emit a JSON manifest line on stdout after the summary (sidecar always written)"
        )]
        json: bool,
        #[arg(
            long,
            help = "skip the recompile-equivalence check (no Python subprocess; for sandboxed/paranoid runs)"
        )]
        no_roundtrip: bool,
        #[arg(long, value_delimiter = ',', help = "comma-separated emit kinds")]
        emit: Vec<String>,
    },
    #[command(
        about = "extract a Python wheel, sdist, egg, .whl, .zip, or any other archive container"
    )]
    Extract {
        #[arg(help = "archive to extract")]
        input: PathBuf,
        #[arg(short, long, help = "output directory")]
        out: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DecompileBackend {
    Native,
}

impl DecompileBackend {
    const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
        }
    }
}

pub(crate) fn run(action: PyCmd, llm_flags: &LlmFlags) -> miette::Result<()> {
    match action {
        PyCmd::Deob {
            input,
            out,
            cleanup,
            emit,
        } => deob::deob(input, out, cleanup, emit, llm_flags),
        PyCmd::Sourcedefender { input, out } => extract::sourcedefender(input, out),
        PyCmd::Disasm { input, out, emit } => disasm::disasm(input, out, emit, llm_flags),
        PyCmd::Decompile {
            input,
            out,
            backend,
            json,
            no_roundtrip,
            emit,
        } => decompile::decompile(input, out, backend, json, no_roundtrip, emit, llm_flags),
        PyCmd::Extract { input, out } => extract::extract(input, out),
    }
}

pub(super) fn py_obj_label(obj: &disrobe_py_marshal::Object) -> String {
    match obj {
        disrobe_py_marshal::Object::String { value, .. }
        | disrobe_py_marshal::Object::ShortAscii { value, .. } => value.clone(),
        other => format!("{other:?}"),
    }
}
