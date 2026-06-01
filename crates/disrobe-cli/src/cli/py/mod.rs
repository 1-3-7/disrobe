#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

mod decompile;
mod deob;
mod disasm;
mod extract;

use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};

use super::emit::EmitSpec;
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
            help = "decompiler backend: `native` (in-tree engine, deterministic, no external tools) | `pycdc` | `decompyle3` | `uncompyle6` (external subprocess; must be on PATH)"
        )]
        backend: DecompileBackend,
        #[arg(
            long,
            help = "emit a JSON manifest line on stdout after the summary (sidecar always written)"
        )]
        json: bool,
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
    Pycdc,
    Decompyle3,
    Uncompyle6,
}

impl DecompileBackend {
    const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Pycdc => "pycdc",
            Self::Decompyle3 => "decompyle3",
            Self::Uncompyle6 => "uncompyle6",
        }
    }

    const fn external_tool_name(self) -> Option<&'static str> {
        match self {
            Self::Native => None,
            Self::Pycdc => Some("pycdc"),
            Self::Decompyle3 => Some("decompyle3"),
            Self::Uncompyle6 => Some("uncompyle6"),
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
            emit,
        } => decompile::decompile(input, out, backend, json, emit, llm_flags),
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

pub(super) fn render_disasm(
    code: &disrobe_py_marshal::CodeObject,
    ver: disrobe_py_marshal::PyVersion,
) -> String {
    let ins: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(code, ver);
    disrobe_pass_py_disasm::render_dis(&ins)
        .lines()
        .map(|l| format!("# {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for variant in [exe, &format!("{exe}.exe")] {
            let p: PathBuf = dir.join(variant);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

pub(super) fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the py pass in this build",
        )?;
    }
    Ok(())
}
