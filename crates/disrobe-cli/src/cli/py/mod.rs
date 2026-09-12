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
        #[arg(
            help = "obfuscated Python source file (or a raw headerless .marshal code-object blob)"
        )]
        input: Option<PathBuf>,
        #[arg(short, long, help = "output path for the deobfuscated source")]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "run ruff-AST constant-fold + dead-branch elimination after peel"
        )]
        cleanup: bool,
        #[arg(
            long,
            value_name = "MAJOR.MINOR",
            help = "Python version hint for marshal recovery (e.g. 3.12); inferred from the bytecode when omitted"
        )]
        pyver: Option<String>,
        #[arg(
            long,
            help = "list the Python obfuscators disrobe can detect and peel, then exit"
        )]
        list: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report (non-applicable kinds are written as stubs)"
        )]
        emit: Vec<String>,
    },
    #[command(
        about = "decrypt a sourcedefender .pye envelope: legacy armored bodies decrypt from the filename-derived key; modern v16 hex bodies are an aes-256-gcm runtime-key wall by default but decrypt statically when a known 32-byte key is supplied via --key"
    )]
    Sourcedefender {
        #[arg(help = ".pye envelope to decrypt")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the decrypted msgpack payload")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_name = "HEX64",
            help = "64 hex chars (32 bytes) of the aes-256-gcm key for a modern v16 body, decrypting it statically (default modern mode is a runtime-license-key wall)"
        )]
        key: Option<String>,
        #[arg(
            long,
            value_name = "PASSWORD",
            help = "custom-mode password (or set SOURCEDEFENDER_PASSWORD); the upstream password->key derivation lives in the closed-source Cython engine, so disrobe reports how to supply the derived key via --key rather than guessing the kdf"
        )]
        password: Option<String>,
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
        about = "decompile a .pyc back to readable Python source (auto-deobfuscates first if the input matches a known Python obfuscator); in-tree native engine supporting CPython 1.0..3.15 with frame-tree + per-version opcode dispatch + round-trip verification"
    )]
    Decompile {
        #[arg(help = ".pyc input file (or obfuscated Python source; auto-deobfuscated)")]
        input: Option<PathBuf>,
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
        #[arg(
            long,
            help = "list the Python obfuscators disrobe auto-deobfuscates, then exit"
        )]
        list: bool,
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
            pyver,
            list,
            emit,
        } => deob::deob(input, out, cleanup, pyver, list, emit, llm_flags),
        PyCmd::Sourcedefender {
            input,
            out,
            key,
            password,
        } => extract::sourcedefender(input, out, key, password),
        PyCmd::Disasm { input, out, emit } => disasm::disasm(input, out, emit, llm_flags),
        PyCmd::Decompile {
            input,
            out,
            backend,
            json,
            no_roundtrip,
            list,
            emit,
        } => decompile::decompile(
            input,
            out,
            backend,
            json,
            no_roundtrip,
            list,
            emit,
            llm_flags,
        ),
        PyCmd::Extract { input, out } => extract::extract(input, out),
    }
}

pub(super) fn py_obj_label(obj: &disrobe_py_marshal::Object) -> String {
    match obj {
        disrobe_py_marshal::Object::String { value, .. }
        | disrobe_py_marshal::Object::Unicode { value, .. }
        | disrobe_py_marshal::Object::ShortAscii { value, .. } => value.clone(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use disrobe_py_marshal::{Object, PyVersion, load};

    use super::py_obj_label;

    #[test]
    fn unicode_const_surfaces_as_clean_string() {
        let marshalled: Vec<u8> = disrobe_py_marshal::dump(
            &Object::Unicode {
                value: "café".to_owned(),
                interned: false,
            },
            PyVersion::PY312,
        )
        .expect("marshal a u-tagged unicode value");
        let decoded: Object = load(&marshalled, PyVersion::PY312).expect("decode u-tagged value");
        assert!(
            matches!(decoded, Object::Unicode { .. }),
            "a 'u' tag must decode to Object::Unicode under py3",
        );
        assert_eq!(
            py_obj_label(&decoded),
            "café",
            "a u-tagged name/const must label as its string, not a debug repr",
        );
    }
}
