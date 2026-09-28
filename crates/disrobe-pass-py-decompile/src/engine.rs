use std::time::Instant;

use disrobe_py_marshal::{
    CodeObject, Object, PyVersion as MarshalVersion, PycFile, load, pyversion_from_magic, read_pyc,
};

use disrobe_pass_py_disasm::alt_runtimes::micropython::{MpyBytecodeModule, parse_bytecode};
use disrobe_pass_py_disasm::alt_runtimes::pypy::{PyPyModule, PyPyVariant, parse as parse_pypy};

use crate::alt_lift::mpy::lift_module as lift_mpy_module;
use crate::ast::builder::take_stubbed_scopes;
use crate::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::codegen::{DefaultEmitter, module_has_unicode_literals};
use crate::emit::{
    EmitOutput, EmitPipeline, LeakedMarker, authentic_literal_markers, carries_a_marker,
    find_leaked_marker,
};
use crate::error::{DecompileError, Result};
use crate::frame_tree::{FrameTree, builder_for};

#[derive(Debug, Clone)]
pub struct NativeDecompile {
    pub source: String,
    pub marshal_version: MarshalVersion,
    pub decompile_version: DecompileVersion,
    pub code: CodeObject,
    pub recovered_directly: bool,
    pub fallback_reason: Option<String>,
    pub stubbed_scopes: usize,
}

impl NativeDecompile {
    #[must_use]
    pub const fn is_disasm_fallback(&self) -> bool {
        self.fallback_reason.is_some()
    }

    #[must_use]
    pub fn source_confidence(&self) -> f64 {
        if self.is_disasm_fallback() {
            return 0.0;
        }
        let scopes: usize = code_object_count(&self.code).max(1);
        let recovered: usize = scopes.saturating_sub(self.stubbed_scopes);
        recovered as f64 / scopes as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    pub source: String,
    pub stubbed_scopes: usize,
}

fn code_object_count(root: &CodeObject) -> usize {
    let mut count: usize = 0;
    let mut pending: Vec<&CodeObject> = vec![root];
    while let Some(code) = pending.pop() {
        count = count.saturating_add(1);
        for constant in &code.consts {
            if let Object::Code(nested) = constant {
                pending.push(nested);
            }
        }
    }
    count
}

fn native_outcome(
    code: CodeObject,
    marshal_version: MarshalVersion,
    decompile_version: DecompileVersion,
) -> NativeDecompile {
    match build_recovered_source(&code, &decompile_version, marshal_version) {
        Ok(recovered) => NativeDecompile {
            source: recovered.source,
            marshal_version,
            decompile_version,
            code,
            recovered_directly: recovered.stubbed_scopes == 0,
            fallback_reason: None,
            stubbed_scopes: recovered.stubbed_scopes,
        },
        Err(real_err) => {
            let reason: String = format!("{real_err}");
            let fallback: String = disasm_fallback_source(&code, &decompile_version, &reason);
            NativeDecompile {
                source: fallback,
                marshal_version,
                decompile_version,
                code,
                recovered_directly: false,
                fallback_reason: Some(reason),
                stubbed_scopes: 0,
            }
        }
    }
}

pub fn decompile_pyc(bytes: &[u8]) -> Result<NativeDecompile> {
    if bytes.len() < 4 {
        return Err(DecompileError::Marshal(
            disrobe_py_marshal::Error::PycHeaderShort {
                need: 4,
                got: bytes.len(),
            },
        ));
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let marshal_version: MarshalVersion =
        pyversion_from_magic(magic).ok_or_else(|| DecompileError::UnsupportedVersion {
            version: format!("unknown pyc magic 0x{magic:08x}"),
        })?;
    let pyc: PycFile = read_pyc(bytes)?;
    let code: CodeObject = match pyc.code {
        Object::Code(boxed) => *boxed,
        other => {
            return Err(DecompileError::Emit {
                reason: format!("pyc top-level object is not a code object: {other:?}"),
            });
        }
    };
    let decompile_version: DecompileVersion = marshal_to_decompile(marshal_version)?;
    Ok(native_outcome(code, marshal_version, decompile_version))
}

pub fn decompile_pypy(bytes: &[u8]) -> Result<NativeDecompile> {
    let module: PyPyModule =
        parse_pypy(bytes).map_err(|e: disrobe_pass_py_disasm::AltRuntimeError| {
            DecompileError::UnsupportedRuntime {
                runtime: format!("pypy container: {e}"),
            }
        })?;
    let compat: MarshalVersion = module.compat_version();
    let code: CodeObject = match load(&module.payload, compat) {
        Ok(Object::Code(boxed)) => *boxed,
        Ok(other) => {
            return Err(DecompileError::Emit {
                reason: format!("pypy payload top-level object is not a code object: {other:?}"),
            });
        }
        Err(e) => return Err(DecompileError::Marshal(e)),
    };
    let base: DecompileVersion = marshal_to_decompile(compat)?;
    let decompile_version: DecompileVersion = DecompileVersion::PyPy(Box::new(base));
    Ok(native_outcome(code, compat, decompile_version))
}

#[must_use]
pub const fn pypy_variant_label(variant: PyPyVariant) -> &'static str {
    match variant {
        PyPyVariant::PyPy27 => "pypy2.7",
        PyPyVariant::PyPy37 => "pypy3.7",
        PyPyVariant::PyPy39 => "pypy3.9",
        PyPyVariant::PyPy310 => "pypy3.10",
    }
}

pub fn decompile_micropython(bytes: &[u8]) -> Result<NativeDecompile> {
    let module: MpyBytecodeModule =
        parse_bytecode(bytes).map_err(|e: disrobe_pass_py_disasm::AltRuntimeError| {
            DecompileError::UnsupportedRuntime {
                runtime: format!("micropython container: {e}"),
            }
        })?;
    let code: CodeObject = lift_mpy_module(&module)?;
    let decompile_version: DecompileVersion = DecompileVersion::V3_10;
    let marshal_version: MarshalVersion = MarshalVersion {
        major: 3,
        minor: 10,
    };
    Ok(native_outcome(code, marshal_version, decompile_version))
}

#[cfg(not(target_arch = "wasm32"))]
const STRUCTURE_STACK_BYTES: usize = 256 * 1024 * 1024;

#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn wall_clock_start() -> Option<Instant> {
    Some(Instant::now())
}

#[cfg(target_arch = "wasm32")]
#[inline]
const fn wall_clock_start() -> Option<Instant> {
    None
}

fn structure_module_here(
    code: &CodeObject,
    frame_tree: &FrameTree,
    decompile_version: &DecompileVersion,
) -> Result<(AstModule, usize)> {
    let module: AstModule =
        DefaultAstBuilder::new().build_module(code, frame_tree, decompile_version)?;
    Ok((module, take_stubbed_scopes()))
}

#[cfg(not(target_arch = "wasm32"))]
fn structure_module(
    code: &CodeObject,
    frame_tree: &FrameTree,
    decompile_version: &DecompileVersion,
) -> Result<(AstModule, usize)> {
    std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
        std::thread::Builder::new()
            .stack_size(STRUCTURE_STACK_BYTES)
            .spawn_scoped(scope, || {
                structure_module_here(code, frame_tree, decompile_version)
            })
            .map_err(DecompileError::Io)?
            .join()
            .map_err(
                |_panic: Box<dyn std::any::Any + Send>| DecompileError::Emit {
                    reason: "ast structurer worker thread panicked".to_owned(),
                },
            )?
    })
}

#[cfg(target_arch = "wasm32")]
fn structure_module(
    code: &CodeObject,
    frame_tree: &FrameTree,
    decompile_version: &DecompileVersion,
) -> Result<(AstModule, usize)> {
    structure_module_here(code, frame_tree, decompile_version)
}

pub fn build_real_source(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> Result<String> {
    build_recovered_source(code, decompile_version, marshal_version)
        .map(|recovered: RecoveredSource| recovered.source)
}

pub fn build_recovered_source(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> Result<RecoveredSource> {
    let started: Option<Instant> = wall_clock_start();
    let frame_tree: FrameTree = builder_for(marshal_version).build(code, marshal_version)?;
    let (mut module, stubbed_scopes): (AstModule, usize) =
        structure_module(code, &frame_tree, decompile_version)?;
    crate::selfcheck::verify_and_repair(&mut module, code, decompile_version);
    let pipeline: EmitPipeline = EmitPipeline {
        emitter: Box::new(DefaultEmitter {
            unicode_literals: module_has_unicode_literals(&module),
            ..DefaultEmitter::new()
        }),
        formatter_enabled: false,
        include_provenance: false,
        include_llm_json: false,
        preserve_blank_lines: true,
    };
    let module_is_empty: bool = module.docstring.is_none() && module.body.is_empty();
    let out: EmitOutput = pipeline.run(&module, decompile_version, started)?;
    if !module_is_empty && out.source.trim().is_empty() {
        return Err(DecompileError::Emit {
            reason: "emit pipeline produced empty source".to_owned(),
        });
    }
    let leaked: Option<LeakedMarker> = if carries_a_marker(&out.source) {
        find_leaked_marker(&out.source, &authentic_literal_markers(code))
    } else {
        None
    };
    if let Some(marker) = leaked {
        return Err(DecompileError::UnresolvedMarker {
            stem: marker.stem,
            line: marker.line,
        });
    }
    Ok(RecoveredSource {
        source: out.source,
        stubbed_scopes,
    })
}

#[must_use]
pub fn disasm_fallback_source(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    real_err: &str,
) -> String {
    let marshal_version: MarshalVersion = MarshalVersion {
        major: decompile_version.major(),
        minor: decompile_version.minor(),
    };
    let ins: Vec<disrobe_pass_py_disasm::Instruction> =
        disrobe_pass_py_disasm::disassemble(code, marshal_version);
    let disasm: String = disrobe_pass_py_disasm::render_dis(&ins);
    format!(
        "# decompile-error: {}\n# disrobe py.decompile (disasm fallback)\n# python {}.{}\n# {} instructions\n\n{}",
        real_err,
        decompile_version.major(),
        decompile_version.minor(),
        ins.len(),
        disasm,
    )
}

pub fn marshal_to_decompile(version: MarshalVersion) -> Result<DecompileVersion> {
    let mapped: DecompileVersion = match (version.major, version.minor) {
        (1, 0) => DecompileVersion::V1_0,
        (1, 1) => DecompileVersion::V1_1,
        (1, 3) => DecompileVersion::V1_3,
        (1, 4) => DecompileVersion::V1_4,
        (1, 5) => DecompileVersion::V1_5,
        (1, 6) => DecompileVersion::V1_6,
        (2, 0) => DecompileVersion::V2_0,
        (2, 1) => DecompileVersion::V2_1,
        (2, 2) => DecompileVersion::V2_2,
        (2, 3) => DecompileVersion::V2_3,
        (2, 4) => DecompileVersion::V2_4,
        (2, 5) => DecompileVersion::V2_5,
        (2, 6) => DecompileVersion::V2_6,
        (2, 7) => DecompileVersion::V2_7,
        (3, 0) => DecompileVersion::V3_0,
        (3, 1) => DecompileVersion::V3_1,
        (3, 2) => DecompileVersion::V3_2,
        (3, 3) => DecompileVersion::V3_3,
        (3, 4) => DecompileVersion::V3_4,
        (3, 5) => DecompileVersion::V3_5,
        (3, 6) => DecompileVersion::V3_6,
        (3, 7) => DecompileVersion::V3_7,
        (3, 8) => DecompileVersion::V3_8,
        (3, 9) => DecompileVersion::V3_9,
        (3, 10) => DecompileVersion::V3_10,
        (3, 11) => DecompileVersion::V3_11,
        (3, 12) => DecompileVersion::V3_12,
        (3, 13) => DecompileVersion::V3_13,
        (3, 14) => DecompileVersion::V3_14,
        (3, 15) => DecompileVersion::V3_15,
        (major, minor) => {
            return Err(DecompileError::UnsupportedVersion {
                version: format!("{major}.{minor}"),
            });
        }
    };
    Ok(mapped)
}
