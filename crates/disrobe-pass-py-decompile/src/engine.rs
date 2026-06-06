use std::time::Instant;

use disrobe_py_marshal::{
    CodeObject, Object, PyVersion as MarshalVersion, PycFile, pyversion_from_magic, read_pyc,
};

use crate::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::codegen::DefaultEmitter;
use crate::emit::{EmitOutput, EmitPipeline};
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
    match build_real_source(&code, &decompile_version, marshal_version) {
        Ok(src) => Ok(NativeDecompile {
            source: src,
            marshal_version,
            decompile_version,
            code,
            recovered_directly: true,
            fallback_reason: None,
        }),
        Err(real_err) => {
            let reason: String = format!("{real_err}");
            let fallback: String = disasm_fallback_source(&code, &decompile_version, &reason);
            Ok(NativeDecompile {
                source: fallback,
                marshal_version,
                decompile_version,
                code,
                recovered_directly: false,
                fallback_reason: Some(reason),
            })
        }
    }
}

/// Stack size of the worker thread the AST structurer runs on. The region structurer recurses
/// through `structure_stmts` for every nested control-flow region, with large per-frame locals; on
/// the default 8 MiB main-thread stack a pathological (mis-recovered, non-shrinking) region can
/// abort the process before the builder's catchable depth guard fires. Running it on a generous
/// stack guarantees the depth guard (a recoverable `Err`) is always what bounds the recursion.
const STRUCTURE_STACK_BYTES: usize = 256 * 1024 * 1024;

pub fn build_real_source(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> Result<String> {
    let started: Instant = Instant::now();
    let frame_tree: FrameTree = builder_for(marshal_version).build(code, marshal_version)?;
    let module: AstModule = std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
        std::thread::Builder::new()
            .stack_size(STRUCTURE_STACK_BYTES)
            .spawn_scoped(scope, || {
                DefaultAstBuilder::new().build_module(code, &frame_tree, decompile_version)
            })
            .map_err(DecompileError::Io)?
            .join()
            .map_err(
                |_panic: Box<dyn std::any::Any + Send>| DecompileError::Emit {
                    reason: "ast structurer worker thread panicked".to_owned(),
                },
            )?
    })?;
    let pipeline: EmitPipeline = EmitPipeline {
        emitter: Box::new(DefaultEmitter::new()),
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
    Ok(out.source)
}

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
