use disrobe_core::{
    Artifact, Capability, CoreError, LegacyPass, PassId, Result as CoreResult, Rung,
};
use miette::Diagnostic;

use disrobe_pass_py_disasm::alt_runtimes::recover::{
    AltRecovery, RecoveredSource, recover_detected,
};
use disrobe_pass_py_disasm::alt_runtimes::{
    AltRuntime as DisasmRuntime, detect_runtime as detect_alt,
};

use crate::engine::{NativeDecompile, decompile_micropython, decompile_pyc, decompile_pypy};
use crate::error::DecompileError;

fn tagged(err: &DecompileError) -> String {
    err.code()
        .map_or_else(|| format!("{err}"), |code| format!("{code}: {err}"))
}

#[derive(Debug, Default)]
pub struct DecompilePass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRoute {
    NativeMarshal,
    AltRuntimeDelegated,
}

impl DecompilePass {
    pub const ID: PassId = "py.decompile";

    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn dispatch_runtime(runtime: AltRuntime) -> RuntimeRoute {
        match runtime {
            AltRuntime::CPython | AltRuntime::PyPy | AltRuntime::MicroPython => {
                RuntimeRoute::NativeMarshal
            }
            AltRuntime::Jython | AltRuntime::IronPython | AltRuntime::Brython => {
                RuntimeRoute::AltRuntimeDelegated
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AltRuntime {
    CPython,
    PyPy,
    MicroPython,
    Jython,
    IronPython,
    Brython,
}

const PYPY_MARKER_MASK: u32 = 0xFFFF_0000;
const PYPY_MARKER_VALUE: u32 = 0xA1B2_0000;
const PYPY_MAGIC_27: u32 = 0xC0DE_F517;
const PYPY_MAGIC_310: u32 = 0xC0DE_F511;
const PYPY_MAGIC_311: u32 = 0xC0DE_F512;
const PYPY_MAGIC_312: u32 = 0xC0DE_F513;
const MICROPYTHON_MARKER: u32 = 0x0000_004D;
const JYTHON_CLASSFILE_MAGIC: u32 = 0xCAFE_BABE;
const PE_DOS_MAGIC_LO: u32 = 0x0000_5A4D;
const BRYTHON_MARKER: u32 = 0x4252_5954;

#[must_use]
pub fn detect_runtime(magic: u32) -> AltRuntime {
    if magic == JYTHON_CLASSFILE_MAGIC {
        return AltRuntime::Jython;
    }
    if (magic & 0x0000_FFFF) == PE_DOS_MAGIC_LO {
        return AltRuntime::IronPython;
    }
    if (magic & 0x0000_00FF) == MICROPYTHON_MARKER && (magic & 0x0000_FF00) <= 0x0600 {
        return AltRuntime::MicroPython;
    }
    if magic == BRYTHON_MARKER {
        return AltRuntime::Brython;
    }
    if matches!(
        magic,
        PYPY_MAGIC_27 | PYPY_MAGIC_310 | PYPY_MAGIC_311 | PYPY_MAGIC_312
    ) || (magic & PYPY_MARKER_MASK) == PYPY_MARKER_VALUE
    {
        return AltRuntime::PyPy;
    }
    AltRuntime::CPython
}

impl LegacyPass for DecompilePass {
    const CONSUMES: &'static [Rung] = &[Rung::Disasm];
    const EMITS: &'static [Rung] = &[Rung::Surface];
    const REQUIRES: &'static [fn() -> Capability] = &[];
    const PRODUCES: &'static [fn() -> Capability] =
        &[|| Capability::produces("py.decompile.surface", 1)];

    fn id(&self) -> PassId {
        Self::ID
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        if bytes.len() < 4 {
            return Err(CoreError::PassFailure(
                "DR-PYDEC-0011: pyc header too short".to_string(),
            ));
        }
        match detect_alt(bytes) {
            Some(DisasmRuntime::PyPy) => {
                let decompiled: NativeDecompile = decompile_pypy(bytes)
                    .map_err(|e: DecompileError| CoreError::PassFailure(tagged(&e)))?;
                return Ok(self.finish(decompiled.source.into_bytes(), artifact.root_hash));
            }
            Some(DisasmRuntime::MicroPython) => {
                let decompiled: NativeDecompile = decompile_micropython(bytes)
                    .map_err(|e: DecompileError| CoreError::PassFailure(tagged(&e)))?;
                return Ok(self.finish(decompiled.source.into_bytes(), artifact.root_hash));
            }
            Some(_) => {
                if let Some(recovery) = recover_detected(bytes).as_ref() {
                    return Ok(self.emit_alt_runtime(recovery, artifact.root_hash));
                }
            }
            None => {}
        }
        let decompiled: NativeDecompile =
            decompile_pyc(bytes).map_err(|e: DecompileError| CoreError::PassFailure(tagged(&e)))?;
        Ok(self.finish(decompiled.source.into_bytes(), artifact.root_hash))
    }
}

impl DecompilePass {
    fn finish(&self, body: Vec<u8>, root_hash: [u8; 32]) -> Artifact {
        let mut next: Artifact = Artifact::new(Rung::Surface, body, root_hash);
        for emitter in <Self as LegacyPass>::PRODUCES {
            next.add_capability(emitter());
        }
        next
    }

    fn emit_alt_runtime(&self, recovery: &AltRecovery, root_hash: [u8; 32]) -> Artifact {
        let body: String = recovery.source.as_ref().map_or_else(
            || recovery.disasm_text.clone(),
            |source: &RecoveredSource| render_recovered_source(recovery.label, source),
        );
        self.finish(body.into_bytes(), root_hash)
    }
}

fn render_recovered_source(label: &str, source: &RecoveredSource) -> String {
    format!(
        "// recovered from {label} via {} decompilation\n{}",
        source.language.label(),
        source.text
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::PassMetadata;

    #[test]
    fn py_decompile_pass_metadata_advertises_capabilities() {
        let p: DecompilePass = DecompilePass::new();
        assert_eq!(PassMetadata::id(&p), "py.decompile");
        assert_eq!(p.emits(), &[Rung::Surface]);
        assert_eq!(p.produced_capabilities().len(), 1);
    }

    #[test]
    fn dispatch_routes_cpython_and_pypy_to_native() {
        assert_eq!(
            DecompilePass::dispatch_runtime(AltRuntime::CPython),
            RuntimeRoute::NativeMarshal
        );
        assert_eq!(
            DecompilePass::dispatch_runtime(AltRuntime::PyPy),
            RuntimeRoute::NativeMarshal
        );
    }

    #[test]
    fn dispatch_routes_alt_runtimes_to_delegation() {
        for rt in [
            AltRuntime::Jython,
            AltRuntime::IronPython,
            AltRuntime::Brython,
        ] {
            assert_eq!(
                DecompilePass::dispatch_runtime(rt),
                RuntimeRoute::AltRuntimeDelegated
            );
        }
    }

    #[test]
    fn py_decompile_run_on_micropython_emits_source() {
        let bytes: &[u8] =
            include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
        let input: Artifact = Artifact::new(Rung::Disasm, bytes.to_vec(), [0u8; 32]);
        let out: Artifact = DecompilePass::new()
            .run(&input)
            .expect("micropython routes");
        let text: String = String::from_utf8_lossy(out.envelope.as_slice()).into_owned();
        assert!(text.contains("def add"), "got: {text}");
        assert!(text.contains("return"), "got: {text}");
        assert!(text.contains("print"), "got: {text}");
    }

    #[test]
    fn py_decompile_run_on_garbage_magic_returns_pass_failure() {
        let input: Artifact = Artifact::new(Rung::Disasm, vec![0u8; 8], [0u8; 32]);
        let err: CoreError = DecompilePass::new()
            .run(&input)
            .expect_err("unknown pyc magic must fail");
        let text: String = format!("{err}");
        assert!(text.contains("DR-PYDEC"), "got: {text}");
    }
}
