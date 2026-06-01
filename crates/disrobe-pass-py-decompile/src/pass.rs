use disrobe_core::{Artifact, Capability, LegacyPass, PassId, Result as CoreResult, Rung};

use crate::error::DecompileError;

#[derive(Debug, Default)]
pub struct DecompilePass;

impl DecompilePass {
    pub const ID: PassId = "py.decompile";

    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn dispatch_runtime(runtime: AltRuntime) -> crate::error::Result<()> {
        match runtime {
            AltRuntime::CPython | AltRuntime::PyPy => Ok(()),
            AltRuntime::MicroPython => Err(DecompileError::AltRuntimeUnsupported {
                runtime: "micropython",
                suggestion: "use disrobe-pass-py-disasm",
            }),
            AltRuntime::Jython => Err(DecompileError::AltRuntimeUnsupported {
                runtime: "jython",
                suggestion: "use disrobe-pass-py-disasm + delegate to disrobe-pass-jvm",
            }),
            AltRuntime::IronPython => Err(DecompileError::AltRuntimeUnsupported {
                runtime: "ironpython",
                suggestion: "use disrobe-pass-py-disasm + delegate to disrobe-pass-dotnet",
            }),
            AltRuntime::Brython => Err(DecompileError::AltRuntimeUnsupported {
                runtime: "brython",
                suggestion: "use disrobe-pass-py-disasm + delegate to disrobe-pass-js-deob",
            }),
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
        let mut next: Artifact = artifact.clone();
        next.rung = Rung::Surface;
        for emitter in <Self as LegacyPass>::PRODUCES {
            next.add_capability(emitter());
        }
        Ok(next)
    }
}
