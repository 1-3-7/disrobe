#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::path::{Path, PathBuf};

use disrobe_pass_native::{Arch, DisasmInsn, NativeFormat, disassemble};
use disrobe_pass_py_decompile::{
    NativeDecompile, RoundtripOutcome, RoundtripStatus, decompile_pyc, roundtrip_native,
};
use disrobe_py_marshal::{PyVersion, magic_for};
use object::{Architecture, Object, ObjectSection, SectionKind};

use crate::common::pyc::{fingerprint, python_version_for_magic};
use crate::debug::{dbg_hex, dbg_kv};
use crate::error::{Error, Result};
use crate::{MAX_RECOVERY_FILE_BYTES, read_file_bounded};

#[derive(Debug, Clone)]
pub struct RecoveredModule {
    pub name: String,
    pub source: String,
    pub python_major: u8,
    pub python_minor: u8,
    pub recovered_directly: bool,
    pub fallback_reason: Option<String>,
    pub roundtrip: RoundtripGrade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundtripGrade {
    Perfect,
    Semantic,
    CodeDiff(String),
    NoInterpreter(String),
    RecompileFailed(String),
    NotAttempted,
}

impl RoundtripGrade {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Perfect => "perfect",
            Self::Semantic => "semantic",
            Self::CodeDiff(_) => "code-diff",
            Self::NoInterpreter(_) => "no-interpreter",
            Self::RecompileFailed(_) => "recompile-failed",
            Self::NotAttempted => "not-attempted",
        }
    }

    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        matches!(self, Self::Perfect | Self::Semantic)
    }
}

#[derive(Debug, Clone)]
pub struct SurfacedNative {
    pub name: String,
    pub disk_path: PathBuf,
    pub format: NativeFormat,
    pub arch: Arch,
    pub code_section: String,
    pub code_offset: u64,
    pub code_size: u64,
    pub instruction_count: usize,
    pub sample: Vec<DisasmInsn>,
}

const SAMPLE_INSTRUCTION_CAP: usize = 32;
const MAX_DISASM_BYTES: usize = 1 << 20;

#[must_use]
pub fn looks_like_bytecode(name: &str) -> bool {
    name.ends_with(".pyc") || name.ends_with(".pyo")
}

#[must_use]
pub fn looks_like_native_extension(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    lower.ends_with(".pyd") || lower.ends_with(".so") || lower.ends_with(".dll")
}

pub fn recover_bytecode_file(name: &str, disk_path: &Path) -> Result<RecoveredModule> {
    let bytes: Vec<u8> = read_file_bounded(disk_path, MAX_RECOVERY_FILE_BYTES)?;
    recover_bytecode(name, &bytes)
}

pub fn recover_bytecode(name: &str, pyc_bytes: &[u8]) -> Result<RecoveredModule> {
    dbg_kv("decompile", || {
        format!("{name} ({} bytes)", pyc_bytes.len())
    });
    dbg_hex("pyc-magic", pyc_bytes, 4);
    let decompiled: NativeDecompile =
        decompile_pyc(pyc_bytes).map_err(|e: disrobe_pass_py_decompile::DecompileError| {
            Error::Decompile {
                module: name.to_owned(),
                reason: e.to_string(),
            }
        })?;
    dbg_kv("decompile-version", || {
        format!(
            "{}.{} direct={}",
            decompiled.marshal_version.major,
            decompiled.marshal_version.minor,
            decompiled.recovered_directly
        )
    });
    let outcome: RoundtripOutcome = roundtrip_native(
        &decompiled.source,
        &decompiled.code,
        &decompiled.decompile_version,
        decompiled.marshal_version,
    );
    let roundtrip: RoundtripGrade = grade(outcome.status);
    dbg_kv("roundtrip", || format!("{name} -> {}", roundtrip.label()));
    Ok(RecoveredModule {
        name: name.to_owned(),
        source: decompiled.source,
        python_major: decompiled.marshal_version.major,
        python_minor: decompiled.marshal_version.minor,
        recovered_directly: decompiled.recovered_directly,
        fallback_reason: decompiled.fallback_reason,
        roundtrip,
    })
}

pub fn recover_raw_marshal(
    name: &str,
    marshal_bytes: &[u8],
    python_major: u8,
    python_minor: u8,
) -> Result<RecoveredModule> {
    let pyc: Vec<u8> = synthesize_pyc(marshal_bytes, python_major, python_minor)?;
    recover_bytecode(name, &pyc)
}

pub fn synthesize_pyc(marshal_bytes: &[u8], major: u8, minor: u8) -> Result<Vec<u8>> {
    let magic: u32 = magic_for(PyVersion { major, minor })
        .ok_or_else(|| Error::UnknownPycMagic((u32::from(major) << 8) | u32::from(minor)))?;
    let header_len: usize = if (major, minor) >= (3, 7) {
        16
    } else if (major, minor) >= (3, 3) {
        12
    } else {
        8
    };
    let mut out: Vec<u8> = Vec::with_capacity(header_len + marshal_bytes.len());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend(std::iter::repeat_n(0u8, header_len - 4));
    out.extend_from_slice(marshal_bytes);
    Ok(out)
}

fn grade(status: RoundtripStatus) -> RoundtripGrade {
    match status {
        RoundtripStatus::Perfect => RoundtripGrade::Perfect,
        RoundtripStatus::Semantic => RoundtripGrade::Semantic,
        RoundtripStatus::CodeDiff { detail } => RoundtripGrade::CodeDiff(detail),
        RoundtripStatus::NoInterpreter { hint } => RoundtripGrade::NoInterpreter(hint),
        RoundtripStatus::RecompileFailed { stderr } => RoundtripGrade::RecompileFailed(stderr),
        RoundtripStatus::Skipped => RoundtripGrade::NotAttempted,
    }
}

pub fn surface_native_file(name: &str, disk_path: &Path) -> Result<SurfacedNative> {
    let bytes: Vec<u8> = read_file_bounded(disk_path, MAX_RECOVERY_FILE_BYTES)?;
    let mut surfaced: SurfacedNative = surface_native(name, &bytes)?;
    surfaced.disk_path = disk_path.to_path_buf();
    Ok(surfaced)
}

pub fn surface_native(name: &str, bytes: &[u8]) -> Result<SurfacedNative> {
    let format: NativeFormat = disrobe_pass_native::detect_format(bytes)
        .map(|f| f.kind)
        .map_err(|e| Error::NativeSurface {
            module: name.to_owned(),
            reason: e.to_string(),
        })?;
    let file: object::File<'_> =
        object::File::parse(bytes).map_err(|e: object::Error| Error::NativeSurface {
            module: name.to_owned(),
            reason: format!("object parse: {e}"),
        })?;
    let arch: Arch = arch_of(&file).ok_or_else(|| Error::NativeSurface {
        module: name.to_owned(),
        reason: format!("unsupported architecture {:?}", file.architecture()),
    })?;
    let section: object::Section<'_, '_> =
        primary_code_section(&file).ok_or_else(|| Error::NativeSurface {
            module: name.to_owned(),
            reason: "no executable code section".to_owned(),
        })?;
    let section_name: String = section
        .name()
        .map_or_else(|_| "<unnamed>".to_owned(), str::to_owned);
    let (section_offset, _): (u64, u64) =
        section.file_range().ok_or_else(|| Error::NativeSurface {
            module: name.to_owned(),
            reason: format!("section `{section_name}` has no file range"),
        })?;
    let data: &[u8] = section
        .data()
        .map_err(|e: object::Error| Error::NativeSurface {
            module: name.to_owned(),
            reason: format!("section `{section_name}` data: {e}"),
        })?;
    let slice: &[u8] = &data[..data.len().min(MAX_DISASM_BYTES)];
    let insns: Vec<DisasmInsn> =
        disassemble(arch, section.address(), slice).map_err(|e| Error::NativeSurface {
            module: name.to_owned(),
            reason: format!("disassemble: {e}"),
        })?;
    dbg_kv("native-surface", || {
        format!(
            "{name}: {format:?}/{arch:?} section={section_name} bytes={} insns={}",
            slice.len(),
            insns.len()
        )
    });
    let sample: Vec<DisasmInsn> = insns.iter().take(SAMPLE_INSTRUCTION_CAP).cloned().collect();
    Ok(SurfacedNative {
        name: name.to_owned(),
        disk_path: PathBuf::new(),
        format,
        arch,
        code_section: section_name,
        code_offset: section_offset,
        code_size: section.size(),
        instruction_count: insns.len(),
        sample,
    })
}

fn arch_of(file: &object::File<'_>) -> Option<Arch> {
    match file.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => Some(Arch::X86_64),
        Architecture::I386 => Some(Arch::X86),
        Architecture::Aarch64 => Some(Arch::Aarch64),
        Architecture::Arm => Some(Arch::Arm32),
        Architecture::Riscv32 => Some(Arch::RiscV32),
        Architecture::Riscv64 => Some(Arch::RiscV64),
        Architecture::PowerPc => Some(Arch::PowerPc32),
        Architecture::PowerPc64 => Some(Arch::PowerPc64),
        _ => None,
    }
}

fn primary_code_section<'data, 'file>(
    file: &'file object::File<'data>,
) -> Option<object::Section<'data, 'file>> {
    file.sections()
        .filter(|s: &object::Section<'data, 'file>| {
            matches!(s.kind(), SectionKind::Text) && s.size() > 0
        })
        .min_by_key(|s: &object::Section<'data, 'file>| s.address())
        .or_else(|| {
            file.sections().find(|s: &object::Section<'data, 'file>| {
                s.name().is_ok_and(|n: &str| n == ".text") && s.size() > 0
            })
        })
}

pub fn classify_bare_pyc(bytes: &[u8]) -> Option<(u8, u8)> {
    let fp: crate::common::pyc::PycFingerprint = fingerprint(bytes)?;
    let _ = python_version_for_magic(fp.magic)?;
    Some((fp.python_major, fp.python_minor))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn synthesize_pyc_prepends_correct_header_for_314() {
        let marshal: Vec<u8> = vec![0xE3, 0x00, 0x01, 0x02];
        let pyc: Vec<u8> = synthesize_pyc(&marshal, 3, 14).expect("synth");
        assert_eq!(pyc.len(), 16 + marshal.len());
        let magic: u32 = u32::from_le_bytes([pyc[0], pyc[1], pyc[2], pyc[3]]);
        assert_eq!(
            magic,
            magic_for(PyVersion {
                major: 3,
                minor: 14
            })
            .unwrap()
        );
        assert_eq!(&pyc[16..], &marshal[..]);
    }

    #[test]
    fn synthesize_pyc_uses_8_byte_header_for_27() {
        let marshal: Vec<u8> = vec![0x63];
        let pyc: Vec<u8> = synthesize_pyc(&marshal, 2, 7).expect("synth");
        assert_eq!(pyc.len(), 8 + marshal.len());
    }

    #[test]
    fn synthesize_pyc_rejects_unknown_version() {
        assert!(synthesize_pyc(&[0u8], 9, 99).is_err());
    }

    #[test]
    fn native_extension_classifier_matches_known_suffixes() {
        assert!(looks_like_native_extension("_socket.pyd"));
        assert!(looks_like_native_extension("libfoo.so"));
        assert!(looks_like_native_extension("python314.DLL"));
        assert!(!looks_like_native_extension("app.pyc"));
    }

    #[test]
    fn bytecode_classifier_matches_pyc_and_pyo() {
        assert!(looks_like_bytecode("app.pyc"));
        assert!(looks_like_bytecode("app.pyo"));
        assert!(!looks_like_bytecode("ext.pyd"));
    }

    #[test]
    fn grade_round_trip_equivalence_predicate() {
        assert!(RoundtripGrade::Perfect.is_equivalent());
        assert!(RoundtripGrade::Semantic.is_equivalent());
        assert!(!RoundtripGrade::NotAttempted.is_equivalent());
        assert!(!RoundtripGrade::NoInterpreter("x".to_owned()).is_equivalent());
    }
}
