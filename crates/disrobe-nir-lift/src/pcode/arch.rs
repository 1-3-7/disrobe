use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::NirFunction;
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::syntax::Endian;

use crate::error::{LiftError, Result};

use super::{PcodeLiftConfig, lower_pcode_block};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum PcodeArch {
    X86_64,
    AArch64,
    Arm32A32,
    Arm32Thumb,
    Mips32Be,
    Mips32Le,
}

#[derive(Debug)]
struct ArchEntry {
    arch: PcodeArch,
    label: &'static str,
    decode: fn(&[u8], u64) -> DecodedBlock,
    config: fn() -> Result<PcodeLiftConfig>,
}

const ARCHITECTURES: [ArchEntry; 6] = [
    ArchEntry {
        arch: PcodeArch::X86_64,
        label: "x86-64",
        decode: decode_x86_64,
        config: config_x86_64,
    },
    ArchEntry {
        arch: PcodeArch::AArch64,
        label: "aarch64",
        decode: decode_aarch64,
        config: config_aarch64,
    },
    ArchEntry {
        arch: PcodeArch::Arm32A32,
        label: "arm32-a32",
        decode: decode_arm32_a32,
        config: PcodeLiftConfig::arm32,
    },
    ArchEntry {
        arch: PcodeArch::Arm32Thumb,
        label: "arm32-thumb",
        decode: decode_arm32_thumb,
        config: PcodeLiftConfig::arm32,
    },
    ArchEntry {
        arch: PcodeArch::Mips32Be,
        label: "mips32-be",
        decode: decode_mips32_be,
        config: config_mips32_be,
    },
    ArchEntry {
        arch: PcodeArch::Mips32Le,
        label: "mips32-le",
        decode: decode_mips32_le,
        config: config_mips32_le,
    },
];

impl PcodeArch {
    pub fn all() -> impl Iterator<Item = Self> {
        ARCHITECTURES.iter().map(|entry: &ArchEntry| entry.arch)
    }

    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        self.entry().map(|entry: &'static ArchEntry| entry.label)
    }

    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        ARCHITECTURES
            .iter()
            .find(|entry: &&ArchEntry| entry.label.eq_ignore_ascii_case(label))
            .map(|entry: &ArchEntry| entry.arch)
    }

    pub fn config(self) -> Result<PcodeLiftConfig> {
        (self.resolved_entry()?.config)()
    }

    pub fn decode(self, bytes: &[u8], address: u64) -> Result<DecodedBlock> {
        Ok((self.resolved_entry()?.decode)(bytes, address))
    }

    fn entry(self) -> Option<&'static ArchEntry> {
        let found: &'static ArchEntry = ARCHITECTURES.get(self as usize)?;
        (found.arch as usize == self as usize).then_some(found)
    }

    fn resolved_entry(self) -> Result<&'static ArchEntry> {
        self.entry().ok_or_else(|| LiftError::InvalidPcode {
            address: 0,
            operation: "ARCH_TABLE".to_owned(),
            reason: "architecture is absent from the lowering table".to_owned(),
        })
    }
}

pub fn lower_for_arch(
    arch: PcodeArch,
    bytes: &[u8],
    address: u64,
    name: &str,
) -> Result<NirFunction> {
    let block: DecodedBlock = arch.decode(bytes, address)?;
    let config: PcodeLiftConfig = arch.config()?;
    lower_pcode_block(&block, name, &config)
}

fn decode_x86_64(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_x86(bytes, address, 64)
}

fn decode_aarch64(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_for_language(Language::AArch64, bytes, address)
}

fn decode_arm32_a32(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_for_language(Language::Arm32(ArmMode::A32), bytes, address)
}

fn decode_arm32_thumb(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_for_language(Language::Arm32(ArmMode::Thumb), bytes, address)
}

fn decode_mips32_be(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_for_language(Language::Mips32(Endian::Big), bytes, address)
}

fn decode_mips32_le(bytes: &[u8], address: u64) -> DecodedBlock {
    decode_block_for_language(Language::Mips32(Endian::Little), bytes, address)
}

#[allow(clippy::unnecessary_wraps)]
fn config_x86_64() -> Result<PcodeLiftConfig> {
    Ok(PcodeLiftConfig::x86_64())
}

#[allow(clippy::unnecessary_wraps)]
fn config_aarch64() -> Result<PcodeLiftConfig> {
    Ok(PcodeLiftConfig::aarch64())
}

fn config_mips32_be() -> Result<PcodeLiftConfig> {
    PcodeLiftConfig::mips32(Endian::Big)
}

fn config_mips32_le() -> Result<PcodeLiftConfig> {
    PcodeLiftConfig::mips32(Endian::Little)
}
