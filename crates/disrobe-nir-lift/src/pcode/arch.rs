use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::{NirArtifact, NirFunction};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr};
use disrobe_sleigh::syntax::Endian;

use crate::error::{LiftError, ProvenanceResult, Result};

use super::{PcodeLiftConfig, lower_pcode_block, lower_pcode_block_with_provenance};

const MAX_REPORTED_GAPS: usize = 4096;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decoder {
    X86_64,
    Sleigh(Language),
}

#[derive(Debug)]
struct ArchEntry {
    arch: PcodeArch,
    label: &'static str,
    decoder: Decoder,
    config: fn() -> Result<PcodeLiftConfig>,
}

const ARCHITECTURES: [ArchEntry; 6] = [
    ArchEntry {
        arch: PcodeArch::X86_64,
        label: "x86-64",
        decoder: Decoder::X86_64,
        config: || Ok(PcodeLiftConfig::x86_64()),
    },
    ArchEntry {
        arch: PcodeArch::AArch64,
        label: "aarch64",
        decoder: Decoder::Sleigh(Language::AArch64),
        config: || Ok(PcodeLiftConfig::aarch64()),
    },
    ArchEntry {
        arch: PcodeArch::Arm32A32,
        label: "arm32-a32",
        decoder: Decoder::Sleigh(Language::Arm32(ArmMode::A32)),
        config: PcodeLiftConfig::arm32,
    },
    ArchEntry {
        arch: PcodeArch::Arm32Thumb,
        label: "arm32-thumb",
        decoder: Decoder::Sleigh(Language::Arm32(ArmMode::Thumb)),
        config: PcodeLiftConfig::arm32,
    },
    ArchEntry {
        arch: PcodeArch::Mips32Be,
        label: "mips32-be",
        decoder: Decoder::Sleigh(Language::Mips32(Endian::Big)),
        config: || PcodeLiftConfig::mips32(Endian::Big),
    },
    ArchEntry {
        arch: PcodeArch::Mips32Le,
        label: "mips32-le",
        decoder: Decoder::Sleigh(Language::Mips32(Endian::Little)),
        config: || PcodeLiftConfig::mips32(Endian::Little),
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

    #[must_use]
    pub fn for_language(language: Language) -> Option<Self> {
        ARCHITECTURES
            .iter()
            .find(|entry: &&ArchEntry| entry.decoder == Decoder::Sleigh(language))
            .map(|entry: &ArchEntry| entry.arch)
    }

    pub fn config(self) -> Result<PcodeLiftConfig> {
        (self.resolved_entry()?.config)()
    }

    pub fn decode(self, bytes: &[u8], address: u64) -> Result<DecodedBlock> {
        Ok(match self.resolved_entry()?.decoder {
            Decoder::X86_64 => decode_block_x86(bytes, address, 64),
            Decoder::Sleigh(language) => decode_block_for_language(language, bytes, address),
        })
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiftGap {
    pub address: u64,
    pub mnemonic: String,
    pub status: DecodeStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiftGaps {
    reported: Vec<LiftGap>,
    total: usize,
}

impl LiftGaps {
    #[must_use]
    pub fn reported(&self) -> &[LiftGap] {
        &self.reported
    }

    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.total > self.reported.len()
    }

    #[must_use]
    pub fn mnemonics(&self) -> Vec<&str> {
        self.reported
            .iter()
            .map(|gap: &LiftGap| gap.mnemonic.as_str())
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchLift {
    pub arch: PcodeArch,
    pub function: NirFunction,
    pub gaps: LiftGaps,
    pub consumed: usize,
}

#[must_use]
pub fn block_gaps(block: &DecodedBlock) -> LiftGaps {
    let undecoded = || {
        block
            .instructions
            .iter()
            .filter(|instruction: &&PcodeInstr| instruction.status != DecodeStatus::Supported)
    };
    LiftGaps {
        reported: undecoded()
            .take(MAX_REPORTED_GAPS)
            .map(|instruction: &PcodeInstr| LiftGap {
                address: instruction.address,
                mnemonic: instruction.mnemonic.clone(),
                status: instruction.status,
            })
            .collect(),
        total: undecoded().count(),
    }
}

pub fn lower_arch(arch: PcodeArch, bytes: &[u8], address: u64, name: &str) -> Result<ArchLift> {
    let config: PcodeLiftConfig = arch.config()?;
    let block: DecodedBlock = arch.decode(bytes, address)?;
    let gaps: LiftGaps = block_gaps(&block);
    let consumed: usize = block.consumed;
    let function: NirFunction = lower_pcode_block(&block, name, &config)?;
    Ok(ArchLift {
        arch,
        function,
        gaps,
        consumed,
    })
}

pub fn lower_for_arch_with_provenance(
    arch: PcodeArch,
    bytes: &[u8],
    address: u64,
    name: &str,
) -> ProvenanceResult<NirArtifact> {
    let config: PcodeLiftConfig = arch.config()?;
    let block: DecodedBlock = arch.decode(bytes, address)?;
    lower_pcode_block_with_provenance(&block, name, &config)
}
