use capstone::Capstone;
use capstone::arch::BuildsCapstone as _;
use capstone::arch::BuildsCapstoneEndian as _;
use capstone::arch::BuildsCapstoneExtraMode as _;
use iced_x86::{
    Decoder, DecoderError, DecoderOptions, GasFormatter, Instruction, IntelFormatter,
    MasmFormatter, NasmFormatter,
};
use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;

use crate::error::{Error, Result};

const X86_MAX_INSTRUCTION_BYTES: usize = 15;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "kebab-case")]
pub enum Syntax {
    #[default]
    Nasm,
    Intel,
    Att,
    Masm,
}

impl Syntax {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nasm => "nasm",
            Self::Intel => "intel",
            Self::Att => "att",
            Self::Masm => "masm",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "nasm" => Some(Self::Nasm),
            "intel" => Some(Self::Intel),
            "att" | "at&t" | "gas" => Some(Self::Att),
            "masm" => Some(Self::Masm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arch {
    X86,
    X86_64,
    Arm32,
    Thumb,
    Aarch64,
    RiscV32,
    RiscV64,
    MipsBe32,
    MipsLe32,
    Mips64,
    PowerPc32,
    PowerPc64,
    Sparc,
    Sparc64,
    Ebpf,
    Avr,
}

impl Arch {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm32 => "arm",
            Self::Thumb => "thumb",
            Self::Aarch64 => "aarch64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::MipsBe32 => "mips-be",
            Self::MipsLe32 => "mips-le",
            Self::Mips64 => "mips64",
            Self::PowerPc32 => "ppc32",
            Self::PowerPc64 => "ppc64",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::Ebpf => "ebpf",
            Self::Avr => "avr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

pub const UNDECODABLE_ARM_MNEMONIC: &str = ".inst";

pub fn disassemble(arch: Arch, base: u64, bytes: &[u8]) -> Result<Vec<DisasmInsn>> {
    match arch {
        Arch::X86 => disasm_iced(bytes, base, 32, Syntax::Nasm),
        Arch::X86_64 => disasm_iced(bytes, base, 64, Syntax::Nasm),
        Arch::Aarch64 => disasm_yaxpeax_aarch64(bytes, base),
        Arch::Arm32 | Arch::Thumb => disasm_yaxpeax_arm(bytes, base, matches!(arch, Arch::Thumb)),
        Arch::RiscV32 | Arch::RiscV64 => disasm_capstone(arch, bytes, base, "capstone-riscv"),
        Arch::MipsBe32 | Arch::MipsLe32 | Arch::Mips64 => {
            disasm_capstone(arch, bytes, base, "capstone-mips")
        }
        Arch::PowerPc32 | Arch::PowerPc64 => disasm_capstone(arch, bytes, base, "capstone-ppc"),
        Arch::Sparc | Arch::Sparc64 => disasm_capstone(arch, bytes, base, "capstone-sparc"),
        Arch::Ebpf => disasm_capstone(arch, bytes, base, "capstone-ebpf"),
        Arch::Avr => disasm_yaxpeax_avr(bytes, base),
    }
}

pub fn disassemble_x86(
    arch: Arch,
    base: u64,
    bytes: &[u8],
    syntax: Syntax,
) -> Result<Vec<DisasmInsn>> {
    let bits: u32 = match arch {
        Arch::X86 => 32,
        Arch::X86_64 => 64,
        other => {
            return Err(Error::UnsupportedArch(format!(
                "{} has no iced-x86 syntax formatter",
                other.label()
            )));
        }
    };
    disasm_iced(bytes, base, bits, syntax)
}

fn iced_formatter(syntax: Syntax) -> Box<dyn iced_x86::Formatter> {
    match syntax {
        Syntax::Nasm => Box::new(NasmFormatter::new()),
        Syntax::Intel => Box::new(IntelFormatter::new()),
        Syntax::Att => Box::new(GasFormatter::new()),
        Syntax::Masm => Box::new(MasmFormatter::new()),
    }
}

fn disasm_iced(bytes: &[u8], base: u64, bits: u32, syntax: Syntax) -> Result<Vec<DisasmInsn>> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, bytes, base, DecoderOptions::NONE);
    let mut formatter: Box<dyn iced_x86::Formatter> = iced_formatter(syntax);
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        let start: usize = (insn.ip().saturating_sub(base)) as usize;
        let end: usize = start + insn.len();
        let raw: Vec<u8> = bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let mut text: String = String::new();
        formatter.format(&insn, &mut text);
        let (mnemonic, operands): (String, String) = split_text(&text);
        out.push(DisasmInsn {
            address: insn.ip(),
            bytes: raw,
            mnemonic,
            operands,
        });
    }
    Ok(out)
}

pub(crate) fn decode_one_x86(bits: u32, address: u64, bytes: &[u8]) -> Option<Instruction> {
    let decode_len: usize = bytes.len().min(X86_MAX_INSTRUCTION_BYTES);
    let window: &[u8] = bytes.get(..decode_len)?;
    if window.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, window, address, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let mut instruction: Instruction = Instruction::default();
    decoder.decode_out(&mut instruction);
    if decoder.last_error() != DecoderError::None
        || instruction.is_invalid()
        || instruction.len() == 0
    {
        return None;
    }
    Some(instruction)
}

fn split_text(text: &str) -> (String, String) {
    match text.split_once(' ') {
        Some((m, ops)) => (m.to_owned(), ops.trim().to_owned()),
        None => (text.to_owned(), String::new()),
    }
}

fn disasm_yaxpeax_aarch64(bytes: &[u8], base: u64) -> Result<Vec<DisasmInsn>> {
    let decoder: yaxpeax_arm::armv8::a64::InstDecoder =
        yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut idx: usize = 0;
    while idx + 4 <= bytes.len() {
        let Some(window): Option<&[u8]> = bytes.get(idx..) else {
            break;
        };
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        let address: u64 = base.wrapping_add(idx as u64);
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let text: String = inst.to_string();
                let (m, ops): (String, String) = split_text(&text);
                let raw: Vec<u8> = bytes[idx..idx + 4].to_vec();
                out.push(DisasmInsn {
                    address,
                    bytes: raw,
                    mnemonic: m,
                    operands: ops,
                });
            }
            Err(_) => out.push(undecodable_arm_word(bytes, idx, 4, address)),
        }
        idx += 4;
    }
    Ok(out)
}

fn disasm_yaxpeax_arm(bytes: &[u8], base: u64, thumb: bool) -> Result<Vec<DisasmInsn>> {
    let decoder: yaxpeax_arm::armv7::InstDecoder = if thumb {
        yaxpeax_arm::armv7::InstDecoder::default_thumb()
    } else {
        yaxpeax_arm::armv7::InstDecoder::default()
    };
    let min_step: usize = if thumb { 2 } else { 4 };
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut start: usize = 0;
    while start.saturating_add(min_step) <= bytes.len() {
        let Some(window): Option<&[u8]> = bytes.get(start..) else {
            break;
        };
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        let address: u64 = base.wrapping_add(start as u64);
        let Ok(inst) = decoder.decode(&mut reader) else {
            out.push(undecodable_arm_word(bytes, start, min_step, address));
            start = start.saturating_add(min_step);
            continue;
        };
        let consumed: usize =
            usize::try_from(yaxpeax_arch::Reader::<u32, u8>::total_offset(&mut reader))
                .unwrap_or(0);
        if consumed == 0 || start.saturating_add(consumed) > bytes.len() {
            break;
        }
        let raw: Vec<u8> = bytes
            .get(start..start.saturating_add(consumed))
            .map_or_else(Vec::new, <[u8]>::to_vec);
        let recovered: Option<(String, String)> =
            if !thumb && inst.opcode == yaxpeax_arm::armv7::Opcode::Invalid {
                <[u8; 4]>::try_from(raw.as_slice())
                    .ok()
                    .and_then(|word: [u8; 4]| arm_a32_hint(u32::from_le_bytes(word)))
            } else {
                None
            };
        let (m, ops): (String, String) = recovered.unwrap_or_else(|| {
            let text: String = inst.to_string();
            split_text(&text)
        });
        out.push(DisasmInsn {
            address,
            bytes: raw,
            mnemonic: m,
            operands: ops,
        });
        start = start.saturating_add(consumed);
    }
    Ok(out)
}

fn undecodable_arm_word(bytes: &[u8], start: usize, width: usize, address: u64) -> DisasmInsn {
    let raw: Vec<u8> = bytes
        .get(start..start.saturating_add(width))
        .map_or_else(Vec::new, <[u8]>::to_vec);
    let operands: String = match *raw.as_slice() {
        [low, high, upper, top] => {
            format!("{:#010x}", u32::from_le_bytes([low, high, upper, top]))
        }
        [low, high] => format!("{:#06x}", u16::from_le_bytes([low, high])),
        _ => String::new(),
    };
    DisasmInsn {
        address,
        bytes: raw,
        mnemonic: UNDECODABLE_ARM_MNEMONIC.to_owned(),
        operands,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmMode {
    A32,
    Thumb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmRegionKind {
    A32,
    Thumb,
    Data,
}

impl ArmRegionKind {
    #[must_use]
    pub const fn of_mapping_symbol(name: &str) -> Option<Self> {
        match name.as_bytes() {
            [b'$', b'a', rest @ ..] if Self::is_mapping_suffix(rest) => Some(Self::A32),
            [b'$', b't', rest @ ..] if Self::is_mapping_suffix(rest) => Some(Self::Thumb),
            [b'$', b'd', rest @ ..] if Self::is_mapping_suffix(rest) => Some(Self::Data),
            _ => None,
        }
    }

    const fn is_mapping_suffix(rest: &[u8]) -> bool {
        matches!(rest, [] | [b'.', ..])
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::A32 => "A32",
            Self::Thumb => "Thumb",
            Self::Data => "data",
        }
    }

    #[must_use]
    pub const fn decode_arch(self) -> Option<Arch> {
        match self {
            Self::A32 => Some(Arch::Arm32),
            Self::Thumb => Some(Arch::Thumb),
            Self::Data => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ArmSelection {
    Decodable(ArmMode),
    Undecodable(String),
}

#[derive(Clone, Debug, Default)]
pub struct ArmMappingSymbols {
    regions: Vec<(u64, ArmRegionKind)>,
}

impl ArmMappingSymbols {
    #[must_use]
    pub fn of(obj: &object::File<'_>) -> Self {
        use object::{Object as _, ObjectSymbol as _, SymbolKind};

        let mut regions: Vec<(u64, ArmRegionKind)> = obj
            .symbols()
            .filter_map(|symbol: object::Symbol<'_, '_>| {
                let name: &str = symbol.name().ok()?;
                let kind: ArmRegionKind = ArmRegionKind::of_mapping_symbol(name)?;
                Some((symbol.address() & !1_u64, kind))
            })
            .collect();
        regions.extend(obj.symbols().filter_map(|symbol: object::Symbol<'_, '_>| {
            (matches!(symbol.kind(), SymbolKind::Text) && symbol.address() & 1 == 1)
                .then(|| (symbol.address() & !1_u64, ArmRegionKind::Thumb))
        }));
        Self::from_regions(regions)
    }

    #[must_use]
    pub fn from_regions(mut regions: Vec<(u64, ArmRegionKind)>) -> Self {
        regions.sort_by_key(|(address, _): &(u64, ArmRegionKind)| *address);
        regions.dedup_by_key(|(address, _): &mut (u64, ArmRegionKind)| *address);
        Self { regions }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    #[must_use]
    pub fn kind_at(&self, address: u64) -> Option<ArmRegionKind> {
        let index: usize = self
            .regions
            .partition_point(|(start, _): &(u64, ArmRegionKind)| *start <= address);
        index
            .checked_sub(1)
            .and_then(|last: usize| self.regions.get(last))
            .map(|(_, kind): &(u64, ArmRegionKind)| *kind)
    }

    #[must_use]
    pub fn select(&self, start: u64, end: u64) -> ArmSelection {
        let Some(opening): Option<ArmRegionKind> = self.kind_at(start) else {
            return ArmSelection::Decodable(ArmMode::A32);
        };
        if matches!(opening, ArmRegionKind::Data) {
            return ArmSelection::Undecodable(format!(
                "the function at {start:#x} opens inside a $d data region, so no instruction stream starts there"
            ));
        }
        for (boundary, kind) in &self.regions {
            if *boundary <= start || *boundary >= end {
                continue;
            }
            if *kind != opening {
                return ArmSelection::Undecodable(format!(
                    "the function range changes from {} to {} at {boundary:#x}; one decode mode would misread the rest",
                    opening.label(),
                    kind.label()
                ));
            }
        }
        ArmSelection::Decodable(if matches!(opening, ArmRegionKind::Thumb) {
            ArmMode::Thumb
        } else {
            ArmMode::A32
        })
    }

    #[must_use]
    pub fn holds(&self, kind: ArmRegionKind) -> bool {
        self.regions
            .iter()
            .any(|(_, found): &(u64, ArmRegionKind)| *found == kind)
    }

    #[must_use]
    pub fn runs(&self, start: u64, end: u64, fallback: ArmRegionKind) -> Vec<ArmRun> {
        if end <= start {
            return Vec::new();
        }
        let mut boundaries: Vec<(u64, ArmRegionKind)> =
            vec![(start, self.kind_at(start).unwrap_or(fallback))];
        boundaries.extend(
            self.regions
                .iter()
                .filter(|(address, _): &&(u64, ArmRegionKind)| *address > start && *address < end)
                .copied(),
        );
        let mut runs: Vec<ArmRun> = Vec::with_capacity(boundaries.len());
        for index in 0..boundaries.len() {
            let (address, kind): (u64, ArmRegionKind) = boundaries[index];
            let next: u64 = boundaries
                .get(index.saturating_add(1))
                .map_or(end, |(address, _): &(u64, ArmRegionKind)| *address);
            if next > address {
                runs.push(ArmRun {
                    kind,
                    start: address,
                    end: next,
                });
            }
        }
        runs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmRun {
    pub kind: ArmRegionKind,
    pub start: u64,
    pub end: u64,
}

fn arm_a32_hint(word: u32) -> Option<(String, String)> {
    if word & 0x0fff_ff00 != 0x0320_f000 {
        return None;
    }
    let op2: u32 = word & 0xff;
    let mnemonic: &str = match op2 {
        0x00 => "nop",
        0x01 => "yield",
        0x02 => "wfe",
        0x03 => "wfi",
        0x04 => "sev",
        0x05 => "sevl",
        0xf0..=0xff => "dbg",
        _ => return None,
    };
    let operands: String = if mnemonic == "dbg" {
        format!("#{}", op2 & 0xf)
    } else {
        String::new()
    };
    Some((mnemonic.to_owned(), operands))
}

fn build_capstone<F>(make: F, engine: &'static str) -> Result<Capstone>
where
    F: FnOnce() -> core::result::Result<Capstone, capstone::Error>,
{
    make().map_err(|e: capstone::Error| Error::Disasm {
        engine,
        message: e.to_string(),
    })
}

pub(crate) fn capstone_for(arch: Arch, detail: bool) -> Result<Option<Capstone>> {
    let engine: Capstone = match arch {
        Arch::Arm32 | Arch::Thumb => build_capstone(
            || {
                Capstone::new()
                    .arm()
                    .mode(if matches!(arch, Arch::Thumb) {
                        capstone::arch::arm::ArchMode::Thumb
                    } else {
                        capstone::arch::arm::ArchMode::Arm
                    })
                    .endian(capstone::Endian::Little)
                    .detail(detail)
                    .build()
            },
            "capstone-arm",
        )?,
        Arch::RiscV32 | Arch::RiscV64 => build_capstone(
            || {
                Capstone::new()
                    .riscv()
                    .mode(if matches!(arch, Arch::RiscV64) {
                        capstone::arch::riscv::ArchMode::RiscV64
                    } else {
                        capstone::arch::riscv::ArchMode::RiscV32
                    })
                    .extra_mode(
                        [capstone::arch::riscv::ArchExtraMode::RiscVC]
                            .iter()
                            .copied(),
                    )
                    .detail(detail)
                    .build()
            },
            "capstone-riscv",
        )?,
        Arch::MipsBe32 | Arch::MipsLe32 | Arch::Mips64 => build_capstone(
            || {
                Capstone::new()
                    .mips()
                    .mode(if matches!(arch, Arch::Mips64) {
                        capstone::arch::mips::ArchMode::Mips64
                    } else {
                        capstone::arch::mips::ArchMode::Mips32
                    })
                    .endian(if matches!(arch, Arch::MipsLe32) {
                        capstone::Endian::Little
                    } else {
                        capstone::Endian::Big
                    })
                    .detail(detail)
                    .build()
            },
            "capstone-mips",
        )?,
        Arch::PowerPc32 | Arch::PowerPc64 => build_capstone(
            || {
                Capstone::new()
                    .ppc()
                    .mode(if matches!(arch, Arch::PowerPc64) {
                        capstone::arch::ppc::ArchMode::Mode64
                    } else {
                        capstone::arch::ppc::ArchMode::Mode32
                    })
                    .endian(capstone::Endian::Big)
                    .detail(detail)
                    .build()
            },
            "capstone-ppc",
        )?,
        Arch::Sparc | Arch::Sparc64 => build_capstone(
            || {
                Capstone::new()
                    .sparc()
                    .mode(if matches!(arch, Arch::Sparc64) {
                        capstone::arch::sparc::ArchMode::V9
                    } else {
                        capstone::arch::sparc::ArchMode::Default
                    })
                    .detail(detail)
                    .build()
            },
            "capstone-sparc",
        )?,
        Arch::Ebpf => build_capstone(
            || {
                Capstone::new()
                    .bpf()
                    .mode(capstone::arch::bpf::ArchMode::Ebpf)
                    .endian(capstone::Endian::Little)
                    .detail(detail)
                    .build()
            },
            "capstone-ebpf",
        )?,
        Arch::X86 | Arch::X86_64 | Arch::Aarch64 | Arch::Avr => return Ok(None),
    };
    Ok(Some(engine))
}

fn capstone_required(arch: Arch, engine: &'static str) -> Result<Capstone> {
    capstone_for(arch, false)?.ok_or_else(|| Error::Disasm {
        engine,
        message: format!("{} has no capstone engine", arch.label()),
    })
}

fn cs_run(cs: &Capstone, bytes: &[u8], base: u64, engine: &'static str) -> Result<Vec<DisasmInsn>> {
    let insns: capstone::Instructions<'_> =
        cs.disasm_all(bytes, base)
            .map_err(|e: capstone::Error| Error::Disasm {
                engine,
                message: e.to_string(),
            })?;
    let mut out: Vec<DisasmInsn> = Vec::with_capacity(insns.len());
    for i in insns.iter() {
        out.push(DisasmInsn {
            address: i.address(),
            bytes: i.bytes().to_vec(),
            mnemonic: i.mnemonic().unwrap_or("").to_owned(),
            operands: i.op_str().unwrap_or("").to_owned(),
        });
    }
    Ok(out)
}

fn disasm_capstone(
    arch: Arch,
    bytes: &[u8],
    base: u64,
    engine: &'static str,
) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = capstone_required(arch, engine)?;
    cs_run(&cs, bytes, base, engine)
}

fn disasm_yaxpeax_avr(bytes: &[u8], base: u64) -> Result<Vec<DisasmInsn>> {
    use yaxpeax_arch_avr::{Arch as AvrArch, Decoder as _, Reader, U8Reader};

    let decoder: <yaxpeax_avr::AVR as AvrArch>::Decoder =
        <<yaxpeax_avr::AVR as AvrArch>::Decoder>::default();
    let mut reader: U8Reader<'_> = U8Reader::new(bytes);
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut addr: u64 = base;
    loop {
        let before: u64 = u64::from(Reader::<u32, u8>::total_offset(&mut reader));
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after: u64 = u64::from(Reader::<u32, u8>::total_offset(&mut reader));
                let consumed: usize = usize::try_from(after - before).unwrap_or(0);
                if consumed == 0 {
                    break;
                }
                let start: usize = usize::try_from(before).unwrap_or(0);
                let raw: Vec<u8> = bytes
                    .get(start..start + consumed)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
                let text: String = inst.to_string();
                let (m, ops): (String, String) = split_text(&text);
                out.push(DisasmInsn {
                    address: addr,
                    bytes: raw,
                    mnemonic: m,
                    operands: ops,
                });
                addr = addr.wrapping_add(after - before);
            }
            Err(e) => {
                if out.is_empty() {
                    return Err(Error::Disasm {
                        engine: "yaxpeax-avr",
                        message: e.to_string(),
                    });
                }
                break;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_mapping_symbol_name_decides_the_region_and_nothing_else_does() {
        let cases: [(&str, Option<ArmRegionKind>); 10] = [
            ("$a", Some(ArmRegionKind::A32)),
            ("$t", Some(ArmRegionKind::Thumb)),
            ("$d", Some(ArmRegionKind::Data)),
            ("$a.0", Some(ArmRegionKind::A32)),
            ("$t.1234", Some(ArmRegionKind::Thumb)),
            ("$d.realdata", Some(ArmRegionKind::Data)),
            ("$x", None),
            ("$", None),
            ("$td", None),
            ("atomic_store", None),
        ];
        for (name, expected) in cases {
            assert_eq!(
                ArmRegionKind::of_mapping_symbol(name),
                expected,
                "{name} must resolve to {expected:?}"
            );
        }
    }

    #[test]
    fn a_function_takes_the_decode_mode_of_the_mapping_symbol_that_opens_it() {
        let mapping: ArmMappingSymbols = ArmMappingSymbols::from_regions(vec![
            (0x2_00f4, ArmRegionKind::A32),
            (0x2_014c, ArmRegionKind::Thumb),
        ]);
        let arm: ArmSelection = mapping.select(0x2_00f4, 0x2_0100);
        assert!(
            matches!(arm, ArmSelection::Decodable(ArmMode::A32)),
            "a function opened by $a decodes as A32, got {arm:?}"
        );
        let thumb: ArmSelection = mapping.select(0x2_014c, 0x2_0160);
        assert!(
            matches!(thumb, ArmSelection::Decodable(ArmMode::Thumb)),
            "a function opened by $t decodes as Thumb, got {thumb:?}"
        );
    }

    #[test]
    fn a_range_that_changes_mode_is_reported_instead_of_read_in_one_mode() {
        let mapping: ArmMappingSymbols = ArmMappingSymbols::from_regions(vec![
            (0x2_00f4, ArmRegionKind::A32),
            (0x2_014c, ArmRegionKind::Thumb),
        ]);
        let spanning: ArmSelection = mapping.select(0x2_010c, 0x2_0160);
        let ArmSelection::Undecodable(reason) = spanning else {
            panic!(
                "a range spanning an A32 to Thumb boundary must not pick one mode: {spanning:?}"
            );
        };
        assert!(
            reason.contains("0x2014c") && reason.contains("A32") && reason.contains("Thumb"),
            "the refusal must name the boundary and both modes: {reason}"
        );

        let data: ArmMappingSymbols =
            ArmMappingSymbols::from_regions(vec![(0x2_0200, ArmRegionKind::Data)]);
        let inside: ArmSelection = data.select(0x2_0208, 0x2_0210);
        assert!(
            matches!(inside, ArmSelection::Undecodable(_)),
            "a range opening inside $d holds no instruction stream, got {inside:?}"
        );
    }

    #[test]
    fn a_range_no_mapping_symbol_covers_decodes_as_a32() {
        let empty: ArmMappingSymbols = ArmMappingSymbols::default();
        assert!(matches!(
            empty.select(0x1000, 0x1010),
            ArmSelection::Decodable(ArmMode::A32)
        ));
        let later: ArmMappingSymbols =
            ArmMappingSymbols::from_regions(vec![(0x2000, ArmRegionKind::Thumb)]);
        assert!(
            matches!(
                later.select(0x1000, 0x1010),
                ArmSelection::Decodable(ArmMode::A32)
            ),
            "a region that opens after the range says nothing about it"
        );
    }

    #[test]
    fn a_thumb_bit_function_symbol_opens_a_thumb_region_when_the_image_has_no_mapping_symbols() {
        let mapping: ArmMappingSymbols =
            ArmMappingSymbols::from_regions(vec![(0x1000, ArmRegionKind::Thumb)]);
        assert!(matches!(
            mapping.select(0x1000, 0x1010),
            ArmSelection::Decodable(ArmMode::Thumb)
        ));
    }

    #[test]
    fn a_section_splits_into_one_run_per_mapping_region_and_data_carries_no_arch() {
        let mapping: ArmMappingSymbols = ArmMappingSymbols::from_regions(vec![
            (0x1000, ArmRegionKind::A32),
            (0x1010, ArmRegionKind::Data),
            (0x1018, ArmRegionKind::Thumb),
        ]);
        let runs: Vec<ArmRun> = mapping.runs(0x1000, 0x1020, ArmRegionKind::A32);
        assert_eq!(
            runs,
            vec![
                ArmRun {
                    kind: ArmRegionKind::A32,
                    start: 0x1000,
                    end: 0x1010
                },
                ArmRun {
                    kind: ArmRegionKind::Data,
                    start: 0x1010,
                    end: 0x1018
                },
                ArmRun {
                    kind: ArmRegionKind::Thumb,
                    start: 0x1018,
                    end: 0x1020
                },
            ],
            "each mapping symbol opens a run that ends where the next one starts"
        );
        assert_eq!(
            runs[1].kind.decode_arch(),
            None,
            "a $d run is never decoded"
        );
        assert_eq!(runs[2].kind.decode_arch(), Some(Arch::Thumb));
    }

    #[test]
    fn an_undecodable_arm_word_becomes_a_gap_and_decoding_continues_after_it() {
        let bytes: [u8; 12] = [
            0x00, 0x00, 0xa0, 0xe1, 0xff, 0xff, 0xff, 0xf7, 0x1e, 0xff, 0x2f, 0xe1,
        ];
        let out: Vec<DisasmInsn> = disassemble(Arch::Arm32, 0x1000, &bytes).expect("disasm");
        assert_eq!(
            out.len(),
            3,
            "an undecodable word must not end the section: {out:?}"
        );
        assert_eq!(out[1].address, 0x1004);
        assert_eq!(out[1].mnemonic, UNDECODABLE_ARM_MNEMONIC);
        assert_eq!(out[1].bytes.len(), 4);
        assert_eq!(out[2].address, 0x1008);
        assert!(
            out[2].mnemonic.starts_with("bx"),
            "the instruction after the gap must still decode: {:?}",
            out[2]
        );
    }

    #[test]
    fn x86_nop_ret_decodes() {
        let bytes: [u8; 2] = [0x90, 0xC3];
        let out: Vec<DisasmInsn> = disassemble(Arch::X86, 0x1000, &bytes).expect("disasm");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].mnemonic, "nop");
        assert_eq!(out[1].mnemonic, "ret");
    }

    #[test]
    fn x86_64_mov_decodes() {
        let bytes: [u8; 7] = [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00];
        let out: Vec<DisasmInsn> = disassemble(Arch::X86_64, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "mov");
    }

    #[test]
    fn aarch64_ret_decodes() {
        let bytes: [u8; 4] = [0xC0, 0x03, 0x5F, 0xD6];
        let out: Vec<DisasmInsn> = disassemble(Arch::Aarch64, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
        assert!(out[0].mnemonic.starts_with("ret"));
    }

    #[test]
    fn an_undecodable_aarch64_word_becomes_a_gap_and_decoding_continues_after_it() {
        let bytes: [u8; 12] = [
            0x1f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let out: Vec<DisasmInsn> = disassemble(Arch::Aarch64, 0x1000, &bytes).expect("disasm");
        assert_eq!(out.len(), 3, "an undecodable word must not end the section");
        assert_eq!(out[1].address, 0x1004);
        assert_eq!(out[1].mnemonic, UNDECODABLE_ARM_MNEMONIC);
        assert_eq!(out[1].bytes, [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(out[2].address, 0x1008);
        assert!(
            out[2].mnemonic.starts_with("ret"),
            "the instruction after the gap must still decode: {:?}",
            out[2]
        );
    }

    #[test]
    fn arm32_nop_decodes() {
        let bytes: [u8; 4] = [0x00, 0xF0, 0x20, 0xE3];
        let out: Vec<DisasmInsn> = disassemble(Arch::Arm32, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "nop");
        assert!(out[0].operands.is_empty());
    }

    #[test]
    fn arm32_hint_space_recovers_yield_and_dbg() {
        assert_eq!(
            arm_a32_hint(0xe320_f001),
            Some(("yield".to_owned(), String::new()))
        );
        assert_eq!(
            arm_a32_hint(0xe320_f0f3),
            Some(("dbg".to_owned(), "#3".to_owned()))
        );
        assert_eq!(arm_a32_hint(0xe1a0_0000), None);
    }

    #[test]
    fn mips_be_lui_decodes() {
        let bytes: [u8; 4] = [0x3C, 0x01, 0x00, 0x01];
        let out: Vec<DisasmInsn> = disassemble(Arch::MipsBe32, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "lui");
    }

    #[test]
    fn riscv_addi_decodes() {
        let bytes: [u8; 4] = [0x13, 0x05, 0x00, 0x00];
        let out: Vec<DisasmInsn> = disassemble(Arch::RiscV32, 0, &bytes).expect("disasm");
        assert!(!out.is_empty());
    }

    #[test]
    fn ppc_addi_decodes() {
        let bytes: [u8; 4] = [0x38, 0x60, 0x00, 0x01];
        let out: Vec<DisasmInsn> = disassemble(Arch::PowerPc32, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn arch_labels_are_stable() {
        assert_eq!(Arch::X86_64.label(), "x86_64");
        assert_eq!(Arch::Aarch64.label(), "aarch64");
        assert_eq!(Arch::RiscV64.label(), "riscv64");
    }

    fn rendered(arch: Arch, bytes: &[u8], syntax: Syntax) -> String {
        let out: Vec<DisasmInsn> =
            disassemble_x86(arch, 0x1000, bytes, syntax).expect("syntax disasm");
        assert_eq!(out.len(), 1, "fixture is a single instruction");
        let insn: &DisasmInsn = &out[0];
        if insn.operands.is_empty() {
            insn.mnemonic.clone()
        } else {
            format!("{} {}", insn.mnemonic, insn.operands)
        }
    }

    #[test]
    fn syntax_parse_accepts_known_dialects() {
        assert_eq!(Syntax::parse("nasm"), Some(Syntax::Nasm));
        assert_eq!(Syntax::parse("Intel"), Some(Syntax::Intel));
        assert_eq!(Syntax::parse("att"), Some(Syntax::Att));
        assert_eq!(Syntax::parse("AT&T"), Some(Syntax::Att));
        assert_eq!(Syntax::parse("gas"), Some(Syntax::Att));
        assert_eq!(Syntax::parse("masm"), Some(Syntax::Masm));
        assert_eq!(Syntax::parse("octal"), None);
        assert_eq!(Syntax::default(), Syntax::Nasm);
    }

    #[test]
    fn att_syntax_reverses_operands_and_adds_sigils() {
        let add: [u8; 2] = [0x01, 0xD8];
        assert_eq!(rendered(Arch::X86, &add, Syntax::Att), "add %ebx,%eax");
        assert_eq!(rendered(Arch::X86, &add, Syntax::Intel), "add eax,ebx");
        assert_eq!(rendered(Arch::X86, &add, Syntax::Nasm), "add eax,ebx");
        assert_eq!(rendered(Arch::X86, &add, Syntax::Masm), "add eax,ebx");
    }

    #[test]
    fn att_immediate_uses_dollar_and_0x_prefix() {
        let mov: [u8; 7] = [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00];
        assert_eq!(rendered(Arch::X86_64, &mov, Syntax::Att), "mov $0x2A,%rax");
        assert_eq!(rendered(Arch::X86_64, &mov, Syntax::Intel), "mov rax,2Ah");
        assert_eq!(rendered(Arch::X86_64, &mov, Syntax::Nasm), "mov rax,2Ah");
    }

    #[test]
    fn intel_keeps_ptr_keyword_where_nasm_drops_it() {
        let store: [u8; 6] = [0xC7, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            rendered(Arch::X86_64, &store, Syntax::Intel),
            "mov dword ptr [rax],1"
        );
        assert_eq!(
            rendered(Arch::X86_64, &store, Syntax::Nasm),
            "mov dword [rax],1"
        );
        assert_eq!(
            rendered(Arch::X86_64, &store, Syntax::Att),
            "movl $1,(%rax)"
        );
    }

    #[test]
    fn disassemble_x86_rejects_non_x86_arch() {
        let err: Error =
            disassemble_x86(Arch::Aarch64, 0, &[0, 0, 0, 0], Syntax::Intel).expect_err("reject");
        assert!(matches!(err, Error::UnsupportedArch(_)));
    }
}
