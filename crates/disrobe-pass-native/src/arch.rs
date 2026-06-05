use capstone::Capstone;
use capstone::arch::BuildsCapstone as _;
use capstone::arch::BuildsCapstoneEndian as _;
use capstone::arch::BuildsCapstoneExtraMode as _;
use iced_x86::{Decoder, DecoderOptions, Formatter as _, Instruction, NasmFormatter};
use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;

use crate::error::{Error, Result};

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

pub fn disassemble(arch: Arch, base: u64, bytes: &[u8]) -> Result<Vec<DisasmInsn>> {
    match arch {
        Arch::X86 => disasm_iced(bytes, base, 32),
        Arch::X86_64 => disasm_iced(bytes, base, 64),
        Arch::Aarch64 => disasm_yaxpeax_aarch64(bytes, base),
        Arch::Arm32 | Arch::Thumb => disasm_yaxpeax_arm(bytes, base, matches!(arch, Arch::Thumb)),
        Arch::RiscV32 => disasm_capstone_riscv(bytes, base, false),
        Arch::RiscV64 => disasm_capstone_riscv(bytes, base, true),
        Arch::MipsBe32 => disasm_capstone_mips(bytes, base, false, true),
        Arch::MipsLe32 => disasm_capstone_mips(bytes, base, false, false),
        Arch::Mips64 => disasm_capstone_mips(bytes, base, true, true),
        Arch::PowerPc32 => disasm_capstone_ppc(bytes, base, false),
        Arch::PowerPc64 => disasm_capstone_ppc(bytes, base, true),
        Arch::Sparc => disasm_capstone_sparc(bytes, base, false),
        Arch::Sparc64 => disasm_capstone_sparc(bytes, base, true),
        Arch::Ebpf => disasm_capstone_ebpf(bytes, base),
        Arch::Avr => disasm_capstone_avr(bytes, base),
    }
}

fn disasm_iced(bytes: &[u8], base: u64, bits: u32) -> Result<Vec<DisasmInsn>> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, bytes, base, DecoderOptions::NONE);
    let mut formatter: NasmFormatter = NasmFormatter::new();
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

fn split_text(text: &str) -> (String, String) {
    match text.split_once(' ') {
        Some((m, ops)) => (m.to_owned(), ops.trim().to_owned()),
        None => (text.to_owned(), String::new()),
    }
}

fn disasm_yaxpeax_aarch64(bytes: &[u8], base: u64) -> Result<Vec<DisasmInsn>> {
    let decoder: yaxpeax_arm::armv8::a64::InstDecoder =
        yaxpeax_arm::armv8::a64::InstDecoder::default();
    let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(bytes);
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut addr: u64 = base;
    let mut idx: usize = 0;
    while idx + 4 <= bytes.len() {
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let text: String = inst.to_string();
                let (m, ops): (String, String) = split_text(&text);
                let raw: Vec<u8> = bytes[idx..idx + 4].to_vec();
                out.push(DisasmInsn {
                    address: addr,
                    bytes: raw,
                    mnemonic: m,
                    operands: ops,
                });
                addr = addr.wrapping_add(4);
                idx += 4;
            }
            Err(e) => {
                return Err(Error::Disasm {
                    engine: "yaxpeax-aarch64",
                    message: e.to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn disasm_yaxpeax_arm(bytes: &[u8], base: u64, thumb: bool) -> Result<Vec<DisasmInsn>> {
    let decoder: yaxpeax_arm::armv7::InstDecoder = if thumb {
        yaxpeax_arm::armv7::InstDecoder::default_thumb()
    } else {
        yaxpeax_arm::armv7::InstDecoder::default()
    };
    let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(bytes);
    let step: usize = if thumb { 2 } else { 4 };
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut addr: u64 = base;
    let mut idx: usize = 0;
    while idx + step <= bytes.len() {
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let text: String = inst.to_string();
                let (m, ops): (String, String) = split_text(&text);
                let raw: Vec<u8> = bytes[idx..idx + step].to_vec();
                out.push(DisasmInsn {
                    address: addr,
                    bytes: raw,
                    mnemonic: m,
                    operands: ops,
                });
                addr = addr.wrapping_add(step as u64);
                idx += step;
            }
            Err(e) => {
                return Err(Error::Disasm {
                    engine: if thumb {
                        "yaxpeax-thumb"
                    } else {
                        "yaxpeax-arm"
                    },
                    message: e.to_string(),
                });
            }
        }
    }
    Ok(out)
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

fn disasm_capstone_riscv(bytes: &[u8], base: u64, bits64: bool) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = build_capstone(
        || {
            Capstone::new()
                .riscv()
                .mode(if bits64 {
                    capstone::arch::riscv::ArchMode::RiscV64
                } else {
                    capstone::arch::riscv::ArchMode::RiscV32
                })
                .extra_mode(
                    [capstone::arch::riscv::ArchExtraMode::RiscVC]
                        .iter()
                        .copied(),
                )
                .build()
        },
        "capstone-riscv",
    )?;
    cs_run(&cs, bytes, base, "capstone-riscv")
}

fn disasm_capstone_mips(
    bytes: &[u8],
    base: u64,
    bits64: bool,
    big_endian: bool,
) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = build_capstone(
        || {
            Capstone::new()
                .mips()
                .mode(if bits64 {
                    capstone::arch::mips::ArchMode::Mips64
                } else {
                    capstone::arch::mips::ArchMode::Mips32
                })
                .endian(if big_endian {
                    capstone::Endian::Big
                } else {
                    capstone::Endian::Little
                })
                .build()
        },
        "capstone-mips",
    )?;
    cs_run(&cs, bytes, base, "capstone-mips")
}

fn disasm_capstone_ppc(bytes: &[u8], base: u64, bits64: bool) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = build_capstone(
        || {
            Capstone::new()
                .ppc()
                .mode(if bits64 {
                    capstone::arch::ppc::ArchMode::Mode64
                } else {
                    capstone::arch::ppc::ArchMode::Mode32
                })
                .endian(capstone::Endian::Big)
                .build()
        },
        "capstone-ppc",
    )?;
    cs_run(&cs, bytes, base, "capstone-ppc")
}

fn disasm_capstone_sparc(bytes: &[u8], base: u64, bits64: bool) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = build_capstone(
        || {
            Capstone::new()
                .sparc()
                .mode(if bits64 {
                    capstone::arch::sparc::ArchMode::V9
                } else {
                    capstone::arch::sparc::ArchMode::Default
                })
                .build()
        },
        "capstone-sparc",
    )?;
    cs_run(&cs, bytes, base, "capstone-sparc")
}

fn disasm_capstone_ebpf(bytes: &[u8], base: u64) -> Result<Vec<DisasmInsn>> {
    let cs: Capstone = build_capstone(
        || {
            Capstone::new()
                .bpf()
                .mode(capstone::arch::bpf::ArchMode::Ebpf)
                .endian(capstone::Endian::Little)
                .build()
        },
        "capstone-ebpf",
    )?;
    cs_run(&cs, bytes, base, "capstone-ebpf")
}

fn disasm_capstone_avr(_bytes: &[u8], _base: u64) -> Result<Vec<DisasmInsn>> {
    Err(Error::UnsupportedArch(
        "avr-not-exposed-in-rust-capstone-0.13-bindings".to_owned(),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn arm32_nop_decodes() {
        let bytes: [u8; 4] = [0x00, 0xF0, 0x20, 0xE3];
        let out: Vec<DisasmInsn> = disassemble(Arch::Arm32, 0, &bytes).expect("disasm");
        assert_eq!(out.len(), 1);
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
}
