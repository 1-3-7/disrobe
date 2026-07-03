use capstone::Capstone;
use capstone::arch::BuildsCapstone as _;
use capstone::arch::BuildsCapstoneEndian as _;
use capstone::arch::BuildsCapstoneExtraMode as _;
use iced_x86::{
    Decoder, DecoderOptions, GasFormatter, Instruction, IntelFormatter, MasmFormatter,
    NasmFormatter,
};
use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;

use crate::error::{Error, Result};

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

pub fn disassemble(arch: Arch, base: u64, bytes: &[u8]) -> Result<Vec<DisasmInsn>> {
    match arch {
        Arch::X86 => disasm_iced(bytes, base, 32, Syntax::Nasm),
        Arch::X86_64 => disasm_iced(bytes, base, 64, Syntax::Nasm),
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
    let min_step: usize = if thumb { 2 } else { 4 };
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut addr: u64 = base;
    loop {
        let before: u64 = u64::from(yaxpeax_arch::Reader::<u32, u8>::total_offset(&mut reader));
        let start: usize = usize::try_from(before).unwrap_or(usize::MAX);
        if start.saturating_add(min_step) > bytes.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after: u64 =
                    u64::from(yaxpeax_arch::Reader::<u32, u8>::total_offset(&mut reader));
                let consumed: usize = usize::try_from(after.saturating_sub(before)).unwrap_or(0);
                if consumed == 0 {
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
                    address: addr,
                    bytes: raw,
                    mnemonic: m,
                    operands: ops,
                });
                addr = addr.wrapping_add(after.saturating_sub(before));
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
