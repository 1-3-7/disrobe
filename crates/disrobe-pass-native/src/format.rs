use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFormat {
    Pe32,
    Pe64,
    EfiPe,
    Elf32,
    Elf64,
    KernelModule,
    MachO32,
    MachO64,
    MachOFat,
    Coff,
    Mz,
    Ne,
    Le,
    Lx,
    Wasm,
    Unknown,
}

impl NativeFormat {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pe32 => "pe32",
            Self::Pe64 => "pe64",
            Self::EfiPe => "efi-pe",
            Self::Elf32 => "elf32",
            Self::Elf64 => "elf64",
            Self::KernelModule => "kmod",
            Self::MachO32 => "macho32",
            Self::MachO64 => "macho64",
            Self::MachOFat => "macho-fat",
            Self::Coff => "coff",
            Self::Mz => "mz",
            Self::Ne => "ne",
            Self::Le => "le",
            Self::Lx => "lx",
            Self::Wasm => "wasm",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedFormat {
    pub kind: NativeFormat,
    pub bits: u8,
    pub subsystem: Option<String>,
    pub notes: Vec<String>,
}

const MZ_MAGIC: &[u8; 2] = b"MZ";
const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const MACHO_MAGIC_LE32: u32 = 0xFEED_FACE;
const MACHO_MAGIC_LE64: u32 = 0xFEED_FACF;
const MACHO_MAGIC_BE32: u32 = 0xCEFA_EDFE;
const MACHO_MAGIC_BE64: u32 = 0xCFFA_EDFE;
const MACHO_FAT_BE: u32 = 0xCAFE_BABE;
const MACHO_FAT_LE: u32 = 0xBEBA_FECA;
const PE_SIG: &[u8; 4] = b"PE\x00\x00";
const NE_SIG: &[u8; 2] = b"NE";
const LE_SIG: &[u8; 2] = b"LE";
const LX_SIG: &[u8; 2] = b"LX";
const WASM_MAGIC: &[u8; 4] = b"\0asm";
const COFF_MACHINE_OFFSETS_MIN: usize = 20;

#[allow(clippy::too_many_lines)]
pub fn detect(bytes: &[u8]) -> Result<DetectedFormat> {
    if bytes.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            had: bytes.len(),
        });
    }
    if bytes.starts_with(WASM_MAGIC) {
        if bytes.len() < 8 {
            return Err(Error::Truncated {
                needed: 8,
                had: bytes.len(),
            });
        }
        return Ok(DetectedFormat {
            kind: NativeFormat::Wasm,
            bits: 0,
            subsystem: None,
            notes: Vec::new(),
        });
    }
    if bytes.starts_with(ELF_MAGIC) {
        if bytes.len() < 5 {
            return Err(Error::Truncated {
                needed: 5,
                had: bytes.len(),
            });
        }
        let class: u8 = bytes[4];
        let kind: NativeFormat = match class {
            1 => NativeFormat::Elf32,
            2 => NativeFormat::Elf64,
            _ => {
                return Err(Error::ObjectParse(format!(
                    "unknown ELF class byte: 0x{class:02X}"
                )));
            }
        };
        let mut notes: Vec<String> = Vec::new();
        let e_type: u16 = if bytes.len() >= 18 {
            u16::from_le_bytes([bytes[16], bytes[17]])
        } else {
            0
        };
        let mut kind_final: NativeFormat = kind;
        if e_type == 1 {
            notes.push("relocatable".to_owned());
            kind_final = NativeFormat::KernelModule;
        } else if e_type == 3 {
            notes.push("shared object".to_owned());
        } else if e_type == 2 {
            notes.push("executable".to_owned());
        }
        return Ok(DetectedFormat {
            kind: kind_final,
            bits: if class == 1 { 32 } else { 64 },
            subsystem: None,
            notes,
        });
    }
    if bytes.len() >= 4 {
        let m32: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(
            m32,
            MACHO_MAGIC_LE32 | MACHO_MAGIC_LE64 | MACHO_MAGIC_BE32 | MACHO_MAGIC_BE64
        ) {
            let is64: bool = matches!(m32, MACHO_MAGIC_LE64 | MACHO_MAGIC_BE64);
            return Ok(DetectedFormat {
                kind: if is64 {
                    NativeFormat::MachO64
                } else {
                    NativeFormat::MachO32
                },
                bits: if is64 { 64 } else { 32 },
                subsystem: None,
                notes: Vec::new(),
            });
        }
        let mbe: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(mbe, MACHO_FAT_BE | MACHO_FAT_LE) {
            return Ok(DetectedFormat {
                kind: NativeFormat::MachOFat,
                bits: 0,
                subsystem: None,
                notes: vec!["universal".to_owned()],
            });
        }
    }
    if bytes.starts_with(MZ_MAGIC) {
        if bytes.len() < 0x40 {
            return Ok(DetectedFormat {
                kind: NativeFormat::Mz,
                bits: 16,
                subsystem: None,
                notes: vec!["dos-mz-stub".to_owned()],
            });
        }
        let e_lfanew: usize =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if e_lfanew == 0 || e_lfanew + 4 > bytes.len() {
            return Ok(DetectedFormat {
                kind: NativeFormat::Mz,
                bits: 16,
                subsystem: None,
                notes: vec!["dos-only".to_owned()],
            });
        }
        let sig4: &[u8] = &bytes[e_lfanew..e_lfanew + 4];
        if sig4 == PE_SIG {
            return classify_pe(bytes, e_lfanew);
        }
        if &sig4[..2] == NE_SIG {
            let subsystem: Option<String> = match disrobe_binfmt::parse_native(bytes) {
                Ok(parsed) => match parsed.format {
                    disrobe_binfmt::ParsedNativeFormat::NeOs2 => Some("os2".to_owned()),
                    disrobe_binfmt::ParsedNativeFormat::NeWindows => Some("windows".to_owned()),
                    _ => None,
                },
                Err(_) => {
                    return Ok(DetectedFormat {
                        kind: NativeFormat::Mz,
                        bits: 16,
                        subsystem: None,
                        notes: vec!["invalid-ne".to_owned()],
                    });
                }
            };
            return Ok(DetectedFormat {
                kind: NativeFormat::Ne,
                bits: 16,
                subsystem,
                notes: Vec::new(),
            });
        }
        if &sig4[..2] == LE_SIG {
            return Ok(DetectedFormat {
                kind: NativeFormat::Le,
                bits: 16,
                subsystem: None,
                notes: Vec::new(),
            });
        }
        if &sig4[..2] == LX_SIG {
            return Ok(DetectedFormat {
                kind: NativeFormat::Lx,
                bits: 32,
                subsystem: None,
                notes: Vec::new(),
            });
        }
        return Ok(DetectedFormat {
            kind: NativeFormat::Mz,
            bits: 16,
            subsystem: None,
            notes: vec!["unknown-extended-header".to_owned()],
        });
    }
    if let Some(kind) = classify_coff_header(bytes) {
        return Ok(DetectedFormat {
            kind,
            bits: 32,
            subsystem: None,
            notes: vec!["headerless-coff".to_owned()],
        });
    }
    Err(Error::UnknownFormat)
}

fn classify_pe(bytes: &[u8], pe_off: usize) -> Result<DetectedFormat> {
    let opt_hdr_off: usize = pe_off + 4 + 20;
    if opt_hdr_off + 2 > bytes.len() {
        return Err(Error::Truncated {
            needed: opt_hdr_off + 2,
            had: bytes.len(),
        });
    }
    let magic: u16 = u16::from_le_bytes([bytes[opt_hdr_off], bytes[opt_hdr_off + 1]]);
    let (kind, bits): (NativeFormat, u8) = match magic {
        0x010B => (NativeFormat::Pe32, 32),
        0x020B => (NativeFormat::Pe64, 64),
        0x0107 => (NativeFormat::Pe32, 32),
        _ => (NativeFormat::Pe32, 32),
    };
    let subsystem_off: usize = opt_hdr_off + 0x44;
    let subsystem: Option<String> = if subsystem_off + 2 <= bytes.len() {
        let s: u16 = u16::from_le_bytes([bytes[subsystem_off], bytes[subsystem_off + 1]]);
        let kind_final: NativeFormat = match s {
            10..=13 => NativeFormat::EfiPe,
            _ => kind,
        };
        let label: String = subsystem_label(s).to_owned();
        return Ok(DetectedFormat {
            kind: kind_final,
            bits,
            subsystem: Some(label),
            notes: Vec::new(),
        });
    } else {
        None
    };
    Ok(DetectedFormat {
        kind,
        bits,
        subsystem,
        notes: Vec::new(),
    })
}

const fn subsystem_label(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-cui",
        5 => "os2-cui",
        7 => "posix-cui",
        8 => "native-win9x",
        9 => "windows-ce-gui",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        13 => "efi-rom",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => "unknown",
    }
}

fn classify_coff_header(bytes: &[u8]) -> Option<NativeFormat> {
    if bytes.len() < COFF_MACHINE_OFFSETS_MIN {
        return None;
    }
    let machine: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
    matches!(
        machine,
        0x014C | 0x8664 | 0x01C0 | 0xAA64 | 0x0166 | 0x01F0 | 0x01F2 | 0x0200
    )
    .then_some(NativeFormat::Coff)
}

#[must_use]
pub fn summarize(formats: &BTreeMap<NativeFormat, u32>) -> String {
    let mut acc: String = String::new();
    for (k, v) in formats {
        acc.push_str(k.label());
        acc.push('=');
        acc.push_str(&v.to_string());
        acc.push(' ');
    }
    acc.trim_end().to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_rejected() {
        let err: Error = detect(&[]).expect_err("must reject empty");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn elf64_class_byte_recognized() {
        let mut buf: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        buf.resize(64, 0);
        buf[16] = 2;
        buf[17] = 0;
        let d: DetectedFormat = detect(&buf).expect("elf64 detect");
        assert_eq!(d.kind, NativeFormat::Elf64);
        assert_eq!(d.bits, 64);
    }

    #[test]
    fn elf_relocatable_classified_as_kmod() {
        let mut buf: Vec<u8> = b"\x7FELF\x02\x01\x01\x00".to_vec();
        buf.resize(64, 0);
        buf[16] = 1;
        buf[17] = 0;
        let d: DetectedFormat = detect(&buf).expect("ko detect");
        assert_eq!(d.kind, NativeFormat::KernelModule);
    }

    #[test]
    fn macho_le64_recognized() {
        let buf: [u8; 32] = [
            0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let d: DetectedFormat = detect(&buf).expect("macho detect");
        assert_eq!(d.kind, NativeFormat::MachO64);
    }

    #[test]
    fn macho_fat_recognized() {
        let buf: [u8; 16] = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        let d: DetectedFormat = detect(&buf).expect("fat detect");
        assert_eq!(d.kind, NativeFormat::MachOFat);
    }

    #[test]
    fn mz_dos_only_classified_when_pe_offset_zero() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0] = b'M';
        buf[1] = b'Z';
        let d: DetectedFormat = detect(&buf).expect("mz detect");
        assert_eq!(d.kind, NativeFormat::Mz);
    }

    #[test]
    fn pe32_minimal_signature_path() {
        let mut buf: Vec<u8> = vec![0u8; 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_off: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        buf[0x80 + 4 + 20] = 0x0B;
        buf[0x80 + 4 + 20 + 1] = 0x01;
        let d: DetectedFormat = detect(&buf).expect("pe32 detect");
        assert!(matches!(d.kind, NativeFormat::Pe32 | NativeFormat::EfiPe));
        assert_eq!(d.bits, 32);
    }

    #[test]
    fn ne_legacy_recognized_through_mz_stub() {
        const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
        let d: DetectedFormat = detect(REAL_NE).expect("ne detect");
        assert_eq!(d.kind, NativeFormat::Ne);
        assert_eq!(d.subsystem.as_deref(), Some("windows"));
    }

    #[test]
    fn invalid_ne_header_is_not_reported_as_a_validated_ne() {
        const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
        let mut bytes: Vec<u8> = REAL_NE.to_vec();
        bytes[0x08..0x0a].copy_from_slice(&9u16.to_le_bytes());
        let detected: DetectedFormat = detect(&bytes).expect("invalid NE classification");
        assert_eq!(detected.kind, NativeFormat::Mz);
        assert_eq!(detected.notes, ["invalid-ne"]);
    }

    #[test]
    fn core_and_component_wasm_preambles_are_classified_consistently() {
        for bytes in [
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00],
        ] {
            let detected: DetectedFormat = detect(&bytes).expect("detect WebAssembly preamble");
            assert_eq!(detected.kind, NativeFormat::Wasm);
            assert_eq!(detected.kind.label(), "wasm");
            assert_eq!(detected.bits, 0);
            assert_eq!(detected.subsystem, None);
            assert!(detected.notes.is_empty());
        }
    }

    #[test]
    fn truncated_wasm_magic_is_not_reported_as_a_complete_format() {
        for length in 4usize..8 {
            let error: Error = detect(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00][..length])
                .expect_err("a partial WebAssembly preamble must be rejected");
            assert!(matches!(error, Error::Truncated { needed: 8, had } if had == length));
        }
    }
}
