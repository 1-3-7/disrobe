use rkyv::{Archive, Deserialize, Serialize, rancor::Error as RkyvError};

use crate::error::{EnvelopeError, Result};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct RawPayload {
    pub source_path: String,
    pub source_bytes: Vec<u8>,
    pub source_hash: [u8; 32],
    pub detected_format: Option<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmPayload {
    pub source_hash: [u8; 32],
    pub instructions: Vec<DisasmInstruction>,
    pub symbol_table: Vec<DisasmSymbol>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub struct DisasmInstruction {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub flow: InsnFlow,
    pub branch_target: Option<u64>,
    pub reg_uses: Vec<RegUse>,
    pub mem_uses: Vec<MemUse>,
    pub rflags: RflagsEffect,
    pub isa: IsaTag,
    pub stack_effect: StackEffect,
    pub segments: InsnSegments,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub struct IsaTag {
    pub cpuid_features: Vec<String>,
    pub encoding: InsnEncoding,
}

impl IsaTag {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cpuid_features.is_empty() && matches!(self.encoding, InsnEncoding::Unknown)
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub enum InsnEncoding {
    #[default]
    Unknown,
    Legacy,
    Vex,
    Evex,
    Xop,
    D3now,
}

impl InsnEncoding {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Legacy => "legacy",
            Self::Vex => "vex",
            Self::Evex => "evex",
            Self::Xop => "xop",
            Self::D3now => "3dnow",
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub struct StackEffect {
    pub sp_delta: i32,
    pub is_stack: bool,
    pub fpu_increment: i8,
    pub fpu_writes_top: bool,
    pub fpu_conditional: bool,
}

impl StackEffect {
    #[must_use]
    pub const fn is_neutral(self) -> bool {
        self.sp_delta == 0 && !self.is_stack && !self.fpu_writes_top
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub struct InsnSegments {
    pub legacy_prefix: u8,
    pub opcode: u8,
    pub modrm: u8,
    pub sib: u8,
    pub displacement: u8,
    pub immediate: u8,
}

impl InsnSegments {
    #[must_use]
    pub const fn total(self) -> usize {
        self.legacy_prefix as usize
            + self.opcode as usize
            + self.modrm as usize
            + self.sib as usize
            + self.displacement as usize
            + self.immediate as usize
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.total() == 0
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct RegUse {
    pub register: String,
    pub access: RegAccess,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub enum RegAccess {
    #[default]
    None,
    Read,
    CondRead,
    Write,
    CondWrite,
    ReadWrite,
    ReadCondWrite,
    NoMemAccess,
}

impl RegAccess {
    #[must_use]
    pub const fn reads(self) -> bool {
        matches!(
            self,
            Self::Read | Self::CondRead | Self::ReadWrite | Self::ReadCondWrite
        )
    }

    #[must_use]
    pub const fn writes(self) -> bool {
        matches!(
            self,
            Self::Write | Self::CondWrite | Self::ReadWrite | Self::ReadCondWrite
        )
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct MemUse {
    pub segment: String,
    pub base: String,
    pub index: String,
    pub scale: u8,
    pub displacement: u64,
    pub memory_size: String,
    pub access: RegAccess,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub struct RflagsEffect {
    pub read: u16,
    pub written: u16,
    pub cleared: u16,
    pub set: u16,
    pub undefined: u16,
}

impl RflagsEffect {
    pub const OF: u16 = 0x0001;
    pub const SF: u16 = 0x0002;
    pub const ZF: u16 = 0x0004;
    pub const AF: u16 = 0x0008;
    pub const CF: u16 = 0x0010;
    pub const PF: u16 = 0x0020;
    pub const DF: u16 = 0x0040;
    pub const IF: u16 = 0x0080;
    pub const AC: u16 = 0x0100;

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.read == 0
            && self.written == 0
            && self.cleared == 0
            && self.set == 0
            && self.undefined == 0
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[rkyv(derive(Debug))]
pub enum InsnFlow {
    #[default]
    Sequential,
    Call,
    IndirectCall,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    Return,
    Interrupt,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmSymbol {
    pub address: u64,
    pub name: String,
    pub kind: DisasmSymbolKind,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub enum DisasmSymbolKind {
    Function,
    Data,
    Label,
    Export,
    Import,
}

#[inline]
pub fn encode_raw(payload: &RawPayload) -> Result<Vec<u8>> {
    rkyv::to_bytes::<RkyvError>(payload)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| EnvelopeError::RkyvSer(e.to_string()))
}

#[inline]
pub fn decode_raw(bytes: &[u8]) -> Result<RawPayload> {
    let archived: &ArchivedRawPayload = rkyv::access::<ArchivedRawPayload, RkyvError>(bytes)
        .map_err(|e| EnvelopeError::RkyvAccess(e.to_string()))?;
    rkyv::deserialize::<RawPayload, RkyvError>(archived)
        .map_err(|e| EnvelopeError::RkyvDeser(e.to_string()))
}

#[inline]
pub fn encode_disasm(payload: &DisasmPayload) -> Result<Vec<u8>> {
    rkyv::to_bytes::<RkyvError>(payload)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| EnvelopeError::RkyvSer(e.to_string()))
}

#[inline]
pub fn decode_disasm(bytes: &[u8]) -> Result<DisasmPayload> {
    let archived: &ArchivedDisasmPayload = rkyv::access::<ArchivedDisasmPayload, RkyvError>(bytes)
        .map_err(|e| EnvelopeError::RkyvAccess(e.to_string()))?;
    rkyv::deserialize::<DisasmPayload, RkyvError>(archived)
        .map_err(|e| EnvelopeError::RkyvDeser(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_raw_payload() {
        let p: RawPayload = RawPayload {
            source_path: "hello.wasm".to_owned(),
            source_bytes: vec![0, 1, 2, 3, 4, 5, 6, 7],
            source_hash: [0xAA; 32],
            detected_format: Some("wasm".to_owned()),
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let decoded: RawPayload = decode_raw(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_raw_payload_no_format() {
        let p: RawPayload = RawPayload {
            source_path: "/tmp/blob".to_owned(),
            source_bytes: vec![],
            source_hash: [0; 32],
            detected_format: None,
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let decoded: RawPayload = decode_raw(&bytes).expect("decode");
        assert_eq!(p, decoded);
        assert!(decoded.detected_format.is_none());
    }

    #[test]
    fn round_trip_disasm_payload() {
        let p: DisasmPayload = DisasmPayload {
            source_hash: [0xBB; 32],
            instructions: vec![
                DisasmInstruction {
                    offset: 0x1000,
                    bytes: vec![0x55, 0x48, 0x89, 0xE5],
                    mnemonic: "push".to_owned(),
                    operands: vec!["rbp".to_owned()],
                    flow: InsnFlow::Sequential,
                    branch_target: None,
                    reg_uses: vec![],
                    mem_uses: vec![],
                    rflags: RflagsEffect::default(),
                    ..DisasmInstruction::default()
                },
                DisasmInstruction {
                    offset: 0x1004,
                    bytes: vec![0xC3],
                    mnemonic: "ret".to_owned(),
                    operands: vec![],
                    flow: InsnFlow::Return,
                    branch_target: None,
                    reg_uses: vec![],
                    mem_uses: vec![],
                    rflags: RflagsEffect::default(),
                    ..DisasmInstruction::default()
                },
            ],
            symbol_table: vec![DisasmSymbol {
                address: 0x1000,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Function,
            }],
        };
        let bytes: Vec<u8> = encode_disasm(&p).expect("encode");
        let decoded: DisasmPayload = decode_disasm(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_disasm_payload_with_instruction_info() {
        let p: DisasmPayload = DisasmPayload {
            source_hash: [0xCC; 32],
            instructions: vec![DisasmInstruction {
                offset: 0x2000,
                bytes: vec![0x01, 0xD8],
                mnemonic: "add".to_owned(),
                operands: vec!["eax".to_owned(), "ebx".to_owned()],
                flow: InsnFlow::Sequential,
                branch_target: None,
                reg_uses: vec![
                    RegUse {
                        register: "EAX".to_owned(),
                        access: RegAccess::ReadWrite,
                    },
                    RegUse {
                        register: "EBX".to_owned(),
                        access: RegAccess::Read,
                    },
                ],
                mem_uses: vec![MemUse {
                    segment: "DS".to_owned(),
                    base: "RBP".to_owned(),
                    index: "None".to_owned(),
                    scale: 1,
                    displacement: 0x10,
                    memory_size: "UInt32".to_owned(),
                    access: RegAccess::Write,
                }],
                rflags: RflagsEffect {
                    read: 0,
                    written: RflagsEffect::OF
                        | RflagsEffect::SF
                        | RflagsEffect::ZF
                        | RflagsEffect::AF
                        | RflagsEffect::CF
                        | RflagsEffect::PF,
                    cleared: 0,
                    set: 0,
                    undefined: 0,
                },
                ..DisasmInstruction::default()
            }],
            symbol_table: vec![],
        };
        let bytes: Vec<u8> = encode_disasm(&p).expect("encode");
        let decoded: DisasmPayload = decode_disasm(&bytes).expect("decode");
        assert_eq!(p, decoded);
        let insn: &DisasmInstruction = &decoded.instructions[0];
        assert!(insn.reg_uses[0].access.reads());
        assert!(insn.reg_uses[0].access.writes());
        assert!(insn.reg_uses[1].access.reads());
        assert!(!insn.reg_uses[1].access.writes());
        assert!(!insn.rflags.is_empty());
    }

    #[test]
    fn round_trip_disasm_payload_with_isa_stack_and_segments() {
        let p: DisasmPayload = DisasmPayload {
            source_hash: [0xDD; 32],
            instructions: vec![DisasmInstruction {
                offset: 0x3000,
                bytes: vec![0xC5, 0xF8, 0x10, 0xC1],
                mnemonic: "vmovups".to_owned(),
                operands: vec!["xmm0".to_owned(), "xmm1".to_owned()],
                flow: InsnFlow::Sequential,
                branch_target: None,
                isa: IsaTag {
                    cpuid_features: vec!["AVX".to_owned()],
                    encoding: InsnEncoding::Vex,
                },
                stack_effect: StackEffect {
                    sp_delta: 0,
                    is_stack: false,
                    fpu_increment: 0,
                    fpu_writes_top: false,
                    fpu_conditional: false,
                },
                segments: InsnSegments {
                    legacy_prefix: 0,
                    opcode: 3,
                    modrm: 1,
                    sib: 0,
                    displacement: 0,
                    immediate: 0,
                },
                ..DisasmInstruction::default()
            }],
            symbol_table: vec![],
        };
        let bytes: Vec<u8> = encode_disasm(&p).expect("encode");
        let decoded: DisasmPayload = decode_disasm(&bytes).expect("decode");
        assert_eq!(p, decoded);
        let insn: &DisasmInstruction = &decoded.instructions[0];
        assert_eq!(insn.isa.encoding, InsnEncoding::Vex);
        assert_eq!(insn.isa.cpuid_features, vec!["AVX".to_owned()]);
        assert_eq!(insn.segments.total(), insn.bytes.len());
        assert!(insn.stack_effect.is_neutral());
    }

    #[test]
    fn reg_access_read_write_classification() {
        assert!(RegAccess::Read.reads());
        assert!(!RegAccess::Read.writes());
        assert!(!RegAccess::Write.reads());
        assert!(RegAccess::Write.writes());
        assert!(RegAccess::ReadWrite.reads());
        assert!(RegAccess::ReadWrite.writes());
        assert!(RegAccess::CondRead.reads());
        assert!(RegAccess::CondWrite.writes());
        assert!(!RegAccess::None.reads());
        assert!(!RegAccess::None.writes());
    }

    #[test]
    fn rkyv_zero_copy_access_does_not_deserialize() {
        let p: RawPayload = RawPayload {
            source_path: "a.bin".to_owned(),
            source_bytes: vec![9, 8, 7],
            source_hash: [1; 32],
            detected_format: None,
        };
        let bytes: Vec<u8> = encode_raw(&p).expect("encode");
        let archived: &ArchivedRawPayload =
            rkyv::access::<ArchivedRawPayload, RkyvError>(&bytes).expect("access");
        assert_eq!(archived.source_path.as_str(), "a.bin");
        assert_eq!(archived.source_bytes.as_slice(), &[9u8, 8, 7]);
        assert_eq!(archived.source_hash, [1u8; 32]);
        assert!(archived.detected_format.is_none());
    }
}
