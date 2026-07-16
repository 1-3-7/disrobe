#[cfg(not(target_arch = "wasm32"))]
use disrobe_pass_native::{Arch as NativeArch_, DisasmInsn, disassemble};
use serde::{Deserialize, Serialize};

use crate::alt_runtimes::micropython::{MAX_TABLE_PREALLOC, bounded_table_count};
use crate::alt_runtimes::{AltRuntimeError, Result};

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[cfg(target_arch = "wasm32")]
const NATIVE_DISASM_WASM_NOTE: &str =
    "native machine-code disassembly unavailable in the browser build";

const MPY_MAGIC: u8 = b'M';
const MIN_NATIVE_VERSION: u8 = 3;
const MAX_NATIVE_VERSION: u8 = 6;
const FEATURE_ARCH_FLAGS_PRESENT: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeKind {
    Native,
    Viper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeKind {
    Bytecode,
    NativePy,
    NativeViper,
    NativeAsm,
}

impl CodeKind {
    const fn from_low_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Bytecode,
            1 => Self::NativePy,
            2 => Self::NativeViper,
            _ => Self::NativeAsm,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bytecode => "bytecode",
            Self::NativePy => "native-py",
            Self::NativeViper => "native-viper",
            Self::NativeAsm => "native-asm",
        }
    }

    const fn is_native(self) -> bool {
        !matches!(self, Self::Bytecode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeArch {
    Unknown,
    None,
    X86,
    X64,
    Armv6,
    Armv6m,
    Armv7m,
    Armv7em,
    Armv7emSp,
    Armv7emDp,
    Xtensa,
    XtensaWin,
    Rv32imc,
    Rv64imc,
}

impl NativeArch {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::Armv6 => "armv6",
            Self::Armv6m => "armv6m",
            Self::Armv7m => "armv7m",
            Self::Armv7em => "armv7em",
            Self::Armv7emSp => "armv7em-singlefloat",
            Self::Armv7emDp => "armv7em-doublefloat",
            Self::Xtensa => "xtensa",
            Self::XtensaWin => "xtensawin",
            Self::Rv32imc => "rv32imc",
            Self::Rv64imc => "rv64imc",
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    const fn disasm_target(self) -> Option<DisasmTarget> {
        match self {
            Self::X86 => Some(DisasmTarget::Native(NativeArch_::X86)),
            Self::X64 => Some(DisasmTarget::Native(NativeArch_::X86_64)),
            Self::Rv32imc => Some(DisasmTarget::Native(NativeArch_::RiscV32)),
            Self::Rv64imc => Some(DisasmTarget::Native(NativeArch_::RiscV64)),
            Self::Armv6 => Some(DisasmTarget::Arm { thumb: false }),
            Self::Armv6m | Self::Armv7m | Self::Armv7em | Self::Armv7emSp | Self::Armv7emDp => {
                Some(DisasmTarget::Arm { thumb: true })
            }
            Self::Unknown | Self::None | Self::Xtensa | Self::XtensaWin => None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy)]
enum DisasmTarget {
    Native(NativeArch_),
    Arm { thumb: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFunction {
    pub kind: CodeKind,
    pub machine_code: Vec<u8>,
    pub prelude_offset: usize,
    pub scope_flags: u32,
    pub disassembly: Vec<DisasmInsn>,
    pub disasm_note: Option<String>,
    pub children: Vec<Self>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroPythonNativeModule {
    pub version: u8,
    pub kind: NativeKind,
    pub arch: NativeArch,
    pub features_raw: u8,
    pub arch_flags: u32,
    pub small_int_bits: u8,
    pub qstrs: Vec<String>,
    pub function: NativeFunction,
    pub native_code: Vec<u8>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let b: u8 = *self.data.get(self.pos).ok_or(AltRuntimeError::Truncated {
            offset: self.pos,
            needed: 1,
            had: 0,
        })?;
        self.pos += 1;
        Ok(b)
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn uint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        loop {
            let b: u8 = self.byte()?;
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let had: usize = self.data.len().saturating_sub(self.pos);
        let end: usize = self.pos.checked_add(n).ok_or(AltRuntimeError::Truncated {
            offset: self.pos,
            needed: n,
            had,
        })?;
        let slice: &[u8] = self
            .data
            .get(self.pos..end)
            .ok_or(AltRuntimeError::Truncated {
                offset: self.pos,
                needed: n,
                had,
            })?;
        self.pos = end;
        Ok(slice)
    }
}

pub fn parse(bytes: &[u8]) -> Result<MicroPythonNativeModule> {
    if bytes.len() < 6 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 6,
            had: bytes.len(),
        });
    }
    let mut reader: Reader<'_> = Reader::new(bytes);
    if reader.byte()? != MPY_MAGIC {
        return Err(AltRuntimeError::BadMagic {
            runtime: "micropython-native",
            got: u32::from(bytes[0]),
        });
    }
    let version: u8 = reader.byte()?;
    if !(MIN_NATIVE_VERSION..=MAX_NATIVE_VERSION).contains(&version) {
        return Err(AltRuntimeError::UnsupportedVersion {
            runtime: "micropython-native",
            version: u32::from(version),
        });
    }
    let features_raw: u8 = reader.byte()?;
    let arch: NativeArch = decode_arch(features_raw);
    if matches!(arch, NativeArch::None) {
        return Err(AltRuntimeError::NotDetected("micropython-native"));
    }
    let small_int_bits: u8 = reader.byte()?;
    let arch_flags: u32 = if features_raw & FEATURE_ARCH_FLAGS_PRESENT != 0 {
        u32::try_from(reader.uint()?).unwrap_or(u32::MAX)
    } else {
        0u32
    };
    let n_qstr: u64 = reader.uint()?;
    let n_obj: u64 = reader.uint()?;
    let qstr_count: usize = bounded_table_count(n_qstr, reader.remaining(), "n_qstr", reader.pos)?;
    let mut qstrs: Vec<String> = Vec::with_capacity(qstr_count.min(MAX_TABLE_PREALLOC));
    for _ in 0..qstr_count {
        qstrs.push(read_qstr(&mut reader)?);
    }
    let obj_count: usize = bounded_table_count(n_obj, reader.remaining(), "n_obj", reader.pos)?;
    for _ in 0..obj_count {
        skip_obj(&mut reader, 0)?;
    }
    let function: NativeFunction = read_raw_code(&mut reader, arch, 0)?;
    let native_code: Vec<u8> = first_native_machine_code(&function);
    let kind: NativeKind = match first_native_kind(&function) {
        Some(CodeKind::NativeViper | CodeKind::NativeAsm) => NativeKind::Viper,
        _ => NativeKind::Native,
    };
    Ok(MicroPythonNativeModule {
        version,
        kind,
        arch,
        features_raw,
        arch_flags,
        small_int_bits,
        qstrs,
        function,
        native_code,
    })
}

fn read_raw_code(reader: &mut Reader<'_>, arch: NativeArch, depth: u8) -> Result<NativeFunction> {
    if depth > 32 {
        return Err(AltRuntimeError::BadEncoding {
            field: "raw_code_nesting",
            offset: reader.pos,
        });
    }
    let kind_len: u64 = reader.uint()?;
    let kind: CodeKind = CodeKind::from_low_bits(u8::try_from(kind_len & 3).unwrap_or(0));
    let has_children: bool = (kind_len >> 2) & 1 == 1;
    let fun_data_len: usize = usize::try_from(kind_len >> 3).unwrap_or(0);
    let fun_data: Vec<u8> = reader.take(fun_data_len)?.to_vec();
    let mut prelude_offset: usize = 0;
    let mut scope_flags: u32 = 0;
    match kind {
        CodeKind::NativePy => {
            prelude_offset = usize::try_from(reader.uint()?).unwrap_or(fun_data_len);
        }
        CodeKind::NativeViper | CodeKind::NativeAsm => {
            scope_flags = u32::try_from(reader.uint()?).unwrap_or(0);
            if matches!(kind, CodeKind::NativeAsm) {
                let _n_pos_args: u64 = reader.uint()?;
                let _type_sig: u64 = reader.uint()?;
            }
        }
        CodeKind::Bytecode => {}
    }
    let machine_code: Vec<u8> = if kind.is_native() {
        let split: usize = if matches!(kind, CodeKind::NativePy) {
            prelude_offset.min(fun_data.len())
        } else {
            fun_data.len()
        };
        fun_data.get(..split).unwrap_or(&fun_data).to_vec()
    } else {
        Vec::new()
    };
    let (disassembly, disasm_note): (Vec<DisasmInsn>, Option<String>) = if kind.is_native() {
        disasm_machine_code(arch, &machine_code)
    } else {
        (Vec::new(), None)
    };
    let mut children: Vec<NativeFunction> = Vec::new();
    if has_children {
        let n_children: u64 = reader.uint()?;
        let child_count: usize = bounded_table_count(
            n_children,
            reader.remaining(),
            "raw_code_children",
            reader.pos,
        )?;
        for _ in 0..child_count {
            children.push(read_raw_code(reader, arch, depth + 1)?);
        }
    }
    Ok(NativeFunction {
        kind,
        machine_code,
        prelude_offset,
        scope_flags,
        disassembly,
        disasm_note,
        children,
    })
}

#[cfg(target_arch = "wasm32")]
fn disasm_machine_code(_arch: NativeArch, _code: &[u8]) -> (Vec<DisasmInsn>, Option<String>) {
    (Vec::new(), Some(NATIVE_DISASM_WASM_NOTE.to_owned()))
}

#[cfg(not(target_arch = "wasm32"))]
fn disasm_machine_code(arch: NativeArch, code: &[u8]) -> (Vec<DisasmInsn>, Option<String>) {
    let Some(target): Option<DisasmTarget> = arch.disasm_target() else {
        return (
            Vec::new(),
            Some(format!(
                "no rust disassembler wired for micropython arch {}",
                arch.label()
            )),
        );
    };
    match target {
        DisasmTarget::Native(native_arch) => match disassemble(native_arch, 0, code) {
            Ok(insns) => (insns, None),
            Err(e) => (Vec::new(), Some(format!("{e}"))),
        },
        DisasmTarget::Arm { thumb } => disasm_arm(code, thumb),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn disasm_arm(code: &[u8], thumb: bool) -> (Vec<DisasmInsn>, Option<String>) {
    use yaxpeax_arch::Decoder as _;

    let decoder: yaxpeax_arm::armv7::InstDecoder = if thumb {
        yaxpeax_arm::armv7::InstDecoder::default_thumb()
    } else {
        yaxpeax_arm::armv7::InstDecoder::default()
    };
    let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(code);
    let mut out: Vec<DisasmInsn> = Vec::new();
    let mut note: Option<String> = None;
    loop {
        let before: usize = usize::try_from(<yaxpeax_arch::U8Reader<'_> as yaxpeax_arch::Reader<
            u32,
            u8,
        >>::total_offset(&mut reader))
        .unwrap_or(usize::MAX);
        if before >= code.len() {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(inst) => {
                let after: usize =
                    usize::try_from(<yaxpeax_arch::U8Reader<'_> as yaxpeax_arch::Reader<
                        u32,
                        u8,
                    >>::total_offset(&mut reader))
                    .unwrap_or(before);
                let raw: Vec<u8> = code
                    .get(before..after)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
                let text: String = inst.to_string();
                let (mnemonic, operands): (String, String) = split_text(&text);
                out.push(DisasmInsn {
                    address: before as u64,
                    bytes: raw,
                    mnemonic,
                    operands,
                });
            }
            Err(e) => {
                note = Some(format!(
                    "{} decode stopped at offset {before}/{}: {e}",
                    if thumb { "thumb" } else { "arm" },
                    code.len()
                ));
                break;
            }
        }
    }
    (out, note)
}

#[cfg(not(target_arch = "wasm32"))]
fn split_text(text: &str) -> (String, String) {
    match text.split_once([' ', '\t']) {
        Some((m, ops)) => (m.to_owned(), ops.trim().to_owned()),
        None => (text.to_owned(), String::new()),
    }
}

fn read_qstr(reader: &mut Reader<'_>) -> Result<String> {
    let header: u64 = reader.uint()?;
    if header & 1 == 1 {
        return Ok(format!("<static-qstr#{}>", header >> 1));
    }
    let len: usize = usize::try_from(header >> 1).unwrap_or(0);
    let raw: &[u8] = reader.take(len)?;
    let text: String = String::from_utf8_lossy(raw).into_owned();
    reader.byte()?;
    Ok(text)
}

const OBJ_FUN_TABLE: u8 = 0;
const OBJ_NONE: u8 = 1;
const OBJ_FALSE: u8 = 2;
const OBJ_TRUE: u8 = 3;
const OBJ_ELLIPSIS: u8 = 4;
const OBJ_STR: u8 = 5;
const OBJ_BYTES: u8 = 6;
const OBJ_INT: u8 = 7;
const OBJ_FLOAT: u8 = 8;
const OBJ_COMPLEX: u8 = 9;
const OBJ_TUPLE: u8 = 10;

const MAX_OBJ_NESTING: u8 = 64;

fn skip_obj(reader: &mut Reader<'_>, depth: u8) -> Result<()> {
    if depth > MAX_OBJ_NESTING {
        return Err(AltRuntimeError::BadEncoding {
            field: "obj_table_nesting",
            offset: reader.pos,
        });
    }
    let obj_type: u8 = reader.byte()?;
    match obj_type {
        OBJ_FUN_TABLE | OBJ_NONE | OBJ_FALSE | OBJ_TRUE | OBJ_ELLIPSIS => Ok(()),
        OBJ_STR | OBJ_BYTES | OBJ_INT | OBJ_FLOAT | OBJ_COMPLEX => {
            let len: usize = usize::try_from(reader.uint()?).unwrap_or(0);
            reader.take(len)?;
            if matches!(obj_type, OBJ_STR | OBJ_BYTES) {
                reader.byte()?;
            }
            Ok(())
        }
        OBJ_TUPLE => {
            let len: u64 = reader.uint()?;
            for _ in 0..len {
                skip_obj(reader, depth.saturating_add(1))?;
            }
            Ok(())
        }
        _ => Err(AltRuntimeError::BadEncoding {
            field: "obj_table",
            offset: reader.pos,
        }),
    }
}

fn first_native_machine_code(function: &NativeFunction) -> Vec<u8> {
    if function.kind.is_native() {
        return function.machine_code.clone();
    }
    for child in &function.children {
        let found: Vec<u8> = first_native_machine_code(child);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn first_native_kind(function: &NativeFunction) -> Option<CodeKind> {
    if function.kind.is_native() {
        return Some(function.kind);
    }
    function.children.iter().find_map(first_native_kind)
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == MPY_MAGIC
        && (MIN_NATIVE_VERSION..=MAX_NATIVE_VERSION).contains(&bytes[1])
        && !matches!(decode_arch(bytes[2]), NativeArch::None)
}

const fn decode_arch(features: u8) -> NativeArch {
    match (features >> 2) & 0x0f {
        0 => NativeArch::None,
        1 => NativeArch::X86,
        2 => NativeArch::X64,
        3 => NativeArch::Armv6,
        4 => NativeArch::Armv6m,
        5 => NativeArch::Armv7m,
        6 => NativeArch::Armv7em,
        7 => NativeArch::Armv7emSp,
        8 => NativeArch::Armv7emDp,
        9 => NativeArch::Xtensa,
        10 => NativeArch::XtensaWin,
        11 => NativeArch::Rv32imc,
        12 => NativeArch::Rv64imc,
        _ => NativeArch::Unknown,
    }
}

#[must_use]
pub fn count_functions(function: &NativeFunction) -> usize {
    1 + function.children.iter().map(count_functions).sum::<usize>()
}

#[must_use]
pub fn total_instructions(function: &NativeFunction) -> usize {
    function.disassembly.len()
        + function
            .children
            .iter()
            .map(total_instructions)
            .sum::<usize>()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn build_native_py_module(arch_id: u8, machine: &[u8], prelude: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = vec![MPY_MAGIC, 6, arch_id << 2, 31, 0, 0];
        let fun_data_len: u64 = (machine.len() + prelude.len()) as u64;
        let native_py_low_bits: u64 = 1;
        let kind_len: u64 = (fun_data_len << 3) | native_py_low_bits;
        push_uint(&mut out, kind_len);
        out.extend_from_slice(machine);
        out.extend_from_slice(prelude);
        push_uint(&mut out, machine.len() as u64);
        out
    }

    fn push_uint(out: &mut Vec<u8>, mut value: u64) {
        let mut buf: Vec<u8> = Vec::new();
        buf.push((value & 0x7f) as u8);
        value >>= 7;
        while value != 0 {
            buf.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        buf.reverse();
        out.extend_from_slice(&buf);
    }

    #[test]
    fn varint_roundtrips() {
        for v in [0u64, 1, 127, 128, 308, 16384, 1_000_000] {
            let mut buf: Vec<u8> = Vec::new();
            push_uint(&mut buf, v);
            let mut r: Reader<'_> = Reader::new(&buf);
            assert_eq!(r.uint().expect("uint"), v);
        }
    }

    #[test]
    fn parses_x64_native_py_and_disassembles() {
        let machine: [u8; 4] = [0x55, 0x48, 0x89, 0xE5];
        let module: MicroPythonNativeModule =
            parse(&build_native_py_module(2, &machine, &[0u8, 0u8, 0u8])).expect("parse");
        assert_eq!(module.arch, NativeArch::X64);
        assert_eq!(module.function.kind, CodeKind::NativePy);
        assert_eq!(module.function.machine_code, machine.to_vec());
        assert_eq!(module.function.prelude_offset, 4);
        assert!(!module.function.disassembly.is_empty());
        assert_eq!(module.function.disassembly[0].mnemonic, "push");
        assert!(module.function.disasm_note.is_none());
    }

    #[test]
    fn machine_code_excludes_prelude_tail() {
        let machine: [u8; 2] = [0x90, 0xC3];
        let prelude: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let module: MicroPythonNativeModule =
            parse(&build_native_py_module(2, &machine, &prelude)).expect("parse");
        assert_eq!(module.function.machine_code, machine.to_vec());
        assert_eq!(module.function.machine_code.len(), 2);
    }

    #[test]
    fn rejects_bytecode_arch_zero() {
        let bytes: [u8; 6] = [MPY_MAGIC, 6, 0x00, 31, 6, 0];
        let err: AltRuntimeError = parse(&bytes).expect_err("must reject bytecode");
        assert!(matches!(err, AltRuntimeError::NotDetected(_)));
    }

    #[test]
    fn detect_rejects_bytecode_accepts_native() {
        let bytecode: [u8; 6] = [MPY_MAGIC, 6, 0x00, 31, 6, 0];
        assert!(!detect(&bytecode));
        let native: [u8; 6] = [MPY_MAGIC, 6, 0x0b, 31, 6, 0];
        assert!(detect(&native));
    }

    #[test]
    fn arch_decode_matches_micropython_enum() {
        assert_eq!(decode_arch(1 << 2), NativeArch::X86);
        assert_eq!(decode_arch(2 << 2), NativeArch::X64);
        assert_eq!(decode_arch(5 << 2), NativeArch::Armv7m);
        assert_eq!(decode_arch(0), NativeArch::None);
    }

    #[test]
    fn skip_obj_deep_tuple_nesting_returns_err_not_stack_overflow() {
        let mut payload: Vec<u8> = Vec::new();
        for _ in 0..512 {
            payload.push(OBJ_TUPLE);
            payload.push(0x01);
        }
        payload.push(OBJ_NONE);
        let mut reader: Reader<'_> = Reader::new(&payload);
        let err: AltRuntimeError = skip_obj(&mut reader, 0).expect_err("must bound recursion");
        assert!(matches!(err, AltRuntimeError::BadEncoding { .. }));
    }

    fn native_header(arch_id: u8) -> Vec<u8> {
        vec![MPY_MAGIC, 6, arch_id << 2, 31]
    }

    #[test]
    fn huge_n_qstr_rejected_before_allocation() {
        let mut bytes: Vec<u8> = native_header(2);
        push_uint(&mut bytes, u64::MAX);
        push_uint(&mut bytes, 0u64);
        let err: AltRuntimeError =
            parse(&bytes).expect_err("declared qstr count exceeding input must be rejected");
        assert!(
            matches!(
                err,
                AltRuntimeError::BadEncoding {
                    field: "n_qstr",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn huge_n_obj_rejected_before_allocation() {
        let mut bytes: Vec<u8> = native_header(2);
        push_uint(&mut bytes, 0u64);
        push_uint(&mut bytes, u64::MAX);
        let err: AltRuntimeError =
            parse(&bytes).expect_err("declared object count exceeding input must be rejected");
        assert!(
            matches!(err, AltRuntimeError::BadEncoding { field: "n_obj", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn huge_child_count_rejected_before_allocation() {
        let mut bytes: Vec<u8> = native_header(2);
        push_uint(&mut bytes, 0u64);
        push_uint(&mut bytes, 0u64);
        let has_children_native_py: u64 = 0b101;
        push_uint(&mut bytes, has_children_native_py);
        push_uint(&mut bytes, 0u64);
        push_uint(&mut bytes, u64::MAX);
        let err: AltRuntimeError =
            parse(&bytes).expect_err("declared child count exceeding input must be rejected");
        assert!(
            matches!(
                err,
                AltRuntimeError::BadEncoding {
                    field: "raw_code_children",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn valid_native_module_still_parses_after_count_bounds() {
        let machine: [u8; 4] = [0x55, 0x48, 0x89, 0xE5];
        let module: MicroPythonNativeModule =
            parse(&build_native_py_module(2, &machine, &[0u8, 0u8, 0u8])).expect("valid parse");
        assert_eq!(module.function.machine_code, machine.to_vec());
        assert!(!module.function.disassembly.is_empty());
    }

    #[test]
    fn adversarial_and_random_headers_never_panic() {
        let mut probes: Vec<Vec<u8>> = Vec::new();
        for extra in [0usize, 1, 2, 3, 7, 33, 200] {
            let mut b: Vec<u8> = native_header(2);
            push_uint(&mut b, u64::MAX);
            push_uint(&mut b, u64::MAX);
            b.extend(std::iter::repeat_n(0x01u8, extra));
            probes.push(b);
        }
        for arch_id in 0u8..=15 {
            let mut b: Vec<u8> = native_header(arch_id);
            push_uint(&mut b, 4u64);
            push_uint(&mut b, 4u64);
            b.extend(std::iter::repeat_n(0xFFu8, 64));
            probes.push(b);
        }
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..2000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len: usize = (state as usize) % 384;
            let bytes: Vec<u8> = (0..len)
                .map(|i: usize| (state.rotate_left(i as u32 & 63) & 0xff) as u8)
                .collect();
            probes.push(bytes);
        }
        for probe in &probes {
            let result: std::thread::Result<()> =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = detect(probe);
                    let _ = parse(probe);
                }));
            assert!(result.is_ok(), "native parse unwound on probe {probe:?}");
        }
    }
}
