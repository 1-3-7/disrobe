use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::alt_runtimes::{AltRuntimeError, Result, validate_input_size};
use crate::{Instruction, disassemble, opname, render_dis};

const PYPY_MAGIC_27: u32 = 0xC0DE_F517;
const PYPY_MAGIC_37: u32 = 0xC0DE_F511;
const PYPY_MAGIC_39: u32 = 0xC0DE_F512;
const PYPY_MAGIC_310: u32 = 0xC0DE_F513;

const OP_JUMP_IF_NOT_DEBUG: u8 = 204;
const OP_BUILD_LIST_FROM_ARG: u8 = 203;
const OP_LOAD_REVDB_VAR: u8 = 205;
const OP_LOOKUP_METHOD: u8 = 201;
const OP_CALL_METHOD: u8 = 202;
const OP_CALL_METHOD_KW: u8 = 206;
const MAX_CODE_UNITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PyPyVariant {
    PyPy27,
    PyPy37,
    PyPy39,
    PyPy310,
}

impl PyPyVariant {
    #[must_use]
    pub const fn cpython_compat(self) -> PyVersion {
        match self {
            Self::PyPy27 => PyVersion::PY27,
            Self::PyPy37 => PyVersion::PY37,
            Self::PyPy39 => PyVersion::PY39,
            Self::PyPy310 => PyVersion::PY310,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PyPyModule {
    pub variant: PyPyVariant,
    pub magic: u32,
    pub header_len: usize,
    pub payload: Vec<u8>,
    pub private_opcode_hits: BTreeMap<u8, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpInsn {
    pub offset: usize,
    pub opcode: u8,
    pub is_private: bool,
}

pub fn parse(bytes: &[u8]) -> Result<PyPyModule> {
    validate_input_size(bytes, "pypy")?;
    if bytes.len() < 4 {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: 4,
            had: bytes.len(),
        });
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let variant: PyPyVariant = variant_for_magic(magic).ok_or(AltRuntimeError::BadMagic {
        runtime: "pypy",
        got: magic,
    })?;
    let header_len: usize = if matches!(variant, PyPyVariant::PyPy27) {
        8
    } else {
        16
    };
    if bytes.len() < header_len {
        return Err(AltRuntimeError::Truncated {
            offset: 0,
            needed: header_len,
            had: bytes.len(),
        });
    }
    let payload: Vec<u8> = bytes[header_len..].to_vec();
    let private_opcode_hits: BTreeMap<u8, u32> = scan_private_opcodes(&payload);
    Ok(PyPyModule {
        variant,
        magic,
        header_len,
        payload,
        private_opcode_hits,
    })
}

#[must_use]
pub fn detect(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    variant_for_magic(magic).is_some()
}

#[must_use]
const fn variant_for_magic(magic: u32) -> Option<PyPyVariant> {
    match magic {
        PYPY_MAGIC_27 => Some(PyPyVariant::PyPy27),
        PYPY_MAGIC_37 => Some(PyPyVariant::PyPy37),
        PYPY_MAGIC_39 => Some(PyPyVariant::PyPy39),
        PYPY_MAGIC_310 => Some(PyPyVariant::PyPy310),
        _ => None,
    }
}

impl PyPyModule {
    pub fn opcodes(&self) -> impl Iterator<Item = OpInsn> + '_ {
        let payload: &Vec<u8> = &self.payload;
        let step: usize = if self.variant == PyPyVariant::PyPy27 {
            1
        } else {
            2
        };
        (0..payload.len())
            .step_by(step)
            .filter_map(move |off: usize| -> Option<OpInsn> {
                let opcode: u8 = *payload.get(off)?;
                Some(OpInsn {
                    offset: off,
                    opcode,
                    is_private: is_private_opcode(opcode),
                })
            })
    }

    #[must_use]
    pub fn private_opcode_total(&self) -> u32 {
        self.private_opcode_hits.values().copied().sum()
    }

    #[must_use]
    pub const fn compat_version(&self) -> PyVersion {
        self.variant.cpython_compat()
    }

    #[must_use]
    pub fn disassemble(&self) -> PyPyDisasm {
        let version: PyVersion = self.compat_version();
        if let Ok(Object::Code(code)) = load(&self.payload, version) {
            let mut units: Vec<PyPyCodeUnit> = Vec::new();
            disassemble_code_tree(code.as_ref(), "<module>", version, 0, &mut units);
            let total: usize = units
                .iter()
                .map(|u: &PyPyCodeUnit| u.instructions.len())
                .sum();
            return PyPyDisasm {
                variant: self.variant,
                compat_version: version,
                marshaled_code: true,
                units,
                instruction_count: total,
            };
        }
        let linear: Vec<PyPyLinearOp> = self.linear_listing(version);
        let count: usize = linear.len();
        PyPyDisasm {
            variant: self.variant,
            compat_version: version,
            marshaled_code: false,
            units: vec![PyPyCodeUnit {
                qualified_name: "<raw-bytecode>".to_owned(),
                depth: 0,
                instructions: Vec::new(),
                raw_listing: linear,
            }],
            instruction_count: count,
        }
    }

    fn linear_listing(&self, version: PyVersion) -> Vec<PyPyLinearOp> {
        let step: usize = if matches!(self.variant, PyPyVariant::PyPy27) {
            1
        } else {
            2
        };
        let mut out: Vec<PyPyLinearOp> = Vec::with_capacity(self.payload.len() / step.max(1));
        let mut offset: usize = 0usize;
        while offset < self.payload.len() {
            let opcode: u8 = self.payload[offset];
            let mnemonic: &'static str = if is_private_opcode(opcode) {
                private_opname(opcode)
            } else {
                opname(opcode, version)
            };
            let arg: Option<u8> = if step == 2 {
                self.payload.get(offset + 1).copied()
            } else {
                None
            };
            out.push(PyPyLinearOp {
                offset,
                opcode,
                mnemonic: mnemonic.to_owned(),
                arg,
                is_private: is_private_opcode(opcode),
            });
            offset += step;
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PyPyDisasm {
    pub variant: PyPyVariant,
    pub compat_version: PyVersion,
    pub marshaled_code: bool,
    pub units: Vec<PyPyCodeUnit>,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PyPyCodeUnit {
    pub qualified_name: String,
    pub depth: usize,
    pub instructions: Vec<Instruction>,
    pub raw_listing: Vec<PyPyLinearOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PyPyLinearOp {
    pub offset: usize,
    pub opcode: u8,
    pub mnemonic: String,
    pub arg: Option<u8>,
    pub is_private: bool,
}

impl PyPyDisasm {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::new();
        crate::push_string_line(
            &mut out,
            format_args!(
                "; pypy {} (cpython-compat {}.{}, {})",
                variant_label(self.variant),
                self.compat_version.major,
                self.compat_version.minor,
                if self.marshaled_code {
                    "marshaled code object"
                } else {
                    "raw interp-level bytecode"
                },
            ),
        );
        for unit in &self.units {
            let indent: String = "  ".repeat(unit.depth);
            if self.marshaled_code {
                crate::push_string_line(
                    &mut out,
                    format_args!("\n{indent}; code {}", unit.qualified_name),
                );
                for line in render_dis(&unit.instructions).lines() {
                    crate::push_string_line(&mut out, format_args!("{indent}{line}"));
                }
            } else {
                for op in &unit.raw_listing {
                    match op.arg {
                        Some(a) => {
                            crate::push_string_line(
                                &mut out,
                                format_args!("{:>6} {:<24} {a}", op.offset, op.mnemonic),
                            );
                        }
                        None => {
                            crate::push_string_line(
                                &mut out,
                                format_args!("{:>6} {}", op.offset, op.mnemonic),
                            );
                        }
                    }
                }
            }
        }
        out
    }
}

fn disassemble_code_tree(
    code: &CodeObject,
    qualified_name: &str,
    version: PyVersion,
    depth: usize,
    out: &mut Vec<PyPyCodeUnit>,
) {
    let mut pending: Vec<(&CodeObject, String, usize)> =
        vec![(code, qualified_name.to_owned(), depth)];
    while let Some((current, current_name, current_depth)) = pending.pop() {
        if out.len() == MAX_CODE_UNITS {
            break;
        }
        let instructions: Vec<Instruction> = disassemble(current, version);
        out.push(PyPyCodeUnit {
            qualified_name: current_name.clone(),
            depth: current_depth,
            instructions,
            raw_listing: Vec::new(),
        });
        for konst in current.consts.iter().rev() {
            if pending.len().saturating_add(out.len()) == MAX_CODE_UNITS {
                break;
            }
            if let Object::Code(inner) = konst {
                let inner_ref: &CodeObject = inner.as_ref();
                let child_name: String = format!("{current_name}.{}", code_object_name(inner_ref));
                let child_depth: usize = current_depth.saturating_add(1usize);
                pending.push((inner_ref, child_name, child_depth));
            }
        }
    }
}

fn code_object_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => "<anonymous>".to_owned(),
    }
}

const fn variant_label(variant: PyPyVariant) -> &'static str {
    match variant {
        PyPyVariant::PyPy27 => "2.7",
        PyPyVariant::PyPy37 => "3.7",
        PyPyVariant::PyPy39 => "3.9",
        PyPyVariant::PyPy310 => "3.10",
    }
}

const fn private_opname(op: u8) -> &'static str {
    match op {
        OP_LOOKUP_METHOD => "LOOKUP_METHOD",
        OP_CALL_METHOD => "CALL_METHOD",
        OP_BUILD_LIST_FROM_ARG => "BUILD_LIST_FROM_ARG",
        OP_JUMP_IF_NOT_DEBUG => "JUMP_IF_NOT_DEBUG",
        OP_LOAD_REVDB_VAR => "LOAD_REVDB_VAR",
        OP_CALL_METHOD_KW => "CALL_METHOD_KW",
        _ => "<pypy-private>",
    }
}

#[must_use]
pub const fn is_private_opcode(op: u8) -> bool {
    matches!(
        op,
        OP_JUMP_IF_NOT_DEBUG
            | OP_BUILD_LIST_FROM_ARG
            | OP_LOAD_REVDB_VAR
            | OP_LOOKUP_METHOD
            | OP_CALL_METHOD
            | OP_CALL_METHOD_KW
    )
}

fn scan_private_opcodes(payload: &[u8]) -> BTreeMap<u8, u32> {
    let mut hits: BTreeMap<u8, u32> = BTreeMap::new();
    let mut cursor: usize = 0usize;
    while cursor < payload.len() {
        let op: u8 = payload[cursor];
        if is_private_opcode(op) {
            *hits.entry(op).or_insert(0u32) += 1u32;
        }
        cursor += 2;
    }
    hits
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_pypy37_header_and_payload() {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&PYPY_MAGIC_37.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[OP_LOOKUP_METHOD, 0, OP_CALL_METHOD, 1, 100, 0]);
        let module: PyPyModule = parse(&bytes).expect("parse pypy");
        assert_eq!(module.variant, PyPyVariant::PyPy37);
        assert_eq!(module.compat_version(), PyVersion::PY37);
        assert_eq!(module.payload.len(), 6);
        assert_eq!(module.private_opcode_total(), 2);
    }

    #[test]
    fn detects_pypy_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(&PYPY_MAGIC_39.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        assert!(detect(&bytes));
    }

    #[test]
    fn rejects_garbage_magic() {
        let bytes: [u8; 16] = [0u8; 16];
        let err: AltRuntimeError = parse(&bytes).expect_err("must reject");
        assert!(matches!(err, AltRuntimeError::BadMagic { .. }));
    }

    #[test]
    fn opcodes_iterator_marks_private() {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&PYPY_MAGIC_37.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[OP_BUILD_LIST_FROM_ARG, 2]);
        let module: PyPyModule = parse(&bytes).expect("parse pypy");
        let insns: Vec<OpInsn> = module.opcodes().collect();
        assert_eq!(insns.len(), 1);
        assert!(insns[0].is_private);
    }

    #[test]
    fn rejects_input_above_parse_cap() {
        let mut bytes: Vec<u8> = build_pypy_image(PYPY_MAGIC_37, 16, &[]);
        bytes.resize(16 * 1024 * 1024 + 17, 0u8);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn magic_to_variant_matches_ground_truth() {
        assert_eq!(variant_for_magic(PYPY_MAGIC_27), Some(PyPyVariant::PyPy27));
        assert_eq!(variant_for_magic(PYPY_MAGIC_37), Some(PyPyVariant::PyPy37));
        assert_eq!(variant_for_magic(PYPY_MAGIC_39), Some(PyPyVariant::PyPy39));
        assert_eq!(
            variant_for_magic(PYPY_MAGIC_310),
            Some(PyPyVariant::PyPy310)
        );
        assert_eq!(variant_for_magic(0xDEAD_BEEF), None);
    }

    #[test]
    fn cpython_compat_mapping() {
        assert_eq!(PyPyVariant::PyPy27.cpython_compat(), PyVersion::PY27);
        assert_eq!(PyPyVariant::PyPy37.cpython_compat(), PyVersion::PY37);
        assert_eq!(PyPyVariant::PyPy39.cpython_compat(), PyVersion::PY39);
        assert_eq!(PyPyVariant::PyPy310.cpython_compat(), PyVersion::PY310);
    }

    struct TableProbe {
        magic: u32,
        header_len: usize,
        variant: PyPyVariant,
        version: PyVersion,
        byte: u8,
        mnemonic: &'static str,
        mislabel_version: PyVersion,
    }

    fn build_pypy_image(magic: u32, header_len: usize, payload: &[u8]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(header_len + payload.len());
        bytes.extend_from_slice(&magic.to_le_bytes());
        bytes.resize(header_len, 0u8);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn magic_selects_version_specific_opcode_table() {
        let probes: [TableProbe; 4] = [
            TableProbe {
                magic: PYPY_MAGIC_27,
                header_len: 8,
                variant: PyPyVariant::PyPy27,
                version: PyVersion::PY27,
                byte: 71,
                mnemonic: "PRINT_ITEM",
                mislabel_version: PyVersion::PY37,
            },
            TableProbe {
                magic: PYPY_MAGIC_37,
                header_len: 16,
                variant: PyPyVariant::PyPy37,
                version: PyVersion::PY37,
                byte: 149,
                mnemonic: "BUILD_LIST_UNPACK",
                mislabel_version: PyVersion::PY39,
            },
            TableProbe {
                magic: PYPY_MAGIC_39,
                header_len: 16,
                variant: PyPyVariant::PyPy39,
                version: PyVersion::PY39,
                byte: 48,
                mnemonic: "RERAISE",
                mislabel_version: PyVersion::PY37,
            },
            TableProbe {
                magic: PYPY_MAGIC_310,
                header_len: 16,
                variant: PyPyVariant::PyPy310,
                version: PyVersion::PY310,
                byte: 30,
                mnemonic: "GET_LEN",
                mislabel_version: PyVersion::PY39,
            },
        ];
        for probe in &probes {
            let image: Vec<u8> = build_pypy_image(probe.magic, probe.header_len, &[probe.byte, 0]);
            let module: PyPyModule = parse(&image).expect("parse pypy image");
            assert_eq!(module.variant, probe.variant);
            assert_eq!(module.compat_version(), probe.version);
            let disasm: PyPyDisasm = module.disassemble();
            assert!(!disasm.marshaled_code);
            assert_eq!(disasm.compat_version, probe.version);
            let first: &PyPyLinearOp = &disasm.units[0].raw_listing[0];
            assert_eq!(first.opcode, probe.byte);
            assert_eq!(first.mnemonic, probe.mnemonic);
            assert_ne!(opname(probe.byte, probe.mislabel_version), probe.mnemonic);
        }
    }
}
