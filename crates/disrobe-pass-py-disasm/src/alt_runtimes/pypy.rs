use disrobe_py_marshal::PyVersion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::alt_runtimes::{AltRuntimeError, Result};

const PYPY_MAGIC_27: u32 = 0xC0DE_F517;
const PYPY_MAGIC_310: u32 = 0xC0DE_F511;
const PYPY_MAGIC_311: u32 = 0xC0DE_F512;
const PYPY_MAGIC_312: u32 = 0xC0DE_F513;

const OP_JUMP_IF_NOT_DEBUG: u8 = 204;
const OP_BUILD_LIST_FROM_ARG: u8 = 203;
const OP_LOAD_REVDB_VAR: u8 = 205;
const OP_LOOKUP_METHOD: u8 = 201;
const OP_CALL_METHOD: u8 = 202;
const OP_CALL_METHOD_KW: u8 = 206;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PyPyVariant {
    PyPy27,
    PyPy37,
    PyPy38,
    PyPy39,
    PyPy310,
    PyPy311,
    PyPy312,
}

impl PyPyVariant {
    #[must_use]
    pub const fn cpython_compat(self) -> PyVersion {
        match self {
            Self::PyPy27 => PyVersion::PY27,
            Self::PyPy37 => PyVersion::PY37,
            Self::PyPy38 => PyVersion::PY38,
            Self::PyPy39 => PyVersion::PY39,
            Self::PyPy310 => PyVersion::PY310,
            Self::PyPy311 => PyVersion::PY311,
            Self::PyPy312 => PyVersion::PY312,
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
        PYPY_MAGIC_310 => Some(PyPyVariant::PyPy37),
        PYPY_MAGIC_311 => Some(PyPyVariant::PyPy39),
        PYPY_MAGIC_312 => Some(PyPyVariant::PyPy310),
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
    fn parses_pypy310_header_and_payload() {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&PYPY_MAGIC_310.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[OP_LOOKUP_METHOD, 0, OP_CALL_METHOD, 1, 100, 0]);
        let module: PyPyModule = parse(&bytes).expect("parse pypy");
        assert_eq!(module.variant, PyPyVariant::PyPy37);
        assert_eq!(module.payload.len(), 6);
        assert_eq!(module.private_opcode_total(), 2);
    }

    #[test]
    fn detects_pypy_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(&PYPY_MAGIC_311.to_le_bytes());
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
        bytes.extend_from_slice(&PYPY_MAGIC_310.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        bytes.extend_from_slice(&[OP_BUILD_LIST_FROM_ARG, 2]);
        let module: PyPyModule = parse(&bytes).expect("parse pypy");
        let insns: Vec<OpInsn> = module.opcodes().collect();
        assert_eq!(insns.len(), 1);
        assert!(insns[0].is_private);
    }

    #[test]
    fn cpython_compat_mapping() {
        assert_eq!(PyPyVariant::PyPy310.cpython_compat(), PyVersion::PY310);
        assert_eq!(PyPyVariant::PyPy27.cpython_compat(), PyVersion::PY27);
    }
}
