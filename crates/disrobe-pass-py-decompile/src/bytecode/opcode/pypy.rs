use crate::bytecode::opcode::{CanonicalOp, JumpKind, OpcodeFamily, OpcodeMap};
use crate::bytecode::version::PyVersion;

#[derive(Debug)]
pub struct PyPyOpcodeMap {
    pub base: Box<dyn OpcodeMap>,
}

const PYPY_LOOKUP_METHOD: u8 = 201;
const PYPY_CALL_METHOD: u8 = 202;
const PYPY_BUILD_LIST_FROM_ARG: u8 = 203;
const PYPY_JUMP_IF_NOT_DEBUG: u8 = 204;
const PYPY_LOAD_REVDB_VAR: u8 = 205;
const PYPY_CALL_METHOD_KW: u8 = 206;

impl OpcodeMap for PyPyOpcodeMap {
    fn version(&self) -> PyVersion {
        PyVersion::PyPy(Box::new(self.base.version()))
    }

    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp {
        match raw {
            PYPY_LOOKUP_METHOD => CanonicalOp::LoadAttr(arg),
            PYPY_CALL_METHOD => CanonicalOp::CallFunction(u8::try_from(arg & 0xFF).unwrap_or(0)),
            PYPY_CALL_METHOD_KW => {
                CanonicalOp::CallFunctionKw(u8::try_from(arg & 0xFF).unwrap_or(0))
            }
            PYPY_BUILD_LIST_FROM_ARG => CanonicalOp::BuildList(arg),
            PYPY_JUMP_IF_NOT_DEBUG => CanonicalOp::JumpForward(i32::try_from(arg).unwrap_or(0)),
            PYPY_LOAD_REVDB_VAR => CanonicalOp::LoadName(arg),
            _ => self.base.decode(raw, arg),
        }
    }

    fn cache_size(&self, op: u8) -> u8 {
        self.base.cache_size(op)
    }

    fn has_arg(&self) -> u8 {
        self.base.has_arg()
    }

    fn opname(&self, op: u8) -> &'static str {
        match op {
            PYPY_LOOKUP_METHOD => "LOOKUP_METHOD",
            PYPY_CALL_METHOD => "CALL_METHOD",
            PYPY_CALL_METHOD_KW => "CALL_METHOD_KW",
            PYPY_BUILD_LIST_FROM_ARG => "BUILD_LIST_FROM_ARG",
            PYPY_JUMP_IF_NOT_DEBUG => "JUMP_IF_NOT_DEBUG",
            PYPY_LOAD_REVDB_VAR => "LOAD_REVDB_VAR",
            _ => self.base.opname(op),
        }
    }

    fn jump_kind(&self, op: u8) -> JumpKind {
        match op {
            PYPY_JUMP_IF_NOT_DEBUG => JumpKind::Relative,
            _ => self.base.jump_kind(op),
        }
    }

    fn family(&self, op: u8) -> OpcodeFamily {
        match op {
            PYPY_LOOKUP_METHOD | PYPY_LOAD_REVDB_VAR => OpcodeFamily::Load,
            PYPY_CALL_METHOD | PYPY_CALL_METHOD_KW => OpcodeFamily::Call,
            PYPY_BUILD_LIST_FROM_ARG => OpcodeFamily::BuildCollection,
            PYPY_JUMP_IF_NOT_DEBUG => OpcodeFamily::Jump,
            _ => self.base.family(op),
        }
    }
}
