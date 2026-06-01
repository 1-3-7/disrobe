use crate::bytecode::opcode::{
    CanonicalOp, JumpKind, OpcodeFamily, OpcodeMap, shared_cache_size, shared_decode,
    shared_family, shared_has_arg, shared_jump_kind, shared_opname,
};
use crate::bytecode::version::PyVersion;

#[derive(Debug)]
pub struct V13OpcodeMap;

impl OpcodeMap for V13OpcodeMap {
    fn version(&self) -> PyVersion {
        PyVersion::V1_3
    }

    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp {
        shared_decode(&PyVersion::V1_3, raw, arg)
    }

    fn cache_size(&self, op: u8) -> u8 {
        shared_cache_size(&PyVersion::V1_3, op)
    }

    fn has_arg(&self) -> u8 {
        shared_has_arg(&PyVersion::V1_3)
    }

    fn opname(&self, op: u8) -> &'static str {
        shared_opname(&PyVersion::V1_3, op)
    }

    fn jump_kind(&self, op: u8) -> JumpKind {
        shared_jump_kind(&PyVersion::V1_3, op)
    }

    fn family(&self, op: u8) -> OpcodeFamily {
        shared_family(&PyVersion::V1_3, op)
    }
}
