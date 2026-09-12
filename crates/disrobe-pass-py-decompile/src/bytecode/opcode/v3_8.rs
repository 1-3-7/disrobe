use crate::bytecode::opcode::{
    CanonicalOp, JumpKind, OpcodeFamily, OpcodeMap, shared_cache_size, shared_decode,
    shared_family, shared_has_arg, shared_jump_kind, shared_opname,
};
use crate::bytecode::version::PyVersion;

#[derive(Debug)]
pub struct V38OpcodeMap;

impl OpcodeMap for V38OpcodeMap {
    fn version(&self) -> PyVersion {
        PyVersion::V3_8
    }

    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp {
        shared_decode(&PyVersion::V3_8, raw, arg)
    }

    fn cache_size(&self, op: u8) -> u8 {
        shared_cache_size(&PyVersion::V3_8, op)
    }

    fn has_arg(&self) -> u8 {
        shared_has_arg(&PyVersion::V3_8)
    }

    fn opname(&self, op: u8) -> &'static str {
        shared_opname(&PyVersion::V3_8, op)
    }

    fn jump_kind(&self, op: u8) -> JumpKind {
        shared_jump_kind(&PyVersion::V3_8, op)
    }

    fn family(&self, op: u8) -> OpcodeFamily {
        shared_family(&PyVersion::V3_8, op)
    }
}
