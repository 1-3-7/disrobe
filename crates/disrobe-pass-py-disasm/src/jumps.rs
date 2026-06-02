//! Per-version jump-target resolution mirroring `CPython` `dis`: relative vs absolute, forward vs
//! backward, with the correct argument scale and inline-cache accounting.

#![allow(clippy::redundant_pub_crate)]

use disrobe_py_marshal::PyVersion;

const WORDCODE_INSTRUCTION_SIZE: u32 = 2;
const LEGACY_INSTRUCTION_SIZE: u32 = 3;
const CACHE_ENTRY_SIZE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JumpKind {
    RelativeForward,
    RelativeBackward,
    Absolute,
    None,
}

/// Classifies an opcode's jump behaviour for the given version, so the disassembler can resolve
/// the destination offset exactly as `CPython`'s `dis` does (relative/absolute, forward/backward,
/// with the per-version argument scale).
#[must_use]
pub(crate) fn jump_kind(opname: &str, version: PyVersion) -> JumpKind {
    if version.major == 3 && version.minor >= 11 {
        match opname {
            "JUMP_BACKWARD"
            | "JUMP_BACKWARD_NO_INTERRUPT"
            | "JUMP_BACKWARD_QUICK"
            | "POP_JUMP_BACKWARD_IF_FALSE"
            | "POP_JUMP_BACKWARD_IF_TRUE"
            | "POP_JUMP_BACKWARD_IF_NONE"
            | "POP_JUMP_BACKWARD_IF_NOT_NONE" => JumpKind::RelativeBackward,
            "FOR_ITER"
            | "JUMP"
            | "JUMP_FORWARD"
            | "JUMP_NO_INTERRUPT"
            | "SEND"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_TRUE"
            | "POP_JUMP_IF_NONE"
            | "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_FORWARD_IF_FALSE"
            | "POP_JUMP_FORWARD_IF_TRUE"
            | "POP_JUMP_FORWARD_IF_NONE"
            | "POP_JUMP_FORWARD_IF_NOT_NONE"
            | "JUMP_IF_FALSE_OR_POP"
            | "JUMP_IF_TRUE_OR_POP" => JumpKind::RelativeForward,
            _ => JumpKind::None,
        }
    } else {
        match opname {
            "FOR_ITER" | "JUMP_FORWARD" | "SETUP_FINALLY" | "SETUP_WITH" | "SETUP_ASYNC_WITH"
            | "SETUP_LOOP" | "SETUP_EXCEPT" | "CALL_FINALLY" | "FOR_LOOP" => {
                JumpKind::RelativeForward
            }
            "JUMP_ABSOLUTE"
            | "JUMP_IF_FALSE_OR_POP"
            | "JUMP_IF_TRUE_OR_POP"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_TRUE"
            | "JUMP_IF_NOT_EXC_MATCH"
            | "JUMP_IF_FALSE"
            | "JUMP_IF_TRUE"
            | "CONTINUE_LOOP" => JumpKind::Absolute,
            _ => JumpKind::None,
        }
    }
}

#[must_use]
pub(crate) fn jump_target(
    kind: JumpKind,
    offset: u32,
    arg: u32,
    caches: u32,
    version: PyVersion,
) -> Option<u32> {
    let wordcode: bool = version.is_wordcode();
    let word_scaled_args: bool = version.major > 3 || (version.major == 3 && version.minor >= 10);
    let scale: u32 = if word_scaled_args {
        WORDCODE_INSTRUCTION_SIZE
    } else {
        1
    };
    let instruction_size: u32 = if wordcode {
        WORDCODE_INSTRUCTION_SIZE
    } else {
        LEGACY_INSTRUCTION_SIZE
    };
    let scaled_arg: u32 = arg.checked_mul(scale)?;
    let next: u32 = offset
        .checked_add(instruction_size)?
        .checked_add(caches.checked_mul(CACHE_ENTRY_SIZE)?)?;
    match kind {
        JumpKind::Absolute => Some(scaled_arg),
        JumpKind::RelativeForward => next.checked_add(scaled_arg),
        JumpKind::RelativeBackward => next.checked_sub(scaled_arg),
        JumpKind::None => None,
    }
}
