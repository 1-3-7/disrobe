use std::collections::BTreeSet;

use crate::error::{Error, Result};

use super::{
    Abi, CallTarget, ExtSource, FrameShape, Item, ItemKind, MemRef, Reg, RegRef, Source,
    StackFrameExtent, Stmt, Width, call_clobber, source_regs, stmt_dest_regs, stmt_value_reads,
};

const fn is_stack_register(reg: Reg) -> bool {
    matches!(reg, Reg::Rsp | Reg::Rbp)
}

fn frame_address(stmt: &Stmt) -> Option<(Reg, Reg, i64)> {
    match stmt {
        Stmt::Assign {
            dest,
            src:
                Source::Lea {
                    base: Some(base @ (Reg::Rsp | Reg::Rbp)),
                    index: None,
                    disp,
                },
        } if !is_stack_register(dest.reg) => Some((dest.reg, *base, *disp)),
        _ => None,
    }
}

fn left_to_the_frame_plan(shape: FrameShape, base: Reg, disp: i64) -> bool {
    let owned: Option<(i64, i64)> = shape
        .stack_extent
        .filter(|_: &StackFrameExtent| shape.base == Some(base) && !shape.red_zone)
        .and_then(|extent: StackFrameExtent| Some((extent.owned_start?, extent.private_end)));
    owned.is_some_and(|(start, end): (i64, i64)| !(start..end).contains(&disp))
}

fn escape_refusal(address: u64) -> Error {
    Error::LlvmIr(format!(
        "stack-frame register escapes a fixed-offset slot access: the stack slot address formed at {address:#x} is used other than as a memory base or a call argument before it dies, so its value may outlive the frame"
    ))
}

fn full_width(reg: RegRef) -> bool {
    reg.width == Width::W64
}

fn indexes_by_holder(mem: &MemRef, holders: &BTreeSet<Reg>) -> bool {
    mem.index
        .is_some_and(|index: super::IndexOperand| holders.contains(&index.reg))
}

enum Use {
    Escapes,
    Derives(Reg),
    Other,
}

fn classify_use(stmt: &Stmt, holders: &BTreeSet<Reg>) -> Use {
    let mut reads: Vec<Reg> = Vec::new();
    match stmt {
        Stmt::Assign {
            dest,
            src: Source::Reg(src),
        } if holders.contains(&src.reg) => {
            return if full_width(*dest) && full_width(*src) && !is_stack_register(dest.reg) {
                Use::Derives(dest.reg)
            } else {
                Use::Escapes
            };
        }
        Stmt::Assign {
            dest,
            src:
                Source::Lea {
                    base: Some(base),
                    index,
                    ..
                },
        } if holders.contains(base) => {
            let indexed: bool =
                index.is_some_and(|index: super::IndexOperand| holders.contains(&index.reg));
            return if full_width(*dest) && !indexed && !is_stack_register(dest.reg) {
                Use::Derives(dest.reg)
            } else {
                Use::Escapes
            };
        }
        Stmt::Assign {
            src: Source::Mem(mem),
            ..
        }
        | Stmt::Extend {
            src: ExtSource::Mem(mem),
            ..
        } => {
            if indexes_by_holder(mem, holders) {
                return Use::Escapes;
            }
        }
        Stmt::Store { addr, src } => {
            if indexes_by_holder(addr, holders) {
                return Use::Escapes;
            }
            source_regs(src, &mut reads);
        }
        Stmt::MemRmw { addr, op } => {
            if indexes_by_holder(addr, holders) {
                return Use::Escapes;
            }
            if let Some(src) = op.source() {
                source_regs(src, &mut reads);
            }
        }
        other => stmt_value_reads(other, &mut reads),
    }
    if reads.iter().any(|reg: &Reg| holders.contains(reg)) {
        Use::Escapes
    } else {
        Use::Other
    }
}

fn address_dies_unescaped(items: &[Item], holder: Reg, abi: Abi) -> bool {
    let mut holders: BTreeSet<Reg> = BTreeSet::from([holder]);
    for later in items {
        if holders.is_empty() {
            return true;
        }
        let stmt: &Stmt = match &later.kind {
            ItemKind::Stmt(stmt) => stmt,
            ItemKind::Branch { .. }
            | ItemKind::Jmp { .. }
            | ItemKind::Switch { .. }
            | ItemKind::Ret => return false,
        };
        if let Stmt::Call { target, args, .. } = stmt {
            if matches!(target, CallTarget::Register)
                && args
                    .first()
                    .is_some_and(|pointer: &Reg| holders.contains(pointer))
            {
                return false;
            }
            for volatile in call_clobber::volatile_gprs(abi) {
                holders.remove(volatile);
            }
            continue;
        }
        let derived: Option<Reg> = match classify_use(stmt, &holders) {
            Use::Escapes => return false,
            Use::Derives(reg) => Some(reg),
            Use::Other => None,
        };
        for written in stmt_dest_regs(stmt) {
            if Some(written) != derived {
                holders.remove(&written);
            }
        }
        if let Some(reg) = derived {
            holders.insert(reg);
        }
    }
    holders.is_empty()
}

pub(super) fn refuse_frame_addresses_that_escape(
    items: &[Item],
    abi: Abi,
    shape: FrameShape,
) -> Result<()> {
    for (position, item) in items.iter().enumerate() {
        let ItemKind::Stmt(stmt) = &item.kind else {
            continue;
        };
        let Some((holder, base, disp)): Option<(Reg, Reg, i64)> = frame_address(stmt) else {
            continue;
        };
        if left_to_the_frame_plan(shape, base, disp) {
            continue;
        }
        let rest: &[Item] = items.get(position + 1..).unwrap_or_default();
        if !address_dies_unescaped(rest, holder, abi) {
            return Err(escape_refusal(item.address));
        }
    }
    Ok(())
}
