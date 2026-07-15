use disrobe_sleigh::pcode::{Space, Varnode};
use iced_x86::Register;

pub(crate) const CF: Varnode = register_node(0x200, 1);
pub(crate) const PF: Varnode = register_node(0x202, 1);
pub(crate) const AF: Varnode = register_node(0x204, 1);
pub(crate) const ZF: Varnode = register_node(0x206, 1);
pub(crate) const SF: Varnode = register_node(0x207, 1);
pub(crate) const DF: Varnode = register_node(0x20a, 1);
pub(crate) const OF: Varnode = register_node(0x20b, 1);
pub(crate) const MXCSR: Varnode = register_node(0x1094, 4);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UniqueAllocator {
    next: u64,
}

impl UniqueAllocator {
    pub(crate) fn allocate(&mut self, size_bytes: u32) -> Option<Varnode> {
        if size_bytes == 0 {
            return None;
        }
        let offset: u64 = self.next;
        let stride: u64 = u64::from(size_bytes).max(8);
        self.next = self.next.checked_add(stride)?;
        Some(Varnode {
            offset,
            size_bytes,
            space: Space::Unique,
        })
    }
}

pub(crate) const fn constant(offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset: offset & mask_for_bytes(size_bytes),
        size_bytes,
        space: Space::Constant,
    }
}

pub(crate) const fn ram_address(offset: u64) -> Varnode {
    Varnode {
        offset,
        size_bytes: 8,
        space: Space::Ram,
    }
}

pub(crate) fn register(register: Register) -> Option<Varnode> {
    let size_bytes: u32 = u32::try_from(register.size()).ok()?;
    if size_bytes == 0 {
        return None;
    }
    if let Some(offset) = gpr_offset(register) {
        return Some(register_node(offset, size_bytes));
    }
    if register.is_vector_register() {
        let index: u64 = u64::try_from(register.number()).ok()?;
        let offset: u64 = 0x1200_u64.checked_add(index.checked_mul(0x40)?)?;
        return Some(register_node(offset, size_bytes));
    }
    if register.is_k() {
        let index: u64 = u64::try_from(register.number()).ok()?;
        let offset: u64 = 0x834_u64.checked_add(index.checked_mul(8)?)?;
        return Some(register_node(offset, size_bytes));
    }
    let offset: u64 = match register {
        Register::EIP | Register::RIP => 0x288,
        Register::ES | Register::CS | Register::SS | Register::DS | Register::FS | Register::GS => {
            let index: u64 = u64::try_from(register.number()).ok()?;
            0x100_u64.checked_add(index.checked_mul(2)?)?
        }
        _ => return None,
    };
    Some(register_node(offset, size_bytes))
}

pub(crate) fn full_gpr(register: Register) -> Option<Varnode> {
    let full: Register = register.full_register();
    gpr_offset(full).map(|offset: u64| register_node(offset, 8))
}

pub(crate) const fn gpr32_by_offset(offset: u64) -> Register {
    match offset {
        0x00 => Register::EAX,
        0x08 => Register::ECX,
        0x10 => Register::EDX,
        0x18 => Register::EBX,
        0x20 => Register::ESP,
        0x28 => Register::EBP,
        0x30 => Register::ESI,
        0x38 => Register::EDI,
        0x80 => Register::R8D,
        0x88 => Register::R9D,
        0x90 => Register::R10D,
        0x98 => Register::R11D,
        0xa0 => Register::R12D,
        0xa8 => Register::R13D,
        0xb0 => Register::R14D,
        0xb8 => Register::R15D,
        _ => Register::None,
    }
}

pub(crate) const fn segment_base(register: Register) -> Option<Varnode> {
    match register {
        Register::FS => Some(register_node(0x110, 8)),
        Register::GS => Some(register_node(0x118, 8)),
        _ => None,
    }
}

pub(crate) fn is_gpr(register: Register) -> bool {
    gpr_offset(register).is_some()
}

pub(crate) fn xmm_lane(selected: Register, byte_offset: u32, size_bytes: u32) -> Option<Varnode> {
    if !selected.is_xmm() || size_bytes == 0 {
        return None;
    }
    let end: u32 = byte_offset.checked_add(size_bytes)?;
    if end > 16 {
        return None;
    }
    let full: Varnode = register(selected)?;
    let offset: u64 = full.offset.checked_add(u64::from(byte_offset))?;
    Some(register_node(offset, size_bytes))
}

fn gpr_offset(register: Register) -> Option<u64> {
    let full: Register = register.full_register();
    let index: u64 = match full {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None,
    };
    let base: u64 = if index < 8 {
        index.checked_mul(8)?
    } else {
        0x80_u64.checked_add(index.saturating_sub(8).checked_mul(8)?)?
    };
    if matches!(
        register,
        Register::AH | Register::CH | Register::DH | Register::BH
    ) {
        base.checked_add(1)
    } else {
        Some(base)
    }
}

const fn register_node(offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space: Space::Register,
    }
}

const fn mask_for_bytes(size_bytes: u32) -> u64 {
    let bits: u32 = size_bytes.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        match 1_u64.checked_shl(bits) {
            Some(value) => value.saturating_sub(1),
            None => 0,
        }
    }
}
