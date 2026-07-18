use iced_x86::{Instruction, OpKind, Register};

use crate::lattice::Width;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    Stack,
    Global,
    Heap,
    Tls,
    ConstPool,
    Unknown,
}

impl Region {
    #[must_use]
    pub const fn never_aliases_other_region(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Rodata,
    Data,
    Bss,
    Other,
}

#[derive(Debug, Default, Clone)]
pub struct RegionModel {
    heap_regs: Vec<Register>,
    frame_regs: Vec<Register>,
    rodata: Vec<(u64, u64)>,
    data: Vec<(u64, u64)>,
    reloc_targets: Vec<u64>,
}

impl RegionModel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_heap(&mut self, reg: Register) {
        let full: Register = reg.full_register();
        if !self.heap_regs.contains(&full) {
            self.heap_regs.push(full);
        }
    }

    pub fn clear_heap(&mut self, reg: Register) {
        let full: Register = reg.full_register();
        self.heap_regs.retain(|held: &Register| *held != full);
    }

    pub fn mark_frame(&mut self, reg: Register) {
        let full: Register = reg.full_register();
        if !self.frame_regs.contains(&full) {
            self.frame_regs.push(full);
        }
    }

    pub fn add_rodata(&mut self, start: u64, end: u64) {
        self.rodata.push((start, end));
    }

    pub fn add_data(&mut self, start: u64, end: u64) {
        self.data.push((start, end));
    }

    pub fn add_reloc_target(&mut self, target: u64) {
        self.reloc_targets.push(target);
    }

    #[must_use]
    fn is_heap(&self, reg: Register) -> bool {
        self.heap_regs.contains(&reg.full_register())
    }

    #[must_use]
    fn is_frame(&self, reg: Register) -> bool {
        matches!(reg, Register::RSP | Register::RBP)
            || self.frame_regs.contains(&reg.full_register())
    }

    #[must_use]
    fn section_of(&self, addr: u64) -> SectionKind {
        if self
            .rodata
            .iter()
            .any(|(s, e): &(u64, u64)| addr >= *s && addr < *e)
        {
            return SectionKind::Rodata;
        }
        if self
            .data
            .iter()
            .any(|(s, e): &(u64, u64)| addr >= *s && addr < *e)
        {
            return SectionKind::Data;
        }
        SectionKind::Other
    }

    #[must_use]
    fn is_reloc_target(&self, addr: u64) -> bool {
        self.reloc_targets.contains(&addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    pub region: Region,
    pub base: Register,
    pub rbp_disp: i64,
    pub width: Width,
    pub escapes: bool,
}

#[must_use]
pub fn classify(insn: &Instruction, memop: u32, model: &RegionModel) -> Option<MemoryAccess> {
    if insn.op_kind(memop) != OpKind::Memory {
        return None;
    }
    let segment: Register = insn.segment_prefix();
    let base: Register = insn.memory_base();
    let width: Width = memory_width(insn);
    let region: Region = classify_region(insn, segment, base, model);
    let rbp_disp: i64 = frame_disp(base, insn);
    Some(MemoryAccess {
        region,
        base,
        rbp_disp,
        width,
        escapes: false,
    })
}

fn classify_region(
    insn: &Instruction,
    segment: Register,
    base: Register,
    model: &RegionModel,
) -> Region {
    if matches!(segment, Register::FS | Register::GS) {
        return Region::Tls;
    }
    if insn.is_ip_rel_memory_operand() {
        let target: u64 = insn.ip_rel_memory_address();
        return match model.section_of(target) {
            SectionKind::Rodata => Region::ConstPool,
            SectionKind::Data | SectionKind::Bss => Region::Global,
            SectionKind::Other if model.is_reloc_target(target) => Region::Global,
            SectionKind::Other => Region::Unknown,
        };
    }
    if model.is_frame(base) {
        return Region::Stack;
    }
    if model.is_heap(base) {
        return Region::Heap;
    }
    if base == Register::None && insn.memory_index() == Register::None {
        let target: u64 = insn.memory_displacement64();
        return match model.section_of(target) {
            SectionKind::Rodata => Region::ConstPool,
            SectionKind::Data | SectionKind::Bss => Region::Global,
            SectionKind::Other if model.is_reloc_target(target) => Region::Global,
            SectionKind::Other => Region::Unknown,
        };
    }
    Region::Unknown
}

fn frame_disp(base: Register, insn: &Instruction) -> i64 {
    if !matches!(base, Register::RBP | Register::RSP) || insn.memory_index() != Register::None {
        return 0;
    }
    i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes())
}

fn memory_width(insn: &Instruction) -> Width {
    let size: usize = insn.memory_size().size();
    u8::try_from(size).map_or(Width::Unknown, Width::from_bytes)
}

#[must_use]
pub fn may_alias(a: MemoryAccess, b: MemoryAccess) -> bool {
    if a.region == Region::Unknown || b.region == Region::Unknown {
        return true;
    }
    if a.escapes || b.escapes {
        return true;
    }
    if a.region != b.region {
        return false;
    }
    if a.region == Region::Stack && a.base == b.base {
        return ranges_overlap(a.rbp_disp, a.width, b.rbp_disp, b.width);
    }
    true
}

fn ranges_overlap(off_a: i64, width_a: Width, off_b: i64, width_b: Width) -> bool {
    let (Some(wa), Some(wb)): (Option<u8>, Option<u8>) = (width_a.bytes(), width_b.bytes()) else {
        return true;
    };
    let end_a: i64 = off_a.saturating_add(i64::from(wa));
    let end_b: i64 = off_b.saturating_add(i64::from(wb));
    off_a < end_b && off_b < end_a
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn stack_access(rbp_disp: i64, width: Width) -> MemoryAccess {
        MemoryAccess {
            region: Region::Stack,
            base: Register::RBP,
            rbp_disp,
            width,
            escapes: false,
        }
    }

    #[test]
    fn distinct_stack_slots_never_alias() {
        let a: MemoryAccess = stack_access(-8, Width::Qword);
        let b: MemoryAccess = stack_access(-16, Width::Qword);
        assert!(!may_alias(a, b));
    }

    #[test]
    fn overlapping_stack_slots_may_alias() {
        let a: MemoryAccess = stack_access(-8, Width::Qword);
        let b: MemoryAccess = stack_access(-4, Width::Dword);
        assert!(may_alias(a, b));
    }

    #[test]
    fn distinct_regions_never_alias() {
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let heap: MemoryAccess = MemoryAccess {
            region: Region::Heap,
            base: Register::RAX,
            rbp_disp: 0,
            width: Width::Qword,
            escapes: false,
        };
        assert!(!may_alias(stack, heap));
    }

    #[test]
    fn unknown_region_may_alias_everything() {
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let unknown: MemoryAccess = MemoryAccess {
            region: Region::Unknown,
            base: Register::RAX,
            rbp_disp: 0,
            width: Width::Qword,
            escapes: false,
        };
        assert!(may_alias(stack, unknown));
        assert!(may_alias(unknown, stack));
    }

    #[test]
    fn escaped_stack_slot_may_alias_same_region() {
        let escaped: MemoryAccess = MemoryAccess {
            escapes: true,
            ..stack_access(-8, Width::Qword)
        };
        let other: MemoryAccess = stack_access(-64, Width::Qword);
        assert!(may_alias(escaped, other));
    }

    #[test]
    fn model_marks_heap_and_frame_registers() {
        let mut model: RegionModel = RegionModel::new();
        model.mark_heap(Register::EAX);
        assert!(model.is_heap(Register::RAX));
        model.clear_heap(Register::RAX);
        assert!(!model.is_heap(Register::RAX));
        model.mark_frame(Register::R12);
        assert!(model.is_frame(Register::R12));
        assert!(model.is_frame(Register::RBP));
    }

    #[test]
    fn section_membership_resolves_kind() {
        let mut model: RegionModel = RegionModel::new();
        model.add_rodata(0x2000, 0x3000);
        model.add_data(0x4000, 0x5000);
        assert_eq!(model.section_of(0x2500), SectionKind::Rodata);
        assert_eq!(model.section_of(0x4001), SectionKind::Data);
        assert_eq!(model.section_of(0x9000), SectionKind::Other);
    }
}
