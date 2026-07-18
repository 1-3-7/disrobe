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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum AliasResult {
    NoAlias {
        reason: Option<DisjointReason>,
    },
    #[default]
    MayAlias,
    PartialAlias,
    MustAlias,
}

impl AliasResult {
    #[must_use]
    pub const fn no_alias(reason: DisjointReason) -> Self {
        Self::NoAlias {
            reason: Some(reason),
        }
    }

    #[must_use]
    pub const fn region_no_alias() -> Self {
        Self::NoAlias { reason: None }
    }

    #[must_use]
    pub const fn may_alias(self) -> bool {
        !matches!(self, Self::NoAlias { .. })
    }

    #[must_use]
    pub const fn is_must(self) -> bool {
        matches!(self, Self::MustAlias)
    }

    #[must_use]
    pub const fn is_partial(self) -> bool {
        matches!(self, Self::PartialAlias)
    }

    #[must_use]
    pub const fn disjoint_reason(self) -> Option<DisjointReason> {
        match self {
            Self::NoAlias { reason } => reason,
            Self::MayAlias | Self::PartialAlias | Self::MustAlias => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisjointReason {
    ConstExtent,
    CorrelatedField,
    BoundedInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IndexSymbol {
    block: usize,
    register_write: Option<usize>,
    call_barrier: Option<usize>,
}

impl IndexSymbol {
    #[must_use]
    pub(crate) const fn new(
        block: usize,
        register_write: Option<usize>,
        call_barrier: Option<usize>,
    ) -> Self {
        Self {
            block,
            register_write,
            call_barrier,
        }
    }
}

pub trait AliasOracle {
    fn alias(&self, a: &MemoryAccess, b: &MemoryAccess) -> AliasResult;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysMayAlias;

impl AliasOracle for AlwaysMayAlias {
    fn alias(&self, _a: &MemoryAccess, _b: &MemoryAccess) -> AliasResult {
        AliasResult::MayAlias
    }
}

impl AliasOracle for RegionModel {
    fn alias(&self, a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
        let result: AliasResult = alias_access(a, b);
        debug_assert!(
            alias_access(b, a) == result,
            "alias oracle must be symmetric",
        );
        debug_assert!(
            !result.is_must() || result.may_alias(),
            "MustAlias must imply MayAlias",
        );
        debug_assert!(
            !(a.escapes || b.escapes) || result.may_alias(),
            "an escaped access must never be proven NoAlias",
        );
        debug_assert!(
            !(a.region == Region::Unknown || b.region == Region::Unknown) || result.may_alias(),
            "an unknown-region access must never be proven NoAlias",
        );
        debug_assert!(
            !unbounded_index_requires_may_alias(a, b) || result.may_alias(),
            "an unbounded indexed access must never be proven NoAlias without correlation",
        );
        result
    }
}

fn alias_access(a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
    if a.escapes || b.escapes {
        return AliasResult::MayAlias;
    }
    if matches!(a.region, Region::Unknown) || matches!(b.region, Region::Unknown) {
        return AliasResult::MayAlias;
    }
    if unbounded_index_requires_may_alias(a, b) {
        return AliasResult::MayAlias;
    }
    if a.region != b.region {
        if a.region.never_aliases_other_region() && b.region.never_aliases_other_region() {
            return AliasResult::region_no_alias();
        }
        return AliasResult::MayAlias;
    }
    match a.region {
        Region::Stack => stack_alias(a, b),
        _ => AliasResult::MayAlias,
    }
}

fn stack_alias(a: &MemoryAccess, b: &MemoryAccess) -> AliasResult {
    if a.base.full_register() != b.base.full_register() {
        return AliasResult::MayAlias;
    }
    let (Some(wa), Some(wb)): (Option<u8>, Option<u8>) = (a.width.bytes(), b.width.bytes()) else {
        return AliasResult::MayAlias;
    };
    if a.index.is_none() && b.index.is_none() {
        return extent_alias(a.rbp_disp, wa, b.rbp_disp, wb, DisjointReason::ConstExtent);
    }
    if indexes_are_correlated(a, b) {
        return extent_alias(
            a.rbp_disp,
            wa,
            b.rbp_disp,
            wb,
            DisjointReason::CorrelatedField,
        );
    }
    bounded_interval_alias(a, wa, b, wb)
}

fn unbounded_index_requires_may_alias(a: &MemoryAccess, b: &MemoryAccess) -> bool {
    (unbounded_index(a) || unbounded_index(b)) && !indexes_are_correlated(a, b)
}

const fn unbounded_index(access: &MemoryAccess) -> bool {
    access.index.is_some() && (access.index_bound.is_none() || !has_valid_index_scale(access))
}

fn indexes_are_correlated(a: &MemoryAccess, b: &MemoryAccess) -> bool {
    let (Some(index_a), Some(index_b), Some(symbol_a), Some(symbol_b)): (
        Option<Register>,
        Option<Register>,
        Option<IndexSymbol>,
        Option<IndexSymbol>,
    ) = (a.index, b.index, a.index_symbol, b.index_symbol) else {
        return false;
    };
    index_a != Register::None
        && index_b != Register::None
        && index_a.full_register() == index_b.full_register()
        && a.index_address_size == b.index_address_size
        && symbol_a == symbol_b
        && has_valid_index_scale(a)
        && has_valid_index_scale(b)
        && a.index_scale == b.index_scale
}

const fn has_valid_index_scale(access: &MemoryAccess) -> bool {
    matches!(access.index_scale, 1 | 2 | 4 | 8)
}

fn extent_alias(
    disp_a: i64,
    width_a: u8,
    disp_b: i64,
    width_b: u8,
    reason: DisjointReason,
) -> AliasResult {
    let Some(end_a): Option<i64> = disp_a.checked_add(i64::from(width_a)) else {
        return AliasResult::MayAlias;
    };
    let Some(end_b): Option<i64> = disp_b.checked_add(i64::from(width_b)) else {
        return AliasResult::MayAlias;
    };
    if disp_a >= end_b || disp_b >= end_a {
        return AliasResult::no_alias(reason);
    }
    if disp_a == disp_b && width_a == width_b {
        return AliasResult::MustAlias;
    }
    AliasResult::PartialAlias
}

fn bounded_interval_alias(
    a: &MemoryAccess,
    width_a: u8,
    b: &MemoryAccess,
    width_b: u8,
) -> AliasResult {
    let (Some(upper_a), Some(upper_b)): (Option<u64>, Option<u64>) =
        (index_upper_bound(a), index_upper_bound(b))
    else {
        return AliasResult::MayAlias;
    };
    if !bounded_offsets_are_linear(a, upper_a, b, upper_b) {
        return AliasResult::MayAlias;
    }
    let scale_a: u8 = address_scale(a);
    let scale_b: u8 = address_scale(b);
    let Some(scale_gcd): Option<u8> = nonzero_gcd(scale_a, scale_b) else {
        return AliasResult::MayAlias;
    };
    let base: i128 = i128::from(a.rbp_disp) - i128::from(b.rbp_disp);
    let minimum: i128 = base - i128::from(scale_b) * i128::from(upper_b);
    let maximum: i128 = base + i128::from(scale_a) * i128::from(upper_a);
    let overlap_minimum: i128 = 1 - i128::from(width_a);
    let overlap_maximum: i128 = i128::from(width_b) - 1;
    let candidate_minimum: i128 = minimum.max(overlap_minimum);
    let candidate_maximum: i128 = maximum.min(overlap_maximum);
    if candidate_minimum > candidate_maximum {
        return AliasResult::no_alias(DisjointReason::BoundedInterval);
    }
    let modulus: i128 = i128::from(scale_gcd);
    let residue: i128 = base.rem_euclid(modulus);
    let first: i128 = candidate_minimum + (residue - candidate_minimum).rem_euclid(modulus);
    if first > candidate_maximum {
        return AliasResult::no_alias(DisjointReason::BoundedInterval);
    }
    AliasResult::MayAlias
}

fn index_upper_bound(access: &MemoryAccess) -> Option<u64> {
    if access.index.is_none() {
        return Some(0);
    }
    if !has_valid_index_scale(access) {
        return None;
    }
    let (lower, upper): (u64, u64) = access.index_bound?;
    (lower <= upper).then_some(upper)
}

fn bounded_offsets_are_linear(
    a: &MemoryAccess,
    upper_a: u64,
    b: &MemoryAccess,
    upper_b: u64,
) -> bool {
    if (a.index.is_some() && a.index_address_size != 8)
        || (b.index.is_some() && b.index_address_size != 8)
    {
        return false;
    }
    let maximum_a: i128 =
        i128::from(a.rbp_disp) + i128::from(address_scale(a)) * i128::from(upper_a);
    let maximum_b: i128 =
        i128::from(b.rbp_disp) + i128::from(address_scale(b)) * i128::from(upper_b);
    let minimum: i128 = i128::from(a.rbp_disp).min(i128::from(b.rbp_disp));
    let maximum: i128 = maximum_a.max(maximum_b);
    maximum - minimum <= i128::from(i64::MAX)
}

const fn address_scale(access: &MemoryAccess) -> u8 {
    if access.index.is_some() {
        access.index_scale
    } else {
        0
    }
}

fn nonzero_gcd(left: u8, right: u8) -> Option<u8> {
    let mut a: u8 = left;
    let mut b: u8 = right;
    while b != 0 {
        let remainder: u8 = a % b;
        a = b;
        b = remainder;
    }
    (a != 0).then_some(a)
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
    bss: Vec<(u64, u64)>,
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

    pub fn add_bss(&mut self, start: u64, end: u64) {
        self.bss.push((start, end));
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
        if self
            .bss
            .iter()
            .any(|(s, e): &(u64, u64)| addr >= *s && addr < *e)
        {
            return SectionKind::Bss;
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
    pub index: Option<Register>,
    pub index_address_size: u8,
    pub index_symbol: Option<IndexSymbol>,
    pub index_scale: u8,
    pub index_bound: Option<(u64, u64)>,
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
    let rbp_disp: i64 = i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes());
    let raw_index: Register = insn.memory_index();
    let index: Option<Register> =
        (raw_index != Register::None).then_some(raw_index.full_register());
    let index_address_size: u8 = index_address_size(raw_index);
    let index_scale: u8 = decoded_index_scale(insn.memory_index_scale());
    Some(MemoryAccess {
        region,
        base,
        rbp_disp,
        index,
        index_address_size,
        index_symbol: None,
        index_scale,
        index_bound: None,
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

fn index_address_size(index: Register) -> u8 {
    match index.size() {
        4 => 4,
        8 => 8,
        _ => 0,
    }
}

const fn decoded_index_scale(scale: u32) -> u8 {
    match scale {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        _ => 0,
    }
}

fn memory_width(insn: &Instruction) -> Width {
    let size: usize = insn.memory_size().size();
    u8::try_from(size).map_or(Width::Unknown, Width::from_bytes)
}

#[must_use]
pub fn may_alias(a: MemoryAccess, b: MemoryAccess) -> bool {
    RegionModel::default().alias(&a, &b).may_alias()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_single(bytes: &[u8]) -> Instruction {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let instruction: Instruction = decoder.decode();
        assert!(!instruction.is_invalid());
        instruction
    }

    fn stack_access(rbp_disp: i64, width: Width) -> MemoryAccess {
        MemoryAccess {
            region: Region::Stack,
            base: Register::RBP,
            rbp_disp,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width,
            escapes: false,
        }
    }

    fn indexed_stack_access(
        rbp_disp: i64,
        width: Width,
        index: Register,
        index_scale: u8,
        index_bound: Option<(u64, u64)>,
    ) -> MemoryAccess {
        MemoryAccess {
            region: Region::Stack,
            base: Register::RBP,
            rbp_disp,
            index: Some(index.full_register()),
            index_address_size: 8,
            index_symbol: Some(IndexSymbol::new(0, None, None)),
            index_scale,
            index_bound,
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
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
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
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
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
        model.add_bss(0x6000, 0x7000);
        assert_eq!(model.section_of(0x2500), SectionKind::Rodata);
        assert_eq!(model.section_of(0x4001), SectionKind::Data);
        assert_eq!(model.section_of(0x6800), SectionKind::Bss);
        assert_eq!(model.section_of(0x9000), SectionKind::Other);
    }

    fn heap_access(width: Width) -> MemoryAccess {
        MemoryAccess {
            region: Region::Heap,
            base: Register::RAX,
            rbp_disp: 0,
            index: None,
            index_address_size: 0,
            index_symbol: None,
            index_scale: 1,
            index_bound: None,
            width,
            escapes: false,
        }
    }

    #[test]
    fn default_alias_result_is_may_alias() {
        assert_eq!(AliasResult::default(), AliasResult::MayAlias);
        assert!(AliasResult::MayAlias.may_alias());
        assert!(AliasResult::PartialAlias.may_alias());
        assert!(AliasResult::MustAlias.may_alias());
        assert!(!AliasResult::no_alias(DisjointReason::ConstExtent).may_alias());
    }

    #[test]
    fn oracle_reports_four_valued_stack_results() {
        let model: RegionModel = RegionModel::new();
        let identical_a: MemoryAccess = stack_access(-8, Width::Qword);
        let identical_b: MemoryAccess = stack_access(-8, Width::Qword);
        assert_eq!(
            model.alias(&identical_a, &identical_b),
            AliasResult::MustAlias
        );

        let wide: MemoryAccess = stack_access(-8, Width::Qword);
        let inner: MemoryAccess = stack_access(-4, Width::Dword);
        assert_eq!(model.alias(&wide, &inner), AliasResult::PartialAlias);

        let low: MemoryAccess = stack_access(-16, Width::Qword);
        let high: MemoryAccess = stack_access(-8, Width::Qword);
        let disjoint: AliasResult = model.alias(&low, &high);
        assert_eq!(disjoint, AliasResult::no_alias(DisjointReason::ConstExtent));
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::ConstExtent)
        );
    }

    #[test]
    fn classify_preserves_indexed_rbp_displacements_for_field_aliasing() {
        let first: Instruction = decode_single(&[0x48, 0x8b, 0x44, 0xcd, 0xc0]);
        let second: Instruction = decode_single(&[0x48, 0x8b, 0x54, 0xcd, 0xc8]);
        let model: RegionModel = RegionModel::new();
        let first_access: MemoryAccess = classify(&first, 1, &model).expect("first memory access");
        let second_access: MemoryAccess =
            classify(&second, 1, &model).expect("second memory access");

        assert_eq!(first_access.region, Region::Stack);
        assert_eq!(second_access.region, Region::Stack);
        assert_eq!(first_access.rbp_disp, -0x40);
        assert_eq!(second_access.rbp_disp, -0x38);
        assert_eq!(first_access.index, Some(Register::RCX));
        assert_eq!(second_access.index, Some(Register::RCX));
        assert_eq!(first_access.index_scale, 8);
        assert_eq!(second_access.index_scale, 8);
        assert_eq!(
            model.alias(&first_access, &second_access),
            AliasResult::MayAlias
        );
    }

    #[test]
    fn correlated_indexes_cancel_to_the_constant_extent_relation() {
        let model: RegionModel = RegionModel::new();
        let low: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let high: MemoryAccess = indexed_stack_access(-0x38, Width::Qword, Register::RCX, 8, None);
        let same: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let overlap: MemoryAccess =
            indexed_stack_access(-0x3c, Width::Dword, Register::RCX, 8, None);

        let disjoint: AliasResult = model.alias(&low, &high);
        assert_eq!(
            disjoint,
            AliasResult::no_alias(DisjointReason::CorrelatedField)
        );
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::CorrelatedField)
        );
        assert_eq!(model.alias(&low, &same), AliasResult::MustAlias);
        assert_eq!(model.alias(&low, &overlap), AliasResult::PartialAlias);
    }

    #[test]
    fn bounded_index_ranges_can_prove_disjoint_extents() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess =
            indexed_stack_access(-0x100, Width::Qword, Register::RCX, 8, Some((0, 3)));
        let second: MemoryAccess =
            indexed_stack_access(-0x80, Width::Qword, Register::RDX, 8, Some((0, 3)));

        let disjoint: AliasResult = model.alias(&first, &second);
        assert_eq!(
            disjoint,
            AliasResult::no_alias(DisjointReason::BoundedInterval)
        );
        assert_eq!(
            disjoint.disjoint_reason(),
            Some(DisjointReason::BoundedInterval)
        );
    }

    #[test]
    fn different_unbounded_indexes_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RCX, 8, None);
        let second: MemoryAccess =
            indexed_stack_access(-0x38, Width::Qword, Register::RDX, 8, None);
        let constant: MemoryAccess = stack_access(-0x40, Width::Qword);

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
        assert_eq!(model.alias(&first, &constant), AliasResult::MayAlias);
    }

    #[test]
    fn different_index_address_sizes_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(-0x40, Width::Qword, Register::RAX, 8, None);
        let second: MemoryAccess = MemoryAccess {
            rbp_disp: -0x38,
            index_address_size: 4,
            ..first
        };

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
    }

    #[test]
    fn bounded_no_alias_never_overlaps_an_enumerated_index_pair() {
        let model: RegionModel = RegionModel::new();
        let scales: [u8; 4] = [1, 2, 4, 8];
        let width: i64 = 8;
        for disp_a in -16_i64..=16 {
            for disp_b in -16_i64..=16 {
                for scale_a in scales {
                    for scale_b in scales {
                        for bound_a in 0_u64..=3 {
                            for bound_b in 0_u64..=3 {
                                let first: MemoryAccess = indexed_stack_access(
                                    disp_a,
                                    Width::Qword,
                                    Register::RCX,
                                    scale_a,
                                    Some((0, bound_a)),
                                );
                                let second: MemoryAccess = indexed_stack_access(
                                    disp_b,
                                    Width::Qword,
                                    Register::RDX,
                                    scale_b,
                                    Some((0, bound_b)),
                                );
                                let result: AliasResult = model.alias(&first, &second);
                                if result.may_alias() {
                                    continue;
                                }
                                assert_eq!(
                                    result.disjoint_reason(),
                                    Some(DisjointReason::BoundedInterval)
                                );
                                for index_a in 0..=bound_a {
                                    for index_b in 0..=bound_b {
                                        let start_a: i64 = disp_a
                                            + i64::try_from(index_a).expect("small index")
                                                * i64::from(scale_a);
                                        let start_b: i64 = disp_b
                                            + i64::try_from(index_b).expect("small index")
                                                * i64::from(scale_b);
                                        let end_a: i64 = start_a + width;
                                        let end_b: i64 = start_b + width;
                                        assert!(start_a >= end_b || start_b >= end_a);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bounded_ranges_that_can_wrap_never_prove_no_alias() {
        let model: RegionModel = RegionModel::new();
        let first: MemoryAccess = indexed_stack_access(
            16,
            Width::Qword,
            Register::RCX,
            8,
            Some((0, (1_u64 << 61) - 2)),
        );
        let second: MemoryAccess =
            indexed_stack_access(0, Width::Qword, Register::RDX, 8, Some((0, 0)));

        assert_eq!(model.alias(&first, &second), AliasResult::MayAlias);
    }

    #[test]
    fn oracle_never_proves_disjoint_across_top_or_escape() {
        let model: RegionModel = RegionModel::new();
        let stack: MemoryAccess = stack_access(-8, Width::Qword);
        let heap: MemoryAccess = heap_access(Width::Qword);
        assert_eq!(model.alias(&stack, &heap), AliasResult::region_no_alias());

        let escaped: MemoryAccess = MemoryAccess {
            escapes: true,
            ..heap
        };
        assert!(model.alias(&stack, &escaped).may_alias());

        let unknown: MemoryAccess = MemoryAccess {
            region: Region::Unknown,
            ..heap
        };
        assert!(model.alias(&stack, &unknown).may_alias());
    }

    #[test]
    fn always_may_alias_stub_never_proves_disjoint() {
        let stub: AlwaysMayAlias = AlwaysMayAlias;
        let low: MemoryAccess = stack_access(-16, Width::Qword);
        let high: MemoryAccess = stack_access(-8, Width::Qword);
        assert_eq!(stub.alias(&low, &high), AliasResult::MayAlias);
    }
}
