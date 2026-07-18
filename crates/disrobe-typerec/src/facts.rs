use std::collections::BTreeMap;

use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register, RflagsBits};

use crate::cells::CellStore;
use crate::cfg::{self, Cfg};
use crate::constraint::Constraint;
use crate::decode::decode_all;
use crate::lattice::{Confidence, Sign, TypeClass, TypeVar, Width};
use crate::memssa::{self, MemSsa};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotMode {
    Merge,
    Split,
}

#[derive(Debug)]
pub struct FactSet {
    pub store: CellStore,
    pub constraints: Vec<Constraint>,
    pub rbp_slots: BTreeMap<i64, TypeVar>,
    pub ssa: MemSsa,
    pub has_frame_pointer: bool,
}

#[derive(Debug)]
enum SlotResolver {
    Merge(BTreeMap<i64, TypeVar>),
    Split(MemSsa),
}

#[derive(Debug)]
struct Extractor {
    store: CellStore,
    constraints: Vec<Constraint>,
    current: BTreeMap<Register, TypeVar>,
    resolver: SlotResolver,
    pending_cmp: Option<(Option<TypeVar>, Option<TypeVar>)>,
    current_ip: u64,
}

impl Extractor {
    const fn new(store: CellStore, resolver: SlotResolver) -> Self {
        Self {
            store,
            constraints: Vec::new(),
            current: BTreeMap::new(),
            resolver,
            pending_cmp: None,
            current_ip: 0,
        }
    }

    fn reg_use(&mut self, reg: Register) -> TypeVar {
        let full: Register = reg.full_register();
        if let Some(existing) = self.current.get(&full) {
            return *existing;
        }
        let fresh: TypeVar = self.store.fresh(TypeClass::Top);
        self.current.insert(full, fresh);
        fresh
    }

    fn reg_def(&mut self, reg: Register) -> TypeVar {
        let full: Register = reg.full_register();
        let fresh: TypeVar = self.store.fresh(TypeClass::Top);
        self.current.insert(full, fresh);
        fresh
    }

    fn slot_cell(&mut self, rbp_disp: i64) -> Option<TypeVar> {
        match &mut self.resolver {
            SlotResolver::Merge(map) => {
                if let Some(existing) = map.get(&rbp_disp) {
                    return Some(*existing);
                }
                let fresh: TypeVar = self.store.fresh(TypeClass::Top);
                map.insert(rbp_disp, fresh);
                Some(fresh)
            }
            SlotResolver::Split(ssa) => ssa.version_cell(self.current_ip, rbp_disp),
        }
    }

    fn operand_read_cell(&mut self, insn: &Instruction, op: u32) -> Option<TypeVar> {
        match insn.op_kind(op) {
            OpKind::Register => {
                let reg: Register = insn.op_register(op);
                reg.is_gpr().then(|| self.reg_use(reg))
            }
            OpKind::Memory => {
                rbp_slot_disp(insn).and_then(|rbp_disp: i64| self.slot_cell(rbp_disp))
            }
            _ => None,
        }
    }

    fn record_slot_width(&mut self, insn: &Instruction) {
        let Some(rbp_disp): Option<i64> = rbp_slot_disp(insn) else {
            return;
        };
        let Some(width): Option<Width> = memory_width(insn) else {
            return;
        };
        let Some(cell): Option<TypeVar> = self.slot_cell(rbp_disp) else {
            return;
        };
        self.constraints
            .push(Constraint::Width(cell, width, Confidence::UsageIdiom));
    }

    fn handle_mov(&mut self, insn: &Instruction) {
        match (insn.op_kind(0), insn.op_kind(1)) {
            (OpKind::Register, OpKind::Register) => {
                let dst_reg: Register = insn.op_register(0);
                let src_reg: Register = insn.op_register(1);
                if dst_reg.is_gpr() && src_reg.is_gpr() {
                    let src: TypeVar = self.reg_use(src_reg);
                    let dst: TypeVar = self.reg_def(dst_reg);
                    self.constraints.push(Constraint::Union(dst, src));
                } else if dst_reg.is_gpr() {
                    let _dst: TypeVar = self.reg_def(dst_reg);
                }
            }
            (OpKind::Register, OpKind::Memory) => {
                let dst_reg: Register = insn.op_register(0);
                if !dst_reg.is_gpr() {
                    return;
                }
                let slot: Option<TypeVar> =
                    rbp_slot_disp(insn).and_then(|rbp_disp: i64| self.slot_cell(rbp_disp));
                let dst: TypeVar = self.reg_def(dst_reg);
                if let Some(src) = slot {
                    self.constraints.push(Constraint::SignLink(dst, src));
                }
            }
            (OpKind::Memory, OpKind::Register) => {
                let src_reg: Register = insn.op_register(1);
                if !src_reg.is_gpr() {
                    return;
                }
                let Some(rbp_disp): Option<i64> = rbp_slot_disp(insn) else {
                    return;
                };
                let src: TypeVar = self.reg_use(src_reg);
                let Some(slot): Option<TypeVar> = self.slot_cell(rbp_disp) else {
                    return;
                };
                self.constraints.push(Constraint::SignLink(slot, src));
            }
            _ => {
                if insn.op_kind(0) == OpKind::Register {
                    let dst_reg: Register = insn.op_register(0);
                    if dst_reg.is_gpr() {
                        let _dst: TypeVar = self.reg_def(dst_reg);
                    }
                }
            }
        }
    }

    fn handle_extend(&mut self, insn: &Instruction) {
        if insn.op_kind(0) != OpKind::Register {
            return;
        }
        let dst_reg: Register = insn.op_register(0);
        if !dst_reg.is_gpr() {
            return;
        }
        let src: Option<TypeVar> = self.operand_read_cell(insn, 1);
        let dst: TypeVar = self.reg_def(dst_reg);
        if let Some(src) = src {
            self.constraints.push(Constraint::SignLink(dst, src));
        }
    }

    fn mark_operand_sign(&mut self, insn: &Instruction, op: u32, sign: Sign) {
        if let Some(cell) = self.operand_read_cell(insn, op) {
            self.constraints
                .push(Constraint::Sign(cell, sign, Confidence::UsageIdiom));
        }
    }

    fn mark_accumulator_sign(&mut self, sign: Sign) {
        let acc: TypeVar = self.reg_use(Register::RAX);
        self.constraints
            .push(Constraint::Sign(acc, sign, Confidence::UsageIdiom));
    }

    fn set_pending_cmp(&mut self, insn: &Instruction) {
        let a: Option<TypeVar> = self.operand_read_cell(insn, 0);
        let b: Option<TypeVar> = self.operand_read_cell(insn, 1);
        self.pending_cmp = Some((a, b));
    }

    fn apply_pending_sign(&mut self, sign: Sign) {
        let Some((a, b)): Option<(Option<TypeVar>, Option<TypeVar>)> = self.pending_cmp else {
            return;
        };
        if let Some(cell) = a {
            self.constraints
                .push(Constraint::Sign(cell, sign, Confidence::UsageIdiom));
        }
        if let Some(cell) = b {
            self.constraints
                .push(Constraint::Sign(cell, sign, Confidence::UsageIdiom));
        }
    }

    fn freshen_fresh_value_write(&mut self, insn: &Instruction) {
        if !fresh_value_write(insn.mnemonic()) || insn.op_kind(0) != OpKind::Register {
            return;
        }
        let dst_reg: Register = insn.op_register(0);
        if dst_reg.is_gpr() {
            let _fresh: TypeVar = self.reg_def(dst_reg);
        }
    }

    fn process(&mut self, insn: &Instruction) {
        self.current_ip = insn.ip();
        self.record_slot_width(insn);
        let mnemonic: Mnemonic = insn.mnemonic();
        match mnemonic {
            Mnemonic::Mov => self.handle_mov(insn),
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => self.handle_extend(insn),
            Mnemonic::Idiv => {
                self.mark_operand_sign(insn, 0, Sign::Signed);
                self.mark_accumulator_sign(Sign::Signed);
            }
            Mnemonic::Div => {
                self.mark_operand_sign(insn, 0, Sign::Unsigned);
                self.mark_accumulator_sign(Sign::Unsigned);
            }
            Mnemonic::Sar => self.mark_operand_sign(insn, 0, Sign::Signed),
            Mnemonic::Shr => self.mark_operand_sign(insn, 0, Sign::Unsigned),
            Mnemonic::Cdq | Mnemonic::Cqo | Mnemonic::Cwd => {
                self.mark_accumulator_sign(Sign::Signed);
            }
            _ => self.freshen_fresh_value_write(insn),
        }
        match mnemonic {
            Mnemonic::Cmp | Mnemonic::Test => self.set_pending_cmp(insn),
            _ => match signed_condition(insn.condition_code()) {
                Some(sign) => {
                    self.apply_pending_sign(sign);
                    self.pending_cmp = None;
                }
                None => {
                    if writes_comparison_flags(insn) {
                        self.pending_cmp = None;
                    }
                }
            },
        }
    }

    fn finish(self, rbp_slots: BTreeMap<i64, TypeVar>, has_frame_pointer: bool) -> FactSet {
        let (slots, ssa): (BTreeMap<i64, TypeVar>, MemSsa) = match self.resolver {
            SlotResolver::Merge(map) => (map, MemSsa::default()),
            SlotResolver::Split(ssa) => (rbp_slots, ssa),
        };
        FactSet {
            store: self.store,
            constraints: self.constraints,
            rbp_slots: slots,
            ssa,
            has_frame_pointer,
        }
    }
}

#[must_use]
pub fn extract(bytes: &[u8], base: u64) -> FactSet {
    extract_from(&decode_all(bytes, base))
}

#[must_use]
pub fn extract_split(bytes: &[u8], base: u64) -> FactSet {
    extract_split_from(&decode_all(bytes, base))
}

pub(crate) fn extract_from(instrs: &[Instruction]) -> FactSet {
    run(instrs, SlotMode::Merge)
}

pub(crate) fn extract_split_from(instrs: &[Instruction]) -> FactSet {
    run(instrs, SlotMode::Split)
}

fn run(instrs: &[Instruction], mode: SlotMode) -> FactSet {
    let has_frame_pointer: bool = detects_frame_pointer(instrs);
    let (store, resolver): (CellStore, SlotResolver) = match mode {
        SlotMode::Merge => (CellStore::new(), SlotResolver::Merge(BTreeMap::new())),
        SlotMode::Split => {
            let cfg: Cfg = cfg::build(instrs);
            let mut store: CellStore = CellStore::new();
            let ssa: MemSsa = memssa::build(instrs, &cfg, &mut store);
            (store, SlotResolver::Split(ssa))
        }
    };
    let mut extractor: Extractor = Extractor::new(store, resolver);
    for insn in instrs {
        extractor.process(insn);
    }
    extractor.finish(BTreeMap::new(), has_frame_pointer)
}

fn detects_frame_pointer(instrs: &[Instruction]) -> bool {
    let mut push_rbp: bool = false;
    for insn in instrs.iter().take(6) {
        match insn.mnemonic() {
            Mnemonic::Push
                if insn.op0_kind() == OpKind::Register && insn.op_register(0) == Register::RBP =>
            {
                push_rbp = true;
            }
            Mnemonic::Mov
                if push_rbp
                    && insn.op0_kind() == OpKind::Register
                    && insn.op1_kind() == OpKind::Register
                    && insn.op_register(0) == Register::RBP
                    && insn.op_register(1) == Register::RSP =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn rbp_slot_disp(insn: &Instruction) -> Option<i64> {
    if insn.memory_base() != Register::RBP || insn.memory_index() != Register::None {
        return None;
    }
    Some(i64::from_ne_bytes(
        insn.memory_displacement64().to_ne_bytes(),
    ))
}

fn memory_width(insn: &Instruction) -> Option<Width> {
    let size: usize = insn.memory_size().size();
    let bytes: u8 = u8::try_from(size).ok()?;
    match Width::from_bytes(bytes) {
        Width::Unknown => None,
        width => Some(width),
    }
}

const fn signed_condition(cc: ConditionCode) -> Option<Sign> {
    match cc {
        ConditionCode::l | ConditionCode::le | ConditionCode::g | ConditionCode::ge => {
            Some(Sign::Signed)
        }
        ConditionCode::b | ConditionCode::be | ConditionCode::a | ConditionCode::ae => {
            Some(Sign::Unsigned)
        }
        _ => None,
    }
}

const fn fresh_value_write(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Lea
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Lzcnt
            | Mnemonic::Tzcnt
            | Mnemonic::Popcnt
            | Mnemonic::Bsr
            | Mnemonic::Bsf
    )
}

const COMPARISON_FLAGS: u32 = RflagsBits::OF
    | RflagsBits::SF
    | RflagsBits::ZF
    | RflagsBits::AF
    | RflagsBits::CF
    | RflagsBits::PF;

fn writes_comparison_flags(insn: &Instruction) -> bool {
    (insn.rflags_modified() | insn.rflags_undefined()) & COMPARISON_FLAGS != 0
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::constraint::solve;

    fn width_sign_of(bytes: &[u8], disp: i64) -> Option<(Width, Sign)> {
        let mut facts: FactSet = extract(bytes, 0x1000);
        solve(&mut facts.store, &facts.constraints);
        let cell: TypeVar = *facts.rbp_slots.get(&disp)?;
        let resolved: crate::cells::CellType = facts.store.resolved(cell);
        Some((resolved.class.width(), resolved.class.sign()))
    }

    #[test]
    fn signed_shift_marks_qword_slot_signed() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x48, 0xc1,
            0xf8, 0x03, 0x5d, 0xc3,
        ];
        let result: Option<(Width, Sign)> = width_sign_of(bytes, 0x10);
        assert_eq!(result, Some((Width::Qword, Sign::Signed)));
    }

    #[test]
    fn unsigned_shift_marks_qword_slot_unsigned() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x48, 0xc1,
            0xe8, 0x03, 0x5d, 0xc3,
        ];
        let result: Option<(Width, Sign)> = width_sign_of(bytes, 0x10);
        assert_eq!(result, Some((Width::Qword, Sign::Unsigned)));
    }

    #[test]
    fn flag_writer_between_cmp_and_signed_jcc_drops_sign() {
        let without_flag_writer: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x39, 0x55, 0x10, 0x7c, 0x00, 0x5d, 0xc3,
        ];
        assert_eq!(
            width_sign_of(without_flag_writer, 0x10),
            Some((Width::Dword, Sign::Signed)),
        );
        let with_flag_writer: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x39, 0x55, 0x10, 0x0f, 0xba, 0xe0, 0x00, 0x7c, 0x00, 0x5d,
            0xc3,
        ];
        assert_eq!(
            width_sign_of(with_flag_writer, 0x10),
            Some((Width::Dword, Sign::Unknown)),
        );
    }

    #[test]
    fn split_mode_separates_conflicting_reuse() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x85, 0xc9, 0x7e, 0x0a, 0x48, 0x89, 0x4d, 0x00, 0x48, 0xc1,
            0x7d, 0x00, 0x02, 0xeb, 0x08, 0x48, 0x89, 0x45, 0x00, 0x48, 0xd1, 0x6d, 0x00, 0x48,
            0x8b, 0x45, 0x00, 0x5d, 0xc3,
        ];
        let mut facts: FactSet = extract_split(bytes, 0x1000);
        solve(&mut facts.store, &facts.constraints);
        let signs: Vec<Sign> = facts
            .ssa
            .versions()
            .iter()
            .filter(|v: &&crate::memssa::VersionInfo| v.rbp_disp == 0 && !v.is_phi && v.live_hi > 0)
            .map(|v: &crate::memssa::VersionInfo| facts.store.resolved(v.cell).class.sign())
            .collect();
        assert!(
            signs.contains(&Sign::Signed) && signs.contains(&Sign::Unsigned),
            "split must recover one signed and one unsigned definition: {signs:?}",
        );
    }
}
