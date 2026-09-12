use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    Instruction, InstructionInfo, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
    UsedMemory,
};

use crate::cfg::{self, Cfg};
use crate::decode::decode_all;
use crate::lattice::Width;
use crate::memssa::AccessKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldNameTier {
    Offset,
    Typed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamClass {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessFlags {
    pub read: bool,
    pub written: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredField {
    pub offset: i64,
    pub width: Width,
    pub access: AccessFlags,
    pub stride: Option<u32>,
    pub is_pointer: bool,
    pub name: String,
    pub name_tier: FieldNameTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredStruct {
    pub rbp_disp: i64,
    pub is_union: bool,
    pub param_class: ParamClass,
    pub fields: Vec<RecoveredField>,
}

impl RecoveredStruct {
    #[must_use]
    pub fn field_slots(&self) -> BTreeSet<(i64, Width)> {
        self.fields
            .iter()
            .filter(|field: &&RecoveredField| field.width != Width::Unknown)
            .map(|field: &RecoveredField| (field.offset, field.width))
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
enum Prov {
    Root {
        rbp_disp: i64,
        offset: i64,
        stride: Option<u32>,
    },
    Scaled {
        stride: u32,
    },
    Field {
        rbp_disp: i64,
        offset: i64,
    },
}

#[derive(Debug, Clone, Copy)]
struct Obs {
    ip: u64,
    offset: i64,
    width: Width,
    kind: AccessKind,
    stride: Option<u32>,
}

#[derive(Debug, Default)]
struct SlotAcc {
    obs: Vec<Obs>,
    pointer_fields: BTreeSet<i64>,
}

#[derive(Debug)]
struct Recoverer {
    factory: InstructionInfoFactory,
    regs: BTreeMap<Register, Prov>,
    slots: BTreeMap<i64, SlotAcc>,
}

impl Recoverer {
    fn new() -> Self {
        Self {
            factory: InstructionInfoFactory::new(),
            regs: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn step(&mut self, insn: &Instruction) {
        let (mems, writes): (Vec<UsedMemory>, Vec<Register>) = {
            let info: &InstructionInfo = self.factory.info(insn);
            let mems: Vec<UsedMemory> = info.used_memory().to_vec();
            let writes: Vec<Register> = info
                .used_registers()
                .iter()
                .filter(|reg: &&iced_x86::UsedRegister| is_write(reg.access()))
                .map(|reg: &iced_x86::UsedRegister| reg.register().full_register())
                .filter(|reg: &Register| reg.is_gpr())
                .collect();
            (mems, writes)
        };
        self.record_accesses(insn.ip(), &mems);
        let update: Option<(Register, Prov)> = self.classify_update(insn, &mems);
        self.apply_writes(&writes, update);
    }

    fn record_accesses(&mut self, ip: u64, mems: &[UsedMemory]) {
        for mem in mems {
            let base: Register = mem.base();
            if base == Register::None {
                continue;
            }
            let Some(prov): Option<Prov> = self.regs.get(&base.full_register()).copied() else {
                continue;
            };
            let Some(kind): Option<AccessKind> = access_kind(mem.access()) else {
                continue;
            };
            match prov {
                Prov::Root {
                    rbp_disp,
                    offset,
                    stride,
                } => {
                    let disp: i64 = displacement(mem);
                    let field_off: i64 = offset.saturating_add(disp);
                    let elem_stride: Option<u32> =
                        if mem.index() != Register::None && mem.scale() > 1 {
                            Some(mem.scale())
                        } else {
                            stride
                        };
                    let entry: &mut SlotAcc = self.slots.entry(rbp_disp).or_default();
                    entry.obs.push(Obs {
                        ip,
                        offset: field_off,
                        width: mem_width(mem),
                        kind,
                        stride: elem_stride,
                    });
                }
                Prov::Field { rbp_disp, offset } => {
                    self.slots
                        .entry(rbp_disp)
                        .or_default()
                        .pointer_fields
                        .insert(offset);
                }
                Prov::Scaled { .. } => {}
            }
        }
    }

    fn classify_update(&self, insn: &Instruction, mems: &[UsedMemory]) -> Option<(Register, Prov)> {
        match insn.mnemonic() {
            Mnemonic::Mov => self.classify_mov(insn, mems),
            Mnemonic::Lea => self.classify_lea(insn),
            Mnemonic::Add => self.classify_add(insn),
            _ => None,
        }
    }

    fn classify_mov(&self, insn: &Instruction, mems: &[UsedMemory]) -> Option<(Register, Prov)> {
        if insn.op_kind(0) != OpKind::Register || insn.op_kind(1) != OpKind::Memory {
            return None;
        }
        let dst: Register = insn.op_register(0).full_register();
        if !dst.is_gpr() {
            return None;
        }
        let mem: &UsedMemory = mems.iter().find(|mem: &&UsedMemory| {
            matches!(access_kind(mem.access()), Some(AccessKind::Load))
        })?;
        let base: Register = mem.base();
        if is_frame(base) && mem.index() == Register::None {
            return Some((
                dst,
                Prov::Root {
                    rbp_disp: displacement(mem),
                    offset: 0,
                    stride: None,
                },
            ));
        }
        let prov: Prov = *self.regs.get(&base.full_register())?;
        let Prov::Root {
            rbp_disp, offset, ..
        } = prov
        else {
            return None;
        };
        if mem.index() != Register::None || mem_width(mem) != Width::Qword {
            return None;
        }
        Some((
            dst,
            Prov::Field {
                rbp_disp,
                offset: offset.saturating_add(displacement(mem)),
            },
        ))
    }

    fn classify_lea(&self, insn: &Instruction) -> Option<(Register, Prov)> {
        if insn.op_kind(0) != OpKind::Register || insn.op_kind(1) != OpKind::Memory {
            return None;
        }
        let dst: Register = insn.op_register(0).full_register();
        if !dst.is_gpr() {
            return None;
        }
        let base: Register = insn.memory_base();
        let index: Register = insn.memory_index();
        if base == Register::None && index != Register::None && insn.memory_index_scale() > 1 {
            return Some((
                dst,
                Prov::Scaled {
                    stride: insn.memory_index_scale(),
                },
            ));
        }
        if index != Register::None {
            return None;
        }
        let prov: Prov = *self.regs.get(&base.full_register())?;
        let Prov::Root {
            rbp_disp,
            offset,
            stride,
        } = prov
        else {
            return None;
        };
        let disp: i64 = i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes());
        Some((
            dst,
            Prov::Root {
                rbp_disp,
                offset: offset.saturating_add(disp),
                stride,
            },
        ))
    }

    fn classify_add(&self, insn: &Instruction) -> Option<(Register, Prov)> {
        if insn.op_kind(0) != OpKind::Register || insn.op_kind(1) != OpKind::Register {
            return None;
        }
        let dst: Register = insn.op_register(0).full_register();
        let src: Register = insn.op_register(1).full_register();
        if !dst.is_gpr() || !src.is_gpr() {
            return None;
        }
        let dst_prov: Option<Prov> = self.regs.get(&dst).copied();
        let src_prov: Option<Prov> = self.regs.get(&src).copied();
        match (dst_prov, src_prov) {
            (
                Some(Prov::Root {
                    rbp_disp, offset, ..
                }),
                Some(Prov::Scaled { stride }),
            )
            | (
                Some(Prov::Scaled { stride }),
                Some(Prov::Root {
                    rbp_disp, offset, ..
                }),
            ) => Some((
                dst,
                Prov::Root {
                    rbp_disp,
                    offset,
                    stride: Some(stride),
                },
            )),
            _ => None,
        }
    }

    fn apply_writes(&mut self, writes: &[Register], update: Option<(Register, Prov)>) {
        let kept: Option<Register> = update.map(|(reg, _): (Register, Prov)| reg);
        for reg in writes {
            if Some(*reg) == kept {
                continue;
            }
            self.regs.remove(reg);
        }
        if let Some((reg, prov)) = update {
            self.regs.insert(reg, prov);
        }
    }

    fn finish(self) -> Vec<RecoveredStruct> {
        let mut out: Vec<RecoveredStruct> = Vec::new();
        for (rbp_disp, acc) in self.slots {
            if acc.obs.is_empty() {
                continue;
            }
            out.push(build_struct(rbp_disp, &acc));
        }
        out.sort_by_key(|item: &RecoveredStruct| item.rbp_disp);
        out
    }
}

fn build_struct(rbp_disp: i64, acc: &SlotAcc) -> RecoveredStruct {
    let mut widths_at: BTreeMap<i64, BTreeSet<Width>> = BTreeMap::new();
    for ob in &acc.obs {
        if ob.width == Width::Unknown {
            continue;
        }
        widths_at.entry(ob.offset).or_default().insert(ob.width);
    }
    let is_union: bool = widths_at
        .values()
        .any(|set: &BTreeSet<Width>| set.len() >= 2);
    let mut fields: Vec<RecoveredField> = Vec::new();
    for (offset, widths) in &widths_at {
        for width in widths {
            fields.push(build_field(acc, *offset, *width));
        }
    }
    fields.sort_by(|a: &RecoveredField, b: &RecoveredField| {
        (a.offset, a.width).cmp(&(b.offset, b.width))
    });
    RecoveredStruct {
        rbp_disp,
        is_union,
        param_class: param_class(acc),
        fields,
    }
}

fn build_field(acc: &SlotAcc, offset: i64, width: Width) -> RecoveredField {
    let mut access: AccessFlags = AccessFlags::default();
    let mut stride: Option<u32> = None;
    for ob in &acc.obs {
        if ob.offset != offset || ob.width != width {
            continue;
        }
        match ob.kind {
            AccessKind::Load => access.read = true,
            AccessKind::Store => access.written = true,
            AccessKind::Rmw => {
                access.read = true;
                access.written = true;
            }
        }
        if ob.stride.is_some() {
            stride = ob.stride;
        }
    }
    let is_pointer: bool = acc.pointer_fields.contains(&offset) && width == Width::Qword;
    let (name, name_tier): (String, FieldNameTier) = name_field(offset, is_pointer, stride);
    RecoveredField {
        offset,
        width,
        access,
        stride,
        is_pointer,
        name,
        name_tier,
    }
}

fn name_field(offset: i64, is_pointer: bool, stride: Option<u32>) -> (String, FieldNameTier) {
    if is_pointer {
        return (format!("p_{offset:#x}"), FieldNameTier::Typed);
    }
    if stride.is_some() {
        return (format!("arr_{offset:#x}"), FieldNameTier::Typed);
    }
    (format!("field_{offset:#x}"), FieldNameTier::Offset)
}

fn param_class(acc: &SlotAcc) -> ParamClass {
    let mut ordered: Vec<&Obs> = acc.obs.iter().collect();
    ordered.sort_by_key(|ob: &&Obs| ob.ip);
    let mut written: bool = false;
    let mut reads_input: bool = false;
    let mut stored_fields: BTreeSet<i64> = BTreeSet::new();
    for ob in ordered {
        match ob.kind {
            AccessKind::Load => {
                if !stored_fields.contains(&ob.offset) {
                    reads_input = true;
                }
            }
            AccessKind::Store => {
                written = true;
                stored_fields.insert(ob.offset);
            }
            AccessKind::Rmw => {
                if !stored_fields.contains(&ob.offset) {
                    reads_input = true;
                }
                written = true;
                stored_fields.insert(ob.offset);
            }
        }
    }
    match (reads_input, written) {
        (true, true) => ParamClass::InOut,
        (false, true) => ParamClass::Out,
        _ => ParamClass::In,
    }
}

const fn is_write(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

const fn access_kind(access: OpAccess) -> Option<AccessKind> {
    match access {
        OpAccess::Read | OpAccess::CondRead => Some(AccessKind::Load),
        OpAccess::Write | OpAccess::CondWrite => Some(AccessKind::Store),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(AccessKind::Rmw),
        OpAccess::None | OpAccess::NoMemAccess => None,
    }
}

fn is_frame(reg: Register) -> bool {
    matches!(reg.full_register(), Register::RBP | Register::RSP)
}

const fn displacement(mem: &UsedMemory) -> i64 {
    i64::from_ne_bytes(mem.displacement().to_ne_bytes())
}

fn mem_width(mem: &UsedMemory) -> Width {
    u8::try_from(mem.memory_size().size()).map_or(Width::Unknown, Width::from_bytes)
}

#[must_use]
pub fn recover_structs(bytes: &[u8], base: u64) -> Vec<RecoveredStruct> {
    recover_structs_from(&decode_all(bytes, base))
}

pub(crate) fn recover_structs_from(instrs: &[Instruction]) -> Vec<RecoveredStruct> {
    let cfg: Cfg = cfg::build(instrs);
    let leaders: BTreeSet<usize> = cfg
        .blocks
        .iter()
        .map(|block: &crate::cfg::BasicBlock| block.start)
        .collect();
    let mut recoverer: Recoverer = Recoverer::new();
    for (index, insn) in instrs.iter().enumerate() {
        if leaders.contains(&index) {
            recoverer.regs.clear();
        }
        recoverer.step(insn);
    }
    recoverer.finish()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn flat_struct_two_int_fields() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x8b, 0x10,
            0x48, 0x8b, 0x45, 0x10, 0x8b, 0x40, 0x04, 0x01, 0xd0, 0x5d, 0xc3,
        ];
        let structs: Vec<RecoveredStruct> = recover_structs(bytes, 0x1000);
        let point: &RecoveredStruct = structs
            .iter()
            .find(|item: &&RecoveredStruct| item.rbp_disp == 0x10)
            .expect("struct at slot 0x10");
        let slots: BTreeSet<(i64, Width)> = point.field_slots();
        assert!(slots.contains(&(0, Width::Dword)));
        assert!(slots.contains(&(4, Width::Dword)));
        assert_eq!(slots.len(), 2);
        assert!(!point.is_union);
    }

    #[test]
    fn union_offset_zero_has_two_widths() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x48, 0x8b,
            0x10, 0x48, 0x8b, 0x45, 0x10, 0x8b, 0x00, 0x5d, 0xc3,
        ];
        let structs: Vec<RecoveredStruct> = recover_structs(bytes, 0x1000);
        let un: &RecoveredStruct = structs
            .iter()
            .find(|item: &&RecoveredStruct| item.rbp_disp == 0x10)
            .expect("struct at slot 0x10");
        assert!(un.is_union, "offset 0 with two widths is a union");
        let slots: BTreeSet<(i64, Width)> = un.field_slots();
        assert!(slots.contains(&(0, Width::Qword)));
        assert!(slots.contains(&(0, Width::Dword)));
    }

    #[test]
    fn no_struct_when_pointer_never_dereferenced() {
        let bytes: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x5d, 0xc3];
        let structs: Vec<RecoveredStruct> = recover_structs(bytes, 0x1000);
        assert!(structs.is_empty(), "an un-dereferenced slot is no struct");
    }

    #[test]
    fn write_before_read_field_is_out_param() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x89, 0x10,
            0x8b, 0x08, 0x5d, 0xc3,
        ];
        let structs: Vec<RecoveredStruct> = recover_structs(bytes, 0x1000);
        let out: &RecoveredStruct = structs
            .iter()
            .find(|item: &&RecoveredStruct| item.rbp_disp == 0x10)
            .expect("struct at slot 0x10");
        assert_eq!(out.param_class, ParamClass::Out);
    }

    #[test]
    fn read_before_write_field_is_inout_param() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x4d, 0x10, 0x48, 0x8b, 0x45, 0x10, 0x8b, 0x08,
            0x89, 0x10, 0x5d, 0xc3,
        ];
        let structs: Vec<RecoveredStruct> = recover_structs(bytes, 0x1000);
        let inout: &RecoveredStruct = structs
            .iter()
            .find(|item: &&RecoveredStruct| item.rbp_disp == 0x10)
            .expect("struct at slot 0x10");
        assert_eq!(inout.param_class, ParamClass::InOut);
    }
}
