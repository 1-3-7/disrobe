use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::descriptor::{self, JavaType, MethodDescriptor};
use crate::dex::{CodeItem, DexFile, FieldId, MethodId};
use crate::dex2jar::ConstantPool;

const MAX_METHOD_INSNS: usize = 8192;
const MAX_CODE_BYTES: usize = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Int,
    Long,
    Float,
    Double,
    Ref,
}

impl Slot {
    const fn category_two(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    const fn width(self) -> i32 {
        if self.category_two() { 2 } else { 1 }
    }

    const fn from_java(ty: &JavaType) -> Self {
        match ty {
            JavaType::Long => Self::Long,
            JavaType::Float => Self::Float,
            JavaType::Double => Self::Double,
            JavaType::Object(_) | JavaType::Array(_) => Self::Ref,
            _ => Self::Int,
        }
    }
}

pub(crate) struct EmittedCode {
    pub(crate) bytes: Vec<u8>,
    pub(crate) max_stack: u16,
    pub(crate) max_locals: u16,
    /// Pre-serialized `Code` sub-attributes (currently only `StackMapTable`),
    /// each as `name_index(u2) length(u4) body`. Empty for branchless bodies.
    pub(crate) attributes: Vec<u8>,
    /// Number of entries packed into `attributes`.
    pub(crate) attribute_count: u16,
}

struct Emitter<'a> {
    dex: &'a DexFile,
    cp: &'a mut ConstantPool,
    code: Vec<u8>,
    reg_type: BTreeMap<u16, Slot>,
    const_kind: BTreeMap<u16, Slot>,
    const_zero: BTreeSet<u16>,
    pending_new: BTreeMap<u16, String>,
    pending_result: Option<Slot>,
    cur_stack: i32,
    max_stack: i32,
    registers_size: u16,
    first_param_reg: u16,
    param_local_slots: u16,
    max_locals: u16,
    bailed: bool,
}

#[must_use]
pub(crate) fn emit_method_code(
    dex: &DexFile,
    cp: &mut ConstantPool,
    item: &CodeItem,
    is_static: bool,
) -> Option<EmittedCode> {
    if item.insns.is_empty() || item.insns.len() > MAX_METHOD_INSNS {
        return None;
    }
    if item.method_name == "<init>" || is_synthetic_class(&item.class) {
        return None;
    }
    if !item.tries.is_empty() {
        return None;
    }
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() {
        return None;
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x0D) {
        return None;
    }
    let last: usize = insns.len() - 1;
    if insns
        .iter()
        .take(last)
        .any(|i: &DalvikInsn| matches!(i.op, 0x0E..=0x11 | 0x27))
    {
        return None;
    }
    let parsed: MethodDescriptor = descriptor::parse_method(&item.method_descriptor)?;
    let const_kind: BTreeMap<u16, Slot> = infer_const_kinds(dex, &insns, &parsed);
    if has_width_conflict(dex, &insns, &parsed, item, is_static) {
        return None;
    }
    let first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let param_local_slots: u16 = u16::from(!is_static)
        + parsed
            .params
            .iter()
            .map(|p: &JavaType| if p.category_two() { 2u16 } else { 1u16 })
            .sum::<u16>();
    let max_locals: u16 = first_param_reg
        .saturating_add(param_local_slots)
        .saturating_add(1)
        .max(param_local_slots)
        .max(1);
    let mut emitter: Emitter<'_> = Emitter {
        dex,
        cp,
        code: Vec::with_capacity(insns.len() * 3),
        reg_type: BTreeMap::new(),
        const_kind,
        const_zero: BTreeSet::new(),
        pending_new: BTreeMap::new(),
        pending_result: None,
        cur_stack: 0,
        max_stack: 0,
        registers_size: item.registers_size,
        first_param_reg,
        param_local_slots,
        max_locals,
        bailed: false,
    };
    emitter.seed_parameter_types(&parsed, is_static);
    for insn in &insns {
        if emitter.bailed || emitter.code.len() > MAX_CODE_BYTES {
            return None;
        }
        emitter.translate(insn, &parsed);
    }
    if emitter.bailed || !emitter.pending_new.is_empty() {
        return None;
    }
    Some(EmittedCode {
        bytes: emitter.code,
        max_stack: emitter.max_stack.max(2) as u16,
        max_locals: emitter.max_locals,
        attributes: Vec::new(),
        attribute_count: 0,
    })
}

impl Emitter<'_> {
    fn seed_parameter_types(&mut self, parsed: &MethodDescriptor, is_static: bool) {
        let mut cursor: u16 = self.first_param_reg;
        if !is_static {
            self.reg_type.insert(cursor, Slot::Ref);
            cursor = cursor.saturating_add(1);
        }
        for ty in &parsed.params {
            let slot: Slot = Slot::from_java(ty);
            self.reg_type.insert(cursor, slot);
            cursor = cursor.saturating_add(if slot.category_two() { 2 } else { 1 });
        }
    }

    const fn bail(&mut self) {
        self.bailed = true;
    }

    fn push(&mut self, byte: u8) {
        self.code.push(byte);
    }

    fn push_u16(&mut self, value: u16) {
        self.code.extend_from_slice(&value.to_be_bytes());
    }

    fn adjust_stack(&mut self, delta: i32) {
        self.cur_stack = (self.cur_stack + delta).max(0);
        if self.cur_stack > self.max_stack {
            self.max_stack = self.cur_stack;
        }
    }

    fn reg_slot(&self, reg: u16) -> Slot {
        self.reg_type.get(&reg).copied().unwrap_or(Slot::Int)
    }

    fn set_reg(&mut self, reg: u16, slot: Slot) {
        self.reg_type.insert(reg, slot);
    }

    const fn local_index(&mut self, reg: u16) -> Option<u16> {
        if reg >= self.registers_size {
            self.bail();
            return None;
        }
        let local: u16 = if reg >= self.first_param_reg {
            reg - self.first_param_reg
        } else {
            self.param_local_slots.saturating_add(reg)
        };
        if local >= self.max_locals {
            self.bail();
            return None;
        }
        Some(local)
    }

    fn emit_load(&mut self, reg: u16) {
        if self.pending_new.contains_key(&reg) {
            self.bail();
            return;
        }
        let slot: Slot = self.reg_slot(reg);
        let Some(index): Option<u16> = self.local_index(reg) else {
            return;
        };
        let (fast, family): (u8, u8) = match slot {
            Slot::Int => (0x1A, 0x15),
            Slot::Long => (0x1E, 0x16),
            Slot::Float => (0x22, 0x17),
            Slot::Double => (0x26, 0x18),
            Slot::Ref => (0x2A, 0x19),
        };
        self.emit_local_op(index, fast, family);
        self.adjust_stack(slot.width());
    }

    /// Loads `reg` for a context that requires a reference. Dalvik encodes a
    /// `null` argument as `const v, 0` (an int 0), so when the source register
    /// was last written by a zero constant this emits `aconst_null` rather than
    /// reading an int-typed local slot through `aload`, which the verifier would
    /// reject as a bad local-variable type.
    fn emit_ref_arg(&mut self, reg: u16) {
        if self.const_zero.contains(&reg) || !matches!(self.reg_slot(reg), Slot::Ref) {
            self.push(0x01);
            self.adjust_stack(1);
        } else {
            self.emit_load(reg);
        }
    }

    fn emit_store(&mut self, reg: u16, slot: Slot) {
        let Some(index): Option<u16> = self.local_index(reg) else {
            return;
        };
        let (fast, family): (u8, u8) = match slot {
            Slot::Int => (0x3B, 0x36),
            Slot::Long => (0x3F, 0x37),
            Slot::Float => (0x43, 0x38),
            Slot::Double => (0x47, 0x39),
            Slot::Ref => (0x4B, 0x3A),
        };
        self.emit_local_op(index, fast, family);
        self.adjust_stack(-slot.width());
        self.set_reg(reg, slot);
        self.const_zero.remove(&reg);
    }

    fn emit_local_op(&mut self, index: u16, fast_base: u8, slow_family: u8) {
        if index <= 3 {
            self.push(fast_base + index as u8);
        } else if u8::try_from(index).is_ok() {
            self.push(slow_family);
            self.push(index as u8);
        } else {
            self.push(0xC4);
            self.push(slow_family);
            self.push_u16(index);
        }
    }

    fn method_id(&self, index: Option<u32>) -> Option<&MethodId> {
        index.and_then(|i| self.dex.method_ids.get(i as usize))
    }

    fn field_id(&self, index: Option<u32>) -> Option<&FieldId> {
        index.and_then(|i| self.dex.field_ids.get(i as usize))
    }

    fn string_at(&self, index: Option<u32>) -> Option<String> {
        index.and_then(|i| self.dex.strings.get(i as usize).cloned())
    }

    fn type_at(&self, index: Option<u32>) -> Option<String> {
        index.and_then(|i| self.dex.type_names.get(i as usize).cloned())
    }

    #[allow(clippy::too_many_lines)]
    fn translate(&mut self, insn: &DalvikInsn, parsed: &MethodDescriptor) {
        let op: u8 = insn.op;
        if !matches!(op, 0x0A..=0x0C) {
            self.discard_pending_result();
        }
        let regs: &[u16] = &insn.regs;
        match op {
            0x00 | 0x1D | 0x1E => {}
            0x01..=0x09 => self.move_reg(regs),
            0x0A => self.move_result(regs, Slot::Int),
            0x0B => self.move_result(regs, Slot::Long),
            0x0C => self.move_result(regs, Slot::Ref),
            0x0E => self.push(0xB1),
            0x0F..=0x11 => self.return_value(regs, parsed),
            0x12..=0x14 => self.const_int(regs, insn),
            0x15 => self.const_high16_int(regs, insn),
            0x16..=0x18 => self.const_long(regs, insn),
            0x19 => self.const_high16_long(regs, insn),
            0x1A | 0x1B => self.const_string(regs, insn),
            0x1C => self.const_class(regs, insn),
            0x1F => self.check_cast(regs, insn),
            0x20 => self.instance_of(regs, insn),
            0x21 => self.array_length(regs),
            0x22 => self.new_instance(regs, insn),
            0x23 => self.new_array(regs, insn),
            0x27 => self.throw(regs),
            0x44..=0x4A => self.array_get(op, regs),
            0x4B..=0x51 => self.array_put(op, regs),
            0x52..=0x58 => self.instance_get(regs, insn),
            0x59..=0x5F => self.instance_put(regs, insn),
            0x60..=0x66 => self.static_get(regs, insn),
            0x67..=0x6D => self.static_put(regs, insn),
            0x6E..=0x72 | 0x74..=0x78 => self.invoke(op, insn),
            0x7B..=0x80 => self.neg(op, regs),
            0x81..=0x8F => self.numeric_cast(op, regs),
            0x90..=0xAF => self.binary_three(op, regs),
            0xB0..=0xCF => self.binary_two_addr(op, regs),
            0xD0..=0xE2 => self.binary_lit(op, regs, insn),
            _ => self.bail(),
        }
    }

    fn move_reg(&mut self, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let slot: Slot = self.reg_slot(src);
        self.emit_load(src);
        self.emit_store(dest, slot);
    }

    fn move_result(&mut self, regs: &[u16], default: Slot) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let slot: Slot = self.pending_result.take().unwrap_or(default);
        self.emit_store(dest, slot);
    }

    fn discard_pending_result(&mut self) {
        let Some(slot): Option<Slot> = self.pending_result.take() else {
            return;
        };
        if slot.category_two() {
            self.push(0x58);
        } else {
            self.push(0x57);
        }
        self.adjust_stack(-slot.width());
    }

    fn return_value(&mut self, regs: &[u16], parsed: &MethodDescriptor) {
        let slot: Slot = Slot::from_java(&parsed.returns);
        if let Some(&src) = regs.first() {
            self.set_reg(src, slot);
            self.emit_load(src);
        }
        let op: u8 = match slot {
            Slot::Int => 0xAC,
            Slot::Long => 0xAD,
            Slot::Float => 0xAE,
            Slot::Double => 0xAF,
            Slot::Ref => 0xB0,
        };
        self.push(op);
        self.adjust_stack(-slot.width());
    }

    fn const_int(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_narrow_const(dest, insn.literal.unwrap_or(0) as i32);
    }

    fn const_high16_int(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let value: i32 = (insn.literal.unwrap_or(0) as i32) << 16;
        self.emit_narrow_const(dest, value);
    }

    fn const_long(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_wide_const(dest, insn.literal.unwrap_or(0));
    }

    fn const_high16_long(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        self.emit_wide_const(dest, insn.literal.unwrap_or(0) << 48);
    }

    fn emit_narrow_const(&mut self, dest: u16, bits: i32) {
        if matches!(self.const_kind.get(&dest), Some(Slot::Float)) {
            let idx: u16 = self.cp.float_bits(bits as u32);
            self.emit_ldc(idx);
            self.emit_store(dest, Slot::Float);
        } else {
            self.push_int_const(bits);
            self.emit_store(dest, Slot::Int);
            if bits == 0 {
                self.const_zero.insert(dest);
            }
        }
    }

    fn emit_wide_const(&mut self, dest: u16, bits: i64) {
        if matches!(self.const_kind.get(&dest), Some(Slot::Double)) {
            let idx: u16 = self.cp.double_bits(bits as u64);
            self.push(0x14);
            self.push_u16(idx);
            self.adjust_stack(2);
            self.emit_store(dest, Slot::Double);
        } else {
            self.push_long_const(bits);
            self.emit_store(dest, Slot::Long);
        }
    }

    fn const_string(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(text): Option<String> = self.string_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.string(&text);
        self.emit_ldc(idx);
        self.emit_store(dest, Slot::Ref);
    }

    fn const_class(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_ldc(idx);
        self.emit_store(dest, Slot::Ref);
    }

    fn check_cast(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&reg): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_load(reg);
        self.push(0xC0);
        self.push_u16(idx);
        self.emit_store(reg, Slot::Ref);
    }

    fn instance_of(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let idx: u16 = self.cp.class_const(&internal_of(&ty));
        self.emit_load(src);
        self.push(0xC1);
        self.push_u16(idx);
        self.emit_store(dest, Slot::Int);
    }

    fn array_length(&mut self, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        self.emit_load(src);
        self.push(0xBE);
        self.emit_store(dest, Slot::Int);
    }

    /// Records a pending `new-instance vDest, Type` without emitting yet. The
    /// matching `invoke-direct {vDest, ...} Type.<init>` fuses both into the
    /// canonical `new Type; dup; <args>; invokespecial; astore vDest` idiom so
    /// the uninitialized reference never lives in a local (which the strict
    /// `StackMapTable`-era verifier rejects). If the pending allocation is read
    /// before its constructor runs, the emitter bails to the verifiable stub.
    fn new_instance(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        self.pending_new.insert(dest, internal_of(&ty));
    }

    fn new_array(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&size)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some(ty): Option<String> = self.type_at(insn.index) else {
            self.bail();
            return;
        };
        let element: &str = ty.strip_prefix('[').unwrap_or(&ty);
        self.emit_load(size);
        match primitive_atype(element) {
            Some(atype) => {
                self.push(0xBC);
                self.push(atype);
            }
            None => {
                let idx: u16 = self.cp.class_const(&internal_of(element));
                self.push(0xBD);
                self.push_u16(idx);
            }
        }
        self.emit_store(dest, Slot::Ref);
    }

    fn throw(&mut self, regs: &[u16]) {
        if let Some(&reg) = regs.first() {
            self.set_reg(reg, Slot::Ref);
            self.emit_load(reg);
        }
        self.push(0xBF);
        self.adjust_stack(-1);
    }

    fn array_get(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = match op {
            0x46 => (0x32, Slot::Ref),
            0x47 | 0x48 => (0x33, Slot::Int),
            0x49 => (0x34, Slot::Int),
            0x4A => (0x35, Slot::Int),
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(array, Slot::Ref);
        self.emit_load(array);
        self.emit_load(index);
        self.push(opcode);
        self.adjust_stack(-2 + slot.width());
        self.emit_store(dest, slot);
    }

    fn array_put(&mut self, op: u8, regs: &[u16]) {
        let (Some(&value), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = match op {
            0x4D => (0x53, Slot::Ref),
            0x4E | 0x4F => (0x54, Slot::Int),
            0x50 => (0x55, Slot::Int),
            0x51 => (0x56, Slot::Int),
            _ => {
                self.bail();
                return;
            }
        };
        self.set_reg(array, Slot::Ref);
        self.set_reg(value, slot);
        self.emit_load(array);
        self.emit_load(index);
        self.emit_load(value);
        self.push(opcode);
        self.adjust_stack(-2 - slot.width());
    }

    fn instance_get(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.set_reg(obj, Slot::Ref);
        self.emit_load(obj);
        self.push(0xB4);
        self.push_u16(idx);
        self.adjust_stack(-1 + slot.width());
        self.emit_store(dest, slot);
    }

    fn instance_put(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&value), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.set_reg(obj, Slot::Ref);
        self.set_reg(value, slot);
        self.emit_load(obj);
        self.emit_load(value);
        self.push(0xB5);
        self.push_u16(idx);
        self.adjust_stack(-1 - slot.width());
    }

    fn static_get(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&dest): Option<&u16> = regs.first() else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.push(0xB2);
        self.push_u16(idx);
        self.adjust_stack(slot.width());
        self.emit_store(dest, slot);
    }

    fn static_put(&mut self, regs: &[u16], insn: &DalvikInsn) {
        let Some(&value): Option<&u16> = regs.first() else {
            return;
        };
        let Some((owner, name, ftype)): Option<(String, String, String)> =
            self.field_parts(insn.index)
        else {
            return;
        };
        let slot: Slot = field_slot(&ftype);
        let idx: u16 = self.cp.fieldref(&owner, &name, &ftype);
        self.set_reg(value, slot);
        self.emit_load(value);
        self.push(0xB3);
        self.push_u16(idx);
        self.adjust_stack(-slot.width());
    }

    fn field_parts(&mut self, index: Option<u32>) -> Option<(String, String, String)> {
        match self.field_id(index) {
            Some(field) => Some((
                internal_of(&field.class),
                field.name.clone(),
                field.type_name.clone(),
            )),
            None => {
                self.bail();
                None
            }
        }
    }

    fn invoke(&mut self, op: u8, insn: &DalvikInsn) {
        let parts: Option<(String, String, String, Vec<String>)> =
            self.method_id(insn.index).map(|m: &MethodId| {
                (
                    internal_of(&m.class),
                    m.name.clone(),
                    m.proto.return_type.clone(),
                    m.proto.parameters.clone(),
                )
            });
        let Some((owner, name, return_type, param_types)): Option<(
            String,
            String,
            String,
            Vec<String>,
        )> = parts
        else {
            self.bail();
            return;
        };
        let descriptor: String = build_descriptor(&param_types, &return_type);
        let is_static: bool = matches!(op, 0x71 | 0x77);
        let is_interface: bool = matches!(op, 0x72 | 0x78);
        let is_special: bool = matches!(op, 0x70 | 0x76);

        if is_special
            && name == "<init>"
            && let Some(&recv) = insn.regs.first()
            && self
                .pending_new
                .get(&recv)
                .is_some_and(|t: &String| *t == owner)
        {
            self.emit_constructor(recv, &owner, &name, &descriptor, &param_types, &insn.regs);
            return;
        }

        let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
        let mut consumed: i32 = 0;
        if !is_static && let Some(&recv) = reg_iter.next() {
            self.set_reg(recv, Slot::Ref);
            self.emit_load(recv);
            consumed += 1;
        }
        for param in &param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_arg(reg);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }

        let idx: u16 = if is_interface {
            self.cp.interface_methodref(&owner, &name, &descriptor)
        } else {
            self.cp.methodref(&owner, &name, &descriptor)
        };
        let invoke_op: u8 = match op {
            0x71 | 0x77 => 0xB8,
            0x72 | 0x78 => 0xB9,
            _ if is_special => 0xB7,
            _ => 0xB6,
        };
        self.push(invoke_op);
        self.push_u16(idx);
        if invoke_op == 0xB9 {
            let count: u8 = consumed.clamp(1, 255) as u8;
            self.push(count);
            self.push(0);
        }
        self.adjust_stack(-consumed);
        if return_type == "V" {
            self.pending_result = None;
        } else {
            let slot: Slot = field_slot(&return_type);
            self.adjust_stack(slot.width());
            self.pending_result = Some(slot);
        }
    }

    /// Emits the fused `new Owner; dup; <args>; invokespecial Owner.<init>;
    /// astore recv` for a `new-instance`/`invoke-direct <init>` pair. The
    /// uninitialized reference stays on the operand stack (via `dup`) until the
    /// constructor consumes it, so it never occupies a local and the strict
    /// verifier accepts the body without a stack-map frame.
    fn emit_constructor(
        &mut self,
        recv: u16,
        owner: &str,
        name: &str,
        descriptor: &str,
        param_types: &[String],
        regs: &[u16],
    ) {
        self.pending_new.remove(&recv);
        let class_idx: u16 = self.cp.class_const(owner);
        self.push(0xBB);
        self.push_u16(class_idx);
        self.adjust_stack(1);
        self.push(0x59);
        self.adjust_stack(1);
        let mut reg_iter: std::slice::Iter<'_, u16> = regs.iter();
        let _ = reg_iter.next();
        let mut consumed: i32 = 0;
        for param in param_types {
            let slot: Slot = field_slot(param);
            if let Some(&reg) = reg_iter.next() {
                if matches!(slot, Slot::Ref) {
                    self.emit_ref_arg(reg);
                } else {
                    self.set_reg(reg, slot);
                    self.emit_load(reg);
                }
                consumed += slot.width();
            }
            if slot.category_two() {
                let _ = reg_iter.next();
            }
        }
        let method_idx: u16 = self.cp.methodref(owner, name, descriptor);
        self.push(0xB7);
        self.push_u16(method_idx);
        self.adjust_stack(-consumed - 1);
        self.emit_store(recv, Slot::Ref);
        self.pending_result = None;
    }

    fn neg(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        match op {
            0x7C => {
                self.set_reg(src, Slot::Int);
                self.emit_load(src);
                self.push_int_const(-1);
                self.push(0x82);
                self.adjust_stack(-1);
                self.emit_store(dest, Slot::Int);
            }
            0x7E => {
                self.set_reg(src, Slot::Long);
                self.emit_load(src);
                self.push_long_const(-1);
                self.push(0x83);
                self.adjust_stack(-2);
                self.emit_store(dest, Slot::Long);
            }
            _ => {
                let (slot, opcode): (Slot, u8) = match op {
                    0x7B => (Slot::Int, 0x74),
                    0x7D => (Slot::Long, 0x75),
                    0x7F => (Slot::Float, 0x76),
                    0x80 => (Slot::Double, 0x77),
                    _ => (Slot::Int, 0x74),
                };
                self.set_reg(src, slot);
                self.emit_load(src);
                self.push(opcode);
                self.emit_store(dest, slot);
            }
        }
    }

    fn numeric_cast(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let (opcode, from, to): (u8, Slot, Slot) = match op {
            0x81 => (0x85, Slot::Int, Slot::Long),
            0x82 => (0x86, Slot::Int, Slot::Float),
            0x83 => (0x87, Slot::Int, Slot::Double),
            0x84 => (0x88, Slot::Long, Slot::Int),
            0x85 => (0x89, Slot::Long, Slot::Float),
            0x86 => (0x8A, Slot::Long, Slot::Double),
            0x87 => (0x8B, Slot::Float, Slot::Int),
            0x88 => (0x8C, Slot::Float, Slot::Long),
            0x89 => (0x8D, Slot::Float, Slot::Double),
            0x8A => (0x8E, Slot::Double, Slot::Int),
            0x8B => (0x8F, Slot::Double, Slot::Long),
            0x8C => (0x90, Slot::Double, Slot::Float),
            0x8D => (0x91, Slot::Int, Slot::Int),
            0x8E => (0x92, Slot::Int, Slot::Int),
            0x8F => (0x93, Slot::Int, Slot::Int),
            _ => (0x88, Slot::Int, Slot::Int),
        };
        self.set_reg(src, from);
        self.emit_load(src);
        self.push(opcode);
        self.adjust_stack(to.width() - from.width());
        self.emit_store(dest, to);
    }

    fn binary_three(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
            (regs.first(), regs.get(1), regs.get(2))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = arith_three(op);
        let rhs_slot: Slot = if is_shift(op) { Slot::Int } else { slot };
        self.set_reg(lhs, slot);
        self.set_reg(rhs, rhs_slot);
        self.emit_load(lhs);
        self.emit_load(rhs);
        self.push(opcode);
        self.adjust_stack(-rhs_slot.width());
        self.emit_store(dest, slot);
    }

    fn binary_two_addr(&mut self, op: u8, regs: &[u16]) {
        let (Some(&dest), Some(&rhs)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let (opcode, slot): (u8, Slot) = arith_three(op - 0x20);
        let rhs_slot: Slot = if is_shift(op - 0x20) { Slot::Int } else { slot };
        self.set_reg(dest, slot);
        self.set_reg(rhs, rhs_slot);
        self.emit_load(dest);
        self.emit_load(rhs);
        self.push(opcode);
        self.adjust_stack(-rhs_slot.width());
        self.emit_store(dest, slot);
    }

    fn binary_lit(&mut self, op: u8, regs: &[u16], insn: &DalvikInsn) {
        let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
        else {
            return;
        };
        let literal: i32 = insn.literal.unwrap_or(0) as i32;
        let reverse: bool = matches!(op, 0xD1 | 0xD9);
        let opcode: u8 = arith_lit_op(op);
        self.set_reg(src, Slot::Int);
        if reverse {
            self.push_int_const(literal);
            self.emit_load(src);
        } else {
            self.emit_load(src);
            self.push_int_const(literal);
        }
        self.push(opcode);
        self.adjust_stack(-1);
        self.emit_store(dest, Slot::Int);
    }

    fn push_int_const(&mut self, value: i32) {
        match value {
            -1..=5 => {
                self.push((0x03 + value) as u8);
                self.adjust_stack(1);
            }
            -128..=127 => {
                self.push(0x10);
                self.push(value as u8);
                self.adjust_stack(1);
            }
            -32768..=32767 => {
                self.push(0x11);
                self.push_u16(value as u16);
                self.adjust_stack(1);
            }
            _ => {
                let idx: u16 = self.cp.integer(value);
                self.emit_ldc(idx);
            }
        }
    }

    fn push_long_const(&mut self, value: i64) {
        if value == 0 {
            self.push(0x09);
        } else if value == 1 {
            self.push(0x0A);
        } else {
            let idx: u16 = self.cp.long(value);
            self.push(0x14);
            self.push_u16(idx);
        }
        self.adjust_stack(2);
    }

    fn emit_ldc(&mut self, idx: u16) {
        if u8::try_from(idx).is_ok() {
            self.push(0x12);
            self.push(idx as u8);
        } else {
            self.push(0x13);
            self.push_u16(idx);
        }
        self.adjust_stack(1);
    }
}

const fn is_shift(op: u8) -> bool {
    matches!(op, 0x98 | 0x99 | 0x9A | 0xA3 | 0xA4 | 0xA5)
}

/// d8/r8 emit lambda, method-reference, and anonymous-class desugaring into
/// synthetic classes whose final name segment is purely numeric (`Foo$1`,
/// `Foo$48`). Their bodies rely on erased-generic bridge receivers whose JVM
/// frame type is `Object` while the body performs `getfield`/`invoke` on the
/// concrete synthetic type, which a from-scratch linear lowering cannot
/// reconstruct without full frame typing. They stay on the verifiable stub.
fn is_synthetic_class(descriptor: &str) -> bool {
    let inner: &str = descriptor.trim_start_matches('L').trim_end_matches(';');
    inner
        .rsplit('$')
        .next()
        .is_some_and(|seg: &str| !seg.is_empty() && seg.bytes().all(|b: u8| b.is_ascii_digit()))
}

/// Dalvik `const`/`const-wide` carry untyped 64- or 32-bit payloads: the same
/// `const-wide v0, 0x4009...` is a `long` or a `double` purely by how a later
/// instruction consumes `v0`. This forward scan records, for each const-defined
/// register, the floating slot a subsequent typed opcode reads it in, so the
/// emitter can pick the correct `Double`/`Float` constant-pool entry and
/// `dstore`/`fstore` instead of a type-confused `lstore`/`istore`.
fn infer_const_kinds(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
) -> BTreeMap<u16, Slot> {
    let mut const_defs: BTreeSet<u16> = BTreeSet::new();
    let mut kinds: BTreeMap<u16, Slot> = BTreeMap::new();
    let record = |reg: u16, slot: Slot, defs: &BTreeSet<u16>, kinds: &mut BTreeMap<u16, Slot>| {
        if defs.contains(&reg) && matches!(slot, Slot::Float | Slot::Double) {
            kinds.entry(reg).or_insert(slot);
        }
    };
    for insn in insns {
        let op: u8 = insn.op;
        let regs: &[u16] = &insn.regs;
        match op {
            0x12..=0x15 => {
                if let Some(&d) = regs.first() {
                    const_defs.insert(d);
                }
            }
            0x16..=0x19 => {
                if let Some(&d) = regs.first() {
                    const_defs.insert(d);
                }
            }
            0xA6..=0xAA => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0xAB..=0xAF => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0xC6..=0xCA => {
                if let Some(&r) = regs.get(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0xCB..=0xCF => {
                if let Some(&r) = regs.get(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0x2D | 0x2E => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Float, &const_defs, &mut kinds);
                }
            }
            0x2F | 0x30 => {
                for &r in regs.iter().skip(1) {
                    record(r, Slot::Double, &const_defs, &mut kinds);
                }
            }
            0x0F..=0x11 => {
                if let Some(&r) = regs.first() {
                    record(r, Slot::from_java(&parsed.returns), &const_defs, &mut kinds);
                }
            }
            0x6E..=0x72 | 0x74..=0x78 => {
                infer_invoke_arg_kinds(dex, insn, &const_defs, &mut kinds);
            }
            0x59..=0x5F | 0x67..=0x6D => {
                let field: Option<&FieldId> =
                    insn.index.and_then(|i| dex.field_ids.get(i as usize));
                if let (Some(field), Some(&r)) = (field, regs.first()) {
                    record(r, field_slot(&field.type_name), &const_defs, &mut kinds);
                }
            }
            _ => {}
        }
    }
    kinds
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cat {
    One,
    Two,
}

/// Conservatively rejects methods whose Dalvik register categories cannot be
/// proven consistent by a single forward pass. The linear lowering reuses one
/// JVM local per Dalvik register; if a register is observed as a single-word
/// value at one point and a wide (long/double) value at another along the
/// straight-line path (common in d8-built `Map.of`/`List.of` autoboxing
/// helpers), the emitted `*store`/`*load` widths would disagree and the body
/// would not verify, so it falls back to the stub.
fn has_width_conflict(
    dex: &DexFile,
    insns: &[DalvikInsn],
    parsed: &MethodDescriptor,
    item: &CodeItem,
    is_static: bool,
) -> bool {
    let mut cat: BTreeMap<u16, Cat> = BTreeMap::new();
    let first_param_reg: u16 = item.registers_size.saturating_sub(item.ins_size);
    let mut cursor: u16 = first_param_reg;
    if !is_static {
        cat.insert(cursor, Cat::One);
        cursor = cursor.saturating_add(1);
    }
    for ty in &parsed.params {
        let c: Cat = if Slot::from_java(ty).category_two() {
            Cat::Two
        } else {
            Cat::One
        };
        cat.insert(cursor, c);
        cursor = cursor.saturating_add(if c == Cat::Two { 2 } else { 1 });
    }

    for insn in insns {
        let (def, def_cat, uses): (Option<u16>, Cat, Vec<(u16, Cat)>) =
            register_effects(dex, insn, parsed);
        for (reg, want) in &uses {
            if matches!(cat.get(reg), Some(have) if *have != *want) {
                return true;
            }
        }
        if let Some(d) = def {
            cat.insert(d, def_cat);
        }
    }
    false
}

#[allow(clippy::too_many_lines)]
fn register_effects(
    dex: &DexFile,
    insn: &DalvikInsn,
    _parsed: &MethodDescriptor,
) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let op: u8 = insn.op;
    let regs: &[u16] = &insn.regs;
    let first: Option<u16> = regs.first().copied();
    let second: Option<u16> = regs.get(1).copied();
    match op {
        0x12..=0x15 | 0x1A | 0x1B | 0x1C => (first, Cat::One, Vec::new()),
        0x16..=0x19 => (first, Cat::Two, Vec::new()),
        0x0A | 0x0C | 0x0D => (first, Cat::One, Vec::new()),
        0x0B => (first, Cat::Two, Vec::new()),
        0x01 | 0x02 | 0x03 | 0x07 | 0x08 | 0x09 => (
            first,
            Cat::One,
            second.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
        ),
        0x04..=0x06 => (
            first,
            Cat::Two,
            second.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x45 => (first, Cat::Two, Vec::new()),
        0x4C => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x0F | 0x11 => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
        ),
        0x10 => (
            None,
            Cat::One,
            first.map(|r| vec![(r, Cat::Two)]).unwrap_or_default(),
        ),
        0x52..=0x58 | 0x60..=0x66 => {
            let c: Cat = field_cat(dex, insn.index);
            (
                first,
                c,
                second.map(|r| vec![(r, Cat::One)]).unwrap_or_default(),
            )
        }
        0x59..=0x5F => {
            let c: Cat = field_cat(dex, insn.index);
            let mut uses: Vec<(u16, Cat)> = Vec::new();
            if let Some(v) = first {
                uses.push((v, c));
            }
            if let Some(o) = second {
                uses.push((o, Cat::One));
            }
            (None, Cat::One, uses)
        }
        0x67..=0x6D => {
            let c: Cat = field_cat(dex, insn.index);
            (
                None,
                Cat::One,
                first.map(|r| vec![(r, c)]).unwrap_or_default(),
            )
        }
        0x90..=0xAF => binary_three_effects(op, regs),
        0xB0..=0xCF => binary_two_addr_effects(op, regs),
        0x81..=0x8F => cast_effects(op, first, second),
        0x6E..=0x72 | 0x74..=0x78 => invoke_effects(dex, insn),
        _ => (None, Cat::One, Vec::new()),
    }
}

fn field_cat(dex: &DexFile, index: Option<u32>) -> Cat {
    let slot: Slot = index
        .and_then(|i| dex.field_ids.get(i as usize))
        .map(|f: &FieldId| field_slot(&f.type_name))
        .unwrap_or(Slot::Int);
    if slot.category_two() {
        Cat::Two
    } else {
        Cat::One
    }
}

const fn arith_cat(op: u8) -> Cat {
    if arith_three(op).1.category_two() {
        Cat::Two
    } else {
        Cat::One
    }
}

fn binary_three_effects(op: u8, regs: &[u16]) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let c: Cat = arith_cat(op);
    let rhs_cat: Cat = if is_shift(op) { Cat::One } else { c };
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    if let Some(&l) = regs.get(1) {
        uses.push((l, c));
    }
    if let Some(&r) = regs.get(2) {
        uses.push((r, rhs_cat));
    }
    (regs.first().copied(), c, uses)
}

fn binary_two_addr_effects(op: u8, regs: &[u16]) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let base: u8 = op - 0x20;
    let c: Cat = arith_cat(base);
    let rhs_cat: Cat = if is_shift(base) { Cat::One } else { c };
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    if let Some(&d) = regs.first() {
        uses.push((d, c));
    }
    if let Some(&r) = regs.get(1) {
        uses.push((r, rhs_cat));
    }
    (regs.first().copied(), c, uses)
}

fn cast_effects(
    op: u8,
    dest: Option<u16>,
    src: Option<u16>,
) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let (from, to): (Cat, Cat) = match op {
        0x81 => (Cat::One, Cat::Two),
        0x82 => (Cat::One, Cat::One),
        0x83 => (Cat::One, Cat::Two),
        0x84 => (Cat::Two, Cat::One),
        0x85 => (Cat::Two, Cat::One),
        0x86 => (Cat::Two, Cat::Two),
        0x87 => (Cat::One, Cat::One),
        0x88 => (Cat::One, Cat::Two),
        0x89 => (Cat::One, Cat::Two),
        0x8A => (Cat::Two, Cat::One),
        0x8B => (Cat::Two, Cat::Two),
        0x8C => (Cat::Two, Cat::One),
        _ => (Cat::One, Cat::One),
    };
    (dest, to, src.map(|r| vec![(r, from)]).unwrap_or_default())
}

fn invoke_effects(dex: &DexFile, insn: &DalvikInsn) -> (Option<u16>, Cat, Vec<(u16, Cat)>) {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return (None, Cat::One, Vec::new());
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut uses: Vec<(u16, Cat)> = Vec::new();
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static && let Some(&recv) = reg_iter.next() {
        uses.push((recv, Cat::One));
    }
    for param in &method.proto.parameters {
        let two: bool = field_slot(param).category_two();
        if let Some(&reg) = reg_iter.next() {
            uses.push((reg, if two { Cat::Two } else { Cat::One }));
        }
        if two {
            let _ = reg_iter.next();
        }
    }
    (None, Cat::One, uses)
}

fn infer_invoke_arg_kinds(
    dex: &DexFile,
    insn: &DalvikInsn,
    const_defs: &BTreeSet<u16>,
    kinds: &mut BTreeMap<u16, Slot>,
) {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| dex.method_ids.get(i as usize))
    else {
        return;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    if !is_static {
        let _ = reg_iter.next();
    }
    for param in &method.proto.parameters {
        let slot: Slot = field_slot(param);
        if let Some(&reg) = reg_iter.next()
            && const_defs.contains(&reg)
            && matches!(slot, Slot::Float | Slot::Double)
        {
            kinds.entry(reg).or_insert(slot);
        }
        if slot.category_two() {
            let _ = reg_iter.next();
        }
    }
}

const fn arith_three(op: u8) -> (u8, Slot) {
    match op {
        0x90 => (0x60, Slot::Int),
        0x91 => (0x64, Slot::Int),
        0x92 => (0x68, Slot::Int),
        0x93 => (0x6C, Slot::Int),
        0x94 => (0x70, Slot::Int),
        0x95 => (0x7E, Slot::Int),
        0x96 => (0x80, Slot::Int),
        0x97 => (0x82, Slot::Int),
        0x98 => (0x78, Slot::Int),
        0x99 => (0x7A, Slot::Int),
        0x9A => (0x7C, Slot::Int),
        0x9B => (0x61, Slot::Long),
        0x9C => (0x65, Slot::Long),
        0x9D => (0x69, Slot::Long),
        0x9E => (0x6D, Slot::Long),
        0x9F => (0x71, Slot::Long),
        0xA0 => (0x7F, Slot::Long),
        0xA1 => (0x81, Slot::Long),
        0xA2 => (0x83, Slot::Long),
        0xA3 => (0x79, Slot::Long),
        0xA4 => (0x7B, Slot::Long),
        0xA5 => (0x7D, Slot::Long),
        0xA6 => (0x62, Slot::Float),
        0xA7 => (0x66, Slot::Float),
        0xA8 => (0x6A, Slot::Float),
        0xA9 => (0x6E, Slot::Float),
        0xAA => (0x72, Slot::Float),
        0xAB => (0x63, Slot::Double),
        0xAC => (0x67, Slot::Double),
        0xAD => (0x6B, Slot::Double),
        0xAE => (0x6F, Slot::Double),
        0xAF => (0x73, Slot::Double),
        _ => (0x60, Slot::Int),
    }
}

const fn arith_lit_op(op: u8) -> u8 {
    match op {
        0xD0 | 0xD8 => 0x60,
        0xD1 | 0xD9 => 0x64,
        0xD2 | 0xDA => 0x68,
        0xD3 | 0xDB => 0x6C,
        0xD4 | 0xDC => 0x70,
        0xD5 | 0xDD => 0x7E,
        0xD6 | 0xDE => 0x80,
        0xD7 | 0xDF => 0x82,
        0xE0 => 0x78,
        0xE1 => 0x7A,
        0xE2 => 0x7C,
        _ => 0x60,
    }
}

const fn field_slot(descriptor: &str) -> Slot {
    match descriptor.as_bytes().first() {
        Some(b'J') => Slot::Long,
        Some(b'F') => Slot::Float,
        Some(b'D') => Slot::Double,
        Some(b'L' | b'[') => Slot::Ref,
        _ => Slot::Int,
    }
}

fn internal_of(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].to_string()
    } else {
        descriptor.to_string()
    }
}

fn build_descriptor(params: &[String], return_type: &str) -> String {
    let mut out: String = String::with_capacity(2 + return_type.len());
    out.push('(');
    for p in params {
        out.push_str(p);
    }
    out.push(')');
    out.push_str(return_type);
    out
}

fn primitive_atype(descriptor: &str) -> Option<u8> {
    match descriptor {
        "Z" => Some(4),
        "C" => Some(5),
        "F" => Some(6),
        "D" => Some(7),
        "B" => Some(8),
        "S" => Some(9),
        "I" => Some(10),
        "J" => Some(11),
        _ => None,
    }
}
