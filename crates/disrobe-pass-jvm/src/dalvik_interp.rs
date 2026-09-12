use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use disrobe_core::codec::{Base64Alphabet, Base64Padding, base64_decode};

use crate::dalvik::{self, ArrayDataPayload, DalvikInsn, SwitchPayload};
use crate::dex::{CodeItem, DexFile, FieldId, MethodId};

pub(crate) const STEP_BUDGET: u64 = 2_000_000;
pub(crate) const MAX_ARRAY_LEN: usize = 1 << 20;
const MAX_RECURSION_DEPTH: u32 = 12;
const MAX_BACKWARD_BRANCHES: u32 = 500_000;
const MAX_HEAP_OBJECTS: usize = 65_536;
const MAX_HEAP_BYTES: usize = 8 << 20;
const WALL_CLOCK_BACKSTOP: Duration = Duration::from_millis(750);
const STEP_CHECK_INTERVAL: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkipReason {
    BudgetExhausted,
    UnsupportedOpcode(u8),
    UnsupportedCall(String),
    Unsound,
    DivByZero,
    OutputTooLarge,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExhausted => write!(f, "budget exhausted"),
            Self::UnsupportedOpcode(op) => write!(f, "unsupported opcode 0x{op:02X}"),
            Self::UnsupportedCall(m) => write!(f, "unsupported call {m}"),
            Self::Unsound => write!(f, "unsound register or heap access"),
            Self::DivByZero => write!(f, "division by zero"),
            Self::OutputTooLarge => write!(f, "output exceeded the size bound"),
        }
    }
}

type HeapId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeapObj {
    Text(Vec<u16>),
    CharArray(Vec<u16>),
    ByteArray(Vec<u8>),
    IntArray(Vec<i32>),
    Builder(Vec<u16>),
    ClassRef(String),
}

impl HeapObj {
    const fn byte_len(&self) -> usize {
        match self {
            Self::Text(v) | Self::CharArray(v) | Self::Builder(v) => v.len() * 2,
            Self::ByteArray(v) => v.len(),
            Self::IntArray(v) => v.len() * 4,
            Self::ClassRef(_) => 0,
        }
    }

    const fn elem_len(&self) -> Option<usize> {
        match self {
            Self::Text(v) | Self::CharArray(v) | Self::Builder(v) => Some(v.len()),
            Self::ByteArray(v) => Some(v.len()),
            Self::IntArray(v) => Some(v.len()),
            Self::ClassRef(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegSlot {
    Undefined,
    I32(u32),
    WideLow(u64),
    WideHigh,
    Wide64(u64),
    Ref(HeapId),
    Null,
}

impl RegSlot {
    const fn as_i32(self) -> Result<i32, SkipReason> {
        match self {
            Self::I32(v) => Ok(v as i32),
            _ => Err(SkipReason::Unsound),
        }
    }

    const fn as_ref(self) -> Result<Option<HeapId>, SkipReason> {
        match self {
            Self::Ref(r) => Ok(Some(r)),
            Self::Null => Ok(None),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn as_heap_id(self) -> Result<HeapId, SkipReason> {
        self.as_ref()?.ok_or(SkipReason::Unsound)
    }
}

enum JdkOutcome {
    NotHandled,
    Handled(Option<RegSlot>),
}

struct Budget {
    steps: u64,
    deadline: Instant,
}

impl Budget {
    fn new() -> Self {
        Self {
            steps: 0,
            deadline: Instant::now() + WALL_CLOCK_BACKSTOP,
        }
    }

    fn tick(&mut self) -> Result<(), SkipReason> {
        self.steps += 1;
        if self.steps > STEP_BUDGET {
            return Err(SkipReason::BudgetExhausted);
        }
        if self.steps.is_multiple_of(STEP_CHECK_INTERVAL) && Instant::now() > self.deadline {
            return Err(SkipReason::BudgetExhausted);
        }
        Ok(())
    }
}

pub(crate) struct Interp<'a> {
    dex: &'a DexFile,
    class: &'a str,
    code_items: &'a [CodeItem],
    heap: Vec<HeapObj>,
    heap_bytes: usize,
    statics: BTreeMap<String, RegSlot>,
    budget: Budget,
    depth: u32,
}

impl<'a> Interp<'a> {
    pub(crate) fn new(dex: &'a DexFile, class: &'a str, code_items: &'a [CodeItem]) -> Self {
        Self {
            dex,
            class,
            code_items,
            heap: Vec::new(),
            heap_bytes: 0,
            statics: BTreeMap::new(),
            budget: Budget::new(),
            depth: 0,
        }
    }

    fn alloc(&mut self, obj: HeapObj) -> Result<HeapId, SkipReason> {
        if let Some(len) = obj.elem_len()
            && len > MAX_ARRAY_LEN
        {
            return Err(SkipReason::OutputTooLarge);
        }
        let size: usize = obj.byte_len();
        if self.heap.len() >= MAX_HEAP_OBJECTS || self.heap_bytes + size > MAX_HEAP_BYTES {
            return Err(SkipReason::OutputTooLarge);
        }
        self.heap_bytes += size;
        self.heap.push(obj);
        Ok(self.heap.len() - 1)
    }

    const fn grow_check(&self, added_bytes: usize) -> Result<(), SkipReason> {
        if self.heap_bytes + added_bytes > MAX_HEAP_BYTES {
            return Err(SkipReason::OutputTooLarge);
        }
        Ok(())
    }

    fn field_key(&self, index: u32) -> Result<String, SkipReason> {
        let f: &FieldId = self
            .dex
            .field_ids
            .get(index as usize)
            .ok_or(SkipReason::Unsound)?;
        Ok(format!("{}.{}:{}", f.class, f.name, f.type_name))
    }

    pub(crate) fn run_clinit(&mut self) -> Result<(), SkipReason> {
        let Some(clinit): Option<&CodeItem> = self
            .code_items
            .iter()
            .find(|c: &&CodeItem| c.class == self.class && c.method_name == "<clinit>")
        else {
            return Ok(());
        };
        let regs: Vec<RegSlot> =
            vec![RegSlot::Undefined; usize::from(clinit.registers_size).max(1)];
        self.execute(clinit, regs)?;
        Ok(())
    }

    pub(crate) fn alloc_text(&mut self, units: Vec<u16>) -> Result<RegSlot, SkipReason> {
        self.alloc(HeapObj::Text(units)).map(RegSlot::Ref)
    }

    pub(crate) fn alloc_byte_array(&mut self, bytes: Vec<u8>) -> Result<RegSlot, SkipReason> {
        self.alloc(HeapObj::ByteArray(bytes)).map(RegSlot::Ref)
    }

    pub(crate) fn alloc_char_array(&mut self, units: Vec<u16>) -> Result<RegSlot, SkipReason> {
        self.alloc(HeapObj::CharArray(units)).map(RegSlot::Ref)
    }

    pub(crate) fn alloc_int_array(&mut self, values: Vec<i32>) -> Result<RegSlot, SkipReason> {
        self.alloc(HeapObj::IntArray(values)).map(RegSlot::Ref)
    }

    pub(crate) fn finish_text(&self, slot: RegSlot) -> Result<String, SkipReason> {
        match slot {
            RegSlot::Ref(r) => self.text_string(r),
            _ => Err(SkipReason::Unsound),
        }
    }

    pub(crate) fn execute(
        &mut self,
        code: &CodeItem,
        args: Vec<RegSlot>,
    ) -> Result<Option<RegSlot>, SkipReason> {
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(SkipReason::BudgetExhausted);
        }
        self.depth += 1;
        let result: Result<Option<RegSlot>, SkipReason> = self.execute_body(code, args);
        self.depth -= 1;
        result
    }

    fn execute_body(
        &mut self,
        code: &CodeItem,
        mut regs: Vec<RegSlot>,
    ) -> Result<Option<RegSlot>, SkipReason> {
        let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
        let pc_to_index: BTreeMap<u32, usize> = insns
            .iter()
            .enumerate()
            .map(|(i, ins): (usize, &DalvikInsn)| (ins.pc, i))
            .collect();
        let mut pending_result: RegSlot = RegSlot::Undefined;
        let mut ip: usize = 0;
        let mut backward_branches: u32 = 0;

        while ip < insns.len() {
            self.budget.tick()?;
            let ins: &DalvikInsn = &insns[ip];
            let mut next_ip: usize = ip + 1;
            match ins.op {
                0x00 => {}
                0x01 | 0x02 | 0x03 | 0x07 | 0x08 | 0x09 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: RegSlot = read_reg(&regs, src)?;
                    write_reg(&mut regs, dst, v)?;
                }
                0x04..=0x06 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i64 = read_wide(&regs, src)?;
                    write_wide(&mut regs, dst, v)?;
                }
                0x0A | 0x0C => {
                    let dst: u16 = one_reg(ins)?;
                    write_reg(&mut regs, dst, pending_result)?;
                }
                0x0B => {
                    let dst: u16 = one_reg(ins)?;
                    let v: u64 = match pending_result {
                        RegSlot::Wide64(v) => v,
                        _ => return Err(SkipReason::Unsound),
                    };
                    write_wide(&mut regs, dst, v as i64)?;
                }
                0x0D => {
                    let dst: u16 = one_reg(ins)?;
                    write_reg(&mut regs, dst, RegSlot::Null)?;
                }
                0x0E => return Ok(None),
                0x0F => {
                    let src: u16 = one_reg(ins)?;
                    return Ok(Some(read_reg(&regs, src)?));
                }
                0x10 => {
                    let src: u16 = one_reg(ins)?;
                    let v: i64 = read_wide(&regs, src)?;
                    return Ok(Some(RegSlot::Wide64(v as u64)));
                }
                0x11 => {
                    let src: u16 = one_reg(ins)?;
                    return Ok(Some(read_reg(&regs, src)?));
                }
                0x12..=0x15 => {
                    let dst: u16 = one_reg(ins)?;
                    let lit: i64 = ins.literal.ok_or(SkipReason::Unsound)?;
                    let value: i32 = if ins.op == 0x15 {
                        (lit << 16) as i32
                    } else {
                        lit as i32
                    };
                    write_reg(&mut regs, dst, RegSlot::I32(value as u32))?;
                }
                0x16..=0x19 => {
                    let dst: u16 = one_reg(ins)?;
                    let lit: i64 = ins.literal.ok_or(SkipReason::Unsound)?;
                    let value: i64 = if ins.op == 0x19 { lit << 48 } else { lit };
                    write_wide(&mut regs, dst, value)?;
                }
                0x1A | 0x1B => {
                    let dst: u16 = one_reg(ins)?;
                    let idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let s: &String = self
                        .dex
                        .strings
                        .get(idx as usize)
                        .ok_or(SkipReason::Unsound)?;
                    let units: Vec<u16> = s.encode_utf16().collect();
                    let r: HeapId = self.alloc(HeapObj::Text(units))?;
                    write_reg(&mut regs, dst, RegSlot::Ref(r))?;
                }
                0x1C => {
                    let dst: u16 = one_reg(ins)?;
                    let type_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let descriptor: String = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .cloned()
                        .ok_or(SkipReason::Unsound)?;
                    let r: HeapId = self.alloc(HeapObj::ClassRef(descriptor))?;
                    write_reg(&mut regs, dst, RegSlot::Ref(r))?;
                }
                0x1F => {}
                0x20 => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x21 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let r: HeapId = read_reg(&regs, src)?.as_heap_id()?;
                    let len: usize = self.array_elem_len(r)?;
                    write_reg(&mut regs, dst, RegSlot::I32(len as u32))?;
                }
                0x22 => {
                    let dst: u16 = one_reg(ins)?;
                    let type_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let descriptor: String = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .cloned()
                        .ok_or(SkipReason::Unsound)?;
                    let obj: HeapObj = match descriptor.as_str() {
                        "Ljava/lang/String;" => HeapObj::Text(Vec::new()),
                        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;" => {
                            HeapObj::Builder(Vec::new())
                        }
                        _ => {
                            return Err(SkipReason::UnsupportedCall(format!(
                                "new-instance {descriptor}"
                            )));
                        }
                    };
                    let r: HeapId = self.alloc(obj)?;
                    write_reg(&mut regs, dst, RegSlot::Ref(r))?;
                }
                0x23 => {
                    let (dst, size_reg): (u16, u16) = two_regs(ins)?;
                    let type_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let descriptor: String = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .cloned()
                        .ok_or(SkipReason::Unsound)?;
                    let len_i: i32 = read_reg(&regs, size_reg)?.as_i32()?;
                    if len_i < 0 {
                        return Err(SkipReason::Unsound);
                    }
                    let len: usize = len_i as usize;
                    if len > MAX_ARRAY_LEN {
                        return Err(SkipReason::OutputTooLarge);
                    }
                    let obj: HeapObj = match descriptor.as_str() {
                        "[B" => HeapObj::ByteArray(vec![0u8; len]),
                        "[C" => HeapObj::CharArray(vec![0u16; len]),
                        "[I" => HeapObj::IntArray(vec![0i32; len]),
                        _ => {
                            return Err(SkipReason::UnsupportedCall(format!(
                                "new-array {descriptor}"
                            )));
                        }
                    };
                    let r: HeapId = self.alloc(obj)?;
                    write_reg(&mut regs, dst, RegSlot::Ref(r))?;
                }
                0x24 | 0x25 => {
                    let type_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let descriptor: String = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .cloned()
                        .ok_or(SkipReason::Unsound)?;
                    let values: Vec<i32> = ins
                        .regs
                        .iter()
                        .map(|&r: &u16| read_reg(&regs, r)?.as_i32())
                        .collect::<Result<Vec<i32>, SkipReason>>()?;
                    let obj: HeapObj = match descriptor.as_str() {
                        "[B" => HeapObj::ByteArray(values.iter().map(|&v: &i32| v as u8).collect()),
                        "[C" => {
                            HeapObj::CharArray(values.iter().map(|&v: &i32| v as u16).collect())
                        }
                        "[I" => HeapObj::IntArray(values),
                        _ => {
                            return Err(SkipReason::UnsupportedCall(format!(
                                "filled-new-array {descriptor}"
                            )));
                        }
                    };
                    let r: HeapId = self.alloc(obj)?;
                    pending_result = RegSlot::Ref(r);
                }
                0x26 => {
                    let dst: u16 = one_reg(ins)?;
                    let payload_off: u32 = ins.payload_off.ok_or(SkipReason::Unsound)?;
                    let payload: ArrayDataPayload =
                        dalvik::parse_fill_array_data(&code.insns, payload_off)
                            .ok_or(SkipReason::Unsound)?;
                    let r: HeapId = read_reg(&regs, dst)?.as_heap_id()?;
                    self.fill_array_data(r, &payload)?;
                }
                0x27 => return Err(SkipReason::Unsound),
                0x28..=0x2A => {
                    next_ip = branch(
                        &pc_to_index,
                        ins,
                        ins.branch_target_pc(),
                        &mut backward_branches,
                    )?;
                }
                0x2B | 0x2C => {
                    let src: u16 = one_reg(ins)?;
                    let key: i32 = read_reg(&regs, src)?.as_i32()?;
                    let payload_off: u32 = ins.payload_off.ok_or(SkipReason::Unsound)?;
                    let switch: SwitchPayload = if ins.op == 0x2B {
                        dalvik::parse_packed_switch(&code.insns, ins.pc, payload_off)
                    } else {
                        dalvik::parse_sparse_switch(&code.insns, ins.pc, payload_off)
                    }
                    .ok_or(SkipReason::Unsound)?;
                    if let Some(pos) = switch.keys.iter().position(|&k: &i32| k == key) {
                        let target: u32 = switch.targets[pos];
                        next_ip = branch(&pc_to_index, ins, Some(target), &mut backward_branches)?;
                    }
                }
                0x2D..=0x30 => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x31 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let a: i64 = read_wide(&regs, dst)?;
                    let b: i64 = read_wide(&regs, src)?;
                    let cmp: i32 = match a.cmp(&b) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    };
                    write_reg(&mut regs, dst, RegSlot::I32(cmp as u32))?;
                }
                0x32..=0x37 => {
                    let (a, b): (u16, u16) = two_regs(ins)?;
                    let lhs: i32 = read_reg(&regs, a)?.as_i32()?;
                    let rhs: i32 = read_reg(&regs, b)?.as_i32()?;
                    if cmp_branch(ins.op, i64::from(lhs), i64::from(rhs)) {
                        next_ip = branch(
                            &pc_to_index,
                            ins,
                            ins.branch_target_pc(),
                            &mut backward_branches,
                        )?;
                    }
                }
                0x38..=0x3D => {
                    let a: u16 = one_reg(ins)?;
                    let lhs: i32 = read_reg(&regs, a)?.as_i32()?;
                    if cmp_branch_zero(ins.op, i64::from(lhs)) {
                        next_ip = branch(
                            &pc_to_index,
                            ins,
                            ins.branch_target_pc(),
                            &mut backward_branches,
                        )?;
                    }
                }
                0x3E..=0x43 => {}
                0x44 => {
                    let (dst, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: i32 = self.int_array_get(r, index)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as u32))?;
                }
                0x45 | 0x46 | 0x47 | 0x4A => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x48 => {
                    let (dst, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: i8 = self.byte_array_get(r, index)?;
                    write_reg(&mut regs, dst, RegSlot::I32(i32::from(v) as u32))?;
                }
                0x49 => {
                    let (dst, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: u16 = self.char_array_get(r, index)?;
                    write_reg(&mut regs, dst, RegSlot::I32(u32::from(v)))?;
                }
                0x4B => {
                    let (src, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    self.int_array_put(r, index, v)?;
                }
                0x4C | 0x4D | 0x4E | 0x51 => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x4F => {
                    let (src, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    self.byte_array_put(r, index, v as u8)?;
                }
                0x50 => {
                    let (src, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let r: HeapId = read_reg(&regs, arr)?.as_heap_id()?;
                    let index: i32 = read_reg(&regs, idx)?.as_i32()?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    self.char_array_put(r, index, v as u16)?;
                }
                0x52..=0x5F => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x60..=0x66 => {
                    let dst: u16 = one_reg(ins)?;
                    let field_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let value: RegSlot = self.get_static(field_idx, ins.op)?;
                    write_reg(&mut regs, dst, value)?;
                }
                0x67..=0x6D => {
                    let src: u16 = one_reg(ins)?;
                    let field_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    let value: RegSlot = read_reg(&regs, src)?;
                    self.put_static(field_idx, value)?;
                }
                0x6E..=0x72 => {
                    let method_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    pending_result = self
                        .invoke(method_idx, &ins.regs, &regs)?
                        .unwrap_or(RegSlot::Undefined);
                }
                0x73 => {}
                0x74..=0x78 => {
                    let method_idx: u32 = ins.index.ok_or(SkipReason::Unsound)?;
                    pending_result = self
                        .invoke(method_idx, &ins.regs, &regs)?
                        .unwrap_or(RegSlot::Undefined);
                }
                0x79 | 0x7A => {}
                0x7B => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    write_reg(&mut regs, dst, RegSlot::I32(v.wrapping_neg() as u32))?;
                }
                0x7C => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    write_reg(&mut regs, dst, RegSlot::I32((!v) as u32))?;
                }
                0x7D => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i64 = read_wide(&regs, src)?;
                    write_wide(&mut regs, dst, v.wrapping_neg())?;
                }
                0x7E => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i64 = read_wide(&regs, src)?;
                    write_wide(&mut regs, dst, !v)?;
                }
                0x7F..=0x80 => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x81 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    write_wide(&mut regs, dst, i64::from(v))?;
                }
                0x82 | 0x83 => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x84 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i64 = read_wide(&regs, src)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as i32 as u32))?;
                }
                0x85..=0x8C => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0x8D..=0x8F => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i32 = read_reg(&regs, src)?.as_i32()?;
                    let masked: i32 = match ins.op {
                        0x8D => i32::from(v as i8),
                        0x8E => i32::from(v as u16),
                        _ => i32::from(v as i16),
                    };
                    write_reg(&mut regs, dst, RegSlot::I32(masked as u32))?;
                }
                0x90..=0x9A => {
                    let (dst, a, b): (u16, u16, u16) = three_regs(ins)?;
                    let lhs: i32 = read_reg(&regs, a)?.as_i32()?;
                    let rhs: i32 = read_reg(&regs, b)?.as_i32()?;
                    let v: i32 = int_binop(ins.op, lhs, rhs)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as u32))?;
                }
                0x9B..=0xA5 => {
                    let (dst, a, b): (u16, u16, u16) = three_regs(ins)?;
                    let lhs: i64 = read_wide(&regs, a)?;
                    let rhs: i64 = read_wide(&regs, b)?;
                    let v: i64 = long_binop(ins.op, lhs, rhs)?;
                    write_wide(&mut regs, dst, v)?;
                }
                0xA6..=0xAF => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0xB0..=0xBA => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lhs: i32 = read_reg(&regs, dst)?.as_i32()?;
                    let rhs: i32 = read_reg(&regs, src)?.as_i32()?;
                    let v: i32 = int_binop(ins.op - 0xB0 + 0x90, lhs, rhs)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as u32))?;
                }
                0xBB..=0xC5 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lhs: i64 = read_wide(&regs, dst)?;
                    let rhs: i64 = read_wide(&regs, src)?;
                    let v: i64 = long_binop(ins.op - 0xBB + 0x9B, lhs, rhs)?;
                    write_wide(&mut regs, dst, v)?;
                }
                0xC6..=0xCF => return Err(SkipReason::UnsupportedOpcode(ins.op)),
                0xD0..=0xD7 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lit: i32 = ins.literal.ok_or(SkipReason::Unsound)? as i32;
                    let lhs: i32 = read_reg(&regs, src)?.as_i32()?;
                    let v: i32 = lit_binop(ins.op, lhs, lit)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as u32))?;
                }
                0xD8..=0xE2 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lit: i32 = ins.literal.ok_or(SkipReason::Unsound)? as i32;
                    let lhs: i32 = read_reg(&regs, src)?.as_i32()?;
                    let v: i32 = lit_binop(ins.op, lhs, lit)?;
                    write_reg(&mut regs, dst, RegSlot::I32(v as u32))?;
                }
                other => return Err(SkipReason::UnsupportedOpcode(other)),
            }
            ip = next_ip;
        }
        Err(SkipReason::Unsound)
    }

    fn fill_array_data(&mut self, r: HeapId, payload: &ArrayDataPayload) -> Result<(), SkipReason> {
        match (self.heap.get(r), payload.element_width) {
            (Some(HeapObj::ByteArray(v)), 1) if v.len() == payload.data.len() => {
                self.heap[r] = HeapObj::ByteArray(payload.data.clone());
                Ok(())
            }
            (Some(HeapObj::CharArray(v)), 2) if v.len() * 2 == payload.data.len() => {
                let units: Vec<u16> = payload
                    .data
                    .chunks_exact(2)
                    .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                self.heap[r] = HeapObj::CharArray(units);
                Ok(())
            }
            (Some(HeapObj::IntArray(v)), 4) if v.len() * 4 == payload.data.len() => {
                let ints: Vec<i32> = payload
                    .data
                    .chunks_exact(4)
                    .map(|c: &[u8]| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                self.heap[r] = HeapObj::IntArray(ints);
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn array_elem_len(&self, r: HeapId) -> Result<usize, SkipReason> {
        self.heap
            .get(r)
            .and_then(HeapObj::elem_len)
            .ok_or(SkipReason::Unsound)
    }

    fn byte_array_get(&self, r: HeapId, index: i32) -> Result<i8, SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get(r) {
            Some(HeapObj::ByteArray(v)) => v
                .get(i)
                .copied()
                .map(|b: u8| b as i8)
                .ok_or(SkipReason::Unsound),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn byte_array_put(&mut self, r: HeapId, index: i32, value: u8) -> Result<(), SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get_mut(r) {
            Some(HeapObj::ByteArray(v)) if i < v.len() => {
                v[i] = value;
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn char_array_get(&self, r: HeapId, index: i32) -> Result<u16, SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get(r) {
            Some(HeapObj::CharArray(v)) => v.get(i).copied().ok_or(SkipReason::Unsound),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn char_array_put(&mut self, r: HeapId, index: i32, value: u16) -> Result<(), SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get_mut(r) {
            Some(HeapObj::CharArray(v)) if i < v.len() => {
                v[i] = value;
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn int_array_get(&self, r: HeapId, index: i32) -> Result<i32, SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get(r) {
            Some(HeapObj::IntArray(v)) => v.get(i).copied().ok_or(SkipReason::Unsound),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn int_array_put(&mut self, r: HeapId, index: i32, value: i32) -> Result<(), SkipReason> {
        let i: usize = usize::try_from(index).map_err(|_| SkipReason::Unsound)?;
        match self.heap.get_mut(r) {
            Some(HeapObj::IntArray(v)) if i < v.len() => {
                v[i] = value;
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn get_static(&self, field_idx: u32, op: u8) -> Result<RegSlot, SkipReason> {
        let field: &FieldId = self
            .dex
            .field_ids
            .get(field_idx as usize)
            .ok_or(SkipReason::Unsound)?;
        if field.class == "Ljava/nio/charset/StandardCharsets;" {
            let name: &str = match field.name.as_str() {
                "UTF_8" => "UTF-8",
                "UTF_16BE" => "UTF-16BE",
                "ISO_8859_1" => "ISO-8859-1",
                "US_ASCII" => "US-ASCII",
                _ => return Err(SkipReason::UnsupportedCall(format!("sget {}", field.name))),
            };
            let r: HeapId = self
                .heap
                .iter()
                .position(|o: &HeapObj| matches!(o, HeapObj::ClassRef(tag) if tag == name))
                .unwrap_or(self.heap.len());
            if r == self.heap.len() {
                return Err(SkipReason::Unsound);
            }
            return Ok(RegSlot::Ref(r));
        }
        if field.class != self.class {
            return Err(SkipReason::UnsupportedCall(format!(
                "sget {}.{}",
                field.class, field.name
            )));
        }
        let key: String = self.field_key(field_idx)?;
        Ok(self.statics.get(&key).copied().unwrap_or(match op {
            0x61 => RegSlot::WideLow(0),
            _ => RegSlot::I32(0),
        }))
    }

    fn put_static(&mut self, field_idx: u32, value: RegSlot) -> Result<(), SkipReason> {
        let field: &FieldId = self
            .dex
            .field_ids
            .get(field_idx as usize)
            .ok_or(SkipReason::Unsound)?;
        if field.class != self.class {
            return Err(SkipReason::UnsupportedCall(format!(
                "sput {}.{}",
                field.class, field.name
            )));
        }
        let key: String = self.field_key(field_idx)?;
        self.statics.insert(key, value);
        Ok(())
    }

    fn invoke(
        &mut self,
        method_idx: u32,
        arg_regs: &[u16],
        regs: &[RegSlot],
    ) -> Result<Option<RegSlot>, SkipReason> {
        let method: &MethodId = self
            .dex
            .method_ids
            .get(method_idx as usize)
            .ok_or(SkipReason::Unsound)?;
        let owner: String = method.class.clone();
        let name: String = method.name.clone();
        let return_type: String = method.proto.return_type.clone();
        let params: Vec<String> = method.proto.parameters.clone();

        if let JdkOutcome::Handled(outcome) =
            self.dispatch_jdk(&owner, &name, &return_type, &params, arg_regs, regs)?
        {
            return Ok(outcome);
        }

        if owner == self.class {
            let target_desc: String = format!("({}){return_type}", params.join(""));
            let target: Option<&CodeItem> = self.code_items.iter().find(|c: &&CodeItem| {
                c.class == owner && c.method_name == name && c.method_descriptor == target_desc
            });
            let Some(target_code): Option<&CodeItem> = target else {
                return Err(SkipReason::UnsupportedCall(format!(
                    "{owner}->{name}{target_desc}"
                )));
            };
            let mut callee_regs: Vec<RegSlot> = vec![
                RegSlot::Undefined;
                usize::from(target_code.registers_size)
                    .max(arg_regs.len())
            ];
            let in_count: usize = usize::from(target_code.ins_size);
            let base: usize = callee_regs.len().saturating_sub(in_count);
            for (i, arg_reg) in arg_regs.iter().take(in_count).enumerate() {
                callee_regs[base + i] = raw_reg(regs, *arg_reg)?;
            }
            return self.execute(target_code, callee_regs);
        }

        Err(SkipReason::UnsupportedCall(format!(
            "{owner}->{name}({})",
            params.join(",")
        )))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_jdk(
        &mut self,
        owner: &str,
        name: &str,
        return_type: &str,
        params: &[String],
        arg_regs: &[u16],
        regs: &[RegSlot],
    ) -> Result<JdkOutcome, SkipReason> {
        let recv_ref = |slot: usize| -> Result<HeapId, SkipReason> {
            read_reg(regs, *arg_regs.get(slot).ok_or(SkipReason::Unsound)?)?.as_heap_id()
        };
        let recv_i32 = |slot: usize| -> Result<i32, SkipReason> {
            read_reg(regs, *arg_regs.get(slot).ok_or(SkipReason::Unsound)?)?.as_i32()
        };
        match (owner, name, params) {
            ("Ljava/lang/String;", "<init>", p) if p == ["[B"] => {
                let this: HeapId = recv_ref(0)?;
                let src: HeapId = recv_ref(1)?;
                let bytes: Vec<u8> = self.byte_array_contents(src)?;
                let units: Vec<u16> = decode_charset("UTF-8", &bytes);
                self.grow_check(units.len() * 2)?;
                self.set_heap(this, HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(None))
            }
            ("Ljava/lang/String;", "<init>", p) if p == ["[B", "I", "I"] => {
                let this: HeapId = recv_ref(0)?;
                let src: HeapId = recv_ref(1)?;
                let off: i32 = recv_i32(2)?;
                let len: i32 = recv_i32(3)?;
                let bytes: Vec<u8> = self.byte_array_slice(src, off, len)?;
                let units: Vec<u16> = decode_charset("UTF-8", &bytes);
                self.grow_check(units.len() * 2)?;
                self.set_heap(this, HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(None))
            }
            ("Ljava/lang/String;", "<init>", p)
                if p == ["[B", "Ljava/lang/String;"]
                    || p == ["[B", "Ljava/nio/charset/Charset;"] =>
            {
                let this: HeapId = recv_ref(0)?;
                let src: HeapId = recv_ref(1)?;
                let charset: String = self.charset_arg(recv_ref(2)?)?;
                let bytes: Vec<u8> = self.byte_array_contents(src)?;
                let units: Vec<u16> = decode_charset(&charset, &bytes);
                self.grow_check(units.len() * 2)?;
                self.set_heap(this, HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(None))
            }
            ("Ljava/lang/String;", "toCharArray", _) => {
                let recv: HeapId = recv_ref(0)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let r: HeapId = self.alloc(HeapObj::CharArray(units))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "getBytes", []) => {
                let recv: HeapId = recv_ref(0)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let bytes: Vec<u8> = encode_charset("UTF-8", &units);
                let r: HeapId = self.alloc(HeapObj::ByteArray(bytes))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "getBytes", p) if p == ["Ljava/lang/String;"] => {
                let recv: HeapId = recv_ref(0)?;
                let charset: HeapId = recv_ref(1)?;
                let charset_name: String = self.text_string(charset)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let bytes: Vec<u8> = encode_charset(&charset_name, &units);
                let r: HeapId = self.alloc(HeapObj::ByteArray(bytes))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "valueOf", p) if p == ["[C"] => {
                let src: HeapId = recv_ref(0)?;
                let units: Vec<u16> = self.char_units(src)?;
                let r: HeapId = self.alloc(HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "charAt", _) => {
                let recv: HeapId = recv_ref(0)?;
                let idx: i32 = recv_i32(1)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let ch: u16 = *units
                    .get(usize::try_from(idx).map_err(|_| SkipReason::Unsound)?)
                    .ok_or(SkipReason::Unsound)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::I32(u32::from(ch)))))
            }
            ("Ljava/lang/String;", "length", _) => {
                let recv: HeapId = recv_ref(0)?;
                let units: Vec<u16> = self.text_units(recv)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::I32(units.len() as u32))))
            }
            ("Ljava/lang/String;", "substring", p) if p == ["I"] => {
                let recv: HeapId = recv_ref(0)?;
                let begin: i32 = recv_i32(1)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let b: usize = usize::try_from(begin).map_err(|_| SkipReason::Unsound)?;
                let slice: &[u16] = units.get(b..).ok_or(SkipReason::Unsound)?;
                let r: HeapId = self.alloc(HeapObj::Text(slice.to_vec()))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "substring", p) if p == ["I", "I"] => {
                let recv: HeapId = recv_ref(0)?;
                let begin: i32 = recv_i32(1)?;
                let end: i32 = recv_i32(2)?;
                let units: Vec<u16> = self.text_units(recv)?;
                let b: usize = usize::try_from(begin).map_err(|_| SkipReason::Unsound)?;
                let e: usize = usize::try_from(end).map_err(|_| SkipReason::Unsound)?;
                let slice: &[u16] = units.get(b..e).ok_or(SkipReason::Unsound)?;
                let r: HeapId = self.alloc(HeapObj::Text(slice.to_vec()))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/String;", "intern", _) => {
                let recv: HeapId = recv_ref(0)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(recv))))
            }
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", "<init>", []) => {
                Ok(JdkOutcome::Handled(None))
            }
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", "append", p)
                if p == ["C"] =>
            {
                let recv: HeapId = recv_ref(0)?;
                let ch: i32 = recv_i32(1)?;
                self.grow_check(2)?;
                self.builder_push(recv, ch as u16)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(recv))))
            }
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", "append", p)
                if p == ["Ljava/lang/String;"] =>
            {
                let recv: HeapId = recv_ref(0)?;
                let src: HeapId = recv_ref(1)?;
                let units: Vec<u16> = self.text_units(src)?;
                self.grow_check(units.len() * 2)?;
                self.builder_extend(recv, &units)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(recv))))
            }
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", "append", p)
                if p == ["I"] =>
            {
                let recv: HeapId = recv_ref(0)?;
                let v: i32 = recv_i32(1)?;
                let units: Vec<u16> = v.to_string().encode_utf16().collect();
                self.grow_check(units.len() * 2)?;
                self.builder_extend(recv, &units)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(recv))))
            }
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", "toString", _) => {
                let recv: HeapId = recv_ref(0)?;
                let units: Vec<u16> = self.builder_units(recv)?;
                let r: HeapId = self.alloc(HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Landroid/util/Base64;", "decode", p) if p == ["[B", "I"] => {
                let src: HeapId = recv_ref(0)?;
                let flags: i32 = recv_i32(1)?;
                let bytes: Vec<u8> = self.byte_array_contents(src)?;
                let decoded: Vec<u8> = android_base64_decode(&bytes, flags)?;
                self.grow_check(decoded.len())?;
                let r: HeapId = self.alloc(HeapObj::ByteArray(decoded))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Landroid/util/Base64;", "decode", p) if p == ["Ljava/lang/String;", "I"] => {
                let src: HeapId = recv_ref(0)?;
                let flags: i32 = recv_i32(1)?;
                let text: String = self.text_string(src)?;
                let decoded: Vec<u8> = android_base64_decode(text.as_bytes(), flags)?;
                self.grow_check(decoded.len())?;
                let r: HeapId = self.alloc(HeapObj::ByteArray(decoded))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/util/Arrays;", "copyOf", p) if p == ["[B", "I"] => {
                let src: HeapId = recv_ref(0)?;
                let len: i32 = recv_i32(1)?;
                let bytes: Vec<u8> = self.byte_array_contents(src)?;
                let out: Vec<u8> = copy_of(&bytes, len, 0u8)?;
                let r: HeapId = self.alloc(HeapObj::ByteArray(out))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/util/Arrays;", "copyOfRange", p) if p == ["[B", "I", "I"] => {
                let src: HeapId = recv_ref(0)?;
                let from: i32 = recv_i32(1)?;
                let to: i32 = recv_i32(2)?;
                let bytes: Vec<u8> = self.byte_array_contents(src)?;
                let out: Vec<u8> = copy_of_range(&bytes, from, to, 0u8)?;
                let r: HeapId = self.alloc(HeapObj::ByteArray(out))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/System;", "arraycopy", p)
                if p == ["Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"] =>
            {
                let src: HeapId = recv_ref(0)?;
                let src_pos: i32 = recv_i32(1)?;
                let dst: HeapId = recv_ref(2)?;
                let dst_pos: i32 = recv_i32(3)?;
                let len: i32 = recv_i32(4)?;
                self.array_copy(src, src_pos, dst, dst_pos, len)?;
                Ok(JdkOutcome::Handled(None))
            }
            ("Ljava/lang/Integer;", "parseInt", p) if p == ["Ljava/lang/String;"] => {
                let src: HeapId = recv_ref(0)?;
                let text: String = self.text_string(src)?;
                let value: i32 = text.trim().parse().map_err(|_| SkipReason::Unsound)?;
                Ok(JdkOutcome::Handled(Some(RegSlot::I32(value as u32))))
            }
            ("Ljava/lang/Integer;", "toString", p) if p == ["I"] => {
                let value: i32 = recv_i32(0)?;
                let units: Vec<u16> = value.to_string().encode_utf16().collect();
                let r: HeapId = self.alloc(HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            ("Ljava/lang/Character;", "toString", p) if p == ["C"] => {
                let ch: i32 = recv_i32(0)?;
                let units: Vec<u16> = vec![ch as u16];
                let r: HeapId = self.alloc(HeapObj::Text(units))?;
                Ok(JdkOutcome::Handled(Some(RegSlot::Ref(r))))
            }
            _ if return_type == "V" && owner.starts_with("Ljava/lang/") => {
                Ok(JdkOutcome::NotHandled)
            }
            _ => Ok(JdkOutcome::NotHandled),
        }
    }

    fn set_heap(&mut self, r: HeapId, obj: HeapObj) -> Result<(), SkipReason> {
        let slot: &mut HeapObj = self.heap.get_mut(r).ok_or(SkipReason::Unsound)?;
        self.heap_bytes = self.heap_bytes.saturating_sub(slot.byte_len());
        self.heap_bytes += obj.byte_len();
        *slot = obj;
        Ok(())
    }

    fn text_units(&self, r: HeapId) -> Result<Vec<u16>, SkipReason> {
        match self.heap.get(r) {
            Some(HeapObj::Text(v)) => Ok(v.clone()),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn text_string(&self, r: HeapId) -> Result<String, SkipReason> {
        self.text_units(r)
            .map(|u: Vec<u16>| String::from_utf16_lossy(&u))
    }

    fn char_units(&self, r: HeapId) -> Result<Vec<u16>, SkipReason> {
        match self.heap.get(r) {
            Some(HeapObj::CharArray(v)) => Ok(v.clone()),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn byte_array_contents(&self, r: HeapId) -> Result<Vec<u8>, SkipReason> {
        match self.heap.get(r) {
            Some(HeapObj::ByteArray(v)) => Ok(v.clone()),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn byte_array_slice(&self, r: HeapId, off: i32, len: i32) -> Result<Vec<u8>, SkipReason> {
        let bytes: Vec<u8> = self.byte_array_contents(r)?;
        let o: usize = usize::try_from(off).map_err(|_| SkipReason::Unsound)?;
        let l: usize = usize::try_from(len).map_err(|_| SkipReason::Unsound)?;
        let end: usize = o.checked_add(l).ok_or(SkipReason::Unsound)?;
        bytes
            .get(o..end)
            .map(<[u8]>::to_vec)
            .ok_or(SkipReason::Unsound)
    }

    fn charset_arg(&self, r: HeapId) -> Result<String, SkipReason> {
        match self.heap.get(r) {
            Some(HeapObj::Text(v)) => Ok(String::from_utf16_lossy(v)),
            Some(HeapObj::ClassRef(tag)) => Ok(tag.clone()),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn builder_push(&mut self, r: HeapId, ch: u16) -> Result<(), SkipReason> {
        match self.heap.get_mut(r) {
            Some(HeapObj::Builder(v)) => {
                v.push(ch);
                self.heap_bytes += 2;
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn builder_extend(&mut self, r: HeapId, units: &[u16]) -> Result<(), SkipReason> {
        match self.heap.get_mut(r) {
            Some(HeapObj::Builder(v)) => {
                v.extend_from_slice(units);
                self.heap_bytes += units.len() * 2;
                Ok(())
            }
            _ => Err(SkipReason::Unsound),
        }
    }

    fn builder_units(&self, r: HeapId) -> Result<Vec<u16>, SkipReason> {
        match self.heap.get(r) {
            Some(HeapObj::Builder(v)) => Ok(v.clone()),
            _ => Err(SkipReason::Unsound),
        }
    }

    fn array_copy(
        &mut self,
        src: HeapId,
        src_pos: i32,
        dst: HeapId,
        dst_pos: i32,
        len: i32,
    ) -> Result<(), SkipReason> {
        let l: usize = usize::try_from(len).map_err(|_| SkipReason::Unsound)?;
        let sp: usize = usize::try_from(src_pos).map_err(|_| SkipReason::Unsound)?;
        let dp: usize = usize::try_from(dst_pos).map_err(|_| SkipReason::Unsound)?;
        match (self.heap.get(src).cloned(), self.heap.get(dst)) {
            (Some(HeapObj::ByteArray(sv)), Some(HeapObj::ByteArray(_))) => {
                let chunk: &[u8] = sv.get(sp..sp + l).ok_or(SkipReason::Unsound)?;
                let chunk_owned: Vec<u8> = chunk.to_vec();
                if let Some(HeapObj::ByteArray(dv)) = self.heap.get_mut(dst) {
                    let dest: &mut [u8] = dv.get_mut(dp..dp + l).ok_or(SkipReason::Unsound)?;
                    dest.copy_from_slice(&chunk_owned);
                    Ok(())
                } else {
                    Err(SkipReason::Unsound)
                }
            }
            (Some(HeapObj::CharArray(sv)), Some(HeapObj::CharArray(_))) => {
                let chunk: &[u16] = sv.get(sp..sp + l).ok_or(SkipReason::Unsound)?;
                let chunk_owned: Vec<u16> = chunk.to_vec();
                if let Some(HeapObj::CharArray(dv)) = self.heap.get_mut(dst) {
                    let dest: &mut [u16] = dv.get_mut(dp..dp + l).ok_or(SkipReason::Unsound)?;
                    dest.copy_from_slice(&chunk_owned);
                    Ok(())
                } else {
                    Err(SkipReason::Unsound)
                }
            }
            (Some(HeapObj::IntArray(sv)), Some(HeapObj::IntArray(_))) => {
                let chunk: &[i32] = sv.get(sp..sp + l).ok_or(SkipReason::Unsound)?;
                let chunk_owned: Vec<i32> = chunk.to_vec();
                if let Some(HeapObj::IntArray(dv)) = self.heap.get_mut(dst) {
                    let dest: &mut [i32] = dv.get_mut(dp..dp + l).ok_or(SkipReason::Unsound)?;
                    dest.copy_from_slice(&chunk_owned);
                    Ok(())
                } else {
                    Err(SkipReason::Unsound)
                }
            }
            _ => Err(SkipReason::Unsound),
        }
    }
}

fn android_base64_decode(input: &[u8], flags: i32) -> Result<Vec<u8>, SkipReason> {
    const URL_SAFE: i32 = 8;
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect();
    let alphabet: Base64Alphabet<'_> = if flags & URL_SAFE != 0 {
        Base64Alphabet::UrlSafe
    } else {
        Base64Alphabet::Standard
    };
    base64_decode(&filtered, alphabet, Base64Padding::Optional).map_err(|_| SkipReason::Unsound)
}

fn copy_of(bytes: &[u8], len: i32, pad: u8) -> Result<Vec<u8>, SkipReason> {
    let l: usize = usize::try_from(len).map_err(|_| SkipReason::Unsound)?;
    if l > MAX_ARRAY_LEN {
        return Err(SkipReason::OutputTooLarge);
    }
    let mut out: Vec<u8> = bytes.iter().copied().take(l).collect();
    out.resize(l, pad);
    Ok(out)
}

fn copy_of_range(bytes: &[u8], from: i32, to: i32, pad: u8) -> Result<Vec<u8>, SkipReason> {
    let f: usize = usize::try_from(from).map_err(|_| SkipReason::Unsound)?;
    let t: usize = usize::try_from(to).map_err(|_| SkipReason::Unsound)?;
    if t < f || t - f > MAX_ARRAY_LEN {
        return Err(SkipReason::Unsound);
    }
    let mut out: Vec<u8> = Vec::with_capacity(t - f);
    for i in f..t {
        out.push(bytes.get(i).copied().unwrap_or(pad));
    }
    Ok(out)
}

fn decode_charset(name: &str, bytes: &[u8]) -> Vec<u16> {
    match name {
        "UTF-16BE" | "UTF_16BE" => {
            let (cow, _had_errors): (std::borrow::Cow<'_, str>, bool) =
                encoding_rs::UTF_16BE.decode_without_bom_handling(bytes);
            cow.encode_utf16().collect()
        }
        "ISO-8859-1" | "ISO_8859_1" | "Latin1" | "8859_1" => {
            bytes.iter().map(|&b: &u8| u16::from(b)).collect()
        }
        "US-ASCII" | "USASCII" | "ASCII" => bytes
            .iter()
            .map(|&b: &u8| if b < 0x80 { u16::from(b) } else { 0xFFFD })
            .collect(),
        _ => {
            let (cow, _had_errors): (std::borrow::Cow<'_, str>, bool) =
                encoding_rs::UTF_8.decode_without_bom_handling(bytes);
            cow.encode_utf16().collect()
        }
    }
}

fn encode_charset(name: &str, units: &[u16]) -> Vec<u8> {
    let text: String = String::from_utf16_lossy(units);
    match name {
        "UTF-16BE" | "UTF_16BE" => {
            let mut out: Vec<u8> = Vec::with_capacity(units.len() * 2);
            for &u in units {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        "ISO-8859-1" | "ISO_8859_1" | "Latin1" | "8859_1" => text
            .chars()
            .map(|c: char| if (c as u32) <= 0xFF { c as u8 } else { b'?' })
            .collect(),
        "US-ASCII" | "USASCII" | "ASCII" => text
            .chars()
            .map(|c: char| if (c as u32) < 0x80 { c as u8 } else { b'?' })
            .collect(),
        _ => text.into_bytes(),
    }
}

fn branch(
    pc_to_index: &BTreeMap<u32, usize>,
    ins: &DalvikInsn,
    target: Option<u32>,
    backward_branches: &mut u32,
) -> Result<usize, SkipReason> {
    let target_pc: u32 = target.ok_or(SkipReason::Unsound)?;
    let target_index: usize = *pc_to_index.get(&target_pc).ok_or(SkipReason::Unsound)?;
    if target_pc <= ins.pc {
        *backward_branches += 1;
        if *backward_branches > MAX_BACKWARD_BRANCHES {
            return Err(SkipReason::BudgetExhausted);
        }
    }
    Ok(target_index)
}

fn one_reg(ins: &DalvikInsn) -> Result<u16, SkipReason> {
    ins.regs.first().copied().ok_or(SkipReason::Unsound)
}

fn two_regs(ins: &DalvikInsn) -> Result<(u16, u16), SkipReason> {
    match (ins.regs.first(), ins.regs.get(1)) {
        (Some(a), Some(b)) => Ok((*a, *b)),
        _ => Err(SkipReason::Unsound),
    }
}

fn three_regs(ins: &DalvikInsn) -> Result<(u16, u16, u16), SkipReason> {
    match (ins.regs.first(), ins.regs.get(1), ins.regs.get(2)) {
        (Some(a), Some(b), Some(c)) => Ok((*a, *b, *c)),
        _ => Err(SkipReason::Unsound),
    }
}

fn read_reg(regs: &[RegSlot], r: u16) -> Result<RegSlot, SkipReason> {
    match regs.get(usize::from(r)) {
        Some(RegSlot::WideHigh) => Err(SkipReason::Unsound),
        Some(slot) => Ok(*slot),
        None => Err(SkipReason::Unsound),
    }
}

fn raw_reg(regs: &[RegSlot], r: u16) -> Result<RegSlot, SkipReason> {
    regs.get(usize::from(r)).copied().ok_or(SkipReason::Unsound)
}

fn write_reg(regs: &mut [RegSlot], r: u16, value: RegSlot) -> Result<(), SkipReason> {
    let slot: &mut RegSlot = regs.get_mut(usize::from(r)).ok_or(SkipReason::Unsound)?;
    *slot = value;
    Ok(())
}

fn read_wide(regs: &[RegSlot], r: u16) -> Result<i64, SkipReason> {
    let lo: usize = usize::from(r);
    let hi: usize = lo + 1;
    match (regs.get(lo), regs.get(hi)) {
        (Some(RegSlot::WideLow(v)), Some(RegSlot::WideHigh)) => Ok(*v as i64),
        _ => Err(SkipReason::Unsound),
    }
}

fn write_wide(regs: &mut [RegSlot], r: u16, value: i64) -> Result<(), SkipReason> {
    let lo: usize = usize::from(r);
    let hi: usize = lo + 1;
    if hi >= regs.len() {
        return Err(SkipReason::Unsound);
    }
    regs[lo] = RegSlot::WideLow(value as u64);
    regs[hi] = RegSlot::WideHigh;
    Ok(())
}

const fn cmp_branch(op: u8, a: i64, b: i64) -> bool {
    match op {
        0x32 => a == b,
        0x33 => a != b,
        0x34 => a < b,
        0x35 => a >= b,
        0x36 => a > b,
        0x37 => a <= b,
        _ => false,
    }
}

const fn cmp_branch_zero(op: u8, a: i64) -> bool {
    match op {
        0x38 => a == 0,
        0x39 => a != 0,
        0x3A => a < 0,
        0x3B => a >= 0,
        0x3C => a > 0,
        0x3D => a <= 0,
        _ => false,
    }
}

const fn int_binop(op: u8, a: i32, b: i32) -> Result<i32, SkipReason> {
    Ok(match op {
        0x90 => a.wrapping_add(b),
        0x91 => a.wrapping_sub(b),
        0x92 => a.wrapping_mul(b),
        0x93 => {
            if b == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_div(b)
        }
        0x94 => {
            if b == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_rem(b)
        }
        0x95 => a & b,
        0x96 => a | b,
        0x97 => a ^ b,
        0x98 => a.wrapping_shl(b as u32),
        0x99 => a.wrapping_shr(b as u32),
        0x9A => ((a as u32).wrapping_shr(b as u32)) as i32,
        _ => return Err(SkipReason::UnsupportedOpcode(op)),
    })
}

const fn long_binop(op: u8, a: i64, b: i64) -> Result<i64, SkipReason> {
    Ok(match op {
        0x9B => a.wrapping_add(b),
        0x9C => a.wrapping_sub(b),
        0x9D => a.wrapping_mul(b),
        0x9E => {
            if b == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_div(b)
        }
        0x9F => {
            if b == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_rem(b)
        }
        0xA0 => a & b,
        0xA1 => a | b,
        0xA2 => a ^ b,
        0xA3 => a.wrapping_shl(b as u32),
        0xA4 => a.wrapping_shr(b as u32),
        0xA5 => ((a as u64).wrapping_shr(b as u32)) as i64,
        _ => return Err(SkipReason::UnsupportedOpcode(op)),
    })
}

const fn lit_binop(op: u8, a: i32, lit: i32) -> Result<i32, SkipReason> {
    Ok(match op {
        0xD0 | 0xD8 => a.wrapping_add(lit),
        0xD1 | 0xD9 => lit.wrapping_sub(a),
        0xD2 | 0xDA => a.wrapping_mul(lit),
        0xD3 | 0xDB => {
            if lit == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_div(lit)
        }
        0xD4 | 0xDC => {
            if lit == 0 {
                return Err(SkipReason::DivByZero);
            }
            a.wrapping_rem(lit)
        }
        0xD5 | 0xDD => a & lit,
        0xD6 | 0xDE => a | lit,
        0xD7 | 0xDF => a ^ lit,
        0xE0 => a.wrapping_shl(lit as u32),
        0xE1 => a.wrapping_shr(lit as u32),
        0xE2 => ((a as u32).wrapping_shr(lit as u32)) as i32,
        _ => return Err(SkipReason::UnsupportedOpcode(op)),
    })
}

pub(crate) fn method_descriptor(method: &MethodId) -> String {
    format!(
        "({}){}",
        method.proto.parameters.concat(),
        method.proto.return_type
    )
}

#[cfg(test)]
mod tests;
