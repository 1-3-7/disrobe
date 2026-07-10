use crate::cil::{Instruction, MethodBody, OperandValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationError {
    UnsupportedOpcode(String),
    StackUnderflow,
    BadLocal(u32),
    BadArgument(u32),
    StepLimitExceeded,
    ExternalCall,
    BadShape,
    OutOfBounds,
    DivideByZero,
    NoResult,
}

const STEP_LIMIT: u64 = 4_000_000;
const MAX_ARRAY: usize = 16 * 1024 * 1024;
const MAX_HEAP_BYTES: usize = 64 * 1024 * 1024;
const MAX_HEAP: usize = 4096;
const MAX_EMULATED_INSTRUCTIONS: usize = 16_384;
const MAX_SWITCH_TARGETS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    I32(i32),
    I64(i64),

    Array(Option<usize>),

    String(Option<usize>),
}

impl Value {
    const fn as_i64(self) -> Result<i64, EmulationError> {
        match self {
            Self::I32(v) => Ok(v as i64),
            Self::I64(v) => Ok(v),
            Self::Array(_) | Self::String(_) => Err(EmulationError::BadShape),
        }
    }

    const fn as_array(self) -> Result<usize, EmulationError> {
        match self {
            Self::Array(Some(r)) => Ok(r),
            Self::Array(None) => Err(EmulationError::OutOfBounds),
            Self::I32(_) | Self::I64(_) | Self::String(_) => Err(EmulationError::BadShape),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeapKind {
    ByteArray,
    CharArray,
    OtherArray,
    String,
}

#[derive(Debug, Clone)]
struct HeapArray {
    bytes: Vec<u8>,
    elem_size: usize,
    kind: HeapKind,
}

impl HeapArray {
    fn new(len: usize, elem_size: usize, kind: HeapKind) -> Self {
        Self {
            bytes: vec![0u8; len.saturating_mul(elem_size)],
            elem_size,
            kind,
        }
    }

    const fn len(&self) -> usize {
        match self.bytes.len().checked_div(self.elem_size) {
            Some(n) => n,
            None => 0,
        }
    }

    fn load(&self, idx: usize, elem: usize) -> Result<i64, EmulationError> {
        let off: usize = idx.checked_mul(elem).ok_or(EmulationError::OutOfBounds)?;
        if off + elem > self.bytes.len() {
            return Err(EmulationError::OutOfBounds);
        }
        let mut v: i64 = 0;
        for i in 0..elem {
            v |= i64::from(self.bytes[off + i]) << (8 * i);
        }
        Ok(v)
    }

    fn store(&mut self, idx: usize, elem: usize, val: i64) -> Result<(), EmulationError> {
        let off: usize = idx.checked_mul(elem).ok_or(EmulationError::OutOfBounds)?;
        if off + elem > self.bytes.len() {
            return Err(EmulationError::OutOfBounds);
        }
        for i in 0..elem {
            self.bytes[off + i] = u8::try_from((val >> (8 * i)) & 0xFF).unwrap_or(0);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubOutput {
    Int(i64),

    Bytes(Vec<u8>),

    Utf16(String),
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_field_names)]
pub struct StubInput {
    pub int_args: Vec<i64>,
    pub byte_array_args: Vec<Vec<u8>>,
    pub char_array_args: Vec<Vec<u16>>,
}

#[derive(Debug, Clone, Default)]
pub struct FieldInitEnv {
    pub field_data: std::collections::BTreeMap<u32, Vec<u8>>,
    pub init_array_tokens: std::collections::BTreeSet<u32>,
    pub array_elem_sizes: std::collections::BTreeMap<u32, usize>,
    pub char_array_tokens: std::collections::BTreeSet<u32>,
    pub string_char_ctor_tokens: std::collections::BTreeSet<u32>,
}

struct Vm<'a> {
    body: &'a MethodBody,
    index_of: Vec<u32>,
    stack: Vec<Value>,
    locals: Vec<Value>,
    args: Vec<Value>,
    heap: Vec<HeapArray>,
    heap_bytes: usize,
    steps: u64,
    env: FieldInitEnv,
}

impl<'a> Vm<'a> {
    fn with_env(
        body: &'a MethodBody,
        args: Vec<Value>,
        heap: Vec<HeapArray>,
        heap_bytes: usize,
        env: FieldInitEnv,
    ) -> Self {
        let index_of: Vec<u32> = body
            .instructions
            .iter()
            .map(|i: &Instruction| i.offset)
            .collect();
        Self {
            body,
            index_of,
            stack: Vec::with_capacity(32),
            locals: vec![Value::I32(0); 64],
            args,
            heap,
            heap_bytes,
            steps: 0,
            env,
        }
    }

    fn pop(&mut self) -> Result<Value, EmulationError> {
        self.stack.pop().ok_or(EmulationError::StackUnderflow)
    }

    fn local(&mut self, n: u32) -> Result<&mut Value, EmulationError> {
        let i: usize = n as usize;
        if i >= self.locals.len() {
            if i >= 4096 {
                return Err(EmulationError::BadLocal(n));
            }
            self.locals.resize(i + 1, Value::I32(0));
        }
        self.locals.get_mut(i).ok_or(EmulationError::BadLocal(n))
    }

    fn arg(&self, n: u32) -> Result<Value, EmulationError> {
        self.args
            .get(n as usize)
            .copied()
            .ok_or(EmulationError::BadArgument(n))
    }

    fn ip_of(&self, offset: u32) -> Option<usize> {
        self.index_of.binary_search(&offset).ok()
    }

    fn alloc(&mut self, len: usize, elem: usize, kind: HeapKind) -> Result<usize, EmulationError> {
        let bytes: usize = len.checked_mul(elem).ok_or(EmulationError::OutOfBounds)?;
        let heap_bytes: usize = self
            .heap_bytes
            .checked_add(bytes)
            .ok_or(EmulationError::OutOfBounds)?;
        if self.heap.len() >= MAX_HEAP || bytes > MAX_ARRAY || heap_bytes > MAX_HEAP_BYTES {
            return Err(EmulationError::OutOfBounds);
        }
        self.heap.push(HeapArray::new(len, elem, kind));
        self.heap_bytes = heap_bytes;
        Ok(self.heap.len() - 1)
    }

    fn elem_size_for(&self, ins: &Instruction) -> usize {
        match ins.operand {
            OperandValue::Token(t) => self.env.array_elem_sizes.get(&t).copied().unwrap_or(1),
            _ => 1,
        }
    }

    fn array_kind_for(&self, ins: &Instruction) -> HeapKind {
        match ins.operand {
            OperandValue::Token(token) if self.env.char_array_tokens.contains(&token) => {
                HeapKind::CharArray
            }
            _ => HeapKind::OtherArray,
        }
    }

    fn is_init_array_call(&self, ins: &Instruction) -> bool {
        matches!(ins.operand, OperandValue::Token(t) if self.env.init_array_tokens.contains(&t))
    }

    fn is_string_char_ctor(&self, ins: &Instruction) -> bool {
        matches!(ins.operand, OperandValue::Token(t) if self.env.string_char_ctor_tokens.contains(&t))
    }

    fn exec_init_array(&mut self) -> Result<(), EmulationError> {
        let token: i64 = self.pop()?.as_i64()?;
        let arr_ref: usize = self.pop()?.as_array()?;
        let field_token: u32 = (token as u64 & 0xFFFF_FFFF) as u32;
        let data: Vec<u8> = self
            .env
            .field_data
            .get(&field_token)
            .cloned()
            .ok_or(EmulationError::BadShape)?;
        let arr: &mut HeapArray = self
            .heap
            .get_mut(arr_ref)
            .ok_or(EmulationError::OutOfBounds)?;
        let n: usize = data.len().min(arr.bytes.len());
        arr.bytes[..n].copy_from_slice(&data[..n]);
        Ok(())
    }

    fn exec_string_char_ctor(&mut self) -> Result<(), EmulationError> {
        let value: Value = self.pop()?;
        let array_ref: usize = value.as_array()?;
        let source: &HeapArray = self
            .heap
            .get(array_ref)
            .ok_or(EmulationError::OutOfBounds)?;
        if source.kind != HeapKind::CharArray {
            return Err(EmulationError::BadShape);
        }
        let bytes: Vec<u8> = source.bytes.clone();
        let string_ref: usize = self.alloc(source.len(), 2, HeapKind::String)?;
        let target: &mut HeapArray = self
            .heap
            .get_mut(string_ref)
            .ok_or(EmulationError::OutOfBounds)?;
        target.bytes.copy_from_slice(&bytes);
        self.stack.push(Value::String(Some(string_ref)));
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn run(&mut self) -> Result<StubOutput, EmulationError> {
        let mut ip: usize = 0;
        loop {
            self.steps += 1;
            if self.steps > STEP_LIMIT {
                return Err(EmulationError::StepLimitExceeded);
            }
            let ins: &Instruction = self
                .body
                .instructions
                .get(ip)
                .ok_or(EmulationError::NoResult)?;
            let mut next: usize = ip + 1;
            match ins.name.as_str() {
                "nop" | "break" => {}
                "pop" => {
                    self.pop()?;
                }
                n if n.starts_with("ldc.i4") => {
                    self.stack.push(Value::I32(int_const(ins, n)));
                }
                "ldc.i8" => {
                    if let OperandValue::I64(v) = ins.operand {
                        self.stack.push(Value::I64(v));
                    }
                }
                "dup" => {
                    let v: Value = *self.stack.last().ok_or(EmulationError::StackUnderflow)?;
                    self.stack.push(v);
                }
                n if n.starts_with("ldloc") => {
                    let idx: u32 = slot_index(ins, n);
                    let v: Value = *self.local(idx)?;
                    self.stack.push(v);
                }
                n if n.starts_with("stloc") => {
                    let idx: u32 = slot_index(ins, n);
                    let v: Value = self.pop()?;
                    *self.local(idx)? = v;
                }
                n if n.starts_with("ldarg") => {
                    let idx: u32 = slot_index(ins, n);
                    let v: Value = self.arg(idx)?;
                    self.stack.push(v);
                }
                n if n.starts_with("starg") => {
                    let idx: usize = slot_index(ins, n) as usize;
                    let v: Value = self.pop()?;
                    if idx < self.args.len() {
                        self.args[idx] = v;
                    }
                }
                "add" | "add.ovf" | "add.ovf.un" => self.bin_i(i64::wrapping_add)?,
                "sub" | "sub.ovf" | "sub.ovf.un" => self.bin_i(i64::wrapping_sub)?,
                "mul" | "mul.ovf" | "mul.ovf.un" => self.bin_i(i64::wrapping_mul)?,
                "and" => self.bin_i(|a: i64, b: i64| a & b)?,
                "or" => self.bin_i(|a: i64, b: i64| a | b)?,
                "xor" => self.bin_i(|a: i64, b: i64| a ^ b)?,
                "shl" => self.bin_i(|a: i64, b: i64| a.wrapping_shl(b as u32))?,
                "shr" => self.bin_i(|a: i64, b: i64| a.wrapping_shr(b as u32))?,
                "shr.un" => {
                    self.bin_i(|a: i64, b: i64| i64::from((a as u32).wrapping_shr(b as u32)))?;
                }
                "div" => self.bin_checked(i64::checked_div)?,
                "rem" => self.bin_checked(i64::checked_rem)?,
                "div.un" => {
                    self.bin_checked(|a, b| {
                        if b == 0 {
                            None
                        } else {
                            Some(i64::from((a as u32).wrapping_div(b as u32)))
                        }
                    })?;
                }
                "rem.un" => {
                    self.bin_checked(|a, b| {
                        if b == 0 {
                            None
                        } else {
                            Some(i64::from((a as u32).wrapping_rem(b as u32)))
                        }
                    })?;
                }
                "neg" => {
                    let v: i64 = self.pop()?.as_i64()?;
                    self.stack.push(Value::I32(v.wrapping_neg() as i32));
                }
                "not" => {
                    let v: i64 = self.pop()?.as_i64()?;
                    self.stack.push(Value::I32(!(v as i32)));
                }
                n if n.starts_with("conv.") => {
                    let v: Value = self.pop()?;
                    self.stack.push(convert_numeric(n, v)?);
                }
                "ldlen" => {
                    let r: usize = self.pop()?.as_array()?;
                    let len: usize = self.heap.get(r).ok_or(EmulationError::OutOfBounds)?.len();
                    self.stack.push(Value::I32(len as i32));
                }
                "newarr" => {
                    let len: i64 = self.pop()?.as_i64()?;
                    if len < 0 {
                        return Err(EmulationError::OutOfBounds);
                    }
                    let elem: usize = self.elem_size_for(ins);
                    let kind: HeapKind = self.array_kind_for(ins);
                    let r: usize = self.alloc(len as usize, elem, kind)?;
                    self.stack.push(Value::Array(Some(r)));
                }
                n if n.starts_with("ldelem") => {
                    let elem: usize = ldelem_size(n);
                    let idx: i64 = self.pop()?.as_i64()?;
                    let r: usize = self.pop()?.as_array()?;
                    let arr: &HeapArray = self.heap.get(r).ok_or(EmulationError::OutOfBounds)?;
                    let real_elem: usize = if n == "ldelem.i" || n == "ldelem.ref" {
                        arr.elem_size
                    } else {
                        elem
                    };
                    let v: i64 = arr.load(
                        usize::try_from(idx).map_err(|_| EmulationError::OutOfBounds)?,
                        real_elem.max(1),
                    )?;
                    self.stack.push(Value::I32(v as i32));
                }
                n if n.starts_with("stelem") => {
                    let elem: usize = stelem_size(n);
                    let v: i64 = self.pop()?.as_i64()?;
                    let idx: i64 = self.pop()?.as_i64()?;
                    let r: usize = self.pop()?.as_array()?;
                    let arr: &mut HeapArray =
                        self.heap.get_mut(r).ok_or(EmulationError::OutOfBounds)?;
                    let real_elem: usize = if n == "stelem.i" || n == "stelem.ref" {
                        arr.elem_size
                    } else {
                        elem
                    };
                    arr.store(
                        usize::try_from(idx).map_err(|_| EmulationError::OutOfBounds)?,
                        real_elem.max(1),
                        v,
                    )?;
                }
                "br" | "br.s" => {
                    next = self.branch(ins)?;
                }
                "switch" => {
                    let index: i64 = self.pop()?.as_i64()?;
                    let OperandValue::Switch(targets) = &ins.operand else {
                        return Err(EmulationError::BadShape);
                    };
                    if let Ok(index) = usize::try_from(index)
                        && let Some(relative) = targets.get(index)
                    {
                        let target: u32 = checked_post_offset(self, ins, *relative)
                            .ok_or(EmulationError::BadShape)?;
                        next = self.ip_of(target).ok_or(EmulationError::BadShape)?;
                    }
                }
                "brtrue" | "brtrue.s" => {
                    let v: Value = self.pop()?;
                    if truthy(v) {
                        next = self.branch(ins)?;
                    }
                }
                "brfalse" | "brfalse.s" => {
                    let v: Value = self.pop()?;
                    if !truthy(v) {
                        next = self.branch(ins)?;
                    }
                }
                "beq" | "beq.s" => next = self.branch_if(ins, |a, b| a == b, next)?,
                "bne.un" | "bne.un.s" => next = self.branch_if(ins, |a, b| a != b, next)?,
                "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => {
                    next = self.branch_if(ins, |a, b| a > b, next)?;
                }
                "bge" | "bge.s" | "bge.un" | "bge.un.s" => {
                    next = self.branch_if(ins, |a, b| a >= b, next)?;
                }
                "blt" | "blt.s" | "blt.un" | "blt.un.s" => {
                    next = self.branch_if(ins, |a, b| a < b, next)?;
                }
                "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                    next = self.branch_if(ins, |a, b| a <= b, next)?;
                }
                "ceq" => self.cmp(|a, b| a == b)?,
                "cgt" | "cgt.un" => self.cmp(|a, b| a > b)?,
                "clt" | "clt.un" => self.cmp(|a, b| a < b)?,
                "ret" => return self.finish(),
                "ldtoken" => {
                    let tok: u32 = match ins.operand {
                        OperandValue::Token(t) => t,
                        _ => return Err(EmulationError::BadShape),
                    };
                    self.stack.push(Value::I32(tok.cast_signed()));
                }
                "call" if self.is_init_array_call(ins) => {
                    self.exec_init_array()?;
                }
                "newobj" if self.is_string_char_ctor(ins) => {
                    self.exec_string_char_ctor()?;
                }
                "call" | "callvirt" | "calli" | "newobj" | "ldsfld" | "ldfld" | "stfld"
                | "ldstr" | "box" | "unbox" | "unbox.any" | "castclass" | "isinst" => {
                    return Err(EmulationError::ExternalCall);
                }
                other => return Err(EmulationError::UnsupportedOpcode(other.to_owned())),
            }
            ip = next;
        }
    }

    fn finish(&mut self) -> Result<StubOutput, EmulationError> {
        let v: Value = self.pop()?;
        match v {
            Value::I32(i) => Ok(StubOutput::Int(i64::from(i))),
            Value::I64(i) => Ok(StubOutput::Int(i)),
            Value::Array(Some(r)) => {
                let arr: &HeapArray = self.heap.get(r).ok_or(EmulationError::OutOfBounds)?;
                if arr.elem_size == 2 {
                    let units: Vec<u16> = arr
                        .bytes
                        .chunks_exact(2)
                        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16(&units)
                        .map(StubOutput::Utf16)
                        .map_err(|_| EmulationError::BadShape)
                } else {
                    Ok(StubOutput::Bytes(arr.bytes.clone()))
                }
            }
            Value::Array(None) | Value::String(None) => Err(EmulationError::NoResult),
            Value::String(Some(r)) => {
                let string: &HeapArray = self.heap.get(r).ok_or(EmulationError::OutOfBounds)?;
                if string.kind != HeapKind::String || string.elem_size != 2 {
                    return Err(EmulationError::BadShape);
                }
                let units: Vec<u16> = string
                    .bytes
                    .chunks_exact(2)
                    .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&units)
                    .map(StubOutput::Utf16)
                    .map_err(|_| EmulationError::BadShape)
            }
        }
    }

    fn branch(&self, ins: &Instruction) -> Result<usize, EmulationError> {
        let target: u32 = match ins.operand {
            OperandValue::BrTarget(rel) => post_offset(self, ins, rel),
            _ => return Err(EmulationError::BadShape),
        };
        self.ip_of(target).ok_or(EmulationError::BadShape)
    }

    fn branch_if(
        &mut self,
        ins: &Instruction,
        pred: fn(i64, i64) -> bool,
        fallthrough: usize,
    ) -> Result<usize, EmulationError> {
        let b: i64 = self.pop()?.as_i64()?;
        let a: i64 = self.pop()?.as_i64()?;
        if pred(a, b) {
            self.branch(ins)
        } else {
            Ok(fallthrough)
        }
    }

    fn bin_i(&mut self, op: fn(i64, i64) -> i64) -> Result<(), EmulationError> {
        let b: i64 = self.pop()?.as_i64()?;
        let a: i64 = self.pop()?.as_i64()?;
        self.stack.push(Value::I32(op(a, b) as i32));
        Ok(())
    }

    fn bin_checked(&mut self, op: fn(i64, i64) -> Option<i64>) -> Result<(), EmulationError> {
        let b: i64 = self.pop()?.as_i64()?;
        let a: i64 = self.pop()?.as_i64()?;
        let r: i64 = op(a, b).ok_or(EmulationError::DivideByZero)?;
        self.stack.push(Value::I32(r as i32));
        Ok(())
    }

    fn cmp(&mut self, pred: fn(i64, i64) -> bool) -> Result<(), EmulationError> {
        let b: i64 = self.pop()?.as_i64()?;
        let a: i64 = self.pop()?.as_i64()?;
        self.stack.push(Value::I32(i32::from(pred(a, b))));
        Ok(())
    }
}

fn post_offset(vm: &Vm<'_>, ins: &Instruction, rel: i32) -> u32 {
    let ip: usize = vm.ip_of(ins.offset).unwrap_or(0);
    let next_off: u32 = vm.index_of.get(ip + 1).copied().unwrap_or(ins.offset);
    (i64::from(next_off) + i64::from(rel)) as u32
}

fn validate_switch_targets(body: &MethodBody, index_of: &[u32]) -> Result<(), EmulationError> {
    if body.instructions.len() > MAX_EMULATED_INSTRUCTIONS {
        return Err(EmulationError::OutOfBounds);
    }
    let mut switch_targets: usize = 0;
    for (index, instruction) in body.instructions.iter().enumerate() {
        let OperandValue::Switch(targets) = &instruction.operand else {
            continue;
        };
        if !body.exception_clauses.is_empty() {
            return Err(EmulationError::BadShape);
        }
        switch_targets = switch_targets
            .checked_add(targets.len())
            .filter(|count: &usize| *count <= MAX_SWITCH_TARGETS)
            .ok_or(EmulationError::OutOfBounds)?;
        let next_index: usize = index.checked_add(1).ok_or(EmulationError::BadShape)?;
        let next_offset: u32 = *index_of.get(next_index).ok_or(EmulationError::BadShape)?;
        for relative in targets {
            let target: i64 = i64::from(next_offset)
                .checked_add(i64::from(*relative))
                .ok_or(EmulationError::BadShape)?;
            let target: u32 = u32::try_from(target).map_err(|_| EmulationError::BadShape)?;
            let target_index: usize = index_of
                .binary_search(&target)
                .map_err(|_| EmulationError::BadShape)?;
            if target_index > 0
                && is_prefix(
                    body.instructions
                        .get(target_index - 1)
                        .ok_or(EmulationError::BadShape)?,
                )
            {
                return Err(EmulationError::BadShape);
            }
        }
    }
    Ok(())
}

fn is_prefix(instruction: &Instruction) -> bool {
    matches!(
        instruction.name.as_str(),
        "unaligned." | "volatile." | "tail." | "constrained." | "no." | "readonly."
    )
}

fn checked_post_offset(vm: &Vm<'_>, ins: &Instruction, rel: i32) -> Option<u32> {
    let ip: usize = vm.ip_of(ins.offset)?;
    let next_off: u32 = *vm.index_of.get(ip.checked_add(1)?)?;
    let target: i64 = i64::from(next_off).checked_add(i64::from(rel))?;
    u32::try_from(target).ok()
}

const fn truthy(v: Value) -> bool {
    match v {
        Value::I32(i) => i != 0,
        Value::I64(i) => i != 0,
        Value::Array(opt) | Value::String(opt) => opt.is_some(),
    }
}

fn convert_numeric(name: &str, v: Value) -> Result<Value, EmulationError> {
    let target: &str = name
        .strip_prefix("conv.")
        .unwrap_or(name)
        .trim_start_matches("ovf.")
        .trim_end_matches(".un");
    let src: i64 = v.as_i64()?;
    let out: Value = match target {
        "i1" => Value::I32(i32::from(src as i8)),
        "u1" => Value::I32(i32::from(src as u8)),
        "i2" => Value::I32(i32::from(src as i16)),
        "u2" => Value::I32(i32::from(src as u16)),
        "i4" | "u4" => Value::I32(src as i32),
        "i8" | "i" => Value::I64(src),
        "u8" | "u" => Value::I64(zero_extend_word(v)),
        _ => return Err(EmulationError::UnsupportedOpcode(name.to_owned())),
    };
    Ok(out)
}

fn zero_extend_word(v: Value) -> i64 {
    match v {
        Value::I32(x) => i64::from(x.cast_unsigned()),
        Value::I64(x) => x,
        Value::Array(_) | Value::String(_) => 0,
    }
}

fn int_const(ins: &Instruction, name: &str) -> i32 {
    if let Some(rest) = name.strip_prefix("ldc.i4.") {
        return match rest {
            "m1" => -1,
            "s" => match ins.operand {
                OperandValue::U8(b) => i32::from(b.cast_signed()),
                _ => 0,
            },
            d => d.parse::<i32>().unwrap_or(0),
        };
    }
    if name == "ldc.i4"
        && let OperandValue::I32(v) = ins.operand
    {
        return v;
    }
    0
}

fn slot_index(ins: &Instruction, name: &str) -> u32 {
    if let Some(rest) = name.rsplit('.').next()
        && let Ok(n) = rest.parse::<u32>()
    {
        return n;
    }
    match ins.operand {
        OperandValue::U8(b) => u32::from(b),
        OperandValue::U16(v) => u32::from(v),
        OperandValue::I32(v) => v.cast_unsigned(),
        _ => 0,
    }
}

const fn ldelem_size(name: &str) -> usize {
    match name.as_bytes() {
        b"ldelem.i1" | b"ldelem.u1" => 1,
        b"ldelem.i2" | b"ldelem.u2" => 2,
        b"ldelem.i8" => 8,
        _ => 4,
    }
}

const fn stelem_size(name: &str) -> usize {
    match name.as_bytes() {
        b"stelem.i1" => 1,
        b"stelem.i2" => 2,
        b"stelem.i8" => 8,
        _ => 4,
    }
}

pub fn emulate_stub(body: &MethodBody, input: &StubInput) -> Result<StubOutput, EmulationError> {
    emulate_stub_with_init(body, input, &FieldInitEnv::default())
}

pub fn emulate_stub_with_init(
    body: &MethodBody,
    input: &StubInput,
    env: &FieldInitEnv,
) -> Result<StubOutput, EmulationError> {
    validate_stub_body(body)?;
    emulate_stub_with_init_prevalidated(body, input, env)
}

pub(crate) fn validate_stub_body(body: &MethodBody) -> Result<(), EmulationError> {
    let index_of: Vec<u32> = body
        .instructions
        .iter()
        .map(|instruction: &Instruction| instruction.offset)
        .collect();
    validate_switch_targets(body, &index_of)
}

pub(crate) fn emulate_stub_with_init_prevalidated(
    body: &MethodBody,
    input: &StubInput,
    env: &FieldInitEnv,
) -> Result<StubOutput, EmulationError> {
    let mut heap: Vec<HeapArray> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    let mut heap_bytes: usize = 0;
    for &i in &input.int_args {
        args.push(Value::I64(i));
    }
    for bytes in &input.byte_array_args {
        heap_bytes = heap_bytes
            .checked_add(bytes.len())
            .filter(|total: &usize| *total <= MAX_HEAP_BYTES)
            .ok_or(EmulationError::OutOfBounds)?;
        if bytes.len() > MAX_ARRAY || heap.len() >= MAX_HEAP {
            return Err(EmulationError::OutOfBounds);
        }
        let mut arr: HeapArray = HeapArray::new(bytes.len(), 1, HeapKind::ByteArray);
        arr.bytes.copy_from_slice(bytes);
        heap.push(arr);
        args.push(Value::Array(Some(heap.len() - 1)));
    }
    for chars in &input.char_array_args {
        let bytes_len: usize = chars
            .len()
            .checked_mul(2)
            .ok_or(EmulationError::OutOfBounds)?;
        heap_bytes = heap_bytes
            .checked_add(bytes_len)
            .filter(|total: &usize| *total <= MAX_HEAP_BYTES)
            .ok_or(EmulationError::OutOfBounds)?;
        if bytes_len > MAX_ARRAY || heap.len() >= MAX_HEAP {
            return Err(EmulationError::OutOfBounds);
        }
        let mut arr: HeapArray = HeapArray::new(chars.len(), 2, HeapKind::CharArray);
        for (i, unit) in chars.iter().enumerate() {
            let off: usize = i * 2;
            arr.bytes[off] = (unit & 0xFF) as u8;
            arr.bytes[off + 1] = (unit >> 8) as u8;
        }
        heap.push(arr);
        args.push(Value::Array(Some(heap.len() - 1)));
    }
    let mut vm: Vm<'_> = Vm::with_env(body, args, heap, heap_bytes, env.clone());
    vm.run()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn emulates_constant_addition() {
        let body: MethodBody = body_from(&[0x1F, 40, 0x18, 0x58, 0x2A]);
        let out: StubOutput = emulate_stub(&body, &StubInput::default()).expect("run");
        assert_eq!(out, StubOutput::Int(42));
    }

    #[test]
    fn emulates_xor_of_argument() {
        let body: MethodBody = body_from(&[0x02, 0x1F, 0x5A, 0x61, 0x2A]);
        let input: StubInput = StubInput {
            int_args: vec![0x0F],
            byte_array_args: vec![],
            char_array_args: vec![],
        };
        let out: StubOutput = emulate_stub(&body, &input).expect("run");
        assert_eq!(out, StubOutput::Int(i64::from(0x0F ^ 0x5A)));
    }

    #[test]
    fn external_call_aborts_cleanly() {
        let mut code: Vec<u8> = vec![0x16, 0x28];
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let err: EmulationError =
            emulate_stub(&body, &StubInput::default()).expect_err("external call");
        assert_eq!(err, EmulationError::ExternalCall);
    }

    #[test]
    fn switch_rejects_an_invalid_unselected_target() {
        let mut code: Vec<u8> = vec![0x16, 0x45];
        code.extend_from_slice(&2u32.to_le_bytes());
        code.extend_from_slice(&0i32.to_le_bytes());
        code.extend_from_slice(&i32::MAX.to_le_bytes());
        code.extend_from_slice(&[0x17, 0x2A]);
        let body: MethodBody = body_from(&code);
        let error: EmulationError =
            emulate_stub(&body, &StubInput::default()).expect_err("invalid switch target");
        assert_eq!(error, EmulationError::BadShape);
    }

    #[test]
    fn switch_rejects_a_target_after_a_prefix() {
        let mut code: Vec<u8> = vec![0x16, 0x45];
        code.extend_from_slice(&1u32.to_le_bytes());
        code.extend_from_slice(&2i32.to_le_bytes());
        code.extend_from_slice(&[0xFE, 0x13, 0x17, 0x2A]);
        let body: MethodBody = body_from(&code);
        let error: EmulationError =
            emulate_stub(&body, &StubInput::default()).expect_err("target after prefix");
        assert_eq!(error, EmulationError::BadShape);
    }

    #[test]
    fn switch_negative_and_out_of_range_selectors_fall_through() {
        for selector in [0x15, 0x17] {
            let mut code: Vec<u8> = vec![selector, 0x45];
            code.extend_from_slice(&1u32.to_le_bytes());
            code.extend_from_slice(&2i32.to_le_bytes());
            code.extend_from_slice(&[0x17, 0x2A, 0x18, 0x2A]);
            let body: MethodBody = body_from(&code);
            let output: StubOutput =
                emulate_stub(&body, &StubInput::default()).expect("switch fallthrough");
            assert_eq!(output, StubOutput::Int(1));
        }
    }

    #[test]
    fn constructed_string_cannot_be_used_as_an_array() {
        let char_token: u32 = 0x0100_0001;
        let ctor_token: u32 = 0x0A00_0001;
        let mut code: Vec<u8> = vec![0x17, 0x8D];
        code.extend_from_slice(&char_token.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x16, 0x1F, 65, 0x9D, 0x73]);
        code.extend_from_slice(&ctor_token.to_le_bytes());
        code.extend_from_slice(&[0x16, 0x93, 0x2A]);
        let body: MethodBody = body_from(&code);
        let mut env: FieldInitEnv = FieldInitEnv::default();
        env.array_elem_sizes.insert(char_token, 2);
        env.char_array_tokens.insert(char_token);
        env.string_char_ctor_tokens.insert(ctor_token);
        let error: EmulationError = emulate_stub_with_init(&body, &StubInput::default(), &env)
            .expect_err("string is not an array");
        assert_eq!(error, EmulationError::BadShape);
    }

    #[test]
    fn string_constructor_rejects_unpaired_utf16() {
        let char_token: u32 = 0x0100_0001;
        let ctor_token: u32 = 0x0A00_0001;
        let mut code: Vec<u8> = vec![0x17, 0x8D];
        code.extend_from_slice(&char_token.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x16, 0x20]);
        code.extend_from_slice(&0xD800i32.to_le_bytes());
        code.extend_from_slice(&[0x9D, 0x73]);
        code.extend_from_slice(&ctor_token.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let mut env: FieldInitEnv = FieldInitEnv::default();
        env.array_elem_sizes.insert(char_token, 2);
        env.char_array_tokens.insert(char_token);
        env.string_char_ctor_tokens.insert(ctor_token);
        let error: EmulationError =
            emulate_stub_with_init(&body, &StubInput::default(), &env).expect_err("invalid UTF-16");
        assert_eq!(error, EmulationError::BadShape);
    }

    #[test]
    fn string_constructor_rejects_a_two_byte_non_char_array() {
        let short_token: u32 = 0x0100_0001;
        let ctor_token: u32 = 0x0A00_0001;
        let mut code: Vec<u8> = vec![0x17, 0x8D];
        code.extend_from_slice(&short_token.to_le_bytes());
        code.extend_from_slice(&[0x73]);
        code.extend_from_slice(&ctor_token.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let mut env: FieldInitEnv = FieldInitEnv::default();
        env.array_elem_sizes.insert(short_token, 2);
        env.string_char_ctor_tokens.insert(ctor_token);
        let error: EmulationError = emulate_stub_with_init(&body, &StubInput::default(), &env)
            .expect_err("short array is not char array");
        assert_eq!(error, EmulationError::BadShape);
    }

    #[test]
    fn string_constructor_copies_the_source_array() {
        let char_token: u32 = 0x0100_0001;
        let ctor_token: u32 = 0x0A00_0001;
        let mut code: Vec<u8> = vec![0x17, 0x8D];
        code.extend_from_slice(&char_token.to_le_bytes());
        code.extend_from_slice(&[0x0A, 0x06, 0x16, 0x1F, 65, 0x9D, 0x06, 0x73]);
        code.extend_from_slice(&ctor_token.to_le_bytes());
        code.extend_from_slice(&[0x0B, 0x06, 0x16, 0x1F, 66, 0x9D, 0x07, 0x2A]);
        let body: MethodBody = body_from(&code);
        let mut env: FieldInitEnv = FieldInitEnv::default();
        env.array_elem_sizes.insert(char_token, 2);
        env.char_array_tokens.insert(char_token);
        env.string_char_ctor_tokens.insert(ctor_token);
        let output: StubOutput =
            emulate_stub_with_init(&body, &StubInput::default(), &env).expect("construct string");
        assert_eq!(output, StubOutput::Utf16("A".to_owned()));
    }

    #[test]
    fn empty_ret_reports_stack_underflow() {
        let body: MethodBody = body_from(&[0x2A]);
        let err: EmulationError =
            emulate_stub(&body, &StubInput::default()).expect_err("empty ret");
        assert_eq!(err, EmulationError::StackUnderflow);
    }

    #[test]
    fn step_limit_halts_infinite_loop() {
        let body: MethodBody = body_from(&[0x2B, 0xFE, 0x2A]);
        let err: EmulationError = emulate_stub(&body, &StubInput::default()).expect_err("infinite");
        assert_eq!(err, EmulationError::StepLimitExceeded);
    }

    #[test]
    fn decrypts_byte_array_xor_loop_to_string() {
        let mut code: Vec<u8> = Vec::new();
        code.push(0x16);
        code.push(0x0A);
        let loop_start: i32 = code.len() as i32;
        code.push(0x02);
        code.push(0x06);
        code.push(0x02);
        code.push(0x06);
        code.push(0x91);
        code.push(0x1F);
        code.push(0x10);
        code.push(0x61);
        code.push(0x9C);
        code.push(0x06);
        code.push(0x17);
        code.push(0x58);
        code.push(0x0A);
        code.push(0x06);
        code.push(0x02);
        code.push(0x8E);
        let blt_op_pos: i32 = code.len() as i32 + 1;
        let rel: i32 = loop_start - (blt_op_pos + 1);
        code.push(0x32);
        code.push(rel as u8);
        code.push(0x02);
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let plain: &[u8] = b"Secret";
        let cipher: Vec<u8> = plain.iter().map(|b: &u8| b ^ 0x10).collect();
        let input: StubInput = StubInput {
            int_args: vec![],
            byte_array_args: vec![cipher],
            char_array_args: vec![],
        };
        let out: StubOutput = emulate_stub(&body, &input).expect("decrypt");
        assert_eq!(out, StubOutput::Bytes(plain.to_vec()));
    }

    fn eval_conv(opcode: u8, value: i32) -> StubOutput {
        let mut code: Vec<u8> = vec![0x20];
        code.extend_from_slice(&value.to_le_bytes());
        code.push(opcode);
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        emulate_stub(&body, &StubInput::default()).expect("conv")
    }

    #[test]
    fn conv_u1_zero_extends_low_byte() {
        assert_eq!(eval_conv(0xD2, 0x1234), StubOutput::Int(0x34));
    }

    #[test]
    fn conv_i1_sign_extends_low_byte() {
        assert_eq!(eval_conv(0x67, 0xFF), StubOutput::Int(-1));
    }

    #[test]
    fn conv_u2_zero_extends_low_word() {
        assert_eq!(eval_conv(0xD1, 0x0001_0041), StubOutput::Int(0x41));
    }

    #[test]
    fn conv_i2_sign_extends_low_word() {
        assert_eq!(eval_conv(0x68, 0xFFFF), StubOutput::Int(-1));
    }

    #[test]
    fn conv_u8_zero_extends_negative_int32() {
        let body: MethodBody = body_from(&[0x15, 0x6E, 0x2A]);
        let out: StubOutput = emulate_stub(&body, &StubInput::default()).expect("conv.u8");
        assert_eq!(out, StubOutput::Int(0xFFFF_FFFF));
    }

    #[test]
    fn conv_float_is_rejected_not_silently_wrong() {
        let body: MethodBody = body_from(&[0x16, 0x6B, 0x2A]);
        let err: EmulationError =
            emulate_stub(&body, &StubInput::default()).expect_err("float conv");
        assert_eq!(err, EmulationError::UnsupportedOpcode("conv.r4".to_owned()));
    }

    #[test]
    fn rolling_byte_key_shift_decoder_matches_wrapping_reference() {
        let mut code: Vec<u8> = vec![0x16, 0x0A, 0x16, 0x0B];
        let loop_start: i32 = code.len() as i32;
        code.extend_from_slice(&[0x07, 0x02, 0x06, 0x91, 0x58, 0xD2, 0x0B]);
        code.extend_from_slice(&[0x02, 0x06, 0x02, 0x06, 0x91, 0x07, 0x19, 0x63, 0x61, 0x9C]);
        code.extend_from_slice(&[0x06, 0x17, 0x58, 0x0A]);
        code.extend_from_slice(&[0x06, 0x02, 0x8E]);
        let blt_op_pos: i32 = code.len() as i32 + 1;
        let rel: i32 = loop_start - (blt_op_pos + 1);
        code.push(0x32);
        code.push(rel as u8);
        code.push(0x02);
        code.push(0x2A);
        let body: MethodBody = body_from(&code);

        let cipher: Vec<u8> = (0u8..48)
            .map(|n: u8| n.wrapping_mul(7).wrapping_add(20))
            .collect();
        let mut key: u8 = 0;
        let mut expected: Vec<u8> = Vec::with_capacity(cipher.len());
        for &b in &cipher {
            key = key.wrapping_add(b);
            expected.push(b ^ (key >> 3));
        }

        let input: StubInput = StubInput {
            int_args: vec![],
            byte_array_args: vec![cipher],
            char_array_args: vec![],
        };
        let out: StubOutput = emulate_stub(&body, &input).expect("rolling decode");
        assert_eq!(out, StubOutput::Bytes(expected));
    }
}
