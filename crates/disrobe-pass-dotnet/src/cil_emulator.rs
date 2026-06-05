//! Sandboxed CIL interpreter for self-contained decryption stubs.

use crate::cil::{Instruction, MethodBody, OperandValue};

/// Reasons a stub emulation halts without producing output.
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
const MAX_HEAP: usize = 4096;

/// A runtime value on the evaluation stack or in a local/argument slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    I32(i32),
    I64(i64),
    /// Index into the array heap; `None` is the null reference.
    Array(Option<usize>),
}

impl Value {
    const fn as_i64(self) -> Result<i64, EmulationError> {
        match self {
            Self::I32(v) => Ok(v as i64),
            Self::I64(v) => Ok(v),
            Self::Array(_) => Err(EmulationError::BadShape),
        }
    }

    const fn as_array(self) -> Result<usize, EmulationError> {
        match self {
            Self::Array(Some(r)) => Ok(r),
            Self::Array(None) => Err(EmulationError::OutOfBounds),
            Self::I32(_) | Self::I64(_) => Err(EmulationError::BadShape),
        }
    }
}

/// A heap array tracking its element width for `byte[]` vs `char[]` semantics.
#[derive(Debug, Clone)]
struct HeapArray {
    bytes: Vec<u8>,
    elem_size: usize,
}

impl HeapArray {
    fn new(len: usize, elem_size: usize) -> Self {
        Self {
            bytes: vec![0u8; len.saturating_mul(elem_size)],
            elem_size,
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

/// The decoded output of a successful stub emulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubOutput {
    /// A returned integer (e.g. a constant decoder).
    Int(i64),
    /// A returned `byte[]`/`char[]` reinterpreted as raw bytes.
    Bytes(Vec<u8>),
    /// A returned array reinterpreted as a UTF-16 string (for `char[]`/2-byte element arrays).
    Utf16(String),
}

/// Inputs supplied to the stub: argument slots (the cipher buffer + any integer keys).
#[derive(Debug, Clone, Default)]
pub struct StubInput {
    pub int_args: Vec<i64>,
    pub byte_array_args: Vec<Vec<u8>>,
}

struct Vm<'a> {
    body: &'a MethodBody,
    index_of: Vec<u32>,
    stack: Vec<Value>,
    locals: Vec<Value>,
    args: Vec<Value>,
    heap: Vec<HeapArray>,
    steps: u64,
}

impl<'a> Vm<'a> {
    fn new(body: &'a MethodBody, args: Vec<Value>, heap: Vec<HeapArray>) -> Self {
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
            steps: 0,
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

    fn alloc(&mut self, len: usize, elem: usize) -> Result<usize, EmulationError> {
        if self.heap.len() >= MAX_HEAP || len.saturating_mul(elem) > MAX_ARRAY {
            return Err(EmulationError::OutOfBounds);
        }
        self.heap.push(HeapArray::new(len, elem));
        Ok(self.heap.len() - 1)
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
                n if n.starts_with("conv.i8") || n.starts_with("conv.u8") => {
                    let v: i64 = self.pop()?.as_i64()?;
                    self.stack.push(Value::I64(v));
                }
                n if n.starts_with("conv.") => {
                    let v: i64 = self.pop()?.as_i64()?;
                    self.stack.push(Value::I32(v as i32));
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
                    let elem: usize = element_size_from_token(ins);
                    let r: usize = self.alloc(len as usize, elem)?;
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
        let v: Value = self.pop().unwrap_or(Value::I32(0));
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
                    Ok(StubOutput::Utf16(String::from_utf16_lossy(&units)))
                } else {
                    Ok(StubOutput::Bytes(arr.bytes.clone()))
                }
            }
            Value::Array(None) => Err(EmulationError::NoResult),
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

const fn truthy(v: Value) -> bool {
    match v {
        Value::I32(i) => i != 0,
        Value::I64(i) => i != 0,
        Value::Array(opt) => opt.is_some(),
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

/// `newarr` element size, defaulting to 1 byte (`byte[]`) without token resolution.
const fn element_size_from_token(_ins: &Instruction) -> usize {
    1
}

/// Emulate a decryption stub body with the supplied inputs.
pub fn emulate_stub(body: &MethodBody, input: &StubInput) -> Result<StubOutput, EmulationError> {
    let mut heap: Vec<HeapArray> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    for &i in &input.int_args {
        args.push(Value::I64(i));
    }
    for bytes in &input.byte_array_args {
        let mut arr: HeapArray = HeapArray::new(bytes.len(), 1);
        arr.bytes.copy_from_slice(bytes);
        heap.push(arr);
        args.push(Value::Array(Some(heap.len() - 1)));
    }
    let mut vm: Vm<'_> = Vm::new(body, args, heap);
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
        };
        let out: StubOutput = emulate_stub(&body, &input).expect("decrypt");
        assert_eq!(out, StubOutput::Bytes(plain.to_vec()));
    }
}
