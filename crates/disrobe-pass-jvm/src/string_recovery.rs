use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{self, Instruction, Operands};
use crate::classfile::{ClassFile, ConstantPoolEntry};

const STEP_LIMIT: u64 = 4_000_000;
const MAX_HEAP_OBJECTS: usize = 8_192;
const MAX_STRING_LEN: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    UnsupportedOpcode(u8),
    StackUnderflow,
    BadLocal(usize),
    StepLimitExceeded,
    NoReturn,
    BadShape,
    UnknownCall(String),
    HeapExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeapObject {
    Chars(Vec<u16>),
    Text(Vec<u16>),
    Builder(Vec<u16>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(i32),
    Long(i64),
    Ref(usize),
    Null,
}

impl Value {
    const fn as_int(self) -> Result<i32, RecoveryError> {
        match self {
            Self::Int(v) => Ok(v),
            _ => Err(RecoveryError::BadShape),
        }
    }

    const fn as_long(self) -> Result<i64, RecoveryError> {
        match self {
            Self::Long(v) => Ok(v),
            _ => Err(RecoveryError::BadShape),
        }
    }

    const fn as_ref(self) -> Result<usize, RecoveryError> {
        match self {
            Self::Ref(r) => Ok(r),
            _ => Err(RecoveryError::BadShape),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringDecryptStub {
    code: Vec<u8>,
    max_locals: u16,
    is_static: bool,
    takes_int: bool,
    int_first: bool,
    method_index: usize,
}

impl StringDecryptStub {
    #[inline]
    #[must_use]
    pub const fn takes_int_seed(&self) -> bool {
        self.takes_int
    }
}

#[must_use]
pub fn find_string_decrypt_methods(cf: &ClassFile) -> Vec<StringDecryptStub> {
    let mut stubs: Vec<StringDecryptStub> = Vec::new();
    for (mi, method) in cf.methods.iter().enumerate() {
        let Ok(desc): Result<&str, crate::error::Error> = cf.utf8_at(method.descriptor_index)
        else {
            continue;
        };
        let (takes_int, int_first, ok): (bool, bool, bool) = match desc {
            "(Ljava/lang/String;)Ljava/lang/String;" => (false, false, true),
            "(Ljava/lang/Object;)Ljava/lang/String;" => (false, false, true),
            "(Ljava/lang/String;I)Ljava/lang/String;" => (true, false, true),
            "(ILjava/lang/String;)Ljava/lang/String;" => (true, true, true),
            _ => (false, false, false),
        };
        if !ok {
            continue;
        }
        let is_static: bool = method.access_flags & 0x0008 != 0;
        for attr in &method.attributes {
            let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
                continue;
            };
            if name != "Code" {
                continue;
            }
            let Ok(code): Result<bytecode::CodeAttribute, crate::error::Error> =
                bytecode::parse_code_attribute(&attr.info)
            else {
                continue;
            };
            stubs.push(StringDecryptStub {
                code: code.code,
                max_locals: code.max_locals,
                is_static,
                takes_int,
                int_first,
                method_index: mi,
            });
        }
    }
    stubs
}

struct Emulator<'a> {
    cf: &'a ClassFile,
    heap: Vec<HeapObject>,
    locals: Vec<Value>,
    stack: Vec<Value>,
}

impl Emulator<'_> {
    fn alloc(&mut self, obj: HeapObject) -> Result<usize, RecoveryError> {
        if self.heap.len() >= MAX_HEAP_OBJECTS {
            return Err(RecoveryError::HeapExhausted);
        }
        self.heap.push(obj);
        Ok(self.heap.len() - 1)
    }

    fn pop(&mut self) -> Result<Value, RecoveryError> {
        self.stack.pop().ok_or(RecoveryError::StackUnderflow)
    }

    fn pop_int(&mut self) -> Result<i32, RecoveryError> {
        self.pop()?.as_int()
    }

    fn pop_long(&mut self) -> Result<i64, RecoveryError> {
        self.pop()?.as_long()
    }

    fn pop_ref(&mut self) -> Result<usize, RecoveryError> {
        self.pop()?.as_ref()
    }
}

pub fn emulate_string_decrypt(
    cf: &ClassFile,
    stub: &StringDecryptStub,
    encrypted: &str,
    int_seed: i32,
) -> Result<String, RecoveryError> {
    let insns: Vec<Instruction> =
        bytecode::disassemble(&stub.code).map_err(|_| RecoveryError::BadShape)?;
    let pc_index: Vec<u32> = insns.iter().map(|i| i.pc).collect();
    let input_units: Vec<u16> = encrypted.encode_utf16().collect();

    let mut emu: Emulator<'_> = Emulator {
        cf,
        heap: Vec::with_capacity(8),
        locals: vec![Value::Int(0); usize::from(stub.max_locals).max(4)],
        stack: Vec::with_capacity(16),
    };
    let str_ref: usize = emu.alloc(HeapObject::Text(input_units))?;
    let arg_base: usize = usize::from(!stub.is_static);
    if !stub.is_static {
        emu.locals[0] = Value::Null;
    }
    if stub.takes_int && stub.int_first {
        set_local(&mut emu.locals, arg_base, Value::Int(int_seed));
        set_local(&mut emu.locals, arg_base + 1, Value::Ref(str_ref));
    } else {
        set_local(&mut emu.locals, arg_base, Value::Ref(str_ref));
        if stub.takes_int {
            set_local(&mut emu.locals, arg_base + 1, Value::Int(int_seed));
        }
    }

    let mut ip: usize = 0;
    let mut steps: u64 = 0;
    while ip < insns.len() {
        steps += 1;
        if steps > STEP_LIMIT {
            return Err(RecoveryError::StepLimitExceeded);
        }
        let insn: &Instruction = &insns[ip];
        let op: u8 = insn.opcode;
        match op {
            0x00 => {}
            0x01 => emu.stack.push(Value::Null),
            0x02 => emu.stack.push(Value::Int(-1)),
            0x03..=0x08 => emu.stack.push(Value::Int(i32::from(op) - 3)),
            0x09 | 0x0A => emu.stack.push(Value::Long(i64::from(op) - 9)),
            0x10 | 0x11 => match &insn.operands {
                Operands::Byte(v) | Operands::Short(v) => emu.stack.push(Value::Int(*v)),
                _ => return Err(RecoveryError::BadShape),
            },
            0x12 | 0x13 => {
                let cp: u16 = const_pool_index(insn)?;
                let v: Value = load_constant(&mut emu, cp)?;
                emu.stack.push(v);
            }
            0x14 => {
                let cp: u16 = const_pool_index(insn)?;
                let v: Value = load_long_constant(&emu, cp)?;
                emu.stack.push(v);
            }
            0x15..=0x2D => {
                let idx: usize = load_local_index(insn, op)?;
                let v: Value = *emu.locals.get(idx).ok_or(RecoveryError::BadLocal(idx))?;
                emu.stack.push(v);
            }
            0x36..=0x4E => {
                let idx: usize = store_local_index(insn, op)?;
                let v: Value = emu.pop()?;
                set_local(&mut emu.locals, idx, v);
            }
            0x33..=0x35 => {
                let index: i32 = emu.pop_int()?;
                let arr_ref: usize = emu.pop_ref()?;
                let ch: u16 = read_char_array(&emu.heap, arr_ref, index)?;
                emu.stack.push(Value::Int(i32::from(ch)));
            }
            0x54..=0x56 => {
                let value: i32 = emu.pop_int()?;
                let index: i32 = emu.pop_int()?;
                let arr_ref: usize = emu.pop_ref()?;
                write_char_array(&mut emu.heap, arr_ref, index, (value & 0xFFFF) as u16)?;
            }
            0x57 => {
                emu.pop()?;
            }
            0x59 => {
                let top: Value = *emu.stack.last().ok_or(RecoveryError::StackUnderflow)?;
                emu.stack.push(top);
            }
            0x5A => {
                let len: usize = emu.stack.len();
                if len < 2 {
                    return Err(RecoveryError::StackUnderflow);
                }
                let top: Value = emu.stack[len - 1];
                emu.stack.insert(len - 2, top);
            }
            0x5B => {
                let len: usize = emu.stack.len();
                if len < 3 {
                    return Err(RecoveryError::StackUnderflow);
                }
                let top: Value = emu.stack[len - 1];
                emu.stack.insert(len - 3, top);
            }
            0x5C => {
                let len: usize = emu.stack.len();
                if len < 2 {
                    return Err(RecoveryError::StackUnderflow);
                }
                let a: Value = emu.stack[len - 2];
                let b: Value = emu.stack[len - 1];
                emu.stack.push(a);
                emu.stack.push(b);
            }
            0x5D => {
                let len: usize = emu.stack.len();
                if len < 3 {
                    return Err(RecoveryError::StackUnderflow);
                }
                let a: Value = emu.stack[len - 2];
                let b: Value = emu.stack[len - 1];
                emu.stack.insert(len - 3, b);
                emu.stack.insert(len - 3, a);
            }
            0x5E => {
                let len: usize = emu.stack.len();
                if len < 4 {
                    return Err(RecoveryError::StackUnderflow);
                }
                let a: Value = emu.stack[len - 2];
                let b: Value = emu.stack[len - 1];
                emu.stack.insert(len - 4, b);
                emu.stack.insert(len - 4, a);
            }
            0x5F => {
                let len: usize = emu.stack.len();
                if len < 2 {
                    return Err(RecoveryError::StackUnderflow);
                }
                emu.stack.swap(len - 1, len - 2);
            }
            0x60 => binary(&mut emu.stack, i32::wrapping_add)?,
            0x64 => binary(&mut emu.stack, i32::wrapping_sub)?,
            0x68 => binary(&mut emu.stack, i32::wrapping_mul)?,
            0x6C => binary(
                &mut emu.stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_div(b) },
            )?,
            0x70 => binary(
                &mut emu.stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_rem(b) },
            )?,
            0x74 => {
                let v: i32 = emu.pop_int()?;
                emu.stack.push(Value::Int(v.wrapping_neg()));
            }
            0x78 => binary(&mut emu.stack, |a, b| a.wrapping_shl(b as u32 & 31))?,
            0x7A => binary(&mut emu.stack, |a, b| a.wrapping_shr(b as u32 & 31))?,
            0x7C => binary(&mut emu.stack, |a, b| {
                ((a as u32) >> (b as u32 & 31)) as i32
            })?,
            0x7E => binary(&mut emu.stack, |a, b| a & b)?,
            0x80 => binary(&mut emu.stack, |a, b| a | b)?,
            0x82 => binary(&mut emu.stack, |a, b| a ^ b)?,
            0x61 => long_binary(&mut emu.stack, i64::wrapping_add)?,
            0x65 => long_binary(&mut emu.stack, i64::wrapping_sub)?,
            0x69 => long_binary(&mut emu.stack, i64::wrapping_mul)?,
            0x6D => long_binary(
                &mut emu.stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_div(b) },
            )?,
            0x71 => long_binary(
                &mut emu.stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_rem(b) },
            )?,
            0x7F => long_binary(&mut emu.stack, |a, b| a & b)?,
            0x81 => long_binary(&mut emu.stack, |a, b| a | b)?,
            0x83 => long_binary(&mut emu.stack, |a, b| a ^ b)?,
            0x75 => {
                let v: i64 = emu.pop_long()?;
                emu.stack.push(Value::Long(v.wrapping_neg()));
            }
            0x79 => {
                let shift: i32 = emu.pop_int()?;
                let v: i64 = emu.pop_long()?;
                emu.stack
                    .push(Value::Long(v.wrapping_shl(shift as u32 & 63)));
            }
            0x7B => {
                let shift: i32 = emu.pop_int()?;
                let v: i64 = emu.pop_long()?;
                emu.stack
                    .push(Value::Long(v.wrapping_shr(shift as u32 & 63)));
            }
            0x7D => {
                let shift: i32 = emu.pop_int()?;
                let v: i64 = emu.pop_long()?;
                emu.stack
                    .push(Value::Long(((v as u64) >> (shift as u32 & 63)) as i64));
            }
            0x84 => {
                let Operands::Iinc { index, delta } = &insn.operands else {
                    return Err(RecoveryError::BadShape);
                };
                let idx: usize = usize::from(*index);
                ensure_local(&mut emu.locals, idx);
                let cur: i32 = emu.locals[idx].as_int()?;
                emu.locals[idx] = Value::Int(cur.wrapping_add(*delta));
            }
            0x85 => {
                let v: i32 = emu.pop_int()?;
                emu.stack.push(Value::Long(i64::from(v)));
            }
            0x88 => {
                let v: i64 = emu.pop_long()?;
                emu.stack.push(Value::Int(v as i32));
            }
            0x94 => {
                let b: i64 = emu.pop_long()?;
                let a: i64 = emu.pop_long()?;
                emu.stack.push(Value::Int(a.cmp(&b) as i32));
            }
            0x86..=0x93 => {
                let v: i32 = emu.pop_int()?;
                let masked: i32 = match op {
                    0x91 => i32::from(v as i8),
                    0x92 => i32::from((v & 0xFFFF) as u16),
                    0x93 => i32::from(v as i16),
                    _ => v,
                };
                emu.stack.push(Value::Int(masked));
            }
            0xBE => {
                let arr_ref: usize = emu.pop_ref()?;
                let len: usize = char_array_len(&emu.heap, arr_ref)?;
                emu.stack.push(Value::Int(len as i32));
            }
            0xBC => {
                let len: i32 = emu.pop_int()?;
                let n: usize = usize::try_from(len).map_err(|_| RecoveryError::BadShape)?;
                if n > MAX_STRING_LEN {
                    return Err(RecoveryError::BadShape);
                }
                let r: usize = emu.alloc(HeapObject::Chars(vec![0u16; n]))?;
                emu.stack.push(Value::Ref(r));
            }
            0xBB => {
                let r: usize = emu.alloc(HeapObject::Builder(Vec::new()))?;
                emu.stack.push(Value::Ref(r));
            }
            0xA7 => {
                ip = branch_to(&pc_index, insn)?;
                continue;
            }
            0x99..=0x9E => {
                let v: i32 = emu.pop_int()?;
                if unary_cmp(op, v) {
                    ip = branch_to(&pc_index, insn)?;
                    continue;
                }
            }
            0x9F..=0xA4 => {
                let b: i32 = emu.pop_int()?;
                let a: i32 = emu.pop_int()?;
                if binary_cmp(op, a, b) {
                    ip = branch_to(&pc_index, insn)?;
                    continue;
                }
            }
            0xC6 | 0xC7 => {
                let v: Value = emu.pop()?;
                let is_null: bool = matches!(v, Value::Null);
                if (op == 0xC6 && is_null) || (op == 0xC7 && !is_null) {
                    ip = branch_to(&pc_index, insn)?;
                    continue;
                }
            }
            0xAA | 0xAB => {
                let key: i32 = emu.pop_int()?;
                let target_pc: u32 = switch_target(insn, key)?;
                ip = resolve_pc(&pc_index, target_pc)?;
                continue;
            }
            0xB6..=0xB9 => {
                let cp: u16 = const_pool_index(insn)?;
                let returned: Option<Value> = invoke(&mut emu, cp, op)?;
                if let Some(ret) = returned {
                    emu.stack.push(ret);
                }
            }
            0xB0 => {
                let r: usize = emu.pop_ref()?;
                return finish(&emu.heap, r);
            }
            0xC0 => {}
            other => return Err(RecoveryError::UnsupportedOpcode(other)),
        }
        ip += 1;
    }
    Err(RecoveryError::NoReturn)
}

fn invoke(emu: &mut Emulator<'_>, cp: u16, op: u8) -> Result<Option<Value>, RecoveryError> {
    let Some(sig): Option<String> = bytecode::resolve_ref(emu.cf, cp) else {
        return Err(RecoveryError::BadShape);
    };
    let (owner_name, rest): (&str, &str) = sig.split_once('.').ok_or(RecoveryError::BadShape)?;
    let (name, desc): (&str, &str) = rest.split_once(':').ok_or(RecoveryError::BadShape)?;
    match (owner_name, name, desc) {
        ("java/lang/String", "charAt", "(I)C") => {
            let index: i32 = emu.pop_int()?;
            let r: usize = emu.pop_ref()?;
            let ch: u16 = read_text_char(&emu.heap, r, index)?;
            Ok(Some(Value::Int(i32::from(ch))))
        }
        ("java/lang/String", "length", "()I") => {
            let r: usize = emu.pop_ref()?;
            let len: usize = text_len(&emu.heap, r)?;
            Ok(Some(Value::Int(len as i32)))
        }
        ("java/lang/String", "toCharArray", "()[C") => {
            let r: usize = emu.pop_ref()?;
            let units: Vec<u16> = text_units(&emu.heap, r)?;
            let new_ref: usize = emu.alloc(HeapObject::Chars(units))?;
            Ok(Some(Value::Ref(new_ref)))
        }
        ("java/lang/String", "<init>", "([C)V" | "([CII)V") => {
            if desc == "([CII)V" {
                let count: i32 = emu.pop_int()?;
                let offset: i32 = emu.pop_int()?;
                let arr_ref: usize = emu.pop_ref()?;
                let target: usize = emu.pop_ref()?;
                let units: Vec<u16> = slice_chars(&emu.heap, arr_ref, offset, count)?;
                set_text(&mut emu.heap, target, units)?;
            } else {
                let arr_ref: usize = emu.pop_ref()?;
                let target: usize = emu.pop_ref()?;
                let units: Vec<u16> = chars_units(&emu.heap, arr_ref)?;
                set_text(&mut emu.heap, target, units)?;
            }
            Ok(None)
        }
        ("java/lang/String", "intern", "()Ljava/lang/String;") => {
            let r: usize = emu.pop_ref()?;
            Ok(Some(Value::Ref(r)))
        }
        ("java/lang/StringBuilder", "<init>", "()V") => {
            let _r: usize = emu.pop_ref()?;
            Ok(None)
        }
        ("java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;") => {
            let ch: i32 = emu.pop_int()?;
            let r: usize = emu.pop_ref()?;
            builder_push(&mut emu.heap, r, (ch & 0xFFFF) as u16)?;
            Ok(Some(Value::Ref(r)))
        }
        ("java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;") => {
            let arg: usize = emu.pop_ref()?;
            let r: usize = emu.pop_ref()?;
            let units: Vec<u16> = text_units(&emu.heap, arg)?;
            builder_extend(&mut emu.heap, r, &units)?;
            Ok(Some(Value::Ref(r)))
        }
        ("java/lang/StringBuilder", "toString", "()Ljava/lang/String;") => {
            let r: usize = emu.pop_ref()?;
            let units: Vec<u16> = builder_units(&emu.heap, r)?;
            let new_ref: usize = emu.alloc(HeapObject::Text(units))?;
            Ok(Some(Value::Ref(new_ref)))
        }
        ("java/lang/String", "valueOf", "([C)Ljava/lang/String;") => {
            let arr_ref: usize = emu.pop_ref()?;
            let units: Vec<u16> = chars_units(&emu.heap, arr_ref)?;
            let new_ref: usize = emu.alloc(HeapObject::Text(units))?;
            Ok(Some(Value::Ref(new_ref)))
        }
        _ => {
            let _ = op;
            Err(RecoveryError::UnknownCall(sig))
        }
    }
}

const fn const_pool_index(insn: &Instruction) -> Result<u16, RecoveryError> {
    match &insn.operands {
        Operands::ConstPool(i) | Operands::InvokeInterface { index: i, .. } => Ok(*i),
        Operands::InvokeDynamic(i) => Ok(*i),
        _ => Err(RecoveryError::BadShape),
    }
}

fn load_constant(emu: &mut Emulator<'_>, cp: u16) -> Result<Value, RecoveryError> {
    let idx: usize = usize::from(cp);
    if idx == 0 || idx >= emu.cf.constant_pool.len() {
        return Err(RecoveryError::BadShape);
    }
    match &emu.cf.constant_pool[idx] {
        ConstantPoolEntry::Integer(v) => Ok(Value::Int(*v)),
        ConstantPoolEntry::String { utf8_index } => {
            let s: &str = emu
                .cf
                .utf8_at(*utf8_index)
                .map_err(|_| RecoveryError::BadShape)?;
            let units: Vec<u16> = s.encode_utf16().collect();
            let r: usize = emu.alloc(HeapObject::Text(units))?;
            Ok(Value::Ref(r))
        }
        _ => Err(RecoveryError::BadShape),
    }
}

fn load_long_constant(emu: &Emulator<'_>, cp: u16) -> Result<Value, RecoveryError> {
    let idx: usize = usize::from(cp);
    if idx == 0 || idx >= emu.cf.constant_pool.len() {
        return Err(RecoveryError::BadShape);
    }
    match &emu.cf.constant_pool[idx] {
        ConstantPoolEntry::Long(v) => Ok(Value::Long(*v)),
        _ => Err(RecoveryError::BadShape),
    }
}

fn load_local_index(insn: &Instruction, op: u8) -> Result<usize, RecoveryError> {
    match op {
        0x15..=0x19 => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(RecoveryError::BadShape),
        },
        0x1A..=0x1D => Ok(usize::from(op - 0x1A)),
        0x1E..=0x21 => Ok(usize::from(op - 0x1E)),
        0x22..=0x25 => Ok(usize::from(op - 0x22)),
        0x26..=0x29 => Ok(usize::from(op - 0x26)),
        0x2A..=0x2D => Ok(usize::from(op - 0x2A)),
        _ => Err(RecoveryError::BadShape),
    }
}

fn store_local_index(insn: &Instruction, op: u8) -> Result<usize, RecoveryError> {
    match op {
        0x36..=0x3A => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(RecoveryError::BadShape),
        },
        0x3B..=0x3E => Ok(usize::from(op - 0x3B)),
        0x3F..=0x42 => Ok(usize::from(op - 0x3F)),
        0x43..=0x46 => Ok(usize::from(op - 0x43)),
        0x47..=0x4A => Ok(usize::from(op - 0x47)),
        0x4B..=0x4E => Ok(usize::from(op - 0x4B)),
        _ => Err(RecoveryError::BadShape),
    }
}

fn ensure_local(locals: &mut Vec<Value>, idx: usize) {
    if idx >= locals.len() {
        locals.resize(idx + 1, Value::Int(0));
    }
}

fn set_local(locals: &mut Vec<Value>, idx: usize, v: Value) {
    ensure_local(locals, idx);
    locals[idx] = v;
}

fn binary<F: Fn(i32, i32) -> i32>(stack: &mut Vec<Value>, f: F) -> Result<(), RecoveryError> {
    let b: i32 = stack.pop().ok_or(RecoveryError::StackUnderflow)?.as_int()?;
    let a: i32 = stack.pop().ok_or(RecoveryError::StackUnderflow)?.as_int()?;
    stack.push(Value::Int(f(a, b)));
    Ok(())
}

fn long_binary<F: Fn(i64, i64) -> i64>(stack: &mut Vec<Value>, f: F) -> Result<(), RecoveryError> {
    let b: i64 = stack
        .pop()
        .ok_or(RecoveryError::StackUnderflow)?
        .as_long()?;
    let a: i64 = stack
        .pop()
        .ok_or(RecoveryError::StackUnderflow)?
        .as_long()?;
    stack.push(Value::Long(f(a, b)));
    Ok(())
}

const fn unary_cmp(op: u8, v: i32) -> bool {
    match op {
        0x99 => v == 0,
        0x9A => v != 0,
        0x9B => v < 0,
        0x9C => v >= 0,
        0x9D => v > 0,
        0x9E => v <= 0,
        _ => false,
    }
}

const fn binary_cmp(op: u8, a: i32, b: i32) -> bool {
    match op {
        0x9F => a == b,
        0xA0 => a != b,
        0xA1 => a < b,
        0xA2 => a >= b,
        0xA3 => a > b,
        0xA4 => a <= b,
        _ => false,
    }
}

fn branch_to(pc_index: &[u32], insn: &Instruction) -> Result<usize, RecoveryError> {
    let target: u32 = bytecode::branch_target(insn).ok_or(RecoveryError::BadShape)?;
    resolve_pc(pc_index, target)
}

fn resolve_pc(pc_index: &[u32], target: u32) -> Result<usize, RecoveryError> {
    pc_index
        .iter()
        .position(|&pc| pc == target)
        .ok_or(RecoveryError::BadShape)
}

fn switch_target(insn: &Instruction, key: i32) -> Result<u32, RecoveryError> {
    let base: i64 = i64::from(insn.pc);
    let offset: i32 = match &insn.operands {
        Operands::TableSwitch {
            default,
            low,
            high,
            offsets,
        } => {
            if key < *low || key > *high {
                *default
            } else {
                let idx: usize =
                    usize::try_from(key - *low).map_err(|_| RecoveryError::BadShape)?;
                *offsets.get(idx).ok_or(RecoveryError::BadShape)?
            }
        }
        Operands::LookupSwitch { default, pairs } => pairs
            .iter()
            .find_map(|(m, off): &(i32, i32)| if *m == key { Some(*off) } else { None })
            .unwrap_or(*default),
        _ => return Err(RecoveryError::BadShape),
    };
    u32::try_from(base + i64::from(offset)).map_err(|_| RecoveryError::BadShape)
}

fn read_char_array(heap: &[HeapObject], r: usize, index: i32) -> Result<u16, RecoveryError> {
    let i: usize = usize::try_from(index).map_err(|_| RecoveryError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => v.get(i).copied().ok_or(RecoveryError::BadShape),
        _ => Err(RecoveryError::BadShape),
    }
}

fn write_char_array(
    heap: &mut [HeapObject],
    r: usize,
    index: i32,
    value: u16,
) -> Result<(), RecoveryError> {
    let i: usize = usize::try_from(index).map_err(|_| RecoveryError::BadShape)?;
    match heap.get_mut(r) {
        Some(HeapObject::Chars(v)) if i < v.len() => {
            v[i] = value;
            Ok(())
        }
        _ => Err(RecoveryError::BadShape),
    }
}

fn char_array_len(heap: &[HeapObject], r: usize) -> Result<usize, RecoveryError> {
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => Ok(v.len()),
        _ => Err(RecoveryError::BadShape),
    }
}

fn read_text_char(heap: &[HeapObject], r: usize, index: i32) -> Result<u16, RecoveryError> {
    let i: usize = usize::try_from(index).map_err(|_| RecoveryError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Text(v)) => v.get(i).copied().ok_or(RecoveryError::BadShape),
        _ => Err(RecoveryError::BadShape),
    }
}

fn text_len(heap: &[HeapObject], r: usize) -> Result<usize, RecoveryError> {
    match heap.get(r) {
        Some(HeapObject::Text(v)) => Ok(v.len()),
        _ => Err(RecoveryError::BadShape),
    }
}

fn text_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, RecoveryError> {
    match heap.get(r) {
        Some(HeapObject::Text(v)) => Ok(v.clone()),
        _ => Err(RecoveryError::BadShape),
    }
}

fn chars_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, RecoveryError> {
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => Ok(v.clone()),
        _ => Err(RecoveryError::BadShape),
    }
}

fn slice_chars(
    heap: &[HeapObject],
    r: usize,
    offset: i32,
    count: i32,
) -> Result<Vec<u16>, RecoveryError> {
    let o: usize = usize::try_from(offset).map_err(|_| RecoveryError::BadShape)?;
    let c: usize = usize::try_from(count).map_err(|_| RecoveryError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => {
            let end: usize = o.checked_add(c).ok_or(RecoveryError::BadShape)?;
            v.get(o..end)
                .map(<[u16]>::to_vec)
                .ok_or(RecoveryError::BadShape)
        }
        _ => Err(RecoveryError::BadShape),
    }
}

fn set_text(heap: &mut [HeapObject], r: usize, units: Vec<u16>) -> Result<(), RecoveryError> {
    match heap.get_mut(r) {
        Some(slot) => {
            *slot = HeapObject::Text(units);
            Ok(())
        }
        None => Err(RecoveryError::BadShape),
    }
}

fn builder_push(heap: &mut [HeapObject], r: usize, ch: u16) -> Result<(), RecoveryError> {
    match heap.get_mut(r) {
        Some(HeapObject::Builder(v)) => {
            if v.len() >= MAX_STRING_LEN {
                return Err(RecoveryError::BadShape);
            }
            v.push(ch);
            Ok(())
        }
        _ => Err(RecoveryError::BadShape),
    }
}

fn builder_extend(heap: &mut [HeapObject], r: usize, units: &[u16]) -> Result<(), RecoveryError> {
    match heap.get_mut(r) {
        Some(HeapObject::Builder(v)) => {
            if v.len() + units.len() > MAX_STRING_LEN {
                return Err(RecoveryError::BadShape);
            }
            v.extend_from_slice(units);
            Ok(())
        }
        _ => Err(RecoveryError::BadShape),
    }
}

fn builder_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, RecoveryError> {
    match heap.get(r) {
        Some(HeapObject::Builder(v)) => Ok(v.clone()),
        _ => Err(RecoveryError::BadShape),
    }
}

fn finish(heap: &[HeapObject], r: usize) -> Result<String, RecoveryError> {
    let units: Vec<u16> = match heap.get(r) {
        Some(HeapObject::Text(v) | HeapObject::Chars(v) | HeapObject::Builder(v)) => v.clone(),
        None => return Err(RecoveryError::BadShape),
    };
    Ok(String::from_utf16_lossy(&units))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRecoveryReport {
    pub recovered: BTreeMap<u16, String>,
    pub attempted: usize,
    pub decrypt_methods: usize,
    pub runtime_key_wall: bool,
}

#[must_use]
pub fn recover_strings(cf: &ClassFile) -> StringRecoveryReport {
    let mut report: StringRecoveryReport = StringRecoveryReport::default();
    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(cf);
    report.decrypt_methods = stubs.len();
    if stubs.is_empty() {
        return report;
    }
    let mut self_calls: bool = false;
    for stub in &stubs {
        if let Ok(insns) = bytecode::disassemble(&stub.code)
            && references_runtime_key(cf, &insns)
        {
            self_calls = true;
        }
    }
    report.runtime_key_wall = self_calls;

    let candidates: Vec<LiteralCandidate> = encrypted_literal_candidates(cf, &stubs);
    for candidate in candidates {
        report.attempted += 1;
        for stub in &stubs {
            let int_arg: i32 = if stub.takes_int {
                candidate
                    .seed
                    .unwrap_or_else(|| i32::from(candidate.utf8_idx))
            } else {
                0
            };
            if let Ok(plain) = emulate_string_decrypt(cf, stub, &candidate.literal, int_arg)
                && is_plausible_plaintext(&plain)
            {
                report.recovered.insert(candidate.utf8_idx, plain);
                break;
            }
        }
    }
    report
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiteralCandidate {
    utf8_idx: u16,
    literal: String,
    seed: Option<i32>,
}

fn references_runtime_key(cf: &ClassFile, insns: &[Instruction]) -> bool {
    let mut random_draw_seen: bool = false;
    let mut deterministic_random_seed_seen: bool = false;
    for insn in insns {
        if !matches!(insn.opcode, 0xB6..=0xB9) {
            continue;
        }
        let (Operands::ConstPool(cp) | Operands::InvokeInterface { index: cp, .. }) = insn.operands
        else {
            continue;
        };
        let Some(sig): Option<String> = bytecode::resolve_ref(cf, cp) else {
            continue;
        };
        if is_non_random_runtime_key_signature(&sig) {
            return true;
        }
        match random_signature(&sig) {
            RandomSignature::None => {}
            RandomSignature::UnseededCtor => {}
            RandomSignature::DeterministicSeed => deterministic_random_seed_seen = true,
            RandomSignature::DeterministicDraw => random_draw_seen = true,
            RandomSignature::Runtime => return true,
        }
    }
    random_draw_seen && !deterministic_random_seed_seen
}

fn is_non_random_runtime_key_signature(sig: &str) -> bool {
    sig.contains("getProperty")
        || sig.contains("currentTimeMillis")
        || sig.contains("nanoTime")
        || sig.contains("getRuntime")
        || sig.contains("getenv")
        || sig.contains("java/security/SecureRandom")
        || sig.contains("getStackTrace")
        || sig.contains("StackTraceElement")
        || sig.contains("Thread") && sig.contains("currentThread")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RandomSignature {
    None,
    UnseededCtor,
    DeterministicSeed,
    DeterministicDraw,
    Runtime,
}

fn random_signature(sig: &str) -> RandomSignature {
    let Some((owner, rest)): Option<(&str, &str)> = sig.split_once('.') else {
        return RandomSignature::None;
    };
    if owner != "java/util/Random" {
        return RandomSignature::None;
    }
    let Some((name, desc)): Option<(&str, &str)> = rest.split_once(':') else {
        return RandomSignature::Runtime;
    };
    match (name, desc) {
        ("<init>", "()V") => RandomSignature::UnseededCtor,
        ("<init>" | "setSeed", "(J)V") => RandomSignature::DeterministicSeed,
        ("nextInt", "()I" | "(I)I") => RandomSignature::DeterministicDraw,
        _ => RandomSignature::Runtime,
    }
}

fn encrypted_literal_candidates(
    cf: &ClassFile,
    stubs: &[StringDecryptStub],
) -> Vec<LiteralCandidate> {
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let string_const_to_utf8: BTreeMap<u16, u16> = string_pool_entries(cf);
    let decrypt_signatures: Vec<String> = decrypt_method_signatures(cf, stubs);

    let mut seen: BTreeSet<u16> = BTreeSet::new();
    let mut out: Vec<LiteralCandidate> = Vec::new();

    for site in call_site_literals(cf, &decrypt_signatures, &string_const_to_utf8) {
        if seen.insert(site.utf8_idx)
            && let Some(value) = strings.get(&site.utf8_idx)
            && !value.is_empty()
        {
            out.push(LiteralCandidate {
                utf8_idx: site.utf8_idx,
                literal: value.clone(),
                seed: site.seed,
            });
        }
    }

    for (cp_idx, utf8_idx) in &string_const_to_utf8 {
        let _ = cp_idx;
        if seen.contains(utf8_idx) {
            continue;
        }
        let Some(value): Option<&String> = strings.get(utf8_idx) else {
            continue;
        };
        if value.is_empty() || !looks_encrypted(value) {
            continue;
        }
        seen.insert(*utf8_idx);
        out.push(LiteralCandidate {
            utf8_idx: *utf8_idx,
            literal: value.clone(),
            seed: None,
        });
    }
    out
}

fn decrypt_method_signatures(cf: &ClassFile, stubs: &[StringDecryptStub]) -> Vec<String> {
    let mut sigs: Vec<String> = Vec::new();
    for stub in stubs {
        let Some(method): Option<&crate::classfile::MethodInfo> = cf.methods.get(stub.method_index)
        else {
            continue;
        };
        let (Ok(name), Ok(desc)): (
            Result<&str, crate::error::Error>,
            Result<&str, crate::error::Error>,
        ) = (
            cf.utf8_at(method.name_index),
            cf.utf8_at(method.descriptor_index),
        ) else {
            continue;
        };
        sigs.push(format!("{name}:{desc}"));
    }
    sigs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallSite {
    utf8_idx: u16,
    seed: Option<i32>,
}

fn call_site_literals(
    cf: &ClassFile,
    decrypt_signatures: &[String],
    string_const_to_utf8: &BTreeMap<u16, u16>,
) -> Vec<CallSite> {
    let mut out: Vec<CallSite> = Vec::new();
    for method in &cf.methods {
        for attr in &method.attributes {
            let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
                continue;
            };
            if name != "Code" {
                continue;
            }
            let Ok(parsed): Result<bytecode::CodeAttribute, crate::error::Error> =
                bytecode::parse_code_attribute(&attr.info)
            else {
                continue;
            };
            let Ok(insns): Result<Vec<Instruction>, crate::error::Error> =
                bytecode::disassemble(&parsed.code)
            else {
                continue;
            };
            scan_call_sites(
                cf,
                &insns,
                decrypt_signatures,
                string_const_to_utf8,
                &mut out,
            );
        }
    }
    out
}

fn scan_call_sites(
    cf: &ClassFile,
    insns: &[Instruction],
    decrypt_signatures: &[String],
    string_const_to_utf8: &BTreeMap<u16, u16>,
    out: &mut Vec<CallSite>,
) {
    let mut pending_literal: Option<u16> = None;
    let mut pending_seed: Option<i32> = None;
    for insn in insns {
        match insn.opcode {
            0x12 | 0x13 => match insn.operands {
                Operands::ConstPool(cp) => {
                    if let Some(utf8_idx) = string_const_to_utf8.get(&cp).copied() {
                        pending_literal = Some(utf8_idx);
                    } else if let Some(value) = ldc_int_value(cf, cp) {
                        pending_seed = Some(value);
                    } else {
                        pending_literal = None;
                        pending_seed = None;
                    }
                }
                _ => {
                    pending_literal = None;
                    pending_seed = None;
                }
            },
            0x02..=0x08 | 0x10 | 0x11 => {
                if let Some(value) = inline_int_value(insn) {
                    pending_seed = Some(value);
                }
            }
            0xB6 | 0xB8 | 0xB9 => {
                if let Some(utf8_idx) = pending_literal
                    && let Operands::ConstPool(cp) | Operands::InvokeInterface { index: cp, .. } =
                        insn.operands
                    && let Some(sig) = bytecode::resolve_ref(cf, cp)
                    && let Some((_, rest)) = sig.split_once('.')
                    && decrypt_signatures.iter().any(|s| s == rest)
                {
                    out.push(CallSite {
                        utf8_idx,
                        seed: pending_seed,
                    });
                }
                pending_literal = None;
                pending_seed = None;
            }
            _ => {
                pending_literal = None;
                pending_seed = None;
            }
        }
    }
}

fn inline_int_value(insn: &Instruction) -> Option<i32> {
    match insn.opcode {
        0x02..=0x08 => Some(i32::from(insn.opcode) - 3),
        0x10 | 0x11 => match insn.operands {
            Operands::Byte(v) | Operands::Short(v) => Some(v),
            _ => None,
        },
        _ => None,
    }
}

fn ldc_int_value(cf: &ClassFile, cp: u16) -> Option<i32> {
    match cf.constant_pool.get(usize::from(cp)) {
        Some(ConstantPoolEntry::Integer(v)) => Some(*v),
        _ => None,
    }
}

fn string_pool_entries(cf: &ClassFile) -> BTreeMap<u16, u16> {
    let mut map: BTreeMap<u16, u16> = BTreeMap::new();
    for (i, entry) in cf.constant_pool.iter().enumerate() {
        if let ConstantPoolEntry::String { utf8_index } = entry
            && let Ok(cp_idx) = u16::try_from(i)
        {
            map.insert(cp_idx, *utf8_index);
        }
    }
    map
}

fn looks_encrypted(s: &str) -> bool {
    let count: usize = s.chars().count();
    if count < 1 {
        return false;
    }
    let non_printable: usize = s
        .chars()
        .filter(|c| !c.is_ascii_graphic() && !c.is_whitespace())
        .count();
    let ratio: f64 = non_printable as f64 / count as f64;
    ratio > 0.30
}

fn is_plausible_plaintext(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace() || (*c as u32) >= 0xA0)
        .count();
    let total: usize = s.chars().count();
    printable * 100 >= total * 85
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
