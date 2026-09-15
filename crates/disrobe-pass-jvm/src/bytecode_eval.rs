use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytecode::{self, Instruction, Operands};
use crate::classfile::{ClassFile, ConstantPoolEntry, MethodInfo};

const STEP_LIMIT: u64 = 6_000_000;
const MAX_HEAP_OBJECTS: usize = 16_384;
const MAX_STRING_LEN: usize = 65_536;
const MAX_CALL_DEPTH: u32 = 24;
const MAX_STACK_DEPTH: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    UnsupportedOpcode(u8),
    StackUnderflow,
    StackOverflow,
    BadLocal(usize),
    StepLimitExceeded,
    CallDepthExceeded,
    NoReturn,
    BadShape,
    UnknownCall(String),
    UnresolvedSelfCall(String),
    HeapExhausted,
    NullDeref,
    RuntimeKeyUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeapObject {
    Chars(Vec<u16>),
    Ints(Vec<i32>),
    Bytes(Vec<i8>),
    Text(Vec<u16>),
    Builder(Vec<u16>),
    Random(Option<JavaRandomState>),
    Frame {
        class_name: String,
        method_name: String,
    },
    FrameArray(Vec<usize>),
    ClassObj {
        internal_name: String,
    },
    Instance {
        class_name: String,
        fields: BTreeMap<String, Value>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JavaRandomState {
    seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(i32),
    Long(i64),
    Ref(usize),
    Null,
}

impl Value {
    const fn as_int(self) -> Result<i32, EvalError> {
        match self {
            Self::Int(v) => Ok(v),
            _ => Err(EvalError::BadShape),
        }
    }

    const fn as_long(self) -> Result<i64, EvalError> {
        match self {
            Self::Long(v) => Ok(v),
            _ => Err(EvalError::BadShape),
        }
    }

    const fn as_ref(self) -> Result<usize, EvalError> {
        match self {
            Self::Ref(r) => Ok(r),
            Self::Null => Err(EvalError::NullDeref),
            _ => Err(EvalError::BadShape),
        }
    }
}

enum JdkOutcome {
    Handled(Option<Value>),
    NotHandled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    pub internal_class_name: String,
    pub method_name: String,
}

impl CallerContext {
    #[inline]
    #[must_use]
    pub const fn new(internal_class_name: String, method_name: String) -> Self {
        Self {
            internal_class_name,
            method_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptMethod {
    pub method_index: usize,
    pub takes_int: bool,
    is_static: bool,
}

#[must_use]
pub fn find_decrypt_methods(cf: &ClassFile) -> Vec<DecryptMethod> {
    let mut out: Vec<DecryptMethod> = Vec::new();
    for (mi, method) in cf.methods.iter().enumerate() {
        let Ok(desc): Result<&str, crate::error::Error> = cf.utf8_at(method.descriptor_index)
        else {
            continue;
        };
        let takes_int: bool = match desc {
            "(Ljava/lang/String;)Ljava/lang/String;" | "(Ljava/lang/Object;)Ljava/lang/String;" => {
                false
            }
            "(Ljava/lang/String;I)Ljava/lang/String;"
            | "(ILjava/lang/String;)Ljava/lang/String;"
            | "(Ljava/lang/Object;I)Ljava/lang/String;" => true,
            _ => continue,
        };
        if method_code(cf, method).is_none() {
            continue;
        }
        out.push(DecryptMethod {
            method_index: mi,
            takes_int,
            is_static: method.access_flags & 0x0008 != 0,
        });
    }
    out
}

fn method_code(cf: &ClassFile, method: &MethodInfo) -> Option<bytecode::CodeAttribute> {
    for attr in &method.attributes {
        let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        if name == "Code"
            && let Ok(code) = bytecode::parse_code_attribute(&attr.info)
        {
            return Some(code);
        }
    }
    None
}

struct Evaluator<'a> {
    cf: &'a ClassFile,
    heap: Vec<HeapObject>,
    statics: BTreeMap<String, Value>,
    clinit_done: bool,
    caller: &'a CallerContext,
    depth: u32,
    steps: u64,
}

impl Evaluator<'_> {
    fn alloc(&mut self, obj: HeapObject) -> Result<usize, EvalError> {
        if self.heap.len() >= MAX_HEAP_OBJECTS {
            return Err(EvalError::HeapExhausted);
        }
        self.heap.push(obj);
        Ok(self.heap.len() - 1)
    }

    fn run_method(
        &mut self,
        method_index: usize,
        args: Vec<Value>,
    ) -> Result<Option<Value>, EvalError> {
        if self.depth >= MAX_CALL_DEPTH {
            return Err(EvalError::CallDepthExceeded);
        }
        let method: &MethodInfo = self
            .cf
            .methods
            .get(method_index)
            .ok_or(EvalError::BadShape)?;
        let code: bytecode::CodeAttribute =
            method_code(self.cf, method).ok_or(EvalError::BadShape)?;
        let insns: Vec<Instruction> =
            bytecode::disassemble(&code.code).map_err(|_| EvalError::BadShape)?;
        let pc_index: Vec<u32> = insns.iter().map(|i: &Instruction| i.pc).collect();

        let mut locals: Vec<Value> =
            vec![Value::Int(0); usize::from(code.max_locals).max(args.len())];
        for (i, v) in args.into_iter().enumerate() {
            if i < locals.len() {
                locals[i] = v;
            }
        }
        let mut stack: Vec<Value> = Vec::with_capacity(usize::from(code.max_stack).min(64));

        self.depth += 1;
        let result: Result<Option<Value>, EvalError> =
            self.interpret(&insns, &pc_index, &mut locals, &mut stack);
        self.depth -= 1;
        result
    }

    fn interpret(
        &mut self,
        insns: &[Instruction],
        pc_index: &[u32],
        locals: &mut Vec<Value>,
        stack: &mut Vec<Value>,
    ) -> Result<Option<Value>, EvalError> {
        let mut ip: usize = 0;
        while ip < insns.len() {
            self.steps += 1;
            if self.steps > STEP_LIMIT {
                return Err(EvalError::StepLimitExceeded);
            }
            if stack.len() > MAX_STACK_DEPTH {
                return Err(EvalError::StackOverflow);
            }
            let insn: &Instruction = &insns[ip];
            let op: u8 = insn.opcode;
            match op {
                0x00 | 0xC0 => {}
                0x01 => stack.push(Value::Null),
                0x02 => stack.push(Value::Int(-1)),
                0x03..=0x08 => stack.push(Value::Int(i32::from(op) - 3)),
                0x09 | 0x0A => stack.push(Value::Long(i64::from(op) - 9)),
                0x10 | 0x11 => match &insn.operands {
                    Operands::Byte(v) | Operands::Short(v) => stack.push(Value::Int(*v)),
                    _ => return Err(EvalError::BadShape),
                },
                0x12 | 0x13 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let v: Value = self.load_constant(cp)?;
                    stack.push(v);
                }
                0x14 => {
                    let cp: u16 = const_pool_index(insn)?;
                    stack.push(self.load_long_constant(cp)?);
                }
                0x15..=0x2D => {
                    let idx: usize = load_local_index(insn, op)?;
                    let v: Value = *locals.get(idx).ok_or(EvalError::BadLocal(idx))?;
                    stack.push(v);
                }
                0x36..=0x4E => {
                    let idx: usize = store_local_index(insn, op)?;
                    let v: Value = pop(stack)?;
                    set_local(locals, idx, v);
                }
                0x32 => {
                    let index: i32 = pop_int(stack)?;
                    let arr_ref: usize = pop_ref(stack)?;
                    let elem: usize = self.read_frame_array(arr_ref, index)?;
                    stack.push(Value::Ref(elem));
                }
                0x33..=0x35 => {
                    let index: i32 = pop_int(stack)?;
                    let arr_ref: usize = pop_ref(stack)?;
                    stack.push(Value::Int(read_byte_or_char_array(
                        &self.heap, arr_ref, index,
                    )?));
                }
                0x2E => {
                    let index: i32 = pop_int(stack)?;
                    let arr_ref: usize = pop_ref(stack)?;
                    stack.push(Value::Int(read_int_array(&self.heap, arr_ref, index)?));
                }
                0x4F => {
                    let value: i32 = pop_int(stack)?;
                    let index: i32 = pop_int(stack)?;
                    let arr_ref: usize = pop_ref(stack)?;
                    write_int_array(&mut self.heap, arr_ref, index, value)?;
                }
                0x54..=0x56 => {
                    let value: i32 = pop_int(stack)?;
                    let index: i32 = pop_int(stack)?;
                    let arr_ref: usize = pop_ref(stack)?;
                    write_byte_or_char_array(&mut self.heap, arr_ref, index, value)?;
                }
                0x57 => {
                    pop(stack)?;
                }
                0x58 => {
                    pop(stack)?;
                    pop(stack)?;
                }
                0x59 => {
                    let top: Value = *stack.last().ok_or(EvalError::StackUnderflow)?;
                    stack.push(top);
                }
                0x5A => {
                    let len: usize = stack.len();
                    if len < 2 {
                        return Err(EvalError::StackUnderflow);
                    }
                    let top: Value = stack[len - 1];
                    stack.insert(len - 2, top);
                }
                0x5B => {
                    let len: usize = stack.len();
                    if len < 3 {
                        return Err(EvalError::StackUnderflow);
                    }
                    let top: Value = stack[len - 1];
                    stack.insert(len - 3, top);
                }
                0x5C => {
                    let len: usize = stack.len();
                    if len < 2 {
                        return Err(EvalError::StackUnderflow);
                    }
                    let a: Value = stack[len - 2];
                    let b: Value = stack[len - 1];
                    stack.push(a);
                    stack.push(b);
                }
                0x5D => {
                    let len: usize = stack.len();
                    if len < 3 {
                        return Err(EvalError::StackUnderflow);
                    }
                    let a: Value = stack[len - 2];
                    let b: Value = stack[len - 1];
                    stack.insert(len - 3, b);
                    stack.insert(len - 3, a);
                }
                0x5E => {
                    let len: usize = stack.len();
                    if len < 4 {
                        return Err(EvalError::StackUnderflow);
                    }
                    let a: Value = stack[len - 2];
                    let b: Value = stack[len - 1];
                    stack.insert(len - 4, b);
                    stack.insert(len - 4, a);
                }
                0x5F => {
                    let len: usize = stack.len();
                    if len < 2 {
                        return Err(EvalError::StackUnderflow);
                    }
                    stack.swap(len - 1, len - 2);
                }
                0x60 => binary(stack, i32::wrapping_add)?,
                0x64 => binary(stack, i32::wrapping_sub)?,
                0x68 => binary(stack, i32::wrapping_mul)?,
                0x6C => binary(stack, |a, b| if b == 0 { 0 } else { a.wrapping_div(b) })?,
                0x70 => binary(stack, |a, b| if b == 0 { 0 } else { a.wrapping_rem(b) })?,
                0x74 => {
                    let v: i32 = pop_int(stack)?;
                    stack.push(Value::Int(v.wrapping_neg()));
                }
                0x78 => binary(stack, |a, b| a.wrapping_shl(b as u32 & 31))?,
                0x7A => binary(stack, |a, b| a.wrapping_shr(b as u32 & 31))?,
                0x7C => binary(stack, |a, b| ((a as u32) >> (b as u32 & 31)) as i32)?,
                0x7E => binary(stack, |a, b| a & b)?,
                0x80 => binary(stack, |a, b| a | b)?,
                0x82 => binary(stack, |a, b| a ^ b)?,
                0x61 => long_binary(stack, i64::wrapping_add)?,
                0x65 => long_binary(stack, i64::wrapping_sub)?,
                0x69 => long_binary(stack, i64::wrapping_mul)?,
                0x6D => long_binary(stack, |a, b| if b == 0 { 0 } else { a.wrapping_div(b) })?,
                0x71 => long_binary(stack, |a, b| if b == 0 { 0 } else { a.wrapping_rem(b) })?,
                0x7F => long_binary(stack, |a, b| a & b)?,
                0x81 => long_binary(stack, |a, b| a | b)?,
                0x83 => long_binary(stack, |a, b| a ^ b)?,
                0x79 => {
                    let shift: i32 = pop_int(stack)?;
                    let v: i64 = pop_long(stack)?;
                    stack.push(Value::Long(v.wrapping_shl(shift as u32 & 63)));
                }
                0x7B => {
                    let shift: i32 = pop_int(stack)?;
                    let v: i64 = pop_long(stack)?;
                    stack.push(Value::Long(v.wrapping_shr(shift as u32 & 63)));
                }
                0x7D => {
                    let shift: i32 = pop_int(stack)?;
                    let v: i64 = pop_long(stack)?;
                    stack.push(Value::Long(((v as u64) >> (shift as u32 & 63)) as i64));
                }
                0x84 => {
                    let Operands::Iinc { index, delta } = &insn.operands else {
                        return Err(EvalError::BadShape);
                    };
                    let idx: usize = usize::from(*index);
                    ensure_local(locals, idx);
                    let cur: i32 = locals[idx].as_int()?;
                    locals[idx] = Value::Int(cur.wrapping_add(*delta));
                }
                0x85 => {
                    let v: i32 = pop_int(stack)?;
                    stack.push(Value::Long(i64::from(v)));
                }
                0x88 => {
                    let v: i64 = pop_long(stack)?;
                    stack.push(Value::Int(v as i32));
                }
                0x94 => {
                    let b: i64 = pop_long(stack)?;
                    let a: i64 = pop_long(stack)?;
                    stack.push(Value::Int(a.cmp(&b) as i32));
                }
                0x86..=0x93 => {
                    let v: i32 = pop_int(stack)?;
                    let masked: i32 = match op {
                        0x91 => i32::from(v as i8),
                        0x92 => i32::from((v & 0xFFFF) as u16),
                        0x93 => i32::from(v as i16),
                        _ => v,
                    };
                    stack.push(Value::Int(masked));
                }
                0xBE => {
                    let arr_ref: usize = pop_ref(stack)?;
                    let len: usize = array_len(&self.heap, arr_ref)?;
                    stack.push(Value::Int(len as i32));
                }
                0xBC => {
                    let len: i32 = pop_int(stack)?;
                    let n: usize = usize::try_from(len).map_err(|_| EvalError::BadShape)?;
                    if n > MAX_STRING_LEN {
                        return Err(EvalError::BadShape);
                    }
                    let Operands::NewArray(atype) = insn.operands else {
                        return Err(EvalError::BadShape);
                    };
                    let obj: HeapObject = match atype {
                        4 | 8 => HeapObject::Bytes(vec![0i8; n]),
                        10 | 11 => HeapObject::Ints(vec![0i32; n]),
                        _ => HeapObject::Chars(vec![0u16; n]),
                    };
                    let r: usize = self.alloc(obj)?;
                    stack.push(Value::Ref(r));
                }
                0xBB => {
                    let cp: u16 = const_pool_index(insn)?;
                    let r: usize = self.new_object(cp)?;
                    stack.push(Value::Ref(r));
                }
                0xA7 => {
                    ip = branch_to(pc_index, insn)?;
                    continue;
                }
                0x99..=0x9E => {
                    let v: i32 = pop_int(stack)?;
                    if unary_cmp(op, v) {
                        ip = branch_to(pc_index, insn)?;
                        continue;
                    }
                }
                0x9F..=0xA4 => {
                    let b: i32 = pop_int(stack)?;
                    let a: i32 = pop_int(stack)?;
                    if binary_cmp(op, a, b) {
                        ip = branch_to(pc_index, insn)?;
                        continue;
                    }
                }
                0xA5 | 0xA6 => {
                    let b: Value = pop(stack)?;
                    let a: Value = pop(stack)?;
                    let eq: bool = ref_eq(a, b);
                    if (op == 0xA5 && eq) || (op == 0xA6 && !eq) {
                        ip = branch_to(pc_index, insn)?;
                        continue;
                    }
                }
                0xC6 | 0xC7 => {
                    let v: Value = pop(stack)?;
                    let is_null: bool = matches!(v, Value::Null);
                    if (op == 0xC6 && is_null) || (op == 0xC7 && !is_null) {
                        ip = branch_to(pc_index, insn)?;
                        continue;
                    }
                }
                0xB2 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let v: Value = self.get_static(cp)?;
                    stack.push(v);
                }
                0xB3 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let v: Value = pop(stack)?;
                    self.put_static(cp, v)?;
                }
                0xB4 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let obj_ref: usize = pop_ref(stack)?;
                    let v: Value = self.get_field(obj_ref, cp)?;
                    stack.push(v);
                }
                0xB5 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let v: Value = pop(stack)?;
                    let obj_ref: usize = pop_ref(stack)?;
                    self.put_field(obj_ref, cp, v)?;
                }
                0xB6..=0xB9 => {
                    let cp: u16 = const_pool_index(insn)?;
                    let returned: Option<Value> = self.invoke(cp, op, stack)?;
                    if let Some(ret) = returned {
                        stack.push(ret);
                    }
                }
                0xAD..=0xB0 => {
                    return Ok(Some(pop(stack)?));
                }
                0xAC => {
                    return Ok(Some(Value::Int(pop_int(stack)?)));
                }
                0xB1 => {
                    return Ok(None);
                }
                0xAA | 0xAB => {
                    let key: i32 = pop_int(stack)?;
                    let target_pc: u32 = switch_target(insn, key)?;
                    ip = resolve_pc(pc_index, target_pc)?;
                    continue;
                }
                other => return Err(EvalError::UnsupportedOpcode(other)),
            }
            ip += 1;
        }
        Err(EvalError::NoReturn)
    }

    fn new_object(&mut self, cp: u16) -> Result<usize, EvalError> {
        let class_name: Option<String> = bytecode::class_internal_name_at(self.cf, cp);
        match class_name.as_deref() {
            Some("java/lang/StringBuilder") => self.alloc(HeapObject::Builder(Vec::new())),
            Some("java/lang/String") => self.alloc(HeapObject::Text(Vec::new())),
            Some("java/util/Random") => self.alloc(HeapObject::Random(None)),
            Some("java/lang/Throwable" | "java/lang/Exception" | "java/lang/RuntimeException") => {
                self.alloc(HeapObject::Text(Vec::new()))
            }
            Some(name) if name == self.cf.this_class_name().unwrap_or("\0") => {
                self.alloc(HeapObject::Instance {
                    class_name: name.to_owned(),
                    fields: BTreeMap::new(),
                })
            }
            _ => self.alloc(HeapObject::Text(Vec::new())),
        }
    }

    fn invoke(
        &mut self,
        cp: u16,
        op: u8,
        stack: &mut Vec<Value>,
    ) -> Result<Option<Value>, EvalError> {
        let Some(sig): Option<String> = bytecode::resolve_ref(self.cf, cp) else {
            return Err(EvalError::BadShape);
        };
        let (owner_name, rest): (&str, &str) = sig.split_once('.').ok_or(EvalError::BadShape)?;
        let (name, desc): (&str, &str) = rest.split_once(':').ok_or(EvalError::BadShape)?;

        match self.invoke_jdk(owner_name, name, desc, stack)? {
            JdkOutcome::Handled(result) => return Ok(result),
            JdkOutcome::NotHandled => {}
        }

        if owner_name == self.cf.this_class_name().unwrap_or("\0") {
            return self.invoke_self(name, desc, op, stack);
        }

        if is_runtime_key_call(owner_name, name) {
            return Err(EvalError::RuntimeKeyUnavailable);
        }

        Err(EvalError::UnknownCall(sig))
    }

    fn invoke_jdk(
        &mut self,
        owner: &str,
        name: &str,
        desc: &str,
        stack: &mut Vec<Value>,
    ) -> Result<JdkOutcome, EvalError> {
        let handled: Option<Value> = match (owner, name, desc) {
            ("java/lang/String", "charAt", "(I)C") => {
                let index: i32 = pop_int(stack)?;
                let r: usize = pop_ref(stack)?;
                Some(Value::Int(i32::from(read_text_char(&self.heap, r, index)?)))
            }
            ("java/lang/String", "length", "()I") => {
                let r: usize = pop_ref(stack)?;
                Some(Value::Int(text_len(&self.heap, r)? as i32))
            }
            ("java/lang/String", "hashCode", "()I") => {
                let r: usize = pop_ref(stack)?;
                Some(Value::Int(java_string_hash(&text_units(&self.heap, r)?)))
            }
            ("java/lang/String", "toCharArray", "()[C") => {
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = text_units(&self.heap, r)?;
                Some(Value::Ref(self.alloc(HeapObject::Chars(units))?))
            }
            ("java/lang/String", "replace", "(CC)Ljava/lang/String;") => {
                let to: i32 = pop_int(stack)?;
                let from: i32 = pop_int(stack)?;
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = text_units(&self.heap, r)?
                    .into_iter()
                    .map(|u: u16| {
                        if i32::from(u) == from {
                            (to & 0xFFFF) as u16
                        } else {
                            u
                        }
                    })
                    .collect();
                Some(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            ("java/lang/String", "<init>", "([C)V") => {
                let arr_ref: usize = pop_ref(stack)?;
                let target: usize = pop_ref(stack)?;
                let units: Vec<u16> = chars_units(&self.heap, arr_ref)?;
                set_text(&mut self.heap, target, units)?;
                None
            }
            ("java/lang/String", "<init>", "([CII)V") => {
                let count: i32 = pop_int(stack)?;
                let offset: i32 = pop_int(stack)?;
                let arr_ref: usize = pop_ref(stack)?;
                let target: usize = pop_ref(stack)?;
                let units: Vec<u16> = slice_chars(&self.heap, arr_ref, offset, count)?;
                set_text(&mut self.heap, target, units)?;
                None
            }
            ("java/lang/String", "intern", "()Ljava/lang/String;") => {
                Some(Value::Ref(pop_ref(stack)?))
            }
            ("java/lang/String", "valueOf", "([C)Ljava/lang/String;") => {
                let arr_ref: usize = pop_ref(stack)?;
                let units: Vec<u16> = chars_units(&self.heap, arr_ref)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            ("java/lang/Object", "<init>", "()V") => {
                pop_ref(stack)?;
                None
            }
            ("java/lang/StringBuilder", "<init>", "()V") => {
                pop_ref(stack)?;
                None
            }
            ("java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;") => {
                let ch: i32 = pop_int(stack)?;
                let r: usize = pop_ref(stack)?;
                builder_push(&mut self.heap, r, (ch & 0xFFFF) as u16)?;
                Some(Value::Ref(r))
            }
            (
                "java/lang/StringBuilder",
                "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            ) => {
                let arg: usize = pop_ref(stack)?;
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = text_units(&self.heap, arg)?;
                builder_extend(&mut self.heap, r, &units)?;
                Some(Value::Ref(r))
            }
            ("java/lang/StringBuilder", "toString", "()Ljava/lang/String;") => {
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = builder_units(&self.heap, r)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            ("java/util/Random", "<init>", "(J)V") => {
                let seed: i64 = pop_long(stack)?;
                let r: usize = pop_ref(stack)?;
                set_random_seed(&mut self.heap, r, seed)?;
                None
            }
            ("java/util/Random", "<init>", "()V") => {
                pop_ref(stack)?;
                None
            }
            ("java/util/Random", "setSeed", "(J)V") => {
                let seed: i64 = pop_long(stack)?;
                let r: usize = pop_ref(stack)?;
                set_random_seed(&mut self.heap, r, seed)?;
                None
            }
            ("java/util/Random", "nextInt", "()I") => {
                let r: usize = pop_ref(stack)?;
                Some(Value::Int(random_next_int(&mut self.heap, r)?))
            }
            ("java/util/Random", "nextInt", "(I)I") => {
                let bound: i32 = pop_int(stack)?;
                let r: usize = pop_ref(stack)?;
                Some(Value::Int(random_next_bounded_int(
                    &mut self.heap,
                    r,
                    bound,
                )?))
            }
            (
                "java/lang/Throwable" | "java/lang/Exception" | "java/lang/RuntimeException",
                "<init>",
                "()V",
            ) => {
                pop_ref(stack)?;
                None
            }
            (
                "java/lang/Throwable" | "java/lang/Exception" | "java/lang/RuntimeException",
                "getStackTrace",
                "()[Ljava/lang/StackTraceElement;",
            ) => {
                pop_ref(stack)?;
                Some(Value::Ref(self.synth_stack_trace()?))
            }
            ("java/lang/Thread", "getStackTrace", "()[Ljava/lang/StackTraceElement;") => {
                pop_ref(stack)?;
                Some(Value::Ref(self.synth_stack_trace()?))
            }
            ("java/lang/Thread", "currentThread", "()Ljava/lang/Thread;") => {
                Some(Value::Ref(self.alloc(HeapObject::Text(Vec::new()))?))
            }
            ("java/lang/StackTraceElement", "getClassName", "()Ljava/lang/String;") => {
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = frame_class_units(&self.heap, r)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            ("java/lang/StackTraceElement", "getMethodName", "()Ljava/lang/String;") => {
                let r: usize = pop_ref(stack)?;
                let units: Vec<u16> = frame_method_units(&self.heap, r)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            (
                "java/lang/Class",
                "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;"
                | "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
            ) => {
                if desc.contains('Z') {
                    pop_ref(stack)?;
                    pop_int(stack)?;
                }
                let r: usize = pop_ref(stack)?;
                let dotted: String = String::from_utf16_lossy(&text_units(&self.heap, r)?);
                let internal: String = dotted.replace('.', "/");
                Some(Value::Ref(self.alloc(HeapObject::ClassObj {
                    internal_name: internal,
                })?))
            }
            ("java/lang/Object", "getClass", "()Ljava/lang/Class;") => {
                let r: usize = pop_ref(stack)?;
                let internal: String = self.runtime_class_of(r)?;
                Some(Value::Ref(self.alloc(HeapObject::ClassObj {
                    internal_name: internal,
                })?))
            }
            (
                "java/lang/Class",
                "getName" | "getCanonicalName" | "getTypeName",
                "()Ljava/lang/String;",
            ) => {
                let r: usize = pop_ref(stack)?;
                let dotted: Vec<u16> = class_name_units(&self.heap, r, false)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(dotted))?))
            }
            ("java/lang/Class", "getSimpleName", "()Ljava/lang/String;") => {
                let r: usize = pop_ref(stack)?;
                let simple: Vec<u16> = class_name_units(&self.heap, r, true)?;
                Some(Value::Ref(self.alloc(HeapObject::Text(simple))?))
            }
            _ => return Ok(JdkOutcome::NotHandled),
        };
        Ok(JdkOutcome::Handled(handled))
    }

    fn invoke_self(
        &mut self,
        name: &str,
        desc: &str,
        op: u8,
        stack: &mut Vec<Value>,
    ) -> Result<Option<Value>, EvalError> {
        let target_index: usize = self
            .find_method(name, desc)
            .ok_or_else(|| EvalError::UnresolvedSelfCall(format!("{name}:{desc}")))?;
        if desc == "()J"
            && let Some(word) = self.reflective_self_hash_word(target_index)?
        {
            return Ok(Some(Value::Long(word)));
        }
        let arg_slots: usize = descriptor_arg_slots(desc);
        let is_static: bool = self
            .cf
            .methods
            .get(target_index)
            .map(|m: &MethodInfo| m.access_flags & 0x0008 != 0)
            .unwrap_or(true);
        let total: usize = arg_slots + usize::from(!is_static && op != 0xB8);
        if stack.len() < total {
            return Err(EvalError::StackUnderflow);
        }
        let args: Vec<Value> = stack.split_off(stack.len() - total);
        self.run_method(target_index, args)
    }

    fn find_method(&self, name: &str, desc: &str) -> Option<usize> {
        self.cf.methods.iter().position(|m: &MethodInfo| {
            self.cf
                .utf8_at(m.name_index)
                .map(|n: &str| n == name)
                .unwrap_or(false)
                && self
                    .cf
                    .utf8_at(m.descriptor_index)
                    .map(|d: &str| d == desc)
                    .unwrap_or(false)
        })
    }

    fn reflective_self_hash_word(&mut self, method_index: usize) -> Result<Option<i64>, EvalError> {
        let Some(fold_index): Option<usize> = reflective_self_hash_fold(self.cf, method_index)
        else {
            return Ok(None);
        };
        let empty: usize = self.alloc(HeapObject::Bytes(Vec::new()))?;
        let args: Vec<Value> = vec![
            Value::Long(0),
            Value::Int(0),
            Value::Long(0),
            Value::Int(0),
            Value::Ref(empty),
        ];
        match self.run_method(fold_index, args)? {
            Some(Value::Long(v)) => Ok(Some(v)),
            _ => Err(EvalError::NoReturn),
        }
    }

    fn synth_stack_trace(&mut self) -> Result<usize, EvalError> {
        let frame: usize = self.alloc(HeapObject::Frame {
            class_name: self.caller.internal_class_name.replace('/', "."),
            method_name: self.caller.method_name.clone(),
        })?;
        let self_frame: usize = self.alloc(HeapObject::Frame {
            class_name: self.cf.this_class_name().unwrap_or("").replace('/', "."),
            method_name: "decrypt".to_owned(),
        })?;
        self.alloc(HeapObject::FrameArray(vec![self_frame, frame]))
    }

    fn runtime_class_of(&self, r: usize) -> Result<String, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::Instance { class_name, .. }) => Ok(class_name.clone()),
            Some(HeapObject::ClassObj { .. }) => Ok("java/lang/Class".to_owned()),
            Some(HeapObject::Text(_)) => Ok("java/lang/String".to_owned()),
            Some(HeapObject::Builder(_)) => Ok("java/lang/StringBuilder".to_owned()),
            Some(HeapObject::Random(_)) => Ok("java/util/Random".to_owned()),
            Some(HeapObject::Chars(_) | HeapObject::Bytes(_) | HeapObject::Ints(_)) => {
                Err(EvalError::BadShape)
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn read_frame_array(&self, arr_ref: usize, index: i32) -> Result<usize, EvalError> {
        let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
        match self.heap.get(arr_ref) {
            Some(HeapObject::FrameArray(v)) => v.get(i).copied().ok_or(EvalError::BadShape),
            _ => Err(EvalError::BadShape),
        }
    }

    fn load_constant(&mut self, cp: u16) -> Result<Value, EvalError> {
        let idx: usize = usize::from(cp);
        if idx == 0 || idx >= self.cf.constant_pool.len() {
            return Err(EvalError::BadShape);
        }
        match &self.cf.constant_pool[idx] {
            ConstantPoolEntry::Integer(v) => Ok(Value::Int(*v)),
            ConstantPoolEntry::String { utf8_index } => {
                let s: &str = self
                    .cf
                    .utf8_at(*utf8_index)
                    .map_err(|_| EvalError::BadShape)?;
                let units: Vec<u16> = s.encode_utf16().collect();
                Ok(Value::Ref(self.alloc(HeapObject::Text(units))?))
            }
            ConstantPoolEntry::Class { .. } => {
                let internal: String =
                    bytecode::class_internal_name_at(self.cf, cp).ok_or(EvalError::BadShape)?;
                Ok(Value::Ref(self.alloc(HeapObject::ClassObj {
                    internal_name: internal,
                })?))
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn load_long_constant(&self, cp: u16) -> Result<Value, EvalError> {
        let idx: usize = usize::from(cp);
        if idx == 0 || idx >= self.cf.constant_pool.len() {
            return Err(EvalError::BadShape);
        }
        match &self.cf.constant_pool[idx] {
            ConstantPoolEntry::Long(v) => Ok(Value::Long(*v)),
            _ => Err(EvalError::BadShape),
        }
    }

    fn run_clinit(&mut self) -> Result<(), EvalError> {
        if self.clinit_done {
            return Ok(());
        }
        self.clinit_done = true;
        if let Some(idx) = self.find_method("<clinit>", "()V") {
            self.run_method(idx, Vec::new())?;
        }
        Ok(())
    }

    fn static_field_key(&self, cp: u16) -> Result<(String, bool), EvalError> {
        let sig: String = bytecode::resolve_ref(self.cf, cp).ok_or(EvalError::BadShape)?;
        let (owner, rest): (&str, &str) = sig.split_once('.').ok_or(EvalError::BadShape)?;
        let own_class: bool = owner == self.cf.this_class_name().unwrap_or("\0");
        Ok((format!("{owner}.{rest}"), own_class))
    }

    fn get_static(&mut self, cp: u16) -> Result<Value, EvalError> {
        let (key, own_class): (String, bool) = self.static_field_key(cp)?;
        if !self.clinit_done {
            self.run_clinit()?;
        }
        if let Some(v) = self.statics.get(&key) {
            return Ok(*v);
        }
        if own_class {
            return Err(EvalError::BadShape);
        }
        Err(EvalError::RuntimeKeyUnavailable)
    }

    fn put_static(&mut self, cp: u16, v: Value) -> Result<(), EvalError> {
        let (key, _own_class): (String, bool) = self.static_field_key(cp)?;
        self.statics.insert(key, v);
        Ok(())
    }

    fn field_name(&self, cp: u16) -> Result<String, EvalError> {
        let sig: String = bytecode::resolve_ref(self.cf, cp).ok_or(EvalError::BadShape)?;
        let (_owner, rest): (&str, &str) = sig.split_once('.').ok_or(EvalError::BadShape)?;
        let (name, _desc): (&str, &str) = rest.split_once(':').ok_or(EvalError::BadShape)?;
        Ok(name.to_owned())
    }

    fn get_field(&self, obj_ref: usize, cp: u16) -> Result<Value, EvalError> {
        let name: String = self.field_name(cp)?;
        match self.heap.get(obj_ref) {
            Some(HeapObject::Instance { fields, .. }) => {
                Ok(fields.get(&name).copied().unwrap_or(Value::Int(0)))
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn put_field(&mut self, obj_ref: usize, cp: u16, v: Value) -> Result<(), EvalError> {
        let name: String = self.field_name(cp)?;
        match self.heap.get_mut(obj_ref) {
            Some(HeapObject::Instance { fields, .. }) => {
                fields.insert(name, v);
                Ok(())
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn construct_self_instance(&mut self) -> Result<usize, EvalError> {
        let class_name: String = self.cf.this_class_name().unwrap_or("").to_owned();
        let obj_ref: usize = self.alloc(HeapObject::Instance {
            class_name,
            fields: BTreeMap::new(),
        })?;
        if let Some(ctor_idx) = self.find_method("<init>", "()V") {
            self.run_method(ctor_idx, vec![Value::Ref(obj_ref)])?;
        }
        Ok(obj_ref)
    }
}

fn reflective_self_hash_fold(cf: &ClassFile, method_index: usize) -> Option<usize> {
    let method: &MethodInfo = cf.methods.get(method_index)?;
    let code: bytecode::CodeAttribute = method_code(cf, method)?;
    let insns: Vec<Instruction> = bytecode::disassemble(&code.code).ok()?;

    let mut walks_reflection: bool = false;
    let mut reads_own_zip: bool = false;
    let mut collects_bytes: bool = false;
    let mut fold_call: Option<usize> = None;

    for insn in &insns {
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
        match sig.as_str() {
            "java/lang/Class.getDeclaredMethods:()[Ljava/lang/reflect/Method;"
            | "java/lang/reflect/Method.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;" =>
            {
                walks_reflection = true;
            }
            "java/util/zip/ZipInputStream.<init>:(Ljava/io/InputStream;)V" => {
                reads_own_zip = true;
            }
            "java/io/ByteArrayOutputStream.toByteArray:()[B" => {
                collects_bytes = true;
            }
            _ => {}
        }
        if let Some((owner, rest)) = sig.split_once('.')
            && owner == cf.this_class_name().unwrap_or("\0")
            && let Some((name, fold_desc)) = rest.split_once(':')
            && fold_desc == "(JJ[B)J"
            && let Some(idx) = cf.methods.iter().position(|m: &MethodInfo| {
                cf.utf8_at(m.name_index)
                    .map(|n: &str| n == name)
                    .unwrap_or(false)
                    && cf
                        .utf8_at(m.descriptor_index)
                        .map(|d: &str| d == fold_desc)
                        .unwrap_or(false)
            })
        {
            fold_call = Some(idx);
        }
    }

    if walks_reflection && reads_own_zip && collects_bytes {
        fold_call
    } else {
        None
    }
}

fn descriptor_arg_slots(desc: &str) -> usize {
    let Some(close): Option<usize> = desc.find(')') else {
        return 0;
    };
    let params: &str = desc.get(1..close).unwrap_or("");
    let bytes: &[u8] = params.as_bytes();
    let mut i: usize = 0;
    let mut slots: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                i += 1;
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                }
                i += 1;
                slots += 1;
            }
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1;
                slots += 1;
            }
            b'J' | b'D' => {
                i += 1;
                slots += 2;
            }
            _ => {
                i += 1;
                slots += 1;
            }
        }
    }
    slots
}

#[must_use]
pub fn recover_reflective_self_hash_empty_fold(cf: &ClassFile) -> Option<i64> {
    let key_method: usize = (0..cf.methods.len()).find(|&idx: &usize| {
        cf.methods
            .get(idx)
            .and_then(|m: &MethodInfo| cf.utf8_at(m.descriptor_index).ok())
            .map(|d: &str| d == "()J")
            .unwrap_or(false)
            && reflective_self_hash_fold(cf, idx).is_some()
    })?;
    let caller: CallerContext = CallerContext::new(String::new(), String::new());
    let mut eval: Evaluator<'_> = Evaluator {
        cf,
        heap: Vec::with_capacity(8),
        statics: BTreeMap::new(),
        clinit_done: true,
        caller: &caller,
        depth: 0,
        steps: 0,
    };
    eval.reflective_self_hash_word(key_method).ok().flatten()
}

pub fn evaluate_decrypt(
    cf: &ClassFile,
    method: &DecryptMethod,
    encrypted: &str,
    int_seed: i32,
    caller: &CallerContext,
) -> Result<String, EvalError> {
    let mut eval: Evaluator<'_> = Evaluator {
        cf,
        heap: Vec::with_capacity(16),
        statics: BTreeMap::new(),
        clinit_done: false,
        caller,
        depth: 0,
        steps: 0,
    };
    eval.run_clinit()?;
    let input_units: Vec<u16> = encrypted.encode_utf16().collect();
    let str_ref: usize = eval.alloc(HeapObject::Text(input_units))?;

    let desc: &str = cf
        .utf8_at(
            cf.methods
                .get(method.method_index)
                .ok_or(EvalError::BadShape)?
                .descriptor_index,
        )
        .map_err(|_| EvalError::BadShape)?;
    let mut args: Vec<Value> = Vec::with_capacity(3);
    if !method.is_static {
        let this_ref: usize = eval.construct_self_instance()?;
        args.push(Value::Ref(this_ref));
    }
    if desc.starts_with("(I") {
        args.push(Value::Int(int_seed));
        args.push(Value::Ref(str_ref));
    } else if method.takes_int {
        args.push(Value::Ref(str_ref));
        args.push(Value::Int(int_seed));
    } else {
        args.push(Value::Ref(str_ref));
    }

    match eval.run_method(method.method_index, args)? {
        Some(Value::Ref(r)) => finish(&eval.heap, r),
        _ => Err(EvalError::NoReturn),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallSite {
    caller_method_index: usize,
    decrypt_method_index: usize,
    literal_utf8_index: u16,
    int_seed: Option<i32>,
}

fn collect_call_sites(cf: &ClassFile, decrypt_methods: &[DecryptMethod]) -> Vec<CallSite> {
    let decrypt_refs: Vec<(usize, String, String, bool)> = decrypt_methods
        .iter()
        .filter_map(|d: &DecryptMethod| {
            let m: &MethodInfo = cf.methods.get(d.method_index)?;
            let name: String = cf.utf8_at(m.name_index).ok()?.to_owned();
            let desc: String = cf.utf8_at(m.descriptor_index).ok()?.to_owned();
            Some((d.method_index, name, desc, d.takes_int))
        })
        .collect();

    let string_const_to_utf8: BTreeMap<u16, u16> = string_pool_entries(cf);
    let mut sites: Vec<CallSite> = Vec::new();

    for (caller_idx, method) in cf.methods.iter().enumerate() {
        let Some(code): Option<bytecode::CodeAttribute> = method_code(cf, method) else {
            continue;
        };
        let Ok(insns): Result<Vec<Instruction>, crate::error::Error> =
            bytecode::disassemble(&code.code)
        else {
            continue;
        };
        scan_for_call_sites(
            cf,
            &insns,
            caller_idx,
            &decrypt_refs,
            &string_const_to_utf8,
            &mut sites,
        );
    }
    sites
}

fn scan_for_call_sites(
    cf: &ClassFile,
    insns: &[Instruction],
    caller_idx: usize,
    decrypt_refs: &[(usize, String, String, bool)],
    string_const_to_utf8: &BTreeMap<u16, u16>,
    sites: &mut Vec<CallSite>,
) {
    let mut pending_literal: Option<u16> = None;
    let mut pending_int: Option<i32> = None;
    for insn in insns {
        match insn.opcode {
            0x12 | 0x13 => {
                if let Operands::ConstPool(cp) = insn.operands {
                    pending_literal = string_const_to_utf8.get(&cp).copied();
                }
            }
            0x02..=0x08 => pending_int = Some(i32::from(insn.opcode) - 3),
            0x10 | 0x11 => {
                if let Operands::Byte(v) | Operands::Short(v) = insn.operands {
                    pending_int = Some(v);
                }
            }
            0xB6 | 0xB8 | 0xB9 => {
                if let Some(utf8_idx) = pending_literal
                    && let Operands::ConstPool(cp) | Operands::InvokeInterface { index: cp, .. } =
                        insn.operands
                    && let Some(sig) = bytecode::resolve_ref(cf, cp)
                    && let Some((_, rest)) = sig.split_once('.')
                    && let Some((name, desc)) = rest.split_once(':')
                    && let Some(found) = decrypt_refs
                        .iter()
                        .find(|(_, n, d, _)| n == name && d == desc)
                {
                    sites.push(CallSite {
                        caller_method_index: caller_idx,
                        decrypt_method_index: found.0,
                        literal_utf8_index: utf8_idx,
                        int_seed: pending_int,
                    });
                }
                pending_literal = None;
                pending_int = None;
            }
            _ => {
                pending_literal = None;
                pending_int = None;
            }
        }
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerKeyedReport {
    pub recovered: BTreeMap<u16, String>,
    pub attempted: usize,
    pub decrypt_methods: usize,
    pub call_sites: usize,
    pub runtime_key_wall: bool,
    pub runtime_key_wall_reason: Option<String>,
}

#[must_use]
pub fn recover_caller_keyed_strings(cf: &ClassFile) -> CallerKeyedReport {
    let mut report: CallerKeyedReport = CallerKeyedReport::default();
    let decrypt_methods: Vec<DecryptMethod> = find_decrypt_methods(cf);
    report.decrypt_methods = decrypt_methods.len();
    if decrypt_methods.is_empty() {
        return report;
    }

    let sites: Vec<CallSite> = collect_call_sites(cf, &decrypt_methods);
    report.call_sites = sites.len();
    let strings: BTreeMap<u16, String> = cf.collect_strings();

    for site in &sites {
        let Some(literal): Option<&String> = strings.get(&site.literal_utf8_index) else {
            continue;
        };
        if literal.is_empty() {
            continue;
        }
        let method: &DecryptMethod = match decrypt_methods
            .iter()
            .find(|d: &&DecryptMethod| d.method_index == site.decrypt_method_index)
        {
            Some(m) => m,
            None => continue,
        };
        let caller_name: String = cf
            .utf8_at(
                cf.methods
                    .get(site.caller_method_index)
                    .map(|m: &MethodInfo| m.name_index)
                    .unwrap_or(0),
            )
            .unwrap_or("")
            .to_owned();
        let caller: CallerContext =
            CallerContext::new(cf.this_class_name().unwrap_or("").to_owned(), caller_name);
        report.attempted += 1;
        let seed: i32 = site.int_seed.unwrap_or(0);
        match evaluate_decrypt(cf, method, literal, seed, &caller) {
            Ok(plain) if is_plausible_plaintext(&plain) => {
                report.recovered.insert(site.literal_utf8_index, plain);
            }
            Err(EvalError::RuntimeKeyUnavailable) => {
                report.runtime_key_wall = true;
                report.runtime_key_wall_reason = Some(
                    "the decrypt method derives its key from runtime-only state (system \
                     property, clock, environment, or live thread identity) that is not present \
                     in the static artifact; the constant stays opaque"
                        .to_owned(),
                );
            }
            _ => {}
        }
    }
    report
}

fn is_runtime_key_call(owner: &str, name: &str) -> bool {
    matches!(
        (owner, name),
        (
            "java/lang/System",
            "getProperty" | "getenv" | "currentTimeMillis" | "nanoTime"
        ) | ("java/lang/Runtime", "getRuntime")
            | ("java/security/SecureRandom" | "java/util/Random", _)
    ) || owner.starts_with("java/lang/reflect")
        || (owner == "java/lang/Class" && name == "getProtectionDomain")
}

const fn ref_eq(a: Value, b: Value) -> bool {
    matches!((a, b), (Value::Null, Value::Null))
        || matches!((a, b), (Value::Ref(x), Value::Ref(y)) if x == y)
}

#[must_use]
pub fn java_string_hash(units: &[u16]) -> i32 {
    let mut h: i32 = 0;
    for u in units {
        h = h.wrapping_mul(31).wrapping_add(i32::from(*u));
    }
    h
}

const JAVA_RANDOM_MULTIPLIER: u64 = 0x0005_DEEC_E66D;
const JAVA_RANDOM_ADDEND: u64 = 0x0B;
const JAVA_RANDOM_MASK: u64 = (1u64 << 48) - 1;
const JAVA_RANDOM_REJECTION_CAP: usize = 128;

impl JavaRandomState {
    const fn from_user_seed(seed: i64) -> Self {
        Self {
            seed: (seed as u64 ^ JAVA_RANDOM_MULTIPLIER) & JAVA_RANDOM_MASK,
        }
    }

    const fn next_bits(&mut self, bits: u32) -> i32 {
        self.seed = self
            .seed
            .wrapping_mul(JAVA_RANDOM_MULTIPLIER)
            .wrapping_add(JAVA_RANDOM_ADDEND)
            & JAVA_RANDOM_MASK;
        (self.seed >> (48 - bits)) as i32
    }

    const fn next_int(&mut self) -> i32 {
        self.next_bits(32)
    }

    fn next_bounded_int(&mut self, bound: i32) -> Result<i32, EvalError> {
        if bound <= 0 {
            return Err(EvalError::BadShape);
        }
        if bound & (bound - 1) == 0 {
            let bits: i32 = self.next_bits(31);
            return Ok(((i64::from(bound) * i64::from(bits)) >> 31) as i32);
        }
        for _ in 0..JAVA_RANDOM_REJECTION_CAP {
            let bits: i32 = self.next_bits(31);
            let value: i32 = bits % bound;
            if bits.wrapping_sub(value).wrapping_add(bound - 1) >= 0 {
                return Ok(value);
            }
        }
        Err(EvalError::StepLimitExceeded)
    }
}

fn set_random_seed(heap: &mut [HeapObject], r: usize, seed: i64) -> Result<(), EvalError> {
    match heap.get_mut(r) {
        Some(HeapObject::Random(state)) => {
            *state = Some(JavaRandomState::from_user_seed(seed));
            Ok(())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn random_next_int(heap: &mut [HeapObject], r: usize) -> Result<i32, EvalError> {
    match heap.get_mut(r) {
        Some(HeapObject::Random(Some(state))) => Ok(state.next_int()),
        Some(HeapObject::Random(None)) => Err(EvalError::RuntimeKeyUnavailable),
        _ => Err(EvalError::BadShape),
    }
}

fn random_next_bounded_int(
    heap: &mut [HeapObject],
    r: usize,
    bound: i32,
) -> Result<i32, EvalError> {
    match heap.get_mut(r) {
        Some(HeapObject::Random(Some(state))) => state.next_bounded_int(bound),
        Some(HeapObject::Random(None)) => Err(EvalError::RuntimeKeyUnavailable),
        _ => Err(EvalError::BadShape),
    }
}

fn pop(stack: &mut Vec<Value>) -> Result<Value, EvalError> {
    stack.pop().ok_or(EvalError::StackUnderflow)
}

fn pop_int(stack: &mut Vec<Value>) -> Result<i32, EvalError> {
    pop(stack)?.as_int()
}

fn pop_long(stack: &mut Vec<Value>) -> Result<i64, EvalError> {
    pop(stack)?.as_long()
}

fn pop_ref(stack: &mut Vec<Value>) -> Result<usize, EvalError> {
    pop(stack)?.as_ref()
}

const fn const_pool_index(insn: &Instruction) -> Result<u16, EvalError> {
    match &insn.operands {
        Operands::ConstPool(i)
        | Operands::InvokeInterface { index: i, .. }
        | Operands::InvokeDynamic(i) => Ok(*i),
        _ => Err(EvalError::BadShape),
    }
}

fn load_local_index(insn: &Instruction, op: u8) -> Result<usize, EvalError> {
    match op {
        0x15..=0x19 => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(EvalError::BadShape),
        },
        0x1A..=0x1D => Ok(usize::from(op - 0x1A)),
        0x1E..=0x21 => Ok(usize::from(op - 0x1E)),
        0x22..=0x25 => Ok(usize::from(op - 0x22)),
        0x26..=0x29 => Ok(usize::from(op - 0x26)),
        0x2A..=0x2D => Ok(usize::from(op - 0x2A)),
        _ => Err(EvalError::BadShape),
    }
}

fn store_local_index(insn: &Instruction, op: u8) -> Result<usize, EvalError> {
    match op {
        0x36..=0x3A => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(EvalError::BadShape),
        },
        0x3B..=0x3E => Ok(usize::from(op - 0x3B)),
        0x3F..=0x42 => Ok(usize::from(op - 0x3F)),
        0x43..=0x46 => Ok(usize::from(op - 0x43)),
        0x47..=0x4A => Ok(usize::from(op - 0x47)),
        0x4B..=0x4E => Ok(usize::from(op - 0x4B)),
        _ => Err(EvalError::BadShape),
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

fn binary<F: Fn(i32, i32) -> i32>(stack: &mut Vec<Value>, f: F) -> Result<(), EvalError> {
    let b: i32 = pop_int(stack)?;
    let a: i32 = pop_int(stack)?;
    stack.push(Value::Int(f(a, b)));
    Ok(())
}

fn long_binary<F: Fn(i64, i64) -> i64>(stack: &mut Vec<Value>, f: F) -> Result<(), EvalError> {
    let b: i64 = pop_long(stack)?;
    let a: i64 = pop_long(stack)?;
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

fn branch_to(pc_index: &[u32], insn: &Instruction) -> Result<usize, EvalError> {
    let target: u32 = bytecode::branch_target(insn).ok_or(EvalError::BadShape)?;
    resolve_pc(pc_index, target)
}

fn resolve_pc(pc_index: &[u32], target: u32) -> Result<usize, EvalError> {
    pc_index
        .iter()
        .position(|&pc| pc == target)
        .ok_or(EvalError::BadShape)
}

fn switch_target(insn: &Instruction, key: i32) -> Result<u32, EvalError> {
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
                let idx: usize = usize::try_from(key - *low).map_err(|_| EvalError::BadShape)?;
                *offsets.get(idx).ok_or(EvalError::BadShape)?
            }
        }
        Operands::LookupSwitch { default, pairs } => pairs
            .iter()
            .find_map(|(m, off): &(i32, i32)| if *m == key { Some(*off) } else { None })
            .unwrap_or(*default),
        _ => return Err(EvalError::BadShape),
    };
    u32::try_from(base + i64::from(offset)).map_err(|_| EvalError::BadShape)
}

fn read_byte_or_char_array(heap: &[HeapObject], r: usize, index: i32) -> Result<i32, EvalError> {
    let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => v.get(i).copied().map(i32::from).ok_or(EvalError::BadShape),
        Some(HeapObject::Bytes(v)) => v.get(i).copied().map(i32::from).ok_or(EvalError::BadShape),
        _ => Err(EvalError::BadShape),
    }
}

fn write_byte_or_char_array(
    heap: &mut [HeapObject],
    r: usize,
    index: i32,
    value: i32,
) -> Result<(), EvalError> {
    let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
    match heap.get_mut(r) {
        Some(HeapObject::Chars(v)) if i < v.len() => {
            v[i] = (value & 0xFFFF) as u16;
            Ok(())
        }
        Some(HeapObject::Bytes(v)) if i < v.len() => {
            v[i] = value as i8;
            Ok(())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn read_int_array(heap: &[HeapObject], r: usize, index: i32) -> Result<i32, EvalError> {
    let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Ints(v)) => v.get(i).copied().ok_or(EvalError::BadShape),
        _ => Err(EvalError::BadShape),
    }
}

fn write_int_array(
    heap: &mut [HeapObject],
    r: usize,
    index: i32,
    value: i32,
) -> Result<(), EvalError> {
    let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
    match heap.get_mut(r) {
        Some(HeapObject::Ints(v)) if i < v.len() => {
            v[i] = value;
            Ok(())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn array_len(heap: &[HeapObject], r: usize) -> Result<usize, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => Ok(v.len()),
        Some(HeapObject::Ints(v)) => Ok(v.len()),
        Some(HeapObject::Bytes(v)) => Ok(v.len()),
        Some(HeapObject::FrameArray(v)) => Ok(v.len()),
        _ => Err(EvalError::BadShape),
    }
}

fn read_text_char(heap: &[HeapObject], r: usize, index: i32) -> Result<u16, EvalError> {
    let i: usize = usize::try_from(index).map_err(|_| EvalError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Text(v)) => v.get(i).copied().ok_or(EvalError::BadShape),
        _ => Err(EvalError::BadShape),
    }
}

fn text_len(heap: &[HeapObject], r: usize) -> Result<usize, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Text(v)) => Ok(v.len()),
        _ => Err(EvalError::BadShape),
    }
}

fn text_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Text(v)) => Ok(v.clone()),
        _ => Err(EvalError::BadShape),
    }
}

fn chars_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => Ok(v.clone()),
        _ => Err(EvalError::BadShape),
    }
}

fn frame_class_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Frame { class_name, .. }) => Ok(class_name.encode_utf16().collect()),
        _ => Err(EvalError::BadShape),
    }
}

fn frame_method_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Frame { method_name, .. }) => Ok(method_name.encode_utf16().collect()),
        _ => Err(EvalError::BadShape),
    }
}

fn class_name_units(heap: &[HeapObject], r: usize, simple: bool) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::ClassObj { internal_name }) => {
            let dotted: String = internal_name.replace('/', ".");
            let chosen: &str = if simple {
                dotted.rsplit('.').next().unwrap_or(dotted.as_str())
            } else {
                dotted.as_str()
            };
            Ok(chosen.encode_utf16().collect())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn slice_chars(
    heap: &[HeapObject],
    r: usize,
    offset: i32,
    count: i32,
) -> Result<Vec<u16>, EvalError> {
    let o: usize = usize::try_from(offset).map_err(|_| EvalError::BadShape)?;
    let c: usize = usize::try_from(count).map_err(|_| EvalError::BadShape)?;
    match heap.get(r) {
        Some(HeapObject::Chars(v)) => {
            let end: usize = o.checked_add(c).ok_or(EvalError::BadShape)?;
            v.get(o..end)
                .map(<[u16]>::to_vec)
                .ok_or(EvalError::BadShape)
        }
        _ => Err(EvalError::BadShape),
    }
}

fn set_text(heap: &mut [HeapObject], r: usize, units: Vec<u16>) -> Result<(), EvalError> {
    match heap.get_mut(r) {
        Some(slot) => {
            *slot = HeapObject::Text(units);
            Ok(())
        }
        None => Err(EvalError::BadShape),
    }
}

fn builder_push(heap: &mut [HeapObject], r: usize, ch: u16) -> Result<(), EvalError> {
    match heap.get_mut(r) {
        Some(HeapObject::Builder(v)) if v.len() < MAX_STRING_LEN => {
            v.push(ch);
            Ok(())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn builder_extend(heap: &mut [HeapObject], r: usize, units: &[u16]) -> Result<(), EvalError> {
    match heap.get_mut(r) {
        Some(HeapObject::Builder(v)) if v.len() + units.len() <= MAX_STRING_LEN => {
            v.extend_from_slice(units);
            Ok(())
        }
        _ => Err(EvalError::BadShape),
    }
}

fn builder_units(heap: &[HeapObject], r: usize) -> Result<Vec<u16>, EvalError> {
    match heap.get(r) {
        Some(HeapObject::Builder(v)) => Ok(v.clone()),
        _ => Err(EvalError::BadShape),
    }
}

fn finish(heap: &[HeapObject], r: usize) -> Result<String, EvalError> {
    let units: Vec<u16> = match heap.get(r) {
        Some(HeapObject::Text(v) | HeapObject::Chars(v) | HeapObject::Builder(v)) => v.clone(),
        _ => return Err(EvalError::BadShape),
    };
    Ok(String::from_utf16_lossy(&units))
}

fn is_plausible_plaintext(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || c.is_whitespace() || (*c as u32) >= 0xA0)
        .count();
    let total: usize = s.chars().count();
    printable * 100 >= total * 85
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::vec_init_then_push,
    clippy::too_many_lines
)]
mod tests;
