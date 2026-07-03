use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dalvik::{self, DalvikInsn};
use crate::dex::{CodeItem, DexFile, FieldId, MethodId};

const STEP_LIMIT: u64 = 2_000_000;
const MAX_ARRAY_LEN: usize = 1 << 20;
const MAX_HEAP_OBJECTS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeIntKey {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub value: i64,
    pub source_library: String,
    pub symbol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    UnsupportedOpcode(u8),
    BadRegister,
    BadIndex,
    StepLimitExceeded,
    NoReturn,
    BadShape,
    HeapExhausted,
    RuntimeKeyUnavailable,
    UnknownCall(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeapObject {
    StringArray(Vec<Option<usize>>),
    CharArray(Vec<u16>),
    Text(Vec<u16>),
    ClassObj(String),
    Instance(String),
    Random(Option<JavaRandomState>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JavaRandomState {
    seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(i64),
    Ref(usize),
    Null,
}

impl Value {
    const fn as_int(self) -> Result<i64, EvalError> {
        match self {
            Self::Int(v) => Ok(v),
            _ => Err(EvalError::BadShape),
        }
    }

    const fn as_ref(self) -> Result<usize, EvalError> {
        match self {
            Self::Ref(r) => Ok(r),
            _ => Err(EvalError::BadShape),
        }
    }
}

struct Interp<'a> {
    dex: &'a DexFile,
    class: &'a str,
    code_items: &'a [CodeItem],
    native_keys: &'a BTreeMap<String, NativeIntKey>,
    heap: Vec<HeapObject>,
    statics: BTreeMap<String, Value>,
    steps: u64,
    depth: u32,
}

impl<'a> Interp<'a> {
    const fn new(
        dex: &'a DexFile,
        class: &'a str,
        code_items: &'a [CodeItem],
        native_keys: &'a BTreeMap<String, NativeIntKey>,
    ) -> Self {
        Self {
            dex,
            class,
            code_items,
            native_keys,
            heap: Vec::new(),
            statics: BTreeMap::new(),
            steps: 0,
            depth: 0,
        }
    }

    fn alloc(&mut self, obj: HeapObject) -> Result<usize, EvalError> {
        if self.heap.len() >= MAX_HEAP_OBJECTS {
            return Err(EvalError::HeapExhausted);
        }
        self.heap.push(obj);
        Ok(self.heap.len() - 1)
    }

    fn field_key(&self, index: u32) -> Option<String> {
        let f: &FieldId = self.dex.field_ids.get(index as usize)?;
        Some(format!("{}.{}:{}", f.class, f.name, f.type_name))
    }

    fn run_clinit(&mut self) -> Result<(), EvalError> {
        let Some(clinit): Option<&CodeItem> = self
            .code_items
            .iter()
            .find(|c: &&CodeItem| c.class == self.class && c.method_name == "<clinit>")
        else {
            return Ok(());
        };
        let regs: Vec<Value> = vec![Value::Int(0); usize::from(clinit.registers_size).max(1)];
        self.execute(clinit, regs)?;
        Ok(())
    }

    fn execute(
        &mut self,
        code: &CodeItem,
        mut regs: Vec<Value>,
    ) -> Result<Option<Value>, EvalError> {
        if self.depth > 8 {
            return Err(EvalError::BadShape);
        }
        self.depth += 1;
        let result: Result<Option<Value>, EvalError> = self.execute_body(code, &mut regs);
        self.depth -= 1;
        result
    }

    fn execute_body(
        &mut self,
        code: &CodeItem,
        regs: &mut [Value],
    ) -> Result<Option<Value>, EvalError> {
        let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
        let pc_to_index: BTreeMap<u32, usize> = insns
            .iter()
            .enumerate()
            .map(|(i, ins): (usize, &DalvikInsn)| (ins.pc, i))
            .collect();
        let mut result_reg: Value = Value::Null;
        let mut ip: usize = 0;

        while ip < insns.len() {
            self.steps += 1;
            if self.steps > STEP_LIMIT {
                return Err(EvalError::StepLimitExceeded);
            }
            let ins: &DalvikInsn = &insns[ip];
            match ins.op {
                0x00 => {}
                0x01 | 0x04 | 0x07 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    set_reg(regs, dst, read_reg(regs, src)?)?;
                }
                0x02 | 0x05 | 0x08 | 0x03 | 0x06 | 0x09 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    set_reg(regs, dst, read_reg(regs, src)?)?;
                }
                0x0A | 0x0C => {
                    let dst: u16 = one_reg(ins)?;
                    set_reg(regs, dst, result_reg)?;
                }
                0x0B => {
                    let dst: u16 = one_reg(ins)?;
                    set_reg(regs, dst, result_reg)?;
                }
                0x0E => return Ok(None),
                0x0F..=0x11 => {
                    let src: u16 = one_reg(ins)?;
                    return Ok(Some(read_reg(regs, src)?));
                }
                0x12..=0x15 => {
                    let dst: u16 = one_reg(ins)?;
                    let lit: i64 = ins.literal.ok_or(EvalError::BadShape)?;
                    let value: i64 = if ins.op == 0x15 { lit << 16 } else { lit };
                    set_reg(regs, dst, Value::Int(value))?;
                }
                0x1A | 0x1B => {
                    let dst: u16 = one_reg(ins)?;
                    let idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let s: &String = self
                        .dex
                        .strings
                        .get(idx as usize)
                        .ok_or(EvalError::BadIndex)?;
                    let units: Vec<u16> = s.encode_utf16().collect();
                    let r: usize = self.alloc(HeapObject::Text(units))?;
                    set_reg(regs, dst, Value::Ref(r))?;
                }
                0x1C => {
                    let dst: u16 = one_reg(ins)?;
                    let type_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let descriptor: &str = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .map(String::as_str)
                        .ok_or(EvalError::BadIndex)?;
                    let r: usize =
                        self.alloc(HeapObject::ClassObj(descriptor_to_binary_name(descriptor)))?;
                    set_reg(regs, dst, Value::Ref(r))?;
                }
                0x1F => {}
                0x21 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let r: usize = read_reg(regs, src)?.as_ref()?;
                    let len: usize = self.array_len(r)?;
                    set_reg(regs, dst, Value::Int(len as i64))?;
                }
                0x22 => {
                    let dst: u16 = one_reg(ins)?;
                    let type_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let descriptor: &str = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .map(String::as_str)
                        .ok_or(EvalError::BadIndex)?;
                    let obj: HeapObject = match descriptor {
                        "Ljava/lang/String;" => HeapObject::Text(Vec::new()),
                        "Ljava/util/Random;" => HeapObject::Random(None),
                        _ => HeapObject::Instance(descriptor_to_binary_name(descriptor)),
                    };
                    let obj_ref: usize = self.alloc(obj)?;
                    set_reg(regs, dst, Value::Ref(obj_ref))?;
                }
                0x23 => {
                    let (dst, size_reg): (u16, u16) = two_regs(ins)?;
                    let type_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let descriptor: &str = self
                        .dex
                        .type_names
                        .get(type_idx as usize)
                        .map(String::as_str)
                        .ok_or(EvalError::BadIndex)?;
                    let len_i: i64 = read_reg(regs, size_reg)?.as_int()?;
                    let len: usize = usize::try_from(len_i).map_err(|_| EvalError::BadShape)?;
                    if len > MAX_ARRAY_LEN {
                        return Err(EvalError::BadShape);
                    }
                    let obj: HeapObject = if descriptor == "[C" {
                        HeapObject::CharArray(vec![0u16; len])
                    } else if descriptor.starts_with("[L") || descriptor.starts_with("[[") {
                        HeapObject::StringArray(vec![None; len])
                    } else {
                        HeapObject::CharArray(vec![0u16; len])
                    };
                    let r: usize = self.alloc(obj)?;
                    set_reg(regs, dst, Value::Ref(r))?;
                }
                0x44..=0x4A => {
                    let (dst, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let arr_ref: usize = read_reg(regs, arr)?.as_ref()?;
                    let index: i64 = read_reg(regs, idx)?.as_int()?;
                    let value: Value = self.array_get(arr_ref, index)?;
                    set_reg(regs, dst, value)?;
                }
                0x4B..=0x51 => {
                    let (src, arr, idx): (u16, u16, u16) = three_regs(ins)?;
                    let arr_ref: usize = read_reg(regs, arr)?.as_ref()?;
                    let index: i64 = read_reg(regs, idx)?.as_int()?;
                    let value: Value = read_reg(regs, src)?;
                    self.array_put(arr_ref, index, value)?;
                }
                0x60..=0x66 => {
                    let dst: u16 = one_reg(ins)?;
                    let field_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let value: Value = self.get_static(field_idx)?;
                    set_reg(regs, dst, value)?;
                }
                0x67..=0x6D => {
                    let src: u16 = one_reg(ins)?;
                    let field_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    let value: Value = read_reg(regs, src)?;
                    self.put_static(field_idx, value)?;
                }
                0x6E..=0x72 => {
                    let method_idx: u32 = ins.index.ok_or(EvalError::BadShape)?;
                    result_reg = self
                        .invoke(method_idx, &ins.regs, regs)?
                        .unwrap_or(Value::Null);
                }
                0x28..=0x2A => {
                    let target: u32 = ins.branch_target_pc().ok_or(EvalError::BadShape)?;
                    ip = *pc_to_index.get(&target).ok_or(EvalError::BadShape)?;
                    continue;
                }
                0x32..=0x37 => {
                    let (a, b): (u16, u16) = two_regs(ins)?;
                    let lhs: i64 = read_reg(regs, a)?.as_int()?;
                    let rhs: i64 = read_reg(regs, b)?.as_int()?;
                    if cmp_branch(ins.op, lhs, rhs) {
                        let target: u32 = ins.branch_target_pc().ok_or(EvalError::BadShape)?;
                        ip = *pc_to_index.get(&target).ok_or(EvalError::BadShape)?;
                        continue;
                    }
                }
                0x38..=0x3D => {
                    let a: u16 = one_reg(ins)?;
                    let lhs: i64 = read_reg(regs, a)?.as_int()?;
                    if cmp_branch_zero(ins.op, lhs) {
                        let target: u32 = ins.branch_target_pc().ok_or(EvalError::BadShape)?;
                        ip = *pc_to_index.get(&target).ok_or(EvalError::BadShape)?;
                        continue;
                    }
                }
                0x7B => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    set_reg(
                        regs,
                        dst,
                        Value::Int(read_reg(regs, src)?.as_int()?.wrapping_neg()),
                    )?;
                }
                0x90..=0x9A => {
                    let (dst, a, b): (u16, u16, u16) = three_regs(ins)?;
                    let lhs: i64 = read_reg(regs, a)?.as_int()?;
                    let rhs: i64 = read_reg(regs, b)?.as_int()?;
                    set_reg(regs, dst, Value::Int(int_binop(ins.op, lhs, rhs)))?;
                }
                0xB0..=0xBA => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lhs: i64 = read_reg(regs, dst)?.as_int()?;
                    let rhs: i64 = read_reg(regs, src)?.as_int()?;
                    set_reg(regs, dst, Value::Int(int_binop_2addr(ins.op, lhs, rhs)))?;
                }
                0xD0..=0xD7 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lit: i64 = ins.literal.ok_or(EvalError::BadShape)?;
                    let lhs: i64 = read_reg(regs, src)?.as_int()?;
                    set_reg(regs, dst, Value::Int(lit_binop(ins.op, lhs, lit)))?;
                }
                0xD8..=0xE2 => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let lit: i64 = ins.literal.ok_or(EvalError::BadShape)?;
                    let lhs: i64 = read_reg(regs, src)?.as_int()?;
                    set_reg(regs, dst, Value::Int(lit_binop(ins.op, lhs, lit)))?;
                }
                0x8D..=0x8F => {
                    let (dst, src): (u16, u16) = two_regs(ins)?;
                    let v: i64 = read_reg(regs, src)?.as_int()?;
                    let masked: i64 = match ins.op {
                        0x8D => i64::from(v as i8),
                        0x8E => i64::from(v as u16),
                        _ => i64::from(v as i16),
                    };
                    set_reg(regs, dst, Value::Int(masked))?;
                }
                other => return Err(EvalError::UnsupportedOpcode(other)),
            }
            ip += 1;
        }
        let _ = result_reg;
        Err(EvalError::NoReturn)
    }

    fn invoke(
        &mut self,
        method_idx: u32,
        arg_regs: &[u16],
        regs: &[Value],
    ) -> Result<Option<Value>, EvalError> {
        let method: &MethodId = self
            .dex
            .method_ids
            .get(method_idx as usize)
            .ok_or(EvalError::BadIndex)?;
        let owner: String = method.class.clone();
        let name: String = method.name.clone();
        let descriptor: String = method_descriptor(method);
        let native_key_id: String = native_key_id(&owner, &name, &descriptor);
        if let Some(native_key) = self.native_keys.get(&native_key_id) {
            return Ok(Some(Value::Int(native_key.value)));
        }

        match (owner.as_str(), name.as_str()) {
            ("Ljava/lang/String;", "toCharArray") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let units: Vec<u16> = self.text_units(recv)?;
                let r: usize = self.alloc(HeapObject::CharArray(units))?;
                Ok(Some(Value::Ref(r)))
            }
            ("Ljava/lang/String;", "valueOf") => {
                let arr: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let units: Vec<u16> = self.char_units(arr)?;
                let r: usize = self.alloc(HeapObject::Text(units))?;
                Ok(Some(Value::Ref(r)))
            }
            ("Ljava/lang/String;", "intern") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                Ok(Some(Value::Ref(recv)))
            }
            ("Ljava/lang/String;", "<init>") => {
                let recv: u16 = *arg_regs.first().ok_or(EvalError::BadShape)?;
                if let Some(arr_reg) = arg_regs.get(1) {
                    let arr: usize = read_reg(regs, *arr_reg)?.as_ref()?;
                    let units: Vec<u16> = self.char_units(arr)?;
                    let target: usize = read_reg(regs, recv)?.as_ref()?;
                    if let Some(slot) = self.heap.get_mut(target) {
                        *slot = HeapObject::Text(units);
                    }
                }
                Ok(None)
            }
            ("Ljava/util/Random;", "<init>") if method.proto.parameters == ["J"] => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let seed: i64 =
                    read_reg(regs, *arg_regs.get(1).ok_or(EvalError::BadShape)?)?.as_int()?;
                set_random_seed(&mut self.heap, recv, seed)?;
                Ok(None)
            }
            ("Ljava/util/Random;", "<init>") if method.proto.parameters.is_empty() => {
                read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                Ok(None)
            }
            ("Ljava/util/Random;", "setSeed") if method.proto.parameters == ["J"] => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let seed: i64 =
                    read_reg(regs, *arg_regs.get(1).ok_or(EvalError::BadShape)?)?.as_int()?;
                set_random_seed(&mut self.heap, recv, seed)?;
                Ok(None)
            }
            ("Ljava/util/Random;", "nextInt") if method.proto.parameters.is_empty() => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                Ok(Some(Value::Int(i64::from(random_next_int(
                    &mut self.heap,
                    recv,
                )?))))
            }
            ("Ljava/util/Random;", "nextInt") if method.proto.parameters == ["I"] => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let bound_raw: i64 =
                    read_reg(regs, *arg_regs.get(1).ok_or(EvalError::BadShape)?)?.as_int()?;
                let bound: i32 = i32::try_from(bound_raw).map_err(|_| EvalError::BadShape)?;
                Ok(Some(Value::Int(i64::from(random_next_bounded_int(
                    &mut self.heap,
                    recv,
                    bound,
                )?))))
            }
            ("Ljava/lang/Object;", "getClass") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let internal: String = self.runtime_class_of(recv)?;
                let r: usize = self.alloc(HeapObject::ClassObj(internal))?;
                Ok(Some(Value::Ref(r)))
            }
            ("Ljava/lang/Class;", "forName") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let dotted: String = String::from_utf16_lossy(&self.text_units(recv)?);
                let r: usize = self.alloc(HeapObject::ClassObj(dotted))?;
                Ok(Some(Value::Ref(r)))
            }
            ("Ljava/lang/Class;", "getName" | "getCanonicalName" | "getTypeName") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let units: Vec<u16> = self.class_name_units(recv, false)?;
                let r: usize = self.alloc(HeapObject::Text(units))?;
                Ok(Some(Value::Ref(r)))
            }
            ("Ljava/lang/Class;", "getSimpleName") => {
                let recv: usize =
                    read_reg(regs, *arg_regs.first().ok_or(EvalError::BadShape)?)?.as_ref()?;
                let units: Vec<u16> = self.class_name_units(recv, true)?;
                let r: usize = self.alloc(HeapObject::Text(units))?;
                Ok(Some(Value::Ref(r)))
            }
            _ if is_runtime_key(&owner, &name) => Err(EvalError::RuntimeKeyUnavailable),
            _ if owner == self.class => {
                let target: Option<&CodeItem> = self
                    .code_items
                    .iter()
                    .find(|c: &&CodeItem| c.class == owner && c.method_name == name);
                let Some(target_code): Option<&CodeItem> = target else {
                    if method.proto.return_type == "I" || method.proto.return_type == "J" {
                        return Err(EvalError::RuntimeKeyUnavailable);
                    }
                    return Err(EvalError::UnknownCall(format!("{owner}.{name}")));
                };
                let mut callee_regs: Vec<Value> = vec![
                    Value::Int(0);
                    usize::from(target_code.registers_size)
                        .max(arg_regs.len())
                ];
                let in_count: usize = usize::from(target_code.ins_size);
                let base: usize = callee_regs.len().saturating_sub(in_count);
                for (i, arg_reg) in arg_regs.iter().take(in_count).enumerate() {
                    callee_regs[base + i] = read_reg(regs, *arg_reg)?;
                }
                self.execute(target_code, callee_regs)
            }
            _ => Ok(Some(Value::Null)),
        }
    }

    fn get_static(&self, field_idx: u32) -> Result<Value, EvalError> {
        let key: String = self.field_key(field_idx).ok_or(EvalError::BadIndex)?;
        if let Some(v) = self.statics.get(&key) {
            return Ok(*v);
        }
        let field: &FieldId = self
            .dex
            .field_ids
            .get(field_idx as usize)
            .ok_or(EvalError::BadIndex)?;
        if field.class == self.class {
            return Ok(Value::Null);
        }
        Err(EvalError::RuntimeKeyUnavailable)
    }

    fn put_static(&mut self, field_idx: u32, value: Value) -> Result<(), EvalError> {
        let key: String = self.field_key(field_idx).ok_or(EvalError::BadIndex)?;
        self.statics.insert(key, value);
        Ok(())
    }

    fn array_len(&self, r: usize) -> Result<usize, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::CharArray(v)) => Ok(v.len()),
            Some(HeapObject::StringArray(v)) => Ok(v.len()),
            _ => Err(EvalError::BadShape),
        }
    }

    fn array_get(&self, r: usize, index: i64) -> Result<Value, EvalError> {
        let i: usize = usize::try_from(index).map_err(|_| EvalError::BadIndex)?;
        match self.heap.get(r) {
            Some(HeapObject::CharArray(v)) => v
                .get(i)
                .map(|u: &u16| Value::Int(i64::from(*u)))
                .ok_or(EvalError::BadIndex),
            Some(HeapObject::StringArray(v)) => match v.get(i) {
                Some(Some(slot)) => Ok(Value::Ref(*slot)),
                Some(None) => Ok(Value::Null),
                None => Err(EvalError::BadIndex),
            },
            _ => Err(EvalError::BadShape),
        }
    }

    fn array_put(&mut self, r: usize, index: i64, value: Value) -> Result<(), EvalError> {
        let i: usize = usize::try_from(index).map_err(|_| EvalError::BadIndex)?;
        match self.heap.get_mut(r) {
            Some(HeapObject::CharArray(v)) if i < v.len() => {
                v[i] = (value.as_int()? & 0xFFFF) as u16;
                Ok(())
            }
            Some(HeapObject::StringArray(v)) if i < v.len() => {
                v[i] = match value {
                    Value::Ref(slot) => Some(slot),
                    Value::Null => None,
                    Value::Int(_) => return Err(EvalError::BadShape),
                };
                Ok(())
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn text_units(&self, r: usize) -> Result<Vec<u16>, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::Text(v)) => Ok(v.clone()),
            _ => Err(EvalError::BadShape),
        }
    }

    fn char_units(&self, r: usize) -> Result<Vec<u16>, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::CharArray(v)) => Ok(v.clone()),
            _ => Err(EvalError::BadShape),
        }
    }

    fn runtime_class_of(&self, r: usize) -> Result<String, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::ClassObj(_)) => Ok("java.lang.Class".to_owned()),
            Some(HeapObject::Text(_)) => Ok("java.lang.String".to_owned()),
            Some(HeapObject::Instance(name)) => Ok(name.clone()),
            Some(HeapObject::Random(_)) => Ok("java.util.Random".to_owned()),
            _ => Err(EvalError::BadShape),
        }
    }

    fn class_name_units(&self, r: usize, simple: bool) -> Result<Vec<u16>, EvalError> {
        match self.heap.get(r) {
            Some(HeapObject::ClassObj(name)) => {
                let chosen: &str = if simple {
                    name.rsplit('.').next().unwrap_or(name.as_str())
                } else {
                    name.as_str()
                };
                Ok(chosen.encode_utf16().collect())
            }
            _ => Err(EvalError::BadShape),
        }
    }

    fn read_text(&self, value: Value) -> Result<String, EvalError> {
        let r: usize = value.as_ref()?;
        match self.heap.get(r) {
            Some(HeapObject::Text(v) | HeapObject::CharArray(v)) => Ok(String::from_utf16_lossy(v)),
            _ => Err(EvalError::BadShape),
        }
    }

    fn static_string_array(&self, field: &FieldId) -> Option<Vec<Option<usize>>> {
        let key: String = format!("{}.{}:{}", field.class, field.name, field.type_name);
        match self.statics.get(&key) {
            Some(Value::Ref(r)) => match self.heap.get(*r) {
                Some(HeapObject::StringArray(v)) => Some(v.clone()),
                _ => None,
            },
            _ => None,
        }
    }
}

fn descriptor_to_binary_name(descriptor: &str) -> String {
    if let Some(inner) = descriptor.strip_prefix('L')
        && let Some(internal) = inner.strip_suffix(';')
    {
        return internal.replace('/', ".");
    }
    descriptor.replace('/', ".")
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

fn is_runtime_key(owner: &str, name: &str) -> bool {
    matches!(
        (owner, name),
        (
            "Ljava/lang/System;",
            "getProperty" | "getenv" | "currentTimeMillis" | "nanoTime"
        ) | (
            "Ljava/lang/Runtime;" | "Ljava/security/SecureRandom;" | "Ljava/util/Random;",
            _
        )
    )
}

fn one_reg(ins: &DalvikInsn) -> Result<u16, EvalError> {
    ins.regs.first().copied().ok_or(EvalError::BadRegister)
}

fn two_regs(ins: &DalvikInsn) -> Result<(u16, u16), EvalError> {
    match (ins.regs.first(), ins.regs.get(1)) {
        (Some(a), Some(b)) => Ok((*a, *b)),
        _ => Err(EvalError::BadRegister),
    }
}

fn three_regs(ins: &DalvikInsn) -> Result<(u16, u16, u16), EvalError> {
    match (ins.regs.first(), ins.regs.get(1), ins.regs.get(2)) {
        (Some(a), Some(b), Some(c)) => Ok((*a, *b, *c)),
        _ => Err(EvalError::BadRegister),
    }
}

fn read_reg(regs: &[Value], r: u16) -> Result<Value, EvalError> {
    regs.get(usize::from(r))
        .copied()
        .ok_or(EvalError::BadRegister)
}

fn set_reg(regs: &mut [Value], r: u16, value: Value) -> Result<(), EvalError> {
    let slot: &mut Value = regs.get_mut(usize::from(r)).ok_or(EvalError::BadRegister)?;
    *slot = value;
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

fn int_binop(op: u8, a: i64, b: i64) -> i64 {
    let r: i32 = match op {
        0x90 => (a as i32).wrapping_add(b as i32),
        0x91 => (a as i32).wrapping_sub(b as i32),
        0x92 => (a as i32).wrapping_mul(b as i32),
        0x93 => {
            if b == 0 {
                0
            } else {
                (a as i32).wrapping_div(b as i32)
            }
        }
        0x94 => {
            if b == 0 {
                0
            } else {
                (a as i32).wrapping_rem(b as i32)
            }
        }
        0x95 => (a as i32) & (b as i32),
        0x96 => (a as i32) | (b as i32),
        0x97 => (a as i32) ^ (b as i32),
        0x98 => (a as i32).wrapping_shl((b as u32) & 31),
        0x99 => (a as i32).wrapping_shr((b as u32) & 31),
        0x9A => ((a as i32 as u32) >> ((b as u32) & 31)) as i32,
        _ => 0,
    };
    i64::from(r)
}

fn int_binop_2addr(op: u8, a: i64, b: i64) -> i64 {
    int_binop(op.wrapping_sub(0xB0).wrapping_add(0x90), a, b)
}

fn lit_binop(op: u8, a: i64, lit: i64) -> i64 {
    let r: i32 = match op {
        0xD0 | 0xD8 => (a as i32).wrapping_add(lit as i32),
        0xD1 | 0xD9 => (lit as i32).wrapping_sub(a as i32),
        0xD2 | 0xDA => (a as i32).wrapping_mul(lit as i32),
        0xD3 | 0xDB => {
            if lit == 0 {
                0
            } else {
                (a as i32).wrapping_div(lit as i32)
            }
        }
        0xD4 | 0xDC => {
            if lit == 0 {
                0
            } else {
                (a as i32).wrapping_rem(lit as i32)
            }
        }
        0xD5 | 0xDD => (a as i32) & (lit as i32),
        0xD6 | 0xDE => (a as i32) | (lit as i32),
        0xD7 | 0xDF => (a as i32) ^ (lit as i32),
        0xE0 => (a as i32).wrapping_shl((lit as u32) & 31),
        0xE1 => (a as i32).wrapping_shr((lit as u32) & 31),
        0xE2 => ((a as i32 as u32) >> ((lit as u32) & 31)) as i32,
        _ => 0,
    };
    i64::from(r)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptedString {
    pub table_index: usize,
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectiveCallSite {
    pub caller_class: String,
    pub caller_method: String,
    pub resolved_member: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexStringRecovery {
    pub class: String,
    pub decrypt_method: String,
    pub table_size: usize,
    pub recovered: Vec<DecryptedString>,
    pub reflective_call_sites: Vec<ReflectiveCallSite>,
    pub runtime_key_wall: bool,
    pub runtime_key_wall_reason: Option<String>,
    pub notes: Vec<String>,
}

#[must_use]
pub fn recover(dex: &DexFile, dex_bytes: &[u8]) -> Vec<DexStringRecovery> {
    recover_with_native_keys(dex, dex_bytes, &[])
}

#[must_use]
pub fn recover_with_native_keys(
    dex: &DexFile,
    dex_bytes: &[u8],
    native_keys: &[NativeIntKey],
) -> Vec<DexStringRecovery> {
    let code_items: Vec<CodeItem> = crate::dex::parse_code_items(dex, dex_bytes);
    let mut out: Vec<DexStringRecovery> = Vec::new();
    let key_map: BTreeMap<String, NativeIntKey> = native_keys
        .iter()
        .map(|key: &NativeIntKey| {
            (
                native_key_id(&key.class, &key.method, &key.descriptor),
                key.clone(),
            )
        })
        .collect();

    let mut classes: Vec<String> = code_items
        .iter()
        .map(|c: &CodeItem| c.class.clone())
        .collect();
    classes.sort();
    classes.dedup();

    for class in &classes {
        if let Some(report) = recover_class(dex, &code_items, class, &key_map) {
            out.push(report);
        }
    }
    out
}

fn recover_class(
    dex: &DexFile,
    code_items: &[CodeItem],
    class: &str,
    native_keys: &BTreeMap<String, NativeIntKey>,
) -> Option<DexStringRecovery> {
    let enc_field: FieldId = find_string_array_field(dex, class)?;
    let decrypt: &CodeItem = code_items
        .iter()
        .find(|c: &&CodeItem| is_table_decryptor(dex, c, class, &enc_field))?;

    let mut interp: Interp<'_> = Interp::new(dex, class, code_items, native_keys);
    if interp.run_clinit().is_err() {
        return None;
    }
    let table: Vec<Option<usize>> = interp.static_string_array(&enc_field)?;
    if table.is_empty() {
        return None;
    }

    let mut report: DexStringRecovery = DexStringRecovery {
        class: class.to_owned(),
        decrypt_method: decrypt.method_name.clone(),
        table_size: table.len(),
        ..Default::default()
    };
    let native_sites: Vec<NativeIntKey> = collect_native_key_sites(dex, decrypt, native_keys);

    for index in 0..table.len() {
        let mut regs: Vec<Value> = vec![Value::Int(0); usize::from(decrypt.registers_size).max(1)];
        let in_count: usize = usize::from(decrypt.ins_size).max(1);
        let base: usize = regs.len().saturating_sub(in_count);
        if base < regs.len() {
            regs[base] = Value::Int(index as i64);
        }
        match interp.execute(decrypt, regs) {
            Ok(Some(value)) => {
                if let Ok(plain) = interp.read_text(value)
                    && is_plausible_plaintext(&plain)
                {
                    report.recovered.push(DecryptedString {
                        table_index: index,
                        plaintext: plain,
                    });
                }
            }
            Err(EvalError::RuntimeKeyUnavailable) => {
                report.runtime_key_wall = true;
                report.runtime_key_wall_reason = Some(runtime_key_reason(&native_sites));
            }
            _ => {}
        }
    }
    if !native_sites.is_empty() && !report.recovered.is_empty() {
        let sources: Vec<String> = native_sites
            .iter()
            .map(|key: &NativeIntKey| format!("{}:{}", key.source_library, key.symbol))
            .collect();
        report.notes.push(format!(
            "resolved {} native integer key site(s) from exported JNI stub(s): {}",
            sources.len(),
            sources.join(", ")
        ));
    }

    report.reflective_call_sites = collect_reflective_sites(dex, code_items, class, decrypt);

    crate::debug::dbg_kv("dex-strdec", || {
        format!(
            "{class}->{} table_size={} recovered={} reflective_sites={} runtime_key_wall={}",
            report.decrypt_method,
            report.table_size,
            report.recovered.len(),
            report.reflective_call_sites.len(),
            report.runtime_key_wall
        )
    });

    if report.recovered.is_empty() && !report.runtime_key_wall {
        return None;
    }

    Some(report)
}

#[must_use]
pub fn native_key_id(class: &str, method: &str, descriptor: &str) -> String {
    format!("{class}->{method}{descriptor}")
}

fn method_descriptor(method: &MethodId) -> String {
    let params: String = method.proto.parameters.concat();
    format!("({params}){}", method.proto.return_type)
}

fn collect_native_key_sites(
    dex: &DexFile,
    code: &CodeItem,
    native_keys: &BTreeMap<String, NativeIntKey>,
) -> Vec<NativeIntKey> {
    let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
    let mut out: Vec<NativeIntKey> = Vec::new();
    for ins in &insns {
        if matches!(ins.op, 0x6E..=0x72 | 0x74..=0x78)
            && let Some(method) = ins.index.and_then(|i: u32| dex.method_ids.get(i as usize))
        {
            let descriptor: String = method_descriptor(method);
            let key: String = native_key_id(&method.class, &method.name, &descriptor);
            if let Some(native_key) = native_keys.get(&key) {
                out.push(native_key.clone());
            }
        }
    }
    out.sort_by(|a: &NativeIntKey, b: &NativeIntKey| {
        (&a.class, &a.method, &a.descriptor).cmp(&(&b.class, &b.method, &b.descriptor))
    });
    out.dedup_by(|a: &mut NativeIntKey, b: &mut NativeIntKey| {
        a.class == b.class && a.method == b.method && a.descriptor == b.descriptor
    });
    out
}

fn runtime_key_reason(native_sites: &[NativeIntKey]) -> String {
    if native_sites.is_empty() {
        return "the decrypt routine derives its key from runtime-only state (system property, environment, clock, secure random, or unresolved native code) that is not present in the static dex; the encrypted table stays opaque".to_owned();
    }
    let refs: Vec<String> = native_sites
        .iter()
        .map(|key: &NativeIntKey| format!("{}:{}", key.source_library, key.symbol))
        .collect();
    format!(
        "the decrypt routine depends on native integer key site(s) that are not statically resolved here: {}",
        refs.join(", ")
    )
}

fn find_string_array_field(dex: &DexFile, class: &str) -> Option<FieldId> {
    dex.field_ids
        .iter()
        .find(|f: &&FieldId| f.class == class && f.type_name == "[Ljava/lang/String;")
        .cloned()
}

fn is_table_decryptor(dex: &DexFile, code: &CodeItem, class: &str, enc_field: &FieldId) -> bool {
    if code.class != class
        || code.method_name == "<clinit>"
        || !code.method_descriptor.ends_with(")Ljava/lang/String;")
    {
        return false;
    }
    let takes_single_int: bool = code.method_descriptor.starts_with("(I)")
        || code.method_descriptor.starts_with("(Ljava/lang/String;)");
    if !takes_single_int {
        return false;
    }
    let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
    let mut reads_enc: bool = false;
    let mut indexes_array: bool = false;
    let mut uses_reflection: bool = false;
    for ins in &insns {
        match ins.op {
            0x60..=0x66 => {
                if let Some(field) = ins.index.and_then(|i: u32| dex.field_ids.get(i as usize))
                    && field.class == enc_field.class
                    && field.name == enc_field.name
                {
                    reads_enc = true;
                }
            }
            0x44..=0x4A => indexes_array = true,
            0x6E..=0x72 | 0x74..=0x78 => {
                if let Some(method) = ins.index.and_then(|i: u32| dex.method_ids.get(i as usize))
                    && ((method.class == "Ljava/lang/Class;"
                        && (method.name == "getDeclaredMethod" || method.name == "getMethod"))
                        || (method.class == "Ljava/lang/reflect/Method;"
                            && method.name == "invoke"))
                {
                    uses_reflection = true;
                }
            }
            _ => {}
        }
    }
    reads_enc && indexes_array && !uses_reflection
}

fn collect_reflective_sites(
    dex: &DexFile,
    code_items: &[CodeItem],
    class: &str,
    decrypt: &CodeItem,
) -> Vec<ReflectiveCallSite> {
    let mut sites: Vec<ReflectiveCallSite> = Vec::new();
    for code in code_items {
        let insns: Vec<DalvikInsn> = dalvik::decode_method(&code.insns);
        let mut pending_member: Option<String> = None;
        let mut saw_get_declared: bool = false;
        let mut saw_invoke: bool = false;
        for ins in &insns {
            match ins.op {
                0x1A | 0x1B => {
                    if let Some(idx) = ins.index {
                        pending_member = dex.strings.get(idx as usize).cloned();
                    }
                }
                0x6E | 0x70 | 0x71 | 0x72 | 0x6F | 0x74..=0x78 => {
                    if let Some(method) =
                        ins.index.and_then(|i: u32| dex.method_ids.get(i as usize))
                    {
                        if method.class == "Ljava/lang/Class;"
                            && (method.name == "getDeclaredMethod" || method.name == "getMethod")
                        {
                            saw_get_declared = true;
                        }
                        if method.class == "Ljava/lang/reflect/Method;" && method.name == "invoke" {
                            saw_invoke = true;
                        }
                    }
                }
                _ => {}
            }
        }
        if saw_get_declared
            && saw_invoke
            && let Some(member) = pending_member
        {
            let resolved: String = if member == decrypt.method_name {
                format!("{class}.{}", decrypt.method_name)
            } else {
                member
            };
            sites.push(ReflectiveCallSite {
                caller_class: code.class.clone(),
                caller_method: code.method_name.clone(),
                resolved_member: resolved,
            });
        }
    }
    sites
}

#[must_use]
pub fn is_plausible_plaintext(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || c.is_whitespace() || (*c as u32) >= 0xA0)
        .count();
    printable * 100 >= s.chars().count() * 85
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex_builder::{
        dexguard_name_keyed_sample, dexguard_native_key_sample, dexguard_reflect_sample,
        dexguard_seeded_random_sample,
    };

    #[test]
    fn dalvik_random_state_matches_jdk_oracle() {
        let mut state: JavaRandomState = JavaRandomState::from_user_seed(1337);
        assert_eq!(state.next_bounded_int(127), Ok(120));
    }

    #[test]
    fn recovers_class_name_keyed_static_table() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "pbkdf2-sha256-310000",
        ];
        let dex: Vec<u8> = dexguard_name_keyed_sample(&plaintexts);
        let parsed: DexFile = crate::dex::parse(&dex).expect("name-keyed dex parses");
        let reports: Vec<DexStringRecovery> = recover(&parsed, &dex);
        assert_eq!(
            reports.len(),
            1,
            "the class-name-seeded table decryptor must be recognised and run"
        );
        let report: &DexStringRecovery = &reports[0];
        let recovered: Vec<String> = report
            .recovered
            .iter()
            .map(|d: &DecryptedString| d.plaintext.clone())
            .collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|r: &String| r == expected),
                "the key is derived from the class's own name via const-class + getName(), which is \
                 static; must recover {expected:?} from {recovered:?}"
            );
        }
        assert!(
            !report.runtime_key_wall,
            "a class-name-derived key is fully static; this must not wall as runtime-keyed"
        );
    }

    #[test]
    fn recovers_authored_plaintext_from_built_dex() {
        let plaintexts: [&str; 4] = [
            "https://api.example.com/v1/auth",
            "X-Api-Key",
            "decryptToken",
            "AES/CBC/PKCS5Padding",
        ];
        let dex: Vec<u8> = dexguard_reflect_sample(&plaintexts, 0x66);
        let parsed: DexFile = crate::dex::parse(&dex).expect("parse");
        let reports: Vec<DexStringRecovery> = recover(&parsed, &dex);
        assert_eq!(reports.len(), 1);
        let report: &DexStringRecovery = &reports[0];
        assert_eq!(report.table_size, plaintexts.len());
        let recovered: Vec<String> = report
            .recovered
            .iter()
            .map(|d: &DecryptedString| d.plaintext.clone())
            .collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|r: &String| r == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
        assert!(!report.reflective_call_sites.is_empty());
    }

    #[test]
    fn recovers_seeded_random_static_table() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "AES/CBC/PKCS5Padding",
        ];
        let dex: Vec<u8> = dexguard_seeded_random_sample(&plaintexts);
        let parsed: DexFile = crate::dex::parse(&dex).expect("seeded random dex parses");
        let reports: Vec<DexStringRecovery> = recover(&parsed, &dex);
        assert_eq!(reports.len(), 1);
        let report: &DexStringRecovery = &reports[0];
        assert_eq!(report.table_size, plaintexts.len());
        assert!(!report.runtime_key_wall);
        let recovered: Vec<String> = report
            .recovered
            .iter()
            .map(|d: &DecryptedString| d.plaintext.clone())
            .collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|r: &String| r == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
    }

    #[test]
    fn recovers_native_keyed_static_table_when_key_is_supplied() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "AES/CBC/PKCS5Padding",
        ];
        let dex: Vec<u8> = dexguard_native_key_sample(&plaintexts, 0x4D);
        let parsed: DexFile = crate::dex::parse(&dex).expect("native-key dex parses");
        let reports_without: Vec<DexStringRecovery> = recover(&parsed, &dex);
        assert_eq!(reports_without.len(), 1);
        assert!(reports_without[0].runtime_key_wall);
        let key: NativeIntKey = NativeIntKey {
            class: "Lcom/disrobe/sample/DexGuardNativeKey;".to_owned(),
            method: "nativeKey".to_owned(),
            descriptor: "()I".to_owned(),
            value: 0x4D,
            source_library: "lib/arm64-v8a/libdgkeys.so".to_owned(),
            symbol: "Java_com_disrobe_sample_DexGuardNativeKey_nativeKey".to_owned(),
        };
        let reports: Vec<DexStringRecovery> = recover_with_native_keys(&parsed, &dex, &[key]);
        assert_eq!(reports.len(), 1);
        let report: &DexStringRecovery = &reports[0];
        assert_eq!(report.table_size, plaintexts.len());
        assert!(!report.runtime_key_wall);
        assert!(
            report
                .notes
                .iter()
                .any(|note: &String| note.contains("native integer key"))
        );
        let recovered: Vec<String> = report
            .recovered
            .iter()
            .map(|d: &DecryptedString| d.plaintext.clone())
            .collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|r: &String| r == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
    }

    #[test]
    fn alloc_caps_heap_object_count() {
        let dex: Vec<u8> = dexguard_reflect_sample(&["seed"], 0x11);
        let parsed: DexFile = crate::dex::parse(&dex).expect("parse");
        let code_items: Vec<CodeItem> = Vec::new();
        let native_keys: BTreeMap<String, NativeIntKey> = BTreeMap::new();
        let mut interp: Interp<'_> = Interp::new(&parsed, "Lx;", &code_items, &native_keys);
        for _ in 0..MAX_HEAP_OBJECTS {
            interp
                .alloc(HeapObject::CharArray(Vec::new()))
                .expect("allocations below the cap must succeed");
        }
        assert_eq!(
            interp.alloc(HeapObject::CharArray(Vec::new())),
            Err(EvalError::HeapExhausted),
            "allocating past the cap must fail rather than grow the heap unbounded"
        );
    }
}
