use crate::bytecode::{self, Instruction, Operands};
use crate::classfile::ClassFile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulationError {
    UnsupportedOpcode(u8),
    StackUnderflow,
    BadLocal(u16),
    StepLimitExceeded,
    NoReturn,
    BadShape,
}

const STEP_LIMIT: u64 = 2_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Int(i32),
    ArrayRef(usize),
}

impl Value {
    const fn as_int(self) -> Result<i32, EmulationError> {
        match self {
            Self::Int(v) => Ok(v),
            Self::ArrayRef(_) => Err(EmulationError::BadShape),
        }
    }

    const fn as_ref(self) -> Result<usize, EmulationError> {
        match self {
            Self::ArrayRef(r) => Ok(r),
            Self::Int(_) => Err(EmulationError::BadShape),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptStub {
    code: Vec<u8>,
    max_locals: u16,
}

#[must_use]
pub fn find_char_array_decrypt(cf: &ClassFile) -> Option<DecryptStub> {
    for method in &cf.methods {
        let desc: &str = cf.utf8_at(method.descriptor_index).ok()?;
        if desc != "([C)[C" && desc != "([C)Ljava/lang/String;" {
            continue;
        }
        for attr in &method.attributes {
            if cf.utf8_at(attr.name_index).ok()? == "Code"
                && let Ok(code) = bytecode::parse_code_attribute(&attr.info)
            {
                return Some(DecryptStub {
                    code: code.code,
                    max_locals: code.max_locals,
                });
            }
        }
    }
    None
}

pub fn emulate_char_array(stub: &DecryptStub, input: &[u16]) -> Result<Vec<u16>, EmulationError> {
    let insns: Vec<Instruction> =
        bytecode::disassemble(&stub.code).map_err(|_| EmulationError::BadShape)?;
    let pc_index: Vec<u32> = insns.iter().map(|i| i.pc).collect();
    let mut heap: Vec<Vec<u16>> = Vec::with_capacity(4);
    heap.push(input.to_vec());
    let mut locals: Vec<Value> = vec![Value::Int(0); usize::from(stub.max_locals).max(1)];
    locals[0] = Value::ArrayRef(0);
    let mut stack: Vec<Value> = Vec::with_capacity(16);
    let mut ip: usize = 0;
    let mut steps: u64 = 0;

    while ip < insns.len() {
        steps += 1;
        if steps > STEP_LIMIT {
            return Err(EmulationError::StepLimitExceeded);
        }
        let insn: &Instruction = &insns[ip];
        let op: u8 = insn.opcode;
        match op {
            0x02 => stack.push(Value::Int(-1)),
            0x03..=0x08 => stack.push(Value::Int(i32::from(op) - 3)),
            0x10 | 0x11 => match &insn.operands {
                Operands::Byte(v) | Operands::Short(v) => stack.push(Value::Int(*v)),
                _ => return Err(EmulationError::BadShape),
            },
            0x15 | 0x19 | 0x1A..=0x2D => {
                let idx: usize = local_index(insn, op)?;
                let v: Value = *locals
                    .get(idx)
                    .ok_or(EmulationError::BadLocal(idx as u16))?;
                stack.push(v);
            }
            0x36 | 0x3A | 0x3B..=0x4E => {
                let idx: usize = store_index(insn, op)?;
                let v: Value = stack.pop().ok_or(EmulationError::StackUnderflow)?;
                ensure_local(&mut locals, idx);
                locals[idx] = v;
            }
            0x34 => {
                let index: i32 = pop_int(&mut stack)?;
                let arr_ref: usize = pop_ref(&mut stack)?;
                let arr: &Vec<u16> = heap.get(arr_ref).ok_or(EmulationError::BadShape)?;
                let ch: u16 = usize::try_from(index)
                    .ok()
                    .and_then(|i| arr.get(i).copied())
                    .ok_or(EmulationError::BadShape)?;
                stack.push(Value::Int(i32::from(ch)));
            }
            0x55 => {
                let value: i32 = pop_int(&mut stack)?;
                let index: i32 = pop_int(&mut stack)?;
                let arr_ref: usize = pop_ref(&mut stack)?;
                let arr: &mut Vec<u16> = heap.get_mut(arr_ref).ok_or(EmulationError::BadShape)?;
                let i: usize = usize::try_from(index).map_err(|_| EmulationError::BadShape)?;
                if i >= arr.len() {
                    return Err(EmulationError::BadShape);
                }
                arr[i] = (value & 0xFFFF) as u16;
            }
            0x59 => {
                let top: Value = *stack.last().ok_or(EmulationError::StackUnderflow)?;
                stack.push(top);
            }
            0x5A => {
                let len: usize = stack.len();
                if len < 2 {
                    return Err(EmulationError::StackUnderflow);
                }
                let top: Value = stack[len - 1];
                stack.insert(len - 2, top);
            }
            0x60 => binary(&mut stack, i32::wrapping_add)?,
            0x64 => binary(&mut stack, i32::wrapping_sub)?,
            0x68 => binary(&mut stack, i32::wrapping_mul)?,
            0x6C => binary(
                &mut stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_div(b) },
            )?,
            0x70 => binary(
                &mut stack,
                |a, b| if b == 0 { 0 } else { a.wrapping_rem(b) },
            )?,
            0x78 => binary(&mut stack, |a, b| a.wrapping_shl(b as u32 & 31))?,
            0x7A => binary(&mut stack, |a, b| a.wrapping_shr(b as u32 & 31))?,
            0x7C => binary(&mut stack, |a, b| ((a as u32) >> (b as u32 & 31)) as i32)?,
            0x7E => binary(&mut stack, |a, b| a & b)?,
            0x80 => binary(&mut stack, |a, b| a | b)?,
            0x82 => binary(&mut stack, |a, b| a ^ b)?,
            0x74 => {
                let v: i32 = pop_int(&mut stack)?;
                stack.push(Value::Int(v.wrapping_neg()));
            }
            0x84 => {
                let Operands::Iinc { index, delta } = &insn.operands else {
                    return Err(EmulationError::BadShape);
                };
                let idx: usize = usize::from(*index);
                ensure_local(&mut locals, idx);
                let cur: i32 = locals[idx].as_int()?;
                locals[idx] = Value::Int(cur.wrapping_add(*delta));
            }
            0x85..=0x93 => {
                let v: i32 = pop_int(&mut stack)?;
                let masked: i32 = match op {
                    0x91 => i32::from(v as i8),
                    0x92 => i32::from((v & 0xFFFF) as u16),
                    0x93 => i32::from(v as i16),
                    _ => v,
                };
                stack.push(Value::Int(masked));
            }
            0xBE => {
                let arr_ref: usize = pop_ref(&mut stack)?;
                let len: usize = heap.get(arr_ref).ok_or(EmulationError::BadShape)?.len();
                stack.push(Value::Int(len as i32));
            }
            0xA7 => {
                ip = branch_to(&pc_index, insn)?;
                continue;
            }
            0x99..=0x9E => {
                let v: i32 = pop_int(&mut stack)?;
                if unary_cmp(op, v) {
                    ip = branch_to(&pc_index, insn)?;
                    continue;
                }
            }
            0x9F..=0xA4 => {
                let b: i32 = pop_int(&mut stack)?;
                let a: i32 = pop_int(&mut stack)?;
                if binary_cmp(op, a, b) {
                    ip = branch_to(&pc_index, insn)?;
                    continue;
                }
            }
            0xB0 => {
                let r: usize = pop_ref(&mut stack)?;
                return heap.get(r).cloned().ok_or(EmulationError::BadShape);
            }
            0xBC => {
                let len: i32 = pop_int(&mut stack)?;
                let n: usize = usize::try_from(len).map_err(|_| EmulationError::BadShape)?;
                if n > input.len().saturating_mul(4).max(4096) {
                    return Err(EmulationError::BadShape);
                }
                heap.push(vec![0u16; n]);
                stack.push(Value::ArrayRef(heap.len() - 1));
            }
            0x00 => {}
            other => return Err(EmulationError::UnsupportedOpcode(other)),
        }
        ip += 1;
    }
    Err(EmulationError::NoReturn)
}

fn local_index(insn: &Instruction, op: u8) -> Result<usize, EmulationError> {
    match op {
        0x15 | 0x19 => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(EmulationError::BadShape),
        },
        0x1A..=0x1D => Ok(usize::from(op - 0x1A)),
        0x1E..=0x21 => Ok(usize::from(op - 0x1E)),
        0x22..=0x25 => Ok(usize::from(op - 0x22)),
        0x26..=0x29 => Ok(usize::from(op - 0x26)),
        0x2A..=0x2D => Ok(usize::from(op - 0x2A)),
        _ => Err(EmulationError::BadShape),
    }
}

fn store_index(insn: &Instruction, op: u8) -> Result<usize, EmulationError> {
    match op {
        0x36 | 0x3A => match &insn.operands {
            Operands::Local(i) => Ok(usize::from(*i)),
            _ => Err(EmulationError::BadShape),
        },
        0x3B..=0x3E => Ok(usize::from(op - 0x3B)),
        0x4B..=0x4E => Ok(usize::from(op - 0x4B)),
        _ => Err(EmulationError::BadShape),
    }
}

fn ensure_local(locals: &mut Vec<Value>, idx: usize) {
    if idx >= locals.len() {
        locals.resize(idx + 1, Value::Int(0));
    }
}

fn pop_int(stack: &mut Vec<Value>) -> Result<i32, EmulationError> {
    stack.pop().ok_or(EmulationError::StackUnderflow)?.as_int()
}

fn pop_ref(stack: &mut Vec<Value>) -> Result<usize, EmulationError> {
    stack.pop().ok_or(EmulationError::StackUnderflow)?.as_ref()
}

fn binary<F: Fn(i32, i32) -> i32>(stack: &mut Vec<Value>, f: F) -> Result<(), EmulationError> {
    let b: i32 = pop_int(stack)?;
    let a: i32 = pop_int(stack)?;
    stack.push(Value::Int(f(a, b)));
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

fn branch_to(pc_index: &[u32], insn: &Instruction) -> Result<usize, EmulationError> {
    let target: u32 = bytecode::branch_target(insn).ok_or(EmulationError::BadShape)?;
    pc_index
        .iter()
        .position(|&pc| pc == target)
        .ok_or(EmulationError::BadShape)
}

#[must_use]
pub fn decrypt_constant(stub: &DecryptStub, encrypted: &str) -> Option<String> {
    let input: Vec<u16> = encrypted.encode_utf16().collect();
    let out: Vec<u16> = emulate_char_array(stub, &input).ok()?;
    Some(String::from_utf16_lossy(&out))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::vec_init_then_push
)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, ConstantPoolEntry, FieldInfo, MethodInfo};

    fn build_xor_decrypt_stub(key: u8) -> DecryptStub {
        let mut code: Vec<u8> = Vec::new();
        code.push(0x2A);
        code.push(0xBE);
        code.push(0xBC);
        code.push(0x05);
        code.push(0x3C);
        code.push(0x03);
        code.push(0x3D);
        let cond_pc: usize = code.len();
        code.push(0x1C);
        code.push(0x2A);
        code.push(0xBE);
        code.push(0xA2);
        let cond_branch_pos: usize = code.len();
        code.extend_from_slice(&[0x00, 0x00]);
        code.push(0x2B);
        code.push(0x1C);
        code.push(0x2A);
        code.push(0x1C);
        code.push(0x34);
        code.push(0x10);
        code.push(key);
        code.push(0x82);
        code.push(0x55);
        code.push(0x84);
        code.push(0x02);
        code.push(0x01);
        code.push(0xA7);
        let goto_pos: usize = code.len();
        code.extend_from_slice(&[0x00, 0x00]);
        let end_pc: usize = code.len();
        code.push(0x2B);
        code.push(0xB0);

        let cond_target: i16 =
            i16::try_from(end_pc).unwrap() - i16::try_from(cond_branch_pos - 1).unwrap();
        code[cond_branch_pos] = cond_target.to_be_bytes()[0];
        code[cond_branch_pos + 1] = cond_target.to_be_bytes()[1];
        let goto_target: i16 =
            i16::try_from(cond_pc).unwrap() - i16::try_from(goto_pos - 1).unwrap();
        code[goto_pos] = goto_target.to_be_bytes()[0];
        code[goto_pos + 1] = goto_target.to_be_bytes()[1];

        DecryptStub {
            code,
            max_locals: 4,
        }
    }

    #[test]
    fn emulates_xor_decrypt_round_trip() {
        let key: u8 = 0x5A;
        let plain: &str = "secret-api-key-42";
        let encrypted: Vec<u16> = plain.encode_utf16().map(|c| c ^ u16::from(key)).collect();
        let stub: DecryptStub = build_xor_decrypt_stub(key);
        let out: Vec<u16> = emulate_char_array(&stub, &encrypted).expect("emulate");
        let decrypted: String = String::from_utf16(&out).expect("utf16");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn finds_decrypt_method_by_signature() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("decrypt".into()));
        cp.push(ConstantPoolEntry::Utf8("([C)[C".into()));
        cp.push(ConstantPoolEntry::Utf8("Code".into()));
        let stub: DecryptStub = build_xor_decrypt_stub(0x11);
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&(stub.code.len() as u32).to_be_bytes());
        info.extend_from_slice(&stub.code);
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::<FieldInfo>::new(),
            methods: vec![MethodInfo {
                access_flags: 0x0008,
                name_index: 1,
                descriptor_index: 2,
                attributes: vec![Attribute {
                    name_index: 3,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let found: DecryptStub = find_char_array_decrypt(&cf).expect("stub found");
        let encrypted: Vec<u16> = "hi".encode_utf16().map(|c| c ^ 0x11u16).collect();
        let out: Vec<u16> = emulate_char_array(&found, &encrypted).expect("emulate");
        assert_eq!(String::from_utf16(&out).unwrap(), "hi");
    }

    #[test]
    fn step_limit_guards_infinite_loop() {
        let code: Vec<u8> = vec![0xA7, 0xFF, 0xFD];
        let stub: DecryptStub = DecryptStub {
            code,
            max_locals: 1,
        };
        let err: EmulationError = emulate_char_array(&stub, &[]).expect_err("should not terminate");
        assert!(matches!(
            err,
            EmulationError::StepLimitExceeded | EmulationError::BadShape
        ));
    }

    #[test]
    fn unsupported_opcode_errors_cleanly() {
        let code: Vec<u8> = vec![0xC2];
        let stub: DecryptStub = DecryptStub {
            code,
            max_locals: 1,
        };
        let err: EmulationError = emulate_char_array(&stub, &[]).expect_err("unsupported");
        assert!(matches!(err, EmulationError::UnsupportedOpcode(0xC2)));
    }
}
