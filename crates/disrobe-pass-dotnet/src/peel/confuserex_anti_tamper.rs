use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, SectionHeader, parse, parse_clr_header};
use crate::peel::confuserex_resources::body_walks_runtime_image;

const IMAGE_BASE: i64 = 0x1000_0000;
const MAX_MAPPED_BYTES: usize = 256 * 1024 * 1024;
const MAX_STEPS: u64 = 64_000_000;
const MAX_STACK: usize = 4096;
const MAX_ARRAY_ELEMENTS: usize = 1 << 20;
const MAX_ARRAYS: usize = 256;
const METHOD_PINVOKE_IMPL: u16 = 0x2000;
const PAGE_READWRITE: i32 = 0x04;
const MODULE_PATH: &str = "C:\\module.dll";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiTamperRecovery {
    pub initializer_token: u32,
    pub section_name: String,
    pub section_rva: u32,
    pub section_size: u32,
    pub bytes_changed: u32,
    pub methods_in_section: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiTamperOutcome {
    Absent,
    Decrypted {
        recovery: AntiTamperRecovery,
        image: Vec<u8>,
    },
    Refused {
        initializer_token: u32,
        reason: String,
    },
}

pub fn decrypt_anti_tamper(image: &[u8]) -> Result<AntiTamperOutcome> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    let model: AssemblyModel = resolver.model();
    let Some((token, body)): Option<(u32, MethodBody)> =
        find_initializer(image, &pe, &resolver, &model)
    else {
        return Ok(AntiTamperOutcome::Absent);
    };
    let Some(mut mapped): Option<Vec<u8>> = map_image(image, &pe) else {
        return Ok(AntiTamperOutcome::Refused {
            initializer_token: token,
            reason: "the section table does not map into a bounded image".to_owned(),
        });
    };
    let original: Vec<u8> = mapped.clone();
    let pinvoke: Vec<u32> = model
        .types
        .iter()
        .flat_map(|t: &TypeModel| t.methods.iter())
        .filter(|m: &&MethodModel| m.flags & METHOD_PINVOKE_IMPL != 0)
        .map(|m: &MethodModel| m.token)
        .collect();
    let mut vm: Vm<'_> = Vm::new(&body, &resolver, &mut mapped, &pinvoke);
    if let Err(fault) = vm.run() {
        return Ok(AntiTamperOutcome::Refused {
            initializer_token: token,
            reason: format!("the initializer did not emulate to completion: {fault}"),
        });
    }
    let Some((section, lo, hi)): Option<(&SectionHeader, usize, usize)> =
        changed_section(&pe, &original, &mapped)
    else {
        return Ok(AntiTamperOutcome::Refused {
            initializer_token: token,
            reason: "the initializer wrote outside a single section or wrote nothing".to_owned(),
        });
    };
    let mut out: Vec<u8> = image.to_vec();
    let mut changed: u32 = 0;
    for (rva, decrypted) in mapped.iter().enumerate().take(hi).skip(lo) {
        let Some(delta): Option<u32> = u32::try_from(rva)
            .ok()
            .and_then(|r: u32| r.checked_sub(section.virtual_address))
        else {
            continue;
        };
        if delta >= section.raw_size {
            continue;
        }
        let Some(file): Option<usize> = usize::try_from(section.raw_pointer)
            .ok()
            .and_then(|p: usize| p.checked_add(usize::try_from(delta).ok()?))
        else {
            continue;
        };
        if let Some(slot) = out.get_mut(file)
            && *slot != *decrypted
        {
            *slot = *decrypted;
            changed = changed.saturating_add(1);
        }
    }
    let (in_section, parsed): (u32, u32) = methods_parse_in(&out, &pe, &model, section);
    if in_section == 0 || parsed != in_section {
        return Ok(AntiTamperOutcome::Refused {
            initializer_token: token,
            reason: format!(
                "{parsed} of {in_section} method bodies in section {:?} parse after the derived key was applied",
                section.name
            ),
        });
    }
    Ok(AntiTamperOutcome::Decrypted {
        recovery: AntiTamperRecovery {
            initializer_token: token,
            section_name: section.name.clone(),
            section_rva: section.virtual_address,
            section_size: section.raw_size,
            bytes_changed: changed,
            methods_in_section: in_section,
        },
        image: out,
    })
}

fn find_initializer(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    model: &AssemblyModel,
) -> Option<(u32, MethodBody)> {
    for ty in &model.types {
        for m in &ty.methods {
            if m.rva == 0 || !m.is_static() || !m.signature.params.is_empty() {
                continue;
            }
            let off: usize = pe.rva_to_offset(m.rva)?;
            let Ok(body): Result<MethodBody> = parse_method_body(image.get(off..)?) else {
                continue;
            };
            if !body_walks_runtime_image(&body) {
                continue;
            }
            let loads_hinstance: bool = body.instructions.iter().any(|i: &Instruction| {
                matches!(i.name.as_str(), "call" | "callvirt")
                    && matches!(i.operand, OperandValue::Token(t) if callee_short(resolver, t) == "GetHINSTANCE")
            });
            if loads_hinstance {
                return Some((m.token, body));
            }
        }
    }
    None
}

fn callee_short(resolver: &Resolver, token: u32) -> String {
    let full: String = resolver.resolve_token(token);
    full.rsplit("::").next().unwrap_or(&full).to_owned()
}

fn map_image(image: &[u8], pe: &PeImage) -> Option<Vec<u8>> {
    let mut extent: usize = 0;
    let mut headers: usize = image.len();
    for s in &pe.sections {
        let va: usize = usize::try_from(s.virtual_address).ok()?;
        let span: usize = usize::try_from(s.virtual_size.max(s.raw_size)).ok()?;
        extent = extent.max(va.checked_add(span)?);
        if s.raw_pointer != 0 {
            headers = headers.min(usize::try_from(s.raw_pointer).ok()?);
        }
    }
    if extent == 0 || extent > MAX_MAPPED_BYTES {
        return None;
    }
    let mut mapped: Vec<u8> = vec![0u8; extent];
    let header_len: usize = headers.min(image.len()).min(extent);
    mapped[..header_len].copy_from_slice(&image[..header_len]);
    for s in &pe.sections {
        let va: usize = usize::try_from(s.virtual_address).ok()?;
        let raw: usize = usize::try_from(s.raw_pointer).ok()?;
        let len: usize = usize::try_from(s.raw_size).ok()?;
        let end_file: usize = raw.checked_add(len)?.min(image.len());
        if raw >= end_file {
            continue;
        }
        let count: usize = (end_file - raw).min(extent.saturating_sub(va));
        mapped[va..va + count].copy_from_slice(&image[raw..raw + count]);
    }
    Some(mapped)
}

fn changed_section<'a>(
    pe: &'a PeImage,
    original: &[u8],
    mapped: &[u8],
) -> Option<(&'a SectionHeader, usize, usize)> {
    let lo: usize = original
        .iter()
        .zip(mapped)
        .position(|(a, b): (&u8, &u8)| a != b)?;
    let hi: usize = original
        .iter()
        .zip(mapped)
        .rposition(|(a, b): (&u8, &u8)| a != b)?
        + 1;
    let section: &SectionHeader = pe.sections.iter().find(|s: &&SectionHeader| {
        let start: usize = usize::try_from(s.virtual_address).unwrap_or(usize::MAX);
        let end: usize =
            start.saturating_add(usize::try_from(s.virtual_size.max(s.raw_size)).unwrap_or(0));
        lo >= start && hi <= end
    })?;
    Some((section, lo, hi))
}

fn methods_parse_in(
    image: &[u8],
    pe: &PeImage,
    model: &AssemblyModel,
    section: &SectionHeader,
) -> (u32, u32) {
    let start: u32 = section.virtual_address;
    let end: u32 = start.saturating_add(section.virtual_size.max(section.raw_size));
    let mut total: u32 = 0;
    let mut parsed: u32 = 0;
    for ty in &model.types {
        for m in &ty.methods {
            if m.rva == 0 || m.rva < start || m.rva >= end {
                continue;
            }
            total = total.saturating_add(1);
            if let Some(off) = pe.rva_to_offset(m.rva)
                && let Some(tail) = image.get(off..)
                && parse_method_body(tail).is_ok()
            {
                parsed = parsed.saturating_add(1);
            }
        }
    }
    (total, parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    I32(i32),
    I64(i64),
    Nat(i64),
    Array(usize),
    Text,
    Object,
    LocalRef(u32),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Fault {
    StepLimit,
    StackUnderflow,
    StackOverflow,
    UnsupportedOpcode(String),
    UnsupportedCall(String),
    BadAddress(i64),
    BadBranch(u32),
    BadArray,
    TypeMismatch(&'static str),
    NoReturn,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StepLimit => write!(f, "step limit of {MAX_STEPS} reached"),
            Self::StackUnderflow => write!(f, "evaluation stack underflow"),
            Self::StackOverflow => write!(f, "evaluation stack overflow"),
            Self::UnsupportedOpcode(name) => write!(f, "unsupported opcode {name}"),
            Self::UnsupportedCall(name) => write!(f, "unsupported call to {name}"),
            Self::BadAddress(addr) => {
                write!(f, "memory access outside the mapped image at {addr:#x}")
            }
            Self::BadBranch(target) => write!(f, "branch to offset {target:#x} outside the method"),
            Self::BadArray => write!(f, "array access outside bounds"),
            Self::TypeMismatch(what) => write!(f, "operand type mismatch at {what}"),
            Self::NoReturn => write!(f, "the method ended without ret"),
        }
    }
}

struct Vm<'a> {
    body: &'a MethodBody,
    resolver: &'a Resolver,
    mapped: &'a mut Vec<u8>,
    pinvoke: &'a [u32],
    stack: Vec<Val>,
    locals: BTreeMap<u32, Val>,
    arrays: Vec<Vec<i64>>,
    steps: u64,
}

impl<'a> Vm<'a> {
    fn new(
        body: &'a MethodBody,
        resolver: &'a Resolver,
        mapped: &'a mut Vec<u8>,
        pinvoke: &'a [u32],
    ) -> Self {
        Self {
            body,
            resolver,
            mapped,
            pinvoke,
            stack: Vec::with_capacity(64),
            locals: BTreeMap::new(),
            arrays: Vec::new(),
            steps: 0,
        }
    }

    fn push(&mut self, v: Val) -> std::result::Result<(), Fault> {
        if self.stack.len() >= MAX_STACK {
            return Err(Fault::StackOverflow);
        }
        self.stack.push(v);
        Ok(())
    }

    fn pop(&mut self) -> std::result::Result<Val, Fault> {
        self.stack.pop().ok_or(Fault::StackUnderflow)
    }

    fn pop_int(&mut self) -> std::result::Result<i64, Fault> {
        match self.pop()? {
            Val::I32(v) => Ok(i64::from(v)),
            Val::I64(v) | Val::Nat(v) => Ok(v),
            Val::Null => Ok(0),
            _ => Err(Fault::TypeMismatch("integer")),
        }
    }

    fn index_of(&self, offset: u32) -> std::result::Result<usize, Fault> {
        self.body
            .instructions
            .binary_search_by_key(&offset, |i: &Instruction| i.offset)
            .map_err(|_| Fault::BadBranch(offset))
    }

    fn next_offset(&self, index: usize) -> u32 {
        self.body
            .instructions
            .get(index + 1)
            .map_or(self.body.code_size, |n: &Instruction| n.offset)
    }

    fn target(&self, index: usize, rel: i32) -> std::result::Result<usize, Fault> {
        let abs: i64 = i64::from(self.next_offset(index)) + i64::from(rel);
        let offset: u32 = u32::try_from(abs).map_err(|_| Fault::BadBranch(0))?;
        self.index_of(offset)
    }

    fn mem_offset(&self, addr: i64, width: usize) -> std::result::Result<usize, Fault> {
        let rel: i64 = addr - IMAGE_BASE;
        let start: usize = usize::try_from(rel).map_err(|_| Fault::BadAddress(addr))?;
        let end: usize = start.checked_add(width).ok_or(Fault::BadAddress(addr))?;
        if end > self.mapped.len() {
            return Err(Fault::BadAddress(addr));
        }
        Ok(start)
    }

    fn load(&self, addr: Val, width: usize) -> std::result::Result<u64, Fault> {
        match addr {
            Val::LocalRef(slot) => {
                let v: i64 = match self.locals.get(&slot).copied().unwrap_or(Val::I32(0)) {
                    Val::I32(v) => i64::from(v),
                    Val::I64(v) | Val::Nat(v) => v,
                    _ => return Err(Fault::TypeMismatch("local load")),
                };
                Ok((v as u64) & mask(width))
            }
            Val::Nat(a) | Val::I64(a) => {
                let start: usize = self.mem_offset(a, width)?;
                let mut value: u64 = 0;
                for i in 0..width {
                    value |= u64::from(self.mapped[start + i]) << (8 * i);
                }
                Ok(value)
            }
            Val::I32(a) => self.load(Val::Nat(i64::from(a)), width),
            _ => Err(Fault::TypeMismatch("pointer load")),
        }
    }

    fn store(&mut self, addr: Val, width: usize, value: i64) -> std::result::Result<(), Fault> {
        match addr {
            Val::LocalRef(slot) => {
                self.locals.insert(slot, Val::I32(value as i32));
                Ok(())
            }
            Val::Nat(a) | Val::I64(a) => {
                let start: usize = self.mem_offset(a, width)?;
                for i in 0..width {
                    self.mapped[start + i] = ((value as u64) >> (8 * i)) as u8;
                }
                Ok(())
            }
            Val::I32(a) => self.store(Val::Nat(i64::from(a)), width, value),
            _ => Err(Fault::TypeMismatch("pointer store")),
        }
    }

    fn binary(&mut self, op: fn(i64, i64, bool) -> i64) -> std::result::Result<(), Fault> {
        let right_value: Val = self.pop()?;
        let left_value: Val = self.pop()?;
        let (left, right): (i64, i64) = (int_of(left_value)?, int_of(right_value)?);
        let wide: bool = matches!(left_value, Val::I64(_) | Val::Nat(_))
            || matches!(right_value, Val::I64(_) | Val::Nat(_));
        let result: i64 = op(left, right, wide);
        let out: Val = if matches!(left_value, Val::Nat(_)) || matches!(right_value, Val::Nat(_)) {
            Val::Nat(result)
        } else if wide {
            Val::I64(result)
        } else {
            Val::I32(result as i32)
        };
        self.push(out)
    }

    fn compare(&mut self, name: &str) -> std::result::Result<bool, Fault> {
        let right_value: Val = self.pop()?;
        let left_value: Val = self.pop()?;
        let (left, right): (i64, i64) = (int_of(left_value)?, int_of(right_value)?);
        let wide: bool = matches!(left_value, Val::I64(_) | Val::Nat(_))
            || matches!(right_value, Val::I64(_) | Val::Nat(_));
        let (unsigned_left, unsigned_right): (u64, u64) = if wide {
            (left as u64, right as u64)
        } else {
            (u64::from(left as u32), u64::from(right as u32))
        };
        Ok(match name {
            "beq" | "beq.s" | "ceq" => left == right,
            "bne.un" | "bne.un.s" => left != right,
            "bgt" | "bgt.s" | "cgt" => left > right,
            "bge" | "bge.s" => left >= right,
            "blt" | "blt.s" | "clt" => left < right,
            "ble" | "ble.s" => left <= right,
            "bgt.un" | "bgt.un.s" | "cgt.un" => unsigned_left > unsigned_right,
            "bge.un" | "bge.un.s" => unsigned_left >= unsigned_right,
            "blt.un" | "blt.un.s" | "clt.un" => unsigned_left < unsigned_right,
            "ble.un" | "ble.un.s" => unsigned_left <= unsigned_right,
            _ => return Err(Fault::UnsupportedOpcode(name.to_owned())),
        })
    }

    fn call(&mut self, token: u32) -> std::result::Result<(), Fault> {
        if self.pinvoke.contains(&token) {
            let params: usize = self
                .resolver
                .callee_signature(token)
                .map_or(0, |s| s.params.len());
            if params != 4 {
                return Err(Fault::UnsupportedCall(format!(
                    "P/Invoke {token:#x} with {params} parameters"
                )));
            }
            let out: Val = self.pop()?;
            let _new_protect: i64 = self.pop_int()?;
            let _size: i64 = self.pop_int()?;
            let _address: Val = self.pop()?;
            self.store(out, 4, i64::from(PAGE_READWRITE))?;
            return self.push(Val::I32(1));
        }
        let short: String = callee_short(self.resolver, token);
        match short.as_str() {
            "GetTypeFromHandle" | "get_Module" => {
                let _: Val = self.pop()?;
                self.push(Val::Object)
            }
            "get_FullyQualifiedName" => {
                let _: Val = self.pop()?;
                self.push(Val::Text)
            }
            "get_Length" => {
                let receiver: Val = self.pop()?;
                if receiver != Val::Text {
                    return Err(Fault::TypeMismatch("string length"));
                }
                self.push(Val::I32(
                    i32::try_from(MODULE_PATH.len()).unwrap_or(i32::MAX),
                ))
            }
            "get_Chars" => {
                let index: i64 = self.pop_int()?;
                let receiver: Val = self.pop()?;
                if receiver != Val::Text {
                    return Err(Fault::TypeMismatch("string index"));
                }
                let ch: u16 = usize::try_from(index)
                    .ok()
                    .and_then(|i: usize| MODULE_PATH.encode_utf16().nth(i))
                    .ok_or(Fault::BadArray)?;
                self.push(Val::I32(i32::from(ch)))
            }
            "GetHINSTANCE" => {
                let _: Val = self.pop()?;
                self.push(Val::Nat(IMAGE_BASE))
            }
            "op_Explicit" => {
                let v: Val = self.pop()?;
                let as_native: Val = match v {
                    Val::I32(x) => Val::Nat(i64::from(x)),
                    Val::I64(x) | Val::Nat(x) => Val::Nat(x),
                    other => other,
                };
                self.push(as_native)
            }
            other => Err(Fault::UnsupportedCall(other.to_owned())),
        }
    }

    fn run(&mut self) -> std::result::Result<(), Fault> {
        let mut index: usize = 0;
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err(Fault::StepLimit);
            }
            let Some(ins): Option<&Instruction> = self.body.instructions.get(index) else {
                return Err(Fault::NoReturn);
            };
            let name: &str = ins.name.as_str();
            let mut next: usize = index + 1;
            if let Some(literal) = crate::peel::deflatten::blocks::int_literal(ins) {
                self.push(Val::I32(literal as i32))?;
                index = next;
                continue;
            }
            if let Ok(access) = crate::cil::decode_slot(ins) {
                let slot: u32 = u32::from(access.index);
                match access.op {
                    crate::cil::SlotOp::LoadLocal => {
                        let v: Val = self.locals.get(&slot).copied().unwrap_or(Val::I32(0));
                        self.push(v)?;
                    }
                    crate::cil::SlotOp::StoreLocal => {
                        let v: Val = self.pop()?;
                        self.locals.insert(slot, v);
                    }
                    crate::cil::SlotOp::LocalAddress => self.push(Val::LocalRef(slot))?,
                    crate::cil::SlotOp::LoadArgument
                    | crate::cil::SlotOp::StoreArgument
                    | crate::cil::SlotOp::ArgumentAddress => {
                        return Err(Fault::UnsupportedOpcode(name.to_owned()));
                    }
                }
                index = next;
                continue;
            }
            match name {
                "nop" | "break" => {}
                "ret" => return Ok(()),
                "dup" => {
                    let top: Val = *self.stack.last().ok_or(Fault::StackUnderflow)?;
                    self.push(top)?;
                }
                "pop" => {
                    let _: Val = self.pop()?;
                }
                "ldnull" => self.push(Val::Null)?,
                "ldtoken" => self.push(Val::Object)?,
                "ldc.i8" => {
                    let OperandValue::I64(v) = ins.operand else {
                        return Err(Fault::TypeMismatch("ldc.i8"));
                    };
                    self.push(Val::I64(v))?;
                }
                "br" | "br.s" => {
                    let OperandValue::BrTarget(rel) = ins.operand else {
                        return Err(Fault::BadBranch(ins.offset));
                    };
                    next = self.target(index, rel)?;
                }
                "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" => {
                    let OperandValue::BrTarget(rel) = ins.operand else {
                        return Err(Fault::BadBranch(ins.offset));
                    };
                    let v: Val = self.pop()?;
                    let truthy: bool = match v {
                        Val::I32(x) => x != 0,
                        Val::I64(x) | Val::Nat(x) => x != 0,
                        Val::Null => false,
                        Val::Array(_) | Val::Text | Val::Object | Val::LocalRef(_) => true,
                    };
                    if truthy == name.starts_with("brtrue") {
                        next = self.target(index, rel)?;
                    }
                }
                "beq" | "beq.s" | "bne.un" | "bne.un.s" | "bgt" | "bgt.s" | "bge" | "bge.s"
                | "blt" | "blt.s" | "ble" | "ble.s" | "bgt.un" | "bgt.un.s" | "bge.un"
                | "bge.un.s" | "blt.un" | "blt.un.s" | "ble.un" | "ble.un.s" => {
                    let OperandValue::BrTarget(rel) = ins.operand else {
                        return Err(Fault::BadBranch(ins.offset));
                    };
                    if self.compare(name)? {
                        next = self.target(index, rel)?;
                    }
                }
                "ceq" | "cgt" | "clt" | "cgt.un" | "clt.un" => {
                    let r: bool = self.compare(name)?;
                    self.push(Val::I32(i32::from(r)))?;
                }
                "switch" => {
                    let OperandValue::Switch(ref targets) = ins.operand else {
                        return Err(Fault::BadBranch(ins.offset));
                    };
                    let selector: i64 = self.pop_int()?;
                    if let Ok(i) = usize::try_from(selector as u32)
                        && let Some(rel) = targets.get(i)
                    {
                        next = self.target(index, *rel)?;
                    }
                }
                "add" | "add.ovf" | "add.ovf.un" => {
                    self.binary(|a: i64, b: i64, _w: bool| a.wrapping_add(b))?;
                }
                "sub" | "sub.ovf" | "sub.ovf.un" => {
                    self.binary(|a: i64, b: i64, _w: bool| a.wrapping_sub(b))?;
                }
                "mul" | "mul.ovf" | "mul.ovf.un" => {
                    self.binary(|a: i64, b: i64, _w: bool| a.wrapping_mul(b))?;
                }
                "and" => self.binary(|a: i64, b: i64, _w: bool| a & b)?,
                "or" => self.binary(|a: i64, b: i64, _w: bool| a | b)?,
                "xor" => self.binary(|a: i64, b: i64, _w: bool| a ^ b)?,
                "shl" => self.binary(|a: i64, b: i64, w: bool| {
                    if w {
                        a.wrapping_shl(b as u32)
                    } else {
                        i64::from((a as i32).wrapping_shl(b as u32))
                    }
                })?,
                "shr" => self.binary(|a: i64, b: i64, w: bool| {
                    if w {
                        a.wrapping_shr(b as u32)
                    } else {
                        i64::from((a as i32).wrapping_shr(b as u32))
                    }
                })?,
                "shr.un" => self.binary(|a: i64, b: i64, w: bool| {
                    if w {
                        ((a as u64).wrapping_shr(b as u32)) as i64
                    } else {
                        i64::from((a as u32).wrapping_shr(b as u32))
                    }
                })?,
                "div.un" | "rem.un" => {
                    let divisor: Val = self.pop()?;
                    let dividend: Val = self.pop()?;
                    let wide: bool = matches!(divisor, Val::I64(_) | Val::Nat(_))
                        || matches!(dividend, Val::I64(_) | Val::Nat(_));
                    let (x, y): (u64, u64) = if wide {
                        (int_of(dividend)? as u64, int_of(divisor)? as u64)
                    } else {
                        (
                            u64::from(int_of(dividend)? as u32),
                            u64::from(int_of(divisor)? as u32),
                        )
                    };
                    if y == 0 {
                        return Err(Fault::TypeMismatch("division by zero"));
                    }
                    let r: u64 = if name == "div.un" { x / y } else { x % y };
                    self.push(if wide {
                        Val::I64(r as i64)
                    } else {
                        Val::I32(r as i32)
                    })?;
                }
                "div" | "rem" => {
                    let y: i64 = self.pop_int()?;
                    let x: i64 = self.pop_int()?;
                    if y == 0 {
                        return Err(Fault::TypeMismatch("division by zero"));
                    }
                    let r: i64 = if name == "div" {
                        x.wrapping_div(y)
                    } else {
                        x.wrapping_rem(y)
                    };
                    self.push(Val::I32(r as i32))?;
                }
                "neg" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(v.wrapping_neg() as i32))?;
                }
                "not" => {
                    let v: Val = self.pop()?;
                    let out: Val = match v {
                        Val::I32(x) => Val::I32(!x),
                        Val::I64(x) => Val::I64(!x),
                        Val::Nat(x) => Val::Nat(!x),
                        _ => return Err(Fault::TypeMismatch("not")),
                    };
                    self.push(out)?;
                }
                "conv.i4" | "conv.u4" | "conv.ovf.i4" | "conv.ovf.u4" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(v as i32))?;
                }
                "conv.u1" | "conv.ovf.u1" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(i32::from(v as u8)))?;
                }
                "conv.i1" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(i32::from(v as i8)))?;
                }
                "conv.u2" | "conv.ovf.u2" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(i32::from(v as u16)))?;
                }
                "conv.i2" => {
                    let v: i64 = self.pop_int()?;
                    self.push(Val::I32(i32::from(v as i16)))?;
                }
                "conv.i8" => {
                    let v: Val = self.pop()?;
                    let out: i64 = match v {
                        Val::I32(x) => i64::from(x),
                        other => int_of(other)?,
                    };
                    self.push(Val::I64(out))?;
                }
                "conv.u8" => {
                    let v: Val = self.pop()?;
                    let out: i64 = match v {
                        Val::I32(x) => i64::from(x as u32),
                        other => int_of(other)?,
                    };
                    self.push(Val::I64(out))?;
                }
                "conv.i" => {
                    let v: Val = self.pop()?;
                    let out: i64 = match v {
                        Val::I32(x) => i64::from(x),
                        Val::LocalRef(_) | Val::Array(_) | Val::Text | Val::Object => {
                            return Err(Fault::TypeMismatch("conv.i"));
                        }
                        other => int_of(other)?,
                    };
                    self.push(Val::Nat(out))?;
                }
                "conv.u" => {
                    let v: Val = self.pop()?;
                    let out: i64 = match v {
                        Val::I32(x) => i64::from(x as u32),
                        Val::LocalRef(_) | Val::Array(_) | Val::Text | Val::Object => {
                            return Err(Fault::TypeMismatch("conv.u"));
                        }
                        other => int_of(other)?,
                    };
                    self.push(Val::Nat(out))?;
                }
                "ldind.u1" | "ldind.i1" | "ldind.u2" | "ldind.i2" | "ldind.u4" | "ldind.i4"
                | "ldind.i8" | "ldind.i" => {
                    let addr: Val = self.pop()?;
                    let width: usize = match name {
                        "ldind.u1" | "ldind.i1" => 1,
                        "ldind.u2" | "ldind.i2" => 2,
                        "ldind.i8" => 8,
                        _ => 4,
                    };
                    let raw: u64 = self.load(addr, width)?;
                    let out: Val = match name {
                        "ldind.i1" => Val::I32(i32::from(raw as u8 as i8)),
                        "ldind.i2" => Val::I32(i32::from(raw as u16 as i16)),
                        "ldind.i8" => Val::I64(raw as i64),
                        "ldind.i" => Val::Nat(raw as i64),
                        _ => Val::I32(raw as u32 as i32),
                    };
                    self.push(out)?;
                }
                "stind.i1" | "stind.i2" | "stind.i4" | "stind.i8" | "stind.i" => {
                    let value: i64 = self.pop_int()?;
                    let addr: Val = self.pop()?;
                    let width: usize = match name {
                        "stind.i1" => 1,
                        "stind.i2" => 2,
                        "stind.i8" => 8,
                        _ => 4,
                    };
                    self.store(addr, width, value)?;
                }
                "newarr" => {
                    let len: i64 = self.pop_int()?;
                    let count: usize = usize::try_from(len).map_err(|_| Fault::BadArray)?;
                    if count > MAX_ARRAY_ELEMENTS || self.arrays.len() >= MAX_ARRAYS {
                        return Err(Fault::BadArray);
                    }
                    self.arrays.push(vec![0i64; count]);
                    self.push(Val::Array(self.arrays.len() - 1))?;
                }
                "ldlen" => {
                    let Val::Array(a) = self.pop()? else {
                        return Err(Fault::TypeMismatch("ldlen"));
                    };
                    let len: usize = self.arrays.get(a).ok_or(Fault::BadArray)?.len();
                    self.push(Val::Nat(i64::try_from(len).unwrap_or(i64::MAX)))?;
                }
                "ldelem.u4" | "ldelem.i4" | "ldelem.u1" | "ldelem.i1" | "ldelem.u2"
                | "ldelem.i2" | "ldelem.i8" | "ldelem.i" | "ldelem" => {
                    let i: i64 = self.pop_int()?;
                    let Val::Array(a) = self.pop()? else {
                        return Err(Fault::TypeMismatch("ldelem"));
                    };
                    let value: i64 = *self
                        .arrays
                        .get(a)
                        .and_then(|arr: &Vec<i64>| arr.get(usize::try_from(i).ok()?))
                        .ok_or(Fault::BadArray)?;
                    let out: Val = match name {
                        "ldelem.i8" => Val::I64(value),
                        "ldelem.i" => Val::Nat(value),
                        _ => Val::I32(value as i32),
                    };
                    self.push(out)?;
                }
                "stelem.i4" | "stelem.i1" | "stelem.i2" | "stelem.i8" | "stelem.i" | "stelem" => {
                    let value: i64 = self.pop_int()?;
                    let i: i64 = self.pop_int()?;
                    let Val::Array(a) = self.pop()? else {
                        return Err(Fault::TypeMismatch("stelem"));
                    };
                    let slot: &mut i64 = self
                        .arrays
                        .get_mut(a)
                        .and_then(|arr: &mut Vec<i64>| arr.get_mut(usize::try_from(i).ok()?))
                        .ok_or(Fault::BadArray)?;
                    *slot = match name {
                        "stelem.i1" => i64::from(value as u8),
                        "stelem.i2" => i64::from(value as u16),
                        "stelem.i4" | "stelem" => i64::from(value as u32),
                        _ => value,
                    };
                }
                "call" | "callvirt" => {
                    let OperandValue::Token(token) = ins.operand else {
                        return Err(Fault::TypeMismatch("call"));
                    };
                    self.call(token)?;
                }
                other => return Err(Fault::UnsupportedOpcode(other.to_owned())),
            }
            index = next;
        }
    }
}

const fn mask(width: usize) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

fn int_of(v: Val) -> std::result::Result<i64, Fault> {
    match v {
        Val::I32(x) => Ok(i64::from(x)),
        Val::I64(x) | Val::Nat(x) => Ok(x),
        Val::Null => Ok(0),
        _ => Err(Fault::TypeMismatch("integer operand")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn helloapp_anti_tamper_section_decrypts_to_parsable_bodies() {
        let image: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
        match decrypt_anti_tamper(&image).unwrap() {
            AntiTamperOutcome::Decrypted {
                recovery,
                image: out,
            } => {
                assert!(recovery.bytes_changed > 0);
                assert!(recovery.methods_in_section >= 50, "{recovery:?}");
                assert_ne!(out, image);
            }
            other => panic!("expected a decrypted section, got {other:?}"),
        }
    }

    #[test]
    fn a_gauntlet_without_anti_tamper_is_reported_absent() {
        let image: Vec<u8> =
            load("../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe");
        assert_eq!(
            decrypt_anti_tamper(&image).unwrap(),
            AntiTamperOutcome::Absent
        );
    }

    #[test]
    fn a_corrupted_body_header_in_the_encrypted_section_is_refused_by_name() {
        let base: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
        let pe: PeImage = parse(&base).unwrap();
        let clr: ClrHeader = parse_clr_header(&base, &pe).unwrap();
        let root: MetadataRoot = parse_metadata_root(&base, &pe, &clr).unwrap();
        let resolver: Resolver = Resolver::build(&base, &pe, &clr, &root).unwrap();
        let model: AssemblyModel = resolver.model();
        let encrypted: &SectionHeader = &pe.sections[0];
        let first_body: usize = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.methods.iter())
            .filter(|m: &&MethodModel| {
                m.rva >= encrypted.virtual_address
                    && m.rva < encrypted.virtual_address + encrypted.raw_size
            })
            .map(|m: &MethodModel| pe.rva_to_offset(m.rva).unwrap())
            .min()
            .unwrap();
        let mut image: Vec<u8> = base;
        image[first_body] ^= 0x5A;
        match decrypt_anti_tamper(&image).unwrap() {
            AntiTamperOutcome::Refused { reason, .. } => {
                assert!(reason.contains("parse after the derived key"), "{reason}");
            }
            other => panic!("a corrupted method header must refuse, got {other:?}"),
        }
    }

    #[test]
    fn only_the_first_sixteen_words_depend_on_the_image_hash() {
        let base: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
        let pe: PeImage = parse(&base).unwrap();
        let text: &SectionHeader = pe
            .sections
            .iter()
            .find(|s: &&SectionHeader| s.name == ".text")
            .unwrap();
        let mut flipped: Vec<u8> = base.clone();
        flipped[usize::try_from(text.raw_pointer + 16).unwrap()] ^= 0x5A;
        let AntiTamperOutcome::Decrypted {
            image: reference, ..
        } = decrypt_anti_tamper(&base).unwrap()
        else {
            panic!("the unmodified image decrypts");
        };
        let AntiTamperOutcome::Decrypted { image: altered, .. } =
            decrypt_anti_tamper(&flipped).unwrap()
        else {
            panic!("a hash change only disturbs the self-synchronising head");
        };
        let start: usize = usize::try_from(pe.sections[0].raw_pointer).unwrap();
        assert_ne!(&reference[start..start + 64], &altered[start..start + 64]);
        assert_eq!(
            &reference[start + 64..start + usize::try_from(pe.sections[0].raw_size).unwrap()],
            &altered[start + 64..start + usize::try_from(pe.sections[0].raw_size).unwrap()]
        );
    }
}
