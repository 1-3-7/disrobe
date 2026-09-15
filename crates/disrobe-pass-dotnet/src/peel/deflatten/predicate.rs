use std::cell::RefCell;
use std::collections::BTreeMap;

use disrobe_pass_native::stub_emu::cpu::NoopHost;
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Perm, Reg};

use crate::cil::{MethodBody, parse_method_body};
use crate::cil_emulator::{StubInput, StubOutput, emulate_stub};
use crate::model::{AssemblyModel, MethodModel};
use crate::pe::PeImage;
use crate::signature::{TypeSig, TypeSigOrVoid};

use super::interp::KeyOracle;

const METHOD_IMPL_CODE_TYPE_MASK: u16 = 0x0003;
const METHOD_IMPL_NATIVE: u16 = 0x0001;
const NATIVE_STUB_READ_CAP: usize = 4096;
const NATIVE_STEP_CAP: u64 = 200_000;

const STUB_CODE_BASE: u64 = 0x0040_0000;
const STUB_STACK_BASE: u64 = 0x0020_0000;
const STUB_STACK_SIZE: u64 = 0x0001_0000;
const STUB_RETURN_SENTINEL: u32 = 0x00FF_FF00;

#[derive(Debug, Clone)]
enum PredicateKind {
    Native(Vec<u8>),
    Managed(MethodBody),
}

#[derive(Debug)]
pub struct PredicateOracle {
    kinds: BTreeMap<u32, PredicateKind>,
    cache: RefCell<BTreeMap<(u32, i64), Option<i64>>>,
}

impl PredicateOracle {
    #[must_use]
    pub fn build(image: &[u8], pe: &PeImage, model: &AssemblyModel) -> Self {
        let mut kinds: BTreeMap<u32, PredicateKind> = BTreeMap::new();
        for ty in &model.types {
            for m in &ty.methods {
                if let Some(kind) = classify(image, pe, m) {
                    kinds.insert(m.token, kind);
                }
            }
        }
        Self {
            kinds,
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub fn predicate_method_count(&self) -> usize {
        self.kinds.len()
    }
}

fn evaluate(kind: &PredicateKind, input: i64) -> Option<i64> {
    match kind {
        PredicateKind::Native(code) => run_native(code, input),
        PredicateKind::Managed(body) => run_managed(body, input),
    }
}

impl KeyOracle for PredicateOracle {
    fn decode(&self, method_token: u32, input: i64) -> Option<i64> {
        let key: (u32, i64) = (method_token, input);
        if let Some(cached) = self.cache.borrow().get(&key) {
            return *cached;
        }
        let result: Option<i64> = self
            .kinds
            .get(&method_token)
            .and_then(|kind: &PredicateKind| evaluate(kind, input));
        self.cache.borrow_mut().insert(key, result);
        result
    }
}

const fn is_int32(sig: &TypeSig) -> bool {
    matches!(sig, TypeSig::I4 | TypeSig::U4)
}

const fn returns_int32(ret: &TypeSigOrVoid) -> bool {
    matches!(ret, TypeSigOrVoid::Type(t) if is_int32(t))
}

fn classify(image: &[u8], pe: &PeImage, m: &MethodModel) -> Option<PredicateKind> {
    if m.rva == 0 || !m.is_static() {
        return None;
    }
    if m.signature.params.len() != 1
        || !is_int32(&m.signature.params[0])
        || !returns_int32(&m.signature.return_type)
    {
        return None;
    }
    let off: usize = pe.rva_to_offset(m.rva)?;
    if m.impl_flags & METHOD_IMPL_CODE_TYPE_MASK == METHOD_IMPL_NATIVE {
        let end: usize = off.saturating_add(NATIVE_STUB_READ_CAP).min(image.len());
        let code: &[u8] = image.get(off..end)?;
        if code.is_empty() {
            return None;
        }
        return Some(PredicateKind::Native(code.to_vec()));
    }
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    Some(PredicateKind::Managed(body))
}

fn run_managed(body: &MethodBody, input: i64) -> Option<i64> {
    let in_arg: StubInput = StubInput {
        int_args: vec![input & 0xFFFF_FFFF],
        byte_array_args: Vec::new(),
        char_array_args: Vec::new(),
    };
    match emulate_stub(body, &in_arg) {
        Ok(StubOutput::Int(v)) => Some(i64::from(v as i32)),
        _ => None,
    }
}

fn run_native(code: &[u8], input: i64) -> Option<i64> {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    let code_pages: u64 = ((code.len() as u64) + 0xFFF) & !0xFFF;
    cpu.mem
        .map(STUB_CODE_BASE, code_pages.max(0x1000), Perm::RWX)
        .ok()?;
    cpu.mem.write(STUB_CODE_BASE, code).ok()?;
    cpu.mem
        .map(STUB_STACK_BASE, STUB_STACK_SIZE, Perm::RW)
        .ok()?;

    let arg: u32 = (input & 0xFFFF_FFFF) as u32;
    let sp: u64 = STUB_STACK_BASE + STUB_STACK_SIZE - 0x100;
    cpu.mem.write_u32(sp, STUB_RETURN_SENTINEL).ok()?;
    cpu.mem.write_u32(sp + 4, arg).ok()?;
    cpu.regs.set(Reg::Rsp, sp);
    cpu.regs.set(Reg::Rcx, u64::from(arg));
    cpu.regs.rip = STUB_CODE_BASE;

    let mut host: NoopHost = NoopHost;
    let reason: ExitReason = cpu.run(&mut host, NATIVE_STEP_CAP).ok()?;
    match reason {
        ExitReason::JumpedOutOfRange { to, .. } if to == u64::from(STUB_RETURN_SENTINEL) => {
            Some(i64::from(cpu.regs.read_sized(Reg::Rax, 32) as u32 as i32))
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn native_stub_evaluates_first_real_predicate() {
        let code: [u8; 48] = [
            0x89, 0xe0, 0x53, 0x57, 0x56, 0x29, 0xe0, 0x83, 0xf8, 0x18, 0x74, 0x07, 0x8b, 0x44,
            0x24, 0x10, 0x50, 0xeb, 0x01, 0x51, 0x58, 0x69, 0xc0, 0x6d, 0x0a, 0x0b, 0xf5, 0xf7,
            0xd8, 0xb9, 0x20, 0x95, 0x97, 0x08, 0x81, 0xc1, 0x49, 0x6a, 0xcd, 0x8b, 0x29, 0xc8,
            0xf7, 0xd0, 0x5e, 0x5f, 0x5b, 0xc3,
        ];
        let out: Option<i64> = run_native(&code, 0x1234_5678);
        let x: u32 = 0x1234_5678;
        let prod: u32 = x.wrapping_mul(0xf50b_0a6d);
        let negv: u32 = 0u32.wrapping_sub(prod);
        let ck: u32 = 0x0897_9520u32.wrapping_add(0x8bcd_6a49);
        let sub: u32 = negv.wrapping_sub(ck);
        let expect: i32 = !sub as i32;
        assert_eq!(out, Some(i64::from(expect)), "got {out:?}");
    }
}
