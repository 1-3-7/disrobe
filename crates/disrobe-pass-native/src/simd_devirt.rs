use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::arch::{Arch, DisasmInsn, disassemble};
use crate::error::{Error, Result};
use crate::pseudo_c::{Abi, LeafRecovery, Reg};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ElemWidth {
    W8,
    W16,
    W32,
    W64,
}

impl ElemWidth {
    pub(crate) const fn bits(self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    pub(crate) const fn bytes(self) -> u64 {
        (self.bits() / 8) as u64
    }

    pub(crate) const fn mask(self) -> u64 {
        match self {
            Self::W64 => u64::MAX,
            _ => (1u64 << self.bits()) - 1,
        }
    }

    pub(crate) const fn c_uint(self) -> &'static str {
        match self {
            Self::W8 => "uint8_t",
            Self::W16 => "uint16_t",
            Self::W32 => "uint32_t",
            Self::W64 => "uint64_t",
        }
    }

    pub(crate) const fn c_int(self) -> &'static str {
        match self {
            Self::W8 => "int8_t",
            Self::W16 => "int16_t",
            Self::W32 => "int32_t",
            Self::W64 => "int64_t",
        }
    }

    pub(crate) const fn from_bytes(bytes: u64) -> Option<Self> {
        match bytes {
            1 => Some(Self::W8),
            2 => Some(Self::W16),
            4 => Some(Self::W32),
            8 => Some(Self::W64),
            _ => None,
        }
    }

    fn sign_extend(self, value: u64) -> i64 {
        let masked: u64 = value & self.mask();
        let shift: u32 = 64 - self.bits();
        ((masked << shift) as i64) >> shift
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RingOp {
    Add,
    Mul,
    And,
    Or,
    Xor,
    SMin,
    SMax,
    UMin,
    UMax,
}

impl RingOp {
    pub(crate) const fn identity(self, width: ElemWidth) -> u64 {
        let mask: u64 = width.mask();
        match self {
            Self::Add | Self::Or | Self::Xor | Self::UMax => 0,
            Self::Mul => 1 & mask,
            Self::And | Self::UMin => mask,
            Self::SMin => mask >> 1,
            Self::SMax => (mask >> 1) + 1,
        }
    }

    pub(crate) fn apply(self, lhs: u64, rhs: u64, width: ElemWidth) -> u64 {
        let mask: u64 = width.mask();
        let a: u64 = lhs & mask;
        let b: u64 = rhs & mask;
        match self {
            Self::Add => a.wrapping_add(b) & mask,
            Self::Mul => a.wrapping_mul(b) & mask,
            Self::And => a & b,
            Self::Or => a | b,
            Self::Xor => a ^ b,
            Self::UMin => a.min(b),
            Self::UMax => a.max(b),
            Self::SMin => (width.sign_extend(a).min(width.sign_extend(b)) as u64) & mask,
            Self::SMax => (width.sign_extend(a).max(width.sign_extend(b)) as u64) & mask,
        }
    }

    pub(crate) const fn is_associative_commutative(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Mul
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::SMin
                | Self::SMax
                | Self::UMin
                | Self::UMax
        )
    }

    pub(crate) const fn c_infix(self) -> Option<&'static str> {
        match self {
            Self::Add => Some("+"),
            Self::Mul => Some("*"),
            Self::And => Some("&"),
            Self::Or => Some("|"),
            Self::Xor => Some("^"),
            Self::SMin | Self::SMax | Self::UMin | Self::UMax => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Term {
    Var(u32),
    Const(u64),
    App {
        op: RingOp,
        width: ElemWidth,
        args: Vec<Self>,
    },
}

impl Term {
    pub(crate) fn app(op: RingOp, width: ElemWidth, args: Vec<Self>) -> Self {
        Self::App { op, width, args }
    }

    pub(crate) fn normalize(&self) -> Self {
        match self {
            Self::Var(_) | Self::Const(_) => self.clone(),
            Self::App { op, width, args } => Self::normalize_app(*op, *width, args),
        }
    }

    fn normalize_app(op: RingOp, width: ElemWidth, args: &[Self]) -> Self {
        let mut flat: Vec<Self> = Vec::with_capacity(args.len());
        for arg in args {
            match arg.normalize() {
                Self::App {
                    op: inner_op,
                    width: inner_width,
                    args: inner_args,
                } if inner_op == op && inner_width == width => flat.extend(inner_args),
                other => flat.push(other),
            }
        }
        let identity: u64 = op.identity(width);
        let mut folded: Option<u64> = None;
        let mut symbolic: Vec<Self> = Vec::with_capacity(flat.len());
        for term in flat {
            if let Self::Const(value) = term {
                folded = Some(folded.map_or_else(
                    || value & width.mask(),
                    |acc: u64| op.apply(acc, value, width),
                ));
            } else {
                symbolic.push(term);
            }
        }
        symbolic.sort_unstable();
        if let Some(value) = folded
            && (value != identity || symbolic.is_empty())
        {
            symbolic.push(Self::Const(value));
            symbolic.sort_unstable();
        }
        match symbolic.len() {
            0 => Self::Const(identity),
            1 => symbolic.into_iter().next().unwrap_or(Self::Const(identity)),
            _ => Self::App {
                op,
                width,
                args: symbolic,
            },
        }
    }
}

pub(crate) fn fold_terms(op: RingOp, width: ElemWidth, lanes: &[Term]) -> Term {
    let mut args: Vec<Term> = Vec::with_capacity(lanes.len() + 1);
    args.push(Term::Const(op.identity(width)));
    args.extend(lanes.iter().cloned());
    Term::app(op, width, args).normalize()
}

pub(crate) fn terms_equivalent(left: &Term, right: &Term) -> bool {
    left.normalize() == right.normalize()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mem {
    pub(crate) base: Option<Reg>,
    pub(crate) index: Option<(Reg, u8)>,
    pub(crate) disp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Gpr { reg: Reg, bytes: u8 },
    Xmm(u8),
    Mem(Mem),
    Imm(i64),
    Rel(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) addr: u64,
    pub(crate) mnem: String,
    pub(crate) ops: Vec<Operand>,
}

impl Insn {
    pub(crate) fn gpr(&self, i: usize) -> Option<(Reg, u8)> {
        match self.ops.get(i)? {
            Operand::Gpr { reg, bytes } => Some((*reg, *bytes)),
            _ => None,
        }
    }

    pub(crate) fn xmm(&self, i: usize) -> Option<u8> {
        match self.ops.get(i)? {
            Operand::Xmm(x) => Some(*x),
            _ => None,
        }
    }

    pub(crate) fn mem(&self, i: usize) -> Option<Mem> {
        match self.ops.get(i)? {
            Operand::Mem(m) => Some(*m),
            _ => None,
        }
    }

    pub(crate) fn imm(&self, i: usize) -> Option<i64> {
        match self.ops.get(i)? {
            Operand::Imm(v) => Some(*v),
            _ => None,
        }
    }

    pub(crate) fn rel(&self, i: usize) -> Option<u64> {
        match self.ops.get(i)? {
            Operand::Rel(v) => Some(*v),
            _ => None,
        }
    }
}

fn parse_gpr(token: &str) -> Option<(Reg, u8)> {
    let (reg, bytes): (Reg, u8) = match token.trim() {
        "rax" => (Reg::Rax, 8),
        "eax" => (Reg::Rax, 4),
        "ax" => (Reg::Rax, 2),
        "al" => (Reg::Rax, 1),
        "rbx" => (Reg::Rbx, 8),
        "ebx" => (Reg::Rbx, 4),
        "bx" => (Reg::Rbx, 2),
        "bl" => (Reg::Rbx, 1),
        "rcx" => (Reg::Rcx, 8),
        "ecx" => (Reg::Rcx, 4),
        "cx" => (Reg::Rcx, 2),
        "cl" => (Reg::Rcx, 1),
        "rdx" => (Reg::Rdx, 8),
        "edx" => (Reg::Rdx, 4),
        "dx" => (Reg::Rdx, 2),
        "dl" => (Reg::Rdx, 1),
        "rsi" => (Reg::Rsi, 8),
        "esi" => (Reg::Rsi, 4),
        "si" => (Reg::Rsi, 2),
        "sil" => (Reg::Rsi, 1),
        "rdi" => (Reg::Rdi, 8),
        "edi" => (Reg::Rdi, 4),
        "di" => (Reg::Rdi, 2),
        "dil" => (Reg::Rdi, 1),
        "rbp" => (Reg::Rbp, 8),
        "ebp" => (Reg::Rbp, 4),
        "rsp" => (Reg::Rsp, 8),
        "esp" => (Reg::Rsp, 4),
        "r8" => (Reg::R8, 8),
        "r8d" => (Reg::R8, 4),
        "r8w" => (Reg::R8, 2),
        "r8b" => (Reg::R8, 1),
        "r9" => (Reg::R9, 8),
        "r9d" => (Reg::R9, 4),
        "r9w" => (Reg::R9, 2),
        "r9b" => (Reg::R9, 1),
        "r10" => (Reg::R10, 8),
        "r10d" => (Reg::R10, 4),
        "r11" => (Reg::R11, 8),
        "r11d" => (Reg::R11, 4),
        "r12" => (Reg::R12, 8),
        "r12d" => (Reg::R12, 4),
        "r13" => (Reg::R13, 8),
        "r13d" => (Reg::R13, 4),
        "r14" => (Reg::R14, 8),
        "r14d" => (Reg::R14, 4),
        "r15" => (Reg::R15, 8),
        "r15d" => (Reg::R15, 4),
        _ => return None,
    };
    Some((reg, bytes))
}

fn parse_imm(token: &str) -> Option<i64> {
    let t: &str = token.trim();
    let (neg, body): (bool, &str) = t
        .strip_prefix('-')
        .map_or((false, t), |rest: &str| (true, rest.trim()));
    let hex_body: Option<&str> = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .or_else(|| body.strip_suffix('h').or_else(|| body.strip_suffix('H')));
    let value: i64 = if let Some(hex) = hex_body {
        i64::from_str_radix(hex, 16)
            .ok()
            .or_else(|| u64::from_str_radix(hex, 16).ok().map(|u: u64| u as i64))?
    } else {
        body.parse::<i64>().ok()?
    };
    Some(if neg { -value } else { value })
}

fn parse_mem(bracketed: &str) -> Option<Mem> {
    let inner: &str = bracketed
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')?
        .trim();
    let mut base: Option<Reg> = None;
    let mut index: Option<(Reg, u8)> = None;
    let mut disp: i64 = 0;
    let mut rest: String = inner.replace('-', "+-");
    if rest.starts_with("+-") {
        rest.remove(0);
    }
    for raw_term in rest.split('+') {
        let term: &str = raw_term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((reg_tok, scale_tok)) = term.split_once('*') {
            let (reg, bytes): (Reg, u8) = parse_gpr(reg_tok.trim())?;
            if bytes != 8 {
                return None;
            }
            let scale: u8 = scale_tok.trim().parse::<u8>().ok()?;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return None;
            }
            index = Some((reg, scale));
            continue;
        }
        if let Some((reg, bytes)) = parse_gpr(term) {
            if bytes != 8 {
                return None;
            }
            if base.is_none() {
                base = Some(reg);
            } else if index.is_none() {
                index = Some((reg, 1));
            } else {
                return None;
            }
            continue;
        }
        disp = disp.checked_add(parse_imm(term)?)?;
    }
    Some(Mem { base, index, disp })
}

fn strip_size_keyword(token: &str) -> &str {
    let t: &str = token.trim();
    for kw in ["byte", "word", "dword", "qword", "xmmword", "oword"] {
        if let Some(rest) = t.strip_prefix(kw) {
            return rest.trim();
        }
    }
    t
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    let trimmed: &str = operands.trim();
    let t: &str = trimmed
        .strip_prefix("short")
        .or_else(|| trimmed.strip_prefix("near"))
        .unwrap_or(trimmed)
        .trim();
    let body: &str = t
        .strip_suffix('h')
        .or_else(|| t.strip_suffix('H'))
        .unwrap_or(t);
    u64::from_str_radix(body, 16).ok()
}

fn parse_operand(token: &str) -> Option<Operand> {
    let raw: &str = strip_size_keyword(token);
    if raw.starts_with('[') {
        return parse_mem(raw).map(Operand::Mem);
    }
    if let Some(rest) = raw.strip_prefix("xmm")
        && let Ok(idx) = rest.trim().parse::<u8>()
        && idx < 16
    {
        return Some(Operand::Xmm(idx));
    }
    if let Some((reg, bytes)) = parse_gpr(raw) {
        return Some(Operand::Gpr { reg, bytes });
    }
    parse_imm(raw).map(Operand::Imm)
}

fn split_operands(operands: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: usize = 0;
    for (i, ch) in operands.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(operands[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail: &str = operands[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

const BRANCH_MNEMONICS: &[&str] = &[
    "jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae", "js",
    "jns", "jo", "jno", "jp", "jnp", "jc", "jnc",
];

pub(crate) fn parse_insn(insn: &DisasmInsn) -> Insn {
    let mnem: &str = insn.mnemonic.trim();
    if BRANCH_MNEMONICS.contains(&mnem) {
        let ops: Vec<Operand> = parse_branch_target(&insn.operands)
            .map(|t: u64| vec![Operand::Rel(t)])
            .unwrap_or_default();
        return Insn {
            addr: insn.address,
            mnem: mnem.to_owned(),
            ops,
        };
    }
    let ops: Vec<Operand> = split_operands(&insn.operands)
        .into_iter()
        .filter_map(parse_operand)
        .collect();
    Insn {
        addr: insn.address,
        mnem: mnem.to_owned(),
        ops,
    }
}

const SYSV_ARGS: [Reg; 6] = [Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9];
const MSX64_ARGS: [Reg; 4] = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];

fn arg_order(abi: Abi) -> &'static [Reg] {
    match abi {
        Abi::SysV => &SYSV_ARGS,
        Abi::MsX64 => &MSX64_ARGS,
        Abi::Aapcs64 => &[],
    }
}

fn arg_index(abi: Abi, reg: Reg) -> Option<usize> {
    arg_order(abi).iter().position(|r: &Reg| *r == reg)
}

fn packed_op_ringop(mnem: &str) -> Option<(RingOp, Option<ElemWidth>)> {
    Some(match mnem {
        "paddb" => (RingOp::Add, Some(ElemWidth::W8)),
        "paddw" => (RingOp::Add, Some(ElemWidth::W16)),
        "paddd" => (RingOp::Add, Some(ElemWidth::W32)),
        "paddq" => (RingOp::Add, Some(ElemWidth::W64)),
        "pxor" => (RingOp::Xor, None),
        "por" => (RingOp::Or, None),
        "pand" => (RingOp::And, None),
        "pmulld" => (RingOp::Mul, Some(ElemWidth::W32)),
        "pmaxsd" | "vsmaxd" => (RingOp::SMax, Some(ElemWidth::W32)),
        "pminsd" | "vsmind" => (RingOp::SMin, Some(ElemWidth::W32)),
        "pmaxud" => (RingOp::UMax, Some(ElemWidth::W32)),
        "pminud" => (RingOp::UMin, Some(ElemWidth::W32)),
        "pmaxsw" | "vsmaxw" => (RingOp::SMax, Some(ElemWidth::W16)),
        "pminsw" | "vsminw" => (RingOp::SMin, Some(ElemWidth::W16)),
        "pmaxub" => (RingOp::UMax, Some(ElemWidth::W8)),
        "pminub" => (RingOp::UMin, Some(ElemWidth::W8)),
        _ => return None,
    })
}

fn pcmpgt_width(mnem: &str) -> Option<ElemWidth> {
    match mnem {
        "pcmpgtb" => Some(ElemWidth::W8),
        "pcmpgtw" => Some(ElemWidth::W16),
        "pcmpgtd" => Some(ElemWidth::W32),
        _ => None,
    }
}

fn signed_minmax_mnemonic(is_max: bool, width: ElemWidth) -> &'static str {
    match (is_max, width) {
        (true, ElemWidth::W8) => "vsmaxb",
        (true, ElemWidth::W16) => "vsmaxw",
        (true, _) => "vsmaxd",
        (false, ElemWidth::W8) => "vsminb",
        (false, ElemWidth::W16) => "vsminw",
        (false, _) => "vsmind",
    }
}

fn virt(addr: u64, mnem: &str, dst: u8, src: u8) -> Insn {
    Insn {
        addr,
        mnem: mnem.to_owned(),
        ops: vec![Operand::Xmm(dst), Operand::Xmm(src)],
    }
}

fn match_blend_inplace(w: &[Insn]) -> Option<Insn> {
    let [i0, i1, i2, i3, i4, i5] = w else {
        return None;
    };
    if i0.mnem != "movdqa"
        || i2.mnem != "pand"
        || i3.mnem != "pandn"
        || i4.mnem != "movdqa"
        || i5.mnem != "por"
    {
        return None;
    }
    let width: ElemWidth = pcmpgt_width(&i1.mnem)?;
    let (tmp, cmp_a): (u8, u8) = (i0.xmm(0)?, i0.xmm(1)?);
    let cmp_b: u8 = if i1.xmm(0)? == tmp {
        i1.xmm(1)?
    } else {
        return None;
    };
    let load: u8 = if i2.xmm(1)? == tmp {
        i2.xmm(0)?
    } else {
        return None;
    };
    let accum: u8 = if i3.xmm(0)? == tmp {
        i3.xmm(1)?
    } else {
        return None;
    };
    if i4.xmm(0)? != accum || i4.xmm(1)? != tmp || i5.xmm(0)? != accum || i5.xmm(1)? != load {
        return None;
    }
    let is_max: bool = cmp_a == load && cmp_b == accum;
    let is_min: bool = cmp_a == accum && cmp_b == load;
    if !is_max && !is_min {
        return None;
    }
    Some(virt(
        i0.addr,
        signed_minmax_mnemonic(is_max, width),
        accum,
        load,
    ))
}

fn match_blend_out(w: &[Insn]) -> Option<(Insn, Insn)> {
    let [i0, i1, i2, i3, i4] = w else {
        return None;
    };
    if i0.mnem != "movdqa" || i2.mnem != "pand" || i3.mnem != "pandn" || i4.mnem != "por" {
        return None;
    }
    let width: ElemWidth = pcmpgt_width(&i1.mnem)?;
    let (tmp, cmp_a): (u8, u8) = (i0.xmm(0)?, i0.xmm(1)?);
    let cmp_b: u8 = if i1.xmm(0)? == tmp {
        i1.xmm(1)?
    } else {
        return None;
    };
    let kept: u8 = if i2.xmm(1)? == tmp {
        i2.xmm(0)?
    } else {
        return None;
    };
    let other: u8 = if i3.xmm(0)? == tmp {
        i3.xmm(1)?
    } else {
        return None;
    };
    let result: u8 = if i4.xmm(1)? == kept && i4.xmm(0)? == tmp {
        tmp
    } else {
        return None;
    };
    let is_max: bool = cmp_a == kept && cmp_b == other;
    let is_min: bool = cmp_a == other && cmp_b == kept;
    if !is_max && !is_min {
        return None;
    }
    Some((
        virt(i0.addr, "movdqa", result, kept),
        virt(
            i0.addr,
            signed_minmax_mnemonic(is_max, width),
            result,
            other,
        ),
    ))
}

fn match_blend_movdqa_min(w: &[Insn]) -> Option<Insn> {
    let [i0, i1, i2, i3, i4] = w else {
        return None;
    };
    if i0.mnem != "movdqa" || i3.mnem != "pandn" || i4.mnem != "por" {
        return None;
    }
    let width: ElemWidth = pcmpgt_width(&i1.mnem)?;
    let (tmp, other): (u8, u8) = (i0.xmm(0)?, i0.xmm(1)?);
    if i1.xmm(0)? != tmp {
        return None;
    }
    let cmp_b: u8 = i1.xmm(1)?;
    if i2.mnem != "pand" || i2.xmm(0)? != cmp_b || i2.xmm(1)? != tmp {
        return None;
    }
    if i3.xmm(0)? != tmp || i3.xmm(1)? != other {
        return None;
    }
    if i4.xmm(0)? != cmp_b || i4.xmm(1)? != tmp {
        return None;
    }
    Some(virt(
        i0.addr,
        signed_minmax_mnemonic(false, width),
        cmp_b,
        other,
    ))
}

fn match_blend_dup_load(w: &[Insn]) -> Option<(usize, Insn)> {
    let i0: &Insn = w.first()?;
    let i1: &Insn = w.get(1)?;
    if !matches!(i0.mnem.as_str(), "movdqu" | "movdqa")
        || !matches!(i1.mnem.as_str(), "movdqu" | "movdqa")
    {
        return None;
    }
    if i0.mem(1)? != i1.mem(1)? {
        return None;
    }
    let (l1, l2): (u8, u8) = (i0.xmm(0)?, i1.xmm(0)?);
    if l1 == l2 {
        return None;
    }
    let rest: &[Insn] = w.get(2..)?;
    let pcmpgtd_off: usize = rest
        .iter()
        .position(|insn: &Insn| pcmpgt_width(&insn.mnem).is_some())?;
    if rest
        .get(..pcmpgtd_off)?
        .iter()
        .any(|skipped: &Insn| skipped.xmm(0).is_some())
    {
        return None;
    }
    let [i2, i3, i4, i5] = rest.get(pcmpgtd_off..pcmpgtd_off + 4)? else {
        return None;
    };
    let width: ElemWidth = pcmpgt_width(&i2.mnem)?;
    let (mask, cmp_b): (u8, u8) = (i2.xmm(0)?, i2.xmm(1)?);
    if mask != l1 {
        return None;
    }
    if i3.mnem != "pand" || i3.xmm(0)? != cmp_b || i3.xmm(1)? != mask {
        return None;
    }
    if i4.mnem != "pandn" || i4.xmm(0)? != mask || i4.xmm(1)? != l2 {
        return None;
    }
    if i5.mnem != "por" || i5.xmm(0)? != cmp_b || i5.xmm(1)? != mask {
        return None;
    }
    let consumed: usize = 2 + pcmpgtd_off + 4;
    Some((
        consumed,
        virt(i2.addr, signed_minmax_mnemonic(false, width), cmp_b, l2),
    ))
}

fn collapse_blends(insns: &[Insn]) -> Vec<Insn> {
    let mut out: Vec<Insn> = Vec::with_capacity(insns.len());
    let mut i: usize = 0;
    while i < insns.len() {
        if let Some(window) = insns.get(i..i + 6)
            && let Some(folded) = match_blend_inplace(window)
        {
            out.push(folded);
            i += 6;
            continue;
        }
        if let Some(window) = insns.get(i..i + 9)
            && let Some((consumed, folded)) = match_blend_dup_load(window)
        {
            out.push(window[0].clone());
            out.push(window[1].clone());
            out.extend_from_slice(&window[2..consumed - 4]);
            out.push(folded);
            i += consumed;
            continue;
        }
        if let Some(window) = insns.get(i..i + 5)
            && let Some((mov, op)) = match_blend_out(window)
        {
            out.push(mov);
            out.push(op);
            i += 5;
            continue;
        }
        if let Some(window) = insns.get(i..i + 5)
            && let Some(folded) = match_blend_movdqa_min(window)
        {
            out.push(folded);
            i += 5;
            continue;
        }
        out.push(insns[i].clone());
        i += 1;
    }
    out
}

fn scalar_op_ringop(mnem: &str) -> Option<RingOp> {
    Some(match mnem {
        "add" => RingOp::Add,
        "xor" => RingOp::Xor,
        "or" => RingOp::Or,
        "and" => RingOp::And,
        _ => return None,
    })
}

fn pshufd_lane_perm(imm: u8, lanes: usize) -> Option<Vec<usize>> {
    match lanes {
        4 => Some(
            (0..4)
                .map(|out: usize| usize::from((imm >> (2 * out)) & 3))
                .collect(),
        ),
        2 => {
            let mut perm: Vec<usize> = Vec::with_capacity(2);
            for out in 0..2 {
                let d0: u8 = (imm >> (4 * out)) & 3;
                let d1: u8 = (imm >> (4 * out + 2)) & 3;
                if d1 != d0 + 1 || d0 % 2 != 0 {
                    return None;
                }
                perm.push(usize::from(d0 / 2));
            }
            Some(perm)
        }
        8 | 16 => {
            let sub: usize = lanes / 4;
            let mut perm: Vec<usize> = Vec::with_capacity(lanes);
            for out_dword in 0..4 {
                let src_dword: usize = usize::from((imm >> (2 * out_dword)) & 3);
                for k in 0..sub {
                    perm.push(src_dword * sub + k);
                }
            }
            Some(perm)
        }
        _ => None,
    }
}

fn shift_right_logical_lanes(
    cur: &[Term],
    dword_bits: u32,
    width: ElemWidth,
    shift_bits: u64,
) -> Option<Vec<Term>> {
    if shift_bits % u64::from(width.bits()) != 0 {
        return None;
    }
    let shift_sub: usize = usize::try_from(shift_bits / u64::from(width.bits())).ok()?;
    let dpl: usize = (dword_bits / width.bits()) as usize;
    if dpl == 0 || shift_sub >= dpl || cur.len() % dpl != 0 {
        return None;
    }
    let ngroups: usize = cur.len() / dpl;
    let mut out: Vec<Term> = Vec::with_capacity(cur.len());
    for g in 0..ngroups {
        for i in 0..dpl {
            let src_i: usize = i + shift_sub;
            out.push(if src_i < dpl {
                cur[g * dpl + src_i].clone()
            } else {
                Term::Const(0)
            });
        }
    }
    Some(out)
}

fn addr_index(insns: &[Insn], addr: u64) -> Option<usize> {
    insns.iter().position(|i: &Insn| i.addr == addr)
}

fn is_back_edge(insn: &Insn) -> Option<u64> {
    if BRANCH_MNEMONICS.contains(&insn.mnem.as_str()) {
        let target: u64 = insn.rel(0)?;
        if target <= insn.addr {
            return Some(target);
        }
    }
    None
}

fn find_back_edges(insns: &[Insn]) -> Vec<(usize, usize)> {
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (idx, insn) in insns.iter().enumerate() {
        if let Some(target) = is_back_edge(insn)
            && let Some(header) = addr_index(insns, target)
        {
            edges.push((header, idx));
        }
    }
    edges
}

#[derive(Debug, Clone)]
struct VectorLoop {
    op: RingOp,
    width: ElemWidth,
    base_reg: Reg,
    step: i64,
    count_reg: Reg,
    accumulators: Vec<u8>,
    elem_offset: i64,
    header_idx: usize,
    back_idx: usize,
}

impl VectorLoop {
    fn lanes_per_reg(&self) -> usize {
        (16 / self.width.bytes()) as usize
    }

    fn total_lanes(&self) -> usize {
        self.accumulators.len() * self.lanes_per_reg()
    }
}

fn analyze_vector_loop(insns: &[Insn], header: usize, back: usize) -> Option<VectorLoop> {
    let body: &[Insn] = insns.get(header..=back)?;
    let mut loads: BTreeMap<u8, (Reg, Reg, u8, i64)> = BTreeMap::new();
    for insn in body {
        if matches!(insn.mnem.as_str(), "movdqu" | "movdqa")
            && let (Some(dst), Some(mem)) = (insn.xmm(0), insn.mem(1))
            && let (Some(base), Some((idx, scale))) = (mem.base, mem.index)
        {
            loads.insert(dst, (base, idx, scale, mem.disp));
        }
    }
    let mut op: Option<(RingOp, ElemWidth)> = None;
    let mut accum_disp: BTreeMap<u8, i64> = BTreeMap::new();
    let mut base_reg: Option<Reg> = None;
    let mut idx_reg: Option<Reg> = None;
    for insn in body {
        let Some((ring, width_hint)) = packed_op_ringop(&insn.mnem) else {
            continue;
        };
        let (Some(dst), Some(src)) = (insn.xmm(0), insn.xmm(1)) else {
            continue;
        };
        let Some(&(lbase, lidx, scale, disp)) = loads.get(&src) else {
            continue;
        };
        let width: ElemWidth =
            width_hint.map_or_else(|| ElemWidth::from_bytes(u64::from(scale)), Some)?;
        if width.bytes() != u64::from(scale) {
            return None;
        }
        if let Some((prev_op, prev_w)) = op
            && (prev_op != ring || prev_w != width)
        {
            return None;
        }
        op = Some((ring, width));
        if *base_reg.get_or_insert(lbase) != lbase || *idx_reg.get_or_insert(lidx) != lidx {
            return None;
        }
        accum_disp.insert(dst, disp);
    }
    let (op, width): (RingOp, ElemWidth) = op?;
    let base_reg: Reg = base_reg?;
    let idx_reg: Reg = idx_reg?;
    let step: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == idx_reg => Some(v),
                _ => None,
            })?;
    let count_reg: Reg = cmp_other_reg(body, idx_reg)?;
    let mut accumulators: Vec<u8> = accum_disp.keys().copied().collect();
    accumulators.sort_unstable();
    let lanes_per_reg: usize = (16 / width.bytes()) as usize;
    let elem_bytes: i64 = i64::try_from(width.bytes()).ok()?;
    let mut starts: Vec<i64> = accum_disp.values().map(|d: &i64| d / elem_bytes).collect();
    if accum_disp.values().any(|d: &i64| d % elem_bytes != 0) {
        return None;
    }
    starts.sort_unstable();
    let elem_offset: i64 = *starts.first()?;
    let expected: Vec<i64> = (0..accumulators.len())
        .map(|k: usize| elem_offset + (k * lanes_per_reg) as i64)
        .collect();
    if starts != expected {
        return None;
    }
    Some(VectorLoop {
        op,
        width,
        base_reg,
        step,
        count_reg,
        accumulators,
        elem_offset,
        header_idx: header,
        back_idx: back,
    })
}

fn cmp_other_reg(body: &[Insn], idx_reg: Reg) -> Option<Reg> {
    body.iter().rev().find_map(|i: &Insn| {
        if i.mnem != "cmp" {
            return None;
        }
        match (i.gpr(0), i.gpr(1)) {
            (Some((a, _)), Some((b, _))) if a == idx_reg => Some(b),
            (Some((a, _)), Some((b, _))) if b == idx_reg => Some(a),
            _ => None,
        }
    })
}

#[derive(Debug, Clone, Copy)]
struct Remainder {
    op: RingOp,
    width: ElemWidth,
    len_reg: Reg,
    acc_bytes: u8,
}

fn analyze_remainder(
    insns: &[Insn],
    header: usize,
    back: usize,
    base_reg: Reg,
) -> Option<Remainder> {
    let body: &[Insn] = insns.get(header..=back)?;
    if body
        .iter()
        .any(|i: &Insn| packed_op_ringop(&i.mnem).is_some())
    {
        return None;
    }
    let mut found: Option<(RingOp, ElemWidth, u8, Reg)> = None;
    for insn in body {
        let Some(op) = scalar_op_ringop(&insn.mnem) else {
            continue;
        };
        let (Some((_, bytes)), Some(mem)) = (insn.gpr(0), insn.mem(1)) else {
            continue;
        };
        let (Some(mbase), Some((midx, scale))) = (mem.base, mem.index) else {
            continue;
        };
        if mbase != base_reg {
            continue;
        }
        let width: ElemWidth = ElemWidth::from_bytes(u64::from(scale))?;
        found = Some((op, width, bytes, midx));
        break;
    }
    let (op, width, acc_bytes, idx): (RingOp, ElemWidth, u8, Reg) = found?;
    let has_inc: bool = body
        .iter()
        .any(|i: &Insn| match (i.mnem.as_str(), i.gpr(0)) {
            ("inc", Some((r, _))) if r == idx => true,
            ("add", Some((r, _))) if r == idx => i.imm(1) == Some(1),
            _ => false,
        });
    if !has_inc {
        return None;
    }
    let len_reg: Reg = cmp_other_reg(body, idx)?;
    Some(Remainder {
        op,
        width,
        len_reg,
        acc_bytes,
    })
}

fn verify_mask(insns: &[Insn], count_reg: Reg, len_reg: Reg, vf: i64) -> Option<()> {
    let and_idx: usize = insns.iter().position(|i: &Insn| {
        i.mnem == "and"
            && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(count_reg)
            && i.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
    })?;
    let constant: i64 = insns.get(..and_idx)?.iter().rev().find_map(|i: &Insn| {
        (i.mnem == "mov" && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(count_reg))
            .then(|| i.imm(1))?
    })?;
    let c: u64 = constant.cast_unsigned();
    let low: u64 = vf.cast_unsigned().checked_sub(1)?;
    if c & low != 0 {
        return None;
    }
    let missing: u64 = !c & !low;
    (missing == 0 || missing == 1u64 << 63).then_some(())
}

fn verify_acc_init(insns: &[Insn], vloop: &VectorLoop) -> Option<()> {
    if vloop.op.identity(vloop.width) != 0 {
        return None;
    }
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    for &acc in &vloop.accumulators {
        let inited: bool = prefix
            .iter()
            .any(|i: &Insn| i.mnem == "pxor" && i.xmm(0) == Some(acc) && i.xmm(1) == Some(acc));
        if !inited {
            return None;
        }
    }
    Some(())
}

fn verify_epilog(
    insns: &[Insn],
    back_idx: usize,
    op: RingOp,
    width: ElemWidth,
    accumulators: &[u8],
) -> Option<()> {
    let lpr: usize = (16 / width.bytes()) as usize;
    let total: usize = accumulators.len() * lpr;
    let mut regs: BTreeMap<u8, Vec<Term>> = BTreeMap::new();
    for (k, &acc) in accumulators.iter().enumerate() {
        let vars: Vec<Term> = (0..lpr)
            .map(|l: usize| Term::Var((k * lpr + l) as u32))
            .collect();
        regs.insert(acc, vars);
    }
    for insn in insns.get(back_idx + 1..)? {
        match insn.mnem.as_str() {
            "movd" | "movq" | "pextrw" | "pextrd" | "pextrq" => {
                let src: u8 = insn.xmm(1)?;
                let lane: usize = match insn.mnem.as_str() {
                    "movd" | "movq" => 0,
                    _ => usize::try_from(insn.imm(2)? & 0xff).ok()?,
                };
                let got: Term = regs.get(&src)?.get(lane)?.clone();
                let all: Vec<Term> = (0..total).map(|i: usize| Term::Var(i as u32)).collect();
                let want: Term = fold_terms(op, width, &all);
                return terms_equivalent(&got, &want).then_some(());
            }
            "movdqa" => {
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let value: Vec<Term> = regs.get(&src)?.clone();
                regs.insert(dst, value);
            }
            "psrldq" => {
                let dst: u8 = insn.xmm(0)?;
                let shift_bytes: u64 = u64::try_from(insn.imm(1)? & 0xff).ok()?;
                let elem_bytes: u64 = width.bytes();
                if shift_bytes % elem_bytes != 0 {
                    return None;
                }
                let lane_shift: usize = usize::try_from(shift_bytes / elem_bytes).ok()?;
                let cur: Vec<Term> = regs.get(&dst)?.clone();
                let shifted: Vec<Term> = (0..cur.len())
                    .map(|i: usize| cur.get(i + lane_shift).cloned().unwrap_or(Term::Const(0)))
                    .collect();
                regs.insert(dst, shifted);
            }
            "pshufd" => {
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let imm: u8 = u8::try_from(insn.imm(2)? & 0xff).ok()?;
                let perm: Vec<usize> = pshufd_lane_perm(imm, lpr)?;
                let source: Vec<Term> = regs.get(&src)?.clone();
                let permuted: Vec<Term> = perm
                    .iter()
                    .map(|&p: &usize| source.get(p).cloned())
                    .collect::<Option<Vec<Term>>>()?;
                regs.insert(dst, permuted);
            }
            "psrlw" | "psrld" | "psrlq" => {
                let dst: u8 = insn.xmm(0)?;
                let shift_bits: u64 = u64::try_from(insn.imm(1)? & 0xff).ok()?;
                let dword_bits: u32 = match insn.mnem.as_str() {
                    "psrlw" => 16,
                    "psrld" => 32,
                    _ => 64,
                };
                let cur: Vec<Term> = regs.get(&dst)?.clone();
                let shifted: Vec<Term> =
                    shift_right_logical_lanes(&cur, dword_bits, width, shift_bits)?;
                regs.insert(dst, shifted);
            }
            other => {
                let Some((ring, _)): Option<(RingOp, Option<ElemWidth>)> = packed_op_ringop(other)
                else {
                    if insn.xmm(0).is_some() || BRANCH_MNEMONICS.contains(&other) {
                        return None;
                    }
                    continue;
                };
                if ring != op {
                    return None;
                }
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let source: Vec<Term> = regs.get(&src)?.clone();
                let dest: Vec<Term> = regs.get(&dst)?.clone();
                if dest.len() != source.len() {
                    return None;
                }
                let combined: Vec<Term> = dest
                    .into_iter()
                    .zip(source)
                    .map(|(a, b): (Term, Term)| Term::app(op, width, vec![a, b]))
                    .collect();
                regs.insert(dst, combined);
            }
        }
    }
    None
}

fn returns_identity_at(insns: &[Insn], addr: u64) -> bool {
    let Some(start) = addr_index(insns, addr) else {
        return false;
    };
    let mut zeroed: bool = false;
    for insn in &insns[start..] {
        match insn.mnem.as_str() {
            "xor" => {
                if let (Some((a, _)), Some((b, _))) = (insn.gpr(0), insn.gpr(1))
                    && a == Reg::Rax
                    && b == Reg::Rax
                {
                    zeroed = true;
                }
            }
            "ret" => return zeroed,
            _ => return false,
        }
    }
    false
}

fn verify_zero_guard(insns: &[Insn], len_reg: Reg) -> Option<()> {
    for (i, insn) in insns.iter().enumerate() {
        let is_test: bool = insn.mnem == "test"
            && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
            && insn.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg);
        if !is_test {
            continue;
        }
        let Some(next) = insns.get(i + 1) else {
            continue;
        };
        if matches!(next.mnem.as_str(), "jle" | "jng")
            && let Some(target) = next.rel(0)
            && returns_identity_at(insns, target)
        {
            return Some(());
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct ReductionForm {
    op: RingOp,
    width: ElemWidth,
    base_reg: Reg,
    len_reg: Reg,
    ret_bytes: u8,
}

fn recognize_reduction(insns: &[Insn]) -> Option<ReductionForm> {
    let edges: Vec<(usize, usize)> = find_back_edges(insns);
    let vloop: VectorLoop = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_vector_loop(insns, h, b))?;
    if !vloop.op.is_associative_commutative() {
        return None;
    }
    if vloop.op.identity(vloop.width) != 0 || vloop.op.c_infix().is_none() {
        return None;
    }
    if vloop.elem_offset != 0 {
        return None;
    }
    if vloop.step <= 0 || usize::try_from(vloop.step).ok()? != vloop.total_lanes() {
        return None;
    }
    if !vloop.step.cast_unsigned().is_power_of_two() {
        return None;
    }
    let rem: Remainder = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_remainder(insns, h, b, vloop.base_reg))?;
    if rem.op != vloop.op || rem.width != vloop.width {
        return None;
    }
    verify_mask(insns, vloop.count_reg, rem.len_reg, vloop.step)?;
    verify_acc_init(insns, &vloop)?;
    verify_epilog(
        insns,
        vloop.back_idx,
        vloop.op,
        vloop.width,
        &vloop.accumulators,
    )?;
    verify_zero_guard(insns, rem.len_reg)?;
    Some(ReductionForm {
        op: vloop.op,
        width: vloop.width,
        base_reg: vloop.base_reg,
        len_reg: rem.len_reg,
        ret_bytes: rem.acc_bytes,
    })
}

fn emit_reduction(form: ReductionForm, abi: Abi, base_pos: usize, len_pos: usize) -> LeafRecovery {
    let nparams: usize = base_pos.max(len_pos) + 1;
    let params: Vec<Reg> = arg_order(abi)[..nparams].to_vec();
    let et: &str = form.width.c_uint();
    let infix: &str = form.op.c_infix().unwrap_or("+");
    let sig: String = (0..nparams)
        .map(|i: usize| format!("uint64_t a{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut source: String = String::new();
    let _ = writeln!(source, "#include <stdint.h>");
    let _ = writeln!(source, "uint64_t recovered({sig}) {{");
    let _ = writeln!(source, "    const {et} *p = (const {et} *)a{base_pos};");
    let _ = writeln!(source, "    int64_t n = (int64_t)a{len_pos};");
    let _ = writeln!(source, "    {et} acc = {};", form.op.identity(form.width));
    let _ = writeln!(source, "    for (int64_t i = 0; i < n; i++) {{");
    let _ = writeln!(source, "        acc = acc {infix} p[i];");
    let _ = writeln!(source, "    }}");
    let _ = writeln!(source, "    return (uint64_t)acc;");
    let _ = writeln!(source, "}}");
    LeafRecovery {
        source,
        rust_source: None,
        return_width_bits: u32::from(form.ret_bytes) * 8,
        param_width_bits: vec![64; params.len()],
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
        call_site_signature: None,
    }
}

#[derive(Debug, Clone)]
struct PtrWalkLoop {
    op: RingOp,
    width: ElemWidth,
    base_reg: Reg,
    end_reg: Reg,
    step_bytes: i64,
    accumulators: Vec<u8>,
    elem_offset: i64,
    header_idx: usize,
    back_idx: usize,
}

fn writes_gpr(insn: &Insn, reg: Reg) -> bool {
    !matches!(insn.mnem.as_str(), "cmp" | "test")
        && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(reg)
}

fn extract_width(mnem: &str) -> Option<ElemWidth> {
    Some(match mnem {
        "movd" | "pextrd" => ElemWidth::W32,
        "movq" | "pextrq" => ElemWidth::W64,
        "pextrw" => ElemWidth::W16,
        "pextrb" => ElemWidth::W8,
        _ => return None,
    })
}

fn analyze_ptrwalk_loop(insns: &[Insn], header: usize, back: usize) -> Option<PtrWalkLoop> {
    let body: &[Insn] = insns.get(header..=back)?;
    let mut loads: BTreeMap<u8, (Reg, i64)> = BTreeMap::new();
    for insn in body {
        if matches!(insn.mnem.as_str(), "movdqu" | "movdqa")
            && let (Some(dst), Some(mem)) = (insn.xmm(0), insn.mem(1))
            && let Some(lbase) = mem.base
            && mem.index.is_none()
        {
            loads.insert(dst, (lbase, mem.disp));
        }
    }
    let mut op: Option<(RingOp, Option<ElemWidth>)> = None;
    let mut accum_disp: BTreeMap<u8, i64> = BTreeMap::new();
    let mut walk: Option<Reg> = None;
    for insn in body {
        let Some((ring, width_hint)) = packed_op_ringop(&insn.mnem) else {
            continue;
        };
        let (Some(dst), Some(src)) = (insn.xmm(0), insn.xmm(1)) else {
            continue;
        };
        let Some(&(lbase, disp)) = loads.get(&src) else {
            continue;
        };
        if let Some((prev_op, prev_hint)) = op
            && (prev_op != ring || prev_hint != width_hint)
        {
            return None;
        }
        op = Some((ring, width_hint));
        if *walk.get_or_insert(lbase) != lbase {
            return None;
        }
        accum_disp.insert(dst, disp);
    }
    let (op, width_hint): (RingOp, Option<ElemWidth>) = op?;
    let walk_reg: Reg = walk?;
    let step_bytes: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == walk_reg => Some(v),
                _ => None,
            })?;
    if step_bytes <= 0 {
        return None;
    }
    let end_reg: Reg = body.iter().rev().find_map(|i: &Insn| {
        if i.mnem != "cmp" {
            return None;
        }
        match (i.gpr(0), i.gpr(1)) {
            (Some((a, _)), Some((b, _))) if a == walk_reg => Some(b),
            (Some((a, _)), Some((b, _))) if b == walk_reg => Some(a),
            _ => None,
        }
    })?;
    if end_reg == walk_reg {
        return None;
    }
    let prefix: &[Insn] = insns.get(..header)?;
    let base_reg: Reg = prefix.iter().rev().find_map(|i: &Insn| {
        (i.mnem == "mov" && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(walk_reg))
            .then(|| i.gpr(1))
            .flatten()
            .map(|(r, _): (Reg, u8)| r)
    })?;
    if base_reg == walk_reg || base_reg == end_reg {
        return None;
    }
    let width: ElemWidth = insns
        .get(back + 1..)?
        .iter()
        .find_map(|i: &Insn| extract_width(&i.mnem))?;
    if let Some(hint) = width_hint
        && hint != width
    {
        return None;
    }
    if accum_disp.len() != 1 {
        return None;
    }
    let elem_bytes_i64: i64 = i64::try_from(width.bytes()).ok()?;
    let disp: i64 = *accum_disp.values().next()?;
    if disp % elem_bytes_i64 != 0 {
        return None;
    }
    let elem_offset: i64 = disp / elem_bytes_i64;
    if elem_offset < 0 {
        return None;
    }
    let accumulators: Vec<u8> = accum_disp.keys().copied().collect();
    Some(PtrWalkLoop {
        op,
        width,
        base_reg,
        end_reg,
        step_bytes,
        accumulators,
        elem_offset,
        header_idx: header,
        back_idx: back,
    })
}

fn analyze_ptrwalk_loop_wide(insns: &[Insn], header: usize, back: usize) -> Option<PtrWalkLoop> {
    let body: &[Insn] = insns.get(header..=back)?;
    let mut loads: BTreeMap<u8, (Reg, i64)> = BTreeMap::new();
    for insn in body {
        if matches!(insn.mnem.as_str(), "movdqu" | "movdqa")
            && let (Some(dst), Some(mem)) = (insn.xmm(0), insn.mem(1))
            && let Some(lbase) = mem.base
            && mem.index.is_none()
        {
            loads.insert(dst, (lbase, mem.disp));
        }
    }
    let mut op: Option<(RingOp, Option<ElemWidth>)> = None;
    let mut accum_disp: BTreeMap<u8, i64> = BTreeMap::new();
    let mut walk: Option<Reg> = None;
    for insn in body {
        let Some((ring, width_hint)) = packed_op_ringop(&insn.mnem) else {
            continue;
        };
        let (Some(dst), Some(src)) = (insn.xmm(0), insn.xmm(1)) else {
            continue;
        };
        let Some(&(lbase, disp)) = loads.get(&src) else {
            continue;
        };
        if let Some((prev_op, prev_hint)) = op
            && (prev_op != ring || prev_hint != width_hint)
        {
            return None;
        }
        op = Some((ring, width_hint));
        if *walk.get_or_insert(lbase) != lbase {
            return None;
        }
        accum_disp.insert(dst, disp);
    }
    let (op, width_hint): (RingOp, Option<ElemWidth>) = op?;
    let walk_reg: Reg = walk?;
    let step_bytes: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == walk_reg => Some(v),
                _ => None,
            })?;
    if step_bytes <= 0 {
        return None;
    }
    let end_reg: Reg = body.iter().rev().find_map(|i: &Insn| {
        if i.mnem != "cmp" {
            return None;
        }
        match (i.gpr(0), i.gpr(1)) {
            (Some((a, _)), Some((b, _))) if a == walk_reg => Some(b),
            (Some((a, _)), Some((b, _))) if b == walk_reg => Some(a),
            _ => None,
        }
    })?;
    if end_reg == walk_reg {
        return None;
    }
    let prefix: &[Insn] = insns.get(..header)?;
    let base_pos: usize = prefix
        .iter()
        .enumerate()
        .rev()
        .find_map(|(p, i): (usize, &Insn)| {
            (i.mnem == "mov" && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(walk_reg)).then_some(p)
        })?;
    let base_reg: Reg = prefix[base_pos].gpr(1)?.0;
    if base_reg == walk_reg {
        return None;
    }
    let width: ElemWidth = insns
        .get(back + 1..)?
        .iter()
        .find_map(|i: &Insn| extract_width(&i.mnem))?;
    if let Some(hint) = width_hint
        && hint != width
    {
        return None;
    }
    if accum_disp.len() != 1 {
        return None;
    }
    let elem_bytes_i64: i64 = i64::try_from(width.bytes()).ok()?;
    let disp: i64 = *accum_disp.values().next()?;
    if disp % elem_bytes_i64 != 0 {
        return None;
    }
    let elem_offset: i64 = disp / elem_bytes_i64;
    if elem_offset < 0 {
        return None;
    }
    let accumulators: Vec<u8> = accum_disp.keys().copied().collect();
    Some(PtrWalkLoop {
        op,
        width,
        base_reg,
        end_reg,
        step_bytes,
        accumulators,
        elem_offset,
        header_idx: header,
        back_idx: back,
    })
}

fn verify_ptrwalk_acc_init(insns: &[Insn], vloop: &PtrWalkLoop) -> Option<()> {
    if vloop.op.identity(vloop.width) != 0 {
        return None;
    }
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    let acc: u8 = *vloop.accumulators.first()?;
    prefix
        .iter()
        .any(|i: &Insn| i.mnem == "pxor" && i.xmm(0) == Some(acc) && i.xmm(1) == Some(acc))
        .then_some(())
}

fn verify_ptrwalk_end(insns: &[Insn], vloop: &PtrWalkLoop) -> Option<Reg> {
    let elem_bytes: u64 = vloop.width.bytes();
    let per_iter: u64 = u64::try_from(vloop.step_bytes).ok()? / elem_bytes;
    if !per_iter.is_power_of_two() || !vloop.step_bytes.cast_unsigned().is_power_of_two() {
        return None;
    }
    let shr_k: i64 = i64::from(per_iter.trailing_zeros());
    let shl_k: i64 = i64::from(vloop.step_bytes.cast_unsigned().trailing_zeros());
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    let writes: Vec<&Insn> = prefix
        .iter()
        .filter(|i: &&Insn| writes_gpr(i, vloop.end_reg))
        .collect();
    let last_four: &[&Insn] = writes.get(writes.len().checked_sub(4)?..)?;
    let [mov, shr, shl, add] = last_four else {
        return None;
    };
    if mov.mnem != "mov" || shr.mnem != "shr" || shl.mnem != "shl" || add.mnem != "add" {
        return None;
    }
    let len_reg: Reg = mov.gpr(1)?.0;
    if shr.imm(1)? != shr_k || shl.imm(1)? != shl_k {
        return None;
    }
    (add.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(vloop.base_reg)).then_some(len_reg)
}

fn resolves_to(insns: &[Insn], upto: usize, reg: Reg, target: Reg) -> bool {
    if reg == target {
        return true;
    }
    let Some(prefix) = insns.get(..upto) else {
        return false;
    };
    let Some(mov) = prefix.iter().rev().find(|i: &&Insn| writes_gpr(i, reg)) else {
        return false;
    };
    mov.mnem == "mov" && mov.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(target)
}

fn last_write_pos(insns: &[Insn], upto: usize, reg: Reg) -> Option<usize> {
    insns
        .get(..upto)?
        .iter()
        .enumerate()
        .rev()
        .find_map(|(p, i): (usize, &Insn)| writes_gpr(i, reg).then_some(p))
}

fn next_write_pos(insns: &[Insn], from: usize, reg: Reg) -> Option<usize> {
    insns
        .get(from..)?
        .iter()
        .position(|i: &Insn| writes_gpr(i, reg))
        .map(|p: usize| p + from)
}

fn verify_ptrwalk_end_aliased(insns: &[Insn], vloop: &PtrWalkLoop) -> Option<(Reg, Reg)> {
    let elem_bytes: u64 = vloop.width.bytes();
    let per_iter: u64 = u64::try_from(vloop.step_bytes).ok()? / elem_bytes;
    if !per_iter.is_power_of_two() || !vloop.step_bytes.cast_unsigned().is_power_of_two() {
        return None;
    }
    let shr_k: i64 = i64::from(per_iter.trailing_zeros());
    let shl_k: i64 = i64::from(vloop.step_bytes.cast_unsigned().trailing_zeros());
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    let writes: Vec<(usize, &Insn)> = prefix
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| writes_gpr(i, vloop.end_reg))
        .collect();
    let last_four: &[(usize, &Insn)] = writes.get(writes.len().checked_sub(4)?..)?;
    let [(_, mov), (_, shr), (_, shl), (add_pos, add)] = last_four else {
        return None;
    };
    if mov.mnem != "mov" || shr.mnem != "shr" || shl.mnem != "shl" || add.mnem != "add" {
        return None;
    }
    let len_reg: Reg = mov.gpr(1)?.0;
    if shr.imm(1)? != shr_k || shl.imm(1)? != shl_k {
        return None;
    }
    let add_src: Reg = add.gpr(1)?.0;
    resolves_to(insns, *add_pos, add_src, vloop.base_reg).then_some((len_reg, add_src))
}

fn verify_tier2_offset_advance(
    region: &[Insn],
    add_pos: usize,
    n_full_reg: Reg,
    len_reg: Reg,
    w2: usize,
) -> bool {
    let Some(add_insn) = region.get(add_pos) else {
        return false;
    };
    if add_insn.mnem != "add" || add_insn.gpr(0).map(|(r, _): (Reg, u8)| r) != Some(n_full_reg) {
        return false;
    }
    let Some((w2_reg, _)) = add_insn.gpr(1) else {
        return false;
    };
    let Ok(w2_i64) = i64::try_from(w2) else {
        return false;
    };
    let Some(and_pos) = last_write_pos(region, add_pos, w2_reg) else {
        return false;
    };
    let and_insn: &Insn = &region[and_pos];
    if and_insn.mnem != "and" || and_insn.imm(1) != Some(-w2_i64) {
        return false;
    }
    let Some(mov_pos) = last_write_pos(region, and_pos, w2_reg) else {
        return false;
    };
    let mov_insn: &Insn = &region[mov_pos];
    let Some((rem_reg, _)) = (mov_insn.mnem == "mov").then(|| mov_insn.gpr(1)).flatten() else {
        return false;
    };
    let Some(sub_pos) = last_write_pos(region, mov_pos, rem_reg) else {
        return false;
    };
    let sub_insn: &Insn = &region[sub_pos];
    if sub_insn.mnem != "sub" {
        return false;
    }
    let (Some((sub_dst, _)), Some((sub_rhs, _))) = (sub_insn.gpr(0), sub_insn.gpr(1)) else {
        return false;
    };
    if sub_dst != rem_reg || !resolves_to(region, sub_pos, sub_rhs, n_full_reg) {
        return false;
    }
    let Some(len_mov_pos) = last_write_pos(region, sub_pos, rem_reg) else {
        return false;
    };
    let len_mov: &Insn = &region[len_mov_pos];
    len_mov.mnem == "mov" && len_mov.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
}

fn verify_wide_skip_seed(
    region: &[Insn],
    zero_gprs: &[Reg],
    zero_xmm: Option<u8>,
    resume_limit: usize,
) -> bool {
    region.iter().enumerate().any(|(p, insn): (usize, &Insn)| {
        if insn.mnem != "jmp" || p < zero_gprs.len() {
            return false;
        }
        let Some(target_addr) = insn.rel(0) else {
            return false;
        };
        let Some(target_pos) = region.iter().position(|i: &Insn| i.addr == target_addr) else {
            return false;
        };
        if target_pos > resume_limit {
            return false;
        }
        let window: &[Insn] = &region[p.saturating_sub(6)..p];
        let gprs_zeroed: bool = zero_gprs.iter().all(|&reg: &Reg| {
            window.iter().any(|i: &Insn| {
                i.mnem == "xor"
                    && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(reg)
                    && i.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(reg)
            })
        });
        let xmm_zeroed: bool = zero_xmm.is_none_or(|x: u8| {
            window
                .iter()
                .any(|i: &Insn| i.mnem == "pxor" && i.xmm(0) == Some(x) && i.xmm(1) == Some(x))
        });
        gprs_zeroed && xmm_zeroed
    })
}

fn verify_wide_peeled_tail(
    insns: &[Insn],
    start: usize,
    base_reg: Reg,
    r_reg: Reg,
    len_reg: Reg,
    op: RingOp,
    width: ElemWidth,
    max_elems: usize,
) -> Option<u8> {
    let region: &[Insn] = insns.get(start..)?;
    let elem_bytes: i64 = i64::try_from(width.bytes()).ok()?;
    let mut aff: BTreeMap<Reg, Aff> = BTreeMap::new();
    aff.insert(r_reg, Aff { r: 1, c: 0 });
    let mut adds: Vec<(i64, Reg, u8, usize)> = Vec::new();
    let mut idx_guards: Vec<(i64, usize)> = Vec::new();
    for (pos, insn) in region.iter().enumerate() {
        if is_store(insn) {
            return None;
        }
        match insn.mnem.as_str() {
            "mov" => {
                if let (Some((d, _)), Some((s, _))) = (insn.gpr(0), insn.gpr(1)) {
                    match aff.get(&s).copied() {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                } else if let Some((d, _)) = insn.gpr(0) {
                    aff.remove(&d);
                }
            }
            "lea" => {
                if let (Some((d, _)), Some(m)) = (insn.gpr(0), insn.mem(1)) {
                    match lea_affine(&aff, m) {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                }
            }
            "cmp" => {
                let compared: Option<i64> = match (insn.gpr(0), insn.gpr(1)) {
                    (Some((a, _)), Some((b, _))) if a == len_reg => {
                        aff.get(&b).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    (Some((a, _)), Some((b, _))) if b == len_reg => {
                        aff.get(&a).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    _ => None,
                };
                if let Some(g) = compared {
                    idx_guards.push((g, pos));
                }
            }
            other => {
                let ring: Option<RingOp> = scalar_op_ringop(other);
                if let (Some(r), Some((d, bytes)), Some(m)) = (ring, insn.gpr(0), insn.mem(1))
                    && r == op
                    && let Some(j) = peeled_elem_index(&aff, m, base_reg, elem_bytes)
                {
                    adds.push((j, d, bytes, pos));
                } else if let (Some(_), Some((d, _)), Some(imm)) = (ring, insn.gpr(0), insn.imm(1))
                    && let Some(a) = aff.get(&d).copied()
                {
                    if other == "add" {
                        aff.insert(
                            d,
                            Aff {
                                r: a.r,
                                c: a.c + imm,
                            },
                        );
                    } else {
                        aff.remove(&d);
                    }
                } else if let Some((d, _)) = insn.gpr(0)
                    && !matches!(other, "jmp" | "je" | "jz" | "jle" | "jng" | "jl")
                {
                    aff.remove(&d);
                }
            }
        }
    }
    adds.sort_by_key(|t: &(i64, Reg, u8, usize)| t.3);
    if adds.is_empty() || adds.len() > max_elems {
        return None;
    }
    let acc: Reg = adds.first()?.1;
    if acc != Reg::Rax {
        return None;
    }
    let ret_bytes: u8 = adds.first()?.2;
    for (want_j, &(j, a, bytes, pos)) in adds.iter().enumerate() {
        if j != i64::try_from(want_j).ok()? || a != acc || bytes != ret_bytes {
            return None;
        }
        if want_j >= 1 {
            let prev_pos: usize = adds[want_j - 1].3;
            let guarded: bool = idx_guards
                .iter()
                .any(|&(g, gp): &(i64, usize)| g == j && gp > prev_pos && gp < pos);
            if !guarded {
                return None;
            }
        }
    }
    Some(ret_bytes)
}

fn verify_wide_ptrwalk_remainder(
    insns: &[Insn],
    back_idx: usize,
    op: RingOp,
    width: ElemWidth,
    acc: u8,
    mem_base: Reg,
    len_reg: Reg,
    vf: usize,
) -> Option<u8> {
    if vf < 2 || vf % 2 != 0 {
        return None;
    }
    let w2: usize = vf / 2;
    let lpr: usize = (16 / width.bytes()) as usize;
    let region: &[Insn] = insns.get(back_idx + 1..)?;
    let mut regs: BTreeMap<u8, Vec<Term>> = BTreeMap::new();
    regs.insert(acc, (0..vf).map(|l: usize| Term::Var(l as u32)).collect());
    let mut n_full_reg: Option<Reg> = None;
    let mut extract1_seen: bool = false;
    let mut tier2_idx_reg: Option<Reg> = None;
    let mut tier2_load_dst: Option<u8> = None;
    let mut tier2_load_pos: Option<usize> = None;
    let mut tier2_partial_xmm: Option<u8> = None;
    let mut extract2_pos: Option<usize> = None;
    let vf_i64: i64 = i64::try_from(vf).ok()?;

    for (pos, insn) in region.iter().enumerate() {
        if n_full_reg.is_none()
            && insn.mnem == "and"
            && insn.imm(1) == Some(-vf_i64)
            && let Some((d, _)) = insn.gpr(0)
            && resolves_to(region, pos, d, len_reg)
        {
            n_full_reg = Some(d);
        }
        if extract1_seen
            && tier2_load_pos.is_none()
            && insn.mnem == "movq"
            && insn.xmm(0).is_some()
            && let Some(mem) = insn.mem(1)
        {
            let n_full: Reg = n_full_reg?;
            let base_ok: bool = mem
                .base
                .is_some_and(|b: Reg| resolves_to(insns, back_idx + 1 + pos, b, mem_base));
            let idx_ok: bool = mem.index.is_some_and(|(i, scale): (Reg, u8)| {
                u64::from(scale) == width.bytes() && resolves_to(region, pos, i, n_full)
            });
            if base_ok && idx_ok && mem.disp == 0 {
                let dst: u8 = insn.xmm(0)?;
                let mut lanes: Vec<Term> =
                    (0..w2).map(|i: usize| Term::Var((vf + i) as u32)).collect();
                lanes.resize(lpr, Term::Const(0));
                regs.insert(dst, lanes);
                tier2_idx_reg = mem.index.map(|(i, _): (Reg, u8)| i);
                tier2_load_dst = Some(dst);
                tier2_load_pos = Some(pos);
                continue;
            }
            return None;
        }
        match insn.mnem.as_str() {
            "movd" | "movq" | "pextrw" | "pextrd" | "pextrq" if insn.xmm(1).is_some() => {
                let src: u8 = insn.xmm(1)?;
                let lane: usize = match insn.mnem.as_str() {
                    "movd" | "movq" => 0,
                    _ => usize::try_from(insn.imm(2)? & 0xff).ok()?,
                };
                let lanes: &Vec<Term> = regs.get(&src)?;
                let got: Term = lanes.get(lane)?.clone();
                if !extract1_seen {
                    let base_vars: Vec<Term> =
                        (0..vf).map(|i: usize| Term::Var(i as u32)).collect();
                    if !terms_equivalent(&got, &fold_terms(op, width, &base_vars)) {
                        return None;
                    }
                    extract1_seen = true;
                } else if tier2_load_pos.is_some() && extract2_pos.is_none() {
                    let all_vars: Vec<Term> =
                        (0..vf + w2).map(|i: usize| Term::Var(i as u32)).collect();
                    if !terms_equivalent(&got, &fold_terms(op, width, &all_vars)) {
                        return None;
                    }
                    extract2_pos = Some(pos);
                    break;
                }
            }
            "movdqa" => {
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let value: Vec<Term> = regs.get(&src)?.clone();
                regs.insert(dst, value);
            }
            "psrldq" => {
                let dst: u8 = insn.xmm(0)?;
                let shift_bytes: u64 = u64::try_from(insn.imm(1)? & 0xff).ok()?;
                let elem_bytes: u64 = width.bytes();
                if shift_bytes % elem_bytes != 0 {
                    return None;
                }
                let lane_shift: usize = usize::try_from(shift_bytes / elem_bytes).ok()?;
                let cur: Vec<Term> = regs.get(&dst)?.clone();
                let shifted: Vec<Term> = (0..cur.len())
                    .map(|i: usize| cur.get(i + lane_shift).cloned().unwrap_or(Term::Const(0)))
                    .collect();
                regs.insert(dst, shifted);
            }
            "pshufd" => {
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let imm: u8 = u8::try_from(insn.imm(2)? & 0xff).ok()?;
                let perm: Vec<usize> = pshufd_lane_perm(imm, lpr)?;
                let source: Vec<Term> = regs.get(&src)?.clone();
                let permuted: Vec<Term> = perm
                    .iter()
                    .map(|&p: &usize| source.get(p).cloned())
                    .collect::<Option<Vec<Term>>>()?;
                regs.insert(dst, permuted);
            }
            "psrlw" | "psrld" | "psrlq" => {
                let dst: u8 = insn.xmm(0)?;
                let shift_bits: u64 = u64::try_from(insn.imm(1)? & 0xff).ok()?;
                let dword_bits: u32 = match insn.mnem.as_str() {
                    "psrlw" => 16,
                    "psrld" => 32,
                    _ => 64,
                };
                let cur: Vec<Term> = regs.get(&dst)?.clone();
                let shifted: Vec<Term> =
                    shift_right_logical_lanes(&cur, dword_bits, width, shift_bits)?;
                regs.insert(dst, shifted);
            }
            other => {
                let Some((ring, _)): Option<(RingOp, Option<ElemWidth>)> = packed_op_ringop(other)
                else {
                    if insn.xmm(0).is_some() {
                        return None;
                    }
                    continue;
                };
                if ring != op {
                    return None;
                }
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let source: Vec<Term> = regs.get(&src)?.clone();
                let dest: Vec<Term> = regs.get(&dst)?.clone();
                if dest.len() != source.len() {
                    return None;
                }
                if tier2_load_dst == Some(dst) && tier2_partial_xmm.is_none() {
                    tier2_partial_xmm = Some(src);
                }
                let combined: Vec<Term> = dest
                    .into_iter()
                    .zip(source)
                    .map(|(a, b): (Term, Term)| Term::app(op, width, vec![a, b]))
                    .collect();
                regs.insert(dst, combined);
            }
        }
    }

    if !extract1_seen {
        return None;
    }
    let n_full: Reg = n_full_reg?;
    let idx_reg: Reg = tier2_idx_reg?;
    let load_pos: usize = tier2_load_pos?;
    let ext2_pos: usize = extract2_pos?;
    let add_pos: usize = last_write_pos(region, ext2_pos, n_full)?;
    if !verify_tier2_offset_advance(region, add_pos, n_full, len_reg, w2) {
        return None;
    }
    if !verify_wide_skip_seed(
        region,
        &[n_full, idx_reg, Reg::Rax],
        tier2_partial_xmm,
        load_pos,
    ) {
        return None;
    }
    let tier3_start: usize = back_idx + 1 + ext2_pos + 1;
    verify_wide_peeled_tail(
        insns,
        tier3_start,
        mem_base,
        n_full,
        len_reg,
        op,
        width,
        w2 - 1,
    )
}

fn traces_pristine_arg(insns: &[Insn], upto: usize, reg: Reg) -> Option<Reg> {
    let prefix: &[Insn] = insns.get(..upto)?;
    let writes: Vec<(usize, &Insn)> = prefix
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| writes_gpr(i, reg))
        .collect();
    match writes.as_slice() {
        [] => Some(reg),
        [(pos, mov)] if mov.mnem == "mov" => {
            let src: Reg = mov.gpr(1)?.0;
            insns
                .get(..*pos)?
                .iter()
                .all(|i: &Insn| !writes_gpr(i, src))
                .then_some(src)
        }
        _ => None,
    }
}

fn verify_ptrwalk_minmax_end(insns: &[Insn], vloop: &PtrWalkLoop) -> Option<Reg> {
    let len_reg: Reg = verify_ptrwalk_end(insns, vloop)?;
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    let mov_pos: usize = prefix.iter().position(|i: &Insn| {
        i.mnem == "mov"
            && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(vloop.end_reg)
            && i.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
    })?;
    let writes: Vec<&Insn> = prefix
        .get(..mov_pos)?
        .iter()
        .filter(|i: &&Insn| writes_gpr(i, len_reg))
        .collect();
    let [lea] = writes.as_slice() else {
        return None;
    };
    let is_self_decrement: bool = lea.mnem == "lea"
        && lea
            .mem(1)
            .is_some_and(|m: Mem| m.base == Some(len_reg) && m.index.is_none() && m.disp == -1);
    is_self_decrement.then_some(len_reg)
}

#[derive(Debug, Clone, Copy)]
struct Aff {
    r: i64,
    c: i64,
}

fn lea_affine(aff: &BTreeMap<Reg, Aff>, m: Mem) -> Option<Aff> {
    let mut r: i64 = 0;
    let mut c: i64 = m.disp;
    if let Some(b) = m.base {
        let a: Aff = *aff.get(&b)?;
        r = r.checked_add(a.r)?;
        c = c.checked_add(a.c)?;
    }
    if let Some((idx, scale)) = m.index {
        let a: Aff = *aff.get(&idx)?;
        r = r.checked_add(a.r.checked_mul(i64::from(scale))?)?;
        c = c.checked_add(a.c.checked_mul(i64::from(scale))?)?;
    }
    Some(Aff { r, c })
}

fn peeled_elem_index(
    aff: &BTreeMap<Reg, Aff>,
    m: Mem,
    base_reg: Reg,
    elem_bytes: i64,
) -> Option<i64> {
    if m.base? != base_reg {
        return None;
    }
    let (idx, scale): (Reg, u8) = m.index?;
    let a: Aff = *aff.get(&idx)?;
    let scale_i: i64 = i64::from(scale);
    if a.r.checked_mul(scale_i)? != elem_bytes {
        return None;
    }
    let byte_const: i64 = a.c.checked_mul(scale_i)?.checked_add(m.disp)?;
    if byte_const % elem_bytes != 0 {
        return None;
    }
    let j: i64 = byte_const / elem_bytes;
    (j >= 0).then_some(j)
}

fn is_store(insn: &Insn) -> bool {
    matches!(
        insn.mnem.as_str(),
        "mov" | "movdqu" | "movdqa" | "movups" | "movaps" | "movq" | "movd"
    ) && insn.mem(0).is_some()
}

fn zeroes_self(insn: &Insn, reg: Reg) -> bool {
    insn.mnem == "xor"
        && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(reg)
        && insn.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(reg)
}

fn verify_scalar_only_seed(
    region: &[Insn],
    acc: Reg,
    r_reg: Reg,
    after: u64,
    block_head: u64,
) -> bool {
    region.iter().enumerate().any(|(p, insn): (usize, &Insn)| {
        if insn.mnem != "jmp" {
            return false;
        }
        let Some(target) = insn.rel(0) else {
            return false;
        };
        if target <= after || target > block_head || p < 2 {
            return false;
        }
        let a: &Insn = &region[p - 1];
        let b: &Insn = &region[p - 2];
        (zeroes_self(a, acc) && zeroes_self(b, r_reg))
            || (zeroes_self(a, r_reg) && zeroes_self(b, acc))
    })
}

fn verify_peeled_remainder(
    insns: &[Insn],
    back_idx: usize,
    base_reg: Reg,
    len_reg: Reg,
    op: RingOp,
    width: ElemWidth,
    vf: usize,
) -> Option<u8> {
    let region: &[Insn] = insns.get(back_idx + 1..)?;
    let elem_bytes: i64 = i64::try_from(width.bytes()).ok()?;
    let mask: i64 = -(i64::try_from(vf).ok()?);
    let residue: i64 = i64::try_from(vf).ok()? - 1;
    let mut aff: BTreeMap<Reg, Aff> = BTreeMap::new();
    let mut holds_len: std::collections::BTreeSet<Reg> = std::collections::BTreeSet::new();
    let mut r_reg: Option<Reg> = None;
    let mut adds: Vec<(i64, Reg, u8, usize)> = Vec::new();
    let mut idx_guards: Vec<(i64, usize)> = Vec::new();
    let mut residue_guard: Option<usize> = None;
    for (pos, insn) in region.iter().enumerate() {
        if is_store(insn) {
            return None;
        }
        match insn.mnem.as_str() {
            "mov" => {
                if let (Some((d, _)), Some((s, _))) = (insn.gpr(0), insn.gpr(1)) {
                    match aff.get(&s).copied() {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                    if s == len_reg {
                        holds_len.insert(d);
                    } else {
                        holds_len.remove(&d);
                    }
                } else if let Some((d, _)) = insn.gpr(0) {
                    aff.remove(&d);
                    holds_len.remove(&d);
                }
            }
            "and" => {
                let (Some((d, _)), Some(imm)) = (insn.gpr(0), insn.imm(1)) else {
                    continue;
                };
                if imm == mask && (holds_len.contains(&d) || d == len_reg) {
                    aff.insert(d, Aff { r: 1, c: 0 });
                    r_reg.get_or_insert(d);
                } else if imm == residue && (holds_len.contains(&d) || sub_of(d, len_reg)) {
                    residue_guard.get_or_insert(pos);
                    aff.remove(&d);
                    holds_len.remove(&d);
                } else {
                    aff.remove(&d);
                    holds_len.remove(&d);
                }
            }
            "test" => {
                if let (Some((a, _)), Some(imm)) = (insn.gpr(0), insn.imm(1))
                    && sub_of(a, len_reg)
                    && imm == residue
                {
                    residue_guard.get_or_insert(pos);
                }
            }
            "lea" => {
                if let (Some((d, _)), Some(m)) = (insn.gpr(0), insn.mem(1)) {
                    match lea_affine(&aff, m) {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                    holds_len.remove(&d);
                }
            }
            "cmp" => {
                let compared: Option<i64> = match (insn.gpr(0), insn.gpr(1)) {
                    (Some((a, _)), Some((b, _))) if a == len_reg => {
                        aff.get(&b).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    (Some((a, _)), Some((b, _))) if b == len_reg => {
                        aff.get(&a).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    _ => None,
                };
                if let Some(g) = compared {
                    idx_guards.push((g, pos));
                }
            }
            other => {
                let ring: Option<RingOp> = scalar_op_ringop(other);
                if let (Some(r), Some((d, bytes)), Some(m)) = (ring, insn.gpr(0), insn.mem(1))
                    && r == op
                    && let Some(j) = peeled_elem_index(&aff, m, base_reg, elem_bytes)
                {
                    adds.push((j, d, bytes, pos));
                } else if let (Some(_), Some((d, _)), Some(imm)) = (ring, insn.gpr(0), insn.imm(1))
                    && let Some(a) = aff.get(&d).copied()
                {
                    if other == "add" {
                        aff.insert(
                            d,
                            Aff {
                                r: a.r,
                                c: a.c + imm,
                            },
                        );
                    } else {
                        aff.remove(&d);
                    }
                } else if let Some((d, _)) = insn.gpr(0)
                    && !matches!(other, "jmp" | "je" | "jz" | "jle" | "jng" | "jl")
                {
                    aff.remove(&d);
                }
            }
        }
    }
    let r_reg: Reg = r_reg?;
    residue_guard?;
    adds.sort_by_key(|t: &(i64, Reg, u8, usize)| t.3);
    if adds.len() != vf - 1 {
        return None;
    }
    let acc: Reg = adds.first()?.1;
    if acc != Reg::Rax {
        return None;
    }
    let ret_bytes: u8 = adds.first()?.2;
    for (want_j, &(j, a, bytes, pos)) in adds.iter().enumerate() {
        if j != i64::try_from(want_j).ok()? || a != acc || bytes != ret_bytes {
            return None;
        }
        if want_j >= 1 {
            let prev_pos: usize = adds[want_j - 1].3;
            let guarded: bool = idx_guards
                .iter()
                .any(|&(g, gp): &(i64, usize)| g == j && gp > prev_pos && gp < pos);
            if !guarded {
                return None;
            }
        }
    }
    let first_add_addr: u64 = region.get(adds.first()?.3)?.addr;
    let extract_addr: u64 = region
        .iter()
        .find_map(|i: &Insn| extract_width(&i.mnem).map(|_| i.addr))?;
    if !verify_scalar_only_seed(region, acc, r_reg, extract_addr, first_add_addr) {
        return None;
    }
    Some(ret_bytes)
}

fn sub_of(reg: Reg, full: Reg) -> bool {
    reg == full
}

fn verify_ptrwalk_minmax_remainder(
    insns: &[Insn],
    back_idx: usize,
    base_reg: Reg,
    masked_reg: Reg,
    op: RingOp,
    elem_offset: i64,
    width: ElemWidth,
    vf: usize,
) -> Option<u8> {
    let region: &[Insn] = insns.get(back_idx + 1..)?;
    let elem_bytes: i64 = i64::try_from(width.bytes()).ok()?;
    let mask: i64 = -(i64::try_from(vf).ok()?);
    let mut aff: BTreeMap<Reg, Aff> = BTreeMap::new();
    let mut mask_established: bool = false;
    let mut pending: Option<(i64, Reg, u8)> = None;
    let mut steps: Vec<(i64, Reg, u8, usize)> = Vec::new();
    let mut idx_guards: Vec<(i64, usize)> = Vec::new();
    for (pos, insn) in region.iter().enumerate() {
        if is_store(insn) {
            return None;
        }
        if let Some((j, loaded, bytes)) = pending
            && pos > 0
            && insn.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(loaded)
            && scalar_cmp_cmov_op(&region[pos - 1], insn) == Some(op)
        {
            steps.push((j, insn.gpr(0)?.0, bytes, pos));
            pending = None;
        }
        match insn.mnem.as_str() {
            "and" => {
                if let (Some((d, _)), Some(imm)) = (insn.gpr(0), insn.imm(1))
                    && d == masked_reg
                    && imm == mask
                {
                    aff.insert(d, Aff { r: 1, c: 0 });
                    mask_established = true;
                }
            }
            "add" => {
                if let (Some((d, _)), Some(imm)) = (insn.gpr(0), insn.imm(1))
                    && let Some(a) = aff.get(&d).copied()
                {
                    aff.insert(
                        d,
                        Aff {
                            r: a.r,
                            c: a.c + imm,
                        },
                    );
                }
            }
            "lea" => {
                if let (Some((d, _)), Some(m)) = (insn.gpr(0), insn.mem(1)) {
                    match lea_affine(&aff, m) {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                }
            }
            "mov" => {
                if let (Some((d, dbytes)), Some(m)) = (insn.gpr(0), insn.mem(1)) {
                    if let Some(j) = peeled_elem_index(&aff, m, base_reg, elem_bytes) {
                        pending = Some((j, d, dbytes));
                    }
                } else if let (Some((d, _)), Some((s, _))) = (insn.gpr(0), insn.gpr(1)) {
                    match aff.get(&s).copied() {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                }
            }
            "cmp" => {
                if let (Some((a, _)), Some((b, _))) = (insn.gpr(0), insn.gpr(1))
                    && traces_pristine_arg(insns, back_idx + 1 + pos, a) == Some(masked_reg)
                    && let Some(bound) = aff.get(&b).copied()
                    && bound.r == 1
                {
                    idx_guards.push((bound.c, pos));
                }
            }
            _ => {}
        }
    }
    if !mask_established {
        return None;
    }
    steps.sort_by_key(|t: &(i64, Reg, u8, usize)| t.3);
    if steps.len() != vf - 1 {
        return None;
    }
    let acc: Reg = steps.first()?.1;
    if acc != Reg::Rax {
        return None;
    }
    let ret_bytes: u8 = steps.first()?.2;
    let base_j: i64 = steps.first()?.0;
    if base_j != elem_offset {
        return None;
    }
    for (want_k, &(j, a, bytes, pos)) in steps.iter().enumerate() {
        if j != base_j + i64::try_from(want_k).ok()? || a != acc || bytes != ret_bytes {
            return None;
        }
        if want_k >= 1 {
            let prev_pos: usize = steps[want_k - 1].3;
            let guarded: bool = idx_guards
                .iter()
                .any(|&(g, gp): &(i64, usize)| g == j && gp > prev_pos && gp < pos);
            if !guarded {
                return None;
            }
        }
    }
    Some(ret_bytes)
}

fn recognize_ptrwalk_reduction(insns: &[Insn]) -> Option<ReductionForm> {
    let edges: Vec<(usize, usize)> = find_back_edges(insns);
    let vloop: PtrWalkLoop = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_loop(insns, h, b))
        .or_else(|| {
            edges
                .iter()
                .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_loop_wide(insns, h, b))
        })?;
    if !vloop.op.is_associative_commutative() {
        return None;
    }
    if vloop.op.identity(vloop.width) != 0 || vloop.op.c_infix().is_none() {
        return None;
    }
    if vloop.accumulators.len() != 1 || vloop.step_bytes != 16 || vloop.elem_offset != 0 {
        return None;
    }
    let vf: usize = (16 / vloop.width.bytes()) as usize;
    verify_ptrwalk_acc_init(insns, &vloop)?;
    verify_epilog(
        insns,
        vloop.back_idx,
        vloop.op,
        vloop.width,
        &vloop.accumulators,
    )?;
    if let Some(len_reg) = verify_ptrwalk_end(insns, &vloop)
        && let Some(ret_bytes) = verify_peeled_remainder(
            insns,
            vloop.back_idx,
            vloop.base_reg,
            len_reg,
            vloop.op,
            vloop.width,
            vf,
        )
    {
        verify_zero_guard(insns, len_reg)?;
        return Some(ReductionForm {
            op: vloop.op,
            width: vloop.width,
            base_reg: vloop.base_reg,
            len_reg,
            ret_bytes,
        });
    }
    let acc: u8 = *vloop.accumulators.first()?;
    let (len_reg, mem_base): (Reg, Reg) = verify_ptrwalk_end_aliased(insns, &vloop)?;
    let ret_bytes: u8 = verify_wide_ptrwalk_remainder(
        insns,
        vloop.back_idx,
        vloop.op,
        vloop.width,
        acc,
        mem_base,
        len_reg,
        vf,
    )?;
    verify_zero_guard(insns, len_reg)?;
    Some(ReductionForm {
        op: vloop.op,
        width: vloop.width,
        base_reg: vloop.base_reg,
        len_reg,
        ret_bytes,
    })
}

fn recognize_ptrwalk_minmax(insns: &[Insn]) -> Option<MinMaxForm> {
    let edges: Vec<(usize, usize)> = find_back_edges(insns);
    let vloop: PtrWalkLoop = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_loop(insns, h, b))?;
    if !matches!(vloop.op, RingOp::SMax | RingOp::SMin) || vloop.elem_offset != 1 {
        return None;
    }
    if vloop.accumulators.len() != 1 || vloop.step_bytes != 16 {
        return None;
    }
    let [acc]: [u8; 1] = vloop.accumulators.as_slice().try_into().ok()?;
    verify_broadcast_seed(insns, vloop.header_idx, vloop.base_reg, acc)?;
    verify_epilog(
        insns,
        vloop.back_idx,
        vloop.op,
        vloop.width,
        &vloop.accumulators,
    )?;
    let len_reg: Reg = verify_ptrwalk_minmax_end(insns, &vloop)?;
    verify_minmax_guard(insns, len_reg)?;
    let vf: usize = (16 / vloop.width.bytes()) as usize;
    let ret_bytes: u8 = verify_ptrwalk_minmax_remainder(
        insns,
        vloop.back_idx,
        vloop.base_reg,
        len_reg,
        vloop.op,
        vloop.elem_offset,
        vloop.width,
        vf,
    )?;
    let base_reg: Reg = traces_pristine_arg(insns, vloop.header_idx, vloop.base_reg)?;
    Some(MinMaxForm {
        op: vloop.op,
        width: vloop.width,
        base_reg,
        len_reg,
        ret_bytes,
    })
}

fn term_to_c(term: &Term) -> String {
    match term {
        Term::Var(_) => "x".to_owned(),
        Term::Const(value) => format!("{value}ull"),
        Term::App { op, width, args } => op.c_infix().map_or_else(
            || minmax_to_c(*op, *width, args),
            |infix: &str| {
                let parts: Vec<String> = args.iter().map(term_to_c).collect();
                format!("({})", parts.join(&format!(" {infix} ")))
            },
        ),
    }
}

fn minmax_to_c(op: RingOp, _width: ElemWidth, args: &[Term]) -> String {
    let cast: &str = match op {
        RingOp::SMin | RingOp::SMax => "(int64_t)",
        _ => "",
    };
    let cmp: &str = match op {
        RingOp::SMax | RingOp::UMax => ">",
        _ => "<",
    };
    let mut acc: String = args.first().map_or_else(|| "x".to_owned(), term_to_c);
    for arg in args.iter().skip(1) {
        let next: String = term_to_c(arg);
        acc = format!("({cast}{acc} {cmp} {cast}{next} ? {acc} : {next})");
    }
    acc
}

#[derive(Debug, Clone)]
struct MapForm {
    transform: Term,
    width: ElemWidth,
    in_reg: Reg,
    out_reg: Reg,
    len_reg: Reg,
}

fn packed_lane_value(
    body: &[Insn],
    load_pos: usize,
    store_pos: usize,
    load_reg: u8,
) -> Option<Term> {
    let mut vals: BTreeMap<u8, Term> = BTreeMap::new();
    vals.insert(load_reg, Term::Var(0));
    for insn in body.get(load_pos + 1..store_pos)? {
        let (dst, src): (u8, Option<u8>) = (insn.xmm(0)?, insn.xmm(1));
        match insn.mnem.as_str() {
            "movdqa" => {
                let value: Term = vals.get(&src?)?.clone();
                vals.insert(dst, value);
            }
            "pslld" | "psllq" | "psllw" => {
                let shift: u32 = u32::try_from(insn.imm(1)?).ok()?;
                let cur: Term = vals.get(&dst)?.clone();
                let factor: u64 = 1u64.checked_shl(shift)?;
                vals.insert(
                    dst,
                    Term::app(RingOp::Mul, ElemWidth::W64, vec![cur, Term::Const(factor)]),
                );
            }
            other => {
                let (ring, _): (RingOp, Option<ElemWidth>) = packed_op_ringop(other)?;
                let s: Term = vals.get(&src?)?.clone();
                let d: Term = vals.get(&dst)?.clone();
                vals.insert(dst, Term::app(ring, ElemWidth::W64, vec![d, s]));
            }
        }
    }
    let store_reg: u8 = body.get(store_pos)?.xmm(1)?;
    vals.get(&store_reg).cloned()
}

fn scalar_lane_value(
    body: &[Insn],
    load_pos: usize,
    store_pos: usize,
    load_reg: Reg,
) -> Option<Term> {
    let mut vals: BTreeMap<Reg, Term> = BTreeMap::new();
    vals.insert(load_reg, Term::Var(0));
    for insn in body.get(load_pos + 1..store_pos)? {
        let (dst, _): (Reg, u8) = insn.gpr(0)?;
        let cur: Term = vals.get(&dst).cloned().unwrap_or(Term::Var(0));
        let value: Term = match insn.mnem.as_str() {
            "mov" => {
                let (src, _): (Reg, u8) = insn.gpr(1)?;
                vals.get(&src)?.clone()
            }
            "add" => match (insn.gpr(1), insn.imm(1)) {
                (Some((r, _)), _) => Term::app(
                    RingOp::Add,
                    ElemWidth::W64,
                    vec![cur, vals.get(&r)?.clone()],
                ),
                (None, Some(v)) => Term::app(
                    RingOp::Add,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.cast_unsigned())],
                ),
                _ => return None,
            },
            "sub" => {
                let v: i64 = insn.imm(1)?;
                Term::app(
                    RingOp::Add,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.wrapping_neg().cast_unsigned())],
                )
            }
            "shl" => {
                let shift: u32 = u32::try_from(insn.imm(1)?).ok()?;
                Term::app(
                    RingOp::Mul,
                    ElemWidth::W64,
                    vec![cur, Term::Const(1u64.checked_shl(shift)?)],
                )
            }
            "imul" => {
                let v: i64 = insn.imm(1).or_else(|| insn.imm(2))?;
                Term::app(
                    RingOp::Mul,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.cast_unsigned())],
                )
            }
            "xor" => Term::app(
                RingOp::Xor,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            "and" => Term::app(
                RingOp::And,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            "or" => Term::app(
                RingOp::Or,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            _ => return None,
        };
        vals.insert(dst, value);
    }
    let store_reg: Reg = body.get(store_pos)?.gpr(1)?.0;
    vals.get(&store_reg).cloned()
}

const XMM_MOVE_MNEMONICS: [&str; 4] = ["movdqu", "movdqa", "movups", "movaps"];

fn map_body_width_hint(body: &[Insn], load_pos: usize, store_pos: usize) -> Option<ElemWidth> {
    body.get(load_pos + 1..store_pos)?
        .iter()
        .find_map(|insn: &Insn| match insn.mnem.as_str() {
            "pslld" | "psrld" => Some(ElemWidth::W32),
            "psllq" | "psrlq" => Some(ElemWidth::W64),
            "psllw" | "psrlw" => Some(ElemWidth::W16),
            other => packed_op_ringop(other).and_then(|(_, w): (RingOp, Option<ElemWidth>)| w),
        })
}

fn analyze_map(insns: &[Insn], header: usize, back: usize) -> Option<(MapForm, Reg)> {
    let body: &[Insn] = insns.get(header..=back)?;
    let loads: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| XMM_MOVE_MNEMONICS.contains(&i.mnem.as_str()))
        .filter_map(|(p, i): (usize, &Insn)| Some((p, i.xmm(0)?, i.mem(1)?)))
        .collect();
    let stores: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| XMM_MOVE_MNEMONICS.contains(&i.mnem.as_str()))
        .filter_map(|(p, i): (usize, &Insn)| Some((p, i.xmm(1)?, i.mem(0)?)))
        .collect();
    if loads.len() != 1 || stores.len() != 1 {
        return None;
    }
    let (load_pos, load_reg, lmem): (usize, u8, Mem) = loads[0];
    let (store_pos, _, smem): (usize, u8, Mem) = stores[0];
    let (in_reg, (in_idx, scale)): (Reg, (Reg, u8)) = (lmem.base?, lmem.index?);
    let (out_reg, (out_idx, out_scale)): (Reg, (Reg, u8)) = (smem.base?, smem.index?);
    if in_idx != out_idx || scale != out_scale || lmem.disp != smem.disp || in_reg == out_reg {
        return None;
    }
    let scale_width: Option<ElemWidth> = (scale != 1)
        .then(|| ElemWidth::from_bytes(u64::from(scale)))
        .flatten();
    let hint_width: Option<ElemWidth> = map_body_width_hint(body, load_pos, store_pos);
    let width: ElemWidth = match (hint_width, scale_width) {
        (Some(h), Some(s)) if h == s => h,
        (Some(h), None) => h,
        (None, Some(s)) => s,
        _ => return None,
    };
    let step: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == in_idx => Some(v),
                _ => None,
            })?;
    if usize::try_from(step).ok()? != (16 / width.bytes()) as usize {
        return None;
    }
    let count_reg: Reg = cmp_other_reg(body, in_idx)?;
    let vec_transform: Term = packed_lane_value(body, load_pos, store_pos, load_reg)?;
    let (scalar_transform, len_reg): (Term, Reg) = find_map_remainder(insns, in_reg, out_reg)?;
    if !terms_equivalent(&vec_transform, &scalar_transform) {
        return None;
    }
    verify_mask(insns, count_reg, len_reg, step)?;
    verify_no_write_guard(insns, len_reg)?;
    Some((
        MapForm {
            transform: scalar_transform,
            width,
            in_reg,
            out_reg,
            len_reg,
        },
        len_reg,
    ))
}

fn find_map_remainder(insns: &[Insn], in_reg: Reg, out_reg: Reg) -> Option<(Term, Reg)> {
    for (header, back) in find_back_edges(insns) {
        let body: &[Insn] = insns.get(header..=back)?;
        if body
            .iter()
            .any(|i: &Insn| packed_op_ringop(&i.mnem).is_some())
        {
            continue;
        }
        let load_pos: Option<usize> = body.iter().position(|i: &Insn| {
            i.mnem == "mov"
                && i.mem(1).and_then(|m: Mem| m.base) == Some(in_reg)
                && i.gpr(0).is_some()
        });
        let store_pos: Option<usize> = body.iter().position(|i: &Insn| {
            i.mnem == "mov"
                && i.mem(0).and_then(|m: Mem| m.base) == Some(out_reg)
                && i.gpr(1).is_some()
        });
        let (Some(lp), Some(sp)) = (load_pos, store_pos) else {
            continue;
        };
        if sp <= lp {
            continue;
        }
        let Some(idx) = body[lp].mem(1).and_then(|m: Mem| m.index).map(|(r, _)| r) else {
            continue;
        };
        let load_reg: Reg = body[lp].gpr(0)?.0;
        let Some(transform) = scalar_lane_value(body, lp, sp, load_reg) else {
            continue;
        };
        let Some(len_reg) = cmp_other_reg(body, idx) else {
            continue;
        };
        return Some((transform, len_reg));
    }
    None
}

fn verify_no_write_guard(insns: &[Insn], len_reg: Reg) -> Option<()> {
    for (i, insn) in insns.iter().enumerate() {
        let is_test: bool = insn.mnem == "test"
            && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
            && insn.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg);
        if !is_test {
            continue;
        }
        let Some(next) = insns.get(i + 1) else {
            continue;
        };
        if matches!(next.mnem.as_str(), "jle" | "jng")
            && let Some(target) = next.rel(0)
            && reaches_ret_without_store(insns, target)
        {
            return Some(());
        }
    }
    None
}

fn reaches_ret_without_store(insns: &[Insn], addr: u64) -> bool {
    let Some(start) = addr_index(insns, addr) else {
        return false;
    };
    for insn in &insns[start..] {
        match insn.mnem.as_str() {
            "ret" => return true,
            "mov" | "movdqu" | "movdqa" if insn.mem(0).is_some() => return false,
            m if BRANCH_MNEMONICS.contains(&m) => return false,
            _ => {}
        }
    }
    false
}

fn emit_map(
    form: &MapForm,
    abi: Abi,
    out_pos: usize,
    in_pos: usize,
    len_pos: usize,
) -> LeafRecovery {
    let nparams: usize = out_pos.max(in_pos).max(len_pos) + 1;
    let params: Vec<Reg> = arg_order(abi)[..nparams].to_vec();
    let uet: &str = form.width.c_uint();
    let expr: String = term_to_c(&form.transform);
    let sig: String = (0..nparams)
        .map(|i: usize| format!("uint64_t a{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut source: String = String::new();
    let _ = writeln!(source, "#include <stdint.h>");
    let _ = writeln!(source, "uint64_t recovered({sig}) {{");
    let _ = writeln!(source, "    {uet} *out = ({uet} *)a{out_pos};");
    let _ = writeln!(source, "    const {uet} *in = (const {uet} *)a{in_pos};");
    let _ = writeln!(source, "    int64_t n = (int64_t)a{len_pos};");
    let _ = writeln!(source, "    for (int64_t i = 0; i < n; i++) {{");
    let _ = writeln!(source, "        uint64_t x = (uint64_t)in[i];");
    let _ = writeln!(source, "        out[i] = ({uet})({expr});");
    let _ = writeln!(source, "    }}");
    let _ = writeln!(source, "    return 0;");
    let _ = writeln!(source, "}}");
    LeafRecovery {
        source,
        rust_source: None,
        return_width_bits: 64,
        param_width_bits: vec![64; params.len()],
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
        call_site_signature: None,
    }
}

fn recognize_map(insns: &[Insn]) -> Option<MapForm> {
    find_back_edges(insns)
        .into_iter()
        .find_map(|(h, b): (usize, usize)| {
            analyze_map(insns, h, b).map(|(form, _): (MapForm, Reg)| form)
        })
}

#[derive(Debug, Clone)]
struct PtrWalkMap {
    transform: Term,
    width: ElemWidth,
    in_reg: Reg,
    out_reg: Reg,
    idx_reg: Reg,
    header_idx: usize,
    back_idx: usize,
}

fn analyze_ptrwalk_map(insns: &[Insn], header: usize, back: usize) -> Option<PtrWalkMap> {
    let body: &[Insn] = insns.get(header..=back)?;
    let loads: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| XMM_MOVE_MNEMONICS.contains(&i.mnem.as_str()))
        .filter_map(|(p, i): (usize, &Insn)| Some((p, i.xmm(0)?, i.mem(1)?)))
        .collect();
    let stores: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| XMM_MOVE_MNEMONICS.contains(&i.mnem.as_str()))
        .filter_map(|(p, i): (usize, &Insn)| Some((p, i.xmm(1)?, i.mem(0)?)))
        .collect();
    if loads.len() != 1 || stores.len() != 1 {
        return None;
    }
    let (load_pos, load_reg, lmem): (usize, u8, Mem) = loads[0];
    let (store_pos, _, smem): (usize, u8, Mem) = stores[0];
    let (in_reg, (idx_reg, scale)): (Reg, (Reg, u8)) = (lmem.base?, lmem.index?);
    let (out_reg, (out_idx, out_scale)): (Reg, (Reg, u8)) = (smem.base?, smem.index?);
    if idx_reg != out_idx
        || scale != out_scale
        || lmem.disp != 0
        || smem.disp != 0
        || in_reg == out_reg
    {
        return None;
    }
    let width: ElemWidth = map_body_width_hint(body, load_pos, store_pos)?;
    let step: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == idx_reg => Some(v),
                _ => None,
            })?;
    if step.checked_mul(i64::from(scale))? != 16 {
        return None;
    }
    let transform: Term = packed_lane_value(body, load_pos, store_pos, load_reg)?;
    Some(PtrWalkMap {
        transform,
        width,
        in_reg,
        out_reg,
        idx_reg,
        header_idx: header,
        back_idx: back,
    })
}

fn verify_ptrwalk_map_bound(insns: &[Insn], pmap: &PtrWalkMap) -> Option<Reg> {
    let body: &[Insn] = insns.get(pmap.header_idx..=pmap.back_idx)?;
    let count_reg: Reg = cmp_other_reg(body, pmap.idx_reg)?;
    let elem_bytes: u64 = pmap.width.bytes();
    let step_bytes: i64 =
        body.iter()
            .find_map(|i: &Insn| match (i.mnem.as_str(), i.gpr(0), i.imm(1)) {
                ("add", Some((r, _)), Some(v)) if r == pmap.idx_reg => Some(v),
                _ => None,
            })?;
    let per_iter: u64 = u64::try_from(step_bytes).ok()? / elem_bytes;
    if !per_iter.is_power_of_two() || !step_bytes.cast_unsigned().is_power_of_two() {
        return None;
    }
    let shr_k: i64 = i64::from(per_iter.trailing_zeros());
    let shl_k: i64 = i64::from(step_bytes.cast_unsigned().trailing_zeros());
    let prefix: &[Insn] = insns.get(..pmap.header_idx)?;
    let writes: Vec<(usize, &Insn)> = prefix
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| writes_gpr(i, count_reg))
        .collect();
    let last_three: &[(usize, &Insn)] = writes.get(writes.len().checked_sub(3)?..)?;
    let [(_, mov), (_, shr), (_, shl)] = last_three else {
        return None;
    };
    if mov.mnem != "mov" || shr.mnem != "shr" || shl.mnem != "shl" {
        return None;
    }
    if shr.imm(1)? != shr_k || shl.imm(1)? != shl_k {
        return None;
    }
    mov.gpr(1).map(|(r, _): (Reg, u8)| r)
}

fn fold_self_add(term: &Term) -> Term {
    match term {
        Term::Var(_) | Term::Const(_) => term.clone(),
        Term::App { op, width, args } => {
            let folded: Vec<Term> = args.iter().map(fold_self_add).collect();
            if *op == RingOp::Add && folded.len() == 2 && folded[0] == folded[1] {
                Term::app(RingOp::Mul, *width, vec![folded[0].clone(), Term::Const(2)])
            } else {
                Term::app(*op, *width, folded)
            }
        }
    }
}

fn find_map_half_block(
    insns: &[Insn],
    region: &[Insn],
    back_idx: usize,
    n_full: Reg,
    in_reg: Reg,
    out_reg: Reg,
    width: ElemWidth,
) -> Option<(usize, usize)> {
    let elem_bytes: u64 = width.bytes();
    let load_pos: usize = region
        .iter()
        .enumerate()
        .find_map(|(pos, insn): (usize, &Insn)| {
            if insn.mnem != "movq" || insn.xmm(0).is_none() {
                return None;
            }
            let mem: Mem = insn.mem(1)?;
            let base_ok: bool = mem
                .base
                .is_some_and(|b: Reg| resolves_to(insns, back_idx + 1 + pos, b, in_reg));
            let idx_ok: bool = mem.index.is_some_and(|(i, scale): (Reg, u8)| {
                u64::from(scale) == elem_bytes && resolves_to(region, pos, i, n_full)
            });
            (base_ok && idx_ok && mem.disp == 0).then_some(pos)
        })?;
    let load_dst: u8 = region.get(load_pos)?.xmm(0)?;
    let after_load: &[Insn] = region.get(load_pos + 1..)?;
    let store_pos: usize =
        after_load
            .iter()
            .enumerate()
            .find_map(|(rel, insn): (usize, &Insn)| {
                if insn.mnem != "movq" || insn.xmm(1) != Some(load_dst) {
                    return None;
                }
                let pos: usize = rel + load_pos + 1;
                let mem: Mem = insn.mem(0)?;
                let base_ok: bool = mem
                    .base
                    .is_some_and(|b: Reg| resolves_to(insns, back_idx + 1 + pos, b, out_reg));
                let idx_ok: bool = mem.index.is_some_and(|(i, scale): (Reg, u8)| {
                    u64::from(scale) == elem_bytes && resolves_to(region, pos, i, n_full)
                });
                (base_ok && idx_ok && mem.disp == 0).then_some(pos)
            })?;
    Some((load_pos, store_pos))
}

fn verify_map_tier2_offset_advance(
    region: &[Insn],
    add_pos: usize,
    n_full_reg: Reg,
    len_reg: Reg,
    w2: usize,
) -> bool {
    let Some(add_insn) = region.get(add_pos) else {
        return false;
    };
    if add_insn.mnem != "add" || add_insn.gpr(0).map(|(r, _): (Reg, u8)| r) != Some(n_full_reg) {
        return false;
    }
    let Some((w2_reg, _)) = add_insn.gpr(1) else {
        return false;
    };
    let Ok(w2_i64) = i64::try_from(w2) else {
        return false;
    };
    let Some(and_pos) = last_write_pos(region, add_pos, w2_reg) else {
        return false;
    };
    let and_insn: &Insn = &region[and_pos];
    if and_insn.mnem != "and" || and_insn.imm(1) != Some(-w2_i64) {
        return false;
    }
    let Some(mut pos) = last_write_pos(region, and_pos, w2_reg) else {
        return false;
    };
    let mut cur: Reg = w2_reg;
    if region[pos].mnem == "mov" {
        let Some((rem_reg, _)) = region[pos].gpr(1) else {
            return false;
        };
        cur = rem_reg;
        let Some(next_pos) = last_write_pos(region, pos, cur) else {
            return false;
        };
        pos = next_pos;
    }
    let sub_insn: &Insn = &region[pos];
    if sub_insn.mnem != "sub" {
        return false;
    }
    let (Some((sub_dst, _)), Some((sub_rhs, _))) = (sub_insn.gpr(0), sub_insn.gpr(1)) else {
        return false;
    };
    if sub_dst != cur || !resolves_to(region, pos, sub_rhs, n_full_reg) {
        return false;
    }
    let Some(len_mov_pos) = last_write_pos(region, pos, cur) else {
        return false;
    };
    let len_mov: &Insn = &region[len_mov_pos];
    len_mov.mnem == "mov" && len_mov.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
}

fn scalar_transform_chain(window: &[Insn], load_reg: Reg) -> Option<Term> {
    let mut cur: Term = Term::Var(0);
    for insn in window {
        let Some((dst, _)): Option<(Reg, u8)> = insn.gpr(0) else {
            continue;
        };
        if dst != load_reg {
            continue;
        }
        cur = match insn.mnem.as_str() {
            "mov" => {
                let (src, _): (Reg, u8) = insn.gpr(1)?;
                if src == load_reg {
                    cur
                } else {
                    return None;
                }
            }
            "add" => match (insn.gpr(1), insn.imm(1)) {
                (Some((r, _)), _) if r == load_reg => {
                    Term::app(RingOp::Add, ElemWidth::W64, vec![cur.clone(), cur])
                }
                (None, Some(v)) => Term::app(
                    RingOp::Add,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.cast_unsigned())],
                ),
                _ => return None,
            },
            "sub" => {
                let v: i64 = insn.imm(1)?;
                Term::app(
                    RingOp::Add,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.wrapping_neg().cast_unsigned())],
                )
            }
            "shl" => {
                let shift: u32 = u32::try_from(insn.imm(1)?).ok()?;
                Term::app(
                    RingOp::Mul,
                    ElemWidth::W64,
                    vec![cur, Term::Const(1u64.checked_shl(shift)?)],
                )
            }
            "imul" => {
                let v: i64 = insn.imm(1).or_else(|| insn.imm(2))?;
                Term::app(
                    RingOp::Mul,
                    ElemWidth::W64,
                    vec![cur, Term::Const(v.cast_unsigned())],
                )
            }
            "xor" => Term::app(
                RingOp::Xor,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            "and" => Term::app(
                RingOp::And,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            "or" => Term::app(
                RingOp::Or,
                ElemWidth::W64,
                vec![cur, Term::Const(insn.imm(1)?.cast_unsigned())],
            ),
            _ => return None,
        };
    }
    Some(cur)
}

fn verify_map_peeled_tail(
    insns: &[Insn],
    start: usize,
    pmap: &PtrWalkMap,
    r_reg: Reg,
    len_reg: Reg,
    max_elems: usize,
) -> Option<()> {
    let in_reg: Reg = pmap.in_reg;
    let out_reg: Reg = pmap.out_reg;
    let transform: &Term = &pmap.transform;
    let width: ElemWidth = pmap.width;
    let region: &[Insn] = insns.get(start..)?;
    let elem_bytes: i64 = i64::try_from(width.bytes()).ok()?;
    let mut aff: BTreeMap<Reg, Aff> = BTreeMap::new();
    aff.insert(r_reg, Aff { r: 1, c: 0 });
    let mut pending: Option<(i64, Reg, usize)> = None;
    let mut stores: Vec<(i64, usize)> = Vec::new();
    let mut idx_guards: Vec<(i64, usize)> = Vec::new();
    let wanted: Term = fold_self_add(transform);
    for (pos, insn) in region.iter().enumerate() {
        if let Some((j, load_reg, load_pos)) = pending
            && is_store(insn)
            && insn.gpr(1).map(|(r, _): (Reg, u8)| r) == Some(load_reg)
            && let Some(smem) = insn.mem(0)
            && peeled_elem_index(&aff, smem, out_reg, elem_bytes) == Some(j)
        {
            let window: &[Insn] = region.get(load_pos + 1..pos)?;
            let got: Term = scalar_transform_chain(window, load_reg)?;
            if !terms_equivalent(&fold_self_add(&got), &wanted) {
                return None;
            }
            stores.push((j, pos));
            pending = None;
            continue;
        }
        if let Some((_, load_reg, _)) = pending
            && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(load_reg)
        {
            continue;
        }
        match insn.mnem.as_str() {
            "mov" if insn.mem(1).is_some() && pending.is_none() => {
                let Some((d, _)): Option<(Reg, u8)> = insn.gpr(0) else {
                    continue;
                };
                let Some(m): Option<Mem> = insn.mem(1) else {
                    continue;
                };
                if let Some(j) = peeled_elem_index(&aff, m, in_reg, elem_bytes) {
                    pending = Some((j, d, pos));
                }
            }
            "mov" => {
                if let (Some((d, _)), Some((s, _))) = (insn.gpr(0), insn.gpr(1)) {
                    match aff.get(&s).copied() {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                } else if let Some((d, _)) = insn.gpr(0) {
                    aff.remove(&d);
                }
            }
            "lea" => {
                if let (Some((d, _)), Some(m)) = (insn.gpr(0), insn.mem(1)) {
                    match lea_affine(&aff, m) {
                        Some(a) => {
                            aff.insert(d, a);
                        }
                        None => {
                            aff.remove(&d);
                        }
                    }
                }
            }
            "cmp" => {
                let compared: Option<i64> = match (insn.gpr(0), insn.gpr(1)) {
                    (Some((a, _)), Some((b, _))) if a == len_reg => {
                        aff.get(&b).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    (Some((a, _)), Some((b, _))) if b == len_reg => {
                        aff.get(&a).filter(|x: &&Aff| x.r == 1).map(|x: &Aff| x.c)
                    }
                    _ => None,
                };
                if let Some(g) = compared {
                    idx_guards.push((g, pos));
                }
            }
            "add" => {
                if let (Some((d, _)), Some(imm)) = (insn.gpr(0), insn.imm(1))
                    && let Some(a) = aff.get(&d).copied()
                {
                    aff.insert(
                        d,
                        Aff {
                            r: a.r,
                            c: a.c + imm,
                        },
                    );
                } else if let Some((d, _)) = insn.gpr(0) {
                    aff.remove(&d);
                }
            }
            other => {
                if let Some((d, _)) = insn.gpr(0)
                    && !matches!(
                        other,
                        "jmp" | "je" | "jz" | "jle" | "jng" | "jl" | "ret" | "nop"
                    )
                {
                    aff.remove(&d);
                }
            }
        }
    }
    stores.sort_by_key(|t: &(i64, usize)| t.1);
    if stores.is_empty() || stores.len() > max_elems {
        return None;
    }
    for (want_j, &(j, pos)) in stores.iter().enumerate() {
        if j != i64::try_from(want_j).ok()? {
            return None;
        }
        if want_j >= 1 {
            let prev_pos: usize = stores[want_j - 1].1;
            let guarded: bool = idx_guards
                .iter()
                .any(|&(g, gp): &(i64, usize)| g == j && gp > prev_pos && gp < pos);
            if !guarded {
                return None;
            }
        }
    }
    Some(())
}

fn recognize_ptrwalk_map(insns: &[Insn]) -> Option<MapForm> {
    let edges: Vec<(usize, usize)> = find_back_edges(insns);
    let pmap: PtrWalkMap = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_map(insns, h, b))?;
    let abi_in_reg: Reg = traces_pristine_arg(insns, pmap.header_idx, pmap.in_reg)?;
    let abi_out_reg: Reg = traces_pristine_arg(insns, pmap.header_idx, pmap.out_reg)?;
    let len_reg: Reg = verify_ptrwalk_map_bound(insns, &pmap)?;
    let abi_len_reg: Reg = traces_pristine_arg(insns, pmap.header_idx, len_reg)?;
    if abi_len_reg == abi_in_reg || abi_len_reg == abi_out_reg {
        return None;
    }
    let vf: usize = (16 / pmap.width.bytes()) as usize;
    if vf < 2 {
        return None;
    }
    let vf_i64: i64 = i64::try_from(vf).ok()?;
    let region: &[Insn] = insns.get(pmap.back_idx + 1..)?;

    let mut n_full_reg: Option<Reg> = None;
    let mut n_full_pos: Option<usize> = None;
    for (pos, insn) in region.iter().enumerate() {
        if insn.mnem == "and"
            && insn.imm(1) == Some(-vf_i64)
            && let Some((d, _)) = insn.gpr(0)
            && resolves_to(region, pos, d, len_reg)
        {
            n_full_reg = Some(d);
            n_full_pos = Some(pos);
            break;
        }
    }
    let n_full: Reg = n_full_reg?;
    let n_full_pos: usize = n_full_pos?;

    let w2: usize = vf / 2;
    if vf % 2 == 0
        && let Some((_, store_pos)) = find_map_half_block(
            insns,
            region,
            pmap.back_idx,
            n_full,
            pmap.in_reg,
            pmap.out_reg,
            pmap.width,
        )
        && let Some(add_pos) = next_write_pos(region, store_pos + 1, n_full)
        && verify_map_tier2_offset_advance(region, add_pos, n_full, len_reg, w2)
    {
        let tail_start: usize = pmap.back_idx + 1 + add_pos + 1;
        verify_map_peeled_tail(insns, tail_start, &pmap, n_full, len_reg, w2 - 1)?;
        return Some(MapForm {
            transform: pmap.transform,
            width: pmap.width,
            in_reg: abi_in_reg,
            out_reg: abi_out_reg,
            len_reg: abi_len_reg,
        });
    }

    let tail_start: usize = pmap.back_idx + 1 + n_full_pos + 1;
    verify_map_peeled_tail(insns, tail_start, &pmap, n_full, len_reg, vf - 1)?;
    Some(MapForm {
        transform: pmap.transform,
        width: pmap.width,
        in_reg: abi_in_reg,
        out_reg: abi_out_reg,
        len_reg: abi_len_reg,
    })
}

#[derive(Debug, Clone, Copy)]
struct MinMaxForm {
    op: RingOp,
    width: ElemWidth,
    base_reg: Reg,
    len_reg: Reg,
    ret_bytes: u8,
}

fn verify_broadcast_seed(insns: &[Insn], header_idx: usize, base_reg: Reg, acc: u8) -> Option<()> {
    let prefix: &[Insn] = insns.get(..header_idx)?;
    let broadcast_pos: usize = prefix
        .iter()
        .position(|i: &Insn| i.mnem == "pshufd" && i.xmm(0) == Some(acc) && i.imm(2) == Some(0))?;
    let broadcast_src: u8 = prefix[broadcast_pos].xmm(1)?;
    let seed_gpr: Reg = prefix
        .get(..broadcast_pos)?
        .iter()
        .rev()
        .find_map(|i: &Insn| {
            (i.mnem == "movd" || i.mnem == "movq")
                .then(|| (i.xmm(0) == Some(broadcast_src)).then(|| i.gpr(1))?)?
        })?
        .0;
    let base_alias: Option<Reg> = prefix.iter().find_map(|i: &Insn| {
        (i.mnem == "mov" && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(base_reg))
            .then(|| i.gpr(1))?
            .map(|(r, _): (Reg, u8)| r)
    });
    prefix
        .iter()
        .any(|i: &Insn| {
            i.mnem == "mov"
                && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(seed_gpr)
                && i.mem(1).is_some_and(|m: Mem| {
                    (m.base == Some(base_reg) || (m.base.is_some() && m.base == base_alias))
                        && m.index.is_none()
                        && m.disp == 0
                })
        })
        .then_some(())
}

fn verify_minmax_seed(insns: &[Insn], vloop: &VectorLoop) -> Option<()> {
    let [acc]: [u8; 1] = vloop.accumulators.as_slice().try_into().ok()?;
    verify_broadcast_seed(insns, vloop.header_idx, vloop.base_reg, acc)
}

fn cmov_family(mnem: &str) -> Option<(bool, bool)> {
    Some(match mnem {
        "cmovg" | "cmovnle" | "cmovge" | "cmovnl" => (true, true),
        "cmovl" | "cmovnge" | "cmovle" | "cmovng" => (false, true),
        "cmova" | "cmovnbe" | "cmovae" | "cmovnb" => (true, false),
        "cmovb" | "cmovnae" | "cmovbe" | "cmovna" => (false, false),
        _ => return None,
    })
}

fn scalar_cmp_cmov_op(prev: &Insn, cmov: &Insn) -> Option<RingOp> {
    let (greater, signed): (bool, bool) = cmov_family(&cmov.mnem)?;
    if prev.mnem != "cmp" {
        return None;
    }
    let (p, _): (Reg, u8) = prev.gpr(0)?;
    let (q, _): (Reg, u8) = prev.gpr(1)?;
    let (dst, _): (Reg, u8) = cmov.gpr(0)?;
    let (src, _): (Reg, u8) = cmov.gpr(1)?;
    if src == dst {
        return None;
    }
    let dst_is_p: bool = if dst == p && src == q {
        true
    } else if dst == q && src == p {
        false
    } else {
        return None;
    };
    Some(match (dst_is_p, greater, signed) {
        (true, true, true) => RingOp::SMin,
        (true, false, true) => RingOp::SMax,
        (true, true, false) => RingOp::UMin,
        (true, false, false) => RingOp::UMax,
        (false, true, true) => RingOp::SMax,
        (false, false, true) => RingOp::SMin,
        (false, true, false) => RingOp::UMax,
        (false, false, false) => RingOp::UMin,
    })
}

fn find_minmax_remainder(insns: &[Insn], base_reg: Reg) -> Option<(RingOp, ElemWidth, Reg, u8)> {
    for (header, back) in find_back_edges(insns) {
        let body: &[Insn] = insns.get(header..=back)?;
        let Some((cmov_pos, op)) = body.iter().enumerate().find_map(|(p, i): (usize, &Insn)| {
            (p > 0)
                .then(|| scalar_cmp_cmov_op(&body[p - 1], i))
                .flatten()
                .map(|o: RingOp| (p, o))
        }) else {
            continue;
        };
        let (_acc, acc_bytes): (Reg, u8) = body[cmov_pos].gpr(0)?;
        let loaded: Reg = body[cmov_pos].gpr(1)?.0;
        let Some(load) = body.iter().find(|i: &&Insn| {
            i.mnem == "mov"
                && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(loaded)
                && i.mem(1).is_some_and(|m: Mem| m.base == Some(base_reg))
        }) else {
            continue;
        };
        let mem: Mem = load.mem(1)?;
        let (idx, scale): (Reg, u8) = mem.index?;
        let width: ElemWidth = ElemWidth::from_bytes(u64::from(scale))?;
        let has_inc: bool = body
            .iter()
            .any(|i: &Insn| match (i.mnem.as_str(), i.gpr(0)) {
                ("inc", Some((r, _))) if r == idx => true,
                ("add", Some((r, _))) if r == idx => i.imm(1) == Some(1),
                _ => false,
            });
        if !has_inc {
            continue;
        }
        let len_reg: Reg = cmp_other_reg(body, idx)?;
        return Some((op, width, len_reg, acc_bytes));
    }
    None
}

fn verify_minmax_mask(insns: &[Insn], count_reg: Reg, len_reg: Reg, vf: i64) -> Option<()> {
    let and_idx: usize = insns.iter().position(|i: &Insn| {
        i.mnem == "and"
            && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(count_reg)
            && i.imm(1).is_some()
    })?;
    let imm: i64 = insns[and_idx].imm(1)?;
    let low: u64 = vf.cast_unsigned().checked_sub(1)?;
    if imm.cast_unsigned() & low != 0 {
        return None;
    }
    let prefix: &[Insn] = insns.get(..and_idx)?;
    let source: Reg = prefix
        .iter()
        .rev()
        .find_map(|i: &Insn| {
            (i.mnem == "mov" && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(count_reg))
                .then(|| i.gpr(1))?
                .map(|(r, _): (Reg, u8)| r)
        })
        .unwrap_or(count_reg);
    let derived_from_len_minus_one: bool = prefix.iter().any(|i: &Insn| {
        i.mnem == "lea"
            && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(source)
            && i.mem(1)
                .is_some_and(|m: Mem| m.base == Some(len_reg) && m.index.is_none() && m.disp == -1)
    });
    derived_from_len_minus_one.then_some(())
}

fn verify_minmax_guard(insns: &[Insn], len_reg: Reg) -> Option<()> {
    for (i, insn) in insns.iter().enumerate() {
        let matches_cmp: bool = insn.mnem == "cmp"
            && insn.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(len_reg)
            && matches!(insn.imm(1), Some(1 | 2));
        if !matches_cmp {
            continue;
        }
        if let Some(next) = insns.get(i + 1)
            && matches!(next.mnem.as_str(), "jl" | "jle" | "jng")
            && next.rel(0).is_some()
        {
            return Some(());
        }
    }
    None
}

fn recognize_minmax(insns: &[Insn]) -> Option<MinMaxForm> {
    let edges: Vec<(usize, usize)> = find_back_edges(insns);
    let vloop: VectorLoop = edges
        .iter()
        .find_map(|&(h, b): &(usize, usize)| analyze_vector_loop(insns, h, b))?;
    if !vloop.op.is_associative_commutative() {
        return None;
    }
    if !matches!(vloop.op, RingOp::SMax | RingOp::SMin) || vloop.elem_offset != 1 {
        return None;
    }
    if vloop.step <= 0 || usize::try_from(vloop.step).ok()? != vloop.total_lanes() {
        return None;
    }
    if !vloop.step.cast_unsigned().is_power_of_two() {
        return None;
    }
    verify_minmax_seed(insns, &vloop)?;
    verify_epilog(
        insns,
        vloop.back_idx,
        vloop.op,
        vloop.width,
        &vloop.accumulators,
    )?;
    let (rem_op, rem_width, len_reg, ret_bytes): (RingOp, ElemWidth, Reg, u8) =
        find_minmax_remainder(insns, vloop.base_reg)?;
    if rem_op != vloop.op || rem_width != vloop.width {
        return None;
    }
    verify_minmax_mask(insns, vloop.count_reg, len_reg, vloop.step)?;
    verify_minmax_guard(insns, len_reg)?;
    Some(MinMaxForm {
        op: vloop.op,
        width: vloop.width,
        base_reg: vloop.base_reg,
        len_reg,
        ret_bytes,
    })
}

fn emit_minmax(form: MinMaxForm, abi: Abi, base_pos: usize, len_pos: usize) -> LeafRecovery {
    let nparams: usize = base_pos.max(len_pos) + 1;
    let params: Vec<Reg> = arg_order(abi)[..nparams].to_vec();
    let iet: &str = form.width.c_int();
    let uet: &str = form.width.c_uint();
    let cmp: &str = if matches!(form.op, RingOp::SMax) {
        ">"
    } else {
        "<"
    };
    let sig: String = (0..nparams)
        .map(|i: usize| format!("uint64_t a{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut source: String = String::new();
    let _ = writeln!(source, "#include <stdint.h>");
    let _ = writeln!(source, "uint64_t recovered({sig}) {{");
    let _ = writeln!(source, "    const {iet} *p = (const {iet} *)a{base_pos};");
    let _ = writeln!(source, "    int64_t n = (int64_t)a{len_pos};");
    let _ = writeln!(source, "    {iet} m = p[0];");
    let _ = writeln!(source, "    for (int64_t i = 1; i < n; i++) {{");
    let _ = writeln!(source, "        {iet} v = p[i];");
    let _ = writeln!(source, "        if (v {cmp} m) m = v;");
    let _ = writeln!(source, "    }}");
    let _ = writeln!(source, "    return (uint64_t)({uet})m;");
    let _ = writeln!(source, "}}");
    LeafRecovery {
        source,
        rust_source: None,
        return_width_bits: u32::from(form.ret_bytes) * 8,
        param_width_bits: vec![64; params.len()],
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
        call_site_signature: None,
    }
}

pub(crate) fn recover_vectorized_loop(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
) -> Result<LeafRecovery> {
    let raw: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    let parsed: Vec<Insn> = raw.iter().map(parse_insn).collect();
    let insns: Vec<Insn> = collapse_blends(&parsed);
    if let Some(form) = recognize_reduction(&insns) {
        let base_pos: usize = arg_index(abi, form.base_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: base pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_reduction(form, abi, base_pos, len_pos));
    }
    if let Some(form) = recognize_ptrwalk_reduction(&insns) {
        let base_pos: usize = arg_index(abi, form.base_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: base pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_reduction(form, abi, base_pos, len_pos));
    }
    if let Some(form) = recognize_minmax(&insns) {
        let base_pos: usize = arg_index(abi, form.base_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: base pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_minmax(form, abi, base_pos, len_pos));
    }
    if let Some(form) = recognize_ptrwalk_minmax(&insns) {
        let base_pos: usize = arg_index(abi, form.base_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: base pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_minmax(form, abi, base_pos, len_pos));
    }
    if let Some(form) = recognize_map(&insns).or_else(|| recognize_ptrwalk_map(&insns)) {
        let out_pos: usize = arg_index(abi, form.out_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: output pointer is not an abi argument register".to_owned())
        })?;
        let in_pos: usize = arg_index(abi, form.in_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: input pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_map(&form, abi, out_pos, in_pos, len_pos));
    }
    Err(Error::LlvmIr(
        "simd-devirt: not a recognized vectorized integer reduction or map".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTHS: [ElemWidth; 4] = [
        ElemWidth::W8,
        ElemWidth::W16,
        ElemWidth::W32,
        ElemWidth::W64,
    ];
    const OPS: [RingOp; 9] = [
        RingOp::Add,
        RingOp::Mul,
        RingOp::And,
        RingOp::Or,
        RingOp::Xor,
        RingOp::SMin,
        RingOp::SMax,
        RingOp::UMin,
        RingOp::UMax,
    ];
    const SAMPLES: [u64; 8] = [
        0,
        1,
        2,
        0x7f,
        0x80,
        0xffff_ffff,
        0x8000_0000_0000_0000,
        0xdead_beef_cafe_f00d,
    ];

    #[test]
    fn identity_is_two_sided_for_every_op_and_width() {
        for op in OPS {
            for width in WIDTHS {
                let e: u64 = op.identity(width);
                for x in SAMPLES {
                    let xm: u64 = x & width.mask();
                    assert_eq!(op.apply(e, xm, width), xm, "{op:?} left identity {width:?}");
                    assert_eq!(
                        op.apply(xm, e, width),
                        xm,
                        "{op:?} right identity {width:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_op_is_commutative_and_associative() {
        for op in OPS {
            assert!(op.is_associative_commutative());
            for width in WIDTHS {
                for a in SAMPLES {
                    for b in SAMPLES {
                        assert_eq!(
                            op.apply(a, b, width),
                            op.apply(b, a, width),
                            "{op:?} commute {width:?}"
                        );
                        for c in SAMPLES {
                            let left: u64 = op.apply(op.apply(a, b, width), c, width);
                            let right: u64 = op.apply(a, op.apply(b, c, width), width);
                            assert_eq!(left, right, "{op:?} assoc {width:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_min_max_respect_width_sign() {
        assert_eq!(RingOp::SMin.apply(0x80, 1, ElemWidth::W8), 0x80);
        assert_eq!(RingOp::SMax.apply(0x80, 1, ElemWidth::W8), 1);
        assert_eq!(RingOp::UMin.apply(0x80, 1, ElemWidth::W8), 1);
        assert_eq!(RingOp::UMax.apply(0x80, 1, ElemWidth::W8), 0x80);
    }

    #[test]
    fn normalizer_is_commutative_and_associative() {
        let w: ElemWidth = ElemWidth::W32;
        let a: Term = Term::Var(1);
        let b: Term = Term::Var(2);
        let c: Term = Term::Var(3);
        let left: Term = Term::app(RingOp::Add, w, vec![a.clone(), b.clone()]);
        let right: Term = Term::app(RingOp::Add, w, vec![b.clone(), a.clone()]);
        assert!(terms_equivalent(&left, &right));
        let nested_l: Term = Term::app(
            RingOp::Add,
            w,
            vec![
                Term::app(RingOp::Add, w, vec![a.clone(), b.clone()]),
                c.clone(),
            ],
        );
        let nested_r: Term = Term::app(
            RingOp::Add,
            w,
            vec![a, Term::app(RingOp::Add, w, vec![b, c])],
        );
        assert!(terms_equivalent(&nested_l, &nested_r));
    }

    #[test]
    fn normalizer_folds_identity_and_constants() {
        let w: ElemWidth = ElemWidth::W32;
        let a: Term = Term::Var(1);
        let with_zero: Term = Term::app(RingOp::Add, w, vec![a.clone(), Term::Const(0)]);
        assert_eq!(with_zero.normalize(), a);
        let consts: Term = Term::app(RingOp::Add, w, vec![Term::Const(2), Term::Const(3)]);
        assert_eq!(consts.normalize(), Term::Const(5));
        let and_ones: Term = Term::app(RingOp::And, w, vec![a.clone(), Term::Const(w.mask())]);
        assert_eq!(and_ones.normalize(), a);
    }

    #[test]
    fn normalizer_has_teeth() {
        let w: ElemWidth = ElemWidth::W32;
        let a: Term = Term::Var(1);
        let b: Term = Term::Var(2);
        let c: Term = Term::Var(3);
        let ab: Term = Term::app(RingOp::Add, w, vec![a.clone(), b]);
        let ac: Term = Term::app(RingOp::Add, w, vec![a.clone(), c]);
        assert!(!terms_equivalent(&ab, &ac));
        let doubled: Term = Term::app(RingOp::Add, w, vec![a.clone(), a.clone()]);
        assert!(!terms_equivalent(&doubled, &a));
        let mul_vs_add: Term = Term::app(RingOp::Mul, w, vec![a.clone(), a]);
        assert!(!terms_equivalent(&mul_vs_add, &doubled));
    }

    fn ins(mnem: &str, operands: &str) -> Insn {
        parse_insn(&DisasmInsn {
            address: 0,
            bytes: Vec::new(),
            mnemonic: mnem.to_owned(),
            operands: operands.to_owned(),
        })
    }

    #[test]
    fn map_body_width_hint_prefers_a_shift_over_a_byte_scaled_index() {
        let body: Vec<Insn> = seq(&[
            ("movdqu", "xmm0,[r9+rax*1]"),
            ("pslld", "xmm0,1"),
            ("movups", "[rcx+rax*1],xmm0"),
        ]);
        assert_eq!(map_body_width_hint(&body, 0, 2), Some(ElemWidth::W32));
        let bitwise_only: Vec<Insn> = seq(&[
            ("movdqu", "xmm0,[r9+rax*1]"),
            ("pxor", "xmm0,xmm1"),
            ("movups", "[rcx+rax*1],xmm0"),
        ]);
        assert_eq!(map_body_width_hint(&bitwise_only, 0, 2), None);
    }

    #[test]
    fn parses_packed_load_and_op() {
        let load: Insn = ins("movdqu", "xmm1,[rdi+rax*4]");
        assert_eq!(load.xmm(0), Some(1));
        assert_eq!(
            load.mem(1),
            Some(Mem {
                base: Some(Reg::Rdi),
                index: Some((Reg::Rax, 4)),
                disp: 0,
            })
        );
        let add: Insn = ins("paddd", "xmm0,xmm1");
        assert_eq!(add.xmm(0), Some(0));
        assert_eq!(add.xmm(1), Some(1));
    }

    #[test]
    fn parses_immediates_regs_and_disp() {
        assert_eq!(ins("add", "rax,4").imm(1), Some(4));
        assert_eq!(ins("cmp", "rcx,20h").imm(1), Some(0x20));
        assert_eq!(
            ins("mov", "rcx,7FFFFFFFFFFFFFFCh").imm(1),
            Some(0x7fff_ffff_ffff_fffc)
        );
        assert_eq!(ins("and", "r8,0FFFFFFFFFFFFFFFCh").imm(1), Some(-4));
        assert_eq!(ins("pshufd", "xmm1,xmm0,0EEh").imm(2), Some(0xee));
        assert_eq!(
            ins("lea", "rdx,[rsi-1]").mem(1).map(|m: Mem| m.disp),
            Some(-1)
        );
        assert_eq!(
            ins("movdqu", "xmm1,[rdi+rax*4+4]").mem(1),
            Some(Mem {
                base: Some(Reg::Rdi),
                index: Some((Reg::Rax, 4)),
                disp: 4,
            })
        );
        assert_eq!(ins("mov", "eax,[rdi]").gpr(0), Some((Reg::Rax, 4)));
        assert_eq!(
            ins("mov", "eax,[rdi]").mem(1),
            Some(Mem {
                base: Some(Reg::Rdi),
                index: None,
                disp: 0,
            })
        );
    }

    fn seq(lines: &[(&str, &str)]) -> Vec<Insn> {
        lines
            .iter()
            .map(|(m, o): &(&str, &str)| ins(m, o))
            .collect()
    }

    #[test]
    fn collapses_inplace_max_and_min_blends() {
        let max_body: Vec<Insn> = seq(&[
            ("movdqa", "xmm2,xmm1"),
            ("pcmpgtd", "xmm2,xmm0"),
            ("pand", "xmm1,xmm2"),
            ("pandn", "xmm2,xmm0"),
            ("movdqa", "xmm0,xmm2"),
            ("por", "xmm0,xmm1"),
        ]);
        let folded: Vec<Insn> = collapse_blends(&max_body);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].mnem, "vsmaxd");
        assert_eq!((folded[0].xmm(0), folded[0].xmm(1)), (Some(0), Some(1)));

        let min_body: Vec<Insn> = seq(&[
            ("movdqa", "xmm2,xmm0"),
            ("pcmpgtd", "xmm2,xmm1"),
            ("pand", "xmm1,xmm2"),
            ("pandn", "xmm2,xmm0"),
            ("movdqa", "xmm0,xmm2"),
            ("por", "xmm0,xmm1"),
        ]);
        let folded_min: Vec<Insn> = collapse_blends(&min_body);
        assert_eq!(folded_min.len(), 1);
        assert_eq!(folded_min[0].mnem, "vsmind");
    }

    #[test]
    fn collapses_out_of_place_epilog_blend() {
        let epi: Vec<Insn> = seq(&[
            ("movdqa", "xmm2,xmm0"),
            ("pcmpgtd", "xmm2,xmm1"),
            ("pand", "xmm0,xmm2"),
            ("pandn", "xmm2,xmm1"),
            ("por", "xmm2,xmm0"),
        ]);
        let folded: Vec<Insn> = collapse_blends(&epi);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].mnem, "movdqa");
        assert_eq!(folded[1].mnem, "vsmaxd");
        assert_eq!((folded[1].xmm(0), folded[1].xmm(1)), (Some(2), Some(1)));
    }

    #[test]
    fn collapses_gcc_dup_load_min_blend_across_an_interleaved_walk_advance() {
        let body: Vec<Insn> = seq(&[
            ("movdqu", "xmm1,[rax+4]"),
            ("movdqu", "xmm3,[rax+4]"),
            ("add", "rax,16"),
            ("pcmpgtd", "xmm1,xmm0"),
            ("pand", "xmm0,xmm1"),
            ("pandn", "xmm1,xmm3"),
            ("por", "xmm0,xmm1"),
            ("cmp", "rax,rcx"),
            ("jne", "short 0000000000000000h"),
        ]);
        let folded: Vec<Insn> = collapse_blends(&body);
        assert_eq!(folded.len(), 6);
        assert_eq!(folded[0].mnem, "movdqu");
        assert_eq!(folded[1].mnem, "movdqu");
        assert_eq!(folded[2].mnem, "add");
        assert_eq!(folded[3].mnem, "vsmind");
        assert_eq!((folded[3].xmm(0), folded[3].xmm(1)), (Some(0), Some(3)));
    }

    #[test]
    fn dup_load_min_blend_requires_the_same_memory_operand_on_both_loads() {
        let body: Vec<Insn> = seq(&[
            ("movdqu", "xmm1,[rax+4]"),
            ("movdqu", "xmm3,[rax+8]"),
            ("pcmpgtd", "xmm1,xmm0"),
            ("pand", "xmm0,xmm1"),
            ("pandn", "xmm1,xmm3"),
            ("por", "xmm0,xmm1"),
            ("cmp", "rax,rcx"),
            ("jne", "short 0000000000000000h"),
        ]);
        let folded: Vec<Insn> = collapse_blends(&body);
        assert_eq!(folded.len(), body.len());
    }

    #[test]
    fn collapses_movdqa_duplicate_min_blend() {
        let body: Vec<Insn> = seq(&[
            ("movdqa", "xmm1,xmm2"),
            ("pcmpgtd", "xmm1,xmm0"),
            ("pand", "xmm0,xmm1"),
            ("pandn", "xmm1,xmm2"),
            ("por", "xmm0,xmm1"),
        ]);
        let folded: Vec<Insn> = collapse_blends(&body);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].mnem, "vsmind");
        assert_eq!((folded[0].xmm(0), folded[0].xmm(1)), (Some(0), Some(2)));
    }

    #[test]
    fn parses_store_extract_and_branches() {
        let store: Insn = ins("movdqu", "[rdi+rcx*4],xmm0");
        assert_eq!(store.mem(0).and_then(|m: Mem| m.base), Some(Reg::Rdi));
        assert_eq!(store.xmm(1), Some(0));
        assert_eq!(ins("movd", "eax,xmm0").gpr(0), Some((Reg::Rax, 4)));
        assert_eq!(ins("movq", "rax,xmm1").gpr(0), Some((Reg::Rax, 8)));
        assert_eq!(ins("jne", "short 0000000000000030h").rel(0), Some(0x30));
        assert_eq!(ins("jl", "near 0000000000000130h").rel(0), Some(0x130));
        assert_eq!(ins("jmp", "short 000000000000005Ah").rel(0), Some(0x5a));
    }

    #[test]
    fn fold_of_partition_equals_fold_of_whole() {
        let w: ElemWidth = ElemWidth::W32;
        let lanes: Vec<Term> = (1..=8).map(Term::Var).collect();
        let whole: Term = fold_terms(RingOp::Add, w, &lanes);
        let left: Term = fold_terms(RingOp::Add, w, &lanes[..4]);
        let right: Term = fold_terms(RingOp::Add, w, &lanes[4..]);
        let combined: Term = Term::app(RingOp::Add, w, vec![left, right]);
        assert!(terms_equivalent(&whole, &combined));
    }

    #[test]
    fn pshufd_lane_perm_expands_dword_permutation_to_narrower_lanes() {
        assert_eq!(pshufd_lane_perm(0xee, 4), Some(vec![2, 3, 2, 3]));
        assert_eq!(
            pshufd_lane_perm(0xee, 8),
            Some(vec![4, 5, 6, 7, 4, 5, 6, 7])
        );
        assert_eq!(
            pshufd_lane_perm(0x55, 8),
            Some(vec![2, 3, 2, 3, 2, 3, 2, 3])
        );
        assert_eq!(
            pshufd_lane_perm(0xe4, 16),
            Some(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert_eq!(pshufd_lane_perm(0, 32), None);
    }

    #[test]
    fn shift_right_logical_lanes_matches_hardware_dword_semantics() {
        let vars: Vec<Term> = (0..8).map(Term::Var).collect();
        assert_eq!(
            shift_right_logical_lanes(&vars, 32, ElemWidth::W16, 16),
            Some(vec![
                Term::Var(1),
                Term::Const(0),
                Term::Var(3),
                Term::Const(0),
                Term::Var(5),
                Term::Const(0),
                Term::Var(7),
                Term::Const(0),
            ])
        );
        assert!(shift_right_logical_lanes(&vars, 32, ElemWidth::W16, 3).is_none());
        assert_eq!(
            shift_right_logical_lanes(&vars, 32, ElemWidth::W16, 0),
            Some(vars)
        );
    }

    #[test]
    fn cmp_cmov_op_matches_both_gcc_and_clang_orientations_for_max() {
        let gcc_cmp: Insn = ins("cmp", "eax,ecx");
        let gcc_cmov: Insn = ins("cmovl", "eax,ecx");
        assert_eq!(scalar_cmp_cmov_op(&gcc_cmp, &gcc_cmov), Some(RingOp::SMax));

        let clang_cmp: Insn = ins("cmp", "r9d,eax");
        let clang_cmov: Insn = ins("cmovg", "eax,r9d");
        assert_eq!(
            scalar_cmp_cmov_op(&clang_cmp, &clang_cmov),
            Some(RingOp::SMax)
        );
    }

    #[test]
    fn cmp_cmov_op_matches_both_gcc_and_clang_orientations_for_min() {
        let gcc_cmp: Insn = ins("cmp", "eax,ecx");
        let gcc_cmov: Insn = ins("cmovg", "eax,ecx");
        assert_eq!(scalar_cmp_cmov_op(&gcc_cmp, &gcc_cmov), Some(RingOp::SMin));

        let clang_cmp: Insn = ins("cmp", "r9d,eax");
        let clang_cmov: Insn = ins("cmovl", "eax,r9d");
        assert_eq!(
            scalar_cmp_cmov_op(&clang_cmp, &clang_cmov),
            Some(RingOp::SMin)
        );
    }

    #[test]
    fn cmp_cmov_op_derives_unsigned_variants_and_rejects_mismatched_operands() {
        let cmp: Insn = ins("cmp", "eax,ecx");
        assert_eq!(
            scalar_cmp_cmov_op(&cmp, &ins("cmova", "eax,ecx")),
            Some(RingOp::UMin)
        );
        assert_eq!(
            scalar_cmp_cmov_op(&cmp, &ins("cmovb", "eax,ecx")),
            Some(RingOp::UMax)
        );
        assert_eq!(scalar_cmp_cmov_op(&cmp, &ins("cmovl", "eax,edx")), None);
        assert_eq!(
            scalar_cmp_cmov_op(&ins("add", "eax,ecx"), &ins("cmovl", "eax,ecx")),
            None
        );
    }

    #[test]
    fn broadcast_seed_accepts_gccs_two_register_chain_and_clangs_self_chain() {
        let base: Insn = ins("mov", "eax,[rcx]");
        let clang_seed: Vec<Insn> = vec![
            base.clone(),
            ins("movd", "xmm0,eax"),
            ins("pshufd", "xmm0,xmm0,0"),
        ];
        assert!(verify_broadcast_seed(&clang_seed, 3, Reg::Rcx, 0).is_some());

        let gcc_seed: Vec<Insn> = vec![base, ins("movd", "xmm3,eax"), ins("pshufd", "xmm0,xmm3,0")];
        assert!(verify_broadcast_seed(&gcc_seed, 3, Reg::Rcx, 0).is_some());

        let unrelated_seed: Vec<Insn> = vec![
            ins("mov", "eax,[rdx]"),
            ins("movd", "xmm3,eax"),
            ins("pshufd", "xmm0,xmm3,0"),
        ];
        assert!(verify_broadcast_seed(&unrelated_seed, 3, Reg::Rcx, 0).is_none());
    }

    fn insn_at(addr: u64, mnem: &str, operands: &str) -> Insn {
        parse_insn(&DisasmInsn {
            address: addr,
            bytes: Vec::new(),
            mnemonic: mnem.to_owned(),
            operands: operands.to_owned(),
        })
    }

    #[test]
    fn recovers_gcc_three_tier_i16_reduction_remainder() {
        let insns: Vec<Insn> = vec![
            insn_at(0x280, "mov", "r8,rcx"),
            insn_at(0x283, "test", "rdx,rdx"),
            insn_at(0x286, "jle", "near 0000000000000380h"),
            insn_at(0x28c, "lea", "rax,[rdx-1]"),
            insn_at(0x290, "cmp", "rax,6"),
            insn_at(0x294, "jbe", "near 0000000000000383h"),
            insn_at(0x29a, "mov", "rax,rcx"),
            insn_at(0x29d, "mov", "rcx,rdx"),
            insn_at(0x2a0, "pxor", "xmm0,xmm0"),
            insn_at(0x2a4, "shr", "rcx,3"),
            insn_at(0x2a8, "shl", "rcx,4"),
            insn_at(0x2ac, "add", "rcx,r8"),
            insn_at(0x2af, "nop", ""),
            insn_at(0x2b0, "movdqu", "xmm3,[rax]"),
            insn_at(0x2b4, "add", "rax,10h"),
            insn_at(0x2b8, "paddw", "xmm0,xmm3"),
            insn_at(0x2bc, "cmp", "rcx,rax"),
            insn_at(0x2bf, "jne", "short 00000000000002B0h"),
            insn_at(0x2c1, "movdqa", "xmm1,xmm0"),
            insn_at(0x2c5, "mov", "rcx,rdx"),
            insn_at(0x2c8, "psrldq", "xmm1,8"),
            insn_at(0x2cd, "and", "rcx,0FFFFFFFFFFFFFFF8h"),
            insn_at(0x2d1, "paddw", "xmm1,xmm0"),
            insn_at(0x2d5, "mov", "r10,rcx"),
            insn_at(0x2d8, "movdqa", "xmm2,xmm1"),
            insn_at(0x2dc, "psrldq", "xmm2,4"),
            insn_at(0x2e1, "paddw", "xmm1,xmm2"),
            insn_at(0x2e5, "movdqa", "xmm2,xmm1"),
            insn_at(0x2e9, "psrldq", "xmm2,2"),
            insn_at(0x2ee, "paddw", "xmm1,xmm2"),
            insn_at(0x2f2, "pextrw", "eax,xmm1,0"),
            insn_at(0x2f7, "movdqa", "xmm1,xmm0"),
            insn_at(0x2fb, "psrldq", "xmm0,8"),
            insn_at(0x300, "paddw", "xmm1,xmm0"),
            insn_at(0x304, "cmp", "rdx,rcx"),
            insn_at(0x307, "je", "short 0000000000000379h"),
            insn_at(0x309, "mov", "r9,rdx"),
            insn_at(0x30c, "sub", "r9,r10"),
            insn_at(0x30f, "lea", "r11,[r9-1]"),
            insn_at(0x313, "cmp", "r11,2"),
            insn_at(0x317, "jbe", "short 0000000000000352h"),
            insn_at(0x319, "movq", "xmm0,[r8+r10*2]"),
            insn_at(0x31f, "mov", "r10,r9"),
            insn_at(0x322, "and", "r10,0FFFFFFFFFFFFFFFCh"),
            insn_at(0x326, "paddw", "xmm0,xmm1"),
            insn_at(0x32a, "add", "rcx,r10"),
            insn_at(0x32d, "and", "r9d,3"),
            insn_at(0x331, "movdqa", "xmm1,xmm0"),
            insn_at(0x335, "psrlq", "xmm1,20h"),
            insn_at(0x33a, "paddw", "xmm0,xmm1"),
            insn_at(0x33e, "movdqa", "xmm1,xmm0"),
            insn_at(0x342, "psrlq", "xmm1,10h"),
            insn_at(0x347, "paddw", "xmm0,xmm1"),
            insn_at(0x34b, "pextrw", "eax,xmm0,0"),
            insn_at(0x350, "je", "short 0000000000000379h"),
            insn_at(0x352, "lea", "r10,[rcx+1]"),
            insn_at(0x356, "lea", "r9,[rcx+rcx]"),
            insn_at(0x35a, "add", "ax,[r8+rcx*2]"),
            insn_at(0x35f, "cmp", "rdx,r10"),
            insn_at(0x362, "jle", "short 0000000000000379h"),
            insn_at(0x364, "add", "rcx,2"),
            insn_at(0x368, "add", "ax,[r8+r9+2]"),
            insn_at(0x36e, "cmp", "rdx,rcx"),
            insn_at(0x371, "jle", "short 0000000000000379h"),
            insn_at(0x373, "add", "ax,[r8+r9+4]"),
            insn_at(0x379, "ret", ""),
            insn_at(0x37a, "nop", ""),
            insn_at(0x380, "xor", "eax,eax"),
            insn_at(0x382, "ret", ""),
            insn_at(0x383, "pxor", "xmm1,xmm1"),
            insn_at(0x387, "xor", "r10d,r10d"),
            insn_at(0x38a, "xor", "ecx,ecx"),
            insn_at(0x38c, "xor", "eax,eax"),
            insn_at(0x38e, "jmp", "0000000000000309h"),
        ];
        let recognized: Option<ReductionForm> = recognize_ptrwalk_reduction(&insns);
        assert!(
            recognized.is_some(),
            "expected the wide ptrwalk remainder path to recognize the gcc i16 reduction"
        );
        if let Some(form) = recognized {
            assert_eq!(form.op, RingOp::Add);
            assert_eq!(form.width, ElemWidth::W16);
            assert_eq!(form.base_reg, Reg::Rcx);
            assert_eq!(form.len_reg, Reg::Rdx);
            assert_eq!(form.ret_bytes, 2);
        }

        let edges: Vec<(usize, usize)> = find_back_edges(&insns);
        let vloop: Option<PtrWalkLoop> = edges
            .iter()
            .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_loop(&insns, h, b))
            .or_else(|| {
                edges
                    .iter()
                    .find_map(|&(h, b): &(usize, usize)| analyze_ptrwalk_loop_wide(&insns, h, b))
            });
        assert!(
            vloop.is_some(),
            "expected a ptrwalk loop analyzer to recognize the vector loop"
        );
        let direct_end: Option<Reg> =
            vloop.and_then(|v: PtrWalkLoop| verify_ptrwalk_end(&insns, &v));
        assert!(
            direct_end.is_none(),
            "the single-tier end-pointer check must stay unable to match this base/end register alias, proving the wide fallback path is the one doing the work"
        );
    }

    #[test]
    fn recovers_gcc_three_tier_i32_map_with_half_width_tier() {
        let insns: Vec<Insn> = vec![
            insn_at(0x580, "mov", "r9,rdx"),
            insn_at(0x583, "test", "r8,r8"),
            insn_at(0x586, "jle", "short 00000000000005BAh"),
            insn_at(0x588, "cmp", "r8,1"),
            insn_at(0x58c, "je", "near 0000000000000640h"),
            insn_at(0x592, "lea", "rax,[rdx+4]"),
            insn_at(0x596, "mov", "rdx,rcx"),
            insn_at(0x599, "sub", "rdx,rax"),
            insn_at(0x59c, "xor", "eax,eax"),
            insn_at(0x59e, "cmp", "rdx,8"),
            insn_at(0x5a2, "ja", "short 00000000000005C0h"),
            insn_at(0x5a4, "nop", "dword [rax]"),
            insn_at(0x5a8, "mov", "edx,[r9+rax*4]"),
            insn_at(0x5ac, "add", "edx,edx"),
            insn_at(0x5ae, "mov", "[rcx+rax*4],edx"),
            insn_at(0x5b1, "add", "rax,1"),
            insn_at(0x5b5, "cmp", "r8,rax"),
            insn_at(0x5b8, "jne", "short 00000000000005A8h"),
            insn_at(0x5ba, "ret", ""),
            insn_at(0x5bb, "nop", "dword [rax+rax]"),
            insn_at(0x5c0, "lea", "rdx,[r8-1]"),
            insn_at(0x5c4, "mov", "rax,r8"),
            insn_at(0x5c7, "cmp", "rdx,2"),
            insn_at(0x5cb, "jbe", "short 0000000000000647h"),
            insn_at(0x5cd, "mov", "rdx,r8"),
            insn_at(0x5d0, "xor", "eax,eax"),
            insn_at(0x5d2, "shr", "rdx,2"),
            insn_at(0x5d6, "shl", "rdx,4"),
            insn_at(0x5da, "nop", "word [rax+rax]"),
            insn_at(0x5e0, "movdqu", "xmm0,[r9+rax]"),
            insn_at(0x5e6, "pslld", "xmm0,1"),
            insn_at(0x5eb, "movups", "[rcx+rax],xmm0"),
            insn_at(0x5ef, "add", "rax,10h"),
            insn_at(0x5f3, "cmp", "rax,rdx"),
            insn_at(0x5f6, "jne", "short 00000000000005E0h"),
            insn_at(0x5f8, "mov", "rdx,r8"),
            insn_at(0x5fb, "and", "rdx,0FFFFFFFFFFFFFFFCh"),
            insn_at(0x5ff, "mov", "r10,rdx"),
            insn_at(0x602, "cmp", "r8,rdx"),
            insn_at(0x605, "je", "short 00000000000005BAh"),
            insn_at(0x607, "mov", "rax,r8"),
            insn_at(0x60a, "sub", "rax,rdx"),
            insn_at(0x60d, "cmp", "rax,1"),
            insn_at(0x611, "je", "short 000000000000062Fh"),
            insn_at(0x613, "movq", "xmm0,[r9+r10*4]"),
            insn_at(0x619, "pslld", "xmm0,1"),
            insn_at(0x61e, "movq", "[rcx+r10*4],xmm0"),
            insn_at(0x624, "test", "al,1"),
            insn_at(0x626, "je", "short 00000000000005BAh"),
            insn_at(0x628, "and", "rax,0FFFFFFFFFFFFFFFEh"),
            insn_at(0x62c, "add", "rdx,rax"),
            insn_at(0x62f, "mov", "eax,[r9+rdx*4]"),
            insn_at(0x633, "add", "eax,eax"),
            insn_at(0x635, "mov", "[rcx+rdx*4],eax"),
            insn_at(0x638, "ret", ""),
            insn_at(0x639, "nop", "dword [rax]"),
            insn_at(0x640, "xor", "eax,eax"),
            insn_at(0x642, "jmp", "00000000000005A8h"),
            insn_at(0x647, "xor", "r10d,r10d"),
            insn_at(0x64a, "xor", "edx,edx"),
            insn_at(0x64c, "jmp", "short 0000000000000613h"),
        ];
        let recognized: Option<MapForm> = recognize_ptrwalk_map(&insns);
        assert!(
            recognized.is_some(),
            "expected the half-width tier2 fold to be recognized"
        );
        if let Some(form) = recognized {
            assert_eq!(form.width, ElemWidth::W32);
            assert_eq!(form.in_reg, Reg::Rdx);
            assert_eq!(form.out_reg, Reg::Rcx);
            assert_eq!(form.len_reg, Reg::R8);
        }
    }

    #[test]
    fn recovers_gcc_i32_map_peeled_tail_with_interleaved_address_precompute() {
        let insns: Vec<Insn> = vec![
            insn_at(0x650, "mov", "r9,rdx"),
            insn_at(0x653, "test", "r8,r8"),
            insn_at(0x656, "jle", "short 0000000000000693h"),
            insn_at(0x658, "lea", "rax,[r8-1]"),
            insn_at(0x65c, "cmp", "rax,2"),
            insn_at(0x660, "jbe", "near 0000000000000710h"),
            insn_at(0x666, "lea", "rax,[rdx+4]"),
            insn_at(0x66a, "mov", "rdx,rcx"),
            insn_at(0x66d, "sub", "rdx,rax"),
            insn_at(0x670, "xor", "eax,eax"),
            insn_at(0x672, "cmp", "rdx,8"),
            insn_at(0x676, "ja", "short 0000000000000698h"),
            insn_at(0x678, "nop", "dword [rax+rax]"),
            insn_at(0x680, "mov", "edx,[r9+rax*4]"),
            insn_at(0x684, "shl", "edx,3"),
            insn_at(0x687, "mov", "[rcx+rax*4],edx"),
            insn_at(0x68a, "add", "rax,1"),
            insn_at(0x68e, "cmp", "r8,rax"),
            insn_at(0x691, "jne", "short 0000000000000680h"),
            insn_at(0x693, "ret", ""),
            insn_at(0x694, "nop", "dword [rax]"),
            insn_at(0x698, "mov", "rdx,r8"),
            insn_at(0x69b, "shr", "rdx,2"),
            insn_at(0x69f, "shl", "rdx,4"),
            insn_at(0x6a3, "nop", "dword [rax+rax]"),
            insn_at(0x6a8, "movdqu", "xmm0,[r9+rax]"),
            insn_at(0x6ae, "pslld", "xmm0,3"),
            insn_at(0x6b3, "movups", "[rcx+rax],xmm0"),
            insn_at(0x6b7, "add", "rax,10h"),
            insn_at(0x6bb, "cmp", "rdx,rax"),
            insn_at(0x6be, "jne", "short 00000000000006A8h"),
            insn_at(0x6c0, "mov", "rax,r8"),
            insn_at(0x6c3, "and", "rax,0FFFFFFFFFFFFFFFCh"),
            insn_at(0x6c7, "test", "r8b,3"),
            insn_at(0x6cb, "je", "short 0000000000000693h"),
            insn_at(0x6cd, "mov", "edx,[r9+rax*4]"),
            insn_at(0x6d1, "shl", "edx,3"),
            insn_at(0x6d4, "mov", "[rcx+rax*4],edx"),
            insn_at(0x6d7, "lea", "rdx,[rax+1]"),
            insn_at(0x6db, "cmp", "r8,rdx"),
            insn_at(0x6de, "jle", "short 0000000000000693h"),
            insn_at(0x6e0, "mov", "r10d,[r9+rdx*4]"),
            insn_at(0x6e4, "add", "rax,2"),
            insn_at(0x6e8, "lea", "r11,[rdx*4]"),
            insn_at(0x6f0, "shl", "r10d,3"),
            insn_at(0x6f4, "mov", "[rcx+rdx*4],r10d"),
            insn_at(0x6f8, "cmp", "r8,rax"),
            insn_at(0x6fb, "jle", "short 0000000000000693h"),
            insn_at(0x6fd, "mov", "eax,[r9+r11+4]"),
            insn_at(0x702, "shl", "eax,3"),
            insn_at(0x705, "mov", "[rcx+r11+4],eax"),
            insn_at(0x70a, "ret", ""),
        ];
        let recognized: Option<MapForm> = recognize_ptrwalk_map(&insns);
        assert!(
            recognized.is_some(),
            "expected the peeled tail to tolerate interleaved next-element address precompute"
        );
        if let Some(form) = recognized {
            assert_eq!(form.width, ElemWidth::W32);
            assert_eq!(form.in_reg, Reg::Rdx);
            assert_eq!(form.out_reg, Reg::Rcx);
            assert_eq!(form.len_reg, Reg::R8);
        }
    }

    #[test]
    fn recovers_gcc_sysv_map_when_entry_swaps_length_into_the_output_arg_register() {
        let insns: Vec<Insn> = vec![
            insn_at(0x650, "mov", "rcx,rdi"),
            insn_at(0x653, "mov", "rdi,rdx"),
            insn_at(0x656, "test", "rdx,rdx"),
            insn_at(0x659, "jle", "short 0000000000000692h"),
            insn_at(0x65b, "lea", "rax,[rdx-1]"),
            insn_at(0x65f, "cmp", "rax,2"),
            insn_at(0x663, "jbe", "near 0000000000000710h"),
            insn_at(0x669, "lea", "rax,[rsi+4]"),
            insn_at(0x66d, "mov", "rdx,rcx"),
            insn_at(0x670, "sub", "rdx,rax"),
            insn_at(0x673, "xor", "eax,eax"),
            insn_at(0x675, "cmp", "rdx,8"),
            insn_at(0x679, "ja", "short 0000000000000698h"),
            insn_at(0x67b, "nop", "dword [rax+rax]"),
            insn_at(0x680, "mov", "edx,[rsi+rax*4]"),
            insn_at(0x683, "shl", "edx,3"),
            insn_at(0x686, "mov", "[rcx+rax*4],edx"),
            insn_at(0x689, "add", "rax,1"),
            insn_at(0x68d, "cmp", "rdi,rax"),
            insn_at(0x690, "jne", "short 0000000000000680h"),
            insn_at(0x692, "ret", ""),
            insn_at(0x693, "nop", "dword [rax+rax]"),
            insn_at(0x698, "mov", "rdx,rdi"),
            insn_at(0x69b, "shr", "rdx,2"),
            insn_at(0x69f, "shl", "rdx,4"),
            insn_at(0x6a3, "nop", "dword [rax+rax]"),
            insn_at(0x6a8, "movdqu", "xmm0,[rsi+rax]"),
            insn_at(0x6ad, "pslld", "xmm0,3"),
            insn_at(0x6b2, "movups", "[rcx+rax],xmm0"),
            insn_at(0x6b6, "add", "rax,10h"),
            insn_at(0x6ba, "cmp", "rdx,rax"),
            insn_at(0x6bd, "jne", "short 00000000000006A8h"),
            insn_at(0x6bf, "mov", "rax,rdi"),
            insn_at(0x6c2, "and", "rax,0FFFFFFFFFFFFFFFCh"),
            insn_at(0x6c6, "test", "dil,3"),
            insn_at(0x6ca, "je", "short 0000000000000692h"),
            insn_at(0x6cc, "mov", "edx,[rsi+rax*4]"),
            insn_at(0x6cf, "shl", "edx,3"),
            insn_at(0x6d2, "mov", "[rcx+rax*4],edx"),
            insn_at(0x6d5, "lea", "rdx,[rax+1]"),
            insn_at(0x6d9, "cmp", "rdi,rdx"),
            insn_at(0x6dc, "jle", "short 0000000000000692h"),
            insn_at(0x6de, "mov", "r10d,[rsi+rdx*4]"),
            insn_at(0x6e2, "add", "rax,2"),
            insn_at(0x6e6, "lea", "r9,[rdx*4]"),
            insn_at(0x6ee, "lea", "r8d,[r10*8]"),
            insn_at(0x6f6, "mov", "[rcx+rdx*4],r8d"),
            insn_at(0x6fa, "cmp", "rdi,rax"),
            insn_at(0x6fd, "jle", "short 0000000000000692h"),
            insn_at(0x6ff, "mov", "eax,[rsi+r9+4]"),
            insn_at(0x704, "shl", "eax,3"),
            insn_at(0x707, "mov", "[rcx+r9+4],eax"),
            insn_at(0x70c, "ret", ""),
            insn_at(0x70d, "nop", "dword [rax]"),
            insn_at(0x710, "xor", "eax,eax"),
            insn_at(0x712, "jmp", "0000000000000680h"),
        ];
        let recognized: Option<MapForm> = recognize_ptrwalk_map(&insns);
        assert!(
            recognized.is_some(),
            "expected the ptrwalk map to recover despite the entry mov rcx,rdi / mov rdi,rdx swap"
        );
        if let Some(form) = recognized {
            assert_eq!(form.width, ElemWidth::W32);
            assert_eq!(form.in_reg, Reg::Rsi);
            assert_eq!(form.out_reg, Reg::Rdi);
            assert_eq!(
                form.len_reg,
                Reg::Rdx,
                "length must resolve to the pristine third argument, not the loop-local rdi that aliases the output pointer register"
            );
        }
    }
}
