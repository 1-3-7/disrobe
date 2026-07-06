use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::arch::{Arch, DisasmInsn, disassemble};
use crate::error::{Error, Result};
use crate::pseudo_c::{Abi, LeafRecovery, Reg};

/// Integer element width of a packed SIMD lane.
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

/// A binary operator that is associative and commutative over the ring `Z / 2^n` for every lane width.
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

/// A symbolic bit-vector term in the loop-body lane algebra used by the bisimulation gate.
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

    /// Canonicalize this term: flatten AC chains, fold constants, drop identities, sort operands.
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

/// Fold a slice of lane terms with an AC operator, seeded by the operator identity.
pub(crate) fn fold_terms(op: RingOp, width: ElemWidth, lanes: &[Term]) -> Term {
    let mut args: Vec<Term> = Vec::with_capacity(lanes.len() + 1);
    args.push(Term::Const(op.identity(width)));
    args.extend(lanes.iter().cloned());
    Term::app(op, width, args).normalize()
}

/// True when two lane terms are provably equal after AC normalization.
pub(crate) fn terms_equivalent(left: &Term, right: &Term) -> bool {
    left.normalize() == right.normalize()
}

/// A memory operand `[base + index*scale + disp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mem {
    pub(crate) base: Option<Reg>,
    pub(crate) index: Option<(Reg, u8)>,
    pub(crate) disp: i64,
}

/// A parsed x86-64 instruction operand in the subset the SIMD recognizer models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Gpr { reg: Reg, bytes: u8 },
    Xmm(u8),
    Mem(Mem),
    Imm(i64),
    Rel(u64),
}

/// A decoded instruction: mnemonic plus its parsed operands.
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
        if let Some(window) = insns.get(i..i + 5)
            && let Some((mov, op)) = match_blend_out(window)
        {
            out.push(mov);
            out.push(op);
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
        _ => None,
    }
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

/// The recognized packed vector loop: its AC operator, lane width, base pointer, and lane coverage.
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

/// The recovered scalar remainder loop, which is the compiler-emitted original body verbatim.
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

fn verify_epilog(insns: &[Insn], vloop: &VectorLoop) -> Option<()> {
    let lpr: usize = vloop.lanes_per_reg();
    let total: usize = vloop.total_lanes();
    let mut regs: BTreeMap<u8, Vec<Term>> = BTreeMap::new();
    for (k, &acc) in vloop.accumulators.iter().enumerate() {
        let vars: Vec<Term> = (0..lpr)
            .map(|l: usize| Term::Var((k * lpr + l) as u32))
            .collect();
        regs.insert(acc, vars);
    }
    for insn in insns.get(vloop.back_idx + 1..)? {
        match insn.mnem.as_str() {
            "movd" | "movq" => {
                let src: u8 = insn.xmm(1)?;
                let got: Term = regs.get(&src)?.first()?.clone();
                let all: Vec<Term> = (0..total).map(|i: usize| Term::Var(i as u32)).collect();
                let want: Term = fold_terms(vloop.op, vloop.width, &all);
                return terms_equivalent(&got, &want).then_some(());
            }
            "movdqa" => {
                let (dst, src): (u8, u8) = (insn.xmm(0)?, insn.xmm(1)?);
                let value: Vec<Term> = regs.get(&src)?.clone();
                regs.insert(dst, value);
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
            other => {
                let (ring, _): (RingOp, Option<ElemWidth>) = packed_op_ringop(other)?;
                if ring != vloop.op {
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
                    .map(|(a, b): (Term, Term)| Term::app(vloop.op, vloop.width, vec![a, b]))
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

/// A proven vectorized integer reduction, sufficient to emit a clean scalar loop.
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
    verify_epilog(insns, &vloop)?;
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
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
    }
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

/// A proven vectorized elementwise map `out[i] = f(in[i])` over the integer ring.
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

fn analyze_map(insns: &[Insn], header: usize, back: usize) -> Option<(MapForm, Reg)> {
    let body: &[Insn] = insns.get(header..=back)?;
    let loads: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| matches!(i.mnem.as_str(), "movdqu" | "movdqa"))
        .filter_map(|(p, i): (usize, &Insn)| Some((p, i.xmm(0)?, i.mem(1)?)))
        .collect();
    let stores: Vec<(usize, u8, Mem)> = body
        .iter()
        .enumerate()
        .filter(|(_, i): &(usize, &Insn)| matches!(i.mnem.as_str(), "movdqu" | "movdqa"))
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
    let width: ElemWidth = ElemWidth::from_bytes(u64::from(scale))?;
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
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
    }
}

fn recognize_map(insns: &[Insn]) -> Option<MapForm> {
    find_back_edges(insns)
        .into_iter()
        .find_map(|(h, b): (usize, usize)| {
            analyze_map(insns, h, b).map(|(form, _): (MapForm, Reg)| form)
        })
}

/// A proven vectorized signed min/max reduction seeded from the first element.
#[derive(Debug, Clone, Copy)]
struct MinMaxForm {
    op: RingOp,
    width: ElemWidth,
    base_reg: Reg,
    len_reg: Reg,
    ret_bytes: u8,
}

fn verify_minmax_seed(insns: &[Insn], vloop: &VectorLoop) -> Option<()> {
    let [acc]: [u8; 1] = vloop.accumulators.as_slice().try_into().ok()?;
    let prefix: &[Insn] = insns.get(..vloop.header_idx)?;
    let broadcast_pos: usize = prefix.iter().position(|i: &Insn| {
        i.mnem == "pshufd" && i.xmm(0) == Some(acc) && i.xmm(1) == Some(acc) && i.imm(2) == Some(0)
    })?;
    let seed_gpr: Reg = prefix
        .get(..broadcast_pos)?
        .iter()
        .rev()
        .find_map(|i: &Insn| {
            (i.mnem == "movd" || i.mnem == "movq")
                .then(|| (i.xmm(0) == Some(acc)).then(|| i.gpr(1))?)?
        })?
        .0;
    let loads_first: bool = prefix.iter().any(|i: &Insn| {
        i.mnem == "mov"
            && i.gpr(0).map(|(r, _): (Reg, u8)| r) == Some(seed_gpr)
            && i.mem(1).is_some_and(|m: Mem| {
                m.base == Some(vloop.base_reg) && m.index.is_none() && m.disp == 0
            })
    });
    loads_first.then_some(())
}

fn cmov_ringop(mnem: &str) -> Option<RingOp> {
    Some(match mnem {
        "cmovg" | "cmovnle" | "cmovge" | "cmovnl" => RingOp::SMax,
        "cmovl" | "cmovnge" | "cmovle" | "cmovng" => RingOp::SMin,
        _ => return None,
    })
}

fn find_minmax_remainder(insns: &[Insn], base_reg: Reg) -> Option<(RingOp, ElemWidth, Reg, u8)> {
    for (header, back) in find_back_edges(insns) {
        let body: &[Insn] = insns.get(header..=back)?;
        let Some((cmov_pos, op)) = body
            .iter()
            .enumerate()
            .find_map(|(p, i): (usize, &Insn)| cmov_ringop(&i.mnem).map(|o: RingOp| (p, o)))
        else {
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
    verify_epilog(insns, &vloop)?;
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
        params,
        fp_params: Vec::new(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: true,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
    }
}

/// Recover an auto-vectorized integer reduction or elementwise map as a clean scalar loop, or sound-reject.
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
    if let Some(form) = recognize_minmax(&insns) {
        let base_pos: usize = arg_index(abi, form.base_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: base pointer is not an abi argument register".to_owned())
        })?;
        let len_pos: usize = arg_index(abi, form.len_reg).ok_or_else(|| {
            Error::LlvmIr("simd-devirt: length is not an abi argument register".to_owned())
        })?;
        return Ok(emit_minmax(form, abi, base_pos, len_pos));
    }
    if let Some(form) = recognize_map(&insns) {
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
}
