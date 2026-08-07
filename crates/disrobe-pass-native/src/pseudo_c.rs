use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::num::NonZeroU8;

use disrobe_emit::Interner;
use disrobe_emit::c::{
    AssignOp, BinaryOp, CBaseType, CDecl, CExpr, CInit, CStmt, CTypeSpec, Cx, DeclaratorChain,
    IntSuffix, LongSuffix, PostfixOp, Radix, TypeName, UnaryOp, render_expr, render_stmt,
};
use disrobe_emit::rust::{
    RBinOp, RUnOp, RustExpr, binary, call as rcall, cast as rcast, int_dec, int_hex, method_call,
    parse_expr, path_expr, ptr_type, render_expr as render_rust_expr, signed_int,
    type_path as rtype_path, unary as runary, unsafe_block, var as rvar,
};

use crate::arch::{Arch, DisasmInsn, disassemble};
use crate::error::{Error, Result};
use crate::structuring;

#[allow(clippy::redundant_pub_crate)]
pub(crate) mod aarch64;
mod aarch64_callsite;
pub mod fp_semantics;
mod return_channel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    A64X1,
    A64X2,
    A64X3,
    A64X4,
    A64X5,
    A64X6,
    A64X7,
    A64X8,
    A64X9,
    A64X10,
    A64X11,
    A64X12,
    A64X13,
    A64X14,
    A64X15,
    A64X16,
    A64X17,
    A64X18,
    A64X19,
    A64X20,
    A64X21,
    A64X22,
    A64X23,
    A64X24,
    A64X25,
    A64X26,
    A64X27,
    A64X28,
    A64Stack0,
    A64Stack1,
    A64Stack2,
    A64Stack3,
    A64Stack4,
    A64Stack5,
    A64Stack6,
    A64Stack7,
    A64Outgoing0,
    A64Outgoing1,
    A64Outgoing2,
    A64Outgoing3,
    A64Outgoing4,
    A64Outgoing5,
    A64Outgoing6,
    A64Outgoing7,
    A64Tmp,
    A64Tmp2,
    A64FlagLhs,
    A64FlagRhs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Width {
    W8,
    W16,
    W32,
    W64,
}

impl Width {
    const fn bits(self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    const fn shift_count_mask(self) -> u32 {
        match self {
            Self::W64 => 63,
            Self::W8 | Self::W16 | Self::W32 => 31,
        }
    }

    const fn from_typerec(width: disrobe_typerec::Width) -> Option<Self> {
        match width {
            disrobe_typerec::Width::Byte => Some(Self::W8),
            disrobe_typerec::Width::Word => Some(Self::W16),
            disrobe_typerec::Width::Dword => Some(Self::W32),
            disrobe_typerec::Width::Qword => Some(Self::W64),
            disrobe_typerec::Width::Unknown | disrobe_typerec::Width::Oword => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Xmm {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
    Xmm16,
    Xmm17,
    Xmm18,
    Xmm19,
    Xmm20,
    Xmm21,
    Xmm22,
    Xmm23,
    Xmm24,
    Xmm25,
    Xmm26,
    Xmm27,
    Xmm28,
    Xmm29,
    Xmm30,
    Xmm31,
}

impl Xmm {
    const fn index(self) -> u8 {
        self as u8
    }
}

fn parse_xmm(token: &str) -> Option<Xmm> {
    Some(match token.trim() {
        "xmm0" => Xmm::Xmm0,
        "xmm1" => Xmm::Xmm1,
        "xmm2" => Xmm::Xmm2,
        "xmm3" => Xmm::Xmm3,
        "xmm4" => Xmm::Xmm4,
        "xmm5" => Xmm::Xmm5,
        "xmm6" => Xmm::Xmm6,
        "xmm7" => Xmm::Xmm7,
        "xmm8" => Xmm::Xmm8,
        "xmm9" => Xmm::Xmm9,
        "xmm10" => Xmm::Xmm10,
        "xmm11" => Xmm::Xmm11,
        "xmm12" => Xmm::Xmm12,
        "xmm13" => Xmm::Xmm13,
        "xmm14" => Xmm::Xmm14,
        "xmm15" => Xmm::Xmm15,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpWidth {
    F32,
    F64,
}

impl FpWidth {
    const fn c_type(self) -> &'static str {
        match self {
            Self::F32 => "float",
            Self::F64 => "double",
        }
    }

    const fn rust_type(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    fn c_power_of_two(self, exponent: NonZeroU8) -> String {
        let magnitude: u8 = exponent.get();
        match self {
            Self::F32 => format!("0x1p{magnitude}f"),
            Self::F64 => format!("0x1p{magnitude}"),
        }
    }

    fn rust_power_of_two(self, exponent: NonZeroU8) -> Option<String> {
        let scale: u128 = 1u128.checked_shl(u32::from(exponent.get()))?;
        Some(format!("{scale}{}", self.rust_type()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundMode {
    Nearest,
    Floor,
    Ceil,
    Trunc,
    TiesAway,
}

impl RoundMode {
    const fn from_imm8(imm: i64) -> Option<Self> {
        if imm & 0x4 != 0 {
            return None;
        }
        Some(match imm & 0x3 {
            0 => Self::Nearest,
            1 => Self::Floor,
            2 => Self::Ceil,
            _ => Self::Trunc,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpMinMaxKind {
    SelectMax,
    SelectMin,
    IeeeMax,
    IeeeMin,
    PropagateMax,
    PropagateMin,
}

impl FpMinMaxKind {
    const fn is_max(self) -> bool {
        matches!(self, Self::SelectMax | Self::IeeeMax | Self::PropagateMax)
    }

    const fn is_propagating_nan(self) -> bool {
        matches!(self, Self::PropagateMax | Self::PropagateMin)
    }

    const fn uses_helper(self) -> bool {
        matches!(
            self,
            Self::IeeeMax | Self::IeeeMin | Self::PropagateMax | Self::PropagateMin
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpFmaKind {
    Madd,
    Msub,
    Nmadd,
    Nmsub,
}

impl FpFmaKind {
    const fn negates_multiplicand(self) -> bool {
        matches!(self, Self::Msub | Self::Nmadd)
    }

    const fn negates_addend(self) -> bool {
        matches!(self, Self::Nmadd | Self::Nmsub)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpUnaryOp {
    Neg,
    Abs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpToIntRound {
    Zero,
    Floor,
    Ceil,
    Away,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpOperand {
    Xmm(Xmm),
    Mem(MemRef),
    Const { bits: u64, width: FpWidth },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpConstant {
    pub site: u64,
    pub bits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PackedConstant {
    site: u64,
    q0: u64,
    q1: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackedOp {
    MovReg(Xmm),
    Const { q0: u64, q1: u64 },
    Zero,
    AddQ(Xmm),
    And(Xmm),
    AndN(Xmm),
    ShlQ(u8),
    ShlDq(u8),
    CmpEqD(Xmm),
    ShufD { src: Xmm, imm: u8 },
    FromGpr { src: RegRef },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegRef {
    reg: Reg,
    width: Width,
}

fn parse_reg(token: &str) -> Option<RegRef> {
    let name: &str = token.trim();
    let (reg, width): (Reg, Width) = match name {
        "rax" => (Reg::Rax, Width::W64),
        "eax" => (Reg::Rax, Width::W32),
        "ax" => (Reg::Rax, Width::W16),
        "al" => (Reg::Rax, Width::W8),
        "rbx" => (Reg::Rbx, Width::W64),
        "ebx" => (Reg::Rbx, Width::W32),
        "bx" => (Reg::Rbx, Width::W16),
        "bl" => (Reg::Rbx, Width::W8),
        "rcx" => (Reg::Rcx, Width::W64),
        "ecx" => (Reg::Rcx, Width::W32),
        "cx" => (Reg::Rcx, Width::W16),
        "cl" => (Reg::Rcx, Width::W8),
        "rdx" => (Reg::Rdx, Width::W64),
        "edx" => (Reg::Rdx, Width::W32),
        "dx" => (Reg::Rdx, Width::W16),
        "dl" => (Reg::Rdx, Width::W8),
        "rsi" => (Reg::Rsi, Width::W64),
        "esi" => (Reg::Rsi, Width::W32),
        "si" => (Reg::Rsi, Width::W16),
        "sil" => (Reg::Rsi, Width::W8),
        "rdi" => (Reg::Rdi, Width::W64),
        "edi" => (Reg::Rdi, Width::W32),
        "di" => (Reg::Rdi, Width::W16),
        "dil" => (Reg::Rdi, Width::W8),
        "rbp" => (Reg::Rbp, Width::W64),
        "ebp" => (Reg::Rbp, Width::W32),
        "rsp" => (Reg::Rsp, Width::W64),
        "esp" => (Reg::Rsp, Width::W32),
        "r8" => (Reg::R8, Width::W64),
        "r8d" => (Reg::R8, Width::W32),
        "r8w" => (Reg::R8, Width::W16),
        "r8b" => (Reg::R8, Width::W8),
        "r9" => (Reg::R9, Width::W64),
        "r9d" => (Reg::R9, Width::W32),
        "r9w" => (Reg::R9, Width::W16),
        "r9b" => (Reg::R9, Width::W8),
        "r10" => (Reg::R10, Width::W64),
        "r10d" => (Reg::R10, Width::W32),
        "r11" => (Reg::R11, Width::W64),
        "r11d" => (Reg::R11, Width::W32),
        "r12" => (Reg::R12, Width::W64),
        "r12d" => (Reg::R12, Width::W32),
        "r13" => (Reg::R13, Width::W64),
        "r13d" => (Reg::R13, Width::W32),
        "r14" => (Reg::R14, Width::W64),
        "r14d" => (Reg::R14, Width::W32),
        "r15" => (Reg::R15, Width::W64),
        "r15d" => (Reg::R15, Width::W32),
        _ => return None,
    };
    Some(RegRef { reg, width })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    MsX64,
    SysV,
    Aapcs64,
}

impl Abi {
    const fn arg_order(self) -> &'static [Reg] {
        match self {
            Self::MsX64 => &[Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9],
            Self::SysV => &[Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9],
            Self::Aapcs64 => &[
                Reg::Rax,
                Reg::A64X1,
                Reg::A64X2,
                Reg::A64X3,
                Reg::A64X4,
                Reg::A64X5,
                Reg::A64X6,
                Reg::A64X7,
                Reg::A64Stack0,
                Reg::A64Stack1,
                Reg::A64Stack2,
                Reg::A64Stack3,
                Reg::A64Stack4,
                Reg::A64Stack5,
                Reg::A64Stack6,
                Reg::A64Stack7,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Add,
    Sub,
    Imul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Sdiv,
    Udiv,
    Umull,
    Smull,
    Umulh,
    Smulh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnOp {
    Neg,
    Not,
    Bswap,
    Clz,
    Rbit,
    Rev16,
    Rev32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MemRmwOp {
    Bin { op: BinOp, src: Source },
    Un(UnOp),
}

impl MemRmwOp {
    const fn source(&self) -> Option<&Source> {
        match self {
            Self::Bin { src, .. } => Some(src),
            Self::Un(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondKind {
    E,
    Ne,
    G,
    Ge,
    L,
    Le,
    A,
    Ae,
    B,
    Be,
    S,
    Ns,
    Vs,
    Vc,
    P,
    Np,
}

impl CondKind {
    fn parse(suffix: &str) -> Option<Self> {
        match suffix {
            "e" | "z" => Some(Self::E),
            "ne" | "nz" => Some(Self::Ne),
            "g" | "nle" => Some(Self::G),
            "ge" | "nl" => Some(Self::Ge),
            "l" | "nge" => Some(Self::L),
            "le" | "ng" => Some(Self::Le),
            "a" | "nbe" => Some(Self::A),
            "ae" | "nb" | "nc" => Some(Self::Ae),
            "b" | "nae" | "c" => Some(Self::B),
            "be" | "na" => Some(Self::Be),
            "s" => Some(Self::S),
            "ns" => Some(Self::Ns),
            "p" | "pe" => Some(Self::P),
            "np" | "po" => Some(Self::Np),
            _ => None,
        }
    }

    const fn is_signed_order(self) -> bool {
        matches!(self, Self::G | Self::Ge | Self::L | Self::Le)
    }

    const fn is_unsigned_order(self) -> bool {
        matches!(self, Self::A | Self::Ae | Self::B | Self::Be)
    }

    const fn sign_zero_only(self) -> bool {
        matches!(self, Self::S | Self::Ns | Self::E | Self::Ne)
    }

    const fn is_overflow(self) -> bool {
        matches!(self, Self::Vs | Self::Vc)
    }

    const fn negate(self) -> Self {
        match self {
            Self::E => Self::Ne,
            Self::Ne => Self::E,
            Self::G => Self::Le,
            Self::Ge => Self::L,
            Self::L => Self::Ge,
            Self::Le => Self::G,
            Self::A => Self::Be,
            Self::Ae => Self::B,
            Self::B => Self::Ae,
            Self::Be => Self::A,
            Self::S => Self::Ns,
            Self::Ns => Self::S,
            Self::Vs => Self::Vc,
            Self::Vc => Self::Vs,
            Self::P => Self::Np,
            Self::Np => Self::P,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpUnorderedModel {
    UnorderedIsEqual,
    UnorderedIsUnequal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Flags {
    Cmp {
        lhs: RegRef,
        rhs: Source,
    },
    Add {
        lhs: RegRef,
        rhs: Source,
    },
    CmpMem {
        lhs: MemRef,
        rhs: Source,
    },
    Test {
        operand: RegRef,
    },
    TestImm {
        operand: RegRef,
        mask: i64,
    },
    Sign {
        result: RegRef,
    },
    FpCmp {
        lhs: Xmm,
        rhs: FpOperand,
        width: FpWidth,
        model: FpUnorderedModel,
    },
    Snapshot {
        var: u32,
    },
    CondCmp {
        prior: Box<Self>,
        precond: CondKind,
        taken: Box<Self>,
        nzcv: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cond {
    Leaf { kind: CondKind, flags: Flags },
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

impl Cond {
    fn leaf(kind: CondKind, flags: Flags) -> Self {
        Self::Leaf { kind, flags }
    }

    fn visit_leaves(&self, visit: &mut impl FnMut(CondKind, &Flags)) {
        match self {
            Self::Leaf { kind, flags } => visit(*kind, flags),
            Self::And(lhs, rhs) | Self::Or(lhs, rhs) => {
                lhs.visit_leaves(visit);
                rhs.visit_leaves(visit);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DividendHigh {
    SignExtended { width: Width },
    Zeroed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexExtend {
    Full,
    SignExtendWord,
    ZeroExtendWord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexOperand {
    reg: Reg,
    scale: u8,
    extend: IndexExtend,
}

impl IndexOperand {
    const fn full(reg: Reg, scale: u8) -> Self {
        Self {
            reg,
            scale,
            extend: IndexExtend::Full,
        }
    }
}

type AddrTerms = (Option<Reg>, Option<IndexOperand>, i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemRef {
    base: Option<Reg>,
    index: Option<IndexOperand>,
    disp: i64,
    width: Width,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Reg(RegRef),
    Imm(i64),
    Lea {
        base: Option<Reg>,
        index: Option<IndexOperand>,
        disp: i64,
    },
    Mem(MemRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum VecElem {
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl VecElem {
    const fn bits(self) -> u32 {
        match self {
            Self::I8 => 8,
            Self::I16 => 16,
            Self::I32 | Self::F32 => 32,
            Self::I64 | Self::F64 => 64,
        }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    const fn c_scalar(self) -> &'static str {
        match self {
            Self::I8 => "int8_t",
            Self::I16 => "int16_t",
            Self::I32 => "int32_t",
            Self::I64 => "int64_t",
            Self::F32 => "float",
            Self::F64 => "double",
        }
    }

    const fn c_unsigned_scalar(self) -> &'static str {
        match self {
            Self::I8 => "uint8_t",
            Self::I16 => "uint16_t",
            Self::I32 | Self::F32 => "uint32_t",
            Self::I64 | Self::F64 => "uint64_t",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct VecArrangement {
    lanes: u8,
    elem: VecElem,
}

impl VecArrangement {
    const fn total_bits(self) -> u32 {
        self.lanes as u32 * self.elem.bits()
    }

    const fn whole_register(elem: VecElem) -> Self {
        Self {
            lanes: (128 / elem.bits()) as u8,
            elem,
        }
    }

    fn type_name(self) -> String {
        format!("recovered_{}x{}", self.elem.tag(), self.lanes)
    }

    fn mem_type_name(self) -> String {
        format!("recovered_{}x{}_mem", self.elem.tag(), self.lanes)
    }
}

const UNALIGNED_U64_TYPE: &str = "recovered_u64_mem";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MinMax {
    is_max: bool,
    signed: bool,
}

impl MinMax {
    const fn cmp(self) -> &'static str {
        if self.is_max { ">" } else { "<" }
    }
}

fn minmax_lane_ty(elem: VecElem, signed: bool) -> &'static str {
    if signed {
        elem.c_scalar()
    } else {
        elem.c_unsigned_scalar()
    }
}

fn minmax_lane_operand(elem: VecElem, signed: bool, base: &str) -> String {
    if signed {
        base.to_owned()
    } else {
        format!("({}){base}", elem.c_unsigned_scalar())
    }
}

fn minmax_select_expr(cmp: &str, a: &str, b: &str) -> String {
    format!("{a} {cmp} {b} ? {a} : {b}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VecBinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    AndNot,
    Smax,
    Smin,
    Umax,
    Umin,
}

impl VecBinOp {
    const fn is_bitwise(self) -> bool {
        matches!(self, Self::And | Self::Or | Self::Xor | Self::AndNot)
    }

    const fn minmax(self) -> Option<MinMax> {
        match self {
            Self::Smax => Some(MinMax {
                is_max: true,
                signed: true,
            }),
            Self::Smin => Some(MinMax {
                is_max: false,
                signed: true,
            }),
            Self::Umax => Some(MinMax {
                is_max: true,
                signed: false,
            }),
            Self::Umin => Some(MinMax {
                is_max: false,
                signed: false,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReduceOp {
    Add,
    Saddl,
    Uaddl,
    Smax,
    Smin,
    Umax,
    Umin,
}

impl ReduceOp {
    const fn minmax(self) -> Option<MinMax> {
        match self {
            Self::Smax => Some(MinMax {
                is_max: true,
                signed: true,
            }),
            Self::Smin => Some(MinMax {
                is_max: false,
                signed: true,
            }),
            Self::Umax => Some(MinMax {
                is_max: true,
                signed: false,
            }),
            Self::Umin => Some(MinMax {
                is_max: false,
                signed: false,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VecStmt {
    Load {
        dest: u8,
        arr: Option<VecArrangement>,
        addr: MemRef,
    },
    Store {
        src: u8,
        arr: Option<VecArrangement>,
        addr: MemRef,
    },
    Bin {
        dest: u8,
        lhs: u8,
        rhs: u8,
        op: VecBinOp,
        arr: VecArrangement,
    },
    Dup {
        dest: u8,
        src: RegRef,
        arr: VecArrangement,
    },
    LaneInsert {
        dest: u8,
        lane: u8,
        src: RegRef,
        arr: VecArrangement,
    },
    Compare {
        dest: u8,
        lhs: u8,
        rhs: Option<u8>,
        arr: VecArrangement,
    },
    MoveImm {
        dest: u8,
        imm: i64,
        arr: VecArrangement,
    },
    Reduce {
        reg: u8,
        op: ReduceOp,
        src: VecArrangement,
        dest: VecElem,
    },
    ExtractToGpr {
        dest: RegRef,
        src: u8,
        elem: VecElem,
    },
    WidenExtend {
        dest: u8,
        src: u8,
        src_elem: VecElem,
        dest_elem: VecElem,
        signed: bool,
        high: bool,
        shift: u8,
    },
    WidenAdd {
        dest: u8,
        src1: u8,
        src2: u8,
        src_elem: VecElem,
        dest_elem: VecElem,
        signed: bool,
        high: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stmt {
    Assign {
        dest: RegRef,
        src: Source,
    },
    BinAssign {
        dest: RegRef,
        op: BinOp,
        src: Source,
    },
    UnAssign {
        dest: RegRef,
        op: UnOp,
    },
    Cond {
        dest: RegRef,
        src: Source,
        kind: CondKind,
        flags: Flags,
    },
    SetCc {
        dest: RegRef,
        kind: CondKind,
        flags: Flags,
    },
    Store {
        addr: MemRef,
        src: Source,
    },
    MemRmw {
        addr: MemRef,
        op: MemRmwOp,
    },
    Extend {
        dest: RegRef,
        src: ExtSource,
        signed: bool,
    },
    MulImm {
        dest: RegRef,
        src: ExtSource,
        imm: i64,
    },
    WideMul {
        src: RegRef,
    },
    Divide {
        divisor: RegRef,
        signed: bool,
    },
    FpBin {
        dest: Xmm,
        lhs: FpOperand,
        rhs: FpOperand,
        op: FpOp,
        width: FpWidth,
    },
    FpMov {
        dest: Xmm,
        src: FpOperand,
        width: FpWidth,
    },
    FpStore {
        addr: MemRef,
        src: Xmm,
        width: FpWidth,
    },
    IntToFp {
        dest: Xmm,
        src: RegRef,
        signed: bool,
        width: FpWidth,
        fbits: Option<NonZeroU8>,
    },
    FpToInt {
        dest: RegRef,
        src: Xmm,
        width: FpWidth,
        signed: bool,
        round: FpToIntRound,
        fbits: Option<NonZeroU8>,
        saturating: bool,
    },
    FpConvert {
        dest: Xmm,
        src: Xmm,
        from: FpWidth,
        to: FpWidth,
    },
    FpMinMax {
        dest: Xmm,
        lhs: FpOperand,
        rhs: FpOperand,
        kind: FpMinMaxKind,
        width: FpWidth,
    },
    FpFma {
        dest: Xmm,
        mul_lhs: FpOperand,
        mul_rhs: FpOperand,
        addend: FpOperand,
        kind: FpFmaKind,
        width: FpWidth,
    },
    FpCsel {
        dest: Xmm,
        if_true: FpOperand,
        if_false: FpOperand,
        kind: CondKind,
        flags: Flags,
        width: FpWidth,
    },
    FpSqrt {
        dest: Xmm,
        src: FpOperand,
        width: FpWidth,
        saturating: bool,
    },
    FpUnary {
        dest: Xmm,
        src: FpOperand,
        op: FpUnaryOp,
        width: FpWidth,
    },
    FpRound {
        dest: Xmm,
        src: FpOperand,
        width: FpWidth,
        mode: RoundMode,
    },
    GprToXmm {
        dest: Xmm,
        src: RegRef,
        width: FpWidth,
    },
    XmmToGpr {
        dest: RegRef,
        src: Xmm,
        width: FpWidth,
    },
    DoubleShift {
        dest: RegRef,
        src: RegRef,
        amount: u8,
        left: bool,
    },
    BlockMove {
        elem: Width,
    },
    BlockFill {
        elem: Width,
    },
    Call {
        target: u64,
        args: Vec<Reg>,
        name: Option<String>,
    },
    FlagSnapshot {
        var: u32,
        kind: CondKind,
        flags: Flags,
    },
    Packed {
        dest: Xmm,
        op: PackedOp,
    },
    PackedToGpr {
        dest: RegRef,
        src: Xmm,
    },
    Vector(VecStmt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtSource {
    Reg(RegRef),
    Mem(MemRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Stmt(Stmt),
    If {
        cond: Cond,
        then_body: Block,
        else_body: Option<Block>,
    },
    DoWhile {
        body: Block,
        cond: LoopCond,
    },
    While {
        body: Block,
        cond: Option<LoopCond>,
    },
    CondSnapshot {
        var: u32,
        cond: CondKind,
        flags: Flags,
    },
    Switch {
        disc: RegRef,
        cases: Vec<SwitchCase>,
        default: Block,
    },
    Break,
    Continue,
    Return,
    Label(u32),
    Goto(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwitchCase {
    values: Vec<i64>,
    body: Block,
    fallthrough: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoopCond {
    Direct { cond: CondKind, flags: Flags },
    Snapshot { var: u32 },
}

type Block = Vec<Node>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarType {
    Int,
    Double,
    Float,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SretReturn {
    pub field_widths: Vec<u32>,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSiteReturnProof {
    FloatingPoint32,
    FloatingPoint64,
    Integer64,
    UnanimousInteger32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteSignatureProof {
    pub return_proof: CallSiteReturnProof,
    pub attributed_sites: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRecovery {
    pub source: String,
    pub rust_source: Option<String>,
    pub return_width_bits: u32,
    pub param_width_bits: Vec<u32>,
    pub params: Vec<Reg>,
    pub fp_params: Vec<ScalarType>,
    pub returns_fp: Option<ScalarType>,
    pub lifted_split_return: bool,
    pub lifted_loop: bool,
    pub lifted_switch: bool,
    pub call_targets: Vec<u64>,
    pub sret: Option<SretReturn>,
    pub call_site_signature: Option<CallSiteSignatureProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    pub table_va: u64,
    pub entries: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCall {
    pub target: u64,
    pub name: Option<String>,
    pub arg_count: usize,
}

pub fn recover_leaf_function(machine_code: &[u8], base: u64) -> Result<LeafRecovery> {
    recover_leaf_function_abi(machine_code, base, Abi::MsX64)
}

pub fn recover_aarch64_function(machine_code: &[u8], base: u64) -> Result<LeafRecovery> {
    recover_aarch64_function_with_image(
        machine_code,
        base,
        &no_aarch64_image,
        &no_aarch64_relocation,
    )
}

pub fn recover_aarch64_function_with_image<'image>(
    machine_code: &[u8],
    base: u64,
    image: &dyn Fn(u64) -> Option<&'image [u8]>,
    relocations: &dyn Fn(u64) -> Option<u64>,
) -> Result<LeafRecovery> {
    aarch64::recover_with_image(machine_code, base, image, relocations)
}

pub fn recover_aarch64_function_with_calls(
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    aarch64::recover_with_calls(machine_code, base, calls)
}

pub fn recover_aarch64_program(object: &[u8]) -> RecoveredProgram {
    aarch64_callsite::recover(object)
}

fn no_aarch64_image(_: u64) -> Option<&'static [u8]> {
    None
}

fn no_aarch64_relocation(_: u64) -> Option<u64> {
    None
}

pub fn recover_leaf_function_abi(machine_code: &[u8], base: u64, abi: Abi) -> Result<LeafRecovery> {
    recover_leaf_function_const_abi(machine_code, base, abi, &[])
}

pub fn recover_leaf_function_const_abi(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    consts: &[FpConstant],
) -> Result<LeafRecovery> {
    recover_leaf_function_calls_impl(machine_code, base, abi, consts, &[], &[])
}

pub fn recover_leaf_function_with_calls(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    recover_leaf_function_calls_impl(machine_code, base, abi, &[], &[], calls)
}

pub fn recover_vectorized_reduction(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
) -> Result<LeafRecovery> {
    require_x86_abi(abi)?;
    crate::simd_devirt::recover_vectorized_loop(machine_code, base, abi)
}

pub fn recover_leaf_function_in_object(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    require_x86_abi(abi)?;
    if let Ok(recovery) = crate::simd_devirt::recover_vectorized_loop(machine_code, base, abi) {
        return Ok(recovery);
    }
    let packed_consts: Vec<PackedConstant> = resolve_packed_constants(object, machine_code, base);
    let straight_err: Error =
        match recover_leaf_function_calls_impl(machine_code, base, abi, &[], &packed_consts, calls)
        {
            Ok(recovery) => return Ok(recovery),
            Err(err) => err,
        };
    match recover_switch_in_object(object, machine_code, base, abi, calls) {
        Ok(recovery) => return Ok(recovery),
        Err(switch_err) => {
            if !matches!(&switch_err, Error::LlvmIr(message) if message.contains("dispatch prologue"))
            {
                return Err(switch_err);
            }
        }
    }
    match recover_value_switch_in_object(object, machine_code, base, abi) {
        Ok(recovery) => return Ok(recovery),
        Err(value_err) => {
            if !matches!(&value_err, Error::LlvmIr(message) if message.contains("dispatch prologue"))
            {
                return Err(value_err);
            }
        }
    }
    match recover_o0_switch_in_object(object, machine_code, base, abi, calls) {
        Ok(recovery) => return Ok(recovery),
        Err(o0_err) => {
            if !matches!(&o0_err, Error::LlvmIr(message) if message.contains("dispatch prologue")) {
                return Err(o0_err);
            }
        }
    }
    match recover_clang_o0_switch_in_object(object, machine_code, base, abi, calls) {
        Ok(recovery) => Ok(recovery),
        Err(clang_err) => {
            if matches!(&clang_err, Error::LlvmIr(message) if message.contains("dispatch prologue"))
            {
                Err(straight_err)
            } else {
                Err(clang_err)
            }
        }
    }
}

pub fn callee_int_arity(callee_code: &[u8], callee_base: u64, abi: Abi) -> Option<usize> {
    recover_leaf_function_abi(callee_code, callee_base, abi)
        .ok()
        .map(|recovery: LeafRecovery| recovery.params.len())
}

const CALL_RESOLUTION_DEPTH: usize = 16;

pub fn resolved_int_arity_in_object(
    object: &[u8],
    callee_code: &[u8],
    callee_base: u64,
    abi: Abi,
) -> Option<usize> {
    resolved_int_arity(object, callee_code, callee_base, abi, CALL_RESOLUTION_DEPTH)
}

fn resolved_int_arity(
    object: &[u8],
    callee_code: &[u8],
    callee_base: u64,
    abi: Abi,
    depth: usize,
) -> Option<usize> {
    let probe: LeafRecovery =
        recover_leaf_function_in_object(object, callee_code, callee_base, abi, &[]).ok()?;
    if probe.call_targets.is_empty() || depth == 0 {
        return Some(probe.params.len());
    }
    let mut resolved: Vec<ResolvedCall> = Vec::with_capacity(probe.call_targets.len());
    let mut seen: Vec<u64> = Vec::new();
    for target in probe.call_targets {
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let Some((nested_code, nested_base)): Option<(Vec<u8>, u64)> =
            callee_code_by_target(object, target)
        else {
            continue;
        };
        let Some(arg_count): Option<usize> =
            resolved_int_arity(object, &nested_code, nested_base, abi, depth - 1)
        else {
            continue;
        };
        resolved.push(ResolvedCall {
            target,
            name: None,
            arg_count,
        });
    }
    recover_leaf_function_in_object(object, callee_code, callee_base, abi, &resolved)
        .ok()
        .map(|recovery: LeafRecovery| recovery.params.len())
}

fn callee_code_by_target(object: &[u8], target: u64) -> Option<(Vec<u8>, u64)> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    let file: object::File<'_> = object::File::parse(object).ok()?;
    if let Some(sym) = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.address() == target
            && s.kind() == object::SymbolKind::Text
            && s.name().is_ok_and(|n: &str| !n.is_empty())
    }) {
        return symbol_code(&file, &sym);
    }
    for section in file.sections() {
        let base: u64 = section.address();
        for (offset, reloc) in section.relocations() {
            if base.checked_add(offset)?.checked_add(4)? != target {
                continue;
            }
            let object::RelocationTarget::Symbol(idx) = reloc.target() else {
                continue;
            };
            let sym: object::Symbol<'_, '_> = file.symbol_by_index(idx).ok()?;
            return symbol_code(&file, &sym);
        }
    }
    None
}

fn symbol_code(file: &object::File<'_>, sym: &object::Symbol<'_, '_>) -> Option<(Vec<u8>, u64)> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

    let object::SymbolSection::Section(section_index) = sym.section() else {
        return None;
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        file.symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
                    && s.name().is_ok_and(|n: &str| !n.is_empty())
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len())
            .min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    Some((data.get(start..end)?.to_vec(), sym_addr))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFunction {
    pub name: String,
    pub address: u64,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFunction {
    pub name: String,
    pub address: u64,
    pub source: String,
    pub rust_source: Option<String>,
    pub return_width_bits: u32,
    pub param_width_bits: Vec<u32>,
    pub params: Vec<Reg>,
    pub fp_params: Vec<ScalarType>,
    pub returns_fp: Option<ScalarType>,
    pub resolved_calls: Vec<u64>,
    pub call_site_signature: Option<CallSiteSignatureProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecoveredFunction {
    pub name: String,
    pub address: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveredProgram {
    pub recovered: Vec<RecoveredFunction>,
    pub unrecovered: Vec<UnrecoveredFunction>,
}

pub fn recover_program(object: &[u8], functions: &[ProgramFunction], abi: Abi) -> RecoveredProgram {
    let by_addr: BTreeMap<u64, &ProgramFunction> = functions
        .iter()
        .map(|f: &ProgramFunction| (f.address, f))
        .collect();
    let mut recovered: Vec<RecoveredFunction> = Vec::with_capacity(functions.len());
    let mut unrecovered: Vec<UnrecoveredFunction> = Vec::new();
    for f in functions {
        match recover_program_function(object, f, &by_addr, abi) {
            Ok(rec) => recovered.push(rec),
            Err(reason) => unrecovered.push(UnrecoveredFunction {
                name: f.name.clone(),
                address: f.address,
                reason,
            }),
        }
    }
    RecoveredProgram {
        recovered,
        unrecovered,
    }
}

fn recover_program_function(
    object: &[u8],
    f: &ProgramFunction,
    by_addr: &BTreeMap<u64, &ProgramFunction>,
    abi: Abi,
) -> core::result::Result<RecoveredFunction, String> {
    let probe: LeafRecovery = recover_leaf_function_in_object(object, &f.code, f.address, abi, &[])
        .map_err(|e: Error| e.to_string())?;
    let mut resolved: Vec<ResolvedCall> = Vec::with_capacity(probe.call_targets.len());
    let mut seen: Vec<u64> = Vec::with_capacity(probe.call_targets.len());
    for target in probe.call_targets {
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let sibling_addr: u64 = if by_addr.contains_key(&target) {
            target
        } else if let Some(relocated) = resolve_relocated_call_target(object, f, target) {
            relocated
        } else {
            target
        };
        let Some(callee): Option<&&ProgramFunction> = by_addr.get(&sibling_addr) else {
            continue;
        };
        let Some(arg_count): Option<usize> =
            resolved_int_arity_in_object(object, &callee.code, callee.address, abi)
        else {
            continue;
        };
        resolved.push(ResolvedCall {
            target,
            name: Some(callee.name.clone()),
            arg_count,
        });
    }
    let rec: LeafRecovery =
        recover_leaf_function_in_object(object, &f.code, f.address, abi, &resolved)
            .map_err(|e: Error| e.to_string())?;
    let resolved_names: Vec<String> = resolved
        .iter()
        .filter_map(|c: &ResolvedCall| c.name.clone())
        .collect();
    let source: String = rename_recovered_c_symbol(&rec.source, &f.name);
    let rust_source: Option<String> = rec
        .rust_source
        .as_deref()
        .map(|body: &str| rename_recovered_rust_symbol(body, &f.name, &resolved_names));
    Ok(RecoveredFunction {
        name: f.name.clone(),
        address: f.address,
        source,
        rust_source,
        return_width_bits: rec.return_width_bits,
        param_width_bits: rec.param_width_bits,
        params: rec.params,
        fp_params: rec.fp_params,
        returns_fp: rec.returns_fp,
        resolved_calls: resolved.iter().map(|c: &ResolvedCall| c.target).collect(),
        call_site_signature: rec.call_site_signature,
    })
}

fn resolve_relocated_call_target(
    object: &[u8],
    caller: &ProgramFunction,
    target: u64,
) -> Option<u64> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let file: object::File<'_> = object::File::parse(object).ok()?;
    let caller_start: u64 = caller.address;
    let caller_len: u64 = u64::try_from(caller.code.len()).ok()?;
    let caller_end: u64 = caller_start.saturating_add(caller_len);
    for section in file.sections() {
        let section_addr: u64 = section.address();
        let Ok(section_data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        for (offset, reloc) in section.relocations() {
            let reloc_addr: u64 = section_addr.saturating_add(offset);
            if reloc_addr < caller_start || reloc_addr >= caller_end {
                continue;
            }
            if reloc_addr.saturating_add(4) != target {
                continue;
            }
            let RelocationTarget::Symbol(sym_index) = reloc.target() else {
                continue;
            };
            let sym: object::Symbol<'_, '_> = file.symbol_by_index(sym_index).ok()?;
            let effective: i64 = reloc_effective_addend(&reloc, section_data, offset, 4).ok()?;
            let sym_addr: i64 = i64::try_from(sym.address()).ok()?;
            let resolved: i64 = sym_addr.checked_add(effective)?.checked_add(4)?;
            return u64::try_from(resolved).ok();
        }
    }
    None
}

fn rename_recovered_c_symbol(source: &str, name: &str) -> String {
    source.replacen("recovered(", &format!("{name}("), 1)
}

fn rename_recovered_rust_symbol(source: &str, name: &str, resolved_names: &[String]) -> String {
    let filtered: String = drop_resolved_sibling_externs(source, resolved_names);
    filtered.replacen("pub fn recovered(", &format!("pub fn {name}("), 1)
}

fn drop_resolved_sibling_externs(source: &str, resolved_names: &[String]) -> String {
    let trailing_newline: bool = source.ends_with('\n');
    let mut out: Vec<String> = Vec::new();
    let mut in_extern_block: bool = false;
    let mut kept_decls: Vec<String> = Vec::new();
    for line in source.lines() {
        if !in_extern_block && line.trim_end() == "extern \"C\" {" {
            in_extern_block = true;
            kept_decls.clear();
            continue;
        }
        if in_extern_block {
            if line.trim() == "}" {
                in_extern_block = false;
                if !kept_decls.is_empty() {
                    out.push("extern \"C\" {".to_owned());
                    out.append(&mut kept_decls);
                    out.push("}".to_owned());
                }
                continue;
            }
            let callee_name: Option<&str> = line
                .trim()
                .strip_prefix("fn ")
                .and_then(|rest: &str| rest.split('(').next());
            let is_resolved_sibling: bool =
                callee_name.is_some_and(|n: &str| resolved_names.iter().any(|r: &String| r == n));
            if !is_resolved_sibling {
                kept_decls.push(line.to_owned());
            }
            continue;
        }
        out.push(line.to_owned());
    }
    let mut joined: String = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    joined
}

struct LeafItems {
    insns: Vec<DisasmInsn>,
    items: Vec<Item>,
    return_width: Width,
}

fn build_leaf_items(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    consts: &[FpConstant],
    packed_consts: &[PackedConstant],
) -> Result<LeafItems> {
    require_x86_abi(abi)?;
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let packed_mode: bool = uses_packed_integer_sse(&insns);
    let mut items: Vec<Item> = Vec::new();
    let mut return_width: Width = Width::W64;
    let mut flags: Option<Flags> = None;
    let mut flags_mark: usize = 0;
    let mut next_sel: u32 = 0;
    let mut dividend_high: Option<DividendHigh> = None;
    let mut saw_ret: bool = false;
    let mut max_branch_target: u64 = 0;
    let mut df_backward: bool = false;
    for insn in &insns {
        if insn.mnemonic == "nop"
            || insn.mnemonic == "endbr64"
            || is_xchg_self(&insn.mnemonic, &insn.operands)
        {
            continue;
        }
        if insn.mnemonic == "cld" {
            df_backward = false;
            continue;
        }
        if insn.mnemonic == "std" {
            df_backward = true;
            continue;
        }
        if insn.mnemonic == "rep" {
            let stmt: Stmt = lift_rep_string(&insn.operands, df_backward).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "unsupported string idiom `{} {}` at {:#x}",
                    insn.mnemonic, insn.operands, insn.address
                ))
            })?;
            flags = None;
            dividend_high = None;
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(stmt),
            });
            continue;
        }
        if matches!(insn.mnemonic.as_str(), "repe" | "repz" | "repne" | "repnz") {
            return Err(Error::LlvmIr(format!(
                "string compare/scan `{} {}` at {:#x} is not a block copy or fill",
                insn.mnemonic, insn.operands, insn.address
            )));
        }
        if is_bare_string_op(&insn.mnemonic) {
            return Err(Error::LlvmIr(format!(
                "unbounded single string op `{}` at {:#x} has no rep count and is not the RDI/RSI/RCX block idiom",
                insn.mnemonic, insn.address
            )));
        }
        if is_frame_management(&insn.mnemonic, &insn.operands)
            || is_ms_x64_callee_saved_xmm_spill(&insn.mnemonic, &insn.operands, abi)
        {
            continue;
        }
        if packed_mode
            && let Some(stmt) =
                lift_packed(&insn.mnemonic, &insn.operands, insn.address, packed_consts)?
        {
            if let Stmt::PackedToGpr { dest, .. } = &stmt
                && dest.reg == Reg::Rax
            {
                return_width = Width::W64;
            }
            flags = None;
            dividend_high = None;
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(stmt),
            });
            continue;
        }
        if let Some(fp_flags) =
            lift_fp_compare(&insn.mnemonic, &insn.operands, insn.address, consts)?
        {
            flags = Some(fp_flags);
            flags_mark = items.len();
            continue;
        }
        if let Some(fp_stmt) = lift_fp(&insn.mnemonic, &insn.operands, insn.address, consts)? {
            if let Stmt::FpToInt { dest, .. } | Stmt::XmmToGpr { dest, .. } = &fp_stmt
                && dest.reg == Reg::Rax
            {
                return_width = dest.width;
            }
            flags = None;
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(fp_stmt),
            });
            continue;
        }
        if let Some(high) = lift_dividend_extend(&insn.mnemonic, &insn.operands) {
            dividend_high = Some(high);
            continue;
        }
        if let Some(divisor) = parse_divide_operand(&insn.mnemonic, &insn.operands) {
            let signed: bool = insn.mnemonic == "idiv";
            let high: DividendHigh = dividend_high.take().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "division at {:#x} without a tracked high-half dividend setup",
                    insn.address
                ))
            })?;
            if !dividend_high_matches(high, signed, divisor.width) {
                return Err(Error::LlvmIr(format!(
                    "division at {:#x} has a high-half dividend inconsistent with a width-fitting `{}`",
                    insn.address, insn.mnemonic
                )));
            }
            flags = None;
            return_width = divisor.width;
            let divide: Stmt = Stmt::Divide { divisor, signed };
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(divide),
            });
            continue;
        }
        if insn.mnemonic == "call"
            && let Some(target) = parse_branch_target(&insn.operands)
        {
            return_width = Width::W64;
            flags = None;
            let call: Stmt = Stmt::Call {
                target,
                args: abi.arg_order().to_vec(),
                name: None,
            };
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(call),
            });
            continue;
        }
        if insn.mnemonic == "ret" {
            saw_ret = true;
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Ret,
            });
            if max_branch_target > insn.address {
                continue;
            }
            break;
        }
        if let Some(target) = parse_branch_target(&insn.operands)
            && let Some(cond_suffix) = insn.mnemonic.strip_prefix('j')
        {
            max_branch_target = max_branch_target.max(target);
            if cond_suffix == "mp" {
                items.push(Item {
                    address: insn.address,
                    kind: ItemKind::Jmp { target },
                });
                continue;
            }
            let kind: CondKind = CondKind::parse(cond_suffix).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "unsupported branch `{} {}` at {:#x}",
                    insn.mnemonic, insn.operands, insn.address
                ))
            })?;
            let live_flags: Flags = flags.clone().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "branch without preceding flags at {:#x}",
                    insn.address
                ))
            })?;
            let (branch_kind, used_flags): (CondKind, Flags) = resolve_conditional_flags(
                &mut items,
                flags_mark,
                kind,
                live_flags,
                &mut next_sel,
                insn.address,
            )?;
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Branch {
                    kind: branch_kind,
                    flags: used_flags,
                    target,
                },
            });
            continue;
        }
        if let Some(new_flags) = lift_flag_setter(&insn.mnemonic, &insn.operands) {
            flags = Some(new_flags);
            flags_mark = items.len();
            continue;
        }
        if let Some(suffix) = insn.mnemonic.strip_prefix("cmov") {
            let kind: CondKind = CondKind::parse(suffix).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "unsupported conditional move `{} {}` at {:#x}",
                    insn.mnemonic, insn.operands, insn.address
                ))
            })?;
            let live_flags: Flags = flags.clone().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "cmov without preceding flags at {:#x}",
                    insn.address
                ))
            })?;
            let (cond_kind, used_flags): (CondKind, Flags) = resolve_conditional_flags(
                &mut items,
                flags_mark,
                kind,
                live_flags,
                &mut next_sel,
                insn.address,
            )?;
            let (lhs, rhs): (&str, &str) = insn
                .operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed cmov at {:#x}", insn.address)))?;
            let dest: RegRef = parse_reg(lhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("cmov dest not a register at {:#x}", insn.address))
            })?;
            let src: Source = parse_source(rhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("cmov src unsupported at {:#x}", insn.address))
            })?;
            if (kind.is_signed_order() || kind.is_unsigned_order())
                && near_miss_ordering_select(&items, &used_flags, &src, dest)
            {
                return Err(Error::LlvmIr(format!(
                    "ordering cmov selecting a compared operand against their difference is not soundly recoverable at {:#x}",
                    insn.address
                )));
            }
            if dest.reg == Reg::Rax {
                return_width = dest.width;
            }
            let stmt: Stmt = Stmt::Cond {
                dest,
                src,
                kind: cond_kind,
                flags: used_flags,
            };
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(stmt),
            });
            continue;
        }
        if let Some(suffix) = insn.mnemonic.strip_prefix("set")
            && let Some(kind) = CondKind::parse(suffix)
        {
            let dest: RegRef = parse_reg(insn.operands.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("setcc dest not a register at {:#x}", insn.address))
            })?;
            if dest.width != Width::W8 {
                return Err(Error::LlvmIr(format!(
                    "setcc at {:#x} does not target a byte register",
                    insn.address
                )));
            }
            let live_flags: Flags = flags.clone().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "setcc without preceding flags at {:#x}",
                    insn.address
                ))
            })?;
            let (cond_kind, used_flags): (CondKind, Flags) = resolve_conditional_flags(
                &mut items,
                flags_mark,
                kind,
                live_flags,
                &mut next_sel,
                insn.address,
            )?;
            if dest.reg == Reg::Rax {
                return_width = dest.width;
            }
            let setcc: Stmt = Stmt::SetCc {
                dest,
                kind: cond_kind,
                flags: used_flags,
            };
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(setcc),
            });
            continue;
        }
        if let Some(stmt) = lift_width_extension(&insn.mnemonic, &insn.operands) {
            if sign_extended_high_read_is_unsound(dividend_high, &stmt) {
                return Err(Error::LlvmIr(format!(
                    "sign-extended high half in rdx from a cqo/cdq is read at {:#x} without a modeled division; not soundly recoverable",
                    insn.address
                )));
            }
            if let Stmt::Extend { dest, .. } = &stmt
                && dest.reg == Reg::Rax
            {
                return_width = dest.width;
            }
            items.push(Item {
                address: insn.address,
                kind: ItemKind::Stmt(stmt),
            });
            continue;
        }
        let stmt: Stmt = lift_one(&insn.mnemonic, &insn.operands).ok_or_else(|| {
            Error::LlvmIr(format!(
                "unsupported leaf instruction `{} {}` at {:#x}",
                insn.mnemonic, insn.operands, insn.address
            ))
        })?;
        if sign_extended_high_read_is_unsound(dividend_high, &stmt) {
            return Err(Error::LlvmIr(format!(
                "sign-extended high half in rdx from a cqo/cdq is read at {:#x} without a modeled division; not soundly recoverable",
                insn.address
            )));
        }
        if let Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. } = &stmt
            && dest.reg == Reg::Rax
        {
            return_width = dest.width;
        }
        if matches!(&stmt, Stmt::WideMul { .. }) {
            return_width = Width::W64;
        }
        dividend_high = track_dividend_high(dividend_high, &stmt);
        match &stmt {
            Stmt::Assign { .. } => {
                if x86_mnemonic_writes_flags(&insn.mnemonic) {
                    flags = None;
                }
            }
            Stmt::BinAssign { dest, op, .. } => {
                flags = match flag_effect_bin(*op) {
                    FlagEffect::Sign => Some(Flags::Sign { result: *dest }),
                    FlagEffect::Clobber => None,
                };
            }
            Stmt::UnAssign { dest, op } => {
                flags = match op {
                    UnOp::Neg => Some(Flags::Sign { result: *dest }),
                    UnOp::Not
                    | UnOp::Bswap
                    | UnOp::Clz
                    | UnOp::Rbit
                    | UnOp::Rev16
                    | UnOp::Rev32 => flags,
                };
            }
            Stmt::Cond { .. } => {}
            Stmt::SetCc { .. } => {}
            Stmt::Store { .. } => {}
            Stmt::MemRmw { .. } => {
                flags = None;
            }
            Stmt::Extend { .. } => {}
            Stmt::MulImm { .. } | Stmt::WideMul { .. } | Stmt::DoubleShift { .. } => {
                flags = None;
            }
            Stmt::Divide { .. } => {
                flags = None;
            }
            Stmt::BlockMove { .. } | Stmt::BlockFill { .. } => {
                flags = None;
            }
            Stmt::FpBin { .. }
            | Stmt::FpMov { .. }
            | Stmt::FpStore { .. }
            | Stmt::IntToFp { .. }
            | Stmt::FpToInt { .. }
            | Stmt::FpConvert { .. }
            | Stmt::FpMinMax { .. }
            | Stmt::FpFma { .. }
            | Stmt::FpCsel { .. }
            | Stmt::FpSqrt { .. }
            | Stmt::FpUnary { .. }
            | Stmt::FpRound { .. }
            | Stmt::GprToXmm { .. }
            | Stmt::XmmToGpr { .. } => {
                flags = None;
            }
            Stmt::Packed { .. } | Stmt::PackedToGpr { .. } => {}
            Stmt::Vector(_) => {
                flags = None;
            }
            Stmt::Call { .. } | Stmt::FlagSnapshot { .. } => {}
        }
        items.push(Item {
            address: insn.address,
            kind: ItemKind::Stmt(stmt),
        });
    }
    if !saw_ret {
        return Err(Error::LlvmIr(
            "no ret found; not a single-exit leaf".to_owned(),
        ));
    }
    fuse_parity_equality_idioms(&mut items, &insns);
    Ok(LeafItems {
        insns,
        items,
        return_width,
    })
}

fn typed_frame_slots(
    machine_code: &[u8],
    base: u64,
    frame: Option<&FramePlan>,
) -> (Option<Reg>, BTreeMap<i64, SlotCType>) {
    let Some(frame): Option<&FramePlan> = frame else {
        return (None, BTreeMap::new());
    };
    if frame.base != Reg::Rbp {
        return (None, BTreeMap::new());
    }
    let typed: disrobe_typerec::TypedFunction =
        disrobe_typerec::recover_function(machine_code, base);
    let mut slots: BTreeMap<i64, SlotCType> = BTreeMap::new();
    for (disp, cint) in typed.typed_slots() {
        if let Some(slot) = SlotCType::from_typerec(cint) {
            slots.insert(disp, slot);
        }
    }
    if slots.is_empty() {
        (None, slots)
    } else {
        (Some(Reg::Rbp), slots)
    }
}

fn recover_leaf_function_calls_impl(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    consts: &[FpConstant],
    packed_consts: &[PackedConstant],
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    let LeafItems {
        insns,
        items,
        mut return_width,
    } = build_leaf_items(machine_code, base, abi, consts, packed_consts)?;
    let mut structured: Structured = structure_items(&items)?;
    if !calls.is_empty() {
        let call_map: BTreeMap<u64, &ResolvedCall> =
            calls.iter().map(|c: &ResolvedCall| (c.target, c)).collect();
        annotate_calls_block(&mut structured.body, &call_map, abi);
    }
    let fp_return: Option<FpWidth> = scalar_fp_return_channel(&structured.body)?;
    let mut call_targets: Vec<u64> = Vec::new();
    collect_call_targets(&structured.body, &mut call_targets);
    if fp_return.is_none() {
        return_width = folded_int_return_width(&structured.body, Width::W64);
    }
    let sret_plan: Option<SretPlan> = fp_return
        .is_none()
        .then(|| detect_sret(&structured.body, abi))
        .flatten();
    let mut params: Vec<Reg> = infer_params(&structured.body, abi);
    let fp_args: Vec<(Xmm, FpWidth)> = infer_fp_params(&structured.body, abi)?;
    validate_ms_x64_shared_argument_index(abi, &params, &fp_args)?;
    if let Some(plan) = &sret_plan {
        params.retain(|r: &Reg| *r != plan.ptr);
    }
    let returns_fp: Option<ScalarType> = fp_return.map(scalar_of_fp);
    let ret: FnReturn = fp_return.map_or(FnReturn::Int(return_width), FnReturn::Fp);
    let signature: FnSignature = FnSignature {
        fp: fp_args,
        int: wide_int_signature(&params),
        vec: Vec::new(),
        ret,
        exact_integer_types: false,
        abi,
    };
    let fp_params: Vec<ScalarType> = signature.ordered_param_types();
    let frame_plan: Option<FramePlan> = plan_frame(&structured.body, classify_frame(&insns, abi))?;
    let mut aggregate_plan: AggregatePlan =
        infer_aggregate_plan(&structured.body, &params, frame_plan.as_ref());
    let (frame_base, frame_slots): (Option<Reg>, BTreeMap<i64, SlotCType>) =
        typed_frame_slots(machine_code, base, frame_plan.as_ref());
    aggregate_plan.frame_base = frame_base;
    aggregate_plan.frame_slots = frame_slots;
    let source: String = emit_c(
        &structured.body,
        &signature,
        frame_plan.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    );
    let rust_source: Option<String> = emit_rust(
        &structured.body,
        &signature,
        frame_plan.as_ref(),
        sret_plan.as_ref(),
        &aggregate_plan,
    );
    let sret: Option<SretReturn> = sret_plan.as_ref().map(|plan: &SretPlan| SretReturn {
        field_widths: plan
            .fields
            .iter()
            .map(|(_, w): &(i64, Width)| w.bits() / 8)
            .collect(),
        size: plan.size,
    });
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits: return_width.bits(),
        param_width_bits: vec![64; params.len()],
        params,
        fp_params,
        returns_fp,
        lifted_split_return: structured.lifted_split_return,
        lifted_loop: structured.lifted_loop,
        lifted_switch: false,
        call_targets,
        sret,
        call_site_signature: None,
    })
}

pub fn recover_leaf_function_rust_abi(machine_code: &[u8], base: u64, abi: Abi) -> Result<String> {
    let recovery: LeafRecovery = recover_leaf_function_abi(machine_code, base, abi)?;
    recovery.rust_source.ok_or_else(|| {
        Error::LlvmIr(
            "recovered leaf is not in the pure-safe rust-emittable class (float, memory access, \
             stack frame, struct return, or switch)"
                .to_owned(),
        )
    })
}

fn scalar_fp_return_channel(body: &Block) -> Result<Option<FpWidth>> {
    if !return_channel::block_has_scalar_fp(body) {
        return Ok(None);
    }
    match return_channel::infer_scalar_return(body)? {
        FnReturn::Fp(width) => Ok(Some(width)),
        FnReturn::Int(_) | FnReturn::Void | FnReturn::Vec(_) => Ok(None),
    }
}

const fn scalar_of_fp(width: FpWidth) -> ScalarType {
    match width {
        FpWidth::F32 => ScalarType::Float,
        FpWidth::F64 => ScalarType::Double,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FnReturn {
    Int(Width),
    Fp(FpWidth),
    Void,
    Vec(VecArrangement),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FnSignature {
    fp: Vec<(Xmm, FpWidth)>,
    int: Vec<(Reg, Width)>,
    vec: Vec<(u8, VecArrangement)>,
    ret: FnReturn,
    exact_integer_types: bool,
    abi: Abi,
}

impl FnSignature {
    fn ordered_param_types(&self) -> Vec<ScalarType> {
        match self.abi {
            Abi::MsX64 => self.ms_x64_ordered_param_types(),
            Abi::SysV | Abi::Aapcs64 => {
                let mut out: Vec<ScalarType> = self
                    .fp
                    .iter()
                    .map(|(_, w): &(Xmm, FpWidth)| scalar_of_fp(*w))
                    .collect();
                out.extend(std::iter::repeat_n(ScalarType::Int, self.int.len()));
                out
            }
        }
    }

    fn ms_x64_ordered_param_types(&self) -> Vec<ScalarType> {
        let int_order: &'static [Reg] = Abi::MsX64.arg_order();
        let fp_order: &'static [Xmm] = fp_arg_order(Abi::MsX64);
        let mut slotted: Vec<(u8, ScalarType)> = Vec::with_capacity(self.int.len() + self.fp.len());
        for (reg, _) in &self.int {
            let slot: u8 = int_order
                .iter()
                .position(|r: &Reg| r == reg)
                .map_or(u8::MAX, |i: usize| i as u8);
            slotted.push((slot, ScalarType::Int));
        }
        for (xmm, width) in &self.fp {
            let slot: u8 = fp_order
                .iter()
                .position(|x: &Xmm| x == xmm)
                .map_or(u8::MAX, |i: usize| i as u8);
            slotted.push((slot, scalar_of_fp(*width)));
        }
        slotted.sort_by_key(|(slot, _): &(u8, ScalarType)| *slot);
        slotted
            .into_iter()
            .map(|(_, ty): (u8, ScalarType)| ty)
            .collect()
    }
}

fn ms_x64_shared_slot_conflict(slot: usize, prior: &'static str, claimant: &'static str) -> Error {
    Error::LlvmIr(format!(
        "microsoft x64 argument position {slot} is claimed by both {prior} and {claimant}; a single shared position cannot hold two argument classes"
    ))
}

fn validate_ms_x64_shared_argument_index(
    abi: Abi,
    params: &[Reg],
    fp_args: &[(Xmm, FpWidth)],
) -> Result<()> {
    if abi != Abi::MsX64 {
        return Ok(());
    }
    let int_order: &'static [Reg] = Abi::MsX64.arg_order();
    let fp_order: &'static [Xmm] = fp_arg_order(Abi::MsX64);
    let mut slot_kind: [Option<&'static str>; 4] = [None; 4];
    for reg in params {
        let Some(slot) = int_order.iter().position(|r: &Reg| r == reg) else {
            continue;
        };
        if let Some(prior) = slot_kind[slot] {
            return Err(ms_x64_shared_slot_conflict(
                slot,
                prior,
                "an integer register",
            ));
        }
        slot_kind[slot] = Some("an integer register");
    }
    for (xmm, _) in fp_args {
        let Some(slot) = fp_order.iter().position(|x: &Xmm| x == xmm) else {
            continue;
        };
        if let Some(prior) = slot_kind[slot] {
            return Err(ms_x64_shared_slot_conflict(
                slot,
                prior,
                "a floating-point register",
            ));
        }
        slot_kind[slot] = Some("a floating-point register");
    }
    let highest: usize = slot_kind
        .iter()
        .rposition(Option::is_some)
        .map_or(0, |i: usize| i + 1);
    if slot_kind[..highest].iter().any(Option::is_none) {
        return Err(Error::LlvmIr(
            "microsoft x64 argument positions read before a write are not contiguous from position 0; a gap between the lowest and highest observed register cannot be represented as a single callable prototype".to_owned(),
        ));
    }
    Ok(())
}

fn wide_int_signature(params: &[Reg]) -> Vec<(Reg, Width)> {
    params
        .iter()
        .copied()
        .map(|reg: Reg| (reg, Width::W64))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallSiteScalar {
    Integer(Width),
    FloatingPoint(FpWidth),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallSiteIdentitySignature {
    fp_params: Vec<FpWidth>,
    int_params: Vec<Width>,
    return_type: CallSiteScalar,
    proof: CallSiteSignatureProof,
}

const AARCH64_CALL_SITE_MAX_INSTRUCTIONS: usize = 4096;

fn aarch64_call_site_body_is_bounded(machine_code: &[u8]) -> bool {
    !machine_code.is_empty()
        && machine_code.len().is_multiple_of(4)
        && machine_code.len() <= AARCH64_CALL_SITE_MAX_INSTRUCTIONS * 4
}

fn recover_call_site_identity(
    machine_code: &[u8],
    base: u64,
    recovered_signature: &CallSiteIdentitySignature,
) -> Result<LeafRecovery> {
    if !aarch64_call_site_body_is_bounded(machine_code) {
        return Err(Error::LlvmIr(
            "call-site signature evidence is outside the bounded aarch64 lift".to_owned(),
        ));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::Aarch64, base, machine_code)?;
    if insns.is_empty() || !insns.iter().all(|insn: &DisasmInsn| insn.mnemonic == "ret") {
        return Err(Error::LlvmIr(
            "call-site signature evidence only applies to a result-free return body".to_owned(),
        ));
    }
    if recovered_signature.fp_params.len() > fp_arg_order(Abi::Aapcs64).len()
        || recovered_signature.int_params.len() > Abi::Aapcs64.arg_order().len()
    {
        return Err(Error::LlvmIr(
            "call-site signature evidence exceeds the aapcs64 register argument limit".to_owned(),
        ));
    }
    let fp: Vec<(Xmm, FpWidth)> = recovered_signature
        .fp_params
        .iter()
        .copied()
        .zip(fp_arg_order(Abi::Aapcs64).iter().copied())
        .map(|(width, register): (FpWidth, Xmm)| (register, width))
        .collect();
    let int: Vec<(Reg, Width)> = recovered_signature
        .int_params
        .iter()
        .copied()
        .zip(Abi::Aapcs64.arg_order().iter().copied())
        .map(|(width, register): (Width, Reg)| (register, width))
        .collect();
    let ret: FnReturn = match recovered_signature.return_type {
        CallSiteScalar::Integer(width) => FnReturn::Int(width),
        CallSiteScalar::FloatingPoint(width) => FnReturn::Fp(width),
    };
    let signature: FnSignature = FnSignature {
        fp,
        int: int.clone(),
        vec: Vec::new(),
        ret,
        exact_integer_types: true,
        abi: Abi::Aapcs64,
    };
    let body: Block = vec![Node::Return];
    let aggregates: AggregatePlan = AggregatePlan::default();
    let source: String = emit_c(&body, &signature, None, None, &aggregates);
    let rust_source: Option<String> = emit_rust(&body, &signature, None, None, &aggregates);
    let params: Vec<Reg> = int.iter().map(|(reg, _): &(Reg, Width)| *reg).collect();
    let param_width_bits: Vec<u32> = int
        .iter()
        .map(|(_, width): &(Reg, Width)| width.bits())
        .collect();
    let fp_params: Vec<ScalarType> = if signature.fp.is_empty() {
        Vec::new()
    } else {
        signature.ordered_param_types()
    };
    let (return_width_bits, returns_fp): (u32, Option<ScalarType>) =
        match recovered_signature.return_type {
            CallSiteScalar::Integer(width) => (width.bits(), None),
            CallSiteScalar::FloatingPoint(FpWidth::F32) => (32, Some(ScalarType::Float)),
            CallSiteScalar::FloatingPoint(FpWidth::F64) => (64, Some(ScalarType::Double)),
        };
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits,
        param_width_bits,
        params,
        fp_params,
        returns_fp,
        lifted_split_return: false,
        lifted_loop: false,
        lifted_switch: false,
        call_targets: Vec::new(),
        sret: None,
        call_site_signature: Some(recovered_signature.proof.clone()),
    })
}

pub fn recover_leaf_function_switch_abi(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    tables: &[JumpTable],
) -> Result<LeafRecovery> {
    recover_leaf_function_switch_const_abi(machine_code, base, abi, tables, &[])
}

pub fn recover_leaf_function_switch_const_abi(
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    tables: &[JumpTable],
    consts: &[FpConstant],
) -> Result<LeafRecovery> {
    require_x86_abi(abi)?;
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let by_addr: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &DisasmInsn)| (insn.address, i))
        .collect();
    let Some(dispatch): Option<SwitchDispatch> = detect_switch_dispatch(&insns) else {
        return Err(Error::LlvmIr(
            "no dense jump-table dispatch prologue in leaf".to_owned(),
        ));
    };
    let Some(table): Option<&JumpTable> = tables
        .iter()
        .find(|t: &&JumpTable| t.table_va == dispatch.table_va)
    else {
        return Err(Error::LlvmIr(format!(
            "no resolved jump table supplied for base {:#x}",
            dispatch.table_va
        )));
    };
    let expected: usize = (dispatch.bound as usize)
        .checked_add(1)
        .ok_or_else(|| Error::LlvmIr("jump-table bound overflow".to_owned()))?;
    if table.entries.len() != expected {
        return Err(Error::LlvmIr(format!(
            "jump table has {} entries but bound implies {expected} cases",
            table.entries.len()
        )));
    }

    let mut case_targets: Vec<u64> = Vec::with_capacity(expected);
    for entry in &table.entries {
        let target: u64 = dispatch
            .table_va
            .checked_add_signed(i64::from(*entry))
            .ok_or_else(|| Error::LlvmIr("jump-table target out of range".to_owned()))?;
        case_targets.push(target);
    }
    build_switch_recovery(&insns, &by_addr, abi, &dispatch, &case_targets, consts, &[])
}

fn require_x86_abi(abi: Abi) -> Result<()> {
    if abi == Abi::Aapcs64 {
        return Err(Error::LlvmIr(
            "aapcs64 requires the aarch64 recovery entry point".to_owned(),
        ));
    }
    Ok(())
}

fn build_switch_recovery(
    insns: &[DisasmInsn],
    by_addr: &BTreeMap<u64, usize>,
    abi: Abi,
    dispatch: &SwitchDispatch,
    case_targets: &[u64],
    consts: &[FpConstant],
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    let mut leaders: Vec<u64> = case_targets.to_vec();
    leaders.push(dispatch.default_addr);
    leaders.sort_unstable();
    leaders.dedup();

    let inter: Vec<Stmt> =
        lift_stmt_range(insns, dispatch.inter_start, dispatch.inter_end, consts)?;

    let mut return_width: Width = Width::W64;
    let mut bodies: BTreeMap<u64, SwitchBody> = BTreeMap::new();
    let mut pending: Vec<u64> = leaders.clone();
    while let Some(addr) = pending.pop() {
        if bodies.contains_key(&addr) {
            continue;
        }
        let (stmts, term, fp_end): (Vec<Stmt>, BodyTerm, Option<FpWidth>) =
            lift_switch_body(insns, by_addr, addr, &leaders, &mut return_width, consts)?;
        if let BodyTerm::Tail(tail) = term {
            pending.push(tail);
        }
        bodies.insert(
            addr,
            SwitchBody {
                stmts,
                term,
                fp_end,
            },
        );
    }

    let disc_used: bool = std::iter::once(&inter)
        .chain(bodies.values().map(|body: &SwitchBody| &body.stmts))
        .any(|stmts: &Vec<Stmt>| {
            stmts.iter().any(|stmt: &Stmt| {
                let mut regs: Vec<Reg> = Vec::new();
                stmt_value_reads(stmt, &mut regs);
                regs.contains(&dispatch.disc.reg)
            })
        });
    let (case_base, first_index): (i64, usize) = match dispatch.bias {
        Some((base, sub_index)) if !disc_used => (base, sub_index),
        _ => (0, dispatch.first_index),
    };

    let preamble: Vec<Stmt> = lift_stmt_range(insns, 0, first_index, consts)?;
    for stmt in preamble.iter().chain(inter.iter()) {
        update_return_width(stmt, &mut return_width);
    }

    let default_addr: u64 = dispatch.default_addr;
    let textual_next =
        |index: usize| -> u64 { case_targets.get(index + 1).copied().unwrap_or(default_addr) };
    let fallthrough_for = |addr: u64| -> Option<u64> {
        case_targets
            .iter()
            .position(|&t: &u64| t == addr)
            .map(|index: usize| textual_next(index))
    };
    let mut int_width: Option<Width> = None;
    for &target in case_targets {
        if let Some(width) = chain_terminal_int_width(&bodies, target, fallthrough_for) {
            int_width = Some(int_width.map_or(width, |cur: Width| cur.max(width)));
        }
    }
    if let Some(width) = chain_terminal_int_width(&bodies, default_addr, |_: u64| None) {
        int_width = Some(int_width.map_or(width, |cur: Width| cur.max(width)));
    }
    let return_width: Width = int_width.unwrap_or(return_width);

    let ret: FnReturn = infer_switch_return(
        case_targets,
        dispatch.default_addr,
        &bodies,
        &leaders,
        return_width,
    )?;

    let mut cases: Vec<SwitchCase> = Vec::with_capacity(case_targets.len());
    for (index, &target) in case_targets.iter().enumerate() {
        let SwitchBody { stmts, term, .. } = bodies
            .get(&target)
            .ok_or_else(|| Error::LlvmIr("case body not lifted".to_owned()))?;
        let mut body: Block = stmts.iter().cloned().map(Node::Stmt).collect();
        let textual_next: u64 = case_targets
            .get(index + 1)
            .copied()
            .unwrap_or(dispatch.default_addr);
        let fallthrough: bool = match term {
            BodyTerm::Ret => false,
            BodyTerm::Tail(tail_addr) if *tail_addr == textual_next => true,
            BodyTerm::Tail(tail_addr) => {
                append_tail(&mut body, &bodies, *tail_addr, &leaders)?;
                false
            }
            BodyTerm::FellInto(next_addr) => {
                if *next_addr != textual_next {
                    return Err(Error::LlvmIr(
                        "case falls through to a non-adjacent block; unsupported".to_owned(),
                    ));
                }
                true
            }
        };
        let offset: i64 =
            i64::try_from(index).map_err(|_| Error::LlvmIr("case index overflow".to_owned()))?;
        let value: i64 = case_base
            .checked_add(offset)
            .ok_or_else(|| Error::LlvmIr("case value overflow".to_owned()))?;
        match cases.last_mut() {
            Some(prev) if !prev.fallthrough && !fallthrough && prev.body == body => {
                prev.values.push(value);
            }
            _ => cases.push(SwitchCase {
                values: vec![value],
                body,
                fallthrough,
            }),
        }
    }

    let SwitchBody {
        stmts: default_stmts,
        term: default_term,
        ..
    } = bodies
        .get(&dispatch.default_addr)
        .ok_or_else(|| Error::LlvmIr("default body not lifted".to_owned()))?;
    let mut default_body: Block = default_stmts.iter().cloned().map(Node::Stmt).collect();
    match default_term {
        BodyTerm::Ret => {}
        BodyTerm::Tail(tail_addr) => append_tail(&mut default_body, &bodies, *tail_addr, &leaders)?,
        BodyTerm::FellInto(_) => {
            return Err(Error::LlvmIr(
                "default body falls into another block; unsupported".to_owned(),
            ));
        }
    }

    let mut body: Block = preamble.into_iter().map(Node::Stmt).collect();
    body.extend(inter.into_iter().map(Node::Stmt));
    body.push(Node::Switch {
        disc: dispatch.disc,
        cases,
        default: default_body,
    });

    if !calls.is_empty() {
        let call_map: BTreeMap<u64, &ResolvedCall> =
            calls.iter().map(|c: &ResolvedCall| (c.target, c)).collect();
        annotate_calls_block(&mut body, &call_map, abi);
    }

    let mut call_targets: Vec<u64> = Vec::new();
    collect_call_targets(&body, &mut call_targets);
    let params: Vec<Reg> = infer_params(&body, abi);
    let fp_args: Vec<(Xmm, FpWidth)> = infer_fp_params(&body, abi)?;
    validate_ms_x64_shared_argument_index(abi, &params, &fp_args)?;
    let signature: FnSignature = FnSignature {
        fp: fp_args,
        int: wide_int_signature(&params),
        vec: Vec::new(),
        ret,
        exact_integer_types: false,
        abi,
    };
    let returns_fp: Option<ScalarType> = match ret {
        FnReturn::Fp(width) => Some(scalar_of_fp(width)),
        FnReturn::Int(_) | FnReturn::Void | FnReturn::Vec(_) => None,
    };
    let frame_plan: Option<FramePlan> = plan_frame(&body, classify_frame(insns, abi))?;
    let aggregate_plan: AggregatePlan = infer_aggregate_plan(&body, &params, frame_plan.as_ref());
    let source: String = emit_c(
        &body,
        &signature,
        frame_plan.as_ref(),
        None,
        &aggregate_plan,
    );
    let rust_source: Option<String> = emit_rust(
        &body,
        &signature,
        frame_plan.as_ref(),
        None,
        &aggregate_plan,
    );
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits: return_width.bits(),
        param_width_bits: vec![64; params.len()],
        params,
        fp_params: signature.ordered_param_types(),
        returns_fp,
        lifted_split_return: false,
        lifted_loop: false,
        lifted_switch: true,
        call_targets,
        sret: None,
        call_site_signature: None,
    })
}

fn recover_switch_in_object(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let by_addr: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &DisasmInsn)| (insn.address, i))
        .collect();
    let Some(dispatch): Option<SwitchDispatch> = detect_switch_dispatch(&insns) else {
        return Err(Error::LlvmIr(
            "no dense jump-table dispatch prologue in leaf".to_owned(),
        ));
    };
    let case_targets: Vec<u64> = object_switch_case_targets(object, base, &insns, &dispatch)?;
    build_switch_recovery(&insns, &by_addr, abi, &dispatch, &case_targets, &[], calls)
}

fn recover_o0_switch_in_object(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let by_addr: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &DisasmInsn)| (insn.address, i))
        .collect();
    let Some((dispatch, second_lea_idx)): Option<(SwitchDispatch, usize)> =
        detect_o0_jump_dispatch(&insns)
    else {
        return Err(Error::LlvmIr(
            "no O0 dense jump-table dispatch prologue in leaf".to_owned(),
        ));
    };
    verify_shared_table_lea(object, base, &insns, dispatch.inter_end, second_lea_idx)?;
    let case_targets: Vec<u64> = object_switch_case_targets(object, base, &insns, &dispatch)?;
    build_switch_recovery(&insns, &by_addr, abi, &dispatch, &case_targets, &[], calls)
}

fn recover_clang_o0_switch_in_object(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    abi: Abi,
    calls: &[ResolvedCall],
) -> Result<LeafRecovery> {
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let by_addr: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &DisasmInsn)| (insn.address, i))
        .collect();
    let Some(dispatch): Option<SwitchDispatch> = detect_clang_o0_jump_dispatch(&insns) else {
        return Err(Error::LlvmIr(
            "no clang O0 jump-table dispatch prologue in leaf".to_owned(),
        ));
    };
    let case_targets: Vec<u64> = object_switch_case_targets(object, base, &insns, &dispatch)?;
    build_switch_recovery(&insns, &by_addr, abi, &dispatch, &case_targets, &[], calls)
}

fn verify_shared_table_lea(
    object: &[u8],
    base: u64,
    insns: &[DisasmInsn],
    first_lea_idx: usize,
    second_lea_idx: usize,
) -> Result<()> {
    use object::{Object as _, ObjectSection as _};

    let file: object::File<'_> = object::File::parse(object)
        .map_err(|e: object::Error| Error::LlvmIr(format!("object parse for table leas: {e}")))?;
    let code_section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            let start: u64 = section.address();
            let end: u64 = start.saturating_add(section.size());
            section.kind() == object::SectionKind::Text && (start..end).contains(&base)
        })
        .ok_or_else(|| Error::LlvmIr("dispatch code section not located".to_owned()))?;
    let first: (object::SectionIndex, u64) =
        lea_table_location(&file, &code_section, insns, first_lea_idx)?;
    let second: (object::SectionIndex, u64) =
        lea_table_location(&file, &code_section, insns, second_lea_idx)?;
    if first != second {
        return Err(Error::LlvmIr(
            "dispatch table leas resolve to different tables; not a soundly recoverable switch"
                .to_owned(),
        ));
    }
    Ok(())
}

fn lea_table_location<'data>(
    file: &object::File<'data>,
    code_section: &object::Section<'data, '_>,
    insns: &[DisasmInsn],
    lea_idx: usize,
) -> Result<(object::SectionIndex, u64)> {
    let lea: &DisasmInsn = insns
        .get(lea_idx)
        .ok_or_else(|| Error::LlvmIr("table lea index out of range".to_owned()))?;
    let disp_field_va: u64 = lea
        .address
        .checked_add(lea.bytes.len() as u64)
        .and_then(|end: u64| end.checked_sub(4))
        .ok_or_else(|| Error::LlvmIr("table lea has no displacement field".to_owned()))?;
    resolve_lea_table(file, code_section, disp_field_va)
}

fn recover_value_switch_in_object(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    abi: Abi,
) -> Result<LeafRecovery> {
    if machine_code.is_empty() {
        return Err(Error::LlvmIr("empty machine code".to_owned()));
    }
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    let Some(switch): Option<ValueTableSwitch> = detect_value_table_switch(&insns) else {
        return Err(Error::LlvmIr(
            "no value-table dispatch prologue in leaf".to_owned(),
        ));
    };
    let values: Vec<i64> = object_value_table(object, base, &insns, &switch)?;
    build_value_switch_recovery(abi, &switch, &values)
}

fn build_value_switch_recovery(
    abi: Abi,
    switch: &ValueTableSwitch,
    values: &[i64],
) -> Result<LeafRecovery> {
    let ret_reg: RegRef = RegRef {
        reg: Reg::Rax,
        width: Width::W64,
    };
    let mut cases: Vec<SwitchCase> = Vec::with_capacity(values.len());
    for (index, &value) in values.iter().enumerate() {
        let case_value: i64 = i64::try_from(index)
            .map_err(|_| Error::LlvmIr("value-switch case overflow".to_owned()))?;
        cases.push(SwitchCase {
            values: vec![case_value],
            body: vec![Node::Stmt(Stmt::Assign {
                dest: ret_reg,
                src: Source::Imm(value),
            })],
            fallthrough: false,
        });
    }
    let default: Block = vec![Node::Stmt(Stmt::Assign {
        dest: ret_reg,
        src: Source::Imm(switch.default_value),
    })];
    let body: Block = vec![Node::Switch {
        disc: switch.disc,
        cases,
        default,
    }];
    let return_width: Width = Width::W64;
    let params: Vec<Reg> = infer_params(&body, abi);
    let signature: FnSignature = FnSignature {
        fp: Vec::new(),
        int: wide_int_signature(&params),
        vec: Vec::new(),
        ret: FnReturn::Int(return_width),
        exact_integer_types: false,
        abi,
    };
    let aggregate_plan: AggregatePlan = infer_aggregate_plan(&body, &params, None);
    let source: String = emit_c(&body, &signature, None, None, &aggregate_plan);
    let rust_source: Option<String> = emit_rust(&body, &signature, None, None, &aggregate_plan);
    Ok(LeafRecovery {
        source,
        rust_source,
        return_width_bits: return_width.bits(),
        param_width_bits: vec![64; params.len()],
        params,
        fp_params: signature.ordered_param_types(),
        returns_fp: None,
        lifted_split_return: false,
        lifted_loop: false,
        lifted_switch: true,
        call_targets: Vec::new(),
        sret: None,
        call_site_signature: None,
    })
}

fn table_span_within_section(table_off: u64, span: u64, table_len: usize) -> bool {
    table_off
        .checked_add(span)
        .is_some_and(|end: u64| end <= table_len as u64)
}

fn object_value_table(
    object: &[u8],
    base: u64,
    insns: &[DisasmInsn],
    switch: &ValueTableSwitch,
) -> Result<Vec<i64>> {
    use object::{Object as _, ObjectSection as _};

    let file: object::File<'_> = object::File::parse(object)
        .map_err(|e: object::Error| Error::LlvmIr(format!("object parse for value table: {e}")))?;
    let width: u64 = u64::from(switch.entry_width);
    let lea: &DisasmInsn = insns
        .get(switch.lea_idx)
        .ok_or_else(|| Error::LlvmIr("value-table lea index out of range".to_owned()))?;
    let disp_field_va: u64 = lea
        .address
        .checked_add(lea.bytes.len() as u64)
        .and_then(|end: u64| end.checked_sub(4))
        .ok_or_else(|| Error::LlvmIr("value-table lea has no displacement field".to_owned()))?;
    let code_section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            let start: u64 = section.address();
            let end: u64 = start.saturating_add(section.size());
            section.kind() == object::SectionKind::Text && (start..end).contains(&base)
        })
        .ok_or_else(|| Error::LlvmIr("value-table code section not located".to_owned()))?;
    let (table_index, table_off): (object::SectionIndex, u64) =
        resolve_lea_table(&file, &code_section, disp_field_va)?;
    let table_section: object::Section<'_, '_> = file
        .section_by_index(table_index)
        .map_err(|e: object::Error| Error::LlvmIr(format!("value-table section missing: {e}")))?;
    let table_data: &[u8] = table_section
        .data()
        .map_err(|e: object::Error| Error::LlvmIr(format!("value-table data unavailable: {e}")))?;
    let table_addr: u64 = table_section.address();
    let span: u64 = width
        .checked_mul(switch.count as u64)
        .ok_or_else(|| Error::LlvmIr("value-table span overflow".to_owned()))?;
    if !table_span_within_section(table_off, span, table_data.len()) {
        return Err(Error::LlvmIr(
            "value-table exceeds table section".to_owned(),
        ));
    }
    for (off, _reloc) in table_section.relocations() {
        let slot: u64 = off.saturating_sub(table_addr);
        if slot >= table_off && slot < table_off.saturating_add(span) {
            return Err(Error::LlvmIr(
                "value-table slot carries a relocation; entries are addresses, not constants"
                    .to_owned(),
            ));
        }
    }
    let mut values: Vec<i64> = Vec::with_capacity(switch.count);
    for index in 0..switch.count {
        let slot: u64 = table_off
            .checked_add(
                width
                    .checked_mul(index as u64)
                    .ok_or_else(|| Error::LlvmIr("value-table index overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::LlvmIr("value-table slot overflow".to_owned()))?;
        let start: usize = usize::try_from(slot)
            .map_err(|_| Error::LlvmIr("value-table slot address overflow".to_owned()))?;
        let value: i64 = match (switch.entry_width, switch.signed_load) {
            (8, _) => table_data
                .get(start..start + 8)
                .and_then(|b: &[u8]| b.try_into().ok())
                .map(i64::from_le_bytes)
                .ok_or_else(|| Error::LlvmIr("value-table slot out of range".to_owned()))?,
            (4, true) => table_data
                .get(start..start + 4)
                .and_then(|b: &[u8]| b.try_into().ok())
                .map(|b: [u8; 4]| i64::from(i32::from_le_bytes(b)))
                .ok_or_else(|| Error::LlvmIr("value-table slot out of range".to_owned()))?,
            (4, false) => table_data
                .get(start..start + 4)
                .and_then(|b: &[u8]| b.try_into().ok())
                .map(|b: [u8; 4]| i64::from(u32::from_le_bytes(b)))
                .ok_or_else(|| Error::LlvmIr("value-table slot out of range".to_owned()))?,
            _ => {
                return Err(Error::LlvmIr(
                    "unsupported value-table entry width".to_owned(),
                ));
            }
        };
        values.push(value);
    }
    Ok(values)
}

fn reloc_effective_addend(
    reloc: &object::Relocation,
    section_data: &[u8],
    slot: u64,
    width: u8,
) -> Result<i64> {
    if !reloc.has_implicit_addend() {
        return Ok(reloc.addend());
    }
    let start: usize =
        usize::try_from(slot).map_err(|_| Error::LlvmIr("relocation slot overflow".to_owned()))?;
    let stored: i64 = match width {
        8 => {
            let bytes: [u8; 8] = section_data
                .get(start..start + 8)
                .and_then(|b: &[u8]| b.try_into().ok())
                .ok_or_else(|| Error::LlvmIr("jump-table slot out of range".to_owned()))?;
            i64::from_le_bytes(bytes)
        }
        _ => {
            let bytes: [u8; 4] = section_data
                .get(start..start + 4)
                .and_then(|b: &[u8]| b.try_into().ok())
                .ok_or_else(|| Error::LlvmIr("jump-table slot out of range".to_owned()))?;
            i64::from(i32::from_le_bytes(bytes))
        }
    };
    Ok(stored.wrapping_add(reloc.addend()))
}

fn resolve_lea_table<'data>(
    file: &object::File<'data>,
    code_section: &object::Section<'data, '_>,
    disp_field_va: u64,
) -> Result<(object::SectionIndex, u64)> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let code_data: &[u8] = code_section
        .data()
        .map_err(|e: object::Error| Error::LlvmIr(format!("code section data unavailable: {e}")))?;
    for (off, reloc) in code_section.relocations() {
        if off != disp_field_va {
            continue;
        }
        let RelocationTarget::Symbol(index) = reloc.target() else {
            continue;
        };
        let sym: object::Symbol<'data, '_> = file
            .symbol_by_index(index)
            .map_err(|e: object::Error| Error::LlvmIr(format!("switch lea symbol missing: {e}")))?;
        let slot: u64 = off.saturating_sub(code_section.address());
        let effective: i64 = reloc_effective_addend(&reloc, code_data, slot, 4)?;
        let target_va: i64 = (sym.address() as i64)
            .checked_add(effective)
            .and_then(|v: i64| v.checked_add(4))
            .ok_or_else(|| Error::LlvmIr("switch table address overflow".to_owned()))?;
        let object::SymbolSection::Section(section_index) = sym.section() else {
            return Err(Error::LlvmIr(
                "switch table symbol is not section-relative".to_owned(),
            ));
        };
        let table_section: object::Section<'data, '_> = file
            .section_by_index(section_index)
            .map_err(|e: object::Error| Error::LlvmIr(format!("table section missing: {e}")))?;
        let table_off: u64 = u64::try_from(target_va - table_section.address() as i64)
            .map_err(|_| Error::LlvmIr("switch table offset negative".to_owned()))?;
        return Ok((section_index, table_off));
    }
    Err(Error::LlvmIr(
        "switch lea has no relocation naming the jump table".to_owned(),
    ))
}

fn resolve_packed_constants(object: &[u8], machine_code: &[u8], base: u64) -> Vec<PackedConstant> {
    use object::{Object as _, ObjectSection as _};

    let Ok(insns): Result<Vec<DisasmInsn>> = disassemble(Arch::X86_64, base, machine_code) else {
        return Vec::new();
    };
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(object)
    else {
        return Vec::new();
    };
    let Some(code_section): Option<object::Section<'_, '_>> =
        file.sections().find(|section: &object::Section<'_, '_>| {
            let start: u64 = section.address();
            let end: u64 = start.saturating_add(section.size());
            section.kind() == object::SectionKind::Text && (start..end).contains(&base)
        })
    else {
        return Vec::new();
    };
    let mut resolved: Vec<PackedConstant> = Vec::new();
    for insn in &insns {
        if !matches!(insn.mnemonic.as_str(), "movdqa" | "movdqu") || !insn.operands.contains("[rel")
        {
            continue;
        }
        let Some(disp_field_va): Option<u64> = (insn.address)
            .checked_add(insn.bytes.len() as u64)
            .and_then(|end: u64| end.checked_sub(4))
        else {
            continue;
        };
        let Ok((section_index, off)): Result<(object::SectionIndex, u64)> =
            resolve_lea_table(&file, &code_section, disp_field_va)
        else {
            continue;
        };
        let Ok(section): core::result::Result<object::Section<'_, '_>, object::Error> =
            file.section_by_index(section_index)
        else {
            continue;
        };
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let start: usize = match usize::try_from(off) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let low: Option<[u8; 8]> = data
            .get(start..start.saturating_add(8))
            .and_then(|b: &[u8]| b.try_into().ok());
        let high: Option<[u8; 8]> = data
            .get(start.saturating_add(8)..start.saturating_add(16))
            .and_then(|b: &[u8]| b.try_into().ok());
        let (Some(low), Some(high)): (Option<[u8; 8]>, Option<[u8; 8]>) = (low, high) else {
            continue;
        };
        resolved.push(PackedConstant {
            site: insn.address,
            q0: u64::from_le_bytes(low),
            q1: u64::from_le_bytes(high),
        });
    }
    resolved
}

fn object_switch_case_targets(
    object: &[u8],
    base: u64,
    insns: &[DisasmInsn],
    dispatch: &SwitchDispatch,
) -> Result<Vec<u64>> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let file: object::File<'_> = object::File::parse(object)
        .map_err(|e: object::Error| Error::LlvmIr(format!("object parse for jump table: {e}")))?;
    let count: usize = (dispatch.bound as usize)
        .checked_add(1)
        .ok_or_else(|| Error::LlvmIr("jump-table bound overflow".to_owned()))?;
    let width: u64 = u64::from(dispatch.entry_width);

    let lea: &DisasmInsn = insns
        .get(dispatch.inter_end)
        .ok_or_else(|| Error::LlvmIr("switch lea index out of range".to_owned()))?;
    let disp_field_va: u64 = (lea.address)
        .checked_add(lea.bytes.len() as u64)
        .and_then(|end: u64| end.checked_sub(4))
        .ok_or_else(|| Error::LlvmIr("switch lea has no displacement field".to_owned()))?;

    let code_section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            let start: u64 = section.address();
            let end: u64 = start.saturating_add(section.size());
            section.kind() == object::SectionKind::Text && (start..end).contains(&base)
        })
        .ok_or_else(|| Error::LlvmIr("switch code section not located".to_owned()))?;

    let (table_index, table_off): (object::SectionIndex, u64) =
        resolve_lea_table(&file, &code_section, disp_field_va)?;
    let table_section: object::Section<'_, '_> = file
        .section_by_index(table_index)
        .map_err(|e: object::Error| Error::LlvmIr(format!("table section missing: {e}")))?;
    let table_data: &[u8] = table_section
        .data()
        .map_err(|e: object::Error| Error::LlvmIr(format!("table data unavailable: {e}")))?;
    let table_addr: u64 = table_section.address();
    let table_va: u64 = table_addr.saturating_add(table_off);
    let span: u64 = width
        .checked_mul(count as u64)
        .ok_or_else(|| Error::LlvmIr("jump-table span overflow".to_owned()))?;
    if !table_span_within_section(table_off, span, table_data.len()) {
        return Err(Error::LlvmIr("jump table exceeds table section".to_owned()));
    }

    let mut slot_relocs: BTreeMap<u64, object::Relocation> = BTreeMap::new();
    for (off, reloc) in table_section.relocations() {
        let slot: u64 = off.saturating_sub(table_addr);
        if slot < table_off || slot >= table_off + span || (slot - table_off) % width != 0 {
            continue;
        }
        slot_relocs.insert(slot, reloc);
    }

    let mut case_targets: Vec<u64> = Vec::with_capacity(count);
    for index in 0..count {
        let slot: u64 = table_off + width * index as u64;
        if let Some(reloc) = slot_relocs.get(&slot) {
            let RelocationTarget::Symbol(sym_index) = reloc.target() else {
                return Err(Error::LlvmIr(
                    "jump-table entry relocation is not symbol-relative".to_owned(),
                ));
            };
            let sym: object::Symbol<'_, '_> = file
                .symbol_by_index(sym_index)
                .map_err(|e| Error::LlvmIr(format!("jump-table entry symbol missing: {e}")))?;
            let effective: i64 =
                reloc_effective_addend(reloc, table_data, slot, dispatch.entry_width)?;
            let intra_table: i64 = i64::try_from(slot - table_off)
                .map_err(|_| Error::LlvmIr("jump-table offset overflow".to_owned()))?;
            let case_off: i64 = (sym.address() as i64)
                .checked_add(effective)
                .and_then(|v: i64| v.checked_sub(intra_table))
                .ok_or_else(|| Error::LlvmIr("jump-table entry overflow".to_owned()))?;
            let target: u64 = u64::try_from(case_off)
                .map_err(|_| Error::LlvmIr("jump-table entry target negative".to_owned()))?;
            case_targets.push(target);
        } else if slot_relocs.is_empty() {
            let start: usize = usize::try_from(slot)
                .map_err(|_| Error::LlvmIr("jump-table slot overflow".to_owned()))?;
            let raw: i64 = match dispatch.entry_width {
                8 => table_data
                    .get(start..start + 8)
                    .and_then(|b: &[u8]| b.try_into().ok())
                    .map(i64::from_le_bytes)
                    .ok_or_else(|| Error::LlvmIr("jump-table slot out of range".to_owned()))?,
                _ => table_data
                    .get(start..start + 4)
                    .and_then(|b: &[u8]| b.try_into().ok())
                    .map(|b: [u8; 4]| i64::from(i32::from_le_bytes(b)))
                    .ok_or_else(|| Error::LlvmIr("jump-table slot out of range".to_owned()))?,
            };
            let target: u64 = table_va
                .checked_add_signed(raw)
                .ok_or_else(|| Error::LlvmIr("jump-table entry out of range".to_owned()))?;
            case_targets.push(target);
        } else {
            return Err(Error::LlvmIr(
                "jump table is partially relocated; cannot resolve every entry".to_owned(),
            ));
        }
    }
    Ok(case_targets)
}

#[derive(Debug, Clone, Copy)]
struct SwitchDispatch {
    disc: RegRef,
    bound: u64,
    default_addr: u64,
    table_va: u64,
    bias: Option<(i64, usize)>,
    entry_width: u8,
    first_index: usize,
    inter_start: usize,
    inter_end: usize,
}

fn detect_switch_dispatch(insns: &[DisasmInsn]) -> Option<SwitchDispatch> {
    'outer: for cmp_idx in 0..insns.len() {
        let Some((disc, bound)): Option<(RegRef, u64)> = parse_cmp_bound(&insns[cmp_idx]) else {
            continue;
        };
        let ja_idx: usize = cmp_idx + 1;
        let Some(ja): Option<&DisasmInsn> = insns.get(ja_idx) else {
            continue;
        };
        if !matches!(ja.mnemonic.as_str(), "ja" | "jae" | "jnbe" | "jnb") {
            continue;
        }
        let Some(default_addr): Option<u64> = parse_branch_target(&ja.operands) else {
            continue;
        };
        let above: bool = matches!(ja.mnemonic.as_str(), "ja" | "jnbe");
        let Some(effective_bound): Option<u64> = (if above {
            Some(bound)
        } else {
            bound.checked_sub(1)
        }) else {
            continue;
        };

        let inter_start: usize = ja_idx + 1;
        let mut lea_hit: Option<(usize, Reg, u64)> = None;
        let mut scan: usize = inter_start;
        while scan < insns.len() {
            let insn: &DisasmInsn = &insns[scan];
            if let Some((dest, va)) = parse_lea_rip(insn) {
                lea_hit = Some((scan, dest, va));
                break;
            }
            if lift_straight_stmt(insn).is_none() && !is_ignorable(insn) {
                continue 'outer;
            }
            scan += 1;
        }
        let Some((lea_idx, base_reg, table_va)): Option<(usize, Reg, u64)> = lea_hit else {
            continue;
        };
        let inter_end: usize = lea_idx;

        let load_idx: usize = lea_idx + 1;
        let Some(load): Option<&DisasmInsn> = insns.get(load_idx) else {
            continue;
        };
        let Some((off_reg, index_reg)): Option<(Reg, Reg)> =
            parse_movsxd_table_load(load, base_reg)
        else {
            continue;
        };
        if index_reg != disc.reg {
            continue;
        }
        let add_idx: usize = load_idx + 1;
        let Some(add): Option<&DisasmInsn> = insns.get(add_idx) else {
            continue;
        };
        if !is_add_regs(add, off_reg, base_reg) {
            continue;
        }
        let jmp_idx: usize = add_idx + 1;
        let Some(jmp): Option<&DisasmInsn> = insns.get(jmp_idx) else {
            continue;
        };
        if !is_indirect_jmp(jmp, off_reg) {
            continue;
        }
        let bias: Option<(i64, usize)> = cmp_idx.checked_sub(1).and_then(|prev: usize| {
            parse_case_bias(&insns[prev], disc.reg).map(|b: i64| (b, prev))
        });
        return Some(SwitchDispatch {
            disc,
            bound: effective_bound,
            default_addr,
            table_va,
            bias,
            entry_width: 4,
            first_index: cmp_idx,
            inter_start,
            inter_end,
        });
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct ValueTableSwitch {
    disc: RegRef,
    count: usize,
    default_value: i64,
    lea_idx: usize,
    entry_width: u8,
    signed_load: bool,
}

fn detect_value_table_switch(insns: &[DisasmInsn]) -> Option<ValueTableSwitch> {
    for cmp_idx in 0..insns.len() {
        let Some((disc, bound)): Option<(RegRef, u64)> = parse_cmp_bound(&insns[cmp_idx]) else {
            continue;
        };
        if disc.reg == Reg::Rax {
            continue;
        }
        let Some(jump): Option<&DisasmInsn> = insns.get(cmp_idx + 1) else {
            continue;
        };
        if !matches!(jump.mnemonic.as_str(), "ja" | "jnbe" | "jae" | "jnb") {
            continue;
        }
        let Some(default_target): Option<u64> = parse_branch_target(&jump.operands) else {
            continue;
        };
        let above: bool = matches!(jump.mnemonic.as_str(), "ja" | "jnbe");
        let Some(effective_bound): Option<u64> = (if above {
            Some(bound)
        } else {
            bound.checked_sub(1)
        }) else {
            continue;
        };
        let Some(count): Option<usize> = usize::try_from(effective_bound)
            .ok()
            .and_then(|b: usize| b.checked_add(1))
        else {
            continue;
        };
        let Some(lea_idx): Option<usize> = next_effective(insns, cmp_idx + 2) else {
            continue;
        };
        let Some((tbl_reg, _table_va)): Option<(Reg, u64)> = parse_lea_rip(&insns[lea_idx]) else {
            continue;
        };
        if tbl_reg == disc.reg {
            continue;
        }
        let Some(load_idx): Option<usize> = next_effective(insns, lea_idx + 1) else {
            continue;
        };
        let Some((entry_width, signed_load)): Option<(u8, bool)> =
            parse_value_table_load(&insns[load_idx], tbl_reg, disc.reg)
        else {
            continue;
        };
        let Some(ret_idx): Option<usize> = next_effective(insns, load_idx + 1) else {
            continue;
        };
        if insns[ret_idx].mnemonic != "ret" {
            continue;
        }
        let Some(default_value): Option<i64> = (if default_target == insns[ret_idx].address {
            preloaded_default(insns, cmp_idx)
        } else {
            default_block_value(insns, default_target)
        }) else {
            continue;
        };
        return Some(ValueTableSwitch {
            disc,
            count,
            default_value,
            lea_idx,
            entry_width,
            signed_load,
        });
    }
    None
}

fn next_effective(insns: &[DisasmInsn], from: usize) -> Option<usize> {
    (from..insns.len()).find(|&i: &usize| !is_ignorable(&insns[i]))
}

fn prev_effective(insns: &[DisasmInsn], before: usize) -> Option<usize> {
    (0..before)
        .rev()
        .find(|&i: &usize| !is_ignorable(&insns[i]))
}

fn preloaded_default(insns: &[DisasmInsn], cmp_idx: usize) -> Option<i64> {
    let idx: usize = (0..cmp_idx)
        .rev()
        .find(|&i: &usize| !is_ignorable(&insns[i]))?;
    match lift_one(&insns[idx].mnemonic, &insns[idx].operands)? {
        Stmt::Assign {
            dest,
            src: Source::Imm(value),
        } if dest.reg == Reg::Rax => Some(value),
        _ => None,
    }
}

fn default_block_value(insns: &[DisasmInsn], target: u64) -> Option<i64> {
    let start: usize = insns
        .iter()
        .position(|insn: &DisasmInsn| insn.address == target)?;
    let mov_idx: usize = next_effective(insns, start)?;
    let value: i64 = match lift_one(&insns[mov_idx].mnemonic, &insns[mov_idx].operands)? {
        Stmt::Assign {
            dest,
            src: Source::Imm(value),
        } if dest.reg == Reg::Rax => value,
        _ => return None,
    };
    let ret_idx: usize = next_effective(insns, mov_idx + 1)?;
    (insns[ret_idx].mnemonic == "ret").then_some(value)
}

fn parse_value_table_load(insn: &DisasmInsn, tbl_reg: Reg, disc_reg: Reg) -> Option<(u8, bool)> {
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.reg != Reg::Rax {
        return None;
    }
    match insn.mnemonic.as_str() {
        "mov" => {
            let mem: MemRef = parse_mem_access(rhs.trim(), Some(dest.width))?;
            let IndexOperand {
                reg: index_reg,
                scale,
                ..
            }: IndexOperand = mem.index?;
            if mem.base != Some(tbl_reg) || index_reg != disc_reg || mem.disp != 0 {
                return None;
            }
            let entry_width: u8 = u8::try_from(mem.width.bits() / 8).ok()?;
            if scale != entry_width || !matches!(entry_width, 4 | 8) {
                return None;
            }
            Some((entry_width, false))
        }
        "movsxd" | "movsx" => {
            if dest.width != Width::W64 {
                return None;
            }
            let mem: MemRef = parse_mem_access(rhs.trim(), Some(Width::W32))?;
            if mem.width != Width::W32 {
                return None;
            }
            let IndexOperand {
                reg: index_reg,
                scale,
                ..
            }: IndexOperand = mem.index?;
            if mem.base != Some(tbl_reg) || index_reg != disc_reg || mem.disp != 0 || scale != 4 {
                return None;
            }
            Some((4, true))
        }
        _ => None,
    }
}

fn detect_o0_jump_dispatch(insns: &[DisasmInsn]) -> Option<(SwitchDispatch, usize)> {
    for cmp_idx in 0..insns.len() {
        let Some((slot, bound)): Option<(MemRef, u64)> = parse_cmp_mem_bound(&insns[cmp_idx])
        else {
            continue;
        };
        let Some(disc_reg): Option<Reg> = (0..cmp_idx)
            .rev()
            .find_map(|i: usize| parse_store_reg_to(&insns[i], &slot))
        else {
            continue;
        };
        let Some(jump): Option<&DisasmInsn> = insns.get(cmp_idx + 1) else {
            continue;
        };
        if !matches!(jump.mnemonic.as_str(), "ja" | "jnbe" | "jae" | "jnb") {
            continue;
        }
        let Some(default_target): Option<u64> = parse_branch_target(&jump.operands) else {
            continue;
        };
        let above: bool = matches!(jump.mnemonic.as_str(), "ja" | "jnbe");
        let Some(effective_bound): Option<u64> = (if above {
            Some(bound)
        } else {
            bound.checked_sub(1)
        }) else {
            continue;
        };
        let Some(reload_idx): Option<usize> = next_effective(insns, cmp_idx + 2) else {
            continue;
        };
        let Some(index_reg): Option<Reg> = parse_load_reg_from(&insns[reload_idx], &slot) else {
            continue;
        };
        let Some(scale_idx): Option<usize> = next_effective(insns, reload_idx + 1) else {
            continue;
        };
        let Some((scale_reg, scaled, scale)): Option<(Reg, Reg, u8)> =
            parse_scaled_index_lea(&insns[scale_idx])
        else {
            continue;
        };
        if scaled != index_reg || scale != 4 {
            continue;
        }
        let Some(lea_idx): Option<usize> = next_effective(insns, scale_idx + 1) else {
            continue;
        };
        let Some((tbl_reg, table_va)): Option<(Reg, u64)> = parse_lea_rip(&insns[lea_idx]) else {
            continue;
        };
        let Some(load_idx): Option<usize> = next_effective(insns, lea_idx + 1) else {
            continue;
        };
        if parse_o0_table_load(&insns[load_idx], scale_reg, tbl_reg).is_none() {
            continue;
        }
        let Some(cdqe_idx): Option<usize> = next_effective(insns, load_idx + 1) else {
            continue;
        };
        if insns[cdqe_idx].mnemonic != "cdqe" {
            continue;
        }
        let Some(base_lea_idx): Option<usize> = next_effective(insns, cdqe_idx + 1) else {
            continue;
        };
        let Some((base_reg, _)): Option<(Reg, u64)> = parse_lea_rip(&insns[base_lea_idx]) else {
            continue;
        };
        let Some(add_idx): Option<usize> = next_effective(insns, base_lea_idx + 1) else {
            continue;
        };
        if !is_add_regs(&insns[add_idx], Reg::Rax, base_reg) {
            continue;
        }
        let Some(jmp_idx): Option<usize> = next_effective(insns, add_idx + 1) else {
            continue;
        };
        if !is_indirect_jmp(&insns[jmp_idx], Reg::Rax) {
            continue;
        }
        let dispatch: SwitchDispatch = SwitchDispatch {
            disc: RegRef {
                reg: disc_reg,
                width: Width::W64,
            },
            bound: effective_bound,
            default_addr: default_target,
            table_va,
            bias: None,
            entry_width: 4,
            first_index: cmp_idx,
            inter_start: cmp_idx + 2,
            inter_end: lea_idx,
        };
        return Some((dispatch, base_lea_idx));
    }
    None
}

fn detect_clang_o0_jump_dispatch(insns: &[DisasmInsn]) -> Option<SwitchDispatch> {
    for chk_idx in 0..insns.len() {
        let Some((reg_c, bound)): Option<(Reg, u64)> = parse_reg_bound_check(&insns[chk_idx])
        else {
            continue;
        };
        let Some(jump): Option<&DisasmInsn> = insns.get(chk_idx + 1) else {
            continue;
        };
        if !matches!(jump.mnemonic.as_str(), "ja" | "jnbe" | "jae" | "jnb") {
            continue;
        }
        let Some(default_addr): Option<u64> = parse_branch_target(&jump.operands) else {
            continue;
        };
        let above: bool = matches!(jump.mnemonic.as_str(), "ja" | "jnbe");
        let Some(effective_bound): Option<u64> = (if above {
            Some(bound)
        } else {
            bound.checked_sub(1)
        }) else {
            continue;
        };
        let Some(store_idx): Option<usize> = prev_effective(insns, chk_idx) else {
            continue;
        };
        let Some(slot): Option<MemRef> = parse_store_of_reg(&insns[store_idx], reg_c) else {
            continue;
        };
        let Some(reload_idx): Option<usize> = next_effective(insns, chk_idx + 2) else {
            continue;
        };
        let Some(index_reg): Option<Reg> = parse_load_reg_from(&insns[reload_idx], &slot) else {
            continue;
        };
        let Some(lea_idx): Option<usize> = next_effective(insns, reload_idx + 1) else {
            continue;
        };
        let Some((tbl_reg, table_va)): Option<(Reg, u64)> = parse_lea_rip(&insns[lea_idx]) else {
            continue;
        };
        let Some(load_idx): Option<usize> = next_effective(insns, lea_idx + 1) else {
            continue;
        };
        let Some((off_reg, load_index)): Option<(Reg, Reg)> =
            parse_movsxd_table_load(&insns[load_idx], tbl_reg)
        else {
            continue;
        };
        if load_index != index_reg {
            continue;
        }
        let Some(add_idx): Option<usize> = next_effective(insns, load_idx + 1) else {
            continue;
        };
        let Some(target_reg): Option<Reg> = parse_add_target(&insns[add_idx], tbl_reg, off_reg)
        else {
            continue;
        };
        let Some(jmp_idx): Option<usize> = next_effective(insns, add_idx + 1) else {
            continue;
        };
        if !is_indirect_jmp(&insns[jmp_idx], target_reg) {
            continue;
        }
        return Some(SwitchDispatch {
            disc: RegRef {
                reg: index_reg,
                width: Width::W64,
            },
            bound: effective_bound,
            default_addr,
            table_va,
            bias: None,
            entry_width: 4,
            first_index: chk_idx,
            inter_start: chk_idx + 2,
            inter_end: lea_idx,
        });
    }
    None
}

fn parse_reg_bound_check(insn: &DisasmInsn) -> Option<(Reg, u64)> {
    if !matches!(insn.mnemonic.as_str(), "cmp" | "sub") {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let disc: RegRef = parse_reg(lhs.trim())?;
    if disc.width != Width::W64 {
        return None;
    }
    let bound: i64 = parse_imm(rhs.trim())?;
    if bound < 1 {
        return None;
    }
    Some((disc.reg, bound as u64))
}

fn parse_store_of_reg(insn: &DisasmInsn, reg: Reg) -> Option<MemRef> {
    if insn.mnemonic != "mov" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    if !is_mem_token(lhs.trim()) {
        return None;
    }
    let src: RegRef = parse_reg(rhs.trim())?;
    if src.reg != reg || src.width != Width::W64 {
        return None;
    }
    parse_mem_access(lhs.trim(), Some(Width::W64))
}

fn parse_add_target(insn: &DisasmInsn, a: Reg, b: Reg) -> Option<Reg> {
    if insn.mnemonic != "add" || a == b {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    let src: RegRef = parse_reg(rhs.trim())?;
    if dest.width != Width::W64 || src.width != Width::W64 {
        return None;
    }
    let pair: [Reg; 2] = [dest.reg, src.reg];
    (pair.contains(&a) && pair.contains(&b)).then_some(dest.reg)
}

fn parse_cmp_mem_bound(insn: &DisasmInsn) -> Option<(MemRef, u64)> {
    if insn.mnemonic != "cmp" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    if !is_mem_token(lhs.trim()) {
        return None;
    }
    let mem: MemRef = parse_mem_access(lhs.trim(), None)?;
    let bound: i64 = parse_imm(rhs.trim())?;
    if bound < 1 {
        return None;
    }
    Some((mem, bound as u64))
}

fn parse_store_reg_to(insn: &DisasmInsn, slot: &MemRef) -> Option<Reg> {
    if insn.mnemonic != "mov" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    if !is_mem_token(lhs.trim()) {
        return None;
    }
    let src: RegRef = parse_reg(rhs.trim())?;
    if src.width != Width::W64 {
        return None;
    }
    let addr: MemRef = parse_mem_access(lhs.trim(), Some(Width::W64))?;
    (addr == *slot).then_some(src.reg)
}

fn parse_load_reg_from(insn: &DisasmInsn, slot: &MemRef) -> Option<Reg> {
    if insn.mnemonic != "mov" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.width != Width::W64 || !is_mem_token(rhs.trim()) {
        return None;
    }
    let mem: MemRef = parse_mem_access(rhs.trim(), Some(Width::W64))?;
    (mem == *slot).then_some(dest.reg)
}

fn parse_scaled_index_lea(insn: &DisasmInsn) -> Option<(Reg, Reg, u8)> {
    if insn.mnemonic != "lea" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.width != Width::W64 {
        return None;
    }
    let (base, index, disp): AddrTerms = parse_addr_terms(rhs.trim())?;
    if base.is_some() || disp != 0 {
        return None;
    }
    let IndexOperand {
        reg: index_reg,
        scale,
        ..
    }: IndexOperand = index?;
    Some((dest.reg, index_reg, scale))
}

fn parse_o0_table_load(insn: &DisasmInsn, scale_reg: Reg, tbl_reg: Reg) -> Option<()> {
    if insn.mnemonic != "mov" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.reg != Reg::Rax || dest.width != Width::W32 {
        return None;
    }
    let mem: MemRef = parse_mem_access(rhs.trim(), Some(Width::W32))?;
    if mem.width != Width::W32 || mem.disp != 0 {
        return None;
    }
    let base: Reg = mem.base?;
    let IndexOperand {
        reg: index_reg,
        scale: index_scale,
        ..
    }: IndexOperand = mem.index?;
    if index_scale != 1 || scale_reg == tbl_reg {
        return None;
    }
    let addr_regs: [Reg; 2] = [base, index_reg];
    (addr_regs.contains(&scale_reg) && addr_regs.contains(&tbl_reg)).then_some(())
}

fn parse_cmp_bound(insn: &DisasmInsn) -> Option<(RegRef, u64)> {
    if insn.mnemonic != "cmp" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let disc: RegRef = parse_reg(lhs.trim())?;
    let bound: i64 = parse_imm(rhs.trim())?;
    if bound < 1 {
        return None;
    }
    Some((disc, bound as u64))
}

fn parse_case_bias(insn: &DisasmInsn, disc: Reg) -> Option<i64> {
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    if parse_reg(lhs.trim())?.reg != disc {
        return None;
    }
    let imm: i64 = parse_imm(rhs.trim())?;
    match insn.mnemonic.as_str() {
        "sub" if imm > 0 => Some(imm),
        "add" if imm < 0 => Some(-imm),
        _ => None,
    }
}

fn parse_lea_rip(insn: &DisasmInsn) -> Option<(Reg, u64)> {
    if insn.mnemonic != "lea" {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.width != Width::W64 {
        return None;
    }
    let inner: &str = rhs.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let body: &str = inner.strip_prefix("rel ")?.trim();
    let va: u64 = parse_hex_u64(body)?;
    Some((dest.reg, va))
}

fn parse_hex_u64(token: &str) -> Option<u64> {
    let t: &str = token.trim();
    let body: &str = t.strip_suffix(['h', 'H']).unwrap_or(t);
    let body: &str = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    u64::from_str_radix(body, 16).ok()
}

fn parse_movsxd_table_load(insn: &DisasmInsn, base_reg: Reg) -> Option<(Reg, Reg)> {
    if !matches!(insn.mnemonic.as_str(), "movsxd" | "movsx") {
        return None;
    }
    let (lhs, rhs): (&str, &str) = insn.operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    if dest.width != Width::W64 {
        return None;
    }
    let mem: MemRef = parse_mem_access(rhs.trim(), Some(Width::W32))?;
    if mem.width != Width::W32 {
        return None;
    }
    let IndexOperand {
        reg: index_reg,
        scale,
        ..
    }: IndexOperand = mem.index?;
    if scale != 4 {
        return None;
    }
    if mem.base != Some(base_reg) || mem.disp != 0 {
        return None;
    }
    Some((dest.reg, index_reg))
}

fn is_add_regs(insn: &DisasmInsn, dest: Reg, src: Reg) -> bool {
    if insn.mnemonic != "add" {
        return false;
    }
    let Some((lhs, rhs)): Option<(&str, &str)> = insn.operands.split_once(',') else {
        return false;
    };
    parse_reg(lhs.trim()).is_some_and(|r: RegRef| r.reg == dest && r.width == Width::W64)
        && parse_reg(rhs.trim()).is_some_and(|r: RegRef| r.reg == src && r.width == Width::W64)
}

fn is_indirect_jmp(insn: &DisasmInsn, reg: Reg) -> bool {
    insn.mnemonic == "jmp" && parse_reg(insn.operands.trim()).is_some_and(|r: RegRef| r.reg == reg)
}

fn is_xchg_self(mnemonic: &str, operands: &str) -> bool {
    mnemonic == "xchg"
        && operands
            .split_once(',')
            .is_some_and(|(a, b): (&str, &str)| a.trim() == b.trim())
}

fn is_ignorable(insn: &DisasmInsn) -> bool {
    insn.mnemonic == "nop"
        || insn.mnemonic == "endbr64"
        || is_xchg_self(&insn.mnemonic, &insn.operands)
        || is_frame_management(&insn.mnemonic, &insn.operands)
}

fn lift_straight_stmt(insn: &DisasmInsn) -> Option<Stmt> {
    if let Some(stmt) = lift_width_extension(&insn.mnemonic, &insn.operands) {
        return Some(stmt);
    }
    lift_one(&insn.mnemonic, &insn.operands)
}

fn lift_stmt_range(
    insns: &[DisasmInsn],
    lo: usize,
    hi: usize,
    consts: &[FpConstant],
) -> Result<Vec<Stmt>> {
    let mut out: Vec<Stmt> = Vec::new();
    let mut lifter: StraightLifter<'_> = StraightLifter::new(consts);
    for insn in &insns[lo..hi] {
        match lifter.feed(insn)? {
            StraightOutcome::Ignorable | StraightOutcome::StateOnly => {}
            StraightOutcome::Emit(stmt) => out.push(stmt),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyTerm {
    Ret,
    Tail(u64),
    FellInto(u64),
}

#[derive(Debug)]
enum StraightOutcome {
    Emit(Stmt),
    StateOnly,
    Ignorable,
}

#[derive(Debug)]
struct StraightLifter<'a> {
    flags: Option<Flags>,
    dividend_high: Option<DividendHigh>,
    consts: &'a [FpConstant],
}

impl<'a> StraightLifter<'a> {
    const fn new(consts: &'a [FpConstant]) -> Self {
        Self {
            flags: None,
            dividend_high: None,
            consts,
        }
    }

    fn feed(&mut self, insn: &DisasmInsn) -> Result<StraightOutcome> {
        if is_ignorable(insn) {
            if x86_mnemonic_writes_flags(&insn.mnemonic) {
                self.flags = None;
            }
            return Ok(StraightOutcome::Ignorable);
        }
        if let Some(fp_flags) =
            lift_fp_compare(&insn.mnemonic, &insn.operands, insn.address, self.consts)?
        {
            self.flags = Some(fp_flags);
            return Ok(StraightOutcome::StateOnly);
        }
        if let Some(fp_stmt) = lift_fp(&insn.mnemonic, &insn.operands, insn.address, self.consts)? {
            self.flags = None;
            self.dividend_high = None;
            return Ok(StraightOutcome::Emit(fp_stmt));
        }
        if let Some(high) = lift_dividend_extend(&insn.mnemonic, &insn.operands) {
            self.dividend_high = Some(high);
            return Ok(StraightOutcome::StateOnly);
        }
        if let Some(divisor) = parse_divide_operand(&insn.mnemonic, &insn.operands) {
            let signed: bool = insn.mnemonic == "idiv";
            let high: DividendHigh = self.dividend_high.take().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "division at {:#x} without a tracked high-half dividend setup",
                    insn.address
                ))
            })?;
            if !dividend_high_matches(high, signed, divisor.width) {
                return Err(Error::LlvmIr(format!(
                    "division at {:#x} has a high-half dividend inconsistent with a width-fitting `{}`",
                    insn.address, insn.mnemonic
                )));
            }
            self.flags = None;
            return Ok(StraightOutcome::Emit(Stmt::Divide { divisor, signed }));
        }
        if let Some(new_flags) = lift_flag_setter(&insn.mnemonic, &insn.operands) {
            self.flags = Some(new_flags);
            return Ok(StraightOutcome::StateOnly);
        }
        if let Some(suffix) = insn.mnemonic.strip_prefix("cmov") {
            let kind: CondKind = CondKind::parse(suffix).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "unsupported conditional move `{} {}` at {:#x}",
                    insn.mnemonic, insn.operands, insn.address
                ))
            })?;
            let live_flags: Flags = self.flags.clone().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "cmov without preceding flags at {:#x}",
                    insn.address
                ))
            })?;
            let Some(kind): Option<CondKind> = canonicalize_x86_fp_condition(kind, &live_flags)
            else {
                return Err(Error::LlvmIr(format!(
                    "condition `{}` not sound against tracked flags at {:#x}",
                    insn.mnemonic, insn.address
                )));
            };
            if !condition_is_sound(kind, &live_flags) {
                return Err(Error::LlvmIr(format!(
                    "condition `{}` not sound against tracked flags at {:#x}",
                    insn.mnemonic, insn.address
                )));
            }
            let (lhs, rhs): (&str, &str) = insn
                .operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed cmov at {:#x}", insn.address)))?;
            let dest: RegRef = parse_reg(lhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("cmov dest not a register at {:#x}", insn.address))
            })?;
            let src: Source = parse_source(rhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("cmov src unsupported at {:#x}", insn.address))
            })?;
            let stmt: Stmt = Stmt::Cond {
                dest,
                src,
                kind,
                flags: live_flags,
            };
            self.flags = flags_after_clobber(self.flags.take(), &stmt);
            return Ok(StraightOutcome::Emit(stmt));
        }
        if let Some(suffix) = insn.mnemonic.strip_prefix("set")
            && let Some(kind) = CondKind::parse(suffix)
        {
            let dest: RegRef = parse_reg(insn.operands.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("setcc dest not a register at {:#x}", insn.address))
            })?;
            if dest.width != Width::W8 {
                return Err(Error::LlvmIr(format!(
                    "setcc at {:#x} does not target a byte register",
                    insn.address
                )));
            }
            let live_flags: Flags = self.flags.clone().ok_or_else(|| {
                Error::LlvmIr(format!(
                    "setcc without preceding flags at {:#x}",
                    insn.address
                ))
            })?;
            let Some(kind): Option<CondKind> = canonicalize_x86_fp_condition(kind, &live_flags)
            else {
                return Err(Error::LlvmIr(format!(
                    "condition `{}` not sound against tracked flags at {:#x}",
                    insn.mnemonic, insn.address
                )));
            };
            if !condition_is_sound(kind, &live_flags) {
                return Err(Error::LlvmIr(format!(
                    "condition `{}` not sound against tracked flags at {:#x}",
                    insn.mnemonic, insn.address
                )));
            }
            let stmt: Stmt = Stmt::SetCc {
                dest,
                kind,
                flags: live_flags,
            };
            self.flags = flags_after_clobber(self.flags.take(), &stmt);
            return Ok(StraightOutcome::Emit(stmt));
        }
        let stmt: Stmt = lift_straight_stmt(insn).ok_or_else(|| {
            Error::LlvmIr(format!(
                "unsupported structured-body instruction `{} {}` at {:#x}",
                insn.mnemonic, insn.operands, insn.address
            ))
        })?;
        if sign_extended_high_read_is_unsound(self.dividend_high, &stmt) {
            return Err(Error::LlvmIr(format!(
                "sign-extended high half in rdx from a cqo/cdq is read at {:#x} without a modeled division; not soundly recoverable",
                insn.address
            )));
        }
        self.dividend_high = track_dividend_high(self.dividend_high, &stmt);
        match &stmt {
            Stmt::BinAssign { dest, op, .. } => {
                self.flags = match flag_effect_bin(*op) {
                    FlagEffect::Sign => Some(Flags::Sign { result: *dest }),
                    FlagEffect::Clobber => None,
                };
            }
            Stmt::UnAssign { dest, op } => {
                self.flags = match op {
                    UnOp::Neg => Some(Flags::Sign { result: *dest }),
                    UnOp::Not
                    | UnOp::Bswap
                    | UnOp::Clz
                    | UnOp::Rbit
                    | UnOp::Rev16
                    | UnOp::Rev32 => flags_after_clobber(self.flags.take(), &stmt),
                };
            }
            Stmt::MulImm { .. } | Stmt::WideMul { .. } | Stmt::DoubleShift { .. } => {
                self.flags = None;
            }
            Stmt::MemRmw { .. } => {
                self.flags = None;
            }
            _ => {
                self.flags = if x86_mnemonic_writes_flags(&insn.mnemonic) {
                    None
                } else {
                    flags_after_clobber(self.flags.take(), &stmt)
                };
            }
        }
        Ok(StraightOutcome::Emit(stmt))
    }
}

fn flags_after_clobber(flags: Option<Flags>, stmt: &Stmt) -> Option<Flags> {
    if let Some(live) = &flags {
        let deps: Vec<Reg> = flag_operand_regs(live);
        if stmt_dest_regs(stmt)
            .iter()
            .any(|reg: &Reg| deps.contains(reg))
        {
            return None;
        }
        let mems: Vec<MemRef> = flag_operand_mems(live);
        if !mems.is_empty() && stmt_writes_aliasing_mem(stmt, &mems) {
            return None;
        }
    }
    flags
}

fn lift_switch_body(
    insns: &[DisasmInsn],
    by_addr: &BTreeMap<u64, usize>,
    start_addr: u64,
    leaders: &[u64],
    return_width: &mut Width,
    consts: &[FpConstant],
) -> Result<(Vec<Stmt>, BodyTerm, Option<FpWidth>)> {
    let start: usize = *by_addr
        .get(&start_addr)
        .ok_or_else(|| Error::LlvmIr(format!("case target {start_addr:#x} not an instruction")))?;
    let mut stmts: Vec<Stmt> = Vec::new();
    let mut lifter: StraightLifter<'_> = StraightLifter::new(consts);
    let mut fp_return: Option<FpWidth> = None;
    let mut idx: usize = start;
    while idx < insns.len() {
        let insn: &DisasmInsn = &insns[idx];
        if idx != start && leaders.contains(&insn.address) {
            return Ok((stmts, BodyTerm::FellInto(insn.address), fp_return));
        }
        if insn.mnemonic == "ret" {
            return Ok((stmts, BodyTerm::Ret, fp_return));
        }
        if insn.mnemonic == "jmp" {
            let target: u64 = parse_branch_target(&insn.operands).ok_or_else(|| {
                Error::LlvmIr("switch case jmp is not a direct forward tail".to_owned())
            })?;
            return Ok((stmts, BodyTerm::Tail(target), fp_return));
        }
        match lifter.feed(insn)? {
            StraightOutcome::Ignorable | StraightOutcome::StateOnly => {}
            StraightOutcome::Emit(stmt) => {
                update_return_width(&stmt, return_width);
                fp_return = fp_return_after(fp_return, &stmt);
                stmts.push(stmt);
            }
        }
        idx += 1;
    }
    Err(Error::LlvmIr(
        "switch case body ran past the function without a terminator".to_owned(),
    ))
}

fn append_tail(
    body: &mut Block,
    bodies: &BTreeMap<u64, SwitchBody>,
    tail_addr: u64,
    leaders: &[u64],
) -> Result<()> {
    if leaders.contains(&tail_addr) {
        return Err(Error::LlvmIr(
            "switch tail jumps into another case (shared-body chain unsupported)".to_owned(),
        ));
    }
    let SwitchBody { stmts, term, .. } = bodies
        .get(&tail_addr)
        .ok_or_else(|| Error::LlvmIr("switch shared tail body not lifted".to_owned()))?;
    if *term != BodyTerm::Ret {
        return Err(Error::LlvmIr(
            "multi-level switch tail chains unsupported".to_owned(),
        ));
    }
    body.extend(stmts.iter().cloned().map(Node::Stmt));
    Ok(())
}

#[derive(Debug, Clone)]
struct SwitchBody {
    stmts: Vec<Stmt>,
    term: BodyTerm,
    fp_end: Option<FpWidth>,
}

fn chain_terminal_fp(
    bodies: &BTreeMap<u64, SwitchBody>,
    start: u64,
    fallthrough_next: impl Fn(u64) -> Option<u64>,
) -> Result<Option<FpWidth>> {
    let mut state: Option<FpWidth> = None;
    let mut addr: u64 = start;
    let mut visited: Vec<u64> = Vec::new();
    loop {
        if visited.contains(&addr) {
            return Err(Error::LlvmIr(
                "switch body chain loops; cannot type return".to_owned(),
            ));
        }
        visited.push(addr);
        let SwitchBody { stmts, term, .. } = bodies
            .get(&addr)
            .ok_or_else(|| Error::LlvmIr("switch body chain hit an unlifted block".to_owned()))?;
        for stmt in stmts {
            state = fp_return_after(state, stmt);
        }
        match term {
            BodyTerm::Ret => return Ok(state),
            BodyTerm::Tail(tail_addr) => {
                if let Some(next) = fallthrough_next(addr)
                    && *tail_addr == next
                {
                    addr = next;
                } else {
                    let SwitchBody {
                        stmts: tail_stmts,
                        term: tail_term,
                        ..
                    } = bodies.get(tail_addr).ok_or_else(|| {
                        Error::LlvmIr("switch tail body not lifted for return typing".to_owned())
                    })?;
                    if *tail_term != BodyTerm::Ret {
                        return Err(Error::LlvmIr(
                            "multi-level switch tail chains unsupported".to_owned(),
                        ));
                    }
                    for stmt in tail_stmts {
                        state = fp_return_after(state, stmt);
                    }
                    return Ok(state);
                }
            }
            BodyTerm::FellInto(next_addr) => addr = *next_addr,
        }
    }
}

fn rax_write_width(stmt: &Stmt) -> Option<Width> {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::SetCc { dest, .. } => (dest.reg == Reg::Rax).then_some(dest.width),
        Stmt::PackedToGpr { dest, .. } => (dest.reg == Reg::Rax).then_some(dest.width),
        Stmt::WideMul { .. } | Stmt::Call { .. } => Some(Width::W64),
        Stmt::Divide { divisor, .. } => Some(divisor.width),
        _ => None,
    }
}

fn folded_int_return_width(nodes: &[Node], incoming: Width) -> Width {
    let mut cur: Width = incoming;
    let mut result: Width = Width::W8;
    for node in nodes {
        match node {
            Node::Stmt(stmt) => {
                if let Some(w) = rax_write_width(stmt) {
                    cur = w;
                }
            }
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                let then_w: Width = folded_int_return_width(then_body, cur);
                let else_w: Width = else_body
                    .as_ref()
                    .map_or(cur, |e: &Block| folded_int_return_width(e, cur));
                cur = then_w.max(else_w);
            }
            Node::While { body, .. } | Node::DoWhile { body, .. } => {
                cur = cur.max(folded_int_return_width(body, cur));
            }
            Node::Switch { cases, default, .. } => {
                let mut widest: Width = folded_int_return_width(default, cur);
                for case in cases {
                    widest = widest.max(folded_int_return_width(&case.body, cur));
                }
                cur = cur.max(widest);
            }
            Node::Return => result = result.max(cur),
            Node::Break
            | Node::CondSnapshot { .. }
            | Node::Continue
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
    result.max(cur)
}

fn chain_terminal_int_width(
    bodies: &BTreeMap<u64, SwitchBody>,
    start: u64,
    fallthrough_next: impl Fn(u64) -> Option<u64>,
) -> Option<Width> {
    let mut width: Option<Width> = None;
    let mut addr: u64 = start;
    let mut visited: Vec<u64> = Vec::new();
    loop {
        if visited.contains(&addr) {
            return width;
        }
        visited.push(addr);
        let SwitchBody { stmts, term, .. } = bodies.get(&addr)?;
        for stmt in stmts {
            if let Some(w) = rax_write_width(stmt) {
                width = Some(w);
            }
        }
        match term {
            BodyTerm::Ret => return width,
            BodyTerm::Tail(tail_addr) => {
                if let Some(next) = fallthrough_next(addr)
                    && *tail_addr == next
                {
                    addr = next;
                } else {
                    if let Some(tail) = bodies.get(tail_addr) {
                        for stmt in &tail.stmts {
                            if let Some(w) = rax_write_width(stmt) {
                                width = Some(w);
                            }
                        }
                    }
                    return width;
                }
            }
            BodyTerm::FellInto(next_addr) => addr = *next_addr,
        }
    }
}

fn unify_fp_return(states: &[Option<FpWidth>], return_width: Width) -> Result<FnReturn> {
    let mut fp: Option<FpWidth> = None;
    let mut saw_int: bool = false;
    for state in states {
        match state {
            None => saw_int = true,
            Some(width) => match fp {
                None => fp = Some(*width),
                Some(seen) if seen == *width => {}
                Some(_) => {
                    return Err(Error::LlvmIr(
                        "switch case bodies return floats of differing widths; cannot type return"
                            .to_owned(),
                    ));
                }
            },
        }
    }
    match (fp, saw_int) {
        (Some(_), true) => Err(Error::LlvmIr(
            "switch mixes integer and floating-point returns across cases; cannot type return"
                .to_owned(),
        )),
        (Some(width), false) => Ok(FnReturn::Fp(width)),
        (None, _) => Ok(FnReturn::Int(return_width)),
    }
}

fn infer_switch_return(
    case_targets: &[u64],
    default_addr: u64,
    bodies: &BTreeMap<u64, SwitchBody>,
    leaders: &[u64],
    return_width: Width,
) -> Result<FnReturn> {
    let fast_int: bool = bodies.values().all(|b: &SwitchBody| b.fp_end.is_none());
    if fast_int {
        return Ok(FnReturn::Int(return_width));
    }
    let textual_next =
        |value: usize| -> u64 { case_targets.get(value + 1).copied().unwrap_or(default_addr) };
    let fallthrough_for = |addr: u64| -> Option<u64> {
        case_targets
            .iter()
            .position(|&t: &u64| t == addr)
            .map(|value: usize| textual_next(value))
    };
    let mut states: Vec<Option<FpWidth>> = Vec::with_capacity(case_targets.len() + 1);
    for &target in case_targets {
        states.push(chain_terminal_fp(bodies, target, fallthrough_for)?);
    }
    let default_body: &SwitchBody = bodies
        .get(&default_addr)
        .ok_or_else(|| Error::LlvmIr("default body not lifted".to_owned()))?;
    match default_body.term {
        BodyTerm::Ret => {
            let mut state: Option<FpWidth> = None;
            for stmt in &default_body.stmts {
                state = fp_return_after(state, stmt);
            }
            states.push(state);
        }
        BodyTerm::Tail(tail_addr) => {
            if leaders.contains(&tail_addr) {
                return Err(Error::LlvmIr(
                    "default tail jumps into another case (shared-body chain unsupported)"
                        .to_owned(),
                ));
            }
            states.push(chain_terminal_fp(bodies, default_addr, |_: u64| None)?);
        }
        BodyTerm::FellInto(_) => {
            return Err(Error::LlvmIr(
                "default body falls into another block; unsupported".to_owned(),
            ));
        }
    }
    unify_fp_return(&states, return_width)
}

fn update_return_width(stmt: &Stmt, return_width: &mut Width) {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::Extend { dest, .. } => {
            if dest.reg == Reg::Rax {
                *return_width = dest.width;
            }
        }
        Stmt::WideMul { .. } | Stmt::Call { .. } => *return_width = Width::W64,
        Stmt::Divide { divisor, .. } => *return_width = divisor.width,
        Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. } => {
            if dest.reg == Reg::Rax {
                *return_width = dest.width;
            }
        }
        Stmt::SetCc { dest, .. } => {
            if dest.reg == Reg::Rax {
                *return_width = dest.width;
            }
        }
        Stmt::Cond { .. }
        | Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpStore { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(_)
        | Stmt::FlagSnapshot { .. } => {}
    }
}

fn annotate_calls_block(body: &mut Block, map: &BTreeMap<u64, &ResolvedCall>, abi: Abi) {
    annotate_calls_block_with_order(body, map, abi.arg_order());
}

fn annotate_calls_block_with_order(
    body: &mut Block,
    map: &BTreeMap<u64, &ResolvedCall>,
    arg_order: &[Reg],
) {
    for node in body.iter_mut() {
        match node {
            Node::Stmt(Stmt::Call { target, args, name }) => {
                if let Some(resolved) = map.get(target) {
                    let count: usize = resolved.arg_count.min(arg_order.len());
                    *args = arg_order[..count].to_vec();
                    name.clone_from(&resolved.name);
                }
            }
            Node::Stmt(_) => {}
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                annotate_calls_block_with_order(then_body, map, arg_order);
                if let Some(else_b) = else_body {
                    annotate_calls_block_with_order(else_b, map, arg_order);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                annotate_calls_block_with_order(body, map, arg_order);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases.iter_mut() {
                    annotate_calls_block_with_order(&mut case.body, map, arg_order);
                }
                annotate_calls_block_with_order(default, map, arg_order);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn collect_call_targets(body: &Block, acc: &mut Vec<u64>) {
    for node in body {
        match node {
            Node::Stmt(Stmt::Call { target, .. }) => acc.push(*target),
            Node::Stmt(_) => {}
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_call_targets(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_call_targets(else_b, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_call_targets(body, acc);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_call_targets(&case.body, acc);
                }
                collect_call_targets(default, acc);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn is_frame_management(mnemonic: &str, operands: &str) -> bool {
    match mnemonic {
        "push" | "pop" => parse_reg(operands.trim()).is_some_and(|r: RegRef| r.width == Width::W64),
        "sub" | "add" => operands_target_rsp_with_imm(operands),
        "leave" => operands.trim().is_empty(),
        "mov" => is_stack_pointer_move(operands),
        "lea" => is_rbp_lea_frame(operands),
        _ => false,
    }
}

const MS_X64_CALLEE_SAVED_XMM: [Xmm; 10] = [
    Xmm::Xmm6,
    Xmm::Xmm7,
    Xmm::Xmm8,
    Xmm::Xmm9,
    Xmm::Xmm10,
    Xmm::Xmm11,
    Xmm::Xmm12,
    Xmm::Xmm13,
    Xmm::Xmm14,
    Xmm::Xmm15,
];

fn mem_operand_bracket(token: &str) -> Option<&str> {
    let trimmed: &str = token.trim();
    if trimmed.starts_with('[') {
        return Some(trimmed);
    }
    let (kw, rest): (&str, &str) = trimmed.split_once(char::is_whitespace)?;
    size_keyword_width(kw.trim())?;
    let rest: &str = rest.trim();
    rest.starts_with('[').then_some(rest)
}

fn is_ms_x64_callee_saved_xmm_spill(mnemonic: &str, operands: &str, abi: Abi) -> bool {
    if abi != Abi::MsX64 || !matches!(mnemonic, "movaps" | "movapd" | "movups" | "movupd") {
        return false;
    }
    let Some((lhs, rhs)): Option<(&str, &str)> = operands.split_once(',') else {
        return false;
    };
    let (lhs, rhs): (&str, &str) = (lhs.trim(), rhs.trim());
    let (mem, xmm_token): (&str, &str) = if let Some(mem) = mem_operand_bracket(lhs) {
        (mem, rhs)
    } else if let Some(mem) = mem_operand_bracket(rhs) {
        (mem, lhs)
    } else {
        return false;
    };
    let Some(xmm): Option<Xmm> = parse_xmm(xmm_token) else {
        return false;
    };
    if !MS_X64_CALLEE_SAVED_XMM.contains(&xmm) {
        return false;
    }
    let Some((base, index, _disp)): Option<AddrTerms> = parse_addr_terms(mem) else {
        return false;
    };
    index.is_none() && matches!(base, Some(Reg::Rsp | Reg::Rbp))
}

fn is_stack_pointer_move(operands: &str) -> bool {
    matches!(
        operands.split_once(','),
        Some((lhs, rhs)) if matches!((lhs.trim(), rhs.trim()), ("rbp", "rsp") | ("rsp", "rbp"))
    )
}

fn rbp_lea_displacement(operands: &str) -> Option<i64> {
    let (dest, src): (&str, &str) = operands.split_once(',')?;
    if !parse_reg(dest.trim()).is_some_and(|r: RegRef| r.reg == Reg::Rbp && r.width == Width::W64) {
        return None;
    }
    let (base, index, disp): AddrTerms = parse_addr_terms(src.trim())?;
    (base == Some(Reg::Rsp) && index.is_none()).then_some(disp)
}

fn is_rbp_lea_frame(operands: &str) -> bool {
    rbp_lea_displacement(operands).is_some()
}

fn writes_stack_pointer(insn: &DisasmInsn) -> bool {
    first_operand_is_rsp(&insn.operands)
}

fn frame_pointer_anchor(real: &[&DisasmInsn]) -> Option<FramePointerAnchor> {
    let mut delta: i64 = 0;
    let mut saved: i64 = 0;
    for insn in real {
        match insn.mnemonic.as_str() {
            "push" => {
                delta = delta.checked_sub(RETURN_ADDRESS_BYTES)?;
                saved = saved.checked_add(RETURN_ADDRESS_BYTES)?;
            }
            "mov" if is_stack_pointer_move(&insn.operands) => {
                return insn
                    .operands
                    .split_once(',')
                    .filter(|(dest, _): &(&str, &str)| dest.trim() == "rbp")
                    .and_then(|_| {
                        Some(FramePointerAnchor {
                            entry_disp: delta.checked_neg()?,
                            saved_bytes: saved,
                        })
                    });
            }
            "lea" if let Some(disp) = rbp_lea_displacement(&insn.operands) => {
                return Some(FramePointerAnchor {
                    entry_disp: delta.checked_add(disp)?.checked_neg()?,
                    saved_bytes: saved,
                });
            }
            "sub" | "add" if writes_stack_pointer(insn) => {
                let imm: i64 = rsp_delta_imm(&insn.mnemonic, &insn.operands)?;
                delta = if insn.mnemonic == "sub" {
                    delta.checked_sub(imm)?
                } else {
                    delta.checked_add(imm)?
                };
            }
            _ if writes_stack_pointer(insn) || stack_depth_changing_mnemonic(&insn.mnemonic) => {
                return None;
            }
            _ => {}
        }
    }
    None
}

fn preceding_real_insn<'a>(real: &[&'a DisasmInsn], index: usize) -> Option<&'a DisasmInsn> {
    index
        .checked_sub(1)
        .and_then(|prior: usize| real.get(prior).copied())
}

fn stack_pointer_break(real: &[&DisasmInsn], rbp_is_frame: bool) -> Option<StackPointerBreak> {
    let mut constant_allocations: usize = 0;
    let mut pushes: usize = 0;
    for (index, insn) in real.iter().enumerate() {
        let mnemonic: &str = insn.mnemonic.as_str();
        if matches!(mnemonic, "push" | "pop") {
            pushes += 1;
            continue;
        }
        if mnemonic == "lea" && writes_stack_pointer(insn) {
            return Some(StackPointerBreak::PointerArithmetic);
        }
        if !writes_stack_pointer(insn) {
            continue;
        }
        match mnemonic {
            "and" | "or" | "xor" => return Some(StackPointerBreak::Realignment),
            "sub" | "add" => {
                if rsp_delta_imm(mnemonic, &insn.operands).is_none() {
                    let probed: bool = preceding_real_insn(real, index)
                        .is_some_and(|prior: &DisasmInsn| prior.mnemonic == "call");
                    return Some(if probed {
                        StackPointerBreak::StackProbe
                    } else {
                        StackPointerBreak::VariableAllocation
                    });
                }
                if mnemonic == "sub" {
                    constant_allocations += 1;
                }
            }
            "mov" if is_stack_pointer_move(&insn.operands) && rbp_is_frame => {}
            _ => return Some(StackPointerBreak::VariableAllocation),
        }
    }
    if rbp_is_frame {
        return None;
    }
    if pushes > 0 {
        return Some(StackPointerBreak::PushBuilt);
    }
    (constant_allocations > 1).then_some(StackPointerBreak::ResizedMidBody)
}

fn rsp_delta_imm(mnemonic: &str, operands: &str) -> Option<i64> {
    if !matches!(mnemonic, "sub" | "add") {
        return None;
    }
    let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
    (lhs.trim() == "rsp")
        .then(|| parse_imm(rhs.trim()))
        .flatten()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackFrameBoundary {
    ReturnAddress { linkage_bytes: i64, home_bytes: i64 },
    EntryStackPointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackFrameExtent {
    owned_start: Option<i64>,
    private_end: i64,
    boundary: StackFrameBoundary,
}

impl StackFrameExtent {
    const fn x86(frame_bytes: i64, red_zone_below: i64, home_bytes: i64) -> Self {
        Self {
            owned_start: Some(-red_zone_below),
            private_end: frame_bytes,
            boundary: StackFrameBoundary::ReturnAddress {
                linkage_bytes: RETURN_ADDRESS_BYTES,
                home_bytes,
            },
        }
    }

    fn x86_frame_pointer(anchor: FramePointerAnchor, home_bytes: i64) -> Option<Self> {
        Some(Self {
            owned_start: None,
            private_end: anchor.entry_disp.checked_sub(anchor.saved_bytes)?,
            boundary: StackFrameBoundary::ReturnAddress {
                linkage_bytes: anchor.saved_bytes.checked_add(RETURN_ADDRESS_BYTES)?,
                home_bytes,
            },
        })
    }

    fn aarch64(frame_bytes: i64, base_to_entry: i64) -> Option<Self> {
        Some(Self {
            owned_start: Some(base_to_entry.checked_sub(frame_bytes)?),
            private_end: base_to_entry,
            boundary: StackFrameBoundary::EntryStackPointer,
        })
    }

    const fn home_bytes(self) -> i64 {
        match self.boundary {
            StackFrameBoundary::ReturnAddress { home_bytes, .. } => home_bytes,
            StackFrameBoundary::EntryStackPointer => 0,
        }
    }

    const fn linkage_bytes(self) -> i64 {
        match self.boundary {
            StackFrameBoundary::ReturnAddress { linkage_bytes, .. } => linkage_bytes,
            StackFrameBoundary::EntryStackPointer => 0,
        }
    }

    fn return_address_start(self) -> i64 {
        self.home_start().saturating_sub(RETURN_ADDRESS_BYTES)
    }

    fn home_start(self) -> i64 {
        self.private_end.saturating_add(self.linkage_bytes())
    }

    fn home_end(self) -> i64 {
        self.home_start().saturating_add(self.home_bytes())
    }

    fn owns(self, disp: i64, bytes: i64) -> bool {
        let Some(end): Option<i64> = disp.checked_add(bytes) else {
            return false;
        };
        let below: bool = self.owned_start.is_none_or(|start: i64| disp >= start);
        (below && end <= self.private_end)
            || (self.home_bytes() > 0 && disp >= self.home_start() && end <= self.home_end())
    }

    fn describe(self) -> String {
        let owned: String = self.owned_start.map_or_else(
            || format!("(-inf, {})", self.private_end),
            |start: i64| format!("[{start}, {})", self.private_end),
        );
        if self.home_bytes() == 0 {
            owned
        } else {
            format!("{owned} and [{}, {})", self.home_start(), self.home_end())
        }
    }

    fn rejection(self, disp: i64, bytes: i64) -> String {
        let owned: String = self.describe();
        match self.boundary {
            StackFrameBoundary::ReturnAddress { linkage_bytes, .. }
                if linkage_bytes > RETURN_ADDRESS_BYTES =>
            {
                format!(
                    "{bytes}-byte slot at {disp} is outside the {owned} bytes this frame owns; the saved registers sit at [{}, {}), the return address at {} and the caller owns the frame above it",
                    self.private_end,
                    self.return_address_start(),
                    self.return_address_start()
                )
            }
            StackFrameBoundary::ReturnAddress { .. } => format!(
                "{bytes}-byte slot at {disp} is outside the {owned} bytes this frame owns; the return address sits at {} and the caller owns the frame above it",
                self.return_address_start()
            ),
            StackFrameBoundary::EntryStackPointer => format!(
                "{bytes}-byte slot at {disp} is outside the {owned} bytes this frame owns; the entry stack pointer sits at {} and incoming stack arguments begin there",
                self.private_end
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FramePointerAnchor {
    entry_disp: i64,
    saved_bytes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackPointerBreak {
    VariableAllocation,
    Realignment,
    PointerArithmetic,
    ResizedMidBody,
    PushBuilt,
    StackProbe,
}

impl StackPointerBreak {
    const fn reason(self) -> &'static str {
        match self {
            Self::VariableAllocation => {
                "the stack pointer moves by a register, so the frame size is not fixed at any offset"
            }
            Self::Realignment => {
                "the stack pointer is realigned by a mask, so no offset is constant relative to entry"
            }
            Self::PointerArithmetic => {
                "the stack pointer is recomputed by an address calculation, so no offset is constant relative to entry"
            }
            Self::ResizedMidBody => {
                "the stack pointer is lowered more than once, so one offset names different bytes in different blocks"
            }
            Self::PushBuilt => {
                "the frame is built by pushes rather than one allocation, so each push shifts every offset"
            }
            Self::StackProbe => {
                "a stack-probe prologue allocates through a register, so the frame size is not fixed at any offset"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameShape {
    base: Option<Reg>,
    rbp_is_frame: bool,
    red_zone: bool,
    stack_extent: Option<StackFrameExtent>,
    stack_pointer_break: Option<StackPointerBreak>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameClass {
    FramePointer,
    AllocatedStackPointer,
    SysvRedZoneLeaf,
    NoFrame,
}

impl FrameClass {
    #[cfg(test)]
    const ALL: [Self; 4] = [
        Self::FramePointer,
        Self::AllocatedStackPointer,
        Self::SysvRedZoneLeaf,
        Self::NoFrame,
    ];

    const fn indexed_refusal(self) -> Option<&'static str> {
        match self {
            Self::SysvRedZoneLeaf => None,
            Self::FramePointer => Some(
                "an indexed frame access sits on a frame-pointer frame, where bytes inside the fixed-offset accesses may still belong to the caller, so the region is not proven to be function scratch",
            ),
            Self::AllocatedStackPointer => Some(
                "an indexed frame access sits on an allocated stack-pointer frame, where bytes inside the fixed-offset accesses may still hold the return address or an incoming argument, so the region is not proven to be function scratch",
            ),
            Self::NoFrame => Some(
                "an indexed frame access needs a provably constant frame base, and this function has none",
            ),
        }
    }
}

impl FrameShape {
    const fn class(self) -> FrameClass {
        if self.rbp_is_frame {
            FrameClass::FramePointer
        } else if self.red_zone {
            FrameClass::SysvRedZoneLeaf
        } else if self.base.is_some() {
            FrameClass::AllocatedStackPointer
        } else {
            FrameClass::NoFrame
        }
    }
}

const SYSV_RED_ZONE_BYTES: i64 = 128;
const MS_X64_HOME_BYTES: i64 = 32;
const RETURN_ADDRESS_BYTES: i64 = 8;

const fn home_space_above_return(abi: Abi) -> i64 {
    if matches!(abi, Abi::MsX64) {
        MS_X64_HOME_BYTES
    } else {
        0
    }
}

fn classify_frame(insns: &[DisasmInsn], abi: Abi) -> FrameShape {
    let real: Vec<&DisasmInsn> = insns
        .iter()
        .filter(|i: &&DisasmInsn| !matches!(i.mnemonic.as_str(), "nop" | "endbr64"))
        .collect();
    let rbp_is_frame: bool = real.iter().any(|i: &&DisasmInsn| {
        (i.mnemonic == "mov" && is_stack_pointer_move(&i.operands))
            || (i.mnemonic == "lea" && is_rbp_lea_frame(&i.operands))
    });
    let stack_pointer_break: Option<StackPointerBreak> = stack_pointer_break(&real, rbp_is_frame);
    if rbp_is_frame {
        return FrameShape {
            base: Some(Reg::Rbp),
            rbp_is_frame: true,
            red_zone: false,
            stack_extent: frame_pointer_anchor(&real).and_then(|anchor: FramePointerAnchor| {
                StackFrameExtent::x86_frame_pointer(anchor, home_space_above_return(abi))
            }),
            stack_pointer_break,
        };
    }
    if stack_pointer_break.is_none()
        && let Some(allocated) = rsp_frame_allocation(&real)
    {
        let red_zone_below: i64 =
            if abi == Abi::SysV && bytes_below_the_stack_pointer_stay_private(insns) {
                SYSV_RED_ZONE_BYTES
            } else {
                0
            };
        return FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
            red_zone: false,
            stack_extent: Some(StackFrameExtent::x86(
                allocated,
                red_zone_below,
                home_space_above_return(abi),
            )),
            stack_pointer_break,
        };
    }
    if abi == Abi::SysV && sysv_red_zone_frame(insns) {
        return FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
            red_zone: true,
            stack_extent: None,
            stack_pointer_break,
        };
    }
    FrameShape {
        base: None,
        rbp_is_frame: false,
        red_zone: false,
        stack_extent: None,
        stack_pointer_break,
    }
}

const fn stack_depth_changing_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"push"
            | b"pusha"
            | b"pushad"
            | b"pushf"
            | b"pushfd"
            | b"pushfq"
            | b"pop"
            | b"popa"
            | b"popad"
            | b"popf"
            | b"popfd"
            | b"popfq"
            | b"leave"
            | b"enter"
            | b"call"
            | b"int"
            | b"int1"
            | b"int3"
            | b"into"
            | b"iret"
            | b"iretd"
            | b"iretq"
            | b"syscall"
            | b"sysenter"
            | b"sysexit"
            | b"sysexitq"
            | b"sysret"
            | b"sysretq"
    )
}

fn first_operand_is_rsp(operands: &str) -> bool {
    operands
        .split_once(',')
        .map_or(operands, |(lhs, _): (&str, &str)| lhs)
        .trim()
        == "rsp"
}

fn red_zone_rsp_uses_are_contained(operands: &str) -> bool {
    let mut rest: &str = operands;
    let mut outside: String = String::new();
    loop {
        let Some(open): Option<usize> = rest.find('[') else {
            outside.push_str(rest);
            return !outside.contains("rsp");
        };
        outside.push_str(rest.get(..open).unwrap_or_default());
        let tail: &str = rest.get(open..).unwrap_or_default();
        let Some(close): Option<usize> = tail.find(']') else {
            return false;
        };
        let bracketed: &str = tail.get(..=close).unwrap_or_default();
        if bracketed.contains("rsp") {
            let Some((base, index, disp)): Option<AddrTerms> = parse_addr_terms(bracketed) else {
                return false;
            };
            if base != Some(Reg::Rsp)
                || index.is_some_and(|idx: IndexOperand| idx.reg == Reg::Rsp)
                || !(-SYSV_RED_ZONE_BYTES..0).contains(&disp)
            {
                return false;
            }
        }
        rest = tail.get(close + 1..).unwrap_or_default();
    }
}

fn bytes_below_the_stack_pointer_stay_private(insns: &[DisasmInsn]) -> bool {
    let Some(first): Option<&DisasmInsn> = insns.first() else {
        return false;
    };
    let Some(last): Option<&DisasmInsn> = insns.last() else {
        return false;
    };
    let start: u64 = first.address;
    let end: u64 = last
        .address
        .saturating_add(u64::try_from(last.bytes.len()).unwrap_or(u64::MAX));
    for (idx, insn) in insns.iter().enumerate() {
        if stack_depth_changing_mnemonic(&insn.mnemonic) {
            return false;
        }
        if insn.mnemonic == "jmp" {
            let Some(target): Option<u64> = parse_branch_target(&insn.operands) else {
                return false;
            };
            if !(start..end).contains(&target)
                || insns
                    .get(idx + 1)
                    .is_some_and(|next: &DisasmInsn| next.address == target)
            {
                return false;
            }
        }
    }
    true
}

fn sysv_red_zone_frame(insns: &[DisasmInsn]) -> bool {
    if !bytes_below_the_stack_pointer_stay_private(insns) {
        return false;
    }
    let mut saw_slot: bool = false;
    for insn in insns {
        if first_operand_is_rsp(&insn.operands) || !red_zone_rsp_uses_are_contained(&insn.operands)
        {
            return false;
        }
        saw_slot = saw_slot || insn.operands.contains("rsp");
    }
    saw_slot
}

fn rsp_frame_allocation(real: &[&DisasmInsn]) -> Option<i64> {
    let first: &&DisasmInsn = real.first()?;
    if first.mnemonic != "sub" {
        return None;
    }
    let alloc: i64 = rsp_delta_imm("sub", &first.operands)?;
    let stack_pointer_stays_constant: bool =
        real.iter()
            .enumerate()
            .all(
                |(idx, insn): (usize, &&DisasmInsn)| match insn.mnemonic.as_str() {
                    "push" | "pop" | "leave" => false,
                    "mov" => insn
                        .operands
                        .split_once(',')
                        .is_none_or(|(lhs, _): (&str, &str)| lhs.trim() != "rsp"),
                    "sub" if rsp_delta_imm("sub", &insn.operands).is_some() => idx == 0,
                    "add" => rsp_delta_imm("add", &insn.operands).map_or(true, |delta: i64| {
                        delta == alloc
                            && real
                                .get(idx + 1)
                                .is_some_and(|n: &&DisasmInsn| n.mnemonic == "ret")
                    }),
                    _ => true,
                },
            );
    stack_pointer_stays_constant.then_some(alloc)
}

const fn is_bare_string_op(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"movsb" | b"movsw" | b"movsq" | b"stosb" | b"stosw" | b"stosd" | b"stosq"
    )
}

fn string_elem_width(op: &str) -> Option<Width> {
    match op {
        "movsb" | "stosb" => Some(Width::W8),
        "movsw" | "stosw" => Some(Width::W16),
        "movsd" | "stosd" => Some(Width::W32),
        "movsq" | "stosq" => Some(Width::W64),
        _ => None,
    }
}

fn lift_rep_string(operands: &str, df_backward: bool) -> Option<Stmt> {
    let op: &str = operands.trim();
    if df_backward {
        return None;
    }
    if op.contains(char::is_whitespace) || op.contains(',') || op.contains('[') {
        return None;
    }
    let elem: Width = string_elem_width(op)?;
    if op.starts_with("movs") {
        Some(Stmt::BlockMove { elem })
    } else {
        Some(Stmt::BlockFill { elem })
    }
}

fn operands_target_rsp_with_imm(operands: &str) -> bool {
    let Some((lhs, rhs)): Option<(&str, &str)> = operands.split_once(',') else {
        return false;
    };
    lhs.trim() == "rsp" && parse_imm(rhs.trim()).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Structured {
    body: Block,
    lifted_split_return: bool,
    lifted_loop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ItemKind {
    Stmt(Stmt),
    Branch {
        kind: CondKind,
        flags: Flags,
        target: u64,
    },
    Jmp {
        target: u64,
    },
    Switch {
        disc: RegRef,
        cases: Vec<(i64, u64)>,
        default: u64,
    },
    Ret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    address: u64,
    kind: ItemKind,
}

fn parse_branch_target(operands: &str) -> Option<u64> {
    let trimmed: &str = operands.trim();
    let token: &str = trimmed
        .strip_prefix("short ")
        .or_else(|| trimmed.strip_prefix("near "))
        .unwrap_or(trimmed)
        .trim();
    if token.contains([' ', ',', '[']) {
        return None;
    }
    let body: &str = token.strip_suffix(['h', 'H']).unwrap_or(token);
    let body: &str = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    u64::from_str_radix(body, 16).ok()
}

fn structure_items(items: &[Item]) -> Result<Structured> {
    if items.is_empty() {
        return Err(Error::LlvmIr("no structured body".to_owned()));
    }
    let Some(ret_pos): Option<usize> = items
        .iter()
        .position(|it: &Item| matches!(it.kind, ItemKind::Ret))
    else {
        return Err(Error::LlvmIr("missing terminal ret".to_owned()));
    };
    if let Some(body) = structure_do_while(items, ret_pos)? {
        return Ok(Structured {
            body,
            lifted_split_return: false,
            lifted_loop: true,
        });
    }
    if let Some(body) = structure_guarded_while(items, ret_pos)? {
        return Ok(Structured {
            body,
            lifted_split_return: false,
            lifted_loop: true,
        });
    }
    if let Some(body) = structure_split_return(items, ret_pos)? {
        return Ok(Structured {
            body,
            lifted_split_return: true,
            lifted_loop: false,
        });
    }
    if let Some(structured) = structure_via_regions(items, false) {
        return Ok(structured);
    }
    if ret_pos + 1 == items.len()
        && let Ok(body) = structure_range(items, 0, ret_pos)
    {
        return Ok(Structured {
            body,
            lifted_split_return: false,
            lifted_loop: false,
        });
    }
    if let Some(body) = structure_reducible_cfg(items)? {
        return Ok(Structured {
            body,
            lifted_split_return: false,
            lifted_loop: true,
        });
    }
    if let Some(structured) = structure_via_regions(items, true) {
        return Ok(structured);
    }
    Err(Error::LlvmIr(
        "multiple/early returns not in forward-skip class".to_owned(),
    ))
}

fn reachable_blocks(blocks: &[CfgBlock]) -> std::collections::BTreeSet<usize> {
    let mut seen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::from([0]);
    let mut stack: Vec<usize> = vec![0];
    while let Some(block) = stack.pop() {
        for succ in blocks[block].successors() {
            if succ < blocks.len() && seen.insert(succ) {
                stack.push(succ);
            }
        }
    }
    seen
}

fn cfg_from_leaf_blocks(blocks: &[CfgBlock]) -> Option<structuring::Cfg> {
    let count: usize = blocks.len();
    let mut nodes: Vec<structuring::CfgNode> = Vec::with_capacity(count);
    for (idx, block) in blocks.iter().enumerate() {
        let pure: bool = block.stmts.is_empty();
        let term: structuring::Terminator = match &block.term {
            BlockTerm::Ret => structuring::Terminator::Return,
            BlockTerm::Jump(t) | BlockTerm::Fall(t) => {
                if *t >= count {
                    return None;
                }
                structuring::Terminator::Goto(*t as u32)
            }
            BlockTerm::Branch {
                taken, fallthrough, ..
            } => {
                if *taken >= count || *fallthrough >= count {
                    return None;
                }
                structuring::Terminator::Branch {
                    atom: idx as u32,
                    taken: *taken as u32,
                    not_taken: *fallthrough as u32,
                }
            }
        };
        nodes.push(structuring::CfgNode { term, pure });
    }
    structuring::Cfg::new(0, nodes).ok()
}

fn atom_branch(blocks: &[CfgBlock], atom: structuring::Atom) -> Option<(CondKind, Flags)> {
    match &blocks.get(atom as usize)?.term {
        BlockTerm::Branch { kind, flags, .. } => Some((*kind, flags.clone())),
        _ => None,
    }
}

fn cond_from_region(
    blocks: &[CfgBlock],
    conds: &structuring::CondPool,
    id: structuring::CondId,
) -> Option<Cond> {
    match conds.nodes().get(id as usize)? {
        structuring::Cond::Leaf(atom) => {
            let (kind, flags): (CondKind, Flags) = atom_branch(blocks, *atom)?;
            Some(Cond::leaf(kind, flags))
        }
        structuring::Cond::NotLeaf(atom) => {
            let (kind, flags): (CondKind, Flags) = atom_branch(blocks, *atom)?;
            Some(Cond::leaf(kind.negate(), flags))
        }
        structuring::Cond::And(lhs, rhs) => {
            let l: Cond = cond_from_region(blocks, conds, *lhs)?;
            let r: Cond = cond_from_region(blocks, conds, *rhs)?;
            Some(Cond::And(Box::new(l), Box::new(r)))
        }
        structuring::Cond::Or(lhs, rhs) => {
            let l: Cond = cond_from_region(blocks, conds, *lhs)?;
            let r: Cond = cond_from_region(blocks, conds, *rhs)?;
            Some(Cond::Or(Box::new(l), Box::new(r)))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkLabel {
    Return,
    Break,
    Continue,
    Goto(u32),
}

const TAIL_SPLIT_BLOCK_CAP: usize = 256;
const TAIL_SUBTREE_CAP: usize = 32;

fn private_tail_subtree(
    root: usize,
    blocks: &[CfgBlock],
    preds: &[Vec<usize>],
) -> Option<Vec<usize>> {
    if root == 0 {
        return None;
    }
    let mut order: Vec<usize> = vec![root];
    let mut seen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::from([root]);
    let mut cursor: usize = 0;
    while cursor < order.len() {
        let node: usize = order[cursor];
        cursor += 1;
        for succ in blocks[node].successors() {
            if succ == root || !seen.insert(succ) {
                return None;
            }
            order.push(succ);
            if order.len() > TAIL_SUBTREE_CAP {
                return None;
            }
        }
    }
    for &node in &order {
        if node != root && preds[node].iter().any(|p: &usize| !seen.contains(p)) {
            return None;
        }
        if blocks[node].successors().is_empty() && !matches!(blocks[node].term, BlockTerm::Ret) {
            return None;
        }
    }
    Some(order)
}

fn retarget_block(term: &mut BlockTerm, from: usize, to: usize) {
    match term {
        BlockTerm::Jump(t) | BlockTerm::Fall(t) => {
            if *t == from {
                *t = to;
            }
        }
        BlockTerm::Branch {
            taken, fallthrough, ..
        } => {
            if *taken == from {
                *taken = to;
            }
            if *fallthrough == from {
                *fallthrough = to;
            }
        }
        BlockTerm::Ret => {}
    }
}

fn split_tail_regions(
    mut blocks: Vec<CfgBlock>,
    mut labels: std::collections::BTreeMap<usize, SinkLabel>,
) -> Option<(Vec<CfgBlock>, std::collections::BTreeMap<usize, SinkLabel>)> {
    loop {
        let preds: Vec<Vec<usize>> = block_predecessors(&blocks);
        let mut chosen: Option<(usize, Vec<usize>)> = None;
        for node in 0..blocks.len() {
            if preds[node].len() < 2 {
                continue;
            }
            if let Some(subtree) = private_tail_subtree(node, &blocks, &preds) {
                chosen = Some((node, subtree));
                break;
            }
        }
        let Some((root, subtree)): Option<(usize, Vec<usize>)> = chosen else {
            return Some((blocks, labels));
        };
        let extra_preds: Vec<usize> = preds[root].iter().skip(1).copied().collect();
        for pred in extra_preds {
            let base: usize = blocks.len();
            let remap: std::collections::BTreeMap<usize, usize> = subtree
                .iter()
                .enumerate()
                .map(|(offset, &orig): (usize, &usize)| (orig, base + offset))
                .collect();
            for &orig in &subtree {
                let mut clone: CfgBlock = blocks[orig].clone();
                for (&from, &to) in &remap {
                    retarget_block(&mut clone.term, from, to);
                }
                if let Some(&label) = labels.get(&orig) {
                    labels.insert(remap[&orig], label);
                }
                blocks.push(clone);
            }
            let copy_root: usize = remap[&root];
            retarget_block(&mut blocks[pred].term, root, copy_root);
            if blocks.len() > TAIL_SPLIT_BLOCK_CAP {
                return None;
            }
        }
    }
}

struct RegionRenderer<'a> {
    blocks: &'a [CfgBlock],
    original_blocks: &'a [CfgBlock],
    result: &'a structuring::StructureResult,
    labels: &'a std::collections::BTreeMap<usize, SinkLabel>,
    forest: &'a structuring::LoopForest,
    allow_loops: bool,
    label_targets: &'a std::collections::BTreeMap<usize, u32>,
    consumed: std::collections::BTreeSet<usize>,
}

impl RegionRenderer<'_> {
    fn original_entry(&self, entry: usize) -> Option<usize> {
        let mapped: u32 = match self.result.clone_map.get(&(entry as u32)) {
            Some(&origin) => origin,
            None => entry as u32,
        };
        let original: usize = mapped as usize;
        if original < self.original_blocks.len() {
            Some(original)
        } else {
            None
        }
    }

    fn render_sink(&self, original_entry: usize, out: &mut Block) {
        match self
            .labels
            .get(&original_entry)
            .copied()
            .unwrap_or(SinkLabel::Return)
        {
            SinkLabel::Return => out.push(Node::Return),
            SinkLabel::Break => out.push(Node::Break),
            SinkLabel::Continue => out.push(Node::Continue),
            SinkLabel::Goto(id) => out.push(Node::Goto(id)),
        }
    }

    fn absorbable_sink(&self, node: usize) -> bool {
        let Some(original): Option<usize> = self.original_entry(node) else {
            return false;
        };
        !self.label_targets.contains_key(&original)
            && matches!(
                self.labels.get(&original).copied(),
                None | Some(SinkLabel::Return)
            )
    }

    fn loop_body_with_return_tails(
        &self,
        header: usize,
        body: &std::collections::BTreeSet<usize>,
    ) -> Option<std::collections::BTreeSet<usize>> {
        let cfg: structuring::Cfg = cfg_from_leaf_blocks(self.blocks)?;
        let mut nodes: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for node in body {
            nodes.insert(u32::try_from(*node).ok()?);
        }
        let extended: std::collections::BTreeSet<u32> =
            structuring::loop_body_absorbing_return_tails(
                &cfg,
                u32::try_from(header).ok()?,
                &nodes,
            )?;
        let mut absorbed: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for node in &extended {
            let index: usize = *node as usize;
            if !nodes.contains(node) && !self.absorbable_sink(index) {
                return None;
            }
            absorbed.insert(index);
        }
        Some(absorbed)
    }

    fn render_loop(&mut self, header: usize, out: &mut Block) -> bool {
        if !self.allow_loops {
            return false;
        }
        let Some(natural): Option<&structuring::NaturalLoop> = self
            .forest
            .loops
            .iter()
            .find(|l: &&structuring::NaturalLoop| l.header as usize == header)
        else {
            return false;
        };
        let mut body: std::collections::BTreeSet<usize> =
            natural.body.iter().map(|n: &u32| *n as usize).collect();
        if let Some(extended) = self.loop_body_with_return_tails(header, &body) {
            body = extended;
        }
        let mut follow: Option<usize> = None;
        for &node in &body {
            for succ in self.blocks[node].successors() {
                if !body.contains(&succ) {
                    match follow {
                        None => follow = Some(succ),
                        Some(f) if f == succ => {}
                        Some(_) => return false,
                    }
                }
            }
        }
        let mut order: Vec<usize> = vec![header];
        order.extend(body.iter().copied().filter(|n: &usize| *n != header));
        let sub_of: std::collections::BTreeMap<usize, usize> = order
            .iter()
            .enumerate()
            .map(|(idx, &node): (usize, &usize)| (node, idx))
            .collect();
        let cont_idx: usize = order.len();
        let brk_idx: usize = order.len() + 1;
        let remap = |target: usize| -> Option<usize> {
            if target == header {
                Some(cont_idx)
            } else if let Some(&idx) = sub_of.get(&target) {
                Some(idx)
            } else if Some(target) == follow {
                Some(brk_idx)
            } else {
                None
            }
        };
        let mut sub_blocks: Vec<CfgBlock> = Vec::with_capacity(order.len() + 2);
        for &node in &order {
            let term: BlockTerm = match &self.blocks[node].term {
                BlockTerm::Ret => BlockTerm::Ret,
                BlockTerm::Jump(t) | BlockTerm::Fall(t) => {
                    let Some(target): Option<usize> = remap(*t) else {
                        return false;
                    };
                    BlockTerm::Jump(target)
                }
                BlockTerm::Branch {
                    kind,
                    flags,
                    taken,
                    fallthrough,
                } => {
                    let (Some(taken), Some(fallthrough)): (Option<usize>, Option<usize>) =
                        (remap(*taken), remap(*fallthrough))
                    else {
                        return false;
                    };
                    BlockTerm::Branch {
                        kind: *kind,
                        flags: flags.clone(),
                        taken,
                        fallthrough,
                    }
                }
            };
            sub_blocks.push(CfgBlock {
                stmts: self.blocks[node].stmts.clone(),
                term,
            });
        }
        sub_blocks.push(CfgBlock {
            stmts: Vec::new(),
            term: BlockTerm::Ret,
        });
        sub_blocks.push(CfgBlock {
            stmts: Vec::new(),
            term: BlockTerm::Ret,
        });
        let mut sub_labels: std::collections::BTreeMap<usize, SinkLabel> =
            std::collections::BTreeMap::new();
        sub_labels.insert(cont_idx, SinkLabel::Continue);
        sub_labels.insert(brk_idx, SinkLabel::Break);
        for &node in &order {
            if matches!(self.blocks[node].term, BlockTerm::Ret)
                && let Some(original) = self.original_entry(node)
                && let Some(&label) = self.labels.get(&original)
            {
                sub_labels.insert(sub_of[&node], label);
            }
        }
        let mut sub_targets: std::collections::BTreeMap<usize, u32> =
            std::collections::BTreeMap::new();
        for (&node, &idx) in &sub_of {
            let Some(original): Option<usize> = self.original_entry(node) else {
                return false;
            };
            if let Some(&label) = self.label_targets.get(&original) {
                sub_targets.insert(idx, label);
            }
        }
        let Some(loop_body): Option<Block> =
            render_cfg_blocks(&sub_blocks, &sub_labels, true, &sub_targets)
        else {
            return false;
        };
        out.push(Node::While {
            body: loop_body,
            cond: None,
        });
        for node in body {
            self.consumed.insert(node);
        }
        true
    }

    fn render(&mut self, id: structuring::RegionId, out: &mut Block) -> bool {
        let region: &structuring::Region = &self.result.regions[id as usize];
        let kind: structuring::RegionKind = region.kind;
        let entry: usize = region.entry as usize;
        let cond: Option<structuring::CondId> = region.cond;
        let head: Option<structuring::RegionId> = region.head;
        let children: Vec<structuring::RegionId> = region.children.clone();
        match kind {
            structuring::RegionKind::Block if children.is_empty() => {
                if entry >= self.blocks.len() || !self.consumed.insert(entry) {
                    return false;
                }
                let Some(original): Option<usize> = self.original_entry(entry) else {
                    return false;
                };
                if let Some(&label) = self.label_targets.get(&original) {
                    out.push(Node::Label(label));
                }
                for stmt in &self.original_blocks[original].stmts {
                    out.push(Node::Stmt(stmt.clone()));
                }
                if matches!(self.blocks[entry].term, BlockTerm::Ret) {
                    self.render_sink(original, out);
                }
                true
            }
            structuring::RegionKind::Block => children
                .iter()
                .all(|&child: &structuring::RegionId| self.render(child, out)),
            structuring::RegionKind::IfThen => {
                let (Some(head), Some(cond_id), Some(&arm)) = (head, cond, children.first()) else {
                    return false;
                };
                if !self.render(head, out) {
                    return false;
                }
                let Some(cond): Option<Cond> =
                    cond_from_region(self.blocks, &self.result.conds, cond_id)
                else {
                    return false;
                };
                let mut then_body: Block = Vec::new();
                if !self.render(arm, &mut then_body) {
                    return false;
                }
                out.push(Node::If {
                    cond,
                    then_body,
                    else_body: None,
                });
                true
            }
            structuring::RegionKind::IfThenElse => {
                let (Some(head), Some(cond_id)) = (head, cond) else {
                    return false;
                };
                let [taken_id, not_taken_id]: [structuring::RegionId; 2] =
                    children.as_slice().try_into().ok().unwrap_or([u32::MAX; 2]);
                if taken_id == u32::MAX {
                    return false;
                }
                if !self.render(head, out) {
                    return false;
                }
                let fused: bool = matches!(
                    self.result.conds.nodes().get(cond_id as usize),
                    Some(structuring::Cond::And(_, _) | structuring::Cond::Or(_, _))
                );
                let Some(cond): Option<Cond> =
                    cond_from_region(self.blocks, &self.result.conds, cond_id)
                else {
                    return false;
                };
                let (guard, then_id, else_id): (
                    Cond,
                    structuring::RegionId,
                    structuring::RegionId,
                ) = if fused {
                    (cond, taken_id, not_taken_id)
                } else {
                    let Cond::Leaf { kind, flags } = cond else {
                        return false;
                    };
                    (Cond::leaf(kind.negate(), flags), not_taken_id, taken_id)
                };
                let mut then_body: Block = Vec::new();
                if !self.render(then_id, &mut then_body) {
                    return false;
                }
                let mut else_body: Block = Vec::new();
                if !self.render(else_id, &mut else_body) {
                    return false;
                }
                out.push(Node::If {
                    cond: guard,
                    then_body,
                    else_body: Some(else_body),
                });
                true
            }
            structuring::RegionKind::While
            | structuring::RegionKind::DoWhile
            | structuring::RegionKind::NaturalLoop
            | structuring::RegionKind::SelfLoop => self.render_loop(entry, out),
            structuring::RegionKind::Switch
            | structuring::RegionKind::Proper
            | structuring::RegionKind::Irreducible => false,
        }
    }
}

fn region_structuring_is_sound(
    blocks: &[CfgBlock],
    cfg: &structuring::Cfg,
    result: &structuring::StructureResult,
) -> bool {
    if result.root_kind() == Some(structuring::RegionKind::Irreducible) {
        return false;
    }
    let forest: structuring::LoopForest = structuring::loop_forest(cfg);
    if forest.irreducible {
        return false;
    }
    for natural in &forest.loops {
        if !natural.body.contains(&natural.header) {
            return false;
        }
        if natural
            .latches
            .iter()
            .any(|latch: &u32| !natural.body.contains(latch))
        {
            return false;
        }
        if let Some(parent) = natural.parent {
            let Some(outer): Option<&structuring::NaturalLoop> = forest.loops.get(parent) else {
                return false;
            };
            if !natural.body.is_subset(&outer.body) {
                return false;
            }
        }
    }
    let exit_sink: usize = blocks.len();
    for region in &result.regions {
        if region.scrutinee.is_some() && region.kind != structuring::RegionKind::Switch {
            return false;
        }
        if region
            .exits
            .iter()
            .any(|target: &u32| *target as usize > exit_sink)
        {
            return false;
        }
    }
    let Ok(pdom): core::result::Result<structuring::PostDominators, structuring::FlowError> =
        structuring::PostDominators::compute(cfg)
    else {
        return false;
    };
    let exit: u32 = pdom.exit();
    if !pdom.post_dominates(exit, 0) {
        return false;
    }
    reachable_blocks(blocks)
        .iter()
        .all(|block: &usize| pdom.immediate_post_dominator(*block as u32).is_some())
}

fn materialize_cns_blocks(
    original_blocks: &[CfgBlock],
    transformed: &structuring::Cfg,
    clone_map: &structuring::CloneMap,
) -> Option<Vec<CfgBlock>> {
    let mut blocks: Vec<CfgBlock> = Vec::with_capacity(transformed.len());
    for node in 0..transformed.len() as u32 {
        let origin: u32 = match clone_map.get(&node) {
            Some(&mapped) => mapped,
            None => node,
        };
        let source: &CfgBlock = original_blocks.get(origin as usize)?;
        let transformed_node: &structuring::CfgNode = transformed.node(node)?;
        let term: BlockTerm = match (&source.term, &transformed_node.term) {
            (BlockTerm::Ret, structuring::Terminator::Return) => BlockTerm::Ret,
            (BlockTerm::Jump(_), structuring::Terminator::Goto(target)) => {
                BlockTerm::Jump(*target as usize)
            }
            (BlockTerm::Fall(_), structuring::Terminator::Goto(target)) => {
                BlockTerm::Fall(*target as usize)
            }
            (
                BlockTerm::Branch { kind, flags, .. },
                structuring::Terminator::Branch {
                    atom,
                    taken,
                    not_taken,
                },
            ) if *atom == origin => BlockTerm::Branch {
                kind: *kind,
                flags: flags.clone(),
                taken: *taken as usize,
                fallthrough: *not_taken as usize,
            },
            _ => return None,
        };
        blocks.push(CfgBlock {
            stmts: source.stmts.clone(),
            term,
        });
    }
    Some(blocks)
}

fn render_cfg_blocks_via_cns(
    blocks: &[CfgBlock],
    labels: &std::collections::BTreeMap<usize, SinkLabel>,
    allow_loops: bool,
    label_targets: &std::collections::BTreeMap<usize, u32>,
) -> Option<Block> {
    let original_cfg: structuring::Cfg = cfg_from_leaf_blocks(blocks)?;
    let budget: structuring::CnsBudget = structuring::CnsBudget::tight_for(&original_cfg);
    let outcome: structuring::CnsOutcome = structuring::structure_with_cns(&original_cfg, budget)?;
    if outcome.result.clone_map.is_empty() {
        return None;
    }
    let transformed_blocks: Vec<CfgBlock> =
        materialize_cns_blocks(blocks, &outcome.cfg, &outcome.result.clone_map)?;
    if !region_structuring_is_sound(&transformed_blocks, &outcome.cfg, &outcome.result) {
        return None;
    }
    let forest: structuring::LoopForest = structuring::loop_forest(&outcome.cfg);
    let root: structuring::RegionId = outcome.result.root?;
    let mut renderer: RegionRenderer<'_> = RegionRenderer {
        blocks: &transformed_blocks,
        original_blocks: blocks,
        result: &outcome.result,
        labels,
        forest: &forest,
        allow_loops,
        label_targets,
        consumed: std::collections::BTreeSet::new(),
    };
    let mut body: Block = Vec::new();
    if !renderer.render(root, &mut body)
        || renderer.consumed != reachable_blocks(&transformed_blocks)
    {
        return None;
    }
    Some(body)
}

fn render_cfg_blocks_once(
    blocks: &[CfgBlock],
    labels: &std::collections::BTreeMap<usize, SinkLabel>,
    allow_loops: bool,
    label_targets: &std::collections::BTreeMap<usize, u32>,
    original_blocks: &[CfgBlock],
    residual: &std::collections::BTreeMap<usize, usize>,
) -> Option<Block> {
    let cfg: structuring::Cfg = cfg_from_leaf_blocks(blocks)?;
    let result: structuring::StructureResult = structuring::structure(&cfg);
    if !result.is_complete() {
        return None;
    }
    if !region_structuring_is_sound(blocks, &cfg, &result) {
        return None;
    }
    let original_cfg: structuring::Cfg = cfg_from_leaf_blocks(original_blocks)?;
    let residual_nodes: std::collections::BTreeMap<u32, u32> = residual
        .iter()
        .map(|(stub, target): (&usize, &usize)| (*stub as u32, *target as u32))
        .collect();
    if !structuring::relowered_matches_original(&original_cfg, &cfg, &residual_nodes) {
        return None;
    }
    let forest: structuring::LoopForest = structuring::loop_forest(&cfg);
    let root: structuring::RegionId = result.root?;
    let mut renderer: RegionRenderer<'_> = RegionRenderer {
        blocks,
        original_blocks: blocks,
        result: &result,
        labels,
        forest: &forest,
        allow_loops,
        label_targets,
        consumed: std::collections::BTreeSet::new(),
    };
    let mut body: Block = Vec::new();
    if !renderer.render(root, &mut body) {
        return None;
    }
    if renderer.consumed != reachable_blocks(blocks) {
        return None;
    }
    Some(body)
}

fn render_cfg_blocks(
    blocks: &[CfgBlock],
    labels: &std::collections::BTreeMap<usize, SinkLabel>,
    allow_loops: bool,
    label_targets: &std::collections::BTreeMap<usize, u32>,
) -> Option<Block> {
    let no_residual: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    if let Some(body) = render_cfg_blocks_once(
        blocks,
        labels,
        allow_loops,
        label_targets,
        blocks,
        &no_residual,
    ) {
        return Some(body);
    }
    let original_cfg: structuring::Cfg = cfg_from_leaf_blocks(blocks)?;
    let has_multi_entry_irreducible: bool =
        !structuring::multi_entry_irreducible_sccs(&original_cfg).is_empty();
    if has_multi_entry_irreducible {
        return render_cfg_blocks_via_cns(blocks, labels, allow_loops, label_targets);
    }
    let expanded: Option<(Vec<CfgBlock>, std::collections::BTreeMap<usize, SinkLabel>)> =
        split_tail_regions(blocks.to_vec(), labels.clone()).filter(
            |(eblocks, _): &(Vec<CfgBlock>, std::collections::BTreeMap<usize, SinkLabel>)| {
                eblocks.len() != blocks.len()
            },
        );
    if let Some((eblocks, elabels)) = expanded.as_ref()
        && let Some(body) = render_cfg_blocks_once(
            eblocks,
            elabels,
            allow_loops,
            label_targets,
            eblocks,
            &no_residual,
        )
    {
        return Some(body);
    }
    for plan in irreducible_lowering_candidates(blocks, labels) {
        let mut merged: std::collections::BTreeMap<usize, u32> = label_targets.clone();
        merged.extend(
            plan.label_targets
                .iter()
                .map(|(k, v): (&usize, &u32)| (*k, *v)),
        );
        if let Some(body) = render_cfg_blocks_once(
            &plan.blocks,
            &plan.labels,
            allow_loops,
            &merged,
            blocks,
            &plan.residual,
        ) {
            return Some(body);
        }
    }
    let mut sources: Vec<(&[CfgBlock], &std::collections::BTreeMap<usize, SinkLabel>)> =
        vec![(blocks, labels)];
    if let Some((eblocks, elabels)) = expanded.as_ref() {
        sources.push((eblocks.as_slice(), elabels));
    }
    for (source, source_labels) in sources {
        for plan in forward_join_lowering_candidates(source, source_labels) {
            let mut merged: std::collections::BTreeMap<usize, u32> = label_targets.clone();
            merged.extend(
                plan.label_targets
                    .iter()
                    .map(|(k, v): (&usize, &u32)| (*k, *v)),
            );
            if let Some(body) = render_cfg_blocks_once(
                &plan.blocks,
                &plan.labels,
                allow_loops,
                &merged,
                source,
                &plan.residual,
            ) {
                return Some(body);
            }
        }
    }
    None
}

struct IrreduciblePlan {
    blocks: Vec<CfgBlock>,
    labels: std::collections::BTreeMap<usize, SinkLabel>,
    label_targets: std::collections::BTreeMap<usize, u32>,
    residual: std::collections::BTreeMap<usize, usize>,
}

fn irreducible_lowering_candidates(
    blocks: &[CfgBlock],
    labels: &std::collections::BTreeMap<usize, SinkLabel>,
) -> Vec<IrreduciblePlan> {
    let Some(cfg): Option<structuring::Cfg> = cfg_from_leaf_blocks(blocks) else {
        return Vec::new();
    };
    let sccs: Vec<structuring::IrreducibleEntry> = structuring::multi_entry_irreducible_sccs(&cfg);
    if sccs.len() != 1 {
        return Vec::new();
    }
    let scc: &structuring::IrreducibleEntry = &sccs[0];
    let candidate_headers: Vec<u32> = if scc.members.contains(&0) {
        if scc.entries.contains(&0) {
            vec![0]
        } else {
            return Vec::new();
        }
    } else {
        scc.entries.clone()
    };
    let mut plans: Vec<IrreduciblePlan> = Vec::new();
    for header in candidate_headers {
        let mut tblocks: Vec<CfgBlock> = blocks.to_vec();
        let mut tlabels: std::collections::BTreeMap<usize, SinkLabel> = labels.clone();
        let mut label_targets: std::collections::BTreeMap<usize, u32> =
            std::collections::BTreeMap::new();
        let mut residual: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();
        let mut stub_of: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();
        for &(pred, target) in &scc.external_edges {
            if target == header {
                continue;
            }
            let target_idx: usize = target as usize;
            let stub: usize = match stub_of.get(&target_idx) {
                Some(&existing) => existing,
                None => {
                    let id: usize = tblocks.len();
                    tblocks.push(CfgBlock {
                        stmts: Vec::new(),
                        term: BlockTerm::Ret,
                    });
                    tlabels.insert(id, SinkLabel::Goto(target));
                    label_targets.insert(target_idx, target);
                    residual.insert(id, target_idx);
                    stub_of.insert(target_idx, id);
                    id
                }
            };
            retarget_block(&mut tblocks[pred as usize].term, target_idx, stub);
        }
        if !residual.is_empty() {
            plans.push(IrreduciblePlan {
                blocks: tblocks,
                labels: tlabels,
                label_targets,
                residual,
            });
        }
    }
    plans
}

const FORWARD_JOIN_PLAN_CAP: usize = 32;

fn forward_join_lowering_candidates(
    blocks: &[CfgBlock],
    labels: &std::collections::BTreeMap<usize, SinkLabel>,
) -> Vec<IrreduciblePlan> {
    let Some(cfg): Option<structuring::Cfg> = cfg_from_leaf_blocks(blocks) else {
        return Vec::new();
    };
    if !structuring::multi_entry_irreducible_sccs(&cfg).is_empty() {
        return Vec::new();
    }
    let reachable: std::collections::BTreeSet<usize> = reachable_blocks(blocks);
    let Some(dominance): Option<structuring::FlowGraph<usize>> = block_flow(blocks) else {
        return Vec::new();
    };
    let preds: Vec<Vec<usize>> = block_predecessors(blocks);
    let mut plans: Vec<IrreduciblePlan> = Vec::new();
    for join in reachable.iter().copied() {
        if join == 0 || labels.contains_key(&join) || blocks[join].successors().is_empty() {
            continue;
        }
        let entering: Vec<usize> = preds[join]
            .iter()
            .copied()
            .filter(|pred: &usize| reachable.contains(pred))
            .collect();
        if entering.len() < 2
            || entering
                .iter()
                .any(|pred: &usize| dominance.dominates(join, *pred))
        {
            continue;
        }
        let Ok(label): core::result::Result<u32, core::num::TryFromIntError> = u32::try_from(join)
        else {
            continue;
        };
        for keep in entering.iter().rev().copied() {
            if plans.len() == FORWARD_JOIN_PLAN_CAP {
                return plans;
            }
            let mut plan_blocks: Vec<CfgBlock> = blocks.to_vec();
            let mut plan_labels: std::collections::BTreeMap<usize, SinkLabel> = labels.clone();
            let mut residual: std::collections::BTreeMap<usize, usize> =
                std::collections::BTreeMap::new();
            for pred in entering
                .iter()
                .copied()
                .filter(|pred: &usize| *pred != keep)
            {
                let stub: usize = plan_blocks.len();
                plan_blocks.push(CfgBlock {
                    stmts: Vec::new(),
                    term: BlockTerm::Ret,
                });
                plan_labels.insert(stub, SinkLabel::Goto(label));
                residual.insert(stub, join);
                retarget_block(&mut plan_blocks[pred].term, join, stub);
            }
            plans.push(IrreduciblePlan {
                blocks: plan_blocks,
                labels: plan_labels,
                label_targets: std::collections::BTreeMap::from([(join, label)]),
                residual,
            });
        }
    }
    plans
}

fn structure_via_regions(items: &[Item], allow_loops: bool) -> Option<Structured> {
    let blocks: Vec<CfgBlock> = build_blocks(items)?;
    let labels: std::collections::BTreeMap<usize, SinkLabel> = std::collections::BTreeMap::new();
    let targets: std::collections::BTreeMap<usize, u32> = std::collections::BTreeMap::new();
    let mut body: Block = render_cfg_blocks(&blocks, &labels, allow_loops, &targets)?;
    if matches!(body.last(), Some(Node::Return)) {
        body.pop();
    }
    let lifted_loop: bool = loop_count(&body) > 0;
    Some(Structured {
        body,
        lifted_split_return: false,
        lifted_loop,
    })
}

fn flags_are_comparison(flags: &Flags) -> bool {
    matches!(
        flags,
        Flags::Cmp { .. }
            | Flags::Add { .. }
            | Flags::CmpMem { .. }
            | Flags::Test { .. }
            | Flags::TestImm { .. }
            | Flags::FpCmp { .. }
            | Flags::CondCmp { .. }
    )
}

fn flag_operand_regs(flags: &Flags) -> Vec<Reg> {
    match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            let mut regs: Vec<Reg> = vec![lhs.reg];
            source_regs(rhs, &mut regs);
            regs
        }
        Flags::CmpMem { lhs, rhs } => {
            let mut regs: Vec<Reg> = Vec::new();
            mem_regs(lhs, &mut regs);
            source_regs(rhs, &mut regs);
            regs
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => vec![operand.reg],
        Flags::Sign { result } => vec![result.reg],
        Flags::FpCmp { rhs, .. } => {
            let mut regs: Vec<Reg> = Vec::new();
            if let FpOperand::Mem(mem) = rhs {
                mem_regs(mem, &mut regs);
            }
            regs
        }
        Flags::Snapshot { .. } => Vec::new(),
        Flags::CondCmp { prior, taken, .. } => {
            let mut regs: Vec<Reg> = flag_operand_regs(prior);
            regs.extend(flag_operand_regs(taken));
            regs
        }
    }
}

fn flag_operand_mems(flags: &Flags) -> Vec<MemRef> {
    let mut mems: Vec<MemRef> = Vec::new();
    collect_flag_mems(flags, &mut mems);
    mems
}

fn collect_flag_mems(flags: &Flags, out: &mut Vec<MemRef>) {
    match flags {
        Flags::Cmp { rhs, .. } | Flags::Add { rhs, .. } => {
            if let Source::Mem(mem) = rhs {
                out.push(*mem);
            }
        }
        Flags::CmpMem { lhs, rhs } => {
            out.push(*lhs);
            if let Source::Mem(mem) = rhs {
                out.push(*mem);
            }
        }
        Flags::FpCmp { rhs, .. } => {
            if let FpOperand::Mem(mem) = rhs {
                out.push(*mem);
            }
        }
        Flags::CondCmp { prior, taken, .. } => {
            collect_flag_mems(prior, out);
            collect_flag_mems(taken, out);
        }
        Flags::Test { .. }
        | Flags::TestImm { .. }
        | Flags::Sign { .. }
        | Flags::Snapshot { .. } => {}
    }
}

fn stmt_writes_aliasing_mem(stmt: &Stmt, mems: &[MemRef]) -> bool {
    match stmt {
        Stmt::Store { addr, .. } | Stmt::MemRmw { addr, .. } => mems
            .iter()
            .any(|compared: &MemRef| may_alias(addr, compared)),
        Stmt::FpStore { .. }
        | Stmt::Vector(VecStmt::Store { .. })
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Call { .. } => true,
        Stmt::Vector(
            VecStmt::Load { .. }
            | VecStmt::Bin { .. }
            | VecStmt::Dup { .. }
            | VecStmt::LaneInsert { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::ExtractToGpr { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. },
        )
        | Stmt::Assign { .. }
        | Stmt::BinAssign { .. }
        | Stmt::UnAssign { .. }
        | Stmt::Cond { .. }
        | Stmt::SetCc { .. }
        | Stmt::Extend { .. }
        | Stmt::MulImm { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpToInt { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Packed { .. }
        | Stmt::PackedToGpr { .. } => false,
    }
}

fn may_alias(store: &MemRef, compared: &MemRef) -> bool {
    let store_const: bool = store.base.is_none() && store.index.is_none();
    let compared_const: bool = compared.base.is_none() && compared.index.is_none();
    if store_const != compared_const {
        return true;
    }
    if !store_const && (store.base != compared.base || store.index != compared.index) {
        return true;
    }
    mem_ranges_overlap(store.disp, store.width, compared.disp, compared.width)
}

fn mem_ranges_overlap(disp_a: i64, width_a: Width, disp_b: i64, width_b: Width) -> bool {
    let (Some(end_a), Some(end_b)): (Option<i64>, Option<i64>) = (
        disp_a.checked_add(i64::from(width_a.bits() / 8)),
        disp_b.checked_add(i64::from(width_b.bits() / 8)),
    ) else {
        return true;
    };
    end_a > disp_b && end_b > disp_a
}

fn flag_operand_xmms(flags: &Flags) -> Vec<Xmm> {
    match flags {
        Flags::FpCmp { lhs, rhs, .. } => {
            let mut regs: Vec<Xmm> = vec![*lhs];
            if let FpOperand::Xmm(x) = rhs {
                regs.push(*x);
            }
            regs
        }
        Flags::CondCmp { prior, taken, .. } => {
            let mut regs: Vec<Xmm> = flag_operand_xmms(prior);
            regs.extend(flag_operand_xmms(taken));
            regs
        }
        Flags::Cmp { .. }
        | Flags::Add { .. }
        | Flags::Test { .. }
        | Flags::TestImm { .. }
        | Flags::Sign { .. }
        | Flags::CmpMem { .. }
        | Flags::Snapshot { .. } => Vec::new(),
    }
}

fn stmt_clobbers_flag_fp(stmt: &Stmt, deps: &[Xmm]) -> bool {
    match stmt {
        Stmt::FpBin { dest, .. }
        | Stmt::FpMov { dest, .. }
        | Stmt::IntToFp { dest, .. }
        | Stmt::FpConvert { dest, .. }
        | Stmt::FpMinMax { dest, .. }
        | Stmt::FpFma { dest, .. }
        | Stmt::FpCsel { dest, .. }
        | Stmt::FpSqrt { dest, .. }
        | Stmt::FpUnary { dest, .. }
        | Stmt::FpRound { dest, .. }
        | Stmt::GprToXmm { dest, .. } => deps.contains(dest),
        Stmt::Vector(_) | Stmt::Packed { .. } => true,
        Stmt::Assign { .. }
        | Stmt::BinAssign { .. }
        | Stmt::UnAssign { .. }
        | Stmt::Cond { .. }
        | Stmt::SetCc { .. }
        | Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::Extend { .. }
        | Stmt::MulImm { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::FpStore { .. }
        | Stmt::FpToInt { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Call { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::PackedToGpr { .. } => false,
    }
}

fn source_regs(src: &Source, acc: &mut Vec<Reg>) {
    match src {
        Source::Reg(r) => acc.push(r.reg),
        Source::Imm(_) => {}
        Source::Lea { base, index, .. } => {
            if let Some(b) = base {
                acc.push(*b);
            }
            if let Some(idx) = index {
                acc.push(idx.reg);
            }
        }
        Source::Mem(mem) => mem_regs(mem, acc),
    }
}

fn mem_regs(mem: &MemRef, acc: &mut Vec<Reg>) {
    if let Some(b) = mem.base {
        acc.push(b);
    }
    if let Some(idx) = mem.index {
        acc.push(idx.reg);
    }
}

fn trailing_latch_copy_dests(body: &Block) -> Vec<Reg> {
    let mut dests: Vec<Reg> = Vec::new();
    for node in body.iter().rev() {
        match node {
            Node::Stmt(Stmt::Assign {
                dest,
                src: Source::Reg(_),
            }) => dests.push(dest.reg),
            _ => break,
        }
    }
    dests
}

fn make_loop_cond(
    body: Block,
    cond: CondKind,
    flags: Flags,
    next_var: &mut u32,
) -> (Block, LoopCond) {
    if !flags_are_comparison(&flags) {
        return (body, LoopCond::Direct { cond, flags });
    }
    let latch_dests: Vec<Reg> = trailing_latch_copy_dests(&body);
    if latch_dests.is_empty() {
        return (body, LoopCond::Direct { cond, flags });
    }
    let operands: Vec<Reg> = flag_operand_regs(&flags);
    if !operands.iter().any(|r: &Reg| latch_dests.contains(r)) {
        return (body, LoopCond::Direct { cond, flags });
    }
    let split: usize = body.len() - latch_dests.len();
    let var: u32 = *next_var;
    *next_var += 1;
    let mut rewritten: Block = body;
    rewritten.insert(split, Node::CondSnapshot { var, cond, flags });
    (rewritten, LoopCond::Snapshot { var })
}

fn structure_do_while(items: &[Item], ret_pos: usize) -> Result<Option<Block>> {
    if items
        .iter()
        .filter(|it: &&Item| matches!(it.kind, ItemKind::Ret))
        .count()
        != 1
        || ret_pos + 1 != items.len()
    {
        return Ok(None);
    }
    if items
        .iter()
        .any(|it: &Item| matches!(it.kind, ItemKind::Jmp { .. }))
    {
        return Ok(None);
    }
    let branch_positions: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(p, it): (usize, &Item)| match it.kind {
            ItemKind::Branch { .. } => Some(p),
            _ => None,
        })
        .collect();
    let &[back_pos]: &[usize] = branch_positions.as_slice() else {
        return Ok(None);
    };
    let ItemKind::Branch {
        kind,
        ref flags,
        target,
    } = items[back_pos].kind
    else {
        return Ok(None);
    };
    let Some(entry_pos): Option<usize> = item_pos(items, target) else {
        return Ok(None);
    };
    if entry_pos > back_pos {
        return Ok(None);
    }
    if back_pos >= ret_pos {
        return Ok(None);
    }
    let preheader: Block = structure_range(items, 0, entry_pos)?;
    let loop_body: Block = structure_range(items, entry_pos, back_pos)?;
    let tail: Block = structure_range(items, back_pos + 1, ret_pos)?;
    let mut next_var: u32 = 0;
    let (loop_body, loop_cond): (Block, LoopCond) =
        make_loop_cond(loop_body, kind, flags.clone(), &mut next_var);
    let mut body: Block = preheader;
    body.push(Node::DoWhile {
        body: loop_body,
        cond: loop_cond,
    });
    body.extend(tail);
    Ok(Some(body))
}

fn structure_guarded_while(items: &[Item], ret_pos: usize) -> Result<Option<Block>> {
    if ret_pos + 1 != items.len() {
        return Ok(None);
    }
    if items
        .iter()
        .any(|it: &Item| matches!(it.kind, ItemKind::Jmp { .. }))
    {
        return Ok(None);
    }
    let branch_positions: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(p, it): (usize, &Item)| match it.kind {
            ItemKind::Branch { .. } => Some(p),
            _ => None,
        })
        .collect();
    let &[first_pos, second_pos]: &[usize] = branch_positions.as_slice() else {
        return Ok(None);
    };
    let ItemKind::Branch {
        kind: back_kind,
        flags: ref back_flags,
        target: back_target,
    } = items[second_pos].kind
    else {
        return Ok(None);
    };
    let Some(entry_pos): Option<usize> = item_pos(items, back_target) else {
        return Ok(None);
    };
    if entry_pos > second_pos || entry_pos <= first_pos {
        return Ok(None);
    }
    if second_pos >= ret_pos {
        return Ok(None);
    }
    let ItemKind::Branch {
        kind: guard_kind,
        flags: ref guard_flags,
        target: guard_target,
    } = items[first_pos].kind
    else {
        return Ok(None);
    };
    let Some(guard_target_pos): Option<usize> = item_pos(items, guard_target) else {
        return Ok(None);
    };
    if guard_target_pos != second_pos + 1 {
        return Ok(None);
    }
    let preheader: Block = structure_range(items, 0, first_pos)?;
    let pre_loop: Block = structure_range(items, first_pos + 1, entry_pos)?;
    let loop_body: Block = structure_range(items, entry_pos, second_pos)?;
    let tail: Block = structure_range(items, second_pos + 1, ret_pos)?;
    let mut next_var: u32 = 0;
    let (loop_body, loop_cond): (Block, LoopCond) =
        make_loop_cond(loop_body, back_kind, back_flags.clone(), &mut next_var);
    let mut then_body: Block = pre_loop;
    then_body.push(Node::DoWhile {
        body: loop_body,
        cond: loop_cond,
    });
    let mut body: Block = preheader;
    body.push(Node::If {
        cond: Cond::leaf(guard_kind.negate(), guard_flags.clone()),
        then_body,
        else_body: None,
    });
    body.extend(tail);
    Ok(Some(body))
}

fn structure_split_return(items: &[Item], ret_pos: usize) -> Result<Option<Block>> {
    if items
        .iter()
        .filter(|it: &&Item| matches!(it.kind, ItemKind::Ret))
        .count()
        != 1
    {
        return Ok(None);
    }
    let ret_addr: u64 = items[ret_pos].address;
    let Some(tail): Option<&Item> = items.last() else {
        return Ok(None);
    };
    let ItemKind::Jmp {
        target: tail_target,
    } = tail.kind
    else {
        return Ok(None);
    };
    if tail_target != ret_addr {
        return Ok(None);
    }
    let branch_positions: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(p, it): (usize, &Item)| match it.kind {
            ItemKind::Branch { .. } => Some(p),
            _ => None,
        })
        .collect();
    let &[guard_pos]: &[usize] = branch_positions.as_slice() else {
        return Ok(None);
    };
    if guard_pos >= ret_pos {
        return Ok(None);
    }
    let jmp_count: usize = items
        .iter()
        .filter(|it: &&Item| matches!(it.kind, ItemKind::Jmp { .. }))
        .count();
    if jmp_count != 1 {
        return Ok(None);
    }
    let ItemKind::Branch {
        kind,
        ref flags,
        target,
    } = items[guard_pos].kind
    else {
        return Ok(None);
    };
    let ool_start_addr: u64 = items[ret_pos + 1].address;
    if target != ool_start_addr {
        return Ok(None);
    }
    let mut head: Block = structure_range(items, 0, guard_pos)?;
    let fall_through: Block = structure_range(items, guard_pos + 1, ret_pos)?;
    let ool_body: Block = structure_range(items, ret_pos + 1, items.len() - 1)?;
    head.push(Node::If {
        cond: Cond::leaf(kind.negate(), flags.clone()),
        then_body: fall_through,
        else_body: Some(ool_body),
    });
    Ok(Some(head))
}

#[derive(Debug, Clone)]
enum BlockTerm {
    Ret,
    Jump(usize),
    Branch {
        kind: CondKind,
        flags: Flags,
        taken: usize,
        fallthrough: usize,
    },
    Fall(usize),
}

#[derive(Debug, Clone)]
struct CfgBlock {
    stmts: Vec<Stmt>,
    term: BlockTerm,
}

impl CfgBlock {
    fn successors(&self) -> Vec<usize> {
        match &self.term {
            BlockTerm::Ret => Vec::new(),
            BlockTerm::Jump(t) | BlockTerm::Fall(t) => vec![*t],
            BlockTerm::Branch {
                taken, fallthrough, ..
            } => vec![*taken, *fallthrough],
        }
    }
}

fn build_blocks(items: &[Item]) -> Option<Vec<CfgBlock>> {
    let addr_to_idx: BTreeMap<u64, usize> = items
        .iter()
        .enumerate()
        .map(|(i, it): (usize, &Item)| (it.address, i))
        .collect();
    let resolve = |target: u64| -> Option<usize> {
        addr_to_idx
            .range(target..)
            .next()
            .map(|(_, idx): (&u64, &usize)| *idx)
    };

    let mut is_leader: Vec<bool> = vec![false; items.len()];
    is_leader[0] = true;
    for (i, it) in items.iter().enumerate() {
        match &it.kind {
            ItemKind::Branch { target, .. } => {
                let t: usize = resolve(*target)?;
                is_leader[t] = true;
                if i + 1 < items.len() {
                    is_leader[i + 1] = true;
                }
            }
            ItemKind::Jmp { target } => {
                let t: usize = resolve(*target)?;
                is_leader[t] = true;
                if i + 1 < items.len() {
                    is_leader[i + 1] = true;
                }
            }
            ItemKind::Ret => {
                if i + 1 < items.len() {
                    is_leader[i + 1] = true;
                }
            }
            ItemKind::Stmt(_) => {}
            ItemKind::Switch { .. } => return None,
        }
    }

    let leaders: Vec<usize> = (0..items.len()).filter(|&i: &usize| is_leader[i]).collect();
    let leader_block: BTreeMap<usize, usize> = leaders
        .iter()
        .enumerate()
        .map(|(b, &i): (usize, &usize)| (i, b))
        .collect();
    let item_block = |item_idx: usize| -> usize {
        let mut b: usize = 0;
        for (k, &leader) in leaders.iter().enumerate() {
            if leader <= item_idx {
                b = k;
            } else {
                break;
            }
        }
        b
    };

    let mut blocks: Vec<CfgBlock> = Vec::with_capacity(leaders.len());
    for (b, &start) in leaders.iter().enumerate() {
        let end: usize = leaders.get(b + 1).copied().unwrap_or(items.len());
        let mut stmts: Vec<Stmt> = Vec::new();
        let mut term: Option<BlockTerm> = None;
        for it in &items[start..end] {
            match &it.kind {
                ItemKind::Stmt(stmt) => stmts.push(stmt.clone()),
                ItemKind::Ret => term = Some(BlockTerm::Ret),
                ItemKind::Jmp { target } => {
                    term = Some(BlockTerm::Jump(item_block(resolve(*target)?)));
                }
                ItemKind::Branch {
                    kind,
                    flags,
                    target,
                } => {
                    let taken: usize = item_block(resolve(*target)?);
                    let fallthrough: usize = b + 1;
                    if fallthrough >= leaders.len() {
                        return None;
                    }
                    term = Some(BlockTerm::Branch {
                        kind: *kind,
                        flags: flags.clone(),
                        taken,
                        fallthrough,
                    });
                }
                ItemKind::Switch { .. } => return None,
            }
        }
        let term: BlockTerm = term.unwrap_or_else(|| BlockTerm::Fall(b + 1));
        let term: BlockTerm = match term {
            BlockTerm::Fall(next) if next >= leaders.len() => return None,
            other => other,
        };
        let _ = &leader_block;
        blocks.push(CfgBlock { stmts, term });
    }
    Some(blocks)
}

fn block_predecessors(blocks: &[CfgBlock]) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (from, block) in blocks.iter().enumerate() {
        for succ in block.successors() {
            if succ < blocks.len() && !preds[succ].contains(&from) {
                preds[succ].push(from);
            }
        }
    }
    preds
}

fn block_flow(blocks: &[CfgBlock]) -> Option<structuring::FlowGraph<usize>> {
    structuring::FlowGraph::build(
        0..blocks.len(),
        0,
        |node: usize, emit: &mut dyn FnMut(structuring::Flow<usize>)| {
            let Some(block): Option<&CfgBlock> = blocks.get(node) else {
                return;
            };
            let targets: Vec<usize> = block.successors();
            if targets.is_empty() {
                emit(structuring::Flow::Exit);
            }
            for target in targets {
                emit(structuring::Flow::To(target));
            }
        },
    )
    .ok()
}

#[derive(Debug, Clone)]
struct LoopInfo {
    header: usize,
    body: std::collections::BTreeSet<usize>,
    exit_targets: std::collections::BTreeSet<usize>,
    follow: usize,
    parent: Option<usize>,
}

fn resolve_trampoline(
    blocks: &[CfgBlock],
    body: &std::collections::BTreeSet<usize>,
    start: usize,
) -> Option<usize> {
    use std::collections::BTreeSet;
    let mut current: usize = start;
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    loop {
        if body.contains(&current) || !seen.insert(current) {
            return None;
        }
        let block: &CfgBlock = blocks.get(current)?;
        if !block.stmts.is_empty() {
            return Some(current);
        }
        match &block.term {
            BlockTerm::Jump(t) | BlockTerm::Fall(t) => current = *t,
            _ => return Some(current),
        }
    }
}

fn resolve_loop_follow(
    blocks: &[CfgBlock],
    body: &std::collections::BTreeSet<usize>,
    exits: &std::collections::BTreeSet<usize>,
) -> Option<usize> {
    if exits.len() == 1 {
        return exits.iter().next().copied();
    }
    let mut follow: Option<usize> = None;
    for &exit in exits {
        let resolved: usize = resolve_trampoline(blocks, body, exit)?;
        match follow {
            None => follow = Some(resolved),
            Some(f) if f == resolved => {}
            Some(_) => return None,
        }
    }
    follow
}

fn detect_loop_forest(
    blocks: &[CfgBlock],
    preds: &[Vec<usize>],
    flow: &structuring::FlowGraph<usize>,
) -> Option<Vec<LoopInfo>> {
    use std::collections::BTreeSet;
    let back_edges: Vec<(usize, usize)> = flow.back_edges();
    if back_edges.is_empty() {
        return Some(Vec::new());
    }

    let mut by_header: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for &(_, header) in &back_edges {
        *by_header.entry(header).or_insert(0) += 1;
    }
    if by_header.values().any(|count: &usize| *count != 1) {
        return None;
    }

    let mut loops: Vec<LoopInfo> = Vec::with_capacity(back_edges.len());
    for &(latch, header) in &back_edges {
        let body: BTreeSet<usize> = flow.natural_loop_body(header, &[latch]);

        for &from in &body {
            if from == header {
                continue;
            }
            for pred in &preds[from] {
                if !body.contains(pred) {
                    return None;
                }
            }
        }

        let mut exit_targets: BTreeSet<usize> = BTreeSet::new();
        for &node in &body {
            for succ in blocks[node].successors() {
                if !body.contains(&succ) {
                    exit_targets.insert(succ);
                }
            }
        }
        let follow: usize = resolve_loop_follow(blocks, &body, &exit_targets)?;
        loops.push(LoopInfo {
            header,
            body,
            exit_targets,
            follow,
            parent: None,
        });
    }

    loops.sort_by_key(|l: &LoopInfo| l.body.len());
    for i in 0..loops.len() {
        for j in (i + 1)..loops.len() {
            let (inner, outer): (&BTreeSet<usize>, &BTreeSet<usize>) =
                (&loops[i].body, &loops[j].body);
            let disjoint: bool = inner.is_disjoint(outer);
            let nested: bool = inner.is_subset(outer);
            if !disjoint && !nested {
                return None;
            }
        }
    }

    for i in 0..loops.len() {
        let mut parent: Option<usize> = None;
        let mut parent_size: usize = usize::MAX;
        for j in 0..loops.len() {
            if i == j {
                continue;
            }
            if loops[i].body.is_subset(&loops[j].body) && loops[j].body.len() < parent_size {
                parent = Some(j);
                parent_size = loops[j].body.len();
            }
        }
        loops[i].parent = parent;
    }

    for i in 0..loops.len() {
        let follow: usize = loops[i].follow;
        if let Some(parent) = loops[i].parent
            && !loops[parent].body.contains(&follow)
        {
            return None;
        }
    }

    Some(loops)
}

struct CfgCtx<'a> {
    blocks: &'a [CfgBlock],
    idom: Vec<Option<usize>>,
    pdom: Vec<std::collections::BTreeSet<usize>>,
    pred_count: Vec<usize>,
    loops: &'a [LoopInfo],
}

impl CfgCtx<'_> {
    fn loop_at_header(&self, block: usize) -> Option<usize> {
        self.loops.iter().position(|l: &LoopInfo| l.header == block)
    }

    fn child_loop_here(&self, active: Option<usize>, block: usize) -> Option<usize> {
        let candidate: usize = self.loop_at_header(block)?;
        if active.is_some_and(|top: usize| candidate == top) {
            return None;
        }
        (self.loops[candidate].parent == active).then_some(candidate)
    }

    fn in_body_of(&self, active: Option<usize>, block: usize) -> bool {
        active.is_none_or(|top: usize| self.loops[top].body.contains(&block))
    }
}

fn immediate_dominators(flow: &structuring::FlowGraph<usize>) -> Vec<Option<usize>> {
    (0..flow.node_count())
        .map(|node: usize| flow.immediate_dominator(node))
        .collect()
}

fn post_dominator_sets(
    flow: &structuring::FlowGraph<usize>,
) -> Vec<std::collections::BTreeSet<usize>> {
    use std::collections::BTreeSet;
    (0..flow.node_count())
        .map(|node: usize| {
            let mut members: BTreeSet<usize> = BTreeSet::new();
            let mut current: usize = node;
            loop {
                if !members.insert(current) {
                    break;
                }
                match flow.immediate_post_dominator(current) {
                    structuring::PostDominator::Node(next) => current = next,
                    structuring::PostDominator::FunctionExit
                    | structuring::PostDominator::Undefined => break,
                }
            }
            members
        })
        .collect()
}

fn structure_reducible_cfg(items: &[Item]) -> Result<Option<Block>> {
    let Some(blocks): Option<Vec<CfgBlock>> = build_blocks(items) else {
        return Ok(None);
    };
    if blocks.len() < 2 {
        return Ok(None);
    }
    let preds: Vec<Vec<usize>> = block_predecessors(&blocks);
    let Some(flow): Option<structuring::FlowGraph<usize>> = block_flow(&blocks) else {
        return Ok(None);
    };
    let Some(loops): Option<Vec<LoopInfo>> = detect_loop_forest(&blocks, &preds, &flow) else {
        return Ok(None);
    };
    let idom: Vec<Option<usize>> = immediate_dominators(&flow);
    let pdom: Vec<std::collections::BTreeSet<usize>> = post_dominator_sets(&flow);
    let pred_count: Vec<usize> = preds.iter().map(Vec::len).collect();
    let ctx: CfgCtx<'_> = CfgCtx {
        blocks: &blocks,
        idom,
        pdom,
        pred_count,
        loops: &loops,
    };
    let mut body: Block = Vec::new();
    let stop: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    match emit_region(&ctx, 0, &[], &stop, &mut visited, &mut body) {
        Ok(()) if loop_count(&body) == loops.len() => Ok(Some(body)),
        _ => Ok(None),
    }
}

fn loop_count(body: &Block) -> usize {
    body.iter()
        .map(|node: &Node| match node {
            Node::While { body, .. } => 1 + loop_count(body),
            Node::DoWhile { body, .. } => loop_count(body),
            Node::If {
                then_body,
                else_body,
                ..
            } => loop_count(then_body) + else_body.as_ref().map_or(0, loop_count),
            _ => 0,
        })
        .sum()
}

#[derive(Debug)]
struct StructureError;

fn emit_stmts(blocks: &[CfgBlock], block: usize, out: &mut Block) {
    for stmt in &blocks[block].stmts {
        out.push(Node::Stmt(stmt.clone()));
    }
}

fn emit_region(
    ctx: &CfgCtx<'_>,
    start: usize,
    loop_stack: &[usize],
    stop: &std::collections::BTreeSet<usize>,
    visited: &mut std::collections::BTreeSet<usize>,
    out: &mut Block,
) -> std::result::Result<(), StructureError> {
    let active: Option<usize> = loop_stack.last().copied();
    let mut current: usize = start;
    loop {
        if stop.contains(&current) {
            return Ok(());
        }
        if let Some(top) = active {
            if ctx.loops[top].exit_targets.contains(&current) {
                out.push(Node::Break);
                return Ok(());
            }
            if current == ctx.loops[top].header {
                out.push(Node::Continue);
                return Ok(());
            }
        }
        if let Some(child) = ctx.child_loop_here(active, current) {
            let mut child_stack: Vec<usize> = loop_stack.to_vec();
            child_stack.push(child);
            let mut loop_body: Block = Vec::new();
            let entry_stop: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
            emit_loop_body(ctx, &child_stack, &entry_stop, visited, &mut loop_body)?;
            out.push(Node::While {
                body: loop_body,
                cond: None,
            });
            current = ctx.loops[child].follow;
            continue;
        }
        if !ctx.in_body_of(active, current) {
            return Err(StructureError);
        }
        if !visited.insert(current) {
            return Err(StructureError);
        }
        emit_stmts(ctx.blocks, current, out);
        match &ctx.blocks[current].term {
            BlockTerm::Ret => {
                if active.is_some() {
                    return Err(StructureError);
                }
                out.push(Node::Return);
                return Ok(());
            }
            BlockTerm::Jump(t) | BlockTerm::Fall(t) => current = *t,
            BlockTerm::Branch {
                kind,
                flags,
                taken,
                fallthrough,
            } => {
                if let Some(orc) =
                    detect_or_chain(ctx, active, current, *kind, flags, *taken, *fallthrough)
                {
                    if !visited.insert(orc.guard) {
                        return Err(StructureError);
                    }
                    let mut branch_stop: std::collections::BTreeSet<usize> = stop.clone();
                    if let Some(f) = orc.follow {
                        branch_stop.insert(f);
                    }
                    let mut then_body: Block = Vec::new();
                    emit_region(
                        ctx,
                        orc.then_blk,
                        loop_stack,
                        &branch_stop,
                        visited,
                        &mut then_body,
                    )?;
                    let mut else_body: Block = Vec::new();
                    emit_region(
                        ctx,
                        orc.else_blk,
                        loop_stack,
                        &branch_stop,
                        visited,
                        &mut else_body,
                    )?;
                    out.push(Node::If {
                        cond: orc.cond,
                        then_body,
                        else_body: if else_body.is_empty() {
                            None
                        } else {
                            Some(else_body)
                        },
                    });
                    match orc.follow {
                        Some(f) => {
                            current = f;
                            continue;
                        }
                        None => return Ok(()),
                    }
                }
                let follow: Option<usize> = branch_follow(ctx, active, current);
                let mut branch_stop: std::collections::BTreeSet<usize> = stop.clone();
                if let Some(f) = follow {
                    branch_stop.insert(f);
                }
                let mut then_body: Block = Vec::new();
                emit_region(
                    ctx,
                    *fallthrough,
                    loop_stack,
                    &branch_stop,
                    visited,
                    &mut then_body,
                )?;
                let mut else_body: Block = Vec::new();
                emit_region(
                    ctx,
                    *taken,
                    loop_stack,
                    &branch_stop,
                    visited,
                    &mut else_body,
                )?;
                out.push(Node::If {
                    cond: Cond::leaf(kind.negate(), flags.clone()),
                    then_body,
                    else_body: if else_body.is_empty() {
                        None
                    } else {
                        Some(else_body)
                    },
                });
                match follow {
                    Some(f) => current = f,
                    None => return Ok(()),
                }
            }
        }
    }
}

fn emit_loop_body(
    ctx: &CfgCtx<'_>,
    loop_stack: &[usize],
    stop: &std::collections::BTreeSet<usize>,
    visited: &mut std::collections::BTreeSet<usize>,
    out: &mut Block,
) -> std::result::Result<(), StructureError> {
    let active: usize = *loop_stack.last().ok_or(StructureError)?;
    let header: usize = ctx.loops[active].header;
    if !visited.insert(header) {
        return Err(StructureError);
    }
    emit_stmts(ctx.blocks, header, out);
    match &ctx.blocks[header].term {
        BlockTerm::Ret => Err(StructureError),
        BlockTerm::Jump(t) | BlockTerm::Fall(t) => {
            emit_region(ctx, *t, loop_stack, stop, visited, out)
        }
        BlockTerm::Branch {
            kind,
            flags,
            taken,
            fallthrough,
        } => {
            let follow: Option<usize> = branch_follow(ctx, Some(active), header);
            let mut branch_stop: std::collections::BTreeSet<usize> = stop.clone();
            if let Some(f) = follow {
                branch_stop.insert(f);
            }
            let mut then_body: Block = Vec::new();
            emit_region(
                ctx,
                *fallthrough,
                loop_stack,
                &branch_stop,
                visited,
                &mut then_body,
            )?;
            let mut else_body: Block = Vec::new();
            emit_region(
                ctx,
                *taken,
                loop_stack,
                &branch_stop,
                visited,
                &mut else_body,
            )?;
            out.push(Node::If {
                cond: Cond::leaf(kind.negate(), flags.clone()),
                then_body,
                else_body: if else_body.is_empty() {
                    None
                } else {
                    Some(else_body)
                },
            });
            follow.map_or(Ok(()), |f: usize| {
                emit_region(ctx, f, loop_stack, stop, visited, out)
            })
        }
    }
}

fn branch_follow(ctx: &CfgCtx<'_>, active: Option<usize>, branch: usize) -> Option<usize> {
    ctx.idom
        .iter()
        .enumerate()
        .filter(|(node, idom): &(usize, &Option<usize>)| {
            **idom == Some(branch)
                && ctx.pred_count[*node] >= 2
                && (ctx.pdom[branch].contains(node) || ctx.blocks[*node].successors().is_empty())
                && ctx.in_body_of(active, *node)
                && active.is_none_or(|top: usize| *node != ctx.loops[top].header)
                && ctx.child_loop_here(active, *node).is_none()
        })
        .map(|(node, _): (usize, &Option<usize>)| node)
        .next()
}

struct OrChain {
    guard: usize,
    then_blk: usize,
    else_blk: usize,
    cond: Cond,
    follow: Option<usize>,
}

fn or_merge_follow(
    ctx: &CfgCtx<'_>,
    active: Option<usize>,
    header: usize,
    then_blk: usize,
    else_blk: usize,
) -> Option<usize> {
    ctx.idom
        .iter()
        .enumerate()
        .filter(|(node, idom): &(usize, &Option<usize>)| {
            **idom == Some(header)
                && *node != then_blk
                && *node != else_blk
                && ctx.pred_count[*node] >= 2
                && ctx.in_body_of(active, *node)
                && active.is_none_or(|top: usize| *node != ctx.loops[top].header)
                && ctx.child_loop_here(active, *node).is_none()
        })
        .map(|(node, _): (usize, &Option<usize>)| node)
        .next()
}

fn detect_or_chain(
    ctx: &CfgCtx<'_>,
    active: Option<usize>,
    header: usize,
    k0: CondKind,
    flags0: &Flags,
    taken: usize,
    fallthrough: usize,
) -> Option<OrChain> {
    let guard: usize = fallthrough;
    if guard == header
        || ctx.pred_count[guard] != 1
        || !ctx.blocks[guard].stmts.is_empty()
        || !ctx.in_body_of(active, guard)
        || ctx.child_loop_here(active, guard).is_some()
        || active.is_some_and(|top: usize| guard == ctx.loops[top].header)
    {
        return None;
    }
    let BlockTerm::Branch {
        kind: k1,
        flags: flags1,
        taken: g_taken,
        fallthrough: g_fallthrough,
    } = &ctx.blocks[guard].term
    else {
        return None;
    };
    if *g_fallthrough != taken {
        return None;
    }
    let then_blk: usize = taken;
    let else_blk: usize = *g_taken;
    if then_blk == guard
        || else_blk == guard
        || then_blk == else_blk
        || then_blk == header
        || else_blk == header
    {
        return None;
    }
    let cond: Cond = Cond::Or(
        Box::new(Cond::leaf(k0, flags0.clone())),
        Box::new(Cond::leaf(k1.negate(), flags1.clone())),
    );
    let follow: Option<usize> = or_merge_follow(ctx, active, header, then_blk, else_blk);
    Some(OrChain {
        guard,
        then_blk,
        else_blk,
        cond,
        follow,
    })
}

fn structure_range(items: &[Item], lo: usize, hi: usize) -> Result<Block> {
    let mut block: Block = Vec::new();
    let mut i: usize = lo;
    while i < hi {
        match &items[i].kind {
            ItemKind::Stmt(stmt) => {
                block.push(Node::Stmt(stmt.clone()));
                i += 1;
            }
            ItemKind::Branch {
                kind,
                flags,
                target,
            } => {
                let target_pos: usize = item_pos(items, *target).ok_or_else(|| {
                    Error::LlvmIr(format!(
                        "branch target {target:#x} is not a forward join point"
                    ))
                })?;
                if target_pos <= i || target_pos > hi {
                    return Err(Error::LlvmIr(
                        "non-forward or out-of-region branch not supported".to_owned(),
                    ));
                }
                let then_lo: usize = i + 1;
                let then_hi: usize = target_pos;
                let (then_body, else_body, next): (Block, Option<Block>, usize) =
                    if let Some(else_target) = trailing_jmp_target(items, then_lo, then_hi) {
                        let else_pos: usize = item_pos(items, else_target)
                            .filter(|p: &usize| *p > target_pos && *p <= hi)
                            .ok_or_else(|| {
                                Error::LlvmIr(
                                    "if/else join target not forward-reducible".to_owned(),
                                )
                            })?;
                        let then_b: Block = structure_range(items, then_lo, then_hi - 1)?;
                        let else_b: Block = structure_range(items, target_pos, else_pos)?;
                        (then_b, Some(else_b), else_pos)
                    } else {
                        let then_b: Block = structure_range(items, then_lo, then_hi)?;
                        (then_b, None, target_pos)
                    };
                block.push(Node::If {
                    cond: Cond::leaf(kind.negate(), flags.clone()),
                    then_body,
                    else_body,
                });
                i = next;
            }
            ItemKind::Jmp { .. } => {
                return Err(Error::LlvmIr(
                    "unstructured jump not in forward-skip class".to_owned(),
                ));
            }
            ItemKind::Ret => {
                return Err(Error::LlvmIr("unexpected interior ret".to_owned()));
            }
            ItemKind::Switch { .. } => {
                return Err(Error::LlvmIr("switch requires cfg structuring".to_owned()));
            }
        }
    }
    Ok(block)
}

fn item_pos(items: &[Item], target: u64) -> Option<usize> {
    items.iter().position(|it: &Item| it.address == target)
}

fn trailing_jmp_target(items: &[Item], lo: usize, hi: usize) -> Option<u64> {
    if hi <= lo {
        return None;
    }
    match items.get(hi - 1).map(|it: &Item| &it.kind) {
        Some(ItemKind::Jmp { target }) => Some(*target),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagEffect {
    Sign,
    Clobber,
}

const fn flag_effect_bin(op: BinOp) -> FlagEffect {
    match op {
        BinOp::Add
        | BinOp::Sub
        | BinOp::And
        | BinOp::Or
        | BinOp::Xor
        | BinOp::Shl
        | BinOp::Shr
        | BinOp::Sar => FlagEffect::Sign,
        BinOp::Imul
        | BinOp::Sdiv
        | BinOp::Udiv
        | BinOp::Umull
        | BinOp::Smull
        | BinOp::Umulh
        | BinOp::Smulh => FlagEffect::Clobber,
    }
}

fn x86_mnemonic_writes_flags(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add"
            | "sub"
            | "adc"
            | "sbb"
            | "and"
            | "or"
            | "xor"
            | "neg"
            | "inc"
            | "dec"
            | "cmp"
            | "test"
            | "shl"
            | "sal"
            | "shr"
            | "sar"
            | "rol"
            | "ror"
            | "rcl"
            | "rcr"
            | "mul"
            | "imul"
            | "div"
            | "idiv"
            | "bt"
            | "bts"
            | "btr"
            | "btc"
            | "bsf"
            | "bsr"
            | "lzcnt"
            | "tzcnt"
            | "popcnt"
    )
}

fn lift_flag_setter(mnemonic: &str, operands: &str) -> Option<Flags> {
    match mnemonic {
        "cmp" => {
            let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
            let lhs_tok: &str = lhs.trim();
            let rhs_tok: &str = rhs.trim();
            if is_mem_token(lhs_tok) {
                if let Some(rhs_reg) = parse_reg(rhs_tok) {
                    let mem: MemRef = parse_mem_access(lhs_tok, Some(rhs_reg.width))?;
                    return Some(Flags::CmpMem {
                        lhs: mem,
                        rhs: Source::Reg(rhs_reg),
                    });
                }
                let mem: MemRef = parse_mem_access(lhs_tok, None)?;
                let imm: i64 = parse_imm(rhs_tok)?;
                return Some(Flags::CmpMem {
                    lhs: mem,
                    rhs: Source::Imm(imm),
                });
            }
            let lhs_reg: RegRef = parse_reg(lhs_tok)?;
            let rhs_src: Source = if is_mem_token(rhs_tok) {
                Source::Mem(parse_mem_access(rhs_tok, Some(lhs_reg.width))?)
            } else {
                parse_source(rhs_tok)?
            };
            Some(Flags::Cmp {
                lhs: lhs_reg,
                rhs: rhs_src,
            })
        }
        "test" => {
            let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
            let lhs_reg: RegRef = parse_reg(lhs.trim())?;
            if let Some(rhs_reg) = parse_reg(rhs.trim()) {
                return (lhs_reg == rhs_reg).then_some(Flags::Test { operand: lhs_reg });
            }
            let mask: i64 = parse_imm(rhs.trim())?;
            Some(Flags::TestImm {
                operand: lhs_reg,
                mask,
            })
        }
        _ => None,
    }
}

fn snapshot_repair(
    items: &mut Vec<Item>,
    kind: CondKind,
    live_flags: &Flags,
    next_sel: &mut u32,
) -> Option<Flags> {
    if !(kind.is_signed_order() || kind.is_unsigned_order()) {
        return None;
    }
    let &Flags::Sign { result } = live_flags else {
        return None;
    };
    let producer: usize = items.iter().rposition(|it: &Item| {
        matches!(
            &it.kind,
            ItemKind::Stmt(Stmt::BinAssign { dest, .. }) if dest.reg == result.reg
        ) || matches!(
            &it.kind,
            ItemKind::Stmt(Stmt::UnAssign { dest, op: UnOp::Neg }) if dest.reg == result.reg
        )
    })?;
    let (cmp_lhs, cmp_rhs, addr): (RegRef, Source, u64) = {
        let ItemKind::Stmt(Stmt::BinAssign {
            dest,
            op: BinOp::Sub,
            src,
        }) = &items[producer].kind
        else {
            return None;
        };
        (*dest, src.clone(), items[producer].address)
    };
    let var: u32 = *next_sel;
    *next_sel += 1;
    items.insert(
        producer,
        Item {
            address: addr,
            kind: ItemKind::Stmt(Stmt::FlagSnapshot {
                var,
                kind,
                flags: Flags::Cmp {
                    lhs: cmp_lhs,
                    rhs: cmp_rhs,
                },
            }),
        },
    );
    Some(Flags::Snapshot { var })
}

fn comparison_operand_clobbered(items: &[Item], mark: usize, flags: &Flags) -> bool {
    let deps: Vec<Reg> = flag_operand_regs(flags);
    let fp_deps: Vec<Xmm> = flag_operand_xmms(flags);
    let mems: Vec<MemRef> = flag_operand_mems(flags);
    if deps.is_empty() && fp_deps.is_empty() && mems.is_empty() {
        return false;
    }
    let start: usize = mark.min(items.len());
    items[start..].iter().any(|item: &Item| {
        let ItemKind::Stmt(stmt) = &item.kind else {
            return false;
        };
        stmt_dest_regs(stmt)
            .iter()
            .any(|reg: &Reg| deps.contains(reg))
            || (!fp_deps.is_empty() && stmt_clobbers_flag_fp(stmt, &fp_deps))
            || (!mems.is_empty() && stmt_writes_aliasing_mem(stmt, &mems))
    })
}

fn resolve_conditional_flags(
    items: &mut Vec<Item>,
    flags_mark: usize,
    kind: CondKind,
    live_flags: Flags,
    next_sel: &mut u32,
    addr: u64,
) -> Result<(CondKind, Flags)> {
    let Some(kind): Option<CondKind> = canonicalize_x86_fp_condition(kind, &live_flags) else {
        return Err(Error::LlvmIr(format!(
            "condition not sound against tracked flags at {addr:#x}"
        )));
    };
    if flags_are_comparison(&live_flags)
        && condition_is_sound(kind, &live_flags)
        && comparison_operand_clobbered(items, flags_mark, &live_flags)
    {
        let var: u32 = *next_sel;
        *next_sel += 1;
        let at: usize = flags_mark.min(items.len());
        let snapshot_addr: u64 = items.get(at).map_or(addr, |item: &Item| item.address);
        items.insert(
            at,
            Item {
                address: snapshot_addr,
                kind: ItemKind::Stmt(Stmt::FlagSnapshot {
                    var,
                    kind,
                    flags: live_flags,
                }),
            },
        );
        return Ok((CondKind::Ne, Flags::Snapshot { var }));
    }
    if condition_is_sound(kind, &live_flags) {
        return Ok((kind, live_flags));
    }
    if let Some(repaired) = snapshot_repair(items, kind, &live_flags, next_sel) {
        return Ok((CondKind::Ne, repaired));
    }
    Err(Error::LlvmIr(format!(
        "condition not sound against tracked flags at {addr:#x}"
    )))
}

fn item_branch_targets(items: &[Item]) -> BTreeSet<u64> {
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for item in items {
        match &item.kind {
            ItemKind::Branch { target, .. } | ItemKind::Jmp { target } => {
                targets.insert(*target);
            }
            ItemKind::Switch { cases, default, .. } => {
                targets.insert(*default);
                targets.extend(cases.iter().map(|(_, target): &(i64, u64)| *target));
            }
            ItemKind::Stmt(_) | ItemKind::Ret => {}
        }
    }
    targets
}

fn fp_cmp_address_regs(rhs: &FpOperand) -> Vec<Reg> {
    let mut regs: Vec<Reg> = Vec::new();
    if let FpOperand::Mem(mem) = rhs {
        mem_regs(mem, &mut regs);
    }
    regs
}

fn parity_fused_kind(op: BinOp, first: CondKind, second: CondKind) -> Option<CondKind> {
    let pair: (CondKind, CondKind) = (first, second);
    match op {
        BinOp::And
            if matches!(
                pair,
                (CondKind::E, CondKind::Np) | (CondKind::Np, CondKind::E)
            ) =>
        {
            Some(CondKind::E)
        }
        BinOp::Or
            if matches!(
                pair,
                (CondKind::Ne, CondKind::P) | (CondKind::P, CondKind::Ne)
            ) =>
        {
            Some(CondKind::Ne)
        }
        _ => None,
    }
}

const fn is_x86_gpr(reg: Reg) -> bool {
    matches!(
        reg,
        Reg::Rax
            | Reg::Rbx
            | Reg::Rcx
            | Reg::Rdx
            | Reg::Rsi
            | Reg::Rdi
            | Reg::Rbp
            | Reg::Rsp
            | Reg::R8
            | Reg::R9
            | Reg::R10
            | Reg::R11
            | Reg::R12
            | Reg::R13
            | Reg::R14
            | Reg::R15
    )
}

fn enumerable_gpr_writes(stmt: &Stmt) -> Option<Vec<RegRef>> {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. }
        | Stmt::Vector(VecStmt::ExtractToGpr { dest, .. }) => Some(vec![*dest]),
        Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpStore { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(
            VecStmt::Load { .. }
            | VecStmt::Store { .. }
            | VecStmt::Bin { .. }
            | VecStmt::Dup { .. }
            | VecStmt::LaneInsert { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. },
        ) => Some(Vec::new()),
        Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::Call { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. } => None,
    }
}

fn preceding_family_writer(
    items: &[Item],
    targets: &BTreeSet<u64>,
    before: usize,
    family: Reg,
) -> Option<usize> {
    for index in (0..before).rev() {
        let item: &Item = &items[index];
        if targets.contains(&item.address) {
            return None;
        }
        let ItemKind::Stmt(stmt) = &item.kind else {
            return None;
        };
        let writes: Vec<RegRef> = enumerable_gpr_writes(stmt)?;
        if writes.iter().any(|write: &RegRef| write.reg == family) {
            return Some(index);
        }
    }
    None
}

fn zero_extending_zero_write(stmt: &Stmt, family: Reg) -> bool {
    match stmt {
        Stmt::Assign {
            dest,
            src: Source::Imm(0),
        } => dest.reg == family && matches!(dest.width, Width::W32 | Width::W64),
        Stmt::BinAssign {
            dest,
            op: BinOp::Xor,
            src: Source::Reg(src),
        } => {
            dest.reg == family
                && src.reg == family
                && src.width == dest.width
                && matches!(dest.width, Width::W32 | Width::W64)
        }
        _ => false,
    }
}

fn upper_bits_proven_zero(
    items: &[Item],
    targets: &BTreeSet<u64>,
    before: usize,
    family: Reg,
) -> bool {
    let mut cursor: usize = before;
    while let Some(index) = preceding_family_writer(items, targets, cursor, family) {
        let ItemKind::Stmt(stmt) = &items[index].kind else {
            return false;
        };
        let Some(writes): Option<Vec<RegRef>> = enumerable_gpr_writes(stmt) else {
            return false;
        };
        if writes
            .iter()
            .any(|write: &RegRef| write.reg == family && write.width != Width::W8)
        {
            return zero_extending_zero_write(stmt, family);
        }
        cursor = index;
    }
    false
}

fn selected_constant_value(stmt: &Stmt, family: Reg) -> Option<i64> {
    if zero_extending_zero_write(stmt, family) {
        return Some(0);
    }
    let Stmt::Assign {
        dest,
        src: Source::Imm(value),
    } = stmt
    else {
        return None;
    };
    (dest.reg == family && matches!(dest.width, Width::W32 | Width::W64)).then_some(*value)
}

const fn ordered_equality_fused_kind(predicate: CondKind, constant: i64) -> Option<CondKind> {
    match (predicate, constant) {
        (CondKind::Np, 0) => Some(CondKind::E),
        (CondKind::P, 1) => Some(CondKind::Ne),
        _ => None,
    }
}

const fn flag_transparent(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign { .. } | Stmt::Extend { .. } | Stmt::SetCc { .. } | Stmt::Cond { .. }
    )
}

fn same_flag_definition(
    items: &[Item],
    insn_index: &BTreeMap<u64, usize>,
    targets: &BTreeSet<u64>,
    span: (usize, usize),
    address_regs: &[Reg],
) -> bool {
    let (predicate, select): (usize, usize) = span;
    if predicate >= select {
        return false;
    }
    let (Some(first), Some(last)): (Option<usize>, Option<usize>) = (
        insn_index.get(&items[predicate].address).copied(),
        insn_index.get(&items[select].address).copied(),
    ) else {
        return false;
    };
    if last.checked_sub(first) != Some(select - predicate) {
        return false;
    }
    (1..select - predicate).all(|offset: usize| {
        let item: &Item = &items[predicate + offset];
        if insn_index.get(&item.address).copied() != Some(first + offset)
            || targets.contains(&item.address)
        {
            return false;
        }
        let ItemKind::Stmt(stmt) = &item.kind else {
            return false;
        };
        flag_transparent(stmt)
            && enumerable_gpr_writes(stmt).is_some_and(|writes: Vec<RegRef>| {
                !writes
                    .iter()
                    .any(|write: &RegRef| address_regs.contains(&write.reg))
            })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderedEqualitySelect {
    dest: RegRef,
    kind: CondKind,
    flags: Flags,
}

fn ordered_equality_select(
    items: &[Item],
    insn_index: &BTreeMap<u64, usize>,
    targets: &BTreeSet<u64>,
    index: usize,
) -> Option<OrderedEqualitySelect> {
    let ItemKind::Stmt(Stmt::Cond {
        dest,
        src: Source::Reg(constant_reg),
        kind: CondKind::Ne,
        flags,
    }) = &items[index].kind
    else {
        return None;
    };
    let Flags::FpCmp {
        lhs,
        rhs,
        width,
        model: FpUnorderedModel::UnorderedIsEqual,
    } = flags
    else {
        return None;
    };
    let (dest, constant_reg): (RegRef, RegRef) = (*dest, *constant_reg);
    if !matches!(dest.width, Width::W32 | Width::W64)
        || dest.width != constant_reg.width
        || !is_x86_gpr(dest.reg)
        || !is_x86_gpr(constant_reg.reg)
        || dest.reg == constant_reg.reg
        || targets.contains(&items[index].address)
    {
        return None;
    }
    let widened: usize = preceding_family_writer(items, targets, index, dest.reg)?;
    let (predicate_at, predicate_family): (usize, Reg) = match &items[widened].kind {
        ItemKind::Stmt(Stmt::SetCc { dest: byte, .. }) if byte.width == Width::W8 => {
            (widened, byte.reg)
        }
        ItemKind::Stmt(Stmt::Extend {
            dest: wide,
            src: ExtSource::Reg(byte),
            signed: false,
        }) if wide.width == Width::W32 && byte.width == Width::W8 && is_x86_gpr(byte.reg) => (
            preceding_family_writer(items, targets, widened, byte.reg)?,
            byte.reg,
        ),
        _ => return None,
    };
    let ItemKind::Stmt(Stmt::SetCc {
        dest: predicate_byte,
        kind: predicate_kind,
        flags: predicate_flags,
    }) = &items[predicate_at].kind
    else {
        return None;
    };
    if predicate_byte.width != Width::W8
        || predicate_byte.reg != predicate_family
        || predicate_flags != flags
    {
        return None;
    }
    if constant_reg.reg == predicate_family {
        return None;
    }
    if predicate_at == widened && !upper_bits_proven_zero(items, targets, predicate_at, dest.reg) {
        return None;
    }
    let constant_at: usize = preceding_family_writer(items, targets, index, constant_reg.reg)?;
    let ItemKind::Stmt(constant_stmt) = &items[constant_at].kind else {
        return None;
    };
    let constant: i64 = selected_constant_value(constant_stmt, constant_reg.reg)?;
    let fused: CondKind = ordered_equality_fused_kind(*predicate_kind, constant)?;
    let address_regs: Vec<Reg> = fp_cmp_address_regs(rhs);
    if !same_flag_definition(
        items,
        insn_index,
        targets,
        (predicate_at, index),
        &address_regs,
    ) {
        return None;
    }
    if address_regs.contains(&dest.reg)
        || address_regs.contains(&constant_reg.reg)
        || address_regs.contains(&predicate_family)
    {
        return None;
    }
    Some(OrderedEqualitySelect {
        dest: RegRef {
            reg: dest.reg,
            width: Width::W8,
        },
        kind: fused,
        flags: Flags::FpCmp {
            lhs: *lhs,
            rhs: *rhs,
            width: *width,
            model: FpUnorderedModel::UnorderedIsUnequal,
        },
    })
}

fn fuse_parity_equality_idioms(items: &mut [Item], insns: &[DisasmInsn]) {
    if items.len() < 3 {
        return;
    }
    let targets: BTreeSet<u64> = item_branch_targets(items);
    let insn_index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(index, insn): (usize, &DisasmInsn)| (insn.address, index))
        .collect();
    for k in 2..items.len() {
        let ItemKind::Stmt(Stmt::BinAssign {
            dest,
            op: op @ (BinOp::And | BinOp::Or),
            src: Source::Reg(src),
        }) = &items[k].kind
        else {
            continue;
        };
        let (dest, src, op): (RegRef, RegRef, BinOp) = (*dest, *src, *op);
        if dest.width != Width::W8 || src.width != Width::W8 || dest.reg == src.reg {
            continue;
        }
        let (
            ItemKind::Stmt(Stmt::SetCc {
                dest: first_dest,
                kind: first_kind,
                flags: first_flags,
            }),
            ItemKind::Stmt(Stmt::SetCc {
                dest: second_dest,
                kind: second_kind,
                flags: second_flags,
            }),
        ) = (&items[k - 2].kind, &items[k - 1].kind)
        else {
            continue;
        };
        let defined: BTreeSet<Reg> = BTreeSet::from([first_dest.reg, second_dest.reg]);
        if defined != BTreeSet::from([dest.reg, src.reg]) {
            continue;
        }
        let Some(fused_kind): Option<CondKind> = parity_fused_kind(op, *first_kind, *second_kind)
        else {
            continue;
        };
        if first_flags != second_flags {
            continue;
        }
        let Flags::FpCmp {
            lhs,
            rhs,
            width,
            model: FpUnorderedModel::UnorderedIsEqual,
        } = first_flags
        else {
            continue;
        };
        let address_regs: Vec<Reg> = fp_cmp_address_regs(rhs);
        if address_regs.contains(&dest.reg) || address_regs.contains(&src.reg) {
            continue;
        }
        if targets.contains(&items[k - 1].address) || targets.contains(&items[k].address) {
            continue;
        }
        let (Some(first_index), Some(second_index), Some(third_index)): (
            Option<&usize>,
            Option<&usize>,
            Option<&usize>,
        ) = (
            insn_index.get(&items[k - 2].address),
            insn_index.get(&items[k - 1].address),
            insn_index.get(&items[k].address),
        ) else {
            continue;
        };
        if *second_index != first_index + 1 || *third_index != second_index + 1 {
            continue;
        }
        let fused_flags: Flags = Flags::FpCmp {
            lhs: *lhs,
            rhs: *rhs,
            width: *width,
            model: FpUnorderedModel::UnorderedIsUnequal,
        };
        items[k].kind = ItemKind::Stmt(Stmt::SetCc {
            dest,
            kind: fused_kind,
            flags: fused_flags,
        });
    }
    for k in 0..items.len() {
        let Some(select): Option<OrderedEqualitySelect> =
            ordered_equality_select(items, &insn_index, &targets, k)
        else {
            continue;
        };
        items[k].kind = ItemKind::Stmt(Stmt::SetCc {
            dest: select.dest,
            kind: select.kind,
            flags: select.flags,
        });
    }
}

fn canonicalize_x86_fp_condition(kind: CondKind, flags: &Flags) -> Option<CondKind> {
    if !matches!(flags, Flags::FpCmp { .. }) {
        return Some(kind);
    }
    match kind {
        CondKind::A => Some(CondKind::G),
        CondKind::Ae => Some(CondKind::Ge),
        CondKind::B => Some(CondKind::L),
        CondKind::Be => Some(CondKind::Le),
        CondKind::E | CondKind::Ne | CondKind::P | CondKind::Np => Some(kind),
        CondKind::G
        | CondKind::Ge
        | CondKind::L
        | CondKind::Le
        | CondKind::S
        | CondKind::Ns
        | CondKind::Vs
        | CondKind::Vc => None,
    }
}

fn condition_is_sound(kind: CondKind, flags: &Flags) -> bool {
    if matches!(kind, CondKind::P | CondKind::Np) {
        return matches!(flags, Flags::FpCmp { .. });
    }
    match flags {
        Flags::Cmp { .. } | Flags::CmpMem { .. } | Flags::Test { .. } => true,
        Flags::Add { .. } => kind.sign_zero_only() || kind.is_overflow(),
        Flags::TestImm { .. } => matches!(kind, CondKind::E | CondKind::Ne),
        Flags::Sign { .. } => kind.sign_zero_only(),
        Flags::FpCmp { .. } => true,
        Flags::Snapshot { .. } => true,
        Flags::CondCmp {
            prior,
            precond,
            taken,
            ..
        } => condition_is_sound(kind, taken) && condition_is_sound(*precond, prior),
    }
}

fn nzcv_condition_holds(kind: CondKind, nzcv: u8) -> bool {
    let n: bool = nzcv & 0b1000 != 0;
    let z: bool = nzcv & 0b0100 != 0;
    let c: bool = nzcv & 0b0010 != 0;
    let v: bool = nzcv & 0b0001 != 0;
    match kind {
        CondKind::E => z,
        CondKind::Ne => !z,
        CondKind::Ae => c,
        CondKind::B => !c,
        CondKind::S => n,
        CondKind::Ns => !n,
        CondKind::Vs => v,
        CondKind::Vc => !v,
        CondKind::A => c && !z,
        CondKind::Be => !c || z,
        CondKind::Ge => n == v,
        CondKind::L => n != v,
        CondKind::G => !z && (n == v),
        CondKind::Le => z || n != v,
        CondKind::P => v,
        CondKind::Np => !v,
    }
}

fn infer_params(body: &Block, abi: Abi) -> Vec<Reg> {
    let arg_order: &[Reg] = abi.arg_order();
    let mut written: BTreeMap<Reg, bool> = BTreeMap::new();
    let mut read_before_write: Vec<Reg> = Vec::new();
    let mut note_read = |reg: Reg, written: &BTreeMap<Reg, bool>, acc: &mut Vec<Reg>| {
        if arg_order.contains(&reg)
            && !written.get(&reg).copied().unwrap_or(false)
            && !acc.contains(&reg)
        {
            acc.push(reg);
        }
    };
    scan_block_params(body, &mut written, &mut read_before_write, &mut note_read);
    let mut ordered: Vec<Reg> = read_before_write;
    ordered.sort_by_key(|r: &Reg| {
        arg_order
            .iter()
            .position(|a: &Reg| a == r)
            .unwrap_or(usize::MAX)
    });
    ordered
}

const FP_ARG_ORDER: [Xmm; 8] = [
    Xmm::Xmm0,
    Xmm::Xmm1,
    Xmm::Xmm2,
    Xmm::Xmm3,
    Xmm::Xmm4,
    Xmm::Xmm5,
    Xmm::Xmm6,
    Xmm::Xmm7,
];

const MS_X64_FP_ARG_ORDER: [Xmm; 4] = [Xmm::Xmm0, Xmm::Xmm1, Xmm::Xmm2, Xmm::Xmm3];

const fn fp_arg_order(abi: Abi) -> &'static [Xmm] {
    match abi {
        Abi::MsX64 => &MS_X64_FP_ARG_ORDER,
        Abi::SysV | Abi::Aapcs64 => &FP_ARG_ORDER,
    }
}

fn infer_fp_params(body: &Block, abi: Abi) -> Result<Vec<(Xmm, FpWidth)>> {
    let mut written: BTreeMap<Xmm, bool> = BTreeMap::new();
    let mut read_before_write: Vec<(Xmm, FpWidth)> = Vec::new();
    scan_fp_params(body, &mut written, &mut read_before_write, abi)?;
    read_before_write.sort_by_key(|(x, _): &(Xmm, FpWidth)| x.index());
    Ok(read_before_write)
}

fn note_fp_read(
    xmm: Xmm,
    width: FpWidth,
    written: &BTreeMap<Xmm, bool>,
    acc: &mut Vec<(Xmm, FpWidth)>,
    abi: Abi,
) -> Result<()> {
    if written.get(&xmm).copied().unwrap_or(false) {
        return Ok(());
    }
    if !fp_arg_order(abi).contains(&xmm) {
        return Err(Error::LlvmIr(format!(
            "floating register {} is read before any write, but under {abi:?} it is volatile scratch rather than an argument register, so its entry value is not recoverable",
            xmm.index()
        )));
    }
    if let Some((_, seen_width)) = acc
        .iter()
        .find(|(seen_xmm, _): &&(Xmm, FpWidth)| *seen_xmm == xmm)
    {
        if *seen_width != width {
            return Err(Error::LlvmIr(format!(
                "floating parameter register {} is read at conflicting widths before a full write",
                xmm.index()
            )));
        }
        return Ok(());
    }
    acc.push((xmm, width));
    Ok(())
}

fn scan_fp_operand(
    operand: &FpOperand,
    width: FpWidth,
    written: &BTreeMap<Xmm, bool>,
    acc: &mut Vec<(Xmm, FpWidth)>,
    abi: Abi,
) -> Result<()> {
    if let FpOperand::Xmm(x) = operand {
        note_fp_read(*x, width, written, acc, abi)?;
    }
    Ok(())
}

fn scan_fp_stmt(
    stmt: &Stmt,
    written: &mut BTreeMap<Xmm, bool>,
    acc: &mut Vec<(Xmm, FpWidth)>,
    abi: Abi,
) -> Result<()> {
    match stmt {
        Stmt::FpBin {
            dest,
            lhs,
            rhs,
            width,
            ..
        } => {
            scan_fp_operand(lhs, *width, written, acc, abi)?;
            scan_fp_operand(rhs, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpMov { dest, src, width } => {
            scan_fp_operand(src, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpStore { src, width, .. } => {
            note_fp_read(*src, *width, written, acc, abi)?;
        }
        Stmt::IntToFp { dest, .. } => {
            written.insert(*dest, true);
        }
        Stmt::FpToInt { src, width, .. } => {
            note_fp_read(*src, *width, written, acc, abi)?;
        }
        Stmt::FpConvert {
            dest, src, from, ..
        } => {
            note_fp_read(*src, *from, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpMinMax {
            dest,
            lhs,
            rhs,
            width,
            ..
        } => {
            scan_fp_operand(lhs, *width, written, acc, abi)?;
            scan_fp_operand(rhs, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpFma {
            dest,
            mul_lhs,
            mul_rhs,
            addend,
            width,
            ..
        } => {
            scan_fp_operand(mul_lhs, *width, written, acc, abi)?;
            scan_fp_operand(mul_rhs, *width, written, acc, abi)?;
            scan_fp_operand(addend, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpCsel {
            dest,
            if_true,
            if_false,
            flags,
            width,
            ..
        } => {
            scan_fp_operand(if_true, *width, written, acc, abi)?;
            scan_fp_operand(if_false, *width, written, acc, abi)?;
            scan_fp_flags(flags, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpSqrt {
            dest, src, width, ..
        }
        | Stmt::FpUnary {
            dest, src, width, ..
        } => {
            scan_fp_operand(src, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::FpRound {
            dest, src, width, ..
        } => {
            scan_fp_operand(src, *width, written, acc, abi)?;
            written.insert(*dest, true);
        }
        Stmt::GprToXmm { dest, .. } => {
            written.insert(*dest, true);
        }
        Stmt::XmmToGpr { src, width, .. } => {
            note_fp_read(*src, *width, written, acc, abi)?;
        }
        Stmt::Cond { flags, .. } | Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. } => {
            scan_fp_flags(flags, written, acc, abi)?;
        }
        _ => {}
    }
    Ok(())
}

fn scan_fp_flags(
    flags: &Flags,
    written: &BTreeMap<Xmm, bool>,
    acc: &mut Vec<(Xmm, FpWidth)>,
    abi: Abi,
) -> Result<()> {
    match flags {
        Flags::FpCmp {
            lhs, rhs, width, ..
        } => {
            note_fp_read(*lhs, *width, written, acc, abi)?;
            scan_fp_operand(rhs, *width, written, acc, abi)?;
        }
        Flags::CondCmp { prior, taken, .. } => {
            scan_fp_flags(prior, written, acc, abi)?;
            scan_fp_flags(taken, written, acc, abi)?;
        }
        _ => {}
    }
    Ok(())
}

fn merge_fp_writes(written: &mut BTreeMap<Xmm, bool>, branches: &[BTreeMap<Xmm, bool>]) {
    let mut registers: BTreeSet<Xmm> = BTreeSet::new();
    for branch in branches {
        registers.extend(branch.keys().copied());
    }
    written.clear();
    for register in registers {
        if branches
            .iter()
            .all(|branch: &BTreeMap<Xmm, bool>| branch.get(&register).copied().unwrap_or(false))
        {
            written.insert(register, true);
        }
    }
}

fn scan_fp_params(
    body: &Block,
    written: &mut BTreeMap<Xmm, bool>,
    acc: &mut Vec<(Xmm, FpWidth)>,
    abi: Abi,
) -> Result<()> {
    for node in body {
        match node {
            Node::Stmt(stmt) => scan_fp_stmt(stmt, written, acc, abi)?,
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                let mut condition_error: Option<Error> = None;
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| {
                    if condition_error.is_none() {
                        condition_error = scan_fp_flags(flags, written, acc, abi).err();
                    }
                });
                if let Some(error) = condition_error {
                    return Err(error);
                }
                let mut then_written: BTreeMap<Xmm, bool> = written.clone();
                scan_fp_params(then_body, &mut then_written, acc, abi)?;
                let mut branches: Vec<BTreeMap<Xmm, bool>> = vec![then_written];
                if let Some(else_b) = else_body {
                    let mut else_written: BTreeMap<Xmm, bool> = written.clone();
                    scan_fp_params(else_b, &mut else_written, acc, abi)?;
                    branches.push(else_written);
                } else {
                    branches.push(written.clone());
                }
                merge_fp_writes(written, &branches);
            }
            Node::DoWhile { body, cond } => {
                let mut loop_written: BTreeMap<Xmm, bool> = written.clone();
                scan_fp_params(body, &mut loop_written, acc, abi)?;
                if let LoopCond::Direct { flags, .. } = cond {
                    scan_fp_flags(flags, &loop_written, acc, abi)?;
                }
            }
            Node::While { body, cond } => {
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    scan_fp_flags(flags, written, acc, abi)?;
                }
                let mut loop_written: BTreeMap<Xmm, bool> = written.clone();
                scan_fp_params(body, &mut loop_written, acc, abi)?;
            }
            Node::Switch { cases, default, .. } => {
                let mut branches: Vec<BTreeMap<Xmm, bool>> = Vec::with_capacity(cases.len() + 1);
                for case in cases {
                    let mut case_written: BTreeMap<Xmm, bool> = written.clone();
                    scan_fp_params(&case.body, &mut case_written, acc, abi)?;
                    branches.push(case_written);
                }
                let mut default_written: BTreeMap<Xmm, bool> = written.clone();
                scan_fp_params(default, &mut default_written, acc, abi)?;
                branches.push(default_written);
                merge_fp_writes(written, &branches);
            }
            Node::CondSnapshot { flags, .. } => scan_fp_flags(flags, written, acc, abi)?,
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
    }
    Ok(())
}

fn node_terminates(node: &Node) -> bool {
    match node {
        Node::Return | Node::Break | Node::Continue | Node::Goto(_) => true,
        Node::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => block_terminates(then_body) && block_terminates(else_body),
        _ => false,
    }
}

fn block_terminates(body: &Block) -> bool {
    body.last().is_some_and(node_terminates)
}

fn scan_block_params(
    body: &Block,
    written: &mut BTreeMap<Reg, bool>,
    acc: &mut Vec<Reg>,
    note: &mut impl FnMut(Reg, &BTreeMap<Reg, bool>, &mut Vec<Reg>),
) {
    for node in body {
        match node {
            Node::Stmt(stmt) => scan_stmt_params(stmt, written, acc, note),
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| {
                    read_flags(flags, written, acc, note);
                });
                let then_terminal: bool = block_terminates(then_body);
                let mut then_written: BTreeMap<Reg, bool> = written.clone();
                scan_block_params(then_body, &mut then_written, acc, note);
                if let Some(else_b) = else_body {
                    let else_terminal: bool = block_terminates(else_b);
                    let mut else_written: BTreeMap<Reg, bool> = written.clone();
                    scan_block_params(else_b, &mut else_written, acc, note);
                    if then_terminal && !else_terminal {
                        *written = else_written;
                    } else if else_terminal && !then_terminal {
                        *written = then_written;
                    }
                }
            }
            Node::DoWhile { body, cond } => {
                let mut loop_written: BTreeMap<Reg, bool> = written.clone();
                scan_block_params(body, &mut loop_written, acc, note);
                if let LoopCond::Direct { flags, .. } = cond {
                    read_flags(flags, &loop_written, acc, note);
                }
            }
            Node::While { body, cond } => {
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    read_flags(flags, written, acc, note);
                }
                let mut loop_written: BTreeMap<Reg, bool> = written.clone();
                scan_block_params(body, &mut loop_written, acc, note);
            }
            Node::Switch {
                disc,
                cases,
                default,
            } => {
                note(disc.reg, written, acc);
                for case in cases {
                    let mut case_written: BTreeMap<Reg, bool> = written.clone();
                    scan_block_params(&case.body, &mut case_written, acc, note);
                }
                let mut default_written: BTreeMap<Reg, bool> = written.clone();
                scan_block_params(default, &mut default_written, acc, note);
            }
            Node::CondSnapshot { flags, .. } => read_flags(flags, written, acc, note),
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
    }
}

fn scan_stmt_params(
    stmt: &Stmt,
    written: &mut BTreeMap<Reg, bool>,
    acc: &mut Vec<Reg>,
    note: &mut impl FnMut(Reg, &BTreeMap<Reg, bool>, &mut Vec<Reg>),
) {
    match stmt {
        Stmt::Assign { dest, src } => {
            read_sources(src, written, acc, note);
            written.insert(dest.reg, true);
        }
        Stmt::BinAssign { dest, src, .. } => {
            note(dest.reg, written, acc);
            read_sources(src, written, acc, note);
            written.insert(dest.reg, true);
        }
        Stmt::UnAssign { dest, .. } => {
            note(dest.reg, written, acc);
            written.insert(dest.reg, true);
        }
        Stmt::Cond {
            dest, src, flags, ..
        } => {
            read_flags(flags, written, acc, note);
            read_sources(src, written, acc, note);
            note(dest.reg, written, acc);
            written.insert(dest.reg, true);
        }
        Stmt::SetCc { dest, flags, .. } => {
            read_flags(flags, written, acc, note);
            note(dest.reg, written, acc);
            written.insert(dest.reg, true);
        }
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            ..
        } => {
            read_flags(flags, written, acc, note);
            for operand in [if_true, if_false] {
                if let FpOperand::Mem(mem) = operand {
                    read_addr(mem, written, acc, note);
                }
            }
        }
        Stmt::Store { addr, src } => {
            read_addr(addr, written, acc, note);
            read_sources(src, written, acc, note);
        }
        Stmt::MemRmw { addr, op } => {
            read_addr(addr, written, acc, note);
            if let Some(src) = op.source() {
                read_sources(src, written, acc, note);
            }
        }
        Stmt::Extend { dest, src, .. } => {
            match src {
                ExtSource::Reg(r) => note(r.reg, written, acc),
                ExtSource::Mem(mem) => read_addr(mem, written, acc, note),
            }
            written.insert(dest.reg, true);
        }
        Stmt::MulImm { dest, src, .. } => {
            match src {
                ExtSource::Reg(r) => note(r.reg, written, acc),
                ExtSource::Mem(mem) => read_addr(mem, written, acc, note),
            }
            written.insert(dest.reg, true);
        }
        Stmt::WideMul { src } => {
            note(Reg::Rax, written, acc);
            note(src.reg, written, acc);
            written.insert(Reg::Rax, true);
            written.insert(Reg::Rdx, true);
        }
        Stmt::Divide { divisor, .. } => {
            note(Reg::Rax, written, acc);
            note(divisor.reg, written, acc);
            written.insert(Reg::Rax, true);
            written.insert(Reg::Rdx, true);
        }
        Stmt::DoubleShift { dest, src, .. } => {
            note(dest.reg, written, acc);
            note(src.reg, written, acc);
            written.insert(dest.reg, true);
        }
        Stmt::BlockMove { .. } => {
            note(Reg::Rdi, written, acc);
            note(Reg::Rsi, written, acc);
            note(Reg::Rcx, written, acc);
            written.insert(Reg::Rdi, true);
            written.insert(Reg::Rsi, true);
            written.insert(Reg::Rcx, true);
        }
        Stmt::BlockFill { .. } => {
            note(Reg::Rdi, written, acc);
            note(Reg::Rax, written, acc);
            note(Reg::Rcx, written, acc);
            written.insert(Reg::Rdi, true);
            written.insert(Reg::Rcx, true);
        }
        Stmt::Call { args, .. } => {
            for reg in args {
                note(*reg, written, acc);
            }
            written.insert(Reg::Rax, true);
        }
        Stmt::IntToFp { src, .. } => {
            note(src.reg, written, acc);
        }
        Stmt::FpToInt { dest, .. } => {
            written.insert(dest.reg, true);
        }
        Stmt::FpBin { lhs, rhs, .. } => {
            if let FpOperand::Mem(mem) = lhs {
                read_addr(mem, written, acc, note);
            }
            if let FpOperand::Mem(mem) = rhs {
                read_addr(mem, written, acc, note);
            }
        }
        Stmt::FpMov { src, .. } => {
            if let FpOperand::Mem(mem) = src {
                read_addr(mem, written, acc, note);
            }
        }
        Stmt::FpStore { addr, .. } => {
            read_addr(addr, written, acc, note);
        }
        Stmt::FpMinMax { lhs, rhs, .. } => {
            if let FpOperand::Mem(mem) = lhs {
                read_addr(mem, written, acc, note);
            }
            if let FpOperand::Mem(mem) = rhs {
                read_addr(mem, written, acc, note);
            }
        }
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            for operand in [mul_lhs, mul_rhs, addend] {
                if let FpOperand::Mem(mem) = operand {
                    read_addr(mem, written, acc, note);
                }
            }
        }
        Stmt::FpSqrt { src, .. } | Stmt::FpUnary { src, .. } => {
            if let FpOperand::Mem(mem) = src {
                read_addr(mem, written, acc, note);
            }
        }
        Stmt::FpRound { src, .. } => {
            if let FpOperand::Mem(mem) = src {
                read_addr(mem, written, acc, note);
            }
        }
        Stmt::GprToXmm { src, .. } => {
            note(src.reg, written, acc);
        }
        Stmt::XmmToGpr { dest, .. } => {
            written.insert(dest.reg, true);
        }
        Stmt::FpConvert { .. } => {}
        Stmt::Packed { op, .. } => {
            if let PackedOp::FromGpr { src } = op {
                note(src.reg, written, acc);
            }
        }
        Stmt::PackedToGpr { dest, .. } => {
            written.insert(dest.reg, true);
        }
        Stmt::Vector(vec) => match vec {
            VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => {
                read_addr(addr, written, acc, note);
            }
            VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => {
                note(src.reg, written, acc);
            }
            VecStmt::ExtractToGpr { dest, .. } => {
                written.insert(dest.reg, true);
            }
            VecStmt::Bin { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. } => {}
        },
        Stmt::FlagSnapshot { flags, .. } => {
            read_flags(flags, written, acc, note);
        }
    }
}

fn read_flags(
    flags: &Flags,
    written: &BTreeMap<Reg, bool>,
    acc: &mut Vec<Reg>,
    note: &mut impl FnMut(Reg, &BTreeMap<Reg, bool>, &mut Vec<Reg>),
) {
    match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            note(lhs.reg, written, acc);
            read_sources(rhs, written, acc, note);
        }
        Flags::CmpMem { lhs, rhs } => {
            read_addr(lhs, written, acc, note);
            read_sources(rhs, written, acc, note);
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => {
            note(operand.reg, written, acc);
        }
        Flags::Sign { result } => note(result.reg, written, acc),
        Flags::FpCmp { rhs, .. } => {
            if let FpOperand::Mem(mem) = rhs {
                read_addr(mem, written, acc, note);
            }
        }
        Flags::Snapshot { .. } => {}
        Flags::CondCmp { prior, taken, .. } => {
            read_flags(prior, written, acc, &mut *note);
            read_flags(taken, written, acc, note);
        }
    }
}

fn read_addr(
    addr: &MemRef,
    written: &BTreeMap<Reg, bool>,
    acc: &mut Vec<Reg>,
    note: &mut impl FnMut(Reg, &BTreeMap<Reg, bool>, &mut Vec<Reg>),
) {
    if let Some(b) = addr.base {
        note(b, written, acc);
    }
    if let Some(idx) = addr.index {
        note(idx.reg, written, acc);
    }
}

fn read_sources(
    src: &Source,
    written: &BTreeMap<Reg, bool>,
    acc: &mut Vec<Reg>,
    note: &mut impl FnMut(Reg, &BTreeMap<Reg, bool>, &mut Vec<Reg>),
) {
    match src {
        Source::Reg(r) => note(r.reg, written, acc),
        Source::Imm(_) => {}
        Source::Lea { base, index, .. } => {
            if let Some(b) = base {
                note(*b, written, acc);
            }
            if let Some(idx) = index {
                note(idx.reg, written, acc);
            }
        }
        Source::Mem(mem) => read_addr(mem, written, acc, note),
    }
}

fn lift_width_extension(mnemonic: &str, operands: &str) -> Option<Stmt> {
    if mnemonic == "cdqe" {
        if !operands.trim().is_empty() {
            return None;
        }
        return Some(Stmt::Extend {
            dest: RegRef {
                reg: Reg::Rax,
                width: Width::W64,
            },
            src: ExtSource::Reg(RegRef {
                reg: Reg::Rax,
                width: Width::W32,
            }),
            signed: true,
        });
    }
    let signed: bool = match mnemonic {
        "movzx" => false,
        "movsx" | "movsxd" => true,
        _ => return None,
    };
    let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    let rhs_tok: &str = rhs.trim();
    if is_mem_token(rhs_tok) {
        let implied: Option<Width> = (mnemonic == "movsxd").then_some(Width::W32);
        let mem: MemRef = parse_mem_access(rhs_tok, implied)?;
        if mem.width >= dest.width {
            return None;
        }
        return Some(Stmt::Extend {
            dest,
            src: ExtSource::Mem(mem),
            signed,
        });
    }
    let src: RegRef = parse_reg(rhs_tok)?;
    if src.width >= dest.width {
        return None;
    }
    Some(Stmt::Extend {
        dest,
        src: ExtSource::Reg(src),
        signed,
    })
}

fn lift_dividend_extend(mnemonic: &str, operands: &str) -> Option<DividendHigh> {
    if !operands.trim().is_empty() {
        return None;
    }
    match mnemonic {
        "cqo" => Some(DividendHigh::SignExtended { width: Width::W64 }),
        "cdq" => Some(DividendHigh::SignExtended { width: Width::W32 }),
        _ => None,
    }
}

fn parse_divide_operand(mnemonic: &str, operands: &str) -> Option<RegRef> {
    if !matches!(mnemonic, "idiv" | "div") {
        return None;
    }
    let divisor: RegRef = parse_reg(operands.trim())?;
    matches!(divisor.width, Width::W32 | Width::W64).then_some(divisor)
}

const fn dividend_high_matches(high: DividendHigh, signed: bool, width: Width) -> bool {
    match high {
        DividendHigh::SignExtended { width: w } => signed && w as u8 == width as u8,
        DividendHigh::Zeroed => !signed,
    }
}

fn sign_extended_high_read_is_unsound(dividend_high: Option<DividendHigh>, stmt: &Stmt) -> bool {
    if !matches!(dividend_high, Some(DividendHigh::SignExtended { .. })) {
        return false;
    }
    let mut reads: Vec<Reg> = Vec::new();
    stmt_value_reads(stmt, &mut reads);
    reads.contains(&Reg::Rdx)
}

fn track_dividend_high(prev: Option<DividendHigh>, stmt: &Stmt) -> Option<DividendHigh> {
    match stmt {
        Stmt::Assign {
            dest,
            src: Source::Imm(0),
        } if dest.reg == Reg::Rdx => Some(DividendHigh::Zeroed),
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
            if dest.reg == Reg::Rdx =>
        {
            None
        }
        Stmt::WideMul { .. } | Stmt::Call { .. } | Stmt::Divide { .. } => None,
        _ => prev,
    }
}

fn stmt_dest_regs(stmt: &Stmt) -> Vec<Reg> {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. } => vec![dest.reg],
        Stmt::Vector(VecStmt::ExtractToGpr { dest, .. }) => vec![dest.reg],
        Stmt::WideMul { .. } | Stmt::Divide { .. } => vec![Reg::Rax, Reg::Rdx],
        Stmt::Call { .. } => vec![Reg::Rax],
        _ => Vec::new(),
    }
}

#[derive(Debug, Default)]
struct SubIdentity {
    origin: BTreeMap<Reg, Reg>,
    diff: BTreeMap<Reg, (Reg, Reg)>,
}

impl SubIdentity {
    fn origin_of(&self, reg: Reg) -> Reg {
        *self.origin.get(&reg).unwrap_or(&reg)
    }

    fn observe(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign {
                dest,
                src: Source::Reg(src),
            } => {
                let root: Reg = self.origin_of(src.reg);
                self.diff.remove(&dest.reg);
                if root == dest.reg {
                    self.origin.remove(&dest.reg);
                } else {
                    self.origin.insert(dest.reg, root);
                }
            }
            Stmt::BinAssign {
                dest,
                op: BinOp::Sub,
                src: Source::Reg(src),
            } => {
                let minuend: Reg = self.origin_of(dest.reg);
                let subtrahend: Reg = self.origin_of(src.reg);
                self.origin.remove(&dest.reg);
                self.diff.insert(dest.reg, (minuend, subtrahend));
            }
            other => {
                for reg in stmt_dest_regs(other) {
                    self.origin.remove(&reg);
                    self.diff.remove(&reg);
                }
            }
        }
    }

    fn is_diff_of(&self, reg: Reg, lo: Reg, ro: Reg) -> bool {
        self.diff
            .get(&reg)
            .is_some_and(|&(a, b): &(Reg, Reg)| (a == lo && b == ro) || (a == ro && b == lo))
    }

    fn selects_operand_and_difference(&self, cmp: &Flags, src: &Source, dest: RegRef) -> bool {
        let (lhs, rhs): (Reg, Reg) = match cmp {
            Flags::Cmp {
                lhs,
                rhs: Source::Reg(rhs),
            } => (lhs.reg, rhs.reg),
            _ => return false,
        };
        let (lo, ro): (Reg, Reg) = (self.origin_of(lhs), self.origin_of(rhs));
        let operands: [Option<Reg>; 2] = [
            Some(dest.reg),
            match src {
                Source::Reg(r) => Some(r.reg),
                _ => None,
            },
        ];
        let mut has_diff: bool = false;
        let mut has_bare: bool = false;
        for reg in operands.into_iter().flatten() {
            if self.is_diff_of(reg, lo, ro) {
                has_diff = true;
            } else {
                let root: Reg = self.origin_of(reg);
                if root == lo || root == ro {
                    has_bare = true;
                }
            }
        }
        has_diff && has_bare
    }
}

fn near_miss_ordering_select(items: &[Item], cmp: &Flags, src: &Source, dest: RegRef) -> bool {
    let mut identity: SubIdentity = SubIdentity::default();
    for item in items {
        if let ItemKind::Stmt(stmt) = &item.kind {
            identity.observe(stmt);
        }
    }
    identity.selects_operand_and_difference(cmp, src, dest)
}

fn fp_stmt_result_xmm(stmt: &Stmt) -> Option<(Xmm, FpWidth)> {
    match stmt {
        Stmt::FpBin { dest, width, .. } | Stmt::FpMov { dest, width, .. } => Some((*dest, *width)),
        Stmt::IntToFp { dest, width, .. } => Some((*dest, *width)),
        Stmt::FpConvert { dest, to, .. } => Some((*dest, *to)),
        Stmt::FpMinMax { dest, width, .. }
        | Stmt::FpFma { dest, width, .. }
        | Stmt::FpCsel { dest, width, .. } => Some((*dest, *width)),
        Stmt::FpSqrt { dest, width, .. }
        | Stmt::FpUnary { dest, width, .. }
        | Stmt::FpRound { dest, width, .. }
        | Stmt::GprToXmm { dest, width, .. } => Some((*dest, *width)),
        _ => None,
    }
}

fn stmt_writes_rax_int(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { dest, .. }
        | Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. } => dest.reg == Reg::Rax,
        Stmt::WideMul { .. } | Stmt::Divide { .. } | Stmt::Call { .. } => true,
        Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpStore { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(_)
        | Stmt::FlagSnapshot { .. } => false,
    }
}

fn fp_return_after(current: Option<FpWidth>, stmt: &Stmt) -> Option<FpWidth> {
    if let Some((dest, width)) = fp_stmt_result_xmm(stmt)
        && dest == Xmm::Xmm0
    {
        return Some(width);
    }
    if stmt_writes_rax_int(stmt) {
        return None;
    }
    current
}

fn is_rip_relative_mem(token: &str) -> bool {
    let trimmed: &str = token.trim();
    let bracketed: &str = trimmed
        .strip_prefix('[')
        .or_else(|| {
            trimmed
                .split_once(char::is_whitespace)
                .filter(|(kw, _): &(&str, &str)| size_keyword_width(kw.trim()).is_some())
                .map(|(_, rest): (&str, &str)| rest.trim())
                .and_then(|rest: &str| rest.strip_prefix('['))
        })
        .unwrap_or("");
    bracketed.trim_start().starts_with("rel ")
}

fn resolve_fp_const(site: u64, width: FpWidth, consts: &[FpConstant]) -> Option<FpOperand> {
    let entry: &FpConstant = consts.iter().find(|c: &&FpConstant| c.site == site)?;
    let bits: u64 = match width {
        FpWidth::F32 => u64::from(entry.bits as u32),
        FpWidth::F64 => entry.bits,
    };
    Some(FpOperand::Const { bits, width })
}

fn parse_fp_operand(
    token: &str,
    width: FpWidth,
    site: u64,
    consts: &[FpConstant],
) -> Result<FpOperand> {
    if let Some(xmm) = parse_xmm(token) {
        return Ok(FpOperand::Xmm(xmm));
    }
    if is_rip_relative_mem(token) {
        return resolve_fp_const(site, width, consts).ok_or_else(|| {
            Error::LlvmIr(format!(
                "rip-relative float operand at {site:#x} has no resolved .rodata constant"
            ))
        });
    }
    if is_mem_token(token) {
        let fallback: Width = match width {
            FpWidth::F32 => Width::W32,
            FpWidth::F64 => Width::W64,
        };
        let mem: MemRef = parse_mem_access(token, Some(fallback)).ok_or_else(|| {
            Error::LlvmIr(format!("float memory operand `{token}` is unsupported"))
        })?;
        return Ok(FpOperand::Mem(mem));
    }
    Err(Error::LlvmIr(format!(
        "float operand `{token}` unsupported"
    )))
}

fn fp_arith_kind(mnemonic: &str) -> Option<(FpOp, FpWidth)> {
    Some(match mnemonic {
        "addsd" => (FpOp::Add, FpWidth::F64),
        "subsd" => (FpOp::Sub, FpWidth::F64),
        "mulsd" => (FpOp::Mul, FpWidth::F64),
        "divsd" => (FpOp::Div, FpWidth::F64),
        "addss" => (FpOp::Add, FpWidth::F32),
        "subss" => (FpOp::Sub, FpWidth::F32),
        "mulss" => (FpOp::Mul, FpWidth::F32),
        "divss" => (FpOp::Div, FpWidth::F32),
        _ => return None,
    })
}

fn fp_minmax_kind(mnemonic: &str) -> Option<(bool, FpWidth)> {
    Some(match mnemonic {
        "minsd" => (false, FpWidth::F64),
        "maxsd" => (true, FpWidth::F64),
        "minss" => (false, FpWidth::F32),
        "maxss" => (true, FpWidth::F32),
        _ => return None,
    })
}

const REJECTED_SSE: &[&str] = &[
    "addpd",
    "subpd",
    "mulpd",
    "divpd",
    "addps",
    "subps",
    "mulps",
    "divps",
    "andpd",
    "andps",
    "andnpd",
    "andnps",
    "orpd",
    "orps",
    "xorpd",
    "xorps",
    "pxor",
    "shufps",
    "shufpd",
    "unpckhpd",
    "unpcklpd",
    "unpckhps",
    "unpcklps",
    "sqrtpd",
    "sqrtps",
    "maxpd",
    "minpd",
    "cmpsd",
    "cmpss",
    "cmpltsd",
    "cmpltss",
    "cmplesd",
    "cmpless",
    "cmpeqsd",
    "cmpeqss",
    "cmpneqsd",
    "cmpneqss",
    "cmpnlesd",
    "cmpnless",
    "cmpnltsd",
    "cmpnltss",
    "haddpd",
    "hsubpd",
    "haddps",
    "hsubps",
    "movhps",
    "movlps",
    "movhpd",
    "movlpd",
    "movddup",
    "movsldup",
    "movshdup",
    "pshufd",
    "cvtdq2pd",
    "cvtpd2dq",
    "cvtps2pd",
    "cvtpd2ps",
    "blendpd",
    "blendps",
    "movmskpd",
    "movmskps",
    "punpcklqdq",
    "punpckhqdq",
];

const PACKED_INT_MARKERS: &[&str] = &[
    "movdqa",
    "movdqu",
    "paddq",
    "paddd",
    "psubq",
    "psubd",
    "pand",
    "pandn",
    "por",
    "psllq",
    "psrlq",
    "pslldq",
    "psrldq",
    "pcmpeqd",
    "pcmpeqq",
    "pcmpeqb",
    "pcmpgtd",
    "pshufd",
    "punpcklqdq",
    "punpckhqdq",
    "punpckldq",
    "punpckhdq",
];

fn uses_packed_integer_sse(insns: &[DisasmInsn]) -> bool {
    insns
        .iter()
        .any(|insn: &DisasmInsn| PACKED_INT_MARKERS.contains(&insn.mnemonic.as_str()))
}

fn packed_xmm_pair(operands: &str) -> Option<(Xmm, Xmm)> {
    let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
    Some((parse_xmm(lhs.trim())?, parse_xmm(rhs.trim())?))
}

fn lift_packed(
    mnemonic: &str,
    operands: &str,
    site: u64,
    consts: &[PackedConstant],
) -> Result<Option<Stmt>> {
    if !operands.contains("xmm") {
        return Ok(None);
    }
    let reject = |detail: &str| -> Result<Option<Stmt>> {
        Err(Error::LlvmIr(format!(
            "unmodeled packed SSE `{mnemonic} {operands}` at {site:#x}: {detail}"
        )))
    };
    let (lhs, rhs): (&str, &str) = operands
        .split_once(',')
        .ok_or_else(|| Error::LlvmIr(format!("malformed packed `{mnemonic}` at {site:#x}")))?;
    let lhs: &str = lhs.trim();
    let rhs: &str = rhs.trim();
    match mnemonic {
        "movq" | "movd" => {
            if let Some(dest) = parse_xmm(lhs) {
                if let Some(src) = parse_reg(rhs) {
                    return Ok(Some(Stmt::Packed {
                        dest,
                        op: PackedOp::FromGpr { src },
                    }));
                }
                return reject("movq/movd into xmm from a non-gpr source is unmodeled");
            }
            if let (Some(dest), Some(src)) = (parse_reg(lhs), parse_xmm(rhs)) {
                return Ok(Some(Stmt::PackedToGpr { dest, src }));
            }
            reject("movq/movd form is unmodeled")
        }
        "movdqa" | "movdqu" => {
            let dest: Xmm = parse_xmm(lhs)
                .ok_or_else(|| Error::LlvmIr(format!("movdqa dest not xmm at {site:#x}")))?;
            if let Some(src) = parse_xmm(rhs) {
                return Ok(Some(Stmt::Packed {
                    dest,
                    op: PackedOp::MovReg(src),
                }));
            }
            if is_rip_relative_mem(rhs) {
                let Some(k): Option<&PackedConstant> =
                    consts.iter().find(|c: &&PackedConstant| c.site == site)
                else {
                    return reject("rip-relative packed constant not resolved from .rodata");
                };
                return Ok(Some(Stmt::Packed {
                    dest,
                    op: PackedOp::Const { q0: k.q0, q1: k.q1 },
                }));
            }
            reject("movdqa memory source is not a resolvable rip-relative constant")
        }
        "pxor" => {
            let (dest, src): (Xmm, Xmm) = packed_xmm_pair(operands)
                .ok_or_else(|| Error::LlvmIr("pxor operands".to_owned()))?;
            if dest == src {
                return Ok(Some(Stmt::Packed {
                    dest,
                    op: PackedOp::Zero,
                }));
            }
            reject("pxor of two distinct registers is unmodeled")
        }
        "paddq" => {
            let (dest, src): (Xmm, Xmm) = packed_xmm_pair(operands)
                .ok_or_else(|| Error::LlvmIr("paddq operands".to_owned()))?;
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::AddQ(src),
            }))
        }
        "pand" => {
            let (dest, src): (Xmm, Xmm) = packed_xmm_pair(operands)
                .ok_or_else(|| Error::LlvmIr("pand operands".to_owned()))?;
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::And(src),
            }))
        }
        "pandn" => {
            let (dest, src): (Xmm, Xmm) = packed_xmm_pair(operands)
                .ok_or_else(|| Error::LlvmIr("pandn operands".to_owned()))?;
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::AndN(src),
            }))
        }
        "pcmpeqd" => {
            let (dest, src): (Xmm, Xmm) = packed_xmm_pair(operands)
                .ok_or_else(|| Error::LlvmIr("pcmpeqd operands".to_owned()))?;
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::CmpEqD(src),
            }))
        }
        "psllq" => {
            let dest: Xmm = parse_xmm(lhs)
                .ok_or_else(|| Error::LlvmIr(format!("psllq dest not xmm at {site:#x}")))?;
            let imm: i64 = parse_imm(rhs)
                .ok_or_else(|| Error::LlvmIr(format!("psllq needs an immediate at {site:#x}")))?;
            if !(0..=255).contains(&imm) {
                return reject("psllq by a register count is unmodeled");
            }
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::ShlQ(imm as u8),
            }))
        }
        "pslldq" => {
            let dest: Xmm = parse_xmm(lhs)
                .ok_or_else(|| Error::LlvmIr(format!("pslldq dest not xmm at {site:#x}")))?;
            let imm: i64 = parse_imm(rhs)
                .ok_or_else(|| Error::LlvmIr(format!("pslldq needs an immediate at {site:#x}")))?;
            if !(0..=255).contains(&imm) {
                return reject("pslldq by a register count is unmodeled");
            }
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::ShlDq(imm as u8),
            }))
        }
        "pshufd" => {
            let mut parts = operands.splitn(3, ',');
            let dest_tok: &str = parts.next().unwrap_or("").trim();
            let src_tok: &str = parts.next().unwrap_or("").trim();
            let imm_tok: &str = parts.next().unwrap_or("").trim();
            let dest: Xmm = parse_xmm(dest_tok)
                .ok_or_else(|| Error::LlvmIr(format!("pshufd dest not xmm at {site:#x}")))?;
            let Some(src): Option<Xmm> = parse_xmm(src_tok) else {
                return reject("pshufd from a memory operand is unmodeled");
            };
            let imm: i64 = parse_imm(imm_tok)
                .ok_or_else(|| Error::LlvmIr(format!("pshufd needs an imm8 at {site:#x}")))?;
            if !(0..=255).contains(&imm) {
                return reject("pshufd control byte out of range");
            }
            Ok(Some(Stmt::Packed {
                dest,
                op: PackedOp::ShufD {
                    src,
                    imm: imm as u8,
                },
            }))
        }
        _ => reject("xmm-touching instruction outside the recovered packed-integer class"),
    }
}

fn lift_fp_compare(
    mnemonic: &str,
    operands: &str,
    site: u64,
    consts: &[FpConstant],
) -> Result<Option<Flags>> {
    let width: FpWidth = match mnemonic {
        "ucomisd" | "comisd" => FpWidth::F64,
        "ucomiss" | "comiss" => FpWidth::F32,
        _ => return Ok(None),
    };
    let (lhs, rhs): (&str, &str) = operands
        .split_once(',')
        .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
    let lhs_xmm: Xmm = parse_xmm(lhs.trim())
        .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` lhs is not an xmm register")))?;
    let rhs_operand: FpOperand = parse_fp_operand(rhs.trim(), width, site, consts)?;
    Ok(Some(Flags::FpCmp {
        lhs: lhs_xmm,
        rhs: rhs_operand,
        width,
        model: FpUnorderedModel::UnorderedIsEqual,
    }))
}

fn lift_fp(
    mnemonic: &str,
    operands: &str,
    site: u64,
    consts: &[FpConstant],
) -> Result<Option<Stmt>> {
    let reject = |m: &str| -> Result<Option<Stmt>> {
        Err(Error::LlvmIr(format!(
            "unmodeled SSE/packed instruction `{m}` outside the scalar float leaf class"
        )))
    };
    if matches!(mnemonic, "xorps" | "xorpd" | "pxor") {
        if let Some((lhs, rhs)) = operands.split_once(',')
            && let Some(dest) = parse_xmm(lhs.trim())
            && let Some(src) = parse_xmm(rhs.trim())
            && dest == src
        {
            return Ok(Some(Stmt::FpMov {
                dest,
                src: FpOperand::Const {
                    bits: 0,
                    width: FpWidth::F64,
                },
                width: FpWidth::F64,
            }));
        }
        return reject(mnemonic);
    }
    if REJECTED_SSE.contains(&mnemonic) {
        return reject(mnemonic);
    }
    if let Some((op, width)) = fp_arith_kind(mnemonic) {
        let (lhs, rhs): (&str, &str) = operands
            .split_once(',')
            .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
        let dest: Xmm = parse_xmm(lhs.trim())
            .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest is not an xmm register")))?;
        let rhs_operand: FpOperand = parse_fp_operand(rhs.trim(), width, site, consts)?;
        return Ok(Some(Stmt::FpBin {
            dest,
            lhs: FpOperand::Xmm(dest),
            rhs: rhs_operand,
            op,
            width,
        }));
    }
    if let Some((is_max, width)) = fp_minmax_kind(mnemonic) {
        let (lhs, rhs): (&str, &str) = operands
            .split_once(',')
            .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
        let dest: Xmm = parse_xmm(lhs.trim())
            .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest is not an xmm register")))?;
        let rhs_operand: FpOperand = parse_fp_operand(rhs.trim(), width, site, consts)?;
        let kind: FpMinMaxKind = if is_max {
            FpMinMaxKind::SelectMax
        } else {
            FpMinMaxKind::SelectMin
        };
        return Ok(Some(Stmt::FpMinMax {
            dest,
            lhs: FpOperand::Xmm(dest),
            rhs: rhs_operand,
            kind,
            width,
        }));
    }
    match mnemonic {
        "movsd" | "movss" => {
            let width: FpWidth = if mnemonic == "movsd" {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let lhs_tok: &str = lhs.trim();
            let rhs_tok: &str = rhs.trim();
            if let Some(dest) = parse_xmm(lhs_tok) {
                let src: FpOperand = parse_fp_operand(rhs_tok, width, site, consts)?;
                return Ok(Some(Stmt::FpMov { dest, src, width }));
            }
            if is_mem_token(lhs_tok) {
                let src: Xmm = parse_xmm(rhs_tok).ok_or_else(|| {
                    Error::LlvmIr(format!("`{mnemonic}` store source not an xmm register"))
                })?;
                let fallback: Width = match width {
                    FpWidth::F32 => Width::W32,
                    FpWidth::F64 => Width::W64,
                };
                let addr: MemRef = parse_mem_access(lhs_tok, Some(fallback)).ok_or_else(|| {
                    Error::LlvmIr(format!("`{mnemonic}` store address unsupported"))
                })?;
                return Ok(Some(Stmt::FpStore { addr, src, width }));
            }
            reject(mnemonic)
        }
        "movaps" | "movapd" | "movups" | "movupd" => {
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let dest: Xmm = parse_xmm(lhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest not an xmm register")))?;
            let src: Xmm = parse_xmm(rhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{mnemonic}` with a memory operand is outside the scalar float leaf class"
                ))
            })?;
            let width: FpWidth = if matches!(mnemonic, "movapd" | "movupd") {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            Ok(Some(Stmt::FpMov {
                dest,
                src: FpOperand::Xmm(src),
                width,
            }))
        }
        "cvtsi2sd" | "cvtsi2ss" => {
            let width: FpWidth = if mnemonic == "cvtsi2sd" {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let dest: Xmm = parse_xmm(lhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest not an xmm register")))?;
            let src: RegRef = fp_convert_int_operand(rhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` integer source unsupported")))?;
            Ok(Some(Stmt::IntToFp {
                dest,
                src,
                signed: true,
                width,
                fbits: None,
            }))
        }
        "cvttsd2si" | "cvttss2si" | "cvtsd2si" | "cvtss2si" => {
            let width: FpWidth = if matches!(mnemonic, "cvttsd2si" | "cvtsd2si") {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            if matches!(mnemonic, "cvtsd2si" | "cvtss2si") {
                return reject(mnemonic);
            }
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let dest: RegRef = parse_reg(lhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest not a register")))?;
            if !matches!(dest.width, Width::W32 | Width::W64) {
                return reject(mnemonic);
            }
            let src: Xmm = parse_xmm(rhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` source not an xmm register")))?;
            Ok(Some(Stmt::FpToInt {
                dest,
                src,
                width,
                signed: true,
                round: FpToIntRound::Zero,
                fbits: None,
                saturating: false,
            }))
        }
        "cvtsd2ss" | "cvtss2sd" => {
            let (from, to): (FpWidth, FpWidth) = if mnemonic == "cvtsd2ss" {
                (FpWidth::F64, FpWidth::F32)
            } else {
                (FpWidth::F32, FpWidth::F64)
            };
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let dest: Xmm = parse_xmm(lhs.trim())
                .ok_or_else(|| Error::LlvmIr(format!("`{mnemonic}` dest not an xmm register")))?;
            let src: Xmm = parse_xmm(rhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{mnemonic}` with a memory operand is outside the scalar float leaf class"
                ))
            })?;
            Ok(Some(Stmt::FpConvert {
                dest,
                src,
                from,
                to,
            }))
        }
        "sqrtsd" | "sqrtss" => {
            let width: FpWidth = if mnemonic == "sqrtsd" {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let dest: Xmm = parse_xmm(lhs.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("`{mnemonic}` dest is not an xmm register"))
            })?;
            let src: FpOperand = parse_fp_operand(rhs.trim(), width, site, consts)?;
            Ok(Some(Stmt::FpSqrt {
                dest,
                src,
                width,
                saturating: false,
            }))
        }
        "roundsd" | "roundss" => {
            let width: FpWidth = if mnemonic == "roundsd" {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            let (dest_tok, rest): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let (src_tok, imm_tok): (&str, &str) = rest.split_once(',').ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{mnemonic}` requires an imm8 rounding-control operand"
                ))
            })?;
            let dest: Xmm = parse_xmm(dest_tok.trim()).ok_or_else(|| {
                Error::LlvmIr(format!("`{mnemonic}` dest is not an xmm register"))
            })?;
            let src: FpOperand = parse_fp_operand(src_tok.trim(), width, site, consts)?;
            let imm: i64 = parse_imm(imm_tok.trim()).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{mnemonic}` imm8 rounding control is not an integer literal"
                ))
            })?;
            let mode: RoundMode = RoundMode::from_imm8(imm).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{mnemonic}` imm8 {imm:#x} defers to the MXCSR rounding mode; the runtime rounding direction is not statically recoverable"
                ))
            })?;
            Ok(Some(Stmt::FpRound {
                dest,
                src,
                width,
                mode,
            }))
        }
        "movq" | "movd" => {
            let width: FpWidth = if mnemonic == "movq" {
                FpWidth::F64
            } else {
                FpWidth::F32
            };
            let gpr_width: Width = if mnemonic == "movq" {
                Width::W64
            } else {
                Width::W32
            };
            let (lhs, rhs): (&str, &str) = operands
                .split_once(',')
                .ok_or_else(|| Error::LlvmIr(format!("malformed `{mnemonic}` operands")))?;
            let lt: &str = lhs.trim();
            let rt: &str = rhs.trim();
            match (parse_xmm(lt), parse_xmm(rt)) {
                (Some(dest), Some(src)) => Ok(Some(Stmt::FpMov {
                    dest,
                    src: FpOperand::Xmm(src),
                    width,
                })),
                (Some(dest), None) => {
                    let src: RegRef = parse_reg(rt)
                        .filter(|r: &RegRef| r.width == gpr_width)
                        .ok_or_else(|| {
                            Error::LlvmIr(format!(
                                "`{mnemonic}` source is neither an xmm nor a width-matched gpr; memory and mmx forms are outside the scalar float leaf class"
                            ))
                        })?;
                    Ok(Some(Stmt::GprToXmm { dest, src, width }))
                }
                (None, Some(src)) => {
                    let dest: RegRef = parse_reg(lt)
                        .filter(|r: &RegRef| r.width == gpr_width)
                        .ok_or_else(|| {
                            Error::LlvmIr(format!(
                                "`{mnemonic}` destination is neither an xmm nor a width-matched gpr; memory and mmx forms are outside the scalar float leaf class"
                            ))
                        })?;
                    Ok(Some(Stmt::XmmToGpr { dest, src, width }))
                }
                (None, None) => Err(Error::LlvmIr(format!(
                    "`{mnemonic} {operands}` moves neither into nor out of an xmm register; memory and mmx forms are outside the scalar float leaf class"
                ))),
            }
        }
        _ => Ok(None),
    }
}

fn fp_convert_int_operand(token: &str) -> Option<RegRef> {
    if let Some(reg) = parse_reg(token) {
        return matches!(reg.width, Width::W32 | Width::W64).then_some(reg);
    }
    None
}

fn lift_one(mnemonic: &str, operands: &str) -> Option<Stmt> {
    let (lhs, rhs): (&str, Option<&str>) = match operands.split_once(',') {
        Some((a, b)) => (a.trim(), Some(b.trim())),
        None => (operands.trim(), None),
    };
    match mnemonic {
        "mov" => {
            let rhs_tok: &str = rhs?;
            if is_mem_token(lhs) {
                let dest_w: Option<Width> = parse_reg(rhs_tok).map(|r: RegRef| r.width);
                let addr: MemRef = parse_mem_access(lhs, dest_w)?;
                let src: Source = parse_source(rhs_tok)?;
                return Some(Stmt::Store { addr, src });
            }
            let dest: RegRef = parse_reg(lhs)?;
            if is_mem_token(rhs_tok) {
                let mem: MemRef = parse_mem_access(rhs_tok, Some(dest.width))?;
                return Some(Stmt::Assign {
                    dest,
                    src: Source::Mem(mem),
                });
            }
            let src: Source = parse_source(rhs_tok)?;
            Some(Stmt::Assign { dest, src })
        }
        "lea" => {
            let dest: RegRef = parse_reg(lhs)?;
            let src: Source = parse_mem(rhs?)?;
            Some(Stmt::Assign { dest, src })
        }
        "mul" => {
            if rhs.is_some() {
                return None;
            }
            let src: RegRef = parse_reg(lhs)?;
            (src.width == Width::W64).then_some(Stmt::WideMul { src })
        }
        "shld" | "shrd" => lift_double_shift(mnemonic, operands),
        "imul" if operands.matches(',').count() == 2 => lift_imul_ternary(operands),
        "add" | "sub" | "imul" | "and" | "or" | "xor" | "shl" | "sal" | "shr" | "sar" => {
            let rhs_tok: &str = rhs?;
            let op: BinOp = match mnemonic {
                "add" => BinOp::Add,
                "sub" => BinOp::Sub,
                "imul" => BinOp::Imul,
                "and" => BinOp::And,
                "or" => BinOp::Or,
                "xor" => BinOp::Xor,
                "shl" | "sal" => BinOp::Shl,
                "shr" => BinOp::Shr,
                "sar" => BinOp::Sar,
                _ => return None,
            };
            if is_mem_token(lhs) {
                if op == BinOp::Imul {
                    return None;
                }
                if is_mem_token(rhs_tok) {
                    return None;
                }
                let hint: Option<Width> = parse_reg(rhs_tok).map(|r: RegRef| r.width);
                let addr: MemRef = parse_mem_access(lhs, hint)?;
                let src: Source = parse_source(rhs_tok)?;
                return Some(Stmt::MemRmw {
                    addr,
                    op: MemRmwOp::Bin { op, src },
                });
            }
            let dest: RegRef = parse_reg(lhs)?;
            if matches!(mnemonic, "xor" | "sub")
                && parse_reg(rhs_tok).is_some_and(|r: RegRef| r.reg == dest.reg)
            {
                return Some(Stmt::Assign {
                    dest,
                    src: Source::Imm(0),
                });
            }
            let src: Source = if is_mem_token(rhs_tok) {
                Source::Mem(parse_mem_access(rhs_tok, Some(dest.width))?)
            } else {
                parse_source(rhs_tok)?
            };
            Some(Stmt::BinAssign { dest, op, src })
        }
        "inc" | "dec" => {
            if rhs.is_some() {
                return None;
            }
            let op: BinOp = if mnemonic == "inc" {
                BinOp::Add
            } else {
                BinOp::Sub
            };
            if is_mem_token(lhs) {
                let addr: MemRef = parse_mem_access(lhs, None)?;
                return Some(Stmt::MemRmw {
                    addr,
                    op: MemRmwOp::Bin {
                        op,
                        src: Source::Imm(1),
                    },
                });
            }
            let dest: RegRef = parse_reg(lhs)?;
            Some(Stmt::BinAssign {
                dest,
                op,
                src: Source::Imm(1),
            })
        }
        "neg" | "not" => {
            let op: UnOp = if mnemonic == "neg" {
                UnOp::Neg
            } else {
                UnOp::Not
            };
            if is_mem_token(lhs) {
                if rhs.is_some() {
                    return None;
                }
                let addr: MemRef = parse_mem_access(lhs, None)?;
                return Some(Stmt::MemRmw {
                    addr,
                    op: MemRmwOp::Un(op),
                });
            }
            let dest: RegRef = parse_reg(lhs)?;
            Some(Stmt::UnAssign { dest, op })
        }
        _ => None,
    }
}

fn lift_double_shift(mnemonic: &str, operands: &str) -> Option<Stmt> {
    let mut parts: std::str::Split<'_, char> = operands.split(',');
    let dest_tok: &str = parts.next()?.trim();
    let src_tok: &str = parts.next()?.trim();
    let amount_tok: &str = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }
    let dest: RegRef = parse_reg(dest_tok)?;
    let src: RegRef = parse_reg(src_tok)?;
    if dest.width != Width::W64 || src.width != Width::W64 {
        return None;
    }
    let amount: i64 = parse_imm(amount_tok)?;
    if !(1..=63).contains(&amount) {
        return None;
    }
    let amount: u8 = u8::try_from(amount).ok()?;
    Some(Stmt::DoubleShift {
        dest,
        src,
        amount,
        left: mnemonic == "shld",
    })
}

fn lift_imul_ternary(operands: &str) -> Option<Stmt> {
    let mut parts: std::str::Split<'_, char> = operands.split(',');
    let dest_tok: &str = parts.next()?.trim();
    let src_tok: &str = parts.next()?.trim();
    let imm_tok: &str = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }
    let dest: RegRef = parse_reg(dest_tok)?;
    if !matches!(dest.width, Width::W32 | Width::W64) {
        return None;
    }
    let imm: i64 = parse_imm(imm_tok)?;
    let src: ExtSource = if is_mem_token(src_tok) {
        let mem: MemRef = parse_mem_access(src_tok, Some(dest.width))?;
        if mem.width != dest.width {
            return None;
        }
        ExtSource::Mem(mem)
    } else {
        let reg: RegRef = parse_reg(src_tok)?;
        if reg.width != dest.width {
            return None;
        }
        ExtSource::Reg(reg)
    };
    Some(Stmt::MulImm { dest, src, imm })
}

fn parse_source(token: &str) -> Option<Source> {
    if let Some(reg) = parse_reg(token) {
        return Some(Source::Reg(reg));
    }
    parse_imm(token).map(Source::Imm)
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

fn parse_addr_terms(bracketed: &str) -> Option<AddrTerms> {
    let inner: &str = bracketed
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')?
        .trim();
    let mut base: Option<Reg> = None;
    let mut index: Option<IndexOperand> = None;
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
            let reg: RegRef = parse_reg(reg_tok.trim())?;
            if reg.width != Width::W64 {
                return None;
            }
            let scale: u8 = scale_tok.trim().parse::<u8>().ok()?;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return None;
            }
            index = Some(IndexOperand::full(reg.reg, scale));
            continue;
        }
        if let Some(reg) = parse_reg(term) {
            if reg.width != Width::W64 {
                return None;
            }
            if base.is_none() {
                base = Some(reg.reg);
            } else if index.is_none() {
                index = Some(IndexOperand::full(reg.reg, 1));
            } else {
                return None;
            }
            continue;
        }
        disp = disp.checked_add(parse_imm(term)?)?;
    }
    Some((base, index, disp))
}

fn parse_mem(token: &str) -> Option<Source> {
    let (base, index, disp): AddrTerms = parse_addr_terms(token)?;
    Some(Source::Lea { base, index, disp })
}

fn size_keyword_width(keyword: &str) -> Option<Width> {
    match keyword {
        "byte" => Some(Width::W8),
        "word" => Some(Width::W16),
        "dword" => Some(Width::W32),
        "qword" => Some(Width::W64),
        _ => None,
    }
}

fn is_mem_token(token: &str) -> bool {
    let trimmed: &str = token.trim();
    if trimmed.starts_with('[') {
        return true;
    }
    trimmed
        .split_once(char::is_whitespace)
        .and_then(|(kw, rest): (&str, &str)| {
            size_keyword_width(kw.trim()).map(|_| rest.trim().starts_with('['))
        })
        .unwrap_or(false)
}

fn parse_mem_access(token: &str, reg_width: Option<Width>) -> Option<MemRef> {
    let trimmed: &str = token.trim();
    let (width, bracketed): (Width, &str) = if trimmed.starts_with('[') {
        (reg_width?, trimmed)
    } else {
        let (kw, rest): (&str, &str) = trimmed.split_once(char::is_whitespace)?;
        let keyword_width: Width = size_keyword_width(kw.trim())?;
        (keyword_width, rest.trim())
    };
    let (base, index, disp): AddrTerms = parse_addr_terms(bracketed)?;
    if base.is_none() && index.is_none() {
        return None;
    }
    Some(MemRef {
        base,
        index,
        disp,
        width,
    })
}

const fn reg_var(reg: Reg) -> &'static str {
    match reg {
        Reg::Rax => "r_rax",
        Reg::Rbx => "r_rbx",
        Reg::Rcx => "r_rcx",
        Reg::Rdx => "r_rdx",
        Reg::Rsi => "r_rsi",
        Reg::Rdi => "r_rdi",
        Reg::Rbp => "r_rbp",
        Reg::Rsp => "r_rsp",
        Reg::R8 => "r_r8",
        Reg::R9 => "r_r9",
        Reg::R10 => "r_r10",
        Reg::R11 => "r_r11",
        Reg::R12 => "r_r12",
        Reg::R13 => "r_r13",
        Reg::R14 => "r_r14",
        Reg::R15 => "r_r15",
        Reg::A64X1 => "r_a64_x1",
        Reg::A64X2 => "r_a64_x2",
        Reg::A64X3 => "r_a64_x3",
        Reg::A64X4 => "r_a64_x4",
        Reg::A64X5 => "r_a64_x5",
        Reg::A64X6 => "r_a64_x6",
        Reg::A64X7 => "r_a64_x7",
        Reg::A64X8 => "r_a64_x8",
        Reg::A64X9 => "r_a64_x9",
        Reg::A64X10 => "r_a64_x10",
        Reg::A64X11 => "r_a64_x11",
        Reg::A64X12 => "r_a64_x12",
        Reg::A64X13 => "r_a64_x13",
        Reg::A64X14 => "r_a64_x14",
        Reg::A64X15 => "r_a64_x15",
        Reg::A64X16 => "r_a64_x16",
        Reg::A64X17 => "r_a64_x17",
        Reg::A64X18 => "r_a64_x18",
        Reg::A64X19 => "r_a64_x19",
        Reg::A64X20 => "r_a64_x20",
        Reg::A64X21 => "r_a64_x21",
        Reg::A64X22 => "r_a64_x22",
        Reg::A64X23 => "r_a64_x23",
        Reg::A64X24 => "r_a64_x24",
        Reg::A64X25 => "r_a64_x25",
        Reg::A64X26 => "r_a64_x26",
        Reg::A64X27 => "r_a64_x27",
        Reg::A64X28 => "r_a64_x28",
        Reg::A64Stack0 => "r_a64_stack0",
        Reg::A64Stack1 => "r_a64_stack1",
        Reg::A64Stack2 => "r_a64_stack2",
        Reg::A64Stack3 => "r_a64_stack3",
        Reg::A64Stack4 => "r_a64_stack4",
        Reg::A64Stack5 => "r_a64_stack5",
        Reg::A64Stack6 => "r_a64_stack6",
        Reg::A64Stack7 => "r_a64_stack7",
        Reg::A64Outgoing0 => "r_a64_outgoing0",
        Reg::A64Outgoing1 => "r_a64_outgoing1",
        Reg::A64Outgoing2 => "r_a64_outgoing2",
        Reg::A64Outgoing3 => "r_a64_outgoing3",
        Reg::A64Outgoing4 => "r_a64_outgoing4",
        Reg::A64Outgoing5 => "r_a64_outgoing5",
        Reg::A64Outgoing6 => "r_a64_outgoing6",
        Reg::A64Outgoing7 => "r_a64_outgoing7",
        Reg::A64Tmp => "r_a64_tmp",
        Reg::A64Tmp2 => "r_a64_tmp2",
        Reg::A64FlagLhs => "r_a64_flag_lhs",
        Reg::A64FlagRhs => "r_a64_flag_rhs",
    }
}

fn loop_cond_var(var: u32) -> String {
    format!("loop_cond_{var}")
}

fn sel_var(var: u32) -> String {
    format!("sel_cc_{var}")
}

fn collect_sel_vars(body: &Block, acc: &mut Vec<u32>) {
    for node in body {
        match node {
            Node::Stmt(Stmt::FlagSnapshot { var, .. }) => {
                if !acc.contains(var) {
                    acc.push(*var);
                }
            }
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_sel_vars(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_sel_vars(else_b, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => collect_sel_vars(body, acc),
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_sel_vars(&case.body, acc);
                }
                collect_sel_vars(default, acc);
            }
            Node::Stmt(_)
            | Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn collect_snapshot_vars(body: &Block, acc: &mut Vec<u32>) {
    for node in body {
        match node {
            Node::CondSnapshot { var, .. } => {
                if !acc.contains(var) {
                    acc.push(*var);
                }
            }
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_snapshot_vars(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_snapshot_vars(else_b, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_snapshot_vars(body, acc);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_snapshot_vars(&case.body, acc);
                }
                collect_snapshot_vars(default, acc);
            }
            Node::Stmt(_)
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

const C_RENDER_WIDTH: usize = 1 << 20;

fn c_render(build: impl FnOnce(&mut Cx<'_>) -> CExpr) -> String {
    let mut interner: Interner = Interner::new();
    let expr: CExpr = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        build(&mut cx)
    };
    render_expr(&expr, &interner, C_RENDER_WIDTH)
}

fn c_opaque(cx: &mut Cx<'_>, text: &str) -> CExpr {
    cx.var(&format!("({text})"))
}

fn c_bin(op: BinaryOp, lhs: CExpr, rhs: CExpr) -> CExpr {
    CExpr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn c_hex_mask(value: u128) -> CExpr {
    CExpr::Int {
        value: value as u64,
        radix: Radix::Hex,
        suffix: IntSuffix {
            unsigned: true,
            long: LongSuffix::LongLong,
        },
    }
}

fn c_i64_literal(value: i64) -> CExpr {
    let suffix: IntSuffix = IntSuffix {
        unsigned: false,
        long: LongSuffix::LongLong,
    };
    if value < 0 {
        CExpr::Unary {
            op: UnaryOp::Neg,
            operand: Box::new(CExpr::Int {
                value: value.unsigned_abs(),
                radix: Radix::Dec,
                suffix,
            }),
        }
    } else {
        CExpr::Int {
            value: value as u64,
            radix: Radix::Dec,
            suffix,
        }
    }
}

fn c_cast(cx: &mut Cx<'_>, ty_name: &str, operand: CExpr) -> CExpr {
    CExpr::Cast {
        ty: TypeName::plain(CTypeSpec::Named(cx.sym(ty_name))),
        operand: Box::new(operand),
    }
}

fn c_ptr_cast(cx: &mut Cx<'_>, base_ty: &str, operand: CExpr) -> CExpr {
    c_cast(cx, &format!("{base_ty}*"), operand)
}

fn c_deref(cx: &mut Cx<'_>, ty: &str, addr: &str) -> CExpr {
    let opaque: CExpr = c_opaque(cx, addr);
    let ptr_cast: CExpr = c_cast(cx, "uintptr_t", opaque);
    let typed_ptr: CExpr = c_ptr_cast(cx, ty, ptr_cast);
    CExpr::Unary {
        op: UnaryOp::Deref,
        operand: Box::new(typed_ptr),
    }
}

fn fold_add(terms: Vec<CExpr>) -> CExpr {
    let mut iter: std::vec::IntoIter<CExpr> = terms.into_iter();
    let first: CExpr = iter.next().unwrap_or_else(|| CExpr::int(0));
    iter.fold(first, |acc: CExpr, term: CExpr| {
        c_bin(BinaryOp::Add, acc, term)
    })
}

fn width_mask(out: &mut String, width: Width, body: &str) {
    match width {
        Width::W64 => {
            let _ = write!(out, "{body}");
        }
        other => {
            let mask: u128 = (1u128 << other.bits()) - 1;
            let rendered: String =
                c_render(|cx| c_bin(BinaryOp::BitAnd, c_opaque(cx, body), c_hex_mask(mask)));
            let _ = write!(out, "{rendered}");
        }
    }
}

fn c_bswap_expr(operand: &str, width: Width) -> String {
    let bits: u32 = width.bits().max(16);
    format!("__builtin_bswap{bits}((uint{bits}_t)({operand}))")
}

fn c_rev32_expr(operand: &str) -> String {
    format!(
        "((((uint64_t)({operand}) & 0x000000ff000000ffull) << 24) | (((uint64_t)({operand}) & 0x0000ff000000ff00ull) << 8) | (((uint64_t)({operand}) & 0x00ff000000ff0000ull) >> 8) | (((uint64_t)({operand}) & 0xff000000ff000000ull) >> 24))"
    )
}

fn c_rev16_expr(operand: &str, width: Width) -> String {
    let bits: u32 = width.bits().max(32);
    let (hi, lo): (&str, &str) = if bits >= 64 {
        ("0xff00ff00ff00ff00ull", "0x00ff00ff00ff00ffull")
    } else {
        ("0xff00ff00u", "0x00ff00ffu")
    };
    format!(
        "((((uint{bits}_t)({operand}) & {hi}) >> 8) | (((uint{bits}_t)({operand}) & {lo}) << 8))"
    )
}

fn c_clz_expr(operand: &str, width: Width) -> String {
    if width.bits() >= 64 {
        format!(
            "((uint64_t)({operand}) == 0 ? 64ull : (uint64_t)__builtin_clzll((uint64_t)({operand})))"
        )
    } else {
        format!(
            "((uint32_t)({operand}) == 0 ? 32u : (uint32_t)__builtin_clz((uint32_t)({operand})))"
        )
    }
}

fn c_rbit_expr(operand: &str, width: Width) -> String {
    if width.bits() >= 64 {
        format!(
            "({{ uint64_t _rb = (uint64_t)({operand}); \
             _rb = ((_rb & 0x5555555555555555ull) << 1) | ((_rb >> 1) & 0x5555555555555555ull); \
             _rb = ((_rb & 0x3333333333333333ull) << 2) | ((_rb >> 2) & 0x3333333333333333ull); \
             _rb = ((_rb & 0x0f0f0f0f0f0f0f0full) << 4) | ((_rb >> 4) & 0x0f0f0f0f0f0f0f0full); \
             _rb = ((_rb & 0x00ff00ff00ff00ffull) << 8) | ((_rb >> 8) & 0x00ff00ff00ff00ffull); \
             _rb = ((_rb & 0x0000ffff0000ffffull) << 16) | ((_rb >> 16) & 0x0000ffff0000ffffull); \
             _rb = (_rb << 32) | (_rb >> 32); _rb; }})"
        )
    } else {
        format!(
            "({{ uint32_t _rb = (uint32_t)({operand}); \
             _rb = ((_rb & 0x55555555u) << 1) | ((_rb >> 1) & 0x55555555u); \
             _rb = ((_rb & 0x33333333u) << 2) | ((_rb >> 2) & 0x33333333u); \
             _rb = ((_rb & 0x0f0f0f0fu) << 4) | ((_rb >> 4) & 0x0f0f0f0fu); \
             _rb = ((_rb & 0x00ff00ffu) << 8) | ((_rb >> 8) & 0x00ff00ffu); \
             _rb = (_rb << 16) | (_rb >> 16); _rb; }})"
        )
    }
}

fn reg_write_rhs(dest_var: &str, width: Width, body: &str) -> String {
    match width {
        Width::W64 => body.to_owned(),
        Width::W32 => {
            let mask: u128 = 0xffff_ffffu128;
            c_render(|cx| c_bin(BinaryOp::BitAnd, c_opaque(cx, body), c_hex_mask(mask)))
        }
        Width::W16 => {
            let (keep, val): (u128, u128) = (0xffff_ffff_ffff_0000u128, 0xffffu128);
            c_render(|cx| {
                c_bin(
                    BinaryOp::BitOr,
                    c_bin(BinaryOp::BitAnd, cx.var(dest_var), c_hex_mask(keep)),
                    c_bin(BinaryOp::BitAnd, c_opaque(cx, body), c_hex_mask(val)),
                )
            })
        }
        Width::W8 => {
            let (keep, val): (u128, u128) = (0xffff_ffff_ffff_ff00u128, 0xffu128);
            c_render(|cx| {
                c_bin(
                    BinaryOp::BitOr,
                    c_bin(BinaryOp::BitAnd, cx.var(dest_var), c_hex_mask(keep)),
                    c_bin(BinaryOp::BitAnd, c_opaque(cx, body), c_hex_mask(val)),
                )
            })
        }
    }
}

fn apply_index_extend(cx: &mut Cx<'_>, expr: CExpr, extend: IndexExtend) -> CExpr {
    match extend {
        IndexExtend::Full => expr,
        IndexExtend::SignExtendWord => {
            let truncated: CExpr = c_cast(cx, "uint32_t", expr);
            let signed: CExpr = c_cast(cx, "int32_t", truncated);
            let widened: CExpr = c_cast(cx, "int64_t", signed);
            c_cast(cx, "uint64_t", widened)
        }
        IndexExtend::ZeroExtendWord => {
            let truncated: CExpr = c_cast(cx, "uint32_t", expr);
            c_cast(cx, "uint64_t", truncated)
        }
    }
}

fn addr_expr(base: Option<Reg>, index: Option<IndexOperand>, disp: i64) -> String {
    c_render(|cx| {
        let mut terms: Vec<CExpr> = Vec::new();
        if let Some(b) = base {
            terms.push(cx.var(reg_var(b)));
        }
        if let Some(idx) = index {
            let scaled: CExpr = CExpr::Int {
                value: u64::from(idx.scale),
                radix: Radix::Dec,
                suffix: IntSuffix {
                    unsigned: true,
                    long: LongSuffix::LongLong,
                },
            };
            let index_expr: CExpr = cx.var(reg_var(idx.reg));
            let index_var: CExpr = apply_index_extend(cx, index_expr, idx.extend);
            terms.push(c_bin(BinaryOp::Mul, index_var, scaled));
        }
        if disp != 0 || terms.is_empty() {
            let signed: CExpr = c_cast(cx, "int64_t", c_i64_literal(disp));
            terms.push(c_cast(cx, "uint64_t", signed));
        }
        fold_add(terms)
    })
}

fn aggregate_field_name(disp: i64) -> String {
    format!("field_{disp:x}")
}

fn aggregate_member_name(scalar: AggregateScalar) -> String {
    let suffix: &str = match scalar {
        AggregateScalar::Integer(Width::W8) => "u8",
        AggregateScalar::Integer(Width::W16) => "u16",
        AggregateScalar::Integer(Width::W32) => "u32",
        AggregateScalar::Integer(Width::W64) => "u64",
        AggregateScalar::Float(FpWidth::F32) => "f32",
        AggregateScalar::Float(FpWidth::F64) => "f64",
    };
    format!("field_0_{suffix}")
}

fn aggregate_c_type_name(plan: &AggregatePlan, root: usize) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    let prefix: &str = match root_plan.shape {
        AggregateShape::Struct { .. } => "recovered_struct",
        AggregateShape::Array { .. } => "recovered_array",
        AggregateShape::Union { .. } => "recovered_union",
    };
    Some(format!("{prefix}_{root}_t"))
}

fn aggregate_c_local_name(plan: &AggregatePlan, root: usize) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    let prefix: &str = match root_plan.shape {
        AggregateShape::Struct { .. } => "recovered_struct",
        AggregateShape::Array { .. } => "recovered_array",
        AggregateShape::Union { .. } => "recovered_union",
    };
    Some(format!("{prefix}_{root}"))
}

fn aggregate_c_base(plan: &AggregatePlan, root: usize, base: Reg) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    if root_plan.bind_local {
        aggregate_c_local_name(plan, root)
    } else {
        let ty: String = aggregate_c_type_name(plan, root)?;
        Some(format!("(({ty} *)(uintptr_t){})", reg_var(base)))
    }
}

fn aggregate_c_mem_expr(
    mem: &MemRef,
    plan: &AggregatePlan,
    scalar: AggregateScalar,
) -> Option<(String, bool)> {
    match plan.access(mem, scalar)? {
        AggregateAccess::Field {
            root,
            base,
            disp,
            nested,
            ..
        } => {
            let base: String = aggregate_c_base(plan, root, base)?;
            let field: String = aggregate_field_name(disp);
            let expr: String = c_render(|cx| {
                let root_expr: CExpr = cx.var(&base);
                cx.member(root_expr, true, &field)
            });
            Some((expr, nested.is_some()))
        }
        AggregateAccess::Array {
            root, base, index, ..
        } => {
            let base: String = aggregate_c_base(plan, root, base)?;
            let expr: String = c_render(|cx| {
                let root_expr: CExpr = cx.var(&base);
                CExpr::Index {
                    base: Box::new(root_expr),
                    index: Box::new(cx.var(reg_var(index))),
                }
            });
            Some((expr, false))
        }
        AggregateAccess::UnionMember { root, base, scalar } => {
            let base: String = aggregate_c_base(plan, root, base)?;
            let member: String = aggregate_member_name(scalar);
            let expr: String = c_render(|cx| {
                let root_expr: CExpr = cx.var(&base);
                cx.member(root_expr, true, &member)
            });
            Some((expr, false))
        }
    }
}

fn deref_expr(mem: &MemRef, plan: &AggregatePlan) -> String {
    if let Some((expr, _)) = aggregate_c_mem_expr(mem, plan, AggregateScalar::Integer(mem.width)) {
        return expr;
    }
    let addr: String = addr_expr(mem.base, mem.index, mem.disp);
    let ty: &str = match mem.width {
        Width::W8 => "uint8_t",
        Width::W16 => "uint16_t",
        Width::W32 => "uint32_t",
        Width::W64 => "uint64_t",
    };
    let rendered: String = c_render(|cx| c_deref(cx, ty, &addr));
    format!("({rendered})")
}

fn slot_typed_lvalue(mem: &MemRef, plan: &AggregatePlan) -> Option<String> {
    let slot: SlotCType = plan.signed_frame_slot(mem)?;
    let addr: String = addr_expr(mem.base, mem.index, mem.disp);
    let rendered: String = c_render(|cx| c_deref(cx, slot.c_name(), &addr));
    Some(format!("({rendered})"))
}

fn slot_typed_rvalue(mem: &MemRef, plan: &AggregatePlan) -> Option<String> {
    let slot: SlotCType = plan.signed_frame_slot(mem)?;
    let addr: String = addr_expr(mem.base, mem.index, mem.disp);
    Some(c_render(|cx| {
        let deref: CExpr = c_deref(cx, slot.c_name(), &addr);
        let narrowed: CExpr = match slot.width {
            Width::W64 => deref,
            other => c_cast(cx, width_c_uint(other), deref),
        };
        c_cast(cx, "uint64_t", narrowed)
    }))
}

fn call_display_name(target: u64, name: Option<&str>) -> String {
    name.map_or_else(|| format!("sub_{target:x}"), str::to_owned)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallDecl {
    display_name: String,
    arg_count: usize,
}

fn collect_call_decls(body: &Block, acc: &mut Vec<CallDecl>) {
    for node in body {
        match node {
            Node::Stmt(Stmt::Call { target, args, name }) => {
                let display_name: String = call_display_name(*target, name.as_deref());
                if !acc
                    .iter()
                    .any(|d: &CallDecl| d.display_name == display_name)
                {
                    acc.push(CallDecl {
                        display_name,
                        arg_count: args.len(),
                    });
                }
            }
            Node::Stmt(_) => {}
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_call_decls(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_call_decls(else_b, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => collect_call_decls(body, acc),
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_call_decls(&case.body, acc);
                }
                collect_call_decls(default, acc);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn source_expr(src: &Source, width: Width, plan: &AggregatePlan) -> String {
    match src {
        Source::Reg(r) => {
            if r.width == width || width == Width::W64 {
                reg_var(r.reg).to_string()
            } else {
                let mask: u128 = (1u128 << r.width.bits()) - 1;
                let rv: &'static str = reg_var(r.reg);
                let rendered: String =
                    c_render(|cx| c_bin(BinaryOp::BitAnd, cx.var(rv), c_hex_mask(mask)));
                format!("({rendered})")
            }
        }
        Source::Imm(value) => {
            let imm: i64 = *value;
            c_render(|cx| {
                let signed: CExpr = c_cast(cx, "int64_t", c_i64_literal(imm));
                c_cast(cx, "uint64_t", signed)
            })
        }
        Source::Lea { base, index, disp } => addr_expr(*base, *index, *disp),
        Source::Mem(mem) => {
            if let Some(typed) = slot_typed_rvalue(mem, plan) {
                return typed;
            }
            let (d, pointer): (String, bool) =
                aggregate_c_mem_expr(mem, plan, AggregateScalar::Integer(mem.width))
                    .unwrap_or_else(|| (deref_expr(mem, plan), false));
            c_render(|cx| {
                let value: CExpr = cx.var(&d);
                let inner: CExpr = if pointer {
                    c_cast(cx, "uintptr_t", value)
                } else {
                    value
                };
                c_cast(cx, "uint64_t", inner)
            })
        }
    }
}

fn collect_fp_semantics_helpers(body: &Block, acc: &mut BTreeSet<&'static str>) {
    for node in body {
        match node {
            Node::Stmt(stmt) => match stmt {
                Stmt::FpMinMax { kind, width, .. } if kind.uses_helper() => {
                    acc.insert(fp_semantics::minmax_helper(
                        kind.is_max(),
                        kind.is_propagating_nan(),
                        *width,
                    ));
                }
                Stmt::FpFma { width, .. } => {
                    acc.insert(fp_semantics::fma_helper(*width));
                }
                Stmt::FpRound { width, mode, .. } => {
                    acc.insert(fp_semantics::rint_helper(*mode, *width));
                }
                Stmt::FpSqrt {
                    width, saturating, ..
                } => {
                    acc.insert(fp_semantics::sqrt_helper(*saturating, *width));
                }
                Stmt::FpToInt {
                    dest,
                    width,
                    signed,
                    round,
                    saturating,
                    ..
                } => {
                    match round {
                        FpToIntRound::Zero => {}
                        FpToIntRound::Floor => {
                            acc.insert(fp_semantics::rint_helper(RoundMode::Floor, *width));
                        }
                        FpToIntRound::Ceil => {
                            acc.insert(fp_semantics::rint_helper(RoundMode::Ceil, *width));
                        }
                        FpToIntRound::Away => {
                            acc.insert(fp_semantics::rint_helper(RoundMode::TiesAway, *width));
                        }
                    }
                    if let Some(helper) =
                        fp_semantics::cvt_helper(*saturating, *signed, dest.width, *width)
                    {
                        acc.insert(helper);
                    }
                }
                _ => {}
            },
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_fp_semantics_helpers(then_body, acc);
                if let Some(body) = else_body {
                    collect_fp_semantics_helpers(body, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_fp_semantics_helpers(body, acc);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_fp_semantics_helpers(&case.body, acc);
                }
                collect_fp_semantics_helpers(default, acc);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn emit_fp_helpers(out: &mut String) {
    let _ = writeln!(out, "#include <string.h>");
    let _ = writeln!(
        out,
        "static inline double fp_d_from_bits(uint64_t b){{ double v; memcpy(&v,&b,8); return v; }}"
    );
    let _ = writeln!(
        out,
        "static inline uint64_t fp_d_to_bits(double v){{ uint64_t b; memcpy(&b,&v,8); return b; }}"
    );
    let _ = writeln!(
        out,
        "static inline float fp_f_from_bits(uint32_t b){{ float v; memcpy(&v,&b,4); return v; }}"
    );
    let _ = writeln!(
        out,
        "static inline uint32_t fp_f_to_bits(float v){{ uint32_t b; memcpy(&b,&v,4); return b; }}"
    );
}

const AGGREGATE_MAX_ROOTS: usize = 8;
const AGGREGATE_MAX_FIELDS: usize = 32;
const AGGREGATE_MAX_ROOT_OBSERVATIONS: usize = 64;
const AGGREGATE_MAX_OBSERVATIONS: usize = 256;
const AGGREGATE_MAX_NODES: usize = 256;
const AGGREGATE_MAX_SCAN_DEPTH: usize = 16;
const AGGREGATE_MAX_NESTING: usize = 2;
const AGGREGATE_MAX_SPAN: i64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AggregateShape {
    Struct { fields: Vec<(i64, Width)> },
    Array { width: Width, scale: u8 },
    Union { members: Vec<AggregateScalar> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateScalar {
    Integer(Width),
    Float(FpWidth),
}

impl AggregateScalar {
    const fn width(self) -> Width {
        match self {
            Self::Integer(width) => width,
            Self::Float(FpWidth::F32) => Width::W32,
            Self::Float(FpWidth::F64) => Width::W64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AggregateObservation {
    mem: MemRef,
    scalar: AggregateScalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AggregateOrigin {
    parent: Reg,
    disp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AggregateRootPlan {
    reg: Reg,
    aliases: Vec<Reg>,
    shape: AggregateShape,
    bind_local: bool,
    depth: usize,
    origin: Option<AggregateOrigin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotCType {
    width: Width,
    signed: bool,
}

impl SlotCType {
    fn from_typerec(cint: disrobe_typerec::CIntType) -> Option<Self> {
        Some(Self {
            width: Width::from_typerec(cint.width())?,
            signed: cint.is_signed(),
        })
    }

    const fn c_name(self) -> &'static str {
        match (self.width, self.signed) {
            (Width::W8, false) => "uint8_t",
            (Width::W8, true) => "int8_t",
            (Width::W16, false) => "uint16_t",
            (Width::W16, true) => "int16_t",
            (Width::W32, false) => "uint32_t",
            (Width::W32, true) => "int32_t",
            (Width::W64, false) => "uint64_t",
            (Width::W64, true) => "int64_t",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct AggregatePlan {
    roots: Vec<AggregateRootPlan>,
    frame_base: Option<Reg>,
    frame_slots: BTreeMap<i64, SlotCType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateAccess {
    Field {
        root: usize,
        base: Reg,
        disp: i64,
        nested: Option<usize>,
    },
    Array {
        root: usize,
        base: Reg,
        index: Reg,
    },
    UnionMember {
        root: usize,
        base: Reg,
        scalar: AggregateScalar,
    },
}

impl AggregatePlan {
    fn root_position(&self, reg: Reg) -> Option<usize> {
        self.roots
            .iter()
            .position(|root: &AggregateRootPlan| root.reg == reg || root.aliases.contains(&reg))
    }

    fn frame_slot(&self, mem: &MemRef) -> Option<SlotCType> {
        if mem.index.is_some() || self.frame_base.is_none() || mem.base != self.frame_base {
            return None;
        }
        let slot: SlotCType = self.frame_slots.get(&mem.disp).copied()?;
        (slot.width == mem.width).then_some(slot)
    }

    fn signed_frame_slot(&self, mem: &MemRef) -> Option<SlotCType> {
        self.frame_slot(mem).filter(|slot: &SlotCType| slot.signed)
    }

    fn linked_child(&self, parent: Reg, disp: i64) -> Option<usize> {
        self.roots.iter().position(|root: &AggregateRootPlan| {
            root.origin.is_some_and(|origin: AggregateOrigin| {
                origin.parent == parent && origin.disp == disp
            })
        })
    }

    fn access(&self, mem: &MemRef, scalar: AggregateScalar) -> Option<AggregateAccess> {
        let base: Reg = mem.base?;
        let root_index: usize = self.root_position(base)?;
        let root: &AggregateRootPlan = self.roots.get(root_index)?;
        match &root.shape {
            AggregateShape::Struct { fields } => {
                if scalar != AggregateScalar::Integer(mem.width)
                    || mem.index.is_some()
                    || !fields.iter().any(|(disp, width): &(i64, Width)| {
                        *disp == mem.disp && *width == mem.width
                    })
                {
                    return None;
                }
                Some(AggregateAccess::Field {
                    root: root_index,
                    base,
                    disp: mem.disp,
                    nested: self.linked_child(root.reg, mem.disp),
                })
            }
            AggregateShape::Array { width, scale } => {
                let IndexOperand {
                    reg: index,
                    scale: access_scale,
                    extend,
                }: IndexOperand = mem.index?;
                if scalar != AggregateScalar::Integer(mem.width)
                    || mem.disp != 0
                    || access_scale != *scale
                    || mem.width != *width
                    || extend != IndexExtend::Full
                {
                    return None;
                }
                Some(AggregateAccess::Array {
                    root: root_index,
                    base,
                    index,
                })
            }
            AggregateShape::Union { members } => {
                if mem.index.is_some()
                    || mem.disp != 0
                    || scalar.width() != mem.width
                    || !members.contains(&scalar)
                {
                    return None;
                }
                Some(AggregateAccess::UnionMember {
                    root: root_index,
                    base,
                    scalar,
                })
            }
        }
    }
}

#[derive(Debug, Default)]
struct AggregateScan {
    mems: Vec<MemRef>,
    observations: Vec<AggregateObservation>,
    writes: BTreeMap<Reg, usize>,
    unemitted_bases: BTreeSet<Reg>,
    nodes: usize,
    exceeded: bool,
}

impl AggregateScan {
    fn note_observation(&mut self, mem: MemRef, scalar: AggregateScalar) {
        if self.mems.len() >= AGGREGATE_MAX_OBSERVATIONS {
            self.exceeded = true;
        } else {
            self.mems.push(mem);
            self.observations.push(AggregateObservation { mem, scalar });
        }
    }

    fn note_mem(&mut self, mem: MemRef) {
        self.note_observation(mem, AggregateScalar::Integer(mem.width));
    }

    fn note_unemitted_mem(&mut self, mem: MemRef, scalar: AggregateScalar) {
        self.note_observation(mem, scalar);
        if let Some(base) = mem.base {
            self.unemitted_bases.insert(base);
        }
    }

    fn note_write(&mut self, reg: Reg) {
        let count: &mut usize = self.writes.entry(reg).or_default();
        let Some(next): Option<usize> = count.checked_add(1) else {
            self.exceeded = true;
            return;
        };
        *count = next;
    }
}

fn aggregate_note_source(scan: &mut AggregateScan, source: &Source) {
    if let Source::Mem(mem) = source {
        scan.note_mem(*mem);
    }
}

fn aggregate_note_ext_source(scan: &mut AggregateScan, source: &ExtSource) {
    if let ExtSource::Mem(mem) = source {
        scan.note_mem(*mem);
    }
}

fn aggregate_note_fp_operand(scan: &mut AggregateScan, operand: &FpOperand, width: FpWidth) {
    if let FpOperand::Mem(mem) = operand {
        scan.note_unemitted_mem(*mem, AggregateScalar::Float(width));
    }
}

fn aggregate_note_flags(scan: &mut AggregateScan, flags: &Flags) {
    match flags {
        Flags::Cmp { rhs, .. } | Flags::Add { rhs, .. } => aggregate_note_source(scan, rhs),
        Flags::CmpMem { lhs, rhs } => {
            scan.note_mem(*lhs);
            aggregate_note_source(scan, rhs);
        }
        Flags::FpCmp { rhs, width, .. } => aggregate_note_fp_operand(scan, rhs, *width),
        Flags::CondCmp { prior, taken, .. } => {
            aggregate_note_flags(scan, prior);
            aggregate_note_flags(scan, taken);
        }
        Flags::Test { .. }
        | Flags::TestImm { .. }
        | Flags::Sign { .. }
        | Flags::Snapshot { .. } => {}
    }
}

fn aggregate_note_stmt(scan: &mut AggregateScan, stmt: &Stmt) {
    for reg in stmt_dest_regs(stmt) {
        scan.note_write(reg);
    }
    match stmt {
        Stmt::Assign { src, .. } | Stmt::BinAssign { src, .. } => {
            aggregate_note_source(scan, src);
        }
        Stmt::Cond { src, flags, .. } => {
            aggregate_note_source(scan, src);
            aggregate_note_flags(scan, flags);
        }
        Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. } => {
            aggregate_note_flags(scan, flags);
        }
        Stmt::Store { addr, src } => {
            scan.note_mem(*addr);
            aggregate_note_source(scan, src);
        }
        Stmt::MemRmw { addr, op } => {
            scan.note_mem(*addr);
            if let Some(source) = op.source() {
                aggregate_note_source(scan, source);
            }
        }
        Stmt::Extend { src, .. } | Stmt::MulImm { src, .. } => {
            aggregate_note_ext_source(scan, src);
        }
        Stmt::FpBin {
            lhs, rhs, width, ..
        } => {
            aggregate_note_fp_operand(scan, lhs, *width);
            aggregate_note_fp_operand(scan, rhs, *width);
        }
        Stmt::FpMinMax {
            lhs, rhs, width, ..
        } => {
            aggregate_note_fp_operand(scan, lhs, *width);
            aggregate_note_fp_operand(scan, rhs, *width);
        }
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            width,
            ..
        } => {
            aggregate_note_fp_operand(scan, mul_lhs, *width);
            aggregate_note_fp_operand(scan, mul_rhs, *width);
            aggregate_note_fp_operand(scan, addend, *width);
        }
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            width,
            ..
        } => {
            aggregate_note_fp_operand(scan, if_true, *width);
            aggregate_note_fp_operand(scan, if_false, *width);
            aggregate_note_flags(scan, flags);
        }
        Stmt::FpMov { src, width, .. }
        | Stmt::FpSqrt { src, width, .. }
        | Stmt::FpUnary { src, width, .. }
        | Stmt::FpRound { src, width, .. } => {
            aggregate_note_fp_operand(scan, src, *width);
        }
        Stmt::FpStore { addr, width, .. } => {
            scan.note_unemitted_mem(*addr, AggregateScalar::Float(*width));
        }
        Stmt::BlockMove { .. } => {
            scan.note_write(Reg::Rdi);
            scan.note_write(Reg::Rsi);
            scan.note_write(Reg::Rcx);
        }
        Stmt::BlockFill { .. } => {
            scan.note_write(Reg::Rdi);
            scan.note_write(Reg::Rcx);
        }
        Stmt::UnAssign { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpToInt { .. }
        | Stmt::FpConvert { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::Call { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(_)
        | Stmt::PackedToGpr { .. } => {}
    }
}

fn aggregate_scan_block(scan: &mut AggregateScan, body: &Block, depth: usize) {
    if depth > AGGREGATE_MAX_SCAN_DEPTH {
        scan.exceeded = true;
        return;
    }
    for node in body {
        if scan.nodes >= AGGREGATE_MAX_NODES {
            scan.exceeded = true;
            return;
        }
        scan.nodes += 1;
        match node {
            Node::Stmt(stmt) => aggregate_note_stmt(scan, stmt),
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| {
                    aggregate_note_flags(scan, flags);
                });
                aggregate_scan_block(scan, then_body, depth + 1);
                if let Some(else_block) = else_body {
                    aggregate_scan_block(scan, else_block, depth + 1);
                }
            }
            Node::DoWhile { body, cond } => {
                if let LoopCond::Direct { flags, .. } = cond {
                    aggregate_note_flags(scan, flags);
                }
                aggregate_scan_block(scan, body, depth + 1);
            }
            Node::While { body, cond } => {
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    aggregate_note_flags(scan, flags);
                }
                aggregate_scan_block(scan, body, depth + 1);
            }
            Node::CondSnapshot { flags, .. } => aggregate_note_flags(scan, flags),
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    aggregate_scan_block(scan, &case.body, depth + 1);
                }
                aggregate_scan_block(scan, default, depth + 1);
            }
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
        if scan.exceeded {
            return;
        }
    }
}

fn aggregate_flat_stmts(body: &Block) -> Option<Vec<&Stmt>> {
    let mut statements: Vec<&Stmt> = Vec::with_capacity(body.len());
    for node in body {
        match node {
            Node::Stmt(stmt) => statements.push(stmt),
            Node::Return => {}
            _ => return None,
        }
    }
    Some(statements)
}

fn aggregate_classify_root(
    reg: Reg,
    observations: &[AggregateObservation],
) -> Option<AggregateShape> {
    let regs: BTreeSet<Reg> = std::iter::once(reg).collect();
    aggregate_classify_regs(&regs, observations)
}

fn aggregate_classify_regs(
    regs: &BTreeSet<Reg>,
    all_observations: &[AggregateObservation],
) -> Option<AggregateShape> {
    let observations: Vec<AggregateObservation> = all_observations
        .iter()
        .copied()
        .filter(|observation: &AggregateObservation| {
            observation
                .mem
                .base
                .is_some_and(|base: Reg| regs.contains(&base))
        })
        .collect();
    if observations.is_empty() || observations.len() > AGGREGATE_MAX_ROOT_OBSERVATIONS {
        return None;
    }
    if all_observations
        .iter()
        .any(|observation: &AggregateObservation| {
            observation
                .mem
                .index
                .is_some_and(|idx: IndexOperand| regs.contains(&idx.reg))
        })
    {
        return None;
    }
    if observations
        .iter()
        .any(|observation: &AggregateObservation| {
            observation.scalar.width() != observation.mem.width
        })
    {
        return None;
    }
    let indexed: usize = observations
        .iter()
        .filter(|observation: &&AggregateObservation| observation.mem.index.is_some())
        .count();
    if indexed == observations.len() {
        if observations
            .iter()
            .any(|observation: &AggregateObservation| {
                !matches!(observation.scalar, AggregateScalar::Integer(_))
            })
        {
            return None;
        }
        let first: MemRef = observations.first()?.mem;
        let IndexOperand { scale, .. }: IndexOperand = first.index?;
        let bytes: u32 = first.width.bits() / 8;
        if !matches!(scale, 1 | 2 | 4 | 8) || u32::from(scale) != bytes {
            return None;
        }
        if observations
            .iter()
            .any(|observation: &AggregateObservation| {
                let mem: MemRef = observation.mem;
                mem.disp != 0
                    || mem.width != first.width
                    || mem.index.is_none_or(|idx: IndexOperand| {
                        idx.scale != scale || idx.extend != IndexExtend::Full
                    })
            })
        {
            return None;
        }
        return Some(AggregateShape::Array {
            width: first.width,
            scale,
        });
    }
    if indexed != 0 {
        return None;
    }
    let mut union_members: Vec<AggregateScalar> = Vec::new();
    if observations
        .iter()
        .all(|observation: &AggregateObservation| observation.mem.disp == 0)
    {
        for observation in &observations {
            if !union_members.contains(&observation.scalar) {
                union_members.push(observation.scalar);
            }
        }
        if (2..=AGGREGATE_MAX_FIELDS).contains(&union_members.len()) {
            return Some(AggregateShape::Union {
                members: union_members,
            });
        }
    }
    if observations
        .iter()
        .any(|observation: &AggregateObservation| {
            !matches!(observation.scalar, AggregateScalar::Integer(_))
        })
    {
        return None;
    }
    let mut by_offset: BTreeMap<i64, Width> = BTreeMap::new();
    for observation in &observations {
        let mem: MemRef = observation.mem;
        if mem.disp < 0 {
            return None;
        }
        match by_offset.get(&mem.disp) {
            Some(width) if *width != mem.width => return None,
            _ => {
                by_offset.insert(mem.disp, mem.width);
            }
        }
    }
    if !(2..=AGGREGATE_MAX_FIELDS).contains(&by_offset.len()) {
        return None;
    }
    let mut end: i64 = 0;
    for (&disp, &width) in &by_offset {
        if disp < end {
            return None;
        }
        let bytes: i64 = i64::from(width.bits() / 8);
        end = disp.checked_add(bytes)?;
        if end > AGGREGATE_MAX_SPAN {
            return None;
        }
    }
    Some(AggregateShape::Struct {
        fields: by_offset.into_iter().collect(),
    })
}

fn aggregate_root_exclusive(statements: &[&Stmt], reg: Reg, definition: usize) -> bool {
    for (index, stmt) in statements.iter().enumerate() {
        let mut reads: Vec<Reg> = Vec::new();
        stmt_value_reads(stmt, &mut reads);
        let read_count: usize = reads
            .iter()
            .filter(|candidate: &&Reg| **candidate == reg)
            .count();
        let mut local_scan: AggregateScan = AggregateScan::default();
        aggregate_note_stmt(&mut local_scan, stmt);
        if local_scan.exceeded {
            return false;
        }
        let base_count: usize = local_scan
            .mems
            .iter()
            .filter(|mem: &&MemRef| mem.base == Some(reg))
            .count();
        if index <= definition {
            if base_count != 0 {
                return false;
            }
            continue;
        }
        if local_scan
            .mems
            .iter()
            .any(|mem: &MemRef| mem.index.is_some_and(|idx: IndexOperand| idx.reg == reg))
            || read_count != base_count
        {
            return false;
        }
    }
    true
}

fn aggregate_frame_reload_source(
    statements: &[&Stmt],
    reg: Reg,
    frame: &FramePlan,
) -> Option<MemRef> {
    let mut source_slot: Option<MemRef> = None;
    let mut live: bool = false;
    let mut saw_access: bool = false;
    for stmt in statements {
        let mut reads: Vec<Reg> = Vec::new();
        stmt_value_reads(stmt, &mut reads);
        let read_count: usize = reads
            .iter()
            .filter(|candidate: &&Reg| **candidate == reg)
            .count();
        let mut local_scan: AggregateScan = AggregateScan::default();
        aggregate_note_stmt(&mut local_scan, stmt);
        if local_scan.exceeded {
            return None;
        }
        let base_count: usize = local_scan
            .mems
            .iter()
            .filter(|mem: &&MemRef| mem.base == Some(reg))
            .count();
        if base_count != 0 {
            if !live {
                return None;
            }
            saw_access = true;
        }
        if live && read_count != base_count {
            return None;
        }
        let reload: Option<MemRef> = match stmt {
            Stmt::Assign {
                dest,
                src: Source::Mem(source),
            } if dest.reg == reg
                && dest.width == Width::W64
                && source.width == Width::W64
                && source.base == Some(frame.base)
                && source.index.is_none() =>
            {
                Some(*source)
            }
            _ => None,
        };
        if stmt_dest_regs(stmt).contains(&reg) {
            if let Some(source) = reload {
                if source_slot.is_some_and(|slot: MemRef| slot != source) {
                    return None;
                }
                source_slot = Some(source);
                live = true;
            } else {
                live = false;
            }
        }
    }
    if saw_access { source_slot } else { None }
}

fn aggregate_nested_origin(
    plan: &AggregatePlan,
    scan: &AggregateScan,
    source: &MemRef,
) -> Option<(usize, Option<AggregateOrigin>)> {
    let Some(parent_reg): Option<Reg> = source.base else {
        return Some((0, None));
    };
    let Some(parent_position): Option<usize> = plan.root_position(parent_reg) else {
        return Some((0, None));
    };
    let parent: &AggregateRootPlan = plan.roots.get(parent_position)?;
    let AggregateShape::Struct { fields } = &parent.shape else {
        return None;
    };
    let matching_field: bool = source.index.is_none()
        && fields
            .iter()
            .any(|(disp, width): &(i64, Width)| *disp == source.disp && *width == Width::W64);
    let matching_accesses: usize = scan
        .mems
        .iter()
        .filter(|mem: &&MemRef| **mem == *source)
        .count();
    if !matching_field || matching_accesses != 1 {
        return None;
    }
    let next_depth: usize = parent.depth.checked_add(1)?;
    if next_depth > AGGREGATE_MAX_NESTING {
        return None;
    }
    Some((
        next_depth,
        Some(AggregateOrigin {
            parent: parent_reg,
            disp: source.disp,
        }),
    ))
}

fn infer_aggregate_plan(body: &Block, params: &[Reg], frame: Option<&FramePlan>) -> AggregatePlan {
    let mut scan: AggregateScan = AggregateScan::default();
    aggregate_scan_block(&mut scan, body, 0);
    if scan.exceeded {
        return AggregatePlan::default();
    }
    let mut plan: AggregatePlan = AggregatePlan::default();
    for &reg in params {
        if plan.roots.len() >= AGGREGATE_MAX_ROOTS {
            return AggregatePlan::default();
        }
        if scan.writes.get(&reg).copied().unwrap_or(0) != 0 {
            continue;
        }
        if let Some(shape) = aggregate_classify_root(reg, &scan.observations) {
            if scan.unemitted_bases.contains(&reg) && !matches!(shape, AggregateShape::Union { .. })
            {
                continue;
            }
            plan.roots.push(AggregateRootPlan {
                reg,
                aliases: Vec::new(),
                shape,
                bind_local: true,
                depth: 0,
                origin: None,
            });
        }
    }
    let Some(statements): Option<Vec<&Stmt>> = aggregate_flat_stmts(body) else {
        return plan;
    };
    for (definition, stmt) in statements.iter().enumerate() {
        if plan.roots.len() >= AGGREGATE_MAX_ROOTS {
            return AggregatePlan::default();
        }
        let Stmt::Assign {
            dest,
            src: Source::Mem(source),
        } = stmt
        else {
            continue;
        };
        if dest.width != Width::W64
            || source.width != Width::W64
            || plan.root_position(dest.reg).is_some()
            || scan.writes.get(&dest.reg).copied().unwrap_or(0) != 1
            || !aggregate_root_exclusive(&statements, dest.reg, definition)
        {
            continue;
        }
        let Some(shape): Option<AggregateShape> =
            aggregate_classify_root(dest.reg, &scan.observations)
        else {
            continue;
        };
        if scan.unemitted_bases.contains(&dest.reg)
            && !matches!(shape, AggregateShape::Union { .. })
        {
            continue;
        }
        let Some((depth, origin)): Option<(usize, Option<AggregateOrigin>)> =
            aggregate_nested_origin(&plan, &scan, source)
        else {
            continue;
        };
        plan.roots.push(AggregateRootPlan {
            reg: dest.reg,
            aliases: Vec::new(),
            shape,
            bind_local: false,
            depth,
            origin,
        });
    }
    if let Some(frame_plan) = frame {
        let candidate_regs: BTreeSet<Reg> = scan
            .mems
            .iter()
            .filter_map(|mem: &MemRef| mem.base)
            .collect();
        let mut groups: Vec<(MemRef, BTreeSet<Reg>)> = Vec::new();
        for reg in candidate_regs {
            if plan.root_position(reg).is_some() {
                continue;
            }
            let Some(slot): Option<MemRef> =
                aggregate_frame_reload_source(&statements, reg, frame_plan)
            else {
                continue;
            };
            if let Some(position) = groups
                .iter()
                .position(|(candidate, _): &(MemRef, BTreeSet<Reg>)| *candidate == slot)
            {
                if let Some((_, regs)) = groups.get_mut(position) {
                    regs.insert(reg);
                }
            } else {
                groups.push((slot, std::iter::once(reg).collect()));
            }
        }
        for (_, regs) in groups {
            let Some(shape): Option<AggregateShape> =
                aggregate_classify_regs(&regs, &scan.observations)
            else {
                continue;
            };
            if regs
                .iter()
                .any(|reg: &Reg| scan.unemitted_bases.contains(reg))
                && !matches!(shape, AggregateShape::Union { .. })
            {
                continue;
            }
            let Some(&reg): Option<&Reg> = regs.first() else {
                continue;
            };
            if plan.roots.len() >= AGGREGATE_MAX_ROOTS {
                return AggregatePlan::default();
            }
            plan.roots.push(AggregateRootPlan {
                reg,
                aliases: regs
                    .iter()
                    .copied()
                    .filter(|candidate: &Reg| *candidate != reg)
                    .collect(),
                shape,
                bind_local: false,
                depth: 0,
                origin: None,
            });
        }
    }
    plan
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FramePlan {
    base: Reg,
    size: usize,
    base_offset: usize,
}

const INDEXED_FRAME_MAX_ELEMENTS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedRegion {
    disp: i64,
    end: i64,
    scale: u8,
    width: Width,
    elements: u64,
}

#[derive(Debug, Default)]
struct FrameScanState {
    slots: Vec<(i64, Width)>,
    regions: Vec<IndexedRegion>,
    bounds: BTreeMap<Reg, u64>,
    misuse: bool,
    stack_pointer_escape: bool,
    indexed_refusal: Option<&'static str>,
}

const fn masked_index_bound(stmt: &Stmt) -> Option<(Reg, u64)> {
    let Stmt::BinAssign {
        dest,
        op: BinOp::And,
        src: Source::Imm(mask),
    } = stmt
    else {
        return None;
    };
    match dest.width {
        Width::W64 => Some((dest.reg, *mask as u64)),
        Width::W32 => Some((dest.reg, (*mask as u64) & 0xffff_ffff)),
        Width::W16 | Width::W8 => None,
    }
}

fn forget_written_bounds(stmt: &Stmt, bounds: &mut BTreeMap<Reg, u64>) {
    match enumerable_gpr_writes(stmt) {
        None => bounds.clear(),
        Some(writes) => {
            for write in &writes {
                bounds.remove(&write.reg);
            }
        }
    }
}

fn forget_block_bounds(body: &Block, bounds: &mut BTreeMap<Reg, u64>) {
    for node in body {
        match node {
            Node::Stmt(stmt) => forget_written_bounds(stmt, bounds),
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                forget_block_bounds(then_body, bounds);
                if let Some(else_b) = else_body {
                    forget_block_bounds(else_b, bounds);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                forget_block_bounds(body, bounds);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    forget_block_bounds(&case.body, bounds);
                }
                forget_block_bounds(default, bounds);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn block_has_unstructured_edge(body: &Block) -> bool {
    body.iter().any(|node: &Node| match node {
        Node::Label(_) | Node::Goto(_) => true,
        Node::If {
            then_body,
            else_body,
            ..
        } => {
            block_has_unstructured_edge(then_body)
                || else_body.as_ref().is_some_and(block_has_unstructured_edge)
        }
        Node::DoWhile { body, .. } | Node::While { body, .. } => block_has_unstructured_edge(body),
        Node::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|case: &SwitchCase| block_has_unstructured_edge(&case.body))
                || block_has_unstructured_edge(default)
        }
        Node::Stmt(_) | Node::CondSnapshot { .. } | Node::Break | Node::Continue | Node::Return => {
            false
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexedModelling {
    Allowed,
    RefusedByFrameClass(FrameClass),
    RefusedByUnstructuredEdge,
}

impl IndexedModelling {
    const UNSTRUCTURED_EDGE_REFUSAL: &'static str = "an indexed frame access sits in a body with an unstructured edge, where the index bound proven on one path does not hold on every path reaching the access";

    const fn decide(shape: FrameShape, body_has_unstructured_edge: bool) -> Self {
        let class: FrameClass = shape.class();
        if class.indexed_refusal().is_some() {
            return Self::RefusedByFrameClass(class);
        }
        if body_has_unstructured_edge {
            return Self::RefusedByUnstructuredEdge;
        }
        Self::Allowed
    }

    const fn refusal(self) -> Option<&'static str> {
        match self {
            Self::Allowed => None,
            Self::RefusedByFrameClass(class) => class.indexed_refusal(),
            Self::RefusedByUnstructuredEdge => Some(Self::UNSTRUCTURED_EDGE_REFUSAL),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FrameScan {
    frame_base: Option<Reg>,
    rbp_is_frame: bool,
    indexed: IndexedModelling,
}

impl FrameScan {
    fn is_stack_reg(self, reg: Reg) -> bool {
        reg == Reg::Rsp || (self.rbp_is_frame && reg == Reg::Rbp)
    }

    fn note_reg(self, reg: Reg, state: &mut FrameScanState) {
        if self.is_stack_reg(reg) {
            state.misuse = true;
            state.stack_pointer_escape |= reg == Reg::Rsp;
        }
    }

    fn indexed_region(
        self,
        mem: &MemRef,
        idx: IndexOperand,
        bounds: &BTreeMap<Reg, u64>,
    ) -> Option<IndexedRegion> {
        if self.indexed != IndexedModelling::Allowed
            || idx.extend != IndexExtend::Full
            || self.is_stack_reg(idx.reg)
            || !matches!(idx.scale, 1 | 2 | 4 | 8)
            || u32::from(idx.scale) != mem.width.bits() / 8
        {
            return None;
        }
        let elements: u64 = bounds.get(&idx.reg)?.checked_add(1)?;
        if elements > INDEXED_FRAME_MAX_ELEMENTS {
            return None;
        }
        let span: i64 = i64::try_from(elements.checked_mul(u64::from(idx.scale))?).ok()?;
        Some(IndexedRegion {
            disp: mem.disp,
            end: mem.disp.checked_add(span)?,
            scale: idx.scale,
            width: mem.width,
            elements,
        })
    }

    fn note_mem(self, mem: &MemRef, state: &mut FrameScanState) {
        if let Some(idx) = mem.index
            && self.is_stack_reg(idx.reg)
        {
            self.note_reg(idx.reg, state);
        }
        match mem.base {
            Some(b) if Some(b) == self.frame_base => match mem.index {
                None => state.slots.push((mem.disp, mem.width)),
                Some(idx) => {
                    if let Some(refusal) = self.indexed.refusal() {
                        state.indexed_refusal.get_or_insert(refusal);
                    }
                    match self.indexed_region(mem, idx, &state.bounds) {
                        Some(region) => state.regions.push(region),
                        None => state.misuse = true,
                    }
                }
            },
            Some(b) if self.is_stack_reg(b) => self.note_reg(b, state),
            _ => {}
        }
    }

    fn note_source(self, src: &Source, state: &mut FrameScanState) {
        match src {
            Source::Reg(r) => self.note_reg(r.reg, state),
            Source::Imm(_) => {}
            Source::Lea { base, index, .. } => {
                if base.is_some_and(|b: Reg| self.is_stack_reg(b))
                    || index.is_some_and(|idx: IndexOperand| self.is_stack_reg(idx.reg))
                {
                    state.misuse = true;
                }
            }
            Source::Mem(mem) => self.note_mem(mem, state),
        }
    }

    fn note_fp(self, op: &FpOperand, state: &mut FrameScanState) {
        if let FpOperand::Mem(mem) = op {
            self.note_mem(mem, state);
        }
    }

    fn note_flags(self, flags: &Flags, state: &mut FrameScanState) {
        match flags {
            Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
                self.note_reg(lhs.reg, state);
                self.note_source(rhs, state);
            }
            Flags::CmpMem { lhs, rhs } => {
                self.note_mem(lhs, state);
                self.note_source(rhs, state);
            }
            Flags::Test { operand } | Flags::TestImm { operand, .. } => {
                self.note_reg(operand.reg, state);
            }
            Flags::Sign { result } => self.note_reg(result.reg, state),
            Flags::FpCmp { rhs, .. } => self.note_fp(rhs, state),
            Flags::Snapshot { .. } => {}
            Flags::CondCmp { prior, taken, .. } => {
                self.note_flags(prior, state);
                self.note_flags(taken, state);
            }
        }
    }

    fn note_stmt(self, stmt: &Stmt, state: &mut FrameScanState) {
        match stmt {
            Stmt::Assign { dest, src } | Stmt::BinAssign { dest, src, .. } => {
                self.note_reg(dest.reg, state);
                self.note_source(src, state);
            }
            Stmt::UnAssign { dest, .. } => self.note_reg(dest.reg, state),
            Stmt::Cond {
                dest, src, flags, ..
            } => {
                self.note_reg(dest.reg, state);
                self.note_source(src, state);
                self.note_flags(flags, state);
            }
            Stmt::SetCc { dest, flags, .. } => {
                self.note_reg(dest.reg, state);
                self.note_flags(flags, state);
            }
            Stmt::Store { addr, src } => {
                self.note_mem(addr, state);
                self.note_source(src, state);
            }
            Stmt::MemRmw { addr, op } => {
                self.note_mem(addr, state);
                if let Some(src) = op.source() {
                    self.note_source(src, state);
                }
            }
            Stmt::Extend { dest, src, .. } => {
                self.note_reg(dest.reg, state);
                match src {
                    ExtSource::Reg(r) => self.note_reg(r.reg, state),
                    ExtSource::Mem(mem) => self.note_mem(mem, state),
                }
            }
            Stmt::MulImm { dest, src, .. } => {
                self.note_reg(dest.reg, state);
                match src {
                    ExtSource::Reg(r) => self.note_reg(r.reg, state),
                    ExtSource::Mem(mem) => self.note_mem(mem, state),
                }
            }
            Stmt::WideMul { src } => self.note_reg(src.reg, state),
            Stmt::Divide { divisor, .. } => self.note_reg(divisor.reg, state),
            Stmt::DoubleShift { dest, src, .. } => {
                self.note_reg(dest.reg, state);
                self.note_reg(src.reg, state);
            }
            Stmt::IntToFp { src, .. } => self.note_reg(src.reg, state),
            Stmt::FpToInt { dest, .. } => self.note_reg(dest.reg, state),
            Stmt::GprToXmm { src, .. } => self.note_reg(src.reg, state),
            Stmt::XmmToGpr { dest, .. } => self.note_reg(dest.reg, state),
            Stmt::FpBin { lhs, rhs, .. } => {
                self.note_fp(lhs, state);
                self.note_fp(rhs, state);
            }
            Stmt::FpMov { src, .. } => self.note_fp(src, state),
            Stmt::FpSqrt { src, .. } | Stmt::FpUnary { src, .. } => {
                self.note_fp(src, state);
            }
            Stmt::FpRound { src, .. } => self.note_fp(src, state),
            Stmt::FpMinMax { lhs, rhs, .. } => {
                self.note_fp(lhs, state);
                self.note_fp(rhs, state);
            }
            Stmt::FpFma {
                mul_lhs,
                mul_rhs,
                addend,
                ..
            } => {
                self.note_fp(mul_lhs, state);
                self.note_fp(mul_rhs, state);
                self.note_fp(addend, state);
            }
            Stmt::FpCsel {
                if_true,
                if_false,
                flags,
                ..
            } => {
                self.note_fp(if_true, state);
                self.note_fp(if_false, state);
                self.note_flags(flags, state);
            }
            Stmt::FpStore { addr, .. } => self.note_mem(addr, state),
            Stmt::FlagSnapshot { flags, .. } => self.note_flags(flags, state),
            Stmt::Packed { op, .. } => {
                if let PackedOp::FromGpr { src } = op {
                    self.note_reg(src.reg, state);
                }
            }
            Stmt::PackedToGpr { dest, .. } => self.note_reg(dest.reg, state),
            Stmt::Vector(vec) => match vec {
                VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => {
                    self.note_mem(addr, state);
                }
                VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => {
                    self.note_reg(src.reg, state);
                }
                VecStmt::Bin { .. }
                | VecStmt::Compare { .. }
                | VecStmt::MoveImm { .. }
                | VecStmt::Reduce { .. }
                | VecStmt::ExtractToGpr { .. }
                | VecStmt::WidenExtend { .. }
                | VecStmt::WidenAdd { .. } => {}
            },
            Stmt::FpConvert { .. }
            | Stmt::BlockMove { .. }
            | Stmt::BlockFill { .. }
            | Stmt::Call { .. } => {}
        }
    }
}

fn scan_frame_block(ctx: FrameScan, body: &Block, state: &mut FrameScanState) {
    for node in body {
        match node {
            Node::Stmt(stmt) => {
                ctx.note_stmt(stmt, state);
                forget_written_bounds(stmt, &mut state.bounds);
                if let Some((reg, bound)) = masked_index_bound(stmt) {
                    state.bounds.insert(reg, bound);
                }
            }
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| {
                    ctx.note_flags(flags, state);
                });
                let entry: BTreeMap<Reg, u64> = state.bounds.clone();
                scan_frame_block(ctx, then_body, state);
                if let Some(else_b) = else_body {
                    state.bounds = entry.clone();
                    scan_frame_block(ctx, else_b, state);
                }
                state.bounds = entry;
                forget_block_bounds(then_body, &mut state.bounds);
                if let Some(else_b) = else_body {
                    forget_block_bounds(else_b, &mut state.bounds);
                }
            }
            Node::DoWhile { body, cond } => {
                forget_block_bounds(body, &mut state.bounds);
                scan_frame_block(ctx, body, state);
                if let LoopCond::Direct { flags, .. } = cond {
                    ctx.note_flags(flags, state);
                }
                forget_block_bounds(body, &mut state.bounds);
            }
            Node::While { body, cond } => {
                forget_block_bounds(body, &mut state.bounds);
                scan_frame_block(ctx, body, state);
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    ctx.note_flags(flags, state);
                }
                forget_block_bounds(body, &mut state.bounds);
            }
            Node::Switch {
                disc,
                cases,
                default,
            } => {
                ctx.note_reg(disc.reg, state);
                for case in cases {
                    forget_block_bounds(&case.body, &mut state.bounds);
                }
                forget_block_bounds(default, &mut state.bounds);
                let entry: BTreeMap<Reg, u64> = state.bounds.clone();
                for case in cases {
                    state.bounds = entry.clone();
                    scan_frame_block(ctx, &case.body, state);
                }
                state.bounds = entry;
                scan_frame_block(ctx, default, state);
            }
            Node::CondSnapshot { flags, .. } => ctx.note_flags(flags, state),
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
    }
}

fn merged_slot_extents(slots: &[(i64, Width)]) -> Vec<(i64, i64)> {
    let mut spans: Vec<(i64, i64)> = slots
        .iter()
        .filter_map(|(disp, width): &(i64, Width)| {
            Some((*disp, disp.checked_add(i64::from(width.bits() / 8))?))
        })
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn check_indexed_regions(state: &FrameScanState) -> Result<()> {
    for (position, region) in state.regions.iter().enumerate() {
        for other in state.regions.iter().skip(position + 1) {
            if region.disp < other.end
                && other.disp < region.end
                && (region.width != other.width
                    || region.scale != other.scale
                    || (region.disp - other.disp) % i64::from(region.scale) != 0)
            {
                return Err(Error::LlvmIr(format!(
                    "two indexed frame accesses cover the same bytes with different element shapes ({}-byte stride {} at {} against {}-byte stride {} at {}); the region is not one array",
                    region.width.bits() / 8,
                    region.scale,
                    region.disp,
                    other.width.bits() / 8,
                    other.scale,
                    other.disp
                )));
            }
        }
    }
    let extents: Vec<(i64, i64)> = merged_slot_extents(&state.slots);
    for region in &state.regions {
        if !extents
            .iter()
            .any(|(start, end): &(i64, i64)| *start <= region.disp && region.end <= *end)
        {
            return Err(Error::LlvmIr(format!(
                "an indexed frame access of {} elements over [{}, {}) is not contained in the frame bytes the fixed-offset accesses prove; its extent cannot be bounded",
                region.elements, region.disp, region.end
            )));
        }
    }
    Ok(())
}

fn plan_frame(body: &Block, shape: FrameShape) -> Result<Option<FramePlan>> {
    let ctx: FrameScan = FrameScan {
        frame_base: shape.base,
        rbp_is_frame: shape.rbp_is_frame,
        indexed: IndexedModelling::decide(shape, block_has_unstructured_edge(body)),
    };
    let mut state: FrameScanState = FrameScanState::default();
    scan_frame_block(ctx, body, &mut state);
    if state.misuse {
        if let Some(unstable) = shape.stack_pointer_break
            && state.stack_pointer_escape
        {
            return Err(Error::LlvmIr(format!(
                "a stack-relative access cannot be given a fixed frame offset: {}",
                unstable.reason()
            )));
        }
        if let Some(refusal) = state.indexed_refusal {
            return Err(Error::LlvmIr(refusal.to_owned()));
        }
        return Err(Error::LlvmIr(
            "stack-frame register escapes a fixed-offset slot access (address-taken, dynamic, aliased, or used as a value); not a modelable spill frame".to_owned(),
        ));
    }
    check_indexed_regions(&state)?;
    let slots: Vec<(i64, Width)> = state.slots;
    if slots.is_empty() {
        return Ok(None);
    }
    let Some(base): Option<Reg> = shape.base else {
        return Err(Error::LlvmIr(
            "stack slots referenced without a provably constant frame base".to_owned(),
        ));
    };
    if shape.red_zone {
        let escaping: Option<&(i64, Width)> = slots.iter().find(|(disp, width): &&(i64, Width)| {
            *disp < -SYSV_RED_ZONE_BYTES || disp + i64::from(width.bits() / 8) > 0
        });
        if let Some((disp, width)) = escaping {
            return Err(Error::LlvmIr(format!(
                "a {}-byte slot at {disp} leaves the {SYSV_RED_ZONE_BYTES}-byte System V red zone below the entry stack pointer",
                width.bits() / 8
            )));
        }
    }
    if let Some(extent) = shape.stack_extent {
        let escaping: Option<&(i64, Width)> = slots
            .iter()
            .find(|(disp, width): &&(i64, Width)| !extent.owns(*disp, i64::from(width.bits() / 8)));
        if let Some((disp, width)) = escaping {
            return Err(Error::LlvmIr(
                extent.rejection(*disp, i64::from(width.bits() / 8)),
            ));
        }
    }
    if base == Reg::Rbp
        && slots
            .iter()
            .any(|(disp, _): &(i64, Width)| (0..16).contains(disp))
    {
        return Err(Error::LlvmIr(
            "access into the saved-frame-pointer/return-address region is not a data slot"
                .to_owned(),
        ));
    }
    let lo: i64 = slots
        .iter()
        .map(|(d, _): &(i64, Width)| *d)
        .min()
        .unwrap_or(0)
        .min(0);
    let hi: i64 = slots
        .iter()
        .map(|(d, w): &(i64, Width)| d + i64::from(w.bits() / 8))
        .max()
        .unwrap_or(0)
        .max(0);
    let size: usize = usize::try_from(hi - lo)
        .map_err(|_| Error::LlvmIr("stack frame size overflow".to_owned()))?;
    let base_offset: usize = usize::try_from(-lo)
        .map_err(|_| Error::LlvmIr("stack frame base offset overflow".to_owned()))?;
    Ok(Some(FramePlan {
        base,
        size,
        base_offset,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SretPlan {
    ptr: Reg,
    fields: Vec<(i64, Width)>,
    size: usize,
}

const fn sret_ptr_reg(abi: Abi) -> Reg {
    match abi {
        Abi::SysV => Reg::Rdi,
        Abi::MsX64 => Reg::Rcx,
        Abi::Aapcs64 => Reg::A64X8,
    }
}

const fn sret_min_memory_class(abi: Abi) -> usize {
    match abi {
        Abi::SysV => 16,
        Abi::MsX64 => 8,
        Abi::Aapcs64 => 16,
    }
}

const fn width_c_uint(width: Width) -> &'static str {
    match width {
        Width::W8 => "uint8_t",
        Width::W16 => "uint16_t",
        Width::W32 => "uint32_t",
        Width::W64 => "uint64_t",
    }
}

const fn aggregate_scalar_c_type(scalar: AggregateScalar) -> &'static str {
    match scalar {
        AggregateScalar::Integer(width) => width_c_uint(width),
        AggregateScalar::Float(FpWidth::F32) => "float",
        AggregateScalar::Float(FpWidth::F64) => "double",
    }
}

fn emit_c_aggregate_types(out: &mut String, plan: &AggregatePlan) {
    for (root_index, root) in plan.roots.iter().enumerate().rev() {
        match &root.shape {
            AggregateShape::Array { width, .. } => {
                let _ = writeln!(
                    out,
                    "    typedef {} recovered_array_{root_index}_t;",
                    width_c_uint(*width)
                );
            }
            AggregateShape::Struct { fields } => {
                let _ = writeln!(
                    out,
                    "    typedef struct __attribute__((packed, may_alias)) {{"
                );
                let mut cursor: i64 = 0;
                for &(disp, width) in fields {
                    if disp > cursor {
                        let gap: i64 = disp - cursor;
                        let _ = writeln!(out, "        uint8_t padding_{cursor:x}[{gap}];");
                    }
                    let field: String = aggregate_field_name(disp);
                    let child_type: Option<String> = plan
                        .linked_child(root.reg, disp)
                        .and_then(|child: usize| aggregate_c_type_name(plan, child));
                    match child_type {
                        Some(child_type) => {
                            let _ = writeln!(out, "        {child_type} *{field};");
                        }
                        None => {
                            let _ = writeln!(out, "        {} {field};", width_c_uint(width));
                        }
                    }
                    let Some(next_cursor): Option<i64> =
                        disp.checked_add(i64::from(width.bits() / 8))
                    else {
                        return;
                    };
                    cursor = next_cursor;
                }
                let _ = writeln!(out, "    }} recovered_struct_{root_index}_t;");
            }
            AggregateShape::Union { members } => {
                let _ = writeln!(
                    out,
                    "    typedef union __attribute__((packed, may_alias)) {{"
                );
                for &scalar in members {
                    let member: String = aggregate_member_name(scalar);
                    let _ = writeln!(out, "        {} {member};", aggregate_scalar_c_type(scalar));
                }
                let _ = writeln!(out, "    }} recovered_union_{root_index}_t;");
            }
        }
    }
}

fn emit_c_aggregate_locals(out: &mut String, plan: &AggregatePlan) {
    for (root_index, root) in plan.roots.iter().enumerate() {
        if !root.bind_local {
            continue;
        }
        let Some(ty): Option<String> = aggregate_c_type_name(plan, root_index) else {
            continue;
        };
        let Some(name): Option<String> = aggregate_c_local_name(plan, root_index) else {
            continue;
        };
        let _ = writeln!(
            out,
            "    {ty} *{name} = ({ty} *)(uintptr_t){};",
            reg_var(root.reg)
        );
    }
}

fn assign_is_pointer_copy(
    dest: RegRef,
    src: &Source,
    alias: &std::collections::BTreeSet<Reg>,
) -> bool {
    if dest.width != Width::W64 {
        return false;
    }
    match src {
        Source::Reg(r) => r.width == Width::W64 && alias.contains(&r.reg),
        Source::Lea {
            base: Some(b),
            index: None,
            disp: 0,
        } => alias.contains(b),
        _ => false,
    }
}

fn mem_reads_alias(mem: &MemRef, alias: &std::collections::BTreeSet<Reg>) -> bool {
    mem.base.is_some_and(|b: Reg| alias.contains(&b))
        || mem
            .index
            .is_some_and(|idx: IndexOperand| alias.contains(&idx.reg))
}

fn source_reads_alias(src: &Source, alias: &std::collections::BTreeSet<Reg>) -> bool {
    match src {
        Source::Reg(r) => alias.contains(&r.reg),
        Source::Imm(_) => false,
        Source::Lea { base, index, .. } => {
            base.is_some_and(|b: Reg| alias.contains(&b))
                || index.is_some_and(|idx: IndexOperand| alias.contains(&idx.reg))
        }
        Source::Mem(mem) => mem_reads_alias(mem, alias),
    }
}

fn stmt_value_reads(stmt: &Stmt, acc: &mut Vec<Reg>) {
    match stmt {
        Stmt::Assign { src, .. } => source_regs(src, acc),
        Stmt::BinAssign { dest, src, .. } => {
            acc.push(dest.reg);
            source_regs(src, acc);
        }
        Stmt::UnAssign { dest, .. } => acc.push(dest.reg),
        Stmt::Cond {
            dest, src, flags, ..
        } => {
            acc.push(dest.reg);
            source_regs(src, acc);
            acc.extend(flag_operand_regs(flags));
        }
        Stmt::SetCc { dest, flags, .. } => {
            acc.push(dest.reg);
            acc.extend(flag_operand_regs(flags));
        }
        Stmt::Store { addr, src } => {
            mem_regs(addr, acc);
            source_regs(src, acc);
        }
        Stmt::MemRmw { addr, op } => {
            mem_regs(addr, acc);
            if let Some(src) = op.source() {
                source_regs(src, acc);
            }
        }
        Stmt::Extend { src, .. } => match src {
            ExtSource::Reg(r) => acc.push(r.reg),
            ExtSource::Mem(mem) => mem_regs(mem, acc),
        },
        Stmt::MulImm { src, .. } => match src {
            ExtSource::Reg(r) => acc.push(r.reg),
            ExtSource::Mem(mem) => mem_regs(mem, acc),
        },
        Stmt::WideMul { src } => {
            acc.push(Reg::Rax);
            acc.push(src.reg);
        }
        Stmt::Divide { divisor, .. } => {
            acc.push(Reg::Rax);
            acc.push(Reg::Rdx);
            acc.push(divisor.reg);
        }
        Stmt::DoubleShift { dest, src, .. } => {
            acc.push(dest.reg);
            acc.push(src.reg);
        }
        Stmt::IntToFp { src, .. } | Stmt::GprToXmm { src, .. } => acc.push(src.reg),
        Stmt::FpToInt { .. } | Stmt::XmmToGpr { .. } | Stmt::FpConvert { .. } => {}
        Stmt::FpBin { lhs, rhs, .. } => {
            if let FpOperand::Mem(mem) = lhs {
                mem_regs(mem, acc);
            }
            if let FpOperand::Mem(mem) = rhs {
                mem_regs(mem, acc);
            }
        }
        Stmt::FpMinMax { lhs, rhs, .. } => {
            if let FpOperand::Mem(mem) = lhs {
                mem_regs(mem, acc);
            }
            if let FpOperand::Mem(mem) = rhs {
                mem_regs(mem, acc);
            }
        }
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            for operand in [mul_lhs, mul_rhs, addend] {
                if let FpOperand::Mem(mem) = operand {
                    mem_regs(mem, acc);
                }
            }
        }
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            ..
        } => {
            for operand in [if_true, if_false] {
                if let FpOperand::Mem(mem) = operand {
                    mem_regs(mem, acc);
                }
            }
            acc.extend(flag_operand_regs(flags));
        }
        Stmt::FpMov { src, .. }
        | Stmt::FpSqrt { src, .. }
        | Stmt::FpUnary { src, .. }
        | Stmt::FpRound { src, .. } => {
            if let FpOperand::Mem(mem) = src {
                mem_regs(mem, acc);
            }
        }
        Stmt::FpStore { addr, .. } => mem_regs(addr, acc),
        Stmt::BlockMove { .. } => {
            acc.push(Reg::Rdi);
            acc.push(Reg::Rsi);
            acc.push(Reg::Rcx);
        }
        Stmt::BlockFill { .. } => {
            acc.push(Reg::Rdi);
            acc.push(Reg::Rax);
            acc.push(Reg::Rcx);
        }
        Stmt::Call { args, .. } => acc.extend_from_slice(args),
        Stmt::Packed { op, .. } => {
            if let PackedOp::FromGpr { src } = op {
                acc.push(src.reg);
            }
        }
        Stmt::PackedToGpr { .. } => {}
        Stmt::Vector(vec) => match vec {
            VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => mem_regs(addr, acc),
            VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => acc.push(src.reg),
            VecStmt::Bin { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::ExtractToGpr { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. } => {}
        },
        Stmt::FlagSnapshot { flags, .. } => acc.extend(flag_operand_regs(flags)),
    }
}

fn stmt_reads_alias(stmt: &Stmt, alias: &std::collections::BTreeSet<Reg>) -> bool {
    let mut regs: Vec<Reg> = Vec::new();
    stmt_value_reads(stmt, &mut regs);
    regs.iter().any(|r: &Reg| alias.contains(r))
}

fn stmt_gpr_dests(stmt: &Stmt) -> Vec<Reg> {
    match stmt {
        Stmt::BinAssign { dest, .. }
        | Stmt::UnAssign { dest, .. }
        | Stmt::Cond { dest, .. }
        | Stmt::SetCc { dest, .. }
        | Stmt::Extend { dest, .. }
        | Stmt::MulImm { dest, .. }
        | Stmt::DoubleShift { dest, .. }
        | Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. } => vec![dest.reg],
        Stmt::WideMul { .. } | Stmt::Divide { .. } => vec![Reg::Rax, Reg::Rdx],
        Stmt::BlockMove { .. } => vec![Reg::Rdi, Reg::Rsi, Reg::Rcx],
        Stmt::BlockFill { .. } => vec![Reg::Rdi, Reg::Rcx],
        Stmt::Call { .. } => vec![Reg::Rax],
        _ => Vec::new(),
    }
}

fn tile_sret_fields(raw: &[(i64, Width)]) -> Option<Vec<(i64, Width)>> {
    if raw.is_empty() {
        return None;
    }
    let mut by_offset: BTreeMap<i64, Width> = BTreeMap::new();
    for &(disp, width) in raw {
        if disp < 0 {
            return None;
        }
        match by_offset.get(&disp) {
            Some(prev) if *prev != width => return None,
            _ => {
                by_offset.insert(disp, width);
            }
        }
    }
    let mut expect: i64 = 0;
    let mut fields: Vec<(i64, Width)> = Vec::with_capacity(by_offset.len());
    for (&disp, &width) in &by_offset {
        if disp != expect {
            return None;
        }
        let bytes: i64 = i64::from(width.bits() / 8);
        if disp % bytes != 0 {
            return None;
        }
        expect = disp.checked_add(bytes)?;
        fields.push((disp, width));
    }
    let max_bytes: i64 = fields
        .iter()
        .map(|(_, w): &(i64, Width)| i64::from(w.bits() / 8))
        .max()?;
    if expect % max_bytes != 0 {
        return None;
    }
    Some(fields)
}

fn detect_sret(body: &Block, abi: Abi) -> Option<SretPlan> {
    let stmts: Vec<&Stmt> = body
        .iter()
        .map(|node: &Node| match node {
            Node::Stmt(stmt) => Some(stmt),
            _ => None,
        })
        .collect::<Option<Vec<&Stmt>>>()?;
    let ptr: Reg = sret_ptr_reg(abi);
    let mut alias: std::collections::BTreeSet<Reg> = std::collections::BTreeSet::new();
    alias.insert(ptr);
    let mut raw_fields: Vec<(i64, Width)> = Vec::new();
    for stmt in &stmts {
        match stmt {
            Stmt::Store { addr, src } => {
                if source_reads_alias(src, &alias) {
                    return None;
                }
                if addr.base.is_some_and(|b: Reg| alias.contains(&b)) {
                    if addr.index.is_some() {
                        return None;
                    }
                    raw_fields.push((addr.disp, addr.width));
                } else if mem_reads_alias(addr, &alias) {
                    return None;
                }
            }
            Stmt::Assign { dest, src } => {
                if assign_is_pointer_copy(*dest, src, &alias) {
                    alias.insert(dest.reg);
                } else {
                    if source_reads_alias(src, &alias) {
                        return None;
                    }
                    alias.remove(&dest.reg);
                }
            }
            other => {
                if matches!(other, Stmt::Call { .. }) || stmt_reads_alias(other, &alias) {
                    return None;
                }
                for dest in stmt_gpr_dests(other) {
                    alias.remove(&dest);
                }
            }
        }
    }
    if abi != Abi::Aapcs64 && !alias.contains(&Reg::Rax) {
        return None;
    }
    let fields: Vec<(i64, Width)> = tile_sret_fields(&raw_fields)?;
    let last: &(i64, Width) = fields.last()?;
    let size: usize = usize::try_from(last.0 + i64::from(last.1.bits() / 8)).ok()?;
    if size <= sret_min_memory_class(abi) {
        return None;
    }
    Some(SretPlan { ptr, fields, size })
}

fn emit_c(
    body: &Block,
    signature: &FnSignature,
    frame: Option<&FramePlan>,
    sret: Option<&SretPlan>,
    aggregates: &AggregatePlan,
) -> String {
    let mut out: String = String::new();
    let _ = writeln!(out, "#include <stdint.h>");
    let uses_fp: bool = !signature.fp.is_empty() || matches!(signature.ret, FnReturn::Fp(_)) || {
        let mut probe: Vec<Xmm> = Vec::new();
        collect_block_xmm(body, &mut probe);
        !probe.is_empty()
    };
    if uses_fp {
        emit_fp_helpers(&mut out);
        let mut requested: BTreeSet<&'static str> = BTreeSet::new();
        collect_fp_semantics_helpers(body, &mut requested);
        for source in fp_semantics::resolved_sources(&requested) {
            let _ = writeln!(out, "{source}");
        }
    } else if block_string_ops_present(body) {
        let _ = writeln!(out, "#include <string.h>");
    }
    let mut call_decls: Vec<CallDecl> = Vec::new();
    collect_call_decls(body, &mut call_decls);
    for decl in &call_decls {
        let params: String = if decl.arg_count == 0 {
            "void".to_owned()
        } else {
            vec!["uint64_t"; decl.arg_count].join(", ")
        };
        let _ = writeln!(out, "extern uint64_t {}({params});", decl.display_name);
    }

    let param_types: Vec<ScalarType> = signature.ordered_param_types();
    let scalar_count: usize = param_types.len();
    let mut int_param_index: usize = 0;
    let mut param_decls: Vec<String> = param_types
        .iter()
        .enumerate()
        .map(|(i, ty): (usize, &ScalarType)| match ty {
            ScalarType::Int => {
                let width: Width = signature.int[int_param_index].1;
                int_param_index += 1;
                let c_type: &str = if signature.exact_integer_types {
                    width_c_uint(width)
                } else {
                    "uint64_t"
                };
                format!("{c_type} a{i}")
            }
            ScalarType::Double => format!("double a{i}"),
            ScalarType::Float => format!("float a{i}"),
        })
        .collect();
    for (k, (_, arr)) in signature.vec.iter().enumerate() {
        param_decls.push(format!("{} a{}", arr.type_name(), scalar_count + k));
    }
    let params_sig: String = if param_decls.is_empty() {
        "void".to_owned()
    } else {
        param_decls.join(", ")
    };
    let mut vec_types: BTreeSet<VecArrangement> = BTreeSet::new();
    collect_block_vec_arrangements(body, &mut vec_types);
    for arr in resolve_block_vec_types(body).values() {
        vec_types.insert(*arr);
    }
    for (_, arr) in &signature.vec {
        vec_types.insert(*arr);
    }
    if let FnReturn::Vec(arr) = signature.ret {
        vec_types.insert(arr);
    }
    for arr in &vec_types {
        let _ = writeln!(
            out,
            "typedef {} {} __attribute__((vector_size({})));",
            arr.elem.c_scalar(),
            arr.type_name(),
            arr.total_bits() / 8
        );
        let _ = writeln!(
            out,
            "typedef {} {} __attribute__((aligned(1)));",
            arr.type_name(),
            arr.mem_type_name()
        );
    }
    if !vec_types.is_empty() {
        let _ = writeln!(
            out,
            "typedef uint64_t {UNALIGNED_U64_TYPE} __attribute__((aligned(1)));"
        );
    }
    if let Some(plan) = sret {
        let _ = writeln!(out, "typedef struct {{");
        for (i, (_, width)) in plan.fields.iter().enumerate() {
            let _ = writeln!(out, "    {} f{i};", width_c_uint(*width));
        }
        let _ = writeln!(out, "}} recovered_sret_t;");
    }
    let return_type: String = match (sret, signature.ret) {
        (Some(_), _) => "recovered_sret_t".to_owned(),
        (None, FnReturn::Int(width)) if signature.exact_integer_types => {
            width_c_uint(width).to_owned()
        }
        (None, FnReturn::Int(_)) => "uint64_t".to_owned(),
        (None, FnReturn::Fp(width)) => width.c_type().to_owned(),
        (None, FnReturn::Void) => "void".to_owned(),
        (None, FnReturn::Vec(arr)) => arr.type_name(),
    };
    let _ = writeln!(out, "{return_type} recovered({params_sig}) {{");
    emit_c_aggregate_types(&mut out, aggregates);
    if sret.is_some() {
        let _ = writeln!(out, "    recovered_sret_t __sret;");
    }
    if let Some(plan) = frame {
        let _ = writeln!(
            out,
            "    _Alignas(16) unsigned char stack_frame[{}];",
            plan.size
        );
    }

    let mut touched_gp: Vec<Reg> = Vec::new();
    collect_block_regs(body, &mut touched_gp);
    if matches!(signature.ret, FnReturn::Int(_)) && !touched_gp.contains(&Reg::Rax) {
        touched_gp.push(Reg::Rax);
    }
    let mut touched_xmm: Vec<Xmm> = Vec::new();
    collect_block_xmm(body, &mut touched_xmm);
    if matches!(signature.ret, FnReturn::Fp(_)) && !touched_xmm.contains(&Xmm::Xmm0) {
        touched_xmm.push(Xmm::Xmm0);
    }

    let mut declared_gp: Vec<Reg> = Vec::new();
    let mut declared_xmm: Vec<Xmm> = Vec::new();
    for (i, ty) in param_types.iter().enumerate() {
        match ty {
            ScalarType::Int => {
                let index: usize = declared_gp.len();
                let reg: Reg = signature.int[index].0;
                let _ = writeln!(out, "    uint64_t {} = a{i};", reg_var(reg));
                declared_gp.push(reg);
            }
            ScalarType::Double | ScalarType::Float => {
                let index: usize = declared_xmm.len();
                let (xmm, width): (Xmm, FpWidth) = signature.fp[index];
                let _ = writeln!(
                    out,
                    "    uint64_t {} = {};",
                    xmm_var(xmm),
                    fp_store_expr(&format!("a{i}"), width)
                );
                declared_xmm.push(xmm);
            }
        }
    }
    for reg in &touched_gp {
        if !declared_gp.contains(reg) {
            let init: String = match (sret, frame) {
                (Some(plan), _) if plan.ptr == *reg => "(uint64_t)(uintptr_t)&__sret".to_owned(),
                (_, Some(plan)) if plan.base == *reg => {
                    format!("(uint64_t)(uintptr_t)(stack_frame + {})", plan.base_offset)
                }
                _ => "0".to_owned(),
            };
            let _ = writeln!(out, "    uint64_t {} = {init};", reg_var(*reg));
            declared_gp.push(*reg);
        }
    }
    emit_c_aggregate_locals(&mut out, aggregates);
    for xmm in &touched_xmm {
        if !declared_xmm.contains(xmm) {
            let _ = writeln!(out, "    uint64_t {} = 0;", xmm_var(*xmm));
            declared_xmm.push(*xmm);
        }
    }
    let mut packed_xmm: Vec<Xmm> = Vec::new();
    collect_block_packed_xmm(body, &mut packed_xmm);
    for xmm in &packed_xmm {
        let _ = writeln!(out, "    uint64_t {} = 0;", packed_lane(*xmm, false));
        let _ = writeln!(out, "    uint64_t {} = 0;", packed_lane(*xmm, true));
    }
    let mut snapshot_vars: Vec<u32> = Vec::new();
    collect_snapshot_vars(body, &mut snapshot_vars);
    for var in &snapshot_vars {
        let _ = writeln!(out, "    uint64_t {} = 0;", loop_cond_var(*var));
    }
    let mut sel_vars: Vec<u32> = Vec::new();
    collect_sel_vars(body, &mut sel_vars);
    for var in &sel_vars {
        let _ = writeln!(out, "    uint64_t {} = 0;", sel_var(*var));
    }
    let vec_type_map: BTreeMap<u8, VecArrangement> = resolve_block_vec_types(body);
    let mut declared_vec: BTreeSet<u8> = BTreeSet::new();
    for (k, (reg, arr)) in signature.vec.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {} {} = a{};",
            arr.type_name(),
            vec_var(*reg),
            scalar_count + k
        );
        declared_vec.insert(*reg);
    }
    for (reg, arr) in &vec_type_map {
        if declared_vec.insert(*reg) {
            let _ = writeln!(out, "    {} {};", arr.type_name(), vec_var(*reg));
        }
    }

    let ret_expr: String = if sret.is_some() {
        "__sret".to_owned()
    } else {
        match signature.ret {
            FnReturn::Int(return_width) => {
                let mut masked: String = String::new();
                width_mask(&mut masked, return_width, reg_var(Reg::Rax));
                masked
            }
            FnReturn::Fp(width) => fp_load(&FpOperand::Xmm(Xmm::Xmm0), width, aggregates),
            FnReturn::Void => String::new(),
            FnReturn::Vec(_) => vec_var(0),
        }
    };

    emit_block(&mut out, body, &ret_expr, aggregates);

    if !matches!(body.last(), Some(Node::Return)) {
        let rendered: String = c_render_stmt(|cx| {
            if ret_expr.is_empty() {
                CStmt::Return(None)
            } else {
                CStmt::Return(Some(cx.var(&ret_expr)))
            }
        });
        write_indented(&mut out, &rendered, "    ");
    }
    let _ = writeln!(out, "}}");
    out
}

fn block_string_ops_present(body: &Block) -> bool {
    body.iter().any(|node: &Node| match node {
        Node::Stmt(stmt) => matches!(stmt, Stmt::BlockMove { .. } | Stmt::BlockFill { .. }),
        Node::If {
            then_body,
            else_body,
            ..
        } => {
            block_string_ops_present(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|b: &Block| block_string_ops_present(b))
        }
        Node::DoWhile { body, .. } | Node::While { body, .. } => block_string_ops_present(body),
        Node::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|c: &SwitchCase| block_string_ops_present(&c.body))
                || block_string_ops_present(default)
        }
        Node::CondSnapshot { .. }
        | Node::Break
        | Node::Continue
        | Node::Return
        | Node::Label(_)
        | Node::Goto(_) => false,
    })
}

fn collect_block_regs(body: &Block, acc: &mut Vec<Reg>) {
    let push = |reg: Reg, acc: &mut Vec<Reg>| {
        if !acc.contains(&reg) {
            acc.push(reg);
        }
    };
    let push_addr = |mem: &MemRef, acc: &mut Vec<Reg>| {
        if let Some(b) = mem.base {
            push(b, acc);
        }
        if let Some(idx) = mem.index {
            push(idx.reg, acc);
        }
    };
    let push_src = |src: &Source, acc: &mut Vec<Reg>| match src {
        Source::Reg(r) => push(r.reg, acc),
        Source::Mem(mem) => push_addr(mem, acc),
        Source::Lea { base, index, .. } => {
            if let Some(b) = base {
                push(*b, acc);
            }
            if let Some(idx) = index {
                push(idx.reg, acc);
            }
        }
        Source::Imm(_) => {}
    };
    let push_flags = |flags: &Flags, acc: &mut Vec<Reg>| match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            push(lhs.reg, acc);
            push_src(rhs, acc);
        }
        Flags::CmpMem { lhs, rhs } => {
            push_addr(lhs, acc);
            push_src(rhs, acc);
        }
        Flags::Test { operand } | Flags::TestImm { operand, .. } => push(operand.reg, acc),
        Flags::Sign { result } => push(result.reg, acc),
        Flags::FpCmp { rhs, .. } => {
            if let FpOperand::Mem(mem) = rhs {
                push_addr(mem, acc);
            }
        }
        Flags::Snapshot { .. } => {}
        Flags::CondCmp { .. } => {
            for reg in flag_operand_regs(flags) {
                push(reg, acc);
            }
        }
    };
    for node in body {
        match node {
            Node::Stmt(stmt) => match stmt {
                Stmt::Assign { dest, src } | Stmt::BinAssign { dest, src, .. } => {
                    push(dest.reg, acc);
                    push_src(src, acc);
                }
                Stmt::UnAssign { dest, .. } => push(dest.reg, acc),
                Stmt::Cond {
                    dest, src, flags, ..
                } => {
                    push(dest.reg, acc);
                    push_src(src, acc);
                    push_flags(flags, acc);
                }
                Stmt::SetCc { dest, flags, .. } => {
                    push(dest.reg, acc);
                    push_flags(flags, acc);
                }
                Stmt::Store { addr, src } => {
                    push_addr(addr, acc);
                    push_src(src, acc);
                }
                Stmt::MemRmw { addr, op } => {
                    push_addr(addr, acc);
                    if let Some(src) = op.source() {
                        push_src(src, acc);
                    }
                }
                Stmt::Extend { dest, src, .. } => {
                    push(dest.reg, acc);
                    match src {
                        ExtSource::Reg(r) => push(r.reg, acc),
                        ExtSource::Mem(mem) => push_addr(mem, acc),
                    }
                }
                Stmt::MulImm { dest, src, .. } => {
                    push(dest.reg, acc);
                    match src {
                        ExtSource::Reg(r) => push(r.reg, acc),
                        ExtSource::Mem(mem) => push_addr(mem, acc),
                    }
                }
                Stmt::WideMul { src } => {
                    push(Reg::Rax, acc);
                    push(Reg::Rdx, acc);
                    push(src.reg, acc);
                }
                Stmt::Divide { divisor, .. } => {
                    push(Reg::Rax, acc);
                    push(Reg::Rdx, acc);
                    push(divisor.reg, acc);
                }
                Stmt::DoubleShift { dest, src, .. } => {
                    push(dest.reg, acc);
                    push(src.reg, acc);
                }
                Stmt::BlockMove { .. } => {
                    push(Reg::Rdi, acc);
                    push(Reg::Rsi, acc);
                    push(Reg::Rcx, acc);
                }
                Stmt::BlockFill { .. } => {
                    push(Reg::Rdi, acc);
                    push(Reg::Rax, acc);
                    push(Reg::Rcx, acc);
                }
                Stmt::IntToFp { src, .. } => push(src.reg, acc),
                Stmt::FpToInt { dest, .. } => push(dest.reg, acc),
                Stmt::FpBin { lhs, rhs, .. } => {
                    if let FpOperand::Mem(mem) = lhs {
                        push_addr(mem, acc);
                    }
                    if let FpOperand::Mem(mem) = rhs {
                        push_addr(mem, acc);
                    }
                }
                Stmt::FpMov { src, .. } => {
                    if let FpOperand::Mem(mem) = src {
                        push_addr(mem, acc);
                    }
                }
                Stmt::FpStore { addr, .. } => push_addr(addr, acc),
                Stmt::FpMinMax { lhs, rhs, .. } => {
                    if let FpOperand::Mem(mem) = lhs {
                        push_addr(mem, acc);
                    }
                    if let FpOperand::Mem(mem) = rhs {
                        push_addr(mem, acc);
                    }
                }
                Stmt::FpFma {
                    mul_lhs,
                    mul_rhs,
                    addend,
                    ..
                } => {
                    for operand in [mul_lhs, mul_rhs, addend] {
                        if let FpOperand::Mem(mem) = operand {
                            push_addr(mem, acc);
                        }
                    }
                }
                Stmt::FpCsel {
                    if_true,
                    if_false,
                    flags,
                    ..
                } => {
                    for operand in [if_true, if_false] {
                        if let FpOperand::Mem(mem) = operand {
                            push_addr(mem, acc);
                        }
                    }
                    push_flags(flags, acc);
                }
                Stmt::FpSqrt { src, .. } | Stmt::FpUnary { src, .. } => {
                    if let FpOperand::Mem(mem) = src {
                        push_addr(mem, acc);
                    }
                }
                Stmt::FpRound { src, .. } => {
                    if let FpOperand::Mem(mem) = src {
                        push_addr(mem, acc);
                    }
                }
                Stmt::GprToXmm { src, .. } => push(src.reg, acc),
                Stmt::XmmToGpr { dest, .. } => push(dest.reg, acc),
                Stmt::FpConvert { .. } => {}
                Stmt::Packed { op, .. } => {
                    if let PackedOp::FromGpr { src } = op {
                        push(src.reg, acc);
                    }
                }
                Stmt::PackedToGpr { dest, .. } => push(dest.reg, acc),
                Stmt::Vector(vec) => match vec {
                    VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => {
                        push_addr(addr, acc);
                    }
                    VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => {
                        push(src.reg, acc);
                    }
                    VecStmt::ExtractToGpr { dest, .. } => push(dest.reg, acc),
                    VecStmt::Bin { .. }
                    | VecStmt::Compare { .. }
                    | VecStmt::MoveImm { .. }
                    | VecStmt::Reduce { .. }
                    | VecStmt::WidenExtend { .. }
                    | VecStmt::WidenAdd { .. } => {}
                },
                Stmt::FlagSnapshot { flags, .. } => push_flags(flags, acc),
                Stmt::Call { args, .. } => {
                    for reg in args {
                        push(*reg, acc);
                    }
                    push(Reg::Rax, acc);
                }
            },
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| push_flags(flags, acc));
                collect_block_regs(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_block_regs(else_b, acc);
                }
            }
            Node::DoWhile { body, cond } => {
                collect_block_regs(body, acc);
                if let LoopCond::Direct { flags, .. } = cond {
                    push_flags(flags, acc);
                }
            }
            Node::While { body, cond } => {
                collect_block_regs(body, acc);
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    push_flags(flags, acc);
                }
            }
            Node::Switch {
                disc,
                cases,
                default,
            } => {
                push(disc.reg, acc);
                for case in cases {
                    collect_block_regs(&case.body, acc);
                }
                collect_block_regs(default, acc);
            }
            Node::CondSnapshot { flags, .. } => push_flags(flags, acc),
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
    }
}

fn collect_block_xmm(body: &Block, acc: &mut Vec<Xmm>) {
    let push = |xmm: Xmm, acc: &mut Vec<Xmm>| {
        if !acc.contains(&xmm) {
            acc.push(xmm);
        }
    };
    let push_operand = |operand: &FpOperand, acc: &mut Vec<Xmm>| {
        if let FpOperand::Xmm(x) = operand {
            push(*x, acc);
        }
    };
    let push_flags = |flags: &Flags, acc: &mut Vec<Xmm>| {
        if let Flags::FpCmp { lhs, rhs, .. } = flags {
            push(*lhs, acc);
            push_operand(rhs, acc);
        }
    };
    for node in body {
        match node {
            Node::Stmt(stmt) => match stmt {
                Stmt::FpBin { dest, lhs, rhs, .. } => {
                    push(*dest, acc);
                    push_operand(lhs, acc);
                    push_operand(rhs, acc);
                }
                Stmt::FpMov { dest, src, .. } => {
                    push(*dest, acc);
                    push_operand(src, acc);
                }
                Stmt::FpStore { src, .. } => push(*src, acc),
                Stmt::IntToFp { dest, .. } => push(*dest, acc),
                Stmt::FpToInt { src, .. } => push(*src, acc),
                Stmt::FpConvert { dest, src, .. } => {
                    push(*dest, acc);
                    push(*src, acc);
                }
                Stmt::FpMinMax { dest, lhs, rhs, .. } => {
                    push(*dest, acc);
                    push_operand(lhs, acc);
                    push_operand(rhs, acc);
                }
                Stmt::FpFma {
                    dest,
                    mul_lhs,
                    mul_rhs,
                    addend,
                    ..
                } => {
                    push(*dest, acc);
                    push_operand(mul_lhs, acc);
                    push_operand(mul_rhs, acc);
                    push_operand(addend, acc);
                }
                Stmt::FpCsel {
                    dest,
                    if_true,
                    if_false,
                    flags,
                    ..
                } => {
                    push(*dest, acc);
                    push_operand(if_true, acc);
                    push_operand(if_false, acc);
                    push_flags(flags, acc);
                }
                Stmt::FpSqrt { dest, src, .. } | Stmt::FpUnary { dest, src, .. } => {
                    push(*dest, acc);
                    push_operand(src, acc);
                }
                Stmt::FpRound { dest, src, .. } => {
                    push(*dest, acc);
                    push_operand(src, acc);
                }
                Stmt::GprToXmm { dest, .. } => push(*dest, acc),
                Stmt::XmmToGpr { src, .. } => push(*src, acc),
                Stmt::Cond { flags, .. } | Stmt::SetCc { flags, .. } => push_flags(flags, acc),
                Stmt::Assign { .. }
                | Stmt::BinAssign { .. }
                | Stmt::UnAssign { .. }
                | Stmt::Store { .. }
                | Stmt::MemRmw { .. }
                | Stmt::Extend { .. }
                | Stmt::MulImm { .. }
                | Stmt::WideMul { .. }
                | Stmt::Divide { .. }
                | Stmt::DoubleShift { .. }
                | Stmt::BlockMove { .. }
                | Stmt::BlockFill { .. }
                | Stmt::FlagSnapshot { .. }
                | Stmt::Packed { .. }
                | Stmt::PackedToGpr { .. }
                | Stmt::Vector(_)
                | Stmt::Call { .. } => {}
            },
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_leaves(&mut |_: CondKind, flags: &Flags| push_flags(flags, acc));
                collect_block_xmm(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_block_xmm(else_b, acc);
                }
            }
            Node::DoWhile { body, cond } => {
                collect_block_xmm(body, acc);
                if let LoopCond::Direct { flags, .. } = cond {
                    push_flags(flags, acc);
                }
            }
            Node::While { body, cond } => {
                collect_block_xmm(body, acc);
                if let Some(LoopCond::Direct { flags, .. }) = cond {
                    push_flags(flags, acc);
                }
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_block_xmm(&case.body, acc);
                }
                collect_block_xmm(default, acc);
            }
            Node::CondSnapshot { flags, .. } => push_flags(flags, acc),
            Node::Break | Node::Continue | Node::Return | Node::Label(_) | Node::Goto(_) => {}
        }
    }
}

fn packed_stmt_lanes(stmt: &Stmt, acc: &mut Vec<Xmm>) {
    let push = |xmm: Xmm, acc: &mut Vec<Xmm>| {
        if !acc.contains(&xmm) {
            acc.push(xmm);
        }
    };
    match stmt {
        Stmt::Packed { dest, op } => {
            push(*dest, acc);
            match op {
                PackedOp::MovReg(src)
                | PackedOp::AddQ(src)
                | PackedOp::And(src)
                | PackedOp::AndN(src)
                | PackedOp::CmpEqD(src)
                | PackedOp::ShufD { src, .. } => push(*src, acc),
                PackedOp::Const { .. }
                | PackedOp::Zero
                | PackedOp::ShlQ(_)
                | PackedOp::ShlDq(_)
                | PackedOp::FromGpr { .. } => {}
            }
        }
        Stmt::PackedToGpr { src, .. } => push(*src, acc),
        _ => {}
    }
}

fn collect_block_packed_xmm(body: &Block, acc: &mut Vec<Xmm>) {
    for node in body {
        match node {
            Node::Stmt(stmt) => packed_stmt_lanes(stmt, acc),
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_block_packed_xmm(then_body, acc);
                if let Some(else_b) = else_body {
                    collect_block_packed_xmm(else_b, acc);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_block_packed_xmm(body, acc);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_block_packed_xmm(&case.body, acc);
                }
                collect_block_packed_xmm(default, acc);
            }
            Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn for_each_vec_stmt(body: &Block, visit: &mut impl FnMut(&VecStmt)) {
    for node in body {
        match node {
            Node::Stmt(Stmt::Vector(vec)) => visit(vec),
            Node::Stmt(_)
            | Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                for_each_vec_stmt(then_body, visit);
                if let Some(else_b) = else_body {
                    for_each_vec_stmt(else_b, visit);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => for_each_vec_stmt(body, visit),
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    for_each_vec_stmt(&case.body, visit);
                }
                for_each_vec_stmt(default, visit);
            }
        }
    }
}

fn block_has_vector(body: &Block) -> bool {
    let mut found: bool = false;
    for_each_vec_stmt(body, &mut |_: &VecStmt| found = true);
    found
}

fn merge_max_vec_width(map: &mut BTreeMap<u8, VecArrangement>, reg: u8, arr: VecArrangement) {
    map.entry(reg)
        .and_modify(|existing: &mut VecArrangement| {
            if arr.total_bits() > existing.total_bits() {
                *existing = arr;
            }
        })
        .or_insert(arr);
}

fn resolve_block_vec_types(body: &Block) -> BTreeMap<u8, VecArrangement> {
    let mut types: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    let mut mem_types: BTreeMap<u8, VecArrangement> = BTreeMap::new();
    for_each_vec_stmt(body, &mut |vec: &VecStmt| match vec {
        VecStmt::Load { dest, arr, .. } => {
            if let Some(arrangement) = arr {
                merge_max_vec_width(&mut mem_types, *dest, *arrangement);
            }
        }
        VecStmt::Store { src, arr, .. } => {
            if let Some(arrangement) = arr {
                merge_max_vec_width(&mut mem_types, *src, *arrangement);
            }
        }
        VecStmt::Bin {
            dest,
            lhs,
            rhs,
            arr,
            ..
        } => {
            types.entry(*dest).or_insert(*arr);
            types.entry(*lhs).or_insert(*arr);
            types.entry(*rhs).or_insert(*arr);
        }
        VecStmt::Dup { dest, arr, .. } | VecStmt::LaneInsert { dest, arr, .. } => {
            types.entry(*dest).or_insert(*arr);
        }
        VecStmt::Compare {
            dest,
            lhs,
            rhs,
            arr,
        } => {
            types.entry(*dest).or_insert(*arr);
            types.entry(*lhs).or_insert(*arr);
            if let Some(rhs) = rhs {
                types.entry(*rhs).or_insert(*arr);
            }
        }
        VecStmt::MoveImm { dest, arr, .. } => {
            types.entry(*dest).or_insert(*arr);
        }
        VecStmt::Reduce { reg, src, .. } => {
            types.entry(*reg).or_insert(*src);
        }
        VecStmt::ExtractToGpr { src, elem, .. } => {
            types
                .entry(*src)
                .or_insert_with(|| VecArrangement::whole_register(*elem));
        }
        VecStmt::WidenExtend {
            dest,
            src,
            src_elem,
            dest_elem,
            ..
        } => {
            types
                .entry(*dest)
                .or_insert_with(|| VecArrangement::whole_register(*dest_elem));
            types
                .entry(*src)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
        }
        VecStmt::WidenAdd {
            dest,
            src1,
            src2,
            src_elem,
            dest_elem,
            ..
        } => {
            types
                .entry(*dest)
                .or_insert_with(|| VecArrangement::whole_register(*dest_elem));
            types
                .entry(*src1)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
            types
                .entry(*src2)
                .or_insert_with(|| VecArrangement::whole_register(*src_elem));
        }
    });
    for (reg, arr) in mem_types {
        types.entry(reg).or_insert(arr);
    }
    types
}

fn collect_block_vec_arrangements(body: &Block, acc: &mut BTreeSet<VecArrangement>) {
    for_each_vec_stmt(body, &mut |vec: &VecStmt| match vec {
        VecStmt::Load { arr, .. } | VecStmt::Store { arr, .. } => {
            if let Some(arrangement) = arr
                && arrangement.total_bits() == 128
            {
                acc.insert(*arrangement);
            }
        }
        VecStmt::Bin { arr, .. }
        | VecStmt::Dup { arr, .. }
        | VecStmt::LaneInsert { arr, .. }
        | VecStmt::Compare { arr, .. }
        | VecStmt::MoveImm { arr, .. } => {
            acc.insert(*arr);
        }
        VecStmt::Reduce { src, dest, .. } => {
            acc.insert(*src);
            acc.insert(VecArrangement::whole_register(*dest));
        }
        VecStmt::ExtractToGpr { elem, .. } => {
            acc.insert(VecArrangement::whole_register(*elem));
        }
        VecStmt::WidenExtend {
            src_elem,
            dest_elem,
            ..
        }
        | VecStmt::WidenAdd {
            src_elem,
            dest_elem,
            ..
        } => {
            acc.insert(VecArrangement::whole_register(*src_elem));
            acc.insert(VecArrangement::whole_register(*dest_elem));
        }
    });
}

fn write_indented(out: &mut String, text: &str, indent: &str) {
    for line in text.lines() {
        let _ = writeln!(out, "{indent}{line}");
    }
}

fn assign_expr_cstmt(cx: &mut Cx<'_>, var: &str, rhs: CExpr) -> CStmt {
    let lhs: CExpr = cx.var(var);
    CStmt::Expr(CExpr::Assign {
        op: AssignOp::Assign,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })
}

fn assign_cstmt(cx: &mut Cx<'_>, var: &str, rhs: &str) -> CStmt {
    let rhs_expr: CExpr = cx.var(rhs);
    assign_expr_cstmt(cx, var, rhs_expr)
}

fn decl_with_init(cx: &mut Cx<'_>, ty_name: &str, name: &str, init: CExpr) -> CStmt {
    let base: CBaseType = CBaseType::plain(cx.named_type(ty_name));
    let decl: CDecl = CDecl {
        storage: None,
        base,
        name: Some(cx.sym(name)),
        declarator: DeclaratorChain::Terminal,
        init: Some(CInit::Expr(init)),
    };
    CStmt::Decl(decl)
}

fn case_value_expr(value: i64) -> CExpr {
    if value < 0 {
        CExpr::Unary {
            op: UnaryOp::Neg,
            operand: Box::new(CExpr::Int {
                value: value.unsigned_abs(),
                radix: Radix::Dec,
                suffix: IntSuffix::none(),
            }),
        }
    } else {
        CExpr::Int {
            value: value as u64,
            radix: Radix::Dec,
            suffix: IntSuffix::none(),
        }
    }
}

fn switch_key_expr(disc: RegRef, cases: &[SwitchCase], plan: &AggregatePlan) -> String {
    let key: String = source_expr(&Source::Reg(disc), disc.width, plan);
    let signed: bool = cases
        .iter()
        .any(|case: &SwitchCase| case.values.iter().any(|value: &i64| *value < 0));
    if !signed {
        return key;
    }
    match disc.width {
        Width::W8 => format!("(int8_t)(uint8_t)({key})"),
        Width::W16 => format!("(int16_t)(uint16_t)({key})"),
        Width::W32 => format!("(int32_t)(uint32_t)({key})"),
        Width::W64 => format!("(int64_t)({key})"),
    }
}

fn switch_case_chain(
    cx: &mut Cx<'_>,
    case: &SwitchCase,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> CStmt {
    let mut stmts: Vec<CStmt> = block_to_cstmts(cx, &case.body, ret_expr, aggregates);
    if !case.fallthrough {
        stmts.push(CStmt::Break);
    }
    let mut chain: CStmt = CStmt::Block(stmts);
    for &value in case.values.iter().rev() {
        chain = CStmt::Case {
            value: case_value_expr(value),
            body: Box::new(chain),
        };
    }
    chain
}

fn switch_default_cstmt(
    cx: &mut Cx<'_>,
    default: &Block,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> CStmt {
    let mut stmts: Vec<CStmt> = block_to_cstmts(cx, default, ret_expr, aggregates);
    stmts.push(CStmt::Break);
    CStmt::Default {
        body: Box::new(CStmt::Block(stmts)),
    }
}

fn node_to_cstmt(
    cx: &mut Cx<'_>,
    node: &Node,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> CStmt {
    match node {
        Node::Stmt(stmt) => stmt_to_cstmt(cx, stmt, aggregates),
        Node::If {
            cond,
            then_body,
            else_body,
        } => {
            let cond_text: String = if_cond_expr(cond, aggregates);
            let then_cstmt: CStmt = braced_block(cx, then_body, ret_expr, aggregates);
            let els_cstmt: Option<Box<CStmt>> = else_body
                .as_ref()
                .map(|b: &Block| Box::new(braced_block(cx, b, ret_expr, aggregates)));
            CStmt::If {
                cond: cx.var(&cond_text),
                then: Box::new(then_cstmt),
                els: els_cstmt,
            }
        }
        Node::DoWhile { body, cond } => {
            let cond_text: String = match cond {
                LoopCond::Direct { cond, flags } => cond_expr(*cond, flags, aggregates),
                LoopCond::Snapshot { var } => loop_cond_var(*var),
            };
            CStmt::DoWhile {
                body: Box::new(braced_block(cx, body, ret_expr, aggregates)),
                cond: cx.var(&cond_text),
            }
        }
        Node::While { body, cond } => {
            let condition: CExpr = match cond {
                Some(LoopCond::Direct { cond, flags }) => {
                    let cond_text: String = cond_expr(*cond, flags, aggregates);
                    cx.var(&cond_text)
                }
                Some(LoopCond::Snapshot { var }) => cx.var(&loop_cond_var(*var)),
                None => CExpr::int(1),
            };
            CStmt::While {
                cond: condition,
                body: Box::new(braced_block(cx, body, ret_expr, aggregates)),
            }
        }
        Node::Switch {
            disc,
            cases,
            default,
        } => {
            let key: String = switch_key_expr(*disc, cases, aggregates);
            let mut body_stmts: Vec<CStmt> = Vec::with_capacity(cases.len() + 1);
            for case in cases {
                body_stmts.push(switch_case_chain(cx, case, ret_expr, aggregates));
            }
            body_stmts.push(switch_default_cstmt(cx, default, ret_expr, aggregates));
            CStmt::Switch {
                value: cx.var(&key),
                body: Box::new(CStmt::Block(body_stmts)),
            }
        }
        Node::CondSnapshot { var, cond, flags } => {
            let cond_text: String = cond_expr(*cond, flags, aggregates);
            assign_cstmt(cx, &loop_cond_var(*var), &cond_text)
        }
        Node::Break => CStmt::Break,
        Node::Continue => CStmt::Continue,
        Node::Return => {
            if ret_expr.is_empty() {
                CStmt::Return(None)
            } else {
                CStmt::Return(Some(cx.var(ret_expr)))
            }
        }
        Node::Label(id) => CStmt::Label {
            name: cx.sym(&label_name(*id)),
            body: Box::new(CStmt::Empty),
        },
        Node::Goto(id) => CStmt::Goto(cx.sym(&label_name(*id))),
    }
}

fn label_name(id: u32) -> String {
    format!("recover_L{id}")
}

fn block_to_cstmts(
    cx: &mut Cx<'_>,
    body: &Block,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> Vec<CStmt> {
    let mut stmts: Vec<CStmt> = Vec::with_capacity(body.len());
    for node in body {
        stmts.push(node_to_cstmt(cx, node, ret_expr, aggregates));
    }
    stmts
}

fn braced_block(
    cx: &mut Cx<'_>,
    body: &Block,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> CStmt {
    CStmt::Block(block_to_cstmts(cx, body, ret_expr, aggregates))
}

fn emit_block(out: &mut String, body: &Block, ret_expr: &str, aggregates: &AggregatePlan) {
    let mut interner: Interner = Interner::new();
    let stmts: Vec<CStmt> = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        block_to_cstmts(&mut cx, body, ret_expr, aggregates)
    };
    for stmt in &stmts {
        let rendered: String = render_stmt(stmt, &interner, C_RENDER_WIDTH);
        write_indented(out, &rendered, "    ");
    }
}

fn c_render_stmt(build: impl FnOnce(&mut Cx<'_>) -> CStmt) -> String {
    let mut interner: Interner = Interner::new();
    let stmt: CStmt = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        build(&mut cx)
    };
    render_stmt(&stmt, &interner, C_RENDER_WIDTH)
}

fn packed_lane(xmm: Xmm, hi: bool) -> String {
    format!("v{}_{}", xmm.index(), if hi { "hi" } else { "lo" })
}

fn packed_dword_expr(lo: &str, hi: &str, dword: u8) -> String {
    match dword & 3 {
        0 => format!("((uint64_t)(uint32_t){lo})"),
        1 => format!("((uint64_t)(uint32_t)({lo} >> 32))"),
        2 => format!("((uint64_t)(uint32_t){hi})"),
        _ => format!("((uint64_t)(uint32_t)({hi} >> 32))"),
    }
}

fn packed_cmpeqd_lane(dest: &str, src: &str) -> String {
    let low: String = format!("(((uint32_t){dest} == (uint32_t){src}) ? 0xffffffffULL : 0ULL)");
    let high: String =
        format!("(((uint32_t)({dest} >> 32) == (uint32_t)({src} >> 32)) ? 0xffffffffULL : 0ULL)");
    format!("({low} | ({high} << 32))")
}

fn packed_op_cstmt(cx: &mut Cx<'_>, dest: Xmm, op: &PackedOp) -> CStmt {
    let d_lo: String = packed_lane(dest, false);
    let d_hi: String = packed_lane(dest, true);
    let mut stmts: Vec<CStmt> = Vec::new();
    match op {
        PackedOp::MovReg(src) => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            stmts.push(assign_cstmt(cx, &d_lo, &s_lo));
            stmts.push(assign_cstmt(cx, &d_hi, &s_hi));
        }
        PackedOp::Const { q0, q1 } => {
            stmts.push(assign_cstmt(cx, &d_lo, &format!("0x{q0:x}ULL")));
            stmts.push(assign_cstmt(cx, &d_hi, &format!("0x{q1:x}ULL")));
        }
        PackedOp::Zero => {
            stmts.push(assign_cstmt(cx, &d_lo, "0ULL"));
            stmts.push(assign_cstmt(cx, &d_hi, "0ULL"));
        }
        PackedOp::AddQ(src) => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            stmts.push(assign_cstmt(cx, &d_lo, &format!("{d_lo} + {s_lo}")));
            stmts.push(assign_cstmt(cx, &d_hi, &format!("{d_hi} + {s_hi}")));
        }
        PackedOp::And(src) => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            stmts.push(assign_cstmt(cx, &d_lo, &format!("{d_lo} & {s_lo}")));
            stmts.push(assign_cstmt(cx, &d_hi, &format!("{d_hi} & {s_hi}")));
        }
        PackedOp::AndN(src) => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            stmts.push(assign_cstmt(cx, &d_lo, &format!("(~{d_lo}) & {s_lo}")));
            stmts.push(assign_cstmt(cx, &d_hi, &format!("(~{d_hi}) & {s_hi}")));
        }
        PackedOp::ShlQ(imm) => {
            if *imm >= 64 {
                stmts.push(assign_cstmt(cx, &d_lo, "0ULL"));
                stmts.push(assign_cstmt(cx, &d_hi, "0ULL"));
            } else {
                stmts.push(assign_cstmt(cx, &d_lo, &format!("{d_lo} << {imm}")));
                stmts.push(assign_cstmt(cx, &d_hi, &format!("{d_hi} << {imm}")));
            }
        }
        PackedOp::ShlDq(imm) => {
            let (lo_expr, hi_expr): (String, String) = packed_shldq_exprs(*imm, "vsd_lo", "vsd_hi");
            let lo_init: CExpr = cx.var(&d_lo);
            stmts.push(decl_with_init(cx, "uint64_t", "vsd_lo", lo_init));
            let hi_init: CExpr = cx.var(&d_hi);
            stmts.push(decl_with_init(cx, "uint64_t", "vsd_hi", hi_init));
            stmts.push(assign_cstmt(cx, &d_lo, &lo_expr));
            stmts.push(assign_cstmt(cx, &d_hi, &hi_expr));
        }
        PackedOp::CmpEqD(src) => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            let lo_expr: String = packed_cmpeqd_lane(&d_lo, &s_lo);
            let hi_expr: String = packed_cmpeqd_lane(&d_hi, &s_hi);
            stmts.push(assign_cstmt(cx, &d_lo, &lo_expr));
            stmts.push(assign_cstmt(cx, &d_hi, &hi_expr));
        }
        PackedOp::ShufD { src, imm } => {
            let s_lo: String = packed_lane(*src, false);
            let s_hi: String = packed_lane(*src, true);
            let lo_init: CExpr = cx.var(&s_lo);
            stmts.push(decl_with_init(cx, "uint64_t", "vsf_lo", lo_init));
            let hi_init: CExpr = cx.var(&s_hi);
            stmts.push(decl_with_init(cx, "uint64_t", "vsf_hi", hi_init));
            let d0: String = packed_dword_expr("vsf_lo", "vsf_hi", imm & 3);
            let d1: String = packed_dword_expr("vsf_lo", "vsf_hi", (imm >> 2) & 3);
            let d2: String = packed_dword_expr("vsf_lo", "vsf_hi", (imm >> 4) & 3);
            let d3: String = packed_dword_expr("vsf_lo", "vsf_hi", (imm >> 6) & 3);
            stmts.push(assign_cstmt(cx, &d_lo, &format!("{d0} | ({d1} << 32)")));
            stmts.push(assign_cstmt(cx, &d_hi, &format!("{d2} | ({d3} << 32)")));
        }
        PackedOp::FromGpr { src } => {
            let mut masked: String = String::new();
            width_mask(&mut masked, src.width, reg_var(src.reg));
            stmts.push(assign_cstmt(cx, &d_lo, &masked));
            stmts.push(assign_cstmt(cx, &d_hi, "0ULL"));
        }
    }
    CStmt::Block(stmts)
}

fn packed_shldq_exprs(imm: u8, lo: &str, hi: &str) -> (String, String) {
    if imm >= 16 {
        return ("0ULL".to_owned(), "0ULL".to_owned());
    }
    let bits: u32 = u32::from(imm) * 8;
    if bits == 0 {
        return (lo.to_owned(), hi.to_owned());
    }
    if bits < 64 {
        let lo_expr: String = format!("({lo} << {bits})");
        let hi_expr: String = format!("(({hi} << {bits}) | ({lo} >> {}))", 64 - bits);
        return (lo_expr, hi_expr);
    }
    if bits == 64 {
        return ("0ULL".to_owned(), lo.to_owned());
    }
    ("0ULL".to_owned(), format!("({lo} << {})", bits - 64))
}

fn c_fp_rint(mode: RoundMode, value: &str, width: FpWidth) -> String {
    let name: &'static str = fp_semantics::rint_helper(mode, width);
    c_render(|cx| {
        let arg: CExpr = cx.var(value);
        cx.call(name, vec![arg])
    })
}

fn stmt_to_cstmt(cx: &mut Cx<'_>, stmt: &Stmt, aggregates: &AggregatePlan) -> CStmt {
    match stmt {
        Stmt::Assign { dest, src } => {
            let body: String = source_expr(src, dest.width, aggregates);
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::BinAssign { dest, op, src } => {
            let var: &'static str = reg_var(dest.reg);
            let rhs_src: String = source_expr(src, dest.width, aggregates);
            let body: String = bin_expr(*op, var, &rhs_src, dest.width);
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::UnAssign { dest, op } => {
            let var: &'static str = reg_var(dest.reg);
            let body: String = match op {
                UnOp::Neg => c_render(|cx| {
                    let inner: CExpr = cx.var(var);
                    let signed: CExpr = c_cast(cx, "int64_t", inner);
                    let negated: CExpr = CExpr::Unary {
                        op: UnaryOp::Neg,
                        operand: Box::new(signed),
                    };
                    c_cast(cx, "uint64_t", negated)
                }),
                UnOp::Not => c_render(|cx| CExpr::Unary {
                    op: UnaryOp::BitNot,
                    operand: Box::new(cx.var(var)),
                }),
                UnOp::Bswap => c_bswap_expr(var, dest.width),
                UnOp::Clz => c_clz_expr(var, dest.width),
                UnOp::Rbit => c_rbit_expr(var, dest.width),
                UnOp::Rev16 => c_rev16_expr(var, dest.width),
                UnOp::Rev32 => c_rev32_expr(var),
            };
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::Cond {
            dest,
            src,
            kind,
            flags,
        } => {
            let cond: String = cond_expr(*kind, flags, aggregates);
            let chosen: String = source_expr(src, dest.width, aggregates);
            let var: &'static str = reg_var(dest.reg);
            let taken: String = reg_write_rhs(var, dest.width, &chosen);
            let body: String = c_render(|cx| CExpr::Ternary {
                cond: Box::new(cx.var(&cond)),
                then: Box::new(cx.var(&taken)),
                els: Box::new(cx.var(var)),
            });
            assign_cstmt(cx, var, &body)
        }
        Stmt::SetCc { dest, kind, flags } => {
            let cond: String = cond_expr(*kind, flags, aggregates);
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = c_render(|cx| {
                let kept: CExpr = c_bin(
                    BinaryOp::BitAnd,
                    cx.var(var),
                    c_hex_mask(0xffff_ffff_ffff_ff00),
                );
                let cond_opaque: CExpr = c_opaque(cx, &cond);
                let ternary: CExpr = CExpr::Ternary {
                    cond: Box::new(cond_opaque),
                    then: Box::new(CExpr::int(1)),
                    els: Box::new(CExpr::int(0)),
                };
                let widened: CExpr = c_cast(cx, "uint64_t", ternary);
                c_bin(BinaryOp::BitOr, kept, widened)
            });
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::FlagSnapshot { var, kind, flags } => {
            let cond: String = cond_expr(*kind, flags, aggregates);
            assign_cstmt(cx, &sel_var(*var), &cond)
        }
        Stmt::Store { addr, src } => {
            let target: String =
                slot_typed_lvalue(addr, aggregates).unwrap_or_else(|| deref_expr(addr, aggregates));
            let value: String = source_expr(src, addr.width, aggregates);
            let mut masked: String = String::new();
            width_mask(&mut masked, addr.width, &value);
            assign_cstmt(cx, &target, &masked)
        }
        Stmt::MemRmw { addr, op } => {
            let target: String = deref_expr(addr, aggregates);
            let current: String = c_render(|cx| {
                let inner: CExpr = cx.var(&target);
                c_cast(cx, "uint64_t", inner)
            });
            let body: String = match op {
                MemRmwOp::Bin { op, src } => {
                    let rhs: String = source_expr(src, addr.width, aggregates);
                    bin_expr(*op, &current, &rhs, addr.width)
                }
                MemRmwOp::Un(UnOp::Neg) => c_render(|cx| {
                    let inner: CExpr = cx.var(&current);
                    let signed: CExpr = c_cast(cx, "int64_t", inner);
                    let negated: CExpr = CExpr::Unary {
                        op: UnaryOp::Neg,
                        operand: Box::new(signed),
                    };
                    c_cast(cx, "uint64_t", negated)
                }),
                MemRmwOp::Un(UnOp::Not) => c_render(|cx| CExpr::Unary {
                    op: UnaryOp::BitNot,
                    operand: Box::new(cx.var(&current)),
                }),
                MemRmwOp::Un(UnOp::Bswap) => c_bswap_expr(&current, addr.width),
                MemRmwOp::Un(UnOp::Clz) => c_clz_expr(&current, addr.width),
                MemRmwOp::Un(UnOp::Rbit) => c_rbit_expr(&current, addr.width),
                MemRmwOp::Un(UnOp::Rev16) => c_rev16_expr(&current, addr.width),
                MemRmwOp::Un(UnOp::Rev32) => c_rev32_expr(&current),
            };
            let mut masked: String = String::new();
            width_mask(&mut masked, addr.width, &body);
            assign_cstmt(cx, &target, &masked)
        }
        Stmt::Extend { dest, src, signed } => {
            let (raw, src_width): (String, Width) = match src {
                ExtSource::Reg(r) => (reg_var(r.reg).to_string(), r.width),
                ExtSource::Mem(mem) => (deref_expr(mem, aggregates), mem.width),
            };
            let body: String = extend_expr(&raw, src_width, dest.width, *signed);
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::MulImm { dest, src, imm } => {
            let operand: String = match src {
                ExtSource::Reg(r) => reg_var(r.reg).to_string(),
                ExtSource::Mem(mem) => {
                    let d: String = deref_expr(mem, aggregates);
                    c_render(|cx| {
                        let inner: CExpr = cx.var(&d);
                        c_cast(cx, "uint64_t", inner)
                    })
                }
            };
            let imm_val: i64 = *imm;
            let body: String = c_render(|cx| {
                let signed: CExpr = c_cast(cx, "int64_t", c_i64_literal(imm_val));
                let factor: CExpr = c_cast(cx, "uint64_t", signed);
                c_bin(BinaryOp::Mul, cx.var(&operand), factor)
            });
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::WideMul { src } => wide_mul_cstmt(cx, *src),
        Stmt::Divide { divisor, signed } => divide_cstmt(cx, *divisor, *signed),
        Stmt::DoubleShift {
            dest,
            src,
            amount,
            left,
        } => {
            let dst: &'static str = reg_var(dest.reg);
            let other: &'static str = reg_var(src.reg);
            let complement: u32 = 64 - u32::from(*amount);
            let amount_val: u64 = u64::from(*amount);
            let complement_val: u64 = u64::from(complement);
            let body: String = c_render(|cx| {
                let (hi, lo): (CExpr, CExpr) = if *left {
                    (
                        c_bin(BinaryOp::Shl, cx.var(dst), CExpr::int(amount_val)),
                        c_bin(BinaryOp::Shr, cx.var(other), CExpr::int(complement_val)),
                    )
                } else {
                    (
                        c_bin(BinaryOp::Shr, cx.var(dst), CExpr::int(amount_val)),
                        c_bin(BinaryOp::Shl, cx.var(other), CExpr::int(complement_val)),
                    )
                };
                c_bin(BinaryOp::BitOr, hi, lo)
            });
            assign_cstmt(cx, dst, &body)
        }
        Stmt::BlockMove { elem } => block_move_cstmt(cx, *elem),
        Stmt::BlockFill { elem } => block_fill_cstmt(cx, *elem),
        Stmt::Call { target, args, name } => call_cstmt(cx, *target, args, name.as_deref()),
        Stmt::FpBin {
            dest,
            lhs,
            rhs,
            op,
            width,
        } => {
            let lhs_val: String = fp_load(lhs, *width, aggregates);
            let rhs_val: String = fp_load(rhs, *width, aggregates);
            let bin_op: BinaryOp = fp_binary_op(*op);
            let computed: String = c_render(|cx| c_bin(bin_op, cx.var(&lhs_val), cx.var(&rhs_val)));
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&computed, *width))
        }
        Stmt::FpMov { dest, src, width } => {
            let value: String = fp_load(src, *width, aggregates);
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&value, *width))
        }
        Stmt::FpStore { addr, src, width } => {
            if let Some((target, _)) =
                aggregate_c_mem_expr(addr, aggregates, AggregateScalar::Float(*width))
            {
                let value: String = fp_load(&FpOperand::Xmm(*src), *width, aggregates);
                assign_cstmt(cx, &target, &value)
            } else {
                let target: String = deref_expr(addr, aggregates);
                let bits: String = xmm_bits(*src, *width);
                assign_cstmt(cx, &target, &bits)
            }
        }
        Stmt::IntToFp {
            dest,
            src,
            signed,
            width,
            fbits,
        } => {
            let bits: u32 = src.width.bits();
            let rv: &'static str = reg_var(src.reg);
            let ty: String = if *signed {
                format!("int{bits}_t")
            } else {
                format!("uint{bits}_t")
            };
            let int_expr: String = c_render(|cx| {
                let inner: CExpr = cx.var(rv);
                let converted: CExpr = c_cast(cx, &ty, inner);
                match fbits {
                    None => converted,
                    Some(fraction) => {
                        let widened: CExpr = c_cast(cx, width.c_type(), converted);
                        let scale: CExpr = cx.var(&width.c_power_of_two(*fraction));
                        c_bin(BinaryOp::Div, widened, scale)
                    }
                }
            });
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&int_expr, *width))
        }
        Stmt::FpToInt {
            dest,
            src,
            width,
            signed,
            round,
            fbits,
            saturating,
        } => {
            let loaded: String = fp_load(&FpOperand::Xmm(*src), *width, aggregates);
            let value: String = match fbits {
                None => loaded,
                Some(fraction) => c_render(|cx| {
                    let lhs: CExpr = cx.var(&loaded);
                    let scale: CExpr = cx.var(&width.c_power_of_two(*fraction));
                    c_bin(BinaryOp::Mul, lhs, scale)
                }),
            };
            let rounded: String = match round {
                FpToIntRound::Zero => value,
                FpToIntRound::Floor => c_fp_rint(RoundMode::Floor, &value, *width),
                FpToIntRound::Ceil => c_fp_rint(RoundMode::Ceil, &value, *width),
                FpToIntRound::Away => c_fp_rint(RoundMode::TiesAway, &value, *width),
            };
            let bits: u32 = dest.width.bits();
            let convert: Option<&'static str> =
                fp_semantics::cvt_helper(*saturating, *signed, dest.width, *width);
            let truncated: String = c_render(|cx| {
                let opaque: CExpr = c_opaque(cx, &rounded);
                let converted: CExpr = if let Some(helper) = convert {
                    cx.call(helper, vec![opaque])
                } else {
                    let converted_type: String = if *signed {
                        format!("int{bits}_t")
                    } else {
                        format!("uint{bits}_t")
                    };
                    c_cast(cx, &converted_type, opaque)
                };
                if *signed {
                    c_cast(cx, &format!("uint{bits}_t"), converted)
                } else {
                    converted
                }
            });
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &truncated);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::FpConvert {
            dest,
            src,
            from,
            to,
        } => {
            let value: String = fp_load(&FpOperand::Xmm(*src), *from, aggregates);
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&value, *to))
        }
        Stmt::FpMinMax {
            dest,
            lhs,
            rhs,
            kind,
            width,
        } => {
            let lhs_val: String = fp_load(lhs, *width, aggregates);
            let rhs_val: String = fp_load(rhs, *width, aggregates);
            let computed: String = if kind.uses_helper() {
                let name: &'static str =
                    fp_semantics::minmax_helper(kind.is_max(), kind.is_propagating_nan(), *width);
                c_render(|cx| {
                    let lhs_arg: CExpr = cx.var(&lhs_val);
                    let rhs_arg: CExpr = cx.var(&rhs_val);
                    cx.call(name, vec![lhs_arg, rhs_arg])
                })
            } else {
                let cmp_op: BinaryOp = if kind.is_max() {
                    BinaryOp::Gt
                } else {
                    BinaryOp::Lt
                };
                c_render(|cx| CExpr::Ternary {
                    cond: Box::new(c_bin(cmp_op, cx.var(&lhs_val), cx.var(&rhs_val))),
                    then: Box::new(cx.var(&lhs_val)),
                    els: Box::new(cx.var(&rhs_val)),
                })
            };
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&computed, *width))
        }
        Stmt::FpFma {
            dest,
            mul_lhs,
            mul_rhs,
            addend,
            kind,
            width,
        } => {
            let lhs_val: String = fp_load(mul_lhs, *width, aggregates);
            let rhs_val: String = fp_load(mul_rhs, *width, aggregates);
            let addend_val: String = fp_load(addend, *width, aggregates);
            let name: &'static str = fp_semantics::fma_helper(*width);
            let neg_mul: bool = kind.negates_multiplicand();
            let neg_add: bool = kind.negates_addend();
            let computed: String = c_render(|cx| {
                let arg0: CExpr = if neg_mul {
                    CExpr::Unary {
                        op: UnaryOp::Neg,
                        operand: Box::new(cx.var(&lhs_val)),
                    }
                } else {
                    cx.var(&lhs_val)
                };
                let arg1: CExpr = cx.var(&rhs_val);
                let arg2: CExpr = if neg_add {
                    CExpr::Unary {
                        op: UnaryOp::Neg,
                        operand: Box::new(cx.var(&addend_val)),
                    }
                } else {
                    cx.var(&addend_val)
                };
                cx.call(name, vec![arg0, arg1, arg2])
            });
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&computed, *width))
        }
        Stmt::FpCsel {
            dest,
            if_true,
            if_false,
            kind,
            flags,
            width,
        } => {
            let cond: String = cond_expr(*kind, flags, aggregates);
            let taken: String = fp_load(if_true, *width, aggregates);
            let untaken: String = fp_load(if_false, *width, aggregates);
            let computed: String = c_render(|cx| CExpr::Ternary {
                cond: Box::new(c_opaque(cx, &cond)),
                then: Box::new(c_opaque(cx, &taken)),
                els: Box::new(c_opaque(cx, &untaken)),
            });
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&computed, *width))
        }
        Stmt::FpSqrt {
            dest,
            src,
            width,
            saturating,
        } => {
            let value: String = fp_load(src, *width, aggregates);
            let name: &'static str = fp_semantics::sqrt_helper(*saturating, *width);
            let call: String = c_render(|cx| {
                let arg: CExpr = cx.var(&value);
                cx.call(name, vec![arg])
            });
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&call, *width))
        }
        Stmt::FpUnary {
            dest,
            src,
            op,
            width,
        } => {
            let value: String = fp_load(src, *width, aggregates);
            let computed: String = match op {
                FpUnaryOp::Neg => c_render(|cx| CExpr::Unary {
                    op: UnaryOp::Neg,
                    operand: Box::new(cx.var(&value)),
                }),
                FpUnaryOp::Abs => {
                    let name: &str = match width {
                        FpWidth::F64 => "__builtin_fabs",
                        FpWidth::F32 => "__builtin_fabsf",
                    };
                    c_render(|cx| {
                        let arg: CExpr = cx.var(&value);
                        cx.call(name, vec![arg])
                    })
                }
            };
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&computed, *width))
        }
        Stmt::FpRound {
            dest,
            src,
            width,
            mode,
        } => {
            let value: String = fp_load(src, *width, aggregates);
            let call: String = c_fp_rint(*mode, &value, *width);
            assign_cstmt(cx, xmm_var(*dest), &fp_store_expr(&call, *width))
        }
        Stmt::GprToXmm { dest, src, width } => {
            let bits: String = match width {
                FpWidth::F64 => reg_var(src.reg).to_string(),
                FpWidth::F32 => {
                    let rv: &'static str = reg_var(src.reg);
                    c_render(|cx| {
                        let inner: CExpr = cx.var(rv);
                        c_cast(cx, "uint32_t", inner)
                    })
                }
            };
            assign_cstmt(cx, xmm_var(*dest), &bits)
        }
        Stmt::XmmToGpr { dest, src, width } => {
            let bits: String = xmm_bits(*src, *width);
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &bits);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::Packed { dest, op } => packed_op_cstmt(cx, *dest, op),
        Stmt::PackedToGpr { dest, src } => {
            let body: String = packed_lane(*src, false);
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = reg_write_rhs(var, dest.width, &body);
            assign_cstmt(cx, var, &rhs)
        }
        Stmt::Vector(vec) => vec_stmt_cstmt(cx, vec),
    }
}

fn vec_var(reg: u8) -> String {
    if reg < 32 {
        format!("v{reg}")
    } else {
        format!("vw{}", reg - 32)
    }
}

fn vec_resolved_arr(arr: Option<VecArrangement>) -> VecArrangement {
    arr.unwrap_or(VecArrangement {
        lanes: 16,
        elem: VecElem::I8,
    })
}

fn vec_deref_expr(arr: VecArrangement, addr: &MemRef) -> String {
    format!(
        "*({}*)({})",
        arr.mem_type_name(),
        addr_expr(addr.base, addr.index, addr.disp)
    )
}

fn vec_low64_lvalue(reg: u8) -> String {
    format!("*(uint64_t *)(&{})", vec_var(reg))
}

fn vec_low64_mem(addr: &MemRef) -> String {
    format!(
        "*({UNALIGNED_U64_TYPE} *)({})",
        addr_expr(addr.base, addr.index, addr.disp)
    )
}

fn vec_low64_load_cstmt(cx: &mut Cx<'_>, dest: u8, addr: &MemRef) -> CStmt {
    let var: String = vec_var(dest);
    let zero: CStmt = assign_cstmt(cx, &var, &format!("(__typeof__({var})){{0}}"));
    let write: CStmt = assign_cstmt(cx, &vec_low64_lvalue(dest), &vec_low64_mem(addr));
    CStmt::Block(vec![zero, write])
}

fn vec_low64_store_cstmt(cx: &mut Cx<'_>, src: u8, addr: &MemRef) -> CStmt {
    assign_cstmt(cx, &vec_low64_mem(addr), &vec_low64_lvalue(src))
}

fn whole_reg_literal(arr: VecArrangement, first: &str) -> String {
    let mut items: Vec<String> = Vec::with_capacity(usize::from(arr.lanes));
    items.push(first.to_owned());
    for _ in 1..arr.lanes {
        items.push("0".to_owned());
    }
    format!("({}){{{}}}", arr.type_name(), items.join(", "))
}

fn reduce_cstmt(
    cx: &mut Cx<'_>,
    reg: u8,
    op: ReduceOp,
    src: VecArrangement,
    dest: VecElem,
) -> CStmt {
    let var: String = vec_var(reg);
    let dest_arr: VecArrangement = VecArrangement::whole_register(dest);
    let lanes: usize = usize::from(src.lanes);
    match op {
        ReduceOp::Add | ReduceOp::Saddl | ReduceOp::Uaddl => {
            let acc_ty: &str = dest.c_unsigned_scalar();
            let terms: Vec<String> = (0..lanes)
                .map(|index: usize| {
                    let lane: String = format!("{var}[{index}]");
                    match op {
                        ReduceOp::Saddl => format!("({acc_ty})({}){lane}", dest.c_scalar()),
                        ReduceOp::Uaddl => {
                            format!("({acc_ty})({}){lane}", src.elem.c_unsigned_scalar())
                        }
                        _ => format!("({acc_ty}){lane}"),
                    }
                })
                .collect();
            let first: String = format!("({})({})", dest.c_scalar(), terms.join(" + "));
            let literal: String = whole_reg_literal(dest_arr, &first);
            let rhs: String = if src == dest_arr {
                literal
            } else {
                format!("({}){literal}", src.type_name())
            };
            assign_cstmt(cx, &var, &rhs)
        }
        ReduceOp::Smax | ReduceOp::Smin | ReduceOp::Umax | ReduceOp::Umin => {
            let Some(mm): Option<MinMax> = op.minmax() else {
                return CStmt::Block(Vec::new());
            };
            let signed: bool = mm.signed;
            let cmp: &str = mm.cmp();
            let lane_ty: &str = minmax_lane_ty(dest, signed);
            let lane = |index: usize| -> String {
                minmax_lane_operand(dest, signed, &format!("{var}[{index}]"))
            };
            let acc: &str = "reduce_acc";
            let mut stmts: Vec<CStmt> = Vec::with_capacity(lanes + 1);
            let init_expr: CExpr = cx.var(&lane(0));
            stmts.push(decl_with_init(cx, lane_ty, acc, init_expr));
            for index in 1..lanes {
                let li: String = lane(index);
                let body: String = minmax_select_expr(cmp, &li, acc);
                stmts.push(assign_cstmt(cx, acc, &body));
            }
            let first: String = format!("({}){acc}", dest.c_scalar());
            let literal: String = whole_reg_literal(dest_arr, &first);
            stmts.push(assign_cstmt(cx, &var, &literal));
            CStmt::Block(stmts)
        }
    }
}

fn minmax_bin_cstmt(
    cx: &mut Cx<'_>,
    dest: u8,
    lhs: &str,
    rhs: &str,
    op: VecBinOp,
    arr: VecArrangement,
) -> CStmt {
    let Some(mm): Option<MinMax> = op.minmax() else {
        return CStmt::Block(Vec::new());
    };
    let signed: bool = mm.signed;
    let cmp: &str = mm.cmp();
    let lanes: usize = usize::from(arr.lanes);
    let dest_scalar: &str = arr.elem.c_scalar();
    let elems: Vec<String> = (0..lanes)
        .map(|index: usize| -> String {
            let a: String = minmax_lane_operand(arr.elem, signed, &format!("{lhs}[{index}]"));
            let b: String = minmax_lane_operand(arr.elem, signed, &format!("{rhs}[{index}]"));
            let sel: String = minmax_select_expr(cmp, &a, &b);
            if signed {
                format!("({sel})")
            } else {
                format!("({dest_scalar})({sel})")
            }
        })
        .collect();
    let literal: String = format!("({}){{{}}}", arr.type_name(), elems.join(", "));
    assign_cstmt(cx, &vec_var(dest), &literal)
}

fn widen_lane_read(src: u8, src_elem: VecElem, signed: bool, index: usize) -> String {
    let src_view: String = VecArrangement::whole_register(src_elem).type_name();
    let lane: String = format!("(({src_view}){})[{index}]", vec_var(src));
    if signed {
        lane
    } else {
        format!("({}){lane}", src_elem.c_unsigned_scalar())
    }
}

fn widen_extend_cstmt(
    cx: &mut Cx<'_>,
    dest: u8,
    src: u8,
    src_elem: VecElem,
    dest_elem: VecElem,
    signed: bool,
    high: bool,
    shift: u8,
) -> CStmt {
    let dest_arr: VecArrangement = VecArrangement::whole_register(dest_elem);
    let lanes: usize = usize::from(dest_arr.lanes);
    let offset: usize = if high { lanes } else { 0 };
    let dest_scalar: &str = dest_elem.c_scalar();
    let terms: Vec<String> = (0..lanes)
        .map(|index: usize| {
            let read: String = widen_lane_read(src, src_elem, signed, offset + index);
            if shift == 0 {
                format!("({dest_scalar}){read}")
            } else {
                format!(
                    "({dest_scalar})(({}){read} << {shift})",
                    dest_elem.c_unsigned_scalar()
                )
            }
        })
        .collect();
    let init: String = format!("({}){{{}}}", dest_arr.type_name(), terms.join(", "));
    assign_cstmt(cx, &vec_var(dest), &init)
}

fn widen_add_cstmt(
    cx: &mut Cx<'_>,
    dest: u8,
    src1: u8,
    src2: u8,
    src_elem: VecElem,
    dest_elem: VecElem,
    signed: bool,
    high: bool,
) -> CStmt {
    let dest_arr: VecArrangement = VecArrangement::whole_register(dest_elem);
    let lanes: usize = usize::from(dest_arr.lanes);
    let offset: usize = if high { lanes } else { 0 };
    let dest_scalar: &str = dest_elem.c_scalar();
    let terms: Vec<String> = (0..lanes)
        .map(|index: usize| {
            let a: String = widen_lane_read(src1, src_elem, signed, offset + index);
            let b: String = widen_lane_read(src2, src_elem, signed, offset + index);
            format!("({dest_scalar}){a} + ({dest_scalar}){b}")
        })
        .collect();
    let init: String = format!("({}){{{}}}", dest_arr.type_name(), terms.join(", "));
    assign_cstmt(cx, &vec_var(dest), &init)
}

fn extract_to_gpr_cstmt(cx: &mut Cx<'_>, dest: RegRef, src: u8, elem: VecElem) -> CStmt {
    let view: VecArrangement = VecArrangement::whole_register(elem);
    let bits: String = format!(
        "({})(({}){})[0]",
        elem.c_unsigned_scalar(),
        view.type_name(),
        vec_var(src)
    );
    let var: &'static str = reg_var(dest.reg);
    let rhs: String = reg_write_rhs(var, dest.width, &bits);
    assign_cstmt(cx, var, &rhs)
}

fn lane_insert_cstmt(
    cx: &mut Cx<'_>,
    dest: u8,
    lane: u8,
    src: RegRef,
    arr: VecArrangement,
) -> CStmt {
    let var: String = vec_var(dest);
    let inserted: String = format!("({}){}", arr.elem.c_scalar(), reg_var(src.reg));
    let lanes: Vec<String> = (0..arr.lanes)
        .map(|index: u8| -> String {
            if index == lane {
                inserted.clone()
            } else {
                format!("{var}[{index}]")
            }
        })
        .collect();
    let init: String = format!("({}){{{}}}", arr.type_name(), lanes.join(", "));
    assign_cstmt(cx, &var, &init)
}

fn vec_stmt_cstmt(cx: &mut Cx<'_>, vec: &VecStmt) -> CStmt {
    match vec {
        VecStmt::Load { dest, arr, addr } => {
            if arr.is_some_and(|a: VecArrangement| a.total_bits() == 64) {
                return vec_low64_load_cstmt(cx, *dest, addr);
            }
            let arrangement: VecArrangement = vec_resolved_arr(*arr);
            let rhs: String = vec_deref_expr(arrangement, addr);
            assign_cstmt(cx, &vec_var(*dest), &rhs)
        }
        VecStmt::Store { src, arr, addr } => {
            if arr.is_some_and(|a: VecArrangement| a.total_bits() == 64) {
                return vec_low64_store_cstmt(cx, *src, addr);
            }
            let arrangement: VecArrangement = vec_resolved_arr(*arr);
            let target: String = vec_deref_expr(arrangement, addr);
            assign_cstmt(cx, &target, &vec_var(*src))
        }
        VecStmt::Bin {
            dest,
            lhs,
            rhs,
            op,
            arr,
        } => {
            let l: String = vec_var(*lhs);
            let r: String = vec_var(*rhs);
            let body: String = match op {
                VecBinOp::Add => format!("{l} + {r}"),
                VecBinOp::Sub => format!("{l} - {r}"),
                VecBinOp::Mul => format!("{l} * {r}"),
                VecBinOp::Div => format!("{l} / {r}"),
                VecBinOp::And => format!("{l} & {r}"),
                VecBinOp::Or => format!("{l} | {r}"),
                VecBinOp::Xor => format!("{l} ^ {r}"),
                VecBinOp::AndNot => format!("{l} & ~{r}"),
                VecBinOp::Smax | VecBinOp::Smin | VecBinOp::Umax | VecBinOp::Umin => {
                    return minmax_bin_cstmt(cx, *dest, &l, &r, *op, *arr);
                }
            };
            assign_cstmt(cx, &vec_var(*dest), &body)
        }
        VecStmt::Compare { dest, lhs, rhs, .. } => {
            let body: String = rhs.as_ref().map_or_else(
                || format!("{} == 0", vec_var(*lhs)),
                |rhs: &u8| format!("{} == {}", vec_var(*lhs), vec_var(*rhs)),
            );
            assign_cstmt(cx, &vec_var(*dest), &body)
        }
        VecStmt::Dup { dest, src, arr } => {
            let scalar: String = format!("({}){}", arr.elem.c_scalar(), reg_var(src.reg));
            let lanes: Vec<String> = std::iter::repeat_n(scalar, usize::from(arr.lanes)).collect();
            let init: String = format!("({}){{{}}}", arr.type_name(), lanes.join(", "));
            assign_cstmt(cx, &vec_var(*dest), &init)
        }
        VecStmt::LaneInsert {
            dest,
            lane,
            src,
            arr,
        } => lane_insert_cstmt(cx, *dest, *lane, *src, *arr),
        VecStmt::MoveImm { dest, imm, arr } => {
            let scalar: String = format!("({}){imm}", arr.elem.c_scalar());
            let lanes: Vec<String> = std::iter::repeat_n(scalar, usize::from(arr.lanes)).collect();
            let init: String = format!("({}){{{}}}", arr.type_name(), lanes.join(", "));
            assign_cstmt(cx, &vec_var(*dest), &init)
        }
        VecStmt::Reduce { reg, op, src, dest } => reduce_cstmt(cx, *reg, *op, *src, *dest),
        VecStmt::ExtractToGpr { dest, src, elem } => extract_to_gpr_cstmt(cx, *dest, *src, *elem),
        VecStmt::WidenExtend {
            dest,
            src,
            src_elem,
            dest_elem,
            signed,
            high,
            shift,
        } => widen_extend_cstmt(
            cx, *dest, *src, *src_elem, *dest_elem, *signed, *high, *shift,
        ),
        VecStmt::WidenAdd {
            dest,
            src1,
            src2,
            src_elem,
            dest_elem,
            signed,
            high,
        } => widen_add_cstmt(
            cx, *dest, *src1, *src2, *src_elem, *dest_elem, *signed, *high,
        ),
    }
}

fn wide_mul_cstmt(cx: &mut Cx<'_>, src: RegRef) -> CStmt {
    let rax: &'static str = reg_var(Reg::Rax);
    let rdx: &'static str = reg_var(Reg::Rdx);
    let factor: &'static str = reg_var(src.reg);
    let rax_ident: CExpr = cx.var(rax);
    let lhs128: CExpr = c_cast(cx, "unsigned __int128", rax_ident);
    let factor_ident: CExpr = cx.var(factor);
    let rhs128: CExpr = c_cast(cx, "unsigned __int128", factor_ident);
    let product: CExpr = c_bin(BinaryOp::Mul, lhs128, rhs128);
    let decl: CStmt = decl_with_init(cx, "unsigned __int128", "wide_prod", product);
    let wide_prod: CExpr = cx.var("wide_prod");
    let rax_rhs: CExpr = c_cast(cx, "uint64_t", wide_prod);
    let assign_rax: CStmt = assign_expr_cstmt(cx, rax, rax_rhs);
    let wide_prod_shr: CExpr = cx.var("wide_prod");
    let shr: CExpr = c_bin(BinaryOp::Shr, wide_prod_shr, CExpr::int(64));
    let rdx_rhs: CExpr = c_cast(cx, "uint64_t", shr);
    let assign_rdx: CStmt = assign_expr_cstmt(cx, rdx, rdx_rhs);
    CStmt::Block(vec![decl, assign_rax, assign_rdx])
}

fn divide_cstmt(cx: &mut Cx<'_>, divisor: RegRef, signed: bool) -> CStmt {
    let rax: &'static str = reg_var(Reg::Rax);
    let rdx: &'static str = reg_var(Reg::Rdx);
    let bits: u32 = divisor.width.bits();
    let divisor_var: &'static str = reg_var(divisor.reg);
    let result_ty: String = if signed {
        format!("int{bits}_t")
    } else {
        format!("uint{bits}_t")
    };
    let rax_ident: CExpr = cx.var(rax);
    let dividend: CExpr = c_cast(cx, &result_ty, rax_ident);
    let decl_lhs: CStmt = decl_with_init(cx, &result_ty, "div_lhs", dividend);
    let divisor_ident: CExpr = cx.var(divisor_var);
    let divisor_expr: CExpr = c_cast(cx, &result_ty, divisor_ident);
    let decl_rhs: CStmt = decl_with_init(cx, &result_ty, "div_rhs", divisor_expr);
    let uwidth_ty: String = format!("uint{bits}_t");
    let div_lhs_a: CExpr = cx.var("div_lhs");
    let div_rhs_a: CExpr = cx.var("div_rhs");
    let quotient: CExpr = c_bin(BinaryOp::Div, div_lhs_a, div_rhs_a);
    let quotient_narrow: CExpr = c_cast(cx, &uwidth_ty, quotient);
    let quotient_wide: CExpr = c_cast(cx, "uint64_t", quotient_narrow);
    let assign_rax: CStmt = assign_expr_cstmt(cx, rax, quotient_wide);
    let div_lhs_b: CExpr = cx.var("div_lhs");
    let div_rhs_b: CExpr = cx.var("div_rhs");
    let remainder: CExpr = c_bin(BinaryOp::Rem, div_lhs_b, div_rhs_b);
    let remainder_narrow: CExpr = c_cast(cx, &uwidth_ty, remainder);
    let remainder_wide: CExpr = c_cast(cx, "uint64_t", remainder_narrow);
    let assign_rdx: CStmt = assign_expr_cstmt(cx, rdx, remainder_wide);
    CStmt::Block(vec![decl_lhs, decl_rhs, assign_rax, assign_rdx])
}

fn block_move_cstmt(cx: &mut Cx<'_>, elem: Width) -> CStmt {
    let dest: &'static str = reg_var(Reg::Rdi);
    let src: &'static str = reg_var(Reg::Rsi);
    let count: &'static str = reg_var(Reg::Rcx);
    let width: u32 = elem.bits() / 8;
    let count_ident: CExpr = cx.var(count);
    let width_lit: CExpr = CExpr::Int {
        value: u64::from(width),
        radix: Radix::Dec,
        suffix: IntSuffix {
            unsigned: true,
            long: LongSuffix::LongLong,
        },
    };
    let move_n_init: CExpr = c_bin(BinaryOp::Mul, count_ident, width_lit);
    let decl_move_n: CStmt = decl_with_init(cx, "uint64_t", "move_n", move_n_init);
    let dest_ptr: CExpr = cx.var(dest);
    let dest_uptr: CExpr = c_cast(cx, "uintptr_t", dest_ptr);
    let dest_void: CExpr = c_ptr_cast(cx, "void", dest_uptr);
    let src_ptr: CExpr = cx.var(src);
    let src_uptr: CExpr = c_cast(cx, "uintptr_t", src_ptr);
    let src_void: CExpr = c_ptr_cast(cx, "const void", src_uptr);
    let move_n_size_ident: CExpr = cx.var("move_n");
    let move_n_size: CExpr = c_cast(cx, "size_t", move_n_size_ident);
    let memcpy_call: CExpr = cx.call("memcpy", vec![dest_void, src_void, move_n_size]);
    let memcpy_stmt: CStmt = CStmt::Expr(memcpy_call);
    let dest_move: CExpr = cx.var(dest);
    let move_n_a: CExpr = cx.var("move_n");
    let dest_add: CExpr = c_bin(BinaryOp::Add, dest_move, move_n_a);
    let assign_dest: CStmt = assign_expr_cstmt(cx, dest, dest_add);
    let src_move: CExpr = cx.var(src);
    let move_n_b: CExpr = cx.var("move_n");
    let src_add: CExpr = c_bin(BinaryOp::Add, src_move, move_n_b);
    let assign_src: CStmt = assign_expr_cstmt(cx, src, src_add);
    let assign_count: CStmt = assign_expr_cstmt(cx, count, CExpr::int(0));
    CStmt::Block(vec![
        decl_move_n,
        memcpy_stmt,
        assign_dest,
        assign_src,
        assign_count,
    ])
}

fn block_fill_cstmt(cx: &mut Cx<'_>, elem: Width) -> CStmt {
    let dest: &'static str = reg_var(Reg::Rdi);
    let value: &'static str = reg_var(Reg::Rax);
    let count: &'static str = reg_var(Reg::Rcx);
    let width: u32 = elem.bits() / 8;
    let fill_stmt: CStmt = match elem {
        Width::W8 => {
            let dest_ptr: CExpr = cx.var(dest);
            let dest_uptr: CExpr = c_cast(cx, "uintptr_t", dest_ptr);
            let dest_void: CExpr = c_ptr_cast(cx, "void", dest_uptr);
            let value_ident: CExpr = cx.var(value);
            let byte_mask: CExpr = c_hex_mask(0xff);
            let masked: CExpr = c_bin(BinaryOp::BitAnd, value_ident, byte_mask);
            let masked_int: CExpr = c_cast(cx, "int", masked);
            let count_ident: CExpr = cx.var(count);
            let count_size: CExpr = c_cast(cx, "size_t", count_ident);
            let memset_call: CExpr = cx.call("memset", vec![dest_void, masked_int, count_size]);
            CStmt::Expr(memset_call)
        }
        other => {
            let ty: &str = match other {
                Width::W8 => "uint8_t",
                Width::W16 => "uint16_t",
                Width::W32 => "uint32_t",
                Width::W64 => "uint64_t",
            };
            let mask: u128 = (1u128 << other.bits()) - 1;
            let decl_fill_i: CStmt = decl_with_init(cx, "uint64_t", "fill_i", CExpr::int(0));
            let fill_i_cond: CExpr = cx.var("fill_i");
            let count_ident: CExpr = cx.var(count);
            let cond: CExpr = c_bin(BinaryOp::Lt, fill_i_cond, count_ident);
            let fill_i_step: CExpr = cx.var("fill_i");
            let step: CExpr = CExpr::Postfix {
                op: PostfixOp::PostInc,
                operand: Box::new(fill_i_step),
            };
            let dest_ptr: CExpr = cx.var(dest);
            let dest_uptr: CExpr = c_cast(cx, "uintptr_t", dest_ptr);
            let dest_typed: CExpr = c_ptr_cast(cx, ty, dest_uptr);
            let fill_i_index: CExpr = cx.var("fill_i");
            let indexed: CExpr = CExpr::Index {
                base: Box::new(dest_typed),
                index: Box::new(fill_i_index),
            };
            let value_ident: CExpr = cx.var(value);
            let mask_lit: CExpr = c_hex_mask(mask);
            let masked: CExpr = c_bin(BinaryOp::BitAnd, value_ident, mask_lit);
            let masked_typed: CExpr = c_cast(cx, ty, masked);
            let assign_index: CExpr = CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(indexed),
                rhs: Box::new(masked_typed),
            };
            let body: CStmt = CStmt::Block(vec![CStmt::Expr(assign_index)]);
            CStmt::For {
                init: Some(Box::new(decl_fill_i)),
                cond: Some(cond),
                step: Some(step),
                body: Box::new(body),
            }
        }
    };
    let dest_a: CExpr = cx.var(dest);
    let count_a: CExpr = cx.var(count);
    let width_lit: CExpr = CExpr::Int {
        value: u64::from(width),
        radix: Radix::Dec,
        suffix: IntSuffix {
            unsigned: true,
            long: LongSuffix::LongLong,
        },
    };
    let count_width: CExpr = c_bin(BinaryOp::Mul, count_a, width_lit);
    let dest_add: CExpr = c_bin(BinaryOp::Add, dest_a, count_width);
    let assign_dest: CStmt = assign_expr_cstmt(cx, dest, dest_add);
    let assign_count: CStmt = assign_expr_cstmt(cx, count, CExpr::int(0));
    CStmt::Block(vec![fill_stmt, assign_dest, assign_count])
}

fn call_cstmt(cx: &mut Cx<'_>, target: u64, args: &[Reg], name: Option<&str>) -> CStmt {
    let display: String = call_display_name(target, name);
    let mut arg_exprs: Vec<CExpr> = Vec::with_capacity(args.len());
    for r in args {
        let arg: CExpr = cx.var(reg_var(*r));
        arg_exprs.push(arg);
    }
    let call_expr: CExpr = cx.call(&display, arg_exprs);
    assign_expr_cstmt(cx, reg_var(Reg::Rax), call_expr)
}

const fn xmm_var(xmm: Xmm) -> &'static str {
    match xmm {
        Xmm::Xmm0 => "x_xmm0",
        Xmm::Xmm1 => "x_xmm1",
        Xmm::Xmm2 => "x_xmm2",
        Xmm::Xmm3 => "x_xmm3",
        Xmm::Xmm4 => "x_xmm4",
        Xmm::Xmm5 => "x_xmm5",
        Xmm::Xmm6 => "x_xmm6",
        Xmm::Xmm7 => "x_xmm7",
        Xmm::Xmm8 => "x_xmm8",
        Xmm::Xmm9 => "x_xmm9",
        Xmm::Xmm10 => "x_xmm10",
        Xmm::Xmm11 => "x_xmm11",
        Xmm::Xmm12 => "x_xmm12",
        Xmm::Xmm13 => "x_xmm13",
        Xmm::Xmm14 => "x_xmm14",
        Xmm::Xmm15 => "x_xmm15",
        Xmm::Xmm16 => "x_xmm16",
        Xmm::Xmm17 => "x_xmm17",
        Xmm::Xmm18 => "x_xmm18",
        Xmm::Xmm19 => "x_xmm19",
        Xmm::Xmm20 => "x_xmm20",
        Xmm::Xmm21 => "x_xmm21",
        Xmm::Xmm22 => "x_xmm22",
        Xmm::Xmm23 => "x_xmm23",
        Xmm::Xmm24 => "x_xmm24",
        Xmm::Xmm25 => "x_xmm25",
        Xmm::Xmm26 => "x_xmm26",
        Xmm::Xmm27 => "x_xmm27",
        Xmm::Xmm28 => "x_xmm28",
        Xmm::Xmm29 => "x_xmm29",
        Xmm::Xmm30 => "x_xmm30",
        Xmm::Xmm31 => "x_xmm31",
    }
}

fn fp_binary_op(op: FpOp) -> BinaryOp {
    match op {
        FpOp::Add => BinaryOp::Add,
        FpOp::Sub => BinaryOp::Sub,
        FpOp::Mul => BinaryOp::Mul,
        FpOp::Div => BinaryOp::Div,
    }
}

fn fp_load(operand: &FpOperand, width: FpWidth, aggregates: &AggregatePlan) -> String {
    match operand {
        FpOperand::Xmm(x) => {
            let xv: &'static str = xmm_var(*x);
            match width {
                FpWidth::F64 => c_render(|cx| {
                    let arg: CExpr = cx.var(xv);
                    cx.call("fp_d_from_bits", vec![arg])
                }),
                FpWidth::F32 => c_render(|cx| {
                    let inner: CExpr = cx.var(xv);
                    let arg: CExpr = c_cast(cx, "uint32_t", inner);
                    cx.call("fp_f_from_bits", vec![arg])
                }),
            }
        }
        FpOperand::Mem(mem) => {
            if let Some((expr, _)) =
                aggregate_c_mem_expr(mem, aggregates, AggregateScalar::Float(width))
            {
                return expr;
            }
            let addr: String = addr_expr(mem.base, mem.index, mem.disp);
            let ty: &str = match width {
                FpWidth::F64 => "double",
                FpWidth::F32 => "float",
            };
            let rendered: String = c_render(|cx| c_deref(cx, ty, &addr));
            format!("({rendered})")
        }
        FpOperand::Const { bits, .. } => fp_const_literal(*bits, width),
    }
}

fn fp_const_literal(bits: u64, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => c_render(|cx| {
            let arg: CExpr = c_hex_mask(u128::from(bits));
            cx.call("fp_d_from_bits", vec![arg])
        }),
        FpWidth::F32 => c_render(|cx| {
            let arg: CExpr = CExpr::Int {
                value: u64::from(bits as u32),
                radix: Radix::Hex,
                suffix: IntSuffix {
                    unsigned: true,
                    long: LongSuffix::None,
                },
            };
            cx.call("fp_f_from_bits", vec![arg])
        }),
    }
}

fn fp_store_expr(value: &str, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => c_render(|cx| {
            let opaque: CExpr = c_opaque(cx, value);
            let arg: CExpr = c_cast(cx, "double", opaque);
            cx.call("fp_d_to_bits", vec![arg])
        }),
        FpWidth::F32 => c_render(|cx| {
            let opaque: CExpr = c_opaque(cx, value);
            let cast: CExpr = c_cast(cx, "float", opaque);
            let call: CExpr = cx.call("fp_f_to_bits", vec![cast]);
            c_cast(cx, "uint64_t", call)
        }),
    }
}

fn xmm_bits(xmm: Xmm, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => xmm_var(xmm).to_string(),
        FpWidth::F32 => {
            let xv: &'static str = xmm_var(xmm);
            c_render(|cx| {
                let inner: CExpr = cx.var(xv);
                c_cast(cx, "uint32_t", inner)
            })
        }
    }
}

fn extend_expr(raw: &str, src_width: Width, dest_width: Width, signed: bool) -> String {
    let src_mask: u128 = (1u128 << src_width.bits()) - 1;
    let dst_bits: u32 = dest_width.bits();
    let src_bits: u32 = src_width.bits();
    c_render(|cx| {
        let narrowed: CExpr = c_bin(BinaryOp::BitAnd, c_opaque(cx, raw), c_hex_mask(src_mask));
        if signed {
            let src_cast: CExpr = c_cast(cx, &format!("int{src_bits}_t"), narrowed);
            let mid_cast: CExpr = c_cast(cx, &format!("int{dst_bits}_t"), src_cast);
            c_cast(cx, &format!("uint{dst_bits}_t"), mid_cast)
        } else {
            let src_cast: CExpr = c_cast(cx, &format!("uint{src_bits}_t"), narrowed);
            c_cast(cx, &format!("uint{dst_bits}_t"), src_cast)
        }
    })
}

fn bin_expr(op: BinOp, lhs: &str, rhs: &str, width: Width) -> String {
    match op {
        BinOp::Add => c_render(|cx| c_bin(BinaryOp::Add, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::Sub => c_render(|cx| c_bin(BinaryOp::Sub, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::Imul => c_render(|cx| c_bin(BinaryOp::Mul, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::And => c_render(|cx| c_bin(BinaryOp::BitAnd, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::Or => c_render(|cx| c_bin(BinaryOp::BitOr, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::Xor => c_render(|cx| c_bin(BinaryOp::BitXor, cx.var(lhs), c_opaque(cx, rhs))),
        BinOp::Shl => {
            let shift_mask: u64 = u64::from(width.shift_count_mask());
            c_render(|cx| {
                let masked_rhs: CExpr =
                    c_bin(BinaryOp::BitAnd, c_opaque(cx, rhs), CExpr::int(shift_mask));
                c_bin(BinaryOp::Shl, cx.var(lhs), masked_rhs)
            })
        }
        BinOp::Shr => {
            let mask: u128 = (1u128 << width.bits()) - 1;
            let shift_mask: u64 = u64::from(width.shift_count_mask());
            c_render(|cx| {
                let masked_lhs: CExpr = c_bin(BinaryOp::BitAnd, cx.var(lhs), c_hex_mask(mask));
                let masked_rhs: CExpr =
                    c_bin(BinaryOp::BitAnd, c_opaque(cx, rhs), CExpr::int(shift_mask));
                c_bin(BinaryOp::Shr, masked_lhs, masked_rhs)
            })
        }
        BinOp::Sar => {
            let bits: u32 = width.bits();
            let shift_mask: u64 = u64::from(width.shift_count_mask());
            c_render(|cx| {
                let inner: CExpr = cx.var(lhs);
                let narrowed: CExpr = c_cast(cx, &format!("int{bits}_t"), inner);
                let signed_lhs: CExpr = c_cast(cx, "int64_t", narrowed);
                let masked_rhs: CExpr =
                    c_bin(BinaryOp::BitAnd, c_opaque(cx, rhs), CExpr::int(shift_mask));
                let shifted: CExpr = c_bin(BinaryOp::Shr, signed_lhs, masked_rhs);
                c_cast(cx, "uint64_t", shifted)
            })
        }
        BinOp::Sdiv => {
            let bits: u32 = width.bits();
            c_render(|cx| {
                let lv: CExpr = cx.var(lhs);
                let l: CExpr = c_cast(cx, &format!("int{bits}_t"), lv);
                let rv: CExpr = c_opaque(cx, rhs);
                let r: CExpr = c_cast(cx, &format!("int{bits}_t"), rv);
                c_cast(cx, "uint64_t", c_bin(BinaryOp::Div, l, r))
            })
        }
        BinOp::Udiv => {
            let bits: u32 = width.bits();
            c_render(|cx| {
                let lv: CExpr = cx.var(lhs);
                let l: CExpr = c_cast(cx, &format!("uint{bits}_t"), lv);
                let rv: CExpr = c_opaque(cx, rhs);
                let r: CExpr = c_cast(cx, &format!("uint{bits}_t"), rv);
                c_cast(cx, "uint64_t", c_bin(BinaryOp::Div, l, r))
            })
        }
        BinOp::Umull => c_render(|cx| {
            let lv: CExpr = cx.var(lhs);
            let l32: CExpr = c_cast(cx, "uint32_t", lv);
            let l: CExpr = c_cast(cx, "uint64_t", l32);
            let rv: CExpr = c_opaque(cx, rhs);
            let r32: CExpr = c_cast(cx, "uint32_t", rv);
            let r: CExpr = c_cast(cx, "uint64_t", r32);
            c_bin(BinaryOp::Mul, l, r)
        }),
        BinOp::Smull => c_render(|cx| {
            let lv: CExpr = cx.var(lhs);
            let l32: CExpr = c_cast(cx, "int32_t", lv);
            let l: CExpr = c_cast(cx, "int64_t", l32);
            let rv: CExpr = c_opaque(cx, rhs);
            let r32: CExpr = c_cast(cx, "int32_t", rv);
            let r: CExpr = c_cast(cx, "int64_t", r32);
            c_cast(cx, "uint64_t", c_bin(BinaryOp::Mul, l, r))
        }),
        BinOp::Umulh => {
            format!(
                "(uint64_t)(((unsigned __int128)(uint64_t)({lhs}) * (unsigned __int128)(uint64_t)({rhs})) >> 64)"
            )
        }
        BinOp::Smulh => {
            format!(
                "(uint64_t)(int64_t)(((__int128)(int64_t)({lhs}) * (__int128)(int64_t)({rhs})) >> 64)"
            )
        }
    }
}

fn signed_operand(expr: &str, width: Width) -> String {
    let bits: u32 = width.bits();
    c_render(|cx| {
        let opaque: CExpr = c_opaque(cx, expr);
        let narrowed: CExpr = c_cast(cx, &format!("int{bits}_t"), opaque);
        c_cast(cx, "int64_t", narrowed)
    })
}

fn unsigned_operand(expr: &str, width: Width) -> String {
    match width {
        Width::W64 => c_render(|cx| {
            let opaque: CExpr = c_opaque(cx, expr);
            c_cast(cx, "uint64_t", opaque)
        }),
        other => {
            let mask: u128 = (1u128 << other.bits()) - 1;
            c_render(|cx| {
                let masked: CExpr = c_bin(BinaryOp::BitAnd, c_opaque(cx, expr), c_hex_mask(mask));
                c_cast(cx, "uint64_t", masked)
            })
        }
    }
}

fn compare_expr(kind: CondKind, lhs_expr: &str, rhs_expr: &str, width: Width) -> String {
    if kind.is_unsigned_order() {
        let a: String = unsigned_operand(lhs_expr, width);
        let b: String = unsigned_operand(rhs_expr, width);
        let op: BinaryOp = match kind {
            CondKind::A => BinaryOp::Gt,
            CondKind::Ae => BinaryOp::Ge,
            CondKind::B => BinaryOp::Lt,
            CondKind::Be => BinaryOp::Le,
            _ => unreachable!(),
        };
        c_render(|cx| c_bin(op, cx.var(&a), cx.var(&b)))
    } else if kind.is_signed_order() {
        let a: String = signed_operand(lhs_expr, width);
        let b: String = signed_operand(rhs_expr, width);
        let op: BinaryOp = match kind {
            CondKind::G => BinaryOp::Gt,
            CondKind::Ge => BinaryOp::Ge,
            CondKind::L => BinaryOp::Lt,
            CondKind::Le => BinaryOp::Le,
            _ => unreachable!(),
        };
        c_render(|cx| c_bin(op, cx.var(&a), cx.var(&b)))
    } else if kind.is_overflow() {
        overflow_expr_c(
            lhs_expr,
            rhs_expr,
            width,
            false,
            matches!(kind, CondKind::Vs),
        )
    } else {
        let a: String = signed_operand(lhs_expr, width);
        let b: String = signed_operand(rhs_expr, width);
        match kind {
            CondKind::E => c_render(|cx| c_bin(BinaryOp::Eq, cx.var(&a), cx.var(&b))),
            CondKind::Ne => c_render(|cx| c_bin(BinaryOp::Ne, cx.var(&a), cx.var(&b))),
            CondKind::S => {
                let diff: String = sign_truncated_diff(lhs_expr, rhs_expr, width);
                c_render(|cx| c_bin(BinaryOp::Lt, cx.var(&diff), CExpr::int(0)))
            }
            CondKind::Ns => {
                let diff: String = sign_truncated_diff(lhs_expr, rhs_expr, width);
                c_render(|cx| c_bin(BinaryOp::Ge, cx.var(&diff), CExpr::int(0)))
            }
            _ => unreachable!(),
        }
    }
}

fn if_cond_expr(cond: &Cond, aggregates: &AggregatePlan) -> String {
    match cond {
        Cond::Leaf { kind, flags } => cond_expr(*kind, flags, aggregates),
        Cond::And(lhs, rhs) => {
            let l: String = if_cond_expr(lhs, aggregates);
            let r: String = if_cond_expr(rhs, aggregates);
            c_render(|cx| c_bin(BinaryOp::LogAnd, c_opaque(cx, &l), c_opaque(cx, &r)))
        }
        Cond::Or(lhs, rhs) => {
            let l: String = if_cond_expr(lhs, aggregates);
            let r: String = if_cond_expr(rhs, aggregates);
            c_render(|cx| c_bin(BinaryOp::LogOr, c_opaque(cx, &l), c_opaque(cx, &r)))
        }
    }
}

fn cond_expr(kind: CondKind, flags: &Flags, aggregates: &AggregatePlan) -> String {
    match flags {
        Flags::Cmp { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: &'static str = reg_var(lhs.reg);
            let rhs_expr: String = source_expr(rhs, width, aggregates);
            compare_expr(kind, lhs_expr, &rhs_expr, width)
        }
        Flags::Add { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: &'static str = reg_var(lhs.reg);
            let rhs_expr: String = source_expr(rhs, width, aggregates);
            add_cond_expr(kind, lhs_expr, &rhs_expr, width)
        }
        Flags::CmpMem { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: String = deref_expr(lhs, aggregates);
            let rhs_expr: String = source_expr(rhs, width, aggregates);
            compare_expr(kind, &lhs_expr, &rhs_expr, width)
        }
        Flags::TestImm { operand, mask } => {
            let width: Width = operand.width;
            let uop: String = unsigned_operand(reg_var(operand.reg), width);
            let mask_val: u128 = u128::from((*mask as u64) & ((1u128 << width.bits()) - 1) as u64);
            let cmp: BinaryOp = match kind {
                CondKind::E => BinaryOp::Eq,
                CondKind::Ne => BinaryOp::Ne,
                _ => unreachable!(),
            };
            c_render(|cx| {
                let masked: CExpr = c_bin(BinaryOp::BitAnd, cx.var(&uop), c_hex_mask(mask_val));
                c_bin(cmp, masked, CExpr::int(0))
            })
        }
        Flags::Test { operand } => {
            let width: Width = operand.width;
            let var: &'static str = reg_var(operand.reg);
            let sop: String = signed_operand(var, width);
            match kind {
                CondKind::E | CondKind::Be => {
                    c_render(|cx| c_bin(BinaryOp::Eq, cx.var(&sop), CExpr::int(0)))
                }
                CondKind::Ne | CondKind::A => {
                    c_render(|cx| c_bin(BinaryOp::Ne, cx.var(&sop), CExpr::int(0)))
                }
                CondKind::G => c_render(|cx| c_bin(BinaryOp::Gt, cx.var(&sop), CExpr::int(0))),
                CondKind::Ge | CondKind::Ns => {
                    c_render(|cx| c_bin(BinaryOp::Ge, cx.var(&sop), CExpr::int(0)))
                }
                CondKind::L | CondKind::S => {
                    c_render(|cx| c_bin(BinaryOp::Lt, cx.var(&sop), CExpr::int(0)))
                }
                CondKind::Le => c_render(|cx| c_bin(BinaryOp::Le, cx.var(&sop), CExpr::int(0))),
                CondKind::Ae | CondKind::Vc => "1".to_owned(),
                CondKind::B | CondKind::Vs => "0".to_owned(),
                CondKind::P | CondKind::Np => {
                    unreachable!("parity has no sound rendering over an integer test")
                }
            }
        }
        Flags::Sign { result } => {
            let width: Width = result.width;
            let var: String = signed_operand(reg_var(result.reg), width);
            match kind {
                CondKind::S => c_render(|cx| c_bin(BinaryOp::Lt, cx.var(&var), CExpr::int(0))),
                CondKind::Ns => c_render(|cx| c_bin(BinaryOp::Ge, cx.var(&var), CExpr::int(0))),
                CondKind::E => c_render(|cx| c_bin(BinaryOp::Eq, cx.var(&var), CExpr::int(0))),
                CondKind::Ne => c_render(|cx| c_bin(BinaryOp::Ne, cx.var(&var), CExpr::int(0))),
                _ => unreachable!(),
            }
        }
        Flags::FpCmp {
            lhs,
            rhs,
            width,
            model,
        } => {
            let a: String = fp_load(&FpOperand::Xmm(*lhs), *width, aggregates);
            let b: String = fp_load(rhs, *width, aggregates);
            let same: bool = matches!(rhs, FpOperand::Xmm(operand) if operand == lhs);
            fp_compare_c(kind, &a, &b, same, *model)
        }
        Flags::Snapshot { var } => {
            let cmp: BinaryOp = if matches!(kind, CondKind::E) {
                BinaryOp::Eq
            } else {
                BinaryOp::Ne
            };
            let sv: String = sel_var(*var);
            c_render(|cx| c_bin(cmp, cx.var(&sv), CExpr::int(0)))
        }
        Flags::CondCmp {
            prior,
            precond,
            taken,
            nzcv,
        } => {
            let precond_expr: String = cond_expr(*precond, prior, aggregates);
            let taken_expr: String = cond_expr(kind, taken, aggregates);
            let else_holds: bool = nzcv_condition_holds(kind, *nzcv);
            let ternary: String = c_render(|cx| CExpr::Ternary {
                cond: Box::new(c_opaque(cx, &precond_expr)),
                then: Box::new(c_opaque(cx, &taken_expr)),
                els: Box::new(CExpr::int(u64::from(else_holds))),
            });
            format!("({ternary})")
        }
    }
}

fn fp_compare_c(
    kind: CondKind,
    a: &str,
    b: &str,
    same_operand: bool,
    model: FpUnorderedModel,
) -> String {
    let ordered =
        |op: BinaryOp| -> String { c_render(|cx| c_bin(op, c_opaque(cx, a), c_opaque(cx, b))) };
    let unordered_of = |op: BinaryOp| -> String {
        c_render(|cx| CExpr::Unary {
            op: UnaryOp::Not,
            operand: Box::new(c_bin(op, c_opaque(cx, a), c_opaque(cx, b))),
        })
    };
    let equal_or_unordered = || -> String {
        c_render(|cx| {
            let not_lt: CExpr = CExpr::Unary {
                op: UnaryOp::Not,
                operand: Box::new(c_bin(BinaryOp::Lt, c_opaque(cx, a), c_opaque(cx, b))),
            };
            let not_gt: CExpr = CExpr::Unary {
                op: UnaryOp::Not,
                operand: Box::new(c_bin(BinaryOp::Gt, c_opaque(cx, a), c_opaque(cx, b))),
            };
            c_bin(BinaryOp::LogAnd, not_lt, not_gt)
        })
    };
    let ordered_unequal = || -> String {
        c_render(|cx| {
            c_bin(
                BinaryOp::LogOr,
                c_bin(BinaryOp::Lt, c_opaque(cx, a), c_opaque(cx, b)),
                c_bin(BinaryOp::Gt, c_opaque(cx, a), c_opaque(cx, b)),
            )
        })
    };
    match kind {
        CondKind::E => match model {
            FpUnorderedModel::UnorderedIsUnequal => ordered(BinaryOp::Eq),
            FpUnorderedModel::UnorderedIsEqual => equal_or_unordered(),
        },
        CondKind::Ne => match model {
            FpUnorderedModel::UnorderedIsUnequal => ordered(BinaryOp::Ne),
            FpUnorderedModel::UnorderedIsEqual => ordered_unequal(),
        },
        CondKind::S | CondKind::B => ordered(BinaryOp::Lt),
        CondKind::Ns | CondKind::Ae => unordered_of(BinaryOp::Lt),
        CondKind::Be => ordered(BinaryOp::Le),
        CondKind::A => unordered_of(BinaryOp::Le),
        CondKind::Ge => ordered(BinaryOp::Ge),
        CondKind::L => unordered_of(BinaryOp::Ge),
        CondKind::G => ordered(BinaryOp::Gt),
        CondKind::Le => unordered_of(BinaryOp::Gt),
        CondKind::Vs | CondKind::P => fp_nan_test_c(a, b, same_operand, true),
        CondKind::Vc | CondKind::Np => fp_nan_test_c(a, b, same_operand, false),
    }
}

fn fp_nan_test_c(a: &str, b: &str, same_operand: bool, unordered: bool) -> String {
    let self_op: BinaryOp = if unordered {
        BinaryOp::Ne
    } else {
        BinaryOp::Eq
    };
    let combine: BinaryOp = if unordered {
        BinaryOp::LogOr
    } else {
        BinaryOp::LogAnd
    };
    c_render(|cx| {
        let a_nan: CExpr = c_bin(self_op, c_opaque(cx, a), c_opaque(cx, a));
        if same_operand {
            a_nan
        } else {
            let b_nan: CExpr = c_bin(self_op, c_opaque(cx, b), c_opaque(cx, b));
            c_bin(combine, a_nan, b_nan)
        }
    })
}

fn sign_truncated_diff(lhs: &str, rhs: &str, width: Width) -> String {
    let a: String = unsigned_operand(lhs, width);
    let b: String = unsigned_operand(rhs, width);
    let bits: u32 = width.bits();
    c_render(|cx| {
        let diff: CExpr = c_bin(BinaryOp::Sub, cx.var(&a), cx.var(&b));
        c_cast(cx, &format!("int{bits}_t"), diff)
    })
}

fn sign_truncated_sum(lhs: &str, rhs: &str, width: Width) -> String {
    let a: String = unsigned_operand(lhs, width);
    let b: String = unsigned_operand(rhs, width);
    let bits: u32 = width.bits();
    c_render(|cx| {
        let sum: CExpr = c_bin(BinaryOp::Add, cx.var(&a), cx.var(&b));
        c_cast(cx, &format!("int{bits}_t"), sum)
    })
}

fn overflow_expr_c(
    lhs_expr: &str,
    rhs_expr: &str,
    width: Width,
    is_add: bool,
    set: bool,
) -> String {
    let bits: u32 = width.bits();
    let uty: String = format!("uint{bits}_t");
    let ity: String = format!("int{bits}_t");
    let op: BinaryOp = if is_add { BinaryOp::Add } else { BinaryOp::Sub };
    let cmp: BinaryOp = if set { BinaryOp::Lt } else { BinaryOp::Ge };
    c_render(|cx: &mut Cx<'_>| {
        let ua = |cx: &mut Cx<'_>| -> CExpr {
            let opaque: CExpr = c_opaque(cx, lhs_expr);
            c_cast(cx, &uty, opaque)
        };
        let ub = |cx: &mut Cx<'_>| -> CExpr {
            let opaque: CExpr = c_opaque(cx, rhs_expr);
            c_cast(cx, &uty, opaque)
        };
        let result = |cx: &mut Cx<'_>| -> CExpr {
            let a: CExpr = ua(cx);
            let b: CExpr = ub(cx);
            let combined: CExpr = c_bin(op, a, b);
            c_cast(cx, &uty, combined)
        };
        let inner: CExpr = if is_add {
            let left: CExpr = c_bin(BinaryOp::BitXor, ua(cx), result(cx));
            let right: CExpr = c_bin(BinaryOp::BitXor, ub(cx), result(cx));
            c_bin(BinaryOp::BitAnd, left, right)
        } else {
            let left: CExpr = c_bin(BinaryOp::BitXor, ua(cx), ub(cx));
            let right: CExpr = c_bin(BinaryOp::BitXor, ua(cx), result(cx));
            c_bin(BinaryOp::BitAnd, left, right)
        };
        let signed: CExpr = c_cast(cx, &ity, inner);
        c_bin(cmp, signed, CExpr::int(0))
    })
}

fn add_cond_expr(kind: CondKind, lhs_expr: &str, rhs_expr: &str, width: Width) -> String {
    if kind.is_overflow() {
        return overflow_expr_c(
            lhs_expr,
            rhs_expr,
            width,
            true,
            matches!(kind, CondKind::Vs),
        );
    }
    let sum: String = sign_truncated_sum(lhs_expr, rhs_expr, width);
    let op: BinaryOp = match kind {
        CondKind::E => BinaryOp::Eq,
        CondKind::Ne => BinaryOp::Ne,
        CondKind::S => BinaryOp::Lt,
        CondKind::Ns => BinaryOp::Ge,
        _ => unreachable!(),
    };
    c_render(|cx| c_bin(op, cx.var(&sum), CExpr::int(0)))
}

const fn rs_int_ty(width: Width) -> &'static str {
    match width {
        Width::W8 => "i8",
        Width::W16 => "i16",
        Width::W32 => "i32",
        Width::W64 => "i64",
    }
}

const fn rs_uint_ty(width: Width) -> &'static str {
    match width {
        Width::W8 => "u8",
        Width::W16 => "u16",
        Width::W32 => "u32",
        Width::W64 => "u64",
    }
}

fn aggregate_rust_type_name(plan: &AggregatePlan, root: usize) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    let prefix: &str = match root_plan.shape {
        AggregateShape::Struct { .. } => "RecoveredStruct",
        AggregateShape::Array { .. } => "RecoveredArray",
        AggregateShape::Union { .. } => "RecoveredUnion",
    };
    Some(format!("{prefix}{root}"))
}

fn emit_rust_aggregate_types(out: &mut String, plan: &AggregatePlan) {
    for (root_index, root) in plan.roots.iter().enumerate().rev() {
        match &root.shape {
            AggregateShape::Array { width, .. } => {
                let _ = writeln!(
                    out,
                    "    type RecoveredArray{root_index} = {};",
                    rs_uint_ty(*width)
                );
            }
            AggregateShape::Struct { fields } => {
                let _ = writeln!(out, "    #[repr(C, packed)]");
                let _ = writeln!(out, "    struct RecoveredStruct{root_index} {{");
                let mut cursor: i64 = 0;
                for &(disp, width) in fields {
                    if disp > cursor {
                        let gap: i64 = disp - cursor;
                        let _ = writeln!(out, "        padding_{cursor:x}: [u8; {gap}],");
                    }
                    let field: String = aggregate_field_name(disp);
                    let child_type: Option<String> = plan
                        .linked_child(root.reg, disp)
                        .and_then(|child: usize| aggregate_rust_type_name(plan, child));
                    match child_type {
                        Some(child_type) => {
                            let _ = writeln!(out, "        {field}: *mut {child_type},");
                        }
                        None => {
                            let _ = writeln!(out, "        {field}: {},", rs_uint_ty(width));
                        }
                    }
                    let Some(next_cursor): Option<i64> =
                        disp.checked_add(i64::from(width.bits() / 8))
                    else {
                        return;
                    };
                    cursor = next_cursor;
                }
                let _ = writeln!(out, "    }}");
            }
            AggregateShape::Union { members } => {
                let _ = writeln!(out, "    #[repr(C)]");
                let _ = writeln!(out, "    union RecoveredUnion{root_index} {{");
                for &scalar in members {
                    let member: String = aggregate_member_name(scalar);
                    let ty: &str = match scalar {
                        AggregateScalar::Integer(width) => rs_uint_ty(width),
                        AggregateScalar::Float(FpWidth::F32) => "f32",
                        AggregateScalar::Float(FpWidth::F64) => "f64",
                    };
                    let _ = writeln!(out, "        {member}: {ty},");
                }
                let _ = writeln!(out, "    }}");
            }
        }
    }
}

fn aggregate_rust_local_name(plan: &AggregatePlan, root: usize) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    let prefix: &str = match root_plan.shape {
        AggregateShape::Struct { .. } => "recovered_struct",
        AggregateShape::Array { .. } => "recovered_array",
        AggregateShape::Union { .. } => "recovered_union",
    };
    Some(format!("{prefix}_{root}"))
}

fn emit_rust_aggregate_locals(out: &mut String, plan: &AggregatePlan) {
    for (root_index, root) in plan.roots.iter().enumerate() {
        if !root.bind_local {
            continue;
        }
        let Some(ty): Option<String> = aggregate_rust_type_name(plan, root_index) else {
            continue;
        };
        let Some(name): Option<String> = aggregate_rust_local_name(plan, root_index) else {
            continue;
        };
        let _ = writeln!(
            out,
            "    let {name}: *mut {ty} = ({} as usize) as *mut {ty};",
            reg_var(root.reg)
        );
    }
}

fn emit_rust(
    body: &Block,
    signature: &FnSignature,
    frame: Option<&FramePlan>,
    sret: Option<&SretPlan>,
    aggregates: &AggregatePlan,
) -> Option<String> {
    if sret.is_some() {
        return None;
    }
    if block_string_ops_present(body) {
        return None;
    }
    if block_has_vector(body) || !signature.vec.is_empty() {
        return None;
    }

    let mut out: String = String::new();
    let mut call_decls: Vec<CallDecl> = Vec::new();
    collect_call_decls(body, &mut call_decls);
    if !call_decls.is_empty() {
        let _ = writeln!(out, "extern \"C\" {{");
        for decl in &call_decls {
            let params: String = (0..decl.arg_count)
                .map(|i: usize| format!("a{i}: u64"))
                .collect::<Vec<String>>()
                .join(", ");
            let _ = writeln!(out, "    fn {}({params}) -> u64;", decl.display_name);
        }
        let _ = writeln!(out, "}}");
    }

    let mut requested: BTreeSet<&'static str> = BTreeSet::new();
    collect_fp_semantics_helpers(body, &mut requested);
    for source in fp_semantics::rust_resolved_sources(&requested) {
        let _ = writeln!(out, "{source}");
    }

    let param_types: Vec<ScalarType> = signature.ordered_param_types();
    let mut int_param_index: usize = 0;
    let params_sig: String = param_types
        .iter()
        .enumerate()
        .map(|(i, ty): (usize, &ScalarType)| match ty {
            ScalarType::Int => {
                let width: Width = signature.int[int_param_index].1;
                int_param_index += 1;
                let rust_type: &str = if signature.exact_integer_types {
                    rs_uint_ty(width)
                } else {
                    "u64"
                };
                format!("a{i}: {rust_type}")
            }
            ScalarType::Double => format!("a{i}: f64"),
            ScalarType::Float => format!("a{i}: f32"),
        })
        .collect::<Vec<String>>()
        .join(", ");
    let return_type: &str = match signature.ret {
        FnReturn::Int(width) if signature.exact_integer_types => rs_uint_ty(width),
        FnReturn::Int(_) => "u64",
        FnReturn::Fp(FpWidth::F64) => "f64",
        FnReturn::Fp(FpWidth::F32) => "f32",
        FnReturn::Void | FnReturn::Vec(_) => "()",
    };
    let _ = writeln!(
        out,
        "#[allow(unused_mut, unused_variables, unused_assignments, unused_parens, dead_code)]"
    );
    let _ = writeln!(out, "pub fn recovered({params_sig}) -> {return_type} {{");
    emit_rust_aggregate_types(&mut out, aggregates);
    if let Some(plan) = frame {
        let _ = writeln!(
            out,
            "    let mut stack_frame: [u8; {}] = [0u8; {}];",
            plan.size, plan.size
        );
        let _ = writeln!(
            out,
            "    let frame_base: u64 = stack_frame.as_mut_ptr() as usize as u64;"
        );
    }

    let mut touched_gp: Vec<Reg> = Vec::new();
    collect_block_regs(body, &mut touched_gp);
    if matches!(signature.ret, FnReturn::Int(_)) && !touched_gp.contains(&Reg::Rax) {
        touched_gp.push(Reg::Rax);
    }
    let mut touched_xmm: Vec<Xmm> = Vec::new();
    collect_block_xmm(body, &mut touched_xmm);
    if matches!(signature.ret, FnReturn::Fp(_)) && !touched_xmm.contains(&Xmm::Xmm0) {
        touched_xmm.push(Xmm::Xmm0);
    }

    let mut declared_gp: Vec<Reg> = Vec::new();
    let mut declared_xmm: Vec<Xmm> = Vec::new();
    for (i, ty) in param_types.iter().enumerate() {
        match ty {
            ScalarType::Int => {
                let index: usize = declared_gp.len();
                let (reg, width): (Reg, Width) = signature.int[index];
                let init: String = if signature.exact_integer_types && width != Width::W64 {
                    format!("u64::from(a{i})")
                } else {
                    format!("a{i}")
                };
                let _ = writeln!(out, "    let mut {}: u64 = {init};", reg_var(reg));
                declared_gp.push(reg);
            }
            ScalarType::Double | ScalarType::Float => {
                let index: usize = declared_xmm.len();
                let (xmm, width): (Xmm, FpWidth) = signature.fp[index];
                let _ = writeln!(
                    out,
                    "    let mut {}: u64 = {};",
                    xmm_var(xmm),
                    rs_fp_store_expr(&format!("a{i}"), width)
                );
                declared_xmm.push(xmm);
            }
        }
    }
    for reg in &touched_gp {
        if !declared_gp.contains(reg) {
            let init: String = match frame {
                Some(plan) if plan.base == *reg => {
                    format!("frame_base.wrapping_add({}u64)", plan.base_offset)
                }
                _ => "0".to_owned(),
            };
            let _ = writeln!(out, "    let mut {}: u64 = {init};", reg_var(*reg));
            declared_gp.push(*reg);
        }
    }
    emit_rust_aggregate_locals(&mut out, aggregates);
    for xmm in &touched_xmm {
        if !declared_xmm.contains(xmm) {
            let _ = writeln!(out, "    let mut {}: u64 = 0;", xmm_var(*xmm));
            declared_xmm.push(*xmm);
        }
    }
    let mut snapshot_vars: Vec<u32> = Vec::new();
    collect_snapshot_vars(body, &mut snapshot_vars);
    for var in &snapshot_vars {
        let _ = writeln!(out, "    let mut {}: u64 = 0;", loop_cond_var(*var));
    }
    let mut sel_vars: Vec<u32> = Vec::new();
    collect_sel_vars(body, &mut sel_vars);
    for var in &sel_vars {
        let _ = writeln!(out, "    let mut {}: u64 = 0;", sel_var(*var));
    }

    let ret_expr: String = match signature.ret {
        FnReturn::Int(return_width) if signature.exact_integer_types => format!(
            "({}) as {}",
            rs_width_mask(return_width, reg_var(Reg::Rax)),
            rs_uint_ty(return_width)
        ),
        FnReturn::Int(return_width) => rs_width_mask(return_width, reg_var(Reg::Rax)),
        FnReturn::Fp(width) => rs_fp_load_xmm(Xmm::Xmm0, width),
        FnReturn::Void | FnReturn::Vec(_) => String::new(),
    };

    rs_emit_block(&mut out, body, 1, &ret_expr, aggregates)?;

    if !matches!(body.last(), Some(Node::Return)) {
        let _ = writeln!(out, "    {ret_expr}");
    }
    let _ = writeln!(out, "}}");
    Some(out)
}

fn rs_emit_block(
    out: &mut String,
    body: &Block,
    depth: usize,
    ret_expr: &str,
    aggregates: &AggregatePlan,
) -> Option<()> {
    let indent: String = "    ".repeat(depth);
    for node in body {
        match node {
            Node::Stmt(stmt) => rs_emit_stmt(out, stmt, &indent, aggregates)?,
            Node::If {
                cond,
                then_body,
                else_body,
            } => {
                let cond_text: String = rs_if_cond_expr(cond, aggregates)?;
                let _ = writeln!(out, "{indent}if {cond_text} {{");
                rs_emit_block(out, then_body, depth + 1, ret_expr, aggregates)?;
                if let Some(else_b) = else_body {
                    let _ = writeln!(out, "{indent}}} else {{");
                    rs_emit_block(out, else_b, depth + 1, ret_expr, aggregates)?;
                }
                let _ = writeln!(out, "{indent}}}");
            }
            Node::DoWhile { body, cond } => {
                let cond_text: String = match cond {
                    LoopCond::Direct { cond, flags } => rs_cond_expr(*cond, flags, aggregates)?,
                    LoopCond::Snapshot { var } => format!("{} != 0", loop_cond_var(*var)),
                };
                let inner: String = "    ".repeat(depth + 1);
                let _ = writeln!(out, "{indent}loop {{");
                rs_emit_block(out, body, depth + 1, ret_expr, aggregates)?;
                let _ = writeln!(out, "{inner}if !({cond_text}) {{ break; }}");
                let _ = writeln!(out, "{indent}}}");
            }
            Node::While { body, cond } => {
                let header: String = match cond {
                    Some(LoopCond::Direct { cond, flags }) => {
                        format!("while {}", rs_cond_expr(*cond, flags, aggregates)?)
                    }
                    Some(LoopCond::Snapshot { var }) => {
                        format!("while {} != 0", loop_cond_var(*var))
                    }
                    None => "loop".to_owned(),
                };
                let _ = writeln!(out, "{indent}{header} {{");
                rs_emit_block(out, body, depth + 1, ret_expr, aggregates)?;
                let _ = writeln!(out, "{indent}}}");
            }
            Node::Switch {
                disc,
                cases,
                default,
            } => {
                let key: String = rs_signed_operand(reg_var(disc.reg), disc.width);
                let _ = writeln!(out, "{indent}match {key} {{");
                for (idx, case) in cases.iter().enumerate() {
                    let pattern: String = case
                        .values
                        .iter()
                        .map(|value: &i64| format!("{value}i64"))
                        .collect::<Vec<String>>()
                        .join(" | ");
                    let _ = writeln!(out, "{indent}    {pattern} => {{");
                    let mut cursor: usize = idx;
                    loop {
                        let arm: &SwitchCase = &cases[cursor];
                        rs_emit_block(out, &arm.body, depth + 2, ret_expr, aggregates)?;
                        if !arm.fallthrough {
                            break;
                        }
                        cursor += 1;
                        if cursor >= cases.len() {
                            rs_emit_block(out, default, depth + 2, ret_expr, aggregates)?;
                            break;
                        }
                    }
                    let _ = writeln!(out, "{indent}    }}");
                }
                let _ = writeln!(out, "{indent}    _ => {{");
                rs_emit_block(out, default, depth + 2, ret_expr, aggregates)?;
                let _ = writeln!(out, "{indent}    }}");
                let _ = writeln!(out, "{indent}}}");
            }
            Node::CondSnapshot { var, cond, flags } => {
                let cond_text: String = rs_cond_expr(*cond, flags, aggregates)?;
                let _ = writeln!(
                    out,
                    "{indent}{} = ({cond_text}) as u64;",
                    loop_cond_var(*var)
                );
            }
            Node::Break => {
                let _ = writeln!(out, "{indent}break;");
            }
            Node::Continue => {
                let _ = writeln!(out, "{indent}continue;");
            }
            Node::Return => {
                let _ = writeln!(out, "{indent}return {ret_expr};");
            }
            Node::Label(_) | Node::Goto(_) => return None,
        }
    }
    Some(())
}

fn rs_emit_reg_assign(out: &mut String, dest: RegRef, body: &str, indent: &str) {
    let var: &'static str = reg_var(dest.reg);
    let masked: String = rs_reg_write_rhs(var, dest.width, body);
    let _ = writeln!(out, "{indent}{var} = {masked};");
}

fn rs_emit_xmm_store(out: &mut String, dest: Xmm, value: &str, width: FpWidth, indent: &str) {
    let _ = writeln!(
        out,
        "{indent}{} = {};",
        xmm_var(dest),
        rs_fp_store_expr(value, width)
    );
}

fn rs_mul_imm_stmt(
    out: &mut String,
    dest: RegRef,
    src: &ExtSource,
    imm: i64,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let operand: String = match src {
        ExtSource::Reg(r) => reg_var(r.reg).to_string(),
        ExtSource::Mem(mem) => rs_deref_read(mem, aggregates),
    };
    let body: String = parse_expr(&operand).map_or_else(
        || format!("({operand}).wrapping_mul(({imm}i64) as u64)"),
        |opaque: RustExpr| {
            let factor: RustExpr = rcast(signed_int(imm, "i64"), rtype_path("u64"));
            render_rust_expr(&method_call(opaque, "wrapping_mul", vec![factor]))
        },
    );
    rs_emit_reg_assign(out, dest, &body, indent);
}

fn rs_emit_wide_mul(out: &mut String, src: RegRef, indent: &str) {
    let rax: &'static str = reg_var(Reg::Rax);
    let rdx: &'static str = reg_var(Reg::Rdx);
    let factor: &'static str = reg_var(src.reg);
    let _ = writeln!(out, "{indent}{{");
    let _ = writeln!(
        out,
        "{indent}    let wide_prod: u128 = ({rax} as u128) * ({factor} as u128);"
    );
    let _ = writeln!(out, "{indent}    {rax} = wide_prod as u64;");
    let _ = writeln!(out, "{indent}    {rdx} = (wide_prod >> 64) as u64;");
    let _ = writeln!(out, "{indent}}}");
}

fn rs_double_shift_stmt(
    out: &mut String,
    dest: RegRef,
    src: RegRef,
    amount: u8,
    left: bool,
    indent: &str,
) {
    let dst: &'static str = reg_var(dest.reg);
    let other: &'static str = reg_var(src.reg);
    let amount32: u32 = u32::from(amount);
    let complement: u32 = 64 - amount32;
    let (first_method, second_method): (&str, &str) = if left {
        ("wrapping_shl", "wrapping_shr")
    } else {
        ("wrapping_shr", "wrapping_shl")
    };
    let combined: RustExpr = binary(
        RBinOp::BitOr,
        method_call(
            rvar(dst),
            first_method,
            vec![int_dec(u128::from(amount32), "u32")],
        ),
        method_call(
            rvar(other),
            second_method,
            vec![int_dec(u128::from(complement), "u32")],
        ),
    );
    let body: String = render_rust_expr(&combined);
    let _ = writeln!(out, "{indent}{dst} = {body};");
}

fn rs_call_stmt(out: &mut String, target: u64, args: &[Reg], name: Option<&str>, indent: &str) {
    let arg_list: String = args
        .iter()
        .map(|r: &Reg| reg_var(*r))
        .collect::<Vec<&str>>()
        .join(", ");
    let _ = writeln!(
        out,
        "{indent}{} = unsafe {{ {}({arg_list}) }};",
        reg_var(Reg::Rax),
        call_display_name(target, name)
    );
}

fn rs_fp_bin_stmt(
    out: &mut String,
    dest: Xmm,
    lhs: &FpOperand,
    rhs: &FpOperand,
    op: FpOp,
    width: FpWidth,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let lhs_val: String = rs_fp_load(lhs, width, aggregates);
    let rhs_val: String = rs_fp_load(rhs, width, aggregates);
    let opstr: &str = match op {
        FpOp::Add => "+",
        FpOp::Sub => "-",
        FpOp::Mul => "*",
        FpOp::Div => "/",
    };
    let computed: String = format!("({lhs_val} {opstr} {rhs_val})");
    rs_emit_xmm_store(out, dest, &computed, width, indent);
}

fn rs_fp_mov_stmt(
    out: &mut String,
    dest: Xmm,
    src: &FpOperand,
    width: FpWidth,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let value: String = rs_fp_load(src, width, aggregates);
    rs_emit_xmm_store(out, dest, &value, width, indent);
}

fn rs_int_to_fp_stmt(
    out: &mut String,
    dest: Xmm,
    src: RegRef,
    signed: bool,
    width: FpWidth,
    fbits: Option<NonZeroU8>,
    indent: &str,
) -> Option<()> {
    let bits: u32 = src.width.bits();
    let int_expr: String = if signed {
        format!("({} as u{bits} as i{bits})", reg_var(src.reg))
    } else {
        format!("({} as u{bits})", reg_var(src.reg))
    };
    let value: String = match fbits {
        None => int_expr,
        Some(fraction) => {
            let scale: String = width.rust_power_of_two(fraction)?;
            format!("({int_expr} as {} / {scale})", width.rust_type())
        }
    };
    rs_emit_xmm_store(out, dest, &value, width, indent);
    Some(())
}

#[derive(Debug, Clone, Copy)]
struct RsFpToIntPlan {
    dest: RegRef,
    src: Xmm,
    width: FpWidth,
    signed: bool,
    round: FpToIntRound,
    fbits: Option<NonZeroU8>,
    saturating: bool,
}

fn rs_fp_to_int_stmt(out: &mut String, plan: RsFpToIntPlan, indent: &str) -> Option<()> {
    let loaded: String = rs_fp_load_xmm(plan.src, plan.width);
    let value: String = match plan.fbits {
        None => loaded,
        Some(fraction) => {
            let scale: String = plan.width.rust_power_of_two(fraction)?;
            format!("({loaded} * {scale})")
        }
    };
    let rounded: String = match plan.round {
        FpToIntRound::Zero => value,
        FpToIntRound::Floor => rs_fp_rint(RoundMode::Floor, &value, plan.width),
        FpToIntRound::Ceil => rs_fp_rint(RoundMode::Ceil, &value, plan.width),
        FpToIntRound::Away => rs_fp_rint(RoundMode::TiesAway, &value, plan.width),
    };
    let ity: &str = rs_int_ty(plan.dest.width);
    let uty: &str = rs_uint_ty(plan.dest.width);
    let truncated: String = if !plan.saturating && plan.signed {
        let ty: &str = plan.width.rust_type();
        let bound: String = format!("2{ty}.powi({})", plan.dest.width.bits() - 1);
        format!(
            "({{ let t: {ty} = {rounded}; (if t >= -({bound}) && t < {bound} {{ t as {ity} }} else {{ {ity}::MIN }}) as {uty} as u64 }})"
        )
    } else if plan.signed {
        format!("((({rounded}) as {ity}) as {uty} as u64)")
    } else {
        format!("((({rounded}) as {uty}) as u64)")
    };
    rs_emit_reg_assign(out, plan.dest, &truncated, indent);
    Some(())
}

fn rs_fp_convert_stmt(
    out: &mut String,
    dest: Xmm,
    src: Xmm,
    from: FpWidth,
    to: FpWidth,
    indent: &str,
) {
    let value: String = rs_fp_load_xmm(src, from);
    rs_emit_xmm_store(out, dest, &value, to, indent);
}

fn rs_fp_rint(mode: RoundMode, value: &str, width: FpWidth) -> String {
    let helper: &'static str = fp_semantics::rint_helper(mode, width);
    format!("{helper}({value})")
}

fn rs_fp_minmax_stmt(
    out: &mut String,
    dest: Xmm,
    lhs: &FpOperand,
    rhs: &FpOperand,
    kind: FpMinMaxKind,
    width: FpWidth,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let lhs_val: String = rs_fp_load(lhs, width, aggregates);
    let rhs_val: String = rs_fp_load(rhs, width, aggregates);
    let computed: String = if kind.uses_helper() {
        let helper: &'static str =
            fp_semantics::minmax_helper(kind.is_max(), kind.is_propagating_nan(), width);
        format!("({helper}({lhs_val}, {rhs_val}))")
    } else {
        let opstr: &str = if kind.is_max() { ">" } else { "<" };
        format!("(if {lhs_val} {opstr} {rhs_val} {{ {lhs_val} }} else {{ {rhs_val} }})")
    };
    rs_emit_xmm_store(out, dest, &computed, width, indent);
}

fn rs_fp_sqrt_stmt(
    out: &mut String,
    dest: Xmm,
    src: &FpOperand,
    width: FpWidth,
    saturating: bool,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let value: String = rs_fp_load(src, width, aggregates);
    let helper: &'static str = fp_semantics::sqrt_helper(saturating, width);
    let call: String = format!("{helper}({value})");
    rs_emit_xmm_store(out, dest, &call, width, indent);
}

fn rs_fp_round_stmt(
    out: &mut String,
    dest: Xmm,
    src: &FpOperand,
    width: FpWidth,
    mode: RoundMode,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let value: String = rs_fp_load(src, width, aggregates);
    let call: String = rs_fp_rint(mode, &value, width);
    rs_emit_xmm_store(out, dest, &call, width, indent);
}

fn rs_gpr_to_xmm_stmt(out: &mut String, dest: Xmm, src: RegRef, width: FpWidth, indent: &str) {
    let bits: String = match width {
        FpWidth::F64 => reg_var(src.reg).to_string(),
        FpWidth::F32 => format!("(({} as u32) as u64)", reg_var(src.reg)),
    };
    let _ = writeln!(out, "{indent}{} = {bits};", xmm_var(dest));
}

fn rs_xmm_to_gpr_stmt(out: &mut String, dest: RegRef, src: Xmm, width: FpWidth, indent: &str) {
    let bits: String = rs_xmm_bits(src, width);
    rs_emit_reg_assign(out, dest, &bits, indent);
}

fn rs_mem_rmw_stmt(
    out: &mut String,
    addr: &MemRef,
    op: &MemRmwOp,
    indent: &str,
    aggregates: &AggregatePlan,
) -> Option<()> {
    let current: String = rs_deref_read(addr, aggregates);
    let body: String = match op {
        MemRmwOp::Bin { op, src } => {
            let rhs: String = rs_source_expr(src, addr.width, aggregates)?;
            rs_bin_expr(*op, &current, &rhs, addr.width)
        }
        MemRmwOp::Un(un_op) => rs_unop_expr(*un_op, &current, addr.width),
    };
    rs_emit_store(out, addr, &body, indent, aggregates);
    Some(())
}

fn rs_emit_stmt(
    out: &mut String,
    stmt: &Stmt,
    indent: &str,
    aggregates: &AggregatePlan,
) -> Option<()> {
    match stmt {
        Stmt::Assign { dest, src } => {
            let body: String = rs_source_expr(src, dest.width, aggregates)?;
            rs_emit_reg_assign(out, *dest, &body, indent);
        }
        Stmt::BinAssign { dest, op, src } => {
            let var: &'static str = reg_var(dest.reg);
            let rhs: String = rs_source_expr(src, dest.width, aggregates)?;
            let body: String = rs_bin_expr(*op, var, &rhs, dest.width);
            rs_emit_reg_assign(out, *dest, &body, indent);
        }
        Stmt::UnAssign { dest, op } => {
            let var: &'static str = reg_var(dest.reg);
            let body: String = rs_unop_expr(*op, var, dest.width);
            rs_emit_reg_assign(out, *dest, &body, indent);
        }
        Stmt::Cond {
            dest,
            src,
            kind,
            flags,
        } => {
            let cond: String = rs_cond_expr(*kind, flags, aggregates)?;
            let chosen: String = rs_source_expr(src, dest.width, aggregates)?;
            let var: &'static str = reg_var(dest.reg);
            let taken: String = rs_reg_write_rhs(var, dest.width, &chosen);
            let _ = writeln!(
                out,
                "{indent}{var} = if {cond} {{ {taken} }} else {{ {var} }};"
            );
        }
        Stmt::SetCc { dest, kind, flags } => {
            let cond: String = rs_cond_expr(*kind, flags, aggregates)?;
            let var: &'static str = reg_var(dest.reg);
            let _ = writeln!(
                out,
                "{indent}{var} = ({var} & 0xffffffffffffff00u64) | (({cond}) as u64);"
            );
        }
        Stmt::FlagSnapshot { var, kind, flags } => {
            let cond: String = rs_cond_expr(*kind, flags, aggregates)?;
            let _ = writeln!(out, "{indent}{} = ({cond}) as u64;", sel_var(*var));
        }
        Stmt::Extend { dest, src, signed } => {
            let (raw, src_width): (String, Width) = match src {
                ExtSource::Reg(r) => (reg_var(r.reg).to_string(), r.width),
                ExtSource::Mem(mem) => (rs_deref_read(mem, aggregates), mem.width),
            };
            let body: String = rs_extend_expr(&raw, src_width, dest.width, *signed);
            rs_emit_reg_assign(out, *dest, &body, indent);
        }
        Stmt::MulImm { dest, src, imm } => {
            rs_mul_imm_stmt(out, *dest, src, *imm, indent, aggregates);
        }
        Stmt::WideMul { src } => rs_emit_wide_mul(out, *src, indent),
        Stmt::Divide { divisor, signed } => rs_emit_divide(out, *divisor, *signed, indent),
        Stmt::DoubleShift {
            dest,
            src,
            amount,
            left,
        } => rs_double_shift_stmt(out, *dest, *src, *amount, *left, indent),
        Stmt::Call { target, args, name } => {
            rs_call_stmt(out, *target, args, name.as_deref(), indent);
        }
        Stmt::FpBin {
            dest,
            lhs,
            rhs,
            op,
            width,
        } => rs_fp_bin_stmt(out, *dest, lhs, rhs, *op, *width, indent, aggregates),
        Stmt::FpMov { dest, src, width } => {
            rs_fp_mov_stmt(out, *dest, src, *width, indent, aggregates);
        }
        Stmt::IntToFp {
            dest,
            src,
            signed,
            width,
            fbits,
        } => rs_int_to_fp_stmt(out, *dest, *src, *signed, *width, *fbits, indent)?,
        Stmt::FpToInt {
            dest,
            src,
            width,
            signed,
            round,
            fbits,
            saturating,
        } => rs_fp_to_int_stmt(
            out,
            RsFpToIntPlan {
                dest: *dest,
                src: *src,
                width: *width,
                signed: *signed,
                round: *round,
                fbits: *fbits,
                saturating: *saturating,
            },
            indent,
        )?,
        Stmt::FpConvert {
            dest,
            src,
            from,
            to,
        } => rs_fp_convert_stmt(out, *dest, *src, *from, *to, indent),
        Stmt::FpMinMax {
            dest,
            lhs,
            rhs,
            kind,
            width,
        } => rs_fp_minmax_stmt(out, *dest, lhs, rhs, *kind, *width, indent, aggregates),
        Stmt::FpFma {
            dest,
            mul_lhs,
            mul_rhs,
            addend,
            kind,
            width,
        } => {
            let lhs_val: String = rs_fp_load(mul_lhs, *width, aggregates);
            let rhs_val: String = rs_fp_load(mul_rhs, *width, aggregates);
            let addend_val: String = rs_fp_load(addend, *width, aggregates);
            let lhs_expr: String = if kind.negates_multiplicand() {
                format!("(-{lhs_val})")
            } else {
                format!("({lhs_val})")
            };
            let addend_expr: String = if kind.negates_addend() {
                format!("(-{addend_val})")
            } else {
                format!("({addend_val})")
            };
            let helper: &'static str = fp_semantics::fma_helper(*width);
            let computed: String = format!("{helper}({lhs_expr}, {rhs_val}, {addend_expr})");
            rs_emit_xmm_store(out, *dest, &computed, *width, indent);
        }
        Stmt::FpCsel {
            dest,
            if_true,
            if_false,
            kind,
            flags,
            width,
        } => {
            let cond: String = rs_cond_expr(*kind, flags, aggregates)?;
            let taken: String = rs_fp_load(if_true, *width, aggregates);
            let untaken: String = rs_fp_load(if_false, *width, aggregates);
            let computed: String = format!("(if {cond} {{ {taken} }} else {{ {untaken} }})");
            rs_emit_xmm_store(out, *dest, &computed, *width, indent);
        }
        Stmt::FpSqrt {
            dest,
            src,
            width,
            saturating,
        } => {
            rs_fp_sqrt_stmt(out, *dest, src, *width, *saturating, indent, aggregates);
        }
        Stmt::FpUnary {
            dest,
            src,
            op,
            width,
        } => {
            let value: String = rs_fp_load(src, *width, aggregates);
            let computed: String = match op {
                FpUnaryOp::Neg => format!("(-({value}))"),
                FpUnaryOp::Abs => format!("({value}).abs()"),
            };
            rs_emit_xmm_store(out, *dest, &computed, *width, indent);
        }
        Stmt::FpRound {
            dest,
            src,
            width,
            mode,
        } => rs_fp_round_stmt(out, *dest, src, *width, *mode, indent, aggregates),
        Stmt::GprToXmm { dest, src, width } => rs_gpr_to_xmm_stmt(out, *dest, *src, *width, indent),
        Stmt::XmmToGpr { dest, src, width } => rs_xmm_to_gpr_stmt(out, *dest, *src, *width, indent),
        Stmt::Store { addr, src } => {
            let value: String = rs_source_expr(src, addr.width, aggregates)?;
            rs_emit_store(out, addr, &value, indent, aggregates);
        }
        Stmt::MemRmw { addr, op } => {
            rs_mem_rmw_stmt(out, addr, op, indent, aggregates)?;
        }
        Stmt::FpStore { addr, src, width } => {
            rs_emit_fp_store(out, addr, *src, *width, indent, aggregates);
        }
        Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Packed { .. }
        | Stmt::Vector(_)
        | Stmt::PackedToGpr { .. } => return None,
    }
    Some(())
}

fn aggregate_rust_base(plan: &AggregatePlan, root: usize, base: Reg) -> Option<String> {
    let root_plan: &AggregateRootPlan = plan.roots.get(root)?;
    if root_plan.bind_local {
        aggregate_rust_local_name(plan, root)
    } else {
        let ty: String = aggregate_rust_type_name(plan, root)?;
        Some(format!("(({} as usize) as *mut {ty})", reg_var(base)))
    }
}

fn aggregate_rust_address(
    mem: &MemRef,
    plan: &AggregatePlan,
    mutable: bool,
    scalar: AggregateScalar,
) -> Option<(String, bool)> {
    match plan.access(mem, scalar)? {
        AggregateAccess::Field {
            root,
            base,
            disp,
            nested,
            ..
        } => {
            let base: String = aggregate_rust_base(plan, root, base)?;
            let field: String = aggregate_field_name(disp);
            let address_macro: &str = if mutable { "addr_of_mut" } else { "addr_of" };
            Some((
                format!("core::ptr::{address_macro}!((*{base}).{field})"),
                nested.is_some(),
            ))
        }
        AggregateAccess::Array {
            root, base, index, ..
        } => {
            let base: String = aggregate_rust_base(plan, root, base)?;
            Some((
                format!("{base}.wrapping_add({} as usize)", reg_var(index)),
                false,
            ))
        }
        AggregateAccess::UnionMember { root, base, scalar } => {
            let base: String = aggregate_rust_base(plan, root, base)?;
            let member: String = aggregate_member_name(scalar);
            let address_macro: &str = if mutable { "addr_of_mut" } else { "addr_of" };
            Some((
                format!("core::ptr::{address_macro}!((*{base}).{member})"),
                false,
            ))
        }
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_deref_read(mem: &MemRef, aggregates: &AggregatePlan) -> String {
    if let Some((ptr, pointer)) =
        aggregate_rust_address(mem, aggregates, false, AggregateScalar::Integer(mem.width))
        && let Some(ptr_expr) = parse_expr(&ptr)
    {
        let read: RustExpr = rcall(
            path_expr(&["core", "ptr", "read_unaligned"]),
            vec![ptr_expr],
        );
        let value: RustExpr = unsafe_block(read);
        let widened: RustExpr = if pointer {
            rcast(rcast(value, rtype_path("usize")), rtype_path("u64"))
        } else {
            rcast(value, rtype_path("u64"))
        };
        return render_rust_expr(&widened);
    }
    let uty: &str = rs_uint_ty(mem.width);
    let ptr: String = rs_addr_expr(mem.base, mem.index, mem.disp);
    match parse_expr(&ptr) {
        Some(ptr_expr) => {
            let as_usize: RustExpr = rcast(ptr_expr, rtype_path("usize"));
            let as_const_ptr: RustExpr = rcast(as_usize, ptr_type(false, rtype_path(uty)));
            let read: RustExpr = rcall(
                path_expr(&["core", "ptr", "read_unaligned"]),
                vec![as_const_ptr],
            );
            render_rust_expr(&rcast(unsafe_block(read), rtype_path("u64")))
        }
        None => {
            format!(
                "(unsafe {{ core::ptr::read_unaligned((({ptr}) as usize) as *const {uty}) }} as u64)"
            )
        }
    }
}

fn rs_emit_store(
    out: &mut String,
    addr: &MemRef,
    value: &str,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let uty: &str = rs_uint_ty(addr.width);
    if let Some((ptr, pointer)) =
        aggregate_rust_address(addr, aggregates, true, AggregateScalar::Integer(addr.width))
        && !pointer
        && let (Some(ptr_expr), Some(value_expr)) = (parse_expr(&ptr), parse_expr(value))
    {
        let write: RustExpr = rcall(
            path_expr(&["core", "ptr", "write_unaligned"]),
            vec![ptr_expr, rcast(value_expr, rtype_path(uty))],
        );
        let stmt: String = format!("{};", render_rust_expr(&unsafe_block(write)));
        let _ = writeln!(out, "{indent}{stmt}");
        return;
    }
    let ptr: String = rs_addr_expr(addr.base, addr.index, addr.disp);
    let stmt: String = match (parse_expr(&ptr), parse_expr(value)) {
        (Some(ptr_expr), Some(value_expr)) => {
            let as_usize: RustExpr = rcast(ptr_expr, rtype_path("usize"));
            let as_mut_ptr: RustExpr = rcast(as_usize, ptr_type(true, rtype_path(uty)));
            let write: RustExpr = rcall(
                path_expr(&["core", "ptr", "write_unaligned"]),
                vec![as_mut_ptr, rcast(value_expr, rtype_path(uty))],
            );
            format!("{};", render_rust_expr(&unsafe_block(write)))
        }
        _ => format!(
            "unsafe {{ core::ptr::write_unaligned((({ptr}) as usize) as *mut {uty}, ({value}) as {uty}); }}"
        ),
    };
    let _ = writeln!(out, "{indent}{stmt}");
}

fn rs_fp_aggregate_slot(
    mem: &MemRef,
    width: FpWidth,
    mutable: bool,
    aggregates: &AggregatePlan,
) -> Option<RustExpr> {
    match aggregate_rust_address(mem, aggregates, mutable, AggregateScalar::Float(width))? {
        (_, true) => None,
        (ptr, false) => parse_expr(&ptr),
    }
}

fn rs_emit_fp_store(
    out: &mut String,
    addr: &MemRef,
    src: Xmm,
    width: FpWidth,
    indent: &str,
    aggregates: &AggregatePlan,
) {
    let value: String = rs_fp_load_xmm(src, width);
    if let Some(ptr_expr) = rs_fp_aggregate_slot(addr, width, true, aggregates)
        && let Some(value_expr) = parse_expr(&value)
    {
        let write: RustExpr = rcall(
            path_expr(&["core", "ptr", "write_unaligned"]),
            vec![ptr_expr, value_expr],
        );
        let _ = writeln!(out, "{indent}{};", render_rust_expr(&unsafe_block(write)));
        return;
    }
    let bits: String = rs_xmm_bits(src, width);
    rs_emit_store(out, addr, &bits, indent, aggregates);
}

const fn rs_fp_bits_ty(width: FpWidth) -> &'static str {
    match width {
        FpWidth::F32 => "u32",
        FpWidth::F64 => "u64",
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_fp_mem_read(mem: &MemRef, width: FpWidth, aggregates: &AggregatePlan) -> String {
    if let Some(ptr_expr) = rs_fp_aggregate_slot(mem, width, false, aggregates) {
        let read: RustExpr = rcall(
            path_expr(&["core", "ptr", "read_unaligned"]),
            vec![ptr_expr],
        );
        return render_rust_expr(&unsafe_block(read));
    }
    let bits_ty: &'static str = rs_fp_bits_ty(width);
    let float_ty: &'static str = width.rust_type();
    let ptr: String = rs_addr_expr(mem.base, mem.index, mem.disp);
    match parse_expr(&ptr) {
        Some(ptr_expr) => {
            let as_usize: RustExpr = rcast(ptr_expr, rtype_path("usize"));
            let as_const_ptr: RustExpr = rcast(as_usize, ptr_type(false, rtype_path(bits_ty)));
            let read: RustExpr = rcall(
                path_expr(&["core", "ptr", "read_unaligned"]),
                vec![as_const_ptr],
            );
            render_rust_expr(&rcall(
                path_expr(&[float_ty, "from_bits"]),
                vec![unsafe_block(read)],
            ))
        }
        None => format!(
            "{float_ty}::from_bits(unsafe {{ core::ptr::read_unaligned((({ptr}) as usize) as *const {bits_ty}) }})"
        ),
    }
}

fn rs_fp_load(operand: &FpOperand, width: FpWidth, aggregates: &AggregatePlan) -> String {
    match operand {
        FpOperand::Xmm(x) => rs_fp_load_xmm(*x, width),
        FpOperand::Mem(mem) => rs_fp_mem_read(mem, width, aggregates),
        FpOperand::Const { bits, .. } => rs_fp_const_literal(*bits, width),
    }
}

fn rs_fp_load_xmm(xmm: Xmm, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => render_rust_expr(&rcall(
            path_expr(&["f64", "from_bits"]),
            vec![rvar(xmm_var(xmm))],
        )),
        FpWidth::F32 => render_rust_expr(&rcall(
            path_expr(&["f32", "from_bits"]),
            vec![rcast(rvar(xmm_var(xmm)), rtype_path("u32"))],
        )),
    }
}

fn rs_fp_const_literal(bits: u64, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => render_rust_expr(&rcall(
            path_expr(&["f64", "from_bits"]),
            vec![int_hex(u128::from(bits), "u64")],
        )),
        FpWidth::F32 => render_rust_expr(&rcall(
            path_expr(&["f32", "from_bits"]),
            vec![int_hex(u128::from(bits as u32), "u32")],
        )),
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_fp_store_expr(value: &str, width: FpWidth) -> String {
    let rust_ty: &str = match width {
        FpWidth::F64 => "f64",
        FpWidth::F32 => "f32",
    };
    match parse_expr(value) {
        Some(opaque) => {
            let as_float: RustExpr = rcast(opaque, rtype_path(rust_ty));
            let bits: RustExpr = method_call(as_float, "to_bits", Vec::new());
            match width {
                FpWidth::F64 => render_rust_expr(&bits),
                FpWidth::F32 => render_rust_expr(&rcast(bits, rtype_path("u64"))),
            }
        }
        None => match width {
            FpWidth::F64 => format!("(({value}) as f64).to_bits()"),
            FpWidth::F32 => format!("((({value}) as f32).to_bits() as u64)"),
        },
    }
}

fn rs_xmm_bits(xmm: Xmm, width: FpWidth) -> String {
    match width {
        FpWidth::F64 => xmm_var(xmm).to_string(),
        FpWidth::F32 => render_rust_expr(&rcast(
            rcast(rvar(xmm_var(xmm)), rtype_path("u32")),
            rtype_path("u64"),
        )),
    }
}

fn rs_emit_divide(out: &mut String, divisor: RegRef, signed: bool, indent: &str) {
    let rax: &'static str = reg_var(Reg::Rax);
    let rdx: &'static str = reg_var(Reg::Rdx);
    let div: &'static str = reg_var(divisor.reg);
    let width: Width = divisor.width;
    let _ = writeln!(out, "{indent}{{");
    if signed {
        let ity: &str = rs_int_ty(width);
        let uty: &str = rs_uint_ty(width);
        let _ = writeln!(out, "{indent}    let div_lhs: {ity} = {rax} as {ity};");
        let _ = writeln!(out, "{indent}    let div_rhs: {ity} = {div} as {ity};");
        let _ = writeln!(
            out,
            "{indent}    {rax} = (div_lhs / div_rhs) as {uty} as u64;"
        );
        let _ = writeln!(
            out,
            "{indent}    {rdx} = (div_lhs % div_rhs) as {uty} as u64;"
        );
    } else {
        let uty: &str = rs_uint_ty(width);
        let _ = writeln!(out, "{indent}    let div_lhs: {uty} = {rax} as {uty};");
        let _ = writeln!(out, "{indent}    let div_rhs: {uty} = {div} as {uty};");
        let _ = writeln!(out, "{indent}    {rax} = (div_lhs / div_rhs) as u64;");
        let _ = writeln!(out, "{indent}    {rdx} = (div_lhs % div_rhs) as u64;");
    }
    let _ = writeln!(out, "{indent}}}");
}

fn rs_rev32_expr(text: &str) -> String {
    format!(
        "(((({text}) as u64 & 0x000000ff000000ffu64) << 24) | ((({text}) as u64 & 0x0000ff000000ff00u64) << 8) | ((({text}) as u64 & 0x00ff000000ff0000u64) >> 8) | ((({text}) as u64 & 0xff000000ff000000u64) >> 24))"
    )
}

fn rs_rev16_expr(text: &str, width_bits: u32) -> String {
    let bits: u32 = width_bits.max(32);
    let (hi, lo): (&str, &str) = if bits >= 64 {
        ("0xff00ff00ff00ff00u64", "0x00ff00ff00ff00ffu64")
    } else {
        ("0xff00ff00u32", "0x00ff00ffu32")
    };
    format!("(((({text}) as u{bits} & {hi}) >> 8) | ((({text}) as u{bits} & {lo}) << 8)) as u64")
}

#[allow(clippy::option_if_let_else)]
fn rs_unop_expr(op: UnOp, text: &str, width: Width) -> String {
    let bits: u32 = width.bits();
    match parse_expr(text) {
        Some(operand) => match op {
            UnOp::Neg => render_rust_expr(&method_call(operand, "wrapping_neg", Vec::new())),
            UnOp::Not => render_rust_expr(&runary(RUnOp::Not, operand)),
            UnOp::Bswap => format!("(({text}) as u{bits}).swap_bytes() as u64"),
            UnOp::Clz => format!("(({text}) as u{bits}).leading_zeros() as u64"),
            UnOp::Rbit => format!("(({text}) as u{bits}).reverse_bits() as u64"),
            UnOp::Rev16 => rs_rev16_expr(text, bits),
            UnOp::Rev32 => rs_rev32_expr(text),
        },
        None => match op {
            UnOp::Neg => format!("({text}).wrapping_neg()"),
            UnOp::Not => format!("(!({text}))"),
            UnOp::Bswap => format!("(({text}) as u{bits}).swap_bytes() as u64"),
            UnOp::Clz => format!("(({text}) as u{bits}).leading_zeros() as u64"),
            UnOp::Rbit => format!("(({text}) as u{bits}).reverse_bits() as u64"),
            UnOp::Rev16 => rs_rev16_expr(text, bits),
            UnOp::Rev32 => rs_rev32_expr(text),
        },
    }
}

fn rs_index_extend(reg: RustExpr, extend: IndexExtend) -> RustExpr {
    match extend {
        IndexExtend::Full => reg,
        IndexExtend::SignExtendWord => {
            let truncated: RustExpr = rcast(reg, rtype_path("u32"));
            let signed: RustExpr = rcast(truncated, rtype_path("i32"));
            let widened: RustExpr = rcast(signed, rtype_path("i64"));
            rcast(widened, rtype_path("u64"))
        }
        IndexExtend::ZeroExtendWord => {
            let truncated: RustExpr = rcast(reg, rtype_path("u32"));
            rcast(truncated, rtype_path("u64"))
        }
    }
}

fn rs_addr_expr(base: Option<Reg>, index: Option<IndexOperand>, disp: i64) -> String {
    let mut parts: Vec<RustExpr> = Vec::new();
    if let Some(b) = base {
        parts.push(rvar(reg_var(b)));
    }
    if let Some(idx) = index {
        let extended: RustExpr = rs_index_extend(rvar(reg_var(idx.reg)), idx.extend);
        let scaled: RustExpr = method_call(
            extended,
            "wrapping_mul",
            vec![int_dec(u128::from(idx.scale), "u64")],
        );
        parts.push(scaled);
    }
    if disp != 0 || parts.is_empty() {
        parts.push(rcast(signed_int(disp, "i64"), rtype_path("u64")));
    }
    let combined: RustExpr = parts
        .into_iter()
        .reduce(|acc: RustExpr, part: RustExpr| method_call(acc, "wrapping_add", vec![part]))
        .unwrap_or_else(|| int_dec(0, "u64"));
    render_rust_expr(&combined)
}

fn rs_source_expr(src: &Source, width: Width, aggregates: &AggregatePlan) -> Option<String> {
    match src {
        Source::Reg(r) => {
            if r.width == width || width == Width::W64 {
                Some(reg_var(r.reg).to_string())
            } else {
                let mask: u128 = (1u128 << r.width.bits()) - 1;
                let masked: RustExpr =
                    binary(RBinOp::BitAnd, rvar(reg_var(r.reg)), int_hex(mask, "u64"));
                Some(render_rust_expr(&masked))
            }
        }
        Source::Imm(value) => Some(render_rust_expr(&rcast(
            signed_int(*value, "i64"),
            rtype_path("u64"),
        ))),
        Source::Lea { base, index, disp } => Some(rs_addr_expr(*base, *index, *disp)),
        Source::Mem(mem) => Some(rs_deref_read(mem, aggregates)),
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_width_mask(width: Width, body: &str) -> String {
    match width {
        Width::W64 => body.to_owned(),
        other => {
            let mask: u128 = (1u128 << other.bits()) - 1;
            match parse_expr(body) {
                Some(opaque) => {
                    render_rust_expr(&binary(RBinOp::BitAnd, opaque, int_hex(mask, "u64")))
                }
                None => format!("(({body}) & 0x{mask:x}u64)"),
            }
        }
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_reg_write_rhs(dest_var: &str, width: Width, body: &str) -> String {
    match width {
        Width::W64 => body.to_owned(),
        Width::W32 => match parse_expr(body) {
            Some(opaque) => {
                render_rust_expr(&binary(RBinOp::BitAnd, opaque, int_hex(0xffff_ffff, "u64")))
            }
            None => format!("(({body}) & 0xffffffffu64)"),
        },
        Width::W16 => match parse_expr(body) {
            Some(opaque) => render_rust_expr(&binary(
                RBinOp::BitOr,
                binary(
                    RBinOp::BitAnd,
                    rvar(dest_var),
                    int_hex(0xffff_ffff_ffff_0000, "u64"),
                ),
                binary(RBinOp::BitAnd, opaque, int_hex(0xffff, "u64")),
            )),
            None => format!("(({dest_var} & 0xffffffffffff0000u64) | (({body}) & 0xffffu64))"),
        },
        Width::W8 => match parse_expr(body) {
            Some(opaque) => render_rust_expr(&binary(
                RBinOp::BitOr,
                binary(
                    RBinOp::BitAnd,
                    rvar(dest_var),
                    int_hex(0xffff_ffff_ffff_ff00, "u64"),
                ),
                binary(RBinOp::BitAnd, opaque, int_hex(0xff, "u64")),
            )),
            None => format!("(({dest_var} & 0xffffffffffffff00u64) | (({body}) & 0xffu64))"),
        },
    }
}

fn rs_bin_expr(op: BinOp, lhs: &str, rhs: &str, width: Width) -> String {
    let bits: u32 = width.bits();
    let shift_mask: u32 = width.shift_count_mask();
    let (parsed_lhs, parsed_rhs): (Option<RustExpr>, Option<RustExpr>) =
        (parse_expr(lhs), parse_expr(rhs));
    match op {
        BinOp::Add => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&method_call(l, "wrapping_add", vec![r])),
            _ => format!("({lhs}).wrapping_add({rhs})"),
        },
        BinOp::Sub => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&method_call(l, "wrapping_sub", vec![r])),
            _ => format!("({lhs}).wrapping_sub({rhs})"),
        },
        BinOp::Imul => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&method_call(l, "wrapping_mul", vec![r])),
            _ => format!("({lhs}).wrapping_mul({rhs})"),
        },
        BinOp::And => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&binary(RBinOp::BitAnd, l, r)),
            _ => format!("(({lhs}) & ({rhs}))"),
        },
        BinOp::Or => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&binary(RBinOp::BitOr, l, r)),
            _ => format!("(({lhs}) | ({rhs}))"),
        },
        BinOp::Xor => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => render_rust_expr(&binary(RBinOp::BitXor, l, r)),
            _ => format!("(({lhs}) ^ ({rhs}))"),
        },
        BinOp::Shl => match (parsed_lhs, parsed_rhs) {
            (Some(l), Some(r)) => {
                let masked_shift: RustExpr =
                    binary(RBinOp::BitAnd, r, int_dec(u128::from(shift_mask), "u64"));
                let amount: RustExpr = rcast(masked_shift, rtype_path("u32"));
                render_rust_expr(&method_call(l, "wrapping_shl", vec![amount]))
            }
            _ => format!("({lhs}).wrapping_shl((({rhs}) & {shift_mask}u64) as u32)"),
        },
        BinOp::Shr => {
            let mask: u128 = (1u128 << bits) - 1;
            match (parsed_lhs, parsed_rhs) {
                (Some(l), Some(r)) => {
                    let masked_lhs: RustExpr = binary(RBinOp::BitAnd, l, int_hex(mask, "u64"));
                    let masked_shift: RustExpr =
                        binary(RBinOp::BitAnd, r, int_dec(u128::from(shift_mask), "u64"));
                    let amount: RustExpr = rcast(masked_shift, rtype_path("u32"));
                    render_rust_expr(&method_call(masked_lhs, "wrapping_shr", vec![amount]))
                }
                _ => format!(
                    "(({lhs}) & 0x{mask:x}u64).wrapping_shr((({rhs}) & {shift_mask}u64) as u32)"
                ),
            }
        }
        BinOp::Sar => {
            let ity: &str = rs_int_ty(width);
            match (parsed_lhs, parsed_rhs) {
                (Some(l), Some(r)) => {
                    let signed: RustExpr = rcast(rcast(l, rtype_path(ity)), rtype_path("i64"));
                    let masked_shift: RustExpr =
                        binary(RBinOp::BitAnd, r, int_dec(u128::from(shift_mask), "u64"));
                    let amount: RustExpr = rcast(masked_shift, rtype_path("u32"));
                    let shifted: RustExpr = method_call(signed, "wrapping_shr", vec![amount]);
                    render_rust_expr(&rcast(shifted, rtype_path("u64")))
                }
                _ => format!(
                    "(((({lhs}) as {ity}) as i64).wrapping_shr((({rhs}) & {shift_mask}u64) as u32) as u64)"
                ),
            }
        }
        BinOp::Sdiv => {
            let ity: &str = rs_int_ty(width);
            match (parsed_lhs, parsed_rhs) {
                (Some(l), Some(r)) => {
                    let ls: RustExpr = rcast(l, rtype_path(ity));
                    let rs: RustExpr = rcast(r, rtype_path(ity));
                    let q: RustExpr = method_call(ls, "wrapping_div", vec![rs]);
                    render_rust_expr(&rcast(q, rtype_path("u64")))
                }
                _ => format!("((({lhs}) as {ity}).wrapping_div(({rhs}) as {ity}) as u64)"),
            }
        }
        BinOp::Udiv => {
            let uty: String = format!("u{}", width.bits());
            match (parsed_lhs, parsed_rhs) {
                (Some(l), Some(r)) => {
                    let ls: RustExpr = rcast(l, rtype_path(&uty));
                    let rs: RustExpr = rcast(r, rtype_path(&uty));
                    let q: RustExpr = method_call(ls, "wrapping_div", vec![rs]);
                    render_rust_expr(&rcast(q, rtype_path("u64")))
                }
                _ => format!("((({lhs}) as {uty}).wrapping_div(({rhs}) as {uty}) as u64)"),
            }
        }
        BinOp::Umull => {
            format!("(({lhs}) as u32 as u64).wrapping_mul(({rhs}) as u32 as u64)")
        }
        BinOp::Smull => {
            format!("((({lhs}) as i32 as i64).wrapping_mul(({rhs}) as i32 as i64) as u64)")
        }
        BinOp::Umulh => {
            format!("((({lhs}) as u128).wrapping_mul(({rhs}) as u128) >> 64) as u64")
        }
        BinOp::Smulh => {
            format!(
                "((({lhs}) as i64 as i128).wrapping_mul(({rhs}) as i64 as i128) >> 64) as i64 as u64"
            )
        }
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_extend_expr(raw: &str, src_width: Width, dst_width: Width, signed: bool) -> String {
    let src_mask: u128 = (1u128 << src_width.bits()) - 1;
    match parse_expr(raw) {
        Some(opaque) => {
            let narrowed: RustExpr = binary(RBinOp::BitAnd, opaque, int_hex(src_mask, "u64"));
            let chain: RustExpr = if signed {
                rcast(
                    rcast(
                        rcast(narrowed, rtype_path(rs_int_ty(src_width))),
                        rtype_path(rs_int_ty(dst_width)),
                    ),
                    rtype_path(rs_uint_ty(dst_width)),
                )
            } else {
                rcast(
                    rcast(narrowed, rtype_path(rs_uint_ty(src_width))),
                    rtype_path(rs_uint_ty(dst_width)),
                )
            };
            render_rust_expr(&rcast(chain, rtype_path("u64")))
        }
        None => {
            let narrowed: String = format!("(({raw}) & 0x{src_mask:x}u64)");
            if signed {
                format!(
                    "({narrowed} as {si} as {di} as {du} as u64)",
                    si = rs_int_ty(src_width),
                    di = rs_int_ty(dst_width),
                    du = rs_uint_ty(dst_width)
                )
            } else {
                format!(
                    "({narrowed} as {su} as {du} as u64)",
                    su = rs_uint_ty(src_width),
                    du = rs_uint_ty(dst_width)
                )
            }
        }
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_signed_operand(expr: &str, width: Width) -> String {
    match parse_expr(expr) {
        Some(opaque) => render_rust_expr(&rcast(
            rcast(opaque, rtype_path(rs_int_ty(width))),
            rtype_path("i64"),
        )),
        None => format!("((({expr}) as {ity}) as i64)", ity = rs_int_ty(width)),
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_unsigned_operand(expr: &str, width: Width) -> String {
    match width {
        Width::W64 => format!("({expr})"),
        other => {
            let mask: u128 = (1u128 << other.bits()) - 1;
            match parse_expr(expr) {
                Some(opaque) => {
                    render_rust_expr(&binary(RBinOp::BitAnd, opaque, int_hex(mask, "u64")))
                }
                None => format!("(({expr}) & 0x{mask:x}u64)"),
            }
        }
    }
}

fn rs_binary_text(a: &str, b: &str, op: RBinOp, op_text: &str) -> String {
    match (parse_expr(a), parse_expr(b)) {
        (Some(l), Some(r)) => render_rust_expr(&binary(op, l, r)),
        _ => format!("{a} {op_text} {b}"),
    }
}

fn fp_compare_rust(
    kind: CondKind,
    a: &str,
    b: &str,
    same_operand: bool,
    model: FpUnorderedModel,
) -> String {
    match kind {
        CondKind::E => match model {
            FpUnorderedModel::UnorderedIsUnequal => rs_binary_text(a, b, RBinOp::Eq, "=="),
            FpUnorderedModel::UnorderedIsEqual => format!(
                "!({}) && !({})",
                rs_binary_text(a, b, RBinOp::Lt, "<"),
                rs_binary_text(a, b, RBinOp::Gt, ">")
            ),
        },
        CondKind::Ne => match model {
            FpUnorderedModel::UnorderedIsUnequal => rs_binary_text(a, b, RBinOp::Ne, "!="),
            FpUnorderedModel::UnorderedIsEqual => format!(
                "({}) || ({})",
                rs_binary_text(a, b, RBinOp::Lt, "<"),
                rs_binary_text(a, b, RBinOp::Gt, ">")
            ),
        },
        CondKind::S | CondKind::B => rs_binary_text(a, b, RBinOp::Lt, "<"),
        CondKind::Ns | CondKind::Ae => format!("!({})", rs_binary_text(a, b, RBinOp::Lt, "<")),
        CondKind::Be => rs_binary_text(a, b, RBinOp::Le, "<="),
        CondKind::A => format!("!({})", rs_binary_text(a, b, RBinOp::Le, "<=")),
        CondKind::Ge => rs_binary_text(a, b, RBinOp::Ge, ">="),
        CondKind::L => format!("!({})", rs_binary_text(a, b, RBinOp::Ge, ">=")),
        CondKind::G => rs_binary_text(a, b, RBinOp::Gt, ">"),
        CondKind::Le => format!("!({})", rs_binary_text(a, b, RBinOp::Gt, ">")),
        CondKind::Vs | CondKind::P => fp_nan_test_rust(a, b, same_operand, true),
        CondKind::Vc | CondKind::Np => fp_nan_test_rust(a, b, same_operand, false),
    }
}

fn fp_nan_test_rust(a: &str, b: &str, same_operand: bool, unordered: bool) -> String {
    let one = |x: &str| -> String {
        if unordered {
            format!("({x}).is_nan()")
        } else {
            format!("!({x}).is_nan()")
        }
    };
    if same_operand {
        one(a)
    } else if unordered {
        format!("{} || {}", one(a), one(b))
    } else {
        format!("{} && {}", one(a), one(b))
    }
}

fn rs_compare_expr(kind: CondKind, lhs_expr: &str, rhs_expr: &str, width: Width) -> String {
    if kind.is_unsigned_order() {
        let a: String = rs_unsigned_operand(lhs_expr, width);
        let b: String = rs_unsigned_operand(rhs_expr, width);
        let (op, op_text): (RBinOp, &str) = match kind {
            CondKind::A => (RBinOp::Gt, ">"),
            CondKind::Ae => (RBinOp::Ge, ">="),
            CondKind::B => (RBinOp::Lt, "<"),
            CondKind::Be => (RBinOp::Le, "<="),
            _ => unreachable!(),
        };
        rs_binary_text(&a, &b, op, op_text)
    } else if kind.is_signed_order() {
        let a: String = rs_signed_operand(lhs_expr, width);
        let b: String = rs_signed_operand(rhs_expr, width);
        let (op, op_text): (RBinOp, &str) = match kind {
            CondKind::G => (RBinOp::Gt, ">"),
            CondKind::Ge => (RBinOp::Ge, ">="),
            CondKind::L => (RBinOp::Lt, "<"),
            CondKind::Le => (RBinOp::Le, "<="),
            _ => unreachable!(),
        };
        rs_binary_text(&a, &b, op, op_text)
    } else if kind.is_overflow() {
        rs_overflow_expr(
            lhs_expr,
            rhs_expr,
            width,
            false,
            matches!(kind, CondKind::Vs),
        )
    } else {
        let a: String = rs_signed_operand(lhs_expr, width);
        let b: String = rs_signed_operand(rhs_expr, width);
        match kind {
            CondKind::E => rs_binary_text(&a, &b, RBinOp::Eq, "=="),
            CondKind::Ne => rs_binary_text(&a, &b, RBinOp::Ne, "!="),
            CondKind::S => {
                let diff: String = rs_sign_truncated_diff(lhs_expr, rhs_expr, width);
                rs_binary_text(&diff, "0", RBinOp::Lt, "<")
            }
            CondKind::Ns => {
                let diff: String = rs_sign_truncated_diff(lhs_expr, rhs_expr, width);
                rs_binary_text(&diff, "0", RBinOp::Ge, ">=")
            }
            _ => unreachable!(),
        }
    }
}

fn rs_sign_truncated_diff(lhs: &str, rhs: &str, width: Width) -> String {
    let a: String = rs_unsigned_operand(lhs, width);
    let b: String = rs_unsigned_operand(rhs, width);
    match (parse_expr(&a), parse_expr(&b)) {
        (Some(l), Some(r)) => {
            let diff: RustExpr = method_call(l, "wrapping_sub", vec![r]);
            render_rust_expr(&rcast(diff, rtype_path(rs_int_ty(width))))
        }
        _ => format!("(({a}).wrapping_sub({b}) as {ity})", ity = rs_int_ty(width)),
    }
}

fn rs_sign_truncated_sum(lhs: &str, rhs: &str, width: Width) -> String {
    let a: String = rs_unsigned_operand(lhs, width);
    let b: String = rs_unsigned_operand(rhs, width);
    match (parse_expr(&a), parse_expr(&b)) {
        (Some(l), Some(r)) => {
            let sum: RustExpr = method_call(l, "wrapping_add", vec![r]);
            render_rust_expr(&rcast(sum, rtype_path(rs_int_ty(width))))
        }
        _ => format!("(({a}).wrapping_add({b}) as {ity})", ity = rs_int_ty(width)),
    }
}

fn rs_overflow_expr(lhs: &str, rhs: &str, width: Width, is_add: bool, set: bool) -> String {
    let uty: &str = rs_uint_ty(width);
    let ity: &str = rs_int_ty(width);
    let a: String = format!("(({lhs}) as {uty})");
    let b: String = format!("(({rhs}) as {uty})");
    let combine: &str = if is_add {
        "wrapping_add"
    } else {
        "wrapping_sub"
    };
    let result: String = format!("({a}.{combine}({b}))");
    let inner: String = if is_add {
        format!("(({a} ^ {result}) & ({b} ^ {result}))")
    } else {
        format!("(({a} ^ {b}) & ({a} ^ {result}))")
    };
    let cmp: &str = if set { "<" } else { ">=" };
    format!("((({inner}) as {ity}) {cmp} 0)")
}

fn rs_add_cond_expr(kind: CondKind, lhs: &str, rhs: &str, width: Width) -> Option<String> {
    if kind.is_overflow() {
        return Some(rs_overflow_expr(
            lhs,
            rhs,
            width,
            true,
            matches!(kind, CondKind::Vs),
        ));
    }
    let sum: String = rs_sign_truncated_sum(lhs, rhs, width);
    let (op, op_text): (RBinOp, &str) = match kind {
        CondKind::E => (RBinOp::Eq, "=="),
        CondKind::Ne => (RBinOp::Ne, "!="),
        CondKind::S => (RBinOp::Lt, "<"),
        CondKind::Ns => (RBinOp::Ge, ">="),
        _ => return None,
    };
    Some(rs_binary_text(&sum, "0", op, op_text))
}

fn rs_if_cond_expr(cond: &Cond, aggregates: &AggregatePlan) -> Option<String> {
    match cond {
        Cond::Leaf { kind, flags } => rs_cond_expr(*kind, flags, aggregates),
        Cond::And(lhs, rhs) => {
            let a: String = rs_if_cond_expr(lhs, aggregates)?;
            let b: String = rs_if_cond_expr(rhs, aggregates)?;
            Some(rs_binary_text(&a, &b, RBinOp::And, "&&"))
        }
        Cond::Or(lhs, rhs) => {
            let a: String = rs_if_cond_expr(lhs, aggregates)?;
            let b: String = rs_if_cond_expr(rhs, aggregates)?;
            Some(rs_binary_text(&a, &b, RBinOp::Or, "||"))
        }
    }
}

#[allow(clippy::option_if_let_else)]
fn rs_cond_expr(kind: CondKind, flags: &Flags, aggregates: &AggregatePlan) -> Option<String> {
    match flags {
        Flags::Cmp { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: &'static str = reg_var(lhs.reg);
            let rhs_expr: String = rs_source_expr(rhs, width, aggregates)?;
            Some(rs_compare_expr(kind, lhs_expr, &rhs_expr, width))
        }
        Flags::Add { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: &'static str = reg_var(lhs.reg);
            let rhs_expr: String = rs_source_expr(rhs, width, aggregates)?;
            rs_add_cond_expr(kind, lhs_expr, &rhs_expr, width)
        }
        Flags::CmpMem { lhs, rhs } => {
            let width: Width = lhs.width;
            let lhs_expr: String = rs_deref_read(lhs, aggregates);
            let rhs_expr: String = rs_source_expr(rhs, width, aggregates)?;
            Some(rs_compare_expr(kind, &lhs_expr, &rhs_expr, width))
        }
        Flags::TestImm { operand, mask } => {
            let width: Width = operand.width;
            let maskval: u64 = (*mask as u64) & ((1u128 << width.bits()) - 1) as u64;
            let unsigned: String = rs_unsigned_operand(reg_var(operand.reg), width);
            let masked: String = match parse_expr(&unsigned) {
                Some(opaque) => render_rust_expr(&binary(
                    RBinOp::BitAnd,
                    opaque,
                    int_hex(u128::from(maskval), "u64"),
                )),
                None => format!("({unsigned} & 0x{maskval:x}u64)"),
            };
            match kind {
                CondKind::E => Some(rs_binary_text(&masked, "0", RBinOp::Eq, "==")),
                CondKind::Ne => Some(rs_binary_text(&masked, "0", RBinOp::Ne, "!=")),
                _ => None,
            }
        }
        Flags::Test { operand } => {
            let width: Width = operand.width;
            let var: String = rs_signed_operand(reg_var(operand.reg), width);
            let expr: String = match kind {
                CondKind::E | CondKind::Be => rs_binary_text(&var, "0", RBinOp::Eq, "=="),
                CondKind::Ne | CondKind::A => rs_binary_text(&var, "0", RBinOp::Ne, "!="),
                CondKind::G => rs_binary_text(&var, "0", RBinOp::Gt, ">"),
                CondKind::Ge | CondKind::Ns => rs_binary_text(&var, "0", RBinOp::Ge, ">="),
                CondKind::L | CondKind::S => rs_binary_text(&var, "0", RBinOp::Lt, "<"),
                CondKind::Le => rs_binary_text(&var, "0", RBinOp::Le, "<="),
                CondKind::Ae | CondKind::Vc => "true".to_owned(),
                CondKind::B | CondKind::Vs => "false".to_owned(),
                CondKind::P | CondKind::Np => {
                    unreachable!("parity has no sound rendering over an integer test")
                }
            };
            Some(expr)
        }
        Flags::Sign { result } => {
            let width: Width = result.width;
            let var: String = rs_signed_operand(reg_var(result.reg), width);
            match kind {
                CondKind::S => Some(rs_binary_text(&var, "0", RBinOp::Lt, "<")),
                CondKind::Ns => Some(rs_binary_text(&var, "0", RBinOp::Ge, ">=")),
                CondKind::E => Some(rs_binary_text(&var, "0", RBinOp::Eq, "==")),
                CondKind::Ne => Some(rs_binary_text(&var, "0", RBinOp::Ne, "!=")),
                _ => None,
            }
        }
        Flags::FpCmp {
            lhs,
            rhs,
            width,
            model,
        } => {
            let a: String = rs_fp_load_xmm(*lhs, *width);
            let b: String = rs_fp_load(rhs, *width, aggregates);
            let same: bool = matches!(rhs, FpOperand::Xmm(operand) if operand == lhs);
            Some(fp_compare_rust(kind, &a, &b, same, *model))
        }
        Flags::Snapshot { var } => {
            let (op, op_text): (RBinOp, &str) = if matches!(kind, CondKind::E) {
                (RBinOp::Eq, "==")
            } else {
                (RBinOp::Ne, "!=")
            };
            Some(rs_binary_text(&sel_var(*var), "0", op, op_text))
        }
        Flags::CondCmp {
            prior,
            precond,
            taken,
            nzcv,
        } => {
            let precond_expr: String = rs_cond_expr(*precond, prior, aggregates)?;
            let taken_expr: String = rs_cond_expr(kind, taken, aggregates)?;
            let else_holds: bool = nzcv_condition_holds(kind, *nzcv);
            Some(format!(
                "(if {precond_expr} {{ {taken_expr} }} else {{ {else_holds} }})"
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn oversized_switch_table_span_is_rejected_before_allocation() {
        let width: u64 = 8;
        let hostile_count: u64 = 0x4000_0000;
        let hostile_span: u64 = width * hostile_count;
        assert!(!table_span_within_section(0, hostile_span, 64));
        assert!(!table_span_within_section(u64::MAX, width, 64));
        assert!(table_span_within_section(0, width * 4, 64));
        assert!(table_span_within_section(16, width * 4, 48));
        assert!(!table_span_within_section(16, width * 4, 47));
    }

    #[test]
    fn lea_add_recovers_two_param_add() {
        let code: [u8; 4] = [0x8d, 0x04, 0x11, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(rec.source.contains("uint64_t recovered"));
        assert!(rec.source.contains("return"));
    }

    #[test]
    fn parse_mem_base_index_scale() {
        let src: Source = parse_mem("[rax+rax*2]").expect("mem");
        assert_eq!(
            src,
            Source::Lea {
                base: Some(Reg::Rax),
                index: Some(IndexOperand::full(Reg::Rax, 2)),
                disp: 0,
            }
        );
    }

    #[test]
    fn no_ret_rejected() {
        let code: [u8; 2] = [0x89, 0xc8];
        let err: Error = recover_leaf_function(&code, 0x1000).expect_err("no ret");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn pointer_load_cluster_lifts_to_width_exact_fields() {
        let code: [u8; 8] = [0x48, 0x8b, 0x01, 0x48, 0x03, 0x41, 0x08, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert!(rec.source.contains("recovered_struct_0_t"));
        assert!(rec.source.contains("recovered_struct_0->field_0"));
        assert!(rec.source.contains("recovered_struct_0->field_8"));
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("struct RecoveredStruct0"));
        assert!(rust.contains("field_0"));
        assert!(rust.contains("field_8"));
    }

    #[test]
    fn dword_load_uses_uint32_deref() {
        let code: [u8; 6] = [0x8b, 0x01, 0x03, 0x41, 0x04, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert_eq!(rec.return_width_bits, 32);
        assert!(rec.source.contains("uint32_t field_0"));
        assert!(rec.source.contains("uint32_t field_4"));
        assert!(rec.source.contains("recovered_struct_0->field_0"));
    }

    #[test]
    fn pointer_store_lifts_to_assignment_through_deref() {
        let code: [u8; 10] = [0x48, 0x89, 0xd0, 0x48, 0x03, 0x01, 0x48, 0x89, 0x01, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(
            rec.source
                .contains("(*(uint64_t*)(uintptr_t)(r_rcx)) = r_rax")
        );
    }

    #[test]
    fn scaled_index_load_lifts_to_array_index() {
        let code: [u8; 5] = [0x48, 0x8b, 0x04, 0xd1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(rec.source.contains("recovered_array_0[r_rdx]"));
        assert!(rec.source.contains("typedef uint64_t recovered_array_0_t;"));
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("type RecoveredArray0 = u64;"));
        assert!(rust.contains("recovered_array_0.wrapping_add(r_rdx as usize)"));
    }

    #[test]
    fn nested_pointer_cluster_lifts_to_linked_struct_types() {
        let code: [u8; 15] = [
            0x48, 0x8b, 0x11, 0x48, 0x8b, 0x42, 0x08, 0x48, 0x03, 0x02, 0x48, 0x03, 0x41, 0x08,
            0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert!(rec.source.contains("recovered_struct_1_t *field_0"));
        assert!(rec.source.contains("recovered_struct_1_t"));
        assert!(rec.source.contains("recovered_struct_0->field_0"));
        assert!(
            rec.source
                .contains("((recovered_struct_1_t *)(uintptr_t)r_rdx)->field_0")
        );
        assert!(
            rec.source
                .contains("((recovered_struct_1_t *)(uintptr_t)r_rdx)->field_8")
        );
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("*mut RecoveredStruct1"));
        assert!(rust.contains("struct RecoveredStruct1"));
    }

    #[test]
    fn nested_scaled_access_lifts_to_a_linked_array_type() {
        let code: [u8; 12] = [
            0x4c, 0x8b, 0x01, 0x49, 0x8b, 0x04, 0xd0, 0x48, 0x03, 0x41, 0x08, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert!(rec.source.contains("recovered_array_1_t *field_0"));
        assert!(
            rec.source
                .contains("((recovered_array_1_t *)(uintptr_t)r_r8)[r_rdx]")
        );
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("*mut RecoveredArray1"));
        assert!(rust.contains("wrapping_add(r_rdx as usize)"));
    }

    #[test]
    fn coincident_integer_accesses_lift_to_a_union() {
        let code: [u8; 8] = [0x8b, 0x01, 0x0f, 0xb7, 0x11, 0x48, 0x01, 0xd0];
        let mut terminated: Vec<u8> = code.to_vec();
        terminated.push(0xc3);
        let rec: LeafRecovery = recover_leaf_function(&terminated, 0x1000).expect("recover");
        assert!(rec.source.contains("typedef union"));
        assert!(rec.source.contains("recovered_union_0_t"));
        assert!(rec.source.contains("field_0_u32"));
        assert!(rec.source.contains("field_0_u16"));
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("union RecoveredUnion0"));
        assert!(rust.contains("field_0_u32"));
        assert!(rust.contains("field_0_u16"));
    }

    #[test]
    fn coincident_integer_and_float_accesses_lift_to_a_union() {
        let code: [u8; 16] = [
            0xf3, 0x0f, 0x10, 0x01, 0x8b, 0x01, 0xf3, 0x0f, 0x2a, 0xc8, 0xf3, 0x0f, 0x58, 0xc1,
            0xc3, 0x90,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code[..15], 0x1000).expect("recover");
        assert!(rec.source.contains("typedef union"));
        assert!(rec.source.contains("field_0_u32"));
        assert!(rec.source.contains("field_0_f32"));
        assert!(rec.source.contains("recovered_union_0->field_0_f32"));
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("union RecoveredUnion0"));
        assert!(rust.contains("field_0_f32"));
    }

    #[test]
    fn coincident_integer_load_and_float_store_lift_to_a_union() {
        let code: [u8; 11] = [
            0x8b, 0x01, 0x66, 0x0f, 0x6e, 0xc0, 0xf3, 0x0f, 0x11, 0x01, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert!(rec.source.contains("recovered_union_0_t"));
        assert!(rec.source.contains("field_0_u32"));
        assert!(rec.source.contains("field_0_f32 ="));
        let rust: &str = rec.rust_source.as_deref().expect("rust output");
        assert!(rust.contains("union RecoveredUnion0"));
        assert!(rust.contains("addr_of_mut!") && rust.contains(".field_0_f32"));
        assert!(rust.contains("core::ptr::write_unaligned"));
    }

    #[test]
    fn shifted_partial_overlap_keeps_raw_accesses() {
        let code: [u8; 10] = [0x48, 0x8b, 0x01, 0x8b, 0x51, 0x04, 0x48, 0x01, 0xd0, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x1000).expect("recover");
        assert!(!rec.source.contains("recovered_struct_"));
        assert!(!rec.source.contains("recovered_union_"));
        assert!(rec.source.contains("(*(uint64_t*)(uintptr_t)(r_rcx))"));
        assert!(
            rec.source
                .contains("(*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)4LL))")
        );
    }

    #[test]
    fn aggregate_classifier_distinguishes_unions_from_rejected_shapes() {
        let conflicting: [MemRef; 2] = [
            MemRef {
                base: Some(Reg::Rcx),
                index: None,
                disp: 0,
                width: Width::W64,
            },
            MemRef {
                base: Some(Reg::Rcx),
                index: None,
                disp: 0,
                width: Width::W32,
            },
        ];
        let conflicting: Vec<AggregateObservation> = conflicting
            .into_iter()
            .map(|mem: MemRef| AggregateObservation {
                mem,
                scalar: AggregateScalar::Integer(mem.width),
            })
            .collect();
        assert!(matches!(
            aggregate_classify_root(Reg::Rcx, &conflicting),
            Some(AggregateShape::Union { .. })
        ));

        let same_type: [AggregateObservation; 2] = [AggregateObservation {
            mem: MemRef {
                base: Some(Reg::Rcx),
                index: None,
                disp: 0,
                width: Width::W32,
            },
            scalar: AggregateScalar::Integer(Width::W32),
        }; 2];
        assert!(aggregate_classify_root(Reg::Rcx, &same_type).is_none());

        let mixed_union_and_tail: [AggregateObservation; 3] = [
            conflicting[0],
            conflicting[1],
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp: 8,
                    width: Width::W32,
                },
                scalar: AggregateScalar::Integer(Width::W32),
            },
        ];
        assert!(aggregate_classify_root(Reg::Rcx, &mixed_union_and_tail).is_none());

        let mismatched_scalar: [AggregateObservation; 2] = [
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp: 0,
                    width: Width::W32,
                },
                scalar: AggregateScalar::Integer(Width::W32),
            },
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp: 0,
                    width: Width::W32,
                },
                scalar: AggregateScalar::Float(FpWidth::F64),
            },
        ];
        assert!(aggregate_classify_root(Reg::Rcx, &mismatched_scalar).is_none());

        let mismatched_array: [AggregateObservation; 1] = [AggregateObservation {
            mem: MemRef {
                base: Some(Reg::Rcx),
                index: Some(IndexOperand::full(Reg::Rdx, 4)),
                disp: 0,
                width: Width::W64,
            },
            scalar: AggregateScalar::Integer(Width::W64),
        }];
        assert!(aggregate_classify_root(Reg::Rcx, &mismatched_array).is_none());

        let root_reused_as_index: [AggregateObservation; 3] = [
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp: 0,
                    width: Width::W64,
                },
                scalar: AggregateScalar::Integer(Width::W64),
            },
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp: 8,
                    width: Width::W64,
                },
                scalar: AggregateScalar::Integer(Width::W64),
            },
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rdx),
                    index: Some(IndexOperand::full(Reg::Rcx, 8)),
                    disp: 0,
                    width: Width::W64,
                },
                scalar: AggregateScalar::Integer(Width::W64),
            },
        ];
        assert!(aggregate_classify_root(Reg::Rcx, &root_reused_as_index).is_none());

        let mut too_many_fields: Vec<AggregateObservation> = Vec::new();
        for field in 0..=AGGREGATE_MAX_FIELDS {
            let disp: i64 = i64::try_from(field)
                .expect("field index")
                .checked_mul(8)
                .expect("field displacement");
            too_many_fields.push(AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: None,
                    disp,
                    width: Width::W64,
                },
                scalar: AggregateScalar::Integer(Width::W64),
            });
        }
        assert!(aggregate_classify_root(Reg::Rcx, &too_many_fields).is_none());

        let too_many_observations: Vec<AggregateObservation> = vec![
            AggregateObservation {
                mem: MemRef {
                    base: Some(Reg::Rcx),
                    index: Some(IndexOperand::full(Reg::Rdx, 8)),
                    disp: 0,
                    width: Width::W64,
                },
                scalar: AggregateScalar::Integer(Width::W64),
            };
            AGGREGATE_MAX_ROOT_OBSERVATIONS
                + 1
        ];
        assert!(aggregate_classify_root(Reg::Rcx, &too_many_observations).is_none());
    }

    #[test]
    fn parse_mem_access_infers_register_width() {
        let mem: MemRef = parse_mem_access("[rcx+8]", Some(Width::W64)).expect("mem");
        assert_eq!(
            mem,
            MemRef {
                base: Some(Reg::Rcx),
                index: None,
                disp: 8,
                width: Width::W64,
            }
        );
    }

    #[test]
    fn parse_mem_access_honors_size_keyword() {
        let mem: MemRef = parse_mem_access("dword [rax]", None).expect("mem");
        assert_eq!(mem.width, Width::W32);
        assert_eq!(mem.base, Some(Reg::Rax));
    }

    #[test]
    fn cond_kind_negation_is_an_involution() {
        for kind in [
            CondKind::E,
            CondKind::Ne,
            CondKind::G,
            CondKind::Ge,
            CondKind::L,
            CondKind::Le,
            CondKind::A,
            CondKind::Ae,
            CondKind::B,
            CondKind::Be,
            CondKind::S,
            CondKind::Ns,
            CondKind::Vs,
            CondKind::Vc,
            CondKind::P,
            CondKind::Np,
        ] {
            assert_eq!(kind.negate().negate(), kind);
            assert_ne!(kind.negate(), kind);
        }
    }

    #[test]
    fn forward_jcc_skip_recovers_negated_if_guard() {
        let code: [u8; 14] = [
            0x48, 0x8d, 0x04, 0x11, 0x48, 0x39, 0xd1, 0x7e, 0x04, 0x48, 0x83, 0xc0, 0x0a, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x2000).expect("recover");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(
            rec.source.contains("if ("),
            "expected a structured if: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("if ((int64_t)(int64_t)(r_rcx) > (int64_t)(int64_t)(r_rdx))"),
            "jle skip must invert to a signed-greater guard: {}",
            rec.source
        );
        assert!(
            !rec.source.contains("<="),
            "must not emit the un-negated jle predicate: {}",
            rec.source
        );
    }

    #[test]
    fn nested_forward_skips_nest_the_if_blocks() {
        let code: [u8; 24] = [
            0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc9, 0x7e, 0x0d, 0x48, 0x8d, 0x04, 0x11,
            0x48, 0x85, 0xd2, 0x7e, 0x04, 0x48, 0x83, 0xc0, 0x64, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x3000).expect("recover");
        let opens: usize = rec.source.matches("if (").count();
        assert_eq!(opens, 2, "two nested guards expected: {}", rec.source);
        let outer: usize = rec.source.find("if (").expect("outer if");
        let inner: usize = rec.source[outer + 4..]
            .find("if (")
            .map(|p: usize| p + outer + 4)
            .expect("inner if");
        let inner_indent: &str = &rec.source[..inner];
        assert!(
            inner_indent
                .lines()
                .last()
                .is_some_and(|l: &str| l.starts_with("        ")),
            "inner if must be indented under the outer block: {}",
            rec.source
        );
    }

    #[test]
    fn single_back_edge_reconstructs_do_while_loop() {
        let code: [u8; 7] = [0x48, 0x83, 0xc0, 0x01, 0x75, 0xfa, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x4000).expect("do-while loop");
        assert!(
            rec.lifted_loop,
            "single back-edge must structure as a loop: {}",
            rec.source
        );
        assert!(
            rec.source.contains("do {"),
            "expected a do-while body: {}",
            rec.source
        );
        assert!(
            rec.source.contains("} while ("),
            "expected a do-while back-edge condition: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("} while ((int64_t)(int64_t)(r_rax) != 0);"),
            "the jne back-edge over `add rax,1` must invert to a not-equal-zero guard: {}",
            rec.source
        );
    }

    #[test]
    fn forward_jump_with_backward_branch_is_rejected() {
        let code: [u8; 8] = [0x48, 0x83, 0xc0, 0x01, 0x75, 0xfb, 0xeb, 0xf9];
        let err: Error = recover_leaf_function(&code, 0x4000)
            .expect_err("a trailing jmp with no terminal ret is out of class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn bytes_after_first_ret_are_truncated_as_unreachable() {
        let code: [u8; 8] = [0x48, 0x89, 0xc8, 0xc3, 0x90, 0x48, 0xff, 0xc0];
        let rec: LeafRecovery =
            recover_leaf_function(&code, 0x5000).expect("trailing padding must not abort");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert!(!rec.source.contains("if ("));
    }

    #[test]
    fn forward_branch_over_the_exit_is_rejected() {
        let code: [u8; 9] = [0x48, 0x85, 0xc9, 0x7e, 0x02, 0xc3, 0x48, 0xff, 0xc0];
        let err: Error = recover_leaf_function(&code, 0x6000)
            .expect_err("branch past the single exit is out of class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn out_of_line_tail_return_idiom_reconstructs_single_return_if_else() {
        let code: [u8; 20] = [
            0x48, 0x85, 0xc9, 0x7f, 0x08, 0x48, 0x89, 0xc8, 0x48, 0xc1, 0xf8, 0x3f, 0xc3, 0xb8,
            0x01, 0x00, 0x00, 0x00, 0xeb, 0xf8,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x7000).expect("sign idiom");
        assert!(
            rec.lifted_split_return,
            "must take the out-of-line tail-return path: {}",
            rec.source
        );
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(
            rec.source.matches("return ").count(),
            1,
            "the three-exit source must collapse to a single return: {}",
            rec.source
        );
        assert!(
            rec.source.contains("} else {"),
            "fallthrough vs out-of-line block must become an if/else: {}",
            rec.source
        );
    }

    #[test]
    fn out_of_line_block_with_head_statement_keeps_prefix_before_if() {
        let code: [u8; 17] = [
            0x48, 0x8d, 0x04, 0x11, 0x48, 0x39, 0xd1, 0x74, 0x01, 0xc3, 0xb8, 0xad, 0xde, 0x00,
            0x00, 0xeb, 0xf8,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x8000).expect("orconst idiom");
        assert!(rec.lifted_split_return, "split-return path: {}", rec.source);
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        let head_pos: usize = rec.source.find("r_rax =").expect("head assign");
        let if_pos: usize = rec.source.find("if (").expect("guard if");
        assert!(
            head_pos < if_pos,
            "the precomputed head value must be emitted before the guard: {}",
            rec.source
        );
    }

    #[test]
    fn top_guarded_while_reconstructs_guard_wrapping_a_do_while() {
        let code: [u8; 0x17] = [
            0x48, 0x89, 0xc8, 0x48, 0x85, 0xc9, 0x74, 0x0e, 0xba, 0x00, 0x00, 0x00, 0x00, 0x48,
            0x83, 0xc2, 0x01, 0x48, 0x39, 0xd0, 0x75, 0xf7, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x4b).expect("guarded while");
        assert!(
            rec.lifted_loop,
            "top-guarded while must structure as a loop: {}",
            rec.source
        );
        let if_pos: usize = rec.source.find("if (").expect("guard if");
        let do_pos: usize = rec.source.find("do {").expect("inner do-while");
        assert!(
            if_pos < do_pos,
            "the zero-trip guard must wrap the do-while body: {}",
            rec.source
        );
        assert!(
            rec.source.contains("} while ("),
            "expected a do-while back-edge condition: {}",
            rec.source
        );
        assert_eq!(
            rec.source.matches("do {").count(),
            1,
            "exactly one loop reconstructed: {}",
            rec.source
        );
    }

    #[test]
    fn movzx_reg_zero_extends_subregister() {
        let code: [u8; 4] = [0x0f, 0xb7, 0xc1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x9000).expect("movzx");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(rec.return_width_bits, 32);
        assert!(
            rec.source
                .contains("r_rax = ((uint32_t)(uint16_t)((r_rcx) & 0xffffULL)) & 0xffffffffULL"),
            "movzx eax,cx must zero-extend the low 16 bits of rcx into rax: {}",
            rec.source
        );
    }

    #[test]
    fn movsx_reg_sign_extends_to_full_width() {
        let code: [u8; 5] = [0x48, 0x0f, 0xbe, 0xc9, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x9100).expect("movsx");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(rec.return_width_bits, 64);
        assert!(
            rec.source
                .contains("r_rcx = (uint64_t)(int64_t)(int8_t)((r_rcx) & 0xffULL)"),
            "movsx rcx,cl must sign-extend the low byte: {}",
            rec.source
        );
    }

    #[test]
    fn movsxd_reg_sign_extends_dword() {
        let code: [u8; 4] = [0x48, 0x63, 0xc1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x9200).expect("movsxd");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert!(
            rec.source
                .contains("r_rax = (uint64_t)(int64_t)(int32_t)((r_rcx) & 0xffffffffULL)"),
            "movsxd rax,ecx must sign-extend the low dword: {}",
            rec.source
        );
    }

    #[test]
    fn cdqe_sign_extends_eax_into_rax() {
        let code: [u8; 3] = [0x48, 0x98, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x9300).expect("cdqe");
        assert!(
            rec.source
                .contains("r_rax = (uint64_t)(int64_t)(int32_t)((r_rax) & 0xffffffffULL)"),
            "cdqe must sign-extend eax into rax: {}",
            rec.source
        );
    }

    #[test]
    fn movzx_mem_zero_extends_byte_load() {
        let code: [u8; 4] = [0x0f, 0xb6, 0x01, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x9400).expect("movzx mem");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert!(
            rec.source.contains("(*(uint8_t*)(uintptr_t)(r_rcx))"),
            "byte load must deref through uint8_t: {}",
            rec.source
        );
        assert!(
            rec.source.contains("(uint32_t)(uint8_t)"),
            "movzx must zero-extend the byte: {}",
            rec.source
        );
    }

    #[test]
    fn width_extension_to_narrower_or_equal_is_rejected() {
        assert!(lift_width_extension("movzx", "ax,eax").is_none());
        assert!(lift_width_extension("movsx", "al,al").is_none());
        assert!(lift_width_extension("cdqe", "rax,eax").is_none());
        assert!(lift_width_extension("mov", "eax,ecx").is_none());
    }

    #[test]
    fn nearmiss_ordering_cmov_is_sound_rejected() {
        let code: [u8; 13] = [
            0x48, 0x89, 0xc8, 0x48, 0x29, 0xd1, 0x48, 0x39, 0xd0, 0x48, 0x0f, 0x4c, 0xc1,
        ];
        let mut full: Vec<u8> = code.to_vec();
        full.push(0xc3);
        let result: Result<LeafRecovery> = recover_leaf_function(&full, 0x9500);
        assert!(
            result.is_err(),
            "gcc 14/15 near-miss ordering cmov `(a>=b)?a:(a-b)` must sound-reject, not emit a wrong select: {:?}",
            result.map(|r: LeafRecovery| r.source)
        );
    }

    #[test]
    fn nearmiss_clobbered_compare_operand_snapshots_before_the_write() {
        let code: [u8; 19] = [
            0x48, 0x89, 0xc8, 0x48, 0x39, 0xd1, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x0f, 0x4d,
            0xd1, 0x48, 0x29, 0xd0, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function(&code, 0x9800).expect("gcc-16 near-miss must recover");
        let snapshot: usize = rec
            .source
            .find("sel_cc_0 = (")
            .expect("compare must be snapshotted");
        let clobber: usize = rec
            .source
            .find("r_rcx = (")
            .expect("the zeroing write must be present");
        assert!(
            snapshot < clobber,
            "the compare must be captured before rcx is clobbered: {}",
            rec.source
        );
        assert!(
            rec.source.contains(">="),
            "the ge compare must be preserved: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rdx = sel_cc_0 != 0 ? r_rcx : r_rdx"),
            "the cmovge must consume the snapshot: {}",
            rec.source
        );
    }

    #[test]
    fn branchless_cqo_abs_is_sound_rejected() {
        let absdiff: [u8; 13] = [
            0x48, 0x89, 0xc8, 0x48, 0x29, 0xd0, 0x48, 0x99, 0x48, 0x31, 0xd0, 0x48, 0x29,
        ];
        let mut absdiff_full: Vec<u8> = absdiff.to_vec();
        absdiff_full.extend_from_slice(&[0xd0, 0xc3]);
        assert!(
            recover_leaf_function(&absdiff_full, 0x9600).is_err(),
            "gcc 14/15 branchless cqo abs must not be silently mis-recovered with a stale rdx"
        );
        let abs64: [u8; 10] = [0x48, 0x89, 0xc8, 0x48, 0x99, 0x48, 0x31, 0xd0, 0x48, 0x29];
        let mut abs64_full: Vec<u8> = abs64.to_vec();
        abs64_full.extend_from_slice(&[0xd0, 0xc3]);
        assert!(
            recover_leaf_function(&abs64_full, 0x9700).is_err(),
            "gcc 14/15 branchless cqo abs64 must not be silently mis-recovered with a stale rdx"
        );
    }

    #[test]
    fn ternary_imul_lifts_to_source_times_constant() {
        let code: [u8; 5] = [0x48, 0x6b, 0xc7, 0x64, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x9500, Abi::SysV).expect("imul3");
        assert_eq!(rec.params, vec![Reg::Rdi]);
        assert!(
            rec.source
                .contains("r_rax = r_rdi * (uint64_t)(int64_t)100LL"),
            "imul rax,rdi,0x64 must lift to rdi * 100: {}",
            rec.source
        );
    }

    #[test]
    fn wide_mul_lifts_to_unsigned_128_bit_product_pair() {
        let code: [u8; 4] = [0x48, 0xf7, 0xe1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x9600, Abi::SysV).expect("mul");
        assert!(
            rec.source.contains(
                "unsigned __int128 wide_prod = (unsigned __int128)r_rax * (unsigned __int128)r_rcx"
            ),
            "mul rcx must form a 128-bit product from rax*rcx: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rax = (uint64_t)wide_prod;")
                && rec.source.contains("r_rdx = (uint64_t)(wide_prod >> 64);"),
            "mul must split the product into rax (low) and rdx (high): {}",
            rec.source
        );
    }

    #[test]
    fn shld_lifts_to_double_precision_left_shift() {
        let code: [u8; 6] = [0x48, 0x0f, 0xa4, 0xc2, 0x3f, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x9700, Abi::SysV).expect("shld");
        assert!(
            rec.source.contains("r_rdx = r_rdx << 63 | r_rax >> 1;"),
            "shld rdx,rax,0x3f must widen to (rdx<<63)|(rax>>1): {}",
            rec.source
        );
    }

    #[test]
    fn shrd_lifts_to_double_precision_right_shift() {
        let code: [u8; 6] = [0x48, 0x0f, 0xac, 0xd0, 0x01, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x9800, Abi::SysV).expect("shrd");
        assert!(
            rec.source.contains("r_rax = r_rax >> 1 | r_rdx << 63;"),
            "shrd rax,rdx,1 must widen to (rax>>1)|(rdx<<63): {}",
            rec.source
        );
    }

    #[test]
    fn out_of_range_double_shift_is_rejected() {
        assert!(lift_double_shift("shld", "rdx,rax,0").is_none());
        assert!(lift_double_shift("shld", "rdx,rax,64").is_none());
        assert!(lift_double_shift("shrd", "eax,edx,3").is_none());
        assert!(lift_double_shift("shld", "rdx,rax").is_none());
    }

    #[test]
    fn call_to_same_object_helper_lifts_to_c_call_and_skips_frame() {
        let code: [u8; 18] = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xef, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 0x01, 0x48,
            0x83, 0xc4, 0x28, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x8).expect("call recover");
        assert_eq!(rec.call_targets, vec![0x0]);
        assert!(
            rec.source.contains("extern uint64_t sub_0("),
            "the helper must be forward-declared with a synthetic sub_<va> name: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rax = sub_0(r_rcx, r_rdx, r_r8, r_r9);"),
            "with no callee facts the call soundly over-approximates all ABI argument registers: {}",
            rec.source
        );
        assert!(
            !rec.source.contains("rsp"),
            "the stack-frame adjust must be skipped, not emitted: {}",
            rec.source
        );
    }

    #[test]
    fn resolved_call_uses_symbol_name_and_callee_arity() {
        let code: [u8; 18] = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xef, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 0x01, 0x48,
            0x83, 0xc4, 0x28, 0xc3,
        ];
        let calls: [ResolvedCall; 1] = [ResolvedCall {
            target: 0x0,
            name: Some("helper".to_owned()),
            arg_count: 1,
        }];
        let rec: LeafRecovery = recover_leaf_function_with_calls(&code, 0x8, Abi::MsX64, &calls)
            .expect("resolved call recover");
        assert!(
            rec.source.contains("extern uint64_t helper(uint64_t);"),
            "a resolved single-argument callee must be declared by symbol name with one arg: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rax = helper(r_rcx);"),
            "the call must pass exactly the callee's live-in argument prefix: {}",
            rec.source
        );
        assert_eq!(
            rec.params,
            vec![Reg::Rcx],
            "the forwarded first argument register must be recovered as the caller's sole parameter"
        );
    }

    #[test]
    fn resolved_zero_arg_call_declares_void() {
        let code: [u8; 18] = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xef, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 0x01, 0x48,
            0x83, 0xc4, 0x28, 0xc3,
        ];
        let calls: [ResolvedCall; 1] = [ResolvedCall {
            target: 0x0,
            name: None,
            arg_count: 0,
        }];
        let rec: LeafRecovery = recover_leaf_function_with_calls(&code, 0x8, Abi::MsX64, &calls)
            .expect("resolved zero-arg call recover");
        assert!(
            rec.source.contains("extern uint64_t sub_0(void);"),
            "a resolved zero-argument callee must be declared (void): {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rax = sub_0();"),
            "a zero-argument call must be emitted with no operands: {}",
            rec.source
        );
        assert!(
            rec.params.is_empty(),
            "a caller that sets no argument registers has no parameters: {:?}",
            rec.params
        );
    }

    #[test]
    fn resolved_call_emits_rust_extern_and_unsafe_call() {
        let code: [u8; 18] = [
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xef, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 0x01, 0x48,
            0x83, 0xc4, 0x28, 0xc3,
        ];
        let calls: [ResolvedCall; 1] = [ResolvedCall {
            target: 0x0,
            name: Some("helper".to_owned()),
            arg_count: 1,
        }];
        let rec: LeafRecovery = recover_leaf_function_with_calls(&code, 0x8, Abi::MsX64, &calls)
            .expect("resolved call recover");
        let rust: String = rec
            .rust_source
            .expect("a frameless integer call caller must be rust-emittable");
        assert!(
            rust.contains("extern \"C\" {") && rust.contains("fn helper(a0: u64) -> u64;"),
            "rust output must forward-declare the callee as extern \"C\": {rust}"
        );
        assert!(
            rust.contains("r_rax = unsafe { helper(r_rcx) };"),
            "rust output must emit the call inside an unsafe block: {rust}"
        );
    }

    #[test]
    fn callee_saved_save_across_call_is_a_plain_move() {
        let code: [u8; 14] = [
            0x53, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x89, 0xc3, 0xe8, 0xe3, 0xff, 0xff, 0xff, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function(&code, 0x10).expect("save-arg recover");
        assert_eq!(rec.call_targets, vec![0x0]);
        assert!(
            rec.source.contains("r_rbx = r_r8"),
            "the cross-call argument save must lift to a register copy: {}",
            rec.source
        );
        assert!(
            !rec.source.contains("push") && !rec.source.contains("rsp"),
            "push/sub-rsp frame management must be skipped: {}",
            rec.source
        );
    }

    #[test]
    fn frame_management_classifies_rsp_adjust_and_register_save() {
        assert!(is_frame_management("sub", "rsp,28h"));
        assert!(is_frame_management("add", "rsp,20h"));
        assert!(is_frame_management("push", "rbx"));
        assert!(is_frame_management("pop", "rbx"));
        assert!(!is_frame_management("sub", "rax,8"));
        assert!(!is_frame_management("push", "1"));
        assert!(!is_frame_management("mov", "rbx,r8"));
    }

    #[test]
    fn parse_branch_target_reads_iced_branch_size_qualifiers() {
        assert_eq!(parse_branch_target("short 0000000000001011h"), Some(0x1011));
        assert_eq!(parse_branch_target("near 0000000000001011h"), Some(0x1011));
        assert_eq!(parse_branch_target("0000000000002000h"), Some(0x2000));
        assert_eq!(parse_branch_target("rax"), None);
        assert_eq!(parse_branch_target("qword [rax]"), None);
        assert_eq!(parse_branch_target("near rax"), None);
        assert_eq!(parse_branch_target("near qword [rax]"), None);
    }

    const JT6_SYSV: [u8; 0x6f] = [
        0x48, 0x83, 0xff, 0x05, 0x77, 0x59, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x63,
        0x0c, 0xb8, 0x48, 0x01, 0xc1, 0xff, 0xe1, 0x48, 0x01, 0xf2, 0x48, 0x8d, 0x04, 0x55, 0x01,
        0x00, 0x00, 0x00, 0xc3, 0x48, 0x09, 0xf2, 0x48, 0x8d, 0x04, 0x55, 0x01, 0x00, 0x00, 0x00,
        0xc3, 0x48, 0x0f, 0xaf, 0xd6, 0x48, 0x8d, 0x04, 0x55, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x48,
        0x31, 0xf2, 0x48, 0x8d, 0x04, 0x55, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x48, 0x29, 0xd6, 0x48,
        0x8d, 0x04, 0x75, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x48, 0x21, 0xf2, 0x48, 0x8d, 0x04, 0x55,
        0x01, 0x00, 0x00, 0x00, 0xc3, 0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x04,
        0x55, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ];

    fn jt6_table() -> Vec<JumpTable> {
        vec![JumpTable {
            table_va: 0xd,
            entries: vec![0x9, 0x3a, 0x21, 0x2e, 0x15, 0x46],
        }]
    }

    #[test]
    fn dense_jump_table_reconstructs_six_case_switch() {
        let rec: LeafRecovery =
            recover_leaf_function_switch_abi(&JT6_SYSV, 0, Abi::SysV, &jt6_table())
                .expect("dense switch");
        assert!(
            rec.lifted_switch,
            "must flag a lifted switch: {}",
            rec.source
        );
        assert_eq!(rec.params, vec![Reg::Rdi, Reg::Rsi, Reg::Rdx]);
        assert!(
            rec.source.contains("switch (r_rdi)"),
            "must switch on the discriminant register: {}",
            rec.source
        );
        for value in 0..=5 {
            assert!(
                rec.source.contains(&format!("case {value}: {{")),
                "expected case {value}: {}",
                rec.source
            );
        }
        assert!(
            rec.source.contains("default: {"),
            "must carry the out-of-range default: {}",
            rec.source
        );
        assert_eq!(
            rec.source.matches("case ").count(),
            6,
            "exactly six dense cases: {}",
            rec.source
        );
    }

    #[test]
    fn dense_switch_rejects_missing_table() {
        let err: Error = recover_leaf_function_switch_abi(&JT6_SYSV, 0, Abi::SysV, &[])
            .expect_err("no table supplied");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn dense_switch_rejects_wrong_entry_count() {
        let short: Vec<JumpTable> = vec![JumpTable {
            table_va: 0xd,
            entries: vec![0x9, 0x3a, 0x21],
        }];
        let err: Error = recover_leaf_function_switch_abi(&JT6_SYSV, 0, Abi::SysV, &short)
            .expect_err("entry-count mismatch");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn dense_switch_rejects_non_switch_leaf() {
        let code: [u8; 4] = [0x8d, 0x04, 0x11, 0xc3];
        let err: Error = recover_leaf_function_switch_abi(&code, 0x1000, Abi::MsX64, &[])
            .expect_err("plain leaf has no dispatch");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn nested_do_while_reconstructs_two_structured_while_loops() {
        let nl_sum: [u8; 0x2c] = [
            0x41, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x89,
            0xc8, 0x49, 0x01, 0xc0, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x39, 0xd0, 0x75, 0xf4, 0x49,
            0x83, 0xc1, 0x01, 0x48, 0x83, 0xc2, 0x01, 0x49, 0x39, 0xc9, 0x75, 0xe4, 0x4c, 0x89,
            0xc0, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&nl_sum, 0, Abi::SysV).expect("nested do-while");
        assert!(
            rec.lifted_loop,
            "two back-edges must structure as loops: {}",
            rec.source
        );
        let outer: usize = rec.source.find("while (1) {").expect("outer while");
        let inner: usize = rec.source[outer + "while (1) {".len()..]
            .find("while (1) {")
            .map(|p: usize| p + outer + "while (1) {".len())
            .expect("inner while nested under the outer");
        let outer_line_indent: &str = rec.source[..outer].lines().last().unwrap_or_default();
        let inner_line_indent: &str = rec.source[..inner].lines().last().unwrap_or_default();
        assert!(
            inner_line_indent.len() > outer_line_indent.len(),
            "the inner loop must be indented inside the outer body: {}",
            rec.source
        );
        assert_eq!(
            rec.source.matches("while (1) {").count(),
            2,
            "exactly two loops for a doubly-nested do-while: {}",
            rec.source
        );
    }

    #[test]
    fn triply_nested_do_while_reconstructs_three_structured_loops() {
        let t3: [u8; 77] = [
            0x56, 0x53, 0x49, 0x89, 0xd3, 0x4c, 0x89, 0xc3, 0x49, 0x89, 0xca, 0x48, 0x8d, 0x34,
            0xd1, 0xba, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x01, 0xc3, 0x4d, 0x8b, 0x02, 0x49, 0x8d,
            0x0c, 0x18, 0x4f, 0x8d, 0x0c, 0x03, 0x4c, 0x89, 0xc0, 0x48, 0x01, 0xc2, 0x48, 0x83,
            0xc0, 0x01, 0x48, 0x39, 0xc8, 0x75, 0xf4, 0x49, 0x83, 0xc0, 0x01, 0x48, 0x83, 0xc1,
            0x01, 0x4c, 0x39, 0xc9, 0x75, 0xe4, 0x49, 0x83, 0xc2, 0x08, 0x49, 0x39, 0xf2, 0x75,
            0xd0, 0x48, 0x89, 0xd0, 0x5b, 0x5e, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&t3, 0, Abi::SysV).expect("triple nested do-while");
        assert!(rec.lifted_loop, "three back-edges must structure as loops");
        assert_eq!(
            rec.source.matches("while (1) {").count(),
            3,
            "the interval structurer generalizes past double nesting: {}",
            rec.source
        );
    }

    #[test]
    fn overlapping_back_edges_are_rejected_as_irreducible() {
        let items: Vec<Item> = vec![
            Item {
                address: 0,
                kind: ItemKind::Stmt(Stmt::Assign {
                    dest: RegRef {
                        reg: Reg::Rax,
                        width: Width::W64,
                    },
                    src: Source::Imm(0),
                }),
            },
            Item {
                address: 1,
                kind: ItemKind::Branch {
                    kind: CondKind::E,
                    flags: Flags::Test {
                        operand: RegRef {
                            reg: Reg::Rcx,
                            width: Width::W64,
                        },
                    },
                    target: 3,
                },
            },
            Item {
                address: 2,
                kind: ItemKind::Branch {
                    kind: CondKind::E,
                    flags: Flags::Test {
                        operand: RegRef {
                            reg: Reg::Rcx,
                            width: Width::W64,
                        },
                    },
                    target: 1,
                },
            },
            Item {
                address: 3,
                kind: ItemKind::Branch {
                    kind: CondKind::E,
                    flags: Flags::Test {
                        operand: RegRef {
                            reg: Reg::Rcx,
                            width: Width::W64,
                        },
                    },
                    target: 2,
                },
            },
            Item {
                address: 4,
                kind: ItemKind::Ret,
            },
        ];
        let out: Option<Block> = structure_reducible_cfg(&items).expect("no hard error");
        assert!(
            out.is_none(),
            "an irreducible two-entry cycle must be soundly rejected, not misstructured"
        );
    }

    fn body_has(body: &Block, want: &dyn Fn(&Node) -> bool) -> bool {
        body.iter().any(|node: &Node| {
            want(node)
                || match node {
                    Node::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        body_has(then_body, want)
                            || else_body
                                .as_ref()
                                .is_some_and(|b: &Block| body_has(b, want))
                    }
                    Node::While { body, .. } | Node::DoWhile { body, .. } => body_has(body, want),
                    Node::Switch { cases, default, .. } => {
                        cases.iter().any(|c: &SwitchCase| body_has(&c.body, want))
                            || body_has(default, want)
                    }
                    _ => false,
                }
        })
    }

    #[test]
    fn two_entry_irreducible_scc_structures_without_goto_via_cns() {
        let guard = |reg: Reg| -> Flags {
            Flags::Test {
                operand: RegRef {
                    reg,
                    width: Width::W64,
                },
            }
        };
        let blocks: Vec<CfgBlock> = vec![
            CfgBlock {
                stmts: Vec::new(),
                term: BlockTerm::Branch {
                    kind: CondKind::E,
                    flags: guard(Reg::Rcx),
                    taken: 1,
                    fallthrough: 2,
                },
            },
            CfgBlock {
                stmts: Vec::new(),
                term: BlockTerm::Jump(2),
            },
            CfgBlock {
                stmts: Vec::new(),
                term: BlockTerm::Branch {
                    kind: CondKind::E,
                    flags: guard(Reg::Rcx),
                    taken: 1,
                    fallthrough: 3,
                },
            },
            CfgBlock {
                stmts: Vec::new(),
                term: BlockTerm::Ret,
            },
        ];
        let cfg: structuring::Cfg = cfg_from_leaf_blocks(&blocks).expect("well-formed block cfg");
        assert!(
            structuring::loop_forest(&cfg).irreducible,
            "fixture must be a genuine two-entry irreducible scc"
        );
        assert!(
            !structuring::structure(&cfg).is_complete(),
            "the region engine alone must still sound-reject the raw irreducible cfg"
        );

        let empty_labels: BTreeMap<usize, SinkLabel> = BTreeMap::new();
        let empty_targets: BTreeMap<usize, u32> = BTreeMap::new();
        let body: Block = render_cfg_blocks(&blocks, &empty_labels, true, &empty_targets)
            .expect("two-entry irreducible scc must structure through CNS");
        assert!(
            body_has(&body, &|node: &Node| matches!(node, Node::While { .. })),
            "expected a while loop on the elected header: {body:?}"
        );
        assert!(!body_has(&body, &|node: &Node| matches!(
            node,
            Node::Label(_)
        )));
        assert!(!body_has(&body, &|node: &Node| matches!(
            node,
            Node::Goto(_)
        )));
    }

    #[test]
    fn signed_divide_lifts_quotient_and_remainder_from_cqo_idiv() {
        let code: [u8; 9] = [0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xa000, Abi::SysV).expect("signed divide");
        assert_eq!(rec.params, vec![Reg::Rdi, Reg::Rsi]);
        assert_eq!(rec.return_width_bits, 64);
        assert!(
            rec.source.contains("int64_t div_lhs = (int64_t)r_rax;"),
            "cqo/idiv must divide the signed 64-bit dividend: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rax = (uint64_t)(uint64_t)(div_lhs / div_rhs);"),
            "quotient must land in rax: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rdx = (uint64_t)(uint64_t)(div_lhs % div_rhs);"),
            "remainder must land in rdx: {}",
            rec.source
        );
    }

    #[test]
    fn unsigned_divide_lifts_from_xor_edx_div() {
        let code: [u8; 8] = [0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xf6];
        let mut with_ret: Vec<u8> = code.to_vec();
        with_ret.push(0xc3);
        let rec: LeafRecovery =
            recover_leaf_function_abi(&with_ret, 0xa100, Abi::SysV).expect("unsigned divide");
        assert!(
            rec.source.contains("uint64_t div_lhs = (uint64_t)r_rax;"),
            "xor edx,edx / div must divide the unsigned 64-bit dividend: {}",
            rec.source
        );
        assert!(
            rec.source.contains("uint64_t div_rhs = (uint64_t)r_rsi;"),
            "divisor must be read unsigned: {}",
            rec.source
        );
    }

    #[test]
    fn thirty_two_bit_signed_divide_uses_int32_operands() {
        let code: [u8; 7] = [0x89, 0xf8, 0x99, 0xf7, 0xfe, 0x90, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xa200, Abi::SysV).expect("32-bit signed divide");
        assert_eq!(rec.return_width_bits, 32);
        assert!(
            rec.source.contains("int32_t div_lhs = (int32_t)r_rax;")
                && rec.source.contains("int32_t div_rhs = (int32_t)r_rsi;"),
            "cdq/idiv on 32-bit operands must divide at int32_t width: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rax = (uint64_t)(uint32_t)(div_lhs / div_rhs);"),
            "32-bit quotient must be zero-extended into rax: {}",
            rec.source
        );
    }

    #[test]
    fn divide_without_high_half_setup_is_rejected() {
        let code: [u8; 6] = [0x48, 0x89, 0xf8, 0x48, 0xf7, 0xf6];
        let mut with_ret: Vec<u8> = code.to_vec();
        with_ret.push(0xc3);
        let err: Error = recover_leaf_function_abi(&with_ret, 0xa300, Abi::SysV)
            .expect_err("idiv without cqo must be out of class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn signed_divide_rejects_zeroed_high_half() {
        let code: [u8; 8] = [0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xfe];
        let mut with_ret: Vec<u8> = code.to_vec();
        with_ret.push(0xc3);
        let err: Error = recover_leaf_function_abi(&with_ret, 0xa400, Abi::SysV)
            .expect_err("idiv after xor edx,edx has an unsound sign-extension");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn addsd_lifts_double_addition_with_fp_signature() {
        let code: [u8; 5] = [0xf2, 0x0f, 0x58, 0xc1, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb000, Abi::SysV).expect("addsd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(
            rec.fp_params,
            vec![ScalarType::Double, ScalarType::Double],
            "addsd xmm0,xmm1 must take two double params: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("double recovered(double a0, double a1)"),
            "double signature expected: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1))"),
            "addsd must recover a double addition: {}",
            rec.source
        );
        assert!(
            rec.source.contains("return fp_d_from_bits(x_xmm0);"),
            "result must be reinterpreted from the low xmm0 bits: {}",
            rec.source
        );
    }

    #[test]
    fn a_read_of_xmm4_is_a_system_v_argument_but_microsoft_x64_volatile_scratch() {
        const CODE: [u8; 5] = [0xf2, 0x0f, 0x58, 0xc4, 0xc3];
        let sysv: LeafRecovery = recover_leaf_function_abi(&CODE, 0xb080, Abi::SysV)
            .expect("xmm4 is the fifth System V floating-point argument register");
        assert_eq!(
            sysv.fp_params,
            vec![ScalarType::Double, ScalarType::Double],
            "System V passes floating-point arguments in xmm0..xmm7: {}",
            sysv.source
        );
        let err: Error = recover_leaf_function_abi(&CODE, 0xb080, Abi::MsX64)
            .expect_err("xmm4 carries no incoming argument under Microsoft x64");
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("floating register 4 is read before any write")
                && message.contains("volatile scratch rather than an argument register"),
            "the rejection must name the register and the calling convention: {message}"
        );
    }

    #[test]
    fn microsoft_x64_still_accepts_every_one_of_its_four_floating_argument_registers() {
        const CODE: [u8; 17] = [
            0xf2, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x58, 0xc2, 0xf2, 0x0f, 0x58, 0xc3, 0xf2, 0x0f,
            0x5c, 0xc3, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&CODE, 0xb090, Abi::MsX64)
            .expect("xmm0..xmm3 are the Microsoft x64 floating-point argument registers");
        assert_eq!(
            rec.fp_params,
            vec![
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double,
                ScalarType::Double
            ],
            "all four Microsoft x64 floating-point argument registers must stay recoverable: {}",
            rec.source
        );
    }

    #[test]
    fn ms_x64_treats_xmm5_through_xmm7_read_before_write_as_volatile_scratch_not_an_argument() {
        for (modrm, xmm_index) in [(0xc5u8, 5u8), (0xc6, 6), (0xc7, 7)] {
            let code: [u8; 5] = [0xf2, 0x0f, 0x58, modrm, 0xc3];
            let err: Error = recover_leaf_function_abi(&code, 0xb0a0, Abi::MsX64)
                .expect_err("xmm5..xmm7 carry no incoming argument under Microsoft x64");
            let Error::LlvmIr(message) = err else {
                panic!("expected a lifter rejection for xmm{xmm_index}");
            };
            assert!(
                message.contains(&format!(
                    "floating register {xmm_index} is read before any write"
                )) && message.contains("volatile scratch rather than an argument register"),
                "xmm{xmm_index} must be rejected as microsoft x64 volatile scratch: {message}"
            );
        }
    }

    #[test]
    fn ms_x64_prologue_spill_of_xmm6_through_xmm15_is_frame_management_not_a_parameter_read() {
        const CODE: [u8; 20] = [
            0x48, 0x83, 0xec, 0x20, 0x0f, 0x29, 0x34, 0x24, 0x48, 0x89, 0xc8, 0x0f, 0x28, 0x34,
            0x24, 0x48, 0x83, 0xc4, 0x20, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&CODE, 0xb0b0, Abi::MsX64)
            .unwrap_or_else(|e: Error| {
                panic!("a callee-saved xmm6 spill/restore must not block leaf recovery: {e}")
            });
        assert_eq!(
            rec.params,
            vec![Reg::Rcx],
            "the only real argument read is rcx; the xmm6 spill contributes nothing: {}",
            rec.source
        );
        assert_eq!(
            rec.fp_params,
            vec![ScalarType::Int],
            "a callee-saved xmm6 spill/restore must never surface as a floating-point parameter: {}",
            rec.source
        );
    }

    #[test]
    fn ms_x64_shared_argument_index_places_the_first_double_in_xmm1_when_rcx_holds_the_int() {
        const CODE: [u8; 8] = [0x48, 0x89, 0xc8, 0xf2, 0x0f, 0x10, 0xd1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&CODE, 0xb0c0, Abi::MsX64)
            .expect("rcx and xmm1 are a contiguous Microsoft x64 shared-index pair");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(
            rec.fp_params,
            vec![ScalarType::Int, ScalarType::Double],
            "the int argument at position 0 must declare before the double at position 1, \
             matching the shared Microsoft x64 argument index: {}",
            rec.source
        );
    }

    #[test]
    fn ms_x64_shared_argument_index_rejects_a_position_claimed_by_both_classes() {
        let params: Vec<Reg> = vec![Reg::Rcx];
        let fp_args: Vec<(Xmm, FpWidth)> = vec![(Xmm::Xmm0, FpWidth::F64)];
        let err: Error = validate_ms_x64_shared_argument_index(Abi::MsX64, &params, &fp_args)
            .expect_err("rcx and xmm0 both claim position 0");
        let Error::LlvmIr(message) = err else {
            panic!("expected a shared-index rejection");
        };
        assert!(
            message.contains("position 0") && message.contains("claimed by both"),
            "the rejection must name the contested position: {message}"
        );
    }

    #[test]
    fn ms_x64_shared_argument_index_rejects_a_gap_below_the_highest_observed_register() {
        let params: Vec<Reg> = Vec::new();
        let fp_args: Vec<(Xmm, FpWidth)> = vec![(Xmm::Xmm1, FpWidth::F64)];
        let err: Error = validate_ms_x64_shared_argument_index(Abi::MsX64, &params, &fp_args)
            .expect_err("xmm1 alone leaves position 0 unaccounted for");
        let Error::LlvmIr(message) = err else {
            panic!("expected a shared-index rejection");
        };
        assert!(
            message.contains("not contiguous"),
            "the rejection must name the contiguity rule: {message}"
        );
    }

    #[test]
    fn ms_x64_shared_argument_index_rule_never_applies_outside_microsoft_x64() {
        let params: Vec<Reg> = vec![Reg::Rsi];
        let fp_args: Vec<(Xmm, FpWidth)> = vec![(Xmm::Xmm0, FpWidth::F64)];
        validate_ms_x64_shared_argument_index(Abi::SysV, &params, &fp_args)
            .expect("system v counts the integer and floating-point files independently");
    }

    #[test]
    fn ms_x64_ordered_param_types_interleaves_by_shared_slot_not_by_register_class() {
        let signature: FnSignature = FnSignature {
            fp: vec![(Xmm::Xmm1, FpWidth::F64)],
            int: vec![(Reg::Rcx, Width::W64)],
            vec: Vec::new(),
            ret: FnReturn::Void,
            exact_integer_types: false,
            abi: Abi::MsX64,
        };
        assert_eq!(
            signature.ordered_param_types(),
            vec![ScalarType::Int, ScalarType::Double]
        );
    }

    #[test]
    fn sysv_ordered_param_types_still_groups_floating_point_before_integer() {
        let signature: FnSignature = FnSignature {
            fp: vec![(Xmm::Xmm0, FpWidth::F64)],
            int: vec![(Reg::Rdi, Width::W64)],
            vec: Vec::new(),
            ret: FnReturn::Void,
            exact_integer_types: false,
            abi: Abi::SysV,
        };
        assert_eq!(
            signature.ordered_param_types(),
            vec![ScalarType::Double, ScalarType::Int]
        );
    }

    #[test]
    fn subss_lifts_float_subtraction() {
        let code: [u8; 5] = [0xf3, 0x0f, 0x5c, 0xc1, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb100, Abi::SysV).expect("subss leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Float));
        assert_eq!(rec.fp_params, vec![ScalarType::Float, ScalarType::Float]);
        assert!(
            rec.source.contains("float recovered(float a0, float a1)"),
            "float signature expected: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("(fp_f_from_bits((uint32_t)x_xmm0) - fp_f_from_bits((uint32_t)x_xmm1))"),
            "subss must recover a float subtraction: {}",
            rec.source
        );
    }

    #[test]
    fn cvtsi2sd_recovers_signed_int_to_double_conversion() {
        let code: [u8; 6] = [0xf2, 0x48, 0x0f, 0x2a, 0xc1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0xb200).expect("cvtsi2sd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(rec.fp_params, vec![ScalarType::Int]);
        assert!(
            rec.source.contains("double recovered(uint64_t a0)"),
            "int-to-double takes an integer param and returns double: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("x_xmm0 = fp_d_to_bits((double)((int64_t)r_rcx));"),
            "cvtsi2sd must cast the signed 64-bit int to a double: {}",
            rec.source
        );
    }

    #[test]
    fn cvttsd2si_recovers_double_to_int_truncation() {
        let code: [u8; 6] = [0xf2, 0x48, 0x0f, 0x2c, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb300, Abi::SysV).expect("cvttsd2si leaf");
        assert_eq!(rec.returns_fp, None);
        assert_eq!(rec.return_width_bits, 64);
        assert_eq!(rec.fp_params, vec![ScalarType::Double]);
        assert!(
            rec.source.contains("uint64_t recovered(double a0)"),
            "double-to-int returns an integer from a double param: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rax = (uint64_t)fpx_cvtind_i64_f64((fp_d_from_bits(x_xmm0)));"),
            "cvttsd2si must truncate the double toward zero into a signed int with the x86 out-of-range value: {}",
            rec.source
        );
    }

    #[test]
    fn cvtss2sd_recovers_float_to_double_widening() {
        let code: [u8; 5] = [0xf3, 0x0f, 0x5a, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb400, Abi::SysV).expect("cvtss2sd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(rec.fp_params, vec![ScalarType::Float]);
        assert!(
            rec.source
                .contains("x_xmm0 = fp_d_to_bits((double)(fp_f_from_bits((uint32_t)x_xmm0)));"),
            "cvtss2sd must widen a float to a double: {}",
            rec.source
        );
    }

    #[test]
    fn ucomisd_branch_recovers_fp_compare_and_select() {
        let code: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc8, 0x76, 0x05, 0xf2, 0x0f, 0x5e, 0xc1, 0xc3, 0xf2, 0x0f, 0x5e,
            0xc8, 0x66, 0x0f, 0x28, 0xc1, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb500, Abi::SysV).expect("ucomisd branch leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert!(
            rec.source.contains("if ("),
            "compare must lower to a branch: {}",
            rec.source
        );
        assert!(
            rec.source.contains("fp_d_from_bits(x_xmm1)")
                && rec.source.contains("fp_d_from_bits(x_xmm0)"),
            "the fp compare must read both xmm operands as doubles: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("if ((fp_d_from_bits(x_xmm1)) > (fp_d_from_bits(x_xmm0)))"),
            "ucomisd xmm1,xmm0 + jbe (taken to the else arm) must recover the negated `>` guard: {}",
            rec.source
        );
    }

    #[test]
    fn packed_sse_is_rejected_as_out_of_class() {
        let code: [u8; 5] = [0x66, 0x0f, 0x58, 0xc1, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0xb600, Abi::SysV)
            .expect_err("addpd is a packed SIMD op outside the scalar float class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn minsd_lifts_to_a_scalar_min_ternary() {
        let code: [u8; 5] = [0xf2, 0x0f, 0x5d, 0xc1, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb700, Abi::SysV).expect("minsd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(rec.fp_params, vec![ScalarType::Double, ScalarType::Double]);
        assert!(
            rec.source.contains(
                "fp_d_from_bits(x_xmm0) < fp_d_from_bits(x_xmm1) ? fp_d_from_bits(x_xmm0) : fp_d_from_bits(x_xmm1)"
            ),
            "minsd xmm0,xmm1 must lower to the dest<src ? dest : src select that mirrors the hardware NaN and signed-zero result: {}",
            rec.source
        );
    }

    #[test]
    fn packed_minpd_is_rejected_as_out_of_class() {
        let code: [u8; 5] = [0x66, 0x0f, 0x5d, 0xc1, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0xb710, Abi::SysV)
            .expect_err("packed minpd operates on two lanes and is outside the scalar float class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn movsd_load_and_store_round_trips_through_memory() {
        let code: [u8; 11] = [
            0xf2, 0x0f, 0x10, 0x07, 0xf2, 0x0f, 0x58, 0xc0, 0xf2, 0x0f, 0x11,
        ];
        let mut with_store: Vec<u8> = code.to_vec();
        with_store.push(0x07);
        with_store.push(0xc3);
        let rec: LeafRecovery =
            recover_leaf_function_abi(&with_store, 0xb800, Abi::SysV).expect("movsd mem leaf");
        assert!(
            rec.source.contains("(*(double*)(uintptr_t)"),
            "movsd load must dereference the address as a double: {}",
            rec.source
        );
        assert!(
            rec.source.contains("x_xmm0"),
            "the loaded scalar lands in an xmm var: {}",
            rec.source
        );
    }

    #[test]
    fn floating_memory_offsets_stay_raw_until_float_fields_are_emitted() {
        let code: [u8; 10] = [0xf2, 0x0f, 0x10, 0x07, 0xf2, 0x0f, 0x58, 0x47, 0x08, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xb810, Abi::SysV).expect("float memory leaf");
        assert!(!rec.source.contains("recovered_struct_"));
        assert!(rec.source.matches("(*(double*)(uintptr_t)").count() >= 2);
    }

    #[test]
    fn xor_self_zeroes_without_reading_the_register() {
        let code: [u8; 6] = [0x31, 0xc9, 0x48, 0x01, 0xc8, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code[..], 0x1000, Abi::SysV).expect("xor-zero leaf");
        assert!(
            !rec.params.contains(&Reg::Rcx),
            "xor ecx,ecx must not make rcx a parameter: {:?}",
            rec.params
        );
        assert!(
            rec.source
                .contains("r_rcx = ((uint64_t)(int64_t)0LL) & 0xffffffffULL"),
            "xor ecx,ecx must lower to a zeroing assignment: {}",
            rec.source
        );
    }

    #[test]
    fn setl_after_cmp_recovers_signed_less_than_boolean() {
        let code: [u8; 10] = [0x48, 0x39, 0xd1, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0xc000).expect("setl leaf");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(
            rec.source.contains(
                "r_rax = r_rax & 0xffffffffffffff00ULL | (uint64_t)(((int64_t)(int64_t)(r_rcx) < (int64_t)(int64_t)(r_rdx)) ? 1 : 0);"
            ),
            "cmp+setl must write only the low byte of rax with a signed-less-than predicate: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("((uint32_t)(uint8_t)((r_rax) & 0xffULL))"),
            "the following movzx eax,al must zero-extend the boolean byte: {}",
            rec.source
        );
    }

    #[test]
    fn sete_after_test_recovers_equal_zero_boolean() {
        let code: [u8; 8] = [0x48, 0x85, 0xc9, 0x0f, 0x94, 0xc0, 0x90, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xc100, Abi::SysV).expect("sete leaf");
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert!(
            rec.source.contains(
                "r_rax = r_rax & 0xffffffffffffff00ULL | (uint64_t)(((int64_t)(int64_t)(r_rcx) == 0) ? 1 : 0);"
            ),
            "test rcx,rcx + sete must recover an equal-zero boolean into the low byte: {}",
            rec.source
        );
    }

    #[test]
    fn setcc_preserves_the_upper_bytes_of_the_destination() {
        let code: [u8; 10] = [0x48, 0x39, 0xd1, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0xc200).expect("setl leaf");
        assert!(
            rec.source.contains("r_rax & 0xffffffffffffff00ULL"),
            "setcc must be modeled as a byte write that keeps the upper 56 bits: {}",
            rec.source
        );
    }

    #[test]
    fn setcc_without_preceding_flags_is_rejected() {
        let code: [u8; 4] = [0x0f, 0x9c, 0xc0, 0xc3];
        let err: Error = recover_leaf_function(&code, 0xc300)
            .expect_err("a setcc with no tracked comparison must be out of class");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn setcc_with_signed_order_over_fp_flags_is_rejected() {
        let code: [u8; 8] = [0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9f, 0xc0, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0xc400, Abi::SysV).expect_err(
            "setg (signed order) is not sound against unordered ucomisd flags and must be rejected",
        );
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn switch_return_unifies_uniform_double_cases_to_fp() {
        let states: [Option<FpWidth>; 3] =
            [Some(FpWidth::F64), Some(FpWidth::F64), Some(FpWidth::F64)];
        let ret: FnReturn =
            unify_fp_return(&states, Width::W64).expect("uniform double cases type as fp");
        assert_eq!(ret, FnReturn::Fp(FpWidth::F64));
    }

    #[test]
    fn switch_return_all_int_cases_stay_int() {
        let states: [Option<FpWidth>; 3] = [None, None, None];
        let ret: FnReturn =
            unify_fp_return(&states, Width::W32).expect("all-int cases type as int");
        assert_eq!(ret, FnReturn::Int(Width::W32));
    }

    #[test]
    fn switch_return_mixed_int_and_fp_cases_are_rejected() {
        let states: [Option<FpWidth>; 3] = [Some(FpWidth::F64), None, Some(FpWidth::F64)];
        let err: Error = unify_fp_return(&states, Width::W64)
            .expect_err("a switch mixing an integer and a float return cannot be typed");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn switch_return_conflicting_fp_widths_are_rejected() {
        let states: [Option<FpWidth>; 2] = [Some(FpWidth::F64), Some(FpWidth::F32)];
        let err: Error = unify_fp_return(&states, Width::W64)
            .expect_err("a switch returning both a double and a float cannot be typed");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn sqrtsd_lifts_scalar_double_square_root() {
        let code: [u8; 5] = [0xf2, 0x0f, 0x51, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd000, Abi::SysV).expect("sqrtsd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(rec.fp_params, vec![ScalarType::Double]);
        assert!(
            rec.source.contains(
                "x_xmm0 = fp_d_to_bits((double)(fpx_sqrt_x86_f64(fp_d_from_bits(x_xmm0))));"
            ),
            "sqrtsd must lower to a double square root over the low xmm0 bits: {}",
            rec.source
        );
    }

    #[test]
    fn sqrtss_lifts_scalar_single_square_root() {
        let code: [u8; 5] = [0xf3, 0x0f, 0x51, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd100, Abi::SysV).expect("sqrtss leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Float));
        assert_eq!(rec.fp_params, vec![ScalarType::Float]);
        assert!(
            rec.source
                .contains("fpx_sqrt_x86_f32(fp_f_from_bits((uint32_t)x_xmm0))"),
            "sqrtss must lower to a single-precision square root: {}",
            rec.source
        );
    }

    #[test]
    fn xorps_self_zeroes_the_xmm_register() {
        let code: [u8; 4] = [0x0f, 0x57, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd200, Abi::SysV).expect("xorps zero leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert!(
            rec.fp_params.is_empty(),
            "self-xor zeroing reads no register and takes no fp param: {:?}",
            rec.fp_params
        );
        assert!(
            rec.source
                .contains("x_xmm0 = fp_d_to_bits((double)(fp_d_from_bits(0x0ULL)));"),
            "xorps xmm0,xmm0 must materialize a 0.0 constant: {}",
            rec.source
        );
    }

    #[test]
    fn xorpd_zero_feeds_addsd_as_an_additive_identity() {
        let code: [u8; 10] = [0x66, 0x0f, 0x57, 0xc9, 0xf2, 0x0f, 0x58, 0xc1, 0x90, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd300, Abi::SysV).expect("xorpd+addsd leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(
            rec.fp_params,
            vec![ScalarType::Double],
            "only xmm0 is read before write; the zeroed xmm1 is not a param: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("(fp_d_from_bits(x_xmm0) + fp_d_from_bits(x_xmm1))"),
            "the addsd of the zeroed register must survive: {}",
            rec.source
        );
    }

    #[test]
    fn movq_gpr_to_xmm_bitcasts_int_to_double() {
        let code: [u8; 6] = [0x66, 0x48, 0x0f, 0x6e, 0xc1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0xd400).expect("movq gpr->xmm leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Double));
        assert_eq!(rec.params, vec![Reg::Rcx]);
        assert_eq!(rec.fp_params, vec![ScalarType::Int]);
        assert!(
            rec.source.contains("x_xmm0 = r_rcx;")
                && rec.source.contains("return fp_d_from_bits(x_xmm0);"),
            "movq xmm0,rcx must copy the integer bits into xmm0 and return them as a double: {}",
            rec.source
        );
    }

    #[test]
    fn movq_xmm_to_gpr_bitcasts_double_to_int() {
        let code: [u8; 6] = [0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd500, Abi::SysV).expect("movq xmm->gpr leaf");
        assert_eq!(rec.returns_fp, None);
        assert_eq!(rec.return_width_bits, 64);
        assert_eq!(rec.fp_params, vec![ScalarType::Double]);
        assert!(
            rec.source.contains("r_rax = x_xmm0;"),
            "movq rax,xmm0 must copy the low double bits into rax verbatim: {}",
            rec.source
        );
    }

    #[test]
    fn movd_gpr_to_xmm_bitcasts_int_to_float() {
        let code: [u8; 5] = [0x66, 0x0f, 0x6e, 0xc1, 0xc3];
        let rec: LeafRecovery = recover_leaf_function(&code, 0xd600).expect("movd gpr->xmm leaf");
        assert_eq!(rec.returns_fp, Some(ScalarType::Float));
        assert!(
            rec.source.contains("x_xmm0 = (uint32_t)r_rcx;"),
            "movd xmm0,ecx must copy the low 32 bits into xmm0: {}",
            rec.source
        );
    }

    #[test]
    fn movd_xmm_to_gpr_bitcasts_float_to_int() {
        let code: [u8; 5] = [0x66, 0x0f, 0x7e, 0xc0, 0xc3];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0xd700, Abi::SysV).expect("movd xmm->gpr leaf");
        assert_eq!(rec.returns_fp, None);
        assert_eq!(rec.return_width_bits, 32);
        assert_eq!(rec.fp_params, vec![ScalarType::Float]);
        assert!(
            rec.source.contains("(uint32_t)x_xmm0"),
            "movd eax,xmm0 must copy the low 32 float bits into eax: {}",
            rec.source
        );
    }

    #[test]
    fn cross_register_xorps_is_rejected_as_a_real_bitwise_op() {
        let code: [u8; 4] = [0x0f, 0x57, 0xc1, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0xd800, Abi::SysV).expect_err(
            "xorps of two distinct registers is a real 128-bit bitwise op, not a zero idiom",
        );
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn cross_register_pxor_is_rejected_as_a_real_bitwise_op() {
        let code: [u8; 5] = [0x66, 0x0f, 0xef, 0xc1, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0xd900, Abi::SysV).expect_err(
            "pxor of two distinct registers is a real 128-bit bitwise op outside the scalar class",
        );
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn rbp_frame_arg_spill_reload_models_slots_as_a_local_frame() {
        let code: [u8; 22] = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b,
            0x45, 0xf8, 0x48, 0x03, 0x45, 0xf0, 0x5d, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function_abi(&code, 0x8000, Abi::SysV).expect("rbp-frame spill add");
        assert_eq!(rec.params, vec![Reg::Rdi, Reg::Rsi]);
        assert!(
            rec.source.contains("unsigned char stack_frame["),
            "expected a real local frame backing the spill slots: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rbp = (uint64_t)(uintptr_t)(stack_frame +"),
            "the frame pointer must be aimed into the local frame array: {}",
            rec.source
        );
    }

    #[test]
    fn rsp_frame_arg_spill_reload_models_slots_as_a_local_frame() {
        let code: [u8; 27] = [
            0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x54, 0x24, 0x08, 0x48, 0x89, 0x0c, 0x24, 0x48,
            0x8b, 0x04, 0x24, 0x48, 0x03, 0x44, 0x24, 0x08, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ];
        let rec: LeafRecovery =
            recover_leaf_function(&code, 0x8100).expect("frameless rsp-frame spill add");
        assert_eq!(rec.params, vec![Reg::Rcx, Reg::Rdx]);
        assert!(
            rec.source
                .contains("r_rsp = (uint64_t)(uintptr_t)(stack_frame +"),
            "the stack pointer must be aimed into the local frame array: {}",
            rec.source
        );
    }

    fn rsp_constant_frame_rejection(code: &[u8], base: u64, abi: Abi) -> String {
        let err: Error = recover_leaf_function_abi(code, base, abi).map_or_else(
            |e: Error| e,
            |rec: LeafRecovery| {
                panic!(
                    "an access outside the bytes an allocated frame owns may not be modeled as a local: {}",
                    rec.source
                )
            },
        );
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("bytes this frame owns"),
            "the containment check must name the extent the slot left: {message}"
        );
        message
    }

    #[test]
    fn an_rsp_constant_slot_at_the_allocation_reads_the_return_address_and_is_rejected() {
        const CODE: [u8; 14] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x18, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let text: String = disasm_text(&CODE, 0x8a00);
        assert_eq!(
            text, "sub rsp,18h; mov rax,[rsp+18h]; add rsp,18h; ret ",
            "the probe must allocate twenty-four bytes and read the slot at the entry stack pointer"
        );
        let message: String = rsp_constant_frame_rejection(&CODE, 0x8a00, Abi::SysV);
        assert!(
            message.contains("8-byte slot at 24 is outside the [-128, 24) bytes"),
            "the rejection must name the eight-byte read of the return address: {message}"
        );
        let ms: String = rsp_constant_frame_rejection(&CODE, 0x8a00, Abi::MsX64);
        assert!(
            ms.contains("8-byte slot at 24 is outside the [0, 24) and [32, 64) bytes"),
            "the return address stays caller-owned under the Microsoft x64 home area too: {ms}"
        );
    }

    #[test]
    fn an_rsp_constant_slot_above_the_allocation_reads_a_caller_byte_and_is_rejected() {
        const CODE: [u8; 14] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        const PAST_HOME: [u8; 14] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let message: String = rsp_constant_frame_rejection(&CODE, 0x8a10, Abi::SysV);
        assert!(
            message.contains("8-byte slot at 32 is outside the [-128, 24) bytes"),
            "under System V a load past the return address reads an incoming stack argument: {message}"
        );
        let ms: String = rsp_constant_frame_rejection(&PAST_HOME, 0x8a18, Abi::MsX64);
        assert!(
            ms.contains("8-byte slot at 64 is outside the [0, 24) and [32, 64) bytes"),
            "a load past the Microsoft x64 home area reads the fifth incoming argument: {ms}"
        );
    }

    #[test]
    fn an_rsp_constant_slot_whose_width_straddles_the_allocation_is_rejected() {
        const EIGHT_BYTE: [u8; 14] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x14, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        const FOUR_BYTE: [u8; 13] = [
            0x48, 0x83, 0xec, 0x18, 0x8b, 0x44, 0x24, 0x16, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let message: String = rsp_constant_frame_rejection(&EIGHT_BYTE, 0x8a20, Abi::SysV);
        assert!(
            message.contains("8-byte slot at 20 is outside the [-128, 24) bytes"),
            "an eight-byte read at twenty runs four bytes into the return address: {message}"
        );
        let narrow: String = rsp_constant_frame_rejection(&FOUR_BYTE, 0x8a30, Abi::SysV);
        assert!(
            narrow.contains("4-byte slot at 22 is outside the [-128, 24) bytes"),
            "a four-byte read at twenty-two runs two bytes into the return address: {narrow}"
        );
    }

    #[test]
    fn an_rsp_constant_slot_below_the_red_zone_of_an_allocated_frame_is_rejected() {
        const CODE: [u8; 21] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0xbc, 0x24, 0x78, 0xff, 0xff, 0xff, 0x48, 0x8b,
            0x84, 0x24, 0x78, 0xff, 0xff, 0xff, 0xc3,
        ];
        let message: String = rsp_constant_frame_rejection(&CODE, 0x8a40, Abi::SysV);
        assert!(
            message.contains("8-byte slot at -136 is outside the [-128, 24) bytes"),
            "the System V guarantee stops one hundred and twenty-eight bytes below the stack pointer: {message}"
        );
    }

    #[test]
    fn an_rsp_constant_slot_below_an_allocated_frame_without_a_red_zone_is_rejected() {
        const CODE: [u8; 19] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x80, 0x48, 0x8b, 0x44, 0x24, 0x80,
            0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let ms: String = rsp_constant_frame_rejection(&CODE, 0x8a48, Abi::MsX64);
        assert!(
            ms.contains("8-byte slot at -128 is outside the [0, 24) and [32, 64) bytes"),
            "the Microsoft x64 ABI reserves nothing below the stack pointer: {ms}"
        );
    }

    #[test]
    fn a_call_under_an_allocated_frame_takes_the_red_zone_out_of_the_frame() {
        const CALLING: [u8; 24] = [
            0x48, 0x83, 0xec, 0x18, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x7c, 0x24, 0xf8,
            0x48, 0x8b, 0x44, 0x24, 0xf8, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let insns: Vec<DisasmInsn> =
            disassemble(Arch::X86_64, 0x8a4c, &CALLING).expect("disassemble calling probe");
        assert_eq!(
            classify_frame(&insns, Abi::SysV),
            FrameShape {
                base: Some(Reg::Rsp),
                rbp_is_frame: false,
                red_zone: false,
                stack_extent: Some(StackFrameExtent::x86(24, 0, 0)),
                stack_pointer_break: None,
            },
            "a callee clobbers the bytes below the stack pointer, so the red zone leaves the frame"
        );
    }

    #[test]
    fn rsp_constant_slots_inside_the_frame_still_model_a_local_frame() {
        let cases: [(&str, Abi, usize, &[u8]); 5] = [
            (
                "an eight-byte slot at the top of the allocation",
                Abi::SysV,
                24,
                &[
                    0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x10, 0x48, 0x8b, 0x44, 0x24,
                    0x10, 0x48, 0x83, 0xc4, 0x18, 0xc3,
                ],
            ),
            (
                "a four-byte slot ending exactly at the allocation",
                Abi::SysV,
                24,
                &[
                    0x48, 0x83, 0xec, 0x18, 0x89, 0x7c, 0x24, 0x14, 0x8b, 0x44, 0x24, 0x14, 0x48,
                    0x83, 0xc4, 0x18, 0xc3,
                ],
            ),
            (
                "a one-byte slot on the last allocated byte",
                Abi::SysV,
                24,
                &[
                    0x48, 0x83, 0xec, 0x18, 0x40, 0x88, 0x7c, 0x24, 0x17, 0x0f, 0xb6, 0x44, 0x24,
                    0x17, 0x48, 0x83, 0xc4, 0x18, 0xc3,
                ],
            ),
            (
                "a call-free System V leaf reaching into the red zone below its allocation",
                Abi::SysV,
                128,
                &[
                    0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x80, 0x48, 0x8b, 0x44, 0x24,
                    0x80, 0x48, 0x83, 0xc4, 0x18, 0xc3,
                ],
            ),
            (
                "a Microsoft x64 spill into the caller-reserved register home area",
                Abi::MsX64,
                40,
                &[
                    0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x4c, 0x24, 0x20, 0x48, 0x8b, 0x44, 0x24,
                    0x20, 0x48, 0x83, 0xc4, 0x18, 0xc3,
                ],
            ),
        ];
        for (index, (what, abi, frame_bytes, code)) in cases.into_iter().enumerate() {
            let base: u64 = 0x8a50 + (index as u64) * 0x20;
            let rec: LeafRecovery = recover_leaf_function_abi(code, base, abi)
                .unwrap_or_else(|e: Error| panic!("{what} is inside the frame: {e}"));
            assert!(
                rec.source
                    .contains(&format!("unsigned char stack_frame[{frame_bytes}];")),
                "{what} must back the bytes it touches: {}",
                rec.source
            );
        }
    }

    #[test]
    fn the_frame_classifier_reports_the_bytes_an_allocated_frame_owns() {
        const CODE: [u8; 19] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x10,
            0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let insns: Vec<DisasmInsn> =
            disassemble(Arch::X86_64, 0x8af0, &CODE).expect("disassemble rsp-constant probe");
        let expected: [(Abi, StackFrameExtent); 2] = [
            (Abi::SysV, StackFrameExtent::x86(24, SYSV_RED_ZONE_BYTES, 0)),
            (Abi::MsX64, StackFrameExtent::x86(24, 0, MS_X64_HOME_BYTES)),
        ];
        for (abi, extent) in expected {
            assert_eq!(
                classify_frame(&insns, abi),
                FrameShape {
                    base: Some(Reg::Rsp),
                    rbp_is_frame: false,
                    red_zone: false,
                    stack_extent: Some(extent),
                    stack_pointer_break: None,
                },
                "{abi:?} bounds the frame to the bytes its ABI makes private"
            );
        }
    }

    fn frame_plan_rejection(code: &[u8], base: u64, abi: Abi) -> String {
        let err: Error = recover_leaf_function_abi(code, base, abi).map_or_else(
            |e: Error| e,
            |rec: LeafRecovery| {
                panic!(
                    "a frame this model cannot bound may not be recovered as a local frame: {}",
                    rec.source
                )
            },
        );
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        message
    }

    #[test]
    fn a_frame_pointer_frame_rejects_the_caller_frame_above_the_saved_registers() {
        const ONE_PUSH: [u8; 10] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x10, 0x5d, 0xc3];
        const TWO_PUSHES: [u8; 12] = [
            0x55, 0x53, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x18, 0x5b, 0x5d, 0xc3,
        ];
        const LEA_ANCHOR: [u8; 12] = [
            0x55, 0x48, 0x8d, 0x6c, 0x24, 0x00, 0x48, 0x8b, 0x45, 0x10, 0x5d, 0xc3,
        ];
        let cases: [(&str, &[u8], &str, &str); 3] = [
            (
                "push rbp; mov rbp,rsp; mov rax,[rbp+10h]; pop rbp; ret ",
                &ONE_PUSH,
                "8-byte slot at 16 is outside the (-inf, 0) bytes this frame owns",
                "the saved registers sit at [0, 8), the return address at 8",
            ),
            (
                "push rbp; push rbx; mov rbp,rsp; mov rax,[rbp+18h]; pop rbx; pop rbp; ret ",
                &TWO_PUSHES,
                "8-byte slot at 24 is outside the (-inf, 0) bytes this frame owns",
                "the saved registers sit at [0, 16), the return address at 16",
            ),
            (
                "push rbp; lea rbp,[rsp]; mov rax,[rbp+10h]; pop rbp; ret ",
                &LEA_ANCHOR,
                "8-byte slot at 16 is outside the (-inf, 0) bytes this frame owns",
                "the saved registers sit at [0, 8), the return address at 8",
            ),
        ];
        for (index, (asm, code, extent, linkage)) in cases.into_iter().enumerate() {
            let base: u64 = 0x9100 + (index as u64) * 0x40;
            assert_eq!(
                disasm_text(code, base),
                asm,
                "the probe must build the frame pointer the case describes"
            );
            let message: String = frame_plan_rejection(code, base, Abi::SysV);
            assert!(
                message.contains(extent),
                "an incoming stack argument is not a local slot: {message}"
            );
            assert!(
                message.contains(linkage),
                "the rejection must place the saved registers the prologue pushed: {message}"
            );
        }
    }

    #[test]
    fn a_microsoft_x64_frame_pointer_frame_owns_the_caller_reserved_home_space() {
        const HOME_SLOT: [u8; 10] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x10, 0x5d, 0xc3];
        const PAST_HOME: [u8; 10] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x30, 0x5d, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&HOME_SLOT, 0x9200, Abi::MsX64)
            .expect("the register home area is callee scratch the caller reserves");
        assert!(
            rec.source.contains("unsigned char stack_frame[24];"),
            "the home slot must be backed like any other byte this frame owns: {}",
            rec.source
        );
        assert_eq!(
            disasm_text(&PAST_HOME, 0x9240),
            "push rbp; mov rbp,rsp; mov rax,[rbp+30h]; pop rbp; ret ",
            "the probe must read the first byte above the home area"
        );
        let message: String = frame_plan_rejection(&PAST_HOME, 0x9240, Abi::MsX64);
        assert!(
            message.contains("8-byte slot at 48 is outside the (-inf, 0) and [16, 48) bytes"),
            "the fifth incoming argument sits above the home area and is not a local: {message}"
        );
    }

    #[test]
    fn a_displaced_frame_pointer_anchor_bounds_the_frame_where_the_prologue_puts_it() {
        const LOCAL_ABOVE_ANCHOR: [u8; 22] = [
            0x55, 0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x80, 0x48,
            0x89, 0x7d, 0x78, 0x48, 0x8b, 0x45, 0x78, 0xc3,
        ];
        const CALLER_ARGUMENT: [u8; 21] = [
            0x55, 0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x80, 0x48,
            0x8b, 0x85, 0x90, 0x01, 0x00, 0x00, 0xc3,
        ];
        assert_eq!(
            disasm_text(&LOCAL_ABOVE_ANCHOR, 0x9300),
            "push rbp; sub rsp,100h; lea rbp,[rsp-80h]; mov [rbp+78h],rdi; mov rax,[rbp+78h]; ret ",
            "the probe must anchor the frame pointer inside its own allocation"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&LOCAL_ABOVE_ANCHOR, 0x9300, Abi::SysV)
            .expect("a displaced anchor leaves locals both above and below itself");
        assert!(
            rec.source.contains("unsigned char stack_frame[128];"),
            "a local above a displaced anchor is still a local: {}",
            rec.source
        );
        assert_eq!(
            disasm_text(&CALLER_ARGUMENT, 0x9340),
            "push rbp; sub rsp,100h; lea rbp,[rsp-80h]; mov rax,[rbp+190h]; ret ",
            "the probe must read the first byte above the return address"
        );
        let message: String = frame_plan_rejection(&CALLER_ARGUMENT, 0x9340, Abi::SysV);
        assert!(
            message.contains("8-byte slot at 400 is outside the (-inf, 384) bytes"),
            "this prologue puts the entry stack pointer at 392, so 400 is the caller's: {message}"
        );
        assert!(
            message.contains("the saved registers sit at [384, 392), the return address at 392"),
            "the rejection must place the linkage where this prologue put it: {message}"
        );
    }

    #[test]
    fn the_frame_pointer_boundary_holds_at_the_last_local_byte_and_the_first_saved_byte() {
        const LAST_LOCAL: [u8; 14] = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x45, 0xf8, 0x5d, 0xc3,
        ];
        const FIRST_SAVED: [u8; 10] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x00, 0x5d, 0xc3];
        assert_eq!(
            disasm_text(&LAST_LOCAL, 0x9400),
            "push rbp; mov rbp,rsp; mov [rbp-8],rdi; mov rax,[rbp-8]; pop rbp; ret ",
            "the probe must end its slot exactly on the boundary"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&LAST_LOCAL, 0x9400, Abi::SysV)
            .expect("a slot ending on the boundary is the last in-frame slot");
        assert!(
            rec.source.contains("unsigned char stack_frame[8];"),
            "the eight bytes below the frame pointer are the frame's own: {}",
            rec.source
        );
        let message: String = frame_plan_rejection(&FIRST_SAVED, 0x9440, Abi::SysV);
        assert!(
            message.contains("8-byte slot at 0 is outside the (-inf, 0) bytes"),
            "the byte on the boundary holds the saved frame pointer, not data: {message}"
        );
    }

    #[test]
    fn every_unstable_stack_pointer_shape_names_why_no_fixed_offset_exists() {
        const VARIABLE: [u8; 18] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x29, 0xc4, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b,
            0x44, 0x24, 0x08, 0xc3,
        ];
        const REALIGNED: [u8; 19] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x83, 0xe4, 0xe0, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48,
            0x8b, 0x44, 0x24, 0x08, 0xc3,
        ];
        const RECOMPUTED: [u8; 20] = [
            0x48, 0x83, 0xec, 0x18, 0x48, 0x8d, 0x64, 0x24, 0xf0, 0x48, 0x89, 0x7c, 0x24, 0x08,
            0x48, 0x8b, 0x44, 0x24, 0x08, 0xc3,
        ];
        const RESIZED: [u8; 25] = [
            0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, 0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00,
            0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x08, 0xc3,
        ];
        const PUSH_BUILT: [u8; 13] = [
            0x53, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x5b, 0xc3,
        ];
        const STACK_PROBE: [u8; 24] = [
            0xb8, 0x00, 0x30, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x29, 0xc4, 0x48,
            0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x08, 0xc3,
        ];
        let cases: [(&[u8], Abi, StackPointerBreak); 6] = [
            (&VARIABLE, Abi::SysV, StackPointerBreak::VariableAllocation),
            (&REALIGNED, Abi::SysV, StackPointerBreak::Realignment),
            (&RECOMPUTED, Abi::SysV, StackPointerBreak::PointerArithmetic),
            (&RESIZED, Abi::SysV, StackPointerBreak::ResizedMidBody),
            (&PUSH_BUILT, Abi::SysV, StackPointerBreak::PushBuilt),
            (&STACK_PROBE, Abi::MsX64, StackPointerBreak::StackProbe),
        ];
        for (index, (code, abi, expected)) in cases.into_iter().enumerate() {
            let base: u64 = 0x9500 + (index as u64) * 0x40;
            let insns: Vec<DisasmInsn> =
                disassemble(Arch::X86_64, base, code).expect("disassemble unstable frame probe");
            assert_eq!(
                classify_frame(&insns, abi).stack_pointer_break,
                Some(expected),
                "the classifier must name the shape that moves the stack pointer: {}",
                disasm_text(code, base)
            );
            let message: String = frame_plan_rejection(code, base, abi);
            assert!(
                message.contains(expected.reason()),
                "the rejection must say why no offset is fixed: {message}"
            );
        }
    }

    #[test]
    fn an_address_taken_slot_keeps_the_escape_message_when_the_stack_pointer_is_constant() {
        const ADDRESS_TAKEN: [u8; 10] =
            [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0xf8, 0x5d, 0xc3];
        let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, 0x9600, &ADDRESS_TAKEN)
            .expect("disassemble address-taken probe");
        assert_eq!(
            classify_frame(&insns, Abi::SysV).stack_pointer_break,
            None,
            "this prologue moves the stack pointer by one constant, so nothing is unstable"
        );
        let message: String = frame_plan_rejection(&ADDRESS_TAKEN, 0x9600, Abi::SysV);
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "a leaked slot address is an escape, not an unstable stack pointer: {message}"
        );
    }

    #[test]
    fn taking_the_address_of_a_stack_slot_is_soundly_rejected() {
        let code: [u8; 10] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0xf8, 0x5d, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0x8200, Abi::SysV)
            .expect_err("a leaked frame-slot address is not a modelable fixed slot");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn reading_the_frame_pointer_as_a_value_is_soundly_rejected() {
        let code: [u8; 9] = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xe8, 0x5d, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0x8300, Abi::SysV)
            .expect_err("using rbp as a value escapes the frame model");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    const RED_ZONE_SLOT: [u8; 11] = [
        0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3,
    ];

    #[test]
    fn sysv_red_zone_slot_below_the_entry_stack_pointer_models_a_local_frame() {
        let rec: LeafRecovery = recover_leaf_function_abi(&RED_ZONE_SLOT, 0x8400, Abi::SysV)
            .expect("a leaf that spills into the System V red zone must lift");
        assert_eq!(rec.params, vec![Reg::Rdi]);
        assert!(
            rec.source.contains("unsigned char stack_frame[8];"),
            "the red zone must back exactly the eight bytes the slot occupies: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rsp = (uint64_t)(uintptr_t)(stack_frame + 8)"),
            "the entry stack pointer must be aimed at the top of the red-zone frame: {}",
            rec.source
        );
    }

    #[test]
    fn microsoft_x64_has_no_red_zone_so_the_same_slot_is_rejected() {
        let err: Error = recover_leaf_function_abi(&RED_ZONE_SLOT, 0x8410, Abi::MsX64).expect_err(
            "the Microsoft x64 ABI reserves nothing below rsp, so the slot is not a private frame",
        );
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "the MS x64 store below rsp must fall through to the unchanged frame rejection: {message}"
        );
    }

    #[test]
    fn a_call_clobbers_the_red_zone_so_a_below_stack_pointer_slot_is_rejected() {
        let code: [u8; 16] = [
            0x48, 0x89, 0x7c, 0x24, 0xf8, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24,
            0xf8, 0xc3,
        ];
        let err: Error = recover_leaf_function_abi(&code, 0x8420, Abi::SysV)
            .expect_err("a call clobbers the red zone, so the slot cannot be a private frame");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn a_tail_jump_out_of_the_function_disqualifies_the_red_zone() {
        let code: [u8; 15] = [
            0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xe9, 0x20, 0x00, 0x00,
            0x00,
        ];
        let err: Error = recover_leaf_function_abi(&code, 0x8430, Abi::SysV)
            .expect_err("a tail jump reaches a callee that clobbers the red zone");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn the_red_zone_frame_shape_enforces_every_precondition_at_its_own_site() {
        let cases: [(&str, bool, &[u8]); 11] = [
            (
                "a plain below-rsp spill and reload is the red zone",
                true,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3,
                ],
            ),
            (
                "an in-function forward jump keeps the red-zone shape",
                true,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0xeb, 0x05, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0x48,
                    0x8b, 0x44, 0x24, 0xf8, 0xc3,
                ],
            ),
            (
                "a direct call clobbers the red zone",
                false,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44,
                    0x24, 0xf8, 0xc3,
                ],
            ),
            (
                "a tail jump past the function end reaches a clobbering callee",
                false,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xe9, 0x20, 0x00,
                    0x00, 0x00,
                ],
            ),
            (
                "a relocated tail jump onto the following address is a call in disguise",
                false,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xe9, 0x00, 0x00,
                    0x00, 0x00,
                ],
            ),
            (
                "an indirect jump has no provable target",
                false,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xff, 0xe0,
                ],
            ),
            (
                "a push moves rsp away from its entry value",
                false,
                &[
                    0x55, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0x5d, 0xc3,
                ],
            ),
            (
                "an access above the entry rsp is an incoming argument",
                false,
                &[0x48, 0x8b, 0x44, 0x24, 0x08, 0xc3],
            ),
            (
                "an access past -128 is outside the red zone",
                false,
                &[
                    0x48, 0x89, 0xbc, 0x24, 0x78, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x84, 0x24, 0x78,
                    0xff, 0xff, 0xff, 0xc3,
                ],
            ),
            (
                "an indexed access inside the red zone keeps the shape",
                true,
                &INDEXED_ARRAY_LOAD,
            ),
            (
                "an indexed access whose base displacement is past -128 is outside the red zone",
                false,
                &[
                    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x84, 0xfc, 0x78,
                    0xff, 0xff, 0xff, 0xc3,
                ],
            ),
        ];
        for (what, expected, code) in cases {
            let insns: Vec<DisasmInsn> =
                disassemble(Arch::X86_64, 0x9000, code).expect("disassemble red-zone probe");
            assert_eq!(
                sysv_red_zone_frame(&insns),
                expected,
                "{what}: {}",
                insns
                    .iter()
                    .map(|i: &DisasmInsn| format!("{} {}", i.mnemonic, i.operands))
                    .collect::<Vec<String>>()
                    .join("; ")
            );
        }
    }

    #[test]
    fn the_microsoft_x64_frame_classifier_never_reports_a_red_zone() {
        let code: [u8; 11] = [
            0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3,
        ];
        let insns: Vec<DisasmInsn> =
            disassemble(Arch::X86_64, 0x9100, &code).expect("disassemble red-zone probe");
        assert!(sysv_red_zone_frame(&insns));
        assert_eq!(
            classify_frame(&insns, Abi::SysV),
            FrameShape {
                base: Some(Reg::Rsp),
                rbp_is_frame: false,
                red_zone: true,
                stack_extent: None,
                stack_pointer_break: None,
            }
        );
        for abi in [Abi::MsX64, Abi::Aapcs64] {
            assert_eq!(
                classify_frame(&insns, abi),
                FrameShape {
                    base: None,
                    rbp_is_frame: false,
                    red_zone: false,
                    stack_extent: None,
                    stack_pointer_break: None,
                },
                "{abi:?} reserves nothing below the stack pointer"
            );
        }
    }

    #[test]
    fn a_red_zone_slot_at_the_exact_128_byte_boundary_is_modeled() {
        let code: [u8; 11] = [
            0x48, 0x89, 0x7c, 0x24, 0x80, 0x48, 0x8b, 0x44, 0x24, 0x80, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x8440, Abi::SysV)
            .expect("a slot at -128 is the last byte the red zone covers");
        assert!(
            rec.source.contains("unsigned char stack_frame[128];"),
            "the deepest legal red-zone slot must back the full 128 bytes: {}",
            rec.source
        );
    }

    #[test]
    fn an_access_past_the_128_byte_red_zone_is_rejected() {
        let code: [u8; 17] = [
            0x48, 0x89, 0xbc, 0x24, 0x78, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x84, 0x24, 0x78, 0xff,
            0xff, 0xff, 0xc3,
        ];
        let err: Error = recover_leaf_function_abi(&code, 0x8450, Abi::SysV)
            .expect_err("a slot at -136 is past the 128 bytes the red zone covers");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn a_red_zone_slot_whose_width_crosses_the_entry_stack_pointer_is_rejected() {
        let code: [u8; 11] = [
            0x48, 0x89, 0x7c, 0x24, 0xfc, 0x48, 0x8b, 0x44, 0x24, 0xfc, 0xc3,
        ];
        let err: Error = recover_leaf_function_abi(&code, 0x8460, Abi::SysV)
            .expect_err("an eight-byte slot at -4 overruns the return address at the entry rsp");
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("leaves the 128-byte System V red zone"),
            "the containment check must name the red zone it left: {message}"
        );
    }

    #[test]
    fn an_incoming_stack_argument_above_the_entry_stack_pointer_is_not_a_red_zone_slot() {
        let code: [u8; 6] = [0x48, 0x8b, 0x44, 0x24, 0x08, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0x8470, Abi::SysV)
            .expect_err("a load above the entry rsp reads an incoming argument, not a local slot");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn a_push_before_a_below_stack_pointer_store_disqualifies_the_red_zone() {
        let code: [u8; 13] = [
            0x55, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0x5d, 0xc3,
        ];
        let err: Error = recover_leaf_function_abi(&code, 0x8480, Abi::SysV)
            .expect_err("a push moves rsp, so the slot is not at a fixed entry-relative offset");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn taking_the_address_of_a_red_zone_slot_is_rejected() {
        let code: [u8; 9] = [0x48, 0x8d, 0x44, 0x24, 0xf8, 0x48, 0x8b, 0x00, 0xc3];
        let err: Error = recover_leaf_function_abi(&code, 0x8490, Abi::SysV)
            .expect_err("a leaked red-zone address is not a modelable fixed slot");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    const INDEXED_ARRAY_LOAD: [u8; 45] = [
        0x48, 0x89, 0x74, 0x24, 0xd8, 0x48, 0x89, 0x54, 0x24, 0xe0, 0x48, 0x01, 0xf2, 0x48, 0x89,
        0x54, 0x24, 0xe8, 0x48, 0xb8, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x48, 0x01,
        0xd0, 0x48, 0x89, 0x44, 0x24, 0xf0, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x44, 0xfc, 0xd8, 0xc3,
    ];

    fn disasm_text(code: &[u8], base: u64) -> String {
        disassemble(Arch::X86_64, base, code)
            .expect("disassemble indexed-frame probe")
            .iter()
            .map(|insn: &DisasmInsn| format!("{} {}", insn.mnemonic, insn.operands))
            .collect::<Vec<String>>()
            .join("; ")
    }

    #[test]
    fn an_indexed_region_over_a_fixed_read_of_the_return_address_is_rejected() {
        const RSP_CONSTANT_INDEXED_OVER_RETURN_ADDRESS: &[u8] = &[
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x3c, 0x24, 0x48, 0x89, 0x74, 0x24, 0x08, 0x48,
            0x89, 0x54, 0x24, 0x10, 0x4c, 0x8b, 0x44, 0x24, 0x18, 0x83, 0xe1, 0x03, 0x48, 0x8b,
            0x04, 0xcc, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let text: String = disasm_text(RSP_CONSTANT_INDEXED_OVER_RETURN_ADDRESS, 0x8600);
        assert!(
            text.contains("sub rsp,18h")
                && text.contains("[rsp+18h]")
                && text.contains("and ecx,3"),
            "the probe must allocate a frame, read the slot holding the return address and mask the index: {text}"
        );
        let outcome: Result<LeafRecovery> =
            recover_leaf_function_abi(RSP_CONSTANT_INDEXED_OVER_RETURN_ADDRESS, 0x8600, Abi::SysV);
        let Err(Error::LlvmIr(message)) = outcome else {
            panic!(
                "an indexed region may not span a fixed access that reads the return address, because the recovery would read an unwritten local where the machine reads the live return address"
            );
        };
        assert!(
            message.contains("sits on an allocated stack-pointer frame"),
            "the refusal must name the frame class that cannot prove the bytes are scratch: {message}"
        );
    }

    #[test]
    fn a_mask_bounded_indexed_red_zone_array_models_a_local_frame() {
        let text: String = disasm_text(&INDEXED_ARRAY_LOAD, 0x8500);
        assert!(
            text.contains("and edi,3") && text.contains("[rsp+rdi*8-28h]"),
            "the probe must carry a 32-bit mask on the index and an indexed rsp access: {text}"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&INDEXED_ARRAY_LOAD, 0x8500, Abi::SysV)
            .expect("a mask-bounded indexed red-zone array must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[40];"),
            "the four eight-byte elements must back exactly forty frame bytes: {}",
            rec.source
        );
        assert!(
            rec.source
                .contains("r_rsp = (uint64_t)(uintptr_t)(stack_frame + 40)"),
            "the entry stack pointer must aim at the top of the indexed frame: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rdi * 8ULL"),
            "the recovered load must keep the runtime index and its scale: {}",
            rec.source
        );
    }

    #[test]
    fn an_indexed_frame_access_without_a_proven_index_bound_is_rejected() {
        let code: [u8; 24] = [
            0x48, 0x89, 0x74, 0x24, 0xe8, 0x48, 0x89, 0x54, 0x24, 0xf0, 0x48, 0x01, 0xf2, 0x48,
            0x89, 0x54, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0xfc, 0xe8, 0xc3,
        ];
        let text: String = disasm_text(&code, 0x8510);
        assert!(
            text.contains("[rsp+rdi*8-18h]") && !text.contains("and edi"),
            "the probe must index the frame with an unmasked register: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8510, Abi::SysV)
            .expect_err("an unbounded index can leave the array, so the frame is not modelable");
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "an index with no proven bound must fall through to the frame rejection: {message}"
        );
    }

    #[test]
    fn an_indexed_frame_region_that_overruns_the_proven_frame_bytes_is_rejected() {
        let code: [u8; 19] = [
            0x48, 0x89, 0x74, 0x24, 0xe8, 0x48, 0x89, 0x54, 0x24, 0xf0, 0x83, 0xe7, 0x03, 0x48,
            0x8b, 0x44, 0xfc, 0xe8, 0xc3,
        ];
        let text: String = disasm_text(&code, 0x8520);
        assert!(
            text.contains("and edi,3") && text.contains("[rsp+rdi*8-18h]"),
            "the probe must mask to four elements over only two proven slots: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8520, Abi::SysV).expect_err(
            "four elements from -24 reach past the entry stack pointer into the return address",
        );
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("is not contained in the frame bytes"),
            "the containment check must name the region it could not bound: {message}"
        );
    }

    #[test]
    fn two_indexed_accesses_to_one_region_at_different_element_widths_are_rejected() {
        let code: [u8; 41] = [
            0x48, 0x89, 0x74, 0x24, 0xd8, 0x48, 0x89, 0x54, 0x24, 0xe0, 0x48, 0x8d, 0x04, 0x32,
            0x48, 0x89, 0x44, 0x24, 0xe8, 0x48, 0x31, 0xf2, 0x48, 0x89, 0x54, 0x24, 0xf0, 0x83,
            0xe7, 0x03, 0x48, 0x63, 0x44, 0xbc, 0xd8, 0x48, 0x03, 0x44, 0xfc, 0xd8, 0xc3,
        ];
        let text: String = disasm_text(&code, 0x8530);
        assert!(
            text.contains("[rsp+rdi*4-28h]") && text.contains("[rsp+rdi*8-28h]"),
            "the probe must read one region as four-byte and as eight-byte elements: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8530, Abi::SysV)
            .expect_err("one region cannot have two element widths");
        let Error::LlvmIr(message) = err else {
            panic!("expected a lifter rejection");
        };
        assert!(
            message.contains("different element shapes"),
            "the element-shape check must name the conflict: {message}"
        );
    }

    #[test]
    fn an_index_scaled_against_the_element_width_is_rejected() {
        let mut code: [u8; 45] = INDEXED_ARRAY_LOAD;
        code[42] = 0xbc;
        let text: String = disasm_text(&code, 0x8540);
        assert!(
            text.contains("mov rax,[rsp+rdi*4-28h]"),
            "the probe must load eight bytes at a four-byte stride: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8540, Abi::SysV)
            .expect_err("a stride that disagrees with the element width is not an array");
        assert!(
            format!("{err}").contains("escapes a fixed-offset slot access"),
            "the shape must be refused as an unmodelable frame access, got {err}"
        );
    }

    #[test]
    fn a_sixteen_bit_mask_does_not_bound_the_index_register() {
        let mut code: Vec<u8> = INDEXED_ARRAY_LOAD.to_vec();
        code.insert(36, 0x66);
        let text: String = disasm_text(&code, 0x8550);
        assert!(
            text.contains("and di,3") && text.contains("[rsp+rdi*8-28h]"),
            "the probe must mask only the low sixteen bits of the index: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8550, Abi::SysV)
            .expect_err("a 16-bit and keeps the upper 48 bits of the index");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn a_mask_after_the_indexed_access_does_not_bound_it() {
        let mut code: Vec<u8> = Vec::with_capacity(INDEXED_ARRAY_LOAD.len());
        code.extend_from_slice(&INDEXED_ARRAY_LOAD[..36]);
        code.extend_from_slice(&INDEXED_ARRAY_LOAD[39..44]);
        code.extend_from_slice(&INDEXED_ARRAY_LOAD[36..39]);
        code.push(0xc3);
        let text: String = disasm_text(&code, 0x8560);
        assert!(
            text.ends_with("and edi,3; ret "),
            "the probe must mask the index only after the indexed access: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8560, Abi::SysV)
            .expect_err("a bound established after the access does not hold at the access");
        assert!(
            format!("{err}").contains("escapes a fixed-offset slot access"),
            "the shape must be refused as an unmodelable frame access, got {err}"
        );
    }

    #[test]
    fn a_write_to_the_index_register_after_the_mask_drops_the_bound() {
        let mut code: Vec<u8> = INDEXED_ARRAY_LOAD.to_vec();
        code.splice(39..39, [0x48, 0x01, 0xf7]);
        let text: String = disasm_text(&code, 0x8570);
        assert!(
            text.contains("and edi,3; add rdi,rsi; mov rax,[rsp+rdi*8-28h]"),
            "the probe must widen the index again between the mask and the access: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8570, Abi::SysV)
            .expect_err("an add after the mask leaves the index unbounded again");
        assert!(matches!(err, Error::LlvmIr(_)));
    }

    #[test]
    fn a_masked_index_past_the_element_cap_is_rejected() {
        let mut code: Vec<u8> = Vec::with_capacity(INDEXED_ARRAY_LOAD.len() + 3);
        code.extend_from_slice(&INDEXED_ARRAY_LOAD[..36]);
        code.extend_from_slice(&[0x81, 0xe7, 0xff, 0xff, 0x00, 0x00]);
        code.extend_from_slice(&INDEXED_ARRAY_LOAD[39..]);
        let text: String = disasm_text(&code, 0x8580);
        assert!(
            text.contains("and edi,0FFFFh") && text.contains("[rsp+rdi*8-28h]"),
            "the probe must bound the index to 65536 elements: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8580, Abi::SysV)
            .expect_err("65536 elements is past the modelable element cap");
        assert!(
            format!("{err}").contains("escapes a fixed-offset slot access"),
            "the shape must be refused as an unmodelable frame access, got {err}"
        );
    }

    #[test]
    fn taking_the_address_of_an_indexed_frame_element_is_rejected() {
        let mut code: Vec<u8> = INDEXED_ARRAY_LOAD.to_vec();
        code.splice(39..44, [0x48, 0x8d, 0x44, 0xfc, 0xd8]);
        let text: String = disasm_text(&code, 0x8590);
        assert!(
            text.contains("lea rax,[rsp+rdi*8-28h]"),
            "the probe must take the address of an indexed frame element: {text}"
        );
        let err: Error = recover_leaf_function_abi(&code, 0x8590, Abi::SysV)
            .expect_err("a leaked indexed frame address is not a modelable region");
        assert!(
            format!("{err}").contains("escapes a fixed-offset slot access"),
            "the shape must be refused as an unmodelable frame access, got {err}"
        );
    }

    #[test]
    fn a_four_byte_indexed_red_zone_array_models_its_own_stride() {
        let code: [u8; 29] = [
            0x89, 0x74, 0x24, 0xe8, 0x89, 0x54, 0x24, 0xec, 0x8d, 0x04, 0x32, 0x89, 0x44, 0x24,
            0xf0, 0x31, 0xf2, 0x89, 0x54, 0x24, 0xf4, 0x83, 0xe7, 0x03, 0x8b, 0x44, 0xbc, 0xe8,
            0xc3,
        ];
        let text: String = disasm_text(&code, 0x85a0);
        assert!(
            text.contains("and edi,3") && text.contains("mov eax,[rsp+rdi*4-18h]"),
            "the probe must index four-byte elements at a four-byte stride: {text}"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x85a0, Abi::SysV)
            .expect("a four-byte indexed red-zone array must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[24];"),
            "four four-byte elements must back exactly twenty-four frame bytes: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rdi * 4ULL"),
            "the recovered load must keep the four-byte stride: {}",
            rec.source
        );
    }

    #[test]
    fn an_indexed_store_into_a_mask_bounded_red_zone_array_models_a_local_frame() {
        let code: [u8; 84] = [
            0x48, 0x89, 0x74, 0x24, 0xd8, 0x48, 0x89, 0x54, 0x24, 0xe0, 0x48, 0x89, 0xd0, 0x48,
            0x31, 0xf0, 0x48, 0x89, 0x44, 0x24, 0xe8, 0x48, 0x8d, 0x04, 0x32, 0x48, 0x89, 0x44,
            0x24, 0xf0, 0x48, 0x0f, 0xaf, 0xd6, 0x48, 0xff, 0xc2, 0x83, 0xe7, 0x03, 0x48, 0x89,
            0x54, 0xfc, 0xd8, 0x48, 0x8b, 0x44, 0x24, 0xe0, 0x48, 0x8b, 0x4c, 0x24, 0xe8, 0x48,
            0x8d, 0x04, 0x40, 0x48, 0x03, 0x44, 0x24, 0xd8, 0x48, 0x8d, 0x0c, 0x89, 0x48, 0x01,
            0xc1, 0x48, 0x8b, 0x54, 0x24, 0xf0, 0x48, 0x8d, 0x04, 0xd1, 0x48, 0x29, 0xd0, 0xc3,
        ];
        let text: String = disasm_text(&code, 0x85b0);
        assert!(
            text.contains("and edi,3") && text.contains("mov [rsp+rdi*8-28h],rdx"),
            "the probe must store through the masked index: {text}"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x85b0, Abi::SysV)
            .expect("an indexed store into a mask-bounded red-zone array must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[40];"),
            "the four eight-byte elements must back exactly forty frame bytes: {}",
            rec.source
        );
    }

    #[test]
    fn movsxd_sign_extends_a_dword_red_zone_slot() {
        let code: [u8; 10] = [0x89, 0x7c, 0x24, 0xfc, 0x48, 0x63, 0x44, 0x24, 0xfc, 0xc3];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x84a0, Abi::SysV)
            .expect("movsxd from a red-zone dword slot must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[4];"),
            "a dword slot at -4 must back exactly four red-zone bytes: {}",
            rec.source
        );
        assert!(
            rec.source.contains("(int64_t)(int32_t)"),
            "movsxd must sign-extend the reloaded dword: {}",
            rec.source
        );
    }

    const RZ_PICK8_FRAME_POINTER: [u8; 71] = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x89, 0x55,
        0xe8, 0x48, 0x89, 0x4d, 0xe0, 0x4c, 0x89, 0x45, 0xd8, 0x48, 0x8b, 0x45, 0xf0, 0x48, 0x89,
        0x45, 0xb0, 0x48, 0x8b, 0x45, 0xe8, 0x48, 0x89, 0x45, 0xb8, 0x48, 0x8b, 0x45, 0xe0, 0x48,
        0x89, 0x45, 0xc0, 0x48, 0x8b, 0x45, 0xd8, 0x48, 0x89, 0x45, 0xc8, 0x48, 0x8b, 0x45, 0xf8,
        0x48, 0x83, 0xe0, 0x03, 0x48, 0x8b, 0x44, 0xc5, 0xb0, 0x5d, 0xc3,
    ];

    const RZ_PICK8_RED_ZONE_LEAF: [u8; 29] = [
        0x48, 0x89, 0x74, 0x24, 0xd8, 0x48, 0x89, 0x54, 0x24, 0xe0, 0x48, 0x89, 0x4c, 0x24, 0xe8,
        0x4c, 0x89, 0x44, 0x24, 0xf0, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x44, 0xfc, 0xd8, 0xc3,
    ];

    const RZ_PICK8_ALLOCATED_FRAME: [u8; 40] = [
        0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44, 0x24, 0x50, 0x48, 0x89, 0x14, 0x24, 0x4c, 0x89,
        0x44, 0x24, 0x08, 0x4c, 0x89, 0x4c, 0x24, 0x10, 0x48, 0x89, 0x44, 0x24, 0x18, 0x83, 0xe1,
        0x03, 0x48, 0x8b, 0x04, 0xcc, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ];

    fn frame_class_of(code: &[u8], abi: Abi) -> FrameClass {
        let insns: Vec<DisasmInsn> =
            disassemble(Arch::X86_64, 0x9200, code).expect("disassemble frame-class probe");
        classify_frame(&insns, abi).class()
    }

    fn rejection_message(code: &[u8], abi: Abi, why: &str) -> String {
        let err: Error =
            recover_leaf_function_abi(code, 0x9200, abi).expect_err(&format!("{why}: {abi:?}"));
        let Error::LlvmIr(message) = err else {
            panic!("{why}: expected a lifter rejection, got a different error kind");
        };
        message
    }

    #[test]
    fn every_frame_class_either_admits_indexed_modelling_or_names_why_it_refuses() {
        assert_eq!(
            FrameClass::ALL.len(),
            4,
            "the enumeration below decides one row per frame class; a new class needs a new row"
        );
        let mut admitted: Vec<FrameClass> = Vec::new();
        for class in FrameClass::ALL {
            let refusal: Option<&'static str> = class.indexed_refusal();
            match class {
                FrameClass::SysvRedZoneLeaf => {
                    assert_eq!(
                        refusal, None,
                        "the System V red-zone leaf is the graded class and must admit indexed modelling"
                    );
                    assert_eq!(
                        frame_class_of(&RZ_PICK8_RED_ZONE_LEAF, Abi::SysV),
                        class,
                        "the graded row must really classify as this class"
                    );
                    admitted.push(class);
                }
                FrameClass::FramePointer => {
                    assert!(
                        refusal.is_some(),
                        "a refused class must name the reason it refuses"
                    );
                    assert_eq!(frame_class_of(&RZ_PICK8_FRAME_POINTER, Abi::SysV), class);
                }
                FrameClass::AllocatedStackPointer => {
                    assert!(
                        refusal.is_some(),
                        "a refused class must name the reason it refuses"
                    );
                    assert_eq!(frame_class_of(&RZ_PICK8_ALLOCATED_FRAME, Abi::MsX64), class);
                }
                FrameClass::NoFrame => {
                    assert!(
                        refusal.is_some(),
                        "a refused class must name the reason it refuses"
                    );
                    assert_eq!(frame_class_of(&RZ_PICK8_RED_ZONE_LEAF, Abi::MsX64), class);
                }
            }
        }
        assert_eq!(
            admitted,
            vec![FrameClass::SysvRedZoneLeaf],
            "exactly one frame class admits indexed modelling"
        );
    }

    #[test]
    fn the_frame_pointer_class_refuses_an_indexed_frame_access_by_name() {
        let text: String = disasm_text(&RZ_PICK8_FRAME_POINTER, 0x9200);
        assert!(
            text.contains("mov rbp,rsp") && text.contains("mov rax,[rbp+rax*8-50h]"),
            "the probe must build a frame pointer and index off it: {text}"
        );
        let message: String = rejection_message(
            &RZ_PICK8_FRAME_POINTER,
            Abi::SysV,
            "a frame-pointer frame does not prove its indexed bytes are function scratch",
        );
        assert!(
            message.contains("sits on a frame-pointer frame"),
            "the refusal must name the frame class: {message}"
        );
    }

    #[test]
    fn the_allocated_stack_pointer_class_refuses_an_indexed_frame_access_by_name() {
        let text: String = disasm_text(&RZ_PICK8_ALLOCATED_FRAME, 0x9200);
        assert!(
            text.contains("sub rsp,28h")
                && text.contains("mov rax,[rsp+50h]")
                && text.contains("mov rax,[rsp+rcx*8]"),
            "the probe must allocate a frame, read an incoming stack argument and index the frame: {text}"
        );
        for abi in [Abi::MsX64, Abi::SysV] {
            let message: String = rejection_message(
                &RZ_PICK8_ALLOCATED_FRAME,
                abi,
                "an allocated frame does not prove its indexed bytes are function scratch",
            );
            assert!(
                message.contains("sits on an allocated stack-pointer frame"),
                "the refusal must name the frame class under {abi:?}: {message}"
            );
        }
    }

    #[test]
    fn the_no_frame_class_never_forms_an_indexed_region_at_all() {
        assert_eq!(
            frame_class_of(&RZ_PICK8_RED_ZONE_LEAF, Abi::MsX64),
            FrameClass::NoFrame
        );
        let shape: FrameShape = FrameShape {
            base: None,
            rbp_is_frame: false,
            red_zone: false,
            stack_extent: None,
            stack_pointer_break: None,
        };
        assert_eq!(shape.class(), FrameClass::NoFrame);
        let ctx: FrameScan = FrameScan {
            frame_base: shape.base,
            rbp_is_frame: shape.rbp_is_frame,
            indexed: IndexedModelling::decide(shape, false),
        };
        let mut state: FrameScanState = FrameScanState::default();
        state.bounds.insert(Reg::Rdi, 3);
        ctx.note_mem(&indexed_frame_mem(Reg::Rsp, Reg::Rdi, 8, -40), &mut state);
        assert!(
            state.regions.is_empty() && state.indexed_refusal.is_none(),
            "a class with no frame base cannot match the frame base, so no indexed region and no indexed refusal can arise: {state:?}"
        );
        let message: String = rejection_message(
            &RZ_PICK8_RED_ZONE_LEAF,
            Abi::MsX64,
            "Microsoft x64 reserves nothing below the stack pointer",
        );
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "the no-frame rejection stays the general frame rejection: {message}"
        );
    }

    #[test]
    fn one_source_is_a_red_zone_leaf_under_system_v_and_an_allocated_frame_under_microsoft_x64() {
        assert_eq!(
            frame_class_of(&RZ_PICK8_RED_ZONE_LEAF, Abi::SysV),
            FrameClass::SysvRedZoneLeaf
        );
        assert_eq!(
            frame_class_of(&RZ_PICK8_ALLOCATED_FRAME, Abi::MsX64),
            FrameClass::AllocatedStackPointer
        );
        let rec: LeafRecovery =
            recover_leaf_function_abi(&RZ_PICK8_RED_ZONE_LEAF, 0x9200, Abi::SysV)
                .expect("the System V lowering of the array pick must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[40];")
                && rec.source.contains("r_rdi * 8ULL"),
            "the red-zone lowering must recover the array and keep its stride: {}",
            rec.source
        );
        let message: String = rejection_message(
            &RZ_PICK8_ALLOCATED_FRAME,
            Abi::MsX64,
            "the Microsoft x64 lowering of the same source allocates a frame",
        );
        assert!(
            message.contains("sits on an allocated stack-pointer frame"),
            "the same source refuses under the other ABI, by class: {message}"
        );
    }

    #[test]
    fn a_one_element_indexed_region_keeps_its_stride_instead_of_collapsing_to_a_scalar_slot() {
        const SINGLE_ELEMENT: [u8; 14] = [
            0x48, 0x89, 0x7c, 0x24, 0xf8, 0x83, 0xe7, 0x00, 0x48, 0x8b, 0x44, 0xfc, 0xf8, 0xc3,
        ];
        let text: String = disasm_text(&SINGLE_ELEMENT, 0x9200);
        assert!(
            text.contains("and edi,0") && text.contains("mov rax,[rsp+rdi*8-8]"),
            "the probe must bound the index to a single element: {text}"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&SINGLE_ELEMENT, 0x9200, Abi::SysV)
            .expect("a one-element indexed region must lift");
        assert!(
            rec.source.contains("r_rdi * 8ULL"),
            "a one-element region stays an indexed access and must not collapse to a scalar slot: {}",
            rec.source
        );
        assert!(
            rec.source.contains("unsigned char stack_frame[8];"),
            "one eight-byte element backs exactly eight frame bytes: {}",
            rec.source
        );
    }

    #[test]
    fn a_mask_of_zero_bounds_an_indexed_region_to_one_element_not_to_none() {
        let mut state: FrameScanState = FrameScanState::default();
        state.bounds.insert(Reg::Rdi, 0);
        let ctx: FrameScan = red_zone_scan();
        let region: IndexedRegion = ctx
            .indexed_region(
                &indexed_frame_mem(Reg::Rsp, Reg::Rdi, 8, -8),
                IndexOperand::full(Reg::Rdi, 8),
                &state.bounds,
            )
            .expect("a zero mask proves a single reachable index");
        assert_eq!(
            (region.elements, region.disp, region.end),
            (1, -8, 0),
            "a highest reachable index of zero is one element, never zero elements"
        );
    }

    #[test]
    fn an_indexed_region_whose_span_overflows_the_offset_space_is_refused() {
        let mut state: FrameScanState = FrameScanState::default();
        state.bounds.insert(Reg::Rdi, 255);
        let ctx: FrameScan = red_zone_scan();
        assert_eq!(
            ctx.indexed_region(
                &indexed_frame_mem(Reg::Rsp, Reg::Rdi, 8, i64::MAX - 8),
                IndexOperand::full(Reg::Rdi, 8),
                &state.bounds,
            ),
            None,
            "an element count times a stride that runs past the offset space cannot name an extent"
        );
        state.bounds.insert(Reg::Rdi, u64::MAX);
        assert_eq!(
            ctx.indexed_region(
                &indexed_frame_mem(Reg::Rsp, Reg::Rdi, 8, 0),
                IndexOperand::full(Reg::Rdi, 8),
                &state.bounds,
            ),
            None,
            "an index bound of the whole unsigned range overflows the element count itself"
        );
    }

    #[test]
    fn an_indexed_region_at_the_red_zone_boundary_is_modeled_and_one_past_it_is_refused() {
        const AT_BOUNDARY: [u8; 29] = [
            0x48, 0x89, 0x74, 0x24, 0x80, 0x48, 0x89, 0x54, 0x24, 0x88, 0x48, 0x89, 0x4c, 0x24,
            0x90, 0x4c, 0x89, 0x44, 0x24, 0x98, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x44, 0xfc, 0x80,
            0xc3,
        ];
        const ONE_BYTE_PAST_BOUNDARY: [u8; 44] = [
            0x48, 0x89, 0xb4, 0x24, 0x7f, 0xff, 0xff, 0xff, 0x48, 0x89, 0x94, 0x24, 0x87, 0xff,
            0xff, 0xff, 0x48, 0x89, 0x8c, 0x24, 0x8f, 0xff, 0xff, 0xff, 0x4c, 0x89, 0x84, 0x24,
            0x97, 0xff, 0xff, 0xff, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x84, 0xfc, 0x7f, 0xff, 0xff,
            0xff, 0xc3,
        ];
        let at_text: String = disasm_text(&AT_BOUNDARY, 0x9200);
        assert!(
            at_text.contains("mov rax,[rsp+rdi*8-80h]"),
            "the probe must start the region at exactly -128: {at_text}"
        );
        assert_eq!(
            frame_class_of(&AT_BOUNDARY, Abi::SysV),
            FrameClass::SysvRedZoneLeaf
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&AT_BOUNDARY, 0x9200, Abi::SysV)
            .expect("a region starting at the last byte the red zone covers must lift");
        assert!(
            rec.source.contains("unsigned char stack_frame[128];"),
            "the region at -128 must back the full 128 red-zone bytes: {}",
            rec.source
        );

        let past_text: String = disasm_text(&ONE_BYTE_PAST_BOUNDARY, 0x9200);
        assert!(
            past_text.contains("mov rax,[rsp+rdi*8-81h]"),
            "the probe must start the region at -129, exactly one byte below the red zone: {past_text}"
        );
        assert_eq!(
            frame_class_of(&ONE_BYTE_PAST_BOUNDARY, Abi::SysV),
            FrameClass::NoFrame,
            "one byte below -128 already takes the function out of the red-zone class"
        );
        let message: String = rejection_message(
            &ONE_BYTE_PAST_BOUNDARY,
            Abi::SysV,
            "a region starting one byte below -128 leaves the red zone",
        );
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "a function that is no longer a red-zone leaf is refused as an unmodelable frame: {message}"
        );
    }

    #[test]
    fn an_indexed_region_that_abuts_the_return_address_slot_is_modeled() {
        const ABUTTING: [u8; 29] = [
            0x48, 0x89, 0x74, 0x24, 0xe0, 0x48, 0x89, 0x54, 0x24, 0xe8, 0x48, 0x89, 0x4c, 0x24,
            0xf0, 0x4c, 0x89, 0x44, 0x24, 0xf8, 0x83, 0xe7, 0x03, 0x48, 0x8b, 0x44, 0xfc, 0xe0,
            0xc3,
        ];
        let text: String = disasm_text(&ABUTTING, 0x9200);
        assert!(
            text.contains("mov [rsp-8],r8") && text.contains("mov rax,[rsp+rdi*8-20h]"),
            "the probe must end the region on the entry stack pointer: {text}"
        );
        let rec: LeafRecovery = recover_leaf_function_abi(&ABUTTING, 0x9200, Abi::SysV)
            .expect("a region ending exactly at the entry stack pointer touches no caller byte");
        assert!(
            rec.source.contains("unsigned char stack_frame[32];"),
            "four eight-byte elements ending at the entry stack pointer back 32 bytes: {}",
            rec.source
        );
        assert!(
            rec.source.contains("r_rdi * 8ULL"),
            "the abutting region stays an indexed access: {}",
            rec.source
        );
    }

    #[test]
    fn writing_the_frame_base_inside_the_body_takes_the_function_out_of_the_red_zone_class() {
        let mut code: Vec<u8> = RZ_PICK8_RED_ZONE_LEAF[..RZ_PICK8_RED_ZONE_LEAF.len() - 1].to_vec();
        code.extend_from_slice(&[0x48, 0x83, 0xc4, 0x08, 0xc3]);
        let text: String = disasm_text(&code, 0x9200);
        assert!(
            text.contains("mov rax,[rsp+rdi*8-28h]") && text.contains("add rsp,8"),
            "the probe must move the frame base after the indexed access: {text}"
        );
        assert_eq!(
            frame_class_of(&code, Abi::SysV),
            FrameClass::NoFrame,
            "a body that moves the stack pointer has no constant frame base"
        );
        let message: String = rejection_message(
            &code,
            Abi::SysV,
            "an unstable frame base cannot anchor an indexed region",
        );
        assert!(
            message.contains("escapes a fixed-offset slot access"),
            "the unstable base must be refused as an unmodelable frame: {message}"
        );
    }

    #[test]
    fn an_unstructured_edge_refuses_indexed_modelling_by_name() {
        let shape: FrameShape = FrameShape {
            base: Some(Reg::Rsp),
            rbp_is_frame: false,
            red_zone: true,
            stack_extent: None,
            stack_pointer_break: None,
        };
        assert_eq!(shape.class(), FrameClass::SysvRedZoneLeaf);
        assert_eq!(
            IndexedModelling::decide(shape, false),
            IndexedModelling::Allowed,
            "the admitted class with a structured body admits indexed modelling"
        );
        let refused: IndexedModelling = IndexedModelling::decide(shape, true);
        assert_eq!(refused, IndexedModelling::RefusedByUnstructuredEdge);
        assert!(
            refused
                .refusal()
                .is_some_and(|reason: &str| reason.contains("unstructured edge")),
            "the unstructured-edge refusal must name its own reason: {refused:?}"
        );
        let body: Block = vec![
            Node::Label(0x9200),
            Node::Stmt(indexed_frame_load(Reg::Rdi, 8, -40)),
            Node::Goto(0x9200),
        ];
        assert!(block_has_unstructured_edge(&body));
        let err: Error =
            plan_frame(&body, shape).expect_err("an unstructured edge refuses indexed modelling");
        assert!(
            format!("{err}").contains("unstructured edge"),
            "the plan must carry the unstructured-edge reason: {err}"
        );
    }

    #[test]
    fn the_frame_class_gate_is_what_stops_the_allocated_frame_region_from_forming() {
        let body: Block = vec![Node::Stmt(indexed_frame_load(Reg::Rdi, 8, -40))];
        let allowed: FrameScan = FrameScan {
            frame_base: Some(Reg::Rsp),
            rbp_is_frame: false,
            indexed: IndexedModelling::Allowed,
        };
        let refused: FrameScan = FrameScan {
            indexed: IndexedModelling::RefusedByFrameClass(FrameClass::AllocatedStackPointer),
            ..allowed
        };
        let mut open: FrameScanState = FrameScanState::default();
        open.bounds.insert(Reg::Rdi, 3);
        scan_frame_block(allowed, &body, &mut open);
        assert_eq!(
            open.regions.len(),
            1,
            "without the class gate the same body yields a modelable indexed region: {open:?}"
        );
        let mut gated: FrameScanState = FrameScanState::default();
        gated.bounds.insert(Reg::Rdi, 3);
        scan_frame_block(refused, &body, &mut gated);
        assert!(
            gated.regions.is_empty() && gated.misuse,
            "the class gate is the single reason the region does not form: {gated:?}"
        );
        assert_eq!(
            gated.indexed_refusal,
            FrameClass::AllocatedStackPointer.indexed_refusal(),
            "the refusal recorded must be the one the class names"
        );
    }

    fn red_zone_scan() -> FrameScan {
        FrameScan {
            frame_base: Some(Reg::Rsp),
            rbp_is_frame: false,
            indexed: IndexedModelling::Allowed,
        }
    }

    const fn indexed_frame_mem(base: Reg, index: Reg, scale: u8, disp: i64) -> MemRef {
        MemRef {
            base: Some(base),
            index: Some(IndexOperand::full(index, scale)),
            disp,
            width: Width::W64,
        }
    }

    fn indexed_frame_load(index: Reg, scale: u8, disp: i64) -> Stmt {
        Stmt::Assign {
            dest: RegRef {
                reg: Reg::Rax,
                width: Width::W64,
            },
            src: Source::Mem(indexed_frame_mem(Reg::Rsp, index, scale, disp)),
        }
    }

    const SYSV_MK3_SRET: [u8; 29] = [
        0x48, 0x89, 0xf8, 0x48, 0x8d, 0x0c, 0x32, 0x48, 0x89, 0x0f, 0x48, 0x89, 0xf1, 0x48, 0x29,
        0xd1, 0x48, 0x89, 0x4f, 0x08, 0x48, 0x0f, 0xaf, 0xd6, 0x48, 0x89, 0x57, 0x10, 0xc3,
    ];

    #[test]
    fn sysv_memory_class_struct_return_lifts_to_by_value_struct() {
        let rec: LeafRecovery = recover_leaf_function_abi(&SYSV_MK3_SRET, 0x1000, Abi::SysV)
            .expect("a three-qword sret leaf must lift");
        let sret: &SretReturn = rec.sret.as_ref().expect("must be recognized as sret");
        assert_eq!(sret.field_widths, vec![8, 8, 8]);
        assert_eq!(sret.size, 24);
        assert_eq!(
            rec.params,
            vec![Reg::Rsi, Reg::Rdx],
            "the hidden pointer in rdi must be dropped, leaving the two real args"
        );
        assert!(
            rec.source
                .contains("typedef struct {\n    uint64_t f0;\n    uint64_t f1;\n    uint64_t f2;\n} recovered_sret_t;"),
            "the reconstructed struct type must be emitted: {}",
            rec.source
        );
        assert!(
            rec.source.contains("recovered_sret_t recovered("),
            "the recovered function must return the struct by value: {}",
            rec.source
        );
        assert!(
            rec.source.contains("recovered_sret_t __sret;")
                && rec.source.contains("r_rdi = (uint64_t)(uintptr_t)&__sret;")
                && rec.source.contains("return __sret;"),
            "the hidden pointer must target the local struct and be returned by value: {}",
            rec.source
        );
    }

    const MSX64_MK3_SRET: [u8; 29] = [
        0x48, 0x89, 0xc8, 0x4a, 0x8d, 0x0c, 0x02, 0x48, 0x89, 0x08, 0x48, 0x89, 0xd1, 0x4c, 0x29,
        0xc1, 0x48, 0x89, 0x48, 0x08, 0x49, 0x0f, 0xaf, 0xd0, 0x48, 0x89, 0x50, 0x10, 0xc3,
    ];

    #[test]
    fn msx64_memory_class_struct_return_drops_hidden_rcx() {
        let rec: LeafRecovery = recover_leaf_function_abi(&MSX64_MK3_SRET, 0x1000, Abi::MsX64)
            .expect("an msx64 sret leaf must lift");
        let sret: &SretReturn = rec.sret.as_ref().expect("must be recognized as sret");
        assert_eq!(sret.field_widths, vec![8, 8, 8]);
        assert_eq!(sret.size, 24);
        assert_eq!(
            rec.params,
            vec![Reg::Rdx, Reg::R8],
            "the hidden pointer copied out of rcx must be dropped for the win64 ABI"
        );
        assert!(
            rec.source.contains("recovered_sret_t recovered(")
                && rec.source.contains("return __sret;"),
            "win64 sret must reconstruct a by-value struct return: {}",
            rec.source
        );
    }

    #[test]
    fn two_qword_fill_is_register_class_not_sret_on_sysv() {
        let code: [u8; 11] = [
            0x48, 0x89, 0xf8, 0x48, 0x89, 0x37, 0x48, 0x89, 0x57, 0x08, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&code, 0x1000, Abi::SysV)
            .expect("a two-qword pointer fill still lifts");
        assert!(
            rec.sret.is_none(),
            "a 16-byte fill is SysV register class, not a hidden-pointer sret: {}",
            rec.source
        );
    }

    #[test]
    fn switch_body_flags_writer_between_compare_and_setcc_rejects() {
        let di = |address: u64, mnemonic: &str, operands: &str| -> DisasmInsn {
            DisasmInsn {
                address,
                bytes: Vec::new(),
                mnemonic: mnemonic.to_owned(),
                operands: operands.to_owned(),
            }
        };

        let baseline: [DisasmInsn; 2] = [di(0, "cmp", "rcx, rdx"), di(1, "setl", "bl")];
        let folded: Vec<Stmt> = lift_stmt_range(&baseline, 0, baseline.len(), &[])
            .expect("a compare then setl folds the comparison");
        assert!(
            matches!(folded.as_slice(), [Stmt::SetCc { .. }]),
            "baseline cmp then setl must fold to a SetCc: {folded:?}"
        );

        let clobbered: [DisasmInsn; 3] = [
            di(0, "cmp", "rcx, rdx"),
            di(1, "xor", "eax, eax"),
            di(2, "setl", "bl"),
        ];
        assert!(
            lift_stmt_range(&clobbered, 0, clobbered.len(), &[]).is_err(),
            "a flags-writing xor zero-idiom between the compare and the setl overwrites the flags register, so the setl must reject rather than fold the stale comparison"
        );

        let unrelated: [DisasmInsn; 3] = [
            di(0, "cmp", "rcx, rdx"),
            di(1, "mov", "eax, esi"),
            di(2, "setl", "bl"),
        ];
        let still_folds: Vec<Stmt> = lift_stmt_range(&unrelated, 0, unrelated.len(), &[])
            .expect("a non-flag-writing mov to an unrelated register keeps the tracked comparison");
        assert!(
            still_folds
                .iter()
                .any(|s: &Stmt| matches!(s, Stmt::SetCc { .. })),
            "a mov that writes neither the flags register nor a compare operand must leave the setl folding: {still_folds:?}"
        );

        let stack_adjust: [DisasmInsn; 3] = [
            di(0, "cmp", "rcx, rdx"),
            di(1, "sub", "rsp, 8"),
            di(2, "setl", "bl"),
        ];
        assert!(
            lift_stmt_range(&stack_adjust, 0, stack_adjust.len(), &[]).is_err(),
            "a stack adjustment takes the ignorable path but still writes the flags register, so the setl must reject rather than fold the stale comparison"
        );

        let padding: [DisasmInsn; 3] = [
            di(0, "cmp", "rcx, rdx"),
            di(1, "nop", ""),
            di(2, "setl", "bl"),
        ];
        let nop_folds: Vec<Stmt> = lift_stmt_range(&padding, 0, padding.len(), &[])
            .expect("an ignorable nop that writes no flags keeps the tracked comparison");
        assert!(
            nop_folds
                .iter()
                .any(|s: &Stmt| matches!(s, Stmt::SetCc { .. })),
            "an ignorable nop between the compare and the setl must leave the setl folding: {nop_folds:?}"
        );
    }

    #[test]
    fn switch_body_store_aliasing_a_memory_compare_rejects() {
        let di = |address: u64, mnemonic: &str, operands: &str| -> DisasmInsn {
            DisasmInsn {
                address,
                bytes: Vec::new(),
                mnemonic: mnemonic.to_owned(),
                operands: operands.to_owned(),
            }
        };

        let aliased: [DisasmInsn; 3] = [
            di(0, "cmp", "[rdi], eax"),
            di(1, "mov", "[rdi], ebx"),
            di(2, "setl", "bl"),
        ];
        assert!(
            lift_stmt_range(&aliased, 0, aliased.len(), &[]).is_err(),
            "a store overwriting the compared memory cell must reject rather than fold the pre-store value"
        );

        let disjoint_slot: [DisasmInsn; 3] = [
            di(0, "cmp", "[rsp+8], eax"),
            di(1, "mov", "[rsp+16], ebx"),
            di(2, "setl", "bl"),
        ];
        let folds: Vec<Stmt> = lift_stmt_range(&disjoint_slot, 0, disjoint_slot.len(), &[]).expect(
            "a store to a provably disjoint same-base slot keeps the tracked memory compare",
        );
        assert!(
            folds.iter().any(|s: &Stmt| matches!(s, Stmt::SetCc { .. })),
            "a store to a disjoint stack slot must leave the memory compare folding: {folds:?}"
        );

        let different_base: [DisasmInsn; 3] = [
            di(0, "cmp", "[rdi], eax"),
            di(1, "mov", "[rsi], ebx"),
            di(2, "setl", "bl"),
        ];
        assert!(
            lift_stmt_range(&different_base, 0, different_base.len(), &[]).is_err(),
            "a store through a different base register may alias the compared cell and must conservatively reject"
        );
    }

    #[test]
    fn fp_equality_rendering_follows_the_unordered_model() {
        let x86: FpUnorderedModel = FpUnorderedModel::UnorderedIsEqual;
        let a64: FpUnorderedModel = FpUnorderedModel::UnorderedIsUnequal;

        assert_eq!(
            fp_compare_c(CondKind::E, "x", "y", false, x86),
            "!((x) < (y)) && !((x) > (y))"
        );
        assert_eq!(
            fp_compare_c(CondKind::Ne, "x", "y", false, x86),
            "(x) < (y) || (x) > (y)"
        );
        assert_eq!(
            fp_compare_c(CondKind::E, "x", "y", false, a64),
            "(x) == (y)"
        );
        assert_eq!(
            fp_compare_c(CondKind::Ne, "x", "y", false, a64),
            "(x) != (y)"
        );

        assert_eq!(
            fp_compare_rust(CondKind::E, "x", "y", false, x86),
            "!(x < y) && !(x > y)"
        );
        assert_eq!(
            fp_compare_rust(CondKind::Ne, "x", "y", false, x86),
            "(x < y) || (x > y)"
        );
        assert_eq!(fp_compare_rust(CondKind::E, "x", "y", false, a64), "x == y");
        assert_eq!(
            fp_compare_rust(CondKind::Ne, "x", "y", false, a64),
            "x != y"
        );
    }

    #[test]
    fn parity_setcc_over_fp_recovers_the_unordered_isnan_test() {
        assert_eq!(CondKind::parse("p"), Some(CondKind::P));
        assert_eq!(CondKind::parse("np"), Some(CondKind::Np));
        assert_eq!(CondKind::parse("pe"), Some(CondKind::P));
        assert_eq!(CondKind::parse("po"), Some(CondKind::Np));
        assert_eq!(CondKind::P.negate(), CondKind::Np);
        assert_eq!(CondKind::Np.negate(), CondKind::P);

        let m: FpUnorderedModel = FpUnorderedModel::UnorderedIsEqual;
        assert_eq!(
            fp_compare_rust(CondKind::P, "x", "y", false, m),
            "(x).is_nan() || (y).is_nan()"
        );
        assert_eq!(
            fp_compare_rust(CondKind::Np, "x", "y", false, m),
            "!(x).is_nan() && !(y).is_nan()"
        );
        assert_eq!(
            fp_compare_c(CondKind::P, "x", "y", false, m),
            fp_compare_c(CondKind::Vs, "x", "y", false, m)
        );

        let di = |address: u64, mnemonic: &str, operands: &str| -> DisasmInsn {
            DisasmInsn {
                address,
                bytes: Vec::new(),
                mnemonic: mnemonic.to_owned(),
                operands: operands.to_owned(),
            }
        };
        let unordered: [DisasmInsn; 2] = [di(0, "ucomisd", "xmm0, xmm1"), di(1, "setp", "al")];
        let lifted: Vec<Stmt> = lift_stmt_range(&unordered, 0, unordered.len(), &[])
            .expect("setp over an fp compare recovers the unordered test");
        assert!(
            matches!(
                lifted.as_slice(),
                [Stmt::SetCc {
                    kind: CondKind::P,
                    ..
                }]
            ),
            "setp over ucomisd must lift to a parity SetCc: {lifted:?}"
        );
    }

    #[test]
    fn parity_guarded_equality_fuses_to_an_ordered_compare() {
        const CROSS_EQ: &str = "(fp_d_from_bits(x_xmm0)) == (fp_d_from_bits(x_xmm1))";
        const CROSS_NE: &str = "(fp_d_from_bits(x_xmm0)) != (fp_d_from_bits(x_xmm1))";
        const UNORDERED_EQ: &str = "!((fp_d_from_bits(x_xmm0)) < (fp_d_from_bits(x_xmm1)))";

        let and_form: [u8; 13] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x94, 0xc0, 0x0f, 0x9b, 0xc1, 0x20, 0xc8, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&and_form, 0xe100, Abi::SysV)
            .expect("the parity-guarded equality idiom recovers");
        assert!(
            rec.source.contains(CROSS_EQ),
            "sete + setnp + and must fold to an ordered equality of the two compared operands: {}",
            rec.source
        );

        let or_form: [u8; 13] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x95, 0xc0, 0x0f, 0x9a, 0xc1, 0x08, 0xc8, 0xc3,
        ];
        let rec_or: LeafRecovery = recover_leaf_function_abi(&or_form, 0xe200, Abi::SysV)
            .expect("the parity-guarded inequality idiom recovers");
        assert!(
            rec_or.source.contains(CROSS_NE),
            "setne + setp + or must fold to an ordered inequality of the two compared operands: {}",
            rec_or.source
        );

        let same_register: [u8; 13] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x94, 0xc0, 0x0f, 0x9b, 0xc0, 0x20, 0xc0, 0xc3,
        ];
        let rec_same: LeafRecovery = recover_leaf_function_abi(&same_register, 0xe300, Abi::SysV)
            .expect("the degenerate same-register sequence still recovers unfused");
        assert!(
            !rec_same.source.contains(CROSS_EQ) && rec_same.source.contains(UNORDERED_EQ),
            "sete al; setnp al; and al,al leaves al holding only the parity byte, so it must keep the unordered form and never fold to an equality: {}",
            rec_same.source
        );

        let mismatched_kinds: [u8; 13] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x94, 0xc0, 0x0f, 0x94, 0xc1, 0x20, 0xc8, 0xc3,
        ];
        let rec_mismatch: LeafRecovery =
            recover_leaf_function_abi(&mismatched_kinds, 0xe400, Abi::SysV)
                .expect("two equality setcc feeding an and still recover unfused");
        assert!(
            !rec_mismatch.source.contains(CROSS_EQ),
            "a sete + sete pair is not the parity-guard idiom and must not fold to an ordered equality: {}",
            rec_mismatch.source
        );

        assert!(
            rec.source.matches("x_xmm1").count() >= 2,
            "the fused recovery must still read both compared operands: {}",
            rec.source
        );
    }

    const ORDERED_SELECT_CROSS_EQ: &str = "(fp_d_from_bits(x_xmm0)) == (fp_d_from_bits(x_xmm1))";
    const ORDERED_SELECT_CROSS_NE: &str = "(fp_d_from_bits(x_xmm0)) != (fp_d_from_bits(x_xmm1))";
    const ORDERED_SELECT_UNFOLDED: &str = "? r_rdx : r_rax";

    fn ordered_select_source(code: &[u8], base: u64) -> String {
        recover_leaf_function_abi(code, base, Abi::SysV)
            .expect("the parity-select sequence recovers")
            .source
    }

    #[test]
    fn parity_select_rejects_a_reexecuted_compare_over_spilled_operands() {
        let respilled: [u8; 50] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x11, 0x45, 0x10, 0xf2, 0x0f, 0x11, 0x4d, 0x18,
            0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2e, 0x45, 0x18, 0x0f, 0x9b, 0xc0, 0xba,
            0x00, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2e, 0x45, 0x18,
            0x0f, 0x45, 0xc2, 0x0f, 0xb6, 0xc0, 0x5d, 0xc3,
        ];
        let source: String = recover_leaf_function_abi(&respilled, 0x9000, Abi::MsX64)
            .expect("the spilled two-compare sequence recovers")
            .source;
        assert!(
            !source.contains("(fp_d_from_bits(x_xmm0)) == ((*(double*)"),
            "the predicate and the select consume two separate compare executions, so no cross-operand ordered equality may be synthesized: {source}"
        );
        assert!(
            source.contains("? (r_rdx) & 0xffffffffULL : r_rax"),
            "the conditional move must survive as a select when the compare is re-executed: {source}"
        );
    }

    #[test]
    fn a_returned_value_that_is_also_compared_stays_floating_point() {
        let fmax2: [u8; 50] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x11, 0x45, 0x10, 0xf2, 0x0f, 0x11, 0x4d, 0x18,
            0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2f, 0x45, 0x18, 0x76, 0x07, 0xf2, 0x0f,
            0x10, 0x45, 0x10, 0xeb, 0x05, 0xf2, 0x0f, 0x10, 0x45, 0x18, 0x66, 0x48, 0x0f, 0x7e,
            0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xc0, 0x5d, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&fmax2, 0x9600, Abi::MsX64)
            .expect("the maximum select recovers");
        assert_eq!(
            rec.returns_fp,
            Some(ScalarType::Double),
            "a maximum that returns one of the two compared operands must keep a floating-point return: {}",
            rec.source
        );
        assert!(
            rec.source.contains("double recovered("),
            "the recovered signature must still claim a floating-point return: {}",
            rec.source
        );
    }

    #[test]
    fn floating_point_scratch_consumed_by_a_conversion_returns_an_integer() {
        let trunc_ll: [u8; 21] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x11, 0x45, 0x10, 0xf2, 0x0f, 0x10, 0x45, 0x10,
            0xf2, 0x48, 0x0f, 0x2c, 0xc0, 0x5d, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&trunc_ll, 0x9700, Abi::MsX64)
            .expect("a truncating conversion recovers");
        assert!(
            rec.returns_fp.is_none(),
            "the reloaded operand is consumed by a conversion into rax, so the return is an integer: {}",
            rec.source
        );
    }

    #[test]
    fn a_call_result_does_not_inherit_an_earlier_floating_point_channel() {
        let after_call: [u8; 15] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x59, 0xc0, 0xe8, 0x27, 0x02, 0x00, 0x00, 0x5d,
            0xc3,
        ];
        if let Ok(rec) = recover_leaf_function_abi(&after_call, 0x9800, Abi::SysV) {
            assert!(
                rec.returns_fp.is_none(),
                "the return value comes from the call's integer register, so an earlier floating-point computation must not type the function: {}",
                rec.source
            );
        }
    }

    #[test]
    fn a_widening_move_into_the_result_register_clears_the_floating_point_channel() {
        let widened: [u8; 20] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x59, 0xc1, 0x66, 0x0f, 0x2e, 0xc2, 0x0f, 0x97,
            0xc2, 0x0f, 0xb6, 0xc2, 0x5d, 0xc3,
        ];
        if let Ok(rec) = recover_leaf_function_abi(&widened, 0x9900, Abi::SysV) {
            assert!(
                rec.returns_fp.is_none(),
                "a widening move produces the integer result, so an earlier floating-point multiply must not type the function: {}",
                rec.source
            );
        }
    }

    #[test]
    fn reading_an_unwritten_scratch_xmm_is_rejected_rather_than_zeroed() {
        let reads_xmm8: [u8; 6] = [0xf2, 0x41, 0x0f, 0x58, 0xc0, 0xc3];
        let outcome: Result<LeafRecovery> =
            recover_leaf_function_abi(&reads_xmm8, 0x9a00, Abi::SysV);
        match outcome {
            Err(_) => {}
            Ok(rec) => panic!(
                "xmm8 is read before any write and is not a parameter register, so its value is uninitialized at entry and the recovery must reject instead of inventing a defined value: {}",
                rec.source
            ),
        }
    }

    #[test]
    fn a_reloaded_compare_operand_does_not_make_the_return_floating_point() {
        let spilled: [u8; 50] = [
            0x55, 0x48, 0x89, 0xe5, 0xf2, 0x0f, 0x11, 0x45, 0x10, 0xf2, 0x0f, 0x11, 0x4d, 0x18,
            0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2e, 0x45, 0x18, 0x0f, 0x9b, 0xc0, 0xba,
            0x00, 0x00, 0x00, 0x00, 0xf2, 0x0f, 0x10, 0x45, 0x10, 0x66, 0x0f, 0x2e, 0x45, 0x18,
            0x0f, 0x45, 0xc2, 0x0f, 0xb6, 0xc0, 0x5d, 0xc3,
        ];
        let rec: LeafRecovery = recover_leaf_function_abi(&spilled, 0x9400, Abi::MsX64)
            .expect("the spilled compare sequence recovers");
        assert!(
            rec.returns_fp.is_none(),
            "xmm0 is only reloaded as a compare operand and the result is produced into rax, so the return type must not be floating point: {}",
            rec.source
        );
        assert!(
            !rec.source.contains("double recovered("),
            "the recovered signature must not claim a floating-point return: {}",
            rec.source
        );
    }

    #[test]
    fn a_self_xor_between_the_predicate_and_the_select_invalidates_the_compare() {
        let zeroed: [u8; 16] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0x31, 0xd2, 0x48, 0x0f,
            0x45, 0xc2,
        ];
        let mut body: Vec<u8> = zeroed.to_vec();
        body.push(0xc3);
        let recovered: Result<LeafRecovery> = recover_leaf_function_abi(&body, 0x9200, Abi::SysV);
        match recovered {
            Err(_) => {}
            Ok(rec) => assert!(
                !rec.source
                    .contains("(fp_d_from_bits(x_xmm0)) == (fp_d_from_bits(x_xmm1))"),
                "a self-xor overwrites the flags the compare established, so the select must not be folded into an ordered equality: {}",
                rec.source
            ),
        }
    }

    #[test]
    fn parity_select_equality_folds_the_widened_predicate_shape() {
        let widened: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x00, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let source: String = ordered_select_source(&widened, 0xf100);
        assert!(
            source.contains(ORDERED_SELECT_CROSS_EQ),
            "setnp + movzx + zero constant + cmovne must fold to an ordered equality of the two compared operands: {source}"
        );
        assert!(
            source.matches("x_xmm1").count() >= 2,
            "the folded select must still read both compared operands: {source}"
        );
        assert!(
            !source.contains(ORDERED_SELECT_UNFOLDED),
            "the conditional move itself must be rewritten, not left beside the folded compare: {source}"
        );
    }

    #[test]
    fn parity_select_equality_folds_the_hoisted_prezero_shape() {
        let prezero: [u8; 19] = [
            0x31, 0xc0, 0xba, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0,
            0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let source: String = ordered_select_source(&prezero, 0xf200);
        assert!(
            source.contains(ORDERED_SELECT_CROSS_EQ),
            "a hoisted xor prezero with no widening step must still fold to an ordered equality: {source}"
        );
        assert!(
            !source.contains(ORDERED_SELECT_UNFOLDED),
            "the conditional move itself must be rewritten in the prezero shape too: {source}"
        );
    }

    #[test]
    fn parity_select_inequality_folds_to_an_ordered_not_equal() {
        let unequal: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9a, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x01, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let source: String = ordered_select_source(&unequal, 0xf300);
        assert!(
            source.contains(ORDERED_SELECT_CROSS_NE),
            "setp + movzx + one constant + cmovne must fold to an ordered inequality: {source}"
        );
        assert!(
            !source.contains(ORDERED_SELECT_UNFOLDED),
            "the conditional move itself must be rewritten in the inequality pairing: {source}"
        );
    }

    #[test]
    fn parity_select_rejects_every_uncorroborated_variant() {
        let equal_select: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x00, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x44, 0xc2, 0xc3,
        ];
        let wrong_constant: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x02, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let ordered_with_one: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x01, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let unordered_with_zero: [u8; 20] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9a, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x00, 0x00, 0x00,
            0x00, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let recompared: [u8; 24] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0xba, 0x00, 0x00, 0x00,
            0x00, 0x66, 0x0f, 0x2e, 0xc1, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let narrow_constant: [u8; 19] = [
            0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b, 0xc0, 0x0f, 0xb6, 0xc0, 0x66, 0xba, 0x00, 0x00,
            0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];
        let narrow_prezero: [u8; 20] = [
            0x66, 0x31, 0xc0, 0xba, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0f, 0x2e, 0xc1, 0x0f, 0x9b,
            0xc0, 0x48, 0x0f, 0x45, 0xc2, 0xc3,
        ];

        let rejected: [(&str, &[u8]); 7] = [
            ("a cmove selects on the wrong flag polarity", &equal_select),
            (
                "a constant of two is neither the zero nor the one pairing",
                &wrong_constant,
            ),
            (
                "an ordered predicate paired with a one constant does not corroborate",
                &ordered_with_one,
            ),
            (
                "an unordered predicate paired with a zero constant does not corroborate",
                &unordered_with_zero,
            ),
            (
                "a second compare between the predicate and the select breaks flag provenance",
                &recompared,
            ),
            (
                "a sixteen bit constant leaves the upper half of the selected register unknown",
                &narrow_constant,
            ),
            (
                "a sixteen bit prezero leaves bits sixteen through thirty one unknown",
                &narrow_prezero,
            ),
        ];
        for (index, (reason, code)) in rejected.iter().enumerate() {
            let base: u64 = 0xf400 + (index as u64) * 0x100;
            let source: String = ordered_select_source(code, base);
            assert!(
                !source.contains(ORDERED_SELECT_CROSS_EQ)
                    && !source.contains(ORDERED_SELECT_CROSS_NE),
                "{reason}, so the select must stay unfolded: {source}"
            );
            assert!(
                source.contains(ORDERED_SELECT_UNFOLDED),
                "{reason}, so the conditional move must survive as a select: {source}"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod structuring_corpus {
    use super::{
        Abi, AggregatePlan, BlockTerm, CfgBlock, Item, LeafItems, Stmt, build_blocks,
        build_leaf_items, structure_items,
    };
    use crate::structuring;
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::process::Command;

    pub(super) const HOST_ABI: Abi = if cfg!(windows) { Abi::MsX64 } else { Abi::SysV };

    pub(super) struct CfShape {
        pub(super) name: &'static str,
        pub(super) source: &'static str,
    }

    pub(super) const CF_CORPUS: &[CfShape] = &[
        CfShape {
            name: "cf_straight",
            source: "long long cf_straight(long long a){ return a * a + 1; }",
        },
        CfShape {
            name: "cf_if_then",
            source: "long long cf_if_then(long long a, long long b){ long long r = a + b; if (a > b) r += 10; return r; }",
        },
        CfShape {
            name: "cf_if_else",
            source: "long long cf_if_else(long long a, long long b){ long long r; if (a > b) r = a + b; else r = a - b; return r; }",
        },
        CfShape {
            name: "cf_nested_if",
            source: "long long cf_nested_if(long long a, long long b, long long c){ long long r = c; if (a > 0) if (b > 0) r = a + b; return r; }",
        },
        CfShape {
            name: "cf_nested_if_else",
            source: "long long cf_nested_if_else(long long a, long long b){ long long r = 0; if (a > 0) { if (b > 0) { r = a + b; } else { r = a - b; } } return r; }",
        },
        CfShape {
            name: "cf_ifelse_chain",
            source: "long long cf_ifelse_chain(long long a){ if (a > 100) return 3; else if (a > 10) return 2; else if (a > 0) return 1; else return 0; }",
        },
        CfShape {
            name: "cf_while",
            source: "long long cf_while(long long n){ long long s = 0; long long i = 0; while (i < n) { s += i; i++; } return s; }",
        },
        CfShape {
            name: "cf_for",
            source: "long long cf_for(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { s += i * i; } return s; }",
        },
        CfShape {
            name: "cf_do_while",
            source: "long long cf_do_while(long long n){ long long s = 0; long long i = 1; do { s += i; i++; } while (i <= n); return s; }",
        },
        CfShape {
            name: "cf_nested_loop",
            source: "long long cf_nested_loop(long long n, long long m){ long long s = 0; for (long long i = 0; i < n; i++) { for (long long j = 0; j < m; j++) { s += i + j; } } return s; }",
        },
        CfShape {
            name: "cf_loop_break",
            source: "long long cf_loop_break(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { if (i > 5) break; s += i; } return s; }",
        },
        CfShape {
            name: "cf_loop_continue",
            source: "long long cf_loop_continue(long long n){ long long s = 0; for (long long i = 0; i < n; i++) { if ((i & 1) == 0) continue; s += i; } return s; }",
        },
        CfShape {
            name: "cf_multi_return",
            source: "long long cf_multi_return(long long a, long long b){ if (a < 0) return -1; if (b < 0) return -2; if (a > b) return a - b; return b - a; }",
        },
        CfShape {
            name: "cf_sc_and",
            source: "long long cf_sc_and(long long a, long long b){ long long r = a - b; if (a > 0 && b > 0) { r = a + b; } return r; }",
        },
        CfShape {
            name: "cf_sc_or",
            source: "long long cf_sc_or(long long a, long long b){ long long r; if (a < 0 || b < 0) { r = a + b; } else { r = a - b; } return r; }",
        },
        CfShape {
            name: "cf_sign",
            source: "long long cf_sign(long long a){ if (a > 0) return 1; if (a < 0) return -1; return 0; }",
        },
        CfShape {
            name: "cf_clamp",
            source: "long long cf_clamp(long long a, long long lo, long long hi){ long long r = a; if (r < lo) r = lo; if (r > hi) r = hi; return r; }",
        },
    ];

    pub(super) fn gcc() -> Option<String> {
        for compiler in ["gcc", "cc", "clang"] {
            if Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
            {
                return Some(compiler.to_owned());
            }
        }
        None
    }

    fn scratch_dir() -> disrobe_core::scratch::ScratchDir {
        disrobe_core::scratch::ScratchDir::create("disrobe-structuring")
            .expect("create scratch directory")
    }

    pub(super) fn compile_corpus(compiler: &str) -> Option<Vec<u8>> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut source: String = String::from("#include <stdint.h>\n");
        for shape in CF_CORPUS {
            source.push_str("__attribute__((noinline,noclone)) ");
            source.push_str(shape.source);
            source.push('\n');
        }
        let scratch: disrobe_core::scratch::ScratchDir = scratch_dir();
        let dir: &std::path::Path = scratch.path();
        let tag: u64 = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let src: PathBuf = dir.join(format!("cf_corpus_{tag}.c"));
        let obj: PathBuf = dir.join(format!("cf_corpus_{tag}.o"));
        std::fs::write(&src, source.as_bytes()).expect("write corpus source");
        let compiled: std::process::Output = Command::new(compiler)
            .args([
                "-O1",
                "-fno-stack-protector",
                "-fno-if-conversion",
                "-fno-if-conversion2",
                "-fno-tree-loop-if-convert",
                "-c",
                "-o",
            ])
            .arg(&obj)
            .arg(&src)
            .output()
            .expect("invoke compiler for cf corpus");
        if !compiled.status.success() {
            eprintln!(
                "cf corpus compile failed: {}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            return None;
        }
        std::fs::read(&obj).ok()
    }

    pub(super) fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
        let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
        let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
        let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
            s.name()
                .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
        })?;
        let section_index: object::SectionIndex = match sym.section() {
            object::SymbolSection::Section(idx) => idx,
            _ => return None,
        };
        let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
        let data: &[u8] = section.data().ok()?;
        let sym_addr: u64 = sym.address();
        let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
        let size: usize = usize::try_from(sym.size()).ok()?;
        let end: usize = if size == 0 {
            let next_off: usize = file
                .symbols()
                .filter(|s: &object::Symbol<'_, '_>| {
                    matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                        && s.address() > sym_addr
                        && s.kind() == object::SymbolKind::Text
                        && s.name().is_ok_and(|n: &str| !n.is_empty())
                })
                .filter_map(|s: object::Symbol<'_, '_>| {
                    usize::try_from(s.address().saturating_sub(section.address())).ok()
                })
                .min()
                .unwrap_or(data.len());
            next_off.min(data.len())
        } else {
            start.saturating_add(size).min(data.len())
        };
        let slice: &[u8] = data.get(start..end)?;
        Some((slice.to_vec(), sym_addr))
    }

    pub(super) fn lift(object_bytes: &[u8], name: &str) -> Option<Vec<Item>> {
        let (code, base): (Vec<u8>, u64) = function_code(object_bytes, name)?;
        build_leaf_items(&code, base, HOST_ABI, &[], &[])
            .ok()
            .map(|leaf: LeafItems| leaf.items)
    }

    pub(super) fn golden_set(object_bytes: &[u8]) -> BTreeSet<&'static str> {
        let mut golden: BTreeSet<&'static str> = BTreeSet::new();
        for shape in CF_CORPUS {
            if let Some(items) = lift(object_bytes, shape.name)
                && structure_items(&items).is_ok()
            {
                golden.insert(shape.name);
            }
        }
        golden
    }

    fn stmt_has_side_effect(stmt: &Stmt) -> bool {
        matches!(
            stmt,
            Stmt::Store { .. }
                | Stmt::MemRmw { .. }
                | Stmt::FpStore { .. }
                | Stmt::BlockMove { .. }
                | Stmt::BlockFill { .. }
                | Stmt::Call { .. }
        )
    }

    fn cfg_from_blocks(blocks: &[CfgBlock]) -> Option<structuring::Cfg> {
        let count: usize = blocks.len();
        let mut nodes: Vec<structuring::CfgNode> = Vec::with_capacity(count);
        for (idx, block) in blocks.iter().enumerate() {
            let pure: bool = block.stmts.iter().all(|s: &Stmt| !stmt_has_side_effect(s));
            let term: structuring::Terminator = match &block.term {
                BlockTerm::Ret => structuring::Terminator::Return,
                BlockTerm::Jump(t) | BlockTerm::Fall(t) => {
                    if *t >= count {
                        return None;
                    }
                    structuring::Terminator::Goto(*t as u32)
                }
                BlockTerm::Branch {
                    taken, fallthrough, ..
                } => {
                    if *taken >= count || *fallthrough >= count {
                        return None;
                    }
                    structuring::Terminator::Branch {
                        atom: idx as u32,
                        taken: *taken as u32,
                        not_taken: *fallthrough as u32,
                    }
                }
            };
            nodes.push(structuring::CfgNode { term, pure });
        }
        structuring::Cfg::new(0, nodes).ok()
    }

    fn region_structures(items: &[Item]) -> Option<bool> {
        let blocks: Vec<CfgBlock> = build_blocks(items)?;
        let cfg: structuring::Cfg = cfg_from_blocks(&blocks)?;
        Some(structuring::structure(&cfg).is_complete())
    }

    #[test]
    fn region_engine_subsumes_golden_ladder() {
        let Some(compiler): Option<String> = gcc() else {
            eprintln!("skipping region subsumption: no C compiler on PATH");
            return;
        };
        let Some(object): Option<Vec<u8>> = compile_corpus(&compiler) else {
            eprintln!("skipping region subsumption: cf corpus did not compile");
            return;
        };
        let mut ladder_total: usize = 0;
        let mut region_covers: usize = 0;
        let mut missed: Vec<&'static str> = Vec::new();
        let mut headroom: Vec<&'static str> = Vec::new();
        for shape in CF_CORPUS {
            let Some(items): Option<Vec<Item>> = lift(&object, shape.name) else {
                continue;
            };
            let ladder_ok: bool = structure_items(&items).is_ok();
            let region_ok: bool = region_structures(&items).unwrap_or(false);
            if ladder_ok {
                ladder_total += 1;
                if region_ok {
                    region_covers += 1;
                } else {
                    missed.push(shape.name);
                }
            } else if region_ok {
                headroom.push(shape.name);
            }
        }
        eprintln!(
            "region engine subsumes {region_covers}/{ladder_total} golden ladder shapes; headroom (engine structures, ladder rejects): {headroom:?}"
        );
        assert!(
            missed.is_empty(),
            "region engine failed to structure control-flow shapes the ladder already recovers: {missed:?}"
        );
        assert_eq!(
            region_covers, ladder_total,
            "the region engine must fully subsume the ladder on the golden set before any emission flip"
        );
        assert!(
            ladder_total >= 11,
            "expected at least the pinned golden floor of control-flow shapes, saw {ladder_total}"
        );
    }

    #[test]
    fn golden_control_flow_ladder_is_locked() {
        let Some(compiler): Option<String> = gcc() else {
            eprintln!("skipping golden lock: no C compiler on PATH");
            return;
        };
        let Some(object): Option<Vec<u8>> = compile_corpus(&compiler) else {
            eprintln!("skipping golden lock: cf corpus did not compile");
            return;
        };
        let golden: BTreeSet<&'static str> = golden_set(&object);
        eprintln!(
            "current ladder golden control-flow set ({}): {golden:?}",
            golden.len()
        );

        let locked: BTreeSet<&'static str> = BTreeSet::from([
            "cf_straight",
            "cf_if_then",
            "cf_if_else",
            "cf_nested_if",
            "cf_nested_if_else",
            "cf_while",
            "cf_for",
            "cf_do_while",
            "cf_nested_loop",
            "cf_sign",
            "cf_clamp",
        ]);
        let regressed: Vec<&&'static str> = locked.difference(&golden).collect();
        assert!(
            regressed.is_empty(),
            "control-flow shapes that structure today regressed to reject: {regressed:?} (current golden: {golden:?})"
        );

        for shape in CF_CORPUS {
            if let Some(items) = lift(&object, shape.name)
                && structure_items(&items).is_ok()
            {
                assert!(
                    build_blocks(&items).is_some(),
                    "the block builder must accept every ladder-structured leaf ({}) so the region engine can consume it",
                    shape.name
                );
            }
        }
    }

    #[test]
    fn region_engine_emits_fused_short_circuit_conditions() {
        let Some(compiler): Option<String> = gcc() else {
            eprintln!("skipping short-circuit fusion evidence: no C compiler on PATH");
            return;
        };
        let Some(object): Option<Vec<u8>> = compile_corpus(&compiler) else {
            eprintln!("skipping short-circuit fusion evidence: cf corpus did not compile");
            return;
        };
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&object, "cf_sc_and") else {
            eprintln!("skipping short-circuit fusion evidence: cf_sc_and symbol not located");
            return;
        };
        let rec: super::LeafRecovery =
            super::recover_leaf_function_abi(&code, base, HOST_ABI).expect("short-circuit leaf");
        assert!(
            rec.source.contains("&&") || rec.source.contains("||"),
            "the region engine must fuse the two branch-based predicates of cf_sc_and into one short-circuit guard rather than nesting: {}",
            rec.source
        );
    }

    #[test]
    fn fused_conditions_render_logical_operators() {
        use super::{
            Cond, CondKind, Flags, Reg, RegRef, Source, Width, if_cond_expr, rs_if_cond_expr,
        };
        let leaf = |reg: Reg, kind: CondKind| -> Cond {
            Cond::leaf(
                kind,
                Flags::Cmp {
                    lhs: RegRef {
                        reg,
                        width: Width::W64,
                    },
                    rhs: Source::Imm(0),
                },
            )
        };
        let and: Cond = Cond::And(
            Box::new(leaf(Reg::Rcx, CondKind::G)),
            Box::new(leaf(Reg::Rdx, CondKind::G)),
        );
        let or: Cond = Cond::Or(
            Box::new(leaf(Reg::Rcx, CondKind::L)),
            Box::new(leaf(Reg::Rdx, CondKind::L)),
        );
        assert!(
            if_cond_expr(&and, &AggregatePlan::default()).contains("&&"),
            "fused AND must render `&&`"
        );
        assert!(
            if_cond_expr(&or, &AggregatePlan::default()).contains("||"),
            "fused OR must render `||`"
        );
        assert!(
            rs_if_cond_expr(&and, &AggregatePlan::default())
                .is_some_and(|s: String| s.contains("&&")),
            "fused AND must render `&&` in rust"
        );
        assert!(
            rs_if_cond_expr(&or, &AggregatePlan::default())
                .is_some_and(|s: String| s.contains("||")),
            "fused OR must render `||` in rust"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod forward_join_scope {
    use super::{
        BlockTerm, CfgBlock, CondKind, Flags, Reg, RegRef, SinkLabel, Source, Stmt, Width,
        forward_join_lowering_candidates, render_cfg_blocks,
    };
    use std::collections::BTreeMap;

    fn probe_flags() -> Flags {
        Flags::Cmp {
            lhs: RegRef {
                reg: Reg::Rax,
                width: Width::W64,
            },
            rhs: Source::Imm(0),
        }
    }

    fn effect(tag: i64) -> Stmt {
        Stmt::Assign {
            dest: RegRef {
                reg: Reg::Rbx,
                width: Width::W64,
            },
            src: Source::Imm(tag),
        }
    }

    fn branch(taken: usize, fallthrough: usize) -> CfgBlock {
        CfgBlock {
            stmts: vec![effect(1)],
            term: BlockTerm::Branch {
                kind: CondKind::E,
                flags: probe_flags(),
                taken,
                fallthrough,
            },
        }
    }

    fn jump(target: usize) -> CfgBlock {
        CfgBlock {
            stmts: vec![effect(2)],
            term: BlockTerm::Jump(target),
        }
    }

    fn ret() -> CfgBlock {
        CfgBlock {
            stmts: Vec::new(),
            term: BlockTerm::Ret,
        }
    }

    fn no_labels() -> BTreeMap<usize, SinkLabel> {
        BTreeMap::new()
    }

    fn contains_goto(body: &[super::Node]) -> bool {
        body.iter().any(|node: &super::Node| match node {
            super::Node::Goto(_) | super::Node::Label(_) => true,
            super::Node::If {
                then_body,
                else_body,
                ..
            } => {
                contains_goto(then_body)
                    || else_body
                        .as_ref()
                        .is_some_and(|arm: &Vec<super::Node>| contains_goto(arm))
            }
            super::Node::While { body, .. } | super::Node::DoWhile { body, .. } => {
                contains_goto(body)
            }
            super::Node::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|case: &super::SwitchCase| contains_goto(&case.body))
                    || contains_goto(default)
            }
            super::Node::Stmt(_)
            | super::Node::CondSnapshot { .. }
            | super::Node::Break
            | super::Node::Continue
            | super::Node::Return => false,
        })
    }

    fn joins_lowered(plans: &[super::IrreduciblePlan]) -> Vec<usize> {
        plans
            .iter()
            .flat_map(|plan: &super::IrreduciblePlan| plan.residual.values().copied())
            .collect()
    }

    #[test]
    fn a_forward_join_with_two_predecessors_is_lowered_once_per_kept_edge() {
        let blocks: Vec<CfgBlock> = vec![branch(2, 1), jump(2), jump(3), ret()];
        let plans: Vec<super::IrreduciblePlan> =
            forward_join_lowering_candidates(&blocks, &no_labels());
        assert_eq!(plans.len(), 2, "one plan per candidate kept edge");
        assert!(
            joins_lowered(&plans).iter().all(|join: &usize| *join == 2),
            "only block 2 is a forward join"
        );
        for plan in &plans {
            assert_eq!(
                plan.blocks.len(),
                blocks.len() + 1,
                "exactly one predecessor edge is rerouted through a stub"
            );
            assert_eq!(plan.label_targets.get(&2).copied(), Some(2));
            for stub in plan.residual.keys() {
                assert_eq!(
                    plan.labels.get(stub).copied(),
                    Some(SinkLabel::Goto(2)),
                    "each stub must carry the join's goto label"
                );
                assert!(matches!(plan.blocks[*stub].term, BlockTerm::Ret));
                assert!(plan.blocks[*stub].stmts.is_empty());
            }
        }
    }

    #[test]
    fn a_loop_header_join_is_never_lowered_to_a_backward_goto() {
        let latch_reaches_header: Vec<CfgBlock> = vec![branch(1, 3), branch(2, 3), jump(1), ret()];
        let plans: Vec<super::IrreduciblePlan> =
            forward_join_lowering_candidates(&latch_reaches_header, &no_labels());
        assert!(
            joins_lowered(&plans).iter().all(|join: &usize| *join != 1),
            "block 1 dominates its own predecessor and must stay a loop header"
        );
    }

    #[test]
    fn a_multi_entry_irreducible_cfg_produces_no_forward_join_plan() {
        let two_entries: Vec<CfgBlock> = vec![branch(2, 1), jump(2), branch(1, 3), ret()];
        assert!(
            forward_join_lowering_candidates(&two_entries, &no_labels()).is_empty(),
            "a multi-entry irreducible scc must be left to the node-splitting path"
        );
    }

    #[test]
    fn the_entry_a_single_predecessor_and_a_sink_are_never_join_candidates() {
        let chain: Vec<CfgBlock> = vec![branch(2, 1), jump(2), jump(3), ret()];
        let joins: Vec<usize> =
            joins_lowered(&forward_join_lowering_candidates(&chain, &no_labels()));
        assert!(!joins.contains(&0), "the entry is never a join");
        assert!(
            !joins.contains(&1),
            "a single-predecessor block is never a join"
        );
        assert!(!joins.contains(&3), "a successor-free sink is never a join");
    }

    #[test]
    fn an_already_labelled_join_is_left_alone() {
        let blocks: Vec<CfgBlock> = vec![branch(2, 1), jump(2), jump(3), ret()];
        let mut labels: BTreeMap<usize, SinkLabel> = BTreeMap::new();
        labels.insert(2, SinkLabel::Break);
        assert!(
            forward_join_lowering_candidates(&blocks, &labels).is_empty(),
            "a block that already carries a sink label must not be relabelled"
        );
    }

    fn mem_copy_shaped_blocks() -> Vec<CfgBlock> {
        vec![
            branch(14, 1),
            branch(12, 2),
            branch(12, 3),
            branch(5, 4),
            jump(9),
            jump(6),
            branch(6, 7),
            branch(14, 8),
            branch(12, 9),
            jump(10),
            branch(10, 11),
            branch(14, 12),
            jump(13),
            branch(13, 14),
            ret(),
        ]
    }

    #[test]
    fn the_kept_edge_is_the_latest_predecessor_and_every_other_edge_becomes_a_goto() {
        let blocks: Vec<CfgBlock> = mem_copy_shaped_blocks();
        let plans: Vec<super::IrreduciblePlan> =
            forward_join_lowering_candidates(&blocks, &no_labels());
        let first_for_twelve: &super::IrreduciblePlan = plans
            .iter()
            .find(|plan: &&super::IrreduciblePlan| {
                plan.label_targets.contains_key(&12) && plan.residual.len() == 3
            })
            .expect("block 12 is a four-predecessor forward join");
        assert!(
            matches!(
                first_for_twelve.blocks[11].term,
                BlockTerm::Branch {
                    fallthrough: 12,
                    ..
                }
            ),
            "the latest predecessor keeps its direct edge to the join"
        );
        for pred in [1_usize, 2, 8] {
            let successors: Vec<usize> = first_for_twelve.blocks[pred].successors();
            assert!(
                !successors.contains(&12),
                "predecessor {pred} must reach the join through a goto stub"
            );
        }
    }

    #[test]
    fn an_accepted_lowering_is_edge_equivalent_and_the_check_has_teeth() {
        let blocks: Vec<CfgBlock> = mem_copy_shaped_blocks();
        let mut plan: super::IrreduciblePlan =
            forward_join_lowering_candidates(&blocks, &no_labels())
                .into_iter()
                .find(|plan: &super::IrreduciblePlan| plan.residual.len() == 3)
                .expect("a four-predecessor join yields a three-stub plan");
        let original: crate::structuring::Cfg =
            super::cfg_from_leaf_blocks(&blocks).expect("original cfg");
        let lowered: crate::structuring::Cfg =
            super::cfg_from_leaf_blocks(&plan.blocks).expect("lowered cfg");
        let residual: BTreeMap<u32, u32> = plan
            .residual
            .iter()
            .map(|(stub, target): (&usize, &usize)| (*stub as u32, *target as u32))
            .collect();
        assert!(
            crate::structuring::relowered_matches_original(&original, &lowered, &residual),
            "a goto stub must preserve every original edge"
        );

        super::retarget_block(&mut plan.blocks[1].term, 15, 3);
        let corrupted_cfg: crate::structuring::Cfg =
            super::cfg_from_leaf_blocks(&plan.blocks).expect("corrupted cfg");
        assert!(
            !crate::structuring::relowered_matches_original(&original, &corrupted_cfg, &residual),
            "misrouting a stub edge must fail the equivalence check"
        );
    }

    #[test]
    fn the_lowering_only_runs_after_every_earlier_attempt_has_failed() {
        let already_structurable: Vec<CfgBlock> = vec![branch(2, 1), jump(3), jump(3), ret()];
        let targets: BTreeMap<usize, u32> = BTreeMap::new();
        let body: Vec<super::Node> =
            render_cfg_blocks(&already_structurable, &no_labels(), true, &targets)
                .expect("a plain diamond structures without any lowering");
        assert!(
            !contains_goto(&body),
            "a shape the earlier passes already handle must not gain a goto: {body:#?}"
        );
    }
}
