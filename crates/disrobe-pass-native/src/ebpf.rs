use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_emit::Interner;
use disrobe_emit::c::{
    AssignOp, BinaryOp, CBaseType, CDecl, CExpr, CInit, CItem, CParam, CStmt, CTypeSpec,
    DeclaratorChain, IntSuffix, LongSuffix, Radix, TypeName, UnaryOp, render_item,
};

use crate::error::{Error, Result};
use crate::structuring;

pub const EBPF_INSN_SIZE: usize = 8;

const CLASS_LD: u8 = 0x00;
const CLASS_LDX: u8 = 0x01;
const CLASS_ST: u8 = 0x02;
const CLASS_STX: u8 = 0x03;
const CLASS_ALU: u8 = 0x04;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const CLASS_ALU64: u8 = 0x07;

const MODE_IMM: u8 = 0x00;
const MODE_ABS: u8 = 0x01;
const MODE_IND: u8 = 0x02;
const MODE_MEM: u8 = 0x03;
const MODE_ATOMIC: u8 = 0x06;

const PSEUDO_MAP_FD: u8 = 1;

const C_RENDER_WIDTH: usize = 1 << 20;

const fn insn_class(opcode: u8) -> u8 {
    opcode & 0x07
}

const fn mem_mode(opcode: u8) -> u8 {
    opcode >> 5
}

const fn mem_size_bits(opcode: u8) -> u8 {
    (opcode >> 3) & 0x03
}

const fn alu_op_nibble(opcode: u8) -> u8 {
    opcode >> 4
}

const fn alu_source_is_reg(opcode: u8) -> bool {
    opcode & 0x08 != 0
}

const HELPERS: &[(u32, &str)] = &[
    (1, "bpf_map_lookup_elem"),
    (2, "bpf_map_update_elem"),
    (3, "bpf_map_delete_elem"),
    (4, "bpf_probe_read"),
    (5, "bpf_ktime_get_ns"),
    (6, "bpf_trace_printk"),
    (7, "bpf_get_prandom_u32"),
    (8, "bpf_get_smp_processor_id"),
    (9, "bpf_skb_store_bytes"),
    (10, "bpf_l3_csum_replace"),
    (11, "bpf_l4_csum_replace"),
    (12, "bpf_tail_call"),
    (13, "bpf_clone_redirect"),
    (14, "bpf_get_current_pid_tgid"),
    (15, "bpf_get_current_uid_gid"),
    (16, "bpf_get_current_comm"),
    (17, "bpf_get_cgroup_classid"),
    (18, "bpf_skb_vlan_push"),
    (19, "bpf_skb_vlan_pop"),
    (20, "bpf_skb_get_tunnel_key"),
    (21, "bpf_skb_set_tunnel_key"),
    (22, "bpf_perf_event_read"),
    (23, "bpf_redirect"),
    (24, "bpf_get_route_realm"),
    (25, "bpf_perf_event_output"),
    (26, "bpf_skb_load_bytes"),
    (27, "bpf_get_stackid"),
    (28, "bpf_csum_diff"),
    (29, "bpf_skb_get_tunnel_opt"),
    (30, "bpf_skb_set_tunnel_opt"),
    (31, "bpf_skb_change_proto"),
    (32, "bpf_skb_change_type"),
    (33, "bpf_skb_under_cgroup"),
    (34, "bpf_get_hash_recalc"),
    (35, "bpf_get_current_task"),
    (36, "bpf_probe_write_user"),
    (37, "bpf_current_task_under_cgroup"),
    (38, "bpf_skb_change_tail"),
    (39, "bpf_skb_pull_data"),
    (40, "bpf_csum_update"),
    (41, "bpf_set_hash_invalid"),
    (42, "bpf_get_numa_node_id"),
    (43, "bpf_skb_change_head"),
    (44, "bpf_xdp_adjust_head"),
    (45, "bpf_probe_read_str"),
    (46, "bpf_get_socket_cookie"),
    (47, "bpf_get_socket_uid"),
    (48, "bpf_set_hash"),
    (49, "bpf_setsockopt"),
    (50, "bpf_skb_adjust_room"),
    (51, "bpf_redirect_map"),
    (52, "bpf_sk_redirect_map"),
    (53, "bpf_sock_map_update"),
    (54, "bpf_xdp_adjust_meta"),
    (55, "bpf_perf_event_read_value"),
    (56, "bpf_perf_prog_read_value"),
    (57, "bpf_getsockopt"),
    (58, "bpf_override_return"),
    (59, "bpf_sock_ops_cb_flags_set"),
    (60, "bpf_msg_redirect_map"),
    (61, "bpf_msg_apply_bytes"),
    (62, "bpf_msg_cork_bytes"),
    (63, "bpf_msg_pull_data"),
    (64, "bpf_bind"),
    (65, "bpf_xdp_adjust_tail"),
    (66, "bpf_skb_get_xfrm_state"),
    (67, "bpf_get_stack"),
    (68, "bpf_skb_load_bytes_relative"),
    (69, "bpf_fib_lookup"),
    (70, "bpf_sock_hash_update"),
    (71, "bpf_msg_redirect_hash"),
    (72, "bpf_sk_redirect_hash"),
    (73, "bpf_lwt_push_encap"),
    (74, "bpf_lwt_seg6_store_bytes"),
    (75, "bpf_lwt_seg6_adjust_srh"),
    (76, "bpf_lwt_seg6_action"),
    (77, "bpf_rc_repeat"),
    (78, "bpf_rc_keydown"),
    (79, "bpf_skb_cgroup_id"),
    (80, "bpf_get_current_cgroup_id"),
    (81, "bpf_get_local_storage"),
    (82, "bpf_sk_select_reuseport"),
    (83, "bpf_skb_ancestor_cgroup_id"),
    (84, "bpf_sk_lookup_tcp"),
    (85, "bpf_sk_lookup_udp"),
    (86, "bpf_sk_release"),
    (87, "bpf_map_push_elem"),
    (88, "bpf_map_pop_elem"),
    (89, "bpf_map_peek_elem"),
    (90, "bpf_msg_push_data"),
    (91, "bpf_msg_pop_data"),
    (92, "bpf_rc_pointer_rel"),
    (93, "bpf_spin_lock"),
    (94, "bpf_spin_unlock"),
    (95, "bpf_sk_fullsock"),
    (96, "bpf_tcp_sock"),
    (97, "bpf_skb_ecn_set_ce"),
    (98, "bpf_get_listener_sock"),
    (99, "bpf_skc_lookup_tcp"),
    (100, "bpf_tcp_check_syncookie"),
    (101, "bpf_sysctl_get_name"),
    (102, "bpf_sysctl_get_current_value"),
    (103, "bpf_sysctl_get_new_value"),
];

#[must_use]
pub fn ebpf_helper_name(id: u32) -> Option<&'static str> {
    HELPERS
        .iter()
        .find(|(hid, _): &&(u32, &str)| *hid == id)
        .map(|(_, name): &(u32, &str)| *name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum EReg {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
}

impl EReg {
    const fn from_nibble(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::R0),
            1 => Some(Self::R1),
            2 => Some(Self::R2),
            3 => Some(Self::R3),
            4 => Some(Self::R4),
            5 => Some(Self::R5),
            6 => Some(Self::R6),
            7 => Some(Self::R7),
            8 => Some(Self::R8),
            9 => Some(Self::R9),
            10 => Some(Self::R10),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::R0 => "r0",
            Self::R1 => "r1",
            Self::R2 => "r2",
            Self::R3 => "r3",
            Self::R4 => "r4",
            Self::R5 => "r5",
            Self::R6 => "r6",
            Self::R7 => "r7",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawInsn {
    opcode: u8,
    dst_reg: u8,
    src_reg: u8,
    off: i16,
    imm: i32,
}

fn decode_raw(bytes: &[u8]) -> Result<Vec<RawInsn>> {
    if bytes.is_empty() || bytes.len() % EBPF_INSN_SIZE != 0 {
        return Err(Error::EbpfDecode(format!(
            "byte length {} is not a positive multiple of {EBPF_INSN_SIZE}",
            bytes.len()
        )));
    }
    let mut out: Vec<RawInsn> = Vec::with_capacity(bytes.len() / EBPF_INSN_SIZE);
    for chunk in bytes.chunks_exact(EBPF_INSN_SIZE) {
        let opcode: u8 = chunk[0];
        let reg_byte: u8 = chunk[1];
        let dst_reg: u8 = reg_byte & 0x0f;
        let src_reg: u8 = (reg_byte >> 4) & 0x0f;
        let off_bytes: [u8; 2] = [chunk[2], chunk[3]];
        let imm_bytes: [u8; 4] = [chunk[4], chunk[5], chunk[6], chunk[7]];
        out.push(RawInsn {
            opcode,
            dst_reg,
            src_reg,
            off: i16::from_le_bytes(off_bytes),
            imm: i32::from_le_bytes(imm_bytes),
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemSize {
    B,
    H,
    W,
    Dw,
}

impl MemSize {
    const fn from_bits(bits: u8) -> Self {
        match bits {
            1 => Self::H,
            2 => Self::B,
            3 => Self::Dw,
            _ => Self::W,
        }
    }

    const fn c_type(self) -> &'static str {
        match self {
            Self::B => "uint8_t",
            Self::H => "uint16_t",
            Self::W => "uint32_t",
            Self::Dw => "uint64_t",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Rsh,
    Mod,
    Xor,
    Arsh,
    SDiv,
    SMod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicOp {
    Add,
    Or,
    And,
    Xor,
    Xchg,
    Cmpxchg,
}

fn atomic_op(imm: i32) -> Option<(AtomicOp, bool)> {
    let raw: u32 = imm as u32;
    let fetch: bool = raw & 0x01 != 0;
    match raw & !0x01 {
        0x00 => Some((AtomicOp::Add, fetch)),
        0x40 => Some((AtomicOp::Or, fetch)),
        0x50 => Some((AtomicOp::And, fetch)),
        0xa0 => Some((AtomicOp::Xor, fetch)),
        0xe0 => Some((AtomicOp::Xchg, true)),
        0xf0 => Some((AtomicOp::Cmpxchg, true)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Sgt,
    Sge,
    Slt,
    Sle,
    SetNz,
    SetZ,
}

impl CmpOp {
    const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Gt => Self::Le,
            Self::Le => Self::Gt,
            Self::Ge => Self::Lt,
            Self::Lt => Self::Ge,
            Self::Sgt => Self::Sle,
            Self::Sle => Self::Sgt,
            Self::Sge => Self::Slt,
            Self::Slt => Self::Sge,
            Self::SetNz => Self::SetZ,
            Self::SetZ => Self::SetNz,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Src {
    Reg(EReg),
    Imm(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallKind {
    Helper(u32),
    Pseudo(i32),
    Kfunc(u32),
    Unknown(u8, i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoweredInsn {
    Alu {
        op: AluOp,
        is64: bool,
        dst: EReg,
        src: Src,
    },
    Neg {
        is64: bool,
        dst: EReg,
    },
    Mov {
        is64: bool,
        dst: EReg,
        src: Src,
    },
    End {
        dst: EReg,
        bits: u8,
        to_be: bool,
    },
    LoadImm64 {
        dst: EReg,
        value: u64,
    },
    MapFdLoad {
        dst: EReg,
        fd: u32,
    },
    Load {
        dst: EReg,
        base: EReg,
        off: i16,
        size: MemSize,
    },
    StoreImm {
        base: EReg,
        off: i16,
        size: MemSize,
        imm: i32,
    },
    StoreReg {
        base: EReg,
        off: i16,
        size: MemSize,
        src: EReg,
    },
    Atomic {
        base: EReg,
        off: i16,
        size: MemSize,
        src: EReg,
        op: AtomicOp,
        fetch: bool,
    },
    LdAbs {
        size: MemSize,
        imm: i32,
    },
    LdInd {
        size: MemSize,
        imm: i32,
        off_reg: EReg,
    },
    Jump {
        target_off: i64,
    },
    Branch {
        cmp: CmpOp,
        dst: EReg,
        src: Src,
        is64: bool,
        target_off: i64,
    },
    Call {
        kind: CallKind,
    },
    Exit,
    Unknown {
        raw: RawInsn,
    },
}

fn lower(raw: &[RawInsn]) -> Vec<Option<LoweredInsn>> {
    let mut out: Vec<Option<LoweredInsn>> = Vec::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let insn: RawInsn = raw[i];
        let cls: u8 = insn_class(insn.opcode);
        if cls == CLASS_LD && mem_mode(insn.opcode) == MODE_IMM && mem_size_bits(insn.opcode) == 3 {
            if i + 1 < raw.len() {
                let hi: RawInsn = raw[i + 1];
                let second_slot_well_formed: bool =
                    hi.opcode == 0 && hi.dst_reg == 0 && hi.src_reg == 0 && hi.off == 0;
                match (EReg::from_nibble(insn.dst_reg), second_slot_well_formed) {
                    (Some(dst), true) => {
                        let value: u64 =
                            u64::from(insn.imm as u32) | (u64::from(hi.imm as u32) << 32);
                        let lowered: LoweredInsn = if insn.src_reg == PSEUDO_MAP_FD {
                            LoweredInsn::MapFdLoad {
                                dst,
                                fd: insn.imm as u32,
                            }
                        } else {
                            LoweredInsn::LoadImm64 { dst, value }
                        };
                        out.push(Some(lowered));
                        out.push(None);
                    }
                    _ => {
                        out.push(Some(LoweredInsn::Unknown { raw: insn }));
                        out.push(Some(LoweredInsn::Unknown { raw: hi }));
                    }
                }
                i += 2;
                continue;
            }
            out.push(Some(LoweredInsn::Unknown { raw: insn }));
            i += 1;
            continue;
        }
        out.push(Some(lower_single(insn)));
        i += 1;
    }
    out
}

fn lower_single(insn: RawInsn) -> LoweredInsn {
    let (Some(dst), Some(src_reg)): (Option<EReg>, Option<EReg>) = (
        EReg::from_nibble(insn.dst_reg),
        EReg::from_nibble(insn.src_reg),
    ) else {
        return LoweredInsn::Unknown { raw: insn };
    };
    match insn_class(insn.opcode) {
        CLASS_ALU => lower_alu(insn, dst, src_reg, false),
        CLASS_ALU64 => lower_alu(insn, dst, src_reg, true),
        CLASS_JMP => lower_jmp(insn, dst, src_reg, true),
        CLASS_JMP32 => lower_jmp(insn, dst, src_reg, false),
        CLASS_LD => lower_ld(insn, src_reg),
        CLASS_LDX => lower_ldx(insn, dst, src_reg),
        CLASS_ST => lower_st(insn, dst),
        CLASS_STX => lower_stx(insn, dst, src_reg),
        _ => LoweredInsn::Unknown { raw: insn },
    }
}

fn lower_alu(insn: RawInsn, dst: EReg, src_reg: EReg, is64: bool) -> LoweredInsn {
    let use_reg: bool = alu_source_is_reg(insn.opcode);
    let src: Src = if use_reg {
        Src::Reg(src_reg)
    } else {
        Src::Imm(insn.imm)
    };
    let signed_variant: bool = insn.off == 1;
    match alu_op_nibble(insn.opcode) {
        0x0 => LoweredInsn::Alu {
            op: AluOp::Add,
            is64,
            dst,
            src,
        },
        0x1 => LoweredInsn::Alu {
            op: AluOp::Sub,
            is64,
            dst,
            src,
        },
        0x2 => LoweredInsn::Alu {
            op: AluOp::Mul,
            is64,
            dst,
            src,
        },
        0x3 => LoweredInsn::Alu {
            op: if signed_variant {
                AluOp::SDiv
            } else {
                AluOp::Div
            },
            is64,
            dst,
            src,
        },
        0x4 => LoweredInsn::Alu {
            op: AluOp::Or,
            is64,
            dst,
            src,
        },
        0x5 => LoweredInsn::Alu {
            op: AluOp::And,
            is64,
            dst,
            src,
        },
        0x6 => LoweredInsn::Alu {
            op: AluOp::Lsh,
            is64,
            dst,
            src,
        },
        0x7 => LoweredInsn::Alu {
            op: AluOp::Rsh,
            is64,
            dst,
            src,
        },
        0x8 => LoweredInsn::Neg { is64, dst },
        0x9 => LoweredInsn::Alu {
            op: if signed_variant {
                AluOp::SMod
            } else {
                AluOp::Mod
            },
            is64,
            dst,
            src,
        },
        0xa => LoweredInsn::Alu {
            op: AluOp::Xor,
            is64,
            dst,
            src,
        },
        0xb => LoweredInsn::Mov { is64, dst, src },
        0xc => LoweredInsn::Alu {
            op: AluOp::Arsh,
            is64,
            dst,
            src,
        },
        0xd if matches!(insn.imm, 16 | 32 | 64) => LoweredInsn::End {
            dst,
            bits: insn.imm as u8,
            to_be: use_reg,
        },
        _ => LoweredInsn::Unknown { raw: insn },
    }
}

fn lower_jmp(insn: RawInsn, dst: EReg, src_reg: EReg, is64: bool) -> LoweredInsn {
    let use_reg: bool = alu_source_is_reg(insn.opcode);
    let src: Src = if use_reg {
        Src::Reg(src_reg)
    } else {
        Src::Imm(insn.imm)
    };
    match alu_op_nibble(insn.opcode) {
        0x0 => {
            let target_off: i64 = if is64 {
                i64::from(insn.off)
            } else {
                i64::from(insn.imm)
            };
            LoweredInsn::Jump { target_off }
        }
        0x8 if is64 => match insn.src_reg {
            0 => LoweredInsn::Call {
                kind: CallKind::Helper(insn.imm as u32),
            },
            1 => LoweredInsn::Call {
                kind: CallKind::Pseudo(insn.imm),
            },
            2 => LoweredInsn::Call {
                kind: CallKind::Kfunc(insn.imm as u32),
            },
            other => LoweredInsn::Call {
                kind: CallKind::Unknown(other, insn.imm),
            },
        },
        0x9 if is64 => LoweredInsn::Exit,
        nibble => {
            let cmp: Option<CmpOp> = match nibble {
                0x1 => Some(CmpOp::Eq),
                0x2 => Some(CmpOp::Gt),
                0x3 => Some(CmpOp::Ge),
                0x4 => Some(CmpOp::SetNz),
                0x5 => Some(CmpOp::Ne),
                0x6 => Some(CmpOp::Sgt),
                0x7 => Some(CmpOp::Sge),
                0xa => Some(CmpOp::Lt),
                0xb => Some(CmpOp::Le),
                0xc => Some(CmpOp::Slt),
                0xd => Some(CmpOp::Sle),
                _ => None,
            };
            cmp.map_or(LoweredInsn::Unknown { raw: insn }, |cmp: CmpOp| {
                LoweredInsn::Branch {
                    cmp,
                    dst,
                    src,
                    is64,
                    target_off: i64::from(insn.off),
                }
            })
        }
    }
}

fn lower_ld(insn: RawInsn, src_reg: EReg) -> LoweredInsn {
    let mode: u8 = mem_mode(insn.opcode);
    let size: MemSize = MemSize::from_bits(mem_size_bits(insn.opcode));
    match mode {
        MODE_ABS => LoweredInsn::LdAbs {
            size,
            imm: insn.imm,
        },
        MODE_IND => LoweredInsn::LdInd {
            size,
            imm: insn.imm,
            off_reg: src_reg,
        },
        _ => LoweredInsn::Unknown { raw: insn },
    }
}

fn lower_ldx(insn: RawInsn, dst: EReg, src: EReg) -> LoweredInsn {
    let mode: u8 = mem_mode(insn.opcode);
    let size: MemSize = MemSize::from_bits(mem_size_bits(insn.opcode));
    if mode == MODE_MEM {
        LoweredInsn::Load {
            dst,
            base: src,
            off: insn.off,
            size,
        }
    } else {
        LoweredInsn::Unknown { raw: insn }
    }
}

fn lower_st(insn: RawInsn, dst: EReg) -> LoweredInsn {
    let mode: u8 = mem_mode(insn.opcode);
    let size: MemSize = MemSize::from_bits(mem_size_bits(insn.opcode));
    if mode == MODE_MEM {
        LoweredInsn::StoreImm {
            base: dst,
            off: insn.off,
            size,
            imm: insn.imm,
        }
    } else {
        LoweredInsn::Unknown { raw: insn }
    }
}

fn lower_stx(insn: RawInsn, dst: EReg, src: EReg) -> LoweredInsn {
    let mode: u8 = mem_mode(insn.opcode);
    let size: MemSize = MemSize::from_bits(mem_size_bits(insn.opcode));
    match mode {
        MODE_MEM => LoweredInsn::StoreReg {
            base: dst,
            off: insn.off,
            size,
            src,
        },
        MODE_ATOMIC if matches!(size, MemSize::W | MemSize::Dw) => match atomic_op(insn.imm) {
            Some((op, fetch)) => LoweredInsn::Atomic {
                base: dst,
                off: insn.off,
                size,
                src,
                op,
                fetch,
            },
            None => LoweredInsn::Unknown { raw: insn },
        },
        _ => LoweredInsn::Unknown { raw: insn },
    }
}

fn bin(op: BinaryOp, lhs: CExpr, rhs: CExpr) -> CExpr {
    CExpr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn cast_to(interner: &mut Interner, ty_name: &str, operand: CExpr) -> CExpr {
    let spec: CTypeSpec = CTypeSpec::Named(interner.intern(ty_name));
    CExpr::Cast {
        ty: TypeName::plain(spec),
        operand: Box::new(operand),
    }
}

fn ptr_cast(interner: &mut Interner, ty_name: &str, operand: CExpr) -> CExpr {
    let spec: CTypeSpec = CTypeSpec::Named(interner.intern(ty_name));
    let ty: TypeName = TypeName {
        base: CBaseType::plain(spec),
        declarator: DeclaratorChain::Terminal.pointer_to(),
    };
    CExpr::Cast {
        ty,
        operand: Box::new(operand),
    }
}

fn ident(interner: &mut Interner, name: &str) -> CExpr {
    CExpr::Ident(interner.intern(name))
}

fn call_expr(interner: &mut Interner, name: &str, args: Vec<CExpr>) -> CExpr {
    CExpr::Call {
        callee: Box::new(ident(interner, name)),
        args,
    }
}

fn reg_ident(interner: &mut Interner, r: EReg) -> CExpr {
    ident(interner, r.name())
}

fn reg_operand(interner: &mut Interner, r: EReg, is64: bool) -> CExpr {
    let value: CExpr = reg_ident(interner, r);
    if is64 {
        value
    } else {
        cast_to(interner, "uint32_t", value)
    }
}

fn imm_operand(imm: i32, is64: bool) -> CExpr {
    let value: u64 = if is64 {
        (i64::from(imm)) as u64
    } else {
        u64::from(imm as u32)
    };
    CExpr::Int {
        value,
        radix: Radix::Hex,
        suffix: IntSuffix {
            unsigned: true,
            long: if is64 {
                LongSuffix::LongLong
            } else {
                LongSuffix::None
            },
        },
    }
}

fn src_operand(interner: &mut Interner, src: &Src, is64: bool) -> CExpr {
    match src {
        Src::Reg(r) => reg_operand(interner, *r, is64),
        Src::Imm(v) => imm_operand(*v, is64),
    }
}

fn assign(lhs: CExpr, rhs: CExpr) -> CStmt {
    CStmt::Expr(CExpr::Assign {
        op: AssignOp::Assign,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    })
}

fn alu_stmt(interner: &mut Interner, op: AluOp, is64: bool, dst: EReg, src: &Src) -> CStmt {
    if matches!(op, AluOp::Div | AluOp::Mod | AluOp::SDiv | AluOp::SMod) {
        return divmod_stmt(interner, op, is64, dst, src);
    }
    let lhs: CExpr = reg_operand(interner, dst, is64);
    let rhs: CExpr = src_operand(interner, src, is64);
    let mask: u64 = if is64 { 63 } else { 31 };
    let computed: CExpr = match op {
        AluOp::Add => bin(BinaryOp::Add, lhs, rhs),
        AluOp::Sub => bin(BinaryOp::Sub, lhs, rhs),
        AluOp::Mul => bin(BinaryOp::Mul, lhs, rhs),
        AluOp::Or => bin(BinaryOp::BitOr, lhs, rhs),
        AluOp::And => bin(BinaryOp::BitAnd, lhs, rhs),
        AluOp::Xor => bin(BinaryOp::BitXor, lhs, rhs),
        AluOp::Lsh => bin(
            BinaryOp::Shl,
            lhs,
            bin(BinaryOp::BitAnd, rhs, CExpr::int(mask)),
        ),
        AluOp::Rsh => bin(
            BinaryOp::Shr,
            lhs,
            bin(BinaryOp::BitAnd, rhs, CExpr::int(mask)),
        ),
        AluOp::Arsh => {
            let signed_ty: &str = if is64 { "int64_t" } else { "int32_t" };
            let unsigned_ty: &str = if is64 { "uint64_t" } else { "uint32_t" };
            let signed_lhs: CExpr = cast_to(interner, signed_ty, lhs);
            let masked_rhs: CExpr = bin(BinaryOp::BitAnd, rhs, CExpr::int(mask));
            let shifted: CExpr = bin(BinaryOp::Shr, signed_lhs, masked_rhs);
            cast_to(interner, unsigned_ty, shifted)
        }
        AluOp::Div | AluOp::Mod | AluOp::SDiv | AluOp::SMod => unreachable!(),
    };
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, computed)
}

fn divmod_stmt(interner: &mut Interner, op: AluOp, is64: bool, dst: EReg, src: &Src) -> CStmt {
    let lhs: CExpr = reg_operand(interner, dst, is64);
    let rhs: CExpr = src_operand(interner, src, is64);
    let signed: bool = matches!(op, AluOp::SDiv | AluOp::SMod);
    let is_div: bool = matches!(op, AluOp::Div | AluOp::SDiv);
    let zero: CExpr = CExpr::int(0);
    let guard: CExpr = bin(BinaryOp::Ne, rhs.clone(), zero.clone());
    let (num, den): (CExpr, CExpr) = if signed {
        let sty: &str = if is64 { "int64_t" } else { "int32_t" };
        (cast_to(interner, sty, lhs), cast_to(interner, sty, rhs))
    } else {
        (lhs, rhs)
    };
    let raw_result: CExpr = if is_div {
        bin(BinaryOp::Div, num, den)
    } else {
        bin(BinaryOp::Rem, num, den)
    };
    let result: CExpr = if signed {
        let uty: &str = if is64 { "uint64_t" } else { "uint32_t" };
        cast_to(interner, uty, raw_result)
    } else {
        raw_result
    };
    let ternary: CExpr = CExpr::Ternary {
        cond: Box::new(guard),
        then: Box::new(result),
        els: Box::new(zero),
    };
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, ternary)
}

fn neg_stmt(interner: &mut Interner, is64: bool, dst: EReg) -> CStmt {
    let signed_ty: &str = if is64 { "int64_t" } else { "int32_t" };
    let unsigned_ty: &str = if is64 { "uint64_t" } else { "uint32_t" };
    let dst_operand: CExpr = reg_operand(interner, dst, is64);
    let operand: CExpr = cast_to(interner, signed_ty, dst_operand);
    let negated: CExpr = CExpr::Unary {
        op: UnaryOp::Neg,
        operand: Box::new(operand),
    };
    let result: CExpr = cast_to(interner, unsigned_ty, negated);
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, result)
}

fn mov_stmt(interner: &mut Interner, is64: bool, dst: EReg, src: &Src) -> CStmt {
    let rhs: CExpr = src_operand(interner, src, is64);
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, rhs)
}

fn end_stmt(interner: &mut Interner, dst: EReg, bits: u8, to_be: bool) -> CStmt {
    let src_ty: &str = match bits {
        16 => "uint16_t",
        32 => "uint32_t",
        _ => "uint64_t",
    };
    let dst_ident_pre: CExpr = reg_ident(interner, dst);
    let truncated: CExpr = cast_to(interner, src_ty, dst_ident_pre);
    let value: CExpr = if to_be {
        let builtin: String = format!("__builtin_bswap{bits}");
        call_expr(interner, &builtin, vec![truncated])
    } else {
        truncated
    };
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, value)
}

fn add_offset(base: CExpr, off: i16) -> CExpr {
    match off.cmp(&0) {
        std::cmp::Ordering::Equal => base,
        std::cmp::Ordering::Greater => bin(BinaryOp::Add, base, CExpr::int(u64::from(off as u16))),
        std::cmp::Ordering::Less => bin(
            BinaryOp::Sub,
            base,
            CExpr::int(u64::from(off.unsigned_abs())),
        ),
    }
}

fn mem_ref(interner: &mut Interner, base: EReg, off: i16, c_ty: &str) -> CExpr {
    let addr: CExpr = add_offset(reg_ident(interner, base), off);
    let pointer: CExpr = ptr_cast(interner, c_ty, addr);
    CExpr::Unary {
        op: UnaryOp::Deref,
        operand: Box::new(pointer),
    }
}

fn load_stmt(interner: &mut Interner, dst: EReg, base: EReg, off: i16, size: MemSize) -> CStmt {
    let mref: CExpr = mem_ref(interner, base, off, size.c_type());
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, mref)
}

fn store_imm_stmt(interner: &mut Interner, base: EReg, off: i16, size: MemSize, imm: i32) -> CStmt {
    let mref: CExpr = mem_ref(interner, base, off, size.c_type());
    let value: CExpr = imm_operand(imm, size == MemSize::Dw);
    let casted: CExpr = cast_to(interner, size.c_type(), value);
    assign(mref, casted)
}

fn store_reg_stmt(
    interner: &mut Interner,
    base: EReg,
    off: i16,
    size: MemSize,
    src: EReg,
) -> CStmt {
    let mref: CExpr = mem_ref(interner, base, off, size.c_type());
    let src_ident: CExpr = reg_ident(interner, src);
    let value: CExpr = cast_to(interner, size.c_type(), src_ident);
    assign(mref, value)
}

fn atomic_stmt(
    interner: &mut Interner,
    base: EReg,
    off: i16,
    size: MemSize,
    src: EReg,
    op: AtomicOp,
    fetch: bool,
) -> CStmt {
    let addr: CExpr = add_offset(reg_ident(interner, base), off);
    let ptr: CExpr = ptr_cast(interner, size.c_type(), addr);
    let src_ident: CExpr = reg_ident(interner, src);
    let builtin: &str = match op {
        AtomicOp::Add => "__sync_fetch_and_add",
        AtomicOp::Or => "__sync_fetch_and_or",
        AtomicOp::And => "__sync_fetch_and_and",
        AtomicOp::Xor => "__sync_fetch_and_xor",
        AtomicOp::Xchg => "__sync_lock_test_and_set",
        AtomicOp::Cmpxchg => "__sync_val_compare_and_swap",
    };
    let call: CExpr = if matches!(op, AtomicOp::Cmpxchg) {
        let r0: CExpr = reg_ident(interner, EReg::R0);
        call_expr(interner, builtin, vec![ptr, r0, src_ident.clone()])
    } else {
        call_expr(interner, builtin, vec![ptr, src_ident.clone()])
    };
    if fetch {
        let dest: CExpr = if matches!(op, AtomicOp::Cmpxchg) {
            reg_ident(interner, EReg::R0)
        } else {
            src_ident
        };
        assign(dest, call)
    } else {
        CStmt::Expr(call)
    }
}

fn ldabs_stmt(interner: &mut Interner, size: MemSize, imm: i32) -> CStmt {
    let name: String = format!("ebpf_ld_abs_{}", size.c_type());
    let call: CExpr = call_expr(interner, &name, vec![imm_operand(imm, true)]);
    let dst_ident: CExpr = reg_ident(interner, EReg::R0);
    assign(dst_ident, call)
}

fn ldind_stmt(interner: &mut Interner, size: MemSize, imm: i32, off_reg: EReg) -> CStmt {
    let name: String = format!("ebpf_ld_ind_{}", size.c_type());
    let args: Vec<CExpr> = vec![reg_ident(interner, off_reg), imm_operand(imm, true)];
    let call: CExpr = call_expr(interner, &name, args);
    let dst_ident: CExpr = reg_ident(interner, EReg::R0);
    assign(dst_ident, call)
}

fn map_fd_stmt(interner: &mut Interner, dst: EReg, fd: u32) -> CStmt {
    let name: String = format!("map_fd_{fd}");
    let var: CExpr = ident(interner, &name);
    let addr: CExpr = CExpr::Unary {
        op: UnaryOp::AddrOf,
        operand: Box::new(var),
    };
    let casted: CExpr = cast_to(interner, "uint64_t", addr);
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, casted)
}

fn load_imm64_stmt(interner: &mut Interner, dst: EReg, value: u64) -> CStmt {
    let lit: CExpr = CExpr::Int {
        value,
        radix: Radix::Hex,
        suffix: IntSuffix {
            unsigned: true,
            long: LongSuffix::LongLong,
        },
    };
    let dst_ident: CExpr = reg_ident(interner, dst);
    assign(dst_ident, lit)
}

fn unknown_stmt(interner: &mut Interner, raw: RawInsn) -> CStmt {
    let name: String = format!("ebpf_unrecognized_opcode_0x{:02x}", raw.opcode);
    let args: Vec<CExpr> = vec![
        CExpr::int(u64::from(raw.dst_reg)),
        CExpr::int(u64::from(raw.src_reg)),
        CExpr::Int {
            value: u64::from(raw.off as u16),
            radix: Radix::Hex,
            suffix: IntSuffix::none(),
        },
        CExpr::Int {
            value: u64::from(raw.imm as u32),
            radix: Radix::Hex,
            suffix: IntSuffix::none(),
        },
    ];
    CStmt::Expr(call_expr(interner, &name, args))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BranchCond {
    lhs: CExpr,
    rhs: CExpr,
    cmp: CmpOp,
}

impl BranchCond {
    fn negate(self) -> Self {
        Self {
            cmp: self.cmp.negate(),
            ..self
        }
    }

    fn to_cexpr(&self) -> CExpr {
        match self.cmp {
            CmpOp::Eq => bin(BinaryOp::Eq, self.lhs.clone(), self.rhs.clone()),
            CmpOp::Ne => bin(BinaryOp::Ne, self.lhs.clone(), self.rhs.clone()),
            CmpOp::Gt | CmpOp::Sgt => bin(BinaryOp::Gt, self.lhs.clone(), self.rhs.clone()),
            CmpOp::Ge | CmpOp::Sge => bin(BinaryOp::Ge, self.lhs.clone(), self.rhs.clone()),
            CmpOp::Lt | CmpOp::Slt => bin(BinaryOp::Lt, self.lhs.clone(), self.rhs.clone()),
            CmpOp::Le | CmpOp::Sle => bin(BinaryOp::Le, self.lhs.clone(), self.rhs.clone()),
            CmpOp::SetNz => bin(
                BinaryOp::Ne,
                bin(BinaryOp::BitAnd, self.lhs.clone(), self.rhs.clone()),
                CExpr::int(0),
            ),
            CmpOp::SetZ => bin(
                BinaryOp::Eq,
                bin(BinaryOp::BitAnd, self.lhs.clone(), self.rhs.clone()),
                CExpr::int(0),
            ),
        }
    }
}

fn branch_cond(
    interner: &mut Interner,
    cmp: CmpOp,
    dst: EReg,
    src: &Src,
    is64: bool,
) -> BranchCond {
    let signed: bool = matches!(cmp, CmpOp::Sgt | CmpOp::Sge | CmpOp::Slt | CmpOp::Sle);
    let (lhs, rhs): (CExpr, CExpr) = if signed {
        let sty: &str = if is64 { "int64_t" } else { "int32_t" };
        let dst_raw: CExpr = reg_operand(interner, dst, is64);
        let src_raw: CExpr = src_operand(interner, src, is64);
        (
            cast_to(interner, sty, dst_raw),
            cast_to(interner, sty, src_raw),
        )
    } else {
        (
            reg_operand(interner, dst, is64),
            src_operand(interner, src, is64),
        )
    };
    BranchCond { lhs, rhs, cmp }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cond {
    Leaf(BranchCond),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

impl Cond {
    fn to_cexpr(&self) -> CExpr {
        match self {
            Self::Leaf(c) => c.to_cexpr(),
            Self::And(a, b) => bin(BinaryOp::LogAnd, a.to_cexpr(), b.to_cexpr()),
            Self::Or(a, b) => bin(BinaryOp::LogOr, a.to_cexpr(), b.to_cexpr()),
        }
    }
}

#[derive(Debug, Clone)]
enum ETerm {
    Return(CExpr),
    Jump(usize),
    Branch {
        cond: BranchCond,
        taken: usize,
        fallthrough: usize,
    },
}

#[derive(Debug, Clone)]
struct EBlock {
    stmts: Vec<CStmt>,
    term: ETerm,
}

impl EBlock {
    fn successors(&self) -> Vec<usize> {
        match &self.term {
            ETerm::Return(_) => Vec::new(),
            ETerm::Jump(t) => vec![*t],
            ETerm::Branch {
                taken, fallthrough, ..
            } => {
                if taken == fallthrough {
                    vec![*taken]
                } else {
                    vec![*taken, *fallthrough]
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
struct BuildReport {
    unknown_opcodes: Vec<u8>,
    unresolved_helper_ids: Vec<u32>,
    resolved_helper_ids: Vec<u32>,
    map_fds: Vec<u32>,
    pseudo_targets: Vec<i64>,
    kfunc_ids: Vec<u32>,
    unknown_call_sources: Vec<(u8, i32)>,
    out_of_bounds_jumps: Vec<usize>,
}

enum SlotEffect {
    Stmt(CStmt),
    Nop,
    Exit(CExpr),
    Jump(i64),
    Branch {
        cond: BranchCond,
        taken: i64,
        fallthrough: usize,
    },
}

fn call_stmt(
    interner: &mut Interner,
    kind: &CallKind,
    idx: usize,
    report: &mut BuildReport,
) -> CStmt {
    let args: Vec<CExpr> = [EReg::R1, EReg::R2, EReg::R3, EReg::R4, EReg::R5]
        .into_iter()
        .map(|r: EReg| reg_ident(interner, r))
        .collect();
    let name: String = match kind {
        CallKind::Helper(id) => match ebpf_helper_name(*id) {
            Some(n) => {
                report.resolved_helper_ids.push(*id);
                n.to_owned()
            }
            None => {
                report.unresolved_helper_ids.push(*id);
                format!("helper_{id}")
            }
        },
        CallKind::Pseudo(off) => {
            let target: i64 = (idx as i64 + 1 + i64::from(*off)) * EBPF_INSN_SIZE as i64;
            report.pseudo_targets.push(target);
            format!("subprog_0x{target:x}")
        }
        CallKind::Kfunc(id) => {
            report.kfunc_ids.push(*id);
            format!("kfunc_{id}")
        }
        CallKind::Unknown(sr, imm) => {
            report.unknown_call_sources.push((*sr, *imm));
            format!("call_unknown_src{sr}_{imm}")
        }
    };
    let call: CExpr = call_expr(interner, &name, args);
    let dst_ident: CExpr = reg_ident(interner, EReg::R0);
    assign(dst_ident, call)
}

fn slot_effect(
    idx: usize,
    insn: Option<&LoweredInsn>,
    interner: &mut Interner,
    report: &mut BuildReport,
) -> SlotEffect {
    let Some(insn) = insn else {
        return SlotEffect::Nop;
    };
    match insn {
        LoweredInsn::Alu { op, is64, dst, src } => {
            SlotEffect::Stmt(alu_stmt(interner, *op, *is64, *dst, src))
        }
        LoweredInsn::Neg { is64, dst } => SlotEffect::Stmt(neg_stmt(interner, *is64, *dst)),
        LoweredInsn::Mov { is64, dst, src } => {
            SlotEffect::Stmt(mov_stmt(interner, *is64, *dst, src))
        }
        LoweredInsn::End { dst, bits, to_be } => {
            SlotEffect::Stmt(end_stmt(interner, *dst, *bits, *to_be))
        }
        LoweredInsn::LoadImm64 { dst, value } => {
            SlotEffect::Stmt(load_imm64_stmt(interner, *dst, *value))
        }
        LoweredInsn::MapFdLoad { dst, fd } => {
            report.map_fds.push(*fd);
            SlotEffect::Stmt(map_fd_stmt(interner, *dst, *fd))
        }
        LoweredInsn::Load {
            dst,
            base,
            off,
            size,
        } => SlotEffect::Stmt(load_stmt(interner, *dst, *base, *off, *size)),
        LoweredInsn::StoreImm {
            base,
            off,
            size,
            imm,
        } => SlotEffect::Stmt(store_imm_stmt(interner, *base, *off, *size, *imm)),
        LoweredInsn::StoreReg {
            base,
            off,
            size,
            src,
        } => SlotEffect::Stmt(store_reg_stmt(interner, *base, *off, *size, *src)),
        LoweredInsn::Atomic {
            base,
            off,
            size,
            src,
            op,
            fetch,
        } => SlotEffect::Stmt(atomic_stmt(interner, *base, *off, *size, *src, *op, *fetch)),
        LoweredInsn::LdAbs { size, imm } => SlotEffect::Stmt(ldabs_stmt(interner, *size, *imm)),
        LoweredInsn::LdInd { size, imm, off_reg } => {
            SlotEffect::Stmt(ldind_stmt(interner, *size, *imm, *off_reg))
        }
        LoweredInsn::Jump { target_off } => {
            let target: i64 = idx as i64 + 1 + *target_off;
            SlotEffect::Jump(target)
        }
        LoweredInsn::Branch {
            cmp,
            dst,
            src,
            is64,
            target_off,
        } => {
            let cond: BranchCond = branch_cond(interner, *cmp, *dst, src, *is64);
            let taken: i64 = idx as i64 + 1 + *target_off;
            SlotEffect::Branch {
                cond,
                taken,
                fallthrough: idx + 1,
            }
        }
        LoweredInsn::Call { kind } => SlotEffect::Stmt(call_stmt(interner, kind, idx, report)),
        LoweredInsn::Exit => {
            let r0: CExpr = reg_ident(interner, EReg::R0);
            let ret: CExpr = cast_to(interner, "int64_t", r0);
            SlotEffect::Exit(ret)
        }
        LoweredInsn::Unknown { raw } => {
            report.unknown_opcodes.push(raw.opcode);
            SlotEffect::Stmt(unknown_stmt(interner, *raw))
        }
    }
}

fn clip(target: i64, len: usize) -> usize {
    if target < 0 {
        return len;
    }
    let unsigned: u64 = target as u64;
    if unsigned >= len as u64 {
        len
    } else {
        unsigned as usize
    }
}

fn build_blocks(
    lowered: &[Option<LoweredInsn>],
    interner: &mut Interner,
    report: &mut BuildReport,
) -> Vec<EBlock> {
    let len: usize = lowered.len();
    if len == 0 {
        return vec![EBlock {
            stmts: Vec::new(),
            term: ETerm::Return(CExpr::int(0)),
        }];
    }
    let effects: Vec<SlotEffect> = lowered
        .iter()
        .enumerate()
        .map(|(i, o): (usize, &Option<LoweredInsn>)| slot_effect(i, o.as_ref(), interner, report))
        .collect();

    let mut is_leader: Vec<bool> = vec![false; len];
    is_leader[0] = true;
    for (i, eff) in effects.iter().enumerate() {
        match eff {
            SlotEffect::Jump(t) => {
                let c: usize = clip(*t, len);
                if c < len {
                    is_leader[c] = true;
                }
                if i + 1 < len {
                    is_leader[i + 1] = true;
                }
            }
            SlotEffect::Branch {
                taken, fallthrough, ..
            } => {
                let ct: usize = clip(*taken, len);
                if ct < len {
                    is_leader[ct] = true;
                }
                if *fallthrough < len {
                    is_leader[*fallthrough] = true;
                }
                if i + 1 < len {
                    is_leader[i + 1] = true;
                }
            }
            SlotEffect::Exit(_) => {
                if i + 1 < len {
                    is_leader[i + 1] = true;
                }
            }
            SlotEffect::Stmt(_) | SlotEffect::Nop => {}
        }
    }

    let mut slot_to_block: Vec<usize> = vec![0; len];
    let mut block_count: usize = 0;
    for i in 0..len {
        if is_leader[i] {
            block_count += 1;
        }
        slot_to_block[i] = block_count - 1;
    }
    let sink_block: usize = block_count;

    let resolve_slot = |slot: usize| -> usize {
        if slot >= len {
            sink_block
        } else {
            slot_to_block[slot]
        }
    };

    let mut blocks: Vec<EBlock> = Vec::with_capacity(block_count + 1);
    let mut i: usize = 0;
    while i < len {
        let start: usize = i;
        let mut stmts: Vec<CStmt> = Vec::new();
        loop {
            match &effects[i] {
                SlotEffect::Stmt(s) => stmts.push(s.clone()),
                SlotEffect::Nop => {}
                SlotEffect::Exit(_) | SlotEffect::Jump(_) | SlotEffect::Branch { .. } => break,
            }
            if i + 1 >= len || is_leader[i + 1] {
                break;
            }
            i += 1;
        }
        let term: ETerm = match &effects[i] {
            SlotEffect::Exit(e) => ETerm::Return(e.clone()),
            SlotEffect::Jump(t) => {
                let c: usize = clip(*t, len);
                let target_block: usize = if c >= len {
                    report.out_of_bounds_jumps.push(i);
                    sink_block
                } else {
                    slot_to_block[c]
                };
                ETerm::Jump(target_block)
            }
            SlotEffect::Branch {
                cond,
                taken,
                fallthrough,
            } => {
                let ct: usize = clip(*taken, len);
                let taken_block: usize = if ct >= len {
                    report.out_of_bounds_jumps.push(i);
                    sink_block
                } else {
                    slot_to_block[ct]
                };
                ETerm::Branch {
                    cond: cond.clone(),
                    taken: taken_block,
                    fallthrough: resolve_slot(*fallthrough),
                }
            }
            SlotEffect::Stmt(_) | SlotEffect::Nop => ETerm::Jump(resolve_slot(i + 1)),
        };
        let _ = start;
        blocks.push(EBlock { stmts, term });
        i += 1;
    }
    blocks.push(EBlock {
        stmts: Vec::new(),
        term: ETerm::Return(CExpr::int(0)),
    });
    blocks
}

fn cfg_from_blocks(blocks: &[EBlock]) -> Option<structuring::Cfg> {
    let count: usize = blocks.len();
    let mut nodes: Vec<structuring::CfgNode> = Vec::with_capacity(count);
    for (idx, block) in blocks.iter().enumerate() {
        let pure: bool = block.stmts.is_empty();
        let term: structuring::Terminator = match &block.term {
            ETerm::Return(_) => structuring::Terminator::Return,
            ETerm::Jump(t) => {
                if *t >= count {
                    return None;
                }
                structuring::Terminator::Goto(*t as u32)
            }
            ETerm::Branch {
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

fn atom_branch(blocks: &[EBlock], atom: structuring::Atom) -> Option<BranchCond> {
    match &blocks.get(atom as usize)?.term {
        ETerm::Branch { cond, .. } => Some(cond.clone()),
        _ => None,
    }
}

fn cond_from_region(
    blocks: &[EBlock],
    conds: &structuring::CondPool,
    id: structuring::CondId,
) -> Option<Cond> {
    match conds.nodes().get(id as usize)? {
        structuring::Cond::Leaf(atom) => Some(Cond::Leaf(atom_branch(blocks, *atom)?)),
        structuring::Cond::NotLeaf(atom) => Some(Cond::Leaf(atom_branch(blocks, *atom)?.negate())),
        structuring::Cond::And(l, r) => Some(Cond::And(
            Box::new(cond_from_region(blocks, conds, *l)?),
            Box::new(cond_from_region(blocks, conds, *r)?),
        )),
        structuring::Cond::Or(l, r) => Some(Cond::Or(
            Box::new(cond_from_region(blocks, conds, *l)?),
            Box::new(cond_from_region(blocks, conds, *r)?),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    Return,
    Break,
    Continue,
}

struct Renderer<'a> {
    blocks: &'a [EBlock],
    result: &'a structuring::StructureResult,
    forest: &'a structuring::LoopForest,
    sinks: &'a BTreeMap<usize, Sink>,
    consumed: BTreeSet<usize>,
}

impl Renderer<'_> {
    fn render_sink(&self, entry: usize, out: &mut Vec<CStmt>) {
        match self.sinks.get(&entry).copied().unwrap_or(Sink::Return) {
            Sink::Return => {
                let ret_expr: Option<CExpr> = match &self.blocks[entry].term {
                    ETerm::Return(e) => Some(e.clone()),
                    _ => None,
                };
                out.push(CStmt::Return(ret_expr));
            }
            Sink::Break => out.push(CStmt::Break),
            Sink::Continue => out.push(CStmt::Continue),
        }
    }

    fn render_loop(&mut self, header: usize, out: &mut Vec<CStmt>) -> bool {
        let Some(natural): Option<&structuring::NaturalLoop> = self
            .forest
            .loops
            .iter()
            .find(|l: &&structuring::NaturalLoop| l.header as usize == header)
        else {
            return false;
        };
        let body: BTreeSet<usize> = natural.body.iter().map(|n: &u32| *n as usize).collect();
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
        let sub_of: BTreeMap<usize, usize> = order
            .iter()
            .enumerate()
            .map(|(i, &n): (usize, &usize)| (n, i))
            .collect();
        let cont_idx: usize = order.len();
        let brk_idx: usize = order.len() + 1;
        let remap = |target: usize| -> Option<usize> {
            if target == header {
                Some(cont_idx)
            } else if let Some(&i) = sub_of.get(&target) {
                Some(i)
            } else if Some(target) == follow {
                Some(brk_idx)
            } else {
                None
            }
        };
        let mut sub_blocks: Vec<EBlock> = Vec::with_capacity(order.len() + 2);
        for &node in &order {
            let term: ETerm = match &self.blocks[node].term {
                ETerm::Return(e) => ETerm::Return(e.clone()),
                ETerm::Jump(t) => {
                    let Some(t2): Option<usize> = remap(*t) else {
                        return false;
                    };
                    ETerm::Jump(t2)
                }
                ETerm::Branch {
                    cond,
                    taken,
                    fallthrough,
                } => {
                    let (Some(t2), Some(f2)): (Option<usize>, Option<usize>) =
                        (remap(*taken), remap(*fallthrough))
                    else {
                        return false;
                    };
                    ETerm::Branch {
                        cond: cond.clone(),
                        taken: t2,
                        fallthrough: f2,
                    }
                }
            };
            sub_blocks.push(EBlock {
                stmts: self.blocks[node].stmts.clone(),
                term,
            });
        }
        sub_blocks.push(EBlock {
            stmts: Vec::new(),
            term: ETerm::Return(CExpr::int(0)),
        });
        sub_blocks.push(EBlock {
            stmts: Vec::new(),
            term: ETerm::Return(CExpr::int(0)),
        });
        let mut sub_sinks: BTreeMap<usize, Sink> = BTreeMap::new();
        sub_sinks.insert(cont_idx, Sink::Continue);
        sub_sinks.insert(brk_idx, Sink::Break);
        for &node in &order {
            if matches!(self.blocks[node].term, ETerm::Return(_))
                && let Some(&s) = self.sinks.get(&node)
            {
                sub_sinks.insert(sub_of[&node], s);
            }
        }
        let Some(loop_body): Option<Vec<CStmt>> = structure_program(&sub_blocks, &sub_sinks) else {
            return false;
        };
        out.push(CStmt::While {
            cond: CExpr::int(1),
            body: Box::new(CStmt::Block(loop_body)),
        });
        for node in body {
            self.consumed.insert(node);
        }
        true
    }

    fn render(&mut self, id: structuring::RegionId, out: &mut Vec<CStmt>) -> bool {
        let region: &structuring::Region = &self.result.regions[id as usize];
        let kind: structuring::RegionKind = region.kind;
        let entry: usize = region.entry as usize;
        let cond_id: Option<structuring::CondId> = region.cond;
        let head: Option<structuring::RegionId> = region.head;
        let children: Vec<structuring::RegionId> = region.children.clone();
        match kind {
            structuring::RegionKind::Block if children.is_empty() => {
                if entry >= self.blocks.len() || !self.consumed.insert(entry) {
                    return false;
                }
                out.extend(self.blocks[entry].stmts.iter().cloned());
                if matches!(self.blocks[entry].term, ETerm::Return(_)) {
                    self.render_sink(entry, out);
                }
                true
            }
            structuring::RegionKind::Block => children
                .iter()
                .all(|&child: &structuring::RegionId| self.render(child, out)),
            structuring::RegionKind::IfThen => {
                let (Some(head), Some(cond_id), Some(&arm)) = (head, cond_id, children.first())
                else {
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
                let mut then_body: Vec<CStmt> = Vec::new();
                if !self.render(arm, &mut then_body) {
                    return false;
                }
                out.push(CStmt::If {
                    cond: cond.to_cexpr(),
                    then: Box::new(CStmt::Block(then_body)),
                    els: None,
                });
                true
            }
            structuring::RegionKind::IfThenElse => {
                let (Some(head), Some(cond_id)) = (head, cond_id) else {
                    return false;
                };
                let [taken_id, not_taken_id]: [structuring::RegionId; 2] = match children.as_slice()
                {
                    [a, b] => [*a, *b],
                    _ => return false,
                };
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
                    let Cond::Leaf(leaf) = cond else {
                        return false;
                    };
                    (Cond::Leaf(leaf.negate()), not_taken_id, taken_id)
                };
                let mut then_body: Vec<CStmt> = Vec::new();
                if !self.render(then_id, &mut then_body) {
                    return false;
                }
                let mut else_body: Vec<CStmt> = Vec::new();
                if !self.render(else_id, &mut else_body) {
                    return false;
                }
                out.push(CStmt::If {
                    cond: guard.to_cexpr(),
                    then: Box::new(CStmt::Block(then_body)),
                    els: Some(Box::new(CStmt::Block(else_body))),
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

fn reachable_blocks(blocks: &[EBlock]) -> BTreeSet<usize> {
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = vec![0];
    seen.insert(0);
    while let Some(n) = stack.pop() {
        for s in blocks[n].successors() {
            if seen.insert(s) {
                stack.push(s);
            }
        }
    }
    seen
}

fn structure_program(blocks: &[EBlock], sinks: &BTreeMap<usize, Sink>) -> Option<Vec<CStmt>> {
    let cfg: structuring::Cfg = cfg_from_blocks(blocks)?;
    let result: structuring::StructureResult = structuring::structure(&cfg);
    if !result.is_complete() {
        return None;
    }
    let forest: structuring::LoopForest = structuring::loop_forest(&cfg);
    let root: structuring::RegionId = result.root?;
    let mut renderer: Renderer<'_> = Renderer {
        blocks,
        result: &result,
        forest: &forest,
        sinks,
        consumed: BTreeSet::new(),
    };
    let mut body: Vec<CStmt> = Vec::new();
    if !renderer.render(root, &mut body) {
        return None;
    }
    if renderer.consumed != reachable_blocks(blocks) {
        return None;
    }
    Some(body)
}

fn render_flat(blocks: &[EBlock], interner: &mut Interner) -> Vec<CStmt> {
    let mut out: Vec<CStmt> = Vec::with_capacity(blocks.len() * 2);
    for (idx, block) in blocks.iter().enumerate() {
        let label: disrobe_emit::Symbol = interner.intern(&format!("ebpf_bb_{idx}"));
        out.push(CStmt::Label {
            name: label,
            body: Box::new(CStmt::Empty),
        });
        out.extend(block.stmts.iter().cloned());
        match &block.term {
            ETerm::Return(e) => out.push(CStmt::Return(Some(e.clone()))),
            ETerm::Jump(t) => {
                let target: disrobe_emit::Symbol = interner.intern(&format!("ebpf_bb_{t}"));
                out.push(CStmt::Goto(target));
            }
            ETerm::Branch {
                cond,
                taken,
                fallthrough,
            } => {
                let taken_label: disrobe_emit::Symbol =
                    interner.intern(&format!("ebpf_bb_{taken}"));
                out.push(CStmt::If {
                    cond: cond.to_cexpr(),
                    then: Box::new(CStmt::Goto(taken_label)),
                    els: None,
                });
                let fall_label: disrobe_emit::Symbol =
                    interner.intern(&format!("ebpf_bb_{fallthrough}"));
                out.push(CStmt::Goto(fall_label));
            }
        }
    }
    out
}

fn dedup_sorted<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

fn decl_u64(interner: &mut Interner, name: &str, init: Option<CExpr>) -> CStmt {
    let spec: CTypeSpec = CTypeSpec::Named(interner.intern("uint64_t"));
    CStmt::Decl(CDecl {
        storage: None,
        base: CBaseType::plain(spec),
        name: Some(interner.intern(name)),
        declarator: DeclaratorChain::Terminal,
        init: init.map(CInit::Expr),
    })
}

const EBPF_STACK_BYTES: u64 = 512;

fn assemble_source(
    interner: &mut Interner,
    func_name: &str,
    report: &BuildReport,
    body: Vec<CStmt>,
) -> String {
    let mut preamble: String = String::new();
    let _ = writeln!(preamble, "#include <stdint.h>");
    for fd in dedup_sorted(report.map_fds.clone()) {
        let _ = writeln!(preamble, "extern void *map_fd_{fd};");
    }
    for id in dedup_sorted(report.resolved_helper_ids.clone()) {
        if let Some(name) = ebpf_helper_name(id) {
            let _ = writeln!(
                preamble,
                "extern uint64_t {name}(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);"
            );
        }
    }
    for id in dedup_sorted(report.unresolved_helper_ids.clone()) {
        let _ = writeln!(
            preamble,
            "extern uint64_t helper_{id}(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);"
        );
    }
    for id in dedup_sorted(report.kfunc_ids.clone()) {
        let _ = writeln!(
            preamble,
            "extern uint64_t kfunc_{id}(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);"
        );
    }
    for target in dedup_sorted(report.pseudo_targets.clone()) {
        let _ = writeln!(
            preamble,
            "extern uint64_t subprog_0x{target:x}(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);"
        );
    }
    for (sr, imm) in dedup_sorted(report.unknown_call_sources.clone()) {
        let _ = writeln!(
            preamble,
            "extern uint64_t call_unknown_src{sr}_{imm}(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);"
        );
    }
    for opcode in dedup_sorted(report.unknown_opcodes.clone()) {
        let _ = writeln!(
            preamble,
            "extern void ebpf_unrecognized_opcode_0x{opcode:02x}(int64_t, int64_t, int64_t, int64_t);"
        );
    }

    let param_names: [&str; 5] = ["r1", "r2", "r3", "r4", "r5"];
    let params: Vec<CParam> = param_names
        .iter()
        .map(|name: &&str| CParam {
            base: CBaseType::plain(CTypeSpec::Named(interner.intern("uint64_t"))),
            name: Some(interner.intern(name)),
            declarator: DeclaratorChain::Terminal,
        })
        .collect();
    let decl: CDecl = CDecl {
        storage: None,
        base: CBaseType::plain(CTypeSpec::Named(interner.intern("int64_t"))),
        name: Some(interner.intern(func_name)),
        declarator: DeclaratorChain::Terminal.returning(params, false),
        init: None,
    };

    let mut full_body: Vec<CStmt> = Vec::new();
    full_body.push(decl_u64(interner, "r0", Some(CExpr::int(0))));
    for extra in ["r6", "r7", "r8", "r9"] {
        full_body.push(decl_u64(interner, extra, Some(CExpr::int(0))));
    }
    let stack_spec: CTypeSpec = CTypeSpec::UnsignedChar;
    let stack_decl: CDecl = CDecl {
        storage: None,
        base: CBaseType::plain(stack_spec),
        name: Some(interner.intern("ebpf_stack")),
        declarator: DeclaratorChain::Terminal.array_of(Some(CExpr::int(EBPF_STACK_BYTES))),
        init: None,
    };
    full_body.push(CStmt::Decl(stack_decl));
    let stack_ident: CExpr = ident(interner, "ebpf_stack");
    let r10_sum: CExpr = bin(BinaryOp::Add, stack_ident, CExpr::int(EBPF_STACK_BYTES));
    let r10_init: CExpr = cast_to(interner, "uint64_t", r10_sum);
    full_body.push(decl_u64(interner, "r10", Some(r10_init)));
    full_body.extend(body);

    let item: CItem = CItem::Function {
        decl,
        body: full_body,
    };
    let rendered: String = render_item(&item, interner, C_RENDER_WIDTH);
    format!("{preamble}{rendered}\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfRecovery {
    pub source: String,
    pub instruction_count: usize,
    pub structured: bool,
    pub unknown_opcodes: Vec<u8>,
    pub unresolved_helper_ids: Vec<u32>,
    pub map_fds: Vec<u32>,
    pub out_of_bounds_jumps: Vec<usize>,
}

pub fn recover_ebpf_program(bytes: &[u8], func_name: &str) -> Result<EbpfRecovery> {
    let raw: Vec<RawInsn> = decode_raw(bytes)?;
    let lowered: Vec<Option<LoweredInsn>> = lower(&raw);
    let mut interner: Interner = Interner::new();
    let mut report: BuildReport = BuildReport::default();
    let blocks: Vec<EBlock> = build_blocks(&lowered, &mut interner, &mut report);
    let sinks: BTreeMap<usize, Sink> = BTreeMap::new();
    let (body, structured): (Vec<CStmt>, bool) = structure_program(&blocks, &sinks).map_or_else(
        || (render_flat(&blocks, &mut interner), false),
        |b: Vec<CStmt>| (b, true),
    );
    let source: String = assemble_source(&mut interner, func_name, &report, body);
    Ok(EbpfRecovery {
        source,
        instruction_count: raw.len(),
        structured,
        unknown_opcodes: dedup_sorted(report.unknown_opcodes),
        unresolved_helper_ids: dedup_sorted(report.unresolved_helper_ids),
        map_fds: dedup_sorted(report.map_fds),
        out_of_bounds_jumps: dedup_sorted(report.out_of_bounds_jumps),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut out: [u8; 8] = [0; 8];
        out[0] = opcode;
        out[1] = (dst & 0x0f) | ((src & 0x0f) << 4);
        out[2..4].copy_from_slice(&off.to_le_bytes());
        out[4..8].copy_from_slice(&imm.to_le_bytes());
        out
    }

    #[test]
    fn decode_raw_rejects_non_multiple_of_eight() {
        let err: Error = decode_raw(&[0u8; 5]).expect_err("must reject");
        assert!(matches!(err, Error::EbpfDecode(_)));
    }

    #[test]
    fn decode_raw_matches_objdump_reference_add_r0_r2() {
        let bytes: [u8; 8] = insn(0x0f, 0, 2, 0, 0);
        let decoded: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].opcode, 0x0f);
        assert_eq!(decoded[0].dst_reg, 0);
        assert_eq!(decoded[0].src_reg, 2);
        let lowered: LoweredInsn = lower_single(decoded[0]);
        assert!(matches!(
            lowered,
            LoweredInsn::Alu {
                op: AluOp::Add,
                is64: true,
                dst: EReg::R0,
                src: Src::Reg(EReg::R2),
            }
        ));
    }

    #[test]
    fn decode_raw_matches_objdump_reference_exit() {
        let bytes: [u8; 8] = insn(0x95, 0, 0, 0, 0);
        let decoded: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        assert!(matches!(lower_single(decoded[0]), LoweredInsn::Exit));
    }

    #[test]
    fn decode_raw_matches_objdump_reference_signed_branch() {
        let bytes: [u8; 8] = insn(0xdd, 1, 2, 6, 0);
        let decoded: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        let lowered: LoweredInsn = lower_single(decoded[0]);
        assert!(matches!(
            lowered,
            LoweredInsn::Branch {
                cmp: CmpOp::Sle,
                dst: EReg::R1,
                src: Src::Reg(EReg::R2),
                is64: true,
                target_off: 6,
            }
        ));
    }

    #[test]
    fn decode_raw_matches_objdump_reference_call_helper() {
        let bytes: [u8; 8] = insn(0x85, 0, 0, 0, 7);
        let decoded: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        let lowered: LoweredInsn = lower_single(decoded[0]);
        assert!(matches!(
            lowered,
            LoweredInsn::Call {
                kind: CallKind::Helper(7)
            }
        ));
        assert_eq!(ebpf_helper_name(7), Some("bpf_get_prandom_u32"));
    }

    #[test]
    fn lddw_folds_two_slots_into_one_logical_instruction() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&insn(0x18, 1, 0, 0, 0x1122_3344u32 as i32));
        bytes.extend_from_slice(&insn(0, 0, 0, 0, 0x5566_7788u32 as i32));
        let raw: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        let lowered: Vec<Option<LoweredInsn>> = lower(&raw);
        assert_eq!(lowered.len(), 2);
        assert!(lowered[1].is_none());
        match &lowered[0] {
            Some(LoweredInsn::LoadImm64 { dst, value }) => {
                assert_eq!(*dst, EReg::R1);
                assert_eq!(*value, 0x5566_7788_1122_3344u64);
            }
            other => panic!("unexpected lowering: {other:?}"),
        }
    }

    #[test]
    fn lddw_pseudo_map_fd_is_recognized() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&insn(0x18, 1, 1, 0, 3));
        bytes.extend_from_slice(&insn(0, 0, 0, 0, 0));
        let raw: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        let lowered: Vec<Option<LoweredInsn>> = lower(&raw);
        assert!(matches!(
            lowered[0],
            Some(LoweredInsn::MapFdLoad {
                dst: EReg::R1,
                fd: 3
            })
        ));
    }

    #[test]
    fn lddw_with_nonzero_second_slot_opcode_degrades_to_unknown() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&insn(0x18, 1, 0, 0, 0x1122_3344u32 as i32));
        bytes.extend_from_slice(&insn(0x07, 0, 0, 0, 0x5566_7788u32 as i32));
        let raw: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        let lowered: Vec<Option<LoweredInsn>> = lower(&raw);
        assert_eq!(lowered.len(), 2);
        assert!(
            matches!(lowered[0], Some(LoweredInsn::Unknown { .. })),
            "malformed second slot must not be silently folded into a 64-bit immediate: {lowered:?}"
        );
        assert!(matches!(lowered[1], Some(LoweredInsn::Unknown { .. })));

        let recovery: EbpfRecovery = recover_ebpf_program(&bytes, "prog").expect("recover");
        assert_eq!(recovery.unknown_opcodes, vec![0x07, 0x18]);
    }

    #[test]
    fn register_nibble_above_ten_degrades_to_unknown() {
        let bytes: [u8; 8] = insn(0xbf, 11, 0, 0, 0);
        let raw: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        assert!(matches!(lower_single(raw[0]), LoweredInsn::Unknown { .. }));

        let recovery: EbpfRecovery = recover_ebpf_program(&bytes, "prog").expect("recover");
        assert!(recovery.unknown_opcodes.contains(&0xbf));
        assert!(
            !recovery.source.contains("r11"),
            "an out-of-range register nibble must never reach C emission as an identifier: {}",
            recovery.source
        );
    }

    #[test]
    fn jump_target_outside_instruction_range_is_recorded_in_report() {
        let bytes: [u8; 8] = insn(0x05, 0, 0, 100, 0);
        let recovery: EbpfRecovery = recover_ebpf_program(&bytes, "prog").expect("recover");
        assert_eq!(recovery.out_of_bounds_jumps, vec![0]);
    }

    #[test]
    fn branch_target_outside_instruction_range_is_recorded_in_report() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&insn(0x1d, 1, 2, 200, 0));
        bytes.extend_from_slice(&insn(0x95, 0, 0, 0, 0));
        let recovery: EbpfRecovery = recover_ebpf_program(&bytes, "prog").expect("recover");
        assert_eq!(recovery.out_of_bounds_jumps, vec![0]);
    }

    #[test]
    fn unknown_opcode_degrades_without_panicking() {
        let bytes: [u8; 8] = insn(0xff, 0, 0, 0, 0);
        let raw: Vec<RawInsn> = decode_raw(&bytes).expect("decode");
        assert!(matches!(lower_single(raw[0]), LoweredInsn::Unknown { .. }));
    }

    #[test]
    fn recover_straight_line_program_never_panics_and_structures() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&insn(0x79, 2, 1, 0, 0));
        bytes.extend_from_slice(&insn(0x79, 0, 1, 8, 0));
        bytes.extend_from_slice(&insn(0x0f, 0, 2, 0, 0));
        bytes.extend_from_slice(&insn(0x95, 0, 0, 0, 0));
        let recovery: EbpfRecovery = recover_ebpf_program(&bytes, "prog").expect("recover");
        assert!(recovery.structured);
        assert!(recovery.source.contains("int64_t prog"));
        assert!(recovery.source.contains("return"));
        assert!(recovery.unknown_opcodes.is_empty());
    }

    #[test]
    fn recover_handles_truncated_input_without_panic() {
        let bytes: [u8; 3] = [0x18, 0x01, 0x00];
        let err: Error = recover_ebpf_program(&bytes, "prog").expect_err("must reject cleanly");
        assert!(matches!(err, Error::EbpfDecode(_)));
    }

    #[test]
    fn recover_handles_arbitrary_bytes_without_panic() {
        for seed in 0u8..64 {
            let mut bytes: Vec<u8> = Vec::with_capacity(64);
            for i in 0..64u8 {
                bytes.push(seed.wrapping_mul(31).wrapping_add(i));
            }
            let _ = recover_ebpf_program(&bytes, "prog");
        }
    }

    #[test]
    fn helper_table_is_sorted_and_deduplicated() {
        let mut seen: Vec<u32> = Vec::new();
        for &(id, _) in HELPERS {
            assert!(!seen.contains(&id), "duplicate helper id {id}");
            seen.push(id);
        }
        let mut sorted: Vec<u32> = seen.clone();
        sorted.sort_unstable();
        assert_eq!(seen, sorted);
    }
}
