use std::collections::BTreeMap;

use crate::decompile::lift::{LiftedProto, lift_proto_dialect};
use crate::error::{Error, Result};
use crate::obfuscator::ironbrew2_dispatch::{
    ArgForm, CallForm, CmpForm, CmpOp, IbOpcode, RetCount, RetForm, recover_opcode_map,
    recover_opcode_table,
};
use crate::obfuscator::ironbrew2_real::{
    IbChunk, IbInstr, decode_bytestring, deserialize_chunk, recover_keys, strip_watermark,
};
use crate::reader::common::{LuaConstant, LuaDialect, LuaProto};

const OP_MOVE: u8 = 0;
const OP_LOADK: u8 = 1;
const OP_LOADBOOL: u8 = 2;
const OP_LOADNIL: u8 = 3;
const OP_GETGLOBAL: u8 = 5;
const OP_GETTABLE: u8 = 6;
const OP_SETGLOBAL: u8 = 7;
const OP_SETTABLE: u8 = 9;
const OP_NEWTABLE: u8 = 10;
const OP_SELF: u8 = 11;
const OP_ADD: u8 = 12;
const OP_SUB: u8 = 13;
const OP_MUL: u8 = 14;
const OP_DIV: u8 = 15;
const OP_MOD: u8 = 16;
const OP_POW: u8 = 17;
const OP_UNM: u8 = 18;
const OP_NOT: u8 = 19;
const OP_LEN: u8 = 20;
const OP_CONCAT: u8 = 21;
const OP_JMP: u8 = 22;
const OP_EQ: u8 = 23;
const OP_LT: u8 = 24;
const OP_LE: u8 = 25;
const OP_TEST: u8 = 26;
const OP_CALL: u8 = 28;
const OP_RETURN: u8 = 30;
const OP_FORLOOP: u8 = 31;
const OP_FORPREP: u8 = 32;
const OP_SETLIST: u8 = 34;
const OP_CLOSURE: u8 = 36;

const RK_BIT: u32 = 1 << 8;
const SBX_BIAS: i64 = 0x1FFFF;

#[derive(Debug, Clone)]
pub struct RecoveredProgram {
    pub proto: LuaProto,
    pub stats: RecoverStats,
    pub chunk: IbChunk,
    pub opmap: BTreeMap<u16, IbOpcode>,
    pub optable: BTreeMap<u16, Vec<IbOpcode>>,
}

#[derive(Debug, Clone, Default)]
pub struct RecoverStats {
    pub total_handlers: usize,
    pub classified_handlers: usize,
    pub total_instructions: usize,
    pub lifted_instructions: usize,
    pub constants: usize,
    pub functions: usize,
    pub xor_key: u8,
}

impl RecoverStats {
    #[must_use]
    pub fn handler_pct(&self) -> u8 {
        pct(self.classified_handlers, self.total_handlers)
    }
    #[must_use]
    pub fn instruction_pct(&self) -> u8 {
        pct(self.lifted_instructions, self.total_instructions)
    }
    #[must_use]
    pub fn fully_recovered(&self) -> bool {
        self.total_handlers > 0
            && self.classified_handlers == self.total_handlers
            && self.lifted_instructions == self.total_instructions
    }
}

#[must_use]
fn pct(num: usize, den: usize) -> u8 {
    if den == 0 {
        return 100;
    }
    u8::try_from((num.saturating_mul(100) / den).min(100)).unwrap_or(100)
}

pub fn recover(src: &str) -> Result<RecoveredProgram> {
    let body: &str = strip_watermark(src);
    let keys = recover_keys(body)?;
    let (payload, _compression): (Vec<u8>, _) = decode_bytestring(body)?;
    let chunk: IbChunk = deserialize_chunk(&payload, &keys)?;
    let max_enum: u16 = chunk_max_op(&chunk);
    let optable: BTreeMap<u16, Vec<IbOpcode>> = recover_opcode_table(body, max_enum)?;
    let opmap: BTreeMap<u16, IbOpcode> = recover_opcode_map(body, max_enum)?;

    let mut stats: RecoverStats = RecoverStats {
        xor_key: keys.xor_key,
        ..RecoverStats::default()
    };
    stats.total_handlers = usize::from(max_enum) + 1;
    stats.classified_handlers = optable
        .values()
        .filter(|ops: &&Vec<IbOpcode>| {
            !ops.is_empty()
                && ops
                    .iter()
                    .all(|o: &IbOpcode| !matches!(o, IbOpcode::Unknown))
        })
        .count();

    let proto: LuaProto = build_proto(&chunk, &opmap, &mut stats);
    Ok(RecoveredProgram {
        proto,
        stats,
        chunk,
        opmap,
        optable,
    })
}

const RUNNABLE_PRELUDE: &str =
    "local __ENV = _ENV or getfenv()\nlocal unpack = unpack or table.unpack\n";

pub fn recover_runnable(src: &str) -> Result<String> {
    let program: RecoveredProgram = recover(src)?;
    Ok(runnable_source(&program))
}

#[must_use]
pub fn runnable_source(program: &RecoveredProgram) -> String {
    let body: String =
        crate::obfuscator::ironbrew2_emit::emit_program(&program.chunk, &program.optable);
    format!("{RUNNABLE_PRELUDE}{body}")
}

#[must_use]
fn chunk_max_op(chunk: &IbChunk) -> u16 {
    let mut m: u16 = 0;
    for ins in &chunk.instrs {
        m = m.max(ins.op);
    }
    for f in &chunk.functions {
        m = m.max(chunk_max_op(f));
    }
    m
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Final(u32),
    JumpAbs { op: u8, a: u32, ib_target: i64 },
}

fn build_proto(
    chunk: &IbChunk,
    opmap: &BTreeMap<u16, IbOpcode>,
    stats: &mut RecoverStats,
) -> LuaProto {
    stats.constants += chunk.constants.len();
    stats.total_instructions += chunk.instrs.len();
    let mut slots: Vec<Slot> = Vec::with_capacity(chunk.instrs.len());
    let mut ib_to_vanilla: Vec<usize> = Vec::with_capacity(chunk.instrs.len() + 1);
    let mut max_reg: u8 = 2;

    for ins in &chunk.instrs {
        ib_to_vanilla.push(slots.len());
        let op: IbOpcode = opmap.get(&ins.op).copied().unwrap_or(IbOpcode::Unknown);
        if let Ok(a) = u8::try_from(ins.a.clamp(0, 255)) {
            max_reg = max_reg.max(a);
        }
        let emitted: bool = emit_slots(op, ins, &mut slots);
        if emitted {
            stats.lifted_instructions += 1;
        }
    }
    ib_to_vanilla.push(slots.len());

    let mut code: Vec<u32> = Vec::with_capacity(slots.len());
    for (vanilla_idx, slot) in slots.iter().enumerate() {
        match slot {
            Slot::Final(word) => code.push(*word),
            Slot::JumpAbs { op, a, ib_target } => {
                let target_ib: usize =
                    (*ib_target).clamp(0, ib_to_vanilla.len() as i64 - 1) as usize;
                let target_vanilla: i64 =
                    *ib_to_vanilla.get(target_ib).unwrap_or(&slots.len()) as i64;
                let sbx: i64 = target_vanilla - (vanilla_idx as i64) - 1;
                code.push(pack_asbx(*op, *a, sbx));
            }
        }
    }

    let mut protos: Vec<LuaProto> = Vec::with_capacity(chunk.functions.len());
    for f in &chunk.functions {
        stats.functions += 1;
        protos.push(build_proto(f, opmap, stats));
    }

    LuaProto {
        source: Some("ironbrew2-devirtualized".to_owned()),
        line_defined: 0,
        last_line_defined: 0,
        num_params: chunk.param_count,
        is_vararg: 2,
        max_stack_size: max_reg.saturating_add(2).max(2),
        code,
        constants: chunk.constants.clone(),
        protos,
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues: Vec::new(),
    }
}

fn emit_slots(op: IbOpcode, ins: &IbInstr, slots: &mut Vec<Slot>) -> bool {
    match op {
        IbOpcode::Jmp => {
            slots.push(Slot::JumpAbs {
                op: OP_JMP,
                a: 0,
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::ForLoop => {
            slots.push(Slot::JumpAbs {
                op: OP_FORLOOP,
                a: reg_a(ins),
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::ForPrep => {
            slots.push(Slot::JumpAbs {
                op: OP_FORPREP,
                a: reg_a(ins),
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::Eq | IbOpcode::Lt | IbOpcode::Le => {
            let cmp_op: u8 = match op {
                IbOpcode::Eq => OP_EQ,
                IbOpcode::Lt => OP_LT,
                _ => OP_LE,
            };
            slots.push(Slot::Final(pack_abc(
                cmp_op,
                0,
                cmp_left(ins),
                cmp_right(ins),
            )));
            slots.push(Slot::JumpAbs {
                op: OP_JMP,
                a: 0,
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::Compare(form) => {
            let (cmp_op, a_field): (u8, u32) = compare_native(form);
            let (left, right): (u32, u32) = compare_operands(form, ins);
            slots.push(Slot::Final(pack_abc(cmp_op, a_field, left, right)));
            slots.push(Slot::JumpAbs {
                op: OP_JMP,
                a: 0,
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::Test => {
            slots.push(Slot::Final(pack_abc(OP_TEST, reg_a(ins), 0, 0)));
            slots.push(Slot::JumpAbs {
                op: OP_JMP,
                a: 0,
                ib_target: ins.b,
            });
            true
        }
        IbOpcode::TestC => {
            slots.push(Slot::Final(pack_abc(OP_TEST, reg_a(ins), 0, 1)));
            slots.push(Slot::JumpAbs {
                op: OP_JMP,
                a: 0,
                ib_target: ins.b,
            });
            true
        }
        _ => match lower_instruction(op, ins) {
            Some(word) => {
                slots.push(Slot::Final(word));
                true
            }
            None => {
                slots.push(Slot::Final(pack_abc(OP_LOADNIL, reg_a(ins), reg_a(ins), 0)));
                false
            }
        },
    }
}

fn compare_native(form: CmpForm) -> (u8, u32) {
    let a_field: u32 = u32::from(!form.jump_when_true);
    let op: u8 = match form.op {
        CmpOp::Eq | CmpOp::Ne => OP_EQ,
        CmpOp::Lt | CmpOp::Gt => OP_LT,
        CmpOp::Le | CmpOp::Ge => OP_LE,
    };
    let a: u32 = match form.op {
        CmpOp::Ne => a_field ^ 1,
        _ => a_field,
    };
    (op, a)
}

fn compare_operands(form: CmpForm, ins: &IbInstr) -> (u32, u32) {
    let left: u32 = cmp_left(ins);
    let right: u32 = cmp_right(ins);
    match form.op {
        CmpOp::Gt | CmpOp::Ge => (right, left),
        _ => (left, right),
    }
}

#[must_use]
fn cmp_left(ins: &IbInstr) -> u32 {
    if mask_ra(ins) {
        RK_BIT | ((ins.a.max(1) - 1) as u32 & 0xFF)
    } else {
        (ins.a.clamp(0, 255)) as u32
    }
}

#[must_use]
fn cmp_right(ins: &IbInstr) -> u32 {
    rk_c(ins)
}

#[must_use]
fn mask_ra(ins: &IbInstr) -> bool {
    ins.mask & 1 != 0
}
#[must_use]
fn mask_rb(ins: &IbInstr) -> bool {
    ins.mask & 2 != 0
}
#[must_use]
fn mask_rc(ins: &IbInstr) -> bool {
    ins.mask & 4 != 0
}

#[must_use]
fn const_index_b(ins: &IbInstr) -> u32 {
    (ins.b.max(1) - 1) as u32
}
#[must_use]
fn const_index_c(ins: &IbInstr) -> u32 {
    (ins.c.max(1) - 1) as u32
}

#[must_use]
fn rk_b(ins: &IbInstr) -> u32 {
    if mask_rb(ins) {
        RK_BIT | (const_index_b(ins) & 0xFF)
    } else {
        (ins.b.clamp(0, 255)) as u32
    }
}
#[must_use]
fn rk_c(ins: &IbInstr) -> u32 {
    if mask_rc(ins) {
        RK_BIT | (const_index_c(ins) & 0xFF)
    } else {
        (ins.c.clamp(0, 255)) as u32
    }
}

#[must_use]
fn reg_a(ins: &IbInstr) -> u32 {
    (ins.a.clamp(0, 255)) as u32
}

fn lower_instruction(op: IbOpcode, ins: &IbInstr) -> Option<u32> {
    match op {
        IbOpcode::Move => Some(pack_abc(OP_MOVE, reg_a(ins), reg_b_reg(ins), 0)),
        IbOpcode::LoadK => Some(pack_abx(OP_LOADK, reg_a(ins), const_index_b(ins))),
        IbOpcode::LoadBool | IbOpcode::LoadBoolC => {
            let skip: u32 = u32::from(matches!(op, IbOpcode::LoadBoolC));
            Some(pack_abc(OP_LOADBOOL, reg_a(ins), (ins.b != 0) as u32, skip))
        }
        IbOpcode::LoadNil => Some(pack_abc(OP_LOADNIL, reg_a(ins), reg_b_reg(ins), 0)),
        IbOpcode::GetGlobal => Some(pack_abx(OP_GETGLOBAL, reg_a(ins), const_index_b(ins))),
        IbOpcode::SetGlobal => Some(pack_abx(OP_SETGLOBAL, reg_a(ins), const_index_b(ins))),
        IbOpcode::GetTable => Some(pack_abc(OP_GETTABLE, reg_a(ins), reg_b_reg(ins), rk_c(ins))),
        IbOpcode::SetTable => Some(pack_abc(OP_SETTABLE, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::NewTable => Some(pack_abc(OP_NEWTABLE, reg_a(ins), 0, 0)),
        IbOpcode::Self_ => Some(pack_abc(OP_SELF, reg_a(ins), reg_b_reg(ins), rk_c(ins))),
        IbOpcode::Add => Some(pack_abc(OP_ADD, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Sub => Some(pack_abc(OP_SUB, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Mul => Some(pack_abc(OP_MUL, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Div => Some(pack_abc(OP_DIV, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Mod => Some(pack_abc(OP_MOD, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Pow => Some(pack_abc(OP_POW, reg_a(ins), rk_b(ins), rk_c(ins))),
        IbOpcode::Unm => Some(pack_abc(OP_UNM, reg_a(ins), reg_b_reg(ins), 0)),
        IbOpcode::Not => Some(pack_abc(OP_NOT, reg_a(ins), reg_b_reg(ins), 0)),
        IbOpcode::Len => Some(pack_abc(OP_LEN, reg_a(ins), reg_b_reg(ins), 0)),
        IbOpcode::Concat => Some(pack_abc(
            OP_CONCAT,
            reg_a(ins),
            reg_b_reg(ins),
            reg_c_reg(ins),
        )),
        IbOpcode::Call(form) => Some(pack_abc(
            OP_CALL,
            reg_a(ins),
            call_b(ins, form),
            call_c(ins, form),
        )),
        IbOpcode::TailCall => Some(pack_abc(
            OP_CALL,
            reg_a(ins),
            reg_b_reg(ins),
            reg_c_reg(ins),
        )),
        IbOpcode::Return(form) => Some(pack_abc(OP_RETURN, reg_a(ins), return_b(ins, form), 0)),
        IbOpcode::SetList => Some(pack_abc(OP_SETLIST, reg_a(ins), setlist_b(ins), 1)),
        IbOpcode::Closure | IbOpcode::ClosureNu => Some(pack_abx(
            OP_CLOSURE,
            reg_a(ins),
            (ins.b.clamp(0, 0x3FFFF)) as u32,
        )),
        _ => None,
    }
}

#[must_use]
fn reg_b_reg(ins: &IbInstr) -> u32 {
    (ins.b.clamp(0, 511)) as u32
}
#[must_use]
fn reg_c_reg(ins: &IbInstr) -> u32 {
    (ins.c.clamp(0, 511)) as u32
}

#[must_use]
fn call_b(ins: &IbInstr, form: CallForm) -> u32 {
    match form.b {
        ArgForm::Fixed => (ins.b - (ins.a - 1)).clamp(0, 511) as u32,
        ArgForm::Two => 2,
        ArgForm::None => 1,
        ArgForm::Top => 0,
    }
}
#[must_use]
fn call_c(ins: &IbInstr, form: CallForm) -> u32 {
    match form.c {
        RetCount::Fixed => (ins.c - (ins.a - 2)).clamp(0, 511) as u32,
        RetCount::None => 0,
        RetCount::Top => 0,
        RetCount::One => 1,
        RetCount::Single => 2,
    }
}
#[must_use]
fn return_b(ins: &IbInstr, form: RetForm) -> u32 {
    match form {
        RetForm::Fixed => (ins.b + 2).clamp(0, 511) as u32,
        RetForm::Two => 2,
        RetForm::Three => 3,
        RetForm::None => 1,
        RetForm::Top => 0,
    }
}
#[must_use]
fn setlist_b(ins: &IbInstr) -> u32 {
    (ins.b - ins.a).clamp(0, 511) as u32
}

#[must_use]
fn pack_abc(op: u8, a: u32, b: u32, c: u32) -> u32 {
    (u32::from(op) & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)
}

#[must_use]
fn pack_abx(op: u8, a: u32, bx: u32) -> u32 {
    (u32::from(op) & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)
}

#[must_use]
fn pack_asbx(op: u8, a: u32, sbx: i64) -> u32 {
    let biased: u32 = ((sbx + SBX_BIAS).clamp(0, 0x3FFFF)) as u32;
    (u32::from(op) & 0x3F) | ((a & 0xFF) << 6) | ((biased & 0x3FFFF) << 14)
}

pub fn lift_to_source(program: &RecoveredProgram) -> Result<String> {
    if program.proto.code.is_empty() && program.stats.total_instructions == 0 {
        return Err(Error::DecompileUnsupported(
            "no instructions recovered from ironbrew2 vm",
        ));
    }
    let lifted: LiftedProto = lift_proto_dialect(&program.proto, LuaDialect::Lua51, 0);
    Ok(lifted.source)
}

#[must_use]
pub fn recovered_strings(program: &RecoveredProgram) -> Vec<String> {
    collect_strings(&program.proto)
}

fn collect_strings(proto: &LuaProto) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in &proto.constants {
        if let LuaConstant::Str(s) = k {
            out.push(s.clone());
        }
    }
    for p in &proto.protos {
        out.extend(collect_strings(p));
    }
    out
}
