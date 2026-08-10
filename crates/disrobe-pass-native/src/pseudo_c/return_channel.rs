use crate::error::{Error, Result};

use super::{
    BinOp, Block, Cond, ExtSource, Flags, FnReturn, FpOperand, FpWidth, LoopCond, Node, PackedOp,
    Reg, Source, Stmt, VecStmt, Width, Xmm, fp_stmt_result_xmm, rax_write_width, stmt_value_reads,
};

const RESULT_GPR: Reg = Reg::Rax;
const RESULT_XMM: Xmm = Xmm::Xmm0;

fn reject(message: &str) -> Error {
    Error::LlvmIr(format!("return channel reject: {message}"))
}

pub(super) fn flags_read_fp_compare(flags: &Flags) -> bool {
    match flags {
        Flags::FpCmp { .. } => true,
        Flags::CondCmp { prior, taken, .. } => {
            flags_read_fp_compare(prior) || flags_read_fp_compare(taken)
        }
        Flags::Cmp { .. }
        | Flags::Add { .. }
        | Flags::CmpMem { .. }
        | Flags::Test { .. }
        | Flags::TestImm { .. }
        | Flags::Sign { .. }
        | Flags::Snapshot { .. } => false,
    }
}

pub(super) fn stmt_is_scalar_fp(stmt: &Stmt) -> bool {
    if matches!(
        stmt,
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
            | Stmt::XmmToGpr { .. }
    ) {
        return true;
    }
    matches!(
        stmt,
        Stmt::Cond { flags, .. } | Stmt::SetCc { flags, .. } | Stmt::FlagSnapshot { flags, .. }
        if flags_read_fp_compare(flags)
    )
}

pub(super) fn block_has_scalar_fp(body: &[Node]) -> bool {
    body.iter().any(|node: &Node| match node {
        Node::Stmt(stmt) => stmt_is_scalar_fp(stmt),
        Node::If {
            cond,
            then_body,
            else_body,
        } => {
            cond_reads_fp_compare(cond)
                || block_has_scalar_fp(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|body: &Block| block_has_scalar_fp(body))
        }
        Node::While { body, cond } => {
            cond.as_ref().is_some_and(loop_cond_reads_fp_compare) || block_has_scalar_fp(body)
        }
        Node::DoWhile { body, cond } => {
            loop_cond_reads_fp_compare(cond) || block_has_scalar_fp(body)
        }
        Node::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|case: &super::SwitchCase| block_has_scalar_fp(&case.body))
                || block_has_scalar_fp(default)
        }
        Node::CondSnapshot { flags, .. } => flags_read_fp_compare(flags),
        Node::Return
        | Node::Break
        | Node::Continue
        | Node::BreakLoop(_)
        | Node::ContinueLoop(_)
        | Node::ResumeAt(_)
        | Node::OuterResume(_)
        | Node::Label(_)
        | Node::Goto(_) => false,
    })
}

fn cond_reads_fp_compare(cond: &Cond) -> bool {
    let mut found: bool = false;
    cond.visit_leaves(&mut |_: super::CondKind, flags: &Flags| {
        found = found || flags_read_fp_compare(flags);
    });
    found
}

fn loop_cond_reads_fp_compare(cond: &LoopCond) -> bool {
    match cond {
        LoopCond::Direct { flags, .. } => flags_read_fp_compare(flags),
        LoopCond::Snapshot { .. } => false,
    }
}

fn fp_operand_xmm(operand: &FpOperand, acc: &mut Vec<Xmm>) {
    if let FpOperand::Xmm(register) = operand {
        acc.push(*register);
    }
}

fn stmt_xmm_data_reads(stmt: &Stmt, acc: &mut Vec<Xmm>) {
    match stmt {
        Stmt::FpBin { lhs, rhs, .. } | Stmt::FpMinMax { lhs, rhs, .. } => {
            fp_operand_xmm(lhs, acc);
            fp_operand_xmm(rhs, acc);
        }
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            for operand in [mul_lhs, mul_rhs, addend] {
                fp_operand_xmm(operand, acc);
            }
        }
        Stmt::FpCsel {
            if_true, if_false, ..
        } => {
            fp_operand_xmm(if_true, acc);
            fp_operand_xmm(if_false, acc);
        }
        Stmt::FpMov { src, .. }
        | Stmt::FpSqrt { src, .. }
        | Stmt::FpUnary { src, .. }
        | Stmt::FpRound { src, .. } => fp_operand_xmm(src, acc),
        Stmt::FpStore { src, .. }
        | Stmt::FpToInt { src, .. }
        | Stmt::XmmToGpr { src, .. }
        | Stmt::FpConvert { src, .. }
        | Stmt::PackedToGpr { src, .. } => acc.push(*src),
        Stmt::Packed { dest, op } => match op {
            PackedOp::MovReg(src) | PackedOp::ShufD { src, .. } => acc.push(*src),
            PackedOp::AddQ(src)
            | PackedOp::And(src)
            | PackedOp::AndN(src)
            | PackedOp::CmpEqD(src)
            | PackedOp::UnpackLowQ(src) => {
                acc.push(*dest);
                acc.push(*src);
            }
            PackedOp::ShlQ(_) | PackedOp::ShlDq(_) | PackedOp::ShrDq8 => acc.push(*dest),
            PackedOp::Const { .. } | PackedOp::Zero | PackedOp::FromGpr { .. } => {}
        },
        Stmt::Assign { .. }
        | Stmt::BinAssign { .. }
        | Stmt::UnAssign { .. }
        | Stmt::Cond { .. }
        | Stmt::SetCc { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Store { .. }
        | Stmt::MemRmw { .. }
        | Stmt::Extend { .. }
        | Stmt::MulImm { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::IntToFp { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Call { .. }
        | Stmt::Vector(_) => {}
    }
}

fn stmt_gpr_data_reads(stmt: &Stmt, acc: &mut Vec<Reg>) {
    stmt_value_reads(stmt, acc);
    let Some(flags): Option<&Flags> = stmt_flags(stmt) else {
        return;
    };
    for register in super::flag_operand_regs(flags) {
        if let Some(position) = acc
            .iter()
            .position(|candidate: &Reg| *candidate == register)
        {
            acc.remove(position);
        }
    }
}

const fn stmt_flags(stmt: &Stmt) -> Option<&Flags> {
    match stmt {
        Stmt::Cond { flags, .. }
        | Stmt::SetCc { flags, .. }
        | Stmt::FpCsel { flags, .. }
        | Stmt::FlagSnapshot { flags, .. } => Some(flags),
        _ => None,
    }
}

fn result_gpr_def_width(stmt: &Stmt) -> Option<Width> {
    match stmt {
        Stmt::Cond { dest, .. } => (dest.reg == RESULT_GPR).then_some(dest.width),
        Stmt::Vector(VecStmt::ExtractToGpr { dest, .. }) => {
            (dest.reg == RESULT_GPR).then_some(dest.width)
        }
        _ => rax_write_width(stmt),
    }
}

fn stmt_gpr_defs(stmt: &Stmt) -> Vec<Reg> {
    match stmt {
        Stmt::PackedToGpr { dest, .. } | Stmt::Vector(VecStmt::ExtractToGpr { dest, .. }) => {
            vec![dest.reg]
        }
        other => super::stmt_gpr_dests(other),
    }
}

const fn vector_dest_index(vec: &VecStmt) -> Option<u8> {
    match vec {
        VecStmt::Load { dest, .. }
        | VecStmt::Bin { dest, .. }
        | VecStmt::Dup { dest, .. }
        | VecStmt::LaneInsert { dest, .. }
        | VecStmt::Compare { dest, .. }
        | VecStmt::MoveImm { dest, .. }
        | VecStmt::WidenExtend { dest, .. }
        | VecStmt::WidenAdd { dest, .. } => Some(*dest),
        VecStmt::Reduce { reg, .. } => Some(*reg),
        VecStmt::Store { .. } | VecStmt::ExtractToGpr { .. } => None,
    }
}

fn stmt_has_observable_effect(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Store { .. }
            | Stmt::MemRmw { .. }
            | Stmt::FpStore { .. }
            | Stmt::BlockMove { .. }
            | Stmt::BlockFill { .. }
            | Stmt::Call { .. }
            | Stmt::Vector(VecStmt::Store { .. })
    )
}

const fn reg_mask(register: Reg) -> u128 {
    let index: u32 = register as u32;
    if index < u128::BITS {
        1u128 << index
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatestResult {
    Int,
    Fp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReturnPath {
    int: Option<Width>,
    int_consumed: bool,
    fp: Option<FpWidth>,
    fp_consumed: bool,
    latest: Option<LatestResult>,
    observable: bool,
    fp_compare_snapshot: Option<u32>,
    compare_derived: u128,
}

impl ReturnPath {
    const fn entry() -> Self {
        Self {
            int: None,
            int_consumed: false,
            fp: None,
            fp_consumed: false,
            latest: None,
            observable: false,
            fp_compare_snapshot: None,
            compare_derived: 0,
        }
    }

    const fn consume_int(&mut self) {
        if self.int.is_some() {
            self.int_consumed = true;
        }
    }

    const fn consume_fp(&mut self) {
        if self.fp.is_some() {
            self.fp_consumed = true;
        }
    }

    const fn clear_fp(&mut self) {
        self.fp = None;
        self.fp_consumed = false;
    }

    const fn is_compare_derived(&self, register: Reg) -> bool {
        self.compare_derived & reg_mask(register) != 0
    }

    const fn set_compare_derived(&mut self, register: Reg, derived: bool) {
        if derived {
            self.compare_derived |= reg_mask(register);
        } else {
            self.compare_derived &= !reg_mask(register);
        }
    }

    fn source_is_compare_derived(&self, source: &Source) -> bool {
        matches!(source, Source::Reg(reference) if self.is_compare_derived(reference.reg))
    }

    fn reads_fp_compare(&self, flags: &Flags) -> bool {
        flags_read_fp_compare(flags)
            || matches!(flags, Flags::Snapshot { var } if self.fp_compare_snapshot == Some(*var))
    }

    fn track_compare_derived(&mut self, stmt: &Stmt, from_fp_compare: bool) {
        match stmt {
            Stmt::SetCc { dest, .. } => self.set_compare_derived(dest.reg, from_fp_compare),
            Stmt::Cond { dest, src, .. } => {
                let carried: bool = from_fp_compare
                    || (self.is_compare_derived(dest.reg) && self.source_is_compare_derived(src));
                self.set_compare_derived(dest.reg, carried);
            }
            Stmt::Assign { dest, src } => {
                let carried: bool = self.source_is_compare_derived(src);
                self.set_compare_derived(dest.reg, carried);
            }
            Stmt::Extend { dest, src, .. } => {
                let carried: bool = match src {
                    ExtSource::Reg(reference) => self.is_compare_derived(reference.reg),
                    ExtSource::Mem(_) => false,
                };
                self.set_compare_derived(dest.reg, carried);
            }
            Stmt::BinAssign {
                dest,
                op: BinOp::Or | BinOp::And | BinOp::Xor,
                src,
            } => {
                let carried: bool =
                    self.is_compare_derived(dest.reg) && self.source_is_compare_derived(src);
                self.set_compare_derived(dest.reg, carried);
            }
            other => {
                for register in stmt_gpr_defs(other) {
                    self.set_compare_derived(register, false);
                }
            }
        }
    }

    fn apply(&mut self, stmt: &Stmt) {
        let mut gprs: Vec<Reg> = Vec::new();
        stmt_gpr_data_reads(stmt, &mut gprs);
        if gprs.contains(&RESULT_GPR) {
            self.consume_int();
        }
        let mut registers: Vec<Xmm> = Vec::new();
        stmt_xmm_data_reads(stmt, &mut registers);
        if registers.contains(&RESULT_XMM) {
            self.consume_fp();
        }

        let from_fp_compare: bool =
            stmt_flags(stmt).is_some_and(|flags: &Flags| self.reads_fp_compare(flags));
        if let Stmt::FlagSnapshot { var, flags, .. } = stmt
            && flags_read_fp_compare(flags)
        {
            self.fp_compare_snapshot = Some(*var);
        }
        self.track_compare_derived(stmt, from_fp_compare);

        if matches!(stmt, Stmt::Call { .. }) {
            self.clear_fp();
        }
        if let Some((dest, width)) = fp_stmt_result_xmm(stmt)
            && dest == RESULT_XMM
        {
            self.fp = Some(width);
            self.fp_consumed = false;
            self.latest = Some(LatestResult::Fp);
        }
        if let Stmt::Packed { dest, .. } = stmt
            && *dest == RESULT_XMM
        {
            self.clear_fp();
        }
        if let Stmt::Vector(vec) = stmt
            && vector_dest_index(vec) == Some(RESULT_XMM.index())
        {
            self.clear_fp();
        }
        if let Some(width) = result_gpr_def_width(stmt) {
            self.int = Some(width);
            self.int_consumed = false;
            self.latest = Some(LatestResult::Int);
            if self.is_compare_derived(RESULT_GPR) {
                self.clear_fp();
            }
        }
        if stmt_has_observable_effect(stmt) {
            self.observable = true;
        }
    }
}

#[derive(Debug, Default)]
struct ReturnFlow {
    next: Vec<ReturnPath>,
    breaks: Vec<ReturnPath>,
    continues: Vec<ReturnPath>,
    returns: Vec<ReturnPath>,
}

fn extend_unique_paths(target: &mut Vec<ReturnPath>, source: Vec<ReturnPath>) {
    for state in source {
        if !target.contains(&state) {
            target.push(state);
        }
    }
}

fn merge_flow(target: &mut ReturnFlow, source: ReturnFlow) {
    extend_unique_paths(&mut target.next, source.next);
    extend_unique_paths(&mut target.breaks, source.breaks);
    extend_unique_paths(&mut target.continues, source.continues);
    extend_unique_paths(&mut target.returns, source.returns);
}

const PATH_BUDGET: usize = 1 << 16;

fn scan_loop(
    body: &[Node],
    incoming: Vec<ReturnPath>,
    executes_once: bool,
    budget: &mut usize,
) -> Result<ReturnFlow> {
    let mut result: ReturnFlow = ReturnFlow::default();
    if !executes_once {
        extend_unique_paths(&mut result.next, incoming.clone());
    }
    let mut pending: Vec<ReturnPath> = incoming;
    let mut visited: Vec<ReturnPath> = Vec::new();
    while let Some(state) = pending.pop() {
        if visited.contains(&state) {
            continue;
        }
        visited.push(state);
        let iteration: ReturnFlow = scan_block(body, vec![state], budget)?;
        extend_unique_paths(&mut result.returns, iteration.returns);
        extend_unique_paths(&mut result.next, iteration.breaks);
        let mut post_condition: Vec<ReturnPath> = iteration.next;
        extend_unique_paths(&mut post_condition, iteration.continues);
        extend_unique_paths(&mut result.next, post_condition.clone());
        for next_state in post_condition {
            if !visited.contains(&next_state) && !pending.contains(&next_state) {
                pending.push(next_state);
            }
        }
    }
    Ok(result)
}

fn scan_block(body: &[Node], incoming: Vec<ReturnPath>, budget: &mut usize) -> Result<ReturnFlow> {
    let mut active: Vec<ReturnPath> = incoming;
    let mut result: ReturnFlow = ReturnFlow::default();
    for node in body {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| reject("return path exploration exceeded its budget"))?;
        match node {
            Node::Stmt(stmt) => {
                for state in &mut active {
                    state.apply(stmt);
                }
            }
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                let then_flow: ReturnFlow = scan_block(then_body, active.clone(), budget)?;
                let else_flow: ReturnFlow = match else_body {
                    Some(else_body) => scan_block(else_body, active.clone(), budget)?,
                    None => ReturnFlow {
                        next: active.clone(),
                        ..ReturnFlow::default()
                    },
                };
                let mut branch_flow: ReturnFlow = ReturnFlow::default();
                merge_flow(&mut branch_flow, then_flow);
                merge_flow(&mut branch_flow, else_flow);
                active = core::mem::take(&mut branch_flow.next);
                extend_unique_paths(&mut result.breaks, branch_flow.breaks);
                extend_unique_paths(&mut result.continues, branch_flow.continues);
                extend_unique_paths(&mut result.returns, branch_flow.returns);
            }
            Node::While { body, .. } => {
                let mut loop_flow: ReturnFlow = scan_loop(body, active, false, budget)?;
                active = core::mem::take(&mut loop_flow.next);
                extend_unique_paths(&mut result.returns, loop_flow.returns);
            }
            Node::DoWhile { body, .. } => {
                let mut loop_flow: ReturnFlow = scan_loop(body, active, true, budget)?;
                active = core::mem::take(&mut loop_flow.next);
                extend_unique_paths(&mut result.returns, loop_flow.returns);
            }
            Node::Switch {
                disc,
                cases,
                default,
            } => {
                if disc.reg == RESULT_GPR {
                    for state in &mut active {
                        state.consume_int();
                    }
                }
                let mut switch_flow: ReturnFlow = ReturnFlow::default();
                for case in cases {
                    let case_flow: ReturnFlow = scan_block(&case.body, active.clone(), budget)?;
                    merge_flow(&mut switch_flow, case_flow);
                }
                let default_flow: ReturnFlow = scan_block(default, active.clone(), budget)?;
                merge_flow(&mut switch_flow, default_flow);
                active = core::mem::take(&mut switch_flow.next);
                extend_unique_paths(&mut active, switch_flow.breaks);
                extend_unique_paths(&mut result.continues, switch_flow.continues);
                extend_unique_paths(&mut result.returns, switch_flow.returns);
            }
            Node::Return => {
                extend_unique_paths(&mut result.returns, core::mem::take(&mut active));
            }
            Node::Break | Node::BreakLoop(_) => {
                extend_unique_paths(&mut result.breaks, core::mem::take(&mut active));
            }
            Node::Continue | Node::ContinueLoop(_) | Node::ResumeAt(_) => {
                extend_unique_paths(&mut result.continues, core::mem::take(&mut active));
            }
            Node::OuterResume(_) => {
                return Err(reject(
                    "return typing does not accept an outer-body resume tree",
                ));
            }
            Node::CondSnapshot { var, flags, .. } => {
                if flags_read_fp_compare(flags) {
                    for state in &mut active {
                        state.fp_compare_snapshot = Some(*var);
                    }
                }
            }
            Node::Label(_) => {}
            Node::Goto(_) => {
                return Err(reject("return typing does not accept unstructured goto"));
            }
        }
    }
    result.next = active;
    Ok(result)
}

fn classify(path: ReturnPath) -> Result<FnReturn> {
    let int: Option<Width> = path.int.filter(|_: &Width| !path.int_consumed);
    let fp: Option<FpWidth> = path.fp.filter(|_: &FpWidth| !path.fp_consumed);
    match (int, fp) {
        (Some(int_width), Some(fp_width)) => match path.latest {
            Some(LatestResult::Int) => Ok(FnReturn::Int(int_width)),
            Some(LatestResult::Fp) => Ok(FnReturn::Fp(fp_width)),
            None => Err(reject(
                "the integer and floating-point result registers both hold an unconsumed definition at a return and neither is the later one",
            )),
        },
        (Some(width), None) => Ok(FnReturn::Int(width)),
        (None, Some(width)) => Ok(FnReturn::Fp(width)),
        (None, None) if path.observable => Ok(FnReturn::Void),
        (None, None) => Err(reject(
            "no result-register definition reaches this return and the path has no observable effect",
        )),
    }
}

pub(super) fn infer_scalar_return(body: &[Node]) -> Result<FnReturn> {
    let mut budget: usize = PATH_BUDGET;
    let mut flow: ReturnFlow = scan_block(body, vec![ReturnPath::entry()], &mut budget)?;
    if !flow.breaks.is_empty() || !flow.continues.is_empty() {
        return Err(reject("control flow does not terminate at every path"));
    }
    extend_unique_paths(&mut flow.returns, core::mem::take(&mut flow.next));
    let mut unified: Option<FnReturn> = None;
    for path in flow.returns {
        let candidate: FnReturn = classify(path)?;
        match unified {
            Some(existing) if existing != candidate => {
                return Err(reject(
                    "scalar return class or width differs across return paths",
                ));
            }
            Some(_) => {}
            None => unified = Some(candidate),
        }
    }
    unified.ok_or_else(|| reject("function has no reachable return"))
}
