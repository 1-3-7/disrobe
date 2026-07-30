use std::collections::BTreeMap;

use crate::disasm::{Instruction, Operand};

use super::expr::{self, BinSegment, Expr, Stmt};
use super::{
    BinMatchState, BinShared, BinaryClause, Block, Env, Flags, Lifter, Reg, as_reg, binmatch,
    close_pattern, has_unrecovered_marker, inline_segment, is_ensure_exactly_zero, label_of,
    literal_u32, rebind_prefix, resugar, simplify,
};

fn push_fail(fails: &mut Vec<u32>, ins: &Instruction) {
    let fail: u32 = ins.operands.first().map_or(0, label_of);
    if fail != 0 && !fails.contains(&fail) {
        fails.push(fail);
    }
}

fn push_match_segment(
    shared: &mut BinShared,
    cursor: &mut usize,
    local_max: &mut usize,
    env: &mut Env,
    flags: &mut Flags,
    seg: binmatch::MatchSegment,
) -> bool {
    let var: String = Lifter::segment_var(shared, *cursor, flags);
    let dst: Option<Reg> = seg.dst.as_ref().and_then(as_reg);
    let mut segment: BinSegment = seg.segment;
    let mut degraded: bool = false;
    if let Some(src) = seg.size_src.as_ref() {
        match as_reg(src).and_then(|reg: Reg| env.bound(reg)) {
            Some(size) => segment.size = Some(Box::new(size)),
            None => degraded = true,
        }
    }
    if seg.binds {
        segment.value = Box::new(Expr::Var(var.clone()));
    }
    if *cursor == shared.all_segments.len() {
        shared.all_segments.push(segment);
        shared.seg_vars.push(var.clone());
        shared.seg_dsts.push(seg.binds.then_some(dst).flatten());
    }
    if seg.binds
        && let Some(dst) = dst
    {
        env.set(dst, Expr::Var(var));
    }
    *cursor += 1;
    *local_max = (*local_max).max(*cursor);
    degraded
}

impl Lifter<'_> {
    pub(super) fn reconstruct_binary_clauses(
        &self,
        entry: u32,
    ) -> Option<(Vec<expr::FnClause>, bool)> {
        let block: Block = self.blocks.get(&entry).copied()?;
        if self.arity != 1
            || !(block.start..block.end)
                .any(|i: usize| self.instrs[i].name.starts_with("bs_start_match"))
        {
            return None;
        }
        let mut flags: Flags = Flags::default();
        let mut ok: bool = true;
        let mut shared: BinShared = BinShared {
            all_segments: Vec::new(),
            pos_len: BTreeMap::new(),
            seg_vars: Vec::new(),
            seg_dsts: Vec::new(),
        };
        let mut clauses: Vec<expr::FnClause> = Vec::new();
        let mut queue: Vec<u32> = vec![entry];
        let mut visited: Vec<u32> = Vec::new();
        while let Some(label) = (!queue.is_empty()).then(|| queue.remove(0)) {
            if visited.contains(&label)
                || self.is_pure_failure(label)
                || self.is_gc_retry(label, &visited)
            {
                continue;
            }
            visited.push(label);
            let Some(walked): Option<BinaryClause> =
                self.walk_binary_clause(label, &mut flags, &mut shared)
            else {
                continue;
            };
            ok = ok && !walked.degraded;
            let pattern: Expr = if walked.wildcard {
                Expr::Var("_".to_owned())
            } else {
                Expr::BinaryConstruct(walked.segments)
            };
            clauses.push(expr::FnClause {
                patterns: vec![pattern],
                guard: None,
                body: resugar::resugar_body(simplify::simplify_body(walked.body)),
            });
            for fail in walked.fails {
                if !visited.contains(&fail) && !queue.contains(&fail) {
                    queue.push(fail);
                }
            }
        }
        if clauses.is_empty() {
            return None;
        }
        let unresolved: bool = clauses
            .iter()
            .any(|c: &expr::FnClause| c.body.iter().any(has_unrecovered_marker));
        Some((clauses, ok && !unresolved))
    }

    fn walk_binary_clause(
        &self,
        label: u32,
        flags: &mut Flags,
        shared: &mut BinShared,
    ) -> Option<BinaryClause> {
        let mut env: Env = Env::default();
        env.set(Reg::X(0), Reg::X(0).var());
        let mut fails: Vec<u32> = Vec::new();
        let mut idx: usize = self.blocks.get(&label)?.start;
        let limit: usize = self.instrs.len();
        let mut exact: bool = false;
        let mut ctx: Option<Reg> = None;
        let mut cursor: usize = shared.all_segments.len();
        let mut local_max: usize = cursor;
        let mut matched: bool = false;
        let mut seg_degraded: bool = false;
        loop {
            if idx >= limit {
                return Some(BinaryClause {
                    segments: close_pattern(
                        &shared.all_segments[..local_max],
                        exact,
                        ctx,
                        &mut env,
                        flags,
                    ),
                    body: Vec::new(),
                    fails,
                    degraded: true,
                    wildcard: !matched,
                });
            }
            let ins: &Instruction = &self.instrs[idx];
            match ins.name {
                name if name.starts_with("bs_start_match") => {
                    matched = true;
                    ctx = ins.operands.last().and_then(as_reg);
                }
                "bs_get_position" => {
                    if let Some(reg) = as_reg(&ins.operands[1]) {
                        shared.pos_len.insert(reg, cursor);
                    }
                }
                "bs_set_position" => {
                    if let Some(reg) = as_reg(&ins.operands[1])
                        && let Some(&len) = shared.pos_len.get(&reg)
                    {
                        cursor = len;
                        local_max = len;
                        rebind_prefix(shared, len, &mut env);
                    }
                }
                "bs_match" => {
                    matched = true;
                    push_fail(&mut fails, ins);
                    if let Some(Operand::List(items)) = ins.operands.get(2) {
                        let decoded: binmatch::MatchCommands =
                            binmatch::decode_match_commands(items, self.chunks);
                        exact |= decoded.exact;
                        seg_degraded |= decoded.degraded;
                        for seg in decoded.segments {
                            seg_degraded |= push_match_segment(
                                shared,
                                &mut cursor,
                                &mut local_max,
                                &mut env,
                                flags,
                                seg,
                            );
                        }
                    }
                }
                "bs_get_integer2" | "bs_get_float2" | "bs_get_binary2" | "bs_get_utf8"
                | "bs_get_utf16" | "bs_get_utf32" => {
                    matched = true;
                    push_fail(&mut fails, ins);
                    match binmatch::decode_get_segment(ins.name, &ins.operands, self.chunks) {
                        Some(seg) => {
                            seg_degraded |= push_match_segment(
                                shared,
                                &mut cursor,
                                &mut local_max,
                                &mut env,
                                flags,
                                seg,
                            );
                        }
                        None => seg_degraded = true,
                    }
                }
                "bs_skip_bits2" | "bs_skip_utf8" | "bs_skip_utf16" | "bs_skip_utf32" => {
                    matched = true;
                    push_fail(&mut fails, ins);
                    match binmatch::decode_skip_segment(ins.name, &ins.operands, self.chunks) {
                        Some(seg) => {
                            seg_degraded |= push_match_segment(
                                shared,
                                &mut cursor,
                                &mut local_max,
                                &mut env,
                                flags,
                                seg,
                            );
                        }
                        None => seg_degraded = true,
                    }
                }
                "bs_match_string" => {
                    matched = true;
                    push_fail(&mut fails, ins);
                    let (segs, lossy): (Vec<binmatch::MatchSegment>, bool) =
                        self.match_string_segments(&ins.operands);
                    seg_degraded |= lossy;
                    for seg in segs {
                        seg_degraded |= push_match_segment(
                            shared,
                            &mut cursor,
                            &mut local_max,
                            &mut env,
                            flags,
                            seg,
                        );
                    }
                }
                "bs_test_tail2" => {
                    let bits: u32 = ins.operands.get(2).map_or(0, literal_u32);
                    if bits > 0 {
                        seg_degraded |= push_match_segment(
                            shared,
                            &mut cursor,
                            &mut local_max,
                            &mut env,
                            flags,
                            binmatch::skip_segment(bits, 1),
                        );
                    }
                    exact = true;
                }
                "bs_test_unit" => {}
                "bs_get_tail" => {
                    matched = true;
                    seg_degraded |= push_match_segment(
                        shared,
                        &mut cursor,
                        &mut local_max,
                        &mut env,
                        flags,
                        binmatch::tail_segment(8, ins.operands.get(1).cloned()),
                    );
                    exact = true;
                }
                "jump" => {
                    if let Some(Operand::Label(l)) = ins.operands.first() {
                        idx = self.blocks.get(l).map_or(limit, |b: &Block| b.start);
                        continue;
                    }
                }
                "line" | "label" | "test_heap" | "allocate" | "allocate_heap"
                | "allocate_heap_zero" | "deallocate" | "trim" | "init_yregs"
                | "bs_init_writable" => {}
                "return" => {
                    return Some(BinaryClause {
                        segments: close_pattern(
                            &shared.all_segments[..local_max],
                            exact,
                            ctx,
                            &mut env,
                            flags,
                        ),
                        body: vec![Stmt::Return(env.get(Reg::X(0)))],
                        fails,
                        degraded: seg_degraded,
                        wildcard: !matched,
                    });
                }
                _ => {
                    let segments: Vec<BinSegment> = close_pattern(
                        &shared.all_segments[..local_max],
                        exact,
                        ctx,
                        &mut env,
                        flags,
                    );
                    let mut sub_flags: Flags = Flags {
                        pat_counter: flags.pat_counter,
                        ..Flags::default()
                    };
                    let region: Block = Block {
                        start: idx,
                        end: limit,
                    };
                    let mut body_env: Env = env.clone();
                    let body: Vec<Stmt> = self.walk_synth(region, &mut body_env, &mut sub_flags, 1);
                    flags.pat_counter = sub_flags.pat_counter;
                    return Some(BinaryClause {
                        segments,
                        body,
                        fails,
                        degraded: seg_degraded || sub_flags.degraded,
                        wildcard: !matched,
                    });
                }
            }
            idx += 1;
        }
    }

    fn segment_var(shared: &BinShared, cursor: usize, flags: &mut Flags) -> String {
        shared
            .seg_vars
            .get(cursor)
            .cloned()
            .unwrap_or_else(|| flags.fresh_pat())
    }

    fn match_string_segments(&self, ops: &[Operand]) -> (Vec<binmatch::MatchSegment>, bool) {
        let bits: u32 = ops.get(2).map_or(0, literal_u32);
        if bits == 0 {
            return (Vec::new(), false);
        }
        if !bits.is_multiple_of(8) {
            return (vec![binmatch::skip_segment(bits, 1)], true);
        }
        let offset: usize = ops.get(3).map_or(0, literal_u32) as usize;
        let len: usize = (bits / 8) as usize;
        let bytes: Vec<BinSegment> = self.strt_string_segments(offset, len);
        if bytes.len() != len {
            return (vec![binmatch::skip_segment(bits, 1)], true);
        }
        (
            bytes.into_iter().map(binmatch::fixed_segment).collect(),
            false,
        )
    }

    fn is_gc_retry(&self, label: u32, visited: &[u32]) -> bool {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return false;
        };
        for i in block.start..block.end {
            match self.instrs[i].name {
                "bs_get_tail" | "bs_get_position" | "bs_set_position" | "line" | "label"
                | "move" | "test_heap" | "allocate" | "deallocate" => {}
                "jump" => {
                    let Some(Operand::Label(l)): Option<&Operand> = self.instrs[i].operands.first()
                    else {
                        return true;
                    };
                    return visited.contains(l)
                        || self.block_opens_match(*l)
                        || !self.blocks.contains_key(l);
                }
                _ => return false,
            }
        }
        false
    }

    fn block_opens_match(&self, label: u32) -> bool {
        self.blocks.get(&label).copied().is_some_and(|b: Block| {
            (b.start..b.end).any(|i: usize| self.instrs[i].name.starts_with("bs_start_match"))
        })
    }

    pub(super) fn is_pure_failure(&self, label: u32) -> bool {
        let Some(block): Option<Block> = self.blocks.get(&label).copied() else {
            return false;
        };
        (block.start..block.end).all(|i: usize| {
            matches!(
                self.instrs[i].name,
                "line" | "label" | "func_clause" | "badmatch" | "case_end" | "if_end"
            )
        }) && (block.start..block.end)
            .any(|i: usize| matches!(self.instrs[i].name, "func_clause" | "badmatch"))
    }

    pub(super) fn exec_bs_start_match(ins: &Instruction, env: &mut Env) {
        let (src, ctx): (Option<Reg>, Option<Reg>) = match ins.name {
            "bs_start_match4" => (as_reg(&ins.operands[2]), as_reg(&ins.operands[3])),
            _ => (
                as_reg(&ins.operands[1]),
                ins.operands.last().and_then(as_reg),
            ),
        };
        let (Some(src), Some(ctx)): (Option<Reg>, Option<Reg>) = (src, ctx) else {
            return;
        };
        env.bin_ctx.insert(
            ctx,
            BinMatchState {
                source: src,
                segments: Vec::new(),
            },
        );
    }

    pub(super) fn exec_bs_match(
        &self,
        ins: &Instruction,
        env: &mut Env,
        flags: &mut Flags,
    ) -> Option<Stmt> {
        let ctx: Reg = as_reg(&ins.operands[1])?;
        let Some(Operand::List(items)) = ins.operands.get(2) else {
            flags.degraded = true;
            return None;
        };
        if is_ensure_exactly_zero(items, self.chunks) {
            return None;
        }
        let subject: Expr = env
            .bin_ctx
            .get(&ctx)
            .map_or_else(|| ctx.var(), |s: &BinMatchState| env.get(s.source));
        let decoded: binmatch::MatchCommands = binmatch::decode_match_commands(items, self.chunks);
        flags.degraded = flags.degraded || decoded.degraded;
        let mut segments: Vec<BinSegment> = Vec::new();
        for seg in decoded.segments {
            segments.push(inline_segment(seg, env, flags));
        }
        if segments.is_empty() {
            return None;
        }
        let rest: String = flags.fresh_pat();
        segments.push(BinSegment {
            value: Box::new(Expr::Var(rest.clone())),
            size: None,
            unit: 8,
            kind: "binary".to_owned(),
            flags: Vec::new(),
        });
        env.set(ctx, Expr::Var(rest));
        Some(Stmt::Match {
            pattern: Expr::BinaryConstruct(segments),
            value: subject,
        })
    }

    pub(super) fn exec_bs_get_tail(ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let Some(ctx): Option<Reg> = as_reg(&ins.operands[0]) else {
            return;
        };
        let Some(dst): Option<Reg> = as_reg(&ins.operands[1]) else {
            return;
        };
        let var: String = flags.fresh_pat();
        env.set(dst, Expr::Var(var.clone()));
        if let Some(state) = env.bin_ctx.get_mut(&ctx) {
            state.segments.push(BinSegment {
                value: Box::new(Expr::Var(var)),
                size: None,
                unit: 8,
                kind: "binary".to_owned(),
                flags: Vec::new(),
            });
        }
    }

    pub(super) fn exec_bs_create_bin(&self, ins: &Instruction, env: &mut Env, flags: &mut Flags) {
        let dst: Option<&Operand> = ins.operands.get(4);
        let Some(Operand::List(items)) = ins.operands.get(5) else {
            flags.degraded = true;
            return;
        };
        let segments: Vec<BinSegment> = self.parse_bin_segments(items, env);
        if let Some(reg) = dst.and_then(as_reg) {
            env.set(reg, Expr::BinaryConstruct(segments));
        }
    }

    fn parse_bin_segments(&self, items: &[Operand], env: &Env) -> Vec<BinSegment> {
        let mut segments: Vec<BinSegment> = Vec::new();
        let mut i: usize = 0;
        while i + 5 < items.len() {
            let kind: &str = match &items[i] {
                Operand::Atom(a) => self.chunks.atoms.get(*a).unwrap_or("integer"),
                _ => "integer",
            };
            let unit: u32 = literal_u32(&items[i + 2]);
            let flag_names: Vec<String> =
                binmatch::decode_construct_flags(&items[i + 3], self.chunks);
            if kind == "string" {
                let offset: usize = literal_u32(&items[i + 4]) as usize;
                let len: usize = literal_u32(&items[i + 5]) as usize;
                segments.extend(self.strt_string_segments(offset, len));
                i += 6;
                continue;
            }
            let value: Expr = self.value(&items[i + 4], env);
            let size: Option<Box<Expr>> = match &items[i + 5] {
                Operand::Atom(a) if self.chunks.atoms.get(*a) == Some("all") => None,
                Operand::Atom(0) => None,
                other => Some(Box::new(self.value(other, env))),
            };
            if matches!(kind, "append" | "private_append") {
                segments.push(BinSegment {
                    value: Box::new(value),
                    size,
                    unit: 8,
                    kind: "binary".to_owned(),
                    flags: Vec::new(),
                });
                i += 6;
                continue;
            }
            let normalized: String = match kind {
                "binary" => "binary".to_owned(),
                "utf8" | "utf16" | "utf32" | "float" => kind.to_owned(),
                _ => "integer".to_owned(),
            };
            segments.push(BinSegment {
                value: Box::new(value),
                size,
                unit,
                kind: normalized,
                flags: flag_names,
            });
            i += 6;
        }
        segments
    }

    fn strt_string_segments(&self, offset: usize, len: usize) -> Vec<BinSegment> {
        let bytes: &[u8] = self
            .chunks
            .strings
            .as_ref()
            .and_then(|s: &crate::chunks::StringTable| s.slice(offset, len))
            .unwrap_or(&[]);
        bytes
            .iter()
            .map(|b: &u8| BinSegment {
                value: Box::new(Expr::Int(i64::from(*b))),
                size: Some(Box::new(Expr::Int(8))),
                unit: 1,
                kind: "integer".to_owned(),
                flags: Vec::new(),
            })
            .collect()
    }
}
