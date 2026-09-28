use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bytecode::{ExceptionEntry, Instruction, Operands};

const OP_JSR: u8 = 0xA8;
const OP_JSR_W: u8 = 0xC9;
const OP_RET: u8 = 0xA9;
const OP_GOTO: u8 = 0xA7;
const OP_ASTORE: u8 = 0x3A;
const OP_ASTORE_0: u8 = 0x4B;
const OP_ASTORE_3: u8 = 0x4E;
const OP_POP: u8 = 0x57;
const MAX_INLINE_DEPTH: usize = 64;
const MAX_OUTPUT: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsrInlineReport {
    pub jsr_sites: usize,
    pub subroutines: usize,
    pub inlined_instructions: usize,
    pub bailed: bool,
    pub note: String,
}

#[must_use]
pub fn contains_jsr(insns: &[Instruction]) -> bool {
    insns
        .iter()
        .any(|i: &Instruction| i.opcode == OP_JSR || i.opcode == OP_JSR_W || i.opcode == OP_RET)
}

struct Emitted {
    opcode: u8,
    mnemonic: &'static str,
    wide: bool,
    operands: Operands,
    old_pc: u32,
    target_old_pc: Option<u32>,
    switch_targets_old_pc: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsrInlined {
    pub insns: Vec<Instruction>,
    pub exception_table: Vec<ExceptionEntry>,
    pub report: JsrInlineReport,
}

fn unmodified(
    insns: &[Instruction],
    exception_table: &[ExceptionEntry],
    report: JsrInlineReport,
) -> JsrInlined {
    JsrInlined {
        insns: insns.to_vec(),
        exception_table: exception_table.to_vec(),
        report,
    }
}

#[must_use]
pub fn inline_jsr_subroutines(
    insns: &[Instruction],
    exception_table: &[ExceptionEntry],
) -> JsrInlined {
    let jsr_sites: usize = insns
        .iter()
        .filter(|i: &&Instruction| i.opcode == OP_JSR || i.opcode == OP_JSR_W)
        .count();
    if jsr_sites == 0 {
        return unmodified(
            insns,
            exception_table,
            JsrInlineReport {
                jsr_sites: 0,
                subroutines: 0,
                inlined_instructions: insns.len(),
                bailed: false,
                note: "no jsr subroutines present".to_owned(),
            },
        );
    }

    let pc_index: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, ins): (usize, &Instruction)| (ins.pc, i))
        .collect();

    let mut subroutine_targets: BTreeSet<u32> = BTreeSet::new();
    for ins in insns {
        if (ins.opcode == OP_JSR || ins.opcode == OP_JSR_W)
            && let Operands::Branch(off) = ins.operands
        {
            subroutine_targets.insert((i64::from(ins.pc) + i64::from(off)) as u32);
        }
    }

    let mut emitted: Vec<Emitted> = Vec::with_capacity(insns.len());
    let mut label_map: BTreeMap<u32, usize> = BTreeMap::new();
    let mut bailed: bool = false;
    let mut i: usize = 0;
    while i < insns.len() {
        let ins: &Instruction = &insns[i];
        if (ins.opcode == OP_JSR || ins.opcode == OP_JSR_W)
            && let Operands::Branch(off) = ins.operands
        {
            let target: u32 = (i64::from(ins.pc) + i64::from(off)) as u32;
            let return_pc: u32 = next_pc(insns, i);
            let body_start: usize = emitted.len();
            if !inline_one(insns, &pc_index, target, return_pc, &mut emitted, 0) {
                bailed = true;
                break;
            }
            label_map.entry(ins.pc).or_insert(body_start);
            i += 1;
            continue;
        }
        if subroutine_targets.contains(&ins.pc) {
            i = skip_subroutine_body(insns, i);
            continue;
        }
        label_map.entry(ins.pc).or_insert(emitted.len());
        emitted.push(copy_insn(ins));
        i += 1;
        if emitted.len() > MAX_OUTPUT {
            bailed = true;
            break;
        }
    }

    if bailed {
        return unmodified(
            insns,
            exception_table,
            JsrInlineReport {
                jsr_sites,
                subroutines: subroutine_targets.len(),
                inlined_instructions: insns.len(),
                bailed: true,
                note: "jsr subroutine structure is irregular (recursive, shared, or oversized); left unmodified rather than mis-linearised".to_owned(),
            },
        );
    }

    let Some(out): Option<Vec<Instruction>> = renumber(&emitted, &label_map) else {
        return unmodified(
            insns,
            exception_table,
            JsrInlineReport {
                jsr_sites,
                subroutines: subroutine_targets.len(),
                inlined_instructions: insns.len(),
                bailed: true,
                note: "jsr inlining produced a branch target that could not be resolved in the linearised stream; left unmodified rather than mis-linearised".to_owned(),
            },
        );
    };
    let Some(remapped): Option<Vec<ExceptionEntry>> =
        remap_exception_table(&emitted, &label_map, exception_table)
    else {
        return unmodified(
            insns,
            exception_table,
            JsrInlineReport {
                jsr_sites,
                subroutines: subroutine_targets.len(),
                inlined_instructions: insns.len(),
                bailed: true,
                note: "an exception handler could not be placed in the linearised stream; left unmodified rather than bound to unrelated instructions".to_owned(),
            },
        );
    };

    let inlined_count: usize = out.len();
    JsrInlined {
        insns: out,
        exception_table: remapped,
        report: JsrInlineReport {
            jsr_sites,
            subroutines: subroutine_targets.len(),
            inlined_instructions: inlined_count,
            bailed: false,
            note: format!(
                "inlined {jsr_sites} jsr call-site(s) across {} subroutine(s) into a jsr-free linear stream",
                subroutine_targets.len()
            ),
        },
    }
}

fn remap_exception_table(
    emitted: &[Emitted],
    label_map: &BTreeMap<u32, usize>,
    exception_table: &[ExceptionEntry],
) -> Option<Vec<ExceptionEntry>> {
    let mut out: Vec<ExceptionEntry> = Vec::with_capacity(exception_table.len());
    for entry in exception_table {
        let protected = u32::from(entry.start_pc)..u32::from(entry.end_pc);
        let handler_pc: u16 = u16::try_from(*label_map.get(&u32::from(entry.handler_pc))?).ok()?;
        let mut run_start: Option<usize> = None;
        for (idx, e) in emitted.iter().enumerate() {
            match (protected.contains(&e.old_pc), run_start) {
                (true, None) => run_start = Some(idx),
                (false, Some(start)) => {
                    out.push(ExceptionEntry {
                        start_pc: u16::try_from(start).ok()?,
                        end_pc: u16::try_from(idx).ok()?,
                        handler_pc,
                        catch_type: entry.catch_type,
                    });
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(start) = run_start {
            out.push(ExceptionEntry {
                start_pc: u16::try_from(start).ok()?,
                end_pc: u16::try_from(emitted.len()).ok()?,
                handler_pc,
                catch_type: entry.catch_type,
            });
        }
    }
    Some(out)
}

fn copy_insn(ins: &Instruction) -> Emitted {
    let target_old_pc: Option<u32> = branch_target_old_pc(ins);
    let at = |off: i32| -> u32 { (i64::from(ins.pc) + i64::from(off)) as u32 };
    let switch_targets_old_pc: Vec<u32> = match &ins.operands {
        Operands::TableSwitch {
            default, offsets, ..
        } => std::iter::once(*default)
            .chain(offsets.iter().copied())
            .map(at)
            .collect(),
        Operands::LookupSwitch { default, pairs } => std::iter::once(*default)
            .chain(pairs.iter().map(|(_, off): &(i32, i32)| *off))
            .map(at)
            .collect(),
        _ => Vec::new(),
    };
    Emitted {
        opcode: ins.opcode,
        mnemonic: ins.mnemonic,
        wide: ins.wide,
        operands: ins.operands.clone(),
        old_pc: ins.pc,
        target_old_pc,
        switch_targets_old_pc,
    }
}

fn branch_target_old_pc(ins: &Instruction) -> Option<u32> {
    match ins.operands {
        Operands::Branch(off) => Some((i64::from(ins.pc) + i64::from(off)) as u32),
        _ => None,
    }
}

fn inline_one(
    insns: &[Instruction],
    pc_index: &BTreeMap<u32, usize>,
    target: u32,
    return_pc: u32,
    emitted: &mut Vec<Emitted>,
    depth: usize,
) -> bool {
    if depth > MAX_INLINE_DEPTH || emitted.len() > MAX_OUTPUT {
        return false;
    }
    let Some(&start): Option<&usize> = pc_index.get(&target) else {
        return false;
    };
    let mut j: usize = start;
    let mut skipped_store: bool = false;
    while j < insns.len() {
        let ins: &Instruction = &insns[j];
        if !skipped_store && is_return_address_consumer(ins.opcode) {
            skipped_store = true;
            j += 1;
            continue;
        }
        match ins.opcode {
            OP_RET => {
                if body_branches_past(&insns[start..=j], ins.pc) {
                    return false;
                }
                emitted.push(Emitted {
                    opcode: OP_GOTO,
                    mnemonic: "goto",
                    wide: false,
                    operands: Operands::Branch(0),
                    old_pc: ins.pc,
                    target_old_pc: Some(return_pc),
                    switch_targets_old_pc: Vec::new(),
                });
                return true;
            }
            OP_JSR | OP_JSR_W => {
                if let Operands::Branch(off) = ins.operands {
                    let inner_target: u32 = (i64::from(ins.pc) + i64::from(off)) as u32;
                    let inner_return: u32 = next_pc(insns, j);
                    if !inline_one(
                        insns,
                        pc_index,
                        inner_target,
                        inner_return,
                        emitted,
                        depth + 1,
                    ) {
                        return false;
                    }
                }
                j += 1;
            }
            _ => {
                emitted.push(copy_insn(ins));
                j += 1;
            }
        }
        if emitted.len() > MAX_OUTPUT {
            return false;
        }
    }
    false
}

fn body_branches_past(body: &[Instruction], ret_pc: u32) -> bool {
    body.iter().any(|ins: &Instruction| {
        branch_target_old_pc(ins).is_some_and(|target: u32| target > ret_pc)
    })
}

const fn is_return_address_consumer(opcode: u8) -> bool {
    opcode == OP_ASTORE || opcode == OP_POP || (opcode >= OP_ASTORE_0 && opcode <= OP_ASTORE_3)
}

fn skip_subroutine_body(insns: &[Instruction], start: usize) -> usize {
    let mut j: usize = start;
    while j < insns.len() {
        if insns[j].opcode == OP_RET {
            return j + 1;
        }
        j += 1;
    }
    insns.len()
}

fn renumber(emitted: &[Emitted], label_map: &BTreeMap<u32, usize>) -> Option<Vec<Instruction>> {
    let mut out: Vec<Instruction> = Vec::with_capacity(emitted.len());
    for (idx, e) in emitted.iter().enumerate() {
        let new_pc: u32 = u32::try_from(idx).ok()?;
        let relative = |old_target: u32| -> Option<i32> {
            let target_idx: usize = resolve_target_index(emitted, idx, old_target, label_map)?;
            let target_pc: i64 = i64::try_from(target_idx).ok()?;
            i32::try_from(target_pc - i64::from(new_pc)).ok()
        };
        let operands: Operands = match (&e.operands, e.target_old_pc) {
            (_, Some(old_target)) => Operands::Branch(relative(old_target)?),
            (Operands::TableSwitch { low, high, .. }, None) => {
                let mut targets = e.switch_targets_old_pc.iter().copied();
                let default: i32 = relative(targets.next()?)?;
                let offsets: Vec<i32> = targets.map(relative).collect::<Option<Vec<i32>>>()?;
                Operands::TableSwitch {
                    default,
                    low: *low,
                    high: *high,
                    offsets,
                }
            }
            (Operands::LookupSwitch { pairs, .. }, None) => {
                let mut targets = e.switch_targets_old_pc.iter().copied();
                let default: i32 = relative(targets.next()?)?;
                let offsets: Vec<i32> = targets.map(relative).collect::<Option<Vec<i32>>>()?;
                if offsets.len() != pairs.len() {
                    return None;
                }
                Operands::LookupSwitch {
                    default,
                    pairs: pairs
                        .iter()
                        .zip(offsets)
                        .map(|((key, _), off): (&(i32, i32), i32)| (*key, off))
                        .collect(),
                }
            }
            (operands, None) => operands.clone(),
        };
        out.push(Instruction {
            pc: new_pc,
            opcode: e.opcode,
            mnemonic: e.mnemonic,
            wide: e.wide,
            operands,
        });
    }
    Some(out)
}

fn resolve_target_index(
    emitted: &[Emitted],
    source_idx: usize,
    old_target: u32,
    label_map: &BTreeMap<u32, usize>,
) -> Option<usize> {
    let mut nearest_backward: Option<usize> = None;
    for idx in (0..source_idx).rev() {
        if emitted[idx].old_pc == old_target {
            nearest_backward = Some(idx);
            break;
        }
    }
    if let Some(idx) = nearest_backward {
        return Some(idx);
    }
    for (idx, e) in emitted.iter().enumerate().skip(source_idx) {
        if e.old_pc == old_target {
            return Some(idx);
        }
    }
    label_map.get(&old_target).copied()
}

fn next_pc(insns: &[Instruction], idx: usize) -> u32 {
    insns
        .get(idx + 1)
        .map_or_else(|| insns[idx].pc, |n: &Instruction| n.pc)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ins(pc: u32, opcode: u8, mnemonic: &'static str, operands: Operands) -> Instruction {
        Instruction {
            pc,
            opcode,
            mnemonic,
            wide: false,
            operands,
        }
    }

    #[test]
    fn no_jsr_passes_through() {
        let insns: Vec<Instruction> = vec![
            ins(0, 0x04, "iconst_1", Operands::None),
            ins(1, 0xAC, "ireturn", Operands::None),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert_eq!(out.len(), 2);
        assert_eq!(report.jsr_sites, 0);
        assert!(!report.bailed);
    }

    #[test]
    fn a_subroutine_with_a_second_ret_is_not_cut_at_the_first() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(5)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, 0x00, "nop", Operands::None),
            ins(5, OP_ASTORE, "astore", Operands::Local(1)),
            ins(7, 0x1A, "iload_0", Operands::None),
            ins(8, 0x99, "ifeq", Operands::Branch(6)),
            ins(11, OP_RET, "ret", Operands::Local(1)),
            ins(13, 0x04, "iconst_1", Operands::None),
            ins(14, 0x3B, "istore_0", Operands::None),
            ins(15, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(report.bailed, "{report:?}");
        assert_eq!(out, insns);
    }

    #[test]
    fn a_switch_keeps_its_targets_after_inlining() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(28)),
            ins(3, 0x1A, "iload_0", Operands::None),
            ins(
                4,
                0xAB,
                "lookupswitch",
                Operands::LookupSwitch {
                    default: 23,
                    pairs: vec![(1, 23)],
                },
            ),
            ins(27, 0xB1, "return", Operands::None),
            ins(28, OP_ASTORE, "astore", Operands::Local(1)),
            ins(30, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![OP_GOTO, 0x1A, 0xAB, 0xB1],
            "{out:?}"
        );
        assert_eq!(
            out[2].operands,
            Operands::LookupSwitch {
                default: 1,
                pairs: vec![(1, 1)],
            },
            "the switch must still land on the return it targeted: {out:?}"
        );
    }

    #[test]
    fn a_try_range_protects_only_the_code_it_covered() {
        let insns: Vec<Instruction> = vec![
            ins(0, 0x04, "iconst_1", Operands::None),
            ins(1, 0x3B, "istore_0", Operands::None),
            ins(2, OP_JSR, "jsr", Operands::Branch(10)),
            ins(5, 0xB1, "return", Operands::None),
            ins(6, 0x4C, "astore_1", Operands::None),
            ins(7, OP_JSR, "jsr", Operands::Branch(5)),
            ins(10, 0x2B, "aload_1", Operands::None),
            ins(11, 0xBF, "athrow", Operands::None),
            ins(12, 0x4D, "astore_2", Operands::None),
            ins(13, 0x05, "iconst_2", Operands::None),
            ins(14, 0x3B, "istore_0", Operands::None),
            ins(15, OP_RET, "ret", Operands::Local(2)),
        ];
        let table: [ExceptionEntry; 1] = [ExceptionEntry {
            start_pc: 0,
            end_pc: 6,
            handler_pc: 6,
            catch_type: 0,
        }];
        let JsrInlined {
            insns: out,
            exception_table,
            report,
        } = inline_jsr_subroutines(&insns, &table);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(
            out.iter()
                .map(|i: &Instruction| i.opcode)
                .collect::<Vec<u8>>(),
            vec![
                0x04, 0x3B, 0x05, 0x3B, OP_GOTO, 0xB1, 0x4C, 0x05, 0x3B, OP_GOTO, 0x2B, 0xBF
            ],
            "{out:?}"
        );
        assert_eq!(
            exception_table,
            vec![
                ExceptionEntry {
                    start_pc: 0,
                    end_pc: 2,
                    handler_pc: 6,
                    catch_type: 0,
                },
                ExceptionEntry {
                    start_pc: 5,
                    end_pc: 6,
                    handler_pc: 6,
                    catch_type: 0,
                },
            ],
            "the inlined finally copy stays outside the try range and the handler follows its code"
        );
    }

    #[test]
    fn inlines_single_subroutine() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(5)),
            ins(3, 0xB1, "return", Operands::None),
            ins(4, 0x00, "nop", Operands::None),
            ins(5, OP_ASTORE, "astore", Operands::Local(1)),
            ins(7, 0x04, "iconst_1", Operands::None),
            ins(8, OP_RET, "ret", Operands::Local(1)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        assert_eq!(report.jsr_sites, 1);
        assert_eq!(report.subroutines, 1);
        assert!(
            out.iter().all(|i: &Instruction| i.opcode != OP_JSR
                && i.opcode != OP_JSR_W
                && i.opcode != OP_RET),
            "output must be jsr/ret-free: {out:?}"
        );
        assert!(
            out.iter().any(|i: &Instruction| i.mnemonic == "iconst_1"),
            "subroutine body must be inlined"
        );
        assert!(
            out.iter().any(|i: &Instruction| i.opcode == OP_GOTO),
            "ret must become a goto back to the return site"
        );
    }

    #[test]
    fn output_is_pc_monotonic_with_resolvable_targets() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(8)),
            ins(3, 0x1b, "iload_1", Operands::None),
            ins(4, 0xac, "ireturn", Operands::None),
            ins(5, 0x00, "nop", Operands::None),
            ins(6, 0x00, "nop", Operands::None),
            ins(7, 0x00, "nop", Operands::None),
            ins(8, OP_ASTORE, "astore", Operands::Local(2)),
            ins(10, 0x1a, "iload_0", Operands::None),
            ins(11, 0x1a, "iload_0", Operands::None),
            ins(12, 0x60, "iadd", Operands::None),
            ins(13, 0x3c, "istore_1", Operands::None),
            ins(14, OP_RET, "ret", Operands::Local(2)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        for w in out.windows(2) {
            assert!(w[0].pc < w[1].pc, "pcs must be strictly monotonic: {out:?}");
        }
        for (idx, i) in out.iter().enumerate() {
            assert_eq!(i.pc, idx as u32, "stride-1 pc renumbering: {out:?}");
        }
        let pcs: BTreeSet<u32> = out.iter().map(|i: &Instruction| i.pc).collect();
        for i in &out {
            if let Operands::Branch(off) = i.operands {
                let target: i64 = i64::from(i.pc) + i64::from(off);
                let target: u32 = u32::try_from(target).expect("target in range");
                assert!(
                    pcs.contains(&target),
                    "branch at pc {} targets {target} which is not a real instruction pc; pcs={pcs:?}",
                    i.pc
                );
            }
        }
        let body: Vec<&'static str> = out.iter().map(|i: &Instruction| i.mnemonic).collect();
        assert_eq!(
            &body[..7],
            &[
                "iload_0", "iload_0", "iadd", "istore_1", "goto", "iload_1", "ireturn"
            ][..],
            "the computation must be inlined before the goto back to the return site: {body:?}"
        );
        let goto: &Instruction = out
            .iter()
            .find(|i: &&Instruction| i.opcode == OP_GOTO)
            .expect("goto");
        let goto_target: u32 = (i64::from(goto.pc)
            + match goto.operands {
                Operands::Branch(off) => i64::from(off),
                _ => panic!("goto must carry a branch offset"),
            }) as u32;
        let ireturn_pc: u32 = out
            .iter()
            .find(|i: &&Instruction| i.opcode == 0xac)
            .map(|i: &Instruction| i.pc)
            .expect("ireturn present");
        let iload_pc: u32 = out
            .iter()
            .find(|i: &&Instruction| i.mnemonic == "iload_1")
            .map(|i: &Instruction| i.pc)
            .expect("iload_1 present");
        assert!(
            goto_target == iload_pc || goto_target == ireturn_pc,
            "goto must jump to the return tail (iload_1/ireturn), got pc {goto_target}"
        );
    }

    #[test]
    fn shared_subroutine_two_sites_each_inlines_a_copy() {
        let insns: Vec<Instruction> = vec![
            ins(0, OP_JSR, "jsr", Operands::Branch(9)),
            ins(3, OP_JSR, "jsr", Operands::Branch(6)),
            ins(6, 0xb1, "return", Operands::None),
            ins(7, 0x00, "nop", Operands::None),
            ins(8, 0x00, "nop", Operands::None),
            ins(9, OP_ASTORE, "astore", Operands::Local(0)),
            ins(11, 0x05, "iconst_2", Operands::None),
            ins(12, 0x57, "pop", Operands::None),
            ins(13, OP_RET, "ret", Operands::Local(0)),
        ];
        let JsrInlined {
            insns: out, report, ..
        } = inline_jsr_subroutines(&insns, &[]);
        assert!(!report.bailed, "{report:?}");
        let copies: usize = out
            .iter()
            .filter(|i: &&Instruction| i.mnemonic == "iconst_2")
            .count();
        assert_eq!(
            copies, 2,
            "each jsr site must receive its own subroutine copy: {out:?}"
        );
        for (idx, i) in out.iter().enumerate() {
            assert_eq!(i.pc, idx as u32);
        }
        let pcs: BTreeSet<u32> = out.iter().map(|i: &Instruction| i.pc).collect();
        for i in &out {
            if let Operands::Branch(off) = i.operands {
                let target: u32 = (i64::from(i.pc) + i64::from(off)) as u32;
                assert!(pcs.contains(&target), "unresolved target {target}: {out:?}");
            }
        }
    }

    #[test]
    fn contains_jsr_detects() {
        let with: Vec<Instruction> = vec![ins(0, OP_JSR, "jsr", Operands::Branch(3))];
        let without: Vec<Instruction> = vec![ins(0, 0x04, "iconst_1", Operands::None)];
        assert!(contains_jsr(&with));
        assert!(!contains_jsr(&without));
    }
}
