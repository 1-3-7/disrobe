use serde::{Deserialize, Serialize};

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind};

pub const STACK_FRAME_SCHEMA: &str = "disrobe.native.stack-frames/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackSlot {
    pub offset: i64,
    pub size: u32,
    pub access_reads: bool,
    pub access_writes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameLayout {
    pub function: String,
    pub address: u64,
    pub uses_frame_pointer: bool,
    pub saved_register_bytes: u32,
    pub fixed_alloc_bytes: u32,
    pub max_stack_depth: u32,
    pub residual_depth: i64,
    pub balanced: bool,
    pub locals: Vec<StackSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrameReport {
    pub schema: &'static str,
    pub frames: Vec<FrameLayout>,
}

#[must_use]
pub fn recover_stack_frames(payload: &DisasmPayload) -> StackFrameReport {
    let mut functions: Vec<&DisasmSymbol> = payload
        .symbol_table
        .iter()
        .filter(|s: &&DisasmSymbol| {
            matches!(
                s.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .collect();
    functions.sort_by_key(|s: &&DisasmSymbol| s.address);
    functions.dedup_by_key(|s: &mut &DisasmSymbol| s.address);

    let mut sorted: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
    sorted.sort_by_key(|i: &&DisasmInstruction| i.offset);
    let last_end: u64 = sorted
        .last()
        .map_or(0, |i: &&DisasmInstruction| i.offset + i.bytes.len() as u64);

    let mut frames: Vec<FrameLayout> = Vec::with_capacity(functions.len());
    for (idx, func) in functions.iter().enumerate() {
        let start: u64 = func.address;
        let end: u64 = functions
            .get(idx + 1)
            .map_or(last_end, |next: &&DisasmSymbol| next.address);
        let body: Vec<&DisasmInstruction> = sorted
            .iter()
            .copied()
            .filter(|i: &&DisasmInstruction| i.offset >= start && i.offset < end)
            .collect();
        if body.is_empty() {
            continue;
        }
        frames.push(analyze_frame(&func.name, start, &body));
    }

    StackFrameReport {
        schema: STACK_FRAME_SCHEMA,
        frames,
    }
}

fn analyze_frame(name: &str, address: u64, body: &[&DisasmInstruction]) -> FrameLayout {
    let mut depth: i64 = 0;
    let mut min_depth: i64 = 0;
    let mut saved_register_bytes: u32 = 0;
    let mut fixed_alloc_bytes: u32 = 0;
    let mut seen_non_push: bool = false;
    let mut uses_frame_pointer: bool = false;

    for insn in body {
        let effect: i64 = i64::from(insn.stack_effect.sp_delta);
        if effect != 0 {
            depth += effect;
            min_depth = min_depth.min(depth);
        }
        if !seen_non_push && is_register_push(insn) {
            saved_register_bytes = saved_register_bytes.saturating_add(push_width(insn));
        } else if insn.stack_effect.sp_delta == 0 || !is_register_push(insn) {
            seen_non_push = true;
        }
        if is_frame_pointer_setup(insn) {
            uses_frame_pointer = true;
        }
        if let Some(alloc) = explicit_stack_alloc(insn)
            && fixed_alloc_bytes == 0
        {
            fixed_alloc_bytes = alloc;
        }
    }

    let max_stack_depth: u32 = u32::try_from(min_depth.unsigned_abs()).unwrap_or(u32::MAX);
    let locals: Vec<StackSlot> = recover_local_slots(body, uses_frame_pointer);

    FrameLayout {
        function: name.to_owned(),
        address,
        uses_frame_pointer,
        saved_register_bytes,
        fixed_alloc_bytes,
        max_stack_depth,
        residual_depth: depth,
        balanced: depth == 0,
        locals,
    }
}

fn is_register_push(insn: &DisasmInstruction) -> bool {
    insn.mnemonic == "push" && insn.stack_effect.is_stack && insn.stack_effect.sp_delta < 0
}

fn push_width(insn: &DisasmInstruction) -> u32 {
    insn.stack_effect.sp_delta.unsigned_abs()
}

fn is_frame_pointer_setup(insn: &DisasmInstruction) -> bool {
    if insn.mnemonic != "mov" {
        return false;
    }
    let writes_bp: bool = insn
        .reg_uses
        .iter()
        .any(|r| (r.register == "RBP" || r.register == "EBP") && r.access.writes());
    let reads_sp: bool = insn
        .reg_uses
        .iter()
        .any(|r| (r.register == "RSP" || r.register == "ESP") && r.access.reads());
    writes_bp && reads_sp
}

fn explicit_stack_alloc(insn: &DisasmInstruction) -> Option<u32> {
    if insn.mnemonic != "sub" {
        return None;
    }
    let targets_sp: bool = insn
        .reg_uses
        .iter()
        .any(|r| (r.register == "RSP" || r.register == "ESP") && r.access.writes());
    if !targets_sp {
        return None;
    }
    let imm: &String = insn.operands.last()?;
    parse_immediate(imm)
}

fn parse_immediate(text: &str) -> Option<u32> {
    let trimmed: &str = text.trim();
    let hex: Option<&str> = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    if let Some(rest) = hex {
        return u32::from_str_radix(rest, 16).ok();
    }
    trimmed.parse::<u32>().ok()
}

fn recover_local_slots(body: &[&DisasmInstruction], uses_frame_pointer: bool) -> Vec<StackSlot> {
    let base: &str = if uses_frame_pointer { "RBP" } else { "RSP" };
    let mut slots: Vec<StackSlot> = Vec::new();
    for insn in body {
        for mem in &insn.mem_uses {
            if mem.base != base && mem.base != frame_alias(base) {
                continue;
            }
            if mem.index != "None" {
                continue;
            }
            let offset: i64 = mem.displacement as i64;
            if uses_frame_pointer && offset > 0 {
                continue;
            }
            let size: u32 = memory_size_bytes(&mem.memory_size);
            if size == 0 {
                continue;
            }
            upsert_slot(
                &mut slots,
                offset,
                size,
                mem.access.reads(),
                mem.access.writes(),
            );
        }
    }
    slots.sort_by_key(|s: &StackSlot| s.offset);
    slots
}

const fn frame_alias(base: &str) -> &str {
    match base.as_bytes() {
        b"RBP" => "EBP",
        b"RSP" => "ESP",
        _ => base,
    }
}

fn upsert_slot(slots: &mut Vec<StackSlot>, offset: i64, size: u32, reads: bool, writes: bool) {
    if let Some(slot) = slots.iter_mut().find(|s| s.offset == offset) {
        slot.size = slot.size.max(size);
        slot.access_reads |= reads;
        slot.access_writes |= writes;
    } else {
        slots.push(StackSlot {
            offset,
            size,
            access_reads: reads,
            access_writes: writes,
        });
    }
}

fn memory_size_bytes(memory_size: &str) -> u32 {
    match memory_size {
        "UInt8" | "Int8" => 1,
        "UInt16" | "Int16" => 2,
        "UInt32" | "Int32" | "Float32" => 4,
        "UInt64" | "Int64" | "Float64" => 8,
        "UInt128" | "Int128" | "Float128" => 16,
        "UInt256" => 32,
        "UInt512" => 64,
        _ => 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::disasm_ir::build_disasm_payload;

    fn corpus_bytes(rel: &str) -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel);
        std::fs::read(path).ok()
    }

    #[test]
    fn real_elf_frames_balance_and_carry_saved_registers() {
        let Some(stripped): Option<Vec<u8>> = corpus_bytes("native/discovery/disc.stripped.elf")
        else {
            return;
        };
        let payload: DisasmPayload = build_disasm_payload(&stripped).expect("build payload");
        let report: StackFrameReport = recover_stack_frames(&payload);
        assert!(
            !report.frames.is_empty(),
            "a real ELF yields recovered stack frames"
        );
        let balanced: usize = report.frames.iter().filter(|f| f.balanced).count();
        assert!(
            balanced > 0,
            "well-formed functions balance their stack across the body: {:?}",
            report
                .frames
                .iter()
                .map(|f| (f.function.clone(), f.residual_depth))
                .collect::<Vec<(String, i64)>>()
        );
        assert!(
            report
                .frames
                .iter()
                .any(|f| f.saved_register_bytes > 0 || f.max_stack_depth > 0),
            "at least one frame touches the stack (prologue pushes or allocation)"
        );
    }

    #[test]
    fn max_depth_tracks_cumulative_stack_effect() {
        let Some(stripped): Option<Vec<u8>> = corpus_bytes("native/discovery/disc.stripped.elf")
        else {
            return;
        };
        let payload: DisasmPayload = build_disasm_payload(&stripped).expect("build payload");
        let report: StackFrameReport = recover_stack_frames(&payload);
        for frame in &report.frames {
            assert!(
                i64::from(frame.max_stack_depth) >= frame.saved_register_bytes as i64,
                "max depth {} must cover the saved-register pushes {} in {}",
                frame.max_stack_depth,
                frame.saved_register_bytes,
                frame.function
            );
        }
    }

    #[test]
    fn report_round_trips_serde() {
        let report: StackFrameReport = StackFrameReport {
            schema: STACK_FRAME_SCHEMA,
            frames: vec![FrameLayout {
                function: "main".to_owned(),
                address: 0x1000,
                uses_frame_pointer: true,
                saved_register_bytes: 8,
                fixed_alloc_bytes: 0x20,
                max_stack_depth: 0x28,
                residual_depth: 0,
                balanced: true,
                locals: vec![StackSlot {
                    offset: -8,
                    size: 8,
                    access_reads: true,
                    access_writes: true,
                }],
            }],
        };
        let json: &'static str = Box::leak(
            serde_json::to_string(&report)
                .expect("serialize")
                .into_boxed_str(),
        );
        let back: StackFrameReport = serde_json::from_str(json).expect("deserialize");
        assert_eq!(report, back);
    }
}
