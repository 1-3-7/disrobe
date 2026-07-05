#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::struct_excessive_bools
)]

use std::collections::{BTreeMap, BTreeSet};

use object::{Object as _, ObjectSection as _, SectionKind};
use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::disasm_ir::build_disasm_payload;
use crate::error::Result;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};
use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind};

const DECODER_MIN_ARITH: u32 = 1;
const DECODER_MIN_MEMORY_OPS: u32 = 2;
const DECODER_MAX_INSNS: usize = 4096;
const MAX_CANDIDATES: usize = 64;
const PER_CANDIDATE_STEP_CAP: u64 = 200_000;
const MAX_BUFFERS_PER_CANDIDATE: usize = 24;
const MIN_RECOVERED_LEN: usize = 4;
const MIN_WIDE_CHARS: usize = 4;
const MAX_DECODE_SPAN: u64 = 64 * 1024;
const MAX_HARVEST_PER_RUN: usize = 512;
const MAX_STRING_LEN: usize = 4096;

const EMU_STACK_BASE: u64 = 0x1000_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_OUTPUT_BASE: u64 = 0x2000_0000;
const EMU_OUTPUT_SIZE: u64 = MAX_DECODE_SPAN;
const EMU_SENTINEL_RET: u64 = 0xDEAD_0000_0000_BEEF;
const EMU_LAZY_PAGE_BUDGET: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatedString {
    pub value: String,
    pub decoder_address: u64,
    pub source_buffer_address: u64,
    pub output_address: u64,
    pub exit: String,
}

#[derive(Debug, Clone)]
pub struct DecoderCandidate {
    pub address: u64,
    pub name: String,
    pub instruction_count: usize,
    pub byte_arith_ops: u32,
    pub arith_ops: u32,
    pub memory_ops: u32,
    pub loop_back_edges: u32,
}

#[derive(Debug, Clone)]
struct LoadedSection {
    address: u64,
    bytes: Vec<u8>,
    writable: bool,
    executable: bool,
}

#[derive(Debug, Default)]
struct DecoderHost;

impl HostCall for DecoderHost {
    fn dispatch(&mut self, _target: u64, _regs: &mut Regs, _mem: &mut Memory) -> Result<bool> {
        Ok(false)
    }
}

#[must_use]
pub fn emulate_string_decoders(bytes: &[u8]) -> Vec<EmulatedString> {
    emulate_string_decoders_inner(bytes).unwrap_or_default()
}

fn emulate_string_decoders_inner(bytes: &[u8]) -> Result<Vec<EmulatedString>> {
    let file: object::File<'_> =
        object::File::parse(bytes).map_err(|e| crate::error::Error::ObjectParse(e.to_string()))?;
    let mode: CpuMode = match object_arch(&file) {
        Some(Arch::X86) => CpuMode::Bits32,
        Some(Arch::X86_64) => CpuMode::Bits64,
        _ => return Ok(Vec::new()),
    };

    let sections: Vec<LoadedSection> = load_sections(&file);
    if sections.is_empty() {
        return Ok(Vec::new());
    }

    let payload: DisasmPayload = build_disasm_payload(bytes)?;
    let candidates: Vec<DecoderCandidate> = identify_candidates(&payload);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let buffers: Vec<(u64, usize)> = candidate_buffers(&sections);
    if buffers.is_empty() {
        return Ok(Vec::new());
    }

    let static_set: BTreeSet<String> = static_strings(&sections);

    let mut out: Vec<EmulatedString> = Vec::new();
    let mut seen: BTreeSet<(u64, u64, String)> = BTreeSet::new();
    for candidate in candidates.iter().take(MAX_CANDIDATES) {
        for &(buf_addr, buf_len) in buffers.iter().take(MAX_BUFFERS_PER_CANDIDATE) {
            let span: u64 = (buf_len as u64).min(MAX_DECODE_SPAN);
            let attempts: Vec<EmulatedString> =
                run_candidate(&sections, mode, candidate, buf_addr, span, &static_set);
            for hit in attempts {
                let key: (u64, u64, String) = (
                    hit.decoder_address,
                    hit.source_buffer_address,
                    hit.value.clone(),
                );
                if seen.insert(key) {
                    out.push(hit);
                }
            }
        }
    }
    out.sort_by(|a: &EmulatedString, b: &EmulatedString| {
        a.decoder_address
            .cmp(&b.decoder_address)
            .then(a.source_buffer_address.cmp(&b.source_buffer_address))
            .then(a.value.cmp(&b.value))
    });
    Ok(out)
}

fn run_candidate(
    sections: &[LoadedSection],
    mode: CpuMode,
    candidate: &DecoderCandidate,
    buf_addr: u64,
    span: u64,
    static_set: &BTreeSet<String>,
) -> Vec<EmulatedString> {
    let mut out: Vec<EmulatedString> = Vec::new();
    for convention in argument_conventions(mode) {
        let Ok((harvested, exit)): Result<(Vec<(u64, String)>, ExitReason)> = emulate_once(
            sections,
            mode,
            candidate.address,
            buf_addr,
            span,
            convention,
        ) else {
            continue;
        };
        let exit_label: String = format!("{exit:?}");
        for (output_address, value) in harvested {
            if static_set.contains(&value) {
                continue;
            }
            out.push(EmulatedString {
                value,
                decoder_address: candidate.address,
                source_buffer_address: buf_addr,
                output_address,
                exit: exit_label.clone(),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
enum ArgConvention {
    SysV64,
    Win64,
    Cdecl32,
    InPlaceSysV64,
    InPlaceWin64,
    InPlaceCdecl32,
}

fn argument_conventions(mode: CpuMode) -> Vec<ArgConvention> {
    match mode {
        CpuMode::Bits64 => vec![
            ArgConvention::SysV64,
            ArgConvention::Win64,
            ArgConvention::InPlaceSysV64,
            ArgConvention::InPlaceWin64,
        ],
        CpuMode::Bits32 => vec![ArgConvention::Cdecl32, ArgConvention::InPlaceCdecl32],
    }
}

fn emulate_once(
    sections: &[LoadedSection],
    mode: CpuMode,
    entry: u64,
    buf_addr: u64,
    span: u64,
    convention: ArgConvention,
) -> Result<(Vec<(u64, String)>, ExitReason)> {
    let mut cpu: Cpu = Cpu::new(mode);
    for section in sections {
        let perm: Perm = if section.executable {
            Perm::RX
        } else if section.writable {
            Perm::RW
        } else {
            Perm::R
        };
        cpu.mem
            .map(section.address, section.bytes.len() as u64, perm)?;
        cpu.mem.write_unchecked(section.address, &section.bytes);
    }
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.map(EMU_OUTPUT_BASE, EMU_OUTPUT_SIZE, Perm::RW)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);

    let in_place: bool = matches!(
        convention,
        ArgConvention::InPlaceSysV64 | ArgConvention::InPlaceWin64 | ArgConvention::InPlaceCdecl32
    );
    let output_addr: u64 = if in_place { buf_addr } else { EMU_OUTPUT_BASE };

    let sp: u64 = EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000;
    cpu.regs.set(Reg::Rsp, sp);
    seed_arguments(&mut cpu, mode, convention, buf_addr, output_addr, span, sp)?;
    cpu.regs.rip = entry;

    cpu.mem.enable_write_log();
    let exit: ExitReason = cpu.run(&mut DecoderHost, PER_CANDIDATE_STEP_CAP)?;

    let harvested: Vec<(u64, String)> = harvest_write_log(cpu.mem.write_log());
    Ok((harvested, exit))
}

fn seed_arguments(
    cpu: &mut Cpu,
    mode: CpuMode,
    convention: ArgConvention,
    buf_addr: u64,
    output_addr: u64,
    span: u64,
    sp: u64,
) -> Result<()> {
    match convention {
        ArgConvention::SysV64 | ArgConvention::InPlaceSysV64 => {
            cpu.regs.set(Reg::Rdi, buf_addr);
            cpu.regs.set(Reg::Rsi, output_addr);
            cpu.regs.set(Reg::Rdx, span);
            cpu.regs.set(Reg::Rcx, span);
            let ret_slot: u64 = sp.wrapping_sub(8);
            cpu.regs.set(Reg::Rsp, ret_slot);
            cpu.mem.write_u64(ret_slot, EMU_SENTINEL_RET)?;
        }
        ArgConvention::Win64 | ArgConvention::InPlaceWin64 => {
            cpu.regs.set(Reg::Rcx, buf_addr);
            cpu.regs.set(Reg::Rdx, output_addr);
            cpu.regs.set(Reg::R8, span);
            cpu.regs.set(Reg::R9, span);
            let shadow: u64 = sp.wrapping_sub(0x20).wrapping_sub(8);
            cpu.regs.set(Reg::Rsp, shadow);
            cpu.mem.write_u64(shadow, EMU_SENTINEL_RET)?;
        }
        ArgConvention::Cdecl32 | ArgConvention::InPlaceCdecl32 => {
            let arg2: u64 = sp.wrapping_sub(4);
            let arg1: u64 = sp.wrapping_sub(8);
            let arg0: u64 = sp.wrapping_sub(12);
            let ret_slot: u64 = sp.wrapping_sub(16);
            cpu.mem.write_u32(arg2, span as u32)?;
            cpu.mem.write_u32(arg1, output_addr as u32)?;
            cpu.mem.write_u32(arg0, buf_addr as u32)?;
            cpu.mem.write_u32(ret_slot, EMU_SENTINEL_RET as u32)?;
            cpu.regs.set(Reg::Rsp, ret_slot);
        }
    }
    let _ = mode;
    Ok(())
}

#[derive(Debug, Clone)]
struct Harvest {
    start: u64,
    span: u64,
    value: String,
}

fn harvest_write_log(log: &[(u64, u8)]) -> Vec<(u64, String)> {
    let ascii: Vec<Harvest> = harvest_ascii(log);
    let wide: Vec<Harvest> = harvest_utf16(log);
    merge_harvests(ascii, wide)
}

fn harvest_ascii(log: &[(u64, u8)]) -> Vec<Harvest> {
    let mut shadow: BTreeMap<u64, u8> = BTreeMap::new();
    let mut out: Vec<Harvest> = Vec::new();
    for &(addr, value) in log {
        if out.len() >= MAX_HARVEST_PER_RUN {
            return out;
        }
        if let Some(&old) = shadow.get(&addr)
            && old != value
            && is_printable_ascii(old)
        {
            seal_run(&mut shadow, addr, &mut out);
        }
        shadow.insert(addr, value);
    }
    flush_shadow(&shadow, &mut out);
    out
}

fn seal_run(shadow: &mut BTreeMap<u64, u8>, addr: u64, out: &mut Vec<Harvest>) {
    let mut start: u64 = addr;
    while let Some(&b) = shadow.get(&start.wrapping_sub(1)) {
        if !is_printable_ascii(b) {
            break;
        }
        start = start.wrapping_sub(1);
    }
    let mut end: u64 = addr;
    while let Some(&b) = shadow.get(&end) {
        if !is_printable_ascii(b) {
            break;
        }
        end = end.wrapping_add(1);
    }
    let mut bytes: Vec<u8> = Vec::with_capacity((end - start) as usize);
    let mut cursor: u64 = start;
    while cursor < end {
        if let Some(&b) = shadow.get(&cursor) {
            bytes.push(b);
        }
        shadow.remove(&cursor);
        cursor = cursor.wrapping_add(1);
    }
    push_candidate(start, &bytes, out);
}

fn flush_shadow(shadow: &BTreeMap<u64, u8>, out: &mut Vec<Harvest>) {
    let mut cur: Option<(u64, u64, Vec<u8>)> = None;
    for (&addr, &value) in shadow {
        let printable: bool = is_printable_ascii(value);
        if let Some((_, next, bytes)) = cur.as_mut()
            && printable
            && *next == addr
        {
            bytes.push(value);
            *next = addr.wrapping_add(1);
            continue;
        }
        if let Some((start, _, bytes)) = cur.take() {
            push_candidate(start, &bytes, out);
        }
        if printable {
            cur = Some((addr, addr.wrapping_add(1), vec![value]));
        }
    }
    if let Some((start, _, bytes)) = cur.take() {
        push_candidate(start, &bytes, out);
    }
}

fn push_candidate(start: u64, bytes: &[u8], out: &mut Vec<Harvest>) {
    if out.len() >= MAX_HARVEST_PER_RUN
        || bytes.len() < MIN_RECOVERED_LEN
        || bytes.len() > MAX_STRING_LEN
        || !run_looks_textual(bytes)
    {
        return;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        out.push(Harvest {
            start,
            span: bytes.len() as u64,
            value: s.to_owned(),
        });
    }
}

fn harvest_utf16(log: &[(u64, u8)]) -> Vec<Harvest> {
    let mut shadow: BTreeMap<u64, u8> = BTreeMap::new();
    let mut out: Vec<Harvest> = Vec::new();
    for &(addr, value) in log {
        if out.len() >= MAX_HARVEST_PER_RUN {
            return out;
        }
        if let Some(&old) = shadow.get(&addr)
            && old != value
        {
            seal_wide_run(&mut shadow, addr, &mut out);
        }
        shadow.insert(addr, value);
    }
    flush_wide(&shadow, &mut out);
    out
}

fn wide_cell(shadow: &BTreeMap<u64, u8>, low: u64) -> bool {
    shadow.get(&low).copied().is_some_and(is_printable_ascii)
        && shadow.get(&low.wrapping_add(1)).copied() == Some(0)
}

fn wide_low_anchor(shadow: &BTreeMap<u64, u8>, addr: u64) -> Option<u64> {
    if wide_cell(shadow, addr) {
        return Some(addr);
    }
    let prev: u64 = addr.checked_sub(1)?;
    wide_cell(shadow, prev).then_some(prev)
}

fn seal_wide_run(shadow: &mut BTreeMap<u64, u8>, addr: u64, out: &mut Vec<Harvest>) {
    let Some(low): Option<u64> = wide_low_anchor(shadow, addr) else {
        return;
    };
    let mut start: u64 = low;
    while let Some(prev) = start.checked_sub(2) {
        if wide_cell(shadow, prev) {
            start = prev;
        } else {
            break;
        }
    }
    let mut end: u64 = low;
    while wide_cell(shadow, end) {
        end = end.wrapping_add(2);
    }
    let mut chars: Vec<u8> = Vec::with_capacity(((end - start) / 2) as usize);
    let mut cursor: u64 = start;
    while cursor < end {
        if let Some(&b) = shadow.get(&cursor) {
            chars.push(b);
        }
        shadow.remove(&cursor);
        shadow.remove(&cursor.wrapping_add(1));
        cursor = cursor.wrapping_add(2);
    }
    push_wide_candidate(start, &chars, out);
}

fn flush_wide(shadow: &BTreeMap<u64, u8>, out: &mut Vec<Harvest>) {
    for (base, bytes) in contiguous_segments(shadow) {
        scan_wide_segment(base, &bytes, out);
    }
}

fn contiguous_segments(shadow: &BTreeMap<u64, u8>) -> Vec<(u64, Vec<u8>)> {
    let mut segs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut cur: Option<(u64, u64, Vec<u8>)> = None;
    for (&addr, &b) in shadow {
        if let Some((_, next, bytes)) = cur.as_mut()
            && *next == addr
        {
            bytes.push(b);
            *next = addr.wrapping_add(1);
            continue;
        }
        if let Some((start, _, bytes)) = cur.take() {
            segs.push((start, bytes));
        }
        cur = Some((addr, addr.wrapping_add(1), vec![b]));
    }
    if let Some((start, _, bytes)) = cur.take() {
        segs.push((start, bytes));
    }
    segs
}

fn scan_wide_segment(base: u64, region: &[u8], out: &mut Vec<Harvest>) {
    let mut i: usize = 0;
    while i + 1 < region.len() {
        if out.len() >= MAX_HARVEST_PER_RUN {
            return;
        }
        if is_printable_ascii(region[i]) && region[i + 1] == 0 {
            let mut chars: Vec<u8> = Vec::new();
            let mut j: usize = i;
            while j + 1 < region.len() && is_printable_ascii(region[j]) && region[j + 1] == 0 {
                chars.push(region[j]);
                j += 2;
            }
            push_wide_candidate(base.wrapping_add(i as u64), &chars, out);
            i = j;
        } else {
            i += 1;
        }
    }
}

fn push_wide_candidate(start: u64, chars: &[u8], out: &mut Vec<Harvest>) {
    if out.len() >= MAX_HARVEST_PER_RUN
        || chars.len() < MIN_WIDE_CHARS
        || chars.len() > MAX_STRING_LEN
        || !run_looks_textual(chars)
    {
        return;
    }
    if let Ok(s) = std::str::from_utf8(chars) {
        out.push(Harvest {
            start,
            span: (chars.len() as u64) * 2,
            value: s.to_owned(),
        });
    }
}

fn spans_overlap(a: &Harvest, b: &Harvest) -> bool {
    a.start < b.start.saturating_add(b.span) && b.start < a.start.saturating_add(a.span)
}

fn merge_harvests(ascii: Vec<Harvest>, wide: Vec<Harvest>) -> Vec<(u64, String)> {
    let mut kept_ascii: Vec<Harvest> = ascii;
    let ascii_values: BTreeSet<String> = kept_ascii
        .iter()
        .map(|h: &Harvest| h.value.clone())
        .collect();
    let mut kept_wide: Vec<Harvest> = Vec::new();
    for cand in wide {
        if kept_ascii.len() + kept_wide.len() >= MAX_HARVEST_PER_RUN {
            break;
        }
        if ascii_values.contains(&cand.value) {
            continue;
        }
        let dominated: bool = kept_ascii
            .iter()
            .any(|a: &Harvest| spans_overlap(a, &cand) && a.span >= cand.span);
        if dominated {
            continue;
        }
        kept_ascii.retain(|a: &Harvest| !(spans_overlap(a, &cand) && a.span < cand.span));
        kept_wide.push(cand);
    }
    let mut merged: Vec<Harvest> = kept_ascii;
    merged.extend(kept_wide);
    merged.sort_by(|a: &Harvest, b: &Harvest| a.start.cmp(&b.start).then(a.value.cmp(&b.value)));
    merged
        .into_iter()
        .map(|h: Harvest| (h.start, h.value))
        .collect()
}

fn static_strings(sections: &[LoadedSection]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for section in sections {
        let mut run: Vec<u8> = Vec::with_capacity(64);
        for &b in &section.bytes {
            if is_printable_ascii(b) {
                run.push(b);
                continue;
            }
            insert_static_run(&run, &mut out);
            run.clear();
        }
        insert_static_run(&run, &mut out);
        insert_static_wide_runs(&section.bytes, &mut out);
    }
    out
}

fn insert_static_wide_runs(bytes: &[u8], out: &mut BTreeSet<String>) {
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if is_printable_ascii(bytes[i]) && bytes[i + 1] == 0 {
            let mut chars: Vec<u8> = Vec::new();
            let mut j: usize = i;
            while j + 1 < bytes.len() && is_printable_ascii(bytes[j]) && bytes[j + 1] == 0 {
                chars.push(bytes[j]);
                j += 2;
            }
            insert_static_run(&chars, out);
            i = j;
        } else {
            i += 1;
        }
    }
}

fn insert_static_run(run: &[u8], out: &mut BTreeSet<String>) {
    if run.len() < MIN_RECOVERED_LEN || run.len() > MAX_STRING_LEN {
        return;
    }
    if let Ok(s) = std::str::from_utf8(run) {
        out.insert(s.to_owned());
    }
}

fn run_looks_textual(run: &[u8]) -> bool {
    let alnum: usize = run
        .iter()
        .filter(|b: &&u8| b.is_ascii_alphanumeric())
        .count();
    alnum * 2 >= run.len()
}

const fn is_printable_ascii(b: u8) -> bool {
    b >= 0x20 && b < 0x7F
}

fn identify_candidates(payload: &DisasmPayload) -> Vec<DecoderCandidate> {
    let starts: Vec<(u64, String)> = function_starts(payload);
    if starts.is_empty() {
        return Vec::new();
    }
    let mut by_offset: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
    by_offset.sort_by_key(|i: &&DisasmInstruction| i.offset);

    let mut out: Vec<DecoderCandidate> = Vec::new();
    for (idx, (start, name)) in starts.iter().enumerate() {
        let end: u64 = starts
            .get(idx + 1)
            .map_or(u64::MAX, |(a, _): &(u64, String)| *a);
        let body: Vec<&DisasmInstruction> = slice_function(&by_offset, *start, end);
        if body.is_empty() || body.len() > DECODER_MAX_INSNS {
            continue;
        }
        let loop_back_edges: u32 = count_loop_back_edges(&body, *start, end);
        if loop_back_edges == 0 {
            continue;
        }
        let arith_ops: u32 = body
            .iter()
            .filter(|i: &&&DisasmInstruction| is_arith(i))
            .count() as u32;
        let memory_ops: u32 = body
            .iter()
            .filter(|i: &&&DisasmInstruction| touches_memory(i))
            .count() as u32;
        if arith_ops < DECODER_MIN_ARITH || memory_ops < DECODER_MIN_MEMORY_OPS {
            continue;
        }
        if !has_byte_store(&body) || !has_byte_load(&body) {
            continue;
        }
        let byte_arith_ops: u32 = body
            .iter()
            .filter(|i: &&&DisasmInstruction| is_byte_arith(i))
            .count() as u32;
        out.push(DecoderCandidate {
            address: *start,
            name: name.clone(),
            instruction_count: body.len(),
            byte_arith_ops,
            arith_ops,
            memory_ops,
            loop_back_edges,
        });
    }
    out.sort_by(|a: &DecoderCandidate, b: &DecoderCandidate| {
        b.arith_ops
            .cmp(&a.arith_ops)
            .then(b.memory_ops.cmp(&a.memory_ops))
            .then(a.address.cmp(&b.address))
    });
    out
}

fn function_starts(payload: &DisasmPayload) -> Vec<(u64, String)> {
    let mut map: BTreeMap<u64, String> = BTreeMap::new();
    for sym in &payload.symbol_table {
        if matches!(
            sym.kind,
            DisasmSymbolKind::Function | DisasmSymbolKind::Export
        ) {
            map.entry(sym.address).or_insert_with(|| symbol_label(sym));
        }
    }
    map.into_iter().collect()
}

fn symbol_label(sym: &DisasmSymbol) -> String {
    if sym.name.is_empty() {
        format!("sub_{:x}", sym.address)
    } else {
        sym.name.clone()
    }
}

fn slice_function<'a>(
    sorted: &[&'a DisasmInstruction],
    start: u64,
    end: u64,
) -> Vec<&'a DisasmInstruction> {
    sorted
        .iter()
        .copied()
        .filter(|i: &&DisasmInstruction| i.offset >= start && i.offset < end)
        .collect()
}

fn count_loop_back_edges(body: &[&DisasmInstruction], start: u64, end: u64) -> u32 {
    body.iter()
        .filter(|i: &&&DisasmInstruction| {
            i.branch_target
                .is_some_and(|t: u64| t >= start && t <= i.offset && t < end)
        })
        .count() as u32
}

fn is_arith(insn: &DisasmInstruction) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "xor"
            | "add"
            | "sub"
            | "rol"
            | "ror"
            | "shl"
            | "shr"
            | "sar"
            | "not"
            | "neg"
            | "and"
            | "or"
            | "imul"
            | "lea"
    )
}

fn is_byte_arith(insn: &DisasmInstruction) -> bool {
    let arith: bool = matches!(
        insn.mnemonic.as_str(),
        "xor" | "add" | "sub" | "rol" | "ror" | "shl" | "shr" | "not" | "neg" | "and" | "or"
    );
    if !arith {
        return false;
    }
    insn.operands.iter().any(|op: &String| {
        let lower: String = op.to_ascii_lowercase();
        lower.contains("byte") || is_byte_register(&lower)
    })
}

fn is_byte_register(operand: &str) -> bool {
    matches!(
        operand,
        "al" | "ah"
            | "bl"
            | "bh"
            | "cl"
            | "ch"
            | "dl"
            | "dh"
            | "sil"
            | "dil"
            | "bpl"
            | "spl"
            | "r8b"
            | "r9b"
            | "r10b"
            | "r11b"
            | "r12b"
            | "r13b"
            | "r14b"
            | "r15b"
    )
}

fn touches_memory(insn: &DisasmInstruction) -> bool {
    insn.operands
        .iter()
        .any(|op: &String| op.contains('[') && op.contains(']'))
}

fn has_byte_store(body: &[&DisasmInstruction]) -> bool {
    body.iter().any(|i: &&DisasmInstruction| {
        if matches!(i.mnemonic.as_str(), "stosb") {
            return true;
        }
        if !is_memory_write_mnemonic(&i.mnemonic) {
            return false;
        }
        let Some(dest): Option<&String> = i.operands.first() else {
            return false;
        };
        if !(dest.contains('[') && dest.contains(']')) {
            return false;
        }
        let dest_lower: String = dest.to_ascii_lowercase();
        let byte_dest: bool = dest_lower.contains("byte");
        let byte_src: bool = i
            .operands
            .iter()
            .skip(1)
            .any(|op: &String| is_byte_register(&op.to_ascii_lowercase()));
        byte_dest || byte_src
    })
}

fn has_byte_load(body: &[&DisasmInstruction]) -> bool {
    body.iter().any(|i: &&DisasmInstruction| {
        if matches!(i.mnemonic.as_str(), "lodsb") {
            return true;
        }
        let mnem: &str = i.mnemonic.as_str();
        let reads_mem_into_byte: bool = matches!(mnem, "movzx" | "movsx" | "movsxd" | "mov")
            && i.operands
                .iter()
                .skip(1)
                .any(|op: &String| op.contains('[') && op.contains(']'));
        let byte_sized: bool = i
            .operands
            .iter()
            .any(|op: &String| op.to_ascii_lowercase().contains("byte"))
            || matches!(mnem, "movzx" | "movsx");
        reads_mem_into_byte && byte_sized
    })
}

fn is_memory_write_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov"
            | "xor"
            | "add"
            | "sub"
            | "and"
            | "or"
            | "rol"
            | "ror"
            | "shl"
            | "shr"
            | "not"
            | "neg"
            | "stosb"
            | "stosw"
            | "stosd"
            | "stosq"
            | "movsb"
            | "movsw"
            | "movsd"
            | "movsq"
            | "inc"
            | "dec"
    )
}

fn candidate_buffers(sections: &[LoadedSection]) -> Vec<(u64, usize)> {
    let mut out: Vec<(u64, usize)> = Vec::new();
    for section in sections {
        if section.executable {
            continue;
        }
        if section.bytes.iter().all(|b: &u8| *b == 0) {
            continue;
        }
        out.push((section.address, section.bytes.len()));
    }
    out.sort_by_key(|(addr, _): &(u64, usize)| *addr);
    out
}

fn load_sections(file: &object::File<'_>) -> Vec<LoadedSection> {
    let mut out: Vec<LoadedSection> = Vec::new();
    for section in file.sections() {
        let address: u64 = section.address();
        if address == 0 {
            continue;
        }
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let kind: SectionKind = section.kind();
        let executable: bool = matches!(kind, SectionKind::Text)
            || section
                .name()
                .is_ok_and(|n: &str| n == ".text" || n == "__text" || n.starts_with(".text"));
        let writable: bool = matches!(kind, SectionKind::Data | SectionKind::UninitializedData);
        out.push(LoadedSection {
            address,
            bytes: data.to_vec(),
            writable: writable || !executable,
            executable,
        });
    }
    out.sort_by_key(|s: &LoadedSection| s.address);
    out
}

fn object_arch(file: &object::File<'_>) -> Option<Arch> {
    match file.architecture() {
        object::Architecture::I386 => Some(Arch::X86),
        object::Architecture::X86_64 => Some(Arch::X86_64),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::obfuscators::recover_single_byte_xor_strings;

    const PLAINTEXT: &[u8] = b"https://c2.evil.example/gate.php";
    const XOR_KEY: [u8; 4] = [0x37, 0x13, 0x55, 0xA9];

    fn multibyte_xor(plain: &[u8], key: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
            .collect()
    }

    const TEXT_VA: u64 = 0x40_0000;
    const DATA_VA: u64 = 0x60_0000;

    fn elf_with_multibyte_xor_decoder() -> Vec<u8> {
        let code: Vec<u8> = sysv64_xor_decoder();
        let mut data: Vec<u8> = multibyte_xor(PLAINTEXT, &XOR_KEY);
        data.extend_from_slice(&XOR_KEY);
        build_elf64_exec(&code, &data, "decode")
    }

    fn build_elf64_exec(text: &[u8], data: &[u8], func_name: &str) -> Vec<u8> {
        let ehdr_size: u64 = 64;
        let shentsize: u16 = 64;
        let text_off: u64 = ehdr_size;
        let data_off: u64 = align_up(text_off + text.len() as u64, 16);

        let shstrtab: Vec<u8> =
            build_strtab(&["", ".text", ".data", ".shstrtab", ".symtab", ".strtab"]);
        let name_text: u32 = strtab_offset(&shstrtab, ".text");
        let name_data: u32 = strtab_offset(&shstrtab, ".data");
        let name_shstr: u32 = strtab_offset(&shstrtab, ".shstrtab");
        let name_symtab: u32 = strtab_offset(&shstrtab, ".symtab");
        let name_strtab: u32 = strtab_offset(&shstrtab, ".strtab");

        let strtab: Vec<u8> = build_strtab(&["", func_name]);
        let name_func: u32 = strtab_offset(&strtab, func_name);

        let shstr_off: u64 = align_up(data_off + data.len() as u64, 16);
        let symtab_off: u64 = align_up(shstr_off + shstrtab.len() as u64, 8);
        let sym_entsize: u64 = 24;
        let sym_count: u64 = 2;
        let strtab_off: u64 = symtab_off + sym_count * sym_entsize;
        let shoff: u64 = align_up(strtab_off + strtab.len() as u64, 8);

        let mut symtab: Vec<u8> = Vec::new();
        symtab.extend_from_slice(&[0u8; 24]);
        let mut sym: Vec<u8> = Vec::new();
        sym.extend_from_slice(&name_func.to_le_bytes());
        sym.push(0x12);
        sym.push(0);
        sym.extend_from_slice(&1u16.to_le_bytes());
        sym.extend_from_slice(&TEXT_VA.to_le_bytes());
        sym.extend_from_slice(&(text.len() as u64).to_le_bytes());
        symtab.extend_from_slice(&sym);

        let mut buf: Vec<u8> = vec![0u8; shoff as usize];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&TEXT_VA.to_le_bytes());
        buf[40..48].copy_from_slice(&shoff.to_le_bytes());
        buf[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes());
        buf[58..60].copy_from_slice(&shentsize.to_le_bytes());
        buf[60..62].copy_from_slice(&6u16.to_le_bytes());
        buf[62..64].copy_from_slice(&3u16.to_le_bytes());

        buf[text_off as usize..text_off as usize + text.len()].copy_from_slice(text);
        buf[data_off as usize..data_off as usize + data.len()].copy_from_slice(data);
        buf[shstr_off as usize..shstr_off as usize + shstrtab.len()].copy_from_slice(&shstrtab);
        buf[symtab_off as usize..symtab_off as usize + symtab.len()].copy_from_slice(&symtab);
        buf[strtab_off as usize..strtab_off as usize + strtab.len()].copy_from_slice(&strtab);

        let shf_write: u64 = 0x1;
        let shf_alloc: u64 = 0x2;
        let shf_execinstr: u64 = 0x4;
        let mut headers: Vec<u8> = Vec::new();
        headers.extend_from_slice(&[0u8; 64]);
        headers.extend_from_slice(&section_header(
            name_text,
            1,
            shf_alloc | shf_execinstr,
            TEXT_VA,
            text_off,
            text.len() as u64,
            0,
            0,
            16,
            0,
        ));
        headers.extend_from_slice(&section_header(
            name_data,
            1,
            shf_alloc | shf_write,
            DATA_VA,
            data_off,
            data.len() as u64,
            0,
            0,
            16,
            0,
        ));
        headers.extend_from_slice(&section_header(
            name_shstr,
            3,
            0,
            0,
            shstr_off,
            shstrtab.len() as u64,
            0,
            0,
            1,
            0,
        ));
        headers.extend_from_slice(&section_header(
            name_symtab,
            2,
            0,
            0,
            symtab_off,
            sym_count * sym_entsize,
            5,
            1,
            8,
            sym_entsize,
        ));
        headers.extend_from_slice(&section_header(
            name_strtab,
            3,
            0,
            0,
            strtab_off,
            strtab.len() as u64,
            0,
            0,
            1,
            0,
        ));
        buf.extend_from_slice(&headers);
        buf
    }

    #[allow(clippy::too_many_arguments)]
    fn section_header(
        name: u32,
        sh_type: u32,
        flags: u64,
        addr: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        align: u64,
        entsize: u64,
    ) -> [u8; 64] {
        let mut h: [u8; 64] = [0u8; 64];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&sh_type.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&addr.to_le_bytes());
        h[24..32].copy_from_slice(&offset.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..44].copy_from_slice(&link.to_le_bytes());
        h[44..48].copy_from_slice(&info.to_le_bytes());
        h[48..56].copy_from_slice(&align.to_le_bytes());
        h[56..64].copy_from_slice(&entsize.to_le_bytes());
        h
    }

    fn build_strtab(names: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for name in names {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        out
    }

    fn strtab_offset(table: &[u8], name: &str) -> u32 {
        let needle: Vec<u8> = {
            let mut v: Vec<u8> = Vec::with_capacity(name.len() + 2);
            v.push(0);
            v.extend_from_slice(name.as_bytes());
            v.push(0);
            v
        };
        windows_find(table, &needle).map_or(0, |pos: usize| (pos + 1) as u32)
    }

    fn windows_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|w: &[u8]| w == needle)
    }

    const fn align_up(value: u64, align: u64) -> u64 {
        (value + align - 1) & !(align - 1)
    }

    fn sysv64_xor_decoder() -> Vec<u8> {
        let plain_len: u8 = PLAINTEXT.len() as u8;
        let key_disp: u8 = PLAINTEXT.len() as u8;
        vec![
            0x45, 0x31, 0xC0, 0x49, 0x83, 0xF8, plain_len, 0x7D, 0x1F, 0x44, 0x89, 0xC0, 0x83,
            0xE0, 0x03, 0x48, 0x98, 0x42, 0x0F, 0xB6, 0x14, 0x07, 0x44, 0x0F, 0xB6, 0x4C, 0x07,
            key_disp, 0x44, 0x31, 0xCA, 0x42, 0x88, 0x14, 0x06, 0x49, 0xFF, 0xC0, 0xEB, 0xDB, 0xC3,
        ]
    }

    const ADD_PLAINTEXT: &[u8] = b"runtime-computed-secret-token-9000";
    const ADD_KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    fn multibyte_add(plain: &[u8], key: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b.wrapping_add(key[i % key.len()]))
            .collect()
    }

    fn elf_with_multibyte_sub_decoder() -> Vec<u8> {
        let code: Vec<u8> = sysv64_sub_decoder();
        let mut data: Vec<u8> = multibyte_add(ADD_PLAINTEXT, &ADD_KEY);
        data.extend_from_slice(&ADD_KEY);
        build_elf64_exec(&code, &data, "unscramble")
    }

    /// System V x86-64 `unscramble(rdi=enc, rsi=out, rdx=len)` that writes `out[i] = enc[i] - key[i & 3]` (wrapping), with the 4-byte key at `enc + len`.
    fn sysv64_sub_decoder() -> Vec<u8> {
        let plain_len: u8 = ADD_PLAINTEXT.len() as u8;
        let key_disp: u8 = ADD_PLAINTEXT.len() as u8;
        vec![
            0x45, 0x31, 0xC0, 0x49, 0x83, 0xF8, plain_len, 0x7D, 0x1F, 0x44, 0x89, 0xC0, 0x83,
            0xE0, 0x03, 0x48, 0x98, 0x42, 0x0F, 0xB6, 0x14, 0x07, 0x44, 0x0F, 0xB6, 0x4C, 0x07,
            key_disp, 0x44, 0x28, 0xCA, 0x42, 0x88, 0x14, 0x06, 0x49, 0xFF, 0xC0, 0xEB, 0xDB, 0xC3,
        ]
    }

    #[test]
    fn emulation_recovers_multibyte_sub_plaintext() {
        let elf: Vec<u8> = elf_with_multibyte_sub_decoder();
        let recovered: Vec<EmulatedString> = emulate_string_decoders(&elf);
        let expected: &str = std::str::from_utf8(ADD_PLAINTEXT).expect("ascii");
        assert!(
            recovered
                .iter()
                .any(|s: &EmulatedString| s.value == expected),
            "emulation must recover the exact multi-byte sub-cipher plaintext {expected:?}; got {:?}",
            recovered
                .iter()
                .map(|s: &EmulatedString| s.value.clone())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn emulation_recovers_multibyte_xor_plaintext() {
        let elf: Vec<u8> = elf_with_multibyte_xor_decoder();
        let recovered: Vec<EmulatedString> = emulate_string_decoders(&elf);
        let expected: &str = std::str::from_utf8(PLAINTEXT).expect("ascii");
        assert!(
            recovered
                .iter()
                .any(|s: &EmulatedString| s.value == expected),
            "emulation must recover the exact multi-byte-xor plaintext {expected:?}; got {:?}",
            recovered
                .iter()
                .map(|s: &EmulatedString| s.value.clone())
                .collect::<Vec<String>>()
        );
        let hit: &EmulatedString = recovered
            .iter()
            .find(|s: &&EmulatedString| s.value == expected)
            .expect("recovered hit present");
        assert!(
            hit.decoder_address != 0,
            "the recovered string must be tagged with the decoder function address"
        );
    }

    #[test]
    fn static_single_byte_xor_does_not_recover_multibyte_plaintext() {
        let encoded: Vec<u8> = multibyte_xor(PLAINTEXT, &XOR_KEY);
        let static_hits: Vec<crate::obfuscators::XorStringHit> =
            recover_single_byte_xor_strings(&encoded);
        let expected: &str = std::str::from_utf8(PLAINTEXT).expect("ascii");
        assert!(
            !static_hits
                .iter()
                .any(|h: &crate::obfuscators::XorStringHit| h.recovered.contains(expected)),
            "the static single-byte-xor path must NOT recover the multi-byte-key plaintext; \
             emulation is the differential capability. static produced {static_hits:?}"
        );
    }

    #[test]
    fn emulation_beats_static_on_the_same_input() {
        let elf: Vec<u8> = elf_with_multibyte_xor_decoder();
        let encoded: Vec<u8> = multibyte_xor(PLAINTEXT, &XOR_KEY);
        let expected: &str = std::str::from_utf8(PLAINTEXT).expect("ascii");

        let emu_recovered: bool = emulate_string_decoders(&elf)
            .iter()
            .any(|s: &EmulatedString| s.value == expected);
        let static_recovered: bool = recover_single_byte_xor_strings(&encoded)
            .iter()
            .any(|h: &crate::obfuscators::XorStringHit| h.recovered.contains(expected));

        assert!(
            emu_recovered && !static_recovered,
            "differential broken: emulation={emu_recovered} static={static_recovered} \
             (emulation must add value the static path cannot)"
        );
    }

    #[test]
    fn no_decoder_no_candidates() {
        let flat: Vec<u8> = vec![0x90, 0x90, 0x90, 0xC3];
        let elf: Vec<u8> = build_elf64_exec(&flat, b"plain ascii payload here", "noop");
        let recovered: Vec<EmulatedString> = emulate_string_decoders(&elf);
        assert!(
            recovered.is_empty(),
            "a flat nop/ret body must not be mistaken for a decoder: {recovered:?}"
        );
    }

    fn wide_bytes(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(s.len() * 2);
        for b in s.bytes() {
            out.push(b);
            out.push(0);
        }
        out
    }

    fn log_from(base: u64, bytes: &[u8]) -> Vec<(u64, u8)> {
        bytes
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| (base.wrapping_add(i as u64), *b))
            .collect()
    }

    #[test]
    fn utf16_recovered_at_even_alignment() {
        let log: Vec<(u64, u8)> = log_from(0x2000_0000, &wide_bytes("alphaBETAgamma"));
        let harvested: Vec<(u64, String)> = harvest_write_log(&log);
        assert!(
            harvested
                .iter()
                .any(|(_, v): &(u64, String)| v == "alphaBETAgamma"),
            "even-aligned UTF-16LE run must be recovered: {harvested:?}"
        );
    }

    #[test]
    fn utf16_recovered_at_odd_alignment() {
        let mut region: Vec<u8> = vec![b'Z'];
        region.extend(wide_bytes("realWIDEstr0"));
        let log: Vec<(u64, u8)> = log_from(0x2000_0000, &region);
        let harvested: Vec<(u64, String)> = harvest_write_log(&log);
        assert!(
            harvested
                .iter()
                .any(|(_, v): &(u64, String)| v == "realWIDEstr0"),
            "a UTF-16LE run beginning at an odd offset must be recovered: {harvested:?}"
        );
    }

    #[test]
    fn utf16_transient_and_surviving_both_recovered() {
        let mut log: Vec<(u64, u8)> = log_from(0x3000_0000, &wide_bytes("firsttransient"));
        log.extend(log_from(0x3000_0000, &wide_bytes("secondsurvivor")));
        let harvested: Vec<(u64, String)> = harvest_write_log(&log);
        assert!(
            harvested
                .iter()
                .any(|(_, v): &(u64, String)| v == "firsttransient"),
            "an overwritten (transient) wide string must survive via the write-log: {harvested:?}"
        );
        assert!(
            harvested
                .iter()
                .any(|(_, v): &(u64, String)| v == "secondsurvivor"),
            "the surviving wide string must be recovered: {harvested:?}"
        );
    }

    #[test]
    fn ascii_run_is_not_misread_as_utf16() {
        let log: Vec<(u64, u8)> = log_from(0x4000_0000, b"plainasciihere");
        let harvested: Vec<(u64, String)> = harvest_write_log(&log);
        assert!(
            harvested
                .iter()
                .any(|(_, v): &(u64, String)| v == "plainasciihere"),
            "the ASCII run must be recovered by the ascii path: {harvested:?}"
        );
        let misread: String = "plainasciihere".chars().step_by(2).collect();
        assert!(
            !harvested.iter().any(|(_, v): &(u64, String)| *v == misread),
            "ASCII data must not be misread as UTF-16 ({misread:?}): {harvested:?}"
        );
    }

    #[test]
    fn utf16_run_below_minimum_is_rejected() {
        let log: Vec<(u64, u8)> = log_from(0x5000_0000, &wide_bytes("ab"));
        let harvested: Vec<(u64, String)> = harvest_write_log(&log);
        assert!(
            !harvested.iter().any(|(_, v): &(u64, String)| v == "ab"),
            "a run shorter than the {MIN_WIDE_CHARS}-char floor must be rejected: {harvested:?}"
        );
    }

    #[test]
    fn merge_prefers_longer_wide_on_overlap() {
        let ascii: Vec<Harvest> = vec![Harvest {
            start: 0x1000,
            span: 4,
            value: "shrt".to_owned(),
        }];
        let wide: Vec<Harvest> = vec![Harvest {
            start: 0x1000,
            span: 16,
            value: "longerwidevalue".to_owned(),
        }];
        let merged: Vec<(u64, String)> = merge_harvests(ascii, wide);
        assert!(
            merged
                .iter()
                .any(|(_, v): &(u64, String)| v == "longerwidevalue"),
            "the longer/higher-confidence interpretation must win: {merged:?}"
        );
        assert!(
            !merged.iter().any(|(_, v): &(u64, String)| v == "shrt"),
            "the shorter overlapping interpretation must be dropped: {merged:?}"
        );
    }

    #[test]
    fn merge_prefers_longer_ascii_over_shorter_wide() {
        let ascii: Vec<Harvest> = vec![Harvest {
            start: 0x1000,
            span: 20,
            value: "longasciistring12345".to_owned(),
        }];
        let wide: Vec<Harvest> = vec![Harvest {
            start: 0x1000,
            span: 8,
            value: "wide".to_owned(),
        }];
        let merged: Vec<(u64, String)> = merge_harvests(ascii, wide);
        assert!(
            merged
                .iter()
                .any(|(_, v): &(u64, String)| v == "longasciistring12345"),
            "the longer ascii interpretation must win over a shorter overlapping wide: {merged:?}"
        );
        assert!(
            !merged.iter().any(|(_, v): &(u64, String)| v == "wide"),
            "the dominated shorter wide must be dropped: {merged:?}"
        );
    }

    #[test]
    fn merge_keeps_disjoint_candidates() {
        let ascii: Vec<Harvest> = vec![Harvest {
            start: 0x1000,
            span: 4,
            value: "asci".to_owned(),
        }];
        let wide: Vec<Harvest> = vec![Harvest {
            start: 0x2000,
            span: 8,
            value: "wide".to_owned(),
        }];
        let merged: Vec<(u64, String)> = merge_harvests(ascii, wide);
        assert_eq!(
            merged.len(),
            2,
            "disjoint ascii and wide candidates must both survive: {merged:?}"
        );
    }

    const _STEP_CAP_BOUNDED: () = assert!(PER_CANDIDATE_STEP_CAP <= 1_000_000);
    const _CANDIDATE_COUNT_BOUNDED: () = assert!(MAX_CANDIDATES <= 256);
    const _BUFFER_SPAN_BOUNDED: () = assert!(MAX_DECODE_SPAN <= 1024 * 1024);
}
