#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::binary::GoImage;
use crate::symbols::GoSymbols;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThunkRecovery {
    pub(crate) plaintext: String,
    pub(crate) thunk_va: u64,
    pub(crate) data_va: u64,
}

const MIN_PLAINTEXT: usize = 8;
const MAX_STEPS: usize = 200_000;
const MAX_THUNK_BYTES: usize = 64 << 10;
const THUNK_SCAN_BUDGET: Duration = Duration::from_secs(8);
const THUNK_SCAN_CHECK_STRIDE: usize = 4096;

fn scan_deadline_hit(start: Instant, processed: usize) -> bool {
    processed.is_multiple_of(THUNK_SCAN_CHECK_STRIDE) && start.elapsed() > THUNK_SCAN_BUDGET
}

struct TextView<'a> {
    base: u64,
    end: u64,
    data: &'a [u8],
}

fn text_views<'a>(image: &GoImage<'a>) -> Vec<TextView<'a>> {
    image
        .sections
        .iter()
        .filter(|s: &&crate::binary::Section<'a>| matches!(s.name.as_str(), ".text" | "__text"))
        .map(|s: &crate::binary::Section<'a>| TextView {
            base: s.address,
            end: s.address.wrapping_add(s.data.len() as u64),
            data: s.data,
        })
        .collect()
}

fn rodata_ranges(image: &GoImage<'_>) -> Vec<(u64, u64)> {
    image
        .sections
        .iter()
        .filter(|s: &&crate::binary::Section<'_>| {
            matches!(
                s.name.as_str(),
                ".rdata" | ".rodata" | "__rodata" | "__const" | ".data.rel.ro"
            )
        })
        .map(|s: &crate::binary::Section<'_>| {
            (s.address, s.address.wrapping_add(s.data.len() as u64))
        })
        .collect()
}

fn flat_text_view<'a>(
    image: &GoImage<'a>,
    spans: &[FuncSpan],
) -> Option<(TextView<'a>, (u64, u64))> {
    let section: &crate::binary::Section<'a> = image.sections.first()?;
    let base: u64 = section.address;
    let end: u64 = base.wrapping_add(section.data.len() as u64);
    let lo: u64 = spans.iter().map(|s: &FuncSpan| s.va).min()?;
    let hi: u64 = spans.iter().map(|s: &FuncSpan| s.end_va).max()?;
    if lo < base || hi > end || lo >= hi {
        return None;
    }
    let view: TextView<'a> = TextView {
        base,
        end,
        data: section.data,
    };
    Some((view, (lo, hi)))
}

fn flat_rodata_ranges(base: u64, end: u64, text: (u64, u64)) -> Vec<(u64, u64)> {
    let (text_lo, text_hi): (u64, u64) = text;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    if base < text_lo {
        ranges.push((base, text_lo));
    }
    if text_hi < end {
        ranges.push((text_hi, end));
    }
    ranges
}

const fn func_va(entry: u64, text_base: u64) -> u64 {
    if entry < text_base {
        entry.wrapping_add(text_base)
    } else {
        entry
    }
}

#[derive(Debug, Clone, Copy)]
struct FuncSpan {
    va: u64,
    end_va: u64,
}

fn func_spans(syms: &GoSymbols, text_base: u64) -> Vec<FuncSpan> {
    let mut spans: Vec<FuncSpan> = syms
        .funcs
        .iter()
        .map(|f: &crate::symbols::GoFunc| FuncSpan {
            va: func_va(f.entry, text_base),
            end_va: func_va(f.end, text_base),
        })
        .collect();
    spans.sort_by_key(|s: &FuncSpan| s.va);
    spans
}

fn runtime_name_at(syms: &GoSymbols, text_base: u64, va: u64) -> Option<&str> {
    syms.funcs
        .iter()
        .find(|f: &&crate::symbols::GoFunc| func_va(f.entry, text_base) == va)
        .map(|f: &crate::symbols::GoFunc| f.name.as_str())
}

fn func_end_at(syms: &GoSymbols, text_base: u64, va: u64) -> Option<u64> {
    syms.funcs
        .iter()
        .find(|f: &&crate::symbols::GoFunc| func_va(f.entry, text_base) == va)
        .map(|f: &crate::symbols::GoFunc| func_va(f.end, text_base))
}

const NON_USER_PREFIXES: [&str; 5] = ["runtime.", "internal/", "type:", "go:", "reflect."];

fn is_garble_closure_name(name: &str) -> bool {
    if NON_USER_PREFIXES.iter().any(|p: &&str| name.starts_with(p)) {
        return false;
    }
    let head: &str = name.split('.').next().unwrap_or(name);
    let first_seg: &str = head.split('/').next().unwrap_or(head);
    let root: &str = head.rsplit('/').next().unwrap_or(head);
    !STDLIB_CLOSURE_ROOTS.contains(&first_seg) && !STDLIB_CLOSURE_ROOTS.contains(&root)
}

const STDLIB_CLOSURE_ROOTS: &[&str] = &[
    "runtime",
    "internal",
    "sync",
    "syscall",
    "reflect",
    "unicode",
    "encoding",
    "errors",
    "io",
    "os",
    "fmt",
    "strconv",
    "strings",
    "sort",
    "bytes",
    "bufio",
    "context",
    "time",
    "math",
    "crypto",
    "net",
    "path",
    "hash",
    "compress",
    "html",
    "regexp",
    "text",
    "container",
    "embed",
    "iter",
    "slices",
    "maps",
    "cmp",
    "vendor",
];

#[must_use]
pub(crate) fn recover_thunk_literals(image: &GoImage<'_>, syms: &GoSymbols) -> Vec<ThunkRecovery> {
    if image.ptr_size != 8 {
        return Vec::new();
    }
    let (text, rodata, text_base): (Vec<TextView<'_>>, Vec<(u64, u64)>, u64) = if image.flat {
        let Some(section): Option<&crate::binary::Section<'_>> = image.sections.first() else {
            return Vec::new();
        };
        let probe_spans: Vec<FuncSpan> = func_spans(syms, section.address);
        let Some((view, text_range)): Option<(TextView<'_>, (u64, u64))> =
            flat_text_view(image, &probe_spans)
        else {
            return Vec::new();
        };
        let base: u64 = view.base;
        let rodata: Vec<(u64, u64)> = flat_rodata_ranges(view.base, view.end, text_range);
        (vec![view], rodata, base)
    } else {
        let text: Vec<TextView<'_>> = text_views(image);
        let Some(first): Option<&TextView<'_>> = text.first() else {
            return Vec::new();
        };
        let text_base: u64 = first.base;
        let rodata: Vec<(u64, u64)> = rodata_ranges(image);
        (text, rodata, text_base)
    };
    if rodata.is_empty() {
        return Vec::new();
    }
    let spans: Vec<FuncSpan> = func_spans(syms, text_base);
    let callers: BTreeMap<u64, Vec<FuncSpan>> = build_caller_index(&text, &spans);

    let mut out: Vec<ThunkRecovery> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let scan_start: Instant = Instant::now();
    let mut processed: usize = 0;
    for span in &spans {
        processed += 1;
        if scan_deadline_hit(scan_start, processed) {
            break;
        }
        if function_is_decrypt_thunk(image, &text, &rodata, span, syms, text_base) {
            let thunk_callers: Vec<FuncSpan> = callers.get(&span.va).cloned().unwrap_or_default();
            for rec in emulate_thunk(image, &text, &rodata, syms, text_base, span, &thunk_callers) {
                if seen.insert(rec.plaintext.clone()) {
                    out.push(rec);
                }
            }
        }
        if function_hosts_inline_literals(&text, span, syms, text_base) {
            for rec in recover_inline_literals(image, &text, &rodata, syms, text_base, span) {
                if seen.insert(rec.plaintext.clone()) {
                    out.push(rec);
                }
            }
        }
    }
    out.sort_by(|a: &ThunkRecovery, b: &ThunkRecovery| a.plaintext.cmp(&b.plaintext));
    out
}

fn view_for<'a, 'b>(text: &'b [TextView<'a>], va: u64) -> Option<&'b TextView<'a>> {
    text.iter()
        .find(|v: &&TextView<'a>| va >= v.base && va < v.end)
}

fn slice_for<'a>(text: &[TextView<'a>], start: u64, end: u64) -> Option<(&'a [u8], u64)> {
    let v: &TextView<'a> = view_for(text, start)?;
    let off: usize = usize::try_from(start - v.base).ok()?;
    if off >= v.data.len() {
        return None;
    }
    let span_end: usize = usize::try_from(end.saturating_sub(start))
        .unwrap_or(MAX_THUNK_BYTES)
        .min(v.data.len() - off)
        .min(MAX_THUNK_BYTES);
    Some((&v.data[off..off + span_end], start))
}

fn in_rodata(rodata: &[(u64, u64)], va: u64) -> bool {
    rodata.iter().any(|(a, b): &(u64, u64)| va >= *a && va < *b)
}

fn function_is_decrypt_thunk(
    image: &GoImage<'_>,
    text: &[TextView<'_>],
    rodata: &[(u64, u64)],
    span: &FuncSpan,
    syms: &GoSymbols,
    text_base: u64,
) -> bool {
    let Some((code, ip)): Option<(&[u8], u64)> = slice_for(text, span.va, span.end_va) else {
        return false;
    };
    if code.len() < 16 {
        return false;
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut blob_ptr_from_rodata: bool = false;
    let mut byte_movzx: usize = 0;
    let mut byte_alu: usize = 0;
    let mut newobject: usize = 0;
    let mut makeslice: usize = 0;
    let mut indirect_calls_with_imm: usize = 0;
    let mut jump_table: bool = false;
    let mut pending_imm: bool = false;
    let _ = MIN_PLAINTEXT;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_ip_rel_memory_operand() {
            let target: u64 = insn.ip_rel_memory_address();
            if in_rodata(rodata, target)
                && matches!(
                    insn.mnemonic(),
                    Mnemonic::Lea
                        | Mnemonic::Movups
                        | Mnemonic::Movdqu
                        | Mnemonic::Movaps
                        | Mnemonic::Movdqa
                        | Mnemonic::Mov
                )
                && rodata_blob_is_ciphertext(image, target)
            {
                blob_ptr_from_rodata = true;
            }
        }
        if insn.mnemonic() == Mnemonic::Movzx
            && (0..insn.op_count()).any(|i: u32| {
                matches!(insn.op_kind(i), OpKind::Memory) && insn.memory_size().size() == 1
            })
        {
            byte_movzx += 1;
        }
        if matches!(
            insn.mnemonic(),
            Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub
        ) {
            byte_alu += 1;
        }
        if insn.mnemonic() == Mnemonic::Mov
            && insn.op0_kind() == OpKind::Register
            && matches!(
                insn.op1_kind(),
                OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate32to64
            )
        {
            pending_imm = true;
        }
        if insn.mnemonic() == Mnemonic::Jmp
            && insn.op0_kind() == OpKind::Memory
            && insn.memory_index() != Register::None
            && insn.memory_index_scale() == 8
        {
            jump_table = true;
        }
        if insn.mnemonic() == Mnemonic::Call {
            match insn.op0_kind() {
                OpKind::NearBranch64 => {
                    let target: u64 = insn.near_branch64();
                    match runtime_name_at(syms, text_base, target) {
                        Some("runtime.newobject") => newobject += 1,
                        Some(n) if n.contains("makeslice") => makeslice += 1,
                        _ => {}
                    }
                }
                OpKind::Register | OpKind::Memory if pending_imm => indirect_calls_with_imm += 1,
                _ => {}
            }
            pending_imm = false;
        }
    }
    let blob_loop: bool = blob_ptr_from_rodata && byte_movzx >= 4 && byte_alu >= 4;
    let seed_chain: bool = newobject >= 1 && indirect_calls_with_imm >= 4 && byte_alu >= 2;
    let split_switch: bool = makeslice >= 1 && jump_table && byte_alu >= 4;
    blob_loop || seed_chain || split_switch
}

fn rodata_blob_is_ciphertext(image: &GoImage<'_>, va: u64) -> bool {
    let Some(bytes): Option<&[u8]> = image.data_at_va(va, 16) else {
        return false;
    };
    let nonascii: usize = bytes.iter().filter(|b: &&u8| !b.is_ascii()).count();
    nonascii >= 3
}

const INLINE_HOST_MIN_MOVZX: usize = 16;
const INLINE_HOST_MIN_ALLOC: usize = 1;
const INLINE_HOST_MIN_USER_CALLS: usize = 3;

fn function_hosts_inline_literals(
    text: &[TextView<'_>],
    span: &FuncSpan,
    syms: &GoSymbols,
    text_base: u64,
) -> bool {
    let Some((code, ip)): Option<(&[u8], u64)> = slice_for(text, span.va, span.end_va) else {
        return false;
    };
    if code.len() < 64 {
        return false;
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut byte_movzx: usize = 0;
    let mut allocs: usize = 0;
    let mut user_calls: usize = 0;
    let mut indirect_calls: usize = 0;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.mnemonic() == Mnemonic::Movzx
            && (0..insn.op_count()).any(|i: u32| {
                matches!(insn.op_kind(i), OpKind::Memory) && insn.memory_size().size() == 1
            })
        {
            byte_movzx += 1;
        }
        if insn.mnemonic() == Mnemonic::Call {
            match insn.op0_kind() {
                OpKind::NearBranch64 => {
                    let target: u64 = insn.near_branch64();
                    match runtime_name_at(syms, text_base, target) {
                        Some(n)
                            if n == "runtime.newobject"
                                || n == "runtime.newarray"
                                || n.contains("makeslice")
                                || n.starts_with("runtime.growslice") =>
                        {
                            allocs += 1;
                        }
                        Some(n) if is_garble_closure_name(n) => user_calls += 1,
                        None => user_calls += 1,
                        _ => {}
                    }
                }
                OpKind::Register | OpKind::Memory => indirect_calls += 1,
                _ => {}
            }
        }
    }
    let _ = indirect_calls;
    byte_movzx >= INLINE_HOST_MIN_MOVZX
        && allocs >= INLINE_HOST_MIN_ALLOC
        && user_calls >= INLINE_HOST_MIN_USER_CALLS
}

fn recover_inline_literals(
    image: &GoImage<'_>,
    text: &[TextView<'_>],
    rodata: &[(u64, u64)],
    syms: &GoSymbols,
    text_base: u64,
    span: &FuncSpan,
) -> Vec<ThunkRecovery> {
    let mut emu: Emu<'_, '_> = Emu {
        image,
        text,
        rodata,
        syms,
        text_base,
        regs: BTreeMap::new(),
        mem: BTreeMap::new(),
        fake_heap: FAKE_HEAP_BASE,
        flags: Flags::default(),
        call_depth: 0,
        step_budget: GLOBAL_STEP_BUDGET,
        consumer_args: Vec::new(),
        collect_consumer_args: true,
        suppress_follow: false,
        decrypted_spans: Vec::new(),
    };
    emu.reset_frame();
    let mut sink: u64 = 0;
    emu.run_block(span.va, span.end_va, None, &mut sink);

    let mut out: Vec<ThunkRecovery> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut precise: Vec<String> = Vec::new();

    for (ptr, len) in std::mem::take(&mut emu.decrypted_spans) {
        let bytes: Vec<u8> = (0..len)
            .map(|i: u64| *emu.mem.get(&(ptr + i)).unwrap_or(&0))
            .collect();
        let Ok(s): Result<&str, _> = std::str::from_utf8(&bytes) else {
            continue;
        };
        if readability_score(s) < MIN_HARVEST_SCORE || s.len() < MIN_INLINE_PLAINTEXT {
            continue;
        }
        if seen.insert(s.to_owned()) {
            precise.push(s.to_owned());
            out.push(ThunkRecovery {
                plaintext: s.to_owned(),
                thunk_va: span.va,
                data_va: ptr,
            });
        }
    }

    for (ptr, len) in std::mem::take(&mut emu.consumer_args) {
        let bytes: Vec<u8> = (0..len)
            .map(|i: u64| *emu.mem.get(&(ptr + i)).unwrap_or(&0))
            .collect();
        let Ok(s): Result<&str, _> = std::str::from_utf8(&bytes) else {
            continue;
        };
        if readability_score(s) < MIN_HARVEST_SCORE {
            continue;
        }
        if s.len() < MIN_INLINE_PLAINTEXT
            || seen.iter().any(|k: &String| k.contains(s))
            || precise.iter().any(|p: &String| s.contains(p.as_str()))
        {
            continue;
        }
        if seen.insert(s.to_owned()) {
            out.push(ThunkRecovery {
                plaintext: s.to_owned(),
                thunk_va: span.va,
                data_va: ptr,
            });
        }
    }

    for run in contiguous_text_runs(&emu) {
        let candidates: [Vec<u8>; 2] = [run.clone(), reversed(&run)];
        for cand in candidates {
            let Ok(s): Result<&str, _> = std::str::from_utf8(&cand) else {
                continue;
            };
            if readability_score(s) < MIN_HARVEST_SCORE {
                continue;
            }
            let trimmed: &str = trim_junk(s);
            if trimmed.len() < MIN_INLINE_PLAINTEXT
                || seen.iter().any(|k: &String| k.contains(trimmed))
                || precise
                    .iter()
                    .any(|p: &String| trimmed.contains(p.as_str()))
                || !seen.insert(trimmed.to_owned())
            {
                continue;
            }
            out.push(ThunkRecovery {
                plaintext: trimmed.to_owned(),
                thunk_va: span.va,
                data_va: 0,
            });
        }
    }
    out
}

const MIN_INLINE_PLAINTEXT: usize = 12;

const MAX_CALLERS_PER_THUNK: usize = 4;

fn build_caller_index(text: &[TextView<'_>], spans: &[FuncSpan]) -> BTreeMap<u64, Vec<FuncSpan>> {
    let mut index: BTreeMap<u64, Vec<FuncSpan>> = BTreeMap::new();
    for span in spans {
        let Some((code, ip)): Option<(&[u8], u64)> = slice_for(text, span.va, span.end_va) else {
            continue;
        };
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
        let mut insn: Instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut insn);
            if insn.mnemonic() == Mnemonic::Call && insn.op0_kind() == OpKind::NearBranch64 {
                let target: u64 = insn.near_branch64();
                let callers: &mut Vec<FuncSpan> = index.entry(target).or_default();
                if callers.len() < MAX_CALLERS_PER_THUNK
                    && !callers.iter().any(|c: &FuncSpan| c.va == span.va)
                {
                    callers.push(*span);
                }
            }
        }
    }
    index
}

const ABI_INT_REGS: [Register; 9] = [
    Register::RAX,
    Register::RBX,
    Register::RCX,
    Register::RDI,
    Register::RSI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
}

struct Emu<'a, 'b> {
    image: &'a GoImage<'b>,
    text: &'a [TextView<'b>],
    rodata: &'a [(u64, u64)],
    syms: &'a GoSymbols,
    text_base: u64,
    regs: BTreeMap<Register, u64>,
    mem: BTreeMap<u64, u8>,
    fake_heap: u64,
    flags: Flags,
    call_depth: u32,
    step_budget: u64,
    consumer_args: Vec<(u64, u64)>,
    collect_consumer_args: bool,
    suppress_follow: bool,
    decrypted_spans: Vec<(u64, u64)>,
}

const STACK_BASE: u64 = 0x7000_0000_0000;
const FAKE_HEAP_BASE: u64 = 0x5000_0000_0000;
const RAM_LOW: u64 = 0x4000_0000_0000;
const RAM_HIGH: u64 = 0x8000_0000_0000;

fn full(r: Register) -> Register {
    if r == Register::None {
        Register::None
    } else {
        r.full_register()
    }
}

impl Emu<'_, '_> {
    fn reg(&self, r: Register) -> u64 {
        if r == Register::None {
            return 0;
        }
        let base: u64 = *self.regs.get(&full(r)).unwrap_or(&0);
        mask_to_size(base, r)
    }

    fn set_reg(&mut self, r: Register, val: u64) {
        if r == Register::None {
            return;
        }
        let f: Register = full(r);
        let size: usize = r.size();
        if size >= 4 {
            self.regs.insert(f, mask_to_size(val, r));
        } else {
            let old: u64 = *self.regs.get(&f).unwrap_or(&0);
            let masked: u64 = merge_sub(old, val, r);
            self.regs.insert(f, masked);
        }
    }

    fn is_ram(addr: u64) -> bool {
        (RAM_LOW..RAM_HIGH).contains(&addr)
    }

    fn read_mem(&self, addr: u64, size: usize) -> u64 {
        let size: usize = size.min(8);
        if Self::is_ram(addr) {
            let mut val: u64 = 0;
            for i in 0..size {
                let b: u8 = *self.mem.get(&(addr + i as u64)).unwrap_or(&0);
                val |= u64::from(b) << (8 * i);
            }
            return val;
        }
        if let Some(bytes) = self.image.data_at_va(addr, size) {
            let mut arr: [u8; 8] = [0u8; 8];
            arr[..size].copy_from_slice(&bytes[..size]);
            return u64::from_le_bytes(arr);
        }
        0
    }

    fn write_mem(&mut self, addr: u64, size: usize, val: u64) {
        if !Self::is_ram(addr) {
            return;
        }
        let size: usize = size.min(8);
        for i in 0..size {
            let a: u64 = addr.wrapping_add(i as u64);
            if self.mem.len() >= MAX_EMU_MEM_BYTES && !self.mem.contains_key(&a) {
                continue;
            }
            let b: u8 = ((val >> (8 * i)) & 0xff) as u8;
            self.mem.insert(a, b);
        }
    }

    fn mem_addr(&self, insn: &Instruction) -> u64 {
        if insn.is_ip_rel_memory_operand() {
            return insn.ip_rel_memory_address();
        }
        let base: u64 = self.reg(insn.memory_base());
        let index_reg: Register = insn.memory_index();
        let index: u64 = if index_reg == Register::None {
            0
        } else {
            self.reg(index_reg)
                .wrapping_mul(u64::from(insn.memory_index_scale()))
        };
        base.wrapping_add(index)
            .wrapping_add(insn.memory_displacement64())
    }
}

fn mask_to_size(val: u64, r: Register) -> u64 {
    match r.size() {
        1 => val & 0xff,
        2 => val & 0xffff,
        4 => val & 0xffff_ffff,
        _ => val,
    }
}

fn merge_sub(old: u64, val: u64, r: Register) -> u64 {
    match r.size() {
        1 => {
            if is_high_byte(r) {
                (old & !0xff00) | ((val & 0xff) << 8)
            } else {
                (old & !0xff) | (val & 0xff)
            }
        }
        2 => (old & !0xffff) | (val & 0xffff),
        _ => val,
    }
}

const fn is_high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::BH | Register::CH | Register::DH)
}

fn read_byte_of(emu: &Emu<'_, '_>, r: Register) -> u64 {
    if is_high_byte(r) {
        (emu.reg(full(r)) >> 8) & 0xff
    } else {
        emu.reg(r) & 0xff
    }
}

fn emulate_thunk(
    image: &GoImage<'_>,
    text: &[TextView<'_>],
    rodata: &[(u64, u64)],
    syms: &GoSymbols,
    text_base: u64,
    span: &FuncSpan,
    thunk_callers: &[FuncSpan],
) -> Vec<ThunkRecovery> {
    let attempts: Vec<Option<FuncSpan>> = if thunk_callers.is_empty() {
        vec![None]
    } else {
        thunk_callers.iter().map(|c: &FuncSpan| Some(*c)).collect()
    };

    let mut best: Option<(i64, Vec<String>, u64)> = None;
    for caller in attempts {
        let (plaintexts, data_va): (Vec<String>, u64) =
            run_one_attempt(image, text, rodata, syms, text_base, span, caller);
        if plaintexts.is_empty() {
            continue;
        }
        let score: i64 = plaintexts
            .iter()
            .map(|s: &String| readability_score(s).max(0))
            .sum();
        if best
            .as_ref()
            .is_none_or(|(b, _, _): &(i64, Vec<String>, u64)| score > *b)
        {
            best = Some((score, plaintexts, data_va));
        }
    }
    let Some((_, plaintexts, data_va)): Option<(i64, Vec<String>, u64)> = best else {
        return Vec::new();
    };
    plaintexts
        .into_iter()
        .map(|plaintext: String| ThunkRecovery {
            plaintext,
            thunk_va: span.va,
            data_va,
        })
        .collect()
}

fn run_one_attempt(
    image: &GoImage<'_>,
    text: &[TextView<'_>],
    rodata: &[(u64, u64)],
    syms: &GoSymbols,
    text_base: u64,
    span: &FuncSpan,
    caller: Option<FuncSpan>,
) -> (Vec<String>, u64) {
    let mut emu: Emu<'_, '_> = Emu {
        image,
        text,
        rodata,
        syms,
        text_base,
        regs: BTreeMap::new(),
        mem: BTreeMap::new(),
        fake_heap: FAKE_HEAP_BASE,
        flags: Flags::default(),
        call_depth: 0,
        step_budget: GLOBAL_STEP_BUDGET,
        consumer_args: Vec::new(),
        collect_consumer_args: false,
        suppress_follow: false,
        decrypted_spans: Vec::new(),
    };
    let mut data_va: u64 = 0;

    if let Some(caller) = caller {
        emu.reset_frame();
        emu.suppress_follow = true;
        let mut sink: u64 = 0;
        emu.run_block(caller.va, caller.end_va, Some(span.va), &mut sink);
        emu.suppress_follow = false;
    }

    let entry_regs: BTreeMap<Register, u64> = abi_pass_through(&emu.regs);
    emu.reset_frame();
    for (r, v) in entry_regs {
        emu.regs.insert(r, v);
    }

    emu.run_block(span.va, span.end_va, None, &mut data_va);

    (harvest_plaintext(&emu), data_va)
}

fn abi_pass_through(regs: &BTreeMap<Register, u64>) -> BTreeMap<Register, u64> {
    ABI_INT_REGS
        .iter()
        .filter_map(|r: &Register| regs.get(r).map(|v: &u64| (*r, *v)))
        .collect()
}

impl Emu<'_, '_> {
    fn reset_frame(&mut self) {
        self.mem.clear();
        self.decrypted_spans.clear();
        self.fake_heap = FAKE_HEAP_BASE;
        self.flags = Flags::default();
        self.regs.insert(Register::RSP, STACK_BASE);
        self.regs.insert(Register::RBP, STACK_BASE);
        self.regs.insert(Register::R14, STACK_BASE + 0x1000);
    }

    #[allow(clippy::too_many_lines)]
    fn run_block(&mut self, start: u64, end_va: u64, stop_call: Option<u64>, data_va: &mut u64) {
        let Some(view): Option<&TextView<'_>> = view_for(self.text, start) else {
            return;
        };
        let rodata: &[(u64, u64)] = self.rodata;
        let mut ip: u64 = start;
        let mut steps: usize = 0;
        let mut insn: Instruction = Instruction::default();
        while ip >= view.base && ip < view.end && ip < end_va && steps < MAX_STEPS {
            steps += 1;
            if self.step_budget == 0 {
                break;
            }
            self.step_budget -= 1;
            let Ok(off): Result<usize, _> = usize::try_from(ip - view.base) else {
                break;
            };
            if off >= view.data.len() {
                break;
            }
            let chunk: &[u8] = &view.data[off..view.data.len().min(off + 16)];
            let mut decoder: Decoder<'_> = Decoder::with_ip(64, chunk, ip, DecoderOptions::NONE);
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                break;
            }
            let next_ip: u64 = insn.next_ip();

            match insn.mnemonic() {
                Mnemonic::Push => {
                    let v: u64 = operand_value(self, &insn, 0);
                    let sp: u64 = self.reg(Register::RSP).wrapping_sub(8);
                    self.regs.insert(Register::RSP, sp);
                    self.write_mem(sp, 8, v);
                }
                Mnemonic::Pop => {
                    let sp: u64 = self.reg(Register::RSP);
                    let v: u64 = self.read_mem(sp, 8);
                    self.regs.insert(Register::RSP, sp.wrapping_add(8));
                    store_op0(self, &insn, v);
                }
                Mnemonic::Jmp if insn.op0_kind() == OpKind::NearBranch64 => {
                    ip = insn.near_branch64();
                    continue;
                }
                Mnemonic::Jmp if insn.op0_kind() == OpKind::Register => {
                    let target: u64 = self.reg(insn.op0_register());
                    if target >= view.base && target < view.end {
                        ip = target;
                        continue;
                    }
                    break;
                }
                Mnemonic::Jmp if insn.op0_kind() == OpKind::Memory => {
                    let addr: u64 = self.mem_addr(&insn);
                    let target: u64 = self.read_mem(addr, 8);
                    if target >= view.base && target < view.end {
                        ip = target;
                        continue;
                    }
                    break;
                }
                Mnemonic::Ret | Mnemonic::Jmp => break,
                Mnemonic::Je
                | Mnemonic::Jne
                | Mnemonic::Jae
                | Mnemonic::Jb
                | Mnemonic::Jbe
                | Mnemonic::Ja
                | Mnemonic::Jg
                | Mnemonic::Jge
                | Mnemonic::Jl
                | Mnemonic::Jle
                | Mnemonic::Js
                | Mnemonic::Jns
                | Mnemonic::Jo
                | Mnemonic::Jno
                    if insn.op0_kind() == OpKind::NearBranch64
                        && branch_taken(insn.mnemonic(), self.flags) =>
                {
                    ip = insn.near_branch64();
                    continue;
                }
                Mnemonic::Call if insn.op0_kind() == OpKind::NearBranch64 => {
                    let target: u64 = insn.near_branch64();
                    if stop_call == Some(target) {
                        return;
                    }
                    self.capture_decrypted_span(Some(target));
                    self.dispatch_call(target, true);
                }
                Mnemonic::Call if insn.op0_kind() == OpKind::Register => {
                    let target: u64 = self.reg(insn.op0_register());
                    self.capture_decrypted_span(None);
                    self.dispatch_call(target, false);
                }
                Mnemonic::Call if insn.op0_kind() == OpKind::Memory => {
                    let addr: u64 = self.mem_addr(&insn);
                    let target: u64 = self.read_mem(addr, 8);
                    self.capture_decrypted_span(None);
                    self.dispatch_call(target, false);
                }
                Mnemonic::Lea => {
                    let addr: u64 = self.mem_addr(&insn);
                    if in_rodata(rodata, addr) && *data_va == 0 {
                        *data_va = addr;
                    }
                    self.set_reg(insn.op0_register(), addr);
                }
                Mnemonic::Mov => exec_mov(self, &insn, rodata, data_va),
                Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => exec_movzx(self, &insn),
                Mnemonic::Movups | Mnemonic::Movdqu | Mnemonic::Movaps | Mnemonic::Movdqa => {
                    exec_movups(self, &insn, rodata, data_va);
                }
                Mnemonic::Xor => exec_alu(self, &insn, AluOp::Xor),
                Mnemonic::Add => exec_alu(self, &insn, AluOp::Add),
                Mnemonic::Sub => exec_alu(self, &insn, AluOp::Sub),
                Mnemonic::And => exec_alu(self, &insn, AluOp::And),
                Mnemonic::Or => exec_alu(self, &insn, AluOp::Or),
                Mnemonic::Imul => exec_imul(self, &insn),
                Mnemonic::Neg => {
                    let size: usize = op0_size(&insn);
                    let a: u64 = operand_value(self, &insn, 0);
                    let res: u64 = mask_bytes(0u64.wrapping_sub(a), size);
                    self.flags.cf = a != 0;
                    self.flags.zf = res == 0;
                    self.flags.sf = res & sign_bit(size) != 0;
                    store_op0(self, &insn, res);
                }
                Mnemonic::Not => {
                    let size: usize = op0_size(&insn);
                    let a: u64 = operand_value(self, &insn, 0);
                    store_op0(self, &insn, mask_bytes(!a, size));
                }
                Mnemonic::Shr => exec_shift(self, &insn, false),
                Mnemonic::Shl => exec_shift(self, &insn, true),
                Mnemonic::Xchg => exec_xchg(self, &insn),
                Mnemonic::Cmp => exec_cmp(self, &insn),
                Mnemonic::Test => exec_test(self, &insn),
                Mnemonic::Inc => {
                    let r: Register = insn.op0_register();
                    let size: usize = if r == Register::None { 8 } else { r.size() };
                    let v: u64 = mask_bytes(self.reg(r).wrapping_add(1), size);
                    self.flags.zf = v == 0;
                    self.flags.sf = v & sign_bit(size) != 0;
                    self.set_reg(r, v);
                }
                Mnemonic::Dec => {
                    let r: Register = insn.op0_register();
                    let size: usize = if r == Register::None { 8 } else { r.size() };
                    let v: u64 = mask_bytes(self.reg(r).wrapping_sub(1), size);
                    self.flags.zf = v == 0;
                    self.flags.sf = v & sign_bit(size) != 0;
                    self.set_reg(r, v);
                }
                _ => {}
            }
            ip = next_ip;
        }
    }
}

const FAKE_ALLOC_STRIDE: u64 = 0x2000;
const MAX_EMU_MEM_BYTES: usize = 8 * 1024 * 1024;
const MAX_NESTED_CALL_DEPTH: u32 = 96;
const GLOBAL_STEP_BUDGET: u64 = 6_000_000;
const MAX_INLINE_STRING: usize = 4096;

const CONSUMER_PTR_LEN_PAIRS: [(Register, Register); 4] = [
    (Register::RAX, Register::RBX),
    (Register::RBX, Register::RCX),
    (Register::RBX, Register::RAX),
    (Register::RDI, Register::RSI),
];

const SPAN_SCAN_REGS: [Register; 9] = ABI_INT_REGS;

const MIN_SPAN_PRINTABLE_PCT: u64 = 88;

impl Emu<'_, '_> {
    const fn fresh_heap(&mut self) -> u64 {
        if self.fake_heap.saturating_add(FAKE_ALLOC_STRIDE) >= RAM_HIGH {
            self.fake_heap = FAKE_HEAP_BASE;
        }
        let ptr: u64 = self.fake_heap;
        self.fake_heap += FAKE_ALLOC_STRIDE;
        ptr
    }

    fn span_is_printable(&self, ptr: u64, len: u64) -> bool {
        if len < MIN_PLAINTEXT as u64 || len > MAX_INLINE_STRING as u64 {
            return false;
        }
        let mut printable: u64 = 0;
        let mut present: u64 = 0;
        for i in 0..len {
            match self.mem.get(&(ptr + i)) {
                Some(&b) => {
                    present += 1;
                    if is_text_byte(b) {
                        printable += 1;
                    }
                }
                None => return false,
            }
        }
        present == len && printable * 100 >= len * MIN_SPAN_PRINTABLE_PCT
    }

    fn capture_decrypted_span(&mut self, direct_target: Option<u64>) {
        let materializer: bool = direct_target.is_none_or(|t: u64| {
            runtime_name_at(self.syms, self.text_base, t).is_some_and(is_string_materializer)
        });
        if !materializer {
            return;
        }
        for ptr_reg in SPAN_SCAN_REGS {
            let ptr: u64 = self.reg(ptr_reg);
            if !Self::is_ram(ptr) {
                continue;
            }
            for len_reg in SPAN_SCAN_REGS {
                if len_reg == ptr_reg {
                    continue;
                }
                let len: u64 = self.reg(len_reg);
                if self.span_is_printable(ptr, len) && !self.decrypted_spans.contains(&(ptr, len)) {
                    self.decrypted_spans.push((ptr, len));
                }
            }
        }
    }

    fn dispatch_call(&mut self, target: u64, is_direct: bool) {
        let name: Option<&str> = runtime_name_at(self.syms, self.text_base, target);
        match name {
            Some("runtime.makeslice" | "runtime.makeslicecopy") => {
                let ptr: u64 = self.fresh_heap();
                self.set_reg(Register::RAX, ptr);
                return;
            }
            Some("runtime.newobject" | "runtime.newarray") => {
                let ptr: u64 = self.fresh_heap();
                self.zero_fill(ptr, FAKE_ALLOC_STRIDE as usize);
                self.set_reg(Register::RAX, ptr);
                return;
            }
            Some(n) if n.starts_with("runtime.growslice") => {
                let old_ptr: u64 = self.reg(Register::RAX);
                let old_len: u64 = self.reg(Register::RBX);
                let ptr: u64 = self.fresh_heap();
                if Self::is_ram(old_ptr) {
                    for i in 0..old_len.min(FAKE_ALLOC_STRIDE) {
                        let b: u8 = *self.mem.get(&(old_ptr + i)).unwrap_or(&0);
                        self.mem.insert(ptr + i, b);
                    }
                }
                self.set_reg(Register::RAX, ptr);
                self.set_reg(Register::RBX, old_len);
                self.set_reg(Register::RCX, FAKE_ALLOC_STRIDE);
                return;
            }
            Some(n) if is_runtime_noop(n) => return,
            Some(n) if !is_garble_closure_name(n) => return,
            _ => {}
        }
        if self.suppress_follow {
            return;
        }
        if is_direct && self.collect_consumer_args && self.call_depth == 0 {
            self.snapshot_consumer_args();
            return;
        }
        let followed_into_user: bool = name.is_none_or(is_garble_closure_name);
        self.call_into_text(target);
        if self.collect_consumer_args && self.call_depth == 0 && followed_into_user {
            self.snapshot_consumer_args();
        }
    }

    fn snapshot_consumer_args(&mut self) {
        for (ptr_reg, len_reg) in CONSUMER_PTR_LEN_PAIRS {
            let ptr: u64 = self.reg(ptr_reg);
            let len: u64 = self.reg(len_reg);
            if Self::is_ram(ptr) && (MIN_PLAINTEXT as u64..=MAX_INLINE_STRING as u64).contains(&len)
            {
                self.consumer_args.push((ptr, len));
            }
        }
    }

    fn call_into_text(&mut self, target: u64) {
        if self.call_depth >= MAX_NESTED_CALL_DEPTH || self.step_budget == 0 {
            return;
        }
        if !self.target_is_followable_closure(target) {
            return;
        }
        let Some(end): Option<u64> = self.closure_end(target) else {
            return;
        };
        self.call_depth += 1;
        let mut sink: u64 = 0;
        self.run_block(target, end, None, &mut sink);
        self.call_depth -= 1;
    }

    fn target_is_followable_closure(&self, target: u64) -> bool {
        runtime_name_at(self.syms, self.text_base, target).map_or_else(
            || view_for(self.text, target).is_some(),
            is_garble_closure_name,
        )
    }

    fn closure_end(&self, target: u64) -> Option<u64> {
        if let Some(end) = func_end_at(self.syms, self.text_base, target) {
            return Some(end);
        }
        view_for(self.text, target).map(|v: &TextView<'_>| v.end)
    }

    fn zero_fill(&mut self, addr: u64, len: usize) {
        let remaining: usize = MAX_EMU_MEM_BYTES.saturating_sub(self.mem.len());
        for i in 0..len.min(remaining) as u64 {
            self.mem.insert(addr + i, 0);
        }
    }
}

fn is_string_materializer(name: &str) -> bool {
    matches!(
        name,
        "runtime.slicebytetostring"
            | "runtime.slicebytetostringtmp"
            | "runtime.convTstring"
            | "runtime.stringtoslicebyte"
    )
}

fn is_runtime_noop(name: &str) -> bool {
    matches!(
        name,
        "runtime.gcWriteBarrier"
            | "runtime.gcWriteBarrier1"
            | "runtime.gcWriteBarrier2"
            | "runtime.gcWriteBarrier3"
            | "runtime.gcWriteBarrier4"
            | "runtime.gcWriteBarrier5"
            | "runtime.gcWriteBarrier6"
            | "runtime.gcWriteBarrier7"
            | "runtime.gcWriteBarrier8"
            | "runtime.morestack"
            | "runtime.morestack_noctxt"
            | "runtime.stackcheck"
    )
}

enum AluOp {
    Xor,
    Add,
    Sub,
    And,
    Or,
}

const fn alu_apply(op: &AluOp, a: u64, b: u64) -> u64 {
    match op {
        AluOp::Xor => a ^ b,
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::And => a & b,
        AluOp::Or => a | b,
    }
}

fn operand_value(emu: &Emu<'_, '_>, insn: &Instruction, idx: u32) -> u64 {
    match insn.op_kind(idx) {
        OpKind::Register => {
            let r: Register = insn.op_register(idx);
            if r.size() == 1 {
                read_byte_of(emu, r)
            } else {
                emu.reg(r)
            }
        }
        OpKind::Memory => {
            let addr: u64 = emu.mem_addr(insn);
            let size: usize = insn.memory_size().size().max(1);
            emu.read_mem(addr, size)
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => insn.immediate(idx),
        _ => 0,
    }
}

fn store_op0(emu: &mut Emu<'_, '_>, insn: &Instruction, val: u64) {
    match insn.op0_kind() {
        OpKind::Register => emu.set_reg(insn.op0_register(), val),
        OpKind::Memory => {
            let addr: u64 = emu.mem_addr(insn);
            let size: usize = insn.memory_size().size().max(1);
            emu.write_mem(addr, size, val);
        }
        _ => {}
    }
}

fn exec_alu(emu: &mut Emu<'_, '_>, insn: &Instruction, op: AluOp) {
    let a: u64 = operand_value(emu, insn, 0);
    let b: u64 = operand_value(emu, insn, 1);
    let size: usize = op0_size(insn);
    let res: u64 = mask_bytes(alu_apply(&op, a, b), size);
    emu.flags = compute_flags(&op, a, b, res, size);
    store_op0(emu, insn, res);
}

const fn sign_bit(size: usize) -> u64 {
    match size {
        1 => 0x80,
        2 => 0x8000,
        4 => 0x8000_0000,
        _ => 0x8000_0000_0000_0000,
    }
}

const fn compute_flags(op: &AluOp, a: u64, b: u64, res: u64, size: usize) -> Flags {
    let sb: u64 = sign_bit(size);
    let zf: bool = res == 0;
    let sf: bool = res & sb != 0;
    let (cf, of): (bool, bool) = match op {
        AluOp::Add => {
            let cf: bool = res < a;
            let of: bool = ((a ^ res) & (b ^ res) & sb) != 0;
            (cf, of)
        }
        AluOp::Sub => {
            let cf: bool = a < b;
            let of: bool = ((a ^ b) & (a ^ res) & sb) != 0;
            (cf, of)
        }
        AluOp::Xor | AluOp::And | AluOp::Or => (false, false),
    };
    Flags { cf, zf, sf, of }
}

fn exec_cmp(emu: &mut Emu<'_, '_>, insn: &Instruction) {
    let a: u64 = operand_value(emu, insn, 0);
    let b: u64 = operand_value(emu, insn, 1);
    let size: usize = op0_size(insn);
    let res: u64 = mask_bytes(a.wrapping_sub(b), size);
    emu.flags = compute_flags(&AluOp::Sub, a, b, res, size);
}

fn exec_test(emu: &mut Emu<'_, '_>, insn: &Instruction) {
    let a: u64 = operand_value(emu, insn, 0);
    let b: u64 = operand_value(emu, insn, 1);
    let size: usize = op0_size(insn);
    let res: u64 = mask_bytes(a & b, size);
    emu.flags = compute_flags(&AluOp::And, a, b, res, size);
}

const fn branch_taken(mnem: Mnemonic, f: Flags) -> bool {
    match mnem {
        Mnemonic::Je => f.zf,
        Mnemonic::Jne => !f.zf,
        Mnemonic::Jb => f.cf,
        Mnemonic::Jae => !f.cf,
        Mnemonic::Jbe => f.cf || f.zf,
        Mnemonic::Ja => !f.cf && !f.zf,
        Mnemonic::Jl => f.sf != f.of,
        Mnemonic::Jge => f.sf == f.of,
        Mnemonic::Jle => f.zf || (f.sf != f.of),
        Mnemonic::Jg => !f.zf && (f.sf == f.of),
        Mnemonic::Js => f.sf,
        Mnemonic::Jns => !f.sf,
        Mnemonic::Jo => f.of,
        Mnemonic::Jno => !f.of,
        _ => false,
    }
}

fn exec_mov(emu: &mut Emu<'_, '_>, insn: &Instruction, rodata: &[(u64, u64)], data_va: &mut u64) {
    if insn.op1_kind() == OpKind::Memory && insn.is_ip_rel_memory_operand() {
        let addr: u64 = insn.ip_rel_memory_address();
        if in_rodata(rodata, addr) && *data_va == 0 {
            *data_va = addr;
        }
    }
    let v: u64 = operand_value(emu, insn, 1);
    store_op0(emu, insn, v);
}

fn exec_movzx(emu: &mut Emu<'_, '_>, insn: &Instruction) {
    let src: u64 = operand_value(emu, insn, 1);
    let src_size: usize = match insn.op1_kind() {
        OpKind::Memory => insn.memory_size().size().max(1),
        OpKind::Register => insn.op1_register().size(),
        _ => 1,
    };
    let masked: u64 = mask_bytes(src, src_size);
    emu.set_reg(insn.op0_register(), masked);
}

fn exec_movups(
    emu: &mut Emu<'_, '_>,
    insn: &Instruction,
    rodata: &[(u64, u64)],
    data_va: &mut u64,
) {
    let width: usize = insn.memory_size().size().max(16);
    if insn.op1_kind() == OpKind::Memory {
        let addr: u64 = emu.mem_addr(insn);
        if in_rodata(rodata, addr) && *data_va == 0 {
            *data_va = addr;
        }
        let bytes: Vec<u8> = (0..width)
            .map(|i: usize| emu.read_mem(addr.wrapping_add(i as u64), 1) as u8)
            .collect();
        emu.set_xmm(insn.op0_register(), &bytes);
    } else if insn.op0_kind() == OpKind::Memory {
        let addr: u64 = emu.mem_addr(insn);
        let bytes: Vec<u8> = emu.get_xmm(insn.op1_register(), width);
        for (i, b) in bytes.iter().enumerate() {
            emu.write_mem(addr.wrapping_add(i as u64), 1, u64::from(*b));
        }
    }
}

fn exec_imul(emu: &mut Emu<'_, '_>, insn: &Instruction) {
    let size: usize = op0_size(insn);
    match insn.op_count() {
        2 => {
            let a: u64 = operand_value(emu, insn, 0);
            let b: u64 = operand_value(emu, insn, 1);
            store_op0(emu, insn, mask_bytes(a.wrapping_mul(b), size));
        }
        3 => {
            let b: u64 = operand_value(emu, insn, 1);
            let c: u64 = operand_value(emu, insn, 2);
            store_op0(emu, insn, mask_bytes(b.wrapping_mul(c), size));
        }
        _ => {
            let a: u64 = emu.reg(Register::RAX);
            let b: u64 = operand_value(emu, insn, 0);
            emu.set_reg(Register::RAX, a.wrapping_mul(b));
        }
    }
}

fn exec_shift(emu: &mut Emu<'_, '_>, insn: &Instruction, left: bool) {
    let a: u64 = operand_value(emu, insn, 0);
    let cnt: u64 = operand_value(emu, insn, 1) & 0x3f;
    let size: usize = op0_size(insn);
    let res: u64 = if left { a << cnt } else { a >> cnt };
    store_op0(emu, insn, mask_bytes(res, size));
}

fn exec_xchg(emu: &mut Emu<'_, '_>, insn: &Instruction) {
    let a: u64 = operand_value(emu, insn, 0);
    let b: u64 = operand_value(emu, insn, 1);
    store_op0(emu, insn, b);
    match insn.op1_kind() {
        OpKind::Register => emu.set_reg(insn.op1_register(), a),
        OpKind::Memory => {
            let addr: u64 = emu.mem_addr(insn);
            let size: usize = insn.memory_size().size().max(1);
            emu.write_mem(addr, size, a);
        }
        _ => {}
    }
}

fn op0_size(insn: &Instruction) -> usize {
    match insn.op0_kind() {
        OpKind::Register => insn.op0_register().size(),
        OpKind::Memory => insn.memory_size().size().max(1),
        _ => 8,
    }
}

const fn mask_bytes(val: u64, size: usize) -> u64 {
    match size {
        1 => val & 0xff,
        2 => val & 0xffff,
        4 => val & 0xffff_ffff,
        _ => val,
    }
}

impl Emu<'_, '_> {
    fn set_xmm(&mut self, r: Register, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.mem.insert(xmm_addr(r, i), *b);
        }
    }

    fn get_xmm(&self, r: Register, width: usize) -> Vec<u8> {
        (0..width)
            .map(|i: usize| *self.mem.get(&xmm_addr(r, i)).unwrap_or(&0))
            .collect()
    }
}

const XMM_BAND: u64 = 0x4800_0000_0000;

const fn xmm_addr(r: Register, i: usize) -> u64 {
    XMM_BAND + (r as u64) * 64 + i as u64
}

const MIN_HARVEST_SCORE: i64 = 12;

fn harvest_plaintext(emu: &Emu<'_, '_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut precise: Vec<String> = Vec::new();
    for &(ptr, len) in &emu.decrypted_spans {
        let bytes: Vec<u8> = (0..len)
            .map(|i: u64| *emu.mem.get(&(ptr + i)).unwrap_or(&0))
            .collect();
        let Ok(s): Result<&str, _> = std::str::from_utf8(&bytes) else {
            continue;
        };
        if readability_score(s) < MIN_HARVEST_SCORE {
            continue;
        }
        if s.len() >= MIN_PLAINTEXT && seen.insert(s.to_owned()) {
            precise.push(s.to_owned());
            out.push(s.to_owned());
        }
    }
    let runs: Vec<Vec<u8>> = contiguous_text_runs(emu);
    for run in &runs {
        let forward: i64 = std::str::from_utf8(run).map_or(-1, readability_score);
        let rev: Vec<u8> = reversed(run);
        let backward: i64 = std::str::from_utf8(&rev).map_or(-1, readability_score);
        let (score, chosen): (i64, &[u8]) = if backward > forward {
            (backward, &rev)
        } else {
            (forward, run.as_slice())
        };
        if score < MIN_HARVEST_SCORE {
            continue;
        }
        let Ok(s): Result<&str, _> = std::str::from_utf8(chosen) else {
            continue;
        };
        let trimmed: &str = trim_junk(s);
        if trimmed.len() < MIN_PLAINTEXT {
            continue;
        }
        if seen.iter().any(|k: &String| k.contains(trimmed))
            || precise
                .iter()
                .any(|p: &String| trimmed.contains(p.as_str()))
        {
            continue;
        }
        if seen.insert(trimmed.to_owned()) {
            out.push(trimmed.to_owned());
        }
    }
    out
}

fn trim_junk(s: &str) -> &str {
    s.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '/' | ':' | '.' | '_')))
}

fn contiguous_text_runs(emu: &Emu<'_, '_>) -> Vec<Vec<u8>> {
    let mut entries: Vec<(u64, u8)> = emu
        .mem
        .iter()
        .filter(|(k, _): &(&u64, &u8)| !(XMM_BAND..XMM_BAND + 0x10000).contains(*k))
        .map(|(k, v): (&u64, &u8)| (*k, *v))
        .collect();
    entries.sort_by_key(|(k, _): &(u64, u8)| *k);

    let mut runs: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut last: u64 = u64::MAX;
    for (addr, byte) in entries {
        if is_text_byte(byte) && addr == last.wrapping_add(1) {
            cur.push(byte);
        } else {
            if cur.len() >= MIN_PLAINTEXT {
                runs.push(std::mem::take(&mut cur));
            }
            cur.clear();
            if is_text_byte(byte) {
                cur.push(byte);
            }
        }
        last = addr;
    }
    if cur.len() >= MIN_PLAINTEXT {
        runs.push(cur);
    }
    runs
}

fn reversed(run: &[u8]) -> Vec<u8> {
    let mut r: Vec<u8> = run.to_vec();
    r.reverse();
    r
}

const READABLE_PUNCT: &[u8] = b" -_/.:,;!?()'\"=+@#%&*\\[]{}<>|~^$\n\t\r";

fn readability_score(s: &str) -> i64 {
    let len: i64 = s.len() as i64;
    let letters: i64 = s.bytes().filter(u8::is_ascii_alphabetic).count() as i64;
    let digits: i64 = s.bytes().filter(u8::is_ascii_digit).count() as i64;
    let spaces_seps: i64 = s
        .bytes()
        .filter(|b: &u8| matches!(*b, b' ' | b'-' | b'_' | b'/' | b'.' | b':'))
        .count() as i64;
    let vowels: i64 = s
        .bytes()
        .filter(|b: &u8| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
        .count() as i64;
    let weird: i64 = s
        .bytes()
        .filter(|b: &u8| !b.is_ascii_alphanumeric() && !READABLE_PUNCT.contains(b))
        .count() as i64;
    if weird > 0 {
        return -1;
    }
    if (letters + digits) * 3 < len * 2 {
        return -1;
    }
    if letters >= 6 && vowels * 5 < letters {
        return -1;
    }
    let longest_consonant: i64 = longest_consonant_run(s);
    if longest_consonant >= 6 {
        return -1;
    }
    let token_bonus: i64 = if has_dictionary_token(s) { 20 } else { 0 };
    len + letters + spaces_seps * 2 + token_bonus
}

fn longest_consonant_run(s: &str) -> i64 {
    let mut best: i64 = 0;
    let mut cur: i64 = 0;
    for b in s.bytes() {
        let lc: u8 = b.to_ascii_lowercase();
        if lc.is_ascii_alphabetic() && !matches!(lc, b'a' | b'e' | b'i' | b'o' | b'u' | b'y') {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

const READABILITY_TOKENS: &[&str] = &[
    "://", ".com", ".php", ".dll", ".exe", ".dat", "/", "http", "key", "the", "ing", "ion", "and",
    "for", "user", "host", "path", "name", "data", "error", "windows", "software", "server",
    "config", "registry", "process", "connect", "request", "value", "string", "buffer", "token",
    "interval", "routine",
];

fn has_dictionary_token(s: &str) -> bool {
    let lowered: String = s.to_ascii_lowercase();
    READABILITY_TOKENS
        .iter()
        .any(|t: &&str| lowered.contains(*t))
}

const fn is_text_byte(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use iced_x86::Register;

    use super::{
        Emu, FAKE_ALLOC_STRIDE, FAKE_HEAP_BASE, Flags, GLOBAL_STEP_BUDGET, GoImage,
        MAX_EMU_MEM_BYTES, RAM_HIGH, RAM_LOW, THUNK_SCAN_BUDGET, THUNK_SCAN_CHECK_STRIDE,
        scan_deadline_hit,
    };
    use crate::binary::{Endian, ImageKind, Section};
    use crate::symbols::GoSymbols;

    fn empty_symbols() -> GoSymbols {
        GoSymbols {
            version_label: "go1.21".to_owned(),
            ptr_size: 8,
            funcs: Vec::new(),
            source_files: Vec::new(),
            package_set: Vec::new(),
        }
    }

    fn empty_image(raw: &[u8]) -> GoImage<'_> {
        GoImage {
            kind: ImageKind::Elf,
            endian: Endian::Little,
            ptr_size: 8,
            sections: Vec::new(),
            raw,
            symbol_addrs: Vec::new(),
            flat: false,
        }
    }

    fn emu<'a, 'b>(image: &'a GoImage<'b>, syms: &'a GoSymbols) -> Emu<'a, 'b> {
        Emu {
            image,
            text: &[],
            rodata: &[],
            syms,
            text_base: 0,
            regs: BTreeMap::new(),
            mem: BTreeMap::new(),
            fake_heap: FAKE_HEAP_BASE,
            flags: Flags::default(),
            call_depth: 0,
            step_budget: GLOBAL_STEP_BUDGET,
            consumer_args: Vec::new(),
            collect_consumer_args: false,
            suppress_follow: false,
            decrypted_spans: Vec::new(),
        }
    }

    #[test]
    fn fresh_heap_never_leaves_the_ram_band() {
        let raw: Vec<u8> = Vec::new();
        let image: GoImage<'_> = empty_image(&raw);
        let syms: GoSymbols = empty_symbols();
        let mut e: Emu<'_, '_> = emu(&image, &syms);
        let iterations: u64 = ((RAM_HIGH - FAKE_HEAP_BASE) / FAKE_ALLOC_STRIDE) + 16;
        for _ in 0..iterations {
            let ptr: u64 = e.fresh_heap();
            assert!(
                (RAM_LOW..RAM_HIGH).contains(&ptr),
                "fresh_heap must stay inside the tracked RAM band, got {ptr:#x}"
            );
        }
    }

    #[test]
    fn zero_fill_never_exceeds_the_emulated_memory_cap() {
        let raw: Vec<u8> = Vec::new();
        let image: GoImage<'_> = empty_image(&raw);
        let syms: GoSymbols = empty_symbols();
        let mut e: Emu<'_, '_> = emu(&image, &syms);
        e.zero_fill(FAKE_HEAP_BASE, usize::MAX);
        assert!(
            e.mem.len() <= MAX_EMU_MEM_BYTES,
            "a newobject/newarray dispatch that ever requests an unbounded fill length \
             must still be capped at MAX_EMU_MEM_BYTES, got {} tracked bytes",
            e.mem.len()
        );
    }

    #[test]
    fn scan_deadline_only_checks_on_stride_and_after_budget() {
        let fresh: std::time::Instant = std::time::Instant::now();
        assert!(
            !scan_deadline_hit(fresh, THUNK_SCAN_CHECK_STRIDE),
            "a stride boundary on a fresh clock must not trip the budget"
        );
        assert!(
            !scan_deadline_hit(fresh, THUNK_SCAN_CHECK_STRIDE - 1),
            "an off-stride iteration must never even sample the clock"
        );
        let elapsed: std::time::Instant = fresh
            .checked_sub(THUNK_SCAN_BUDGET + std::time::Duration::from_secs(1))
            .expect("clock far enough in the past to model an exhausted budget");
        assert!(
            scan_deadline_hit(elapsed, THUNK_SCAN_CHECK_STRIDE),
            "an exhausted budget sampled on a stride boundary must break the scan"
        );
        assert!(
            !scan_deadline_hit(elapsed, THUNK_SCAN_CHECK_STRIDE + 1),
            "even an exhausted budget is ignored off the check stride"
        );
    }

    #[test]
    fn read_write_mem_clamp_wide_memory_operand() {
        let raw: Vec<u8> = Vec::new();
        let image: GoImage<'_> = empty_image(&raw);
        let syms: GoSymbols = empty_symbols();
        let mut e: Emu<'_, '_> = emu(&image, &syms);
        let addr: u64 = RAM_LOW + 0x100;
        e.write_mem(addr, 32, 0xDEAD_BEEF_CAFE_F00D);
        let value: u64 = e.read_mem(addr, 32);
        assert_eq!(
            value, 0xDEAD_BEEF_CAFE_F00D,
            "a >8-byte memory operand must clamp to 8 bytes, never panic"
        );
        e.set_reg(Register::RAX, value);
        assert_eq!(e.reg(Register::RAX), 0xDEAD_BEEF_CAFE_F00D);
    }

    #[test]
    fn read_mem_clamps_wide_image_backed_operand_without_panicking() {
        let section_bytes: [u8; 16] = [
            0x0d, 0xf0, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let raw: Vec<u8> = Vec::new();
        let image: GoImage<'_> = GoImage {
            kind: ImageKind::Elf,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".rodata".to_owned(),
                address: 0x40_0000,
                data: &section_bytes,
                mapped_len: u64::try_from(section_bytes.len()).expect("fixture size fits u64"),
            }],
            raw: &raw,
            symbol_addrs: Vec::new(),
            flat: false,
        };
        let syms: GoSymbols = empty_symbols();
        let e: Emu<'_, '_> = emu(&image, &syms);
        let value: u64 = e.read_mem(0x40_0000, 16);
        assert_eq!(
            value, 0xDEAD_BEEF_CAFE_F00D,
            "a >8-byte operand backed by a real section must clamp to the low 8 bytes \
             instead of indexing past the 8-byte staging buffer"
        );
    }
}
