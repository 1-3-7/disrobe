use std::collections::BTreeMap;

use disrobe_bytes::read_uleb128_at;
use serde::{Deserialize, Serialize};

use crate::macho::{self, ParsedSlice, Section, SliceView};
use crate::native_bodies::DisasmInstruction;

const LC_DYLD_INFO: u32 = 0x22;
const PTR_SIZE_64: u64 = 8;
const MAX_BIND_OPS: usize = 1 << 20;
const MAX_SLOTS: usize = 1 << 20;
const MAX_TOTAL_BINDS: usize = 1 << 20;
const MAX_STUB_ENTRIES: usize = 1 << 16;
const MAX_CALL_SITES: usize = 1 << 14;
const BACKWARD_WINDOW: usize = 24;
const MAX_CSTR: usize = 4096;

const SECT_OBJC_SELREFS: &str = "__objc_selrefs";
const SECT_OBJC_CLASSREFS: &str = "__objc_classrefs";
const SECT_STUBS: &str = "__stubs";
const SEG_TEXT: &str = "__TEXT";
const SEG_DATA: &str = "__DATA";
const SEG_DATA_CONST: &str = "__DATA_CONST";

const CLASS_PREFIX: &str = "_OBJC_CLASS_$_";
const METACLASS_PREFIX: &str = "_OBJC_METACLASS_$_";

const RO_NAME_OFF: usize = 0x18;
const CLASS_DATA_OFF: usize = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchArch {
    Arm64,
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcSend {
    pub selector: String,
    pub receiver_class: Option<String>,
    pub rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcMessageSend {
    pub call_site: u64,
    pub send: ObjcSend,
}

#[derive(Debug, Clone, Default)]
pub struct DispatchMaps {
    pub imports_by_addr: BTreeMap<u64, String>,
    pub selref_by_va: BTreeMap<u64, String>,
    pub classref_by_va: BTreeMap<u64, String>,
    pub stub_symbol_by_va: BTreeMap<u64, String>,
}

impl DispatchMaps {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.imports_by_addr.is_empty()
            && self.selref_by_va.is_empty()
            && self.classref_by_va.is_empty()
            && self.stub_symbol_by_va.is_empty()
    }
}

#[must_use]
pub fn build_dispatch_maps(slice: &[u8], parsed: &ParsedSlice, arch: DispatchArch) -> DispatchMaps {
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return DispatchMaps::default();
    };
    let imports_by_addr: BTreeMap<u64, String> = parse_binds(slice, parsed, &view);
    let selref_by_va: BTreeMap<u64, String> = build_selref_map(parsed, &view);
    let classref_by_va: BTreeMap<u64, String> = build_classref_map(parsed, &view, &imports_by_addr);
    let stub_symbol_by_va: BTreeMap<u64, String> =
        build_stub_map(slice, parsed, &imports_by_addr, arch);
    DispatchMaps {
        imports_by_addr,
        selref_by_va,
        classref_by_va,
        stub_symbol_by_va,
    }
}

fn find_section_any<'a>(parsed: &'a ParsedSlice, segs: &[&str], name: &str) -> Option<&'a Section> {
    segs.iter()
        .find_map(|seg: &&str| macho::find_section(parsed, seg, name))
}

fn build_selref_map(parsed: &ParsedSlice, view: &SliceView<'_>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> =
        find_section_any(parsed, &[SEG_DATA, SEG_DATA_CONST], SECT_OBJC_SELREFS)
    else {
        return out;
    };
    let count: usize = usize::try_from(section.size / PTR_SIZE_64)
        .unwrap_or(0)
        .min(MAX_SLOTS);
    for i in 0..count {
        let slot_va: u64 = section.addr.saturating_add((i as u64) * PTR_SIZE_64);
        let file_off: usize = (section.offset as usize).saturating_add(i * 8);
        let Some(name_va): Option<u64> = view.read_pointer_at(parsed, file_off) else {
            continue;
        };
        let Some(selector): Option<String> = view.cstr_at_vmaddr(parsed, name_va, MAX_CSTR) else {
            continue;
        };
        if !selector.is_empty() {
            out.insert(slot_va, selector);
        }
    }
    out
}

fn build_classref_map(
    parsed: &ParsedSlice,
    view: &SliceView<'_>,
    imports_by_addr: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> =
        find_section_any(parsed, &[SEG_DATA, SEG_DATA_CONST], SECT_OBJC_CLASSREFS)
    else {
        return out;
    };
    let count: usize = usize::try_from(section.size / PTR_SIZE_64)
        .unwrap_or(0)
        .min(MAX_SLOTS);
    for i in 0..count {
        let slot_va: u64 = section.addr.saturating_add((i as u64) * PTR_SIZE_64);
        if let Some(symbol) = imports_by_addr.get(&slot_va)
            && let Some(name) = strip_class_symbol(symbol)
        {
            out.insert(slot_va, name.to_owned());
            continue;
        }
        let file_off: usize = (section.offset as usize).saturating_add(i * 8);
        if let Some(class_va) = view.read_pointer_at(parsed, file_off)
            && let Some(name) = local_class_name(parsed, view, class_va)
        {
            out.insert(slot_va, name);
        }
    }
    out
}

fn strip_class_symbol(symbol: &str) -> Option<&str> {
    symbol
        .strip_prefix(CLASS_PREFIX)
        .or_else(|| symbol.strip_prefix(METACLASS_PREFIX))
        .filter(|name: &&str| !name.is_empty())
}

fn local_class_name(parsed: &ParsedSlice, view: &SliceView<'_>, class_va: u64) -> Option<String> {
    let class_off: usize = macho::vmaddr_to_offset(parsed, class_va)?;
    let bits: u64 = view.read_u64_at(class_off.checked_add(CLASS_DATA_OFF)?)?;
    let data_va: u64 = macho::decode_bound_pointer(bits & macho::FAST_DATA_MASK, view.base());
    let ro_off: usize = macho::vmaddr_to_offset(parsed, data_va)?;
    let name_va: u64 = view.read_pointer_at(parsed, ro_off.checked_add(RO_NAME_OFF)?)?;
    view.cstr_at_vmaddr(parsed, name_va, MAX_CSTR)
        .filter(|name: &String| !name.is_empty())
}

fn build_stub_map(
    slice: &[u8],
    parsed: &ParsedSlice,
    imports_by_addr: &BTreeMap<u64, String>,
    arch: DispatchArch,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(section): Option<&Section> = macho::find_section(parsed, SEG_TEXT, SECT_STUBS) else {
        return out;
    };
    let Some(bytes): Option<&[u8]> = macho::section_bytes(slice, section) else {
        return out;
    };
    match arch {
        DispatchArch::Arm64 => build_arm64_stub_map(section.addr, bytes, imports_by_addr, &mut out),
        DispatchArch::X86_64 => build_x86_stub_map(section.addr, bytes, imports_by_addr, &mut out),
    }
    out
}

fn build_arm64_stub_map(
    base: u64,
    bytes: &[u8],
    imports_by_addr: &BTreeMap<u64, String>,
    out: &mut BTreeMap<u64, String>,
) {
    let stride: usize = 12;
    let mut offset: usize = 0;
    let mut entries: usize = 0;
    while offset + stride <= bytes.len() && entries < MAX_STUB_ENTRIES {
        entries += 1;
        let entry_va: u64 = base.saturating_add(offset as u64);
        let w0: u32 = read_u32_le(bytes, offset);
        let w1: u32 = read_u32_le(bytes, offset + 4);
        if let Some((_, page)) = decode_adrp(entry_va, w0)
            && let Some((_, _, off)) = decode_ldr64(w1)
        {
            let slot: u64 = page.saturating_add(off);
            if let Some(symbol) = imports_by_addr.get(&slot) {
                out.insert(entry_va, symbol.clone());
            }
        }
        offset += stride;
    }
}

fn build_x86_stub_map(
    base: u64,
    bytes: &[u8],
    imports_by_addr: &BTreeMap<u64, String>,
    out: &mut BTreeMap<u64, String>,
) {
    let stride: usize = 6;
    let mut offset: usize = 0;
    let mut entries: usize = 0;
    while offset + stride <= bytes.len() && entries < MAX_STUB_ENTRIES {
        entries += 1;
        if bytes.get(offset) == Some(&0xFF) && bytes.get(offset + 1) == Some(&0x25) {
            let entry_va: u64 = base.saturating_add(offset as u64);
            let disp: i32 = read_i32_le(bytes, offset + 2);
            let end: u64 = entry_va.saturating_add(stride as u64);
            let slot: u64 = end.wrapping_add(disp as i64 as u64);
            if let Some(symbol) = imports_by_addr.get(&slot) {
                out.insert(entry_va, symbol.clone());
            }
        }
        offset += stride;
    }
}

fn parse_binds(slice: &[u8], parsed: &ParsedSlice, view: &SliceView<'_>) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    let Some(command): Option<&macho::LoadCommand> = parsed
        .load_commands
        .iter()
        .find(|lc: &&macho::LoadCommand| lc.cmd == LC_DYLD_INFO)
    else {
        return out;
    };
    let base: usize = command.data_offset;
    let streams: [(u32, u32); 3] = [
        (read_lc_u32(view, base, 16), read_lc_u32(view, base, 20)),
        (read_lc_u32(view, base, 24), read_lc_u32(view, base, 28)),
        (read_lc_u32(view, base, 32), read_lc_u32(view, base, 36)),
    ];
    let mut total: usize = 0;
    for (off, size) in streams {
        interpret_bind(
            slice,
            parsed,
            off as usize,
            size as usize,
            &mut out,
            &mut total,
        );
    }
    out
}

fn read_lc_u32(view: &SliceView<'_>, base: usize, delta: usize) -> u32 {
    view.read_u32_at(base.saturating_add(delta)).unwrap_or(0)
}

fn interpret_bind(
    slice: &[u8],
    parsed: &ParsedSlice,
    start: usize,
    size: usize,
    out: &mut BTreeMap<u64, String>,
    total: &mut usize,
) {
    let end: usize = start.saturating_add(size).min(slice.len());
    let Some(stream): Option<&[u8]> = slice.get(start..end) else {
        return;
    };
    let mut cursor: usize = 0;
    let mut seg_index: usize = 0;
    let mut seg_off: u64 = 0;
    let mut symbol: String = String::new();
    let mut ops: usize = 0;
    while cursor < stream.len() && ops < MAX_BIND_OPS && *total < MAX_TOTAL_BINDS {
        ops += 1;
        let byte: u8 = stream[cursor];
        cursor += 1;
        let opcode: u8 = byte & 0xF0;
        let imm: u8 = byte & 0x0F;
        match opcode {
            0x20 | 0x60 => cursor = skip_uleb(stream, cursor),
            0x40 => {
                let (text, next): (String, usize) = read_cstr(stream, cursor);
                symbol = text;
                cursor = next;
            }
            0x70 => {
                seg_index = imm as usize;
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                seg_off = value;
                cursor = next;
            }
            0x80 => {
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                seg_off = seg_off.wrapping_add(value);
                cursor = next;
            }
            0x90 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                seg_off = seg_off.wrapping_add(PTR_SIZE_64);
            }
            0xA0 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                let (value, next): (u64, usize) = read_uleb(stream, cursor);
                cursor = next;
                seg_off = seg_off.wrapping_add(PTR_SIZE_64).wrapping_add(value);
            }
            0xB0 => {
                bind_one(parsed, seg_index, seg_off, &symbol, out);
                *total += 1;
                seg_off = seg_off
                    .wrapping_add(PTR_SIZE_64)
                    .wrapping_add((imm as u64).wrapping_mul(PTR_SIZE_64));
            }
            0xC0 => {
                let (count, next): (u64, usize) = read_uleb(stream, cursor);
                let (skip, next2): (u64, usize) = read_uleb(stream, next);
                cursor = next2;
                let bounded: u64 = count.min(MAX_SLOTS as u64);
                for _ in 0..bounded {
                    if *total >= MAX_TOTAL_BINDS {
                        break;
                    }
                    bind_one(parsed, seg_index, seg_off, &symbol, out);
                    *total += 1;
                    seg_off = seg_off.wrapping_add(PTR_SIZE_64).wrapping_add(skip);
                }
            }
            _ => {}
        }
    }
}

fn bind_one(
    parsed: &ParsedSlice,
    seg_index: usize,
    seg_off: u64,
    symbol: &str,
    out: &mut BTreeMap<u64, String>,
) {
    if symbol.is_empty() {
        return;
    }
    let Some(segment): Option<&macho::Segment> = parsed.segments.get(seg_index) else {
        return;
    };
    let addr: u64 = segment.vmaddr.saturating_add(seg_off);
    out.insert(addr, symbol.to_owned());
}

fn read_uleb(stream: &[u8], cursor: usize) -> (u64, usize) {
    match read_uleb128_at(stream, cursor) {
        Ok((value, consumed)) => (value, cursor + consumed),
        Err(_) => (0, stream.len()),
    }
}

fn skip_uleb(stream: &[u8], cursor: usize) -> usize {
    read_uleb(stream, cursor).1
}

fn read_cstr(stream: &[u8], cursor: usize) -> (String, usize) {
    let mut end: usize = cursor;
    while end < stream.len() && stream[end] != 0 {
        end += 1;
    }
    let text: String = std::str::from_utf8(&stream[cursor..end])
        .map(str::to_owned)
        .unwrap_or_default();
    (text, (end + 1).min(stream.len()))
}

#[derive(Debug, Clone, Copy)]
enum CallForm {
    Direct(u64),
    Indirect(u8),
}

#[derive(Debug, Clone, Default)]
struct Step {
    addr: u64,
    boundary: bool,
    call: Option<CallForm>,
    adrp: Option<u64>,
    ldr: Option<(u8, u8, u64)>,
    rip_load: Option<(u8, u64)>,
    writes: WriteSet,
    recognized: bool,
}

#[derive(Debug, Clone, Copy, Default)]
enum WriteSet {
    #[default]
    None,
    One(u8),
    Two(u8, u8),
}

impl WriteSet {
    const fn contains(self, reg: u8) -> bool {
        match self {
            Self::None => false,
            Self::One(a) => a == reg,
            Self::Two(a, b) => a == reg || b == reg,
        }
    }
}

const ARM_SEL_REG: u8 = 1;
const ARM_RECV_REG: u8 = 0;
const X86_SEL_REG: u8 = 6;
const X86_RECV_REG: u8 = 7;

const MSGSEND_SYMBOLS: [&str; 5] = [
    "_objc_msgSend",
    "_objc_msgSendSuper",
    "_objc_msgSendSuper2",
    "_objc_msgSend_stret",
    "_objc_msgSendSuper2_stret",
];

fn dispatch_kind(symbol: &str) -> Option<Dispatch> {
    if MSGSEND_SYMBOLS.contains(&symbol) {
        return Some(Dispatch::MsgSend {
            is_super: symbol.contains("Super"),
        });
    }
    match symbol {
        "_objc_alloc" => Some(Dispatch::Alloc),
        "_objc_alloc_init" => Some(Dispatch::AllocInit),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum Dispatch {
    MsgSend { is_super: bool },
    Alloc,
    AllocInit,
}

#[must_use]
pub fn annotate_instructions(
    instructions: &[DisasmInstruction],
    arch: DispatchArch,
    maps: &DispatchMaps,
) -> Vec<ObjcMessageSend> {
    if maps.is_empty() {
        return Vec::new();
    }
    let steps: Vec<Step> = instructions
        .iter()
        .map(|insn: &DisasmInstruction| decode_step(insn, arch))
        .collect();
    let mut out: Vec<ObjcMessageSend> = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if out.len() >= MAX_CALL_SITES {
            break;
        }
        let Some(call): Option<CallForm> = step.call else {
            continue;
        };
        let Some(symbol): Option<&String> = call_symbol(&steps, index, call, maps) else {
            continue;
        };
        let Some(kind): Option<Dispatch> = dispatch_kind(symbol) else {
            continue;
        };
        if let Some(send) = resolve_send(&steps, index, arch, maps, kind) {
            out.push(ObjcMessageSend {
                call_site: step.addr,
                send,
            });
        }
    }
    out
}

fn call_symbol<'a>(
    steps: &[Step],
    index: usize,
    call: CallForm,
    maps: &'a DispatchMaps,
) -> Option<&'a String> {
    match call {
        CallForm::Direct(target) => maps
            .stub_symbol_by_va
            .get(&target)
            .or_else(|| maps.imports_by_addr.get(&target)),
        CallForm::Indirect(reg) => {
            let slot: u64 = trace_pointer_slot(steps, index, reg)?;
            maps.imports_by_addr.get(&slot)
        }
    }
}

fn resolve_send(
    steps: &[Step],
    index: usize,
    arch: DispatchArch,
    maps: &DispatchMaps,
    kind: Dispatch,
) -> Option<ObjcSend> {
    let (sel_reg, recv_reg): (u8, u8) = match arch {
        DispatchArch::Arm64 => (ARM_SEL_REG, ARM_RECV_REG),
        DispatchArch::X86_64 => (X86_SEL_REG, X86_RECV_REG),
    };
    match kind {
        Dispatch::MsgSend { is_super } => {
            let selector: String = trace_selector(steps, index, sel_reg, maps)?;
            let receiver_class: Option<String> = if is_super {
                None
            } else {
                trace_receiver_class(steps, index, recv_reg, maps)
            };
            let recv_token: String = receiver_token(receiver_class.as_deref(), is_super, arch);
            let rendered: String = render_message(&selector, &recv_token, arch);
            Some(ObjcSend {
                selector,
                receiver_class,
                rendered,
            })
        }
        Dispatch::Alloc => {
            let receiver_class: Option<String> = trace_receiver_class(steps, index, recv_reg, maps);
            let recv_token: String = receiver_token(receiver_class.as_deref(), false, arch);
            Some(ObjcSend {
                selector: "alloc".to_owned(),
                rendered: format!("[{recv_token} alloc]"),
                receiver_class,
            })
        }
        Dispatch::AllocInit => {
            let receiver_class: Option<String> = trace_receiver_class(steps, index, recv_reg, maps);
            let recv_token: String = receiver_token(receiver_class.as_deref(), false, arch);
            Some(ObjcSend {
                selector: "init".to_owned(),
                rendered: format!("[[{recv_token} alloc] init]"),
                receiver_class,
            })
        }
    }
}

fn receiver_token(receiver_class: Option<&str>, is_super: bool, arch: DispatchArch) -> String {
    if is_super {
        return "super".to_owned();
    }
    if let Some(name) = receiver_class {
        return name.to_owned();
    }
    match arch {
        DispatchArch::Arm64 => "x0".to_owned(),
        DispatchArch::X86_64 => "rdi".to_owned(),
    }
}

const fn arg_registers(arch: DispatchArch) -> &'static [&'static str] {
    match arch {
        DispatchArch::Arm64 => &["x2", "x3", "x4", "x5", "x6", "x7"],
        DispatchArch::X86_64 => &["rdx", "rcx", "r8", "r9"],
    }
}

fn render_message(selector: &str, recv: &str, arch: DispatchArch) -> String {
    if !selector.contains(':') {
        return format!("[{recv} {selector}]");
    }
    let args: &[&str] = arg_registers(arch);
    let mut rendered: String = String::from("[");
    rendered.push_str(recv);
    let mut arg_index: usize = 0;
    for keyword in selector.split(':') {
        if keyword.is_empty() {
            continue;
        }
        rendered.push(' ');
        rendered.push_str(keyword);
        rendered.push(':');
        rendered.push_str(args.get(arg_index).copied().unwrap_or("?"));
        arg_index += 1;
    }
    rendered.push(']');
    rendered
}

fn trace_selector(
    steps: &[Step],
    call_index: usize,
    reg: u8,
    maps: &DispatchMaps,
) -> Option<String> {
    let slot: u64 = trace_pointer_slot(steps, call_index, reg)?;
    maps.selref_by_va.get(&slot).cloned()
}

fn trace_receiver_class(
    steps: &[Step],
    call_index: usize,
    reg: u8,
    maps: &DispatchMaps,
) -> Option<String> {
    let slot: u64 = trace_pointer_slot(steps, call_index, reg)?;
    maps.classref_by_va.get(&slot).cloned()
}

fn trace_pointer_slot(steps: &[Step], from: usize, reg: u8) -> Option<u64> {
    let def_index: usize = find_def(steps, from, reg)?;
    let (_, base, off): (u8, u8, u64) = steps[def_index].ldr?;
    if let Some(page) = steps[def_index].rip_load_slot() {
        return Some(page.wrapping_add(off));
    }
    let base_index: usize = find_def(steps, def_index, base)?;
    let page: u64 = steps[base_index].adrp?;
    Some(page.wrapping_add(off))
}

impl Step {
    fn rip_load_slot(&self) -> Option<u64> {
        self.rip_load.map(|(_, slot): (u8, u64)| slot)
    }
}

fn find_def(steps: &[Step], from: usize, reg: u8) -> Option<usize> {
    let lower: usize = from.saturating_sub(BACKWARD_WINDOW);
    for index in (lower..from).rev() {
        let step: &Step = &steps[index];
        if step.boundary {
            return None;
        }
        if step.writes.contains(reg) {
            return Some(index);
        }
        if !step.recognized {
            return None;
        }
    }
    None
}

fn decode_step(insn: &DisasmInstruction, arch: DispatchArch) -> Step {
    let bytes: Vec<u8> = hex_to_bytes(&insn.bytes);
    match arch {
        DispatchArch::Arm64 => decode_arm64(insn.address, &bytes),
        DispatchArch::X86_64 => decode_x86(insn.address, &bytes),
    }
}

fn decode_arm64(addr: u64, bytes: &[u8]) -> Step {
    let mut step: Step = Step {
        addr,
        ..Step::default()
    };
    if bytes.len() < 4 {
        return step;
    }
    let word: u32 = read_u32_le(bytes, 0);
    if let Some((rd, page)) = decode_adrp(addr, word) {
        step.adrp = Some(page);
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return step;
    }
    if let Some((rt, rn, off)) = decode_ldr64(word) {
        step.ldr = Some((rt, rn, off));
        step.writes = WriteSet::One(rt);
        step.recognized = true;
        return step;
    }
    if word & 0xFC00_0000 == 0x9400_0000 {
        step.call = Some(CallForm::Direct(branch_target(addr, word)));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFC00_0000 == 0x1400_0000 {
        step.call = Some(CallForm::Direct(branch_target(addr, word)));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        step.call = Some(CallForm::Indirect(((word >> 5) & 0x1F) as u8));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        step.call = Some(CallForm::Indirect(((word >> 5) & 0x1F) as u8));
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    if word & 0xFFFF_FC1F == 0xD65F_0000
        || word & 0xFF00_0010 == 0x5400_0000
        || word & 0x7E00_0000 == 0x3400_0000
        || word & 0x7E00_0000 == 0x3600_0000
    {
        step.boundary = true;
        step.recognized = true;
        return step;
    }
    classify_arm64_writer(word, &mut step);
    step
}

const fn classify_arm64_writer(word: u32, step: &mut Step) {
    let rd: u8 = (word & 0x1F) as u8;
    let hi7: u32 = (word >> 24) & 0x7F;
    if word & 0x1F80_0000 == 0x1280_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if hi7 == 0x11 || hi7 == 0x51 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0x7FE0_0000 == 0x2A00_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0xFFC0_0000 == 0xB940_0000 || word & 0xFFE0_0C00 == 0xF840_0000 {
        step.writes = WriteSet::One(rd);
        step.recognized = true;
        return;
    }
    if word & 0x7FC0_0000 == 0x2940_0000 {
        let rt: u8 = (word & 0x1F) as u8;
        let rt2: u8 = ((word >> 10) & 0x1F) as u8;
        step.writes = WriteSet::Two(rt, rt2);
        step.recognized = true;
        return;
    }
    if word & 0xFFC0_0000 == 0xF900_0000
        || word & 0xFFE0_0C00 == 0xF800_0000
        || word & 0x7FC0_0000 == 0x2900_0000
        || word & 0xFFC0_0000 == 0xB900_0000
    {
        step.writes = WriteSet::None;
        step.recognized = true;
    }
}

fn decode_adrp(addr: u64, word: u32) -> Option<(u8, u64)> {
    if word & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let rd: u8 = (word & 0x1F) as u8;
    let immlo: u64 = u64::from((word >> 29) & 0x3);
    let immhi: u64 = u64::from((word >> 5) & 0x7_FFFF);
    let imm21: u64 = (immhi << 2) | immlo;
    let signed: i64 = ((imm21 << 43) as i64) >> 43;
    let page_delta: i64 = signed << 12;
    let base: i64 = (addr & !0xFFF) as i64;
    Some((rd, base.wrapping_add(page_delta) as u64))
}

fn decode_ldr64(word: u32) -> Option<(u8, u8, u64)> {
    if word & 0xFFC0_0000 != 0xF940_0000 {
        return None;
    }
    let rt: u8 = (word & 0x1F) as u8;
    let rn: u8 = ((word >> 5) & 0x1F) as u8;
    let imm12: u64 = u64::from((word >> 10) & 0xFFF);
    Some((rt, rn, imm12 * 8))
}

fn branch_target(addr: u64, word: u32) -> u64 {
    let imm26: u64 = u64::from(word & 0x03FF_FFFF);
    let signed: i64 = ((imm26 << 38) as i64) >> 38;
    addr.wrapping_add((signed << 2) as u64)
}

fn decode_x86(addr: u64, bytes: &[u8]) -> Step {
    let mut step: Step = Step {
        addr,
        ..Step::default()
    };
    if bytes.is_empty() {
        return step;
    }
    let len: usize = bytes.len();
    let end: u64 = addr.wrapping_add(len as u64);
    let mut i: usize = 0;
    let (mut rex_r, mut rex_b): (u8, u8) = (0, 0);
    while i < len {
        let byte: u8 = bytes[i];
        if (0x40..=0x4F).contains(&byte) {
            rex_r = (byte >> 2) & 1;
            rex_b = byte & 1;
            i += 1;
            continue;
        }
        if matches!(
            byte,
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65
        ) {
            i += 1;
            continue;
        }
        break;
    }
    let Some(&opcode): Option<&u8> = bytes.get(i) else {
        return step;
    };
    match opcode {
        0xE8 => {
            step.call = Some(CallForm::Direct(end.wrapping_add(read_disp(bytes, i + 1))));
            step.boundary = true;
            step.recognized = true;
        }
        0xE9 | 0xEB | 0xC3 | 0xC2 | 0xF4 | 0x70..=0x7F => {
            step.boundary = true;
            step.recognized = true;
        }
        0x0F => {
            if matches!(bytes.get(i + 1), Some(0x80..=0x8F)) {
                step.boundary = true;
                step.recognized = true;
            }
        }
        0xFF => decode_x86_ff(bytes, i, end, rex_b, &mut step),
        0x8B | 0x63 => decode_x86_load(bytes, i, end, rex_r, rex_b, &mut step),
        0x89 | 0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 => {
            decode_x86_store(bytes, i, rex_b, &mut step);
        }
        0x8D | 0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 => {
            decode_x86_reg_dest(bytes, i, rex_r, &mut step);
        }
        0xB8..=0xBF => {
            step.writes = WriteSet::One((opcode - 0xB8) | (rex_b << 3));
            step.recognized = true;
        }
        0x58..=0x5F => {
            step.writes = WriteSet::One((opcode - 0x58) | (rex_b << 3));
            step.recognized = true;
        }
        0x83 | 0x81 | 0xC7 => decode_x86_group_imm(bytes, i, rex_b, &mut step),
        0x50..=0x57 | 0x39 | 0x3B | 0x85 | 0x90 => {
            step.recognized = true;
        }
        _ => {}
    }
    step
}

fn decode_x86_ff(bytes: &[u8], i: usize, end: u64, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = (modrm >> 3) & 0x7;
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    match reg {
        2 | 3 => {
            if mode == 0 && rm == 5 {
                let slot: u64 = end.wrapping_add(read_disp(bytes, i + 2));
                step.call = Some(CallForm::Direct(slot));
            }
            step.boundary = true;
            step.recognized = true;
        }
        4 | 5 => {
            step.boundary = true;
            step.recognized = true;
        }
        0 | 1 => {
            if mode == 3 {
                step.writes = WriteSet::One(rm | (rex_b << 3));
            }
            step.recognized = true;
        }
        _ => {
            step.recognized = true;
        }
    }
}

fn decode_x86_load(bytes: &[u8], i: usize, end: u64, rex_r: u8, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = ((modrm >> 3) & 0x7) | (rex_r << 3);
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    step.writes = WriteSet::One(reg);
    step.recognized = true;
    if mode == 0 && rm == 5 {
        let slot: u64 = end.wrapping_add(read_disp(bytes, i + 2));
        step.ldr = Some((reg, 0xFF, 0));
        step.rip_load = Some((reg, slot));
    } else if mode == 3 {
        let _ = rex_b;
    }
}

fn decode_x86_store(bytes: &[u8], i: usize, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    if mode == 3 {
        step.writes = WriteSet::One(rm | (rex_b << 3));
    }
    step.recognized = true;
}

fn decode_x86_reg_dest(bytes: &[u8], i: usize, rex_r: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let reg: u8 = ((modrm >> 3) & 0x7) | (rex_r << 3);
    step.writes = WriteSet::One(reg);
    step.recognized = true;
}

fn decode_x86_group_imm(bytes: &[u8], i: usize, rex_b: u8, step: &mut Step) {
    let Some(&modrm): Option<&u8> = bytes.get(i + 1) else {
        return;
    };
    let mode: u8 = modrm >> 6;
    let rm: u8 = modrm & 0x7;
    let reg: u8 = (modrm >> 3) & 0x7;
    if mode == 3 && reg != 7 {
        step.writes = WriteSet::One(rm | (rex_b << 3));
    }
    step.recognized = true;
}

fn read_disp(bytes: &[u8], off: usize) -> u64 {
    read_i32_le(bytes, off) as i64 as u64
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    let mut arr: [u8; 4] = [0u8; 4];
    if let Some(window) = bytes.get(off..off + 4) {
        arr.copy_from_slice(window);
    }
    u32::from_le_bytes(arr)
}

fn read_i32_le(bytes: &[u8], off: usize) -> i32 {
    read_u32_le(bytes, off) as i32
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let raw: &[u8] = hex.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(raw.len() / 2);
    let mut index: usize = 0;
    while index + 1 < raw.len() {
        let hi: u8 = hex_nibble(raw[index]);
        let lo: u8 = hex_nibble(raw[index + 1]);
        if hi == 0xFF || lo == 0xFF {
            break;
        }
        out.push((hi << 4) | lo);
        index += 2;
    }
    out
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0xFF,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::macho::{Bitness, CpuKind, Endian, SliceHeader};
    use std::time::{Duration, Instant};

    fn wide_data_segment() -> ParsedSlice {
        ParsedSlice {
            header: SliceHeader {
                cpu: CpuKind::Arm64,
                bitness: Bitness::Bits64,
                endian: Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            segments: vec![macho::Segment {
                name: SEG_DATA.to_owned(),
                vmaddr: 0x1000,
                vmsize: 0x1_0000_0000,
                fileoff: 0,
                filesize: 0x1_0000_0000,
                sections: Vec::<Section>::new(),
            }],
            load_commands: Vec::new(),
            encryption: None,
            code_signature_off: None,
            code_signature_size: None,
            symtab: None,
        }
    }

    fn push_uleb(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte: u8 = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn repeated_uleb_times_skipping_cannot_exceed_shared_cap() {
        let parsed: ParsedSlice = wide_data_segment();
        let mut stream: Vec<u8> = Vec::new();
        stream.push(0x40);
        stream.extend_from_slice(b"_s\0");
        stream.push(0x70);
        push_uleb(&mut stream, 0);
        for _ in 0..8u32 {
            stream.push(0xC0);
            push_uleb(&mut stream, MAX_SLOTS as u64);
            push_uleb(&mut stream, 0);
        }
        let mut out: BTreeMap<u64, String> = BTreeMap::new();
        let mut total: usize = 0;
        let started: Instant = Instant::now();
        interpret_bind(&stream, &parsed, 0, stream.len(), &mut out, &mut total);
        let elapsed: Duration = started.elapsed();
        assert_eq!(total, MAX_TOTAL_BINDS);
        assert_eq!(out.len(), MAX_TOTAL_BINDS);
        assert!(
            elapsed < Duration::from_secs(3),
            "bind parse took {elapsed:?}"
        );
    }
}
