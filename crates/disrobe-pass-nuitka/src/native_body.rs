use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::debug::DebugLog;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::body::{CmpOpKind, LiftFidelity, PythonExpr, PythonStmt};
use crate::const_blob::{CodeKind, CodeObjectMeta, NuitkaConstants};

const MAX_TEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 20_000;
const MAX_IMPL_INSNS: usize = 20_000;
const CTOR_WINDOW: usize = 24;
const MAX_ENUMERATION_INSNS: usize = 4_000_000;
const MAX_API_CALLS: usize = 64;
const MIN_CONSTRUCTOR_IMPLS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum NativeOp {
    ParamLoad { index: usize },
    NoneLoad,
    ConstSlotLoad { slot: u64 },
    Call { callee: String },
    RichCompare { predicate: Option<CmpOpKind> },
    Iterate,
    IterNext,
    Attribute,
    Subscript,
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReturnOrigin {
    Param(usize),
    NoneConst,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameBinding {
    CodeObject,
    Positional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFunctionBody {
    pub name: String,
    pub qualname: String,
    pub impl_address: u64,
    pub constructed_in: u64,
    pub constructor: u64,
    pub code_size: u64,
    pub argcount: u32,
    pub varnames: Vec<String>,
    pub kind: CodeKind,
    pub name_binding: NameBinding,
    pub api_calls: Vec<String>,
    pub ops: Vec<NativeOp>,
    pub instruction_count: u64,
    pub recovered_stmts: Vec<PythonStmt>,
    pub fidelity: LiftFidelity,
    pub reconstruction_note: String,
}

impl NativeFunctionBody {
    #[must_use]
    pub const fn is_body_recovered(&self) -> bool {
        !self.recovered_stmts.is_empty()
    }

    #[must_use]
    pub const fn is_name_bound(&self) -> bool {
        matches!(self.name_binding, NameBinding::CodeObject)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBodyRecovery {
    pub module_name: String,
    pub located_impls: usize,
    pub host_functions: usize,
    pub constructors: Vec<u64>,
    pub bound_functions: usize,
    pub reconstructed_bodies: usize,
    pub functions: Vec<NativeFunctionBody>,
    pub notes: Vec<String>,
}

impl NativeBodyRecovery {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    #[must_use]
    pub fn body_for(&self, name: &str) -> Option<&NativeFunctionBody> {
        self.functions.iter().find(|f: &&NativeFunctionBody| {
            f.is_name_bound() && f.name == name && f.is_body_recovered()
        })
    }
}

struct PeView {
    text_base: u64,
    text: Vec<u8>,
    functions: Vec<(u64, u64)>,
    function_begins: BTreeSet<u64>,
    iat: BTreeMap<u64, String>,
}

fn read_u16(image: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(image.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(image: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(image.get(at..at + 8)?.try_into().ok()?))
}

struct Section {
    name: String,
    virtual_address: u64,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

fn parse_pe(image: &[u8]) -> Option<PeView> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew: usize = read_u32(image, 0x3c)? as usize;
    if image.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let machine: u16 = read_u16(image, coff)?;
    if machine != 0x8664 {
        return None;
    }
    let num_sections: usize = read_u16(image, coff + 2)? as usize;
    let opt_size: usize = read_u16(image, coff + 16)? as usize;
    let opt: usize = coff + 20;
    let magic: u16 = read_u16(image, opt)?;
    if magic != 0x20b {
        return None;
    }
    let image_base: u64 = read_u64(image, opt + 24)?;
    let dir_count: u32 = read_u32(image, opt + 108)?;
    let import_dir_rva: u64 = if dir_count > 1 {
        u64::from(read_u32(image, opt + 120)?)
    } else {
        0
    };
    let exception_dir_rva: u64 = if dir_count > 3 {
        u64::from(read_u32(image, opt + 136)?)
    } else {
        0
    };
    let exception_dir_size: u32 = if dir_count > 3 {
        read_u32(image, opt + 140)?
    } else {
        0
    };
    let section_table: usize = opt + opt_size;
    let mut sections: Vec<Section> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sh: usize = section_table + i * 40;
        let raw_name: &[u8] = image.get(sh..sh + 8)?;
        let name_end: usize = raw_name.iter().position(|&b: &u8| b == 0).unwrap_or(8);
        let name: String = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        sections.push(Section {
            name,
            virtual_size: read_u32(image, sh + 8)?,
            virtual_address: u64::from(read_u32(image, sh + 12)?),
            raw_size: read_u32(image, sh + 16)?,
            raw_ptr: read_u32(image, sh + 20)?,
        });
    }

    let rva_to_off = |rva: u64| -> Option<usize> {
        for s in &sections {
            let span: u64 = u64::from(s.virtual_size.max(s.raw_size));
            if rva >= s.virtual_address && rva < s.virtual_address + span {
                let delta: u64 = rva - s.virtual_address;
                if delta >= u64::from(s.raw_size) {
                    return None;
                }
                return usize::try_from(u64::from(s.raw_ptr) + delta).ok();
            }
        }
        None
    };

    let text_section: &Section = sections
        .iter()
        .filter(|s: &&Section| s.name.starts_with(".text") && s.raw_size > 0)
        .max_by_key(|s: &&Section| s.raw_size)?;
    let text_off: usize = text_section.raw_ptr as usize;
    let text_len: usize = (text_section.raw_size as usize).min(MAX_TEXT_BYTES);
    let text: Vec<u8> = image.get(text_off..text_off + text_len)?.to_vec();
    let text_base: u64 = image_base + text_section.virtual_address;

    let functions: Vec<(u64, u64)> = parse_pdata(
        image,
        image_base,
        exception_dir_rva,
        exception_dir_size,
        &rva_to_off,
    );
    let function_begins: BTreeSet<u64> = functions.iter().map(|(b, _): &(u64, u64)| *b).collect();
    let iat: BTreeMap<u64, String> = parse_imports(image, image_base, import_dir_rva, &rva_to_off);

    Some(PeView {
        text_base,
        text,
        functions,
        function_begins,
        iat,
    })
}

fn parse_pdata(
    image: &[u8],
    image_base: u64,
    dir_rva: u64,
    dir_size: u32,
    rva_to_off: &impl Fn(u64) -> Option<usize>,
) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    if dir_rva == 0 || dir_size == 0 {
        return out;
    }
    let Some(base_off): Option<usize> = rva_to_off(dir_rva) else {
        return out;
    };
    let count: usize = (dir_size as usize / 12).min(MAX_FUNCTIONS);
    for i in 0..count {
        let at: usize = base_off + i * 12;
        let (Some(begin), Some(end)): (Option<u32>, Option<u32>) =
            (read_u32(image, at), read_u32(image, at + 4))
        else {
            break;
        };
        if begin != 0 && end > begin {
            out.push((image_base + u64::from(begin), image_base + u64::from(end)));
        }
    }
    out
}

fn parse_imports(
    image: &[u8],
    image_base: u64,
    dir_rva: u64,
    rva_to_off: &impl Fn(u64) -> Option<usize>,
) -> BTreeMap<u64, String> {
    let mut iat: BTreeMap<u64, String> = BTreeMap::new();
    if dir_rva == 0 {
        return iat;
    }
    let Some(mut desc_off): Option<usize> = rva_to_off(dir_rva) else {
        return iat;
    };
    for _ in 0..4096 {
        let (Some(original_first_thunk), Some(first_thunk)): (Option<u32>, Option<u32>) =
            (read_u32(image, desc_off), read_u32(image, desc_off + 16))
        else {
            break;
        };
        if original_first_thunk == 0 && first_thunk == 0 {
            break;
        }
        let lookup_rva: u32 = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        collect_import_thunks(
            image,
            image_base,
            lookup_rva,
            first_thunk,
            rva_to_off,
            &mut iat,
        );
        desc_off += 20;
        if iat.len() >= 200_000 {
            break;
        }
    }
    iat
}

fn collect_import_thunks(
    image: &[u8],
    image_base: u64,
    lookup_rva: u32,
    first_thunk_rva: u32,
    rva_to_off: &impl Fn(u64) -> Option<usize>,
    iat: &mut BTreeMap<u64, String>,
) {
    let (Some(mut lookup_off), Some(_)): (Option<usize>, Option<usize>) = (
        rva_to_off(u64::from(lookup_rva)),
        rva_to_off(u64::from(first_thunk_rva)),
    ) else {
        return;
    };
    let mut slot_va: u64 = image_base + u64::from(first_thunk_rva);
    for _ in 0..100_000 {
        let Some(entry): Option<u64> = read_u64(image, lookup_off) else {
            break;
        };
        if entry == 0 {
            break;
        }
        if entry & (1u64 << 63) == 0 {
            let hint_name_rva: u64 = entry & 0x7fff_ffff;
            if let Some(name_off) = rva_to_off(hint_name_rva + 2)
                && let Some(name) = read_ascii(image, name_off)
            {
                iat.insert(slot_va, name);
            }
        }
        lookup_off += 8;
        slot_va += 8;
    }
}

fn read_ascii(image: &[u8], off: usize) -> Option<String> {
    let slice: &[u8] = image.get(off..off + 256)?;
    let end: usize = slice.iter().position(|&b: &u8| b == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&slice[..end]).ok().map(str::to_owned)
}

fn rip_target(insn: &Instruction) -> Option<u64> {
    insn.is_ip_rel_memory_operand()
        .then(|| insn.ip_rel_memory_address())
}

fn direct_branch_target(insn: &Instruction) -> Option<u64> {
    matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| insn.near_branch_target())
}

fn decode_function(view: &PeView, begin: u64, end: u64) -> Vec<Instruction> {
    let start: usize = match usize::try_from(begin.saturating_sub(view.text_base)) {
        Ok(v) if v < view.text.len() => v,
        _ => return Vec::new(),
    };
    let stop: usize = usize::try_from(end.saturating_sub(view.text_base))
        .unwrap_or(view.text.len())
        .min(view.text.len());
    if stop <= start {
        return Vec::new();
    }
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(64, &view.text[start..stop], begin, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() && out.len() < MAX_IMPL_INSNS {
        decoder.decode_out(&mut insn);
        out.push(insn);
    }
    out
}

fn resolve_thunk(view: &PeView, target: u64) -> Option<String> {
    let insns: Vec<Instruction> = decode_function(view, target, target + 8);
    let first: &Instruction = insns.first()?;
    if first.mnemonic() == Mnemonic::Jmp
        && let Some(slot) = rip_target(first)
    {
        return view.iat.get(&slot).cloned();
    }
    None
}

fn call_import_name(view: &PeView, insn: &Instruction) -> Option<String> {
    if let Some(slot) = rip_target(insn)
        && let Some(name) = view.iat.get(&slot)
    {
        return Some(name.clone());
    }
    let target: u64 = direct_branch_target(insn)?;
    resolve_thunk(view, target)
}

struct CtorSite {
    site: u64,
    impl_address: u64,
    callee: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocatedImpl {
    address: u64,
    host: u64,
    constructor: u64,
}

#[derive(Debug, Clone, Default)]
struct ImplSites {
    impls: Vec<LocatedImpl>,
    primary_host_impls: Vec<u64>,
    constructors: Vec<u64>,
    hosts: usize,
    decode_budget_exhausted: bool,
}

fn collect_ctor_sites(view: &PeView) -> (BTreeMap<u64, Vec<CtorSite>>, BTreeSet<u64>, bool) {
    let mut callee_impls: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut per_host: BTreeMap<u64, Vec<CtorSite>> = BTreeMap::new();
    let mut decoded: usize = 0;
    let mut exhausted: bool = false;

    for &(begin, end) in &view.functions {
        if decoded >= MAX_ENUMERATION_INSNS {
            exhausted = true;
            break;
        }
        let insns: Vec<Instruction> = decode_function(view, begin, end);
        decoded = decoded.saturating_add(insns.len());
        for (index, insn) in insns.iter().enumerate() {
            if insn.mnemonic() != Mnemonic::Lea {
                continue;
            }
            let Some(target): Option<u64> = rip_target(insn) else {
                continue;
            };
            if !view.function_begins.contains(&target) {
                continue;
            }
            let upper: usize = (index + CTOR_WINDOW).min(insns.len());
            for follow in &insns[index + 1..upper] {
                if follow.flow_control() == FlowControl::Return {
                    break;
                }
                if follow.mnemonic() == Mnemonic::Call
                    && let Some(callee) = direct_branch_target(follow)
                    && view.function_begins.contains(&callee)
                {
                    callee_impls.entry(callee).or_default().insert(target);
                    per_host.entry(begin).or_default().push(CtorSite {
                        site: insn.ip(),
                        impl_address: target,
                        callee,
                    });
                    break;
                }
            }
        }
    }

    let constructors: BTreeSet<u64> = callee_impls
        .iter()
        .filter(|(_, impls): &(&u64, &BTreeSet<u64>)| impls.len() >= MIN_CONSTRUCTOR_IMPLS)
        .map(|(callee, _): (&u64, &BTreeSet<u64>)| *callee)
        .collect();
    (per_host, constructors, exhausted)
}

fn ordered_host_impls<'a>(
    sites: &'a [CtorSite],
    constructors: &BTreeSet<u64>,
) -> Vec<&'a CtorSite> {
    let mut matching: Vec<&CtorSite> = sites
        .iter()
        .filter(|site: &&CtorSite| constructors.contains(&site.callee))
        .collect();
    matching.sort_by_key(|site: &&CtorSite| site.site);
    matching
}

fn locate_impls(view: &PeView) -> ImplSites {
    let (per_host, constructors, decode_budget_exhausted): (
        BTreeMap<u64, Vec<CtorSite>>,
        BTreeSet<u64>,
        bool,
    ) = collect_ctor_sites(view);
    if constructors.is_empty() {
        return ImplSites {
            decode_budget_exhausted,
            ..ImplSites::default()
        };
    }

    let mut hosts: usize = 0;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut impls: Vec<LocatedImpl> = Vec::new();
    for (&host, sites) in &per_host {
        let matching: Vec<&CtorSite> = ordered_host_impls(sites, &constructors);
        if matching.is_empty() {
            continue;
        }
        let before: usize = impls.len();
        for site in matching {
            if impls.len() >= MAX_FUNCTIONS {
                break;
            }
            if seen.insert(site.impl_address) {
                impls.push(LocatedImpl {
                    address: site.impl_address,
                    host,
                    constructor: site.callee,
                });
            }
        }
        if impls.len() > before {
            hosts += 1;
        }
    }

    let primary_host: Option<u64> = per_host
        .iter()
        .map(|(host, sites): (&u64, &Vec<CtorSite>)| {
            (*host, ordered_host_impls(sites, &constructors).len())
        })
        .filter(|(_, count): &(u64, usize)| *count > 0)
        .max_by_key(|(_, count): &(u64, usize)| *count)
        .map(|(host, _): (u64, usize)| host);
    let primary_host_impls: Vec<u64> = primary_host
        .and_then(|host: u64| per_host.get(&host))
        .map(|sites: &Vec<CtorSite>| {
            let mut seen_primary: BTreeSet<u64> = BTreeSet::new();
            ordered_host_impls(sites, &constructors)
                .into_iter()
                .filter(|site: &&CtorSite| seen_primary.insert(site.impl_address))
                .map(|site: &CtorSite| site.impl_address)
                .collect()
        })
        .unwrap_or_default();

    ImplSites {
        impls,
        primary_host_impls,
        constructors: constructors.into_iter().collect(),
        hosts,
        decode_budget_exhausted,
    }
}

fn user_code_objects(constants: &NuitkaConstants) -> Vec<CodeObjectMeta> {
    let mut out: Vec<CodeObjectMeta> = Vec::new();
    for module in &constants.modules {
        for code in &module.code_objects {
            if code.name.starts_with('<') {
                continue;
            }
            out.push(code.clone());
        }
    }
    out
}

fn trace_ops(view: &PeView, insns: &[Instruction]) -> (Vec<NativeOp>, ReturnOrigin) {
    let mut ops: Vec<NativeOp> = Vec::new();
    let mut origin: BTreeMap<u32, ReturnOrigin> = BTreeMap::new();
    let mut pars_reg_dirty: bool = false;
    let mut last_small_imm: Option<u32> = None;
    let mut rax_origin: ReturnOrigin = ReturnOrigin::Unknown;

    for insn in insns {
        capture_small_imm(insn, &mut last_small_imm);
        match insn.mnemonic() {
            Mnemonic::Lea | Mnemonic::Mov => {
                handle_move(view, insn, &mut origin, &mut pars_reg_dirty, &mut ops);
            }
            Mnemonic::Call => {
                if let Some(name) = call_import_name(view, insn) {
                    classify_call(&name, last_small_imm, &mut ops);
                }
                if insn.op0_kind() == OpKind::Register {
                    origin.insert(full(insn.op0_register()) as u32, ReturnOrigin::Other);
                }
                origin.insert(Register::RAX as u32, ReturnOrigin::Other);
            }
            _ => {
                if insn.op_count() > 0
                    && insn.op0_kind() == OpKind::Register
                    && writes_operand0(insn.mnemonic())
                {
                    let reg: Register = full(insn.op0_register());
                    if reg == Register::R8 {
                        pars_reg_dirty = true;
                    }
                    origin.insert(reg as u32, ReturnOrigin::Other);
                }
            }
        }
        if insn.flow_control() == FlowControl::Return {
            ops.push(NativeOp::Return);
            rax_origin = origin
                .get(&(Register::RAX as u32))
                .copied()
                .unwrap_or(ReturnOrigin::Unknown);
        }
    }
    (ops, rax_origin)
}

fn capture_small_imm(insn: &Instruction, last: &mut Option<u32>) {
    let count: u32 = insn.op_count();
    for i in 0..count {
        if matches!(
            insn.op_kind(i),
            OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32
        ) {
            let value: u64 = insn.immediate(i);
            if value <= 5 {
                *last = Some(value as u32);
            }
        }
    }
}

fn handle_move(
    view: &PeView,
    insn: &Instruction,
    origin: &mut BTreeMap<u32, ReturnOrigin>,
    pars_reg_dirty: &mut bool,
    ops: &mut Vec<NativeOp>,
) {
    if insn.op0_kind() != OpKind::Register {
        if insn.op0_register() == Register::R8 || insn.memory_base() == Register::R8 {
            *pars_reg_dirty = true;
        }
        return;
    }
    let dest: Register = full(insn.op0_register());
    if insn.mnemonic() == Mnemonic::Mov && insn.op1_kind() == OpKind::Register {
        let src: Register = full(insn.op1_register());
        let value: ReturnOrigin = origin
            .get(&(src as u32))
            .copied()
            .unwrap_or(ReturnOrigin::Other);
        origin.insert(dest as u32, value);
        if dest == Register::R8 {
            *pars_reg_dirty = true;
        }
        return;
    }
    if insn.mnemonic() == Mnemonic::Mov && insn.op1_kind() == OpKind::Memory {
        if insn.memory_base() == Register::R8
            && insn.memory_index() == Register::None
            && !*pars_reg_dirty
        {
            let disp: u64 = insn.memory_displacement64();
            if disp.is_multiple_of(8) && disp < 512 {
                let index: usize = (disp / 8) as usize;
                ops.push(NativeOp::ParamLoad { index });
                origin.insert(dest as u32, ReturnOrigin::Param(index));
                if dest == Register::R8 {
                    *pars_reg_dirty = true;
                }
                return;
            }
        }
        if let Some(slot) = rip_target(insn) {
            if view
                .iat
                .get(&slot)
                .is_some_and(|n: &String| n == "_Py_NoneStruct")
            {
                ops.push(NativeOp::NoneLoad);
                origin.insert(dest as u32, ReturnOrigin::NoneConst);
                if dest == Register::R8 {
                    *pars_reg_dirty = true;
                }
                return;
            }
            origin.insert(dest as u32, ReturnOrigin::Other);
            if dest == Register::R8 {
                *pars_reg_dirty = true;
            }
            return;
        }
    }
    origin.insert(dest as u32, ReturnOrigin::Other);
    if dest == Register::R8 {
        *pars_reg_dirty = true;
    }
}

fn classify_call(name: &str, last_small_imm: Option<u32>, ops: &mut Vec<NativeOp>) {
    match name {
        "PyObject_RichCompare" | "PyObject_RichCompareBool" => {
            let predicate: Option<CmpOpKind> = last_small_imm.and_then(predicate_from_imm);
            ops.push(NativeOp::RichCompare { predicate });
        }
        "PyObject_GetIter" => ops.push(NativeOp::Iterate),
        "PyIter_Next" | "PyIter_Send" => ops.push(NativeOp::IterNext),
        "PyObject_GetAttr" | "PyObject_GetAttrString" => ops.push(NativeOp::Attribute),
        "PyObject_GetItem" => ops.push(NativeOp::Subscript),
        "PyObject_Call"
        | "PyObject_CallFunctionObjArgs"
        | "PyObject_CallMethodObjArgs"
        | "PyObject_Vectorcall"
        | "PyObject_VectorcallMethod" => ops.push(NativeOp::Call {
            callee: name.to_owned(),
        }),
        _ => {}
    }
}

const fn predicate_from_imm(imm: u32) -> Option<CmpOpKind> {
    Some(match imm {
        0 => CmpOpKind::Lt,
        1 => CmpOpKind::Le,
        2 => CmpOpKind::Eq,
        3 => CmpOpKind::Ne,
        4 => CmpOpKind::Gt,
        5 => CmpOpKind::Ge,
        _ => return None,
    })
}

const fn writes_operand0(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Lea
            | Mnemonic::Movzx
            | Mnemonic::Movsx
            | Mnemonic::Imul
            | Mnemonic::Pop
            | Mnemonic::Setne
            | Mnemonic::Sete
    )
}

fn full(register: Register) -> Register {
    register.full_register()
}

fn reconstruct(
    ops: &[NativeOp],
    return_origin: ReturnOrigin,
    params: &[String],
) -> (Vec<PythonStmt>, LiftFidelity, String) {
    let has_control_ops: bool = ops.iter().any(|op: &NativeOp| {
        matches!(
            op,
            NativeOp::RichCompare { .. }
                | NativeOp::Iterate
                | NativeOp::IterNext
                | NativeOp::Attribute
                | NativeOp::Subscript
                | NativeOp::Call { .. }
        )
    });
    let return_count: usize = ops
        .iter()
        .filter(|op: &&NativeOp| matches!(op, NativeOp::Return))
        .count();
    let single_return: bool = return_count <= 1;

    match return_origin {
        ReturnOrigin::Param(index) if !has_control_ops && single_return => {
            let Some(name): Option<&String> = params.get(index) else {
                return (Vec::new(), LiftFidelity::PartialBody, marker(ops));
            };
            (
                vec![PythonStmt::Return(PythonExpr::Name(name.clone()))],
                LiftFidelity::FullBody,
                "native: pass-through return of parameter recovered from the impl dataflow"
                    .to_owned(),
            )
        }
        ReturnOrigin::NoneConst if !has_control_ops && single_return => (
            vec![PythonStmt::Return(PythonExpr::Const("None".to_owned()))],
            LiftFidelity::FullBody,
            "native: unconditional `return None` recovered from the impl dataflow".to_owned(),
        ),
        _ => (Vec::new(), LiftFidelity::PartialBody, marker(ops)),
    }
}

fn inferred_argcount(ops: &[NativeOp], return_origin: ReturnOrigin) -> usize {
    let mut max_index: Option<usize> = None;
    for op in ops {
        if let NativeOp::ParamLoad { index } = op {
            max_index = Some(max_index.map_or(*index, |m: usize| m.max(*index)));
        }
    }
    if let ReturnOrigin::Param(index) = return_origin {
        max_index = Some(max_index.map_or(index, |m: usize| m.max(index)));
    }
    max_index.map_or(0, |m: usize| m + 1)
}

fn positional_params(count: usize) -> Vec<String> {
    (0..count).map(|i: usize| format!("arg{i}")).collect()
}

fn marker(ops: &[NativeOp]) -> String {
    let mut summary: Vec<&str> = Vec::new();
    for op in ops {
        let label: &str = match op {
            NativeOp::RichCompare { .. } => "compare",
            NativeOp::Iterate | NativeOp::IterNext => "iterate",
            NativeOp::Attribute => "attribute",
            NativeOp::Subscript => "subscript",
            NativeOp::Call { .. } => "call",
            NativeOp::ParamLoad { .. }
            | NativeOp::NoneLoad
            | NativeOp::ConstSlotLoad { .. }
            | NativeOp::Return => continue,
        };
        if !summary.contains(&label) {
            summary.push(label);
        }
    }
    if summary.is_empty() {
        "native: no invertible idiom recognized in the specialized machine code".to_owned()
    } else {
        format!(
            "native: recognized {} operation(s); full control-flow reconstruction is bounded by \
             MSVC -O2 helper specialization",
            summary.join(", ")
        )
    }
}

fn collect_api_calls(view: &PeView, insns: &[Instruction]) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for insn in insns {
        if names.len() >= MAX_API_CALLS {
            break;
        }
        if insn.mnemonic() != Mnemonic::Call {
            continue;
        }
        if let Some(name) = call_import_name(view, insn) {
            names.insert(name);
        }
    }
    names.into_iter().collect()
}

fn imports_cpython_api(view: &PeView) -> bool {
    view.iat
        .values()
        .any(|name: &String| name.starts_with("Py") || name.starts_with("_Py"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingPlan {
    Union,
    PrimaryHost,
    None,
}

const fn plan_binding(sites: &ImplSites, codes: &[CodeObjectMeta]) -> BindingPlan {
    if codes.is_empty() {
        return BindingPlan::None;
    }
    if sites.impls.len() == codes.len() {
        return BindingPlan::Union;
    }
    if sites.primary_host_impls.len() == codes.len() {
        return BindingPlan::PrimaryHost;
    }
    BindingPlan::None
}

#[must_use]
pub fn lift_native_bodies(
    image: &[u8],
    constants: Option<&NuitkaConstants>,
) -> Option<NativeBodyRecovery> {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("native-body");
    let view: PeView = parse_pe(image)?;
    if view.text.is_empty() || view.functions.is_empty() {
        return None;
    }
    if constants.is_none() && !imports_cpython_api(&view) {
        dbg.line(|| {
            "native body lift: no constants chunk parsed and no CPython C-API import in this \
             image, so it is not treated as a compiled-Python module"
                .to_owned()
        });
        return None;
    }
    let sites: ImplSites = locate_impls(&view);
    if sites.impls.is_empty() {
        return None;
    }
    let codes: Vec<CodeObjectMeta> = constants.map(user_code_objects).unwrap_or_default();
    let plan: BindingPlan = plan_binding(&sites, &codes);
    let primary_order: BTreeMap<u64, usize> = match plan {
        BindingPlan::PrimaryHost => sites
            .primary_host_impls
            .iter()
            .enumerate()
            .map(|(order, address): (usize, &u64)| (*address, order))
            .collect(),
        BindingPlan::Union | BindingPlan::None => BTreeMap::new(),
    };

    let mut functions: Vec<NativeFunctionBody> = Vec::new();
    let mut reconstructed: usize = 0;
    let end_of: BTreeMap<u64, u64> = view.functions.iter().copied().collect();

    for (index, located) in sites.impls.iter().enumerate() {
        let Some(&end): Option<&u64> = end_of.get(&located.address) else {
            continue;
        };
        let insns: Vec<Instruction> = decode_function(&view, located.address, end);
        if insns.is_empty() {
            continue;
        }
        let (ops, return_origin): (Vec<NativeOp>, ReturnOrigin) = trace_ops(&view, &insns);
        let code: Option<&CodeObjectMeta> = match plan {
            BindingPlan::Union => codes.get(index),
            BindingPlan::PrimaryHost => primary_order
                .get(&located.address)
                .and_then(|order: &usize| codes.get(*order)),
            BindingPlan::None => None,
        };
        let traced_argcount: usize = inferred_argcount(&ops, return_origin);
        let (name, qualname, kind, name_binding): (String, String, CodeKind, NameBinding) = code
            .map_or_else(
                || {
                    let label: String = format!("native_impl_{index}");
                    (
                        label.clone(),
                        label,
                        CodeKind::Function,
                        NameBinding::Positional,
                    )
                },
                |c: &CodeObjectMeta| {
                    (
                        c.name.clone(),
                        c.qualname.clone().unwrap_or_else(|| c.name.clone()),
                        c.kind,
                        NameBinding::CodeObject,
                    )
                },
            );
        let params: Vec<String> = match code {
            Some(c) if !c.varnames.is_empty() => c
                .varnames
                .iter()
                .take((c.argcount as usize).max(traced_argcount))
                .cloned()
                .collect(),
            _ => positional_params(traced_argcount),
        };
        let argcount: u32 = u32::try_from(params.len()).unwrap_or(0);
        let (recovered_stmts, fidelity, note): (Vec<PythonStmt>, LiftFidelity, String) =
            reconstruct(&ops, return_origin, &params);
        if !recovered_stmts.is_empty() {
            reconstructed += 1;
        }
        functions.push(NativeFunctionBody {
            name,
            qualname,
            impl_address: located.address,
            constructed_in: located.host,
            constructor: located.constructor,
            code_size: end.saturating_sub(located.address),
            argcount,
            varnames: params,
            kind,
            name_binding,
            api_calls: collect_api_calls(&view, &insns),
            ops,
            instruction_count: insns.len() as u64,
            recovered_stmts,
            fidelity,
            reconstruction_note: note,
        });
    }

    if functions.is_empty() {
        return None;
    }

    let bound: usize = functions
        .iter()
        .filter(|f: &&NativeFunctionBody| f.is_name_bound())
        .count();
    let notes: Vec<String> = build_notes(&sites, &codes, plan, bound, reconstructed);
    dbg.kv("located impls", || sites.impls.len().to_string());
    dbg.kv("host functions", || sites.hosts.to_string());
    dbg.kv("reconstructed", || reconstructed.to_string());

    Some(NativeBodyRecovery {
        module_name: constants
            .and_then(|c: &NuitkaConstants| c.modules.first())
            .map(|m: &crate::const_blob::ModuleConstants| m.name.clone())
            .unwrap_or_default(),
        located_impls: sites.impls.len(),
        host_functions: sites.hosts,
        constructors: sites.constructors,
        bound_functions: bound,
        reconstructed_bodies: reconstructed,
        functions,
        notes,
    })
}

fn build_notes(
    sites: &ImplSites,
    codes: &[CodeObjectMeta],
    plan: BindingPlan,
    bound: usize,
    reconstructed: usize,
) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    notes.push(format!(
        "native body lift: located {} function impl(s) via the Nuitka function-constructor \
         cross-reference across {} constructing function(s) and {} constructor(s); bound {} to \
         recovered code-object metadata; reconstructed {} executable body/bodies for \
         provably-sound idioms (pass-through / `return None`)",
        sites.impls.len(),
        sites.hosts,
        sites.constructors.len(),
        bound,
        reconstructed
    ));
    notes.push(
        "native body lift: operator identity, control flow, and per-slot constant values are \
         specialized into type-slot dispatch by the optimizing C compiler, so remaining functions \
         surface an operation trace and the resolved CPython C-API call set rather than an \
         invented body"
            .to_owned(),
    );
    match plan {
        BindingPlan::Union => {}
        BindingPlan::PrimaryHost => notes.push(format!(
            "native body lift: {} of the {} located impl(s) come from the largest constructing \
             function and match the {} recovered user code object(s) one to one, so only those \
             carry code-object names; the remaining impl(s) are reported positionally",
            sites.primary_host_impls.len(),
            sites.impls.len(),
            codes.len()
        )),
        BindingPlan::None => notes.push(format!(
            "native body lift: located {} impl(s) but the image carries {} user code object(s); \
             the source-order binding is not certain, so impls are reported positionally with an \
             operation trace and no name-bound executable body",
            sites.impls.len(),
            codes.len()
        )),
    }
    if sites.decode_budget_exhausted {
        notes.push(format!(
            "native body lift: the constructor cross-reference stopped at the {MAX_ENUMERATION_INSNS} \
             instruction decode budget, so impl enumeration over this image is partial"
        ));
    }
    notes
}
