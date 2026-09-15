use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::num::TryFromIntError;

#[cfg(not(target_arch = "wasm32"))]
use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoAbi, ResolvedCall, disassemble, recover_aarch64_function,
    recover_aarch64_function_with_calls, recover_leaf_function_abi,
    recover_leaf_function_with_calls,
};

use crate::error::Error;
use crate::error::Result;
use crate::v8v9::BccArch;

#[cfg(not(target_arch = "wasm32"))]
const SHT_PROGBITS: u32 = 1;
#[cfg(not(target_arch = "wasm32"))]
const SHF_ALLOC: u64 = 0x2;
#[cfg(not(target_arch = "wasm32"))]
const SHF_EXECINSTR: u64 = 0x4;
#[cfg(not(target_arch = "wasm32"))]
const SHF_STRINGS: u64 = 0x20;
#[cfg(not(target_arch = "wasm32"))]
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
#[cfg(not(target_arch = "wasm32"))]
const MAX_FUNCTIONS: usize = 4096;
#[cfg(not(target_arch = "wasm32"))]
const MAX_DISASM_LINES: usize = 4096;
#[cfg(not(target_arch = "wasm32"))]
const MIN_STRING_LEN: usize = 4;
#[cfg(not(target_arch = "wasm32"))]
const MAX_CALL_TARGETS_SCANNED: usize = 1024;
#[cfg(not(target_arch = "wasm32"))]
const MAX_RESOLVED_CALLS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunctionNameSource {
    DispatchDescriptor,
    EntryAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionId {
    pub entry_va: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoCFunction {
    pub id: FunctionId,
    pub signature: String,
    pub pseudo_c: String,
    pub size: u32,
    pub parameter_count: u32,
    pub modeled: bool,
    pub note: Option<String>,
    pub name_source: FunctionNameSource,
    pub resolved_callees: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccLiftOutput {
    pub architecture: BccArch,
    pub text_base: u64,
    pub functions: BTreeMap<FunctionId, PseudoCFunction>,
    pub function_records: Vec<PseudoCFunction>,
    pub modeled_count: usize,
    pub unmodeled_count: usize,
    pub strings: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccLiftRefusal {
    pub blob_index: usize,
    pub architecture: BccArch,
    pub reason: BccLiftRefusalReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BccLiftRefusalReason {
    UnsupportedArchitecture { id: u32 },
    NativeLiftUnavailable { target: String },
    LiftFailed { message: String },
}

impl BccLiftRefusalReason {
    pub(crate) fn from_error(error: &Error) -> Self {
        match error {
            Error::BccUnsupportedArchitecture { id } => Self::UnsupportedArchitecture { id: *id },
            Error::BccLiftUnavailable { target } => Self::NativeLiftUnavailable {
                target: target.clone(),
            },
            _ => Self::LiftFailed {
                message: error.to_string(),
            },
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedArchitecture { .. } => "unsupported_architecture",
            Self::NativeLiftUnavailable { .. } => "native_lift_unavailable",
            Self::LiftFailed { .. } => "lift_failed",
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeTarget {
    arch: Arch,
    abi: PseudoAbi,
}

#[cfg(target_arch = "wasm32")]
pub fn lift_bcc_native(_blob: &[u8], _arch: BccArch) -> Result<BccLiftOutput> {
    Err(crate::error::Error::BccLiftUnavailable {
        target: "wasm32".to_owned(),
    })
}

#[cfg(target_arch = "wasm32")]
pub fn lift_bcc_code_region(
    _code: &[u8],
    _base: u64,
    _arch: BccArch,
) -> Result<Vec<PseudoCFunction>> {
    Err(Error::BccLiftUnavailable {
        target: "wasm32".to_owned(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
struct ExecutableImage {
    base: u64,
    code: Vec<u8>,
    strings: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn lift_bcc_native(blob: &[u8], arch: BccArch) -> Result<BccLiftOutput> {
    if blob.is_empty() {
        return Err(Error::BccLiftEmptyBlob);
    }
    let target: NativeTarget = arch_to_target(arch)?;

    let image: ExecutableImage = extract_executable_image(blob)?;
    let roster: Vec<RosterEntry> = roster_from_dispatch(blob, arch, image.base, image.code.len());
    let functions: Vec<PseudoCFunction> =
        lift_code_region_with_roster(&image.code, image.base, target, &roster);

    let carved_count: usize = functions.len();
    let mut map: BTreeMap<FunctionId, PseudoCFunction> = BTreeMap::new();
    for func in &functions {
        let identity: FunctionId = func.id.clone();
        map.entry(identity).or_insert_with(|| func.clone());
    }
    let modeled_count: usize = functions
        .iter()
        .filter(|func: &&PseudoCFunction| func.modeled)
        .count();
    let unmodeled_count: usize = carved_count.checked_sub(modeled_count).ok_or_else(|| {
        Error::BccPublicationAccountingMismatch {
            detail: format!(
                "modeled count {modeled_count} exceeds carved function count {carved_count}"
            ),
        }
    })?;

    let mut notes: Vec<String> = Vec::new();
    if modeled_count == 0 && unmodeled_count > 0 {
        notes.push(
            "every discovered BCC function delegates to the PyArmor/CPython runtime dispatch table via indirect calls; native disassembly is surfaced per function, but the object semantics are resolved at load time and are not statically standalone-recompilable"
                .to_owned(),
        );
    }

    Ok(BccLiftOutput {
        architecture: arch,
        text_base: image.base,
        functions: map,
        function_records: functions,
        modeled_count,
        unmodeled_count,
        strings: image.strings,
        notes,
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn lift_bcc_code_region(code: &[u8], base: u64, arch: BccArch) -> Result<Vec<PseudoCFunction>> {
    let target: NativeTarget = arch_to_target(arch)?;
    Ok(lift_code_region_with_roster(code, base, target, &[]))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn lift_code_region(code: &[u8], base: u64, abi: PseudoAbi) -> Vec<PseudoCFunction> {
    let target: NativeTarget = target_from_abi(abi);
    lift_code_region_with_roster(code, base, target, &[])
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RosterEntry {
    pub(crate) entry_va: u64,
    pub(crate) end_va: u64,
    pub(crate) name: String,
}

#[cfg(not(target_arch = "wasm32"))]
struct FunctionSite {
    entry_va: u64,
    name: String,
    name_source: FunctionNameSource,
    insn_start: usize,
    insn_end: usize,
    window: Option<(usize, usize, u32)>,
}

#[cfg(not(target_arch = "wasm32"))]
fn lift_code_region_with_roster(
    code: &[u8],
    base: u64,
    target: NativeTarget,
    roster: &[RosterEntry],
) -> Vec<PseudoCFunction> {
    let Ok(insns): std::result::Result<Vec<DisasmInsn>, _> = disassemble(target.arch, base, code)
    else {
        return Vec::new();
    };
    if insns.is_empty() {
        return Vec::new();
    }
    let sites: Vec<FunctionSite> = if roster.is_empty() {
        sites_from_linear_scan(&insns, code, base, 0, insns.len())
    } else {
        sites_from_roster(roster, &insns, code, base)
    };

    let mut probes: BTreeMap<u64, std::result::Result<LeafRecovery, String>> = BTreeMap::new();
    for site in &sites {
        let Some((start_off, end_off, _)): Option<(usize, usize, u32)> = site.window else {
            continue;
        };
        let Some(slice): Option<&[u8]> = code.get(start_off..end_off) else {
            continue;
        };
        let outcome: std::result::Result<LeafRecovery, String> =
            recover_native_function(slice, site.entry_va, target.abi, &[]);
        probes.insert(site.entry_va, outcome);
    }

    let names: BTreeMap<u64, &str> = sites
        .iter()
        .map(|site: &FunctionSite| (site.entry_va, site.name.as_str()))
        .collect();

    let mut out: Vec<PseudoCFunction> = Vec::with_capacity(sites.len());
    for site in &sites {
        let insns_slice: &[DisasmInsn] = insns
            .get(site.insn_start..site.insn_end)
            .unwrap_or_default();
        let Some((start_off, end_off, size)): Option<(usize, usize, u32)> = site.window else {
            out.push(render_declined_function(
                site,
                0,
                insns_slice,
                "BCC function address range exceeds input bytes".to_owned(),
            ));
            continue;
        };
        let Some(slice): Option<&[u8]> = code.get(start_off..end_off) else {
            out.push(render_declined_function(
                site,
                0,
                insns_slice,
                "BCC function address range exceeds input bytes".to_owned(),
            ));
            continue;
        };
        let Some(Ok(probe)): Option<&std::result::Result<LeafRecovery, String>> =
            probes.get(&site.entry_va)
        else {
            let reason: String = probes.get(&site.entry_va).map_or_else(
                || "BCC function body was not probed".to_owned(),
                |outcome: &std::result::Result<LeafRecovery, String>| {
                    outcome.as_ref().err().cloned().unwrap_or_default()
                },
            );
            out.push(render_declined_function(site, size, insns_slice, reason));
            continue;
        };
        let resolved: Vec<ResolvedCall> = resolve_sibling_calls(probe, &names, &probes);
        if resolved.is_empty() {
            out.push(render_modeled_function(site, probe, size, &[], None));
            continue;
        }
        let callees: Vec<String> = resolved
            .iter()
            .filter_map(|call: &ResolvedCall| call.name.clone())
            .collect();
        match recover_native_function(slice, site.entry_va, target.abi, &resolved) {
            Ok(linked) => out.push(render_modeled_function(site, &linked, size, &callees, None)),
            Err(e) => out.push(render_modeled_function(
                site,
                probe,
                size,
                &[],
                Some(format!(
                    "sibling-resolved recovery declined ({e}); the unresolved recovery is surfaced instead"
                )),
            )),
        }
    }
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn recover_native_function(
    code: &[u8],
    base: u64,
    abi: PseudoAbi,
    calls: &[ResolvedCall],
) -> std::result::Result<LeafRecovery, String> {
    let recovered: std::result::Result<LeafRecovery, disrobe_pass_native::error::Error> = match abi
    {
        PseudoAbi::MsX64 | PseudoAbi::SysV if calls.is_empty() => {
            recover_leaf_function_abi(code, base, abi)
        }
        PseudoAbi::MsX64 | PseudoAbi::SysV => {
            recover_leaf_function_with_calls(code, base, abi, calls)
        }
        PseudoAbi::Aapcs64 if calls.is_empty() => recover_aarch64_function(code, base),
        PseudoAbi::Aapcs64 => recover_aarch64_function_with_calls(code, base, calls),
    };
    recovered.map_err(|error: disrobe_pass_native::error::Error| error.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_sibling_calls(
    probe: &LeafRecovery,
    names: &BTreeMap<u64, &str>,
    probes: &BTreeMap<u64, std::result::Result<LeafRecovery, String>>,
) -> Vec<ResolvedCall> {
    let mut resolved: Vec<ResolvedCall> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for target in probe.call_targets.iter().take(MAX_CALL_TARGETS_SCANNED) {
        if resolved.len() >= MAX_RESOLVED_CALLS {
            break;
        }
        if seen.contains(target) {
            continue;
        }
        seen.push(*target);
        let Some(name): Option<&&str> = names.get(target) else {
            continue;
        };
        let Some(Ok(callee)): Option<&std::result::Result<LeafRecovery, String>> =
            probes.get(target)
        else {
            continue;
        };
        resolved.push(ResolvedCall {
            target: *target,
            name: Some((*name).to_owned()),
            signature: callee.signature.clone(),
        });
    }
    resolved
}

#[cfg(not(target_arch = "wasm32"))]
fn sites_from_linear_scan(
    insns: &[DisasmInsn],
    code: &[u8],
    base: u64,
    offset: usize,
    limit: usize,
) -> Vec<FunctionSite> {
    let Some(window): Option<&[DisasmInsn]> = insns.get(offset..limit) else {
        return Vec::new();
    };
    let bounds: Vec<(usize, usize)> = discover_functions(window);
    let mut out: Vec<FunctionSite> = Vec::with_capacity(bounds.len());
    for (start_idx, end_idx) in bounds {
        let Some(first): Option<&DisasmInsn> = window.get(start_idx) else {
            continue;
        };
        let Some(last): Option<&DisasmInsn> =
            end_idx.checked_sub(1).and_then(|i: usize| window.get(i))
        else {
            continue;
        };
        let entry_va: u64 = first.address;
        out.push(FunctionSite {
            entry_va,
            name: format!("sub_{entry_va:x}"),
            name_source: FunctionNameSource::EntryAddress,
            insn_start: offset.saturating_add(start_idx),
            insn_end: offset.saturating_add(end_idx),
            window: byte_window_from_last(code, base, entry_va, last),
        });
    }
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn sites_from_roster(
    roster: &[RosterEntry],
    insns: &[DisasmInsn],
    code: &[u8],
    base: u64,
) -> Vec<FunctionSite> {
    let region_end: u64 = base.saturating_add(u64::try_from(code.len()).unwrap_or(u64::MAX));
    let mut ordered: Vec<&RosterEntry> = roster
        .iter()
        .filter(|entry: &&RosterEntry| {
            entry.entry_va >= base && entry.entry_va < region_end && entry.end_va >= entry.entry_va
        })
        .collect();
    ordered.sort_by_key(|entry: &&RosterEntry| entry.entry_va);

    let mut sites: Vec<FunctionSite> = Vec::with_capacity(ordered.len());
    let mut cursor: u64 = base;
    for (index, entry) in ordered.iter().enumerate() {
        let next_start: u64 = ordered
            .get(index + 1)
            .map_or(region_end, |next: &&RosterEntry| next.entry_va);
        let end_va: u64 = entry.end_va.min(next_start).min(region_end);
        if end_va < entry.entry_va {
            continue;
        }
        if entry.entry_va > cursor {
            let gap_start: usize = insn_index_at_or_after(insns, cursor);
            let gap_end: usize = insn_index_at_or_after(insns, entry.entry_va);
            sites.extend(sites_from_linear_scan(
                insns, code, base, gap_start, gap_end,
            ));
        }
        sites.push(FunctionSite {
            entry_va: entry.entry_va,
            name: entry.name.clone(),
            name_source: FunctionNameSource::DispatchDescriptor,
            insn_start: insn_index_at_or_after(insns, entry.entry_va),
            insn_end: insn_index_at_or_after(insns, end_va),
            window: byte_window_from_range(code, base, entry.entry_va, end_va),
        });
        cursor = end_va;
    }
    if cursor < region_end {
        let gap_start: usize = insn_index_at_or_after(insns, cursor);
        sites.extend(sites_from_linear_scan(
            insns,
            code,
            base,
            gap_start,
            insns.len(),
        ));
    }
    sites.sort_by_key(|site: &FunctionSite| site.entry_va);
    sites
}

#[cfg(not(target_arch = "wasm32"))]
fn insn_index_at_or_after(insns: &[DisasmInsn], va: u64) -> usize {
    insns.partition_point(|insn: &DisasmInsn| insn.address < va)
}

#[cfg(not(target_arch = "wasm32"))]
fn render_modeled_function(
    site: &FunctionSite,
    recovery: &LeafRecovery,
    size: u32,
    callees: &[String],
    note: Option<String>,
) -> PseudoCFunction {
    let parameter_count: u32 = saturating_u32_len(recovery.signature.callable_arity());
    let pseudo_c: String = rename_recovered(recovery, &site.name);
    let signature: String = extract_signature(&pseudo_c, &site.name);
    let mut resolved_callees: Vec<String> = callees.to_vec();
    resolved_callees.sort_unstable();
    resolved_callees.dedup();
    PseudoCFunction {
        id: FunctionId {
            entry_va: site.entry_va,
            name: site.name.clone(),
        },
        signature,
        pseudo_c,
        size,
        parameter_count,
        modeled: true,
        note,
        name_source: site.name_source,
        resolved_callees,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn byte_window_from_last(
    code: &[u8],
    base: u64,
    entry_va: u64,
    last: &DisasmInsn,
) -> Option<(usize, usize, u32)> {
    let last_len: u64 = u64::try_from(last.bytes.len()).ok()?;
    let end_va: u64 = last.address.checked_add(last_len)?;
    byte_window_from_range(code, base, entry_va, end_va)
}

#[cfg(not(target_arch = "wasm32"))]
fn byte_window_from_range(
    code: &[u8],
    base: u64,
    entry_va: u64,
    end_va: u64,
) -> Option<(usize, usize, u32)> {
    let size: u32 = saturating_u32(end_va.checked_sub(entry_va)?);
    let start_delta: u64 = entry_va.checked_sub(base)?;
    let end_delta: u64 = end_va.checked_sub(base)?;
    let start_off: usize = usize::try_from(start_delta).ok()?;
    let end_off: usize = usize::try_from(end_delta).ok()?;
    if end_off > code.len() || start_off >= end_off {
        return None;
    }
    Some((start_off, end_off, size))
}

#[cfg(not(target_arch = "wasm32"))]
fn render_declined_function(
    site: &FunctionSite,
    size: u32,
    insns: &[DisasmInsn],
    reason: String,
) -> PseudoCFunction {
    let name: &str = site.name.as_str();
    let pseudo_c: String = render_unmodeled(name, site.entry_va, insns, &reason);
    PseudoCFunction {
        id: FunctionId {
            entry_va: site.entry_va,
            name: site.name.clone(),
        },
        signature: format!("void {name}(void)"),
        pseudo_c,
        size,
        parameter_count: 0,
        modeled: false,
        note: Some(reason),
        name_source: site.name_source,
        resolved_callees: Vec::new(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn roster_from_dispatch(
    blob: &[u8],
    arch: BccArch,
    base: u64,
    code_len: usize,
) -> Vec<RosterEntry> {
    let region_end: u64 = base.saturating_add(u64::try_from(code_len).unwrap_or(u64::MAX));
    crate::bcc::dispatch::parse_dispatch(blob, arch, 0)
        .into_iter()
        .filter(|entry: &crate::bcc::dispatch::DispatchEntry| {
            entry.code_offset >= base && entry.code_offset < region_end
        })
        .map(|entry: crate::bcc::dispatch::DispatchEntry| RosterEntry {
            entry_va: entry.code_offset,
            end_va: entry.code_offset.saturating_add(entry.size).min(region_end),
            name: entry.name,
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn saturating_u32_len(value: usize) -> u32 {
    let converted: std::result::Result<u32, TryFromIntError> = u32::try_from(value);
    converted.map_or(u32::MAX, |value: u32| value)
}

#[cfg(not(target_arch = "wasm32"))]
fn saturating_u32(value: u64) -> u32 {
    let converted: std::result::Result<u32, TryFromIntError> = u32::try_from(value);
    converted.map_or(u32::MAX, |value: u32| value)
}

#[cfg(not(target_arch = "wasm32"))]
fn rename_recovered(recovery: &LeafRecovery, name: &str) -> String {
    recovery
        .source
        .replacen("recovered(", &format!("{name}("), 1)
}

#[cfg(not(target_arch = "wasm32"))]
fn extract_signature(pseudo_c: &str, name: &str) -> String {
    let needle: String = format!("{name}(");
    pseudo_c
        .lines()
        .find(|line: &&str| line.contains(needle.as_str()))
        .map_or_else(
            || format!("uint64_t {name}(void)"),
            |line: &str| line.trim_end_matches(" {").trim().to_owned(),
        )
}

#[cfg(not(target_arch = "wasm32"))]
fn render_unmodeled(name: &str, entry_va: u64, insns: &[DisasmInsn], reason: &str) -> String {
    let mut out: String = String::new();
    push_format(
        &mut out,
        format_args!("/* {name} @ {entry_va:#x}: in-crate pseudo-C lift declined ({reason}).\n"),
    );
    out.push_str(
        "   BCC compiles CPython bytecode to native code that calls the PyArmor runtime dispatch\n",
    );
    out.push_str(
        "   table indirectly; the recovered semantics live behind load-time-resolved pointers and\n",
    );
    out.push_str(
        "   are not statically standalone-recompilable. Verified native disassembly follows. */\n",
    );
    push_format(&mut out, format_args!("void {name}(void) {{\n"));
    for (i, insn) in insns.iter().enumerate() {
        if i >= MAX_DISASM_LINES {
            push_format(
                &mut out,
                format_args!("    /* ... {} more instructions */\n", insns.len() - i),
            );
            break;
        }
        let rel: u64 = insn.address.saturating_sub(entry_va);
        if insn.operands.is_empty() {
            push_format(
                &mut out,
                format_args!("    /* +{rel:#06x}  {} */\n", insn.mnemonic),
            );
        } else {
            push_format(
                &mut out,
                format_args!(
                    "    /* +{rel:#06x}  {} {} */\n",
                    insn.mnemonic, insn.operands
                ),
            );
        }
    }
    out.push_str("}\n");
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn discover_functions(insns: &[DisasmInsn]) -> Vec<(usize, usize)> {
    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut idx: usize = 0;
    let n: usize = insns.len();
    while idx < n && bounds.len() < MAX_FUNCTIONS {
        while idx < n && is_padding(&insns[idx]) {
            idx += 1;
        }
        if idx >= n {
            break;
        }
        let start: usize = idx;
        let mut max_branch_target: u64 = 0;
        let mut end: Option<usize> = None;
        let mut cursor: usize = idx;
        while cursor < n {
            let insn: &DisasmInsn = &insns[cursor];
            if let Some(target) = branch_target(insn) {
                max_branch_target = max_branch_target.max(target);
            }
            let terminates: bool = insn.address >= max_branch_target
                && (insn.mnemonic == "ret"
                    || (insn.mnemonic == "jmp" && branch_target(insn).is_some()));
            if terminates {
                end = Some(cursor + 1);
                break;
            }
            cursor += 1;
        }
        if let Some(e) = end {
            bounds.push((start, e));
            idx = e;
        } else {
            bounds.push((start, n));
            break;
        }
    }
    bounds
}

#[cfg(not(target_arch = "wasm32"))]
fn is_padding(insn: &DisasmInsn) -> bool {
    insn.mnemonic == "nop" || insn.mnemonic == "int3"
}

#[cfg(not(target_arch = "wasm32"))]
fn branch_target(insn: &DisasmInsn) -> Option<u64> {
    let is_branch: bool =
        insn.mnemonic == "jmp" || (insn.mnemonic.starts_with('j') && insn.mnemonic.len() <= 4);
    if !is_branch {
        return None;
    }
    parse_hex_operand(&insn.operands)
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_hex_operand(operands: &str) -> Option<u64> {
    let trimmed: &str = operands.trim();
    let token: &str = trimmed
        .strip_prefix("short ")
        .map_or(trimmed, |token: &str| token.trim());
    if token.contains([' ', ',', '[']) {
        return None;
    }
    let body_without_suffix: &str = token
        .strip_suffix(['h', 'H'])
        .map_or(token, |body: &str| body);
    let body: &str = body_without_suffix
        .strip_prefix("0x")
        .or_else(|| body_without_suffix.strip_prefix("0X"))
        .map_or(body_without_suffix, |body: &str| body);
    u64::from_str_radix(body, 16).ok()
}

#[cfg(not(target_arch = "wasm32"))]
const fn arch_to_target(arch: BccArch) -> Result<NativeTarget> {
    match arch {
        BccArch::WinX64 => Ok(NativeTarget {
            arch: Arch::X86_64,
            abi: PseudoAbi::MsX64,
        }),
        BccArch::LinuxX64 => Ok(NativeTarget {
            arch: Arch::X86_64,
            abi: PseudoAbi::SysV,
        }),
        BccArch::DarwinArm64 => Ok(NativeTarget {
            arch: Arch::Aarch64,
            abi: PseudoAbi::Aapcs64,
        }),
        BccArch::Other(id) => Err(Error::BccUnsupportedArchitecture { id }),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
const fn target_from_abi(abi: PseudoAbi) -> NativeTarget {
    let arch: Arch = match abi {
        PseudoAbi::MsX64 | PseudoAbi::SysV => Arch::X86_64,
        PseudoAbi::Aapcs64 => Arch::Aarch64,
    };
    NativeTarget { arch, abi }
}

#[cfg(not(target_arch = "wasm32"))]
fn extract_executable_image(blob: &[u8]) -> Result<ExecutableImage> {
    if blob.len() >= 4 && blob[..4] == ELF_MAGIC {
        return parse_elf64(blob);
    }
    parse_via_object(blob)
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_elf64(blob: &[u8]) -> Result<ExecutableImage> {
    if blob.len() < 64 || blob[4] != 2 || blob[5] != 1 {
        return Err(Error::BccLiftParse(
            "not a little-endian ELF64 relocatable object".to_owned(),
        ));
    }
    let e_shoff: usize = usize::try_from(read_u64(blob, 0x28)?).map_err(|_: TryFromIntError| {
        Error::BccLiftParse("ELF section table offset exceeds addressable memory".to_owned())
    })?;
    let e_shentsize: usize = usize::from(read_u16(blob, 0x3a)?);
    let e_shnum: usize = usize::from(read_u16(blob, 0x3c)?);
    if e_shentsize < 64 || e_shnum == 0 {
        return Err(Error::BccLiftParse(
            "degenerate ELF section table".to_owned(),
        ));
    }

    let mut best_exec: Option<(u64, usize, usize)> = None;
    let mut strings: Vec<String> = Vec::new();
    for i in 0..e_shnum {
        let sh: usize = e_shoff
            .checked_add(i.checked_mul(e_shentsize).ok_or_else(section_overflow)?)
            .ok_or_else(section_overflow)?;
        if sh.checked_add(64).is_none_or(|end: usize| end > blob.len()) {
            break;
        }
        let sh_type: u32 = read_u32(blob, sh + 4)?;
        let sh_flags: u64 = read_u64(blob, sh + 8)?;
        let sh_addr: u64 = read_u64(blob, sh + 16)?;
        let sh_offset: usize = match usize::try_from(read_u64(blob, sh + 24)?) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let sh_size: usize = match usize::try_from(read_u64(blob, sh + 32)?) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(section): Option<&[u8]> = sh_offset
            .checked_add(sh_size)
            .and_then(|end: usize| blob.get(sh_offset..end))
        else {
            continue;
        };
        if sh_type == SHT_PROGBITS
            && sh_flags & SHF_EXECINSTR != 0
            && sh_flags & SHF_ALLOC != 0
            && best_exec.is_none_or(|(_, _, best): (u64, usize, usize)| sh_size > best)
        {
            best_exec = Some((sh_addr, sh_offset, sh_size));
        }
        if sh_flags & SHF_STRINGS != 0 {
            strings.extend(carve_c_strings(section));
        }
    }

    let Some((base, offset, size)): Option<(u64, usize, usize)> = best_exec else {
        return Err(Error::BccLiftParse(
            "no executable PROGBITS section in ELF image".to_owned(),
        ));
    };
    let code: Vec<u8> = blob
        .get(offset..offset + size)
        .ok_or_else(|| Error::BccLiftParse("executable section out of range".to_owned()))?
        .to_vec();
    strings.sort_unstable();
    strings.dedup();
    Ok(ExecutableImage {
        base,
        code,
        strings,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_via_object(blob: &[u8]) -> Result<ExecutableImage> {
    use object::{Object as _, ObjectSection as _};
    let file: object::File<'_> =
        object::File::parse(blob).map_err(|e| Error::BccLiftParse(format!("{e}")))?;
    let mut best: Option<(u64, Vec<u8>)> = None;
    let mut strings: Vec<String> = Vec::new();
    for section in file.sections() {
        let Ok(data): std::result::Result<&[u8], _> = section.data() else {
            continue;
        };
        match section.kind() {
            object::SectionKind::Text
                if best
                    .as_ref()
                    .is_none_or(|(_, b): &(u64, Vec<u8>)| data.len() > b.len()) =>
            {
                best = Some((section.address(), data.to_vec()));
            }
            object::SectionKind::ReadOnlyString | object::SectionKind::ReadOnlyData => {
                strings.extend(carve_c_strings(data));
            }
            _ => {}
        }
    }
    let Some((base, code)): Option<(u64, Vec<u8>)> = best else {
        return Err(Error::BccLiftParse(
            "no text section in object image".to_owned(),
        ));
    };
    strings.sort_unstable();
    strings.dedup();
    Ok(ExecutableImage {
        base,
        code,
        strings,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn carve_c_strings(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for chunk in data.split(|b: &u8| *b == 0) {
        if chunk.len() >= MIN_STRING_LEN
            && chunk
                .iter()
                .all(|b: &u8| b.is_ascii_graphic() || *b == b' ')
        {
            out.push(String::from_utf8_lossy(chunk).into_owned());
        }
    }
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn section_overflow() -> Error {
    Error::BccLiftParse("ELF section header offset overflow".to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
fn read_u16(blob: &[u8], off: usize) -> Result<u16> {
    let bytes: [u8; 2] = blob
        .get(off..off + 2)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u16".to_owned()))?;
    Ok(u16::from_le_bytes(bytes))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_u32(blob: &[u8], off: usize) -> Result<u32> {
    let bytes: [u8; 4] = blob
        .get(off..off + 4)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u32".to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_u64(blob: &[u8], off: usize) -> Result<u64> {
    let bytes: [u8; 8] = blob
        .get(off..off + 8)
        .and_then(|s: &[u8]| s.try_into().ok())
        .ok_or_else(|| Error::BccLiftParse("truncated ELF u64".to_owned()))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_returns_specific_error() {
        let err: Error = lift_bcc_native(&[], BccArch::WinX64).unwrap_err();
        assert!(matches!(err, Error::BccLiftEmptyBlob));
    }

    #[test]
    fn aarch64_code_region_uses_the_native_aapcs64_recovery() {
        let code: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xc0, 0x03, 0x5f, 0xd6];
        let out: Vec<PseudoCFunction> =
            lift_bcc_code_region(&code, 0x1000, BccArch::DarwinArm64).expect("ARM64 lift");
        assert_eq!(out.len(), 1);
        assert!(out[0].modeled);
        assert_eq!(out[0].parameter_count, 2);
    }

    #[test]
    fn unknown_architecture_is_not_lifted_as_microsoft_x64() {
        let blob: Vec<u8> = vec![0u8; 64];
        let error: Error = lift_bcc_native(&blob, BccArch::Other(0xdead)).unwrap_err();
        assert!(matches!(
            error,
            Error::BccUnsupportedArchitecture { id: 0xdead }
        ));
    }

    #[test]
    fn non_elf_garbage_errors_with_parse() {
        let blob: Vec<u8> = vec![0x11u8; 128];
        let err: Error = lift_bcc_native(&blob, BccArch::WinX64).unwrap_err();
        assert!(matches!(err, Error::BccLiftParse(_)));
    }

    #[test]
    fn arch_maps_to_expected_abi() {
        assert!(matches!(
            arch_to_target(BccArch::WinX64),
            Ok(NativeTarget {
                arch: Arch::X86_64,
                abi: PseudoAbi::MsX64
            })
        ));
        assert!(matches!(
            arch_to_target(BccArch::LinuxX64),
            Ok(NativeTarget {
                arch: Arch::X86_64,
                abi: PseudoAbi::SysV
            })
        ));
        assert!(matches!(
            arch_to_target(BccArch::DarwinArm64),
            Ok(NativeTarget {
                arch: Arch::Aarch64,
                abi: PseudoAbi::Aapcs64
            })
        ));
        assert!(matches!(
            arch_to_target(BccArch::Other(0xdead)),
            Err(Error::BccUnsupportedArchitecture { id: 0xdead })
        ));
    }

    #[test]
    fn parse_hex_operand_reads_near_targets() {
        assert_eq!(parse_hex_operand("0x1b0"), Some(0x1b0));
        assert_eq!(parse_hex_operand("short 0x7d"), Some(0x7d));
        assert_eq!(parse_hex_operand("1ach"), Some(0x1ac));
        assert_eq!(parse_hex_operand("qword ptr [rax+8]"), None);
        assert_eq!(parse_hex_operand("rax"), None);
    }

    #[test]
    fn discover_functions_splits_ret_and_padding() {
        let mc: &[u8] = &[0x48, 0x01, 0xd0, 0xc3, 0x90, 0x90, 0x48, 0x29, 0xd0, 0xc3];
        let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, 0x1000, mc).unwrap();
        let bounds: Vec<(usize, usize)> = discover_functions(&insns);
        assert_eq!(bounds.len(), 2, "two ret-terminated functions expected");
    }

    #[test]
    fn leaf_add_lifts_and_is_modeled() {
        let mc: &[u8] = &[0x48, 0x8d, 0x04, 0x37, 0xc3];
        let funcs: Vec<PseudoCFunction> = lift_code_region(mc, 0x2000, PseudoAbi::SysV);
        assert_eq!(funcs.len(), 1);
        assert!(
            funcs[0].modeled,
            "lea-based add must lift into the leaf class"
        );
        assert!(funcs[0].pseudo_c.contains("sub_2000("));
        assert!(!funcs[0].pseudo_c.contains("recovered("));
    }

    #[test]
    fn indirect_call_body_is_surfaced_as_unmodeled_disasm() {
        let mc: &[u8] = &[0xff, 0x50, 0x08, 0xc3];
        let funcs: Vec<PseudoCFunction> = lift_code_region(mc, 0x3000, PseudoAbi::MsX64);
        assert_eq!(funcs.len(), 1);
        assert!(!funcs[0].modeled);
        assert!(funcs[0].pseudo_c.contains("call"));
        assert!(funcs[0].note.is_some());
    }

    #[test]
    fn address_overflow_is_surfaced_without_panicking() {
        let mc: &[u8] = &[0xc3];
        let funcs: Vec<PseudoCFunction> = lift_code_region(mc, u64::MAX, PseudoAbi::SysV);
        assert_eq!(funcs.len(), 1);
        assert!(!funcs[0].modeled);
        assert!(matches!(
            funcs[0].note.as_deref(),
            Some("BCC function address range exceeds input bytes")
        ));
    }

    #[test]
    fn carve_c_strings_keeps_printable_runs() {
        let data: &[u8] = b"ab\0hello\0\x01\x02";
        let strings: Vec<String> = carve_c_strings(data);
        assert_eq!(strings, vec!["hello".to_owned()]);
    }
}
