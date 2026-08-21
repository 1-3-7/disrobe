use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::DartFunctionSymbol;
use super::arm64_data::{IntegerOperands, integer_operands};
use super::call_args::DART_ARGUMENT_REGISTERS;
use super::cid_table::matches_version;
use super::dart_graph::DartGraphLimits;
use super::disasm::{Arm64Disassembly, Arm64FlowKind, Arm64Function, Arm64Instruction};
use super::object_pool::{DartPoolLiteral, resolve_pool_literals};
use super::pool_table::{DartPoolTable, DartPoolTableStats, pool_slot_of_offset};
use super::structured::{DartCallArgumentCounts, DartStructuredBody};
use crate::debug::{dbg_kv, dbg_section};
use crate::error::Result;

const POOL_REG: u8 = 27;

const THR_REG: u8 = 26;

const NULL_REG: u8 = 22;

const DISPATCH_TABLE_REG: u8 = 21;

const IC_DATA_REG: u8 = 5;

const SYS_SP_REG: u8 = 31;

const DART_SP_REG: u8 = 15;

const POOL_ENTRY_BYTES: u64 = 8;

const CALL_SETUP_LOOKBACK: usize = 6;

const GUARD_LOOKBACK: usize = 4;

const WRITE_BARRIER_LOOKAHEAD: usize = 3;

const COND_EQ: u8 = 0;

const COND_NE: u8 = 1;

const COND_HS: u8 = 2;

const COND_HI: u8 = 8;

const COND_LS: u8 = 9;

const ARM64_BRK_MASK: u32 = 0xFFE0_001F;

const ARM64_BRK_MATCH: u32 = 0xD420_0000;

#[must_use]
pub(crate) const fn is_arm64_trap(raw: u32) -> bool {
    raw & ARM64_BRK_MASK == ARM64_BRK_MATCH
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartCallKind {
    Static,
    InstanceSwitchable,
    TableDispatch,
    RuntimeStub,
    Closure,
    UnresolvedIndirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCallSite {
    pub address: u64,
    pub kind: DartCallKind,
    pub target_offset: Option<u64>,
    pub target_name: Option<String>,
    pub selector_slot: Option<u64>,
    pub is_self_recursive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartCheckKind {
    NullCheck,
    BoundsCheck,
    StackOverflow,
    WriteBarrier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartElidedCheck {
    pub address: u64,
    pub kind: DartCheckKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartPoolLoadForm {
    Direct,
    ShiftedAdd,
    RegisterOffset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPoolRef {
    pub address: u64,
    pub dest_reg: u8,
    pub slot_index: u64,
    pub form: DartPoolLoadForm,
    pub resolved_content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartUnliftedArm64 {
    pub address: u64,
    pub bytes: u32,
    pub text: String,
}

impl DartUnliftedArm64 {
    #[must_use]
    pub fn to_pseudo_dart(&self) -> String {
        format!(
            "unliftedArm64(address: {:#010x}, bytes: {:#010x}, text: \"{}\");",
            self.address,
            self.bytes,
            escape_dart_string(&self.text)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartLiftedFunction {
    pub offset: usize,
    pub name: Option<String>,
    pub instruction_count: usize,
    pub arg_registers: u8,
    pub calls: Vec<DartCallSite>,
    pub elided_checks: Vec<DartElidedCheck>,
    pub pool_refs: Vec<DartPoolRef>,
    pub inline_double_literals: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlifted_arm64: Vec<DartUnliftedArm64>,
    pub basic_block_count: usize,
    pub conditional_branch_count: usize,
    pub source_conditional_estimate: usize,
    pub has_loop_back_edge: bool,
    pub ends_in_return: bool,
    pub declared_parameter_count: Option<u8>,
    pub inferred_parameter_count: u8,
    pub lifted_statement_count: usize,
    pub unlifted_statement_count: usize,
    pub structured_body: Option<String>,
}

impl DartLiftedFunction {
    #[must_use]
    pub fn static_call_names(&self) -> Vec<&str> {
        self.calls
            .iter()
            .filter(|c: &&DartCallSite| c.kind == DartCallKind::Static)
            .filter_map(|c: &DartCallSite| c.target_name.as_deref())
            .collect::<Vec<&str>>()
    }

    #[must_use]
    pub fn is_structured(&self) -> bool {
        self.structured_body.is_some()
    }

    #[must_use]
    pub fn best_pseudo_dart(&self) -> String {
        self.structured_body
            .clone()
            .unwrap_or_else(|| self.to_pseudo_dart())
    }

    #[must_use]
    pub fn to_pseudo_dart(&self) -> String {
        let mut out: String = String::new();
        let params: String = (0..self.arg_registers)
            .map(|i: u8| format!("arg{i}"))
            .collect::<Vec<String>>()
            .join(", ");
        let label: String = self
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:#010x}", self.offset));
        let _ = writeln!(out, "{label}({params}) {{");
        if self.has_loop_back_edge {
            let _ = writeln!(out, "  loop over {} basic blocks", self.basic_block_count);
        }
        let mut call_index: usize = 0;
        let mut residue_index: usize = 0;
        while call_index < self.calls.len() || residue_index < self.unlifted_arm64.len() {
            let call: Option<&DartCallSite> = self.calls.get(call_index);
            let residue: Option<&DartUnliftedArm64> = self.unlifted_arm64.get(residue_index);
            match (call, residue) {
                (Some(call), Some(residue)) if call.address <= residue.address => {
                    render_call(&mut out, call);
                    call_index = call_index.saturating_add(1);
                }
                (_, Some(residue)) => {
                    let _ = writeln!(out, "  {}", residue.to_pseudo_dart());
                    residue_index = residue_index.saturating_add(1);
                }
                (Some(call), None) => {
                    render_call(&mut out, call);
                    call_index = call_index.saturating_add(1);
                }
                (None, None) => break,
            }
        }
        let _ = writeln!(
            out,
            "  source_conditionals={} (raw={}, elided_checks={})",
            self.source_conditional_estimate,
            self.conditional_branch_count,
            self.elided_checks.len()
        );
        out.push('}');
        out
    }
}

fn render_call(out: &mut String, call: &DartCallSite) {
    match call.kind {
        DartCallKind::Static => {
            let target: &str = call
                .target_name
                .as_deref()
                .map_or("<unnamed>", |name: &str| name);
            let recursion: &str = if call.is_self_recursive {
                " (self-recursive)"
            } else {
                ""
            };
            let _ = writeln!(out, "  {target}(){recursion};");
        }
        DartCallKind::InstanceSwitchable => {
            let _ = writeln!(out, "  receiver.selector@pool[{}]();", slot_or_qm(call));
        }
        DartCallKind::TableDispatch => {
            let _ = writeln!(out, "  dispatch_table[..]();");
        }
        DartCallKind::RuntimeStub => {
            let _ = writeln!(out, "  runtime_stub();");
        }
        DartCallKind::Closure => {
            let _ = writeln!(out, "  closure();");
        }
        DartCallKind::UnresolvedIndirect => {
            let _ = writeln!(out, "  indirect_call();");
        }
    }
}

pub(super) fn escape_dart_string(text: &str) -> String {
    let mut escaped: String = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '$' => escaped.push_str("\\$"),
            other if other.is_control() => {
                let _ = write!(escaped, "\\u{{{:04X}}}", u32::from(other));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

#[must_use]
fn slot_or_qm(call: &DartCallSite) -> String {
    call.selector_slot
        .map_or_else(|| "?".to_owned(), |slot: u64| slot.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotLiftReport {
    pub version_hash: String,
    pub abi_resolved: bool,
    pub function_count: usize,
    pub named_function_count: usize,
    pub cluster_named_function_count: usize,
    pub structured_function_count: usize,
    pub flat_fallback_count: usize,
    pub functions: Vec<DartLiftedFunction>,
    pub static_call_edges: usize,
    pub named_static_call_edges: usize,
    pub instance_call_sites: usize,
    pub table_dispatch_sites: usize,
    pub runtime_stub_calls: usize,
    pub self_recursive_functions: usize,
    pub elided_null_checks: usize,
    pub elided_bounds_checks: usize,
    pub elided_stack_overflow_checks: usize,
    pub elided_write_barriers: usize,
    pub pool_refs_total: usize,
    pub pool_refs_wide_offset: usize,
    pub pool_content_resolved: usize,
    pub pool_literals: Vec<DartPoolLiteral>,
    pub pool_slots: Option<DartPoolTableStats>,
    pub call_sites_with_arguments: usize,
    pub call_sites_opaque: usize,
    pub lifted_statements: usize,
    pub unlifted_statements: usize,
    pub recovered_return_expressions: usize,
    pub recovered_field_stores: usize,
    pub recovered_conditions: usize,
    pub inline_double_literals: Vec<DartPoolLiteral>,
    pub inline_double_count: usize,
    pub notes: Vec<String>,
}

const ABI_UNRESOLVED_NOTE: &str = "snapshot version hash is not pinned; ARM64 Dart ABI register roles (PP/THR/NULL/dispatch) are version-keyed and are not guessed, so this report is boundary and control-flow structure only";

const POOL_CONTENT_NOTE: &str = "pool slot indices are resolved from every PP-relative load form and the version-keyed ObjectPool cluster is deserialized per slot, so a call-site load resolves to its own string, double, integer, list or declared name; slots holding a snapshot base object, a native-function entry or a body shape this layout does not model stay unresolved rather than fabricated";

const INLINE_DOUBLE_NOTE: &str = "double literals that gen_snapshot materializes with an inline fmov 8-bit immediate never reach the ObjectPool; they are decoded byte-exact from the AArch64 fmov encoding and attributed to the function that loads them";

const FIELD_NAME_WALL_NOTE: &str = "instance field names are dropped by the product AOT precompiler (Precompiler::DropFields); they are absent from the snapshot bytes and are never fabricated. field access surfaces by offset only";

const CLUSTER_NAME_NOTE: &str = "this image carries no dart function symbol table, so function boundaries and names come from the isolate snapshot instructions table joined through each code object's owning function";

const CLUSTER_NAME_UNAVAILABLE_NOTE: &str = "this image carries no dart function symbol table and the isolate snapshot cluster walk could not supply offset-to-name coverage";

const POOL_UNAVAILABLE_NOTE: &str = "this image does not present a readable pair of VM and isolate snapshot blobs, so object-pool slot attribution is unavailable and call arguments that read the pool render as slot references";

const BODY_LIFT_NOTE: &str = "body statements are lifted to pseudo-Dart expressions from the ARM64 arithmetic, logical, bitfield, conditional-select and double-precision families; an instruction whose value the tracker cannot resolve keeps its unliftedArm64 marker with the original bytes and disassembly, so a body never omits an instruction it did not lift";

const BLOCK_MERGE_NOTE: &str = "a block with more than one predecessor starts from an empty tracker state, so a value produced before a control-flow merge is not carried into it; loop bodies therefore keep more unliftedArm64 markers than straight-line code, which is a merge-conservatism boundary rather than a decode limit";

const TYPE_PARAMETER_NAME_NOTE: &str = "the product AOT precompiler drops type-parameter names, so an uninstantiated type argument surfaces by its position in the vector as typeParam@N rather than by the name the source declared; the position is read from the artifact and the name is never invented";

const INLINE_WALL_NOTE: &str = "small leaf methods are inlined and tree-shaken; their boundaries do not survive in the AOT image, so they are honestly absent rather than reconstructed";

pub fn lift_libapp_aot(bytes: &[u8]) -> Result<AotLiftReport> {
    dbg_section("dart.aot-lift");
    let layout: super::LibAppLayout = super::parse_libapp_so(bytes)?;
    let recovery: super::DartLibAppRecovery = super::decompile_libapp_so_recovery(bytes)?;
    let (cluster_symbols, cluster_named, cluster_note): (
        Vec<DartFunctionSymbol>,
        usize,
        Option<String>,
    ) = if layout.function_symbols.is_empty() {
        cluster_derived_symbols(bytes)
    } else {
        (Vec::new(), 0, None)
    };
    let symbols: &[DartFunctionSymbol] = if layout.function_symbols.is_empty() {
        &cluster_symbols
    } else {
        &layout.function_symbols
    };
    let disasm: Arm64Disassembly = if symbols.is_empty() {
        super::disassemble_libapp_so(bytes)?
    } else {
        let instructions: Vec<u8> = super::isolate_instruction_bytes(bytes)?;
        disassemble_symtab_functions(&instructions, symbols)
    };
    dbg_kv("aot.functions", || disasm.function_count.to_string());
    let isolate_data: Vec<u8> = super::isolate_data_bytes(bytes)?;
    let attempted: Result<Option<DartPoolTable>> =
        super::vm_data_bytes(bytes).and_then(|vm_data: Vec<u8>| {
            DartPoolTable::build(&vm_data, &isolate_data, DartGraphLimits::default())
        });
    let (pool, unavailable): (Option<DartPoolTable>, Option<String>) = match attempted {
        Ok(table) => (table, None),
        Err(error) => (None, Some(format!("{POOL_UNAVAILABLE_NOTE}: {error}"))),
    };
    dbg_kv("aot.pool-slots", || {
        pool.as_ref().map_or_else(
            || "unavailable".to_owned(),
            |table| table.slot_count().to_string(),
        )
    });
    let mut report: AotLiftReport = lift_functions(
        &recovery.version_hash,
        &disasm,
        symbols,
        &isolate_data,
        pool.as_ref(),
    );
    report.cluster_named_function_count = cluster_named;
    if let Some(note) = cluster_note {
        report.notes.push(note);
    }
    if let Some(note) = unavailable {
        report.notes.push(note);
    }
    Ok(report)
}

#[must_use]
fn cluster_derived_symbols(bytes: &[u8]) -> (Vec<DartFunctionSymbol>, usize, Option<String>) {
    let report: super::DartGraphRecoveryReport =
        match super::recover_dart_pinned_elf(bytes, &super::DartGraphRecoveryOptions::default()) {
            Ok(report) => report,
            Err(error) => {
                return (
                    Vec::new(),
                    0,
                    Some(format!("{CLUSTER_NAME_UNAVAILABLE_NOTE}: {error}")),
                );
            }
        };
    if report.code_names.entries.is_empty() || report.code_names.boundaries.is_empty() {
        let reason: String = if report.code_names.reason.is_empty() {
            "the pinned cluster walk resolved no code object to a declared function".to_owned()
        } else {
            report.code_names.reason
        };
        return (
            Vec::new(),
            0,
            Some(format!("{CLUSTER_NAME_UNAVAILABLE_NOTE}: {reason}")),
        );
    }
    let mut names: BTreeMap<u64, &str> = BTreeMap::new();
    for entry in &report.code_names.entries {
        names
            .entry(entry.instructions_offset)
            .or_insert(entry.qualified_name.as_str());
    }
    let mut symbols: Vec<DartFunctionSymbol> =
        Vec::with_capacity(report.code_names.boundaries.len());
    let mut named: usize = 0;
    for boundary in &report.code_names.boundaries {
        let name: Option<&&str> = names.get(&boundary.instructions_offset);
        if name.is_some() {
            named = named.saturating_add(1);
        }
        symbols.push(DartFunctionSymbol {
            offset: usize::try_from(boundary.instructions_offset).unwrap_or(usize::MAX),
            address: boundary.instructions_offset,
            size: boundary.payload_length,
            name: name.map_or_else(String::new, |resolved: &&str| (*resolved).to_owned()),
        });
    }
    let total: usize = symbols.len();
    (
        symbols,
        named,
        Some(format!(
            "{CLUSTER_NAME_NOTE}: {named} of {total} instructions-table payloads carry a declared owning function",
        )),
    )
}

#[must_use]
fn disassemble_symtab_functions(
    instructions: &[u8],
    symbols: &[DartFunctionSymbol],
) -> Arm64Disassembly {
    let mut ordered: Vec<&DartFunctionSymbol> =
        symbols.iter().collect::<Vec<&DartFunctionSymbol>>();
    ordered.sort_unstable_by_key(|symbol: &&DartFunctionSymbol| symbol.offset);
    ordered.dedup_by_key(|symbol: &mut &DartFunctionSymbol| symbol.offset);

    let mut functions: Vec<Arm64Function> = Vec::with_capacity(ordered.len());
    for (idx, symbol) in ordered.iter().enumerate() {
        let next_offset: usize = ordered
            .get(idx + 1)
            .map_or(instructions.len(), |next: &&DartFunctionSymbol| next.offset);
        let size_limit: usize = symbol.offset.saturating_add(symbol.size as usize);
        let limit: usize = size_limit.min(next_offset);
        let declared: Option<String> = (!symbol.name.is_empty()).then(|| symbol.name.clone());
        functions.push(super::disasm::disassemble_range(
            instructions,
            0,
            symbol.offset,
            limit,
            declared,
        ));
    }
    let total_instructions: usize = functions
        .iter()
        .map(|f: &Arm64Function| f.decoded_instruction_count)
        .sum::<usize>();
    Arm64Disassembly {
        function_count: functions.len(),
        functions,
        total_instructions,
    }
}

#[must_use]
pub fn lift_functions(
    version_hash: &str,
    disasm: &Arm64Disassembly,
    symbols: &[DartFunctionSymbol],
    isolate_data: &[u8],
    pool: Option<&DartPoolTable>,
) -> AotLiftReport {
    let abi_resolved: bool = matches_version(version_hash);
    let index: SymbolIndex = SymbolIndex::build(symbols);

    let mut call_argument_counts: DartCallArgumentCounts = DartCallArgumentCounts::default();
    let mut functions: Vec<DartLiftedFunction> = Vec::with_capacity(disasm.functions.len());
    for func in &disasm.functions {
        functions.push(lift_one(
            func,
            &index,
            abi_resolved,
            pool,
            &mut call_argument_counts,
        ));
    }

    let named_function_count: usize = functions
        .iter()
        .filter(|f: &&DartLiftedFunction| f.name.is_some())
        .count();
    let structured_function_count: usize = functions
        .iter()
        .filter(|f: &&DartLiftedFunction| f.is_structured())
        .count();
    let flat_fallback_count: usize = functions.len().saturating_sub(structured_function_count);
    let mut static_call_edges: usize = 0;
    let mut named_static_call_edges: usize = 0;
    let mut instance_call_sites: usize = 0;
    let mut table_dispatch_sites: usize = 0;
    let mut runtime_stub_calls: usize = 0;
    let mut self_recursive_functions: usize = 0;
    let mut elided_null_checks: usize = 0;
    let mut elided_bounds_checks: usize = 0;
    let mut elided_stack_overflow_checks: usize = 0;
    let mut elided_write_barriers: usize = 0;
    let mut pool_refs_total: usize = 0;
    let mut pool_refs_wide_offset: usize = 0;
    let mut inline_double_bits: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    for func in &functions {
        for bits in &func.inline_double_literals {
            inline_double_bits.insert(*bits);
        }
        let mut saw_self_recursion: bool = false;
        for call in &func.calls {
            match call.kind {
                DartCallKind::Static => {
                    static_call_edges += 1;
                    if call.target_name.is_some() {
                        named_static_call_edges += 1;
                    }
                    if call.is_self_recursive {
                        saw_self_recursion = true;
                    }
                }
                DartCallKind::InstanceSwitchable => instance_call_sites += 1,
                DartCallKind::TableDispatch => table_dispatch_sites += 1,
                DartCallKind::RuntimeStub => runtime_stub_calls += 1,
                DartCallKind::Closure | DartCallKind::UnresolvedIndirect => {}
            }
        }
        if saw_self_recursion {
            self_recursive_functions += 1;
        }
        for check in &func.elided_checks {
            match check.kind {
                DartCheckKind::NullCheck => elided_null_checks += 1,
                DartCheckKind::BoundsCheck => elided_bounds_checks += 1,
                DartCheckKind::StackOverflow => elided_stack_overflow_checks += 1,
                DartCheckKind::WriteBarrier => elided_write_barriers += 1,
            }
        }
        for pref in &func.pool_refs {
            pool_refs_total += 1;
            if matches!(
                pref.form,
                DartPoolLoadForm::ShiftedAdd | DartPoolLoadForm::RegisterOffset
            ) {
                pool_refs_wide_offset += 1;
            }
        }
    }

    let pool_literals: Vec<DartPoolLiteral> = if abi_resolved {
        resolve_pool_literals(isolate_data)
    } else {
        Vec::new()
    };
    let pool_content_resolved: usize = pool_literals.len();

    let inline_double_literals: Vec<DartPoolLiteral> = inline_double_bits
        .into_iter()
        .map(DartPoolLiteral::Double)
        .collect::<Vec<DartPoolLiteral>>();
    let inline_double_count: usize = inline_double_literals.len();

    let mut notes: Vec<String> = Vec::new();
    if abi_resolved {
        notes.push(POOL_CONTENT_NOTE.to_owned());
        notes.push(INLINE_DOUBLE_NOTE.to_owned());
        notes.push(FIELD_NAME_WALL_NOTE.to_owned());
        notes.push(TYPE_PARAMETER_NAME_NOTE.to_owned());
        notes.push(INLINE_WALL_NOTE.to_owned());
        notes.push(BODY_LIFT_NOTE.to_owned());
        notes.push(BLOCK_MERGE_NOTE.to_owned());
    } else {
        notes.push(ABI_UNRESOLVED_NOTE.to_owned());
    }

    AotLiftReport {
        version_hash: version_hash.to_owned(),
        abi_resolved,
        function_count: functions.len(),
        named_function_count,
        cluster_named_function_count: 0,
        structured_function_count,
        flat_fallback_count,
        functions,
        static_call_edges,
        named_static_call_edges,
        instance_call_sites,
        table_dispatch_sites,
        runtime_stub_calls,
        self_recursive_functions,
        elided_null_checks,
        elided_bounds_checks,
        elided_stack_overflow_checks,
        elided_write_barriers,
        pool_refs_total,
        pool_refs_wide_offset,
        pool_content_resolved,
        pool_literals,
        pool_slots: pool.map(DartPoolTable::stats),
        call_sites_with_arguments: call_argument_counts.recovered_sites,
        call_sites_opaque: call_argument_counts.opaque_sites,
        lifted_statements: call_argument_counts.lifted_statements,
        unlifted_statements: call_argument_counts.unlifted_statements,
        recovered_return_expressions: call_argument_counts.recovered_returns,
        recovered_field_stores: call_argument_counts.recovered_field_stores,
        recovered_conditions: call_argument_counts.recovered_conditions,
        inline_double_literals,
        inline_double_count,
        notes,
    }
}

#[must_use]
fn lift_one(
    func: &Arm64Function,
    index: &SymbolIndex,
    abi_resolved: bool,
    pool: Option<&DartPoolTable>,
    counts: &mut DartCallArgumentCounts,
) -> DartLiftedFunction {
    let (start, end): (u64, u64) = func_range(func);
    let (basic_block_count, has_loop_back_edge): (usize, bool) =
        control_flow_shape(func, start, end);
    let conditional_branch_count: usize = func
        .instructions
        .iter()
        .filter(|i: &&Arm64Instruction| i.flow == Arm64FlowKind::ConditionalBranch)
        .count();

    let mut calls: Vec<DartCallSite> = Vec::new();
    let mut elided_checks: Vec<DartElidedCheck> = Vec::new();
    let mut pool_refs: Vec<DartPoolRef> = Vec::new();
    let mut inline_double_literals: Vec<u64> = Vec::new();
    let unlifted_arm64: Vec<DartUnliftedArm64> = func
        .instructions
        .iter()
        .filter(|instruction: &&Arm64Instruction| {
            matches!(
                instruction.flow,
                Arm64FlowKind::Sequential
                    | Arm64FlowKind::IndirectBranch
                    | Arm64FlowKind::DecodeError
            ) && !is_arm64_trap(instruction.bytes)
        })
        .map(|instruction: &Arm64Instruction| DartUnliftedArm64 {
            address: instruction.address,
            bytes: instruction.bytes,
            text: instruction.text.clone(),
        })
        .collect();

    if abi_resolved {
        pool_refs = resolve_pool_refs(&func.instructions, pool);
        inline_double_literals = recover_inline_double_literals(&func.instructions);
        for (i, insn) in func.instructions.iter().enumerate() {
            match insn.flow {
                Arm64FlowKind::DirectCall => {
                    let call: DartCallSite = classify_direct_call(insn, index, start, end);
                    calls.push(call);
                }
                Arm64FlowKind::IndirectCall => {
                    let call: DartCallSite = classify_indirect_call(&func.instructions, i);
                    calls.push(call);
                }
                Arm64FlowKind::ConditionalBranch => {
                    if let Some(kind) = classify_guard(&func.instructions, i) {
                        elided_checks.push(DartElidedCheck {
                            address: insn.address,
                            kind,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    let source_conditional_estimate: usize =
        conditional_branch_count.saturating_sub(count_conditional_guards(&elided_checks));

    let inferred_parameter_count: u8 = infer_arg_registers(func);
    let mut arg_registers: u8 = inferred_parameter_count;
    let structured: Option<DartStructuredBody> = if abi_resolved {
        let label: String = func
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:#010x}", func.entry_offset));
        let resolve = |target: u64| index.resolve(target).map(str::to_owned);
        let abi: super::structured::DartAbi<'_> = super::structured::DartAbi {
            fn_start: start,
            fn_end: end,
            label: &label,
            arg_registers,
            resolve: &resolve,
            pool,
        };
        super::structured::structure_dart_function(func, &abi, counts)
    } else {
        None
    };
    let declared_parameter_count: Option<u8> = structured
        .as_ref()
        .and_then(|body: &DartStructuredBody| body.parameter_count);
    if let Some(parameter_count) = declared_parameter_count {
        arg_registers = parameter_count;
    }
    let lifted_statement_count: usize = structured
        .as_ref()
        .map_or(0, |body: &DartStructuredBody| body.lifted_statements);
    let unlifted_statement_count: usize = structured
        .as_ref()
        .map_or(0, |body: &DartStructuredBody| body.unlifted_statements);
    let structured_body: Option<String> = structured.map(|body: DartStructuredBody| body.text);

    DartLiftedFunction {
        offset: func.entry_offset,
        name: func.name.clone(),
        instruction_count: func.instructions.len(),
        arg_registers,
        calls,
        elided_checks,
        pool_refs,
        inline_double_literals,
        unlifted_arm64,
        basic_block_count,
        conditional_branch_count,
        source_conditional_estimate,
        has_loop_back_edge,
        ends_in_return: func.ends_in_return,
        declared_parameter_count,
        inferred_parameter_count,
        lifted_statement_count,
        unlifted_statement_count,
        structured_body,
    }
}

#[must_use]
fn infer_arg_registers(func: &Arm64Function) -> u8 {
    const WINDOW_INSNS: usize = 64;
    let mut written: u32 = 0;
    let mut highest: Option<usize> = None;
    for insn in func.instructions.iter().take(WINDOW_INSNS) {
        if insn.flow == Arm64FlowKind::Return {
            break;
        }
        let operands: IntegerOperands = integer_operands(insn.bytes);
        for source in operands.reads() {
            if written & (1_u32 << source) != 0 {
                continue;
            }
            if let Some(position) = DART_ARGUMENT_REGISTERS
                .iter()
                .position(|register: &u8| *register == source)
            {
                highest = Some(highest.map_or(position, |seen: usize| seen.max(position)));
            }
        }
        if let Some(destination) = operands.destination {
            written |= 1_u32 << destination;
        }
        if matches!(
            insn.flow,
            Arm64FlowKind::DirectCall | Arm64FlowKind::IndirectCall
        ) {
            break;
        }
    }
    highest.map_or(0, |position: usize| {
        u8::try_from(position.saturating_add(1)).unwrap_or(u8::MAX)
    })
}

#[must_use]
fn count_conditional_guards(checks: &[DartElidedCheck]) -> usize {
    checks
        .iter()
        .filter(|c: &&DartElidedCheck| c.kind != DartCheckKind::WriteBarrier)
        .count()
}

#[must_use]
fn func_range(func: &Arm64Function) -> (u64, u64) {
    let start: u64 = func
        .instructions
        .first()
        .map_or(func.entry_offset as u64, |i: &Arm64Instruction| i.address);
    let end: u64 = func
        .instructions
        .last()
        .map_or(start, |i: &Arm64Instruction| i.address + 4);
    (start, end)
}

#[must_use]
fn control_flow_shape(func: &Arm64Function, start: u64, end: u64) -> (usize, bool) {
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(start);
    let mut has_loop_back_edge: bool = false;
    for insn in &func.instructions {
        let terminator: bool = matches!(
            insn.flow,
            Arm64FlowKind::DirectBranch
                | Arm64FlowKind::ConditionalBranch
                | Arm64FlowKind::IndirectBranch
                | Arm64FlowKind::Return
        );
        if terminator {
            let next: u64 = insn.address + 4;
            if next >= start && next < end {
                leaders.insert(next);
            }
        }
        if let Some(target) = insn.branch_target
            && target >= start
            && target < end
        {
            leaders.insert(target);
            if target <= insn.address {
                has_loop_back_edge = true;
            }
        }
    }
    (leaders.len(), has_loop_back_edge)
}

#[must_use]
fn classify_direct_call(
    insn: &Arm64Instruction,
    index: &SymbolIndex,
    start: u64,
    end: u64,
) -> DartCallSite {
    let target: Option<u64> = insn.branch_target;
    let is_self_recursive: bool = target.is_some_and(|t: u64| t >= start && t < end);
    let (kind, target_name): (DartCallKind, Option<String>) = match target {
        Some(t) => match index.resolve(t) {
            Some(name) => (DartCallKind::Static, Some(name.to_owned())),
            None => {
                if is_self_recursive {
                    (DartCallKind::Static, None)
                } else {
                    (DartCallKind::RuntimeStub, None)
                }
            }
        },
        None => (DartCallKind::RuntimeStub, None),
    };
    DartCallSite {
        address: insn.address,
        kind,
        target_offset: target,
        target_name,
        selector_slot: None,
        is_self_recursive,
    }
}

#[must_use]
fn classify_indirect_call(instructions: &[Arm64Instruction], at: usize) -> DartCallSite {
    let address: u64 = instructions[at].address;
    let blr_reg: Option<u8> = blr_target_reg(instructions[at].bytes);
    let window_start: usize = at.saturating_sub(CALL_SETUP_LOOKBACK);
    let mut selector_slot: Option<u64> = None;
    let mut kind: DartCallKind = DartCallKind::UnresolvedIndirect;

    for prior in (window_start..at).rev() {
        let raw: u32 = instructions[prior].bytes;
        if let Some((rt, rn, byte_off)) = ldr_imm_unsigned(raw) {
            if rt == IC_DATA_REG {
                selector_slot = pool_slot_from(rn, byte_off);
                kind = DartCallKind::InstanceSwitchable;
                break;
            }
            if rn == DISPATCH_TABLE_REG && blr_reg == Some(rt) {
                kind = DartCallKind::TableDispatch;
                break;
            }
            if rn == THR_REG && blr_reg == Some(rt) {
                kind = DartCallKind::RuntimeStub;
                break;
            }
        }
        if let Some((rt, rn, _)) = ldr_reg_offset(raw)
            && rn == DISPATCH_TABLE_REG
            && blr_reg == Some(rt)
        {
            kind = DartCallKind::TableDispatch;
            break;
        }
    }

    if kind == DartCallKind::UnresolvedIndirect
        && blr_reg.is_some()
        && loads_closure_entry(instructions, window_start, at, blr_reg)
    {
        kind = DartCallKind::Closure;
    }

    DartCallSite {
        address,
        kind,
        target_offset: None,
        target_name: None,
        selector_slot,
        is_self_recursive: false,
    }
}

#[must_use]
fn loads_closure_entry(
    instructions: &[Arm64Instruction],
    window_start: usize,
    at: usize,
    blr_reg: Option<u8>,
) -> bool {
    for prior in (window_start..at).rev() {
        if let Some((rt, rn, _)) = ldr_imm_unsigned(instructions[prior].bytes)
            && blr_reg == Some(rt)
            && rn != POOL_REG
            && rn != THR_REG
            && rn != DISPATCH_TABLE_REG
            && rn != SYS_SP_REG
        {
            return true;
        }
    }
    false
}

#[must_use]
pub(crate) fn classify_guard(
    instructions: &[Arm64Instruction],
    at: usize,
) -> Option<DartCheckKind> {
    let raw: u32 = instructions[at].bytes;
    if let Some((rt, _, _)) = tbz_tbnz(raw)
        && rt != SYS_SP_REG
        && following_direct_call(instructions, at)
    {
        return Some(DartCheckKind::WriteBarrier);
    }
    let cond: u8 = bcond(raw)?;
    let window_start: usize = at.saturating_sub(GUARD_LOOKBACK);

    let mut saw_thr_load: bool = false;
    let mut saw_null_cmp: bool = false;
    let mut saw_sp_cmp: bool = false;
    let mut saw_reg_reg_cmp: bool = false;
    for prior in (window_start..at).rev() {
        let praw: u32 = instructions[prior].bytes;
        if let Some((_, rn, _)) = ldr_imm_unsigned(praw)
            && rn == THR_REG
        {
            saw_thr_load = true;
        }
        if let Some((rd, rn, rm)) = subs_shifted_reg(praw)
            && rd == SYS_SP_REG
        {
            if rm == NULL_REG || rn == NULL_REG {
                saw_null_cmp = true;
            } else if rn == SYS_SP_REG || rn == DART_SP_REG {
                saw_sp_cmp = true;
            } else {
                saw_reg_reg_cmp = true;
            }
        }
        if let Some((rd, rn, _)) = subs_imm(praw)
            && rd == SYS_SP_REG
            && rn == NULL_REG
        {
            saw_null_cmp = true;
        }
    }

    if (cond == COND_LS || cond == COND_HS) && saw_sp_cmp && saw_thr_load {
        return Some(DartCheckKind::StackOverflow);
    }
    if (cond == COND_EQ || cond == COND_NE) && saw_null_cmp {
        return Some(DartCheckKind::NullCheck);
    }
    if (cond == COND_HS || cond == COND_HI) && saw_reg_reg_cmp {
        return Some(DartCheckKind::BoundsCheck);
    }
    None
}

#[must_use]
fn following_direct_call(instructions: &[Arm64Instruction], at: usize) -> bool {
    let end: usize = (at + 1 + WRITE_BARRIER_LOOKAHEAD).min(instructions.len());
    instructions
        .get(at + 1..end)
        .into_iter()
        .flatten()
        .any(|i: &Arm64Instruction| i.flow == Arm64FlowKind::DirectCall)
}

#[must_use]
fn pool_slot_content(pool: Option<&DartPoolTable>, slot: u64) -> Option<String> {
    let index: usize = usize::try_from(slot).ok()?;
    pool?.render_slot(index, false)
}

fn resolve_pool_refs(
    instructions: &[Arm64Instruction],
    pool: Option<&DartPoolTable>,
) -> Vec<DartPoolRef> {
    let mut refs: Vec<DartPoolRef> = Vec::new();
    let mut scratch: BTreeMap<u8, u64> = BTreeMap::new();
    for insn in instructions {
        let raw: u32 = insn.bytes;
        if let Some((rt, rn, byte_off)) = ldr_imm_unsigned(raw) {
            if rn == POOL_REG {
                if let Some(slot) = pool_slot_from(rn, byte_off) {
                    refs.push(DartPoolRef {
                        address: insn.address,
                        dest_reg: rt,
                        slot_index: slot,
                        form: DartPoolLoadForm::Direct,
                        resolved_content: pool_slot_content(pool, slot),
                    });
                }
            } else if let Some(base) = scratch.get(&rn).copied()
                && let Some(slot) = pool_slot_of_offset(base.saturating_add(byte_off))
            {
                refs.push(DartPoolRef {
                    address: insn.address,
                    dest_reg: rt,
                    slot_index: slot,
                    form: DartPoolLoadForm::ShiftedAdd,
                    resolved_content: pool_slot_content(pool, slot),
                });
            }
            scratch.remove(&rt);
            continue;
        }
        if let Some((rt, rn, rm_base)) = ldr_reg_offset(raw)
            && rn == POOL_REG
            && let Some(base) = scratch.get(&rm_base).copied()
            && let Some(slot) = pool_slot_of_offset(base)
        {
            refs.push(DartPoolRef {
                address: insn.address,
                dest_reg: rt,
                slot_index: slot,
                form: DartPoolLoadForm::RegisterOffset,
                resolved_content: pool_slot_content(pool, slot),
            });
            scratch.remove(&rt);
            continue;
        }
        if let Some((rd, rn, applied)) = add_imm(raw)
            && rn == POOL_REG
        {
            scratch.insert(rd, applied);
            continue;
        }
        if let Some((rd, imm)) = movz(raw) {
            scratch.insert(rd, imm);
            continue;
        }
        if let Some((rd, imm, shift)) = movk(raw)
            && let Some(prior) = scratch.get(&rd).copied()
        {
            let cleared: u64 = prior & !(0xFFFFu64 << shift);
            scratch.insert(rd, cleared | (imm << shift));
            continue;
        }
        if let Some(rd) = single_dest_reg(raw) {
            scratch.remove(&rd);
        }
    }
    refs
}

const FMOV_DOUBLE_IMM_MASK: u32 = 0xFFE0_1E00;

const FMOV_DOUBLE_IMM_MATCH: u32 = 0x1E60_1000;

#[must_use]
fn recover_inline_double_literals(instructions: &[Arm64Instruction]) -> Vec<u64> {
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for insn in instructions {
        if let Some(bits) = fmov_double_immediate(insn.bytes)
            && f64::from_bits(bits).is_finite()
        {
            seen.insert(bits);
        }
    }
    seen.into_iter().collect::<Vec<u64>>()
}

#[must_use]
pub(super) fn fmov_double_immediate(raw: u32) -> Option<u64> {
    if raw & FMOV_DOUBLE_IMM_MASK != FMOV_DOUBLE_IMM_MATCH {
        return None;
    }
    let imm8: u8 = ((raw >> 13) & 0xFF) as u8;
    Some(vfp_expand_double(imm8))
}

#[must_use]
const fn vfp_expand_double(imm8: u8) -> u64 {
    let sign: u64 = ((imm8 >> 7) & 1) as u64;
    let b6: u64 = ((imm8 >> 6) & 1) as u64;
    let exp: u64 = ((1 - b6) << 10) | ((0xFF * b6) << 2) | ((imm8 >> 4) & 0x3) as u64;
    let frac: u64 = ((imm8 & 0xF) as u64) << 48;
    (sign << 63) | (exp << 52) | frac
}

#[must_use]
fn pool_slot_from(rn: u8, byte_off: u64) -> Option<u64> {
    if rn != POOL_REG {
        return None;
    }
    pool_slot_of_offset(byte_off)
}

#[derive(Debug)]
struct SymbolIndex {
    exact: BTreeMap<u64, String>,
    intervals: Vec<(u64, u64, String)>,
}

impl SymbolIndex {
    #[must_use]
    fn build(symbols: &[DartFunctionSymbol]) -> Self {
        let mut exact: BTreeMap<u64, String> = BTreeMap::new();
        let mut intervals: Vec<(u64, u64, String)> = Vec::with_capacity(symbols.len());
        for symbol in symbols {
            let start: u64 = symbol.offset as u64;
            if symbol.name.is_empty() {
                continue;
            }
            exact.entry(start).or_insert_with(|| symbol.name.clone());
            if symbol.size > 0 {
                intervals.push((start, start + symbol.size, symbol.name.clone()));
            }
        }
        intervals.sort_by_key(|entry: &(u64, u64, String)| entry.0);
        Self { exact, intervals }
    }

    #[must_use]
    fn resolve(&self, target: u64) -> Option<&str> {
        if let Some(name) = self.exact.get(&target) {
            return Some(name.as_str());
        }
        let idx: usize = self
            .intervals
            .partition_point(|entry: &(u64, u64, String)| entry.0 <= target);
        if idx == 0 {
            return None;
        }
        let (start, end, name): &(u64, u64, String) = &self.intervals[idx - 1];
        if target >= *start && target < *end {
            Some(name.as_str())
        } else {
            None
        }
    }
}

#[must_use]
pub(super) fn ldr_imm_unsigned(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFFC0_0000 != 0xF940_0000 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, imm12 * POOL_ENTRY_BYTES))
}

#[must_use]
pub(super) fn ldr_reg_offset(raw: u32) -> Option<(u8, u8, u8)> {
    if raw & 0xFFE0_0C00 != 0xF860_0800 {
        return None;
    }
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, rm))
}

#[must_use]
pub(super) fn add_imm(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFF00_0000 != 0x9100_0000 {
        return None;
    }
    let shift: u32 = (raw >> 22) & 0x3;
    if shift > 1 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let applied: u64 = imm12 << (shift * 12);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rn, applied))
}

#[must_use]
pub(super) fn movz(raw: u32) -> Option<(u8, u64)> {
    if raw & 0xFF80_0000 != 0xD280_0000 {
        return None;
    }
    let shift: u32 = ((raw >> 21) & 0x3) * 16;
    let imm16: u64 = u64::from((raw >> 5) & 0xFFFF);
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, imm16 << shift))
}

#[must_use]
pub(super) fn movk(raw: u32) -> Option<(u8, u64, u32)> {
    if raw & 0xFF80_0000 != 0xF280_0000 {
        return None;
    }
    let shift: u32 = ((raw >> 21) & 0x3) * 16;
    let imm16: u64 = u64::from((raw >> 5) & 0xFFFF);
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, imm16, shift))
}

#[must_use]
pub(crate) fn subs_shifted_reg(raw: u32) -> Option<(u8, u8, u8)> {
    if raw & 0xFF20_0000 != 0xEB00_0000 {
        return None;
    }
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rn, rm))
}

#[must_use]
pub(crate) fn subs_imm(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFF00_0000 != 0xF100_0000 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rn, imm12))
}

#[must_use]
pub(crate) fn bcond(raw: u32) -> Option<u8> {
    if raw & 0xFF00_0010 != 0x5400_0000 {
        return None;
    }
    Some((raw & 0xF) as u8)
}

#[must_use]
pub(crate) fn tbz_tbnz(raw: u32) -> Option<(u8, u32, bool)> {
    if raw & 0x7F00_0000 != 0x3600_0000 {
        return None;
    }
    let is_tbnz: bool = raw & 0x0100_0000 != 0;
    let bit_hi: u32 = (raw >> 31) & 0x1;
    let bit_lo: u32 = (raw >> 19) & 0x1F;
    let bit: u32 = (bit_hi << 5) | bit_lo;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, bit, is_tbnz))
}

#[must_use]
pub(super) fn blr_target_reg(raw: u32) -> Option<u8> {
    if raw & 0xFFFF_FC1F != 0xD63F_0000 {
        return None;
    }
    Some(((raw >> 5) & 0x1F) as u8)
}

#[must_use]
pub(super) fn single_dest_reg(raw: u32) -> Option<u8> {
    if let Some((rd, _, _)) = add_imm(raw) {
        return Some(rd);
    }
    if let Some((rd, _)) = movz(raw) {
        return Some(rd);
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::disasm::disassemble_function;
    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(ws.len() * 4);
        for w in ws {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    #[test]
    fn unlifted_arm64_text_is_a_valid_dart_string_literal() {
        let residue: DartUnliftedArm64 = DartUnliftedArm64 {
            address: 0x1000,
            bytes: 0x9000_0000,
            text: "adrp x0, $+0x20 \\\"path\\\"\n".to_owned(),
        };
        assert_eq!(
            residue.to_pseudo_dart(),
            r#"unliftedArm64(address: 0x00001000, bytes: 0x90000000, text: "adrp x0, \$+0x20 \\\"path\\\"\n");"#
        );
    }

    fn bl(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x9400_0000 | ((imm as u32) & 0x03ff_ffff)
    }

    fn ldr_pool(dst: u32, byte_offset: u32) -> u32 {
        let imm12: u32 = byte_offset / 8;
        0xF940_0000 | (imm12 << 10) | (27u32 << 5) | dst
    }

    fn ldr_from(dst: u32, base: u32, byte_offset: u32) -> u32 {
        let imm12: u32 = byte_offset / 8;
        0xF940_0000 | (imm12 << 10) | (base << 5) | dst
    }

    fn add_pool(dst: u32, hi: u32) -> u32 {
        0x9100_0000 | (0x1 << 22) | (hi << 10) | (27u32 << 5) | dst
    }

    fn blr(reg: u32) -> u32 {
        0xD63F_0000 | (reg << 5)
    }

    fn ret() -> u32 {
        0xD65F_03C0
    }

    fn cmp_reg(rn: u32, rm: u32) -> u32 {
        0xEB00_0000 | (rm << 16) | (rn << 5) | 31
    }

    fn bcc(cond: u32) -> u32 {
        0x5400_0000 | (cond << 5) | cond
    }

    fn symbol(offset: usize, size: u64, name: &str) -> DartFunctionSymbol {
        DartFunctionSymbol {
            offset,
            address: offset as u64,
            size,
            name: name.to_owned(),
        }
    }

    #[test]
    fn resolves_direct_static_call_to_symbol_name() {
        let bytes: Vec<u8> = words(&[bl(0x100, 0x200), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex =
            SymbolIndex::build(&[symbol(0x200, 0x40, "WarehouseLedger.mostValuable")]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert_eq!(lifted.calls.len(), 1);
        assert_eq!(lifted.calls[0].kind, DartCallKind::Static);
        assert_eq!(
            lifted.calls[0].target_name.as_deref(),
            Some("WarehouseLedger.mostValuable")
        );
    }

    #[test]
    fn detects_self_recursion() {
        let bytes: Vec<u8> = words(&[ldr_pool(0, 8), bl(0x104, 0x100), ret()]);
        let func: Arm64Function =
            disassemble_function(&bytes, 0x100, 0, bytes.len(), Some("fib".to_owned()));
        let index: SymbolIndex = SymbolIndex::build(&[symbol(0x100, 0x0c, "fib")]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert!(
            lifted
                .calls
                .iter()
                .any(|c: &DartCallSite| c.is_self_recursive),
            "a bl back into the function's own range is self-recursion, calls={:?}",
            lifted.calls
        );
    }

    #[test]
    fn classifies_switchable_instance_call_via_x5_pool_load() {
        let bytes: Vec<u8> = words(&[ldr_pool(IC_DATA_REG as u32, 64), blr(3), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        let call: &DartCallSite = lifted
            .calls
            .iter()
            .find(|c: &&DartCallSite| c.kind == DartCallKind::InstanceSwitchable)
            .expect("x5 pool-load then blr is a switchable instance call");
        assert_eq!(call.selector_slot, Some(6));
    }

    #[test]
    fn classifies_table_dispatch_via_x21() {
        let bytes: Vec<u8> = words(&[ldr_from(9, DISPATCH_TABLE_REG as u32, 32), blr(9), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert!(
            lifted
                .calls
                .iter()
                .any(|c: &DartCallSite| c.kind == DartCallKind::TableDispatch),
            "ldr from x21 then blr is a table dispatch, calls={:?}",
            lifted.calls
        );
    }

    #[test]
    fn resolves_wide_offset_pool_load_via_add_ldr() {
        let bytes: Vec<u8> = words(&[add_pool(16, 1), ldr_from(0, 16, 16), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        let wide: &DartPoolRef = lifted
            .pool_refs
            .iter()
            .find(|p: &&DartPoolRef| p.form == DartPoolLoadForm::ShiftedAdd)
            .expect("add x16,x27,#1,lsl#12 then ldr must resolve a wide pool slot");
        assert_eq!(wide.slot_index, ((1u64 << 12) + 16 - 16) / 8);
    }

    fn fmov_d(imm8: u8, rd: u32) -> u32 {
        0x1E60_1000 | (u32::from(imm8) << 13) | rd
    }

    #[test]
    fn decodes_fmov_double_immediate_byte_exact() {
        assert_eq!(
            fmov_double_immediate(fmov_d(0x11, 0)),
            Some(4.25f64.to_bits()),
            "fmov d0,#4.25 has imm8 0x11 and must decode byte-exact"
        );
        assert_eq!(
            fmov_double_immediate(fmov_d(0x00, 3)).map(f64::from_bits),
            Some(2.0),
            "imm8 0x00 encodes 2.0 regardless of destination register"
        );
        assert_eq!(
            fmov_double_immediate(fmov_d(0xF0, 5)).map(f64::from_bits),
            Some(-1.0),
            "the sign bit of imm8 flips to a negative literal"
        );
        assert_eq!(
            fmov_double_immediate(ldr_pool(0, 8)),
            None,
            "a pool load is not an fmov immediate"
        );
    }

    #[test]
    fn lifts_inline_fmov_double_and_attributes_it_to_the_function() {
        let bytes: Vec<u8> = words(&[fmov_d(0x11, 0), ret()]);
        let func: Arm64Function =
            disassemble_function(&bytes, 0x100, 0, bytes.len(), Some("build".to_owned()));
        let index: SymbolIndex = SymbolIndex::build(&[symbol(0x100, 0x08, "build")]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert_eq!(
            lifted.inline_double_literals,
            vec![4.25f64.to_bits()],
            "the fmov #4.25 must lift as an inline double attributed to build, got {:?}",
            lifted.inline_double_literals
        );
    }

    #[test]
    fn unresolved_version_suppresses_inline_double_recovery() {
        let bytes: Vec<u8> = words(&[fmov_d(0x11, 0), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            false,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert!(
            lifted.inline_double_literals.is_empty(),
            "an unpinned ABI must not decode inline immediates"
        );
    }

    #[test]
    fn elides_null_check_but_keeps_real_branch() {
        let bytes: Vec<u8> = words(&[
            cmp_reg(3, NULL_REG as u32),
            bcc(u32::from(COND_EQ)),
            cmp_reg(3, 4),
            bcc(12),
            ret(),
        ]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            true,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert_eq!(lifted.conditional_branch_count, 2);
        assert!(
            lifted
                .elided_checks
                .iter()
                .any(|c: &DartElidedCheck| c.kind == DartCheckKind::NullCheck),
            "cmp x3,x22 then b.eq is a null-check guard, elided={:?}",
            lifted.elided_checks
        );
        assert_eq!(
            lifted.source_conditional_estimate, 1,
            "one guard elided, one real conditional remains"
        );
    }

    #[test]
    fn unresolved_version_degrades_to_structure_only() {
        let bytes: Vec<u8> = words(&[cmp_reg(3, NULL_REG as u32), bcc(u32::from(COND_EQ)), ret()]);
        let func: Arm64Function = disassemble_function(&bytes, 0x100, 0, bytes.len(), None);
        let index: SymbolIndex = SymbolIndex::build(&[]);
        let lifted: DartLiftedFunction = lift_one(
            &func,
            &index,
            false,
            None,
            &mut DartCallArgumentCounts::default(),
        );
        assert!(
            lifted.calls.is_empty()
                && lifted.elided_checks.is_empty()
                && lifted.pool_refs.is_empty(),
            "an unpinned version must not guess ABI roles"
        );
        assert!(
            lifted.conditional_branch_count >= 1,
            "raw control-flow structure is still reported"
        );
    }

    #[test]
    fn symtab_disassembly_lifts_non_overlapping_functions() {
        let bytes: Vec<u8> = words(&[0xa9bf_7bfd, 0x9100_03fd, ret(), 0x9100_0000, ret()]);
        let symbols: Vec<DartFunctionSymbol> =
            vec![symbol(0, 12, "Alpha.build"), symbol(12, 8, "Beta.run")];
        let disasm: Arm64Disassembly = disassemble_symtab_functions(&bytes, &symbols);
        assert_eq!(disasm.function_count, 2);
        assert_eq!(disasm.functions[0].name.as_deref(), Some("Alpha.build"));
        assert_eq!(
            disasm.functions[0].instructions.len(),
            3,
            "non-overlapping symbols decode exactly their own byte range"
        );
        assert_eq!(disasm.functions[1].name.as_deref(), Some("Beta.run"));
        assert_eq!(disasm.functions[1].instructions.len(), 2);
        assert_eq!(disasm.total_instructions, 5);
    }

    #[test]
    fn symtab_disassembly_bounds_overlapping_symbol_flood() {
        const ARM64_INSN_LEN: usize = 4;
        let region_words: usize = 2048;
        let bytes: Vec<u8> = words(&vec![0xd503_201fu32; region_words]);
        let mut symbols: Vec<DartFunctionSymbol> = Vec::with_capacity(region_words);
        for i in 0..region_words {
            symbols.push(symbol(
                i * ARM64_INSN_LEN,
                bytes.len() as u64,
                "Overlap.alias",
            ));
        }
        let disasm: Arm64Disassembly = disassemble_symtab_functions(&bytes, &symbols);
        let retained: usize = disasm
            .functions
            .iter()
            .map(|f: &Arm64Function| f.instructions.len())
            .sum::<usize>();
        assert!(
            retained <= bytes.len() / ARM64_INSN_LEN,
            "an overlapping symbol flood must decode each region slot at most once; retained {retained} instructions for {} region bytes",
            bytes.len()
        );
    }

    #[test]
    fn report_aggregates_and_flags_walls() {
        let bytes: Vec<u8> = words(&[bl(0x100, 0x100), ret()]);
        let disasm: Arm64Disassembly = super::super::disasm::disassemble_functions(
            &bytes,
            0x100,
            &[0],
            &[Some("fib".to_owned())],
        );
        let report: AotLiftReport = lift_functions(
            super::super::cid_table::DART_3_12_VERSION_HASH,
            &disasm,
            &[symbol(0x100, 0x08, "fib")],
            &[],
            None,
        );
        assert!(report.abi_resolved);
        assert!(report.self_recursive_functions >= 1);
        assert!(
            report
                .notes
                .iter()
                .any(|n: &String| n.contains("Precompiler::DropFields")),
            "the field-name wall must be stated honestly"
        );
    }
}
