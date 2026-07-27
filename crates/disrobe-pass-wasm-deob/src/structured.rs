use std::collections::BTreeMap;
use std::fmt::Arguments;

use wasmparser::{BlockType, FunctionBody, Operator, Parser, Payload, ValType};

use crate::MAX_RENDER_INDENT;
use crate::error::{Error, Result};
use crate::gc_types::{
    ArrayTypeRecord, GcStorageKind, GcTypeGraph, StructTypeRecord, recover_gc_types,
};
use crate::lift::{CalleeNames, HighLang, LiftCoverage, rust_op_fn_name, rust_unop_fn_name};
use crate::memory64::scan_memories;
use crate::op_names::operator_mnemonic;
use crate::signature::{FunctionSig, MAX_FUNCTION_LOCALS};

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut impl std::fmt::Write, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

fn push_format_line(output: &mut impl std::fmt::Write, args: Arguments<'_>) {
    push_format(output, args);
    match output.write_char('\n') {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleCtx {
    memory64: BTreeMap<u32, bool>,
    gc: GcTypeGraph,
    tag_param_counts: Vec<usize>,
}

impl ModuleCtx {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let memory64: BTreeMap<u32, bool> = scan_memories(bytes)
            .map(|report| {
                report
                    .memories
                    .iter()
                    .map(|(idx, rec)| (*idx, rec.memory64))
                    .collect()
            })
            .unwrap_or_default();
        let gc: GcTypeGraph = recover_gc_types(bytes).unwrap_or_default();
        let tag_param_counts: Vec<usize> = scan_tag_param_counts(bytes);
        Self {
            memory64,
            gc,
            tag_param_counts,
        }
    }

    fn is_memory64(&self, index: u32) -> bool {
        self.memory64.get(&index).copied().unwrap_or(false)
    }

    fn struct_record(&self, type_index: u32) -> Option<&StructTypeRecord> {
        self.gc.structs.get(&type_index)
    }

    fn array_record(&self, type_index: u32) -> Option<&ArrayTypeRecord> {
        self.gc.arrays.get(&type_index)
    }

    fn tag_param_count(&self, tag_index: u32) -> usize {
        self.tag_param_counts
            .get(tag_index as usize)
            .copied()
            .unwrap_or(0)
    }
}

fn scan_tag_param_counts(bytes: &[u8]) -> Vec<usize> {
    let mut type_param_counts: Vec<usize> = Vec::new();
    let mut tag_type_indices: Vec<u32> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload): std::result::Result<Payload<'_>, _> = payload else {
            return Vec::new();
        };
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let Ok(group): std::result::Result<wasmparser::RecGroup, _> = group else {
                        continue;
                    };
                    for sub in group.into_types() {
                        let count: usize = match &sub.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(f) => f.params().len(),
                            _ => 0,
                        };
                        type_param_counts.push(count);
                    }
                }
            }
            Payload::TagSection(reader) => {
                for tag in reader {
                    let Ok(tag): std::result::Result<wasmparser::TagType, _> = tag else {
                        continue;
                    };
                    tag_type_indices.push(tag.func_type_idx);
                }
            }
            _ => {}
        }
    }
    tag_type_indices
        .into_iter()
        .map(|ti: u32| type_param_counts.get(ti as usize).copied().unwrap_or(0))
        .collect()
}

#[derive(Debug, Clone)]
struct Operand {
    text: String,
    ty: ValType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Block,
    Loop,
    If,
}

#[derive(Debug, Clone)]
struct Frame {
    kind: FrameKind,
    label: usize,
    result: Option<ValType>,
    result_var: Option<String>,
    stack_height: usize,
    idiomatic: bool,
    merged_into: Option<usize>,
}

struct Translator<'a> {
    lang: HighLang,
    callees: &'a CalleeNames,
    sig: &'a FunctionSig,
    module: Option<&'a ModuleCtx>,
    locals: Vec<ValType>,
    stack: Vec<Operand>,
    control: Vec<Frame>,
    out: String,
    next_tmp: u32,
    next_label: usize,
    indent: usize,
    blocks_emitted: usize,
    unreachable: bool,
    coverage: LiftCoverage,
    targeted_labels: std::collections::BTreeSet<usize>,
    loop_block_merges: BTreeMap<usize, usize>,
}

pub(crate) fn lift_body_structured(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    lang: HighLang,
) -> Result<(String, usize, LiftCoverage)> {
    let locals: Vec<ValType> = read_locals(body, &sig.params)?;

    let reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    let mut ops: Vec<Operator<'_>> = Vec::new();
    for op in reader {
        ops.push(op.map_err(|e| Error::Parse(e.to_string()))?);
    }
    let targeted_labels: std::collections::BTreeSet<usize> = scan_branch_targets(&ops);
    let loop_block_merges: BTreeMap<usize, usize> = scan_loop_block_merges(&ops);

    let mut t: Translator<'_> = Translator {
        lang,
        callees,
        sig,
        module: callees.module_ctx(),
        locals,
        stack: Vec::new(),
        control: Vec::new(),
        out: String::new(),
        next_tmp: 0,
        next_label: 0,
        indent: 1,
        blocks_emitted: 1,
        unreachable: false,
        coverage: LiftCoverage::default(),
        targeted_labels,
        loop_block_merges,
    };
    t.emit_local_decls();

    let op_count: usize = ops.len();
    for (i, op) in ops.iter().enumerate() {
        let is_final_end: bool = i + 1 == op_count && matches!(op, Operator::End);
        t.translate(op, is_final_end)?;
    }
    t.finish();
    Ok((t.out, t.blocks_emitted, t.coverage))
}

fn scan_branch_targets(ops: &[Operator<'_>]) -> std::collections::BTreeSet<usize> {
    let mut targeted: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut next_label: usize = 0;
    let open = |stack: &mut Vec<usize>, next_label: &mut usize| {
        stack.push(*next_label);
        *next_label += 1;
    };
    let mark = |stack: &[usize], depth: u32, targeted: &mut std::collections::BTreeSet<usize>| {
        if let Some(idx) = stack.len().checked_sub(depth as usize + 1) {
            if let Some(label) = stack.get(idx) {
                targeted.insert(*label);
            }
        }
    };
    for op in ops {
        match op {
            Operator::TryTable { try_table } => {
                for catch in &try_table.catches {
                    let label: u32 = match *catch {
                        wasmparser::Catch::One { label, .. }
                        | wasmparser::Catch::OneRef { label, .. }
                        | wasmparser::Catch::All { label }
                        | wasmparser::Catch::AllRef { label } => label,
                    };
                    mark(&stack, label, &mut targeted);
                }
                open(&mut stack, &mut next_label);
            }
            Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::Try { .. } => open(&mut stack, &mut next_label),
            Operator::End | Operator::Delegate { .. } => {
                stack.pop();
            }
            Operator::Br { relative_depth }
            | Operator::BrIf { relative_depth }
            | Operator::BrOnNull { relative_depth }
            | Operator::BrOnNonNull { relative_depth }
            | Operator::BrOnCast { relative_depth, .. }
            | Operator::BrOnCastFail { relative_depth, .. }
            | Operator::BrOnCastDescEq { relative_depth, .. }
            | Operator::BrOnCastDescEqFail { relative_depth, .. } => {
                mark(&stack, *relative_depth, &mut targeted);
            }
            Operator::BrTable { targets } => {
                mark(&stack, targets.default(), &mut targeted);
                for tgt in targets.targets().flatten() {
                    mark(&stack, tgt, &mut targeted);
                }
            }
            _ => {}
        }
    }
    targeted
}

struct OpenControl {
    label: usize,
    kind: FrameKind,
    blockty: BlockType,
    open_index: usize,
}

fn scan_loop_block_merges(ops: &[Operator<'_>]) -> BTreeMap<usize, usize> {
    let mut merges: BTreeMap<usize, usize> = BTreeMap::new();
    let mut stack: Vec<OpenControl> = Vec::new();
    let mut next_label: usize = 0;
    for (index, op) in ops.iter().enumerate() {
        match op {
            Operator::Block { blockty } => {
                stack.push(OpenControl {
                    label: next_label,
                    kind: FrameKind::Block,
                    blockty: *blockty,
                    open_index: index,
                });
                next_label += 1;
            }
            Operator::Loop { blockty } => {
                stack.push(OpenControl {
                    label: next_label,
                    kind: FrameKind::Loop,
                    blockty: *blockty,
                    open_index: index,
                });
                next_label += 1;
            }
            Operator::If { .. } | Operator::Try { .. } | Operator::TryTable { .. } => {
                stack.push(OpenControl {
                    label: next_label,
                    kind: FrameKind::If,
                    blockty: BlockType::Empty,
                    open_index: index,
                });
                next_label += 1;
            }
            Operator::End | Operator::Delegate { .. } => {
                let Some(closing): Option<OpenControl> = stack.pop() else {
                    continue;
                };
                if matches!(closing.kind, FrameKind::Loop)
                    && matches!(closing.blockty, BlockType::Empty)
                {
                    if let Some(wrapper) = stack.last() {
                        let loop_immediately_after_block: bool =
                            closing.open_index == wrapper.open_index + 1;
                        let end_immediately_after_loop_end: bool =
                            ops.get(index + 1).is_some_and(is_block_close);
                        if matches!(wrapper.kind, FrameKind::Block)
                            && matches!(wrapper.blockty, BlockType::Empty)
                            && loop_immediately_after_block
                            && end_immediately_after_loop_end
                        {
                            merges.insert(wrapper.label, closing.label);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    merges
}

const fn is_block_close(op: &Operator<'_>) -> bool {
    matches!(op, Operator::End)
}

fn read_locals(body: &FunctionBody<'_>, params: &[ValType]) -> Result<Vec<ValType>> {
    let mut out: Vec<ValType> = params.to_vec();
    let reader: wasmparser::LocalsReader<'_> = body
        .get_locals_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    for item in reader {
        let (count, ty): (u32, ValType) = item.map_err(|e| Error::Parse(e.to_string()))?;
        let remaining: usize = MAX_FUNCTION_LOCALS.saturating_sub(out.len());
        let take: usize = (count as usize).min(remaining);
        out.extend(std::iter::repeat_n(ty, take));
        if out.len() >= MAX_FUNCTION_LOCALS {
            break;
        }
    }
    Ok(out)
}

impl Translator<'_> {
    fn emit_signature_prefix(&self) -> String {
        let mut s: String = String::new();
        match self.lang {
            HighLang::Rust => {
                push_text!(s, "pub fn {}(", self.sig.name);
                for (i, ty) in self.sig.params.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    let name: String = self.param_name(i);
                    push_text!(s, "{name}: {}", rust_ty(*ty));
                }
                s.push(')');
                if let Some(ret) = self.sig.results.first() {
                    push_text!(s, " -> {}", rust_ty(*ret));
                }
                s.push_str(" {\n");
            }
            HighLang::TypeScript => {
                push_text!(s, "export function {}(", self.sig.name);
                for (i, ty) in self.sig.params.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    let name: String = self.param_name(i);
                    push_text!(s, "{name}: {}", ts_ty(*ty));
                }
                let ret: &str = self.sig.results.first().map_or("void", |t| ts_ty(*t));
                push_line!(s, "): {ret} {{");
            }
            HighLang::C => {
                let ret: &str = self.sig.results.first().map_or("void", |t| c_ty(*t));
                push_text!(s, "{ret} {}(", self.sig.name);
                if self.sig.params.is_empty() {
                    s.push_str("void");
                } else {
                    for (i, ty) in self.sig.params.iter().enumerate() {
                        if i > 0 {
                            s.push_str(", ");
                        }
                        let name: String = self.param_name(i);
                        push_text!(s, "{} {name}", c_ty(*ty));
                    }
                }
                s.push_str(") {\n");
            }
        }
        s
    }

    fn emit_local_decls(&mut self) {
        let param_count: usize = self.sig.params.len();
        let decls: Vec<(usize, ValType)> = self
            .locals
            .iter()
            .enumerate()
            .skip(param_count)
            .map(|(i, ty)| (i, *ty))
            .collect();
        for (i, ty) in decls {
            let init: &str = zero_lit(ty, self.lang);
            let name: String = self.local_name(u32::try_from(i).unwrap_or(u32::MAX));
            match self.lang {
                HighLang::Rust => {
                    push_line!(self.out, "    let mut {name}: {} = {init};", rust_ty(ty));
                }
                HighLang::TypeScript => {
                    push_line!(self.out, "    let {name}: {} = {init};", ts_ty(ty));
                }
                HighLang::C => {
                    push_line!(self.out, "    {} {name} = {init};", c_ty(ty));
                }
            }
        }
    }

    fn param_name(&self, index: usize) -> String {
        self.local_name(u32::try_from(index).unwrap_or(u32::MAX))
    }

    fn pad(&self) -> String {
        "    ".repeat(self.indent.min(MAX_RENDER_INDENT))
    }

    fn local_name(&self, idx: u32) -> String {
        if let Some(real) = self.sig.local_name(idx) {
            return sanitize_local(real);
        }
        if (idx as usize) < self.sig.params.len() {
            format!("p{idx}")
        } else {
            format!("l{idx}")
        }
    }

    fn local_type(&self, idx: u32) -> ValType {
        self.locals
            .get(idx as usize)
            .copied()
            .unwrap_or(ValType::I32)
    }

    fn push(&mut self, text: String, ty: ValType) {
        self.stack.push(Operand { text, ty });
    }

    fn pop(&mut self, site: &str) -> Result<Operand> {
        self.stack
            .pop()
            .ok_or_else(|| Error::Parse(format!("stack underflow at {site}")))
    }

    fn fresh_tmp(&mut self) -> String {
        let n: u32 = self.next_tmp;
        self.next_tmp += 1;
        format!("t{n}")
    }

    fn spill(&mut self, expr: &str, ty: ValType) {
        let name: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {name}: {} = {expr};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}let {name}: {} = {expr};", ts_ty(ty));
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{} {name} = {expr};", c_ty(ty));
            }
        }
        self.push(name, ty);
    }

    fn spill_decl(&mut self, expr: &str, rust_decl: &str, ts_decl: &str, c_decl: &str) {
        let name: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {name}: {rust_decl} = {expr};");
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}let {name}: {ts_decl} = {expr};");
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{c_decl} {name} = {expr};");
            }
        }
        self.push(name, REF_TYPE);
    }

    fn emit_stmt(&mut self, stmt: &str) {
        let pad: String = self.pad();
        push_line!(self.out, "{pad}{stmt}");
    }

    fn translate(&mut self, op: &Operator<'_>, is_final_end: bool) -> Result<()> {
        if self.unreachable && !is_structural(op) {
            self.coverage.record_translated();
            return Ok(());
        }
        match op {
            Operator::Nop => self.coverage.record_translated(),
            Operator::Unreachable => {
                self.emit_unreachable();
                self.unreachable = true;
                self.coverage.record_translated();
            }
            Operator::Block { blockty } => {
                self.open_frame(FrameKind::Block, *blockty);
                self.coverage.record_translated();
            }
            Operator::Loop { blockty } => {
                self.open_frame(FrameKind::Loop, *blockty);
                self.coverage.record_translated();
            }
            Operator::If { blockty } => {
                self.open_if(*blockty)?;
                self.coverage.record_translated();
            }
            Operator::Else => {
                self.do_else()?;
                self.coverage.record_translated();
            }
            Operator::End => {
                self.close_frame(is_final_end);
                self.coverage.record_translated();
            }
            Operator::Br { relative_depth } => {
                self.do_br(*relative_depth)?;
                self.coverage.record_translated();
            }
            Operator::BrIf { relative_depth } => {
                self.do_br_if(*relative_depth)?;
                self.coverage.record_translated();
            }
            Operator::BrTable { targets } => {
                self.do_br_table(targets)?;
                self.coverage.record_translated();
            }
            Operator::Return => {
                self.do_return()?;
                self.coverage.record_translated();
            }
            Operator::Call { function_index } => {
                self.do_call(*function_index)?;
                self.coverage.record_translated();
            }
            Operator::CallIndirect { type_index, .. } => {
                self.do_call_indirect(*type_index)?;
                self.coverage.record_translated();
            }
            Operator::Drop => {
                self.pop("drop")?;
                self.coverage.record_translated();
            }
            Operator::Select | Operator::TypedSelect { .. } => {
                self.do_select()?;
                self.coverage.record_translated();
            }
            Operator::LocalGet { local_index } => {
                let ty: ValType = self.local_type(*local_index);
                self.push(self.local_name(*local_index), ty);
                self.coverage.record_translated();
            }
            Operator::LocalSet { local_index } => {
                let v: Operand = self.pop("local.set")?;
                let name: String = self.local_name(*local_index);
                self.emit_stmt(&format!(
                    "{name} = {};",
                    coerce(&v, self.local_type(*local_index), self.lang)
                ));
                self.coverage.record_translated();
            }
            Operator::LocalTee { local_index } => {
                let v: Operand = self.pop("local.tee")?;
                let name: String = self.local_name(*local_index);
                let ty: ValType = self.local_type(*local_index);
                self.emit_stmt(&format!("{name} = {};", coerce(&v, ty, self.lang)));
                self.push(name, ty);
                self.coverage.record_translated();
            }
            Operator::GlobalGet { global_index } => {
                self.do_global_get(*global_index);
                self.coverage.record_translated();
            }
            Operator::GlobalSet { global_index } => {
                self.do_global_set(*global_index)?;
                self.coverage.record_translated();
            }
            Operator::I32Const { value } => {
                self.push(rust_i32(*value, self.lang), ValType::I32);
                self.coverage.record_translated();
            }
            Operator::I64Const { value } => {
                self.push(rust_i64(*value, self.lang), ValType::I64);
                self.coverage.record_translated();
            }
            Operator::F32Const { value } => {
                self.push(f32_lit(value.bits(), self.lang), ValType::F32);
                self.coverage.record_translated();
            }
            Operator::F64Const { value } => {
                self.push(f64_lit(value.bits(), self.lang), ValType::F64);
                self.coverage.record_translated();
            }
            other => self.translate_numeric_or_memory(other)?,
        }
        Ok(())
    }

    fn translate_numeric_or_memory(&mut self, op: &Operator<'_>) -> Result<()> {
        if let Some((kind, ty)) = crate::ssa::binop_kind(op) {
            let b: Operand = self.pop("binop")?;
            let a: Operand = self.pop("binop")?;
            let fname: String = self.helper(rust_op_fn_name(kind));
            let expr: String = format!("{fname}({}, {})", a.text, b.text);
            let res: ValType = binop_result_ty(kind, ty);
            self.spill(&expr, res);
            self.coverage.record_translated();
            return Ok(());
        }
        if let Some((unop, ty)) = crate::ssa::unop_kind(op) {
            let a: Operand = self.pop("unop")?;
            let fname: String = self.helper(rust_unop_fn_name(unop));
            let expr: String = format!("{fname}({})", a.text);
            self.spill(&expr, unop_result_ty(unop, ty));
            self.coverage.record_translated();
            return Ok(());
        }
        if let Some((suffix, ty, memarg)) = load_descriptor(op) {
            let addr: Operand = self.pop("load")?;
            let wide: bool = self.memory_is_64(memarg.memory);
            let suffix64: String = if wide {
                format!("{suffix}_a64")
            } else {
                suffix.to_owned()
            };
            let fname: String = self.helper(&format!("wasm_load_{suffix64}"));
            let addr_text: String = self.addr_operand(&addr, wide);
            let expr: String = format!("{fname}({addr_text}, {})", memarg.offset);
            self.spill(&expr, ty);
            self.coverage.record_translated();
            return Ok(());
        }
        if let Some((suffix, memarg)) = store_descriptor(op) {
            let val: Operand = self.pop("store")?;
            let addr: Operand = self.pop("store")?;
            let wide: bool = self.memory_is_64(memarg.memory);
            let suffix64: String = if wide {
                format!("{suffix}_a64")
            } else {
                suffix.to_owned()
            };
            let fname: String = self.helper(&format!("wasm_store_{suffix64}"));
            let addr_text: String = self.addr_operand(&addr, wide);
            self.emit_stmt(&format!(
                "{fname}({addr_text}, {}, {});",
                memarg.offset, val.text
            ));
            self.coverage.record_translated();
            return Ok(());
        }
        match op {
            Operator::MemorySize { mem } => {
                let wide: bool = self.memory_is_64(*mem);
                let f: String = self.helper("wasm_memory_size");
                let expr: String = if wide {
                    self.widen_to_i64(&format!("{f}()"))
                } else {
                    format!("{f}()")
                };
                self.spill(&expr, if wide { ValType::I64 } else { ValType::I32 });
                self.coverage.record_translated();
                Ok(())
            }
            Operator::MemoryGrow { mem } => {
                let wide: bool = self.memory_is_64(*mem);
                let delta: Operand = self.pop("memory.grow")?;
                let f: String = self.helper("wasm_memory_grow");
                let delta_text: String = if wide {
                    self.narrow_to_i32(&delta.text)
                } else {
                    delta.text
                };
                let call: String = format!("{f}({delta_text})");
                let expr: String = if wide { self.widen_to_i64(&call) } else { call };
                self.spill(&expr, if wide { ValType::I64 } else { ValType::I32 });
                self.coverage.record_translated();
                Ok(())
            }
            Operator::MemoryCopy { .. } => self.do_memory_copy(op),
            Operator::MemoryFill { .. } => self.do_memory_fill(op),
            Operator::MemoryInit { data_index, .. } => self.do_memory_init(*data_index, op),
            Operator::DataDrop { data_index } => {
                let f: String = self.helper("wasm_data_drop");
                self.emit_stmt(&format!("{f}({data_index});"));
                self.coverage.record_translated();
                Ok(())
            }
            other => self.translate_feature(other),
        }
    }

    fn translate_feature(&mut self, op: &Operator<'_>) -> Result<()> {
        if self.try_funcref(op)? {
            return Ok(());
        }
        if self.try_gc(op)? {
            return Ok(());
        }
        if self.try_simd(op)? {
            return Ok(());
        }
        if self.try_eh(op)? {
            return Ok(());
        }
        if self.try_atomic(op)? {
            return Ok(());
        }
        if self.try_table(op)? {
            return Ok(());
        }
        if self.try_wide(op)? {
            return Ok(());
        }
        if self.try_misc(op)? {
            return Ok(());
        }
        self.emit_untranslated(op);
        Ok(())
    }

    fn try_atomic(&mut self, op: &Operator<'_>) -> Result<bool> {
        let Some(desc): Option<crate::op_lift::AtomicDesc> = crate::op_lift::atomic_descriptor(op)
        else {
            return Ok(false);
        };
        if matches!(desc.shape, crate::op_lift::AtomicShape::Fence) {
            let f: String = self.helper(desc.helper);
            self.emit_stmt(&format!("{f}();"));
            self.coverage.record_translated();
            return Ok(true);
        }
        let memarg: wasmparser::MemArg =
            crate::op_lift::atomic_memarg(op).unwrap_or(wasmparser::MemArg {
                align: 0,
                max_align: 0,
                offset: 0,
                memory: 0,
            });
        let wide: bool = self.memory_is_64(memarg.memory);
        let suffix: String = if wide {
            format!("{}_a64", desc.helper)
        } else {
            desc.helper.to_owned()
        };
        let fname: String = self.helper(&suffix);
        match desc.shape {
            crate::op_lift::AtomicShape::Load => {
                let addr: Operand = self.pop("atomic.load")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!("{fname}({addr_text}, {})", memarg.offset);
                self.spill(&expr, desc.result);
            }
            crate::op_lift::AtomicShape::Store => {
                let val: Operand = self.pop("atomic.store")?;
                let addr: Operand = self.pop("atomic.store")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                self.emit_stmt(&format!(
                    "{fname}({addr_text}, {}, {});",
                    memarg.offset, val.text
                ));
            }
            crate::op_lift::AtomicShape::Rmw => {
                let val: Operand = self.pop("atomic.rmw")?;
                let addr: Operand = self.pop("atomic.rmw")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!("{fname}({addr_text}, {}, {})", memarg.offset, val.text);
                self.spill(&expr, desc.result);
            }
            crate::op_lift::AtomicShape::Cmpxchg => {
                let replacement: Operand = self.pop("atomic.cmpxchg")?;
                let expected: Operand = self.pop("atomic.cmpxchg")?;
                let addr: Operand = self.pop("atomic.cmpxchg")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!(
                    "{fname}({addr_text}, {}, {}, {})",
                    memarg.offset, expected.text, replacement.text
                );
                self.spill(&expr, desc.result);
            }
            crate::op_lift::AtomicShape::Wait => {
                let timeout: Operand = self.pop("atomic.wait")?;
                let expected: Operand = self.pop("atomic.wait")?;
                let addr: Operand = self.pop("atomic.wait")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!(
                    "{fname}({addr_text}, {}, {}, {})",
                    memarg.offset, expected.text, timeout.text
                );
                self.spill(&expr, ValType::I32);
            }
            crate::op_lift::AtomicShape::Notify => {
                let count: Operand = self.pop("atomic.notify")?;
                let addr: Operand = self.pop("atomic.notify")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String =
                    format!("{fname}({addr_text}, {}, {})", memarg.offset, count.text);
                self.spill(&expr, ValType::I32);
            }
            crate::op_lift::AtomicShape::Fence => {}
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn emit_untranslated(&mut self, op: &Operator<'_>) {
        let mnemonic: String = operator_mnemonic(op);
        match self.lang {
            HighLang::Rust | HighLang::C => {
                self.emit_stmt(&format!(
                    "/* DR-WASMDEOB-UNRECOVERED: no lifter for op {mnemonic} */"
                ));
            }
            HighLang::TypeScript => {
                self.emit_stmt(&format!(
                    "// DR-WASMDEOB-UNRECOVERED: no lifter for op {mnemonic}"
                ));
            }
        }
        self.coverage.record_untranslated(mnemonic);
    }

    fn helper(&self, rust_name: &str) -> String {
        match self.lang {
            HighLang::Rust | HighLang::C => rust_name.to_owned(),
            HighLang::TypeScript => snake_to_camel(rust_name),
        }
    }

    fn decl_result_var(&mut self, label: usize, result: Option<ValType>) -> Option<String> {
        let ty: ValType = result?;
        let var: String = format!("b{label}");
        let pad: String = self.pad();
        let zero: &str = zero_lit(ty, self.lang);
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let mut {var}: {} = {zero};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}let {var}: {} = {zero};", ts_ty(ty));
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{} {var} = {zero};", c_ty(ty));
            }
        }
        Some(var)
    }

    fn open_frame(&mut self, kind: FrameKind, blockty: BlockType) {
        self.open_frame_inner(kind, blockty, true);
    }

    fn open_frame_inner(&mut self, kind: FrameKind, blockty: BlockType, allow_idiomatic: bool) {
        let result: Option<ValType> = block_result(blockty);
        let label: usize = self.next_label;
        self.next_label += 1;
        if let Some(loop_label) = self.loop_block_merges.get(&label).copied() {
            self.control.push(Frame {
                kind: FrameKind::Block,
                label,
                result: None,
                result_var: None,
                stack_height: self.stack.len(),
                idiomatic: false,
                merged_into: Some(loop_label),
            });
            return;
        }
        let idiomatic: bool = allow_idiomatic
            && matches!(kind, FrameKind::Block)
            && !self.targeted_labels.contains(&label);
        let result_var: Option<String> = self.decl_result_var(label, result);
        let frame: Frame = Frame {
            kind,
            label,
            result,
            result_var,
            stack_height: self.stack.len(),
            idiomatic,
            merged_into: None,
        };
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                if idiomatic {
                    push_line!(self.out, "{pad}{{");
                } else {
                    let lbl: String = block_label(&frame);
                    push_line!(self.out, "{pad}{lbl}: loop {{");
                }
                self.indent += 1;
            }
            HighLang::C => {
                if !idiomatic && matches!(kind, FrameKind::Loop) {
                    push_line!(self.out, "{pad}c_entry_{label}: ;");
                }
                push_line!(self.out, "{pad}{{");
                self.indent += 1;
            }
        }
        self.blocks_emitted += 1;
        self.control.push(frame);
    }

    fn open_if(&mut self, blockty: BlockType) -> Result<()> {
        let cond: Operand = self.pop("if")?;
        let result: Option<ValType> = block_result(blockty);
        let label: usize = self.next_label;
        self.next_label += 1;
        let idiomatic: bool = !self.targeted_labels.contains(&label);
        let result_var: Option<String> = self.decl_result_var(label, result);
        let frame: Frame = Frame {
            kind: FrameKind::If,
            label,
            result,
            result_var,
            stack_height: self.stack.len(),
            idiomatic,
            merged_into: None,
        };
        let pad: String = self.pad();
        let cond_expr: String = truthy(&cond, self.lang);
        if !idiomatic {
            match self.lang {
                HighLang::Rust | HighLang::TypeScript => {
                    let lbl: String = block_label(&frame);
                    push_line!(self.out, "{pad}{lbl}: loop {{");
                }
                HighLang::C => {
                    push_line!(self.out, "{pad}{{");
                }
            }
            self.indent += 1;
        }
        let pad_if: String = self.pad();
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                push_line!(self.out, "{pad_if}if {cond_expr} {{");
            }
            HighLang::C => {
                push_line!(self.out, "{pad_if}if ({cond_expr}) {{");
            }
        }
        self.indent += 1;
        self.blocks_emitted += 1;
        self.control.push(frame);
        Ok(())
    }

    fn do_else(&mut self) -> Result<()> {
        let frame: Frame = self
            .control
            .last()
            .cloned()
            .ok_or_else(|| Error::Parse("else without if".into()))?;
        if self.stack.len() > frame.stack_height {
            if let (Some(var), Some(top)) = (frame.result_var.as_ref(), self.stack.last().cloned())
            {
                self.emit_stmt(&format!("{var} = {};", top.text));
            }
        }
        self.stack.truncate(frame.stack_height);
        self.indent -= 1;
        self.emit_stmt("} else {");
        self.indent += 1;
        self.unreachable = false;
        Ok(())
    }

    fn close_frame(&mut self, is_final_end: bool) {
        if is_final_end {
            self.flush_function_result();
            return;
        }
        let Some(frame): Option<Frame> = self.control.pop() else {
            return;
        };
        if let Some(loop_label) = frame.merged_into {
            self.stack.truncate(frame.stack_height);
            if matches!(self.lang, HighLang::C) {
                self.emit_stmt(&format!("c_exit_{loop_label}: ;"));
            }
            self.unreachable = false;
            return;
        }
        let value_on_stack: bool = self.stack.len() > frame.stack_height;
        if let (Some(var), true) = (frame.result_var.as_ref(), value_on_stack) {
            if let Some(top) = self.stack.last().cloned() {
                self.emit_stmt(&format!("{var} = {};", top.text));
            }
        }
        self.stack.truncate(frame.stack_height);

        if frame.idiomatic {
            self.indent -= 1;
            self.emit_stmt("}");
            self.unreachable = false;
            if let Some(var) = frame.result_var {
                self.push(var, frame.result.unwrap_or(ValType::I32));
            }
            return;
        }

        match self.lang {
            HighLang::Rust | HighLang::TypeScript => match frame.kind {
                FrameKind::Loop | FrameKind::Block => {
                    self.emit_stmt("break;");
                    self.indent -= 1;
                    self.emit_stmt("}");
                }
                FrameKind::If => {
                    self.indent -= 1;
                    self.emit_stmt("}");
                    self.emit_stmt("break;");
                    self.indent -= 1;
                    self.emit_stmt("}");
                }
            },
            HighLang::C => {
                if matches!(frame.kind, FrameKind::If) {
                    self.indent -= 1;
                    self.emit_stmt("}");
                }
                self.indent -= 1;
                self.emit_stmt("}");
                if matches!(frame.kind, FrameKind::Block | FrameKind::If) {
                    self.emit_stmt(&format!("c_exit_{}: ;", frame.label));
                }
            }
        }
        self.unreachable = false;
        if let Some(var) = frame.result_var {
            self.push(var, frame.result.unwrap_or(ValType::I32));
        }
    }

    fn branch_action(&self, frame: &Frame) -> String {
        if let Some(loop_label) = frame.merged_into {
            return match self.lang {
                HighLang::Rust | HighLang::TypeScript => format!("break 'b{loop_label};"),
                HighLang::C => format!("goto c_exit_{loop_label};"),
            };
        }
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                let lbl: String = block_label(frame);
                match frame.kind {
                    FrameKind::Loop => format!("continue {lbl};"),
                    FrameKind::Block | FrameKind::If => format!("break {lbl};"),
                }
            }
            HighLang::C => match frame.kind {
                FrameKind::Loop => format!("goto c_entry_{};", frame.label),
                FrameKind::Block | FrameKind::If => format!("goto c_exit_{};", frame.label),
            },
        }
    }

    fn do_br(&mut self, relative_depth: u32) -> Result<()> {
        let idx: usize = self
            .control
            .len()
            .checked_sub(relative_depth as usize + 1)
            .ok_or_else(|| Error::Parse("br depth out of range".into()))?;
        let frame: Frame = self.control[idx].clone();
        self.assign_branch_result(&frame);
        let action: String = self.branch_action(&frame);
        self.emit_stmt(&action);
        self.unreachable = true;
        Ok(())
    }

    fn do_br_if(&mut self, relative_depth: u32) -> Result<()> {
        let cond: Operand = self.pop("br_if")?;
        let idx: usize = self
            .control
            .len()
            .checked_sub(relative_depth as usize + 1)
            .ok_or_else(|| Error::Parse("br_if depth out of range".into()))?;
        let frame: Frame = self.control[idx].clone();
        let cond_expr: String = truthy(&cond, self.lang);
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => self.emit_stmt(&format!("if {cond_expr} {{")),
            HighLang::C => self.emit_stmt(&format!("if ({cond_expr}) {{")),
        }
        self.indent += 1;
        self.assign_branch_result(&frame);
        let action: String = self.branch_action(&frame);
        self.emit_stmt(&action);
        self.indent -= 1;
        self.emit_stmt("}");
        Ok(())
    }

    fn do_br_table(&mut self, targets: &wasmparser::BrTable<'_>) -> Result<()> {
        let selector: Operand = self.pop("br_table")?;
        let pad: String = self.pad();
        let sel: String = selector.text;
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}match {sel} {{");
            }
            HighLang::TypeScript | HighLang::C => {
                push_line!(self.out, "{pad}switch ({sel}) {{");
            }
        }
        self.indent += 1;
        for (case, tgt) in targets.targets().enumerate() {
            let depth: u32 = tgt.map_err(|e| Error::Parse(e.to_string()))?;
            self.emit_br_table_arm(&format!("{case}"), depth, false)?;
        }
        self.emit_br_table_arm("default", targets.default(), true)?;
        self.indent -= 1;
        self.emit_stmt("}");
        self.unreachable = true;
        Ok(())
    }

    fn emit_br_table_arm(
        &mut self,
        pat: &str,
        relative_depth: u32,
        is_default: bool,
    ) -> Result<()> {
        let idx: usize = self
            .control
            .len()
            .checked_sub(relative_depth as usize + 1)
            .ok_or_else(|| Error::Parse("br_table depth out of range".into()))?;
        let frame: Frame = self.control[idx].clone();
        let action: String = self.branch_action(&frame);
        match self.lang {
            HighLang::Rust => {
                let arm: &str = if is_default { "_" } else { pat };
                if let Some(assignment) = self.branch_result_assignment(&frame) {
                    self.emit_stmt(&format!("{arm} => {{ {assignment} {action} }}"));
                } else {
                    self.emit_stmt(&format!("{arm} => {{ {action} }}"));
                }
            }
            HighLang::TypeScript | HighLang::C => {
                if is_default {
                    self.emit_stmt("default: {");
                } else {
                    self.emit_stmt(&format!("case {pat}: {{"));
                }
                self.indent += 1;
                self.assign_branch_result(&frame);
                self.emit_stmt(&action);
                self.indent -= 1;
                self.emit_stmt("}");
            }
        }
        Ok(())
    }

    fn assign_branch_result(&mut self, frame: &Frame) {
        if let Some(assignment) = self.branch_result_assignment(frame) {
            self.emit_stmt(&assignment);
        }
    }

    fn branch_result_assignment(&self, frame: &Frame) -> Option<String> {
        if matches!(frame.kind, FrameKind::Loop) {
            return None;
        }
        let var: &String = frame.result_var.as_ref()?;
        let top: &Operand = self.stack.last()?;
        Some(format!("{var} = {};", top.text))
    }

    fn do_return(&mut self) -> Result<()> {
        if self.sig.results.is_empty() {
            self.emit_stmt("return;");
        } else {
            let v: Operand = self.pop("return")?;
            let ret_ty: ValType = self.sig.results[0];
            self.emit_stmt(&format!("return {};", coerce(&v, ret_ty, self.lang)));
        }
        self.unreachable = true;
        Ok(())
    }

    fn do_call(&mut self, function_index: u32) -> Result<()> {
        let name: String = self.callees.resolve(function_index);
        let (params, results): (Vec<ValType>, Vec<ValType>) =
            self.callees.signature(function_index);
        let mut args: Vec<String> = Vec::with_capacity(params.len());
        for _ in 0..params.len() {
            args.push(self.pop("call")?.text);
        }
        args.reverse();
        let call_expr: String = format!("{name}({})", args.join(", "));
        if let Some(ret) = results.first() {
            self.spill(&call_expr, *ret);
        } else {
            self.emit_stmt(&format!("{call_expr};"));
        }
        Ok(())
    }

    fn do_call_indirect(&mut self, type_index: u32) -> Result<()> {
        let callee: Operand = self.pop("call_indirect")?;
        let (params, results): (Vec<ValType>, Vec<ValType>) =
            self.callees.type_signature(type_index);
        let mut args: Vec<String> = Vec::with_capacity(params.len());
        for _ in 0..params.len() {
            args.push(self.pop("call_indirect")?.text);
        }
        args.reverse();
        let call_expr: String = format!(
            "call_indirect_type{type_index}({}, {})",
            callee.text,
            args.join(", ")
        );
        if let Some(ret) = results.first() {
            self.spill(&call_expr, *ret);
        } else {
            self.emit_stmt(&format!("{call_expr};"));
        }
        Ok(())
    }

    fn do_select(&mut self) -> Result<()> {
        let cond: Operand = self.pop("select")?;
        let if_false: Operand = self.pop("select")?;
        let if_true: Operand = self.pop("select")?;
        let ty: ValType = if_true.ty;
        let expr: String = match self.lang {
            HighLang::Rust => format!(
                "if {} {{ {} }} else {{ {} }}",
                truthy(&cond, self.lang),
                if_true.text,
                if_false.text
            ),
            HighLang::TypeScript | HighLang::C => format!(
                "({} ? {} : {})",
                truthy(&cond, self.lang),
                if_true.text,
                if_false.text
            ),
        };
        self.spill(&expr, ty);
        Ok(())
    }

    fn do_global_get(&mut self, global_index: u32) {
        let expr: String = match self.lang {
            HighLang::Rust => format!("(wasm_global_get({global_index}) as i32)"),
            HighLang::TypeScript => format!("wasmGlobalGet({global_index})"),
            HighLang::C => format!("(int32_t)wasm_global_get({global_index})"),
        };
        self.spill(&expr, ValType::I32);
    }

    fn do_global_set(&mut self, global_index: u32) -> Result<()> {
        let v: Operand = self.pop("global.set")?;
        match self.lang {
            HighLang::Rust => {
                self.emit_stmt(&format!(
                    "wasm_global_set({global_index}, ({}) as i64);",
                    v.text
                ));
            }
            HighLang::TypeScript => {
                self.emit_stmt(&format!("wasmGlobalSet({global_index}, {});", v.text));
            }
            HighLang::C => {
                self.emit_stmt(&format!(
                    "wasm_global_set({global_index}, (int64_t)({}));",
                    v.text
                ));
            }
        }
        Ok(())
    }

    fn memory_is_64(&self, memory_index: u32) -> bool {
        self.module
            .is_some_and(|ctx: &ModuleCtx| ctx.is_memory64(memory_index))
    }

    fn addr_operand(&self, addr: &Operand, wide: bool) -> String {
        if wide {
            match (self.lang, addr.ty) {
                (HighLang::Rust, ValType::I32) => format!("({} as i64)", addr.text),
                (HighLang::C, ValType::I32) => format!("(int64_t)({})", addr.text),
                _ => addr.text.clone(),
            }
        } else {
            addr.text.clone()
        }
    }

    fn widen_to_i64(&self, expr: &str) -> String {
        match self.lang {
            HighLang::Rust => format!("({expr} as i64)"),
            HighLang::TypeScript => format!("BigInt({expr})"),
            HighLang::C => format!("(int64_t)({expr})"),
        }
    }

    fn narrow_to_i32(&self, expr: &str) -> String {
        match self.lang {
            HighLang::Rust => format!("({expr} as i32)"),
            HighLang::TypeScript => format!("Number({expr})"),
            HighLang::C => format!("(int32_t)({expr})"),
        }
    }

    fn usize_index(&self, op: &Operand) -> String {
        match (self.lang, op.ty) {
            (HighLang::Rust, ValType::I64) => format!("({} as u64 as usize)", op.text),
            (HighLang::Rust, _) => format!("({} as u32 as usize)", op.text),
            (HighLang::C, ValType::I64) => format!("(size_t)(uint64_t)({})", op.text),
            (HighLang::C, _) => format!("(size_t)(uint32_t)({})", op.text),
            (HighLang::TypeScript, ValType::I64) => format!("Number({})", op.text),
            (HighLang::TypeScript, _) => op.text.clone(),
        }
    }

    fn do_memory_copy(&mut self, _op: &Operator<'_>) -> Result<()> {
        let n: Operand = self.pop("memory.copy")?;
        let src: Operand = self.pop("memory.copy")?;
        let dst: Operand = self.pop("memory.copy")?;
        let f: String = self.helper("wasm_memory_copy");
        let dst_i: String = self.usize_index(&dst);
        let src_i: String = self.usize_index(&src);
        let n_i: String = self.usize_index(&n);
        self.emit_stmt(&format!("{f}({dst_i}, {src_i}, {n_i});"));
        self.coverage.record_translated();
        Ok(())
    }

    fn do_memory_fill(&mut self, _op: &Operator<'_>) -> Result<()> {
        let n: Operand = self.pop("memory.fill")?;
        let val: Operand = self.pop("memory.fill")?;
        let dst: Operand = self.pop("memory.fill")?;
        let f: String = self.helper("wasm_memory_fill");
        let dst_i: String = self.usize_index(&dst);
        let n_i: String = self.usize_index(&n);
        self.emit_stmt(&format!("{f}({dst_i}, {}, {n_i});", val.text));
        self.coverage.record_translated();
        Ok(())
    }

    fn do_memory_init(&mut self, data_index: u32, _op: &Operator<'_>) -> Result<()> {
        let n: Operand = self.pop("memory.init")?;
        let src: Operand = self.pop("memory.init")?;
        let dst: Operand = self.pop("memory.init")?;
        let f: String = self.helper("wasm_memory_init");
        let dst_i: String = self.usize_index(&dst);
        let src_i: String = self.usize_index(&src);
        let n_i: String = self.usize_index(&n);
        self.emit_stmt(&format!("{f}({data_index}, {dst_i}, {src_i}, {n_i});"));
        self.coverage.record_translated();
        Ok(())
    }

    fn try_funcref(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::RefFunc { function_index } => {
                let name: String = self.callees.resolve(*function_index);
                self.push(name, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::RefNull { .. } => {
                let expr: String = match self.lang {
                    HighLang::Rust => "0usize".to_owned(),
                    HighLang::TypeScript => "null".to_owned(),
                    HighLang::C => "((funcref_t)0)".to_owned(),
                };
                self.push(expr, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::RefIsNull => {
                let r: Operand = self.pop("ref.is_null")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("(({} == 0) as i32)", r.text),
                    HighLang::TypeScript => format!("({} === null ? 1 : 0)", r.text),
                    HighLang::C => format!("(({}) == 0)", r.text),
                };
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::RefAsNonNull => {
                let r: Operand = self.pop("ref.as_non_null")?;
                self.push(r.text, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::CallRef { type_index } => {
                self.do_call_ref(*type_index, false)?;
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::ReturnCallRef { type_index } => {
                self.do_call_ref(*type_index, true)?;
                self.coverage.record_translated();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn do_call_ref(&mut self, type_index: u32, tail: bool) -> Result<()> {
        let callee: Operand = self.pop("call_ref")?;
        let (params, results): (Vec<ValType>, Vec<ValType>) =
            self.callees.type_signature(type_index);
        let mut args: Vec<String> = Vec::with_capacity(params.len());
        for _ in 0..params.len() {
            args.push(self.pop("call_ref")?.text);
        }
        args.reverse();
        let recv: String = match self.lang {
            HighLang::Rust => format!("({})", callee.text),
            HighLang::TypeScript | HighLang::C => callee.text,
        };
        let call_expr: String = format!("{recv}({})", args.join(", "));
        if tail {
            self.emit_stmt(&format!("return {call_expr};"));
            self.unreachable = true;
        } else if let Some(ret) = results.first() {
            self.spill(&call_expr, *ret);
        } else {
            self.emit_stmt(&format!("{call_expr};"));
        }
        Ok(())
    }

    fn try_gc(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::StructNew { struct_type_index } => {
                self.do_struct_new(*struct_type_index, false, false)?;
                Ok(true)
            }
            Operator::StructNewDefault { struct_type_index } => {
                self.do_struct_new(*struct_type_index, true, false)?;
                Ok(true)
            }
            Operator::StructNewDesc { struct_type_index } => {
                self.do_struct_new(*struct_type_index, false, true)?;
                Ok(true)
            }
            Operator::StructNewDefaultDesc { struct_type_index } => {
                self.do_struct_new(*struct_type_index, true, true)?;
                Ok(true)
            }
            Operator::RefGetDesc { .. } => {
                let r: Operand = self.pop("ref.get_desc")?;
                let f: String = self.helper("wasm_ref_get_desc");
                let expr: String = format!("{f}({})", r.text);
                self.spill(&expr, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::RefCastDescEqNonNull { .. } | Operator::RefCastDescEqNullable { .. } => {
                let desc: Operand = self.pop("ref.cast_desc")?;
                let r: Operand = self.pop("ref.cast_desc")?;
                let f: String = self.helper("wasm_ref_cast_desc");
                let expr: String = format!("{f}({}, {})", r.text, desc.text);
                self.spill(&expr, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::StructGet {
                struct_type_index,
                field_index,
            }
            | Operator::StructGetS {
                struct_type_index,
                field_index,
            }
            | Operator::StructGetU {
                struct_type_index,
                field_index,
            } => {
                self.do_struct_get(*struct_type_index, *field_index)?;
                Ok(true)
            }
            Operator::StructSet {
                struct_type_index,
                field_index,
            } => {
                self.do_struct_set(*struct_type_index, *field_index)?;
                Ok(true)
            }
            Operator::ArrayNew { array_type_index } => {
                self.do_array_new(*array_type_index)?;
                Ok(true)
            }
            Operator::ArrayNewFixed {
                array_type_index,
                array_size,
            } => {
                self.do_array_new_fixed(*array_type_index, *array_size)?;
                Ok(true)
            }
            Operator::ArrayGet { array_type_index }
            | Operator::ArrayGetS { array_type_index }
            | Operator::ArrayGetU { array_type_index } => {
                self.do_array_get(*array_type_index)?;
                Ok(true)
            }
            Operator::ArraySet { array_type_index } => {
                self.do_array_set(*array_type_index)?;
                Ok(true)
            }
            Operator::ArrayLen => {
                let arr: Operand = self.pop("array.len")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("({}.len() as i32)", arr.text),
                    HighLang::TypeScript => format!("{}.length", arr.text),
                    HighLang::C => format!("(int32_t)({}->len)", arr.text),
                };
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::RefI31 => {
                let v: Operand = self.pop("ref.i31")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("({} & 0x7fff_ffff)", v.text),
                    HighLang::TypeScript => format!("({} & 0x7fffffff)", v.text),
                    HighLang::C => format!("({} & 0x7fffffff)", v.text),
                };
                self.spill(&expr, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::I31GetS => {
                let v: Operand = self.pop("i31.get_s")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("(({} << 1) >> 1)", v.text),
                    HighLang::TypeScript => format!("(({} << 1) >> 1)", v.text),
                    HighLang::C => format!("(((int32_t)({}) << 1) >> 1)", v.text),
                };
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::I31GetU => {
                let v: Operand = self.pop("i31.get_u")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("({} & 0x7fff_ffff)", v.text),
                    HighLang::TypeScript => format!("({} & 0x7fffffff)", v.text),
                    HighLang::C => format!("({} & 0x7fffffff)", v.text),
                };
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn do_struct_new(&mut self, type_index: u32, default: bool, with_desc: bool) -> Result<()> {
        let field_count: usize = self
            .module
            .and_then(|ctx: &ModuleCtx| ctx.struct_record(type_index))
            .map_or(0usize, |rec: &StructTypeRecord| rec.fields.len());
        let name: String = struct_name(type_index);
        if with_desc {
            let _: Operand = self.pop("struct.new_desc")?;
        }
        let mut fields: Vec<String> = Vec::with_capacity(field_count);
        if default {
            for _ in 0..field_count {
                fields.push(zero_lit(ValType::I32, self.lang).to_owned());
            }
        } else {
            for _ in 0..field_count {
                fields.push(self.pop("struct.new")?.text);
            }
            fields.reverse();
        }
        let inits: String = fields
            .iter()
            .enumerate()
            .map(|(i, v): (usize, &String)| {
                format!(
                    "{}: {v}",
                    struct_field_name(type_index, u32::try_from(i).unwrap_or(u32::MAX))
                )
            })
            .collect::<Vec<String>>()
            .join(", ");
        let expr: String = match self.lang {
            HighLang::Rust => format!("{name} {{ {inits} }}"),
            HighLang::TypeScript => format!("{{ {inits} }}"),
            HighLang::C => "0".to_owned(),
        };
        self.spill_decl(&expr, &name, "Record<string, number | bigint>", "int32_t");
        self.coverage.record_translated();
        Ok(())
    }

    fn do_struct_get(&mut self, type_index: u32, field_index: u32) -> Result<()> {
        let obj: Operand = self.pop("struct.get")?;
        let field: String = struct_field_name(type_index, field_index);
        let expr: String = match self.lang {
            HighLang::Rust | HighLang::TypeScript => format!("{}.{field}", obj.text),
            HighLang::C => format!("{}->{field}", obj.text),
        };
        self.spill(&expr, self.struct_field_ty(type_index, field_index));
        self.coverage.record_translated();
        Ok(())
    }

    fn do_struct_set(&mut self, type_index: u32, field_index: u32) -> Result<()> {
        let val: Operand = self.pop("struct.set")?;
        let obj: Operand = self.pop("struct.set")?;
        let field: String = struct_field_name(type_index, field_index);
        let target: String = match self.lang {
            HighLang::Rust | HighLang::TypeScript => format!("{}.{field}", obj.text),
            HighLang::C => format!("{}->{field}", obj.text),
        };
        self.emit_stmt(&format!("{target} = {};", val.text));
        self.coverage.record_translated();
        Ok(())
    }

    fn struct_field_ty(&self, type_index: u32, field_index: u32) -> ValType {
        self.module
            .and_then(|ctx: &ModuleCtx| ctx.struct_record(type_index))
            .and_then(|rec: &StructTypeRecord| rec.fields.get(&field_index))
            .map_or(ValType::I32, |f| storage_val_type(f.storage))
    }

    fn array_elem_ty(&self, type_index: u32) -> ValType {
        self.module
            .and_then(|ctx: &ModuleCtx| ctx.array_record(type_index))
            .map_or(ValType::I32, |rec: &ArrayTypeRecord| {
                storage_val_type(rec.element.storage)
            })
    }

    fn do_array_new(&mut self, type_index: u32) -> Result<()> {
        let len: Operand = self.pop("array.new")?;
        let init: Operand = self.pop("array.new")?;
        let elem: ValType = self.array_elem_ty(type_index);
        let expr: String = match self.lang {
            HighLang::Rust => format!("vec![{}; ({} as usize)]", init.text, len.text),
            HighLang::TypeScript => format!("new Array({}).fill({})", len.text, init.text),
            HighLang::C => "0".to_owned(),
        };
        let rust_decl: String = format!("Vec<{}>", rust_ty(elem));
        let ts_decl: &str = ts_array_decl(elem);
        self.spill_decl(&expr, &rust_decl, ts_decl, "int32_t");
        self.coverage.record_translated();
        Ok(())
    }

    fn do_array_new_fixed(&mut self, type_index: u32, size: u32) -> Result<()> {
        let mut elems: Vec<String> = Vec::with_capacity((size as usize).min(self.stack.len()));
        for _ in 0..size {
            elems.push(self.pop("array.new_fixed")?.text);
        }
        elems.reverse();
        let joined: String = elems.join(", ");
        let elem: ValType = self.array_elem_ty(type_index);
        let expr: String = match self.lang {
            HighLang::Rust => format!("vec![{joined}]"),
            HighLang::TypeScript => format!("[{joined}]"),
            HighLang::C => "0".to_owned(),
        };
        let rust_decl: String = format!("Vec<{}>", rust_ty(elem));
        let ts_decl: &str = ts_array_decl(elem);
        self.spill_decl(&expr, &rust_decl, ts_decl, "int32_t");
        self.coverage.record_translated();
        Ok(())
    }

    fn do_array_get(&mut self, type_index: u32) -> Result<()> {
        let index: Operand = self.pop("array.get")?;
        let arr: Operand = self.pop("array.get")?;
        let expr: String = match self.lang {
            HighLang::Rust => format!("{}[({} as usize)]", arr.text, index.text),
            HighLang::TypeScript | HighLang::C => format!("{}[{}]", arr.text, index.text),
        };
        self.spill(&expr, self.array_elem_ty(type_index));
        self.coverage.record_translated();
        Ok(())
    }

    fn do_array_set(&mut self, _type_index: u32) -> Result<()> {
        let val: Operand = self.pop("array.set")?;
        let index: Operand = self.pop("array.set")?;
        let arr: Operand = self.pop("array.set")?;
        let target: String = match self.lang {
            HighLang::Rust => format!("{}[({} as usize)]", arr.text, index.text),
            HighLang::TypeScript | HighLang::C => format!("{}[{}]", arr.text, index.text),
        };
        self.emit_stmt(&format!("{target} = {};", val.text));
        self.coverage.record_translated();
        Ok(())
    }

    fn try_simd(&mut self, op: &Operator<'_>) -> Result<bool> {
        if let Some(desc) = simd_binop(op) {
            let b: Operand = self.pop("simd.binop")?;
            let a: Operand = self.pop("simd.binop")?;
            let expr: String = format!("{}({}, {})", self.helper(desc), a.text, b.text);
            self.spill(&expr, ValType::V128);
            self.coverage.record_translated();
            return Ok(true);
        }
        if let Some(desc) = simd_unop(op) {
            let a: Operand = self.pop("simd.unop")?;
            let expr: String = format!("{}({})", self.helper(desc), a.text);
            self.spill(&expr, ValType::V128);
            self.coverage.record_translated();
            return Ok(true);
        }
        if let Some(desc) = simd_splat(op) {
            let a: Operand = self.pop("simd.splat")?;
            let expr: String = format!("{}({})", self.helper(desc), a.text);
            self.spill(&expr, ValType::V128);
            self.coverage.record_translated();
            return Ok(true);
        }
        match op {
            Operator::V128Const { value } => {
                let lit: u128 = u128::from_le_bytes(*value.bytes());
                let expr: String = match self.lang {
                    HighLang::Rust => format!("{lit}u128"),
                    HighLang::TypeScript => format!("{lit}n"),
                    HighLang::C => {
                        let bytes: String = value
                            .bytes()
                            .iter()
                            .map(u8::to_string)
                            .collect::<Vec<String>>()
                            .join(", ");
                        format!("(v128_t){{ .u8 = {{ {bytes} }} }}")
                    }
                };
                self.spill(&expr, ValType::V128);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::V128Load { memarg } => {
                let addr: Operand = self.pop("v128.load")?;
                let wide: bool = self.memory_is_64(memarg.memory);
                let suffix: &str = if wide { "v128_a64" } else { "v128" };
                let fname: String = self.helper(&format!("wasm_load_{suffix}"));
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!("{fname}({addr_text}, {})", memarg.offset);
                self.spill(&expr, ValType::V128);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::V128Store { memarg } => {
                let val: Operand = self.pop("v128.store")?;
                let addr: Operand = self.pop("v128.store")?;
                let wide: bool = self.memory_is_64(memarg.memory);
                let suffix: &str = if wide { "v128_a64" } else { "v128" };
                let fname: String = self.helper(&format!("wasm_store_{suffix}"));
                let addr_text: String = self.addr_operand(&addr, wide);
                self.emit_stmt(&format!(
                    "{fname}({addr_text}, {}, {});",
                    memarg.offset, val.text
                ));
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::V128Bitselect => {
                let mask: Operand = self.pop("v128.bitselect")?;
                let b: Operand = self.pop("v128.bitselect")?;
                let a: Operand = self.pop("v128.bitselect")?;
                let expr: String = format!(
                    "{}({}, {}, {})",
                    self.helper("wasm_v128_bitselect"),
                    a.text,
                    b.text,
                    mask.text
                );
                self.spill(&expr, ValType::V128);
                self.coverage.record_translated();
                Ok(true)
            }
            other => self.try_simd_extended(other),
        }
    }

    fn try_simd_extended(&mut self, op: &Operator<'_>) -> Result<bool> {
        if let Some(desc) = crate::op_lift::simd_load_store(op) {
            self.lift_simd_mem(desc)?;
            self.coverage.record_translated();
            return Ok(true);
        }
        let Some(desc): Option<crate::op_lift::SimdDesc> = crate::op_lift::simd_descriptor(op)
        else {
            return Ok(false);
        };
        let fname: String = self.helper(desc.helper);
        match desc.shape {
            crate::op_lift::SimdShape::Un => {
                let a: Operand = self.pop("simd.un")?;
                let expr: String = format!("{fname}({})", a.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::Bin => {
                let b: Operand = self.pop("simd.bin")?;
                let a: Operand = self.pop("simd.bin")?;
                let expr: String = format!("{fname}({}, {})", a.text, b.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::Tern => {
                let c: Operand = self.pop("simd.tern")?;
                let b: Operand = self.pop("simd.tern")?;
                let a: Operand = self.pop("simd.tern")?;
                let expr: String = format!("{fname}({}, {}, {})", a.text, b.text, c.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::Shift => {
                let s: Operand = self.pop("simd.shift")?;
                let a: Operand = self.pop("simd.shift")?;
                let s_text: String = self.narrow_to_i32_if(&s);
                let expr: String = format!("{fname}({}, {s_text})", a.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::ExtractLane(ty) => {
                let a: Operand = self.pop("simd.extract")?;
                let lane: u8 = crate::op_lift::simd_lane_immediate(op).unwrap_or(0);
                let expr: String = format!("{fname}({}, {})", a.text, self.lane_index(lane));
                self.spill(&expr, ty);
            }
            crate::op_lift::SimdShape::ReplaceLane(_) => {
                let v: Operand = self.pop("simd.replace")?;
                let a: Operand = self.pop("simd.replace")?;
                let lane: u8 = crate::op_lift::simd_lane_immediate(op).unwrap_or(0);
                let expr: String =
                    format!("{fname}({}, {}, {})", a.text, self.lane_index(lane), v.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::Shuffle => {
                let b: Operand = self.pop("simd.shuffle")?;
                let a: Operand = self.pop("simd.shuffle")?;
                let lanes: [u8; 16] = crate::op_lift::simd_shuffle_lanes(op).unwrap_or([0u8; 16]);
                let lit: String = self.shuffle_lane_literal(&lanes);
                let expr: String = format!("{fname}({}, {}, {lit})", a.text, b.text);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdShape::ToI32 => {
                let a: Operand = self.pop("simd.toi32")?;
                let expr: String = format!("{fname}({})", a.text);
                self.spill(&expr, ValType::I32);
            }
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn narrow_to_i32_if(&self, op: &Operand) -> String {
        if op.ty == ValType::I32 {
            op.text.clone()
        } else {
            self.narrow_to_i32(&op.text)
        }
    }

    fn lane_index(&self, lane: u8) -> String {
        match self.lang {
            HighLang::Rust => format!("{lane}usize"),
            HighLang::TypeScript | HighLang::C => format!("{lane}"),
        }
    }

    fn shuffle_lane_literal(&self, lanes: &[u8; 16]) -> String {
        let inner: String = lanes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        match self.lang {
            HighLang::Rust => format!("[{inner}]"),
            HighLang::TypeScript => format!("[{inner}]"),
            HighLang::C => {
                let bytes: String = lanes
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("(const uint8_t[16]){{ {bytes} }}")
            }
        }
    }

    fn lift_simd_mem(&mut self, desc: crate::op_lift::SimdMem) -> Result<()> {
        let wide: bool = self.memory_is_64(desc.memarg.memory);
        let suffix: String = if wide {
            format!("{}_a64", desc.helper)
        } else {
            desc.helper.to_owned()
        };
        let fname: String = self.helper(&suffix);
        match desc.kind {
            crate::op_lift::SimdMemKind::Load => {
                let addr: Operand = self.pop("simd.load")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let expr: String = format!("{fname}({addr_text}, {})", desc.memarg.offset);
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdMemKind::LoadLane => {
                let vec: Operand = self.pop("simd.load_lane")?;
                let addr: Operand = self.pop("simd.load_lane")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let lane: u8 = desc.lane.unwrap_or(0);
                let expr: String = format!(
                    "{fname}({addr_text}, {}, {}, {})",
                    desc.memarg.offset,
                    vec.text,
                    self.lane_index(lane)
                );
                self.spill(&expr, ValType::V128);
            }
            crate::op_lift::SimdMemKind::Store => {
                let val: Operand = self.pop("simd.store")?;
                let addr: Operand = self.pop("simd.store")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                self.emit_stmt(&format!(
                    "{fname}({addr_text}, {}, {});",
                    desc.memarg.offset, val.text
                ));
            }
            crate::op_lift::SimdMemKind::StoreLane => {
                let val: Operand = self.pop("simd.store_lane")?;
                let addr: Operand = self.pop("simd.store_lane")?;
                let addr_text: String = self.addr_operand(&addr, wide);
                let lane: u8 = desc.lane.unwrap_or(0);
                self.emit_stmt(&format!(
                    "{fname}({addr_text}, {}, {}, {});",
                    desc.memarg.offset,
                    val.text,
                    self.lane_index(lane)
                ));
            }
        }
        Ok(())
    }

    fn try_table(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::TableGet { table } => {
                let idx: Operand = self.pop("table.get")?;
                let f: String = self.helper("wasm_table_get");
                let expr: String = format!("{f}({table}, {})", idx.text);
                self.spill(&expr, REF_TYPE);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableSet { table } => {
                let val: Operand = self.pop("table.set")?;
                let idx: Operand = self.pop("table.set")?;
                let f: String = self.helper("wasm_table_set");
                self.emit_stmt(&format!("{f}({table}, {}, {});", idx.text, val.text));
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableSize { table } => {
                let f: String = self.helper("wasm_table_size");
                let expr: String = format!("{f}({table})");
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableGrow { table } => {
                let n: Operand = self.pop("table.grow")?;
                let init: Operand = self.pop("table.grow")?;
                let f: String = self.helper("wasm_table_grow");
                let expr: String = format!("{f}({table}, {}, {})", init.text, n.text);
                self.spill(&expr, ValType::I32);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableFill { table } => {
                let n: Operand = self.pop("table.fill")?;
                let val: Operand = self.pop("table.fill")?;
                let idx: Operand = self.pop("table.fill")?;
                let f: String = self.helper("wasm_table_fill");
                self.emit_stmt(&format!(
                    "{f}({table}, {}, {}, {});",
                    idx.text, val.text, n.text
                ));
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableCopy {
                dst_table,
                src_table,
            } => {
                let n: Operand = self.pop("table.copy")?;
                let src: Operand = self.pop("table.copy")?;
                let dst: Operand = self.pop("table.copy")?;
                let f: String = self.helper("wasm_table_copy");
                self.emit_stmt(&format!(
                    "{f}({dst_table}, {src_table}, {}, {}, {});",
                    dst.text, src.text, n.text
                ));
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::TableInit { elem_index, table } => {
                let n: Operand = self.pop("table.init")?;
                let src: Operand = self.pop("table.init")?;
                let dst: Operand = self.pop("table.init")?;
                let f: String = self.helper("wasm_table_init");
                self.emit_stmt(&format!(
                    "{f}({table}, {elem_index}, {}, {}, {});",
                    dst.text, src.text, n.text
                ));
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::ElemDrop { elem_index } => {
                let f: String = self.helper("wasm_elem_drop");
                self.emit_stmt(&format!("{f}({elem_index});"));
                self.coverage.record_translated();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn try_wide(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::I64Add128 | Operator::I64Sub128 => {
                let helper_name: &str = if matches!(op, Operator::I64Add128) {
                    "wasm_i64_add128"
                } else {
                    "wasm_i64_sub128"
                };
                let b_hi: Operand = self.pop("i64.add128")?;
                let b_lo: Operand = self.pop("i64.add128")?;
                let a_hi: Operand = self.pop("i64.add128")?;
                let a_lo: Operand = self.pop("i64.add128")?;
                self.emit_wide_pair(helper_name, &[a_lo.text, a_hi.text, b_lo.text, b_hi.text]);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::I64MulWideS | Operator::I64MulWideU => {
                let helper_name: &str = if matches!(op, Operator::I64MulWideS) {
                    "wasm_i64_mul_wide_s"
                } else {
                    "wasm_i64_mul_wide_u"
                };
                let b: Operand = self.pop("i64.mul_wide")?;
                let a: Operand = self.pop("i64.mul_wide")?;
                self.emit_wide_pair(helper_name, &[a.text, b.text]);
                self.coverage.record_translated();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn emit_wide_pair(&mut self, helper_name: &str, args: &[String]) {
        let f: String = self.helper(helper_name);
        let call: String = format!("{f}({})", args.join(", "));
        let pair: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {pair}: (i64, i64) = {call};");
                let lo: String = self.fresh_tmp();
                let hi: String = self.fresh_tmp();
                let pad2: String = self.pad();
                push_line!(self.out, "{pad2}let {lo}: i64 = {pair}.0;");
                push_line!(self.out, "{pad2}let {hi}: i64 = {pair}.1;");
                self.push(lo, ValType::I64);
                self.push(hi, ValType::I64);
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}const {pair}: [bigint, bigint] = {call};");
                self.push(format!("{pair}[0]"), ValType::I64);
                self.push(format!("{pair}[1]"), ValType::I64);
            }
            HighLang::C => {
                push_line!(self.out, "{pad}wasm_i128_pair {pair} = {call};");
                self.push(format!("{pair}.lo"), ValType::I64);
                self.push(format!("{pair}.hi"), ValType::I64);
            }
        }
    }

    fn try_eh(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::TryTable { try_table } => {
                self.open_try_table(try_table);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::Throw { tag_index } => {
                let payload_count: usize = self
                    .module
                    .map_or(0, |ctx: &ModuleCtx| ctx.tag_param_count(*tag_index));
                let mut payloads: Vec<String> = Vec::with_capacity(payload_count);
                for _ in 0..payload_count {
                    payloads.push(self.pop("throw")?.text);
                }
                payloads.reverse();
                self.do_throw(Some(*tag_index), payloads);
                self.coverage.record_translated();
                Ok(true)
            }
            Operator::ThrowRef => {
                let r: Operand = self.pop("throw_ref")?;
                self.do_throw(None, vec![r.text]);
                self.coverage.record_translated();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn try_misc(&mut self, op: &Operator<'_>) -> Result<bool> {
        if self.try_gc_extra(op)? {
            return Ok(true);
        }
        if self.try_shared_atomic(op)? {
            return Ok(true);
        }
        if self.try_control_extra(op)? {
            return Ok(true);
        }
        if self.try_stack_switching(op)? {
            return Ok(true);
        }
        self.try_legacy_eh(op)
    }

    fn try_gc_extra(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::RefEq => {
                let b: Operand = self.pop("ref.eq")?;
                let a: Operand = self.pop("ref.eq")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("(({} == {}) as i32)", a.text, b.text),
                    HighLang::TypeScript => format!("({} === {} ? 1 : 0)", a.text, b.text),
                    HighLang::C => format!("(({}) == ({}))", a.text, b.text),
                };
                self.spill(&expr, ValType::I32);
            }
            Operator::RefTestNonNull { .. } | Operator::RefTestNullable { .. } => {
                let nullable: bool = matches!(op, Operator::RefTestNullable { .. });
                let r: Operand = self.pop("ref.test")?;
                let f: String = self.helper("wasm_ref_test");
                let expr: String = format!("{f}({}, {})", r.text, i32::from(nullable));
                self.spill(&expr, ValType::I32);
            }
            Operator::RefCastNonNull { .. } | Operator::RefCastNullable { .. } => {
                let r: Operand = self.pop("ref.cast")?;
                self.push(r.text, REF_TYPE);
            }
            Operator::AnyConvertExtern | Operator::ExternConvertAny => {
                let r: Operand = self.pop("ref.convert")?;
                self.push(r.text, REF_TYPE);
            }
            Operator::ArrayNewDefault { array_type_index } => {
                let len: Operand = self.pop("array.new_default")?;
                let elem: ValType = self.array_elem_ty(*array_type_index);
                let zero: &str = zero_lit(elem, self.lang);
                let expr: String = match self.lang {
                    HighLang::Rust => format!("vec![{zero}; ({} as usize)]", len.text),
                    HighLang::TypeScript => format!("new Array({}).fill({zero})", len.text),
                    HighLang::C => "0".to_owned(),
                };
                let rust_decl: String = format!("Vec<{}>", rust_ty(elem));
                let ts_decl: &str = ts_array_decl(elem);
                self.spill_decl(&expr, &rust_decl, ts_decl, "int32_t");
            }
            Operator::ArrayNewData {
                array_type_index, ..
            }
            | Operator::ArrayNewElem {
                array_type_index, ..
            } => {
                let len: Operand = self.pop("array.new_seg")?;
                let offset: Operand = self.pop("array.new_seg")?;
                let elem: ValType = self.array_elem_ty(*array_type_index);
                let f: String = self.helper("wasm_array_new_seg");
                let expr: String = format!("{f}({}, {})", offset.text, len.text);
                let rust_decl: String = format!("Vec<{}>", rust_ty(elem));
                let ts_decl: &str = ts_array_decl(elem);
                self.spill_decl(&expr, &rust_decl, ts_decl, "int32_t");
            }
            Operator::ArrayFill { .. } => {
                let n: Operand = self.pop("array.fill")?;
                let val: Operand = self.pop("array.fill")?;
                let idx: Operand = self.pop("array.fill")?;
                let arr: Operand = self.pop("array.fill")?;
                let f: String = self.helper("wasm_array_fill");
                self.emit_stmt(&format!(
                    "{f}({}, {}, {}, {});",
                    arr.text, idx.text, val.text, n.text
                ));
            }
            Operator::ArrayCopy { .. } => {
                let n: Operand = self.pop("array.copy")?;
                let src_idx: Operand = self.pop("array.copy")?;
                let src: Operand = self.pop("array.copy")?;
                let dst_idx: Operand = self.pop("array.copy")?;
                let dst: Operand = self.pop("array.copy")?;
                let f: String = self.helper("wasm_array_copy");
                self.emit_stmt(&format!(
                    "{f}({}, {}, {}, {}, {});",
                    dst.text, dst_idx.text, src.text, src_idx.text, n.text
                ));
            }
            Operator::ArrayInitData { .. } | Operator::ArrayInitElem { .. } => {
                let n: Operand = self.pop("array.init_seg")?;
                let src: Operand = self.pop("array.init_seg")?;
                let idx: Operand = self.pop("array.init_seg")?;
                let arr: Operand = self.pop("array.init_seg")?;
                let f: String = self.helper("wasm_array_init_seg");
                self.emit_stmt(&format!(
                    "{f}({}, {}, {}, {});",
                    arr.text, idx.text, src.text, n.text
                ));
            }
            _ => return Ok(false),
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn try_shared_atomic(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::RefI31Shared => {
                let v: Operand = self.pop("ref.i31_shared")?;
                let expr: String = match self.lang {
                    HighLang::Rust => format!("({} & 0x7fff_ffff)", v.text),
                    HighLang::TypeScript | HighLang::C => format!("({} & 0x7fffffff)", v.text),
                };
                self.spill(&expr, REF_TYPE);
            }
            Operator::GlobalAtomicGet { global_index, .. } => {
                self.do_global_get(*global_index);
            }
            Operator::GlobalAtomicSet { global_index, .. } => {
                return self.do_global_set(*global_index).map(|()| true);
            }
            Operator::GlobalAtomicRmwAdd { global_index, .. }
            | Operator::GlobalAtomicRmwSub { global_index, .. }
            | Operator::GlobalAtomicRmwAnd { global_index, .. }
            | Operator::GlobalAtomicRmwOr { global_index, .. }
            | Operator::GlobalAtomicRmwXor { global_index, .. }
            | Operator::GlobalAtomicRmwXchg { global_index, .. } => {
                self.do_global_atomic_rmw(*global_index, global_rmw_op(op))?;
            }
            Operator::GlobalAtomicRmwCmpxchg { global_index, .. } => {
                self.do_global_atomic_cmpxchg(*global_index)?;
            }
            Operator::StructAtomicGet {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicGetS {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicGetU {
                struct_type_index,
                field_index,
                ..
            } => {
                self.do_struct_get(*struct_type_index, *field_index)?;
            }
            Operator::StructAtomicSet {
                struct_type_index,
                field_index,
                ..
            } => {
                self.do_struct_set(*struct_type_index, *field_index)?;
            }
            Operator::StructAtomicRmwAdd {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicRmwSub {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicRmwAnd {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicRmwOr {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicRmwXor {
                struct_type_index,
                field_index,
                ..
            }
            | Operator::StructAtomicRmwXchg {
                struct_type_index,
                field_index,
                ..
            } => {
                self.do_struct_atomic_rmw(*struct_type_index, *field_index, struct_rmw_op(op))?;
            }
            Operator::StructAtomicRmwCmpxchg {
                struct_type_index,
                field_index,
                ..
            } => {
                self.do_struct_atomic_cmpxchg(*struct_type_index, *field_index)?;
            }
            Operator::ArrayAtomicGet {
                array_type_index, ..
            }
            | Operator::ArrayAtomicGetS {
                array_type_index, ..
            }
            | Operator::ArrayAtomicGetU {
                array_type_index, ..
            } => {
                self.do_array_get(*array_type_index)?;
            }
            Operator::ArrayAtomicSet { .. } => {
                self.do_array_set(0)?;
            }
            Operator::ArrayAtomicRmwAdd {
                array_type_index, ..
            }
            | Operator::ArrayAtomicRmwSub {
                array_type_index, ..
            }
            | Operator::ArrayAtomicRmwAnd {
                array_type_index, ..
            }
            | Operator::ArrayAtomicRmwOr {
                array_type_index, ..
            }
            | Operator::ArrayAtomicRmwXor {
                array_type_index, ..
            }
            | Operator::ArrayAtomicRmwXchg {
                array_type_index, ..
            } => {
                self.do_array_atomic_rmw(*array_type_index, array_rmw_op(op))?;
            }
            Operator::ArrayAtomicRmwCmpxchg {
                array_type_index, ..
            } => {
                self.do_array_atomic_cmpxchg(*array_type_index)?;
            }
            Operator::TableAtomicGet { table_index, .. } => {
                return self.try_table(&Operator::TableGet {
                    table: *table_index,
                });
            }
            Operator::TableAtomicSet { table_index, .. } => {
                return self.try_table(&Operator::TableSet {
                    table: *table_index,
                });
            }
            Operator::TableAtomicRmwXchg { table_index, .. } => {
                let val: Operand = self.pop("table.atomic.xchg")?;
                let idx: Operand = self.pop("table.atomic.xchg")?;
                let f: String = self.helper("wasm_table_atomic_rmw_xchg");
                let expr: String = format!("{f}({table_index}, {}, {})", idx.text, val.text);
                self.spill(&expr, REF_TYPE);
            }
            Operator::TableAtomicRmwCmpxchg { table_index, .. } => {
                let replacement: Operand = self.pop("table.atomic.cmpxchg")?;
                let expected: Operand = self.pop("table.atomic.cmpxchg")?;
                let idx: Operand = self.pop("table.atomic.cmpxchg")?;
                let f: String = self.helper("wasm_table_atomic_rmw_cmpxchg");
                let expr: String = format!(
                    "{f}({table_index}, {}, {}, {})",
                    idx.text, expected.text, replacement.text
                );
                self.spill(&expr, REF_TYPE);
            }
            _ => return Ok(false),
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn do_global_atomic_rmw(&mut self, global_index: u32, op_sym: &str) -> Result<()> {
        let v: Operand = self.pop("global.atomic.rmw")?;
        let f: String = self.helper("wasm_global_atomic_rmw");
        let expr: String = match self.lang {
            HighLang::Rust => format!(
                "({f}({global_index}, ({}) as i64, \"{op_sym}\") as i32)",
                v.text
            ),
            HighLang::TypeScript => format!("{}({global_index}, {}, \"{op_sym}\")", f, v.text),
            HighLang::C => format!(
                "(int32_t){f}({global_index}, (int64_t)({}), \"{op_sym}\")",
                v.text
            ),
        };
        self.spill(&expr, ValType::I32);
        Ok(())
    }

    fn do_global_atomic_cmpxchg(&mut self, global_index: u32) -> Result<()> {
        let replacement: Operand = self.pop("global.atomic.cmpxchg")?;
        let expected: Operand = self.pop("global.atomic.cmpxchg")?;
        let f: String = self.helper("wasm_global_atomic_cmpxchg");
        let expr: String = match self.lang {
            HighLang::Rust => format!(
                "({f}({global_index}, ({}) as i64, ({}) as i64) as i32)",
                expected.text, replacement.text
            ),
            HighLang::TypeScript => {
                format!(
                    "{f}({global_index}, {}, {})",
                    expected.text, replacement.text
                )
            }
            HighLang::C => format!(
                "(int32_t){f}({global_index}, (int64_t)({}), (int64_t)({}))",
                expected.text, replacement.text
            ),
        };
        self.spill(&expr, ValType::I32);
        Ok(())
    }

    fn do_struct_atomic_rmw(
        &mut self,
        type_index: u32,
        field_index: u32,
        op_sym: &str,
    ) -> Result<()> {
        let val: Operand = self.pop("struct.atomic.rmw")?;
        let obj: Operand = self.pop("struct.atomic.rmw")?;
        let field: String = struct_field_name(type_index, field_index);
        let target: String = match self.lang {
            HighLang::Rust | HighLang::TypeScript => format!("{}.{field}", obj.text),
            HighLang::C => format!("{}->{field}", obj.text),
        };
        let prev: String = self.fresh_tmp();
        let ty: ValType = self.struct_field_ty(type_index, field_index);
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {prev}: {} = {target};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}const {prev}: {} = {target};", ts_ty(ty));
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{} {prev} = {target};", c_ty(ty));
            }
        }
        self.emit_stmt(&format!(
            "{target} = {};",
            self.rmw_apply(&prev, op_sym, &val.text)
        ));
        self.push(prev, ty);
        Ok(())
    }

    fn do_struct_atomic_cmpxchg(&mut self, type_index: u32, field_index: u32) -> Result<()> {
        let replacement: Operand = self.pop("struct.atomic.cmpxchg")?;
        let expected: Operand = self.pop("struct.atomic.cmpxchg")?;
        let obj: Operand = self.pop("struct.atomic.cmpxchg")?;
        let field: String = struct_field_name(type_index, field_index);
        let target: String = match self.lang {
            HighLang::Rust | HighLang::TypeScript => format!("{}.{field}", obj.text),
            HighLang::C => format!("{}->{field}", obj.text),
        };
        let ty: ValType = self.struct_field_ty(type_index, field_index);
        self.emit_cmpxchg_field(&target, &expected.text, &replacement.text, ty);
        Ok(())
    }

    fn do_array_atomic_rmw(&mut self, type_index: u32, op_sym: &str) -> Result<()> {
        let val: Operand = self.pop("array.atomic.rmw")?;
        let index: Operand = self.pop("array.atomic.rmw")?;
        let arr: Operand = self.pop("array.atomic.rmw")?;
        let target: String = match self.lang {
            HighLang::Rust => format!("{}[({} as usize)]", arr.text, index.text),
            HighLang::TypeScript | HighLang::C => format!("{}[{}]", arr.text, index.text),
        };
        let ty: ValType = self.array_elem_ty(type_index);
        let prev: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {prev}: {} = {target};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}const {prev}: {} = {target};", ts_ty(ty));
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{} {prev} = {target};", c_ty(ty));
            }
        }
        self.emit_stmt(&format!(
            "{target} = {};",
            self.rmw_apply(&prev, op_sym, &val.text)
        ));
        self.push(prev, ty);
        Ok(())
    }

    fn do_array_atomic_cmpxchg(&mut self, type_index: u32) -> Result<()> {
        let replacement: Operand = self.pop("array.atomic.cmpxchg")?;
        let expected: Operand = self.pop("array.atomic.cmpxchg")?;
        let index: Operand = self.pop("array.atomic.cmpxchg")?;
        let arr: Operand = self.pop("array.atomic.cmpxchg")?;
        let target: String = match self.lang {
            HighLang::Rust => format!("{}[({} as usize)]", arr.text, index.text),
            HighLang::TypeScript | HighLang::C => format!("{}[{}]", arr.text, index.text),
        };
        let ty: ValType = self.array_elem_ty(type_index);
        self.emit_cmpxchg_field(&target, &expected.text, &replacement.text, ty);
        Ok(())
    }

    fn emit_cmpxchg_field(&mut self, target: &str, expected: &str, replacement: &str, ty: ValType) {
        let prev: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                push_line!(self.out, "{pad}let {prev}: {} = {target};", rust_ty(ty));
                push_line!(
                    self.out,
                    "{pad}if {prev} == {expected} {{ {target} = {replacement}; }}"
                );
            }
            HighLang::TypeScript => {
                push_line!(self.out, "{pad}const {prev}: {} = {target};", ts_ty(ty));
                push_line!(
                    self.out,
                    "{pad}if ({prev} === {expected}) {{ {target} = {replacement}; }}"
                );
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{} {prev} = {target};", c_ty(ty));
                push_line!(
                    self.out,
                    "{pad}if ({prev} == {expected}) {{ {target} = {replacement}; }}"
                );
            }
        }
        self.push(prev, ty);
    }

    fn rmw_apply(&self, prev: &str, op_sym: &str, val: &str) -> String {
        match (op_sym, self.lang) {
            ("add", HighLang::Rust) => format!("{prev}.wrapping_add({val})"),
            ("sub", HighLang::Rust) => format!("{prev}.wrapping_sub({val})"),
            ("add", HighLang::TypeScript) => format!("i64({prev} + {val})"),
            ("sub", HighLang::TypeScript) => format!("i64({prev} - {val})"),
            ("add", HighLang::C) => format!("({prev} + {val})"),
            ("sub", HighLang::C) => format!("({prev} - {val})"),
            ("and", _) => format!("{prev} & {val}"),
            ("or", _) => format!("{prev} | {val}"),
            ("xor", _) => format!("{prev} ^ {val}"),
            _ => val.to_owned(),
        }
    }

    fn try_control_extra(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::ReturnCall { function_index } => {
                self.do_tail_call(*function_index)?;
            }
            Operator::ReturnCallIndirect { type_index, .. } => {
                self.do_tail_call_indirect(*type_index)?;
            }
            Operator::MemoryDiscard { .. } => {
                let n: Operand = self.pop("memory.discard")?;
                let dst: Operand = self.pop("memory.discard")?;
                let f: String = self.helper("wasm_memory_discard");
                let dst_i: String = self.usize_index(&dst);
                let n_i: String = self.usize_index(&n);
                self.emit_stmt(&format!("{f}({dst_i}, {n_i});"));
            }
            Operator::BrOnNull { relative_depth } => {
                self.do_br_on_null(*relative_depth, true)?;
            }
            Operator::BrOnNonNull { relative_depth } => {
                self.do_br_on_null(*relative_depth, false)?;
            }
            Operator::BrOnCast { relative_depth, .. }
            | Operator::BrOnCastDescEq { relative_depth, .. } => {
                self.do_br_on_cast(*relative_depth, true)?;
            }
            Operator::BrOnCastFail { relative_depth, .. }
            | Operator::BrOnCastDescEqFail { relative_depth, .. } => {
                self.do_br_on_cast(*relative_depth, false)?;
            }
            _ => return Ok(false),
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn do_br_on_cast(&mut self, relative_depth: u32, branch_on_success: bool) -> Result<()> {
        let r: Operand = self.pop("br_on_cast")?;
        let idx: usize = self
            .control
            .len()
            .checked_sub(relative_depth as usize + 1)
            .ok_or_else(|| Error::Parse("br_on_cast depth out of range".into()))?;
        let frame: Frame = self.control[idx].clone();
        let test: String = self.helper("wasm_ref_test");
        let matches: String = format!("{test}({}, 1)", r.text);
        let cond: String = if branch_on_success {
            match self.lang {
                HighLang::Rust => format!("({matches} != 0)"),
                HighLang::TypeScript => format!("({matches} !== 0)"),
                HighLang::C => format!("(({matches}) != 0)"),
            }
        } else {
            match self.lang {
                HighLang::Rust => format!("({matches} == 0)"),
                HighLang::TypeScript => format!("({matches} === 0)"),
                HighLang::C => format!("(({matches}) == 0)"),
            }
        };
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => self.emit_stmt(&format!("if {cond} {{")),
            HighLang::C => self.emit_stmt(&format!("if ({cond}) {{")),
        }
        self.indent += 1;
        if let Some(var) = frame.result_var.as_ref() {
            self.emit_stmt(&format!("{var} = {};", r.text));
        }
        let action: String = self.branch_action(&frame);
        self.emit_stmt(&action);
        self.indent -= 1;
        self.emit_stmt("}");
        self.push(r.text, REF_TYPE);
        Ok(())
    }

    fn do_tail_call(&mut self, function_index: u32) -> Result<()> {
        let name: String = self.callees.resolve(function_index);
        let (params, _results): (Vec<ValType>, Vec<ValType>) =
            self.callees.signature(function_index);
        let mut args: Vec<String> = Vec::with_capacity(params.len());
        for _ in 0..params.len() {
            args.push(self.pop("return_call")?.text);
        }
        args.reverse();
        let call_expr: String = format!("{name}({})", args.join(", "));
        if self.sig.results.is_empty() {
            self.emit_stmt(&format!("{call_expr};"));
            self.emit_stmt("return;");
        } else {
            self.emit_stmt(&format!("return {call_expr};"));
        }
        self.unreachable = true;
        Ok(())
    }

    fn do_tail_call_indirect(&mut self, type_index: u32) -> Result<()> {
        let callee: Operand = self.pop("return_call_indirect")?;
        let (params, _results): (Vec<ValType>, Vec<ValType>) =
            self.callees.type_signature(type_index);
        let mut args: Vec<String> = Vec::with_capacity(params.len());
        for _ in 0..params.len() {
            args.push(self.pop("return_call_indirect")?.text);
        }
        args.reverse();
        let call_expr: String = format!(
            "call_indirect_type{type_index}({}, {})",
            callee.text,
            args.join(", ")
        );
        if self.sig.results.is_empty() {
            self.emit_stmt(&format!("{call_expr};"));
            self.emit_stmt("return;");
        } else {
            self.emit_stmt(&format!("return {call_expr};"));
        }
        self.unreachable = true;
        Ok(())
    }

    fn do_br_on_null(&mut self, relative_depth: u32, on_null: bool) -> Result<()> {
        let r: Operand = self.pop("br_on_null")?;
        let idx: usize = self
            .control
            .len()
            .checked_sub(relative_depth as usize + 1)
            .ok_or_else(|| Error::Parse("br_on_null depth out of range".into()))?;
        let frame: Frame = self.control[idx].clone();
        let cond: String = if on_null {
            match self.lang {
                HighLang::Rust => format!("({} == 0)", r.text),
                HighLang::TypeScript => format!("({} === null)", r.text),
                HighLang::C => format!("(({}) == 0)", r.text),
            }
        } else {
            match self.lang {
                HighLang::Rust => format!("({} != 0)", r.text),
                HighLang::TypeScript => format!("({} !== null)", r.text),
                HighLang::C => format!("(({}) != 0)", r.text),
            }
        };
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => self.emit_stmt(&format!("if {cond} {{")),
            HighLang::C => self.emit_stmt(&format!("if ({cond}) {{")),
        }
        self.indent += 1;
        if on_null {
            self.assign_branch_result(&frame);
        } else if let Some(var) = frame.result_var.as_ref() {
            self.emit_stmt(&format!("{var} = {};", r.text));
        }
        let action: String = self.branch_action(&frame);
        self.emit_stmt(&action);
        self.indent -= 1;
        self.emit_stmt("}");
        if on_null {
            self.push(r.text, REF_TYPE);
        }
        Ok(())
    }

    fn try_stack_switching(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::ContNew { .. } => {
                let r: Operand = self.pop("cont.new")?;
                let f: String = self.helper("wasm_cont_new");
                let expr: String = format!("{f}({})", r.text);
                self.spill(&expr, REF_TYPE);
            }
            Operator::ContBind { .. } => {
                let r: Operand = self.pop("cont.bind")?;
                let f: String = self.helper("wasm_cont_bind");
                let expr: String = format!("{f}({})", r.text);
                self.spill(&expr, REF_TYPE);
            }
            Operator::Suspend { tag_index } => {
                let f: String = self.helper("wasm_suspend");
                let expr: String = format!("{f}({tag_index})");
                self.spill(&expr, REF_TYPE);
            }
            Operator::Resume { .. }
            | Operator::ResumeThrow { .. }
            | Operator::ResumeThrowRef { .. } => {
                let r: Operand = self.pop("resume")?;
                let f: String = self.helper("wasm_resume");
                let expr: String = format!("{f}({})", r.text);
                self.spill(&expr, REF_TYPE);
            }
            Operator::Switch { .. } => {
                let r: Operand = self.pop("switch")?;
                let f: String = self.helper("wasm_cont_switch");
                let expr: String = format!("{f}({})", r.text);
                self.spill(&expr, REF_TYPE);
            }
            _ => return Ok(false),
        }
        self.coverage.record_translated();
        Ok(true)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn try_legacy_eh(&mut self, op: &Operator<'_>) -> Result<bool> {
        match op {
            Operator::Try { blockty } => {
                self.open_frame_inner(FrameKind::Block, *blockty, false);
            }
            Operator::Catch { .. } | Operator::CatchAll => {
                let f: String = self.helper("wasm_exception_pending");
                let pad: String = self.pad();
                match self.lang {
                    HighLang::Rust => {
                        push_line!(self.out, "{pad}let _ = {f}(None);");
                    }
                    HighLang::TypeScript => {
                        push_line!(self.out, "{pad}{f}(null);");
                    }
                    HighLang::C => {
                        push_line!(self.out, "{pad}(void){f}(-1);");
                    }
                }
            }
            Operator::Rethrow { .. } => {
                let f: String = self.helper("wasm_throw_ref");
                self.emit_stmt(&format!("{f}(0);"));
                self.emit_throw_unwind();
                self.unreachable = true;
            }
            Operator::Delegate { .. } => {
                self.close_frame(false);
            }
            _ => return Ok(false),
        }
        self.coverage.record_translated();
        Ok(true)
    }

    fn open_try_table(&mut self, try_table: &wasmparser::TryTable) {
        let result: Option<ValType> = block_result(try_table.ty);
        let label: usize = self.next_label;
        self.next_label += 1;
        let result_var: Option<String> = self.decl_result_var(label, result);
        let frame: Frame = Frame {
            kind: FrameKind::Block,
            label,
            result,
            result_var,
            stack_height: self.stack.len(),
            idiomatic: false,
            merged_into: None,
        };
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                let lbl: String = block_label(&frame);
                push_line!(self.out, "{pad}{lbl}: loop {{");
                self.indent += 1;
            }
            HighLang::C => {
                push_line!(self.out, "{pad}{{");
                self.indent += 1;
            }
        }
        for catch in &try_table.catches {
            self.emit_catch_handler(catch);
        }
        self.blocks_emitted += 1;
        self.control.push(frame);
    }

    fn emit_catch_handler(&mut self, catch: &wasmparser::Catch) {
        let (predicate, relative_depth): (String, u32) = match *catch {
            wasmparser::Catch::One { tag, label } | wasmparser::Catch::OneRef { tag, label } => {
                (self.exception_matches(Some(tag)), label)
            }
            wasmparser::Catch::All { label } | wasmparser::Catch::AllRef { label } => {
                (self.exception_matches(None), label)
            }
        };
        let Some(idx): Option<usize> = self.control.len().checked_sub(relative_depth as usize + 1)
        else {
            return;
        };
        let Some(frame): Option<Frame> = self.control.get(idx).cloned() else {
            return;
        };
        let action: String = self.branch_action(&frame);
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                self.emit_stmt(&format!("if {predicate} {{ {action} }}"));
            }
            HighLang::C => {
                self.emit_stmt(&format!("if ({predicate}) {{ {action} }}"));
            }
        }
    }

    fn exception_matches(&self, tag: Option<u32>) -> String {
        match (self.lang, tag) {
            (HighLang::Rust, Some(t)) => format!("wasm_exception_pending(Some({t}))"),
            (HighLang::Rust, None) => "wasm_exception_pending(None)".to_owned(),
            (HighLang::TypeScript, Some(t)) => format!("wasmExceptionPending({t})"),
            (HighLang::TypeScript, None) => "wasmExceptionPending(null)".to_owned(),
            (HighLang::C, Some(t)) => format!("wasm_exception_pending({t})"),
            (HighLang::C, None) => "wasm_exception_pending(-1)".to_owned(),
        }
    }

    fn do_throw(&mut self, tag_index: Option<u32>, payloads: Vec<String>) {
        if let Some(t) = tag_index {
            let f: String = self.helper("wasm_throw");
            self.emit_stmt(&format!("{f}({t});"));
        } else {
            let r: String = payloads
                .into_iter()
                .next()
                .unwrap_or_else(|| "0".to_owned());
            let f: String = self.helper("wasm_throw_ref");
            self.emit_stmt(&format!("{f}({r});"));
        }
        self.emit_throw_unwind();
        self.unreachable = true;
    }

    fn emit_throw_unwind(&mut self) {
        if self.sig.results.is_empty() {
            self.emit_stmt("return;");
        } else {
            let ret_ty: ValType = self.sig.results[0];
            self.emit_stmt(&format!("return {};", zero_lit(ret_ty, self.lang)));
        }
    }

    fn emit_unreachable(&mut self) {
        match self.lang {
            HighLang::Rust => self.emit_stmt("unreachable!();"),
            HighLang::TypeScript => self.emit_stmt("throw new Error(\"unreachable\");"),
            HighLang::C => self.emit_stmt("__builtin_unreachable();"),
        }
    }

    fn flush_function_result(&mut self) {
        if self.unreachable {
            return;
        }
        if self.sig.results.is_empty() {
            return;
        }
        let ret_ty: ValType = self.sig.results[0];
        if let Some(top) = self.stack.last().cloned() {
            self.emit_stmt(&format!("return {};", coerce(&top, ret_ty, self.lang)));
        } else {
            self.emit_stmt(&format!("return {};", zero_lit(ret_ty, self.lang)));
        }
    }

    fn finish(&mut self) {
        let prefix: String = self.emit_signature_prefix();
        let mut full: String = String::with_capacity(prefix.len() + self.out.len() + 4);
        full.push_str(&prefix);
        full.push_str(&self.out);
        full.push_str("}\n");
        self.out = full;
    }
}

fn block_label(frame: &Frame) -> String {
    format!("'b{}", frame.label)
}

fn rmw_symbol(name: &str) -> &'static str {
    if name.contains("Add") {
        "add"
    } else if name.contains("Sub") {
        "sub"
    } else if name.contains("And") {
        "and"
    } else if name.contains("Or") {
        "or"
    } else if name.contains("Xor") {
        "xor"
    } else {
        "xchg"
    }
}

fn global_rmw_op(op: &Operator<'_>) -> &'static str {
    rmw_symbol(&operator_mnemonic(op))
}

fn struct_rmw_op(op: &Operator<'_>) -> &'static str {
    rmw_symbol(&format!("{op:?}"))
}

fn array_rmw_op(op: &Operator<'_>) -> &'static str {
    rmw_symbol(&format!("{op:?}"))
}

fn struct_name(type_index: u32) -> String {
    format!("Struct{type_index}")
}

fn struct_field_name(type_index: u32, field_index: u32) -> String {
    format!("f{field_index}_{type_index}")
}

#[must_use]
pub fn rust_module_decls(bytes: &[u8]) -> String {
    let graph: GcTypeGraph = recover_gc_types(bytes).unwrap_or_default();
    let mut out: String = String::new();
    for (idx, rec) in &graph.structs {
        push_line!(out, "#[derive(Clone)]");
        push_line!(out, "struct {} {{", struct_name(*idx));
        for (field_idx, field) in &rec.fields {
            let ty: ValType = storage_val_type(field.storage);
            push_line!(
                out,
                "    {}: {},",
                struct_field_name(*idx, *field_idx),
                rust_ty(ty)
            );
        }
        out.push_str("}\n");
    }
    out
}

const fn is_structural(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::End
            | Operator::Else
            | Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::TryTable { .. }
    )
}

const fn block_result(blockty: BlockType) -> Option<ValType> {
    match blockty {
        BlockType::Type(t) => Some(t),
        BlockType::Empty | BlockType::FuncType(_) => None,
    }
}

const REF_TYPE: ValType = ValType::FUNCREF;

const fn ts_array_decl(elem: ValType) -> &'static str {
    match elem {
        ValType::I64 | ValType::V128 => "bigint[]",
        _ => "number[]",
    }
}

const fn storage_val_type(storage: GcStorageKind) -> ValType {
    match storage {
        GcStorageKind::I8 | GcStorageKind::I16 | GcStorageKind::I32 => ValType::I32,
        GcStorageKind::I64 => ValType::I64,
        GcStorageKind::F32 => ValType::F32,
        GcStorageKind::F64 => ValType::F64,
        GcStorageKind::V128 => ValType::V128,
        GcStorageKind::Ref(_) | GcStorageKind::NullableRef(_) => REF_TYPE,
    }
}

const fn simd_binop(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::V128And => "wasm_v128_and",
        Operator::V128Or => "wasm_v128_or",
        Operator::V128Xor => "wasm_v128_xor",
        Operator::V128AndNot => "wasm_v128_andnot",
        Operator::I8x16Add => "wasm_i8x16_add",
        Operator::I8x16Sub => "wasm_i8x16_sub",
        Operator::I16x8Add => "wasm_i16x8_add",
        Operator::I16x8Sub => "wasm_i16x8_sub",
        Operator::I16x8Mul => "wasm_i16x8_mul",
        Operator::I32x4Add => "wasm_i32x4_add",
        Operator::I32x4Sub => "wasm_i32x4_sub",
        Operator::I32x4Mul => "wasm_i32x4_mul",
        Operator::I64x2Add => "wasm_i64x2_add",
        Operator::I64x2Sub => "wasm_i64x2_sub",
        Operator::I64x2Mul => "wasm_i64x2_mul",
        Operator::F32x4Add => "wasm_f32x4_add",
        Operator::F32x4Sub => "wasm_f32x4_sub",
        Operator::F32x4Mul => "wasm_f32x4_mul",
        Operator::F32x4Div => "wasm_f32x4_div",
        Operator::F64x2Add => "wasm_f64x2_add",
        Operator::F64x2Sub => "wasm_f64x2_sub",
        Operator::F64x2Mul => "wasm_f64x2_mul",
        Operator::F64x2Div => "wasm_f64x2_div",
        _ => return None,
    })
}

const fn simd_unop(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::V128Not => "wasm_v128_not",
        Operator::F32x4Neg => "wasm_f32x4_neg",
        Operator::F64x2Neg => "wasm_f64x2_neg",
        Operator::F32x4Sqrt => "wasm_f32x4_sqrt",
        Operator::F64x2Sqrt => "wasm_f64x2_sqrt",
        Operator::F32x4Abs => "wasm_f32x4_abs",
        Operator::F64x2Abs => "wasm_f64x2_abs",
        _ => return None,
    })
}

const fn simd_splat(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::I8x16Splat => "wasm_i8x16_splat",
        Operator::I16x8Splat => "wasm_i16x8_splat",
        Operator::I32x4Splat => "wasm_i32x4_splat",
        Operator::I64x2Splat => "wasm_i64x2_splat",
        Operator::F32x4Splat => "wasm_f32x4_splat",
        Operator::F64x2Splat => "wasm_f64x2_splat",
        _ => return None,
    })
}

const fn binop_result_ty(kind: crate::ssa::OpKind, operand_ty: ValType) -> ValType {
    use crate::ssa::OpKind;
    match kind {
        OpKind::I32Eq
        | OpKind::I32Ne
        | OpKind::I32LtS
        | OpKind::I32LtU
        | OpKind::I32GtS
        | OpKind::I32GtU
        | OpKind::I32LeS
        | OpKind::I32LeU
        | OpKind::I32GeS
        | OpKind::I32GeU
        | OpKind::I64Eq
        | OpKind::I64Ne
        | OpKind::I64LtS
        | OpKind::I64LtU
        | OpKind::I64GtS
        | OpKind::I64GtU
        | OpKind::I64LeS
        | OpKind::I64LeU
        | OpKind::I64GeS
        | OpKind::I64GeU
        | OpKind::F32Eq
        | OpKind::F32Ne
        | OpKind::F32Lt
        | OpKind::F32Gt
        | OpKind::F32Le
        | OpKind::F32Ge
        | OpKind::F64Eq
        | OpKind::F64Ne
        | OpKind::F64Lt
        | OpKind::F64Gt
        | OpKind::F64Le
        | OpKind::F64Ge => ValType::I32,
        _ => operand_ty,
    }
}

const fn unop_result_ty(op: crate::ssa::UnOp, operand_ty: ValType) -> ValType {
    use crate::ssa::UnOp;
    match op {
        UnOp::I32Eqz | UnOp::I64Eqz => ValType::I32,
        _ => operand_ty,
    }
}

const fn rust_ty(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "u128",
        ValType::Ref(_) => "usize",
        ValType::I32 => "i32",
    }
}

const fn ts_ty(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 | ValType::V128 => "bigint",
        ValType::I32 | ValType::F32 | ValType::F64 | ValType::Ref(_) => "number",
    }
}

const fn c_ty(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "int64_t",
        ValType::F32 => "float",
        ValType::F64 => "double",
        ValType::V128 => "v128_t",
        ValType::Ref(_) | ValType::I32 => "int32_t",
    }
}

const fn zero_lit(ty: ValType, lang: HighLang) -> &'static str {
    match (lang, ty) {
        (HighLang::Rust, ValType::I64) => "0i64",
        (HighLang::Rust, ValType::F32) => "0.0f32",
        (HighLang::Rust, ValType::F64) => "0.0f64",
        (HighLang::Rust, ValType::V128) => "0u128",
        (HighLang::Rust, ValType::Ref(_)) => "0usize",
        (HighLang::Rust, _) => "0i32",
        (HighLang::TypeScript, ValType::I64 | ValType::V128) => "0n",
        (HighLang::TypeScript, _) => "0",
        (HighLang::C, ValType::I64) => "0LL",
        (HighLang::C, ValType::F32 | ValType::F64) => "0.0",
        (HighLang::C, ValType::V128) => "(v128_t){ 0 }",
        (HighLang::C, _) => "0",
    }
}

fn truthy(v: &Operand, lang: HighLang) -> String {
    match lang {
        HighLang::Rust => format!("({} != 0)", v.text),
        HighLang::TypeScript => format!("({} !== 0)", v.text),
        HighLang::C => format!("(({}) != 0)", v.text),
    }
}

fn coerce(v: &Operand, _want: ValType, _lang: HighLang) -> String {
    v.text.clone()
}

fn rust_i32(n: i32, lang: HighLang) -> String {
    match lang {
        HighLang::Rust => {
            if n == i32::MIN {
                "i32::MIN".to_owned()
            } else if n < 0 {
                format!("({n}i32)")
            } else {
                format!("{n}i32")
            }
        }
        HighLang::TypeScript => format!("{n}"),
        HighLang::C => {
            if n == i32::MIN {
                "INT32_MIN".to_owned()
            } else {
                format!("INT32_C({n})")
            }
        }
    }
}

fn rust_i64(n: i64, lang: HighLang) -> String {
    match lang {
        HighLang::Rust => {
            if n == i64::MIN {
                "i64::MIN".to_owned()
            } else if n < 0 {
                format!("({n}i64)")
            } else {
                format!("{n}i64")
            }
        }
        HighLang::TypeScript => format!("{n}n"),
        HighLang::C => {
            if n == i64::MIN {
                "INT64_MIN".to_owned()
            } else {
                format!("INT64_C({n})")
            }
        }
    }
}

fn f32_lit(bits: u32, lang: HighLang) -> String {
    match lang {
        HighLang::Rust => format!("f32::from_bits({bits}u32)"),
        HighLang::TypeScript => format!("wasmF32FromBits(0x{bits:08x})"),
        HighLang::C => format!("wasm_f32_reinterpret_i32((int32_t)0x{bits:08x}u)"),
    }
}

fn f64_lit(bits: u64, lang: HighLang) -> String {
    match lang {
        HighLang::Rust => format!("f64::from_bits({bits}u64)"),
        HighLang::TypeScript => format!("wasmF64FromBits(0x{bits:016x}n)"),
        HighLang::C => format!("wasm_f64_reinterpret_i64((int64_t)0x{bits:016x}ull)"),
    }
}

fn sanitize_local(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len() + 1);
    for (i, ch) in raw.chars().enumerate() {
        let ok: bool = if i == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        out.push(if ok { ch } else { '_' });
    }
    if out.is_empty() {
        out.push('_');
    }
    if is_reserved_word(&out) {
        out.insert(0, '_');
    }
    out
}

fn is_reserved_word(name: &str) -> bool {
    matches!(
        name,
        "as" | "break"
            | "const"
            | "continue"
            | "else"
            | "enum"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "ref"
            | "return"
            | "self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "function"
            | "var"
            | "void"
            | "int"
            | "char"
            | "double"
            | "float"
            | "class"
            | "new"
            | "delete"
            | "this"
            | "default"
            | "switch"
            | "case"
            | "do"
            | "goto"
    )
}

fn snake_to_camel(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len());
    let mut upper_next: bool = false;
    for ch in name.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

const fn load_descriptor(op: &Operator<'_>) -> Option<(&'static str, ValType, wasmparser::MemArg)> {
    use wasmparser::ValType as V;
    Some(match op {
        Operator::I32Load { memarg } => ("i32", V::I32, *memarg),
        Operator::I64Load { memarg } => ("i64", V::I64, *memarg),
        Operator::F32Load { memarg } => ("f32", V::F32, *memarg),
        Operator::F64Load { memarg } => ("f64", V::F64, *memarg),
        Operator::I32Load8U { memarg } => ("i32_8u", V::I32, *memarg),
        Operator::I32Load8S { memarg } => ("i32_8s", V::I32, *memarg),
        Operator::I32Load16U { memarg } => ("i32_16u", V::I32, *memarg),
        Operator::I32Load16S { memarg } => ("i32_16s", V::I32, *memarg),
        Operator::I64Load8U { memarg } => ("i64_8u", V::I64, *memarg),
        Operator::I64Load8S { memarg } => ("i64_8s", V::I64, *memarg),
        Operator::I64Load16U { memarg } => ("i64_16u", V::I64, *memarg),
        Operator::I64Load16S { memarg } => ("i64_16s", V::I64, *memarg),
        Operator::I64Load32U { memarg } => ("i64_32u", V::I64, *memarg),
        Operator::I64Load32S { memarg } => ("i64_32s", V::I64, *memarg),
        _ => return None,
    })
}

const fn store_descriptor(op: &Operator<'_>) -> Option<(&'static str, wasmparser::MemArg)> {
    Some(match op {
        Operator::I32Store { memarg } => ("i32", *memarg),
        Operator::I64Store { memarg } => ("i64", *memarg),
        Operator::F32Store { memarg } => ("f32", *memarg),
        Operator::F64Store { memarg } => ("f64", *memarg),
        Operator::I32Store8 { memarg } => ("i32_8", *memarg),
        Operator::I32Store16 { memarg } => ("i32_16", *memarg),
        Operator::I64Store8 { memarg } => ("i64_8", *memarg),
        Operator::I64Store16 { memarg } => ("i64_16", *memarg),
        Operator::I64Store32 { memarg } => ("i64_32", *memarg),
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod merge_tests {
    use wasmparser::{FunctionBody, Parser, Payload};

    use crate::lift::{CalleeNames, HighLang};
    use crate::signature::{FunctionSig, ModuleSignatures, extract_signatures};

    use super::lift_body_structured;

    fn first_body(bytes: &[u8]) -> FunctionBody<'_> {
        Parser::new(0)
            .parse_all(bytes)
            .find_map(|payload| match payload {
                Ok(Payload::CodeSectionEntry(body)) => Some(body),
                _ => None,
            })
            .expect("one defined function body")
    }

    fn lift_only_function(wat: &str, lang: HighLang) -> String {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat");
        let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");
        let sig: &FunctionSig = sigs.defined().first().expect("one defined function");
        let callees: CalleeNames = CalleeNames::new(sigs.callee_names());
        let body: FunctionBody<'_> = first_body(&bytes);
        let (source, _blocks, _coverage): (String, usize, _) =
            lift_body_structured(&body, sig, &callees, lang).expect("structured lift");
        source
    }

    const COUNTED_LOOP: &str = r#"(module
      (func $sum_to (export "sum_to") (param $n i32) (result i32)
        (local $i i32) (local $acc i32)
        i32.const 0
        local.set $i
        i32.const 0
        local.set $acc
        block $exit
          loop $loop
            local.get $i
            local.get $n
            i32.ge_s
            br_if $exit
            local.get $acc
            local.get $i
            i32.add
            local.set $acc
            local.get $i
            i32.const 1
            i32.add
            local.set $i
            br $loop
          end
        end
        local.get $acc))"#;

    const TRAILING_OPS_AFTER_LOOP: &str = r#"(module
      (func $not_canonical (export "not_canonical") (param $n i32) (result i32)
        (local $i i32) (local $acc i32)
        block $exit
          loop $loop
            local.get $i
            local.get $n
            i32.ge_s
            br_if $exit
            local.get $i
            i32.const 1
            i32.add
            local.set $i
            br $loop
          end
          local.get $acc
          i32.const 1
          i32.add
          local.set $acc
        end
        local.get $acc))"#;

    #[test]
    fn deeply_nested_blocks_clamp_structured_indentation() {
        let depth: usize = 400usize;
        let mut wat: String = String::from("(module (func $deep (export \"deep\") ");
        for _ in 0..depth {
            wat.push_str("block ");
        }
        for _ in 0..depth {
            wat.push_str("end ");
        }
        wat.push_str("))");
        let source: String = lift_only_function(&wat, HighLang::Rust);
        let max_indent_spaces: usize = source
            .lines()
            .map(|line: &str| line.len() - line.trim_start_matches(' ').len())
            .max()
            .unwrap_or(0usize);
        assert!(
            max_indent_spaces <= 4usize * crate::MAX_RENDER_INDENT + 8usize,
            "deep nesting must clamp indentation, saw {max_indent_spaces} leading spaces"
        );
        assert!(
            source.len() < depth * 700usize,
            "clamped output must stay linear in nesting depth"
        );
    }

    #[test]
    fn counted_loop_collapses_to_single_labeled_loop_rust() {
        let source: String = lift_only_function(COUNTED_LOOP, HighLang::Rust);
        assert_eq!(
            source.matches(": loop {").count(),
            1,
            "the block+loop counted idiom must collapse to ONE labeled loop:\n{source}"
        );
        assert!(
            source.contains("break 'b1;"),
            "the br_if exit must retarget to break the collapsed loop label:\n{source}"
        );
        assert!(
            source.contains("continue 'b1;"),
            "the back edge must continue the collapsed loop label:\n{source}"
        );
        assert!(
            !source.contains("'b0:"),
            "the wrapping block label must be elided after the merge:\n{source}"
        );
    }

    #[test]
    fn counted_loop_collapses_to_single_labeled_loop_typescript() {
        let source: String = lift_only_function(COUNTED_LOOP, HighLang::TypeScript);
        assert_eq!(
            source.matches(": loop {").count(),
            1,
            "the block+loop counted idiom must collapse to ONE labeled loop:\n{source}"
        );
        assert!(source.contains("break 'b1;"), "{source}");
        assert!(source.contains("continue 'b1;"), "{source}");
    }

    #[test]
    fn counted_loop_collapses_to_single_label_c() {
        let source: String = lift_only_function(COUNTED_LOOP, HighLang::C);
        assert!(
            source.contains("c_entry_1:"),
            "the loop entry label must survive:\n{source}"
        );
        assert!(
            source.contains("c_exit_1:"),
            "the merged block exit must point at the loop's exit label:\n{source}"
        );
        assert!(
            source.contains("goto c_exit_1;"),
            "the br_if exit must goto the loop's exit label:\n{source}"
        );
        assert!(
            !source.contains("c_exit_0:"),
            "the wrapping block exit label must be elided:\n{source}"
        );
    }

    #[test]
    fn non_canonical_block_loop_is_not_collapsed() {
        let source: String = lift_only_function(TRAILING_OPS_AFTER_LOOP, HighLang::Rust);
        assert_eq!(
            source.matches(": loop {").count(),
            2,
            "a block with statements after its inner loop is NOT the counted idiom and must keep \
             both labeled loops:\n{source}"
        );
    }

    fn rustc_path() -> Option<std::path::PathBuf> {
        let probe: &str = if cfg!(windows) { "where" } else { "which" };
        let out: std::process::Output = std::process::Command::new(probe)
            .arg("rustc")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text: String = String::from_utf8_lossy(&out.stdout).to_string();
        let first: &str = text.lines().next()?.trim();
        (!first.is_empty()).then(|| std::path::PathBuf::from(first))
    }

    fn run_recovered_sum_to(wat: &str, arg: i32, tag: &str) -> Option<i32> {
        let rustc: std::path::PathBuf = rustc_path()?;
        let body: String = lift_only_function(wat, HighLang::Rust);
        let mut program: String = crate::lift::rust_runtime_prelude().to_owned();
        program.push('\n');
        program.push_str(&body);
        program.push_str("\nfn main() { println!(\"{}\", sum_to(");
        program.push_str(&arg.to_string());
        program.push_str(")); }\n");
        let purpose: String = format!("disrobe_merge_teeth_{tag}");
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&purpose).ok()?;
        let dir: std::path::PathBuf = scratch.path().to_path_buf();
        let rs: std::path::PathBuf = dir.join("recovered.rs");
        std::fs::write(&rs, &program).ok()?;
        let bin: std::path::PathBuf = dir.join(if cfg!(windows) { "rec.exe" } else { "rec" });
        let compiled: std::process::Output = std::process::Command::new(&rustc)
            .args(["--edition", "2021", "-O", "-o"])
            .arg(&bin)
            .arg(&rs)
            .output()
            .ok()?;
        assert!(
            compiled.status.success(),
            "rustc rejected recovered source ({tag}):\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let run: std::process::Output = std::process::Command::new(&bin).output().ok()?;
        String::from_utf8_lossy(&run.stdout)
            .trim()
            .parse::<i32>()
            .ok()
    }

    #[test]
    fn collapsed_counted_loop_computes_the_right_sum_under_rustc() {
        let Some(value): Option<i32> = run_recovered_sum_to(COUNTED_LOOP, 10, "ok") else {
            eprintln!("SKIP: rustc unavailable for the collapsed-loop teeth check");
            return;
        };
        assert_eq!(
            value, 45,
            "the collapsed single-loop counted form must still sum 0..10 to 45"
        );
    }

    #[test]
    fn a_wrong_loop_bound_flows_through_the_collapse_and_diverges() {
        let wrong_bound: String = COUNTED_LOOP.replace("i32.ge_s", "i32.gt_s");
        assert_ne!(
            wrong_bound, COUNTED_LOOP,
            "the fault injection must actually change the exit test"
        );
        let Some(value): Option<i32> = run_recovered_sum_to(&wrong_bound, 10, "wrong") else {
            eprintln!("SKIP: rustc unavailable for the wrong-bound teeth check");
            return;
        };
        assert_ne!(
            value, 45,
            "a deliberately wrong loop bound (>= becomes >) must produce a detectably different \
             result after the collapse, proving the oracle has teeth; got {value}"
        );
    }
}
