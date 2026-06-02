use std::fmt::Write;

use wasmparser::{BlockType, FunctionBody, Operator, ValType};

use crate::error::{Error, Result};
use crate::lift::{CalleeNames, HighLang, rust_op_fn_name, rust_unop_fn_name};
use crate::signature::FunctionSig;

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
}

struct Translator<'a> {
    lang: HighLang,
    callees: &'a CalleeNames,
    sig: &'a FunctionSig,
    locals: Vec<ValType>,
    stack: Vec<Operand>,
    control: Vec<Frame>,
    out: String,
    next_tmp: u32,
    next_label: usize,
    indent: usize,
    blocks_emitted: usize,
    unreachable: bool,
}

/// Lifts a function body from its (already-structured) WebAssembly operator stream to
/// compilable high-level source.
///
/// WASM bytecode is a properly-nested tree of `block`/`loop`/`if`/`else`/`end`, so this
/// forward pass needs no CFG reconstruction: control flow maps to labeled loops/blocks
/// and `if/else`, and the value stack maps to SSA-like temporaries. Returns
/// `(source, blocks_emitted)`.
pub(crate) fn lift_body_structured(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    lang: HighLang,
) -> Result<(String, usize)> {
    let locals: Vec<ValType> = read_locals(body, &sig.params)?;
    let mut t: Translator<'_> = Translator {
        lang,
        callees,
        sig,
        locals,
        stack: Vec::new(),
        control: Vec::new(),
        out: String::new(),
        next_tmp: 0,
        next_label: 0,
        indent: 1,
        blocks_emitted: 1,
        unreachable: false,
    };
    t.emit_local_decls();

    let reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    let mut ops: Vec<Operator<'_>> = Vec::new();
    for op in reader {
        ops.push(op.map_err(|e| Error::Parse(e.to_string()))?);
    }
    let op_count: usize = ops.len();
    for (i, op) in ops.iter().enumerate() {
        let is_final_end: bool = i + 1 == op_count && matches!(op, Operator::End);
        t.translate(op, is_final_end)?;
    }
    t.finish();
    Ok((t.out, t.blocks_emitted))
}

fn read_locals(body: &FunctionBody<'_>, params: &[ValType]) -> Result<Vec<ValType>> {
    let mut out: Vec<ValType> = params.to_vec();
    let reader: wasmparser::LocalsReader<'_> = body
        .get_locals_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    for item in reader {
        let (count, ty): (u32, ValType) = item.map_err(|e| Error::Parse(e.to_string()))?;
        for _ in 0..count {
            out.push(ty);
        }
    }
    Ok(out)
}

impl Translator<'_> {
    fn emit_signature_prefix(&self) -> String {
        let mut s: String = String::new();
        match self.lang {
            HighLang::Rust => {
                let _ = write!(s, "pub fn {}(", self.sig.name);
                for (i, ty) in self.sig.params.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    let _ = write!(s, "p{i}: {}", rust_ty(*ty));
                }
                s.push(')');
                if let Some(ret) = self.sig.results.first() {
                    let _ = write!(s, " -> {}", rust_ty(*ret));
                }
                s.push_str(" {\n");
            }
            HighLang::TypeScript => {
                let _ = write!(s, "export function {}(", self.sig.name);
                for (i, ty) in self.sig.params.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    let _ = write!(s, "p{i}: {}", ts_ty(*ty));
                }
                let ret: &str = self.sig.results.first().map_or("void", |t| ts_ty(*t));
                let _ = writeln!(s, "): {ret} {{");
            }
            HighLang::C => {
                let ret: &str = self.sig.results.first().map_or("void", |t| c_ty(*t));
                let _ = write!(s, "{ret} {}(", self.sig.name);
                if self.sig.params.is_empty() {
                    s.push_str("void");
                } else {
                    for (i, ty) in self.sig.params.iter().enumerate() {
                        if i > 0 {
                            s.push_str(", ");
                        }
                        let _ = write!(s, "{} p{i}", c_ty(*ty));
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
            match self.lang {
                HighLang::Rust => {
                    let _ = writeln!(self.out, "    let mut l{i}: {} = {init};", rust_ty(ty));
                }
                HighLang::TypeScript => {
                    let _ = writeln!(self.out, "    let l{i}: {} = {init};", ts_ty(ty));
                }
                HighLang::C => {
                    let _ = writeln!(self.out, "    {} l{i} = {init};", c_ty(ty));
                }
            }
        }
    }

    fn pad(&self) -> String {
        "    ".repeat(self.indent)
    }

    fn local_name(&self, idx: u32) -> String {
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

    /// Spills a value-producing expression to a typed temporary and pushes the temp.
    fn spill(&mut self, expr: &str, ty: ValType) {
        let name: String = self.fresh_tmp();
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust => {
                let _ = writeln!(self.out, "{pad}let {name}: {} = {expr};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                let _ = writeln!(self.out, "{pad}let {name}: {} = {expr};", ts_ty(ty));
            }
            HighLang::C => {
                let _ = writeln!(self.out, "{pad}{} {name} = {expr};", c_ty(ty));
            }
        }
        self.push(name, ty);
    }

    fn emit_stmt(&mut self, stmt: &str) {
        let pad: String = self.pad();
        let _ = writeln!(self.out, "{pad}{stmt}");
    }

    fn translate(&mut self, op: &Operator<'_>, is_final_end: bool) -> Result<()> {
        if self.unreachable && !is_structural(op) {
            return Ok(());
        }
        match op {
            Operator::Nop => {}
            Operator::Unreachable => {
                self.emit_unreachable();
                self.unreachable = true;
            }
            Operator::Block { blockty } => self.open_frame(FrameKind::Block, *blockty),
            Operator::Loop { blockty } => self.open_frame(FrameKind::Loop, *blockty),
            Operator::If { blockty } => self.open_if(*blockty)?,
            Operator::Else => self.do_else()?,
            Operator::End => self.close_frame(is_final_end),
            Operator::Br { relative_depth } => self.do_br(*relative_depth)?,
            Operator::BrIf { relative_depth } => self.do_br_if(*relative_depth)?,
            Operator::BrTable { targets } => self.do_br_table(targets)?,
            Operator::Return => self.do_return()?,
            Operator::Call { function_index } => self.do_call(*function_index)?,
            Operator::CallIndirect { type_index, .. } => self.do_call_indirect(*type_index)?,
            Operator::Drop => {
                self.pop("drop")?;
            }
            Operator::Select | Operator::TypedSelect { .. } => self.do_select()?,
            Operator::LocalGet { local_index } => {
                let ty: ValType = self.local_type(*local_index);
                self.push(self.local_name(*local_index), ty);
            }
            Operator::LocalSet { local_index } => {
                let v: Operand = self.pop("local.set")?;
                let name: String = self.local_name(*local_index);
                self.emit_stmt(&format!(
                    "{name} = {};",
                    coerce(&v, self.local_type(*local_index), self.lang)
                ));
            }
            Operator::LocalTee { local_index } => {
                let v: Operand = self.pop("local.tee")?;
                let name: String = self.local_name(*local_index);
                let ty: ValType = self.local_type(*local_index);
                self.emit_stmt(&format!("{name} = {};", coerce(&v, ty, self.lang)));
                self.push(name, ty);
            }
            Operator::GlobalGet { global_index } => self.do_global_get(*global_index),
            Operator::GlobalSet { global_index } => self.do_global_set(*global_index)?,
            Operator::I32Const { value } => self.push(rust_i32(*value, self.lang), ValType::I32),
            Operator::I64Const { value } => self.push(rust_i64(*value, self.lang), ValType::I64),
            Operator::F32Const { value } => {
                self.push(f32_lit(value.bits(), self.lang), ValType::F32);
            }
            Operator::F64Const { value } => {
                self.push(f64_lit(value.bits(), self.lang), ValType::F64);
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
            return Ok(());
        }
        if let Some((unop, ty)) = crate::ssa::unop_kind(op) {
            let a: Operand = self.pop("unop")?;
            let fname: String = self.helper(rust_unop_fn_name(unop));
            let expr: String = format!("{fname}({})", a.text);
            self.spill(&expr, unop_result_ty(unop, ty));
            return Ok(());
        }
        if let Some((suffix, ty, offset)) = load_descriptor(op) {
            let addr: Operand = self.pop("load")?;
            let fname: String = self.helper(&format!("wasm_load_{suffix}"));
            let expr: String = format!("{fname}({}, {offset})", addr.text);
            self.spill(&expr, ty);
            return Ok(());
        }
        if let Some((suffix, offset)) = store_descriptor(op) {
            let val: Operand = self.pop("store")?;
            let addr: Operand = self.pop("store")?;
            let fname: String = self.helper(&format!("wasm_store_{suffix}"));
            self.emit_stmt(&format!("{fname}({}, {offset}, {});", addr.text, val.text));
            return Ok(());
        }
        match op {
            Operator::MemorySize { .. } => {
                let f: String = self.helper("wasm_memory_size");
                let expr: String = format!("{f}()");
                self.spill(&expr, ValType::I32);
                Ok(())
            }
            Operator::MemoryGrow { .. } => {
                let delta: Operand = self.pop("memory.grow")?;
                let f: String = self.helper("wasm_memory_grow");
                let expr: String = format!("{f}({})", delta.text);
                self.spill(&expr, ValType::I32);
                Ok(())
            }
            _ => Err(Error::Parse(format!(
                "DR-WASMDEOB-STRUCT: unsupported operator ({:?})",
                core::mem::discriminant(op)
            ))),
        }
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
                let _ = writeln!(self.out, "{pad}let mut {var}: {} = {zero};", rust_ty(ty));
            }
            HighLang::TypeScript => {
                let _ = writeln!(self.out, "{pad}let {var}: {} = {zero};", ts_ty(ty));
            }
            HighLang::C => {
                let _ = writeln!(self.out, "{pad}{} {var} = {zero};", c_ty(ty));
            }
        }
        Some(var)
    }

    fn open_frame(&mut self, kind: FrameKind, blockty: BlockType) {
        let result: Option<ValType> = block_result(blockty);
        let label: usize = self.next_label;
        self.next_label += 1;
        let result_var: Option<String> = self.decl_result_var(label, result);
        let frame: Frame = Frame {
            kind,
            label,
            result,
            result_var,
            stack_height: self.stack.len(),
        };
        let pad: String = self.pad();
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                let lbl: String = block_label(&frame);
                let _ = writeln!(self.out, "{pad}{lbl}: loop {{");
                self.indent += 1;
            }
            HighLang::C => {
                if matches!(kind, FrameKind::Loop) {
                    let _ = writeln!(self.out, "{pad}c_entry_{label}: ;");
                }
                let _ = writeln!(self.out, "{pad}{{");
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
        let result_var: Option<String> = self.decl_result_var(label, result);
        let frame: Frame = Frame {
            kind: FrameKind::If,
            label,
            result,
            result_var,
            stack_height: self.stack.len(),
        };
        let pad: String = self.pad();
        let cond_expr: String = truthy(&cond, self.lang);
        match self.lang {
            HighLang::Rust | HighLang::TypeScript => {
                let lbl: String = block_label(&frame);
                let _ = writeln!(self.out, "{pad}{lbl}: loop {{");
                self.indent += 1;
                let pad2: String = self.pad();
                let _ = writeln!(self.out, "{pad2}if {cond_expr} {{");
                self.indent += 1;
            }
            HighLang::C => {
                let _ = writeln!(self.out, "{pad}{{");
                self.indent += 1;
                let pad2: String = self.pad();
                let _ = writeln!(self.out, "{pad2}if ({cond_expr}) {{");
                self.indent += 1;
            }
        }
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
        let value_on_stack: bool = self.stack.len() > frame.stack_height;
        if let (Some(var), true) = (frame.result_var.as_ref(), value_on_stack) {
            if let Some(top) = self.stack.last().cloned() {
                self.emit_stmt(&format!("{var} = {};", top.text));
            }
        }
        self.stack.truncate(frame.stack_height);

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
                let _ = writeln!(self.out, "{pad}match {sel} {{");
            }
            HighLang::TypeScript | HighLang::C => {
                let _ = writeln!(self.out, "{pad}switch ({sel}) {{");
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
                self.emit_stmt(&format!("{arm} => {{ {action} }}"));
            }
            HighLang::TypeScript | HighLang::C => {
                if is_default {
                    self.emit_stmt("default: {");
                } else {
                    self.emit_stmt(&format!("case {pat}: {{"));
                }
                self.indent += 1;
                self.emit_stmt(&action);
                self.indent -= 1;
                self.emit_stmt("}");
            }
        }
        Ok(())
    }

    fn assign_branch_result(&mut self, frame: &Frame) {
        if let (Some(var), Some(top)) = (frame.result_var.as_ref(), self.stack.last().cloned()) {
            self.emit_stmt(&format!("{var} = {};", top.text));
        }
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

const fn is_structural(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::End
            | Operator::Else
            | Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
    )
}

const fn block_result(blockty: BlockType) -> Option<ValType> {
    match blockty {
        BlockType::Type(t) => Some(t),
        BlockType::Empty | BlockType::FuncType(_) => None,
    }
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
        ValType::V128 | ValType::Ref(_) | ValType::I32 => "int32_t",
    }
}

const fn zero_lit(ty: ValType, lang: HighLang) -> &'static str {
    match (lang, ty) {
        (HighLang::Rust, ValType::I64) => "0i64",
        (HighLang::Rust, ValType::F32) => "0.0f32",
        (HighLang::Rust, ValType::F64) => "0.0f64",
        (HighLang::Rust, ValType::V128) => "0u128",
        (HighLang::Rust, _) => "0i32",
        (HighLang::TypeScript, ValType::I64 | ValType::V128) => "0n",
        (HighLang::TypeScript, _) => "0",
        (HighLang::C, ValType::I64) => "0LL",
        (HighLang::C, ValType::F32 | ValType::F64) => "0.0",
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

const fn load_descriptor(op: &Operator<'_>) -> Option<(&'static str, ValType, u64)> {
    use wasmparser::ValType as V;
    Some(match op {
        Operator::I32Load { memarg } => ("i32", V::I32, memarg.offset),
        Operator::I64Load { memarg } => ("i64", V::I64, memarg.offset),
        Operator::F32Load { memarg } => ("f32", V::F32, memarg.offset),
        Operator::F64Load { memarg } => ("f64", V::F64, memarg.offset),
        Operator::I32Load8U { memarg } => ("i32_8u", V::I32, memarg.offset),
        Operator::I32Load8S { memarg } => ("i32_8s", V::I32, memarg.offset),
        Operator::I32Load16U { memarg } => ("i32_16u", V::I32, memarg.offset),
        Operator::I32Load16S { memarg } => ("i32_16s", V::I32, memarg.offset),
        Operator::I64Load8U { memarg } => ("i64_8u", V::I64, memarg.offset),
        Operator::I64Load8S { memarg } => ("i64_8s", V::I64, memarg.offset),
        Operator::I64Load16U { memarg } => ("i64_16u", V::I64, memarg.offset),
        Operator::I64Load16S { memarg } => ("i64_16s", V::I64, memarg.offset),
        Operator::I64Load32U { memarg } => ("i64_32u", V::I64, memarg.offset),
        Operator::I64Load32S { memarg } => ("i64_32s", V::I64, memarg.offset),
        _ => return None,
    })
}

const fn store_descriptor(op: &Operator<'_>) -> Option<(&'static str, u64)> {
    Some(match op {
        Operator::I32Store { memarg } => ("i32", memarg.offset),
        Operator::I64Store { memarg } => ("i64", memarg.offset),
        Operator::F32Store { memarg } => ("f32", memarg.offset),
        Operator::F64Store { memarg } => ("f64", memarg.offset),
        Operator::I32Store8 { memarg } => ("i32_8", memarg.offset),
        Operator::I32Store16 { memarg } => ("i32_16", memarg.offset),
        Operator::I64Store8 { memarg } => ("i64_8", memarg.offset),
        Operator::I64Store16 { memarg } => ("i64_16", memarg.offset),
        Operator::I64Store32 { memarg } => ("i64_32", memarg.offset),
        _ => return None,
    })
}
