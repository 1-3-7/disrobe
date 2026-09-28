use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::decompile::{Expr, MAX_DUP_EXPR_NODES, expr_node_count_capped};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{DexFile, FieldId, MethodId};

#[derive(Clone, Copy)]
pub(crate) struct MethodIdentity<'a> {
    pub(crate) declaring_class: &'a str,
    pub(crate) descriptor: &'a str,
    pub(crate) is_static: bool,
    pub(crate) is_constructor: bool,
}

pub(crate) struct MethodContext<'a> {
    pub(crate) dex: &'a DexFile,
    pub(crate) declaring_class: &'a str,
    pub(crate) desugar: crate::dalvik_desugar::DesugarView<'a>,
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) is_static: bool,
    pub(crate) is_constructor: bool,
    pub(crate) return_type: Option<crate::descriptor::JavaType>,
    pub(crate) inline_temporaries: bool,
    pub(crate) param_regs: BTreeMap<u16, String>,
    pub(crate) this_reg: Option<u16>,
    pub(crate) inline_depth: u16,
    pub(crate) inlined_helpers: &'a crate::dalvik_desugar::InlinedHelpers,
    pub(crate) register_kinds: BTreeMap<u16, ValueKind>,
    pub(crate) naming: Option<&'a RegisterNaming>,
    pub(crate) code: &'a [u16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalType {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Reference(String),
}

impl LocalType {
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Boolean => "boolean".to_owned(),
            Self::Byte => "byte".to_owned(),
            Self::Char => "char".to_owned(),
            Self::Short => "short".to_owned(),
            Self::Int => "int".to_owned(),
            Self::Long => "long".to_owned(),
            Self::Float => "float".to_owned(),
            Self::Double => "double".to_owned(),
            Self::Reference(source) => source.clone(),
        }
    }

    const fn kind(&self) -> Option<ValueKind> {
        match self {
            Self::Boolean => Some(ValueKind::Boolean),
            Self::Byte | Self::Char | Self::Short | Self::Int => Some(ValueKind::IntLike),
            Self::Reference(_) => Some(ValueKind::Reference),
            Self::Long | Self::Float | Self::Double => None,
        }
    }

    const fn narrow_cast(&self) -> Option<&'static str> {
        match self {
            Self::Byte => Some("byte"),
            Self::Char => Some("char"),
            Self::Short => Some("short"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedLocal {
    pub(crate) name: String,
    pub(crate) ty: Option<LocalType>,
    pub(crate) declared: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RegisterNaming {
    pub(crate) locals: Vec<NamedLocal>,
    pub(crate) def_locals: BTreeMap<(u32, u16), usize>,
    pub(crate) by_name: BTreeMap<String, usize>,
    pub(crate) threaded_receivers: BTreeSet<u32>,
}

impl RegisterNaming {
    pub(crate) fn def_local(&self, pc: u32, register: u16) -> Option<&NamedLocal> {
        self.def_locals
            .get(&(pc, register))
            .and_then(|&index: &usize| self.locals.get(index))
    }

    pub(crate) fn named(&self, name: &str) -> Option<&NamedLocal> {
        self.by_name
            .get(name)
            .and_then(|&index: &usize| self.locals.get(index))
    }
}

impl<'a> MethodContext<'a> {
    pub(crate) fn new(
        dex: &'a DexFile,
        identity: MethodIdentity<'a>,
        registers_size: u16,
        ins_size: u16,
        inline_temporaries: bool,
        desugar: crate::dalvik_desugar::DesugarView<'a>,
        inlined_helpers: &'a crate::dalvik_desugar::InlinedHelpers,
    ) -> Self {
        let parsed: Option<MethodDescriptor> = descriptor::parse_method(identity.descriptor);
        let return_type: Option<crate::descriptor::JavaType> = parsed
            .as_ref()
            .map(|method: &MethodDescriptor| method.returns.clone());
        let first_param_reg: u16 = registers_size.saturating_sub(ins_size);
        let mut param_regs: BTreeMap<u16, String> = BTreeMap::new();
        let mut register_kinds: BTreeMap<u16, ValueKind> = BTreeMap::new();
        let mut this_reg: Option<u16> = None;
        let mut cursor: u16 = first_param_reg;
        if !identity.is_static {
            this_reg = Some(cursor);
            cursor = cursor.saturating_add(1);
        }
        if let Some(md) = &parsed {
            for (i, p) in md.params.iter().enumerate() {
                param_regs.insert(cursor, format!("arg{i}"));
                if let Some(kind) = java_type_value_kind(p) {
                    register_kinds.insert(cursor, kind);
                }
                let step: u16 = if p.category_two() { 2 } else { 1 };
                cursor = cursor.saturating_add(step);
            }
        }
        Self {
            dex,
            declaring_class: identity.declaring_class,
            desugar,
            registers_size,
            ins_size,
            is_static: identity.is_static,
            is_constructor: identity.is_constructor,
            return_type,
            inline_temporaries,
            param_regs,
            this_reg,
            inline_depth: 0,
            inlined_helpers,
            register_kinds,
            naming: None,
            code: &[],
        }
    }

    pub(crate) fn with_parameter_names(mut self, names: &[String]) -> Self {
        for (slot, name) in self.param_regs.values_mut().zip(names) {
            slot.clone_from(name);
        }
        self
    }

    pub(crate) const fn with_naming(mut self, naming: &'a RegisterNaming) -> Self {
        self.naming = Some(naming);
        self
    }

    pub(crate) const fn with_code(mut self, code: &'a [u16]) -> Self {
        self.code = code;
        self
    }

    pub(crate) fn def_lvalue(&self, pc: u32, reg: u16) -> String {
        self.naming
            .and_then(|naming: &RegisterNaming| naming.def_local(pc, reg))
            .map_or_else(
                || self.register_lvalue(reg),
                |local: &NamedLocal| local.name.clone(),
            )
    }

    fn def_type(&self, pc: u32, reg: u16) -> Option<&LocalType> {
        self.naming
            .and_then(|naming: &RegisterNaming| naming.def_local(pc, reg))
            .and_then(|local: &NamedLocal| local.ty.as_ref())
    }

    fn threads_receiver(&self, pc: u32) -> bool {
        self.naming
            .is_none_or(|naming: &RegisterNaming| naming.threaded_receivers.contains(&pc))
    }

    pub(crate) fn register_name(&self, reg: u16) -> Expr {
        if Some(reg) == self.this_reg {
            return Expr::This;
        }
        if let Some(name) = self.param_regs.get(&reg) {
            return Expr::Local(name.clone());
        }
        Expr::Local(format!("var{reg}"))
    }

    pub(crate) fn register_lvalue(&self, reg: u16) -> String {
        if let Some(name) = self.param_regs.get(&reg) {
            return name.clone();
        }
        format!("var{reg}")
    }

    fn method_id(&self, index: u32) -> Option<&MethodId> {
        self.dex.method_ids.get(index as usize)
    }

    fn field_id(&self, index: u32) -> Option<&FieldId> {
        self.dex.field_ids.get(index as usize)
    }

    fn string_at(&self, index: u32) -> Option<&str> {
        self.dex.strings.get(index as usize).map(String::as_str)
    }

    fn type_at(&self, index: u32) -> Option<&str> {
        self.dex.type_names.get(index as usize).map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueKind {
    Boolean,
    IntLike,
    Reference,
}

const fn java_type_value_kind(ty: &crate::descriptor::JavaType) -> Option<ValueKind> {
    match ty {
        crate::descriptor::JavaType::Boolean => Some(ValueKind::Boolean),
        crate::descriptor::JavaType::Byte
        | crate::descriptor::JavaType::Char
        | crate::descriptor::JavaType::Short
        | crate::descriptor::JavaType::Int => Some(ValueKind::IntLike),
        crate::descriptor::JavaType::Object(_) | crate::descriptor::JavaType::Array(_) => {
            Some(ValueKind::Reference)
        }
        crate::descriptor::JavaType::Long
        | crate::descriptor::JavaType::Float
        | crate::descriptor::JavaType::Double
        | crate::descriptor::JavaType::Void => None,
    }
}

pub(crate) struct RegisterFile {
    slots: BTreeMap<u16, Expr>,
    pending: BTreeSet<u16>,
    kinds: BTreeMap<u16, ValueKind>,
}

impl RegisterFile {
    pub(crate) const fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            pending: BTreeSet::new(),
            kinds: BTreeMap::new(),
        }
    }

    fn read(&self, ctx: &MethodContext<'_>, reg: u16) -> Expr {
        match self.slots.get(&reg) {
            Some(expr) if expr_node_count_capped(expr, MAX_DUP_EXPR_NODES) < MAX_DUP_EXPR_NODES => {
                expr.clone()
            }
            Some(_) => Expr::Opaque("?".to_string()),
            None => ctx.register_name(reg),
        }
    }

    fn write(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
        self.pending.insert(reg);
        self.kinds.remove(&reg);
    }

    fn write_with_kind(&mut self, reg: u16, expr: Expr, kind: Option<ValueKind>) {
        self.write(reg, expr);
        if let Some(kind) = kind {
            self.kinds.insert(reg, kind);
        }
    }

    fn write_materialized(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
        self.pending.remove(&reg);
        self.kinds.remove(&reg);
    }

    fn seed_register_with_name(&mut self, ctx: &MethodContext<'_>, reg: u16) {
        self.slots.insert(reg, ctx.register_name(reg));
        self.pending.remove(&reg);
        self.kinds.remove(&reg);
    }

    pub(crate) fn current(&self, ctx: &MethodContext<'_>, reg: u16) -> Expr {
        self.read(ctx, reg)
    }

    pub(crate) fn pending_registers(&self) -> impl Iterator<Item = u16> + '_ {
        self.pending.iter().copied()
    }

    pub(crate) fn seed(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
        self.pending.remove(&reg);
        self.kinds.remove(&reg);
    }

    pub(crate) fn slot(&self, reg: u16) -> Option<&Expr> {
        self.slots.get(&reg)
    }

    pub(crate) fn is_pending(&self, reg: u16) -> bool {
        self.pending.contains(&reg)
    }

    pub(crate) fn set_variable(&mut self, reg: u16, name: String) {
        self.seed(reg, Expr::Local(name));
    }

    pub(crate) fn defer(&mut self, reg: u16) {
        self.pending.insert(reg);
    }

    pub(crate) fn replace(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
    }
}

pub(crate) enum LiftOutcome {
    Statement(String),
    Statements(Vec<String>),
    None,
    Unlifted,
}

pub(crate) struct PendingResult {
    expr: Expr,
    materialized_in: Option<u16>,
    kind: Option<ValueKind>,
}

impl PendingResult {
    pub(crate) fn materializes(&self, reg: u16) -> bool {
        self.materialized_in == Some(reg)
    }

    pub(crate) fn discards_statement(&self) -> bool {
        self.expr.discarded_side_effect().is_some()
    }

    pub(crate) fn is_null_check(&self) -> bool {
        is_null_check_call(&self.expr)
    }

    pub(crate) fn into_statement(self) -> Option<String> {
        if self.materialized_in.is_some() {
            return None;
        }
        self.expr.discarded_side_effect()
    }
}

fn descriptor_value_kind(type_descriptor: &str) -> Option<ValueKind> {
    crate::descriptor::parse_field(type_descriptor)
        .as_ref()
        .and_then(java_type_value_kind)
}

#[derive(Debug, Eq, PartialEq)]
enum DirectInitTarget {
    Allocate,
    This,
    Super,
    Invalid,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn lift_insn(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending_result: &mut Option<PendingResult>,
) -> LiftOutcome {
    let op: u8 = insn.op;
    let regs: &[u16] = &insn.regs;
    let receiver_consumes_pending: bool = matches!(op, 0x6E..=0x72 | 0x74..=0x78)
        && pending_result
            .as_ref()
            .and_then(|result: &PendingResult| result.materialized_in)
            .is_some_and(|register: u16| regs.first() == Some(&register));
    let discarded: Option<String> = if matches!(op, 0x0A..=0x0C) {
        None
    } else if receiver_consumes_pending {
        let _: Option<PendingResult> = pending_result.take();
        None
    } else {
        pending_result
            .take()
            .and_then(|result: PendingResult| result.expr.discarded_side_effect())
    };
    let outcome: LiftOutcome = match op {
        0x00 | 0x1D | 0x1E => LiftOutcome::None,
        0x01..=0x09 => move_register(ctx, file, insn),
        0x0A..=0x0C => {
            if let (Some(&dest), Some(result)) = (regs.first(), pending_result.take()) {
                file.write_with_kind(dest, result.expr, result.kind);
            }
            LiftOutcome::None
        }
        0x0D => {
            if let Some(&dest) = regs.first() {
                file.write(dest, Expr::Local("ex".to_string()));
            }
            LiftOutcome::None
        }
        0x0E => {
            if matches!(ctx.return_type, Some(crate::descriptor::JavaType::Void)) {
                LiftOutcome::Statement("return".to_string())
            } else {
                LiftOutcome::Unlifted
            }
        }
        0x0F..=0x11 => {
            let Some(return_type): Option<&crate::descriptor::JavaType> = ctx.return_type.as_ref()
            else {
                return LiftOutcome::Unlifted;
            };
            if !return_opcode_matches(op, return_type) {
                return LiftOutcome::Unlifted;
            }
            let Some(&register): Option<&u16> = regs.first() else {
                return LiftOutcome::Unlifted;
            };
            let value: Expr = file.read(ctx, register);
            let Some(rendered): Option<String> =
                render_return_value(ctx, file, op, register, &value)
            else {
                return LiftOutcome::Unlifted;
            };
            LiftOutcome::Statement(format!("return {rendered}"))
        }
        0x12..=0x19 => const_value(ctx, file, regs, insn),
        0x1A | 0x1B => const_string(ctx, file, regs, insn),
        0x1C => const_class(ctx, file, regs, insn),
        0x1F => check_cast(ctx, file, regs, insn),
        0x20 => instance_of(ctx, file, regs, insn),
        0x21 => array_length(ctx, file, regs),
        0x22 => new_instance(ctx, file, regs, insn),
        0x23 => new_array(ctx, file, regs, insn),
        0x24 | 0x25 => filled_new_array(ctx, file, insn, pending_result),
        0x26 => fill_array_data(ctx, file, insn),
        0x27 => {
            let value: Expr = regs
                .first()
                .map_or_else(|| Expr::Opaque("?".to_string()), |&r| file.read(ctx, r));
            LiftOutcome::Statement(format!("throw {}", value.render()))
        }
        0x44..=0x4A => array_get(ctx, file, regs, op),
        0x4B..=0x51 => array_put(ctx, file, regs, op),
        0x52..=0x58 => instance_get(ctx, file, regs, insn),
        0x59..=0x5F => instance_put(ctx, file, regs, insn),
        0x60..=0x66 => static_get(ctx, file, regs, insn),
        0x67..=0x6D => static_put(ctx, file, regs, insn),
        0x6E..=0x72 | 0x74..=0x78 => invoke(ctx, file, insn, pending_result),
        0x7B | 0x7D | 0x7F => unary(ctx, file, regs, "-"),
        0x7C | 0x7E => unary(ctx, file, regs, "~"),
        0x81..=0x8F => numeric_cast(ctx, file, regs, op),
        0x90..=0x97 | 0x9B..=0xA2 | 0xA6..=0xAF => {
            binary_three(ctx, file, regs, arith_op(op), matches!(op, 0x90..=0x97))
        }
        0x98..=0x9A | 0xA3..=0xA5 => {
            binary_three(ctx, file, regs, arith_op(op), matches!(op, 0x98..=0x9A))
        }
        0xB0..=0xB7 | 0xBB..=0xC2 | 0xC6..=0xCF => {
            binary_2addr(ctx, file, regs, arith_op(op), matches!(op, 0xB0..=0xB7))
        }
        0xB8..=0xBA | 0xC3..=0xC5 => {
            binary_2addr(ctx, file, regs, arith_op(op), matches!(op, 0xB8..=0xBA))
        }
        0x2D..=0x31 => cmp_three(ctx, file, regs, op),
        0xD0..=0xD7 => binary_lit(ctx, file, regs, insn, arith_lit_op(op)),
        0xD8..=0xE2 => binary_lit(ctx, file, regs, insn, arith_lit_op(op)),
        0x28..=0x2C | 0x32..=0x3D => LiftOutcome::None,
        _ => LiftOutcome::Unlifted,
    };
    match (discarded, outcome) {
        (Some(side_effect), LiftOutcome::Statement(statement)) => {
            LiftOutcome::Statements(vec![side_effect, statement])
        }
        (Some(side_effect), LiftOutcome::Statements(mut statements)) => {
            statements.insert(0, side_effect);
            LiftOutcome::Statements(statements)
        }
        (Some(side_effect), LiftOutcome::None) => LiftOutcome::Statement(side_effect),
        (_, LiftOutcome::Unlifted) => LiftOutcome::Unlifted,
        (None, outcome) => outcome,
    }
}

fn move_register(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) =
        (insn.regs.first(), insn.regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let value: Expr = file.read(ctx, src);
    let kind: Option<ValueKind> = operand_value_kind(ctx, file, src, &value);
    if ctx.inline_temporaries {
        file.write_with_kind(dest, value, kind);
        return LiftOutcome::None;
    }
    let lvalue: String = ctx.def_lvalue(insn.pc, dest);
    let rendered: String = assignment_value(ctx, file, src, &value, ctx.def_type(insn.pc, dest));
    let stored: Expr = if expr_has_effect(&value) || expr_mentions_local(&value, &lvalue) {
        Expr::Local(lvalue.clone())
    } else {
        value
    };
    file.write_materialized(dest, stored);
    if let Some(kind) = kind {
        file.kinds.insert(dest, kind);
    }
    LiftOutcome::Statement(format!("{lvalue} = {rendered}"))
}

pub(crate) fn assignment_value(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    register: u16,
    value: &Expr,
    target: Option<&LocalType>,
) -> String {
    match target {
        Some(LocalType::Boolean) => {
            render_boolean_value(ctx, file, register, value).unwrap_or_else(|| value.render())
        }
        Some(ty @ (LocalType::Byte | LocalType::Char | LocalType::Short | LocalType::Int)) => {
            let numeric: Expr = numeric_int_operand(ctx, file, register, value.clone());
            match ty.narrow_cast() {
                Some(cast) if !is_narrow_value(ctx, &numeric, ty, cast) => {
                    format!("({cast}) ({})", numeric.render())
                }
                _ => numeric.render(),
            }
        }
        Some(LocalType::Long | LocalType::Float | LocalType::Double | LocalType::Reference(_))
        | None => value.render(),
    }
}

fn is_narrow_value(ctx: &MethodContext<'_>, value: &Expr, ty: &LocalType, cast: &str) -> bool {
    match value {
        Expr::Cast { ty: target, .. } => target == cast,
        Expr::Local(name) => ctx
            .naming
            .and_then(|naming: &RegisterNaming| naming.named(name))
            .is_some_and(|local: &NamedLocal| local.ty.as_ref() == Some(ty)),
        _ => false,
    }
}

pub(crate) fn expr_mentions_local(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Local(local) => local == name,
        Expr::Opaque(text) => text_mentions_identifier(text, name),
        Expr::Const(_) | Expr::This | Expr::StaticField { .. } | Expr::New(_) => false,
        Expr::Field { receiver, .. } => expr_mentions_local(receiver, name),
        Expr::Binary { lhs, rhs, .. }
        | Expr::Cmp { lhs, rhs, .. }
        | Expr::ArrayLoad {
            array: lhs,
            index: rhs,
        } => expr_mentions_local(lhs, name) || expr_mentions_local(rhs, name),
        Expr::Unary { value, .. }
        | Expr::Cast { value, .. }
        | Expr::InstanceOf { value, .. }
        | Expr::ArrayLength(value)
        | Expr::NewArray { size: value, .. } => expr_mentions_local(value, name),
        Expr::ArrayInit { elements, .. } => elements
            .iter()
            .any(|element: &Expr| expr_mentions_local(element, name)),
        Expr::Invoke { receiver, args, .. } => {
            receiver
                .as_deref()
                .is_some_and(|value: &Expr| expr_mentions_local(value, name))
                || args.iter().any(|arg: &Expr| expr_mentions_local(arg, name))
        }
    }
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
}

fn identifier_at(text: &str, start: usize, length: usize) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let before: Option<u8> = start
        .checked_sub(1)
        .and_then(|at: usize| bytes.get(at).copied());
    let after: Option<u8> = bytes.get(start + length).copied();
    !before.is_some_and(|byte: u8| is_identifier_byte(byte) || byte == b'.')
        && !after.is_some_and(is_identifier_byte)
}

fn text_mentions_identifier(text: &str, name: &str) -> bool {
    text.match_indices(name)
        .any(|(start, _): (usize, &str)| identifier_at(text, start, name.len()))
}

pub(crate) fn rename_local(expr: &Expr, from: &str, to: &str) -> Expr {
    let rename = |value: &Expr| Box::new(rename_local(value, from, to));
    match expr {
        Expr::Local(local) if local == from => Expr::Local(to.to_owned()),
        Expr::Opaque(text) => Expr::Opaque(rename_identifier(text, from, to)),
        Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::StaticField { .. } | Expr::New(_) => {
            expr.clone()
        }
        Expr::Field {
            receiver,
            owner,
            name,
            boolean,
        } => Expr::Field {
            receiver: rename(receiver),
            owner: owner.clone(),
            name: name.clone(),
            boolean: *boolean,
        },
        Expr::Binary { op, lhs, rhs } => Expr::Binary {
            op,
            lhs: rename(lhs),
            rhs: rename(rhs),
        },
        Expr::Cmp { kind, lhs, rhs } => Expr::Cmp {
            kind: *kind,
            lhs: rename(lhs),
            rhs: rename(rhs),
        },
        Expr::ArrayLoad { array, index } => Expr::ArrayLoad {
            array: rename(array),
            index: rename(index),
        },
        Expr::Unary { op, value } => Expr::Unary {
            op,
            value: rename(value),
        },
        Expr::Cast { ty, value } => Expr::Cast {
            ty: ty.clone(),
            value: rename(value),
        },
        Expr::InstanceOf { value, ty } => Expr::InstanceOf {
            value: rename(value),
            ty: ty.clone(),
        },
        Expr::ArrayLength(value) => Expr::ArrayLength(rename(value)),
        Expr::NewArray { ty, size } => Expr::NewArray {
            ty: ty.clone(),
            size: rename(size),
        },
        Expr::ArrayInit { ty, elements } => Expr::ArrayInit {
            ty: ty.clone(),
            elements: elements
                .iter()
                .map(|element: &Expr| rename_local(element, from, to))
                .collect(),
        },
        Expr::Invoke {
            receiver,
            owner,
            method,
            args,
            returns_bool,
        } => Expr::Invoke {
            receiver: receiver.as_deref().map(rename),
            owner: owner.clone(),
            method: method.clone(),
            args: args
                .iter()
                .map(|arg: &Expr| rename_local(arg, from, to))
                .collect(),
            returns_bool: *returns_bool,
        },
    }
}

fn rename_identifier(text: &str, from: &str, to: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut copied: usize = 0;
    for (start, _) in text.match_indices(from) {
        if start < copied || !identifier_at(text, start, from.len()) {
            continue;
        }
        out.push_str(text.get(copied..start).unwrap_or_default());
        out.push_str(to);
        copied = start + from.len();
    }
    out.push_str(text.get(copied..).unwrap_or_default());
    out
}

pub(crate) fn expr_has_effect(expr: &Expr) -> bool {
    match expr {
        Expr::Invoke { .. } | Expr::NewArray { .. } | Expr::ArrayInit { .. } => true,
        Expr::Opaque(text) => text != "?",
        Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::StaticField { .. } | Expr::New(_) => {
            false
        }
        Expr::Field { receiver, .. } => expr_has_effect(receiver),
        Expr::Binary { lhs, rhs, .. }
        | Expr::Cmp { lhs, rhs, .. }
        | Expr::ArrayLoad {
            array: lhs,
            index: rhs,
        } => expr_has_effect(lhs) || expr_has_effect(rhs),
        Expr::Unary { value, .. }
        | Expr::Cast { value, .. }
        | Expr::InstanceOf { value, .. }
        | Expr::ArrayLength(value) => expr_has_effect(value),
    }
}

const CONFINED_BUILDERS: [&str; 2] = ["StringBuilder", "StringBuffer"];

fn is_null_check_call(expr: &Expr) -> bool {
    match expr {
        Expr::Invoke {
            receiver: Some(_),
            owner,
            method,
            args,
            ..
        } => owner == "Object" && method == "getClass" && args.is_empty(),
        Expr::Invoke {
            receiver: None,
            owner,
            method,
            args,
            ..
        } => owner == "java.util.Objects" && method == "requireNonNull" && args.len() == 1,
        _ => false,
    }
}

pub(crate) fn expr_reads_state(expr: &Expr) -> bool {
    match expr {
        Expr::Field { .. } | Expr::StaticField { .. } | Expr::ArrayLoad { .. } => true,
        Expr::Invoke {
            receiver,
            owner,
            method,
            args,
            ..
        } => {
            let confined: bool = CONFINED_BUILDERS.contains(&owner.as_str())
                && matches!(method.as_str(), "append" | "toString" | "length")
                && receiver.is_some();
            !confined
                || receiver.as_deref().is_some_and(expr_reads_state)
                || args.iter().any(expr_reads_state)
        }
        Expr::Opaque(text) => !CONFINED_BUILDERS
            .iter()
            .any(|builder: &&str| *text == format!("new {builder}()")),
        Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::New(_) => false,
        Expr::Binary { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_state(lhs) || expr_reads_state(rhs)
        }
        Expr::Unary { value, .. }
        | Expr::Cast { value, .. }
        | Expr::InstanceOf { value, .. }
        | Expr::ArrayLength(value)
        | Expr::NewArray { size: value, .. } => expr_reads_state(value),
        Expr::ArrayInit { elements, .. } => elements.iter().any(expr_reads_state),
    }
}

fn render_return_value(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    op: u8,
    register: u16,
    value: &Expr,
) -> Option<String> {
    if op != 0x0F || !matches!(ctx.return_type, Some(crate::descriptor::JavaType::Boolean)) {
        return Some(value.render());
    }
    render_boolean_value(ctx, file, register, value)
}

const fn return_opcode_matches(op: u8, return_type: &crate::descriptor::JavaType) -> bool {
    match op {
        0x0F => matches!(
            return_type,
            crate::descriptor::JavaType::Byte
                | crate::descriptor::JavaType::Char
                | crate::descriptor::JavaType::Float
                | crate::descriptor::JavaType::Int
                | crate::descriptor::JavaType::Short
                | crate::descriptor::JavaType::Boolean
        ),
        0x10 => matches!(
            return_type,
            crate::descriptor::JavaType::Long | crate::descriptor::JavaType::Double
        ),
        0x11 => matches!(
            return_type,
            crate::descriptor::JavaType::Object(_) | crate::descriptor::JavaType::Array(_)
        ),
        _ => false,
    }
}

fn render_boolean_value(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    register: u16,
    value: &Expr,
) -> Option<String> {
    if expression_is_boolean(value) {
        return Some(value.render());
    }
    if let Expr::Const(constant) = value {
        return Some(match constant.as_str() {
            "0" => "false".to_owned(),
            "1" => "true".to_owned(),
            _ => format!("{constant} != 0"),
        });
    }
    let kind: ValueKind = file
        .kinds
        .get(&register)
        .copied()
        .or_else(|| match value {
            Expr::Local(name) => local_value_kind(ctx, name),
            _ => None,
        })
        .or_else(|| expression_int_kind(value))?;
    match kind {
        ValueKind::Boolean => Some(value.render()),
        ValueKind::IntLike => Some(format!("{} != 0", value.render())),
        ValueKind::Reference => None,
    }
}

fn local_value_kind(ctx: &MethodContext<'_>, name: &str) -> Option<ValueKind> {
    if let Some(naming) = ctx.naming
        && let Some(local) = naming.named(name)
    {
        return local.ty.as_ref().and_then(LocalType::kind);
    }
    let register: u16 = ctx
        .param_regs
        .iter()
        .find_map(|(register, parameter): (&u16, &String)| (parameter == name).then_some(*register))
        .or_else(|| name.strip_prefix("var")?.parse::<u16>().ok())?;
    ctx.register_kinds.get(&register).copied()
}

fn expression_int_kind(value: &Expr) -> Option<ValueKind> {
    match value {
        Expr::Binary { op, .. }
            if matches!(
                *op,
                "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>" | ">>>"
            ) =>
        {
            Some(ValueKind::IntLike)
        }
        Expr::Unary { op, .. } if matches!(*op, "-" | "~") => Some(ValueKind::IntLike),
        Expr::Cast { ty, .. } if matches!(ty.as_str(), "int" | "byte" | "short" | "char") => {
            Some(ValueKind::IntLike)
        }
        Expr::Cmp { .. } | Expr::ArrayLength(_) => Some(ValueKind::IntLike),
        _ => None,
    }
}

fn expression_is_boolean(value: &Expr) -> bool {
    match value {
        Expr::Const(constant) => matches!(constant.as_str(), "true" | "false"),
        Expr::InstanceOf { .. } => true,
        Expr::Invoke { returns_bool, .. } => *returns_bool,
        Expr::Cast { ty, .. } => ty == "boolean",
        Expr::Field { boolean, .. } | Expr::StaticField { boolean, .. } => *boolean,
        Expr::Binary { op, .. } => {
            matches!(*op, "==" | "!=" | "<" | "<=" | ">" | ">=" | "&&" | "||")
        }
        Expr::Unary { op, .. } => *op == "!",
        Expr::Local(_)
        | Expr::Opaque(_)
        | Expr::This
        | Expr::Cmp { .. }
        | Expr::ArrayLength(_)
        | Expr::ArrayLoad { .. }
        | Expr::New(_)
        | Expr::NewArray { .. }
        | Expr::ArrayInit { .. } => false,
    }
}

fn const_value(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let raw: i64 = insn.literal.unwrap_or(0);
    let value: i64 = match insn.op {
        0x15 => i64::from((raw as i32).wrapping_shl(16)),
        0x19 => raw.wrapping_shl(48),
        _ => raw,
    };
    let wide: bool = matches!(insn.op, 0x16..=0x19);
    let literal: String = match ctx.def_type(insn.pc, dest) {
        Some(LocalType::Double) if wide => double_literal(value as u64),
        Some(LocalType::Float) if !wide => float_literal(value as u32),
        Some(LocalType::Reference(_)) if value == 0 => "null".to_owned(),
        _ if wide => format!("{value}L"),
        _ => value.to_string(),
    };
    file.write(dest, Expr::Const(literal));
    LiftOutcome::None
}

pub(crate) fn double_literal(bits: u64) -> String {
    let value: f64 = f64::from_bits(bits);
    if value.is_finite() {
        format!("{value:?}")
    } else {
        format!("Double.longBitsToDouble({}L)", bits as i64)
    }
}

pub(crate) fn float_literal(bits: u32) -> String {
    let value: f32 = f32::from_bits(bits);
    if value.is_finite() {
        format!("{value:?}f")
    } else {
        format!("Float.intBitsToFloat({})", bits as i32)
    }
}

fn const_string(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let Some(text): Option<&str> = insn.index.and_then(|i| ctx.string_at(i)) else {
        return LiftOutcome::Unlifted;
    };
    file.write(dest, Expr::Const(crate::bytecode::escape_java_string(text)));
    LiftOutcome::None
}

fn const_class(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn.index.and_then(|i| ctx.type_at(i)).map_or_else(
        || "Object".to_string(),
        |value: &str| source_type(ctx, value),
    );
    let text: String = format!("{ty}.class");
    file.write(dest, Expr::Const(text));
    LiftOutcome::None
}

fn check_cast(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn.index.and_then(|i| ctx.type_at(i)).map_or_else(
        || "Object".to_string(),
        |value: &str| source_type(ctx, value),
    );
    let value: Expr = file.read(ctx, dest);
    file.write(
        dest,
        Expr::Cast {
            ty,
            value: Box::new(value),
        },
    );
    LiftOutcome::None
}

fn instance_of(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let ty: String = insn.index.and_then(|i| ctx.type_at(i)).map_or_else(
        || "Object".to_string(),
        |value: &str| source_type(ctx, value),
    );
    let value: Expr = file.read(ctx, src);
    file.write(
        dest,
        Expr::InstanceOf {
            value: Box::new(value),
            ty,
        },
    );
    LiftOutcome::None
}

fn array_length(ctx: &MethodContext<'_>, file: &mut RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let array: Expr = file.read(ctx, src);
    file.write(dest, Expr::ArrayLength(Box::new(array)));
    LiftOutcome::None
}

fn new_instance(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn.index.and_then(|i| ctx.type_at(i)).map_or_else(
        || "Object".to_string(),
        |value: &str| source_type(ctx, value),
    );
    file.write(dest, Expr::New(ty));
    LiftOutcome::None
}

fn new_array(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&size_reg)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let Some((element, _)): Option<(String, crate::descriptor::JavaType)> = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .and_then(|array: &str| array_element_type(ctx, array))
    else {
        return LiftOutcome::Unlifted;
    };
    let size: Expr = file.read(ctx, size_reg);
    file.write(
        dest,
        Expr::NewArray {
            ty: element,
            size: Box::new(size),
        },
    );
    LiftOutcome::None
}

fn array_element_type(
    ctx: &MethodContext<'_>,
    array: &str,
) -> Option<(String, crate::descriptor::JavaType)> {
    let element: &str = array.strip_prefix('[')?;
    let parsed: crate::descriptor::JavaType = descriptor::parse_field(element)?;
    let rendered: String = match &parsed {
        crate::descriptor::JavaType::Object(_) | crate::descriptor::JavaType::Array(_) => {
            source_type(ctx, element)
        }
        crate::descriptor::JavaType::Void => return None,
        primitive => primitive.render(),
    };
    Some((rendered, parsed))
}

fn filled_new_array(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    insn: &DalvikInsn,
    pending_result: &mut Option<PendingResult>,
) -> LiftOutcome {
    let Some(array): Option<&str> = insn.index.and_then(|index: u32| ctx.type_at(index)) else {
        return LiftOutcome::Unlifted;
    };
    let Some((element, parsed)): Option<(String, crate::descriptor::JavaType)> =
        array_element_type(ctx, array)
    else {
        return LiftOutcome::Unlifted;
    };
    if parsed.category_two() {
        return LiftOutcome::Unlifted;
    }
    let reference: bool = matches!(
        parsed,
        crate::descriptor::JavaType::Object(_) | crate::descriptor::JavaType::Array(_)
    );
    let element_descriptor: &str = array.get(1..).unwrap_or_default();
    let elements: Vec<Expr> = insn
        .regs
        .iter()
        .map(
            |&register: &u16| match argument_value(ctx, file, register, element_descriptor) {
                Expr::Const(constant) if reference && constant == "0" => {
                    Expr::Const("null".to_owned())
                }
                value => value,
            },
        )
        .collect();
    *pending_result = Some(PendingResult {
        expr: Expr::ArrayInit {
            ty: element,
            elements,
        },
        materialized_in: None,
        kind: Some(ValueKind::Reference),
    });
    LiftOutcome::None
}

const MAX_ARRAY_DATA_ELEMENTS: usize = 16_384;

fn array_data_elements(
    element: &str,
    payload: &crate::dalvik::ArrayDataPayload,
) -> Option<Vec<Expr>> {
    let width: u16 = match element {
        "boolean" | "byte" => 1,
        "short" | "char" => 2,
        "int" | "float" => 4,
        "long" | "double" => 8,
        _ => return None,
    };
    if payload.element_width != width {
        return None;
    }
    let chunks: std::slice::ChunksExact<'_, u8> = payload.data.chunks_exact(usize::from(width));
    if !chunks.remainder().is_empty() || chunks.len() > MAX_ARRAY_DATA_ELEMENTS {
        return None;
    }
    chunks
        .map(|chunk: &[u8]| {
            let mut bytes: [u8; 8] = [0; 8];
            bytes.get_mut(..chunk.len())?.copy_from_slice(chunk);
            let bits: u64 = u64::from_le_bytes(bytes);
            let [b0, b1, b2, b3, ..]: [u8; 8] = bytes;
            let text: String = match element {
                "boolean" => match bits {
                    0 => "false".to_owned(),
                    1 => "true".to_owned(),
                    _ => return None,
                },
                "byte" => i8::from_le_bytes([b0]).to_string(),
                "short" => i16::from_le_bytes([b0, b1]).to_string(),
                "char" => char_element(u16::from_le_bytes([b0, b1])),
                "int" => i32::from_le_bytes([b0, b1, b2, b3]).to_string(),
                "float" => float_literal(u32::from_le_bytes([b0, b1, b2, b3])),
                "long" => format!("{}L", i64::from_le_bytes(bytes)),
                _ => double_literal(bits),
            };
            Some(Expr::Const(text))
        })
        .collect()
}

pub(crate) fn char_element(unit: u16) -> String {
    match u8::try_from(unit) {
        Ok(byte) if (b' '..=b'~').contains(&byte) && !matches!(byte, b'\'' | b'\\') => {
            format!("'{}'", char::from(byte))
        }
        _ => unit.to_string(),
    }
}

fn array_variable_element(ctx: &MethodContext<'_>, array: &Expr) -> Option<String> {
    let Expr::Local(name) = array else {
        return None;
    };
    let local: &NamedLocal = ctx.naming?.named(name)?;
    let Some(LocalType::Reference(ty)) = &local.ty else {
        return None;
    };
    ty.strip_suffix("[]").map(str::to_owned)
}

fn fill_array_data(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&register): Option<&u16> = insn.regs.first() else {
        return LiftOutcome::Unlifted;
    };
    let Some(payload): Option<crate::dalvik::ArrayDataPayload> = insn
        .payload_off
        .and_then(|offset: u32| crate::dalvik::parse_fill_array_data(ctx.code, offset))
    else {
        return LiftOutcome::Unlifted;
    };
    if file.is_pending(register)
        && let Some(Expr::NewArray { ty, size }) = file.slot(register)
        && let Expr::Const(length) = size.as_ref()
    {
        let Some(elements): Option<Vec<Expr>> = array_data_elements(ty, &payload) else {
            return LiftOutcome::Unlifted;
        };
        if length.parse::<usize>().ok() != Some(elements.len()) {
            return LiftOutcome::Unlifted;
        }
        let filled: Expr = Expr::ArrayInit {
            ty: ty.clone(),
            elements,
        };
        file.replace(register, filled);
        return LiftOutcome::None;
    }
    let array: Expr = file.read(ctx, register);
    let Some(element): Option<String> = array_variable_element(ctx, &array) else {
        return LiftOutcome::Unlifted;
    };
    let Some(elements): Option<Vec<Expr>> = array_data_elements(&element, &payload) else {
        return LiftOutcome::Unlifted;
    };
    let count: usize = elements.len();
    let source: Expr = Expr::ArrayInit {
        ty: element,
        elements,
    };
    LiftOutcome::Statement(format!(
        "System.arraycopy({}, 0, {}, 0, {count})",
        source.render(),
        array.render()
    ))
}

fn array_get(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: u8,
) -> LiftOutcome {
    let (Some(&dest), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let array_expr: Expr = file.read(ctx, array);
    let index_expr: Expr = file.read(ctx, index);
    let kind: Option<ValueKind> = match op {
        0x47 => Some(ValueKind::Boolean),
        0x44 | 0x48..=0x4A => Some(ValueKind::IntLike),
        _ => None,
    };
    file.write_with_kind(
        dest,
        Expr::ArrayLoad {
            array: Box::new(array_expr),
            index: Box::new(index_expr),
        },
        kind,
    );
    LiftOutcome::None
}

fn array_put(ctx: &MethodContext<'_>, file: &RegisterFile, regs: &[u16], op: u8) -> LiftOutcome {
    let (Some(&value), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let value_expr: Expr = file.read(ctx, value);
    let array_expr: Expr = file.read(ctx, array);
    let index_expr: Expr = file.read(ctx, index);
    let rendered_value: String = match (op, &value_expr) {
        (0x4E, _) => {
            let Some(rendered): Option<String> =
                render_boolean_value(ctx, file, value, &value_expr)
            else {
                return LiftOutcome::Unlifted;
            };
            rendered
        }
        (0x4D, Expr::Const(constant)) if constant == "0" => "null".to_owned(),
        _ => value_expr.render(),
    };
    LiftOutcome::Statement(format!(
        "{}[{}] = {}",
        array_expr.render(),
        index_expr.render(),
        rendered_value
    ))
}

fn instance_get(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let name: String = field.name.clone();
    let owner: String = ctx.desugar.core_library.project_type(&field.class);
    let boolean: bool = field.type_name == "Z";
    let receiver: Expr = file.read(ctx, obj);
    let expr: Expr = Expr::Field {
        receiver: Box::new(receiver),
        owner,
        name,
        boolean,
    };
    file.write_with_kind(dest, expr, descriptor_value_kind(&field.type_name));
    LiftOutcome::None
}

fn instance_put(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&value), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::Unlifted;
    };
    if (insn.op == 0x5C) != (field.type_name == "Z") {
        return LiftOutcome::Unlifted;
    }
    let value_expr: Expr = file.read(ctx, value);
    let receiver: Expr = file.read(ctx, obj);
    let target: String = match &receiver {
        Expr::This => format!("this.{}", field.name),
        _ => format!("{}.{}", receiver.render(), field.name),
    };
    let rendered_value: String = if field.type_name == "Z" {
        let Some(rendered): Option<String> = render_boolean_value(ctx, file, value, &value_expr)
        else {
            return LiftOutcome::Unlifted;
        };
        rendered
    } else {
        value_expr.render()
    };
    LiftOutcome::Statement(format!("{target} = {rendered_value}"))
}

fn static_get(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let owner: String = source_type(ctx, &field.class);
    file.write_with_kind(
        dest,
        Expr::StaticField {
            owner,
            name: field.name.clone(),
            boolean: field.type_name == "Z",
        },
        descriptor_value_kind(&field.type_name),
    );
    LiftOutcome::None
}

fn static_put(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&value): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::Unlifted;
    };
    if (insn.op == 0x6A) != (field.type_name == "Z") {
        return LiftOutcome::Unlifted;
    }
    let owner: String = source_type(ctx, &field.class);
    let value_expr: Expr = file.read(ctx, value);
    let rendered_value: String = if field.type_name == "Z" {
        let Some(rendered): Option<String> = render_boolean_value(ctx, file, value, &value_expr)
        else {
            return LiftOutcome::Unlifted;
        };
        rendered
    } else {
        value_expr.render()
    };
    LiftOutcome::Statement(format!("{owner}.{} = {rendered_value}", field.name))
}

fn invoke(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending_result: &mut Option<PendingResult>,
) -> LiftOutcome {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| ctx.method_id(i)) else {
        return LiftOutcome::None;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let is_direct: bool = matches!(insn.op, 0x70 | 0x76);
    let recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod> = insn
        .index
        .and_then(|index: u32| ctx.desugar.interfaces.rewrites_call(index));
    let recovered_receiver_first: bool = recovered_default.is_some_and(
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
            recovered.kind == crate::dalvik_desugar::InterfaceMethodKind::Default
        },
    );
    let core_projection: Option<crate::dalvik_core_library::CoreMethodProjection> =
        ctx.desugar.core_library.project_method(method).filter(
            |projection: &crate::dalvik_core_library::CoreMethodProjection| {
                core_projection_matches_invoke(projection, method, is_static, insn.regs.len())
            },
        );
    let owner_descriptor: &str = recovered_default.map_or_else(
        || {
            core_projection
                .as_ref()
                .map_or(method.class.as_str(), |projection| {
                    projection.owner.as_str()
                })
        },
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.interface.as_str(),
    );
    let owner: String = descriptor::binary_to_source(owner_descriptor);
    let name: String = recovered_default.map_or_else(
        || {
            core_projection
                .as_ref()
                .map_or_else(|| method.name.clone(), |projection| projection.name.clone())
        },
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.name.clone(),
    );
    let returns_void: bool = core_projection
        .as_ref()
        .map_or(method.proto.return_type == "V", |projection| {
            projection.return_type == "V"
        });
    let core_receiver_first: bool = core_projection.as_ref().is_some_and(|projection| {
        projection.shape == crate::dalvik_core_library::CoreInvokeShape::ReceiverFirst
    });

    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    let receiver_register: Option<u16> =
        if !is_static || recovered_receiver_first || core_receiver_first {
            insn.regs.first().copied()
        } else {
            None
        };
    let receiver: Option<Expr> = if !is_static {
        reg_iter.next().map(|&r| file.read(ctx, r))
    } else if recovered_receiver_first || core_receiver_first {
        reg_iter.next().map(|&r| file.read(ctx, r))
    } else {
        None
    };
    let parameters: &[String] = if recovered_receiver_first {
        let Some(parameters): Option<&[String]> = method.proto.parameters.get(1..) else {
            return LiftOutcome::None;
        };
        parameters
    } else if let Some(projection) = &core_projection {
        projection.parameters.as_slice()
    } else {
        &method.proto.parameters
    };
    let mut args: Vec<Expr> = Vec::with_capacity(parameters.len());
    for param in parameters {
        let Some(&r): Option<&u16> = reg_iter.next() else {
            break;
        };
        args.push(argument_value(ctx, file, r, param));
        if is_category_two(param) {
            let _: Option<&u16> = reg_iter.next();
        }
    }

    if name == "<init>" && is_direct {
        let joined: String = args
            .iter()
            .map(Expr::render)
            .collect::<Vec<String>>()
            .join(", ");
        let target: DirectInitTarget = direct_init_target(
            ctx.is_constructor,
            ctx.declaring_class,
            &method.class,
            receiver.as_ref(),
        );
        if matches!(target, DirectInitTarget::Allocate) {
            let Some(Expr::New(ty)): Option<&Expr> = receiver.as_ref() else {
                return LiftOutcome::None;
            };
            let reference: Option<String> =
                ctx.desugar.functionals.recovered(&method.class).and_then(
                    |recovered: &crate::dalvik_desugar::RecoveredFunctional| {
                        render_functional(ctx, recovered, &args)
                    },
                );
            let constructed: Expr =
                Expr::Opaque(reference.unwrap_or_else(|| format!("new {ty}({joined})")));
            *pending_result = Some(PendingResult {
                expr: constructed.clone(),
                materialized_in: receiver_register,
                kind: None,
            });
            if let Some(&recv_reg) = insn.regs.first() {
                file.write(recv_reg, constructed);
            }
            return LiftOutcome::None;
        }
        return direct_init_outcome(target, joined);
    }

    let return_type: &str = core_projection
        .as_ref()
        .map_or(method.proto.return_type.as_str(), |projection| {
            projection.return_type.as_str()
        });
    let result_kind: Option<ValueKind> = descriptor_value_kind(return_type);
    let call: Expr = Expr::Invoke {
        receiver: receiver.map(Box::new),
        owner,
        method: name,
        args,
        returns_bool: return_type == "Z",
    };
    if returns_void {
        return LiftOutcome::Statement(call.render());
    }
    let materialized_in: Option<u16> =
        receiver_register.filter(|_| returns_receiver(method) && ctx.threads_receiver(insn.pc));
    if let Some(register) = materialized_in {
        file.write(register, call.clone());
    }
    *pending_result = Some(PendingResult {
        expr: call,
        materialized_in,
        kind: result_kind,
    });
    LiftOutcome::None
}

fn argument_value(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    register: u16,
    param: &str,
) -> Expr {
    let value: Expr = file.read(ctx, register);
    match param {
        "Z" => match &value {
            Expr::Const(constant) if constant == "0" => Expr::Const("false".to_owned()),
            Expr::Const(constant) if constant == "1" => Expr::Const("true".to_owned()),
            _ if operand_value_kind(ctx, file, register, &value) == Some(ValueKind::IntLike) => {
                Expr::Binary {
                    op: "!=",
                    lhs: Box::new(value),
                    rhs: Box::new(Expr::Const("0".to_owned())),
                }
            }
            _ => value,
        },
        "B" | "C" | "S" if matches!(&value, Expr::Const(constant) if constant.parse::<i32>().is_ok()) =>
        {
            let ty: &str = match param {
                "B" => "byte",
                "C" => "char",
                _ => "short",
            };
            Expr::Cast {
                ty: ty.to_owned(),
                value: Box::new(value),
            }
        }
        "I" | "B" | "C" | "S" => numeric_int_operand(ctx, file, register, value),
        _ => value,
    }
}

fn direct_init_target(
    is_constructor: bool,
    declaring_class: &str,
    target_class: &str,
    receiver: Option<&Expr>,
) -> DirectInitTarget {
    match receiver {
        Some(Expr::New(_)) => DirectInitTarget::Allocate,
        Some(Expr::This) if is_constructor => {
            if declaring_class == target_class {
                DirectInitTarget::This
            } else {
                DirectInitTarget::Super
            }
        }
        _ => DirectInitTarget::Invalid,
    }
}

fn direct_init_outcome(target: DirectInitTarget, joined: String) -> LiftOutcome {
    match target {
        DirectInitTarget::This => LiftOutcome::Statement(format!("this({joined})")),
        DirectInitTarget::Super => LiftOutcome::Statement(format!("super({joined})")),
        DirectInitTarget::Allocate => LiftOutcome::None,
        DirectInitTarget::Invalid => LiftOutcome::Unlifted,
    }
}

fn render_functional(
    ctx: &MethodContext<'_>,
    recovered: &crate::dalvik_desugar::RecoveredFunctional,
    args: &[Expr],
) -> Option<String> {
    match recovered {
        crate::dalvik_desugar::RecoveredFunctional::MethodReference(reference) => {
            render_method_reference(ctx.desugar.core_library, reference, args)
        }
        crate::dalvik_desugar::RecoveredFunctional::CapturedLambda(lambda) => {
            render_captured_lambda(ctx, lambda, args)
        }
    }
}

fn render_method_reference(
    core_library: &crate::dalvik_core_library::CoreLibraryRecovery,
    recovered: &crate::dalvik_desugar::RecoveredMethodRef,
    args: &[Expr],
) -> Option<String> {
    let name: &str = recovered.name.as_str();
    if recovered.kind == crate::dalvik_desugar::MethodRefKind::BoundInstance {
        if args.len() != 1 {
            return None;
        }
        let rendered: String = args.first()?.render();
        let receiver: String = if is_expression_name(&rendered) {
            rendered
        } else {
            format!("({rendered})")
        };
        return Some(format!("{receiver}::{name}"));
    }
    if !args.is_empty() {
        return None;
    }
    Some(format!(
        "{}::{name}",
        descriptor::binary_to_source(&core_library.project_type(&recovered.owner))
    ))
}

const LAMBDA_PARAMETER_PREFIXES: [&str; 4] = ["p", "q", "r", "s"];

fn lambda_parameter_names(captures: &[String], arity: usize) -> Option<Vec<String>> {
    for prefix in LAMBDA_PARAMETER_PREFIXES {
        let names: Vec<String> = (0..arity)
            .map(|position: usize| format!("{prefix}{position}"))
            .collect();
        let collides: bool = names.iter().any(|name: &String| {
            captures
                .iter()
                .any(|capture: &String| capture.contains(name.as_str()))
        });
        if !collides {
            return Some(names);
        }
    }
    None
}

const MAX_INLINE_DEPTH: u16 = 2;

fn operation_node_counts(expr: &Expr) -> (usize, usize, usize) {
    fn walk(expr: &Expr, invokes: &mut usize, opaques: &mut usize, news: &mut usize) {
        match expr {
            Expr::Binary { lhs, rhs, .. }
            | Expr::Cmp { lhs, rhs, .. }
            | Expr::ArrayLoad {
                array: lhs,
                index: rhs,
            } => {
                walk(lhs, invokes, opaques, news);
                walk(rhs, invokes, opaques, news);
            }
            Expr::Unary { value, .. }
            | Expr::Cast { value, .. }
            | Expr::InstanceOf { value, .. }
            | Expr::ArrayLength(value)
            | Expr::NewArray { size: value, .. } => walk(value, invokes, opaques, news),
            Expr::Field { receiver, .. } => walk(receiver, invokes, opaques, news),
            Expr::ArrayInit { elements, .. } => {
                for element in elements {
                    walk(element, invokes, opaques, news);
                }
            }
            Expr::Invoke { receiver, args, .. } => {
                *invokes = invokes.saturating_add(1);
                if let Some(value) = receiver {
                    walk(value, invokes, opaques, news);
                }
                for arg in args {
                    walk(arg, invokes, opaques, news);
                }
            }
            Expr::Opaque(_) => *opaques = opaques.saturating_add(1),
            Expr::New(_) => *news = news.saturating_add(1),
            Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::StaticField { .. } => {}
        }
    }
    let (mut invokes, mut opaques, mut news): (usize, usize, usize) = (0, 0, 0);
    walk(expr, &mut invokes, &mut opaques, &mut news);
    (invokes, opaques, news)
}

fn inline_helper_body(
    ctx: &MethodContext<'_>,
    body: &crate::dalvik_desugar::HelperBody,
    receiver: Option<&Expr>,
    captures: &[Expr],
    parameters: &[String],
    reached: &crate::dalvik_desugar::InlinedHelpers,
) -> Option<String> {
    if ctx.inline_depth >= MAX_INLINE_DEPTH {
        return None;
    }
    let mut nested: MethodContext<'_> = MethodContext::new(
        ctx.dex,
        MethodIdentity {
            declaring_class: ctx.declaring_class,
            descriptor: &body.descriptor,
            is_static: body.is_static,
            is_constructor: false,
        },
        body.registers_size,
        body.ins_size,
        true,
        ctx.desugar,
        reached,
    )
    .with_code(&body.insns);
    nested.inline_depth = ctx.inline_depth.checked_add(1)?;

    let parsed: MethodDescriptor = descriptor::parse_method(&body.descriptor)?;
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(&nested, &mut file);
    let mut cursor: u16 = body.registers_size.checked_sub(body.ins_size)?;
    if body.is_static {
        if receiver.is_some() {
            return None;
        }
    } else {
        file.write_materialized(cursor, receiver?.clone());
        cursor = cursor.checked_add(1)?;
    }
    let supplied: Vec<Expr> = captures
        .iter()
        .cloned()
        .chain(
            parameters
                .iter()
                .map(|name: &String| Expr::Local(name.clone())),
        )
        .collect();
    if supplied.len() != parsed.params.len() {
        return None;
    }
    for (position, parameter) in parsed.params.iter().enumerate() {
        file.write_materialized(cursor, supplied.get(position)?.clone());
        cursor = cursor.checked_add(if parameter.category_two() { 2 } else { 1 })?;
    }
    if cursor != body.registers_size {
        return None;
    }

    let instructions: Vec<DalvikInsn> = crate::dalvik::decode_method(&body.insns);
    let mut pending: Option<PendingResult> = None;
    let mut produced: Option<Expr> = None;
    let (mut calls, mut constructions, mut allocations): (usize, usize, usize) = (0, 0, 0);
    for insn in &instructions {
        match insn.op {
            0x0F..=0x11 => {
                if pending.as_ref().is_some_and(|result: &PendingResult| {
                    result.materialized_in.is_none()
                        && result.expr.discarded_side_effect().is_some()
                }) {
                    return None;
                }
                let &register: &u16 = insn.regs.first()?;
                produced = Some(file.current(&nested, register));
                break;
            }
            0x0E => {
                produced = pending.take().map(|result: PendingResult| result.expr);
                break;
            }
            _ => {}
        }
        let mut readable_pending: bool = false;
        if let Some(result) = pending.as_ref() {
            let taken_by_move: bool = matches!(insn.op, 0x0A..=0x0C);
            readable_pending = result.materialized_in.is_some();
            if !taken_by_move && !readable_pending && result.expr.discarded_side_effect().is_some()
            {
                return None;
            }
        }
        if insn.op == 0x22 {
            allocations = allocations.checked_add(1)?;
        }
        if matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
            let target: &MethodId = ctx.dex.method_ids.get(insn.index? as usize)?;
            if target.name == "<init>" {
                constructions = constructions.checked_add(1)?;
            } else {
                calls = calls.checked_add(1)?;
            }
        }
        match lift_insn(&nested, &mut file, insn, &mut pending) {
            LiftOutcome::None => {}
            LiftOutcome::Unlifted => return None,
            LiftOutcome::Statement(_) | LiftOutcome::Statements(_) if readable_pending => {}
            LiftOutcome::Statement(_) | LiftOutcome::Statements(_) => return None,
        }
    }

    let expression: Expr = produced?;
    let (invokes, opaques, news): (usize, usize, usize) = operation_node_counts(&expression);
    if invokes != calls || opaques != constructions || news != 0 || allocations != constructions {
        return None;
    }
    Some(expression.render())
}

fn render_captured_lambda(
    ctx: &MethodContext<'_>,
    recovered: &crate::dalvik_desugar::RecoveredCapturedLambda,
    args: &[Expr],
) -> Option<String> {
    if args.len() != recovered.capture_count {
        return None;
    }
    let rendered: Vec<String> = args.iter().map(Expr::render).collect();
    let parameters: Vec<String> = lambda_parameter_names(&rendered, recovered.parameter_count)?;
    let head: String = if parameters.len() == 1 {
        parameters.first()?.clone()
    } else {
        format!("({})", parameters.join(", "))
    };
    let (receiver_arg, forwarded_args): (Option<&Expr>, &[Expr]) = if recovered.receiver_capture {
        (args.first(), args.get(1..)?)
    } else {
        (None, args)
    };
    if let Some(body) = recovered.helper_body.as_ref() {
        let reached: crate::dalvik_desugar::InlinedHelpers =
            crate::dalvik_desugar::InlinedHelpers::default();
        if let Some(inlined) = inline_helper_body(
            ctx,
            body,
            receiver_arg,
            forwarded_args,
            &parameters,
            &reached,
        ) {
            ctx.inlined_helpers.absorb(&reached);
            if body.elide_declaration {
                ctx.inlined_helpers.record(recovered.helper_index);
            }
            return Some(format!("{head} -> {inlined}"));
        }
    }
    let (target, forwarded): (String, &[String]) = if recovered.receiver_capture {
        let receiver_text: &String = rendered.first()?;
        let receiver: String = if is_expression_name(receiver_text) {
            receiver_text.clone()
        } else {
            format!("({receiver_text})")
        };
        (receiver, rendered.get(1..)?)
    } else {
        (
            descriptor::binary_to_source(
                &ctx.desugar
                    .core_library
                    .project_type(&recovered.helper_owner),
            ),
            rendered.as_slice(),
        )
    };
    let mut passed: Vec<String> = forwarded.to_vec();
    passed.extend(parameters);
    Some(format!(
        "{head} -> {target}.{}({})",
        descriptor::java_writable_identifier(&recovered.helper_name),
        passed.join(", ")
    ))
}

fn is_expression_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(crate::name_disambig::is_java_source_identifier)
}

pub(crate) fn returns_receiver(method: &MethodId) -> bool {
    matches!(
        method.class.as_str(),
        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;"
    ) && matches!(
        method.name.as_str(),
        "append" | "appendCodePoint" | "delete" | "deleteCharAt" | "insert" | "replace" | "reverse"
    ) && method.proto.return_type == method.class
}

fn core_projection_matches_invoke(
    projection: &crate::dalvik_core_library::CoreMethodProjection,
    method: &MethodId,
    is_static: bool,
    register_count: usize,
) -> bool {
    if projection.shape != crate::dalvik_core_library::CoreInvokeShape::Preserve && !is_static {
        return false;
    }
    let parameter_words: Option<usize> =
        method
            .proto
            .parameters
            .iter()
            .try_fold(0usize, |count: usize, parameter: &String| {
                count.checked_add(if is_category_two(parameter) { 2 } else { 1 })
            });
    parameter_words.and_then(|count: usize| count.checked_add(usize::from(!is_static)))
        == Some(register_count)
}

fn source_type(ctx: &MethodContext<'_>, binary: &str) -> String {
    let projected: String = ctx.desugar.core_library.project_type(binary);
    descriptor::binary_to_source(&projected)
}

fn unary(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let value: Expr = numeric_int_operand(ctx, file, src, file.read(ctx, src));
    let result: Expr = Expr::Unary {
        op,
        value: Box::new(value),
    };
    file.write(dest, result);
    LiftOutcome::None
}

fn numeric_cast(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: u8,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let ty: &str = cast_target(op);
    let value: Expr = file.read(ctx, src);
    let result: Expr = Expr::Cast {
        ty: ty.to_string(),
        value: Box::new(value),
    };
    file.write(dest, result);
    LiftOutcome::None
}

fn binary_three(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
    int_operation: bool,
) -> LiftOutcome {
    let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, lhs);
    let rhs_expr: Expr = file.read(ctx, rhs);
    write_binary(
        ctx,
        file,
        dest,
        op,
        int_operation,
        (lhs, lhs_expr),
        (rhs, rhs_expr),
    );
    LiftOutcome::None
}

fn operand_value_kind(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    register: u16,
    value: &Expr,
) -> Option<ValueKind> {
    if expression_is_boolean(value) {
        return Some(ValueKind::Boolean);
    }
    file.kinds
        .get(&register)
        .copied()
        .or_else(|| match value {
            Expr::Local(name) => local_value_kind(ctx, name),
            _ => None,
        })
        .or_else(|| expression_int_kind(value))
}

fn numeric_int_operand(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    register: u16,
    value: Expr,
) -> Expr {
    if operand_value_kind(ctx, file, register, &value) == Some(ValueKind::Boolean) {
        Expr::Opaque(format!("({} ? 1 : 0)", value.render()))
    } else {
        value
    }
}

fn write_binary(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    dest: u16,
    op: &'static str,
    int_operation: bool,
    (lhs, lhs_expr): (u16, Expr),
    (rhs, rhs_expr): (u16, Expr),
) {
    if !int_operation {
        file.write(
            dest,
            Expr::Binary {
                op,
                lhs: Box::new(lhs_expr),
                rhs: Box::new(rhs_expr),
            },
        );
        return;
    }
    if matches!(op, "&" | "|" | "^")
        && operand_value_kind(ctx, file, lhs, &lhs_expr) == Some(ValueKind::Boolean)
        && operand_value_kind(ctx, file, rhs, &rhs_expr) == Some(ValueKind::Boolean)
    {
        file.write_with_kind(
            dest,
            Expr::Binary {
                op,
                lhs: Box::new(lhs_expr),
                rhs: Box::new(rhs_expr),
            },
            Some(ValueKind::Boolean),
        );
        return;
    }
    let lhs_value: Expr = numeric_int_operand(ctx, file, lhs, lhs_expr);
    let rhs_value: Expr = numeric_int_operand(ctx, file, rhs, rhs_expr);
    file.write(
        dest,
        Expr::Binary {
            op,
            lhs: Box::new(lhs_value),
            rhs: Box::new(rhs_value),
        },
    );
}

fn binary_2addr(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
    int_operation: bool,
) -> LiftOutcome {
    let (Some(&dest), Some(&rhs)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, dest);
    let rhs_expr: Expr = file.read(ctx, rhs);
    write_binary(
        ctx,
        file,
        dest,
        op,
        int_operation,
        (dest, lhs_expr),
        (rhs, rhs_expr),
    );
    LiftOutcome::None
}

fn binary_lit(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let literal: i64 = insn.literal.unwrap_or(0);
    let source: Expr = file.read(ctx, src);
    if op == "^"
        && literal == 1
        && operand_value_kind(ctx, file, src, &source) == Some(ValueKind::Boolean)
    {
        file.write_with_kind(
            dest,
            Expr::Unary {
                op: "!",
                value: Box::new(source),
            },
            Some(ValueKind::Boolean),
        );
        return LiftOutcome::None;
    }
    let lhs_expr: Expr = numeric_int_operand(ctx, file, src, source);
    let result: Expr = if insn.op == 0xD1 || insn.op == 0xD9 {
        Expr::Binary {
            op,
            lhs: Box::new(Expr::Const(literal.to_string())),
            rhs: Box::new(lhs_expr),
        }
    } else {
        Expr::Binary {
            op,
            lhs: Box::new(lhs_expr),
            rhs: Box::new(Expr::Const(literal.to_string())),
        }
    };
    file.write(dest, result);
    LiftOutcome::None
}

fn cmp_three(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    opcode: u8,
) -> LiftOutcome {
    let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, lhs);
    let rhs_expr: Expr = file.read(ctx, rhs);
    let kind: crate::decompile::CmpKind = match opcode {
        0x2D | 0x2F => crate::decompile::CmpKind::NanLow,
        0x2E | 0x30 => crate::decompile::CmpKind::NanHigh,
        _ => crate::decompile::CmpKind::Long,
    };
    file.write(
        dest,
        Expr::Cmp {
            kind,
            lhs: Box::new(lhs_expr),
            rhs: Box::new(rhs_expr),
        },
    );
    LiftOutcome::None
}

pub(crate) fn render_branch_condition(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    insn: &DalvikInsn,
) -> String {
    let op: u8 = insn.op;
    match op {
        0x32..=0x37 => {
            let (Some(&a), Some(&b)): (Option<&u16>, Option<&u16>) =
                (insn.regs.first(), insn.regs.get(1))
            else {
                return "true".to_string();
            };
            let lhs: Expr = file.read(ctx, a);
            let rhs: Expr = file.read(ctx, b);
            format!("{} {} {}", lhs.render(), compare_op(op), rhs.render())
        }
        0x38..=0x3D => {
            let Some(&a): Option<&u16> = insn.regs.first() else {
                return "true".to_string();
            };
            let value: Expr = file.read(ctx, a);
            let kind: Option<ValueKind> = operand_value_kind(ctx, file, a, &value);
            match &value {
                Expr::Cmp { kind, lhs, rhs } => {
                    kind.render_relation(&lhs.render(), comparez_op(op), &rhs.render())
                }
                _ if matches!(op, 0x38 | 0x39) && kind == Some(ValueKind::Boolean) => {
                    let inner: String = value.render();
                    if op == 0x38 {
                        format!("!{inner}")
                    } else {
                        inner
                    }
                }
                _ if matches!(op, 0x38 | 0x39) && kind == Some(ValueKind::Reference) => {
                    format!("{} {} null", value.render(), comparez_op(op))
                }
                _ => format!("{} {} 0", value.render(), comparez_op(op)),
            }
        }
        _ => "true".to_string(),
    }
}

pub(crate) fn seed_block_registers(ctx: &MethodContext<'_>, file: &mut RegisterFile) {
    for reg in 0..ctx.registers_size {
        file.seed_register_with_name(ctx, reg);
    }
    let _ = ctx.ins_size;
    let _ = ctx.is_static;
}

const fn is_category_two(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes().first(), Some(b'J' | b'D'))
}

const fn cast_target(op: u8) -> &'static str {
    match op {
        0x81 | 0x88 | 0x8B => "long",
        0x82 | 0x85 | 0x8C => "float",
        0x83 | 0x86 | 0x89 => "double",
        0x84 | 0x87 | 0x8A => "int",
        0x8D => "byte",
        0x8E => "char",
        0x8F => "short",
        _ => "int",
    }
}

const fn arith_op(op: u8) -> &'static str {
    match op {
        0x90 | 0x9B | 0xA6 | 0xAB | 0xB0 | 0xBB | 0xC6 | 0xCB => "+",
        0x91 | 0x9C | 0xA7 | 0xAC | 0xB1 | 0xBC | 0xC7 | 0xCC => "-",
        0x92 | 0x9D | 0xA8 | 0xAD | 0xB2 | 0xBD | 0xC8 | 0xCD => "*",
        0x93 | 0x9E | 0xA9 | 0xAE | 0xB3 | 0xBE | 0xC9 | 0xCE => "/",
        0x94 | 0x9F | 0xAA | 0xAF | 0xB4 | 0xBF | 0xCA | 0xCF => "%",
        0x95 | 0xA0 | 0xB5 | 0xC0 => "&",
        0x96 | 0xA1 | 0xB6 | 0xC1 => "|",
        0x97 | 0xA2 | 0xB7 | 0xC2 => "^",
        0x98 | 0xA3 | 0xB8 | 0xC3 => "<<",
        0x99 | 0xA4 | 0xB9 | 0xC4 => ">>",
        0x9A | 0xA5 | 0xBA | 0xC5 => ">>>",
        _ => "?",
    }
}

const fn arith_lit_op(op: u8) -> &'static str {
    match op {
        0xD0 | 0xD8 => "+",
        0xD1 | 0xD9 => "-",
        0xD2 | 0xDA => "*",
        0xD3 | 0xDB => "/",
        0xD4 | 0xDC => "%",
        0xD5 | 0xDD => "&",
        0xD6 | 0xDE => "|",
        0xD7 | 0xDF => "^",
        0xE0 => "<<",
        0xE1 => ">>",
        0xE2 => ">>>",
        _ => "?",
    }
}

const fn compare_op(op: u8) -> &'static str {
    match op {
        0x32 => "==",
        0x33 => "!=",
        0x34 => "<",
        0x35 => ">=",
        0x36 => ">",
        0x37 => "<=",
        _ => "?",
    }
}

const fn comparez_op(op: u8) -> &'static str {
    match op {
        0x38 => "==",
        0x39 => "!=",
        0x3A => "<",
        0x3B => ">=",
        0x3C => ">",
        0x3D => "<=",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DirectInitTarget, LiftOutcome, MethodContext, MethodIdentity, RegisterFile,
        core_projection_matches_invoke, direct_init_outcome, direct_init_target,
        lambda_parameter_names, lift_insn, render_method_reference, returns_receiver,
    };
    use crate::dalvik::{DalvikInsn, InsnFormat, opcode};
    use crate::dalvik_core_library::{CoreInvokeShape, CoreLibraryRecovery, CoreMethodProjection};
    use crate::dalvik_desugar::{
        DefaultInterfaceRecovery, DesugarView, FunctionalRecovery, InlinedHelpers, MethodRefKind,
        RecoveredMethodRef,
    };
    use crate::decompile::Expr;
    use crate::dex::{MethodId, ProtoId};

    fn method(class: &str, name: &str, returns: &str) -> MethodId {
        MethodId {
            class: class.to_string(),
            proto: ProtoId {
                shorty: String::new(),
                return_type: returns.to_string(),
                parameters: Vec::new(),
            },
            name: name.to_string(),
        }
    }

    fn insn(op: u8, regs: Vec<u16>, literal: Option<i64>) -> DalvikInsn {
        DalvikInsn {
            pc: 0,
            op,
            mnemonic: opcode(op).mnemonic,
            width: 1,
            format: InsnFormat::Fmt11x,
            regs,
            literal,
            index: None,
            branch: None,
            payload_off: None,
        }
    }

    fn indexed_insn(op: u8, regs: Vec<u16>, index: u32) -> DalvikInsn {
        DalvikInsn {
            index: Some(index),
            ..insn(op, regs, None)
        }
    }

    fn with_context<T>(
        descriptor: &str,
        test: impl FnOnce(&MethodContext<'_>) -> T,
    ) -> Result<T, String> {
        with_parameter_context(descriptor, 4, 0, test)
    }

    fn with_parameter_context<T>(
        descriptor: &str,
        registers: u16,
        ins: u16,
        test: impl FnOnce(&MethodContext<'_>) -> T,
    ) -> Result<T, String> {
        let bytes: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
        let dex: crate::dex::DexFile =
            crate::dex::parse(bytes).map_err(|error| error.to_string())?;
        let interfaces: DefaultInterfaceRecovery = DefaultInterfaceRecovery::default();
        let functionals: FunctionalRecovery = FunctionalRecovery::default();
        let core_library: CoreLibraryRecovery = CoreLibraryRecovery::default();
        let inlined_helpers: InlinedHelpers = InlinedHelpers::default();
        let context: MethodContext<'_> = MethodContext::new(
            &dex,
            MethodIdentity {
                declaring_class: "LProbe;",
                descriptor,
                is_static: true,
                is_constructor: false,
            },
            registers,
            ins,
            false,
            DesugarView {
                interfaces: &interfaces,
                functionals: &functionals,
                core_library: &core_library,
            },
            &inlined_helpers,
        );
        Ok(test(&context))
    }

    fn return_outcome(descriptor: &str, op: u8, expression: Expr) -> Result<LiftOutcome, String> {
        with_context(descriptor, |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            file.write(0, expression);
            let mut pending = None;
            lift_insn(context, &mut file, &insn(op, vec![0], None), &mut pending)
        })
    }

    fn return_statement(descriptor: &str, op: u8, expression: Expr) -> Result<String, String> {
        match return_outcome(descriptor, op, expression)? {
            LiftOutcome::Statement(statement) => Ok(statement),
            _ => Err("return did not produce one statement".to_owned()),
        }
    }

    fn moved_boolean_expression(context: &MethodContext<'_>) -> RegisterFile {
        let mut file: RegisterFile = RegisterFile::new();
        file.write(
            1,
            Expr::Invoke {
                receiver: Some(Box::new(Expr::Local("value".to_owned()))),
                owner: "String".to_owned(),
                method: "isEmpty".to_owned(),
                args: Vec::new(),
                returns_bool: true,
            },
        );
        let mut pending = None;
        let moved: LiftOutcome = lift_insn(
            context,
            &mut file,
            &insn(0x01, vec![0, 1], None),
            &mut pending,
        );
        assert!(matches!(
            moved,
            LiftOutcome::Statement(statement) if statement == "var0 = value.isEmpty()"
        ));
        file
    }

    fn field_index(context: &MethodContext<'_>, descriptor: &str) -> Result<u32, String> {
        context
            .dex
            .field_ids
            .iter()
            .position(|field| field.type_name == descriptor)
            .and_then(|index: usize| u32::try_from(index).ok())
            .ok_or_else(|| format!("fixture contains no indexed {descriptor} field"))
    }

    #[test]
    fn integer_field_and_call_results_compare_with_zero_at_boolean_boundaries() -> Result<(), String>
    {
        with_parameter_context(
            "()Z",
            3,
            0,
            |context: &MethodContext<'_>| -> Result<(), String> {
                let int_field: u32 = field_index(context, "I")?;
                let int_field_name: String = context
                    .field_id(int_field)
                    .ok_or_else(|| "fixture int field disappeared".to_owned())?
                    .name
                    .clone();
                let mut file: RegisterFile = RegisterFile::new();
                file.write(1, Expr::Local("holder".to_owned()));
                let mut pending = None;
                let _: LiftOutcome = lift_insn(
                    context,
                    &mut file,
                    &indexed_insn(0x52, vec![0, 1], int_field),
                    &mut pending,
                );
                let outcome: LiftOutcome =
                    lift_insn(context, &mut file, &insn(0x0F, vec![0], None), &mut pending);
                let LiftOutcome::Statement(statement) = outcome else {
                    return Err("integer field return was not lifted".to_owned());
                };
                assert!(
                    statement.starts_with("return ")
                        && statement.ends_with(&format!(".{int_field_name} != 0")),
                    "{statement}"
                );

                let static_call: u32 = context
                    .dex
                    .method_ids
                    .iter()
                    .position(|method| {
                        method.proto.return_type == "I" && method.proto.parameters.is_empty()
                    })
                    .and_then(|index: usize| u32::try_from(index).ok())
                    .ok_or_else(|| "fixture contains no ()I method".to_owned())?;
                let mut file: RegisterFile = RegisterFile::new();
                let mut pending = None;
                let _: LiftOutcome = lift_insn(
                    context,
                    &mut file,
                    &indexed_insn(0x71, Vec::new(), static_call),
                    &mut pending,
                );
                let _: LiftOutcome =
                    lift_insn(context, &mut file, &insn(0x0A, vec![2], None), &mut pending);
                let outcome: LiftOutcome =
                    lift_insn(context, &mut file, &insn(0x0F, vec![2], None), &mut pending);
                assert!(
                    matches!(
                        &outcome,
                        LiftOutcome::Statement(statement)
                            if statement.starts_with("return ") && statement.ends_with("() != 0")
                    ),
                    "{}",
                    match &outcome {
                        LiftOutcome::Statement(statement) => statement.as_str(),
                        _ => "not a statement",
                    }
                );
                Ok(())
            },
        )??;
        Ok(())
    }

    #[test]
    fn boolean_parameters_return_and_store_without_integer_comparison() -> Result<(), String> {
        with_parameter_context("(Z)Z", 1, 1, |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            let mut pending = None;
            let outcome: LiftOutcome =
                lift_insn(context, &mut file, &insn(0x0F, vec![0], None), &mut pending);
            assert!(matches!(
                outcome,
                LiftOutcome::Statement(statement) if statement == "return arg0"
            ));
        })?;
        with_parameter_context("(I)Z", 1, 1, |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            let mut pending = None;
            let outcome: LiftOutcome =
                lift_insn(context, &mut file, &insn(0x0F, vec![0], None), &mut pending);
            assert!(matches!(
                outcome,
                LiftOutcome::Statement(statement) if statement == "return arg0 != 0"
            ));
        })?;
        with_parameter_context(
            "(Z)V",
            2,
            1,
            |context: &MethodContext<'_>| -> Result<(), String> {
                let index: u32 = field_index(context, "Z")?;
                let field_name: String = context
                    .field_id(index)
                    .ok_or_else(|| "fixture boolean field disappeared".to_owned())?
                    .name
                    .clone();
                let mut file: RegisterFile = RegisterFile::new();
                file.write(0, Expr::This);
                let mut pending = None;
                let outcome: LiftOutcome = lift_insn(
                    context,
                    &mut file,
                    &indexed_insn(0x5C, vec![1, 0], index),
                    &mut pending,
                );
                assert!(matches!(
                    outcome,
                    LiftOutcome::Statement(statement)
                        if statement == format!("this.{field_name} = arg0")
                ));
                Ok(())
            },
        )??;
        Ok(())
    }

    #[test]
    fn boolean_array_elements_keep_boolean_type_and_unknown_values_refuse() -> Result<(), String> {
        with_context("()V", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            file.write(0, Expr::Local("source".to_owned()));
            file.write(1, Expr::Const("0".to_owned()));
            file.write(3, Expr::Local("target".to_owned()));
            let mut pending = None;
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x47, vec![2, 0, 1], None),
                &mut pending,
            );
            let copied: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x4E, vec![2, 3, 1], None),
                &mut pending,
            );
            assert!(matches!(
                copied,
                LiftOutcome::Statement(statement) if statement == "target[0] = source[0]"
            ));
            file.write(2, Expr::Opaque("?".to_owned()));
            let refused: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x4E, vec![2, 3, 1], None),
                &mut pending,
            );
            assert!(matches!(refused, LiftOutcome::Unlifted));
        })?;
        Ok(())
    }

    #[test]
    fn move_into_boolean_array_store_reads_the_moved_boolean_once() -> Result<(), String> {
        with_context("()V", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = moved_boolean_expression(context);
            file.write(2, Expr::Local("flags".to_owned()));
            file.write(3, Expr::Const("0".to_owned()));
            let mut pending = None;
            let outcome: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x4E, vec![0, 2, 3], None),
                &mut pending,
            );
            assert!(matches!(
                outcome,
                LiftOutcome::Statement(statement) if statement == "flags[0] = var0"
            ));
        })?;
        Ok(())
    }

    #[test]
    fn move_into_boolean_instance_field_reads_the_moved_boolean_once() -> Result<(), String> {
        with_context("()V", |context: &MethodContext<'_>| -> Result<(), String> {
            let index: u32 = field_index(context, "Z")?;
            let field_name: String = context
                .field_id(index)
                .ok_or_else(|| "fixture boolean field disappeared".to_owned())?
                .name
                .clone();
            let mut file: RegisterFile = moved_boolean_expression(context);
            file.write(2, Expr::This);
            let mut pending = None;
            let outcome: LiftOutcome = lift_insn(
                context,
                &mut file,
                &indexed_insn(0x5C, vec![0, 2], index),
                &mut pending,
            );
            assert!(matches!(
                outcome,
                LiftOutcome::Statement(statement)
                    if statement == format!("this.{field_name} = var0")
            ));
            Ok(())
        })??;
        Ok(())
    }

    #[test]
    fn move_into_boolean_static_field_reads_the_moved_boolean_once() -> Result<(), String> {
        with_context("()V", |context: &MethodContext<'_>| -> Result<(), String> {
            let index: u32 = field_index(context, "Z")?;
            let field = context
                .field_id(index)
                .ok_or_else(|| "fixture boolean field disappeared".to_owned())?;
            let owner: String = super::source_type(context, &field.class);
            let field_name: String = field.name.clone();
            let mut file: RegisterFile = moved_boolean_expression(context);
            let mut pending = None;
            let outcome: LiftOutcome = lift_insn(
                context,
                &mut file,
                &indexed_insn(0x6A, vec![0], index),
                &mut pending,
            );
            assert!(matches!(
                outcome,
                LiftOutcome::Statement(statement)
                    if statement == format!("{owner}.{field_name} = var0")
            ));
            Ok(())
        })??;
        Ok(())
    }

    #[test]
    fn boolean_field_stores_refuse_both_descriptor_opcode_mismatch_directions() -> Result<(), String>
    {
        with_context("()V", |context: &MethodContext<'_>| -> Result<(), String> {
            let boolean_index: u32 = field_index(context, "Z")?;
            let integer_index: u32 = field_index(context, "I")?;
            let mut file: RegisterFile = RegisterFile::new();
            file.write(0, Expr::Const("1".to_owned()));
            file.write(1, Expr::This);
            let mut pending = None;
            for instruction in [
                indexed_insn(0x5C, vec![0, 1], integer_index),
                indexed_insn(0x59, vec![0, 1], boolean_index),
                indexed_insn(0x6A, vec![0], integer_index),
                indexed_insn(0x67, vec![0], boolean_index),
            ] {
                assert!(matches!(
                    lift_insn(context, &mut file, &instruction, &mut pending),
                    LiftOutcome::Unlifted
                ));
            }
            Ok(())
        })??;
        Ok(())
    }

    #[test]
    fn instance_and_static_field_stores_refuse_missing_and_out_of_range_indices()
    -> Result<(), String> {
        with_context("()V", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            file.write(0, Expr::Const("1".to_owned()));
            file.write(1, Expr::This);
            let mut pending = None;
            for instruction in [
                insn(0x59, vec![0, 1], None),
                indexed_insn(0x59, vec![0, 1], u32::MAX),
                insn(0x67, vec![0], None),
                indexed_insn(0x67, vec![0], u32::MAX),
            ] {
                assert!(matches!(
                    lift_insn(context, &mut file, &instruction, &mut pending),
                    LiftOutcome::Unlifted
                ));
            }
        })?;
        Ok(())
    }

    #[test]
    fn exact_boolean_return_normalizes_only_the_int_compatible_boundary() -> Result<(), String> {
        assert_eq!(
            return_statement("()Z", 0x0F, Expr::Const("0".to_owned()))?,
            "return false"
        );
        assert_eq!(
            return_statement("()Z", 0x0F, Expr::Const("1".to_owned()))?,
            "return true"
        );
        assert_eq!(
            return_statement("()Z", 0x0F, Expr::Const("7".to_owned()))?,
            "return 7 != 0"
        );
        assert_eq!(
            return_statement(
                "()Z",
                0x0F,
                Expr::InstanceOf {
                    value: Box::new(Expr::Local("value".to_owned())),
                    ty: "Probe".to_owned(),
                },
            )?,
            "return (value instanceof Probe)"
        );
        Ok(())
    }

    #[test]
    fn malformed_and_cross_category_returns_are_refused() -> Result<(), String> {
        for (descriptor, op) in [
            ("()Q", 0x0F),
            ("()Q", 0x0E),
            ("()Z", 0x10),
            ("()Z", 0x11),
            ("()J", 0x0F),
            ("()Ljava/lang/String;", 0x0F),
            ("()I", 0x10),
            ("()I", 0x11),
            ("()I", 0x0E),
            ("()V", 0x0F),
        ] {
            assert!(matches!(
                return_outcome(descriptor, op, Expr::Const("1".to_owned()))?,
                LiftOutcome::Unlifted
            ));
        }
        Ok(())
    }

    #[test]
    fn return_value_without_a_register_is_refused() -> Result<(), String> {
        with_context("()I", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            let mut pending = None;
            assert!(matches!(
                lift_insn(
                    context,
                    &mut file,
                    &insn(0x0F, Vec::new(), None),
                    &mut pending,
                ),
                LiftOutcome::Unlifted
            ));
        })?;
        Ok(())
    }

    #[test]
    fn boolean_register_operands_keep_boolean_or_materialize_for_integer_use() -> Result<(), String>
    {
        with_parameter_context("(ZZ)I", 4, 2, |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            let mut pending = None;
            let (left, right): (u16, u16) = (2, 3);
            assert_eq!(
                context.param_regs.keys().copied().collect::<Vec<u16>>(),
                vec![left, right]
            );
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x95, vec![0, left, right], None),
                &mut pending,
            );
            assert_eq!(file.current(context, 0).render(), "(arg0 & arg1)");
            assert_eq!(file.kinds.get(&0), Some(&super::ValueKind::Boolean));
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x90, vec![1, left, right], None),
                &mut pending,
            );
            assert_eq!(
                file.current(context, 1).render(),
                "((arg0 ? 1 : 0) + (arg1 ? 1 : 0))"
            );
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0x7C, vec![2, left], None),
                &mut pending,
            );
            assert_eq!(file.current(context, 2).render(), "(~(arg0 ? 1 : 0))");
        })?;
        Ok(())
    }

    #[test]
    fn integer_xor_materializes_a_moved_boolean_expression() -> Result<(), String> {
        with_context("()I", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            file.write(
                1,
                Expr::InstanceOf {
                    value: Box::new(Expr::Local("value".to_owned())),
                    ty: "Probe".to_owned(),
                },
            );
            let mut pending = None;
            assert!(matches!(
                lift_insn(
                    context,
                    &mut file,
                    &insn(0x01, vec![0, 1], None),
                    &mut pending,
                ),
                LiftOutcome::Statement(statement)
                    if statement == "var0 = (value instanceof Probe)"
            ));
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0xDF, vec![0, 0], Some(1)),
                &mut pending,
            );
            assert_eq!(
                file.current(context, 0).render(),
                "(!(value instanceof Probe))"
            );
        })?;
        Ok(())
    }

    #[test]
    fn integer_xor_materializes_boolean_invoke_result_as_zero_or_one() -> Result<(), String> {
        with_context("()Z", |context: &MethodContext<'_>| {
            let mut file: RegisterFile = RegisterFile::new();
            file.write(
                0,
                Expr::Invoke {
                    receiver: Some(Box::new(Expr::Local("value".to_owned()))),
                    owner: "String".to_owned(),
                    method: "isEmpty".to_owned(),
                    args: Vec::new(),
                    returns_bool: true,
                },
            );
            let mut pending = None;
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0xDF, vec![0, 0], Some(1)),
                &mut pending,
            );
            assert_eq!(file.current(context, 0).render(), "(!value.isEmpty())");
            let _: LiftOutcome = lift_insn(
                context,
                &mut file,
                &insn(0xD8, vec![1, 0], Some(1)),
                &mut pending,
            );
            assert_eq!(
                file.current(context, 1).render(),
                "(((!value.isEmpty()) ? 1 : 0) + 1)"
            );
        })?;
        Ok(())
    }

    #[test]
    fn lambda_parameters_step_away_from_a_captured_lambda() {
        let free: Vec<String> = vec!["arg0".to_owned(), "this".to_owned()];
        assert_eq!(
            lambda_parameter_names(&free, 2),
            Some(vec!["p0".to_owned(), "p1".to_owned()])
        );
        let nested: Vec<String> = vec!["p0 -> Owner.lambda$inner$0(p0)".to_owned()];
        assert_eq!(
            lambda_parameter_names(&nested, 1),
            Some(vec!["q0".to_owned()])
        );
        let exhausted: Vec<String> = vec!["p0 q0 r0 s0".to_owned()];
        assert_eq!(lambda_parameter_names(&exhausted, 1), None);
        assert_eq!(lambda_parameter_names(&nested, 0), Some(Vec::new()));
    }

    #[test]
    fn only_mutable_builder_methods_thread_the_receiver_expression() {
        let append: MethodId = method(
            "Ljava/lang/StringBuilder;",
            "append",
            "Ljava/lang/StringBuilder;",
        );
        let concat: MethodId = method("Ljava/lang/String;", "concat", "Ljava/lang/String;");
        let builder_factory: MethodId = method(
            "Ljava/lang/StringBuilder;",
            "newBuilder",
            "Ljava/lang/StringBuilder;",
        );
        assert!(returns_receiver(&append));
        assert!(!returns_receiver(&concat));
        assert!(!returns_receiver(&builder_factory));
    }

    #[test]
    fn direct_init_target_requires_a_constructor_for_this_delegation() {
        assert_eq!(
            direct_init_target(true, "LProbe;", "LProbe;", Some(&Expr::This)),
            DirectInitTarget::This
        );
        assert_eq!(
            direct_init_target(false, "LProbe;", "LProbe;", Some(&Expr::This)),
            DirectInitTarget::Invalid
        );
        assert!(matches!(
            direct_init_outcome(DirectInitTarget::Invalid, String::new()),
            LiftOutcome::Unlifted
        ));
        assert_eq!(
            direct_init_target(true, "LProbe;", "LBase;", Some(&Expr::This)),
            DirectInitTarget::Super
        );
        assert_eq!(
            direct_init_target(
                true,
                "LProbe;",
                "LProbe;",
                Some(&Expr::New("Probe".to_string()))
            ),
            DirectInitTarget::Allocate
        );
        assert_eq!(
            direct_init_target(
                true,
                "LProbe;",
                "LBase;",
                Some(&Expr::Local("not_this".to_string()))
            ),
            DirectInitTarget::Invalid
        );
    }

    #[test]
    fn core_library_projection_requires_static_shape_and_exact_register_words() {
        let mut target: MethodId =
            method("Lj$/util/Collection$-EL;", "stream", "Ljava/lang/Object;");
        target.proto.parameters = vec!["Ljava/util/Collection;".to_string(), "J".to_string()];
        let projection: CoreMethodProjection = CoreMethodProjection {
            owner: "Ljava/util/Collection;".to_string(),
            name: "stream".to_string(),
            parameters: vec!["J".to_string()],
            return_type: "Ljava/lang/Object;".to_string(),
            shape: CoreInvokeShape::ReceiverFirst,
        };
        assert!(core_projection_matches_invoke(
            &projection,
            &target,
            true,
            3
        ));
        assert!(!core_projection_matches_invoke(
            &projection,
            &target,
            true,
            2
        ));
        assert!(!core_projection_matches_invoke(
            &projection,
            &target,
            false,
            4
        ));
    }

    #[test]
    fn method_reference_owner_uses_marker_confirmed_core_library_projection() {
        let bytes: &[u8] =
            include_bytes!("../../../corpus/jvm/desugar-core/CoreLibraryProbe-min21.dex");
        let dex: Result<crate::dex::DexFile, crate::error::Error> = crate::dex::parse(bytes);
        assert!(dex.is_ok());
        let Ok(dex): Result<crate::dex::DexFile, crate::error::Error> = dex else {
            return;
        };
        let recovery: CoreLibraryRecovery = CoreLibraryRecovery::analyze(&dex);
        let reference: RecoveredMethodRef = RecoveredMethodRef {
            kind: MethodRefKind::Static,
            owner: "Lj$/time/Duration;".to_string(),
            name: "ofMinutes".to_string(),
        };
        assert_eq!(
            render_method_reference(&recovery, &reference, &[]),
            Some("java.time.Duration::ofMinutes".to_string())
        );
    }
}
