use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_py_disasm::alt_runtimes::micropython::{
    MpyArg, MpyBytecodeModule, MpyDecodedInsn, MpyFunction, MpyObject,
};
use disrobe_py_marshal::{CodeEra, CodeObject, Object};

use crate::ast::builder::is_simple_identifier;
use crate::error::{DecompileError, Result};

const OP_POP_TOP: u8 = 1;
const OP_ROT_TWO: u8 = 2;
const OP_ROT_THREE: u8 = 3;
const OP_DUP_TOP: u8 = 4;
const OP_DUP_TOP_TWO: u8 = 5;
const OP_NOP: u8 = 9;
const OP_UNARY_POSITIVE: u8 = 10;
const OP_UNARY_NEGATIVE: u8 = 11;
const OP_UNARY_NOT: u8 = 12;
const OP_UNARY_INVERT: u8 = 15;
const OP_BINARY_MATRIX_MULTIPLY: u8 = 16;
const OP_BINARY_POWER: u8 = 19;
const OP_BINARY_MULTIPLY: u8 = 20;
const OP_BINARY_MODULO: u8 = 22;
const OP_BINARY_ADD: u8 = 23;
const OP_BINARY_SUBTRACT: u8 = 24;
const OP_BINARY_SUBSCR: u8 = 25;
const OP_BINARY_FLOOR_DIVIDE: u8 = 26;
const OP_BINARY_TRUE_DIVIDE: u8 = 27;
const OP_INPLACE_FLOOR_DIVIDE: u8 = 28;
const OP_INPLACE_TRUE_DIVIDE: u8 = 29;
const OP_INPLACE_ADD: u8 = 55;
const OP_INPLACE_SUBTRACT: u8 = 56;
const OP_INPLACE_MULTIPLY: u8 = 57;
const OP_INPLACE_MODULO: u8 = 59;
const OP_STORE_SUBSCR: u8 = 60;
const OP_BINARY_LSHIFT: u8 = 62;
const OP_BINARY_RSHIFT: u8 = 63;
const OP_BINARY_AND: u8 = 64;
const OP_BINARY_XOR: u8 = 65;
const OP_BINARY_OR: u8 = 66;
const OP_INPLACE_POWER: u8 = 67;
const OP_GET_ITER: u8 = 68;
const OP_LOAD_BUILD_CLASS: u8 = 71;
const OP_YIELD_FROM: u8 = 72;
const OP_INPLACE_LSHIFT: u8 = 75;
const OP_INPLACE_RSHIFT: u8 = 76;
const OP_INPLACE_AND: u8 = 77;
const OP_INPLACE_XOR: u8 = 78;
const OP_INPLACE_OR: u8 = 79;
const OP_IMPORT_STAR: u8 = 84;
const OP_YIELD_VALUE: u8 = 86;
const OP_POP_BLOCK: u8 = 87;
const OP_POP_EXCEPT: u8 = 89;
const OP_RETURN_VALUE: u8 = 83;
const OP_STORE_NAME: u8 = 90;
const OP_DELETE_NAME: u8 = 91;
const OP_UNPACK_SEQUENCE: u8 = 92;
const OP_FOR_ITER: u8 = 93;
const OP_UNPACK_EX: u8 = 94;
const OP_STORE_ATTR: u8 = 95;
const OP_STORE_GLOBAL: u8 = 97;
const OP_DELETE_GLOBAL: u8 = 98;
const OP_LOAD_CONST: u8 = 100;
const OP_LOAD_NAME: u8 = 101;
const OP_BUILD_TUPLE: u8 = 102;
const OP_BUILD_LIST: u8 = 103;
const OP_BUILD_SET: u8 = 104;
const OP_BUILD_MAP: u8 = 105;
const OP_LOAD_ATTR: u8 = 106;
const OP_IMPORT_NAME: u8 = 108;
const OP_IMPORT_FROM: u8 = 109;
const OP_JUMP_FORWARD: u8 = 110;
const OP_JUMP_IF_FALSE_OR_POP: u8 = 111;
const OP_JUMP_IF_TRUE_OR_POP: u8 = 112;
const OP_JUMP_ABSOLUTE: u8 = 113;
const OP_POP_JUMP_IF_FALSE: u8 = 114;
const OP_POP_JUMP_IF_TRUE: u8 = 115;
const OP_LOAD_GLOBAL: u8 = 116;
const OP_SETUP_FINALLY: u8 = 122;
const OP_LOAD_FAST: u8 = 124;
const OP_STORE_FAST: u8 = 125;
const OP_DELETE_FAST: u8 = 126;
const OP_RAISE_VARARGS: u8 = 130;
const OP_CALL_FUNCTION: u8 = 131;
const OP_MAKE_FUNCTION: u8 = 132;
const OP_BUILD_SLICE: u8 = 133;
const OP_LOAD_CLOSURE: u8 = 135;
const OP_LOAD_DEREF: u8 = 136;
const OP_STORE_DEREF: u8 = 137;
const OP_DELETE_DEREF: u8 = 138;
const OP_CALL_FUNCTION_KW: u8 = 141;
const OP_CALL_FUNCTION_EX: u8 = 142;
const OP_SETUP_WITH: u8 = 143;
const OP_EXTENDED_ARG: u8 = 144;
const OP_MAP_ADD: u8 = 147;
const OP_LOAD_METHOD: u8 = 160;
const OP_CALL_METHOD: u8 = 161;

const CO_OPTIMIZED: i32 = 0x0001;
const CO_NEWLOCALS: i32 = 0x0002;
const CO_VARARGS: i32 = 0x0004;
const CO_VARKEYWORDS: i32 = 0x0008;
const CO_GENERATOR: i32 = 0x0020;

const MP_SCOPE_FLAG_GENERATOR: u32 = 0x01;
const MP_SCOPE_FLAG_VARKEYWORDS: u32 = 0x02;
const MP_SCOPE_FLAG_VARARGS: u32 = 0x04;

const MAKE_FUNCTION_POS_DEFAULTS: u32 = 0x01;
const MAKE_FUNCTION_KW_DEFAULTS: u32 = 0x02;
const MAKE_FUNCTION_CLOSURE: u32 = 0x08;

const CLASS_CELL_NAME: &str = "__class__";
const CLASS_CELL_STORE: &str = "__classcell__";
const VARARGS_SLOT_NAME: &str = "varargs";
const VARKEYWORDS_SLOT_NAME: &str = "varkwargs";

#[derive(Debug, Clone)]
enum Emitted {
    Plain { op: u8, arg: u32 },
    JumpAbs { op: u8, mp_target: usize },
    JumpRel { op: u8, mp_target: usize },
    Unsupported { mnemonic: String },
}

#[derive(Debug, Clone)]
struct LiftContext {
    free_names: Vec<String>,
    is_module: bool,
    is_class_body: bool,
}

impl LiftContext {
    fn module() -> Self {
        Self {
            free_names: Vec::new(),
            is_module: true,
            is_class_body: false,
        }
    }

    fn nested(free_names: Vec<String>, is_class_body: bool) -> Self {
        Self {
            free_names,
            is_module: false,
            is_class_body,
        }
    }
}

pub fn lift_module(module: &MpyBytecodeModule) -> Result<CodeObject> {
    lift_function(&module.function, module, &LiftContext::module())
}

fn lift_function(
    func: &MpyFunction,
    module: &MpyBytecodeModule,
    context: &LiftContext,
) -> Result<CodeObject> {
    let mut consts: ConstPool = ConstPool::new();
    let mut names: NamePool = NamePool::new();

    let facts: ScopeFacts = scan_scope(func, context.free_names.len());
    let class_cell: Option<usize> = context
        .is_class_body
        .then(|| class_cell_slot(func, &facts))
        .flatten();
    let mut scope: Scope = build_scope(func, &context.free_names, &facts, class_cell)?;

    let mut child_codes: Vec<CodeObject> = Vec::with_capacity(func.children.len());
    for (index, child) in func.children.iter().enumerate() {
        let free_names: Vec<String> = facts
            .child_free_slots
            .get(&index)
            .map(|slots: &Vec<usize>| {
                slots
                    .iter()
                    .map(|slot: &usize| scope.name_of_slot(*slot))
                    .collect()
            })
            .unwrap_or_default();
        let child_context: LiftContext =
            LiftContext::nested(free_names, facts.class_body_children.contains(&index));
        child_codes.push(lift_function(child, module, &child_context)?);
    }

    let emitted: Vec<(usize, Emitted)> = lift_instructions(
        func,
        module,
        &facts,
        class_cell,
        &child_codes,
        &mut consts,
        &mut names,
        &mut scope,
    )?;

    let (code_bytes, lnotab): (Vec<u8>, Vec<u8>) = assemble(&emitted)?;

    let flags: i32 = function_flags(func, context.is_module);
    let argcount: i32 =
        i32::try_from(func.n_pos_args.saturating_sub(scope.free_count())).unwrap_or(0);
    let kwonly: i32 = i32::try_from(func.n_kwonly_args).unwrap_or(0);

    let mut code: CodeObject = CodeObject::new(CodeEra::Py38to310);
    code.argcount = argcount;
    code.kwonlyargcount = kwonly;
    code.nlocals = i32::try_from(scope.varnames.entries.len()).unwrap_or(0);
    code.stacksize = i32::try_from(func.n_state).unwrap_or(0);
    code.flags = flags;
    code.code = code_bytes;
    code.consts = consts.into_objects();
    code.names = names.into_objects();
    code.cellvars = scope
        .cellvars
        .iter()
        .map(|s: &String| short_ascii(s))
        .collect();
    code.freevars = scope
        .freevars
        .iter()
        .map(|s: &String| short_ascii(s))
        .collect();
    code.varnames = scope.varnames.into_objects();
    code.filename = Object::ShortAscii {
        value: "<mpy>".to_owned(),
        interned: false,
    };
    code.name = Object::ShortAscii {
        value: func.simple_name.clone(),
        interned: false,
    };
    code.qualname = Object::ShortAscii {
        value: func.simple_name.clone(),
        interned: false,
    };
    code.firstlineno = 1;
    code.lnotab = lnotab;
    Ok(code)
}

#[derive(Debug, Default)]
struct ScopeFacts {
    cell_slots: BTreeSet<usize>,
    closure_operands: BTreeSet<usize>,
    child_free_slots: BTreeMap<usize, Vec<usize>>,
    class_body_children: BTreeSet<usize>,
    placeholders: BTreeSet<usize>,
    default_flags: BTreeMap<usize, u32>,
    slot_hints: BTreeMap<usize, String>,
    block_depth: BTreeMap<usize, usize>,
    inside_try: BTreeSet<usize>,
}

const fn is_make_op(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"MAKE_FUNCTION" | b"MAKE_FUNCTION_DEFARGS" | b"MAKE_CLOSURE" | b"MAKE_CLOSURE_DEFARGS"
    )
}

const fn is_defargs_op(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"MAKE_FUNCTION_DEFARGS" | b"MAKE_CLOSURE_DEFARGS"
    )
}

fn closure_arg(arg: &MpyArg) -> (usize, usize) {
    match arg {
        MpyArg::MakeClosure {
            table_index,
            n_closed,
        } => (
            usize::try_from(*table_index).unwrap_or(usize::MAX),
            usize::from(*n_closed),
        ),
        MpyArg::Uint(v) => (usize::try_from(*v).unwrap_or(usize::MAX), 0),
        _ => (usize::MAX, 0),
    }
}

fn child_target(arg: &MpyArg) -> usize {
    closure_arg(arg).0
}

fn slot_of(arg: &MpyArg) -> usize {
    usize::try_from(uint_arg(arg)).unwrap_or(usize::MAX)
}

fn scan_scope(func: &MpyFunction, n_free: usize) -> ScopeFacts {
    let mut facts: ScopeFacts = ScopeFacts::default();
    let instrs: &[MpyDecodedInsn] = &func.instructions;
    let cap: usize = usize::try_from(MAX_SLOT_INDEX).unwrap_or(usize::MAX);
    let record_cell = |slot: usize, set: &mut BTreeSet<usize>| {
        if slot >= n_free && slot < cap {
            set.insert(slot);
        }
    };
    for (i, insn) in instrs.iter().enumerate() {
        match insn.mnemonic.as_str() {
            "LOAD_DEREF" | "STORE_DEREF" | "DELETE_DEREF" => {
                record_cell(slot_of(&insn.arg), &mut facts.cell_slots);
            }
            "MAKE_CLOSURE" | "MAKE_CLOSURE_DEFARGS" => {
                let (child, closed): (usize, usize) = closure_arg(&insn.arg);
                let mut slots: Vec<usize> = Vec::with_capacity(closed);
                if i >= closed {
                    for (k, operand) in instrs.iter().enumerate().take(i).skip(i - closed) {
                        if !matches!(operand.mnemonic.as_str(), "LOAD_FAST" | "LOAD_FAST_N") {
                            slots.clear();
                            break;
                        }
                        let slot: usize = slot_of(&operand.arg);
                        facts.closure_operands.insert(k);
                        record_cell(slot, &mut facts.cell_slots);
                        slots.push(slot);
                    }
                }
                if slots.len() == closed {
                    facts.child_free_slots.insert(child, slots);
                }
            }
            "LOAD_BUILD_CLASS" => {
                if let Some(next) = instrs.get(i + 1)
                    && is_make_op(&next.mnemonic)
                {
                    facts.class_body_children.insert(child_target(&next.arg));
                }
            }
            _ => {}
        }
    }
    let has_defargs: bool = instrs
        .iter()
        .any(|x: &MpyDecodedInsn| is_defargs_op(&x.mnemonic));
    for (i, insn) in instrs.iter().enumerate() {
        if insn.mnemonic != "LOAD_NULL" {
            continue;
        }
        let Some(next): Option<&MpyDecodedInsn> = instrs.get(i + 1) else {
            continue;
        };
        if is_defargs_op(&next.mnemonic) || (has_defargs && next.mnemonic == "BUILD_MAP") {
            facts.placeholders.insert(i);
        }
    }
    for (i, insn) in instrs.iter().enumerate() {
        if !is_defargs_op(&insn.mnemonic) {
            continue;
        }
        let child: usize = child_target(&insn.arg);
        let mut flags: u32 = 0;
        if func
            .children
            .get(child)
            .is_some_and(|c: &MpyFunction| c.n_def_pos_args > 0)
        {
            flags |= MAKE_FUNCTION_POS_DEFAULTS;
        }
        let kw_present: bool = i
            .checked_sub(1)
            .and_then(|p: usize| instrs.get(p))
            .is_some_and(|p: &MpyDecodedInsn| p.mnemonic != "LOAD_NULL");
        if kw_present {
            flags |= MAKE_FUNCTION_KW_DEFAULTS;
        }
        facts.default_flags.insert(i, flags);
    }
    for (i, insn) in instrs.iter().enumerate() {
        if !is_make_op(&insn.mnemonic) {
            continue;
        }
        let Some(store): Option<&MpyDecodedInsn> = instrs.get(i + 1) else {
            continue;
        };
        if !matches!(store.mnemonic.as_str(), "STORE_FAST" | "STORE_FAST_N") {
            continue;
        }
        let child: usize = child_target(&insn.arg);
        let Some(name): Option<&String> = func
            .children
            .get(child)
            .map(|c: &MpyFunction| &c.simple_name)
        else {
            continue;
        };
        if is_simple_identifier(name) && !PYTHON_KEYWORDS.contains(&name.as_str()) {
            facts.slot_hints.insert(slot_of(&store.arg), name.clone());
        }
    }
    for (i, insn) in instrs.iter().enumerate() {
        let open: Vec<&MpyDecodedInsn> = instrs[..i]
            .iter()
            .filter(|prior: &&MpyDecodedInsn| {
                matches!(
                    prior.mnemonic.as_str(),
                    "SETUP_EXCEPT" | "SETUP_FINALLY" | "SETUP_WITH"
                ) && rel_target(&prior.arg).is_some_and(|t: usize| t > insn.offset)
            })
            .collect();
        if open.is_empty() {
            continue;
        }
        if insn.mnemonic == "RETURN_VALUE" {
            facts.block_depth.insert(i, open.len());
        }
        if open
            .last()
            .is_some_and(|s: &&MpyDecodedInsn| s.mnemonic == "SETUP_EXCEPT")
        {
            facts.inside_try.insert(i);
        }
    }
    facts
}

fn class_cell_slot(func: &MpyFunction, facts: &ScopeFacts) -> Option<usize> {
    let instrs: &[MpyDecodedInsn] = &func.instructions;
    let last: &MpyDecodedInsn = instrs.last()?;
    if last.mnemonic != "RETURN_VALUE" {
        return None;
    }
    let push: &MpyDecodedInsn = instrs.get(instrs.len().checked_sub(2)?)?;
    if !matches!(push.mnemonic.as_str(), "LOAD_FAST" | "LOAD_FAST_N") {
        return None;
    }
    let slot: usize = slot_of(&push.arg);
    facts.cell_slots.contains(&slot).then_some(slot)
}

#[derive(Debug)]
struct Scope {
    n_free: usize,
    freevars: Vec<String>,
    cellvars: Vec<String>,
    cell_of_slot: BTreeMap<usize, u32>,
    local_of_slot: BTreeMap<usize, u32>,
    slot_hints: BTreeMap<usize, String>,
    varnames: NamePool,
}

impl Scope {
    const fn free_count(&self) -> u32 {
        self.n_free as u32
    }

    fn deref_index(&self, slot: usize) -> Option<u32> {
        if slot < self.n_free {
            return u32::try_from(self.cellvars.len().checked_add(slot)?).ok();
        }
        self.cell_of_slot.get(&slot).copied()
    }

    fn local_index(&mut self, slot: usize) -> Result<u32> {
        if let Some(idx) = self.local_of_slot.get(&slot) {
            return Ok(*idx);
        }
        if slot >= usize::try_from(MAX_SLOT_INDEX).unwrap_or(usize::MAX) {
            return Err(DecompileError::Emit {
                reason: format!("local slot index {slot} exceeds the {MAX_SLOT_INDEX} slot cap"),
            });
        }
        let name: String = self
            .slot_hints
            .get(&slot)
            .cloned()
            .unwrap_or_else(|| format!("local{slot}"));
        let idx: u32 = self.varnames.push_unique(&name);
        self.local_of_slot.insert(slot, idx);
        Ok(idx)
    }

    fn name_of_slot(&self, slot: usize) -> String {
        if slot < self.n_free {
            return self
                .freevars
                .get(slot)
                .cloned()
                .unwrap_or_else(|| format!("free{slot}"));
        }
        self.cell_of_slot
            .get(&slot)
            .and_then(|i: &u32| self.cellvars.get(usize::try_from(*i).unwrap_or(usize::MAX)))
            .cloned()
            .unwrap_or_else(|| format!("cell{slot}"))
    }
}

fn build_scope(
    func: &MpyFunction,
    free_names: &[String],
    facts: &ScopeFacts,
    class_cell: Option<usize>,
) -> Result<Scope> {
    let n_free: usize = free_names.len();
    let total_args: u32 = func.n_pos_args.saturating_add(func.n_kwonly_args);
    if total_args >= MAX_SLOT_INDEX {
        return Err(DecompileError::Emit {
            reason: format!(
                "function prelude declares {total_args} parameters, over the {MAX_SLOT_INDEX} local-slot cap"
            ),
        });
    }
    let declared: usize = usize::try_from(total_args).unwrap_or(0);
    let mut cells: NamePool = NamePool::new();
    let mut cell_of_slot: BTreeMap<usize, u32> = BTreeMap::new();
    for slot in &facts.cell_slots {
        let name: String = if class_cell == Some(*slot) {
            CLASS_CELL_NAME.to_owned()
        } else {
            declared_parameter_name(func, *slot)
                .map_or_else(|| format!("cell{slot}"), str::to_owned)
        };
        cell_of_slot.insert(*slot, cells.push_unique(&name));
    }
    let mut varnames: NamePool = NamePool::new();
    let mut local_of_slot: BTreeMap<usize, u32> = BTreeMap::new();
    for slot in parameter_slot_order(func, n_free, declared) {
        let name: String =
            declared_parameter_name(func, slot).map_or_else(|| format!("arg{slot}"), str::to_owned);
        local_of_slot.insert(slot, varnames.push_unique(&name));
    }
    let mut next_slot: usize = declared;
    if func.scope_flags & MP_SCOPE_FLAG_VARARGS != 0 {
        local_of_slot.insert(next_slot, varnames.push_unique(VARARGS_SLOT_NAME));
        next_slot = next_slot.saturating_add(1);
    }
    if func.scope_flags & MP_SCOPE_FLAG_VARKEYWORDS != 0 {
        local_of_slot.insert(next_slot, varnames.push_unique(VARKEYWORDS_SLOT_NAME));
    }
    Ok(Scope {
        n_free,
        freevars: free_names.to_vec(),
        cellvars: cells.entries,
        cell_of_slot,
        local_of_slot,
        slot_hints: facts.slot_hints.clone(),
        varnames,
    })
}

fn parameter_slot_order(func: &MpyFunction, n_free: usize, declared: usize) -> Vec<usize> {
    let positional_end: usize = usize::try_from(func.n_pos_args)
        .unwrap_or(declared)
        .min(declared);
    let mut order: Vec<usize> = (n_free..positional_end).collect();
    let keyword_only: Vec<usize> = (positional_end..declared).collect();
    if func.scope_flags & MP_SCOPE_FLAG_VARARGS != 0 && keyword_only.len() > 1 {
        order.extend(keyword_only.iter().skip(1));
        order.extend(keyword_only.first());
    } else {
        order.extend(keyword_only);
    }
    order
}

fn function_flags(func: &MpyFunction, is_module: bool) -> i32 {
    if is_module {
        return 0;
    }
    let mut flags: i32 = CO_OPTIMIZED | CO_NEWLOCALS;
    if func.scope_flags & MP_SCOPE_FLAG_VARARGS != 0 {
        flags |= CO_VARARGS;
    }
    if func.scope_flags & MP_SCOPE_FLAG_VARKEYWORDS != 0 {
        flags |= CO_VARKEYWORDS;
    }
    if func.scope_flags & MP_SCOPE_FLAG_GENERATOR != 0 {
        flags |= CO_GENERATOR;
    }
    flags
}

const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

fn declared_parameter_name(func: &MpyFunction, slot: usize) -> Option<&str> {
    let candidate: &str = func.arg_names.get(slot)?.as_str();
    (is_simple_identifier(candidate) && !PYTHON_KEYWORDS.contains(&candidate)).then_some(candidate)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn lift_instructions(
    func: &MpyFunction,
    module: &MpyBytecodeModule,
    facts: &ScopeFacts,
    class_cell: Option<usize>,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    names: &mut NamePool,
    scope: &mut Scope,
) -> Result<Vec<(usize, Emitted)>> {
    let instrs: &[MpyDecodedInsn] = &func.instructions;
    let mut out: Vec<(usize, Emitted)> = Vec::with_capacity(instrs.len());
    let mut i: usize = 0;
    while i < instrs.len() {
        if facts.placeholders.contains(&i) {
            i += 1;
            continue;
        }
        if let Some(consumed) = lift_super_method(instrs, i, names, &mut out) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = lift_exception_match(instrs, i, scope, &mut out)? {
            i += consumed;
            continue;
        }
        if let Some(slot) = class_cell
            && is_class_cell_tail(instrs, i, slot)
        {
            let cell: u32 = scope
                .deref_index(slot)
                .ok_or_else(|| DecompileError::Emit {
                    reason: format!("class body cell slot {slot} has no cell mapping"),
                })?;
            let offset: usize = instrs[i].offset;
            out.push((
                offset,
                Emitted::Plain {
                    op: OP_LOAD_CLOSURE,
                    arg: cell,
                },
            ));
            out.push((
                offset,
                Emitted::Plain {
                    op: OP_DUP_TOP,
                    arg: 0,
                },
            ));
            out.push((
                offset,
                Emitted::Plain {
                    op: OP_STORE_NAME,
                    arg: names.intern(CLASS_CELL_STORE),
                },
            ));
            i += 1;
            continue;
        }
        if facts.closure_operands.contains(&i) {
            let slot: usize = slot_of(&instrs[i].arg);
            let cell: u32 = scope
                .deref_index(slot)
                .ok_or_else(|| DecompileError::Emit {
                    reason: format!("closure operand slot {slot} has no cell mapping"),
                })?;
            out.push((
                instrs[i].offset,
                Emitted::Plain {
                    op: OP_LOAD_CLOSURE,
                    arg: cell,
                },
            ));
            i += 1;
            continue;
        }
        if let Some(range_loop) = detect_range_loop(instrs, i) {
            let range_name: u32 = names.intern("range");
            let bound: &MpyDecodedInsn = &instrs[range_loop.bound_idx];
            let store_i: &MpyDecodedInsn = &instrs[range_loop.store_idx];
            let for_iter_mp: usize = instrs[range_loop.jump_idx].offset;
            let exit_mp: usize = range_loop.exit_mp;

            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_LOAD_GLOBAL,
                    arg: range_name,
                },
            ));
            for e in lift_one(bound, module, child_codes, consts, names, scope, 0, false)? {
                out.push((bound.offset, e));
            }
            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_CALL_FUNCTION,
                    arg: 1,
                },
            ));
            out.push((
                bound.offset,
                Emitted::Plain {
                    op: OP_GET_ITER,
                    arg: 0,
                },
            ));
            out.push((
                for_iter_mp,
                Emitted::JumpRel {
                    op: OP_FOR_ITER,
                    mp_target: exit_mp,
                },
            ));
            for e in lift_one(store_i, module, child_codes, consts, names, scope, 0, false)? {
                out.push((store_i.offset, e));
            }
            let mut last_body_off: usize = store_i.offset;
            for (k, body) in instrs[range_loop.body_start_idx..range_loop.body_end_idx]
                .iter()
                .enumerate()
            {
                last_body_off = body.offset;
                let at: usize = range_loop.body_start_idx.saturating_add(k);
                let defaults: u32 = facts.default_flags.get(&at).copied().unwrap_or(0);
                for e in lift_one(
                    body,
                    module,
                    child_codes,
                    consts,
                    names,
                    scope,
                    defaults,
                    facts.inside_try.contains(&at),
                )? {
                    out.push((body.offset, e));
                }
            }
            out.push((
                last_body_off,
                Emitted::JumpAbs {
                    op: OP_JUMP_ABSOLUTE,
                    mp_target: for_iter_mp,
                },
            ));
            i = range_loop.end_idx;
            continue;
        }
        let insn: &MpyDecodedInsn = &instrs[i];
        if matches!(
            insn.mnemonic.as_str(),
            "CALL_FUNCTION" | "CALL_METHOD" | "CALL_FUNCTION_N" | "CALL_METHOD_N"
        ) {
            let (n_pos, n_kw): (u32, u32) = call_shape(&insn.arg);
            if n_kw > 0 {
                let is_method: bool = insn.mnemonic.starts_with("CALL_METHOD");
                if keyword_call(&mut out, insn.offset, n_pos, n_kw, is_method, consts).is_none() {
                    out.push((
                        insn.offset,
                        Emitted::Unsupported {
                            mnemonic: format!("{} with {n_kw} keyword argument(s)", insn.mnemonic),
                        },
                    ));
                }
                i += 1;
                continue;
            }
        }
        for _ in 0..facts.block_depth.get(&i).copied().unwrap_or(0) {
            out.push((
                insn.offset,
                Emitted::Plain {
                    op: OP_POP_BLOCK,
                    arg: 0,
                },
            ));
        }
        let defaults: u32 = facts.default_flags.get(&i).copied().unwrap_or(0);
        let inside_try: bool = facts.inside_try.contains(&i);
        for e in lift_one(
            insn,
            module,
            child_codes,
            consts,
            names,
            scope,
            defaults,
            inside_try,
        )? {
            out.push((insn.offset, e));
        }
        i += 1;
    }
    Ok(out)
}

fn is_class_cell_tail(instrs: &[MpyDecodedInsn], at: usize, cell_slot: usize) -> bool {
    if at.saturating_add(2) != instrs.len() {
        return false;
    }
    let Some(push): Option<&MpyDecodedInsn> = instrs.get(at) else {
        return false;
    };
    if !matches!(push.mnemonic.as_str(), "LOAD_FAST" | "LOAD_FAST_N") {
        return false;
    }
    slot_of(&push.arg) == cell_slot
}

fn lift_super_method(
    instrs: &[MpyDecodedInsn],
    at: usize,
    names: &mut NamePool,
    out: &mut Vec<(usize, Emitted)>,
) -> Option<usize> {
    let load_super: &MpyDecodedInsn = instrs.get(at)?;
    if !matches!(load_super.mnemonic.as_str(), "LOAD_GLOBAL" | "LOAD_NAME")
        || qstr_text(&load_super.arg) != "super"
    {
        return None;
    }
    let type_push: &MpyDecodedInsn = instrs.get(at + 1)?;
    if type_push.mnemonic != "LOAD_DEREF" {
        return None;
    }
    let self_push: &MpyDecodedInsn = instrs.get(at + 2)?;
    if !matches!(self_push.mnemonic.as_str(), "LOAD_FAST" | "LOAD_FAST_N") {
        return None;
    }
    let method: &MpyDecodedInsn = instrs.get(at + 3)?;
    if method.mnemonic != "LOAD_SUPER_METHOD" {
        return None;
    }
    let super_name: u32 = names.intern("super");
    let method_name: u32 = names.intern(&qstr_text(&method.arg));
    out.push((
        load_super.offset,
        Emitted::Plain {
            op: OP_LOAD_GLOBAL,
            arg: super_name,
        },
    ));
    out.push((
        type_push.offset,
        Emitted::Plain {
            op: OP_CALL_FUNCTION,
            arg: 0,
        },
    ));
    out.push((self_push.offset, Emitted::Plain { op: OP_NOP, arg: 0 }));
    out.push((
        method.offset,
        Emitted::Plain {
            op: OP_LOAD_METHOD,
            arg: method_name,
        },
    ));
    Some(4)
}

fn lift_exception_match(
    instrs: &[MpyDecodedInsn],
    at: usize,
    scope: &mut Scope,
    out: &mut Vec<(usize, Emitted)>,
) -> Result<Option<usize>> {
    let Some(test): Option<&MpyDecodedInsn> = instrs.get(at) else {
        return Ok(None);
    };
    if test.mnemonic != "BINARY_OP"
        || !matches!(test.arg, MpyArg::BinaryOp(MP_BINARY_OP_EXCEPTION_MATCH))
    {
        return Ok(None);
    }
    let Some(branch): Option<&MpyDecodedInsn> = instrs.get(at + 1) else {
        return Ok(None);
    };
    if branch.mnemonic != "POP_JUMP_IF_FALSE" {
        return Ok(None);
    }
    let Some(target): Option<usize> = rel_target(&branch.arg) else {
        return Ok(None);
    };
    out.push((test.offset, Emitted::Plain { op: OP_NOP, arg: 0 }));
    out.push((
        branch.offset,
        Emitted::JumpAbs {
            op: OP_JUMP_IF_NOT_EXC_MATCH,
            mp_target: target,
        },
    ));
    let Some(bind): Option<&MpyDecodedInsn> = instrs.get(at + 2) else {
        return Ok(Some(2));
    };
    let pop: Emitted = Emitted::Plain {
        op: OP_POP_TOP,
        arg: 0,
    };
    match bind.mnemonic.as_str() {
        "POP_TOP" => {
            for _ in 0..3 {
                out.push((bind.offset, pop.clone()));
            }
            Ok(Some(3))
        }
        "STORE_FAST" | "STORE_FAST_N" => {
            out.push((bind.offset, pop.clone()));
            for e in slot_access(&bind.arg, scope, OP_STORE_FAST, OP_STORE_DEREF)? {
                out.push((bind.offset, e));
            }
            out.push((bind.offset, pop));
            Ok(Some(3))
        }
        _ => Ok(Some(2)),
    }
}

#[derive(Debug, Clone, Copy)]
struct RangeLoop {
    bound_idx: usize,
    jump_idx: usize,
    store_idx: usize,
    body_start_idx: usize,
    body_end_idx: usize,
    exit_mp: usize,
    end_idx: usize,
}

const MP_BINARY_OP_LESS: u8 = 0;
const MP_BINARY_OP_EXCEPTION_MATCH: u8 = 8;
const MP_BINARY_OP_ADD: u8 = 14;

fn detect_range_loop(instrs: &[MpyDecodedInsn], at: usize) -> Option<RangeLoop> {
    if at == 0 {
        return None;
    }
    let bound_idx: usize = at - 1;
    if !is_simple_load(&instrs[bound_idx]) {
        return None;
    }
    if instrs[at].mnemonic != "LOAD_CONST_SMALL_INT" || small_int_value(&instrs[at].arg) != 0 {
        return None;
    }
    let jump_idx: usize = at + 1;
    let jump: &MpyDecodedInsn = instrs.get(jump_idx)?;
    if jump.mnemonic != "JUMP" {
        return None;
    }
    let cond_mp: usize = rel_target(&jump.arg)?;
    let cond_idx: usize = instrs
        .iter()
        .position(|x: &MpyDecodedInsn| x.offset == cond_mp)?;
    let body_start_off: usize = instrs.get(jump_idx + 1)?.offset;

    let dup_idx: usize = jump_idx + 1;
    if instrs.get(dup_idx)?.mnemonic != "DUP_TOP" {
        return None;
    }
    let store_idx: usize = dup_idx + 1;
    if instrs.get(store_idx)?.mnemonic != "STORE_FAST" {
        return None;
    }
    if cond_idx < 2 {
        return None;
    }
    let incr_a: &MpyDecodedInsn = instrs.get(cond_idx - 2)?;
    let incr_b: &MpyDecodedInsn = instrs.get(cond_idx - 1)?;
    if incr_a.mnemonic != "LOAD_CONST_SMALL_INT" || small_int_value(&incr_a.arg) != 1 {
        return None;
    }
    if incr_b.mnemonic != "BINARY_OP" || !matches!(incr_b.arg, MpyArg::BinaryOp(MP_BINARY_OP_ADD)) {
        return None;
    }
    if !matches_range_tail(instrs, cond_idx, body_start_off) {
        return None;
    }
    let exit_idx: usize = cond_idx + 6;
    let exit_mp: usize = instrs
        .get(exit_idx)
        .map_or(usize::MAX, |x: &MpyDecodedInsn| x.offset);
    Some(RangeLoop {
        bound_idx,
        jump_idx,
        store_idx,
        body_start_idx: store_idx + 1,
        body_end_idx: cond_idx - 2,
        exit_mp,
        end_idx: exit_idx,
    })
}

fn matches_range_tail(instrs: &[MpyDecodedInsn], cond_idx: usize, body_start_off: usize) -> bool {
    let expect: [(&str, Option<u8>); 6] = [
        ("DUP_TOP_TWO", None),
        ("ROT_TWO", None),
        ("BINARY_OP", Some(MP_BINARY_OP_LESS)),
        ("POP_JUMP_IF_TRUE", None),
        ("POP_TOP", None),
        ("POP_TOP", None),
    ];
    for (k, (name, op)) in expect.iter().enumerate() {
        let Some(insn): Option<&MpyDecodedInsn> = instrs.get(cond_idx + k) else {
            return false;
        };
        if insn.mnemonic != *name {
            return false;
        }
        if let Some(want) = op
            && !matches!(&insn.arg, MpyArg::BinaryOp(o) if o == want)
        {
            return false;
        }
        if *name == "POP_JUMP_IF_TRUE" && rel_target(&insn.arg) != Some(body_start_off) {
            return false;
        }
    }
    true
}

fn is_simple_load(insn: &MpyDecodedInsn) -> bool {
    matches!(
        insn.mnemonic.as_str(),
        "LOAD_FAST" | "LOAD_GLOBAL" | "LOAD_NAME" | "LOAD_CONST_SMALL_INT" | "LOAD_DEREF"
    )
}

const fn rel_target(arg: &MpyArg) -> Option<usize> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            Some(*byte_offset)
        }
        _ => None,
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
fn lift_one(
    insn: &MpyDecodedInsn,
    module: &MpyBytecodeModule,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    names: &mut NamePool,
    scope: &mut Scope,
    defaults: u32,
    inside_try: bool,
) -> Result<Vec<Emitted>> {
    let m: &str = insn.mnemonic.as_str();
    let plain = |op: u8, arg: u32| -> Vec<Emitted> { vec![Emitted::Plain { op, arg }] };
    let unsupported = || -> Vec<Emitted> {
        vec![Emitted::Unsupported {
            mnemonic: insn.mnemonic.clone(),
        }]
    };

    let result: Vec<Emitted> = match m {
        "LOAD_CONST_STRING" => {
            let value: Object = qstr_str_const(&insn.arg);
            plain(OP_LOAD_CONST, consts.intern(value))
        }
        "LOAD_CONST_SMALL_INT" => {
            let v: i64 = small_int_value(&insn.arg);
            plain(OP_LOAD_CONST, consts.intern(int_object(v)))
        }
        "LOAD_CONST_OBJ" => {
            let value: Object = object_const(&insn.arg, module);
            plain(OP_LOAD_CONST, consts.intern(value))
        }
        "LOAD_CONST_NONE" => plain(OP_LOAD_CONST, consts.intern(Object::None)),
        "LOAD_CONST_FALSE" => plain(OP_LOAD_CONST, consts.intern(Object::False)),
        "LOAD_CONST_TRUE" => plain(OP_LOAD_CONST, consts.intern(Object::True)),
        "LOAD_NULL" => plain(OP_LOAD_CONST, consts.intern(Object::None)),
        "LOAD_NAME" => plain(OP_LOAD_NAME, names.intern(&qstr_text(&insn.arg))),
        "LOAD_GLOBAL" => plain(OP_LOAD_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "LOAD_ATTR" => plain(OP_LOAD_ATTR, names.intern(&qstr_text(&insn.arg))),
        "LOAD_METHOD" => plain(OP_LOAD_METHOD, names.intern(&qstr_text(&insn.arg))),
        "LOAD_SUPER_METHOD" => plain(OP_LOAD_METHOD, names.intern(&qstr_text(&insn.arg))),
        "STORE_NAME" => plain(OP_STORE_NAME, names.intern(&qstr_text(&insn.arg))),
        "STORE_GLOBAL" => plain(OP_STORE_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "STORE_ATTR" => plain(OP_STORE_ATTR, names.intern(&qstr_text(&insn.arg))),
        "DELETE_NAME" => plain(OP_DELETE_NAME, names.intern(&qstr_text(&insn.arg))),
        "DELETE_GLOBAL" => plain(OP_DELETE_GLOBAL, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_NAME" => plain(OP_IMPORT_NAME, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_FROM" => plain(OP_IMPORT_FROM, names.intern(&qstr_text(&insn.arg))),
        "IMPORT_STAR" => plain(OP_IMPORT_STAR, 0),
        "LOAD_FAST" | "LOAD_FAST_N" => slot_access(&insn.arg, scope, OP_LOAD_FAST, OP_LOAD_DEREF)?,
        "STORE_FAST" | "STORE_FAST_N" => {
            slot_access(&insn.arg, scope, OP_STORE_FAST, OP_STORE_DEREF)?
        }
        "DELETE_FAST" => slot_access(&insn.arg, scope, OP_DELETE_FAST, OP_DELETE_DEREF)?,
        "LOAD_DEREF" => plain(OP_LOAD_DEREF, cell_access(&insn.arg, scope)?),
        "STORE_DEREF" => plain(OP_STORE_DEREF, cell_access(&insn.arg, scope)?),
        "DELETE_DEREF" => plain(OP_DELETE_DEREF, cell_access(&insn.arg, scope)?),
        "BUILD_TUPLE" => plain(OP_BUILD_TUPLE, uint_arg(&insn.arg)),
        "BUILD_LIST" => plain(OP_BUILD_LIST, uint_arg(&insn.arg)),
        "BUILD_MAP" => plain(OP_BUILD_MAP, uint_arg(&insn.arg)),
        "BUILD_SET" => plain(OP_BUILD_SET, uint_arg(&insn.arg)),
        "BUILD_SLICE" => plain(OP_BUILD_SLICE, uint_arg(&insn.arg)),
        "UNPACK_SEQUENCE" => plain(OP_UNPACK_SEQUENCE, uint_arg(&insn.arg)),
        "UNPACK_EX" => plain(OP_UNPACK_EX, uint_arg(&insn.arg)),
        "MAKE_FUNCTION" => make_function(&insn.arg, child_codes, consts, 0),
        "MAKE_FUNCTION_DEFARGS" => make_function(&insn.arg, child_codes, consts, defaults),
        "MAKE_CLOSURE" => make_closure(&insn.arg, child_codes, consts, 0),
        "MAKE_CLOSURE_DEFARGS" => make_closure(&insn.arg, child_codes, consts, defaults),
        "CALL_FUNCTION" => call_function(&insn.arg),
        "CALL_METHOD" => call_method(&insn.arg),
        "CALL_FUNCTION_VAR_KW" => plain(OP_CALL_FUNCTION_EX, 1),
        "CALL_METHOD_VAR_KW" => plain(OP_CALL_FUNCTION_EX, 1),
        "RETURN_VALUE" => plain(OP_RETURN_VALUE, 0),
        "POP_TOP" => plain(OP_POP_TOP, 0),
        "DUP_TOP" => plain(OP_DUP_TOP, 0),
        "DUP_TOP_TWO" => plain(OP_DUP_TOP_TWO, 0),
        "ROT_TWO" => plain(OP_ROT_TWO, 0),
        "ROT_THREE" => plain(OP_ROT_THREE, 0),
        "GET_ITER" | "GET_ITER_STACK" => plain(OP_GET_ITER, 0),
        "LOAD_BUILD_CLASS" => plain(OP_LOAD_BUILD_CLASS, 0),
        "LOAD_SUBSCR" => plain(OP_BINARY_SUBSCR, 0),
        "STORE_SUBSCR" => plain(OP_STORE_SUBSCR, 0),
        "STORE_COMP" => store_comp(&insn.arg),
        "YIELD_VALUE" => plain(OP_YIELD_VALUE, 0),
        "YIELD_FROM" => plain(OP_YIELD_FROM, 0),
        "RAISE_LAST" => plain(OP_RAISE_VARARGS, 0),
        "RAISE_OBJ" => plain(OP_RAISE_VARARGS, 1),
        "RAISE_FROM" => plain(OP_RAISE_VARARGS, 2),
        "UNARY_OP" => unary_op(&insn.arg, &unsupported),
        "BINARY_OP" => binary_op(&insn.arg, &unsupported),
        "JUMP" => jump_abs(OP_JUMP_ABSOLUTE, &insn.arg),
        "POP_JUMP_IF_TRUE" => jump_abs(OP_POP_JUMP_IF_TRUE, &insn.arg),
        "POP_JUMP_IF_FALSE" => jump_abs(OP_POP_JUMP_IF_FALSE, &insn.arg),
        "JUMP_IF_TRUE_OR_POP" => jump_abs(OP_JUMP_IF_TRUE_OR_POP, &insn.arg),
        "JUMP_IF_FALSE_OR_POP" => jump_abs(OP_JUMP_IF_FALSE_OR_POP, &insn.arg),
        "FOR_ITER" => jump_rel(OP_FOR_ITER, &insn.arg),
        "SETUP_WITH" => jump_rel(OP_SETUP_WITH, &insn.arg),
        "SETUP_EXCEPT" | "SETUP_FINALLY" => jump_rel(OP_SETUP_FINALLY, &insn.arg),
        "WITH_CLEANUP" => plain(OP_POP_BLOCK, 0),
        "END_FINALLY" => plain(OP_RERAISE, 0),
        "POP_EXCEPT_JUMP" => {
            let close: u8 = if inside_try {
                OP_POP_BLOCK
            } else {
                OP_POP_EXCEPT
            };
            let mut v: Vec<Emitted> = vec![Emitted::Plain { op: close, arg: 0 }];
            v.extend(jump_rel(OP_JUMP_FORWARD, &insn.arg));
            v
        }
        "STORE_MAP" => vec![
            Emitted::Plain {
                op: OP_ROT_TWO,
                arg: 0,
            },
            Emitted::Plain {
                op: OP_MAP_ADD,
                arg: 1,
            },
        ],
        _ => unsupported(),
    };
    Ok(result)
}

fn jump_abs(op: u8, arg: &MpyArg) -> Vec<Emitted> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            vec![Emitted::JumpAbs {
                op,
                mp_target: *byte_offset,
            }]
        }
        _ => vec![Emitted::Unsupported {
            mnemonic: "jump-without-target".to_owned(),
        }],
    }
}

fn jump_rel(op: u8, arg: &MpyArg) -> Vec<Emitted> {
    match arg {
        MpyArg::RelTarget { byte_offset } | MpyArg::UnwindTarget { byte_offset, .. } => {
            vec![Emitted::JumpRel {
                op,
                mp_target: *byte_offset,
            }]
        }
        _ => vec![Emitted::Unsupported {
            mnemonic: "jump-without-target".to_owned(),
        }],
    }
}

fn call_shape(arg: &MpyArg) -> (u32, u32) {
    let packed: u32 = uint_arg(arg);
    (packed & 0xFF, (packed >> 8) & 0xFF)
}

fn call_function(arg: &MpyArg) -> Vec<Emitted> {
    let (n_pos, n_kw): (u32, u32) = call_shape(arg);
    vec![Emitted::Plain {
        op: OP_CALL_FUNCTION,
        arg: n_pos.saturating_add(n_kw),
    }]
}

fn call_method(arg: &MpyArg) -> Vec<Emitted> {
    let (n_pos, n_kw): (u32, u32) = call_shape(arg);
    vec![Emitted::Plain {
        op: OP_CALL_METHOD,
        arg: n_pos.saturating_add(n_kw),
    }]
}

const fn emitted_stack_effect(op: u8, arg: u32) -> Option<(u32, u32)> {
    match op {
        OP_NOP | OP_ROT_TWO | OP_ROT_THREE | OP_POP_BLOCK | OP_DELETE_FAST | OP_DELETE_NAME
        | OP_DELETE_GLOBAL | OP_DELETE_DEREF | OP_JUMP_FORWARD | OP_JUMP_ABSOLUTE
        | OP_EXTENDED_ARG => Some((0, 0)),
        OP_POP_TOP
        | OP_STORE_NAME
        | OP_STORE_GLOBAL
        | OP_STORE_FAST
        | OP_STORE_DEREF
        | OP_RETURN_VALUE
        | OP_IMPORT_STAR
        | OP_POP_JUMP_IF_FALSE
        | OP_POP_JUMP_IF_TRUE
        | OP_JUMP_IF_FALSE_OR_POP
        | OP_JUMP_IF_TRUE_OR_POP => Some((1, 0)),
        OP_DUP_TOP_TWO => Some((0, 2)),
        OP_DUP_TOP | OP_LOAD_CONST | OP_LOAD_NAME | OP_LOAD_GLOBAL | OP_LOAD_FAST
        | OP_LOAD_DEREF | OP_LOAD_CLOSURE | OP_LOAD_BUILD_CLASS | OP_IMPORT_FROM => Some((0, 1)),
        OP_LOAD_ATTR | OP_GET_ITER | OP_YIELD_VALUE | OP_UNARY_POSITIVE | OP_UNARY_NEGATIVE
        | OP_UNARY_NOT | OP_UNARY_INVERT => Some((1, 1)),
        OP_LOAD_METHOD => Some((1, 2)),
        OP_BINARY_POWER
        | OP_BINARY_MULTIPLY
        | OP_BINARY_MATRIX_MULTIPLY
        | OP_BINARY_MODULO
        | OP_BINARY_ADD
        | OP_BINARY_SUBTRACT
        | OP_BINARY_SUBSCR
        | OP_BINARY_FLOOR_DIVIDE
        | OP_BINARY_TRUE_DIVIDE
        | OP_BINARY_LSHIFT
        | OP_BINARY_RSHIFT
        | OP_BINARY_AND
        | OP_BINARY_XOR
        | OP_BINARY_OR
        | OP_INPLACE_ADD
        | OP_INPLACE_SUBTRACT
        | OP_INPLACE_MULTIPLY
        | OP_INPLACE_MODULO
        | OP_INPLACE_POWER
        | OP_INPLACE_FLOOR_DIVIDE
        | OP_INPLACE_TRUE_DIVIDE
        | OP_INPLACE_LSHIFT
        | OP_INPLACE_RSHIFT
        | OP_INPLACE_AND
        | OP_INPLACE_XOR
        | OP_INPLACE_OR
        | OP_COMPARE_OP
        | OP_IS_OP
        | OP_CONTAINS_OP
        | OP_IMPORT_NAME
        | OP_YIELD_FROM => Some((2, 1)),
        OP_STORE_ATTR | OP_MAP_ADD => Some((2, 0)),
        OP_STORE_SUBSCR => Some((3, 0)),
        OP_UNPACK_SEQUENCE => Some((1, arg)),
        OP_BUILD_TUPLE | OP_BUILD_LIST | OP_BUILD_SET | OP_BUILD_SLICE => Some((arg, 1)),
        OP_BUILD_MAP => Some((arg.saturating_mul(2), 1)),
        OP_RAISE_VARARGS => Some((arg, 0)),
        OP_CALL_FUNCTION => Some((arg.saturating_add(1), 1)),
        OP_CALL_METHOD | OP_CALL_FUNCTION_KW => Some((arg.saturating_add(2), 1)),
        OP_CALL_FUNCTION_EX => Some((if arg & 1 == 1 { 3 } else { 2 }, 1)),
        OP_MAKE_FUNCTION => Some((2 + (arg & 0x0F).count_ones(), 1)),
        _ => None,
    }
}

fn producer_of_depth(out: &[(usize, Emitted)], depth: u32) -> Option<usize> {
    let target: i64 = 1 - i64::from(depth);
    let mut height: i64 = 0;
    for j in (0..out.len()).rev() {
        let (op, arg): (u8, u32) = match &out[j].1 {
            Emitted::Plain { op, arg } => (*op, *arg),
            Emitted::JumpAbs { op, .. } | Emitted::JumpRel { op, .. } => (*op, 0),
            Emitted::Unsupported { .. } => return None,
        };
        let (pops, pushes): (u32, u32) = emitted_stack_effect(op, arg)?;
        let pushed: i64 = i64::from(pushes);
        if pushed > 0 && height >= target && target > height - pushed {
            return Some(j);
        }
        height = height - pushed + i64::from(pops);
        if height < target {
            return None;
        }
    }
    None
}

fn keyword_call(
    out: &mut Vec<(usize, Emitted)>,
    offset: usize,
    n_pos: u32,
    n_kw: u32,
    is_method: bool,
    consts: &mut ConstPool,
) -> Option<()> {
    let mut keys: Vec<Object> = Vec::with_capacity(usize::try_from(n_kw).ok()?);
    for i in 0..n_kw {
        let depth: u32 = 2u32.checked_mul(n_kw.checked_sub(i)?)?;
        let at: usize = producer_of_depth(out, depth)?;
        let Emitted::Plain {
            op: OP_LOAD_CONST,
            arg,
        } = out[at].1
        else {
            return None;
        };
        keys.push(consts.entries.get(usize::try_from(arg).ok()?)?.clone());
        out[at].1 = Emitted::Plain { op: OP_NOP, arg: 0 };
    }
    if is_method {
        let callee_depth: u32 = n_pos.checked_add(2u32.checked_mul(n_kw)?)?.checked_add(1)?;
        let at: usize = producer_of_depth(out, callee_depth)?;
        let Emitted::Plain {
            op: OP_LOAD_METHOD,
            arg,
        } = out[at].1
        else {
            return None;
        };
        out[at].1 = Emitted::Plain {
            op: OP_LOAD_ATTR,
            arg,
        };
    }
    let names: u32 = consts.intern(Object::Tuple(keys));
    out.push((
        offset,
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: names,
        },
    ));
    out.push((
        offset,
        Emitted::Plain {
            op: OP_CALL_FUNCTION_KW,
            arg: n_pos.saturating_add(n_kw),
        },
    ));
    Some(())
}

fn store_comp(arg: &MpyArg) -> Vec<Emitted> {
    let packed: u32 = uint_arg(arg);
    let kind: u32 = packed & 0x03;
    let op: u8 = match kind {
        0 => OP_INPLACE_ADD,
        _ => OP_NOP,
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

fn make_function(
    arg: &MpyArg,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    flag: u32,
) -> Vec<Emitted> {
    let idx: usize = match arg {
        MpyArg::Uint(v) => usize::try_from(*v).unwrap_or(usize::MAX),
        MpyArg::MakeClosure { table_index, .. } => {
            usize::try_from(*table_index).unwrap_or(usize::MAX)
        }
        _ => usize::MAX,
    };
    let Some(code): Option<&CodeObject> = child_codes.get(idx) else {
        return vec![Emitted::Unsupported {
            mnemonic: "make-function-bad-index".to_owned(),
        }];
    };
    let name: String = code_name(code);
    let code_const: u32 = consts.intern(Object::Code(Box::new(code.clone())));
    let name_const: u32 = consts.intern(short_ascii(&name));
    vec![
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: code_const,
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: name_const,
        },
        Emitted::Plain {
            op: OP_MAKE_FUNCTION,
            arg: flag,
        },
    ]
}

fn make_closure(
    arg: &MpyArg,
    child_codes: &[CodeObject],
    consts: &mut ConstPool,
    defaults: u32,
) -> Vec<Emitted> {
    let (idx, n_closed): (usize, usize) = closure_arg(arg);
    let Some(code): Option<&CodeObject> = child_codes.get(idx) else {
        return vec![Emitted::Unsupported {
            mnemonic: "make-closure-bad-index".to_owned(),
        }];
    };
    let name: String = code_name(code);
    let flag: u32 = defaults | MAKE_FUNCTION_CLOSURE;
    let code_const: u32 = consts.intern(Object::Code(Box::new(code.clone())));
    let name_const: u32 = consts.intern(short_ascii(&name));
    vec![
        Emitted::Plain {
            op: OP_BUILD_TUPLE,
            arg: u32::try_from(n_closed).unwrap_or(0),
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: code_const,
        },
        Emitted::Plain {
            op: OP_LOAD_CONST,
            arg: name_const,
        },
        Emitted::Plain {
            op: OP_MAKE_FUNCTION,
            arg: flag,
        },
    ]
}

fn unary_op(arg: &MpyArg, unsupported: &dyn Fn() -> Vec<Emitted>) -> Vec<Emitted> {
    let ord: u8 = match arg {
        MpyArg::UnaryOp(o) => *o,
        _ => return unsupported(),
    };
    let op: u8 = match ord {
        0 => OP_UNARY_POSITIVE,
        1 => OP_UNARY_NEGATIVE,
        2 => OP_UNARY_INVERT,
        3 => OP_UNARY_NOT,
        _ => return unsupported(),
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

#[allow(clippy::match_same_arms)]
fn binary_op(arg: &MpyArg, unsupported: &dyn Fn() -> Vec<Emitted>) -> Vec<Emitted> {
    let ord: u8 = match arg {
        MpyArg::BinaryOp(o) => *o,
        _ => return unsupported(),
    };
    if let Some((op, cmp_arg)) = compare_op_for(ord) {
        return vec![Emitted::Plain { op, arg: cmp_arg }];
    }
    let op: u8 = match ord {
        9 => OP_INPLACE_OR,
        10 => OP_INPLACE_XOR,
        11 => OP_INPLACE_AND,
        12 => OP_INPLACE_LSHIFT,
        13 => OP_INPLACE_RSHIFT,
        14 => OP_INPLACE_ADD,
        15 => OP_INPLACE_SUBTRACT,
        16 => OP_INPLACE_MULTIPLY,
        17 => OP_BINARY_MATRIX_MULTIPLY,
        18 => OP_INPLACE_FLOOR_DIVIDE,
        19 => OP_INPLACE_TRUE_DIVIDE,
        20 => OP_INPLACE_MODULO,
        21 => OP_INPLACE_POWER,
        22 => OP_BINARY_OR,
        23 => OP_BINARY_XOR,
        24 => OP_BINARY_AND,
        25 => OP_BINARY_LSHIFT,
        26 => OP_BINARY_RSHIFT,
        27 => OP_BINARY_ADD,
        28 => OP_BINARY_SUBTRACT,
        29 => OP_BINARY_MULTIPLY,
        30 => OP_BINARY_MATRIX_MULTIPLY,
        31 => OP_BINARY_FLOOR_DIVIDE,
        32 => OP_BINARY_TRUE_DIVIDE,
        33 => OP_BINARY_MODULO,
        34 => OP_BINARY_POWER,
        _ => return unsupported(),
    };
    vec![Emitted::Plain { op, arg: 0 }]
}

const OP_COMPARE_OP: u8 = 107;
const OP_IS_OP: u8 = 117;
const OP_CONTAINS_OP: u8 = 118;
const OP_RERAISE: u8 = 119;
const OP_JUMP_IF_NOT_EXC_MATCH: u8 = 121;

fn compare_op_for(ord: u8) -> Option<(u8, u32)> {
    match ord {
        0 => Some((OP_COMPARE_OP, 0)),
        1 => Some((OP_COMPARE_OP, 4)),
        2 => Some((OP_COMPARE_OP, 2)),
        3 => Some((OP_COMPARE_OP, 1)),
        4 => Some((OP_COMPARE_OP, 5)),
        5 => Some((OP_COMPARE_OP, 3)),
        6 => Some((OP_CONTAINS_OP, 0)),
        7 => Some((OP_IS_OP, 0)),
        _ => None,
    }
}

fn assemble(emitted: &[(usize, Emitted)]) -> Result<(Vec<u8>, Vec<u8>)> {
    for (_, e) in emitted {
        if let Emitted::Unsupported { mnemonic } = e {
            return Err(DecompileError::UnsupportedRuntime {
                runtime: format!("micropython opcode not modeled: {mnemonic}"),
            });
        }
    }

    let mut lengths: Vec<u32> = emitted
        .iter()
        .map(|(_, e): &(usize, Emitted)| -> u32 { instr_byte_len(non_jump_arg(e)) })
        .collect();

    let mut resolved_args: Vec<u32> = vec![0u32; emitted.len()];
    for _ in 0..16 {
        let (byte_for_index, end_byte): (Vec<u32>, u32) = layout(&lengths);
        let mp_to_byte: BTreeMap<usize, u32> = build_mp_map(emitted, &byte_for_index);
        let resolve_target = |mp_target: usize| -> u32 {
            mp_to_byte
                .range(mp_target..)
                .next()
                .map_or(end_byte, |(_, b): (&usize, &u32)| *b)
        };
        let mut changed: bool = false;
        for (i, (_, e)) in emitted.iter().enumerate() {
            let here: u32 = byte_for_index[i];
            let next: u32 = here.saturating_add(lengths[i]);
            let arg: u32 = match e {
                Emitted::Plain { arg, .. } => *arg,
                Emitted::JumpAbs { mp_target, .. } => resolve_target(*mp_target) / 2,
                Emitted::JumpRel { mp_target, .. } => {
                    resolve_target(*mp_target).saturating_sub(next) / 2
                }
                Emitted::Unsupported { .. } => 0,
            };
            resolved_args[i] = arg;
            let needed: u32 = instr_byte_len(arg);
            if needed > lengths[i] {
                lengths[i] = needed;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut code: Vec<u8> = Vec::with_capacity(emitted.len() * 2);
    for (i, (_, e)) in emitted.iter().enumerate() {
        let op: u8 = match e {
            Emitted::Plain { op, .. }
            | Emitted::JumpAbs { op, .. }
            | Emitted::JumpRel { op, .. } => *op,
            Emitted::Unsupported { .. } => OP_NOP,
        };
        emit_wordcode_padded(&mut code, op, resolved_args[i], lengths[i]);
    }
    let lnotab: Vec<u8> = single_line_lnotab(code.len());
    Ok((code, lnotab))
}

fn layout(lengths: &[u32]) -> (Vec<u32>, u32) {
    let mut byte_for_index: Vec<u32> = Vec::with_capacity(lengths.len());
    let mut cursor: u32 = 0;
    for &len in lengths {
        byte_for_index.push(cursor);
        cursor = cursor.saturating_add(len);
    }
    (byte_for_index, cursor)
}

fn build_mp_map(emitted: &[(usize, Emitted)], byte_for_index: &[u32]) -> BTreeMap<usize, u32> {
    let mut mp_to_byte: BTreeMap<usize, u32> = BTreeMap::new();
    for (i, (mp_off, _)) in emitted.iter().enumerate() {
        mp_to_byte.entry(*mp_off).or_insert(byte_for_index[i]);
    }
    mp_to_byte
}

const fn non_jump_arg(e: &Emitted) -> u32 {
    match e {
        Emitted::Plain { arg, .. } => *arg,
        Emitted::JumpAbs { .. } | Emitted::JumpRel { .. } | Emitted::Unsupported { .. } => 0,
    }
}

const fn instr_byte_len(arg: u32) -> u32 {
    if arg > 0x00FF_FFFF {
        8
    } else if arg > 0x0000_FFFF {
        6
    } else if arg > 0x0000_00FF {
        4
    } else {
        2
    }
}

fn emit_wordcode_padded(code: &mut Vec<u8>, op: u8, arg: u32, byte_len: u32) {
    let len: u32 = byte_len.max(instr_byte_len(arg));
    if len >= 8 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 24) & 0xFF).unwrap_or(0));
    }
    if len >= 6 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 16) & 0xFF).unwrap_or(0));
    }
    if len >= 4 {
        code.push(OP_EXTENDED_ARG);
        code.push(u8::try_from((arg >> 8) & 0xFF).unwrap_or(0));
    }
    code.push(op);
    code.push(u8::try_from(arg & 0xFF).unwrap_or(0));
}

fn single_line_lnotab(code_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut remaining: usize = code_len;
    while remaining > 0 {
        let chunk: u8 = u8::try_from(remaining.min(254)).unwrap_or(254);
        out.push(chunk);
        out.push(0);
        remaining -= usize::from(chunk);
    }
    out
}

fn code_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => "<anonymous>".to_owned(),
    }
}

fn qstr_text(arg: &MpyArg) -> String {
    match arg {
        MpyArg::Qstr { text, .. } => text.clone(),
        _ => "<qstr?>".to_owned(),
    }
}

fn qstr_str_const(arg: &MpyArg) -> Object {
    match arg {
        MpyArg::Qstr { text, .. } => short_ascii(text),
        _ => Object::None,
    }
}

fn small_int_value(arg: &MpyArg) -> i64 {
    match arg {
        MpyArg::SmallInt(v) => *v,
        MpyArg::Uint(v) => i64::try_from(*v).unwrap_or(0),
        _ => 0,
    }
}

fn uint_arg(arg: &MpyArg) -> u32 {
    match arg {
        MpyArg::Uint(v) => u32::try_from(*v).unwrap_or(u32::MAX),
        MpyArg::SmallInt(v) => u32::try_from(*v).unwrap_or(0),
        _ => 0,
    }
}

const MAX_SLOT_INDEX: u32 = 1 << 16;

fn slot_access(arg: &MpyArg, scope: &mut Scope, local_op: u8, cell_op: u8) -> Result<Vec<Emitted>> {
    let slot: usize = slot_of(arg);
    if slot >= usize::try_from(MAX_SLOT_INDEX).unwrap_or(usize::MAX) {
        return Err(DecompileError::Emit {
            reason: format!("local slot index {slot} exceeds the {MAX_SLOT_INDEX} local-slot cap"),
        });
    }
    if let Some(cell) = scope.deref_index(slot) {
        return Ok(vec![Emitted::Plain {
            op: cell_op,
            arg: cell,
        }]);
    }
    Ok(vec![Emitted::Plain {
        op: local_op,
        arg: scope.local_index(slot)?,
    }])
}

fn cell_access(arg: &MpyArg, scope: &Scope) -> Result<u32> {
    let slot: usize = slot_of(arg);
    scope.deref_index(slot).ok_or_else(|| DecompileError::Emit {
        reason: format!("LOAD/STORE_DEREF cell slot {slot} has no cell mapping in this scope"),
    })
}

fn object_const(arg: &MpyArg, module: &MpyBytecodeModule) -> Object {
    let idx: usize = match arg {
        MpyArg::Object { index } => usize::try_from(*index).unwrap_or(usize::MAX),
        _ => usize::MAX,
    };
    module
        .typed_objects
        .get(idx)
        .map_or(Object::None, mpy_object_to_marshal)
}

#[allow(clippy::match_same_arms)]
fn mpy_object_to_marshal(obj: &MpyObject) -> Object {
    match obj {
        MpyObject::None | MpyObject::FunTable => Object::None,
        MpyObject::False => Object::False,
        MpyObject::True => Object::True,
        MpyObject::Ellipsis => Object::Ellipsis,
        MpyObject::Str(s) => short_ascii(s),
        MpyObject::Bytes(b) => Object::Bytes(b.clone()),
        MpyObject::Int(s) => s
            .trim()
            .parse::<i64>()
            .map_or_else(|_| short_ascii(s), int_object),
        MpyObject::Float(s) => s
            .trim()
            .parse::<f64>()
            .map_or_else(|_| short_ascii(s), Object::Float),
        MpyObject::Complex(s) => short_ascii(s),
        MpyObject::Tuple(items) => Object::Tuple(items.iter().map(mpy_object_to_marshal).collect()),
    }
}

fn int_object(v: i64) -> Object {
    i32::try_from(v).map_or(Object::Int64(v), Object::Int)
}

fn short_ascii(s: &str) -> Object {
    Object::ShortAscii {
        value: s.to_owned(),
        interned: false,
    }
}

#[derive(Debug)]
struct ConstPool {
    entries: Vec<Object>,
}

impl ConstPool {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn intern(&mut self, value: Object) -> u32 {
        if let Some(pos) = self.entries.iter().position(|e: &Object| *e == value) {
            return u32::try_from(pos).unwrap_or(0);
        }
        let idx: u32 = u32::try_from(self.entries.len()).unwrap_or(0);
        self.entries.push(value);
        idx
    }

    fn into_objects(self) -> Vec<Object> {
        self.entries
    }
}

#[derive(Debug)]
struct NamePool {
    entries: Vec<String>,
}

impl NamePool {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(pos) = self.entries.iter().position(|e: &String| e == name) {
            return u32::try_from(pos).unwrap_or(0);
        }
        let idx: u32 = u32::try_from(self.entries.len()).unwrap_or(0);
        self.entries.push(name.to_owned());
        idx
    }

    fn push_unique(&mut self, name: &str) -> u32 {
        let idx: u32 = u32::try_from(self.entries.len()).unwrap_or(0);
        let mut candidate: String = name.to_owned();
        let mut suffix: usize = 1;
        while self.entries.contains(&candidate) {
            candidate = format!("{name}_{suffix}");
            suffix = suffix.saturating_add(1);
        }
        self.entries.push(candidate);
        idx
    }

    fn into_objects(self) -> Vec<Object> {
        self.entries
            .into_iter()
            .map(|s: String| short_ascii(&s))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn function_with_args(arg_names: &[&str], n_pos_args: u32) -> MpyFunction {
        MpyFunction {
            simple_name: "probe".to_owned(),
            arg_names: arg_names.iter().map(|s: &&str| (*s).to_owned()).collect(),
            n_state: 4,
            n_exc_stack: 0,
            scope_flags: 0,
            n_pos_args,
            n_kwonly_args: 0,
            n_def_pos_args: 0,
            instructions: Vec::new(),
            children: Vec::new(),
        }
    }

    fn scope_of(func: &MpyFunction, free_names: &[String]) -> Scope {
        let facts: ScopeFacts = scan_scope(func, free_names.len());
        build_scope(func, free_names, &facts, None).unwrap()
    }

    #[test]
    fn slot_access_caps_index_and_does_not_balloon_the_pool() {
        let func: MpyFunction = function_with_args(&[], 0);
        let mut scope: Scope = scope_of(&func, &[]);
        let err: DecompileError =
            slot_access(&MpyArg::Uint(u64::from(u32::MAX)), &mut scope, 0, 0).unwrap_err();
        assert!(
            matches!(err, DecompileError::Emit { .. }),
            "an out-of-range fast slot must be a bounded Emit error, got {err:?}"
        );
        assert!(
            scope.varnames.entries.len() < MAX_SLOT_INDEX as usize,
            "the rejected slot must not have grown the name pool: {}",
            scope.varnames.entries.len()
        );
    }

    #[test]
    fn slot_access_at_cap_boundary_rejects() {
        let func: MpyFunction = function_with_args(&[], 0);
        let mut scope: Scope = scope_of(&func, &[]);
        assert!(slot_access(&MpyArg::Uint(u64::from(MAX_SLOT_INDEX)), &mut scope, 0, 0).is_err());
        assert!(scope.varnames.entries.is_empty());
    }

    #[test]
    fn an_undeclared_slot_gets_its_own_generated_local_name() {
        let func: MpyFunction = function_with_args(&["items"], 1);
        let mut scope: Scope = scope_of(&func, &[]);
        assert_eq!(scope.local_index(3).unwrap(), 1);
        assert_eq!(
            scope.varnames.entries,
            vec!["items".to_owned(), "local3".to_owned()]
        );
    }

    #[test]
    fn a_free_slot_resolves_to_a_deref_index_past_the_cells() {
        let func: MpyFunction = function_with_args(&["", "x"], 2);
        let scope: Scope = scope_of(&func, &["base".to_owned()]);
        assert_eq!(scope.freevars, vec!["base".to_owned()]);
        assert_eq!(scope.deref_index(0), Some(0));
        assert_eq!(
            scope.varnames.entries,
            vec!["x".to_owned()],
            "the closure cell prefix must not become a parameter"
        );
    }

    #[test]
    fn declared_parameter_names_seed_the_local_slots() {
        let func: MpyFunction = function_with_args(&["items", "step"], 2);
        let scope: Scope = scope_of(&func, &[]);
        assert_eq!(
            scope.varnames.entries,
            vec!["items".to_owned(), "step".to_owned()]
        );
    }

    #[test]
    fn a_parameter_name_that_is_not_a_usable_identifier_falls_back_to_its_position() {
        let func: MpyFunction = function_with_args(&["class", "<qstr#9>", "9lives", ""], 4);
        let scope: Scope = scope_of(&func, &[]);
        assert_eq!(
            scope.varnames.entries,
            vec![
                "arg0".to_owned(),
                "arg1".to_owned(),
                "arg2".to_owned(),
                "arg3".to_owned()
            ]
        );
    }

    #[test]
    fn a_parameter_named_like_a_generated_slot_never_collapses_two_slots() {
        let func: MpyFunction = function_with_args(&["local1", "local1"], 2);
        let mut scope: Scope = scope_of(&func, &[]);
        assert_eq!(scope.local_index(3).unwrap(), 2);
        assert_eq!(
            scope.varnames.entries.len(),
            3,
            "every slot must own a distinct name"
        );
        let mut seen: Vec<&String> = scope.varnames.entries.iter().collect();
        seen.sort();
        seen.dedup();
        assert_eq!(
            seen.len(),
            3,
            "slot names collided: {:?}",
            scope.varnames.entries
        );
    }

    #[test]
    fn an_absurd_declared_parameter_count_is_rejected_before_seeding() {
        let func: MpyFunction = function_with_args(&[], u32::MAX);
        let facts: ScopeFacts = scan_scope(&func, 0);
        let err: DecompileError = build_scope(&func, &[], &facts, None).unwrap_err();
        assert!(matches!(err, DecompileError::Emit { .. }), "got {err:?}");
    }

    #[test]
    fn star_argument_slots_are_seeded_from_the_prelude_scope_flags() {
        let mut func: MpyFunction = function_with_args(&["a"], 1);
        func.scope_flags = MP_SCOPE_FLAG_VARARGS | MP_SCOPE_FLAG_VARKEYWORDS;
        let scope: Scope = scope_of(&func, &[]);
        assert_eq!(
            scope.varnames.entries,
            vec![
                "a".to_owned(),
                VARARGS_SLOT_NAME.to_owned(),
                VARKEYWORDS_SLOT_NAME.to_owned()
            ]
        );
        assert_eq!(scope.local_of_slot.get(&1), Some(&1));
        assert_eq!(scope.local_of_slot.get(&2), Some(&2));
    }
}
