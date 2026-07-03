use std::collections::{BTreeMap, BTreeSet};

use crate::decompile::{py_repr_bytes, py_repr_str, render_float};
use crate::vm::{ObjCtor, PickleValue};

const PREAMBLE: &str = "def _apply_state(obj, state):\n    if state is None:\n        return obj\n    setstate = getattr(obj, \"__setstate__\", None)\n    if setstate is not None:\n        setstate(state)\n        return obj\n    slotstate = None\n    if isinstance(state, tuple) and len(state) == 2:\n        state, slotstate = state\n    if state:\n        obj.__dict__.update(state)\n    if slotstate:\n        for _k, _v in slotstate.items():\n            setattr(obj, _k, _v)\n    return obj\n\n\ndef _unsupported(reason):\n    raise RuntimeError(\"disrobe: unreconstructable pickle shape: \" + reason)\n";

const MAX_CYCLE_TARGETS: usize = 4_096;

include!("compat_pickle.rs");

/// Translate a legacy Python-2 `(module, name)` global to its Python-3 name.
fn map_global(module: &str, name: &str) -> (String, String) {
    if let Some(&(_, _, new_module, new_name)) = NAME_MAPPING
        .iter()
        .find(|(m, n, _, _): &&(&str, &str, &str, &str)| *m == module && *n == name)
    {
        return (new_module.to_owned(), new_name.to_owned());
    }
    if let Some(&(_, new_module)) = IMPORT_MAPPING
        .iter()
        .find(|(m, _): &&(&str, &str)| *m == module)
    {
        return (new_module.to_owned(), name.to_owned());
    }
    (module.to_owned(), name.to_owned())
}

/// A re-executable `Python` reconstruction of a pickle object graph.
#[derive(Debug, Clone)]
pub struct Reconstruction {
    pub program: String,
    pub reexecutable: bool,
    pub unsupported: Vec<String>,
}

struct Ctx<'a> {
    targets: Vec<(u64, &'a PickleValue)>,
}

impl Ctx<'_> {
    fn cycle_target(&self, node: &PickleValue) -> Option<u64> {
        self.targets
            .iter()
            .find_map(|(key, value): &(u64, &PickleValue)| (*value == node).then_some(*key))
    }
}

#[must_use]
pub fn reconstruct(value: &PickleValue, memo: &BTreeMap<u64, PickleValue>) -> Reconstruction {
    let mut needed: BTreeSet<u64> = BTreeSet::new();
    collect_needed(value, memo, &mut needed);

    let mut reexecutable: bool = true;
    let mut reasons: Vec<String> = Vec::new();

    for key in &needed {
        if !memo.contains_key(key) {
            reexecutable = false;
            reasons.push(format!(
                "memo key {key} referenced by a back-edge is absent"
            ));
        }
    }
    if needed.len() > MAX_CYCLE_TARGETS {
        reexecutable = false;
        reasons.push(format!(
            "cycle-target count {} exceeds reconstruction cap {MAX_CYCLE_TARGETS}",
            needed.len()
        ));
    }

    let mut modules: BTreeSet<String> = BTreeSet::new();
    scan(value, &mut modules, &mut reasons, &mut reexecutable);
    for key in &needed {
        if let Some(entry) = memo.get(key) {
            scan(entry, &mut modules, &mut reasons, &mut reexecutable);
        }
    }
    reasons.sort_unstable();
    reasons.dedup();

    let targets: Vec<(u64, &PickleValue)> = needed
        .iter()
        .filter_map(|key: &u64| memo.get(key).map(|value: &PickleValue| (*key, value)))
        .collect();
    let ctx: Ctx<'_> = Ctx { targets };

    let mut program: String = String::with_capacity(512);
    program.push_str(PREAMBLE);
    program.push('\n');
    for module in &modules {
        program.push_str(&format!("import {module}\n"));
    }
    program.push_str("_m = {}\n");

    emit_shells(&ctx, memo, &needed, &mut program);
    emit_fill(&ctx, memo, &needed, &mut program);

    let mut root: String = String::new();
    render(&ctx, value, &mut root);
    program.push_str(&format!("result = {root}\n"));

    Reconstruction {
        program,
        reexecutable,
        unsupported: reasons,
    }
}

fn emit_shells(
    ctx: &Ctx<'_>,
    memo: &BTreeMap<u64, PickleValue>,
    needed: &BTreeSet<u64>,
    program: &mut String,
) {
    for key in needed {
        if let Some(PickleValue::List(_)) = memo.get(key) {
            program.push_str(&format!("_m[{key}] = []\n"));
        } else if let Some(PickleValue::Dict(_)) = memo.get(key) {
            program.push_str(&format!("_m[{key}] = {{}}\n"));
        } else if let Some(PickleValue::Set(_)) = memo.get(key) {
            program.push_str(&format!("_m[{key}] = set()\n"));
        }
    }
    for key in needed {
        if let Some(PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            ..
        }) = memo.get(key)
        {
            let mut base: String = String::new();
            render_object_base(ctx, *ctor, cls, args, kwargs.as_deref(), &mut base);
            program.push_str(&format!("_m[{key}] = {base}\n"));
        }
    }
}

fn emit_fill(
    ctx: &Ctx<'_>,
    memo: &BTreeMap<u64, PickleValue>,
    needed: &BTreeSet<u64>,
    program: &mut String,
) {
    for key in needed {
        match memo.get(key) {
            Some(PickleValue::List(items)) if !items.is_empty() => {
                let mut body: String = String::new();
                render_seq_items(ctx, items, &mut body);
                program.push_str(&format!("_m[{key}].extend([{body}])\n"));
            }
            Some(PickleValue::Set(items)) if !items.is_empty() => {
                let mut body: String = String::new();
                render_seq_items(ctx, items, &mut body);
                program.push_str(&format!("_m[{key}].update([{body}])\n"));
            }
            Some(PickleValue::Dict(pairs)) => {
                for (dict_key, dict_val) in pairs {
                    let mut k: String = String::new();
                    let mut v: String = String::new();
                    render(ctx, dict_key, &mut k);
                    render(ctx, dict_val, &mut v);
                    program.push_str(&format!("_m[{key}][{k}] = {v}\n"));
                }
            }
            Some(PickleValue::Object {
                state: Some(state), ..
            }) => {
                let mut rendered: String = String::new();
                render(ctx, state, &mut rendered);
                program.push_str(&format!("_apply_state(_m[{key}], {rendered})\n"));
            }
            _ => {}
        }
    }
}

fn render(ctx: &Ctx<'_>, value: &PickleValue, out: &mut String) {
    if let PickleValue::MemoRef { key } = value {
        out.push_str(&format!("_m[{key}]"));
        return;
    }
    if is_target_kind(value)
        && let Some(key) = ctx.cycle_target(value)
    {
        out.push_str(&format!("_m[{key}]"));
        return;
    }
    match value {
        PickleValue::None => out.push_str("None"),
        PickleValue::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
        PickleValue::Int(v) => out.push_str(&v.to_string()),
        PickleValue::BigInt(s) => out.push_str(s),
        PickleValue::Float(v) => render_float(*v, out),
        PickleValue::Str(s) => out.push_str(&py_repr_str(s)),
        PickleValue::Bytes(b) => out.push_str(&py_repr_bytes(b)),
        PickleValue::List(items) => {
            out.push('[');
            render_seq_items(ctx, items, out);
            out.push(']');
        }
        PickleValue::Tuple(items) => {
            out.push('(');
            render_seq_items(ctx, items, out);
            if items.len() == 1 {
                out.push(',');
            }
            out.push(')');
        }
        PickleValue::Set(items) => {
            if items.is_empty() {
                out.push_str("set()");
            } else {
                out.push('{');
                render_seq_items(ctx, items, out);
                out.push('}');
            }
        }
        PickleValue::FrozenSet(items) => {
            out.push_str("frozenset([");
            render_seq_items(ctx, items, out);
            out.push_str("])");
        }
        PickleValue::Dict(pairs) => {
            out.push('{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(ctx, k, out);
                out.push_str(": ");
                render(ctx, v, out);
            }
            out.push('}');
        }
        PickleValue::Global { module, name } => {
            let (module, name): (String, String) = map_global(module, name);
            out.push_str(&format!("{module}.{name}"));
        }
        PickleValue::Reduce { callable, args } => render_call(ctx, callable, args, out),
        PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            state,
        } => {
            if state.is_some() {
                out.push_str("_apply_state(");
            }
            render_object_base(ctx, *ctor, cls, args, kwargs.as_deref(), out);
            if let Some(state) = state {
                out.push_str(", ");
                render(ctx, state, out);
                out.push(')');
            }
        }
        PickleValue::Ext { code } => {
            out.push_str(&format!(
                "_unsupported('EXT extension registry code {code}')"
            ));
        }
        PickleValue::OutOfBandBuffer { .. } => {
            out.push_str("_unsupported('out-of-band buffer')");
        }
        PickleValue::PersId { .. } => out.push_str("_unsupported('persistent id')"),
        PickleValue::MemoRef { .. } => {}
    }
}

fn render_object_base(
    ctx: &Ctx<'_>,
    ctor: ObjCtor,
    cls: &PickleValue,
    args: &PickleValue,
    kwargs: Option<&PickleValue>,
    out: &mut String,
) {
    match ctor {
        ObjCtor::NewObj | ObjCtor::NewObjEx => {
            render(ctx, cls, out);
            out.push_str(".__new__(");
            render(ctx, cls, out);
            render_positional_tail(ctx, args, out);
            if let Some(kw) = kwargs {
                out.push_str(", **");
                render(ctx, kw, out);
            }
            out.push(')');
        }
        ObjCtor::Reduce | ObjCtor::Inst | ObjCtor::Obj => {
            render(ctx, cls, out);
            render_call_args(ctx, args, out);
        }
    }
}

fn render_call(ctx: &Ctx<'_>, callable: &PickleValue, args: &PickleValue, out: &mut String) {
    render(ctx, callable, out);
    render_call_args(ctx, args, out);
}

fn render_call_args(ctx: &Ctx<'_>, args: &PickleValue, out: &mut String) {
    match args {
        PickleValue::Tuple(items) => {
            out.push('(');
            render_seq_items(ctx, items, out);
            out.push(')');
        }
        other => {
            out.push_str("(*");
            render(ctx, other, out);
            out.push(')');
        }
    }
}

fn render_positional_tail(ctx: &Ctx<'_>, args: &PickleValue, out: &mut String) {
    match args {
        PickleValue::Tuple(items) => {
            for item in items {
                out.push_str(", ");
                render(ctx, item, out);
            }
        }
        other => {
            out.push_str(", *");
            render(ctx, other, out);
        }
    }
}

fn render_seq_items(ctx: &Ctx<'_>, items: &[PickleValue], out: &mut String) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(ctx, item, out);
    }
}

#[inline]
fn is_target_kind(value: &PickleValue) -> bool {
    matches!(
        value,
        PickleValue::List(_)
            | PickleValue::Dict(_)
            | PickleValue::Set(_)
            | PickleValue::Object { .. }
    )
}

fn collect_needed(
    value: &PickleValue,
    memo: &BTreeMap<u64, PickleValue>,
    needed: &mut BTreeSet<u64>,
) {
    let mut work: Vec<u64> = Vec::new();
    collect_refs(value, &mut work);
    while let Some(key) = work.pop() {
        if needed.insert(key)
            && let Some(entry) = memo.get(&key)
        {
            collect_refs(entry, &mut work);
        }
    }
}

fn collect_refs(value: &PickleValue, out: &mut Vec<u64>) {
    match value {
        PickleValue::MemoRef { key } => out.push(*key),
        PickleValue::List(items)
        | PickleValue::Tuple(items)
        | PickleValue::Set(items)
        | PickleValue::FrozenSet(items) => {
            for item in items {
                collect_refs(item, out);
            }
        }
        PickleValue::Dict(pairs) => {
            for (k, v) in pairs {
                collect_refs(k, out);
                collect_refs(v, out);
            }
        }
        PickleValue::PersId { id } => collect_refs(id, out),
        PickleValue::Reduce { callable, args } => {
            collect_refs(callable, out);
            collect_refs(args, out);
        }
        PickleValue::Object {
            cls,
            args,
            kwargs,
            state,
            ..
        } => {
            collect_refs(cls, out);
            collect_refs(args, out);
            if let Some(kwargs) = kwargs {
                collect_refs(kwargs, out);
            }
            if let Some(state) = state {
                collect_refs(state, out);
            }
        }
        _ => {}
    }
}

fn scan(
    value: &PickleValue,
    modules: &mut BTreeSet<String>,
    reasons: &mut Vec<String>,
    ok: &mut bool,
) {
    match value {
        PickleValue::Global { module, name } => {
            if module.is_empty() {
                *ok = false;
                reasons.push(format!("global {name} has no importable module"));
            } else {
                let (mapped, _): (String, String) = map_global(module, name);
                modules.insert(mapped);
            }
        }
        PickleValue::Ext { code } => {
            *ok = false;
            reasons.push(format!(
                "EXT extension code {code} resolves only via the runtime copyreg registry"
            ));
        }
        PickleValue::OutOfBandBuffer { .. } => {
            *ok = false;
            reasons.push("out-of-band buffer payload is not carried in the stream".to_owned());
        }
        PickleValue::PersId { id } => {
            *ok = false;
            reasons.push("persistent id requires a runtime persistent_load".to_owned());
            scan(id, modules, reasons, ok);
        }
        PickleValue::List(items)
        | PickleValue::Tuple(items)
        | PickleValue::Set(items)
        | PickleValue::FrozenSet(items) => {
            for item in items {
                scan(item, modules, reasons, ok);
            }
        }
        PickleValue::Dict(pairs) => {
            for (k, v) in pairs {
                scan(k, modules, reasons, ok);
                scan(v, modules, reasons, ok);
            }
        }
        PickleValue::Reduce { callable, args } => {
            scan(callable, modules, reasons, ok);
            scan(args, modules, reasons, ok);
        }
        PickleValue::Object {
            cls,
            args,
            kwargs,
            state,
            ..
        } => {
            if !is_constructible(cls) {
                *ok = false;
                reasons.push("BUILD applied to a non-constructible target".to_owned());
            }
            scan(cls, modules, reasons, ok);
            scan(args, modules, reasons, ok);
            if let Some(kwargs) = kwargs {
                scan(kwargs, modules, reasons, ok);
            }
            if let Some(state) = state {
                scan(state, modules, reasons, ok);
            }
        }
        _ => {}
    }
}

#[inline]
fn is_constructible(cls: &PickleValue) -> bool {
    matches!(
        cls,
        PickleValue::Global { .. } | PickleValue::Reduce { .. } | PickleValue::Object { .. }
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::disasm::{Disassembly, disassemble};
    use crate::vm::Session;

    fn build(bytes: &[u8]) -> Reconstruction {
        let dis: Disassembly = disassemble(bytes).expect("disasm");
        let mut session: Session = Session::new();
        let result: PickleValue = session.run(&dis).expect("vm");
        reconstruct(&result, session.memo())
    }

    #[test]
    fn primitive_int_is_reexecutable() {
        let r: Reconstruction = build(b"\x80\x02K\x2a.");
        assert!(r.reexecutable);
        assert!(r.program.contains("result = 42"));
    }

    #[test]
    fn self_referential_list_two_phase() {
        let r: Reconstruction = build(b"\x80\x02]q\x00h\x00a.");
        assert!(r.reexecutable, "cyclic list must stay reexecutable");
        assert!(r.program.contains("_m[0] = []"));
        assert!(r.program.contains("_m[0].extend([_m[0]])"));
        assert!(r.program.contains("result = _m[0]"));
    }

    #[test]
    fn ext_code_is_marked_unsupported() {
        let r: Reconstruction = build(b"\x80\x02\x82\x10.");
        assert!(!r.reexecutable);
        assert!(!r.unsupported.is_empty());
    }

    #[test]
    fn global_reference_imports_module() {
        let r: Reconstruction =
            build(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x94.");
        assert!(r.reexecutable);
        assert!(r.program.contains("import os"));
        assert!(r.program.contains("result = os.system"));
    }
}
