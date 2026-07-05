use crate::vm::{ObjCtor, PickleValue};

const MAX_RENDER_DEPTH: u32 = 2_048;
const RENDER_DEPTH_MARKER: &str = "<max-depth>";

#[must_use]
pub fn to_python(value: &PickleValue) -> String {
    let mut out: String = String::new();
    render(value, 0, &mut out);
    out
}

#[must_use]
pub fn to_python_assignment(value: &PickleValue) -> String {
    format!("result = {}\n", to_python(value))
}

fn render(value: &PickleValue, depth: u32, out: &mut String) {
    if depth >= MAX_RENDER_DEPTH {
        out.push_str(RENDER_DEPTH_MARKER);
        return;
    }
    let child: u32 = depth + 1;
    match value {
        PickleValue::None => out.push_str("None"),
        PickleValue::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
        PickleValue::Int(v) => out.push_str(&v.to_string()),
        PickleValue::BigInt(s) => out.push_str(s),
        PickleValue::Float(v) => render_float(*v, out),
        PickleValue::Str(s) => out.push_str(&py_repr_str(s)),
        PickleValue::Bytes(b) => out.push_str(&py_repr_bytes(b)),
        PickleValue::List(items) => render_seq(items, "[", "]", child, out),
        PickleValue::Tuple(items) => render_tuple(items, child, out),
        PickleValue::Set(items) => render_set("{", items, "}", child, out, "set()"),
        PickleValue::FrozenSet(items) => {
            out.push_str("frozenset(");
            render_seq(items, "[", "]", child, out);
            out.push(')');
        }
        PickleValue::Dict(pairs) => render_dict(pairs, child, out),
        PickleValue::Global { module, name } => {
            out.push_str(&format!("{module}.{name}"));
        }
        PickleValue::Ext { code } => out.push_str(&format!("copyreg._inverted_registry[{code}]")),
        PickleValue::OutOfBandBuffer { readonly } => {
            out.push_str(if *readonly {
                "<out-of-band readonly buffer>"
            } else {
                "<out-of-band buffer>"
            });
        }
        PickleValue::PersId { id } => {
            out.push_str("persistent_load(");
            render(id, child, out);
            out.push(')');
        }
        PickleValue::Reduce { callable, args } => {
            render(callable, child, out);
            render_call_args(args, child, out);
        }
        PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            state,
            listitems,
            dictitems,
        } => {
            render_object(
                *ctor,
                cls,
                args,
                kwargs.as_deref(),
                state.as_deref(),
                listitems,
                dictitems,
                child,
                out,
            );
        }
        PickleValue::MemoRef { key } => out.push_str(&format!("_m[{key}]")),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_object(
    ctor: ObjCtor,
    cls: &PickleValue,
    args: &PickleValue,
    kwargs: Option<&PickleValue>,
    state: Option<&PickleValue>,
    listitems: &[PickleValue],
    dictitems: &[(PickleValue, PickleValue)],
    depth: u32,
    out: &mut String,
) {
    let mut expr: String = String::new();
    match ctor {
        ObjCtor::NewObj | ObjCtor::NewObjEx => {
            render(cls, depth, &mut expr);
            expr.push_str(".__new__(");
            render(cls, depth, &mut expr);
            render_positional_tail(args, depth, &mut expr);
            if let Some(kw) = kwargs {
                expr.push_str(", **");
                render(kw, depth, &mut expr);
            }
            expr.push(')');
        }
        ObjCtor::Reduce | ObjCtor::Inst | ObjCtor::Obj => {
            render(cls, depth, &mut expr);
            render_call_args(args, depth, &mut expr);
        }
    }
    if !listitems.is_empty() {
        let mut body: String = String::new();
        render_seq(listitems, "[", "]", depth, &mut body);
        expr = format!("_extend({expr}, {body})");
    }
    if !dictitems.is_empty() {
        let mut body: String = String::new();
        render_pair_tuples(dictitems, depth, &mut body);
        expr = format!("_setitems({expr}, [{body}])");
    }
    if let Some(s) = state {
        let mut rendered: String = String::new();
        render(s, depth, &mut rendered);
        expr = format!("_apply_state({expr}, {rendered})");
    }
    out.push_str(&expr);
}

fn render_pair_tuples(pairs: &[(PickleValue, PickleValue)], depth: u32, out: &mut String) {
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('(');
        render(k, depth, out);
        out.push_str(", ");
        render(v, depth, out);
        out.push(')');
    }
}

fn render_positional_tail(args: &PickleValue, depth: u32, out: &mut String) {
    match args {
        PickleValue::Tuple(items) => {
            for item in items {
                out.push_str(", ");
                render(item, depth, out);
            }
        }
        other => {
            out.push_str(", *");
            render(other, depth, out);
        }
    }
}

fn render_call_args(args: &PickleValue, depth: u32, out: &mut String) {
    match args {
        PickleValue::Tuple(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, depth, out);
            }
            out.push(')');
        }
        other => {
            out.push('(');
            out.push('*');
            render(other, depth, out);
            out.push(')');
        }
    }
}

fn render_seq(items: &[PickleValue], open: &str, close: &str, depth: u32, out: &mut String) {
    out.push_str(open);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(item, depth, out);
    }
    out.push_str(close);
}

fn render_tuple(items: &[PickleValue], depth: u32, out: &mut String) {
    out.push('(');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(item, depth, out);
    }
    if items.len() == 1 {
        out.push(',');
    }
    out.push(')');
}

fn render_set(
    open: &str,
    items: &[PickleValue],
    close: &str,
    depth: u32,
    out: &mut String,
    empty: &str,
) {
    if items.is_empty() {
        out.push_str(empty);
        return;
    }
    render_seq(items, open, close, depth, out);
}

fn render_dict(pairs: &[(PickleValue, PickleValue)], depth: u32, out: &mut String) {
    out.push('{');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(k, depth, out);
        out.push_str(": ");
        render(v, depth, out);
    }
    out.push('}');
}

pub(crate) fn render_float(v: f64, out: &mut String) {
    if v.is_nan() {
        out.push_str("float('nan')");
    } else if v.is_infinite() {
        out.push_str(if v > 0.0 {
            "float('inf')"
        } else {
            "float('-inf')"
        });
    } else if v.fract() == 0.0 && v.abs() < 1e16 {
        out.push_str(&format!("{v:.1}"));
    } else {
        out.push_str(&v.to_string());
    }
}

pub(crate) fn py_repr_str(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

pub(crate) fn py_repr_bytes(b: &[u8]) -> String {
    let mut out: String = String::with_capacity(b.len() + 3);
    out.push_str("b'");
    for &byte in b {
        match byte {
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn renders_primitives() {
        assert_eq!(to_python(&PickleValue::None), "None");
        assert_eq!(to_python(&PickleValue::Bool(true)), "True");
        assert_eq!(to_python(&PickleValue::Int(42)), "42");
        assert_eq!(to_python(&PickleValue::Str("hi".into())), "'hi'");
    }

    #[test]
    fn renders_single_tuple_trailing_comma() {
        let v: PickleValue = PickleValue::Tuple(vec![PickleValue::Int(1)]);
        assert_eq!(to_python(&v), "(1,)");
    }

    #[test]
    fn renders_reduce_as_call() {
        let v: PickleValue = PickleValue::Reduce {
            callable: Box::new(PickleValue::Global {
                module: "os".into(),
                name: "system".into(),
            }),
            args: Box::new(PickleValue::Tuple(vec![PickleValue::Str("id".into())])),
        };
        assert_eq!(to_python(&v), "os.system('id')");
    }

    #[test]
    fn renders_dict() {
        let v: PickleValue =
            PickleValue::Dict(vec![(PickleValue::Str("k".into()), PickleValue::Int(1))]);
        assert_eq!(to_python(&v), "{'k': 1}");
    }

    #[test]
    fn renders_empty_set() {
        assert_eq!(to_python(&PickleValue::Set(vec![])), "set()");
    }

    #[test]
    fn render_stays_bounded_on_deeply_nested_value() {
        let mut value: PickleValue = PickleValue::Int(0);
        for _ in 0..(MAX_RENDER_DEPTH as usize + 5_000) {
            value = PickleValue::List(vec![value]);
        }
        let out: String = to_python(&value);
        assert!(
            out.contains(RENDER_DEPTH_MARKER),
            "a value past the render cap must emit the truncation marker, not overflow"
        );
        assert!(
            out.matches('[').count() <= MAX_RENDER_DEPTH as usize,
            "render must stop descending at the depth cap"
        );
    }
}
