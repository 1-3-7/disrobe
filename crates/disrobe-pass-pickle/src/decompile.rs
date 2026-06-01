use crate::vm::PickleValue;

#[must_use]
pub fn to_python(value: &PickleValue) -> String {
    let mut out: String = String::new();
    render(value, &mut out);
    out
}

#[must_use]
pub fn to_python_assignment(value: &PickleValue) -> String {
    format!("result = {}\n", to_python(value))
}

fn render(value: &PickleValue, out: &mut String) {
    match value {
        PickleValue::None => out.push_str("None"),
        PickleValue::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
        PickleValue::Int(v) => out.push_str(&v.to_string()),
        PickleValue::BigInt(s) => out.push_str(s),
        PickleValue::Float(v) => render_float(*v, out),
        PickleValue::Str(s) => out.push_str(&py_repr_str(s)),
        PickleValue::Bytes(b) => out.push_str(&py_repr_bytes(b)),
        PickleValue::List(items) => render_seq(items, "[", "]", out),
        PickleValue::Tuple(items) => render_tuple(items, out),
        PickleValue::Set(items) => render_set("{", items, "}", out, "set()"),
        PickleValue::FrozenSet(items) => {
            out.push_str("frozenset(");
            render_seq(items, "[", "]", out);
            out.push(')');
        }
        PickleValue::Dict(pairs) => render_dict(pairs, out),
        PickleValue::Global { module, name } => {
            out.push_str(&format!("{module}.{name}"));
        }
        PickleValue::Ext { code } => out.push_str(&format!("copyreg._inverted_registry[{code}]")),
        PickleValue::PersId { id } => {
            out.push_str("persistent_load(");
            render(id, out);
            out.push(')');
        }
        PickleValue::Reduce { callable, args } => {
            render(callable, out);
            render_call_args(args, out);
        }
        PickleValue::Object { cls, args, state } => render_object(cls, args, state.as_deref(), out),
        PickleValue::MemoRef { key } => out.push_str(&format!("memo[{key}]")),
    }
}

fn render_object(
    cls: &PickleValue,
    args: &PickleValue,
    state: Option<&PickleValue>,
    out: &mut String,
) {
    out.push_str("__build__(");
    render(cls, out);
    out.push_str(", args=");
    render(args, out);
    if let Some(s) = state {
        out.push_str(", state=");
        render(s, out);
    }
    out.push(')');
}

fn render_call_args(args: &PickleValue, out: &mut String) {
    match args {
        PickleValue::Tuple(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(')');
        }
        other => {
            out.push('(');
            out.push('*');
            render(other, out);
            out.push(')');
        }
    }
}

fn render_seq(items: &[PickleValue], open: &str, close: &str, out: &mut String) {
    out.push_str(open);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(item, out);
    }
    out.push_str(close);
}

fn render_tuple(items: &[PickleValue], out: &mut String) {
    out.push('(');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(item, out);
    }
    if items.len() == 1 {
        out.push(',');
    }
    out.push(')');
}

fn render_set(open: &str, items: &[PickleValue], close: &str, out: &mut String, empty: &str) {
    if items.is_empty() {
        out.push_str(empty);
        return;
    }
    render_seq(items, open, close, out);
}

fn render_dict(pairs: &[(PickleValue, PickleValue)], out: &mut String) {
    out.push('{');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        render(k, out);
        out.push_str(": ");
        render(v, out);
    }
    out.push('}');
}

fn render_float(v: f64, out: &mut String) {
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

fn py_repr_str(s: &str) -> String {
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

fn py_repr_bytes(b: &[u8]) -> String {
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
}
