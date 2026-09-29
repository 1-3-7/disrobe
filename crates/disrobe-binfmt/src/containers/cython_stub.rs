use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::cython::{CythonClass, CythonFunction, CythonModule};

const MAX_STUB_BYTES: usize = 4 * 1024 * 1024;

#[must_use]
pub fn render_cython_stub(module: &CythonModule) -> String {
    let mut out: String = String::new();
    let sources: String = if module.source_files.is_empty() {
        "no source file name survived".to_owned()
    } else {
        format!("compiled from {}", module.source_files.join(", "))
    };
    let _ = writeln!(
        out,
        "\"\"\"Import surface of the Cython extension `{}` ({sources}), recovered from its compiled method and type tables.\"\"\"",
        python_text(&module.module_name)
    );

    let mut methods_by_class: BTreeMap<String, Vec<&CythonFunction>> = BTreeMap::new();
    let mut top_level: Vec<&CythonFunction> = Vec::new();
    for function in &module.functions {
        match method_owner(function) {
            Some(owner) => methods_by_class.entry(owner).or_default().push(function),
            None => top_level.push(function),
        }
    }
    let mut classes: Vec<CythonClass> = module.classes.clone();
    for owner in methods_by_class.keys() {
        if !classes.iter().any(|c: &CythonClass| &c.name == owner) {
            classes.push(CythonClass {
                name: owner.clone(),
                doc: None,
                methods: Vec::new(),
                type_symbol: None,
            });
        }
    }

    for function in top_level {
        out.push('\n');
        render_function(&mut out, function, "");
        if out.len() > MAX_STUB_BYTES {
            return out;
        }
    }
    for class in &classes {
        out.push('\n');
        render_class(
            &mut out,
            class,
            methods_by_class
                .get(class.name.as_str())
                .map_or(&[], Vec::as_slice),
        );
        if out.len() > MAX_STUB_BYTES {
            return out;
        }
    }
    out
}

fn method_owner(function: &CythonFunction) -> Option<String> {
    if let Some((owner, _)) = function
        .qualname
        .as_deref()
        .and_then(|q: &str| q.rsplit_once('.'))
    {
        return Some(owner.to_owned());
    }
    let first: &str = function.doc.as_deref()?.lines().next()?;
    let (owner, rest): (&str, &str) = first.split_once('.')?;
    (!owner.is_empty()
        && owner.chars().all(|c: char| c.is_alphanumeric() || c == '_')
        && rest.starts_with(&format!("{}(", function.name)))
    .then(|| owner.to_owned())
}

fn render_class(out: &mut String, class: &CythonClass, methods: &[&CythonFunction]) {
    let _ = writeln!(out, "class {}:", python_identifier(&class.name));
    let (init_params, doc): (Option<String>, Option<String>) =
        class.doc.as_deref().map_or((None, None), |d: &str| {
            split_embedded_signature(d, &class.name)
        });
    let doc: Option<String> = doc.filter(|d: &String| !d.trim().is_empty());
    if let Some(doc) = &doc {
        write_docstring(out, doc, "    ");
    }
    if let Some(params) = &init_params {
        let _ = writeln!(
            out,
            "    def __init__({}) -> None: ...",
            method_parameters(params)
        );
    }
    for method in methods {
        render_function(out, method, "    ");
    }
    let extras: Vec<&String> = class
        .methods
        .iter()
        .filter(|name: &&String| {
            *name != "__init__" && !methods.iter().any(|m: &&CythonFunction| &m.name == *name)
        })
        .collect();
    for name in &extras {
        let _ = writeln!(
            out,
            "    def {}(self, *args, **kwargs): ...",
            python_identifier(name)
        );
    }
    if doc.is_none() && init_params.is_none() && methods.is_empty() && extras.is_empty() {
        out.push_str("    ...\n");
    }
}

fn render_function(out: &mut String, function: &CythonFunction, indent: &str) {
    let is_method: bool = !indent.is_empty();
    let embedded: Option<(Option<String>, Option<String>)> = function
        .doc
        .as_deref()
        .map(|d: &str| split_embedded_signature(d, &function.name));
    let signature_text: Option<String> = function.signature.clone().or_else(|| {
        embedded
            .as_ref()
            .and_then(|(params, _)| params.as_ref())
            .map(|params: &String| format!("{}({params})", function.name))
    });
    let doc: Option<String> = embedded.and_then(|(_, d)| d);
    let (params, returns): (String, Option<&'static str>) = signature_text
        .as_deref()
        .and_then(|s: &str| parse_signature(s, &function.name))
        .map_or_else(
            || {
                let fallback: String = if is_method {
                    "self, *args, **kwargs".to_owned()
                } else {
                    "*args, **kwargs".to_owned()
                };
                (fallback, None)
            },
            |(params, returns): (Vec<String>, Option<&'static str>)| {
                let rendered: String = params
                    .iter()
                    .map(|p: &String| render_parameter(p))
                    .collect::<Vec<String>>()
                    .join(", ");
                let rendered: String = if is_method {
                    method_parameters_from(&rendered)
                } else {
                    rendered
                };
                (rendered, returns)
            },
        );
    let arrow: String = returns.map_or_else(String::new, |r: &str| format!(" -> {r}"));
    let name: String = python_identifier(&function.name);
    match doc.filter(|d: &String| !d.trim().is_empty()) {
        Some(doc) => {
            let _ = writeln!(out, "{indent}def {name}({params}){arrow}:");
            write_docstring(out, &doc, &format!("{indent}    "));
            let _ = writeln!(out, "{indent}    ...");
        }
        None => {
            let _ = writeln!(out, "{indent}def {name}({params}){arrow}: ...");
        }
    }
}

fn method_parameters(params: &str) -> String {
    match parse_signature(&format!("__init__({params})"), "__init__") {
        Some((parsed, _)) => method_parameters_from(
            &parsed
                .iter()
                .map(|p: &String| render_parameter(p))
                .collect::<Vec<String>>()
                .join(", "),
        ),
        None => "self, *args, **kwargs".to_owned(),
    }
}

fn method_parameters_from(rendered: &str) -> String {
    let first: &str = rendered.split(',').next().unwrap_or("").trim();
    if first == "self" || first.starts_with("self:") {
        rendered.to_owned()
    } else if rendered.is_empty() {
        "self".to_owned()
    } else {
        format!("self, {rendered}")
    }
}

fn split_embedded_signature(doc: &str, name: &str) -> (Option<String>, Option<String>) {
    let (first, rest): (&str, &str) = doc.split_once('\n').unwrap_or((doc, ""));
    let unqualified: &str = first
        .split_once('.')
        .filter(|(owner, rest): &(&str, &str)| {
            !owner.contains('(') && rest.starts_with(&format!("{name}("))
        })
        .map_or(first, |(_, rest): (&str, &str)| rest);
    let Some(tail) = unqualified
        .strip_prefix(name)
        .and_then(|t: &str| t.strip_prefix('('))
    else {
        return (None, Some(doc.to_owned()));
    };
    let Some(close) = tail.rfind(')') else {
        return (None, Some(doc.to_owned()));
    };
    let rest: &str = rest.trim_start_matches('\n');
    (
        Some(tail[..close].to_owned()),
        (!rest.trim().is_empty()).then(|| rest.to_owned()),
    )
}

fn parse_signature(signature: &str, name: &str) -> Option<(Vec<String>, Option<&'static str>)> {
    let body: &str = signature
        .trim()
        .strip_prefix(name)
        .unwrap_or_else(|| signature.trim());
    let open: usize = body.find('(')?;
    let close: usize = body.rfind(')')?;
    if close < open {
        return None;
    }
    let inner: &str = &body[open + 1..close];
    let returns: Option<&'static str> = body[close + 1..]
        .trim()
        .strip_prefix("->")
        .and_then(|r: &str| python_type(r.trim()));
    let mut params: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut current: String = String::new();
    for c in inner.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                params.push(current.trim().to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        params.push(current.trim().to_owned());
    }
    params
        .iter()
        .all(|p: &String| !p.is_empty())
        .then_some((params, returns))
}

fn render_parameter(param: &str) -> String {
    if param.starts_with('*') || param == "/" {
        return param.to_owned();
    }
    let (declaration, default): (&str, Option<&str>) = match param.split_once('=') {
        Some((d, v)) => (d.trim(), Some(v.trim())),
        None => (param.trim(), None),
    };
    let mut words: Vec<&str> = declaration.split_whitespace().collect();
    let name: &str = words.pop().unwrap_or("arg");
    let annotation: Option<&'static str> = (!words.is_empty())
        .then(|| python_type(&words.join(" ")))
        .flatten();
    let name: String = python_identifier(name.trim_start_matches('*'));
    match (annotation, default) {
        (Some(t), Some(d)) => format!("{name}: {t} = {d}"),
        (Some(t), None) => format!("{name}: {t}"),
        (None, Some(d)) => format!("{name}={d}"),
        (None, None) => name,
    }
}

fn python_type(c_type: &str) -> Option<&'static str> {
    let normalized: String = c_type
        .split_whitespace()
        .filter(|w: &&str| !matches!(*w, "const" | "signed" | "unsigned"))
        .collect::<Vec<&str>>()
        .join(" ");
    match normalized.as_str() {
        "int" | "long" | "long long" | "short" | "char" | "Py_ssize_t" | "size_t" => Some("int"),
        "double" | "float" | "long double" => Some("float"),
        "bint" | "bool" => Some("bool"),
        "str" | "unicode" => Some("str"),
        "bytes" => Some("bytes"),
        "list" => Some("list"),
        "dict" => Some("dict"),
        "tuple" => Some("tuple"),
        "object" => Some("object"),
        _ => None,
    }
}

fn write_docstring(out: &mut String, doc: &str, indent: &str) {
    let escaped: String = doc.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    let mut lines: std::str::Lines<'_> = escaped.lines();
    let first: &str = lines.next().unwrap_or("");
    let _ = write!(out, "{indent}\"\"\"{first}");
    for line in lines {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = write!(out, "\n{indent}{line}");
        }
    }
    out.push_str("\"\"\"\n");
}

fn python_identifier(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    match cleaned.chars().next() {
        Some(c) if c.is_alphabetic() || c == '_' => cleaned,
        _ => format!("_{cleaned}"),
    }
}

fn python_text(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
