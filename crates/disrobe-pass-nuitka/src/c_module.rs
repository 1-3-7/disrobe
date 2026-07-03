use serde::{Deserialize, Serialize};

use crate::demangle::{DemangledFunction, demangle_function};
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CCodeObject {
    pub name: String,
    pub line: u32,
    pub arg_names_const: Option<String>,
    pub arg_count: u32,
    pub kw_only_count: u32,
    pub pos_only_count: u32,
    pub has_varargs: bool,
    pub has_kwargs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CImplBody {
    pub function_name: String,
    pub source_index: u32,
    pub params: Vec<String>,
    pub parent_names: Vec<String>,
    pub impl_symbol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CFunctionWiring {
    pub function_name: String,
    pub annotations_dict_const: Option<String>,
    pub defaults_const: Option<String>,
    pub doc_const: Option<String>,
    pub parent_names: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CModuleStructure {
    pub module_name: String,
    pub code_objects: Vec<CCodeObject>,
    pub impl_bodies: Vec<CImplBody>,
    pub wirings: Vec<CFunctionWiring>,
    pub has_main_guard: bool,
    pub notes: Vec<String>,
}

const DIGEST_NAME_PREFIX: &str = "const_str_digest_";
const STR_PLAIN_PREFIX: &str = "const_str_plain_";

#[inline]
fn strip_mod_consts(token: &str) -> &str {
    token.strip_prefix("mod_consts.").unwrap_or(token)
}

#[inline]
fn is_preprocessor(line: &str) -> bool {
    let t: &str = line.trim_start();
    t.starts_with("#if")
        || t.starts_with("#endif")
        || t.starts_with("#else")
        || t.starts_with("#elif")
}

fn parse_module_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let t: &str = line.trim();
        let Some(body): Option<&str> = t.strip_prefix("PyObject *module_") else {
            continue;
        };
        let Some(name): Option<&str> = body.strip_suffix(';') else {
            continue;
        };
        if !name.is_empty() && name.chars().all(|c: char| c.is_alphanumeric() || c == '_') {
            return Some(name.to_owned());
        }
    }
    None
}

fn parse_code_objects(source: &str) -> Vec<CCodeObject> {
    let mut out: Vec<CCodeObject> = Vec::new();
    for line in source.lines() {
        let Some(open): Option<usize> = line.find("MAKE_CODE_OBJECT(") else {
            continue;
        };
        let after: &str = &line[open + "MAKE_CODE_OBJECT(".len()..];
        let Some(close): Option<usize> = after.find(')') else {
            continue;
        };
        let args: Vec<&str> = after[..close].split(',').map(str::trim).collect();
        if args.len() < 10 {
            continue;
        }
        let name_token: &str = strip_mod_consts(args[3]);
        let Some(name): Option<&str> = name_token.strip_prefix(STR_PLAIN_PREFIX) else {
            continue;
        };
        if name_token.starts_with(DIGEST_NAME_PREFIX) || name.is_empty() {
            continue;
        }
        let Ok(line_no): core::result::Result<u32, _> = args[1].parse() else {
            continue;
        };
        let arg_names_raw: &str = strip_mod_consts(args[5]);
        let arg_names_const: Option<String> = if arg_names_raw == "NULL" {
            None
        } else {
            Some(arg_names_raw.to_owned())
        };
        let Ok(arg_count): core::result::Result<u32, _> = args[7].parse() else {
            continue;
        };
        let Ok(kw_only_count): core::result::Result<u32, _> = args[8].parse() else {
            continue;
        };
        let Ok(pos_only_count): core::result::Result<u32, _> = args[9].parse() else {
            continue;
        };
        let flags: &str = args[2];
        let has_varargs: bool = flags.contains("CO_VARARGS");
        let has_kwargs: bool = flags.contains("CO_VARKEYWORDS");
        out.push(CCodeObject {
            name: name.to_owned(),
            line: line_no,
            arg_names_const,
            arg_count,
            kw_only_count,
            pos_only_count,
            has_varargs,
            has_kwargs,
        });
    }
    out
}

fn parse_impl_bodies(lines: &[&str]) -> Vec<CImplBody> {
    let mut out: Vec<CImplBody> = Vec::new();
    let mut i: usize = 0usize;
    while i < lines.len() {
        let line: &str = lines[i];
        let demangled: Option<DemangledFunction> = impl_decl_demangle(line);
        let Some(demangled): Option<DemangledFunction> = demangled else {
            i += 1;
            continue;
        };
        let (params, end): (Vec<(u32, String)>, usize) = collect_params(lines, i);
        let mut ordered: Vec<(u32, String)> = params;
        ordered.sort_by_key(|(idx, _): &(u32, String)| *idx);
        out.push(CImplBody {
            function_name: demangled.function_name,
            source_index: demangled.source_index,
            params: ordered.into_iter().map(|(_, n): (u32, String)| n).collect(),
            parent_names: demangled.parent_names,
            impl_symbol: demangled.raw_symbol,
        });
        i = end + 1;
    }
    out
}

fn impl_decl_demangle(line: &str) -> Option<DemangledFunction> {
    let t: &str = line.trim_start();
    let after: &str = t.strip_prefix("static PyObject *")?;
    let symbol: &str = after.split('(').next()?;
    if !symbol.starts_with("impl_") {
        return None;
    }
    if !line.contains("python_pars") {
        return None;
    }
    demangle_function(symbol)
}

fn collect_params(lines: &[&str], decl: usize) -> (Vec<(u32, String)>, usize) {
    let mut depth: i32 = 0i32;
    let mut started: bool = false;
    let mut params: Vec<(u32, String)> = Vec::new();
    let mut i: usize = decl;
    while i < lines.len() {
        let line: &str = lines[i];
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if let Some((idx, name)) = parse_param_line(line) {
            params.push((idx, name));
        }
        if started && depth <= 0 {
            return (params, i);
        }
        i += 1;
    }
    (params, lines.len().saturating_sub(1))
}

fn parse_param_line(line: &str) -> Option<(u32, String)> {
    let t: &str = line.trim();
    if let Some(after) = t.strip_prefix("PyObject *par_") {
        let (name, rest): (&str, &str) = after.split_once(" = python_pars[")?;
        let idx: u32 = rest.split(']').next()?.trim().parse().ok()?;
        if name.is_empty() {
            return None;
        }
        return Some((idx, name.to_owned()));
    }
    if let Some(after) = t.strip_prefix("struct Nuitka_CellObject *par_") {
        let (name, rest): (&str, &str) = after.split_once(" = Nuitka_Cell_New1(python_pars[")?;
        let idx: u32 = rest.split(']').next()?.trim().parse().ok()?;
        if name.is_empty() {
            return None;
        }
        return Some((idx, name.to_owned()));
    }
    None
}

fn parse_wirings(lines: &[&str]) -> Vec<CFunctionWiring> {
    let mut bindings: Vec<(DemangledFunction, Option<String>)> = Vec::new();
    let mut pending_dict: Option<String> = None;
    for line in lines {
        if let Some(dict) = parse_dict_copy(line) {
            pending_dict = Some(dict);
            continue;
        }
        if let Some(demangled) = parse_make_function_call(line) {
            bindings.push((demangled, pending_dict.take()));
            continue;
        }
        if line.contains("UPDATE_STRING_DICT1") {
            pending_dict = None;
        }
    }

    bindings
        .into_iter()
        .map(
            |(demangled, annotations_dict_const): (DemangledFunction, Option<String>)| {
                let (defaults_const, doc_const): (Option<String>, Option<String>) = (None, None);
                CFunctionWiring {
                    function_name: demangled.function_name,
                    annotations_dict_const,
                    defaults_const,
                    doc_const,
                    parent_names: demangled.parent_names,
                }
            },
        )
        .collect()
}

fn resolve_make_function_defaults(lines: &[&str], make_symbol: &str) -> Option<String> {
    let needle: String = format!("= {make_symbol}(");
    let call_line: &str = lines.iter().find(|l: &&&str| l.contains(needle.as_str()))?;
    let open: usize = call_line.find(needle.as_str())? + needle.len();
    let after: &str = &call_line[open..];
    let inner: &str = after.split(')').next()?;
    let args: Vec<&str> = inner.split(',').map(str::trim).collect();
    let defaults_arg: &str = args
        .iter()
        .copied()
        .find(|a: &&str| *a != "tstate" && !a.contains("annotations") && *a != "NULL")?;
    let token: &str = strip_mod_consts(defaults_arg);
    if token.starts_with("const_") {
        return Some(token.to_owned());
    }
    if token.starts_with("tmp_") {
        let assign: String = format!("{token} = ");
        let assign_line: &str = lines
            .iter()
            .find(|l: &&&str| l.trim_start().starts_with(assign.as_str()))?;
        let rhs: &str = assign_line
            .split(" = ")
            .nth(1)?
            .trim()
            .trim_end_matches(';');
        let rhs_token: &str = strip_mod_consts(rhs);
        if rhs_token.starts_with("const_") {
            return Some(rhs_token.to_owned());
        }
    }
    None
}

fn parse_dict_copy(line: &str) -> Option<String> {
    let open: usize = line.find("DICT_COPY(")?;
    let after: &str = &line[open + "DICT_COPY(".len()..];
    let inner: &str = after.split(')').next()?;
    let last_arg: &str = inner.rsplit(',').next()?.trim();
    let token: &str = strip_mod_consts(last_arg);
    if token.starts_with("const_dict_") {
        Some(token.to_owned())
    } else {
        None
    }
}

fn parse_make_function_call(line: &str) -> Option<DemangledFunction> {
    let assign: usize = line.find("= MAKE_FUNCTION_")?;
    let after: &str = &line[assign + "= ".len()..];
    let symbol: &str = after.split('(').next()?;
    if !symbol.contains("$$$") {
        return None;
    }
    demangle_function(symbol)
}

fn resolve_new_slots(source: &str, impl_symbol: &str) -> Option<(Option<String>, Option<String>)> {
    let needle: &str = "Nuitka_Function_New(";
    let mut search: usize = 0usize;
    while let Some(rel) = source[search..].find(needle) {
        let start: usize = search + rel;
        let depth_open: usize = start + needle.len() - 1;
        debug_assert!(source.is_char_boundary(depth_open));
        let close: usize = matching_paren(source, depth_open)?;
        let inner: &str = &source[depth_open + 1..close];
        let cleaned: Vec<&str> = inner
            .lines()
            .filter(|l: &&str| !is_preprocessor(l))
            .collect();
        let slots: Vec<String> = split_top_level_args(&cleaned.join("\n"));
        let first: &str = slots.first().map_or("", |s: &String| s.as_str());
        if first.trim() == impl_symbol {
            let defaults: Option<String> =
                slots.get(4).map(String::as_str).and_then(non_null_const);
            let doc: Option<String> = slots.get(8).map(String::as_str).and_then(non_null_const);
            return Some((defaults, doc));
        }
        search = close + 1;
    }
    None
}

fn matching_paren(source: &str, open: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: i32 = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_args(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth: i32 = 0i32;
    let mut cur: String = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_owned());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}

fn non_null_const(slot: &str) -> Option<String> {
    let token: &str = strip_mod_consts(slot.trim());
    if token == "NULL" || token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn detect_main_guard(lines: &[&str]) -> bool {
    let mut main_temp: Option<&str> = None;
    for line in lines {
        let t: &str = line.trim();
        if let Some((lhs, rhs)) = t.split_once(" = ") {
            let rhs_token: &str = strip_mod_consts(rhs.trim_end_matches(';').trim());
            if rhs_token == "const_str_plain___main__" && lhs.starts_with("tmp_cmp_expr_right") {
                main_temp = Some(lhs.trim());
            }
        }
        if let Some(temp) = main_temp
            && line.contains("RICH_COMPARE_EQ")
            && line.contains(temp)
        {
            return true;
        }
    }
    false
}

pub fn parse_c_module(source: &str) -> Result<CModuleStructure> {
    let lines: Vec<&str> = source.lines().collect();

    let module_name: String = parse_module_name(source).ok_or_else(|| {
        Error::SurfaceBinding(
            "no `PyObject *module_<name>;` declaration found; not a Nuitka module.<name>.c"
                .to_owned(),
        )
    })?;
    let code_objects: Vec<CCodeObject> = parse_code_objects(source);
    let impl_bodies: Vec<CImplBody> = parse_impl_bodies(&lines);
    let mut wirings: Vec<CFunctionWiring> = parse_wirings(&lines);

    for wiring in &mut wirings {
        if let Some(body) = impl_bodies.iter().find(|b: &&CImplBody| {
            b.function_name == wiring.function_name && b.parent_names == wiring.parent_names
        }) {
            let impl_symbol: &str = &body.impl_symbol;
            if let Some((defaults, doc)) = resolve_new_slots(source, impl_symbol) {
                wiring.defaults_const = defaults;
                wiring.doc_const = doc;
            }
            let make_symbol: String = impl_symbol.replacen("impl_", "MAKE_FUNCTION_", 1);
            if let Some(defaults) = resolve_make_function_defaults(&lines, &make_symbol) {
                wiring.defaults_const = Some(defaults);
            }
        }
    }

    let has_main_guard: bool = detect_main_guard(&lines);

    let mut notes: Vec<String> = Vec::new();
    let n_impl: usize = impl_bodies.len();
    let n_wire: usize = wirings.len();
    if n_impl != n_wire {
        notes.push(format!(
            "structure mismatch: {n_impl} impl bodies vs {n_wire} wirings"
        ));
    }

    Ok(CModuleStructure {
        module_name,
        code_objects,
        impl_bodies,
        wirings,
        has_main_guard,
        notes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const C_SRC: &str =
        include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");

    #[test]
    fn parses_module_name() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        assert_eq!(m.module_name, "hello");
    }

    #[test]
    fn parses_three_impl_bodies_in_order() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        let names: Vec<&str> = m
            .impl_bodies
            .iter()
            .map(|b: &CImplBody| b.function_name.as_str())
            .collect();
        assert_eq!(names, vec!["greet", "fib", "main"]);
        assert_eq!(m.impl_bodies[0].params, vec!["name"]);
        assert_eq!(m.impl_bodies[1].params, vec!["n"]);
        assert!(m.impl_bodies[2].params.is_empty());
    }

    #[test]
    fn parses_code_objects_excluding_digest() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        let names: Vec<&str> = m
            .code_objects
            .iter()
            .map(|c: &CCodeObject| c.name.as_str())
            .collect();
        assert!(names.contains(&"greet"));
        assert!(names.contains(&"fib"));
        assert!(names.contains(&"main"));
        assert_eq!(m.code_objects.len(), 3);
    }

    #[test]
    fn malformed_code_object_numbers_are_skipped() {
        let source: &str = r"
PyObject *module_m;
static PyCodeObject *codeobj_bad = MAKE_CODE_OBJECT(module_filename_obj, nope, 0, mod_consts.const_str_plain_bad, NULL, NULL, NULL, xx, yy, zz);
";
        let m: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(m.code_objects.is_empty());
    }

    #[test]
    fn wirings_bind_annotation_dicts() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        let greet: &CFunctionWiring = m
            .wirings
            .iter()
            .find(|w: &&CFunctionWiring| w.function_name == "greet")
            .expect("greet wiring");
        assert_eq!(
            greet.annotations_dict_const.as_deref(),
            Some("const_dict_0d747635c5b87742d1bd242db31edac3")
        );
        for w in &m.wirings {
            assert_eq!(w.defaults_const, None);
            assert_eq!(w.doc_const, None);
        }
    }

    #[test]
    fn detects_main_guard_from_real_bytes() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        assert!(m.has_main_guard);
    }

    #[test]
    fn self_consistency_three_each() {
        let m: CModuleStructure = parse_c_module(C_SRC).expect("parse");
        assert_eq!(m.impl_bodies.len(), 3);
        assert_eq!(m.wirings.len(), 3);
        assert_eq!(m.code_objects.len(), 3);
        assert!(m.notes.is_empty());
    }
}
