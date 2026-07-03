use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemangledSymbol {
    pub mangled: String,
    pub demangled: String,
    pub module: Option<String>,
    pub name: String,
    pub params: Vec<String>,
    pub instantiation: Option<String>,
}

impl DemangledSymbol {
    #[must_use]
    pub fn qualified_name(&self) -> String {
        match &self.module {
            Some(module) if !module.is_empty() => format!("{module}.{}", self.name),
            _ => self.name.clone(),
        }
    }
}

#[must_use]
pub fn demangle_nim(mangled: &str) -> Option<DemangledSymbol> {
    let body: &str = mangled.strip_prefix("_ZN")?;
    let mut rest: &str = body;
    let mut components: Vec<String> = Vec::new();
    while let Some((segment, tail)) = read_length_prefixed(rest) {
        components.push(nim_decode_operator(&segment));
        rest = tail;
        if rest.starts_with('E') {
            rest = &rest[1..];
            break;
        }
    }
    if components.is_empty() {
        return None;
    }
    let mut params: Vec<String> = Vec::new();
    let mut param_tail: &str = rest;
    while let Some((segment, tail)) = read_nim_type(param_tail, 0) {
        params.push(segment);
        param_tail = tail;
    }
    let name: String = components.last().cloned().unwrap_or_default();
    let module: Option<String> = if components.len() >= 2 {
        Some(components[..components.len() - 1].join("."))
    } else {
        None
    };
    let qualified: String = components.join(".");
    let demangled: String = if params.is_empty() {
        qualified
    } else {
        format!("{qualified}({})", params.join(", "))
    };
    Some(DemangledSymbol {
        mangled: mangled.to_owned(),
        demangled,
        module,
        name,
        params,
        instantiation: None,
    })
}

const NIM_OPERATOR_WORDS: &[(&str, &str)] = &[
    ("plus", "+"),
    ("minus", "-"),
    ("star", "*"),
    ("slash", "/"),
    ("backslash", "\\"),
    ("eq", "="),
    ("less", "<"),
    ("greater", ">"),
    ("bar", "|"),
    ("percent", "%"),
    ("amp", "&"),
    ("dollar", "$"),
    ("at", "@"),
    ("hat", "^"),
    ("dot", "."),
    ("colon", ":"),
    ("tilde", "~"),
    ("excl", "!"),
    ("qmark", "?"),
    ("plusplus", "++"),
];

fn nim_decode_operator(segment: &str) -> String {
    let Some(core): Option<&str> = segment.strip_suffix('_') else {
        return segment.to_owned();
    };
    if core.is_empty() {
        return segment.to_owned();
    }
    let mut decoded: String = String::new();
    let mut cursor: &str = core;
    while !cursor.is_empty() {
        let Some((word, op)): Option<&(&str, &str)> = NIM_OPERATOR_WORDS
            .iter()
            .filter(|(word, _): &&(&str, &str)| cursor.starts_with(word))
            .max_by_key(|(word, _): &&(&str, &str)| word.len())
        else {
            break;
        };
        decoded.push_str(op);
        cursor = &cursor[word.len()..];
    }
    if decoded.is_empty() {
        return segment.to_owned();
    }
    decoded.push_str(cursor);
    decoded
}

const MAX_NIM_DEPTH: usize = 256;

fn decode_nim_subrange(token: &str) -> Option<String> {
    let upper: &str = token.strip_prefix("range0")?;
    if upper.is_empty() || !upper.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("range[0..{upper}]"))
}

fn read_nim_type(input: &str, depth: usize) -> Option<(String, &str)> {
    if depth > MAX_NIM_DEPTH {
        return None;
    }
    if let Some(after) = input.strip_prefix('N') {
        return read_nim_nested(after);
    }
    let (base, mut rest): (String, &str) = read_length_prefixed(input)?;
    let mut value: String =
        decode_nim_subrange(&base).unwrap_or_else(|| nim_decode_operator(&base));
    if let Some(after) = rest.strip_prefix('I') {
        let (args, tail): (Vec<String>, &str) = read_nim_template_args(after, depth + 1)?;
        if !args.is_empty() {
            value = format!("{value}[{}]", args.join(", "));
        }
        rest = tail;
    }
    Some((value, rest))
}

fn read_nim_nested(input: &str) -> Option<(String, &str)> {
    let mut components: Vec<String> = Vec::new();
    let mut cursor: &str = input;
    while let Some((segment, tail)) = read_length_prefixed(cursor) {
        components.push(nim_decode_operator(&segment));
        cursor = tail;
        if let Some(after) = cursor.strip_prefix('E') {
            cursor = after;
            break;
        }
    }
    if components.is_empty() {
        return None;
    }
    Some((components.join("."), cursor))
}

fn read_nim_template_args(input: &str, depth: usize) -> Option<(Vec<String>, &str)> {
    let mut args: Vec<String> = Vec::new();
    let mut cursor: &str = input;
    loop {
        if let Some(after) = cursor.strip_prefix('E') {
            return Some((args, after));
        }
        let (arg, tail): (String, &str) = read_nim_type(cursor, depth)?;
        args.push(arg);
        cursor = tail;
    }
}

#[must_use]
pub fn demangle_zig(mangled: &str) -> Option<DemangledSymbol> {
    if mangled.is_empty() || mangled.starts_with('_') && !mangled.contains('.') {
        return None;
    }
    if mangled.starts_with("__zig_") {
        return None;
    }
    if !mangled.contains('.') {
        return None;
    }
    let (path, instantiation): (&str, Option<String>) = mangled
        .find("__anon_")
        .map_or((mangled, None), |idx: usize| {
            (&mangled[..idx], Some(mangled[idx + 2..].to_owned()))
        });
    let last_dot: Option<usize> = top_level_dot(path, true);
    let first_dot: Option<usize> = top_level_dot(path, false);
    let name: String =
        last_dot.map_or_else(|| path.to_owned(), |idx: usize| path[idx + 1..].to_owned());
    if name.is_empty() {
        return None;
    }
    let module: Option<String> = first_dot.map(|idx: usize| path[..idx].to_owned());
    Some(DemangledSymbol {
        mangled: mangled.to_owned(),
        demangled: path.to_owned(),
        module,
        name,
        params: Vec::new(),
        instantiation,
    })
}

fn top_level_dot(path: &str, last: bool) -> Option<usize> {
    let bytes: &[u8] = path.as_bytes();
    let mut depth: i32 = 0;
    let mut found: Option<usize> = None;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = (depth - 1).max(0),
            b'.' if depth == 0 => {
                found = Some(i);
                if !last {
                    return found;
                }
            }
            _ => {}
        }
    }
    found
}

#[must_use]
pub fn demangle_crystal(symbol: &str) -> Option<DemangledSymbol> {
    let trimmed: &str = symbol.trim();
    if trimmed.is_empty() {
        return None;
    }
    let core: &str = trimmed.strip_suffix(".class").unwrap_or(trimmed);
    let (path, params): (&str, Vec<String>) = match core.split_once('(') {
        Some((head, args)) => {
            let args_inner: &str = args.strip_suffix(')').unwrap_or(args);
            let parsed: Vec<String> = args_inner
                .split(',')
                .map(|s: &str| s.trim().to_owned())
                .filter(|s: &String| !s.is_empty())
                .collect();
            (head, parsed)
        }
        None => (core, Vec::new()),
    };
    let (module, name): (Option<String>, String) = match path.rsplit_once("::") {
        Some((ns, leaf)) => (Some(ns.to_owned()), leaf.to_owned()),
        None => match path.split_once('#') {
            Some((ty, method)) => (Some(ty.to_owned()), method.to_owned()),
            None => (None, path.to_owned()),
        },
    };
    if name.is_empty() || !is_crystal_identifier(path) {
        return None;
    }
    Some(DemangledSymbol {
        mangled: symbol.to_owned(),
        demangled: core.to_owned(),
        module,
        name,
        params,
        instantiation: None,
    })
}

#[must_use]
pub fn demangle_d(mangled: &str) -> Option<DemangledSymbol> {
    if mangled == "_Dmain" {
        return Some(DemangledSymbol {
            mangled: mangled.to_owned(),
            demangled: "D main".to_owned(),
            module: None,
            name: "main".to_owned(),
            params: Vec::new(),
            instantiation: None,
        });
    }
    let result: crate::d_mangle::DResult = crate::d_mangle::demangle_d_result(mangled)?;
    let (module, name): (Option<String>, String) = split_qualified(&result.qualified);
    let instantiation: Option<String> = extract_instantiation(&result.qualified);
    Some(DemangledSymbol {
        mangled: mangled.to_owned(),
        demangled: result.demangled,
        module,
        name,
        params: result.params,
        instantiation,
    })
}

fn extract_instantiation(qualified: &str) -> Option<String> {
    let open: usize = qualified.find("!(")?;
    let bytes: &[u8] = qualified.as_bytes();
    let mut depth: i32 = 0;
    let mut i: usize = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(qualified[open + 2..i].to_owned());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_qualified(qualified: &str) -> (Option<String>, String) {
    let bytes: &[u8] = qualified.as_bytes();
    let mut depth: i32 = 0;
    let mut last_dot: Option<usize> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'!' if bytes.get(i + 1) == Some(&b'(') => {
                let mut d: i32 = 1;
                i += 2;
                while i < bytes.len() && d > 0 {
                    match bytes[i] {
                        b'(' => d += 1,
                        b')' => d -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = (depth - 1).max(0),
            b'.' if depth == 0 => last_dot = Some(i),
            _ => {}
        }
        i += 1;
    }
    last_dot.map_or_else(
        || (None, qualified.to_owned()),
        |idx: usize| {
            (
                Some(qualified[..idx].to_owned()),
                qualified[idx + 1..].to_owned(),
            )
        },
    )
}

fn read_length_prefixed(input: &str) -> Option<(String, &str)> {
    let digit_end: usize = input.find(|c: char| !c.is_ascii_digit())?;
    if digit_end == 0 {
        return None;
    }
    let len: usize = input[..digit_end].parse::<usize>().ok()?;
    if len == 0 {
        return None;
    }
    let value_end: usize = digit_end.checked_add(len)?;
    let bytes: &[u8] = input.as_bytes();
    if value_end > bytes.len()
        || !input.is_char_boundary(digit_end)
        || !input.is_char_boundary(value_end)
    {
        return None;
    }
    let value: String = input[digit_end..value_end].to_owned();
    Some((value, &input[value_end..]))
}

fn is_crystal_identifier(path: &str) -> bool {
    let stripped: String = path
        .replace("::", "")
        .replace(['#', '(', ')', ' ', ',', '|'], "");
    !stripped.is_empty()
        && stripped
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && path
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn nim_itanium_nested_with_param() {
        let d: DemangledSymbol = demangle_nim("_ZN5hello5greetE6string").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("hello"));
        assert_eq!(d.name, "greet");
        assert_eq!(d.params, vec!["string".to_owned()]);
        assert_eq!(d.demangled, "hello.greet(string)");
    }

    #[test]
    fn nim_itanium_fib_int() {
        let d: DemangledSymbol = demangle_nim("_ZN5hello3fibE3int").expect("demangle");
        assert_eq!(d.name, "fib");
        assert_eq!(d.demangled, "hello.fib(int)");
    }

    #[test]
    fn nim_rejects_non_itanium() {
        assert!(demangle_nim("NimMainModule").is_none());
        assert!(demangle_nim("main").is_none());
    }

    #[test]
    fn nim_decodes_arithmetic_operators() {
        let d: DemangledSymbol = demangle_nim("_ZN6system13minuspercent_E3int3int").expect("d");
        assert_eq!(d.name, "-%");
        assert_eq!(d.demangled, "system.-%(int, int)");
        let p: DemangledSymbol = demangle_nim("_ZN6system12pluspercent_E3int3int").expect("d");
        assert_eq!(p.name, "+%");
        assert_eq!(p.demangled, "system.+%(int, int)");
    }

    #[test]
    fn nim_decodes_dollar_stringify_operator() {
        let d: DemangledSymbol = demangle_nim("_ZN7dollars7dollar_E3int").expect("d");
        assert_eq!(d.name, "$");
        assert_eq!(d.demangled, "dollars.$(int)");
    }

    #[test]
    fn nim_decodes_lifecycle_hook_with_generic_param() {
        let d: DemangledSymbol =
            demangle_nim("_ZN6stdlib10eqdestroy_E3varIN10exceptions11IndexDefectEE").expect("d");
        assert_eq!(d.name, "=destroy");
        assert_eq!(d.module.as_deref(), Some("stdlib"));
        assert_eq!(d.params, vec!["var[exceptions.IndexDefect]".to_owned()]);
        assert_eq!(d.demangled, "stdlib.=destroy(var[exceptions.IndexDefect])");
    }

    #[test]
    fn nim_recovers_seq_generic_param() {
        let d: DemangledSymbol =
            demangle_nim("_ZN6system10eqdestroy_E3seqIN6system15StackTraceEntryEE").expect("d");
        assert_eq!(d.name, "=destroy");
        assert_eq!(d.params, vec!["seq[system.StackTraceEntry]".to_owned()]);
    }

    #[test]
    fn nim_plain_identifier_is_not_operator_decoded() {
        let d: DemangledSymbol = demangle_nim("_ZN5hello3fibE3int").expect("d");
        assert_eq!(d.name, "fib");
        assert_eq!(d.demangled, "hello.fib(int)");
    }

    #[test]
    fn nim_decodes_zero_based_subrange_type() {
        let d: DemangledSymbol =
            demangle_nim("_ZN6system7copyMemE7pointer7pointer25range09223372036854775807")
                .expect("d");
        assert_eq!(d.name, "copyMem");
        assert_eq!(
            d.params,
            vec![
                "pointer".to_owned(),
                "pointer".to_owned(),
                "range[0..9223372036854775807]".to_owned(),
            ],
            "the Nim Natural subrange must decode to range[0..high]"
        );
    }

    #[test]
    fn nim_decodes_subrange_inside_array_generic() {
        let d: DemangledSymbol =
            demangle_nim("_ZN11digitsutils8addCharsE3varI6stringE5arrayI8range0234charE3int3int")
                .expect("d");
        assert_eq!(d.name, "addChars");
        assert_eq!(
            d.params,
            vec![
                "var[string]".to_owned(),
                "array[range[0..23], char]".to_owned(),
                "int".to_owned(),
                "int".to_owned(),
            ]
        );
    }

    #[test]
    fn zig_dotted_plain() {
        let d: DemangledSymbol = demangle_zig("hello.fib").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("hello"));
        assert_eq!(d.name, "fib");
        assert_eq!(d.demangled, "hello.fib");
        assert!(d.instantiation.is_none());
    }

    #[test]
    fn zig_strips_anon_instantiation() {
        let d: DemangledSymbol = demangle_zig("hello.greet__anon_2858").expect("demangle");
        assert_eq!(d.name, "greet");
        assert_eq!(d.demangled, "hello.greet");
        assert_eq!(d.instantiation.as_deref(), Some("anon_2858"));
    }

    #[test]
    fn zig_nested_posix() {
        let d: DemangledSymbol = demangle_zig("start.posixCallMainAndExit").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("start"));
        assert_eq!(d.name, "posixCallMainAndExit");
    }

    #[test]
    fn zig_rejects_bare_c_symbol() {
        assert!(demangle_zig("_start").is_none());
        assert!(demangle_zig("main").is_none());
    }

    #[test]
    fn zig_generic_instantiation_leaf_extracted_past_nested_dots() {
        let d: DemangledSymbol = demangle_zig(
            "array_hash_map.ArrayHashMapUnmanaged(u64,dwarf.CommonInformationEntry,array_hash_map.AutoContext(u64),false).get",
        )
        .expect("demangle");
        assert_eq!(
            d.name, "get",
            "leaf name must be the final top-level segment, not split inside the generic args"
        );
        assert_eq!(d.module.as_deref(), Some("array_hash_map"));
    }

    #[test]
    fn zig_generic_method_strips_anon_and_keeps_real_leaf() {
        let d: DemangledSymbol = demangle_zig(
            "array_hash_map.ArrayHashMapUnmanaged(u64,dwarf.CommonInformationEntry,array_hash_map.AutoContext(u64),false).getAdapted__anon_8393",
        )
        .expect("demangle");
        assert_eq!(d.name, "getAdapted");
        assert_eq!(d.instantiation.as_deref(), Some("anon_8393"));
        assert!(!d.name.contains('('), "name must not leak generic args");
    }

    #[test]
    fn zig_leaf_survives_internal_spaces_in_generics() {
        let d: DemangledSymbol = demangle_zig(
            "compress.flate.bit_reader.BitReader(u32,io.GenericReader(*io.fixed_buffer_stream.FixedBufferStream([]const u8),error{},(function 'read'))).alignBits",
        )
        .expect("demangle");
        assert_eq!(d.name, "alignBits");
        assert_eq!(d.module.as_deref(), Some("compress"));
    }

    #[test]
    fn zig_rejects_compiler_reflection_builtins() {
        assert!(demangle_zig("__zig_probe_stack").is_none());
        assert!(
            demangle_zig("__zig_is_named_enum_value_dwarf.DwarfSection").is_none(),
            "compiler reflection thunk must not be demangled as a user module"
        );
        assert!(demangle_zig("__zig_tag_name_dwarf.call_frame.Opcode").is_none());
    }

    #[test]
    fn crystal_namespaced_type() {
        let d: DemangledSymbol = demangle_crystal("Crystal::EventLoop::IOCP").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("Crystal::EventLoop"));
        assert_eq!(d.name, "IOCP");
    }

    #[test]
    fn crystal_instance_method() {
        let d: DemangledSymbol = demangle_crystal("Greeter#greet").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("Greeter"));
        assert_eq!(d.name, "greet");
    }

    #[test]
    fn crystal_strips_class_suffix() {
        let d: DemangledSymbol = demangle_crystal("Greeter.class").expect("demangle");
        assert_eq!(d.name, "Greeter");
        assert_eq!(d.demangled, "Greeter");
    }

    #[test]
    fn crystal_rejects_garbage() {
        assert!(demangle_crystal("D$#8").is_none());
        assert!(demangle_crystal("").is_none());
    }

    #[test]
    fn d_member_function() {
        let d: DemangledSymbol = demangle_d("_D5hello7Greeter3fibMFlZl").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("hello.Greeter"));
        assert_eq!(d.name, "fib");
        assert_eq!(d.demangled, "long hello.Greeter.fib(long)");
        assert_eq!(d.params, vec!["long".to_owned()]);
        assert_eq!(d.qualified_name(), "hello.Greeter.fib");
    }

    #[test]
    fn d_constructor() {
        let d: DemangledSymbol =
            demangle_d("_D5hello7Greeter6__ctorMFAyaZCQBcQz").expect("demangle");
        assert_eq!(
            d.demangled,
            "hello.Greeter hello.Greeter.__ctor(immutable(char)[])"
        );
        assert_eq!(d.name, "__ctor");
        assert_eq!(d.params, vec!["immutable(char)[]".to_owned()]);
    }

    #[test]
    fn d_main_entrypoint() {
        let d: DemangledSymbol = demangle_d("_Dmain").expect("demangle");
        assert_eq!(d.name, "main");
        assert_eq!(d.demangled, "D main");
        assert!(d.module.is_none());
    }

    #[test]
    fn d_template_instance_leaf() {
        let d: DemangledSymbol =
            demangle_d("_D3std5stdio__T7writelnTAyaZQnFNfQjZv").expect("demangle");
        assert_eq!(
            d.module.as_deref(),
            Some("std.stdio.writeln!(immutable(char)[])")
        );
        assert_eq!(d.name, "writeln");
        assert_eq!(
            d.demangled,
            "@safe void std.stdio.writeln!(immutable(char)[]).writeln(immutable(char)[])"
        );
        assert_eq!(d.instantiation.as_deref(), Some("immutable(char)[]"));
        assert!(
            d.module
                .as_deref()
                .is_some_and(|m: &str| m.starts_with("std.stdio")),
            "module scope must begin with the std.stdio package"
        );
    }

    #[test]
    fn d_nested_module_path() {
        let d: DemangledSymbol =
            demangle_d("_D4core10checkedint__T4adduZQgFNaNbNiNfmmKbZm").expect("demangle");
        assert_eq!(d.module.as_deref(), Some("core.checkedint.addu!()"));
        assert_eq!(d.name, "addu");
        assert_eq!(
            d.demangled,
            "pure nothrow @nogc @safe ulong core.checkedint.addu!().addu(ulong, ulong, ref bool)"
        );
        assert_eq!(
            d.params,
            vec![
                "ulong".to_owned(),
                "ulong".to_owned(),
                "ref bool".to_owned()
            ]
        );
    }

    #[test]
    fn d_rejects_non_d() {
        assert!(demangle_d("main").is_none());
        assert!(demangle_d("NimMainModule").is_none());
        assert!(demangle_d("_ZN5hello3fibE3int").is_none());
    }
}
