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

#[must_use]
pub fn demangle_nim(mangled: &str) -> Option<DemangledSymbol> {
    let body: &str = mangled.strip_prefix("_ZN")?;
    let mut rest: &str = body;
    let mut components: Vec<String> = Vec::new();
    while let Some((segment, tail)) = read_length_prefixed(rest) {
        components.push(segment);
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
    while let Some((segment, tail)) = read_length_prefixed(param_tail) {
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

#[must_use]
pub fn demangle_zig(mangled: &str) -> Option<DemangledSymbol> {
    if mangled.is_empty() || mangled.starts_with('_') && !mangled.contains('.') {
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
    let segments: Vec<&str> = path.split('.').collect();
    let name: String = (*segments.last()?).to_owned();
    let module: Option<String> = if segments.len() >= 2 {
        Some(segments[0].to_owned())
    } else {
        None
    };
    Some(DemangledSymbol {
        mangled: mangled.to_owned(),
        demangled: path.to_owned(),
        module,
        name,
        params: Vec::new(),
        instantiation,
    })
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
}
