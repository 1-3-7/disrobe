use std::collections::BTreeMap;

pub(crate) fn sanitize_identifier(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let mut prev_underscore: bool = true;
    for ch in raw.chars() {
        let mapped: char = if ch.is_ascii_alphanumeric() { ch } else { '_' };
        if mapped == '_' {
            if !prev_underscore {
                out.push('_');
            }
            prev_underscore = true;
        } else {
            out.push(mapped);
            prev_underscore = false;
        }
    }
    if out.ends_with('_') {
        out.pop();
    }
    let mut result: String = if out.is_empty() {
        "anon".to_owned()
    } else {
        out
    };
    if result
        .chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_digit())
    {
        result.insert_str(0, "t_");
    }
    if is_cxx_keyword(&result) {
        result.push_str("_ty");
    }
    result
}

pub(crate) struct Deduper {
    seen: BTreeMap<String, u32>,
}

impl Deduper {
    pub(crate) fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
        }
    }

    pub(crate) fn assign(&mut self, base: &str) -> String {
        let counter: &mut u32 = self.seen.entry(base.to_owned()).or_insert(0);
        let assigned: String = if *counter == 0 {
            base.to_owned()
        } else {
            format!("{base}_{counter}")
        };
        *counter += 1;
        assigned
    }
}

fn is_cxx_keyword(name: &str) -> bool {
    matches!(
        name,
        "alignas"
            | "alignof"
            | "and"
            | "and_eq"
            | "asm"
            | "auto"
            | "bitand"
            | "bitor"
            | "bool"
            | "break"
            | "case"
            | "catch"
            | "char"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "class"
            | "co_await"
            | "co_return"
            | "co_yield"
            | "compl"
            | "concept"
            | "const"
            | "const_cast"
            | "consteval"
            | "constexpr"
            | "constinit"
            | "continue"
            | "decltype"
            | "default"
            | "delete"
            | "do"
            | "double"
            | "dynamic_cast"
            | "else"
            | "enum"
            | "explicit"
            | "export"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "friend"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "mutable"
            | "namespace"
            | "new"
            | "noexcept"
            | "not"
            | "not_eq"
            | "nullptr"
            | "operator"
            | "or"
            | "or_eq"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "reinterpret_cast"
            | "requires"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "static_assert"
            | "static_cast"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "thread_local"
            | "throw"
            | "true"
            | "try"
            | "typedef"
            | "typeid"
            | "typename"
            | "union"
            | "unsigned"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "wchar_t"
            | "while"
            | "xor"
            | "xor_eq"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_collapses_punctuation_and_keeps_readability() {
        assert_eq!(sanitize_identifier("std::vector<int>"), "std_vector_int");
        assert_eq!(
            sanitize_identifier("<lambda_1@main.cpp:4:5>"),
            "lambda_1_main_cpp_4_5"
        );
        assert_eq!(sanitize_identifier("Point"), "Point");
    }

    #[test]
    fn sanitize_handles_leading_digit_and_keyword_collision() {
        assert_eq!(sanitize_identifier("3Foo"), "t_3Foo");
        assert_eq!(sanitize_identifier("class"), "class_ty");
    }

    #[test]
    fn sanitize_never_produces_an_empty_identifier() {
        assert_eq!(sanitize_identifier("<<<>>>"), "anon");
        assert_eq!(sanitize_identifier(""), "anon");
    }

    #[test]
    fn deduper_disambiguates_repeated_bases_deterministically() {
        let mut d: Deduper = Deduper::new();
        assert_eq!(d.assign("Foo"), "Foo");
        assert_eq!(d.assign("Foo"), "Foo_1");
        assert_eq!(d.assign("Foo"), "Foo_2");
        assert_eq!(d.assign("Bar"), "Bar");
    }

    const CXX_RESERVED_MEMBER_NAMES: &[&str] = &[
        "or",
        "not",
        "xor",
        "bitand",
        "bitor",
        "compl",
        "and_eq",
        "or_eq",
        "xor_eq",
        "not_eq",
        "nullptr",
        "constexpr",
        "decltype",
        "noexcept",
        "static_assert",
        "thread_local",
        "concept",
        "requires",
        "char16_t",
        "char32_t",
    ];

    #[test]
    fn sanitize_guards_cxx_alternative_tokens_and_modern_keywords() {
        for reserved in CXX_RESERVED_MEMBER_NAMES {
            let sanitized: String = sanitize_identifier(reserved);
            assert_eq!(
                sanitized,
                format!("{reserved}_ty"),
                "identifier `{reserved}` is a reserved word in C++ and must be renamed"
            );
        }
    }

    fn cxx_compiler() -> Option<String> {
        for compiler in ["g++", "clang++", "c++"] {
            if std::process::Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
            {
                return Some(compiler.to_owned());
            }
        }
        None
    }

    fn compiles_as_cxx(compiler: &str, std_flag: &str, source: &str, tag: &str) -> bool {
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-pdb-names-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let src: std::path::PathBuf = dir.join(format!("names_{tag}.cpp"));
        std::fs::write(&src, source.as_bytes()).expect("write source");
        std::process::Command::new(compiler)
            .args([std_flag, "-fsyntax-only"])
            .arg(&src)
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
    }

    #[test]
    fn sanitized_reserved_member_names_compile_as_cxx() {
        let Some(compiler): Option<String> = cxx_compiler() else {
            return;
        };
        let std_flag: &str = if compiles_as_cxx(
            &compiler,
            "-std=c++20",
            "struct Probe { int m; };\n",
            "std_probe",
        ) {
            "-std=c++20"
        } else {
            "-std=c++17"
        };
        let mut reserved_seen: u32 = 0;
        for reserved in CXX_RESERVED_MEMBER_NAMES {
            let sanitized: String = sanitize_identifier(reserved);
            let fixed_source: String = format!("struct S {{ int {sanitized}; }};\n");
            assert!(
                compiles_as_cxx(
                    &compiler,
                    std_flag,
                    &fixed_source,
                    &format!("fixed_{reserved}")
                ),
                "expected sanitized member `int {sanitized};` to compile as C++"
            );
            let raw_source: String = format!("struct S {{ int {reserved}; }};\n");
            if !compiles_as_cxx(&compiler, std_flag, &raw_source, &format!("raw_{reserved}")) {
                reserved_seen += 1;
            }
        }
        assert!(
            reserved_seen >= 10,
            "expected the C++ compiler to reject most reserved names as members, only {reserved_seen} rejected"
        );
    }
}
