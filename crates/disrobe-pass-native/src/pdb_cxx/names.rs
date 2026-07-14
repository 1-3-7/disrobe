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
            | "asm"
            | "auto"
            | "bool"
            | "break"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "continue"
            | "default"
            | "delete"
            | "do"
            | "double"
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
            | "operator"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "template"
            | "this"
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
}
