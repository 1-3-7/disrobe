use crate::pdb_cxx::spelling::TypeOp;

pub(crate) fn build_declarator(ops: &[TypeOp], name: String) -> String {
    let Some((first, rest)) = ops.split_first() else {
        return name;
    };
    match first {
        TypeOp::Array(_) | TypeOp::Function { .. } => build_declarator_suffix(first, rest, name),
        TypeOp::Pointer {
            const_q,
            volatile_q,
        } => {
            let combined: String = format!("{} {name}", qualifier_token(*const_q, *volatile_q));
            let wrapped: String = wrap_if_needed(rest, combined);
            build_declarator(rest, wrapped)
        }
        TypeOp::LValueRef => {
            let combined: String = format!("& {name}");
            let wrapped: String = wrap_if_needed(rest, combined);
            build_declarator(rest, wrapped)
        }
        TypeOp::RValueRef => {
            let combined: String = format!("&& {name}");
            let wrapped: String = wrap_if_needed(rest, combined);
            build_declarator(rest, wrapped)
        }
        TypeOp::MemberPointer {
            class_name,
            const_q,
            volatile_q,
        } => {
            let combined: String = format!(
                "{class_name}::{} {name}",
                qualifier_token(*const_q, *volatile_q)
            );
            let wrapped: String = wrap_if_needed(rest, combined);
            build_declarator(rest, wrapped)
        }
    }
}

fn build_declarator_suffix(first: &TypeOp, rest: &[TypeOp], name: String) -> String {
    let combined: String = match first {
        TypeOp::Array(count) => format!("{name}[{count}]"),
        TypeOp::Function {
            params,
            varargs,
            calling_convention,
        } => {
            let mut plist: Vec<String> = params.clone();
            if *varargs {
                plist.push("...".to_owned());
            }
            if plist.is_empty() {
                plist.push("void".to_owned());
            }
            let cc: String = calling_convention.map_or_else(String::new, |s: &str| format!("{s} "));
            format!("{cc}{name}({})", plist.join(", "))
        }
        _ => name,
    };
    build_declarator(rest, combined)
}

fn qualifier_token(const_q: bool, volatile_q: bool) -> String {
    let mut token: String = "*".to_owned();
    if const_q {
        token.push_str(" const");
    }
    if volatile_q {
        token.push_str(" volatile");
    }
    token
}

fn wrap_if_needed(rest: &[TypeOp], combined: String) -> String {
    if matches!(
        rest.first(),
        Some(TypeOp::Array(_) | TypeOp::Function { .. })
    ) {
        format!("({combined})")
    } else {
        combined
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::pdb_cxx::spelling::ResolvedSpelling;

    fn spelling(base_text: &str, ops: Vec<TypeOp>) -> ResolvedSpelling {
        ResolvedSpelling {
            base_text: base_text.to_owned(),
            ops,
            byte_size: None,
            degraded: false,
            bitfield: None,
            opaque_refs: Vec::new(),
            value_dependency: None,
        }
    }

    #[test]
    fn declarator_pointer_to_array_gets_parens() {
        let s: ResolvedSpelling = spelling(
            "int",
            vec![
                TypeOp::Pointer {
                    const_q: false,
                    volatile_q: false,
                },
                TypeOp::Array(4),
            ],
        );
        let text: String = s
            .declare("p")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        assert_eq!(text, "int (* p)[4]");
    }

    #[test]
    fn declarator_array_of_pointer_has_no_parens() {
        let s: ResolvedSpelling = spelling(
            "int",
            vec![
                TypeOp::Array(4),
                TypeOp::Pointer {
                    const_q: false,
                    volatile_q: false,
                },
            ],
        );
        let text: String = s
            .declare("p")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        assert_eq!(text, "int * p[4]");
    }

    #[test]
    fn declarator_function_pointer_member() {
        let s: ResolvedSpelling = spelling(
            "int",
            vec![
                TypeOp::Pointer {
                    const_q: false,
                    volatile_q: false,
                },
                TypeOp::Function {
                    params: vec!["int".to_owned(), "char".to_owned()],
                    varargs: false,
                    calling_convention: None,
                },
            ],
        );
        let text: String = s
            .declare("fp")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        assert_eq!(text, "int (* fp)(int, char)");
    }

    #[test]
    fn declarator_plain_scalar_has_no_wrapping() {
        let s: ResolvedSpelling = spelling("unsigned int", Vec::new());
        assert_eq!(s.declare("x"), "unsigned int x");
    }
}
