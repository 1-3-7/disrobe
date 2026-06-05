use std::fmt::Write;

use wasmparser::{FunctionBody, ValType};

use crate::lift::{CalleeNames, HighLang, LiftResult, LiftTarget};
use crate::signature::FunctionSig;
use crate::structured::lift_body_structured;

/// Self-contained C runtime prelude (`#include`s + WebAssembly numeric/memory helpers).
#[must_use]
pub const fn c_runtime_prelude() -> &'static str {
    C_PRELUDE
}

/// Lifts a function body to compilable C via the structured operator-stream translator.
#[must_use]
pub(crate) fn lift_function_body_c(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
) -> LiftResult {
    match lift_body_structured(body, sig, callees, HighLang::C) {
        Ok((source, blocks_emitted, coverage)) => LiftResult {
            target: LiftTarget::C,
            pseudo_source: source,
            blocks_emitted,
            coverage,
        },
        Err(e) => LiftResult {
            target: LiftTarget::C,
            pseudo_source: c_stub(sig, &e.to_string()),
            blocks_emitted: 0,
            coverage: crate::lift::LiftCoverage {
                total_ops: 0,
                translated_ops: 0,
                untranslated: vec!["<parse-failure>".to_owned()],
            },
        },
    }
}

fn c_stub(sig: &FunctionSig, reason: &str) -> String {
    let mut s: String = String::new();
    let _ = writeln!(s, "/* not lifted: {reason} */");
    let ret: &str = sig.results.first().map_or("void", |t| c_type(*t));
    let _ = write!(s, "{ret} {}(", sig.name);
    if sig.params.is_empty() {
        s.push_str("void");
    } else {
        for (i, ty) in sig.params.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "{} p{i}", c_type(*ty));
        }
    }
    s.push_str(") {\n");
    if !sig.results.is_empty() {
        s.push_str("    return 0;\n");
    }
    s.push_str("}\n");
    s
}

const fn c_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "int64_t",
        ValType::F32 => "float",
        ValType::F64 => "double",
        ValType::V128 | ValType::Ref(_) | ValType::I32 => "int32_t",
    }
}

const C_PRELUDE: &str = include_str!("prelude/c.c.txt");

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wasmparser::{Parser, Payload};

    fn sig(name: &str, params: Vec<ValType>, results: Vec<ValType>) -> FunctionSig {
        FunctionSig {
            name: name.to_owned(),
            params,
            results,
            exported: true,
            imported: false,
            local_names: Vec::new(),
        }
    }

    fn lift_first(wat: &str, s: &FunctionSig) -> LiftResult {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("wat parse");
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Ok(Payload::CodeSectionEntry(body)) = payload {
                return lift_function_body_c(&body, s, &CalleeNames::new(Vec::new()));
            }
        }
        panic!("no code section");
    }

    const ADD: &str =
        r"(module (func (param i32) (param i32) (result i32) local.get 0 local.get 1 i32.add))";

    #[test]
    fn add_emits_typed_signature_and_helper_call() {
        let s: FunctionSig = sig("add", vec![ValType::I32, ValType::I32], vec![ValType::I32]);
        let out: LiftResult = lift_first(ADD, &s);
        assert!(
            out.pseudo_source
                .contains("int32_t add(int32_t p0, int32_t p1)")
        );
        assert!(out.pseudo_source.contains("wasm_i32_add(p0, p1)"));
        assert!(out.pseudo_source.contains("return"));
    }

    #[test]
    fn prelude_is_self_contained_includes() {
        assert!(c_runtime_prelude().contains("#include <stdint.h>"));
        assert!(c_runtime_prelude().contains("wasm_i32_add"));
    }
}
