use wasmparser::{FunctionBody, ValType};

use crate::error::{Error, Result};
use crate::lift::{
    CalleeNames, HighLang, LiftResult, LiftTarget, ModuleRenderBudget, ModuleSourceBuffer,
    atomic_memory_refusal_coverage,
};
use crate::signature::FunctionSig;
use crate::structured::lift_body_structured;

#[must_use]
pub const fn c_runtime_prelude() -> &'static str {
    C_PRELUDE
}

#[must_use]
pub(crate) fn lift_function_body_c(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
) -> LiftResult {
    match try_lift_function_body_c(body, sig, callees) {
        Ok(result) => result,
        Err(Error::AtomicMemoryModel(reason)) => LiftResult {
            target: LiftTarget::C,
            pseudo_source: c_atomic_memory_refusal_stub(
                sig,
                &Error::AtomicMemoryModel(reason).to_string(),
            ),
            blocks_emitted: 0,
            coverage: atomic_memory_refusal_coverage(),
        },
        Err(error) => LiftResult {
            target: LiftTarget::C,
            pseudo_source: c_stub(sig, &error.to_string()),
            blocks_emitted: 0,
            coverage: crate::lift::LiftCoverage {
                total_ops: 0,
                translated_ops: 0,
                untranslated: vec!["<parse-failure>".to_owned()],
            },
        },
    }
}

pub(crate) fn try_lift_function_body_c(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
) -> Result<LiftResult> {
    let (source, blocks_emitted, coverage): (String, usize, crate::lift::LiftCoverage) =
        lift_body_structured(body, sig, callees, HighLang::C)?;
    Ok(LiftResult {
        target: LiftTarget::C,
        pseudo_source: source,
        blocks_emitted,
        coverage,
    })
}

pub(crate) fn try_lift_function_body_c_with_budget(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    budget: &mut ModuleRenderBudget,
) -> Result<LiftResult> {
    let (source, blocks_emitted, coverage): (String, usize, crate::lift::LiftCoverage) =
        crate::structured::lift_body_structured_with_budget(
            body,
            sig,
            callees,
            HighLang::C,
            budget,
        )?;
    Ok(LiftResult {
        target: LiftTarget::C,
        pseudo_source: source,
        blocks_emitted,
        coverage,
    })
}

pub(crate) fn lift_function_body_c_with_budget(
    body: &FunctionBody<'_>,
    sig: &FunctionSig,
    callees: &CalleeNames,
    budget: &mut ModuleRenderBudget,
) -> Result<LiftResult> {
    let checkpoint: usize = budget.checkpoint();
    match try_lift_function_body_c_with_budget(body, sig, callees, budget) {
        Ok(result) => Ok(result),
        Err(error @ Error::ModuleSourceLimit { .. }) => Err(error),
        Err(Error::AtomicMemoryModel(reason)) => {
            budget.rollback(checkpoint);
            let reason: String = Error::AtomicMemoryModel(reason).to_string();
            let pseudo_source: String =
                c_atomic_memory_refusal_stub_with_budget(sig, &reason, budget)?;
            super::lift::charge_coverage_entry(budget, "<unsupported-atomic-memory-model>")?;
            Ok(LiftResult {
                target: LiftTarget::C,
                pseudo_source,
                blocks_emitted: 0,
                coverage: atomic_memory_refusal_coverage(),
            })
        }
        Err(error) => {
            budget.rollback(checkpoint);
            let pseudo_source: String = c_stub_with_budget(sig, &error.to_string(), budget)?;
            super::lift::charge_coverage_entry(budget, "<parse-failure>")?;
            Ok(LiftResult {
                target: LiftTarget::C,
                pseudo_source,
                blocks_emitted: 0,
                coverage: crate::lift::LiftCoverage {
                    total_ops: 0,
                    translated_ops: 0,
                    untranslated: vec!["<parse-failure>".to_owned()],
                },
            })
        }
    }
}

fn c_atomic_memory_refusal_stub(sig: &FunctionSig, reason: &str) -> String {
    let mut source: String = String::new();
    render_c_atomic_memory_refusal_stub(&mut source, sig, reason);
    source
}

fn c_atomic_memory_refusal_stub_with_budget(
    sig: &FunctionSig,
    reason: &str,
    budget: &mut ModuleRenderBudget,
) -> Result<String> {
    let mut source: ModuleSourceBuffer<'_> = ModuleSourceBuffer::new(budget);
    render_c_atomic_memory_refusal_stub(&mut source, sig, reason);
    source.finish()
}

fn render_c_atomic_memory_refusal_stub(
    source: &mut impl std::fmt::Write,
    sig: &FunctionSig,
    reason: &str,
) {
    let result: &str = sig
        .results
        .first()
        .map_or("void", |ty: &ValType| c_type(*ty));
    crate::push_string_fmt(source, format_args!("{result} {}(", sig.name));
    if sig.params.is_empty() {
        crate::push_string_fmt(source, format_args!("void"));
    } else {
        let params: std::iter::Enumerate<std::slice::Iter<'_, ValType>> =
            sig.params.iter().enumerate();
        for (index, ty) in params {
            if index > 0 {
                crate::push_string_fmt(source, format_args!(", "));
            }
            crate::push_string_fmt(source, format_args!("{} p{index}", c_type(*ty)));
        }
    }
    crate::push_string_fmt(source, format_args!(") {{\n"));
    for index in 0..sig.params.len() {
        crate::push_string_line(source, format_args!("    (void)p{index};"));
    }
    crate::push_string_line(source, format_args!("    fputs({reason:?}, stderr);"));
    crate::push_string_fmt(
        source,
        format_args!("    fputc('\\n', stderr);\n    fflush(stderr);\n    abort();\n}}\n"),
    );
}

fn c_stub(sig: &FunctionSig, reason: &str) -> String {
    let mut s: String = String::new();
    render_c_stub(&mut s, sig, reason);
    s
}

fn c_stub_with_budget(
    sig: &FunctionSig,
    reason: &str,
    budget: &mut ModuleRenderBudget,
) -> Result<String> {
    let mut source: ModuleSourceBuffer<'_> = ModuleSourceBuffer::new(budget);
    render_c_stub(&mut source, sig, reason);
    source.finish()
}

fn render_c_stub(s: &mut impl std::fmt::Write, sig: &FunctionSig, reason: &str) {
    crate::push_string_line(s, format_args!("/* not lifted: {reason} */"));
    let ret: &str = sig.results.first().map_or("void", |t| c_type(*t));
    crate::push_string_fmt(s, format_args!("{ret} {}(", sig.name));
    if sig.params.is_empty() {
        crate::push_string_fmt(s, format_args!("void"));
    } else {
        for (i, ty) in sig.params.iter().enumerate() {
            if i > 0 {
                crate::push_string_fmt(s, format_args!(", "));
            }
            crate::push_string_fmt(s, format_args!("{} p{i}", c_type(*ty)));
        }
    }
    crate::push_string_fmt(s, format_args!(") {{\n"));
    if !sig.results.is_empty() {
        crate::push_string_fmt(s, format_args!("    return 0;\n"));
    }
    crate::push_string_fmt(s, format_args!("}}\n"));
}

const fn c_type(ty: ValType) -> &'static str {
    match ty {
        ValType::I64 => "int64_t",
        ValType::F32 => "float",
        ValType::F64 => "double",
        ValType::V128 => "v128_t",
        ValType::Ref(_) | ValType::I32 => "int32_t",
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
