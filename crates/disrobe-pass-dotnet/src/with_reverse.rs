use std::fmt::Write as _;

use crate::cil::{Instruction, MethodBody, OperandValue};
use crate::names::NameTable;
use crate::structurize::{TargetLang, TokenNamer, csharp_string_literal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Arg(u32),
    Local(u32),
}

#[derive(Debug, Clone)]
struct Assignment {
    property: String,
    value: String,
}

#[must_use]
pub(crate) fn reconstruct_with_expression<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> Option<String> {
    if lang != TargetLang::CSharp {
        return None;
    }
    let ops: Vec<&Instruction> = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| !is_noise(&i.name))
        .collect();
    if ops.len() < 4 {
        return None;
    }

    let has_this: bool = namer.outer_has_this();
    let source: Source = load_source(ops[0])?;
    if !is_clone_call(ops[1], namer) {
        return None;
    }

    let mut cursor: usize = 2;
    let mut assignments: Vec<Assignment> = Vec::new();
    while cursor + 2 < ops.len() {
        if ops[cursor].name != "dup" {
            break;
        }
        let value: String = constant_or_load(ops[cursor + 1], namer, names, has_this)?;
        let property: String = property_setter_name(ops[cursor + 2], namer)?;
        assignments.push(Assignment { property, value });
        cursor += 3;
    }

    if assignments.is_empty() {
        return None;
    }
    if !returns_top_of_stack(&ops[cursor..]) {
        return None;
    }

    let source_name: String = render_source(source, names, has_this)?;
    Some(render_with(&source_name, &assignments))
}

fn render_with(source: &str, assignments: &[Assignment]) -> String {
    let parts: Vec<String> = assignments
        .iter()
        .map(|a: &Assignment| format!("{} = {}", a.property, a.value))
        .collect();
    let mut text: String = String::new();
    let _ = writeln!(text, "    return {source} with {{ {} }};", parts.join(", "));
    text
}

fn returns_top_of_stack(tail: &[&Instruction]) -> bool {
    matches!(tail, [ret] if ret.name == "ret")
}

fn is_clone_call<N: TokenNamer>(ins: &Instruction, namer: &N) -> bool {
    if ins.name != "callvirt" && ins.name != "call" {
        return false;
    }
    let OperandValue::Token(token): OperandValue = ins.operand else {
        return false;
    };
    let name: String = namer.name(token);
    let member: &str = name.rsplit("::").next().unwrap_or(&name);
    member == "<Clone>$"
}

fn property_setter_name<N: TokenNamer>(ins: &Instruction, namer: &N) -> Option<String> {
    if ins.name != "callvirt" && ins.name != "call" {
        return None;
    }
    let OperandValue::Token(token): OperandValue = ins.operand else {
        return None;
    };
    let name: String = namer.name(token);
    let member: &str = name.rsplit("::").next().unwrap_or(&name);
    let property: &str = member.strip_prefix("set_")?;
    let valid: bool = !property.is_empty()
        && property
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && property
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    valid.then(|| property.to_owned())
}

fn constant_or_load<N: TokenNamer>(
    ins: &Instruction,
    namer: &N,
    names: &NameTable,
    has_this: bool,
) -> Option<String> {
    if let Some(source) = load_source(ins) {
        return render_source(source, names, has_this);
    }
    constant_value(ins, namer)
}

fn constant_value<N: TokenNamer>(ins: &Instruction, namer: &N) -> Option<String> {
    match ins.name.as_str() {
        "ldstr" => match ins.operand {
            OperandValue::Token(t) => Some(csharp_string_literal(&namer.name(t))),
            _ => None,
        },
        "ldnull" => Some("null".to_owned()),
        "ldc.i4.m1" => Some("-1".to_owned()),
        name if name.starts_with("ldc.i4") => Some(int_const(ins, name).to_string()),
        "ldc.i8" => match ins.operand {
            OperandValue::I64(v) => Some(format!("{v}L")),
            _ => None,
        },
        _ => None,
    }
}

fn render_source(source: Source, names: &NameTable, has_this: bool) -> Option<String> {
    match source {
        Source::Arg(0) if has_this => None,
        Source::Arg(raw) => {
            let slot: u32 = if has_this { raw } else { raw.saturating_add(1) };
            Some(names.arg_name(slot))
        }
        Source::Local(slot) => Some(NameTable::local_name(slot)),
    }
}

fn load_source(ins: &Instruction) -> Option<Source> {
    if let Some(slot) = ldarg_slot(ins) {
        return Some(Source::Arg(slot));
    }
    ldloc_slot(ins).map(Source::Local)
}

fn ldarg_slot(ins: &Instruction) -> Option<u32> {
    match ins.name.as_str() {
        "ldarg.0" => Some(0),
        "ldarg.1" => Some(1),
        "ldarg.2" => Some(2),
        "ldarg.3" => Some(3),
        "ldarg" | "ldarg.s" => operand_index(ins),
        _ => None,
    }
}

fn ldloc_slot(ins: &Instruction) -> Option<u32> {
    match ins.name.as_str() {
        "ldloc.0" => Some(0),
        "ldloc.1" => Some(1),
        "ldloc.2" => Some(2),
        "ldloc.3" => Some(3),
        "ldloc" | "ldloc.s" => operand_index(ins),
        _ => None,
    }
}

fn operand_index(ins: &Instruction) -> Option<u32> {
    match ins.operand {
        OperandValue::U8(v) => Some(u32::from(v)),
        OperandValue::U16(v) => Some(u32::from(v)),
        OperandValue::I32(v) => u32::try_from(v).ok(),
        _ => None,
    }
}

fn int_const(ins: &Instruction, name: &str) -> i64 {
    if let Some(rest) = name.strip_prefix("ldc.i4.") {
        return match rest {
            "s" => match ins.operand {
                OperandValue::U8(b) => i64::from(b.cast_signed()),
                _ => 0,
            },
            d => d.parse::<i64>().unwrap_or(0),
        };
    }
    if name == "ldc.i4"
        && let OperandValue::I32(v) = ins.operand
    {
        return i64::from(v);
    }
    0
}

fn is_noise(name: &str) -> bool {
    matches!(name, "nop" | "break")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cil::FlowControl;

    #[derive(Debug, Default)]
    struct StubNamer;

    impl TokenNamer for StubNamer {
        fn name(&self, token: u32) -> String {
            match token {
                1 => "Sample.Point::<Clone>$".to_owned(),
                2 => "Sample.Point::set_X".to_owned(),
                3 => "Sample.Point::set_Y".to_owned(),
                _ => format!("token_{token:08X}"),
            }
        }

        fn outer_has_this(&self) -> bool {
            false
        }
    }

    fn ins(name: &str, operand: OperandValue) -> Instruction {
        Instruction {
            offset: 0,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow: FlowControl::Next,
        }
    }

    fn body(instructions: Vec<Instruction>) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: 0,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions,
            exception_clauses: Vec::new(),
        }
    }

    fn names() -> NameTable {
        NameTable::new(
            false,
            vec!["p".to_owned(), "v".to_owned()],
            vec!["Point".to_owned(), "int".to_owned()],
            Vec::new(),
        )
    }

    #[test]
    fn rewrites_single_constant_property() {
        let b: MethodBody = body(vec![
            ins("ldarg.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(1)),
            ins("dup", OperandValue::None),
            ins("ldc.i4.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(3)),
            ins("ret", OperandValue::None),
        ]);
        let out: String = reconstruct_with_expression(&b, &StubNamer, &names(), TargetLang::CSharp)
            .expect("with");
        assert_eq!(out.trim_end(), "    return p with { Y = 0 };");
    }

    #[test]
    fn rewrites_two_properties_in_order() {
        let b: MethodBody = body(vec![
            ins("ldarg.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(1)),
            ins("dup", OperandValue::None),
            ins("ldc.i4.1", OperandValue::None),
            ins("callvirt", OperandValue::Token(2)),
            ins("dup", OperandValue::None),
            ins("ldc.i4.2", OperandValue::None),
            ins("callvirt", OperandValue::Token(3)),
            ins("ret", OperandValue::None),
        ]);
        let out: String = reconstruct_with_expression(&b, &StubNamer, &names(), TargetLang::CSharp)
            .expect("with");
        assert_eq!(out.trim_end(), "    return p with { X = 1, Y = 2 };");
    }

    #[test]
    fn rewrites_argument_value() {
        let b: MethodBody = body(vec![
            ins("ldarg.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(1)),
            ins("dup", OperandValue::None),
            ins("ldarg.1", OperandValue::None),
            ins("callvirt", OperandValue::Token(2)),
            ins("ret", OperandValue::None),
        ]);
        let out: String = reconstruct_with_expression(&b, &StubNamer, &names(), TargetLang::CSharp)
            .expect("with");
        assert_eq!(out.trim_end(), "    return p with { X = v };");
    }

    #[test]
    fn ignores_non_clone_head() {
        let b: MethodBody = body(vec![
            ins("ldarg.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(2)),
            ins("dup", OperandValue::None),
            ins("ldc.i4.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(3)),
            ins("ret", OperandValue::None),
        ]);
        assert!(
            reconstruct_with_expression(&b, &StubNamer, &names(), TargetLang::CSharp).is_none()
        );
    }

    #[test]
    fn ignores_without_trailing_ret() {
        let b: MethodBody = body(vec![
            ins("ldarg.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(1)),
            ins("dup", OperandValue::None),
            ins("ldc.i4.0", OperandValue::None),
            ins("callvirt", OperandValue::Token(3)),
            ins("pop", OperandValue::None),
            ins("ret", OperandValue::None),
        ]);
        assert!(
            reconstruct_with_expression(&b, &StubNamer, &names(), TargetLang::CSharp).is_none()
        );
    }
}
