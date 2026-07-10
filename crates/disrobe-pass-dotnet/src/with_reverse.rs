use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::cil::{Instruction, MethodBody, OperandValue};
use crate::names::NameTable;
use crate::structurize::{StructuredMethod, TargetLang, TokenNamer, csharp_string_literal};

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
    Some(render_with(&source_name, &assignments, 4))
}

fn with_clause(assignments: &[Assignment]) -> String {
    assignments
        .iter()
        .map(|a: &Assignment| format!("{} = {}", a.property, a.value))
        .collect::<Vec<String>>()
        .join(", ")
}

fn render_with(source: &str, assignments: &[Assignment], indent: usize) -> String {
    let pad: String = " ".repeat(indent);
    let mut text: String = String::new();
    let _ = writeln!(
        text,
        "{pad}return {source} with {{ {} }};",
        with_clause(assignments)
    );
    text
}

fn render_with_line(source: &str, assignments: &[Assignment], indent: usize) -> String {
    let pad: String = " ".repeat(indent);
    let mut text: String = String::new();
    let _ = write!(
        text,
        "{pad}return {source} with {{ {} }};",
        with_clause(assignments)
    );
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

struct StructCopyMatch {
    decl_index: usize,
    source: String,
    assignments: Vec<Assignment>,
    return_index: usize,
    body_indent: usize,
}

#[must_use]
pub(crate) fn reconstruct_struct_with_expressions(
    methods: &mut [StructuredMethod],
    record_struct_types: &BTreeSet<String>,
) -> u32 {
    let mut rewritten: u32 = 0;
    for m in methods.iter_mut() {
        if let Some(updated) = rewrite_struct_copy_body(&m.body, record_struct_types) {
            m.body = updated;
            rewritten = rewritten.saturating_add(1);
        }
    }
    rewritten
}

fn rewrite_struct_copy_body(body: &str, record_struct_types: &BTreeSet<String>) -> Option<String> {
    let lines: Vec<&str> = body.lines().collect();
    let m: StructCopyMatch = detect_struct_copy(&lines, record_struct_types)?;
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        if i == m.decl_index {
            continue;
        }
        if i == m.decl_index + 1 && line.trim().is_empty() {
            continue;
        }
        if i > m.decl_index && i < m.return_index {
            continue;
        }
        if i == m.return_index {
            out.push(render_with_line(&m.source, &m.assignments, m.body_indent));
            continue;
        }
        out.push((*line).to_owned());
    }
    let mut joined: String = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    Some(joined)
}

fn detect_struct_copy(
    lines: &[&str],
    record_struct_types: &BTreeSet<String>,
) -> Option<StructCopyMatch> {
    for (decl_index, line) in lines.iter().enumerate() {
        let Some((_ty, local_name)) = struct_local_decl(line, record_struct_types) else {
            continue;
        };
        if let Some(m) = try_match_struct_copy(lines, decl_index, &local_name) {
            return Some(m);
        }
    }
    None
}

fn try_match_struct_copy(
    lines: &[&str],
    decl_index: usize,
    local_name: &str,
) -> Option<StructCopyMatch> {
    let body_indent: usize = indent_of(lines[decl_index]);
    let assign_index: usize = next_nonblank(lines, decl_index + 1)?;
    if indent_of(lines[assign_index]) != body_indent {
        return None;
    }
    let source: String = assignment_value(lines[assign_index], local_name)?;
    if !is_simple_source_expr(&source) || contains_word(&source, local_name) {
        return None;
    }

    let mut cursor: usize = assign_index + 1;
    let mut assignments: Vec<Assignment> = Vec::new();
    loop {
        let idx: usize = next_nonblank(lines, cursor)?;
        if indent_of(lines[idx]) != body_indent {
            return None;
        }
        if let Some((property, value)) = struct_property_assignment(lines[idx], local_name) {
            if contains_word(&value, local_name) {
                return None;
            }
            assignments.push(Assignment { property, value });
            cursor = idx + 1;
            continue;
        }
        if line_is_return_of(lines[idx], local_name) {
            if assignments.is_empty() {
                return None;
            }
            if local_referenced_outside(lines, local_name, decl_index, idx) {
                return None;
            }
            return Some(StructCopyMatch {
                decl_index,
                source,
                assignments,
                return_index: idx,
                body_indent,
            });
        }
        return None;
    }
}

fn struct_local_decl(
    line: &str,
    record_struct_types: &BTreeSet<String>,
) -> Option<(String, String)> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    if inner.contains('=') || inner.contains('(') || inner.contains('{') {
        return None;
    }
    let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
    let ty: &str = ty.trim();
    if !record_struct_types.contains(ty) {
        return None;
    }
    let valid_name: bool = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    valid_name.then(|| (ty.to_owned(), name.to_owned()))
}

fn struct_property_assignment(line: &str, local_name: &str) -> Option<(String, String)> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" = ")?;
    let lhs: &str = lhs.trim();
    let property: &str = lhs.strip_prefix(local_name)?.strip_prefix('.')?;
    let valid_property: bool = !property.is_empty()
        && property
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && property
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    valid_property.then(|| (property.to_owned(), rhs.trim().to_owned()))
}

fn is_simple_source_expr(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg: &str| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .next()
                    .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
                && seg
                    .bytes()
                    .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn assignment_value(line: &str, name: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" = ")?;
    (lhs.trim() == name).then(|| rhs.trim().to_owned())
}

fn line_is_return_of(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    t.strip_suffix(';')
        .and_then(|s: &str| s.strip_prefix("return "))
        .is_some_and(|v: &str| v.trim() == name)
}

fn local_referenced_outside(
    lines: &[&str],
    name: &str,
    decl_index: usize,
    return_index: usize,
) -> bool {
    lines.iter().enumerate().any(|(i, l): (usize, &&str)| {
        (i < decl_index || i > return_index) && contains_word(l, name)
    })
}

fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes: &[u8] = haystack.as_bytes();
    let wlen: usize = word.len();
    haystack.match_indices(word).any(|(i, _): (usize, &str)| {
        let before_ok: bool = i == 0 || !is_ident_byte(bytes[i - 1]);
        let after_ok: bool = i + wlen >= bytes.len() || !is_ident_byte(bytes[i + wlen]);
        before_ok && after_ok
    })
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn indent_of(line: &str) -> usize {
    line.bytes().take_while(|b: &u8| *b == b' ').count()
}

fn next_nonblank(lines: &[&str], start: usize) -> Option<usize> {
    (start..lines.len()).find(|&i: &usize| !lines[i].trim().is_empty())
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

    fn structured(body: &str) -> StructuredMethod {
        StructuredMethod {
            signature: "EdgeCases.Coordinate Shift(EdgeCases.Coordinate c, double dx, double dy)"
                .to_owned(),
            body: body.to_owned(),
            statement_count: 0,
            recovered_locals: 0,
            recovered_branches: 0,
            typed_locals: 0,
            named_params: 0,
        }
    }

    fn coordinate_types() -> BTreeSet<String> {
        BTreeSet::from(["EdgeCases.Coordinate".to_owned()])
    }

    #[test]
    fn rewrites_struct_local_copy_to_with_expression() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Coordinate local0;\n\n    local0 = c;\n    local0.Latitude = c.Latitude + dx;\n    local0.Longitude = c.Longitude + dy;\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(rewritten, 1);
        assert_eq!(
            methods[0].body,
            "{\n    return c with { Latitude = c.Latitude + dx, Longitude = c.Longitude + dy };\n}\n"
        );
    }

    #[test]
    fn ignores_local_of_an_unknown_type() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Rgb local0;\n\n    local0 = c;\n    local0.Latitude = c.Latitude + dx;\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn ignores_source_expression_with_a_call() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Coordinate local0;\n\n    local0 = Make();\n    local0.Latitude = dx;\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn ignores_rhs_that_reads_the_partially_mutated_copy() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Coordinate local0;\n\n    local0 = c;\n    local0.Latitude = local0.Longitude + dx;\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(
            rewritten, 0,
            "a with-expression evaluates every initializer against the original value, \
             not a partially mutated copy, so this shape must be rejected"
        );
    }

    #[test]
    fn ignores_local_referenced_after_the_return() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Coordinate local0;\n\n    local0 = c;\n    local0.Latitude = dx;\n    if (local0.Latitude > 0)\n    {\n        return local0;\n    }\n\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(rewritten, 0);
    }

    #[test]
    fn ignores_bare_copy_with_no_property_mutation() {
        let mut methods: Vec<StructuredMethod> = vec![structured(
            "{\n    EdgeCases.Coordinate local0;\n\n    local0 = c;\n    return local0;\n}\n",
        )];
        let rewritten: u32 = reconstruct_struct_with_expressions(&mut methods, &coordinate_types());
        assert_eq!(rewritten, 0);
    }
}
