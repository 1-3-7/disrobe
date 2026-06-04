use serde::Serialize;

use super::pcode_real::{RealModuleDisasm, RealPCodeLine};

/// Outcome of lowering a disassembled p-code module into readable VB pseudocode.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticLift {
    pub module: String,
    pub pseudocode: String,
    pub lifted_lines: usize,
    pub unlifted_lines: usize,
    pub walls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Procedure,
    If,
    For,
    ForEach,
    Do,
    While,
    With,
    Select,
}

struct OpenBlock {
    kind: BlockKind,
    header_out_index: usize,
}

struct Lifter {
    stack: Vec<String>,
    out: Vec<String>,
    indent: usize,
    blocks: Vec<OpenBlock>,
    lifted: usize,
    unlifted: usize,
    walls: Vec<String>,
}

impl Lifter {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            out: Vec::new(),
            indent: 0,
            blocks: Vec::new(),
            lifted: 0,
            unlifted: 0,
            walls: Vec::new(),
        }
    }

    fn pop(&mut self) -> String {
        self.stack.pop().unwrap_or_else(|| "<?>".to_owned())
    }

    fn pop_n(&mut self, n: usize) -> Vec<String> {
        let mut args: Vec<String> = Vec::with_capacity(n);
        for _ in 0..n {
            args.push(self.pop());
        }
        args.reverse();
        args
    }

    fn emit(&mut self, stmt: String) {
        let pad: String = "    ".repeat(self.indent);
        self.out.push(format!("{pad}{stmt}"));
    }

    fn open(&mut self, kind: BlockKind, header: String) {
        let header_out_index: usize = self.out.len();
        self.emit(header);
        self.blocks.push(OpenBlock {
            kind,
            header_out_index,
        });
        self.indent += 1;
    }

    fn close(&mut self, footer: String) {
        if self.indent > 0 {
            self.indent -= 1;
        }
        self.blocks.pop();
        self.emit(footer);
    }

    fn relabel_procedure(&mut self, keyword: &str) {
        let Some(block): Option<&OpenBlock> = self.blocks.last() else {
            return;
        };
        if block.kind != BlockKind::Procedure {
            return;
        }
        let header_index: usize = block.header_out_index;
        if let Some(header) = self.out.get_mut(header_index) {
            *header = header.replacen("Sub ", &format!("{keyword} "), 1);
        }
    }
}

#[must_use]
fn parse_mnemonic(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((head, rest)) => (head, rest.trim()),
        None => (text, ""),
    }
}

#[must_use]
fn first_operand(rest: &str) -> &str {
    rest.split_whitespace().next().unwrap_or("")
}

#[must_use]
fn quoted_payload(rest: &str) -> Option<String> {
    let start: usize = rest.find('"')?;
    let end: usize = rest.rfind('"')?;
    if end > start {
        Some(rest[start..=end].to_owned())
    } else {
        None
    }
}

#[must_use]
fn call_arg_count(rest: &str) -> usize {
    rest.split_whitespace()
        .find_map(|tok: &str| {
            tok.strip_prefix("0x")
                .and_then(|hex: &str| u32::from_str_radix(hex, 16).ok())
        })
        .unwrap_or(0) as usize
}

#[must_use]
fn join_args(args: &[String]) -> String {
    args.join(", ")
}

fn binary(l: &mut Lifter, op: &str) {
    let rhs: String = l.pop();
    let lhs: String = l.pop();
    l.stack.push(format!("{lhs} {op} {rhs}"));
}

fn unary_prefix(l: &mut Lifter, op: &str) {
    let v: String = l.pop();
    l.stack.push(format!("{op}{v}"));
}

/// Lower a single disassembled p-code line's mnemonic stream into zero or more VB statements.
fn lift_line(l: &mut Lifter, line: &RealPCodeLine) {
    let produced_before: usize = l.out.len();
    let mut saw_known: bool = false;
    for raw in line.text.lines() {
        let (mnem, rest): (&str, &str) = parse_mnemonic(raw.trim());
        if mnem.is_empty() {
            continue;
        }
        saw_known |= apply(l, mnem, rest, line);
    }
    if l.stack.len() == 1 && l.out.len() == produced_before {
        let expr: String = l.pop();
        if !expr.is_empty() && expr != "<?>" {
            l.emit(expr);
        }
    }
    if saw_known {
        l.lifted += 1;
    } else if !line.text.trim().is_empty() && !line.text.contains("<empty>") {
        l.unlifted += 1;
    }
    l.stack.clear();
}

fn apply(l: &mut Lifter, mnem: &str, rest: &str, line: &RealPCodeLine) -> bool {
    match mnem {
        "LitStr" | "QuoteRem" | "Rem" => {
            if mnem == "Rem" || mnem == "QuoteRem" {
                let body: String = quoted_payload(rest).unwrap_or_default();
                let inner: &str = body.trim_matches('"');
                l.stack.push(format!("'{inner}"));
            } else {
                l.stack
                    .push(quoted_payload(rest).unwrap_or_else(|| "\"\"".to_owned()));
            }
            true
        }
        "LitDI2" | "LitDI4" | "LitDI8" | "LitHI2" | "LitHI4" | "LitHI8" | "LitOI2" | "LitOI4"
        | "LitOI8" | "LitR4" | "LitR8" | "LitCy" | "LitDate" | "LitSmallI2" => {
            l.stack.push(lit_number(mnem, rest));
            true
        }
        "LitVarSpecial" => {
            l.stack.push("Empty".to_owned());
            true
        }
        "LitNothing" => {
            l.stack.push("Nothing".to_owned());
            true
        }
        "LitDefault" => {
            l.stack.push("Default".to_owned());
            true
        }
        "Ld" | "LdLHS" | "LdAddressOf" => {
            l.stack.push(first_operand(rest).to_owned());
            true
        }
        "MemLd" | "MemLdWith" => {
            let name: &str = first_operand(rest);
            let base: String = if mnem == "MemLdWith" {
                String::new()
            } else {
                l.pop()
            };
            l.stack.push(format!("{base}.{name}"));
            true
        }
        "Me" | "MeImplicit" => {
            l.stack.push("Me".to_owned());
            true
        }
        "ArgsLd" | "ArgsMemLd" | "ArgsMemLdWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let args: Vec<String> = l.pop_n(argc);
            let base: String = if mnem == "ArgsMemLd" {
                l.pop()
            } else {
                String::new()
            };
            let dot: &str = if mnem == "ArgsMemLdWith" {
                "."
            } else if base.is_empty() {
                ""
            } else {
                "."
            };
            l.stack
                .push(format!("{base}{dot}{name}({})", join_args(&args)));
            true
        }
        "IndexLd" => {
            let argc: usize = call_arg_count(rest).max(1);
            let args: Vec<String> = l.pop_n(argc);
            let base: String = l.pop();
            l.stack.push(format!("{base}({})", join_args(&args)));
            true
        }
        "Add" => {
            binary(l, "+");
            true
        }
        "Sub" => {
            binary(l, "-");
            true
        }
        "Mul" => {
            binary(l, "*");
            true
        }
        "Div" => {
            binary(l, "/");
            true
        }
        "IDiv" => {
            binary(l, "\\");
            true
        }
        "Mod" => {
            binary(l, "Mod");
            true
        }
        "Pwr" => {
            binary(l, "^");
            true
        }
        "Concat" => {
            binary(l, "&");
            true
        }
        "And" => {
            binary(l, "And");
            true
        }
        "Or" => {
            binary(l, "Or");
            true
        }
        "Xor" => {
            binary(l, "Xor");
            true
        }
        "Eqv" => {
            binary(l, "Eqv");
            true
        }
        "Imp" => {
            binary(l, "Imp");
            true
        }
        "Eq" => {
            binary(l, "=");
            true
        }
        "Ne" => {
            binary(l, "<>");
            true
        }
        "Le" => {
            binary(l, "<=");
            true
        }
        "Ge" => {
            binary(l, ">=");
            true
        }
        "Lt" => {
            binary(l, "<");
            true
        }
        "Gt" => {
            binary(l, ">");
            true
        }
        "Like" => {
            binary(l, "Like");
            true
        }
        "Is" => {
            binary(l, "Is");
            true
        }
        "Not" => {
            unary_prefix(l, "Not ");
            true
        }
        "UMi" => {
            unary_prefix(l, "-");
            true
        }
        "Paren" => {
            let v: String = l.pop();
            l.stack.push(format!("({v})"));
            true
        }
        "FnAbs" | "FnFix" | "FnInt" | "FnSgn" | "FnLen" | "FnLenB" => {
            let v: String = l.pop();
            let fname: &str = mnem.strip_prefix("Fn").unwrap_or(mnem);
            l.stack.push(format!("{fname}({v})"));
            true
        }
        "St" | "SetOrSt" => {
            let value: String = l.pop();
            let target: &str = first_operand(rest);
            l.emit(format!("{target} = {value}"));
            true
        }
        "MemSt" => {
            let value: String = l.pop();
            let name: &str = first_operand(rest);
            let base: String = l.pop();
            l.emit(format!("{base}.{name} = {value}"));
            true
        }
        "Set" | "SetStmt" => {
            let value: String = l.pop();
            let target: &str = first_operand(rest);
            l.emit(format!("Set {target} = {value}"));
            true
        }
        "ArgsCall" | "ArgsMemCall" | "ArgsMemCallWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let args: Vec<String> = l.pop_n(argc);
            let base: String = if mnem == "ArgsMemCall" {
                l.pop()
            } else {
                String::new()
            };
            let prefix: String = match mnem {
                "ArgsMemCallWith" => format!(".{name}"),
                "ArgsMemCall" => format!("{base}.{name}"),
                _ => name.to_owned(),
            };
            if args.is_empty() {
                l.emit(prefix);
            } else {
                l.emit(format!("{prefix} {}", join_args(&args)));
            }
            true
        }
        "FuncDefn" | "FuncDefnSave" => {
            let header: String = signature_header(line);
            l.open(BlockKind::Procedure, header);
            true
        }
        "EndSub" => {
            l.close("End Sub".to_owned());
            true
        }
        "EndFunc" => {
            l.relabel_procedure("Function");
            l.close("End Function".to_owned());
            true
        }
        "EndProp" => {
            l.relabel_procedure("Property");
            l.close("End Property".to_owned());
            true
        }
        "If" | "IfBlock" => {
            let cond: String = l.pop();
            l.open(BlockKind::If, format!("If {cond} Then"));
            true
        }
        "Else" | "ElseBlock" => {
            if l.indent > 0 {
                l.indent -= 1;
            }
            l.emit("Else".to_owned());
            l.indent += 1;
            true
        }
        "ElseIfBlock" => {
            let cond: String = l.pop();
            if l.indent > 0 {
                l.indent -= 1;
            }
            l.emit(format!("ElseIf {cond} Then"));
            l.indent += 1;
            true
        }
        "EndIf" | "EndIfBlock" => {
            l.close("End If".to_owned());
            true
        }
        "For" | "ForStep" => {
            let limit: String = l.pop();
            let init: String = l.pop();
            let var: String = l.pop();
            let step: String = if mnem == "ForStep" {
                let s: String = l.pop();
                format!(" Step {s}")
            } else {
                String::new()
            };
            l.open(
                BlockKind::For,
                format!("For {var} = {init} To {limit}{step}"),
            );
            true
        }
        "ForEach" | "ForEachAs" => {
            let coll: String = l.pop();
            let var: String = l.pop();
            l.open(BlockKind::ForEach, format!("For Each {var} In {coll}"));
            true
        }
        "Next" | "NextVar" => {
            l.close("Next".to_owned());
            true
        }
        "Do" => {
            l.open(BlockKind::Do, "Do".to_owned());
            true
        }
        "DoWhile" => {
            let cond: String = l.pop();
            l.open(BlockKind::Do, format!("Do While {cond}"));
            true
        }
        "DoUnitil" => {
            let cond: String = l.pop();
            l.open(BlockKind::Do, format!("Do Until {cond}"));
            true
        }
        "Loop" => {
            l.close("Loop".to_owned());
            true
        }
        "LoopWhile" => {
            let cond: String = l.pop();
            l.close(format!("Loop While {cond}"));
            true
        }
        "LoopUntil" => {
            let cond: String = l.pop();
            l.close(format!("Loop Until {cond}"));
            true
        }
        "While" => {
            let cond: String = l.pop();
            l.open(BlockKind::While, format!("While {cond}"));
            true
        }
        "Wend" => {
            l.close("Wend".to_owned());
            true
        }
        "With" | "StartWithExpr" => {
            let obj: String = l.pop();
            l.open(BlockKind::With, format!("With {obj}"));
            true
        }
        "EndWith" => {
            l.close("End With".to_owned());
            true
        }
        "SelectCase" | "SelectType" => {
            let sel: String = l.pop();
            l.open(BlockKind::Select, format!("Select Case {sel}"));
            true
        }
        "Case" | "CaseEq" => {
            let v: String = l.pop();
            l.emit(format!("Case {v}"));
            true
        }
        "CaseElse" => {
            l.emit("Case Else".to_owned());
            true
        }
        "EndSelect" => {
            l.close("End Select".to_owned());
            true
        }
        "ExitSub" => {
            l.emit("Exit Sub".to_owned());
            true
        }
        "ExitFunc" => {
            l.emit("Exit Function".to_owned());
            true
        }
        "ExitFor" => {
            l.emit("Exit For".to_owned());
            true
        }
        "ExitDo" => {
            l.emit("Exit Do".to_owned());
            true
        }
        "ExitProp" => {
            l.emit("Exit Property".to_owned());
            true
        }
        "GoTo" => {
            l.emit(format!("GoTo {}", first_operand(rest)));
            true
        }
        "GoSub" => {
            l.emit(format!("GoSub {}", first_operand(rest)));
            true
        }
        "Label" => {
            l.emit(format!("{}:", first_operand(rest)));
            true
        }
        "OnError" => {
            l.emit(format!("On Error GoTo {}", first_operand(rest)));
            true
        }
        "Resume" => {
            let target: &str = first_operand(rest);
            if target.is_empty() {
                l.emit("Resume".to_owned());
            } else {
                l.emit(format!("Resume {target}"));
            }
            true
        }
        "Return" => {
            l.emit("Return".to_owned());
            true
        }
        "Stop" => {
            l.emit("Stop".to_owned());
            true
        }
        "End" => {
            l.emit("End".to_owned());
            true
        }
        "DoEvents" => {
            l.stack.push("DoEvents".to_owned());
            true
        }
        "Dim" | "DimImplicit" | "VarDefn" | "BoS" | "BoSImplicit" | "BoL" | "Coerce"
        | "CoerceVar" | "Paren0" | "EndContext" | "Context" | "LineCont" | "ParamByVal"
        | "ParamOmitted" => true,
        _ => false,
    }
}

#[must_use]
fn lit_number(mnem: &str, rest: &str) -> String {
    let words: Vec<u16> = rest
        .split_whitespace()
        .filter_map(|tok: &str| {
            tok.strip_prefix("0x")
                .and_then(|hex: &str| u16::from_str_radix(hex, 16).ok())
        })
        .collect();
    match mnem {
        "LitDI2" | "LitHI2" | "LitOI2" | "LitSmallI2" => {
            let v: i16 = words.first().copied().unwrap_or(0) as i16;
            v.to_string()
        }
        "LitDI4" | "LitHI4" | "LitOI4" => {
            let lo: u32 = words.first().copied().unwrap_or(0) as u32;
            let hi: u32 = words.get(1).copied().unwrap_or(0) as u32;
            ((hi << 16 | lo) as i32).to_string()
        }
        "LitR4" => {
            let lo: u32 = words.first().copied().unwrap_or(0) as u32;
            let hi: u32 = words.get(1).copied().unwrap_or(0) as u32;
            f32::from_bits(hi << 16 | lo).to_string()
        }
        "LitR8" => {
            let mut bits: u64 = 0;
            for (i, w) in words.iter().take(4).enumerate() {
                bits |= (*w as u64) << (16 * i);
            }
            f64::from_bits(bits).to_string()
        }
        _ => {
            let mut bits: u64 = 0;
            for (i, w) in words.iter().take(4).enumerate() {
                bits |= (*w as u64) << (16 * i);
            }
            (bits as i64).to_string()
        }
    }
}

#[must_use]
fn signature_header(line: &RealPCodeLine) -> String {
    for raw in line.text.lines() {
        let (mnem, rest): (&str, &str) = parse_mnemonic(raw.trim());
        if mnem == "ArgsCall" || mnem == "FuncDefn" || mnem == "FuncDefnSave" {
            let name: &str = first_operand(rest);
            if !name.is_empty() && !name.starts_with("func_") {
                return format!("Sub {name}()");
            }
        }
    }
    "Sub Main()".to_owned()
}

/// Lower a disassembled p-code module into readable VB pseudocode statement templates.
///
/// The lift is a deterministic stack-machine evaluator over the mnemonic stream produced
/// by [`super::pcode_real::disassemble_pcode_real`]; literals and loads push expression
/// fragments, operators fold them, and statement/control-flow opcodes emit indented lines.
/// Lines whose entire mnemonic stream is unrecognised are counted as `unlifted_lines` and
/// preserved as a disassembly comment so recovery is never silently fabricated.
#[must_use]
pub fn semantic_lift(module: &RealModuleDisasm) -> SemanticLift {
    let mut l: Lifter = Lifter::new();
    for line in &module.lines {
        let before_lifted: usize = l.lifted;
        let before_out: usize = l.out.len();
        lift_line(&mut l, line);
        if l.lifted == before_lifted && l.out.len() == before_out {
            let body: &str = line.text.trim();
            if !body.is_empty() && !body.contains("<empty>") {
                let first: &str = body.lines().next().unwrap_or(body);
                l.emit(format!("' [pcode] {first}"));
            }
        }
    }
    while !l.blocks.is_empty() {
        let kind: BlockKind = l.blocks[l.blocks.len() - 1].kind;
        let footer: &str = match kind {
            BlockKind::Procedure => "End Sub",
            BlockKind::If => "End If",
            BlockKind::For | BlockKind::ForEach => "Next",
            BlockKind::Do | BlockKind::While => "Loop",
            BlockKind::With => "End With",
            BlockKind::Select => "End Select",
        };
        l.walls.push(format!(
            "unterminated {kind:?} block closed synthetically with `{footer}`"
        ));
        l.close(footer.to_owned());
    }
    SemanticLift {
        module: module.name.clone(),
        pseudocode: l.out.join("\n"),
        lifted_lines: l.lifted,
        unlifted_lines: l.unlifted,
        walls: l.walls,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vba::pcode::PCodeInstruction;

    fn line(idx: usize, text: &str) -> RealPCodeLine {
        RealPCodeLine {
            line_index: idx,
            instructions: Vec::<PCodeInstruction>::new(),
            text: text.to_owned(),
        }
    }

    fn module(name: &str, lines: Vec<RealPCodeLine>) -> RealModuleDisasm {
        RealModuleDisasm {
            name: name.to_owned(),
            pcode_offset_in_stream: 0,
            num_lines: lines.len(),
            lines,
        }
    }

    #[test]
    fn lifts_msgbox_hello_world() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x000B \"hello world\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("MsgBox \"hello world\""),
            "lift output:\n{}",
            r.pseudocode
        );
        assert!(r.pseudocode.contains("End Sub"));
        assert_eq!(r.unlifted_lines, 0, "lift:\n{}", r.pseudocode);
        assert!(r.walls.is_empty());
    }

    #[test]
    fn lifts_assignment_and_arithmetic() {
        let m: RealModuleDisasm = module(
            "M",
            vec![line(
                0,
                "Ld a\nLitDI2 0x0002\nMul\nLitDI2 0x0003\nAdd\nSt result",
            )],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("result = a * 2 + 3"),
            "lift output:\n{}",
            r.pseudocode
        );
    }

    #[test]
    fn lifts_if_then_else_block() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "Ld x\nLitDI2 0x0000\nGt\nIfBlock"),
                line(1, "LitStr 0x0001 \"y\"\nArgsCall Print 0x0001"),
                line(2, "ElseBlock"),
                line(3, "LitStr 0x0001 \"n\"\nArgsCall Print 0x0001"),
                line(4, "EndIfBlock"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("If x > 0 Then"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("Else"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("End If"), "{}", r.pseudocode);
    }

    #[test]
    fn lifts_for_loop_with_member_call() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "Ld i\nLitDI2 0x0001\nLitDI2 0x000A\nFor"),
                line(1, "Ld obj\nLitStr 0x0001 \"v\"\nArgsMemCall Add 0x0001"),
                line(2, "Next"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("For i = 1 To 10"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("obj.Add \"v\""), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("Next"), "{}", r.pseudocode);
    }

    #[test]
    fn unterminated_block_records_wall() {
        let m: RealModuleDisasm = module(
            "M",
            vec![line(
                0,
                "FuncDefn func_0\nLitStr 0x01 \"x\"\nArgsCall Print 0x0001",
            )],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("End Sub"), "{}", r.pseudocode);
        assert_eq!(r.walls.len(), 1, "walls={:?}", r.walls);
    }

    #[test]
    fn unknown_mnemonic_preserved_not_fabricated() {
        let m: RealModuleDisasm = module("M", vec![line(0, "Unknown_0F3A (raw=0x1234)")]);
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("' [pcode] Unknown_0F3A"),
            "{}",
            r.pseudocode
        );
        assert_eq!(r.lifted_lines, 0);
    }
}
