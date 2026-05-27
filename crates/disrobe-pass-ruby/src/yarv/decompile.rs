use serde::{Deserialize, Serialize};

use crate::yarv::disasm::{YarvDisasm, YarvInstruction};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvDecompiled {
    pub source: String,
    pub statement_count: u32,
    pub fidelity: Fidelity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fidelity {
    Lossy,
    StructuralOnly,
}

#[must_use]
pub fn decompile(d: &YarvDisasm) -> YarvDecompiled {
    let mut stack: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for ins in &d.instructions {
        translate(ins, &mut stack, &mut lines);
    }
    lines.extend(core::mem::take(&mut stack));
    let mut out: String =
        String::with_capacity(lines.iter().map(String::len).sum::<usize>() + lines.len());
    for line in &lines {
        out.push_str(line);
        out.push('\n');
    }
    let statement_count: u32 = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    YarvDecompiled {
        source: out,
        statement_count,
        fidelity: Fidelity::Lossy,
    }
}

fn translate(ins: &YarvInstruction, stack: &mut Vec<String>, lines: &mut Vec<String>) {
    let mnem: &str = ins.mnemonic.as_str();
    if translate_push(mnem, ins, stack) {
        return;
    }
    if translate_assign(mnem, ins, stack, lines) {
        return;
    }
    if translate_compound(mnem, ins, stack) {
        return;
    }
    if translate_binop(mnem, stack) {
        return;
    }
    translate_control_or_unknown(mnem, ins, stack, lines);
}

fn translate_push(mnem: &str, ins: &YarvInstruction, stack: &mut Vec<String>) -> bool {
    let arg: u32 = ins.operands.first().copied().unwrap_or(0);
    match mnem {
        "nop" => true,
        "putnil" => {
            stack.push("nil".to_owned());
            true
        }
        "putself" => {
            stack.push("self".to_owned());
            true
        }
        "putobject" => {
            stack.push(format!("OBJ#{arg}"));
            true
        }
        "putstring" => {
            stack.push(format!("STR#{arg}"));
            true
        }
        "putiseq" => {
            stack.push(format!("ISEQ#{arg}"));
            true
        }
        "getlocal" | "getlocal_OP__WC__0" | "getlocal_OP__WC__1" => {
            stack.push(format!("local_{arg}"));
            true
        }
        "getinstancevariable" => {
            stack.push(format!("@ivar_{arg}"));
            true
        }
        "getconstant" => {
            stack.push(format!("CONST_{arg}"));
            true
        }
        _ => false,
    }
}

fn translate_assign(
    mnem: &str,
    ins: &YarvInstruction,
    stack: &mut Vec<String>,
    lines: &mut Vec<String>,
) -> bool {
    let arg: u32 = ins.operands.first().copied().unwrap_or(0);
    let pop_rhs = |s: &mut Vec<String>| -> String { s.pop().unwrap_or_else(|| "nil".to_owned()) };
    match mnem {
        "setlocal" | "setlocal_OP__WC__0" | "setlocal_OP__WC__1" => {
            let rhs: String = pop_rhs(stack);
            lines.push(format!("local_{arg} = {rhs}"));
            true
        }
        "setinstancevariable" => {
            let rhs: String = pop_rhs(stack);
            lines.push(format!("@ivar_{arg} = {rhs}"));
            true
        }
        "setconstant" => {
            let rhs: String = pop_rhs(stack);
            lines.push(format!("CONST_{arg} = {rhs}"));
            true
        }
        _ => false,
    }
}

fn translate_compound(mnem: &str, ins: &YarvInstruction, stack: &mut Vec<String>) -> bool {
    let count: usize = ins.operands.first().copied().unwrap_or(0) as usize;
    match mnem {
        "newarray" => {
            let items: Vec<String> = take_n(stack, count);
            stack.push(format!("[{}]", items.join(", ")));
            true
        }
        "newhash" => {
            let items: Vec<String> = take_n(stack, count);
            stack.push(format!("{{{}}}", items.join(", ")));
            true
        }
        "newrange" => {
            let high: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
            let low: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
            stack.push(format!("({low}..{high})"));
            true
        }
        "concatstrings" => {
            let parts: Vec<String> = take_n(stack, count);
            stack.push(parts.join(" + "));
            true
        }
        "opt_send_without_block" | "send" => {
            let recv: String = stack.pop().unwrap_or_else(|| "self".to_owned());
            stack.push(format!("{recv}.call_{:?}", ins.operands));
            true
        }
        _ => false,
    }
}

fn translate_binop(mnem: &str, stack: &mut Vec<String>) -> bool {
    let op: Option<&str> = match mnem {
        "opt_plus" => Some("+"),
        "opt_minus" => Some("-"),
        "opt_mult" => Some("*"),
        "opt_div" => Some("/"),
        "opt_mod" => Some("%"),
        "opt_eq" => Some("=="),
        "opt_lt" => Some("<"),
        "opt_le" => Some("<="),
        "opt_gt" => Some(">"),
        "opt_ge" => Some(">="),
        _ => None,
    };
    let Some(op) = op else {
        return false;
    };
    let rhs: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
    let lhs: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
    stack.push(format!("({lhs} {op} {rhs})"));
    true
}

fn translate_control_or_unknown(
    mnem: &str,
    ins: &YarvInstruction,
    stack: &mut Vec<String>,
    lines: &mut Vec<String>,
) {
    let target: u32 = ins.operands.first().copied().unwrap_or(0);
    match mnem {
        "pop" => {
            if let Some(expr) = stack.pop() {
                lines.push(expr);
            }
        }
        "leave" => match stack.pop() {
            Some(expr) => lines.push(format!("return {expr}")),
            None => lines.push("return".to_owned()),
        },
        "jump" => lines.push(format!("goto {target}")),
        "branchif" => {
            let cond: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
            lines.push(format!("if {cond}; goto {target}; end"));
        }
        "branchunless" => {
            let cond: String = stack.pop().unwrap_or_else(|| "nil".to_owned());
            lines.push(format!("unless {cond}; goto {target}; end"));
        }
        other => lines.push(format!("# unhandled: {other} {:?}", ins.operands)),
    }
}

#[inline]
fn take_n(stack: &mut Vec<String>, count: usize) -> Vec<String> {
    let n: usize = stack.len().min(count);
    let from: usize = stack.len() - n;
    stack.split_off(from)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::yarv::disasm::{YarvDisasm, YarvInstruction};
    use crate::yarv::opcodes::YarvVersion;

    fn ins(mnem: &str, ops: Vec<u32>) -> YarvInstruction {
        YarvInstruction {
            offset: 0,
            opcode: 0,
            mnemonic: mnem.to_owned(),
            operands: ops,
        }
    }

    fn disasm(items: Vec<YarvInstruction>) -> YarvDisasm {
        YarvDisasm {
            version: YarvVersion::new(3, 2),
            instructions: items,
            iseq_label: "<top>".to_owned(),
        }
    }

    #[test]
    fn decompile_return_one_plus_two() {
        let d: YarvDisasm = disasm(vec![
            ins("putobject", vec![1]),
            ins("putobject", vec![2]),
            ins("opt_plus", vec![0]),
            ins("leave", vec![]),
        ]);
        let out: YarvDecompiled = decompile(&d);
        assert!(out.source.contains("return (OBJ#1 + OBJ#2)"));
    }

    #[test]
    fn decompile_local_assignment() {
        let d: YarvDisasm = disasm(vec![
            ins("putobject", vec![42]),
            ins("setlocal", vec![3, 0]),
            ins("leave", vec![]),
        ]);
        let out: YarvDecompiled = decompile(&d);
        assert!(out.source.contains("local_3 = OBJ#42"));
    }
}
