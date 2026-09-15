use disrobe_mba::{Expr, Width, equivalent_exhaustive};
use iced_x86::code_asm::{CodeAssembler, eax, ecx, edx, esi};

use super::*;

const BASE: u64 = 0x3000;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble substitution")
}

fn parse_back(text: &str) -> Option<Expr> {
    parse_expr(&mut Cursor::new(text))
}

#[test]
fn xor_plus_twice_and_simplifies_to_add() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.xor(ecx, edx).unwrap();
    asm.mov(eax, esi).unwrap();
    asm.and(eax, edx).unwrap();
    asm.add(eax, eax).unwrap();
    asm.add(eax, ecx).unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);

    let result: SubstitutionResult =
        simplify_sequence(64, BASE, &bytes).expect("arith sequence lifts");
    assert!(
        result.changed,
        "the substituted form must simplify, original = {}",
        result.original_expr
    );
    assert!(
        result.proven,
        "the rewrite must be exhaustively proven equivalent"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "simplified expression must be smaller: {} -> {}",
        result.original_nodes,
        result.simplified_nodes
    );
    let simplified: Expr = parse_back(&result.simplified_expr).expect("re-parse simplified expr");
    let expected: Expr = Expr::add(Expr::var(0), Expr::var(1));
    assert!(
        equivalent_exhaustive(&simplified, &expected, Width::W8, 2),
        "expected esi + edx, got `{}`",
        result.simplified_expr
    );
}

#[test]
fn subtract_self_folds_to_zero() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, ecx).unwrap();
    asm.sub(eax, ecx).unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    let result: SubstitutionResult = simplify_sequence(64, BASE, &bytes).expect("lifts");
    let simplified: Expr = parse_back(&result.simplified_expr).expect("re-parse");
    assert!(
        equivalent_exhaustive(&simplified, &Expr::konst(0), Width::W8, 1),
        "x - x must fold to 0, got `{}`",
        result.simplified_expr
    );
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos] == b' ' {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        self.skip_ws();
        let byte: u8 = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }
}

fn parse_expr(cursor: &mut Cursor<'_>) -> Option<Expr> {
    let byte: u8 = cursor.peek()?;
    match byte {
        b'(' => parse_binary(cursor),
        b'~' => {
            cursor.bump();
            Some(Expr::not(parse_expr(cursor)?))
        }
        b'-' => {
            cursor.bump();
            Some(Expr::neg(parse_expr(cursor)?))
        }
        b'v' => parse_var(cursor),
        b'0'..=b'9' => parse_const(cursor),
        _ => None,
    }
}

fn parse_binary(cursor: &mut Cursor<'_>) -> Option<Expr> {
    if cursor.bump()? != b'(' {
        return None;
    }
    let left: Expr = parse_expr(cursor)?;
    let op: u8 = cursor.bump()?;
    let right: Expr = parse_expr(cursor)?;
    if cursor.bump()? != b')' {
        return None;
    }
    match op {
        b'+' => Some(Expr::add(left, right)),
        b'-' => Some(Expr::sub(left, right)),
        b'*' => Some(Expr::mul(left, right)),
        b'&' => Some(Expr::and(left, right)),
        b'|' => Some(Expr::or(left, right)),
        b'^' => Some(Expr::xor(left, right)),
        _ => None,
    }
}

fn parse_var(cursor: &mut Cursor<'_>) -> Option<Expr> {
    cursor.bump();
    let mut value: u32 = 0;
    let mut seen: bool = false;
    while let Some(byte) = cursor.bytes.get(cursor.pos).copied() {
        if byte.is_ascii_digit() {
            value = value * 10 + u32::from(byte - b'0');
            cursor.pos += 1;
            seen = true;
        } else {
            break;
        }
    }
    seen.then_some(Expr::var(value))
}

fn parse_const(cursor: &mut Cursor<'_>) -> Option<Expr> {
    let mut value: u64 = 0;
    let mut seen: bool = false;
    while let Some(byte) = cursor.bytes.get(cursor.pos).copied() {
        if byte.is_ascii_digit() {
            value = value * 10 + u64::from(byte - b'0');
            cursor.pos += 1;
            seen = true;
        } else {
            break;
        }
    }
    seen.then_some(Expr::konst(value))
}
