use std::collections::BTreeSet;

use crate::error::{GeneratorError, GeneratorResult};
use crate::term::{MAX_TERM_DEPTH, MAX_TERM_NODES, Op, Term};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarMap {
    names: Vec<String>,
}

impl VarMap {
    #[must_use]
    pub fn from_names(names: &BTreeSet<String>) -> Self {
        Self {
            names: names.iter().cloned().collect(),
        }
    }

    #[must_use]
    pub fn index_of(&self, name: &str) -> Option<u32> {
        self.names
            .iter()
            .position(|candidate: &String| candidate == name)
            .and_then(|position: usize| u32::try_from(position).ok())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.names.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[must_use]
pub fn scan_identifiers(text: &str) -> BTreeSet<String> {
    let bytes: &[u8] = text.as_bytes();
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let byte: u8 = bytes[cursor];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start: usize = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            if let Some(slice) = text.get(start..cursor) {
                found.insert(slice.to_owned());
            }
        } else {
            cursor += 1;
        }
    }
    found
}

#[derive(Debug)]
struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    cursor: usize,
    context: &'a str,
    nodes: usize,
}

impl<'a> Scanner<'a> {
    const fn new(text: &'a str, context: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            cursor: 0,
            context,
            nodes: 0,
        }
    }

    fn skip_space(&mut self) {
        while self.cursor < self.bytes.len() && self.bytes[self.cursor].is_ascii_whitespace() {
            self.cursor += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.bytes.get(self.cursor).copied()
    }

    fn eat(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn eat_pair(&mut self, first: u8, second: u8) -> bool {
        self.skip_space();
        if self.bytes.get(self.cursor).copied() == Some(first)
            && self.bytes.get(self.cursor + 1).copied() == Some(second)
        {
            self.cursor += 2;
            true
        } else {
            false
        }
    }

    const fn charge(&mut self) -> GeneratorResult<()> {
        self.nodes += 1;
        if self.nodes > MAX_TERM_NODES {
            return Err(GeneratorError::NodeBudget {
                limit: MAX_TERM_NODES,
            });
        }
        Ok(())
    }

    fn unexpected(&self) -> GeneratorError {
        self.bytes.get(self.cursor).copied().map_or_else(
            || GeneratorError::UnexpectedEnd {
                context: self.context.to_owned(),
            },
            |byte: u8| GeneratorError::UnexpectedCharacter {
                found: char::from(byte),
                offset: self.cursor,
                context: self.context.to_owned(),
            },
        )
    }
}

const LEVEL_OR: u8 = 0;
const LEVEL_XOR: u8 = 1;
const LEVEL_AND: u8 = 2;
const LEVEL_SHIFT: u8 = 3;
const LEVEL_SUM: u8 = 4;
const LEVEL_PRODUCT: u8 = 5;

pub fn parse_infix(text: &str, vars: &VarMap, context: &str) -> GeneratorResult<Term> {
    let mut scanner: Scanner<'_> = Scanner::new(text, context);
    let parsed: Term = parse_level(&mut scanner, vars, LEVEL_OR, 0)?;
    scanner.skip_space();
    if scanner.cursor != scanner.bytes.len() {
        return Err(GeneratorError::TrailingInput {
            offset: scanner.cursor,
            context: context.to_owned(),
        });
    }
    Ok(parsed)
}

fn parse_level(
    scanner: &mut Scanner<'_>,
    vars: &VarMap,
    level: u8,
    depth: usize,
) -> GeneratorResult<Term> {
    if depth > MAX_TERM_DEPTH {
        return Err(GeneratorError::DepthBudget {
            limit: MAX_TERM_DEPTH,
        });
    }
    if level > LEVEL_PRODUCT {
        return parse_unary(scanner, vars, depth + 1);
    }
    let mut left: Term = parse_level(scanner, vars, level + 1, depth + 1)?;
    loop {
        let Some(op) = match_operator(scanner, level) else {
            return Ok(left);
        };
        let right: Term = parse_level(scanner, vars, level + 1, depth + 1)?;
        scanner.charge()?;
        left = Term::bin(op, left, right);
    }
}

fn match_operator(scanner: &mut Scanner<'_>, level: u8) -> Option<Op> {
    match level {
        LEVEL_OR => scanner.eat(b'|').then_some(Op::Or),
        LEVEL_XOR => scanner.eat(b'^').then_some(Op::Xor),
        LEVEL_AND => scanner.eat(b'&').then_some(Op::And),
        LEVEL_SHIFT => {
            if scanner.eat_pair(b'<', b'<') {
                Some(Op::Shl)
            } else if scanner.eat_pair(b'>', b'>') {
                Some(Op::Shr)
            } else {
                None
            }
        }
        LEVEL_SUM => {
            if scanner.eat(b'+') {
                Some(Op::Add)
            } else if scanner.eat(b'-') {
                Some(Op::Sub)
            } else {
                None
            }
        }
        LEVEL_PRODUCT => scanner.eat(b'*').then_some(Op::Mul),
        _ => None,
    }
}

fn parse_unary(scanner: &mut Scanner<'_>, vars: &VarMap, depth: usize) -> GeneratorResult<Term> {
    if depth > MAX_TERM_DEPTH {
        return Err(GeneratorError::DepthBudget {
            limit: MAX_TERM_DEPTH,
        });
    }
    match scanner.peek() {
        Some(b'-') => {
            scanner.cursor += 1;
            let inner: Term = parse_unary(scanner, vars, depth + 1)?;
            scanner.charge()?;
            Ok(Term::neg(inner))
        }
        Some(b'~') => {
            scanner.cursor += 1;
            let inner: Term = parse_unary(scanner, vars, depth + 1)?;
            scanner.charge()?;
            Ok(Term::not(inner))
        }
        Some(b'+') => {
            scanner.cursor += 1;
            parse_unary(scanner, vars, depth + 1)
        }
        _ => parse_atom(scanner, vars, depth + 1),
    }
}

fn parse_atom(scanner: &mut Scanner<'_>, vars: &VarMap, depth: usize) -> GeneratorResult<Term> {
    let Some(byte) = scanner.peek() else {
        return Err(GeneratorError::UnexpectedEnd {
            context: scanner.context.to_owned(),
        });
    };
    if byte == b'(' {
        scanner.cursor += 1;
        let inner: Term = parse_level(scanner, vars, LEVEL_OR, depth + 1)?;
        if !scanner.eat(b')') {
            return Err(scanner.unexpected());
        }
        return Ok(inner);
    }
    if byte.is_ascii_digit() {
        return parse_number(scanner);
    }
    if byte.is_ascii_alphabetic() || byte == b'_' {
        let start: usize = scanner.cursor;
        while scanner.cursor < scanner.bytes.len()
            && (scanner.bytes[scanner.cursor].is_ascii_alphanumeric()
                || scanner.bytes[scanner.cursor] == b'_')
        {
            scanner.cursor += 1;
        }
        let Some(name) = scanner.text.get(start..scanner.cursor) else {
            return Err(scanner.unexpected());
        };
        let Some(index) = vars.index_of(name) else {
            return Err(GeneratorError::UnknownIdentifier {
                name: name.to_owned(),
                context: scanner.context.to_owned(),
            });
        };
        scanner.charge()?;
        return Ok(Term::var(index));
    }
    Err(scanner.unexpected())
}

fn parse_number(scanner: &mut Scanner<'_>) -> GeneratorResult<Term> {
    let start: usize = scanner.cursor;
    let hexadecimal: bool = scanner.bytes.get(scanner.cursor).copied() == Some(b'0')
        && matches!(
            scanner.bytes.get(scanner.cursor + 1).copied(),
            Some(b'x' | b'X')
        );
    if hexadecimal {
        scanner.cursor += 2;
        while scanner.cursor < scanner.bytes.len()
            && scanner.bytes[scanner.cursor].is_ascii_hexdigit()
        {
            scanner.cursor += 1;
        }
    } else {
        while scanner.cursor < scanner.bytes.len() && scanner.bytes[scanner.cursor].is_ascii_digit()
        {
            scanner.cursor += 1;
        }
    }
    let Some(literal) = scanner.text.get(start..scanner.cursor) else {
        return Err(scanner.unexpected());
    };
    let value: u64 = if hexadecimal {
        let Some(digits) = literal.get(2..) else {
            return Err(GeneratorError::LiteralOutOfRange {
                literal: literal.to_owned(),
            });
        };
        u64::from_str_radix(digits, 16)
    } else {
        literal.parse::<u64>()
    }
    .map_err(|_| GeneratorError::LiteralOutOfRange {
        literal: literal.to_owned(),
    })?;
    scanner.charge()?;
    Ok(Term::constant(value))
}

pub fn parse_prefix(text: &str) -> GeneratorResult<Term> {
    let mut scanner: Scanner<'_> = Scanner::new(text, "prefix term");
    let parsed: Term = parse_prefix_node(&mut scanner, 0)?;
    scanner.skip_space();
    if scanner.cursor != scanner.bytes.len() {
        return Err(GeneratorError::TrailingInput {
            offset: scanner.cursor,
            context: "prefix term".to_owned(),
        });
    }
    Ok(parsed)
}

fn parse_prefix_node(scanner: &mut Scanner<'_>, depth: usize) -> GeneratorResult<Term> {
    if depth > MAX_TERM_DEPTH {
        return Err(GeneratorError::DepthBudget {
            limit: MAX_TERM_DEPTH,
        });
    }
    if !scanner.eat(b'(') {
        return Err(scanner.unexpected());
    }
    let start: usize = scanner.cursor;
    while scanner.cursor < scanner.bytes.len()
        && scanner.bytes[scanner.cursor].is_ascii_alphabetic()
    {
        scanner.cursor += 1;
    }
    let Some(tag) = scanner.text.get(start..scanner.cursor) else {
        return Err(scanner.unexpected());
    };
    let node: Term = match tag {
        "const" => {
            let value: u64 = parse_prefix_integer(scanner)?;
            Term::constant(value)
        }
        "var" => {
            let raw: u64 = parse_prefix_integer(scanner)?;
            let index: u32 = u32::try_from(raw).map_err(|_| GeneratorError::LiteralOutOfRange {
                literal: raw.to_string(),
            })?;
            Term::var(index)
        }
        "neg" => Term::neg(parse_prefix_node(scanner, depth + 1)?),
        "not" => Term::not(parse_prefix_node(scanner, depth + 1)?),
        other => {
            let Some(op) = Op::from_tag(other) else {
                return Err(GeneratorError::UnknownOperator {
                    tag: other.to_owned(),
                    context: "prefix term".to_owned(),
                });
            };
            let left: Term = parse_prefix_node(scanner, depth + 1)?;
            let right: Term = parse_prefix_node(scanner, depth + 1)?;
            Term::bin(op, left, right)
        }
    };
    scanner.charge()?;
    if !scanner.eat(b')') {
        return Err(scanner.unexpected());
    }
    Ok(node)
}

fn parse_prefix_integer(scanner: &mut Scanner<'_>) -> GeneratorResult<u64> {
    scanner.skip_space();
    let start: usize = scanner.cursor;
    while scanner.cursor < scanner.bytes.len() && scanner.bytes[scanner.cursor].is_ascii_digit() {
        scanner.cursor += 1;
    }
    let Some(literal) = scanner.text.get(start..scanner.cursor) else {
        return Err(scanner.unexpected());
    };
    literal
        .parse::<u64>()
        .map_err(|_| GeneratorError::LiteralOutOfRange {
            literal: literal.to_owned(),
        })
}
