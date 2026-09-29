#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_shell::vba::vbs::{VbsReport, deobfuscate_vbs};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Str(String),
    Num(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Str(String),
    Num(i64),
    Ident(String),
    Op(char),
    IntDiv,
}

const MAX_OUTPUT_CHARS: usize = 1 << 16;
const MAX_DEPTH: usize = 64;

const WINDOWS_1252_HIGH: [u32; 32] = [
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
    0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
];

fn lex(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        match c {
            ' ' | '\t' => i += 1,
            '"' => {
                let mut value: String = String::new();
                i += 1;
                loop {
                    match (chars.get(i), chars.get(i + 1)) {
                        (Some('"'), Some('"')) => {
                            value.push('"');
                            i += 2;
                        }
                        (Some('"'), _) => {
                            i += 1;
                            break;
                        }
                        (Some(ch), _) => {
                            value.push(*ch);
                            i += 1;
                        }
                        (None, _) => return Err("unterminated string".to_owned()),
                    }
                }
                tokens.push(Token::Str(value));
            }
            '&' if chars
                .get(i + 1)
                .is_some_and(|n: &char| n.eq_ignore_ascii_case(&'h')) =>
            {
                let start: usize = i + 2;
                let mut end: usize = start;
                while chars.get(end).is_some_and(char::is_ascii_hexdigit) {
                    end += 1;
                }
                let digits: String = chars[start..end].iter().collect();
                let value: i64 =
                    i64::from_str_radix(&digits, 16).map_err(|e| format!("hex literal: {e}"))?;
                tokens.push(Token::Num(value));
                i = end;
            }
            '0'..='9' => {
                let start: usize = i;
                while chars.get(i).is_some_and(char::is_ascii_digit) {
                    i += 1;
                }
                let digits: String = chars[start..i].iter().collect();
                tokens.push(Token::Num(
                    digits.parse::<i64>().map_err(|e| format!("number: {e}"))?,
                ));
            }
            'A'..='Z' | 'a'..='z' | '_' => {
                let start: usize = i;
                while chars
                    .get(i)
                    .is_some_and(|ch: &char| ch.is_ascii_alphanumeric() || *ch == '_')
                {
                    i += 1;
                }
                let name: String = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase();
                tokens.push(Token::Ident(name));
            }
            '\\' => {
                tokens.push(Token::IntDiv);
                i += 1;
            }
            '&' | '+' | '-' | '*' | '/' | '^' | '(' | ')' | ',' => {
                tokens.push(Token::Op(c));
                i += 1;
            }
            other => return Err(format!("unexpected character {other:?}")),
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn eat(&mut self, op: char) -> bool {
        if self.peek() == Some(&Token::Op(op)) {
            self.at += 1;
            return true;
        }
        false
    }

    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("expression nests too deeply".to_owned());
        }
        Ok(())
    }

    fn concatenation(&mut self) -> Result<Value, String> {
        self.enter()?;
        let mut left: Value = self.additive()?;
        while self.eat('&') {
            let right: Value = self.additive()?;
            left = Value::Str(format!("{}{}", as_text(&left), as_text(&right)));
            bounded(&left)?;
        }
        self.depth -= 1;
        Ok(left)
    }

    fn additive(&mut self) -> Result<Value, String> {
        let mut left: Value = self.int_division()?;
        loop {
            if self.eat('+') {
                let right: Value = self.int_division()?;
                left = match (left, right) {
                    (Value::Str(a), Value::Str(b)) => Value::Str(a + &b),
                    (a, b) => Value::Num(
                        as_number(&a)?
                            .checked_add(as_number(&b)?)
                            .ok_or("overflow")?,
                    ),
                };
                bounded(&left)?;
            } else if self.eat('-') {
                let right: Value = self.int_division()?;
                left = Value::Num(
                    as_number(&left)?
                        .checked_sub(as_number(&right)?)
                        .ok_or("overflow")?,
                );
            } else {
                return Ok(left);
            }
        }
    }

    fn int_division(&mut self) -> Result<Value, String> {
        let mut left: Value = self.multiplicative()?;
        while self.peek() == Some(&Token::IntDiv) {
            self.at += 1;
            let right: i64 = as_number(&self.multiplicative()?)?;
            if right == 0 {
                return Err("division by zero".to_owned());
            }
            left = Value::Num(as_number(&left)?.checked_div(right).ok_or("overflow")?);
        }
        Ok(left)
    }

    fn multiplicative(&mut self) -> Result<Value, String> {
        let mut left: Value = self.unary()?;
        loop {
            if self.eat('*') {
                let right: i64 = as_number(&self.unary()?)?;
                left = Value::Num(as_number(&left)?.checked_mul(right).ok_or("overflow")?);
            } else if self.peek() == Some(&Token::Op('/')) {
                return Err("floating division is outside the evaluated subset".to_owned());
            } else {
                return Ok(left);
            }
        }
    }

    fn unary(&mut self) -> Result<Value, String> {
        if self.eat('-') {
            let value: i64 = as_number(&self.unary()?)?;
            return Ok(Value::Num(value.checked_neg().ok_or("overflow")?));
        }
        let base: Value = self.primary()?;
        if self.eat('^') {
            return Err("exponentiation is outside the evaluated subset".to_owned());
        }
        Ok(base)
    }

    fn arguments(&mut self) -> Result<Vec<Value>, String> {
        if !self.eat('(') {
            return Err("expected an argument list".to_owned());
        }
        let mut args: Vec<Value> = Vec::new();
        if self.eat(')') {
            return Ok(args);
        }
        loop {
            args.push(self.concatenation()?);
            if self.eat(')') {
                return Ok(args);
            }
            if !self.eat(',') {
                return Err("expected `,` or `)`".to_owned());
            }
        }
    }

    fn primary(&mut self) -> Result<Value, String> {
        match self.tokens.get(self.at).cloned() {
            Some(Token::Str(s)) => {
                self.at += 1;
                Ok(Value::Str(s))
            }
            Some(Token::Num(n)) => {
                self.at += 1;
                Ok(Value::Num(n))
            }
            Some(Token::Op('(')) => {
                self.at += 1;
                let inner: Value = self.concatenation()?;
                if !self.eat(')') {
                    return Err("expected `)`".to_owned());
                }
                Ok(inner)
            }
            Some(Token::Ident(name)) => {
                self.at += 1;
                let args: Vec<Value> = self.arguments()?;
                call(&name, &args)
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

fn bounded(value: &Value) -> Result<(), String> {
    match value {
        Value::Str(s) if s.chars().count() > MAX_OUTPUT_CHARS => Err("string too long".to_owned()),
        _ => Ok(()),
    }
}

fn as_text(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        Value::Num(n) => n.to_string(),
    }
}

fn as_number(value: &Value) -> Result<i64, String> {
    match value {
        Value::Num(n) => Ok(*n),
        Value::Str(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("type mismatch: {s:?} is not a number")),
    }
}

fn string_arg(args: &[Value], index: usize) -> Result<String, String> {
    args.get(index)
        .map(as_text)
        .ok_or_else(|| format!("missing argument {index}"))
}

fn number_arg(args: &[Value], index: usize) -> Result<i64, String> {
    as_number(
        args.get(index)
            .ok_or_else(|| format!("missing argument {index}"))?,
    )
}

fn chr_ansi(code: i64) -> Result<char, String> {
    let code: u32 = u32::try_from(code).map_err(|_| "Chr out of range".to_owned())?;
    match code {
        0..=0x7F | 0xA0..=0xFF => char::from_u32(code).ok_or_else(|| "Chr".to_owned()),
        0x80..=0x9F => match WINDOWS_1252_HIGH[(code - 0x80) as usize] {
            0 => Err(format!("Chr({code}) has no Windows-1252 character")),
            mapped => char::from_u32(mapped).ok_or_else(|| "Chr".to_owned()),
        },
        _ => Err(format!("Chr({code}) is out of range")),
    }
}

fn chr_wide(code: i64) -> Result<char, String> {
    let unit: u32 = u32::try_from(code.rem_euclid(0x1_0000)).map_err(|_| "ChrW".to_owned())?;
    if !(-0x8000..=0xFFFF).contains(&code) {
        return Err(format!("ChrW({code}) is out of range"));
    }
    char::from_u32(unit).ok_or_else(|| format!("ChrW({code}) is a lone surrogate"))
}

fn call(name: &str, args: &[Value]) -> Result<Value, String> {
    let s = |i: usize| string_arg(args, i);
    let n = |i: usize| number_arg(args, i);
    let chars = |text: &str| text.chars().collect::<Vec<char>>();
    let value: Value = match name {
        "chr" => Value::Str(chr_ansi(n(0)?)?.to_string()),
        "chrw" => Value::Str(chr_wide(n(0)?)?.to_string()),
        "asc" | "ascw" => {
            let text: String = s(0)?;
            let first: char = text.chars().next().ok_or("Asc of an empty string")?;
            Value::Num(i64::from(u32::from(first)))
        }
        "strreverse" => Value::Str(s(0)?.chars().rev().collect()),
        "lcase" => Value::Str(s(0)?.to_lowercase()),
        "ucase" => Value::Str(s(0)?.to_uppercase()),
        "len" => Value::Num(i64::try_from(s(0)?.chars().count()).map_err(|_| "len")?),
        "cstr" => Value::Str(s(0)?),
        "space" => Value::Str(
            " ".repeat(
                usize::try_from(n(0)?)
                    .map_err(|_| "Space")?
                    .min(MAX_OUTPUT_CHARS),
            ),
        ),
        "string" => {
            let count: usize = usize::try_from(n(0)?).map_err(|_| "String count")?;
            let ch: char = match &args.get(1) {
                Some(Value::Num(code)) => chr_ansi(*code)?,
                Some(Value::Str(text)) => text.chars().next().ok_or("String of an empty string")?,
                None => return Err("String needs two arguments".to_owned()),
            };
            Value::Str(std::iter::repeat_n(ch, count.min(MAX_OUTPUT_CHARS)).collect())
        }
        "left" | "right" => {
            let text: Vec<char> = chars(&s(0)?);
            let count: usize = usize::try_from(n(1)?)
                .map_err(|_| "negative length")?
                .min(text.len());
            let slice: &[char] = if name == "left" {
                &text[..count]
            } else {
                &text[text.len() - count..]
            };
            Value::Str(slice.iter().collect())
        }
        "mid" => {
            let text: Vec<char> = chars(&s(0)?);
            let start: usize = usize::try_from(n(1)?).map_err(|_| "Mid start")?;
            if start == 0 {
                return Err("Mid start must be at least 1".to_owned());
            }
            let from: usize = (start - 1).min(text.len());
            let count: usize = if args.len() > 2 {
                usize::try_from(n(2)?).map_err(|_| "Mid length")?
            } else {
                text.len()
            };
            Value::Str(text[from..(from + count).min(text.len())].iter().collect())
        }
        "replace" => {
            let find: String = s(1)?;
            if find.is_empty() {
                Value::Str(s(0)?)
            } else {
                Value::Str(s(0)?.replace(&find, &s(2)?))
            }
        }
        other => return Err(format!("{other} is outside the evaluated subset")),
    };
    bounded(&value)?;
    Ok(value)
}

fn evaluate(expression: &str) -> Result<Value, String> {
    let mut parser: Parser = Parser {
        tokens: lex(expression)?,
        at: 0,
        depth: 0,
    };
    let value: Value = parser.concatenation()?;
    if parser.at != parser.tokens.len() {
        return Err(format!("trailing tokens in {expression:?}"));
    }
    Ok(value)
}

fn right_hand_side(statement: &str) -> &str {
    statement
        .split_once('=')
        .map_or(statement, |(_, rhs): (&str, &str)| rhs)
        .trim()
}

fn assert_fold_preserves_value(expression: &str) -> VbsReport {
    let program: String = format!("x = {expression}");
    let original: Value =
        evaluate(expression).unwrap_or_else(|e| panic!("reference rejects {expression:?}: {e}"));
    let report: VbsReport = deobfuscate_vbs(&program);
    let folded: &str = right_hand_side(&report.output);
    let recovered: Value = evaluate(folded).unwrap_or_else(|e| {
        panic!("recovered {folded:?} from {expression:?} is not evaluable: {e}")
    });
    assert_eq!(
        as_text(&recovered),
        as_text(&original),
        "{expression:?} folded to {folded:?}"
    );
    report
}

#[test]
fn the_reference_follows_vbscript_rules() {
    assert_eq!(
        evaluate("Chr(72) & Chr(105)"),
        Ok(Value::Str("Hi".to_owned()))
    );
    assert_eq!(evaluate("\"a\"\"b\""), Ok(Value::Str("a\"b".to_owned())));
    assert_eq!(evaluate("1 + 2 & 3"), Ok(Value::Str("33".to_owned())));
    assert_eq!(evaluate("\"1\" + 2"), Ok(Value::Num(3)));
    assert_eq!(evaluate("\"a\" + \"b\""), Ok(Value::Str("ab".to_owned())));
    assert!(evaluate("\"a\" + 1").is_err());
    assert_eq!(evaluate("Chr(128)"), Ok(Value::Str("\u{20AC}".to_owned())));
    assert!(evaluate("Chr(129)").is_err());
    assert_eq!(
        evaluate("ChrW(&H263A)"),
        Ok(Value::Str("\u{263A}".to_owned()))
    );
    assert!(evaluate("ChrW(&HD800)").is_err());
    assert_eq!(
        evaluate("StrReverse(\"cba\")"),
        Ok(Value::Str("abc".to_owned()))
    );
    assert_eq!(
        evaluate("Mid(\"hello\", 2, 3)"),
        Ok(Value::Str("ell".to_owned()))
    );
    assert_eq!(evaluate("7 \\ 2 & \"\""), Ok(Value::Str("3".to_owned())));
    assert_eq!(evaluate("-2 * 3"), Ok(Value::Num(-6)));
}

#[test]
fn hand_written_obfuscation_shapes_fold_to_the_same_value() {
    let shapes: [&str; 12] = [
        "Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)",
        "ChrW(87) & ChrW(&H53) & \"hell\"",
        "StrReverse(\"llehS.tpircSW\")",
        "\"Wr\" & \"ite\" & Chr(76) & \"og\"",
        "Chr(34) & \"quoted\" & Chr(34)",
        "Chr(65) + Chr(66)",
        "\"n\" & 1 + 2",
        "Chr(72) & (Chr(105) & Chr(33))",
        "UCase(Chr(97)) & LCase(\"BC\")",
        "Mid(\"xxABCxx\", 3, 3) & Chr(68)",
        "Replace(\"a-b-c\", \"-\", \"\") & ChrW(9731)",
        "Chr(128) & ChrW(8364)",
    ];
    let mut chr_folds: usize = 0;
    for shape in shapes {
        chr_folds += assert_fold_preserves_value(shape).chr_substitutions;
    }
    assert!(
        chr_folds >= 12,
        "the corpus must exercise the Chr folds, folded {chr_folds}"
    );
}

#[test]
fn generated_expressions_fold_to_the_same_value() {
    let mut seed: u64 = 0x5EED_0F_0B5C;
    let mut next = |bound: u64| -> u64 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % bound
    };
    let mut folded_any: usize = 0;
    for _ in 0..600 {
        let parts: u64 = 1 + next(6);
        let mut pieces: Vec<String> = Vec::new();
        for _ in 0..parts {
            let piece: String = match next(6) {
                0 => format!("Chr({})", 32 + next(95)),
                1 => format!("ChrW({})", 32 + next(0x2FFF)),
                2 => format!("ChrW(&H{:X})", 0x20 + next(0x5E)),
                3 => {
                    let text: String = (0..1 + next(5))
                        .map(|_| char::from(b'a' + u8::try_from(next(26)).unwrap_or(0)))
                        .collect();
                    format!("StrReverse(\"{text}\")")
                }
                4 => format!("\"{}\"", ["x", "\"\"", "", "Run", " "][next(5) as usize]),
                _ => format!("Chr({}) & Chr({})", 48 + next(10), 65 + next(26)),
            };
            pieces.push(piece);
        }
        let expression: String = pieces.join(" & ");
        folded_any += assert_fold_preserves_value(&expression).chr_substitutions;
    }
    assert!(folded_any > 600, "folded {folded_any}");
}

#[test]
fn a_fold_that_changes_the_value_is_caught() {
    let expression: &str = "Chr(72) & Chr(105)";
    let report: VbsReport = deobfuscate_vbs(&format!("x = {expression}"));
    let folded: String = right_hand_side(&report.output).to_owned();
    let mutated: String = folded.replacen('H', "h", 1);
    assert_ne!(folded, mutated, "the mutation must change the folded text");
    assert_ne!(
        evaluate(&mutated).map(|v: Value| as_text(&v)),
        evaluate(expression).map(|v: Value| as_text(&v)),
        "the grader must reject a fold that changes one character"
    );
}

#[test]
fn an_unwrapped_execute_runs_exactly_the_string_its_argument_evaluates_to() {
    let arguments: [&str; 4] = [
        "\"x = \" & Chr(34) & \"a\" & Chr(34)",
        "StrReverse(\")1(tuO\")",
        "\"MsgBox \" & Chr(34) & \"h\" & Chr(105) & Chr(34)",
        "\"y = \" & \"\"\"q\"\"\"",
    ];
    for argument in arguments {
        let expected: String = as_text(
            &evaluate(argument).unwrap_or_else(|e| panic!("reference rejects {argument:?}: {e}")),
        );
        let report: VbsReport = deobfuscate_vbs(&format!("Execute({argument})"));
        assert_eq!(report.execute_unwraps, 1, "{argument:?}: {}", report.output);
        assert_eq!(report.output, expected, "{argument:?}");
    }
}
