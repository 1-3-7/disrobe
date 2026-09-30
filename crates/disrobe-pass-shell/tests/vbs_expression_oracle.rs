#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_shell::DynamicPolicy;
use disrobe_pass_shell::vba::vbs::{VbsReport, deobfuscate_vbs, deobfuscate_vbs_with_policy};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

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
const MAX_EXECUTE_DEPTH: usize = 8;

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
            ' ' | '\t' | '\r' => i += 1,
            '\'' => break,
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
            '&' | '+' | '-' | '*' | '/' | '^' | '(' | ')' | ',' | '=' | '.' | ':' => {
                tokens.push(Token::Op(c));
                i += 1;
            }
            other => return Err(format!("unexpected character {other:?}")),
        }
    }
    Ok(tokens)
}

struct Parser<'v> {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
    variables: &'v BTreeMap<String, Value>,
}

impl Parser<'_> {
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
                if self.peek() == Some(&Token::Op('(')) {
                    let args: Vec<Value> = self.arguments()?;
                    return call(&name, &args);
                }
                self.variables
                    .get(&name)
                    .cloned()
                    .ok_or_else(|| format!("variable {name} is read before it is assigned"))
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
    let variables: BTreeMap<String, Value> = BTreeMap::new();
    let mut parser: Parser = Parser {
        tokens: lex(expression)?,
        at: 0,
        depth: 0,
        variables: &variables,
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
    let mut seed: u64 = 0x005E_ED0F_0B5C;
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
                    let text: String = (0..=next(5))
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

#[derive(Debug, Default, PartialEq, Eq)]
struct Behaviour {
    outputs: Vec<Vec<String>>,
    executes: usize,
}

#[derive(Debug, Default)]
struct Interpreter {
    variables: BTreeMap<String, Value>,
    declared: BTreeSet<String>,
    behaviour: Behaviour,
}

fn describe(token: &Token) -> String {
    match token {
        Token::Ident(name) => name.clone(),
        other => format!("{other:?}"),
    }
}

impl Interpreter {
    fn program(&mut self, text: &str, depth: usize) -> Result<(), String> {
        for line in text.lines() {
            let tokens: Vec<Token> = lex(line)?;
            for statement in tokens.split(|token: &Token| *token == Token::Op(':')) {
                self.statement(statement, depth)?;
            }
        }
        Ok(())
    }

    fn parser(&self, tokens: &[Token]) -> Parser<'_> {
        Parser {
            tokens: tokens.to_vec(),
            at: 0,
            depth: 0,
            variables: &self.variables,
        }
    }

    fn expression(&self, tokens: &[Token]) -> Result<Value, String> {
        let mut parser: Parser<'_> = self.parser(tokens);
        let value: Value = parser.concatenation()?;
        if let Some(token) = parser.peek() {
            return Err(format!(
                "{} after an expression is outside the evaluated subset",
                describe(token)
            ));
        }
        Ok(value)
    }

    fn arguments(&self, tokens: &[Token]) -> Result<Vec<String>, String> {
        let mut parser: Parser<'_> = self.parser(tokens);
        let mut arguments: Vec<String> = Vec::new();
        if tokens.is_empty() {
            return Ok(arguments);
        }
        loop {
            arguments.push(as_text(&parser.concatenation()?));
            match parser.peek() {
                None => return Ok(arguments),
                Some(Token::Op(',')) => parser.at += 1,
                Some(token) => {
                    return Err(format!(
                        "{} between arguments is outside the evaluated subset",
                        describe(token)
                    ));
                }
            }
        }
    }

    fn statement(&mut self, tokens: &[Token], depth: usize) -> Result<(), String> {
        match tokens {
            [] => Ok(()),
            [Token::Ident(keyword), names @ ..] if keyword == "dim" => self.declare(names),
            [
                Token::Ident(object),
                Token::Op('.'),
                Token::Ident(method),
                arguments @ ..,
            ] if object == "wscript" && method == "echo" => self.output(arguments),
            [Token::Ident(keyword), arguments @ ..] if keyword == "msgbox" => {
                self.output(arguments)
            }
            [Token::Ident(keyword), argument @ ..]
                if keyword == "execute" || keyword == "executeglobal" =>
            {
                let body: String = as_text(&self.expression(argument)?);
                if depth >= MAX_EXECUTE_DEPTH {
                    return Err(format!("{keyword} nests deeper than {MAX_EXECUTE_DEPTH}"));
                }
                self.behaviour.executes += 1;
                self.program(&body, depth + 1)
            }
            [Token::Ident(name), Token::Op('='), expression @ ..] => {
                let value: Value = self.expression(expression)?;
                self.variables.insert(name.clone(), value);
                Ok(())
            }
            [first, ..] => Err(format!(
                "statement starting {} is outside the evaluated subset",
                describe(first)
            )),
        }
    }

    fn declare(&mut self, names: &[Token]) -> Result<(), String> {
        if names.len().is_multiple_of(2) {
            return Err("Dim needs a name after every comma".to_owned());
        }
        for (index, token) in names.iter().enumerate() {
            match (index % 2, token) {
                (0, Token::Ident(name)) => {
                    if !self.declared.insert(name.clone()) {
                        return Err(format!("Dim {name} redefines a declared name"));
                    }
                }
                (1, Token::Op(',')) => {}
                (_, other) => {
                    return Err(format!(
                        "Dim of {} is outside the evaluated subset",
                        describe(other)
                    ));
                }
            }
        }
        Ok(())
    }

    fn output(&mut self, arguments: &[Token]) -> Result<(), String> {
        let recorded: Vec<String> = self.arguments(arguments)?;
        self.behaviour.outputs.push(recorded);
        Ok(())
    }
}

fn behaviour(program: &str) -> Result<Behaviour, String> {
    let mut interpreter: Interpreter = Interpreter::default();
    interpreter.program(program, 0)?;
    Ok(interpreter.behaviour)
}

#[derive(Debug)]
enum Verdict {
    Refused {
        program: &'static str,
        reason: String,
    },
    Differs {
        original: Vec<Vec<String>>,
        recovered: Vec<Vec<String>>,
    },
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { program, reason } => {
                write!(f, "the reference refuses the {program} program: {reason}")
            }
            Self::Differs {
                original,
                recovered,
            } => write!(
                f,
                "the recorded outputs differ: original {original:?}, recovered {recovered:?}"
            ),
        }
    }
}

fn grade(original: &str, recovered: &str) -> Result<Behaviour, Verdict> {
    let expected: Behaviour = behaviour(original).map_err(|reason: String| Verdict::Refused {
        program: "original",
        reason,
    })?;
    let actual: Behaviour = behaviour(recovered).map_err(|reason: String| Verdict::Refused {
        program: "recovered",
        reason,
    })?;
    if actual.outputs != expected.outputs {
        return Err(Verdict::Differs {
            original: expected.outputs,
            recovered: actual.outputs,
        });
    }
    Ok(actual)
}

#[derive(Debug, Clone, Copy)]
enum Layer {
    Literal,
    StrReverse,
    Chr,
}

impl Layer {
    const fn name(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::StrReverse => "strreverse",
            Self::Chr => "chr",
        }
    }

    fn wrap(self, call: &str, payload: &str) -> String {
        match self {
            Self::Literal => format!("{call}({})", vbs_literal(payload)),
            Self::StrReverse => format!(
                "{call}(StrReverse({}))",
                vbs_literal(&payload.chars().rev().collect::<String>())
            ),
            Self::Chr => {
                let codes: Vec<String> = payload
                    .chars()
                    .map(|c: char| {
                        assert!(
                            c == ' ' || c.is_ascii_graphic(),
                            "the chr layer encodes printable ASCII only, found {c:?}"
                        );
                        format!("Chr({})", u32::from(c))
                    })
                    .collect();
                format!("{call}({})", codes.join(" & "))
            }
        }
    }
}

fn vbs_literal(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\"\""))
}

struct Sample {
    name: &'static str,
    source: &'static str,
    call: &'static str,
    groups: &'static [usize],
    layers: &'static [Layer],
}

const SAMPLES: [Sample; 6] = [
    Sample {
        name: "execute_strreverse",
        source: "greeting.vbs",
        call: "Execute",
        groups: &[5],
        layers: &[Layer::StrReverse],
    },
    Sample {
        name: "execute_chr",
        source: "arithmetic.vbs",
        call: "Execute",
        groups: &[5],
        layers: &[Layer::Chr],
    },
    Sample {
        name: "nested_two",
        source: "two_deep.vbs",
        call: "Execute",
        groups: &[3],
        layers: &[Layer::Chr, Layer::StrReverse],
    },
    Sample {
        name: "nested_three",
        source: "three_deep.vbs",
        call: "Execute",
        groups: &[5],
        layers: &[Layer::StrReverse, Layer::Chr, Layer::Literal],
    },
    Sample {
        name: "executeglobal_defines",
        source: "global_define.vbs",
        call: "ExecuteGlobal",
        groups: &[2],
        layers: &[Layer::Chr],
    },
    Sample {
        name: "execute_each_statement",
        source: "siblings.vbs",
        call: "Execute",
        groups: &[1, 1, 1],
        layers: &[Layer::StrReverse],
    },
];

fn read_corpus(relative: &str) -> String {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/vbs")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn build(sample: &Sample, source: &str) -> String {
    let statements: Vec<&str> = source
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .collect();
    let mut lines: Vec<String> = Vec::new();
    let mut at: usize = 0;
    for size in sample.groups {
        let group: &[&str] = statements.get(at..at + size).unwrap_or_else(|| {
            panic!("{} groups more statements than its source has", sample.name)
        });
        let mut text: String = group.join(" : ");
        for layer in sample.layers {
            text = layer.wrap(sample.call, &text);
        }
        lines.push(text);
        at += size;
    }
    lines.extend(
        statements[at..]
            .iter()
            .map(|line: &&str| (*line).to_owned()),
    );
    lines.join("\n") + "\n"
}

fn manifest_entry(sample: &Sample) -> String {
    let groups: Vec<String> = sample.groups.iter().map(usize::to_string).collect();
    let layers: Vec<String> = sample
        .layers
        .iter()
        .map(|layer: &Layer| format!("\"{}\"", layer.name()))
        .collect();
    format!(
        "[samples.{}]\nsource = \"plain/{}\"\nlayered = \"layered/{}.vbs\"\ncall = \"{}\"\ngroups = [{}]\nlayers = [{}]\n",
        sample.name,
        sample.source,
        sample.name,
        sample.call,
        groups.join(", "),
        layers.join(", ")
    )
}

#[test]
fn the_statement_reference_follows_vbscript_rules() {
    let cases: [(&str, &str, usize); 5] = [
        (
            "Dim a : a = \"x\" : WScript.Echo a, 1 + 2",
            r#"[["x", "3"]]"#,
            0,
        ),
        (
            "ExecuteGlobal \"Dim g : g = 5\"\nMsgBox g * 2",
            r#"[["10"]]"#,
            1,
        ),
        ("Execute(\"MsgBox \"\"a:b\"\" ' tail\")", r#"[["a:b"]]"#, 1),
        (
            "wscript.ECHO StrReverse(\"cba\") ' Execute \"x\"\nWScript.Echo",
            r#"[["abc"], []]"#,
            0,
        ),
        (
            "x = 1 : Execute \"x = x + 1 : Execute \"\"x = x * 10\"\"\" : MsgBox x",
            r#"[["20"]]"#,
            2,
        ),
    ];
    for (program, outputs, executes) in cases {
        let run: Behaviour =
            behaviour(program).unwrap_or_else(|e| panic!("reference refuses {program:?}: {e}"));
        assert_eq!(format!("{:?}", run.outputs), outputs, "{program:?}");
        assert_eq!(run.executes, executes, "{program:?}");
    }
}

#[test]
fn the_statement_reference_refuses_unknown_constructs_by_name() {
    let mut too_deep: String = "MsgBox 1".to_owned();
    for _ in 0..=MAX_EXECUTE_DEPTH {
        too_deep = Layer::Literal.wrap("Execute", &too_deep);
    }
    let cases: [(&str, &str); 8] = [
        ("If 1 Then MsgBox 1", "statement starting if"),
        ("Set o = Nothing", "statement starting set"),
        ("Sub f : End Sub", "statement starting sub"),
        ("MsgBox missing", "variable missing is read before"),
        ("Dim a : Dim a", "Dim a redefines"),
        (
            "WScript.Echo CreateObject(\"x\")",
            "createobject is outside the evaluated subset",
        ),
        ("x = 1.5", "Op('.') after an expression"),
        (&too_deep, "execute nests deeper than 8"),
    ];
    for (program, reason) in cases {
        let refusal: String = match behaviour(program) {
            Ok(accepted) => format!("accepted with {accepted:?}"),
            Err(reason) => reason,
        };
        assert!(
            refusal.contains(reason),
            "{program:?} must be refused with {reason:?}, got {refusal:?}"
        );
    }
}

#[test]
fn layered_samples_rebuild_from_their_plain_scripts() {
    let manifest: String = read_corpus("MANIFEST.toml");
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for sample in &SAMPLES {
        let source: String = read_corpus(&format!("plain/{}", sample.source));
        let layered: String = read_corpus(&format!("layered/{}.vbs", sample.name));
        assert_eq!(
            build(sample, &source),
            layered,
            "layered/{}.vbs is not the recorded build of plain/{}",
            sample.name,
            sample.source
        );
        let entry: String = manifest_entry(sample);
        assert!(
            manifest.contains(&entry),
            "MANIFEST.toml must record the build:\n{entry}"
        );
        expected.insert(format!("{}.vbs", sample.name));
    }
    let directory: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/vbs/layered");
    let committed: BTreeSet<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|e| panic!("{}: {e}", directory.display()))
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .unwrap_or_else(|e| panic!("{}: {e}", directory.display()))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(committed, expected, "every layered sample must be graded");
}

#[test]
fn unwrapped_execute_bodies_behave_like_the_original() {
    for sample in &SAMPLES {
        let source: String = read_corpus(&format!("plain/{}", sample.source));
        let layered: String = read_corpus(&format!("layered/{}.vbs", sample.name));
        let plain: Behaviour = behaviour(&source)
            .unwrap_or_else(|e| panic!("reference refuses plain/{}: {e}", sample.source));
        assert!(
            !plain.outputs.is_empty(),
            "{} records no output",
            sample.name
        );
        assert_eq!(
            plain.executes, 0,
            "plain/{} must not Execute",
            sample.source
        );
        let original: Behaviour = grade(&source, &layered)
            .unwrap_or_else(|v: Verdict| panic!("{} build changed behaviour: {v}", sample.name));
        let layers: usize = sample.layers.len();
        let total: usize = sample.groups.len() * layers;
        assert_eq!(original.executes, total, "{}", sample.name);
        for policy in [DynamicPolicy::StaticOnly, DynamicPolicy::AllowDynamic] {
            let report: VbsReport = deobfuscate_vbs_with_policy(&layered, policy);
            let recovered: Behaviour =
                grade(&layered, &report.output).unwrap_or_else(|v: Verdict| {
                    panic!(
                        "{} under {policy:?}: {v}\nrecovered:\n{}",
                        sample.name, report.output
                    )
                });
            let remaining: usize =
                sample.groups.len() * layers.saturating_sub(policy.max_eval_depth());
            assert_eq!(
                recovered.executes, remaining,
                "{} under {policy:?} left the wrong number of Execute layers:\n{}",
                sample.name, report.output
            );
            assert_eq!(
                report.execute_unwraps,
                total - remaining,
                "{} under {policy:?}",
                sample.name
            );
            assert_eq!(
                report.walls.is_empty(),
                remaining == 0,
                "{} under {policy:?}: {:?}",
                sample.name,
                report.walls
            );
        }
    }
}

#[test]
fn the_grade_rejects_a_fold_that_reverses_the_wrong_segment() {
    let sample: &Sample = &SAMPLES[0];
    let layered: String = read_corpus(&format!("layered/{}.vbs", sample.name));
    let recovered: String = deobfuscate_vbs(&layered).output;
    let open: usize = recovered
        .find('"')
        .expect("the recovered body holds a literal");
    let close: usize = open
        + 1
        + recovered[open + 1..]
            .find('"')
            .expect("the literal is terminated");
    let segment: String = recovered[open + 1..close].chars().rev().collect();
    let mutated: String = format!("{}{segment}{}", &recovered[..=open], &recovered[close..]);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    assert!(grade(&layered, &recovered).is_ok());
    match grade(&layered, &mutated) {
        Err(Verdict::Differs {
            original: before,
            recovered: after,
        }) => assert_ne!(before, after),
        other => panic!("the grade must reject the wrong segment reversal, got {other:?}"),
    }
}
