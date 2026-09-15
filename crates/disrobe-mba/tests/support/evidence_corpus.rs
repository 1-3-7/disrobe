#![allow(dead_code)]

use std::path::{Path, PathBuf};

use disrobe_mba::{Expr, Width};
use serde::Deserialize;

pub(crate) const CASE_KEYS: [&str; 9] = [
    "generator",
    "id",
    "obfuscated",
    "obfuscated_nodes",
    "seed",
    "source",
    "transform",
    "var_count",
    "width",
];

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Case {
    pub(crate) generator: String,
    pub(crate) id: String,
    pub(crate) obfuscated: String,
    pub(crate) obfuscated_nodes: usize,
    pub(crate) seed: u64,
    pub(crate) source: String,
    pub(crate) transform: String,
    pub(crate) var_count: u32,
    pub(crate) width: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Check {
    pub(crate) inputs: Vec<u64>,
    pub(crate) output: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Truth {
    pub(crate) checks: Vec<Check>,
    pub(crate) id: String,
    pub(crate) original: String,
    pub(crate) original_nodes: usize,
}

pub(crate) fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("evidence")
        .join("corpus")
        .join("mba")
}

pub(crate) fn read_lines(path: &Path) -> Vec<String> {
    let text: String = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    text.lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

pub(crate) fn load_cases(directory: &Path) -> Vec<Case> {
    read_lines(&directory.join("cases.jsonl"))
        .iter()
        .map(|line: &String| {
            serde_json::from_str::<Case>(line)
                .unwrap_or_else(|error| panic!("malformed case record: {error}\n{line}"))
        })
        .collect()
}

pub(crate) fn load_truths(directory: &Path) -> Vec<Truth> {
    read_lines(&directory.join("truth.jsonl"))
        .iter()
        .map(|line: &String| {
            serde_json::from_str::<Truth>(line)
                .unwrap_or_else(|error| panic!("malformed truth record: {error}\n{line}"))
        })
        .collect()
}

pub(crate) fn width_from_bits(bits: u32) -> Width {
    Width::from_bits(bits).unwrap_or_else(|| panic!("corpus declares an unsupported width {bits}"))
}

#[derive(Debug)]
struct PrefixReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> PrefixReader<'a> {
    const fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            cursor: 0,
        }
    }

    fn skip_space(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.cursor += 1;
        }
    }

    fn expect(&mut self, byte: u8) {
        self.skip_space();
        assert_eq!(
            self.bytes.get(self.cursor).copied(),
            Some(byte),
            "prefix term is malformed at byte {}",
            self.cursor
        );
        self.cursor += 1;
    }

    fn word(&mut self) -> String {
        self.skip_space();
        let start: usize = self.cursor;
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(u8::is_ascii_alphabetic)
        {
            self.cursor += 1;
        }
        String::from_utf8_lossy(&self.bytes[start..self.cursor]).into_owned()
    }

    fn integer(&mut self) -> u64 {
        self.skip_space();
        let start: usize = self.cursor;
        while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
            self.cursor += 1;
        }
        let digits: String = String::from_utf8_lossy(&self.bytes[start..self.cursor]).into_owned();
        digits
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("prefix term carries a bad integer {digits:?}: {error}"))
    }

    fn term(&mut self) -> Expr {
        self.expect(b'(');
        let tag: String = self.word();
        let built: Expr = match tag.as_str() {
            "const" => Expr::konst(self.integer()),
            "var" => {
                let raw: u64 = self.integer();
                let index: u32 = u32::try_from(raw).unwrap_or_else(|_| {
                    panic!("prefix term carries a var index {raw} out of range")
                });
                Expr::var(index)
            }
            "neg" => Expr::neg(self.term()),
            "not" => Expr::not(self.term()),
            "add" => self.binary(Expr::add),
            "sub" => self.binary(Expr::sub),
            "mul" => self.binary(Expr::mul),
            "and" => self.binary(Expr::and),
            "or" => self.binary(Expr::or),
            "xor" => self.binary(Expr::xor),
            "shl" => self.binary(Expr::shl),
            "shr" => self.binary(Expr::shr),
            other => panic!("prefix term carries an unknown tag {other:?}"),
        };
        self.expect(b')');
        built
    }

    fn binary(&mut self, build: fn(Expr, Expr) -> Expr) -> Expr {
        let left: Expr = self.term();
        let right: Expr = self.term();
        build(left, right)
    }
}

pub(crate) fn parse_prefix(text: &str) -> Expr {
    let mut reader: PrefixReader<'_> = PrefixReader::new(text);
    let parsed: Expr = reader.term();
    reader.skip_space();
    assert_eq!(
        reader.cursor,
        reader.bytes.len(),
        "prefix term has trailing input: {text}"
    );
    parsed
}
