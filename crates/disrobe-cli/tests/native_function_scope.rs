#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![cfg(feature = "native")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use object::{Object as _, ObjectSection as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const RUN_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const FIXTURE_FILES: [&str; 5] = [
    "scope.c",
    "scope.dll",
    "scope.map",
    "scope.unwind.txt",
    "scope.objdump.txt",
];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture(name: &str) -> PathBuf {
    workspace_root()
        .join("corpus")
        .join("native")
        .join("function-scope")
        .join(name)
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(std::env::var_os("DISROBE_BIN").expect(
        "DISROBE_BIN must name the disrobe binary built by `cargo build -p disrobe-cli --bin disrobe` for this caller test",
    ));
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn run(args: &[&str]) -> CapturedOutput {
    let bin: PathBuf = disrobe_bin();
    let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_captured(&bin, &argv, RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|e| panic!("cannot start {}: {e}", bin.display()))
        .unwrap_or_else(|| panic!("disrobe {args:?} exceeded its timeout"))
}

fn run_ok(args: &[&str]) -> String {
    let output: CapturedOutput = run(args);
    assert_eq!(
        output.exit_code,
        Some(0),
        "disrobe {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn run_json(args: &[&str]) -> Value {
    let mut with_json: Vec<&str> = args.to_vec();
    with_json.push("--json");
    serde_json::from_str(&run_ok(&with_json)).expect("JSON document on stdout")
}

fn refusal(args: &[&str]) -> String {
    let output: CapturedOutput = run(args);
    assert_ne!(
        output.exit_code,
        Some(0),
        "disrobe {args:?} must refuse, but it printed:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    stderr
        .split_whitespace()
        .filter(|word: &&str| *word != "│")
        .collect::<Vec<&str>>()
        .join(" ")
}

fn path_arg(path: &Path) -> String {
    path.to_str().expect("UTF-8 fixture path").to_owned()
}

#[derive(Debug, Clone)]
struct ObjdumpInstruction {
    rva: u64,
    mnemonic: String,
    operands: String,
    target: Option<u64>,
    branch: Option<u64>,
}

#[derive(Debug)]
struct Reference {
    base: u64,
    functions: BTreeMap<u64, String>,
    symbols: BTreeMap<String, u64>,
    unwind: Vec<(u64, u64)>,
    instructions: Vec<ObjdumpInstruction>,
    image: Vec<u8>,
    source: String,
}

fn table_hashes(build: &str) -> BTreeMap<String, (u64, String)> {
    let mut rows: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for line in build.lines() {
        let cells: Vec<&str> = line
            .split('|')
            .map(str::trim)
            .filter(|cell: &&str| !cell.is_empty())
            .collect();
        if let [name, bytes, digest] = cells.as_slice()
            && let Ok(size) = bytes.parse::<u64>()
        {
            rows.insert(
                name.trim_matches('`').to_owned(),
                (size, digest.trim_matches('`').to_owned()),
            );
        }
    }
    rows
}

fn parse_hex(text: &str) -> u64 {
    let digits: &str = text.trim().trim_start_matches("0x");
    u64::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("hex {text:?}: {e}"))
}

impl Reference {
    fn load() -> Self {
        let build: String =
            std::fs::read_to_string(fixture("BUILD.md")).expect("the fixture's BUILD.md");
        let rows: BTreeMap<String, (u64, String)> = table_hashes(&build);
        for name in FIXTURE_FILES {
            let bytes: Vec<u8> = std::fs::read(fixture(name))
                .unwrap_or_else(|e| panic!("committed fixture {name} is missing: {e}"));
            let (size, digest): &(u64, String) = rows
                .get(name)
                .unwrap_or_else(|| panic!("BUILD.md records no hash for {name}"));
            assert_eq!(
                bytes.len() as u64,
                *size,
                "{name} size differs from BUILD.md"
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                *digest,
                "{name} differs from the bytes BUILD.md records"
            );
        }
        let map: String = std::fs::read_to_string(fixture("scope.map")).expect("linker map");
        let base: u64 = map
            .lines()
            .find_map(|line: &str| line.trim().strip_prefix("Preferred load address is "))
            .map(parse_hex)
            .expect("the map names the preferred load address");
        let mut functions: BTreeMap<u64, String> = BTreeMap::new();
        let mut symbols: BTreeMap<String, u64> = BTreeMap::new();
        let mut in_publics: bool = false;
        for line in map.lines() {
            if line.contains("Publics by Value") {
                in_publics = true;
                continue;
            }
            if line.trim_start().starts_with("entry point at") {
                break;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if !in_publics || tokens.len() < 4 || tokens[0].starts_with("0000:") {
                continue;
            }
            let rva: u64 = parse_hex(tokens[2]) - base;
            symbols.insert(tokens[1].to_owned(), rva);
            if tokens[3] == "f" {
                functions.insert(rva, tokens[1].to_owned());
            }
        }
        let unwind_text: String =
            std::fs::read_to_string(fixture("scope.unwind.txt")).expect("unwind reference");
        let field = |line: &str, key: &str| -> Option<u64> {
            line.trim()
                .strip_prefix(key)
                .map(|rest: &str| parse_hex(rest.trim().trim_matches(['(', ')'])) - base)
        };
        let starts: Vec<u64> = unwind_text
            .lines()
            .filter_map(|line: &str| field(line, "StartAddress:"))
            .collect();
        let ends: Vec<u64> = unwind_text
            .lines()
            .filter_map(|line: &str| field(line, "EndAddress:"))
            .collect();
        assert_eq!(starts.len(), ends.len());
        let unwind: Vec<(u64, u64)> = starts.into_iter().zip(ends).collect();
        let objdump: String =
            std::fs::read_to_string(fixture("scope.objdump.txt")).expect("objdump reference");
        let mut instructions: Vec<ObjdumpInstruction> = Vec::new();
        for line in objdump.lines() {
            let trimmed: &str = line.trim_start();
            if trimmed.ends_with(">:") {
                continue;
            }
            let Some((address, rest)): Option<(&str, &str)> = trimmed.split_once(':') else {
                continue;
            };
            let Ok(va) = u64::from_str_radix(address, 16) else {
                continue;
            };
            let (body, comment): (&str, Option<&str>) = rest
                .split_once('#')
                .map_or((rest, None), |(body, comment): (&str, &str)| {
                    (body, Some(comment))
                });
            let body: &str = body.trim();
            let (mnemonic, operands): (&str, &str) = body
                .split_once(char::is_whitespace)
                .map_or((body, ""), |(mnemonic, operands): (&str, &str)| {
                    (mnemonic, operands.trim())
                });
            let branch: Option<u64> = (mnemonic == "call" || mnemonic.starts_with('j'))
                .then(|| operands.split_whitespace().next())
                .flatten()
                .filter(|token: &&str| token.starts_with("0x"))
                .map(|token: &str| parse_hex(token) - base);
            instructions.push(ObjdumpInstruction {
                rva: va - base,
                mnemonic: mnemonic.to_owned(),
                operands: operands.to_owned(),
                target: comment.map(|text: &str| parse_hex(text) - base),
                branch,
            });
        }
        assert!(
            instructions.len() > 100,
            "the objdump reference must hold the whole .text listing"
        );
        Self {
            base,
            functions,
            symbols,
            unwind,
            instructions,
            image: std::fs::read(fixture("scope.dll")).expect("fixture DLL"),
            source: std::fs::read_to_string(fixture("scope.c")).expect("fixture source"),
        }
    }

    fn function(&self, name: &str) -> u64 {
        self.functions
            .iter()
            .find(|(_, candidate): &(&u64, &String)| candidate.as_str() == name)
            .map_or_else(
                || panic!("the linker map names no function {name}"),
                |(rva, _): (&u64, &String)| *rva,
            )
    }

    fn symbol(&self, name: &str) -> u64 {
        *self
            .symbols
            .get(name)
            .unwrap_or_else(|| panic!("the linker map names no symbol {name}"))
    }

    fn owner(&self, rva: u64) -> &str {
        self.functions.range(..=rva).next_back().map_or_else(
            || panic!("no map function precedes {rva:#x}"),
            |(_, name): (&u64, &String)| name.as_str(),
        )
    }

    fn next_function_after(&self, rva: u64) -> u64 {
        self.functions.range(rva + 1..).next().map_or_else(
            || self.instructions.last().expect("instructions").rva + 1,
            |(start, _): (&u64, &String)| *start,
        )
    }

    fn rvas_in(&self, start: u64, end: u64) -> Vec<u64> {
        self.instructions
            .iter()
            .filter(|instruction: &&ObjdumpInstruction| {
                instruction.rva >= start && instruction.rva < end
            })
            .map(|instruction: &ObjdumpInstruction| instruction.rva)
            .collect()
    }

    fn try_file_offset(&self, rva: u64) -> Option<usize> {
        let file: object::File<'_> = object::File::parse(self.image.as_slice()).expect("PE");
        file.sections()
            .find_map(|section: object::Section<'_, '_>| {
                let start: u64 = section.address() - self.base;
                let (offset, size): (u64, u64) = section.file_range()?;
                (rva >= start && rva < start + size)
                    .then(|| usize::try_from(offset + (rva - start)).expect("offset"))
            })
    }

    fn file_offset(&self, rva: u64) -> usize {
        self.try_file_offset(rva)
            .unwrap_or_else(|| panic!("rva {rva:#x} is not file-backed"))
    }

    fn bytes_at(&self, rva: u64, len: usize) -> &[u8] {
        let offset: usize = self.file_offset(rva);
        &self.image[offset..offset + len]
    }

    fn owner_start(&self, rva: u64) -> u64 {
        self.functions.range(..=rva).next_back().map_or_else(
            || panic!("no map function precedes {rva:#x}"),
            |(start, _): (&u64, &String)| *start,
        )
    }

    fn mapped_names(&self, document: &Value) -> BTreeSet<String> {
        document["matches"]
            .as_array()
            .expect("matches")
            .iter()
            .map(|item: &Value| {
                let start: u64 = item["function_rva"].as_u64().expect("function_rva");
                self.functions
                    .get(&start)
                    .unwrap_or_else(|| {
                        panic!("disrobe reports a function at {start:#x}, where the linker map starts none")
                    })
                    .clone()
            })
            .collect()
    }

    fn xrefs(&self, target: u64) -> BTreeSet<u64> {
        self.instructions
            .iter()
            .filter(|instruction: &&ObjdumpInstruction| {
                instruction.target == Some(target) || instruction.branch == Some(target)
            })
            .map(|instruction: &ObjdumpInstruction| instruction.rva)
            .collect()
    }

    fn const_users(&self, width: usize, bits: u64) -> BTreeSet<String> {
        let mut users: BTreeSet<String> = BTreeSet::new();
        for instruction in &self.instructions {
            let operands: Vec<&str> = instruction.operands.split(", ").collect();
            let destination_width: Option<usize> = operands.first().and_then(|first: &&str| {
                if first.starts_with("qword ptr") || first.starts_with('r') {
                    Some(8)
                } else if first.starts_with("dword ptr") || first.starts_with('e') {
                    Some(4)
                } else {
                    None
                }
            });
            let immediate: Option<u64> = operands.last().and_then(|last: &&str| {
                let negative: bool = last.starts_with("-0x");
                let digits: &str = last.trim_start_matches('-').strip_prefix("0x")?;
                let magnitude: u64 = u64::from_str_radix(digits, 16).ok()?;
                Some(if negative {
                    magnitude.wrapping_neg()
                } else {
                    magnitude
                })
            });
            let immediate_match: bool = operands.len() > 1
                && destination_width == Some(width)
                && immediate.map(|value: u64| {
                    if width == 4 {
                        value & 0xffff_ffff
                    } else {
                        value
                    }
                }) == Some(bits);
            let load_width: Option<usize> = if instruction.operands.contains("qword ptr [rip") {
                Some(8)
            } else if instruction.operands.contains("dword ptr [rip") {
                Some(4)
            } else {
                None
            };
            let load_match: bool = instruction.mnemonic != "lea"
                && load_width == Some(width)
                && instruction.target.is_some_and(|target: u64| {
                    self.try_file_offset(target).is_some_and(|offset: usize| {
                        let mut word: [u8; 8] = [0; 8];
                        word[..width].copy_from_slice(&self.image[offset..offset + width]);
                        u64::from_le_bytes(word) == bits
                    })
                });
            if immediate_match || load_match {
                users.insert(self.owner(instruction.rva).to_owned());
            }
        }
        users
    }

    fn field_users(&self, displacements: &[u64]) -> BTreeSet<String> {
        let mut seen: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for instruction in &self.instructions {
            let Some(inner): Option<&str> = instruction
                .operands
                .split_once('[')
                .and_then(|(_, rest): (&str, &str)| rest.split_once(']'))
                .map(|(inner, _): (&str, &str)| inner)
            else {
                continue;
            };
            let terms: Vec<&str> = inner.split(" + ").collect();
            let base: &str = terms[0];
            if base.contains('*') || base == "rsp" || base == "rip" {
                continue;
            }
            let displacement: u64 = terms
                .iter()
                .skip(1)
                .find(|term: &&&str| term.starts_with("0x"))
                .map_or(0, |term: &&str| parse_hex(term));
            if displacements.contains(&displacement) {
                seen.entry(self.owner(instruction.rva).to_owned())
                    .or_default()
                    .insert(displacement);
            }
        }
        seen.into_iter()
            .filter(|(_, found): &(String, BTreeSet<u64>)| found.len() == displacements.len())
            .map(|(name, _): (String, BTreeSet<u64>)| name)
            .collect()
    }

    fn patched(&self, scratch: &ScratchDir, edits: &[(u64, &[u8])]) -> PathBuf {
        let mut bytes: Vec<u8> = self.image.clone();
        for (rva, replacement) in edits {
            let offset: usize = self.file_offset(*rva);
            bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
        }
        let path: PathBuf = scratch.path().join("scope-mutated.dll");
        std::fs::write(&path, bytes).expect("write mutated fixture");
        path
    }

    fn pdata_entry(&self, start: u64) -> u64 {
        let file: object::File<'_> = object::File::parse(self.image.as_slice()).expect("PE");
        let pdata: object::Section<'_, '_> = file
            .section_by_name(".pdata")
            .expect("the fixture has a .pdata section");
        let data: &[u8] = pdata.data().expect(".pdata bytes");
        let index: usize = data
            .chunks_exact(12)
            .position(|record: &[u8]| {
                u64::from(u32::from_le_bytes(record[..4].try_into().expect("word"))) == start
            })
            .unwrap_or_else(|| panic!("no .pdata entry begins at {start:#x}"));
        pdata.address() - self.base + (index as u64) * 12
    }
}

fn scoped(input: &Path, selector: &[&str]) -> Value {
    let mut args: Vec<String> = vec!["native".into(), "disasm".into(), path_arg(input)];
    args.extend(selector.iter().map(|arg: &&str| (*arg).to_owned()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_json(&borrowed)
}

fn function_json(input: &Path, rva: u64) -> Value {
    scoped(input, &["--function", &format!("{rva:#x}")])
}

fn listed_rvas(document: &Value) -> Vec<u64> {
    document["instructions"]
        .as_array()
        .expect("instruction array")
        .iter()
        .map(|instruction: &Value| instruction["rva"].as_u64().expect("rva"))
        .collect()
}

fn mnemonic_of(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or("")
}

fn constants(document: &Value) -> Vec<(u64, String, u64, Vec<String>)> {
    document["instructions"]
        .as_array()
        .expect("instruction array")
        .iter()
        .filter_map(|instruction: &Value| {
            let constant: &Value = instruction.get("constant")?;
            Some((
                instruction["rva"].as_u64().expect("rva"),
                constant["kind"].as_str().expect("kind").to_owned(),
                constant["target"].as_u64().expect("target"),
                constant["values"]
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(|value: &Value| value.as_str().expect("value").to_owned())
                    .collect(),
            ))
        })
        .collect()
}

#[test]
fn every_pdata_function_lists_exactly_its_unwind_range() {
    let reference: Reference = Reference::load();
    assert_eq!(
        reference.unwind.len(),
        2,
        "the MSVC build gives settings_apply and settings_blend unwind entries"
    );
    for (start, end) in &reference.unwind {
        let document: Value = function_json(&fixture("scope.dll"), *start);
        let scope: &Value = &document["scope"];
        assert_eq!(scope["source"], "pdata", "{document}");
        assert_eq!(scope["start"].as_u64(), Some(*start));
        assert_eq!(scope["end"].as_u64(), Some(*end));
        assert_eq!(
            scope["name"].as_str(),
            Some(reference.functions[start].as_str())
        );
        assert_eq!(listed_rvas(&document), reference.rvas_in(*start, *end));
        let ours: Vec<String> = document["instructions"]
            .as_array()
            .expect("instructions")
            .iter()
            .map(|instruction: &Value| {
                mnemonic_of(instruction["text"].as_str().expect("text")).to_owned()
            })
            .collect();
        let theirs: Vec<String> = reference
            .instructions
            .iter()
            .filter(|instruction: &&ObjdumpInstruction| {
                instruction.rva >= *start && instruction.rva < *end
            })
            .map(|instruction: &ObjdumpInstruction| instruction.mnemonic.clone())
            .collect();
        assert_eq!(ours, theirs, "mnemonics of {start:#x}");
    }
}

#[test]
fn a_patched_unwind_end_moves_the_listed_range() {
    let reference: Reference = Reference::load();
    let (start, end): (u64, u64) = reference.unwind[0];
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-pdata").expect("scratch");
    let shortened: u64 = end - 10;
    let entry: u64 = reference.pdata_entry(start);
    let mutated: PathBuf =
        reference.patched(&scratch, &[(entry + 4, &(shortened as u32).to_le_bytes())]);
    let document: Value = function_json(&mutated, start);
    assert_eq!(document["scope"]["end"].as_u64(), Some(shortened));
    assert_ne!(
        listed_rvas(&document),
        reference.rvas_in(start, end),
        "the listing must follow the unwind entry, so a shortened entry cannot still match the reference"
    );
}

#[test]
fn a_leaf_function_without_unwind_data_is_bounded_by_discovery() {
    let reference: Reference = Reference::load();
    for name in [
        "counter_add",
        "curve_at",
        "settings_init",
        "settings_horizon_scale",
    ] {
        let start: u64 = reference.function(name);
        assert!(
            reference
                .unwind
                .iter()
                .all(|(begin, _): &(u64, u64)| *begin != start),
            "{name} is a leaf without unwind data"
        );
        let next: u64 = reference.next_function_after(start);
        let body_end: u64 = reference
            .instructions
            .iter()
            .filter(|instruction: &&ObjdumpInstruction| {
                instruction.rva >= start && instruction.rva < next && instruction.mnemonic != "int3"
            })
            .map(|instruction: &ObjdumpInstruction| instruction.rva + 1)
            .max()
            .expect("function body");
        let document: Value = function_json(&fixture("scope.dll"), start);
        let scope: &Value = &document["scope"];
        assert_eq!(scope["source"], "discovery", "{name}: {document}");
        assert_eq!(scope["start"].as_u64(), Some(start));
        let end: u64 = scope["end"].as_u64().expect("end");
        assert!(
            end >= body_end && end <= next,
            "{name}: discovered end {end:#x} must cover the body ending before {body_end:#x} and stop at the next function {next:#x}"
        );
        assert_eq!(
            listed_rvas(&document),
            reference.rvas_in(start, end),
            "{name}"
        );
    }
}

#[test]
fn rip_relative_loads_are_annotated_with_the_constant_they_read() {
    let reference: Reference = Reference::load();
    for literal in [
        "0.4375f",
        "0.5f",
        "1.0f",
        "2.71875",
        "\"scope-ascii-title\"",
        "L\"scope-wide-title\"",
        "\"scope-default-title\"",
    ] {
        assert!(
            reference.source.contains(literal),
            "scope.c holds {literal}"
        );
    }
    let cases: [(&str, &[(&str, &str)]); 4] = [
        (
            "settings_blend",
            &[
                ("f32", "1"),
                ("f32", "0.4375"),
                ("f32", "0.4375"),
                ("f32", "0.5"),
                ("f32", "0.5"),
            ],
        ),
        ("settings_horizon_scale", &[("f64", "2.71875")]),
        (
            "settings_init",
            &[
                ("ascii", "scope-ascii-title"),
                ("utf16", "scope-wide-title"),
            ],
        ),
        ("settings_title", &[("ascii", "scope-default-title")]),
    ];
    for (name, expected) in cases {
        let start: u64 = reference.function(name);
        let document: Value = function_json(&fixture("scope.dll"), start);
        let found: Vec<(u64, String, u64, Vec<String>)> = constants(&document);
        let kinds: Vec<(&str, &str)> = found
            .iter()
            .map(|(_, kind, _, values): &(u64, String, u64, Vec<String>)| {
                (kind.as_str(), values[0].as_str())
            })
            .collect();
        assert_eq!(kinds, expected.to_vec(), "{name}: {document}");
        for (rva, _, target, _) in &found {
            let objdump: &ObjdumpInstruction = reference
                .instructions
                .iter()
                .find(|instruction: &&ObjdumpInstruction| instruction.rva == *rva)
                .expect("the annotated instruction exists in the reference listing");
            assert_eq!(
                objdump.target,
                Some(*target),
                "{name} {rva:#x}: the annotation must name the address llvm-objdump resolves"
            );
        }
    }
    let curve: Value = function_json(&fixture("scope.dll"), reference.function("curve_at"));
    assert!(
        constants(&curve).is_empty(),
        "a lea of a float table is not a string: {curve}"
    );
}

#[test]
fn a_changed_constant_in_read_only_data_changes_the_annotation() {
    let reference: Reference = Reference::load();
    let constant: u64 = reference.symbol("__real@3ee00000");
    assert_eq!(reference.bytes_at(constant, 4), 0.4375f32.to_le_bytes());
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-rdata").expect("scratch");
    let mutated: PathBuf = reference.patched(&scratch, &[(constant, &0.75f32.to_le_bytes())]);
    let document: Value = function_json(&mutated, reference.function("settings_luma"));
    let values: Vec<String> = constants(&document)
        .into_iter()
        .map(|(_, _, _, values): (u64, String, u64, Vec<String>)| values[0].clone())
        .collect();
    assert_eq!(values, vec!["0.75".to_owned()]);
}

#[test]
fn text_and_json_listings_carry_the_same_instructions() {
    let reference: Reference = Reference::load();
    let start: u64 = reference.function("settings_blend");
    let selector: String = format!("{start:#x}");
    let text: String = run_ok(&[
        "native",
        "disasm",
        &path_arg(&fixture("scope.dll")),
        "--function",
        &selector,
    ]);
    let text_lines: Vec<&str> = text
        .lines()
        .filter_map(|line: &str| line.strip_prefix("  "))
        .filter(|line: &&str| line.starts_with("0x"))
        .collect();
    let document: Value = function_json(&fixture("scope.dll"), start);
    let json_lines: Vec<String> = document["instructions"]
        .as_array()
        .expect("instructions")
        .iter()
        .map(|instruction: &Value| {
            let line: String = format!(
                "{:#x}: {}",
                instruction["rva"].as_u64().expect("rva"),
                instruction["text"].as_str().expect("text")
            );
            match instruction.get("constant") {
                None => line,
                Some(constant) => {
                    let values: Vec<&str> = constant["values"]
                        .as_array()
                        .expect("values")
                        .iter()
                        .map(|value: &Value| value.as_str().expect("value"))
                        .collect();
                    format!(
                        "{line}  ; {} {}",
                        constant["kind"].as_str().expect("kind"),
                        values.join(", ")
                    )
                }
            }
        })
        .collect();
    assert_eq!(text_lines, json_lines);
    assert!(
        text.contains("function settings_blend: rva 0x10b0..0x1117 (.pdata unwind range)"),
        "{text}"
    );
}

#[test]
fn a_range_lists_exactly_the_requested_bytes() {
    let reference: Reference = Reference::load();
    let start: u64 = reference.function("settings_horizon_scale");
    let end: u64 = start + 0x11;
    let document: Value = scoped(
        &fixture("scope.dll"),
        &["--range", &format!("{start:#x}:{end:#x}")],
    );
    assert_eq!(document["scope"]["kind"], "range");
    assert_eq!(document["scope"]["name"], "settings_horizon_scale");
    assert_eq!(listed_rvas(&document), reference.rvas_in(start, end));
}

#[test]
fn selections_outside_function_starts_and_code_are_refused_by_name() {
    let reference: Reference = Reference::load();
    let dll: String = path_arg(&fixture("scope.dll"));
    let apply: u64 = reference.function("settings_apply");
    let inside: String = format!("{:#x}", apply + 0x29);
    let stderr: String = refusal(&["native", "disasm", &dll, "--function", &inside]);
    assert!(stderr.contains("DR-NATIVE-0303"), "{stderr}");
    assert!(
        stderr.contains("0x29 bytes into settings_apply"),
        "{stderr}"
    );
    let stderr: String = refusal(&["native", "disasm", &dll, "--function", "0x9000"]);
    assert!(stderr.contains("DR-NATIVE-0303"), "{stderr}");
    assert!(stderr.contains("outside every function"), "{stderr}");
    let table: u64 = reference.symbol("k_curve");
    let rdata: String = format!("{table:#x}:{:#x}", table + 0x10);
    let stderr: String = refusal(&["native", "disasm", &dll, "--range", &rdata]);
    assert!(stderr.contains("DR-NATIVE-0304"), "{stderr}");
    assert!(stderr.contains("not executable"), "{stderr}");
    let title: u64 = reference.function("settings_title");
    let past: String = format!("{title:#x}:{:#x}", title + 0x1000);
    let stderr: String = refusal(&["native", "disasm", &dll, "--range", &past]);
    assert!(stderr.contains("DR-NATIVE-0304"), "{stderr}");
    assert!(stderr.contains("runs past the end"), "{stderr}");
    let stderr: String = refusal(&["native", "disasm", &dll, "--range", "0x1120:0x1120"]);
    assert!(stderr.contains("DR-NATIVE-0305"), "{stderr}");
    let stderr: String = refusal(&["native", "disasm", &dll, "--function", "zz"]);
    assert!(stderr.contains("DR-NATIVE-0302"), "{stderr}");
    let stderr: String = refusal(&["native", "decompile", &dll, "--function", &inside]);
    assert!(stderr.contains("DR-NATIVE-0303"), "{stderr}");
    let stderr: String = refusal(&[
        "native",
        "decompile",
        &dll,
        "--backend",
        "ghidra",
        "--function",
        &format!("{apply:#x}"),
    ]);
    assert!(stderr.contains("DR-NATIVE-0310"), "{stderr}");
}

#[test]
fn a_chained_unwind_entry_joins_its_parent_function() {
    let reference: Reference = Reference::load();
    let (apply_start, apply_end): (u64, u64) = reference.unwind[0];
    let (blend_start, blend_end): (u64, u64) = reference.unwind[1];
    let parent: u64 = reference.pdata_entry(apply_start);
    let child: u64 = reference.pdata_entry(blend_start);
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-chain").expect("scratch");
    let indirect: u32 = (parent as u32) | 1;
    let mutated: PathBuf = reference.patched(&scratch, &[(child + 8, &indirect.to_le_bytes())]);
    let stderr: String = refusal(&[
        "native",
        "disasm",
        &path_arg(&mutated),
        "--function",
        &format!("{blend_start:#x}"),
    ]);
    assert!(stderr.contains("DR-NATIVE-0307"), "{stderr}");
    assert!(stderr.contains("settings_apply"), "{stderr}");
    let document: Value = function_json(&mutated, apply_start);
    assert_eq!(
        document["scope"]["chained"],
        serde_json::json!([{ "start": blend_start, "end": blend_end }])
    );
    let mut expected: Vec<u64> = reference.rvas_in(apply_start, apply_end);
    expected.extend(reference.rvas_in(blend_start, blend_end));
    assert_eq!(listed_rvas(&document), expected);
    let counter: u64 = reference.function("counter_add");
    let xrefs: Value = run_json(&[
        "query",
        &path_arg(&mutated),
        "xrefs-to",
        &format!("{counter:#x}"),
    ]);
    assert_eq!(
        reference.mapped_names(&xrefs),
        BTreeSet::from(["settings_apply".to_owned()])
    );
}

fn whole_image_blocks(source: &str) -> BTreeMap<u64, Vec<String>> {
    let mut blocks: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut current: Option<u64> = None;
    for line in source.lines() {
        if let Some(header) = line.strip_prefix("/* ")
            && let Some((_, address)) = header.split_once(" @ ")
        {
            let va: u64 = parse_hex(address.trim_end_matches(" */"));
            blocks.insert(va, Vec::new());
            current = Some(va);
            continue;
        }
        if let Some(va) = current {
            blocks
                .get_mut(&va)
                .expect("open block")
                .push(line.to_owned());
        }
    }
    for lines in blocks.values_mut() {
        while lines
            .last()
            .is_some_and(|line: &String| line.trim().is_empty())
        {
            lines.pop();
        }
    }
    blocks
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|c: &char| !c.is_whitespace() && *c != '\u{2502}')
        .collect()
}

#[test]
fn a_function_decompiles_alone_as_it_does_in_the_whole_image() {
    let reference: Reference = Reference::load();
    let dll: String = path_arg(&fixture("scope.dll"));
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-native-scope-decompile").expect("scratch");
    let out: String = path_arg(scratch.path());
    run_ok(&["native", "decompile", &dll, "--out", &out]);
    let whole: String =
        std::fs::read_to_string(scratch.path().join("scope.c")).expect("whole-image C output");
    let blocks: BTreeMap<u64, Vec<String>> = whole_image_blocks(&whole);
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(scratch.path().join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    let refused: BTreeMap<u64, String> = manifest["unrecovered"]
        .as_array()
        .expect("unrecovered")
        .iter()
        .map(|item: &Value| {
            (
                item["address"].as_u64().expect("address"),
                item["reason"].as_str().expect("reason").to_owned(),
            )
        })
        .collect();
    for name in [
        "counter_add",
        "counter_reset",
        "curve_at",
        "settings_init",
        "settings_title",
    ] {
        let start: u64 = reference.function(name);
        let block: &Vec<String> = blocks
            .get(&(reference.base + start))
            .unwrap_or_else(|| panic!("the whole-image run recovers {name}:\n{whole}"));
        let document: Value = run_json(&[
            "native",
            "decompile",
            &dll,
            "--function",
            &format!("{start:#x}"),
        ]);
        assert_eq!(document["scope"]["start"].as_u64(), Some(start), "{name}");
        let ours: Vec<String> = document["source"]
            .as_str()
            .expect("source")
            .lines()
            .filter(|line: &&str| !line.trim_start().starts_with("#include"))
            .map(str::to_owned)
            .collect();
        assert_eq!(&ours, block, "{name}");
    }
    let apply: u64 = reference.function("settings_apply");
    let reason: &String = refused
        .get(&(reference.base + apply))
        .expect("the whole-image run refuses settings_apply");
    let stderr: String = refusal(&[
        "native",
        "decompile",
        &dll,
        "--function",
        &format!("{apply:#x}"),
    ]);
    assert!(stderr.contains("DR-NATIVE-0309"), "{stderr}");
    assert!(
        compact(&stderr).contains(&compact(reason)),
        "the scoped refusal must carry the whole-image reason {reason:?}: {stderr}"
    );
}

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|name: &&str| (*name).to_owned()).collect()
}

#[test]
fn xrefs_to_an_address_match_the_disassembler_reference() {
    let reference: Reference = Reference::load();
    let dll: String = path_arg(&fixture("scope.dll"));
    let cases: [(&str, usize); 4] = [
        ("g_counter", 4),
        ("__real@3ee00000", 3),
        ("k_curve", 1),
        ("counter_add", 3),
    ];
    for (symbol, count) in cases {
        let target: u64 = reference.symbol(symbol);
        let expected: BTreeSet<u64> = reference.xrefs(target);
        assert_eq!(expected.len(), count, "{symbol} reference sites");
        let document: Value = run_json(&["query", &dll, "xrefs-to", &format!("{target:#x}")]);
        assert_eq!(document["query"], "xrefs-to");
        assert_eq!(document["truncated"], false);
        let sites: &Vec<Value> = document["matches"].as_array().expect("matches");
        let found: BTreeSet<u64> = sites
            .iter()
            .map(|site: &Value| site["rva"].as_u64().expect("rva"))
            .collect();
        assert_eq!(found, expected, "{symbol}");
        for site in sites {
            let rva: u64 = site["rva"].as_u64().expect("rva");
            assert_eq!(
                site["function_rva"].as_u64(),
                Some(reference.owner_start(rva)),
                "{symbol} {rva:#x} belongs to {}",
                reference.owner(rva)
            );
        }
    }
    let counter: Value = run_json(&[
        "query",
        &dll,
        "xrefs-to",
        &format!("{:#x}", reference.symbol("g_counter")),
    ]);
    let kinds: BTreeSet<(String, String)> = counter["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|site: &Value| {
            (
                reference
                    .owner(site["rva"].as_u64().expect("rva"))
                    .to_owned(),
                site["kind"].as_str().expect("kind").to_owned(),
            )
        })
        .collect();
    assert!(kinds.contains(&("counter_reset".to_owned(), "write".to_owned())));
    assert!(kinds.contains(&("counter_reset".to_owned(), "read".to_owned())));
}

#[test]
fn a_redirected_operand_drops_out_of_the_xrefs() {
    let reference: Reference = Reference::load();
    let counter: u64 = reference.symbol("g_counter");
    let reset: u64 = reference.function("counter_reset");
    let first: &ObjdumpInstruction = reference
        .instructions
        .iter()
        .find(|instruction: &&ObjdumpInstruction| instruction.rva == reset)
        .expect("counter_reset's first instruction");
    assert_eq!(first.target, Some(counter));
    let displacement: i32 =
        i32::from_le_bytes(reference.bytes_at(reset + 2, 4).try_into().expect("disp32"));
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-xref").expect("scratch");
    let mutated: PathBuf =
        reference.patched(&scratch, &[(reset + 2, &(displacement - 4).to_le_bytes())]);
    let document: Value = run_json(&[
        "query",
        &path_arg(&mutated),
        "xrefs-to",
        &format!("{counter:#x}"),
    ]);
    let found: BTreeSet<u64> = document["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|site: &Value| site["rva"].as_u64().expect("rva"))
        .collect();
    assert_ne!(found, reference.xrefs(counter));
    assert!(!found.contains(&reset));
}

#[test]
fn const_users_find_the_functions_that_load_or_store_each_default() {
    let reference: Reference = Reference::load();
    let dll: String = path_arg(&fixture("scope.dll"));
    for literal in [
        "0.4375f",
        "1.0625f",
        "1234.5625",
        "2.71875",
        "0.5f",
        "0x5C0FE00Du",
        "0x9E3779B97F4A7C15ull",
    ] {
        assert!(
            reference.source.contains(literal),
            "scope.c holds {literal}"
        );
    }
    let cases: [(&str, usize, u64, &[&str]); 7] = [
        (
            "f32:0.4375",
            4,
            u64::from(0.4375f32.to_bits()),
            &["settings_blend", "settings_luma"],
        ),
        (
            "f32:1.0625",
            4,
            u64::from(1.0625f32.to_bits()),
            &["settings_init"],
        ),
        (
            "f32:0.5",
            4,
            u64::from(0.5f32.to_bits()),
            &["settings_blend"],
        ),
        (
            "f64:2.71875",
            8,
            2.71875f64.to_bits(),
            &["settings_horizon_scale"],
        ),
        (
            "f64:1234.5625",
            8,
            1234.5625f64.to_bits(),
            &["settings_init"],
        ),
        ("u32:0x5c0fe00d", 4, 0x5c0f_e00d, &["settings_init"]),
        (
            "u64:0x9e3779b97f4a7c15",
            8,
            0x9e37_79b9_7f4a_7c15,
            &["settings_init"],
        ),
    ];
    for (value, width, bits, source_users) in cases {
        let expected: BTreeSet<String> = reference.const_users(width, bits);
        assert_eq!(
            expected,
            names(source_users),
            "the reference users of {value}"
        );
        let document: Value = run_json(&["query", &dll, "const-users", value]);
        assert_eq!(document["query"], "const-users");
        assert_eq!(document["bits"].as_u64(), Some(bits), "{value}");
        assert_eq!(
            reference.mapped_names(&document),
            expected,
            "{value}: {document}"
        );
    }
}

#[test]
fn a_changed_immediate_drops_its_function_from_const_users() {
    let reference: Reference = Reference::load();
    let init: u64 = reference.function("settings_init");
    let store: &ObjdumpInstruction = reference
        .instructions
        .iter()
        .find(|instruction: &&ObjdumpInstruction| {
            instruction.rva >= init && instruction.operands.ends_with("0x3f880000")
        })
        .expect("settings_init stores 1.0625f as an immediate");
    let immediate_at: u64 = store.rva + 3;
    assert_eq!(reference.bytes_at(immediate_at, 4), 1.0625f32.to_le_bytes());
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-imm").expect("scratch");
    let mutated: PathBuf = reference.patched(&scratch, &[(immediate_at, &1.125f32.to_le_bytes())]);
    let document: Value = run_json(&["query", &path_arg(&mutated), "const-users", "f32:1.0625"]);
    assert!(reference.mapped_names(&document).is_empty(), "{document}");
}

#[test]
fn field_users_need_every_listed_displacement() {
    let reference: Reference = Reference::load();
    let dll: String = path_arg(&fixture("scope.dll"));
    let cases: [(&str, &[u64], &[&str]); 2] = [
        (
            "0x4,0x8",
            &[0x4, 0x8],
            &["settings_blend", "settings_init", "settings_luma"],
        ),
        (
            "0x18,0x1c",
            &[0x18, 0x1c],
            &["settings_apply", "settings_init"],
        ),
    ];
    for (list, displacements, source_users) in cases {
        let expected: BTreeSet<String> = reference.field_users(displacements);
        assert_eq!(
            expected,
            names(source_users),
            "the reference users of {list}"
        );
        let document: Value = run_json(&["query", &dll, "field-users", list]);
        assert_eq!(document["query"], "field-users");
        assert_eq!(
            reference.mapped_names(&document),
            expected,
            "{list}: {document}"
        );
    }
    let luma: u64 = reference.function("settings_luma");
    let gamma_read: &ObjdumpInstruction = reference
        .instructions
        .iter()
        .find(|instruction: &&ObjdumpInstruction| {
            instruction.rva >= luma && instruction.operands.contains("[rcx + 0x8]")
        })
        .expect("settings_luma reads gamma");
    let displacement_at: u64 = gamma_read.rva + 4;
    assert_eq!(reference.bytes_at(displacement_at, 1), [0x08]);
    let scratch: ScratchDir = ScratchDir::create("disrobe-native-scope-field").expect("scratch");
    let mutated: PathBuf = reference.patched(&scratch, &[(displacement_at, &[0x0c])]);
    let document: Value = run_json(&["query", &path_arg(&mutated), "field-users", "0x4,0x8"]);
    assert_eq!(
        reference.mapped_names(&document),
        names(&["settings_blend", "settings_init"])
    );
}

#[test]
fn malformed_value_queries_are_refused_by_name() {
    let dll: String = path_arg(&fixture("scope.dll"));
    let stderr: String = refusal(&["query", &dll, "const-users", "f16:1"]);
    assert!(stderr.contains("DR-NATIVE-0311"), "{stderr}");
    let stderr: String = refusal(&["query", &dll, "const-users", "f32:abc"]);
    assert!(stderr.contains("DR-NATIVE-0311"), "{stderr}");
    let stderr: String = refusal(&["query", &dll, "field-users", "0x4,zz"]);
    assert!(stderr.contains("DR-NATIVE-0312"), "{stderr}");
    let stderr: String = refusal(&["query", &dll, "xrefs-to", "0xnothex"]);
    assert!(stderr.contains("DR-NATIVE-0302"), "{stderr}");
}
