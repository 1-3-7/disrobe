#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;

use disrobe_pass_beam::{BeamFile, SymbolicFunction, SymbolicModule, symbolic_disassemble};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
        .join("disasm_oracle")
}

struct OracleFunction {
    name: String,
    arity: u32,
    entry: u32,
    instructions: Vec<String>,
}

fn parse_oracle(text: &str) -> Vec<OracleFunction> {
    let mut funcs: Vec<OracleFunction> = Vec::new();
    for raw in text.lines() {
        let line: &str = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with("module ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("function ") {
            let fields: Vec<&str> = rest.rsplitn(3, ' ').collect();
            let entry: u32 = fields[0].parse().expect("entry");
            let arity: u32 = fields[1].parse().expect("arity");
            let name: String = unquote(fields[2]);
            funcs.push(OracleFunction {
                name,
                arity,
                entry,
                instructions: Vec::new(),
            });
        } else if let Some(func) = funcs.last_mut() {
            func.instructions.push(normalize(line));
        }
    }
    funcs
}

fn unquote(name: &str) -> String {
    name.strip_prefix('\'')
        .and_then(|s: &str| s.strip_suffix('\''))
        .unwrap_or(name)
        .to_owned()
}

fn normalize(text: &str) -> String {
    let collapsed: String = text.chars().filter(|c: &char| !c.is_whitespace()).collect();
    let with_line: String = normalize_line_file(&collapsed);
    sort_maps(&with_line)
}

fn normalize_line_file(s: &str) -> String {
    let needle: &str = "{location,\"";
    let Some(start) = s.find(needle) else {
        return s.to_owned();
    };
    let after_quote: usize = start + needle.len();
    let Some(rel_close) = s[after_quote..].find('"') else {
        return s.to_owned();
    };
    let close: usize = after_quote + rel_close;
    let mut out: String = String::with_capacity(s.len());
    out.push_str(&s[..start]);
    out.push_str("{location,line");
    out.push_str(&s[close + 1..]);
    out
}

fn opens(c: char, prev: char) -> bool {
    c == '{' || c == '[' || (c == '<' && prev != '=')
}

fn closes(c: char, prev: char) -> bool {
    c == '}' || c == ']' || (c == '>' && prev != '=')
}

fn sort_maps(s: &str) -> String {
    let bytes: Vec<char> = s.chars().collect();
    let mut out: String = String::with_capacity(s.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == '#' && bytes.get(i + 1) == Some(&'{') {
            let mut depth: i32 = 0;
            let mut j: usize = i + 2;
            let start: usize = j;
            let mut prev: char = '{';
            while j < bytes.len() {
                let c: char = bytes[j];
                if opens(c, prev) {
                    depth += 1;
                } else if closes(c, prev) {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                prev = c;
                j += 1;
            }
            let inner: String = bytes[start..j].iter().collect();
            let mut parts: Vec<String> = Vec::new();
            let mut d: i32 = 0;
            let mut last: usize = 0;
            let mut p: char = ' ';
            let inner_chars: Vec<char> = inner.chars().collect();
            for (k, &c) in inner_chars.iter().enumerate() {
                if opens(c, p) {
                    d += 1;
                } else if closes(c, p) {
                    d -= 1;
                } else if c == ',' && d == 0 {
                    parts.push(inner_chars[last..k].iter().collect());
                    last = k + 1;
                }
                p = c;
            }
            parts.push(inner_chars[last..].iter().collect());
            parts.sort();
            out.push_str("#{");
            out.push_str(&parts.join(","));
            out.push('}');
            i = j + 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

fn assert_module_matches(beam_rel: &str, oracle_rel: &str) {
    let dir: PathBuf = corpus_dir();
    let bytes: Vec<u8> = std::fs::read(dir.join(beam_rel))
        .unwrap_or_else(|e: std::io::Error| panic!("read {beam_rel}: {e}"));
    let oracle_text: String = std::fs::read_to_string(dir.join(oracle_rel))
        .unwrap_or_else(|e: std::io::Error| panic!("read {oracle_rel}: {e}"));
    let beam: BeamFile = BeamFile::parse(&bytes).expect("parse beam");
    let module: SymbolicModule = symbolic_disassemble(&beam).expect("symbolic disasm");
    let oracle: Vec<OracleFunction> = parse_oracle(&oracle_text);

    assert_eq!(
        module.functions.len(),
        oracle.len(),
        "function count mismatch for {beam_rel}"
    );

    let mut total: usize = 0;
    let mut matched: usize = 0;
    for (dis, ora) in module.functions.iter().zip(oracle.iter()) {
        let dis: &SymbolicFunction = dis;
        assert_eq!(dis.name, ora.name, "function name mismatch in {beam_rel}");
        assert_eq!(dis.arity, ora.arity, "arity mismatch for {}", ora.name);
        assert_eq!(
            dis.entry_label, ora.entry,
            "entry-label mismatch for {}",
            ora.name
        );
        assert_eq!(
            dis.instructions.len(),
            ora.instructions.len(),
            "instruction count mismatch for {} in {beam_rel}",
            ora.name
        );
        for (di, oi) in dis.instructions.iter().zip(ora.instructions.iter()) {
            total += 1;
            let normalized: String = normalize(&di.text);
            if &normalized == oi {
                matched += 1;
            } else {
                panic!(
                    "instruction mismatch in {beam_rel} fn {}:\n  disrobe: {normalized}\n  oracle : {oi}",
                    ora.name
                );
            }
        }
    }
    assert_eq!(
        matched, total,
        "{beam_rel}: {matched}/{total} instructions matched beam_disasm"
    );
    assert!(total > 0, "{beam_rel} produced no instructions");
}

#[test]
fn probe_matches_beam_disasm_oracle() {
    assert_module_matches("probe.beam", "probe.beam_disasm.txt");
}

#[test]
fn probe2_matches_beam_disasm_oracle() {
    assert_module_matches("probe2.beam", "probe2.beam_disasm.txt");
}

#[test]
fn committed_corpus_beams_disassemble_symbolically() {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let beam_root: PathBuf = manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam");
    for rel in [
        "erlang/hello.beam",
        "elixir/Elixir.Hello.beam",
        "megafile/edge_cases.beam",
        "megafile/Elixir.EdgeCases.MyServer.beam",
    ] {
        let bytes: Vec<u8> = std::fs::read(beam_root.join(rel))
            .unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"));
        let beam: BeamFile = BeamFile::parse(&bytes).expect("parse beam");
        let module: SymbolicModule = symbolic_disassemble(&beam).expect("symbolic disasm");
        assert!(!module.functions.is_empty(), "{rel} produced no functions");
        assert!(
            module
                .functions
                .iter()
                .all(|f: &SymbolicFunction| !f.instructions.is_empty()),
            "{rel} has a function with no instructions"
        );
    }
}
