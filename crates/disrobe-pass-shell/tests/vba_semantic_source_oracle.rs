#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_shell::{
    RealModuleDisasm, RealPCodeReport, SemanticLift, disassemble_pcode_real, semantic_lift,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn vbaproject_from_docm(relative: &str) -> Vec<u8> {
    let bytes: Vec<u8> = std::fs::read(corpus_path(relative))
        .unwrap_or_else(|e: std::io::Error| panic!("read {relative}: {e}"));
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open docm zip");
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("zip index");
        if f.name().to_ascii_lowercase().ends_with("vbaproject.bin") {
            let mut out: Vec<u8> = Vec::new();
            f.read_to_end(&mut out).expect("read vbaProject.bin");
            return out;
        }
    }
    panic!("no vbaProject.bin inside {relative}");
}

const STOPWORDS: &[&str] = &[
    "as", "byval", "byref", "dim", "public", "private", "end", "then", "sub", "function",
    "property", "get", "let", "set", "to", "step", "in",
];

fn tokens(line: &str) -> BTreeSet<String> {
    let lower: String = line.to_ascii_lowercase();
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut cur: String = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            push_token(&mut out, std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        push_token(&mut out, cur);
    }
    out
}

fn push_token(set: &mut BTreeSet<String>, tok: String) {
    if tok.len() > 1 && !STOPWORDS.contains(&tok.as_str()) {
        set.insert(tok);
    }
}

fn sig_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l: &str| l.trim().to_owned())
        .filter(|l: &String| !l.is_empty() && !l.starts_with('\'') && !l.starts_with("Attribute "))
        .collect()
}

fn lift_module(docm: &str, module: &str) -> SemanticLift {
    let bin: Vec<u8> = vbaproject_from_docm(docm);
    let report: RealPCodeReport = disassemble_pcode_real(&bin).expect("disasm real p-code");
    let target: &RealModuleDisasm = report
        .modules
        .iter()
        .find(|m: &&RealModuleDisasm| m.name == module)
        .unwrap_or_else(|| panic!("module {module} not found"));
    semantic_lift(target)
}

struct Grade {
    line_recovery_pct: f64,
    token_recall_pct: f64,
    line_hits: usize,
    line_total: usize,
}

fn grade(recovered: &str, authored: &str) -> Grade {
    let rec_lines: Vec<String> = sig_lines(recovered);
    let auth_lines: Vec<String> = sig_lines(authored);
    let rec_token_lines: Vec<BTreeSet<String>> =
        rec_lines.iter().map(|l: &String| tokens(l)).collect();

    let mut line_hits: usize = 0;
    for al in &auth_lines {
        let at: BTreeSet<String> = tokens(al);
        if at.is_empty() {
            line_hits += 1;
            continue;
        }
        let best: f64 = rec_token_lines
            .iter()
            .filter(|rt: &&BTreeSet<String>| !rt.is_empty())
            .map(|rt: &BTreeSet<String>| at.intersection(rt).count() as f64 / at.len() as f64)
            .fold(0.0_f64, f64::max);
        if best >= 0.7 {
            line_hits += 1;
        }
    }

    let auth_tokens: BTreeSet<String> =
        auth_lines.iter().flat_map(|l: &String| tokens(l)).collect();
    let rec_tokens: BTreeSet<String> = rec_lines.iter().flat_map(|l: &String| tokens(l)).collect();
    let recalled: usize = auth_tokens.intersection(&rec_tokens).count();

    Grade {
        line_recovery_pct: 100.0 * line_hits as f64 / auth_lines.len().max(1) as f64,
        token_recall_pct: 100.0 * recalled as f64 / auth_tokens.len().max(1) as f64,
        line_hits,
        line_total: auth_lines.len(),
    }
}

fn assert_constructs(recovered: &str, authored: &str, constructs: &[&str]) {
    let rec_lower: String = recovered.to_ascii_lowercase();
    let auth_lower: String = authored.to_ascii_lowercase();
    for c in constructs {
        let needle: String = c.to_ascii_lowercase();
        if auth_lower.contains(&needle) {
            assert!(
                rec_lower.contains(&needle),
                "recovered source is missing construct {c:?} that is present in the authored .bas"
            );
        }
    }
}

const ALL_CONSTRUCTS: &[&str] = &[
    "Public Sub",
    "Public Function",
    "Property Get",
    "Property Let",
    "Property Set",
    "Enum ",
    "Type ",
    "ReDim",
    "For Each",
    "Do While",
    "Do Until",
    "Select Case",
    "On Error",
    "Erase",
    "Const ",
];

#[test]
fn sourceprobe_lift_recovers_authored_source() {
    let lift: SemanticLift = lift_module("vba/sourceprobe.docm", "SourceProbe");
    let authored: String = std::fs::read_to_string(corpus_path("vba/sourceprobe/SourceProbe.bas"))
        .expect("read SourceProbe.bas");
    assert_eq!(
        lift.unlifted_lines, 0,
        "every disassembled line of SourceProbe must lift; pseudocode:\n{}",
        lift.pseudocode
    );
    assert!(
        lift.walls.is_empty(),
        "well-formed module must not need synthetic block closures; walls={:?}",
        lift.walls
    );
    let g: Grade = grade(&lift.pseudocode, &authored);
    assert!(
        g.line_recovery_pct >= 90.0,
        "SourceProbe authored-line recovery {:.1}% below floor 90% ({}/{})\n{}",
        g.line_recovery_pct,
        g.line_hits,
        g.line_total,
        lift.pseudocode
    );
    assert!(
        g.token_recall_pct >= 95.0,
        "SourceProbe identifier recall {:.1}% below floor 95%",
        g.token_recall_pct
    );
    assert_constructs(&lift.pseudocode, &authored, ALL_CONSTRUCTS);
}

#[test]
fn edgecases_lift_recovers_authored_source() {
    let lift: SemanticLift = lift_module("vba/megafile.docm", "EdgeCases");
    let authored: String = std::fs::read_to_string(corpus_path("vba/megafile/EdgeCases.bas"))
        .expect("read EdgeCases.bas");
    assert_eq!(
        lift.unlifted_lines, 0,
        "every disassembled line of EdgeCases must lift; unlifted lines indicate a dropped opcode"
    );
    let g: Grade = grade(&lift.pseudocode, &authored);
    assert!(
        g.line_recovery_pct >= 75.0,
        "EdgeCases authored-line recovery {:.1}% below floor 75% ({}/{})\n{}",
        g.line_recovery_pct,
        g.line_hits,
        g.line_total,
        lift.pseudocode
    );
    assert!(
        g.token_recall_pct >= 90.0,
        "EdgeCases identifier recall {:.1}% below floor 90%",
        g.token_recall_pct
    );
    assert_constructs(&lift.pseudocode, &authored, ALL_CONSTRUCTS);
}

#[test]
fn greetingtemplate_class_recovers_events_via_reparse() {
    let lift: SemanticLift = lift_module("vba/megafile.docm", "GreetingTemplate");
    for needle in [
        "Public Event Rendered(ByVal Output As String)",
        "RaiseEvent MoodChanged",
        "Public Property Get Prefix() As String",
    ] {
        assert!(
            lift.pseudocode.contains(needle),
            "class module lift missing {needle:?}; pseudocode:\n{}",
            lift.pseudocode
        );
    }
}
