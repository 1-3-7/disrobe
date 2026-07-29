#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

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

fn strip_trailing_comment(line: &str) -> &str {
    let mut in_string: bool = false;
    for (index, byte) in line.as_bytes().iter().enumerate() {
        match byte {
            b'"' => in_string = !in_string,
            b'\'' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

fn normalize(line: &str) -> String {
    let source: &str = strip_trailing_comment(line);
    let mut out: String = String::with_capacity(source.len());
    let mut in_string: bool = false;
    let mut pending_space: bool = false;
    for ch in source.chars() {
        if in_string {
            out.push(ch);
            if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.push('"');
            in_string = true;
            continue;
        }
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch.to_ascii_lowercase());
    }
    out
}

fn ends_with_continuation(line: &str) -> bool {
    let trimmed: &str = line.trim_end();
    let Some(head) = trimmed.strip_suffix('_') else {
        return false;
    };
    head.is_empty() || head.ends_with(char::is_whitespace)
}

fn join_continuations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let head: &str = if ends_with_continuation(raw) {
            raw.trim_end()
                .strip_suffix('_')
                .expect("continuation suffix checked")
                .trim_end()
        } else {
            raw
        };
        let merged: String = pending.take().map_or_else(
            || head.to_owned(),
            |mut acc: String| {
                acc.push(' ');
                acc.push_str(head.trim_start());
                acc
            },
        );
        if ends_with_continuation(raw) {
            pending = Some(merged);
        } else {
            out.push(merged);
        }
    }
    if let Some(acc) = pending {
        out.push(acc);
    }
    out
}

fn code_lines(text: &str) -> Vec<String> {
    join_continuations(text)
        .into_iter()
        .map(|l: String| normalize(&l))
        .filter(|l: &String| !l.is_empty() && !l.starts_with("attribute "))
        .collect()
}

fn align_in_order(authored: &[String], recovered: &[String]) -> Vec<Option<usize>> {
    let rows: usize = authored.len();
    let cols: usize = recovered.len();
    let stride: usize = cols + 1;
    let mut table: Vec<u32> = vec![0_u32; (rows + 1) * stride];
    for a in (0..rows).rev() {
        for r in (0..cols).rev() {
            let cell: u32 = if authored[a] == recovered[r] {
                table[(a + 1) * stride + r + 1] + 1
            } else {
                table[(a + 1) * stride + r].max(table[a * stride + r + 1])
            };
            table[a * stride + r] = cell;
        }
    }
    let mut mapping: Vec<Option<usize>> = vec![None; rows];
    let mut a: usize = 0;
    let mut r: usize = 0;
    while a < rows && r < cols {
        if authored[a] == recovered[r] {
            mapping[a] = Some(r);
            a += 1;
            r += 1;
        } else if table[(a + 1) * stride + r] >= table[a * stride + r + 1] {
            a += 1;
        } else {
            r += 1;
        }
    }
    mapping
}

struct Grade {
    matched: usize,
    total: usize,
    line_match_pct: f64,
    first_mismatch: Option<Mismatch>,
}

struct Mismatch {
    authored_ordinal: usize,
    authored: String,
    recovered: String,
}

fn grade(recovered: &str, authored: &str) -> Grade {
    let auth_lines: Vec<String> = code_lines(authored);
    let rec_lines: Vec<String> = code_lines(recovered);
    let mapping: Vec<Option<usize>> = align_in_order(&auth_lines, &rec_lines);

    let matched: usize = mapping
        .iter()
        .filter(|m: &&Option<usize>| m.is_some())
        .count();
    let mut first_mismatch: Option<Mismatch> = None;
    let mut cursor: usize = 0;
    for (index, slot) in mapping.iter().enumerate() {
        match slot {
            Some(r) => cursor = r + 1,
            None => {
                if first_mismatch.is_none() {
                    first_mismatch = Some(Mismatch {
                        authored_ordinal: index + 1,
                        authored: auth_lines[index].clone(),
                        recovered: rec_lines
                            .get(cursor)
                            .cloned()
                            .unwrap_or_else(|| "<past end of recovered source>".to_owned()),
                    });
                }
            }
        }
    }

    Grade {
        matched,
        total: auth_lines.len(),
        line_match_pct: 100.0 * matched as f64 / auth_lines.len().max(1) as f64,
        first_mismatch,
    }
}

fn assert_line_match(label: &str, grade: &Grade, floor_pct: f64, expected_total: usize) {
    let detail: String = grade.first_mismatch.as_ref().map_or_else(
        || "every authored line matched in order".to_owned(),
        |m: &Mismatch| {
            format!(
                "first unmatched authored line {}\n  authored:  {}\n  recovered: {}",
                m.authored_ordinal, m.authored, m.recovered
            )
        },
    );
    println!(
        "{label}: in-order line match {:.2}% ({}/{})\n{label}: {detail}",
        grade.line_match_pct, grade.matched, grade.total
    );
    assert_eq!(
        grade.total, expected_total,
        "{label} authored code-line count changed; the match rate denominator is pinned so a \
         shrinking fixture cannot raise the rate"
    );
    assert!(
        grade.line_match_pct >= floor_pct,
        "{label} in-order line match {:.2}% below floor {floor_pct:.2}% ({}/{})\n{detail}",
        grade.line_match_pct,
        grade.matched,
        grade.total
    );
}

fn assert_every_line_lifted(label: &str, lift: &SemanticLift) {
    let markers: Vec<&str> = lift
        .pseudocode
        .lines()
        .filter(|l: &&str| l.trim_start().starts_with("' [pcode] "))
        .collect();
    assert!(
        markers.is_empty(),
        "{label} emitted {} raw p-code passthrough lines; first: {}",
        markers.len(),
        markers.first().unwrap_or(&"")
    );
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

const SOURCEPROBE_LINE_FLOOR_PCT: f64 = 100.0;
const SOURCEPROBE_AUTHORED_LINES: usize = 71;
const EDGECASES_LINE_FLOOR_PCT: f64 = 100.0;
const EDGECASES_AUTHORED_LINES: usize = 552;

#[test]
fn sourceprobe_lift_recovers_authored_source() {
    let lift: SemanticLift = lift_module("vba/sourceprobe.docm", "SourceProbe");
    let authored: String = std::fs::read_to_string(corpus_path("vba/sourceprobe/SourceProbe.bas"))
        .expect("read SourceProbe.bas");
    assert_every_line_lifted("SourceProbe", &lift);
    assert!(
        lift.walls.is_empty(),
        "well-formed module must not need block closures inferred by the lifter; walls={:?}",
        lift.walls
    );
    let g: Grade = grade(&lift.pseudocode, &authored);
    assert_line_match(
        "SourceProbe",
        &g,
        SOURCEPROBE_LINE_FLOOR_PCT,
        SOURCEPROBE_AUTHORED_LINES,
    );
    assert_constructs(&lift.pseudocode, &authored, ALL_CONSTRUCTS);
}

#[test]
fn edgecases_lift_recovers_authored_source() {
    let lift: SemanticLift = lift_module("vba/megafile.docm", "EdgeCases");
    let authored: String = std::fs::read_to_string(corpus_path("vba/megafile/EdgeCases.bas"))
        .expect("read EdgeCases.bas");
    assert_every_line_lifted("EdgeCases", &lift);
    let g: Grade = grade(&lift.pseudocode, &authored);
    assert_line_match(
        "EdgeCases",
        &g,
        EDGECASES_LINE_FLOOR_PCT,
        EDGECASES_AUTHORED_LINES,
    );
    assert_constructs(&lift.pseudocode, &authored, ALL_CONSTRUCTS);
}

const IF_BLOCK: &str = "If a > b Then\n    x = a - b\nEnd If\n";

#[test]
fn identical_source_matches_every_line() {
    let g: Grade = grade(IF_BLOCK, IF_BLOCK);
    assert_eq!((g.matched, g.total), (3, 3));
}

#[test]
fn flipped_comparison_direction_does_not_match() {
    let recovered: &str = "If a < b Then\n    x = a - b\nEnd If\n";
    assert_eq!(grade(recovered, IF_BLOCK).matched, 2);
}

#[test]
fn swapped_operands_do_not_match() {
    let recovered: &str = "If a > b Then\n    x = b - a\nEnd If\n";
    assert_eq!(grade(recovered, IF_BLOCK).matched, 2);
}

#[test]
fn widened_comparison_does_not_match() {
    let recovered: &str = "If a >= b Then\n    x = a - b\nEnd If\n";
    assert_eq!(grade(recovered, IF_BLOCK).matched, 2);
}

#[test]
fn reordered_lines_do_not_all_match() {
    let recovered: &str = "End If\n    x = a - b\nIf a > b Then\n";
    assert_eq!(grade(recovered, IF_BLOCK).matched, 1);
}

#[test]
fn one_recovered_line_cannot_satisfy_many_authored_lines() {
    let recovered: &str = "If a > b Then\n";
    let authored: &str = "If a > b Then\nIf a > b Then\nIf a > b Then\n";
    assert_eq!(grade(recovered, authored).matched, 1);
}

#[test]
fn missing_lines_are_not_covered_by_surplus_recovered_lines() {
    let recovered: &str = "If a > b Then\nEnd If\nEnd If\nEnd If\n";
    assert_eq!(grade(recovered, IF_BLOCK).matched, 2);
}

#[test]
fn whitespace_and_keyword_case_are_free() {
    assert_eq!(normalize("  IF   a > b  Then "), normalize("if a > b then"));
    assert_eq!(normalize("Dim X As Long"), normalize("dim x as long"));
}

#[test]
fn string_literal_case_and_spacing_are_preserved() {
    assert_ne!(normalize("s = \"Hello\""), normalize("s = \"hello\""));
    assert_eq!(normalize("s = \"a  b\""), "s = \"a  b\"");
    assert_eq!(normalize("s = \"it's\""), "s = \"it's\"");
}

#[test]
fn operators_and_operand_order_are_preserved() {
    assert_ne!(normalize("x = a - b"), normalize("x = b - a"));
    assert_ne!(normalize("If a >= b"), normalize("If a > b"));
    assert_ne!(normalize("x = a Or b"), normalize("x = a And b"));
}

#[test]
fn trailing_comments_are_excluded() {
    assert_eq!(normalize("x = 1 ' trailing note"), normalize("x = 1"));
}

#[test]
fn continuations_join_into_one_logical_line() {
    let joined: Vec<String> =
        join_continuations("PointInRect = p.X >= r.X _\n    And p.Y >= r.Y\n");
    assert_eq!(joined, vec!["PointInRect = p.X >= r.X And p.Y >= r.Y"]);
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
