#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_shell::{RealPCodeLine, RealPCodeReport, disassemble_pcode_real};

type ModuleLines = BTreeMap<String, BTreeMap<usize, Vec<String>>>;

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
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

fn normalize_instr(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn parse_pcodedmp_golden(text: &str) -> ModuleLines {
    let mut mods: ModuleLines = BTreeMap::new();
    let mut current_module: Option<String> = None;
    let mut current_line: Option<usize> = None;
    let mut in_streams: bool = false;
    for raw in text.lines() {
        if raw.trim() == "Module streams:" {
            in_streams = true;
            continue;
        }
        if !in_streams {
            continue;
        }
        if let Some(rest) = raw.strip_prefix("VBA/")
            && let Some((name, _)) = rest.split_once(" - ")
        {
            current_module = Some(name.trim().to_owned());
            current_line = None;
            mods.entry(name.trim().to_owned()).or_default();
            continue;
        }
        if let Some(rest) = raw.strip_prefix("Line #")
            && let Some(idx) = rest
                .strip_suffix(':')
                .and_then(|d: &str| d.trim().parse().ok())
            && let Some(module) = current_module.as_ref()
        {
            current_line = Some(idx);
            mods.entry(module.clone())
                .or_default()
                .entry(idx)
                .or_default();
            continue;
        }
        if raw.starts_with('\t')
            && let (Some(module), Some(idx)) = (current_module.as_ref(), current_line)
        {
            let instr: String = normalize_instr(raw);
            if !instr.is_empty() {
                mods.entry(module.clone())
                    .or_default()
                    .entry(idx)
                    .or_default()
                    .push(instr);
            }
        }
    }
    mods
}

fn disrobe_module_lines(report: &RealPCodeReport) -> ModuleLines {
    let mut mods: ModuleLines = BTreeMap::new();
    for module in &report.modules {
        let entry: &mut BTreeMap<usize, Vec<String>> = mods.entry(module.name.clone()).or_default();
        for line in &module.lines {
            let bucket: &mut Vec<String> = entry.entry(line.line_index).or_default();
            collect_line_instrs(line, bucket);
        }
    }
    mods
}

fn collect_line_instrs(line: &RealPCodeLine, bucket: &mut Vec<String>) {
    for text in line.text.lines() {
        if text.contains("<empty>") {
            continue;
        }
        let instr: String = normalize_instr(text);
        if !instr.is_empty() {
            bucket.push(instr);
        }
    }
}

const PCODEDMP_SHIFTED_TABLE_INDEX_FLOOR: usize = 0xBF;
const MEGAFILE_PCODEDMP_SHIFTED_LINES: usize = 122;
const MEGAFILE_PCODEDMP_UNRESOLVED_NAME_LINES: usize = 1;
const MEGAFILE_PCODEDMP_TRUNCATED_ARG_LINES: usize = 19;
const SOURCEPROBE_PCODEDMP_TRUNCATED_ARG_LINES: usize = 2;
const MEGAFILE_PCODEDMP_UNRESOLVED_TYPE_LINES: usize = 21;
const SOURCEPROBE_PCODEDMP_UNRESOLVED_TYPE_LINES: usize = 2;

fn segments(text: &str) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new();
    for ch in text.chars() {
        let is_word: bool = ch.is_ascii_alphanumeric() || ch == '_';
        match out.last_mut() {
            Some((kind, buf)) if *kind == is_word => buf.push(ch),
            _ => out.push((is_word, ch.to_string())),
        }
    }
    out
}

fn is_table_predecessor(identifiers: &[String], golden: &str, disrobe: &str) -> bool {
    identifiers
        .iter()
        .enumerate()
        .skip(PCODEDMP_SHIFTED_TABLE_INDEX_FLOOR)
        .any(|(i, name): (usize, &String)| {
            name == disrobe && identifiers.get(i - 1).is_some_and(|p: &String| p == golden)
        })
}

fn is_unresolved_placeholder(text: &str) -> bool {
    text.strip_prefix("id_")
        .is_some_and(|hex: &str| hex.len() == 4 && hex.chars().all(|c: char| c.is_ascii_hexdigit()))
}

fn explain_names(golden: &str, disrobe: &str, identifiers: &[String]) -> Option<NameDefects> {
    let g: Vec<(bool, String)> = segments(golden);
    let d: Vec<(bool, String)> = segments(disrobe);
    if g.len() != d.len() {
        return None;
    }
    let mut defects: NameDefects = NameDefects {
        shifted: false,
        unresolved: false,
    };
    for ((g_word, g_text), (d_word, d_text)) in g.iter().zip(d.iter()) {
        if g_word != d_word {
            return None;
        }
        if g_text == d_text {
            continue;
        }
        if !*g_word {
            return None;
        }
        if is_unresolved_placeholder(g_text) && identifiers.iter().any(|n: &String| n == d_text) {
            defects.unresolved = true;
            continue;
        }
        if is_table_predecessor(identifiers, g_text, d_text) {
            defects.shifted = true;
            continue;
        }
        return None;
    }
    Some(defects)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NameDefects {
    shifted: bool,
    unresolved: bool,
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth: usize = 0;
    for (offset, ch) in text[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn keep_only_first_parameter(text: &str) -> Option<String> {
    let open: usize = text.match_indices('(').nth(1)?.0;
    let close: usize = matching_paren(text, open)?;
    let args: &str = text.get(open + 1..close)?;
    let comma: usize = args.find(", ")?;
    Some(format!(
        "{}{}{}",
        &text[..=open],
        &args[..comma],
        &text[close..]
    ))
}

const TYPE_SLOT: char = '\u{1}';
const CLAUSE_HEADS: [&str; 2] = [" (As ", " (New As "];

fn parenthesised_clause_end(chars: &[char], at: usize) -> Option<usize> {
    let starts_a_clause: bool = CLAUSE_HEADS
        .iter()
        .any(|h: &&str| chars[at..].starts_with(&h.chars().collect::<Vec<char>>()[..]));
    if !starts_a_clause {
        return None;
    }
    let mut depth: usize = 0;
    for (offset, ch) in chars[at + 1..].iter().enumerate() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at + offset + 2);
                }
            }
            _ => {}
        }
    }
    None
}

fn bare_type_end(chars: &[char], start: usize) -> usize {
    let mut end: usize = start;
    while end < chars.len() {
        if chars[end] == '(' && chars.get(end + 1) == Some(&')') {
            end += 2;
            continue;
        }
        if chars[end] == ',' || chars[end] == ')' {
            break;
        }
        end += 1;
    }
    end
}

fn split_type_clauses(text: &str) -> (String, Vec<String>) {
    let chars: Vec<char> = text.chars().collect();
    let as_marker: Vec<char> = " As ".chars().collect();
    let mut skeleton: String = String::new();
    let mut types: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        if let Some(end) = parenthesised_clause_end(&chars, i) {
            let inner: String = chars[i + 2..end - 1].iter().collect();
            types.push(
                inner
                    .trim_start_matches("New ")
                    .trim_start_matches("As ")
                    .to_owned(),
            );
            i = end;
            continue;
        }
        if chars[i..].starts_with(&as_marker[..]) {
            let start: usize = i + as_marker.len();
            let end: usize = bare_type_end(&chars, start);
            let mut name: String = chars[start..end].iter().collect::<String>();
            name.truncate(name.trim_end().len());
            if let Some(head) = skeleton.strip_suffix("()") {
                skeleton = head.to_owned();
                name.push_str("()");
            }
            types.push(name);
            skeleton.push(TYPE_SLOT);
            i = end;
            continue;
        }
        skeleton.push(chars[i]);
        i += 1;
    }
    (skeleton, types)
}

fn pcodedmp_could_not_render(golden: &str, disrobe: &str) -> bool {
    if disrobe.is_empty() {
        return false;
    }
    let unnamed: bool = golden.is_empty() || golden == "<crash>";
    let array_only_in_disrobe: bool = disrobe.ends_with("()") && !golden.ends_with("()");
    unnamed || array_only_in_disrobe
}

fn type_lists_align(golden: &[String], disrobe: &[String]) -> bool {
    let mut reachable: Vec<bool> = vec![false; golden.len() + 1];
    reachable[0] = true;
    for d in disrobe {
        let mut next: Vec<bool> = reachable.clone();
        for i in 0..golden.len() {
            let compatible: bool = golden[i] == *d || pcodedmp_could_not_render(&golden[i], d);
            if reachable[i] && compatible {
                next[i + 1] = true;
            }
        }
        reachable = next;
    }
    reachable[golden.len()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Explanation {
    shifted: bool,
    unresolved: bool,
    truncated: bool,
    typed: bool,
}

fn explain_divergence(golden: &str, disrobe: &str, identifiers: &[String]) -> Option<Explanation> {
    for truncated in [false, true] {
        let candidate: String = if truncated {
            keep_only_first_parameter(disrobe)?
        } else {
            disrobe.to_owned()
        };
        let (golden_skeleton, golden_types): (String, Vec<String>) = split_type_clauses(golden);
        let (candidate_skeleton, candidate_types): (String, Vec<String>) =
            split_type_clauses(&candidate);
        if !type_lists_align(&golden_types, &candidate_types) {
            continue;
        }
        let names: NameDefects = if golden_skeleton == candidate_skeleton {
            NameDefects {
                shifted: false,
                unresolved: false,
            }
        } else if let Some(defects) =
            explain_names(&golden_skeleton, &candidate_skeleton, identifiers)
        {
            defects
        } else {
            continue;
        };
        return Some(Explanation {
            shifted: names.shifted,
            unresolved: names.unresolved,
            truncated,
            typed: golden_types != candidate_types,
        });
    }
    None
}

struct Parity {
    matched_lines: usize,
    explained_lines: usize,
    shifted_lines: usize,
    unresolved_name_lines: usize,
    truncated_arg_lines: usize,
    recovered_type_lines: usize,
    total_lines: usize,
    matched_instrs: usize,
    explained_instrs: usize,
    total_instrs: usize,
    mismatches: Vec<String>,
}

fn assert_same_modules(tag: &str, golden: &ModuleLines, disrobe: &ModuleLines) {
    let golden_names: Vec<&str> = golden.keys().map(String::as_str).collect();
    let disrobe_names: Vec<&str> = disrobe.keys().map(String::as_str).collect();
    assert_eq!(
        disrobe_names, golden_names,
        "{tag}: disrobe and pcodedmp must report the same module set"
    );
}

fn measure_parity(golden: &ModuleLines, disrobe: &ModuleLines, identifiers: &[String]) -> Parity {
    let mut p: Parity = Parity {
        matched_lines: 0,
        explained_lines: 0,
        shifted_lines: 0,
        unresolved_name_lines: 0,
        truncated_arg_lines: 0,
        recovered_type_lines: 0,
        total_lines: 0,
        matched_instrs: 0,
        explained_instrs: 0,
        total_instrs: 0,
        mismatches: Vec::new(),
    };
    for (module, golden_lines) in golden {
        let Some(disrobe_lines): Option<&BTreeMap<usize, Vec<String>>> = disrobe.get(module) else {
            p.mismatches.push(format!(
                "module {module} present in pcodedmp but not disrobe"
            ));
            continue;
        };
        let mut line_indices: Vec<usize> = golden_lines
            .keys()
            .chain(disrobe_lines.keys())
            .copied()
            .collect();
        line_indices.sort_unstable();
        line_indices.dedup();
        for idx in line_indices {
            let empty: Vec<String> = Vec::new();
            let golden_instrs: &Vec<String> = golden_lines.get(&idx).unwrap_or(&empty);
            let disrobe_instrs: &Vec<String> = disrobe_lines.get(&idx).unwrap_or(&empty);
            if golden_instrs.is_empty() && disrobe_instrs.is_empty() {
                continue;
            }
            p.total_lines += 1;
            let widest: usize = golden_instrs.len().max(disrobe_instrs.len());
            p.total_instrs += widest;
            let mut line: Option<Explanation> = (golden_instrs.len() == disrobe_instrs.len())
                .then_some(Explanation {
                    shifted: false,
                    unresolved: false,
                    truncated: false,
                    typed: false,
                });
            for slot in 0..widest {
                match (golden_instrs.get(slot), disrobe_instrs.get(slot)) {
                    (Some(golden_instr), Some(disrobe_instr)) if golden_instr == disrobe_instr => {
                        p.matched_instrs += 1;
                    }
                    (Some(golden_instr), Some(disrobe_instr)) => {
                        match explain_divergence(golden_instr, disrobe_instr, identifiers) {
                            Some(defect) => {
                                p.explained_instrs += 1;
                                line = line.map(|acc: Explanation| Explanation {
                                    shifted: acc.shifted || defect.shifted,
                                    unresolved: acc.unresolved || defect.unresolved,
                                    truncated: acc.truncated || defect.truncated,
                                    typed: acc.typed || defect.typed,
                                });
                            }
                            None => line = None,
                        }
                    }
                    _ => line = None,
                }
            }
            if golden_instrs == disrobe_instrs {
                p.matched_lines += 1;
            } else if let Some(defect) = line {
                p.explained_lines += 1;
                p.shifted_lines += usize::from(defect.shifted);
                p.unresolved_name_lines += usize::from(defect.unresolved);
                p.truncated_arg_lines += usize::from(defect.truncated);
                p.recovered_type_lines += usize::from(defect.typed);
            } else if p.mismatches.len() < 20 {
                p.mismatches.push(format!(
                    "[{module} L{idx}]\n  pcodedmp: {golden_instrs:?}\n  disrobe:  {disrobe_instrs:?}"
                ));
            }
        }
    }
    p
}

fn assert_full_parity(
    tag: &str,
    docm: &str,
    golden_file: &str,
    min_instrs: usize,
    expected_shifted_lines: usize,
    expected_unresolved_name_lines: usize,
    expected_truncated_arg_lines: usize,
    expected_recovered_type_lines: usize,
) {
    let bin: Vec<u8> = vbaproject_from_docm(docm);
    let report: RealPCodeReport = disassemble_pcode_real(&bin).expect("disasm real p-code");
    let golden_text: String = std::fs::read_to_string(golden_path(golden_file))
        .unwrap_or_else(|e: std::io::Error| panic!("read golden {golden_file}: {e}"));
    let golden: ModuleLines = parse_pcodedmp_golden(&golden_text);
    let disrobe: ModuleLines = disrobe_module_lines(&report);
    assert_same_modules(tag, &golden, &disrobe);
    let p: Parity = measure_parity(&golden, &disrobe, &report.identifiers);
    assert!(
        p.total_instrs >= min_instrs,
        "{tag}: expected at least {min_instrs} disassembled instructions from the pcodedmp golden, \
         got {} (golden fixture may be stale or truncated)",
        p.total_instrs
    );
    assert!(
        p.mismatches.is_empty(),
        "{tag}: disrobe disassembly diverged from pcodedmp 1.2.6 ({}/{} instructions, {}/{} lines match):\n{}",
        p.matched_instrs,
        p.total_instrs,
        p.matched_lines,
        p.total_lines,
        p.mismatches.join("\n")
    );
    assert_eq!(
        p.matched_instrs + p.explained_instrs,
        p.total_instrs,
        "{tag}: every disassembled opcode+operand must either match the pcodedmp golden \
         byte-for-byte or differ only by a known pcodedmp 1.2.6 defect: reading one \
         identifier-table slot too low, leaving an object reference unresolved, keeping only \
         the first parameter of a declaration, or failing to name a user-defined type"
    );
    assert_eq!(p.matched_lines + p.explained_lines, p.total_lines);
    assert_eq!(
        p.shifted_lines, expected_shifted_lines,
        "{tag}: the count of lines where pcodedmp 1.2.6 names an identifier one table slot too \
         low is pinned; a change here means the resolver moved, not the fixture"
    );
    assert_eq!(
        p.unresolved_name_lines, expected_unresolved_name_lines,
        "{tag}: the count of lines naming an object pcodedmp 1.2.6 leaves as an id_XXXX \
         placeholder is pinned; a change here means the resolver moved, not the fixture"
    );
    assert_eq!(
        p.truncated_arg_lines, expected_truncated_arg_lines,
        "{tag}: the count of declarations where pcodedmp 1.2.6 keeps only the first parameter is \
         pinned; a change here means the parameter chain walk moved, not the fixture"
    );
    assert_eq!(
        p.recovered_type_lines, expected_recovered_type_lines,
        "{tag}: the count of lines carrying a user-defined type name pcodedmp 1.2.6 could not \
         resolve is pinned; a change here means the type resolver moved, not the fixture"
    );
}

#[test]
fn parity_rejects_a_fabricated_disrobe_module() {
    let bin: Vec<u8> = vbaproject_from_docm("vba/hello.docm");
    let report: RealPCodeReport = disassemble_pcode_real(&bin).expect("disasm real p-code");
    let golden_text: String = std::fs::read_to_string(golden_path("hello.pcodedmp.txt"))
        .expect("read hello pcodedmp golden");
    let golden: ModuleLines = parse_pcodedmp_golden(&golden_text);
    let mut disrobe: ModuleLines = disrobe_module_lines(&report);
    assert_same_modules("hello baseline", &golden, &disrobe);
    disrobe
        .entry("FabricatedModule".to_owned())
        .or_default()
        .insert(0, vec!["LitDI2 0x0001".to_owned()]);
    let failure: Result<(), Box<dyn std::any::Any + Send>> = std::panic::catch_unwind(|| {
        assert_same_modules("hello mutation", &golden, &disrobe);
    });
    assert!(failure.is_err(), "a fabricated module must fail parity");
}

#[test]
fn megafile_disasm_matches_pcodedmp_golden() {
    assert_full_parity(
        "megafile",
        "vba/megafile.docm",
        "megafile.pcodedmp.txt",
        1800,
        MEGAFILE_PCODEDMP_SHIFTED_LINES,
        MEGAFILE_PCODEDMP_UNRESOLVED_NAME_LINES,
        MEGAFILE_PCODEDMP_TRUNCATED_ARG_LINES,
        MEGAFILE_PCODEDMP_UNRESOLVED_TYPE_LINES,
    );
}

#[test]
fn sourceprobe_disasm_matches_pcodedmp_golden() {
    assert_full_parity(
        "sourceprobe",
        "vba/sourceprobe.docm",
        "sourceprobe.pcodedmp.txt",
        170,
        0,
        0,
        SOURCEPROBE_PCODEDMP_TRUNCATED_ARG_LINES,
        SOURCEPROBE_PCODEDMP_UNRESOLVED_TYPE_LINES,
    );
}

#[test]
fn hello_disasm_matches_pcodedmp_golden() {
    assert_full_parity(
        "hello",
        "vba/hello.docm",
        "hello.pcodedmp.txt",
        4,
        0,
        0,
        0,
        0,
    );
}

#[test]
fn keeping_only_the_first_parameter_needs_a_real_parameter_list() {
    assert_eq!(
        keep_only_first_parameter("FuncDefn (Public Sub S(ByVal a As Long, ByVal b As Long))"),
        Some("FuncDefn (Public Sub S(ByVal a As Long))".to_owned())
    );
    assert_eq!(
        keep_only_first_parameter("FuncDefn (Public Sub S(ByVal a As Long))"),
        None
    );
    assert_eq!(keep_only_first_parameter("FuncDefn (Public Sub S())"), None);
    assert_eq!(keep_only_first_parameter("Ld a"), None);
}

#[test]
fn shift_allowance_needs_a_real_neighbour_in_the_identifier_table() {
    let identifiers: Vec<String> = vec![String::new(); PCODEDMP_SHIFTED_TABLE_INDEX_FLOOR]
        .into_iter()
        .chain(["contents".to_owned(), "ReadBytes".to_owned()])
        .collect();
    let shifted: NameDefects = NameDefects {
        shifted: true,
        unresolved: false,
    };
    let unresolved: NameDefects = NameDefects {
        shifted: false,
        unresolved: true,
    };
    assert_eq!(
        explain_names("St contents", "St ReadBytes", &identifiers),
        Some(shifted)
    );
    assert_eq!(
        explain_names("New id_3C00", "New ReadBytes", &identifiers),
        Some(unresolved)
    );
    assert_eq!(
        explain_names("New id_3C00", "New Absent", &identifiers),
        None
    );
    assert_eq!(
        explain_names("St ReadBytes", "St contents", &identifiers),
        None
    );
    assert_eq!(
        explain_names("St contents", "St Elsewhere", &identifiers),
        None
    );
    assert_eq!(
        explain_names("Ld contents", "St ReadBytes", &identifiers),
        None
    );
}
