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

struct Parity {
    matched_lines: usize,
    total_lines: usize,
    matched_instrs: usize,
    total_instrs: usize,
    mismatches: Vec<String>,
}

fn measure_parity(golden: &ModuleLines, disrobe: &ModuleLines) -> Parity {
    let mut p: Parity = Parity {
        matched_lines: 0,
        total_lines: 0,
        matched_instrs: 0,
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
            let g: &Vec<String> = golden_lines.get(&idx).unwrap_or(&empty);
            let d: &Vec<String> = disrobe_lines.get(&idx).unwrap_or(&empty);
            if g.is_empty() && d.is_empty() {
                continue;
            }
            p.total_lines += 1;
            if g == d {
                p.matched_lines += 1;
            } else if p.mismatches.len() < 20 {
                p.mismatches.push(format!(
                    "[{module} L{idx}]\n  pcodedmp: {g:?}\n  disrobe:  {d:?}"
                ));
            }
            let n: usize = g.len().max(d.len());
            p.total_instrs += n;
            for i in 0..n {
                if g.get(i) == d.get(i) {
                    p.matched_instrs += 1;
                }
            }
        }
    }
    p
}

fn assert_full_parity(tag: &str, docm: &str, golden_file: &str, min_instrs: usize) {
    let bin: Vec<u8> = vbaproject_from_docm(docm);
    let report: RealPCodeReport = disassemble_pcode_real(&bin).expect("disasm real p-code");
    let golden_text: String = std::fs::read_to_string(golden_path(golden_file))
        .unwrap_or_else(|e: std::io::Error| panic!("read golden {golden_file}: {e}"));
    let golden: ModuleLines = parse_pcodedmp_golden(&golden_text);
    let disrobe: ModuleLines = disrobe_module_lines(&report);
    let p: Parity = measure_parity(&golden, &disrobe);
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
        p.matched_instrs, p.total_instrs,
        "{tag}: every disassembled opcode+operand must match the pcodedmp golden byte-for-byte"
    );
    assert_eq!(p.matched_lines, p.total_lines);
}

#[test]
fn megafile_disasm_matches_pcodedmp_golden() {
    assert_full_parity(
        "megafile",
        "vba/megafile.docm",
        "megafile.pcodedmp.txt",
        1800,
    );
}

#[test]
fn sourceprobe_disasm_matches_pcodedmp_golden() {
    assert_full_parity(
        "sourceprobe",
        "vba/sourceprobe.docm",
        "sourceprobe.pcodedmp.txt",
        170,
    );
}

#[test]
fn hello_disasm_matches_pcodedmp_golden() {
    assert_full_parity("hello", "vba/hello.docm", "hello.pcodedmp.txt", 4);
}
