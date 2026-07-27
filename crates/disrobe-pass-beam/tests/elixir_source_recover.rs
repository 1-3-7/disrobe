#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{
    BeamFile, DebugInfo, ElixirRecovery, ErlangSurface, EzArchive, RecoverySource, parse_dbgi,
    recover_elixir, recover_erlang,
};

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join("beam")
        .join(rel)
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn beam_from_ez(suffix: &str) -> BeamFile {
    let bytes: Vec<u8> = std::fs::read(corpus("megafile/edge_cases.ez")).unwrap();
    let archive: EzArchive = EzArchive::parse(&bytes).unwrap();
    let entry = archive
        .beam_files()
        .into_iter()
        .find(|e: &&disrobe_pass_beam::EzEntry| e.path.contains(suffix))
        .unwrap_or_else(|| panic!("{suffix} not in ez"));
    BeamFile::parse(&entry.data).unwrap()
}

fn recover(beam: &BeamFile) -> ElixirRecovery {
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi present");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    recover_elixir(beam.module_name().unwrap(), &info).expect("recover")
}

fn semantic_exports(beam: &BeamFile) -> BTreeSet<(String, u32)> {
    let mut out: BTreeSet<(String, u32)> = BTreeSet::new();
    for entry in &beam.chunks.exports {
        let Some(name): Option<&str> = beam.chunks.atoms.get(entry.function_atom_index) else {
            continue;
        };
        if name == "__info__" || name == "module_info" {
            continue;
        }
        out.insert((name.to_owned(), entry.arity));
    }
    out
}

fn idents(src: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut cur: String = String::new();
    for ch in src.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.insert(cur);
    }
    out.retain(|t: &String| t.len() >= 2 && !t.chars().next().unwrap().is_ascii_digit());
    out
}

#[test]
fn real_elixir_recovered_source_recompiles_with_elixirc() {
    let Some(elixirc): Option<PathBuf> = find_on_path("elixirc") else {
        println!("SKIP: elixirc not on PATH");
        return;
    };
    let bytes: Vec<u8> = std::fs::read(corpus("elixir/Elixir.Hello.beam")).unwrap();
    let original: BeamFile = BeamFile::parse(&bytes).expect("typed parse");
    let surface: ErlangSurface = recover_erlang(&original).expect("recover");
    assert_eq!(surface.recovered_from, RecoverySource::ElixirDbgiForm);

    let scratch: ScratchDir =
        ScratchDir::create("disrobe_elixir_recompile").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("hello_recovered.ex");
    std::fs::write(&src_path, &surface.source).expect("write recovered ex");
    let out: std::process::Output = Command::new(&elixirc)
        .arg("-o")
        .arg(&dir)
        .arg(&src_path)
        .output()
        .expect("elixirc");
    assert!(
        out.status.success(),
        "recovered Elixir source failed elixirc:\nstdout:\n{}\nstderr:\n{}\nsource:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        surface.source
    );
    let compiled_path: PathBuf = dir.join("Elixir.Hello.beam");
    let compiled_bytes: Vec<u8> = std::fs::read(&compiled_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", compiled_path.display()));
    let compiled: BeamFile = BeamFile::parse(&compiled_bytes).expect("parse recompiled beam");
    assert_eq!(compiled.module_name(), original.module_name());
    assert_eq!(semantic_exports(&compiled), semantic_exports(&original));
}

#[test]
fn elixir_megafile_recovers_real_definition_heads() {
    let beam: BeamFile = beam_from_ez("Elixir.EdgeCases.beam");
    let rec: ElixirRecovery = recover(&beam);

    assert!(rec.source.starts_with("defmodule EdgeCases do"));
    assert!(rec.source.trim_end().ends_with("end"));

    let original: String = std::fs::read_to_string(corpus("megafile/edge_cases.ex")).unwrap();

    let expected_defs: [&str; 12] = [
        "def main do",
        "def pattern_match_basic({:ok, value})",
        "def pipe_chain(list)",
        "def with_demo(map)",
        "def comprehension_simple(list)",
        "def comprehension_multi(xs, ys)",
        "def case_demo(x)",
        "def cond_demo(x)",
        "def map_update(m, k)",
        "def update_struct",
        "def tuple_destructure({a, b, c})",
        "def binary_pattern",
    ];
    let missing: Vec<&str> = expected_defs
        .iter()
        .copied()
        .filter(|d: &&str| !rec.source.contains(d))
        .collect();
    assert!(
        missing.is_empty(),
        "missing recovered defs {missing:?}\n--- recovered ---\n{}",
        rec.source
    );

    let orig_names: BTreeSet<String> = original
        .lines()
        .filter_map(|l: &str| {
            let t: &str = l.trim_start();
            for kw in ["def ", "defp ", "defmacro ", "defmacrop "] {
                if let Some(rest) = t.strip_prefix(kw) {
                    let name: String = rest
                        .chars()
                        .take_while(|c: &char| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            None
        })
        .collect();
    let rec_names: BTreeSet<String> = idents(&rec.source);
    let recovered_count: usize = orig_names
        .iter()
        .filter(|n: &&String| rec_names.contains(*n))
        .count();
    let pct: f64 = (recovered_count as f64) * 100.0 / (orig_names.len() as f64);
    println!(
        "def-name recovery (incl. nested-module defs): {recovered_count}/{} = {pct:.1}%",
        orig_names.len()
    );

    let nested_only: BTreeSet<&str> = [
        "__using__",
        "handle_call",
        "handle_cast",
        "handle_info",
        "init",
        "render",
    ]
    .into_iter()
    .collect();
    let root_names: BTreeSet<&String> = orig_names
        .iter()
        .filter(|n: &&String| !nested_only.contains(n.as_str()))
        .collect();
    let root_recovered: usize = root_names
        .iter()
        .filter(|n: &&&String| rec_names.contains(**n))
        .count();
    let root_pct: f64 = (root_recovered as f64) * 100.0 / (root_names.len() as f64);
    println!(
        "root-module def-name recovery: {root_recovered}/{} = {root_pct:.1}%",
        root_names.len()
    );
    assert!(
        (root_pct - 100.0).abs() < f64::EPSILON,
        "expected 100% root-module def-name recovery, got {root_pct:.1}% ({root_recovered}/{})\nmissing: {:?}",
        root_names.len(),
        root_names
            .iter()
            .filter(|n: &&&String| !rec_names.contains(**n))
            .collect::<Vec<_>>()
    );
}

#[test]
fn elixir_megafile_recovery_is_block_balanced() {
    let beam: BeamFile = beam_from_ez("Elixir.EdgeCases.beam");
    let rec: ElixirRecovery = recover(&beam);
    let opens: usize = count_word_excluding_keyword(&rec.source, "do")
        + count_word_excluding_keyword(&rec.source, "fn");
    let ends: usize = count_word_excluding_keyword(&rec.source, "end");
    assert_eq!(
        opens, ends,
        "unbalanced do/fn ({opens}) vs end ({ends})\n{}",
        rec.source
    );
}

fn count_word_excluding_keyword(src: &str, word: &str) -> usize {
    let bytes: &[u8] = src.as_bytes();
    let mut count: usize = 0;
    let mut start: usize = 0;
    while let Some(rel) = src[start..].find(word) {
        let at: usize = start + rel;
        let before_ok: bool = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after: Option<u8> = bytes.get(at + word.len()).copied();
        let after_is_ident: bool = after.is_some_and(is_ident_byte);
        let after_is_colon: bool = after == Some(b':');
        if before_ok && !after_is_ident && !after_is_colon {
            count += 1;
        }
        start = at + word.len();
    }
    count
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[test]
fn elixir_submodules_recover_headers() {
    for (suffix, module) in [
        ("Elixir.EdgeCases.MyServer.beam", "EdgeCases.MyServer"),
        ("Elixir.EdgeCases.Address.beam", "EdgeCases.Address"),
        ("Elixir.EdgeCases.Greeter.beam", "EdgeCases.Greeter"),
    ] {
        let beam: BeamFile = beam_from_ez(suffix);
        let rec: ElixirRecovery = recover(&beam);
        assert!(
            rec.source.contains(&format!("defmodule {module} do")),
            "module {module}: header missing\n{}",
            rec.source
        );
        assert!(rec.source.trim_end().ends_with("end"));
    }
}

#[test]
fn recover_erlang_routes_elixir_dbgi_to_elixir_source() {
    let beam: BeamFile = beam_from_ez("Elixir.EdgeCases.beam");
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.recovered_from, RecoverySource::ElixirDbgiForm);
    assert!(surface.source.starts_with("defmodule EdgeCases do"));
    assert!(surface.source.contains("def main do"));
    assert!(surface.source.contains("def comprehension_simple(list)"));
}
