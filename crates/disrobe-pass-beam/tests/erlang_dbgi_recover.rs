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

use std::path::PathBuf;

use disrobe_pass_beam::{
    BeamFile, DebugInfo, ErlangSurface, EzArchive, RecoverySource, parse_dbgi, recover_erlang,
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

fn erlang_megafile() -> Vec<u8> {
    let bytes: Vec<u8> = std::fs::read(corpus("megafile/edge_cases.ez")).unwrap();
    let archive: EzArchive = EzArchive::parse(&bytes).unwrap();
    archive
        .beam_files()
        .into_iter()
        .find(|e: &&disrobe_pass_beam::EzEntry| e.path.ends_with("ebin/edge_cases.beam"))
        .unwrap()
        .data
        .clone()
}

/// The modern OTP `{debug_info_v1, erl_abstract_code, {Forms, Opts}}` chunk must
/// parse as Erlang abstract code, NOT misclassify as the Elixir `elixir_v1`
/// backend (which shares the `debug_info_v1` tag).
#[test]
fn erlang_dbgi_v1_parses_as_abstract_code() {
    let beam: BeamFile = BeamFile::parse(&erlang_megafile()).unwrap();
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi present");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    match info {
        DebugInfo::ErlangAbstractCode { forms, .. } => {
            assert!(forms.as_list().is_some(), "forms should be a list");
        }
        other => panic!("expected ErlangAbstractCode, got {other:?}"),
    }
}

/// `recover_erlang` on the real OTP-29 megafile routes through the abstract-code
/// path and recovers module attributes + every exported function head, verified
/// against the original `.erl` ground truth (non-circular).
#[test]
fn erlang_megafile_recovers_abstract_surface() {
    let beam: BeamFile = BeamFile::parse(&erlang_megafile()).unwrap();
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.recovered_from, RecoverySource::AbstractCode);
    assert!(surface.source.contains("-module(edge_cases)."));

    let expected_heads: [&str; 10] = [
        "main(",
        "handle_call(",
        "handle_cast(",
        "handle_info(",
        "bit_syntax_decode(",
        "list_comprehension(",
        "guarded_dispatch(",
        "binary_comprehension(",
        "try_demo(",
        "deeply_nested(",
    ];
    let missing: Vec<&str> = expected_heads
        .iter()
        .copied()
        .filter(|h: &&str| !surface.source.contains(h))
        .collect();
    assert!(
        missing.is_empty(),
        "missing function heads {missing:?}\n{}",
        surface.source
    );

    let original: String = std::fs::read_to_string(corpus("megafile/edge_cases.erl")).unwrap();
    let orig_fns: Vec<String> = original
        .lines()
        .filter_map(|l: &str| {
            let t: &str = l.trim_start();
            let first: char = t.chars().next()?;
            if !first.is_ascii_lowercase() {
                return None;
            }
            let name: String = t
                .chars()
                .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let rest: &str = &t[name.len()..];
            (rest.starts_with('(') && t.contains("->")).then_some(name)
        })
        .collect();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let recovered: usize = orig_fns
        .iter()
        .filter(|n: &&String| seen.insert((*n).clone()))
        .filter(|n: &&String| {
            surface.source.contains(&format!("{n}(")) || surface.source.contains(&format!("\n{n} "))
        })
        .count();
    let total: usize = seen.len();
    let pct: f64 = (recovered as f64) * 100.0 / (total as f64);
    println!("erlang abstract-code fn-head recovery: {recovered}/{total} = {pct:.1}%");
    assert!(
        pct >= 95.0,
        "expected >=95% fn-head recovery, got {pct:.1}% ({recovered}/{total})"
    );
}
