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

#[test]
fn erlang_megafile_recovers_full_bodies() {
    let beam: BeamFile = BeamFile::parse(&erlang_megafile()).unwrap();
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    let src: &str = &surface.source;

    let expected_fragments: [&str; 12] = [
        "[X * 2 || X <- List, X > 0, X rem 2 =:= 1]",
        "guarded_dispatch(X) when is_integer(X), X > 1000 ->",
        "<<A:8, B:16/big, C:32/little, Rest/binary>>",
        "M1 = M0#{three => 3, four => 4}",
        "State#state{count = C + N}",
        "[{K, V} || {K, V} <- Pairs, is_atom(K), is_integer(V), V > 0]",
        "[{X, Y} || X <- Xs, Y <- Ys, X =/= Y]",
        "<< <<X:8>> || <<X:8>> <= Bin",
        "fun(X) -> X + N end",
        "after 1000 ->",
        "io:format",
        "999999999999999999999",
    ];
    let missing: Vec<&str> = expected_fragments
        .iter()
        .copied()
        .filter(|f: &&str| !src.contains(f))
        .collect();
    assert!(
        missing.is_empty(),
        "missing recovered constructs {missing:?}\n--- recovered (lines 70-130) ---\n{}",
        src.lines().skip(69).take(60).collect::<Vec<_>>().join("\n")
    );

    let original: String = std::fs::read_to_string(corpus("megafile/edge_cases.erl")).unwrap();
    let orig: std::collections::BTreeSet<String> = sig_tokens(&original);
    let rec: std::collections::BTreeSet<String> = sig_tokens(src);
    let hit: usize = orig.iter().filter(|t: &&String| rec.contains(*t)).count();
    let pct: f64 = (hit as f64) * 100.0 / (orig.len() as f64);
    println!(
        "erlang abstract-code token recovery: {hit}/{} = {pct:.1}%",
        orig.len()
    );
    assert!(
        pct >= 98.0,
        "expected >=98% token recovery from abstract code, got {pct:.1}%"
    );
}

#[test]
fn erlang_no_dbgi_core_lift_recovers_module_attributes() {
    let bytes: Vec<u8> = erlang_megafile();
    let stripped: Vec<u8> = strip_dbgi(&bytes);
    let beam: BeamFile = BeamFile::parse(&stripped).unwrap();
    assert!(beam.chunks.dbgi.is_none(), "Dbgi must be stripped");
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.recovered_from, RecoverySource::CoreLifted);
    assert!(surface.source.starts_with("-module(edge_cases)."));
    assert!(
        surface.source.contains("-behaviour(gen_server)."),
        "behaviour attribute should be recovered from the Attr chunk\n{}",
        &surface.source[..surface.source.len().min(400)]
    );
    assert!(
        !surface.source.contains("module_info"),
        "compiler-injected module_info must not appear"
    );
    assert!(
        !surface.source.contains("-import("),
        "BIF/external calls are not -import directives"
    );
    assert!(surface.source.contains("main() ->"));
    assert!(surface.source.contains("handle_call("));
}

#[test]
fn erlang_no_dbgi_resugars_single_generator_list_comprehension() {
    let stripped: Vec<u8> = strip_dbgi(&erlang_megafile());
    let beam: BeamFile = BeamFile::parse(&stripped).unwrap();
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    let src: &str = &surface.source;

    let lc_line: &str = src
        .lines()
        .skip_while(|l: &&str| !l.starts_with("list_comprehension(X0)"))
        .nth(1)
        .expect("list_comprehension body line");
    assert!(
        lc_line.contains("* 2") && lc_line.contains("rem 2") && lc_line.contains("<-"),
        "plain comprehension should recover the element and rem filter: {lc_line}"
    );
    assert!(
        !src.contains("list_comprehension/1-lc$^0"),
        "the inlined plain helper must be removed"
    );

    let filtered_line: &str = src
        .lines()
        .skip_while(|l: &&str| !l.starts_with("list_comprehension_filtered(X0)"))
        .nth(1)
        .expect("filtered body line");
    assert!(
        filtered_line.contains("{T0, T1} || {T0, T1} <-"),
        "tuple-pattern generator should be recovered as a tuple pattern: {filtered_line}"
    );
    assert!(
        !src.contains("list_comprehension_filtered/1-lc$^0"),
        "the inlined tuple-pattern helper must be removed"
    );

    assert!(
        src.contains("'-higher_order/2-lc$^0/1-0-'(X1, X0)"),
        "a capture-carrying comprehension keeps its faithful helper recursion"
    );

    assert_no_dangling_lc_helpers(src);
}

fn assert_no_dangling_lc_helpers(src: &str) {
    let mut defined: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut called: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for line in src.lines() {
        let trimmed: &str = line.trim_start();
        if let Some(name) = lc_helper_token(trimmed) {
            if trimmed.starts_with(name) && trimmed.contains(") ->") {
                defined.insert(name);
            } else {
                called.insert(name);
            }
        }
    }
    let dangling: Vec<&str> = called.difference(&defined).copied().collect();
    assert!(
        dangling.is_empty(),
        "dangling lc-helper calls (removed but still referenced): {dangling:?}"
    );
}

fn lc_helper_token(line: &str) -> Option<&str> {
    let start: usize = line.find("'-")?;
    let rest: &str = &line[start..];
    let end: usize = rest[2..].find('\'')? + 3;
    let token: &str = &rest[..end];
    token.contains("-lc$^").then_some(token)
}

fn strip_dbgi(bytes: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor: usize = 12;
    while cursor + 8 <= bytes.len() {
        let tag: &[u8] = &bytes[cursor..cursor + 4];
        let len: usize = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let total: usize = 8 + len.div_ceil(4) * 4;
        if tag != b"Dbgi" {
            body.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
    let mut out: Vec<u8> = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(&u32::try_from(4 + body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&body);
    out
}

fn sig_tokens(src: &str) -> std::collections::BTreeSet<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
