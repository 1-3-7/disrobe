#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_beam::{
    BeamFile, DebugInfo, EzArchive, EzEntry, RecoverySource, parse_dbgi, parse_docs,
    recover_elixir_with_docs, recover_erlang,
};

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("beam")
        .join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

fn tokens(src: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut cur: String = String::new();
    for ch in src.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '@' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.insert(cur);
    }
    out.retain(|t: &String| t.len() >= 2 && !t.chars().next().expect("nonempty").is_ascii_digit());
    out
}

fn recovery_pct(original: &str, recovered: &str) -> f64 {
    let orig: BTreeSet<String> = tokens(original);
    let rec: BTreeSet<String> = tokens(recovered);
    if orig.is_empty() {
        return 100.0;
    }
    let hit: usize = orig.iter().filter(|t: &&String| rec.contains(*t)).count();
    (hit as f64) * 100.0 / (orig.len() as f64)
}

fn beam_from_megafile(suffix: &str) -> BeamFile {
    let bytes: Vec<u8> = read("megafile/edge_cases.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let entry: EzEntry = archive
        .beam_files()
        .into_iter()
        .find(|e: &&EzEntry| e.path.ends_with(suffix) || e.path.contains(suffix))
        .cloned()
        .unwrap_or_else(|| panic!("{suffix} inside edge_cases.ez"));
    BeamFile::parse(&entry.data).expect("parse inner beam")
}

#[test]
fn erlang_abstract_code_recovers_original_above_threshold() {
    let original: String = String::from_utf8(read("megafile/edge_cases.erl")).expect("erl utf8");
    let beam: BeamFile = beam_from_megafile("ebin/edge_cases.beam");
    let surface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.recovered_from, RecoverySource::AbstractCode);
    let pct: f64 = recovery_pct(&original, &surface.source);
    assert!(
        pct >= 95.0,
        "erlang abstract-code recovery regressed: {pct:.1}% (expected >= 95%)"
    );
}

#[test]
fn elixir_dbgi_recovers_original_above_threshold() {
    let original: String = String::from_utf8(read("megafile/edge_cases.ex")).expect("ex utf8");
    let beam: BeamFile = beam_from_megafile("Elixir.EdgeCases.beam");
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    let module_docs = beam.chunks.docs.as_ref().and_then(|d| parse_docs(&d.term));
    let rec = recover_elixir_with_docs(
        beam.module_name().expect("module"),
        &info,
        module_docs.as_ref(),
    )
    .expect("recover");
    let pct: f64 = recovery_pct(&original, &rec.source);
    assert!(
        pct >= 85.0,
        "elixir dbgi recovery regressed: {pct:.1}% (expected >= 85%)"
    );
}

#[test]
fn elixir_dbgi_recovers_moduledoc_and_struct_fields() {
    let beam: BeamFile = beam_from_megafile("Elixir.EdgeCases.beam");
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    let module_docs = beam.chunks.docs.as_ref().and_then(|d| parse_docs(&d.term));
    let rec = recover_elixir_with_docs(
        beam.module_name().expect("module"),
        &info,
        module_docs.as_ref(),
    )
    .expect("recover");

    let module_doc: &str = rec.module_doc.as_deref().expect("moduledoc recovered");
    assert!(
        module_doc.contains("Megafile exercising Elixir constructs"),
        "moduledoc text wrong: {module_doc:?}"
    );

    let names: BTreeSet<String> = rec.struct_fields.iter().map(|f| f.name.clone()).collect();
    for expected in ["id", "name", "email", "tags", "created_at", "meta"] {
        assert!(
            names.contains(expected),
            "defstruct missing field {expected}: got {names:?}"
        );
    }
    assert!(
        rec.source.contains("defstruct ["),
        "rendered source missing defstruct"
    );
    assert!(
        rec.source.contains("@moduledoc"),
        "rendered source missing @moduledoc"
    );
}

#[test]
fn elixir_struct_fields_render_atoms_before_keywords() {
    let beam: BeamFile = beam_from_megafile("Elixir.EdgeCases.beam");
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    let rec = recover_elixir_with_docs(beam.module_name().expect("module"), &info, None)
        .expect("recover");
    let line: &str = rec
        .source
        .lines()
        .find(|l: &&str| l.trim_start().starts_with("defstruct "))
        .expect("defstruct line");
    let first_keyword: Option<usize> = line.find(": ");
    if let Some(kw_pos) = first_keyword {
        let after: &str = &line[kw_pos..];
        assert!(
            !after.contains(", :"),
            "bare atom field after keyword field is invalid Elixir: {line}"
        );
    }
}

#[test]
fn stripped_dbgi_is_honest_core_lift_wall_not_abstract() {
    let bytes: Vec<u8> = read("megafile/edge_cases.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let entry: EzEntry = archive
        .beam_files()
        .into_iter()
        .find(|e: &&EzEntry| e.path.ends_with("ebin/edge_cases.beam"))
        .cloned()
        .expect("erlang beam");
    let stripped: Vec<u8> = strip_chunk(&entry.data, b"Dbgi");
    let beam: BeamFile = BeamFile::parse(&stripped).expect("parse stripped");
    assert!(
        beam.chunks.dbgi.is_none(),
        "Dbgi must be absent after strip"
    );
    let surface = recover_erlang(&beam).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "without Dbgi recovery must fall back to bytecode core-lift, never claim AbstractCode"
    );
    let original: String = String::from_utf8(read("megafile/edge_cases.erl")).expect("erl utf8");
    let pct: f64 = recovery_pct(&original, &surface.source);
    assert!(
        (40.0..98.0).contains(&pct),
        "core-lift (no debug info) should be partial, got {pct:.1}%; \
         100% would mean the wall is fake or the oracle is circular"
    );
    assert!(
        surface.source.contains("-module(edge_cases)"),
        "core-lift must still recover module identity from bytecode"
    );
}

fn strip_chunk(bytes: &[u8], target: &[u8; 4]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len());
    body.extend_from_slice(b"BEAM");
    let mut cursor: usize = 12;
    while cursor + 8 <= bytes.len() {
        let tag: &[u8] = &bytes[cursor..cursor + 4];
        let len: usize = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let padded: usize = len.div_ceil(4) * 4;
        let total: usize = 8 + padded;
        if tag != target {
            body.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
    let inner: Vec<u8> = body[4..].to_vec();
    let mut out: Vec<u8> = Vec::with_capacity(12 + inner.len());
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(
        &u32::try_from(4 + inner.len())
            .expect("form fits")
            .to_be_bytes(),
    );
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&inner);
    out
}
