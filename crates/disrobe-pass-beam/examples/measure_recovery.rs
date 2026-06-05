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

use disrobe_pass_beam::{
    BeamFile, DebugInfo, EzArchive, parse_dbgi, recover_elixir, recover_erlang,
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

fn tokens(src: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut cur: String = String::new();
    for ch in src.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '@' {
            cur.push(ch);
        } else {
            if !cur.is_empty() {
                out.insert(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.insert(cur);
    }
    out.retain(|t: &String| t.len() >= 2 && !t.chars().next().unwrap().is_ascii_digit());
    out
}

fn recovery_pct(original: &str, recovered: &str) -> (usize, usize, f64) {
    let orig: BTreeSet<String> = tokens(original);
    let rec: BTreeSet<String> = tokens(recovered);
    let hit: usize = orig.iter().filter(|t: &&String| rec.contains(*t)).count();
    let total: usize = orig.len();
    let pct: f64 = if total == 0 {
        100.0
    } else {
        (hit as f64) * 100.0 / (total as f64)
    };
    (hit, total, pct)
}

fn elixir_beam(archive: &EzArchive, suffix: &str) -> BeamFile {
    let entry = archive
        .beam_files()
        .into_iter()
        .find(|e| e.path.contains(suffix))
        .unwrap_or_else(|| panic!("{suffix} not in ez"));
    BeamFile::parse(&entry.data).unwrap()
}

fn main() {
    let ez: Vec<u8> = std::fs::read(corpus("megafile/edge_cases.ez")).unwrap();
    let archive: EzArchive = EzArchive::parse(&ez).unwrap();

    println!("== WITH Dbgi (Elixir megafile) ==");
    let original_ex: String = std::fs::read_to_string(corpus("megafile/edge_cases.ex")).unwrap();
    let beam: BeamFile = elixir_beam(&archive, "Elixir.EdgeCases.beam");
    let dbgi = beam.chunks.dbgi.as_ref().unwrap();
    let info: DebugInfo = parse_dbgi(&dbgi.term).unwrap();
    let rec = recover_elixir(beam.module_name().unwrap(), &info).unwrap();
    let (hit, total, pct) = recovery_pct(&original_ex, &rec.source);
    println!("Elixir.EdgeCases: {hit}/{total} tokens = {pct:.1}%");
    let lines: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    println!("--- recovered source (first {lines} lines) ---");
    for (i, line) in rec.source.lines().enumerate().take(lines) {
        println!("{:>4}| {line}", i + 1);
    }

    println!("\n== WITH Dbgi (Erlang abstract-code) ==");
    let original_erl: String = std::fs::read_to_string(corpus("megafile/edge_cases.erl")).unwrap();
    let erl_bytes: Vec<u8> = archive
        .beam_files()
        .into_iter()
        .find(|e| e.path.ends_with("ebin/edge_cases.beam"))
        .unwrap()
        .data
        .clone();
    let erl_beam: BeamFile = BeamFile::parse(&erl_bytes).unwrap();
    let surface = recover_erlang(&erl_beam).unwrap();
    let (h2, t2, p2) = recovery_pct(&original_erl, &surface.source);
    println!(
        "edge_cases (from={:?}): {h2}/{t2} tokens = {p2:.1}%",
        surface.recovered_from
    );
    let missing: BTreeSet<String> = tokens(&original_erl)
        .difference(&tokens(&surface.source))
        .cloned()
        .collect();
    println!("  missing erlang tokens: {missing:?}");
    if std::env::var("DUMP_ERL").is_ok() {
        for (i, line) in surface.source.lines().enumerate() {
            println!("E{:>4}| {line}", i + 1);
        }
    }

    println!("\n== WITHOUT Dbgi (Erlang core-lift, Dbgi stripped) ==");
    let stripped: Vec<u8> = strip_dbgi_chunk(&erl_bytes);
    let no_dbgi: BeamFile = BeamFile::parse(&stripped).unwrap();
    assert!(no_dbgi.chunks.dbgi.is_none(), "Dbgi must be stripped");
    let surface2 = recover_erlang(&no_dbgi).unwrap();
    let (h3, t3, p3) = recovery_pct(&original_erl, &surface2.source);
    println!(
        "edge_cases (from={:?}): {h3}/{t3} tokens = {p3:.1}%",
        surface2.recovered_from
    );
    let missing2: BTreeSet<String> = tokens(&original_erl)
        .difference(&tokens(&surface2.source))
        .cloned()
        .collect();
    println!(
        "  missing no-dbgi tokens ({}): {missing2:?}",
        missing2.len()
    );
    if std::env::var("DUMP_NODBGI").is_ok() {
        for (i, line) in surface2.source.lines().enumerate() {
            println!("N{:>4}| {line}", i + 1);
        }
    }
}

/// Rebuilds a BEAM IFF dropping the `Dbgi` chunk so the recover path is forced
/// onto the register-named core-lift (the honest no-Dbgi cohort).
fn strip_dbgi_chunk(bytes: &[u8]) -> Vec<u8> {
    let mut chunks: Vec<u8> = Vec::with_capacity(bytes.len());
    chunks.extend_from_slice(b"BEAM");
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
        if tag != b"Dbgi" {
            chunks.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
    let body: Vec<u8> = chunks[4..].to_vec();
    let mut out: Vec<u8> = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(b"FOR1");
    out.extend_from_slice(&u32::try_from(4 + body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&body);
    out
}
