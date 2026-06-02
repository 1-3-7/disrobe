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

use std::path::PathBuf;

use disrobe_pass_beam::{BeamFile, EzArchive, RawBeam};

fn corpus_root() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
}

fn load_fixture(rel: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_root().join(rel)).ok()
}

fn read_committed_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

fn megafile_beam_from_ez(inner_suffix: &str) -> BeamFile {
    let bytes: Vec<u8> = read_committed_fixture("megafile/edge_cases.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let inner: &disrobe_pass_beam::EzEntry = archive
        .beam_files()
        .into_iter()
        .find(|e: &&disrobe_pass_beam::EzEntry| e.path.ends_with(inner_suffix))
        .unwrap_or_else(|| panic!("{inner_suffix} inside tracked edge_cases.ez"));
    BeamFile::parse(&inner.data).expect("parse inner beam")
}

#[test]
fn smoke_real_erlang_hello_beam_parses() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("erlang/hello.beam") else {
        eprintln!("skip: erlang/hello.beam corpus fixture absent");
        return;
    };
    let raw: RawBeam = RawBeam::parse(&bytes).expect("raw parse");
    let tags: Vec<String> = raw
        .raw_chunks
        .iter()
        .map(|c: &disrobe_pass_beam::RawChunk| String::from_utf8_lossy(&c.tag).into_owned())
        .collect();
    assert!(tags.iter().any(|t: &String| t == "AtU8" || t == "Atom"));
    assert!(tags.iter().any(|t: &String| t == "Code"));
    assert!(tags.iter().any(|t: &String| t == "ExpT"));
}

#[test]
fn smoke_real_erlang_hello_beam_typed_module() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("erlang/hello.beam") else {
        eprintln!("skip: erlang/hello.beam corpus fixture absent");
        return;
    };
    let beam: BeamFile = BeamFile::parse(&bytes).expect("typed parse");
    assert_eq!(beam.module_name(), Some("hello"));
    let code: &disrobe_pass_beam::CodeChunk = beam.chunks.code.as_ref().expect("Code chunk");
    assert!(code.num_functions >= 1);
    assert!(code.num_labels >= 1);
    assert!(!beam.chunks.exports.is_empty());
    let main: &disrobe_pass_beam::chunks::ExportEntry = beam
        .chunks
        .exports
        .iter()
        .find(|e: &&disrobe_pass_beam::chunks::ExportEntry| {
            beam.chunks
                .atoms
                .get(e.function_atom_index)
                .is_some_and(|n: &str| n == "main")
        })
        .expect("main export");
    assert_eq!(main.arity, 0);
}

#[test]
fn smoke_real_elixir_hello_beam_typed_module() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("elixir/Elixir.Hello.beam") else {
        eprintln!("skip: elixir/Elixir.Hello.beam corpus fixture absent");
        return;
    };
    let beam: BeamFile = BeamFile::parse(&bytes).expect("typed parse");
    assert_eq!(beam.module_name(), Some("Elixir.Hello"));
    assert!(beam.chunks.code.is_some());
    assert!(!beam.chunks.exports.is_empty());
}

#[test]
fn smoke_real_ez_archive_lists_beam() {
    let bytes: Vec<u8> = read_committed_fixture("ez/hello.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let beams: Vec<&disrobe_pass_beam::EzEntry> = archive.beam_files();
    assert!(!beams.is_empty(), "expected at least one .beam in ez");
    let names: Vec<&str> = beams
        .iter()
        .map(|e: &&disrobe_pass_beam::EzEntry| e.path.as_str())
        .collect();
    assert!(names.iter().any(|n: &&str| n.ends_with("hello.beam")));
}

#[test]
fn megafile_real_erlang_beam_typed_module() {
    let beam: BeamFile = megafile_beam_from_ez("ebin/edge_cases.beam");
    assert_eq!(beam.module_name(), Some("edge_cases"));
    let code: &disrobe_pass_beam::CodeChunk = beam.chunks.code.as_ref().expect("Code chunk");
    assert!(
        code.num_functions >= 30,
        "expected many functions, got {}",
        code.num_functions
    );
    assert!(
        beam.chunks.exports.len() >= 30,
        "expected many exports, got {}",
        beam.chunks.exports.len()
    );
    assert!(beam.chunks.attributes.is_some());
    assert!(beam.chunks.compile_info.is_some());
    assert!(
        beam.chunks.atoms.len() >= 80,
        "expected rich atom table, got {}",
        beam.chunks.atoms.len()
    );
}

#[test]
fn megafile_real_erlang_beam_known_atoms_present() {
    let beam: BeamFile = megafile_beam_from_ez("ebin/edge_cases.beam");
    let atoms: Vec<&str> = (1..=beam.chunks.atoms.len())
        .filter_map(|i: usize| beam.chunks.atoms.get(u32::try_from(i).expect("idx fits")))
        .collect();
    let expected: [&str; 8] = [
        "edge_cases",
        "main",
        "gen_server",
        "handle_call",
        "handle_cast",
        "handle_info",
        "init",
        "terminate",
    ];
    for atom in expected {
        assert!(atoms.contains(&atom), "missing atom {atom} in {atoms:?}");
    }
}

#[test]
fn megafile_real_elixir_beam_typed_module() {
    let beam: BeamFile = megafile_beam_from_ez("ebin/Elixir.EdgeCases.beam");
    assert_eq!(beam.module_name(), Some("Elixir.EdgeCases"));
    let code: &disrobe_pass_beam::CodeChunk = beam.chunks.code.as_ref().expect("Code chunk");
    assert!(code.num_functions >= 30);
    assert!(beam.chunks.exports.len() >= 30);
}

#[test]
fn megafile_real_ez_archive_bundles_all_beams() {
    let bytes: Vec<u8> = read_committed_fixture("megafile/edge_cases.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let beams: Vec<&disrobe_pass_beam::EzEntry> = archive.beam_files();
    assert!(
        beams.len() >= 10,
        "expected >=10 beams in ez (1 erlang + 11 elixir), got {}",
        beams.len()
    );
    let names: Vec<&str> = beams
        .iter()
        .map(|e: &&disrobe_pass_beam::EzEntry| e.path.as_str())
        .collect();
    assert!(names.iter().any(|n: &&str| n.ends_with("edge_cases.beam")));
    assert!(
        names
            .iter()
            .any(|n: &&str| n.contains("Elixir.EdgeCases.beam"))
    );
    assert!(names.iter().any(|n: &&str| n.contains("MyServer")));
    assert!(names.iter().any(|n: &&str| n.contains("Renderable")));
}

#[test]
fn megafile_real_ez_each_inner_beam_parses() {
    let bytes: Vec<u8> = read_committed_fixture("megafile/edge_cases.ez");
    let archive: EzArchive = EzArchive::parse(&bytes).expect("ez parse");
    let beams: Vec<&disrobe_pass_beam::EzEntry> = archive.beam_files();
    for entry in beams {
        let beam: BeamFile = BeamFile::parse(&entry.data)
            .unwrap_or_else(|e: disrobe_pass_beam::Error| panic!("parse {}: {e}", entry.path));
        let name: &str = beam.module_name().expect("module name");
        assert!(!name.is_empty(), "module name empty for {}", entry.path);
    }
}
