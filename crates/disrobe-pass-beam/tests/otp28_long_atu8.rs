#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{BeamFile, RawBeam, RawChunk};

use common::erlang_toolchain::{Erlang, otp_version, require_erlang, run_bounded};

const GRADED: &str = "OTP 28 long AtU8 atom parsing";
const OTP_VERSION: &str = "28.5.0.3";
const EXPECTED_CHARACTER: &str = "é";
const EXPECTED_CHARACTER_COUNT: usize = 255;

fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
        .join(rel)
}

fn fixture_source() -> PathBuf {
    corpus("otp28_long_atu8/otp28_long_atu8.erl")
}

fn expected_atom() -> String {
    EXPECTED_CHARACTER.repeat(EXPECTED_CHARACTER_COUNT)
}

fn require_otp28() -> Erlang {
    let erlang: Erlang = require_erlang(GRADED).unwrap_or_else(|| {
        panic!(
            "the OTP 28 AtU8 integration gate requires erlc and erl; the dedicated CI job must provision OTP {OTP_VERSION}"
        )
    });
    assert_eq!(
        erlang.release, "28",
        "the OTP 28 AtU8 integration gate requires OTP release 28, but erl reports {}",
        erlang.release
    );
    let version: String = otp_version(&erlang.erl)
        .unwrap_or_else(|defect: String| panic!("the full OTP version probe failed: {defect}"));
    assert_eq!(
        version, OTP_VERSION,
        "the OTP 28 AtU8 integration gate requires OTP {OTP_VERSION}, but the OTP_VERSION file reports {version}"
    );
    erlang
}

fn erlc_compile(erlc: &Path, source: &Path, out_dir: &Path) -> (bool, String) {
    let mut command: Command = Command::new(erlc);
    command
        .arg("+deterministic")
        .arg("-o")
        .arg(out_dir)
        .arg(source);
    match run_bounded(command) {
        Some((ok, stdout, stderr)) => (ok, format!("stdout:\n{stdout}\nstderr:\n{stderr}")),
        None => (false, "erlc timed out".to_owned()),
    }
}

fn erl_string_literal(value: &str) -> String {
    let escaped: String = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn beam_lib_atoms_check(erl: &Path, code_dir: &Path, beam: &Path) -> (bool, String) {
    let beam_text: String = beam.to_string_lossy().into_owned();
    let eval: String = format!(
        "Expected = otp28_long_atu8:atom(), {{ok, {{otp28_long_atu8, [{{atoms, Atoms}}]}}}} = beam_lib:chunks({}, [atoms]), true = lists:any(fun({{_, Atom}}) -> Atom =:= Expected end, Atoms), {} = length(atom_to_list(Expected)), true = byte_size(atom_to_binary(Expected, utf8)) > 255, halt(0).",
        erl_string_literal(&beam_text),
        EXPECTED_CHARACTER_COUNT
    );
    let mut command: Command = Command::new(erl);
    command
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&eval);
    match run_bounded(command) {
        Some((ok, stdout, stderr)) => (
            ok,
            format!("eval: {eval}\nstdout:\n{stdout}\nstderr:\n{stderr}"),
        ),
        None => (false, format!("erl timed out evaluating {eval}")),
    }
}

fn fixture_text() -> String {
    let path: PathBuf = fixture_source();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()))
}

fn source_with_256_character_atom(source: &str) -> String {
    let expected: String = expected_atom();
    let occurrences: usize = source.matches(&expected).count();
    assert_eq!(
        occurrences, 1,
        "the tracked OTP 28 source must contain the exact 255-character atom once"
    );
    let mutant_atom: String = format!("{expected}{EXPECTED_CHARACTER}");
    source.replacen(&expected, &mutant_atom, 1)
}

#[test]
#[ignore = "requires exact OTP 28.5.0.3"]
fn otp28_erlc_long_atu8_atom_is_preserved() {
    let erlang: Erlang = require_otp28();
    let source: String = fixture_text();
    let expected: String = expected_atom();
    let occurrences: usize = source.matches(&expected).count();
    assert_eq!(
        occurrences, 1,
        "the tracked OTP 28 source must contain the exact 255-character atom once"
    );
    let fixture: PathBuf = fixture_source();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_beam_otp28_long_atu8").expect("create scratch directory");
    let out_dir: PathBuf = scratch.path().join("original");
    std::fs::create_dir(&out_dir).expect("create compiler output directory");
    let (compiled, compile_detail): (bool, String) = erlc_compile(&erlang.erlc, &fixture, &out_dir);
    assert!(
        compiled,
        "OTP {OTP_VERSION} erlc rejected the tracked long-AtU8 source:\n{compile_detail}"
    );
    let beam_path: PathBuf = out_dir.join("otp28_long_atu8.beam");
    let beam_bytes: Vec<u8> = std::fs::read(&beam_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", beam_path.display()));
    let raw: RawBeam = RawBeam::parse(&beam_bytes).expect("parse compiler-produced BEAM");
    let long_atom_chunk: &RawChunk = raw
        .find(b"AtU8")
        .expect("OTP 28 compiler must emit an AtU8 atom table");
    let count_prefix: &[u8] = long_atom_chunk
        .data
        .get(..4)
        .expect("AtU8 chunk must carry a signed count");
    let count_bytes: [u8; 4] = count_prefix
        .try_into()
        .expect("AtU8 signed count must occupy four bytes");
    let signed_count: i32 = i32::from_be_bytes(count_bytes);
    assert!(
        signed_count < 0,
        "OTP 28 long-atom encoding must use the negative AtU8 count form, got {signed_count}"
    );
    let parsed: BeamFile = BeamFile::parse(&beam_bytes).expect("parse compiler-produced BEAM");
    assert!(
        parsed
            .chunks
            .atoms
            .atoms
            .iter()
            .any(|atom: &String| atom == &expected),
        "the parsed atom table omitted the 255-character atom"
    );
    let (beam_lib_ok, beam_lib_detail): (bool, String) =
        beam_lib_atoms_check(&erlang.erl, &out_dir, &beam_path);
    assert!(
        beam_lib_ok,
        "OTP beam_lib did not validate the compiler-produced long atom:\n{beam_lib_detail}"
    );
}

#[test]
#[ignore = "requires exact OTP 28.5.0.3"]
fn otp28_erlc_rejects_a_256_character_atom_mutation() {
    let erlang: Erlang = require_otp28();
    let source: String = fixture_text();
    let mutant: String = source_with_256_character_atom(&source);
    let scratch: ScratchDir = ScratchDir::create("disrobe_beam_otp28_long_atu8_mutation")
        .expect("create scratch directory");
    let source_path: PathBuf = scratch.path().join("otp28_long_atu8.erl");
    std::fs::write(&source_path, mutant)
        .unwrap_or_else(|error: std::io::Error| panic!("write {}: {error}", source_path.display()));
    let out_dir: PathBuf = scratch.path().join("mutant");
    std::fs::create_dir(&out_dir).expect("create compiler output directory");
    let (compiled, compile_detail): (bool, String) =
        erlc_compile(&erlang.erlc, &source_path, &out_dir);
    assert!(
        !compiled,
        "OTP {OTP_VERSION} erlc accepted a 256-character atom mutation:\n{compile_detail}"
    );
}
