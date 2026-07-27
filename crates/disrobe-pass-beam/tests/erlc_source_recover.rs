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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{BeamFile, ErlangSurface, RecoverySource, recover_erlang};

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

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
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

fn strip_chunk(bytes: &[u8], target: &[u8; 4]) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor: usize = 12;
    while cursor + 8 <= bytes.len() {
        let tag: [u8; 4] = [
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ];
        let len: usize = u32::from_be_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let padded: usize = len.div_ceil(4) * 4;
        let total: usize = 8 + padded;
        if &tag != target {
            inner.extend_from_slice(&bytes[cursor..(cursor + total).min(bytes.len())]);
        }
        cursor += total;
    }
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

fn erlc_compile(erlc: &Path, src: &Path, out_dir: &Path) -> (bool, String) {
    let out: std::process::Output = Command::new(erlc)
        .arg("-o")
        .arg(out_dir)
        .arg(src)
        .output()
        .expect("spawn erlc");
    let msg: String = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), msg)
}

fn semantic_exports(beam: &BeamFile) -> BTreeSet<(String, u32)> {
    let mut out: BTreeSet<(String, u32)> = BTreeSet::new();
    for entry in &beam.chunks.exports {
        let Some(name): Option<&str> = beam.chunks.atoms.get(entry.function_atom_index) else {
            continue;
        };
        if name == "module_info" {
            continue;
        }
        out.insert((name.to_owned(), entry.arity));
    }
    out
}

struct Roundtrip {
    stripped_beam: BeamFile,
    surface: ErlangSurface,
    recompiled_ok: bool,
    recompile_msg: String,
    rec_dir: PathBuf,
    orig_dir: PathBuf,
    _scratch: ScratchDir,
}

fn roundtrip(erlc: &Path, module: &str, rel: &str) -> Roundtrip {
    let purpose: String = format!("disrobe_erlc_{module}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let base: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = base.join("orig");
    let rec_dir: PathBuf = base.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let src: PathBuf = corpus(rel);
    let (compiled_ok, msg): (bool, String) = erlc_compile(erlc, &src, &orig_dir);
    assert!(compiled_ok, "corpus source {rel} must compile:\n{msg}");

    let raw: Vec<u8> = std::fs::read(orig_dir.join(format!("{module}.beam"))).expect("read beam");
    let stripped_bytes: Vec<u8> = strip_chunk(&strip_chunk(&raw, b"Dbgi"), b"Docs");
    let stripped_beam: BeamFile = BeamFile::parse(&stripped_bytes).expect("parse stripped");
    assert!(
        stripped_beam.chunks.dbgi.is_none(),
        "{module}: Dbgi must be stripped so the debug-info path cannot fire"
    );

    let surface: ErlangSurface = recover_erlang(&stripped_beam).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "{module}: with Dbgi/Docs stripped, recovery must fall back to bytecode core-lift"
    );

    let rec_src: PathBuf = rec_dir.join(format!("{module}.erl"));
    std::fs::write(&rec_src, &surface.source).expect("write recovered");
    let (recompiled_ok, recompile_msg): (bool, String) = erlc_compile(erlc, &rec_src, &rec_dir);
    Roundtrip {
        stripped_beam,
        surface,
        recompiled_ok,
        recompile_msg,
        rec_dir,
        orig_dir,
        _scratch: scratch,
    }
}

fn run_call(erl: &Path, code_dir: &Path, module: &str, call: &str) -> (bool, String) {
    let eval: String = format!("io:format(\"~p~n\", [{module}:{call}]), halt().");
    let out: std::process::Output = Command::new(erl)
        .current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&eval)
        .output()
        .expect("spawn erl");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

const SOURCES: [(&str, &str); 4] = [
    ("hello", "erlang/hello.erl"),
    ("probe", "disasm_oracle/probe.erl"),
    ("probe2", "disasm_oracle/probe2.erl"),
    ("edge_cases", "megafile/edge_cases.erl"),
];

const RECOMPILE_FLOOR: usize = 4;

#[test]
fn stripped_core_lift_recompiles_to_matching_exports() {
    let Some(erlc): Option<PathBuf> = find_on_path("erlc") else {
        println!("SKIP: erlc not on PATH (Erlang/OTP not installed)");
        return;
    };
    let mut ok: usize = 0;
    for (module, rel) in SOURCES {
        let rt: Roundtrip = roundtrip(&erlc, module, rel);
        assert!(
            rt.recompiled_ok,
            "{module}: erlc rejected the stripped core-lift recovery:\n{}\n\
             --- recovered {module}.erl ---\n{}",
            rt.recompile_msg, rt.surface.source
        );
        let rec_beam: BeamFile = BeamFile::parse(
            &std::fs::read(rt.rec_dir.join(format!("{module}.beam"))).expect("read recompiled"),
        )
        .expect("parse recompiled");
        assert_eq!(
            semantic_exports(&rec_beam),
            semantic_exports(&rt.stripped_beam),
            "{module}: recompiled exports must match the stripped original"
        );
        ok += 1;
    }
    println!("STRIPPED CORE-LIFT RECOMPILE FLOOR: {ok}/{}", SOURCES.len());
    assert!(
        ok >= RECOMPILE_FLOOR,
        "stripped core-lift recompile floor regressed: {ok}/{} (floor {RECOMPILE_FLOOR})",
        SOURCES.len()
    );
}

fn battery(module: &str) -> &'static [&'static str] {
    match module {
        "hello" => &["main()"],
        "probe" => &[
            "add(2, 3)",
            "fac(6)",
            "greet(\"bob\")",
            "classify(42)",
            "classify(some_atom)",
            "classify(3.14)",
            "sumlist([1, 2, 3, 4, 10])",
            "mapkv(#{key => found})",
            "mapkv(#{})",
            "tup()",
        ],
        "probe2" => &[
            "safe_div(10, 4)",
            "safe_div(3, 0)",
            "loop(5)",
            "build_bin(258)",
            "match_bin(<<10, 20, 30, 40>>)",
            "match_bin(nope)",
            "comp([3, -1, 4, -2, 5])",
            "recform()",
            "recget({point, 7, 8, lbl})",
            "bigm()",
            "floats(3, 6)",
            "sel(3)",
            "sel(99)",
            "mapbuild(colour, red)",
            "nested_try(fun() -> ok end)",
            "nested_try(fun() -> throw(boom) end)",
        ],
        "edge_cases" => &[
            "tuple_pivot({1, 2, 3})",
            "tuple_pivot({1, 2, 3, 4})",
            "if_demo(500)",
            "if_demo(50)",
            "if_demo(5)",
            "if_demo(-1)",
            "case_demo({ok, 1})",
            "case_demo(plain_atom)",
            "cond_like(true, false)",
            "cond_like(false, true)",
            "cond_like(false, false)",
            "guarded_dispatch(2000)",
            "guarded_dispatch(5)",
            "guarded_dispatch(1.5)",
            "multi_clause_recur(0)",
            "multi_clause_recur(1)",
            "multi_clause_recur(8)",
            "string_concat_three(<<\"a\">>, <<\"b\">>, <<\"c\">>)",
            "bit_syntax_decode(<<1, 2, 3, 4, 5, 6, 7>>)",
            "bit_syntax_decode(<<9>>)",
            "pattern_match_args({ok, 9})",
            "pattern_match_args({error, boom})",
            "list_comprehension([1, 2, 3, 4, 5])",
            "list_comprehension_filtered([{a, 1}, {b, -2}, {c, 3}])",
            "map_ops()",
            "record_ops()",
            "big_int_demo()",
            "float_arith()",
            "boolean_short_circuit(true, false)",
            "deep_pattern_destructure({user, #{name => n, addr => #{city => c, zip => z}}})",
        ],
        _ => &[],
    }
}

#[test]
fn stripped_core_lift_preserves_call_semantics() {
    let (Some(erlc), Some(erl)): (Option<PathBuf>, Option<PathBuf>) =
        (find_on_path("erlc"), find_on_path("erl"))
    else {
        println!("SKIP: erlc/erl not on PATH (Erlang/OTP not installed)");
        return;
    };
    let mut checked: usize = 0;
    for (module, rel) in SOURCES {
        let rt: Roundtrip = roundtrip(&erlc, module, rel);
        assert!(
            rt.recompiled_ok,
            "{module}: recompile failed, cannot run battery"
        );
        for call in battery(module) {
            let (orig_ok, orig_out): (bool, String) = run_call(&erl, &rt.orig_dir, module, call);
            assert!(
                orig_ok,
                "{module}:{call} must succeed on the original (battery precondition):\n{orig_out}"
            );
            let (rec_ok, rec_out): (bool, String) = run_call(&erl, &rt.rec_dir, module, call);
            assert!(
                rec_ok,
                "{module}:{call} raised on the recovered module but not the original:\n{rec_out}"
            );
            assert_eq!(
                rec_out, orig_out,
                "{module}:{call} produced a different result after core-lift round-trip\n\
                 original: {orig_out:?}\n recovered: {rec_out:?}"
            );
            checked += 1;
        }
    }
    println!("STRIPPED CORE-LIFT SEMANTIC BATTERY: {checked} calls output-identical");
    assert!(checked >= 50, "battery unexpectedly small: {checked}");
}
