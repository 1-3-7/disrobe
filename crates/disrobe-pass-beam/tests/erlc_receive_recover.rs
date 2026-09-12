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

mod common;

use common::erlang_toolchain::{Erlang, require_erlang, run_bounded};

const GRADED: &str =
    "stripped core-lift receive and timeout recovery over the erlang receive corpus";
const CALL_BUDGET_MS: u32 = 5_000;

fn corpus(module: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("beam")
        .join("receive_oracle")
        .join(format!("{module}.erl"))
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

fn erlc_compile(erlc: &Path, src: &Path, out_dir: &Path, flags: &[&str]) -> (bool, String) {
    let mut cmd: Command = Command::new(erlc);
    for flag in flags {
        cmd.arg(flag);
    }
    cmd.arg("-o").arg(out_dir).arg(src);
    match run_bounded(cmd) {
        Some((ok, stdout, stderr)) => (ok, format!("stdout:\n{stdout}\nstderr:\n{stderr}")),
        None => (false, "erlc did not exit within its bound".to_owned()),
    }
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

fn run_call(erl: &Path, code_dir: &Path, module: &str, call: &str) -> String {
    let expression: String = format!(
        "{{Worker, Ref}} = spawn_monitor(fun() -> exit({{disrobe_value, {module}:{call}}}) end), \
         Outcome = receive {{'DOWN', Ref, process, Worker, Reason}} -> Reason \
         after {CALL_BUDGET_MS} -> exit(Worker, kill), disrobe_call_did_not_return end, \
         case Outcome of {{disrobe_value, Value}} -> io:format(\"~p\", [Value]); \
         disrobe_call_did_not_return -> io:format(\"disrobe_call_did_not_return\"); \
         Other -> io:format(\"disrobe_call_raised ~p\", [Other]) end, halt()."
    );
    let mut cmd: Command = Command::new(erl);
    cmd.current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&expression);
    match run_bounded(cmd) {
        Some((true, stdout, _)) => stdout.trim().to_owned(),
        Some((false, stdout, stderr)) => {
            format!(
                "disrobe_erl_exited_nonzero {} {}",
                stdout.trim(),
                stderr.trim()
            )
        }
        None => "disrobe_erl_did_not_exit".to_owned(),
    }
}

struct Roundtrip {
    stripped: BeamFile,
    surface: ErlangSurface,
    orig_dir: PathBuf,
    rec_dir: PathBuf,
    _scratch: ScratchDir,
}

fn roundtrip(
    erlang: &Erlang,
    module: &str,
    rewrite: fn(&str) -> String,
    flags: &[&str],
) -> Roundtrip {
    let scratch: ScratchDir =
        ScratchDir::create(&format!("disrobe_receive_{module}")).expect("create scratch directory");
    let base: PathBuf = scratch.path().to_path_buf();
    let orig_dir: PathBuf = base.join("orig");
    let rec_dir: PathBuf = base.join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let source: PathBuf = corpus(module);
    let (compiled, message): (bool, String) = erlc_compile(&erlang.erlc, &source, &orig_dir, flags);
    assert!(
        compiled,
        "corpus module {module} must compile with {flags:?}:\n{message}"
    );

    let raw: Vec<u8> =
        std::fs::read(orig_dir.join(format!("{module}.beam"))).expect("read original beam");
    let stripped_bytes: Vec<u8> = strip_chunk(&strip_chunk(&raw, b"Dbgi"), b"Docs");
    let stripped: BeamFile = BeamFile::parse(&stripped_bytes).expect("parse stripped beam");
    assert!(
        stripped.chunks.dbgi.is_none(),
        "{module}: Dbgi must be stripped so the debug-info path cannot fire"
    );
    assert!(
        stripped.chunks.docs.is_none(),
        "{module}: Docs must be stripped so documentation metadata cannot influence recovery"
    );

    let surface: ErlangSurface = recover_erlang(&stripped).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "{module}: recovery must fall back to bytecode core-lift"
    );

    let rewritten: String = rewrite(&surface.source);
    let rec_source: PathBuf = rec_dir.join(format!("{module}.erl"));
    std::fs::write(&rec_source, &rewritten).expect("write recovered source");
    let (recompiled, message): (bool, String) =
        erlc_compile(&erlang.erlc, &rec_source, &rec_dir, &[]);
    assert!(
        recompiled,
        "{module}: erlc rejected the recovered source:\n{message}\n--- recovered ---\n{rewritten}"
    );

    Roundtrip {
        stripped,
        surface,
        orig_dir,
        rec_dir,
        _scratch: scratch,
    }
}

fn unchanged(source: &str) -> String {
    source.to_owned()
}

const CLAUSE_BATTERY: [(&str, &str); 18] = [
    ("arith_guard(5)", "big_enough"),
    ("arith_guard(1)", "too_small"),
    ("arith_guard(zzz)", "too_small"),
    ("accessor_guard([1, 2])", "head_one"),
    ("accessor_guard(plain)", "plain_atom"),
    ("atoms(red)", "{picked,1}"),
    ("atoms(green)", "{picked,2}"),
    ("atoms(blue)", "{picked,3}"),
    ("tagged(5)", "{sum,6}"),
    ("selective()", "{3,1,2}"),
    ("guarded(42)", "{big,42}"),
    ("guarded(3)", "{small,3}"),
    ("guarded(-1)", "{nonpos,-1}"),
    ("catch_all(stop)", "stopped"),
    ("catch_all({weird, 1})", "{other,{weird,1}}"),
    ("nested()", "{1,2}"),
    ("sequential()", "{first_a,second_b}"),
    ("server_roundtrip()", "7"),
];

const TIMEOUT_BATTERY: [(&str, &str); 12] = [
    ("idle()", "idle"),
    ("prompt()", "got_ready"),
    ("literal_timeout()", "{timed_out,25}"),
    ("variable_timeout(0)", "{timed_out,0}"),
    ("variable_timeout(25)", "{timed_out,25}"),
    ("infinite()", "went"),
    ("timeout_after_skip()", "still_waiting"),
    ("nested_timeout()", "{7,none}"),
    ("drain(4)", "[1,2,3,4]"),
    ("computed_timeout(3)", "{timed_out,7}"),
    ("called_timeout()", "timed_out"),
    ("shared_tail(marker)", "{marker,default}"),
];

fn battery(module: &str) -> &'static [(&'static str, &'static str)] {
    match module {
        "recv_clauses" => &CLAUSE_BATTERY,
        "recv_timeouts" => &TIMEOUT_BATTERY,
        _ => &[],
    }
}

const MODULES: [&str; 2] = ["recv_clauses", "recv_timeouts"];

fn grade_every_call(erlang: &Erlang, flags: &[&str]) -> (usize, usize) {
    let mut identical: usize = 0;
    let mut total: usize = 0;
    for module in MODULES {
        let trip: Roundtrip = roundtrip(erlang, module, unchanged, flags);
        assert_eq!(
            semantic_exports(&trip.stripped),
            {
                let recompiled: BeamFile = BeamFile::parse(
                    &std::fs::read(trip.rec_dir.join(format!("{module}.beam")))
                        .expect("read recompiled beam"),
                )
                .expect("parse recompiled beam");
                semantic_exports(&recompiled)
            },
            "{module}: the recovered module must export the same functions"
        );
        for (call, expected) in battery(module) {
            total += 1;
            let original: String = run_call(&erlang.erl, &trip.orig_dir, module, call);
            assert_eq!(
                original, *expected,
                "{module}:{call} must produce {expected} on the reference build built with \
                 {flags:?} (corpus precondition), got {original}"
            );
            let recovered: String = run_call(&erlang.erl, &trip.rec_dir, module, call);
            assert_eq!(
                recovered, original,
                "{module}:{call} changed under core-lift recovery of a {flags:?} build\
                 \n--- recovered source ---\n{}",
                trip.surface.source
            );
            identical += 1;
        }
    }
    (identical, total)
}

#[test]
fn stripped_core_lift_preserves_receive_semantics() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let (identical, total): (usize, usize) = grade_every_call(&erlang, &[]);
    println!(
        "BEAM receive recovery: {identical}/{total} calls output-identical under OTP {}",
        erlang.release
    );
    assert_eq!(identical, total);
    assert_eq!(total, CLAUSE_BATTERY.len() + TIMEOUT_BATTERY.len());
}

#[test]
fn stripped_core_lift_preserves_receive_semantics_under_an_untyped_lowering() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let (identical, total): (usize, usize) = grade_every_call(&erlang, &["+no_type_opt"]);
    println!(
        "BEAM receive recovery without type optimization: {identical}/{total} calls \
         output-identical under OTP {}",
        erlang.release
    );
    assert_eq!(identical, total);
    assert_eq!(total, CLAUSE_BATTERY.len() + TIMEOUT_BATTERY.len());
}

fn function_block<'a>(source: &'a str, head: &str) -> &'a str {
    source
        .split("\n\n")
        .find(|block: &&str| block.starts_with(head))
        .unwrap_or_else(|| panic!("recovered source has no function starting with {head:?}"))
}

#[test]
fn recovered_receive_carries_a_timeout_only_where_the_bytecode_waits_with_one() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let trip: Roundtrip = roundtrip(&erlang, "recv_timeouts", unchanged, &[]);
    let source: &str = &trip.surface.source;

    for (head, timeout) in [
        ("idle() ->", "after 0 ->"),
        ("prompt() ->", "after 1000 ->"),
        ("literal_timeout() ->", "after 25 ->"),
        ("timeout_after_skip() ->", "after 25 ->"),
        ("collect(", "after 0 ->"),
        ("shared_tail(", "after 25 ->"),
    ] {
        let block: &str = function_block(source, head);
        assert!(
            block.contains(timeout),
            "{head} lost its `{timeout}` clause:\n{block}"
        );
    }

    let called: &str = function_block(source, "called_timeout() ->");
    assert!(
        called.contains("after 12 ->") || called.contains("after budget() ->"),
        "called_timeout must wait on the folded constant or on the call itself:\n{called}"
    );

    let variable: &str = function_block(source, "variable_timeout(");
    let parameter: &str = variable
        .lines()
        .next()
        .and_then(|line: &str| line.split_once('('))
        .and_then(|(_, rest): (&str, &str)| rest.split_once(')'))
        .map(|(name, _): (&str, &str)| name)
        .expect("variable_timeout head names its parameter");
    assert!(
        variable.contains(&format!("after {parameter} ->")),
        "variable_timeout must wait on its own parameter {parameter}:\n{variable}"
    );

    let infinite: &str = function_block(source, "infinite() ->");
    assert!(
        !infinite.contains("after "),
        "an infinite `wait` must not gain a timeout clause:\n{infinite}"
    );

    let nested: &str = function_block(source, "nested_timeout() ->");
    assert_eq!(
        nested.matches("after 25 ->").count(),
        2,
        "both the inner and the outer timeout must survive:\n{nested}"
    );
}

fn drop_a_timeout_clause(source: &str) -> String {
    let head: &str = "literal_timeout() ->";
    let block: &str = function_block(source, head);
    let lines: Vec<&str> = block.lines().collect();
    let start: usize = lines
        .iter()
        .position(|line: &&str| line.trim_start().starts_with("after "))
        .expect("the recovered literal_timeout carries a timeout clause");
    let end: usize = lines
        .iter()
        .rposition(|line: &&str| line.trim() == "end.")
        .expect("the recovered literal_timeout ends its receive");
    let mut kept: Vec<&str> = lines[..start].to_vec();
    kept.extend_from_slice(&lines[end..]);
    source.replace(block, &kept.join("\n"))
}

#[test]
fn the_runtime_differential_rejects_a_recovered_receive_whose_timeout_was_dropped() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let trip: Roundtrip = roundtrip(&erlang, "recv_timeouts", drop_a_timeout_clause, &[]);
    let original: String = run_call(
        &erlang.erl,
        &trip.orig_dir,
        "recv_timeouts",
        "literal_timeout()",
    );
    assert_eq!(original, "{timed_out,25}");
    let mutated: String = run_call(
        &erlang.erl,
        &trip.rec_dir,
        "recv_timeouts",
        "literal_timeout()",
    );
    assert_eq!(
        mutated, "disrobe_call_did_not_return",
        "dropping the recovered timeout must make the call block, which the differential must \
         observe rather than pass"
    );
    assert_ne!(mutated, original);
}

fn weaken_a_receive_guard(source: &str) -> String {
    let block: &str = function_block(source, "guarded(");
    let lines: Vec<&str> = block.lines().collect();
    let body: usize = lines
        .iter()
        .position(|line: &&str| line.contains("{big,"))
        .unwrap_or_else(|| panic!("the recovered guarded/1 has no big arm:\n{block}"));
    let head: usize = lines[..body]
        .iter()
        .rposition(|line: &&str| line.contains(" when "))
        .unwrap_or_else(|| panic!("the recovered big arm carries no guard:\n{block}"));
    assert!(
        lines[head].contains("10"),
        "the recovered big arm no longer compares against 10, so this control cannot weaken it:\n{}",
        lines[head]
    );
    let mut rewritten: Vec<String> = lines.iter().map(|line: &&str| (*line).to_owned()).collect();
    rewritten[head] = lines[head].replace("10", "0");
    let block_after: String = rewritten.join("\n");
    assert_ne!(block_after, block, "the guard control changed nothing");
    source.replace(block, &block_after)
}

#[test]
fn the_runtime_differential_rejects_a_recovered_receive_with_a_weakened_guard() {
    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let trip: Roundtrip = roundtrip(&erlang, "recv_clauses", weaken_a_receive_guard, &[]);
    let original: String = run_call(&erlang.erl, &trip.orig_dir, "recv_clauses", "guarded(3)");
    assert_eq!(original, "{small,3}");
    let mutated: String = run_call(&erlang.erl, &trip.rec_dir, "recv_clauses", "guarded(3)");
    assert_eq!(
        mutated, "{big,3}",
        "weakening the recovered clause guard must change the observed result"
    );
    assert_ne!(mutated, original);
}
