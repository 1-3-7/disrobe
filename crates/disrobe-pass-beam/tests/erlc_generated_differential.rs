#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{BeamFile, ErlangSurface, RecoverySource, recover_erlang};

mod common;

use common::erlang_toolchain::{Erlang, require_erlang, run_bounded};

const PROGRAMS: u64 = 40;
const GRADED: &str = "generated Erlang programs through the stripped core lift";
const VARIABLES: [&str; 4] = ["A", "B", "C", "D"];

struct Generator {
    state: u64,
    bindings: u32,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0xA076_1D64_78BD_642F,
            bindings: 0,
        }
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 33) % bound
    }

    fn atom(&mut self, bound: usize) -> String {
        match self.below(3) {
            0 => self.below(20).to_string(),
            _ => VARIABLES[self.below(bound as u64) as usize].to_owned(),
        }
    }

    fn arithmetic(&mut self, depth: u32, bound: usize) -> String {
        if depth == 0 || self.below(3) == 0 {
            return self.atom(bound);
        }
        let left: String = self.arithmetic(depth - 1, bound);
        let right: String = self.arithmetic(depth - 1, bound);
        match self.below(5) {
            0 => format!("({left} + {right})"),
            1 => format!("({left} - {right})"),
            2 => format!("(({left} * {right}) rem 97)"),
            3 => format!("({left} rem {})", 2 + self.below(9)),
            _ => format!("f({left})"),
        }
    }

    fn guard(&mut self, bound: usize) -> String {
        let left: String = self.arithmetic(1, bound);
        let right: String = self.arithmetic(1, bound);
        let op: &str = ["<", "=<", "=:=", "=/=", ">", ">="][self.below(6) as usize];
        format!("{left} {op} {right}")
    }

    fn guard_test(&mut self, bound: usize) -> String {
        let left: String = self.atom(bound);
        let right: String = self.atom(bound);
        let op: &str = ["<", "=<", "=:=", "=/=", ">", ">="][self.below(6) as usize];
        format!("{left} {op} {right}")
    }

    fn value(&mut self, bound: usize) -> String {
        match self.below(13) {
            8 => format!(
                "g({{{}, {}}})",
                ["small", "big", "other"][self.below(3) as usize],
                self.arithmetic(1, bound)
            ),
            9 => format!(
                "lists:foldl(fun(X, Acc) -> (Acc * 3 + X) rem 1000 end, {}, lists:seq(1, {}))",
                self.arithmetic(1, bound),
                self.below(6)
            ),
            10 => format!(
                "case ({} andalso {}) orelse {} of true -> {}; false -> {} end",
                self.guard(bound),
                self.guard(bound),
                self.guard(bound),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound)
            ),
            11 => {
                let n: u32 = self.bindings;
                self.bindings += 1;
                format!(
                    "begin <<P{n}:8, Q{n}:8, _/binary>> = <<(({}) rem 256), (({}) rem 256), 7>>, P{n} * 256 + Q{n} end",
                    self.arithmetic(1, bound),
                    self.arithmetic(1, bound)
                )
            }
            12 => format!(
                "length(lists:reverse(lists:duplicate({}, $a) ++ \"xyz\"))",
                self.below(5)
            ),
            0 => format!(
                "case {} of true -> {}; false -> {} end",
                self.guard(bound),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound)
            ),
            1 => format!(
                "if {} -> {}; true -> {} end",
                self.guard_test(bound),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound)
            ),
            2 => format!(
                "lists:sum([f(X) || X <- lists:seq(0, {}), X rem 2 =:= {}])",
                self.below(8),
                self.below(2)
            ),
            3 => format!("h({}, {})", self.below(6), self.arithmetic(1, bound)),
            4 => format!(
                "try {} div ({} - {}) catch error:badarith -> -1 end",
                self.arithmetic(1, bound),
                self.atom(bound),
                self.atom(bound)
            ),
            5 => format!(
                "element({}, {{{}, {}, {}}})",
                1 + self.below(3),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound)
            ),
            6 => format!(
                "maps:get(k{}, #{{k0 => {}, k1 => {}}}, {})",
                self.below(3),
                self.arithmetic(1, bound),
                self.arithmetic(1, bound),
                self.below(10)
            ),
            _ => self.arithmetic(2, bound),
        }
    }

    fn module(&mut self, name: &str) -> String {
        let k: u64 = 1 + self.below(5);
        let c: u64 = 1 + self.below(4);
        let mut out: String = format!(
            "-module({name}).\n-export([test/0]).\n\nf(X) when X > {k} -> X - {k};\nf(X) -> X + {k}.\n\nh(0, Acc) -> Acc;\nh(N, Acc) -> h(N - 1, (Acc + N * {c}) rem 1000).\n\ng({{small, V}}) when V < 10 -> V * 2;\ng({{small, V}}) -> V;\ng({{big, V}}) -> V + 100;\ng({{_, V}}) -> -V.\n\ntest() ->\n"
        );
        for (index, name) in VARIABLES.iter().enumerate() {
            let value: String = if index == 0 {
                self.below(10).to_string()
            } else {
                self.value(index)
            };
            writeln!(out, "    {name} = {value},").expect("write to a String");
        }
        let tail: String = self.value(VARIABLES.len());
        writeln!(out, "    {{A, B, C, D, {tail}}}.").expect("write to a String");
        out
    }
}

fn compile(erlang: &Erlang, options: &[&str], src: &Path, out_dir: &Path) -> Result<(), String> {
    let mut cmd: Command = Command::new(&erlang.erlc);
    cmd.args(options).arg("-o").arg(out_dir).arg(src);
    match run_bounded(cmd) {
        Some((true, _, _)) => Ok(()),
        Some((false, so, se)) => Err(format!("stdout:\n{so}\nstderr:\n{se}")),
        None => Err("erlc timed out".to_owned()),
    }
}

fn run_test(erlang: &Erlang, code_dir: &Path, module: &str) -> Option<String> {
    let mut cmd: Command = Command::new(&erlang.erl);
    cmd.current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(format!("io:format(\"~p~n\", [{module}:test()]), halt()."));
    match run_bounded(cmd) {
        Some((true, stdout, _)) => Some(stdout),
        _ => None,
    }
}

fn recovered_source(erlang: &Erlang, base: &Path, module: &str, source: &str) -> (PathBuf, String) {
    let orig_dir: PathBuf = base.join("orig");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    let src: PathBuf = orig_dir.join(format!("{module}.erl"));
    std::fs::write(&src, source).expect("write source");
    compile(erlang, &["+no_debug_info"], &src, &orig_dir)
        .unwrap_or_else(|why: String| panic!("{module} must compile:\n{why}\n{source}"));
    let bytes: Vec<u8> = std::fs::read(orig_dir.join(format!("{module}.beam"))).expect("read beam");
    let beam: BeamFile = BeamFile::parse(&bytes).expect("parse beam");
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(
        surface.recovered_from,
        RecoverySource::CoreLifted,
        "{module}: a +no_debug_info build must recover through the core lift"
    );
    (orig_dir, surface.source)
}

fn recovered_output(
    erlang: &Erlang,
    base: &Path,
    module: &str,
    recovered: &str,
) -> Result<String, String> {
    let rec_dir: PathBuf = base.join("rec");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");
    let rec_src: PathBuf = rec_dir.join(format!("{module}.erl"));
    std::fs::write(&rec_src, recovered).expect("write recovered");
    compile(erlang, &[], &rec_src, &rec_dir)
        .map_err(|why: String| format!("recompile rejected:\n{why}"))?;
    run_test(erlang, &rec_dir, module).ok_or_else(|| "the recovered test/0 failed".to_owned())
}

#[test]
fn generated_programs_recompile_and_run_identically() {
    let erlang: Erlang = require_erlang(GRADED);
    let mut failures: Vec<String> = Vec::new();
    for seed in 0..PROGRAMS {
        let module: String = format!("gen{seed}");
        let source: String = Generator::new(seed).module(&module);
        let scratch: ScratchDir =
            ScratchDir::create(&format!("disrobe_beam_generated_{seed}")).expect("scratch");
        let (orig_dir, recovered): (PathBuf, String) =
            recovered_source(&erlang, scratch.path(), &module, &source);
        let expected: String = run_test(&erlang, &orig_dir, &module)
            .unwrap_or_else(|| panic!("{module}: the generated test/0 must run:\n{source}"));
        match recovered_output(&erlang, scratch.path(), &module, &recovered) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => failures.push(format!(
                "{module}: expected {expected} got {actual}\n--- source ---\n{source}--- recovered ---\n{recovered}"
            )),
            Err(why) => failures.push(format!(
                "{module}: {why}\n--- source ---\n{source}--- recovered ---\n{recovered}"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {PROGRAMS} generated modules diverged:\n{}",
        failures.len(),
        failures.join("\n=====\n")
    );
}

#[test]
fn captured_calls_and_comprehension_helpers_recompile_and_run_identically() {
    let erlang: Erlang = require_erlang(GRADED);
    let scratch: ScratchDir = ScratchDir::create("disrobe_beam_captures").expect("scratch");
    let source: &str = "-module(captures).\n-export([test/0]).\n\
        counter(Parent, N) -> receive {add, V} -> counter(Parent, N + V); stop -> Parent ! {total, N} end.\n\
        test() ->\n\
        Adders = [fun(V) -> V + K end || K <- [1, 10, 100]],\n\
        Applied = [F(5) || F <- Adders],\n\
        Self = self(),\n\
        Pid = spawn(fun() -> counter(Self, 0) end),\n\
        [Pid ! {add, V} || V <- [1, 2, 3]],\n\
        Pid ! stop,\n\
        Total = receive {total, T} -> T after 2000 -> timeout end,\n\
        {Applied, Total}.\n";
    let (orig_dir, recovered): (PathBuf, String) =
        recovered_source(&erlang, scratch.path(), "captures", source);
    let expected: String = run_test(&erlang, &orig_dir, "captures").expect("original runs");
    assert_eq!(expected.trim(), "{[6,15,105],6}");
    assert_eq!(
        recovered_output(&erlang, scratch.path(), "captures", &recovered),
        Ok(expected),
        "--- recovered ---\n{recovered}"
    );
}

#[test]
fn failed_matches_and_generators_still_raise_after_recovery() {
    let erlang: Erlang = require_erlang(GRADED);
    let scratch: ScratchDir = ScratchDir::create("disrobe_beam_badmatch").expect("scratch");
    let source: &str = "-module(matches).\n-export([test/0]).\n\
        deposit(B, V) when V > 0 -> {ok, B + V};\n\
        deposit(B, _) -> {error, B}.\n\
        step(B) -> {ok, B1} = deposit(B, 5), {error, _} = deposit(B1, -1), B1.\n\
        sends(P, L) -> [P ! {add, V} || V <- L].\n\
        test() ->\n\
        Good = step(10),\n\
        Bad = try {ok, X} = deposit(3, -2), X catch error:{badmatch, V} -> {caught, V} end,\n\
        Gen = try sends(self(), not_a_list) catch error:{bad_generator, G} -> {bad, G} end,\n\
        {Good, Bad, Gen}.\n";
    let (orig_dir, recovered): (PathBuf, String) =
        recovered_source(&erlang, scratch.path(), "matches", source);
    let expected: String = run_test(&erlang, &orig_dir, "matches").expect("original runs");
    assert_eq!(expected.trim(), "{15,{caught,{error,3}},{bad,not_a_list}}");
    assert_eq!(
        recovered_output(&erlang, scratch.path(), "matches", &recovered),
        Ok(expected),
        "--- recovered ---\n{recovered}"
    );
}

#[test]
fn the_generator_is_deterministic_and_varied() {
    assert_eq!(Generator::new(3).module("m"), Generator::new(3).module("m"));
    let all: String = (0..PROGRAMS)
        .map(|seed: u64| Generator::new(seed).module("m"))
        .collect();
    for shape in [
        "case ",
        "if ",
        " || X <- ",
        "h(",
        "try ",
        "element(",
        "maps:get(",
        "f(",
        "g({",
        "lists:foldl(",
        "andalso",
        "<<P0:8",
        "lists:duplicate(",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_constant_is_caught() {
    let erlang: Erlang = require_erlang(GRADED);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_beam_generated_mutation").expect("scratch");
    let source: &str = "-module(mutant).\n-export([test/0]).\ntest() -> {1 + 2, 40}.\n";
    let (orig_dir, recovered): (PathBuf, String) =
        recovered_source(&erlang, scratch.path(), "mutant", source);
    let expected: String = run_test(&erlang, &orig_dir, "mutant").expect("original runs");
    let mutated: String = recovered.replacen("40", "41", 1);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    assert_ne!(
        recovered_output(&erlang, scratch.path(), "mutant", &mutated).ok(),
        Some(expected)
    );
}
