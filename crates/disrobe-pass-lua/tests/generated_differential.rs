#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_lua::decompile::{DecompiledChunk, decompile_auto};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const PROGRAMS_PER_LANE: u64 = 5000;
const LANES: [&str; 5] = ["5.1", "5.2", "5.3", "5.4", "5.5"];
const RUN_TIMEOUT: Duration = Duration::from_secs(8);
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;

struct Generator {
    state: u64,
    loop_serial: u32,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
            loop_serial: 0,
        }
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 33) % bound
    }

    const fn variable(&mut self) -> &'static str {
        VARIABLES[self.below(VARIABLES.len() as u64) as usize]
    }

    fn atom(&mut self) -> String {
        match self.below(3) {
            0 => self.below(20).to_string(),
            _ => self.variable().to_owned(),
        }
    }

    fn arithmetic(&mut self, depth: u32) -> String {
        if depth == 0 || self.below(3) == 0 {
            return self.atom();
        }
        let left: String = self.arithmetic(depth - 1);
        let right: String = self.arithmetic(depth - 1);
        match self.below(4) {
            0 => format!("({left} + {right})"),
            1 => format!("({left} - {right})"),
            2 => format!("({left} * {right}) % 97"),
            _ => format!("({left} % {})", 2 + self.below(9)),
        }
    }

    fn condition(&mut self) -> String {
        let left: String = self.arithmetic(1);
        let right: String = self.arithmetic(1);
        let comparison: String = match self.below(6) {
            0 => format!("{left} < {right}"),
            1 => format!("{left} <= {right}"),
            2 => format!("{left} == {right}"),
            3 => format!("{left} ~= {right}"),
            4 => format!("{left} > {right}"),
            _ => format!("{left} >= {right}"),
        };
        match self.below(5) {
            0 => format!("not ({comparison})"),
            1 => format!(
                "({comparison}) and {} > {}",
                self.variable(),
                self.below(10)
            ),
            2 => format!(
                "({comparison}) or {} == {}",
                self.variable(),
                self.below(10)
            ),
            _ => comparison,
        }
    }

    fn value(&mut self) -> String {
        match self.below(6) {
            0 => format!(
                "({}) and {} or {}",
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            1 => format!("(t[{}] or {})", self.below(4), self.arithmetic(1)),
            2 => format!("f({})", self.arithmetic(1)),
            _ => format!("{} % 1000", self.arithmetic(2)),
        }
    }

    fn block(&mut self, depth: u32, indent: usize, out: &mut String) {
        let count: u64 = 1 + self.below(4);
        for _ in 0..count {
            self.statement(depth, indent, out);
        }
    }

    fn statement(&mut self, depth: u32, indent: usize, out: &mut String) {
        let pad: String = "  ".repeat(indent);
        let choice: u64 = if depth >= MAX_BLOCK_DEPTH {
            self.below(4)
        } else {
            self.below(10)
        };
        match choice {
            0 | 1 => {
                let target: &str = self.variable();
                let value: String = self.value();
                writeln!(out, "{pad}{target} = {value}").expect("write to a String");
            }
            2 => {
                let value: String = self.value();
                writeln!(out, "{pad}emit({value})").expect("write to a String");
            }
            3 => {
                let key: u64 = self.below(4);
                let value: String = self.arithmetic(1);
                writeln!(out, "{pad}t[{key}] = {value}").expect("write to a String");
            }
            4 | 5 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if {cond} then").expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                if self.below(2) == 0 {
                    let other: String = self.condition();
                    writeln!(out, "{pad}elseif {other} then").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                if self.below(2) == 0 {
                    writeln!(out, "{pad}else").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                writeln!(out, "{pad}end").expect("write to a String");
            }
            6 => {
                self.loop_serial += 1;
                let var: String = format!("i{}", self.loop_serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                writeln!(out, "{pad}for {var} = {first}, {last} do").expect("write to a String");
                writeln!(
                    out,
                    "{pad}  {} = ({} + {var}) % 1000",
                    self.variable(),
                    self.variable()
                )
                .expect("write to a String");
                self.loop_body(depth, indent, out);
                writeln!(out, "{pad}end").expect("write to a String");
            }
            7 => {
                self.loop_serial += 1;
                let counter: String = format!("n{}", self.loop_serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                writeln!(out, "{pad}local {counter} = 0").expect("write to a String");
                writeln!(
                    out,
                    "{pad}while {counter} < {limit} and ({cond} or {counter} == 0) do"
                )
                .expect("write to a String");
                writeln!(out, "{pad}  {counter} = {counter} + 1").expect("write to a String");
                self.loop_body(depth, indent, out);
                writeln!(out, "{pad}end").expect("write to a String");
            }
            8 => {
                self.loop_serial += 1;
                let counter: String = format!("n{}", self.loop_serial);
                let limit: u64 = 1 + self.below(5);
                write!(out, "{pad}local {counter} = 0\n{pad}repeat\n").expect("write to a String");
                writeln!(out, "{pad}  {counter} = {counter} + 1").expect("write to a String");
                self.loop_body(depth, indent, out);
                let cond: String = self.condition();
                writeln!(out, "{pad}until {counter} >= {limit} or {cond}")
                    .expect("write to a String");
            }
            _ => {
                let value: String = self.arithmetic(2);
                writeln!(out, "{pad}emit({value})").expect("write to a String");
            }
        }
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        if self.below(3) == 0 {
            let pad: String = "  ".repeat(indent + 1);
            let cond: String = self.condition();
            writeln!(out, "{pad}if {cond} then break end").expect("write to a String");
        }
    }

    fn program(&mut self) -> String {
        let mut out: String = String::from(
            "local out = {}\nlocal function emit(v) out[#out + 1] = tostring(v) end\nlocal t = {}\n",
        );
        for name in VARIABLES {
            writeln!(out, "local {name} = {}", self.below(10)).expect("write to a String");
        }
        let k: u64 = 1 + self.below(5);
        writeln!(
            out,
            "local function f(x) if x > {k} then return x - {k} end return x + {k} end"
        )
        .expect("write to a String");
        self.block(0, 0, &mut out);
        out.push_str("emit(a) emit(b) emit(c) emit(d) emit(e)\nprint(table.concat(out, \" \"))\n");
        out
    }
}

fn reports_version(program: &str, version: &str) -> Result<(), String> {
    let output: ToolOutput = tool_output(CommandSpec::new(program, RUN_TIMEOUT).arg("-v"))
        .map_err(|error: disrobe_testkit::ToolError| format!("`{program}`: {error}"))?;
    let banner: String = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if banner.contains(&format!("Lua {version}")) {
        Ok(())
    } else {
        Err(format!("`{program}` reports `{}`", banner.trim()))
    }
}

fn find_program(stem: &str, version: &str) -> String {
    let compact: String = version.replace('.', "");
    let candidates: [String; 4] = [
        format!("{stem}{version}"),
        format!("{stem}{version}.exe"),
        format!("{stem}{compact}"),
        stem.to_owned(),
    ];
    let mut defects: Vec<String> = Vec::new();
    for candidate in &candidates {
        match reports_version(candidate, version) {
            Ok(()) => return candidate.clone(),
            Err(defect) => defects.push(defect),
        }
    }
    panic!(
        "the generated differential needs `{stem}{version}` (Lua {version}) on PATH and cannot \
         grade without it: {}",
        defects.join("; ")
    )
}

fn toolchain(version: &str) -> (String, String) {
    (find_program("luac", version), find_program("lua", version))
}

fn run(lua: &str, script: &Path) -> Result<String, String> {
    let output: ToolOutput = tool_output(CommandSpec::new(lua, RUN_TIMEOUT).arg(script))
        .map_err(|error: disrobe_testkit::ToolError| error.to_string())?;
    if output.timed_out {
        return Err(format!("timed out after {RUN_TIMEOUT:?}"));
    }
    if !output.success {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n"))
}

fn recovered_source(luac: &str, dir: &Path, name: &str, source: &str) -> String {
    let src: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&src, source).expect("write the generated program");
    let bytecode: PathBuf = dir.join(format!("{name}.luac"));
    let compiled: ToolOutput = tool_output(
        CommandSpec::new(luac, RUN_TIMEOUT)
            .args(["-s", "-o"])
            .arg(&bytecode)
            .arg(&src),
    )
    .expect("luac starts");
    assert!(
        compiled.success,
        "{name}: luac -s compiles the generated program:\n{}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes: Vec<u8> = std::fs::read(&bytecode).expect("read the bytecode");
    let decompiled: DecompiledChunk = decompile_auto(&bytes).expect("decompile");
    decompiled.source
}

fn divergences(version: &str) -> (usize, Vec<String>) {
    let label: String = format!("lua{version}");
    let (luac, lua): (String, String) = toolchain(version);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("disrobe_lua_generated_{label}"))
            .expect("scratch dir");
    let dir: &Path = scratch.path();
    let mut failures: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for seed in 0..PROGRAMS_PER_LANE {
        let source: String = Generator::new(seed).program();
        let name: String = format!("gen{seed}");
        let original_path: PathBuf = dir.join(format!("{name}.orig.lua"));
        std::fs::write(&original_path, &source).expect("write original");
        let expected: String = run(&lua, &original_path).unwrap_or_else(|error: String| {
            panic!("{label} seed {seed}: the generated program must run: {error}\n{source}")
        });
        let recovered: String = recovered_source(&luac, dir, &name, &source);
        let recovered_path: PathBuf = dir.join(format!("{name}.dec.lua"));
        std::fs::write(&recovered_path, &recovered).expect("write recovered");
        graded += 1;
        let actual: Result<String, String> = run(&lua, &recovered_path);
        if actual.as_deref() != Ok(expected.as_str()) {
            let shown: String = actual.unwrap_or_else(|error: String| format!("<failed: {error}>"));
            failures.push(format!(
                "{label} seed {seed}\n--- expected ---\n{expected}--- actual ---\n{shown}\n--- source ---\n{source}--- recovered ---\n{recovered}"
            ));
        }
    }
    (graded, failures)
}

fn assert_lane(version: &str) {
    let (graded, failures): (usize, Vec<String>) = divergences(version);
    assert_eq!(graded as u64, PROGRAMS_PER_LANE);
    assert!(
        failures.is_empty(),
        "{} of {graded} generated lua{version} programs re-executed differently:\n{}",
        failures.len(),
        failures.join("\n=====\n")
    );
}

#[test]
fn generated_programs_reexecute_identically_lua_5_1() {
    assert_lane("5.1");
}

#[test]
fn generated_programs_reexecute_identically_lua_5_2() {
    assert_lane("5.2");
}

#[test]
fn generated_programs_reexecute_identically_lua_5_3() {
    assert_lane("5.3");
}

#[test]
fn generated_programs_reexecute_identically_lua_5_4() {
    assert_lane("5.4");
}

#[test]
fn generated_programs_reexecute_identically_lua_5_5() {
    assert_lane("5.5");
}

const PINNED_SHAPES: &[(&str, &str)] = &[
    (
        "testset_pending",
        include_str!("../../../corpus/lua/behaviour/testset_pending.lua"),
    ),
    (
        "branch_reassign",
        include_str!("../../../corpus/lua/behaviour/branch_reassign.lua"),
    ),
    (
        "compare_select",
        include_str!("../../../corpus/lua/behaviour/compare_select.lua"),
    ),
    (
        "loop_locals",
        include_str!("../../../corpus/lua/behaviour/loop_locals.lua"),
    ),
];

#[test]
fn pinned_generated_shapes_reexecute_identically() {
    let mut failures: Vec<String> = Vec::new();
    for version in LANES {
        let (luac, lua): (String, String) = toolchain(version);
        let scratch: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
            &format!("disrobe_lua_generated_pinned_lua{version}"),
        )
        .expect("scratch dir");
        let dir: &Path = scratch.path();
        for (name, source) in PINNED_SHAPES {
            let original_path: PathBuf = dir.join(format!("{name}.orig.lua"));
            std::fs::write(&original_path, source).expect("write original");
            let expected: String = run(&lua, &original_path).unwrap_or_else(|error: String| {
                panic!("lua{version} {name}: the pinned program must run: {error}")
            });
            let recovered: String = recovered_source(&luac, dir, name, source);
            let recovered_path: PathBuf = dir.join(format!("{name}.dec.lua"));
            std::fs::write(&recovered_path, &recovered).expect("write recovered");
            let actual: Result<String, String> = run(&lua, &recovered_path);
            if actual.as_deref() != Ok(expected.as_str()) {
                failures.push(format!(
                    "lua{version} {name}\n--- expected ---\n{expected}--- actual ---\n{actual:?}\n--- recovered ---\n{recovered}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n=====\n"));
}

#[test]
fn the_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).program();
    assert_eq!(first, Generator::new(7).program());
    let distinct: std::collections::BTreeSet<String> = (0..PROGRAMS_PER_LANE)
        .map(|seed: u64| Generator::new(seed).program())
        .collect();
    assert_eq!(distinct.len() as u64, PROGRAMS_PER_LANE);
    let all: String = distinct.into_iter().collect();
    for shape in [
        "while ",
        "repeat\n",
        "for i",
        "elseif ",
        "break end",
        ") and ",
        "f(",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_field_read_feeding_a_tail_call_stays_inline() {
    let (luac, _lua): (String, String) = toolchain("5.4");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_lua_tail_call_inline").expect("scratch");
    let source: &str =
        "local function join(t)\n  return table.concat(t, \",\")\nend\nprint(join({1, 2}))\n";
    let recovered: String = recovered_source(&luac, scratch.path(), "tail_inline", source);
    assert!(
        recovered.contains("return table.concat(") && !recovered.contains("= table.concat"),
        "the unreachable RETURN after a TAILCALL must not count as a second read:\n{recovered}"
    );
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    for version in LANES {
        assert_mutation_is_caught(version);
    }
}

fn assert_mutation_is_caught(version: &str) {
    let (luac, lua): (String, String) = toolchain(version);
    let scratch: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_lua_generated_mutation_lua{version}"),
    )
    .expect("scratch");
    let dir: &Path = scratch.path();
    let source: &str = "local a, b = 3, 4\nprint(a + b, a * b)\n";
    let recovered: String = recovered_source(&luac, dir, "mutant", source);
    let mutated: String = recovered.replacen('+', "-", 1);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    let original_path: PathBuf = dir.join("mutant.orig.lua");
    std::fs::write(&original_path, source).expect("write");
    let mutated_path: PathBuf = dir.join("mutant.mut.lua");
    std::fs::write(&mutated_path, &mutated).expect("write");
    assert_ne!(run(&lua, &original_path), run(&lua, &mutated_path));
}
