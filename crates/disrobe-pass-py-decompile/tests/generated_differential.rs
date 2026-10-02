#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const PROGRAMS: u64 = 300;
const KNOWN_DIVERGENT: [u64; 20] = [
    48, 73, 81, 100, 101, 112, 124, 161, 164, 182, 201, 213, 244, 255, 256, 259, 280, 282, 291, 298,
];
const RUN_TIMEOUT: Duration = Duration::from_secs(10);
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;
const INTERPRETER: &str = "3.14";

struct Generator {
    state: u64,
    serial: u32,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
            serial: 0,
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
        match self.below(5) {
            0 => format!("({left} + {right})"),
            1 => format!("({left} - {right})"),
            2 => format!("({left} * {right}) % 97"),
            3 => format!("({left} // {})", 1 + self.below(7)),
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
            3 => format!("{left} != {right}"),
            4 => format!("{left} > {right}"),
            _ => format!("{left} >= {right}"),
        };
        match self.below(6) {
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
            3 => format!("{} in t", self.arithmetic(1)),
            _ => comparison,
        }
    }

    fn value(&mut self) -> String {
        match self.below(8) {
            0 => format!(
                "{} if {} else {}",
                self.arithmetic(1),
                self.condition(),
                self.arithmetic(1)
            ),
            1 => {
                let index: u64 = self.below(3);
                format!(
                    "(t[{index}] if len(t) > {index} else {})",
                    self.arithmetic(1)
                )
            }
            2 => format!("f({})", self.arithmetic(1)),
            3 => format!(
                "sum(x * {} for x in range({}) if x % 2 == {})",
                self.atom(),
                self.below(6),
                self.below(2)
            ),
            4 => format!("len([x for x in t if x > {}])", self.arithmetic(1)),
            5 => format!("({} or {})", self.arithmetic(1), self.arithmetic(1)),
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
        let pad: String = "    ".repeat(indent);
        let choice: u64 = if depth >= MAX_BLOCK_DEPTH {
            self.below(5)
        } else {
            self.below(12)
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
                let value: String = self.arithmetic(1);
                writeln!(out, "{pad}t.append({value})").expect("write to a String");
            }
            4 => {
                let target: &str = self.variable();
                let value: String = self.arithmetic(1);
                let op: &str = ["+=", "-=", "*="][self.below(3) as usize];
                writeln!(out, "{pad}{target} {op} {value}").expect("write to a String");
                writeln!(out, "{pad}{target} %= 1000").expect("write to a String");
            }
            5 | 6 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if {cond}:").expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                if self.below(2) == 0 {
                    let other: String = self.condition();
                    writeln!(out, "{pad}elif {other}:").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                if self.below(2) == 0 {
                    writeln!(out, "{pad}else:").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
            }
            7 => {
                self.serial += 1;
                let var: String = format!("i{}", self.serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                writeln!(out, "{pad}for {var} in range({first}, {last}):")
                    .expect("write to a String");
                writeln!(
                    out,
                    "{pad}    {} = ({} + {var}) % 1000",
                    self.variable(),
                    self.variable()
                )
                .expect("write to a String");
                self.loop_body(depth, indent, out);
                if self.below(3) == 0 {
                    writeln!(out, "{pad}else:").expect("write to a String");
                    writeln!(out, "{pad}    emit(\"done{}\")", self.serial)
                        .expect("write to a String");
                }
            }
            8 => {
                self.serial += 1;
                let counter: String = format!("n{}", self.serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                writeln!(out, "{pad}{counter} = 0").expect("write to a String");
                writeln!(
                    out,
                    "{pad}while {counter} < {limit} and ({cond} or {counter} == 0):"
                )
                .expect("write to a String");
                writeln!(out, "{pad}    {counter} += 1").expect("write to a String");
                self.loop_body(depth, indent, out);
            }
            9 => {
                let divisor: String = self.arithmetic(1);
                let target: &str = self.variable();
                writeln!(out, "{pad}try:").expect("write to a String");
                writeln!(
                    out,
                    "{pad}    {target} = {} // ({divisor} % 3)",
                    self.atom()
                )
                .expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                writeln!(out, "{pad}except ZeroDivisionError:").expect("write to a String");
                writeln!(out, "{pad}    emit(\"zero\")").expect("write to a String");
                if self.below(2) == 0 {
                    writeln!(out, "{pad}finally:").expect("write to a String");
                    writeln!(out, "{pad}    emit({})", self.variable()).expect("write to a String");
                }
            }
            _ => {
                let value: String = self.arithmetic(2);
                writeln!(out, "{pad}emit({value})").expect("write to a String");
            }
        }
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        let pad: String = "    ".repeat(indent + 1);
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if {cond}:").expect("write to a String");
                writeln!(out, "{pad}    break").expect("write to a String");
            }
            1 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if {cond}:").expect("write to a String");
                writeln!(out, "{pad}    continue").expect("write to a String");
                writeln!(out, "{pad}emit({})", self.variable()).expect("write to a String");
            }
            _ => {}
        }
    }

    fn program(&mut self) -> String {
        let mut out: String =
            String::from("out = []\n\n\ndef emit(v):\n    out.append(str(v))\n\n\n");
        let k: u64 = 1 + self.below(5);
        writeln!(
            out,
            "def f(x):\n    if x > {k}:\n        return x - {k}\n    return x + {k}\n\n"
        )
        .expect("write to a String");
        out.push_str("def main():\n    t = []\n");
        for name in VARIABLES {
            writeln!(out, "    {name} = {}", self.below(10)).expect("write to a String");
        }
        self.block(0, 1, &mut out);
        out.push_str("    emit(a)\n    emit(b)\n    emit(c)\n    emit(d)\n    emit(e)\n    emit(t)\n\n\nmain()\nprint(\" \".join(out))\n");
        out
    }
}

fn interpreter() -> BandInterpreter {
    resolve_band(&[INTERPRETER], &[])
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "the generated Python differential requires CPython {INTERPRETER} \
                 (uv python install {INTERPRETER})"
            )
        })
}

fn run(python: &Path, script: &Path) -> Result<String, String> {
    let output: ToolOutput = tool_output(CommandSpec::new(python, RUN_TIMEOUT).arg(script))
        .map_err(|error: disrobe_testkit::ToolError| error.to_string())?;
    if output.timed_out {
        return Err(format!("timed out after {RUN_TIMEOUT:?}"));
    }
    if !output.success {
        return Err(output.stderr_text().trim().to_owned());
    }
    Ok(output.stdout_text().replace("\r\n", "\n"))
}

fn recover_source(interp: &BandInterpreter, source: &str, name: &str, dir: &Path) -> String {
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(interp, source, name, dir);
    assert!(
        !recovered.is_empty(),
        "{name}: no source was recovered: {outcome:?}\n{source}"
    );
    recovered
}

#[test]
fn generated_programs_reexecute_identically_python_3_14() {
    let interp: BandInterpreter = interpreter();
    let dir: PathBuf = band_scratch("generated_differential");
    let mut divergent: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        let source: String = Generator::new(seed).program();
        let name: String = format!("gen{seed}");
        let original_path: PathBuf = dir.join(format!("{name}.orig.py"));
        std::fs::write(&original_path, &source).expect("write original");
        let expected: String = run(&interp.path, &original_path).unwrap_or_else(|error: String| {
            panic!("seed {seed}: the generated program must run: {error}\n{source}")
        });
        let recovered: String = recover_source(&interp, &source, &name, &dir);
        let recovered_path: PathBuf = dir.join(format!("{name}.run.py"));
        std::fs::write(&recovered_path, &recovered).expect("write recovered");
        let actual: Result<String, String> = run(&interp.path, &recovered_path);
        if actual.as_deref() != Ok(expected.as_str()) {
            let shown: String = actual.unwrap_or_else(|error: String| format!("<failed: {error}>"));
            divergent.insert(
                seed,
                format!(
                    "seed {seed}\n--- expected ---\n{expected}--- actual ---\n{shown}\n--- source ---\n{source}--- recovered ---\n{recovered}"
                ),
            );
        }
    }
    let known: BTreeSet<u64> = KNOWN_DIVERGENT.into_iter().collect();
    let regressed: Vec<&str> = divergent
        .iter()
        .filter(|(seed, _)| !known.contains(seed))
        .map(|(_, detail)| detail.as_str())
        .collect();
    let recovered_seeds: Vec<u64> = known
        .iter()
        .copied()
        .filter(|seed: &u64| !divergent.contains_key(seed))
        .collect();
    assert!(
        regressed.is_empty(),
        "{} generated Python programs outside KNOWN_DIVERGENT re-executed differently:\n{}",
        regressed.len(),
        regressed.join("\n=====\n")
    );
    assert!(
        recovered_seeds.is_empty(),
        "seeds {recovered_seeds:?} now re-execute identically; remove them from KNOWN_DIVERGENT"
    );
}

#[test]
fn known_divergent_seeds_are_sorted_unique_and_generated() {
    assert!(
        KNOWN_DIVERGENT
            .windows(2)
            .all(|pair: &[u64]| pair[0] < pair[1]),
        "KNOWN_DIVERGENT must be strictly ascending"
    );
    assert!(
        KNOWN_DIVERGENT.iter().all(|&seed: &u64| seed < PROGRAMS),
        "every KNOWN_DIVERGENT seed must be one of the {PROGRAMS} generated programs"
    );
}

#[test]
fn the_python_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).program();
    assert_eq!(first, Generator::new(7).program());
    let distinct: std::collections::BTreeSet<String> = (0..PROGRAMS)
        .map(|seed: u64| Generator::new(seed).program())
        .collect();
    assert_eq!(distinct.len() as u64, PROGRAMS);
    let all: String = distinct.into_iter().collect();
    for shape in [
        "while ",
        "for i",
        "elif ",
        "break\n",
        "continue\n",
        "except ZeroDivisionError",
        "finally:",
        " if ",
        " for x in ",
        "else:\n",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let interp: BandInterpreter = interpreter();
    let dir: PathBuf = band_scratch("generated_differential_mutation");
    let source: &str = "def main():\n    a, b = 3, 4\n    print(a + b, a * b)\n\n\nmain()\n";
    let recovered: String = recover_source(&interp, source, "mutant", &dir);
    let mutated: String = recovered.replacen('+', "-", 1);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    let original_path: PathBuf = dir.join("mutant.orig.py");
    std::fs::write(&original_path, source).expect("write");
    let mutated_path: PathBuf = dir.join("mutant.mut.py");
    std::fs::write(&mutated_path, &mutated).expect("write");
    assert_ne!(
        run(&interp.path, &original_path),
        run(&interp.path, &mutated_path)
    );
}
