#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    unreachable_pub,
    clippy::redundant_pub_crate
)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_php::{Decompilation, RecoveryReport, recover_php};
use php_toolchain::{
    PHP_OPCACHE, PhpRun, PhpRuntime, compile_opcache_image, opcache_extension, require_php,
    unmeasured,
};

const GRADED: &str = "the generated PHP program differential";
const PROGRAMS: u64 = 300;
const VARIABLES: [&str; 5] = ["$a", "$b", "$c", "$d", "$e"];
const MAX_BLOCK_DEPTH: u32 = 3;
const SHOWN_FAILURES: usize = 6;
const KNOWN_DIVERGENT: [u64; 0] = [];

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
            2 => format!("(({left} * {right}) % 97)"),
            3 => format!("intdiv({left}, {})", 1 + self.below(7)),
            _ => format!("({left} % {})", 2 + self.below(9)),
        }
    }

    fn condition(&mut self) -> String {
        let left: String = self.arithmetic(1);
        let right: String = self.arithmetic(1);
        let comparison: String = match self.below(6) {
            0 => format!("{left} < {right}"),
            1 => format!("{left} <= {right}"),
            2 => format!("{left} === {right}"),
            3 => format!("{left} !== {right}"),
            4 => format!("{left} > {right}"),
            _ => format!("{left} >= {right}"),
        };
        match self.below(6) {
            0 => format!("!({comparison})"),
            1 => format!("({comparison}) && {} > {}", self.variable(), self.below(10)),
            2 => format!(
                "({comparison}) || {} === {}",
                self.variable(),
                self.below(10)
            ),
            3 => format!("in_array({}, $t, true)", self.arithmetic(1)),
            _ => comparison,
        }
    }

    fn value(&mut self) -> String {
        match self.below(8) {
            0 => format!(
                "(({}) ? {} : {})",
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            1 => format!("($t[{}] ?? {})", self.below(4), self.arithmetic(1)),
            2 => format!("f({})", self.arithmetic(1)),
            3 => format!("max({}, {})", self.arithmetic(1), self.arithmetic(1)),
            4 => format!(
                "match ({} % 3) {{ 0 => {}, 1, -1 => {}, default => {} }}",
                self.arithmetic(1),
                self.atom(),
                self.atom(),
                self.atom()
            ),
            _ => format!("({} % 1000)", self.arithmetic(2)),
        }
    }

    fn block(&mut self, depth: u32, indent: usize, out: &mut String) {
        let count: u64 = 1 + self.below(4);
        for _ in 0..count {
            self.statement(depth, indent, out);
        }
    }

    fn braced(&mut self, depth: u32, indent: usize, out: &mut String) {
        out.push_str(" {\n");
        self.block(depth + 1, indent + 1, out);
        out.push_str(&"    ".repeat(indent));
        out.push('}');
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
                writeln!(out, "{pad}{target} = {value};").expect("write to a String");
            }
            2 => {
                let value: String = self.value();
                writeln!(out, "{pad}$out[] = {value};").expect("write to a String");
            }
            3 => {
                let value: String = self.arithmetic(1);
                writeln!(out, "{pad}$t[] = {value};").expect("write to a String");
            }
            4 => {
                let target: &str = self.variable();
                let value: String = self.arithmetic(1);
                let op: &str = ["+=", "-=", "*="][self.below(3) as usize];
                writeln!(out, "{pad}{target} {op} {value};").expect("write to a String");
                writeln!(out, "{pad}{target} %= 1000;").expect("write to a String");
            }
            5 | 6 => {
                let cond: String = self.condition();
                write!(out, "{pad}if ({cond})").expect("write to a String");
                self.braced(depth, indent, out);
                if self.below(2) == 0 {
                    let other: String = self.condition();
                    write!(out, " elseif ({other})").expect("write to a String");
                    self.braced(depth, indent, out);
                }
                if self.below(2) == 0 {
                    out.push_str(" else");
                    self.braced(depth, indent, out);
                }
                out.push('\n');
            }
            7 => {
                self.serial += 1;
                let var: String = format!("$i{}", self.serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                if self.below(2) == 0 {
                    writeln!(
                        out,
                        "{pad}for ({var} = {first}; {var} <= {last}; {var}++) {{"
                    )
                    .expect("write to a String");
                } else {
                    writeln!(out, "{pad}foreach (range({first}, {last}) as {var}) {{")
                        .expect("write to a String");
                }
                writeln!(
                    out,
                    "{pad}    {} = ({} + {var}) % 1000;",
                    self.variable(),
                    self.variable()
                )
                .expect("write to a String");
                self.loop_body(depth, indent, out);
                writeln!(out, "{pad}}}").expect("write to a String");
            }
            8 => {
                self.serial += 1;
                let counter: String = format!("$n{}", self.serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                writeln!(out, "{pad}{counter} = 0;").expect("write to a String");
                if self.below(3) == 0 {
                    writeln!(out, "{pad}do {{").expect("write to a String");
                    writeln!(out, "{pad}    {counter}++;").expect("write to a String");
                    self.loop_body(depth, indent, out);
                    writeln!(
                        out,
                        "{pad}}} while ({counter} < {limit} && ({cond} || {counter} === 1));"
                    )
                    .expect("write to a String");
                } else {
                    writeln!(
                        out,
                        "{pad}while ({counter} < {limit} && ({cond} || {counter} === 0)) {{"
                    )
                    .expect("write to a String");
                    writeln!(out, "{pad}    {counter}++;").expect("write to a String");
                    self.loop_body(depth, indent, out);
                    writeln!(out, "{pad}}}").expect("write to a String");
                }
            }
            9 => {
                let divisor: String = format!("({} + {})", self.arithmetic(1), self.variable());
                let target: &str = self.variable();
                let numerator: String = self.atom();
                writeln!(out, "{pad}try {{").expect("write to a String");
                writeln!(out, "{pad}    {target} = {numerator} % ({divisor} % 3);")
                    .expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                writeln!(out, "{pad}}} catch (DivisionByZeroError $error) {{")
                    .expect("write to a String");
                writeln!(out, "{pad}    $out[] = 'zero';").expect("write to a String");
                if self.below(2) == 0 {
                    let shown: &str = self.variable();
                    writeln!(out, "{pad}}} finally {{").expect("write to a String");
                    writeln!(out, "{pad}    $out[] = {shown};").expect("write to a String");
                }
                writeln!(out, "{pad}}}").expect("write to a String");
            }
            10 => {
                let subject: String = self.arithmetic(1);
                writeln!(out, "{pad}switch ((({subject}) % 4 + 4) % 4) {{")
                    .expect("write to a String");
                writeln!(out, "{pad}    case 0:").expect("write to a String");
                self.block(depth + 1, indent + 2, out);
                writeln!(out, "{pad}        break;").expect("write to a String");
                writeln!(out, "{pad}    case 1:").expect("write to a String");
                writeln!(out, "{pad}    case 2:").expect("write to a String");
                self.block(depth + 1, indent + 2, out);
                writeln!(out, "{pad}        break;").expect("write to a String");
                if self.below(2) == 0 {
                    writeln!(out, "{pad}    default:").expect("write to a String");
                    self.block(depth + 1, indent + 2, out);
                }
                writeln!(out, "{pad}}}").expect("write to a String");
            }
            _ => {
                let value: String = self.arithmetic(2);
                writeln!(out, "{pad}$out[] = {value};").expect("write to a String");
            }
        }
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        let pad: String = "    ".repeat(indent + 1);
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if ({cond}) {{ break; }}").expect("write to a String");
            }
            1 => {
                let cond: String = self.condition();
                let shown: &str = self.variable();
                writeln!(out, "{pad}if ({cond}) {{ continue; }}").expect("write to a String");
                writeln!(out, "{pad}$out[] = {shown};").expect("write to a String");
            }
            _ => {}
        }
    }

    fn program(&mut self) -> String {
        let k: u64 = 1 + self.below(5);
        let mut out: String = format!(
            "<?php\nfunction f(int $x): int\n{{\n    return $x > {k} ? $x - {k} : $x + {k};\n}}\n\nfunction run(): array\n{{\n    $out = [];\n    $t = [];\n"
        );
        for name in VARIABLES {
            writeln!(out, "    {name} = {};", self.below(10)).expect("write to a String");
        }
        self.block(0, 1, &mut out);
        out.push_str(
            "    array_push($out, $a, $b, $c, $d, $e, '[' . implode(',', $t) . ']');\n    return $out;\n}\n\necho implode(' ', run()), \"\\n\";\n",
        );
        out
    }
}

struct Toolchain {
    php: PhpRuntime,
    opcache: PathBuf,
}

fn toolchain() -> Option<Toolchain> {
    let php: PhpRuntime = require_php(GRADED)?;
    let Some(opcache): Option<PathBuf> = opcache_extension(&php) else {
        unmeasured(
            &PHP_OPCACHE,
            GRADED,
            "the opcache extension was not found beside the php binary",
        );
        return None;
    };
    Some(Toolchain { php, opcache })
}

fn recovered_source(toolchain: &Toolchain, seed: u64, source: &str) -> Result<String, String> {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_php_generated").expect("create scratch directory");
    let image: Vec<u8> = compile_opcache_image(
        &toolchain.php,
        &toolchain.opcache,
        source.as_bytes(),
        scratch.path(),
        &format!("gen{seed}"),
    )?;
    let report: RecoveryReport =
        recover_php(&image, None).map_err(|err| format!("the image did not recover: {err}"))?;
    let decompiled: Decompilation = report
        .decompilation
        .ok_or_else(|| "the op array route returned no decompilation".to_owned())?;
    if !decompiled.unrecovered.is_empty() {
        let records: Vec<String> = decompiled
            .unrecovered
            .iter()
            .map(|refusal| {
                format!(
                    "{} op {} {}: {}",
                    refusal.container, refusal.index, refusal.mnemonic, refusal.reason
                )
            })
            .collect();
        return Err(format!("refused by name: {}", records.join("; ")));
    }
    Ok(decompiled.php_skeleton)
}

fn grade(toolchain: &Toolchain, seed: u64, source: &str) -> Option<String> {
    let original: PhpRun = toolchain
        .php
        .run_reporting_errors(&format!("gen{seed} original"), source.as_bytes());
    assert!(
        original.exited_clean && original.stderr.is_empty() && !original.stdout.is_empty(),
        "seed {seed}: the generated program must run cleanly and print, stderr `{}`:\n{source}",
        original.stderr
    );
    let recovered: String = match recovered_source(toolchain, seed, source) {
        Ok(recovered) => recovered,
        Err(defect) => return Some(defect),
    };
    let run: PhpRun = toolchain
        .php
        .run_reporting_errors(&format!("gen{seed} recovered"), recovered.as_bytes());
    if run.exited_clean && run.stderr.is_empty() && run.stdout == original.stdout {
        return None;
    }
    Some(format!(
        "printed {:?} (exit clean {}, stderr `{}`), the original printed {:?}\n--- recovered ---\n{recovered}",
        String::from_utf8_lossy(&run.stdout),
        run.exited_clean,
        run.stderr,
        String::from_utf8_lossy(&original.stdout)
    ))
}

#[test]
fn generated_programs_reexecute_identically_on_php() {
    let Some(toolchain): Option<Toolchain> = toolchain() else {
        return;
    };
    let mut failures: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        let source: String = Generator::new(seed).program();
        if let Some(why) = grade(&toolchain, seed, &source) {
            failures.insert(seed, format!("{why}\n--- source ---\n{source}"));
        }
    }
    let pinned: BTreeSet<u64> = KNOWN_DIVERGENT.into_iter().collect();
    let divergent: BTreeSet<u64> = failures.keys().copied().collect();
    let regressed: Vec<u64> = divergent.difference(&pinned).copied().collect();
    let fixed: Vec<u64> = pinned.difference(&divergent).copied().collect();
    let summary: Vec<String> = failures
        .iter()
        .map(|(seed, why): (&u64, &String)| {
            format!("  seed {seed}: {}", why.lines().next().unwrap_or_default())
        })
        .collect();
    let shown: Vec<String> = failures
        .iter()
        .filter(|(seed, _): &(&u64, &String)| !pinned.contains(seed))
        .take(SHOWN_FAILURES)
        .map(|(seed, why): (&u64, &String)| format!("seed {seed}: {why}"))
        .collect();
    assert!(
        regressed.is_empty() && fixed.is_empty(),
        "{} of {PROGRAMS} generated PHP programs did not recover to the same behaviour; the \
         divergent set must equal KNOWN_DIVERGENT exactly, which only ever shrinks. Newly \
         divergent: {regressed:?}. Now recovered, remove from KNOWN_DIVERGENT: {fixed:?}.\n{}\n{}",
        failures.len(),
        summary.join("\n"),
        shown.join("\n=====\n")
    );
}

#[test]
fn the_php_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).program();
    assert_eq!(first, Generator::new(7).program());
    let programs: BTreeSet<String> = (0..PROGRAMS)
        .map(|seed: u64| Generator::new(seed).program())
        .collect();
    assert_eq!(programs.len() as u64, PROGRAMS);
    let all: String = programs.into_iter().collect();
    for shape in [
        "while (",
        "do {",
        "for ($i",
        "foreach (range(",
        "elseif (",
        " else {",
        "break;",
        "continue;",
        "catch (DivisionByZeroError",
        "finally {",
        "switch (",
        "default:",
        "match (",
        " ?? ",
        "in_array(",
        "intdiv(",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let Some(toolchain): Option<Toolchain> = toolchain() else {
        return;
    };
    let source: &str = "<?php\n$a = 3;\n$b = 4;\necho $a + $b, ' ', $a * $b, \"\\n\";\n";
    let recovered: String =
        recovered_source(&toolchain, 9999, source).expect("the control program recovers");
    let mutated: String = recovered.replacen('+', "-", 1);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    let original: PhpRun = toolchain
        .php
        .run_reporting_errors("control", source.as_bytes());
    let changed: PhpRun = toolchain
        .php
        .run_reporting_errors("control mutated", mutated.as_bytes());
    assert!(original.exited_clean && changed.exited_clean);
    assert_ne!(original.stdout, changed.stdout);
}
