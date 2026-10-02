#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_ruby::analyze_bytes;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use ruby_toolchain::{ToolchainBanner, require_exact_mri_recompile};

const GRADED: &str = "the generated Ruby program differential";
const PROGRAMS: u64 = 300;
const RUN_TIMEOUT: Duration = Duration::from_secs(20);
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;

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
            3 => format!("({left} / {})", 1 + self.below(7)),
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
            0 => format!("!({comparison})"),
            1 => format!("({comparison}) && {} > {}", self.variable(), self.below(10)),
            2 => format!(
                "({comparison}) || {} == {}",
                self.variable(),
                self.below(10)
            ),
            3 => format!("t.include?({})", self.arithmetic(1)),
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
            1 => format!("(t[{}] || {})", self.below(4), self.arithmetic(1)),
            2 => format!("f({})", self.arithmetic(1)),
            3 => format!(
                "(0...{}).select {{ |x| x % 2 == {} }}.sum {{ |x| x * {} }}",
                self.below(6),
                self.below(2),
                self.atom()
            ),
            4 => format!("t.count {{ |x| x > {} }}", self.arithmetic(1)),
            5 => format!("[{}, {}].max", self.arithmetic(1), self.arithmetic(1)),
            _ => format!("({} % 1000)", self.arithmetic(2)),
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
                writeln!(out, "{pad}t << {value}").expect("write to a String");
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
                let keyword: &str = if self.below(4) == 0 { "unless" } else { "if" };
                writeln!(out, "{pad}{keyword} {cond}").expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                if keyword == "if" && self.below(2) == 0 {
                    let other: String = self.condition();
                    writeln!(out, "{pad}elsif {other}").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                if self.below(2) == 0 {
                    writeln!(out, "{pad}else").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                writeln!(out, "{pad}end").expect("write to a String");
            }
            7 => {
                self.serial += 1;
                let var: String = format!("i{}", self.serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                writeln!(out, "{pad}({first}..{last}).each do |{var}|").expect("write to a String");
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
            8 => {
                self.serial += 1;
                let counter: String = format!("n{}", self.serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                let negated: bool = self.below(3) == 0;
                writeln!(out, "{pad}{counter} = 0").expect("write to a String");
                if negated {
                    writeln!(
                        out,
                        "{pad}until {counter} >= {limit} || !({cond} || {counter} == 0)"
                    )
                    .expect("write to a String");
                } else {
                    writeln!(
                        out,
                        "{pad}while {counter} < {limit} && ({cond} || {counter} == 0)"
                    )
                    .expect("write to a String");
                }
                writeln!(out, "{pad}  {counter} += 1").expect("write to a String");
                self.loop_body(depth, indent, out);
                writeln!(out, "{pad}end").expect("write to a String");
            }
            9 => {
                let divisor: String = self.arithmetic(1);
                let target: &str = self.variable();
                writeln!(out, "{pad}begin").expect("write to a String");
                writeln!(out, "{pad}  {target} = {} / ({divisor} % 3)", self.atom())
                    .expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                writeln!(out, "{pad}rescue ZeroDivisionError").expect("write to a String");
                writeln!(out, "{pad}  emit(\"zero\")").expect("write to a String");
                if self.below(2) == 0 {
                    writeln!(out, "{pad}ensure").expect("write to a String");
                    writeln!(out, "{pad}  emit({})", self.variable()).expect("write to a String");
                }
                writeln!(out, "{pad}end").expect("write to a String");
            }
            10 => {
                let subject: String = self.arithmetic(1);
                writeln!(out, "{pad}case {subject} % 4").expect("write to a String");
                writeln!(out, "{pad}when 0").expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                writeln!(out, "{pad}when 1, 2").expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                if self.below(2) == 0 {
                    writeln!(out, "{pad}else").expect("write to a String");
                    self.block(depth + 1, indent + 1, out);
                }
                writeln!(out, "{pad}end").expect("write to a String");
            }
            _ => {
                let value: String = self.arithmetic(2);
                writeln!(out, "{pad}emit({value})").expect("write to a String");
            }
        }
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        let pad: String = "  ".repeat(indent + 1);
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}break if {cond}").expect("write to a String");
            }
            1 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}next if {cond}").expect("write to a String");
                writeln!(out, "{pad}emit({})", self.variable()).expect("write to a String");
            }
            _ => {}
        }
    }

    fn program(&mut self) -> String {
        let mut out: String = String::from("$out = []\n\ndef emit(v)\n  $out << v.to_s\nend\n\n");
        let k: u64 = 1 + self.below(5);
        writeln!(
            out,
            "def f(x)\n  return x - {k} if x > {k}\n  x + {k}\nend\n"
        )
        .expect("write to a String");
        out.push_str("def main\n  t = []\n");
        for name in VARIABLES {
            writeln!(out, "  {name} = {}", self.below(10)).expect("write to a String");
        }
        self.block(0, 1, &mut out);
        out.push_str(
            "  emit(a)\n  emit(b)\n  emit(c)\n  emit(d)\n  emit(e)\n  emit(t.inspect)\nend\n\nmain\nputs $out.join(\" \")\n",
        );
        out
    }
}

fn run(ruby: &Path, script: &Path) -> Result<String, String> {
    let output: ToolOutput = tool_output(CommandSpec::new(ruby, RUN_TIMEOUT).arg(script))
        .map_err(|error: disrobe_testkit::ToolError| error.to_string())?;
    if output.timed_out {
        return Err(format!("timed out after {RUN_TIMEOUT:?}"));
    }
    if !output.success {
        return Err(output.stderr_text().trim().to_owned());
    }
    Ok(output.stdout_text().replace("\r\n", "\n"))
}

fn recover_source(ruby: &Path, dir: &Path, name: &str, source: &str) -> String {
    let src: PathBuf = dir.join(format!("{name}.rb"));
    std::fs::write(&src, source).expect("write the generated program");
    let ibf: PathBuf = dir.join(format!("{name}.yarvc"));
    let compiled: ToolOutput = tool_output(
        CommandSpec::new(ruby, RUN_TIMEOUT)
            .arg("-e")
            .arg("File.binwrite(ARGV[1], RubyVM::InstructionSequence.compile_file(ARGV[0]).to_binary)")
            .arg(&src)
            .arg(&ibf),
    )
    .expect("ruby starts");
    assert!(
        compiled.success,
        "{name}: ruby compiles the generated program:\n{}\n{source}",
        compiled.stderr_text()
    );
    let bytes: Vec<u8> = std::fs::read(&ibf).expect("read the instruction sequence");
    let analysis = analyze_bytes(&bytes, &format!("{name}.yarvc"))
        .unwrap_or_else(|error| panic!("{name}: analyze: {error}"));
    analysis
        .yarv
        .unwrap_or_else(|| panic!("{name}: a YARV analysis"))
        .decompiled
        .source
}

#[test]
fn generated_programs_reexecute_identically_ruby_3_4() {
    let toolchain: ToolchainBanner = require_exact_mri_recompile(GRADED);
    let ruby: PathBuf = PathBuf::from(&toolchain.executable);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_ruby_generated").expect("create scratch directory");
    let dir: &Path = scratch.path();
    let mut failures: Vec<String> = Vec::new();
    for seed in 0..PROGRAMS {
        let source: String = Generator::new(seed).program();
        let name: String = format!("gen{seed}");
        let original_path: PathBuf = dir.join(format!("{name}.orig.rb"));
        std::fs::write(&original_path, &source).expect("write original");
        let expected: String = run(&ruby, &original_path).unwrap_or_else(|error: String| {
            panic!("seed {seed}: the generated program must run: {error}\n{source}")
        });
        let recovered: String = recover_source(&ruby, dir, &name, &source);
        let recovered_path: PathBuf = dir.join(format!("{name}.dec.rb"));
        std::fs::write(&recovered_path, &recovered).expect("write recovered");
        let actual: Result<String, String> = run(&ruby, &recovered_path);
        if actual.as_deref() != Ok(expected.as_str()) {
            let shown: String = actual.unwrap_or_else(|error: String| format!("<failed: {error}>"));
            failures.push(format!(
                "seed {seed}\n--- expected ---\n{expected}--- actual ---\n{shown}\n--- source ---\n{source}--- recovered ---\n{recovered}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {PROGRAMS} generated Ruby programs re-executed differently:\n{}",
        failures.len(),
        failures.join("\n=====\n")
    );
}

#[test]
fn the_ruby_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).program();
    assert_eq!(first, Generator::new(7).program());
    let distinct: std::collections::BTreeSet<String> = (0..PROGRAMS)
        .map(|seed: u64| Generator::new(seed).program())
        .collect();
    assert_eq!(distinct.len() as u64, PROGRAMS);
    let all: String = distinct.into_iter().collect();
    for shape in [
        "while ",
        "until ",
        ".each do |i",
        "elsif ",
        "unless ",
        "break if",
        "next if",
        "rescue ZeroDivisionError",
        "ensure\n",
        "case ",
        " ? ",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let toolchain: ToolchainBanner = require_exact_mri_recompile(GRADED);
    let ruby: PathBuf = PathBuf::from(&toolchain.executable);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_ruby_generated_mutation").expect("create scratch directory");
    let dir: &Path = scratch.path();
    let source: &str = "a = 3\nb = 4\nputs a + b, a * b\n";
    let recovered: String = recover_source(&ruby, dir, "mutant", source);
    let mutated: String = recovered.replacen('+', "-", 1);
    assert_ne!(
        mutated, recovered,
        "the mutation must change the recovered text"
    );
    let original_path: PathBuf = dir.join("mutant.orig.rb");
    std::fs::write(&original_path, source).expect("write");
    let mutated_path: PathBuf = dir.join("mutant.mut.rb");
    std::fs::write(&mutated_path, &mutated).expect("write");
    assert_ne!(run(&ruby, &original_path), run(&ruby, &mutated_path));
}
