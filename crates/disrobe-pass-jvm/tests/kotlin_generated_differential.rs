#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};
use disrobe_testkit::{Available, CommandSpec, ToolError, ToolOutput, require, tool_output};

const PROGRAMS: u64 = 300;
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;
const TOOL_TIMEOUT: Duration = Duration::from_mins(5);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPAIR_ROUNDS: usize = 16;
const RUN_TIMEOUT: Duration = Duration::from_secs(30);
const SHOWN_FAILURES: usize = 6;
const KNOWN_DIVERGENT: [u64; 2] = [217, 292];
const KOTLINC_PREREQUISITE: &str = "disrobe-pass-jvm::kotlinc";
const TOP_LEVEL_CLASS: &str = "GenKt";
const OBJECT_CLASS: &str = "Obj";

const SINK: &str = r"import java.util.List;

public final class Sink {
    private static final StringBuilder TEXT = new StringBuilder();

    private Sink() {
    }

    public static void reset() {
        TEXT.setLength(0);
    }

    public static void emit(int value) {
        TEXT.append(value).append(' ');
    }

    public static void emit(String value) {
        TEXT.append(value).append(' ');
    }

    public static void emit(List<Integer> values) {
        TEXT.append(values).append(' ');
    }

    public static int f(int x, int k) {
        return x > k ? x - k : x + k;
    }

    public static String take() {
        return TEXT.toString();
    }
}
";

const fn in_object(seed: u64) -> bool {
    seed % 3 == 2
}

const fn class_of(seed: u64) -> &'static str {
    if in_object(seed) {
        OBJECT_CLASS
    } else {
        TOP_LEVEL_CLASS
    }
}

fn line(out: &mut String, pad: &str, text: &str) {
    writeln!(out, "{pad}{text}").expect("write to a String");
}

struct Generator {
    state: u64,
    serial: u32,
    k: u64,
    loops: Vec<Option<String>>,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
            serial: 0,
            k: 0,
            loops: Vec::new(),
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
        match self.below(8) {
            0 => format!("!({comparison})"),
            1 => format!("({comparison}) && {} > {}", self.variable(), self.below(10)),
            2 => format!(
                "({comparison}) || {} == {}",
                self.variable(),
                self.below(10)
            ),
            3 => format!("t.contains({})", self.arithmetic(1)),
            4 => format!("({}) in t", self.arithmetic(1)),
            5 => format!("(u != null && u > {})", self.below(10)),
            _ => comparison,
        }
    }

    fn value(&mut self) -> String {
        match self.below(12) {
            0 => format!(
                "(if ({}) {} else {})",
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            1 => format!(
                "(if ({}) {} else if ({}) {} else {})",
                self.condition(),
                self.arithmetic(1),
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            2 => {
                let index: u64 = self.below(4);
                format!(
                    "(if (t.size > {index}) t[{index}] else {})",
                    self.arithmetic(1)
                )
            }
            3 => format!("Sink.f({}, {})", self.arithmetic(1), self.k),
            4 => format!("maxOf({}, {})", self.arithmetic(1), self.arithmetic(1)),
            5 => format!(
                "(when {{ {} -> {}; {} -> {}; else -> {} }})",
                self.condition(),
                self.arithmetic(1),
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            6 => format!(
                "(when (({}) % 3) {{ 0 -> {}; 1, -1 -> {}; else -> {} }})",
                self.arithmetic(1),
                self.arithmetic(1),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            7 => format!("(u ?: {})", self.arithmetic(1)),
            8 => format!("(u?.plus({}) ?: {})", self.atom(), self.arithmetic(1)),
            9 => format!("(u?.let {{ it * 2 % 97 }} ?: {})", self.arithmetic(1)),
            _ => format!("({} % 1000)", self.arithmetic(2)),
        }
    }

    fn block(&mut self, depth: u32, indent: usize, out: &mut String) {
        let count: u64 = 1 + self.below(4);
        for _ in 0..count {
            self.statement(depth, indent, out);
        }
    }

    fn label(&mut self) -> Option<String> {
        (self.below(2) == 0).then(|| format!("l{}", self.serial))
    }

    fn jump(&mut self) -> String {
        let keyword: &str = if self.below(2) == 0 {
            "break"
        } else {
            "continue"
        };
        self.jump_with(keyword)
    }

    fn jump_with(&mut self, keyword: &str) -> String {
        let labels: Vec<String> = self.loops.iter().flatten().cloned().collect();
        if labels.is_empty() || self.below(3) == 0 {
            return keyword.to_owned();
        }
        let chosen: &String = &labels[self.below(labels.len() as u64) as usize];
        format!("{keyword}@{chosen}")
    }

    fn statement(&mut self, depth: u32, indent: usize, out: &mut String) {
        let pad: String = "    ".repeat(indent);
        let choice: u64 = if depth >= MAX_BLOCK_DEPTH {
            self.below(7)
        } else {
            self.below(17)
        };
        match choice {
            0 | 1 => {
                let target: &str = self.variable();
                let value: String = self.value();
                line(out, &pad, &format!("{target} = {value}"));
            }
            2 => {
                let value: String = self.value();
                line(out, &pad, &format!("Sink.emit({value})"));
            }
            3 => {
                let value: String = self.arithmetic(1);
                if self.below(2) == 0 {
                    line(out, &pad, &format!("t.add({value})"));
                } else {
                    line(out, &pad, &format!("t += {value}"));
                }
            }
            4 => {
                let target: &str = self.variable();
                let value: String = self.arithmetic(1);
                let op: &str = ["+=", "-=", "*="][self.below(3) as usize];
                line(out, &pad, &format!("{target} {op} {value}"));
                line(out, &pad, &format!("{target} %= 1000"));
            }
            5 => self.nullable(&pad, out),
            6 => {
                let first: &str = self.variable();
                let value: String = self.arithmetic(1);
                line(
                    out,
                    &pad,
                    &format!("Sink.emit(\"{first}=${first} n=${{t.size}} u=$u w=${{{value}}}\")"),
                );
            }
            7 | 8 => {
                let cond: String = self.condition();
                line(out, &pad, &format!("if ({cond}) {{"));
                self.block(depth + 1, indent + 1, out);
                if self.below(2) == 0 {
                    let other: String = self.condition();
                    line(out, &pad, &format!("}} else if ({other}) {{"));
                    self.block(depth + 1, indent + 1, out);
                }
                if self.below(2) == 0 {
                    line(out, &pad, "} else {");
                    self.block(depth + 1, indent + 1, out);
                }
                line(out, &pad, "}");
            }
            9 => {
                self.serial += 1;
                let var: String = format!("i{}", self.serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                let range: String = match self.below(5) {
                    0 | 1 => format!("{first}..{last}"),
                    2 => format!("{first} until {}", last + 1),
                    3 => format!("{last} downTo {first}"),
                    _ => format!("{first} until {} step {}", last + 3, 2 + self.below(2)),
                };
                let label: Option<String> = self.label();
                let prefix: String = label
                    .as_ref()
                    .map_or_else(String::new, |name: &String| format!("{name}@ "));
                line(out, &pad, &format!("{prefix}for ({var} in {range}) {{"));
                let target: &str = self.variable();
                let source: &str = self.variable();
                line(
                    out,
                    &pad,
                    &format!("    {target} = ({source} + {var}) % 1000"),
                );
                self.loops.push(label);
                self.loop_body(depth, indent, out);
                self.loops.pop();
                line(out, &pad, "}");
            }
            10 => {
                self.serial += 1;
                let counter: String = format!("n{}", self.serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                let label: Option<String> = self.label();
                let prefix: String = label
                    .as_ref()
                    .map_or_else(String::new, |name: &String| format!("{name}@ "));
                line(out, &pad, &format!("var {counter} = 0"));
                self.loops.push(label);
                if self.below(3) == 0 {
                    line(out, &pad, &format!("{prefix}do {{"));
                    line(out, &pad, &format!("    {counter}++"));
                    self.loop_body(depth, indent, out);
                    line(
                        out,
                        &pad,
                        &format!("}} while ({counter} < {limit} && ({cond} || {counter} == 1))"),
                    );
                } else {
                    line(
                        out,
                        &pad,
                        &format!(
                            "{prefix}while ({counter} < {limit} && ({cond} || {counter} == 0)) {{"
                        ),
                    );
                    line(out, &pad, &format!("    {counter}++"));
                    self.loop_body(depth, indent, out);
                    line(out, &pad, "}");
                }
                self.loops.pop();
            }
            11 => {
                let divisor: String = format!("({} + {})", self.arithmetic(1), self.variable());
                let target: &str = self.variable();
                let numerator: String = self.atom();
                line(out, &pad, "try {");
                line(
                    out,
                    &pad,
                    &format!("    {target} = {numerator} / ({divisor} % 3)"),
                );
                self.block(depth + 1, indent + 1, out);
                line(out, &pad, "} catch (error: ArithmeticException) {");
                line(out, &pad, "    Sink.emit(\"zero\")");
                if self.below(2) == 0 {
                    let shown: &str = self.variable();
                    line(out, &pad, "} finally {");
                    line(out, &pad, &format!("    Sink.emit({shown})"));
                }
                line(out, &pad, "}");
            }
            12 => {
                let divisor: String = format!("({} + {})", self.arithmetic(1), self.variable());
                let target: &str = self.variable();
                let numerator: String = self.atom();
                let fallback: String = self.arithmetic(1);
                line(
                    out,
                    &pad,
                    &format!(
                        "{target} = try {{ {numerator} / ({divisor} % 3) }} catch (error: ArithmeticException) {{ {fallback} }}"
                    ),
                );
            }
            13 => {
                let subject: String = self.arithmetic(1);
                line(out, &pad, &format!("when ((({subject}) % 4 + 4) % 4) {{"));
                line(out, &pad, "    0 -> {");
                self.block(depth + 1, indent + 2, out);
                line(out, &pad, "    }");
                line(out, &pad, "    1, 2 -> {");
                self.block(depth + 1, indent + 2, out);
                line(out, &pad, "    }");
                if self.below(2) == 0 {
                    line(out, &pad, "    else -> {");
                    self.block(depth + 1, indent + 2, out);
                    line(out, &pad, "    }");
                }
                line(out, &pad, "}");
            }
            14 => {
                line(out, &pad, "when {");
                for _ in 0..=self.below(2) {
                    let cond: String = self.condition();
                    line(out, &pad, &format!("    {cond} -> {{"));
                    self.block(depth + 1, indent + 2, out);
                    line(out, &pad, "    }");
                }
                if self.below(2) == 0 {
                    line(out, &pad, "    else -> {");
                    self.block(depth + 1, indent + 2, out);
                    line(out, &pad, "    }");
                }
                line(out, &pad, "}");
            }
            15 if !self.loops.is_empty() => {
                let cond: String = self.condition();
                let jump: String = self.jump();
                line(out, &pad, &format!("if ({cond}) {jump}"));
            }
            _ => {
                let value: String = self.arithmetic(2);
                line(out, &pad, &format!("Sink.emit({value})"));
            }
        }
    }

    fn nullable(&mut self, pad: &str, out: &mut String) {
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                let value: String = self.arithmetic(1);
                line(out, pad, &format!("u = if ({cond}) null else {value}"));
            }
            1 => {
                let offset: u64 = self.below(10);
                line(out, pad, &format!("u?.let {{ Sink.emit(it + {offset}) }}"));
            }
            2 => {
                let target: &str = self.variable();
                let value: String = self.arithmetic(1);
                line(
                    out,
                    pad,
                    &format!("if (u != null) {{ {target} = (u + {value}) % 1000 }}"),
                );
            }
            _ => {
                let step: u64 = 1 + self.below(9);
                line(out, pad, &format!("u = u?.plus({step})?.rem(1000)"));
            }
        }
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        let pad: String = "    ".repeat(indent + 1);
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                let jump: String = self.jump();
                line(out, &pad, &format!("if ({cond}) {jump}"));
            }
            1 => {
                let cond: String = self.condition();
                let shown: &str = self.variable();
                let jump: String = self.jump_with("continue");
                line(out, &pad, &format!("if ({cond}) {jump}"));
                line(out, &pad, &format!("Sink.emit({shown})"));
            }
            _ => {}
        }
    }

    fn method(&mut self, seed: u64) -> String {
        self.k = 1 + self.below(5);
        let base: usize = usize::from(in_object(seed));
        let pad: String = "    ".repeat(base);
        let inner: String = "    ".repeat(base + 1);
        let mut out: String = String::new();
        line(&mut out, &pad, &format!("fun prog{seed}() {{"));
        line(
            &mut out,
            &inner,
            "val t: MutableList<Int> = mutableListOf()",
        );
        for name in VARIABLES {
            let initial: u64 = self.below(10);
            line(&mut out, &inner, &format!("var {name} = {initial}"));
        }
        let nullable: String = match self.below(2) {
            0 => "null".to_owned(),
            _ => self.below(10).to_string(),
        };
        line(&mut out, &inner, &format!("var u: Int? = {nullable}"));
        self.block(0, base + 1, &mut out);
        for name in VARIABLES {
            line(&mut out, &inner, &format!("Sink.emit({name})"));
        }
        line(&mut out, &inner, "Sink.emit(\"u=$u\")");
        line(&mut out, &inner, "Sink.emit(t)");
        line(&mut out, &pad, "}");
        out
    }
}

fn generated_methods() -> BTreeMap<u64, String> {
    (0..PROGRAMS)
        .map(|seed: u64| (seed, Generator::new(seed).method(seed)))
        .collect()
}

fn kotlin_file(methods: &BTreeMap<u64, String>) -> String {
    let mut top: String = String::new();
    let mut object: String = format!("object {OBJECT_CLASS} {{\n");
    for (seed, method) in methods {
        let target: &mut String = if in_object(*seed) {
            &mut object
        } else {
            &mut top
        };
        target.push_str(method);
        target.push('\n');
    }
    object.push_str("}\n");
    top.push_str(&object);
    top
}

fn main_class() -> String {
    let mut out: String =
        String::from("public final class Main {\n    public static void main(String[] args) {\n");
    for seed in 0..PROGRAMS {
        let call: String = if in_object(seed) {
            format!("{OBJECT_CLASS}.INSTANCE.prog{seed}()")
        } else {
            format!("{TOP_LEVEL_CLASS}.prog{seed}()")
        };
        writeln!(
            out,
            "        Sink.reset();\n        try {{ {call}; }} catch (Exception error) {{ Sink.emit(\"threw \" + error.getClass().getSimpleName()); }}\n        System.out.println(\"{seed}: \" + Sink.take());\n        System.out.flush();"
        )
        .expect("write to a String");
    }
    out.push_str("    }\n}\n");
    out
}

struct Toolchain {
    kotlinc: PathBuf,
    javac: PathBuf,
    java: PathBuf,
    runtime: Vec<PathBuf>,
}

fn toolchain() -> Toolchain {
    let name: &str = if cfg!(windows) {
        "kotlinc.bat"
    } else {
        "kotlinc"
    };
    let kotlinc: PathBuf = match require(
        KOTLINC_PREREQUISITE,
        "kotlinc 2.4.10 on PATH (JetBrains release kotlin-compiler-2.4.10.zip), which compiles \
         the generated Kotlin programs this differential grades",
        common::find_on_path(name),
    ) {
        Ok(Available::Present(path)) => path,
        Ok(Available::NotMeasured { record }) => panic!(
            "the Kotlin generated differential has no measurement without kotlinc, so it cannot \
             be listed optional (record {})",
            record.display()
        ),
        Err(error) => panic!("{error}"),
    };
    Toolchain {
        kotlinc,
        javac: common::grader_jdk_tool("javac"),
        java: common::grader_jdk_tool("java"),
        runtime: common::kotlin_runtime(),
    }
}

impl Toolchain {
    fn classpath(&self, classes: &Path) -> OsString {
        std::env::join_paths(std::iter::once(classes.to_path_buf()).chain(self.runtime.clone()))
            .expect("classpath entries hold no separator")
    }

    fn javac(&self, directory: &Path, classes: &Path, sources: &[(String, String)]) -> ToolOutput {
        let mut javac: CommandSpec = CommandSpec::new(self.javac.clone(), TOOL_TIMEOUT)
            .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
            .args([
                "-nowarn",
                "-proc:none",
                "-encoding",
                "UTF-8",
                "-Xmaxerrs",
                "100000",
            ])
            .arg("-cp")
            .arg(self.classpath(classes))
            .arg("-d")
            .arg(classes.to_path_buf())
            .current_dir(directory.to_path_buf());
        for (name, source) in sources {
            let path: PathBuf = directory.join(name);
            std::fs::write(&path, source).expect("write a java source");
            javac = javac.arg(path);
        }
        let build: ToolOutput = tool_output(javac)
            .unwrap_or_else(|error: ToolError| panic!("javac could not start: {error}"));
        assert!(
            !build.timed_out,
            "javac did not finish within {} seconds",
            TOOL_TIMEOUT.as_secs()
        );
        build
    }

    fn kotlinc(&self, directory: &Path, classes: &Path, source: &str) -> ToolOutput {
        let path: PathBuf = directory.join("Gen.kt");
        std::fs::write(&path, source).expect("write the Kotlin source");
        let build: ToolOutput = tool_output(
            CommandSpec::new(self.kotlinc.clone(), TOOL_TIMEOUT)
                .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
                .arg(path)
                .args(["-jvm-target", "17", "-nowarn", "-cp"])
                .arg(classes.to_path_buf())
                .arg("-d")
                .arg(classes.to_path_buf())
                .current_dir(directory.to_path_buf()),
        )
        .unwrap_or_else(|error: ToolError| panic!("kotlinc could not start: {error}"));
        assert!(
            !build.timed_out,
            "kotlinc did not finish within {} seconds",
            TOOL_TIMEOUT.as_secs()
        );
        build
    }

    fn run(&self, directory: &Path, classes: &Path) -> Run {
        let run: ToolOutput = tool_output(
            CommandSpec::new(self.java.clone(), RUN_TIMEOUT)
                .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
                .arg("-cp")
                .arg(self.classpath(classes))
                .arg("Main")
                .current_dir(directory.to_path_buf()),
        )
        .unwrap_or_else(|error: ToolError| panic!("the Main program could not start: {error}"));
        let mut lines: BTreeMap<u64, String> = BTreeMap::new();
        for text in run.stdout_text().lines() {
            if let Some((seed, rest)) = text.split_once(": ")
                && let Ok(seed) = seed.trim().parse::<u64>()
            {
                lines.insert(seed, rest.trim_end().to_owned());
            }
        }
        let hung: Option<(u64, String)> = if run.success {
            None
        } else {
            let reason: String = if run.timed_out {
                format!(
                    "does not terminate within {} seconds",
                    RUN_TIMEOUT.as_secs()
                )
            } else {
                format!("crashes the process: {}", run.stderr_text().trim())
            };
            (0..PROGRAMS)
                .find(|seed: &u64| !lines.contains_key(seed))
                .map(|seed: u64| (seed, reason))
        };
        Run { lines, hung }
    }
}

struct Run {
    lines: BTreeMap<u64, String>,
    hung: Option<(u64, String)>,
}

struct Reference {
    lines: BTreeMap<u64, String>,
    classes: BTreeMap<&'static str, Vec<u8>>,
}

fn build_reference(tools: &Toolchain, kotlin: &str) -> Reference {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_kotlin_generated_original").expect("create scratch");
    let directory: &Path = scratch.path();
    let classes: PathBuf = directory.join("classes");
    std::fs::create_dir_all(&classes).expect("create the class output directory");
    assert_built(&tools.javac(
        directory,
        &classes,
        &[("Sink.java".to_owned(), SINK.to_owned())],
    ));
    assert_built(&tools.kotlinc(directory, &classes, kotlin));
    assert_built(&tools.javac(
        directory,
        &classes,
        &[("Main.java".to_owned(), main_class())],
    ));
    let run: Run = tools.run(directory, &classes);
    assert_eq!(run.hung, None, "every generated program terminates");
    assert_eq!(
        run.lines.len() as u64,
        PROGRAMS,
        "the reference run prints one line per program"
    );
    let classes: BTreeMap<&'static str, Vec<u8>> = [TOP_LEVEL_CLASS, OBJECT_CLASS]
        .into_iter()
        .map(|name: &'static str| {
            let image: Vec<u8> = std::fs::read(classes.join(format!("{name}.class")))
                .unwrap_or_else(|error: std::io::Error| {
                    panic!("kotlinc wrote no {name}.class: {error}")
                });
            (name, image)
        })
        .collect();
    Reference {
        lines: run.lines,
        classes,
    }
}

fn assert_built(build: &ToolOutput) {
    assert!(
        build.success,
        "the generated reference must compile:\n{}{}",
        excerpt(&build.stdout_text(), 6000),
        excerpt(&build.stderr_text(), 6000)
    );
}

struct Built {
    build: ToolOutput,
    run: Option<Run>,
}

fn build_recovered(tools: &Toolchain, units: &BTreeMap<&'static str, String>) -> Built {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_kotlin_generated_recovered").expect("create scratch");
    let directory: &Path = scratch.path();
    let classes: PathBuf = directory.join("classes");
    std::fs::create_dir_all(&classes).expect("create the class output directory");
    let mut sources: Vec<(String, String)> = vec![
        ("Sink.java".to_owned(), SINK.to_owned()),
        ("Main.java".to_owned(), main_class()),
    ];
    for (name, source) in units {
        sources.push((format!("{name}.java"), source.clone()));
    }
    let build: ToolOutput = tools.javac(directory, &classes, &sources);
    let run: Option<Run> = build.success.then(|| tools.run(directory, &classes));
    Built { build, run }
}

fn prog_seed(text: &str) -> Option<u64> {
    let trimmed: &str = text.trim_start();
    if !trimmed.starts_with("public ") {
        return None;
    }
    let (_, rest): (&str, &str) = trimmed.split_once(" void prog")?;
    rest.split('(').next()?.trim().parse::<u64>().ok()
}

fn recovered_methods(source: &str) -> BTreeMap<u64, String> {
    let mut methods: BTreeMap<u64, String> = BTreeMap::new();
    let mut lines: std::str::Lines<'_> = source.lines();
    while let Some(first) = lines.next() {
        let Some(seed) = prog_seed(first) else {
            continue;
        };
        let indent: usize = first.len() - first.trim_start().len();
        let closing: String = format!("{}}}", " ".repeat(indent));
        let mut text: String = format!("{first}\n");
        if !first.trim_end().ends_with('}') {
            for body in lines.by_ref() {
                text.push_str(body);
                text.push('\n');
                if body.trim_end() == closing {
                    break;
                }
            }
        }
        methods.insert(seed, text);
    }
    methods
}

fn stub(seed: u64) -> String {
    let modifiers: &str = if in_object(seed) {
        "public final"
    } else {
        "public static final"
    };
    format!(
        "    {modifiers} void prog{seed}() {{\n        throw new IllegalStateException(\"unrecovered\");\n    }}\n"
    )
}

fn candidate_unit(
    class: &'static str,
    decompiled: &str,
    recovered: &BTreeMap<u64, String>,
    failures: &BTreeMap<u64, String>,
) -> String {
    let mut source: String = decompiled.to_owned();
    let mut missing: String = String::new();
    for seed in (0..PROGRAMS).filter(|seed: &u64| class_of(*seed) == class) {
        if !failures.contains_key(&seed) {
            continue;
        }
        match recovered.get(&seed) {
            Some(text) => source = source.replacen(text.as_str(), &stub(seed), 1),
            None => missing.push_str(&stub(seed)),
        }
    }
    if !missing.is_empty() {
        let end: usize = source
            .rfind('}')
            .unwrap_or_else(|| panic!("the recovered {class} source has no closing brace"));
        source.insert_str(end, &missing);
    }
    source
}

fn seeds_named_by_diagnostics(
    build: &ToolOutput,
    units: &BTreeMap<&'static str, String>,
) -> BTreeMap<u64, Vec<String>> {
    let diagnostics: String = format!("{}{}", build.stdout_text(), build.stderr_text());
    let mut seeds: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (class, source) in units {
        let file: String = format!("{class}.java:");
        let mut starts: Vec<(usize, u64)> = Vec::new();
        for (index, text) in source.lines().enumerate() {
            if let Some(seed) = prog_seed(text) {
                starts.push((index + 1, seed));
            }
        }
        for text in diagnostics.lines() {
            let Some(at) = text.find(&file).filter(|_| text.contains(": error: ")) else {
                continue;
            };
            let Some(number) = text[at + file.len()..]
                .split(':')
                .next()
                .and_then(|digits: &str| digits.parse::<usize>().ok())
            else {
                continue;
            };
            if let Some((_, seed)) = starts.iter().rev().find(|(start, _)| *start <= number) {
                let message: &str = text[at..].trim();
                let messages: &mut Vec<String> = seeds.entry(*seed).or_default();
                if !messages.iter().any(|known: &String| known == message) {
                    messages.push(message.to_owned());
                }
            }
        }
    }
    seeds
}

fn excerpt(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end: usize = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n...", &text[..end])
}

#[derive(Clone)]
struct Recovery {
    decompiled: BTreeMap<&'static str, String>,
    methods: BTreeMap<u64, String>,
}

fn decompile(reference: &Reference) -> Recovery {
    let mut decompiled: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut methods: BTreeMap<u64, String> = BTreeMap::new();
    for (class, image) in &reference.classes {
        let recovered: DecompiledClass = decompile_classfile_bytes(image)
            .unwrap_or_else(|error| panic!("decompile {class}.class: {error}"));
        for (seed, text) in recovered_methods(&recovered.source) {
            if class_of(seed) == *class {
                methods.insert(seed, text);
            }
        }
        decompiled.insert(*class, recovered.source);
    }
    Recovery {
        decompiled,
        methods,
    }
}

fn reexecute(
    tools: &Toolchain,
    recovery: &Recovery,
    failures: &mut BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    for round in 0..MAX_REPAIR_ROUNDS {
        let units: BTreeMap<&'static str, String> = recovery
            .decompiled
            .iter()
            .map(|(class, source): (&&'static str, &String)| {
                (
                    *class,
                    candidate_unit(class, source, &recovery.methods, failures),
                )
            })
            .collect();
        let built: Built = build_recovered(tools, &units);
        if let Some(run) = built.run {
            if let Some((seed, reason)) = run.hung {
                failures.insert(
                    seed,
                    format!(
                        "the recovered body {reason}:\n{}",
                        excerpt(recovery.methods.get(&seed).map_or("", String::as_str), 3000)
                    ),
                );
                continue;
            }
            return run.lines;
        }
        let named: BTreeMap<u64, Vec<String>> = seeds_named_by_diagnostics(&built.build, &units);
        assert!(
            !named.is_empty(),
            "the recovered classes failed to compile in round {round} without naming a prog \
             method:\n{}\n{}",
            excerpt(&built.build.stderr_text(), 4000),
            units
                .iter()
                .map(|(class, source): (&&'static str, &String)| format!(
                    "--- {class} ---\n{}",
                    excerpt(source, 4000)
                ))
                .collect::<Vec<String>>()
                .join("\n")
        );
        for (seed, messages) in named {
            failures.entry(seed).or_insert_with(|| {
                format!(
                    "the recovered body does not compile: {}\n{}",
                    messages.join(" | "),
                    excerpt(recovery.methods.get(&seed).map_or("", String::as_str), 3000)
                )
            });
        }
    }
    panic!("no recovered build compiled within {MAX_REPAIR_ROUNDS} rounds");
}

#[test]
fn generated_kotlin_programs_reexecute_identically_on_the_jvm() {
    let tools: Toolchain = toolchain();
    let original: BTreeMap<u64, String> = generated_methods();
    let reference: Reference = build_reference(&tools, &kotlin_file(&original));
    let recovery: Recovery = decompile(&reference);
    let mut failures: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        if !recovery.methods.contains_key(&seed) {
            failures.insert(
                seed,
                format!(
                    "the decompiler emitted no prog body\n{}",
                    excerpt(&recovery.decompiled[class_of(seed)], 3000)
                ),
            );
        }
    }
    let outputs: BTreeMap<u64, String> = reexecute(&tools, &recovery, &mut failures);
    for seed in 0..PROGRAMS {
        if failures.contains_key(&seed) {
            continue;
        }
        let expected: &String = &reference.lines[&seed];
        let actual: Option<&String> = outputs.get(&seed);
        if actual != Some(expected) {
            failures.insert(
                seed,
                format!(
                    "printed {actual:?}, the original printed {expected:?}\n--- recovered ---\n{}",
                    excerpt(&recovery.methods[&seed], 3000)
                ),
            );
        }
    }
    let pinned: BTreeSet<u64> = KNOWN_DIVERGENT.into_iter().collect();
    let divergent: BTreeSet<u64> = failures.keys().copied().collect();
    let regressed: Vec<u64> = divergent.difference(&pinned).copied().collect();
    let fixed: Vec<u64> = pinned.difference(&divergent).copied().collect();
    let shown: Vec<String> = failures
        .iter()
        .filter(|(seed, _): &(&u64, &String)| !pinned.contains(seed))
        .chain(
            failures
                .iter()
                .filter(|(seed, _): &(&u64, &String)| pinned.contains(seed)),
        )
        .take(SHOWN_FAILURES)
        .map(|(seed, why): (&u64, &String)| {
            format!(
                "seed {seed}: {why}\n--- source ---\n{}",
                excerpt(&original[seed], 3000)
            )
        })
        .collect();
    let summary: Vec<String> = failures
        .iter()
        .map(|(seed, why): (&u64, &String)| {
            let reason: &str = why.lines().next().unwrap_or_default();
            let marker: &str = why
                .lines()
                .find_map(|text: &str| text.trim_start().strip_prefix("// <decompile: "))
                .unwrap_or_default();
            format!(
                "  seed {seed}: {} {}",
                excerpt(reason, 240),
                excerpt(marker, 160)
            )
        })
        .collect();
    assert!(
        regressed.is_empty() && fixed.is_empty(),
        "{} of {PROGRAMS} generated Kotlin programs did not recover to the same behaviour; the \
         divergent set must equal KNOWN_DIVERGENT exactly, which only ever shrinks. Newly \
         divergent: {regressed:?}. Now recovered, remove from KNOWN_DIVERGENT: {fixed:?}.\n{}\n{}",
        failures.len(),
        summary.join("\n"),
        shown.join("\n=====\n")
    );
}

#[test]
fn the_kotlin_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).method(7);
    assert_eq!(first, Generator::new(7).method(7));
    let methods: BTreeMap<u64, String> = generated_methods();
    let distinct: BTreeSet<&String> = methods.values().collect();
    assert_eq!(distinct.len() as u64, PROGRAMS);
    let all: String = methods.values().cloned().collect();
    for shape in [
        "while (",
        "do {",
        "for (i",
        "..",
        " until ",
        " step ",
        " downTo ",
        "} else if (",
        "} else {",
        "if (t.size > ",
        "break\n",
        "continue\n",
        "break@l",
        "continue@l",
        "@ for (",
        "@ while (",
        "catch (error: ArithmeticException)",
        "} finally {",
        "= try {",
        "when ((",
        "when {",
        "1, 2 -> {",
        "else -> {",
        "(when {",
        "(when ((",
        "(u ?: ",
        "u?.plus(",
        "u?.let {",
        "u != null",
        "${t.size}",
        "t.contains(",
        ") in t",
        "t += ",
        "maxOf(",
        "Sink.f(",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
    let objects: usize = (0..PROGRAMS).filter(|seed: &u64| in_object(*seed)).count();
    assert!(objects > 0 && (objects as u64) < PROGRAMS);
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let tools: Toolchain = toolchain();
    let programs: BTreeMap<u64, String> = (0..PROGRAMS)
        .map(|seed: u64| {
            let pad: &str = if in_object(seed) { "    " } else { "" };
            (
                seed,
                format!(
                    "{pad}fun prog{seed}() {{\n{pad}    var a = {seed} + 3\n{pad}    var b = 4\n{pad}    a %= 50\n{pad}    Sink.emit(a * b)\n{pad}}}\n"
                ),
            )
        })
        .collect();
    let reference: Reference = build_reference(&tools, &kotlin_file(&programs));
    let recovery: Recovery = decompile(&reference);
    let mut failures: BTreeMap<u64, String> = BTreeMap::new();
    let faithful: BTreeMap<u64, String> = reexecute(&tools, &recovery, &mut failures);
    assert!(
        failures.is_empty(),
        "the control programs must recover: {failures:?}"
    );
    assert_eq!(faithful, reference.lines);
    let body: &String = &recovery.methods[&0];
    let mutated_body: String = body.replacen(" * ", " - ", 1);
    assert_ne!(
        &mutated_body, body,
        "the recovered control body multiplies:\n{body}"
    );
    let mut mutant: Recovery = recovery.clone();
    let unit: &mut String = mutant
        .decompiled
        .get_mut(class_of(0))
        .expect("the control class was decompiled");
    *unit = unit.replacen(body.as_str(), &mutated_body, 1);
    mutant.methods.insert(0, mutated_body);
    let changed: BTreeMap<u64, String> = reexecute(&tools, &mutant, &mut failures);
    assert!(failures.is_empty());
    assert_ne!(changed.get(&0), reference.lines.get(&0));
    assert_eq!(changed.get(&1), reference.lines.get(&1));
}
