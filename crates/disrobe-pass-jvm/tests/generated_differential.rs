#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    DecompiledClass, DecompiledDex, decompile_classfile_bytes, decompile_dex_from_bytes,
};
use disrobe_testkit::{Available, CommandSpec, ToolError, ToolOutput, require, tool_output};
use sha2::{Digest, Sha256};

const PROGRAMS: u64 = 300;
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;
const TOOL_TIMEOUT: Duration = Duration::from_mins(5);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPAIR_ROUNDS: usize = 16;
const RUN_TIMEOUT: Duration = Duration::from_mins(1);
const PROGRAM_MILLIS: u64 = 5_000;
const SHOWN_FAILURES: usize = 6;
const KNOWN_DIVERGENT: [u64; 0] = [];
const DEX_KNOWN_DIVERGENT: [u64; 105] = [
    5, 11, 12, 18, 27, 30, 35, 40, 43, 45, 51, 54, 56, 57, 58, 61, 63, 66, 69, 70, 71, 72, 73, 74,
    79, 82, 86, 87, 89, 92, 94, 100, 105, 107, 110, 111, 116, 119, 124, 125, 126, 127, 131, 134,
    140, 141, 146, 151, 155, 156, 157, 158, 161, 162, 163, 165, 168, 169, 170, 171, 173, 174, 179,
    180, 182, 183, 184, 189, 194, 199, 202, 209, 217, 218, 219, 224, 225, 227, 231, 233, 234, 236,
    240, 241, 242, 243, 248, 251, 256, 258, 264, 267, 270, 273, 274, 275, 280, 281, 283, 286, 288,
    292, 296, 297, 298,
];
const D8_PREREQUISITE: &str = "disrobe-pass-jvm::r8-jar";
const R8_JAR_SHA256: &str = "3b4de3053885da105e39c15212261d22653d6d1b5eb92323dd04ae913cc8286f";

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

struct Generator {
    state: u64,
    serial: u32,
    k: u64,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
            serial: 0,
            k: 0,
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
            3 => format!("t.contains({})", self.arithmetic(1)),
            _ => comparison,
        }
    }

    fn value(&mut self) -> String {
        match self.below(7) {
            0 => format!(
                "(({}) ? {} : {})",
                self.condition(),
                self.arithmetic(1),
                self.arithmetic(1)
            ),
            1 => {
                let index: u64 = self.below(4);
                format!(
                    "(t.size() > {index} ? t.get({index}) : {})",
                    self.arithmetic(1)
                )
            }
            2 => format!("Sink.f({}, {})", self.arithmetic(1), self.k),
            3 => format!("Math.max({}, {})", self.arithmetic(1), self.arithmetic(1)),
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
                writeln!(out, "{pad}Sink.emit({value});").expect("write to a String");
            }
            3 => {
                let value: String = self.arithmetic(1);
                writeln!(out, "{pad}t.add({value});").expect("write to a String");
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
                writeln!(out, "{pad}if ({cond})").expect("write to a String");
                self.braced(depth, indent, out);
                if self.below(2) == 0 {
                    let other: String = self.condition();
                    writeln!(out, "{pad}else if ({other})").expect("write to a String");
                    self.braced(depth, indent, out);
                }
                if self.below(2) == 0 {
                    writeln!(out, "{pad}else").expect("write to a String");
                    self.braced(depth, indent, out);
                }
            }
            7 => {
                self.serial += 1;
                let var: String = format!("i{}", self.serial);
                let first: u64 = self.below(4);
                let last: u64 = first + self.below(5);
                writeln!(
                    out,
                    "{pad}for (int {var} = {first}; {var} <= {last}; {var}++)"
                )
                .expect("write to a String");
                writeln!(out, "{pad}{{").expect("write to a String");
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
                let counter: String = format!("n{}", self.serial);
                let limit: u64 = 1 + self.below(5);
                let cond: String = self.condition();
                writeln!(out, "{pad}int {counter} = 0;").expect("write to a String");
                if self.below(3) == 0 {
                    writeln!(out, "{pad}do").expect("write to a String");
                    writeln!(out, "{pad}{{").expect("write to a String");
                    writeln!(out, "{pad}    {counter}++;").expect("write to a String");
                    self.loop_body(depth, indent, out);
                    writeln!(
                        out,
                        "{pad}}} while ({counter} < {limit} && ({cond} || {counter} == 1));"
                    )
                    .expect("write to a String");
                } else {
                    writeln!(
                        out,
                        "{pad}while ({counter} < {limit} && ({cond} || {counter} == 0))"
                    )
                    .expect("write to a String");
                    writeln!(out, "{pad}{{").expect("write to a String");
                    writeln!(out, "{pad}    {counter}++;").expect("write to a String");
                    self.loop_body(depth, indent, out);
                    writeln!(out, "{pad}}}").expect("write to a String");
                }
            }
            9 => {
                let divisor: String = format!("({} + {})", self.arithmetic(1), self.variable());
                let target: &str = self.variable();
                let numerator: String = self.atom();
                writeln!(out, "{pad}try").expect("write to a String");
                writeln!(out, "{pad}{{").expect("write to a String");
                writeln!(out, "{pad}    {target} = {numerator} / ({divisor} % 3);")
                    .expect("write to a String");
                self.block(depth + 1, indent + 1, out);
                writeln!(out, "{pad}}}").expect("write to a String");
                writeln!(out, "{pad}catch (ArithmeticException error)").expect("write to a String");
                writeln!(out, "{pad}{{").expect("write to a String");
                writeln!(out, "{pad}    Sink.emit(\"zero\");").expect("write to a String");
                writeln!(out, "{pad}}}").expect("write to a String");
                if self.below(2) == 0 {
                    let shown: &str = self.variable();
                    writeln!(out, "{pad}finally").expect("write to a String");
                    writeln!(out, "{pad}{{").expect("write to a String");
                    writeln!(out, "{pad}    Sink.emit({shown});").expect("write to a String");
                    writeln!(out, "{pad}}}").expect("write to a String");
                }
            }
            10 => {
                let subject: String = self.arithmetic(1);
                writeln!(out, "{pad}switch ((({subject}) % 4 + 4) % 4)")
                    .expect("write to a String");
                writeln!(out, "{pad}{{").expect("write to a String");
                writeln!(out, "{pad}    case 0:").expect("write to a String");
                self.case_body(depth, indent, out);
                writeln!(out, "{pad}    case 1:").expect("write to a String");
                writeln!(out, "{pad}    case 2:").expect("write to a String");
                self.case_body(depth, indent, out);
                if self.below(2) == 0 {
                    writeln!(out, "{pad}    default:").expect("write to a String");
                    self.case_body(depth, indent, out);
                }
                writeln!(out, "{pad}}}").expect("write to a String");
            }
            _ => {
                let value: String = self.arithmetic(2);
                writeln!(out, "{pad}Sink.emit({value});").expect("write to a String");
            }
        }
    }

    fn braced(&mut self, depth: u32, indent: usize, out: &mut String) {
        let pad: String = "    ".repeat(indent);
        writeln!(out, "{pad}{{").expect("write to a String");
        self.block(depth + 1, indent + 1, out);
        writeln!(out, "{pad}}}").expect("write to a String");
    }

    fn case_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        let pad: String = "    ".repeat(indent + 2);
        writeln!(out, "{pad}{{").expect("write to a String");
        self.block(depth + 1, indent + 3, out);
        writeln!(out, "{pad}    break;").expect("write to a String");
        writeln!(out, "{pad}}}").expect("write to a String");
    }

    fn loop_body(&mut self, depth: u32, indent: usize, out: &mut String) {
        self.block(depth + 1, indent + 1, out);
        let pad: String = "    ".repeat(indent + 1);
        match self.below(4) {
            0 => {
                let cond: String = self.condition();
                writeln!(out, "{pad}if ({cond}) break;").expect("write to a String");
            }
            1 => {
                let cond: String = self.condition();
                let shown: &str = self.variable();
                writeln!(out, "{pad}if ({cond}) continue;").expect("write to a String");
                writeln!(out, "{pad}Sink.emit({shown});").expect("write to a String");
            }
            _ => {}
        }
    }

    fn method(&mut self, seed: u64) -> String {
        self.k = 1 + self.below(5);
        let mut out: String = format!(
            "    public static void prog{seed}()\n    {{\n        List<Integer> t = new ArrayList<>();\n"
        );
        for name in VARIABLES {
            writeln!(out, "        int {name} = {};", self.below(10)).expect("write to a String");
        }
        self.block(0, 2, &mut out);
        for name in VARIABLES {
            writeln!(out, "        Sink.emit({name});").expect("write to a String");
        }
        out.push_str("        Sink.emit(t);\n    }\n");
        out
    }
}

fn generated_methods() -> BTreeMap<u64, String> {
    (0..PROGRAMS)
        .map(|seed: u64| (seed, Generator::new(seed).method(seed)))
        .collect()
}

fn gen_class(methods: &BTreeMap<u64, String>) -> String {
    let mut out: String = String::from(
        "import java.util.ArrayList;\nimport java.util.List;\n\npublic final class Gen {\n",
    );
    for method in methods.values() {
        out.push_str(method);
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

fn main_class() -> String {
    let mut out: String = String::from(
        "public final class Main {\n    public static void main(String[] args) throws InterruptedException {\n        int from = args.length > 0 ? Integer.parseInt(args[0]) : 0;\n        Runnable[] programs = {\n",
    );
    for seed in 0..PROGRAMS {
        writeln!(out, "            Gen::prog{seed},").expect("write to a String");
    }
    write!(
        out,
        "        }};\n        for (int seed = from; seed < programs.length; seed++) {{\n            final Runnable program = programs[seed];\n            final String[] line = new String[1];\n            Thread worker = new Thread(() -> {{\n                Sink.reset();\n                try {{ program.run(); }} catch (Throwable error) {{ Sink.emit(\"threw \" + error.getClass().getSimpleName()); }}\n                line[0] = Sink.take();\n            }});\n            worker.setDaemon(true);\n            worker.start();\n            worker.join({PROGRAM_MILLIS});\n            if (worker.isAlive() || line[0] == null) {{\n                System.out.println(seed + \"! does not terminate within {PROGRAM_MILLIS} ms\");\n                System.out.flush();\n                Runtime.getRuntime().halt(3);\n            }}\n            System.out.println(seed + \": \" + line[0]);\n            System.out.flush();\n        }}\n    }}\n}}\n"
    )
    .expect("write to a String");
    out
}

struct Jdk {
    javac: PathBuf,
    java: PathBuf,
}

fn jdk() -> Jdk {
    Jdk {
        javac: common::grader_jdk_tool("javac"),
        java: common::grader_jdk_tool("java"),
    }
}

struct Built {
    build: ToolOutput,
    lines: BTreeMap<u64, String>,
    hung: BTreeMap<u64, String>,
    classes: PathBuf,
}

fn build_and_run(jdk: &Jdk, directory: &Path, gen_source: &str) -> Built {
    let sources: [(&str, String); 3] = [
        ("Sink.java", SINK.to_owned()),
        ("Main.java", main_class()),
        ("Gen.java", gen_source.to_owned()),
    ];
    let classes: PathBuf = directory.join("classes");
    std::fs::create_dir_all(&classes).expect("create the class output directory");
    let mut javac: CommandSpec = CommandSpec::new(jdk.javac.clone(), TOOL_TIMEOUT)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
        .args([
            "-J-Xmx3g",
            "-nowarn",
            "-proc:none",
            "-encoding",
            "UTF-8",
            "-Xmaxerrs",
            "100000",
        ])
        .arg("-d")
        .arg(classes.clone())
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
    let mut lines: BTreeMap<u64, String> = BTreeMap::new();
    let mut hung: BTreeMap<u64, String> = BTreeMap::new();
    let mut from: u64 = 0;
    while build.success && from < PROGRAMS {
        let run: ToolOutput = tool_output(
            CommandSpec::new(jdk.java.clone(), RUN_TIMEOUT)
                .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
                .arg("-Xmx2g")
                .arg("-cp")
                .arg(classes.clone())
                .arg("Main")
                .arg(from.to_string())
                .current_dir(directory.to_path_buf()),
        )
        .unwrap_or_else(|error: ToolError| panic!("the Main program could not start: {error}"));
        let mut stalled: Option<(u64, String)> = None;
        for line in run.stdout_text().lines() {
            if let Some((seed, rest)) = line.split_once(": ")
                && let Ok(seed) = seed.trim().parse::<u64>()
            {
                lines.insert(seed, rest.trim_end().to_owned());
            } else if let Some((seed, rest)) = line.split_once("! ")
                && let Ok(seed) = seed.trim().parse::<u64>()
            {
                stalled = Some((seed, rest.trim_end().to_owned()));
            }
        }
        let next: Option<u64> = (from..PROGRAMS).find(|seed: &u64| !lines.contains_key(seed));
        let Some(missing) = next else {
            break;
        };
        let reason: String = match stalled {
            Some((seed, why)) if seed == missing => why,
            _ if run.timed_out => format!(
                "does not terminate within {} seconds",
                RUN_TIMEOUT.as_secs()
            ),
            _ => format!("crashes the process: {}", run.stderr_text().trim()),
        };
        hung.insert(missing, reason);
        from = missing + 1;
    }
    Built {
        build,
        lines,
        hung,
        classes,
    }
}

fn prog_seed(line: &str) -> Option<u64> {
    line.trim_start()
        .strip_prefix("public static void prog")
        .and_then(|rest: &str| rest.split('(').next())
        .and_then(|digits: &str| digits.trim().parse::<u64>().ok())
}

fn recovered_methods(source: &str) -> BTreeMap<u64, String> {
    let mut methods: BTreeMap<u64, String> = BTreeMap::new();
    let mut lines: std::str::Lines<'_> = source.lines();
    while let Some(line) = lines.next() {
        let Some(seed) = prog_seed(line) else {
            continue;
        };
        let indent: usize = line.len() - line.trim_start().len();
        let closing: String = format!("{}}}", " ".repeat(indent));
        let mut text: String = format!("{line}\n");
        if !line.trim_end().ends_with('}') {
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

fn seeds_named_by_diagnostics(build: &ToolOutput, source: &str) -> BTreeMap<u64, Vec<String>> {
    let mut starts: Vec<(usize, u64)> = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if let Some(seed) = prog_seed(line) {
            starts.push((index + 1, seed));
        }
    }
    let diagnostics: String = format!("{}{}", build.stdout_text(), build.stderr_text());
    let mut seeds: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for line in diagnostics.lines() {
        let Some(at) = line
            .find("Gen.java:")
            .filter(|_| line.contains(": error: "))
        else {
            continue;
        };
        let Some(number) = line[at + "Gen.java:".len()..]
            .split(':')
            .next()
            .and_then(|digits: &str| digits.parse::<usize>().ok())
        else {
            continue;
        };
        if let Some((_, seed)) = starts.iter().rev().find(|(start, _)| *start <= number) {
            let message: &str = line[at..].trim();
            let messages: &mut Vec<String> = seeds.entry(*seed).or_default();
            if !messages.iter().any(|known: &String| known == message) {
                messages.push(message.to_owned());
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

#[test]
fn generated_programs_reexecute_identically_on_the_jvm() {
    let jdk: Jdk = jdk();
    let original: BTreeMap<u64, String> = generated_methods();
    let original_scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_generated_original").expect("create scratch");
    let reference: Built = build_and_run(&jdk, original_scratch.path(), &gen_class(&original));
    assert!(
        reference.build.success,
        "the generated programs must compile:\n{}{}",
        reference.build.stdout_text(),
        reference.build.stderr_text()
    );
    assert!(
        reference.hung.is_empty(),
        "every generated program terminates: {:?}",
        reference.hung
    );
    assert_eq!(
        reference.lines.len() as u64,
        PROGRAMS,
        "the reference run prints one line per program"
    );
    let image: Vec<u8> =
        std::fs::read(reference.classes.join("Gen.class")).expect("read the compiled Gen class");
    let decompiled: DecompiledClass = decompile_classfile_bytes(&image).expect("decompile");
    let recovered: BTreeMap<u64, String> = recovered_methods(&decompiled.source);
    grade_recovered(
        &jdk,
        &original,
        &reference,
        &recovered,
        &decompiled.source,
        &KNOWN_DIVERGENT,
        "class-file",
    );
}

fn grade_recovered(
    jdk: &Jdk,
    original: &BTreeMap<u64, String>,
    reference: &Built,
    recovered: &BTreeMap<u64, String>,
    decompiled_source: &str,
    known: &[u64],
    route: &str,
) {
    let mut failures: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        if !recovered.contains_key(&seed) {
            failures.insert(
                seed,
                format!(
                    "the decompiler emitted no prog body\n{}",
                    excerpt(decompiled_source, 3000)
                ),
            );
        }
    }
    let mut outputs: BTreeMap<u64, String> = BTreeMap::new();
    for _ in 0..MAX_REPAIR_ROUNDS {
        let candidate: BTreeMap<u64, String> = (0..PROGRAMS)
            .map(|seed: u64| {
                let body: &String = if failures.contains_key(&seed) {
                    &original[&seed]
                } else {
                    &recovered[&seed]
                };
                (seed, body.clone())
            })
            .collect();
        let source: String = gen_class(&candidate);
        let scratch: ScratchDir =
            ScratchDir::create("disrobe_jvm_generated_recovered").expect("create scratch");
        let built: Built = build_and_run(jdk, scratch.path(), &source);
        for (seed, reason) in &built.hung {
            failures.insert(
                *seed,
                format!(
                    "the recovered body {reason}:\n{}",
                    excerpt(&recovered[seed], 3000)
                ),
            );
        }
        if built.build.success {
            outputs = built.lines;
            break;
        }
        let named: BTreeMap<u64, Vec<String>> = seeds_named_by_diagnostics(&built.build, &source);
        assert!(
            !named.is_empty(),
            "the recovered class failed to compile without naming a prog method:\n{}",
            excerpt(&built.build.stderr_text(), 4000)
        );
        for (seed, messages) in named {
            failures.entry(seed).or_insert_with(|| {
                format!(
                    "the recovered body does not compile: {}\n{}",
                    messages.join(" | "),
                    excerpt(&recovered[&seed], 3000)
                )
            });
        }
    }
    assert!(
        !outputs.is_empty(),
        "no recovered build compiled within {MAX_REPAIR_ROUNDS} rounds"
    );
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
                    excerpt(&recovered[&seed], 3000)
                ),
            );
        }
    }
    let pinned: BTreeSet<u64> = known.iter().copied().collect();
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
                .find_map(|line: &str| line.trim_start().strip_prefix("// <decompile: "))
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
        "{} of {PROGRAMS} generated Java programs did not recover to the same behaviour through \
         the {route} route; the divergent set must equal its known-divergent list exactly, which only ever shrinks. Newly \
         divergent: {regressed:?}. Now recovered, remove from KNOWN_DIVERGENT: {fixed:?}.\n{}\n{}",
        failures.len(),
        summary.join("\n"),
        shown.join("\n=====\n")
    );
}

fn r8_jar() -> PathBuf {
    let located: Option<PathBuf> = std::env::var_os("DISROBE_R8_JAR")
        .map(PathBuf::from)
        .filter(|path: &PathBuf| path.is_file());
    let jar: PathBuf = match require(
        D8_PREREQUISITE,
        "the pinned R8/D8 9.1.31 jar (r8-9.1.31.jar from Google Maven, sha256 \
         3b4de3053885da105e39c15212261d22653d6d1b5eb92323dd04ae913cc8286f) named by \
         DISROBE_R8_JAR, which lowers the generated programs to DEX for the Dalvik route",
        located,
    ) {
        Ok(Available::Present(path)) => path,
        Ok(Available::NotMeasured { record }) => panic!(
            "the DEX generated differential has no measurement without D8, so it cannot be \
             listed optional (record {})",
            record.display()
        ),
        Err(error) => panic!("{error}"),
    };
    let bytes: Vec<u8> = std::fs::read(&jar).expect("read the R8 jar");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        R8_JAR_SHA256,
        "{} is not the pinned R8 9.1.31 jar, so the DEX it writes would not match the \
         known-divergent list",
        jar.display()
    );
    jar
}

#[test]
fn generated_programs_reexecute_identically_through_dex() {
    let jdk: Jdk = jdk();
    let r8: PathBuf = r8_jar();
    let original: BTreeMap<u64, String> = generated_methods();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_generated_dex").expect("create scratch");
    let reference: Built = build_and_run(&jdk, scratch.path(), &gen_class(&original));
    assert!(
        reference.build.success,
        "the generated programs must compile:\n{}{}",
        reference.build.stdout_text(),
        reference.build.stderr_text()
    );
    assert!(
        reference.hung.is_empty(),
        "every generated program terminates: {:?}",
        reference.hung
    );
    let dex_dir: PathBuf = scratch.path().join("dex");
    std::fs::create_dir_all(&dex_dir).expect("create the dex output directory");
    let lowered: ToolOutput = tool_output(
        CommandSpec::new(jdk.java.clone(), TOOL_TIMEOUT)
            .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
            .args(["-Xmx2g", "-cp"])
            .arg(r8)
            .args([
                "com.android.tools.r8.D8",
                "--release",
                "--no-desugaring",
                "--min-api",
                "26",
                "--output",
            ])
            .arg(dex_dir.clone())
            .arg(reference.classes.join("Gen.class"))
            .current_dir(scratch.path().to_path_buf()),
    )
    .unwrap_or_else(|error: ToolError| panic!("d8 could not start: {error}"));
    assert!(
        lowered.success,
        "d8 must lower Gen.class:\n{}{}",
        lowered.stdout_text(),
        lowered.stderr_text()
    );
    let dex: Vec<u8> = std::fs::read(dex_dir.join("classes.dex")).expect("read classes.dex");
    let decompiled: DecompiledDex = decompile_dex_from_bytes(&dex).expect("decompile the DEX");
    let source: String = decompiled
        .sources
        .iter()
        .find(|(unit, _): &(&String, &String)| unit.ends_with("Gen.java"))
        .map_or_else(
            || decompiled.source.clone(),
            |(_, text): (&String, &String)| text.clone(),
        );
    let recovered: BTreeMap<u64, String> = recovered_methods(&source);
    grade_recovered(
        &jdk,
        &original,
        &reference,
        &recovered,
        &source,
        &DEX_KNOWN_DIVERGENT,
        "DEX",
    );
}

#[test]
fn the_java_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).method(7);
    assert_eq!(first, Generator::new(7).method(7));
    let methods: BTreeMap<u64, String> = generated_methods();
    let distinct: BTreeSet<&String> = methods.values().collect();
    assert_eq!(distinct.len() as u64, PROGRAMS);
    let all: String = methods.values().cloned().collect();
    for shape in [
        "while (",
        "do\n",
        "for (int i",
        "else if (",
        "else\n",
        "break;",
        "continue;",
        "catch (ArithmeticException error)",
        "finally\n",
        "switch (",
        "default:",
        " ? ",
        "t.contains(",
        "Math.max(",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let jdk: Jdk = jdk();
    let method: String = "    public static void prog0()\n    {\n        List<Integer> t = new ArrayList<>();\n        int a = 3;\n        int b = 4;\n        Sink.emit(a + b);\n        Sink.emit(t);\n    }\n".to_owned();
    let mutated: String = method.replacen("a + b", "a - b", 1);
    let mut programs: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        let text: String = method.replace("prog0", &format!("prog{seed}"));
        programs.insert(seed, text);
    }
    let mut mutant: BTreeMap<u64, String> = programs.clone();
    mutant.insert(0, mutated);
    let original_scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_generated_control").expect("create scratch");
    let original: Built = build_and_run(&jdk, original_scratch.path(), &gen_class(&programs));
    let mutant_scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_generated_mutant").expect("create scratch");
    let changed: Built = build_and_run(&jdk, mutant_scratch.path(), &gen_class(&mutant));
    assert!(original.build.success && changed.build.success);
    assert_ne!(original.lines.get(&0), changed.lines.get(&0));
    assert_eq!(original.lines.get(&1), changed.lines.get(&1));
}

#[test]
fn a_program_that_never_returns_is_isolated_and_the_rest_still_run() {
    let jdk: Jdk = jdk();
    let method: String =
        "    public static void prog0()\n    {\n        Sink.emit(1);\n    }\n".to_owned();
    let mut programs: BTreeMap<u64, String> = BTreeMap::new();
    for seed in 0..PROGRAMS {
        programs.insert(seed, method.replace("prog0", &format!("prog{seed}")));
    }
    programs.insert(
        1,
        "    public static void prog1()\n    {\n        int spin = 0;\n        while (spin >= 0) { spin = (spin + 1) % 7; }\n    }\n".to_owned(),
    );
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_jvm_generated_hang").expect("create scratch");
    let built: Built = build_and_run(&jdk, scratch.path(), &gen_class(&programs));
    assert!(built.build.success);
    assert_eq!(built.hung.keys().copied().collect::<Vec<u64>>(), vec![1]);
    assert_eq!(built.lines.len() as u64, PROGRAMS - 1);
    assert_eq!(built.lines.get(&2).map(String::as_str), Some("1"));
}
