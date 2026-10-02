#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const PROGRAMS: u64 = 300;
const WIDE_SWEEP_SEEDS: [u64; 11] = [
    806, 1028, 1138, 1179, 2306, 3676, 4618, 5384, 5608, 5696, 10548,
];
const RICH_FIRST: u64 = 1_000_000;
const RICH_PROGRAMS: u64 = 300;
const GEN_TYPE: &str = "GenDiff.Gen";
const VARIABLES: [&str; 5] = ["a", "b", "c", "d", "e"];
const MAX_BLOCK_DEPTH: u32 = 3;
const TOOL_TIMEOUT: Duration = Duration::from_mins(10);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPAIR_ROUNDS: usize = 12;
const RUN_TIMEOUT: Duration = Duration::from_mins(1);
const SHOWN_FAILURES: usize = 6;
const KNOWN_DIVERGENT: [u64; 191] = [
    1_000_001, 1_000_003, 1_000_004, 1_000_007, 1_000_009, 1_000_012, 1_000_013, 1_000_014,
    1_000_016, 1_000_017, 1_000_020, 1_000_022, 1_000_026, 1_000_027, 1_000_028, 1_000_031,
    1_000_032, 1_000_034, 1_000_035, 1_000_037, 1_000_038, 1_000_039, 1_000_040, 1_000_043,
    1_000_044, 1_000_047, 1_000_048, 1_000_049, 1_000_050, 1_000_053, 1_000_054, 1_000_057,
    1_000_058, 1_000_060, 1_000_061, 1_000_062, 1_000_064, 1_000_066, 1_000_067, 1_000_068,
    1_000_070, 1_000_072, 1_000_075, 1_000_077, 1_000_078, 1_000_079, 1_000_080, 1_000_081,
    1_000_083, 1_000_086, 1_000_090, 1_000_092, 1_000_094, 1_000_095, 1_000_096, 1_000_097,
    1_000_098, 1_000_099, 1_000_100, 1_000_101, 1_000_102, 1_000_104, 1_000_105, 1_000_106,
    1_000_107, 1_000_110, 1_000_111, 1_000_113, 1_000_114, 1_000_115, 1_000_117, 1_000_118,
    1_000_119, 1_000_121, 1_000_122, 1_000_123, 1_000_124, 1_000_126, 1_000_129, 1_000_130,
    1_000_131, 1_000_132, 1_000_133, 1_000_134, 1_000_135, 1_000_136, 1_000_137, 1_000_139,
    1_000_140, 1_000_141, 1_000_142, 1_000_144, 1_000_145, 1_000_147, 1_000_148, 1_000_149,
    1_000_150, 1_000_152, 1_000_153, 1_000_154, 1_000_157, 1_000_158, 1_000_159, 1_000_160,
    1_000_163, 1_000_165, 1_000_166, 1_000_167, 1_000_168, 1_000_169, 1_000_170, 1_000_171,
    1_000_173, 1_000_175, 1_000_177, 1_000_181, 1_000_182, 1_000_183, 1_000_184, 1_000_185,
    1_000_187, 1_000_188, 1_000_191, 1_000_193, 1_000_196, 1_000_197, 1_000_198, 1_000_199,
    1_000_200, 1_000_203, 1_000_205, 1_000_206, 1_000_209, 1_000_211, 1_000_212, 1_000_214,
    1_000_216, 1_000_218, 1_000_219, 1_000_220, 1_000_221, 1_000_222, 1_000_223, 1_000_224,
    1_000_226, 1_000_227, 1_000_228, 1_000_232, 1_000_233, 1_000_235, 1_000_236, 1_000_239,
    1_000_240, 1_000_241, 1_000_242, 1_000_245, 1_000_247, 1_000_248, 1_000_249, 1_000_250,
    1_000_252, 1_000_254, 1_000_255, 1_000_256, 1_000_257, 1_000_258, 1_000_259, 1_000_263,
    1_000_264, 1_000_267, 1_000_269, 1_000_271, 1_000_273, 1_000_275, 1_000_276, 1_000_278,
    1_000_280, 1_000_282, 1_000_284, 1_000_285, 1_000_287, 1_000_288, 1_000_290, 1_000_291,
    1_000_292, 1_000_293, 1_000_294, 1_000_296, 1_000_297, 1_000_298, 1_000_299,
];

const PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <AssemblyName>GenDiff</AssemblyName>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <Deterministic>true</Deterministic>
    <Optimize>true</Optimize>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
"#;

const SINK: &str = r#"using System;
using System.Collections.Generic;
using System.Text;

namespace GenDiff
{
    public static class Sink
    {
        private static readonly StringBuilder Text = new StringBuilder();

        public static void Reset()
        {
            Text.Clear();
        }

        public static void Emit(int value)
        {
            Text.Append(value).Append(' ');
        }

        public static void Emit(string value)
        {
            Text.Append(value).Append(' ');
        }

        public static void Emit(List<int> values)
        {
            Text.Append('[').Append(string.Join(",", values)).Append("] ");
        }

        public static int F(int x, int k)
        {
            return x > k ? x - k : x + k;
        }

        public static string Take()
        {
            return Text.ToString();
        }
    }
}
"#;

struct Generator {
    state: u64,
    serial: u32,
    k: u64,
    rich: bool,
}

impl Generator {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
            serial: 0,
            k: 0,
            rich: seed >= RICH_FIRST,
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
            3 => format!("t.Contains({})", self.arithmetic(1)),
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
                format!("(t.Count > {index} ? t[{index}] : {})", self.arithmetic(1))
            }
            2 => format!("Sink.F({}, {})", self.arithmetic(1), self.k),
            3 => format!("Math.Max({}, {})", self.arithmetic(1), self.arithmetic(1)),
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
        if self.rich && self.below(3) == 0 {
            self.rich_statement(depth, indent, out);
            return;
        }
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
                writeln!(out, "{pad}Sink.Emit({value});").expect("write to a String");
            }
            3 => {
                let value: String = self.arithmetic(1);
                writeln!(out, "{pad}t.Add({value});").expect("write to a String");
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
                writeln!(out, "{pad}catch (DivideByZeroException)").expect("write to a String");
                writeln!(out, "{pad}{{").expect("write to a String");
                writeln!(out, "{pad}    Sink.Emit(\"zero\");").expect("write to a String");
                writeln!(out, "{pad}}}").expect("write to a String");
                if self.below(2) == 0 {
                    let shown: &str = self.variable();
                    writeln!(out, "{pad}finally").expect("write to a String");
                    writeln!(out, "{pad}{{").expect("write to a String");
                    writeln!(out, "{pad}    Sink.Emit({shown});").expect("write to a String");
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
                writeln!(out, "{pad}Sink.Emit({value});").expect("write to a String");
            }
        }
    }

    fn modulo3(&mut self) -> String {
        format!("((({}) % 3 + 3) % 3)", self.arithmetic(1))
    }

    fn rich_statement(&mut self, depth: u32, indent: usize, out: &mut String) {
        let pad: String = "    ".repeat(indent);
        self.serial += 1;
        let n: u32 = self.serial;
        let target: &str = self.variable();
        let line = |out: &mut String, text: &str| {
            writeln!(out, "{pad}{text}").expect("write to a String");
        };
        match self.below(13) {
            0 => {
                let value: String = self.value();
                line(out, &format!("s = s + {value} + \",\";"));
                line(out, "if (s.Length > 40) s = s.Substring(s.Length - 20);");
            }
            1 => {
                let first: &str = self.variable();
                let second: String = self.arithmetic(1);
                line(out, &format!("s = $\"{{{first}}}-{{{second}}}\";"));
                line(out, "Sink.Emit(s.Length % 100);");
            }
            2 => {
                let subject: String = self.modulo3();
                let (zero, one, other): (String, String, String) =
                    (self.value(), self.value(), self.value());
                line(
                    out,
                    &format!(
                        "{target} = {subject} switch {{ 0 => {zero}, 1 => {one}, _ => {other} }};"
                    ),
                );
            }
            3 => {
                let captured: &str = self.variable();
                let argument: String = self.arithmetic(1);
                let k: u64 = self.k;
                line(
                    out,
                    &format!("Func<int, int> f{n} = x => (x * {captured} + {k}) % 1000;"),
                );
                line(out, &format!("{target} = f{n}({argument});"));
            }
            4 => {
                let bound: String = self.atom();
                let divisor: u64 = 2 + self.below(9);
                line(
                    out,
                    &format!(
                        "{target} = t.Where(x => x > {bound}).Select(x => x % {divisor}).Sum() % 1000;"
                    ),
                );
            }
            5 => {
                let numerator: String = self.atom();
                let divisor: String = format!("({} + {})", self.arithmetic(1), self.variable());
                let filtered: &str = self.variable();
                let k: u64 = self.k;
                line(out, "try");
                line(out, "{");
                line(
                    out,
                    &format!("    {target} = {numerator} / ({divisor} % 3);"),
                );
                line(out, "}");
                line(
                    out,
                    &format!("catch (DivideByZeroException) when ({filtered} > {k})"),
                );
                line(out, "{");
                line(out, "    Sink.Emit(\"filtered\");");
                line(out, "}");
                line(out, "catch (DivideByZeroException)");
                line(out, "{");
                line(out, "    Sink.Emit(\"zero\");");
                line(out, "}");
            }
            6 => {
                let cond: String = self.condition();
                let some: String = self.arithmetic(1);
                let fallback: String = self.atom();
                line(out, &format!("int? m{n} = ({cond}) ? {some} : (int?)null;"));
                line(out, &format!("{target} = (m{n} ?? {fallback}) % 1000;"));
                line(out, &format!("if (m{n}.HasValue) Sink.Emit(m{n}.Value);"));
            }
            7 => {
                let cond: String = self.condition();
                line(out, &format!("foreach (int x{n} in t)"));
                line(out, "{");
                line(out, &format!("    {target} = ({target} + x{n}) % 1000;"));
                line(out, &format!("    if ({cond}) break;"));
                line(out, "}");
            }
            8 => {
                let first: &str = self.variable();
                let second: &str = self.variable();
                line(out, "try");
                line(out, "{");
                line(
                    out,
                    &format!("    {target} = checked({first} * 1000000 * ({second} + 1)) % 1000;"),
                );
                line(out, "}");
                line(out, "catch (OverflowException)");
                line(out, "{");
                line(out, "    Sink.Emit(\"overflow\");");
                line(out, "}");
            }
            9 => {
                let captured: &str = self.variable();
                let argument: String = self.arithmetic(1);
                line(out, &format!("int L{n}(int x) => (x + {captured}) % 97;"));
                line(out, &format!("{target} = L{n}({argument});"));
            }
            10 => {
                let key: String = self.modulo3();
                let (zero, one): (String, String) = (self.value(), self.value());
                line(out, &format!("switch (\"k\" + {key})"));
                line(out, "{");
                line(out, "    case \"k0\":");
                line(out, &format!("        {target} = {zero};"));
                line(out, "        break;");
                line(out, "    case \"k1\":");
                line(out, &format!("        Sink.Emit({one});"));
                line(out, "        break;");
                line(out, "    default:");
                line(out, "        Sink.Emit(\"other\");");
                line(out, "        break;");
                line(out, "}");
            }
            11 => {
                let flag: String = self.condition();
                let other: String = self.condition();
                line(out, &format!("bool g{n} = {flag};"));
                line(out, &format!("if (g{n} || {other})"));
                self.braced(depth, indent, out);
                line(out, &format!("Sink.Emit(g{n} ? 1 : 0);"));
            }
            _ => {
                let first: &str = self.variable();
                let second: &str = self.variable();
                let scale: u64 = 100_000 + self.below(900_000);
                line(
                    out,
                    &format!("long w{n} = (long){first} * {scale} + {second}++;"),
                );
                line(out, &format!("{target} = (int)(w{n} % 1000) + --{second};"));
                line(out, &format!("{target} %= 1000;"));
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
                writeln!(out, "{pad}Sink.Emit({shown});").expect("write to a String");
            }
            _ => {}
        }
    }

    fn method(&mut self, seed: u64) -> String {
        self.k = 1 + self.below(5);
        let mut out: String = format!(
            "        public static void Prog{seed}()\n        {{\n            List<int> t = new List<int>();\n"
        );
        for name in VARIABLES {
            writeln!(out, "            int {name} = {};", self.below(10))
                .expect("write to a String");
        }
        if self.rich {
            out.push_str("            string s = \"\";\n");
        }
        self.block(0, 3, &mut out);
        for name in VARIABLES {
            writeln!(out, "            Sink.Emit({name});").expect("write to a String");
        }
        if self.rich {
            out.push_str("            Sink.Emit(s);\n");
        }
        out.push_str("            Sink.Emit(t);\n        }\n");
        out
    }
}

fn seeds() -> impl Iterator<Item = u64> {
    (0..PROGRAMS)
        .chain(WIDE_SWEEP_SEEDS)
        .chain(RICH_FIRST..RICH_FIRST + RICH_PROGRAMS)
}

fn generated_methods() -> BTreeMap<u64, String> {
    seeds()
        .map(|seed: u64| (seed, Generator::new(seed).method(seed)))
        .collect()
}

fn gen_class(methods: &BTreeMap<u64, String>) -> String {
    let mut out: String = String::from(
        "using System;\nusing System.Collections.Generic;\nusing System.Linq;\n\nnamespace GenDiff\n{\n    public static class Gen\n    {\n",
    );
    for method in methods.values() {
        out.push_str(method);
        out.push('\n');
    }
    out.push_str("    }\n}\n");
    out
}

fn program_class() -> String {
    let mut out: String = String::from(
        "using System;\n\nnamespace GenDiff\n{\n    public static class Program\n    {\n        public static void Main()\n        {\n",
    );
    for seed in seeds() {
        writeln!(
            out,
            "            Sink.Reset();\n            try {{ Gen.Prog{seed}(); }} catch (Exception error) {{ Sink.Emit(\"threw \" + error.GetType().Name); }}\n            Console.WriteLine(\"{seed}: \" + Sink.Take());"
        )
        .expect("write to a String");
    }
    out.push_str("        }\n    }\n}\n");
    out
}

fn dotnet() -> CommandSpec {
    CommandSpec::new("dotnet", TOOL_TIMEOUT)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
        .env("MSBUILDDISABLENODEREUSE", "1")
        .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
        .env("UseSharedCompilation", "false")
}

fn run_tool(command: CommandSpec, label: &str) -> ToolOutput {
    let output: ToolOutput = tool_output(command)
        .unwrap_or_else(|error: ToolError| panic!("{label} could not start: {error}"));
    assert!(
        !output.timed_out,
        "{label} did not finish within {} seconds",
        TOOL_TIMEOUT.as_secs()
    );
    output
}

fn require_dotnet() {
    let version: ToolOutput = run_tool(dotnet().arg("--version"), "dotnet --version");
    assert!(
        version.success,
        "this test compiles the generated C# and the recovered C# with the dotnet SDK, so \
         `dotnet --version` must succeed:\n{}",
        version.stderr_text()
    );
}

struct Built {
    build: ToolOutput,
    lines: BTreeMap<u64, String>,
    hung: Option<(u64, String)>,
    assembly: PathBuf,
}

fn build_and_run(directory: &Path, gen_source: &str) -> Built {
    std::fs::write(directory.join("GenDiff.csproj"), PROJECT).expect("write project");
    std::fs::write(directory.join("Sink.cs"), SINK).expect("write sink");
    std::fs::write(directory.join("Program.cs"), program_class()).expect("write program");
    std::fs::write(directory.join("Gen.cs"), gen_source).expect("write generated class");
    let build: ToolOutput = run_tool(
        dotnet()
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory.to_path_buf()),
        "dotnet build",
    );
    let assembly: PathBuf = if build.success {
        common::built_assembly(directory, "GenDiff", &build.stdout_text())
    } else {
        directory.join("bin")
    };
    let mut lines: BTreeMap<u64, String> = BTreeMap::new();
    let mut hung: Option<(u64, String)> = None;
    if build.success {
        let run: ToolOutput = tool_output(
            CommandSpec::new("dotnet", RUN_TIMEOUT)
                .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
                .arg(assembly.clone())
                .current_dir(directory.to_path_buf()),
        )
        .unwrap_or_else(|error: ToolError| panic!("the GenDiff program could not start: {error}"));
        for line in run.stdout_text().lines() {
            if let Some((seed, rest)) = line.split_once(": ")
                && let Ok(seed) = seed.trim().parse::<u64>()
            {
                lines.insert(seed, rest.trim_end().to_owned());
            }
        }
        if !run.success {
            let reason: String = if run.timed_out {
                format!(
                    "does not terminate within {} seconds",
                    RUN_TIMEOUT.as_secs()
                )
            } else {
                format!("crashes the process: {}", run.stderr_text().trim())
            };
            hung = seeds()
                .find(|seed: &u64| !lines.contains_key(seed))
                .map(|seed: u64| (seed, reason));
        }
    }
    Built {
        build,
        lines,
        hung,
        assembly,
    }
}

fn prog_seed(method: &StructuredMethod) -> Option<u64> {
    method
        .body
        .lines()
        .find_map(|line: &str| line.trim_start().strip_prefix("public static void Prog"))
        .and_then(|rest: &str| rest.split('(').next())
        .and_then(|digits: &str| digits.trim().parse::<u64>().ok())
}

fn recovered_methods(assembly: &DecompiledAssembly) -> BTreeMap<u64, String> {
    assembly
        .methods
        .iter()
        .filter(|method: &&StructuredMethod| {
            method
                .body
                .lines()
                .next()
                .is_some_and(|line: &str| line.contains(GEN_TYPE))
        })
        .filter_map(|method: &StructuredMethod| {
            let seed: u64 = prog_seed(method)?;
            let mut text: String = String::new();
            for line in method.body.lines() {
                text.push_str("        ");
                text.push_str(line);
                text.push('\n');
            }
            Some((seed, text))
        })
        .collect()
}

fn seeds_named_by_diagnostics(build: &ToolOutput, source: &str) -> BTreeMap<u64, Vec<String>> {
    let mut starts: Vec<(usize, u64)> = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if let Some(seed) = line
            .trim_start()
            .strip_prefix("public static void Prog")
            .and_then(|rest: &str| rest.split('(').next())
            .and_then(|digits: &str| digits.trim().parse::<u64>().ok())
        {
            starts.push((index + 1, seed));
        }
    }
    let diagnostics: String = format!("{}{}", build.stdout_text(), build.stderr_text());
    let mut seeds: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for line in diagnostics.lines() {
        let Some(at) = line.find("Gen.cs(").filter(|_| line.contains(": error ")) else {
            continue;
        };
        let Some(number) = line[at + "Gen.cs(".len()..]
            .split([',', ')'])
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
fn generated_programs_reexecute_identically_on_net9() {
    require_dotnet();
    let original: BTreeMap<u64, String> = generated_methods();
    let original_scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_generated_original").expect("create scratch");
    let reference: Built = build_and_run(original_scratch.path(), &gen_class(&original));
    assert!(
        reference.build.success,
        "the generated programs must compile:\n{}{}",
        reference.build.stdout_text(),
        reference.build.stderr_text()
    );
    assert_eq!(reference.hung, None, "every generated program terminates");
    assert_eq!(
        reference.lines.len(),
        original.len(),
        "the reference run prints one line per program"
    );
    let image: Vec<u8> = std::fs::read(&reference.assembly).expect("read the built assembly");
    let decompiled: DecompiledAssembly = decompile_assembly(&image).expect("decompile");
    let recovered: BTreeMap<u64, String> = recovered_methods(&decompiled);

    let mut failures: BTreeMap<u64, String> = BTreeMap::new();
    for &seed in original.keys() {
        if !recovered.contains_key(&seed) {
            failures.insert(seed, "the decompiler emitted no Prog body".to_owned());
        }
    }
    let mut outputs: BTreeMap<u64, String> = BTreeMap::new();
    for _ in 0..MAX_REPAIR_ROUNDS {
        let candidate: BTreeMap<u64, String> = original
            .keys()
            .map(|&seed: &u64| {
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
            ScratchDir::create("disrobe_dotnet_generated_recovered").expect("create scratch");
        let built: Built = build_and_run(scratch.path(), &source);
        if let Some((seed, reason)) = built.hung {
            failures.insert(
                seed,
                format!(
                    "the recovered body {reason}:\n{}",
                    excerpt(&recovered[&seed], 3000)
                ),
            );
            continue;
        }
        if built.build.success {
            outputs = built.lines;
            break;
        }
        let named: BTreeMap<u64, Vec<String>> = seeds_named_by_diagnostics(&built.build, &source);
        assert!(
            !named.is_empty(),
            "the recovered class failed to compile without naming a Prog method:\n{}",
            excerpt(&built.build.stdout_text(), 4000)
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
    for &seed in original.keys() {
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
            let refusal: &str = why
                .lines()
                .find_map(|line: &str| line.trim_start().strip_prefix("// disrobe: "))
                .unwrap_or_default();
            format!("  seed {seed}: {reason} {}", excerpt(refusal, 160))
        })
        .collect();
    assert!(
        regressed.is_empty() && fixed.is_empty(),
        "{} of {} generated C# programs did not recover to the same behaviour; the \
         divergent set must equal KNOWN_DIVERGENT exactly, which only ever shrinks. Newly \
         divergent: {regressed:?}. Now recovered, remove from KNOWN_DIVERGENT: {fixed:?}.\n{}\n{}",
        failures.len(),
        original.len(),
        summary.join("\n"),
        shown.join("\n=====\n")
    );
}

#[test]
fn the_csharp_generator_is_deterministic_and_varied() {
    let first: String = Generator::new(7).method(7);
    assert_eq!(first, Generator::new(7).method(7));
    let methods: BTreeMap<u64, String> = generated_methods();
    let distinct: BTreeSet<&String> = methods.values().collect();
    assert_eq!(distinct.len(), methods.len());
    let all: String = methods.values().cloned().collect();
    for shape in [
        "while (",
        "do\n",
        "for (int i",
        "else if (",
        "else\n",
        "break;",
        "continue;",
        "catch (DivideByZeroException)",
        "finally\n",
        "switch (",
        "default:",
        " ? ",
        "t.Contains(",
        "Math.Max(",
        " switch { 0 => ",
        "Func<int, int> f",
        ".Where(x => x > ",
        "when (",
        "int? m",
        "foreach (int x",
        "checked(",
        "int L",
        "case \"k0\":",
        "bool g",
        "long w",
        "s = $\"",
    ] {
        assert!(all.contains(shape), "the corpus never generates `{shape}`");
    }
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    require_dotnet();
    let method: String = "        public static void Prog0()\n        {\n            List<int> t = new List<int>();\n            int a = 3;\n            int b = 4;\n            Sink.Emit(a + b);\n            Sink.Emit(t);\n        }\n".to_owned();
    let mutated: String = method.replacen("a + b", "a - b", 1);
    let mut programs: BTreeMap<u64, String> = BTreeMap::new();
    for seed in seeds() {
        let text: String = method.replace("Prog0", &format!("Prog{seed}"));
        programs.insert(seed, text);
    }
    let mut mutant: BTreeMap<u64, String> = programs.clone();
    mutant.insert(0, mutated);
    let original_scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_generated_control").expect("create scratch");
    let original: Built = build_and_run(original_scratch.path(), &gen_class(&programs));
    let mutant_scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_generated_mutant").expect("create scratch");
    let changed: Built = build_and_run(mutant_scratch.path(), &gen_class(&mutant));
    assert!(original.build.success && changed.build.success);
    assert_ne!(original.lines.get(&0), changed.lines.get(&0));
    assert_eq!(original.lines.get(&1), changed.lines.get(&1));
}
