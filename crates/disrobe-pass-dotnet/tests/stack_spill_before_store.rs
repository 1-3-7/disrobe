#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const PROBE_TYPE: &str = "StackSpill.Probe";
const SPILL_PREFIX: &str = "__disrobe_spill_";
const TOOL_TIMEOUT: Duration = Duration::from_mins(10);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const PROBES: [(&str, bool); 8] = [
    ("Concat", true),
    ("ByRef", true),
    ("Argument", true),
    ("AfterConditional", true),
    ("InsideConditional", false),
    ("StaticField", true),
    ("Element", true),
    ("Untouched", false),
];
const EXPECTED_LINES: [(&str, bool); 10] = [
    ("8,40", true),
    ("809", true),
    ("607", true),
    ("8,40", true),
    ("8,4", true),
    ("809", false),
    ("801", false),
    ("509", true),
    ("309", true),
    ("403", false),
];

fn fixture(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/stack_spill");
    path.push(name);
    path
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture(name))
        .unwrap_or_else(|error: std::io::Error| panic!("read fixture {name}: {error}"))
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

fn dotnet() -> CommandSpec {
    CommandSpec::new("dotnet", TOOL_TIMEOUT)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
        .env("MSBUILDDISABLENODEREUSE", "1")
        .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
        .env("UseSharedCompilation", "false")
}

fn require_dotnet() {
    let version: ToolOutput = run_tool(dotnet().arg("--version"), "dotnet --version");
    assert!(
        version.success,
        "this test builds its fixture and the recovered C# with the dotnet SDK recorded in \
         .developer/TOOLS.md, so `dotnet --version` must succeed:\n{}",
        version.stderr_text()
    );
}

struct Program {
    build: ToolOutput,
    run: Option<ToolOutput>,
    assembly: PathBuf,
}

fn build_and_run(directory: &Path, probe_source: &str) -> Program {
    std::fs::write(
        directory.join("StackSpill.csproj"),
        read_fixture("StackSpill.csproj"),
    )
    .expect("write project");
    std::fs::write(directory.join("Ledger.cs"), read_fixture("Ledger.cs")).expect("write ledger");
    std::fs::write(directory.join("Probe.cs"), probe_source).expect("write probe");
    let build: ToolOutput = run_tool(
        dotnet()
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory.to_path_buf()),
        "dotnet build",
    );
    let assembly: PathBuf = directory.join("bin/Release/net8.0/StackSpill.dll");
    let run: Option<ToolOutput> = build.success.then(|| {
        run_tool(
            dotnet()
                .arg(assembly.clone())
                .current_dir(directory.to_path_buf()),
            "the StackSpill program",
        )
    });
    Program {
        build,
        run,
        assembly,
    }
}

fn expect_run(program: &Program, label: &str, source: &str) -> String {
    let Some(run) = program.run.as_ref() else {
        panic!(
            "{label} did not compile:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
            program.build.stdout_text(),
            program.build.stderr_text()
        );
    };
    assert!(
        run.success,
        "{label} failed at run time:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        run.stdout_text(),
        run.stderr_text()
    );
    run.stdout_text().replace("\r\n", "\n")
}

fn method_name(method: &StructuredMethod) -> Option<&str> {
    let header: &str = method
        .body
        .lines()
        .find(|line: &&str| line.trim_start().starts_with("public static "))?;
    let before_parameters: &str = header.split('(').next()?;
    before_parameters.rsplit(' ').next()
}

fn probe_methods(assembly: &DecompiledAssembly) -> Vec<&StructuredMethod> {
    assembly
        .methods
        .iter()
        .filter(|method: &&StructuredMethod| {
            method
                .body
                .lines()
                .next()
                .is_some_and(|line: &str| line.contains(PROBE_TYPE))
        })
        .collect()
}

fn recovered_probe_source(methods: &[&StructuredMethod]) -> String {
    let mut source: String =
        "using System;\n\nnamespace StackSpill\n{\n    public static partial class Probe\n    {\n"
            .to_owned();
    for method in methods {
        for line in method.body.lines() {
            source.push_str("        ");
            source.push_str(line);
            source.push('\n');
        }
        source.push('\n');
    }
    source.push_str("    }\n}\n");
    source
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn replace_identifier(text: &str, name: &str, replacement: &str) -> String {
    let mut output: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(at) = rest.find(name) {
        let end: usize = at + name.len();
        let before_is_identifier: bool = rest[..at].bytes().last().is_some_and(is_identifier_byte);
        let after_is_identifier: bool = rest
            .as_bytes()
            .get(end)
            .copied()
            .is_some_and(is_identifier_byte);
        output.push_str(&rest[..at]);
        if before_is_identifier || after_is_identifier {
            output.push_str(name);
        } else {
            output.push_str(replacement);
        }
        rest = &rest[end..];
    }
    output.push_str(rest);
    output
}

fn inline_spills(source: &str) -> (String, usize) {
    let mut kept: Vec<String> = Vec::new();
    let mut spills: Vec<(String, String)> = Vec::new();
    for line in source.lines() {
        let declaration: Option<(&str, &str)> = line
            .trim_start()
            .strip_prefix("var ")
            .filter(|rest: &&str| rest.starts_with(SPILL_PREFIX))
            .and_then(|rest: &str| rest.strip_suffix(';'))
            .and_then(|rest: &str| rest.split_once(" = "));
        match declaration {
            Some((name, value)) => spills.push((name.to_owned(), value.to_owned())),
            None => kept.push(line.to_owned()),
        }
    }
    let mut inlined: String = kept.join("\n");
    inlined.push('\n');
    for (name, value) in spills.iter().rev() {
        inlined = replace_identifier(&inlined, name, &format!("({value})"));
    }
    (inlined, spills.len())
}

#[test]
fn pending_reads_are_spilled_before_a_store_changes_their_location() {
    require_dotnet();
    let original_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_stack_spill_original")
            .expect("create original scratch directory");
    let original_source: String = read_fixture("Probe.cs");
    let original: Program = build_and_run(original_scratch.path(), &original_source);
    let expected: String = expect_run(&original, "the original fixture", &original_source);
    let reference: Vec<&str> = EXPECTED_LINES
        .iter()
        .map(|(line, _): &(&str, bool)| *line)
        .collect();
    assert_eq!(
        expected.lines().collect::<Vec<&str>>(),
        reference,
        "the original program is the reference and must print the values C# defines"
    );

    let image: Vec<u8> = std::fs::read(&original.assembly).expect("read built fixture assembly");
    let assembly: DecompiledAssembly = decompile_assembly(&image).expect("decompile fixture");
    let methods: Vec<&StructuredMethod> = probe_methods(&assembly);
    let recovered_source: String = recovered_probe_source(&methods);
    let recovered_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_stack_spill_recovered")
            .expect("create recovered scratch directory");
    let recovered: Program = build_and_run(recovered_scratch.path(), &recovered_source);
    let actual: String = expect_run(&recovered, "the recovered probes", &recovered_source);
    assert_eq!(
        actual, expected,
        "the recovered probes must print exactly what the original prints:
{recovered_source}"
    );

    let names: Vec<&str> = methods
        .iter()
        .filter_map(|method: &&StructuredMethod| method_name(method))
        .collect();
    for (probe, spills) in PROBES {
        let Some(method) = methods
            .iter()
            .find(|method: &&&StructuredMethod| method_name(method) == Some(probe))
        else {
            panic!("the decompiled assembly must carry Probe.{probe}; found {names:?}");
        };
        assert_eq!(
            method.body.contains(SPILL_PREFIX),
            spills,
            "Probe.{probe} must spill exactly when a store changes a location a pending              expression reads:
{}",
            method.body
        );
    }

    let (mutated_source, inlined): (String, usize) = inline_spills(&recovered_source);
    let spilling_probes: usize = PROBES
        .iter()
        .filter(|(_, spills): &&(&str, bool)| *spills)
        .count();
    assert!(
        inlined >= spilling_probes,
        "the mutation control must inline at least one spill per spilling probe, inlined          {inlined}:
{recovered_source}"
    );
    let mutated_scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_stack_spill_mutated")
            .expect("create mutated scratch directory");
    let mutated: Program = build_and_run(mutated_scratch.path(), &mutated_source);
    let mutated_output: String = expect_run(&mutated, "the spill-inlined probes", &mutated_source);
    let mutated_lines: Vec<&str> = mutated_output.lines().collect();
    assert_eq!(
        mutated_lines.len(),
        EXPECTED_LINES.len(),
        "the spill-inlined probes must print one line per probe call:
{mutated_output}"
    );
    let misgraded: Vec<(usize, &str, &str)> = EXPECTED_LINES
        .iter()
        .zip(mutated_lines.iter())
        .enumerate()
        .filter(
            |(_, ((want, depends), got)): &(usize, (&(&str, bool), &&str))| {
                (want == *got) == *depends
            },
        )
        .map(|(index, ((want, _), got)): (usize, (&(&str, bool), &&str))| (index, *want, *got))
        .collect();
    assert!(
        misgraded.is_empty(),
        "inlining the spills must change exactly the lines whose value depends on a spill,          mismatched (line, expected, mutated) {misgraded:?}:
{mutated_output}
source:
{mutated_source}"
    );
}
