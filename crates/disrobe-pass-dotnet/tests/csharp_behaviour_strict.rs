#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const FIXTURES: [&str; 11] = [
    "BoolFlags",
    "CachedLambdaInLoop",
    "CapturedFuncInvoke",
    "CapturedTernaryAnd",
    "ClosureLinq",
    "FilterWithFlags",
    "InterpolatedStrings",
    "LocalFunctionByRef",
    "LiteralSafeClosure",
    "NullableTernary",
    "SharedClosure",
];
const NAMESPACE: &str = "Behaviour";
const SECTION: &str = "== ";
const MUTATION_FIXTURE: &str = "CapturedFuncInvoke";
const TOOL_TIMEOUT: Duration = Duration::from_mins(10);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

const PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <AssemblyName>Behaviour</AssemblyName>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <Deterministic>true</Deterministic>
    <Optimize>true</Optimize>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
"#;

fn fixture_source(name: &str) -> String {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/behaviour");
    path.push(format!("{name}.cs"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()))
}

fn program() -> String {
    let mut out: String = format!(
        "using System;\n\nnamespace {NAMESPACE}\n{{\n    public static class Program\n    {{\n        public static void Main()\n        {{\n"
    );
    for name in FIXTURES {
        writeln!(
            out,
            "            Console.WriteLine(\"{SECTION}{name}\");\n            try {{ {name}.Run(); }} catch (Exception error) {{ Console.WriteLine(\"threw \" + error.GetType().Name); }}"
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
        "this test compiles the fixtures and the recovered C# with the dotnet SDK, so \
         `dotnet --version` must succeed:\n{}",
        version.stderr_text()
    );
}

fn build(directory: &Path, sources: &BTreeMap<String, String>) -> Result<PathBuf, ToolOutput> {
    std::fs::write(directory.join("Behaviour.csproj"), PROJECT).expect("write project");
    std::fs::write(directory.join("Program.cs"), program()).expect("write program");
    for (name, source) in sources {
        std::fs::write(directory.join(format!("{name}.cs")), source).expect("write fixture");
    }
    let build: ToolOutput = run_tool(
        dotnet()
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory.to_path_buf()),
        "dotnet build",
    );
    if build.success {
        Ok(common::built_assembly(
            directory,
            "Behaviour",
            &build.stdout_text(),
        ))
    } else {
        Err(build)
    }
}

fn run(directory: &Path, assembly: &Path, label: &str) -> BTreeMap<String, String> {
    let run: ToolOutput = run_tool(
        dotnet()
            .arg(assembly.to_path_buf())
            .current_dir(directory.to_path_buf()),
        label,
    );
    assert!(
        run.success,
        "{label} failed at run time:\n{}{}",
        run.stdout_text(),
        run.stderr_text()
    );
    let mut sections: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in run.stdout_text().replace("\r\n", "\n").lines() {
        if let Some(name) = line.strip_prefix(SECTION) {
            current = Some(name.to_owned());
            sections.insert(name.to_owned(), String::new());
        } else if let Some(name) = &current {
            let text: &mut String = sections.entry(name.clone()).or_default();
            text.push_str(line);
            text.push('\n');
        }
    }
    sections
}

fn build_and_run(
    directory: &Path,
    sources: &BTreeMap<String, String>,
    label: &str,
) -> (PathBuf, BTreeMap<String, String>) {
    let assembly: PathBuf = build(directory, sources).unwrap_or_else(|output: ToolOutput| {
        panic!(
            "{label} must compile:\n{}{}\n{}",
            output.stdout_text(),
            output.stderr_text(),
            sources
                .values()
                .cloned()
                .collect::<Vec<String>>()
                .join("\n")
        )
    });
    let sections: BTreeMap<String, String> = run(directory, &assembly, label);
    (assembly, sections)
}

fn fixtures_named_by_diagnostics(output: &ToolOutput) -> Vec<String> {
    let diagnostics: String = format!("{}{}", output.stdout_text(), output.stderr_text());
    FIXTURES
        .iter()
        .filter(|name: &&&str| {
            diagnostics.lines().any(|line: &str| {
                line.contains(": error ") && line.contains(&format!("{name}.cs("))
            })
        })
        .map(|name: &&str| (*name).to_owned())
        .collect()
}

fn original_sources() -> BTreeMap<String, String> {
    FIXTURES
        .iter()
        .map(|name: &&str| ((*name).to_owned(), fixture_source(name)))
        .collect()
}

fn is_user_method(method: &StructuredMethod, name: &str) -> bool {
    let mut lines = method.body.lines();
    let owner: &str = lines.next().unwrap_or_default().trim();
    let signature: &str = lines.next().unwrap_or_default();
    owner == format!("// {NAMESPACE}.{name}")
        && !signature.contains('<')
        && !signature.contains(".ctor")
        && !signature.contains(".cctor")
}

fn recovered_sources(assembly: &DecompiledAssembly) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for name in FIXTURES {
        let mut source: String = format!(
            "using System;\nusing System.Collections.Generic;\nusing System.Linq;\n\nnamespace {NAMESPACE}\n{{\n    public static class {name}\n    {{\n"
        );
        let methods: Vec<&StructuredMethod> = assembly
            .methods
            .iter()
            .filter(|m: &&StructuredMethod| is_user_method(m, name))
            .collect();
        assert!(
            !methods.is_empty(),
            "the decompiler emitted no method of {NAMESPACE}.{name}"
        );
        for method in methods {
            for line in method.body.lines() {
                source.push_str("        ");
                source.push_str(line);
                source.push('\n');
            }
            source.push('\n');
        }
        source.push_str("    }\n}\n");
        out.insert(name.to_owned(), source);
    }
    out
}

fn reference_and_recovery() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    require_dotnet();
    let original_scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_behaviour_original").expect("create scratch");
    let (assembly, sections): (PathBuf, BTreeMap<String, String>) = build_and_run(
        original_scratch.path(),
        &original_sources(),
        "the original fixtures",
    );
    let image: Vec<u8> = std::fs::read(&assembly).expect("read the built assembly");
    let decompiled: DecompiledAssembly = decompile_assembly(&image).expect("decompile");
    (sections, recovered_sources(&decompiled))
}

#[test]
fn every_fixture_recovers_to_identical_behaviour() {
    let (reference, recovered): (BTreeMap<String, String>, BTreeMap<String, String>) =
        reference_and_recovery();
    for name in FIXTURES {
        let output: &str = reference.get(name).map_or("", String::as_str);
        assert!(
            !output.is_empty() && !output.contains("threw "),
            "the original {name} must print its values without throwing:\n{output}"
        );
    }
    let originals: BTreeMap<String, String> = original_sources();
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    for (name, source) in &recovered {
        if source.contains("disrobe:") {
            failures.insert(name.clone(), format!("refused or left plumbing:\n{source}"));
        }
    }
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_behaviour_recovered").expect("create scratch");
    let mut outputs: Option<BTreeMap<String, String>> = None;
    for _ in 0..=FIXTURES.len() {
        let candidate: BTreeMap<String, String> = recovered
            .iter()
            .map(|(name, source): (&String, &String)| {
                let chosen: &String = if failures.contains_key(name) {
                    &originals[name]
                } else {
                    source
                };
                (name.clone(), chosen.clone())
            })
            .collect();
        match build(scratch.path(), &candidate) {
            Ok(assembly) => {
                outputs = Some(run(scratch.path(), &assembly, "the recovered fixtures"));
                break;
            }
            Err(output) => {
                let named: Vec<String> = fixtures_named_by_diagnostics(&output);
                assert!(
                    named
                        .iter()
                        .any(|name: &String| !failures.contains_key(name)),
                    "the recovered fixtures failed to compile without naming a new fixture:\n{}",
                    output.stdout_text()
                );
                for name in named {
                    let source: &str = recovered.get(&name).map_or("", String::as_str);
                    failures
                        .entry(name)
                        .or_insert_with(|| format!("does not compile:\n{source}"));
                }
            }
        }
    }
    let outputs: BTreeMap<String, String> =
        outputs.expect("a recovered build compiles once failing fixtures are set aside");
    for name in FIXTURES {
        if failures.contains_key(name) {
            continue;
        }
        if outputs.get(name) != reference.get(name) {
            failures.insert(
                name.to_owned(),
                format!(
                    "printed {:?}, the original printed {:?}\n{}",
                    outputs.get(name),
                    reference.get(name),
                    recovered.get(name).map_or("", String::as_str)
                ),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "every fixture must re-execute exactly like the original; diverged: {:?}\n{}",
        failures.keys().collect::<Vec<&String>>(),
        failures
            .iter()
            .map(|(name, why): (&String, &String)| format!("{name}: {why}"))
            .collect::<Vec<String>>()
            .join("\n=====\n")
    );
}

#[test]
fn a_recovery_with_one_changed_operator_is_caught() {
    let (reference, mut recovered): (BTreeMap<String, String>, BTreeMap<String, String>) =
        reference_and_recovery();
    let source: &mut String = recovered
        .get_mut(MUTATION_FIXTURE)
        .expect("the mutation fixture is recovered");
    let mutated: String = source.replacen(" + 3)", " + 4)", 1);
    assert_ne!(
        &mutated, source,
        "the mutation control must change the recovered {MUTATION_FIXTURE}"
    );
    *source = mutated;
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_behaviour_mutant").expect("create scratch");
    let (_, sections): (PathBuf, BTreeMap<String, String>) =
        build_and_run(scratch.path(), &recovered, "the mutated recovery");
    assert_ne!(
        sections.get(MUTATION_FIXTURE),
        reference.get(MUTATION_FIXTURE),
        "changing one operator in the recovered {MUTATION_FIXTURE} must change what it prints"
    );
    for name in FIXTURES
        .iter()
        .filter(|name: &&&str| **name != MUTATION_FIXTURE)
    {
        assert_eq!(
            sections.get(*name),
            reference.get(*name),
            "the mutation of {MUTATION_FIXTURE} must leave {name} untouched"
        );
    }
}

#[test]
fn display_class_lowering_preserves_literal_text() {
    let (reference, recovered): (BTreeMap<String, String>, BTreeMap<String, String>) =
        reference_and_recovery();
    let source: String = recovered
        .get("LiteralSafeClosure")
        .cloned()
        .expect("LiteralSafeClosure is recovered");
    assert!(
        !source.contains("disrobe:"),
        "literal-safety recovery must not pass through a refusal comment:\n{source}"
    );
    assert!(
        source.contains("local0 this.field <Run>b__0"),
        "display-class lowering must not rewrite names inside a C# string literal:\n{source}"
    );
    let mut candidate: BTreeMap<String, String> = original_sources();
    candidate.insert("LiteralSafeClosure".to_owned(), source);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_dotnet_literal_safe_closure").expect("create scratch");
    let (_, sections): (PathBuf, BTreeMap<String, String>) = build_and_run(
        scratch.path(),
        &candidate,
        "the recovered literal-safe closure with authored peers",
    );
    assert_eq!(
        sections.get("LiteralSafeClosure"),
        reference.get("LiteralSafeClosure"),
        "the literal-safe closure must re-execute exactly like its authored original"
    );
}
