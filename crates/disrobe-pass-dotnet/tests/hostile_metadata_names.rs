#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::source_text::is_unsafe_in_source;
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const ORIGINAL_NAME: &[u8] = b"NegatedConditions\0";
const HOSTILE_NAME: &[u8] = b"Ne\nt\xe2\x80\xaeConditions\0";

fn fixture() -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/unsigned_overflow/UnsignedOverflow.dll");
    std::fs::read(path).expect("read the unsigned_overflow fixture")
}

fn with_hostile_type_name(mut bytes: Vec<u8>) -> Vec<u8> {
    assert_eq!(ORIGINAL_NAME.len(), HOSTILE_NAME.len());
    let at: usize = bytes
        .windows(ORIGINAL_NAME.len())
        .position(|window: &[u8]| window == ORIGINAL_NAME)
        .expect("the #Strings heap holds the type name");
    bytes[at..at + HOSTILE_NAME.len()].copy_from_slice(HOSTILE_NAME);
    bytes
}

fn emitted_text(asm: &DecompiledAssembly) -> String {
    asm.methods
        .iter()
        .map(|method: &StructuredMethod| method.body.as_str())
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn a_type_name_with_a_newline_and_a_bidi_override_stays_on_its_line() {
    let original: DecompiledAssembly = decompile_assembly(&fixture()).expect("decompile original");
    let hostile: DecompiledAssembly =
        decompile_assembly(&with_hostile_type_name(fixture())).expect("decompile patched");
    assert_eq!(
        original.methods.len(),
        hostile.methods.len(),
        "renaming one type must not add or drop methods"
    );
    let text: String = emitted_text(&hostile);
    assert!(
        !text.contains('\u{202e}'),
        "the right-to-left override reached the emitted C#"
    );
    let original_lines: usize = emitted_text(&original).lines().count();
    assert_eq!(
        text.lines().count(),
        original_lines,
        "a newline in the type name added a line to the emitted C#:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line: &str| line.contains("Ne") && line.contains("Conditions")),
        "the renamed type is still named, escaped, on one line:\n{text}"
    );
}

const TOOL_TIMEOUT: Duration = Duration::from_mins(10);
const TOOL_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const RIGHT_TO_LEFT_OVERRIDE: [u8; 3] = [0xE2, 0x80, 0xAE];
const LINE_SEPARATOR: [u8; 3] = [0xE2, 0x80, 0xA8];
const OVERRIDE_MARKER: [u8; 3] = *b"Q7Z";
const SEPARATOR_MARKER: [u8; 3] = *b"W7Z";

const PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>Hostile</AssemblyName>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
"#;

const SOURCE: &str = r#"namespace Hostile
{
    public static class BoxQ7Z
    {
        public static int FieldW7Z = 7;

        public static string RunQ7Z(int valueW7Z)
        {
            return "ok" + valueW7Z + FieldW7Z;
        }

        public static void Main()
        {
            System.Console.WriteLine(RunQ7Z(1));
        }
    }
}
"#;

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

fn build(directory: &Path, source: &str) -> ToolOutput {
    std::fs::write(directory.join("Hostile.csproj"), PROJECT).expect("write project");
    std::fs::write(directory.join("Program.cs"), source).expect("write source");
    run_tool(
        dotnet()
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory.to_path_buf()),
        "dotnet build",
    )
}

fn replace_marker(image: &mut [u8], marker: [u8; 3], replacement: [u8; 3]) -> usize {
    let mut replaced: usize = 0;
    let mut at: usize = 0;
    while at + marker.len() <= image.len() {
        if image[at..at + marker.len()] == marker {
            image[at..at + marker.len()].copy_from_slice(&replacement);
            replaced += 1;
            at += marker.len();
        } else {
            at += 1;
        }
    }
    replaced
}

fn hostile_image() -> Vec<u8> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_hostile_names_original")
            .expect("create scratch directory");
    let built: ToolOutput = build(scratch.path(), SOURCE);
    assert!(
        built.success,
        "the fixture does not compile:\nstdout:\n{}\nstderr:\n{}",
        built.stdout_text(),
        built.stderr_text()
    );
    let assembly: PathBuf = common::built_assembly(scratch.path(), "Hostile", &built.stdout_text());
    let mut image: Vec<u8> = std::fs::read(&assembly).expect("read the built assembly");
    let overrides: usize = replace_marker(&mut image, OVERRIDE_MARKER, RIGHT_TO_LEFT_OVERRIDE);
    let separators: usize = replace_marker(&mut image, SEPARATOR_MARKER, LINE_SEPARATOR);
    assert!(
        overrides >= 2 && separators >= 2,
        "the #Strings heap must carry the type, method, field and parameter names the markers \
         stand in for; replaced {overrides} override and {separators} separator markers"
    );
    image
}

fn recovered_source(assembly: &DecompiledAssembly) -> String {
    let mut source: String =
        "namespace Recovered\n{\n    public static partial class Shell\n    {\n".to_owned();
    for method in &assembly.methods {
        let method: &StructuredMethod = method;
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

fn syntax_errors(output: &ToolOutput) -> Vec<String> {
    output
        .stdout_text()
        .lines()
        .chain(output.stderr_text().lines())
        .filter(|line: &&str| {
            line.split("error CS")
                .nth(1)
                .and_then(|rest: &str| rest.get(..4))
                .and_then(|code: &str| code.parse::<u32>().ok())
                .is_some_and(|code: u32| (1000..=1060).contains(&code))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn format_and_line_separator_characters_in_metadata_names_never_reach_the_csharp_raw() {
    let version: ToolOutput = run_tool(dotnet().arg("--version"), "dotnet --version");
    assert!(
        version.success,
        "this test builds its fixture and the recovered C# with the dotnet SDK, so `dotnet \
         --version` must succeed:\n{}",
        version.stderr_text()
    );
    let image: Vec<u8> = hostile_image();
    let assembly: DecompiledAssembly =
        decompile_assembly(&image).expect("the patched assembly still decompiles");
    let source: String = recovered_source(&assembly);
    assert!(
        source.contains("Box") && source.contains("Run"),
        "the recovered source must name the hostile type and method:\n{source}"
    );
    let raw: Vec<char> = source
        .chars()
        .filter(|c: &char| *c != '\n' && *c != '\r' && is_unsafe_in_source(*c))
        .collect();
    assert!(
        raw.is_empty(),
        "the recovered C# carries raw control or format characters {raw:?}, which reorder or \
         break the text a reviewer reads:\n{source}"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_hostile_names_recovered")
            .expect("create scratch directory");
    let rebuilt: ToolOutput = build(scratch.path(), &source);
    let errors: Vec<String> = syntax_errors(&rebuilt);
    assert!(
        errors.is_empty(),
        "csc reports syntax errors in the recovered C#, so an escaped name is not valid C#:\n{}\n\
         source:\n{source}",
        errors.join("\n")
    );
}
