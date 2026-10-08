#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_dotnet::csharp_project::{
    CSharpProject, emit_csharp_project, member_identifier, type_identifier,
};
use disrobe_pass_dotnet::decompile::{Decompiled, decompile_assembly_detailed};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::signature::{TypeSig, TypeSigOrVoid};
use disrobe_pass_dotnet::structurize::TargetLang;
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const TOOL_TIMEOUT: Duration = Duration::from_mins(10);
const TOOL_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const FRAMEWORK_DIR: &str = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319";
const NETCORE_TFM: &str = "net9.0";
const MUTATION_FIXTURE: &str = "confuserex-gauntlet";
const MUTATION_FROM: &str = "\"gauntlet-build-v1\"";
const MUTATION_TO: &str = "\"gauntlet-build-v2\"";

const FULLY_RECOVERED: &[&str] = &[
    "confuserex-gauntlet",
    "bitmono-gauntlet",
    "obfuscar-gauntlet",
    "helloapp-confuserex2",
    "helloapp-obfuscar",
    "confuserex1-gauntlet-minimum",
    "confuserex1-gauntlet-normal",
    "confuserex1-gauntlet-aggressive",
    "confuserex1-gauntlet-maximum",
    "confuserex1-behaviour-minimum",
    "bitmono45-gauntlet-minimal",
    "bitmono45-gauntlet-balanced",
    "bitmono45-gauntlet-maximum",
    "bitmono45-behaviour-minimal",
    "bitmono45-behaviour-balanced",
    "bitmono45-behaviour-maximum",
];

const RESIDUAL: &[(&str, &str)] = &[
    ("edgecases-confuserex2", "control-flow flattening"),
    ("edgecases-obfuscar", "does not compile"),
    (
        "confuserex1-behaviour-normal",
        "the switch dispatcher lies inside an exception region",
    ),
    (
        "confuserex1-behaviour-aggressive",
        "the switch dispatcher lies inside an exception region",
    ),
    (
        "confuserex1-behaviour-maximum",
        "the switch dispatcher lies inside an exception region",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reference {
    AuthoredNet48Exe(&'static str),
    AuthoredNetCoreConsole(&'static str),
    CleanLibrary(&'static str),
    CommittedNet48Exe(&'static str),
    CommittedNetCoreDll(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Driver {
    None,
    Authored(&'static str),
    SignatureMatched,
}

#[derive(Debug, Clone, Copy)]
struct Fixture {
    name: &'static str,
    protected: &'static str,
    reference: Reference,
    driver: Driver,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "confuserex-gauntlet",
        protected: "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.confuserex2.exe",
        reference: Reference::AuthoredNet48Exe(
            "../../corpus/dotnet/confuserex/gauntlet/GauntletSample.cs",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono-gauntlet",
        protected: "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll",
        reference: Reference::AuthoredNetCoreConsole(
            "../../corpus/dotnet/obfuscators/bitmono/gauntlet/clean_original.cs",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "obfuscar-gauntlet",
        protected: "../../corpus/dotnet/obfuscators/obfuscar/gauntlet/GauntletSample.obfuscar.dll",
        reference: Reference::AuthoredNetCoreConsole(
            "../../corpus/dotnet/obfuscators/obfuscar/gauntlet/clean_original.cs",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "helloapp-confuserex2",
        protected: "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll",
        reference: Reference::CleanLibrary("../../corpus/dotnet/HelloAppLegacy.dll"),
        driver: Driver::Authored(HELLOAPP_DRIVER),
    },
    Fixture {
        name: "helloapp-obfuscar",
        protected: "../../corpus/dotnet/HelloAppLegacy.obfuscar.dll",
        reference: Reference::CleanLibrary("../../corpus/dotnet/HelloAppLegacy.dll"),
        driver: Driver::SignatureMatched,
    },
    Fixture {
        name: "edgecases-confuserex2",
        protected: "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll",
        reference: Reference::CleanLibrary("../../corpus/dotnet/megafile/EdgeCases.baseline.dll"),
        driver: Driver::Authored(EDGECASES_DRIVER),
    },
    Fixture {
        name: "confuserex1-gauntlet-minimum",
        protected: "../../corpus/dotnet/confuserex/real/GauntletSample.minimum.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/GauntletSample.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-gauntlet-normal",
        protected: "../../corpus/dotnet/confuserex/real/GauntletSample.normal.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/GauntletSample.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-gauntlet-aggressive",
        protected: "../../corpus/dotnet/confuserex/real/GauntletSample.aggressive.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/GauntletSample.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-gauntlet-maximum",
        protected: "../../corpus/dotnet/confuserex/real/GauntletSample.maximum.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/GauntletSample.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-behaviour-minimum",
        protected: "../../corpus/dotnet/confuserex/real/BehaviourSuite.minimum.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/BehaviourSuite.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-behaviour-normal",
        protected: "../../corpus/dotnet/confuserex/real/BehaviourSuite.normal.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/BehaviourSuite.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-behaviour-aggressive",
        protected: "../../corpus/dotnet/confuserex/real/BehaviourSuite.aggressive.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/BehaviourSuite.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "confuserex1-behaviour-maximum",
        protected: "../../corpus/dotnet/confuserex/real/BehaviourSuite.maximum.exe",
        reference: Reference::CommittedNet48Exe(
            "../../corpus/dotnet/confuserex/real/BehaviourSuite.clean.exe",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-gauntlet-minimal",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.Minimal.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-gauntlet-balanced",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.Balanced.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-gauntlet-maximum",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.Maximum.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-behaviour-minimal",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.Minimal.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-behaviour-balanced",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.Balanced.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "bitmono45-behaviour-maximum",
        protected: "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.Maximum.dll",
        reference: Reference::CommittedNetCoreDll(
            "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.clean.dll",
        ),
        driver: Driver::None,
    },
    Fixture {
        name: "edgecases-obfuscar",
        protected: "../../corpus/dotnet/megafile/EdgeCases.obfuscar.dll",
        reference: Reference::CleanLibrary("../../corpus/dotnet/megafile/EdgeCases.baseline.dll"),
        driver: Driver::SignatureMatched,
    },
];

const HELLOAPP_DRIVER: &str = r#"public static class DisrobeDriver
{
    public static int Main()
    {
        System.Console.WriteLine(HelloAppLegacy.Program.Greeting("disrobe"));
        System.Console.WriteLine(HelloAppLegacy.Program.Add(2, 40));
        System.Console.WriteLine(HelloAppLegacy.Program.Add(-7, 7));
        return 3;
    }
}
"#;

const EDGECASES_DRIVER: &str = r#"public static class DisrobeDriver
{
    static void Try(string label, System.Func<object> call)
    {
        try
        {
            object value = call();
            System.Console.WriteLine(label + " = " + (value == null ? "null" : value.ToString()));
        }
        catch (System.Exception error)
        {
            System.Console.WriteLine(label + " threw " + error.GetType().Name);
        }
    }

    public static int Main()
    {
        foreach (int score in new int[] { -5, 0, 7, 50, 500, 5000 })
        {
            Try("Bucket(" + score + ")", () => EdgeCases.PatternKit.Bucket(score));
        }
        Try("Classify(null)", () => EdgeCases.PatternKit.Classify(null));
        Try("Classify(5)", () => EdgeCases.PatternKit.Classify(5));
        Try("Classify(-3)", () => EdgeCases.PatternKit.Classify(-3));
        Try("Classify(0)", () => EdgeCases.PatternKit.Classify(0));
        Try("Classify(hi)", () => EdgeCases.PatternKit.Classify("hi"));
        Try("Classify(long)", () => EdgeCases.PatternKit.Classify("a long string here"));
        Try("Classify(empty-array)", () => EdgeCases.PatternKit.Classify(new int[0]));
        Try("Classify(pair)", () => EdgeCases.PatternKit.Classify(new int[] { 1, 2 }));
        Try("Repeat", () => EdgeCases.StringPlayground.Repeat('x', 3));
        Try("Parse", () => string.Join(";", EdgeCases.ConfigParser.Parse("a=1\n# c\nb = 2\nbad")));
        Try("SafeDivide(10,2)", () => EdgeCases.ExceptionPlayground.SafeDivide(10, 2));
        Try("SafeDivide(1,0)", () => EdgeCases.ExceptionPlayground.SafeDivide(1, 0));
        Try("SafeDivide(min,-1)", () => EdgeCases.ExceptionPlayground.SafeDivide(int.MinValue, -1));
        return 0;
    }
}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    stdout: String,
    exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Full,
    Residual(String),
}

struct Tools {
    csc: PathBuf,
    framework: PathBuf,
}

fn manifest(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = manifest(rel);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!("fixture {} must be present: {error}", path.display())
    })
}

fn dotnet() -> CommandSpec {
    CommandSpec::new("dotnet", TOOL_TIMEOUT)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
        .env("MSBUILDDISABLENODEREUSE", "1")
        .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
        .env("UseSharedCompilation", "false")
        .env("DOTNET_NOLOGO", "1")
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
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

fn require_tools() -> Tools {
    let version: ToolOutput = run_tool(dotnet().arg("--version"), "dotnet --version");
    assert!(
        version.success,
        "this grader compiles the recovered C# with the dotnet SDK, so `dotnet --version` must succeed:\n{}",
        version.stderr_text()
    );
    let sdks: ToolOutput = run_tool(dotnet().arg("--list-sdks"), "dotnet --list-sdks");
    let mut csc: Option<PathBuf> = None;
    for line in sdks.stdout_text().lines() {
        let Some((ver, rest)): Option<(&str, &str)> = line.split_once(' ') else {
            continue;
        };
        let root: &str = rest.trim().trim_start_matches('[').trim_end_matches(']');
        let candidate: PathBuf = Path::new(root)
            .join(ver)
            .join("Roslyn")
            .join("bincore")
            .join("csc.dll");
        if candidate.is_file() {
            csc = Some(candidate);
        }
    }
    let csc: PathBuf = csc.unwrap_or_else(|| {
        panic!(
            "no installed dotnet SDK carries Roslyn/bincore/csc.dll; the net48 fixtures are compiled with it:\n{}",
            sdks.stdout_text()
        )
    });
    let framework: PathBuf = PathBuf::from(FRAMEWORK_DIR);
    for required in ["mscorlib.dll", "System.dll", "System.Core.dll"] {
        assert!(
            framework.join(required).is_file(),
            "the .NET Framework 4.x runtime directory {FRAMEWORK_DIR} must provide {required} to compile and run the net48 fixtures"
        );
    }
    Tools { csc, framework }
}

fn normalize(stdout: &str) -> String {
    stdout.replace("\r\n", "\n")
}

fn observe(output: &ToolOutput) -> Observed {
    Observed {
        stdout: normalize(&output.stdout_text()),
        exit_code: output.exit_code,
    }
}

fn compile_net48(
    tools: &Tools,
    directory: &Path,
    sources: &[PathBuf],
    exe_name: &str,
) -> Result<PathBuf, String> {
    let exe: PathBuf = directory.join(exe_name);
    let mut command: CommandSpec = dotnet()
        .arg(tools.csc.clone())
        .args([
            "-nologo",
            "-noconfig",
            "-nostdlib",
            "-target:exe",
            "-platform:anycpu",
            "-langversion:latest",
            "-nowarn:0168,0219,0414,0436,0649,8321",
        ])
        .arg(format!("-out:{}", exe.display()))
        .current_dir(directory.to_path_buf());
    for reference in ["mscorlib.dll", "System.dll", "System.Core.dll"] {
        command = command.arg(format!("-r:{}", tools.framework.join(reference).display()));
    }
    for source in sources {
        command = command.arg(source.clone());
    }
    let output: ToolOutput = run_tool(command, "csc (net48)");
    if output.success && exe.is_file() {
        Ok(exe)
    } else {
        Err(format!("{}{}", output.stdout_text(), output.stderr_text()))
    }
}

fn run_net48(exe: &Path, directory: &Path) -> Observed {
    let output: ToolOutput = run_tool(
        CommandSpec::new(exe.to_path_buf(), TOOL_TIMEOUT)
            .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES)
            .current_dir(directory.to_path_buf()),
        "net48 program",
    );
    observe(&output)
}

fn project_file(assembly: &str, reference: Option<&Path>) -> String {
    let reference_block: String = reference.map_or_else(String::new, |path: &Path| {
        format!(
            "  <ItemGroup>\n    <Reference Include=\"{}\">\n      <HintPath>{}</HintPath>\n    </Reference>\n  </ItemGroup>\n",
            path.file_stem().and_then(|s| s.to_str()).unwrap_or("Reference"),
            path.display()
        )
    });
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>{NETCORE_TFM}</TargetFramework>\n    <AssemblyName>{assembly}</AssemblyName>\n    <RootNamespace>{assembly}</RootNamespace>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <Deterministic>true</Deterministic>\n    <Optimize>true</Optimize>\n    <DebugType>none</DebugType>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <LangVersion>latest</LangVersion>\n    <TreatWarningsAsErrors>false</TreatWarningsAsErrors>\n    <NoWarn>CS0168;CS0219;CS0414;CS0436;CS0649;CS8321;CS0108;CS0114;CS1717;CS0162</NoWarn>\n    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>\n  </PropertyGroup>\n{reference_block}</Project>\n"
    )
}

fn compile_netcore(
    directory: &Path,
    assembly: &str,
    reference: Option<&Path>,
) -> Result<PathBuf, String> {
    std::fs::write(
        directory.join(format!("{assembly}.csproj")),
        project_file(assembly, reference),
    )
    .expect("write project");
    let output: ToolOutput = run_tool(
        dotnet()
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory.to_path_buf()),
        "dotnet build",
    );
    let built: PathBuf = directory
        .join("bin")
        .join("Release")
        .join(NETCORE_TFM)
        .join(format!("{assembly}.dll"));
    if output.success && built.is_file() {
        Ok(built)
    } else {
        Err(format!("{}{}", output.stdout_text(), output.stderr_text()))
    }
}

fn run_netcore(assembly: &Path, directory: &Path) -> Observed {
    let output: ToolOutput = run_tool(
        dotnet()
            .arg(assembly.to_path_buf())
            .current_dir(directory.to_path_buf()),
        "dotnet program",
    );
    observe(&output)
}

fn run_clean_netcore_console(source: &Path, scratch: &Path) -> Observed {
    let directory: PathBuf = scratch.join("reference");
    std::fs::create_dir_all(&directory).expect("create reference dir");
    std::fs::copy(source, directory.join("Program.cs")).expect("copy clean source");
    let built: PathBuf =
        compile_netcore(&directory, "Reference", None).unwrap_or_else(|diag: String| {
            panic!(
                "the authored clean source {} must compile:\n{diag}",
                source.display()
            )
        });
    run_netcore(&built, &directory)
}

fn run_clean_net48_exe(tools: &Tools, source: &Path, scratch: &Path) -> Observed {
    let directory: PathBuf = scratch.join("reference");
    std::fs::create_dir_all(&directory).expect("create reference dir");
    let copied: PathBuf = directory.join("Program.cs");
    std::fs::copy(source, &copied).expect("copy clean source");
    let exe: PathBuf = compile_net48(tools, &directory, &[copied], "Reference.exe").unwrap_or_else(
        |diag: String| {
            panic!(
                "the authored clean source {} must compile:\n{diag}",
                source.display()
            )
        },
    );
    run_net48(&exe, &directory)
}

fn run_committed_net48_exe(exe: &Path, scratch: &Path) -> Observed {
    let directory: PathBuf = scratch.join("reference");
    std::fs::create_dir_all(&directory).expect("create reference dir");
    let copied: PathBuf = directory.join("Reference.exe");
    std::fs::copy(exe, &copied).expect("copy committed clean exe");
    run_net48(&copied, &directory)
}

fn run_committed_netcore_dll(dll: &Path, scratch: &Path) -> Observed {
    let directory: PathBuf = scratch.join("reference");
    std::fs::create_dir_all(&directory).expect("create reference dir");
    let copied: PathBuf = directory.join("Reference.dll");
    std::fs::copy(dll, &copied).expect("copy committed clean dll");
    std::fs::write(
        directory.join("Reference.runtimeconfig.json"),
        format!(
            "{{\n  \"runtimeOptions\": {{\n    \"tfm\": \"{NETCORE_TFM}\",\n    \"rollForward\": \"Major\",\n    \"framework\": {{ \"name\": \"Microsoft.NETCore.App\", \"version\": \"9.0.0\" }}\n  }}\n}}\n"
        ),
    )
    .expect("write runtimeconfig");
    run_netcore(&copied, &directory)
}

fn run_clean_library(library: &Path, driver: &str, scratch: &Path) -> Observed {
    let directory: PathBuf = scratch.join("reference");
    std::fs::create_dir_all(&directory).expect("create reference dir");
    std::fs::write(directory.join("Driver.cs"), driver).expect("write driver");
    let built: PathBuf =
        compile_netcore(&directory, "Reference", Some(library)).unwrap_or_else(|diag: String| {
            panic!(
                "the driver against the clean library {} must compile:\n{diag}",
                library.display()
            )
        });
    run_netcore(&built, &directory)
}

fn metadata_model(image: &[u8]) -> AssemblyModel {
    let pe: PeImage = parse(image).expect("pe");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata");
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).expect("resolver");
    resolver.model()
}

fn recovered_model(detailed: &Decompiled, image: &[u8]) -> AssemblyModel {
    let pe: PeImage = parse(image).expect("pe");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata");
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).expect("resolver");
    match &detailed.unprotected {
        Some(u) => resolver
            .with_renames(
                u.member_renames.clone(),
                u.type_renames.clone(),
                u.namespace_renames.clone(),
            )
            .model(),
        None => resolver.model(),
    }
}

const fn sample_argument(sig: &TypeSig) -> Option<&'static str> {
    Some(match sig {
        TypeSig::I4 => "7",
        TypeSig::I8 => "7L",
        TypeSig::U4 => "7u",
        TypeSig::String => "\"disrobe\"",
        TypeSig::Boolean => "true",
        TypeSig::R8 => "2.5d",
        TypeSig::R4 => "2.5f",
        TypeSig::Char => "'x'",
        _ => return None,
    })
}

const fn printable_return(sig: &TypeSigOrVoid) -> bool {
    matches!(
        sig,
        TypeSigOrVoid::Type(
            TypeSig::I4
                | TypeSig::I8
                | TypeSig::U4
                | TypeSig::U8
                | TypeSig::I2
                | TypeSig::U2
                | TypeSig::U1
                | TypeSig::I1
                | TypeSig::String
                | TypeSig::Boolean
                | TypeSig::R8
                | TypeSig::R4
                | TypeSig::Char
        )
    )
}

fn signature_key(m: &MethodModel) -> String {
    format!(
        "{}({})",
        m.signature.return_type.render(),
        m.signature
            .params
            .iter()
            .map(TypeSig::render)
            .collect::<Vec<String>>()
            .join(",")
    )
}

#[derive(Debug, Clone)]
struct Callable {
    type_name: String,
    full_name: String,
    method_name: String,
    signature: String,
    arguments: Vec<&'static str>,
}

fn callables(model: &AssemblyModel, rename: bool) -> Vec<Callable> {
    let mut out: Vec<Callable> = Vec::new();
    for ty in &model.types {
        if ty.flags & 0x7 != 1 || ty.name.starts_with('<') {
            continue;
        }
        for m in &ty.methods {
            if !m.is_static()
                || m.flags & 0x7 != 6
                || m.signature.generic_param_count != 0
                || m.name.starts_with('.')
            {
                continue;
            }
            if !printable_return(&m.signature.return_type) {
                continue;
            }
            let Some(arguments): Option<Vec<&'static str>> =
                m.signature.params.iter().map(sample_argument).collect()
            else {
                continue;
            };
            let type_name: String = if rename {
                if ty.namespace.is_empty() {
                    type_identifier(&ty.name)
                } else {
                    format!(
                        "{}.{}",
                        ty.namespace
                            .split('.')
                            .map(member_identifier)
                            .collect::<Vec<String>>()
                            .join("."),
                        type_identifier(&ty.name)
                    )
                }
            } else {
                ty.full_name.clone()
            };
            let method_name: String = if rename {
                member_identifier(&m.name)
            } else {
                m.name.clone()
            };
            out.push(Callable {
                type_name,
                full_name: ty.full_name.clone(),
                method_name,
                signature: signature_key(m),
                arguments,
            });
        }
    }
    out
}

fn unique_by_signature(list: &[Callable]) -> BTreeMap<String, Callable> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in list {
        *counts.entry(c.signature.clone()).or_insert(0) += 1;
    }
    list.iter()
        .filter(|c: &&Callable| counts.get(&c.signature) == Some(&1))
        .map(|c: &Callable| (c.signature.clone(), c.clone()))
        .collect()
}

fn signature_driver(calls: &[(String, Callable)]) -> String {
    let mut source: String = String::from(
        "public static class DisrobeDriver\n{\n    static void Try(string label, System.Func<object> call)\n    {\n        try { object value = call(); System.Console.WriteLine(label + \" = \" + (value == null ? \"null\" : value.ToString())); }\n        catch (System.Exception error) { System.Console.WriteLine(label + \" threw \" + error.GetType().Name); }\n    }\n\n    public static int Main()\n    {\n",
    );
    for (label, call) in calls {
        let _ = writeln!(
            source,
            "        Try(\"{label}\", () => {}.{}({}));",
            call.type_name,
            call.method_name,
            call.arguments.join(", ")
        );
    }
    source.push_str("        return 0;\n    }\n}\n");
    source
}

fn signature_drivers(clean_image: &[u8], protected_image: &[u8]) -> (String, String, usize) {
    let clean: Vec<Callable> = callables(&metadata_model(clean_image), false);
    let detailed: Decompiled =
        decompile_assembly_detailed(protected_image, TargetLang::CSharp).expect("decompile");
    let recovered_image: &[u8] = detailed.image(protected_image);
    let model: AssemblyModel = recovered_model(&detailed, recovered_image);
    let omitted: BTreeSet<String> = model
        .types
        .iter()
        .filter(|t: &&TypeModel| {
            detailed
                .unprotected
                .as_ref()
                .is_some_and(|u| u.omits_type(t.token))
        })
        .map(|t: &TypeModel| t.full_name.clone())
        .collect();
    let recovered: Vec<Callable> = callables(&model, true)
        .into_iter()
        .filter(|c: &Callable| !omitted.contains(&c.full_name))
        .collect();
    let clean_unique: BTreeMap<String, Callable> = unique_by_signature(&clean);
    let recovered_unique: BTreeMap<String, Callable> = unique_by_signature(&recovered);
    let mut clean_calls: Vec<(String, Callable)> = Vec::new();
    let mut recovered_calls: Vec<(String, Callable)> = Vec::new();
    for (signature, clean_call) in &clean_unique {
        let Some(recovered_call): Option<&Callable> = recovered_unique.get(signature) else {
            continue;
        };
        let label: String = format!("{} {}", signature, clean_call.method_name);
        clean_calls.push((label.clone(), clean_call.clone()));
        recovered_calls.push((label, recovered_call.clone()));
    }
    (
        signature_driver(&clean_calls),
        signature_driver(&recovered_calls),
        clean_calls.len(),
    )
}

fn write_project(project: &CSharpProject, directory: &Path) -> Vec<PathBuf> {
    std::fs::create_dir_all(directory).expect("create recovered dir");
    let mut sources: Vec<PathBuf> = Vec::new();
    for (name, source) in &project.files {
        let path: PathBuf = directory.join(name);
        std::fs::write(&path, source).expect("write recovered source");
        sources.push(path);
    }
    sources
}

fn first_diagnostics(diag: &str) -> String {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut lines: Vec<String> = Vec::new();
    for line in diag.lines() {
        if line.contains(": error ") && seen.insert(line.trim().to_owned()) {
            lines.push(line.trim().to_owned());
        }
        if lines.len() >= 5 {
            break;
        }
    }
    lines.join("\n")
}

struct Graded {
    outcome: Outcome,
    reference: Observed,
    recovered: Option<Observed>,
    project: CSharpProject,
    scratch: ScratchDir,
    recovered_dir: PathBuf,
}

fn grade(tools: &Tools, fixture: &Fixture) -> Graded {
    let protected: Vec<u8> = read_fixture(fixture.protected);
    let scratch: ScratchDir =
        ScratchDir::create(&format!("disrobe_protector_reexec_{}", fixture.name)).expect("scratch");
    let project: CSharpProject = emit_csharp_project(&protected).unwrap_or_else(|error| {
        panic!(
            "{}: the protected image must decompile: {error}",
            fixture.name
        )
    });
    let recovered_dir: PathBuf = scratch.path().join("recovered");
    let sources: Vec<PathBuf> = write_project(&project, &recovered_dir);
    let mut residuals: Vec<String> = Vec::new();
    if let Some(report) = &project.protection {
        for r in &report.residuals {
            residuals.push(format!("{}: {}", r.layer, r.reason));
        }
    }
    for refusal in &project.refusals {
        residuals.push(format!(
            "{}::{}: {}",
            refusal.type_name, refusal.member, refusal.reason
        ));
    }
    let (reference, recovered): (Observed, Result<Observed, String>) =
        match (fixture.reference, fixture.driver) {
            (Reference::AuthoredNet48Exe(source), Driver::None) => {
                let reference: Observed =
                    run_clean_net48_exe(tools, &manifest(source), scratch.path());
                let recovered: Result<Observed, String> =
                    compile_net48(tools, &recovered_dir, &sources, "Recovered.exe")
                        .map(|exe: PathBuf| run_net48(&exe, &recovered_dir));
                (reference, recovered)
            }
            (Reference::CommittedNet48Exe(exe), Driver::None) => {
                let reference: Observed = run_committed_net48_exe(&manifest(exe), scratch.path());
                let recovered: Result<Observed, String> =
                    compile_net48(tools, &recovered_dir, &sources, "Recovered.exe")
                        .map(|exe: PathBuf| run_net48(&exe, &recovered_dir));
                (reference, recovered)
            }
            (Reference::CommittedNetCoreDll(dll), Driver::None) => {
                let reference: Observed = run_committed_netcore_dll(&manifest(dll), scratch.path());
                let recovered: Result<Observed, String> =
                    compile_netcore(&recovered_dir, "Recovered", None)
                        .map(|dll: PathBuf| run_netcore(&dll, &recovered_dir));
                (reference, recovered)
            }
            (Reference::AuthoredNetCoreConsole(source), Driver::None) => {
                let reference: Observed =
                    run_clean_netcore_console(&manifest(source), scratch.path());
                let recovered: Result<Observed, String> =
                    compile_netcore(&recovered_dir, "Recovered", None)
                        .map(|dll: PathBuf| run_netcore(&dll, &recovered_dir));
                (reference, recovered)
            }
            (Reference::CleanLibrary(library), Driver::Authored(driver)) => {
                let reference: Observed =
                    run_clean_library(&manifest(library), driver, scratch.path());
                std::fs::write(recovered_dir.join("Driver.cs"), driver).expect("write driver");
                let recovered: Result<Observed, String> =
                    compile_netcore(&recovered_dir, "Recovered", None)
                        .map(|dll: PathBuf| run_netcore(&dll, &recovered_dir));
                (reference, recovered)
            }
            (Reference::CleanLibrary(library), Driver::SignatureMatched) => {
                let clean_image: Vec<u8> = read_fixture(library);
                let (clean_driver, recovered_driver, paired): (String, String, usize) =
                    signature_drivers(&clean_image, &protected);
                assert!(
                    paired > 0,
                    "{}: the signature-matched driver must pair at least one public static method",
                    fixture.name
                );
                let reference: Observed =
                    run_clean_library(&manifest(library), &clean_driver, scratch.path());
                std::fs::write(recovered_dir.join("Driver.cs"), &recovered_driver)
                    .expect("write driver");
                let recovered: Result<Observed, String> =
                    compile_netcore(&recovered_dir, "Recovered", None)
                        .map(|dll: PathBuf| run_netcore(&dll, &recovered_dir));
                (reference, recovered)
            }
            (reference, driver) => panic!(
                "{}: unsupported fixture shape {reference:?} with {driver:?}",
                fixture.name
            ),
        };
    let (outcome, observed): (Outcome, Option<Observed>) = match recovered {
        Err(diag) => (
            Outcome::Residual(format!(
                "recovered C# does not compile:\n{}\nlayer residuals: {}",
                first_diagnostics(&diag),
                residuals.join("; ")
            )),
            None,
        ),
        Ok(observed) if observed == reference && residuals.is_empty() => {
            (Outcome::Full, Some(observed))
        }
        Ok(observed) if observed == reference => (
            Outcome::Residual(format!(
                "output matches but named residuals remain: {}",
                residuals.join("; ")
            )),
            Some(observed),
        ),
        Ok(observed) => (
            Outcome::Residual(format!(
                "output differs: recovered printed {:?} (exit {:?}), the reference printed {:?} (exit {:?}); layer residuals: {}",
                observed.stdout,
                observed.exit_code,
                reference.stdout,
                reference.exit_code,
                residuals.join("; ")
            )),
            Some(observed),
        ),
    };
    Graded {
        outcome,
        reference,
        recovered: observed,
        project,
        scratch,
        recovered_dir,
    }
}

fn fixture_named(name: &str) -> &'static Fixture {
    FIXTURES
        .iter()
        .find(|f: &&Fixture| f.name == name)
        .unwrap_or_else(|| panic!("fixture {name} is not declared"))
}

#[test]
fn every_protected_fixture_is_classified_full_or_named_residual() {
    let tools: Tools = require_tools();
    let mut failures: Vec<String> = Vec::new();
    for fixture in FIXTURES {
        let graded: Graded = grade(&tools, fixture);
        println!(
            "{}: {}",
            fixture.name,
            match &graded.outcome {
                Outcome::Full => "full".to_owned(),
                Outcome::Residual(reason) => format!("residual: {reason}"),
            }
        );
        assert!(
            !graded.reference.stdout.is_empty(),
            "{}: the reference program must print something",
            fixture.name
        );
        let expected_full: bool = FULLY_RECOVERED.contains(&fixture.name);
        let expected_residual: Option<&str> = RESIDUAL
            .iter()
            .find(|(name, _): &&(&str, &str)| *name == fixture.name)
            .map(|(_, needle): &(&str, &str)| *needle);
        match (&graded.outcome, expected_full, expected_residual) {
            (Outcome::Full, true, _) => {}
            (Outcome::Full, false, Some(_)) => failures.push(format!(
                "{}: now fully recovered; promote it from RESIDUAL to FULLY_RECOVERED",
                fixture.name
            )),
            (Outcome::Residual(reason), true, _) => failures.push(format!(
                "{}: must stay fully recovered but reported a residual: {reason}",
                fixture.name
            )),
            (Outcome::Residual(reason), false, Some(needle)) => {
                if !reason.contains(needle) {
                    failures.push(format!(
                        "{}: residual must name {needle:?}; got: {reason}",
                        fixture.name
                    ));
                }
                let named_layer: bool = graded
                    .project
                    .protection
                    .as_ref()
                    .is_some_and(|p| !p.fully_recovered || !graded.project.refusals.is_empty())
                    || reason.contains("does not compile")
                    || reason.contains("output differs");
                assert!(named_layer, "{}: a residual must be named", fixture.name);
            }
            (_, false, None) => failures.push(format!(
                "{}: every fixture must be listed in FULLY_RECOVERED or RESIDUAL",
                fixture.name
            )),
        }
        drop(graded.scratch);
    }
    assert!(
        failures.is_empty(),
        "protector re-execution grade:\n{}",
        failures.join("\n\n")
    );
}

#[test]
fn a_recovery_with_one_changed_literal_is_caught() {
    let tools: Tools = require_tools();
    let fixture: &Fixture = fixture_named(MUTATION_FIXTURE);
    let graded: Graded = grade(&tools, fixture);
    assert_eq!(
        graded.outcome,
        Outcome::Full,
        "{MUTATION_FIXTURE} must be fully recovered before the mutation control runs"
    );
    let mutated_dir: PathBuf = graded.scratch.path().join("mutated");
    std::fs::create_dir_all(&mutated_dir).expect("create mutated dir");
    let mut sources: Vec<PathBuf> = Vec::new();
    let mut mutated: bool = false;
    for (name, source) in &graded.project.files {
        let text: String = if source.contains(MUTATION_FROM) {
            mutated = true;
            source.replacen(MUTATION_FROM, MUTATION_TO, 1)
        } else {
            source.clone()
        };
        let path: PathBuf = mutated_dir.join(name);
        std::fs::write(&path, text).expect("write mutated source");
        sources.push(path);
    }
    assert!(
        mutated,
        "the recovered project must contain the literal {MUTATION_FROM}"
    );
    let exe: PathBuf = compile_net48(&tools, &mutated_dir, &sources, "Mutated.exe")
        .unwrap_or_else(|diag: String| panic!("the mutated recovery must still compile:\n{diag}"));
    let observed: Observed = run_net48(&exe, &mutated_dir);
    assert_ne!(
        observed, graded.reference,
        "changing one recovered literal must change what the program prints"
    );
    assert_eq!(
        graded.recovered.as_ref(),
        Some(&graded.reference),
        "the unmodified recovery prints exactly what the reference prints"
    );
    let _ = graded.recovered_dir;
}
