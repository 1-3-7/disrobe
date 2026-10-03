#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_dotnet::cil::{MethodBody, disassemble};
use disrobe_pass_dotnet::cil_emulator::{StubInput, StubOutput, emulate_stub};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};

const DOTNET_TIMEOUT: Duration = Duration::from_mins(1);
const DOTNET_CAPTURE_LIMIT: usize = 64 * 1024;
const CLR_EXPECTED_OUTPUT: [i64; 2] = [0, -128];
const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net9.0</TargetFramework>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <Nullable>disable</Nullable>\n    <InvariantGlobalization>true</InvariantGlobalization>\n  </PropertyGroup>\n</Project>\n";
const CLR_REFERENCE_SOURCE: &str = "using System;\nusing System.Reflection.Emit;\n\ninternal static class Program\n{\n    private static int Main()\n    {\n        Console.WriteLine(UnsignedLessThan().Invoke());\n        Console.WriteLine(SignedByteLoad().Invoke());\n        return 0;\n    }\n\n    private static Func<int> UnsignedLessThan()\n    {\n        DynamicMethod method = new DynamicMethod(\"UnsignedLessThan\", typeof(int), Type.EmptyTypes);\n        ILGenerator il = method.GetILGenerator();\n        il.Emit(OpCodes.Ldc_I4_M1);\n        il.Emit(OpCodes.Ldc_I4_0);\n        il.Emit(OpCodes.Clt_Un);\n        il.Emit(OpCodes.Ret);\n        return (Func<int>)method.CreateDelegate(typeof(Func<int>));\n    }\n\n    private static Func<int> SignedByteLoad()\n    {\n        DynamicMethod method = new DynamicMethod(\"SignedByteLoad\", typeof(int), Type.EmptyTypes);\n        ILGenerator il = method.GetILGenerator();\n        il.Emit(OpCodes.Ldc_I4_1);\n        il.Emit(OpCodes.Newarr, typeof(sbyte));\n        il.Emit(OpCodes.Dup);\n        il.Emit(OpCodes.Ldc_I4_0);\n        il.Emit(OpCodes.Ldc_I4, 128);\n        il.Emit(OpCodes.Stelem_I1);\n        il.Emit(OpCodes.Ldc_I4_0);\n        il.Emit(OpCodes.Ldelem_I1);\n        il.Emit(OpCodes.Ret);\n        return (Func<int>)method.CreateDelegate(typeof(Func<int>));\n    }\n}\n";
const CLT_UN: &[u8] = &[0x15, 0x16, 0xfe, 0x05, 0x2a];
const LDELEM_I1: &[u8] = &[
    0x17, 0x8d, 0x01, 0x00, 0x00, 0x01, 0x25, 0x16, 0x20, 0x80, 0x00, 0x00, 0x00, 0x9c, 0x16, 0x90,
    0x2a,
];

struct CilCase {
    name: &'static str,
    operation: &'static str,
    mutant_operation: &'static str,
    original: &'static [u8],
    mutated: Vec<u8>,
}

fn mutate_opcode(original: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(
        from.len(),
        to.len(),
        "opcode mutation preserves instruction width"
    );
    let offsets: Vec<usize> = original
        .windows(from.len())
        .enumerate()
        .filter_map(|(offset, bytes): (usize, &[u8])| (bytes == from).then_some(offset))
        .collect();
    let [offset]: [usize; 1] = offsets
        .try_into()
        .expect("the authored CIL body has one mutation target");
    let mut mutated: Vec<u8> = original.to_vec();
    mutated[offset..offset + to.len()].copy_from_slice(to);
    mutated
}

fn cases() -> [CilCase; 2] {
    [
        CilCase {
            name: "clt.un sign-bit comparison",
            operation: "clt.un",
            mutant_operation: "clt",
            original: CLT_UN,
            mutated: mutate_opcode(CLT_UN, &[0xfe, 0x05], &[0xfe, 0x04]),
        },
        CilCase {
            name: "ldelem.i1 sign extension",
            operation: "ldelem.i1",
            mutant_operation: "ldelem.u1",
            original: LDELEM_I1,
            mutated: mutate_opcode(LDELEM_I1, &[0x90], &[0x91]),
        },
    ]
}

fn body(code: &[u8]) -> MethodBody {
    MethodBody {
        max_stack: 8,
        code_size: u32::try_from(code.len()).expect("small authored CIL body"),
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: disassemble(code).expect("authored CIL must disassemble"),
        exception_clauses: Vec::new(),
    }
}

fn dotnet() -> CommandSpec {
    CommandSpec::new("dotnet", DOTNET_TIMEOUT)
        .capture_limits(DOTNET_CAPTURE_LIMIT, DOTNET_CAPTURE_LIMIT)
        .env("MSBUILDDISABLENODEREUSE", "1")
        .env("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
        .env("UseSharedCompilation", "false")
        .reap_descendants_on_exit()
}

fn run_tool(command: CommandSpec, label: &str) -> ToolOutput {
    let output: ToolOutput = tool_output(command)
        .unwrap_or_else(|error: ToolError| panic!("{label} could not start: {error}"));
    assert!(
        !output.timed_out,
        "{label} did not finish within {} seconds",
        DOTNET_TIMEOUT.as_secs()
    );
    output
}

fn clr_reference_outputs() -> Vec<i64> {
    let scratch: ScratchDir = ScratchDir::create("cil-integer-reference")
        .expect("create CLR reference scratch directory");
    let project: PathBuf = scratch.path().join("CilIntegerReference.csproj");
    std::fs::write(&project, CSPROJ).expect("write CLR reference project");
    std::fs::write(scratch.path().join("Program.cs"), CLR_REFERENCE_SOURCE)
        .expect("write CLR reference source");
    let output: ToolOutput = run_tool(
        dotnet()
            .args([
                "run",
                "--configuration",
                "Release",
                "--nologo",
                "--verbosity",
                "quiet",
            ])
            .current_dir(scratch.path().to_path_buf()),
        "dotnet CLR reference",
    );
    assert!(
        output.success,
        "CLR reference compilation or run failed: {}",
        output.stderr_text()
    );
    output
        .stdout_text()
        .lines()
        .map(|line: &str| line.parse::<i64>().expect("CLR reference integer output"))
        .collect()
}

fn assert_case(case: &CilCase, expected: i64) {
    let original: MethodBody = body(case.original);
    assert!(
        original
            .instructions
            .iter()
            .any(|instruction| instruction.name == case.operation),
        "{} must decode its authored opcode",
        case.name
    );
    let output: StubOutput = emulate_stub(&original, &StubInput::default())
        .unwrap_or_else(|error| panic!("{} emulator error: {error:?}", case.name));
    assert_eq!(output, StubOutput::Int(expected), "{}", case.name);

    let mutant: MethodBody = body(&case.mutated);
    assert!(
        mutant
            .instructions
            .iter()
            .any(|instruction| instruction.name == case.mutant_operation),
        "{} mutation must decode its replacement opcode",
        case.name
    );
    let mutated: StubOutput = emulate_stub(&mutant, &StubInput::default())
        .unwrap_or_else(|error| panic!("{} mutant emulator error: {error:?}", case.name));
    assert_ne!(
        mutated,
        StubOutput::Int(expected),
        "{} mutation must disagree with the independent CLR reference",
        case.name
    );
}

#[test]
fn clt_un_matches_clr_and_rejects_the_signed_mutation() {
    let reference: Vec<i64> = clr_reference_outputs();
    assert_eq!(
        reference,
        CLR_EXPECTED_OUTPUT.to_vec(),
        "the independent CLR reference must preserve its authored semantics"
    );
    let [clt_un, _ldelem_i1]: [CilCase; 2] = cases();
    assert_case(&clt_un, CLR_EXPECTED_OUTPUT[0]);
}

#[test]
fn ldelem_i1_matches_clr_and_rejects_the_unsigned_mutation() {
    let reference: Vec<i64> = clr_reference_outputs();
    assert_eq!(
        reference,
        CLR_EXPECTED_OUTPUT.to_vec(),
        "the independent CLR reference must preserve its authored semantics"
    );
    let [_clt_un, ldelem_i1]: [CilCase; 2] = cases();
    assert_case(&ldelem_i1, CLR_EXPECTED_OUTPUT[1]);
}
