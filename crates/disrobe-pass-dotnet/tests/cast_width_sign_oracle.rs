#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_dotnet::cil::{MethodBody, disassemble};
use disrobe_pass_dotnet::structurize::{TokenNamer, decompile_method};

#[derive(Debug)]
struct StaticNamer;

impl TokenNamer for StaticNamer {
    fn name(&self, token: u32) -> String {
        format!("token_{token:08X}")
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

fn dotnet_available() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn body_from(code: &[u8]) -> MethodBody {
    MethodBody {
        max_stack: 8,
        code_size: code.len() as u32,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: disassemble(code).expect("disasm"),
        exception_clauses: Vec::new(),
    }
}

fn emit(sig: &str, code: &[u8]) -> String {
    decompile_method(sig, &body_from(code), &StaticNamer).body
}

struct Case {
    name: &'static str,
    body: String,
    call: &'static str,
    expected: &'static str,
    guarded: bool,
}

const LDARG_0: u8 = 0x02;
const LDC_I4_1: u8 = 0x17;
const RET: u8 = 0x2A;

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "NarrowByte",
            body: emit("static byte NarrowByte(int arg1)", &[LDARG_0, 0xD2, RET]),
            call: "NarrowByte(300)",
            expected: "44",
            guarded: false,
        },
        Case {
            name: "NarrowSByte",
            body: emit("static sbyte NarrowSByte(int arg1)", &[LDARG_0, 0x67, RET]),
            call: "NarrowSByte(200)",
            expected: "-56",
            guarded: false,
        },
        Case {
            name: "NegativeToUInt",
            body: emit(
                "static uint NegativeToUInt(int arg1)",
                &[LDARG_0, 0x6D, RET],
            ),
            call: "NegativeToUInt(-1)",
            expected: "4294967295",
            guarded: false,
        },
        Case {
            name: "LongToInt",
            body: emit("static int LongToInt(long arg1)", &[LDARG_0, 0x69, RET]),
            call: "LongToInt(4294967338L)",
            expected: "42",
            guarded: false,
        },
        Case {
            name: "SignedShift",
            body: emit(
                "static int SignedShift(int arg1)",
                &[LDARG_0, LDC_I4_1, 0x63, RET],
            ),
            call: "SignedShift(-1)",
            expected: "-1",
            guarded: false,
        },
        Case {
            name: "UnsignedShift",
            body: emit(
                "static int UnsignedShift(int arg1)",
                &[LDARG_0, LDC_I4_1, 0x64, RET],
            ),
            call: "UnsignedShift(-1)",
            expected: "2147483647",
            guarded: false,
        },
        Case {
            name: "CheckedOverflow",
            body: emit(
                "static byte CheckedOverflow(int arg1)",
                &[LDARG_0, 0xB4, RET],
            ),
            call: "CheckedOverflow(300)",
            expected: "OVERFLOW",
            guarded: true,
        },
    ]
}

fn assemble_program(cases: &[Case]) -> String {
    let mut src: String = String::from("using System;\n\npublic static class Program\n{\n");
    for c in cases {
        for line in c.body.lines() {
            src.push_str("    ");
            src.push_str(line);
            src.push('\n');
        }
        src.push('\n');
    }
    src.push_str("    public static void Main()\n    {\n");
    for c in cases {
        if c.guarded {
            writeln!(
                src,
                "        try {{ Console.WriteLine({}); }} catch (OverflowException) {{ Console.WriteLine(\"OVERFLOW\"); }}",
                c.call
            )
            .expect("format guarded call");
        } else {
            writeln!(src, "        Console.WriteLine({});", c.call).expect("format call");
        }
    }
    src.push_str("    }\n}\n");
    src
}

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <AssemblyName>castoracle</AssemblyName>\n  </PropertyGroup>\n</Project>\n";

#[test]
fn constant_narrowing_conversion_emits_unchecked_context() {
    let body: String = emit("static byte M()", &{
        let mut code: Vec<u8> = vec![0x20];
        code.extend_from_slice(&300i32.to_le_bytes());
        code.push(0xD2);
        code.push(RET);
        code
    });
    assert!(
        body.contains("unchecked((byte)300)"),
        "a constant narrowing conversion must recompile via an unchecked context; got:\n{body}"
    );
}

#[test]
fn checked_overflow_conversion_emits_checked_context() {
    let body: String = emit("static byte M(int arg1)", &[LDARG_0, 0xB4, RET]);
    assert!(
        body.contains("checked((byte)arg1)"),
        "conv.ovf.* must emit a checked cast context; got:\n{body}"
    );
}

#[test]
fn cast_width_sign_recompiles_and_evaluates_to_matching_values() {
    if !dotnet_available() {
        eprintln!("SKIP cast/width/sign eval oracle: no dotnet SDK on PATH");
        return;
    }
    let cases: Vec<Case> = cases();
    let program: String = assemble_program(&cases);
    let tmp: PathBuf = std::env::temp_dir().join("disrobe_cast_width_sign_oracle");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    std::fs::write(tmp.join("castoracle.csproj"), CSPROJ).expect("write csproj");
    std::fs::write(tmp.join("Program.cs"), &program).expect("write program");

    let out: std::process::Output = Command::new("dotnet")
        .args(["run", "-c", "Release", "-v", "q", "--nologo"])
        .current_dir(&tmp)
        .output()
        .expect("dotnet run");

    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "emitted C# failed to compile or run.\nPROGRAM:\n{program}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l: &&str| !l.is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        cases.len(),
        "expected {} output lines, got {}.\nPROGRAM:\n{program}\nSTDOUT:\n{stdout}",
        cases.len(),
        lines.len()
    );
    for (case, actual) in cases.iter().zip(lines.iter()) {
        assert_eq!(
            *actual, case.expected,
            "case {} emitted the wrong value: expected {}, got {}.\nBODY:\n{}\nPROGRAM:\n{program}",
            case.name, case.expected, actual, case.body
        );
    }
}
