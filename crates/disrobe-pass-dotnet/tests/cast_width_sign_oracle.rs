#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_dotnet::cil::{MethodBody, disassemble};
use disrobe_pass_dotnet::names::NameTable;
use disrobe_pass_dotnet::structurize::{TargetLang, TokenNamer, decompile_method_named};

const UNRESOLVED_OPERAND_KIND: &str = "__unresolved_operand_kind";

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

fn require_dotnet(grader: &str) {
    let probe: std::io::Result<std::process::Output> =
        Command::new("dotnet").arg("--version").output();
    let reached: bool = matches!(&probe, Ok(output) if output.status.success());
    assert!(
        reached,
        "{grader} grades recovered C# with the real csc that ships in the dotnet SDK, so \
         `dotnet --version` must succeed here. it did not. a grader that cannot reach its \
         compiler reports no measurement at all rather than passing on an empty population"
    );
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

fn declared_parameters(sig: &str) -> NameTable {
    let open: usize = sig.find('(').expect("signature opens its parameter list");
    let close: usize = sig.rfind(')').expect("signature closes its parameter list");
    let mut names: Vec<String> = Vec::new();
    let mut types: Vec<String> = Vec::new();
    for parameter in sig[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|p: &&str| !p.is_empty())
    {
        let (ty, name): (&str, &str) = parameter
            .rsplit_once(' ')
            .expect("each parameter carries a type and a name");
        types.push(ty.to_owned());
        names.push(name.to_owned());
    }
    NameTable::new(false, names, types, Vec::new())
}

fn emit(sig: &str, code: &[u8]) -> String {
    decompile_method_named(
        sig,
        &body_from(code),
        &StaticNamer,
        &declared_parameters(sig),
        TargetLang::CSharp,
    )
    .body
}

struct Case {
    name: &'static str,
    body: String,
    call: &'static str,
    expected: &'static str,
    guarded: bool,
    sign_sensitive: bool,
}

const LDARG_0: u8 = 0x02;
const LDARG_1: u8 = 0x03;
const LDC_I4_0: u8 = 0x16;
const LDC_I4_1: u8 = 0x17;
const RET: u8 = 0x2A;
const BLT_UN_S: u8 = 0x37;
const DIV_UN: u8 = 0x5C;
const REM_UN: u8 = 0x5E;
const CONV_U8: u8 = 0x6E;
const CONV_R_UN: u8 = 0x76;
const CONV_OVF_U8_UN: u8 = 0x89;
const ADD_OVF: u8 = 0xD6;
const ADD_OVF_UN: u8 = 0xD7;
const MUL_OVF_UN: u8 = 0xD9;
const SUB_OVF: u8 = 0xDA;
const SUB_OVF_UN: u8 = 0xDB;
const PREFIX: u8 = 0xFE;
const CGT_UN: u8 = 0x03;
const CLT_UN: u8 = 0x05;

const fn case(
    name: &'static str,
    body: String,
    call: &'static str,
    expected: &'static str,
) -> Case {
    Case {
        name,
        body,
        call,
        expected,
        guarded: false,
        sign_sensitive: false,
    }
}

const fn sensitive(mut c: Case) -> Case {
    c.sign_sensitive = true;
    c
}

const fn guarded(mut c: Case) -> Case {
    c.guarded = true;
    c
}

fn cases() -> Vec<Case> {
    vec![
        case(
            "NarrowByte",
            emit("static byte NarrowByte(int arg1)", &[LDARG_0, 0xD2, RET]),
            "NarrowByte(300)",
            "44",
        ),
        case(
            "NarrowSByte",
            emit("static sbyte NarrowSByte(int arg1)", &[LDARG_0, 0x67, RET]),
            "NarrowSByte(200)",
            "-56",
        ),
        case(
            "NegativeToUInt",
            emit(
                "static uint NegativeToUInt(int arg1)",
                &[LDARG_0, 0x6D, RET],
            ),
            "NegativeToUInt(-1)",
            "4294967295",
        ),
        case(
            "LongToInt",
            emit("static int LongToInt(long arg1)", &[LDARG_0, 0x69, RET]),
            "LongToInt(4294967338L)",
            "42",
        ),
        case(
            "SignedShift",
            emit(
                "static int SignedShift(int arg1)",
                &[LDARG_0, LDC_I4_1, 0x63, RET],
            ),
            "SignedShift(-1)",
            "-1",
        ),
        case(
            "UnsignedShift",
            emit(
                "static int UnsignedShift(int arg1)",
                &[LDARG_0, LDC_I4_1, 0x64, RET],
            ),
            "UnsignedShift(-1)",
            "2147483647",
        ),
        guarded(case(
            "CheckedOverflow",
            emit(
                "static byte CheckedOverflow(int arg1)",
                &[LDARG_0, 0xB4, RET],
            ),
            "CheckedOverflow(300)",
            "OVERFLOW",
        )),
        sensitive(case(
            "UnsignedLess",
            emit(
                "static bool UnsignedLess(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, PREFIX, CLT_UN, RET],
            ),
            "UnsignedLess(-1, 1)",
            "False",
        )),
        sensitive(case(
            "UnsignedGreaterLong",
            emit(
                "static bool UnsignedGreaterLong(long arg1, long arg2)",
                &[LDARG_0, LDARG_1, PREFIX, CGT_UN, RET],
            ),
            "UnsignedGreaterLong(-1L, 1L)",
            "True",
        )),
        sensitive(case(
            "UnsignedBranch",
            emit(
                "static int UnsignedBranch(int arg1, int arg2)",
                &[
                    LDARG_0, LDARG_1, BLT_UN_S, 0x02, LDC_I4_0, RET, LDC_I4_1, RET,
                ],
            ),
            "UnsignedBranch(-1, 1)",
            "0",
        )),
        sensitive(case(
            "UnorderedLess",
            emit(
                "static bool UnorderedLess(double arg1, double arg2)",
                &[LDARG_0, LDARG_1, PREFIX, CLT_UN, RET],
            ),
            "UnorderedLess(double.NaN, 1.0)",
            "True",
        )),
        sensitive(case(
            "UnsignedDivide",
            emit(
                "static int UnsignedDivide(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, DIV_UN, RET],
            ),
            "UnsignedDivide(-2, 2)",
            "2147483647",
        )),
        sensitive(case(
            "UnsignedRemainder",
            emit(
                "static int UnsignedRemainder(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, REM_UN, RET],
            ),
            "UnsignedRemainder(-1, 10)",
            "5",
        )),
        sensitive(case(
            "ZeroExtend",
            emit(
                "static ulong ZeroExtend(int arg1)",
                &[LDARG_0, CONV_U8, RET],
            ),
            "ZeroExtend(-1)",
            "4294967295",
        )),
        sensitive(case(
            "UnsignedToDouble",
            emit(
                "static double UnsignedToDouble(int arg1)",
                &[LDARG_0, CONV_R_UN, RET],
            ),
            "UnsignedToDouble(-1)",
            "4294967295",
        )),
        sensitive(guarded(case(
            "CheckedWidenUnsigned",
            emit(
                "static ulong CheckedWidenUnsigned(int arg1)",
                &[LDARG_0, CONV_OVF_U8_UN, RET],
            ),
            "CheckedWidenUnsigned(-1)",
            "4294967295",
        ))),
        sensitive(guarded(case(
            "CheckedAdd",
            emit(
                "static int CheckedAdd(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, ADD_OVF, RET],
            ),
            "CheckedAdd(2147483647, 1)",
            "OVERFLOW",
        ))),
        guarded(case(
            "CheckedAddUnsignedFits",
            emit(
                "static int CheckedAddUnsignedFits(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, ADD_OVF_UN, RET],
            ),
            "CheckedAddUnsignedFits(-2, 1)",
            "-1",
        )),
        sensitive(guarded(case(
            "CheckedAddUnsigned",
            emit(
                "static int CheckedAddUnsigned(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, ADD_OVF_UN, RET],
            ),
            "CheckedAddUnsigned(-1, 1)",
            "OVERFLOW",
        ))),
        sensitive(guarded(case(
            "CheckedMultiplyUnsigned",
            emit(
                "static int CheckedMultiplyUnsigned(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, MUL_OVF_UN, RET],
            ),
            "CheckedMultiplyUnsigned(65536, 65536)",
            "OVERFLOW",
        ))),
        sensitive(guarded(case(
            "CheckedSubtract",
            emit(
                "static int CheckedSubtract(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, SUB_OVF, RET],
            ),
            "CheckedSubtract(-2147483648, 1)",
            "OVERFLOW",
        ))),
        sensitive(guarded(case(
            "CheckedSubtractUnsigned",
            emit(
                "static int CheckedSubtractUnsigned(int arg1, int arg2)",
                &[LDARG_0, LDARG_1, SUB_OVF_UN, RET],
            ),
            "CheckedSubtractUnsigned(0, 1)",
            "OVERFLOW",
        ))),
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

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <InvariantGlobalization>true</InvariantGlobalization>\n    <AssemblyName>castoracle</AssemblyName>\n  </PropertyGroup>\n</Project>\n";

fn evaluate(program: &str, purpose: &str) -> Vec<String> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose).expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    std::fs::write(tmp.join("castoracle.csproj"), CSPROJ).expect("write csproj");
    std::fs::write(tmp.join("Program.cs"), program).expect("write program");

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
    stdout
        .lines()
        .map(str::trim)
        .filter(|l: &&str| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

fn diverging_cases<'a>(cases: &'a [Case], lines: &[String], program: &str) -> BTreeSet<&'a str> {
    assert_eq!(
        lines.len(),
        cases.len(),
        "expected {} output lines, got {}.\nPROGRAM:\n{program}\nOUTPUT:\n{lines:?}",
        cases.len(),
        lines.len()
    );
    cases
        .iter()
        .zip(lines.iter())
        .filter(|(case, actual): &(&Case, &String)| actual.as_str() != case.expected)
        .map(|(case, _): (&Case, &String)| case.name)
        .collect()
}

fn strip_sign_semantics(body: &str) -> String {
    const UNCHECKED_PLACEHOLDER: &str = "\u{1}";
    body.replace("unchecked(", UNCHECKED_PLACEHOLDER)
        .replace("checked(", "unchecked(")
        .replace(UNCHECKED_PLACEHOLDER, "unchecked(")
        .replace("(ulong)arg1", "arg1")
        .replace("(ulong)arg2", "arg2")
        .replace("(uint)", "")
        .replace("!(arg1 >= arg2)", "(arg1 < arg2)")
}

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
fn unsigned_opcode_over_an_operand_of_unknown_width_is_refused_by_name() {
    let body: String = emit(
        "static bool M(Flags arg1, Flags arg2)",
        &[LDARG_0, LDARG_1, PREFIX, CLT_UN, RET],
    );
    assert!(
        body.contains(&format!(
            "throw new System.NotSupportedException(\"{UNRESOLVED_OPERAND_KIND}"
        )) && !body.contains("arg1 < arg2"),
        "clt.un over operands whose stack width is unknown must refuse the method by name rather than guess a cast; got:\n{body}"
    );
}

#[test]
fn cast_width_sign_recompiles_and_evaluates_to_matching_values() {
    require_dotnet("the cast, width and sign evaluation gate");
    let cases: Vec<Case> = cases();
    let program: String = assemble_program(&cases);
    let lines: Vec<String> = evaluate(&program, "disrobe_cast_width_sign_oracle");
    let diverging: BTreeSet<&str> = diverging_cases(&cases, &lines, &program);
    assert!(
        diverging.is_empty(),
        "these cases evaluated to a value the IL does not produce: {diverging:?}.\nPROGRAM:\n{program}\nOUTPUT:\n{lines:?}"
    );
}

#[test]
fn stripping_the_unsigned_and_checked_renderings_turns_the_gate_red() {
    require_dotnet("the cast, width and sign mutation control");
    let cases: Vec<Case> = cases()
        .into_iter()
        .map(|mut c: Case| {
            if c.sign_sensitive {
                let stripped: String = strip_sign_semantics(&c.body);
                assert_ne!(
                    stripped, c.body,
                    "the mutation must actually change the {} body it grades",
                    c.name
                );
                c.body = stripped;
            }
            c
        })
        .collect();
    let mutated: String = assemble_program(&cases);
    let lines: Vec<String> = evaluate(&mutated, "disrobe_cast_width_sign_mutation");
    let diverging: BTreeSet<&str> = diverging_cases(&cases, &lines, &mutated);
    let sensitive: BTreeSet<&str> = cases
        .iter()
        .filter(|c: &&Case| c.sign_sensitive)
        .map(|c: &Case| c.name)
        .collect();
    let undetected: Vec<&&str> = sensitive.difference(&diverging).collect();
    assert!(
        undetected.is_empty(),
        "with its unsigned casts, checked contexts and unordered negation removed, the recovered C# still evaluated these cases to the IL's value, so the gate cannot see their loss: {undetected:?}.\nMUTATED PROGRAM:\n{mutated}\nOUTPUT:\n{lines:?}"
    );
}
