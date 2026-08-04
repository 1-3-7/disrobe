#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

fn decompile_edgecases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn body_in_type(asm: &DecompiledAssembly, declaring_type: &str, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.body
                .lines()
                .next()
                .is_some_and(|first: &str| first.contains(declaring_type))
                && m.signature.contains(needle)
        })
        .map_or_else(
            || panic!("method {declaring_type}::{needle} not found"),
            |m| m.body.clone(),
        )
}

fn body_of(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains(needle))
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

fn money_inequality(asm: &DecompiledAssembly) -> String {
    body_in_type(asm, "EdgeCases.Money", " op_Inequality(")
}

fn money_inequality_source(body: &str) -> String {
    format!(
        "namespace EdgeCases\n{{\n    public readonly struct Money\n    {{\n        private readonly long pennies;\n\n        public Money(long pennies)\n        {{\n            this.pennies = pennies;\n        }}\n\n        public bool Equals(Money other)\n        {{\n            return pennies == other.pennies;\n        }}\n\n{body}\n    }}\n}}\n\npublic static class Program\n{{\n    public static int Main()\n    {{\n        EdgeCases.Money value = new EdgeCases.Money(37);\n        EdgeCases.Money equal = new EdgeCases.Money(37);\n        EdgeCases.Money different = new EdgeCases.Money(38);\n        if (EdgeCases.Money.op_Inequality(value, equal))\n        {{\n            return 1;\n        }}\n        if (!EdgeCases.Money.op_Inequality(value, different))\n        {{\n            return 2;\n        }}\n        return 0;\n    }}\n}}\n"
    )
}

fn write_money_inequality_probe(directory: &Path, source: &str) {
    std::fs::write(
        directory.join("MoneyInequalityProbe.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings><GenerateAssemblyInfo>false</GenerateAssemblyInfo><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup></Project>",
    )
    .expect("write Money inequality compiler project");
    std::fs::write(directory.join("MoneyInequalityProbe.cs"), source)
        .expect("write Money inequality compiler source");
}

fn build_money_inequality_probe(directory: &Path) -> Output {
    Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(directory)
        .output()
        .expect("build Money inequality compiler probe")
}

fn run_money_inequality_probe(directory: &Path) -> Output {
    Command::new("dotnet")
        .args(["run", "-c", "Release", "-v", "q", "-nologo", "--no-build"])
        .current_dir(directory)
        .output()
        .expect("run Money inequality compiler probe")
}

#[test]
fn bool_methods_return_true_false_not_integer_literals() {
    let asm: DecompiledAssembly = decompile();
    let print_members: String = body_of(&asm, "PrintMembers");
    assert!(
        print_members.contains("return true;"),
        "a bool method's `return 1;` must render as `return true;`; got:\n{print_members}"
    );
    assert!(
        !print_members.contains("return 1;") && !print_members.contains("return 0;"),
        "no bare integer-literal bool return may survive in a bool method; got:\n{print_members}"
    );
}

#[test]
fn nested_boolean_ceq_compiles_and_preserves_money_inequality() {
    let asm: DecompiledAssembly = decompile_edgecases();
    let body: String = money_inequality(&asm);
    assert!(
        body.contains("return left.Equals(right) == false;"),
        "a Boolean call followed by ldc.i4.0 and ceq must render as Boolean equality, got:\n{body}"
    );
    assert!(
        !body.contains("left.Equals(right) == 0"),
        "a CIL false representation must not survive as an integer operand in C#, got:\n{body}"
    );
    let source: String = money_inequality_source(&body);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_money_inequality_ceq")
            .expect("create Money inequality compiler scratch directory");
    write_money_inequality_probe(scratch.path(), &source);
    let build_output: Output = build_money_inequality_probe(scratch.path());
    assert!(
        build_output.status.success(),
        "the real EdgeCases Money inequality output must compile with warnings as errors:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
    let output: Output = run_money_inequality_probe(scratch.path());
    assert!(
        output.status.success(),
        "the real EdgeCases Money inequality output must distinguish equal and unequal values:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen(
        "left.Equals(right) == false",
        "left.Equals(right) == true",
        1,
    );
    assert_ne!(mutated, source, "the Boolean equality mutation must apply");
    write_money_inequality_probe(scratch.path(), &mutated);
    let mutated_build: Output = build_money_inequality_probe(scratch.path());
    assert!(
        mutated_build.status.success(),
        "the Boolean equality mutation must compile so its runtime result is observable:\nstdout:\n{}\nstderr:\n{}\nsource:\n{mutated}",
        String::from_utf8_lossy(&mutated_build.stdout),
        String::from_utf8_lossy(&mutated_build.stderr)
    );
    let mutated_output: Output = run_money_inequality_probe(scratch.path());
    assert_eq!(
        mutated_output.status.code(),
        Some(1),
        "the mutated real-metadata output must fail the equality case:\nstdout:\n{}\nstderr:\n{}\nsource:\n{mutated}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}

#[test]
fn non_bool_methods_keep_their_integer_returns() {
    let asm: DecompiledAssembly = decompile();
    let get_x: String = body_of(&asm, "get_X");
    assert!(
        !get_x.contains("return true;") && !get_x.contains("return false;"),
        "an int-returning accessor must not be rewritten to a bool return; got:\n{get_x}"
    );
}

#[test]
fn integer_constants_take_the_declared_type_of_what_they_are_stored_in() {
    let asm: DecompiledAssembly = decompile_edgecases();
    let dispose: String = body_in_type(&asm, "EdgeCases.DisposableScope", "void Dispose(");
    assert!(
        dispose.contains("this.disposed = true;"),
        "a store of 1 into a bool field must render as true; got:\n{dispose}"
    );
    let object_writer: String = body_in_type(&asm, "EdgeCases.JsonLite", "Object");
    assert!(
        object_writer.contains("local1 = true;") && object_writer.contains("local1 = false;"),
        "stores of 1 and 0 into a bool local must render as true and false; got:\n{object_writer}"
    );
    assert!(
        object_writer.contains("local0.Append(':');"),
        "a char argument must render as a char literal, since Append(58) binds to the int overload and appends digits; got:\n{object_writer}"
    );
    let parse: String = body_in_type(&asm, "EdgeCases.ConfigParser", "Parse");
    assert!(
        parse.contains("new System.Char[1] { '\\u000A' }"),
        "a char array element must render as a char literal; got:\n{parse}"
    );
    assert!(
        parse.contains("local2 = 0;") && parse.contains("local2 = local2 + 1;"),
        "an int local must keep its integer stores; got:\n{parse}"
    );
}

#[test]
fn decompile_remains_lossless_after_bool_return_canon() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after bool-return canonicalization; got {} failures",
        asm.methods_failed
    );
}
