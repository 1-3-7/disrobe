#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use disrobe_pass_dotnet::cil::{MethodBody, disassemble};
use disrobe_pass_dotnet::model::IsInstTargetKind;
use disrobe_pass_dotnet::structurize::{CallInfo, TokenNamer, decompile_method};

struct ValueTypeNamer;

impl TokenNamer for ValueTypeNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "Money".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        match token {
            0x0100_0001 => IsInstTargetKind::ValueType,
            _ => IsInstTargetKind::Unsupported,
        }
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

fn body_from(code: &[u8]) -> MethodBody {
    MethodBody {
        max_stack: 8,
        code_size: u32::try_from(code.len()).expect("method body size"),
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: disassemble(code).expect("disassemble isinst body"),
        exception_clauses: Vec::new(),
    }
}

fn run_probe(directory: &Path, source: &str) -> Output {
    std::fs::write(
        directory.join("RetainedIsInst.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings><GenerateAssemblyInfo>false</GenerateAssemblyInfo><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup></Project>",
    )
    .expect("write retained-isinst project");
    std::fs::write(directory.join("RetainedIsInst.cs"), source)
        .expect("write retained-isinst source");
    Command::new("dotnet")
        .args(["run", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(directory)
        .output()
        .expect("run retained-isinst oracle")
}

#[test]
fn retained_value_type_isinst_preserves_boxed_identity_and_nulls() {
    let version: Output = Command::new("dotnet")
        .arg("--version")
        .output()
        .expect("run dotnet --version");
    assert!(
        version.status.success(),
        "dotnet --version failed:\n{}",
        String::from_utf8_lossy(&version.stderr)
    );

    let mut code: Vec<u8> = vec![0x02, 0x75];
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.push(0x2A);
    let recovered: String = decompile_method(
        "object Probe(object arg1)",
        &body_from(&code),
        &ValueTypeNamer,
    )
    .body;
    let source: String = format!(
        "public struct Money\n{{\n    public int Value;\n}}\n\npublic static class Program\n{{\n    public static {recovered}\n\n    public static int Main()\n    {{\n        object boxed = new Money {{ Value = 37 }};\n        object matched = Probe(boxed);\n        if (!object.ReferenceEquals(boxed, matched))\n        {{\n            return 1;\n        }}\n        if (Probe(new object()) is not null)\n        {{\n            return 2;\n        }}\n        if (Probe(null) is not null)\n        {{\n            return 3;\n        }}\n        return 0;\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_retained_value_type_isinst")
            .expect("create retained-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "recovered retained value-type isinst must preserve boxed identity and null behavior:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let retained_expression: &str = "((object)arg1 is var __disrobe_isinst_0001 && __disrobe_isinst_0001 is Money ? __disrobe_isinst_0001 : null)";
    assert!(
        source.contains(retained_expression),
        "the retained-isinst mutation must target the recovered expression:\n{source}"
    );
    let identity_mutation: &str = "((object)arg1 is var __disrobe_isinst_0001 && __disrobe_isinst_0001 is Money ? (object)new Money() : null)";
    let mutated: String = source.replacen(retained_expression, identity_mutation, 1);
    assert_ne!(
        mutated, source,
        "the retained-isinst identity mutation must apply"
    );
    let mutated_output: Output = run_probe(scratch.path(), &mutated);
    assert_eq!(
        mutated_output.status.code(),
        Some(1),
        "the identity mutation must be rejected by the CLR oracle:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}

struct CallOrderNamer;

impl TokenNamer for CallOrderNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "Money".to_owned(),
            0x0A00_0001 => "Program::First".to_owned(),
            0x0A00_0002 => "Program::Second".to_owned(),
            0x0A00_0003 => "Program::Consume".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        match token {
            0x0100_0001 => IsInstTargetKind::ValueType,
            _ => IsInstTargetKind::Unsupported,
        }
    }

    fn call_info(&self, token: u32) -> Option<CallInfo> {
        match token {
            0x0A00_0001 | 0x0A00_0002 => Some(CallInfo {
                arg_count: 0,
                returns_value: true,
                has_this: false,
                byref_param_mask: 0,
            }),
            0x0A00_0003 => Some(CallInfo {
                arg_count: 2,
                returns_value: true,
                has_this: false,
                byref_param_mask: 0,
            }),
            _ => None,
        }
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

#[test]
fn retained_value_type_isinst_keeps_left_to_right_call_order() {
    let mut code: Vec<u8> = Vec::new();
    for token in [0x0A00_0001u32, 0x0A00_0002] {
        code.push(0x28);
        code.extend_from_slice(&token.to_le_bytes());
    }
    code.push(0x75);
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.push(0x28);
    code.extend_from_slice(&0x0A00_0003u32.to_le_bytes());
    code.push(0x2A);
    let recovered: String =
        decompile_method("int Probe()", &body_from(&code), &CallOrderNamer).body;
    let source: String = format!(
        "public struct Money\n{{\n    public int Value;\n}}\n\npublic static class Program\n{{\n    private static string Trace = \"\";\n    private static readonly object Boxed = new Money {{ Value = 37 }};\n\n    public static object First()\n    {{\n        Trace += \"1\";\n        return new object();\n    }}\n\n    public static object Second()\n    {{\n        Trace += \"2\";\n        return Boxed;\n    }}\n\n    public static int Consume(object first, object second)\n    {{\n        Trace += \"3\";\n        return object.ReferenceEquals(second, Boxed) ? 0 : 1;\n    }}\n\n    public static {recovered}\n\n    public static int Main()\n    {{\n        return Probe() == 0 && Trace == \"123\" ? 0 : 1;\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_retained_value_type_isinst_order")
            .expect("create retained-isinst order scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "retained value-type isinst must preserve evaluation order and boxed identity:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_return: &str = "return Program.Consume(First(), ((object)Program.Second() is var __disrobe_isinst_000A && __disrobe_isinst_000A is Money ? __disrobe_isinst_000A : null));";
    assert!(
        recovered.contains(expected_return),
        "the call-order mutation must target the recovered return:\n{recovered}"
    );
    let hoisted_return: &str = "object __disrobe_hoisted = Program.Second();\n        return Program.Consume(First(), ((object)__disrobe_hoisted is var __disrobe_isinst_000A && __disrobe_isinst_000A is Money ? __disrobe_isinst_000A : null));";
    let hoisted: String = recovered.replacen(expected_return, hoisted_return, 1);
    assert_ne!(hoisted, recovered, "the call-order mutation must apply");
    let mutated_source: String = source.replacen(&recovered, &hoisted, 1);
    let mutated_output: Output = run_probe(scratch.path(), &mutated_source);
    assert_eq!(
        mutated_output.status.code(),
        Some(1),
        "hoisting the second operand must expose the reversed trace:\nstdout:\n{}\nstderr:\n{}\nsource:\n{mutated_source}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}

struct RenderableUnknownTargetNamer;

impl TokenNamer for RenderableUnknownTargetNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "ExternalStruct".to_owned(),
            0x0100_0002 => "ExternalClass".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        match token {
            0x0100_0001 | 0x0100_0002 => IsInstTargetKind::RenderableUnknown,
            _ => IsInstTargetKind::Unsupported,
        }
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

#[test]
fn retained_renderable_unknown_isinst_preserves_object_boundary() {
    let mut struct_code: Vec<u8> = vec![0x02, 0x75];
    struct_code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    struct_code.push(0x2A);
    let struct_recovered: String = decompile_method(
        "object StructProbe(object arg1)",
        &body_from(&struct_code),
        &RenderableUnknownTargetNamer,
    )
    .body;

    let mut class_code: Vec<u8> = vec![0x02, 0x75];
    class_code.extend_from_slice(&0x0100_0002u32.to_le_bytes());
    class_code.push(0x2A);
    let class_recovered: String = decompile_method(
        "object ClassProbe(object arg1)",
        &body_from(&class_code),
        &RenderableUnknownTargetNamer,
    )
    .body;

    assert!(
        struct_recovered.contains(" is ExternalStruct")
            && class_recovered.contains(" is ExternalClass")
            && !struct_recovered.contains("__unresolved_isinst_target")
            && !class_recovered.contains("__unresolved_isinst_target"),
        "renderable unknown targets must use a C# type test:\nstruct:\n{struct_recovered}\nclass:\n{class_recovered}"
    );
    let source: String = format!(
        "public struct ExternalStruct\n{{\n    public int Value;\n}}\n\npublic sealed class ExternalClass\n{{\n    public int Value;\n}}\n\npublic static class Program\n{{\n    public static {struct_recovered}\n\n    public static {class_recovered}\n\n    public static int Main()\n    {{\n        object boxed = new ExternalStruct {{ Value = 7 }};\n        ExternalClass reference = new ExternalClass {{ Value = 11 }};\n        if (!object.ReferenceEquals(boxed, StructProbe(boxed)))\n        {{\n            return 1;\n        }}\n        if (StructProbe(new object()) is not null)\n        {{\n            return 2;\n        }}\n        if (!object.ReferenceEquals(reference, ClassProbe(reference)))\n        {{\n            return 3;\n        }}\n        return ClassProbe(new object()) is null ? 0 : 4;\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_retained_renderable_unknown_isinst")
            .expect("create retained-renderable-unknown-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "retained renderable-unknown isinst must preserve value and reference object boundaries:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen(" is ExternalStruct", " is ExternalClass", 1);
    assert_ne!(mutated, source, "the retained-isinst mutation must apply");
    let mutated_output: Output = run_probe(scratch.path(), &mutated);
    assert!(
        !mutated_output.status.success(),
        "the retained-isinst control must reject a mismatched type test:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}

struct UnsupportedTargetNamer;

impl TokenNamer for UnsupportedTargetNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "!!0".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, _token: u32) -> IsInstTargetKind {
        IsInstTargetKind::Unsupported
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

#[test]
fn retained_unsupported_isinst_refuses_without_rendering_its_target() {
    let mut code: Vec<u8> = vec![0x02, 0x75];
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.push(0x2A);
    let recovered: String = decompile_method(
        "object Probe(object arg1)",
        &body_from(&code),
        &UnsupportedTargetNamer,
    )
    .body;
    let refusal: &str = "(new System.Func<object, dynamic>((object _) => { throw new System.NotSupportedException(\"__unresolved_isinst_target\"); }))((object)arg1)";
    assert!(
        recovered.contains(refusal) && !recovered.contains("!!0"),
        "a retained unsupported isinst must use a target-independent refusal:\n{recovered}"
    );
    let source: String = format!(
        "public static class Program\n{{\n    public static {recovered}\n\n    public static int Main()\n    {{\n        try\n        {{\n            _ = Probe(new object());\n            return 1;\n        }}\n        catch (System.NotSupportedException)\n        {{\n            return 0;\n        }}\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_retained_unsupported_isinst")
            .expect("create retained-unsupported-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "retained unsupported isinst must compile and refuse explicitly:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen(refusal, "((object)arg1) is !!0", 1);
    assert_ne!(
        mutated, source,
        "the retained-unsupported mutation must apply"
    );
    let mutated_output: Output = run_probe(scratch.path(), &mutated);
    assert!(
        !mutated_output.status.success(),
        "rendering an unsupported target must fail C# compilation:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}

struct NullableTargetNamer;

impl TokenNamer for NullableTargetNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "System.Nullable<int>".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, _token: u32) -> IsInstTargetKind {
        IsInstTargetKind::Unsupported
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

#[test]
fn direct_unsupported_nullable_isinst_refuses_before_csharp_rejects_the_pattern() {
    let mut code: Vec<u8> = vec![0x02, 0x75];
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.extend_from_slice(&[0x2C, 0x02, 0x17, 0x2A, 0x16, 0x2A]);
    let recovered: String = decompile_method(
        "int Probe(object arg1)",
        &body_from(&code),
        &NullableTargetNamer,
    )
    .body;
    let refusal: &str = "(new System.Func<object, bool>((object _) => { throw new System.NotSupportedException(\"__unresolved_isinst_target\"); }))((object)arg1)";
    assert!(
        recovered.contains(refusal) && !recovered.contains("System.Nullable<int>"),
        "a direct unsupported isinst must use a target-independent refusal:\n{recovered}"
    );
    let source: String = format!(
        "public static class Program\n{{\n    public static {recovered}\n\n    public static int Main()\n    {{\n        try\n        {{\n            _ = Probe(new object());\n            return 1;\n        }}\n        catch (System.NotSupportedException)\n        {{\n            return 0;\n        }}\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_direct_unsupported_nullable_isinst")
            .expect("create direct-unsupported-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "direct unsupported nullable isinst must compile and refuse explicitly:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ReferenceTargetNamer;

impl TokenNamer for ReferenceTargetNamer {
    fn name(&self, token: u32) -> String {
        match token {
            0x0100_0001 => "Target".to_owned(),
            other => format!("token_{other:08X}"),
        }
    }

    fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        match token {
            0x0100_0001 => IsInstTargetKind::ReferenceType,
            _ => IsInstTargetKind::Unsupported,
        }
    }

    fn outer_has_this(&self) -> bool {
        false
    }
}

#[test]
fn direct_isinst_casts_a_sealed_operand_to_object_before_testing() {
    let mut code: Vec<u8> = vec![0x02, 0x75];
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.extend_from_slice(&[0x2C, 0x02, 0x17, 0x2A, 0x16, 0x2A]);
    let recovered: String = decompile_method(
        "int Probe(SealedSource arg1)",
        &body_from(&code),
        &ReferenceTargetNamer,
    )
    .body;
    let predicate: &str = "((object)arg1) is Target";
    assert!(
        recovered.contains(predicate),
        "direct isinst must retain the CLR object boundary:\n{recovered}"
    );
    let source: String = format!(
        "public sealed class SealedSource {{ }}\npublic sealed class Target {{ }}\n\npublic static class Program\n{{\n    public static {recovered}\n\n    public static int Main()\n    {{\n        return Probe(new SealedSource()) == 0 ? 0 : 1;\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_direct_isinst_object_boundary")
            .expect("create direct-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "direct isinst must compile for sealed unrelated types:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen(predicate, "arg1 is Target", 1);
    assert_ne!(
        mutated, source,
        "the direct-isinst boundary mutation must apply"
    );
    let mutated_output: Output = run_probe(scratch.path(), &mutated);
    assert!(
        !mutated_output.status.success(),
        "without the object boundary, sealed unrelated types must fail C# compilation:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
    let diagnostics: String = format!(
        "{}{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
    assert!(
        diagnostics.contains("CS0184"),
        "the direct-isinst mutation must fail for the sealed-type pattern:\n{diagnostics}"
    );
}

#[test]
fn retained_reference_isinst_casts_a_sealed_operand_to_object_before_as() {
    let mut code: Vec<u8> = vec![0x02, 0x75];
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.push(0x2A);
    let recovered: String = decompile_method(
        "Target Probe(SealedSource arg1)",
        &body_from(&code),
        &ReferenceTargetNamer,
    )
    .body;
    let expression: &str = "((object)arg1) as Target";
    assert!(
        recovered.contains(expression),
        "retained reference isinst must retain the CLR object boundary:\n{recovered}"
    );
    let source: String = format!(
        "public sealed class SealedSource {{ }}\npublic sealed class Target {{ }}\n\npublic static class Program\n{{\n    public static {recovered}\n\n    public static int Main()\n    {{\n        return Probe(new SealedSource()) is null ? 0 : 1;\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_retained_reference_isinst_boundary")
            .expect("create retained-reference-isinst scratch directory");
    let output: Output = run_probe(scratch.path(), &source);
    assert!(
        output.status.success(),
        "retained reference isinst must compile for sealed unrelated types:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen(expression, "arg1 as Target", 1);
    assert_ne!(
        mutated, source,
        "the retained-reference boundary mutation must apply"
    );
    let mutated_output: Output = run_probe(scratch.path(), &mutated);
    assert!(
        !mutated_output.status.success(),
        "without the object boundary, sealed unrelated reference types must fail C# compilation:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
    let diagnostics: String = format!(
        "{}{}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
    assert!(
        diagnostics.contains("CS0039"),
        "the retained-reference mutation must fail for the sealed-type as-expression:\n{diagnostics}"
    );
}
