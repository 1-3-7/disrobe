#![cfg(feature = "chain")]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::aot::{AotReport, AotRuntime, ReadyToRunHeader, detect};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/managed_abi_net9_x86_64.exe");
const SOURCE: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.csproj.txt");
const BUILD: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.build.txt");
const LINK_MAP: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.unwind.txt");
const DISASM: &str = include_str!("fixtures/native_aot/managed_abi_net9_x86_64.disasm.txt");
const LINK_SYMBOL_PREFIX: &str = "managed_abi_net9_x86_64_ManagedAbiProbe__";
const DECLARING_TYPE: &str = "ManagedAbiProbe";
const AMD64_MACHINE: u16 = 0x8664;
const PROBE_METHODS: [&str; 7] = [
    "Add",
    "Negate",
    "Widen",
    "IsPositive",
    "Mask",
    "Blend",
    "Scale",
];
const MANAGED_TO_C: [(&str, &str); 12] = [
    ("System.Boolean", "bool"),
    ("System.SByte", "int8_t"),
    ("System.Byte", "uint8_t"),
    ("System.Int16", "int16_t"),
    ("System.UInt16", "uint16_t"),
    ("System.Char", "uint16_t"),
    ("System.Int32", "int32_t"),
    ("System.UInt32", "uint32_t"),
    ("System.Int64", "int64_t"),
    ("System.UInt64", "uint64_t"),
    ("System.IntPtr", "intptr_t"),
    ("System.UIntPtr", "uintptr_t"),
];
const EXPECTED_BODIES: [(&str, &str); 7] = [
    (
        "Add",
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx + r_rdx * 1ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Negate",
        "#include <stdint.h>\nint32_t recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx) & 0xffffffffULL;\n    r_rax = ((uint64_t)-(int64_t)r_rax) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Widen",
        "#include <stdint.h>\nint64_t recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = (uint64_t)(int64_t)(int32_t)((r_rcx) & 0xffffffffULL);\n    return (int64_t)(uint64_t)(r_rax);\n}\n",
    ),
    (
        "IsPositive",
        "#include <stdbool.h>\n#include <stdint.h>\nbool recovered(int32_t a0) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rax = 0;\n    r_rax = r_rax & 0xffffffffffffff00ULL | (uint64_t)(((int64_t)(int32_t)(r_rcx) > 0) ? 1 : 0);\n    r_rax = ((uint32_t)(uint8_t)((r_rax) & 0xffULL)) & 0xffffffffULL;\n    return (bool)(uint8_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Mask",
        "#include <stdint.h>\nuint32_t recovered(uint32_t a0, uint8_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rcx) & 0xffffffffULL;\n    r_rcx = ((uint32_t)(uint8_t)((r_rdx) & 0xffULL)) & 0xffffffffULL;\n    r_rax = ((r_rax & 0xffffffffULL) >> (((r_rcx & 0xffULL)) & 31)) & 0xffffffffULL;\n    return (uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Blend",
        "#include <stdint.h>\nint32_t recovered(int32_t a0, int32_t a1, int32_t a2, int32_t a3) {\n    uint64_t r_rcx = (uint32_t)a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_r8 = (uint32_t)a2;\n    uint64_t r_r9 = (uint32_t)a3;\n    uint64_t r_rax = 0;\n    r_rdx = (r_rdx + (r_rdx)) & 0xffffffffULL;\n    r_rcx = (r_rcx + (r_rdx)) & 0xffffffffULL;\n    r_rax = (r_r8 + r_r8 * 2ULL) & 0xffffffffULL;\n    r_rax = (r_rax + (r_rcx)) & 0xffffffffULL;\n    r_rax = (r_rax + r_r9 * 4ULL) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
    (
        "Scale",
        "#include <stdint.h>\nint32_t recovered(uintptr_t a0, int32_t a1) {\n    uint64_t r_rcx = a0;\n    uint64_t r_rdx = (uint32_t)a1;\n    uint64_t r_rax = 0;\n    r_rax = (r_rdx) & 0xffffffffULL;\n    r_rax = (r_rax * ((uint64_t)(*(uint32_t*)(uintptr_t)(r_rcx + (uint64_t)(int64_t)8LL)))) & 0xffffffffULL;\n    return (int32_t)(uint32_t)((r_rax) & 0xffffffffULL);\n}\n",
    ),
];

fn compiler_load_address() -> Result<u64, &'static str> {
    let text: &str = LINK_MAP
        .lines()
        .find_map(|line: &str| {
            line.split_once("Preferred load address is ")
                .map(|(_head, value): (&str, &str)| value)
        })
        .ok_or("compiler map load address is absent")?;
    u64::from_str_radix(text.trim(), 16)
        .map_err(|_: std::num::ParseIntError| "compiler map load address is malformed")
}

fn compiler_method_rva(method: &str) -> Result<u32, &'static str> {
    let symbol: String = format!("{LINK_SYMBOL_PREFIX}{method}");
    let address_text: &str = LINK_MAP
        .lines()
        .find_map(|line: &str| {
            let mut fields: std::str::SplitWhitespace<'_> = line.split_whitespace();
            let _section: &str = fields.next()?;
            if fields.next()? != symbol {
                return None;
            }
            fields.next()
        })
        .ok_or("compiler map method address is absent")?;
    let address: u64 = u64::from_str_radix(address_text, 16)
        .map_err(|_: std::num::ParseIntError| "compiler map method address is malformed")?;
    let rva: u64 = address
        .checked_sub(compiler_load_address()?)
        .ok_or("compiler map address precedes the image base")?;
    u32::try_from(rva).map_err(|_: std::num::TryFromIntError| "compiler map RVA does not fit u32")
}

fn evidence_range(method: &str) -> Result<(u32, u32), &'static str> {
    let symbol: String = format!("{LINK_SYMBOL_PREFIX}{method}");
    let mut found: Option<(u32, u32)> = None;
    for line in UNWIND.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 || *fields.last().unwrap_or(&"") != symbol {
            continue;
        }
        let begin: u32 = u32::from_str_radix(fields.get(1).unwrap_or(&""), 16)
            .map_err(|_: std::num::ParseIntError| "unwind begin RVA is malformed")?;
        let end: u32 = u32::from_str_radix(fields.get(2).unwrap_or(&""), 16)
            .map_err(|_: std::num::ParseIntError| "unwind end RVA is malformed")?;
        if found.is_some() {
            return Err("unwind evidence names the method more than once");
        }
        found = Some((begin, end));
    }
    found.ok_or("unwind evidence for the method is absent")
}

fn evidence_bytes(method: &str) -> Result<Vec<u8>, &'static str> {
    let header: String = format!("# {DECLARING_TYPE}.{method} [");
    let mut bytes: Vec<u8> = Vec::new();
    let mut inside: bool = false;
    for line in DISASM.lines() {
        if line.starts_with('#') {
            if inside {
                break;
            }
            inside = line.starts_with(header.as_str());
            continue;
        }
        if !inside {
            continue;
        }
        let (_address, remainder): (&str, &str) = line
            .split_once(':')
            .ok_or("disassembly evidence line has no address")?;
        let encoded: &str = remainder
            .split('\t')
            .next()
            .ok_or("disassembly evidence line has no encoding")?;
        for token in encoded.split_whitespace() {
            bytes.push(
                u8::from_str_radix(token, 16)
                    .map_err(|_: std::num::ParseIntError| "disassembly byte is malformed")?,
            );
        }
    }
    if bytes.is_empty() {
        return Err("disassembly evidence for the method is absent");
    }
    Ok(bytes)
}

fn declared_managed_signature(
    method: &str,
) -> Result<(bool, &'static str, Vec<&'static str>), &'static str> {
    let prefix: String = format!("{DECLARING_TYPE}.{method} managed signature: ");
    let declaration: &str = BUILD
        .lines()
        .find_map(|line: &str| line.strip_prefix(prefix.as_str()))
        .ok_or("build evidence does not declare the managed signature")?;
    let (kind, remainder): (&str, &str) = declaration
        .split_once(' ')
        .ok_or("declared managed signature has no receiver kind")?;
    let has_this: bool = match kind {
        "instance" => true,
        "static" => false,
        _other => return Err("declared managed signature has an unknown receiver kind"),
    };
    let (return_type, remainder): (&str, &str) = remainder
        .split_once(' ')
        .ok_or("declared managed signature has no return type")?;
    let parameters: &str = remainder
        .split_once('(')
        .and_then(|(_name, tail): (&str, &str)| tail.strip_suffix(')'))
        .ok_or("declared managed signature has no parameter list")?;
    let mut managed: Vec<&'static str> = Vec::new();
    for parameter in parameters
        .split(',')
        .map(str::trim)
        .filter(|parameter: &&str| !parameter.is_empty())
    {
        managed.push(c_type_for(parameter)?);
    }
    Ok((has_this, c_type_for(return_type)?, managed))
}

fn c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    MANAGED_TO_C
        .iter()
        .find(|(name, _rendered): &&(&str, &str)| *name == managed)
        .map(|(_name, rendered): &(&str, &str)| *rendered)
        .ok_or("the declared managed type has no C99 equivalent in this grader")
}

fn expected_prototype(method: &str) -> Result<String, &'static str> {
    let (has_this, return_type, parameters): (bool, &'static str, Vec<&'static str>) =
        declared_managed_signature(method)?;
    let mut slots: Vec<&'static str> = Vec::new();
    if has_this {
        slots.push("uintptr_t");
    }
    slots.extend(parameters);
    let rendered: String = slots
        .iter()
        .enumerate()
        .map(|(index, slot): (usize, &&'static str)| format!("{slot} a{index}"))
        .collect::<Vec<String>>()
        .join(", ");
    let includes: &str = if return_type == "bool" || slots.contains(&"bool") {
        "#include <stdbool.h>\n#include <stdint.h>\n"
    } else {
        "#include <stdint.h>\n"
    };
    Ok(format!(
        "{includes}{return_type} recovered({rendered}) {{\n"
    ))
}

fn auto_document() -> Result<serde_json::Value, &'static str> {
    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = DOTNET_PASS.run(&input).map_err(
        |_: disrobe_core::error::CoreError| "the auto route refused the NativeAOT image",
    )?;
    serde_json::from_slice(&output.envelope)
        .map_err(|_: serde_json::Error| "the NativeAOT artifact is not JSON")
}

fn method_record<'document>(
    document: &'document serde_json::Value,
    declaring_type: &str,
    name: &str,
) -> Result<&'document serde_json::Value, &'static str> {
    document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == declaring_type && method["name"] == name
            })
        })
        .ok_or("the compiler-emitted method is absent from the auto artifact")
}

#[test]
fn the_fixture_carries_the_compiler_evidence_it_is_graded_against() -> Result<(), &'static str> {
    assert!(SOURCE.contains("public static int Add(int left, int right) => left + right;"));
    assert!(SOURCE.contains("public static long Widen(int value) => value;"));
    assert!(SOURCE.contains("public static bool IsPositive(int value) => value > 0;"));
    assert!(SOURCE.contains("public static uint Mask(uint value, byte shift) => value >> shift;"));
    assert!(SOURCE.contains("public int Scale(int value) => value * this.factor;"));
    assert!(PROJECT.contains("<TargetFramework>net9.0</TargetFramework>"));
    assert!(PROJECT.contains("<PublishAot>true</PublishAot>"));
    assert!(BUILD.contains("Compiler: Microsoft.DotNet.ILCompiler 9.0.18"));
    assert!(BUILD.contains("HASTHIS 0x20"));

    let pe: PeImage =
        parse(IMAGE).map_err(|_: disrobe_pass_dotnet::Error| "the fixture is not a PE image")?;
    assert_eq!(
        (pe.bitness, pe.machine),
        (PeBitness::Pe32Plus, AMD64_MACHINE)
    );
    assert_eq!(pe.image_base, compiler_load_address()?);
    for method in PROBE_METHODS {
        let start_rva: u32 = compiler_method_rva(method)?;
        let (begin, end): (u32, u32) = evidence_range(method)?;
        assert_eq!(begin, start_rva, "{method}");
        let bytes: Vec<u8> = evidence_bytes(method)?;
        assert_eq!(
            u32::try_from(bytes.len())
                .map_err(|_: std::num::TryFromIntError| "evidence byte count does not fit u32")?,
            end.checked_sub(begin)
                .ok_or("the unwind range for the method is reversed")?,
            "{method}"
        );
        let offset: usize = pe
            .rva_to_offset(start_rva)
            .ok_or("the compiler method body is not file backed")?;
        let end_offset: usize = offset
            .checked_add(bytes.len())
            .ok_or("the compiler method body end overflowed")?;
        assert_eq!(
            IMAGE.get(offset..end_offset),
            Some(bytes.as_slice()),
            "{method}"
        );
    }
    Ok(())
}

#[test]
fn auto_reattaches_every_declared_managed_signature_to_its_body() -> Result<(), &'static str> {
    let document: serde_json::Value = auto_document()?;
    assert_eq!(document["schema"], "disrobe.dotnet.native-aot-symbols/v1");
    assert_eq!(document["runtime"], "net9");

    for method_name in PROBE_METHODS {
        let method: &serde_json::Value = method_record(&document, DECLARING_TYPE, method_name)?;
        let start_rva: u32 = compiler_method_rva(method_name)?;
        let (begin, end): (u32, u32) = evidence_range(method_name)?;
        assert_eq!(method["entrypoint_rva"], start_rva, "{method_name}");
        assert_eq!(method["code_range"]["start_rva"], begin, "{method_name}");
        assert_eq!(method["code_range"]["end_rva"], end, "{method_name}");
        assert_eq!(method["body"]["status"], "recovered", "{method_name}");
        let pseudo_c: &str = method["body"]["pseudo_c"]
            .as_str()
            .ok_or("the recovered body carries no pseudo-C")?;
        assert!(
            pseudo_c.starts_with(expected_prototype(method_name)?.as_str()),
            "{method_name}: {pseudo_c}"
        );
        let expected: &str = EXPECTED_BODIES
            .iter()
            .find(|(name, _body): &&(&str, &str)| *name == method_name)
            .map(|(_name, body): &(&str, &str)| *body)
            .ok_or("the graded body for the method is absent")?;
        assert_eq!(pseudo_c, expected, "{method_name}");
    }
    Ok(())
}

#[test]
fn a_signature_outside_the_primitive_table_keeps_the_register_typed_body()
-> Result<(), &'static str> {
    let document: serde_json::Value = auto_document()?;
    let reference_equals: &serde_json::Value =
        method_record(&document, "System.Object", "ReferenceEquals")?;
    assert_eq!(
        reference_equals["signature"]["calling_convention"], 0,
        "System.Object.ReferenceEquals is a static two-reference comparison"
    );
    assert_eq!(
        reference_equals["signature"]["parameter_types"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let pseudo_c: &str = reference_equals["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")?;

    assert!(
        pseudo_c
            .starts_with("#include <stdint.h>\nuint64_t recovered(uint64_t a0, uint64_t a1) {\n"),
        "an object-reference signature must keep the register-typed prototype: {pseudo_c}"
    );
    Ok(())
}

#[test]
fn the_runtime_label_comes_from_the_metadata_version_not_a_build_path() -> Result<(), &'static str>
{
    assert!(
        !IMAGE.windows(6).any(|window: &[u8]| window == b"net9.0"),
        "this fixture must not carry a target-framework marker string"
    );
    let report: AotReport = detect(IMAGE);
    let header: ReadyToRunHeader = report
        .ready_to_run
        .clone()
        .ok_or("the NativeAOT header is absent")?;
    assert_eq!((header.major_version, header.minor_version), (10, 1));
    assert_eq!(report.runtime_label, AotRuntime::Net9);

    let major_offset: usize = usize::try_from(header.file_offset)
        .map_err(|_: std::num::TryFromIntError| "the header offset does not fit usize")?
        .checked_add(4)
        .ok_or("the header major-version offset overflowed")?;
    let major_end: usize = major_offset
        .checked_add(2)
        .ok_or("the header major-version end overflowed")?;
    let mut unlisted: Vec<u8> = IMAGE.to_vec();
    unlisted
        .get_mut(major_offset..major_end)
        .ok_or("the header major-version field is truncated")?
        .copy_from_slice(&11u16.to_le_bytes());
    let unlisted_report: AotReport = detect(&unlisted);

    assert_eq!(
        unlisted_report
            .ready_to_run
            .as_ref()
            .map(|header: &ReadyToRunHeader| header.major_version),
        Some(11)
    );
    assert_eq!(unlisted_report.runtime_label, AotRuntime::Unknown);
    Ok(())
}
