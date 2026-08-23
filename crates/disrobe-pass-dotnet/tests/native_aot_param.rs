#![cfg(feature = "chain")]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/managed_abi_param_net9_x86_64.exe");
const SOURCE: &str = include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.csproj.txt");
const BUILD: &str = include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.build.txt");
const LINK_MAP: &str =
    include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.unwind.txt");
const DISASM: &str = include_str!("fixtures/native_aot/managed_abi_param_net9_x86_64.disasm.txt");

const AMD64_MACHINE: u16 = 0x8664;
const DECLARING_TYPE: &str = "ManagedParamProbe";
const LINK_SYMBOL_PREFIX: &str = "managed_abi_param_net9_x86_64_ManagedParamProbe__";
const STDINT_INCLUDE: &str = "#include <stdint.h>\n";
const INSTANCE_REFERENCE_C_TYPE: &str = "uintptr_t";
const LIFTED_PARAMETER_TYPE: &str = "uint64_t";

const MANAGED_TO_C: [(&str, &str); 15] = [
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
    ("System.Single", "float"),
    ("System.Double", "double"),
    ("System.Void", "void"),
];

const PROBE_METHODS: [&str; 8] = [
    "_ctor", "Sum", "Scale", "Wide", "Echo", "Narrow", "Blend", "Weighted",
];

const INDIRECT_PARAMETERS: [(&str, &str); 6] = [
    ("Sum", "ManagedPair"),
    ("Scale", "ManagedPair"),
    ("Wide", "ManagedTriple"),
    ("Echo", "ManagedPair"),
    ("Blend", "ManagedMixed"),
    ("Weighted", "ManagedPair"),
];

const AGGREGATE_EVIDENCED: [&str; 5] = ["Sum", "Scale", "Wide", "Blend", "Weighted"];

const DECLARED_ABSTENTIONS: [(&str, &str); 1] = [("Narrow", "type-outside-primitive-table")];

const MANAGED_SIGNATURE_METHODS: [&str; 7] =
    ["_ctor", "Sum", "Scale", "Wide", "Echo", "Blend", "Weighted"];

type DeclaredField = (String, String);
type DeclaredLayout = (Vec<DeclaredField>, usize);

fn c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    MANAGED_TO_C
        .iter()
        .find(|(candidate, _rendered): &&(&str, &str)| *candidate == managed)
        .map(|(_candidate, rendered): &(&str, &'static str)| *rendered)
        .ok_or("the declared managed type has no C99 equivalent in the independent mapping")
}

fn is_system_scalar(managed: &str) -> bool {
    MANAGED_TO_C
        .iter()
        .any(|(candidate, _rendered): &(&str, &str)| *candidate == managed)
}

fn build_line(prefix: &str) -> Result<&'static str, &'static str> {
    let mut found: Option<&'static str> = None;
    for line in BUILD.lines() {
        let Some(rest): Option<&str> = line.strip_prefix(prefix) else {
            continue;
        };
        if found.is_some() {
            return Err("the build record states the same fact twice");
        }
        found = Some(rest.trim());
    }
    found.ok_or("the build record does not state this fact")
}

fn declared_managed_signature(method: &str) -> Result<(bool, String, Vec<String>), &'static str> {
    let stated: &str =
        build_line(format!("{DECLARING_TYPE}.{method} managed signature: ").as_str())?;
    let (kind, rest): (&str, &str) = stated
        .split_once(' ')
        .ok_or("the declared managed signature has no calling kind")?;
    let has_this: bool = match kind {
        "instance" => true,
        "static" => false,
        _ => return Err("the declared managed signature has an unknown calling kind"),
    };
    let (return_type, rest): (&str, &str) = rest
        .split_once(' ')
        .ok_or("the declared managed signature has no return type")?;
    let (_name, parameters): (&str, &str) = rest
        .split_once('(')
        .ok_or("the declared managed signature has no parameter list")?;
    let parameters: &str = parameters
        .strip_suffix(')')
        .ok_or("the declared managed signature parameter list is unterminated")?;
    let parameters: Vec<String> = if parameters.is_empty() {
        Vec::new()
    } else {
        parameters
            .split(',')
            .map(|entry: &str| entry.trim().to_owned())
            .collect()
    };
    Ok((has_this, return_type.to_owned(), parameters))
}

fn declared_layout(struct_name: &str) -> Result<DeclaredLayout, &'static str> {
    let stated: &str = build_line(format!("{struct_name} declared layout: ").as_str())?;
    let mut entries: Vec<&str> = stated.split(',').map(str::trim).collect();
    let size_entry: &str = entries.pop().ok_or("the declared layout states no size")?;
    let size: usize = size_entry
        .strip_suffix(" bytes")
        .ok_or("the declared layout size is not stated in bytes")?
        .parse::<usize>()
        .map_err(|_error: std::num::ParseIntError| "the declared layout size is not a number")?;
    if entries.first().copied() != Some("sequential") {
        return Err("the declared layout is not sequential");
    }
    let mut fields: Vec<DeclaredField> = Vec::new();
    for entry in entries.iter().skip(1) {
        let (managed, name): (&str, &str) = entry
            .split_once(' ')
            .ok_or("a declared field has no managed type and name")?;
        fields.push((managed.to_owned(), name.to_owned()));
    }
    Ok((fields, size))
}

fn expected_typedef(struct_name: &str) -> Result<String, &'static str> {
    let (fields, _size): DeclaredLayout = declared_layout(struct_name)?;
    let mut rendered: String = String::from("typedef struct {\n");
    for (managed, name) in &fields {
        rendered.push_str("    ");
        rendered.push_str(c_type_for(managed.as_str())?);
        rendered.push(' ');
        rendered.push_str(name.as_str());
        rendered.push_str(";\n");
    }
    rendered.push_str("} ");
    rendered.push_str(struct_name);
    rendered.push_str(";\n");
    Ok(rendered)
}

fn declared_offsets(struct_name: &str) -> Result<Vec<(usize, usize)>, &'static str> {
    let (fields, size): DeclaredLayout = declared_layout(struct_name)?;
    let mut placed: Vec<(usize, usize)> = Vec::new();
    let mut offset: usize = 0;
    for (managed, _name) in &fields {
        let width: usize = match c_type_for(managed.as_str())? {
            "bool" | "int8_t" | "uint8_t" => 1,
            "int16_t" | "uint16_t" => 2,
            "int32_t" | "uint32_t" | "float" => 4,
            _ => 8,
        };
        placed.push((offset, width));
        offset = offset
            .checked_add(width)
            .ok_or("the declared layout offset overflowed")?;
    }
    if offset != size {
        return Err("the declared field widths do not sum to the declared size");
    }
    Ok(placed)
}

fn expected_prototype(method: &str) -> Result<String, &'static str> {
    let (has_this, return_type, parameters): (bool, String, Vec<String>) =
        declared_managed_signature(method)?;
    let return_c: String = if is_system_scalar(return_type.as_str()) {
        c_type_for(return_type.as_str())?.to_owned()
    } else {
        return_type
    };
    let mut slots: Vec<String> = Vec::new();
    if has_this {
        slots.push(INSTANCE_REFERENCE_C_TYPE.to_owned());
    }
    for parameter in &parameters {
        if is_system_scalar(parameter.as_str()) {
            slots.push(c_type_for(parameter.as_str())?.to_owned());
        } else {
            slots.push(format!("{parameter} *"));
        }
    }
    let rendered: String = if slots.is_empty() {
        "void".to_owned()
    } else {
        slots
            .iter()
            .enumerate()
            .map(|(index, slot): (usize, &String)| {
                if slot.ends_with('*') {
                    format!("{slot}a{index}")
                } else {
                    format!("{slot} a{index}")
                }
            })
            .collect::<Vec<String>>()
            .join(", ")
    };
    Ok(format!("{return_c} recovered({rendered}) {{\n"))
}

fn compiler_load_address() -> Result<u64, &'static str> {
    LINK_MAP
        .lines()
        .find_map(|line: &str| {
            line.trim()
                .strip_prefix("Preferred load address is ")
                .and_then(|value: &str| u64::from_str_radix(value.trim(), 16).ok())
        })
        .ok_or("the link map does not state a preferred load address")
}

fn compiler_method_rva(method: &str) -> Result<u32, &'static str> {
    let symbol: String = format!("{LINK_SYMBOL_PREFIX}{method}");
    let base: u64 = compiler_load_address()?;
    let mut found: Option<u32> = None;
    for line in LINK_MAP.lines() {
        let mut fields: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let _section: Option<&str> = fields.next();
        if fields.next() != Some(symbol.as_str()) {
            continue;
        }
        let address: u64 = fields
            .next()
            .and_then(|value: &str| u64::from_str_radix(value, 16).ok())
            .ok_or("the link map symbol carries no address")?;
        let rva: u32 = u32::try_from(
            address
                .checked_sub(base)
                .ok_or("the link map address is below the load address")?,
        )
        .map_err(|_error: std::num::TryFromIntError| "the link map RVA does not fit u32")?;
        if found.is_some() {
            return Err("the link map names the same symbol twice");
        }
        found = Some(rva);
    }
    found.ok_or("the link map does not name the compiler-emitted method")
}

fn evidence_range(method: &str) -> Result<(u32, u32), &'static str> {
    let symbol: String = format!("{LINK_SYMBOL_PREFIX}{method}");
    let mut found: Option<(u32, u32)> = None;
    for line in UNWIND.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 || fields.get(4) != Some(&symbol.as_str()) {
            continue;
        }
        let begin: u32 = fields
            .get(1)
            .and_then(|value: &&str| u32::from_str_radix(value, 16).ok())
            .ok_or("the unwind record carries no begin RVA")?;
        let end: u32 = fields
            .get(2)
            .and_then(|value: &&str| u32::from_str_radix(value, 16).ok())
            .ok_or("the unwind record carries no end RVA")?;
        if found.is_some() {
            return Err("the unwind evidence names the same symbol twice");
        }
        found = Some((begin, end));
    }
    found.ok_or("the unwind evidence does not name the compiler-emitted method")
}

fn evidence_bytes(method: &str) -> Result<Vec<u8>, &'static str> {
    let header: String = format!("# {DECLARING_TYPE}.{method} [");
    let mut bytes: Vec<u8> = Vec::new();
    let mut inside: bool = false;
    for line in DISASM.lines() {
        if line.starts_with('#') {
            inside = line.starts_with(header.as_str());
            continue;
        }
        if !inside {
            continue;
        }
        let (_address, rest): (&str, &str) = line
            .split_once(':')
            .ok_or("a disassembly line carries no address")?;
        for token in rest.split_whitespace() {
            if token.len() != 2 {
                break;
            }
            let Ok(byte): Result<u8, std::num::ParseIntError> = u8::from_str_radix(token, 16)
            else {
                break;
            };
            bytes.push(byte);
        }
    }
    if bytes.is_empty() {
        return Err("the disassembly evidence carries no bytes for this method");
    }
    Ok(bytes)
}

fn document() -> Result<serde_json::Value, &'static str> {
    let input: Artifact = Artifact::new(Rung::Raw, IMAGE.to_vec(), [0u8; 32]);
    let output: Artifact = DOTNET_PASS.run(&input).map_err(
        |_error: disrobe_core::error::CoreError| "the auto route refused the NativeAOT image",
    )?;
    serde_json::from_slice(&output.envelope)
        .map_err(|_error: serde_json::Error| "the NativeAOT artifact is not JSON")
}

fn metadata_name(method: &str) -> &str {
    if method == "_ctor" { ".ctor" } else { method }
}

fn method_record<'document>(
    document: &'document serde_json::Value,
    name: &str,
) -> Result<&'document serde_json::Value, &'static str> {
    document["methods"]
        .as_array()
        .and_then(|methods: &Vec<serde_json::Value>| {
            methods.iter().find(|method: &&serde_json::Value| {
                method["declaring_type"] == DECLARING_TYPE && method["name"] == name
            })
        })
        .ok_or("the compiler-emitted method is absent from the auto artifact")
}

fn recovered_pseudo_c<'document>(
    document: &'document serde_json::Value,
    method: &str,
) -> Result<&'document str, &'static str> {
    method_record(document, metadata_name(method))?["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")
}

fn lifted_aggregate_offsets(pseudo_c: &str) -> Result<Vec<(usize, usize)>, &'static str> {
    let mut placed: Vec<(usize, usize)> = Vec::new();
    for line in pseudo_c.lines() {
        let trimmed: &str = line.trim();
        let Some(entry): Option<&str> = trimmed.strip_suffix(';') else {
            continue;
        };
        let Some((scalar, member)): Option<(&str, &str)> = entry.split_once(' ') else {
            continue;
        };
        let Some(offset_text): Option<&str> = member.strip_prefix("field_") else {
            continue;
        };
        let offset: usize = usize::from_str_radix(offset_text, 16)
            .map_err(|_error: std::num::ParseIntError| "a recovered member offset is not hex")?;
        let width: usize = match scalar {
            "uint8_t" => 1,
            "uint16_t" => 2,
            "uint32_t" => 4,
            "uint64_t" => 8,
            _ => return Err("a recovered member has an unexpected scalar type"),
        };
        placed.push((offset, width));
    }
    Ok(placed)
}

#[test]
fn the_fixture_carries_the_compiler_evidence_it_is_graded_against() -> Result<(), &'static str> {
    let pe: PeImage = parse(IMAGE)
        .map_err(|_error: disrobe_pass_dotnet::Error| "the fixture is not a PE image")?;
    assert_eq!(pe.machine, AMD64_MACHINE);
    assert_eq!(pe.bitness, PeBitness::Pe32Plus);
    assert_eq!(pe.image_base, compiler_load_address()?);
    assert!(
        SOURCE.contains("public static long Sum(ManagedPair pair)"),
        "the committed source declares the graded struct-parameter method"
    );
    assert!(
        SOURCE.contains("typeof(ManagedPair).GetFields("),
        "the committed source roots the field metadata the grade depends on"
    );
    assert!(
        PROJECT.contains("<PublishAot>true</PublishAot>"),
        "the committed project publishes NativeAOT"
    );

    for method in PROBE_METHODS {
        let rva: u32 = compiler_method_rva(method)?;
        let (begin, end): (u32, u32) = evidence_range(method)?;
        assert_eq!(
            rva, begin,
            "the compiler link map and the unwind evidence disagree on {method}"
        );
        assert!(end > begin, "the unwind range for {method} is not forward");
        let expected: Vec<u8> = evidence_bytes(method)?;
        let length: usize = usize::try_from(
            end.checked_sub(begin)
                .ok_or("the unwind range underflowed")?,
        )
        .map_err(|_error: std::num::TryFromIntError| "the unwind range does not fit usize")?;
        assert_eq!(
            expected.len(),
            length,
            "the disassembly evidence for {method} does not cover its unwind range"
        );
        let actual: &[u8] = pe
            .slice_exact_file_backed_rva(IMAGE, begin, length)
            .ok_or("the graded range is not file backed in the committed image")?;
        assert_eq!(
            actual, expected,
            "the committed image does not carry the disassembled bytes for {method}"
        );
    }
    Ok(())
}

#[test]
fn auto_attaches_the_declared_struct_to_an_indirect_parameter() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    let mut attached: usize = 0;
    for (method, struct_name) in INDIRECT_PARAMETERS {
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let expected: String = format!(
            "{STDINT_INCLUDE}{}{}",
            expected_typedef(struct_name)?,
            expected_prototype(method)?
        );
        assert!(
            pseudo_c.starts_with(expected.as_str()),
            "{method} must carry the parameter struct declared in the build record\n\
             expected prefix:\n{expected}\nrecovered:\n{pseudo_c}"
        );
        assert_eq!(
            method_record(&document, metadata_name(method))?["body"]["signature_source"],
            "managed",
            "{method} must record that its signature came from managed metadata"
        );
        attached = attached
            .checked_add(1)
            .ok_or("the attached count overflowed")?;
    }
    assert_eq!(
        attached,
        INDIRECT_PARAMETERS.len(),
        "every declared indirect parameter must reattach"
    );
    Ok(())
}

#[test]
fn the_reattached_parameter_replaces_the_lifted_register_type() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    for (method, struct_name) in INDIRECT_PARAMETERS {
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let (has_this, _return_type, _parameters): (bool, String, Vec<String>) =
            declared_managed_signature(method)?;
        let index: usize = usize::from(has_this);
        assert!(
            !pseudo_c.contains(format!("{LIFTED_PARAMETER_TYPE} a{index})").as_str())
                && !pseudo_c.contains(format!("{LIFTED_PARAMETER_TYPE} a{index},").as_str()),
            "{method} must not keep the register-typed parameter: {pseudo_c}"
        );
        assert!(
            pseudo_c.contains(format!("{struct_name} *a{index}").as_str()),
            "{method} must spell the parameter as a pointer to the declared struct: {pseudo_c}"
        );
        assert!(
            pseudo_c.contains(
                format!(" = ({LIFTED_PARAMETER_TYPE})({INSTANCE_REFERENCE_C_TYPE})a{index};\n")
                    .as_str()
            ),
            "{method} must convert the declared pointer where the lifter bound the register: \
             {pseudo_c}"
        );
        let (fields, _size): DeclaredLayout = declared_layout(struct_name)?;
        for (_managed, name) in &fields {
            assert!(
                pseudo_c.contains(format!(" {name};\n").as_str()),
                "{method} must carry the declared member {name}: {pseudo_c}"
            );
        }
    }
    Ok(())
}

#[test]
fn the_declared_layout_agrees_with_the_offsets_the_lifter_recovered() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    let mut graded: Vec<&str> = Vec::new();
    for method in AGGREGATE_EVIDENCED {
        let struct_name: &str = INDIRECT_PARAMETERS
            .iter()
            .find(|(candidate, _name): &&(&str, &str)| *candidate == method)
            .map(|(_candidate, name): &(&str, &str)| *name)
            .ok_or("an aggregate-evidenced method declares no struct parameter")?;
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let recovered: Vec<(usize, usize)> = lifted_aggregate_offsets(pseudo_c)?;
        assert!(
            !recovered.is_empty(),
            "{method} is pinned as aggregate-evidenced, so the body must carry the offsets the \
             lifter recovered from the machine code: {pseudo_c}"
        );
        let declared: Vec<(usize, usize)> = declared_offsets(struct_name)?;
        for entry in &recovered {
            assert!(
                declared.contains(entry),
                "{method} reads offset {} width {} through the parameter, which the declared \
                 layout of {struct_name} does not place there: {declared:?}",
                entry.0,
                entry.1
            );
        }
        graded.push(method);
    }
    assert_eq!(
        graded,
        AGGREGATE_EVIDENCED.to_vec(),
        "the aggregate-evidenced population is pinned by name"
    );
    Ok(())
}

#[test]
fn a_register_passed_struct_keeps_the_register_typed_body() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    for (method, wire) in DECLARED_ABSTENTIONS {
        let body: &serde_json::Value = &method_record(&document, metadata_name(method))?["body"];
        assert_eq!(
            body["signature_source"], "registers",
            "{method} is a declared abstention and must keep the register-typed body"
        );
        assert_eq!(
            body["signature_abstention"], wire,
            "{method} must abstain for the declared reason"
        );
        let (_has_this, _return_type, parameters): (bool, String, Vec<String>) =
            declared_managed_signature(method)?;
        let declared: &String = parameters
            .first()
            .ok_or("the declared abstention takes no parameter")?;
        let (_fields, size): DeclaredLayout = declared_layout(declared.as_str())?;
        assert!(
            matches!(size, 1 | 2 | 4 | 8),
            "{method} is pinned because {declared} is a size the runtime passes in the register, \
             got {size} bytes"
        );
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        assert!(
            !pseudo_c.contains(format!("{declared} *").as_str()),
            "{method} must not spell a pointer for a register-passed struct: {pseudo_c}"
        );
    }
    Ok(())
}

#[test]
fn the_managed_signature_population_is_pinned_by_name() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    let mut managed: Vec<String> = Vec::new();
    for method in PROBE_METHODS {
        if method_record(&document, metadata_name(method))?["body"]["signature_source"] == "managed"
        {
            managed.push(method.to_owned());
        }
    }
    assert_eq!(
        managed,
        MANAGED_SIGNATURE_METHODS
            .iter()
            .map(|name: &&str| (*name).to_owned())
            .collect::<Vec<String>>(),
        "the set of methods carrying a managed signature is pinned by name, not by count"
    );
    assert_eq!(
        managed.len().checked_add(DECLARED_ABSTENTIONS.len()),
        Some(PROBE_METHODS.len()),
        "every probe method is either reattached or a declared abstention"
    );
    Ok(())
}
