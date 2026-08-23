#![cfg(feature = "chain")]

use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_dotnet::chain_detector::DOTNET_PASS;
use disrobe_pass_dotnet::pe::{PeBitness, PeImage, parse};

const IMAGE: &[u8] = include_bytes!("fixtures/native_aot/managed_abi_sret_net9_x86_64.exe");
const SOURCE: &str = include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.cs");
const PROJECT: &str = include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.csproj.txt");
const BUILD: &str = include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.build.txt");
const LINK_MAP: &str =
    include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.link.map.txt");
const UNWIND: &str = include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.unwind.txt");
const DISASM: &str = include_str!("fixtures/native_aot/managed_abi_sret_net9_x86_64.disasm.txt");

const AMD64_MACHINE: u16 = 0x8664;
const DECLARING_TYPE: &str = "ManagedSretProbe";
const LINK_SYMBOL_PREFIX: &str = "managed_abi_sret_net9_x86_64_ManagedSretProbe__";
const STDINT_INCLUDE: &str = "#include <stdint.h>\n";
const LIFTED_STRUCT_RETURN_TYPE: &str = "recovered_sret_t";

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
    "_ctor", "Split", "Spread", "Quarter", "Narrow", "Widen", "Label", "Doubled",
];

const REATTACHED_STRUCT_RETURNS: [(&str, &str); 3] = [
    ("Split", "ManagedPair"),
    ("Spread", "ManagedTriple"),
    ("Quarter", "ManagedQuad"),
];

const DECLARED_ABSTENTIONS: [(&str, &str); 4] = [
    ("Narrow", "hidden-struct-return"),
    ("Widen", "hidden-struct-return"),
    ("Label", "type-outside-primitive-table"),
    ("Doubled", "hidden-struct-return"),
];

const MANAGED_SIGNATURE_METHODS: [&str; 4] = ["_ctor", "Split", "Spread", "Quarter"];

fn c_type_for(managed: &str) -> Result<&'static str, &'static str> {
    MANAGED_TO_C
        .iter()
        .find(|(candidate, _rendered): &&(&str, &str)| *candidate == managed)
        .map(|(_candidate, rendered): &(&str, &'static str)| *rendered)
        .ok_or("the declared managed type has no C99 equivalent in the independent mapping")
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

fn declared_layout(struct_name: &str) -> Result<(Vec<(String, String)>, usize), &'static str> {
    let stated: &str = build_line(format!("{struct_name} declared layout: ").as_str())?;
    let mut entries: Vec<&str> = stated.split(',').map(str::trim).collect();
    let size_entry: &str = entries.pop().ok_or("the declared layout states no size")?;
    let size: usize = size_entry
        .strip_suffix(" bytes")
        .ok_or("the declared layout size is not stated in bytes")?
        .parse::<usize>()
        .map_err(|_error: std::num::ParseIntError| "the declared layout size is not a number")?;
    let kind: &str = entries
        .first()
        .copied()
        .ok_or("the declared layout states no layout kind")?;
    if kind != "sequential" {
        return Err("the declared layout is not sequential");
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    for entry in entries.iter().skip(1) {
        let (managed, name): (&str, &str) = entry
            .split_once(' ')
            .ok_or("a declared field has no managed type and name")?;
        fields.push((managed.to_owned(), name.to_owned()));
    }
    Ok((fields, size))
}

fn expected_typedef(struct_name: &str) -> Result<String, &'static str> {
    let (fields, _size): (Vec<(String, String)>, usize) = declared_layout(struct_name)?;
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

fn lifted_typedef(struct_name: &str) -> Result<String, &'static str> {
    let (fields, _size): (Vec<(String, String)>, usize) = declared_layout(struct_name)?;
    let mut rendered: String = String::from("typedef struct {\n");
    for (index, (managed, _name)) in fields.iter().enumerate() {
        let width: &str = match c_type_for(managed.as_str())? {
            "int8_t" | "uint8_t" | "bool" => "uint8_t",
            "int16_t" | "uint16_t" => "uint16_t",
            "int32_t" | "uint32_t" | "float" => "uint32_t",
            _ => "uint64_t",
        };
        rendered.push_str(format!("    {width} f{index};\n").as_str());
    }
    rendered.push_str("} ");
    rendered.push_str(LIFTED_STRUCT_RETURN_TYPE);
    rendered.push_str(";\n");
    Ok(rendered)
}

fn expected_prototype(method: &str) -> Result<String, &'static str> {
    let (has_this, return_type, parameters): (bool, String, Vec<String>) =
        declared_managed_signature(method)?;
    let return_c: &str = if MANAGED_TO_C
        .iter()
        .any(|(candidate, _rendered): &(&str, &str)| *candidate == return_type)
    {
        c_type_for(return_type.as_str())?
    } else {
        return_type.as_str()
    };
    let mut slots: Vec<String> = Vec::new();
    if has_this {
        slots.push("uintptr_t".to_owned());
    }
    for parameter in &parameters {
        slots.push(c_type_for(parameter.as_str())?.to_owned());
    }
    let rendered: String = if slots.is_empty() {
        "void".to_owned()
    } else {
        slots
            .iter()
            .enumerate()
            .map(|(index, slot): (usize, &String)| format!("{slot} a{index}"))
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

fn metadata_name(method: &str) -> &str {
    if method == "_ctor" { ".ctor" } else { method }
}

fn recovered_pseudo_c<'document>(
    document: &'document serde_json::Value,
    method: &str,
) -> Result<&'document str, &'static str> {
    method_record(document, metadata_name(method))?["body"]["pseudo_c"]
        .as_str()
        .ok_or("the recovered body carries no pseudo-C")
}

#[test]
fn the_fixture_carries_the_compiler_evidence_it_is_graded_against() -> Result<(), &'static str> {
    let pe: PeImage = parse(IMAGE)
        .map_err(|_error: disrobe_pass_dotnet::Error| "the fixture is not a PE image")?;
    assert_eq!(pe.machine, AMD64_MACHINE);
    assert_eq!(pe.bitness, PeBitness::Pe32Plus);
    assert_eq!(pe.image_base, compiler_load_address()?);
    assert!(
        SOURCE.contains("public static ManagedPair Split(long value)"),
        "the committed source declares the graded struct-returning method"
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
fn auto_reattaches_the_declared_struct_layout_to_a_hidden_struct_return() -> Result<(), &'static str>
{
    let document: serde_json::Value = document()?;
    let mut reattached: usize = 0;
    for (method, struct_name) in REATTACHED_STRUCT_RETURNS {
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let expected: String = format!(
            "{STDINT_INCLUDE}{}{}",
            expected_typedef(struct_name)?,
            expected_prototype(method)?
        );
        assert!(
            pseudo_c.starts_with(expected.as_str()),
            "{method} must carry the struct layout declared in the build record\n\
             expected prefix:\n{expected}\nrecovered:\n{pseudo_c}"
        );
        assert_eq!(
            method_record(&document, metadata_name(method))?["body"]["signature_source"],
            "managed",
            "{method} must record that its signature came from managed metadata"
        );
        reattached = reattached
            .checked_add(1)
            .ok_or("the reattached count overflowed")?;
    }
    assert_eq!(
        reattached,
        REATTACHED_STRUCT_RETURNS.len(),
        "every declared struct return must reattach"
    );
    Ok(())
}

#[test]
fn the_reattached_struct_replaces_every_lifted_placeholder_name() -> Result<(), &'static str> {
    let document: serde_json::Value = document()?;
    for (method, struct_name) in REATTACHED_STRUCT_RETURNS {
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let lifted: String = lifted_typedef(struct_name)?;
        assert_ne!(
            lifted,
            expected_typedef(struct_name)?,
            "the lifted and managed typedefs for {struct_name} must differ, \
             otherwise this grade cannot separate them"
        );
        assert!(
            !pseudo_c.contains(lifted.as_str()),
            "{method} must not keep the register-width typedef: {pseudo_c}"
        );
        assert!(
            !pseudo_c.contains(LIFTED_STRUCT_RETURN_TYPE),
            "{method} must not keep the placeholder return type: {pseudo_c}"
        );
        let (fields, _size): (Vec<(String, String)>, usize) = declared_layout(struct_name)?;
        for (index, (_managed, name)) in fields.iter().enumerate() {
            assert!(
                !pseudo_c.contains(format!(" f{index};\n").as_str()),
                "{method} must not keep the positional member f{index}: {pseudo_c}"
            );
            assert!(
                pseudo_c.contains(format!(" {name};\n").as_str()),
                "{method} must carry the declared member {name}: {pseudo_c}"
            );
        }
        assert!(
            pseudo_c.contains(format!("    {struct_name} __sret;\n").as_str()),
            "{method} must declare its return slot with the managed type: {pseudo_c}"
        );
    }
    Ok(())
}

#[test]
fn the_declared_abstentions_keep_the_register_typed_body() -> Result<(), &'static str> {
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
        let pseudo_c: &str = recovered_pseudo_c(&document, method)?;
        let (_has_this, return_type, _parameters): (bool, String, Vec<String>) =
            declared_managed_signature(method)?;
        assert!(
            !pseudo_c.contains(format!("{return_type} recovered(").as_str()),
            "{method} must not attach a managed prototype it could not prove: {pseudo_c}"
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
