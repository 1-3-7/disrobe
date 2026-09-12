use std::collections::BTreeSet;

use disrobe_pass_dotnet::{
    AssemblyModel, ClrHeader, DecompiledAssembly, ExceptionClause, Instruction, MetadataRoot,
    MethodBody, MethodModel, OperandValue, PeBitness, PeImage, Resolver, StreamHeader, TableStream,
    TargetLang, decompile_assembly_in, parse, parse_clr_header, parse_metadata_root,
    parse_method_body, parse_table_stream,
};
use serde::Serialize;

const INPUT_BYTES: usize = 8 * 1024 * 1024;
const OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INSTRUCTIONS: usize = 65_536;
const MAX_METHOD_INSTRUCTIONS: usize = 16_384;

fn admit_table_counts(stream: &TableStream) -> Result<(), String> {
    let total: u64 = stream
        .row_counts
        .values()
        .map(|&count| u64::from(count))
        .sum();
    if total > 32_768
        || stream.row_counts.get(&2).copied().unwrap_or(0) > 512
        || stream.row_counts.get(&3).copied().unwrap_or(0) > 4096
        || stream.row_counts.get(&4).copied().unwrap_or(0) > 4096
        || stream.row_counts.get(&5).copied().unwrap_or(0) > 1024
        || stream.row_counts.get(&6).copied().unwrap_or(0) > 1024
    {
        return Err("Assembly metadata exceeds the browser limits of 512 types, 4096 field definitions or pointers, 1024 method definitions or pointers, or 32,768 total rows.".to_owned());
    }
    Ok(())
}

fn admit_model(model: &AssemblyModel) -> Result<(), String> {
    let mut fields: BTreeSet<u32> = BTreeSet::new();
    let mut methods: BTreeSet<u32> = BTreeSet::new();
    for ty in &model.types {
        for field in &ty.fields {
            if !fields.insert(field.token) {
                return Err(format!(
                    "Assembly metadata repeats field token 0x{:08x}.",
                    field.token
                ));
            }
            if fields.len() > 4096 {
                return Err(
                    "The materialized assembly exceeds the browser limit of 4096 fields."
                        .to_owned(),
                );
            }
        }
        for method in &ty.methods {
            if !methods.insert(method.token) {
                return Err(format!(
                    "Assembly metadata repeats method token 0x{:08x}.",
                    method.token
                ));
            }
            if methods.len() > 1024 {
                return Err(
                    "The materialized assembly exceeds the browser limit of 1024 methods."
                        .to_owned(),
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CilInstruction {
    offset: u32,
    name: String,
    operand: String,
    reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum MethodCode {
    Available {
        max_stack: u16,
        code_size: u32,
        local_signature_token: u32,
        init_locals: bool,
        instructions: Vec<CilInstruction>,
        exceptions: Vec<ExceptionClause>,
    },
    Absent,
    Invalid {
        error: String,
    },
}

#[derive(Debug, Serialize)]
struct MethodListing {
    token: u32,
    code: MethodCode,
}

#[derive(Debug, Serialize)]
pub struct DotnetResult {
    ok: bool,
    format: &'static str,
    bitness: PeBitness,
    runtime: String,
    model: AssemblyModel,
    bytecode: Vec<MethodListing>,
    csharp: DecompiledAssembly,
    fsharp: DecompiledAssembly,
    vbnet: DecompiledAssembly,
}

fn admit_metadata(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
) -> Result<(), String> {
    let metadata: &[u8] = disrobe_pass_dotnet::metadata::metadata_slice(image, pe, clr, root)
        .map_err(|error| error.to_string())?;
    let header: StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or("The assembly has no metadata tables.")?;
    let stream: TableStream =
        parse_table_stream(metadata, header).map_err(|error| error.to_string())?;
    admit_table_counts(&stream)?;
    if let Some(strings) = root.streams.get("#Strings") {
        let start: usize = strings.offset as usize;
        let end: usize = start
            .checked_add(strings.size as usize)
            .ok_or("Invalid metadata string range.")?;
        let heap: &[u8] = metadata
            .get(start..end)
            .ok_or("Truncated metadata string heap.")?;
        if heap.split(|&byte| byte == 0).any(|name| name.len() > 4096) {
            return Err(
                "An assembly metadata name exceeds the browser limit of 4096 bytes.".to_owned(),
            );
        }
    }
    Ok(())
}

fn operand_text(operand: &OperandValue, next_offset: u32) -> String {
    match operand {
        OperandValue::None => String::new(),
        OperandValue::I32(value) => value.to_string(),
        OperandValue::I64(value) => value.to_string(),
        OperandValue::U8(value) => value.to_string(),
        OperandValue::U16(value) => value.to_string(),
        OperandValue::F32Bits(bits) => format!("bits(0x{bits:08x})"),
        OperandValue::F64Bits(bits) => format!("bits(0x{bits:016x})"),
        OperandValue::BrTarget(offset) => (i64::from(next_offset) + i64::from(*offset)).to_string(),
        OperandValue::Token(token) => format!("0x{token:08x}"),
        OperandValue::Switch(offsets) => offsets
            .iter()
            .map(|&offset| (i64::from(next_offset) + i64::from(offset)).to_string())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn method_code(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    method: &MethodModel,
    remaining: &mut usize,
) -> Result<MethodCode, String> {
    if method.rva == 0 {
        return Ok(MethodCode::Absent);
    }
    let parsed = pe
        .slice_at_rva_to_end(image, method.rva)
        .and_then(parse_method_body);
    let body: MethodBody = match parsed {
        Ok(body) => body,
        Err(error) => {
            return Ok(MethodCode::Invalid {
                error: error.to_string(),
            });
        }
    };
    let edges: usize = body
        .instructions
        .iter()
        .map(|instruction| match &instruction.operand {
            OperandValue::BrTarget(_) => 1,
            OperandValue::Switch(offsets) => offsets.len(),
            _ => 0,
        })
        .sum();
    if body.instructions.len() > MAX_METHOD_INSTRUCTIONS
        || body.instructions.len() > *remaining
        || body.exception_clauses.len() > 256
        || edges > 2048
    {
        return Err("CIL exceeds the browser limits of 16,384 instructions per method, 65,536 per assembly, 256 exception clauses or 2048 branch targets per method.".to_owned());
    }
    *remaining -= body.instructions.len();
    let instructions: Vec<CilInstruction> = body
        .instructions
        .iter()
        .enumerate()
        .map(|(index, instruction): (usize, &Instruction)| {
            let next_offset: u32 = body
                .instructions
                .get(index + 1)
                .map_or(body.code_size, |next| next.offset);
            let reference: Option<String> = match instruction.operand {
                OperandValue::Token(token) => Some(resolver.resolve_token(token)),
                _ => None,
            };
            CilInstruction {
                offset: instruction.offset,
                name: instruction.name.clone(),
                operand: operand_text(&instruction.operand, next_offset),
                reference,
            }
        })
        .collect();
    Ok(MethodCode::Available {
        max_stack: body.max_stack,
        code_size: body.code_size,
        local_signature_token: body.local_var_sig_tok,
        init_locals: body.init_locals,
        instructions,
        exceptions: body.exception_clauses,
    })
}

fn recover(
    image: &[u8],
    language: TargetLang,
    remaining: &mut usize,
) -> Result<DecompiledAssembly, String> {
    let result: DecompiledAssembly =
        decompile_assembly_in(image, language).map_err(|error| error.to_string())?;
    for method in &result.methods {
        *remaining = remaining
            .checked_sub(method.signature.len())
            .and_then(|left| left.checked_sub(method.body.len()))
            .ok_or("Recovered .NET methods exceed the 8 MiB source limit.")?;
    }
    Ok(result)
}

pub fn analyze(image: &[u8]) -> Result<DotnetResult, String> {
    if image.len() > INPUT_BYTES {
        return Err(".NET recovery accepts assemblies up to 8 MiB.".to_owned());
    }
    if image.len() < 64 {
        return Err(format!(
            "Incomplete PE header: expected at least 64 bytes, received {}.",
            image.len()
        ));
    }
    let pe: PeImage = parse(image).map_err(|error| error.to_string())?;
    let clr: ClrHeader = parse_clr_header(image, &pe).map_err(|error| error.to_string())?;
    let root: MetadataRoot =
        parse_metadata_root(image, &pe, &clr).map_err(|error| error.to_string())?;
    admit_metadata(image, &pe, &clr, &root)?;
    let resolver: Resolver =
        Resolver::build(image, &pe, &clr, &root).map_err(|error| error.to_string())?;
    resolver
        .validate_definition_signatures()
        .map_err(|error| format!("Invalid .NET definition signature: {error}"))?;
    let model: AssemblyModel = resolver.model();
    admit_model(&model)?;
    let mut remaining: usize = MAX_INSTRUCTIONS;
    let mut bytecode: Vec<MethodListing> = Vec::new();
    for ty in &model.types {
        for method in &ty.methods {
            bytecode.push(MethodListing {
                token: method.token,
                code: method_code(image, &pe, &resolver, method, &mut remaining)?,
            });
        }
    }
    let mut source_bytes: usize = OUTPUT_BYTES;
    let csharp: DecompiledAssembly = recover(image, TargetLang::CSharp, &mut source_bytes)?;
    let fsharp: DecompiledAssembly = recover(image, TargetLang::FSharp, &mut source_bytes)?;
    let vbnet: DecompiledAssembly = recover(image, TargetLang::VbNet, &mut source_bytes)?;
    Ok(DotnetResult {
        ok: true,
        format: "dotnet",
        bitness: pe.bitness,
        runtime: root.version,
        model,
        bytecode,
        csharp,
        fsharp,
        vbnet,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AssemblyModel, ClrHeader, DotnetResult, INPUT_BYTES, MetadataRoot, MethodCode, MethodModel,
        PeImage, Resolver, StreamHeader, TableStream, admit_model, admit_table_counts, analyze,
        parse, parse_clr_header, parse_metadata_root, parse_table_stream,
    };
    const SHAPES: &[u8] = include_bytes!("../../../../corpus/dotnet/shapes/Shapes.dll");

    fn shapes_parts() -> Result<(PeImage, ClrHeader, MetadataRoot, Resolver), String> {
        let pe: PeImage = parse(SHAPES).map_err(|error| error.to_string())?;
        let clr: ClrHeader = parse_clr_header(SHAPES, &pe).map_err(|error| error.to_string())?;
        let root: MetadataRoot =
            parse_metadata_root(SHAPES, &pe, &clr).map_err(|error| error.to_string())?;
        let resolver: Resolver =
            Resolver::build(SHAPES, &pe, &clr, &root).map_err(|error| error.to_string())?;
        Ok((pe, clr, root, resolver))
    }

    #[test]
    fn malformed_definition_blob_is_rejected_before_source_recovery() -> Result<(), String> {
        let (pe, clr, root, resolver) = shapes_parts()?;
        let metadata_start: usize = pe.rva_to_offset(clr.metadata.rva).ok_or("metadata RVA")?;
        let blob_header: &StreamHeader = root.streams.get("#Blob").ok_or("blob heap")?;
        let signature: u32 = resolver
            .tables()
            .methods
            .first()
            .ok_or("method definition")?
            .signature;
        let blob_start: usize = metadata_start + blob_header.offset as usize + signature as usize;
        let (length, prefix): (u32, usize) =
            disrobe_pass_dotnet::metadata::decompress_uint(&SHAPES[blob_start..])
                .ok_or("signature blob length")?;
        assert!(length > 0);
        let mut malformed: Vec<u8> = SHAPES.to_vec();
        malformed[blob_start + prefix] = 0xff;
        let error: String = analyze(&malformed)
            .err()
            .ok_or("invalid signature was accepted")?;
        assert!(error.contains("Invalid .NET definition signature"));
        assert!(analyze(SHAPES).is_ok());
        Ok(())
    }

    #[test]
    fn pointer_table_counts_have_the_same_limits_as_definitions() -> Result<(), String> {
        let (pe, clr, root, _) = shapes_parts()?;
        let metadata: &[u8] =
            disrobe_pass_dotnet::metadata::metadata_slice(SHAPES, &pe, &clr, &root)
                .map_err(|error| error.to_string())?;
        let header: StreamHeader = root
            .streams
            .get("#~")
            .or_else(|| root.streams.get("#-"))
            .copied()
            .ok_or("table stream")?;
        let stream: TableStream =
            parse_table_stream(metadata, header).map_err(|error| error.to_string())?;
        admit_table_counts(&stream)?;
        for (table, maximum) in [(3u8, 4096u32), (5u8, 1024u32)] {
            let mut candidate: TableStream = stream.clone();
            candidate.row_counts.insert(table, maximum);
            admit_table_counts(&candidate)?;
            candidate.row_counts.insert(table, maximum + 1);
            assert!(admit_table_counts(&candidate).is_err());
        }
        Ok(())
    }

    #[test]
    fn materialized_duplicate_methods_are_refused() -> Result<(), String> {
        let (_, _, _, resolver) = shapes_parts()?;
        let mut model: AssemblyModel = resolver.model();
        admit_model(&model)?;
        let owner = model
            .types
            .iter_mut()
            .find(|ty| !ty.methods.is_empty())
            .ok_or("method owner")?;
        let duplicate: MethodModel = owner.methods[0].clone();
        owner.methods.push(duplicate);
        let error: String = admit_model(&model)
            .err()
            .ok_or("duplicate method token was accepted")?;
        assert!(error.contains("repeats method token"));
        Ok(())
    }

    #[test]
    fn materialized_method_count_is_bounded_independently_of_table_counts() -> Result<(), String> {
        let (_, _, _, resolver) = shapes_parts()?;
        let mut model: AssemblyModel = resolver.model();
        let owner_index: usize = model
            .types
            .iter()
            .position(|ty| !ty.methods.is_empty())
            .ok_or("method owner")?;
        let prototype: MethodModel = model.types[owner_index].methods[0].clone();
        for ty in &mut model.types {
            ty.methods.clear();
        }
        for row in 1u32..=1024 {
            let mut method: MethodModel = prototype.clone();
            method.token = 0x0600_0000 | row;
            model.types[owner_index].methods.push(method);
        }
        admit_model(&model)?;
        let mut excess: MethodModel = prototype;
        excess.token = 0x0600_0401;
        model.types[owner_index].methods.push(excess);
        let error: String = admit_model(&model)
            .err()
            .ok_or("materialized method limit was not enforced")?;
        assert!(error.contains("1024 methods"));
        Ok(())
    }

    #[test]
    fn shapes_metadata_and_three_languages_retain_original_operations() -> Result<(), String> {
        let result: DotnetResult = analyze(SHAPES)?;
        let shapes = result
            .model
            .types
            .iter()
            .find(|ty| ty.full_name == "Sample.Shapes")
            .ok_or("missing Shapes type")?;
        for name in ["Grade", "Size", "Negate", "Mul"] {
            let method = shapes
                .methods
                .iter()
                .find(|method| method.name == name)
                .ok_or("missing source method")?;
            let listing = result
                .bytecode
                .iter()
                .find(|listing| listing.token == method.token)
                .ok_or("missing method listing")?;
            let MethodCode::Available { instructions, .. } = &listing.code else {
                return Err("missing method body".to_owned());
            };
            let operation: &str = if name == "Mul" {
                "mul"
            } else if name == "Negate" {
                "neg"
            } else {
                "ldstr"
            };
            assert!(
                instructions
                    .iter()
                    .any(|instruction| instruction.name == operation)
            );
            for language in [&result.csharp, &result.fsharp, &result.vbnet] {
                assert!(
                    language
                        .methods
                        .iter()
                        .any(|recovered| recovered.token == method.token
                            && recovered.signature.contains(name))
                );
            }
        }
        assert_eq!(result.csharp.methods_failed, 0);
        assert_eq!(result.fsharp.methods_failed, 0);
        assert_eq!(result.vbnet.methods_failed, 0);
        Ok(())
    }

    #[test]
    fn compiled_numeric_fixture_preserves_cil_bits_and_target_literals() -> Result<(), String> {
        let image: &[u8] = include_bytes!(
            "../../../disrobe-pass-dotnet/tests/fixtures/browser_numbers/dotnet-BrowserNumbers.dll"
        );
        let result: DotnetResult = analyze(image)?;
        let methods: &[MethodModel] = &result
            .model
            .types
            .iter()
            .find(|ty| ty.full_name == "BrowserNumbers")
            .ok_or("numeric fixture type")?
            .methods;
        assert_eq!(methods.len(), 5);
        for (name, opcode, operand) in [
            ("AboveSafe", "ldc.i8", "9007199254740993"),
            ("Minimum", "ldc.i8", "-9223372036854775808"),
            ("LiteralDouble", "ldc.r8", "bits(0x3ff4000000000000)"),
            ("NegativeZeroLiteral", "ldc.r8", "bits(0x8000000000000000)"),
        ] {
            let token: u32 = methods
                .iter()
                .find(|method| method.name == name)
                .ok_or_else(|| format!("numeric method {name}"))?
                .token;
            let listing = result
                .bytecode
                .iter()
                .find(|entry| entry.token == token)
                .ok_or_else(|| format!("numeric CIL {name}"))?;
            let MethodCode::Available { instructions, .. } = &listing.code else {
                return Err(format!("numeric CIL unavailable for {name}"));
            };
            assert!(instructions.iter().any(|instruction| instruction.name == opcode && instruction.operand == operand));
            if let Some((csharp, fsharp, vbnet)) = match name {
                "LiteralDouble" => Some(("1.25D", "1.25", "1.25R")),
                "NegativeZeroLiteral" => Some(("-0D", "-0.0", "-0R")),
                _ => None,
            } {
                for (source, literal) in [
                    (&result.csharp, format!("return {csharp};")),
                    (&result.fsharp, fsharp.to_owned()),
                    (&result.vbnet, format!("Return {vbnet}")),
                ] {
                    let method = source
                        .methods
                        .iter()
                        .find(|method| method.token == token)
                        .ok_or_else(|| format!("numeric source {name}"))?;
                    assert!(
                        method.body.lines().any(|line| line.trim() == literal),
                        "{}",
                        method.body
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_assembly_rejection_preserves_valid_followup() -> Result<(), String> {
        assert!(analyze(&[]).is_err());
        assert_eq!(
            analyze(b"MZ")
                .err()
                .ok_or("short DOS header was accepted")?,
            "Incomplete PE header: expected at least 64 bytes, received 2."
        );
        assert!(analyze(&vec![0; INPUT_BYTES + 1]).is_err());
        assert!(
            analyze(SHAPES)?
                .model
                .types
                .iter()
                .any(|ty| ty.full_name == "Sample.Shapes")
        );
        Ok(())
    }
}
