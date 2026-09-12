use std::collections::BTreeMap;
use std::fmt::Write as _;

use disrobe_pass_dotnet::metadata::{
    MetadataRoot, StreamHeader, TableStream, metadata_slice, metadata_stream_extent,
    parse_metadata_root, parse_table_stream, read_strings_heap,
};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::tables::{
    HeapWidths, MemberRefRow, MethodDefRow, MethodImplRow, RowRef, TableId, TableSpan, Tables,
    TypeRefRow, parse_tables, table_spans,
};
use disrobe_pass_dotnet::{DecompiledAssembly, StructuredMethod, decompile_assembly};
use sha2::{Digest, Sha256};

const IMAGE: &[u8] = include_bytes!("fixtures/methodimpl_shapes/MethodImplShapes.dll");
const REFERENCE: &str = include_str!("fixtures/methodimpl_shapes/MethodImplShapes.metadata.txt");
const MANIFEST: &str = include_str!("fixtures/methodimpl_shapes/MANIFEST.toml");
const IL_SOURCE: &str = include_str!("fixtures/methodimpl_shapes/MethodImplShapes.il");

const TABLE_STREAM_NAME: &str = "#~";
const STRINGS_STREAM_NAME: &str = "#Strings";
const METHOD_IMPL_TABLE: u8 = 0x19;
const TYPE_DEF_TABLE: u8 = 0x02;
const METHOD_DEF_TABLE: u8 = 0x06;
const MEMBER_REF_TABLE: u8 = 0x0A;
const SMALL_SIMPLE_INDEX_LIMIT: u32 = 1 << 16;
const SMALL_METHOD_DEF_OR_REF_LIMIT: u32 = 1 << 15;
const METHOD_DEF_OR_REF_TAG_BITS: u32 = 1;
const METHOD_DEF_TAG: u32 = 0;
const TYPE_REF_TABLE: u8 = 0x01;
const MODULE_TABLE: u8 = 0x00;
const MODULE_REF_TABLE: u8 = 0x1A;
const ASSEMBLY_REF_TABLE: u8 = 0x23;
const SMALL_RESOLUTION_SCOPE_LIMIT: u32 = 1 << 14;
const RESOLUTION_SCOPE_TAG_BITS: u32 = 2;
const MODULE_SCOPE_TAG: u32 = 0;
const CROSS_MODULE_TYPE_REF_ROW: u32 = 3;

fn describe(row: Option<RowRef>) -> String {
    row.map_or_else(
        || "nil".to_owned(),
        |value: RowRef| format!("{:?}[{}]", value.table, value.row),
    )
}

fn reference_kind(kind: &str) -> Result<TableId, String> {
    match kind {
        "TypeDefinition" => Ok(TableId::TypeDef),
        "TypeReference" => Ok(TableId::TypeRef),
        "TypeSpecification" => Ok(TableId::TypeSpec),
        "MethodDefinition" => Ok(TableId::MethodDef),
        "MemberReference" => Ok(TableId::MemberRef),
        "AssemblyReference" => Ok(TableId::AssemblyRef),
        "ModuleReference" => Ok(TableId::ModuleRef),
        "ModuleDefinition" => Ok(TableId::Module),
        other => Err(format!(
            "the reference dump names an unmapped handle kind {other}"
        )),
    }
}

fn reference_handle(value: &str) -> Result<String, String> {
    if value == "nil" {
        return Ok("nil".to_owned());
    }
    let (kind, remainder): (&str, &str) = value
        .split_once('[')
        .ok_or_else(|| format!("the reference dump handle {value} carries no row number"))?;
    let row: &str = remainder
        .strip_suffix(']')
        .ok_or_else(|| format!("the reference dump handle {value} is unterminated"))?;
    let table: TableId = reference_kind(kind)?;
    Ok(format!("{table:?}[{row}]"))
}

fn reference_section(name: &str) -> Result<Vec<BTreeMap<&'static str, &'static str>>, String> {
    let mut rows: Vec<BTreeMap<&'static str, &'static str>> = Vec::new();
    let mut inside: bool = false;
    for line in REFERENCE.lines() {
        if let Some(section) = line.strip_prefix("== ") {
            inside = section.trim_end_matches(" ==") == name;
            continue;
        }
        if !inside || line.is_empty() {
            continue;
        }
        let mut fields: BTreeMap<&'static str, &'static str> = BTreeMap::new();
        for field in line.split(' ') {
            let (key, value): (&str, &str) = field.split_once('=').ok_or_else(|| {
                format!("the reference dump field {field} is not a key and value")
            })?;
            fields.insert(key, value);
        }
        rows.push(fields);
    }
    if rows.is_empty() {
        return Err(format!("the reference dump carries no {name} section"));
    }
    Ok(rows)
}

fn reference_field<'row>(
    row: &'row BTreeMap<&'static str, &'static str>,
    key: &str,
) -> Result<&'row str, String> {
    row.get(key)
        .copied()
        .ok_or_else(|| format!("the reference dump row carries no {key} field"))
}

struct Metadata<'image> {
    bytes: &'image [u8],
    file_offset: usize,
    table_header: StreamHeader,
    strings_header: StreamHeader,
}

fn metadata_of(image: &[u8]) -> Result<Metadata<'_>, String> {
    let pe: PeImage =
        parse(image).map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let clr: ClrHeader = parse_clr_header(image, &pe)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let bytes: &[u8] = metadata_slice(image, &pe, &clr, &root)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let file_offset: usize = pe
        .rva_to_offset(clr.metadata.rva)
        .ok_or_else(|| "the metadata directory has no file offset".to_owned())?;
    let table_header: StreamHeader = root
        .streams
        .get(TABLE_STREAM_NAME)
        .copied()
        .ok_or_else(|| format!("the image carries no {TABLE_STREAM_NAME} stream"))?;
    let strings_header: StreamHeader = root
        .streams
        .get(STRINGS_STREAM_NAME)
        .copied()
        .ok_or_else(|| format!("the image carries no {STRINGS_STREAM_NAME} stream"))?;
    Ok(Metadata {
        bytes,
        file_offset,
        table_header,
        strings_header,
    })
}

fn tables_of(image: &[u8]) -> Result<Tables, String> {
    let metadata: Metadata<'_> = metadata_of(image)?;
    parse_tables(metadata.bytes, metadata.table_header)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())
}

fn strings_of(image: &[u8]) -> Result<BTreeMap<u32, String>, String> {
    let metadata: Metadata<'_> = metadata_of(image)?;
    Ok(read_strings_heap(metadata.bytes, metadata.strings_header))
}

fn heap_string(strings: &BTreeMap<u32, String>, offset: u32) -> &str {
    strings.get(&offset).map_or("", String::as_str)
}

struct MethodImplLayout {
    file_offset: usize,
    row_width: usize,
    rows: u32,
    class_width: usize,
    coded_width: usize,
}

fn method_impl_layout(image: &[u8]) -> Result<MethodImplLayout, String> {
    let metadata: Metadata<'_> = metadata_of(image)?;
    let stream: TableStream = parse_table_stream(metadata.bytes, metadata.table_header)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let spans: BTreeMap<u8, TableSpan> = table_spans(metadata.bytes, metadata.table_header)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let span: TableSpan = spans
        .get(&METHOD_IMPL_TABLE)
        .copied()
        .ok_or_else(|| "the image carries no MethodImpl table".to_owned())?;
    let rows_of = |table: u8| -> u32 { stream.row_counts.get(&table).copied().unwrap_or(0) };
    let class_width: usize = if rows_of(TYPE_DEF_TABLE) < SMALL_SIMPLE_INDEX_LIMIT {
        2
    } else {
        4
    };
    let coded_rows: u32 = rows_of(METHOD_DEF_TABLE).max(rows_of(MEMBER_REF_TABLE));
    let coded_width: usize = if coded_rows < SMALL_METHOD_DEF_OR_REF_LIMIT {
        2
    } else {
        4
    };
    let derived: usize = class_width
        .checked_add(coded_width.saturating_mul(2))
        .ok_or_else(|| "the derived MethodImpl row width overflowed".to_owned())?;
    if derived != span.row_width {
        return Err(format!(
            "the derived MethodImpl row width {derived} disagrees with the parsed width {}",
            span.row_width
        ));
    }
    let file_offset: usize = metadata
        .file_offset
        .checked_add(metadata.table_header.offset as usize)
        .and_then(|value: usize| value.checked_add(span.offset))
        .ok_or_else(|| "the MethodImpl table offset overflowed".to_owned())?;
    Ok(MethodImplLayout {
        file_offset,
        row_width: span.row_width,
        rows: span.rows,
        class_width,
        coded_width,
    })
}

fn with_patched_method_impl_body(image: &[u8], row: u32, encoded: u32) -> Result<Vec<u8>, String> {
    let layout: MethodImplLayout = method_impl_layout(image)?;
    if row == 0 || row > layout.rows {
        return Err(format!(
            "MethodImpl row {row} is outside the committed table"
        ));
    }
    if layout.coded_width != 2 {
        return Err("this fixture is expected to use two-byte coded indexes".to_owned());
    }
    let index: usize =
        usize::try_from(row.saturating_sub(1)).map_err(|_error: std::num::TryFromIntError| {
            "the row index does not fit usize".to_owned()
        })?;
    let field: usize = layout
        .file_offset
        .checked_add(index.saturating_mul(layout.row_width))
        .and_then(|value: usize| value.checked_add(layout.class_width))
        .ok_or_else(|| "the MethodImpl body field offset overflowed".to_owned())?;
    let end: usize = field
        .checked_add(layout.coded_width)
        .ok_or_else(|| "the MethodImpl body field end overflowed".to_owned())?;
    let value: u16 = u16::try_from(encoded).map_err(|_error: std::num::TryFromIntError| {
        "the coded index does not fit two bytes".to_owned()
    })?;
    let mut patched: Vec<u8> = image.to_vec();
    patched
        .get_mut(field..end)
        .ok_or_else(|| "the MethodImpl body field is outside the image".to_owned())?
        .copy_from_slice(&value.to_le_bytes());
    Ok(patched)
}

const fn method_def_or_ref(rid: u32) -> u32 {
    (rid << METHOD_DEF_OR_REF_TAG_BITS) | METHOD_DEF_TAG
}

const fn resolution_scope_module(rid: u32) -> u32 {
    (rid << RESOLUTION_SCOPE_TAG_BITS) | MODULE_SCOPE_TAG
}

fn with_patched_type_ref_scope(image: &[u8], row: u32, encoded: u32) -> Result<Vec<u8>, String> {
    let metadata: Metadata<'_> = metadata_of(image)?;
    let stream: TableStream = parse_table_stream(metadata.bytes, metadata.table_header)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let spans: BTreeMap<u8, TableSpan> = table_spans(metadata.bytes, metadata.table_header)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let span: TableSpan = spans
        .get(&TYPE_REF_TABLE)
        .copied()
        .ok_or_else(|| "the image carries no TypeRef table".to_owned())?;
    if row == 0 || row > span.rows {
        return Err(format!("TypeRef row {row} is outside the committed table"));
    }
    let rows_of = |table: u8| -> u32 { stream.row_counts.get(&table).copied().unwrap_or(0) };
    let widest: u32 = rows_of(MODULE_TABLE)
        .max(rows_of(MODULE_REF_TABLE))
        .max(rows_of(ASSEMBLY_REF_TABLE))
        .max(rows_of(TYPE_REF_TABLE));
    let scope_width: usize = if widest < SMALL_RESOLUTION_SCOPE_LIMIT {
        2
    } else {
        4
    };
    let strings_width: usize = HeapWidths::from_flags(stream.heap_sizes).strings;
    let derived: usize = scope_width
        .checked_add(strings_width.saturating_mul(2))
        .ok_or_else(|| "the derived TypeRef row width overflowed".to_owned())?;
    if derived != span.row_width {
        return Err(format!(
            "the derived TypeRef row width {derived} disagrees with the parsed width {}",
            span.row_width
        ));
    }
    if scope_width != 2 {
        return Err("this fixture is expected to use two-byte resolution scopes".to_owned());
    }
    let index: usize =
        usize::try_from(row.saturating_sub(1)).map_err(|_error: std::num::TryFromIntError| {
            "the row index does not fit usize".to_owned()
        })?;
    let field: usize = metadata
        .file_offset
        .checked_add(metadata.table_header.offset as usize)
        .and_then(|value: usize| value.checked_add(span.offset))
        .and_then(|value: usize| value.checked_add(index.saturating_mul(span.row_width)))
        .ok_or_else(|| "the TypeRef scope field offset overflowed".to_owned())?;
    let end: usize = field
        .checked_add(scope_width)
        .ok_or_else(|| "the TypeRef scope field end overflowed".to_owned())?;
    let value: u16 = u16::try_from(encoded).map_err(|_error: std::num::TryFromIntError| {
        "the coded index does not fit two bytes".to_owned()
    })?;
    let mut patched: Vec<u8> = image.to_vec();
    patched
        .get_mut(field..end)
        .ok_or_else(|| "the TypeRef scope field is outside the image".to_owned())?
        .copy_from_slice(&value.to_le_bytes());
    Ok(patched)
}

fn headers(image: &[u8]) -> Result<BTreeMap<(String, String), String>, String> {
    let assembly: DecompiledAssembly =
        decompile_assembly(image).map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    for method in &assembly.methods {
        let (declaring, header): (&str, &str) = split_signature(method)?;
        let name: String = method_name(header)?;
        let key: (String, String) = (declaring.to_owned(), name);
        if let Some(existing) = out.get(&key) {
            if existing != header {
                return Err(format!(
                    "{key:?} was recovered twice with different headers: {existing} and {header}"
                ));
            }
            continue;
        }
        out.insert(key, header.to_owned());
    }
    Ok(out)
}

fn split_signature(method: &StructuredMethod) -> Result<(&str, &str), String> {
    let mut lines: std::str::Lines<'_> = method.signature.lines();
    let declaring: &str = lines
        .next()
        .and_then(|line: &str| line.strip_prefix("// "))
        .ok_or_else(|| format!("MethodDef 0x{:08X} has no declaring type", method.token))?;
    let header: &str = lines
        .next()
        .ok_or_else(|| format!("MethodDef 0x{:08X} has no header", method.token))?;
    if lines.next().is_some() {
        return Err(format!(
            "MethodDef 0x{:08X} has a malformed signature: {}",
            method.token, method.signature
        ));
    }
    Ok((declaring, header))
}

fn method_name(header: &str) -> Result<String, String> {
    let open: usize = header
        .find('(')
        .ok_or_else(|| format!("the header {header} carries no parameter list"))?;
    let prefix: &str = header
        .get(..open)
        .ok_or_else(|| format!("the header {header} has no name before its parameter list"))?;
    let name: &str = prefix
        .rsplit(' ')
        .next()
        .ok_or_else(|| format!("the header {header} carries no method name"))?;
    Ok(name.to_owned())
}

fn header_of<'map>(
    map: &'map BTreeMap<(String, String), String>,
    declaring: &str,
    name: &str,
) -> Result<&'map str, String> {
    map.get(&(declaring.to_owned(), name.to_owned()))
        .map(String::as_str)
        .ok_or_else(|| format!("{declaring}::{name} was not recovered"))
}

#[test]
fn the_committed_assembly_matches_the_hash_its_manifest_pins() -> Result<(), String> {
    let mut digest: String = String::with_capacity(64);
    for byte in Sha256::digest(IMAGE) {
        write!(digest, "{byte:02x}").map_err(|error: std::fmt::Error| error.to_string())?;
    }
    if !MANIFEST.contains(digest.as_str()) {
        return Err(format!(
            "the committed assembly hashes to {digest}, which the manifest does not pin"
        ));
    }
    assert!(
        IL_SOURCE.contains(".override method instance bool [mscorlib]System.Object::Equals(object) with method instance bool [.module Sibling.netmodule]MethodImplShapes.Foreign::Equals(object)"),
        "the committed IL source must still author the cross-module body encoding"
    );
    Ok(())
}

#[test]
fn the_table_parser_agrees_with_the_reference_reader_on_every_methodimpl_row() -> Result<(), String>
{
    let tables: Tables = tables_of(IMAGE)?;
    let reference: Vec<BTreeMap<&'static str, &'static str>> = reference_section("MethodImpl")?;

    assert_eq!(
        tables.method_impls.len(),
        reference.len(),
        "the parsed MethodImpl row count must equal the reference reader's"
    );
    for (index, expected) in reference.iter().enumerate() {
        let parsed: &MethodImplRow = tables
            .method_impls
            .get(index)
            .ok_or_else(|| format!("MethodImpl row {index} is absent from the parse"))?;
        let class: String = format!("{:?}[{}]", TableId::TypeDef, parsed.class_type);
        assert_eq!(
            class,
            reference_handle(reference_field(expected, "class")?)?,
            "MethodImpl row {index} declaring type"
        );
        assert_eq!(
            describe(parsed.method_body),
            reference_handle(reference_field(expected, "body")?)?,
            "MethodImpl row {index} body"
        );
        assert_eq!(
            describe(parsed.method_declaration),
            reference_handle(reference_field(expected, "decl")?)?,
            "MethodImpl row {index} declaration"
        );
    }
    let bodies: Vec<TableId> = tables
        .method_impls
        .iter()
        .filter_map(|row: &MethodImplRow| row.method_body.map(|body: RowRef| body.table))
        .collect();
    assert!(
        bodies.contains(&TableId::MethodDef) && bodies.contains(&TableId::MemberRef),
        "the fixture must encode bodies through both MethodDef and MemberRef: {bodies:?}"
    );
    Ok(())
}

#[test]
fn the_table_parser_agrees_with_the_reference_reader_on_memberref_parents_and_typeref_scopes()
-> Result<(), String> {
    let tables: Tables = tables_of(IMAGE)?;
    let strings: BTreeMap<u32, String> = strings_of(IMAGE)?;
    let member_refs: Vec<BTreeMap<&'static str, &'static str>> = reference_section("MemberRef")?;
    let type_refs: Vec<BTreeMap<&'static str, &'static str>> = reference_section("TypeRef")?;

    assert_eq!(tables.member_refs.len(), member_refs.len());
    for (index, expected) in member_refs.iter().enumerate() {
        let parsed: &MemberRefRow = tables
            .member_refs
            .get(index)
            .ok_or_else(|| format!("MemberRef row {index} is absent from the parse"))?;
        assert_eq!(
            heap_string(&strings, parsed.name),
            reference_field(expected, "name")?,
            "MemberRef row {index} name"
        );
        assert_eq!(
            describe(parsed.parent),
            reference_handle(reference_field(expected, "parent")?)?,
            "MemberRef row {index} parent"
        );
    }

    assert_eq!(tables.type_refs.len(), type_refs.len());
    for (index, expected) in type_refs.iter().enumerate() {
        let parsed: &TypeRefRow = tables
            .type_refs
            .get(index)
            .ok_or_else(|| format!("TypeRef row {index} is absent from the parse"))?;
        assert_eq!(
            heap_string(&strings, parsed.namespace),
            reference_field(expected, "ns")?,
            "TypeRef row {index} namespace"
        );
        assert_eq!(
            heap_string(&strings, parsed.name),
            reference_field(expected, "name")?,
            "TypeRef row {index} name"
        );
        assert_eq!(
            describe(parsed.resolution_scope),
            reference_handle(reference_field(expected, "scope")?)?,
            "TypeRef row {index} resolution scope"
        );
    }

    let scopes: Vec<String> = tables
        .type_refs
        .iter()
        .map(|row: &TypeRefRow| describe(row.resolution_scope))
        .collect();
    assert!(
        scopes
            .iter()
            .any(|scope: &String| scope.starts_with("ModuleRef")),
        "the fixture must carry a cross-module TypeRef: {scopes:?}"
    );
    Ok(())
}

#[test]
fn the_table_parser_agrees_with_the_reference_reader_on_method_flags() -> Result<(), String> {
    let tables: Tables = tables_of(IMAGE)?;
    let strings: BTreeMap<u32, String> = strings_of(IMAGE)?;
    let reference: Vec<BTreeMap<&'static str, &'static str>> = reference_section("MethodDef")?;

    assert_eq!(tables.methods.len(), reference.len());
    for (index, expected) in reference.iter().enumerate() {
        let parsed: &MethodDefRow = tables
            .methods
            .get(index)
            .ok_or_else(|| format!("MethodDef row {index} is absent from the parse"))?;
        assert_eq!(
            heap_string(&strings, parsed.name),
            reference_field(expected, "name")?,
            "MethodDef row {index} name"
        );
        assert_eq!(
            format!("0x{:04X}", parsed.flags),
            reference_field(expected, "attrs")?,
            "MethodDef row {index} flags"
        );
    }
    Ok(())
}

#[test]
fn recovered_headers_follow_the_authored_slot_and_methodimpl_encodings() -> Result<(), String> {
    let map: BTreeMap<(String, String), String> = headers(IMAGE)?;

    assert_eq!(
        header_of(&map, "MethodImplShapes.ReuseSlotOverride", "Equals")?,
        "public override bool Equals(object obj)"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.FinalReuseSlotOverride", "Equals")?,
        "public override bool Equals(object obj)",
        "Final on a reused slot is still the C# override shape"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.NewSlotVirtual", "Equals")?,
        "public bool Equals(object obj)",
        "a new slot introduces a method rather than overriding one"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.FinalWithoutVirtual", "Equals")?,
        "public bool Equals(object obj)",
        "Final without Virtual is legal IL that C# cannot express as an override"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.MethodDefImplBody", "Equals")?,
        "public bool Equals(object obj)",
        "a MethodImpl body encoded through MethodDef is an explicit implementation"
    );
    assert_eq!(
        header_of(
            &map,
            "MethodImplShapes.AssemblyRefTypeRefImplBody",
            "Equals"
        )?,
        "public bool Equals(object obj)",
        "a MethodImpl body through a MemberRef with an AssemblyRef-scoped TypeRef parent is not \
         provably this method"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.ModuleRefTypeRefImplBody", "Equals")?,
        "public bool Equals(object obj)",
        "a cross-module TypeRef parent must never be read as this module's type"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.TypeSpecImplBody", "Equals")?,
        "public bool Equals(object obj)",
        "a MethodImpl body through a MemberRef with a TypeSpec parent is not provably this method"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.UnrelatedImplBody", "Equals")?,
        "public override bool Equals(object obj)",
        "a MethodImpl on a sibling method must not disturb this one"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.UnrelatedImplBody", "GetHashCode")?,
        "public int GetHashCode()",
        "the sibling that does carry the MethodImpl loses the override shape"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.AllThreeOverrides", "Equals")?,
        "public override bool Equals(object obj)"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.AllThreeOverrides", "GetHashCode")?,
        "public override int GetHashCode()"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.AllThreeOverrides", "ToString")?,
        "public override string ToString()"
    );
    assert_eq!(
        header_of(
            &map,
            "MethodImplShapes.Meter",
            "MethodImplShapes.IGauge.Read"
        )?,
        "private int MethodImplShapes.IGauge.Read()",
        "an explicit interface implementation on a class keeps its private final slot"
    );
    Ok(())
}

#[test]
fn a_null_methodimpl_body_still_counts_as_an_explicit_implementation() -> Result<(), String> {
    let patched: Vec<u8> = with_patched_method_impl_body(IMAGE, 5, 0)?;
    let tables: Tables = tables_of(&patched)?;
    let row: &MethodImplRow = tables
        .method_impls
        .get(4)
        .ok_or_else(|| "the patched MethodImpl row is absent".to_owned())?;
    assert_eq!(
        row.method_body, None,
        "the perturbation must land on the fifth MethodImpl row's body"
    );
    assert_eq!(
        row.class_type, 10,
        "the perturbation must leave the declaring type untouched"
    );

    let map: BTreeMap<(String, String), String> = headers(&patched)?;
    assert_eq!(
        header_of(&map, "MethodImplShapes.UnrelatedImplBody", "Equals")?,
        "public bool Equals(object obj)",
        "a MethodImpl whose body cannot be read must suppress the override shape for every method \
         on its type"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.ReuseSlotOverride", "Equals")?,
        "public override bool Equals(object obj)",
        "the perturbation must reach one type only"
    );
    Ok(())
}

#[test]
fn a_methodimpl_body_row_past_the_table_names_no_method() -> Result<(), String> {
    let patched: Vec<u8> = with_patched_method_impl_body(IMAGE, 5, method_def_or_ref(9999))?;
    let tables: Tables = tables_of(&patched)?;
    let row: &MethodImplRow = tables
        .method_impls
        .get(4)
        .ok_or_else(|| "the patched MethodImpl row is absent".to_owned())?;
    assert_eq!(
        row.method_body,
        Some(RowRef {
            table: TableId::MethodDef,
            row: 9999,
        }),
        "the perturbation must land on the fifth MethodImpl row's body"
    );

    let map: BTreeMap<(String, String), String> = headers(&patched)?;
    assert_eq!(
        header_of(&map, "MethodImplShapes.UnrelatedImplBody", "GetHashCode")?,
        "public override int GetHashCode()",
        "a body row past the end of the MethodDef table names no method, so the explicit \
         implementation that suppressed this override is gone"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.UnrelatedImplBody", "Equals")?,
        "public override bool Equals(object obj)"
    );
    Ok(())
}

#[test]
fn a_methodimpl_body_through_a_same_module_typeref_stays_an_explicit_implementation()
-> Result<(), String> {
    let committed: Tables = tables_of(IMAGE)?;
    let before: &TypeRefRow = committed
        .type_refs
        .get(2)
        .ok_or_else(|| "the cross-module TypeRef is absent from the committed image".to_owned())?;
    assert_eq!(
        describe(before.resolution_scope),
        "ModuleRef[1]",
        "the committed encoding must start as the cross-module one ilasm can author"
    );

    let patched: Vec<u8> =
        with_patched_type_ref_scope(IMAGE, CROSS_MODULE_TYPE_REF_ROW, resolution_scope_module(1))?;
    let tables: Tables = tables_of(&patched)?;
    let after: &TypeRefRow = tables
        .type_refs
        .get(2)
        .ok_or_else(|| "the patched TypeRef row is absent".to_owned())?;
    assert_eq!(
        after.resolution_scope,
        Some(RowRef {
            table: TableId::Module,
            row: 1,
        }),
        "the perturbation must rescope the TypeRef to this module"
    );
    assert_eq!(
        (after.name, after.namespace),
        (before.name, before.namespace),
        "the perturbation must touch the resolution scope only"
    );
    let body: Option<RowRef> = tables
        .method_impls
        .get(2)
        .ok_or_else(|| "the third MethodImpl row is absent".to_owned())?
        .method_body;
    assert_eq!(
        describe(body),
        "MemberRef[2]",
        "the rescoped TypeRef must still be the parent of this MethodImpl body"
    );

    let map: BTreeMap<(String, String), String> = headers(&patched)?;
    assert_eq!(
        header_of(&map, "MethodImplShapes.ModuleRefTypeRefImplBody", "Equals")?,
        "public bool Equals(object obj)",
        "a MethodImpl body reaching this module's own type through a TypeRef rather than a \
         MethodDef is still an explicit implementation"
    );
    assert_eq!(
        header_of(&map, "MethodImplShapes.ReuseSlotOverride", "Equals")?,
        "public override bool Equals(object obj)",
        "the perturbation must reach one type only"
    );
    Ok(())
}

fn metadata_end_offset(image: &[u8]) -> Result<usize, String> {
    let pe: PeImage =
        parse(image).map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let clr: ClrHeader = parse_clr_header(image, &pe)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)
        .map_err(|error: disrobe_pass_dotnet::Error| error.to_string())?;
    let start: usize = pe
        .rva_to_offset(clr.metadata.rva)
        .ok_or_else(|| "the metadata directory has no file offset".to_owned())?;
    let extent: usize = usize::try_from(metadata_stream_extent(&root)).map_err(
        |_error: std::num::TryFromIntError| "the metadata extent does not fit usize".to_owned(),
    )?;
    start
        .checked_add(extent)
        .ok_or_else(|| "the metadata end offset overflowed".to_owned())
}

#[test]
fn a_truncation_inside_the_metadata_is_refused_and_the_bytes_after_it_are_not_needed()
-> Result<(), String> {
    let end: usize = metadata_end_offset(IMAGE)?;
    assert_eq!(
        end, 2152,
        "the committed image must still describe itself entirely within its metadata extent"
    );
    let full: BTreeMap<(String, String), String> = headers(IMAGE)?;
    let mut accepted: Vec<usize> = Vec::new();
    for length in 0..end {
        let prefix: &[u8] = IMAGE
            .get(..length)
            .ok_or_else(|| format!("the truncation to {length} bytes is out of range"))?;
        if decompile_assembly(prefix).is_ok() {
            accepted.push(length);
        }
    }
    assert!(
        accepted.is_empty(),
        "a truncation that cuts into the metadata must be refused; these were accepted: \
         {accepted:?}"
    );
    for length in end..IMAGE.len() {
        let prefix: &[u8] = IMAGE
            .get(..length)
            .ok_or_else(|| format!("the truncation to {length} bytes is out of range"))?;
        assert_eq!(
            headers(prefix)?,
            full,
            "dropping the padding and relocations after byte {length} must not change what is \
             recovered"
        );
    }
    Ok(())
}
