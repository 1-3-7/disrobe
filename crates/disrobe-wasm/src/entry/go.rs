use disrobe_pass_go::{
    GoBuildInfo, GoFunc, GoGenericInstantiation, GoImage, GoItab, GoItabSlot, GoMethod,
    GoStructField, GoSymbols, GoTypeMeta, GoTypeRef, ImageKind, LocatedPclntab, Moduledata,
    ModuledataSource, assign_absolute_vas, extract_build_info, link_method_functions,
    locate_moduledata, locate_pclntab, parse_symbols, try_extract_typemeta,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use serde::{Serialize, Serializer};

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_SYMBOLS: u64 = 65_536;
const MAX_TYPES: u64 = 16_384;
const MAX_RECORDS: usize = 131_072;
const MAX_IMAGE_NAMES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Address(u64);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:#x}", self.0))
    }
}

#[derive(Debug, Serialize)]
struct Function {
    name: String,
    entry: Address,
    end: Address,
    address: Option<Address>,
    file: Option<String>,
    start_line: Option<i32>,
    linker_symbol: Option<String>,
    abi0: bool,
}

#[derive(Debug, Serialize)]
struct Symbols {
    version: String,
    functions: Vec<Function>,
    source_files: Vec<String>,
    packages: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Method {
    name: Option<String>,
    address: Address,
    linker_name: Option<String>,
    exported: bool,
}

#[derive(Debug, Serialize)]
struct Field {
    name: String,
    type_address: Address,
    type_name: String,
    kind: u8,
    kind_label: String,
    offset: Address,
    tag: Option<String>,
    embedded: bool,
    exported: bool,
}

#[derive(Debug, Serialize)]
struct InterfaceMethod {
    name: Option<String>,
    signature: Option<String>,
    type_address: Address,
    exported: bool,
}

#[derive(Debug, Serialize)]
struct Type {
    address: Address,
    name: Option<String>,
    kind: Option<u8>,
    kind_label: Option<String>,
    methods: Vec<Method>,
    fields: Vec<Field>,
    fields_rejected: bool,
    interface_methods: Vec<InterfaceMethod>,
    interface_methods_rejected: bool,
}

#[derive(Debug, Serialize)]
struct InterfaceSlot {
    index: u32,
    address: Address,
    method_name: Option<String>,
    linker_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct InterfaceTable {
    address: Address,
    interface_name: Option<String>,
    concrete_name: Option<String>,
    functions: Vec<InterfaceSlot>,
    unimplemented: bool,
}

#[derive(Debug, Serialize)]
struct RuntimeMetadata {
    types: Vec<Type>,
    interfaces: Vec<InterfaceTable>,
    strings: Vec<String>,
    generics: Vec<GoGenericInstantiation>,
    traversal_limit_reached: bool,
}

#[derive(Debug, Serialize)]
struct Module {
    source: ModuledataSource,
    pclntab: Address,
    type_links: Address,
    type_links_count: u64,
    interface_links: Address,
    interface_links_count: u64,
    types_start: Address,
    types_end: Address,
    text_start: Address,
    text_end: Address,
    name: Option<String>,
    build_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GoResult {
    ok: bool,
    format: &'static str,
    container: &'static str,
    pointer_width: u8,
    build_info: Option<GoBuildInfo>,
    symbols: Option<Symbols>,
    types: Option<RuntimeMetadata>,
    module: Option<Module>,
}

fn admit_image(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_INPUT {
        return Err("Go metadata: input exceeds 16 MiB; use the CLI for this file".to_string());
    }
    let file: object::File<'_> = object::File::parse(bytes)
        .map_err(|error: object::Error| format!("Go metadata: native container: {error}"))?;
    let mut names: usize = 0;
    for (index, section) in file.sections().enumerate() {
        if index >= 4096 {
            return Err("Go metadata: container exceeds 4096 sections".to_string());
        }
        names = names.saturating_add(section.name().unwrap_or("").len());
        if names > MAX_IMAGE_NAMES {
            return Err("Go metadata: container names exceed 16 MiB".to_string());
        }
    }
    for (index, symbol) in file.symbols().enumerate() {
        if index >= MAX_SYMBOLS as usize {
            return Err("Go metadata: container exceeds 65536 linker symbols".to_string());
        }
        names = names.saturating_add(symbol.name().unwrap_or("").len());
        if names > MAX_IMAGE_NAMES {
            return Err("Go metadata: container names exceed 16 MiB".to_string());
        }
    }
    Ok(())
}

fn admit_tables(functions: u64, files: u64, types: u64, interfaces: u64) -> Result<(), String> {
    if functions > MAX_SYMBOLS || files > MAX_SYMBOLS {
        return Err("Go metadata: function or source-file table exceeds 65536 records".to_string());
    }
    if types > MAX_TYPES || interfaces > MAX_TYPES {
        return Err("Go metadata: type or interface table exceeds 16384 records".to_string());
    }
    Ok(())
}

pub fn analyze(bytes: &[u8]) -> Result<GoResult, String> {
    admit_image(bytes)?;
    let image: GoImage<'_> = GoImage::parse(bytes).map_err(go_error)?;
    let container: &'static str = match image.kind() {
        ImageKind::Elf => "ELF",
        ImageKind::Pe => "PE",
        ImageKind::MachO => "Mach-O",
    };
    let located: LocatedPclntab<'_> = match locate_pclntab(&image) {
        Ok(located) => located,
        Err(disrobe_pass_go::Error::PclntabMissing) => {
            let build_info: Option<GoBuildInfo> = extract_build_info(&image);
            if build_info
                .as_ref()
                .and_then(|info: &GoBuildInfo| info.go_version.as_ref())
                .is_none()
            {
                return Err(
                    "Go metadata: no Go build information or function table found".to_string(),
                );
            }
            return Ok(GoResult {
                ok: true,
                format: "go",
                container,
                pointer_width: image.ptr_size() * 8,
                build_info,
                symbols: None,
                types: None,
                module: None,
            });
        }
        Err(error) => return Err(go_error(error)),
    };
    admit_tables(located.header.n_funcs, located.header.n_files, 0, 0)?;
    let mut symbols: GoSymbols = parse_symbols(&image, &located).map_err(go_error)?;
    let mut module: Moduledata = locate_moduledata(&image, &located);
    admit_tables(0, 0, module.typelinks_len, module.itablinks_len)?;
    let text_base: Option<u64> = (module.text_va != 0)
        .then_some(module.text_va)
        .or_else(|| image.text_section_base());
    assign_absolute_vas(
        &mut symbols.funcs,
        located.header.version,
        located.header.text_start,
        text_base,
    );
    let types: Option<RuntimeMetadata> = if module.via == ModuledataSource::None {
        None
    } else {
        let mut metadata: GoTypeMeta = try_extract_typemeta(&image, &module).map_err(go_error)?;
        let functions: Vec<(u64, &str)> = symbols
            .funcs
            .iter()
            .map(|function: &GoFunc| (function.entry, function.name.as_str()))
            .collect();
        link_method_functions(&mut metadata, &functions, module.text_va);
        Some(types_view(metadata)?)
    };
    if symbols.funcs.len() > MAX_SYMBOLS as usize
        || symbols.source_files.len() > MAX_SYMBOLS as usize
    {
        return Err(
            "Go metadata: recovered function or source-file table exceeds 65536 records"
                .to_string(),
        );
    }
    Ok(GoResult {
        ok: true,
        format: "go",
        container,
        pointer_width: image.ptr_size() * 8,
        build_info: module.build_info.take(),
        symbols: Some(Symbols {
            version: symbols.version_label,
            functions: symbols
                .funcs
                .into_iter()
                .map(|function: GoFunc| Function {
                    name: function.name,
                    entry: Address(function.entry),
                    end: Address(function.end),
                    address: function.va.map(Address),
                    file: function.file,
                    start_line: function.start_line,
                    linker_symbol: function.linker_symbol,
                    abi0: function.abi0,
                })
                .collect(),
            source_files: symbols.source_files,
            packages: symbols.package_set,
        }),
        types,
        module: Some(Module {
            source: module.via,
            pclntab: Address(module.pclntab_va),
            type_links: Address(module.typelinks_va),
            type_links_count: module.typelinks_len,
            interface_links: Address(module.itablinks_va),
            interface_links_count: module.itablinks_len,
            types_start: Address(module.types_va),
            types_end: Address(module.etypes_va),
            text_start: Address(module.text_va),
            text_end: Address(module.etext_va),
            name: module.modulename,
            build_version: module.buildversion,
        }),
    })
}

fn types_view(metadata: GoTypeMeta) -> Result<RuntimeMetadata, String> {
    let records: usize = metadata
        .types
        .iter()
        .fold(0_usize, |count: usize, ty: &GoTypeRef| {
            count
                .saturating_add(1)
                .saturating_add(ty.fields.len())
                .saturating_add(ty.methods.len())
                .saturating_add(ty.imethods.len())
        })
        .saturating_add(
            metadata
                .itabs
                .iter()
                .fold(0_usize, |count: usize, table: &GoItab| {
                    count.saturating_add(1).saturating_add(table.fun.len())
                }),
        );
    if records > MAX_RECORDS {
        return Err("Go metadata: nested type metadata exceeds 131072 records".to_string());
    }
    let traversal_limit_reached: bool = metadata.types.len() >= MAX_TYPES as usize;
    Ok(RuntimeMetadata {
        traversal_limit_reached,
        types: metadata
            .types
            .into_iter()
            .map(|ty: GoTypeRef| Type {
                address: Address(ty.va),
                name: ty.name,
                kind: ty.kind,
                kind_label: ty.kind_label,
                fields_rejected: ty.fields_rejected,
                interface_methods_rejected: ty.imethods_rejected,
                methods: ty
                    .methods
                    .into_iter()
                    .map(|method: GoMethod| Method {
                        name: method.name,
                        address: Address(method.func_va),
                        linker_name: method.linker_name,
                        exported: method.exported,
                    })
                    .collect(),
                fields: ty
                    .fields
                    .into_iter()
                    .map(|field: GoStructField| Field {
                        name: field.name,
                        type_address: Address(field.type_va),
                        type_name: field.type_name,
                        kind: field.kind,
                        kind_label: field.kind_label,
                        offset: Address(field.offset),
                        tag: field.tag,
                        embedded: field.embedded,
                        exported: field.exported,
                    })
                    .collect(),
                interface_methods: ty
                    .imethods
                    .into_iter()
                    .map(
                        |method: disrobe_pass_go::GoInterfaceMethod| InterfaceMethod {
                            name: method.name,
                            signature: method.signature,
                            type_address: Address(method.type_va),
                            exported: method.exported,
                        },
                    )
                    .collect(),
            })
            .collect(),
        interfaces: metadata
            .itabs
            .into_iter()
            .map(|table: GoItab| InterfaceTable {
                address: Address(table.va),
                interface_name: table.interface_name,
                concrete_name: table.concrete_name,
                unimplemented: table.unimplemented,
                functions: table
                    .fun
                    .into_iter()
                    .map(|slot: GoItabSlot| InterfaceSlot {
                        index: slot.index,
                        address: Address(slot.func_va),
                        method_name: slot.method_name,
                        linker_name: slot.linker_name,
                    })
                    .collect(),
            })
            .collect(),
        strings: metadata.strings,
        generics: metadata.generics,
    })
}

fn go_error(error: disrobe_pass_go::Error) -> String {
    format!("Go metadata: {error}")
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    let native: bool = bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.get(..4).is_some_and(|head: &[u8]| {
            matches!(
                head,
                [0xcf | 0xce, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf | 0xce]
            )
        });
    native
        && [
            b"\xff Go buildinf:".as_slice(),
            b"runtime.morestack".as_slice(),
        ]
        .iter()
        .any(|marker: &&[u8]| {
            bytes
                .windows(marker.len())
                .any(|window: &[u8]| window == *marker)
        })
}

#[cfg(test)]
mod tests {
    use super::{Address, MAX_SYMBOLS, MAX_TYPES, admit_tables};

    #[test]
    fn addresses_preserve_bits_above_javascript_integer_precision() {
        let serialized: Result<String, serde_json::Error> =
            serde_json::to_string(&Address(0xfedc_ba98_7654_3210));
        assert!(matches!(
            serialized.as_deref(),
            Ok("\"0xfedcba9876543210\"")
        ));
    }

    #[test]
    fn declared_tables_reject_the_first_over_limit_record() {
        assert!(admit_tables(MAX_SYMBOLS, MAX_SYMBOLS, MAX_TYPES, MAX_TYPES).is_ok());
        assert!(admit_tables(MAX_SYMBOLS + 1, 0, 0, 0).is_err());
        assert!(admit_tables(0, MAX_SYMBOLS + 1, 0, 0).is_err());
        assert!(admit_tables(0, 0, MAX_TYPES + 1, 0).is_err());
        assert!(admit_tables(0, 0, 0, MAX_TYPES + 1).is_err());
    }
}
