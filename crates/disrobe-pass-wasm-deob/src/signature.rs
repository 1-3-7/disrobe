use serde::Serialize;
use wasmparser::{KnownCustom, NameSectionReader, Parser, Payload, TypeRef, ValType};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionSig {
    pub name: String,
    #[serde(skip)]
    pub params: Vec<ValType>,
    #[serde(skip)]
    pub results: Vec<ValType>,
    pub exported: bool,
    pub imported: bool,
}

impl FunctionSig {
    #[inline]
    #[must_use]
    pub fn placeholder(defined_index: u32) -> Self {
        Self {
            name: format!("func_{defined_index}"),
            params: Vec::new(),
            results: Vec::new(),
            exported: false,
            imported: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleSignatures {
    sigs: Vec<FunctionSig>,
    imported_function_count: u32,
}

impl ModuleSignatures {
    #[inline]
    #[must_use]
    pub fn defined(&self) -> &[FunctionSig] {
        let start: usize = self.imported_function_count as usize;
        self.sigs.get(start..).unwrap_or(&[])
    }

    #[inline]
    #[must_use]
    pub const fn imported_function_count(&self) -> usize {
        self.imported_function_count as usize
    }

    #[inline]
    #[must_use]
    pub fn by_function_index(&self, function_index: u32) -> Option<&FunctionSig> {
        self.sigs.get(function_index as usize)
    }

    #[inline]
    #[must_use]
    pub fn defined_sig(&self, defined_index: u32) -> Option<&FunctionSig> {
        self.by_function_index(self.imported_function_count.saturating_add(defined_index))
    }

    /// Per-function-index `(params, results)` for `CallSignatures::new`, so the SSA
    /// builder pops exact callee arity and assigns real result types.
    #[must_use]
    pub fn call_signatures(&self) -> Vec<(Vec<ValType>, Vec<ValType>)> {
        self.sigs
            .iter()
            .map(|s| (s.params.clone(), s.results.clone()))
            .collect()
    }

    /// Function-index -> emitted identifier, for resolving `call` targets in lifted source.
    #[must_use]
    pub fn callee_names(&self) -> Vec<String> {
        self.sigs.iter().map(|s| s.name.clone()).collect()
    }
}

struct RawFuncType {
    params: Vec<ValType>,
    results: Vec<ValType>,
}

pub fn extract_signatures(bytes: &[u8]) -> Result<ModuleSignatures> {
    let mut func_types: Vec<RawFuncType> = Vec::new();
    let mut function_type_indices: Vec<u32> = Vec::new();
    let mut imported_function_type_indices: Vec<u32> = Vec::new();
    let mut export_names: Vec<(u32, String)> = Vec::new();
    let mut name_section_names: Vec<(u32, String)> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group: wasmparser::RecGroup =
                        group.map_err(|e| Error::Parse(e.to_string()))?;
                    for sub in group.into_types() {
                        match &sub.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(ft) => {
                                func_types.push(RawFuncType {
                                    params: ft.params().to_vec(),
                                    results: ft.results().to_vec(),
                                });
                            }
                            _ => func_types.push(RawFuncType {
                                params: Vec::new(),
                                results: Vec::new(),
                            }),
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group: wasmparser::Imports<'_> =
                        group.map_err(|e| Error::Parse(e.to_string()))?;
                    if let wasmparser::Imports::Single(_, imp) = group
                        && let TypeRef::Func(type_index) = imp.ty
                    {
                        imported_function_type_indices.push(type_index);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    function_type_indices.push(ty.map_err(|e| Error::Parse(e.to_string()))?);
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    let exp: wasmparser::Export<'_> =
                        exp.map_err(|e| Error::Parse(e.to_string()))?;
                    if matches!(exp.kind, wasmparser::ExternalKind::Func) {
                        export_names.push((exp.index, exp.name.to_owned()));
                    }
                }
            }
            Payload::CustomSection(reader) if reader.name() == "name" => {
                if let KnownCustom::Name(names) = reader.as_known() {
                    collect_name_section(names, &mut name_section_names)?;
                }
            }
            _ => {}
        }
    }

    let imported_function_count: u32 =
        u32::try_from(imported_function_type_indices.len()).unwrap_or(u32::MAX);

    let mut sigs: Vec<FunctionSig> =
        Vec::with_capacity(imported_function_type_indices.len() + function_type_indices.len());

    for (idx, type_index) in imported_function_type_indices.iter().enumerate() {
        let (params, results): (Vec<ValType>, Vec<ValType>) =
            type_signature(&func_types, *type_index);
        let function_index: u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        sigs.push(FunctionSig {
            name: resolve_name(
                function_index,
                imported_function_count,
                &name_section_names,
                &export_names,
            ),
            params,
            results,
            exported: export_names.iter().any(|(i, _)| *i == function_index),
            imported: true,
        });
    }

    for (defined_idx, type_index) in function_type_indices.iter().enumerate() {
        let (params, results): (Vec<ValType>, Vec<ValType>) =
            type_signature(&func_types, *type_index);
        let function_index: u32 =
            imported_function_count.saturating_add(u32::try_from(defined_idx).unwrap_or(u32::MAX));
        sigs.push(FunctionSig {
            name: resolve_name(
                function_index,
                imported_function_count,
                &name_section_names,
                &export_names,
            ),
            params,
            results,
            exported: export_names.iter().any(|(i, _)| *i == function_index),
            imported: false,
        });
    }

    Ok(ModuleSignatures {
        sigs,
        imported_function_count,
    })
}

fn type_signature(func_types: &[RawFuncType], type_index: u32) -> (Vec<ValType>, Vec<ValType>) {
    func_types.get(type_index as usize).map_or_else(
        || (Vec::new(), Vec::new()),
        |ft| (ft.params.clone(), ft.results.clone()),
    )
}

fn resolve_name(
    function_index: u32,
    imported_function_count: u32,
    name_section_names: &[(u32, String)],
    export_names: &[(u32, String)],
) -> String {
    if let Some((_, name)) = name_section_names
        .iter()
        .find(|(i, _)| *i == function_index)
    {
        return sanitize_identifier(name);
    }
    if let Some((_, name)) = export_names.iter().find(|(i, _)| *i == function_index) {
        return sanitize_identifier(name);
    }
    if function_index < imported_function_count {
        format!("import_{function_index}")
    } else {
        format!("func_{}", function_index - imported_function_count)
    }
}

fn collect_name_section(reader: NameSectionReader<'_>, out: &mut Vec<(u32, String)>) -> Result<()> {
    for subsection in reader {
        let name: wasmparser::Name<'_> = subsection.map_err(|e| Error::Parse(e.to_string()))?;
        if let wasmparser::Name::Function(map) = name {
            for naming in map {
                let naming: wasmparser::Naming<'_> =
                    naming.map_err(|e| Error::Parse(e.to_string()))?;
                out.push((naming.index, naming.name.to_owned()));
            }
        }
    }
    Ok(())
}

fn sanitize_identifier(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for (i, ch) in raw.chars().enumerate() {
        let ok: bool = if i == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        out.push(if ok { ch } else { '_' });
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

#[must_use]
pub fn signatures_or_placeholders(bytes: &[u8]) -> ModuleSignatures {
    extract_signatures(bytes).unwrap_or_default()
}

#[must_use]
pub fn count_defined_function_bodies(bytes: &[u8]) -> usize {
    let mut count: usize = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(_)) = payload {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const ARITH4: &[u8] = include_bytes!("../tests/fixtures/arith4.wasm");

    #[test]
    fn extracts_five_defined_signatures_with_export_names() {
        let sigs: ModuleSignatures = extract_signatures(ARITH4).expect("sigs");
        let defined: &[FunctionSig] = sigs.defined();
        assert_eq!(defined.len(), 5, "five defined functions");
        let add: &FunctionSig = &defined[0];
        assert_eq!(add.name, "add");
        assert_eq!(add.params, vec![ValType::I32, ValType::I32]);
        assert_eq!(add.results, vec![ValType::I32]);
        assert!(add.exported);
    }

    #[test]
    fn recovers_f64_signature() {
        let sigs: ModuleSignatures = extract_signatures(ARITH4).expect("sigs");
        let defined: &[FunctionSig] = sigs.defined();
        let mul: &FunctionSig = &defined[4];
        assert_eq!(mul.name, "mul_f64");
        assert_eq!(mul.params, vec![ValType::F64, ValType::F64]);
        assert_eq!(mul.results, vec![ValType::F64]);
    }

    #[test]
    fn body_count_matches_signature_count() {
        let sigs: ModuleSignatures = extract_signatures(ARITH4).expect("sigs");
        assert_eq!(sigs.defined().len(), count_defined_function_bodies(ARITH4));
    }

    #[test]
    fn garbage_yields_error() {
        assert!(extract_signatures(b"not wasm").is_err());
    }
}
