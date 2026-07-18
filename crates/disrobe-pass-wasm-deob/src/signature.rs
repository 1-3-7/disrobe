use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use wasmparser::{KnownCustom, NameSectionReader, Parser, Payload, TypeRef, ValType};

use crate::error::{Error, Result};

pub(crate) const MAX_FUNCTION_LOCALS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionSig {
    pub name: String,
    #[serde(skip)]
    pub params: Vec<ValType>,
    #[serde(skip)]
    pub results: Vec<ValType>,
    pub exported: bool,
    pub imported: bool,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_names: Vec<Option<String>>,
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
            local_names: Vec::new(),
        }
    }

    #[inline]
    #[must_use]
    pub fn local_name(&self, index: u32) -> Option<&str> {
        self.local_names
            .get(index as usize)
            .and_then(Option::as_deref)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleSignatures {
    sigs: Vec<FunctionSig>,
    imported_function_count: u32,
    export_aliases: Vec<ExportAlias>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportAlias {
    pub function_index: u32,
    pub canonical: String,
    pub aliases: Vec<String>,
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

    #[must_use]
    pub fn call_signatures(&self) -> Vec<(Vec<ValType>, Vec<ValType>)> {
        self.sigs
            .iter()
            .map(|s| (s.params.clone(), s.results.clone()))
            .collect()
    }

    #[must_use]
    pub fn callee_names(&self) -> Vec<String> {
        self.sigs.iter().map(|s| s.name.clone()).collect()
    }

    #[inline]
    #[must_use]
    pub fn export_aliases(&self) -> &[ExportAlias] {
        &self.export_aliases
    }

    #[must_use]
    pub fn aliased_exports(&self) -> Vec<&ExportAlias> {
        self.export_aliases
            .iter()
            .filter(|a| !a.aliases.is_empty())
            .collect()
    }

    #[inline]
    pub fn defined_sig_mut(&mut self, defined_index: u32) -> Option<&mut FunctionSig> {
        let abs: usize =
            (self.imported_function_count as usize).checked_add(defined_index as usize)?;
        self.sigs.get_mut(abs)
    }

    pub fn attach_local_names<F>(&mut self, mut provider: F) -> usize
    where
        F: FnMut(u32) -> Vec<Option<String>>,
    {
        let defined_count: u32 = u32::try_from(
            self.sigs
                .len()
                .saturating_sub(self.imported_function_count as usize),
        )
        .unwrap_or(u32::MAX);
        let mut attached: usize = 0;
        for defined_index in 0..defined_count {
            let names: Vec<Option<String>> = provider(defined_index);
            if names.iter().any(Option::is_some)
                && let Some(sig) = self.defined_sig_mut(defined_index)
            {
                sig.local_names = names;
                attached += 1;
            }
        }
        attached
    }
}

#[must_use]
pub fn dwarf_local_names(
    parameter_names: &[Option<String>],
    variable_names: &[Option<String>],
) -> Vec<Option<String>> {
    let capacity: usize = parameter_names
        .len()
        .saturating_add(variable_names.len())
        .min(MAX_FUNCTION_LOCALS);
    let mut out: Vec<Option<String>> = Vec::with_capacity(capacity);
    out.extend(parameter_names.iter().take(MAX_FUNCTION_LOCALS).cloned());
    let remaining: usize = MAX_FUNCTION_LOCALS.saturating_sub(out.len());
    out.extend(variable_names.iter().take(remaining).cloned());
    out
}

fn bounded_valtypes(values: &[ValType]) -> Vec<ValType> {
    let count: usize = values.len().min(MAX_FUNCTION_LOCALS);
    let mut out: Vec<ValType> = Vec::with_capacity(count);
    out.extend(values.iter().take(count).copied());
    out
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
    let mut name_section_locals: std::collections::BTreeMap<u32, Vec<Option<String>>> =
        std::collections::BTreeMap::new();

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
                                    params: bounded_valtypes(ft.params()),
                                    results: bounded_valtypes(ft.results()),
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
                    collect_name_section(names, &mut name_section_names, &mut name_section_locals);
                }
            }
            _ => {}
        }
    }

    let imported_function_count: u32 =
        u32::try_from(imported_function_type_indices.len()).unwrap_or(u32::MAX);

    let name_by_index: BTreeMap<u32, &str> = {
        let mut index: BTreeMap<u32, &str> = BTreeMap::new();
        for (function_index, name) in &name_section_names {
            index.entry(*function_index).or_insert(name.as_str());
        }
        index
    };
    let export_by_index: BTreeMap<u32, &str> = {
        let mut index: BTreeMap<u32, &str> = BTreeMap::new();
        for (function_index, name) in &export_names {
            index.entry(*function_index).or_insert(name.as_str());
        }
        index
    };
    let exported_indices: BTreeSet<u32> = export_names.iter().map(|(i, _)| *i).collect();

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
                &name_by_index,
                &export_by_index,
            ),
            params,
            results,
            exported: exported_indices.contains(&function_index),
            imported: true,
            local_names: Vec::new(),
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
                &name_by_index,
                &export_by_index,
            ),
            params,
            results,
            exported: exported_indices.contains(&function_index),
            imported: false,
            local_names: name_section_locals
                .get(&function_index)
                .cloned()
                .unwrap_or_default(),
        });
    }

    let export_aliases: Vec<ExportAlias> = dedup_export_aliases(&export_names);

    Ok(ModuleSignatures {
        sigs,
        imported_function_count,
        export_aliases,
    })
}

#[must_use]
pub fn dedup_export_aliases(export_names: &[(u32, String)]) -> Vec<ExportAlias> {
    let mut order: Vec<u32> = Vec::new();
    let mut grouped: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::new();
    for (index, name) in export_names {
        let bucket: &mut Vec<String> = grouped.entry(*index).or_default();
        if bucket.is_empty() {
            order.push(*index);
        }
        bucket.push(sanitize_identifier(name));
    }
    order
        .into_iter()
        .filter_map(|index: u32| {
            let names: Vec<String> = grouped.remove(&index)?;
            let mut iter: std::vec::IntoIter<String> = names.into_iter();
            let canonical: String = iter.next()?;
            Some(ExportAlias {
                function_index: index,
                canonical,
                aliases: iter.collect(),
            })
        })
        .collect()
}

fn type_signature(func_types: &[RawFuncType], type_index: u32) -> (Vec<ValType>, Vec<ValType>) {
    func_types.get(type_index as usize).map_or_else(
        || (Vec::new(), Vec::new()),
        |ft| (bounded_valtypes(&ft.params), bounded_valtypes(&ft.results)),
    )
}

fn resolve_name(
    function_index: u32,
    imported_function_count: u32,
    name_by_index: &BTreeMap<u32, &str>,
    export_by_index: &BTreeMap<u32, &str>,
) -> String {
    if let Some(&name) = name_by_index.get(&function_index) {
        return sanitize_identifier(name);
    }
    if let Some(&name) = export_by_index.get(&function_index) {
        return sanitize_identifier(name);
    }
    if function_index < imported_function_count {
        format!("import_{function_index}")
    } else {
        format!("func_{}", function_index - imported_function_count)
    }
}

fn collect_name_section(
    reader: NameSectionReader<'_>,
    out: &mut Vec<(u32, String)>,
    locals_out: &mut std::collections::BTreeMap<u32, Vec<Option<String>>>,
) {
    for subsection in reader {
        let Ok(name): std::result::Result<wasmparser::Name<'_>, _> = subsection else {
            break;
        };
        match name {
            wasmparser::Name::Function(map) => {
                for naming in map {
                    let Ok(naming): std::result::Result<wasmparser::Naming<'_>, _> = naming else {
                        break;
                    };
                    out.push((naming.index, naming.name.to_owned()));
                }
            }
            wasmparser::Name::Local(indirect) => {
                for group in indirect {
                    let Ok(group): std::result::Result<wasmparser::IndirectNaming<'_>, _> = group
                    else {
                        break;
                    };
                    let mut names: Vec<Option<String>> = Vec::new();
                    for naming in group.names {
                        let Ok(naming): std::result::Result<wasmparser::Naming<'_>, _> = naming
                        else {
                            break;
                        };
                        let idx: usize = naming.index as usize;
                        if idx >= MAX_FUNCTION_LOCALS {
                            continue;
                        }
                        if names.len() <= idx {
                            names.resize(idx + 1, None);
                        }
                        names[idx] = Some(naming.name.to_owned());
                    }
                    if names.iter().any(Option::is_some) {
                        locals_out.insert(group.index, names);
                    }
                }
            }
            _ => {}
        }
    }
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

    #[test]
    fn dedup_export_aliases_groups_same_index() {
        let raw: Vec<(u32, String)> = vec![
            (3, "compute".to_owned()),
            (3, "computeAlias".to_owned()),
            (4, "other".to_owned()),
        ];
        let aliases: Vec<ExportAlias> = dedup_export_aliases(&raw);
        assert_eq!(aliases.len(), 2);
        let compute: &ExportAlias = aliases
            .iter()
            .find(|a| a.function_index == 3)
            .expect("index 3");
        assert_eq!(compute.canonical, "compute");
        assert_eq!(compute.aliases, vec!["computeAlias".to_owned()]);
        let other: &ExportAlias = aliases
            .iter()
            .find(|a| a.function_index == 4)
            .expect("index 4");
        assert!(other.aliases.is_empty());
    }

    #[test]
    fn aliased_exports_recovered_from_module() {
        let wat: &str = r#"
            (module
              (func $impl (param i32) (result i32) local.get 0)
              (export "run" (func $impl))
              (export "run_alias" (func $impl)))
        "#;
        let bytes: Vec<u8> = wat::parse_str(wat).expect("wat");
        let sigs: ModuleSignatures = extract_signatures(&bytes).expect("sigs");
        let aliased: Vec<&ExportAlias> = sigs.aliased_exports();
        assert_eq!(aliased.len(), 1, "one function exported under two names");
        assert_eq!(aliased[0].canonical, "run");
        assert_eq!(aliased[0].aliases, vec!["run_alias".to_owned()]);
    }

    #[test]
    fn signature_vectors_are_capped_before_clone() {
        let values: Vec<ValType> = vec![ValType::I32; MAX_FUNCTION_LOCALS + 8];
        let bounded: Vec<ValType> = bounded_valtypes(&values);
        assert_eq!(bounded.len(), MAX_FUNCTION_LOCALS);

        let raw: RawFuncType = RawFuncType {
            params: values.clone(),
            results: values,
        };
        let (params, results): (Vec<ValType>, Vec<ValType>) = type_signature(&[raw], 0);
        assert_eq!(params.len(), MAX_FUNCTION_LOCALS);
        assert_eq!(results.len(), MAX_FUNCTION_LOCALS);
    }

    #[test]
    fn dwarf_local_names_caps_combined_names() {
        let params: Vec<Option<String>> = vec![Some("p".to_owned()); MAX_FUNCTION_LOCALS + 8];
        let vars: Vec<Option<String>> = vec![Some("v".to_owned()); 8];
        let names: Vec<Option<String>> = dwarf_local_names(&params, &vars);
        assert_eq!(names.len(), MAX_FUNCTION_LOCALS);
        assert_eq!(names.first().and_then(Option::as_deref), Some("p"));
        assert_eq!(names.last().and_then(Option::as_deref), Some("p"));
    }

    #[test]
    fn resolve_name_prefers_name_section_then_export_then_placeholder() {
        let mut name_by_index: BTreeMap<u32, &str> = BTreeMap::new();
        name_by_index.insert(5, "from_name_section");
        let mut export_by_index: BTreeMap<u32, &str> = BTreeMap::new();
        export_by_index.insert(5, "from_export");
        export_by_index.insert(6, "only_export");

        assert_eq!(
            resolve_name(5, 2, &name_by_index, &export_by_index),
            "from_name_section",
            "name section wins over export"
        );
        assert_eq!(
            resolve_name(6, 2, &name_by_index, &export_by_index),
            "only_export",
            "export used when the name section has no entry"
        );
        assert_eq!(
            resolve_name(1, 2, &name_by_index, &export_by_index),
            "import_1",
            "imported placeholder below the import count"
        );
        assert_eq!(
            resolve_name(4, 2, &name_by_index, &export_by_index),
            "func_2",
            "defined placeholder offsets by the import count"
        );
    }

    fn many_exported_module(count: usize) -> Vec<u8> {
        let mut source: String = String::with_capacity(count * 48 + 16);
        source.push_str("(module\n");
        for i in 0..count {
            source.push_str("  (func (export \"f");
            source.push_str(&i.to_string());
            source.push_str("\") (result i32) i32.const 0)\n");
        }
        source.push(')');
        wat::parse_str(&source).expect("many-export module parses")
    }

    #[test]
    fn resolves_many_export_names_within_bound() {
        let count: usize = 15000;
        let bytes: Vec<u8> = many_exported_module(count);
        let start: std::time::Instant = std::time::Instant::now();
        let sigs: ModuleSignatures = extract_signatures(&bytes).expect("sigs");
        let elapsed: std::time::Duration = start.elapsed();
        let defined: &[FunctionSig] = sigs.defined();
        assert_eq!(defined.len(), count, "one signature per function");
        for (i, sig) in defined.iter().enumerate() {
            assert_eq!(sig.name, format!("f{i}"), "export name resolved by index");
            assert!(sig.exported, "each function is exported");
        }
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "signature extraction must scale, took {elapsed:?}"
        );
    }
}
