use std::ops::Range;

use serde::Serialize;
use wasmparser::{ComponentExternalKind, ComponentTypeRef, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComponentClassification {
    CoreModule,
    Component,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComponentExternKind {
    Module,
    Func,
    Value,
    Type,
    Instance,
    Component,
}

impl From<ComponentExternalKind> for ComponentExternKind {
    fn from(value: ComponentExternalKind) -> Self {
        match value {
            ComponentExternalKind::Module => Self::Module,
            ComponentExternalKind::Func => Self::Func,
            ComponentExternalKind::Value => Self::Value,
            ComponentExternalKind::Type => Self::Type,
            ComponentExternalKind::Instance => Self::Instance,
            ComponentExternalKind::Component => Self::Component,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComponentTypeRefKind {
    Module,
    Func,
    Value,
    Type,
    Instance,
    Component,
}

impl From<&ComponentTypeRef> for ComponentTypeRefKind {
    fn from(value: &ComponentTypeRef) -> Self {
        match value {
            ComponentTypeRef::Module(_) => Self::Module,
            ComponentTypeRef::Func(_) => Self::Func,
            ComponentTypeRef::Value(_) => Self::Value,
            ComponentTypeRef::Type(_) => Self::Type,
            ComponentTypeRef::Instance(_) => Self::Instance,
            ComponentTypeRef::Component(_) => Self::Component,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentImportRecord {
    pub name: String,
    pub type_kind: ComponentTypeRefKind,
    pub raw_type_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentExportRecord {
    pub name: String,
    pub kind: ComponentExternKind,
    pub index: u32,
    pub typed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbeddedModule {
    pub depth: u8,
    pub start: usize,
    pub end: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AdapterFuncKind {
    Lift,
    Lower,
    ResourceNew,
    ResourceDrop,
    ResourceRep,
    TaskReturn,
    TaskCancel,
    BackpressureSet,
    ContextGet,
    ContextSet,
    Yield,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AdapterFuncRecord {
    pub kind: AdapterFuncKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentManifest {
    pub classification: ComponentClassification,
    pub world_imports: Vec<ComponentImportRecord>,
    pub world_exports: Vec<ComponentExportRecord>,
    pub type_decl_count: u32,
    pub core_type_decl_count: u32,
    pub embedded_modules: Vec<EmbeddedModule>,
    pub embedded_components: Vec<EmbeddedModule>,
    pub adapter_funcs: Vec<AdapterFuncRecord>,
}

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const COMPONENT_VERSION_LO: u8 = 0x0d;
const MODULE_VERSION_LO: u8 = 0x01;

#[inline]
#[must_use]
pub fn classify_preamble(bytes: &[u8]) -> ComponentClassification {
    if bytes.len() < 8 || !bytes.starts_with(WASM_MAGIC) {
        return ComponentClassification::Unknown;
    }
    match bytes[4] {
        MODULE_VERSION_LO => ComponentClassification::CoreModule,
        COMPONENT_VERSION_LO => ComponentClassification::Component,
        _ => ComponentClassification::Unknown,
    }
}

pub fn parse_component_manifest(bytes: &[u8]) -> Result<ComponentManifest> {
    let classification: ComponentClassification = classify_preamble(bytes);
    let mut manifest: ComponentManifest = ComponentManifest {
        classification,
        world_imports: Vec::new(),
        world_exports: Vec::new(),
        type_decl_count: 0,
        core_type_decl_count: 0,
        embedded_modules: Vec::new(),
        embedded_components: Vec::new(),
        adapter_funcs: Vec::new(),
    };

    if matches!(
        classification,
        ComponentClassification::CoreModule | ComponentClassification::Unknown
    ) {
        return Ok(manifest);
    }

    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| parse_err(&e))?;
        match payload {
            Payload::ComponentImportSection(reader) => {
                for imp in reader {
                    let imp: wasmparser::ComponentImport<'_> = imp.map_err(|e| parse_err(&e))?;
                    let raw_name: &str = imp.name.name;
                    let raw_type_index: Option<u32> = type_ref_index(&imp.ty);
                    manifest.world_imports.push(ComponentImportRecord {
                        name: raw_name.to_owned(),
                        type_kind: (&imp.ty).into(),
                        raw_type_index,
                    });
                }
            }
            Payload::ComponentExportSection(reader) => {
                for exp in reader {
                    let exp: wasmparser::ComponentExport<'_> = exp.map_err(|e| parse_err(&e))?;
                    manifest.world_exports.push(ComponentExportRecord {
                        name: exp.name.name.to_owned(),
                        kind: exp.kind.into(),
                        index: exp.index,
                        typed: exp.ty.is_some(),
                    });
                }
            }
            Payload::ComponentTypeSection(reader) => {
                manifest.type_decl_count = manifest.type_decl_count.saturating_add(reader.count());
            }
            Payload::CoreTypeSection(reader) => {
                manifest.core_type_decl_count =
                    manifest.core_type_decl_count.saturating_add(reader.count());
            }
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                manifest
                    .embedded_modules
                    .push(range_to_embedded(0, unchecked_range));
            }
            Payload::ComponentSection {
                unchecked_range, ..
            } => {
                manifest
                    .embedded_components
                    .push(range_to_embedded(0, unchecked_range));
            }
            Payload::ComponentCanonicalSection(reader) => {
                for canon in reader {
                    let canon: wasmparser::CanonicalFunction = canon.map_err(|e| parse_err(&e))?;
                    manifest.adapter_funcs.push(AdapterFuncRecord {
                        kind: classify_canonical(&canon),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(manifest)
}

#[inline]
const fn range_to_embedded(depth: u8, range: Range<usize>) -> EmbeddedModule {
    let size: usize = range.end.saturating_sub(range.start);
    EmbeddedModule {
        depth,
        start: range.start,
        end: range.end,
        size,
    }
}

#[inline]
const fn type_ref_index(ty: &ComponentTypeRef) -> Option<u32> {
    match ty {
        ComponentTypeRef::Module(i)
        | ComponentTypeRef::Func(i)
        | ComponentTypeRef::Instance(i)
        | ComponentTypeRef::Component(i)
        | ComponentTypeRef::Type(wasmparser::TypeBounds::Eq(i)) => Some(*i),
        ComponentTypeRef::Type(wasmparser::TypeBounds::SubResource)
        | ComponentTypeRef::Value(_) => None,
    }
}

const fn classify_canonical(canon: &wasmparser::CanonicalFunction) -> AdapterFuncKind {
    use wasmparser::CanonicalFunction as C;
    match canon {
        C::Lift { .. } => AdapterFuncKind::Lift,
        C::Lower { .. } => AdapterFuncKind::Lower,
        C::ResourceNew { .. } => AdapterFuncKind::ResourceNew,
        C::ResourceDrop { .. } | C::ResourceDropAsync { .. } => AdapterFuncKind::ResourceDrop,
        C::ResourceRep { .. } => AdapterFuncKind::ResourceRep,
        C::TaskReturn { .. } => AdapterFuncKind::TaskReturn,
        C::TaskCancel => AdapterFuncKind::TaskCancel,
        _ => AdapterFuncKind::Other,
    }
}

#[inline]
fn parse_err(e: &wasmparser::BinaryReaderError) -> Error {
    Error::Parse(format!("{e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn minimal_core_module() -> [u8; 8] {
        [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    fn minimal_component() -> [u8; 8] {
        [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00]
    }

    #[test]
    fn classify_recognises_core_module() {
        let bytes: [u8; 8] = minimal_core_module();
        assert_eq!(
            classify_preamble(&bytes),
            ComponentClassification::CoreModule
        );
    }

    #[test]
    fn classify_recognises_component() {
        let bytes: [u8; 8] = minimal_component();
        assert_eq!(
            classify_preamble(&bytes),
            ComponentClassification::Component
        );
    }

    #[test]
    fn classify_rejects_garbage() {
        assert_eq!(classify_preamble(b"xx"), ComponentClassification::Unknown);
        assert_eq!(
            classify_preamble(b"GIF89a__"),
            ComponentClassification::Unknown
        );
    }

    #[test]
    fn core_module_parse_returns_no_component_data() {
        let bytes: [u8; 8] = minimal_core_module();
        let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse");
        assert_eq!(manifest.classification, ComponentClassification::CoreModule);
        assert!(manifest.world_imports.is_empty());
        assert!(manifest.world_exports.is_empty());
        assert!(manifest.embedded_modules.is_empty());
        assert!(manifest.embedded_components.is_empty());
        assert!(manifest.adapter_funcs.is_empty());
    }

    #[test]
    fn minimal_component_parses_and_reports_classification() {
        let bytes: [u8; 8] = minimal_component();
        let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse");
        assert_eq!(manifest.classification, ComponentClassification::Component);
    }

    const COMPONENT_WITH_NESTED_MODULE: &str = r#"
        (component
          (core module $m
            (func (export "add") (param i32 i32) (result i32)
              local.get 0
              local.get 1
              i32.add))
          (core instance $i (instantiate $m))
          (alias core export $i "add" (core func $add))
          (func $lifted (param "x" u32) (param "y" u32) (result u32)
            (canon lift (core func $add)))
          (export "add" (func $lifted)))
    "#;

    #[test]
    fn embedded_module_range_carves_a_standalone_validating_module() {
        let bytes: Vec<u8> = wat::parse_str(COMPONENT_WITH_NESTED_MODULE).expect("encode wat");
        let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse");
        let member: &EmbeddedModule = manifest
            .embedded_modules
            .first()
            .expect("one embedded module");
        let slice: &[u8] = &bytes[member.start..member.end];
        assert_eq!(
            &slice[..4],
            WASM_MAGIC,
            "carved embedded module must begin with the wasm magic"
        );
        assert!(
            wasmparser::validate(slice).is_ok(),
            "carved embedded module bytes must validate as a standalone core module"
        );
    }

    #[test]
    fn component_with_nested_module_records_embedded_and_adapter() {
        let bytes: Vec<u8> = wat::parse_str(COMPONENT_WITH_NESTED_MODULE).expect("encode wat");
        assert_eq!(
            classify_preamble(&bytes),
            ComponentClassification::Component
        );
        let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse");
        assert_eq!(manifest.classification, ComponentClassification::Component);
        assert!(
            !manifest.embedded_modules.is_empty(),
            "expected embedded core module"
        );
        assert!(
            manifest
                .adapter_funcs
                .iter()
                .any(|a| matches!(a.kind, AdapterFuncKind::Lift)),
            "expected at least one Lift adapter"
        );
        assert!(
            manifest
                .world_exports
                .iter()
                .any(|e| e.name == "add" && matches!(e.kind, ComponentExternKind::Func)),
            "expected exported add func"
        );
    }
}
