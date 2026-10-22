use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::dalvik_core_library::{CoreInvokeShape, CoreMethodProjection};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{CodeItem, CodeItemsReport, DexCodeState, DexFile, DexMethodCode, MethodId};

const CATALOG_JSON: &str = include_str!("../data/d8_backports.json");
const MAX_CATALOG_ENTRIES: usize = 4_096;
const MAX_FINGERPRINT_INSNS: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackportApi {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub receiver_first: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CatalogEntry {
    fingerprint: String,
    api: BackportApi,
}

static CATALOG: LazyLock<BTreeMap<String, BackportApi>> = LazyLock::new(|| {
    let entries: Vec<CatalogEntry> = serde_json::from_str(CATALOG_JSON).unwrap_or_default();
    entries
        .into_iter()
        .take(MAX_CATALOG_ENTRIES)
        .map(|entry: CatalogEntry| (entry.fingerprint, entry.api))
        .collect()
});

#[derive(Debug, Default)]
pub(crate) struct BackportRecovery {
    by_method: BTreeMap<(String, String, String), BackportApi>,
    suppressed_classes: BTreeSet<String>,
}

impl BackportRecovery {
    pub(crate) fn analyze(dex: &DexFile, report: &CodeItemsReport) -> Self {
        let mut by_class: BTreeMap<&str, Vec<&DexMethodCode>> = BTreeMap::new();
        for method in report.methods() {
            by_class
                .entry(method.class.as_str())
                .or_default()
                .push(method);
        }
        let mut by_method: BTreeMap<(String, String, String), BackportApi> = BTreeMap::new();
        let mut suppressed_classes: BTreeSet<String> = BTreeSet::new();
        for (class, methods) in by_class {
            if methods.is_empty() || !methods.iter().all(|m: &&DexMethodCode| is_static_helper(m)) {
                continue;
            }
            let mut all_recovered: bool = true;
            for method in &methods {
                let recovered: Option<&BackportApi> = method_code(report, method)
                    .and_then(|item: &CodeItem| fingerprint(dex, item))
                    .and_then(|print: String| CATALOG.get(&print));
                match recovered {
                    Some(api) => {
                        by_method.insert(
                            (
                                method.class.clone(),
                                method.method_name.clone(),
                                method.method_descriptor.clone(),
                            ),
                            api.clone(),
                        );
                    }
                    None => all_recovered = false,
                }
            }
            if all_recovered {
                suppressed_classes.insert(class.to_owned());
            }
        }
        Self {
            by_method,
            suppressed_classes,
        }
    }

    pub(crate) fn suppresses_class(&self, class: &str) -> bool {
        self.suppressed_classes.contains(class)
    }

    pub(crate) fn suppresses_method(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.by_method
            .contains_key(&(class.to_owned(), name.to_owned(), descriptor.to_owned()))
    }

    pub(crate) fn project_method(&self, method: &MethodId) -> Option<CoreMethodProjection> {
        let descriptor: String = format!(
            "({}){}",
            method.proto.parameters.join(""),
            method.proto.return_type
        );
        let api: &BackportApi =
            self.by_method
                .get(&(method.class.clone(), method.name.clone(), descriptor))?;
        let parsed: MethodDescriptor = descriptor::parse_method(&api.descriptor)?;
        let parameters: Vec<String> = parsed
            .params
            .iter()
            .map(descriptor::JavaType::descriptor)
            .collect();
        Some(CoreMethodProjection {
            owner: api.owner.clone(),
            name: api.name.clone(),
            parameters,
            return_type: parsed.returns.descriptor(),
            shape: if api.receiver_first {
                CoreInvokeShape::ReceiverFirst
            } else {
                CoreInvokeShape::Static
            },
        })
    }
}

const ACC_STATIC: u32 = 0x0008;

fn is_static_helper(method: &DexMethodCode) -> bool {
    method.access_flags & ACC_STATIC != 0 && method.method_name != "<clinit>"
}

fn method_code<'a>(report: &'a CodeItemsReport, method: &DexMethodCode) -> Option<&'a CodeItem> {
    match method.state {
        DexCodeState::Decoded(index) => report.decoded().get(index),
        DexCodeState::Absent | DexCodeState::Refused(_) => None,
    }
}

fn fingerprint(dex: &DexFile, item: &CodeItem) -> Option<String> {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() || insns.len() > MAX_FINGERPRINT_INSNS {
        return None;
    }
    let normalize = |text: &str| -> String { text.replace(item.class.as_str(), "<self>") };
    let mut out: String = format!("D:{}", normalize(&item.method_descriptor));
    for insn in &insns {
        if insn.mnemonic == "unused" {
            return None;
        }
        if insn.mnemonic == "nop" || insn.mnemonic.starts_with("move-result") {
            continue;
        }
        out.push(' ');
        out.push_str(insn.mnemonic);
        if let Some(literal) = insn.literal {
            let _ = write!(out, "={literal}");
        }
        let Some(index): Option<u32> = insn.index else {
            continue;
        };
        let index: usize = index as usize;
        let reference: String = match insn.op {
            0x1a | 0x1b => format!("S:{}", dex.strings.get(index)?),
            0x1c | 0x1f | 0x20 | 0x22..=0x25 => {
                format!("T:{}", normalize(dex.type_names.get(index)?))
            }
            0x52..=0x6d => {
                let field: &crate::dex::FieldId = dex.field_ids.get(index)?;
                format!(
                    "F:{}.{}:{}",
                    normalize(&field.class),
                    field.name,
                    normalize(&field.type_name)
                )
            }
            0x6e..=0x72 | 0x74..=0x78 => {
                let method: &MethodId = dex.method_ids.get(index)?;
                let name: &str = if method.class == item.class {
                    "<helper>"
                } else {
                    method.name.as_str()
                };
                format!(
                    "M:{}.{name}({}){}",
                    normalize(&method.class),
                    normalize(&method.proto.parameters.join("")),
                    normalize(&method.proto.return_type)
                )
            }
            _ => format!("I:{index}"),
        };
        out.push(' ');
        out.push_str(&reference);
    }
    Some(out)
}

fn is_application_helper(class: &str, probe_class: &str) -> bool {
    if class == probe_class {
        return false;
    }
    !(class.starts_with("Ljava/") || class.starts_with("Lj$/"))
}

pub fn derive_backport_catalog(
    dex: &DexFile,
    bytes: &[u8],
    probes: &[(String, BackportApi)],
) -> Result<String, String> {
    let report: CodeItemsReport = crate::dex::parse_code_items(dex, bytes);
    let mut entries: BTreeMap<String, BackportApi> = BTreeMap::new();
    for (probe_name, api) in probes {
        let probe: &DexMethodCode = report
            .methods()
            .iter()
            .find(|method: &&DexMethodCode| method.method_name == *probe_name)
            .ok_or_else(|| format!("probe method {probe_name} is absent from the dex"))?;
        let probe_item: &CodeItem = method_code(&report, probe)
            .ok_or_else(|| format!("probe method {probe_name} has no decoded body"))?;
        let callee: &MethodId = decode_method(&probe_item.insns)
            .iter()
            .filter(|insn: &&DalvikInsn| matches!(insn.op, 0x71 | 0x77))
            .filter_map(|insn: &DalvikInsn| insn.index)
            .filter_map(|index: u32| dex.method_ids.get(index as usize))
            .rfind(|method: &&MethodId| is_application_helper(&method.class, &probe.class))
            .ok_or_else(|| format!("probe method {probe_name} calls no synthetic helper"))?;
        let callee_descriptor: String = format!(
            "({}){}",
            callee.proto.parameters.join(""),
            callee.proto.return_type
        );
        let helper: &DexMethodCode = report
            .methods()
            .iter()
            .find(|method: &&DexMethodCode| {
                let same_name: bool = method.method_name == callee.name;
                same_name
                    && method.class == callee.class
                    && method.method_descriptor == callee_descriptor
            })
            .ok_or_else(|| format!("helper {}.{} is absent", callee.class, callee.name))?;
        let item: &CodeItem = method_code(&report, helper)
            .ok_or_else(|| format!("helper {}.{} has no body", callee.class, callee.name))?;
        let print: String = fingerprint(dex, item).ok_or_else(|| {
            format!(
                "helper {}.{} does not fingerprint",
                callee.class, callee.name
            )
        })?;
        if let Some(existing) = entries.get(&print)
            && existing != api
        {
            return Err(format!(
                "probe {probe_name} maps a helper already recorded as {}.{}",
                existing.owner, existing.name
            ));
        }
        entries.insert(print, api.clone());
    }
    let catalog: Vec<CatalogEntry> = entries
        .into_iter()
        .map(|(fingerprint, api): (String, BackportApi)| CatalogEntry { fingerprint, api })
        .collect();
    let mut text: String = serde_json::to_string_pretty(&catalog)
        .map_err(|error: serde_json::Error| error.to_string())?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_catalog_parses_and_is_keyed_by_distinct_fingerprints() {
        let entries: Vec<CatalogEntry> = serde_json::from_str(CATALOG_JSON).unwrap_or_default();
        assert!(!entries.is_empty(), "the backport catalog is valid json");
        assert_eq!(entries.len(), CATALOG.len(), "fingerprints are distinct");
        assert!(
            entries.iter().all(|entry: &CatalogEntry| {
                descriptor::parse_method(&entry.api.descriptor).is_some()
                    && entry.api.owner.starts_with('L')
                    && entry.api.owner.ends_with(';')
            }),
            "every entry names a parseable API"
        );
    }
}
