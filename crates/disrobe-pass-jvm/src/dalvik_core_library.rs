use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::Deserialize;

use crate::dex::{DexFile, MethodId};

const CONFIGURATION_IDENTIFIER: &str = "com.tools.android:desugar_jdk_libs_configuration:2.1.5";
const MAX_MARKER_BYTES: usize = 4096;
const MAX_MARKER_IDENTIFIERS: usize = 16;
const MAX_DIAGNOSTICS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreInvokeShape {
    Preserve,
    Static,
    ReceiverFirst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoreMethodProjection {
    pub(crate) owner: String,
    pub(crate) name: String,
    pub(crate) parameters: Vec<String>,
    pub(crate) return_type: String,
    pub(crate) shape: CoreInvokeShape,
}

#[derive(Debug, Default)]
pub(crate) struct CoreLibraryRecovery {
    broad_relocation: bool,
    defined_classes: BTreeSet<String>,
    diagnostics: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DesugarMarker {
    #[serde(rename = "desugared-library-identifiers")]
    identifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct ExactHelperProjection {
    source_owner: &'static str,
    source_name: &'static str,
    source_parameters: &'static [&'static str],
    source_return_type: &'static str,
    owner: &'static str,
    name: &'static str,
    parameters: &'static [&'static str],
    return_type: &'static str,
    shape: CoreInvokeShape,
}

const EXACT_HELPERS: &[ExactHelperProjection] = &[
    ExactHelperProjection {
        source_owner: "Lj$/util/DateRetargetClass;",
        source_name: "toInstant",
        source_parameters: &["Ljava/util/Date;"],
        source_return_type: "Lj$/time/Instant;",
        owner: "Ljava/util/Date;",
        name: "toInstant",
        parameters: &[],
        return_type: "Ljava/time/Instant;",
        shape: CoreInvokeShape::ReceiverFirst,
    },
    ExactHelperProjection {
        source_owner: "Lj$/util/DesugarDate;",
        source_name: "from",
        source_parameters: &["Lj$/time/Instant;"],
        source_return_type: "Ljava/util/Date;",
        owner: "Ljava/util/Date;",
        name: "from",
        parameters: &["Ljava/time/Instant;"],
        return_type: "Ljava/util/Date;",
        shape: CoreInvokeShape::Static,
    },
    ExactHelperProjection {
        source_owner: "Lj$/util/concurrent/DesugarTimeUnit;",
        source_name: "convert",
        source_parameters: &["Ljava/util/concurrent/TimeUnit;", "Lj$/time/Duration;"],
        source_return_type: "J",
        owner: "Ljava/util/concurrent/TimeUnit;",
        name: "convert",
        parameters: &["Ljava/time/Duration;"],
        return_type: "J",
        shape: CoreInvokeShape::ReceiverFirst,
    },
];

impl CoreLibraryRecovery {
    pub(crate) fn analyze(dex: &DexFile) -> Self {
        let mut marker_matches: bool = false;
        let mut marker_conflicts: bool = false;
        for value in &dex.strings {
            if !value.starts_with("~~D8") && !value.starts_with("~~R8") {
                continue;
            }
            let Some(marker): Option<DesugarMarker> = parse_marker(value) else {
                marker_conflicts = true;
                continue;
            };
            if marker.identifiers.len() > MAX_MARKER_IDENTIFIERS {
                marker_conflicts = true;
                continue;
            }
            for identifier in marker.identifiers {
                if identifier == CONFIGURATION_IDENTIFIER {
                    marker_matches = true;
                } else {
                    marker_conflicts = true;
                }
            }
        }
        let defined_classes: BTreeSet<String> = dex.class_descriptors.iter().cloned().collect();
        let owns_relocated_class: bool = defined_classes
            .iter()
            .any(|descriptor: &String| descriptor.starts_with("Lj$/"));
        let mut recovery: Self = Self {
            broad_relocation: marker_matches && !marker_conflicts && !owns_relocated_class,
            defined_classes,
            diagnostics: Vec::new(),
        };
        let has_relocated_reference: bool = dex
            .type_names
            .iter()
            .any(|descriptor: &String| contains_j_object(descriptor));
        if has_relocated_reference && !recovery.broad_relocation {
            let reason: &str = if marker_conflicts {
                "DR-JVM-CORE-0002 conflicting or malformed desugared-library marker"
            } else if owns_relocated_class {
                "DR-JVM-CORE-0003 program defines a j$/ class"
            } else {
                "DR-JVM-CORE-0001 supported desugared-library marker is absent"
            };
            recovery.diagnostics.push(reason.to_string());
        }
        if recovery.broad_relocation {
            let mut refusals: BTreeSet<String> = BTreeSet::new();
            let retained_limit: usize = MAX_DIAGNOSTICS - 1;
            let mut refusal_count: usize = 0;
            for method in &dex.method_ids {
                if method.class.starts_with("Lj$/") && recovery.project_method(method).is_none() {
                    refusal_count += 1;
                    let parameters: String = method.proto.parameters.join("");
                    refusals.insert(format!(
                        "DR-JVM-CORE-0004 unsupported generated call {}->{}({}){}",
                        method.class, method.name, parameters, method.proto.return_type
                    ));
                    if refusals.len() > retained_limit {
                        let _: Option<String> = refusals.pop_last();
                    }
                }
            }
            let retained_count: usize = refusals.len();
            recovery.diagnostics.extend(refusals);
            if refusal_count > retained_count {
                recovery.diagnostics.push(format!(
                    "DR-JVM-CORE-0005 omitted {} additional generated-call diagnostics at limit {}",
                    refusal_count - retained_count,
                    MAX_DIAGNOSTICS
                ));
            }
        }
        recovery
    }

    pub(crate) fn project_type(&self, descriptor: &str) -> String {
        project_descriptor(descriptor, self.broad_relocation)
    }

    pub(crate) fn project_method(&self, method: &MethodId) -> Option<CoreMethodProjection> {
        if method.name.is_empty()
            || !descriptor_is_valid(&method.class)
            || !return_descriptor_is_valid(&method.proto.return_type)
            || method
                .proto
                .parameters
                .iter()
                .any(|parameter: &String| !descriptor_is_valid(parameter))
        {
            return None;
        }
        if !self.defined_classes.contains(&method.class)
            && let Some(projection) = exact_helper_projection(method)
        {
            return Some(projection);
        }
        if self.broad_relocation {
            if let Some(owner) = method.class.strip_suffix("$-EL;") {
                let emitted_owner: String = format!("{owner};");
                if !is_relocatable(&emitted_owner) {
                    return None;
                }
                let receiver: &String = method.proto.parameters.first()?;
                let projected_owner: String = project_descriptor(&emitted_owner, true);
                if project_descriptor(receiver, true) != projected_owner {
                    return None;
                }
                return Some(CoreMethodProjection {
                    owner: projected_owner,
                    name: method.name.clone(),
                    parameters: method
                        .proto
                        .parameters
                        .iter()
                        .skip(1)
                        .map(|parameter: &String| project_descriptor(parameter, true))
                        .collect(),
                    return_type: project_descriptor(&method.proto.return_type, true),
                    shape: CoreInvokeShape::ReceiverFirst,
                });
            }
            if let Some(owner) = method.class.strip_suffix("$-CC;") {
                let emitted_owner: String = format!("{owner};");
                if !is_relocatable(&emitted_owner) {
                    return None;
                }
                let projected_owner: String = project_descriptor(&emitted_owner, true);
                if let Some(name) = method.name.strip_prefix("$default$") {
                    if name.is_empty() {
                        return None;
                    }
                    let receiver: &String = method.proto.parameters.first()?;
                    if project_descriptor(receiver, true) != projected_owner {
                        return None;
                    }
                    return Some(CoreMethodProjection {
                        owner: projected_owner,
                        name: name.to_string(),
                        parameters: method
                            .proto
                            .parameters
                            .iter()
                            .skip(1)
                            .map(|parameter: &String| project_descriptor(parameter, true))
                            .collect(),
                        return_type: project_descriptor(&method.proto.return_type, true),
                        shape: CoreInvokeShape::ReceiverFirst,
                    });
                }
                return Some(CoreMethodProjection {
                    owner: projected_owner,
                    name: method.name.clone(),
                    parameters: method
                        .proto
                        .parameters
                        .iter()
                        .map(|parameter: &String| project_descriptor(parameter, true))
                        .collect(),
                    return_type: project_descriptor(&method.proto.return_type, true),
                    shape: CoreInvokeShape::Static,
                });
            }
            if is_relocatable(&method.class) {
                return Some(CoreMethodProjection {
                    owner: project_descriptor(&method.class, true),
                    name: method.name.clone(),
                    parameters: method
                        .proto
                        .parameters
                        .iter()
                        .map(|parameter: &String| project_descriptor(parameter, true))
                        .collect(),
                    return_type: project_descriptor(&method.proto.return_type, true),
                    shape: CoreInvokeShape::Preserve,
                });
            }
        }
        None
    }

    pub(crate) fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

fn parse_marker(value: &str) -> Option<DesugarMarker> {
    if value.len() > MAX_MARKER_BYTES {
        return None;
    }
    let json: &str = value
        .strip_prefix("~~D8")
        .or_else(|| value.strip_prefix("~~R8"))?;
    serde_json::from_str(json).ok()
}

fn exact_helper_projection(method: &MethodId) -> Option<CoreMethodProjection> {
    let index: usize = EXACT_HELPERS
        .binary_search_by(|projection: &ExactHelperProjection| {
            compare_helper_projection(projection, method)
        })
        .ok()?;
    let projection: &ExactHelperProjection = EXACT_HELPERS.get(index)?;
    Some(CoreMethodProjection {
        owner: projection.owner.to_string(),
        name: projection.name.to_string(),
        parameters: projection
            .parameters
            .iter()
            .map(|parameter: &&str| (*parameter).to_string())
            .collect(),
        return_type: projection.return_type.to_string(),
        shape: projection.shape,
    })
}

fn compare_helper_projection(projection: &ExactHelperProjection, method: &MethodId) -> Ordering {
    projection
        .source_owner
        .cmp(method.class.as_str())
        .then_with(|| projection.source_name.cmp(method.name.as_str()))
        .then_with(|| {
            projection
                .source_parameters
                .iter()
                .copied()
                .cmp(method.proto.parameters.iter().map(String::as_str))
        })
        .then_with(|| {
            projection
                .source_return_type
                .cmp(method.proto.return_type.as_str())
        })
}

fn project_descriptor(descriptor: &str, enabled: bool) -> String {
    if !enabled || !descriptor_is_valid(descriptor) {
        return descriptor.to_string();
    }
    let mut output: String = String::with_capacity(descriptor.len());
    let mut cursor: usize = 0;
    while cursor < descriptor.len() {
        let Some((next, object_range)) = next_descriptor_part(descriptor, cursor) else {
            return descriptor.to_string();
        };
        if let Some((object_start, object_end)) = object_range {
            let object: &str = &descriptor[object_start..object_end];
            if is_relocatable(object) {
                output.push_str("Ljava/");
                output.push_str(&object[4..]);
            } else {
                output.push_str(object);
            }
        } else {
            output.push_str(&descriptor[cursor..next]);
        }
        cursor = next;
    }
    output
}

fn contains_j_object(descriptor: &str) -> bool {
    if !descriptor_is_valid(descriptor) {
        return false;
    }
    let mut cursor: usize = 0;
    while cursor < descriptor.len() {
        let Some((next, object_range)) = next_descriptor_part(descriptor, cursor) else {
            return false;
        };
        if object_range.is_some_and(|(object_start, object_end): (usize, usize)| {
            descriptor[object_start..object_end].starts_with("Lj$/")
        }) {
            return true;
        }
        cursor = next;
    }
    false
}

fn descriptor_is_valid(descriptor: &str) -> bool {
    if descriptor.starts_with('(') {
        let mut cursor: usize = 1;
        while descriptor.as_bytes().get(cursor).copied() != Some(b')') {
            let Some(next): Option<usize> = type_descriptor_end(descriptor, cursor, false) else {
                return false;
            };
            cursor = next;
        }
        let Some(return_start): Option<usize> = cursor.checked_add(1) else {
            return false;
        };
        return type_descriptor_end(descriptor, return_start, true) == Some(descriptor.len());
    }
    type_descriptor_end(descriptor, 0, false) == Some(descriptor.len())
}

fn return_descriptor_is_valid(descriptor: &str) -> bool {
    type_descriptor_end(descriptor, 0, true) == Some(descriptor.len())
}

fn type_descriptor_end(descriptor: &str, cursor: usize, allow_void: bool) -> Option<usize> {
    let mut atom_start: usize = cursor;
    let mut dimensions: usize = 0;
    while descriptor.as_bytes().get(atom_start).copied() == Some(b'[') {
        dimensions = dimensions.checked_add(1)?;
        if dimensions > usize::from(crate::descriptor::MAX_ARRAY_DIMENSIONS) {
            return None;
        }
        atom_start = atom_start.checked_add(1)?;
    }
    let byte: u8 = *descriptor.as_bytes().get(atom_start)?;
    if matches!(byte, b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z') {
        return atom_start.checked_add(1);
    }
    if byte == b'V' && allow_void && atom_start == cursor {
        return atom_start.checked_add(1);
    }
    if byte != b'L' {
        return None;
    }
    let name_start: usize = atom_start.checked_add(1)?;
    let name_suffix: &str = descriptor.get(name_start..)?;
    let relative_end: usize = name_suffix.find(';')?;
    let internal_name: &str = &name_suffix[..relative_end];
    if internal_name.is_empty()
        || internal_name
            .bytes()
            .any(|value: u8| matches!(value, b'[' | b'(' | b')' | b'.'))
        || internal_name
            .split('/')
            .any(|component: &str| component.is_empty())
    {
        return None;
    }
    name_start.checked_add(relative_end)?.checked_add(1)
}

fn next_descriptor_part(
    descriptor: &str,
    cursor: usize,
) -> Option<(usize, Option<(usize, usize)>)> {
    let byte: u8 = *descriptor.as_bytes().get(cursor)?;
    if byte == b'L' {
        let object_end: usize = cursor
            .checked_add(descriptor.get(cursor..)?.find(';')?)?
            .checked_add(1)?;
        return Some((object_end, Some((cursor, object_end))));
    }
    if matches!(
        byte,
        b'(' | b')' | b'[' | b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'V' | b'Z'
    ) {
        return cursor.checked_add(1).map(|next: usize| (next, None));
    }
    None
}

fn is_relocatable(descriptor: &str) -> bool {
    descriptor_is_valid(descriptor)
        && matches!(
            descriptor,
            value if value.starts_with("Lj$/time/")
                || value.starts_with("Lj$/util/")
                || value.starts_with("Lj$/nio/")
        )
        && !descriptor
            .rsplit_once('/')
            .is_some_and(|(_, name): (&str, &str)| name.starts_with("Desugar"))
        && !descriptor.contains("$-CC;")
        && !descriptor.contains("$-EL;")
        && !descriptor.contains("$Wrapper")
        && !descriptor.contains("$VivifiedWrapper")
        && !descriptor.contains("ApiFlips")
        && !descriptor.contains("Conversions")
        && !descriptor.contains("RetargetClass")
}

#[cfg(test)]
mod tests {
    use super::{
        CoreLibraryRecovery, MAX_DIAGNOSTICS, MAX_MARKER_BYTES, contains_j_object, parse_marker,
        project_descriptor,
    };
    use crate::dex::{DexFile, MethodId};

    const LOW_MINIMUM: &[u8] =
        include_bytes!("../../../corpus/jvm/desugar-core/CoreLibraryProbe-min21.dex");

    fn fixture_dex() -> Option<DexFile> {
        crate::dex::parse(LOW_MINIMUM).ok()
    }

    fn supported_recovery() -> Option<CoreLibraryRecovery> {
        fixture_dex().map(|dex: DexFile| CoreLibraryRecovery::analyze(&dex))
    }

    #[test]
    fn wrapper_and_api_flip_descriptors_are_not_projected() {
        for descriptor in [
            "Lj$/util/Optional$Wrapper;",
            "Lj$/util/Optional$VivifiedWrapper;",
            "Lj$/nio/file/PathApiFlips;",
            "Lj$/nio/file/PathApiFlips$DirectoryStreamFilterWrapper;",
            "Lj$/nio/file/attribute/FileAttributeConversions$PosixFileAttributesWrapper;",
            "Lj$/util/stream/FlatMapApiFlips$FunctionStreamWrapper;",
            "Lj$/util/OptionalConversions;",
            "Lj$/time/DesugarClock;",
            "Lj$/util/Collection$-EL;",
            "Lj$/util/stream/IntStream$-CC;",
        ] {
            assert_eq!(project_descriptor(descriptor, true), descriptor);
        }
        assert_eq!(
            project_descriptor("([Lj$/time/Duration;)Lj$/util/Optional;", true),
            "([Ljava/time/Duration;)Ljava/util/Optional;"
        );
        assert_eq!(
            project_descriptor("Lfoo/Lj$/time/Duration;", true),
            "Lfoo/Lj$/time/Duration;"
        );
        assert!(!contains_j_object("Lfoo/Lj$/time/Duration;"));
        for malformed in [
            "garbageLj$/time/Duration;",
            "(ILj$/time/Duration;",
            "[V",
            "L/j$/time/Duration;",
            "Lj$/time//Duration;",
            "Lj$/time/Duration/;",
        ] {
            assert_eq!(project_descriptor(malformed, true), malformed);
            assert!(!contains_j_object(malformed));
        }
        let oversized_array: String = format!("{}Lj$/time/Duration;", "[".repeat(256));
        assert_eq!(project_descriptor(&oversized_array, true), oversized_array);
    }

    #[test]
    fn internal_desugared_library_namespaces_are_not_projected_under_java() {
        let recovery: Option<CoreLibraryRecovery> = supported_recovery();
        assert!(recovery.is_some());
        let Some(recovery): Option<CoreLibraryRecovery> = recovery else {
            return;
        };
        assert_eq!(
            recovery.project_type("Lj$/jdk/internal/misc/Unsafe;"),
            "Lj$/jdk/internal/misc/Unsafe;"
        );
        assert_eq!(
            recovery.project_type("Lj$/sun/nio/ch/Interruptible;"),
            "Lj$/sun/nio/ch/Interruptible;"
        );
        assert_eq!(
            recovery.project_type("Lj$/adapter/HybridFileSystemProvider;"),
            "Lj$/adapter/HybridFileSystemProvider;"
        );
    }

    #[test]
    fn marker_parser_is_bounded_and_requires_d8_or_r8_framing() {
        assert!(parse_marker("{}").is_none());
        assert!(parse_marker(&format!("~~D8{}", "x".repeat(MAX_MARKER_BYTES))).is_none());
    }

    #[test]
    fn generated_call_diagnostics_are_bounded_and_report_omissions() {
        let dex: Option<DexFile> = fixture_dex();
        assert!(dex.is_some());
        let Some(mut dex): Option<DexFile> = dex else {
            return;
        };
        let template: Option<MethodId> = dex
            .method_ids
            .iter()
            .find(|method: &&MethodId| method.class == "Lj$/util/concurrent/DesugarTimeUnit;")
            .cloned();
        assert!(template.is_some());
        let Some(template): Option<MethodId> = template else {
            return;
        };
        dex.method_ids = (0..300)
            .map(|index: usize| {
                let mut method: MethodId = template.clone();
                method.name = format!("unsupported{index:03}");
                method
            })
            .collect();
        let recovery: CoreLibraryRecovery = CoreLibraryRecovery::analyze(&dex);
        assert_eq!(recovery.diagnostics().len(), MAX_DIAGNOSTICS);
        assert!(
            recovery
                .diagnostics()
                .last()
                .is_some_and(|reason: &String| reason.contains("omitted 45"))
        );
    }

    #[test]
    fn unknown_j_prefix_call_remains_unchanged_with_a_named_diagnostic() {
        let dex: Option<DexFile> = fixture_dex();
        assert!(dex.is_some());
        let Some(mut dex): Option<DexFile> = dex else {
            return;
        };
        let method: Option<MethodId> = dex.method_ids.first().cloned();
        assert!(method.is_some());
        let Some(mut method): Option<MethodId> = method else {
            return;
        };
        method.class = "Lj$/adapter/HybridFileSystemProvider;".to_string();
        method.name = "open".to_string();
        dex.method_ids = vec![method.clone()];
        let recovery: CoreLibraryRecovery = CoreLibraryRecovery::analyze(&dex);
        assert_eq!(
            recovery.project_type(&method.class),
            "Lj$/adapter/HybridFileSystemProvider;"
        );
        assert!(recovery.project_method(&method).is_none());
        assert_eq!(recovery.diagnostics().len(), 1);
        assert!(
            recovery.diagnostics()[0]
                .contains("unsupported generated call Lj$/adapter/HybridFileSystemProvider;->open")
        );
    }

    #[test]
    fn unknown_and_wrapper_dispatch_helpers_are_not_projected() {
        let recovery: Option<CoreLibraryRecovery> = supported_recovery();
        assert!(recovery.is_some());
        let Some(recovery): Option<CoreLibraryRecovery> = recovery else {
            return;
        };
        let dex: Option<DexFile> = fixture_dex();
        assert!(dex.is_some());
        let Some(dex): Option<DexFile> = dex else {
            return;
        };
        let template: Option<MethodId> = dex.method_ids.first().cloned();
        assert!(template.is_some());
        let Some(template): Option<MethodId> = template else {
            return;
        };
        for (owner, receiver) in [
            (
                "Lj$/adapter/HybridFileSystemProvider$-EL;",
                "Lj$/adapter/HybridFileSystemProvider;",
            ),
            (
                "Lj$/util/Optional$Wrapper$-EL;",
                "Lj$/util/Optional$Wrapper;",
            ),
        ] {
            let mut method: MethodId = template.clone();
            method.class = owner.to_string();
            method.proto.parameters = vec![receiver.to_string()];
            assert!(recovery.project_method(&method).is_none());
        }
        let mut static_helper: MethodId = template;
        static_helper.class = "Lj$/adapter/HybridFileSystemProvider$-CC;".to_string();
        assert!(recovery.project_method(&static_helper).is_none());
        static_helper.class = "Lj$/util/Collection$-CC;".to_string();
        static_helper.name = "$default$".to_string();
        assert!(recovery.project_method(&static_helper).is_none());
        let mut malformed: MethodId = static_helper;
        malformed.class = "Lj$/time/Duration;trailing".to_string();
        assert!(recovery.project_method(&malformed).is_none());
        malformed.class = "Lj$/time/Duration;".to_string();
        malformed.proto.parameters = vec!["Lj$/time/Duration;trailing".to_string()];
        assert!(recovery.project_method(&malformed).is_none());
        malformed.proto.parameters.clear();
        malformed.proto.return_type = "Vtrailing".to_string();
        assert!(recovery.project_method(&malformed).is_none());
    }

    #[test]
    fn array_only_relocated_reference_reports_the_missing_marker() {
        let dex: Option<DexFile> = fixture_dex();
        assert!(dex.is_some());
        let Some(mut dex): Option<DexFile> = dex else {
            return;
        };
        dex.strings
            .retain(|value: &String| !value.starts_with("~~D8"));
        dex.type_names = vec!["[Lj$/time/Duration;".to_string()];
        let recovery: CoreLibraryRecovery = CoreLibraryRecovery::analyze(&dex);
        assert_eq!(
            recovery.diagnostics(),
            ["DR-JVM-CORE-0001 supported desugared-library marker is absent"]
        );
    }
}
