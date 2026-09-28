use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dalvik::DalvikInsn;
use crate::dalvik_cfg::{
    DalvikMethodCfg, DefUses, RegisterAccess, RegisterFlow, RegisterSet, ValueNode,
    build_dalvik_cfg_from_code_item,
};
use crate::dalvik_lift::{
    LiftOutcome, LocalType, MethodContext, MethodIdentity, NamedLocal, PendingResult, RegisterFile,
    RegisterNaming, assignment_value, expr_has_effect, expr_mentions_local, expr_reads_state,
    lift_insn, rename_local, render_branch_condition,
};
use crate::dalvik_typestate::{RegType, TypeStates};
use crate::decompile::Expr;
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, EdgeKind, NaturalLoop, Region, Structurer, SwitchKey,
    compute_dominators, find_natural_loops,
};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{
    ACC_ABSTRACT, ACC_NATIVE, ACC_STATIC, CodeItem, CodeItemsReport, DexCodeState, DexFile,
    DexInnerClass, DexMethodCode, DexSystemMetadata, parse_code_items, parse_system_metadata,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledDex {
    pub source: String,
    #[serde(default)]
    pub sources: BTreeMap<String, String>,
    pub class_count: usize,
    pub method_count: usize,
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
    pub code_scan_complete: bool,
    pub decode_error_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranslatedDefaultMethod {
    pub(crate) source_stem: String,
    pub(crate) owner: Vec<String>,
    pub(crate) abstract_declaration: String,
    pub(crate) definition: String,
}

const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

#[must_use]
pub fn decompile_dex(dex: &DexFile, bytes: &[u8]) -> DecompiledDex {
    crate::name_disambig::ensure_writable_identifier_scope(dex_declared_identifiers(dex), || {
        decompile_dex_scoped(dex, bytes)
    })
}

fn dex_declared_identifiers(dex: &DexFile) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for method in &dex.method_ids {
        names.insert(method.name.clone());
    }
    for field in &dex.field_ids {
        names.insert(field.name.clone());
    }
    for descriptor_name in &dex.class_descriptors {
        let trimmed: &str = crate::descriptor::descriptor_to_binary_name(descriptor_name);
        if let Some(segment) = trimmed.rsplit('/').next() {
            names.insert(segment.to_owned());
        }
    }
    names
}

fn decompile_dex_scoped(dex: &DexFile, bytes: &[u8]) -> DecompiledDex {
    let metadata_report: crate::dex::DexSystemMetadataReport = parse_system_metadata(dex, bytes);
    for diagnostic in &metadata_report.diagnostics {
        crate::debug::dbg_kv("dex-system-metadata-dropped", || {
            format!(
                "{:?} @{}: {}",
                diagnostic.class, diagnostic.offset, diagnostic.reason
            )
        });
    }
    let metadata: DexSystemMetadata = metadata_report.metadata;
    let code_report: CodeItemsReport = parse_code_items(dex, bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let items: Vec<CodeItem> = code_report.decoded().to_vec();
    let interfaces: crate::dalvik_desugar::DefaultInterfaceRecovery =
        crate::dalvik_desugar::DefaultInterfaceRecovery::analyze(dex, bytes, &code_report);
    let functionals: crate::dalvik_desugar::FunctionalRecovery =
        crate::dalvik_desugar::FunctionalRecovery::analyze(dex, bytes, &code_report);
    let core_library: crate::dalvik_core_library::CoreLibraryRecovery =
        crate::dalvik_core_library::CoreLibraryRecovery::analyze(dex);
    let desugar: crate::dalvik_desugar::DesugarView<'_> = crate::dalvik_desugar::DesugarView {
        interfaces: &interfaces,
        functionals: &functionals,
        core_library: &core_library,
    };
    let mut by_class: BTreeMap<String, Vec<&DexMethodCode>> = BTreeMap::new();
    for descriptor_name in &dex.class_descriptors {
        by_class.entry(descriptor_name.clone()).or_default();
    }
    for method in code_report.methods() {
        by_class
            .entry(method.class.clone())
            .or_default()
            .push(method);
    }

    let string_recovery: BTreeMap<String, crate::dalvik_strdec::DexStringRecovery> =
        crate::dalvik_strdec::recover(dex, bytes)
            .into_iter()
            .map(|r: crate::dalvik_strdec::DexStringRecovery| (r.class.clone(), r))
            .collect();
    let generic_recovery: crate::dalvik_strdec_generic::GenericStringRecovery =
        crate::dalvik_strdec_generic::recover(dex, bytes);
    let mut generic_by_method: BTreeMap<
        (String, String),
        Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>,
    > = BTreeMap::new();
    for site in &generic_recovery.call_sites {
        generic_by_method
            .entry((site.caller_class.clone(), site.caller_method.clone()))
            .or_default()
            .push(site);
    }
    let cff_by_method: BTreeMap<(String, String, String), crate::dalvik_dexguard::DalvikMethodCff> =
        crate::dalvik_dexguard::unflatten_dex_methods(&items)
            .1
            .into_iter()
            .filter(|m: &crate::dalvik_dexguard::DalvikMethodCff| m.flattened)
            .map(|m: crate::dalvik_dexguard::DalvikMethodCff| {
                (
                    (
                        m.class.clone(),
                        m.method_name.clone(),
                        m.method_descriptor.clone(),
                    ),
                    m,
                )
            })
            .collect();

    let declarations: BTreeMap<String, crate::dalvik_desugar::ClassDeclaration> =
        crate::dalvik_desugar::class_declarations(dex, bytes).unwrap_or_default();
    let mut rendered_classes: BTreeMap<String, RenderedClass> = BTreeMap::new();
    let renders = |class: &str| {
        by_class.contains_key(class)
            && !desugar.interfaces.suppresses_class(class)
            && !desugar.functionals.suppresses_class(class)
    };
    let (mut children, mut member_owner): (
        BTreeMap<String, Vec<String>>,
        BTreeMap<String, String>,
    ) = rendered_member_classes(&metadata, renders);
    let source_members: BTreeMap<String, (String, String)> = source_named_members(
        by_class.keys().filter(|class: &&String| renders(class)),
        &metadata,
        &member_owner,
        |class: &str| descriptor::binary_to_source(&desugar.core_library.project_type(class)),
        |companion: &str| {
            desugar
                .interfaces
                .recovered_companion_interface(companion)
                .map(str::to_owned)
        },
    );
    for (child, (parent, _simple)) in &source_members {
        children
            .entry(parent.clone())
            .or_default()
            .push(child.clone());
        member_owner.insert(child.clone(), parent.clone());
    }

    let mut static_field_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for field in code_report.fields() {
        if field.is_static {
            *static_field_counts.entry(field.class.as_str()).or_default() += 1;
        }
    }
    for (class_descriptor, methods) in &by_class {
        if desugar.interfaces.suppresses_class(class_descriptor)
            || desugar.functionals.suppresses_class(class_descriptor)
        {
            continue;
        }
        let recovery: Option<&crate::dalvik_strdec::DexStringRecovery> =
            string_recovery.get(class_descriptor);
        let members: ClassMembers<'_> = ClassMembers {
            methods,
            fields: code_report.fields(),
            static_values: class_static_values(
                dex,
                bytes,
                class_descriptor,
                static_field_counts
                    .get(class_descriptor.as_str())
                    .copied()
                    .unwrap_or(0),
            ),
            decoded: &items,
            declaration: declarations.get(class_descriptor),
        };
        let kotlin_evidence: KotlinClassEvidence<'_> = KotlinClassEvidence {
            source_file: source_file_for_class(dex, bytes, class_descriptor),
            metadata_is_absent: matches!(
                class_kotlin_metadata_evidence(dex, bytes, class_descriptor),
                KotlinMetadataEvidence::Absent
            ),
            continuation_impl_bridge: continuation_impl_ancestor(dex, class_descriptor),
            inner_class: metadata
                .classes
                .get(class_descriptor)
                .and_then(|class_metadata| class_metadata.inner_class.as_ref()),
            nested: member_owner.contains_key(class_descriptor),
            source_member_name: source_members
                .get(class_descriptor)
                .map(|(_parent, simple): &(String, String)| simple.as_str()),
        };
        let mut rendered: RenderedClass = render_class(
            dex,
            class_descriptor,
            kotlin_evidence,
            &members,
            recovery,
            &cff_by_method,
            &generic_by_method,
            desugar,
        );
        if rendered_classes.is_empty() && !desugar.core_library.diagnostics().is_empty() {
            let mut annotated: String = String::with_capacity(rendered.text.len());
            for diagnostic in desugar.core_library.diagnostics() {
                let _: std::fmt::Result = writeln!(annotated, "// {diagnostic}");
            }
            annotated.push_str(&rendered.text);
            rendered.text = annotated;
        }
        rendered_classes.insert(class_descriptor.clone(), rendered);
    }
    let class_count: usize = rendered_classes.len();
    let method_count: usize = rendered_classes
        .values()
        .map(|rendered: &RenderedClass| rendered.method_count)
        .sum();
    let fully_lifted: usize = rendered_classes
        .values()
        .map(|rendered: &RenderedClass| rendered.fully_lifted)
        .sum();
    let fallback: usize = rendered_classes
        .values()
        .map(|rendered: &RenderedClass| rendered.fallback)
        .sum();
    let (mut source, sources): (String, BTreeMap<String, String>) =
        compose_rendered_sources(rendered_classes, &children, &member_owner);
    let _: Option<()> = code_report
        .unrecovered_tail()
        .map(|tail: &crate::dex::DexCodeTail| {
            crate::debug::dbg_kv("dex-code-walk-incomplete", || {
                format!("{}: {}", tail.class, tail.error)
            });
            source.push_str("// <decompile: malformed bytecode>\n");
        });

    DecompiledDex {
        source,
        sources,
        class_count,
        method_count,
        fully_lifted_methods: fully_lifted,
        fallback_methods: fallback,
        code_scan_complete,
        decode_error_count,
    }
}

pub(crate) fn translated_default_methods(
    dex: &DexFile,
    bytes: &[u8],
) -> Vec<TranslatedDefaultMethod> {
    let code_report: CodeItemsReport = parse_code_items(dex, bytes);
    let interfaces: crate::dalvik_desugar::DefaultInterfaceRecovery =
        crate::dalvik_desugar::DefaultInterfaceRecovery::analyze(dex, bytes, &code_report);
    let functionals: crate::dalvik_desugar::FunctionalRecovery =
        crate::dalvik_desugar::FunctionalRecovery::analyze(dex, bytes, &code_report);
    let core_library: crate::dalvik_core_library::CoreLibraryRecovery =
        crate::dalvik_core_library::CoreLibraryRecovery::analyze(dex);
    let desugar: crate::dalvik_desugar::DesugarView<'_> = crate::dalvik_desugar::DesugarView {
        interfaces: &interfaces,
        functionals: &functionals,
        core_library: &core_library,
    };
    let inlined_helpers: crate::dalvik_desugar::InlinedHelpers =
        crate::dalvik_desugar::InlinedHelpers::default();
    let metadata: DexSystemMetadata = parse_system_metadata(dex, bytes).metadata;
    interfaces
        .recovered_methods()
        .filter_map(
            |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
                let target: &DexMethodCode =
                    code_report
                        .methods()
                        .iter()
                        .find(|method: &&DexMethodCode| {
                            method.class == recovered.interface
                                && method.method_name == recovered.name
                                && method.method_descriptor == recovered.descriptor
                        })?;
                let bridge: &CodeItem = code_report.decoded().get(recovered.bridge_item)?;
                let (source_stem, owner): (String, Vec<String>) =
                    translated_owner_path(&metadata, &recovered.interface)?;
                let simple: &str = owner.last()?;
                let rendered: RenderedMethod = render_method(
                    dex,
                    ClassRenderInfo {
                        simple,
                        source_file: None,
                        metadata_is_absent: true,
                        continuation_impl_bridge: false,
                        is_interface: true,
                    },
                    bridge,
                    None,
                    None,
                    desugar,
                    Some(recovered),
                    &inlined_helpers,
                );
                if !rendered.fully_lifted {
                    return None;
                }
                let abstract_declaration: String =
                    render_unavailable_method(simple, target, None, desugar)
                        .text
                        .trim()
                        .to_owned();
                Some(TranslatedDefaultMethod {
                    source_stem,
                    owner,
                    abstract_declaration,
                    definition: rendered
                        .text
                        .lines()
                        .map(|line: &str| line.strip_prefix("    ").unwrap_or(line))
                        .collect::<Vec<&str>>()
                        .join("\n"),
                })
            },
        )
        .collect()
}

fn translated_owner_path(
    metadata: &DexSystemMetadata,
    class_descriptor: &str,
) -> Option<(String, Vec<String>)> {
    let mut owner: Vec<String> = Vec::new();
    let mut current: &str = class_descriptor;
    for _ in 0..=MAX_NESTED_CLASS_DEPTH {
        let class_metadata: Option<&crate::dex::DexClassMetadata> = metadata.classes.get(current);
        let Some(inner): Option<&DexInnerClass> =
            class_metadata.and_then(|class| class.inner_class.as_ref())
        else {
            let binary: &str = descriptor::descriptor_to_binary_name(current);
            owner.push(descriptor::java_writable_identifier(
                binary.rsplit('/').next()?,
            ));
            owner.reverse();
            return Some((binary.to_owned(), owner));
        };
        owner.push(descriptor::java_writable_identifier(
            inner.simple_name.as_deref()?,
        ));
        current = class_metadata?.enclosing_class.as_deref()?;
    }
    None
}

struct RenderedClass {
    text: String,
    source_path: String,
    method_count: usize,
    fully_lifted: usize,
    fallback: usize,
}

fn indent_nested_class(rendered: &str) -> String {
    let mut indented: String = String::with_capacity(rendered.len().saturating_add(64));
    for line in rendered.lines() {
        indented.push_str("    ");
        indented.push_str(line);
        indented.push('\n');
    }
    indented
}

fn insert_nested_class(parent: &mut String, child: &str) -> bool {
    let Some(closing_offset): Option<usize> = parent.rfind("}\n") else {
        return false;
    };
    let nested: String = indent_nested_class(child);
    parent.insert_str(closing_offset, &nested);
    true
}

const MAX_NESTED_CLASS_DEPTH: usize = 64;

fn source_named_members<'a>(
    classes: impl Iterator<Item = &'a String>,
    metadata: &DexSystemMetadata,
    member_owner: &BTreeMap<String, String>,
    source_name: impl Fn(&str) -> String,
    companion_interface: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, (String, String)> {
    let candidates: Vec<(&String, String)> = classes
        .map(|class: &String| (class, source_name(class)))
        .collect();
    let by_source: BTreeMap<&str, &String> = candidates
        .iter()
        .map(|(class, source): &(&String, String)| (source.as_str(), *class))
        .collect();
    let mut members: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (class, source) in &candidates {
        let unnamed_inner: bool = metadata
            .classes
            .get(*class)
            .and_then(|class_metadata| class_metadata.inner_class.as_ref())
            .is_some_and(|inner: &DexInnerClass| inner.simple_name.is_none());
        if !unnamed_inner || member_owner.contains_key(*class) {
            continue;
        }
        let Some((parent_source, simple)): Option<(&str, &str)> = source.rsplit_once('.') else {
            continue;
        };
        let Some(parent): Option<&&String> = by_source.get(parent_source) else {
            continue;
        };
        if *parent == *class || !lexically_encloses(metadata, parent, class, &companion_interface) {
            continue;
        }
        members.insert((*class).clone(), ((*parent).clone(), simple.to_owned()));
    }
    members
}

fn lexically_encloses(
    metadata: &DexSystemMetadata,
    ancestor: &str,
    class: &str,
    companion_interface: &impl Fn(&str) -> Option<String>,
) -> bool {
    let mut current: String = class.to_owned();
    for _ in 0..=MAX_NESTED_CLASS_DEPTH {
        let Some(class_metadata): Option<&crate::dex::DexClassMetadata> =
            metadata.classes.get(&current)
        else {
            return false;
        };
        if class_metadata.inner_class.is_none() {
            return false;
        }
        let Some(recorded_owner): Option<&str> =
            class_metadata.enclosing_class.as_deref().or_else(|| {
                class_metadata
                    .enclosing_method
                    .as_ref()
                    .map(|method: &crate::dex::DexEnclosingMethod| method.class.as_str())
            })
        else {
            return false;
        };
        let owner: String =
            companion_interface(recorded_owner).unwrap_or_else(|| recorded_owner.to_owned());
        if owner == ancestor {
            return true;
        }
        current = owner;
    }
    false
}

fn rendered_member_classes(
    metadata: &DexSystemMetadata,
    renders: impl Fn(&str) -> bool,
) -> (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) {
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut member_owner: BTreeMap<String, String> = BTreeMap::new();
    for (owner, class_metadata) in &metadata.classes {
        if !renders(owner) {
            continue;
        }
        for child in &class_metadata.member_classes {
            children
                .entry(owner.clone())
                .or_default()
                .push(child.clone());
            member_owner.insert(child.clone(), owner.clone());
        }
    }
    (children, member_owner)
}

fn compose_rendered_sources(
    mut rendered_classes: BTreeMap<String, RenderedClass>,
    children: &BTreeMap<String, Vec<String>>,
    member_owner: &BTreeMap<String, String>,
) -> (String, BTreeMap<String, String>) {
    let roots: Vec<String> = rendered_classes
        .keys()
        .filter(|descriptor: &&String| !member_owner.contains_key(*descriptor))
        .cloned()
        .collect();
    let mut source: String = String::with_capacity(4096);
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut pending: std::collections::VecDeque<String> = roots.into();
    while let Some(descriptor) = pending
        .pop_front()
        .or_else(|| rendered_classes.keys().next().cloned())
    {
        let mut detached: Vec<RenderedClass> = Vec::new();
        let Some(rendered): Option<RenderedClass> = compose_rendered_class(
            &descriptor,
            children,
            &mut rendered_classes,
            0,
            &mut detached,
        ) else {
            continue;
        };
        for emitted in std::iter::once(rendered).chain(detached) {
            append_rendered_source(&mut source, &mut sources, emitted);
        }
    }
    (source, sources)
}

fn append_rendered_source(
    source: &mut String,
    sources: &mut BTreeMap<String, String>,
    rendered: RenderedClass,
) {
    if !source.is_empty() {
        source.push('\n');
    }
    source.push_str(&rendered.text);
    match sources.entry(rendered.source_path) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(rendered.text);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            let merged: &mut String = slot.get_mut();
            merged.push('\n');
            merged.push_str(&strip_package_header(&rendered.text));
        }
    }
}

fn compose_rendered_class(
    descriptor: &str,
    children: &BTreeMap<String, Vec<String>>,
    rendered_classes: &mut BTreeMap<String, RenderedClass>,
    depth: usize,
    detached: &mut Vec<RenderedClass>,
) -> Option<RenderedClass> {
    let mut rendered: RenderedClass = rendered_classes.remove(descriptor)?;
    if depth < MAX_NESTED_CLASS_DEPTH
        && let Some(member_descriptors) = children.get(descriptor)
    {
        for child_descriptor in member_descriptors {
            let Some(child): Option<RenderedClass> = compose_rendered_class(
                child_descriptor,
                children,
                rendered_classes,
                depth + 1,
                detached,
            ) else {
                continue;
            };
            if !insert_nested_class(&mut rendered.text, &child.text) {
                detached.push(child);
            }
        }
    }
    Some(rendered)
}

fn strip_package_header(rendered: &str) -> String {
    let mut out: String = String::with_capacity(rendered.len());
    let mut skipping: bool = true;
    for line in rendered.lines() {
        if skipping {
            let trimmed: &str = line.trim_start();
            if trimmed.starts_with("package ") && trimmed.ends_with(';') {
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            skipping = false;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn java_source_path(package: Option<&str>, simple: &str) -> String {
    let leaf: &str = simple.split('.').next_back().unwrap_or(simple);
    match package {
        Some(pkg) if !pkg.is_empty() => format!("{}/{leaf}.java", pkg.replace('.', "/")),
        _ => format!("{leaf}.java"),
    }
}

fn source_file_for_class<'a>(
    dex: &'a DexFile,
    bytes: &'a [u8],
    class_descriptor: &str,
) -> Option<&'a str> {
    let class_index: usize = dex
        .class_descriptors
        .iter()
        .position(|descriptor: &String| descriptor == class_descriptor)?;
    let class_offset: usize =
        (dex.header.class_defs_off as usize).checked_add(class_index.checked_mul(32)?)?;
    let source_offset: usize = class_offset.checked_add(16)?;
    let source_index: usize = u32::from_le_bytes(
        bytes
            .get(source_offset..source_offset + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    dex.strings.get(source_index).map(String::as_str)
}

enum KotlinMetadataEvidence {
    Absent,
    Present,
    Unknown,
}

fn class_kotlin_metadata_evidence(
    dex: &DexFile,
    bytes: &[u8],
    class_descriptor: &str,
) -> KotlinMetadataEvidence {
    let Some(class_index): Option<usize> = dex
        .class_descriptors
        .iter()
        .position(|descriptor: &String| descriptor == class_descriptor)
    else {
        return KotlinMetadataEvidence::Unknown;
    };
    let Some(class_offset): Option<usize> =
        (dex.header.class_defs_off as usize).checked_add(class_index.saturating_mul(32))
    else {
        return KotlinMetadataEvidence::Unknown;
    };
    let Some(annotation_directory): Option<usize> = class_offset
        .checked_add(20)
        .and_then(|offset| dex_u32(bytes, offset))
    else {
        return KotlinMetadataEvidence::Unknown;
    };
    if annotation_directory == 0 {
        return KotlinMetadataEvidence::Absent;
    }
    let Some(annotation_set): Option<usize> = dex_u32(bytes, annotation_directory) else {
        return KotlinMetadataEvidence::Unknown;
    };
    if annotation_set == 0 {
        return KotlinMetadataEvidence::Absent;
    }
    let Some(count): Option<usize> = dex_u32(bytes, annotation_set) else {
        return KotlinMetadataEvidence::Unknown;
    };
    let Some(entries_end): Option<usize> = annotation_set.checked_add(4).and_then(|start| {
        count
            .checked_mul(4)
            .and_then(|size| start.checked_add(size))
    }) else {
        return KotlinMetadataEvidence::Unknown;
    };
    if entries_end > bytes.len() {
        return KotlinMetadataEvidence::Unknown;
    }
    for index in 0..count {
        let Some(entry): Option<usize> = annotation_set.checked_add(4 + index.saturating_mul(4))
        else {
            return KotlinMetadataEvidence::Unknown;
        };
        let Some(annotation): Option<usize> = dex_u32(bytes, entry) else {
            return KotlinMetadataEvidence::Unknown;
        };
        if !matches!(bytes.get(annotation), Some(0..=2)) {
            return KotlinMetadataEvidence::Unknown;
        }
        let Some(type_index): Option<usize> = annotation
            .checked_add(1)
            .and_then(|offset: usize| dex_uleb128(bytes, offset))
        else {
            return KotlinMetadataEvidence::Unknown;
        };
        if dex.type_names.get(type_index).is_none() {
            return KotlinMetadataEvidence::Unknown;
        }
        if dex
            .type_names
            .get(type_index)
            .is_some_and(|name: &String| name == "Lkotlin/Metadata;")
        {
            return KotlinMetadataEvidence::Present;
        }
    }
    KotlinMetadataEvidence::Absent
}

fn dex_u32(bytes: &[u8], offset: usize) -> Option<usize> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
        .and_then(|value: u32| usize::try_from(value).ok())
}

fn dex_uleb128(bytes: &[u8], offset: usize) -> Option<usize> {
    let mut value: u32 = 0;
    for shift in (0..35).step_by(7) {
        let byte: u8 = *bytes.get(offset.checked_add(shift / 7)?)?;
        if shift == 28 && byte & 0xf0 != 0 {
            return None;
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return usize::try_from(value).ok();
        }
    }
    None
}

fn continuation_impl_ancestor(dex: &DexFile, class_descriptor: &str) -> bool {
    let mut current: &str = class_descriptor;
    for _ in 0..=dex.class_descriptors.len() {
        if matches!(
            current,
            "Lkotlin/coroutines/jvm/internal/ContinuationImpl;"
                | "Lkotlin/coroutines/jvm/internal/RestrictedContinuationImpl;"
        ) {
            return true;
        }
        let Some(parent): Option<&String> = dex.class_super_descriptors.get(current) else {
            return false;
        };
        current = parent;
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticValue {
    Integral { value_type: u8, value: i64 },
    Float(u32),
    Double(u64),
    String(u32),
    Null,
    Boolean(bool),
    Unrendered(&'static str),
}

type StaticValues = Result<Vec<StaticValue>, &'static str>;

const VALUE_BYTE: u8 = 0x00;
const VALUE_SHORT: u8 = 0x02;
const VALUE_CHAR: u8 = 0x03;
const VALUE_INT: u8 = 0x04;
const VALUE_LONG: u8 = 0x06;

fn encoded_bits(bytes: &[u8], cursor: &mut usize, size: usize) -> Result<u64, &'static str> {
    let end: usize = cursor
        .checked_add(size)
        .ok_or("static value offset overflows")?;
    let value_bytes: &[u8] = bytes.get(*cursor..end).ok_or("static value is truncated")?;
    let mut raw: [u8; 8] = [0; 8];
    raw.get_mut(..size)
        .ok_or("static value is wider than eight bytes")?
        .copy_from_slice(value_bytes);
    *cursor = end;
    Ok(u64::from_le_bytes(raw))
}

fn encoded_static_value(bytes: &[u8], cursor: &mut usize) -> Result<StaticValue, &'static str> {
    let header: u8 = *bytes.get(*cursor).ok_or("static value is truncated")?;
    *cursor = cursor
        .checked_add(1)
        .ok_or("static value offset overflows")?;
    let value_type: u8 = header & 0x1f;
    let value_arg: u8 = header >> 5;
    let size: usize = usize::from(value_arg) + 1;
    let widest: u8 = match value_type {
        VALUE_BYTE => 0,
        VALUE_SHORT | VALUE_CHAR => 1,
        VALUE_INT | 0x10 | 0x15..=0x1b => 3,
        VALUE_LONG | 0x11 => 7,
        0x1e => {
            return if value_arg == 0 {
                Ok(StaticValue::Null)
            } else {
                Err("static null value has a payload")
            };
        }
        0x1f => {
            return match value_arg {
                0 => Ok(StaticValue::Boolean(false)),
                1 => Ok(StaticValue::Boolean(true)),
                _ => Err("static boolean value is neither 0 nor 1"),
            };
        }
        0x1c | 0x1d => return Err("static value is an array or annotation"),
        _ => return Err("static value type is invalid"),
    };
    if value_arg > widest {
        return Err("static value is wider than its type");
    }
    let raw: u64 = encoded_bits(bytes, cursor, size)?;
    let shift: u32 = u32::try_from(64 - size * 8).map_err(|_| "static value width overflows")?;
    let value: StaticValue = match value_type {
        VALUE_BYTE | VALUE_SHORT | VALUE_INT | VALUE_LONG => StaticValue::Integral {
            value_type,
            value: ((raw << shift) as i64) >> shift,
        },
        VALUE_CHAR => StaticValue::Integral {
            value_type,
            value: i64::from(u16::try_from(raw).map_err(|_| "static char value is too wide")?),
        },
        0x10 => StaticValue::Float(
            u32::try_from(raw << ((3 - u32::from(value_arg)) * 8))
                .map_err(|_| "static float value is too wide")?,
        ),
        0x11 => StaticValue::Double(raw << ((7 - u32::from(value_arg)) * 8)),
        0x17 => {
            StaticValue::String(u32::try_from(raw).map_err(|_| "static string index is too wide")?)
        }
        0x18 => StaticValue::Unrendered("class constant"),
        0x1b => StaticValue::Unrendered("enum constant"),
        _ => StaticValue::Unrendered("method, field or handle constant"),
    };
    Ok(value)
}

fn class_static_values(
    dex: &DexFile,
    bytes: &[u8],
    class_descriptor: &str,
    static_fields: usize,
) -> StaticValues {
    let Some(class_index): Option<usize> = dex
        .class_descriptors
        .iter()
        .position(|descriptor: &String| descriptor == class_descriptor)
    else {
        return Ok(Vec::new());
    };
    let offset: usize = class_index
        .checked_mul(32)
        .and_then(|relative: usize| (dex.header.class_defs_off as usize).checked_add(relative))
        .and_then(|class_offset: usize| class_offset.checked_add(28))
        .and_then(|field: usize| dex_u32(bytes, field))
        .ok_or("class definition is truncated")?;
    if offset == 0 {
        return Ok(Vec::new());
    }
    let (count, mut cursor): (u32, usize) =
        crate::dex::read_uleb128(bytes, offset).map_err(|_| "static value count is malformed")?;
    let count: usize = usize::try_from(count).map_err(|_| "static value count overflows")?;
    if count > static_fields {
        return Err("more static values than static fields");
    }
    let mut values: Vec<StaticValue> = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(encoded_static_value(bytes, &mut cursor)?);
    }
    Ok(values)
}

fn static_initializer(
    dex: &DexFile,
    type_name: &str,
    value: StaticValue,
) -> Result<Option<String>, &'static str> {
    let expected: Option<u8> = match type_name {
        "B" => Some(VALUE_BYTE),
        "S" => Some(VALUE_SHORT),
        "C" => Some(VALUE_CHAR),
        "I" => Some(VALUE_INT),
        "J" => Some(VALUE_LONG),
        _ => None,
    };
    let reference: bool = type_name.starts_with('L') || type_name.starts_with('[');
    match value {
        StaticValue::Integral { value: 0, .. }
        | StaticValue::Float(0)
        | StaticValue::Double(0)
        | StaticValue::Boolean(false)
            if !reference =>
        {
            Ok(None)
        }
        StaticValue::Integral { value_type, value } if expected == Some(value_type) => {
            Ok(Some(match value_type {
                VALUE_LONG => format!("{value}L"),
                VALUE_CHAR => crate::dalvik_lift::char_element(
                    u16::try_from(value).map_err(|_| "char value is out of range")?,
                ),
                _ => value.to_string(),
            }))
        }
        StaticValue::Float(bits) if type_name == "F" => {
            Ok(Some(crate::dalvik_lift::float_literal(bits)))
        }
        StaticValue::Double(bits) if type_name == "D" => {
            Ok(Some(crate::dalvik_lift::double_literal(bits)))
        }
        StaticValue::Boolean(true) if type_name == "Z" => Ok(Some("true".to_owned())),
        StaticValue::Null if reference => Ok(None),
        StaticValue::String(index) if reference => dex
            .strings
            .get(index as usize)
            .map(|text: &String| Some(crate::bytecode::escape_java_string(text)))
            .ok_or("string index is out of range"),
        StaticValue::Unrendered(kind) => Err(kind),
        _ => Err("value does not match the field type"),
    }
}

fn field_declarations(
    dex: &DexFile,
    fields: &[crate::dex::DexFieldDecl],
    class_descriptor: &str,
    static_values: &StaticValues,
) -> String {
    let mut out: String = String::new();
    if let Err(reason) = static_values {
        let _: std::fmt::Result = writeln!(
            out,
            "    // <decompile: static field values are not rendered: {reason}>"
        );
    }
    let mut static_ordinal: usize = 0;
    for field in fields {
        if field.class != class_descriptor {
            continue;
        }
        let value: Option<StaticValue> = if field.is_static {
            static_ordinal += 1;
            static_values
                .as_ref()
                .ok()
                .and_then(|values: &Vec<StaticValue>| values.get(static_ordinal - 1))
                .copied()
        } else {
            None
        };
        let Some(rendered): Option<String> =
            descriptor::parse_field(&field.type_name).map(|ty: descriptor::JavaType| ty.render())
        else {
            continue;
        };
        let name: String = descriptor::java_writable_identifier(&field.name);
        let modifier: &str = if field.is_static {
            "public static "
        } else {
            "public "
        };
        let initializer: String = match value
            .map(|value: StaticValue| static_initializer(dex, &field.type_name, value))
        {
            None | Some(Ok(None)) => String::new(),
            Some(Ok(Some(literal))) => format!(" = {literal}"),
            Some(Err(reason)) => {
                let _: std::fmt::Result = writeln!(
                    out,
                    "    // <decompile: static value of {name} is not rendered: {reason}>"
                );
                String::new()
            }
        };
        let _: std::fmt::Result = writeln!(out, "    {modifier}{rendered} {name}{initializer};");
    }
    out
}

fn java_static_block(text: &str) -> Option<std::borrow::Cow<'_, str>> {
    let Some(body): Option<&str> = text
        .strip_prefix(
            "    static {
",
        )
        .and_then(|rest: &str| rest.strip_suffix("    }"))
    else {
        return Some(std::borrow::Cow::Borrowed(text));
    };
    let body: &str = body
        .strip_suffix(
            "        return;
",
        )
        .unwrap_or(body);
    if body.trim().is_empty() {
        None
    } else {
        Some(std::borrow::Cow::Owned(format!(
            "    static {{
{body}    }}"
        )))
    }
}

struct ClassMembers<'a> {
    methods: &'a [&'a DexMethodCode],
    fields: &'a [crate::dex::DexFieldDecl],
    static_values: StaticValues,
    decoded: &'a [CodeItem],
    declaration: Option<&'a crate::dalvik_desugar::ClassDeclaration>,
}

#[derive(Clone, Copy)]
struct ClassRenderInfo<'a> {
    simple: &'a str,
    source_file: Option<&'a str>,
    metadata_is_absent: bool,
    continuation_impl_bridge: bool,
    is_interface: bool,
}

#[derive(Clone, Copy)]
struct KotlinClassEvidence<'a> {
    source_file: Option<&'a str>,
    metadata_is_absent: bool,
    continuation_impl_bridge: bool,
    inner_class: Option<&'a DexInnerClass>,
    nested: bool,
    source_member_name: Option<&'a str>,
}

fn render_class(
    dex: &DexFile,
    class_descriptor: &str,
    kotlin_evidence: KotlinClassEvidence<'_>,
    members: &ClassMembers<'_>,
    recovery: Option<&crate::dalvik_strdec::DexStringRecovery>,
    cff_by_method: &BTreeMap<(String, String, String), crate::dalvik_dexguard::DalvikMethodCff>,
    generic_by_method: &BTreeMap<
        (String, String),
        Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>,
    >,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> RenderedClass {
    let inner_class: Option<&DexInnerClass> = kotlin_evidence.inner_class;
    let projected_class: String = desugar.core_library.project_type(class_descriptor);
    let binary: &str = descriptor::descriptor_to_binary_name(&projected_class);
    let (package_binary, binary_simple): (Option<&str>, &str) = match binary.rfind('/') {
        Some(position) => (Some(&binary[..position]), &binary[position + 1..]),
        None => (None, binary),
    };
    let package: Option<String> = package_binary.map(|value: &str| value.replace('/', "."));
    let top_level_source: String = descriptor::binary_to_source(binary_simple);
    let top_level_simple: String = if top_level_source.contains('.') {
        descriptor::java_writable_identifier(binary_simple)
    } else {
        top_level_source
    };
    let simple: &str = inner_class
        .and_then(|metadata: &DexInnerClass| metadata.simple_name.as_deref())
        .or(kotlin_evidence.source_member_name)
        .unwrap_or(&top_level_simple);

    let mut text: String = String::with_capacity(1024);
    if !kotlin_evidence.nested
        && let Some(pkg) = package.as_deref()
    {
        let _ = writeln!(text, "package {pkg};");
        let _ = writeln!(text);
    }
    let declared_flags: u32 = members.declaration.map_or(
        0,
        |declaration: &crate::dalvik_desugar::ClassDeclaration| declaration.access_flags,
    );
    let is_interface: bool = desugar.interfaces.recovers_interface(class_descriptor)
        || declared_flags & ACC_INTERFACE != 0
        || inner_class.is_some_and(|metadata: &DexInnerClass| {
            u32::from(metadata.access_flags) & ACC_INTERFACE != 0
        });
    let class_is_abstract: bool = declared_flags & ACC_ABSTRACT != 0
        || members
            .methods
            .iter()
            .any(|method: &&DexMethodCode| method.access_flags & ACC_ABSTRACT != 0);
    let class_declaration: String = class_declaration(
        is_interface,
        class_is_abstract,
        inner_class,
        kotlin_evidence.source_member_name.is_some(),
    );
    let supertypes: String =
        supertype_clause(class_descriptor, members.declaration, is_interface, desugar);
    let _: std::fmt::Result = writeln!(text, "{class_declaration} {simple}{supertypes} {{");

    if let Some(rec) = recovery {
        text.push_str(&recovered_strings_annotation(rec));
    }
    text.push_str(&field_declarations(
        dex,
        members.fields,
        class_descriptor,
        &members.static_values,
    ));

    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;
    let inlined_helpers: crate::dalvik_desugar::InlinedHelpers =
        crate::dalvik_desugar::InlinedHelpers::default();
    let mut declared: Vec<(u32, RenderedMethod)> = Vec::with_capacity(members.methods.len());
    let class: ClassRenderInfo<'_> = ClassRenderInfo {
        simple,
        source_file: kotlin_evidence.source_file,
        metadata_is_absent: kotlin_evidence.metadata_is_absent,
        continuation_impl_bridge: kotlin_evidence.continuation_impl_bridge,
        is_interface,
    };
    for method in members.methods {
        if is_clashing_bridge(method, members.methods) {
            continue;
        }
        if desugar.interfaces.suppresses_method(
            &method.class,
            &method.method_name,
            &method.method_descriptor,
        ) {
            continue;
        }
        let recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod> =
            desugar.interfaces.recovered_method(
                &method.class,
                &method.method_name,
                &method.method_descriptor,
            );
        let item: Option<&CodeItem> = match &method.state {
            DexCodeState::Decoded(index) => members.decoded.get(*index),
            DexCodeState::Absent | DexCodeState::Refused(_) => None,
        };
        let cff: Option<&crate::dalvik_dexguard::DalvikMethodCff> = cff_by_method.get(&(
            method.class.clone(),
            method.method_name.clone(),
            method.method_descriptor.clone(),
        ));
        let generic_sites: Option<&Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>> =
            generic_by_method.get(&(method.class.clone(), method.method_name.clone()));
        let rendered: RenderedMethod = match (&method.state, item, recovered_default) {
            (_, _, Some(recovered)) => members.decoded.get(recovered.bridge_item).map_or_else(
                || {
                    render_unavailable_method(
                        simple,
                        method,
                        Some("default interface bridge is absent"),
                        desugar,
                    )
                },
                |bridge: &CodeItem| {
                    render_method(
                        dex,
                        class,
                        bridge,
                        None,
                        None,
                        desugar,
                        Some(recovered),
                        &inlined_helpers,
                    )
                },
            ),
            (DexCodeState::Decoded(_), Some(_), None)
                if method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0 =>
            {
                render_unavailable_method(
                    simple,
                    method,
                    Some("code item is present on a bodyless declaration"),
                    desugar,
                )
            }
            (DexCodeState::Decoded(_), Some(item), None) => render_method(
                dex,
                class,
                item,
                cff,
                generic_sites,
                desugar,
                None,
                &inlined_helpers,
            ),
            (DexCodeState::Decoded(_), None, None) => {
                render_unavailable_method(simple, method, Some("decoded body is absent"), desugar)
            }
            (DexCodeState::Absent, _, None) => {
                let expected_absence: bool = method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0;
                if expected_absence {
                    render_unavailable_method(simple, method, None, desugar)
                } else {
                    render_unavailable_method(simple, method, Some("code item is absent"), desugar)
                }
            }
            (DexCodeState::Refused(error), _, None) => {
                let reason: String = error.to_string();
                render_unavailable_method(simple, method, Some(&reason), desugar)
            }
        };
        declared.push((method.method_index, rendered));
    }

    for (method_index, rendered) in declared {
        if inlined_helpers.contains(method_index) {
            continue;
        }
        if let Some(member) = java_static_block(&rendered.text) {
            let _ = writeln!(text, "{member}");
        }
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else if rendered.has_body || rendered.refused {
            fallback += 1;
        }
    }

    for recovered in desugar.interfaces.injected_methods(class_descriptor) {
        let rendered: RenderedMethod = members.decoded.get(recovered.bridge_item).map_or_else(
            || {
                let metadata: Option<&DexMethodCode> = members
                    .methods
                    .iter()
                    .copied()
                    .find(|method: &&DexMethodCode| method.method_index == recovered.bridge_method);
                metadata.map_or_else(
                    || RenderedMethod {
                        text: String::new(),
                        fully_lifted: false,
                        has_body: false,
                        refused: true,
                    },
                    |method: &DexMethodCode| {
                        render_unavailable_method(
                            simple,
                            method,
                            Some("static interface companion body is absent"),
                            desugar,
                        )
                    },
                )
            },
            |item: &CodeItem| {
                render_method(
                    dex,
                    class,
                    item,
                    None,
                    None,
                    desugar,
                    Some(recovered),
                    &inlined_helpers,
                )
            },
        );
        let _ = writeln!(text, "{}", rendered.text);
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else if rendered.has_body || rendered.refused {
            fallback += 1;
        }
    }

    let _ = writeln!(text, "}}");
    RenderedClass {
        text,
        source_path: java_source_path(package.as_deref(), simple),
        method_count,
        fully_lifted,
        fallback,
    }
}

fn supertype_clause(
    class_descriptor: &str,
    declaration: Option<&crate::dalvik_desugar::ClassDeclaration>,
    is_interface: bool,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> String {
    let source = |descriptor_text: &str| -> String {
        descriptor::binary_to_source(&desugar.core_library.project_type(descriptor_text))
    };
    let mut interfaces: Vec<String> = Vec::new();
    let declared: &[String] = declaration.map_or(
        &[],
        |declaration: &crate::dalvik_desugar::ClassDeclaration| declaration.interfaces.as_slice(),
    );
    let recovered: Option<&std::collections::BTreeSet<String>> =
        desugar.interfaces.implemented_interfaces(class_descriptor);
    for interface in declared.iter().chain(recovered.into_iter().flatten()) {
        let rendered: String = source(interface);
        if !interfaces.contains(&rendered) {
            interfaces.push(rendered);
        }
    }
    let superclass: Option<String> = declaration
        .and_then(|declaration: &crate::dalvik_desugar::ClassDeclaration| {
            declaration.superclass.as_deref()
        })
        .filter(|superclass: &&str| !is_interface && !IMPLICIT_SUPERCLASSES.contains(superclass))
        .map(source);
    let mut clause: String = String::new();
    if let Some(superclass) = superclass {
        let _: std::fmt::Result = write!(clause, " extends {superclass}");
    }
    if !interfaces.is_empty() {
        let keyword: &str = if is_interface {
            "extends"
        } else {
            "implements"
        };
        let _: std::fmt::Result = write!(clause, " {keyword} {}", interfaces.join(", "));
    }
    clause
}

const IMPLICIT_SUPERCLASSES: [&str; 4] = [
    "Ljava/lang/Object;",
    "Ljava/lang/Enum;",
    "Ljava/lang/Record;",
    "Lcom/android/tools/r8/RecordTag;",
];

const ACC_INTERFACE: u32 = 0x0200;
const ACC_BRIDGE: u32 = 0x0040;

fn parameter_list(method_descriptor: &str) -> Option<&str> {
    method_descriptor
        .split_once(')')
        .map(|(parameters, _): (&str, &str)| parameters)
}

fn is_clashing_bridge(method: &DexMethodCode, methods: &[&DexMethodCode]) -> bool {
    let Some(parameters): Option<&str> = parameter_list(&method.method_descriptor) else {
        return false;
    };
    method.access_flags & ACC_BRIDGE != 0
        && methods.iter().any(|other: &&DexMethodCode| {
            other.access_flags & ACC_BRIDGE == 0
                && other.method_name == method.method_name
                && parameter_list(&other.method_descriptor) == Some(parameters)
        })
}

fn class_declaration(
    is_interface: bool,
    inferred_abstract: bool,
    inner_class: Option<&DexInnerClass>,
    source_member: bool,
) -> String {
    let flags: u16 = inner_class.map_or(0, |metadata: &DexInnerClass| metadata.access_flags);
    let mut declaration: String = String::new();
    if flags & 0x0001 != 0 || inner_class.is_none() {
        declaration.push_str("public ");
    } else if flags & 0x0002 != 0 {
        declaration.push_str("private ");
    } else if flags & 0x0004 != 0 {
        declaration.push_str("protected ");
    }
    if !is_interface && (flags & 0x0008 != 0 || source_member) {
        declaration.push_str("static ");
    }
    if !is_interface && flags & 0x0010 != 0 {
        declaration.push_str("final ");
    }
    if is_interface {
        declaration.push_str("interface");
    } else {
        if inferred_abstract || flags & 0x0400 != 0 {
            declaration.push_str("abstract ");
        }
        declaration.push_str("class");
    }
    declaration
}

fn recovered_strings_annotation(rec: &crate::dalvik_strdec::DexStringRecovery) -> String {
    let mut out: String = String::new();
    if !rec.recovered.is_empty() {
        let _ = writeln!(
            out,
            "    // recovered {} encrypted string(s) by running {}() over the static table:",
            rec.recovered.len(),
            rec.decrypt_method
        );
        for d in &rec.recovered {
            let _ = writeln!(
                out,
                "    //   [{}] = {}",
                d.table_index,
                crate::bytecode::escape_java_string(&d.plaintext)
            );
        }
        for site in &rec.reflective_call_sites {
            let _ = writeln!(
                out,
                "    // reflective decrypt call site {}->{} resolves to {}",
                site.caller_class, site.caller_method, site.resolved_member
            );
        }
    } else if rec.runtime_key_wall
        && let Some(reason) = &rec.runtime_key_wall_reason
    {
        let _ = writeln!(out, "    // string decrypt not recoverable: {reason}");
    }
    out
}

fn generic_call_site_annotation(
    sites: &[&crate::dalvik_strdec_generic::CallSiteRecovery],
) -> String {
    let mut out: String = String::new();
    for site in sites {
        match &site.outcome {
            crate::dalvik_strdec_generic::CallSiteOutcome::Recovered(plain) => {
                let _ = writeln!(
                    out,
                    "        // recovered call site pc={}: {}->{}{} = {}",
                    site.pc,
                    site.decrypt_class,
                    site.decrypt_method,
                    site.decrypt_descriptor,
                    crate::bytecode::escape_java_string(plain)
                );
            }
            crate::dalvik_strdec_generic::CallSiteOutcome::Skipped(reason) => {
                let _ = writeln!(
                    out,
                    "        // decrypt call site pc={} to {}->{}{} not recoverable: {reason}",
                    site.pc, site.decrypt_class, site.decrypt_method, site.decrypt_descriptor
                );
            }
        }
    }
    out
}

struct RenderedMethod {
    text: String,
    fully_lifted: bool,
    has_body: bool,
    refused: bool,
}

fn render_unavailable_method(
    class_simple: &str,
    method: &DexMethodCode,
    refusal: Option<&str>,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> RenderedMethod {
    let projected_descriptor: String = desugar.core_library.project_type(&method.method_descriptor);
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(&projected_descriptor);
    let is_constructor: bool = method.method_name == "<init>";
    let is_clinit: bool = method.method_name == "<clinit>";
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let mut modifiers: Vec<&str> = vec!["public"];
    if is_static && !is_clinit {
        modifiers.push("static");
    }
    if method.access_flags & ACC_ABSTRACT != 0 {
        modifiers.push("abstract");
    }
    if method.access_flags & ACC_NATIVE != 0 {
        modifiers.push("native");
    }
    let modifier: String = modifiers.join(" ");
    let params: String = parsed.as_ref().map_or_else(String::new, |descriptor| {
        descriptor
            .params
            .iter()
            .enumerate()
            .map(
                |(index, parameter): (usize, &crate::descriptor::JavaType)| {
                    format!("{} arg{index}", parameter.render())
                },
            )
            .collect::<Vec<String>>()
            .join(", ")
    });
    let mut signature: String = if is_constructor {
        format!("    {modifier} {class_simple}({params})")
    } else if is_clinit {
        "    static".to_string()
    } else {
        let result: String = parsed.as_ref().map_or_else(
            || "void".to_string(),
            |descriptor| descriptor.returns.render(),
        );
        format!(
            "    {modifier} {result} {}({params})",
            crate::descriptor::java_writable_identifier(&method.method_name)
        )
    };
    let Some(reason): Option<&str> = refusal else {
        signature.push(';');
        return RenderedMethod {
            text: signature,
            fully_lifted: false,
            has_body: false,
            refused: false,
        };
    };
    crate::debug::dbg_kv("dex-method-code-reject", || {
        format!(
            "{}->{}{}: {reason}",
            method.class, method.method_name, method.method_descriptor
        )
    });
    let bodyless: bool = method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0;
    if bodyless {
        let _: std::fmt::Result = write!(signature, "; // <decompile: malformed bytecode>");
    } else if is_clinit {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n    }}"
        );
    } else {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n        throw new UnsupportedOperationException(\"malformed bytecode\");\n    }}"
        );
    }
    RenderedMethod {
        text: signature,
        fully_lifted: false,
        has_body: !bodyless,
        refused: true,
    }
}

fn render_method(
    dex: &DexFile,
    class: ClassRenderInfo<'_>,
    item: &CodeItem,
    cff: Option<&crate::dalvik_dexguard::DalvikMethodCff>,
    generic_sites: Option<&Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>>,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
    recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod>,
    inlined_helpers: &crate::dalvik_desugar::InlinedHelpers,
) -> RenderedMethod {
    let method_descriptor: &str = recovered_default.map_or(
        item.method_descriptor.as_str(),
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.descriptor.as_str(),
    );
    let method_name: &str = recovered_default.map_or(
        item.method_name.as_str(),
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| recovered.name.as_str(),
    );
    let projected_method_descriptor: String = desugar.core_library.project_type(method_descriptor);
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(&projected_method_descriptor);
    let footprint: u16 = parsed
        .as_ref()
        .map(|md| {
            md.params
                .iter()
                .map(|p| if p.category_two() { 2u16 } else { 1u16 })
                .sum()
        })
        .unwrap_or(0);
    let is_constructor: bool = method_name == "<init>";
    let is_clinit: bool = method_name == "<clinit>";
    let is_static: bool =
        recovered_default.is_some_and(
            |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
                recovered.kind == crate::dalvik_desugar::InterfaceMethodKind::Static
            },
        ) || recovered_default.is_none() && !is_constructor && item.ins_size <= footprint;
    let continuation_register: Option<u16> = parsed.as_ref().and_then(|descriptor: &MethodDescriptor| {
        descriptor.params.last().and_then(|parameter: &crate::descriptor::JavaType| {
            if matches!(parameter, crate::descriptor::JavaType::Object(name) if name == "Lkotlin/coroutines/Continuation;") {
                item.registers_size.checked_sub(1)
            } else {
                None
            }
        })
    });
    let decoded: Vec<DalvikInsn> = crate::dalvik::decode_method(&item.insns);
    let complete_decode: bool = !decoded.is_empty()
        && decoded
            .iter()
            .all(|insn: &DalvikInsn| insn.mnemonic != "unused")
        && decoded
            .iter()
            .map(|insn: &DalvikInsn| usize::from(insn.width))
            .sum::<usize>()
            == item.insns.len();
    let continuation_is_unused: bool = complete_decode
        && continuation_register
            .is_some_and(|register: u16| !incoming_register_is_used(item, register));
    let hide_final_continuation: bool =
        parsed
            .as_ref()
            .is_some_and(|descriptor: &MethodDescriptor| {
                crate::kotlin::is_metadata_absent_suspend_signature(
                    class.metadata_is_absent,
                    class.source_file,
                    method_name,
                    descriptor,
                    continuation_is_unused,
                    class.continuation_impl_bridge,
                )
            });

    let mut signature: String = String::new();
    let modifier: &str = if recovered_default.is_some_and(
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
            recovered.kind == crate::dalvik_desugar::InterfaceMethodKind::Default
        },
    ) {
        "public default "
    } else if is_static {
        "public static "
    } else if class.is_interface && !is_constructor && !is_clinit {
        "public default "
    } else {
        "public "
    };

    let debug_name_offset: usize = usize::from(recovered_default.is_some_and(
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
            recovered.kind == crate::dalvik_desugar::InterfaceMethodKind::Default
        },
    ));
    let parameter_names: Vec<String> = source_parameter_names(
        item,
        parsed
            .as_ref()
            .map_or(0, |md: &MethodDescriptor| md.params.len()),
        debug_name_offset,
    );
    let params: String = match &parsed {
        Some(md) => md
            .params
            .iter()
            .zip(&parameter_names)
            .enumerate()
            .filter(
                |(i, _): &(usize, (&crate::descriptor::JavaType, &String))| {
                    !hide_final_continuation || *i + 1 != md.params.len()
                },
            )
            .map(
                |(_, (p, name)): (usize, (&crate::descriptor::JavaType, &String))| {
                    format!("{} {name}", p.render())
                },
            )
            .collect::<Vec<String>>()
            .join(", "),
        None => String::new(),
    };

    if is_constructor {
        let _ = write!(signature, "    {modifier}{}({params})", class.simple);
    } else if is_clinit {
        let _ = write!(signature, "    static");
    } else {
        let ret: String = parsed
            .as_ref()
            .map_or_else(|| "void".to_string(), |md| md.returns.render());
        let _ = write!(
            signature,
            "    {modifier}{ret} {}({params})",
            crate::descriptor::java_writable_identifier(method_name)
        );
    }

    let rewired: Option<DalvikMethodCfg> = cff
        .filter(|method: &&crate::dalvik_dexguard::DalvikMethodCff| method.fully_unflattened)
        .and_then(|_| crate::dalvik_dexguard::rewired_method_cfg(item));
    let lifted_from_rewired: bool = rewired.is_some();
    let body: MethodBody = lift_method(
        dex,
        item,
        rewired,
        MethodIdentity {
            declaring_class: &item.class,
            descriptor: method_descriptor,
            is_static,
            is_constructor,
        },
        recovered_default.is_some_and(
            |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
                recovered.kind == crate::dalvik_desugar::InterfaceMethodKind::Default
            },
        ),
        desugar,
        inlined_helpers,
        &parameter_names,
    );
    let cff_note: String = cff.map_or_else(String::new, |method| {
        cff_annotation(method, lifted_from_rewired)
    });
    let generic_note: String = generic_sites
        .map(
            |sites: &Vec<&crate::dalvik_strdec_generic::CallSiteRecovery>| {
                generic_call_site_annotation(sites)
            },
        )
        .unwrap_or_default();
    let text: String = format!(
        "{signature} {{\n{cff_note}{generic_note}{}    }}",
        body.text
    );
    RenderedMethod {
        text,
        fully_lifted: body.fully_lifted,
        has_body: true,
        refused: false,
    }
}

fn source_parameter_names(item: &CodeItem, count: usize, offset: usize) -> Vec<String> {
    let mut chosen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    (0..count)
        .map(|index: usize| {
            let name: String = item
                .param_names
                .get(index + offset)
                .and_then(Option::as_deref)
                .filter(|name: &&str| {
                    crate::name_disambig::is_java_source_identifier(name)
                        && !is_generated_local_name(name)
                        && !chosen.contains(*name)
                })
                .map_or_else(|| format!("arg{index}"), str::to_owned);
            chosen.insert(name.clone());
            name
        })
        .collect()
}

fn is_generated_local_name(name: &str) -> bool {
    name == "ex"
        || ["arg", "var", "tmp", "p", "q", "r", "s"]
            .iter()
            .filter_map(|prefix: &&str| name.strip_prefix(prefix))
            .any(|rest: &str| {
                rest.bytes()
                    .next()
                    .is_some_and(|byte: u8| byte.is_ascii_digit())
            })
}

fn cff_annotation(
    cff: &crate::dalvik_dexguard::DalvikMethodCff,
    lifted_from_rewired: bool,
) -> String {
    if !cff.flattened {
        return String::new();
    }
    let block_order: String = cff
        .recovered_block_order
        .iter()
        .map(u32::to_string)
        .collect::<Vec<String>>()
        .join(", ");
    let mut out: String = String::new();
    if lifted_from_rewired {
        let _ = writeln!(
            out,
            "        // control-flow flattening removed: {} dispatcher(s) rewired, {} state \
             transition(s) redirected to their case block, block order [{block_order}]; the body \
             below is lifted from the rewired graph",
            cff.dispatchers_resolved, cff.edges_redirected
        );
        return out;
    }
    let reason: String = cff.rewire_refusal.as_ref().map_or_else(
        || "the rewired graph could not be rebuilt".to_owned(),
        ToString::to_string,
    );
    let _ = writeln!(
        out,
        "        // control-flow flattening detected: {} dispatcher(s) partly resolved, block order \
         [{block_order}], {} residual dispatcher edge(s); not rewired because {reason}; the body \
         below is still rendered from the flattened graph",
        cff.dispatchers_resolved, cff.residual_dispatcher_edges
    );
    out
}

struct MethodBody {
    text: String,
    fully_lifted: bool,
}

fn incoming_register_is_used(item: &CodeItem, register: u16) -> bool {
    let Some(built): Option<DalvikMethodCfg> = build_dalvik_cfg_from_code_item(item) else {
        return true;
    };
    let mut incoming: Vec<Option<bool>> = vec![None; built.cfg.blocks.len()];
    let entry: usize = built.cfg.entry.0 as usize;
    let Some(entry_state): Option<&mut Option<bool>> = incoming.get_mut(entry) else {
        return true;
    };
    *entry_state = Some(true);
    let mut pending: std::collections::VecDeque<BlockId> =
        std::collections::VecDeque::from([built.cfg.entry]);
    while let Some(block_id) = pending.pop_front() {
        let block_index: usize = block_id.0 as usize;
        let Some(block): Option<&BasicBlock> = built.cfg.blocks.get(block_index) else {
            return true;
        };
        let Some(mut live): Option<bool> = incoming.get(block_index).copied().flatten() else {
            continue;
        };
        let block_entry_live: bool = live;
        let Some(insns): Option<&[DalvikInsn]> =
            built.insns.get(block.insn_range.0..block.insn_range.1)
        else {
            return true;
        };
        for insn in insns {
            if live && instruction_reads_register(insn, register) {
                return true;
            }
            if instruction_writes_register(insn, register) {
                live = false;
            }
        }
        for edge in &block.successors {
            let successor: usize = edge.target.0 as usize;
            let propagated: bool = if matches!(edge.kind, EdgeKind::Exception) {
                block_entry_live
            } else {
                live
            };
            let Some(state): Option<&mut Option<bool>> = incoming.get_mut(successor) else {
                return true;
            };
            let merged: bool = state.unwrap_or(false) || propagated;
            if *state != Some(merged) {
                *state = Some(merged);
                pending.push_back(edge.target);
            }
        }
    }
    false
}

fn instruction_reads_register(insn: &DalvikInsn, register: u16) -> bool {
    if !writes_first_register(insn.op) {
        return insn.regs.contains(&register);
    }
    if matches!(insn.op, 0x1F | 0xB0..=0xCF) {
        return insn.regs.contains(&register);
    }
    insn.regs
        .get(1..)
        .is_some_and(|regs: &[u16]| regs.contains(&register))
}

fn instruction_writes_register(insn: &DalvikInsn, register: u16) -> bool {
    writes_first_register(insn.op) && insn.regs.first() == Some(&register)
}

fn lift_method(
    dex: &DexFile,
    item: &CodeItem,
    rewired: Option<DalvikMethodCfg>,
    identity: MethodIdentity<'_>,
    inline_temporaries: bool,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
    inlined_helpers: &crate::dalvik_desugar::InlinedHelpers,
    parameter_names: &[String],
) -> MethodBody {
    if item.insns.is_empty() {
        return MethodBody {
            text: String::new(),
            fully_lifted: true,
        };
    }
    let Some(built): Option<DalvikMethodCfg> =
        rewired.or_else(|| build_dalvik_cfg_from_code_item(item))
    else {
        return MethodBody {
            text: "        // <decompile: malformed bytecode>\n".to_string(),
            fully_lifted: false,
        };
    };
    let blackobf_note: String =
        blackobfuscator_annotation(&built.insns, &built.switch_payloads, dex);
    let accesses: MethodAccesses = register_accesses(dex, &built.cfg, &built.insns);
    let Some(flow): Option<RegisterFlow> =
        RegisterFlow::analyze(&built.cfg, &accesses.accesses, item.registers_size)
    else {
        return MethodBody {
            text: format!("{blackobf_note}        // <decompile: register flow unavailable>\n"),
            fully_lifted: false,
        };
    };
    let dom: Dominators = compute_dominators(&built.cfg);
    let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &dom);
    let mut structurer: Structurer<'_> =
        Structurer::with_switch_map(&built.cfg, &dom, &loops, &[], built.switch_map.clone());
    let root: Region = structurer.structure();

    let base: MethodContext<'_> = MethodContext::new(
        dex,
        identity,
        item.registers_size,
        item.ins_size,
        inline_temporaries,
        desugar,
        inlined_helpers,
    )
    .with_parameter_names(parameter_names)
    .with_code(&item.insns);
    let states: Option<TypeStates> = method_type_states(dex, &built, identity, item);
    let locals: MethodLocals = method_locals(
        &base,
        identity,
        &built,
        &flow,
        states.as_ref(),
        accesses.threaded,
    );
    let ctx: MethodContext<'_> = base.with_naming(&locals.naming);
    let mut render: RenderState<'_> = RenderState {
        ctx: &ctx,
        cfg: &built.cfg,
        insns: &built.insns,
        accesses: &accesses.accesses,
        flow: &flow,
        locals: &locals,
        rendered_blocks: std::collections::BTreeSet::new(),
        fully_lifted: !structurer.had_irreducible,
        assigned: std::collections::BTreeSet::new(),
        temporaries: 0,
    };
    let mut out: String = String::new();
    render_region(&mut render, &root, &mut out, 2);
    let mut declarations: String = String::new();
    for &index in &render.assigned {
        let Some(local): Option<&NamedLocal> = locals.naming.locals.get(index) else {
            continue;
        };
        if !local.declared {
            continue;
        }
        match &local.ty {
            Some(ty) => {
                let _: std::fmt::Result =
                    writeln!(declarations, "        {} {};", ty.render(), local.name);
            }
            None => render.fully_lifted = false,
        }
    }
    MethodBody {
        text: format!("{blackobf_note}{declarations}{out}"),
        fully_lifted: render.fully_lifted,
    }
}

struct MethodAccesses {
    accesses: Vec<RegisterAccess>,
    threaded: std::collections::BTreeSet<u32>,
}

fn register_accesses(dex: &DexFile, cfg: &Cfg, insns: &[DalvikInsn]) -> MethodAccesses {
    let mut accesses: Vec<RegisterAccess> = vec![RegisterAccess::default(); insns.len()];
    let mut threaded: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for block in &cfg.blocks {
        let (start, end): (usize, usize) = block.insn_range;
        let mut allocated: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
        for index in start..end.min(insns.len()) {
            let insn: &DalvikInsn = &insns[index];
            let next: Option<&DalvikInsn> = if index + 1 < end {
                insns.get(index + 1)
            } else {
                None
            };
            let access: RegisterAccess = match insn.op {
                0x6E..=0x72 | 0x74..=0x78 => {
                    invoke_access(dex, insn, next, &allocated, &mut threaded)
                }
                _ => instruction_access(insn),
            };
            for &register in &access.defs {
                if insn.op == 0x22 {
                    allocated.insert(register);
                } else {
                    allocated.remove(&register);
                }
            }
            if let Some(slot) = accesses.get_mut(index) {
                *slot = access;
            }
        }
    }
    MethodAccesses { accesses, threaded }
}

fn instruction_access(insn: &DalvikInsn) -> RegisterAccess {
    let register = |position: usize| insn.regs.get(position).copied();
    let (uses, defs): (Vec<Option<u16>>, Vec<Option<u16>>) = match insn.op {
        0x01..=0x09 => (vec![register(1)], vec![register(0)]),
        0x0A..=0x0D | 0x12..=0x1C | 0x22 | 0x60..=0x66 => (Vec::new(), vec![register(0)]),
        0x0F..=0x11 | 0x1D | 0x1E | 0x26 | 0x27 | 0x2B | 0x2C | 0x38..=0x3D | 0x67..=0x6D => {
            (vec![register(0)], Vec::new())
        }
        0x1F => (vec![register(0)], vec![register(0)]),
        0x20 | 0x21 | 0x23 | 0x52..=0x58 | 0x7B..=0x8F | 0xD0..=0xE2 => {
            (vec![register(1)], vec![register(0)])
        }
        0x24 | 0x25 => (insn.regs.iter().copied().map(Some).collect(), Vec::new()),
        0x2D..=0x31 | 0x44..=0x4A | 0x90..=0xAF => {
            (vec![register(1), register(2)], vec![register(0)])
        }
        0x32..=0x37 | 0x59..=0x5F => (vec![register(0), register(1)], Vec::new()),
        0x4B..=0x51 => (vec![register(0), register(1), register(2)], Vec::new()),
        0xB0..=0xCF => (vec![register(0), register(1)], vec![register(0)]),
        _ => (Vec::new(), Vec::new()),
    };
    RegisterAccess {
        uses: uses.into_iter().flatten().collect(),
        defs: defs.into_iter().flatten().collect(),
    }
}

fn invoke_access(
    dex: &DexFile,
    insn: &DalvikInsn,
    next: Option<&DalvikInsn>,
    allocated: &std::collections::BTreeSet<u16>,
    threaded: &mut std::collections::BTreeSet<u32>,
) -> RegisterAccess {
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let method: Option<&crate::dex::MethodId> = insn
        .index
        .and_then(|index: u32| dex.method_ids.get(index as usize));
    let mut registers = insn.regs.iter().copied();
    let mut uses: Vec<u16> = Vec::with_capacity(insn.regs.len());
    let Some(method): Option<&crate::dex::MethodId> = method else {
        uses.extend(registers);
        return RegisterAccess {
            uses,
            defs: Vec::new(),
        };
    };
    if !is_static {
        uses.extend(registers.next());
    }
    for parameter in &method.proto.parameters {
        let Some(register): Option<u16> = registers.next() else {
            break;
        };
        uses.push(register);
        if matches!(parameter.as_bytes().first(), Some(b'J' | b'D')) {
            let _: Option<u16> = registers.next();
        }
    }
    let mut defs: Vec<u16> = Vec::new();
    if let Some(&receiver) = insn.regs.first().filter(|_| !is_static) {
        let initializes: bool = matches!(insn.op, 0x70 | 0x76)
            && method.name == "<init>"
            && allocated.contains(&receiver);
        let threads: bool = crate::dalvik_lift::returns_receiver(method)
            && next.is_some_and(|following: &DalvikInsn| {
                matches!(following.op, 0x6E..=0x72 | 0x74..=0x78)
                    && following.regs.first() == Some(&receiver)
            });
        if threads {
            threaded.insert(insn.pc);
        }
        if initializes || threads {
            defs.push(receiver);
        }
    }
    RegisterAccess { uses, defs }
}

fn method_type_states(
    dex: &DexFile,
    built: &DalvikMethodCfg,
    identity: MethodIdentity<'_>,
    item: &CodeItem,
) -> Option<TypeStates> {
    let parsed: MethodDescriptor = descriptor::parse_method(identity.descriptor)?;
    let switch_targets: BTreeMap<u32, Vec<u32>> = built
        .switch_payloads
        .iter()
        .map(|(pc, payload): &(u32, crate::dalvik::SwitchPayload)| (*pc, payload.targets.clone()))
        .collect();
    let mut handler_edges: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut catch_types: BTreeMap<u32, std::collections::BTreeSet<Option<String>>> =
        BTreeMap::new();
    for region in &built.cfg.exception_regions {
        for insn in &built.insns {
            if insn.pc >= region.try_start_pc && insn.pc < region.try_end_pc {
                let handlers: &mut Vec<u32> = handler_edges.entry(insn.pc).or_default();
                if !handlers.contains(&region.handler_pc) {
                    handlers.push(region.handler_pc);
                }
            }
        }
        catch_types
            .entry(region.handler_pc)
            .or_default()
            .insert(region.catch_type.clone());
    }
    let move_exception_type: BTreeMap<u32, String> = catch_types
        .into_iter()
        .map(
            |(pc, types): (u32, std::collections::BTreeSet<Option<String>>)| {
                let single: Option<String> = if types.len() == 1 {
                    types.into_iter().next().flatten()
                } else {
                    None
                };
                let internal: String = single.map_or_else(
                    || "java/lang/Throwable".to_owned(),
                    |ty: String| descriptor::descriptor_to_binary_name(&ty).to_owned(),
                );
                (pc, internal)
            },
        )
        .collect();
    let edges: crate::dalvik_typestate::CfgEdges<'_> = crate::dalvik_typestate::CfgEdges {
        switch_targets: &switch_targets,
        handler_edges: &handler_edges,
        move_exception_type: &move_exception_type,
    };
    let no_eager_allocations: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let shape: crate::dalvik_typestate::MethodShape<'_> = crate::dalvik_typestate::MethodShape {
        registers_size: item.registers_size,
        ins_size: item.ins_size,
        is_static: identity.is_static,
        is_init_ctor: identity.is_constructor && !identity.is_static,
        class_internal: identity.declaring_class,
        materialize_new_pcs: &no_eager_allocations,
    };
    crate::dalvik_typestate::analyze(dex, &built.insns, &parsed, &shape, &edges)
}

struct MethodLocals {
    naming: RegisterNaming,
    web_local: BTreeMap<usize, usize>,
}

#[derive(Default)]
struct WebEvidence {
    types: Vec<RegType>,
    declared: Option<LocalType>,
    boolean: bool,
    integral_def: bool,
    integral_use: bool,
    narrow: std::collections::BTreeSet<u8>,
}

impl WebEvidence {
    fn record_descriptor_def(&mut self, descriptor_text: &str) {
        match descriptor_text.as_bytes().first() {
            Some(b'Z') => self.boolean = true,
            Some(&kind @ (b'B' | b'C' | b'S')) => {
                self.narrow.insert(kind);
            }
            _ => self.integral_def = true,
        }
    }

    fn record_def(&mut self, dex: &DexFile, insns: &[DalvikInsn], index: usize) {
        let Some(insn): Option<&DalvikInsn> = insns.get(index) else {
            return;
        };
        let literal: i64 = insn.literal.unwrap_or(0);
        match insn.op {
            0x12..=0x14 if matches!(literal, 0 | 1) => {}
            0x15 if literal == 0 => {}
            0x01..=0x03 | 0x95..=0x97 | 0xB5..=0xB7 => {}
            0xD5..=0xD7 | 0xDD..=0xDF if matches!(literal, 0 | 1) => {}
            0x0A => {
                let returned: Option<&str> = index
                    .checked_sub(1)
                    .and_then(|previous: usize| insns.get(previous))
                    .filter(
                        |previous: &&DalvikInsn| matches!(previous.op, 0x6E..=0x72 | 0x74..=0x78),
                    )
                    .and_then(|previous: &DalvikInsn| previous.index)
                    .and_then(|method: u32| dex.method_ids.get(method as usize))
                    .map(|method: &crate::dex::MethodId| method.proto.return_type.as_str());
                match returned {
                    Some(descriptor_text) => self.record_descriptor_def(descriptor_text),
                    None => self.integral_def = true,
                }
            }
            0x20 | 0x47 | 0x55 | 0x63 => self.boolean = true,
            0x48 | 0x56 | 0x64 | 0x8D => {
                self.narrow.insert(b'B');
            }
            0x49 | 0x57 | 0x65 | 0x8E => {
                self.narrow.insert(b'C');
            }
            0x4A | 0x58 | 0x66 | 0x8F => {
                self.narrow.insert(b'S');
            }
            _ => self.integral_def = true,
        }
    }

    fn record_use(
        &mut self,
        dex: &DexFile,
        insn: &DalvikInsn,
        register: u16,
        returns: Option<&crate::descriptor::JavaType>,
    ) {
        let invoked: Vec<Option<u8>> = invoke_operand_kinds(dex, insn);
        for (position, &operand) in insn.regs.iter().enumerate() {
            if operand != register {
                continue;
            }
            match insn.op {
                0x01..=0x03
                | 0x32
                | 0x33
                | 0x38
                | 0x39
                | 0x95..=0x97
                | 0xB5..=0xB7
                | 0xD5..=0xD7
                | 0xDD..=0xDF => {}
                0x0F => match returns {
                    Some(crate::descriptor::JavaType::Boolean) => self.boolean = true,
                    Some(
                        crate::descriptor::JavaType::Byte
                        | crate::descriptor::JavaType::Char
                        | crate::descriptor::JavaType::Short,
                    ) => {}
                    _ => self.integral_use = true,
                },
                0x4E | 0x5C | 0x6A if position == 0 => self.boolean = true,
                0x4F..=0x51 | 0x5D..=0x5F | 0x6B..=0x6D if position == 0 => {}
                0x6E..=0x72 | 0x74..=0x78 => match invoked.get(position).copied().flatten() {
                    Some(b'Z') => self.boolean = true,
                    Some(b'B' | b'C' | b'S') => {}
                    _ => self.integral_use = true,
                },
                _ => self.integral_use = true,
            }
        }
    }

    fn local_type(
        &self,
        lattice: &crate::dalvik_typestate::TypeLattice<'_>,
        desugar: crate::dalvik_desugar::DesugarView<'_>,
    ) -> Option<LocalType> {
        if let Some(declared) = &self.declared {
            return Some(declared.clone());
        }
        let (first, rest): (&RegType, &[RegType]) = self.types.split_first()?;
        let joined: RegType = rest
            .iter()
            .fold(first.clone(), |acc: RegType, ty: &RegType| {
                lattice.join(&acc, ty)
            });
        match joined {
            RegType::Int => Some(self.refined_int()),
            RegType::Long => Some(LocalType::Long),
            RegType::Float => Some(LocalType::Float),
            RegType::Double => Some(LocalType::Double),
            RegType::Ref(name) => {
                let descriptor_text: String = if name.starts_with('[') {
                    name
                } else {
                    format!("L{name};")
                };
                let projected: String = desugar.core_library.project_type(&descriptor_text);
                descriptor::parse_field(&projected)
                    .map(|ty: descriptor::JavaType| LocalType::Reference(ty.render()))
            }
            RegType::NullRef | RegType::ZeroOrNull => {
                Some(LocalType::Reference("Object".to_owned()))
            }
            RegType::Top | RegType::UninitializedThis | RegType::Uninitialized(_) => None,
        }
    }

    fn refined_int(&self) -> LocalType {
        if self.boolean && !self.integral_def && !self.integral_use && self.narrow.is_empty() {
            return LocalType::Boolean;
        }
        if self.integral_def || self.boolean || self.narrow.len() != 1 {
            return LocalType::Int;
        }
        match self.narrow.first() {
            Some(b'B') => LocalType::Byte,
            Some(b'C') => LocalType::Char,
            Some(b'S') => LocalType::Short,
            _ => LocalType::Int,
        }
    }
}

fn invoke_operand_kinds(dex: &DexFile, insn: &DalvikInsn) -> Vec<Option<u8>> {
    if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
        return Vec::new();
    }
    let Some(method): Option<&crate::dex::MethodId> = insn
        .index
        .and_then(|index: u32| dex.method_ids.get(index as usize))
    else {
        return Vec::new();
    };
    let mut kinds: Vec<Option<u8>> = Vec::with_capacity(insn.regs.len());
    if !matches!(insn.op, 0x71 | 0x77) {
        kinds.push(Some(b'L'));
    }
    for parameter in &method.proto.parameters {
        let kind: Option<u8> = parameter.as_bytes().first().copied();
        kinds.push(kind);
        if matches!(kind, Some(b'J' | b'D')) {
            kinds.push(None);
        }
    }
    kinds
}

fn java_local_type(ty: &descriptor::JavaType) -> Option<LocalType> {
    Some(match ty {
        descriptor::JavaType::Boolean => LocalType::Boolean,
        descriptor::JavaType::Byte => LocalType::Byte,
        descriptor::JavaType::Char => LocalType::Char,
        descriptor::JavaType::Short => LocalType::Short,
        descriptor::JavaType::Int => LocalType::Int,
        descriptor::JavaType::Long => LocalType::Long,
        descriptor::JavaType::Float => LocalType::Float,
        descriptor::JavaType::Double => LocalType::Double,
        descriptor::JavaType::Object(_) | descriptor::JavaType::Array(_) => {
            LocalType::Reference(ty.render())
        }
        descriptor::JavaType::Void => return None,
    })
}

fn parameter_types(
    ctx: &MethodContext<'_>,
    identity: MethodIdentity<'_>,
) -> BTreeMap<u16, LocalType> {
    let Some(parsed): Option<MethodDescriptor> =
        descriptor::parse_method(&ctx.desugar.core_library.project_type(identity.descriptor))
    else {
        return BTreeMap::new();
    };
    ctx.param_regs
        .keys()
        .copied()
        .zip(&parsed.params)
        .filter_map(|(register, ty): (u16, &descriptor::JavaType)| {
            java_local_type(ty).map(|local: LocalType| (register, local))
        })
        .collect()
}

fn method_locals(
    ctx: &MethodContext<'_>,
    identity: MethodIdentity<'_>,
    built: &DalvikMethodCfg,
    flow: &RegisterFlow,
    states: Option<&TypeStates>,
    threaded: std::collections::BTreeSet<u32>,
) -> MethodLocals {
    let dex: &DexFile = ctx.dex;
    let parameters: BTreeMap<u16, LocalType> = parameter_types(ctx, identity);
    let mut web_register: BTreeMap<usize, u16> = BTreeMap::new();
    let mut evidence: BTreeMap<usize, WebEvidence> = BTreeMap::new();
    for (node_index, node) in flow.nodes().iter().enumerate() {
        let Some(web): Option<usize> = flow.web_of(node_index) else {
            continue;
        };
        let register: u16 = match node {
            ValueNode::Entry { register, .. } | ValueNode::Def { register, .. } => *register,
        };
        web_register.entry(web).or_insert(register);
        let facts: &mut WebEvidence = evidence.entry(web).or_default();
        match node {
            ValueNode::Entry { block, register } if BlockId(*block) == built.cfg.entry => {
                if let Some(declared) = parameters.get(register) {
                    facts.declared = Some(declared.clone());
                }
            }
            ValueNode::Entry { .. } => {}
            ValueNode::Def { insn, .. } => facts.record_def(dex, &built.insns, *insn),
        }
    }
    for (insn, register, web) in flow.uses() {
        let facts: &mut WebEvidence = evidence.entry(web).or_default();
        if let Some(instruction) = built.insns.get(insn) {
            facts.record_use(dex, instruction, register, ctx.return_type.as_ref());
        }
        if let Some(states) = states
            && states.reached.get(insn).copied().unwrap_or(false)
            && let Some(ty) = states
                .entry_state
                .get(insn)
                .and_then(|state: &crate::dalvik_typestate::RegState| state.get(&register))
        {
            facts.types.push(ty.clone());
        }
    }

    let lattice: crate::dalvik_typestate::TypeLattice<'_> =
        crate::dalvik_typestate::TypeLattice::new(dex);
    let this_type: LocalType = LocalType::Reference(descriptor::binary_to_source(
        &ctx.desugar
            .core_library
            .project_type(identity.declaring_class),
    ));
    let mut naming: RegisterNaming = RegisterNaming {
        threaded_receivers: threaded,
        ..RegisterNaming::default()
    };
    let mut web_local: BTreeMap<usize, usize> = BTreeMap::new();
    let mut by_register: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for (&web, &register) in &web_register {
        by_register.entry(register).or_default().push(web);
    }
    for (register, webs) in by_register {
        let parameter: Option<(&String, &LocalType)> =
            ctx.param_regs.get(&register).zip(parameters.get(&register));
        let is_this: bool = ctx.this_reg == Some(register);
        let entry_web: Option<usize> = flow.entry_web(built.cfg.entry, register);
        let mut typed_names: Vec<(LocalType, String)> = Vec::new();
        let mut suffix: usize = 0;
        for web in webs {
            let ty: Option<LocalType> = evidence
                .get(&web)
                .and_then(|facts: &WebEvidence| facts.local_type(&lattice, ctx.desugar));
            let holds_entry: bool = entry_web == Some(web);
            let local: NamedLocal = if is_this && holds_entry {
                NamedLocal {
                    name: "this".to_owned(),
                    ty: Some(this_type.clone()),
                    declared: false,
                }
            } else if let Some((name, declared)) = parameter
                && (holds_entry || ty.as_ref() == Some(declared))
            {
                NamedLocal {
                    name: name.clone(),
                    ty: Some(declared.clone()),
                    declared: false,
                }
            } else {
                let shared: Option<&String> = ty.as_ref().and_then(|wanted: &LocalType| {
                    typed_names
                        .iter()
                        .find(|(seen, _): &&(LocalType, String)| seen == wanted)
                        .map(|(_, name): &(LocalType, String)| name)
                });
                let name: String = shared.cloned().unwrap_or_else(|| {
                    let fresh: String = if suffix == 0 {
                        format!("var{register}")
                    } else {
                        format!("var{register}_{suffix}")
                    };
                    suffix += 1;
                    if let Some(ty) = &ty {
                        typed_names.push((ty.clone(), fresh.clone()));
                    }
                    fresh
                });
                NamedLocal {
                    name,
                    ty,
                    declared: true,
                }
            };
            let index: usize = intern_local(&mut naming, local);
            web_local.insert(web, index);
        }
    }
    for (register, name) in &ctx.param_regs {
        if !naming.by_name.contains_key(name) {
            let _: usize = intern_local(
                &mut naming,
                NamedLocal {
                    name: name.clone(),
                    ty: parameters.get(register).cloned(),
                    declared: false,
                },
            );
        }
    }
    for (node_index, node) in flow.nodes().iter().enumerate() {
        let ValueNode::Def { insn, register } = node else {
            continue;
        };
        let (Some(instruction), Some(&index)): (Option<&DalvikInsn>, Option<&usize>) = (
            built.insns.get(*insn),
            flow.web_of(node_index)
                .and_then(|web: usize| web_local.get(&web)),
        ) else {
            continue;
        };
        naming.def_locals.insert((instruction.pc, *register), index);
    }
    MethodLocals { naming, web_local }
}

fn intern_local(naming: &mut RegisterNaming, local: NamedLocal) -> usize {
    if let Some(&index) = naming.by_name.get(&local.name) {
        return index;
    }
    let index: usize = naming.locals.len();
    naming.by_name.insert(local.name.clone(), index);
    naming.locals.push(local);
    index
}

const fn writes_first_register(op: u8) -> bool {
    matches!(
        op,
        0x01..=0x0D
            | 0x12..=0x1C
            | 0x1F..=0x23
            | 0x2D..=0x31
            | 0x44..=0x4A
            | 0x52..=0x58
            | 0x60..=0x66
            | 0x7B..=0xE2
    )
}

fn blackobfuscator_annotation(
    insns: &[crate::dalvik::DalvikInsn],
    switch_payloads: &[(u32, crate::dalvik::SwitchPayload)],
    dex: &DexFile,
) -> String {
    let report: crate::dalvik_blackobf::BlackObfReport =
        crate::dalvik_blackobf::detect_blackobfuscator(insns, switch_payloads);
    if !report.flattened {
        return String::new();
    }
    let strings: &[String] = &dex.strings;
    let deflatten: Option<crate::dalvik_blackobf::BlackObfDeflatten> =
        crate::dalvik_blackobf::deflatten_blackobfuscator(insns, switch_payloads, strings);
    match deflatten {
        Some(d) if d.resolved_cases > 0 => format!(
            "        // BlackObfuscator control-flow flattening: {} of {} dispatcher case(s) mapped back to their block, linear block order [{}]; the body below is still rendered from the flattened graph\n",
            d.resolved_cases,
            d.resolved_cases + d.unresolved_cases,
            d.linear_block_pcs
                .iter()
                .map(u32::to_string)
                .collect::<Vec<String>>()
                .join(", ")
        ),
        _ => format!(
            "        // BlackObfuscator control-flow flattening detected ({} hashCode-keyed dispatcher case(s)); block-name strings unresolved\n",
            report.dispatch_cases
        ),
    }
}

struct RenderState<'a> {
    ctx: &'a MethodContext<'a>,
    cfg: &'a Cfg,
    insns: &'a [DalvikInsn],
    accesses: &'a [RegisterAccess],
    flow: &'a RegisterFlow,
    locals: &'a MethodLocals,
    rendered_blocks: std::collections::BTreeSet<BlockId>,
    fully_lifted: bool,
    assigned: std::collections::BTreeSet<usize>,
    temporaries: usize,
}

struct BlockWalk {
    file: RegisterFile,
    pending: Option<PendingResult>,
    origins: BTreeMap<u16, u32>,
    points: Vec<RegisterSet>,
    handlers: RegisterSet,
    start: usize,
    end: usize,
    replay: bool,
}

struct FlushRequest<'r> {
    assign: Vec<u16>,
    external: Option<String>,
    effect: bool,
    live: &'r RegisterSet,
    exclude: &'r [u16],
}

fn indent_string(level: usize) -> String {
    "    ".repeat(level)
}

fn render_region(state: &mut RenderState<'_>, region: &Region, out: &mut String, level: usize) {
    if out.len() > MAX_RENDER_BYTES {
        return;
    }
    match region {
        Region::Block(bid) => render_block(state, *bid, out, level),
        Region::Sequence(items) => {
            for r in items {
                render_region(state, r, out, level);
            }
        }
        Region::IfThen {
            head, then_body, ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::IfThenElse {
            head,
            then_body,
            else_body,
            ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}} else {{");
            render_region(state, else_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::While { header, body, exit } => {
            let mut head: String = String::new();
            let cond: String = render_head_condition(state, *header, &mut head, level + 1);
            let negated: bool =
                matches!(exit, Some(e) if header_cond_true_target(state.cfg, *header) == Some(*e));
            let displayed: String = if negated { invert(&cond) } else { cond };
            let pad: String = indent_string(level);
            if head.is_empty() {
                let _ = writeln!(out, "{pad}while ({displayed}) {{");
            } else {
                let _ = writeln!(out, "{pad}while (true) {{");
                out.push_str(&head);
                let _ = writeln!(out, "{pad}    if ({}) {{", invert(&displayed));
                let _ = writeln!(out, "{pad}        break;");
                let _ = writeln!(out, "{pad}    }}");
            }
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::DoWhile { header, body, .. } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}do {{");
            render_block(state, *header, out, level + 1);
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}} while (true);");
        }
        Region::Switch {
            head,
            cases,
            default,
            fallthrough,
            ..
        } => {
            let subject: String = render_switch_subject(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}switch ({subject}) {{");
            for (i, (key, body)) in cases.iter().enumerate() {
                let _ = writeln!(out, "{pad}    case {}:", format_switch_key(key, i));
                render_region(state, body, out, level + 2);
                if !fallthrough.contains(&i) {
                    let _ = writeln!(out, "{pad}        break;");
                }
            }
            if let Some(def) = default {
                let _ = writeln!(out, "{pad}    default:");
                render_region(state, def, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Try { try_body, handlers } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(state, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex) {{");
                render_region(state, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_body,
            ..
        } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(state, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex) {{");
                render_region(state, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}} finally {{");
            render_region(state, finally_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryWithResources {
            resource_slot,
            try_body,
        } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try (v{resource_slot}) {{");
            render_region(state, try_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Synchronized {
            lock_block,
            lock_slot,
            body,
        } => {
            render_block(state, *lock_block, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}synchronized (v{lock_slot}) {{");
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::LabeledLoop { label, body } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}L{label}:");
            render_region(state, body, out, level);
        }
        Region::Break { label } => {
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}break L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}break;");
                }
            }
        }
        Region::Continue { label, latch } => {
            if let Some(latch_bid) = latch {
                render_block(state, *latch_bid, out, level);
            }
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}continue L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}continue;");
                }
            }
        }
        Region::Irreducible { blocks } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}// irreducible region");
            for bid in blocks {
                render_block(state, *bid, out, level);
            }
            state.fully_lifted = false;
        }
    }
}

fn block_insn_range(state: &RenderState<'_>, bid: BlockId) -> (usize, usize) {
    let block: &BasicBlock = &state.cfg.blocks[bid.0 as usize];
    block.insn_range
}

fn entry_value(state: &RenderState<'_>, bid: BlockId, register: u16) -> Expr {
    let local: Option<&NamedLocal> = state
        .flow
        .entry_web(bid, register)
        .and_then(|web: usize| state.locals.web_local.get(&web))
        .and_then(|&index: &usize| state.locals.naming.locals.get(index));
    match local {
        Some(local) if local.name == "this" => Expr::This,
        Some(local) => Expr::Local(local.name.clone()),
        None => state.ctx.register_name(register),
    }
}

fn open_block(state: &RenderState<'_>, bid: BlockId, replay: bool) -> Option<BlockWalk> {
    let block: &BasicBlock = state.cfg.blocks.get(bid.0 as usize)?;
    let points: Vec<RegisterSet> = state.flow.live_points(block, state.accesses)?;
    let handlers: RegisterSet = state.flow.handler_live(bid)?.clone();
    let mut file: RegisterFile = RegisterFile::new();
    for register in 0..state.ctx.registers_size {
        file.seed(register, entry_value(state, bid, register));
    }
    Some(BlockWalk {
        file,
        pending: None,
        origins: BTreeMap::new(),
        points,
        handlers,
        start: block.insn_range.0,
        end: block.insn_range.1,
        replay,
    })
}

fn live_at(walk: &BlockWalk, point: usize) -> RegisterSet {
    walk.points
        .get(point)
        .or_else(|| walk.points.last())
        .cloned()
        .unwrap_or_else(|| RegisterSet::empty(0))
}

fn target_name(state: &mut RenderState<'_>, walk: &BlockWalk, register: u16) -> String {
    match walk.origins.get(&register) {
        Some(&pc) => {
            if state.locals.naming.def_local(pc, register).is_none() {
                state.fully_lifted = false;
            }
            state.ctx.def_lvalue(pc, register)
        }
        None => match walk.file.slot(register) {
            Some(Expr::Local(name)) => name.clone(),
            _ => {
                state.fully_lifted = false;
                state.ctx.register_lvalue(register)
            }
        },
    }
}

fn record_assignment(state: &mut RenderState<'_>, walk: &BlockWalk, register: u16) {
    let index: Option<usize> = walk
        .origins
        .get(&register)
        .and_then(|&pc: &u32| state.locals.naming.def_locals.get(&(pc, register)).copied());
    match index {
        Some(index) => {
            state.assigned.insert(index);
        }
        None => state.fully_lifted = false,
    }
}

fn is_effect_ordered(value: &Expr) -> bool {
    expr_has_effect(value) || expr_reads_state(value)
}

fn flush(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    request: &FlushRequest<'_>,
    out: &mut String,
    level: usize,
) {
    let mut members: Vec<u16> = Vec::new();
    let mut names: BTreeMap<u16, String> = BTreeMap::new();
    let mut assigned_names: Vec<String> = request.external.iter().cloned().collect();
    let mut effect: bool = request.effect;
    for &register in &request.assign {
        if members.contains(&register) {
            continue;
        }
        let name: String = target_name(state, walk, register);
        effect |= walk.file.slot(register).is_some_and(expr_has_effect);
        assigned_names.push(name.clone());
        names.insert(register, name);
        members.push(register);
    }
    loop {
        let mut grew: bool = false;
        for register in request.live.iter() {
            if members.contains(&register) || request.exclude.contains(&register) {
                continue;
            }
            let Some(value): Option<Expr> = walk.file.slot(register).cloned() else {
                continue;
            };
            if matches!(value, Expr::This) {
                continue;
            }
            let own: String = target_name(state, walk, register);
            if matches!(&value, Expr::Local(name) if *name == own) {
                continue;
            }
            let hazard: bool = assigned_names
                .iter()
                .any(|name: &String| expr_mentions_local(&value, name));
            let ordered: bool = effect && is_effect_ordered(&value);
            if !hazard && !ordered {
                continue;
            }
            if walk.file.is_pending(register) {
                effect |= expr_has_effect(&value);
                assigned_names.push(own.clone());
                names.insert(register, own);
                members.push(register);
                grew = true;
            } else {
                walk.file.set_variable(register, own);
            }
        }
        if !grew {
            break;
        }
    }
    members.sort_by_key(|register: &u16| (walk.origins.get(register).copied(), *register));
    let pad: String = indent_string(level);
    while !members.is_empty() {
        let precedes = |walk: &BlockWalk, before: u16, after: u16| -> bool {
            let (Some(first), Some(second)): (Option<&Expr>, Option<&Expr>) =
                (walk.file.slot(before), walk.file.slot(after))
            else {
                return false;
            };
            let reads_old: bool = names
                .get(&after)
                .is_some_and(|name: &String| expr_mentions_local(first, name));
            let effect_order: bool = (expr_has_effect(first) || expr_has_effect(second))
                && is_effect_ordered(first)
                && is_effect_ordered(second)
                && walk.origins.get(&before) < walk.origins.get(&after);
            reads_old || effect_order
        };
        let ready: Option<usize> = members.iter().position(|&candidate: &u16| {
            !members
                .iter()
                .any(|&other: &u16| other != candidate && precedes(walk, other, candidate))
        });
        let Some(position): Option<usize> = ready else {
            let blocked: Option<String> = members.iter().find_map(|&candidate: &u16| {
                let name: &String = names.get(&candidate)?;
                members
                    .iter()
                    .any(|&other: &u16| {
                        other != candidate
                            && walk
                                .file
                                .slot(other)
                                .is_some_and(|value: &Expr| expr_mentions_local(value, name))
                    })
                    .then(|| name.clone())
            });
            let Some(name): Option<String> = blocked else {
                state.fully_lifted = false;
                break;
            };
            let temporary: String = format!("tmp{}", state.temporaries);
            state.temporaries += 1;
            if walk.replay {
                state.fully_lifted = false;
            }
            let ty: String = match state
                .locals
                .naming
                .named(&name)
                .and_then(|local: &NamedLocal| local.ty.as_ref())
            {
                Some(ty) => ty.render(),
                None => {
                    state.fully_lifted = false;
                    "Object".to_owned()
                }
            };
            let _: std::fmt::Result = writeln!(out, "{pad}{ty} {temporary} = {name};");
            for &register in &members {
                if let Some(value) = walk.file.slot(register).cloned() {
                    walk.file
                        .replace(register, rename_local(&value, &name, &temporary));
                }
            }
            continue;
        };
        let register: u16 = members.remove(position);
        let Some(value): Option<Expr> = walk.file.slot(register).cloned() else {
            continue;
        };
        let Some(name): Option<String> = names.get(&register).cloned() else {
            continue;
        };
        if matches!(value, Expr::New(_)) {
            state.fully_lifted = false;
            continue;
        }
        let target: Option<LocalType> = walk
            .origins
            .get(&register)
            .and_then(|&pc: &u32| state.locals.naming.def_local(pc, register))
            .and_then(|local: &NamedLocal| local.ty.clone());
        let rendered: String =
            assignment_value(state.ctx, &walk.file, register, &value, target.as_ref());
        let _: std::fmt::Result = writeln!(out, "{pad}{name} = {rendered};");
        record_assignment(state, walk, register);
        walk.file.set_variable(register, name);
    }
}

fn effect_statement(value: &Expr) -> Option<String> {
    match value {
        Expr::Invoke { .. } => Some(value.render()),
        Expr::Opaque(text) if text.starts_with("new ") => Some(text.clone()),
        Expr::Cast { value, .. } => effect_statement(value),
        _ => None,
    }
}

fn walk_insn(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    index: usize,
    out: &mut String,
    level: usize,
) {
    let insns: &[DalvikInsn] = state.insns;
    let insn: &DalvikInsn = &insns[index];
    let point: usize = index.saturating_sub(walk.start);
    let after: RegisterSet = live_at(walk, point + 1);
    let defs: Vec<u16> = state
        .accesses
        .get(index)
        .map(|access: &RegisterAccess| access.defs.clone())
        .unwrap_or_default();
    let moved: Option<u16> = if matches!(insn.op, 0x01..=0x09) && !state.ctx.inline_temporaries {
        insn.regs.first().copied()
    } else {
        None
    };
    let moved_value: Option<&Expr> = moved
        .and_then(|_| insn.regs.get(1))
        .and_then(|&source: &u16| walk.file.slot(source));
    let copies_this: bool = matches!(moved_value, Some(Expr::This));
    let dead_move: bool = copies_this
        || moved.is_some_and(|dest: u16| {
            !after.contains(dest) && !moved_value.is_some_and(expr_has_effect)
        });
    if let Some(dest) = moved.filter(|_| !dead_move) {
        let request: FlushRequest<'_> = FlushRequest {
            assign: Vec::new(),
            external: Some(state.ctx.def_lvalue(insn.pc, dest)),
            effect: false,
            live: &after,
            exclude: &[dest],
        };
        flush(state, walk, &request, out, level);
    }
    if may_throw(insn.op) {
        let assign: Vec<u16> = walk
            .file
            .pending_registers()
            .filter(|&register: &u16| walk.handlers.contains(register))
            .collect();
        if !assign.is_empty() {
            let request: FlushRequest<'_> = FlushRequest {
                assign,
                external: None,
                effect: false,
                live: &live_at(walk, point),
                exclude: &[],
            };
            flush(state, walk, &request, out, level);
        }
    }
    let null_check: bool = walk
        .pending
        .as_ref()
        .is_some_and(PendingResult::is_null_check)
        && !matches!(insn.op, 0x0A..=0x0C);
    let predicted: bool = predicts_statement(state, walk, insn);
    if predicted {
        let request: FlushRequest<'_> = FlushRequest {
            assign: Vec::new(),
            external: None,
            effect: true,
            live: &after,
            exclude: &defs,
        };
        flush(state, walk, &request, out, level);
    }
    let outcome: LiftOutcome = lift_insn_tracked(state, &mut walk.file, insn, &mut walk.pending);
    for &register in &defs {
        walk.origins.insert(register, insn.pc);
    }
    let mut statements: Vec<String> = match outcome {
        LiftOutcome::Statement(statement) => vec![statement],
        LiftOutcome::Statements(statements) => statements,
        LiftOutcome::None | LiftOutcome::Unlifted => Vec::new(),
    };
    if dead_move {
        statements.pop();
        if let Some(dest) = moved.filter(|&dest: &u16| copies_this && after.contains(dest)) {
            walk.file.defer(dest);
        }
    } else if let Some(dest) = moved {
        record_assignment(state, walk, dest);
    }
    if !predicted && !null_check && statements.len() > usize::from(moved.is_some() && !dead_move) {
        let request: FlushRequest<'_> = FlushRequest {
            assign: Vec::new(),
            external: None,
            effect: true,
            live: &after,
            exclude: &defs,
        };
        flush(state, walk, &request, out, level);
    }
    let pad: String = indent_string(level);
    for statement in statements {
        let _: std::fmt::Result = writeln!(out, "{pad}{statement};");
    }
    anchor_effects(state, walk, index, &defs, &after, out, level);
    order_pending_effects(state, walk, index, &defs, &after, out, level);
    if insn.op == 0x26 {
        anchor_filled_array(state, walk, index, &after, out, level);
    }
}

fn order_pending_effects(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    index: usize,
    defs: &[u16],
    after: &RegisterSet,
    out: &mut String,
    level: usize,
) {
    for &register in defs {
        let Some(value): Option<Expr> = walk.file.slot(register).cloned() else {
            continue;
        };
        let Some(&origin): Option<&u32> = walk.origins.get(&register) else {
            continue;
        };
        if !walk.file.is_pending(register) || !orders_effects(&value) {
            continue;
        }
        let assign: Vec<u16> = walk
            .file
            .pending_registers()
            .filter(|&other: &u16| {
                other != register
                    && after.contains(other)
                    && walk
                        .origins
                        .get(&other)
                        .is_some_and(|&defined: &u32| defined < origin)
                    && walk.file.slot(other).is_some_and(|earlier: &Expr| {
                        orders_effects(earlier)
                            && (expr_has_effect(earlier) || expr_has_effect(&value))
                    })
                    && !consumed_in_order(state, walk, index, other, register)
            })
            .collect();
        if assign.is_empty() {
            continue;
        }
        if walk.pending.as_ref().is_some_and(|result: &PendingResult| {
            assign
                .iter()
                .any(|&earlier: &u16| result.materializes(earlier))
        }) {
            walk.pending = None;
        }
        let request: FlushRequest<'_> = FlushRequest {
            assign,
            external: None,
            effect: false,
            live: after,
            exclude: &[],
        };
        flush(state, walk, &request, out, level);
    }
}

fn orders_effects(value: &Expr) -> bool {
    let functional: bool =
        matches!(value, Expr::Opaque(text) if text != "?" && !text.starts_with("new "));
    !functional && is_effect_ordered(value)
}

fn consumed_in_order(
    state: &RenderState<'_>,
    walk: &BlockWalk,
    index: usize,
    earlier: u16,
    later: u16,
) -> bool {
    for next in index + 1..walk.end {
        let (Some(insn), Some(access)): (Option<&DalvikInsn>, Option<&RegisterAccess>) =
            (state.insns.get(next), state.accesses.get(next))
        else {
            return false;
        };
        if access.uses.contains(&earlier) || access.uses.contains(&later) {
            let Some(order): Option<Vec<u16>> = evaluation_order(insn) else {
                return false;
            };
            let first: Option<usize> = order.iter().position(|&r: &u16| r == earlier);
            let second: Option<usize> = order.iter().position(|&r: &u16| r == later);
            return matches!((first, second), (Some(first), Some(second)) if first < second);
        }
        if access.defs.contains(&earlier) || access.defs.contains(&later) {
            return false;
        }
    }
    false
}

fn evaluation_order(insn: &DalvikInsn) -> Option<Vec<u16>> {
    let register = |position: usize| insn.regs.get(position).copied();
    let order: Vec<Option<u16>> = match insn.op {
        0x24 | 0x25 | 0x6E..=0x72 | 0x74..=0x78 => return Some(insn.regs.clone()),
        0x2D..=0x31 | 0x44..=0x4A | 0x90..=0xAF => vec![register(1), register(2)],
        0x32..=0x37 | 0xB0..=0xCF => vec![register(0), register(1)],
        0x4B..=0x51 => vec![register(1), register(2), register(0)],
        0x59..=0x5F => vec![register(1), register(0)],
        _ => return None,
    };
    order.into_iter().collect()
}

fn fills_next(state: &RenderState<'_>, walk: &BlockWalk, index: usize, register: u16) -> bool {
    index + 1 < walk.end
        && state.insns.get(index + 1).is_some_and(|next: &DalvikInsn| {
            next.op == 0x26 && next.regs.first() == Some(&register)
        })
}

fn anchor_filled_array(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    index: usize,
    after: &RegisterSet,
    out: &mut String,
    level: usize,
) {
    let Some(&register): Option<&u16> = state
        .insns
        .get(index)
        .and_then(|insn: &DalvikInsn| insn.regs.first())
    else {
        return;
    };
    if !walk.file.is_pending(register)
        || !matches!(walk.file.slot(register), Some(Expr::ArrayInit { .. }))
    {
        return;
    }
    let single_use: bool = index
        .checked_sub(1)
        .and_then(|allocation: usize| state.flow.def_uses(allocation, register))
        .is_some_and(|facts: DefUses| facts.local_uses == 2 && !facts.escapes);
    if single_use {
        return;
    }
    let request: FlushRequest<'_> = FlushRequest {
        assign: vec![register],
        external: None,
        effect: false,
        live: after,
        exclude: &[],
    };
    flush(state, walk, &request, out, level);
}

const fn may_throw(op: u8) -> bool {
    matches!(
        op,
        0x1C..=0x27
            | 0x44..=0x72
            | 0x74..=0x78
            | 0x93
            | 0x94
            | 0x9E
            | 0x9F
            | 0xB3
            | 0xB4
            | 0xBE
            | 0xBF
            | 0xD3
            | 0xD4
            | 0xDB
            | 0xDC
    )
}

fn predicts_statement(state: &RenderState<'_>, walk: &BlockWalk, insn: &DalvikInsn) -> bool {
    let invoke: bool = matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78);
    let discards: Option<bool> = walk
        .pending
        .as_ref()
        .filter(|result: &&PendingResult| {
            result.discards_statement()
                && !matches!(insn.op, 0x0A..=0x0C)
                && !(invoke
                    && insn
                        .regs
                        .first()
                        .is_some_and(|&receiver: &u16| result.materializes(receiver)))
        })
        .map(|result: &PendingResult| !result.is_null_check());
    if discards == Some(true) {
        return true;
    }
    match insn.op {
        0x27 | 0x4B..=0x51 | 0x59..=0x5F | 0x67..=0x6D => true,
        0x6E..=0x72 | 0x74..=0x78 => insn
            .index
            .and_then(|index: u32| state.ctx.dex.method_ids.get(index as usize))
            .is_some_and(|method: &crate::dex::MethodId| {
                let allocates: bool = method.name == "<init>"
                    && insn
                        .regs
                        .first()
                        .and_then(|&receiver: &u16| walk.file.slot(receiver))
                        .is_some_and(|value: &Expr| matches!(value, Expr::New(_)));
                method.proto.return_type == "V" && !allocates
            }),
        _ => false,
    }
}

fn anchor_effects(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    index: usize,
    defs: &[u16],
    after: &RegisterSet,
    out: &mut String,
    level: usize,
) {
    for &register in defs {
        let Some(value): Option<Expr> = walk.file.slot(register).cloned() else {
            continue;
        };
        if !walk.file.is_pending(register)
            || matches!(value, Expr::New(_))
            || !expr_has_effect(&value)
            || matches!(value, Expr::NewArray { .. }) && fills_next(state, walk, index, register)
        {
            continue;
        }
        let facts: DefUses = state.flow.def_uses(index, register).unwrap_or(DefUses {
            local_uses: 0,
            escapes: true,
        });
        if facts.local_uses == 1 && !facts.escapes {
            continue;
        }
        if walk
            .pending
            .as_ref()
            .is_some_and(|result: &PendingResult| result.materializes(register))
        {
            walk.pending = None;
        }
        let dead: bool = facts.local_uses == 0 && !facts.escapes && !after.contains(register);
        if dead && let Some(statement) = effect_statement(&value) {
            let request: FlushRequest<'_> = FlushRequest {
                assign: Vec::new(),
                external: None,
                effect: true,
                live: after,
                exclude: defs,
            };
            flush(state, walk, &request, out, level);
            let _: std::fmt::Result = writeln!(out, "{}{statement};", indent_string(level));
            let name: String = target_name(state, walk, register);
            walk.file.set_variable(register, name);
            continue;
        }
        let request: FlushRequest<'_> = FlushRequest {
            assign: vec![register],
            external: None,
            effect: false,
            live: after,
            exclude: &[],
        };
        flush(state, walk, &request, out, level);
    }
}

fn close_block(
    state: &mut RenderState<'_>,
    walk: &mut BlockWalk,
    bid: BlockId,
    out: &mut String,
    level: usize,
) {
    let (start, end): (usize, usize) = block_insn_range(state, bid);
    let exit: RegisterSet = live_at(walk, end.saturating_sub(start));
    if let Some(result) = walk.pending.take() {
        let continues_in_successor: bool = state
            .insns
            .get(end)
            .is_some_and(|following: &DalvikInsn| matches!(following.op, 0x0A..=0x0C));
        if continues_in_successor {
            state.fully_lifted = false;
        } else if let Some(statement) = result.into_statement() {
            let request: FlushRequest<'_> = FlushRequest {
                assign: Vec::new(),
                external: None,
                effect: true,
                live: &exit,
                exclude: &[],
            };
            flush(state, walk, &request, out, level);
            let _: std::fmt::Result = writeln!(out, "{}{statement};", indent_string(level));
        }
    }
    let Some(block): Option<&BasicBlock> = state.cfg.blocks.get(bid.0 as usize) else {
        return;
    };
    if block.successors.is_empty() {
        return;
    }
    let terminates: bool = end
        .checked_sub(1)
        .and_then(|last: usize| state.insns.get(last))
        .is_some_and(|last: &DalvikInsn| {
            last.is_conditional_branch() || last.is_unconditional_goto() || last.is_switch()
        });
    let live: RegisterSet = if terminates {
        live_at(walk, end.saturating_sub(start).saturating_sub(1))
    } else {
        exit
    };
    let Some(live_out): Option<RegisterSet> = state.flow.live_out(bid).cloned() else {
        return;
    };
    let assign: Vec<u16> = walk
        .file
        .pending_registers()
        .filter(|&register: &u16| live_out.contains(register))
        .collect();
    let request: FlushRequest<'_> = FlushRequest {
        assign,
        external: None,
        effect: false,
        live: &live,
        exclude: &[],
    };
    flush(state, walk, &request, out, level);
}

fn walk_block_body(
    state: &mut RenderState<'_>,
    bid: BlockId,
    body_end: usize,
    replay: bool,
    out: &mut String,
    level: usize,
) -> Option<BlockWalk> {
    let (start, end): (usize, usize) = block_insn_range(state, bid);
    let Some(mut walk): Option<BlockWalk> = open_block(state, bid, replay) else {
        state.fully_lifted = false;
        return None;
    };
    let insns: &[DalvikInsn] = state.insns;
    let body: &[DalvikInsn] = insns.get(start..body_end.min(end)).unwrap_or_default();
    for (offset, insn) in body.iter().enumerate() {
        if insn.is_conditional_branch() || insn.is_unconditional_goto() || insn.is_switch() {
            continue;
        }
        walk_insn(state, &mut walk, start + offset, out, level);
    }
    close_block(state, &mut walk, bid, out, level);
    Some(walk)
}

fn render_block(state: &mut RenderState<'_>, bid: BlockId, out: &mut String, level: usize) {
    if !state.rendered_blocks.insert(bid) {
        return;
    }
    let (_, end): (usize, usize) = block_insn_range(state, bid);
    let _: Option<BlockWalk> = walk_block_body(state, bid, end, false, out, level);
}

fn walk_head(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> Option<(BlockWalk, usize)> {
    let (start, end): (usize, usize) = block_insn_range(state, head);
    if start == end {
        return None;
    }
    let body_end: usize = end - 1;
    let already: bool = !state.rendered_blocks.insert(head);
    let mut scratch: String = String::new();
    let sink: &mut String = if already { &mut scratch } else { out };
    walk_block_body(state, head, body_end, already, sink, level)
        .map(|walk: BlockWalk| (walk, body_end))
}

fn render_head_condition(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    match walk_head(state, head, out, level) {
        Some((walk, body_end)) => {
            render_branch_condition(state.ctx, &walk.file, &state.insns[body_end])
        }
        None => "true".to_string(),
    }
}

fn render_switch_subject(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let Some((walk, body_end)): Option<(BlockWalk, usize)> = walk_head(state, head, out, level)
    else {
        return "var0".to_string();
    };
    state.insns[body_end]
        .regs
        .first()
        .map(|&register: &u16| walk.file.current(state.ctx, register).render())
        .unwrap_or_else(|| "var0".to_string())
}

fn lift_insn_tracked(
    state: &mut RenderState<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending: &mut Option<PendingResult>,
) -> LiftOutcome {
    let outcome: LiftOutcome = lift_insn(state.ctx, file, insn, pending);
    record_lift_outcome(&mut state.fully_lifted, &outcome);
    outcome
}

const fn record_lift_outcome(fully_lifted: &mut bool, outcome: &LiftOutcome) {
    if matches!(outcome, LiftOutcome::Unlifted) {
        *fully_lifted = false;
    }
}

fn header_cond_true_target(cfg: &Cfg, head: BlockId) -> Option<BlockId> {
    let block: &BasicBlock = &cfg.blocks[head.0 as usize];
    block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))
        .map(|e| e.target)
}

fn format_switch_key(key: &SwitchKey, fallback_idx: usize) -> String {
    match key {
        SwitchKey::Range { low, high } => (*low..=*high)
            .map(|v: i32| v.to_string())
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(vs) if !vs.is_empty() => vs
            .iter()
            .map(i32::to_string)
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(_) => fallback_idx.to_string(),
    }
}

fn invert(cond: &str) -> String {
    if let Some(rest) = cond.strip_prefix('!') {
        return rest.to_string();
    }
    if cond.contains(" == ") {
        return cond.replacen(" == ", " != ", 1);
    }
    if cond.contains(" != ") {
        return cond.replacen(" != ", " == ", 1);
    }
    if cond.contains(" <= ") {
        return cond.replacen(" <= ", " > ", 1);
    }
    if cond.contains(" >= ") {
        return cond.replacen(" >= ", " < ", 1);
    }
    if cond.contains(" < ") {
        return cond.replacen(" < ", " >= ", 1);
    }
    if cond.contains(" > ") {
        return cond.replacen(" > ", " <= ", 1);
    }
    format!("!({cond})")
}

pub fn decompile_dex_bytes(bytes: &[u8]) -> crate::error::Result<DecompiledDex> {
    let dex: DexFile = crate::dex::parse(bytes)?;
    Ok(decompile_dex(&dex, bytes))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_cff_note_claims_removal_only_when_lifted_from_the_rewired_graph() {
        let cff: crate::dalvik_dexguard::DalvikMethodCff =
            crate::dalvik_dexguard::DalvikMethodCff {
                class: "Lcom/example/A;".to_owned(),
                method_name: "run".to_owned(),
                method_descriptor: "()V".to_owned(),
                flattened: true,
                fully_unflattened: true,
                dispatchers_resolved: 1,
                edges_redirected: 3,
                dead_branches_folded: 0,
                dispatcher_blocks_pruned: 1,
                residual_dispatcher_edges: 0,
                recovered_block_order: vec![0, 2, 1],
                rewire_refusal: None,
            };
        let rendered_flat: String = cff_annotation(&cff, false);
        assert!(!rendered_flat.contains("removed"), "{rendered_flat}");
        assert!(
            rendered_flat.contains("still rendered from the flattened graph"),
            "{rendered_flat}"
        );
        let lifted: String = cff_annotation(&cff, true);
        assert!(lifted.contains("flattening removed"), "{lifted}");
        assert!(lifted.contains("lifted from the rewired graph"), "{lifted}");
    }

    const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
    const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

    fn decompiled() -> DecompiledDex {
        let dex: DexFile = crate::dex::parse(EDGECASES_DEX).expect("parse edgecases.dex");
        decompile_dex(&dex, EDGECASES_DEX)
    }

    #[test]
    fn malformed_default_companion_is_not_projected_into_translated_source() {
        let mut dex: DexFile = crate::dex::parse(EDGECASES_DEX).expect("parse mutation source");
        let bridge: &mut crate::dex::MethodId = dex
            .method_ids
            .iter_mut()
            .find(|method: &&mut crate::dex::MethodId| {
                method.class.ends_with("Shape$-CC;") && method.name == "$default$label"
            })
            .expect("find default companion bridge");
        bridge.name = "<clinit>".to_owned();

        let recovered: Vec<TranslatedDefaultMethod> =
            translated_default_methods(&dex, EDGECASES_DEX);
        assert!(
            recovered
                .iter()
                .all(|method: &TranslatedDefaultMethod| !method.definition.contains(" label("))
        );
        let fallback: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
        assert!(
            fallback.source.contains("Shape$_u002D_CC"),
            "{}",
            fallback.source
        );
    }

    fn rendered_class_fixture(name: &str, text: &str) -> RenderedClass {
        RenderedClass {
            text: text.to_owned(),
            source_path: format!("{name}.java"),
            method_count: 1,
            fully_lifted: 1,
            fallback: 0,
        }
    }

    fn member_metadata(owner: &str, members: &[&str]) -> DexSystemMetadata {
        let mut metadata: DexSystemMetadata = DexSystemMetadata::default();
        metadata.classes.insert(
            owner.to_owned(),
            crate::dex::DexClassMetadata {
                member_classes: members
                    .iter()
                    .map(|member: &&str| (*member).to_owned())
                    .collect(),
                ..crate::dex::DexClassMetadata::default()
            },
        );
        metadata
    }

    #[test]
    fn translated_owner_paths_follow_inner_class_metadata_instead_of_dollar_signs() {
        let mut metadata: DexSystemMetadata = DexSystemMetadata::default();
        for top_level in ["Lcash/Money$Box;", "Lcash/Wallet;", "La/c;"] {
            metadata.classes.insert(
                top_level.to_owned(),
                crate::dex::DexClassMetadata::default(),
            );
        }
        for (nested, simple, enclosing) in [
            ("Lcash/Wallet$Card;", "Card", "Lcash/Wallet;"),
            ("La/b;", "Card", "La/c;"),
        ] {
            metadata.classes.insert(
                nested.to_owned(),
                crate::dex::DexClassMetadata {
                    inner_class: Some(DexInnerClass {
                        simple_name: Some(simple.to_owned()),
                        access_flags: 0x0609,
                    }),
                    enclosing_class: Some(enclosing.to_owned()),
                    ..crate::dex::DexClassMetadata::default()
                },
            );
        }
        metadata.classes.insert(
            "La/local;".to_owned(),
            crate::dex::DexClassMetadata {
                inner_class: Some(DexInnerClass {
                    simple_name: Some("Local".to_owned()),
                    access_flags: 0x0600,
                }),
                enclosing_method: Some(crate::dex::DexEnclosingMethod {
                    class: "La/c;".to_owned(),
                    name: "run".to_owned(),
                    descriptor: "()V".to_owned(),
                }),
                ..crate::dex::DexClassMetadata::default()
            },
        );

        let path = |class: &str| translated_owner_path(&metadata, class);
        assert_eq!(
            path("Lcash/Money$Box;"),
            Some(("cash/Money$Box".to_owned(), vec!["Money$Box".to_owned()]))
        );
        assert_eq!(
            path("Lcash/Wallet$Card;"),
            Some((
                "cash/Wallet".to_owned(),
                vec!["Wallet".to_owned(), "Card".to_owned()]
            ))
        );
        assert_eq!(
            path("La/b;"),
            Some(("a/c".to_owned(), vec!["c".to_owned(), "Card".to_owned()]))
        );
        assert_eq!(path("La/local;"), None);
    }

    #[test]
    fn only_metadata_enclosed_unnamed_classes_nest_under_their_reference_parent() {
        let mut metadata: DexSystemMetadata = member_metadata("LOuter;", &["LOuter$Api;"]);
        metadata.classes.insert(
            "LOuter$Api;".to_owned(),
            crate::dex::DexClassMetadata {
                inner_class: Some(DexInnerClass {
                    simple_name: Some("Api".to_owned()),
                    access_flags: 0x0609,
                }),
                enclosing_class: Some("LOuter;".to_owned()),
                ..crate::dex::DexClassMetadata::default()
            },
        );
        metadata.classes.insert(
            "LOuter$Api$1;".to_owned(),
            crate::dex::DexClassMetadata {
                inner_class: Some(DexInnerClass {
                    simple_name: None,
                    access_flags: 0,
                }),
                enclosing_method: Some(crate::dex::DexEnclosingMethod {
                    class: "LOuter$Api;".to_owned(),
                    name: "create".to_owned(),
                    descriptor: "()LOuter$Api;".to_owned(),
                }),
                ..crate::dex::DexClassMetadata::default()
            },
        );
        for unannotated in ["LOuter$Api$-CC;", "LOuter$Box;"] {
            metadata.classes.insert(
                unannotated.to_owned(),
                crate::dex::DexClassMetadata::default(),
            );
        }
        let classes: Vec<String> = [
            "LOuter;",
            "LOuter$Api;",
            "LOuter$Api$1;",
            "LOuter$Api$-CC;",
            "LOuter$Box;",
        ]
        .iter()
        .map(|class: &&str| (*class).to_owned())
        .collect();
        let member_owner: BTreeMap<String, String> =
            BTreeMap::from([("LOuter$Api;".to_owned(), "LOuter;".to_owned())]);
        let source_names: BTreeMap<&str, &str> = BTreeMap::from([
            ("LOuter;", "Outer"),
            ("LOuter$Api;", "Outer.Api"),
            ("LOuter$Api$1;", "Outer.Api$_1"),
            ("LOuter$Api$-CC;", "Outer.Api$_u002D_CC"),
            ("LOuter$Box;", "Outer.Box"),
        ]);
        let mut metadata: DexSystemMetadata = metadata;
        metadata.classes.insert(
            "LOuter$Api$2;".to_owned(),
            crate::dex::DexClassMetadata {
                inner_class: Some(DexInnerClass {
                    simple_name: None,
                    access_flags: 0,
                }),
                enclosing_method: Some(crate::dex::DexEnclosingMethod {
                    class: "LOuter$Api$-CC;".to_owned(),
                    name: "inMemory".to_owned(),
                    descriptor: "()LOuter$Api;".to_owned(),
                }),
                ..crate::dex::DexClassMetadata::default()
            },
        );
        let mut classes: Vec<String> = classes;
        classes.push("LOuter$Api$2;".to_owned());
        let mut source_names: BTreeMap<&str, &str> = source_names;
        source_names.insert("LOuter$Api$2;", "Outer.Api$_2");
        let name = |class: &str| source_names[class].to_owned();

        let unrecovered_companion: BTreeMap<String, (String, String)> =
            source_named_members(classes.iter(), &metadata, &member_owner, name, |_: &str| {
                None
            });
        assert_eq!(
            unrecovered_companion,
            BTreeMap::from([(
                "LOuter$Api$1;".to_owned(),
                ("LOuter;".to_owned(), "Api$_1".to_owned())
            )])
        );
        let recovered_companion: BTreeMap<String, (String, String)> = source_named_members(
            classes.iter(),
            &metadata,
            &member_owner,
            name,
            |companion: &str| (companion == "LOuter$Api$-CC;").then(|| "LOuter$Api;".to_owned()),
        );
        assert_eq!(
            recovered_companion,
            BTreeMap::from([
                (
                    "LOuter$Api$1;".to_owned(),
                    ("LOuter;".to_owned(), "Api$_1".to_owned())
                ),
                (
                    "LOuter$Api$2;".to_owned(),
                    ("LOuter;".to_owned(), "Api$_2".to_owned())
                )
            ])
        );
    }

    #[test]
    fn member_classes_of_an_unrendered_owner_are_emitted_as_roots() {
        let metadata: DexSystemMetadata = member_metadata("LSynthetic;", &["LReal;"]);
        let (children, member_owner): (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) =
            rendered_member_classes(&metadata, |owner: &str| owner != "LSynthetic;");
        assert!(children.is_empty());
        assert!(member_owner.is_empty());
        let rendered: BTreeMap<String, RenderedClass> = BTreeMap::from([(
            "LReal;".to_owned(),
            rendered_class_fixture("Real", "public class Real {\n}\n"),
        )]);
        let (source, sources): (String, BTreeMap<String, String>) =
            compose_rendered_sources(rendered, &children, &member_owner);
        assert_eq!(source, "public class Real {\n}\n");
        assert_eq!(sources.keys().collect::<Vec<&String>>(), ["Real.java"]);

        let (children, member_owner): (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) =
            rendered_member_classes(&metadata, |_: &str| true);
        assert_eq!(
            member_owner.get("LReal;").map(String::as_str),
            Some("LSynthetic;")
        );
        let orphaned: BTreeMap<String, RenderedClass> = BTreeMap::from([(
            "LReal;".to_owned(),
            rendered_class_fixture("Real", "static class Real {\n}\n"),
        )]);
        let (source, _): (String, BTreeMap<String, String>) =
            compose_rendered_sources(orphaned, &children, &member_owner);
        assert_eq!(source, "static class Real {\n}\n");
    }

    #[test]
    fn nested_composition_failure_and_cycles_keep_every_rendered_class() {
        let metadata: DexSystemMetadata = member_metadata("LOuter;", &["LOuter$Inner;"]);
        let (children, member_owner): (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) =
            rendered_member_classes(&metadata, |_: &str| true);
        let unclosed: BTreeMap<String, RenderedClass> = BTreeMap::from([
            (
                "LOuter;".to_owned(),
                rendered_class_fixture("Outer", "public class Outer {"),
            ),
            (
                "LOuter$Inner;".to_owned(),
                rendered_class_fixture("Inner", "static class Inner {\n}\n"),
            ),
        ]);
        let (source, sources): (String, BTreeMap<String, String>) =
            compose_rendered_sources(unclosed, &children, &member_owner);
        assert_eq!(source, "public class Outer {\nstatic class Inner {\n}\n");
        assert_eq!(
            sources.keys().collect::<Vec<&String>>(),
            ["Inner.java", "Outer.java"]
        );

        let mut cyclic: DexSystemMetadata = member_metadata("LA;", &["LB;"]);
        cyclic
            .classes
            .extend(member_metadata("LB;", &["LA;"]).classes);
        let (children, member_owner): (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) =
            rendered_member_classes(&cyclic, |_: &str| true);
        let rendered: BTreeMap<String, RenderedClass> = BTreeMap::from([
            (
                "LA;".to_owned(),
                rendered_class_fixture("A", "class A {\n}\n"),
            ),
            (
                "LB;".to_owned(),
                rendered_class_fixture("B", "class B {\n}\n"),
            ),
        ]);
        let (source, _): (String, BTreeMap<String, String>) =
            compose_rendered_sources(rendered, &children, &member_owner);
        assert_eq!(source, "class A {\n    class B {\n    }\n}\n");
    }

    #[test]
    fn unlifted_constructor_instruction_makes_the_method_partial() {
        let mut fully_lifted: bool = true;
        record_lift_outcome(&mut fully_lifted, &LiftOutcome::Unlifted);
        assert!(!fully_lifted);
    }

    #[test]
    fn gcd_body_has_modulo_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int gcd(").expect("gcd present");
        let slice: &str = &src[start..(start + 400).min(src.len())];
        assert!(slice.contains('%'), "gcd body must contain %: {slice}");
        assert!(
            slice.contains("while"),
            "gcd body must contain a loop: {slice}"
        );
        assert!(
            slice.contains("Math.abs"),
            "gcd body must reference Math.abs: {slice}"
        );
    }

    #[test]
    fn dotint_body_has_array_index_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int dotInt(").expect("dotInt present");
        let slice: &str = &src[start..(start + 500).min(src.len())];
        assert!(slice.contains('['), "dotInt must index arrays: {slice}");
        assert!(slice.contains("while"), "dotInt must loop: {slice}");
    }

    #[test]
    fn const_high16_families_render_full_width_values() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        assert!(
            src.contains("radius() <= 100.0)"),
            "100.0 (const-wide/high16 0x4059) compared with a double must render as the double \
             it encodes"
        );
        assert!(
            src.contains("(this.base * 0.5)"),
            "0.5 (const-wide/high16 0x3FE0) multiplied with a double must render as the double \
             it encodes"
        );
        assert!(
            !src.contains("4636737291354636288L") && !src.contains("4602678819172646912L"),
            "a double constant must not leak as the long holding its bit pattern"
        );
        assert!(
            src.contains("-2147483648"),
            "Integer.MIN_VALUE (const/high16 0x8000) must render shifted, not -32768"
        );
        assert!(
            !src.contains("16473L") && !src.contains("16352L"),
            "raw const-wide/high16 operands must not leak as long literals"
        );
    }

    fn render_static_probe(
        descriptor: &str,
        registers: u16,
        ins: u16,
        insns: Vec<u16>,
    ) -> MethodBody {
        let dex: DexFile = crate::dex::parse(EDGECASES_DEX).expect("parse edgecases.dex");
        let item: CodeItem = CodeItem {
            method_name: "probe".to_owned(),
            method_descriptor: descriptor.to_owned(),
            class: "LProbe;".to_owned(),
            is_direct: true,
            registers_size: registers,
            ins_size: ins,
            outs_size: 0,
            insns,
            tries: Vec::new(),
            param_names: Vec::new(),
        };
        let interfaces: crate::dalvik_desugar::DefaultInterfaceRecovery =
            crate::dalvik_desugar::DefaultInterfaceRecovery::default();
        let functionals: crate::dalvik_desugar::FunctionalRecovery =
            crate::dalvik_desugar::FunctionalRecovery::default();
        let core_library: crate::dalvik_core_library::CoreLibraryRecovery =
            crate::dalvik_core_library::CoreLibraryRecovery::default();
        let helpers: crate::dalvik_desugar::InlinedHelpers =
            crate::dalvik_desugar::InlinedHelpers::default();
        let names: Vec<String> = (0..ins).map(|index: u16| format!("arg{index}")).collect();
        lift_method(
            &dex,
            &item,
            None,
            MethodIdentity {
                declaring_class: "LProbe;",
                descriptor,
                is_static: true,
                is_constructor: false,
            },
            false,
            crate::dalvik_desugar::DesugarView {
                interfaces: &interfaces,
                functionals: &functionals,
                core_library: &core_library,
            },
            &helpers,
            &names,
        )
    }

    #[test]
    fn crossed_block_end_assignments_save_the_overwritten_value_first() {
        let body: MethodBody = render_static_probe(
            "(II)I",
            7,
            2,
            vec![
                0x5001, 0x6101, 0x0128, 0x04D8, 0x0101, 0x01D8, 0x0100, 0x00D8, 0x0004, 0x0128,
                0x00DA, 0x6400, 0x10B0, 0x000F,
            ],
        );
        assert!(body.fully_lifted, "{}", body.text);
        let lines: Vec<&str> = body.text.lines().map(str::trim).collect();
        let swap: [&str; 3] = [
            "int tmp0 = var1;",
            "var1 = (var0 + 1);",
            "var0 = ((tmp0 + 1) + 0);",
        ];
        assert!(
            lines
                .windows(swap.len())
                .any(|window: &[&str]| window == swap.as_slice()),
            "{}",
            body.text
        );
        assert!(
            lines.contains(&"return ((var0 * 100) + var1);"),
            "{}",
            body.text
        );
    }

    #[test]
    fn kotlin_dex_emits_without_panic() {
        let dex: DexFile = crate::dex::parse(EDGECASES_KT_DEX).expect("parse edgecases kt dex");
        let out: DecompiledDex = decompile_dex(&dex, EDGECASES_KT_DEX);
        assert!(out.class_count > 0, "kotlin dex must yield classes");
    }
}
