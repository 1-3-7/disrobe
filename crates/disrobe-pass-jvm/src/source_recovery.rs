use std::collections::BTreeMap;

use crate::classfile::{ClassFile, parse};
use crate::decompile::{
    DecompiledClass, decompile_class_with_inners, is_identifier_byte, with_class_set_functions,
};
use crate::error::{Error, Result};
use crate::opaque_flow::{FunctionKey, PureFunction, pure_functions};
use crate::proguard::{ClassHierarchy, Mapping};
use crate::protectors::{
    InlinedStrings, ProtectorPeelReport, inline_recovered_strings, peel_classfile,
};
use crate::rename::{RenameReport, rename_classfile};

const MAX_CLASSES: usize = 65_536;
const MAX_NESTING: usize = 64;
const NESTED_INDENT: &str = "    ";
const SYNTHETIC_OUTER_FIELD: &str = "this$";
const DECLARATION_KINDS: [&str; 5] = ["class", "interface", "enum", "record", "@interface"];

#[derive(Debug, Clone, Copy, Default)]
pub struct SourceRecoveryOptions<'a> {
    pub mapping: Option<&'a Mapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredUnit {
    pub class_name: String,
    pub relative_path: String,
    pub source: String,
    pub fallback_methods: usize,
    pub inner_classes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceRecovery {
    pub units: Vec<RecoveredUnit>,
    pub classes_renamed: usize,
    pub members_renamed: usize,
    pub references_renamed: usize,
    pub strings_inlined: usize,
    pub banners_removed: usize,
}

fn top_level_owner<'a>(name: &'a str, known: &BTreeMap<String, ClassFile>) -> &'a str {
    let mut owner: &str = name;
    let mut cursor: &str = name;
    while let Some((outer, _)) = cursor.rsplit_once('$') {
        if outer.is_empty() || outer.ends_with('/') {
            break;
        }
        if known.contains_key(outer) {
            owner = outer;
        }
        cursor = outer;
    }
    owner
}

struct NestedSource {
    source: String,
    fallback_methods: usize,
}

fn is_anonymous_segment(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte: u8| byte.is_ascii_digit())
}

fn replace_identifier(text: &str, from: &str, to: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    let mut search: usize = 0;
    while let Some(offset) = text[search..].find(from) {
        let start: usize = search + offset;
        let end: usize = start + from.len();
        let bounded: bool = (start == 0 || !is_identifier_byte(bytes[start - 1]))
            && bytes
                .get(end)
                .is_none_or(|byte: &u8| !is_identifier_byte(*byte));
        if bounded {
            out.push_str(&text[cursor..start]);
            out.push_str(to);
            cursor = end;
        }
        search = end;
    }
    out.push_str(&text[cursor..]);
    out
}

fn nested_declaration(source: &str, leaf: &str, simple: &str) -> Option<String> {
    let body: &str = match source.split_once('\n') {
        Some((first, rest)) if first.starts_with("package ") => rest.trim_start_matches('\n'),
        _ => source,
    };
    let mut out: String = String::with_capacity(body.len() + 64);
    let mut declared: bool = false;
    for line in body.lines() {
        let mut line: String = replace_identifier(line, leaf, simple);
        if !declared
            && let Some(kind) = DECLARATION_KINDS
                .iter()
                .find(|kind: &&&str| line.contains(&format!("{kind} {simple}")))
        {
            let at: usize = line.find(&format!("{kind} {simple}"))?;
            if !line[..at]
                .split_whitespace()
                .any(|word: &str| word == "static")
            {
                line.insert_str(at, "static ");
            }
            declared = true;
        }
        if !line.is_empty() {
            out.push_str(NESTED_INDENT);
        }
        out.push_str(&line);
        out.push('\n');
    }
    declared.then_some(out)
}

fn has_outer_instance(cf: &ClassFile) -> bool {
    cf.fields.iter().any(|field| {
        cf.utf8_at(field.name_index)
            .is_ok_and(|name: &str| name.starts_with(SYNTHETIC_OUTER_FIELD))
    })
}

fn render_class_tree(
    name: &str,
    cf: &ClassFile,
    classes: &BTreeMap<String, ClassFile>,
    depth: usize,
) -> NestedSource {
    let prefix: String = format!("{name}$");
    let mut children: Vec<(&str, &ClassFile)> = Vec::new();
    let mut inners: BTreeMap<String, ClassFile> = BTreeMap::new();
    for (candidate, inner) in classes.range(prefix.clone()..) {
        let Some(rest): Option<&str> = candidate.strip_prefix(&prefix) else {
            break;
        };
        let first: &str = rest.split('$').next().unwrap_or(rest);
        let named: bool = !first.is_empty() && !is_anonymous_segment(first);
        if named && first == rest {
            children.push((candidate.as_str(), inner));
        } else if !(named && classes.contains_key(&format!("{prefix}{first}"))) {
            inners.insert(format!("{candidate}.class"), inner.clone());
        }
    }
    let decompiled: DecompiledClass = decompile_class_with_inners(cf, &inners);
    let mut source: String = decompiled.source;
    let mut fallback_methods: usize = decompiled.fallback_methods;
    let mut nested: String = String::new();
    for (child, child_cf) in children {
        let simple: &str = &child[prefix.len()..];
        let leaf: &str = child.rsplit('/').next().unwrap_or(child);
        if depth >= MAX_NESTING
            || has_outer_instance(child_cf)
            || !crate::name_disambig::is_java_type_identifier(simple)
            || !crate::name_disambig::is_java_source_identifier(leaf)
        {
            fallback_methods += child_cf.methods.len().max(1);
            continue;
        }
        let rendered: NestedSource = render_class_tree(child, child_cf, classes, depth + 1);
        fallback_methods += rendered.fallback_methods;
        match nested_declaration(&rendered.source, leaf, simple) {
            Some(text) => nested.push_str(&text),
            None => fallback_methods += child_cf.methods.len().max(1),
        }
    }
    if !nested.is_empty() {
        match source.rfind('}') {
            Some(close) => source.insert_str(close, &nested),
            None => fallback_methods += 1,
        }
    }
    NestedSource {
        source,
        fallback_methods,
    }
}

pub fn recover_sources(
    class_files: &[Vec<u8>],
    options: SourceRecoveryOptions<'_>,
) -> Result<SourceRecovery> {
    if class_files.len() > MAX_CLASSES {
        return Err(Error::TooManyClasses(class_files.len()));
    }
    let mut recovery: SourceRecovery = SourceRecovery::default();
    let mut parsed: Vec<ClassFile> = Vec::with_capacity(class_files.len());
    let mut hierarchy: ClassHierarchy = ClassHierarchy::new();
    for bytes in class_files {
        let cf: ClassFile = parse(bytes)?;
        hierarchy.record_classfile(&cf);
        parsed.push(cf);
    }
    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    for cf in parsed {
        let renamed: ClassFile = match options.mapping {
            Some(mapping) => {
                let (renamed, report): (ClassFile, RenameReport) =
                    rename_classfile(mapping, &cf, &hierarchy);
                recovery.classes_renamed += report.classes_renamed;
                recovery.members_renamed += report.members_renamed;
                recovery.references_renamed += report.references_renamed;
                renamed
            }
            None => cf,
        };
        let peeled: ClassFile = match peel_classfile(&renamed) {
            Some(report) if !report.strings_recovered.is_empty() => {
                let report: ProtectorPeelReport = report;
                let inlined: InlinedStrings =
                    inline_recovered_strings(&renamed, &report.strings_recovered);
                recovery.strings_inlined += inlined.call_sites_inlined;
                recovery.banners_removed += inlined.banners_removed;
                inlined.class
            }
            _ => renamed,
        };
        let name: String = peeled.this_class_name()?.to_owned();
        if classes.insert(name.clone(), peeled).is_some() {
            return Err(Error::DuplicateClass(name));
        }
    }
    let mut functions: BTreeMap<FunctionKey, PureFunction> = BTreeMap::new();
    for cf in classes.values() {
        functions.extend(pure_functions(cf));
    }
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in classes.keys() {
        let owner: &str = top_level_owner(name, &classes);
        owners.entry(owner.to_owned()).or_default();
        if owner != name
            && let Some(inners) = owners.get_mut(owner)
        {
            inners.push(name.clone());
        }
    }
    let rendered_units: Vec<(String, Vec<String>, NestedSource)> =
        with_class_set_functions(functions, || {
            owners
                .into_iter()
                .filter_map(|(owner, inner_names): (String, Vec<String>)| {
                    let cf: &ClassFile = classes.get(&owner)?;
                    let rendered: NestedSource = render_class_tree(&owner, cf, &classes, 0);
                    Some((owner, inner_names, rendered))
                })
                .collect()
        });
    for (owner, inner_names, rendered) in rendered_units {
        let directory: &str = owner.rsplit_once('/').map_or("", |(package, _)| package);
        let file_name: String = format!("{}.java", crate::decompile::simple_class_name(&owner));
        recovery.units.push(RecoveredUnit {
            relative_path: if directory.is_empty() {
                file_name
            } else {
                format!("{directory}/{file_name}")
            },
            class_name: owner,
            source: rendered.source,
            fallback_methods: rendered.fallback_methods,
            inner_classes: inner_names,
        });
    }
    Ok(recovery)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::classfile::ConstantPoolEntry;

    fn known(names: &[&str]) -> BTreeMap<String, ClassFile> {
        names
            .iter()
            .map(|name: &&str| {
                (
                    (*name).to_owned(),
                    ClassFile {
                        minor_version: 0,
                        major_version: 52,
                        constant_pool: Vec::new(),
                        access_flags: 0,
                        this_class: 0,
                        super_class: 0,
                        interfaces: Vec::new(),
                        fields: Vec::new(),
                        methods: Vec::new(),
                        attributes: Vec::new(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn nested_and_anonymous_classes_attach_to_the_outermost_known_class() {
        let classes: BTreeMap<String, ClassFile> =
            known(&["a/Outer", "a/Outer$Inner", "a/Outer$Inner$1", "a/S$5$5"]);
        assert_eq!(top_level_owner("a/Outer$Inner$1", &classes), "a/Outer");
        assert_eq!(top_level_owner("a/Outer$Inner", &classes), "a/Outer");
        assert_eq!(top_level_owner("a/Outer", &classes), "a/Outer");
        assert_eq!(top_level_owner("a/S$5$5", &classes), "a/S$5$5");
    }

    #[test]
    fn an_oversized_class_set_is_refused() {
        let classes: Vec<Vec<u8>> = vec![Vec::new(); MAX_CLASSES + 1];
        let error: Error =
            recover_sources(&classes, SourceRecoveryOptions::default()).expect_err("refused");
        assert!(error.to_string().contains("too many classes"));
    }

    fn named_class(name: &str) -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![
                ConstantPoolEntry::Placeholder,
                ConstantPoolEntry::Utf8(name.to_owned()),
                ConstantPoolEntry::Class { name_index: 1 },
                ConstantPoolEntry::Utf8("java/lang/Object".to_owned()),
                ConstantPoolEntry::Class { name_index: 3 },
            ],
            access_flags: 0x0021,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        }
    }

    fn nested_chain(depth: usize) -> BTreeMap<String, ClassFile> {
        let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
        let mut name: String = "p/C0".to_owned();
        for level in 0..depth {
            if level > 0 {
                name = format!("{name}$C{level}");
            }
            classes.insert(name.clone(), named_class(&name));
        }
        classes
    }

    #[test]
    fn named_nested_classes_are_declared_inside_their_outer_class() {
        let classes: BTreeMap<String, ClassFile> = nested_chain(3);
        let root: &ClassFile = classes.get("p/C0").expect("root");
        let rendered: NestedSource = render_class_tree("p/C0", root, &classes, 0);
        assert_eq!(rendered.fallback_methods, 0, "{}", rendered.source);
        assert!(
            rendered.source.contains("static class C1 {"),
            "{}",
            rendered.source
        );
        assert!(
            rendered.source.contains("static class C2 {"),
            "{}",
            rendered.source
        );
        assert!(!rendered.source.contains("C0$C1"), "{}", rendered.source);
    }

    #[test]
    fn nesting_past_the_bound_is_counted_as_unrecovered() {
        let classes: BTreeMap<String, ClassFile> = nested_chain(MAX_NESTING + 4);
        let root: &ClassFile = classes.get("p/C0").expect("root");
        let rendered: NestedSource = render_class_tree("p/C0", root, &classes, 0);
        assert!(rendered.fallback_methods > 0);
        assert!(
            !rendered
                .source
                .contains(&format!("class C{} ", MAX_NESTING + 1))
        );
    }

    #[test]
    fn identifier_replacement_stops_at_identifier_boundaries() {
        assert_eq!(
            replace_identifier("Outer$In(Outer$Inner x, Outer$In y)", "Outer$In", "In"),
            "In(Outer$Inner x, In y)"
        );
    }
}
