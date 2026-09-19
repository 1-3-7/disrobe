#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::expect_used,
    clippy::panic
)]

use disrobe_pass_jvm::dex::{
    DexClassMetadata, DexInnerClass, DexSystemMetadata, DexSystemMetadataReport,
    parse_system_metadata,
};
use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder};
use std::collections::BTreeMap;
use std::io::Read as _;

use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{
    Attribute, ClassFile, ConstantPoolEntry, DecompiledDex, DexFile, decompile_dex,
    parse_classfile, parse_dex,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_JAR: &[u8] = include_bytes!("../../../corpus/jvm/megafile/EdgeCases-baseline.jar");
const MULTIDEX_OUTER_DEX: &[u8] =
    include_bytes!("fixtures/dex_system_metadata/MultidexOuter-min21.dex");
const MULTIDEX_INNER_DEX: &[u8] =
    include_bytes!("fixtures/dex_system_metadata/MultidexInner-min21.dex");
const INITIALIZER_LOCAL_DEX: &[u8] =
    include_bytes!("fixtures/dex_system_metadata/InitializerLocal-min21.dex");
const MULTIDEX_SOURCE: &str = include_str!("fixtures/dex_system_metadata/Outer.java");
const INITIALIZER_LOCAL_SOURCE: &str =
    include_str!("fixtures/dex_system_metadata/InitializerLocal.java");

pub mod common;

fn javac_classes(
    scratch_name: &str,
    relative_source: &str,
    source: &str,
) -> BTreeMap<String, ClassFile> {
    let javac: std::path::PathBuf =
        common::find_on_path("javac").expect("javac is required for the metadata oracle");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(scratch_name).expect("create javac scratch");
    let source_path: std::path::PathBuf = scratch.path().join(relative_source);
    std::fs::create_dir_all(source_path.parent().expect("oracle source parent"))
        .expect("create oracle source directory");
    std::fs::write(&source_path, source).expect("write oracle source");
    let classes_dir: std::path::PathBuf = scratch.path().join("classes");
    let output: std::process::Output = std::process::Command::new(javac)
        .arg("-Xlint:-options")
        .arg("--release")
        .arg("8")
        .arg("-d")
        .arg(&classes_dir)
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        output.status.success(),
        "oracle compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    let mut pending: Vec<std::path::PathBuf> = vec![classes_dir.clone()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read oracle output") {
            let path: std::path::PathBuf = entry.expect("oracle output entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative: String = path
                .strip_prefix(&classes_dir)
                .expect("oracle class under output")
                .to_string_lossy()
                .replace('\\', "/");
            let bytes: Vec<u8> = std::fs::read(&path).expect("read oracle class");
            classes.insert(
                relative,
                parse_classfile(&bytes).expect("parse oracle class"),
            );
        }
    }
    classes
}

fn enclosing_method_attribute(class_file: &ClassFile) -> Option<(String, u16)> {
    let matching: Vec<&Attribute> = class_file
        .attributes
        .iter()
        .filter(|candidate: &&Attribute| {
            class_file
                .utf8_at(candidate.name_index)
                .is_ok_and(|name: &str| name == "EnclosingMethod")
        })
        .collect();
    let [attribute]: [&Attribute; 1] = matching.try_into().ok()?;
    let class_name: String = class_file
        .class_name(read_u16(&attribute.info, 0))
        .expect("enclosing class constant")
        .to_owned();
    Some((class_name, read_u16(&attribute.info, 2)))
}

fn translated_class(translated: &Dex2JarResult, entry: &str) -> ClassFile {
    parse_classfile(
        translated
            .jar_entries
            .get(entry)
            .unwrap_or_else(|| panic!("translated entry {entry}")),
    )
    .expect("parse translated class")
}

#[test]
fn multidex_members_split_across_dex_files_parse_decompile_and_translate() {
    let oracle: BTreeMap<String, ClassFile> = javac_classes(
        "dex_metadata_multidex_oracle",
        "fixture/multidex/Outer.java",
        MULTIDEX_SOURCE,
    );
    for (bytes, entry, member, dropped_relationship) in [
        (
            MULTIDEX_OUTER_DEX,
            "fixture/multidex/Outer.class",
            "make(",
            "MemberClasses child is not defined in this DEX",
        ),
        (
            MULTIDEX_INNER_DEX,
            "fixture/multidex/Outer$Inner.class",
            "get(",
            "enclosing class is not defined in this DEX",
        ),
    ] {
        let dex: DexFile = parse_dex(bytes).expect("a split multidex member must parse");
        let report: DexSystemMetadataReport = parse_system_metadata(&dex, bytes);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason.contains(dropped_relationship)),
            "{entry}: {:?}",
            report.diagnostics
        );
        assert!(
            report
                .metadata
                .classes
                .values()
                .all(|class| class.member_classes.is_empty()
                    && class.inner_class.is_none()
                    && class.enclosing_class.is_none()),
            "{entry} kept a relationship to a class outside this DEX"
        );
        let recovered: DecompiledDex = decompile_dex(&dex, bytes);
        assert!(
            recovered.source.contains(member),
            "{entry} lost {member}:\n{}",
            recovered.source
        );
        assert!(
            !recovered.source.contains("malformed DEX system metadata"),
            "{}",
            recovered.source
        );
        let translated: Dex2JarResult =
            translate_dex_bytes(bytes).expect("a split multidex member must translate");
        let class: ClassFile = translated_class(&translated, entry);
        let javac_class: &ClassFile = oracle.get(entry).expect("javac oracle class");
        assert_eq!(signature_map(&class), signature_map(javac_class), "{entry}");
        let production: disrobe_pass_jvm::AndroidDecompileOutput =
            disrobe_pass_jvm::android_decompile_dex(
                bytes,
                disrobe_pass_jvm::BackendPreference::PreferInHouse,
            )
            .expect("the production Android route must accept a split multidex member");
        assert!(!production.sources.is_empty(), "{entry}");
    }
}

#[test]
fn initializer_local_named_class_metadata_matches_javac() {
    let oracle: BTreeMap<String, ClassFile> = javac_classes(
        "dex_metadata_initializer_local_oracle",
        "fixture/initlocal/InitializerLocal.java",
        INITIALIZER_LOCAL_SOURCE,
    );
    let dex: DexFile =
        parse_dex(INITIALIZER_LOCAL_DEX).expect("an initializer-local named class must parse");
    let recovered: DecompiledDex = decompile_dex(&dex, INITIALIZER_LOCAL_DEX);
    assert!(recovered.source.contains("next("), "{}", recovered.source);
    assert!(
        !recovered.source.contains("malformed DEX system metadata"),
        "{}",
        recovered.source
    );
    let translated: Dex2JarResult = translate_dex_bytes(INITIALIZER_LOCAL_DEX)
        .expect("an initializer-local named class must translate");
    for entry in [
        "fixture/initlocal/InitializerLocal.class",
        "fixture/initlocal/InitializerLocal$1Counter.class",
    ] {
        let class: ClassFile = translated_class(&translated, entry);
        let javac_class: &ClassFile = oracle.get(entry).expect("javac oracle class");
        assert_eq!(inner_entries(&class), inner_entries(javac_class), "{entry}");
        assert_eq!(
            enclosing_method_attribute(&class),
            enclosing_method_attribute(javac_class),
            "{entry}"
        );
    }
    assert_eq!(
        enclosing_method_attribute(
            oracle
                .get("fixture/initlocal/InitializerLocal$1Counter.class")
                .expect("javac local class")
        ),
        Some(("fixture/initlocal/InitializerLocal".to_owned(), 0))
    );
    disrobe_pass_jvm::android_decompile_dex(
        INITIALIZER_LOCAL_DEX,
        disrobe_pass_jvm::BackendPreference::PreferInHouse,
    )
    .expect("the production Android route must accept an initializer-local class");
}

#[test]
fn malformed_signature_bytes_drop_only_the_affected_signatures() {
    let needle: [u8; 5] = [0x03, b'T', b'A', b';', 0x00];
    let positions: Vec<usize> = EDGECASES_DEX
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window): &(usize, &[u8])| *window == needle)
        .map(|(position, _): (usize, &[u8])| position)
        .collect();
    let [position]: [usize; 1] = positions
        .try_into()
        .unwrap_or_else(|found: Vec<usize>| panic!("expected one TA; string, found {found:?}"));
    let mut patched: Vec<u8> = EDGECASES_DEX.to_vec();
    patched[position + 2] = b';';

    let dex: DexFile = parse_dex(&patched).expect("a malformed Signature must not refuse the DEX");
    let recovered: DecompiledDex = decompile_dex(&dex, &patched);
    let baseline: DecompiledDex = decompile_dex(
        &parse_dex(EDGECASES_DEX).expect("parse unpatched DEX"),
        EDGECASES_DEX,
    );
    assert_eq!(recovered.class_count, baseline.class_count);
    assert!(
        !recovered.source.contains("malformed DEX system metadata"),
        "{}",
        recovered.source
    );

    let clean: Dex2JarResult = translate_dex_bytes(EDGECASES_DEX).expect("translate unpatched");
    let degraded: Dex2JarResult =
        translate_dex_bytes(&patched).expect("a malformed Signature must not refuse translation");
    assert_eq!(
        clean.jar_entries.keys().collect::<Vec<&String>>(),
        degraded.jar_entries.keys().collect::<Vec<&String>>()
    );
    let mut dropped: usize = 0;
    for (entry, bytes) in &clean.jar_entries {
        let clean_signatures: BTreeMap<String, String> =
            signature_map(&parse_classfile(bytes).expect("parse clean class"));
        let degraded_signatures: BTreeMap<String, String> =
            signature_map(&translated_class(&degraded, entry));
        for (key, value) in &clean_signatures {
            if let Some(kept) = degraded_signatures.get(key) {
                assert_eq!(kept, value, "{entry} {key}");
            } else {
                assert!(
                    value.contains("TA;"),
                    "{entry} {key} lost an unaffected signature {value}"
                );
                dropped += 1;
            }
        }
        assert!(
            degraded_signatures
                .keys()
                .all(|key: &String| clean_signatures.contains_key(key)),
            "{entry}"
        );
    }
    assert!(dropped > 0);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InnerEntry {
    inner: String,
    outer: Option<String>,
    simple: Option<String>,
    flags: u16,
}

fn attribute<'a>(
    class_file: &'a ClassFile,
    attributes: &'a [Attribute],
    name: &str,
) -> &'a Attribute {
    let matches: Vec<&Attribute> = attributes
        .iter()
        .filter(|candidate: &&Attribute| {
            class_file
                .utf8_at(candidate.name_index)
                .is_ok_and(|actual: &str| actual == name)
        })
        .collect();
    let [attribute]: [&Attribute; 1] =
        matches.try_into().unwrap_or_else(|found: Vec<&Attribute>| {
            panic!("expected one {name} attribute, found {}", found.len())
        });
    attribute
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("two attribute bytes"),
    )
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four DEX bytes"),
    )
}

fn read_uleb(bytes: &[u8], mut offset: usize) -> (u32, usize) {
    let mut value: u32 = 0;
    for shift in (0..35).step_by(7) {
        let byte: u8 = *bytes.get(offset).expect("ULEB128 byte");
        offset += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return (value, offset);
        }
    }
    panic!("ULEB128 width");
}

fn first_relevant_annotation(dex: &DexFile, bytes: &[u8]) -> (usize, usize, usize) {
    for class_index in 0..dex.header.class_defs_size as usize {
        let class_offset: usize = dex.header.class_defs_off as usize + class_index * 32;
        let directory_offset: usize = read_u32_le(bytes, class_offset + 20) as usize;
        if directory_offset == 0 {
            continue;
        }
        let set_offset: usize = read_u32_le(bytes, directory_offset) as usize;
        if set_offset == 0 {
            continue;
        }
        let count: usize = read_u32_le(bytes, set_offset) as usize;
        for entry_index in 0..count {
            let entry_offset: usize = set_offset + 4 + entry_index * 4;
            let annotation_offset: usize = read_u32_le(bytes, entry_offset) as usize;
            let (type_index, body_offset): (u32, usize) = read_uleb(bytes, annotation_offset + 1);
            let descriptor: &str = dex
                .type_names
                .get(type_index as usize)
                .expect("annotation descriptor");
            if matches!(
                descriptor,
                "Ldalvik/annotation/MemberClasses;"
                    | "Ldalvik/annotation/InnerClass;"
                    | "Ldalvik/annotation/EnclosingClass;"
                    | "Ldalvik/annotation/EnclosingMethod;"
                    | "Ldalvik/annotation/Signature;"
            ) {
                return (entry_offset, annotation_offset, body_offset);
            }
        }
    }
    panic!("relevant system annotation");
}

fn inner_entries(class_file: &ClassFile) -> Vec<InnerEntry> {
    let info: &[u8] = &attribute(class_file, &class_file.attributes, "InnerClasses").info;
    let count: usize = usize::from(read_u16(info, 0));
    assert_eq!(info.len(), 2 + count * 8);
    let mut entries: Vec<InnerEntry> = Vec::with_capacity(count);
    for index in 0..count {
        let offset: usize = 2 + index * 8;
        let inner_index: u16 = read_u16(info, offset);
        let outer_index: u16 = read_u16(info, offset + 2);
        let name_index: u16 = read_u16(info, offset + 4);
        entries.push(InnerEntry {
            inner: class_file
                .class_name(inner_index)
                .expect("inner class constant")
                .to_owned(),
            outer: (outer_index != 0).then(|| {
                class_file
                    .class_name(outer_index)
                    .expect("outer class constant")
                    .to_owned()
            }),
            simple: (name_index != 0).then(|| {
                class_file
                    .utf8_at(name_index)
                    .expect("inner name constant")
                    .to_owned()
            }),
            flags: read_u16(info, offset + 6),
        });
    }
    entries.sort();
    entries
}

fn signature(class_file: &ClassFile, attributes: &[Attribute]) -> Option<String> {
    let matching: Vec<&Attribute> = attributes
        .iter()
        .filter(|candidate: &&Attribute| {
            class_file
                .utf8_at(candidate.name_index)
                .is_ok_and(|name: &str| name == "Signature")
        })
        .collect();
    let [attribute]: [&Attribute; 1] = matching.try_into().ok()?;
    let index: u16 = read_u16(&attribute.info, 0);
    class_file.utf8_at(index).ok().map(str::to_owned)
}

fn signature_map(class_file: &ClassFile) -> BTreeMap<String, String> {
    let mut signatures: BTreeMap<String, String> = BTreeMap::new();
    if let Some(value) = signature(class_file, &class_file.attributes) {
        signatures.insert("class".to_owned(), value);
    }
    for field in &class_file.fields {
        if let Some(value) = signature(class_file, &field.attributes) {
            let name: &str = class_file.utf8_at(field.name_index).expect("field name");
            let descriptor: &str = class_file
                .utf8_at(field.descriptor_index)
                .expect("field descriptor");
            signatures.insert(format!("field:{name}:{descriptor}"), value);
        }
    }
    for method in &class_file.methods {
        if let Some(value) = signature(class_file, &method.attributes) {
            let name: &str = class_file.utf8_at(method.name_index).expect("method name");
            let descriptor: &str = class_file
                .utf8_at(method.descriptor_index)
                .expect("method descriptor");
            signatures.insert(format!("method:{name}:{descriptor}"), value);
        }
    }
    signatures
}

fn classfiles_from_jar(bytes: &[u8]) -> BTreeMap<String, ClassFile> {
    let reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(reader).expect("open baseline jar");
    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> = archive.by_index(index).expect("jar entry");
        if !entry.name().ends_with(".class") {
            continue;
        }
        let name: String = entry.name().to_owned();
        let mut class_bytes: Vec<u8> = Vec::new();
        entry
            .read_to_end(&mut class_bytes)
            .expect("read class entry");
        classes.insert(
            name,
            parse_classfile(&class_bytes).expect("parse class entry"),
        );
    }
    classes
}

#[test]
fn edgecases_named_members_share_the_authoritative_outer_compilation_unit() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse the real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let outer: &String = recovered
        .sources
        .get("EdgeCases.java")
        .expect("outer compilation unit");

    for declaration in [
        "interface Adder",
        "class CounterWorker",
        "interface FluentBuilder",
        "class Outer",
        "class Pair",
    ] {
        assert!(
            outer.contains(declaration),
            "missing authoritative member declaration {declaration:?}:\n{outer}"
        );
    }
    for obsolete_path in [
        "EdgeCases/Adder.java",
        "EdgeCases/CounterWorker.java",
        "EdgeCases/FluentBuilder.java",
        "EdgeCases/Outer.java",
        "EdgeCases/Pair.java",
    ] {
        assert!(
            !recovered.sources.contains_key(obsolete_path),
            "named member retained obsolete package path {obsolete_path}"
        );
    }
    for identity in [
        "public static EdgeCases.Adder adderFn()",
        "public static int callInner()",
        "public EdgeCases.FluentBuilder set(String arg0, Object arg1)",
        "public static int runWorker(EdgeCases.CounterWorker arg0)",
        "public static String unpackPair(EdgeCases.Pair arg0)",
        "public static java.util.List windowed(java.util.List arg0)",
    ] {
        assert!(
            recovered.source.contains(identity),
            "projected clean method identity is absent: {identity}"
        );
    }
}

#[test]
fn edgecases_system_annotations_translate_to_exact_jvm_metadata() {
    let translated: Dex2JarResult =
        translate_dex_bytes(EDGECASES_DEX).expect("translate the real D8 artifact");
    let baseline: BTreeMap<String, ClassFile> = classfiles_from_jar(EDGECASES_JAR);
    let translated_outer: ClassFile = parse_classfile(
        translated
            .jar_entries
            .get("EdgeCases.class")
            .expect("translated outer class"),
    )
    .expect("parse translated outer class");
    let baseline_outer: &ClassFile = baseline
        .get("EdgeCases.class")
        .expect("baseline outer class");
    let expected_inners: Vec<InnerEntry> = inner_entries(baseline_outer)
        .into_iter()
        .filter(|entry: &InnerEntry| {
            entry.inner.starts_with("EdgeCases$") && entry.inner != "EdgeCases$Repository$1"
        })
        .collect();
    assert_eq!(inner_entries(&translated_outer), expected_inners);

    let translated_multilevel: ClassFile = parse_classfile(
        translated
            .jar_entries
            .get("EdgeCases$Outer$Inner.class")
            .expect("translated multi-level inner class"),
    )
    .expect("parse translated multi-level inner class");
    let baseline_multilevel: &ClassFile = baseline
        .get("EdgeCases$Outer$Inner.class")
        .expect("baseline multi-level inner class");
    assert_eq!(
        inner_entries(&translated_multilevel),
        inner_entries(baseline_multilevel)
    );

    for class_name in [
        "EdgeCases.class",
        "EdgeCases$Pair.class",
        "EdgeCases$FluentBuilder.class",
    ] {
        let translated_class: ClassFile = parse_classfile(
            translated
                .jar_entries
                .get(class_name)
                .unwrap_or_else(|| panic!("translated class {class_name}")),
        )
        .unwrap_or_else(|error| panic!("parse translated class {class_name}: {error}"));
        let baseline_class: &ClassFile = baseline
            .get(class_name)
            .unwrap_or_else(|| panic!("baseline class {class_name}"));
        let mut expected_signatures: BTreeMap<String, String> = signature_map(baseline_class);
        if class_name == "EdgeCases$Pair.class" {
            expected_signatures.insert(
                "class".to_owned(),
                "<A:Ljava/lang/Object;B:Ljava/lang/Object;>Lcom/android/tools/r8/RecordTag;"
                    .to_owned(),
            );
        }
        assert_eq!(signature_map(&translated_class), expected_signatures);
    }

    let translated_anonymous: ClassFile = parse_classfile(
        translated
            .jar_entries
            .get("EdgeCases$1.class")
            .expect("translated anonymous class"),
    )
    .expect("parse translated anonymous class");
    let anonymous_entry: InnerEntry = inner_entries(&translated_anonymous)
        .into_iter()
        .find(|entry: &InnerEntry| entry.inner == "EdgeCases$1")
        .expect("anonymous InnerClasses entry");
    assert_eq!(anonymous_entry.outer, None);
    assert_eq!(anonymous_entry.simple, None);
    assert_eq!(anonymous_entry.flags, 0);

    let enclosing: &Attribute = attribute(
        &translated_anonymous,
        &translated_anonymous.attributes,
        "EnclosingMethod",
    );
    assert_eq!(enclosing.info.len(), 4);
    assert_eq!(
        translated_anonymous
            .class_name(read_u16(&enclosing.info, 0))
            .expect("enclosing class"),
        "EdgeCases"
    );
    let method_index: usize = usize::from(read_u16(&enclosing.info, 2));
    let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = translated_anonymous
        .constant_pool
        .get(method_index)
        .expect("enclosing method constant")
    else {
        panic!("enclosing method must use NameAndType");
    };
    assert_eq!(
        translated_anonymous
            .utf8_at(*name_index)
            .expect("method name"),
        "memoize"
    );
    assert_eq!(
        translated_anonymous
            .utf8_at(*descriptor_index)
            .expect("method descriptor"),
        "(Ljava/util/function/Supplier;)Ljava/util/function/Supplier;"
    );
}

fn diagnostic_for(report: &DexSystemMetadataReport, class: &str, fragment: &str) -> bool {
    report.diagnostics.iter().any(|diagnostic| {
        diagnostic.class.as_deref() == Some(class) && diagnostic.reason.contains(fragment)
    })
}

#[test]
fn annotation_directory_offsets_and_counts_are_bounded() {
    let parsed: DexFile = parse_dex(EDGECASES_DEX).expect("parse mutation source");
    let class_defs_offset: usize = parsed.header.class_defs_off as usize;
    let mut offset_out_of_range: Vec<u8> = EDGECASES_DEX.to_vec();
    offset_out_of_range[class_defs_offset + 20..class_defs_offset + 24]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let offset_report: DexSystemMetadataReport = parse_system_metadata(
        &parse_dex(&offset_out_of_range).expect("an out-of-range directory offset still parses"),
        &offset_out_of_range,
    );
    assert!(
        diagnostic_for(
            &offset_report,
            &parsed.class_descriptors[0],
            "annotation directory offset is out of range"
        ),
        "{:?}",
        offset_report.diagnostics
    );
    translate_dex_bytes(&offset_out_of_range)
        .expect("an out-of-range directory offset still translates");

    let annotated_class: usize = (0..parsed.header.class_defs_size as usize)
        .map(|index: usize| class_defs_offset + index * 32)
        .find(|offset: &usize| {
            u32::from_le_bytes(
                EDGECASES_DEX[*offset + 20..*offset + 24]
                    .try_into()
                    .expect("annotation offset bytes"),
            ) != 0
        })
        .expect("annotated class");
    let annotated_descriptor: &String =
        &parsed.class_descriptors[(annotated_class - class_defs_offset) / 32];
    let directory_offset: usize = u32::from_le_bytes(
        EDGECASES_DEX[annotated_class + 20..annotated_class + 24]
            .try_into()
            .expect("annotation directory offset bytes"),
    ) as usize;
    let annotation_set_offset: usize = u32::from_le_bytes(
        EDGECASES_DEX[directory_offset..directory_offset + 4]
            .try_into()
            .expect("class annotation set offset bytes"),
    ) as usize;

    let mut count_over_budget: Vec<u8> = EDGECASES_DEX.to_vec();
    count_over_budget[annotation_set_offset..annotation_set_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let budget_report: DexSystemMetadataReport = parse_system_metadata(
        &parse_dex(&count_over_budget).expect("an over-budget set count still parses"),
        &count_over_budget,
    );
    assert!(
        diagnostic_for(
            &budget_report,
            annotated_descriptor,
            "annotation set is truncated"
        ),
        "{:?}",
        budget_report.diagnostics
    );
    translate_dex_bytes(&count_over_budget).expect("an over-budget set count still translates");

    let data_end: usize = parsed.header.data_off as usize + parsed.header.data_size as usize;
    let count_past_data_end: usize = (data_end - annotation_set_offset) / 4;
    assert!(count_past_data_end <= EDGECASES_DEX.len());
    let mut truncated_set: Vec<u8> = EDGECASES_DEX.to_vec();
    truncated_set[annotation_set_offset..annotation_set_offset + 4].copy_from_slice(
        &u32::try_from(count_past_data_end)
            .expect("bounded set count")
            .to_le_bytes(),
    );
    let truncated_report: DexSystemMetadataReport = parse_system_metadata(
        &parse_dex(&truncated_set).expect("an in-budget truncated set still parses"),
        &truncated_set,
    );
    assert!(
        diagnostic_for(
            &truncated_report,
            annotated_descriptor,
            "annotation set is truncated"
        ),
        "{:?}",
        truncated_report.diagnostics
    );
    translate_dex_bytes(&truncated_set).expect("an in-budget truncated set still translates");
}

fn assert_other_classes_keep_exact_metadata(
    mutated: &[u8],
    corrupted_descriptor: &str,
    expected_reason: &str,
) {
    let original: DexSystemMetadataReport = parse_system_metadata(
        &parse_dex(EDGECASES_DEX).expect("parse original"),
        EDGECASES_DEX,
    );
    let report: DexSystemMetadataReport =
        parse_system_metadata(&parse_dex(mutated).expect("parse mutation"), mutated);
    let mut compared: usize = 0;
    for (descriptor, class_metadata) in &original.metadata.classes {
        if descriptor == corrupted_descriptor
            || class_metadata
                .member_classes
                .contains(&corrupted_descriptor.to_owned())
            || class_metadata.enclosing_class.as_deref() == Some(corrupted_descriptor)
            || class_metadata
                .enclosing_method
                .as_ref()
                .is_some_and(|method| method.class == corrupted_descriptor)
        {
            continue;
        }
        assert_eq!(
            report.metadata.classes.get(descriptor),
            Some(class_metadata),
            "{descriptor} lost metadata after {corrupted_descriptor} was corrupted"
        );
        compared += 1;
    }
    assert!(
        original
            .metadata
            .classes
            .iter()
            .filter(|(descriptor, _)| descriptor.as_str() != corrupted_descriptor)
            .any(
                |(_, class_metadata)| !class_metadata.member_classes.is_empty()
                    || class_metadata.inner_class.is_some()
            ),
        "the comparison must include classes with nesting metadata"
    );
    assert!(compared > 10, "{compared}");
    assert!(
        diagnostic_for(&report, corrupted_descriptor, expected_reason),
        "{:?}",
        report.diagnostics
    );
}

#[test]
fn a_corrupted_first_annotated_class_leaves_later_class_metadata_exact() {
    let parsed: DexFile = parse_dex(EDGECASES_DEX).expect("parse mutation source");
    let class_defs_offset: usize = parsed.header.class_defs_off as usize;
    let annotated_class: usize = (0..parsed.header.class_defs_size as usize)
        .map(|index: usize| class_defs_offset + index * 32)
        .find(|offset: &usize| {
            u32::from_le_bytes(
                EDGECASES_DEX[*offset + 20..*offset + 24]
                    .try_into()
                    .expect("annotation offset bytes"),
            ) != 0
        })
        .expect("annotated class");
    let annotated_descriptor: String =
        parsed.class_descriptors[(annotated_class - class_defs_offset) / 32].clone();
    let directory_offset: usize = u32::from_le_bytes(
        EDGECASES_DEX[annotated_class + 20..annotated_class + 24]
            .try_into()
            .expect("annotation directory offset bytes"),
    ) as usize;
    let annotation_set_offset: usize = u32::from_le_bytes(
        EDGECASES_DEX[directory_offset..directory_offset + 4]
            .try_into()
            .expect("class annotation set offset bytes"),
    ) as usize;

    let mut huge_field_count: Vec<u8> = EDGECASES_DEX.to_vec();
    huge_field_count[directory_offset + 4..directory_offset + 8]
        .copy_from_slice(&0x7FFF_FFFF_u32.to_le_bytes());
    assert_other_classes_keep_exact_metadata(
        &huge_field_count,
        &annotated_descriptor,
        "annotation directory entries are truncated",
    );

    let mut huge_set_count: Vec<u8> = EDGECASES_DEX.to_vec();
    huge_set_count[annotation_set_offset..annotation_set_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    assert_other_classes_keep_exact_metadata(
        &huge_set_count,
        &annotated_descriptor,
        "annotation set is truncated",
    );
}

#[test]
fn relevant_annotation_body_must_not_cross_data_end() {
    let mut parsed: DexFile = parse_dex(EDGECASES_DEX).expect("parse mutation source");
    let (entry_offset, annotation_offset, body_offset): (usize, usize, usize) =
        first_relevant_annotation(&parsed, EDGECASES_DEX);
    let mut moved_body: Vec<u8> = EDGECASES_DEX.to_vec();
    let moved_annotation_offset: usize = moved_body.len();
    moved_body.extend_from_slice(&EDGECASES_DEX[annotation_offset..]);
    moved_body[entry_offset..entry_offset + 4].copy_from_slice(
        &u32::try_from(moved_annotation_offset)
            .expect("moved annotation offset")
            .to_le_bytes(),
    );
    let moved_body_offset: usize =
        moved_annotation_offset + body_offset.saturating_sub(annotation_offset);
    let data_offset: usize = parsed.header.data_off as usize;
    parsed.header.data_size =
        u32::try_from(moved_body_offset - data_offset).expect("bounded data size");
    let report: DexSystemMetadataReport = parse_system_metadata(&parsed, &moved_body);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.offset == moved_body_offset),
        "{:?}",
        report.diagnostics
    );
}

#[test]
fn dollar_in_an_unannotated_top_level_name_never_implies_nesting() {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcash/Money$Box;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: Vec::new(),
    });
    let bytes: Vec<u8> = builder.build();
    let dex: DexFile = parse_dex(&bytes).expect("parse controlled DEX");
    let recovered: DecompiledDex = decompile_dex(&dex, &bytes);

    assert_eq!(
        recovered.sources.keys().cloned().collect::<Vec<String>>(),
        vec!["cash/Money$Box.java".to_owned()]
    );
    assert!(recovered.source.contains("package cash;"));
    assert!(recovered.source.contains("public class Money$Box"));
    assert!(!recovered.source.contains("package cash.Money;"));
}

#[test]
fn dollar_in_an_unannotated_name_beside_its_prefix_class_never_implies_nesting() {
    let mut builder: DexBuilder = DexBuilder::new();
    for class in ["Lcash/Money;", "Lcash/Money$Box;"] {
        builder.add_class(ClassDef {
            class: class.to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
    }
    let bytes: Vec<u8> = builder.build();
    let dex: DexFile = parse_dex(&bytes).expect("parse controlled DEX");
    let recovered: DecompiledDex = decompile_dex(&dex, &bytes);

    assert_eq!(
        recovered.sources.keys().cloned().collect::<Vec<String>>(),
        vec![
            "cash/Money$Box.java".to_owned(),
            "cash/Money.java".to_owned()
        ]
    );
    let money: &String = recovered
        .sources
        .get("cash/Money.java")
        .expect("top-level Money");
    assert!(!money.contains("Box"), "{money}");
    let money_box: &String = recovered
        .sources
        .get("cash/Money$Box.java")
        .expect("top-level Money$Box");
    assert!(money_box.contains("package cash;"), "{money_box}");
    assert!(money_box.contains("public class Money$Box"), "{money_box}");
    assert!(!money_box.contains("static class"), "{money_box}");
}

fn metadata_refusal(dex: &DexFile) -> String {
    parse_system_metadata(dex, EDGECASES_DEX)
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.reason)
        .collect::<Vec<String>>()
        .join("\n")
}

#[test]
fn system_annotation_indices_relationships_and_output_are_bounded() {
    let parsed: DexFile = parse_dex(EDGECASES_DEX).expect("parse mutation source");

    let mut invalid_index: DexFile = parsed.clone();
    invalid_index.type_names.clear();
    assert!(metadata_refusal(&invalid_index).contains("type index is out of range"));

    let mut missing_child: DexFile = parsed.clone();
    let child_type: &mut String = missing_child
        .type_names
        .iter_mut()
        .find(|name: &&mut String| name.as_str() == "LEdgeCases$Adder;")
        .expect("member type");
    *child_type = "Lmissing/Child;".to_owned();
    assert!(metadata_refusal(&missing_child).contains("child is not defined"));
    let degraded: DexSystemMetadata = parse_system_metadata(&missing_child, EDGECASES_DEX).metadata;
    let outer_members: &Vec<String> = &degraded
        .classes
        .get("LEdgeCases;")
        .expect("outer metadata survives")
        .member_classes;
    assert!(!outer_members.is_empty());
    assert!(
        !outer_members
            .iter()
            .any(|member| member == "Lmissing/Child;")
    );

    let mut conflicting_owner: DexFile = parsed.clone();
    let outer_type: &mut String = conflicting_owner
        .type_names
        .iter_mut()
        .find(|name: &&mut String| name.as_str() == "LEdgeCases;")
        .expect("outer type");
    *outer_type = "LEdgeCases$Outer;".to_owned();
    assert!(metadata_refusal(&conflicting_owner).contains("invalid or conflicting"));

    let parsed_report: DexSystemMetadataReport = parse_system_metadata(&parsed, EDGECASES_DEX);
    assert!(
        parsed_report.diagnostics.is_empty(),
        "{:?}",
        parsed_report.diagnostics
    );
    let parsed_metadata: DexSystemMetadata = parsed_report.metadata;
    let cycle_refused: bool = parsed_metadata.classes.iter().any(
        |(class_name, class_metadata): (&String, &DexClassMetadata)| {
            let Some(enclosing_method) = &class_metadata.enclosing_method else {
                return false;
            };
            let mut cycle: DexFile = parsed.clone();
            let Some(method) = cycle.method_ids.iter_mut().find(|method| {
                method.class == enclosing_method.class
                    && method.name == enclosing_method.name
                    && format!(
                        "({}){}",
                        method.proto.parameters.join(""),
                        method.proto.return_type
                    ) == enclosing_method.descriptor
            }) else {
                return false;
            };
            method.class.clone_from(class_name);
            metadata_refusal(&cycle).contains("contains a cycle")
        },
    );
    assert!(cycle_refused);

    let mut invalid_signature: DexFile = parsed.clone();
    let fragment: &mut String = invalid_signature
        .strings
        .iter_mut()
        .find(|value: &&mut String| value.as_str() == "TA;")
        .expect("signature fragment");
    *fragment = "T;".to_owned();
    assert!(metadata_refusal(&invalid_signature).contains("grammar is invalid"));

    let mut oversized_output: DexFile = parsed;
    let fragment: &mut String = oversized_output
        .strings
        .iter_mut()
        .find(|value: &&mut String| value.as_str() == "TA;")
        .expect("signature fragment");
    *fragment = "T".repeat(4 * 1024 * 1024 + 1);
    assert!(metadata_refusal(&oversized_output).contains("output budget exceeded"));
}

#[test]
fn system_annotation_enclosing_depth_is_bounded() {
    let mut metadata: DexSystemMetadata = DexSystemMetadata::default();
    for index in 0..=65 {
        metadata.classes.insert(
            format!("LC{index};"),
            DexClassMetadata {
                inner_class: Some(DexInnerClass {
                    simple_name: None,
                    access_flags: 0,
                }),
                enclosing_class: Some(format!("LC{};", index + 1)),
                ..DexClassMetadata::default()
            },
        );
    }
    metadata
        .classes
        .insert("LC66;".to_owned(), DexClassMetadata::default());
    let report: DexSystemMetadataReport = metadata.normalize();
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason.contains("depth exceeded")),
        "{:?}",
        report.diagnostics
    );
    for cleared in ["LC0;", "LC1;"] {
        assert!(
            report.metadata.classes[cleared].inner_class.is_none(),
            "{cleared} keeps an over-deep relationship"
        );
    }
    assert!(
        report.metadata.classes["LC2;"].inner_class.is_some(),
        "a chain of exactly 64 enclosing steps must be kept"
    );
}
