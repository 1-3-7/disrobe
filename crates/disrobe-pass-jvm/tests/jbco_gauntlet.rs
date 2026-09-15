#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, DecompiledClass, JarExtract, UnmappedHeuristics, decompile_class,
    extract_jar, heuristic_recover, parse_classfile,
};

const CLEAN_JAR: &[u8] = include_bytes!("../../../corpus/jvm/obfuscators/jbco/Sample-clean.jar");
const OBF_JAR: &[u8] = include_bytes!("../../../corpus/jvm/obfuscators/jbco/Sample-obf.jar");

const MAIN_ENTRY: &str = "com/example/app/Sample.class";

fn load(jar: &[u8]) -> JarExtract {
    extract_jar(jar).expect("extract jbco gauntlet jar")
}

fn parse_entry(jx: &JarExtract, entry: &str) -> ClassFile {
    let bytes: &Vec<u8> = jx
        .classes
        .get(entry)
        .unwrap_or_else(|| panic!("class {entry} not present in jar"));
    parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {entry}: {e}"))
}

fn string_literals(cf: &ClassFile) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::String { utf8_index } = entry
            && let Ok(value) = cf.utf8_at(*utf8_index)
        {
            out.insert(value.to_string());
        }
    }
    out
}

fn member_names(cf: &ClassFile) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &cf.fields {
        out.insert(cf.utf8_at(f.name_index).expect("field name").to_string());
    }
    for m in &cf.methods {
        out.insert(cf.utf8_at(m.name_index).expect("method name").to_string());
    }
    out
}

fn is_jbco_mangled(name: &str) -> bool {
    name != "<init>"
        && name != "<clinit>"
        && name != "main"
        && name.len() >= 4
        && name
            .chars()
            .any(|c: char| c == '$' || c == 'I' || c == 'l' || c.is_ascii_digit())
        && !name.chars().any(|c: char| c == '_')
}

#[test]
fn obf_class_parses_through_jbco_control_flow_obfuscation() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let dc: DecompiledClass = decompile_class(&main);
    assert!(
        dc.method_count >= 8,
        "JBCO adds a <clinit> for embedded constants; the obfuscated class must still lift ctor + 5 renamed methods + main + clinit, got {}",
        dc.method_count
    );
    assert_eq!(
        dc.fallback_methods, 0,
        "disrobe must fully lift every method through JBCO's goto-augmentation and indirect-if traps with zero fallbacks, got {} fallbacks",
        dc.fallback_methods
    );
    assert!(
        dc.fully_lifted_methods >= 8,
        "every method body must lift past the JBCO control-flow obfuscation, got {} lifted",
        dc.fully_lifted_methods
    );
    assert!(
        !dc.source.is_empty(),
        "decompiled JBCO-obfuscated source must not be empty"
    );
}

#[test]
fn obf_class_carries_jbco_constant_embedding_signature() {
    let clean: JarExtract = load(CLEAN_JAR);
    let obf: JarExtract = load(OBF_JAR);
    let clean_main: ClassFile = parse_entry(&clean, MAIN_ENTRY);
    let obf_main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    assert_eq!(
        clean_main.fields.len(),
        2,
        "the clean program declares exactly two instance fields"
    );
    assert!(
        obf_main.fields.len() >= 10,
        "JBCO 'Embed Constants in Fields' must hoist numeric constants into many synthetic static fields, got {}",
        obf_main.fields.len()
    );
    let has_clinit: bool = obf_main.methods.iter().any(|m| {
        obf_main
            .utf8_at(m.name_index)
            .is_ok_and(|n| n == "<clinit>")
    });
    assert!(
        has_clinit,
        "JBCO constant embedding must inject a static initializer (<clinit>) absent from the clean class"
    );
    let clean_has_clinit: bool = clean_main.methods.iter().any(|m| {
        clean_main
            .utf8_at(m.name_index)
            .is_ok_and(|n| n == "<clinit>")
    });
    assert!(
        !clean_has_clinit,
        "the clean class has no static initializer; the <clinit> is a JBCO artifact"
    );
}

#[test]
fn every_clean_string_literal_recovered_verbatim_from_obf() {
    let clean: JarExtract = load(CLEAN_JAR);
    let obf: JarExtract = load(OBF_JAR);
    let clean_strings: BTreeSet<String> = string_literals(&parse_entry(&clean, MAIN_ENTRY));
    let obf_strings: BTreeSet<String> = string_literals(&parse_entry(&obf, MAIN_ENTRY));
    assert!(
        clean_strings.len() >= 5,
        "the clean program embeds at least 5 string literals, found {}",
        clean_strings.len()
    );
    let missing: Vec<&String> = clean_strings.difference(&obf_strings).collect();
    assert!(
        missing.is_empty(),
        "JBCO does not encrypt string literals; every clean string must survive verbatim, missing: {missing:?}"
    );
    assert!(
        obf_strings.contains("JBCO_GAUNTLET_BANNER v3"),
        "the banner literal must be recovered verbatim from the obfuscated class"
    );
    assert!(
        obf_strings.contains("DISROBE"),
        "the fold seed literal must be recovered verbatim from the obfuscated class"
    );
    for fragment in ["large:\u{1}", "medium:\u{1}", "small:\u{1}"] {
        assert!(
            obf_strings.contains(fragment),
            "classify concat fragment {fragment:?} must be recovered verbatim"
        );
    }
}

#[test]
fn original_identifiers_discarded_main_entrypoint_preserved() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let names: BTreeSet<String> = member_names(&main);
    for original in [
        "banner",
        "accumulate",
        "fold",
        "classify",
        "report",
        "counter",
        "checksum",
    ] {
        assert!(
            !names.contains(original),
            "JBCO renames non-exposed members irreversibly; {original:?} must not appear in the artifact"
        );
    }
    assert!(
        names.contains("main"),
        "the static main entrypoint name must be preserved by JBCO"
    );
    assert_eq!(
        main.this_class_name()
            .expect("this class")
            .rsplit('/')
            .next(),
        Some("Sample"),
        "the exposed class name survives JBCO"
    );
}

#[test]
fn renamed_members_are_jbco_dollar_digit_mangled() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let renamed_methods: usize = main
        .methods
        .iter()
        .filter(|m| main.utf8_at(m.name_index).is_ok_and(is_jbco_mangled))
        .count();
    assert!(
        renamed_methods >= 4,
        "the non-exposed methods must be renamed to JBCO dollar/digit/Il-soup identifiers, got {renamed_methods}"
    );
    let renamed_fields: usize = main
        .fields
        .iter()
        .filter(|f| main.utf8_at(f.name_index).is_ok_and(is_jbco_mangled))
        .count();
    assert!(
        renamed_fields >= 10,
        "the original fields plus the embedded-constant fields must all carry JBCO-mangled names, got {renamed_fields}"
    );
}

#[test]
fn clean_baseline_structure_is_canonical() {
    let clean: JarExtract = load(CLEAN_JAR);
    let main: ClassFile = parse_entry(&clean, MAIN_ENTRY);
    let dc: DecompiledClass = decompile_class(&main);
    assert_eq!(
        dc.method_count, 7,
        "clean Sample exposes ctor + banner + accumulate + fold + classify + report + main"
    );
    assert_eq!(dc.field_count, 2, "clean Sample exposes counter + checksum");
    let names: BTreeSet<String> = member_names(&main);
    for original in [
        "banner",
        "accumulate",
        "fold",
        "classify",
        "report",
        "counter",
        "checksum",
    ] {
        assert!(
            names.contains(original),
            "clean baseline must carry the original member name {original:?}"
        );
    }
}

#[test]
fn jbco_mangled_members_canonicalize_to_stable_slots() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let mut obfuscated_names: Vec<String> = Vec::new();
    for f in &main.fields {
        obfuscated_names.push(main.utf8_at(f.name_index).expect("field name").to_string());
    }
    for m in &main.methods {
        obfuscated_names.push(main.utf8_at(m.name_index).expect("method name").to_string());
    }
    let h: UnmappedHeuristics = heuristic_recover(&obfuscated_names);
    assert!(
        !h.mapped.is_empty(),
        "disrobe must canonicalize JBCO dollar/digit/Il-soup identifiers, names={obfuscated_names:?}"
    );
    let canonicalized: usize = obfuscated_names
        .iter()
        .filter(|n: &&String| is_jbco_mangled(n))
        .filter(|n: &&String| h.mapped.contains_key(*n))
        .count();
    let mangled_total: usize = obfuscated_names
        .iter()
        .filter(|n| is_jbco_mangled(n))
        .count();
    assert_eq!(
        canonicalized, mangled_total,
        "every JBCO-mangled member must receive a stable canonical slot, {canonicalized} of {mangled_total}"
    );
    for (raw, canonical) in &h.mapped {
        assert_ne!(
            raw, canonical,
            "a canonical slot must differ from the raw JBCO token"
        );
        assert!(
            canonical.starts_with("cls_")
                || canonical.starts_with("fn_")
                || canonical.starts_with("var_"),
            "JBCO canonical name must use a stable cls_/fn_/var_ slot, got {canonical}"
        );
    }
}
