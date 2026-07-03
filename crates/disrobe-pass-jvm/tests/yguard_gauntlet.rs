#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, DecompiledClass, JarExtract, UnmappedHeuristics, decompile_class,
    extract_jar, heuristic_recover, parse_classfile,
};

const CLEAN_JAR: &[u8] =
    include_bytes!("../../../corpus/jvm/obfuscators/yguard/Calculator-clean.jar");
const OBF_JAR: &[u8] = include_bytes!("../../../corpus/jvm/obfuscators/yguard/Calculator-obf.jar");

const MAIN_ENTRY: &str = "com/example/app/Calculator.class";
const CLEAN_INNER_ENTRY: &str = "com/example/app/Calculator$Ledger.class";
const OBF_INNER_ENTRY: &str = "com/example/app/Calculator$_A.class";

fn load(jar: &[u8]) -> JarExtract {
    extract_jar(jar).expect("extract yguard gauntlet jar")
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

fn all_string_literals(jx: &JarExtract) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (entry, bytes) in &jx.classes {
        let cf: ClassFile = parse_classfile(bytes).unwrap_or_else(|e| panic!("parse {entry}: {e}"));
        out.extend(string_literals(&cf));
    }
    out
}

fn leaf(name: &str) -> String {
    let after_slash: &str = name.rsplit('/').next().unwrap_or(name);
    after_slash
        .rsplit('$')
        .next()
        .unwrap_or(after_slash)
        .to_string()
}

#[test]
fn obf_jar_carries_yguard_manifest_fingerprint() {
    let jx: JarExtract = load(OBF_JAR);
    let manifest: &str = jx.manifest.as_deref().expect("obf jar manifest");
    assert!(
        manifest.contains("yGuard"),
        "obfuscated jar manifest must carry the yGuard Created-By fingerprint, got:\n{manifest}"
    );
    assert!(
        manifest.contains("Main-Class: com.example.app.Calculator"),
        "the kept main class entrypoint must survive in the manifest, got:\n{manifest}"
    );
}

#[test]
fn obf_jar_inner_class_was_renamed_main_class_kept() {
    let clean: JarExtract = load(CLEAN_JAR);
    let obf: JarExtract = load(OBF_JAR);
    assert!(
        clean.classes.contains_key(CLEAN_INNER_ENTRY),
        "clean jar must hold the original inner class Calculator$Ledger"
    );
    assert!(
        !obf.classes.contains_key(CLEAN_INNER_ENTRY),
        "yGuard must have renamed Calculator$Ledger away"
    );
    assert!(
        obf.classes.contains_key(OBF_INNER_ENTRY),
        "yGuard renamed the inner class to Calculator$_A, got {:?}",
        obf.classes.keys().collect::<Vec<&String>>()
    );
    assert!(
        obf.classes.contains_key(MAIN_ENTRY),
        "the exposed main class name must be preserved"
    );
}

#[test]
fn obf_members_are_short_mangled_identifiers() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let renamed_fields: usize = main
        .fields
        .iter()
        .filter(|f| {
            main.utf8_at(f.name_index)
                .is_ok_and(|n| n.len() <= 2 && n.chars().all(|c| c.is_ascii_uppercase()))
        })
        .count();
    assert!(
        renamed_fields >= 4,
        "all four Calculator fields must be renamed to short identifiers (A/B/C/D), got {renamed_fields}"
    );
    let renamed_methods: usize = main
        .methods
        .iter()
        .filter(|m| {
            main.utf8_at(m.name_index)
                .is_ok_and(|n| n.len() == 1 && n.chars().all(|c| c.is_ascii_uppercase()))
        })
        .count();
    assert!(
        renamed_methods >= 5,
        "the five non-exposed methods must be renamed to single-letter identifiers, got {renamed_methods}"
    );
}

#[test]
fn structure_recovered_two_classes_with_members() {
    let obf: JarExtract = load(OBF_JAR);
    assert_eq!(
        obf.classes.len(),
        2,
        "exactly two classes (main + inner) survive yGuard rename"
    );
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let main_dc: DecompiledClass = decompile_class(&main);
    assert!(
        main_dc.method_count >= 6,
        "Calculator decompile must recover ctor + banner + accumulate + fibonacci + describe + shutdown + main, got {}",
        main_dc.method_count
    );
    assert_eq!(
        main_dc.field_count, 4,
        "Calculator must expose 4 recovered fields"
    );
    assert!(
        !main_dc.source.is_empty(),
        "decompiled Calculator source must not be empty"
    );

    let inner: ClassFile = parse_entry(&obf, OBF_INNER_ENTRY);
    let inner_dc: DecompiledClass = decompile_class(&inner);
    assert!(
        inner_dc.method_count >= 3,
        "inner Ledger decompile must recover ctor + record + size + checksum, got {}",
        inner_dc.method_count
    );
    assert_eq!(
        inner_dc.field_count, 2,
        "inner Ledger must expose 2 recovered fields (count + checksum)"
    );
}

#[test]
fn every_clean_string_literal_recovered_from_obf_jar() {
    let clean: JarExtract = load(CLEAN_JAR);
    let obf: JarExtract = load(OBF_JAR);
    let clean_strings: BTreeSet<String> = all_string_literals(&clean);
    let obf_strings: BTreeSet<String> = all_string_literals(&obf);
    assert!(
        clean_strings.len() >= 9,
        "the clean program embeds at least 9 string literals, found {}",
        clean_strings.len()
    );
    let missing: Vec<&String> = clean_strings.difference(&obf_strings).collect();
    assert!(
        missing.is_empty(),
        "yGuard does not encrypt literals; every clean string must survive verbatim, missing: {missing:?}"
    );
    for exact in [
        "calc engine ready v7",
        "calc engine ready",
        "calc engine shutdown",
    ] {
        assert!(
            obf_strings.contains(exact),
            "plain string literal {exact:?} must be recovered verbatim from the obfuscated jar"
        );
    }
    for prefix in [
        "large:",
        "medium:",
        "small:",
        "accumulate(10)=",
        "fibonacci(12)=",
        "calc engine shutdown entries=",
    ] {
        assert!(
            obf_strings.iter().any(|s| s.starts_with(prefix)),
            "concat-fragment literal starting {prefix:?} must be recovered from the obfuscated jar"
        );
    }
}

#[test]
fn renamed_identifiers_canonicalize_via_heuristic() {
    let obf: JarExtract = load(OBF_JAR);
    let main: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let mut obfuscated_names: Vec<String> = Vec::new();
    for f in &main.fields {
        obfuscated_names.push(main.utf8_at(f.name_index).expect("field name").to_string());
    }
    for m in &main.methods {
        obfuscated_names.push(main.utf8_at(m.name_index).expect("method name").to_string());
    }
    let lowered: Vec<String> = obfuscated_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let h: UnmappedHeuristics = heuristic_recover(&lowered);
    assert!(
        !h.mapped.is_empty(),
        "the heuristic recoverer must canonicalize at least one short yGuard identifier, names={lowered:?}"
    );
    for (obfuscated, canonical) in &h.mapped {
        assert_ne!(
            obfuscated, canonical,
            "a canonical name must differ from the raw yGuard token"
        );
    }
}

#[test]
fn original_identifiers_are_not_recoverable_from_artifact() {
    let obf: JarExtract = load(OBF_JAR);
    let mut all_member_names: BTreeSet<String> = BTreeSet::new();
    for bytes in obf.classes.values() {
        let cf: ClassFile = parse_classfile(bytes).expect("parse obf class");
        for f in &cf.fields {
            all_member_names.insert(cf.utf8_at(f.name_index).expect("field name").to_string());
        }
        for m in &cf.methods {
            all_member_names.insert(cf.utf8_at(m.name_index).expect("method name").to_string());
        }
    }
    for original in [
        "banner",
        "accumulate",
        "fibonacci",
        "describe",
        "shutdown",
        "record",
    ] {
        assert!(
            !all_member_names.contains(original),
            "yGuard discards the original-name map; {original:?} must not appear in the artifact \
             (recovery canonicalizes names, it does not restore originals)"
        );
    }
    let main_class: ClassFile = parse_entry(&obf, MAIN_ENTRY);
    let main_leaf: String = leaf(main_class.this_class_name().expect("this"));
    assert_eq!(
        main_leaf, "Calculator",
        "only the exposed entrypoint keeps its original name"
    );
}
