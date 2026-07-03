#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]
use std::collections::BTreeMap;

use disrobe_pass_jvm::{
    ClassFile, FingerprintReport, JarExtract, LibrarySignatureSet, ProguardMapping, extract_jar,
    fingerprint_library_symbols, parse_classfile, parse_proguard_mapping,
};

const LIB_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard_libfp/stringkit-lib.jar");
const OBF_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard_libfp/app-obf.jar");
const OBF_OPT_JAR: &[u8] = include_bytes!("../../../corpus/jvm/proguard_libfp/app-obf-opt.jar");
const MAPPING: &str = include_str!("../../../corpus/jvm/proguard_libfp/ground-truth-mapping.txt");
const MAPPING_OPT: &str =
    include_str!("../../../corpus/jvm/proguard_libfp/ground-truth-mapping-opt.txt");

fn load_classes(jar: &[u8]) -> Vec<ClassFile> {
    let jx: JarExtract = extract_jar(jar).expect("extract jar");
    let mut out: Vec<ClassFile> = Vec::new();
    for (name, bytes) in &jx.classes {
        if name.ends_with(".class") {
            out.push(parse_classfile(bytes).expect("parse classfile"));
        }
    }
    out
}

fn class_truth(mapping_txt: &str) -> BTreeMap<String, String> {
    let mapping: ProguardMapping = parse_proguard_mapping(mapping_txt).expect("parse mapping");
    let mut truth: BTreeMap<String, String> = BTreeMap::new();
    for (obf, cls) in &mapping.classes {
        truth.insert(obf.replace('.', "/"), cls.original_name.replace('.', "/"));
    }
    truth
}

fn descriptor_params(descriptor: &str) -> String {
    let open: usize = descriptor.find('(').map_or(0, |i: usize| i + 1);
    let close: usize = descriptor.find(')').unwrap_or(descriptor.len());
    descriptor.get(open..close).unwrap_or("").to_owned()
}

fn method_truth(mapping_txt: &str) -> BTreeMap<(String, String, String), String> {
    let mapping: ProguardMapping = parse_proguard_mapping(mapping_txt).expect("parse mapping");
    let mut truth: BTreeMap<(String, String, String), String> = BTreeMap::new();
    for (obf_class, cls) in &mapping.classes {
        let obf_internal: String = obf_class.replace('.', "/");
        for (obf_method, overloads) in &cls.methods {
            for m in overloads {
                truth.insert(
                    (
                        obf_internal.clone(),
                        obf_method.clone(),
                        m.descriptor_params.clone(),
                    ),
                    m.original_name.clone(),
                );
            }
        }
    }
    truth
}

#[test]
fn reidentifies_all_library_classes_without_a_mapping() {
    let library: LibrarySignatureSet = LibrarySignatureSet::from_classfiles(&load_classes(LIB_JAR));
    let obf: Vec<ClassFile> = load_classes(OBF_JAR);
    let report: FingerprintReport = fingerprint_library_symbols(&obf, &library);
    let truth: BTreeMap<String, String> = class_truth(MAPPING);

    assert_eq!(
        report.class_count(),
        3,
        "expected all three library classes re-identified, got {}",
        report.class_count()
    );
    for c in &report.classes {
        let expected: &String = truth
            .get(&c.obfuscated_name)
            .unwrap_or_else(|| panic!("no ground truth for obf class {}", c.obfuscated_name));
        assert_eq!(
            &c.original_name, expected,
            "class {} re-identified as {} but ground truth is {}",
            c.obfuscated_name, c.original_name, expected
        );
    }
    let names: Vec<&str> = report
        .classes
        .iter()
        .map(|c| c.original_name.as_str())
        .collect();
    assert!(names.contains(&"com/acme/stringkit/StringKit"));
    assert!(names.contains(&"com/acme/stringkit/CaseFormat"));
    assert!(names.contains(&"com/acme/stringkit/Hashing"));
}

#[test]
fn reidentified_methods_match_ground_truth_mapping() {
    let library: LibrarySignatureSet = LibrarySignatureSet::from_classfiles(&load_classes(LIB_JAR));
    let obf: Vec<ClassFile> = load_classes(OBF_JAR);
    let report: FingerprintReport = fingerprint_library_symbols(&obf, &library);
    let m_truth: BTreeMap<(String, String, String), String> = method_truth(MAPPING);

    let mut checked: usize = 0;
    for c in &report.classes {
        let simple_orig: &str = c
            .original_name
            .rsplit('/')
            .next()
            .unwrap_or(&c.original_name);
        for m in &c.methods {
            let key: (String, String, String) = (
                c.obfuscated_name.clone(),
                m.obfuscated_name.clone(),
                descriptor_params(&m.descriptor),
            );
            let expected: &String = m_truth.get(&key).unwrap_or_else(|| {
                panic!(
                    "no ground-truth method for {}.{}{}",
                    c.obfuscated_name, m.obfuscated_name, m.descriptor
                )
            });
            assert_eq!(
                &m.original_name,
                expected,
                "method {}.{}{} re-identified as {} but ground truth is {} (class {})",
                c.obfuscated_name,
                m.obfuscated_name,
                m.descriptor,
                m.original_name,
                expected,
                simple_orig
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "expected all ten library methods re-identified, got {checked}"
    );
}

#[test]
fn survives_proguard_optimization_pass() {
    let library: LibrarySignatureSet = LibrarySignatureSet::from_classfiles(&load_classes(LIB_JAR));
    let obf: Vec<ClassFile> = load_classes(OBF_OPT_JAR);
    let report: FingerprintReport = fingerprint_library_symbols(&obf, &library);
    let truth: BTreeMap<String, String> = class_truth(MAPPING_OPT);

    assert_eq!(
        report.class_count(),
        3,
        "expected all three library classes re-identified under optimization, got {}",
        report.class_count()
    );
    for c in &report.classes {
        let expected: &String = truth
            .get(&c.obfuscated_name)
            .unwrap_or_else(|| panic!("no ground truth for obf class {}", c.obfuscated_name));
        assert_eq!(&c.original_name, expected);
    }

    let m_truth: BTreeMap<(String, String, String), String> = method_truth(MAPPING_OPT);
    let mut recovered: usize = 0;
    for c in &report.classes {
        for m in &c.methods {
            let key: (String, String, String) = (
                c.obfuscated_name.clone(),
                m.obfuscated_name.clone(),
                descriptor_params(&m.descriptor),
            );
            let expected: &String = m_truth.get(&key).expect("ground-truth method present");
            assert_eq!(
                &m.original_name, expected,
                "optimized method {}.{}{} re-identified as {} but truth is {}",
                c.obfuscated_name, m.obfuscated_name, m.descriptor, m.original_name, expected
            );
            recovered += 1;
        }
    }
    assert!(
        recovered >= 6,
        "expected several signature-preserving methods recovered under optimization, got {recovered}"
    );
}

#[test]
fn no_false_positives_against_empty_library() {
    let empty: LibrarySignatureSet = LibrarySignatureSet::default();
    let obf: Vec<ClassFile> = load_classes(OBF_JAR);
    let report: FingerprintReport = fingerprint_library_symbols(&obf, &empty);
    assert_eq!(report.class_count(), 0);
    assert_eq!(report.method_count(), 0);
}

#[test]
fn application_class_is_not_mislabeled_as_a_library_class() {
    let library: LibrarySignatureSet = LibrarySignatureSet::from_classfiles(&load_classes(LIB_JAR));
    let app_only: Vec<ClassFile> = load_classes(OBF_JAR)
        .into_iter()
        .filter(|cf: &ClassFile| cf.this_class_name().is_ok_and(|n: &str| n == "app/App"))
        .collect();
    assert_eq!(app_only.len(), 1, "expected the app.App class present");
    let report: FingerprintReport = fingerprint_library_symbols(&app_only, &library);
    assert_eq!(
        report.class_count(),
        0,
        "the application class must not be re-identified as a stringkit library class, got {:?}",
        report
            .classes
            .iter()
            .map(|c| (c.obfuscated_name.as_str(), c.original_name.as_str()))
            .collect::<Vec<_>>()
    );
}
