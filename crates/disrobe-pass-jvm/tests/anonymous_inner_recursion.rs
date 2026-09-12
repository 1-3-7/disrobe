#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use disrobe_pass_jvm::{
    ClassFile, DecompiledClass, Dex2JarResult, decompile_class_with_inners, parse_classfile,
    translate_dex_bytes,
};

const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

fn translated_classes(dex_bytes: &[u8]) -> BTreeMap<String, ClassFile> {
    let translated: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate the dex");
    let mut classes: BTreeMap<String, ClassFile> = BTreeMap::new();
    for (name, bytes) in &translated.jar_entries {
        if let Ok(parsed) = parse_classfile(bytes) {
            classes.insert(name.clone(), parsed);
        }
    }
    classes
}

fn anonymous(entry_name: &str) -> bool {
    entry_name
        .trim_end_matches(".class")
        .rsplit('$')
        .next()
        .is_some_and(|tail: &str| !tail.is_empty() && tail.bytes().all(|b: u8| b.is_ascii_digit()))
}

#[test]
fn a_class_whose_anonymous_inners_reference_each_other_still_renders() {
    let classes: BTreeMap<String, ClassFile> = translated_classes(EDGECASES_KT_DEX);
    let (_name, main): (&String, &ClassFile) = classes
        .iter()
        .find(|(name, _)| name.ends_with("EdgeCasesKt.class") && !name.contains('$'))
        .expect("the kotlin fixture carries a main class");
    let anon: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(name, _)| anonymous(name))
        .map(|(name, class)| (name.clone(), class.clone()))
        .collect();
    assert!(
        anon.len() > 1,
        "this fixture has to carry several anonymous inner classes for the check to mean anything, \
         found {}",
        anon.len()
    );

    let rendered: DecompiledClass = decompile_class_with_inners(main, &anon);

    assert!(
        !rendered.source.is_empty(),
        "inlining an anonymous class body must terminate and produce source. Before the inline \
         depth and revisit guard existed, these {} anonymous classes drove the renderer into \
         unbounded recursion and the process died on a stack overflow, which no caller can catch",
        anon.len()
    );
    assert!(
        rendered.source.contains("class EdgeCasesKt"),
        "the rendered unit still has to be the main class"
    );
}

#[test]
fn inlining_anonymous_bodies_adds_source_rather_than_replacing_it() {
    let classes: BTreeMap<String, ClassFile> = translated_classes(EDGECASES_KT_DEX);
    let (_name, main): (&String, &ClassFile) = classes
        .iter()
        .find(|(name, _)| name.ends_with("EdgeCasesKt.class") && !name.contains('$'))
        .expect("the kotlin fixture carries a main class");
    let anon: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(name, _)| anonymous(name))
        .map(|(name, class)| (name.clone(), class.clone()))
        .collect();
    let empty: BTreeMap<String, ClassFile> = BTreeMap::new();

    let without: DecompiledClass = decompile_class_with_inners(main, &empty);
    let with: DecompiledClass = decompile_class_with_inners(main, &anon);

    assert!(
        with.source.len() > without.source.len(),
        "the guard bounds the recursion; it must not switch inlining off, or every anonymous body \
         would silently collapse to a constructor call. Without inners {} bytes, with {} bytes",
        without.source.len(),
        with.source.len()
    );
}
