#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, DecompiledClass, MethodInfo, decompile_classfile_bytes,
    parse_classfile,
};

const CALCULATOR: &[u8] = include_bytes!("../../../corpus/jvm/groovy/Calculator.class");

fn implements_interface(cf: &ClassFile, fqn: &str) -> bool {
    cf.interfaces
        .iter()
        .any(|idx: &u16| cf.class_name(*idx).is_ok_and(|n: &str| n == fqn))
}

#[test]
fn groovy_class_parses_and_is_recognisably_groovy() {
    let cf: ClassFile = parse_classfile(CALCULATOR).expect("parse groovyc Calculator.class");
    assert_eq!(
        cf.this_class_name().expect("this_class"),
        "disrobe/sample/Calculator"
    );
    assert!(
        implements_interface(&cf, "groovy/lang/GroovyObject"),
        "a real groovyc class implements groovy.lang.GroovyObject"
    );
    let has_groovy_constant: bool = cf.constant_pool.iter().any(|e: &ConstantPoolEntry| {
        matches!(e, ConstantPoolEntry::Utf8(s) if s.contains("groovy/lang/MetaClass"))
    });
    assert!(
        has_groovy_constant,
        "groovyc weaves a groovy.lang.MetaClass reference into every class"
    );
}

#[test]
fn groovy_class_decompiles_via_in_house_decoder() {
    let decompiled: DecompiledClass =
        decompile_classfile_bytes(CALCULATOR).expect("in-house decompile of groovy class");
    let src: &str = &decompiled.source;
    assert!(
        src.contains("class Calculator"),
        "decompiled source must name the class:\n{src}"
    );
    let cf: ClassFile = parse_classfile(CALCULATOR).expect("parse");
    let method_names: Vec<&str> = cf
        .methods
        .iter()
        .filter_map(|m: &MethodInfo| cf.utf8_at(m.name_index).ok())
        .collect::<Vec<&str>>();
    assert!(
        method_names.contains(&"addTo"),
        "addTo(int) must survive: {method_names:?}"
    );
    assert!(
        method_names.contains(&"describe"),
        "describe() must survive: {method_names:?}"
    );
    assert!(
        decompiled.method_count >= 2,
        "at least the two user methods are counted: {}",
        decompiled.method_count
    );
}
