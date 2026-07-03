#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};
use disrobe_pass_jvm::{
    DexFile, JniSurfaceReport, ResolvedNative, analyze_jni_surface, extract_native_methods,
    parse_dex,
};
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

const ACC_PUBLIC_NATIVE: u32 = 0x0001 | 0x0100;
const ACC_STATIC_NATIVE: u32 = 0x0008 | 0x0100;

fn native_method(name: &str, params: Vec<String>, ret: &str, flags: u32) -> EncodedMethod {
    EncodedMethod {
        method: MethodRef {
            class: "Lcom/disrobe/fixture/NativeProbe;".to_owned(),
            proto: ProtoRef {
                return_type: ret.to_owned(),
                params,
            },
            name: name.to_owned(),
        },
        access_flags: flags,
        is_direct: false,
        registers_size: 0,
        ins_size: 0,
        outs_size: 0,
        insns: Vec::new(),
        relocations: Vec::new(),
    }
}

fn build_native_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/fixture/NativeProbe;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![
            native_method(
                "compute",
                vec!["I".to_owned(), "Ljava/lang/String;".to_owned()],
                "I",
                ACC_PUBLIC_NATIVE,
            ),
            native_method("simple", Vec::new(), "V", ACC_PUBLIC_NATIVE),
            native_method(
                "with_underscore",
                vec!["[J".to_owned()],
                "J",
                ACC_STATIC_NATIVE,
            ),
            native_method("overloaded", vec!["I".to_owned()], "I", ACC_PUBLIC_NATIVE),
            native_method(
                "overloaded",
                vec!["Ljava/lang/String;".to_owned()],
                "I",
                ACC_PUBLIC_NATIVE,
            ),
        ],
    });
    builder.build()
}

fn build_jni_so(exports: &[&str]) -> Vec<u8> {
    let mut obj: Object = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    for (i, name) in exports.iter().enumerate() {
        let offset: u64 = obj.append_section_data(text, &[0x1f, 0x20, 0x03, 0xd5], 4);
        let _ = offset;
        obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: (i as u64) * 4,
            size: 4,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    obj.write().expect("write elf .so")
}

#[test]
fn dex_native_methods_extracted_with_correct_jni_mangling() {
    let dex_bytes: Vec<u8> = build_native_dex();
    let dex: DexFile = parse_dex(&dex_bytes).expect("parse synthetic dex");
    let natives = extract_native_methods(&dex, &dex_bytes);
    assert_eq!(natives.len(), 5, "five native methods declared");

    let by_short: std::collections::BTreeMap<String, String> = natives
        .iter()
        .map(|n| (n.method.clone(), n.jni_short_symbol.clone()))
        .collect();
    assert_eq!(
        by_short.get("compute").map(String::as_str),
        Some("Java_com_disrobe_fixture_NativeProbe_compute"),
        "short JNI symbol matches javac -h output"
    );

    let with_underscore = natives
        .iter()
        .find(|n| n.method == "with_underscore")
        .expect("static native present");
    assert_eq!(
        with_underscore.jni_short_symbol, "Java_com_disrobe_fixture_NativeProbe_with_1underscore",
        "underscore mangles to _1 (matches javac -h)"
    );

    let overloaded_int = natives
        .iter()
        .find(|n| n.method == "overloaded" && n.descriptor == "(I)I")
        .expect("overloaded(int) present");
    assert_eq!(
        overloaded_int.jni_long_symbol, "Java_com_disrobe_fixture_NativeProbe_overloaded__I",
        "long JNI symbol for overloaded(int) matches javac -h"
    );
    let overloaded_str = natives
        .iter()
        .find(|n| n.method == "overloaded" && n.descriptor == "(Ljava/lang/String;)I")
        .expect("overloaded(String) present");
    assert_eq!(
        overloaded_str.jni_long_symbol,
        "Java_com_disrobe_fixture_NativeProbe_overloaded__Ljava_lang_String_2",
        "long JNI symbol for overloaded(String) matches javac -h"
    );
}

#[test]
fn jni_methods_correlate_to_real_so_exports() {
    let dex_bytes: Vec<u8> = build_native_dex();
    let dex: DexFile = parse_dex(&dex_bytes).expect("parse synthetic dex");

    let so_bytes: Vec<u8> = build_jni_so(&[
        "Java_com_disrobe_fixture_NativeProbe_compute",
        "Java_com_disrobe_fixture_NativeProbe_overloaded__I",
        "JNI_OnLoad",
    ]);
    assert!(
        disrobe_binfmt::parse_native(&so_bytes).is_ok(),
        "the authored .so is a real parseable ELF"
    );

    let report: JniSurfaceReport = analyze_jni_surface(
        &[("classes.dex", &dex, dex_bytes.as_slice())],
        &[("lib/arm64-v8a/libnative.so", so_bytes.as_slice())],
    );

    assert_eq!(report.native_method_count, 5);
    assert_eq!(report.libraries.len(), 1, "one native library parsed");
    let lib = &report.libraries[0];
    assert_eq!(lib.abi.as_deref(), Some("arm64-v8a"));
    assert_eq!(lib.jni_exports.len(), 2, "two Java_ exports filtered");

    let compute: &ResolvedNative = report
        .native_methods
        .iter()
        .find(|m| m.method == "compute")
        .expect("compute method");
    assert_eq!(
        compute.resolved_in.as_deref(),
        Some("lib/arm64-v8a/libnative.so"),
        "compute resolves to the real .so via its short JNI symbol"
    );

    let overloaded_int: &ResolvedNative = report
        .native_methods
        .iter()
        .find(|m| m.method == "overloaded" && m.descriptor == "(I)I")
        .expect("overloaded(int)");
    assert_eq!(
        overloaded_int.resolved_in.as_deref(),
        Some("lib/arm64-v8a/libnative.so"),
        "overloaded(int) resolves via its long (arg-mangled) symbol"
    );

    let simple: &ResolvedNative = report
        .native_methods
        .iter()
        .find(|m| m.method == "simple")
        .expect("simple");
    assert_eq!(
        simple.resolved_in, None,
        "simple() is dynamically registered (not a static export) -> unresolved"
    );

    assert_eq!(report.resolved_statically, 2);
    assert_eq!(report.dynamic_only, 3);
}
