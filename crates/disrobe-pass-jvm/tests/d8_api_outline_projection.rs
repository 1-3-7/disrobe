#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use disrobe_pass_jvm::bytecode::{Operands, disassemble, parse_code_attribute};
use disrobe_pass_jvm::classfile::{Attribute, ConstantPoolEntry, FieldInfo, MethodInfo};
use disrobe_pass_jvm::decompile::{ACC_STATIC, ACC_SYNTHETIC};
use disrobe_pass_jvm::{
    AndroidDecompileOutput, BackendPreference, ClassFile, Dex2JarResult, android_decompile_dex,
    decompile_class_with_inners, parse_classfile, translate_dex_bytes,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const COMPARATOR_DESCRIPTOR: &str = "(Ljava/util/function/ToIntFunction;)Ljava/util/Comparator;";

fn translated_classes() -> BTreeMap<String, ClassFile> {
    let translated: Dex2JarResult =
        translate_dex_bytes(EDGECASES_DEX).expect("translate the tracked D8 artifact");
    translated
        .jar_entries
        .iter()
        .filter_map(|(name, bytes): (&String, &Vec<u8>)| {
            parse_classfile(bytes)
                .ok()
                .map(|class: ClassFile| (name.clone(), class))
        })
        .collect()
}

fn comparator_method(class: &ClassFile) -> usize {
    class
        .methods
        .iter()
        .position(|method: &MethodInfo| {
            class.utf8_at(method.name_index).ok() == Some("m")
                && class.utf8_at(method.descriptor_index).ok() == Some(COMPARATOR_DESCRIPTOR)
        })
        .expect("tracked comparator outline")
}

fn code_attribute(class: &ClassFile, method: usize) -> usize {
    class.methods[method]
        .attributes
        .iter()
        .position(|attribute: &Attribute| class.utf8_at(attribute.name_index).ok() == Some("Code"))
        .expect("outline Code attribute")
}

fn recovered_with(classes: &BTreeMap<String, ClassFile>) -> String {
    let main: &ClassFile = classes.get("EdgeCases.class").expect("outer class");
    decompile_class_with_inners(main, classes).source
}

fn stable_of_body(source: &str) -> &str {
    let name: usize = source.find(" stableOf(").expect("stableOf method");
    let start: usize = source[..name]
        .rfind('\n')
        .map_or(0, |index: usize| index + 1);
    let tail: &str = &source[start..];
    let end: usize = tail.find("\n    }").expect("stableOf closing brace");
    &tail[..end]
}

fn assert_comparator_refused(classes: &BTreeMap<String, ClassFile>) {
    let source: String = recovered_with(classes);
    let body: &str = stable_of_body(&source);
    assert!(body.contains("EdgeCases$_0.m(arg0)"), "{body}");
    assert!(!body.contains("Comparator.comparingInt"), "{body}");
}

#[test]
fn verified_d8_api_outlines_project_to_their_jdk_calls() {
    let output: AndroidDecompileOutput =
        android_decompile_dex(EDGECASES_DEX, BackendPreference::PreferInHouse)
            .expect("decompile the tracked D8 artifact");
    let source: &str = output
        .sources
        .get("EdgeCases.java")
        .expect("recover the outer source unit");

    for expected in [
        "java.util.Map.of(",
        "java.util.List.of(",
        "java.util.Set.of(",
        "java.util.Comparator.comparingInt(",
        "java.util.Objects.nonNull(",
        "java.util.stream.IntStream.range(",
    ] {
        assert!(
            source.contains(expected),
            "the recovered source must project {expected}:\n{source}"
        );
    }
    assert_eq!(source.matches("java.util.Map.of(").count(), 1);
    assert_eq!(source.matches("java.util.List.of(").count(), 1);
    assert_eq!(source.matches("java.util.Set.of(").count(), 1);
    assert_eq!(
        source.matches("java.util.Comparator.comparingInt(").count(),
        1
    );
    assert_eq!(source.matches("java.util.Objects.nonNull(").count(), 1);
    assert_eq!(
        source.matches("java.util.stream.IntStream.range(").count(),
        1
    );
    assert!(source.contains("java.util.Objects.nonNull(arg0)"));
    assert!(source.contains("java.util.stream.IntStream.range(var1, arg0)"));
    assert!(source.contains("EdgeCases$_0.m(arg0, var1)"));
    assert!(source.contains("EdgeCases$_0.switchDispatch"));
}

#[test]
fn state_and_instance_behavior_refuse_the_entire_outline_class() {
    let mut with_field: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = with_field
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    outline.fields.push(FieldInfo {
        access_flags: 0,
        name_index: outline.methods[method].name_index,
        descriptor_index: outline.methods[method].descriptor_index,
        attributes: Vec::new(),
    });
    assert_comparator_refused(&with_field);

    let mut with_instance: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = with_instance
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    outline.methods[method].access_flags &= !ACC_STATIC;
    assert_comparator_refused(&with_instance);
}

#[test]
fn names_and_arities_do_not_admit_user_or_anonymous_classes() {
    let mut user_named: BTreeMap<String, ClassFile> = translated_classes();
    user_named
        .get_mut("EdgeCases$0.class")
        .expect("outline class")
        .access_flags &= !ACC_SYNTHETIC;
    assert_comparator_refused(&user_named);

    let mut anonymous_shape: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = anonymous_shape
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    let mut constructor: MethodInfo = outline.methods[method].clone();
    constructor.access_flags &= !ACC_STATIC;
    outline.methods.push(constructor);
    assert_comparator_refused(&anonymous_shape);
}

#[test]
fn altered_unresolved_exceptional_and_duplicate_helpers_refuse_projection() {
    let mut altered: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = altered.get_mut("EdgeCases$0.class").expect("outline class");
    let method: usize = comparator_method(outline);
    let attribute: usize = code_attribute(outline, method);
    outline.methods[method].attributes[attribute].info[8] = 0x01;
    assert_comparator_refused(&altered);

    let mut unresolved: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = unresolved
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    let attribute: usize = code_attribute(outline, method);
    outline.methods[method].attributes[attribute].info[10..12]
        .copy_from_slice(&u16::MAX.to_be_bytes());
    assert_comparator_refused(&unresolved);

    let mut exceptional: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = exceptional
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    let attribute: usize = code_attribute(outline, method);
    let info: &mut Vec<u8> = &mut outline.methods[method].attributes[attribute].info;
    let code_length: usize =
        u32::from_be_bytes(info[4..8].try_into().expect("code length")) as usize;
    let table: usize = 8 + code_length;
    info[table..table + 2].copy_from_slice(&1_u16.to_be_bytes());
    let end: u16 = u16::try_from(code_length).expect("small outline");
    info.splice(
        table + 2..table + 2,
        [0_u16, end, 0_u16, 0_u16]
            .into_iter()
            .flat_map(u16::to_be_bytes),
    );
    assert_comparator_refused(&exceptional);

    let mut duplicate: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = duplicate
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    outline.methods.push(outline.methods[method].clone());
    assert_comparator_refused(&duplicate);
}

#[test]
fn recursion_and_population_caps_refuse_projection() {
    let mut recursive: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = recursive
        .get_mut("EdgeCases$0.class")
        .expect("outline class");
    let method: usize = comparator_method(outline);
    let attribute: usize = code_attribute(outline, method);
    let parsed = parse_code_attribute(&outline.methods[method].attributes[attribute].info)
        .expect("parse comparator code");
    let instructions = disassemble(&parsed.code).expect("disassemble comparator code");
    let external_index: u16 = instructions
        .iter()
        .find_map(|instruction| match instruction.operands {
            Operands::ConstPool(index) if instruction.opcode == 0xb8 => Some(index),
            _ => None,
        })
        .expect("comparingInt call");
    let self_class_index: u16 = outline
        .constant_pool
        .iter()
        .enumerate()
        .find_map(|(index, entry): (usize, &ConstantPoolEntry)| {
            let index: u16 = u16::try_from(index).ok()?;
            matches!(entry, ConstantPoolEntry::Class { .. })
                .then(|| outline.class_name(index).ok())
                .flatten()
                .filter(|name: &&str| *name == "EdgeCases$0")
                .map(|_| index)
        })
        .expect("outline class constant");
    let name_index: u16 = u16::try_from(outline.constant_pool.len()).expect("small pool");
    outline
        .constant_pool
        .push(ConstantPoolEntry::Utf8("m".to_owned()));
    let descriptor_index: u16 = u16::try_from(outline.constant_pool.len()).expect("small pool");
    outline
        .constant_pool
        .push(ConstantPoolEntry::Utf8(COMPARATOR_DESCRIPTOR.to_owned()));
    let self_name_and_type_index: u16 =
        u16::try_from(outline.constant_pool.len()).expect("small pool");
    outline.constant_pool.push(ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    });
    let self_index: u16 = u16::try_from(outline.constant_pool.len()).expect("small pool");
    outline.constant_pool.push(ConstantPoolEntry::Methodref {
        class_index: self_class_index,
        name_and_type_index: self_name_and_type_index,
    });
    let info: &mut Vec<u8> = &mut outline.methods[method].attributes[attribute].info;
    let code = &mut info[8..];
    let pool_offset: usize = code
        .windows(3)
        .position(|window: &[u8]| window[0] == 0xb8 && window[1..] == external_index.to_be_bytes())
        .expect("invokestatic operand");
    code[pool_offset + 1..pool_offset + 3].copy_from_slice(&self_index.to_be_bytes());
    assert_comparator_refused(&recursive);

    let mut capped: BTreeMap<String, ClassFile> = translated_classes();
    let outline: &mut ClassFile = capped.get_mut("EdgeCases$0.class").expect("outline class");
    let method: usize = comparator_method(outline);
    let template: MethodInfo = outline.methods[method].clone();
    outline.methods.resize(513, template);
    assert_comparator_refused(&capped);
}
