#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const ITEM_INTEGER: u8 = 1;
const ITEM_NULL: u8 = 5;
const ITEM_OBJECT: u8 = 7;

fn object_init() -> MethodRef {
    MethodRef {
        class: "Ljava/lang/Object;".to_owned(),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: Vec::new(),
        },
        name: "<init>".to_owned(),
    }
}

fn sample_ctor() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt35c_one(0x70, 0, 0));
    relocs.push(Reloc::MethodIndex {
        unit: 1,
        method: object_init(),
    });
    units.extend(insn::fmt10x(0x0E));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: Vec::new(),
            },
            name: "<init>".to_owned(),
        },
        access_flags: 0x1,
        is_direct: true,
        registers_size: 1,
        ins_size: 1,
        outs_size: 1,
        insns: units,
        relocations: relocs,
    }
}

fn pick_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocs: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 0));
    units.push(0x38 | (2u16 << 8));
    units.push(5);
    units.extend(insn::fmt21c(0x1A, 0, 0));
    relocs.push(Reloc::StringIndex {
        unit: 4,
        value: "picked".to_owned(),
    });
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.extend(insn::fmt11x(0x11, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/String;".to_owned(),
                params: vec!["I".to_owned()],
            },
            name: "pick".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: relocs,
    }
}

fn count_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 0));
    units.push(0x38 | (2u16 << 8));
    units.push(4);
    units.extend(insn::fmt11n(0x12, 0, 7));
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt11n(0x12, 1, 1));
    units.extend(insn::fmt11x(0x0F, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "I".to_owned(),
                params: vec!["I".to_owned()],
            },
            name: "count".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn single_or_null_method() -> EncodedMethod {
    let value_of: MethodRef = MethodRef {
        class: "Ljava/lang/Byte;".to_owned(),
        proto: ProtoRef {
            return_type: "Ljava/lang/Byte;".to_owned(),
            params: vec!["B".to_owned()],
        },
        name: "valueOf".to_owned(),
    };
    let test: MethodRef = MethodRef {
        class: "Ljava/util/function/Predicate;".to_owned(),
        proto: ProtoRef {
            return_type: "Z".to_owned(),
            params: vec!["Ljava/lang/Object;".to_owned()],
        },
        name: "test".to_owned(),
    };
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(0x21, 0, 7));
    units.extend(insn::fmt11n(0x12, 1, 0));
    units.extend(insn::fmt11n(0x12, 2, 0));
    units.extend(insn::fmt12x(0x07, 4, 2));
    units.extend(insn::fmt11n(0x12, 3, 0));
    units.extend(insn::fmt22t(0x35, 1, 0, 25));
    units.extend(insn::fmt23x(0x48, 5, 7, 1));
    units.extend(insn::fmt35c_one(0x71, 5, 0));
    units.extend(insn::fmt11x(0x0C, 6));
    units.extend(insn::fmt35c_two(0x72, 8, 6, 0));
    units.extend(insn::fmt11x(0x0A, 6));
    units.extend([0x0638, 10]);
    units.extend([0x0338, 3]);
    units.extend(insn::fmt11x(0x11, 2));
    units.extend(insn::fmt35c_one(0x71, 5, 0));
    units.extend(insn::fmt11x(0x0C, 4));
    units.extend(insn::fmt11n(0x12, 3, 1));
    units.extend(insn::fmt22b(0xD8, 1, 1, 1));
    units.push(0xE828);
    units.extend([0x0339, 3]);
    units.extend(insn::fmt11x(0x11, 2));
    units.extend(insn::fmt11x(0x11, 4));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/Byte;".to_owned(),
                params: vec!["[B".to_owned(), "Ljava/util/function/Predicate;".to_owned()],
            },
            name: "singleOrNull".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 9,
        ins_size: 2,
        outs_size: 2,
        insns: units,
        relocations: vec![
            Reloc::MethodIndex {
                unit: 10,
                method: value_of.clone(),
            },
            Reloc::MethodIndex {
                unit: 14,
                method: test,
            },
            Reloc::MethodIndex {
                unit: 23,
                method: value_of,
            },
        ],
    }
}

fn cast_split_method() -> EncodedMethod {
    let mut units: Vec<u16> = vec![0x0238, 5];
    units.extend(insn::fmt21c(0x1A, 2, 0));
    units.push(0x0628);
    units.extend(insn::fmt21c(0x1A, 0, 0));
    units.extend(insn::fmt12x(0x07, 2, 0));
    units.extend(insn::fmt21c(0x1F, 2, 0));
    units.extend(insn::fmt11x(0x11, 2));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/CharSequence;".to_owned(),
                params: vec!["I".to_owned()],
            },
            name: "castSplit".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 3,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: vec![
            Reloc::StringIndex {
                unit: 3,
                value: "left".to_owned(),
            },
            Reloc::StringIndex {
                unit: 6,
                value: "right".to_owned(),
            },
            Reloc::TypeIndex {
                unit: 9,
                descriptor: "Ljava/lang/CharSequence;".to_owned(),
            },
        ],
    }
}

fn make_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            sample_ctor(),
            pick_method(),
            count_method(),
            branched_constant_return("empty", 0),
            single_or_null_method(),
            cast_split_method(),
        ],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn branched_constant_return(name: &str, value: i8) -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, value));
    units.push(0x28 | (1u16 << 8));
    units.extend(insn::fmt11x(0x11, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: "LSample;".to_owned(),
            proto: ProtoRef {
                return_type: "Ljava/lang/String;".to_owned(),
                params: Vec::new(),
            },
            name: name.to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: 1,
        ins_size: 0,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn boxed_float_methods() -> Vec<EncodedMethod> {
    let value_of: MethodRef = MethodRef {
        class: "Ljava/lang/Float;".to_owned(),
        proto: ProtoRef {
            return_type: "Ljava/lang/Float;".to_owned(),
            params: vec!["F".to_owned()],
        },
        name: "valueOf".to_owned(),
    };
    let mut nullable: Vec<u16> = vec![0x0139, 4, 0x0012, 0x0928];
    nullable.extend(insn::fmt35c_one(0x71, 0, 0));
    nullable.extend(insn::fmt11x(0x0A, 0));
    nullable.extend(insn::fmt35c_one(0x71, 0, 0));
    nullable.extend(insn::fmt11x(0x0C, 0));
    nullable.extend(insn::fmt11x(0x11, 0));
    let mut constant: Vec<u16> = insn::fmt21s(0x15, 0, 0x4020);
    constant.extend(insn::fmt35c_one(0x71, 0, 0));
    constant.extend(insn::fmt11x(0x0C, 0));
    constant.extend(insn::fmt11x(0x11, 0));
    vec![
        EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "LBoxedFloats;".to_owned(),
                proto: ProtoRef {
                    return_type: "Ljava/lang/Float;".to_owned(),
                    params: vec!["Ljava/lang/String;".to_owned(), "I".to_owned()],
                },
                name: "pick".to_owned(),
            },
            access_flags: 0x9,
            is_direct: true,
            registers_size: 2,
            ins_size: 2,
            outs_size: 1,
            insns: nullable,
            relocations: vec![
                Reloc::MethodIndex {
                    unit: 5,
                    method: MethodRef {
                        class: "Ljava/lang/Float;".to_owned(),
                        proto: ProtoRef {
                            return_type: "F".to_owned(),
                            params: vec!["Ljava/lang/String;".to_owned()],
                        },
                        name: "parseFloat".to_owned(),
                    },
                },
                Reloc::MethodIndex {
                    unit: 9,
                    method: value_of.clone(),
                },
            ],
        },
        EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "LBoxedFloats;".to_owned(),
                proto: ProtoRef {
                    return_type: "Ljava/lang/Float;".to_owned(),
                    params: Vec::new(),
                },
                name: "constant".to_owned(),
            },
            access_flags: 0x9,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 1,
            insns: constant,
            relocations: vec![Reloc::MethodIndex {
                unit: 3,
                method: value_of,
            }],
        },
    ]
}

fn boxed_float_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LBoxedFloats;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: boxed_float_methods(),
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn make_reference_return_mismatch_dex() -> Vec<u8> {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 1));
    units.push(0x38);
    units.push(3);
    units.extend(insn::fmt11n(0x12, 0, 2));
    units.extend(insn::fmt11x(0x11, 0));
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LReferenceReturnMismatch;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "LReferenceReturnMismatch;".to_owned(),
                proto: ProtoRef {
                    return_type: "Ljava/lang/String;".to_owned(),
                    params: Vec::new(),
                },
                name: "bad".to_owned(),
            },
            access_flags: 0x9,
            is_direct: true,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: units,
            relocations: Vec::new(),
        }],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn cp_utf8(cf: &ClassFile, idx: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(idx)) {
        Some(ConstantPoolEntry::Utf8(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn stack_map_body(cf: &ClassFile, method_name: &str) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some(method_name))
        .unwrap_or_else(|| panic!("{method_name} present"));
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .unwrap_or_else(|| panic!("{method_name} has Code"));
    let info: &[u8] = &code.info;
    let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    let mut o: usize = 8 + code_len;
    let exc_len: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2 + exc_len * 8;
    let attr_count: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2;
    for _ in 0..attr_count {
        let name_idx: u16 = u16::from_be_bytes([info[o], info[o + 1]]);
        let len: usize =
            u32::from_be_bytes([info[o + 2], info[o + 3], info[o + 4], info[o + 5]]) as usize;
        let body_start: usize = o + 6;
        if cp_utf8(cf, name_idx) == Some("StackMapTable") {
            return info[body_start..body_start + len].to_vec();
        }
        o = body_start + len;
    }
    panic!("{method_name} has no StackMapTable attribute");
}

fn local_tags(body: &[u8]) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut o: usize = 0;
    let entries: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    for _ in 0..entries {
        let frame_type: u8 = body[o];
        o += 1;
        assert_eq!(frame_type, 255, "the lifter emits full_frame frames only");
        o += 2;
        let num_locals: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        let mut tags: Vec<u8> = Vec::with_capacity(num_locals);
        for _ in 0..num_locals {
            let tag: u8 = body[o];
            o += 1;
            tags.push(tag);
            if tag == ITEM_OBJECT || tag == 8 {
                o += 2;
            }
        }
        frames.push(tags);
        let num_stack: usize = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        o += 2;
        for _ in 0..num_stack {
            let tag: u8 = body[o];
            o += 1;
            if tag == ITEM_OBJECT || tag == 8 {
                o += 2;
            }
        }
    }
    frames
}

fn sample_class() -> ClassFile {
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present in translation");
    parse_classfile(sample).expect("parse Sample.class")
}

#[test]
fn a_nonzero_integer_cannot_be_recovered_as_a_null_reference_return() {
    let result: Dex2JarResult = translate_dex_bytes(&make_reference_return_mismatch_dex())
        .expect("translate crafted mismatch dex");
    assert_eq!(result.bodies_recovered, 0);
    assert_eq!(result.stubbed_body_count, 1);
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.class == "ReferenceReturnMismatch"
                && diagnostic.method.as_deref() == Some("bad()Ljava/lang/String;")
                && diagnostic.reason
                    == "DR-JVM-0093: control-flow JVM emitter refusal: \
                        reference-return-type-mismatch"
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn a_persistent_null_reference_survives_the_single_or_null_loop() {
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    assert_eq!(result.bodies_recovered, 6, "{:?}", result.diagnostics);
    assert_eq!(result.stubbed_body_count, 0, "{:?}", result.diagnostics);
}

#[test]
fn an_in_place_reference_cast_preserves_a_split_parameter_at_the_join() {
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    assert_eq!(result.bodies_recovered, 6, "{:?}", result.diagnostics);
    assert_eq!(result.stubbed_body_count, 0, "{:?}", result.diagnostics);
}

#[test]
fn a_zero_reference_return_survives_an_unconditional_branch() {
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate branched null");
    assert_eq!(result.bodies_recovered, 6, "{:?}", result.diagnostics);
    assert_eq!(result.stubbed_body_count, 0);
    let cf: ClassFile = parse_classfile(&result.jar_entries["Sample.class"]).expect("parse Sample");
    let method: &disrobe_pass_jvm::MethodInfo = cf
        .methods
        .iter()
        .find(|method| cp_utf8(&cf, method.name_index) == Some("empty"))
        .expect("empty method");
    let attribute: &disrobe_pass_jvm::Attribute = method
        .attributes
        .iter()
        .find(|attribute| cp_utf8(&cf, attribute.name_index) == Some("Code"))
        .expect("empty method body");
    let code: disrobe_pass_jvm::CodeAttribute =
        disrobe_pass_jvm::parse_code_attribute(&attribute.info).expect("parse method code");
    let instructions: Vec<disrobe_pass_jvm::Instruction> =
        disrobe_pass_jvm::disassemble(&code.code).expect("disassemble method code");
    let opcodes: Vec<u8> = instructions
        .iter()
        .map(|instruction| instruction.opcode)
        .collect();
    assert!(opcodes.ends_with(&[0x01, 0xB0]), "{opcodes:?}");
}

#[test]
fn a_nonzero_reference_return_stays_refused_after_an_unconditional_branch() {
    assert_reference_return_refused(branched_constant_return("bad", 1));
}

#[test]
fn a_null_return_is_not_a_float_constant_when_its_register_is_reused_for_boxing() {
    let result: Dex2JarResult =
        translate_dex_bytes(&boxed_float_dex()).expect("translate boxed floats");
    assert_eq!(result.bodies_recovered, 2, "{:?}", result.diagnostics);
    assert_eq!(result.stubbed_body_count, 0);
}

#[test]
fn an_arithmetic_zero_cannot_be_recovered_as_a_null_reference_return() {
    let mut method: EncodedMethod = branched_constant_return("bad", 1);
    method.insns.insert(1, 0x00B1);
    assert_reference_return_refused(method);
}

#[test]
fn a_constant_used_as_both_float_and_reference_is_refused_in_either_branch_order() {
    let value_of: MethodRef = MethodRef {
        class: "Ljava/lang/Float;".to_owned(),
        proto: ProtoRef {
            return_type: "Ljava/lang/Float;".to_owned(),
            params: vec!["F".to_owned()],
        },
        name: "valueOf".to_owned(),
    };
    let mut float_first: Vec<u16> = vec![0x0012, 0x0138, 7];
    float_first.extend(insn::fmt35c_one(0x71, 0, 0));
    float_first.extend([0x000C, 0x0011, 0x0011]);
    let mut null_first: Vec<u16> = vec![0x0012, 0x0138, 3, 0x0011];
    null_first.extend(insn::fmt35c_one(0x71, 0, 0));
    null_first.extend([0x000C, 0x0011]);
    let mut sequential: Vec<u16> = vec![0x0012, 0x0128];
    sequential.extend(insn::fmt35c_one(0x71, 0, 0));
    sequential.extend([0x010C, 0x0011]);
    for (name, units, invocation_index) in [
        ("floatFirst", float_first, 4),
        ("nullFirst", null_first, 5),
        ("sequential", sequential, 3),
    ] {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "LMixedZero;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x1,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "LMixedZero;".to_owned(),
                    proto: ProtoRef {
                        return_type: "Ljava/lang/Float;".to_owned(),
                        params: vec!["I".to_owned()],
                    },
                    name: name.to_owned(),
                },
                access_flags: 0x9,
                is_direct: true,
                registers_size: 2,
                ins_size: 1,
                outs_size: 1,
                insns: units,
                relocations: vec![Reloc::MethodIndex {
                    unit: invocation_index,
                    method: value_of.clone(),
                }],
            }],
            virtual_methods: Vec::new(),
        });
        let result: Dex2JarResult =
            translate_dex_bytes(&builder.build()).expect("translate mixed zero");
        assert_eq!(
            result.bodies_recovered, 0,
            "{name}: {:?}",
            result.diagnostics
        );
        assert_eq!(result.stubbed_body_count, 1, "{name}");
        assert!(
            result.diagnostics.iter().any(|diagnostic| diagnostic
                .reason
                .ends_with("constant-float-reference-conflict")),
            "{name}: {:?}",
            result.diagnostics
        );
    }
}

#[test]
fn a_zero_used_as_float_and_in_place_cast_is_refused_in_either_branch_order() {
    let value_of: MethodRef = MethodRef {
        class: "Ljava/lang/Float;".to_owned(),
        proto: ProtoRef {
            return_type: "Ljava/lang/Float;".to_owned(),
            params: vec!["F".to_owned()],
        },
        name: "valueOf".to_owned(),
    };
    let mut float_first: Vec<u16> = vec![0x0012, 0x0138, 7];
    float_first.extend(insn::fmt35c_one(0x71, 0, 0));
    float_first.extend([0x000C, 0x0011]);
    float_first.extend(insn::fmt21c(0x1F, 0, 0));
    float_first.push(0x0011);
    let mut cast_first: Vec<u16> = vec![0x0012, 0x0138, 5];
    cast_first.extend(insn::fmt21c(0x1F, 0, 0));
    cast_first.push(0x0011);
    cast_first.extend(insn::fmt35c_one(0x71, 0, 0));
    cast_first.extend([0x000C, 0x0011]);
    for (name, units, relocations) in [
        (
            "floatFirstCast",
            float_first,
            vec![
                Reloc::MethodIndex {
                    unit: 4,
                    method: value_of.clone(),
                },
                Reloc::TypeIndex {
                    unit: 9,
                    descriptor: "Ljava/lang/Object;".to_owned(),
                },
            ],
        ),
        (
            "castFirstFloat",
            cast_first,
            vec![
                Reloc::TypeIndex {
                    unit: 4,
                    descriptor: "Ljava/lang/Object;".to_owned(),
                },
                Reloc::MethodIndex {
                    unit: 7,
                    method: value_of,
                },
            ],
        ),
    ] {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "LMixedCastZero;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x1,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "LMixedCastZero;".to_owned(),
                    proto: ProtoRef {
                        return_type: "Ljava/lang/Object;".to_owned(),
                        params: vec!["I".to_owned()],
                    },
                    name: name.to_owned(),
                },
                access_flags: 0x9,
                is_direct: true,
                registers_size: 2,
                ins_size: 1,
                outs_size: 1,
                insns: units,
                relocations,
            }],
            virtual_methods: Vec::new(),
        });
        let result: Dex2JarResult =
            translate_dex_bytes(&builder.build()).expect("translate mixed cast zero");
        assert_eq!(
            result.bodies_recovered, 0,
            "{name}: {:?}",
            result.diagnostics
        );
        assert_eq!(result.stubbed_body_count, 1, "{name}");
        assert!(
            result.diagnostics.iter().any(|diagnostic| diagnostic
                .reason
                .ends_with("constant-float-reference-conflict")),
            "{name}: {:?}",
            result.diagnostics
        );
    }
}

#[test]
fn a_zero_and_nonzero_join_cannot_be_recovered_as_a_null_reference_return() {
    let mut method: EncodedMethod = branched_constant_return("bad", 0);
    method.method.proto.params = vec!["I".to_owned()];
    method.registers_size = 2;
    method.ins_size = 1;
    method.insns = vec![0x0012, 0x0138, 3, 0x1012, 0x0011];
    assert_reference_return_refused(method);
}

fn assert_reference_return_refused(method: EncodedMethod) {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "LSample;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![method],
        virtual_methods: Vec::new(),
    });
    let result: Dex2JarResult =
        translate_dex_bytes(&builder.build()).expect("translate invalid return");
    assert_eq!(result.bodies_recovered, 0);
    assert_eq!(result.stubbed_body_count, 1);
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .method
            .as_deref()
            .is_some_and(|name: &str| name.starts_with("bad("))
            && diagnostic
                .reason
                .ends_with("reference-return-type-mismatch")
    }));
}

#[test]
fn a_zero_constant_that_joins_a_reference_two_blocks_later_is_framed_as_a_reference() {
    let cf: ClassFile = sample_class();
    let frames: Vec<Vec<u8>> = local_tags(&stack_map_body(&cf, "pick"));
    assert!(
        !frames.is_empty(),
        "pick() branches, so it must carry frames"
    );
    for tags in &frames {
        let slot: u8 = *tags
            .get(1)
            .expect("local 1 carries the register the zero constant defines");
        assert!(
            matches!(slot, ITEM_NULL | ITEM_OBJECT),
            "pick() writes a dalvik zero constant into a register whose only other definition is a \
             String, and the two meet two blocks downstream at the return. The frame declares tag \
             {slot} for that local, which is integer, so the lift stored an int there while the \
             frame at the join describes the merged reference. Deciding the constant's java type \
             from the next instruction alone cannot see a join that far away; the decision has to \
             be made over the whole chain of program points the constant reaches"
        );
    }
}

#[test]
fn a_zero_constant_that_joins_an_int_two_blocks_later_stays_an_int() {
    let cf: ClassFile = sample_class();
    let frames: Vec<Vec<u8>> = local_tags(&stack_map_body(&cf, "count"));
    assert!(
        !frames.is_empty(),
        "count() branches, so it must carry frames"
    );
    for tags in &frames {
        let slot: u8 = *tags
            .get(1)
            .expect("local 1 carries the register the zero constant defines");
        assert_eq!(
            slot, ITEM_INTEGER,
            "count() returns the register the zero constant defines and nothing reaching it is a \
             reference, so the frame has to keep it integer. A resolver that answers `reference` \
             whenever it is unsure would turn every dalvik zero into a null and break every int \
             that starts at zero"
        );
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Sample", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method pick = c.getMethod("pick", int.class);
        java.lang.reflect.Method count = c.getMethod("count", int.class);
        java.lang.reflect.Method empty = c.getMethod("empty");
        java.lang.reflect.Method castSplit = c.getMethod("castSplit", int.class);
        java.lang.reflect.Method single = c.getMethod(
            "singleOrNull", byte[].class, java.util.function.Predicate.class);
        java.util.function.Predicate<Object> all = value -> true;
        java.util.function.Predicate<Object> twos = value -> ((Byte) value).byteValue() == 2;
        Class<?> floats = Class.forName("BoxedFloats", true, Probe.class.getClassLoader());
        java.lang.reflect.Method boxed = floats.getMethod("pick", String.class, int.class);
        System.out.println("verify_ok=1 pick0=" + pick.invoke(null, 0)
            + " pick1=" + pick.invoke(null, 1)
            + " count0=" + count.invoke(null, 0)
            + " count1=" + count.invoke(null, 1)
            + " empty=" + empty.invoke(null)
            + " castZero=" + castSplit.invoke(null, 0)
            + " castOne=" + castSplit.invoke(null, 1)
            + " singleEmpty=" + single.invoke(null, new byte[0], all)
            + " singleOne=" + single.invoke(null, new byte[] {1}, all)
            + " singleMany=" + single.invoke(null, new byte[] {1, 2}, all)
            + " singleTwo=" + single.invoke(null, new byte[] {1, 2}, twos)
            + " float0=" + boxed.invoke(null, "1.5", 0)
            + " float1=" + boxed.invoke(null, "1.5", 1)
            + " constant=" + floats.getMethod("constant").invoke(null));
    }
}
"#;

#[test]
fn the_recovered_class_passes_the_real_jvm_verifier_and_runs() {
    let java: PathBuf = find_on_path("java").expect("install a JDK and put java on PATH");
    let javac: PathBuf = find_on_path("javac").expect("install a JDK and put javac on PATH");
    let dir: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        &format!("disrobe_dalvik_null_constant_frame_{}", std::process::id()),
    )
    .expect("scratch dir");
    let result: Dex2JarResult = translate_dex_bytes(&make_dex()).expect("translate crafted dex");
    let sample: &Vec<u8> = result
        .jar_entries
        .get("Sample.class")
        .expect("Sample.class present");
    std::fs::write(dir.path().join("Sample.class"), sample).expect("write Sample.class");
    let floats: Dex2JarResult =
        translate_dex_bytes(&boxed_float_dex()).expect("translate boxed floats");
    std::fs::write(
        dir.path().join("BoxedFloats.class"),
        &floats.jar_entries["BoxedFloats.class"],
    )
    .expect("write BoxedFloats.class");
    let src: PathBuf = dir.path().join("Probe.java");
    std::fs::write(&src, PROBE_SRC).expect("write Probe.java");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(dir.path())
        .arg(&src)
        .output()
        .expect("compile Probe");
    assert!(
        compiled.status.success(),
        "compile Probe: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run: std::process::Output = Command::new(&java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(dir.path())
        .arg("Probe")
        .output()
        .expect("run Probe");
    let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&run.stderr).into_owned();
    assert!(
        run.status.success() && stdout.contains("verify_ok=1"),
        "the recovered Sample did not link and run under -Xverify:all.\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
    assert!(
        stdout.contains("pick0=null") && stdout.contains("pick1=picked"),
        "pick() takes the branch that leaves the zero constant in place when its argument is zero \
         and the branch that assigns the string otherwise, so the recovered method is checked for \
         behavior and not only for a frame the verifier accepts: {stdout}"
    );
    assert!(
        stdout.contains("count0=0") && stdout.contains("count1=7"),
        "count() must return 0 on the branch that leaves the zero constant in place and 7 on the \
         branch that assigns it: {stdout}"
    );
    assert!(stdout.contains("empty=null"), "{stdout}");
    assert!(
        stdout.contains("castZero=right") && stdout.contains("castOne=left"),
        "{stdout}"
    );
    assert!(
        stdout.contains("singleEmpty=null")
            && stdout.contains("singleOne=1")
            && stdout.contains("singleMany=null")
            && stdout.contains("singleTwo=2"),
        "{stdout}"
    );
    assert!(
        stdout.contains("float0=null")
            && stdout.contains("float1=1.5")
            && stdout.contains("constant=2.5"),
        "{stdout}"
    );
}
