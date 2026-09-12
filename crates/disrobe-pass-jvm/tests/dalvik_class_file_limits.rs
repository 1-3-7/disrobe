#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

pub mod common;

use std::path::PathBuf;

use common::{JvmVerifier, VerifyScope, lines_with_prefix, parse_metric};
use disrobe_pass_jvm::assemble_jar;
use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const HOST: &str = "LimitHost";
const OBJECT: &str = "java/lang/Object";

const OVERSIZED: &str = "past_the_local_slot_limit";
const REPRESENTABLE: &str = "inside_the_local_slot_limit";

const ATHROW: u8 = 0xBF;

fn descriptor_of(class: &str) -> String {
    format!("L{class};")
}

fn init_ref(class: &str) -> MethodRef {
    MethodRef {
        class: descriptor_of(class),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: Vec::new(),
        },
        name: "<init>".to_owned(),
    }
}

fn ctor() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt35c_one(0x70, 0, 0));
    units.extend(insn::fmt10x(0x0E));
    EncodedMethod {
        tries: Vec::new(),
        method: init_ref(HOST),
        access_flags: 0x1,
        is_direct: true,
        registers_size: 1,
        ins_size: 1,
        outs_size: 1,
        insns: units,
        relocations: vec![Reloc::MethodIndex {
            unit: 1,
            method: init_ref(OBJECT),
        }],
    }
}

fn counter(name: &str, registers_size: u16) -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 3));
    units.extend(insn::fmt22b(0xD8, 0, 0, 4));
    units.extend(insn::fmt11x(0x0F, 0));
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: descriptor_of(HOST),
            proto: ProtoRef {
                return_type: "I".to_owned(),
                params: Vec::new(),
            },
            name: name.to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size,
        ins_size: 0,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn limits_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: descriptor_of(HOST),
        super_class: descriptor_of(OBJECT),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            ctor(),
            counter(REPRESENTABLE, 4),
            counter(OVERSIZED, u16::MAX),
        ],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn utf8_at(cf: &ClassFile, index: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(index)) {
        Some(ConstantPoolEntry::Utf8(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn code_of(cf: &ClassFile, method: &str) -> Vec<u8> {
    let info: &Vec<u8> = cf
        .methods
        .iter()
        .find(|m| utf8_at(cf, m.name_index) == Some(method))
        .unwrap_or_else(|| panic!("{method} is present in the lifted class"))
        .attributes
        .iter()
        .find(|a| utf8_at(cf, a.name_index) == Some("Code"))
        .map_or_else(|| panic!("{method} carries a Code attribute"), |a| &a.info);
    let length: usize = usize::try_from(u32::from_be_bytes([info[4], info[5], info[6], info[7]]))
        .expect("a code length fits usize");
    info[8..8 + length].to_vec()
}

fn lifted_host(result: &Dex2JarResult) -> ClassFile {
    let entry: &Vec<u8> = result
        .jar_entries
        .get(&format!("{HOST}.class"))
        .expect("the limit host class is present in the translation");
    parse_classfile(entry).expect("parse the lifted limit host class")
}

#[test]
fn a_method_past_the_local_slot_limit_is_counted_as_unrecovered() {
    let result: Dex2JarResult =
        translate_dex_bytes(&limits_dex()).expect("translate the class-file limit dex");
    eprintln!(
        "CLASS FILE LIMITS: method_total={} bodies_recovered={} stubbed_body_count={}",
        result.method_total, result.bodies_recovered, result.stubbed_body_count
    );
    assert_eq!(
        result.method_total, 3,
        "the host class declares a constructor and two counters, and every one of them has to \
         reach the population the recovery ratio is taken over"
    );
    assert_eq!(
        result.stubbed_body_count, 1,
        "exactly one method sits past the class-file local slot limit, and a method the emitter \
         refuses has to be counted as unrecovered rather than dropped from the denominator; a \
         limit that clamps instead of rejecting leaves this at zero while the emitted slot indexes \
         are computed against a bound that is too small"
    );
    assert_eq!(
        result.bodies_recovered,
        result.method_total - result.stubbed_body_count,
        "every method carries exactly one verdict, so a recovered count that does not complete the \
         stubbed one means a method left the population ungraded"
    );
}

#[test]
fn the_refused_method_is_a_stub_and_the_representable_one_is_a_real_body() {
    let result: Dex2JarResult =
        translate_dex_bytes(&limits_dex()).expect("translate the class-file limit dex");
    let cf: ClassFile = lifted_host(&result);
    let refused: Vec<u8> = code_of(&cf, OVERSIZED);
    let kept: Vec<u8> = code_of(&cf, REPRESENTABLE);
    assert_eq!(
        refused.last(),
        Some(&ATHROW),
        "a method the emitter refuses has to carry a throwing stub, so a reader can tell the body \
         apart from a recovered one"
    );
    assert_ne!(
        kept.last(),
        Some(&ATHROW),
        "the counter that fits inside the limit differs from the oversized one only by its \
         register file, so a stub here means the rejection took the whole class with it"
    );
    assert!(
        kept.len() >= 3,
        "the representable counter loads a constant, adds to it and returns, so a body of {} bytes \
         is not the code this test grades",
        kept.len()
    );
}

#[test]
fn a_class_holding_a_refused_method_still_passes_the_real_jvm_verifier() {
    let verifier: JvmVerifier = match JvmVerifier::prepare(&format!(
        "disrobe_dalvik_class_file_limits_{}",
        std::process::id()
    )) {
        Ok(prepared) => prepared,
        Err(why) => panic!(
            "this gate grades a limit rejection against a real jvm and has no second reference to \
             fall back to: {why}"
        ),
    };
    let result: Dex2JarResult =
        translate_dex_bytes(&limits_dex()).expect("translate the class-file limit dex");
    let jar: Vec<u8> = assemble_jar(&result).expect("assemble the class-file limit jar");
    let jar_path: PathBuf = verifier.write_jar("class-file-limits", &jar);
    let stdout: String = verifier.run(VerifyScope::Classes { permille: 1000 }, jar_path.as_path());

    let rejected: usize = parse_metric(&stdout, "lifter_verify_fail_classes=");
    let clean: usize = parse_metric(&stdout, "verify_clean_classes=");
    eprintln!("CLASS FILE LIMITS VERIFY: clean={clean} rejected={rejected}");
    assert_eq!(
        rejected,
        0,
        "the jvm rejected the class that holds the refused method, so the rejection path emitted \
         malformed bytecode rather than a clean stub:\n{}",
        lines_with_prefix(&stdout, "VERIFY ").join("\n")
    );
    assert_eq!(
        clean, 1,
        "the gate builds one class and it has to reach a verdict under -Xverify:all"
    );
}
