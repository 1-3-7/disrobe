#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

pub mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{JvmVerifier, VerifyScope, lines_with_prefix, parse_metric};
use disrobe_pass_jvm::assemble_jar;
use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const MID: &str = "MergeMid";
const LEFT: &str = "MergeLeft";
const RIGHT: &str = "MergeRight";
const HOST: &str = "BigMerge";
const OBJECT: &str = "java/lang/Object";

const BLOCK_COUNT: usize = 78;

const INT_BLOCK_UNITS: usize = 8;

const REF_BLOCK_UNITS: usize = 10;

const MIN_CODE_UNITS: usize = 600;

const EMITTED_FRAMES: usize = 156;

const fn is_ref_block(index: usize) -> bool {
    index % 5 == 4
}

fn ref_block_count() -> usize {
    (0..BLOCK_COUNT)
        .filter(|i: &usize| is_ref_block(*i))
        .count()
}

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

fn tag_ref() -> MethodRef {
    MethodRef {
        class: descriptor_of(MID),
        proto: ProtoRef {
            return_type: "I".to_owned(),
            params: Vec::new(),
        },
        name: "tag".to_owned(),
    }
}

fn ctor(class: &str, super_class: &str) -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt35c_one(0x70, 0, 0));
    units.extend(insn::fmt10x(0x0E));
    EncodedMethod {
        method: init_ref(class),
        access_flags: 0x1,
        is_direct: true,
        registers_size: 1,
        ins_size: 1,
        outs_size: 1,
        insns: units,
        relocations: vec![Reloc::MethodIndex {
            unit: 1,
            method: init_ref(super_class),
        }],
    }
}

fn tag_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 7));
    units.extend(insn::fmt11x(0x0F, 0));
    EncodedMethod {
        method: tag_ref(),
        access_flags: 0x1,
        is_direct: false,
        registers_size: 2,
        ins_size: 1,
        outs_size: 0,
        insns: units,
        relocations: Vec::new(),
    }
}

fn run_ref() -> MethodRef {
    MethodRef {
        class: descriptor_of(HOST),
        proto: ProtoRef {
            return_type: "I".to_owned(),
            params: vec![descriptor_of(LEFT), descriptor_of(RIGHT), "I".to_owned()],
        },
        name: "run".to_owned(),
    }
}

fn int_diamond(units: &mut Vec<u16>) {
    units.push(0x38 | (5u16 << 8));
    units.push(5);
    units.extend(insn::fmt22b(0xD8, 0, 0, 1));
    units.push(0x28 | (3u16 << 8));
    units.extend(insn::fmt22b(0xD8, 0, 0, 2));
    units.extend(insn::fmt10x(0x00));
}

fn reference_diamond(units: &mut Vec<u16>, relocations: &mut Vec<Reloc>, base: usize) {
    units.push(0x38 | (5u16 << 8));
    units.push(4);
    units.extend(insn::fmt12x(0x07, 1, 3));
    units.push(0x28 | (2u16 << 8));
    units.extend(insn::fmt12x(0x07, 1, 4));
    units.extend(insn::fmt35c_one(0x6E, 1, 0));
    relocations.push(Reloc::MethodIndex {
        unit: base + 6,
        method: tag_ref(),
    });
    units.extend(insn::fmt11x(0x0A, 2));
    units.extend(insn::fmt12x(0xB0, 0, 2));
}

fn run_method() -> EncodedMethod {
    let mut units: Vec<u16> = Vec::new();
    let mut relocations: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt11n(0x12, 0, 0));
    for index in 0..BLOCK_COUNT {
        let base: usize = units.len();
        if is_ref_block(index) {
            reference_diamond(&mut units, &mut relocations, base);
            assert_eq!(units.len() - base, REF_BLOCK_UNITS);
        } else {
            int_diamond(&mut units);
            assert_eq!(units.len() - base, INT_BLOCK_UNITS);
        }
    }
    units.extend(insn::fmt11x(0x0F, 0));
    EncodedMethod {
        method: run_ref(),
        access_flags: 0x9,
        is_direct: true,
        registers_size: 6,
        ins_size: 3,
        outs_size: 1,
        insns: units,
        relocations,
    }
}

fn plain_class(class: &str, super_class: &str, methods: Vec<EncodedMethod>) -> ClassDef {
    let mut direct: Vec<EncodedMethod> = vec![ctor(class, super_class)];
    let mut virtual_methods: Vec<EncodedMethod> = Vec::new();
    for method in methods {
        if method.is_direct {
            direct.push(method);
        } else {
            virtual_methods.push(method);
        }
    }
    ClassDef {
        class: descriptor_of(class),
        super_class: descriptor_of(super_class),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: direct,
        virtual_methods,
    }
}

fn merge_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(plain_class(MID, OBJECT, vec![tag_method()]));
    builder.add_class(plain_class(LEFT, MID, Vec::new()));
    builder.add_class(plain_class(RIGHT, MID, Vec::new()));
    builder.add_class(plain_class(HOST, OBJECT, vec![run_method()]));
    builder.build()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerificationType {
    Top,
    Primitive(u8),
    Null,
    UninitializedThis,
    Object(String),
    Uninitialized(u16),
}

#[derive(Debug)]
struct Frame {
    offset: usize,
    locals: Vec<VerificationType>,
}

struct FrameReader<'a> {
    body: &'a [u8],
    cursor: usize,
}

impl<'a> FrameReader<'a> {
    const fn new(body: &'a [u8]) -> Self {
        Self { body, cursor: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let value: u8 = *self.body.get(self.cursor)?;
        self.cursor += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi: u8 = self.u8()?;
        let lo: u8 = self.u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    fn verification_type(&mut self, cf: &ClassFile) -> Option<VerificationType> {
        match self.u8()? {
            0 => Some(VerificationType::Top),
            tag @ 1..=4 => Some(VerificationType::Primitive(tag)),
            5 => Some(VerificationType::Null),
            6 => Some(VerificationType::UninitializedThis),
            7 => {
                let index: u16 = self.u16()?;
                Some(VerificationType::Object(
                    cf.class_name(index).ok()?.to_owned(),
                ))
            }
            8 => Some(VerificationType::Uninitialized(self.u16()?)),
            _ => None,
        }
    }
}

fn utf8_at(cf: &ClassFile, index: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(index)) {
        Some(ConstantPoolEntry::Utf8(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn code_attribute<'a>(cf: &'a ClassFile, method: &str) -> &'a [u8] {
    let info: &'a Vec<u8> = cf
        .methods
        .iter()
        .find(|m| utf8_at(cf, m.name_index) == Some(method))
        .unwrap_or_else(|| panic!("{method} is present in the lifted class"))
        .attributes
        .iter()
        .find(|a| utf8_at(cf, a.name_index) == Some("Code"))
        .map_or_else(|| panic!("{method} carries a Code attribute"), |a| &a.info);
    info.as_slice()
}

fn stack_map_body<'a>(cf: &'a ClassFile, code: &'a [u8]) -> Option<&'a [u8]> {
    let code_len: usize = usize::try_from(u32::from_be_bytes([
        *code.get(4)?,
        *code.get(5)?,
        *code.get(6)?,
        *code.get(7)?,
    ]))
    .ok()?;
    let mut cursor: usize = 8usize.checked_add(code_len)?;
    let exception_len: usize = usize::from(u16::from_be_bytes([
        *code.get(cursor)?,
        *code.get(cursor + 1)?,
    ]));
    cursor = cursor
        .checked_add(2)?
        .checked_add(exception_len.checked_mul(8)?)?;
    let attribute_count: usize = usize::from(u16::from_be_bytes([
        *code.get(cursor)?,
        *code.get(cursor + 1)?,
    ]));
    cursor = cursor.checked_add(2)?;
    for _ in 0..attribute_count {
        let name_index: u16 = u16::from_be_bytes([*code.get(cursor)?, *code.get(cursor + 1)?]);
        let length: usize = usize::try_from(u32::from_be_bytes([
            *code.get(cursor + 2)?,
            *code.get(cursor + 3)?,
            *code.get(cursor + 4)?,
            *code.get(cursor + 5)?,
        ]))
        .ok()?;
        let start: usize = cursor.checked_add(6)?;
        let end: usize = start.checked_add(length)?;
        if utf8_at(cf, name_index) == Some("StackMapTable") {
            return code.get(start..end);
        }
        cursor = end;
    }
    None
}

fn frames_of(cf: &ClassFile, method: &str) -> Vec<Frame> {
    let code: &[u8] = code_attribute(cf, method);
    let Some(body): Option<&[u8]> = stack_map_body(cf, code) else {
        return Vec::new();
    };
    let mut reader: FrameReader<'_> = FrameReader::new(body);
    let entries: usize = usize::from(reader.u16().expect("the table records a frame count"));
    let mut frames: Vec<Frame> = Vec::with_capacity(entries);
    let mut offset: Option<usize> = None;
    for _ in 0..entries {
        assert_eq!(
            reader.u8(),
            Some(255),
            "the lifter emits full_frame entries only, so any other tag means this parser is \
             reading a table shape the assertions below were never written for"
        );
        let delta: usize = usize::from(reader.u16().expect("a full frame records its delta"));
        let at: usize = offset.map_or(delta, |previous: usize| previous + delta + 1);
        offset = Some(at);
        let local_count: usize =
            usize::from(reader.u16().expect("a full frame records its locals"));
        let mut locals: Vec<VerificationType> = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            locals.push(
                reader
                    .verification_type(cf)
                    .expect("every local carries a verification type this parser knows"),
            );
        }
        let stack_count: usize = usize::from(reader.u16().expect("a full frame records its stack"));
        for _ in 0..stack_count {
            reader
                .verification_type(cf)
                .expect("every stack entry carries a verification type this parser knows");
        }
        frames.push(Frame { offset: at, locals });
    }
    frames
}

fn lifted(result: &Dex2JarResult, class: &str) -> ClassFile {
    let entry: &Vec<u8> = result
        .jar_entries
        .get(&format!("{class}.class"))
        .unwrap_or_else(|| panic!("{class}.class is present in the translation"));
    parse_classfile(entry).expect("parse a lifted merge-gate class")
}

const ATHROW: u8 = 0xBF;

fn is_throw_stub(cf: &ClassFile, method: &str) -> bool {
    let code: &[u8] = code_attribute(cf, method);
    let length: usize = usize::try_from(u32::from_be_bytes([code[4], code[5], code[6], code[7]]))
        .expect("a code length fits usize");
    code.get(8 + length - 1) == Some(&ATHROW)
}

#[test]
fn the_merge_gate_method_is_longer_than_the_committed_corpus_reaches() {
    let method: EncodedMethod = run_method();
    assert!(
        method.insns.len() > MIN_CODE_UNITS,
        "this gate exists because the committed dex corpus holds no method above {MIN_CODE_UNITS} \
         code units, and the real-apk rejections cluster past that length; the built method is \
         {} units",
        method.insns.len()
    );
    assert_eq!(
        method.relocations.len(),
        ref_block_count(),
        "every reference diamond calls the supertype method exactly once, so a relocation count \
         that drifts means the block layout no longer matches what the assertions describe"
    );
}

#[test]
fn a_long_method_joins_sibling_references_at_their_shared_supertype() {
    let result: Dex2JarResult =
        translate_dex_bytes(&merge_dex()).expect("translate the merge-gate dex");
    let cf: ClassFile = lifted(&result, HOST);
    assert!(
        !is_throw_stub(&cf, "run"),
        "the lifter fell back to a throw stub for the long merge method, so the frame assertions \
         below would grade a stub rather than a recovered body"
    );

    let frames: Vec<Frame> = frames_of(&cf, "run");
    eprintln!(
        "LARGE MERGE FRAMES: blocks={BLOCK_COUNT} reference_blocks={} frames={}",
        ref_block_count(),
        frames.len()
    );
    assert_eq!(
        frames.len(),
        EMITTED_FRAMES,
        "the dex this gate builds is fixed and the translation is deterministic, so the frame \
         count cannot move without the lifter moving; a method with {BLOCK_COUNT} diamonds reaches \
         two join points per diamond"
    );

    let mid: VerificationType = VerificationType::Object(MID.to_owned());
    let carrying_mid: usize = frames
        .iter()
        .filter(|frame: &&Frame| frame.locals.contains(&mid))
        .count();
    assert!(
        carrying_mid >= ref_block_count(),
        "each of the {} reference diamonds joins {LEFT} with {RIGHT} and then calls a method \
         declared on {MID}, so the frame at each join has to name {MID}; only {carrying_mid} \
         frames do. Widening an unequal reference pair to {OBJECT} still satisfies the frame \
         itself, and the invokevirtual on the next instruction is what rejects",
        ref_block_count()
    );

    let object_locals: usize = frames
        .iter()
        .filter(|frame: &&Frame| {
            frame
                .locals
                .contains(&VerificationType::Object(OBJECT.to_owned()))
        })
        .count();
    assert_eq!(
        object_locals, 0,
        "no local in this method ever holds a plain {OBJECT}, so a frame naming one is the \
         supertype join collapsing to the top of the hierarchy"
    );

    let offsets: BTreeSet<usize> = frames.iter().map(|frame: &Frame| frame.offset).collect();
    assert_eq!(
        offsets.len(),
        frames.len(),
        "two frames landed on one jvm offset; the delta loop that follows subtracts one from a \
         zero gap and drops the whole table"
    );
}

#[test]
fn the_long_merge_method_passes_the_real_jvm_verifier() {
    let verifier: JvmVerifier = match JvmVerifier::prepare(&format!(
        "disrobe_dalvik_large_merge_{}",
        std::process::id()
    )) {
        Ok(prepared) => prepared,
        Err(why) => panic!(
            "this gate grades a long-method frame merge against a real jvm and has no second \
             reference to fall back to: {why}"
        ),
    };
    let result: Dex2JarResult =
        translate_dex_bytes(&merge_dex()).expect("translate the merge-gate dex");
    let jar: Vec<u8> = assemble_jar(&result).expect("assemble the merge-gate jar");
    let jar_path: PathBuf = verifier.write_jar("large-merge", &jar);
    let stdout: String = verifier.run(VerifyScope::Classes { permille: 1000 }, jar_path.as_path());

    let clean: usize = parse_metric(&stdout, "verify_clean_classes=");
    let rejected: usize = parse_metric(&stdout, "lifter_verify_fail_classes=");
    let skipped: usize = parse_metric(&stdout, "link_skipped_classes=");
    let unstable: usize = parse_metric(&stdout, "link_unstable_classes=");
    let bodies_clean: usize = parse_metric(&stdout, "body_clean=");
    let bodies_failed: usize = parse_metric(&stdout, "body_fail=");
    eprintln!(
        "LARGE MERGE VERIFY: clean={clean} rejected={rejected} link_skipped={skipped} \
         link_unstable={unstable} body_clean={bodies_clean} body_fail={bodies_failed}"
    );
    for line in lines_with_prefix(&stdout, "VERIFY ") {
        eprintln!("  {line}");
    }
    for line in lines_with_prefix(&stdout, "BODYVERIFY ") {
        eprintln!("  {line}");
    }

    assert_eq!(
        rejected,
        0,
        "the real jvm rejected a recovered merge-gate class:\n{}",
        lines_with_prefix(&stdout, "VERIFY ").join("\n")
    );
    assert_eq!(
        skipped, 0,
        "every class this gate builds is in the same jar, so none of them may reach the verifier \
         with a missing supertype"
    );
    assert_eq!(
        unstable, 0,
        "the jvm ended a class in a resource error rather than a verdict"
    );
    assert_eq!(
        clean, 4,
        "the gate builds {MID}, {LEFT}, {RIGHT} and {HOST}, and all four have to pass \
         -Xverify:all for the long-method join to count as graded"
    );
    assert_eq!(
        bodies_failed,
        0,
        "the jvm rejected a re-hosted merge-gate body:\n{}",
        lines_with_prefix(&stdout, "BODYVERIFY ").join("\n")
    );
    assert!(
        bodies_clean >= 1,
        "the re-hosted body pass graded nothing, so the long merge method never reached the \
         verifier as a standalone body"
    );
}
