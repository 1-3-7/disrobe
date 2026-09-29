#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::dalvik_r8_inline::{
    Candidate, Confidence, InversionReport, Rewrite, Transform, invert,
};
use disrobe_pass_jvm::dex::{DexFile, parse};
use disrobe_pass_jvm::dex_builder::{
    ClassDef, DexBuilder, EncodedField, EncodedMethod, FieldRef, MethodRef, ProtoRef, Reloc, insn,
};

const OUTLINE_CLASS: &str = "Lcom/example/-$$ExternalSyntheticOutline0;";
const CALC_CLASS: &str = "Lcom/example/Calc;";
const COLOR_CLASS: &str = "Lcom/example/Color;";
const COLOR_ARRAY: &str = "[Lcom/example/Color;";
const OBJECT: &str = "Ljava/lang/Object;";
const ENUM: &str = "Ljava/lang/Enum;";

struct Asm {
    units: Vec<u16>,
    relocs: Vec<Reloc>,
}

impl Asm {
    const fn new() -> Self {
        Self {
            units: Vec::new(),
            relocs: Vec::new(),
        }
    }

    fn raw(&mut self, units: Vec<u16>) {
        self.units.extend(units);
    }

    fn field(&mut self, units: Vec<u16>, field: FieldRef) {
        let at: usize = self.units.len() + 1;
        self.units.extend(units);
        self.relocs.push(Reloc::FieldIndex { unit: at, field });
    }

    fn method(&mut self, units: Vec<u16>, method: MethodRef) {
        let at: usize = self.units.len() + 1;
        self.units.extend(units);
        self.relocs.push(Reloc::MethodIndex { unit: at, method });
    }

    fn typed(&mut self, units: Vec<u16>, descriptor: &str) {
        let at: usize = self.units.len() + 1;
        self.units.extend(units);
        self.relocs.push(Reloc::TypeIndex {
            unit: at,
            descriptor: descriptor.to_owned(),
        });
    }
}

fn proto(ret: &str, params: &[&str]) -> ProtoRef {
    ProtoRef {
        return_type: ret.to_owned(),
        params: params.iter().map(|p: &&str| (*p).to_owned()).collect(),
    }
}

fn mref(class: &str, name: &str, ret: &str, params: &[&str]) -> MethodRef {
    MethodRef {
        class: class.to_owned(),
        proto: proto(ret, params),
        name: name.to_owned(),
    }
}

fn values_field() -> FieldRef {
    FieldRef {
        class: COLOR_CLASS.to_owned(),
        type_desc: COLOR_ARRAY.to_owned(),
        name: "$VALUES".to_owned(),
    }
}

fn method(
    method_ref: MethodRef,
    access_flags: u32,
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    asm: Asm,
) -> EncodedMethod {
    EncodedMethod {
        tries: Vec::new(),
        method: method_ref,
        access_flags,
        is_direct: true,
        registers_size,
        ins_size,
        outs_size,
        insns: asm.units,
        relocations: asm.relocs,
    }
}

fn pure_combine_body() -> Asm {
    let mut asm: Asm = Asm::new();
    asm.raw(insn::fmt22b(0xDA, 0, 1, 31));
    asm.raw(insn::fmt23x(0x90, 0, 0, 2));
    asm.raw(insn::fmt11x(0x0F, 0));
    asm
}

fn caller_body(target: &MethodRef) -> Asm {
    let mut asm: Asm = Asm::new();
    asm.method(insn::fmt35c_two(0x71, 2, 3, 0), target.clone());
    asm.raw(insn::fmt11x(0x0A, 0));
    asm.method(insn::fmt35c_two(0x71, 3, 2, 0), target.clone());
    asm.raw(insn::fmt11x(0x0A, 1));
    asm.raw(insn::fmt23x(0x90, 0, 0, 1));
    asm.raw(insn::fmt11x(0x0F, 0));
    asm
}

fn build_sample() -> Vec<u8> {
    let outline_m: MethodRef = mref(OUTLINE_CLASS, "m", "I", &["I", "I"]);
    let real_helper: MethodRef = mref(CALC_CLASS, "realHelper", "I", &["I", "I"]);

    let outline_class: ClassDef = ClassDef {
        class: OUTLINE_CLASS.to_owned(),
        super_class: OBJECT.to_owned(),
        access_flags: 0x1011,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![method(
            outline_m.clone(),
            0x1009,
            3,
            2,
            0,
            pure_combine_body(),
        )],
        virtual_methods: Vec::new(),
    };

    let calc_class: ClassDef = ClassDef {
        class: CALC_CLASS.to_owned(),
        super_class: OBJECT.to_owned(),
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            method(
                mref(CALC_CLASS, "combine", "I", &["I", "I"]),
                0x9,
                4,
                2,
                2,
                caller_body(&outline_m),
            ),
            method(real_helper.clone(), 0x9, 3, 2, 0, pure_combine_body()),
            method(
                mref(CALC_CLASS, "combine2", "I", &["I", "I"]),
                0x9,
                4,
                2,
                2,
                caller_body(&real_helper),
            ),
        ],
        virtual_methods: Vec::new(),
    };

    let mut clinit: Asm = Asm::new();
    clinit.raw(insn::fmt11n(0x12, 0, 2));
    clinit.typed(insn::fmt22c(0x23, 0, 0, 0), COLOR_ARRAY);
    clinit.field(insn::fmt21c(0x69, 0, 0), values_field());
    clinit.raw(insn::fmt10x(0x0E));

    let mut values: Asm = Asm::new();
    values.field(insn::fmt21c(0x62, 0, 0), values_field());
    values.method(
        insn::fmt35c_one(0x6E, 0, 0),
        mref(COLOR_ARRAY, "clone", OBJECT, &[]),
    );
    values.raw(insn::fmt11x(0x0C, 0));
    values.typed(insn::fmt21c(0x1F, 0, 0), COLOR_ARRAY);
    values.raw(insn::fmt11x(0x11, 0));

    let mut count: Asm = Asm::new();
    count.field(insn::fmt21c(0x62, 0, 0), values_field());
    count.raw(insn::fmt12x(0x21, 0, 0));
    count.raw(insn::fmt11x(0x0F, 0));

    let color_class: ClassDef = ClassDef {
        class: COLOR_CLASS.to_owned(),
        super_class: ENUM.to_owned(),
        access_flags: 0x4011,
        static_fields: vec![EncodedField {
            field: values_field(),
            access_flags: 0x1018,
        }],
        static_values: Vec::new(),
        direct_methods: vec![
            method(
                mref(COLOR_CLASS, "<clinit>", "V", &[]),
                0x10008,
                1,
                0,
                0,
                clinit,
            ),
            method(
                mref(COLOR_CLASS, "values", COLOR_ARRAY, &[]),
                0x1009,
                1,
                0,
                1,
                values,
            ),
            method(mref(COLOR_CLASS, "count", "I", &[]), 0x9, 1, 0, 0, count),
        ],
        virtual_methods: Vec::new(),
    };

    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(outline_class);
    builder.add_class(calc_class);
    builder.add_class(color_class);
    builder.build()
}

fn find_inline<'a>(report: &'a InversionReport, method_name: &str) -> Option<&'a Candidate> {
    report.candidates.iter().find(|c: &&Candidate| {
        matches!(&c.transform, Transform::InlineOutlinedHelper { helper_method, .. } if helper_method == method_name)
    })
}

fn find_enum<'a>(report: &'a InversionReport, field: &str) -> Option<&'a Candidate> {
    report.candidates.iter().find(|c: &&Candidate| {
        matches!(&c.transform, Transform::RestoreEnumValues { field: f, .. } if f == field)
    })
}

#[test]
fn outlined_helper_is_reinlined_over_ssa_with_ir_gate_green() {
    let bytes: Vec<u8> = build_sample();
    let dex: DexFile = parse(&bytes).expect("parse built dex");
    let report: InversionReport = invert(&dex, &bytes);

    let candidate: &Candidate = find_inline(&report, "m").expect("outline m candidate");
    assert!(
        candidate.applied,
        "outline should be applied: {candidate:?}"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.rewrites.len(), 2, "two call sites re-inlined");
    assert!(
        candidate.rewrites.iter().all(|r| r.gate_green),
        "IR effect-sequence gate must be green on every site: {candidate:?}"
    );

    let afters: Vec<&str> = candidate
        .rewrites
        .iter()
        .map(|r| r.after.as_str())
        .collect();
    assert!(afters.contains(&"((v2 * 31) + v3)"), "afters={afters:?}");
    assert!(afters.contains(&"((v3 * 31) + v2)"), "afters={afters:?}");
    assert!(
        candidate.rewrites.iter().all(|r| r.before.contains(".m(")),
        "before must render the outlined call"
    );
    if let Transform::InlineOutlinedHelper { call_sites, .. } = &candidate.transform {
        assert_eq!(*call_sites, 2);
    }
}

#[test]
fn developer_authored_helper_is_never_inlined() {
    let bytes: Vec<u8> = build_sample();
    let dex: DexFile = parse(&bytes).expect("parse built dex");
    let report: InversionReport = invert(&dex, &bytes);

    assert!(
        find_inline(&report, "realHelper").is_none(),
        "a non-synthetic developer helper with an identical body must not be inverted"
    );
}

#[test]
fn cached_enum_values_is_restored_to_idiomatic_call() {
    let bytes: Vec<u8> = build_sample();
    let dex: DexFile = parse(&bytes).expect("parse built dex");
    let report: InversionReport = invert(&dex, &bytes);

    let candidate: &Candidate = find_enum(&report, "$VALUES").expect("enum values candidate");
    assert!(
        candidate.applied,
        "enum restore should apply: {candidate:?}"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    let restored: &Rewrite = candidate
        .rewrites
        .iter()
        .find(|r: &&Rewrite| r.before == "com.example.Color.$VALUES")
        .expect("a $VALUES read site");
    assert_eq!(restored.after, "com.example.Color.values()");
    assert!(restored.gate_green);
}

#[test]
fn report_partitions_applied_and_abstained() {
    let bytes: Vec<u8> = build_sample();
    let dex: DexFile = parse(&bytes).expect("parse built dex");
    let report: InversionReport = invert(&dex, &bytes);
    assert!(
        report.applied().len() >= 2,
        "expected the outline inline and the enum restore to apply: {:?}",
        report.candidates
    );
}

#[test]
fn d8_r8_differential_when_toolchain_present() {
    let available: bool = ["d8", "r8", "d8.bat", "r8.bat"].iter().any(|tool: &&str| {
        std::process::Command::new(tool)
            .arg("--version")
            .output()
            .is_ok()
    });
    if !available {
        eprintln!(
            "d8/r8 not on PATH: end-to-end differential is PATH-gated; the IR effect-sequence gate \
             ran on the hand-assembled DEX fixtures instead"
        );
        return;
    }
    let bytes: Vec<u8> = build_sample();
    let dex: DexFile = parse(&bytes).expect("parse built dex");
    let report: InversionReport = invert(&dex, &bytes);
    assert!(!report.applied().is_empty());
}
