#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

pub mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use common::find_on_path;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_jvm::dex_builder::{
    CatchHandler, ClassDef, DexBuilder, EncodedField, EncodedMethod, FieldRef, MethodRef, ProtoRef,
    Reloc, TryItem, insn,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, parse_classfile};

const REQUIRE_JVM: &str = "DISROBE_REQUIRE_JVM";
const JVM_TIMEOUT: Duration = Duration::from_secs(30);
const JVM_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;

const CONVERSIONS: &[Conversion] = &[
    Conversion::new(0x81, "i2l", "I", "J"),
    Conversion::new(0x82, "i2f", "I", "F"),
    Conversion::new(0x83, "i2d", "I", "D"),
    Conversion::new(0x84, "l2i", "J", "I"),
    Conversion::new(0x85, "l2f", "J", "F"),
    Conversion::new(0x86, "l2d", "J", "D"),
    Conversion::new(0x87, "f2i", "F", "I"),
    Conversion::new(0x88, "f2l", "F", "J"),
    Conversion::new(0x89, "f2d", "F", "D"),
    Conversion::new(0x8A, "d2i", "D", "I"),
    Conversion::new(0x8B, "d2l", "D", "J"),
    Conversion::new(0x8C, "d2f", "D", "F"),
    Conversion::new(0x8D, "i2b", "I", "I"),
    Conversion::new(0x8E, "i2c", "I", "I"),
    Conversion::new(0x8F, "i2s", "I", "I"),
];

struct Conversion {
    op: u8,
    name: &'static str,
    src: &'static str,
    dest: &'static str,
}

impl Conversion {
    const fn new(op: u8, name: &'static str, src: &'static str, dest: &'static str) -> Self {
        Self {
            op,
            name,
            src,
            dest,
        }
    }

    const fn src_slots(&self) -> u16 {
        if is_wide(self.src) { 2 } else { 1 }
    }

    const fn dest_slots(&self) -> u16 {
        if is_wide(self.dest) { 2 } else { 1 }
    }
}

const fn is_wide(desc: &str) -> bool {
    matches!(desc.as_bytes(), [b'J' | b'D'])
}

const fn tag_for_desc(desc: &str) -> u8 {
    match desc.as_bytes() {
        [b'J'] => 4,
        [b'F'] => 2,
        [b'D'] => 3,
        _ => 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    AliasSource,
    OverwriteWideHigh,
    BranchMergeToTop,
    ZeroMergeToTop,
    LoopBackEdge,
    ArithmeticUse,
    ArgumentUse,
    VirtualUse,
    RangeUse,
    FieldStore,
    ArrayStore,
    PostThrowTarget,
    WideRegisterFile,
    TryBody,
    HandlerEntry,
}

impl Shape {
    const fn slug(self) -> &'static str {
        match self {
            Self::AliasSource => "Alias",
            Self::OverwriteWideHigh => "High",
            Self::BranchMergeToTop => "Merge",
            Self::ZeroMergeToTop => "ZeroMerge",
            Self::LoopBackEdge => "Loop",
            Self::ArithmeticUse => "Arithmetic",
            Self::ArgumentUse => "Arg",
            Self::VirtualUse => "Virtual",
            Self::RangeUse => "Range",
            Self::FieldStore => "Field",
            Self::ArrayStore => "Array",
            Self::PostThrowTarget => "PostThrow",
            Self::WideRegisterFile => "Wide",
            Self::TryBody => "Try",
            Self::HandlerEntry => "Handler",
        }
    }

    const fn applies(self, conv: &Conversion) -> bool {
        match self {
            Self::OverwriteWideHigh => is_wide(conv.src),
            _ => true,
        }
    }
}

fn class_name(shape: Shape, conv: &Conversion) -> String {
    format!("C{}{}", shape.slug(), conv.name)
}

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

fn ctor(class: &str) -> EncodedMethod {
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
            class: format!("L{class};"),
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
        relocations: Vec::new().into_iter().chain(relocs).collect(),
    }
}

const fn return_op(desc: &str) -> u8 {
    if is_wide(desc) { 0x10 } else { 0x0F }
}

struct Body {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    insns: Vec<u16>,
    return_type: &'static str,
    params: Vec<String>,
    relocations: Vec<Reloc>,
    tries: Vec<TryItem>,
}

const SINK: &str = "ConvSink";

fn sink_ref(desc: &str) -> MethodRef {
    MethodRef {
        class: format!("L{SINK};"),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: vec![desc.to_owned()],
        },
        name: "take".to_owned(),
    }
}

fn sink_method(desc: &'static str) -> EncodedMethod {
    let slots: u16 = if is_wide(desc) { 2 } else { 1 };
    EncodedMethod {
        tries: Vec::new(),
        method: sink_ref(desc),
        access_flags: 0x9,
        is_direct: true,
        registers_size: slots,
        ins_size: slots,
        outs_size: 0,
        insns: insn::fmt10x(0x0E),
        relocations: Vec::new(),
    }
}

fn sink_virtual_method(desc: &'static str) -> EncodedMethod {
    let slots: u16 = if is_wide(desc) { 2 } else { 1 };
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: format!("L{SINK};"),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: vec![desc.to_owned()],
            },
            name: "takeVirtual".to_owned(),
        },
        access_flags: 0x1,
        is_direct: false,
        registers_size: slots + 1,
        ins_size: slots + 1,
        outs_size: 0,
        insns: insn::fmt10x(0x0E),
        relocations: Vec::new(),
    }
}

fn sink_class() -> ClassDef {
    ClassDef {
        class: format!("L{SINK};"),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            ctor(SINK),
            sink_method("I"),
            sink_method("J"),
            sink_method("F"),
            sink_method("D"),
        ],
        virtual_methods: vec![
            sink_virtual_method("I"),
            sink_virtual_method("J"),
            sink_virtual_method("F"),
            sink_virtual_method("D"),
        ],
    }
}

const fn move_op(desc: &str) -> u8 {
    if is_wide(desc) { 0x04 } else { 0x01 }
}

fn alias_source_body(conv: &Conversion) -> Body {
    let scratch: u16 = conv.src_slots().max(conv.dest_slots());
    let ins_size: u16 = conv.src_slots() + 1;
    let registers_size: u16 = scratch + ins_size;
    let param: u8 = u8::try_from(scratch).expect("register index fits u8");
    let cond: u8 = u8::try_from(scratch + conv.src_slots()).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(move_op(conv.src), 0, param));
    units.extend(insn::fmt12x(conv.op, 0, 0));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(2);
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt11x(return_op(conv.dest), 0));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: conv.dest,
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

fn overwrite_wide_high_body(conv: &Conversion) -> Body {
    let scratch: u16 = 2u16.max(1 + conv.dest_slots());
    let ins_size: u16 = conv.src_slots() + 1;
    let registers_size: u16 = scratch + ins_size;
    let param: u8 = u8::try_from(scratch).expect("register index fits u8");
    let cond: u8 = u8::try_from(scratch + conv.src_slots()).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(0x04, 0, param));
    units.extend(insn::fmt12x(conv.op, 1, 0));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(2);
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt11x(return_op(conv.dest), 1));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: conv.dest,
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

fn branch_merge_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let scratch: u16 = dest_slots + 1;
    let registers_size: u16 = scratch + ins_size;
    let dest: u8 = 0;
    let tail: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let src: u8 = u8::try_from(scratch).expect("register index fits u8");
    let cond: u8 = u8::try_from(scratch + src_slots).expect("register index fits u8");

    let mut units: Vec<u16> = Vec::new();
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(5);
    units.extend(insn::fmt12x(conv.op, dest, src));
    units.extend(insn::fmt11n(0x12, tail, 0));
    units.push(0x28 | (4u16 << 8));
    units.extend(insn::fmt11n(0x12, dest, 1));
    units.extend(insn::fmt11n(0x12, tail, 0));
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

fn zero_merge_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = dest_slots + ins_size;
    let dest: u8 = 0;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let cond: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(4);
    units.extend(insn::fmt12x(conv.op, dest, src));
    units.push(0x28 | (3u16 << 8));
    units.extend(insn::fmt11n(0x12, dest, 0));
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

fn loop_back_edge_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = dest_slots + ins_size;
    let dest: u8 = 0;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let counter: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");

    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(conv.op, dest, src));
    units.extend(insn::fmt22b(0xD8, counter, counter, -1));
    units.push(0x3C | (u16::from(counter) << 8));
    units.push((-3i16) as u16);
    units.extend(insn::fmt11x(return_op(conv.dest), dest));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: conv.dest,
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

const fn arithmetic_op(desc: &str) -> u8 {
    match desc.as_bytes() {
        [b'J'] => 0xBB,
        [b'F'] => 0xC6,
        [b'D'] => 0xCB,
        _ => 0xB0,
    }
}

fn arithmetic_use_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = dest_slots + ins_size;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let cond: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(conv.op, 0, src));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt12x(arithmetic_op(conv.dest), 0, 0));
    units.extend(insn::fmt11x(return_op(conv.dest), 0));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: conv.dest,
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

fn argument_use_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = dest_slots + ins_size;
    let dest: u8 = 0;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let cond: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");

    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(conv.op, dest, src));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let call_at: usize = units.len();
    if dest_slots == 2 {
        units.extend(insn::fmt35c_two(0x71, dest, dest + 1, 0));
    } else {
        units.extend(insn::fmt35c_one(0x71, dest, 0));
    }
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: dest_slots,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: vec![Reloc::MethodIndex {
            unit: call_at + 1,
            method: sink_ref(conv.dest),
        }],
        tries: Vec::new(),
    }
}

fn virtual_use_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let receiver: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let scratch: u16 = dest_slots + 1;
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = scratch + ins_size;
    let src: u8 = u8::try_from(scratch).expect("register index fits u8");
    let cond: u8 = u8::try_from(scratch + src_slots).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    let mut relocations: Vec<Reloc> = Vec::new();
    let new_at: usize = units.len();
    units.extend(insn::fmt21c(0x22, receiver, 0));
    relocations.push(Reloc::TypeIndex {
        unit: new_at + 1,
        descriptor: format!("L{SINK};"),
    });
    let ctor_at: usize = units.len();
    units.extend(insn::fmt35c_one(0x70, receiver, 0));
    relocations.push(Reloc::MethodIndex {
        unit: ctor_at + 1,
        method: object_init_for(SINK),
    });
    units.extend(insn::fmt12x(conv.op, 0, src));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let call_at: usize = units.len();
    if dest_slots == 2 {
        units.extend(insn::fmt35c_three(0x6E, receiver, 0, 1, 0));
    } else {
        units.extend(insn::fmt35c_two(0x6E, receiver, 0, 0));
    }
    relocations.push(Reloc::MethodIndex {
        unit: call_at + 1,
        method: MethodRef {
            class: format!("L{SINK};"),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: vec![conv.dest.to_owned()],
            },
            name: "takeVirtual".to_owned(),
        },
    });
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: dest_slots + 1,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations,
        tries: Vec::new(),
    }
}

fn object_init_for(class: &str) -> MethodRef {
    MethodRef {
        class: format!("L{class};"),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: Vec::new(),
        },
        name: "<init>".to_owned(),
    }
}

fn range_use_body(conv: &Conversion) -> Body {
    const RANGE_START: u16 = 16;
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = WIDE_SCRATCH + ins_size;
    let source: u16 = WIDE_SCRATCH;
    let cond: u8 = u8::try_from(WIDE_SCRATCH + src_slots).expect("register index fits u8");
    let source_move: u8 = if is_wide(conv.src) { 0x06 } else { 0x03 };
    let dest_move: u8 = if is_wide(conv.dest) { 0x06 } else { 0x03 };
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt32x(source_move, 0, source));
    units.extend(insn::fmt12x(conv.op, 0, 0));
    units.extend(insn::fmt32x(dest_move, RANGE_START, 0));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let call_at: usize = units.len();
    units.push(0x77 | (conv.dest_slots() << 8));
    units.push(0);
    units.push(RANGE_START);
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: conv.dest_slots(),
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: vec![Reloc::MethodIndex {
            unit: call_at + 1,
            method: sink_ref(conv.dest),
        }],
        tries: Vec::new(),
    }
}

fn value_field(class: &str, desc: &str) -> FieldRef {
    FieldRef {
        class: format!("L{class};"),
        type_desc: desc.to_owned(),
        name: "value".to_owned(),
    }
}

fn field_store_body(conv: &Conversion, class: &str) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = dest_slots + ins_size;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let cond: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(conv.op, 0, src));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let field_at: usize = units.len();
    let op: u8 = if is_wide(conv.dest) { 0x68 } else { 0x67 };
    units.extend(insn::fmt21c(op, 0, 0));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: vec![Reloc::FieldIndex {
            unit: field_at + 1,
            field: value_field(class, conv.dest),
        }],
        tries: Vec::new(),
    }
}

fn array_store_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let array: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let size: u8 = array + 1;
    let index: u8 = size + 1;
    let scratch: u16 = dest_slots + 3;
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = scratch + ins_size;
    let src: u8 = u8::try_from(scratch).expect("register index fits u8");
    let cond: u8 = u8::try_from(scratch + src_slots).expect("register index fits u8");
    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt12x(conv.op, 0, src));
    units.extend(insn::fmt11n(0x12, size, 1));
    let array_at: usize = units.len();
    units.extend(insn::fmt22c(0x23, array, size, 0));
    units.extend(insn::fmt11n(0x12, index, 0));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt10x(0x00));
    let store_op: u8 = if is_wide(conv.dest) { 0x4C } else { 0x4B };
    units.extend(insn::fmt23x(store_op, 0, array, index));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: vec![Reloc::TypeIndex {
            unit: array_at + 1,
            descriptor: format!("[{}", conv.dest),
        }],
        tries: Vec::new(),
    }
}

fn post_throw_target_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 2;
    let registers_size: u16 = dest_slots + ins_size;
    let src: u8 = u8::try_from(dest_slots).expect("register index fits u8");
    let exception: u8 = u8::try_from(dest_slots + src_slots).expect("register index fits u8");
    let cond: u8 = exception + 1;
    let mut units: Vec<u16> = Vec::new();
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(3);
    units.extend(insn::fmt11x(0x27, exception));
    units.extend(insn::fmt12x(conv.op, 0, src));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(2);
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: "V",
        params: vec![
            conv.src.to_owned(),
            "Ljava/lang/RuntimeException;".to_owned(),
            "I".to_owned(),
        ],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

const WIDE_SCRATCH: u16 = 20;

fn wide_register_file_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let ins_size: u16 = src_slots + 1;
    let registers_size: u16 = WIDE_SCRATCH + ins_size;
    let source: u16 = WIDE_SCRATCH;
    let cond: u8 = u8::try_from(WIDE_SCRATCH + src_slots).expect("register index fits u8");
    let wide_move: u8 = if is_wide(conv.src) { 0x06 } else { 0x03 };

    let mut units: Vec<u16> = Vec::new();
    units.extend(insn::fmt32x(wide_move, 0, source));
    units.extend(insn::fmt12x(conv.op, 0, 0));
    units.push(0x38 | (u16::from(cond) << 8));
    units.push(2);
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt11x(return_op(conv.dest), 0));
    let _ = dest_slots;
    Body {
        registers_size,
        ins_size,
        outs_size: 0,
        insns: units,
        return_type: conv.dest,
        params: vec![conv.src.to_owned(), "I".to_owned()],
        relocations: Vec::new(),
        tries: Vec::new(),
    }
}

const CAUGHT: &str = "Ljava/lang/Exception;";

fn sink_call(units: &mut Vec<u16>, relocations: &mut Vec<Reloc>, first: u16, desc: &'static str) {
    let at: usize = units.len();
    let low: u8 = u8::try_from(first).expect("register index fits u8");
    if is_wide(desc) {
        units.extend(insn::fmt35c_two(0x71, low, low + 1, 0));
    } else {
        units.extend(insn::fmt35c_one(0x71, low, 0));
    }
    relocations.push(Reloc::MethodIndex {
        unit: at + 1,
        method: sink_ref(desc),
    });
}

fn try_body_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let exception: u16 = dest_slots;
    let source: u16 = dest_slots + 1;
    let registers_size: u16 = dest_slots + 1 + src_slots;

    let mut units: Vec<u16> = Vec::new();
    let mut relocations: Vec<Reloc> = Vec::new();
    units.extend(insn::fmt12x(
        conv.op,
        0,
        u8::try_from(source).expect("register index fits u8"),
    ));
    sink_call(&mut units, &mut relocations, 0, conv.dest);
    units.push(0x28 | (3u16 << 8));
    units.extend(insn::fmt11x(
        0x0D,
        u8::try_from(exception).expect("register index fits u8"),
    ));
    units.extend(insn::fmt10x(0x00));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size: src_slots,
        outs_size: dest_slots,
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned()],
        relocations,
        tries: vec![TryItem {
            start_unit: 0,
            unit_count: 5,
            handlers: vec![CatchHandler {
                exception_type: Some(CAUGHT.to_owned()),
                handler_unit: 5,
            }],
        }],
    }
}

fn handler_entry_body(conv: &Conversion) -> Body {
    let dest_slots: u16 = conv.dest_slots();
    let src_slots: u16 = conv.src_slots();
    let exception: u16 = dest_slots;
    let source: u16 = dest_slots + 1;
    let registers_size: u16 = dest_slots + 1 + src_slots;

    let mut units: Vec<u16> = Vec::new();
    let mut relocations: Vec<Reloc> = Vec::new();
    sink_call(&mut units, &mut relocations, source, conv.src);
    units.push(0x28 | (7u16 << 8));
    units.extend(insn::fmt11x(
        0x0D,
        u8::try_from(exception).expect("register index fits u8"),
    ));
    units.extend(insn::fmt12x(
        conv.op,
        0,
        u8::try_from(source).expect("register index fits u8"),
    ));
    sink_call(&mut units, &mut relocations, 0, conv.dest);
    units.extend(insn::fmt10x(0x0E));
    units.extend(insn::fmt10x(0x0E));
    Body {
        registers_size,
        ins_size: src_slots,
        outs_size: dest_slots.max(src_slots),
        insns: units,
        return_type: "V",
        params: vec![conv.src.to_owned()],
        relocations,
        tries: vec![TryItem {
            start_unit: 0,
            unit_count: 4,
            handlers: vec![CatchHandler {
                exception_type: Some(CAUGHT.to_owned()),
                handler_unit: 4,
            }],
        }],
    }
}

fn body_for(shape: Shape, conv: &Conversion, class: &str) -> Body {
    match shape {
        Shape::AliasSource => alias_source_body(conv),
        Shape::OverwriteWideHigh => overwrite_wide_high_body(conv),
        Shape::BranchMergeToTop => branch_merge_body(conv),
        Shape::ZeroMergeToTop => zero_merge_body(conv),
        Shape::LoopBackEdge => loop_back_edge_body(conv),
        Shape::ArithmeticUse => arithmetic_use_body(conv),
        Shape::ArgumentUse => argument_use_body(conv),
        Shape::VirtualUse => virtual_use_body(conv),
        Shape::RangeUse => range_use_body(conv),
        Shape::FieldStore => field_store_body(conv, class),
        Shape::ArrayStore => array_store_body(conv),
        Shape::PostThrowTarget => post_throw_target_body(conv),
        Shape::WideRegisterFile => wide_register_file_body(conv),
        Shape::TryBody => try_body_body(conv),
        Shape::HandlerEntry => handler_entry_body(conv),
    }
}

fn shape_class(shape: Shape, conv: &Conversion) -> ClassDef {
    let name: String = class_name(shape, conv);
    let body: Body = body_for(shape, conv, &name);
    let method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: format!("L{name};"),
            proto: ProtoRef {
                return_type: body.return_type.to_owned(),
                params: body.params.clone(),
            },
            name: "conv".to_owned(),
        },
        access_flags: 0x9,
        is_direct: true,
        registers_size: body.registers_size,
        ins_size: body.ins_size,
        outs_size: body.outs_size,
        insns: body.insns,
        relocations: body.relocations,
        tries: body.tries,
    };
    ClassDef {
        class: format!("L{name};"),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: if shape == Shape::FieldStore {
            vec![EncodedField {
                field: value_field(&name, conv.dest),
                access_flags: 0x9,
            }]
        } else {
            Vec::new()
        },
        static_values: Vec::new(),
        direct_methods: vec![ctor(&name), method],
        virtual_methods: Vec::new(),
    }
}

const SHAPES: &[Shape] = &[
    Shape::AliasSource,
    Shape::OverwriteWideHigh,
    Shape::BranchMergeToTop,
    Shape::ZeroMergeToTop,
    Shape::LoopBackEdge,
    Shape::ArithmeticUse,
    Shape::ArgumentUse,
    Shape::VirtualUse,
    Shape::RangeUse,
    Shape::FieldStore,
    Shape::ArrayStore,
    Shape::PostThrowTarget,
    Shape::WideRegisterFile,
    Shape::TryBody,
    Shape::HandlerEntry,
];

const NO_CONVERSION: &str = "CNoConversion";

fn no_conversion_class() -> ClassDef {
    let units: Vec<u16> = [
        insn::fmt12x(0x01, 0, 1),
        vec![0x38, 2],
        insn::fmt10x(0x00),
        insn::fmt10x(0x0E),
    ]
    .concat();
    ClassDef {
        class: format!("L{NO_CONVERSION};"),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x1,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            ctor(NO_CONVERSION),
            EncodedMethod {
                method: MethodRef {
                    class: format!("L{NO_CONVERSION};"),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: vec!["I".to_owned()],
                    },
                    name: "conv".to_owned(),
                },
                access_flags: 0x9,
                is_direct: true,
                registers_size: 2,
                ins_size: 1,
                outs_size: 0,
                insns: units,
                relocations: Vec::new(),
                tries: Vec::new(),
            },
        ],
        virtual_methods: Vec::new(),
    }
}

fn emitted_classes() -> Vec<(Shape, &'static Conversion, String)> {
    let mut out: Vec<(Shape, &'static Conversion, String)> = Vec::new();
    for shape in SHAPES {
        for conv in CONVERSIONS {
            if shape.applies(conv) {
                out.push((*shape, conv, class_name(*shape, conv)));
            }
        }
    }
    out
}

fn shapes_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(sink_class());
    builder.add_class(no_conversion_class());
    for (shape, conv, _name) in emitted_classes() {
        builder.add_class(shape_class(shape, conv));
    }
    builder.build()
}

fn all_class_names() -> Vec<String> {
    let mut names: Vec<String> = vec![SINK.to_owned(), NO_CONVERSION.to_owned()];
    names.extend(
        emitted_classes()
            .into_iter()
            .map(|(_shape, _conv, name): (Shape, &Conversion, String)| name),
    );
    names
}

fn cp_utf8(cf: &ClassFile, idx: u16) -> Option<&str> {
    match cf.constant_pool.get(usize::from(idx)) {
        Some(ConstantPoolEntry::Utf8(s)) => Some(s.as_str()),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FrameTags {
    locals: Vec<u8>,
    stack: Vec<u8>,
}

fn stack_map_tags(cf: &ClassFile) -> Vec<FrameTags> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some("conv"))
        .expect("conv method present");
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("conv has Code");
    let info: &[u8] = &code.info;
    let code_len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    let mut o: usize = 8 + code_len;
    let exc_len: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2 + exc_len * 8;
    let attr_count: usize = u16::from_be_bytes([info[o], info[o + 1]]) as usize;
    o += 2;
    let mut body: Option<&[u8]> = None;
    for _ in 0..attr_count {
        let name_idx: u16 = u16::from_be_bytes([info[o], info[o + 1]]);
        let len: usize =
            u32::from_be_bytes([info[o + 2], info[o + 3], info[o + 4], info[o + 5]]) as usize;
        let start: usize = o + 6;
        if cp_utf8(cf, name_idx) == Some("StackMapTable") {
            body = Some(&info[start..start + len]);
            break;
        }
        o = start + len;
    }
    let Some(body): Option<&[u8]> = body else {
        return Vec::new();
    };
    let mut frames: Vec<FrameTags> = Vec::new();
    let mut p: usize = 0;
    let entries: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    for _ in 0..entries {
        assert_eq!(body[p], 255, "the lifter emits full_frame frames only");
        p += 1 + 2;
        let num_locals: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let mut locals: Vec<u8> = Vec::with_capacity(num_locals);
        for _ in 0..num_locals {
            let tag: u8 = body[p];
            locals.push(tag);
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
        let num_stack: usize = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let mut stack: Vec<u8> = Vec::with_capacity(num_stack);
        for _ in 0..num_stack {
            let tag: u8 = body[p];
            stack.push(tag);
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
        frames.push(FrameTags { locals, stack });
    }
    frames
}

fn nonzero_tag_multiset(tags: &[u8]) -> BTreeMap<u8, usize> {
    let mut out: BTreeMap<u8, usize> = BTreeMap::new();
    for &t in tags {
        if t != 0 {
            *out.entry(t).or_insert(0) += 1;
        }
    }
    out
}

fn parsed_class(result: &Dex2JarResult, name: &str) -> ClassFile {
    let entry: &Vec<u8> = result
        .jar_entries
        .get(&format!("{name}.class"))
        .unwrap_or_else(|| panic!("{name}.class present in translation"));
    parse_classfile(entry).expect("parse a lifted conversion-shape class")
}

const ATHROW: u8 = 0xBF;

fn conv_code(cf: &ClassFile) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some("conv"))
        .expect("conv method present");
    let code = method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("conv has Code");
    let info: &[u8] = &code.info;
    let len: usize = u32::from_be_bytes([info[4], info[5], info[6], info[7]]) as usize;
    info[8..8 + len].to_vec()
}

#[test]
fn every_conversion_shape_lifts_to_a_recovered_body() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    let all: Vec<(Shape, &Conversion, String)> = emitted_classes();
    let mut stubbed: Vec<String> = Vec::new();
    for (_shape, _conv, name) in &all {
        let cf: ClassFile = parsed_class(&result, name);
        if conv_code(&cf).last() == Some(&ATHROW) {
            stubbed.push(name.clone());
        }
    }
    assert!(
        stubbed.is_empty(),
        "the lifter fell back to a throw stub for {} of {} conversion shapes, so the frame \
         assertions below would grade a stub rather than a recovered body: {}",
        stubbed.len(),
        all.len(),
        stubbed.join(", ")
    );
}

#[test]
fn no_conversion_control_keeps_precise_non_top_frame_tags() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    let cf: ClassFile = parsed_class(&result, NO_CONVERSION);
    let frames: Vec<FrameTags> = stack_map_tags(&cf);
    assert_eq!(
        frames,
        vec![FrameTags {
            locals: vec![1, 1],
            stack: Vec::new(),
        }],
        "the no-conversion control must keep its scratch and parameter typed as int"
    );
}

#[test]
fn a_conversion_whose_destination_aliases_its_source_frames_the_result_type() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for conv in CONVERSIONS {
        let name: String = class_name(Shape::AliasSource, conv);
        let cf: ClassFile = parsed_class(&result, &name);
        let frames: Vec<FrameTags> = stack_map_tags(&cf);
        let frame: &FrameTags = frames.first().unwrap_or_else(|| {
            panic!("{name} branches after the conversion, so it carries a frame")
        });
        let observed: BTreeMap<u8, usize> = nonzero_tag_multiset(&frame.locals);
        assert!(
            frame.stack.is_empty(),
            "{name} must have an empty operand stack"
        );
        let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
        *expected.entry(tag_for_desc(conv.src)).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        *expected.entry(tag_for_desc(conv.dest)).or_insert(0) += 1;
        assert_eq!(
            observed, expected,
            "{name} converts {} to {} in place, so the frame carries the untouched {} parameter, \
             the int branch condition and one {} result; the emitted frame is {frame:?}. A result \
             tag that names the wrong width is what makes the store and the frame disagree",
            conv.src, conv.dest, conv.src, conv.dest
        );
    }
}

#[test]
fn a_conversion_over_a_live_wide_pair_invalidates_the_half_it_overwrites() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for conv in CONVERSIONS {
        if !Shape::OverwriteWideHigh.applies(conv) {
            continue;
        }
        let name: String = class_name(Shape::OverwriteWideHigh, conv);
        let cf: ClassFile = parsed_class(&result, &name);
        let frames: Vec<FrameTags> = stack_map_tags(&cf);
        let frame: &FrameTags = frames.first().unwrap_or_else(|| {
            panic!("{name} branches after the conversion, so it carries a frame")
        });
        let observed: BTreeMap<u8, usize> = nonzero_tag_multiset(&frame.locals);
        assert!(
            frame.stack.is_empty(),
            "{name} must have an empty operand stack"
        );
        let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
        *expected.entry(tag_for_desc(conv.src)).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        *expected.entry(tag_for_desc(conv.dest)).or_insert(0) += 1;
        assert_eq!(
            observed, expected,
            "{name} writes its {} result over the high half of the live {} pair at the scratch \
             register, so that pair is dead and the frame must describe the parameter copy, the \
             int branch condition and the result alone; the emitted frame is {frame:?}. A second \
             {} tag here means the low half kept a wide type whose other half was overwritten",
            conv.dest, conv.src, conv.src
        );
    }
}

#[test]
fn a_conversion_in_one_arm_of_a_branch_merges_to_top_at_the_join() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for conv in CONVERSIONS {
        let name: String = class_name(Shape::BranchMergeToTop, conv);
        let cf: ClassFile = parsed_class(&result, &name);
        let frames: Vec<FrameTags> = stack_map_tags(&cf);
        assert!(
            !frames.is_empty(),
            "{name} branches, so it must carry a StackMapTable"
        );
        let joined: &FrameTags = frames.last().expect("the join frame is the last one");
        let observed: BTreeMap<u8, usize> = nonzero_tag_multiset(&joined.locals);
        assert!(
            joined.stack.is_empty(),
            "{name} must have an empty operand stack"
        );
        let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
        *expected.entry(tag_for_desc(conv.src)).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        if tag_for_desc(conv.dest) == 1 {
            *expected.entry(1).or_insert(0) += 1;
        }
        assert_eq!(
            observed,
            expected,
            "{name} ({} to {}) converts on one arm and writes an int constant on the other, so the \
             join frame carries the {} source, the int branch condition and a converted register \
             that is {}; the emitted frame is {joined:?}. A frame that keeps the converted type on \
             a path that never produced it is what the real verifier rejects",
            conv.src,
            conv.dest,
            conv.src,
            if tag_for_desc(conv.dest) == 1 {
                "an integer on both arms"
            } else {
                "top because the two arms disagree"
            }
        );
    }
}

#[test]
fn zero_or_null_merges_with_each_numeric_conversion_result_without_retaining_a_stale_type() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for conv in CONVERSIONS {
        let name: String = class_name(Shape::ZeroMergeToTop, conv);
        let cf: ClassFile = parsed_class(&result, &name);
        let frames: Vec<FrameTags> = stack_map_tags(&cf);
        let joined: &FrameTags = frames.last().expect("the zero merge frame");
        let observed: BTreeMap<u8, usize> = nonzero_tag_multiset(&joined.locals);
        assert!(
            joined.stack.is_empty(),
            "{name} must have an empty operand stack"
        );
        let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
        *expected.entry(tag_for_desc(conv.src)).or_insert(0) += 1;
        *expected.entry(1).or_insert(0) += 1;
        if tag_for_desc(conv.dest) == 1 {
            *expected.entry(1).or_insert(0) += 1;
        }
        assert_eq!(
            observed, expected,
            "{name} merges ZeroOrNull with the {} result; the exact join tags are {joined:?}",
            conv.dest
        );
    }
}

#[test]
fn a_conversion_inside_a_loop_body_keeps_its_result_type_across_the_back_edge() {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for conv in CONVERSIONS {
        let name: String = class_name(Shape::LoopBackEdge, conv);
        let cf: ClassFile = parsed_class(&result, &name);
        let frames: Vec<FrameTags> = stack_map_tags(&cf);
        assert!(
            !frames.is_empty(),
            "{name} carries a back edge, so it must carry a StackMapTable"
        );
        let entry: &FrameTags = frames.first().expect("the loop header frame");
        let observed: BTreeMap<u8, usize> = nonzero_tag_multiset(&entry.locals);
        assert!(
            entry.stack.is_empty(),
            "{name} must have an empty operand stack"
        );
        assert!(
            observed.contains_key(&tag_for_desc(conv.src)),
            "{name} ({} to {}) must still describe its {} source at the loop header, but the \
             frame holds {observed:?}",
            conv.src,
            conv.dest,
            conv.src
        );
        assert!(
            observed.contains_key(&1),
            "{name} must still describe its int loop counter at the header, but the frame holds \
             {observed:?}"
        );
    }
}

fn expected_typed_use_tags(shape: Shape, conv: &Conversion) -> BTreeMap<u8, usize> {
    let mut expected: BTreeMap<u8, usize> = BTreeMap::new();
    *expected.entry(tag_for_desc(conv.src)).or_insert(0) += 1;
    *expected.entry(tag_for_desc(conv.dest)).or_insert(0) += 1;
    *expected.entry(1).or_insert(0) += 1;
    match shape {
        Shape::VirtualUse | Shape::PostThrowTarget => {
            *expected.entry(7).or_insert(0) += 1;
        }
        Shape::RangeUse => {
            *expected.entry(tag_for_desc(conv.dest)).or_insert(0) += 1;
        }
        Shape::ArrayStore => {
            *expected.entry(7).or_insert(0) += 1;
            *expected.entry(1).or_insert(0) += 2;
        }
        Shape::ArithmeticUse | Shape::ArgumentUse | Shape::FieldStore => {}
        _ => panic!("{shape:?} is not a typed-use shape"),
    }
    expected
}

#[test]
fn every_typed_use_observes_the_exact_conversion_result_tag() {
    const TYPED_USE_SHAPES: &[Shape] = &[
        Shape::ArithmeticUse,
        Shape::ArgumentUse,
        Shape::VirtualUse,
        Shape::RangeUse,
        Shape::FieldStore,
        Shape::ArrayStore,
        Shape::PostThrowTarget,
    ];
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    for shape in TYPED_USE_SHAPES {
        for conv in CONVERSIONS {
            let name: String = class_name(*shape, conv);
            let cf: ClassFile = parsed_class(&result, &name);
            let frames: Vec<FrameTags> = stack_map_tags(&cf);
            let frame: &FrameTags = if *shape == Shape::PostThrowTarget {
                frames.last()
            } else {
                frames.first()
            }
            .unwrap_or_else(|| panic!("{name} must carry a typed-use frame"));
            let result_from_end: usize = match shape {
                Shape::VirtualUse => 1,
                Shape::ArrayStore => 3,
                Shape::ArithmeticUse
                | Shape::ArgumentUse
                | Shape::RangeUse
                | Shape::FieldStore
                | Shape::PostThrowTarget => 0,
                _ => panic!("{shape:?} is not a typed-use shape"),
            };
            let result_index: usize = frame
                .locals
                .len()
                .checked_sub(result_from_end + 1)
                .unwrap_or_else(|| panic!("{name} result local is present"));
            assert_eq!(
                frame.locals.get(result_index),
                Some(&tag_for_desc(conv.dest)),
                "{name} must place the conversion result in its exact scratch local"
            );
            assert!(
                frame.stack.is_empty(),
                "{name} must have an empty operand stack"
            );
            assert_eq!(
                nonzero_tag_multiset(&frame.locals),
                expected_typed_use_tags(*shape, conv),
                "{name} emitted the wrong exact local tags: {frame:?}"
            );
        }
    }
}

#[test]
fn the_asserted_frame_tags_separate_every_conversion_result_type() {
    let mut distinguishable: usize = 0;
    let mut collisions: Vec<String> = Vec::new();
    for left in CONVERSIONS {
        for right in CONVERSIONS {
            if left.name >= right.name {
                continue;
            }
            let same_source: bool = left.src == right.src;
            let same_dest: bool = tag_for_desc(left.dest) == tag_for_desc(right.dest);
            if !same_source {
                continue;
            }
            if same_dest {
                collisions.push(format!("{} and {}", left.name, right.name));
            } else {
                distinguishable += 1;
            }
        }
    }
    assert!(
        distinguishable >= 12,
        "only {distinguishable} same-source conversion pairs carry different result tags, so \
         swapping two conversion results would not move any asserted multiset"
    );
    assert_eq!(
        collisions,
        vec![
            "i2b and i2c".to_string(),
            "i2b and i2s".to_string(),
            "i2c and i2s".to_string(),
        ],
        "the only conversion pairs a frame tag cannot separate are the three int-to-int \
         narrowings, which the jvm represents identically; any other collision means the \
         assertions above would pass through a swapped result type"
    );
}

fn probe_source(names: &[String]) -> String {
    let list: String = names
        .iter()
        .map(|n: &String| format!("\"{n}\""))
        .collect::<Vec<String>>()
        .join(", ");
    PROBE_SRC.replace("__NAMES__", &list)
}

const SECOND_CLASS_FILE_MAJOR: u16 = 51;

struct ProbeOutcome {
    clean: usize,
    fail: usize,
    other: usize,
    detail: String,
}

fn stamped_major(bytes: &[u8], major: u16) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    out[6..8].copy_from_slice(&major.to_be_bytes());
    out
}

fn class_bytes(result: &Dex2JarResult, name: &str) -> Vec<u8> {
    result
        .jar_entries
        .get(&format!("{name}.class"))
        .unwrap_or_else(|| panic!("{name}.class present in translation"))
        .clone()
}

fn stack_map_body_range(cf: &ClassFile, info: &[u8]) -> Option<(usize, usize)> {
    let code_len: usize =
        usize::try_from(u32::from_be_bytes([info[4], info[5], info[6], info[7]])).ok()?;
    let mut cursor: usize = 8 + code_len;
    let exception_len: usize = usize::from(u16::from_be_bytes([info[cursor], info[cursor + 1]]));
    cursor += 2 + exception_len * 8;
    let attribute_count: usize = usize::from(u16::from_be_bytes([info[cursor], info[cursor + 1]]));
    cursor += 2;
    for _ in 0..attribute_count {
        let name_index: u16 = u16::from_be_bytes([info[cursor], info[cursor + 1]]);
        let length: usize = usize::try_from(u32::from_be_bytes([
            info[cursor + 2],
            info[cursor + 3],
            info[cursor + 4],
            info[cursor + 5],
        ]))
        .ok()?;
        let start: usize = cursor + 6;
        if cp_utf8(cf, name_index) == Some("StackMapTable") {
            return Some((start, length));
        }
        cursor = start + length;
    }
    None
}

fn frame_tag_offsets(body: &[u8]) -> Vec<usize> {
    let mut offsets: Vec<usize> = Vec::new();
    let mut p: usize = 0;
    let entries: usize = usize::from(u16::from_be_bytes([body[p], body[p + 1]]));
    p += 2;
    for _ in 0..entries {
        assert_eq!(body[p], 255, "the lifter emits full_frame entries only");
        p += 3;
        let locals: usize = usize::from(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
        for _ in 0..locals {
            offsets.push(p);
            let tag: u8 = body[p];
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
        let stack: usize = usize::from(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
        for _ in 0..stack {
            offsets.push(p);
            let tag: u8 = body[p];
            p += 1;
            if tag == 7 || tag == 8 {
                p += 2;
            }
        }
    }
    offsets
}

fn frame_local_tag_offsets(body: &[u8]) -> Vec<Vec<usize>> {
    let mut frames: Vec<Vec<usize>> = Vec::new();
    let mut p: usize = 2;
    let entries: usize = usize::from(u16::from_be_bytes([body[0], body[1]]));
    for _ in 0..entries {
        assert_eq!(body[p], 255, "the lifter emits full_frame entries only");
        p += 3;
        let locals: usize = usize::from(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
        let mut offsets: Vec<usize> = Vec::with_capacity(locals);
        for _ in 0..locals {
            offsets.push(p);
            let tag: u8 = body[p];
            p += if tag == 7 || tag == 8 { 3 } else { 1 };
        }
        let stack: usize = usize::from(u16::from_be_bytes([body[p], body[p + 1]]));
        p += 2;
        for _ in 0..stack {
            let tag: u8 = body[p];
            p += if tag == 7 || tag == 8 { 3 } else { 1 };
        }
        frames.push(offsets);
    }
    frames
}

const fn swapped_tag(tag: u8) -> u8 {
    match tag {
        1 => 2,
        2 => 1,
        3 => 4,
        4 => 3,
        other => other,
    }
}

fn conv_code_info(cf: &ClassFile) -> Vec<u8> {
    let method = cf
        .methods
        .iter()
        .find(|m| cp_utf8(cf, m.name_index) == Some("conv"))
        .expect("conv method present");
    method
        .attributes
        .iter()
        .find(|a| cp_utf8(cf, a.name_index) == Some("Code"))
        .expect("conv has Code")
        .info
        .clone()
}

#[derive(Clone, Copy)]
enum FrameSelection {
    First,
    Last,
}

fn replace_local_tag(
    name: &str,
    bytes: &[u8],
    selection: FrameSelection,
    local_from_end: usize,
    replacement: u8,
) -> Vec<u8> {
    let cf: ClassFile = parse_classfile(bytes).expect("parse a lifted conversion-shape class");
    let info: Vec<u8> = conv_code_info(&cf);
    let code_at: usize = bytes
        .windows(info.len())
        .position(|window: &[u8]| window == info.as_slice())
        .unwrap_or_else(|| panic!("{name} conv Code attribute is present"));
    let (body_at, body_len): (usize, usize) = stack_map_body_range(&cf, &info)
        .unwrap_or_else(|| panic!("{name} carries a StackMapTable"));
    let frames: Vec<Vec<usize>> = frame_local_tag_offsets(&info[body_at..body_at + body_len]);
    let frame_index: usize = match selection {
        FrameSelection::First => 0,
        FrameSelection::Last => frames
            .len()
            .checked_sub(1)
            .unwrap_or_else(|| panic!("{name} frame index is present")),
    };
    let local_index: usize = frames[frame_index]
        .len()
        .checked_sub(local_from_end + 1)
        .unwrap_or_else(|| panic!("{name} local from end {local_from_end} is present"));
    let offset: usize = frames[frame_index][local_index];
    let at: usize = code_at + body_at + offset;
    assert_ne!(
        bytes[at], replacement,
        "{name} perturbation must change a tag"
    );
    let mut out: Vec<u8> = bytes.to_vec();
    out[at] = replacement;
    out
}

fn swap_frame_tags(name: &str, bytes: &[u8]) -> Vec<u8> {
    let cf: ClassFile = parse_classfile(bytes).expect("parse a lifted conversion-shape class");
    let info: Vec<u8> = conv_code_info(&cf);
    let occurrences: Vec<usize> = bytes
        .windows(info.len())
        .enumerate()
        .filter_map(|(at, window): (usize, &[u8])| (window == info.as_slice()).then_some(at))
        .collect();
    assert_eq!(
        occurrences.len(),
        1,
        "{name} carries {} copies of its conv Code attribute, so the patch below cannot name which \
         one it rewrites",
        occurrences.len()
    );
    let code_at: usize = occurrences[0];
    let (body_at, body_len): (usize, usize) = stack_map_body_range(&cf, &info)
        .unwrap_or_else(|| panic!("{name} carries a StackMapTable"));
    let body: &[u8] = &info[body_at..body_at + body_len];
    let offsets: Vec<usize> = frame_tag_offsets(body);

    let mut out: Vec<u8> = bytes.to_vec();
    let mut swapped: usize = 0;
    for offset in offsets {
        let at: usize = code_at + body_at + offset;
        let tag: u8 = out[at];
        let replacement: u8 = swapped_tag(tag);
        if replacement != tag {
            out[at] = replacement;
            swapped += 1;
        }
    }
    assert!(
        swapped > 0,
        "{name} carries no int, float, long or double frame tag to swap. A frame typed Top \
         everywhere satisfies the verifier and destroys the recovery, so a shape with nothing to \
         perturb is the failure this gate exists to catch"
    );
    out
}

fn run_probe(
    label: &str,
    classes: &[(String, Vec<u8>)],
    graded: &[String],
) -> Option<ProbeOutcome> {
    let required: bool = std::env::var_os(REQUIRE_JVM).is_some();
    let (Some(java), Some(javac)): (Option<PathBuf>, Option<PathBuf>) =
        (find_on_path("java"), find_on_path("javac"))
    else {
        assert!(
            !required,
            "{REQUIRE_JVM} is set, so the conversion-shape frames must be graded by a real jvm \
             rather than skipped; java and javac have to be on PATH"
        );
        eprintln!("SKIP conversion-shape {label} gate: java or javac not on PATH");
        return None;
    };

    let purpose: String = format!("disrobe_conv_shape_{label}_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    for (name, bytes) in classes {
        std::fs::write(dir.join(format!("{name}.class")), bytes).expect("write class");
    }

    let probe_path: PathBuf = dir.join("Probe.java");
    std::fs::write(&probe_path, probe_source(graded)).expect("write probe");
    let compiled_args: [OsString; 3] = [
        OsString::from("-d"),
        dir.as_os_str().to_os_string(),
        probe_path.as_os_str().to_os_string(),
    ];
    let compiled: CapturedOutput =
        run_captured(&javac, &compiled_args, JVM_TIMEOUT, JVM_CAPTURE_LIMIT)
            .expect("launch javac probe")
            .expect("javac probe exceeded its wall-clock bound");
    assert!(
        compiled.exit_code == Some(0),
        "the conversion-shape probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let run_args: [OsString; 4] = [
        OsString::from("-Xverify:all"),
        OsString::from("-cp"),
        dir.as_os_str().to_os_string(),
        OsString::from("Probe"),
    ];
    let run: CapturedOutput = run_captured(&java, &run_args, JVM_TIMEOUT, JVM_CAPTURE_LIMIT)
        .expect("launch the java probe")
        .expect("java probe exceeded its wall-clock bound");
    let out: String = String::from_utf8_lossy(&run.stdout).into_owned();
    eprintln!(
        "CONVERSION SHAPE {label}: graded={} status={} stdout={} stderr={}",
        graded.len(),
        run.exit_code
            .map_or_else(|| "signal".to_owned(), |code: i32| code.to_string()),
        out.trim(),
        String::from_utf8_lossy(&run.stderr).trim()
    );
    assert!(
        run.exit_code == Some(0) && out.contains("shape_clean="),
        "the conversion-shape probe did not run to completion under -Xverify:all"
    );
    let metric = |key: &str| -> usize {
        out.split_whitespace()
            .find_map(|t: &str| t.strip_prefix(key))
            .and_then(|v: &str| v.parse::<usize>().ok())
            .unwrap_or(usize::MAX)
    };
    Some(ProbeOutcome {
        clean: metric("shape_clean="),
        fail: metric("shape_fail="),
        other: metric("shape_other="),
        detail: out.trim().to_owned(),
    })
}

fn translated_classes(major: Option<u16>) -> Vec<(String, Vec<u8>)> {
    let result: Dex2JarResult =
        translate_dex_bytes(&shapes_dex()).expect("translate the conversion-shape dex");
    all_class_names()
        .into_iter()
        .map(|name: String| {
            let raw: Vec<u8> = class_bytes(&result, &name);
            let bytes: Vec<u8> = major.map_or_else(|| raw.clone(), |m: u16| stamped_major(&raw, m));
            (name, bytes)
        })
        .collect()
}

fn graded_shape_names() -> Vec<String> {
    emitted_classes()
        .into_iter()
        .map(|(_shape, _conv, name): (Shape, &Conversion, String)| name)
        .collect()
}

#[test]
fn every_conversion_shape_passes_xverify_all() {
    let graded: Vec<String> = graded_shape_names();
    let Some(outcome): Option<ProbeOutcome> =
        run_probe("verify", &translated_classes(None), &graded)
    else {
        return;
    };
    assert_eq!(
        outcome.fail, 0,
        "the real jvm verifier rejected at least one lifted conversion shape: {}",
        outcome.detail
    );
    assert_eq!(
        outcome.other, 0,
        "a conversion shape failed to load for a reason other than verification: {}",
        outcome.detail
    );
    assert_eq!(
        outcome.clean,
        graded.len(),
        "expected all {} conversion shapes to pass -Xverify:all: {}",
        graded.len(),
        outcome.detail
    );
}

#[test]
fn no_conversion_control_passes_xverify_all() {
    let graded: Vec<String> = vec![NO_CONVERSION.to_owned()];
    let Some(outcome): Option<ProbeOutcome> =
        run_probe("no-conversion", &translated_classes(None), &graded)
    else {
        return;
    };
    assert_eq!(outcome.clean, 1, "{}", outcome.detail);
    assert_eq!(outcome.fail, 0, "{}", outcome.detail);
    assert_eq!(outcome.other, 0, "{}", outcome.detail);
}

#[test]
fn every_conversion_shape_passes_xverify_all_at_a_second_class_file_version() {
    let graded: Vec<String> = graded_shape_names();
    let classes: Vec<(String, Vec<u8>)> = translated_classes(Some(SECOND_CLASS_FILE_MAJOR));
    let Some(outcome): Option<ProbeOutcome> = run_probe("second-version", &classes, &graded) else {
        return;
    };
    assert_eq!(
        outcome.fail, 0,
        "the emitted frames satisfy the type-checking verifier at the version the lifter writes \
         but not at major {SECOND_CLASS_FILE_MAJOR}, which is the version the strict verifier was \
         introduced at: {}",
        outcome.detail
    );
    assert_eq!(
        outcome.other, 0,
        "a conversion shape restamped at major {SECOND_CLASS_FILE_MAJOR} failed to load for a \
         reason other than verification: {}",
        outcome.detail
    );
    assert_eq!(outcome.clean, graded.len(), "{}", outcome.detail);
}

#[test]
fn swapping_the_frame_tags_of_every_conversion_shape_is_rejected() {
    let graded: Vec<String> = graded_shape_names();
    let classes: Vec<(String, Vec<u8>)> = translated_classes(None)
        .into_iter()
        .map(|(name, bytes): (String, Vec<u8>)| {
            if graded.contains(&name) {
                let patched: Vec<u8> = swap_frame_tags(&name, &bytes);
                (name, patched)
            } else {
                (name, bytes)
            }
        })
        .collect();
    let Some(outcome): Option<ProbeOutcome> = run_probe("tag-swap", &classes, &graded) else {
        return;
    };
    assert_eq!(
        outcome.clean, 0,
        "a conversion shape still passed -Xverify:all after every int, float, long and double tag \
         in its StackMapTable was swapped for the other width of the same slot count. A frame that \
         can be swapped without the verifier noticing is a frame that describes nothing: {}",
        outcome.detail
    );
    assert_eq!(
        outcome.other, 0,
        "a swapped shape failed for a reason other than verification, so this perturbation is not \
         grading the frame it claims to: {}",
        outcome.detail
    );
    assert_eq!(
        outcome.fail,
        graded.len(),
        "all {} conversion shapes have to be rejected once their frame tags are swapped: {}",
        graded.len(),
        outcome.detail
    );
}

fn classes_with_local_tag_replacements(
    replacements: &BTreeMap<String, (FrameSelection, usize, u8)>,
) -> Vec<(String, Vec<u8>)> {
    translated_classes(None)
        .into_iter()
        .map(|(name, bytes): (String, Vec<u8>)| {
            let Some((selection, local_from_end, replacement)): Option<&(
                FrameSelection,
                usize,
                u8,
            )> = replacements.get(&name) else {
                return (name, bytes);
            };
            let patched: Vec<u8> =
                replace_local_tag(&name, &bytes, *selection, *local_from_end, *replacement);
            (name, patched)
        })
        .collect()
}

fn assert_targeted_perturbations_fail(
    label: &str,
    replacements: BTreeMap<String, (FrameSelection, usize, u8)>,
) {
    let graded: Vec<String> = replacements.keys().cloned().collect();
    let classes: Vec<(String, Vec<u8>)> = classes_with_local_tag_replacements(&replacements);
    let Some(outcome): Option<ProbeOutcome> = run_probe(label, &classes, &graded) else {
        return;
    };
    assert_eq!(outcome.clean, 0, "{}", outcome.detail);
    assert_eq!(outcome.other, 0, "{}", outcome.detail);
    assert_eq!(outcome.fail, graded.len(), "{}", outcome.detail);
}

#[test]
fn each_conversion_result_tag_is_individually_required_by_the_verifier() {
    let replacements: BTreeMap<String, (FrameSelection, usize, u8)> = CONVERSIONS
        .iter()
        .map(|conv: &Conversion| {
            let name: String = class_name(Shape::ArithmeticUse, conv);
            let replacement: u8 = swapped_tag(tag_for_desc(conv.dest));
            (name, (FrameSelection::First, 0, replacement))
        })
        .collect();
    assert_targeted_perturbations_fail("result-tag", replacements);
}

#[test]
fn branch_merges_reject_a_tag_from_only_the_converted_arm() {
    let replacements: BTreeMap<String, (FrameSelection, usize, u8)> = CONVERSIONS
        .iter()
        .filter(|conv: &&Conversion| tag_for_desc(conv.dest) != 1)
        .map(|conv: &Conversion| {
            let name: String = class_name(Shape::BranchMergeToTop, conv);
            let destination_from_end: usize = if conv.dest_slots() == 2 { 2 } else { 1 };
            (
                name,
                (
                    FrameSelection::Last,
                    destination_from_end,
                    tag_for_desc(conv.dest),
                ),
            )
        })
        .collect();
    assert_targeted_perturbations_fail("branch-one-side", replacements);
}

#[test]
fn overwritten_wide_pairs_reject_a_live_low_half() {
    let replacements: BTreeMap<String, (FrameSelection, usize, u8)> = CONVERSIONS
        .iter()
        .filter(|conv: &&Conversion| Shape::OverwriteWideHigh.applies(conv))
        .map(|conv: &Conversion| {
            let name: String = class_name(Shape::OverwriteWideHigh, conv);
            (name, (FrameSelection::First, 1, tag_for_desc(conv.src)))
        })
        .collect();
    assert_targeted_perturbations_fail("wide-pair-live", replacements);
}

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        String[] names = { __NAMES__ };
        int clean = 0, fail = 0, other = 0;
        StringBuilder sb = new StringBuilder();
        for (String n : names) {
            try {
                Class<?> c = Class.forName(n, true, Probe.class.getClassLoader());
                c.getDeclaredMethods();
                c.getDeclaredConstructors();
                clean++;
            } catch (VerifyError ve) {
                fail++;
                String m = String.valueOf(ve.getMessage()).replace('\n', ' ');
                sb.append(n).append("=FAIL(").append(m.substring(0, Math.min(160, m.length()))).append(") ");
            } catch (Throwable t) {
                other++;
                sb.append(n).append("=OTHER(").append(t.getClass().getSimpleName()).append(") ");
            }
        }
        System.out.println("shape_clean=" + clean + " shape_fail=" + fail + " shape_other=" + other);
        System.out.println(sb.toString().trim());
    }
}
"#;
