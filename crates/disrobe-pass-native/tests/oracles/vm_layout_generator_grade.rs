#![allow(clippy::panic, clippy::expect_used)]

use crate::vm_layout_generator;

use disrobe_pass_native::vm_devirt::detect::{
    Bitness, DispatchKind, HandlerEntry, Segment, VmStructure,
};
use disrobe_pass_native::vm_devirt::layout::ContextRole;
use disrobe_pass_native::vm_devirt::{BinKind, HandlerSemantics, MicroOp, fingerprint_handlers};

use vm_layout_generator::{
    EmitRefusal, GeneratedLayout, emit_arithmetic_shift_handler, layout_for_seed,
};

const HANDLER_VA: u64 = 0x0040_1000;

const CLANG_STACK_8_SP_16: [u8; 46] = [
    0x4c, 0x8b, 0x47, 0x08, 0x4c, 0x8b, 0x4f, 0x10, 0x41, 0x8b, 0x09, 0x49, 0x8b, 0x44, 0xc8, 0xf8,
    0x49, 0x8b, 0x54, 0xc8, 0xf0, 0x48, 0x83, 0xe0, 0x3f, 0x49, 0x89, 0xca, 0x48, 0x89, 0xc1, 0x48,
    0xd3, 0xfa, 0x4b, 0x89, 0x54, 0xd0, 0xf0, 0x41, 0xff, 0xca, 0x45, 0x89, 0x11, 0xc3,
];

const CLANG_STACK_40_SP_48: [u8; 46] = [
    0x4c, 0x8b, 0x47, 0x28, 0x4c, 0x8b, 0x4f, 0x30, 0x41, 0x8b, 0x09, 0x49, 0x8b, 0x44, 0xc8, 0xf8,
    0x49, 0x8b, 0x54, 0xc8, 0xf0, 0x48, 0x83, 0xe0, 0x3f, 0x49, 0x89, 0xca, 0x48, 0x89, 0xc1, 0x48,
    0xd3, 0xfa, 0x4b, 0x89, 0x54, 0xd0, 0xf0, 0x41, 0xff, 0xca, 0x45, 0x89, 0x11, 0xc3,
];

const CLANG_STACK_NEG24_SP_56: [u8; 46] = [
    0x4c, 0x8b, 0x47, 0xe8, 0x4c, 0x8b, 0x4f, 0x38, 0x41, 0x8b, 0x09, 0x49, 0x8b, 0x44, 0xc8, 0xf8,
    0x49, 0x8b, 0x54, 0xc8, 0xf0, 0x48, 0x83, 0xe0, 0x3f, 0x49, 0x89, 0xca, 0x48, 0x89, 0xc1, 0x48,
    0xd3, 0xfa, 0x4b, 0x89, 0x54, 0xd0, 0xf0, 0x41, 0xff, 0xca, 0x45, 0x89, 0x11, 0xc3,
];

fn build_layout(value_stack: i64, stack_pointer: i64) -> GeneratedLayout {
    vm_layout_generator::layout_from_offsets(value_stack, stack_pointer)
}

fn summarize(body: &[u8]) -> HandlerSemantics {
    let structure: VmStructure = VmStructure {
        bitness: Bitness::Bits64,
        image_base: HANDLER_VA,
        dispatcher_va: HANDLER_VA,
        dispatch_kind: DispatchKind::SwitchJumpTable,
        handlers: vec![HandlerEntry {
            index: 0,
            va: HANDLER_VA,
            code: body.to_vec(),
        }],
        bytecode_va: 0,
        bytecode: Vec::new(),
        entry_vip: 0,
        loaded: vec![Segment {
            va: HANDLER_VA,
            bytes: body.to_vec(),
            executable: true,
        }],
    };
    let mut summaries: Vec<HandlerSemantics> =
        fingerprint_handlers(&[], Bitness::Bits64, &structure).expect("one handler");
    summaries.remove(0)
}

#[test]
fn the_emitter_reproduces_what_a_real_assembler_produces() {
    let cases: [(i64, i64, &[u8]); 3] = [
        (8, 16, CLANG_STACK_8_SP_16.as_slice()),
        (40, 48, CLANG_STACK_40_SP_48.as_slice()),
        (-24, 56, CLANG_STACK_NEG24_SP_56.as_slice()),
    ];
    for (value_stack, stack_pointer, reference) in cases {
        let layout: GeneratedLayout = build_layout(value_stack, stack_pointer);
        let emitted: Vec<u8> =
            emit_arithmetic_shift_handler(&layout).expect("both offsets fit a byte displacement");
        assert_eq!(
            emitted.as_slice(),
            reference,
            "emitted bytes for stack={value_stack} sp={stack_pointer} differ from the assembler's"
        );
    }
}

#[test]
fn a_generated_layout_is_deterministic_for_a_seed() {
    for seed in 0..32_u64 {
        assert_eq!(layout_for_seed(seed), layout_for_seed(seed));
    }
}

#[test]
fn generated_layouts_are_not_all_the_same() {
    let distinct: std::collections::BTreeSet<(i64, i64)> = (0..64_u64)
        .map(|seed: u64| {
            let layout: GeneratedLayout = layout_for_seed(seed);
            (
                layout.offset(ContextRole::ValueStack),
                layout.offset(ContextRole::StackPointer),
            )
        })
        .collect();
    assert!(
        distinct.len() > 8,
        "the generator produced only {} distinct layouts across 64 seeds",
        distinct.len()
    );
}

#[test]
fn a_generated_layout_never_puts_two_roles_at_one_offset() {
    for seed in 0..256_u64 {
        let layout: GeneratedLayout = layout_for_seed(seed);
        assert_ne!(
            layout.offset(ContextRole::ValueStack),
            layout.offset(ContextRole::StackPointer),
            "seed {seed} placed two roles at one offset"
        );
    }
}

#[test]
fn an_offset_too_wide_for_the_encoding_refuses_instead_of_emitting_wrong_bytes() {
    let layout: GeneratedLayout = build_layout(4096, 16);
    let refusal: EmitRefusal =
        emit_arithmetic_shift_handler(&layout).expect_err("4096 does not fit a byte displacement");
    assert_eq!(
        refusal,
        EmitRefusal::DisplacementOutOfRange {
            role: ContextRole::ValueStack,
            offset: 4096,
        }
    );
}

#[test]
fn overlapping_roles_refuse_instead_of_emitting_an_ambiguous_handler() {
    let layout: GeneratedLayout = build_layout(24, 24);
    let refusal: EmitRefusal =
        emit_arithmetic_shift_handler(&layout).expect_err("two roles cannot share one offset");
    assert_eq!(
        refusal,
        EmitRefusal::OverlappingOffsets {
            first: ContextRole::ValueStack,
            second: ContextRole::StackPointer,
        }
    );
}

const MISMATCHED_LAYOUTS: &[(i64, i64)] = &[(40, 48), (-24, 56), (32, 40), (24, 8), (16, 8)];

const ADVANCE_PC_ONLY: [u8; 8] = [0x48, 0x8b, 0x47, 0x18, 0x83, 0x00, 0x01, 0xc3];

#[test]
fn the_assumed_layout_is_the_only_one_that_recovers() {
    let assumed: GeneratedLayout = build_layout(8, 16);
    let assumed_body: Vec<u8> =
        emit_arithmetic_shift_handler(&assumed).expect("assumed layout emits");
    assert_eq!(
        summarize(&assumed_body).micro_op,
        MicroOp::Binary { op: BinKind::Sar },
        "the layout run_probe hardcodes must classify"
    );
    for (value_stack, stack_pointer) in MISMATCHED_LAYOUTS {
        let shifted: GeneratedLayout = build_layout(*value_stack, *stack_pointer);
        let body: Vec<u8> = emit_arithmetic_shift_handler(&shifted).expect("shifted layout emits");
        assert_ne!(
            summarize(&body).micro_op,
            MicroOp::Binary { op: BinKind::Sar },
            "stack={value_stack} sp={stack_pointer} recovered the right operation by accident, \
             which means this fixture no longer demonstrates the layout dependence it exists for"
        );
    }
}

#[test]
fn a_mismatched_layout_is_refused_rather_than_reported_as_a_no_op() {
    for (value_stack, stack_pointer) in MISMATCHED_LAYOUTS {
        let shifted: GeneratedLayout = build_layout(*value_stack, *stack_pointer);
        let body: Vec<u8> = emit_arithmetic_shift_handler(&shifted).expect("shifted layout emits");
        assert_eq!(
            summarize(&body).micro_op,
            MicroOp::Unknown,
            "stack={value_stack} sp={stack_pointer}: a handler that shifts a value through a              context layout the probe does not model must be refused, not summarized"
        );
    }
}

#[test]
fn a_handler_that_only_advances_the_program_counter_is_a_no_op() {
    let semantics: HandlerSemantics = summarize(&ADVANCE_PC_ONLY);
    assert_eq!(semantics.micro_op, MicroOp::Nop);
    assert_eq!(semantics.pc_advance, 1);
}
