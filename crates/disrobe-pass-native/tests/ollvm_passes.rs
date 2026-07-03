//! OLLVM deobfuscation tests.
//!
//! The authoritative non-circular gate is the `real_ollvm_*` set: it runs disrobe against
//! function bytes emitted by a real ollvm-16 compiler (`corpus/native/ollvm/*.bin`). The
//! `*_self_authored_*` tests assemble idealized shapes with iced-x86 and exercise the
//! linear-cmp-chain / clean-register-sequence path some non-OLLVM tools also emit; they are
//! NOT a substitute for the real-bytes gate (they once masked a capability gap by being
//! shaped to disrobe's own model) and must never be the only coverage for a recovery claim.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    BogusBranch, CffUnflattenReport, DeobfBits, ObfuscatorFamily, OpaqueResult, SubstitutionResult,
    detect_obfuscators, strip_ollvm_bcf, undo_ollvm_substitution, unflatten_ollvm,
};
use iced_x86::code_asm::{CodeAssembler, CodeLabel, cl, dword_ptr, eax, ecx, edx, esi, rbp};

const BASE: u64 = 0x1000;

#[test]
fn ollvm_cff_marker_detected_by_switch_var_symbol() {
    let mut buf: Vec<u8> = vec![0u8; 64];
    buf[0..10].copy_from_slice(b"switch_var");
    let hits = detect_obfuscators(&buf);
    assert!(
        hits.iter()
            .any(|h| h.family == ObfuscatorFamily::OllvmFlattening)
    );
}

fn flattened_function() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case_a: CodeLabel = asm.create_label();
    let mut case_b: CodeLabel = asm.create_label();
    let mut case_c: CodeLabel = asm.create_label();

    asm.mov(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.je(case_a).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.je(case_b).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.je(case_c).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut case_a).unwrap();
    asm.mov(eax, 1i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_b).unwrap();
    asm.add(eax, 7i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_c).unwrap();
    asm.ret().unwrap();
    asm.assemble(BASE).expect("assemble")
}

#[test]
fn ollvm_cff_unflatten_recovers_self_authored_linear_chain_shape() {
    let bytes: Vec<u8> = flattened_function();
    let report: CffUnflattenReport = unflatten_ollvm(DeobfBits::Bits64, BASE, &bytes, BASE);
    assert!(
        report.fully_recovered,
        "expected full recovery of the self-authored flattened function: {report:?}"
    );
    assert_eq!(report.recovered_blocks, 3);
    assert!(report.dispatcher_address.is_some());
    assert!(
        report.linear_order.windows(2).all(|w| w[0] < w[1]),
        "recovered blocks must be in source order: {:x?}",
        report.linear_order
    );
}

#[test]
fn ollvm_bcf_folds_self_authored_opaque_always_even_predicate() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut real: CodeLabel = asm.create_label();
    asm.mov(ecx, eax).unwrap();
    asm.imul_2(ecx, eax).unwrap();
    asm.add(ecx, eax).unwrap();
    asm.and(ecx, 1i32).unwrap();
    asm.cmp(ecx, 0i32).unwrap();
    asm.je(real).unwrap();
    asm.set_label(&mut real).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let block: &[u8] = &bytes[..bytes.len() - 1];
    let result: BogusBranch =
        strip_ollvm_bcf(DeobfBits::Bits64, BASE, block).expect("analyzable opaque branch");
    assert_eq!(result.result, OpaqueResult::AlwaysTaken);
}

#[test]
fn ollvm_substitution_folds_self_authored_sequence_back_to_addition() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.xor(ecx, edx).unwrap();
    asm.mov(eax, esi).unwrap();
    asm.and(eax, edx).unwrap();
    asm.add(eax, eax).unwrap();
    asm.add(eax, ecx).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let result: SubstitutionResult =
        undo_ollvm_substitution(DeobfBits::Bits64, BASE, &bytes).expect("arith lifts");
    assert!(result.changed && result.proven);
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn ollvm_substitution_folds_shift_encoded_carry_back_to_addition() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(ecx, esi).unwrap();
    asm.xor(ecx, edx).unwrap();
    asm.mov(eax, esi).unwrap();
    asm.and(eax, edx).unwrap();
    asm.shl(eax, 1u32).unwrap();
    asm.add(eax, ecx).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let result: SubstitutionResult = undo_ollvm_substitution(DeobfBits::Bits64, BASE, &bytes)
        .expect("shift-encoded arith lifts");
    assert!(
        result.changed && result.proven,
        "(x ^ y) + ((x & y) << 1) is x + y and must fold with a re-execution proof: {result:?}"
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

#[test]
fn ollvm_substitution_folds_through_movzx_loaded_operands() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.movzx(eax, cl).unwrap();
    asm.mov(edx, eax).unwrap();
    asm.xor(eax, edx).unwrap();
    let bytes: Vec<u8> = asm.assemble(BASE).expect("assemble");
    let result: SubstitutionResult = undo_ollvm_substitution(DeobfBits::Bits64, BASE, &bytes)
        .expect("a movzx-loaded byte operand must not abort the arithmetic lift");
    assert!(
        result.changed && result.proven,
        "(c & 0xff) ^ (c & 0xff) is 0 and must fold with a re-execution proof: {result:?}"
    );
    assert!(result.simplified_nodes < result.original_nodes);
}

fn corpus(name: &str) -> std::path::PathBuf {
    let mut p: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("native");
    p.push("ollvm");
    p.push(name);
    p
}

#[test]
fn real_ollvm_cff_unflatten_round_trip() {
    let Ok(flattened): std::io::Result<Vec<u8>> = std::fs::read(corpus("classify_fla.bin")) else {
        eprintln!("skip: real OLLVM classify_fla.bin absent");
        return;
    };
    let detected = detect_obfuscators(&flattened);
    assert!(
        detected
            .iter()
            .any(|h| h.family == ObfuscatorFamily::OllvmFlattening),
        "disrobe must DETECT real ollvm-16 -fla by its dispatcher shape (no symbols): {detected:?}"
    );
    let plain: Vec<u8> = std::fs::read(corpus("classify_plain.bin")).expect("plain present");
    assert!(
        !detect_obfuscators(&plain)
            .iter()
            .any(|h| h.family == ObfuscatorFamily::OllvmFlattening),
        "plain (unobfuscated) classify must NOT be flagged as flattened (no false positive)"
    );

    let base: u64 = 0x1000;
    let report: CffUnflattenReport = unflatten_ollvm(DeobfBits::Bits64, base, &flattened, base);
    assert!(
        report.fully_recovered,
        "disrobe must fully recover the REAL ollvm-16 -fla classify(): {report:?}"
    );
    assert!(report.dispatcher_address.is_some());
    assert_eq!(
        report.state_variable_register.as_deref(),
        Some("R9D"),
        "real OLLVM uses a register state variable, not a stack slot: {report:?}"
    );
    assert!(
        report.recovered_blocks >= 3,
        "all three original classify blocks must be recovered: {report:?}"
    );
    assert!(
        report.linear_order.windows(2).all(|w| w[0] < w[1]),
        "recovered blocks must be in source order: {:x?}",
        report.linear_order
    );
}

#[test]
fn real_ollvm_cff_recovers_a_flattened_loop() {
    let Ok(flattened): std::io::Result<Vec<u8>> = std::fs::read(corpus("sumto_fla.bin")) else {
        eprintln!("skip: real OLLVM sumto_fla.bin absent");
        return;
    };
    let base: u64 = 0x1000;
    let report: CffUnflattenReport = unflatten_ollvm(DeobfBits::Bits64, base, &flattened, base);
    assert!(
        report.fully_recovered,
        "disrobe must fully recover the REAL ollvm-16 -fla for-loop sum_to() - the loop's \
         register-copy + cmov state transition (mov r9d,r10d; cmovg r10d,r8d): {report:?}"
    );
    assert!(
        report.recovered_blocks >= 4,
        "the loop init + header + body + exit blocks must all recover: {report:?}"
    );
    assert!(
        detect_obfuscators(&flattened)
            .iter()
            .any(|h| h.family == ObfuscatorFamily::OllvmFlattening),
        "the flattened loop must be detected as OLLVM CFF"
    );
}

#[test]
fn real_ollvm_sub_lifts_through_stack_slots() {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus("sub_mixer_O0.bin")) else {
        eprintln!("skip: real OLLVM sub_mixer_O0.bin absent");
        return;
    };
    let Some(result): Option<SubstitutionResult> =
        undo_ollvm_substitution(DeobfBits::Bits64, 0x1000, &bytes)
    else {
        panic!(
            "disrobe must LIFT the real -O0 -sub mixer through its stack slots \
             (mov [rsp+N],reg / mov reg,[rsp+N]); before the fix this returned None"
        );
    };
    assert_eq!(
        result.dest, "EAX",
        "the recovered value is the function result in EAX, not a frame register: {result:?}"
    );
    assert!(
        result.original_expr.contains("v0") && result.original_expr.contains("v1"),
        "both arguments must survive the stack round-trip into the lifted expression: {result:?}"
    );
}

#[test]
fn real_ollvm_bcf_folds_opaque_predicate_or_real_condition() {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(corpus("bcf_classify_O0.bin")) else {
        eprintln!("skip: real OLLVM bcf_classify_O0.bin absent");
        return;
    };
    let block: &[u8] = first_predicate_block(&bytes);
    let Some(branch): Option<BogusBranch> = strip_ollvm_bcf(DeobfBits::Bits64, BASE, block) else {
        panic!(
            "disrobe must fold the real -O0 -bcf opaque predicate. ollvm ORs an \
             always-even x*(x-1)&1==0 predicate (materialized via sete/setl/or/test) \
             with the real branch condition; before the fix this returned None"
        );
    };
    assert_eq!(
        branch.result,
        OpaqueResult::AlwaysTaken,
        "the opaque-OR-real predicate is always true, so the real edge is always taken: {branch:?}"
    );
    assert!(
        branch.dead_target.is_some() && branch.live_target.is_some(),
        "folding must name both the bogus dead edge and the surviving live edge: {branch:?}"
    );
}

fn first_predicate_block(bytes: &[u8]) -> &[u8] {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut dec: Decoder<'_> = Decoder::with_ip(64, bytes, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut end: usize = bytes.len();
    while dec.can_decode() {
        dec.decode_out(&mut insn);
        if insn.flow_control() == FlowControl::ConditionalBranch {
            end = usize::try_from(insn.ip() - BASE).unwrap_or(bytes.len()) + insn.len();
            break;
        }
    }
    &bytes[..end]
}
