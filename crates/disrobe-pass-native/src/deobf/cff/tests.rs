use iced_x86::code_asm::{CodeAssembler, CodeLabel, dword_ptr, eax, rbp};

use super::*;

const BASE: u64 = 0x1000;

fn assemble(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(BASE).expect("assemble flattened function")
}

fn flattened_three_block_chain() -> Vec<u8> {
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
    asm.add(eax, 2i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case_c).unwrap();
    asm.ret().unwrap();

    assemble(&mut asm)
}

fn linear_unflattened_baseline() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    asm.mov(eax, 1i32).unwrap();
    asm.add(eax, 2i32).unwrap();
    asm.ret().unwrap();
    assemble(&mut asm)
}

#[test]
fn recovers_linear_order_from_flattened_function() {
    let bytes: Vec<u8> = flattened_three_block_chain();
    let outcome: CffOutcome = unflatten(64, BASE, &bytes, BASE);
    let CffOutcome::Recovered(rec) = outcome else {
        panic!("flattened function not recognized as flattened");
    };
    assert!(
        rec.fully_recovered,
        "expected full recovery, unresolved = {:?}, order = {:x?}",
        rec.unresolved_blocks, rec.linear_order
    );
    assert_eq!(
        rec.state_case_count, 3,
        "dispatcher should expose three state cases"
    );
    assert_eq!(
        rec.recovered_block_count, 3,
        "three real blocks (A, B, C) should be on the linear path"
    );
    assert!(
        rec.linear_order.windows(2).all(|w: &[u64]| w[0] < w[1]),
        "OLLVM -O0 lays case blocks in source order; recovered order = {:x?}",
        rec.linear_order
    );
}

#[test]
fn recovered_listing_drops_state_machinery_and_keeps_real_work() {
    let bytes: Vec<u8> = flattened_three_block_chain();
    let CffOutcome::Recovered(rec) = unflatten(64, BASE, &bytes, BASE) else {
        panic!("not flattened");
    };
    assert!(
        rec.listing.contains("mov eax,1") || rec.listing.contains("mov eax, 1"),
        "real instruction `mov eax,1` missing from cleaned listing:\n{}",
        rec.listing
    );
    assert!(
        rec.listing.contains("add eax,2") || rec.listing.contains("add eax, 2"),
        "real instruction `add eax,2` missing from cleaned listing:\n{}",
        rec.listing
    );
    assert!(
        !rec.listing.contains("[rbp-4],1") && !rec.listing.contains("[rbp-04h],1"),
        "state-store machinery leaked into the cleaned listing:\n{}",
        rec.listing
    );
}

#[test]
fn recovered_real_work_matches_unflattened_baseline() {
    let flattened: Vec<u8> = flattened_three_block_chain();
    let CffOutcome::Recovered(rec) = unflatten(64, BASE, &flattened, BASE) else {
        panic!("not flattened");
    };
    let baseline: Vec<u8> = linear_unflattened_baseline();
    let mut baseline_decoder: iced_x86::Decoder<'_> =
        iced_x86::Decoder::with_ip(64, &baseline, BASE, iced_x86::DecoderOptions::NONE);
    let mut baseline_mnemonics: Vec<iced_x86::Mnemonic> = Vec::new();
    while baseline_decoder.can_decode() {
        let mut insn: iced_x86::Instruction = iced_x86::Instruction::default();
        baseline_decoder.decode_out(&mut insn);
        baseline_mnemonics.push(insn.mnemonic());
    }
    for mnem in [iced_x86::Mnemonic::Mov, iced_x86::Mnemonic::Add] {
        assert!(
            baseline_mnemonics.contains(&mnem),
            "baseline must contain {mnem:?}"
        );
    }
    assert!(
        rec.listing.to_lowercase().contains("mov") && rec.listing.to_lowercase().contains("add"),
        "recovered listing must carry the same real ops as the hand-written linear baseline"
    );
}

#[test]
fn conditional_dispatch_recovers_both_arms() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case0: CodeLabel = asm.create_label();
    let mut case1: CodeLabel = asm.create_label();
    let mut case2: CodeLabel = asm.create_label();
    let mut case3: CodeLabel = asm.create_label();
    let mut go_two: CodeLabel = asm.create_label();

    asm.mov(dword_ptr(rbp - 8), 0i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(dword_ptr(rbp - 8), 0i32).unwrap();
    asm.je(case0).unwrap();
    asm.cmp(dword_ptr(rbp - 8), 1i32).unwrap();
    asm.je(case1).unwrap();
    asm.cmp(dword_ptr(rbp - 8), 2i32).unwrap();
    asm.je(case2).unwrap();
    asm.cmp(dword_ptr(rbp - 8), 3i32).unwrap();
    asm.je(case3).unwrap();
    asm.ret().unwrap();

    asm.set_label(&mut case0).unwrap();
    asm.add(eax, 1i32).unwrap();
    asm.cmp(eax, 5i32).unwrap();
    asm.jg(go_two).unwrap();
    asm.mov(dword_ptr(rbp - 8), 1i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut go_two).unwrap();
    asm.mov(dword_ptr(rbp - 8), 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case1).unwrap();
    asm.add(eax, 10i32).unwrap();
    asm.mov(dword_ptr(rbp - 8), 3i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case2).unwrap();
    asm.add(eax, 20i32).unwrap();
    asm.mov(dword_ptr(rbp - 8), 3i32).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case3).unwrap();
    asm.ret().unwrap();

    let bytes: Vec<u8> = assemble(&mut asm);
    let CffOutcome::Recovered(rec) = unflatten(64, BASE, &bytes, BASE) else {
        panic!("conditional flattened function not recognized");
    };
    assert_eq!(rec.state_case_count, 4);
    assert!(
        rec.recovered_block_count >= 4,
        "entry plus both arms of the branch plus the join must be recovered, got {} blocks ({:x?})",
        rec.recovered_block_count,
        rec.linear_order
    );
    assert!(
        rec.listing.contains("conditional: taken state"),
        "the recovered listing must annotate the two-way state branch:\n{}",
        rec.listing
    );
}

#[test]
fn plain_linear_function_is_not_flattened() {
    let bytes: Vec<u8> = linear_unflattened_baseline();
    assert_eq!(
        unflatten(64, BASE, &bytes, BASE),
        CffOutcome::NotFlattened,
        "an honest linear function must not be misreported as flattened"
    );
}

fn flattened_jump_table_dispatch(table_va: u64) -> (Vec<u8>, Vec<u64>) {
    use iced_x86::code_asm::{qword_ptr, r8};

    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case_a: CodeLabel = asm.create_label();
    let mut case_b: CodeLabel = asm.create_label();
    let mut case_c: CodeLabel = asm.create_label();
    let mut done: CodeLabel = asm.create_label();

    asm.mov(r8, 0i64).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut dispatcher).unwrap();
    asm.jmp(qword_ptr(r8 * 8 + table_va)).unwrap();

    asm.set_label(&mut case_a).unwrap();
    asm.mov(eax, 11i32).unwrap();
    asm.mov(r8, 1i64).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case_b).unwrap();
    asm.add(eax, 22i32).unwrap();
    asm.mov(r8, 2i64).unwrap();
    asm.jmp(dispatcher).unwrap();

    asm.set_label(&mut case_c).unwrap();
    asm.add(eax, 33i32).unwrap();
    asm.jmp(done).unwrap();

    asm.set_label(&mut done).unwrap();
    asm.ret().unwrap();

    let code: Vec<u8> = asm.assemble(BASE).expect("assemble jump-table function");
    let labels: Vec<u64> = case_block_starts(&code);
    (code, labels)
}

fn case_block_starts(code: &[u8]) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, BASE, DecoderOptions::NONE);
    let mut dispatcher_va: Option<u64> = None;
    let mut starts: Vec<u64> = Vec::new();
    let mut pending_target: Option<u64> = None;
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        let ip: u64 = decoder.ip();
        decoder.decode_out(&mut insn);
        if pending_target.take() == Some(ip) {
            starts.push(ip);
        }
        match insn.flow_control() {
            FlowControl::UnconditionalBranch => {
                let target: u64 = insn.near_branch_target();
                if dispatcher_va.is_none() {
                    dispatcher_va = Some(target);
                } else if Some(target) == dispatcher_va {
                    pending_target = Some(insn.next_ip());
                }
            }
            FlowControl::IndirectBranch => {
                pending_target = Some(insn.next_ip());
            }
            _ => {}
        }
    }
    starts.truncate(3);
    starts
}

#[test]
fn jump_table_dispatcher_is_linearized() {
    let probe: (Vec<u8>, Vec<u64>) = flattened_jump_table_dispatch(0);
    let code_len: u64 = probe.0.len() as u64;
    let table_va: u64 = BASE + code_len;

    let (code, targets): (Vec<u8>, Vec<u64>) = flattened_jump_table_dispatch(table_va);
    let mut bytes: Vec<u8> = code;
    while bytes.len() as u64 != table_va - BASE {
        bytes.push(0x90);
    }
    for target in &targets {
        bytes.extend_from_slice(&target.to_le_bytes());
    }

    let outcome: CffOutcome = unflatten(64, BASE, &bytes, BASE);
    let CffOutcome::Recovered(rec) = outcome else {
        panic!("jump-table flattened function not recognized as flattened");
    };
    assert_eq!(
        rec.state_case_count, 3,
        "the three-entry jump table must expose three state cases"
    );
    assert!(
        rec.recovered_block_count >= 3,
        "all three real case blocks must be linearized, got {} ({:x?})",
        rec.recovered_block_count,
        rec.linear_order
    );
    let listing: String = rec.listing.to_lowercase();
    assert!(
        listing.contains("mov eax,0bh") || listing.contains("mov eax, 0bh"),
        "case A real work (mov eax,11) must survive in the cleaned listing:\n{}",
        rec.listing
    );
    assert!(
        listing.contains("add eax,16h") && listing.contains("add eax,21h"),
        "case B (add 22) and case C (add 33) real work must survive:\n{}",
        rec.listing
    );
}

#[test]
fn single_compare_is_not_a_dispatcher() {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut tail: CodeLabel = asm.create_label();
    asm.cmp(eax, 7i32).unwrap();
    asm.je(tail).unwrap();
    asm.add(eax, 1i32).unwrap();
    asm.set_label(&mut tail).unwrap();
    asm.ret().unwrap();
    let bytes: Vec<u8> = assemble(&mut asm);
    assert_eq!(
        unflatten(64, BASE, &bytes, BASE),
        CffOutcome::NotFlattened,
        "a lone branch is not a flattening dispatcher"
    );
}
