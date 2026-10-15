use super::super::{Abi, LeafRecovery, ParameterBinding, Reg, recover_leaf_function_abi};
use super::{I386Convention, I386Signature};

const BASE: u64 = 0x1000;

fn recover(code: &[u8]) -> LeafRecovery {
    recover_leaf_function_abi(code, BASE, Abi::I386)
        .unwrap_or_else(|error| panic!("{code:02x?} must recover: {error}"))
}

fn refusal(code: &[u8]) -> String {
    match recover_leaf_function_abi(code, BASE, Abi::I386) {
        Ok(recovery) => panic!(
            "{code:02x?} must be refused, recovered:\n{}",
            recovery.source
        ),
        Err(error) => error.to_string(),
    }
}

fn signature(recovery: &LeafRecovery) -> I386Signature {
    recovery
        .signature
        .i386()
        .expect("an x86-32 recovery carries its convention")
}

fn registers(recovery: &LeafRecovery) -> Vec<Reg> {
    recovery
        .signature
        .parameter_bindings()
        .iter()
        .map(|binding: &ParameterBinding| match binding {
            ParameterBinding::Integer { register, .. } => *register,
            other => panic!("x86-32 parameters are integers, not {other:?}"),
        })
        .collect()
}

#[test]
fn a_cdecl_leaf_reads_its_arguments_from_the_caller_stack() {
    let recovery: LeafRecovery = recover(&[0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3]);
    let found: I386Signature = signature(&recovery);
    assert_eq!(found.convention, I386Convention::Cdecl);
    assert_eq!((found.stack_arguments, found.callee_pop_bytes), (2, 0));
    assert_eq!(
        registers(&recovery),
        vec![Reg::X86Stack0, Reg::X86Stack1],
        "{}",
        recovery.source
    );
    assert!(
        recovery
            .source
            .contains("uint32_t recovered(uint32_t a0, uint32_t a1)"),
        "{}",
        recovery.source
    );
}

#[test]
fn a_stdcall_callee_pops_exactly_its_stack_arguments() {
    let recovery: LeafRecovery = recover(&[
        0x8b, 0x44, 0x24, 0x04, 0x2b, 0x44, 0x24, 0x08, 0xc2, 0x0c, 0x00,
    ]);
    let found: I386Signature = signature(&recovery);
    assert_eq!(found.convention, I386Convention::Stdcall);
    assert_eq!((found.stack_arguments, found.callee_pop_bytes), (3, 12));
    assert!(
        recovery.source.contains(
            "uint32_t __attribute__((stdcall)) recovered(uint32_t a0, uint32_t a1, uint32_t a2)"
        ),
        "a stdcall callee that pops twelve bytes keeps its unread third argument: {}",
        recovery.source
    );
}

#[test]
fn a_fastcall_callee_takes_ecx_and_edx_before_its_stack_arguments() {
    let recovery: LeafRecovery =
        recover(&[0x8d, 0x04, 0x11, 0x2b, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00]);
    let found: I386Signature = signature(&recovery);
    assert_eq!(found.convention, I386Convention::Fastcall);
    assert_eq!(
        registers(&recovery),
        vec![Reg::Rcx, Reg::Rdx, Reg::X86Stack0],
        "{}",
        recovery.source
    );
}

#[test]
fn a_thiscall_method_takes_this_in_ecx_and_pops_its_stack_arguments() {
    let recovery: LeafRecovery = recover(&[0x8b, 0x01, 0x03, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00]);
    let found: I386Signature = signature(&recovery);
    assert_eq!(found.convention, I386Convention::Thiscall);
    assert_eq!(registers(&recovery), vec![Reg::Rcx, Reg::X86Stack0]);
    assert!(
        recovery.source.contains("__attribute__((thiscall))"),
        "{}",
        recovery.source
    );
}

#[test]
fn a_sign_extended_result_returns_the_edx_eax_pair() {
    let recovery: LeafRecovery = recover(&[0x8b, 0x44, 0x24, 0x04, 0x99, 0xc3]);
    assert!(signature(&recovery).returns_edx_eax);
    assert_eq!(recovery.return_width_bits, 64);
    assert!(
        recovery.source.contains("uint64_t recovered(uint32_t a0)"),
        "{}",
        recovery.source
    );
}

#[test]
fn an_ebp_frame_with_a_saved_register_drops_the_save_and_restore() {
    let recovery: LeafRecovery = recover(&[
        0x55, 0x89, 0xe5, 0x53, 0x8b, 0x5d, 0x08, 0x8d, 0x43, 0x01, 0x5b, 0x5d, 0xc3,
    ]);
    assert_eq!(registers(&recovery), vec![Reg::X86Stack0]);
    assert!(
        !recovery.source.contains("stack_frame"),
        "a frame that only saves ebp and ebx needs no stack array: {}",
        recovery.source
    );
}

#[test]
fn call_next_and_pop_resolve_a_pc_relative_access_to_an_absolute_address() {
    let recovery: LeafRecovery = recover(&[
        0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x8b, 0x80, 0x00, 0x01, 0x00, 0x00, 0xc3,
    ]);
    assert!(
        recovery.source.contains("0x1105"),
        "the load names the absolute address 0x1005 + 0x100: {}",
        recovery.source
    );
}

#[test]
fn an_x87_result_is_refused_by_name() {
    let error: String = refusal(&[0xd9, 0x44, 0x24, 0x04, 0xc3]);
    assert!(error.contains("x87"), "{error}");
}

#[test]
fn a_register_argument_in_eax_is_refused_as_an_unmodelled_convention() {
    let error: String = refusal(&[0x8d, 0x40, 0x01, 0xc3]);
    assert!(error.contains("regparm"), "{error}");
}

#[test]
fn a_tail_jump_out_of_the_function_is_refused() {
    let error: String = refusal(&[0xe9, 0xfb, 0x3f, 0x00, 0x00]);
    assert!(error.contains("tail call"), "{error}");
}

#[test]
fn realigning_the_stack_without_a_frame_pointer_is_refused() {
    let error: String = refusal(&[0x83, 0xe4, 0xf0, 0x31, 0xc0, 0xc3]);
    assert!(error.contains("realigned"), "{error}");
}

#[test]
fn returning_with_an_unbalanced_stack_is_refused() {
    let error: String = refusal(&[0x83, 0xec, 0x04, 0x31, 0xc0, 0xc3]);
    assert!(error.contains("away from its entry value"), "{error}");
}

#[test]
fn a_call_without_the_callee_image_is_refused() {
    let error: String = refusal(&[0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3]);
    assert!(error.contains("pops"), "{error}");
}

#[test]
fn a_callee_that_reads_past_the_bytes_it_pops_is_refused() {
    let error: String = refusal(&[0x8b, 0x44, 0x24, 0x08, 0xc2, 0x04, 0x00]);
    assert!(error.contains("belongs to its caller"), "{error}");
}

#[test]
fn a_double_shift_by_cl_is_refused() {
    let error: String = refusal(&[0x8b, 0x44, 0x24, 0x04, 0x0f, 0xa5, 0xc2, 0xc3]);
    assert!(error.contains("by cl"), "{error}");
}

#[test]
fn writing_the_stack_pointer_from_a_register_is_refused() {
    let error: String = refusal(&[0x89, 0xc4, 0xc3]);
    assert!(error.contains("stack pointer is written"), "{error}");
}
