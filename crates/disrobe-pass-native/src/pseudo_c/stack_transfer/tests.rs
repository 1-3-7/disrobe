use super::*;
use crate::arch::{Arch, disassemble};

const BASE: u64 = 0x1000;

fn plan(bytes: &[u8], abi: Abi) -> Result<BTreeMap<u64, Stmt>> {
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86_64, BASE, bytes).expect("authored bytes");
    plan_stack_transfers(&insns, abi, &[])
}

fn refusal(bytes: &[u8], abi: Abi) -> String {
    match plan(bytes, abi) {
        Ok(moves) => panic!("expected a refusal, got {moves:?}"),
        Err(error) => error.to_string(),
    }
}

fn r64(reg: Reg) -> RegRef {
    RegRef {
        reg,
        width: Width::W64,
    }
}

#[test]
fn a_value_moved_through_push_and_pop_becomes_a_register_move() {
    let moves: BTreeMap<u64, Stmt> =
        plan(&[0x57, 0x58, 0xc3], Abi::SysV).expect("push rdi; pop rax; ret");
    assert_eq!(
        moves.get(&(BASE + 1)),
        Some(&Stmt::Assign {
            dest: r64(Reg::Rax),
            src: Source::Reg(r64(Reg::Rdi)),
        })
    );
    assert_eq!(moves.len(), 1);
}

#[test]
fn epilogue_restores_of_dead_registers_stay_frame_management() {
    let callee_saved: [u8; 11] = [
        0x53, 0x48, 0x89, 0xfb, 0x48, 0x89, 0xd8, 0x5b, 0xc3, 0x90, 0x90,
    ];
    assert!(
        plan(&callee_saved, Abi::SysV)
            .expect("push rbx; mov rbx, rdi; mov rax, rbx; pop rbx; ret")
            .is_empty()
    );
    let alignment: [u8; 5] = [0x50, 0x89, 0xf8, 0x59, 0xc3];
    assert!(
        plan(&alignment, Abi::SysV)
            .expect("push rax; mov eax, edi; pop rcx; ret")
            .is_empty()
    );
}

#[test]
fn unpaired_or_modified_stack_transfers_are_refused_by_name() {
    let modified: String = refusal(&[0x57, 0x48, 0x89, 0xf7, 0x58, 0xc3], Abi::SysV);
    assert!(
        modified.contains("after the register changed"),
        "{modified}"
    );
    let unpaired: String = refusal(&[0x58, 0xc3], Abi::SysV);
    assert!(unpaired.contains("no matching push"), "{unpaired}");
    let stack_pointer: String = refusal(&[0x57, 0x5c, 0xc3], Abi::SysV);
    assert!(stack_pointer.contains("`pop rsp`"), "{stack_pointer}");
}

#[test]
fn a_return_through_a_pushed_value_is_refused() {
    let pushed_return: String = refusal(&[0x57, 0xc3], Abi::SysV);
    assert!(
        pushed_return.contains("returns through the value"),
        "{pushed_return}"
    );
    assert!(
        plan(&[0x57, 0x48, 0x83, 0xc4, 0x08, 0xc3], Abi::SysV)
            .expect("push rdi; add rsp, 8; ret")
            .is_empty()
    );
}

#[test]
fn ms_x64_xmm_saves_are_frame_management_only_at_the_frame_edges() {
    let save: [u8; 5] = [0x0f, 0x29, 0x74, 0x24, 0x10];
    let restore: [u8; 5] = [0x0f, 0x28, 0x74, 0x24, 0x10];
    let clobber: [u8; 4] = [0xf2, 0x0f, 0x58, 0xf0];
    let read_back: [u8; 4] = [0x66, 0x0f, 0x28, 0xc6];

    let edges: Vec<u8> = [&save[..], &clobber, &restore, &[0xc3]].concat();
    assert!(
        plan(&edges, Abi::MsX64)
            .expect("save, clobber, restore, ret")
            .is_empty()
    );

    let late_save: Vec<u8> = [&clobber[..], &save, &restore, &[0xc3]].concat();
    let late: String = refusal(&late_save, Abi::MsX64);
    assert!(late.contains("after the body changed it"), "{late}");

    let live_restore: Vec<u8> = [&save[..], &clobber, &restore, &read_back, &[0xc3]].concat();
    let live: String = refusal(&live_restore, Abi::MsX64);
    assert!(live.contains("is read afterwards"), "{live}");
}
