#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{LeafRecovery, PseudoAbi, recover_leaf_function_abi};

#[path = "support/compiler_toolchain.rs"]
#[allow(clippy::redundant_pub_crate)]
mod compiler_toolchain;
#[path = "support/object_symbol.rs"]
#[allow(clippy::redundant_pub_crate)]
mod object_symbol;

use object_symbol::function_code;

const HOST_ABI: PseudoAbi = if cfg!(windows) {
    PseudoAbi::MsX64
} else {
    PseudoAbi::SysV
};

const RANDOM_STATES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Equivalent,
    Refused(&'static str),
}

struct Stub {
    name: &'static str,
    body: &'static str,
    expect: Expect,
    ms_x64_only: bool,
}

const STUBS: &[Stub] = &[
    Stub {
        name: "opr_r10w_add",
        body: "mov r10, $a0\nmov r11, $a1\nadd r10w, r11w\nmov rax, r10\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_r12w_move",
        body: "push r12\nmov r12, $a0\nmov r11, $a1\nmov r12w, r11w\nmov rax, r12\npop r12\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_r13w_sub",
        body: "mov rax, $a1\npush r13\nmov r13, $a0\nsub r13w, ax\nmov rax, r13\npop r13\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_r14w_zext",
        body: "push r14\nmov r14, $a0\nmovzx eax, r14w\nadd rax, $a1\npop r14\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_r15w_xor",
        body: "push r15\nmov r15, $a0\nxor r15w, $a1w\nmov rax, r15\npop r15\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_bpl_add",
        body: "push rbp\nmov rbp, $a0\nadd bpl, $a1b\nmov rax, rbp\npop rbp\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_bp_xor",
        body: "push rbp\nmov rbp, $a0\nxor bp, $a1w\nmov rax, rbp\npop rbp\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_push_pop_move",
        body: "push $a0\npop rax\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_push_pop_swap",
        body: "push $a0\npush $a1\npop rax\npop rcx\nsub rax, rcx\nret",
        expect: Expect::Equivalent,
        ms_x64_only: false,
    },
    Stub {
        name: "opr_high_byte_add_al_ah",
        body: "mov rax, $a0\nadd al, ah\nret",
        expect: Expect::Refused("high-byte register `ah`"),
        ms_x64_only: false,
    },
    Stub {
        name: "opr_high_byte_sub_al_dh",
        body: "mov rdx, $a1\nmov rax, $a0\nsub al, dh\nret",
        expect: Expect::Refused("high-byte register `dh`"),
        ms_x64_only: false,
    },
    Stub {
        name: "opr_high_byte_cmp_cl_ch",
        body: "mov rcx, $a0\nxor eax, eax\ncmp cl, ch\nsetb al\nret",
        expect: Expect::Refused("high-byte register `ch`"),
        ms_x64_only: false,
    },
    Stub {
        name: "opr_high_byte_xor_al_bh",
        body: "push rbx\nmov rbx, $a0\nmov rax, $a1\nxor al, bh\npop rbx\nret",
        expect: Expect::Refused("high-byte register `bh`"),
        ms_x64_only: false,
    },
    Stub {
        name: "opr_push_pop_modified",
        body: "push $a0\nmov $a0, $a1\npop rax\nadd rax, $a0\nret",
        expect: Expect::Refused("after the register changed"),
        ms_x64_only: false,
    },
    Stub {
        name: "opr_xmm6_mid_body_spill",
        body: "sub rsp, 40\nmovaps [rsp], xmm6\nmovq xmm6, $a0\nmovaps [rsp+16], xmm6\nmovq xmm6, $a1\nmovaps xmm6, [rsp+16]\nmovq rax, xmm6\nmovaps xmm6, [rsp]\nadd rsp, 40\nret",
        expect: Expect::Refused("a mid-body xmm spill"),
        ms_x64_only: true,
    },
];

fn active_stubs() -> impl Iterator<Item = &'static Stub> {
    STUBS
        .iter()
        .filter(|stub: &&Stub| !stub.ms_x64_only || HOST_ABI == PseudoAbi::MsX64)
}

fn stub_asm() -> String {
    let (a0, a1, a1w, a1b): (&str, &str, &str, &str) = if HOST_ABI == PseudoAbi::MsX64 {
        ("rcx", "rdx", "dx", "dl")
    } else {
        ("rdi", "rsi", "si", "sil")
    };
    let mut asm: String = String::from("\t.intel_syntax noprefix\n\t.text\n");
    for stub in active_stubs() {
        let body: String = stub
            .body
            .replace("$a0", a0)
            .replace("$a1w", a1w)
            .replace("$a1b", a1b)
            .replace("$a1", a1);
        let name: &str = stub.name;
        if cfg!(windows) {
            let _ = writeln!(
                asm,
                "\t.globl {name}\n\t.def {name}; .scl 2; .type 32; .endef\n{name}:"
            );
        } else {
            let _ = writeln!(asm, "\t.globl {name}\n\t.type {name}, @function\n{name}:");
        }
        for line in body.lines() {
            let _ = writeln!(asm, "\t{line}");
        }
        if !cfg!(windows) {
            let _ = writeln!(asm, "\t.size {name}, .-{name}");
        }
    }
    asm
}

fn driver(recovered_decls: &str, flag_decls: &str, driver_body: &str) -> String {
    format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n#include <string.h>\n{recovered_decls}\n\
         static uint64_t state = 0x9e3779b97f4a7c15ULL;\n\
         static uint64_t next_state(void) {{\n\
         \x20   state ^= state >> 12; state ^= state << 25; state ^= state >> 27;\n\
         \x20   return state * 0x2545f4914f6cdd1dULL;\n\
         }}\n\
         static uint64_t draw(void) {{\n\
         \x20   uint64_t value = next_state();\n\
         \x20   switch (next_state() & 7) {{\n\
         \x20   case 0: return value | 0xffffffffffff0000ULL;\n\
         \x20   case 1: return value & 0xffffffffffff00ffULL;\n\
         \x20   case 2: return value | 0x000000000000ff00ULL;\n\
         \x20   case 3: return value & 0xffffffff0000ffffULL;\n\
         \x20   default: return value;\n\
         \x20   }}\n\
         }}\n\
         int main(void) {{\n\
         \x20   int mismatched = 0;\n\
         {flag_decls}\
         \x20   for (size_t k = 0; k < {RANDOM_STATES}; k++) {{\n\
         \x20       unsigned long long x = draw(), y = draw();\n\
         {driver_body}\
         \x20   }}\n\
         \x20   if (mismatched) return 1;\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    )
}

fn recovered_decl(stub: &Stub, recovery: &LeafRecovery) -> String {
    recovery
        .source
        .replacen(
            "uint64_t recovered(",
            &format!("uint64_t rec_{}(", stub.name),
            1,
        )
        .lines()
        .filter(|line: &&str| !line.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn comparison(stub: &Stub, recovery: &LeafRecovery) -> String {
    let arity: usize = recovery.signature.callable_arity();
    assert!(
        arity <= 2,
        "{} recovered with arity {arity}, above the two authored arguments: {}",
        stub.name,
        recovery.source
    );
    let args: String = ["(uint64_t)x", "(uint64_t)y"][..arity].join(", ");
    let mask: String = if recovery.return_width_bits >= 64 {
        "0xffffffffffffffffULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1_u128 << recovery.return_width_bits) - 1)
    };
    format!(
        "\x20       {{\n\
         \x20           unsigned long long want = {name}(x, y) & {mask};\n\
         \x20           unsigned long long got = rec_{name}({args}) & {mask};\n\
         \x20           if (want != got && !bad_{name}) {{ bad_{name} = 1; mismatched = 1; printf(\"MISMATCH {name} x=%llx y=%llx want=%llx got=%llx\\n\", x, y, want, got); }}\n\
         \x20       }}\n",
        name = stub.name,
    )
}

#[test]
#[cfg_attr(
    any(target_os = "macos", not(target_arch = "x86_64")),
    ignore = "the operand and stack-transfer differential executes assembled x86-64 ground-truth stubs"
)]
fn low_registers_and_stack_transfers_recompile_equal_and_high_bytes_refuse() {
    let compiler: String = compiler_toolchain::require_any(&["gcc", "clang", "cc"]);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-operand-registers").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let asm: String = stub_asm();
    let asm_path: PathBuf = dir.join("operand_stubs.s");
    std::fs::write(&asm_path, asm.as_bytes()).expect("write operand stubs");
    let object_path: PathBuf = dir.join("operand_stubs.o");
    let assemble: std::process::Output = Command::new(&compiler)
        .args(["-c", "-o"])
        .arg(&object_path)
        .arg(&asm_path)
        .output()
        .expect("invoke the compiler to assemble the operand stubs");
    assert!(
        assemble.status.success(),
        "{compiler} could not assemble the intel-syntax operand stubs: {}\n{asm}",
        String::from_utf8_lossy(&assemble.stderr)
    );
    let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read operand stub object");

    let mut failures: Vec<String> = Vec::new();
    let mut recovered_decls: String = String::new();
    let mut flag_decls: String = String::new();
    let mut driver_body: String = String::new();
    let mut graded: usize = 0;
    for stub in active_stubs() {
        let (code, base): (Vec<u8>, u64) = function_code(&object_bytes, stub.name)
            .unwrap_or_else(|| panic!("{} is not in the assembled object", stub.name));
        let outcome = recover_leaf_function_abi(&code, base, HOST_ABI);
        if let Ok(recovery) = &outcome {
            recovered_decls.push_str(&recovered_decl(stub, recovery));
            let _ = writeln!(
                recovered_decls,
                "\nextern unsigned long long {}(unsigned long long, unsigned long long);",
                stub.name
            );
            let _ = writeln!(flag_decls, "    int bad_{} = 0;", stub.name);
            driver_body.push_str(&comparison(stub, recovery));
            graded += 1;
        }
        match (stub.expect, outcome) {
            (Expect::Equivalent, Ok(_)) => {}
            (Expect::Equivalent, Err(error)) => {
                failures.push(format!("{} must lift but was refused: {error}", stub.name));
            }
            (Expect::Refused(reason), Err(error)) => {
                let text: String = error.to_string();
                if !text.contains(reason) {
                    failures.push(format!(
                        "{} was refused for the wrong reason (want `{reason}`): {text}",
                        stub.name
                    ));
                }
            }
            (Expect::Refused(reason), Ok(recovery)) => {
                failures.push(format!(
                    "{} must be refused (`{reason}`) but lifted:\n{}",
                    stub.name, recovery.source
                ));
            }
        }
    }

    let driver_source: String = driver(&recovered_decls, &flag_decls, &driver_body);
    let driver_path: PathBuf = dir.join("operand_driver.c");
    std::fs::write(&driver_path, driver_source.as_bytes()).expect("write operand driver");
    let harness: PathBuf = dir.join(if cfg!(windows) {
        "operand_harness.exe"
    } else {
        "operand_harness"
    });
    let link: std::process::Output = Command::new(&compiler)
        .args(["-O1", "-o"])
        .arg(&harness)
        .arg(&driver_path)
        .arg(&object_path)
        .output()
        .expect("invoke the compiler to link the operand harness");
    assert!(
        link.status.success(),
        "operand harness link failed: {}\n--- driver.c ---\n{driver_source}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&harness)
        .output()
        .expect("run the operand harness");
    let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
    assert!(
        failures.is_empty()
            && run.status.success()
            && stdout.contains("OK")
            && !stdout.contains("MISMATCH"),
        "{}\noperand differential over {graded} lifted stubs: {stdout}\nstderr: {}\n--- driver.c ---\n{driver_source}",
        failures.join("\n"),
        String::from_utf8_lossy(&run.stderr)
    );
    println!(
        "operand differential passed for {graded} stubs over {RANDOM_STATES} dirty register states ({HOST_ABI:?})"
    );
}
