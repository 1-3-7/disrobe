#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, recover_aarch64_function, recover_leaf_function_abi,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StubAbi {
    Host,
    MsX64Only,
    SysV,
}

impl StubAbi {
    const fn lift_abi(self) -> PseudoAbi {
        match self {
            Self::Host => HOST_ABI,
            Self::MsX64Only => PseudoAbi::MsX64,
            Self::SysV => PseudoAbi::SysV,
        }
    }

    fn active(self) -> bool {
        self != Self::MsX64Only || HOST_ABI == PseudoAbi::MsX64
    }

    fn c_attribute(self) -> &'static str {
        if self.lift_abi() == PseudoAbi::SysV {
            "__attribute__((sysv_abi)) "
        } else {
            ""
        }
    }
}

struct Stub {
    name: &'static str,
    body: &'static str,
    expect: Expect,
    abi: StubAbi,
}

const STUBS: &[Stub] = &[
    Stub {
        name: "opr_r10w_add",
        body: "mov r10, $a0\nmov r11, $a1\nadd r10w, r11w\nmov rax, r10\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_r12w_move",
        body: "push r12\nmov r12, $a0\nmov r11, $a1\nmov r12w, r11w\nmov rax, r12\npop r12\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_r13w_sub",
        body: "mov rax, $a1\npush r13\nmov r13, $a0\nsub r13w, ax\nmov rax, r13\npop r13\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_r14w_zext",
        body: "push r14\nmov r14, $a0\nmovzx eax, r14w\nadd rax, $a1\npop r14\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_r15w_xor",
        body: "push r15\nmov r15, $a0\nxor r15w, $a1w\nmov rax, r15\npop r15\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_bpl_add",
        body: "push rbp\nmov rbp, $a0\nadd bpl, $a1b\nmov rax, rbp\npop rbp\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_bp_xor",
        body: "push rbp\nmov rbp, $a0\nxor bp, $a1w\nmov rax, rbp\npop rbp\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_push_pop_move",
        body: "push $a0\npop rax\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_push_pop_swap",
        body: "push $a0\npush $a1\npop rax\npop rcx\nsub rax, rcx\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_high_byte_add_al_ah",
        body: "mov rax, $a0\nadd al, ah\nret",
        expect: Expect::Refused("high-byte register `ah`"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_high_byte_sub_al_dh",
        body: "mov rdx, $a1\nmov rax, $a0\nsub al, dh\nret",
        expect: Expect::Refused("high-byte register `dh`"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_high_byte_cmp_cl_ch",
        body: "mov rcx, $a0\nxor eax, eax\ncmp cl, ch\nsetb al\nret",
        expect: Expect::Refused("high-byte register `ch`"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_high_byte_xor_al_bh",
        body: "push rbx\nmov rbx, $a0\nmov rax, $a1\nxor al, bh\npop rbx\nret",
        expect: Expect::Refused("high-byte register `bh`"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_push_pop_modified",
        body: "push $a0\nmov $a0, $a1\npop rax\nadd rax, $a0\nret",
        expect: Expect::Refused("after the register changed"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "opr_xmm6_mid_body_spill",
        body: "sub rsp, 40\nmovaps [rsp], xmm6\nmovq xmm6, $a0\nmovaps [rsp+16], xmm6\nmovq xmm6, $a1\nmovaps xmm6, [rsp+16]\nmovq rax, xmm6\nmovaps xmm6, [rsp]\nadd rsp, 40\nret",
        expect: Expect::Refused("a mid-body xmm spill"),
        abi: StubAbi::MsX64Only,
    },
    Stub {
        name: "abi_pair_helper",
        body: "mov rax, $a0\nlea rdx, [$a0+1]\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::SysV,
    },
    Stub {
        name: "abi_rdx_after_pair_call",
        body: "push rbx\ncall abi_pair_helper\nxor rax, rdx\npop rbx\nret",
        expect: Expect::Refused("caller-saved register `rdx` is read"),
        abi: StubAbi::SysV,
    },
    Stub {
        name: "abi_rcx_after_call",
        body: "push rbx\nmov rcx, $a0\ncall abi_pair_helper\nadd rax, rcx\npop rbx\nret",
        expect: Expect::Refused("caller-saved register `rcx` is read"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "abi_r11_byte_after_call",
        body: "push rbx\nmov r11, $a1\ncall abi_pair_helper\nmov r11b, al\nmov rax, r11\npop rbx\nret",
        expect: Expect::Refused("caller-saved register `r11` is read"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "abi_xmm1_after_call",
        body: "push rbx\nmovq xmm1, $a0\ncall abi_pair_helper\nmovq rax, xmm1\npop rbx\nret",
        expect: Expect::Refused("caller-saved register `xmm1` is read"),
        abi: StubAbi::Host,
    },
    Stub {
        name: "abi_sysv_second_only_lea",
        body: "lea rax, [$a1+$a1*2+1]\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::SysV,
    },
    Stub {
        name: "abi_sysv_second_only_sub",
        body: "mov rax, $a1\nsub rax, 7\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::SysV,
    },
    Stub {
        name: "abi_cmov32_zero_extends_both_arms",
        body: "mov r10, $a1\ncmp $a0, $a1\ncmovb r10d, $a0d\nlea rax, [r10+$a0]\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "abi_cmov32_rax_zero_extends_both_arms",
        body: "mov rax, $a1\ncmp $a0, $a1\ncmova eax, $a0d\nadd rax, $a0\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
    Stub {
        name: "abi_cmov16_keeps_upper_bits",
        body: "mov r10, $a1\ncmp $a0, $a1\ncmovb r10w, $a0w\nlea rax, [r10+$a0]\nret",
        expect: Expect::Equivalent,
        abi: StubAbi::Host,
    },
];

fn active_stubs() -> impl Iterator<Item = &'static Stub> {
    STUBS.iter().filter(|stub: &&Stub| stub.abi.active())
}

fn argument_registers(abi: PseudoAbi) -> [(&'static str, &'static str); 7] {
    if abi == PseudoAbi::MsX64 {
        [
            ("$a0d", "ecx"),
            ("$a0w", "cx"),
            ("$a1d", "edx"),
            ("$a1w", "dx"),
            ("$a1b", "dl"),
            ("$a0", "rcx"),
            ("$a1", "rdx"),
        ]
    } else {
        [
            ("$a0d", "edi"),
            ("$a0w", "di"),
            ("$a1d", "esi"),
            ("$a1w", "si"),
            ("$a1b", "sil"),
            ("$a0", "rdi"),
            ("$a1", "rsi"),
        ]
    }
}

fn stub_asm() -> String {
    let mut asm: String = String::from("\t.intel_syntax noprefix\n\t.text\n");
    for stub in active_stubs() {
        let body: String = argument_registers(stub.abi.lift_abi()).iter().fold(
            stub.body.to_owned(),
            |body: String, (placeholder, register): &(&str, &str)| {
                body.replace(placeholder, register)
            },
        );
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

fn recovered_decl(name: &str, recovery: &LeafRecovery) -> String {
    recovery
        .source
        .replacen("uint64_t recovered(", &format!("uint64_t rec_{name}("), 1)
        .lines()
        .filter(|line: &&str| !line.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn comparison(name: &str, recovery: &LeafRecovery) -> String {
    let arity: usize = recovery.signature.callable_arity();
    assert!(
        arity <= 2,
        "{name} recovered with arity {arity}, above the two authored arguments: {}",
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
    )
}

#[derive(Default)]
struct Differential {
    failures: Vec<String>,
    recovered_decls: String,
    flag_decls: String,
    driver_body: String,
    graded: usize,
}

impl Differential {
    fn record(
        &mut self,
        name: &str,
        expect: Expect,
        outcome: disrobe_pass_native::Result<LeafRecovery>,
        original_decl: &str,
    ) {
        match (expect, outcome) {
            (Expect::Equivalent, Ok(recovery)) => {
                self.recovered_decls
                    .push_str(&recovered_decl(name, &recovery));
                let _ = writeln!(self.recovered_decls, "\n{original_decl}");
                let _ = writeln!(self.flag_decls, "    int bad_{name} = 0;");
                self.driver_body.push_str(&comparison(name, &recovery));
                self.graded += 1;
            }
            (Expect::Equivalent, Err(error)) => {
                self.failures
                    .push(format!("{name} must lift but was refused: {error}"));
            }
            (Expect::Refused(reason), Err(error)) => {
                let text: String = error.to_string();
                if !text.contains(reason) {
                    self.failures.push(format!(
                        "{name} was refused for the wrong reason (want `{reason}`): {text}"
                    ));
                }
            }
            (Expect::Refused(reason), Ok(recovery)) => {
                self.failures.push(format!(
                    "{name} must be refused (`{reason}`) but lifted:\n{}",
                    recovery.source
                ));
            }
        }
    }

    fn run(self, compiler: &str, dir: &Path, objects: &[PathBuf], label: &str) {
        let driver_source: String =
            driver(&self.recovered_decls, &self.flag_decls, &self.driver_body);
        let driver_path: PathBuf = dir.join(format!("{label}_driver.c"));
        std::fs::write(&driver_path, driver_source.as_bytes()).expect("write differential driver");
        let harness: PathBuf = dir.join(if cfg!(windows) {
            format!("{label}_harness.exe")
        } else {
            format!("{label}_harness")
        });
        let link: std::process::Output = Command::new(compiler)
            .args(["-O1", "-o"])
            .arg(&harness)
            .arg(&driver_path)
            .args(objects)
            .output()
            .expect("invoke the compiler to link the differential harness");
        assert!(
            link.status.success(),
            "{}\n{label} harness link failed: {}\n--- driver.c ---\n{driver_source}",
            self.failures.join("\n"),
            String::from_utf8_lossy(&link.stderr)
        );
        let run: std::process::Output = Command::new(&harness)
            .output()
            .expect("run the differential harness");
        let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
        assert!(
            self.failures.is_empty()
                && run.status.success()
                && stdout.contains("OK")
                && !stdout.contains("MISMATCH"),
            "{}\n{label} differential over {} lifted functions: {stdout}\nstderr: {}\n--- driver.c ---\n{driver_source}",
            self.failures.join("\n"),
            self.graded,
            String::from_utf8_lossy(&run.stderr)
        );
        println!(
            "{label} differential passed for {} functions over {RANDOM_STATES} dirty register states",
            self.graded
        );
    }
}

fn run_compiler(compiler: &str, args: &[&str], input: &Path, output: &Path, what: &str) {
    let result: std::process::Output = Command::new(compiler)
        .args(args)
        .arg("-o")
        .arg(output)
        .arg(input)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("invoke {compiler} to build {what}: {error}")
        });
    assert!(
        result.status.success(),
        "{compiler} could not build {what}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
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
    run_compiler(
        &compiler,
        &["-c"],
        &asm_path,
        &object_path,
        "the intel-syntax operand stubs",
    );
    let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read operand stub object");

    let mut differential: Differential = Differential::default();
    for stub in active_stubs() {
        let (code, base): (Vec<u8>, u64) = function_code(&object_bytes, stub.name)
            .unwrap_or_else(|| panic!("{} is not in the assembled object", stub.name));
        let outcome: disrobe_pass_native::Result<LeafRecovery> =
            recover_leaf_function_abi(&code, base, stub.abi.lift_abi());
        let original_decl: String = format!(
            "extern {}unsigned long long {}(unsigned long long, unsigned long long);",
            stub.abi.c_attribute(),
            stub.name
        );
        differential.record(stub.name, stub.expect, outcome, &original_decl);
    }
    differential.run(&compiler, &dir, &[object_path], "operand");
}

const SYSV_C_SOURCE: &str = "#if defined(__clang__)\n\
#define KEEP __attribute__((sysv_abi, noinline))\n\
#else\n\
#define KEEP __attribute__((sysv_abi, noipa))\n\
#endif\n\
struct TAG_pair { unsigned long long lo, hi; };\n\
KEEP struct TAG_pair TAG_make_pair(unsigned long long x) { struct TAG_pair p = { x * 3u, x ^ 0x5555u }; return p; }\n\
KEEP unsigned long long TAG_pair_xor(unsigned long long x) { struct TAG_pair p = TAG_make_pair(x + 1u); return p.lo ^ p.hi; }\n\
KEEP unsigned long long TAG_second_only(unsigned long long unused, unsigned long long b) { (void)unused; return b * 3u + 1u; }\n\
KEEP unsigned long long TAG_min32_plus_high(unsigned long long a, unsigned long long b) { unsigned x = (unsigned)a, y = (unsigned)b; unsigned m = x < y ? x : y; return (unsigned long long)m + (a >> 32); }\n";

const SYSV_C_ROWS: [(&str, Expect); 3] = [
    (
        "pair_xor",
        Expect::Refused("caller-saved register `rdx` is read"),
    ),
    ("second_only", Expect::Equivalent),
    ("min32_plus_high", Expect::Equivalent),
];

#[test]
#[cfg_attr(
    any(target_os = "macos", not(target_arch = "x86_64")),
    ignore = "the SysV call-ABI differential executes x86-64 objects built by gcc and clang"
)]
fn sysv_callbacks_selects_and_pair_returns_from_gcc_and_clang_recompile_equal_or_refuse() {
    let linker: String = compiler_toolchain::require_any(&["gcc", "clang", "cc"]);
    let compilers: [String; 2] = [
        compiler_toolchain::require_one("gcc"),
        compiler_toolchain::require_one("clang"),
    ];
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-sysv-call-abi").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut differential: Differential = Differential::default();
    let mut objects: Vec<PathBuf> = Vec::new();
    for compiler in &compilers {
        for opt in ["-O0", "-O1", "-O2"] {
            let tag: String = format!("{compiler}_{}", opt.trim_start_matches('-'));
            let source_path: PathBuf = dir.join(format!("{tag}.c"));
            std::fs::write(&source_path, SYSV_C_SOURCE.replace("TAG", &tag))
                .expect("write authored SysV source");
            let object_path: PathBuf = dir.join(format!("{tag}.o"));
            let mut args: Vec<&str> = vec!["-c", opt];
            if compiler == "clang" && cfg!(windows) {
                args.push("--target=x86_64-w64-windows-gnu");
            }
            run_compiler(
                compiler,
                &args,
                &source_path,
                &object_path,
                "the authored SysV rows",
            );
            let object_bytes: Vec<u8> =
                std::fs::read(&object_path).expect("read authored SysV object");
            for (row, expect) in SYSV_C_ROWS {
                let name: String = format!("{tag}_{row}");
                let (code, base): (Vec<u8>, u64) = function_code(&object_bytes, &name)
                    .unwrap_or_else(|| panic!("{name} is not in the {compiler} {opt} object"));
                let outcome: disrobe_pass_native::Result<LeafRecovery> =
                    recover_leaf_function_abi(&code, base, PseudoAbi::SysV);
                let original_decl: String = format!(
                    "extern __attribute__((sysv_abi)) unsigned long long {name}(unsigned long long, unsigned long long);"
                );
                differential.record(&name, expect, outcome, &original_decl);
            }
            objects.push(object_path);
        }
    }
    differential.run(&linker, &dir, &objects, "sysv_call_abi");
}

const AARCH64_STUBS: &str = "\t.text\n\
\t.globl a64_helper\n\t.type a64_helper, %function\na64_helper:\n\tadd x0, x0, #1\n\tret\n\t.size a64_helper, .-a64_helper\n\
\t.globl a64_csel_w_not_taken\n\t.type a64_csel_w_not_taken, %function\na64_csel_w_not_taken:\n\tcmp x0, x1\n\tcsel w1, w0, w1, lo\n\tadd x0, x1, x0\n\tret\n\t.size a64_csel_w_not_taken, .-a64_csel_w_not_taken\n\
\t.globl a64_second_only\n\t.type a64_second_only, %function\na64_second_only:\n\tadd x0, x1, #7\n\tret\n\t.size a64_second_only, .-a64_second_only\n\
\t.globl a64_x2_after_call\n\t.type a64_x2_after_call, %function\na64_x2_after_call:\n\tstp x29, x30, [sp, #-16]!\n\tmov x29, sp\n\tbl a64_helper\n\tadd x0, x0, x2\n\tldp x29, x30, [sp], #16\n\tret\n\t.size a64_x2_after_call, .-a64_x2_after_call\n";

const AARCH64_REFERENCES: &str = "static unsigned long long a64_helper(unsigned long long x0, unsigned long long x1) { (void)x1; return x0 + 1u; }\n\
static unsigned long long a64_csel_w_not_taken(unsigned long long x0, unsigned long long x1) { unsigned long long w1 = x0 < x1 ? (unsigned long long)(unsigned)x0 : (unsigned long long)(unsigned)x1; return w1 + x0; }\n\
static unsigned long long a64_second_only(unsigned long long x0, unsigned long long x1) { (void)x0; return x1 + 7u; }\n";

const AARCH64_ROWS: [(&str, Expect); 4] = [
    ("a64_helper", Expect::Equivalent),
    ("a64_csel_w_not_taken", Expect::Equivalent),
    ("a64_second_only", Expect::Equivalent),
    (
        "a64_x2_after_call",
        Expect::Refused("caller-saved register `x2` is read"),
    ),
];

#[test]
fn aarch64_word_selects_prototypes_and_post_call_reads_match_the_architecture() {
    let linker: String = compiler_toolchain::require_any(&["gcc", "clang", "cc"]);
    let assembler: String = compiler_toolchain::require_one("clang");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-aarch64-call-abi").expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let asm_path: PathBuf = dir.join("aarch64_stubs.s");
    std::fs::write(&asm_path, AARCH64_STUBS).expect("write aarch64 stubs");
    let object_path: PathBuf = dir.join("aarch64_stubs.o");
    run_compiler(
        &assembler,
        &["--target=aarch64-linux-gnu", "-c"],
        &asm_path,
        &object_path,
        "the aarch64 stubs",
    );
    let object_bytes: Vec<u8> = std::fs::read(&object_path).expect("read aarch64 stub object");
    let mut differential: Differential = Differential {
        recovered_decls: AARCH64_REFERENCES.to_owned(),
        ..Differential::default()
    };
    for (name, expect) in AARCH64_ROWS {
        let (code, base): (Vec<u8>, u64) = function_code(&object_bytes, name)
            .unwrap_or_else(|| panic!("{name} is not in the aarch64 object"));
        let outcome: disrobe_pass_native::Result<LeafRecovery> =
            recover_aarch64_function(&code, base);
        differential.record(name, expect, outcome, "");
    }
    differential.run(&linker, &dir, &[], "aarch64_call_abi");
}
