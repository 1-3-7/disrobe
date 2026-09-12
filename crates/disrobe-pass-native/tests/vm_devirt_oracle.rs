#![cfg(target_arch = "x86_64")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::missing_const_for_fn,
    clippy::format_push_string,
    dead_code
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::vm_devirt::detect::Bitness;
use disrobe_pass_native::vm_devirt::eval::evaluate;
use disrobe_pass_native::vm_devirt::{
    DispatchKind, HandlerSemantics, LiftedProgram, MicroOp, VmBlock, VmCfg, VmDetection, VmInsn,
    devirtualize,
};

const OP_PUSH_IMM: u8 = 0;
const OP_PUSH_REG: u8 = 1;
const OP_POP_REG: u8 = 2;
const OP_ADD: u8 = 3;
const OP_SUB: u8 = 4;
const OP_MUL: u8 = 5;
const OP_XOR: u8 = 6;
const OP_AND: u8 = 7;
const OP_OR: u8 = 8;
const OP_SHL: u8 = 9;
const OP_CMP_LT: u8 = 10;
const OP_CMP_EQ: u8 = 11;
const OP_CMP_GT: u8 = 12;
const OP_NEG: u8 = 13;
const OP_BR_TRUE: u8 = 14;
const OP_BR_FALSE: u8 = 15;
const OP_JUMP: u8 = 16;
const OP_RET: u8 = 17;

#[derive(Default)]
struct Asm {
    code: Vec<u8>,
    fixups: Vec<(usize, String)>,
    labels: std::collections::BTreeMap<String, u32>,
}

impl Asm {
    fn push_imm(&mut self, v: i32) {
        self.code.push(OP_PUSH_IMM);
        self.code.extend_from_slice(&v.to_le_bytes());
    }
    fn push_reg(&mut self, r: u8) {
        self.code.push(OP_PUSH_REG);
        self.code.push(r);
    }
    fn pop_reg(&mut self, r: u8) {
        self.code.push(OP_POP_REG);
        self.code.push(r);
    }
    fn op(&mut self, o: u8) {
        self.code.push(o);
    }
    fn br_true(&mut self, label: &str) {
        self.code.push(OP_BR_TRUE);
        self.fixups.push((self.code.len(), label.to_owned()));
        self.code.extend_from_slice(&0u32.to_le_bytes());
    }
    fn br_false(&mut self, label: &str) {
        self.code.push(OP_BR_FALSE);
        self.fixups.push((self.code.len(), label.to_owned()));
        self.code.extend_from_slice(&0u32.to_le_bytes());
    }
    fn jump(&mut self, label: &str) {
        self.code.push(OP_JUMP);
        self.fixups.push((self.code.len(), label.to_owned()));
        self.code.extend_from_slice(&0u32.to_le_bytes());
    }
    fn label(&mut self, name: &str) {
        self.labels.insert(name.to_owned(), self.code.len() as u32);
    }
    fn ret(&mut self) {
        self.code.push(OP_RET);
    }
    fn finish(mut self) -> Vec<u8> {
        for (at, label) in &self.fixups {
            let target: u32 = *self
                .labels
                .get(label)
                .unwrap_or_else(|| panic!("undefined label {label}"));
            self.code[*at..*at + 4].copy_from_slice(&target.to_le_bytes());
        }
        self.code
    }
}

fn program_poly() -> Vec<u8> {
    let mut a: Asm = Asm::default();
    a.push_reg(0);
    a.push_reg(1);
    a.op(OP_MUL);
    a.push_reg(0);
    a.push_reg(1);
    a.op(OP_XOR);
    a.op(OP_ADD);
    a.push_imm(7);
    a.op(OP_SUB);
    a.ret();
    a.finish()
}

fn expected_poly(x: i64, y: i64) -> i64 {
    (x.wrapping_mul(y)).wrapping_add(x ^ y).wrapping_sub(7)
}

fn program_sum_to() -> Vec<u8> {
    let mut a: Asm = Asm::default();
    a.push_imm(0);
    a.pop_reg(1);
    a.push_imm(1);
    a.pop_reg(2);
    a.label("loop");
    a.push_reg(2);
    a.push_reg(0);
    a.op(OP_CMP_GT);
    a.br_true("done");
    a.push_reg(1);
    a.push_reg(2);
    a.op(OP_ADD);
    a.pop_reg(1);
    a.push_reg(2);
    a.push_imm(1);
    a.op(OP_ADD);
    a.pop_reg(2);
    a.jump("loop");
    a.label("done");
    a.push_reg(1);
    a.ret();
    a.finish()
}

fn expected_sum_to(n: i64) -> i64 {
    let mut acc: i64 = 0;
    let mut i: i64 = 1;
    while i <= n {
        acc = acc.wrapping_add(i);
        i += 1;
    }
    acc
}

fn program_max3() -> Vec<u8> {
    let mut a: Asm = Asm::default();
    a.push_reg(0);
    a.pop_reg(3);
    a.push_reg(3);
    a.push_reg(1);
    a.op(OP_CMP_LT);
    a.br_false("skip1");
    a.push_reg(1);
    a.pop_reg(3);
    a.label("skip1");
    a.push_reg(3);
    a.push_reg(2);
    a.op(OP_CMP_LT);
    a.br_false("skip2");
    a.push_reg(2);
    a.pop_reg(3);
    a.label("skip2");
    a.push_reg(3);
    a.ret();
    a.finish()
}

fn expected_max3(a: i64, b: i64, c: i64) -> i64 {
    a.max(b).max(c)
}

fn clang_path() -> Option<PathBuf> {
    let candidates: [&str; 3] = [
        "clang",
        "C:\\Program Files\\LLVM\\bin\\clang.exe",
        "/usr/bin/clang",
    ];
    for cand in candidates {
        let ok: bool = Command::new(cand)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
        if ok {
            return Some(PathBuf::from(cand));
        }
    }
    None
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

struct CompiledVm {
    binary: PathBuf,
    bytecode: Vec<u8>,
    _tmp: PathBuf,
}

fn compile_vm(clang: &Path, name: &str, bytecode: &[u8]) -> Option<CompiledVm> {
    let out_dir: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("vm_oracle");
    std::fs::create_dir_all(&out_dir).ok()?;
    let inc_path: PathBuf = out_dir.join(format!("{name}_bytecode.inc"));
    let inc_body: String = render_inc(bytecode);
    std::fs::write(&inc_path, inc_body).ok()?;

    let src_template: String = std::fs::read_to_string(fixtures_dir().join("vm_oracle.c")).ok()?;
    let src_path: PathBuf = out_dir.join(format!("{name}.c"));
    let patched: String = src_template.replace(
        "#include \"vm_oracle_bytecode.inc\"",
        &format!("#include \"{name}_bytecode.inc\""),
    );
    std::fs::write(&src_path, patched).ok()?;

    let exe_ext: &str = if cfg!(windows) { ".exe" } else { "" };
    let bin_path: PathBuf = out_dir.join(format!("{name}{exe_ext}"));
    let status: std::process::Output = Command::new(clang)
        .arg("-O1")
        .arg("-fno-inline")
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .ok()?;
    if !status.status.success() {
        eprintln!("clang failed: {}", String::from_utf8_lossy(&status.stderr));
        return None;
    }
    Some(CompiledVm {
        binary: bin_path,
        bytecode: bytecode.to_vec(),
        _tmp: out_dir,
    })
}

fn render_inc(bytecode: &[u8]) -> String {
    let mut s: String = String::new();
    for (i, b) in bytecode.iter().enumerate() {
        if i % 16 == 0 {
            s.push_str("\n    ");
        }
        s.push_str(&format!("0x{b:02x}, "));
    }
    s.push('\n');
    s
}

fn run_binary(bin: &Path, args: &[i64]) -> Option<i64> {
    let mut cmd: Command = Command::new(bin);
    for a in args {
        cmd.arg(a.to_string());
    }
    let out: std::process::Output = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    text.parse::<i64>().ok()
}

fn detect_bitness(bin: &Path) -> Bitness {
    use object::Object as _;
    let bytes: Vec<u8> = std::fs::read(bin).unwrap_or_default();
    let is_64: bool = object::File::parse(&*bytes).is_ok_and(|f: object::File<'_>| f.is_64());
    if is_64 {
        Bitness::Bits64
    } else {
        Bitness::Bits32
    }
}

fn straight_line_run(program: &LiftedProgram) -> Vec<&VmInsn> {
    let mut ordered: Vec<&VmInsn> = program.insns.iter().collect();
    ordered.sort_by_key(|i: &&VmInsn| i.offset);
    let start: usize = ordered
        .iter()
        .position(|i: &&VmInsn| i.offset == program.entry_offset)
        .unwrap_or(0);
    let mut run: Vec<&VmInsn> = Vec::new();
    for insn in &ordered[start..] {
        run.push(insn);
        if insn.micro_op.is_terminator() {
            break;
        }
    }
    run
}

#[test]
fn oracle_poly_devirtualizes_and_matches_binary() {
    let Some(clang): Option<PathBuf> = clang_path() else {
        eprintln!("SKIP: clang not available, cannot build the real VM oracle binary");
        return;
    };
    let bytecode: Vec<u8> = program_poly();
    let Some(vm): Option<CompiledVm> = compile_vm(&clang, "poly", &bytecode) else {
        eprintln!("SKIP: failed to compile the VM oracle binary");
        return;
    };

    let inputs: [(i64, i64); 5] = [(3, 4), (10, 7), (-5, 9), (100, 100), (0, 0)];
    for (x, y) in inputs {
        let ground: i64 = expected_poly(x, y);
        let binary_out: i64 =
            run_binary(&vm.binary, &[x, y, 0]).expect("oracle binary must run and print a result");
        assert_eq!(
            binary_out, ground,
            "the compiled VM (real handlers over bytecode) must compute the original poly() for ({x},{y})"
        );
    }

    let image: Vec<u8> = std::fs::read(&vm.binary).expect("read oracle binary");
    let bitness: Bitness = detect_bitness(&vm.binary);
    let (report, lifted, cfg, semantics): (_, LiftedProgram, VmCfg, Vec<HandlerSemantics>) =
        devirtualize(&image, bitness).expect("devirtualize the real oracle binary");

    println!("poly detection: {:?}", report.detection);
    println!(
        "poly: {} handlers, {} fingerprinted, {} insns, {} blocks",
        report.handler_count,
        report.fingerprinted_count,
        report.bytecode_insn_count,
        report.block_count
    );
    println!("{}", report.recovered_listing);
    println!("{}", report.pseudocode);

    assert_eq!(
        report.detection.dispatch_kind,
        DispatchKind::CallThreaded,
        "the oracle uses a function-pointer dispatch table"
    );
    assert!(
        report.bytecode_insn_count >= 8,
        "poly lifts to at least 8 virtual instructions"
    );
    assert!(
        lifted.unresolved_opcodes.is_empty(),
        "every opcode used by poly must be fingerprinted; unresolved={:?}",
        lifted.unresolved_opcodes
    );
    let reachable_run: Vec<&VmInsn> = straight_line_run(&lifted);
    assert!(
        reachable_run
            .last()
            .is_some_and(|i: &&VmInsn| matches!(i.micro_op, MicroOp::Return)),
        "poly's recovered run from entry ends in a return"
    );
    assert!(
        reachable_run.iter().all(|i: &&VmInsn| !matches!(
            i.micro_op,
            MicroOp::BranchTrue | MicroOp::BranchFalse | MicroOp::Jump
        )),
        "poly is straight-line: no branch or jump executes before the return"
    );
    let entry_block: &VmBlock = cfg
        .block_at(cfg.entry)
        .expect("the entry block is present in the recovered cfg");
    assert!(
        entry_block.branch.is_none(),
        "the entry block has no conditional branch (poly is not a loop or if)"
    );

    let mul_fp: bool = semantics.iter().any(|s: &HandlerSemantics| {
        matches!(
            s.micro_op,
            MicroOp::Binary {
                op: disrobe_pass_native::vm_devirt::microop::BinKind::Mul
            }
        )
    });
    assert!(
        mul_fp,
        "the multiply handler must be behaviorally identified"
    );

    for (x, y) in inputs {
        let ground: i64 = expected_poly(x, y);
        let recovered: i64 = evaluate(&lifted, &[x, y, 0], 8)
            .expect("re-execute lifted IR")
            .return_value;
        assert_eq!(
            recovered, ground,
            "the devirtualized IR must reproduce poly({x},{y}) = {ground}; got {recovered}"
        );
    }
}

#[test]
fn oracle_sum_to_loop_devirtualizes_and_matches_binary() {
    let Some(clang): Option<PathBuf> = clang_path() else {
        eprintln!("SKIP: clang not available");
        return;
    };
    let bytecode: Vec<u8> = program_sum_to();
    let Some(vm): Option<CompiledVm> = compile_vm(&clang, "sum_to", &bytecode) else {
        eprintln!("SKIP: failed to compile VM oracle");
        return;
    };

    let inputs: [i64; 6] = [0, 1, 5, 10, 50, 100];
    for n in inputs {
        let ground: i64 = expected_sum_to(n);
        let binary_out: i64 = run_binary(&vm.binary, &[n, 0, 0]).expect("oracle binary runs");
        assert_eq!(
            binary_out, ground,
            "the compiled loop VM must compute sum_to({n}) = {ground}"
        );
    }

    let image: Vec<u8> = std::fs::read(&vm.binary).unwrap();
    let bitness: Bitness = detect_bitness(&vm.binary);
    let (report, lifted, cfg, _semantics): (_, LiftedProgram, VmCfg, Vec<HandlerSemantics>) =
        devirtualize(&image, bitness).expect("devirtualize loop oracle");

    println!("sum_to: {} blocks", report.block_count);
    println!("{}", report.recovered_listing);
    println!("{}", report.pseudocode);

    assert!(
        lifted.unresolved_opcodes.is_empty(),
        "loop opcodes all fingerprinted; unresolved={:?}",
        lifted.unresolved_opcodes
    );
    assert!(
        cfg.blocks.len() >= 3,
        "a loop with a conditional exit has at least 3 blocks; got {}",
        cfg.blocks.len()
    );

    for n in inputs {
        let ground: i64 = expected_sum_to(n);
        let recovered: i64 = evaluate(&lifted, &[n, 0, 0], 8)
            .expect("re-exec lifted loop")
            .return_value;
        assert_eq!(
            recovered, ground,
            "devirtualized loop IR must reproduce sum_to({n}) = {ground}; got {recovered}"
        );
    }
}

#[test]
fn oracle_max3_branches_devirtualize_and_match_binary() {
    let Some(clang): Option<PathBuf> = clang_path() else {
        eprintln!("SKIP: clang not available");
        return;
    };
    let bytecode: Vec<u8> = program_max3();
    let Some(vm): Option<CompiledVm> = compile_vm(&clang, "max3", &bytecode) else {
        eprintln!("SKIP: failed to compile VM oracle");
        return;
    };

    let inputs: [(i64, i64, i64); 6] = [
        (1, 2, 3),
        (3, 2, 1),
        (2, 3, 1),
        (-5, -2, -9),
        (7, 7, 7),
        (10, -100, 50),
    ];
    for (a, b, c) in inputs {
        let ground: i64 = expected_max3(a, b, c);
        let binary_out: i64 = run_binary(&vm.binary, &[a, b, c]).expect("oracle runs");
        assert_eq!(
            binary_out, ground,
            "the compiled branch VM must compute max3({a},{b},{c}) = {ground}"
        );
    }

    let image: Vec<u8> = std::fs::read(&vm.binary).unwrap();
    let bitness: Bitness = detect_bitness(&vm.binary);
    let (report, lifted, _cfg, _semantics): (_, LiftedProgram, VmCfg, Vec<HandlerSemantics>) =
        devirtualize(&image, bitness).expect("devirtualize branch oracle");
    println!("{}", report.pseudocode);

    assert!(lifted.unresolved_opcodes.is_empty());
    for (a, b, c) in inputs {
        let ground: i64 = expected_max3(a, b, c);
        let recovered: i64 = evaluate(&lifted, &[a, b, c], 8)
            .expect("re-exec lifted branches")
            .return_value;
        assert_eq!(
            recovered, ground,
            "devirtualized branch IR must reproduce max3({a},{b},{c}) = {ground}; got {recovered}"
        );
    }
}

#[test]
fn codescan_recovers_without_export_symbols() {
    let Some(clang): Option<PathBuf> = clang_path() else {
        eprintln!("SKIP: clang not available");
        return;
    };
    let bytecode: Vec<u8> = program_poly();
    let Some(vm): Option<CompiledVm> = compile_vm(&clang, "codescan", &bytecode) else {
        eprintln!("SKIP: failed to compile VM oracle");
        return;
    };
    let image: Vec<u8> = std::fs::read(&vm.binary).unwrap();
    let bitness: Bitness = detect_bitness(&vm.binary);

    let structure =
        disrobe_pass_native::vm_devirt::detect::recover_structure_codescan_only(&image, bitness)
            .expect(
                "code-scan must recover VM structure without relying on disrobe's own export names",
            );

    println!(
        "codescan: dispatcher={:#x} table handlers={} bytecode_va={:#x} kind={:?}",
        structure.dispatcher_va,
        structure.handlers.len(),
        structure.bytecode_va,
        structure.dispatch_kind
    );
    assert!(
        structure.handlers.len() >= 18,
        "code-scan recovered the handler table by walking code pointers; got {}",
        structure.handlers.len()
    );
    assert_eq!(
        structure.dispatch_kind,
        DispatchKind::CallThreaded,
        "the indirect handler call is recognized as call-threaded dispatch"
    );

    let semantics: Vec<HandlerSemantics> =
        disrobe_pass_native::vm_devirt::fingerprint_handlers(&image, bitness, &structure)
            .expect("fingerprint handlers recovered by code-scan");
    let lifted: LiftedProgram =
        disrobe_pass_native::vm_devirt::lift_bytecode(&image, &structure, &semantics)
            .expect("lift the code-scan-recovered bytecode");

    let inputs: [(i64, i64); 4] = [(3, 4), (10, 7), (-5, 9), (100, 100)];
    for (x, y) in inputs {
        let ground: i64 = expected_poly(x, y);
        let binary_out: i64 = run_binary(&vm.binary, &[x, y, 0]).expect("oracle runs");
        let recovered: i64 = evaluate(&lifted, &[x, y, 0], 8)
            .expect("re-exec code-scan-lifted IR")
            .return_value;
        assert_eq!(
            recovered, binary_out,
            "code-scan devirtualized IR must reproduce the real binary output for poly({x},{y})"
        );
        assert_eq!(recovered, ground);
    }
}

#[test]
fn detection_reports_structure_on_real_binary() {
    let Some(clang): Option<PathBuf> = clang_path() else {
        eprintln!("SKIP: clang not available");
        return;
    };
    let bytecode: Vec<u8> = program_poly();
    let Some(vm): Option<CompiledVm> = compile_vm(&clang, "detect_probe", &bytecode) else {
        eprintln!("SKIP: failed to compile VM oracle");
        return;
    };
    let image: Vec<u8> = std::fs::read(&vm.binary).unwrap();
    let bitness: Bitness = detect_bitness(&vm.binary);
    let detection: VmDetection =
        disrobe_pass_native::vm_devirt::detect_vm(&image, bitness).expect("detect VM structure");

    assert_eq!(
        detection.dispatch_kind,
        DispatchKind::CallThreaded,
        "the indirect handler call is recognized as call-threaded dispatch"
    );
    assert!(
        detection.handler_count >= 2,
        "detection recovers a populated handler table; got {}",
        detection.handler_count
    );
    assert!(
        detection.bytecode_len >= bytecode.len(),
        "the reported bytecode region covers at least the program; got {} for a {}-byte program",
        detection.bytecode_len,
        bytecode.len()
    );

    let (_report, lifted, _cfg, _semantics): (_, LiftedProgram, VmCfg, Vec<HandlerSemantics>) =
        devirtualize(&image, bitness).expect("devirtualize the detected structure");
    assert!(
        lifted.unresolved_opcodes.is_empty(),
        "the recovered handler set resolves every opcode poly uses; unresolved={:?}",
        lifted.unresolved_opcodes
    );
    for (x, y) in [(3, 4), (10, 7), (-5, 9), (100, 100)] {
        let ground: i64 = expected_poly(x, y);
        let recovered: i64 = evaluate(&lifted, &[x, y, 0], 8)
            .expect("re-execute lifted IR from the reported structure")
            .return_value;
        assert_eq!(
            recovered, ground,
            "the structure detection feeds a lift that reproduces poly({x},{y}) = {ground}"
        );
    }
}
