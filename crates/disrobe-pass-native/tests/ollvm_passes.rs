#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{
    BogusBranch, CffUnflattenReport, DeobfBits, ObfuscatorFamily, OpaqueResult, SubstitutionResult,
    detect_obfuscators, strip_ollvm_bcf, undo_ollvm_substitution, unflatten_ollvm,
};
use iced_x86::code_asm::{CodeAssembler, CodeLabel, cl, dword_ptr, eax, ecx, edx, esi, rbp};
use object::{Object, ObjectSection, ObjectSymbol};

const BASE: u64 = 0x1000;

const ASSEMBLED_CARRY_ENCODING_SCOPE: &str = "the input here is assembled by this test, so it establishes only that the named instruction \
     encoding lifts and folds, never that a real code generator emits it; the end-to-end grade on \
     third-party compiler output of the same identity is \
     real_compiler_carry_substitution_folds_back_to_addition and on committed ollvm output is \
     real_ollvm_sub_lifts_through_stack_slots.";

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
    assert_eq!(
        result.result,
        OpaqueResult::AlwaysTaken,
        "this leg assembles its own cmp/jcc spelling of the always-even predicate, so it pins \
         that one encoding and establishes nothing about compiler-chosen code; the end-to-end \
         grade on third-party output is \
         real_compiler_opaque_even_predicate_folds_and_a_data_dependent_branch_survives and on \
         committed ollvm output is real_ollvm_bcf_folds_opaque_predicate_or_real_condition"
    );
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
    assert!(
        result.changed && result.proven,
        "{ASSEMBLED_CARRY_ENCODING_SCOPE} this leg pins the add-reg-with-itself doubling: \
         {result:?}"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "the fold must shrink the expression: {result:?}"
    );
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
        "(x ^ y) + ((x & y) << 1) is x + y and must fold with a re-execution proof. \
         {ASSEMBLED_CARRY_ENCODING_SCOPE} this leg pins the shl-by-one doubling: {result:?}"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "the fold must shrink the expression: {result:?}"
    );
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
        "(c & 0xff) ^ (c & 0xff) is 0 and must fold with a re-execution proof. \
         {ASSEMBLED_CARRY_ENCODING_SCOPE} this leg pins a movzx out of a sub-register rather than \
         out of memory, which is the form a code generator never picks for a stack argument: \
         {result:?}"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "the fold must shrink the expression: {result:?}"
    );
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

const SIBLING_SRC: &str = include_str!("fixtures/ollvm_sibling_shapes.c");

fn compiler_version_line(tool: &str) -> Option<String> {
    let out: std::process::Output = std::process::Command::new(tool)
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    Some(text.lines().next().unwrap_or_default().trim().to_owned())
}

fn distinct_c_compilers() -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, String)> = Vec::new();
    for tool in ["cc", "gcc", "clang"] {
        let Some(identity): Option<String> = compiler_version_line(tool) else {
            eprintln!("NOT GRADED: C compiler {tool} does not answer --version on this host");
            continue;
        };
        if found
            .iter()
            .any(|(_, seen): &(&'static str, String)| *seen == identity)
        {
            continue;
        }
        found.push((tool, identity));
    }
    found
}

fn object_is_x86_64(bytes: &[u8]) -> bool {
    object::File::parse(bytes)
        .is_ok_and(|file: object::File<'_>| file.architecture() == object::Architecture::X86_64)
}

fn compile_sibling_object(cc: &str, dir: &std::path::Path) -> Result<Vec<u8>, String> {
    let src: std::path::PathBuf = dir.join(format!("ollvm_sibling_{cc}.c"));
    std::fs::write(&src, SIBLING_SRC)
        .map_err(|err: std::io::Error| format!("{cc}: cannot stage the fixture source: {err}"))?;
    let mut rejected: Vec<String> = Vec::new();
    for (tag, cross, unguard) in [
        ("cross-unguarded", true, true),
        ("host-unguarded", false, true),
        ("cross-default", true, false),
        ("host-default", false, false),
    ] {
        let obj: std::path::PathBuf = dir.join(format!("ollvm_sibling_{cc}_{tag}.o"));
        let mut cmd: std::process::Command = std::process::Command::new(cc);
        if cross {
            cmd.arg("--target=x86_64-unknown-linux-gnu");
        }
        if unguard {
            cmd.args(["-fno-stack-protector", "-fcf-protection=none"]);
        }
        let Ok(out): std::io::Result<std::process::Output> =
            cmd.args(["-O0", "-c", "-o"]).arg(&obj).arg(&src).output()
        else {
            return Err(format!("{cc}: the compiler cannot be invoked"));
        };
        if !out.status.success() {
            rejected.push(format!(
                "{tag}: {}",
                String::from_utf8_lossy(&out.stderr)
                    .trim()
                    .replace('\n', " ")
            ));
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&obj)
            .map_err(|err: std::io::Error| format!("{cc}: {tag} object unreadable: {err}"))?;
        if !object_is_x86_64(&bytes) {
            rejected.push(format!("{tag}: the emitted object is not x86-64"));
            continue;
        }
        return Ok(bytes);
    }
    Err(format!(
        "{cc}: no attempt produced an x86-64 object [{}]",
        rejected.join(" | ")
    ))
}

fn trim_to_first_return(code: &[u8]) -> Vec<u8> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        if insn.mnemonic() == Mnemonic::Ret {
            let end: usize = usize::try_from(insn.ip() - BASE).unwrap_or(code.len()) + insn.len();
            return code[..end.min(code.len())].to_vec();
        }
    }
    code.to_vec()
}

fn function_code(object_bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let underscored: String = format!("_{name}");
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name().is_ok_and(|n: &str| n == name || n == underscored)
    })?;
    let object::SymbolSection::Section(section_index) = sym.section() else {
        return None;
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let declared: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if declared == 0 {
        file.symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len())
            .min(data.len())
    } else {
        start.saturating_add(declared).min(data.len())
    };
    Some(trim_to_first_return(data.get(start..end)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveredForm {
    PlainAddition,
    MaskedAddition,
}

fn is_free_variable(token: &str) -> bool {
    token.strip_prefix('v').is_some_and(|index: &str| {
        !index.is_empty() && index.bytes().all(|byte: u8| byte.is_ascii_digit())
    })
}

fn addition_terms(expr: &str) -> Option<(&str, &str)> {
    let inner: &str = expr
        .strip_prefix('(')
        .and_then(|rest: &str| rest.strip_suffix(')'))
        .unwrap_or(expr);
    let mut terms: std::str::Split<'_, &str> = inner.split(" + ");
    match (terms.next(), terms.next(), terms.next()) {
        (Some(lhs), Some(rhs), None) => Some((lhs, rhs)),
        _ => None,
    }
}

fn byte_masked_variable(term: &str) -> Option<&str> {
    if is_free_variable(term) {
        return Some(term);
    }
    let inner: &str = term.strip_prefix('(')?.strip_suffix(')')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" & ")?;
    match (is_free_variable(lhs), is_free_variable(rhs)) {
        (true, false) if rhs == "255" => Some(lhs),
        (false, true) if lhs == "255" => Some(rhs),
        _ => None,
    }
}

fn is_addition_of_two_distinct_variables(expr: &str) -> bool {
    addition_terms(expr).is_some_and(|(lhs, rhs): (&str, &str)| {
        is_free_variable(lhs) && is_free_variable(rhs) && lhs != rhs
    })
}

fn is_byte_masked_addition_of_two_distinct_variables(expr: &str) -> bool {
    addition_terms(expr).is_some_and(|(lhs, rhs): (&str, &str)| {
        matches!(
            (byte_masked_variable(lhs), byte_masked_variable(rhs)),
            (Some(left), Some(right)) if left != right
        )
    })
}

fn assert_carry_identity_recovers(label: &str, code: &[u8], form: RecoveredForm) {
    let Some(result): Option<SubstitutionResult> =
        undo_ollvm_substitution(DeobfBits::Bits64, BASE, code)
    else {
        panic!(
            "{label}: a real code generator's spelling of (a ^ b) + ((a & b) << 1) must lift to an \
             arithmetic expression, got None over {} bytes: {code:02x?}",
            code.len()
        );
    };
    println!(
        "{label}: dest={} nodes {}->{} proven={} changed={} original={} simplified={}",
        result.dest,
        result.original_nodes,
        result.simplified_nodes,
        result.proven,
        result.changed,
        result.original_expr,
        result.simplified_expr,
    );
    assert!(
        result.changed && result.proven,
        "{label}: (a ^ b) + ((a & b) << 1) is a + b and must fold with a re-execution proof: \
         {result:?}"
    );
    assert!(
        result.simplified_nodes < result.original_nodes,
        "{label}: the fold must shrink the expression: {result:?}"
    );
    let recovered: &str = result.simplified_expr.as_str();
    match form {
        RecoveredForm::PlainAddition => assert!(
            is_addition_of_two_distinct_variables(recovered),
            "{label}: the recovered value must be exactly the addition of the two arguments that \
             the source wrote before substitution, got {recovered}: {result:?}"
        ),
        RecoveredForm::MaskedAddition => {
            println!(
                "{label}: reduced_all_the_way_to_the_byte_masked_addition={}",
                is_byte_masked_addition_of_two_distinct_variables(recovered)
            );
            assert!(
                recovered.contains(" + ") && !recovered.contains("<<"),
                "{label}: the shift-encoded doubling must be rewritten and an addition must \
                 remain. This leg does not establish that byte-loaded operands reduce all the way \
                 to the masked addition of both arguments, because one real compiler's 8-bit \
                 partial-register spelling stops at an equivalent residual; read the printed \
                 reduced_all_the_way flag instead of reading a pass here as full recovery: \
                 {result:?}"
            );
        }
    }
}

const CARRY_CASES: &[(&str, RecoveredForm)] = &[
    ("carry_add_shift", RecoveredForm::PlainAddition),
    ("carry_add_double", RecoveredForm::PlainAddition),
    ("carry_add_bytes", RecoveredForm::MaskedAddition),
];

#[test]
fn real_compiler_carry_substitution_folds_back_to_addition() {
    let compilers: Vec<(&'static str, String)> = distinct_c_compilers();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-ollvm-sibling-sub").expect("create scratch directory");
    let dir: std::path::PathBuf = scratch.path().to_path_buf();
    let mut graded: u32 = 0;
    let mut rejected: Vec<String> = Vec::new();
    for (cc, identity) in &compilers {
        let object_bytes: Vec<u8> = match compile_sibling_object(cc, &dir) {
            Ok(bytes) => bytes,
            Err(why) => {
                eprintln!("NOT GRADED: {why}");
                rejected.push(why);
                continue;
            }
        };
        for &(name, form) in CARRY_CASES {
            let Some(code): Option<Vec<u8>> = function_code(&object_bytes, name) else {
                panic!("{identity}: {name} must be locatable in the object it just compiled");
            };
            assert_carry_identity_recovers(&format!("{identity}/{name}"), &code, form);
            graded += 1;
        }
    }
    assert!(
        graded > 0,
        "this grade needs one C compiler out of cc/gcc/clang that can emit an x86-64 object; \
         candidates were {compilers:?} and every attempt was rejected [{}]",
        rejected.join(" | ")
    );
    println!("graded {graded} real compiler-emitted carry-substitution functions");
}

fn expected_even_predicate_outcome(block: &[u8]) -> OpaqueResult {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, block, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut branch: Option<Mnemonic> = None;
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.flow_control() == FlowControl::ConditionalBranch {
            branch = Some(insn.mnemonic());
        }
    }
    match branch {
        Some(Mnemonic::Je) => OpaqueResult::AlwaysTaken,
        Some(Mnemonic::Jne) => OpaqueResult::AlwaysNotTaken,
        other => panic!(
            "x * (x + 1) is even for every int, so testing its low bit sets the zero flag \
             unconditionally and the branch outcome follows from the condition code; this grade \
             derives the expected outcome only for JE and JNE, and the compiler emitted {other:?}"
        ),
    }
}

#[test]
fn real_compiler_opaque_even_predicate_folds_and_a_data_dependent_branch_survives() {
    let compilers: Vec<(&'static str, String)> = distinct_c_compilers();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-ollvm-sibling-bcf").expect("create scratch directory");
    let dir: std::path::PathBuf = scratch.path().to_path_buf();
    let mut graded: u32 = 0;
    let mut rejected: Vec<String> = Vec::new();
    for (cc, identity) in &compilers {
        let object_bytes: Vec<u8> = match compile_sibling_object(cc, &dir) {
            Ok(bytes) => bytes,
            Err(why) => {
                eprintln!("NOT GRADED: {why}");
                rejected.push(why);
                continue;
            }
        };
        let Some(opaque): Option<Vec<u8>> = function_code(&object_bytes, "always_even_predicate")
        else {
            panic!("{identity}: always_even_predicate must be locatable in the compiled object");
        };
        let opaque_block: &[u8] = first_predicate_block(&opaque);
        let expected: OpaqueResult = expected_even_predicate_outcome(opaque_block);
        let Some(branch): Option<BogusBranch> =
            strip_ollvm_bcf(DeobfBits::Bits64, BASE, opaque_block)
        else {
            panic!(
                "{identity}: the compiler's own materialization of the always-even predicate must \
                 fold, got None over {} bytes: {opaque_block:02x?}",
                opaque_block.len()
            );
        };
        println!("{identity}/always_even_predicate: expected={expected:?} got={branch:?}");
        assert_eq!(
            branch.result, expected,
            "{identity}: the always-even predicate decides the branch, and the emitted condition \
             code fixes which way: {branch:?}"
        );
        assert!(
            branch.dead_target.is_some() && branch.live_target.is_some(),
            "{identity}: folding must name both the dead edge and the surviving live edge: \
             {branch:?}"
        );

        let Some(live): Option<Vec<u8>> = function_code(&object_bytes, "data_dependent_predicate")
        else {
            panic!("{identity}: data_dependent_predicate must be locatable in the compiled object");
        };
        let live_block: &[u8] = first_predicate_block(&live);
        let verdict: Option<BogusBranch> = strip_ollvm_bcf(DeobfBits::Bits64, BASE, live_block);
        println!("{identity}/data_dependent_predicate: verdict={verdict:?}");
        assert!(
            !verdict.as_ref().is_some_and(|found: &BogusBranch| matches!(
                found.result,
                OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
            )),
            "{identity}: x > 10 depends on the argument, so the same compiler's spelling of it \
             must never be folded away as bogus: {verdict:?}"
        );
        graded += 1;
    }
    assert!(
        graded > 0,
        "this grade needs one C compiler out of cc/gcc/clang that can emit an x86-64 object; \
         candidates were {compilers:?} and every attempt was rejected [{}]",
        rejected.join(" | ")
    );
    println!("graded {graded} real compiler-emitted predicate pairs");
}

fn seed_xor_to_or_defect(code: &[u8]) -> Option<Vec<u8>> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
    const XOR_R32_RM32: u8 = 0x33;
    const OR_R32_RM32: u8 = 0x0B;
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, code, BASE, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.mnemonic() != Mnemonic::Xor {
            continue;
        }
        let offset: usize = usize::try_from(insn.ip() - BASE).ok()?;
        if code.get(offset) != Some(&XOR_R32_RM32) {
            continue;
        }
        let original_len: usize = insn.len();
        let mut mutant: Vec<u8> = code.to_vec();
        *mutant.get_mut(offset)? = OR_R32_RM32;
        let mut check: Decoder<'_> =
            Decoder::with_ip(64, mutant.get(offset..)?, BASE, DecoderOptions::NONE);
        let mutated: Instruction = check.decode();
        if mutated.mnemonic() != Mnemonic::Or || mutated.len() != original_len {
            return None;
        }
        return Some(mutant);
    }
    None
}

#[test]
fn a_seeded_xor_to_or_defect_is_rejected_by_the_real_compiler_carry_grade() {
    let compilers: Vec<(&'static str, String)> = distinct_c_compilers();
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-ollvm-sibling-mutant").expect("create scratch directory");
    let dir: std::path::PathBuf = scratch.path().to_path_buf();
    let mut graded: u32 = 0;
    let mut rejected: Vec<String> = Vec::new();
    for (cc, identity) in &compilers {
        let object_bytes: Vec<u8> = match compile_sibling_object(cc, &dir) {
            Ok(bytes) => bytes,
            Err(why) => {
                eprintln!("NOT GRADED: {why}");
                rejected.push(why);
                continue;
            }
        };
        let Some(code): Option<Vec<u8>> = function_code(&object_bytes, "carry_add_shift") else {
            panic!("{identity}: carry_add_shift must be locatable in the compiled object");
        };
        let Some(mutant): Option<Vec<u8>> = seed_xor_to_or_defect(&code) else {
            panic!(
                "{identity}: carry_add_shift must contain one XOR r32, r/m32 to retarget at the \
                 same length so the seeded defect is a single byte: {code:02x?}"
            );
        };
        assert_eq!(
            mutant.len(),
            code.len(),
            "{identity}: the seeded defect must not resize the function"
        );
        let differing: usize = code
            .iter()
            .zip(mutant.iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
        assert_eq!(
            differing, 1,
            "{identity}: exactly one byte may differ between the real function and the mutant"
        );
        let outcome: Option<SubstitutionResult> =
            undo_ollvm_substitution(DeobfBits::Bits64, BASE, &mutant);
        println!("{identity}/carry_add_shift mutant verdict: {outcome:?}");
        let weaker_signals_still_hold: bool =
            outcome.as_ref().is_some_and(|r: &SubstitutionResult| {
                r.changed && r.proven && r.simplified_nodes < r.original_nodes
            });
        println!(
            "{identity}/carry_add_shift mutant still satisfies changed+proven+shrunk: \
             {weaker_signals_still_hold}, so only the recovered-expression check discriminates"
        );
        let accepted_as_addition: bool = outcome.as_ref().is_some_and(|r: &SubstitutionResult| {
            r.proven && is_addition_of_two_distinct_variables(&r.simplified_expr)
        });
        assert!(
            !accepted_as_addition,
            "{identity}: (a | b) + ((a & b) << 1) is not a + b, so the grade that accepts \
             carry_add_shift must reject this one-byte mutant of it: {outcome:?}"
        );
        graded += 1;
    }
    assert!(
        graded > 0,
        "this control needs one C compiler out of cc/gcc/clang that can emit an x86-64 object; \
         candidates were {compilers:?} and every attempt was rejected [{}]",
        rejected.join(" | ")
    );
    println!("rejected the seeded defect on {graded} real compiler-emitted functions");
}
