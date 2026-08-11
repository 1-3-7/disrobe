use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_native::{
    CallSiteReturnProof, CallSiteSignatureProof, PseudoReg as Reg, PseudoScalarType as ScalarType,
    RecoveredFunction, RecoveredProgram, recover_aarch64_program,
};
use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, RelocationFlags, RelocationTarget,
};
use tempfile::TempDir;

const OPTIMIZATION_LEVELS: [&str; 5] = ["O0", "O1", "O2", "O3", "Os"];
const CALLEE_C: &str = r"
__attribute__((noinline)) float fp_id_f(float x) { return x; }
__attribute__((noinline)) double fp_id_d(double x) { return x; }
__attribute__((noinline)) unsigned id_w(unsigned x) { return x; }
__attribute__((noinline)) unsigned long long id_x(unsigned long long x) { return x; }
";
const CALLER_C: &str = r"
extern float fp_id_f(float);
extern double fp_id_d(double);
extern unsigned id_w(unsigned);
extern unsigned long long id_x(unsigned long long);
float consume_fp_id_f(const float *p) { return fp_id_f(*p) + 1.0f; }
double consume_fp_id_d(const double *p) { return fp_id_d(*p) + 1.0; }
unsigned consume_id_w(const unsigned *p) { return id_w(*p) + 1U; }
unsigned long long consume_id_x(const unsigned long long *p) { return id_x(*p) + 1ULL; }
";
const HOST_ORIGINALS: &str = r"
float orig_fp_id_f(float x) { return x; }
double orig_fp_id_d(double x) { return x; }
unsigned orig_id_w(unsigned x) { return x; }
unsigned long long orig_id_x(unsigned long long x) { return x; }
";
const HOST_HELPERS: &str = r"
static inline double fp_d_from_bits(uint64_t b) { double v; memcpy(&v, &b, 8); return v; }
static inline uint64_t fp_d_to_bits(double v) { uint64_t b; memcpy(&b, &v, 8); return b; }
static inline float fp_f_from_bits(uint32_t b) { float v; memcpy(&v, &b, 4); return v; }
static inline uint32_t fp_f_to_bits(float v) { uint32_t b; memcpy(&b, &v, 4); return b; }
";
const HOST_MAIN: &str = r"
typedef union { float f; unsigned u; } f32_bits;
typedef union { double f; unsigned long long u; } f64_bits;
int main(void) {
    const unsigned fv[] = { 0U, 0x80000000U, 0x3f800000U, 0x7fc12345U };
    const unsigned long long dv[] = {
        0ULL, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0x7ff8123456789abcULL
    };
    for (unsigned i = 0; i < 4U; ++i) {
        f32_bits fa = { .u = fv[i] };
        f32_bits fo = { .f = orig_fp_id_f(fa.f) };
        f32_bits fr = { .f = rec_fp_id_f(fa.f) };
        f64_bits da = { .u = dv[i] };
        f64_bits do_ = { .f = orig_fp_id_d(da.f) };
        f64_bits dr = { .f = rec_fp_id_d(da.f) };
        if (fo.u != fr.u || do_.u != dr.u) return 1;
        if (orig_id_w(fv[i]) != rec_id_w(fv[i])) return 2;
        if (orig_id_x(dv[i]) != rec_id_x(dv[i])) return 3;
    }
    return 0;
}
";
const RET_CALLEE_ASM: &str = r"
.text
.globl target
.type target,%function
target:
    ret
.size target, .-target
";
const AMBIGUOUS_CALLEE_C: &str = r"
__attribute__((noinline)) float fp_id_f(float x) { return x; }
";
const RETURNING_CALLER_C: &str = r"
extern float fp_id_f(float);
__attribute__((noinline, disable_tail_calls))
float ambiguous(const float *p) { return fp_id_f(*p); }
";
const DISCARDING_CALLER_C: &str = r"
extern float fp_id_f(float);
__attribute__((noinline, disable_tail_calls))
void ambiguous(const float *p) { (void)fp_id_f(*p); }
";

#[derive(Debug, PartialEq, Eq)]
struct CompiledFunctionShape {
    code: Vec<u8>,
    relocations: Vec<(u64, u32, i64, String)>,
}

fn command_output(command: &mut Command) -> Output {
    let output: Output = command
        .output()
        .unwrap_or_else(|error| panic!("command did not start: {command:?}: {error}"));
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn compile_translation_unit(
    directory: &Path,
    stem: &str,
    extension: &str,
    source: &str,
    optimization: &str,
) -> PathBuf {
    let source_path: PathBuf = directory.join(format!("{stem}.{extension}"));
    let object_path: PathBuf = directory.join(format!("{stem}.o"));
    fs::write(&source_path, source).expect("fixture source must be writable");
    let mut command: Command = Command::new("clang");
    command
        .arg("--target=aarch64-unknown-linux-gnu")
        .arg(format!("-{optimization}"))
        .arg("-ffreestanding")
        .arg("-fno-stack-protector")
        .arg("-ffunction-sections")
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path);
    let _: Output = command_output(&mut command);
    object_path
}

fn linker_path() -> PathBuf {
    let mut locate: Command = Command::new("clang");
    locate.arg("--print-prog-name=ld.lld");
    let located: Output = command_output(&mut locate);
    let printed: String = String::from_utf8(located.stdout).expect("linker path must be utf-8");
    let candidate: PathBuf = PathBuf::from(printed.trim());
    if candidate.is_file() {
        candidate
    } else {
        PathBuf::from(format!("{}.exe", candidate.display()))
    }
}

fn link_with(directory: &Path, objects: &[PathBuf], mode: &str, stem: &str) -> Vec<u8> {
    let output_path: PathBuf = directory.join(stem);
    let mut command: Command = Command::new(linker_path());
    command.arg(mode);
    for object_path in objects {
        command.arg(object_path);
    }
    command.arg("-o").arg(&output_path);
    let _: Output = command_output(&mut command);
    fs::read(output_path).expect("linked fixture must be readable")
}

fn link_relocatable(directory: &Path, objects: &[PathBuf]) -> Vec<u8> {
    link_with(directory, objects, "-r", "combined.o")
}

fn link_shared(directory: &Path, objects: &[PathBuf]) -> Vec<u8> {
    link_with(directory, objects, "-shared", "combined.so")
}

fn compile_c_pair(callee: &str, caller: &str, optimization: &str) -> Vec<u8> {
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let callee_object: PathBuf =
        compile_translation_unit(directory.path(), "callee", "c", callee, optimization);
    let caller_object: PathBuf =
        compile_translation_unit(directory.path(), "caller", "c", caller, optimization);
    link_relocatable(directory.path(), &[callee_object, caller_object])
}

fn compile_asm_units(units: &[(&str, &str)]) -> Vec<u8> {
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let mut objects: Vec<PathBuf> = Vec::with_capacity(units.len());
    for (stem, source) in units {
        let object_path: PathBuf =
            compile_translation_unit(directory.path(), stem, "s", source, "O1");
        objects.push(object_path);
    }
    link_relocatable(directory.path(), &objects)
}

fn compile_single_asm(source: &str) -> Vec<u8> {
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let object_path: PathBuf =
        compile_translation_unit(directory.path(), "fixture", "s", source, "O1");
    fs::read(object_path).expect("fixture object must be readable")
}

fn compiled_function_shape(object_bytes: &[u8], name: &str) -> CompiledFunctionShape {
    let file: object::File<'_> =
        object::File::parse(object_bytes).expect("compiled object must parse");
    let symbol: object::Symbol<'_, '_> = file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| {
            symbol.is_definition() && symbol.name().is_ok_and(|candidate: &str| candidate == name)
        })
        .unwrap_or_else(|| panic!("compiled object lacks function symbol {name}"));
    let section_index: object::SectionIndex = symbol
        .section_index()
        .unwrap_or_else(|| panic!("function symbol {name} lacks a section"));
    let section: object::Section<'_, '_> = file
        .section_by_index(section_index)
        .unwrap_or_else(|error: object::Error| panic!("function section is unavailable: {error}"));
    let section_data: &[u8] = section
        .data()
        .expect("function section data must be readable");
    let section_address: u64 = section.address();
    let function_address: u64 = symbol.address();
    let function_size: u64 = symbol.size();
    assert!(
        function_size > 0,
        "function symbol {name} has no bounded body"
    );
    let function_end_address: u64 = function_address
        .checked_add(function_size)
        .expect("function address range must fit in u64");
    let function_offset: u64 = function_address
        .checked_sub(section_address)
        .expect("function address must not precede its section");
    let start: usize = usize::try_from(function_offset).expect("function offset must fit in usize");
    let size: usize = usize::try_from(function_size).expect("function size must fit in usize");
    let end: usize = start
        .checked_add(size)
        .expect("function byte range must fit in usize");
    let code: Vec<u8> = section_data
        .get(start..end)
        .unwrap_or_else(|| panic!("function {name} exceeds its section"))
        .to_vec();
    let mut relocations: Vec<(u64, u32, i64, String)> = Vec::new();
    for (section_offset, relocation) in section.relocations() {
        let relocation_address: u64 = section_address
            .checked_add(section_offset)
            .expect("relocation address must fit in u64");
        if relocation_address < function_address || relocation_address >= function_end_address {
            continue;
        }
        let relative_offset: u64 = relocation_address
            .checked_sub(function_address)
            .expect("function relocation offset must be non-negative");
        let r_type: u32 = match relocation.flags() {
            RelocationFlags::Elf { r_type } => r_type,
            flags => panic!("function relocation must use ELF flags, got {flags:?}"),
        };
        let target_index: object::SymbolIndex = match relocation.target() {
            RelocationTarget::Symbol(index) => index,
            target => panic!("function relocation must target a symbol, got {target:?}"),
        };
        let target: object::Symbol<'_, '_> = file
            .symbol_by_index(target_index)
            .unwrap_or_else(|error: object::Error| panic!("relocation target is invalid: {error}"));
        let target_name: String = target
            .name()
            .expect("relocation target name must be valid UTF-8")
            .to_owned();
        relocations.push((relative_offset, r_type, relocation.addend(), target_name));
    }
    CompiledFunctionShape { code, relocations }
}

fn recovered<'a>(program: &'a RecoveredProgram, name: &str) -> &'a RecoveredFunction {
    program
        .recovered
        .iter()
        .find(|function: &&RecoveredFunction| function.name == name)
        .unwrap_or_else(|| {
            let reason: String = program
                .unrecovered
                .iter()
                .find(|function| function.name == name)
                .map_or_else(
                    || "missing symbol".to_owned(),
                    |function| function.reason.clone(),
                );
            panic!("{name} was not recovered: {reason}")
        })
}

fn refused_reason(program: &RecoveredProgram, name: &str) -> String {
    program
        .unrecovered
        .iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("{name} was unexpectedly recovered"))
        .reason
        .clone()
}

fn proof(function: &RecoveredFunction) -> CallSiteSignatureProof {
    function
        .call_site_signature
        .clone()
        .unwrap_or_else(|| panic!("{} lacks call-site proof", function.name))
}

fn recovered_body(source: &str, original_name: &str, recovered_name: &str) -> String {
    source
        .lines()
        .filter(|line: &&str| {
            !line.starts_with("#include")
                && !line.starts_with("static inline double fp_d_from_bits")
                && !line.starts_with("static inline uint64_t fp_d_to_bits")
                && !line.starts_with("static inline float fp_f_from_bits")
                && !line.starts_with("static inline uint32_t fp_f_to_bits")
        })
        .collect::<Vec<&str>>()
        .join("\n")
        .replacen(
            &format!(" {original_name}("),
            &format!(" {recovered_name}("),
            1,
        )
}

fn verify_host_equivalence(program: &RecoveredProgram) {
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let source_path: PathBuf = directory.path().join("grade.c");
    let executable_path: PathBuf = directory.path().join("grade.exe");
    let mut source: String = String::from("#include <stdint.h>\n#include <string.h>\n");
    source.push_str(HOST_HELPERS);
    source.push_str(HOST_ORIGINALS);
    for name in ["fp_id_f", "fp_id_d", "id_w", "id_x"] {
        let function: &RecoveredFunction = recovered(program, name);
        source.push_str(&recovered_body(
            &function.source,
            name,
            &format!("rec_{name}"),
        ));
        source.push('\n');
    }
    source.push_str(HOST_MAIN);
    fs::write(&source_path, source).expect("host grade source must be writable");
    let compiler: String = super::cc().expect("host C compiler must be available");
    let mut compile: Command = Command::new(compiler);
    compile
        .arg("-O1")
        .arg("-fno-fast-math")
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path);
    let _: Output = command_output(&mut compile);
    let mut execute: Command = Command::new(&executable_path);
    let _: Output = command_output(&mut execute);
}

fn assert_fp_signature(
    function: &RecoveredFunction,
    scalar: ScalarType,
    rule: CallSiteReturnProof,
) {
    assert_eq!(function.returns_fp, Some(scalar));
    assert_eq!(function.signature.parameter_types(), vec![scalar]);
    assert!(function.signature.observed_integer_registers().is_empty());
    assert!(function.signature.integer_width_bits().is_empty());
    let evidence: CallSiteSignatureProof = proof(function);
    assert_eq!(evidence.return_proof, rule);
    assert_eq!(evidence.attributed_sites, 1);
}

fn assert_int_signature(function: &RecoveredFunction, width: u32, rule: CallSiteReturnProof) {
    assert_eq!(function.returns_fp, None);
    assert!(function.signature.parameter_types().is_empty());
    assert_eq!(
        function.signature.observed_integer_registers(),
        vec![Reg::Rax]
    );
    assert_eq!(function.signature.integer_width_bits(), vec![width]);
    let evidence: CallSiteSignatureProof = proof(function);
    assert_eq!(evidence.return_proof, rule);
    assert_eq!(evidence.attributed_sites, 1);
}

#[test]
#[ignore = "requires clang, ld.lld, and a host C compiler"]
fn call_site_signature_matrix_recompiles_equivalently() {
    let mut graded: usize = 0;
    for optimization in OPTIMIZATION_LEVELS {
        let object: Vec<u8> = compile_c_pair(CALLEE_C, CALLER_C, optimization);
        let program: RecoveredProgram = recover_aarch64_program(&object);
        let fp_f: &RecoveredFunction = recovered(&program, "fp_id_f");
        let fp_d: &RecoveredFunction = recovered(&program, "fp_id_d");
        let id_w: &RecoveredFunction = recovered(&program, "id_w");
        let id_x: &RecoveredFunction = recovered(&program, "id_x");
        if optimization == "O0" {
            assert!(fp_f.call_site_signature.is_none());
            assert!(fp_d.call_site_signature.is_none());
            assert!(id_w.call_site_signature.is_none());
            assert!(id_x.call_site_signature.is_none());
        } else {
            assert_fp_signature(
                fp_f,
                ScalarType::Float,
                CallSiteReturnProof::FloatingPoint32,
            );
            assert_fp_signature(
                fp_d,
                ScalarType::Double,
                CallSiteReturnProof::FloatingPoint64,
            );
            assert_int_signature(id_w, 32, CallSiteReturnProof::UnanimousInteger32);
            assert_int_signature(id_x, 64, CallSiteReturnProof::Integer64);
        }
        verify_host_equivalence(&program);
        graded += 4;
    }
    assert_eq!(graded, 20);
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn bare_call_does_not_prove_a_floating_point_return() {
    for optimization in ["O1", "O2", "O3", "Os"] {
        let returning_object: Vec<u8> =
            compile_c_pair(AMBIGUOUS_CALLEE_C, RETURNING_CALLER_C, optimization);
        let discarding_object: Vec<u8> =
            compile_c_pair(AMBIGUOUS_CALLEE_C, DISCARDING_CALLER_C, optimization);
        let returning_shape: CompiledFunctionShape =
            compiled_function_shape(&returning_object, "ambiguous");
        let discarding_shape: CompiledFunctionShape =
            compiled_function_shape(&discarding_object, "ambiguous");
        assert_eq!(
            returning_shape, discarding_shape,
            "returning and discarding callers must be indistinguishable at {optimization}"
        );
        assert_eq!(returning_shape.relocations.len(), 1);
        assert_eq!(
            returning_shape.relocations[0].1,
            object::elf::R_AARCH64_CALL26
        );
        assert_eq!(returning_shape.relocations[0].3, "fp_id_f");
        let returning_program: RecoveredProgram = recover_aarch64_program(&returning_object);
        let discarding_program: RecoveredProgram = recover_aarch64_program(&discarding_object);
        let returning_reason: String = refused_reason(&returning_program, "fp_id_f");
        let discarding_reason: String = refused_reason(&discarding_program, "fp_id_f");
        assert_eq!(returning_reason, discarding_reason);
        assert!(returning_reason.contains("every attributed caller ignores the result"));
        assert!(returning_reason.contains("return type remains underdetermined"));
    }
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn relocation_symbols_keep_aliased_signatures_separate() {
    let callee: &str = r"
.text
.globl alias_f
.globl alias_d
.type alias_f,%function
.type alias_d,%function
alias_f:
alias_d:
    ret
.size alias_f, .-alias_f
.size alias_d, .-alias_d
";
    let float_caller: &str = r"
.text
.globl call_alias_f
.type call_alias_f,%function
call_alias_f:
    ldr s0, [x0]
    bl alias_f
    fadd s0, s0, s1
    ret
.size call_alias_f, .-call_alias_f
";
    let double_caller: &str = r"
.text
.globl call_alias_d
.type call_alias_d,%function
call_alias_d:
    ldr d0, [x0]
    bl alias_d
    fadd d0, d0, d1
    ret
.size call_alias_d, .-call_alias_d
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", callee),
        ("float_caller", float_caller),
        ("double_caller", double_caller),
    ]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    assert_fp_signature(
        recovered(&program, "alias_f"),
        ScalarType::Float,
        CallSiteReturnProof::FloatingPoint32,
    );
    assert_fp_signature(
        recovered(&program, "alias_d"),
        ScalarType::Double,
        CallSiteReturnProof::FloatingPoint64,
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn half_precision_call_site_evidence_reaches_the_public_signature_proof() {
    let callee: &str = r"
.text
.arch armv8.2-a+fp16
.globl half_target
.type half_target,%function
half_target:
    ret
.size half_target, .-half_target
";
    let caller: &str = r"
.text
.arch armv8.2-a+fp16
.globl half_caller
.type half_caller,%function
half_caller:
    ldr h0, [x0]
    bl half_target
    fadd h0, h0, h1
    ret
.size half_caller, .-half_caller
";
    let object: Vec<u8> = compile_asm_units(&[("half_callee", callee), ("half_caller", caller)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    assert_fp_signature(
        recovered(&program, "half_target"),
        ScalarType::Half,
        CallSiteReturnProof::FloatingPoint16,
    );
}

#[test]
#[ignore = "requires clang"]
fn unique_direct_branch_without_relocation_is_attributed() {
    let source: &str = r"
.text
.globl direct_target
.type direct_target,%function
direct_target:
    ret
.size direct_target, .-direct_target
.globl direct_caller
.type direct_caller,%function
direct_caller:
    ldr s0, [x0]
    .inst 0x97fffffe
    fadd s0, s0, s1
    ret
.size direct_caller, .-direct_caller
";
    let object: Vec<u8> = compile_single_asm(source);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    assert_fp_signature(
        recovered(&program, "direct_target"),
        ScalarType::Float,
        CallSiteReturnProof::FloatingPoint32,
    );
}

#[test]
#[ignore = "requires clang"]
fn direct_branch_to_aliased_address_is_not_attributed() {
    let source: &str = r"
.text
.globl direct_alias_f
.globl direct_alias_d
.type direct_alias_f,%function
.type direct_alias_d,%function
direct_alias_f:
direct_alias_d:
    ret
.size direct_alias_f, .-direct_alias_f
.size direct_alias_d, .-direct_alias_d
.globl direct_alias_caller
.type direct_alias_caller,%function
direct_alias_caller:
    ldr s0, [x0]
    .inst 0x97fffffe
    fadd s0, s0, s1
    ret
.size direct_alias_caller, .-direct_alias_caller
";
    let object: Vec<u8> = compile_single_asm(source);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let float_reason: String = refused_reason(&program, "direct_alias_f");
    let double_reason: String = refused_reason(&program, "direct_alias_d");
    assert!(float_reason.contains("result-free return is ambiguous"));
    assert!(double_reason.contains("result-free return is ambiguous"));
}

#[test]
#[ignore = "requires clang"]
fn zero_sized_alias_blocks_direct_address_attribution() {
    let source: &str = r"
.text
.globl zero_alias_target
.globl zero_alias_shadow
.type zero_alias_target,%function
.type zero_alias_shadow,%function
zero_alias_target:
zero_alias_shadow:
    ret
.size zero_alias_target, .-zero_alias_target
.globl zero_alias_caller
.type zero_alias_caller,%function
zero_alias_caller:
    ldr s0, [x0]
    .inst 0x97fffffe
    fadd s0, s0, s1
    ret
.size zero_alias_caller, .-zero_alias_caller
";
    let object: Vec<u8> = compile_single_asm(source);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let reason: String = refused_reason(&program, "zero_alias_target");
    assert!(
        reason.contains("result-free return is ambiguous"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn tail_jump_contributes_argument_evidence() {
    let normal_caller: &str = r"
.text
.globl normal_caller
.type normal_caller,%function
normal_caller:
    bl target
    fadd s0, s0, s1
    ret
.size normal_caller, .-normal_caller
";
    let tail_caller: &str = r"
.text
.globl tail_caller
.type tail_caller,%function
tail_caller:
    ldr s0, [x0]
    b target
.size tail_caller, .-tail_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("normal", normal_caller),
        ("tail", tail_caller),
    ]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "target");
    assert_eq!(
        function.signature.parameter_types(),
        vec![ScalarType::Float]
    );
    assert_eq!(proof(function).attributed_sites, 2);
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn stale_pre_call_s0_does_not_prove_a_return() {
    let caller: &str = r"
.text
.globl stale_caller
.type stale_caller,%function
stale_caller:
    fmov s0, w0
    str s0, [x1]
    bl target
    mov w0, 7
    ret
.size stale_caller, .-stale_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("every attributed caller ignores the result"));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn disagreeing_attributed_sites_refuse() {
    let float_caller: &str = r"
.text
.globl float_caller
.type float_caller,%function
float_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
.size float_caller, .-float_caller
";
    let double_caller: &str = r"
.text
.globl double_caller
.type double_caller,%function
double_caller:
    ldr d0, [x0]
    bl target
    fadd d0, d0, d1
    ret
.size double_caller, .-double_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("float", float_caller),
        ("double", double_caller),
    ]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("proof-grade attributed sites disagree"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn argument_arity_conflict_refuses() {
    let unary_caller: &str = r"
.text
.globl unary_caller
.type unary_caller,%function
unary_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s2
    ret
.size unary_caller, .-unary_caller
";
    let binary_caller: &str = r"
.text
.globl binary_caller
.type binary_caller,%function
binary_caller:
    ldp s0, s1, [x0]
    bl target
    fadd s0, s0, s2
    ret
.size binary_caller, .-binary_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("unary", unary_caller),
        ("binary", binary_caller),
    ]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("argument class, width, or arity"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn return_width_conflict_refuses() {
    let float_caller: &str = r"
.text
.globl float_width_caller
.type float_width_caller,%function
float_width_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
.size float_width_caller, .-float_width_caller
";
    let double_caller: &str = r"
.text
.globl double_width_caller
.type double_width_caller,%function
double_width_caller:
    ldr s0, [x0]
    bl target
    fadd d0, d0, d1
    ret
.size double_width_caller, .-double_width_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("float", float_caller),
        ("double", double_caller),
    ]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("return class or width"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn contradictory_attributed_site_is_not_ignored() {
    let valid_caller: &str = r"
.text
.globl valid_caller
.type valid_caller,%function
valid_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
.size valid_caller, .-valid_caller
";
    let contradictory_caller: &str = r"
.text
.globl contradictory_caller
.type contradictory_caller,%function
contradictory_caller:
    ldr s0, [x0]
    bl target
    fmov w1, s0
    add x0, x0, 1
    ret
.size contradictory_caller, .-contradictory_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("valid", valid_caller),
        ("contradictory", contradictory_caller),
    ]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("both floating-point and integer result registers"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn unsupported_result_access_invalidates_the_site() {
    let caller: &str = r"
.text
.globl unsupported_result_caller
.type unsupported_result_caller,%function
unsupported_result_caller:
    ldr s0, [x0]
    bl target
    cbz w1, 1f
    fadd s0, s0, s1
    ret
1:
    orr v1.16b, v0.16b, v0.16b
    ret
.size unsupported_result_caller, .-unsupported_result_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("unsupported result-register access"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn unresolved_post_call_edge_invalidates_the_site() {
    let caller: &str = r"
.text
.globl unresolved_result_caller
.type unresolved_result_caller,%function
unresolved_result_caller:
    ldr s0, [x0]
    bl target
    cbnz w1, external_result_consumer
    fadd s0, s0, s1
    ret
.size unresolved_result_caller, .-unresolved_result_caller
.globl external_result_consumer
.type external_result_consumer,%function
external_result_consumer:
    fadd d0, d0, d1
    ret
.size external_result_consumer, .-external_result_consumer
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("unresolved post-call control-flow edge"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn result_register_width_must_match_the_proven_argument() {
    let caller: &str = r"
.text
.globl mismatched_width_caller
.type mismatched_width_caller,%function
mismatched_width_caller:
    ldr s0, [x0]
    bl target
    fadd d0, d0, d1
    ret
.size mismatched_width_caller, .-mismatched_width_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn nonprefix_register_evidence_refuses() {
    let caller: &str = r"
.text
.globl nonprefix_caller
.type nonprefix_caller,%function
nonprefix_caller:
    ldr s0, [x0]
    ldr s3, [x1]
    bl target
    fadd s0, s0, s1
    ret
.size nonprefix_caller, .-nonprefix_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("floating-point register prefix"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn universally_ignored_result_refuses() {
    let caller: &str = r"
.text
.globl ignored_caller
.type ignored_caller,%function
ignored_caller:
    ldr s0, [x0]
    bl target
    mov w0, 7
    ret
.size ignored_caller, .-ignored_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("return type remains underdetermined"));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn post_call_redefinition_blocks_a_stale_read() {
    let caller: &str = r"
.text
.globl redefined_caller
.type redefined_caller,%function
redefined_caller:
    ldr s0, [x0]
    bl target
    fmov s0, w1
    fadd s0, s0, s1
    ret
.size redefined_caller, .-redefined_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x_read_dominates_compatible_w_reads() {
    let word_caller: &str = r"
.text
.globl word_caller
.type word_caller,%function
word_caller:
    ldr w0, [x0]
    bl target
    add w0, w0, 1
    ret
.size word_caller, .-word_caller
";
    let extended_caller: &str = r"
.text
.globl extended_caller
.type extended_caller,%function
extended_caller:
    ldr w0, [x0]
    bl target
    add x0, x0, 1
    ret
.size extended_caller, .-extended_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("word", word_caller),
        ("extended", extended_caller),
    ]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "target");
    assert_eq!(function.return_width_bits, 64);
    assert_eq!(function.signature.integer_width_bits(), vec![32]);
    assert_eq!(proof(function).return_proof, CallSiteReturnProof::Integer64);
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn indirect_composite_without_layout_refuses() {
    let caller: &str = r"
.text
.globl composite_caller
.type composite_caller,%function
composite_caller:
    sub sp, sp, 32
    add x8, sp, 8
    bl target
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size composite_caller, .-composite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("indirect composite return but not its layout"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn discarded_argument_site_contributes_no_composite_evidence() {
    let composite_caller: &str = r"
.text
.globl noisy_composite_caller
.type noisy_composite_caller,%function
noisy_composite_caller:
    sub sp, sp, 32
    ldr s3, [x0]
    add x8, sp, 8
    bl target
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size noisy_composite_caller, .-noisy_composite_caller
";
    let scalar_caller: &str = r"
.text
.globl scalar_caller
.type scalar_caller,%function
scalar_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
.size scalar_caller, .-scalar_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("composite", composite_caller),
        ("scalar", scalar_caller),
    ]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "target");
    assert_eq!(
        function.signature.parameter_types(),
        vec![ScalarType::Float]
    );
    assert_eq!(function.returns_fp, Some(ScalarType::Float));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_setup_without_a_buffer_read_proves_nothing() {
    let caller: &str = r"
.text
.globl unused_composite_caller
.type unused_composite_caller,%function
unused_composite_caller:
    sub sp, sp, 32
    add x8, sp, 8
    bl target
    mov w0, 7
    add sp, sp, 32
    ret
.size unused_composite_caller, .-unused_composite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_nonbuffer_definition_proves_nothing() {
    let caller: &str = r"
.text
.globl nonbuffer_composite_caller
.type nonbuffer_composite_caller,%function
nonbuffer_composite_caller:
    sub sp, sp, 32
    mov x8, x0
    bl target
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size nonbuffer_composite_caller, .-nonbuffer_composite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_buffer_base_change_proves_nothing() {
    let caller: &str = r"
.text
.globl moving_buffer_caller
.type moving_buffer_caller,%function
moving_buffer_caller:
    sub sp, sp, 32
    add x8, sp, 8
    sub sp, sp, 16
    bl target
    ldr x0, [sp, 8]
    add sp, sp, 48
    ret
.size moving_buffer_caller, .-moving_buffer_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_buffer_store_before_read_proves_nothing() {
    let caller: &str = r"
.text
.globl overwritten_buffer_caller
.type overwritten_buffer_caller,%function
overwritten_buffer_caller:
    sub sp, sp, 32
    add x8, sp, 8
    bl target
    str x1, [sp, 8]
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size overwritten_buffer_caller, .-overwritten_buffer_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_buffer_alias_store_before_read_proves_nothing() {
    let caller: &str = r"
.text
.globl alias_overwrite_caller
.type alias_overwrite_caller,%function
alias_overwrite_caller:
    sub sp, sp, 32
    add x8, sp, 8
    bl target
    add x9, sp, 8
    str x1, [x9]
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size alias_overwrite_caller, .-alias_overwrite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn x8_system_memory_effect_before_read_proves_nothing() {
    let caller: &str = r"
.arch armv8.5-a+memtag
.text
.globl system_overwrite_caller
.type system_overwrite_caller,%function
system_overwrite_caller:
    sub sp, sp, 32
    add x8, sp, 8
    bl target
    add x9, sp, 8
    dc gzva, x9
    ldr x0, [sp, 8]
    add sp, sp, 32
    ret
.size system_overwrite_caller, .-system_overwrite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn call_relocation_requires_a_matching_branch_opcode() {
    let caller: &str = r"
.text
.globl mismatched_caller
.type mismatched_caller,%function
mismatched_caller:
    ldr s0, [x0]
1:
    nop
    .reloc 1b, R_AARCH64_CALL26, target
    fadd s0, s0, s1
    ret
.size mismatched_caller, .-mismatched_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("result-free return is ambiguous"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn nonzero_call_relocation_addend_is_not_attributed() {
    let callee: &str = r"
.text
.globl addend_target
.type addend_target,%function
addend_target:
    ret
    ret
.size addend_target, .-addend_target
";
    let caller: &str = r"
.text
.globl addend_caller
.type addend_caller,%function
addend_caller:
    ldr s0, [x0]
    bl addend_target+4
    fadd s0, s0, s1
    ret
.size addend_caller, .-addend_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", callee), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "addend_target");
    assert!(
        reason.contains("result-free return is ambiguous"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn mixed_register_classes_preserve_the_recovered_interface() {
    let callee: &str = r"
.text
.globl mixed_target
.type mixed_target,%function
mixed_target:
    ret
.size mixed_target, .-mixed_target
";
    let caller: &str = r"
.text
.globl mixed_caller
.type mixed_caller,%function
mixed_caller:
    ldr s0, [x0]
    ldr w0, [x1]
    bl mixed_target
    fadd s0, s0, s1
    ret
.size mixed_caller, .-mixed_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", callee), ("caller", caller)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "mixed_target");
    assert_eq!(
        function.signature.parameter_types(),
        vec![ScalarType::Float, ScalarType::Int]
    );
    assert_eq!(
        function.signature.observed_integer_registers(),
        vec![Reg::Rax]
    );
    assert_eq!(function.signature.integer_width_bits(), vec![32]);
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn intervening_parameter_use_refuses() {
    let caller: &str = r"
.text
.globl used_caller
.type used_caller,%function
used_caller:
    ldr s0, [x0]
    str s0, [x1]
    bl target
    fadd s0, s0, s1
    ret
.size used_caller, .-used_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn read_modify_write_parameter_definition_refuses() {
    let caller: &str = r"
.text
.globl read_modify_write_caller
.type read_modify_write_caller,%function
read_modify_write_caller:
    mov x0, 1
    movk x0, 2, lsl 16
    bl target
    add x0, x0, 1
    ret
.size read_modify_write_caller, .-read_modify_write_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn alternate_parameter_consumer_refuses() {
    let caller: &str = r"
.text
.globl alternate_caller
.type alternate_caller,%function
alternate_caller:
    ldr s0, [x0]
    cbz w1, 1f
    fmov s2, s0
    ret
1:
    bl target
    fadd s0, s0, s1
    ret
.size alternate_caller, .-alternate_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn out_of_body_branch_target_blocks_argument_exclusivity() {
    let caller: &str = r"
.text
.globl escaping_caller
.type escaping_caller,%function
escaping_caller:
    ldr s0, [x0]
    cbnz w1, alternate_consumer
    bl target
    fadd s0, s0, s1
    ret
.size escaping_caller, .-escaping_caller
.globl alternate_consumer
.type alternate_consumer,%function
alternate_consumer:
    fmov s2, s0
    ret
.size alternate_consumer, .-alternate_consumer
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn store_exclusive_status_write_does_not_read_a_result() {
    let caller: &str = r"
.text
.globl exclusive_store_caller
.type exclusive_store_caller,%function
exclusive_store_caller:
    ldr w0, [x0]
    ldxr w1, [x2]
    bl target
    stxr w0, w1, [x2]
    ret
.size exclusive_store_caller, .-exclusive_store_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn indirect_call_is_not_attributed() {
    let caller: &str = r"
.text
.globl indirect_caller
.type indirect_caller,%function
indirect_caller:
    ldr s0, [x0]
    adrp x16, target
    add x16, x16, :lo12:target
    blr x16
    fadd s0, s0, s1
    ret
.size indirect_caller, .-indirect_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("result-free return is ambiguous"));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn authenticated_indirect_calls_are_dataflow_barriers() {
    let callees: &str = r"
.text
.globl target_blraa
.type target_blraa,%function
target_blraa:
    ret
.size target_blraa, .-target_blraa
.globl target_blraaz
.type target_blraaz,%function
target_blraaz:
    ret
.size target_blraaz, .-target_blraaz
.globl target_blrab
.type target_blrab,%function
target_blrab:
    ret
.size target_blrab, .-target_blrab
.globl target_blrabz
.type target_blrabz,%function
target_blrabz:
    ret
.size target_blrabz, .-target_blrabz
";
    let callers: &str = r"
.arch armv8.3-a+pauth
.text
.globl caller_blraa
.type caller_blraa,%function
caller_blraa:
    ldr s0, [x0]
    blraa x16, x17
    bl target_blraa
    fadd s0, s0, s1
    ret
.size caller_blraa, .-caller_blraa
.globl caller_blraaz
.type caller_blraaz,%function
caller_blraaz:
    ldr s0, [x0]
    blraaz x16
    bl target_blraaz
    fadd s0, s0, s1
    ret
.size caller_blraaz, .-caller_blraaz
.globl caller_blrab
.type caller_blrab,%function
caller_blrab:
    ldr s0, [x0]
    blrab x16, x17
    bl target_blrab
    fadd s0, s0, s1
    ret
.size caller_blrab, .-caller_blrab
.globl caller_blrabz
.type caller_blrabz,%function
caller_blrabz:
    ldr s0, [x0]
    blrabz x16
    bl target_blrabz
    fadd s0, s0, s1
    ret
.size caller_blrabz, .-caller_blrabz
";
    let object: Vec<u8> = compile_asm_units(&[("callees", callees), ("callers", callers)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let blraa: String = refused_reason(&program, "target_blraa");
    let blraaz: String = refused_reason(&program, "target_blraaz");
    let blrab: String = refused_reason(&program, "target_blrab");
    let blrabz: String = refused_reason(&program, "target_blrabz");
    assert!(blraa.contains("matching proven argument"), "{blraa}");
    assert!(blraaz.contains("matching proven argument"), "{blraaz}");
    assert!(blrab.contains("matching proven argument"), "{blrab}");
    assert!(blrabz.contains("matching proven argument"), "{blrabz}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn authenticated_returns_and_branches_end_dataflow_paths() {
    let callees: &str = r"
.text
.globl target_retaa
.type target_retaa,%function
target_retaa:
    ret
.size target_retaa, .-target_retaa
.globl target_retab
.type target_retab,%function
target_retab:
    ret
.size target_retab, .-target_retab
.globl target_braa
.type target_braa,%function
target_braa:
    ret
.size target_braa, .-target_braa
.globl target_braaz
.type target_braaz,%function
target_braaz:
    ret
.size target_braaz, .-target_braaz
.globl target_brab
.type target_brab,%function
target_brab:
    ret
.size target_brab, .-target_brab
.globl target_brabz
.type target_brabz,%function
target_brabz:
    ret
.size target_brabz, .-target_brabz
";
    let callers: &str = r"
.arch armv8.3-a+pauth
.text
.globl caller_retaa
.type caller_retaa,%function
caller_retaa:
    ldr s0, [x0]
    bl target_retaa
    retaa
    fadd s0, s0, s1
    ret
.size caller_retaa, .-caller_retaa
.globl caller_retab
.type caller_retab,%function
caller_retab:
    ldr s0, [x0]
    bl target_retab
    retab
    fadd s0, s0, s1
    ret
.size caller_retab, .-caller_retab
.globl caller_braa
.type caller_braa,%function
caller_braa:
    ldr s0, [x0]
    bl target_braa
    braa x16, x17
    fadd s0, s0, s1
    ret
.size caller_braa, .-caller_braa
.globl caller_braaz
.type caller_braaz,%function
caller_braaz:
    ldr s0, [x0]
    bl target_braaz
    braaz x16
    fadd s0, s0, s1
    ret
.size caller_braaz, .-caller_braaz
.globl caller_brab
.type caller_brab,%function
caller_brab:
    ldr s0, [x0]
    bl target_brab
    brab x16, x17
    fadd s0, s0, s1
    ret
.size caller_brab, .-caller_brab
.globl caller_brabz
.type caller_brabz,%function
caller_brabz:
    ldr s0, [x0]
    bl target_brabz
    brabz x16
    fadd s0, s0, s1
    ret
.size caller_brabz, .-caller_brabz
";
    let object: Vec<u8> = compile_asm_units(&[("callees", callees), ("callers", callers)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let retaa: String = refused_reason(&program, "target_retaa");
    let retab: String = refused_reason(&program, "target_retab");
    let braa: String = refused_reason(&program, "target_braa");
    let braaz: String = refused_reason(&program, "target_braaz");
    let brab: String = refused_reason(&program, "target_brab");
    let brabz: String = refused_reason(&program, "target_brabz");
    assert!(
        retaa.contains("return type remains underdetermined"),
        "{retaa}"
    );
    assert!(
        retab.contains("return type remains underdetermined"),
        "{retab}"
    );
    assert!(
        braa.contains("return type remains underdetermined"),
        "{braa}"
    );
    assert!(
        braaz.contains("return type remains underdetermined"),
        "{braaz}"
    );
    assert!(
        brab.contains("return type remains underdetermined"),
        "{brab}"
    );
    assert!(
        brabz.contains("return type remains underdetermined"),
        "{brabz}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn compatible_word_and_doubleword_reads_within_one_site_prove_x_width() {
    let caller: &str = r"
.text
.globl mixed_width_caller
.type mixed_width_caller,%function
mixed_width_caller:
    ldr x0, [x1]
    bl target
    cbz w2, 1f
    add w0, w0, 1
    ret
1:
    add x0, x0, 1
    ret
.size mixed_width_caller, .-mixed_width_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "target");
    assert_eq!(function.signature.integer_width_bits(), vec![64]);
    assert_eq!(function.return_width_bits, 64);
    assert_eq!(proof(function).return_proof, CallSiteReturnProof::Integer64);
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn malformed_caller_body_is_not_evidence() {
    let caller: &str = r"
.text
.globl malformed_caller
.type malformed_caller,%function
malformed_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
    .byte 0
.size malformed_caller, .-malformed_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("result-free return is ambiguous"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn malformed_result_free_body_is_not_recovered() {
    let callee: &str = r"
.text
.globl malformed_target
.type malformed_target,%function
malformed_target:
    ret
    .byte 0
.size malformed_target, .-malformed_target
";
    let caller: &str = r"
.text
.globl malformed_target_caller
.type malformed_target_caller,%function
malformed_target_caller:
    ldr s0, [x0]
    bl malformed_target
    fadd s0, s0, s1
    ret
.size malformed_target_caller, .-malformed_target_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", callee), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "malformed_target");
    assert!(reason.contains("four-byte aligned"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn oversized_result_free_body_is_not_recovered() {
    let callee: &str = r"
.text
.globl oversized_target
.type oversized_target,%function
oversized_target:
    .rept 4097
    ret
    .endr
.size oversized_target, .-oversized_target
";
    let caller: &str = r"
.text
.globl oversized_target_caller
.type oversized_target_caller,%function
oversized_target_caller:
    ldr s0, [x0]
    bl oversized_target
    fadd s0, s0, s1
    ret
.size oversized_target_caller, .-oversized_target_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", callee), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "oversized_target");
    assert!(reason.contains("bounded lift"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn unresolved_predecessor_blocks_argument_proof() {
    let caller: &str = r"
.text
.globl unresolved_predecessor_caller
.type unresolved_predecessor_caller,%function
unresolved_predecessor_caller:
    cbz w1, unresolved_join
    ldr s0, [x0]
.globl unresolved_join
unresolved_join:
    bl target
    fadd s0, s0, s1
    ret
.size unresolved_predecessor_caller, .-unresolved_predecessor_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(reason.contains("matching proven argument"), "{reason}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn unresolved_predecessor_blocks_indirect_composite_proof() {
    let caller: &str = r"
.text
.globl unresolved_composite_caller
.type unresolved_composite_caller,%function
unresolved_composite_caller:
    cbz w1, unresolved_composite_join
    add x8, sp, 8
.globl unresolved_composite_join
unresolved_composite_join:
    bl target
    ldr x0, [sp, 8]
    ret
.size unresolved_composite_caller, .-unresolved_composite_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("return type remains underdetermined"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn nonterminating_symbol_end_invalidates_result_proof() {
    let caller: &str = r"
.text
.globl unterminated_caller
.type unterminated_caller,%function
unterminated_caller:
    ldr s0, [x0]
    bl target
    cbz w1, 1f
    fadd s0, s0, s1
    ret
1:
    nop
.size unterminated_caller, .-unterminated_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("unresolved post-call control-flow edge"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn conditional_symbol_end_fallthrough_invalidates_result_proof() {
    let caller: &str = r"
.text
.globl unterminated_conditional_caller
.type unterminated_conditional_caller,%function
unterminated_conditional_caller:
    ldr s0, [x0]
    bl target
    cbz w1, 1f
    fadd s0, s0, s1
    ret
1:
    cbnz w2, 1b
.size unterminated_conditional_caller, .-unterminated_conditional_caller
";
    let object: Vec<u8> = compile_asm_units(&[("callee", RET_CALLEE_ASM), ("caller", caller)]);
    let reason: String = refused_reason(&recover_aarch64_program(&object), "target");
    assert!(
        reason.contains("unresolved post-call control-flow edge"),
        "{reason}"
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn nonprefix_site_discards_unsupported_result_evidence() {
    let noisy_caller: &str = r"
.text
.globl noisy_caller
.type noisy_caller,%function
noisy_caller:
    ldr s3, [x0]
    bl target
    orr v1.16b, v0.16b, v0.16b
    ret
.size noisy_caller, .-noisy_caller
";
    let scalar_caller: &str = r"
.text
.globl scalar_caller
.type scalar_caller,%function
scalar_caller:
    ldr s0, [x0]
    bl target
    fadd s0, s0, s1
    ret
.size scalar_caller, .-scalar_caller
";
    let object: Vec<u8> = compile_asm_units(&[
        ("callee", RET_CALLEE_ASM),
        ("noisy", noisy_caller),
        ("scalar", scalar_caller),
    ]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let function: &RecoveredFunction = recovered(&program, "target");
    assert_eq!(
        function.signature.parameter_types(),
        vec![ScalarType::Float]
    );
    assert_eq!(function.returns_fp, Some(ScalarType::Float));
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn exception_calls_are_result_dataflow_barriers() {
    let callees: &str = r"
.text
.globl target_svc
.type target_svc,%function
target_svc:
    ret
.size target_svc, .-target_svc
.globl target_hvc
.type target_hvc,%function
target_hvc:
    ret
.size target_hvc, .-target_hvc
.globl target_smc
.type target_smc,%function
target_smc:
    ret
.size target_smc, .-target_smc
";
    let callers: &str = r"
.text
.globl caller_svc
.type caller_svc,%function
caller_svc:
    ldr x0, [x1]
    bl target_svc
    svc #0
    add x0, x0, 1
    ret
.size caller_svc, .-caller_svc
.globl caller_hvc
.type caller_hvc,%function
caller_hvc:
    ldr x0, [x1]
    bl target_hvc
    hvc #0
    add x0, x0, 1
    ret
.size caller_hvc, .-caller_hvc
.globl caller_smc
.type caller_smc,%function
caller_smc:
    ldr x0, [x1]
    bl target_smc
    smc #0
    add x0, x0, 1
    ret
.size caller_smc, .-caller_smc
";
    let object: Vec<u8> = compile_asm_units(&[("callees", callees), ("callers", callers)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let svc: String = refused_reason(&program, "target_svc");
    let hvc: String = refused_reason(&program, "target_hvc");
    let smc: String = refused_reason(&program, "target_smc");
    assert!(svc.contains("return type remains underdetermined"), "{svc}");
    assert!(hvc.contains("return type remains underdetermined"), "{hvc}");
    assert!(smc.contains("return type remains underdetermined"), "{smc}");
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn exception_returns_end_result_dataflow_paths() {
    let callees: &str = r"
.text
.globl target_eret
.type target_eret,%function
target_eret:
    ret
.size target_eret, .-target_eret
.globl target_eretaa
.type target_eretaa,%function
target_eretaa:
    ret
.size target_eretaa, .-target_eretaa
.globl target_eretab
.type target_eretab,%function
target_eretab:
    ret
.size target_eretab, .-target_eretab
.globl target_drps
.type target_drps,%function
target_drps:
    ret
.size target_drps, .-target_drps
";
    let callers: &str = r"
.arch armv8.3-a+pauth
.text
.globl caller_eret
.type caller_eret,%function
caller_eret:
    ldr s0, [x0]
    bl target_eret
    eret
    fadd s0, s0, s1
    ret
.size caller_eret, .-caller_eret
.globl caller_eretaa
.type caller_eretaa,%function
caller_eretaa:
    ldr s0, [x0]
    bl target_eretaa
    eretaa
    fadd s0, s0, s1
    ret
.size caller_eretaa, .-caller_eretaa
.globl caller_eretab
.type caller_eretab,%function
caller_eretab:
    ldr s0, [x0]
    bl target_eretab
    eretab
    fadd s0, s0, s1
    ret
.size caller_eretab, .-caller_eretab
.globl caller_drps
.type caller_drps,%function
caller_drps:
    ldr s0, [x0]
    bl target_drps
    drps
    fadd s0, s0, s1
    ret
.size caller_drps, .-caller_drps
";
    let object: Vec<u8> = compile_asm_units(&[("callees", callees), ("callers", callers)]);
    let program: RecoveredProgram = recover_aarch64_program(&object);
    let eret: String = refused_reason(&program, "target_eret");
    let eretaa: String = refused_reason(&program, "target_eretaa");
    let eretab: String = refused_reason(&program, "target_eretab");
    let drps: String = refused_reason(&program, "target_drps");
    assert!(
        eret.contains("return type remains underdetermined"),
        "{eret}"
    );
    assert!(
        eretaa.contains("return type remains underdetermined"),
        "{eretaa}"
    );
    assert!(
        eretab.contains("return type remains underdetermined"),
        "{eretab}"
    );
    assert!(
        drps.contains("return type remains underdetermined"),
        "{drps}"
    );
}

const DENSE_SWITCH_LEVELS: [&str; 4] = ["O1", "O2", "O3", "Os"];
const DENSE_SWITCH_UNOPTIMIZED_LEVEL: &str = "O0";
const DENSE_SWITCH_LABELS_PER_TABLE: usize = 20;
const DENSE_SWITCH_DRAWS_PER_DISCRIMINANT: u32 = 8;
const DENSE_SWITCH_GUARD_MARGIN: i64 = 3;
const DENSE_SWITCH_MUTATED_FUNCTION: &str = "sw_tab_add";
const DENSE_SWITCH_MUTATED_LABEL: &str = "case 0:";
const DENSE_SWITCH_MUTATED_REPLACEMENT: &str = "case 4096:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenseSwitchShape {
    Unsigned32,
    Unsigned64,
    Signed32Small,
}

#[derive(Debug, Clone, Copy)]
struct DenseSwitchCase {
    name: &'static str,
    lowest_label: i64,
    highest_label: i64,
    shape: DenseSwitchShape,
}

const DENSE_SWITCH_CASES: [DenseSwitchCase; 6] = [
    DenseSwitchCase {
        name: "sw_tab_add",
        lowest_label: 0,
        highest_label: 19,
        shape: DenseSwitchShape::Unsigned32,
    },
    DenseSwitchCase {
        name: "sw_tab_offset",
        lowest_label: 100,
        highest_label: 119,
        shape: DenseSwitchShape::Unsigned32,
    },
    DenseSwitchCase {
        name: "sw_tab_negative",
        lowest_label: -10,
        highest_label: 9,
        shape: DenseSwitchShape::Unsigned32,
    },
    DenseSwitchCase {
        name: "sw_tab_shared",
        lowest_label: 0,
        highest_label: 19,
        shape: DenseSwitchShape::Unsigned32,
    },
    DenseSwitchCase {
        name: "sw_tab_wide",
        lowest_label: 0,
        highest_label: 19,
        shape: DenseSwitchShape::Unsigned64,
    },
    DenseSwitchCase {
        name: "sw_tab_signed",
        lowest_label: 0,
        highest_label: 19,
        shape: DenseSwitchShape::Signed32Small,
    },
];

const DENSE_SWITCH_C: &str = r"
unsigned sw_tab_add(int x, unsigned a, unsigned b) {
    switch (x) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return a ^ b;
        case 4: return a | b;
        case 5: return a & b;
        case 6: return a << 1;
        case 7: return b >> 2;
        case 8: return a + 2u * b;
        case 9: return a - 3u * b;
        case 10: return (a ^ b) + 5u;
        case 11: return (a | b) - 7u;
        case 12: return (a & b) * 3u;
        case 13: return a * a;
        case 14: return b * b;
        case 15: return a + b + 11u;
        case 16: return a - b - 13u;
        case 17: return (a >> 1) + (b << 2);
        case 18: return (a << 3) ^ b;
        case 19: return a | (b + 17u);
        default: return 0xa5a5a5a5u;
    }
}

unsigned sw_tab_offset(int x, unsigned a, unsigned b) {
    switch (x) {
        case 100: return a + b;
        case 101: return a - b;
        case 102: return a * b;
        case 103: return a ^ b;
        case 104: return a | b;
        case 105: return a & b;
        case 106: return a << 2;
        case 107: return b >> 1;
        case 108: return a + 3u * b;
        case 109: return a - 5u * b;
        case 110: return (a ^ b) + 9u;
        case 111: return (a | b) - 3u;
        case 112: return (a & b) * 7u;
        case 113: return a * a + 1u;
        case 114: return b * b - 1u;
        case 115: return a + b + 21u;
        case 116: return a - b - 23u;
        case 117: return (a >> 2) + (b << 1);
        case 118: return (a << 1) ^ b;
        case 119: return a | (b + 31u);
        default: return 0x5a5a5a5au;
    }
}

unsigned sw_tab_negative(int x, unsigned a, unsigned b) {
    switch (x) {
        case -10: return a + b;
        case -9: return a - b;
        case -8: return a * b;
        case -7: return a ^ b;
        case -6: return a | b;
        case -5: return a & b;
        case -4: return a << 3;
        case -3: return b >> 3;
        case -2: return a + 4u * b;
        case -1: return a - 7u * b;
        case 0: return (a ^ b) + 13u;
        case 1: return (a | b) - 11u;
        case 2: return (a & b) * 5u;
        case 3: return a * a + 3u;
        case 4: return b * b - 3u;
        case 5: return a + b + 41u;
        case 6: return a - b - 43u;
        case 7: return (a >> 3) + (b << 3);
        case 8: return (a << 2) ^ b;
        case 9: return a | (b + 51u);
        default: return 0xdeadbeefu;
    }
}

unsigned sw_tab_shared(int x, unsigned a, unsigned b) {
    switch (x) {
        case 0:
        case 5:
        case 10: return a + b;
        case 1:
        case 6:
        case 11: return a - b;
        case 2:
        case 7: return a * b;
        case 3:
        case 8: return a ^ b;
        case 4:
        case 9: return a | b;
        case 12: return a & b;
        case 13: return a << 1;
        case 14: return b >> 1;
        case 15: return a + 2u * b;
        case 16: return a - 2u * b;
        case 17: return a * a;
        case 18: return b * b;
        case 19: return a + b + 7u;
        default: return 0x13571357u;
    }
}

unsigned long long sw_tab_wide(int x, unsigned long long a, unsigned long long b) {
    switch (x) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return a ^ b;
        case 4: return a | b;
        case 5: return a & b;
        case 6: return a << 1;
        case 7: return b >> 2;
        case 8: return (unsigned long long)((long long)a >> 3);
        case 9: return a - 3ull * b;
        case 10: return (a ^ b) + 5ull;
        case 11: return (a | b) - 7ull;
        case 12: return (a & b) * 3ull;
        case 13: return a * a;
        case 14: return b * b;
        case 15: return a + b + 11ull;
        case 16: return a - b - 13ull;
        case 17: return (a >> 1) + (b << 2);
        case 18: return (a << 3) ^ b;
        case 19: return a | (b + 17ull);
        default: return 0x0123456789abcdefull;
    }
}

int sw_tab_signed(int x, int a, int b) {
    switch (x) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return a ^ b;
        case 4: return a | b;
        case 5: return a & b;
        case 6: return a >> 1;
        case 7: return b >> 2;
        case 8: return -a;
        case 9: return -b;
        case 10: return a + b + 5;
        case 11: return a - b - 7;
        case 12: return (a ^ b) >> 3;
        case 13: return a * 3;
        case 14: return b * 5;
        case 15: return (a >> 4) + b;
        case 16: return a - (b >> 5);
        case 17: return (a | b) >> 2;
        case 18: return (a & b) - 9;
        case 19: return a + (b >> 6);
        default: return -424242;
    }
}
";

fn dense_switch_object(level: &str) -> Vec<u8> {
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let object: PathBuf =
        compile_translation_unit(directory.path(), "dense_switch", "c", DENSE_SWITCH_C, level);
    link_shared(directory.path(), &[object])
}

fn dense_switch_originals() -> String {
    let mut source: String = String::new();
    for case in DENSE_SWITCH_CASES {
        let _ = writeln!(source, "#define {} orig_{}", case.name, case.name);
    }
    source.push_str(DENSE_SWITCH_C);
    for case in DENSE_SWITCH_CASES {
        let _ = writeln!(source, "#undef {}", case.name);
    }
    source
}

fn dense_switch_block(level: &str, case: DenseSwitchCase, symbol: &str, seed: u64) -> String {
    let lowest: i64 = case.lowest_label.saturating_sub(DENSE_SWITCH_GUARD_MARGIN);
    let highest: i64 = case.highest_label.saturating_add(DENSE_SWITCH_GUARD_MARGIN);
    let name: &str = case.name;
    let draws: u32 = DENSE_SWITCH_DRAWS_PER_DISCRIMINANT;
    let body: String = match case.shape {
        DenseSwitchShape::Unsigned32 => format!(
            "            unsigned a = (unsigned)xs(&s);\n\
             \x20           unsigned b = (unsigned)xs(&s);\n\
             \x20           uint64_t want = (uint64_t)orig_{name}((int)x, a, b);\n\
             \x20           uint64_t got = {symbol}((uint64_t)(uint32_t)(int)x, (uint64_t)a, (uint64_t)b);\n"
        ),
        DenseSwitchShape::Unsigned64 => format!(
            "            unsigned long long a = (unsigned long long)xs(&s);\n\
             \x20           unsigned long long b = (unsigned long long)xs(&s);\n\
             \x20           uint64_t want = (uint64_t)orig_{name}((int)x, a, b);\n\
             \x20           uint64_t got = {symbol}((uint64_t)(uint32_t)(int)x, (uint64_t)a, (uint64_t)b);\n"
        ),
        DenseSwitchShape::Signed32Small => format!(
            "            int a = (int)(xs(&s) % 2001ULL) - 1000;\n\
             \x20           int b = (int)(xs(&s) % 2001ULL) - 1000;\n\
             \x20           uint64_t want = (uint64_t)(uint32_t)orig_{name}((int)x, a, b);\n\
             \x20           uint64_t got = {symbol}((uint64_t)(uint32_t)(int)x, (uint64_t)(uint32_t)a, (uint64_t)(uint32_t)b);\n"
        ),
    };
    format!(
        "    {{\n\
         \x20       uint64_t s = {seed}ULL;\n\
         \x20       for (long long x = {lowest}; x <= {highest}; ++x) {{\n\
         \x20           for (unsigned k = 0; k < {draws}U; ++k) {{\n\
         {body}\
         \x20               if (want == got) {{ passed++; }} else {{ fails++; printf(\"FAIL {level} {name} x=%lld want=%llu got=%llu\\n\", x, (unsigned long long)want, (unsigned long long)got); }}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DenseSwitchTally {
    passed: u64,
    fails: u64,
    graded_functions: usize,
}

fn dense_switch_grade(mutated: Option<&str>) -> DenseSwitchTally {
    let mut decls: String = String::new();
    let mut blocks: String = String::new();
    let mut graded: Vec<(String, String)> = Vec::new();
    for (level_index, level) in DENSE_SWITCH_LEVELS.iter().enumerate() {
        let image: Vec<u8> = dense_switch_object(level);
        let program: RecoveredProgram = recover_aarch64_program(&image);
        for (case_index, case) in DENSE_SWITCH_CASES.iter().enumerate() {
            let function: &RecoveredFunction = recovered(&program, case.name);
            assert!(
                function.source.contains("switch ("),
                "{level} {} recovered without a switch, so the jump-table path was not what got graded:\n{}",
                case.name,
                function.source
            );
            assert_eq!(
                function.source.matches("case ").count(),
                DENSE_SWITCH_LABELS_PER_TABLE,
                "{level} {} must recover every dense case label:\n{}",
                case.name,
                function.source
            );
            assert!(
                function.source.contains("default:"),
                "{level} {} must recover the out-of-range default:\n{}",
                case.name,
                function.source
            );
            assert!(
                !function.source.contains("goto "),
                "{level} {} must structure the dispatch without a goto:\n{}",
                case.name,
                function.source
            );
            let symbol: String = format!("rec_{level}_{}", case.name);
            let mut body: String = recovered_body(&function.source, case.name, &symbol);
            if mutated == Some(case.name) {
                let replaced: String = body.replacen(
                    DENSE_SWITCH_MUTATED_LABEL,
                    DENSE_SWITCH_MUTATED_REPLACEMENT,
                    1,
                );
                assert_ne!(
                    replaced, body,
                    "the mutation control must find `{DENSE_SWITCH_MUTATED_LABEL}` in the recovered {} body",
                    case.name
                );
                body = replaced;
            }
            decls.push_str(&body);
            decls.push('\n');
            let seed: u64 = 0x9E37_79B9_7F4A_7C15u64
                ^ ((level_index as u64) << 32)
                ^ ((case_index as u64).wrapping_add(1)).wrapping_mul(0x0000_0100_0000_01B3);
            blocks.push_str(&dense_switch_block(level, *case, &symbol, seed));
            graded.push(((*level).to_owned(), case.name.to_owned()));
        }
    }
    let originals: String = dense_switch_originals();
    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         {originals}\n\
         static long long passed = 0;\n\
         static long long fails = 0;\n\
         {decls}\n\
         int main(void) {{\n\
         {blocks}\
         \x20   printf(\"SWITCHDONE passed=%lld fails=%lld\\n\", passed, fails);\n\
         \x20   return 0;\n\
         }}\n"
    );
    let directory: TempDir = tempfile::tempdir().expect("temporary directory must be available");
    let source_path: PathBuf = directory.path().join("dense_switch_grade.c");
    let executable_path: PathBuf =
        directory
            .path()
            .join(if cfg!(windows) { "grade.exe" } else { "grade" });
    fs::write(&source_path, driver.as_bytes()).expect("dense switch driver must be writable");
    let compiler: String = super::cc().expect("host C compiler must be available");
    let mut compile: Command = Command::new(compiler);
    compile
        .arg("-O1")
        .arg("-fno-strict-aliasing")
        .arg(&source_path)
        .arg("-o")
        .arg(&executable_path);
    let _: Output = command_output(&mut compile);
    let mut execute: Command = Command::new(&executable_path);
    let output: Output = command_output(&mut execute);
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut tally: Option<(u64, u64)> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("SWITCHDONE ") {
            let mut passed: u64 = 0;
            let mut fails: u64 = 0;
            for token in rest.split_whitespace() {
                if let Some(value) = token.strip_prefix("passed=") {
                    passed = value.parse().unwrap_or(0);
                } else if let Some(value) = token.strip_prefix("fails=") {
                    fails = value.parse().unwrap_or(0);
                }
            }
            tally = Some((passed, fails));
        } else if line.starts_with("FAIL ") {
            eprintln!("{line}");
        }
    }
    let Some((passed, fails)): Option<(u64, u64)> = tally else {
        panic!("dense switch driver produced no summary:\n{stdout}");
    };
    DenseSwitchTally {
        passed,
        fails,
        graded_functions: graded.len(),
    }
}

#[test]
#[ignore = "requires clang, ld.lld, and a host C compiler"]
fn dense_jump_table_switches_recompile_equivalently() {
    let tally: DenseSwitchTally = dense_switch_grade(None);
    let expected_functions: usize = DENSE_SWITCH_LEVELS.len() * DENSE_SWITCH_CASES.len();
    assert_eq!(
        tally.graded_functions, expected_functions,
        "every optimization level must contribute every dense-switch function"
    );
    let expected_comparisons: u64 = DENSE_SWITCH_LEVELS.len() as u64
        * DENSE_SWITCH_CASES
            .iter()
            .map(|case: &DenseSwitchCase| {
                let span: i64 = case
                    .highest_label
                    .saturating_add(DENSE_SWITCH_GUARD_MARGIN)
                    .saturating_sub(case.lowest_label.saturating_sub(DENSE_SWITCH_GUARD_MARGIN))
                    .saturating_add(1);
                u64::try_from(span).unwrap_or(0) * u64::from(DENSE_SWITCH_DRAWS_PER_DISCRIMINANT)
            })
            .sum::<u64>();
    eprintln!(
        "=== AARCH64 DENSE SWITCH GRADE: {} functions, {} comparisons, {} equivalent, {} divergent ===",
        tally.graded_functions, expected_comparisons, tally.passed, tally.fails
    );
    assert_eq!(
        tally.passed.saturating_add(tally.fails),
        expected_comparisons,
        "every scheduled comparison must be accounted for"
    );
    assert_eq!(
        tally.fails, 0,
        "every recovered dense switch must behave as the original on every case and both guard edges"
    );
}

#[test]
#[ignore = "requires clang, ld.lld, and a host C compiler"]
fn dense_jump_table_grade_rejects_a_mislabelled_case() {
    let tally: DenseSwitchTally = dense_switch_grade(Some(DENSE_SWITCH_MUTATED_FUNCTION));
    eprintln!(
        "=== AARCH64 DENSE SWITCH MUTATION CONTROL: {} equivalent, {} divergent ===",
        tally.passed, tally.fails
    );
    assert!(
        tally.fails
            >= u64::from(DENSE_SWITCH_DRAWS_PER_DISCRIMINANT)
                * u64::try_from(DENSE_SWITCH_LEVELS.len()).unwrap_or(1),
        "moving one case label off its discriminant must diverge at that discriminant on every level, saw {} divergences",
        tally.fails
    );
}

#[test]
#[ignore = "requires clang and ld.lld"]
fn dense_jump_table_switch_population_at_o0_is_reported() {
    let image: Vec<u8> = dense_switch_object(DENSE_SWITCH_UNOPTIMIZED_LEVEL);
    let program: RecoveredProgram = recover_aarch64_program(&image);
    let mut recovered_names: Vec<&str> = Vec::new();
    let mut refused: Vec<(String, String)> = Vec::new();
    for case in DENSE_SWITCH_CASES {
        let found: Option<&RecoveredFunction> = program
            .recovered
            .iter()
            .find(|function: &&RecoveredFunction| function.name == case.name);
        if let Some(function) = found {
            recovered_names.push(case.name);
            assert!(
                function.source.contains("switch ("),
                "{} recovered at O0 without a switch:\n{}",
                case.name,
                function.source
            );
        } else {
            let reason: String = program
                .unrecovered
                .iter()
                .find(|function| function.name == case.name)
                .map_or_else(
                    || "absent from the symbol table".to_owned(),
                    |function| function.reason.clone(),
                );
            refused.push((case.name.to_owned(), reason));
        }
    }
    eprintln!(
        "=== AARCH64 DENSE SWITCH AT O0: {} recovered, {} refused ===",
        recovered_names.len(),
        refused.len()
    );
    for (name, reason) in &refused {
        eprintln!("  REFUSED {name}: {reason}");
    }
    assert_eq!(
        recovered_names.len() + refused.len(),
        DENSE_SWITCH_CASES.len(),
        "every O0 dense-switch function must be either recovered or refused by name"
    );
}
