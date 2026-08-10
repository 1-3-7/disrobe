#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::disallowed_methods,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;
#[cfg(windows)]
use std::sync::OnceLock;

use disrobe_core::anti_analysis::{
    AntiAnalysisReport, Confidence, FindingSeverity, Technique, scan,
};
use disrobe_core::scratch::ScratchDir;
use goblin::pe::PE;
#[cfg(windows)]
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-aa-corpus").expect("create scratch dir")
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn first_c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|c: &&'static str| tool_available(c))
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

fn compile_c(cc: &str, dir: &std::path::Path, stem: &str, src: &str, opt: &str) -> Option<Vec<u8>> {
    let src_path: PathBuf = dir.join(format!("{stem}.c"));
    std::fs::write(&src_path, src).expect("write c source");
    let out_path: PathBuf = dir.join(exe_name(stem));
    let status: std::process::ExitStatus = Command::new(cc)
        .arg(opt)
        .arg(&src_path)
        .arg("-o")
        .arg(&out_path)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    std::fs::read(&out_path).ok()
}

const TINY_C: &str = "int main(void){return 0;}\n";
const MEDIUM_C: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2); }
int main(int argc,char**argv){
    int total=0; char buf[64];
    for(int i=0;i<argc+10;i++){
        total+=fib(i%12);
        snprintf(buf,sizeof buf,"iter %d total %d",i,total);
        if(strlen(buf)>3) total^=(int)buf[0];
    }
    char*p=(char*)malloc(128);
    if(p){ memset(p,total&0xff,128); total+=p[7]; free(p); }
    printf("result %d\n",total);
    return total&0x7f;
}
"#;

fn assert_zero_anti_analysis_verdicts(label: &str, bytes: &[u8]) {
    let report: AntiAnalysisReport = scan(bytes, Some(label));
    let verdicts: Vec<&Technique> = report
        .findings
        .iter()
        .filter(|f| f.detected)
        .map(|f| &f.technique)
        .collect();
    assert!(
        verdicts.is_empty(),
        "benign artifact {label} must yield ZERO anti-analysis verdicts; got {verdicts:?} \
         (full findings: {:?})",
        report.findings
    );
}

#[cfg(windows)]
fn subsequence_offsets(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate): (usize, &[u8])| (candidate == needle).then_some(offset))
        .collect()
}

#[cfg(windows)]
fn unique_field<'a>(output: &'a str, prefix: &str) -> &'a str {
    let values: Vec<&str> = output
        .lines()
        .filter_map(|line: &str| line.strip_prefix(prefix))
        .collect();
    assert_eq!(values.len(), 1, "rustc -Vv must contain one {prefix} field");
    values[0]
}

#[cfg(windows)]
fn pinned_rustc() -> &'static std::path::Path {
    static RUSTC: OnceLock<PathBuf> = OnceLock::new();
    RUSTC.get_or_init(|| {
        let rustc: PathBuf =
            std::env::var_os("RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
        let version: std::process::Output = Command::new(&rustc)
            .arg("-Vv")
            .output()
            .expect("run active rustc -Vv");
        assert!(version.status.success(), "active rustc -Vv must succeed");
        let version_text: String =
            String::from_utf8(version.stdout).expect("rustc -Vv must be UTF-8");
        assert_eq!(unique_field(&version_text, "release: "), "1.96.1");
        assert_eq!(
            unique_field(&version_text, "commit-hash: "),
            "31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd"
        );
        assert_eq!(
            unique_field(&version_text, "host: "),
            "x86_64-pc-windows-msvc"
        );
        rustc
    })
}

#[cfg(windows)]
#[test]
fn pinned_windows_cargo_contains_regression_surface_and_is_clean() {
    let rustc: &'static std::path::Path = pinned_rustc();
    let sysroot: std::process::Output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("run active rustc --print sysroot");
    assert!(
        sysroot.status.success(),
        "active rustc --print sysroot must succeed"
    );
    let sysroot_text: String =
        String::from_utf8(sysroot.stdout).expect("rustc sysroot must be UTF-8");
    let cargo_path: PathBuf = PathBuf::from(sysroot_text.trim())
        .join("bin")
        .join("cargo.exe");
    let bytes: Vec<u8> = std::fs::read(&cargo_path).expect("read pinned toolchain cargo.exe");
    assert_eq!(bytes.len(), 31_350_272);
    let digest: String = format!("{:X}", Sha256::digest(&bytes));
    assert_eq!(
        digest,
        "AAA2A484C6D5C1DC145E8FB965A8803B2489CD3C8D9157EF7CF0608FCFF134C6"
    );

    for (needle, expected) in [
        (b"wine_get_version\0".as_slice(), 1usize),
        (b"ntdll.dll\0".as_slice(), 2usize),
        (b"GetProcAddress\0".as_slice(), 1usize),
        (b"QueryPerformanceCounter\0".as_slice(), 2usize),
        (b"GetTickCount\0".as_slice(), 2usize),
        (b"GetTickCount64\0".as_slice(), 2usize),
        (b"dbghelp.dll\0".as_slice(), 1usize),
    ] {
        assert_eq!(subsequence_offsets(&bytes, needle).len(), expected);
    }
    assert_eq!(subsequence_offsets(&bytes, b"GetProcAddress").len(), 2);

    let timing_windows: std::collections::BTreeSet<usize> = [
        b"QueryPerformanceCounter\0".as_slice(),
        b"GetTickCount\0".as_slice(),
        b"GetTickCount64\0".as_slice(),
    ]
    .into_iter()
    .flat_map(|needle: &[u8]| subsequence_offsets(&bytes, needle))
    .map(|offset: usize| offset / 4096)
    .collect();
    assert!(timing_windows.len() >= 2);
    assert_zero_anti_analysis_verdicts("pinned-windows-cargo", &bytes);
}

#[cfg(windows)]
const WINE_EXPORT_SOURCE: &str = r#"
type HModule = *mut core::ffi::c_void;
type FarProc = Option<unsafe extern "system" fn() -> isize>;
type WineGetVersion = unsafe extern "system" fn() -> *const u8;
static NTDLL_W: [u16; 10] = [0x006e, 0x0074, 0x0064, 0x006c, 0x006c, 0x002e, 0x0064, 0x006c, 0x006c, 0x0000];
static WINE_GET_VERSION: [u8; 17] = *b"wine_get_version\0";
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> HModule;
    fn GetProcAddress(module: HModule, proc_name: *const u8) -> FarProc;
}
#[unsafe(no_mangle)]
pub static mut DISROBE_WINE_EXPORT_RESULT: usize = 0;
#[unsafe(no_mangle)]
pub unsafe extern "system" fn disrobe_probe_wine_export() {
    let module: HModule = unsafe { GetModuleHandleW(NTDLL_W.as_ptr()) };
    let value: usize = if module as usize == 0 {
        0
    } else {
        match unsafe { GetProcAddress(module, WINE_GET_VERSION.as_ptr()) } {
            Some(proc) => {
                let probe: WineGetVersion = unsafe { core::mem::transmute(proc) };
                unsafe { probe() as usize }
            }
            None => 0,
        }
    };
    unsafe { core::ptr::addr_of_mut!(DISROBE_WINE_EXPORT_RESULT).write_volatile(value) };
}
"#;

#[cfg(windows)]
const WINE_REGISTRY_SOURCE: &str = r#"
type HKey = *mut core::ffi::c_void;
static SOFTWARE_WINE_W: [u16; 14] = [0x0053, 0x006f, 0x0066, 0x0074, 0x0077, 0x0061, 0x0072, 0x0065, 0x005c, 0x0057, 0x0069, 0x006e, 0x0065, 0x0000];
const HKEY_CURRENT_USER_BITS: usize = 0xffff_ffff_8000_0001;
const KEY_READ: u32 = 0x0002_0019;
const ERROR_SUCCESS: u32 = 0;
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(root: HKey, subkey: *const u16, options: u32, access: u32, out_handle: *mut HKey) -> u32;
    fn RegCloseKey(handle: HKey) -> u32;
}
#[unsafe(no_mangle)]
pub static mut DISROBE_WINE_REGISTRY_STATUS: u32 = u32::MAX;
#[unsafe(no_mangle)]
pub unsafe extern "system" fn disrobe_probe_wine_registry() {
    let mut handle: HKey = core::ptr::null_mut();
    let status: u32 = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER_BITS as HKey,
            SOFTWARE_WINE_W.as_ptr(),
            0,
            KEY_READ,
            core::ptr::addr_of_mut!(handle),
        )
    };
    if status == ERROR_SUCCESS && handle as usize != 0 {
        let _: u32 = unsafe { RegCloseKey(handle) };
    }
    unsafe { core::ptr::addr_of_mut!(DISROBE_WINE_REGISTRY_STATUS).write_volatile(status) };
}
"#;

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WineFixtureKind {
    Export,
    Registry,
    Dual,
}

#[cfg(windows)]
fn wine_fixture_source(kind: WineFixtureKind) -> String {
    match kind {
        WineFixtureKind::Export => WINE_EXPORT_SOURCE.to_string(),
        WineFixtureKind::Registry => WINE_REGISTRY_SOURCE.to_string(),
        WineFixtureKind::Dual => format!("{WINE_EXPORT_SOURCE}\n{WINE_REGISTRY_SOURCE}"),
    }
}

#[cfg(windows)]
fn compile_wine_fixture(dir: &std::path::Path, kind: WineFixtureKind, opt_level: &str) -> Vec<u8> {
    let kind_name: &str = match kind {
        WineFixtureKind::Export => "export",
        WineFixtureKind::Registry => "registry",
        WineFixtureKind::Dual => "dual",
    };
    let source_path: PathBuf = dir.join(format!("wine_{kind_name}_{opt_level}.rs"));
    let output_path: PathBuf = dir.join(format!("wine_{kind_name}_{opt_level}.dll"));
    std::fs::write(&source_path, wine_fixture_source(kind)).expect("write Wine probe source");
    let output: std::process::Output = Command::new(pinned_rustc())
        .args([
            "--target",
            "x86_64-pc-windows-msvc",
            "--crate-type",
            "cdylib",
            "--edition",
            "2024",
            &format!("-Copt-level={opt_level}"),
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("launch pinned rustc for Wine fixture");
    assert!(
        output.status.success(),
        "Wine fixture compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(output_path).expect("read Wine fixture")
}

#[cfg(windows)]
fn unique_export_rva(pe: &PE<'_>, name: &str) -> usize {
    let matches: Vec<usize> = pe
        .exports
        .iter()
        .filter(|export: &&goblin::pe::export::Export<'_>| export.name == Some(name))
        .map(|export: &goblin::pe::export::Export<'_>| export.rva)
        .collect();
    assert_eq!(matches.len(), 1, "one export named {name}");
    matches[0]
}

#[cfg(windows)]
fn mapped_file_range(pe: &PE<'_>, rva: usize, size: usize) -> std::ops::Range<usize> {
    let end_rva: usize = rva.checked_add(size).expect("mapped RVA range overflow");
    let matches: Vec<std::ops::Range<usize>> = pe
        .sections
        .iter()
        .filter_map(|section: &goblin::pe::section_table::SectionTable| {
            let section_rva: usize = usize::try_from(section.virtual_address).ok()?;
            let raw_size: usize = usize::try_from(section.size_of_raw_data).ok()?;
            let section_end: usize = section_rva.checked_add(raw_size)?;
            if rva < section_rva || end_rva > section_end {
                return None;
            }
            let delta: usize = rva.checked_sub(section_rva)?;
            let raw_start: usize = usize::try_from(section.pointer_to_raw_data)
                .ok()?
                .checked_add(delta)?;
            let raw_end: usize = raw_start.checked_add(size)?;
            Some(raw_start..raw_end)
        })
        .collect();
    assert_eq!(matches.len(), 1, "RVA {rva:#x} must map once");
    matches[0].clone()
}

#[cfg(windows)]
fn require_result_slot(pe: &PE<'_>, bytes: &[u8], name: &str, size: usize) -> usize {
    let rva: usize = unique_export_rva(pe, name);
    let range: std::ops::Range<usize> = mapped_file_range(pe, rva, size);
    assert!(range.end <= bytes.len(), "result slot must be file-backed");
    let containing: Vec<&goblin::pe::section_table::SectionTable> = pe
        .sections
        .iter()
        .filter(|section: &&goblin::pe::section_table::SectionTable| {
            let start: usize = section.virtual_address as usize;
            let end: usize = start.saturating_add(section.size_of_raw_data as usize);
            start <= rva && rva.saturating_add(size) <= end
        })
        .collect();
    assert_eq!(containing.len(), 1);
    let characteristics: u32 = containing[0].characteristics;
    assert_ne!(
        characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE,
        0
    );
    assert_eq!(
        characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE,
        0
    );
    rva
}

#[cfg(windows)]
fn decoded_probe(pe: &PE<'_>, bytes: &[u8], export_name: &str) -> Vec<Instruction> {
    let rva: usize = unique_export_rva(pe, export_name);
    let exception: &goblin::pe::exception::ExceptionData<'_> =
        pe.exception_data.as_ref().expect("PE exception directory");
    let functions: Vec<goblin::pe::exception::RuntimeFunction> = exception
        .functions()
        .map(|function| function.expect("runtime function entry"))
        .filter(|function: &goblin::pe::exception::RuntimeFunction| {
            function.begin_address as usize <= rva && rva < function.end_address as usize
        })
        .collect();
    assert_eq!(
        functions.len(),
        1,
        "probe must belong to one runtime function"
    );
    let function: goblin::pe::exception::RuntimeFunction = functions[0];
    assert_eq!(
        function.begin_address as usize, rva,
        "probe export must equal runtime function entry"
    );
    let size: usize = (function.end_address - function.begin_address) as usize;
    assert!(size <= 65_536);
    let range: std::ops::Range<usize> =
        mapped_file_range(pe, function.begin_address as usize, size);
    assert!(range.end <= bytes.len());
    let mut decoder: Decoder<'_> = Decoder::with_ip(
        64,
        &bytes[range],
        pe.image_base + u64::from(function.begin_address),
        DecoderOptions::NONE,
    );
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        assert!(instructions.len() < 4096, "instruction budget exceeded");
        let instruction: Instruction = decoder.decode();
        assert!(!instruction.is_invalid(), "invalid probe instruction");
        instructions.push(instruction);
    }
    instructions
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportCallForm {
    DirectIat,
    PureThunk,
    LoadedIatRegister,
}

#[cfg(windows)]
fn writes_register(instruction: &Instruction, register: Register) -> bool {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    factory
        .info(instruction)
        .used_registers()
        .iter()
        .any(|used: &iced_x86::UsedRegister| {
            used.register().full_register() == register.full_register()
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        })
}

#[cfg(windows)]
fn decode_at_va(
    pe: &PE<'_>,
    bytes: &[u8],
    va: u64,
    cap: usize,
) -> Result<Vec<Instruction>, String> {
    let rva_u64: u64 = va
        .checked_sub(pe.image_base)
        .ok_or_else(|| "address below image base".to_string())?;
    let rva: usize = usize::try_from(rva_u64).map_err(|_| "RVA conversion overflow".to_string())?;
    let section: &goblin::pe::section_table::SectionTable = pe
        .sections
        .iter()
        .find(|section: &&goblin::pe::section_table::SectionTable| {
            let start: usize = section.virtual_address as usize;
            let end: usize = start.saturating_add(section.size_of_raw_data as usize);
            start <= rva && rva < end
        })
        .ok_or_else(|| "address is not file-backed".to_string())?;
    let delta: usize = rva
        .checked_sub(section.virtual_address as usize)
        .ok_or_else(|| "section delta underflow".to_string())?;
    let available: usize = (section.size_of_raw_data as usize)
        .checked_sub(delta)
        .ok_or_else(|| "section range underflow".to_string())?
        .min(cap);
    let start: usize = (section.pointer_to_raw_data as usize)
        .checked_add(delta)
        .ok_or_else(|| "file offset overflow".to_string())?;
    let end: usize = start
        .checked_add(available)
        .ok_or_else(|| "file range overflow".to_string())?;
    let slice: &[u8] = bytes
        .get(start..end)
        .ok_or_else(|| "file range is truncated".to_string())?;
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, slice, va, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && instructions.len() < 4 {
        let instruction: Instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err("invalid thunk instruction".to_string());
        }
        instructions.push(instruction);
        if !matches!(instruction.flow_control(), FlowControl::Next) {
            break;
        }
    }
    Ok(instructions)
}

#[cfg(windows)]
fn pure_thunk_targets_iat(
    pe: &PE<'_>,
    bytes: &[u8],
    target: u64,
    named_iat_va: u64,
) -> Result<(), String> {
    let instructions: Vec<Instruction> = decode_at_va(pe, bytes, target, 32)?;
    if instructions.is_empty() || instructions.len() > 4 {
        return Err("pure thunk instruction count".to_string());
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let terminal: bool = index + 1 == instructions.len();
        if terminal {
            if instruction.flow_control() != FlowControl::IndirectBranch
                || instruction.op0_kind() != OpKind::Memory
                || !instruction.is_ip_rel_memory_operand()
                || instruction.ip_rel_memory_address() != named_iat_va
            {
                return Err("pure thunk terminal target".to_string());
            }
        } else if !matches!(instruction.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Nop) {
            return Err("impure thunk instruction".to_string());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn resolve_import_call_form(
    pe: &PE<'_>,
    bytes: &[u8],
    instructions: &[Instruction],
    call_index: usize,
    named_iat_va: u64,
    all_iat_vas: &std::collections::BTreeSet<u64>,
) -> Result<ImportCallForm, String> {
    let call: &Instruction = instructions
        .get(call_index)
        .ok_or_else(|| "call index outside probe".to_string())?;
    match call.flow_control() {
        FlowControl::IndirectCall
            if call.op0_kind() == OpKind::Memory && call.is_ip_rel_memory_operand() =>
        {
            if call.ip_rel_memory_address() == named_iat_va {
                Ok(ImportCallForm::DirectIat)
            } else {
                Err("direct call references the wrong IAT slot".to_string())
            }
        }
        FlowControl::Call => {
            pure_thunk_targets_iat(pe, bytes, call.near_branch_target(), named_iat_va)?;
            Ok(ImportCallForm::PureThunk)
        }
        FlowControl::IndirectCall if call.op0_kind() == OpKind::Register => {
            let target: Register = call.op0_register().full_register();
            for index in (0..call_index).rev() {
                let instruction: &Instruction = &instructions[index];
                if instruction.flow_control() != FlowControl::Next {
                    return Err("control split before loaded-register call".to_string());
                }
                if !writes_register(instruction, target) {
                    continue;
                }
                if instruction.mnemonic() != Mnemonic::Mov
                    || instruction.op0_kind() != OpKind::Register
                    || instruction.op0_register().full_register() != target
                    || instruction.op1_kind() != OpKind::Memory
                    || !instruction.is_ip_rel_memory_operand()
                {
                    return Err("loaded IAT register was overwritten".to_string());
                }
                let loaded_va: u64 = instruction.ip_rel_memory_address();
                if loaded_va != named_iat_va {
                    return Err("loaded-register call uses the wrong IAT slot".to_string());
                }
                let referenced_iats: usize = instructions[index..=call_index]
                    .iter()
                    .filter(|candidate: &&Instruction| {
                        candidate.is_ip_rel_memory_operand()
                            && all_iat_vas.contains(&candidate.ip_rel_memory_address())
                    })
                    .count();
                if referenced_iats != 1 {
                    return Err("loaded-register call has an alternate IAT target".to_string());
                }
                return Ok(ImportCallForm::LoadedIatRegister);
            }
            Err("loaded-register call has no IAT definition".to_string())
        }
        _ => Err("unsupported import call form".to_string()),
    }
}

#[cfg(windows)]
fn require_one_import_call(
    pe: &PE<'_>,
    bytes: &[u8],
    instructions: &[Instruction],
    name: &str,
    dll: &str,
) -> (usize, ImportCallForm) {
    let named_imports: Vec<&goblin::pe::import::Import<'_>> = pe
        .imports
        .iter()
        .filter(|import: &&goblin::pe::import::Import<'_>| import.name.as_ref() == name)
        .collect();
    assert_eq!(named_imports.len(), 1, "one import named {name}");
    assert!(
        named_imports[0].dll.eq_ignore_ascii_case(dll),
        "{name} must belong to {dll}"
    );
    let named_iat_va: u64 = pe.image_base + named_imports[0].offset as u64;
    let all_iat_vas: std::collections::BTreeSet<u64> = pe
        .imports
        .iter()
        .map(|import: &goblin::pe::import::Import<'_>| pe.image_base + import.offset as u64)
        .collect();
    let resolved: Vec<(usize, ImportCallForm)> = instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction): &(usize, &Instruction)| {
            matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            )
        })
        .filter_map(|(index, _): (usize, &Instruction)| {
            resolve_import_call_form(pe, bytes, instructions, index, named_iat_va, &all_iat_vas)
                .ok()
                .map(|form: ImportCallForm| (index, form))
        })
        .collect();
    assert_eq!(resolved.len(), 1, "one resolved call to {name}");
    resolved[0]
}

#[cfg(windows)]
fn decode_sequence(bytes: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let instruction: Instruction = decoder.decode();
        assert!(!instruction.is_invalid());
        instructions.push(instruction);
    }
    instructions
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackLocation {
    base: Register,
    displacement: i64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceOrigin {
    Constant(u64),
    Address(u64),
    StackAddress(StackLocation),
    ModuleReturn,
    ProcReturn,
    DynamicReturn,
    RegistryStatus,
    RegistryHandle,
}

#[cfg(windows)]
fn memory_location(instruction: &Instruction) -> Option<StackLocation> {
    let base: Register = instruction.memory_base().full_register();
    if !matches!(base, Register::RSP | Register::RBP)
        || instruction.memory_index() != Register::None
    {
        return None;
    }
    Some(StackLocation {
        base,
        displacement: instruction.memory_displacement64() as i64,
    })
}

#[cfg(windows)]
fn immediate_value(instruction: &Instruction, operand: u32) -> Option<u64> {
    match instruction.op_kind(operand) {
        OpKind::Immediate8 => Some(u64::from(instruction.immediate8())),
        OpKind::Immediate8to16 => Some(instruction.immediate8to16() as u64),
        OpKind::Immediate8to32 => Some(instruction.immediate8to32() as u64),
        OpKind::Immediate8to64 => Some(instruction.immediate8to64() as u64),
        OpKind::Immediate16 => Some(u64::from(instruction.immediate16())),
        OpKind::Immediate32 => Some(u64::from(instruction.immediate32())),
        OpKind::Immediate32to64 => Some(instruction.immediate32to64() as u64),
        OpKind::Immediate64 => Some(instruction.immediate64()),
        _ => None,
    }
}

#[cfg(windows)]
struct TraceContext {
    api_returns: std::collections::BTreeMap<usize, TraceOrigin>,
    registry_out: Option<(usize, StackLocation)>,
    reachable: std::collections::BTreeSet<usize>,
    steps: usize,
}

#[cfg(windows)]
impl TraceContext {
    fn step(&mut self) -> Result<(), String> {
        self.steps = self
            .steps
            .checked_add(1)
            .ok_or_else(|| "transfer counter overflow".to_string())?;
        if self.steps > 65_536 {
            return Err("transfer budget exceeded".to_string());
        }
        Ok(())
    }

    fn register_before(
        &mut self,
        instructions: &[Instruction],
        before: usize,
        register: Register,
    ) -> Result<TraceOrigin, String> {
        let normalized: Register = register.full_register();
        for index in (0..before).rev() {
            self.step()?;
            let instruction: &Instruction = &instructions[index];
            let defines_register: bool = (normalized == Register::RAX
                && matches!(
                    instruction.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ))
                || writes_register(instruction, normalized);
            if !self.reachable.contains(&index) {
                if defines_register {
                    return Err("nearest register definition is unreachable".to_string());
                }
                continue;
            }
            if defines_register && !definition_dominates_use(instructions, index, before)? {
                return Err("register definition does not dominate use".to_string());
            }
            if normalized == Register::RAX
                && matches!(
                    instruction.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                )
            {
                if let Some(origin) = self.api_returns.get(&index).copied() {
                    return Ok(origin);
                }
                if self.call_target(instructions, index)? == TraceOrigin::ProcReturn {
                    return Ok(TraceOrigin::DynamicReturn);
                }
                return Err("unknown call return".to_string());
            }
            if !writes_register(instruction, normalized) {
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == normalized
            {
                if instruction.op1_kind() == OpKind::Register {
                    return self.register_before(instructions, index, instruction.op1_register());
                }
                if instruction.op1_kind() == OpKind::Memory {
                    let location: StackLocation = memory_location(instruction)
                        .ok_or_else(|| "unknown memory alias".to_string())?;
                    return self.stack_before(instructions, index, location);
                }
                if let Some(value) = immediate_value(instruction, 1) {
                    return Ok(TraceOrigin::Constant(value));
                }
            }
            if instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == normalized
            {
                if instruction.is_ip_rel_memory_operand() {
                    return Ok(TraceOrigin::Address(instruction.ip_rel_memory_address()));
                }
                let location: StackLocation = memory_location(instruction)
                    .ok_or_else(|| "unknown LEA memory alias".to_string())?;
                return Ok(TraceOrigin::StackAddress(location));
            }
            if instruction.mnemonic() == Mnemonic::Xor
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register().full_register() == normalized
                && instruction.op1_register().full_register() == normalized
            {
                return Ok(TraceOrigin::Constant(0));
            }
            return Err("unsupported register definition".to_string());
        }
        Err("register has no local definition".to_string())
    }

    fn stack_before(
        &mut self,
        instructions: &[Instruction],
        before: usize,
        location: StackLocation,
    ) -> Result<TraceOrigin, String> {
        for index in (0..before).rev() {
            self.step()?;
            if !self.reachable.contains(&index) {
                continue;
            }
            if self.registry_out == Some((index, location)) {
                if !definition_dominates_use(instructions, index, before)? {
                    return Err("out-handle definition does not dominate use".to_string());
                }
                return Ok(TraceOrigin::RegistryHandle);
            }
            let instruction: &Instruction = &instructions[index];
            if instruction.mnemonic() != Mnemonic::Mov
                || instruction.op0_kind() != OpKind::Memory
                || memory_location(instruction) != Some(location)
            {
                continue;
            }
            if !definition_dominates_use(instructions, index, before)? {
                return Err("stack definition does not dominate use".to_string());
            }
            if instruction.op1_kind() == OpKind::Register {
                return self.register_before(instructions, index, instruction.op1_register());
            }
            if let Some(value) = immediate_value(instruction, 1) {
                return Ok(TraceOrigin::Constant(value));
            }
            return Err("unsupported stack definition".to_string());
        }
        Err("stack location has no local definition".to_string())
    }

    fn call_target(
        &mut self,
        instructions: &[Instruction],
        index: usize,
    ) -> Result<TraceOrigin, String> {
        let instruction: &Instruction = instructions
            .get(index)
            .ok_or_else(|| "call index outside probe".to_string())?;
        if !self.reachable.contains(&index) {
            return Err("dynamic call is unreachable".to_string());
        }
        if instruction.op0_kind() == OpKind::Register {
            return self.register_before(instructions, index, instruction.op0_register());
        }
        if instruction.op0_kind() == OpKind::Memory {
            let location: StackLocation = memory_location(instruction)
                .ok_or_else(|| "dynamic call has unknown memory alias".to_string())?;
            return self.stack_before(instructions, index, location);
        }
        Err("dynamic call target is not local".to_string())
    }
}

#[cfg(windows)]
fn possible_register_origins(
    instructions: &[Instruction],
    before: usize,
    register: Register,
    trace: &mut TraceContext,
) -> Result<Vec<TraceOrigin>, String> {
    let normalized: Register = register.full_register();
    let mut origins: Vec<TraceOrigin> = Vec::new();
    for index in 0..before {
        trace.step()?;
        if !trace.reachable.contains(&index) {
            continue;
        }
        let instruction: &Instruction = &instructions[index];
        let defines_register: bool = (normalized == Register::RAX
            && matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ))
            || writes_register(instruction, normalized);
        if !defines_register
            || !register_definition_reaches_use(instructions, index, before, normalized, trace)?
        {
            continue;
        }
        if normalized == Register::RAX
            && matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            )
        {
            if let Some(origin) = trace.api_returns.get(&index).copied() {
                origins.push(origin);
                continue;
            }
            if trace.call_target(instructions, index)? == TraceOrigin::ProcReturn {
                origins.push(TraceOrigin::DynamicReturn);
                continue;
            }
            return Err("unknown possible call return".to_string());
        }
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            if instruction.op1_kind() == OpKind::Memory {
                let location: StackLocation = memory_location(instruction)
                    .ok_or_else(|| "possible origin has unknown memory alias".to_string())?;
                origins.extend(possible_stack_origins(
                    instructions,
                    index,
                    location,
                    trace,
                )?);
                continue;
            }
            if instruction.op1_kind() == OpKind::Register {
                origins.extend(possible_register_origins(
                    instructions,
                    index,
                    instruction.op1_register(),
                    trace,
                )?);
                continue;
            }
            if let Some(value) = immediate_value(instruction, 1) {
                origins.push(TraceOrigin::Constant(value));
                continue;
            }
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == normalized
        {
            if instruction.is_ip_rel_memory_operand() {
                origins.push(TraceOrigin::Address(instruction.ip_rel_memory_address()));
                continue;
            }
            let location: StackLocation = memory_location(instruction)
                .ok_or_else(|| "possible LEA has unknown memory alias".to_string())?;
            origins.push(TraceOrigin::StackAddress(location));
            continue;
        }
        if instruction.mnemonic() == Mnemonic::Xor
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register().full_register() == normalized
            && instruction.op1_register().full_register() == normalized
        {
            origins.push(TraceOrigin::Constant(0));
            continue;
        }
        return Err("unsupported possible register definition".to_string());
    }
    if origins.is_empty() {
        return Err("register has no possible definitions".to_string());
    }
    origins.sort_by_key(|origin: &TraceOrigin| format!("{origin:?}"));
    origins.dedup();
    Ok(origins)
}

#[cfg(windows)]
fn possible_stack_origins(
    instructions: &[Instruction],
    before: usize,
    location: StackLocation,
    trace: &mut TraceContext,
) -> Result<Vec<TraceOrigin>, String> {
    let mut origins: Vec<TraceOrigin> = Vec::new();
    for index in 0..before {
        trace.step()?;
        if !trace.reachable.contains(&index) {
            continue;
        }
        if trace.registry_out == Some((index, location))
            && stack_definition_reaches_use(instructions, index, before, location, trace)?
        {
            origins.push(TraceOrigin::RegistryHandle);
        }
        let instruction: &Instruction = &instructions[index];
        if instruction.mnemonic() != Mnemonic::Mov
            || instruction.op0_kind() != OpKind::Memory
            || memory_location(instruction) != Some(location)
        {
            continue;
        }
        if !stack_definition_reaches_use(instructions, index, before, location, trace)? {
            continue;
        }
        if instruction.op1_kind() == OpKind::Register {
            origins.extend(possible_register_origins(
                instructions,
                index,
                instruction.op1_register(),
                trace,
            )?);
        } else if let Some(value) = immediate_value(instruction, 1) {
            origins.push(TraceOrigin::Constant(value));
        } else {
            return Err("unsupported possible stack definition".to_string());
        }
    }
    if origins.is_empty() {
        return Err("stack location has no possible definitions".to_string());
    }
    origins.sort_by_key(|origin: &TraceOrigin| format!("{origin:?}"));
    origins.dedup();
    Ok(origins)
}

#[cfg(windows)]
fn reachable_instruction_indices(
    instructions: &[Instruction],
) -> Result<std::collections::BTreeSet<usize>, String> {
    if instructions.is_empty() {
        return Err("probe has no instructions".to_string());
    }
    reachable_instruction_indices_from(instructions, 0, None)
}

#[cfg(windows)]
fn instruction_indices_by_ip(
    instructions: &[Instruction],
) -> Result<std::collections::BTreeMap<u64, usize>, String> {
    let mut by_ip: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if by_ip.insert(instruction.ip(), index).is_some() {
            return Err("probe has duplicate instruction addresses".to_string());
        }
    }
    Ok(by_ip)
}

#[cfg(windows)]
fn instruction_successors(
    instructions: &[Instruction],
    by_ip: &std::collections::BTreeMap<u64, usize>,
    index: usize,
) -> Result<Vec<usize>, String> {
    let instruction: &Instruction = instructions
        .get(index)
        .ok_or_else(|| "control-flow index outside probe".to_string())?;
    let fallthrough: Option<usize> = (index + 1 < instructions.len()).then_some(index + 1);
    match instruction.flow_control() {
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
            Ok(fallthrough.into_iter().collect())
        }
        FlowControl::ConditionalBranch => {
            let target: usize = *by_ip
                .get(&instruction.near_branch_target())
                .ok_or_else(|| "conditional branch leaves probe".to_string())?;
            Ok(fallthrough
                .into_iter()
                .chain(std::iter::once(target))
                .collect())
        }
        FlowControl::UnconditionalBranch => {
            let target: usize = *by_ip
                .get(&instruction.near_branch_target())
                .ok_or_else(|| "unconditional branch leaves probe".to_string())?;
            Ok(vec![target])
        }
        FlowControl::Return
        | FlowControl::IndirectBranch
        | FlowControl::Interrupt
        | FlowControl::Exception
        | FlowControl::XbeginXabortXend => Ok(Vec::new()),
    }
}

#[cfg(windows)]
fn reachable_instruction_indices_from(
    instructions: &[Instruction],
    start: usize,
    avoided: Option<usize>,
) -> Result<std::collections::BTreeSet<usize>, String> {
    let by_ip: std::collections::BTreeMap<u64, usize> = instruction_indices_by_ip(instructions)?;
    let mut pending: Vec<usize> = vec![start];
    let mut reachable: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut traversed_edges: usize = 0;
    while let Some(index) = pending.pop() {
        if avoided == Some(index) {
            continue;
        }
        if !reachable.insert(index) {
            continue;
        }
        if reachable.len() > 4096 {
            return Err("reachable instruction budget exceeded".to_string());
        }
        let successors: Vec<usize> = instruction_successors(instructions, &by_ip, index)?;
        traversed_edges = traversed_edges
            .checked_add(successors.len())
            .ok_or_else(|| "reachable edge counter overflow".to_string())?;
        if traversed_edges > 8192 {
            return Err("reachable edge budget exceeded".to_string());
        }
        pending.extend(successors);
    }
    Ok(reachable)
}

#[cfg(windows)]
fn definition_dominates_use(
    instructions: &[Instruction],
    definition: usize,
    use_index: usize,
) -> Result<bool, String> {
    let from_definition: std::collections::BTreeSet<usize> =
        reachable_instruction_indices_from(instructions, definition, None)?;
    if !from_definition.contains(&use_index) {
        return Ok(false);
    }
    let without_definition: std::collections::BTreeSet<usize> =
        reachable_instruction_indices_from(instructions, 0, Some(definition))?;
    Ok(!without_definition.contains(&use_index))
}

#[cfg(windows)]
fn stack_definition_reaches_use(
    instructions: &[Instruction],
    definition: usize,
    use_index: usize,
    location: StackLocation,
    trace: &mut TraceContext,
) -> Result<bool, String> {
    let by_ip: std::collections::BTreeMap<u64, usize> = instruction_indices_by_ip(instructions)?;
    let mut pending: Vec<usize> = instruction_successors(instructions, &by_ip, definition)?;
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    while let Some(index) = pending.pop() {
        trace.step()?;
        if index == use_index {
            return Ok(true);
        }
        if !visited.insert(index) {
            continue;
        }
        if visited.len() > 4096 {
            return Err("stack path instruction budget exceeded".to_string());
        }
        if trace.registry_out == Some((index, location)) {
            continue;
        }
        let instruction: &Instruction = instructions
            .get(index)
            .ok_or_else(|| "stack path index outside probe".to_string())?;
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && memory_location(instruction) == Some(location)
        {
            continue;
        }
        pending.extend(instruction_successors(instructions, &by_ip, index)?);
    }
    Ok(false)
}

#[cfg(windows)]
fn register_definition_reaches_use(
    instructions: &[Instruction],
    definition: usize,
    use_index: usize,
    register: Register,
    trace: &mut TraceContext,
) -> Result<bool, String> {
    let by_ip: std::collections::BTreeMap<u64, usize> = instruction_indices_by_ip(instructions)?;
    let mut pending: Vec<usize> = instruction_successors(instructions, &by_ip, definition)?;
    let mut visited: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    while let Some(index) = pending.pop() {
        trace.step()?;
        if index == use_index {
            return Ok(true);
        }
        if !visited.insert(index) {
            continue;
        }
        if visited.len() > 4096 {
            return Err("register path instruction budget exceeded".to_string());
        }
        let instruction: &Instruction = instructions
            .get(index)
            .ok_or_else(|| "register path index outside probe".to_string())?;
        if writes_register(instruction, register)
            || (register == Register::RAX
                && matches!(
                    instruction.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ))
        {
            continue;
        }
        pending.extend(instruction_successors(instructions, &by_ip, index)?);
    }
    Ok(false)
}

#[cfg(windows)]
fn unique_literal_rva(pe: &PE<'_>, bytes: &[u8], literal: &[u8]) -> usize {
    let mut matches: Vec<usize> = Vec::new();
    for section in &pe.sections {
        let characteristics: u32 = section.characteristics;
        if characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ == 0
            || characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0
            || characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
        {
            continue;
        }
        let start: usize = section.pointer_to_raw_data as usize;
        let size: usize = section.size_of_raw_data as usize;
        let Some(end): Option<usize> = start.checked_add(size) else {
            continue;
        };
        let Some(raw): Option<&[u8]> = bytes.get(start..end) else {
            continue;
        };
        for offset in subsequence_offsets(raw, literal) {
            let rva: usize = (section.virtual_address as usize)
                .checked_add(offset)
                .expect("literal RVA overflow");
            matches.push(rva);
        }
    }
    assert_eq!(matches.len(), 1, "one mapped literal object");
    matches[0]
}

#[cfg(windows)]
struct ComparisonBranchPaths {
    branch: usize,
    zero_starts: Vec<usize>,
    nonzero_starts: Vec<usize>,
}

#[cfg(windows)]
fn direct_comparison_branch_paths(
    instructions: &[Instruction],
    branch: usize,
) -> Option<ComparisonBranchPaths> {
    let instruction: &Instruction = instructions.get(branch)?;
    let by_ip: std::collections::BTreeMap<u64, usize> =
        instruction_indices_by_ip(instructions).ok()?;
    let target: usize = by_ip.get(&instruction.near_branch_target()).copied()?;
    let fallthrough: usize = branch.checked_add(1)?;
    if fallthrough >= instructions.len() {
        return None;
    }
    match instruction.condition_code() {
        ConditionCode::e => Some(ComparisonBranchPaths {
            branch,
            zero_starts: vec![target],
            nonzero_starts: vec![fallthrough],
        }),
        ConditionCode::ne => Some(ComparisonBranchPaths {
            branch,
            zero_starts: vec![fallthrough],
            nonzero_starts: vec![target],
        }),
        _ => None,
    }
}

#[cfg(windows)]
fn registry_status_branch_paths(
    instructions: &[Instruction],
    reachable: &std::collections::BTreeSet<usize>,
    comparison: usize,
    end: usize,
    trace: &mut TraceContext,
) -> Option<ComparisonBranchPaths> {
    let status_set: usize = comparison.checked_add(1)?;
    let status_instruction: &Instruction = instructions.get(status_set)?;
    if !reachable.contains(&status_set)
        || status_instruction.mnemonic() != Mnemonic::Setne
        || status_instruction.op0_kind() != OpKind::Register
    {
        return None;
    }
    let status_register: Register = status_instruction.op0_register().full_register();
    let handle_test: usize = (status_set + 1..end).find(|index: &usize| {
        let instruction: &Instruction = &instructions[*index];
        instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register().full_register()
                == instruction.op1_register().full_register()
            && trace
                .register_before(instructions, *index, instruction.op0_register())
                .is_ok_and(|origin: TraceOrigin| origin == TraceOrigin::RegistryHandle)
    })?;
    for instruction in &instructions[status_set + 1..handle_test] {
        if writes_register(instruction, status_register)
            || instruction.flow_control() != FlowControl::Next
            || instruction.rflags_modified() != 0
            || instruction.rflags_read() != 0
        {
            return None;
        }
    }
    let handle_set: usize = handle_test.checked_add(1)?;
    let merge: usize = handle_set.checked_add(1)?;
    let merged_test: usize = merge.checked_add(1)?;
    let branch: usize = merged_test.checked_add(1)?;
    if branch >= end {
        return None;
    }
    let handle_set_instruction: &Instruction = instructions.get(handle_set)?;
    let merge_instruction: &Instruction = instructions.get(merge)?;
    let merged_test_instruction: &Instruction = instructions.get(merged_test)?;
    let branch_instruction: &Instruction = instructions.get(branch)?;
    if handle_set_instruction.mnemonic() != Mnemonic::Sete
        || handle_set_instruction.op0_kind() != OpKind::Register
        || merge_instruction.mnemonic() != Mnemonic::Or
        || merge_instruction.op0_kind() != OpKind::Register
        || merge_instruction.op1_kind() != OpKind::Register
        || merge_instruction.op1_register().full_register() != status_register
        || merge_instruction.op0_register().full_register()
            != handle_set_instruction.op0_register().full_register()
        || merged_test_instruction.mnemonic() != Mnemonic::Cmp
        || merged_test_instruction.op0_kind() != OpKind::Register
        || merged_test_instruction.op0_register().full_register()
            != merge_instruction.op0_register().full_register()
        || immediate_value(merged_test_instruction, 1) != Some(1)
        || branch_instruction.flow_control() != FlowControl::ConditionalBranch
        || branch_instruction.condition_code() != ConditionCode::e
    {
        return None;
    }
    let direct: ComparisonBranchPaths = direct_comparison_branch_paths(instructions, branch)?;
    Some(ComparisonBranchPaths {
        branch,
        zero_starts: vec![direct.zero_starts[0], direct.nonzero_starts[0]],
        nonzero_starts: direct.zero_starts,
    })
}

#[cfg(windows)]
fn branch_using_comparison_flags(
    instructions: &[Instruction],
    reachable: &std::collections::BTreeSet<usize>,
    comparison: usize,
    end: usize,
    trace: &mut TraceContext,
    allow_registry_status_chain: bool,
) -> Option<ComparisonBranchPaths> {
    if allow_registry_status_chain
        && let Some(paths) =
            registry_status_branch_paths(instructions, reachable, comparison, end, trace)
    {
        return Some(paths);
    }
    for index in comparison + 1..end {
        if !reachable.contains(&index) {
            continue;
        }
        let instruction: &Instruction = &instructions[index];
        if instruction.flow_control() == FlowControl::ConditionalBranch {
            return direct_comparison_branch_paths(instructions, index);
        }
        if instruction.mnemonic() == Mnemonic::Cmove
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && trace
                .register_before(instructions, index, instruction.op0_register())
                .is_ok_and(|origin: TraceOrigin| origin == TraceOrigin::Constant(1))
            && trace
                .register_before(instructions, index, instruction.op1_register())
                .is_ok_and(|origin: TraceOrigin| origin == TraceOrigin::Constant(0))
        {
            let selected: Register = instruction.op0_register().full_register();
            for test_index in index + 1..end {
                if !reachable.contains(&test_index) {
                    continue;
                }
                let test: &Instruction = &instructions[test_index];
                if test.mnemonic() == Mnemonic::Test
                    && test.op0_kind() == OpKind::Register
                    && test.op0_register().full_register() == selected
                    && immediate_value(test, 1) == Some(1)
                {
                    return branch_using_comparison_flags(
                        instructions,
                        reachable,
                        test_index,
                        end,
                        trace,
                        false,
                    );
                }
                if writes_register(test, selected)
                    || test.flow_control() != FlowControl::Next
                    || test.rflags_modified() != 0
                    || test.rflags_read() != 0
                {
                    return None;
                }
            }
            return None;
        }
        if instruction.flow_control() != FlowControl::Next
            || instruction.rflags_modified() != 0
            || instruction.rflags_read() != 0
        {
            return None;
        }
    }
    None
}

#[cfg(windows)]
fn require_comparison_and_branch(
    instructions: &[Instruction],
    start: usize,
    end: usize,
    origin: TraceOrigin,
    success_when_zero: bool,
    trace: &mut TraceContext,
) {
    let reachable: std::collections::BTreeSet<usize> = trace.reachable.clone();
    let (comparison, paths): (usize, ComparisonBranchPaths) = (start..end)
        .find_map(|index: usize| {
            if !trace.reachable.contains(&index) {
                return None;
            }
            let instruction: &Instruction = &instructions[index];
            let compares_origin: bool =
                matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Test)
                    && (0..instruction.op_count()).any(|operand: u32| {
                        instruction.op_kind(operand) == OpKind::Register
                            && trace
                                .register_before(
                                    instructions,
                                    index,
                                    instruction.op_register(operand),
                                )
                                .is_ok_and(|actual: TraceOrigin| actual == origin)
                    });
            let compares_zero: bool = match instruction.mnemonic() {
                Mnemonic::Test => {
                    instruction.op0_kind() == OpKind::Register
                        && instruction.op1_kind() == OpKind::Register
                        && instruction.op0_register().full_register()
                            == instruction.op1_register().full_register()
                }
                Mnemonic::Cmp => (0..instruction.op_count())
                    .any(|operand: u32| immediate_value(instruction, operand) == Some(0)),
                _ => false,
            };
            (compares_origin && compares_zero)
                .then(|| {
                    branch_using_comparison_flags(
                        instructions,
                        &reachable,
                        index,
                        end,
                        trace,
                        origin == TraceOrigin::RegistryStatus,
                    )
                })
                .flatten()
                .map(|paths: ComparisonBranchPaths| (index, paths))
        })
        .expect("API return must control an unmodified zero-comparison branch");
    assert!(comparison < paths.branch);
    let zero_reaches: bool = paths.zero_starts.into_iter().any(|start: usize| {
        reachable_instruction_indices_from(instructions, start, None)
            .expect("bounded zero path")
            .contains(&end)
    });
    let nonzero_reaches: bool = paths.nonzero_starts.into_iter().any(|start: usize| {
        reachable_instruction_indices_from(instructions, start, None)
            .expect("bounded nonzero path")
            .contains(&end)
    });
    assert_eq!(zero_reaches, success_when_zero, "zero-result edge");
    assert_eq!(nonzero_reaches, !success_when_zero, "nonzero-result edge");
}

#[cfg(windows)]
fn require_probe_budgets(instructions: &[Instruction]) {
    assert!(instructions.len() <= 4096, "probe instruction budget");
    let edges: usize = instructions
        .iter()
        .map(
            |instruction: &Instruction| match instruction.flow_control() {
                FlowControl::ConditionalBranch => 2usize,
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => 1usize,
                _ => 0usize,
            },
        )
        .try_fold(0usize, |total: usize, count: usize| {
            total.checked_add(count)
        })
        .expect("control-flow edge count overflow");
    assert!(edges <= 8192);
    let mut locations: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    for instruction in instructions {
        for used in factory.info(instruction).used_registers() {
            locations.insert(format!("register:{:?}", used.register().full_register()));
        }
        if let Some(location) = memory_location(instruction) {
            locations.insert(format!(
                "stack:{:?}:{}",
                location.base, location.displacement
            ));
        }
    }
    assert!(locations.len() <= 512);
}

#[cfg(windows)]
fn require_global_store_origin(
    instructions: &[Instruction],
    target_va: u64,
    expected: TraceOrigin,
    allow_zero_merge: bool,
    trace: &mut TraceContext,
) {
    let stores: Vec<(usize, Register)> = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction): (usize, &Instruction)| {
            (trace.reachable.contains(&index)
                && instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == target_va
                && instruction.op1_kind() == OpKind::Register)
                .then_some((index, instruction.op1_register()))
        })
        .collect();
    assert_eq!(stores.len(), 1, "one exact result-slot store");
    let store_index: usize = stores[0].0;
    let source: Register = stores[0].1.full_register();
    let mut origins: Vec<TraceOrigin> =
        possible_register_origins(instructions, store_index, source, trace)
            .expect("trace all result-slot sources");
    if expected == TraceOrigin::DynamicReturn {
        let proc_call: usize = trace
            .api_returns
            .iter()
            .find_map(|(index, origin): (&usize, &TraceOrigin)| {
                (*origin == TraceOrigin::ProcReturn).then_some(*index)
            })
            .expect("GetProcAddress return definition");
        for index in proc_call + 1..store_index {
            let instruction: &Instruction = &instructions[index];
            let defines_source: bool = writes_register(instruction, source)
                || (source == Register::RAX
                    && matches!(
                        instruction.flow_control(),
                        FlowControl::Call | FlowControl::IndirectCall
                    ));
            if !defines_source {
                continue;
            }
            if let Ok(origin) = trace.register_before(instructions, index + 1, source)
                && matches!(
                    origin,
                    TraceOrigin::DynamicReturn | TraceOrigin::Constant(0)
                )
            {
                origins.push(origin);
            }
        }
    }
    assert!(
        origins.contains(&expected),
        "missing result origin {expected:?}: {origins:?}"
    );
    assert!(
        origins.iter().all(|origin: &TraceOrigin| {
            *origin == expected || (allow_zero_merge && *origin == TraceOrigin::Constant(0))
        }),
        "unknown result merge input: {origins:?}"
    );
}

#[cfg(windows)]
fn require_export_relations(pe: &PE<'_>, bytes: &[u8], instructions: &[Instruction]) {
    require_probe_budgets(instructions);
    let reachable: std::collections::BTreeSet<usize> =
        reachable_instruction_indices(instructions).expect("bounded export control flow");
    let ntdll: [u8; 20] = [
        0x6e, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c,
        0x00, 0x6c, 0x00, 0x00, 0x00,
    ];
    let ntdll_rva: usize = unique_literal_rva(pe, bytes, &ntdll);
    let proc_rva: usize = unique_literal_rva(pe, bytes, b"wine_get_version\0");
    let result_rva: usize = require_result_slot(pe, bytes, "DISROBE_WINE_EXPORT_RESULT", 8);
    let (module_call, _): (usize, ImportCallForm) =
        require_one_import_call(pe, bytes, instructions, "GetModuleHandleW", "kernel32.dll");
    let (proc_call, _): (usize, ImportCallForm) =
        require_one_import_call(pe, bytes, instructions, "GetProcAddress", "kernel32.dll");
    assert!(reachable.contains(&module_call));
    assert!(reachable.contains(&proc_call));
    assert!(module_call < proc_call);
    let mut trace: TraceContext = TraceContext {
        api_returns: [
            (module_call, TraceOrigin::ModuleReturn),
            (proc_call, TraceOrigin::ProcReturn),
        ]
        .into_iter()
        .collect(),
        registry_out: None,
        reachable,
        steps: 0,
    };
    assert_eq!(
        trace
            .register_before(instructions, module_call, Register::RCX)
            .expect("GetModuleHandleW RCX"),
        TraceOrigin::Address(pe.image_base + ntdll_rva as u64),
        "GetModuleHandleW RCX literal"
    );
    assert_eq!(
        trace
            .register_before(instructions, proc_call, Register::RCX)
            .expect("GetProcAddress RCX"),
        TraceOrigin::ModuleReturn,
        "GetProcAddress RCX module return"
    );
    assert_eq!(
        trace
            .register_before(instructions, proc_call, Register::RDX)
            .expect("GetProcAddress RDX"),
        TraceOrigin::Address(pe.image_base + proc_rva as u64),
        "GetProcAddress RDX literal"
    );
    require_comparison_and_branch(
        instructions,
        module_call + 1,
        proc_call,
        TraceOrigin::ModuleReturn,
        false,
        &mut trace,
    );
    let dynamic_call: usize = (proc_call + 1..instructions.len())
        .find(|index: &usize| {
            if !trace.reachable.contains(index) {
                return false;
            }
            let instruction: &Instruction = &instructions[*index];
            instruction.flow_control() == FlowControl::IndirectCall
                && trace
                    .call_target(instructions, *index)
                    .is_ok_and(|origin: TraceOrigin| origin == TraceOrigin::ProcReturn)
        })
        .expect("dynamic Wine export call");
    require_comparison_and_branch(
        instructions,
        proc_call + 1,
        dynamic_call,
        TraceOrigin::ProcReturn,
        false,
        &mut trace,
    );
    require_global_store_origin(
        instructions,
        pe.image_base + result_rva as u64,
        TraceOrigin::DynamicReturn,
        true,
        &mut trace,
    );
}

#[cfg(windows)]
fn require_registry_relations(pe: &PE<'_>, bytes: &[u8], instructions: &[Instruction]) {
    require_probe_budgets(instructions);
    let reachable: std::collections::BTreeSet<usize> =
        reachable_instruction_indices(instructions).expect("bounded registry control flow");
    let software_wine: [u8; 28] = [
        0x53, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x77, 0x00, 0x61, 0x00, 0x72, 0x00, 0x65,
        0x00, 0x5c, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x00, 0x00,
    ];
    let literal_rva: usize = unique_literal_rva(pe, bytes, &software_wine);
    let result_rva: usize = require_result_slot(pe, bytes, "DISROBE_WINE_REGISTRY_STATUS", 4);
    let (open_call, _): (usize, ImportCallForm) =
        require_one_import_call(pe, bytes, instructions, "RegOpenKeyExW", "advapi32.dll");
    let (close_call, _): (usize, ImportCallForm) =
        require_one_import_call(pe, bytes, instructions, "RegCloseKey", "advapi32.dll");
    assert!(reachable.contains(&open_call));
    assert!(
        reachable.contains(&close_call),
        "RegCloseKey must be reachable"
    );
    assert!(open_call < close_call);
    let mut trace: TraceContext = TraceContext {
        api_returns: std::iter::once((open_call, TraceOrigin::RegistryStatus)).collect(),
        registry_out: None,
        reachable,
        steps: 0,
    };
    assert_eq!(
        trace
            .register_before(instructions, open_call, Register::RCX)
            .expect("RegOpenKeyExW RCX"),
        TraceOrigin::Constant(0xffff_ffff_8000_0001),
        "RegOpenKeyExW RCX root key"
    );
    assert_eq!(
        trace
            .register_before(instructions, open_call, Register::RDX)
            .expect("RegOpenKeyExW RDX"),
        TraceOrigin::Address(pe.image_base + literal_rva as u64),
        "RegOpenKeyExW RDX literal"
    );
    assert_eq!(
        trace
            .register_before(instructions, open_call, Register::R8)
            .expect("RegOpenKeyExW R8"),
        TraceOrigin::Constant(0),
        "RegOpenKeyExW R8 options"
    );
    assert_eq!(
        trace
            .register_before(instructions, open_call, Register::R9)
            .expect("RegOpenKeyExW R9"),
        TraceOrigin::Constant(0x0002_0019),
        "RegOpenKeyExW R9 access"
    );
    let fifth_argument: StackLocation = StackLocation {
        base: Register::RSP,
        displacement: 0x20,
    };
    let out_location: StackLocation = match trace
        .stack_before(instructions, open_call, fifth_argument)
        .expect("RegOpenKeyExW fifth argument")
    {
        TraceOrigin::StackAddress(location) => location,
        other => panic!("unexpected fifth argument {other:?}"),
    };
    assert_eq!(
        trace
            .stack_before(instructions, open_call, out_location)
            .expect("out handle initialization"),
        TraceOrigin::Constant(0)
    );
    trace.registry_out = Some((open_call, out_location));
    require_comparison_and_branch(
        instructions,
        open_call + 1,
        close_call,
        TraceOrigin::RegistryStatus,
        true,
        &mut trace,
    );
    assert_eq!(
        trace
            .register_before(instructions, close_call, Register::RCX)
            .expect("RegCloseKey RCX"),
        TraceOrigin::RegistryHandle,
        "RegCloseKey RCX registry handle"
    );
    require_global_store_origin(
        instructions,
        pe.image_base + result_rva as u64,
        TraceOrigin::RegistryStatus,
        false,
        &mut trace,
    );
}

#[cfg(windows)]
fn require_wine_fixture_shape(kind: WineFixtureKind, bytes: &[u8]) {
    let pe: PE<'_> = PE::parse(bytes).expect("parse compiler-produced PE");
    assert!(pe.is_64, "fixture must be PE32+");
    assert_eq!(
        pe.header.coff_header.machine,
        goblin::pe::header::COFF_MACHINE_X86_64,
        "fixture must be AMD64"
    );
    let has_export: bool = matches!(kind, WineFixtureKind::Export | WineFixtureKind::Dual);
    let has_registry: bool = matches!(kind, WineFixtureKind::Registry | WineFixtureKind::Dual);
    assert_eq!(
        pe.exports
            .iter()
            .any(|export: &goblin::pe::export::Export<'_>| {
                export.name == Some("disrobe_probe_wine_export")
            }),
        has_export
    );
    assert_eq!(
        pe.exports
            .iter()
            .any(|export: &goblin::pe::export::Export<'_>| {
                export.name == Some("disrobe_probe_wine_registry")
            }),
        has_registry
    );
    let import_names: std::collections::BTreeSet<&str> = pe
        .imports
        .iter()
        .map(|import: &goblin::pe::import::Import<'_>| import.name.as_ref())
        .collect();
    if has_export {
        assert!(import_names.contains("GetModuleHandleW"));
        assert!(import_names.contains("GetProcAddress"));
        let instructions: Vec<Instruction> = decoded_probe(&pe, bytes, "disrobe_probe_wine_export");
        require_export_relations(&pe, bytes, &instructions);
    }
    if has_registry {
        assert!(import_names.contains("RegOpenKeyExW"));
        assert!(import_names.contains("RegCloseKey"));
        let instructions: Vec<Instruction> =
            decoded_probe(&pe, bytes, "disrobe_probe_wine_registry");
        require_registry_relations(&pe, bytes, &instructions);
    }
}

#[cfg(windows)]
#[test]
fn wine_probe_matrix_first_detects_with_both_probes_at_o0_and_o2() {
    let scratch: ScratchDir = scratch_dir();
    for opt_level in ["0", "2"] {
        let mut detections: Vec<bool> = Vec::new();
        for (kind, expected_evidence) in [
            (WineFixtureKind::Export, vec!["wine_get_version"]),
            (WineFixtureKind::Registry, vec!["software\\wine"]),
            (
                WineFixtureKind::Dual,
                vec!["software\\wine", "wine_get_version"],
            ),
        ] {
            let bytes: Vec<u8> = compile_wine_fixture(scratch.path(), kind, opt_level);
            require_wine_fixture_shape(kind, &bytes);
            let report: AntiAnalysisReport = scan(&bytes, Some("compiler-produced-wine-probe"));
            let finding: &disrobe_core::anti_analysis::AntiAnalysisFinding = report
                .findings
                .iter()
                .find(
                    |finding: &&disrobe_core::anti_analysis::AntiAnalysisFinding| {
                        finding.technique == Technique::AntiSandbox
                    },
                )
                .expect("Wine fixture must surface AntiSandbox");
            let expected_detected: bool = matches!(kind, WineFixtureKind::Dual);
            assert_eq!(finding.detected, expected_detected);
            assert_eq!(finding.confidence, Confidence::High);
            assert_eq!(
                finding.severity,
                if expected_detected {
                    FindingSeverity::Detected
                } else {
                    FindingSeverity::Informational
                }
            );
            let wine_evidence_keys: [&str; 4] = [
                "wine_get_version",
                "wine_get_unix_file_name",
                "software\\wine",
                "\\\\.\\winex11",
            ];
            let evidence: std::collections::BTreeSet<&str> = finding
                .evidence
                .iter()
                .filter_map(|detail: &String| {
                    wine_evidence_keys
                        .iter()
                        .copied()
                        .find(|needle: &&str| detail.contains(*needle))
                })
                .collect();
            assert_eq!(evidence, expected_evidence.into_iter().collect());
            detections.push(finding.detected);
        }
        assert_eq!(detections, vec![false, false, true]);
    }
}

#[cfg(windows)]
#[test]
fn wine_pe_oracle_rejects_loaded_iat_register_mutations() {
    let scratch: ScratchDir = scratch_dir();
    let bytes: Vec<u8> = compile_wine_fixture(scratch.path(), WineFixtureKind::Export, "0");
    let pe: PE<'_> = PE::parse(&bytes).expect("parse O0 Wine export PE");
    let real_instructions: Vec<Instruction> =
        decoded_probe(&pe, &bytes, "disrobe_probe_wine_export");
    require_export_relations(&pe, &bytes, &real_instructions);
    let instructions: Vec<Instruction> = decode_sequence(
        &[0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0xD0],
        0x1000,
    );
    let named_iat_va: u64 = 0x2000;
    let wrong_iat_va: u64 = 0x3000;
    let all_iat_vas: std::collections::BTreeSet<u64> =
        [named_iat_va, wrong_iat_va].into_iter().collect();
    let call_index: usize = 1;
    assert_eq!(
        resolve_import_call_form(
            &pe,
            &bytes,
            &instructions,
            call_index,
            named_iat_va,
            &all_iat_vas,
        ),
        Ok(ImportCallForm::LoadedIatRegister)
    );

    let overwritten: Vec<Instruction> = decode_sequence(
        &[
            0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xFF, 0xD0,
        ],
        0x1000,
    );
    assert!(
        resolve_import_call_form(&pe, &bytes, &overwritten, 2, named_iat_va, &all_iat_vas,)
            .is_err()
    );

    let wrong_slot: Vec<Instruction> = decode_sequence(
        &[0x48, 0x8B, 0x05, 0xF9, 0x1F, 0x00, 0x00, 0xFF, 0xD0],
        0x1000,
    );
    assert!(
        resolve_import_call_form(
            &pe,
            &bytes,
            &wrong_slot,
            call_index,
            named_iat_va,
            &all_iat_vas,
        )
        .is_err()
    );

    let control_split: Vec<Instruction> = decode_sequence(
        &[
            0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0x75, 0x00, 0xFF, 0xD0,
        ],
        0x1000,
    );
    assert!(
        resolve_import_call_form(&pe, &bytes, &control_split, 2, named_iat_va, &all_iat_vas,)
            .is_err()
    );

    let hopped: Vec<Instruction> = decode_sequence(
        &[0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, 0xFF, 0x10],
        0x1000,
    );
    assert!(
        resolve_import_call_form(&pe, &bytes, &hopped, call_index, named_iat_va, &all_iat_vas,)
            .is_err()
    );
}

#[cfg(windows)]
fn assert_relation_rejected(label: &str, expected: &str, check: impl FnOnce()) {
    let rejected: std::thread::Result<()> =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(check));
    let Err(payload) = rejected else {
        panic!("{label} mutation was accepted");
    };
    let message: &str = match (
        payload.downcast_ref::<String>(),
        payload.downcast_ref::<&'static str>(),
    ) {
        (Some(message), _) => message.as_str(),
        (None, Some(message)) => message,
        (None, None) => panic!("{label} mutation produced a non-string panic"),
    };
    assert!(
        message.contains(expected),
        "{label} mutation rejected for unexpected reason: {message}"
    );
}

#[cfg(windows)]
fn replace_nearest_register_definition(
    instructions: &[Instruction],
    before: usize,
    register: Register,
    replacement_bytes: &[u8],
) -> Vec<Instruction> {
    let normalized: Register = register.full_register();
    let index: usize = (0..before)
        .rev()
        .find(|index: &usize| writes_register(&instructions[*index], normalized))
        .expect("register definition to mutate");
    let mut replacement: Instruction =
        decode_sequence(replacement_bytes, instructions[index].ip())[0];
    replacement.set_ip(instructions[index].ip());
    let mut mutated: Vec<Instruction> = instructions.to_vec();
    mutated[index] = replacement;
    mutated
}

#[cfg(windows)]
fn duplicate_literal_bytes(pe: &PE<'_>, bytes: &[u8], literal: &[u8]) -> Vec<u8> {
    let original_rva: usize = unique_literal_rva(pe, bytes, literal);
    let original_range: std::ops::Range<usize> = mapped_file_range(pe, original_rva, literal.len());
    let destination: usize = pe
        .sections
        .iter()
        .filter(|section: &&goblin::pe::section_table::SectionTable| {
            let characteristics: u32 = section.characteristics;
            characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0
                && characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE == 0
                && characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE == 0
        })
        .find_map(|section: &goblin::pe::section_table::SectionTable| {
            let start: usize = section.pointer_to_raw_data as usize;
            let end: usize = start.checked_add(section.size_of_raw_data as usize)?;
            let raw: &[u8] = bytes.get(start..end)?;
            raw.windows(literal.len()).enumerate().rev().find_map(
                |(offset, candidate): (usize, &[u8])| {
                    let destination: usize = start.checked_add(offset)?;
                    let destination_end: usize = destination.checked_add(literal.len())?;
                    (candidate.iter().all(|byte: &u8| *byte == 0)
                        && (destination_end <= original_range.start
                            || destination >= original_range.end))
                        .then_some(destination)
                },
            )
        })
        .expect("read-only padding for duplicate literal");
    let mut mutated: Vec<u8> = bytes.to_vec();
    mutated[destination..destination + literal.len()].copy_from_slice(literal);
    mutated
}

#[cfg(windows)]
fn imported_iat_va(pe: &PE<'_>, name: &str) -> u64 {
    let matches: Vec<u64> = pe
        .imports
        .iter()
        .filter(|import: &&goblin::pe::import::Import<'_>| import.name.as_ref() == name)
        .map(|import: &goblin::pe::import::Import<'_>| pe.image_base + import.offset as u64)
        .collect();
    assert_eq!(matches.len(), 1);
    matches[0]
}

#[cfg(windows)]
fn rip_relative_displacement(next_ip: u64, target: u64) -> [u8; 4] {
    let displacement: i64 = i64::try_from(target).expect("target fits i64")
        - i64::try_from(next_ip).expect("instruction address fits i64");
    i32::try_from(displacement)
        .expect("RIP-relative target fits i32")
        .to_le_bytes()
}

#[cfg(windows)]
fn thunk_bytes_at_export(pe: &PE<'_>, bytes: &[u8], instructions: &[u8]) -> (Vec<u8>, u64) {
    let rva: usize = unique_export_rva(pe, "disrobe_probe_wine_export");
    let range: std::ops::Range<usize> = mapped_file_range(pe, rva, 32);
    assert!(instructions.len() <= range.len());
    let mut mutated: Vec<u8> = bytes.to_vec();
    mutated[range.clone()].fill(0x90);
    mutated[range.start..range.start + instructions.len()].copy_from_slice(instructions);
    (mutated, pe.image_base + rva as u64)
}

#[cfg(windows)]
#[test]
fn wine_pe_oracle_rejects_unbound_literals_wrong_abi_and_impure_thunks() {
    let scratch: ScratchDir = scratch_dir();
    let export_bytes: Vec<u8> = compile_wine_fixture(scratch.path(), WineFixtureKind::Export, "0");
    let export_pe: PE<'_> = PE::parse(&export_bytes).expect("parse O0 Wine export PE");
    let mut aliased_pe: PE<'_> = PE::parse(&export_bytes).expect("parse aliased O0 Wine export PE");
    let aliased_export: &mut goblin::pe::export::Export<'_> = aliased_pe
        .exports
        .iter_mut()
        .find(|export: &&mut goblin::pe::export::Export<'_>| {
            export.name == Some("disrobe_probe_wine_export")
        })
        .expect("Wine export to alias");
    aliased_export.rva = aliased_export
        .rva
        .checked_add(1)
        .expect("interior export RVA");
    assert_relation_rejected(
        "interior exported alias",
        "probe export must equal runtime function entry",
        || {
            let _: Vec<Instruction> =
                decoded_probe(&aliased_pe, &export_bytes, "disrobe_probe_wine_export");
        },
    );
    let export_instructions: Vec<Instruction> =
        decoded_probe(&export_pe, &export_bytes, "disrobe_probe_wine_export");
    require_export_relations(&export_pe, &export_bytes, &export_instructions);
    let (module_call, _): (usize, ImportCallForm) = require_one_import_call(
        &export_pe,
        &export_bytes,
        &export_instructions,
        "GetModuleHandleW",
        "kernel32.dll",
    );
    let (proc_call, _): (usize, ImportCallForm) = require_one_import_call(
        &export_pe,
        &export_bytes,
        &export_instructions,
        "GetProcAddress",
        "kernel32.dll",
    );
    let ntdll: [u8; 20] = [
        0x6e, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c,
        0x00, 0x6c, 0x00, 0x00, 0x00,
    ];
    let ntdll_rva: usize = unique_literal_rva(&export_pe, &export_bytes, &ntdll);
    let ntdll_range: std::ops::Range<usize> = mapped_file_range(&export_pe, ntdll_rva, ntdll.len());
    let literal_va: u64 = export_pe.image_base + ntdll_rva as u64;
    let mut missing_terminator: Vec<u8> = export_bytes.clone();
    missing_terminator[ntdll_range.end - 1] = 1;
    assert_relation_rejected("missing terminator", "one mapped literal object", || {
        require_export_relations(&export_pe, &missing_terminator, &export_instructions);
    });
    let duplicated_literal: Vec<u8> =
        duplicate_literal_bytes(&export_pe, &export_bytes, b"wine_get_version\0");
    assert_relation_rejected("duplicate literal", "one mapped literal object", || {
        require_export_relations(&export_pe, &duplicated_literal, &export_instructions);
    });
    let mut wrong_encoding: Vec<u8> = export_bytes.clone();
    wrong_encoding[ntdll_range.start + 1] = 1;
    assert_relation_rejected(
        "wrong literal encoding",
        "one mapped literal object",
        || {
            require_export_relations(&export_pe, &wrong_encoding, &export_instructions);
        },
    );

    let mut sibling_literal: Vec<Instruction> = export_instructions.clone();
    let module_argument: usize = (0..module_call)
        .rev()
        .find(|index: &usize| writes_register(&sibling_literal[*index], Register::RCX))
        .expect("module argument definition");
    assert!(sibling_literal[module_argument].is_ip_rel_memory_operand());
    sibling_literal[module_argument].set_memory_displacement64(literal_va + 2);
    assert_relation_rejected("sibling literal", "GetModuleHandleW RCX literal", || {
        require_export_relations(&export_pe, &export_bytes, &sibling_literal);
    });
    let wrong_proc_literal: Vec<Instruction> = replace_nearest_register_definition(
        &export_instructions,
        proc_call,
        Register::RDX,
        &[0x48, 0x31, 0xD2],
    );
    assert_relation_rejected(
        "wrong procedure literal",
        "GetProcAddress RDX literal",
        || {
            require_export_relations(&export_pe, &export_bytes, &wrong_proc_literal);
        },
    );

    let mut unrelated_api_call: Vec<Instruction> = export_instructions.clone();
    let mut duplicate_call: Instruction = unrelated_api_call[module_call];
    duplicate_call.set_ip(0x1000);
    unrelated_api_call.insert(module_call, duplicate_call);
    assert_relation_rejected(
        "duplicate API call",
        "one resolved call to GetModuleHandleW",
        || {
            require_export_relations(&export_pe, &export_bytes, &unrelated_api_call);
        },
    );
    let replaced_module_return: Vec<Instruction> = replace_nearest_register_definition(
        &export_instructions,
        proc_call,
        Register::RCX,
        &[0x48, 0x31, 0xC9],
    );
    assert_relation_rejected(
        "replaced module return",
        "GetProcAddress RCX module return",
        || {
            require_export_relations(&export_pe, &export_bytes, &replaced_module_return);
        },
    );

    let reachable: std::collections::BTreeSet<usize> =
        reachable_instruction_indices(&export_instructions).expect("export reachability");
    let mut trace: TraceContext = TraceContext {
        api_returns: [
            (module_call, TraceOrigin::ModuleReturn),
            (proc_call, TraceOrigin::ProcReturn),
        ]
        .into_iter()
        .collect(),
        registry_out: None,
        reachable,
        steps: 0,
    };
    let dynamic_call: usize = (proc_call + 1..export_instructions.len())
        .find(|index: &usize| {
            let instruction: &Instruction = &export_instructions[*index];
            instruction.flow_control() == FlowControl::IndirectCall
                && trace
                    .call_target(&export_instructions, *index)
                    .is_ok_and(|origin: TraceOrigin| origin == TraceOrigin::ProcReturn)
        })
        .expect("dynamic export call");
    let mut replaced_proc_return: Vec<Instruction> = export_instructions.clone();
    let mut wrong_dynamic_call: Instruction = decode_sequence(&[0xFF, 0xD1], 0)[0];
    wrong_dynamic_call.set_ip(replaced_proc_return[dynamic_call].ip());
    replaced_proc_return[dynamic_call] = wrong_dynamic_call;
    assert_relation_rejected(
        "replaced procedure return",
        "dynamic Wine export call",
        || {
            require_export_relations(&export_pe, &export_bytes, &replaced_proc_return);
        },
    );

    let result_rva: usize = unique_export_rva(&export_pe, "DISROBE_WINE_EXPORT_RESULT");
    let result_va: u64 = export_pe.image_base + result_rva as u64;
    let mut wrong_export_result: Vec<Instruction> = export_instructions.clone();
    let result_store: usize = wrong_export_result
        .iter()
        .position(|instruction: &Instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == result_va
        })
        .expect("export result store");
    wrong_export_result[result_store].set_memory_displacement64(result_va + 8);
    assert_relation_rejected("wrong export result", "one exact result-slot store", || {
        require_export_relations(&export_pe, &export_bytes, &wrong_export_result);
    });

    let mut moved_to_sibling: Vec<Instruction> = export_instructions;
    let mut branch: Instruction = decode_sequence(&[0xEB, 0x00], 0x1000)[0];
    branch.set_near_branch64(moved_to_sibling[module_call].ip());
    let mut definition: Instruction =
        decode_sequence(&[0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00], 0x1002)[0];
    definition.set_memory_displacement64(literal_va);
    moved_to_sibling.insert(module_call, branch);
    moved_to_sibling.insert(module_call + 1, definition);
    assert_relation_rejected(
        "unreachable sibling definition",
        "nearest register definition is unreachable",
        || {
            require_export_relations(&export_pe, &export_bytes, &moved_to_sibling);
        },
    );

    let named_iat_va: u64 = imported_iat_va(&export_pe, "GetModuleHandleW");
    let wrong_iat_va: u64 = imported_iat_va(&export_pe, "GetProcAddress");
    let export_va: u64 =
        export_pe.image_base + unique_export_rva(&export_pe, "disrobe_probe_wine_export") as u64;
    let mut argument_mutating_thunk: Vec<u8> = vec![0x48, 0x31, 0xC9, 0xFF, 0x25];
    argument_mutating_thunk
        .extend_from_slice(&rip_relative_displacement(export_va + 9, named_iat_va));
    let (argument_mutating_bytes, argument_mutating_va): (Vec<u8>, u64) =
        thunk_bytes_at_export(&export_pe, &export_bytes, &argument_mutating_thunk);
    assert!(
        pure_thunk_targets_iat(
            &export_pe,
            &argument_mutating_bytes,
            argument_mutating_va,
            named_iat_va,
        )
        .is_err()
    );

    let mut second_iat_thunk: Vec<u8> = vec![0x48, 0x8B, 0x05];
    second_iat_thunk.extend_from_slice(&rip_relative_displacement(export_va + 7, wrong_iat_va));
    second_iat_thunk.extend_from_slice(&[0xFF, 0x25]);
    second_iat_thunk.extend_from_slice(&rip_relative_displacement(export_va + 13, named_iat_va));
    let (second_iat_bytes, second_iat_va): (Vec<u8>, u64) =
        thunk_bytes_at_export(&export_pe, &export_bytes, &second_iat_thunk);
    assert!(
        pure_thunk_targets_iat(&export_pe, &second_iat_bytes, second_iat_va, named_iat_va,)
            .is_err()
    );

    let mut second_hop_thunk: Vec<u8> = vec![0xE9];
    second_hop_thunk.extend_from_slice(&rip_relative_displacement(export_va + 5, export_va + 16));
    let (second_hop_bytes, second_hop_va): (Vec<u8>, u64) =
        thunk_bytes_at_export(&export_pe, &export_bytes, &second_hop_thunk);
    assert!(
        pure_thunk_targets_iat(&export_pe, &second_hop_bytes, second_hop_va, named_iat_va,)
            .is_err()
    );

    let oversized_probe: Vec<Instruction> = (0..4097)
        .flat_map(|_| decode_sequence(&[0x90], 0))
        .collect();
    assert_relation_rejected("oversized probe", "probe instruction budget", || {
        require_probe_budgets(&oversized_probe);
    });

    let registry_bytes: Vec<u8> =
        compile_wine_fixture(scratch.path(), WineFixtureKind::Registry, "0");
    let registry_pe: PE<'_> = PE::parse(&registry_bytes).expect("parse O0 Wine registry PE");
    let registry_instructions: Vec<Instruction> =
        decoded_probe(&registry_pe, &registry_bytes, "disrobe_probe_wine_registry");
    require_registry_relations(&registry_pe, &registry_bytes, &registry_instructions);
    let (open_call, _): (usize, ImportCallForm) = require_one_import_call(
        &registry_pe,
        &registry_bytes,
        &registry_instructions,
        "RegOpenKeyExW",
        "advapi32.dll",
    );
    let (close_call, _): (usize, ImportCallForm) = require_one_import_call(
        &registry_pe,
        &registry_bytes,
        &registry_instructions,
        "RegCloseKey",
        "advapi32.dll",
    );
    for (register, replacement) in [
        (Register::RCX, &[0x48, 0x31, 0xC9][..]),
        (Register::RDX, &[0x48, 0x31, 0xD2][..]),
        (Register::R8, &[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00][..]),
        (Register::R9, &[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00][..]),
    ] {
        let wrong_argument: Vec<Instruction> = replace_nearest_register_definition(
            &registry_instructions,
            open_call,
            register,
            replacement,
        );
        let expected: &str = match register {
            Register::RCX => "RegOpenKeyExW RCX root key",
            Register::RDX => "RegOpenKeyExW RDX literal",
            Register::R8 => "RegOpenKeyExW R8 options",
            Register::R9 => "RegOpenKeyExW R9 access",
            other => panic!("unsupported registry argument register {other:?}"),
        };
        assert_relation_rejected("wrong registry argument", expected, || {
            require_registry_relations(&registry_pe, &registry_bytes, &wrong_argument);
        });
    }

    let fifth_argument: StackLocation = StackLocation {
        base: Register::RSP,
        displacement: 0x20,
    };
    let mut wrong_fifth_argument: Vec<Instruction> = registry_instructions.clone();
    let fifth_store: usize = (0..open_call)
        .rev()
        .find(|index: &usize| {
            wrong_fifth_argument[*index].op0_kind() == OpKind::Memory
                && memory_location(&wrong_fifth_argument[*index]) == Some(fifth_argument)
        })
        .expect("fifth argument store");
    wrong_fifth_argument[fifth_store].set_memory_displacement64(0x28);
    assert_relation_rejected(
        "wrong fifth registry argument",
        "RegOpenKeyExW fifth argument",
        || {
            require_registry_relations(&registry_pe, &registry_bytes, &wrong_fifth_argument);
        },
    );

    let mut missing_success_edge: Vec<Instruction> = registry_instructions.clone();
    for instruction in &mut missing_success_edge[open_call + 1..close_call] {
        if instruction.flow_control() == FlowControl::ConditionalBranch {
            let ip: u64 = instruction.ip();
            *instruction = decode_sequence(&[0x90], ip)[0];
        }
    }
    assert_relation_rejected(
        "missing registry success edge",
        "RegCloseKey must be reachable",
        || {
            require_registry_relations(&registry_pe, &registry_bytes, &missing_success_edge);
        },
    );

    let mut inverted_success_edge: Vec<Instruction> = registry_instructions.clone();
    for instruction in &mut inverted_success_edge[open_call + 1..close_call] {
        if instruction.flow_control() == FlowControl::ConditionalBranch {
            instruction.negate_condition_code();
            break;
        }
    }
    assert_relation_rejected("inverted registry success edge", "zero-result edge", || {
        require_registry_relations(&registry_pe, &registry_bytes, &inverted_success_edge);
    });

    let wrong_handle_reload: Vec<Instruction> = replace_nearest_register_definition(
        &registry_instructions,
        close_call,
        Register::RCX,
        &[0x48, 0x31, 0xC9],
    );
    assert_relation_rejected(
        "wrong registry handle reload",
        "RegCloseKey RCX registry handle",
        || {
            require_registry_relations(&registry_pe, &registry_bytes, &wrong_handle_reload);
        },
    );

    let registry_result_rva: usize =
        unique_export_rva(&registry_pe, "DISROBE_WINE_REGISTRY_STATUS");
    let registry_result_va: u64 = registry_pe.image_base + registry_result_rva as u64;
    let registry_store: usize = registry_instructions
        .iter()
        .position(|instruction: &Instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.is_ip_rel_memory_operand()
                && instruction.ip_rel_memory_address() == registry_result_va
        })
        .expect("registry result store");
    let registry_source: Register = registry_instructions[registry_store]
        .op1_register()
        .full_register();
    let zero_bytes: &[u8] = match registry_source {
        Register::RAX => &[0x31, 0xC0],
        Register::RSI => &[0x31, 0xF6],
        other => panic!("unsupported registry result register {other:?}"),
    };
    let mut zero_merge: Vec<Instruction> = registry_instructions.clone();
    let mut bypass: Instruction = decode_sequence(&[0x75, 0x00], 0x1000)[0];
    bypass.set_near_branch64(zero_merge[registry_store].ip());
    let zero: Instruction = decode_sequence(zero_bytes, 0x1002)[0];
    zero_merge.insert(registry_store, bypass);
    zero_merge.insert(registry_store + 1, zero);
    assert_relation_rejected(
        "registry status zero overwrite",
        "unknown result merge input",
        || {
            require_registry_relations(&registry_pe, &registry_bytes, &zero_merge);
        },
    );

    let mut wrong_registry_result: Vec<Instruction> = registry_instructions;
    wrong_registry_result[registry_store].set_memory_displacement64(registry_result_va + 4);
    assert_relation_rejected(
        "wrong registry result",
        "one exact result-slot store",
        || {
            require_registry_relations(&registry_pe, &registry_bytes, &wrong_registry_result);
        },
    );
}

#[test]
fn benign_c_binaries_yield_zero_verdicts() {
    let Some(cc): Option<&'static str> = first_c_compiler() else {
        eprintln!("SKIP: no C compiler (cc/gcc/clang) available");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut compiled_any: bool = false;
    for (stem, src) in [("aa_tiny", TINY_C), ("aa_medium", MEDIUM_C)] {
        for opt in ["-O0", "-O2"] {
            let unique: String = format!("{stem}{}", opt.replace('-', "_"));
            let Some(bytes): Option<Vec<u8>> = compile_c(cc, &dir, &unique, src, opt) else {
                eprintln!("SKIP: {cc} {opt} failed to build {stem}");
                continue;
            };
            compiled_any = true;
            assert_zero_anti_analysis_verdicts(&format!("{cc}{opt}/{stem}"), &bytes);
        }
    }
    assert!(
        compiled_any,
        "at least one benign C build must succeed to exercise the precision corpus"
    );
}

#[test]
fn benign_rust_binary_yields_zero_verdicts() {
    if !tool_available("rustc") {
        eprintln!("SKIP: rustc unavailable");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("aa_rust.rs");
    std::fs::write(
        &src_path,
        "fn main(){ let mut s:u64=0; for i in 0..1000u64 { s=s.wrapping_add(i*i^s); } \
         println!(\"{}\", s); }\n",
    )
    .expect("write rust source");
    let mut compiled_any: bool = false;
    for (label, opt) in [("debug", "0"), ("release", "2")] {
        let out_path: PathBuf = dir.join(exe_name(&format!("aa_rust_{label}")));
        let ok: bool = Command::new("rustc")
            .arg(format!("-Copt-level={opt}"))
            .arg(&src_path)
            .arg("-o")
            .arg(&out_path)
            .status()
            .is_ok_and(|s: std::process::ExitStatus| s.success());
        if !ok {
            eprintln!("SKIP: rustc {label} build failed");
            continue;
        }
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&out_path) else {
            continue;
        };
        compiled_any = true;
        assert_zero_anti_analysis_verdicts(&format!("rust/{label}"), &bytes);
    }
    if !compiled_any {
        eprintln!("SKIP: no rust build succeeded");
    }
}

#[test]
fn positive_recall_real_binary_calling_two_debugger_checks() {
    if !tool_available("rustc") {
        eprintln!("SKIP: rustc unavailable");
        return;
    }
    if !cfg!(windows) {
        eprintln!("SKIP: IsDebuggerPresent/CheckRemoteDebuggerPresent are win32-only");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("aa_two_debug_checks.rs");
    std::fs::write(
        &src_path,
        "unsafe extern \"system\" { \
             fn IsDebuggerPresent() -> i32; \
             fn CheckRemoteDebuggerPresent(h_process: isize, pb_debugger_present: *mut i32) -> i32; \
         } \
         fn main(){ unsafe { \
             let a: i32 = IsDebuggerPresent(); \
             let mut b: i32 = 0; \
             CheckRemoteDebuggerPresent(-1isize, std::ptr::addr_of_mut!(b)); \
             println!(\"{a} {b}\"); \
         } }\n",
    )
    .expect("write rust source");
    let out_path: PathBuf = dir.join(exe_name("aa_two_debug_checks"));
    let ok: bool = Command::new("rustc")
        .arg("-Copt-level=0")
        .arg(&src_path)
        .arg("-o")
        .arg(&out_path)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());
    if !ok {
        eprintln!("SKIP: rustc build of the two-debugger-check probe failed");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&out_path).expect("read compiled probe");
    let report: AntiAnalysisReport = scan(&bytes, Some("rust/two-debugger-checks"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "a real binary that calls two distinct high-confidence anti-debug apis must still \
         reach an AntiDebug verdict; got {:?}",
        report.findings
    );
}

const LARGE_BENIGN_FIXTURE: &str = "large-benign-x86_64-pc-windows-msvc.exe";
const LARGE_BENIGN_MANIFEST: &str = "MANIFEST.toml";
const LARGE_BENIGN_GENERATOR: &str = "generate.ps1";
const LARGE_BENIGN_MINIMUM_TEXT_BYTES: u64 = 5 * 1024 * 1024;
const LARGE_BENIGN_MAXIMUM_TEXT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct LargeBenignManifest {
    schema_version: u32,
    description: String,
    fixtures: Vec<LargeBenignFixture>,
}

#[derive(Deserialize)]
struct LargeBenignFixture {
    path: String,
    format: String,
    tool: String,
    sha256: String,
    bytes: u64,
    text_raw_bytes: u64,
    generator_sha256: String,
    target: String,
    compiler_release: String,
    compiler_commit: String,
    rustc_args: Vec<String>,
    linker_release: String,
    linker_sha256: String,
    sdk_version: String,
    sdk_kernel32_sha256: String,
    provenance: String,
    source_license: String,
    rust_runtime_license: String,
    llvm_license: String,
    windows_sdk_license: String,
}

fn large_benign_fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/native/anti-analysis")
}

fn large_benign_fixture_path() -> PathBuf {
    large_benign_fixture_directory().join(LARGE_BENIGN_FIXTURE)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn committed_large_benign_fixture_has_no_detected_findings() {
    let fixture_directory: PathBuf = large_benign_fixture_directory();
    let mut fixture_entries: Vec<String> = std::fs::read_dir(&fixture_directory)
        .expect("read fixture directory")
        .map(|entry: Result<std::fs::DirEntry, std::io::Error>| {
            entry
                .expect("read fixture directory entry")
                .file_name()
                .into_string()
                .expect("fixture entry name must be UTF-8")
        })
        .collect();
    fixture_entries.sort();
    assert_eq!(
        fixture_entries,
        vec![
            LARGE_BENIGN_MANIFEST.to_string(),
            LARGE_BENIGN_GENERATOR.to_string(),
            LARGE_BENIGN_FIXTURE.to_string(),
        ]
    );
    let fixture_path: PathBuf = large_benign_fixture_path();
    assert!(
        fixture_path.is_file(),
        "the large benign fixture must be committed at {}",
        fixture_path.display()
    );
    let manifest_path: PathBuf = fixture_directory.join(LARGE_BENIGN_MANIFEST);
    let generator_path: PathBuf = fixture_directory.join(LARGE_BENIGN_GENERATOR);
    let manifest_text: String =
        std::fs::read_to_string(&manifest_path).expect("read fixture manifest");
    let manifest: LargeBenignManifest =
        toml::from_str(&manifest_text).expect("parse fixture manifest");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(
        manifest.description,
        "Pinned self-authored Rust PE32+ x86-64 fixture for the anti-analysis precision corpus. The committed executable provides a 5-16 MiB file-backed executable text span and must not reach a detected finding."
    );
    assert_eq!(manifest.fixtures.len(), 1);
    let fixture: &LargeBenignFixture = &manifest.fixtures[0];
    let fixture_bytes: Vec<u8> = std::fs::read(&fixture_path).expect("read committed fixture");
    let generator_bytes: Vec<u8> = std::fs::read(&generator_path).expect("read fixture generator");
    assert_eq!(fixture.path, LARGE_BENIGN_FIXTURE);
    assert_eq!(fixture.format, "PE32+ x86-64");
    assert_eq!(fixture.sha256, sha256_hex(&fixture_bytes));
    assert_eq!(fixture.generator_sha256, sha256_hex(&generator_bytes));
    let fixture_bytes_len: u64 =
        u64::try_from(fixture_bytes.len()).expect("fixture size must fit in u64");
    assert_eq!(fixture.bytes, fixture_bytes_len);
    assert_eq!(fixture.target, "x86_64-pc-windows-msvc");
    assert_eq!(fixture.compiler_release, "1.96.1");
    assert_eq!(
        fixture.compiler_commit,
        "31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd"
    );
    assert_eq!(
        fixture.rustc_args,
        vec![
            "--target".to_string(),
            "x86_64-pc-windows-msvc".to_string(),
            "--edition".to_string(),
            "2024".to_string(),
            "-Copt-level=1".to_string(),
            "-Cdebuginfo=0".to_string(),
            "-Cstrip=symbols".to_string(),
            "-Clinker=<pinned-rust-lld>".to_string(),
            "-Clinker-flavor=lld-link".to_string(),
            "-Clink-arg=/Brepro".to_string(),
            "-Clink-arg=/DEBUG:NONE".to_string(),
            "--remap-path-prefix=<owned-temp>=.".to_string(),
        ]
    );
    assert_eq!(
        fixture.tool,
        "rustc 1.96.1 (31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd), rust-lld 22.1.2 (1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e), Windows SDK 10.0.26100.0"
    );
    assert_eq!(
        fixture.provenance,
        "self-authored deterministic Rust source generated in an owned unique temporary directory and compiled directly with the pinned toolchain"
    );
    assert_eq!(
        fixture.linker_release,
        "LLD 22.1.2 (https://github.com/rust-lang/llvm-project.git 1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e)"
    );
    assert_eq!(
        fixture.linker_sha256,
        "21d542ef31ee7308dffb79f3e7ebf4ffa0f4a109874c95b8cc78190c36fccbbe"
    );
    assert_eq!(fixture.sdk_version, "10.0.26100.0");
    assert_eq!(
        fixture.sdk_kernel32_sha256,
        "341c7d56125a03b458e4d5093e4c79b33123ccfdfd610fe236937b8e6f3134bb"
    );
    assert_eq!(fixture.source_license, "MIT OR Apache-2.0");
    assert_eq!(fixture.rust_runtime_license, "MIT OR Apache-2.0");
    assert_eq!(fixture.llvm_license, "Apache-2.0 WITH LLVM-exception");
    assert_eq!(
        fixture.windows_sdk_license,
        "Microsoft Software License Terms for the Windows Software Development Kit"
    );
    let pe: PE<'_> = PE::parse(&fixture_bytes).expect("parse committed PE32+ fixture");
    assert!(pe.is_64, "fixture must be PE32+");
    assert_eq!(
        pe.header.coff_header.machine,
        goblin::pe::header::COFF_MACHINE_X86_64,
        "fixture must target x86-64"
    );
    let text_sections: Vec<&goblin::pe::section_table::SectionTable> = pe
        .sections
        .iter()
        .filter(|section: &&goblin::pe::section_table::SectionTable| {
            section.name().is_ok_and(|name: &str| name == ".text")
                && section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
        })
        .collect();
    assert_eq!(
        text_sections.len(),
        1,
        "fixture must contain one executable .text section"
    );
    let text_raw_start: usize = usize::try_from(text_sections[0].pointer_to_raw_data)
        .expect(".text raw offset must fit in usize");
    let text_raw_len: usize = usize::try_from(text_sections[0].size_of_raw_data)
        .expect(".text raw size must fit in usize");
    let text_raw_end: usize = text_raw_start
        .checked_add(text_raw_len)
        .expect(".text raw range must not overflow usize");
    assert!(
        text_raw_end <= fixture_bytes.len(),
        ".text raw range must lie inside the committed fixture"
    );
    let text_raw_bytes: u64 = u64::from(text_sections[0].size_of_raw_data);
    assert_eq!(fixture.text_raw_bytes, text_raw_bytes);
    assert!(text_raw_bytes >= LARGE_BENIGN_MINIMUM_TEXT_BYTES);
    assert!(text_raw_bytes <= LARGE_BENIGN_MAXIMUM_TEXT_BYTES);
    let report: AntiAnalysisReport =
        scan(&fixture_bytes, Some("large-benign-x86_64-pc-windows-msvc"));
    assert!(
        report.findings.iter().all(|finding| !finding.detected),
        "the committed large benign fixture must not reach an anti-analysis verdict: {:?}",
        report.findings
    );
}

#[test]
fn upx_packed_benign_reports_only_packing() {
    let Some(cc): Option<&'static str> = first_c_compiler() else {
        eprintln!("SKIP: no C compiler for upx corpus");
        return;
    };
    if !tool_available("upx") {
        eprintln!("SKIP: upx unavailable");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let Some(_): Option<Vec<u8>> = compile_c(cc, &dir, "aa_upx", MEDIUM_C, "-O2") else {
        eprintln!("SKIP: could not build upx input");
        return;
    };
    let input: PathBuf = dir.join(exe_name("aa_upx"));
    let packed: PathBuf = dir.join(exe_name("aa_upx_packed"));
    let ok: bool = Command::new("upx")
        .arg("--best")
        .arg("-q")
        .arg("-o")
        .arg(&packed)
        .arg(&input)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());
    if !ok {
        eprintln!("SKIP: upx packing failed");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&packed).expect("read packed");
    let report: AntiAnalysisReport = scan(&bytes, Some("upx-packed"));
    let verdicts: Vec<Technique> = report
        .findings
        .iter()
        .filter(|f| f.detected)
        .map(|f| f.technique)
        .collect();
    assert_eq!(
        verdicts,
        vec![Technique::Packing],
        "a upx-packed benign must report exactly one verdict, Packing; got {:?}",
        report.findings
    );
}

fn pe_with_code(payload: &[u8], bits64: bool) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let opt_size: usize = if bits64 { 0xF0 } else { 0xE0 };
    let sect_start: usize = pe_off + 24 + opt_size;
    let raw_ptr: usize = 0x200;
    let total: usize = (raw_ptr + payload.len().max(1)).max(sect_start + 40);
    let mut img: Vec<u8> = vec![0u8; total];
    img[0] = b'M';
    img[1] = b'Z';
    img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let machine: u16 = if bits64 { 0x8664 } else { 0x014C };
    img[pe_off + 4..pe_off + 6].copy_from_slice(&machine.to_le_bytes());
    img[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    img[pe_off + 20..pe_off + 22].copy_from_slice(&u16::try_from(opt_size).unwrap().to_le_bytes());
    let opt_start: usize = pe_off + 24;
    let magic: u16 = if bits64 { 0x020B } else { 0x010B };
    img[opt_start..opt_start + 2].copy_from_slice(&magic.to_le_bytes());
    let base: usize = sect_start;
    img[base..base + 8].copy_from_slice(b".text\0\0\0");
    let plen: u32 = u32::try_from(payload.len()).unwrap();
    img[base + 8..base + 12].copy_from_slice(&plen.to_le_bytes());
    img[base + 12..base + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    img[base + 16..base + 20].copy_from_slice(&plen.to_le_bytes());
    img[base + 20..base + 24].copy_from_slice(&u32::try_from(raw_ptr).unwrap().to_le_bytes());
    img[base + 36..base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    img[raw_ptr..raw_ptr + payload.len()].copy_from_slice(payload);
    img
}

fn detects(report: &AntiAnalysisReport, technique: Technique) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.technique == technique && f.detected)
}

fn surfaced(report: &AntiAnalysisReport, technique: Technique) -> bool {
    report.findings.iter().any(|f| f.technique == technique)
}

#[test]
fn positive_recall_peb_being_debugged_32bit() {
    let mut payload: Vec<u8> = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
    payload.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02, 0x84, 0xC0]);
    let report: AntiAnalysisReport =
        scan(&pe_with_code(&payload, false), Some("peb-beingdebugged"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "peb beingdebugged read must reach a verdict: {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_peb_ntglobalflag_64bit() {
    let mut payload: Vec<u8> = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
    payload.extend_from_slice(&[0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00]);
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("peb-ntglobalflag"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_rdtsc_sandwich() {
    let payload: Vec<u8> = vec![0x0F, 0x31, 0x50, 0x0F, 0xA2, 0x58, 0x0F, 0x31, 0x2B, 0xC1];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("rdtsc-sandwich"));
    assert!(
        detects(&report, Technique::TimingEvasion),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_sidt_red_pill_surfaced() {
    let payload: Vec<u8> = vec![0x0F, 0x01, 0x4C, 0x24, 0xFE, 0x3C, 0xFF];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("sidt-compare"));
    assert!(
        surfaced(&report, Technique::AntiVm),
        "an instruction-boundary sidt red-pill store is surfaced for triage (informational): {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_icebp_int_cluster() {
    let payload: Vec<u8> = vec![0x90, 0xCD, 0x2D, 0x90, 0x48, 0xF1, 0x90];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("icebp-cluster"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_hardware_breakpoint_surfaced() {
    let mut payload: Vec<u8> = vec![0xB8, 0x10, 0x00, 0x01, 0x00];
    payload.extend_from_slice(b"GetThreadContext\x00");
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("hwbp"));
    assert!(
        surfaced(&report, Technique::AntiDebug),
        "a context-debug-registers flag immediate is surfaced for triage (informational): {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_anti_disasm_cluster() {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&[0xEB, 0x01, 0xE8]);
    payload.extend_from_slice(&[0xEB, 0x01, 0xE9]);
    payload.extend_from_slice(&[0xEB, 0x01, 0x0F]);
    payload.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), Some("desync-cluster"));
    assert!(
        detects(&report, Technique::AntiDisassembly),
        "a dense jump-into-instruction desync cluster is verdict-grade: {:?}",
        report.findings
    );
}
