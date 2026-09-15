#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_native::stub_emu::cpu::NoopHost;
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Perm, Reg};
use disrobe_pass_native::{
    ReassembledStackString, StackStringRodataWindow, reassemble_stack_strings,
    reassemble_stack_strings_with_rodata,
};
use iced_x86::code_asm::{CodeAssembler, byte_ptr, dword_ptr, rsp};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

const STACK_STRING_C: &str = r"
#include <stdio.h>
__attribute__((noinline))
int emit(volatile char *sink) {
    char buf[32];
    buf[0]='h'; buf[1]='t'; buf[2]='t'; buf[3]='p';
    buf[4]=':'; buf[5]='/'; buf[6]='/'; buf[7]='b';
    buf[8]='a'; buf[9]='d'; buf[10]='.'; buf[11]='h';
    buf[12]='o'; buf[13]='s'; buf[14]='t'; buf[15]=0;
    int total = 0;
    for (int i = 0; i < 16; ++i) { sink[i] = buf[i]; total += buf[i]; }
    return total;
}
int main(void) {
    volatile char out[32];
    return emit(out) & 0x7f;
}
";

fn gcc_available() -> bool {
    Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn extract_text_section(object: &[u8]) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};
    let parsed: object::File<'_> = object::File::parse(object).ok()?;
    for section in parsed.sections() {
        let name: &str = section.name().unwrap_or("");
        if (name == ".text" || name == "text")
            && let Ok(data) = section.data()
            && !data.is_empty()
        {
            return Some(data.to_vec());
        }
    }
    None
}

#[test]
fn recovers_inlined_stack_string_from_gcc_compiled_object() {
    if !gcc_available() {
        println!("SKIP: gcc not on PATH; cannot grade against a real compiler");
        return;
    }
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("stackstr.c");
    std::fs::write(&src, STACK_STRING_C).expect("write C");

    let mut recovered_any: bool = false;
    let mut elf_text_seen: bool = false;
    for opt in ["-O1", "-O2"] {
        let obj: PathBuf = dir.path().join(format!("stackstr{opt}.o"));
        let build: std::process::Output = Command::new("gcc")
            .arg(opt)
            .arg("-fno-stack-protector")
            .arg("-c")
            .arg("-o")
            .arg(&obj)
            .arg(&src)
            .output()
            .expect("invoke gcc");
        if !build.status.success() {
            continue;
        }
        let Ok(object_bytes): Result<Vec<u8>, _> = std::fs::read(&obj) else {
            continue;
        };
        let Some(text): Option<Vec<u8>> = extract_text_section(&object_bytes) else {
            continue;
        };
        elf_text_seen = true;
        let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, 0, &text);
        if strings
            .iter()
            .any(|s: &ReassembledStackString| s.value.contains("http://bad.host"))
        {
            recovered_any = true;
        }
    }
    if !elf_text_seen {
        println!(
            "SKIP: gcc produced no ELF object with a .text section (e.g. a macos mach-o object)"
        );
        return;
    }
    assert!(
        recovered_any,
        "at least one optimization level must lay the URL down as immediate stack stores that \
         disrobe reassembles back to 'http://bad.host'"
    );
}

fn clang_available() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn compile_linux_elf_object(src: &std::path::Path, obj: &std::path::Path, opt: &str) -> bool {
    Command::new("clang")
        .arg("--target=x86_64-unknown-linux-gnu")
        .arg(opt)
        .arg("-fno-stack-protector")
        .arg("-c")
        .arg("-o")
        .arg(obj)
        .arg(src)
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

type RipLiteralWindow = (u64, Vec<u8>);
type ResolvedText = (u64, Vec<u8>, Vec<RipLiteralWindow>);

fn text_with_resolved_rip_literals(object_bytes: &[u8]) -> Option<ResolvedText> {
    let parsed: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let text: object::Section<'_, '_> = parsed
        .sections()
        .find(|s: &object::Section<'_, '_>| s.name().is_ok_and(|n: &str| n == ".text"))?;
    let text_addr: u64 = text.address();
    let text_data: Vec<u8> = text.data().ok()?.to_vec();

    let mut windows: Vec<(u64, Vec<u8>)> = Vec::new();
    for (reloc_off, reloc) in text.relocations() {
        let RelocationTarget::Symbol(sym_idx) = reloc.target() else {
            continue;
        };
        let Ok(symbol) = parsed.symbol_by_index(sym_idx) else {
            continue;
        };
        let object::SymbolSection::Section(target_section_idx) = symbol.section() else {
            continue;
        };
        let Ok(target_section) = parsed.section_by_index(target_section_idx) else {
            continue;
        };
        let Ok(pool) = target_section.data() else {
            continue;
        };
        let literal_addr: u64 = text_addr.wrapping_add(reloc_off).wrapping_add(4);
        let _ = (reloc.addend(), symbol.address());
        windows.push((literal_addr, pool.to_vec()));
    }
    Some((text_addr, text_data, windows))
}

#[test]
fn recovers_sse_block_store_from_real_clang_o1_object() {
    if !clang_available() {
        println!("SKIP: clang not on PATH; cannot grade the SSE lowering against a real compiler");
        return;
    }
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("stackstr.c");
    std::fs::write(&src, STACK_STRING_C).expect("write C");

    let mut graded_any: bool = false;
    let mut recovered_any: bool = false;
    for opt in ["-O0", "-O1", "-O2", "-O3"] {
        let obj: PathBuf = dir.path().join(format!("stackstr{opt}.o"));
        if !compile_linux_elf_object(&src, &obj, opt) {
            continue;
        }
        let Ok(object_bytes): Result<Vec<u8>, _> = std::fs::read(&obj) else {
            continue;
        };
        if object_bytes.get(..4) != Some(&[0x7F, b'E', b'L', b'F']) {
            continue;
        }
        let Some((text_addr, text_data, windows)): Option<ResolvedText> =
            text_with_resolved_rip_literals(&object_bytes)
        else {
            continue;
        };
        graded_any = true;
        let rodata: Vec<StackStringRodataWindow<'_>> = windows
            .iter()
            .map(|(addr, bytes): &(u64, Vec<u8>)| StackStringRodataWindow {
                address: *addr,
                bytes,
            })
            .collect();
        let strings: Vec<ReassembledStackString> =
            reassemble_stack_strings_with_rodata(64, text_addr, &text_data, &rodata);
        if strings
            .iter()
            .any(|s: &ReassembledStackString| s.value.contains("http://bad.host"))
        {
            recovered_any = true;
        }
    }
    if !graded_any {
        println!("SKIP: clang produced no gradable linux ELF object");
        return;
    }
    assert!(
        recovered_any,
        "with the rip-relative const pool resolved from the object's own relocation table, the \
         SSE-lowered build must reassemble the URL; ground truth is the .rodata.cst16 literal"
    );
}

fn assemble64(asm: &mut CodeAssembler) -> Vec<u8> {
    asm.assemble(0x1000).expect("assemble xor-decode stub")
}

#[test]
fn xor_decode_recovery_matches_stub_emu_final_memory() {
    const KEY: u8 = 0x37;
    const STACK_BASE: u64 = 0x2_0000;
    const SLOT: i64 = 0x40;
    let plaintext: &[u8; 12] = b"secret-key-1";
    let mut enc: [u8; 12] = *plaintext;
    for b in &mut enc {
        *b ^= KEY;
    }

    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    for chunk in 0..3usize {
        let word: i32 = i32::from_le_bytes([
            enc[chunk * 4],
            enc[chunk * 4 + 1],
            enc[chunk * 4 + 2],
            enc[chunk * 4 + 3],
        ]);
        asm.mov(dword_ptr(rsp + (SLOT + chunk as i64 * 4)), word)
            .unwrap();
    }
    for i in 0..12i64 {
        asm.xor(byte_ptr(rsp + (SLOT + i)), i32::from(KEY)).unwrap();
    }
    let mut done: iced_x86::code_asm::CodeLabel = asm.create_label();
    asm.set_label(&mut done).unwrap();
    asm.jmp(done).unwrap();
    let code: Vec<u8> = assemble64(&mut asm);

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits64);
    cpu.mem
        .map(0x1000, 0x1000, Perm::RWX)
        .expect("map code page");
    cpu.mem
        .map(STACK_BASE, 0x1000, Perm::RW)
        .expect("map stack page");
    cpu.mem.write_unchecked(0x1000, &code);
    cpu.regs.rip = 0x1000;
    cpu.regs.set(Reg::Rsp, STACK_BASE);
    let exit: ExitReason = cpu.run(&mut NoopHost, 200).expect("emulate decode stub");
    assert!(
        matches!(
            exit,
            ExitReason::StepCap(_) | ExitReason::JumpedOutOfRange { .. }
        ),
        "the self-jmp terminator should park the emulator, got {exit:?}"
    );

    let emulated: Vec<u8> = cpu
        .mem
        .read((STACK_BASE as i64 + SLOT) as u64, 12)
        .expect("read decoded stack bytes");
    let emulated_text: String = String::from_utf8(emulated).expect("emulated bytes are utf8");
    assert_eq!(
        emulated_text, "secret-key-1",
        "sanity: the emulator itself must decode the plaintext into stack memory"
    );

    let strings: Vec<ReassembledStackString> = reassemble_stack_strings(64, 0x1000, &code);
    assert!(
        strings
            .iter()
            .any(|s: &ReassembledStackString| s.value == emulated_text),
        "static store+xor recovery must equal the emulator's final stack memory ({emulated_text:?}); got {strings:?}"
    );
}
