use std::collections::BTreeMap;

use disrobe_core::neutralize::RuntimeCheck;

use crate::error::Result;
use crate::stub_emu::cpu::ReadWatch;
use crate::stub_emu::{Cpu, CpuMode, Memory, Perm};

const KERNEL32_BASE: u64 = 0x7C80_0000;
const NTDLL_BASE: u64 = 0x7C90_0000;
const WINMM_BASE: u64 = 0x7CA0_0000;
const MODULE_IMAGE_SIZE: u64 = 0x0010_0000;

const EXPORT_STUB_BASE: u64 = 0x7D00_0000;
const EXPORT_STUB_STRIDE: u64 = 0x10;

const TEB_BASE: u64 = 0x7EFD_E000;
const TEB_SIZE: u64 = 0x0000_2000;
const PEB_BASE: u64 = 0x7EFD_D000;
const PEB_SIZE: u64 = 0x0000_1000;
const LDR_REGION_BASE: u64 = 0x7EFC_0000;
const LDR_REGION_SIZE: u64 = 0x0000_2000;
const PROCESS_HEAP_BASE: u64 = 0x7EFB_0000;
const PROCESS_HEAP_SIZE: u64 = 0x0000_1000;

const DEFAULT_IMAGE_BASE: u64 = 0x0040_0000;
const HEAP_GROWABLE: u32 = 0x0000_0002;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const PAGE_PROTECT_MODIFIER_MASK: u32 = 0x0000_0700;

const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy)]
struct Layout {
    ptr: u64,
    teb_self: u64,
    teb_peb: u64,
    peb_image_base: u64,
    peb_ldr: u64,
    peb_process_heap: u64,
    peb_nt_global_flag: u64,
    ldr_inload: u64,
    ldr_inmemory: u64,
    ldr_ininit: u64,
    entry_inload: u64,
    entry_inmemory: u64,
    entry_ininit: u64,
    entry_dllbase: u64,
    entry_entrypoint: u64,
    entry_sizeofimage: u64,
    entry_fullname: u64,
    entry_basename: u64,
    entry_stride: u64,
    heap_flags: u64,
    heap_force_flags: u64,
}

const LAYOUT32: Layout = Layout {
    ptr: 4,
    teb_self: 0x18,
    teb_peb: 0x30,
    peb_image_base: 0x08,
    peb_ldr: 0x0C,
    peb_process_heap: 0x18,
    peb_nt_global_flag: 0x68,
    ldr_inload: 0x0C,
    ldr_inmemory: 0x14,
    ldr_ininit: 0x1C,
    entry_inload: 0x00,
    entry_inmemory: 0x08,
    entry_ininit: 0x10,
    entry_dllbase: 0x18,
    entry_entrypoint: 0x1C,
    entry_sizeofimage: 0x20,
    entry_fullname: 0x24,
    entry_basename: 0x2C,
    entry_stride: 0x40,
    heap_flags: 0x40,
    heap_force_flags: 0x44,
};

const LAYOUT64: Layout = Layout {
    ptr: 8,
    teb_self: 0x30,
    teb_peb: 0x60,
    peb_image_base: 0x10,
    peb_ldr: 0x18,
    peb_process_heap: 0x30,
    peb_nt_global_flag: 0xBC,
    ldr_inload: 0x10,
    ldr_inmemory: 0x20,
    ldr_ininit: 0x30,
    entry_inload: 0x00,
    entry_inmemory: 0x10,
    entry_ininit: 0x20,
    entry_dllbase: 0x30,
    entry_entrypoint: 0x38,
    entry_sizeofimage: 0x40,
    entry_fullname: 0x48,
    entry_basename: 0x58,
    entry_stride: 0x100,
    heap_flags: 0x70,
    heap_force_flags: 0x74,
};

const fn layout_for(mode: CpuMode) -> Layout {
    match mode {
        CpuMode::Bits32 => LAYOUT32,
        CpuMode::Bits64 => LAYOUT64,
    }
}

#[must_use]
pub fn perm_from_page_protect(flags: u32) -> Perm {
    match flags & !PAGE_PROTECT_MODIFIER_MASK {
        PAGE_NOACCESS => Perm::default(),
        PAGE_READONLY => Perm::R,
        PAGE_READWRITE | PAGE_WRITECOPY => Perm::RW,
        PAGE_EXECUTE | PAGE_EXECUTE_READ => Perm::RX,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => Perm::RWX,
        _ => Perm::RW,
    }
}

#[must_use]
pub fn page_protect_from_perm(perm: Perm) -> u32 {
    match (perm.read, perm.write, perm.execute) {
        (false, false, false) => PAGE_NOACCESS,
        (_, false, false) => PAGE_READONLY,
        (_, true, false) => PAGE_READWRITE,
        (_, false, true) => PAGE_EXECUTE_READ,
        (_, true, true) => PAGE_EXECUTE_READWRITE,
    }
}

#[must_use]
pub fn perm_from_section_characteristics(characteristics: u32) -> Perm {
    Perm {
        read: characteristics & SCN_MEM_READ != 0,
        write: characteristics & SCN_MEM_WRITE != 0,
        execute: characteristics & SCN_MEM_EXECUTE != 0,
    }
}

const KERNEL32_EXPORTS: &[&str] = &[
    "AddVectoredExceptionHandler",
    "CheckRemoteDebuggerPresent",
    "CloseHandle",
    "CreateFileA",
    "CreateFileW",
    "ExitProcess",
    "FreeLibrary",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "GetLastError",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetProcAddress",
    "GetProcessHeap",
    "GetTickCount",
    "GetTickCount64",
    "GlobalAlloc",
    "GlobalFree",
    "GlobalReAlloc",
    "HeapAlloc",
    "HeapCreate",
    "HeapFree",
    "HeapReAlloc",
    "IsBadReadPtr",
    "IsDebuggerPresent",
    "LoadLibraryA",
    "LoadLibraryW",
    "LocalAlloc",
    "LocalFree",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "RemoveVectoredExceptionHandler",
    "SetLastError",
    "Sleep",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "VirtualQuery",
    "WriteFile",
];

const NTDLL_EXPORTS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "RtlAddVectoredExceptionHandler",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "RtlRemoveVectoredExceptionHandler",
    "ZwQueryInformationProcess",
    "ZwSetInformationThread",
];

const WINMM_EXPORTS: &[&str] = &["timeGetTime"];

#[derive(Debug, Clone)]
pub struct SyntheticWindows {
    exports_by_addr: BTreeMap<u64, &'static str>,
    exports_by_name: BTreeMap<&'static str, u64>,
    module_bases: BTreeMap<&'static str, u64>,
    mode: CpuMode,
}

impl SyntheticWindows {
    #[must_use]
    pub fn export_addr(&self, name: &str) -> Option<u64> {
        self.exports_by_name.get(name).copied()
    }

    #[must_use]
    pub fn symbol_for(&self, addr: u64) -> Option<&'static str> {
        self.exports_by_addr.get(&addr).copied()
    }

    #[must_use]
    pub fn is_export_stub(&self, addr: u64) -> bool {
        self.exports_by_addr.contains_key(&addr)
    }

    #[must_use]
    pub fn module_base(&self, dll_name: &str) -> Option<u64> {
        let lower: String = dll_name.to_ascii_lowercase();
        self.module_bases.get(lower.as_str()).copied()
    }

    #[must_use]
    pub const fn mode(&self) -> CpuMode {
        self.mode
    }

    #[must_use]
    pub const fn peb_base(&self) -> u64 {
        PEB_BASE
    }

    #[must_use]
    pub const fn teb_base(&self) -> u64 {
        TEB_BASE
    }

    pub fn resolve_export_by_name_ptr(&self, mem: &Memory, name_ptr: u64) -> Option<u64> {
        let name: String = read_cstr(mem, name_ptr, 128)?;
        self.export_addr(&name)
    }
}

pub fn install_synthetic_windows(cpu: &mut Cpu) -> Result<SyntheticWindows> {
    install_synthetic_windows_for_image(cpu, DEFAULT_IMAGE_BASE)
}

pub fn install_synthetic_windows_for_image(
    cpu: &mut Cpu,
    image_base: u64,
) -> Result<SyntheticWindows> {
    let mode: CpuMode = cpu.mode;
    let mut exports_by_addr: BTreeMap<u64, &'static str> = BTreeMap::new();
    let mut exports_by_name: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut next_stub: u64 = EXPORT_STUB_BASE;

    let kernel32_stubs: Vec<(&'static str, u64)> = assign_stubs(
        KERNEL32_EXPORTS,
        &mut next_stub,
        &mut exports_by_addr,
        &mut exports_by_name,
    );
    let ntdll_stubs: Vec<(&'static str, u64)> = assign_stubs(
        NTDLL_EXPORTS,
        &mut next_stub,
        &mut exports_by_addr,
        &mut exports_by_name,
    );
    let winmm_stubs: Vec<(&'static str, u64)> = assign_stubs(
        WINMM_EXPORTS,
        &mut next_stub,
        &mut exports_by_addr,
        &mut exports_by_name,
    );

    map_module_image(cpu, mode, NTDLL_BASE, &ntdll_stubs)?;
    map_module_image(cpu, mode, KERNEL32_BASE, &kernel32_stubs)?;
    map_module_image(cpu, mode, WINMM_BASE, &winmm_stubs)?;

    map_teb_peb_ldr(cpu, mode, image_base)?;

    let module_bases: BTreeMap<&'static str, u64> = BTreeMap::from([
        ("ntdll.dll", NTDLL_BASE),
        ("kernel32.dll", KERNEL32_BASE),
        ("kernelbase.dll", KERNEL32_BASE),
        ("winmm.dll", WINMM_BASE),
    ]);

    Ok(SyntheticWindows {
        exports_by_addr,
        exports_by_name,
        module_bases,
        mode,
    })
}

fn assign_stubs(
    names: &[&'static str],
    next_stub: &mut u64,
    by_addr: &mut BTreeMap<u64, &'static str>,
    by_name: &mut BTreeMap<&'static str, u64>,
) -> Vec<(&'static str, u64)> {
    let mut out: Vec<(&'static str, u64)> = Vec::with_capacity(names.len());
    for name in names {
        let addr: u64 = *next_stub;
        *next_stub += EXPORT_STUB_STRIDE;
        by_addr.insert(addr, name);
        by_name.insert(name, addr);
        out.push((name, addr));
    }
    out
}

fn poke_bytes(mem: &mut Memory, addr: u64, bytes: &[u8]) {
    mem.write_unchecked(addr, bytes);
}

fn poke_u16(mem: &mut Memory, addr: u64, value: u16) {
    mem.write_unchecked(addr, &value.to_le_bytes());
}

fn poke_u32(mem: &mut Memory, addr: u64, value: u32) {
    mem.write_unchecked(addr, &value.to_le_bytes());
}

fn poke_u64(mem: &mut Memory, addr: u64, value: u64) {
    mem.write_unchecked(addr, &value.to_le_bytes());
}

fn poke_ptr(mem: &mut Memory, mode: CpuMode, addr: u64, value: u64) {
    match mode {
        CpuMode::Bits32 => poke_u32(mem, addr, value as u32),
        CpuMode::Bits64 => poke_u64(mem, addr, value),
    }
}

fn map_module_image(
    cpu: &mut Cpu,
    mode: CpuMode,
    base: u64,
    stubs: &[(&'static str, u64)],
) -> Result<()> {
    cpu.mem.map(base, MODULE_IMAGE_SIZE, Perm::RX)?;
    let mem: &mut Memory = &mut cpu.mem;

    let e_lfanew: u32 = 0x80;
    poke_bytes(mem, base, b"MZ");
    poke_u32(mem, base + 0x3C, e_lfanew);

    let pe: u64 = base + u64::from(e_lfanew);
    poke_bytes(mem, pe, b"PE\x00\x00");
    let coff: u64 = pe + 4;
    let (machine, opt_hdr_size, opt_magic): (u16, u16, u16) = match mode {
        CpuMode::Bits32 => (0x014C, 0xE0, 0x010B),
        CpuMode::Bits64 => (0x8664, 0xF0, 0x020B),
    };
    poke_u16(mem, coff, machine);
    poke_u16(mem, coff + 2, 1);
    poke_u16(mem, coff + 16, opt_hdr_size);
    poke_u16(mem, coff + 18, 0x210E);

    let opt: u64 = coff + 20;
    poke_u16(mem, opt, opt_magic);
    match mode {
        CpuMode::Bits32 => poke_u32(mem, opt + 28, base as u32),
        CpuMode::Bits64 => poke_u64(mem, opt + 24, base),
    }
    poke_u32(mem, opt + 56, MODULE_IMAGE_SIZE as u32);
    poke_u32(mem, opt + 60, 0x400);
    let (dir_count_off, export_dir_off): (u64, u64) = match mode {
        CpuMode::Bits32 => (92, 96),
        CpuMode::Bits64 => (108, 112),
    };
    poke_u32(mem, opt + dir_count_off, 16);

    let export_rva: u32 = 0x1000;
    let export_size: u32 = build_export_directory(mem, base, export_rva, stubs);
    poke_u32(mem, opt + export_dir_off, export_rva);
    poke_u32(mem, opt + export_dir_off + 4, export_size);

    let sec: u64 = opt + u64::from(opt_hdr_size);
    poke_bytes(mem, sec, b".text\x00\x00\x00");
    poke_u32(mem, sec + 8, MODULE_IMAGE_SIZE as u32 - 0x1000);
    poke_u32(mem, sec + 12, 0x1000);
    poke_u32(mem, sec + 16, MODULE_IMAGE_SIZE as u32 - 0x1000);
    poke_u32(mem, sec + 20, 0x1000);
    poke_u32(mem, sec + 36, 0x6000_0020);

    Ok(())
}

fn build_export_directory(
    mem: &mut Memory,
    base: u64,
    export_rva: u32,
    stubs: &[(&'static str, u64)],
) -> u32 {
    let count: u32 = stubs.len() as u32;
    let dir: u64 = base + u64::from(export_rva);

    let func_array_rva: u32 = export_rva + 0x28;
    let name_array_rva: u32 = func_array_rva + count * 4;
    let ordinal_array_rva: u32 = name_array_rva + count * 4;
    let name_strings_rva: u32 = ordinal_array_rva + count * 2;

    let mut sorted: Vec<(&'static str, u64)> = stubs.to_vec();
    sorted.sort_by(|a: &(&'static str, u64), b: &(&'static str, u64)| a.0.cmp(b.0));

    let dll_name_rva: u32 = name_strings_rva;
    let mut cursor: u32 = name_strings_rva;
    poke_bytes(mem, base + u64::from(cursor), b"synth.dll\x00");
    cursor += 10;

    let mut name_rvas: Vec<u32> = Vec::with_capacity(sorted.len());
    for (name, _addr) in &sorted {
        name_rvas.push(cursor);
        poke_bytes(mem, base + u64::from(cursor), name.as_bytes());
        poke_bytes(mem, base + u64::from(cursor) + name.len() as u64, &[0u8]);
        cursor += name.len() as u32 + 1;
    }

    poke_u32(mem, dir, 0);
    poke_u32(mem, dir + 4, 0);
    poke_u32(mem, dir + 8, 0);
    poke_u32(mem, dir + 12, dll_name_rva);
    poke_u32(mem, dir + 16, 1);
    poke_u32(mem, dir + 20, count);
    poke_u32(mem, dir + 24, count);
    poke_u32(mem, dir + 28, func_array_rva);
    poke_u32(mem, dir + 32, name_array_rva);
    poke_u32(mem, dir + 36, ordinal_array_rva);

    for (i, (_name, addr)) in sorted.iter().enumerate() {
        let func_rva: u32 = addr.wrapping_sub(base) as u32;
        poke_u32(
            mem,
            base + u64::from(func_array_rva) + i as u64 * 4,
            func_rva,
        );
        poke_u32(
            mem,
            base + u64::from(name_array_rva) + i as u64 * 4,
            name_rvas[i],
        );
        poke_u16(
            mem,
            base + u64::from(ordinal_array_rva) + i as u64 * 2,
            i as u16,
        );
    }

    cursor - export_rva
}

fn map_teb_peb_ldr(cpu: &mut Cpu, mode: CpuMode, image_base: u64) -> Result<()> {
    let l: Layout = layout_for(mode);
    cpu.mem.map(TEB_BASE, TEB_SIZE, Perm::RW)?;
    cpu.mem.map(PEB_BASE, PEB_SIZE, Perm::RW)?;
    cpu.mem.map(LDR_REGION_BASE, LDR_REGION_SIZE, Perm::RW)?;
    cpu.mem
        .map(PROCESS_HEAP_BASE, PROCESS_HEAP_SIZE, Perm::RW)?;

    let mem: &mut Memory = &mut cpu.mem;
    poke_ptr(mem, mode, TEB_BASE, 0xFFFF_FFFF);
    poke_ptr(mem, mode, TEB_BASE + l.teb_self, TEB_BASE);
    poke_ptr(mem, mode, TEB_BASE + l.teb_peb, PEB_BASE);

    poke_bytes(mem, PEB_BASE + 2, &[0u8]);
    poke_ptr(mem, mode, PEB_BASE + l.peb_image_base, image_base);
    poke_ptr(mem, mode, PEB_BASE + l.peb_process_heap, PROCESS_HEAP_BASE);
    poke_u32(mem, PEB_BASE + l.peb_nt_global_flag, 0);
    poke_u32(mem, PROCESS_HEAP_BASE + l.heap_flags, HEAP_GROWABLE);
    poke_u32(mem, PROCESS_HEAP_BASE + l.heap_force_flags, 0);

    let ldr_data: u64 = LDR_REGION_BASE;
    poke_ptr(mem, mode, PEB_BASE + l.peb_ldr, ldr_data);
    poke_u32(mem, ldr_data, 0x30);
    poke_u32(mem, ldr_data + 4, 1);

    let entries_base: u64 = LDR_REGION_BASE + 0x100;
    let modules: [(u64, &str); 3] = [
        (NTDLL_BASE, "ntdll.dll"),
        (KERNEL32_BASE, "kernel32.dll"),
        (WINMM_BASE, "winmm.dll"),
    ];
    let mut entry_addrs: Vec<u64> = Vec::with_capacity(modules.len());
    for i in 0..modules.len() {
        entry_addrs.push(entries_base + i as u64 * l.entry_stride);
    }

    let names_base: u64 = LDR_REGION_BASE + 0x1000;
    let mut name_cursor: u64 = names_base;

    for (i, (dll_base, name)) in modules.iter().enumerate() {
        let entry: u64 = entry_addrs[i];
        poke_ptr(mem, mode, entry + l.entry_dllbase, *dll_base);
        poke_ptr(mem, mode, entry + l.entry_entrypoint, 0);
        poke_u32(mem, entry + l.entry_sizeofimage, MODULE_IMAGE_SIZE as u32);

        let utf16: Vec<u16> = name.encode_utf16().collect();
        let byte_len: u16 = (utf16.len() * 2) as u16;
        let buf: u64 = name_cursor;
        for (k, unit) in utf16.iter().enumerate() {
            poke_u16(mem, buf + k as u64 * 2, *unit);
        }
        poke_u16(mem, buf + utf16.len() as u64 * 2, 0);
        name_cursor += utf16.len() as u64 * 2 + 2;

        for field in [l.entry_basename, l.entry_fullname] {
            poke_u16(mem, entry + field, byte_len);
            poke_u16(mem, entry + field + 2, byte_len + 2);
            poke_ptr(mem, mode, entry + field + l.ptr, buf);
        }
    }

    link_module_list(
        mem,
        mode,
        ldr_data + l.ldr_inload,
        &entry_addrs,
        l.entry_inload,
    );
    link_module_list(
        mem,
        mode,
        ldr_data + l.ldr_inmemory,
        &entry_addrs,
        l.entry_inmemory,
    );
    link_module_list(
        mem,
        mode,
        ldr_data + l.ldr_ininit,
        &entry_addrs,
        l.entry_ininit,
    );

    for watch in [
        ReadWatch {
            start: PEB_BASE + 2,
            len: 1,
            check: RuntimeCheck::PebBeingDebugged,
            field: "PEB.BeingDebugged",
        },
        ReadWatch {
            start: PEB_BASE + l.peb_nt_global_flag,
            len: 4,
            check: RuntimeCheck::PebNtGlobalFlag,
            field: "PEB.NtGlobalFlag",
        },
        ReadWatch {
            start: PROCESS_HEAP_BASE + l.heap_flags,
            len: 4,
            check: RuntimeCheck::HeapFlags,
            field: "ProcessHeap.Flags",
        },
        ReadWatch {
            start: PROCESS_HEAP_BASE + l.heap_force_flags,
            len: 4,
            check: RuntimeCheck::HeapFlags,
            field: "ProcessHeap.ForceFlags",
        },
    ] {
        let _ = cpu.watch_read(watch);
    }
    match mode {
        CpuMode::Bits32 => cpu.set_fs_base(TEB_BASE),
        CpuMode::Bits64 => cpu.set_gs_base(TEB_BASE),
    }
    Ok(())
}

fn link_module_list(
    mem: &mut Memory,
    mode: CpuMode,
    list_head: u64,
    entry_addrs: &[u64],
    link_offset: u64,
) {
    let ptr: u64 = layout_for(mode).ptr;
    let links: Vec<u64> = entry_addrs.iter().map(|e: &u64| *e + link_offset).collect();
    let n: usize = links.len();
    for i in 0..n {
        let flink: u64 = if i + 1 < n { links[i + 1] } else { list_head };
        let blink: u64 = if i == 0 { list_head } else { links[i - 1] };
        poke_ptr(mem, mode, links[i], flink);
        poke_ptr(mem, mode, links[i] + ptr, blink);
    }
    let head_flink: u64 = if n > 0 { links[0] } else { list_head };
    let head_blink: u64 = if n > 0 { links[n - 1] } else { list_head };
    poke_ptr(mem, mode, list_head, head_flink);
    poke_ptr(mem, mode, list_head + ptr, head_blink);
}

pub(crate) fn read_cstr(mem: &Memory, addr: u64, cap: usize) -> Option<String> {
    let mut bytes: Vec<u8> = Vec::with_capacity(cap.min(256));
    for i in 0..cap {
        let b: u8 = mem.read_u8(addr.wrapping_add(i as u64)).ok()?;
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(&bytes).ok().map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn read_ptr(mem: &Memory, mode: CpuMode, addr: u64) -> u64 {
        match mode {
            CpuMode::Bits32 => u64::from(mem.read_u32(addr).unwrap()),
            CpuMode::Bits64 => mem.read_u64(addr).unwrap(),
        }
    }

    fn read_unicode_base_name(mem: &Memory, mode: CpuMode, entry: u64) -> String {
        let l: Layout = layout_for(mode);
        let len: u16 = mem.read_u16(entry + l.entry_basename).unwrap();
        let buf: u64 = read_ptr(mem, mode, entry + l.entry_basename + l.ptr);
        let mut units: Vec<u16> = Vec::new();
        for k in 0..(len as u64 / 2) {
            units.push(mem.read_u16(buf + k * 2).unwrap());
        }
        String::from_utf16(&units).unwrap()
    }

    fn walk_finds_kernel32(mode: CpuMode) {
        let l: Layout = layout_for(mode);
        let mut cpu: Cpu = Cpu::new(mode);
        install_synthetic_windows(&mut cpu).unwrap();

        let peb: u64 = read_ptr(&cpu.mem, mode, TEB_BASE + l.teb_peb);
        assert_eq!(peb, PEB_BASE);
        let ldr: u64 = read_ptr(&cpu.mem, mode, peb + l.peb_ldr);
        assert_eq!(ldr, LDR_REGION_BASE);

        let head: u64 = ldr + l.ldr_inload;
        let mut cur: u64 = read_ptr(&cpu.mem, mode, head);
        let mut found_kernel32: bool = false;
        let mut walked: u32 = 0;
        while cur != head && walked < 8 {
            let entry: u64 = cur - l.entry_inload;
            let name: String = read_unicode_base_name(&cpu.mem, mode, entry);
            if name.eq_ignore_ascii_case("kernel32.dll") {
                let dll_base: u64 = read_ptr(&cpu.mem, mode, entry + l.entry_dllbase);
                assert_eq!(dll_base, KERNEL32_BASE);
                found_kernel32 = true;
            }
            cur = read_ptr(&cpu.mem, mode, cur);
            walked += 1;
        }
        assert!(
            found_kernel32,
            "kernel32.dll must be reachable via InLoadOrderModuleList in {mode:?}"
        );
    }

    #[test]
    fn peb_ldr_chain_finds_kernel32_by_base_name() {
        walk_finds_kernel32(CpuMode::Bits32);
    }

    #[test]
    fn peb_ldr_chain_finds_kernel32_by_base_name_in_64_bit_layout() {
        walk_finds_kernel32(CpuMode::Bits64);
    }

    #[test]
    fn peb_reads_not_debugged_in_both_layouts() {
        for mode in [CpuMode::Bits32, CpuMode::Bits64] {
            let l: Layout = layout_for(mode);
            let mut cpu: Cpu = Cpu::new(mode);
            let env: SyntheticWindows =
                install_synthetic_windows_for_image(&mut cpu, 0x0040_0000).unwrap();
            assert_eq!(
                cpu.mem.read_u8(env.peb_base() + 2).unwrap(),
                0,
                "BeingDebugged"
            );
            assert_eq!(
                cpu.mem
                    .read_u32(env.peb_base() + l.peb_nt_global_flag)
                    .unwrap(),
                0,
                "NtGlobalFlag"
            );
            let heap: u64 = read_ptr(&cpu.mem, mode, env.peb_base() + l.peb_process_heap);
            assert_eq!(
                cpu.mem.read_u32(heap + l.heap_flags).unwrap(),
                HEAP_GROWABLE
            );
            assert_eq!(cpu.mem.read_u32(heap + l.heap_force_flags).unwrap(), 0);
            assert_eq!(
                read_ptr(&cpu.mem, mode, env.peb_base() + l.peb_image_base),
                0x0040_0000
            );
        }
    }

    fn export_directory_resolves(mode: CpuMode, wanted: &str) {
        let mut cpu: Cpu = Cpu::new(mode);
        let env: SyntheticWindows = install_synthetic_windows(&mut cpu).unwrap();

        let e_lfanew: u64 = u64::from(cpu.mem.read_u32(KERNEL32_BASE + 0x3C).unwrap());
        let opt: u64 = KERNEL32_BASE + e_lfanew + 4 + 20;
        let export_dir_off: u64 = match mode {
            CpuMode::Bits32 => 96,
            CpuMode::Bits64 => 112,
        };
        let exp_rva: u64 = u64::from(cpu.mem.read_u32(opt + export_dir_off).unwrap());
        let dir: u64 = KERNEL32_BASE + exp_rva;
        let count: u32 = cpu.mem.read_u32(dir + 24).unwrap();
        let funcs: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 28).unwrap());
        let names: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 32).unwrap());
        let ordinals: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 36).unwrap());

        let mut resolved: Option<u64> = None;
        for i in 0..count {
            let name_rva: u64 = u64::from(cpu.mem.read_u32(names + u64::from(i) * 4).unwrap());
            let name: String = read_cstr(&cpu.mem, KERNEL32_BASE + name_rva, 64).unwrap();
            if name == wanted {
                let ord: u16 = cpu.mem.read_u16(ordinals + u64::from(i) * 2).unwrap();
                let func_rva: u64 =
                    u64::from(cpu.mem.read_u32(funcs + u64::from(ord) * 4).unwrap());
                resolved = Some(KERNEL32_BASE + func_rva);
            }
        }
        let addr: u64 = resolved.unwrap_or_else(|| panic!("{wanted} must be exported"));
        assert_eq!(addr, env.export_addr(wanted).unwrap());
        assert_eq!(env.symbol_for(addr), Some(wanted));
    }

    #[test]
    fn export_directory_parses_to_stub_addresses() {
        export_directory_resolves(CpuMode::Bits32, "GetProcAddress");
    }

    #[test]
    fn anti_debug_exports_are_reachable_through_the_export_directory() {
        for name in [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "GetTickCount",
            "QueryPerformanceCounter",
            "AddVectoredExceptionHandler",
            "OutputDebugStringA",
        ] {
            export_directory_resolves(CpuMode::Bits32, name);
            export_directory_resolves(CpuMode::Bits64, name);
        }
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        let env: SyntheticWindows = install_synthetic_windows(&mut cpu).unwrap();
        for name in [
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "timeGetTime",
        ] {
            assert!(env.export_addr(name).is_some(), "{name}");
        }
        assert_eq!(env.module_base("KERNEL32.DLL"), Some(KERNEL32_BASE));
        assert_eq!(env.module_base("winmm.dll"), Some(WINMM_BASE));
    }
}
