use std::collections::BTreeMap;

use crate::error::Result;
use crate::stub_emu::{Cpu, Memory, Perm};

const KERNEL32_BASE: u64 = 0x7C80_0000;
const NTDLL_BASE: u64 = 0x7C90_0000;
const MODULE_IMAGE_SIZE: u64 = 0x0010_0000;

const EXPORT_STUB_BASE: u64 = 0x7D00_0000;
const EXPORT_STUB_STRIDE: u64 = 0x10;

const TEB_BASE: u64 = 0x7EFD_E000;
const TEB_SIZE: u64 = 0x0000_2000;
const PEB_BASE: u64 = 0x7EFD_D000;
const PEB_SIZE: u64 = 0x0000_1000;
const LDR_REGION_BASE: u64 = 0x7EFC_0000;
const LDR_REGION_SIZE: u64 = 0x0000_2000;

const TEB_SELF_OFFSET: u64 = 0x18;
const TEB_PEB_OFFSET: u64 = 0x30;
const PEB_LDR_OFFSET: u64 = 0x0C;

const PEB_LDR_INLOAD_OFFSET: u64 = 0x0C;
const PEB_LDR_INMEMORY_OFFSET: u64 = 0x14;
const PEB_LDR_ININIT_OFFSET: u64 = 0x1C;

const LDR_ENTRY_INLOAD: u64 = 0x00;
const LDR_ENTRY_INMEMORY: u64 = 0x08;
const LDR_ENTRY_ININIT: u64 = 0x10;
const LDR_ENTRY_DLLBASE: u64 = 0x18;
const LDR_ENTRY_ENTRYPOINT: u64 = 0x1C;
const LDR_ENTRY_SIZEOFIMAGE: u64 = 0x20;
const LDR_ENTRY_FULLNAME: u64 = 0x24;
const LDR_ENTRY_BASENAME: u64 = 0x2C;
const LDR_ENTRY_STRIDE: u64 = 0x40;

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
    "CloseHandle",
    "CreateFileA",
    "CreateFileW",
    "ExitProcess",
    "FreeLibrary",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetLastError",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetProcAddress",
    "GetProcessHeap",
    "GlobalAlloc",
    "GlobalFree",
    "GlobalReAlloc",
    "HeapAlloc",
    "HeapCreate",
    "HeapFree",
    "HeapReAlloc",
    "IsBadReadPtr",
    "LoadLibraryA",
    "LoadLibraryW",
    "LocalAlloc",
    "LocalFree",
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
    "RtlAllocateHeap",
    "RtlFreeHeap",
];

#[derive(Debug, Clone)]
pub struct SyntheticWindows {
    exports_by_addr: BTreeMap<u64, &'static str>,
    exports_by_name: BTreeMap<&'static str, u64>,
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

    pub fn resolve_export_by_name_ptr(&self, mem: &Memory, name_ptr: u64) -> Option<u64> {
        let name: String = read_cstr(mem, name_ptr, 128)?;
        self.export_addr(&name)
    }
}

pub fn install_synthetic_windows(cpu: &mut Cpu) -> Result<SyntheticWindows> {
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

    map_module_image(cpu, NTDLL_BASE, &ntdll_stubs)?;
    map_module_image(cpu, KERNEL32_BASE, &kernel32_stubs)?;

    map_teb_peb_ldr(cpu)?;

    Ok(SyntheticWindows {
        exports_by_addr,
        exports_by_name,
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

fn map_module_image(cpu: &mut Cpu, base: u64, stubs: &[(&'static str, u64)]) -> Result<()> {
    cpu.mem.map(base, MODULE_IMAGE_SIZE, Perm::RX)?;
    let mem: &mut Memory = &mut cpu.mem;

    let e_lfanew: u32 = 0x80;
    poke_bytes(mem, base, b"MZ");
    poke_u32(mem, base + 0x3C, e_lfanew);

    let pe: u64 = base + u64::from(e_lfanew);
    poke_bytes(mem, pe, b"PE\x00\x00");
    let coff: u64 = pe + 4;
    poke_u16(mem, coff, 0x014C);
    poke_u16(mem, coff + 2, 1);
    let opt_hdr_size: u16 = 0xE0;
    poke_u16(mem, coff + 16, opt_hdr_size);
    poke_u16(mem, coff + 18, 0x210E);

    let opt: u64 = coff + 20;
    poke_u16(mem, opt, 0x010B);
    poke_u32(mem, opt + 28, base as u32);
    poke_u32(mem, opt + 56, MODULE_IMAGE_SIZE as u32);
    poke_u32(mem, opt + 60, 0x400);
    poke_u32(mem, opt + 92, 16);

    let export_rva: u32 = 0x1000;
    let export_size: u32 = build_export_directory(mem, base, export_rva, stubs);
    poke_u32(mem, opt + 96, export_rva);
    poke_u32(mem, opt + 100, export_size);

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

fn map_teb_peb_ldr(cpu: &mut Cpu) -> Result<()> {
    cpu.mem.map(TEB_BASE, TEB_SIZE, Perm::RW)?;
    cpu.mem.map(PEB_BASE, PEB_SIZE, Perm::RW)?;
    cpu.mem.map(LDR_REGION_BASE, LDR_REGION_SIZE, Perm::RW)?;

    cpu.mem.write_u32(TEB_BASE, 0xFFFF_FFFF)?;
    cpu.mem
        .write_u32(TEB_BASE + TEB_SELF_OFFSET, TEB_BASE as u32)?;
    cpu.mem
        .write_u32(TEB_BASE + TEB_PEB_OFFSET, PEB_BASE as u32)?;

    let ldr_data: u64 = LDR_REGION_BASE;
    cpu.mem
        .write_u32(PEB_BASE + PEB_LDR_OFFSET, ldr_data as u32)?;
    cpu.mem.write_u32(ldr_data, 0x30)?;
    cpu.mem.write_u32(ldr_data + 4, 1)?;

    let entries_base: u64 = LDR_REGION_BASE + 0x100;
    let modules: [(u64, &str); 2] = [(NTDLL_BASE, "ntdll.dll"), (KERNEL32_BASE, "kernel32.dll")];
    let mut entry_addrs: Vec<u64> = Vec::with_capacity(modules.len());
    for i in 0..modules.len() {
        entry_addrs.push(entries_base + i as u64 * LDR_ENTRY_STRIDE);
    }

    let names_base: u64 = LDR_REGION_BASE + 0x800;
    let mut name_cursor: u64 = names_base;

    for (i, (dll_base, name)) in modules.iter().enumerate() {
        let entry: u64 = entry_addrs[i];
        cpu.mem
            .write_u32(entry + LDR_ENTRY_DLLBASE, *dll_base as u32)?;
        cpu.mem.write_u32(entry + LDR_ENTRY_ENTRYPOINT, 0)?;
        cpu.mem
            .write_u32(entry + LDR_ENTRY_SIZEOFIMAGE, MODULE_IMAGE_SIZE as u32)?;

        let utf16: Vec<u16> = name.encode_utf16().collect();
        let byte_len: u16 = (utf16.len() * 2) as u16;
        let buf: u64 = name_cursor;
        for (k, unit) in utf16.iter().enumerate() {
            cpu.mem.write_u16(buf + k as u64 * 2, *unit)?;
        }
        cpu.mem.write_u16(buf + utf16.len() as u64 * 2, 0)?;
        name_cursor += utf16.len() as u64 * 2 + 2;

        cpu.mem.write_u16(entry + LDR_ENTRY_BASENAME, byte_len)?;
        cpu.mem
            .write_u16(entry + LDR_ENTRY_BASENAME + 2, byte_len + 2)?;
        cpu.mem
            .write_u32(entry + LDR_ENTRY_BASENAME + 4, buf as u32)?;
        cpu.mem.write_u16(entry + LDR_ENTRY_FULLNAME, byte_len)?;
        cpu.mem
            .write_u16(entry + LDR_ENTRY_FULLNAME + 2, byte_len + 2)?;
        cpu.mem
            .write_u32(entry + LDR_ENTRY_FULLNAME + 4, buf as u32)?;
    }

    link_module_list(
        cpu,
        ldr_data + PEB_LDR_INLOAD_OFFSET,
        &entry_addrs,
        LDR_ENTRY_INLOAD,
    )?;
    link_module_list(
        cpu,
        ldr_data + PEB_LDR_INMEMORY_OFFSET,
        &entry_addrs,
        LDR_ENTRY_INMEMORY,
    )?;
    link_module_list(
        cpu,
        ldr_data + PEB_LDR_ININIT_OFFSET,
        &entry_addrs,
        LDR_ENTRY_ININIT,
    )?;

    cpu.set_fs_base(TEB_BASE);
    Ok(())
}

fn link_module_list(
    cpu: &mut Cpu,
    list_head: u64,
    entry_addrs: &[u64],
    link_offset: u64,
) -> Result<()> {
    let links: Vec<u64> = entry_addrs.iter().map(|e: &u64| *e + link_offset).collect();
    let n: usize = links.len();
    for i in 0..n {
        let flink: u64 = if i + 1 < n { links[i + 1] } else { list_head };
        let blink: u64 = if i == 0 { list_head } else { links[i - 1] };
        cpu.mem.write_u32(links[i], flink as u32)?;
        cpu.mem.write_u32(links[i] + 4, blink as u32)?;
    }
    let head_flink: u64 = if n > 0 { links[0] } else { list_head };
    let head_blink: u64 = if n > 0 { links[n - 1] } else { list_head };
    cpu.mem.write_u32(list_head, head_flink as u32)?;
    cpu.mem.write_u32(list_head + 4, head_blink as u32)?;
    Ok(())
}

fn read_cstr(mem: &Memory, addr: u64, cap: usize) -> Option<String> {
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
    use crate::stub_emu::CpuMode;

    fn read_unicode_base_name(mem: &Memory, entry: u64) -> String {
        let len: u16 = mem.read_u16(entry + LDR_ENTRY_BASENAME).unwrap();
        let buf: u64 = u64::from(mem.read_u32(entry + LDR_ENTRY_BASENAME + 4).unwrap());
        let mut units: Vec<u16> = Vec::new();
        for k in 0..(len as u64 / 2) {
            units.push(mem.read_u16(buf + k * 2).unwrap());
        }
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn peb_ldr_chain_finds_kernel32_by_base_name() {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        let env: SyntheticWindows = install_synthetic_windows(&mut cpu).unwrap();

        let peb: u64 = u64::from(cpu.mem.read_u32(TEB_BASE + TEB_PEB_OFFSET).unwrap());
        assert_eq!(peb, PEB_BASE);
        let ldr: u64 = u64::from(cpu.mem.read_u32(peb + PEB_LDR_OFFSET).unwrap());
        assert_eq!(ldr, LDR_REGION_BASE);

        let head: u64 = ldr + PEB_LDR_INLOAD_OFFSET;
        let mut cur: u64 = u64::from(cpu.mem.read_u32(head).unwrap());
        let mut found_kernel32: bool = false;
        let mut walked: u32 = 0;
        while cur != head && walked < 8 {
            let entry: u64 = cur - LDR_ENTRY_INLOAD;
            let name: String = read_unicode_base_name(&cpu.mem, entry);
            if name.eq_ignore_ascii_case("kernel32.dll") {
                let dll_base: u64 = u64::from(cpu.mem.read_u32(entry + LDR_ENTRY_DLLBASE).unwrap());
                assert_eq!(dll_base, KERNEL32_BASE);
                found_kernel32 = true;
            }
            cur = u64::from(cpu.mem.read_u32(cur).unwrap());
            walked += 1;
        }
        assert!(
            found_kernel32,
            "kernel32.dll must be reachable via InLoadOrderModuleList"
        );
        let _ = env;
    }

    #[test]
    fn export_directory_parses_to_stub_addresses() {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        let env: SyntheticWindows = install_synthetic_windows(&mut cpu).unwrap();

        let e_lfanew: u64 = u64::from(cpu.mem.read_u32(KERNEL32_BASE + 0x3C).unwrap());
        let opt: u64 = KERNEL32_BASE + e_lfanew + 4 + 20;
        let exp_rva: u64 = u64::from(cpu.mem.read_u32(opt + 96).unwrap());
        let dir: u64 = KERNEL32_BASE + exp_rva;
        let count: u32 = cpu.mem.read_u32(dir + 24).unwrap();
        let funcs: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 28).unwrap());
        let names: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 32).unwrap());
        let ordinals: u64 = KERNEL32_BASE + u64::from(cpu.mem.read_u32(dir + 36).unwrap());

        let mut resolved: Option<u64> = None;
        for i in 0..count {
            let name_rva: u64 = u64::from(cpu.mem.read_u32(names + u64::from(i) * 4).unwrap());
            let name: String = read_cstr(&cpu.mem, KERNEL32_BASE + name_rva, 64).unwrap();
            if name == "GetProcAddress" {
                let ord: u16 = cpu.mem.read_u16(ordinals + u64::from(i) * 2).unwrap();
                let func_rva: u64 =
                    u64::from(cpu.mem.read_u32(funcs + u64::from(ord) * 4).unwrap());
                resolved = Some(KERNEL32_BASE + func_rva);
            }
        }
        let addr: u64 = resolved.expect("GetProcAddress must be exported");
        assert_eq!(addr, env.export_addr("GetProcAddress").unwrap());
        assert_eq!(env.symbol_for(addr), Some("GetProcAddress"));
    }
}
