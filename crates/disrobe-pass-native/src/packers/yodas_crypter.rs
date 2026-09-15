use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, find_subsequence, parse_pe_image};
use crate::packers::section_recovery::emulated_image_capacity;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const YODAS_CRYPTER_SECTION: &[u8] = b"yC";
const VERBATIM_SECTION_NAMES: &[&[u8]] = &[b".rsrc", b".reloc"];
const ENCRYPTED_SECTION_NAMES: &[&[u8]] = &[b".text", b".rdata", b".data", b"CODE", b"DATA"];
const YC2_MARKER: &[u8] = b"yC2.0";

const EMU_STACK_BASE: u64 = 0x0030_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_HEAP_BASE: u64 = 0x1000_0000;
const EMU_HEAP_SIZE: u64 = 0x0400_0000;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const SYNTH_KERNEL32_BASE: u64 = 0x7C80_0000;
const SYNTH_API_BASE: u64 = 0x7C81_0000;
const SYNTH_API_STRIDE: u64 = 0x10;
const EMU_LAZY_PAGE_BUDGET: u32 = 131_072;
const STEP_CAP_YC: u64 = 64_000_000;

const KERNEL32_APIS: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "GetVersion",
    "GetVersionExA",
    "ExitProcess",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionRecovery {
    ByteIdentical,
    EncryptedCarve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSection {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub recovery: SectionRecovery,
    pub compared_bytes: usize,
    pub matching_bytes: usize,
    pub bytes: Vec<u8>,
}

impl RecoveredSection {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn plaintext_pct(&self) -> f64 {
        if self.compared_bytes == 0 {
            return 0.0;
        }
        100.0 * self.matching_bytes as f64 / self.compared_bytes as f64
    }

    #[must_use]
    pub fn is_byte_identical(&self) -> bool {
        self.recovery == SectionRecovery::ByteIdentical
            && self.compared_bytes > 0
            && self.matching_bytes == self.compared_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YodasCrypterReport {
    pub has_yc2_marker: bool,
    pub stub_section_present: bool,
    pub recovered_sections: Vec<RecoveredSection>,
    pub limitation_note: String,
}

impl YodasCrypterReport {
    #[must_use]
    pub fn byte_identical_sections(&self) -> Vec<&RecoveredSection> {
        self.recovered_sections
            .iter()
            .filter(|s: &&RecoveredSection| s.is_byte_identical())
            .collect()
    }

    #[must_use]
    pub fn encrypted_sections(&self) -> Vec<&RecoveredSection> {
        self.recovered_sections
            .iter()
            .filter(|s: &&RecoveredSection| s.recovery == SectionRecovery::EncryptedCarve)
            .collect()
    }
}

pub fn unpack_yodas_crypter(packed: &[u8], original: &[u8]) -> Result<YodasCrypterReport> {
    let packed_img: PeImage = parse_pe_image(packed)?;
    let original_img: PeImage = parse_pe_image(original)?;
    let stub_present: bool = packed_img.section_by_name(YODAS_CRYPTER_SECTION).is_some();
    if !stub_present {
        return Err(Error::SignatureDb(
            "Yoda's Crypter: yC stub section absent - not a Yoda's Crypter image".to_owned(),
        ));
    }
    let has_marker: bool = find_subsequence(packed, YC2_MARKER).is_some();
    let decrypted_image: Vec<u8> = emulate_yc_stub(packed, &packed_img)?;
    let mut recovered: Vec<RecoveredSection> = Vec::with_capacity(original_img.sections.len());
    for orig_sec in &original_img.sections {
        let name: Vec<u8> = orig_sec.name_trimmed().to_vec();
        let Some(packed_sec): Option<&PeSection> = packed_img.section_by_name(&name) else {
            continue;
        };
        let orig_raw: &[u8] = raw_bytes(original, orig_sec);
        let is_verbatim: bool = VERBATIM_SECTION_NAMES.contains(&name.as_slice());
        let is_encrypted: bool = ENCRYPTED_SECTION_NAMES.contains(&name.as_slice());
        let recovered_raw: Vec<u8> = if is_encrypted {
            section_from_image(&decrypted_image, packed_sec, orig_raw.len())
        } else {
            raw_bytes(packed, packed_sec).to_vec()
        };
        let compare_len: usize = orig_raw.len().min(recovered_raw.len());
        let matching: usize =
            count_matching(&orig_raw[..compare_len], &recovered_raw[..compare_len]);
        let fully_recovered: bool = compare_len > 0 && matching == compare_len;
        let recovery: SectionRecovery = if fully_recovered || is_verbatim {
            SectionRecovery::ByteIdentical
        } else {
            SectionRecovery::EncryptedCarve
        };
        recovered.push(RecoveredSection {
            name,
            virtual_address: orig_sec.virtual_address,
            recovery,
            compared_bytes: compare_len,
            matching_bytes: matching,
            bytes: recovered_raw[..compare_len].to_vec(),
        });
    }
    Ok(YodasCrypterReport {
        has_yc2_marker: has_marker,
        stub_section_present: stub_present,
        recovered_sections: recovered,
        limitation_note: "Yoda's Crypter stores .rsrc/.reloc verbatim and section-encrypts \
.text/.rdata/.data via the yC stub. The stub is driven to its original entry point through the \
in-house stub_emu x86 interpreter; the now-decrypted code/data sections are read back from the \
emulated image and graded byte-for-byte against the independent original."
            .to_owned(),
    })
}

#[derive(Debug)]
struct YcStubHost {
    api_addr: std::collections::BTreeMap<u64, &'static str>,
    heap_brk: u64,
    heap_end: u64,
    image_base: u64,
}

impl YcStubHost {
    fn new(image_base: u64) -> Self {
        let mut api_addr: std::collections::BTreeMap<u64, &'static str> =
            std::collections::BTreeMap::new();
        for (i, name) in KERNEL32_APIS.iter().enumerate() {
            api_addr.insert(SYNTH_API_BASE + (i as u64) * SYNTH_API_STRIDE, name);
        }
        Self {
            api_addr,
            heap_brk: EMU_HEAP_BASE,
            heap_end: EMU_HEAP_BASE + EMU_HEAP_SIZE,
            image_base,
        }
    }

    fn synth_addr_for(name: &str) -> Option<u64> {
        KERNEL32_APIS
            .iter()
            .position(|n: &&str| *n == name)
            .map(|i: usize| SYNTH_API_BASE + (i as u64) * SYNTH_API_STRIDE)
    }
}

fn read_emu_cstr(mem: &Memory, addr: u64) -> String {
    let mut out: Vec<u8> = Vec::new();
    for i in 0..128u64 {
        let b: Vec<u8> = mem.read_lossy(addr + i, 1);
        if b.is_empty() || b[0] == 0 {
            break;
        }
        out.push(b[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl HostCall for YcStubHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        let sp: u64 = regs.get(Reg::Rsp);
        let arg = |i: u64| -> u64 { u64::from(mem.read_u32(sp.wrapping_add(i * 4)).unwrap_or(0)) };
        let Some(name): Option<&'static str> = self.api_addr.get(&target).copied() else {
            regs.write_sized(Reg::Rax, 0, 32);
            return Ok(true);
        };
        match name {
            "GetProcAddress" => {
                let proc_name: String = read_emu_cstr(mem, arg(2));
                let resolved: u64 = Self::synth_addr_for(&proc_name).unwrap_or(SYNTH_API_BASE);
                regs.write_sized(Reg::Rax, resolved, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(2 * 4));
            }
            "LoadLibraryA" | "LoadLibraryW" => {
                regs.write_sized(Reg::Rax, SYNTH_KERNEL32_BASE, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(4));
            }
            "GetModuleHandleA" | "GetModuleHandleW" => {
                let module: u64 = arg(1);
                let handle: u64 = if module == 0 {
                    self.image_base
                } else {
                    SYNTH_KERNEL32_BASE
                };
                regs.write_sized(Reg::Rax, handle, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(4));
            }
            "VirtualAlloc" => {
                let size: u32 = arg(2) as u32;
                let aligned: u64 = ((u64::from(size) + 0xFFF) & !0xFFFu64).max(0x1000);
                let at: u64 = (self.heap_brk + 0xFFF) & !0xFFFu64;
                if at + aligned > self.heap_end {
                    regs.write_sized(Reg::Rax, 0, 32);
                } else {
                    self.heap_brk = at + aligned;
                    mem.map(at, aligned, Perm::RWX)?;
                    regs.write_sized(Reg::Rax, at, 32);
                }
                regs.set(Reg::Rsp, sp.wrapping_add(4 * 4));
            }
            "VirtualProtect" => {
                let old_protect_ptr: u64 = arg(4);
                if old_protect_ptr != 0 {
                    let _ = mem.write_u32(old_protect_ptr, 0x40);
                }
                regs.write_sized(Reg::Rax, 1, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(4 * 4));
            }
            "VirtualFree" => {
                regs.write_sized(Reg::Rax, 1, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(3 * 4));
            }
            "GetVersion" => {
                regs.write_sized(Reg::Rax, 0x0A28_0105, 32);
            }
            "GetVersionExA" => {
                regs.write_sized(Reg::Rax, 1, 32);
                regs.set(Reg::Rsp, sp.wrapping_add(4));
            }
            "ExitProcess" => {
                return Ok(false);
            }
            _ => {
                regs.write_sized(Reg::Rax, 0, 32);
            }
        }
        Ok(true)
    }
}

fn emulate_yc_stub(packed: &[u8], img: &PeImage) -> Result<Vec<u8>> {
    let stub: &PeSection = img.section_by_name(YODAS_CRYPTER_SECTION).ok_or_else(|| {
        Error::SignatureDb("Yoda's Crypter: yC stub section absent during emulation".to_owned())
    })?;
    let stub_rva: u32 = stub.virtual_address;
    let image_base: u64 = img.image_base;
    let capacity: u64 = emulated_image_capacity(img, packed.len());

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, img, image_base);
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.map(EMU_HEAP_BASE, EMU_HEAP_SIZE, Perm::RWX)?;
    map_synthetic_teb(&mut cpu)?;
    seed_loader_iat(&mut cpu, packed, img, image_base);
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    cpu.enable_seh_dispatch();

    cpu.regs.rip = image_base + u64::from(img.entry_point_rva);
    cpu.regs
        .set(Reg::Rsp, EMU_STACK_BASE + EMU_STACK_SIZE - 0x1000);
    for reg in [
        Reg::Rax,
        Reg::Rbx,
        Reg::Rcx,
        Reg::Rdx,
        Reg::Rsi,
        Reg::Rdi,
        Reg::Rbp,
    ] {
        cpu.regs.write_sized(reg, 0, 32);
    }

    let stub_lo: u64 = image_base + u64::from(stub_rva);
    let mut host: YcStubHost = YcStubHost::new(image_base);
    run_until_oep(&mut cpu, &mut host, image_base, stub_lo, capacity);
    Ok(cpu.mem.read_lossy(image_base, capacity as usize))
}

fn seed_loader_iat(cpu: &mut Cpu, packed: &[u8], img: &PeImage, image_base: u64) {
    let Some(import_dir): Option<&crate::packers::pe_sections::DataDirectory> =
        img.data_directories.get(1)
    else {
        return;
    };
    let import_rva: u32 = import_dir.virtual_address;
    if import_rva == 0 {
        return;
    }
    let mut idx: u32 = 0;
    loop {
        let desc_rva: u32 = import_rva + idx * 20;
        let Some(desc_off): Option<usize> = rva_to_file_off(img, desc_rva) else {
            break;
        };
        if desc_off + 20 > packed.len() {
            break;
        }
        let oft_rva: u32 = read_u32(packed, desc_off).unwrap_or(0);
        let first_thunk_rva: u32 = read_u32(packed, desc_off + 16).unwrap_or(0);
        let name_rva: u32 = read_u32(packed, desc_off + 12).unwrap_or(0);
        if oft_rva == 0 && first_thunk_rva == 0 && name_rva == 0 {
            break;
        }
        let thunk_table_rva: u32 = if oft_rva != 0 {
            oft_rva
        } else {
            first_thunk_rva
        };
        let mut t: u32 = 0;
        while let Some(thunk_off) = rva_to_file_off(img, thunk_table_rva + t * 4) {
            if thunk_off + 4 > packed.len() {
                break;
            }
            let thunk: u32 = read_u32(packed, thunk_off).unwrap_or(0);
            if thunk == 0 {
                break;
            }
            if thunk & 0x8000_0000 == 0
                && let Some(func_off) = rva_to_file_off(img, thunk + 2)
            {
                let func_name: String = read_file_cstr(packed, func_off);
                let synth: Option<u64> = YcStubHost::synth_addr_for(&func_name);
                if let Some(addr) = synth {
                    let iat_slot: u64 = image_base + u64::from(first_thunk_rva) + u64::from(t) * 4;
                    let _ = cpu.mem.write_u32(iat_slot, addr as u32);
                }
            }
            t += 1;
            if t > 4096 {
                break;
            }
        }
        idx += 1;
        if idx > 64 {
            break;
        }
    }
}

fn rva_to_file_off(img: &PeImage, rva: u32) -> Option<usize> {
    for sec in &img.sections {
        let span: u32 = sec.virtual_size.max(sec.raw_size);
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span) {
            return Some((sec.raw_pointer + (rva - sec.virtual_address)) as usize);
        }
    }
    None
}

fn read_file_cstr(bytes: &[u8], off: usize) -> String {
    if off >= bytes.len() {
        return String::new();
    }
    let end: usize = bytes[off..]
        .iter()
        .position(|b: &u8| *b == 0)
        .map_or(bytes.len(), |n: usize| off + n);
    String::from_utf8_lossy(&bytes[off..end]).into_owned()
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    crate::packers::pe_sections::read_u32(bytes, off)
}

fn run_until_oep(
    cpu: &mut Cpu,
    host: &mut YcStubHost,
    image_base: u64,
    stub_lo: u64,
    capacity: u64,
) {
    let image_hi: u64 = image_base + capacity;
    let mut steps: u64 = 0;
    let mut entered_stub: bool = false;
    loop {
        if steps >= STEP_CAP_YC {
            return;
        }
        steps += 1;
        let ip: u64 = cpu.regs.rip;
        let in_stub: bool = ip >= stub_lo && ip < image_hi;
        if in_stub {
            entered_stub = true;
        } else if entered_stub && ip >= image_base && ip < stub_lo {
            return;
        }
        let exit: Result<ExitReason> = cpu.run(host, 1);
        match exit {
            Ok(ExitReason::StepCap(_)) => {}
            Ok(ExitReason::JumpedOutOfRange { to, .. })
                if to >= image_base && to < stub_lo && (to - image_base) as u32 != 0 =>
            {
                return;
            }
            _ => return,
        }
    }
}

fn section_from_image(image: &[u8], packed_sec: &PeSection, want_len: usize) -> Vec<u8> {
    let va: usize = packed_sec.virtual_address as usize;
    if va >= image.len() {
        return Vec::new();
    }
    let avail: usize = image.len() - va;
    let take: usize = want_len.min(avail);
    image[va..va + take].to_vec()
}

fn map_image(cpu: &mut Cpu, packed: &[u8], img: &PeImage, base: u64) {
    let hdr: usize = 0x1000.min(packed.len());
    cpu.mem.write_unchecked(base, &packed[..hdr]);
    for sec in &img.sections {
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        cpu.mem
            .write_unchecked(base + u64::from(sec.virtual_address), &packed[start..end]);
    }
}

fn map_synthetic_teb(cpu: &mut Cpu) -> Result<()> {
    cpu.mem.map(EMU_TEB_BASE, 0x2000, Perm::RW)?;
    cpu.mem.map(EMU_PEB_BASE, 0x1000, Perm::RW)?;
    cpu.mem.write_u32(EMU_TEB_BASE, 0xFFFF_FFFF)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x18, EMU_TEB_BASE as u32)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x30, EMU_PEB_BASE as u32)?;
    cpu.set_fs_base(EMU_TEB_BASE);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YodasCrypterCarve {
    pub stub_section_present: bool,
    pub has_yc2_marker: bool,

    pub verbatim_sections: Vec<(Vec<u8>, Vec<u8>)>,

    pub recovered_image: Vec<u8>,
}

pub fn recover_yodas_crypter_carve(packed: &[u8]) -> Result<YodasCrypterCarve> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub_present: bool = img.section_by_name(YODAS_CRYPTER_SECTION).is_some();
    if !stub_present {
        return Err(Error::SignatureDb(
            "Yoda's Crypter: yC stub section absent - not a Yoda's Crypter image".to_owned(),
        ));
    }
    let has_marker: bool = find_subsequence(packed, YC2_MARKER).is_some();
    let mut verbatim_sections: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        let is_verbatim: bool = VERBATIM_SECTION_NAMES.contains(&name);
        if !is_verbatim {
            continue;
        }
        let body: &[u8] = raw_bytes(packed, sec);
        verbatim_sections.push((name.to_vec(), body.to_vec()));
    }
    Ok(YodasCrypterCarve {
        stub_section_present: stub_present,
        has_yc2_marker: has_marker,
        verbatim_sections,
        recovered_image: packed.to_vec(),
    })
}

#[inline]
fn raw_bytes<'a>(image: &'a [u8], sec: &PeSection) -> &'a [u8] {
    match sec.raw_range(image.len()) {
        Some((start, end)) => &image[start..end],
        None => {
            let start: usize = (sec.raw_pointer as usize).min(image.len());
            &image[start..]
        }
    }
}

#[inline]
fn count_matching(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .filter(|(x, y): &(&u8, &u8)| x == y)
        .count()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_image_without_yc_section() {
        let mut packed: Vec<u8> = build_pe_with_sections(&[(b".text", 0x1000, &[0u8; 16])]);
        let original: Vec<u8> = packed.clone();
        packed.truncate(packed.len());
        let r: Result<YodasCrypterReport> = unpack_yodas_crypter(&packed, &original);
        assert!(r.is_err(), "no yC section must reject");
    }

    #[test]
    fn verbatim_section_is_byte_identical() {
        let rsrc: [u8; 32] = core::array::from_fn(|i: usize| (i as u8).wrapping_mul(7));
        let original: Vec<u8> =
            build_pe_with_sections(&[(b".rsrc", 0x1000, &rsrc), (b".text", 0x2000, &[0xAA; 32])]);
        let packed: Vec<u8> = build_pe_with_sections(&[
            (b".rsrc", 0x1000, &rsrc),
            (b".text", 0x2000, &[0x11; 32]),
            (b"yC", 0x3000, &[0x60, 0xE8]),
        ]);
        let report: YodasCrypterReport = unpack_yodas_crypter(&packed, &original).expect("unpack");
        let rsrc_sec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".rsrc")
            .expect(".rsrc recovered");
        assert!(rsrc_sec.is_byte_identical());
        assert!((rsrc_sec.plaintext_pct() - 100.0).abs() < f64::EPSILON);
        let text_sec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".text")
            .expect(".text recovered");
        assert_eq!(text_sec.recovery, SectionRecovery::EncryptedCarve);
        assert!(text_sec.plaintext_pct() < 100.0);
    }

    fn build_pe_with_sections(secs: &[(&[u8], u32, &[u8])]) -> Vec<u8> {
        let header_len: usize = 0x400;
        let mut buf: Vec<u8> = vec![0u8; header_len];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec_table: usize = opt_off + 0xE0;
        let mut raw_cursor: usize = header_len;
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, (name, va, data)) in secs.iter().enumerate() {
            let off: usize = sec_table + i * 40;
            let mut name_buf: [u8; 8] = [0u8; 8];
            name_buf[..name.len()].copy_from_slice(name);
            buf[off..off + 8].copy_from_slice(&name_buf);
            buf[off + 8..off + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            buf[off + 16..off + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&(raw_cursor as u32).to_le_bytes());
            bodies.push((raw_cursor, (*data).to_vec()));
            raw_cursor += data.len();
        }
        buf.resize(raw_cursor, 0);
        for (off, data) in bodies {
            buf[off..off + data.len()].copy_from_slice(&data);
        }
        buf
    }

    const FIXTURE_IMAGE_BASE: u32 = 0x0040_0000;
    const FIXTURE_SECTION_ALIGN: u32 = 0x1000;
    const FIXTURE_FILE_ALIGN: u32 = 0x200;
    const FIXTURE_OPT_HDR: u16 = 0xE0;

    fn align_up(v: u32, a: u32) -> u32 {
        let mask: u32 = a - 1;
        v.wrapping_add(mask) & !mask
    }

    fn yc_encrypt_section(plain: &[u8], key_seed: u32) -> Vec<u8> {
        let mut out: Vec<u8> = plain.to_vec();
        let pad: usize = (4 - (out.len() % 4)) % 4;
        out.resize(out.len() + pad, 0);
        let mut key: u32 = key_seed;
        let mut i: usize = 0;
        while i < out.len() {
            let plain_dword: u32 = u32::from_le_bytes([out[i], out[i + 1], out[i + 2], out[i + 3]]);
            let cipher: u32 = (plain_dword ^ key).rotate_left(7);
            out[i..i + 4].copy_from_slice(&cipher.to_le_bytes());
            key = key.wrapping_add(cipher);
            i += 4;
        }
        out
    }

    fn emit_decrypt_loop(stub: &mut Vec<u8>, dest_va: u32, dword_count: u32, key_seed: u32) {
        stub.push(0xBE);
        stub.extend_from_slice(&dest_va.to_le_bytes());
        stub.push(0xB9);
        stub.extend_from_slice(&dword_count.to_le_bytes());
        stub.push(0xB8);
        stub.extend_from_slice(&key_seed.to_le_bytes());
        let loop_top: usize = stub.len();
        stub.extend_from_slice(&[0x8B, 0x16]);
        stub.extend_from_slice(&[0x89, 0xD3]);
        stub.extend_from_slice(&[0xC1, 0xCA, 0x07]);
        stub.extend_from_slice(&[0x31, 0xC2]);
        stub.extend_from_slice(&[0x89, 0x16]);
        stub.extend_from_slice(&[0x01, 0xD8]);
        stub.extend_from_slice(&[0x83, 0xC6, 0x04]);
        stub.push(0x49);
        let after_dec: usize = stub.len() + 2;
        let rel: i8 = (loop_top as isize - after_dec as isize) as i8;
        stub.extend_from_slice(&[0x75, rel as u8]);
    }

    struct YcSection {
        name: &'static [u8],
        va: u32,
        plain: Vec<u8>,
        key_seed: u32,
        characteristics: u32,
    }

    fn build_yc_packed(sections: &[YcSection], oep_va: u32, stub_va: u32) -> (Vec<u8>, Vec<u8>) {
        let mut stub: Vec<u8> = Vec::new();
        stub.extend_from_slice(b"yC2.0\0");
        stub.push(0x60);
        for sec in sections {
            if !ENCRYPTED_SECTION_NAMES.contains(&sec.name) {
                continue;
            }
            let dwords: u32 = align_up(sec.plain.len() as u32, 4) / 4;
            emit_decrypt_loop(&mut stub, FIXTURE_IMAGE_BASE + sec.va, dwords, sec.key_seed);
        }
        stub.push(0x61);
        stub.push(0xB8);
        stub.extend_from_slice(&(FIXTURE_IMAGE_BASE + oep_va).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xE0]);

        let entry_va: u32 = stub_va + (b"yC2.0\0".len() as u32);

        let mut original: Vec<BuiltSection> = Vec::new();
        let mut packed: Vec<BuiltSection> = Vec::new();
        for sec in sections {
            original.push(BuiltSection {
                name: sec.name,
                va: sec.va,
                body: sec.plain.clone(),
                characteristics: sec.characteristics,
            });
            let body: Vec<u8> = if ENCRYPTED_SECTION_NAMES.contains(&sec.name) {
                yc_encrypt_section(&sec.plain, sec.key_seed)
            } else {
                sec.plain.clone()
            };
            packed.push(BuiltSection {
                name: sec.name,
                va: sec.va,
                body,
                characteristics: sec.characteristics,
            });
        }
        packed.push(BuiltSection {
            name: b"yC",
            va: stub_va,
            body: stub,
            characteristics: 0xE000_0060,
        });

        let original_pe: Vec<u8> = assemble_pe(oep_va, &original);
        let packed_pe: Vec<u8> = assemble_pe(entry_va, &packed);
        (packed_pe, original_pe)
    }

    struct BuiltSection {
        name: &'static [u8],
        va: u32,
        body: Vec<u8>,
        characteristics: u32,
    }

    fn assemble_pe(entry_rva: u32, sections: &[BuiltSection]) -> Vec<u8> {
        let e_lfanew: usize = 0x80;
        let coff: usize = e_lfanew + 4;
        let opt: usize = coff + 20;
        let sec_table: usize = opt + FIXTURE_OPT_HDR as usize;
        let headers_raw: u32 =
            align_up((sec_table + sections.len() * 40) as u32, FIXTURE_FILE_ALIGN);

        let mut raw_cursor: u32 = headers_raw;
        let mut raw_offs: Vec<u32> = Vec::with_capacity(sections.len());
        for s in sections {
            raw_offs.push(raw_cursor);
            raw_cursor += align_up(s.body.len() as u32, FIXTURE_FILE_ALIGN);
        }
        let mut buf: Vec<u8> = vec![0u8; raw_cursor as usize];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        buf[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\x00\x00");
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&FIXTURE_OPT_HDR.to_le_bytes());
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&FIXTURE_IMAGE_BASE.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&FIXTURE_SECTION_ALIGN.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&FIXTURE_FILE_ALIGN.to_le_bytes());
        let size_of_image: u32 = sections
            .iter()
            .map(|s: &BuiltSection| align_up(s.va + s.body.len() as u32, FIXTURE_SECTION_ALIGN))
            .max()
            .unwrap_or(FIXTURE_SECTION_ALIGN);
        buf[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&headers_raw.to_le_bytes());
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

        for (i, s) in sections.iter().enumerate() {
            let off: usize = sec_table + i * 40;
            let mut name: [u8; 8] = [0u8; 8];
            name[..s.name.len().min(8)].copy_from_slice(&s.name[..s.name.len().min(8)]);
            buf[off..off + 8].copy_from_slice(&name);
            buf[off + 8..off + 12].copy_from_slice(&(s.body.len() as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&s.va.to_le_bytes());
            buf[off + 16..off + 20]
                .copy_from_slice(&align_up(s.body.len() as u32, FIXTURE_FILE_ALIGN).to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&raw_offs[i].to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&s.characteristics.to_le_bytes());
            let ro: usize = raw_offs[i] as usize;
            buf[ro..ro + s.body.len()].copy_from_slice(&s.body);
        }
        buf
    }

    fn sample_text_bytes() -> Vec<u8> {
        let mut t: Vec<u8> = Vec::new();
        for i in 0..64u32 {
            t.extend_from_slice(&[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10]);
            t.extend_from_slice(&i.to_le_bytes());
            t.extend_from_slice(&[0x90, 0xC9, 0xC3]);
        }
        t
    }

    fn sample_rdata_bytes() -> Vec<u8> {
        let mut d: Vec<u8> = Vec::new();
        for s in [
            "kernel32.dll",
            "GetProcAddress",
            "LoadLibraryA",
            "ExitProcess",
        ] {
            d.extend_from_slice(s.as_bytes());
            d.push(0);
        }
        d.extend_from_slice(&[0xCD; 48]);
        d
    }

    #[test]
    fn stub_emu_decrypts_text_and_rdata_byte_identical() {
        let text: Vec<u8> = sample_text_bytes();
        let rdata: Vec<u8> = sample_rdata_bytes();
        let rsrc: Vec<u8> = (0..200u32)
            .map(|i: u32| (i.wrapping_mul(13)) as u8)
            .collect();

        let text_va: u32 = 0x1000;
        let rdata_va: u32 = align_up(text_va + text.len() as u32, FIXTURE_SECTION_ALIGN);
        let rsrc_va: u32 = align_up(rdata_va + rdata.len() as u32, FIXTURE_SECTION_ALIGN);
        let stub_va: u32 = align_up(rsrc_va + rsrc.len() as u32, FIXTURE_SECTION_ALIGN);
        let oep_va: u32 = text_va;

        let sections: Vec<YcSection> = vec![
            YcSection {
                name: b".text",
                va: text_va,
                plain: text.clone(),
                key_seed: 0xDEAD_BEEF,
                characteristics: 0x6000_0020,
            },
            YcSection {
                name: b".rdata",
                va: rdata_va,
                plain: rdata,
                key_seed: 0x1234_5678,
                characteristics: 0x4000_0040,
            },
            YcSection {
                name: b".rsrc",
                va: rsrc_va,
                plain: rsrc,
                key_seed: 0,
                characteristics: 0x4000_0040,
            },
        ];

        let (packed, original): (Vec<u8>, Vec<u8>) = build_yc_packed(&sections, oep_va, stub_va);

        let packed_img: PeImage = parse_pe_image(&packed).expect("packed pe parses");
        let text_sec: &PeSection = packed_img.section_by_name(b".text").expect(".text");
        let on_disk: &[u8] = raw_bytes(&packed, text_sec);
        assert!(
            on_disk[..text.len()] != text[..],
            "packed .text must be encrypted on disk, never plaintext"
        );

        let report: YodasCrypterReport =
            unpack_yodas_crypter(&packed, &original).expect("emulated unpack");
        assert!(report.has_yc2_marker, "yC2.0 marker present");

        let text_rec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".text")
            .expect(".text recovered");
        assert!(
            text_rec.is_byte_identical(),
            ".text must decrypt byte-identical via stub_emu: {}/{} matching",
            text_rec.matching_bytes,
            text_rec.compared_bytes,
        );
        assert_eq!(
            &text_rec.bytes[..text.len()],
            &text[..],
            ".text bytes must equal the plaintext original"
        );

        let rdata_rec: &RecoveredSection = report
            .recovered_sections
            .iter()
            .find(|s: &&RecoveredSection| s.name == b".rdata")
            .expect(".rdata recovered");
        assert!(
            rdata_rec.is_byte_identical(),
            ".rdata must decrypt byte-identical: {}/{} matching",
            rdata_rec.matching_bytes,
            rdata_rec.compared_bytes,
        );

        let byte_identical: Vec<&RecoveredSection> = report.byte_identical_sections();
        assert!(
            byte_identical
                .iter()
                .any(|s: &&RecoveredSection| s.name == b".text"),
            ".text must appear in the byte-identical set, proving the wall is gone"
        );
    }

    #[test]
    fn encrypt_decrypt_is_exact_inverse() {
        let plain: Vec<u8> = sample_text_bytes();
        let key: u32 = 0xCAFE_F00D;
        let cipher: Vec<u8> = yc_encrypt_section(&plain, key);
        assert!(cipher[..plain.len()] != plain[..], "cipher must differ");
        let mut recovered: Vec<u8> = cipher;
        let mut k: u32 = key;
        let mut i: usize = 0;
        while i < recovered.len() {
            let c: u32 = u32::from_le_bytes([
                recovered[i],
                recovered[i + 1],
                recovered[i + 2],
                recovered[i + 3],
            ]);
            let p: u32 = c.rotate_right(7) ^ k;
            recovered[i..i + 4].copy_from_slice(&p.to_le_bytes());
            k = k.wrapping_add(c);
            i += 4;
        }
        assert_eq!(
            &recovered[..plain.len()],
            &plain[..],
            "scheme must round-trip"
        );
    }
}
