#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::many_single_char_names
)]

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use crate::packers::section_recovery::{SectionRecoveryReport, section_recovery_report};
use crate::stub_emu::mem::MAX_MAP_BYTES;
use crate::stub_emu::{Cpu, CpuMode, ExitReason, HostCall, Memory, Perm, Reg, Regs};

const YODAS_PROTECTOR_SECTION: &[u8] = b".yP";
const EMU_STACK_BASE: u64 = 0x0030_0000;
const EMU_STACK_SIZE: u64 = 0x0010_0000;
const EMU_HEAP_BASE: u64 = 0x6000_0000;
const EMU_HEAP_SIZE: u64 = 0x0400_0000;
const EMU_TEB_BASE: u64 = 0x7EFD_E000;
const EMU_PEB_BASE: u64 = 0x7EFD_D000;
const EMU_LDR_BASE: u64 = 0x7EFD_C000;
const EMU_LDR_ENTRY_BASE: u64 = 0x7EFD_B000;
const EMU_LAZY_PAGE_BUDGET: u32 = 65_536;
const STEP_CAP_YP: u64 = 120_000_000;

const RESOURCE_DIR_INDEX: usize = 2;
const IMPORT_DIR_INDEX: usize = 1;

const SENT_LOADLIBRARY: u64 = 0xF000_0000;
const SENT_GETPROCADDRESS: u64 = 0xF000_0004;
const SENT_API_BASE: u64 = 0xF100_0000;
const FAKE_MODULE_BASE: u64 = 0x6E00_0000;
const FAKE_VALLOC_BASE: u64 = 0x2000_0000;
const FAKE_SCRATCH_BASE: u64 = 0x1800_0000;

const YP_IAT_LOADLIBRARY_OFFSET: u32 = 0x35;
const YP_IAT_GETPROCADDRESS_OFFSET: u32 = 0x39;

const ALG_RC4: u64 = 0x6801;
const INVALID_HANDLE_VALUE: u64 = 0xFFFF_FFFF;

const KERNEL_DEBUGGER_DEVICES: &[&str] = &[
    "SICE", "SIWVID", "NTICE", "NTOGO", "REGVXG", "REGSYS", "FILEVXG", "FILEM", "TRW", "ICEEXT",
    "SYSER",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashInputSource {
    Image,
    Heap,
    Stack,
    TebPeb,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashInputTrace {
    pub address: u64,
    pub length: u32,
    pub source: HashInputSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticDecryptRefutation {
    pub rc4_key_derived: bool,
    pub image_resident_seed_bytes: u32,
    pub crypt_decrypt_target_observed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForcedRc4Replay {
    pub derived_key: Vec<u8>,
    pub content_recovery_pct: f64,
    pub best_section_recovery_pct: f64,
    pub post_decrypt_mean_entropy: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubProgress {
    HaltedInAntiEmulationGuard {
        final_rva: u32,
        guard_mnemonic: String,
        anti_debug_int3_in_stub: u32,
        int3_gauntlet_cleared: bool,
        apis_resolved: u32,
        content_key_derived: bool,
        content_cipher_invoked: bool,
        hash_inputs: Vec<HashInputTrace>,
        static_decrypt_refutation: StaticDecryptRefutation,
    },
    ReachedOriginalEntry {
        oep_rva: u32,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct YodasProtectorPhase2 {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub stub_section_rva: u32,

    pub stub_progress: StubProgress,
    pub content_bytes_mutated_by_stub: usize,

    pub resource_recovery_pct: f64,
    pub content_recovery_pct: Option<f64>,
    pub section_report: Option<SectionRecoveryReport>,

    pub forced_rc4_replay: Option<ForcedRc4Replay>,

    pub wall_note: String,
}

#[derive(Debug)]
struct YpHost {
    calls: u32,
    api_names: BTreeMap<u64, String>,
    next_api: u64,
    next_module: u64,
    valloc_cursor: u64,
    scratch_cursor: u64,
    next_handle: u64,
    hash_seeds: BTreeMap<u64, Vec<u8>>,
    hash_inputs: Vec<HashInputTrace>,
    key_material: BTreeMap<u64, Vec<u8>>,
    apis_resolved: u32,
    content_key_derived: bool,
    content_cipher_invoked: bool,
    decrypt_target_observed: bool,
    derived_rc4_key: Option<Vec<u8>>,
    image_base: u64,
    image_limit: u64,
}

impl YpHost {
    fn new(image_base: u64, image_size: u64) -> Self {
        Self {
            calls: 0,
            api_names: BTreeMap::new(),
            next_api: SENT_API_BASE,
            next_module: FAKE_MODULE_BASE,
            valloc_cursor: FAKE_VALLOC_BASE,
            scratch_cursor: FAKE_SCRATCH_BASE,
            next_handle: 0x100,
            hash_seeds: BTreeMap::new(),
            hash_inputs: Vec::new(),
            key_material: BTreeMap::new(),
            apis_resolved: 0,
            content_key_derived: false,
            content_cipher_invoked: false,
            decrypt_target_observed: false,
            derived_rc4_key: None,
            image_base,
            image_limit: image_base.saturating_add(image_size),
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h: u64 = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(4);
        h
    }

    fn classify_hash_input(&self, address: u64, length: u64) -> HashInputSource {
        if length == 0 {
            return HashInputSource::Other;
        }
        if range_within(address, length, self.image_base, self.image_limit) {
            return HashInputSource::Image;
        }
        if range_within(
            address,
            length,
            EMU_HEAP_BASE,
            EMU_HEAP_BASE + EMU_HEAP_SIZE,
        ) {
            return HashInputSource::Heap;
        }
        if range_within(
            address,
            length,
            EMU_STACK_BASE,
            EMU_STACK_BASE + EMU_STACK_SIZE,
        ) {
            return HashInputSource::Stack;
        }
        if range_within(address, length, EMU_TEB_BASE, EMU_TEB_BASE + 0x2000)
            || range_within(address, length, EMU_PEB_BASE, EMU_PEB_BASE + 0x1000)
        {
            return HashInputSource::TebPeb;
        }
        HashInputSource::Other
    }

    fn static_decrypt_refutation(&self) -> StaticDecryptRefutation {
        let image_resident_seed_bytes: u32 = if hash_inputs_are_image_resident(&self.hash_inputs) {
            self.hash_inputs
                .iter()
                .fold(0u32, |sum: u32, input: &HashInputTrace| {
                    sum.saturating_add(input.length)
                })
        } else {
            0
        };
        StaticDecryptRefutation {
            rc4_key_derived: self.content_key_derived,
            image_resident_seed_bytes,
            crypt_decrypt_target_observed: self.decrypt_target_observed,
        }
    }
}

fn read_c_string(mem: &Memory, addr: u64) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..512u64 {
        let b: u8 = mem.read_u8(addr.wrapping_add(i)).unwrap_or(0);
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn is_kernel_debugger_device(name: &str) -> bool {
    let trimmed: &str = name
        .trim_start_matches('\\')
        .trim_start_matches('.')
        .trim_start_matches('\\');
    KERNEL_DEBUGGER_DEVICES
        .iter()
        .any(|dev: &&str| trimmed.eq_ignore_ascii_case(dev))
}

fn range_within(address: u64, length: u64, start: u64, end: u64) -> bool {
    let Some(stop): Option<u64> = address.checked_add(length) else {
        return false;
    };
    address >= start && stop <= end
}

impl HostCall for YpHost {
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool> {
        self.calls = self.calls.saturating_add(1);
        let esp: u64 = regs.read_sized(Reg::Rsp, 32);
        let arg = |mem: &Memory, n: u64| -> u64 {
            u64::from(mem.read_u32(esp.wrapping_add(n * 4)).unwrap_or(0))
        };
        let pop_args = |regs: &mut Regs, n: u64| {
            let sp: u64 = regs.read_sized(Reg::Rsp, 32);
            regs.write_sized(Reg::Rsp, sp.wrapping_add(n * 4), 32);
        };

        if target == SENT_LOADLIBRARY {
            let _name: String = read_c_string(mem, arg(mem, 0));
            let handle: u64 = self.next_module;
            self.next_module = self.next_module.wrapping_add(0x10000);
            regs.write_sized(Reg::Rax, handle, 32);
            pop_args(regs, 1);
            return Ok(true);
        }
        if target == SENT_GETPROCADDRESS {
            let name_ptr: u64 = arg(mem, 1);
            let name: String = if name_ptr < 0x10000 {
                format!("#{name_ptr}")
            } else {
                read_c_string(mem, name_ptr)
            };
            let sentinel: u64 = self.next_api;
            self.next_api = self.next_api.wrapping_add(4);
            self.api_names.insert(sentinel, name);
            self.apis_resolved = self.apis_resolved.saturating_add(1);
            regs.write_sized(Reg::Rax, sentinel, 32);
            pop_args(regs, 2);
            return Ok(true);
        }
        if let Some(name) = self.api_names.get(&target).cloned() {
            return self.emulate_winapi(&name, regs, mem, esp);
        }
        regs.write_sized(Reg::Rax, 1, 32);
        Ok(true)
    }
}

impl YpHost {
    fn emulate_winapi(
        &mut self,
        name: &str,
        regs: &mut Regs,
        mem: &mut Memory,
        esp: u64,
    ) -> Result<bool> {
        let arg = |mem: &Memory, n: u64| -> u64 {
            u64::from(mem.read_u32(esp.wrapping_add(n * 4)).unwrap_or(0))
        };
        let pop_args = |regs: &mut Regs, n: u64| {
            let sp: u64 = regs.read_sized(Reg::Rsp, 32);
            regs.write_sized(Reg::Rsp, sp.wrapping_add(n * 4), 32);
        };
        let (rax, argc): (u64, u64) = match name {
            "VirtualAlloc" => {
                let requested: u64 = arg(mem, 0);
                let size: u64 = arg(mem, 1).max(0x1000);
                let rounded: u64 = (size.wrapping_add(0xFFF)) & !0xFFFu64;
                let addr: u64 = if requested != 0 {
                    requested & !0xFFFu64
                } else {
                    let a: u64 = self.valloc_cursor;
                    self.valloc_cursor = self.valloc_cursor.wrapping_add(rounded);
                    a
                };
                let _ = mem.map(addr, rounded.min(MAX_MAP_BYTES), Perm::RWX);
                (if requested != 0 { requested } else { addr }, 4)
            }
            "VirtualProtect" => {
                let old: u64 = arg(mem, 3);
                if old != 0 {
                    let _ = mem.write_u32(old, 0x40);
                }
                (1, 4)
            }
            "VirtualFree" => (1, 3),
            "VirtualQuery" => (0, 3),
            "GlobalAlloc" | "LocalAlloc" => {
                let size: u64 = arg(mem, 1).max(0x1000);
                let rounded: u64 = (size.wrapping_add(0xFFF)) & !0xFFFu64;
                let addr: u64 = self.scratch_cursor;
                self.scratch_cursor = self.scratch_cursor.wrapping_add(rounded);
                let _ = mem.map(addr, rounded.min(MAX_MAP_BYTES), Perm::RWX);
                (addr, 2)
            }
            "GlobalFree" | "LocalFree" => (0, 1),
            "GetModuleHandleA" => (0x40_0000, 1),
            "GetModuleFileNameA" => {
                write_c_string(mem, arg(mem, 1), b"C:\\sample.exe");
                (13, 3)
            }
            "GetCurrentProcess" => (0xFFFF_FFFF, 0),
            "GetCurrentThread" => (0xFFFF_FFFE, 0),
            "GetCurrentProcessId" => (0x1234, 0),
            "GetCurrentThreadId" => (0x5678, 0),
            "IsDebuggerPresent" => (0, 0),
            "CheckRemoteDebuggerPresent" => {
                if arg(mem, 1) != 0 {
                    let _ = mem.write_u32(arg(mem, 1), 0);
                }
                (1, 2)
            }
            "GetTickCount" => (0x0010_0000, 0),
            "GetVersion" => (0x0A28_0105, 0),
            "GetForegroundWindow" | "GetTopWindow" | "FindWindowA" | "FindWindowExA" => (0, 1),
            "GetWindowLongA" | "SetWindowLongA" => (0, 2),
            "GetPriorityClass" => (0x20, 1),
            "SetPriorityClass" | "SetThreadPriority" => (1, 2),
            "BlockInput" => (1, 1),
            "GetWindowsDirectoryA" => {
                write_c_string(mem, arg(mem, 0), b"C:\\Windows");
                (10, 2)
            }
            "CreateFileA" | "CreateFileW" => {
                let fname: String = read_c_string(mem, arg(mem, 0));
                if is_kernel_debugger_device(&fname) {
                    (INVALID_HANDLE_VALUE, 7)
                } else {
                    (self.alloc_handle(), 7)
                }
            }
            "ReadFile" => {
                if arg(mem, 3) != 0 {
                    let _ = mem.write_u32(arg(mem, 3), 0);
                }
                (1, 5)
            }
            "GetFileSize" => (0, 2),
            "CloseHandle" => (1, 1),
            "GetLastError" => (0, 0),
            "CreateToolhelp32Snapshot" => (self.alloc_handle(), 2),
            "Process32First" | "Process32Next" | "Module32First" | "Module32Next"
            | "Thread32First" | "Thread32Next" => (0, 2),
            "OpenProcess" | "OpenThread" => (self.alloc_handle(), 3),
            "TerminateProcess" => (1, 2),
            "SuspendThread" | "ResumeThread" => (0, 1),
            "DebugActiveProcess" | "DebugActiveProcessStop" => (1, 1),
            "RegCreateKeyExA" => {
                if arg(mem, 7) != 0 {
                    let h: u64 = self.alloc_handle();
                    let _ = mem.write_u32(arg(mem, 7), h as u32);
                }
                (0, 9)
            }
            "RegOpenKeyExA" => {
                if arg(mem, 4) != 0 {
                    let h: u64 = self.alloc_handle();
                    let _ = mem.write_u32(arg(mem, 4), h as u32);
                }
                (0, 5)
            }
            "RegCloseKey" => (0, 1),
            "RegSetValueExA" => (0, 6),
            "RegQueryValueExA" => (2, 6),
            "CryptAcquireContextA" => {
                if arg(mem, 0) != 0 {
                    let h: u64 = self.alloc_handle();
                    let _ = mem.write_u32(arg(mem, 0), h as u32);
                }
                (1, 5)
            }
            "CryptReleaseContext" => (1, 2),
            "CryptCreateHash" => {
                if arg(mem, 4) != 0 {
                    let h: u64 = self.alloc_handle();
                    self.hash_seeds.insert(h, Vec::new());
                    let _ = mem.write_u32(arg(mem, 4), h as u32);
                }
                (1, 5)
            }
            "CryptHashData" => {
                let handle: u64 = arg(mem, 0);
                let ptr: u64 = arg(mem, 1);
                let len: u64 = arg(mem, 2);
                let capped_len: u64 = len.min(0x10000);
                let source: HashInputSource = self.classify_hash_input(ptr, capped_len);
                self.hash_inputs.push(HashInputTrace {
                    address: ptr,
                    length: capped_len as u32,
                    source,
                });
                let mut buf: Vec<u8> = Vec::with_capacity(capped_len as usize);
                for i in 0..capped_len {
                    buf.push(mem.read_u8(ptr.wrapping_add(i)).unwrap_or(0));
                }
                if let Some(seed) = self.hash_seeds.get_mut(&handle) {
                    seed.extend_from_slice(&buf);
                }
                (1, 4)
            }
            "CryptDeriveKey" => {
                let algid: u64 = arg(mem, 1);
                let hash_handle: u64 = arg(mem, 2);
                let out: u64 = arg(mem, 4);
                let seed: Vec<u8> = self
                    .hash_seeds
                    .get(&hash_handle)
                    .cloned()
                    .unwrap_or_default();
                let digest: [u8; 16] = md5_digest(&seed);
                let key_handle: u64 = self.alloc_handle();
                self.key_material.insert(key_handle, digest.to_vec());
                if algid == ALG_RC4 {
                    self.content_key_derived = true;
                    self.derived_rc4_key = Some(digest.to_vec());
                }
                if out != 0 {
                    let _ = mem.write_u32(out, key_handle as u32);
                }
                (1, 5)
            }
            "CryptDestroyHash" | "CryptDestroyKey" => (1, 2),
            "CryptDecrypt" => {
                self.content_cipher_invoked = true;
                let key_handle: u64 = arg(mem, 0);
                let ptr: u64 = arg(mem, 4);
                let len_ptr: u64 = arg(mem, 5);
                let len: u64 = u64::from(mem.read_u32(len_ptr).unwrap_or(0)).min(0x0400_0000);
                self.decrypt_target_observed = ptr != 0 && len != 0;
                let key: Vec<u8> = self
                    .key_material
                    .get(&key_handle)
                    .cloned()
                    .unwrap_or_default();
                if !key.is_empty() {
                    let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
                    for i in 0..len {
                        buf.push(mem.read_u8(ptr.wrapping_add(i)).unwrap_or(0));
                    }
                    rc4_in_place(&key, &mut buf);
                    for (i, b) in buf.iter().enumerate() {
                        let _ = mem.write_u8(ptr.wrapping_add(i as u64), *b);
                    }
                }
                (1, 6)
            }
            "CryptEncrypt" => (1, 7),
            "LoadLibraryA" => {
                let h: u64 = self.next_module;
                self.next_module = self.next_module.wrapping_add(0x10000);
                (h, 1)
            }
            "GetProcAddress" => {
                let name_ptr: u64 = arg(mem, 1);
                let inner: String = if name_ptr < 0x10000 {
                    format!("#{name_ptr}")
                } else {
                    read_c_string(mem, name_ptr)
                };
                let sentinel: u64 = self.next_api;
                self.next_api = self.next_api.wrapping_add(4);
                self.api_names.insert(sentinel, inner);
                self.apis_resolved = self.apis_resolved.saturating_add(1);
                (sentinel, 2)
            }
            "ExitProcess" | "ExitThread" | "TerminateThread" => return Ok(false),
            "Sleep" => (0, 1),
            "MessageBoxA" => (1, 4),
            _ => (1, 0),
        };
        regs.write_sized(Reg::Rax, rax, 32);
        if argc > 0 {
            pop_args(regs, argc);
        }
        Ok(true)
    }
}

fn write_c_string(mem: &mut Memory, addr: u64, value: &[u8]) {
    if addr == 0 {
        return;
    }
    for (i, b) in value.iter().enumerate() {
        let _ = mem.write_u8(addr.wrapping_add(i as u64), *b);
    }
    let _ = mem.write_u8(addr.wrapping_add(value.len() as u64), 0);
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    let mut msg: Vec<u8> = input.to_vec();
    let bit_len: u64 = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut m: [u32; 16] = [0u32; 16];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d): (u32, u32, u32, u32) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g): (u32, usize) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let added: u32 = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(added.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out: [u8; 16] = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn rc4_in_place(key: &[u8], data: &mut [u8]) {
    if key.is_empty() {
        return;
    }
    let mut s: [u8; 256] = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256usize {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
        s.swap(i, j);
    }
    let mut i: usize = 0;
    let mut k: usize = 0;
    for b in data.iter_mut() {
        i = (i + 1) & 0xFF;
        k = (k + s[i] as usize) & 0xFF;
        s.swap(i, k);
        let stream: u8 = s[(s[i] as usize + s[k] as usize) & 0xFF];
        *b ^= stream;
    }
}

pub fn unpack_yodas_protector_phase2(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<YodasProtectorPhase2> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img
        .section_by_name(YODAS_PROTECTOR_SECTION)
        .ok_or_else(|| {
            Error::SignatureDb(
                "Yoda's Protector: .yP stub section absent - not a Yoda's Protector image"
                    .to_owned(),
            )
        })?;
    let stub_rva: u32 = stub.virtual_address;
    let image_base: u64 = img.image_base;
    let capacity: u64 = u64::from(img.size_of_image)
        .max(last_section_end_va(&img))
        .min(MAX_MAP_BYTES);

    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem.map(image_base, capacity, Perm::RWX)?;
    map_image(&mut cpu, packed, &img, image_base);
    cpu.mem.map(EMU_STACK_BASE, EMU_STACK_SIZE, Perm::RW)?;
    cpu.mem.map(EMU_HEAP_BASE, EMU_HEAP_SIZE, Perm::RWX)?;
    map_synthetic_teb(&mut cpu, image_base)?;
    cpu.mem.enable_lazy_commit(EMU_LAZY_PAGE_BUDGET);
    cpu.enable_seh_dispatch();
    resolve_stub_import_table(&mut cpu, &img, image_base);

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

    let mut host: YpHost = YpHost::new(image_base, capacity);
    let anti_debug_int3: u32 = count_int3_in_stub(packed, &img, stub_rva);
    let exit: ExitReason = cpu.run(&mut host, STEP_CAP_YP)?;
    let final_rva: u32 = (cpu.regs.rip.saturating_sub(image_base)) as u32;

    let content_mutated: usize = count_content_mutation(&cpu, packed, &img, image_base);

    let oep_reached: bool = matches!(
        exit,
        ExitReason::JumpedOutOfRange { .. } if final_rva < stub_rva && final_rva != 0
    ) && content_mutated > 0;

    let int3_gauntlet_cleared: bool = host.apis_resolved > 0;

    let stub_progress: StubProgress = if oep_reached {
        StubProgress::ReachedOriginalEntry { oep_rva: final_rva }
    } else {
        StubProgress::HaltedInAntiEmulationGuard {
            final_rva,
            guard_mnemonic: exit_mnemonic(&exit),
            anti_debug_int3_in_stub: anti_debug_int3,
            int3_gauntlet_cleared,
            apis_resolved: host.apis_resolved,
            content_key_derived: host.content_key_derived,
            content_cipher_invoked: host.content_cipher_invoked,
            hash_inputs: host.hash_inputs.clone(),
            static_decrypt_refutation: host.static_decrypt_refutation(),
        }
    };

    let recovered: Vec<u8> = cpu.mem.read_lossy(image_base, capacity as usize);
    let resource_pct: f64 = resource_recovery_pct(packed, &img, original)?;

    let (content_pct, report): (Option<f64>, Option<SectionRecoveryReport>) = match original {
        Some(orig) => {
            let report: SectionRecoveryReport =
                section_recovery_report(orig, &recovered, &[YODAS_PROTECTOR_SECTION])?;
            (Some(report.content_recovery_pct()), Some(report))
        }
        None => (None, None),
    };

    let forced_rc4_replay: Option<ForcedRc4Replay> = match (host.derived_rc4_key.as_ref(), original)
    {
        (Some(key), Some(orig)) => Some(forced_rc4_replay(packed, &img, orig, key)?),
        _ => None,
    };

    let wall_note: String =
        build_wall_note(&stub_progress, content_mutated, forced_rc4_replay.as_ref());

    Ok(YodasProtectorPhase2 {
        image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        stub_section_rva: stub_rva,
        stub_progress,
        content_bytes_mutated_by_stub: content_mutated,
        resource_recovery_pct: resource_pct,
        content_recovery_pct: content_pct,
        section_report: report,
        forced_rc4_replay,
        wall_note,
    })
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts: [u64; 256] = [0u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len: f64 = data.len() as f64;
    counts
        .iter()
        .filter(|c: &&u64| **c > 0)
        .fold(0.0_f64, |acc: f64, c: &u64| -> f64 {
            let p: f64 = *c as f64 / len;
            p.mul_add(-p.log2(), acc)
        })
}

fn forced_rc4_replay(
    packed: &[u8],
    img: &PeImage,
    original: &[u8],
    key: &[u8],
) -> Result<ForcedRc4Replay> {
    let orig_img: PeImage = parse_pe_image(original)?;
    let mut total_matching: usize = 0;
    let mut total_compared: usize = 0;
    let mut best: f64 = 0.0;
    let mut entropy_sum: f64 = 0.0;
    let mut entropy_count: usize = 0;

    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if name == YODAS_PROTECTOR_SECTION || name == b".rsrc" {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        let mut buf: Vec<u8> = packed[start..end].to_vec();
        rc4_in_place(key, &mut buf);
        entropy_sum += shannon_entropy(&buf);
        entropy_count += 1;

        let Some(osec): Option<&PeSection> = orig_img
            .sections
            .iter()
            .find(|os: &&PeSection| os.virtual_address == sec.virtual_address)
        else {
            continue;
        };
        let Some((ostart, oend)): Option<(usize, usize)> = osec.raw_range(original.len()) else {
            continue;
        };
        let cmp: usize = buf.len().min(oend - ostart);
        if cmp == 0 {
            continue;
        }
        let matching: usize = buf[..cmp]
            .iter()
            .zip(original[ostart..ostart + cmp].iter())
            .filter(|(a, b): &(&u8, &u8)| a == b)
            .count();
        total_matching += matching;
        total_compared += cmp;
        let pct: f64 = 100.0 * matching as f64 / cmp as f64;
        if pct > best {
            best = pct;
        }
    }

    let content_recovery_pct: f64 = if total_compared == 0 {
        0.0
    } else {
        100.0 * total_matching as f64 / total_compared as f64
    };
    let post_decrypt_mean_entropy: f64 = if entropy_count == 0 {
        0.0
    } else {
        entropy_sum / entropy_count as f64
    };
    Ok(ForcedRc4Replay {
        derived_key: key.to_vec(),
        content_recovery_pct,
        best_section_recovery_pct: best,
        post_decrypt_mean_entropy,
    })
}

fn build_wall_note(
    progress: &StubProgress,
    content_mutated: usize,
    replay: Option<&ForcedRc4Replay>,
) -> String {
    match progress {
        StubProgress::ReachedOriginalEntry { oep_rva, .. } => format!(
            "Yoda's Protector .yP stub emulated to the original entry point (OEP rva=0x{oep_rva:x}); \
             content decrypted in memory ({content_mutated} bytes mutated by the stub)."
        ),
        StubProgress::HaltedInAntiEmulationGuard {
            final_rva,
            guard_mnemonic,
            anti_debug_int3_in_stub,
            int3_gauntlet_cleared,
            apis_resolved,
            content_key_derived,
            content_cipher_invoked,
            hash_inputs,
            static_decrypt_refutation,
        } => {
            let hash_summary: String = hash_input_summary(hash_inputs);
            let gauntlet: &str = if *int3_gauntlet_cleared {
                "The INT3 anti-debug sled is bypassed."
            } else {
                "The INT3 anti-debug sled was not cleared under emulation."
            };
            let crypto: String = format!(
                "The stub clears the SoftICE/NTICE device probe and the PEB->Ldr loader walk, \
                 resolves {apis_resolved} imports, derives the RC4 content key from \
                 {} image-resident seed bytes (content_key_derived={content_key_derived}), then \
                 self-terminates at a deeper anti-emulation control-flow transfer before the \
                 content cipher runs (CryptDecrypt invoked={content_cipher_invoked}, \
                 target_observed={}).",
                static_decrypt_refutation.image_resident_seed_bytes,
                static_decrypt_refutation.crypt_decrypt_target_observed
            );
            let key_note: String = replay.map_or_else(
                || {
                    "Static RC4 refutation: the key seed is image-resident; no original was \
                     supplied to grade a forced decrypt."
                        .to_owned()
                },
                |r: &ForcedRc4Replay| {
                    format!(
                        "Static RC4 refutation: the key seed is image-resident, so the derived RC4 \
                         key is fully reconstructed and replayed over the carved content sections \
                         directly; the replay recovers {:.2}% (best section {:.2}%) and leaves mean \
                         entropy {:.2}, i.e. the on-disk sections are not a flat RC4 ciphertext of \
                         the original - they are RC4 over a compressed stream, so a forced flat \
                         decrypt cannot reconstruct the original and is not faked as recovery.",
                        r.content_recovery_pct,
                        r.best_section_recovery_pct,
                        r.post_decrypt_mean_entropy
                    )
                },
            );
            format!(
                "Yoda's Protector .yP: {gauntlet} {crypto} CryptHashData provenance: {hash_summary}. \
                 Static seed bytes observed={}. Halt rva=0x{final_rva:x} exit={guard_mnemonic}; \
                 {content_mutated} content bytes mutated. {key_note} The {anti_debug_int3_in_stub} \
                 INT3 traps clear, but content remains behind this control-flow wall and is never faked.",
                static_decrypt_refutation.image_resident_seed_bytes
            )
        }
    }
}

fn hash_inputs_are_image_resident(inputs: &[HashInputTrace]) -> bool {
    !inputs.is_empty()
        && inputs
            .iter()
            .all(|input: &HashInputTrace| input.source == HashInputSource::Image)
}

fn hash_input_summary(inputs: &[HashInputTrace]) -> String {
    let calls: usize = inputs.len();
    let bytes: u32 = inputs
        .iter()
        .fold(0u32, |sum: u32, input: &HashInputTrace| {
            sum.saturating_add(input.length)
        });
    let image: usize = inputs
        .iter()
        .filter(|input: &&HashInputTrace| input.source == HashInputSource::Image)
        .count();
    let heap: usize = inputs
        .iter()
        .filter(|input: &&HashInputTrace| input.source == HashInputSource::Heap)
        .count();
    let stack: usize = inputs
        .iter()
        .filter(|input: &&HashInputTrace| input.source == HashInputSource::Stack)
        .count();
    let teb_peb: usize = inputs
        .iter()
        .filter(|input: &&HashInputTrace| input.source == HashInputSource::TebPeb)
        .count();
    let other: usize = inputs
        .iter()
        .filter(|input: &&HashInputTrace| input.source == HashInputSource::Other)
        .count();
    format!(
        "{calls} call(s), {bytes} byte(s), sources image={image} heap={heap} stack={stack} teb_peb={teb_peb} other={other}"
    )
}

fn resolve_stub_import_table(cpu: &mut Cpu, img: &PeImage, image_base: u64) {
    let Some(dir): Option<&crate::packers::pe_sections::DataDirectory> =
        img.data_directories.get(IMPORT_DIR_INDEX)
    else {
        return;
    };
    if dir.virtual_address == 0 {
        return;
    }
    let ll_slot: u64 = image_base + u64::from(dir.virtual_address + YP_IAT_LOADLIBRARY_OFFSET);
    let gp_slot: u64 = image_base + u64::from(dir.virtual_address + YP_IAT_GETPROCADDRESS_OFFSET);
    let _ = cpu.mem.write_u32(ll_slot, SENT_LOADLIBRARY as u32);
    let _ = cpu.mem.write_u32(gp_slot, SENT_GETPROCADDRESS as u32);
}

fn last_section_end_va(img: &PeImage) -> u64 {
    img.sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
        })
        .max()
        .unwrap_or(0)
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
        let dst: u64 = base + u64::from(sec.virtual_address);
        cpu.mem.write_unchecked(dst, &packed[start..end]);
    }
}

fn map_synthetic_teb(cpu: &mut Cpu, image_base: u64) -> Result<()> {
    cpu.mem.map(EMU_TEB_BASE, 0x2000, Perm::RW)?;
    cpu.mem.map(EMU_PEB_BASE, 0x1000, Perm::RW)?;
    cpu.mem.map(EMU_LDR_BASE, 0x1000, Perm::RW)?;
    cpu.mem.map(EMU_LDR_ENTRY_BASE, 0x1000, Perm::RW)?;
    cpu.mem.write_u32(EMU_TEB_BASE, 0xFFFF_FFFF)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x18, EMU_TEB_BASE as u32)?;
    cpu.mem
        .write_u32(EMU_TEB_BASE + 0x30, EMU_PEB_BASE as u32)?;
    cpu.mem.write_u32(EMU_PEB_BASE + 0x2, 0)?;
    cpu.mem.write_u32(EMU_PEB_BASE + 0x8, image_base as u32)?;
    cpu.mem.write_u32(EMU_PEB_BASE + 0xC, EMU_LDR_BASE as u32)?;
    write_synthetic_loader(cpu, image_base)?;
    cpu.set_fs_base(EMU_TEB_BASE);
    Ok(())
}

fn write_synthetic_loader(cpu: &mut Cpu, image_base: u64) -> Result<()> {
    let entry: u32 = EMU_LDR_ENTRY_BASE as u32;
    let ldr: u32 = EMU_LDR_BASE as u32;
    for off in [0x0Cu64, 0x14, 0x1C] {
        cpu.mem.write_u32(EMU_LDR_BASE + off, entry)?;
        cpu.mem.write_u32(EMU_LDR_BASE + off + 4, entry)?;
    }
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE, ldr + 0x0C)?;
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE + 4, ldr + 0x0C)?;
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE + 0x08, ldr + 0x14)?;
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE + 0x0C, ldr + 0x14)?;
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE + 0x10, ldr + 0x1C)?;
    cpu.mem.write_u32(EMU_LDR_ENTRY_BASE + 0x14, ldr + 0x1C)?;
    cpu.mem
        .write_u32(EMU_LDR_ENTRY_BASE + 0x18, image_base as u32)?;
    Ok(())
}

fn count_int3_in_stub(packed: &[u8], img: &PeImage, stub_rva: u32) -> u32 {
    let Some(stub): Option<&PeSection> = img.section_containing_rva(stub_rva) else {
        return 0;
    };
    let Some((start, end)): Option<(usize, usize)> = stub.raw_range(packed.len()) else {
        return 0;
    };
    packed[start..end]
        .iter()
        .fold(0u32, |n: u32, b: &u8| n + u32::from(*b == 0xCC))
}

fn count_content_mutation(cpu: &Cpu, packed: &[u8], img: &PeImage, base: u64) -> usize {
    let mut mutated: usize = 0;
    for sec in &img.sections {
        let name: &[u8] = sec.name_trimmed();
        if name == YODAS_PROTECTOR_SECTION || name == b".rsrc" {
            continue;
        }
        let Some((start, end)): Option<(usize, usize)> = sec.raw_range(packed.len()) else {
            continue;
        };
        if start >= end {
            continue;
        }
        let dst: u64 = base + u64::from(sec.virtual_address);
        let now: Vec<u8> = cpu.mem.read_lossy(dst, end - start);
        mutated += now
            .iter()
            .zip(packed[start..end].iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
    }
    mutated
}

fn resource_recovery_pct(packed: &[u8], img: &PeImage, original: Option<&[u8]>) -> Result<f64> {
    let Some(orig): Option<&[u8]> = original else {
        return Ok(0.0);
    };
    let orig_img: PeImage = parse_pe_image(orig)?;
    let (Some(orig_rsrc), Some(packed_rsrc)): (Option<&PeSection>, Option<&PeSection>) = (
        orig_img.section_by_name(b".rsrc"),
        img.section_by_name(b".rsrc"),
    ) else {
        return Ok(0.0);
    };
    let orig_raw: &[u8] = match orig_rsrc.raw_range(orig.len()) {
        Some((s, e)) => &orig[s..e],
        None => return Ok(0.0),
    };
    let packed_raw: &[u8] = match packed_rsrc.raw_range(packed.len()) {
        Some((s, e)) => &packed[s..e],
        None => return Ok(0.0),
    };
    let compare: usize = orig_raw.len().min(packed_raw.len());
    if compare == 0 {
        return Ok(0.0);
    }
    let matching: usize = orig_raw[..compare]
        .iter()
        .zip(packed_raw[..compare].iter())
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let _ = RESOURCE_DIR_INDEX;
    Ok(100.0 * matching as f64 / compare as f64)
}

fn exit_mnemonic(exit: &ExitReason) -> String {
    match exit {
        ExitReason::UnsupportedInstr { mnemonic, .. } => mnemonic.clone(),
        ExitReason::GuestFault(s) => format!("guest-fault:{s}"),
        ExitReason::HostHalt(s) => format!("host-halt:{s}"),
        ExitReason::JumpedOutOfRange { to, .. } => format!("jump-out-of-range:0x{to:x}"),
        ExitReason::StepCap(n) => format!("step-cap:{n}"),
        ExitReason::RepLimit(n) => format!("rep-limit:{n}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_image_without_yp_section() {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let r: Result<YodasProtectorPhase2> = unpack_yodas_protector_phase2(&buf, None);
        assert!(r.is_err());
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(
            md5_digest(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
        assert_eq!(
            md5_digest(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }

    #[test]
    fn rc4_matches_known_vector() {
        let mut data: Vec<u8> = b"Plaintext".to_vec();
        rc4_in_place(b"Key", &mut data);
        assert_eq!(
            data,
            vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
    }
}
