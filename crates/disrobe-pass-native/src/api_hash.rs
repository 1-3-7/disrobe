use std::collections::BTreeMap;
use std::sync::OnceLock;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
use serde::{Deserialize, Serialize};

const CRC32_POLY: u32 = 0xEDB8_8320;
const DJB2_SEED: u32 = 5381;
const FNV1A_OFFSET: u32 = 0x811C_9DC5;
const FNV1A_PRIME: u32 = 0x0100_0193;
const MAX_HARVEST_INSNS: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashFamily {
    Ror13Add,
    Ror7Add,
    Rol5Add,
    Djb2,
    Sdbm,
    Crc32,
    Fnv1a32,
}

impl HashFamily {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ror13Add => "ror13-add",
            Self::Ror7Add => "ror7-add",
            Self::Rol5Add => "rol5-add",
            Self::Djb2 => "djb2",
            Self::Sdbm => "sdbm",
            Self::Crc32 => "crc32",
            Self::Fnv1a32 => "fnv1a-32",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Ror13Add,
            Self::Ror7Add,
            Self::Rol5Add,
            Self::Djb2,
            Self::Sdbm,
            Self::Crc32,
            Self::Fnv1a32,
        ]
    }

    #[must_use]
    pub fn hash(self, name: &[u8], case_insensitive: bool) -> u32 {
        match self {
            Self::Ror13Add => rotate_add_hash(name, 13, false, case_insensitive),
            Self::Ror7Add => rotate_add_hash(name, 7, false, case_insensitive),
            Self::Rol5Add => rotate_add_hash(name, 5, true, case_insensitive),
            Self::Djb2 => djb2_hash(name, case_insensitive),
            Self::Sdbm => sdbm_hash(name, case_insensitive),
            Self::Crc32 => crc32_hash(name, case_insensitive),
            Self::Fnv1a32 => fnv1a_hash(name, case_insensitive),
        }
    }
}

const fn fold_byte(byte: u8, case_insensitive: bool) -> u8 {
    if case_insensitive && byte.is_ascii_uppercase() {
        byte + 32
    } else {
        byte
    }
}

fn rotate_add_hash(name: &[u8], rotate: u32, left: bool, case_insensitive: bool) -> u32 {
    let mut acc: u32 = 0;
    for &byte in name {
        let rotated: u32 = if left {
            acc.rotate_left(rotate)
        } else {
            acc.rotate_right(rotate)
        };
        acc = rotated.wrapping_add(u32::from(fold_byte(byte, case_insensitive)));
    }
    acc
}

fn djb2_hash(name: &[u8], case_insensitive: bool) -> u32 {
    let mut acc: u32 = DJB2_SEED;
    for &byte in name {
        acc = acc
            .wrapping_mul(33)
            .wrapping_add(u32::from(fold_byte(byte, case_insensitive)));
    }
    acc
}

fn sdbm_hash(name: &[u8], case_insensitive: bool) -> u32 {
    let mut acc: u32 = 0;
    for &byte in name {
        let value: u32 = u32::from(fold_byte(byte, case_insensitive));
        acc = value
            .wrapping_add(acc.wrapping_shl(6))
            .wrapping_add(acc.wrapping_shl(16))
            .wrapping_sub(acc);
    }
    acc
}

fn crc32_hash(name: &[u8], case_insensitive: bool) -> u32 {
    let mut acc: u32 = u32::MAX;
    for &byte in name {
        acc ^= u32::from(fold_byte(byte, case_insensitive));
        for _ in 0..8 {
            let mask: u32 = (acc & 1).wrapping_neg();
            acc = (acc >> 1) ^ (CRC32_POLY & mask);
        }
    }
    !acc
}

fn fnv1a_hash(name: &[u8], case_insensitive: bool) -> u32 {
    let mut acc: u32 = FNV1A_OFFSET;
    for &byte in name {
        acc ^= u32::from(fold_byte(byte, case_insensitive));
        acc = acc.wrapping_mul(FNV1A_PRIME);
    }
    acc
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiHashHit {
    pub call_site: u64,
    pub hash: u32,
    pub family: HashFamily,
    pub resolved_name: Option<String>,
    pub dll: Option<String>,
}

impl ApiHashHit {
    #[must_use]
    pub fn annotation(&self) -> String {
        match (&self.dll, &self.resolved_name) {
            (Some(dll), Some(name)) => format!(
                "api: {dll}!{name} ({}=0x{:08x})",
                self.family.label(),
                self.hash
            ),
            (None, Some(name)) => {
                format!("api: {name} ({}=0x{:08x})", self.family.label(), self.hash)
            }
            _ => format!(
                "unresolved hash 0x{:08x} (family {})",
                self.hash,
                self.family.label()
            ),
        }
    }
}

type ExportCorpus = &'static [(&'static str, &'static [&'static str])];

const EXPORT_CORPUS: ExportCorpus = &[
    (
        "kernel32.dll",
        &[
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "GetProcAddress",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualFree",
            "CreateThread",
            "CreateRemoteThread",
            "CreateProcessA",
            "CreateProcessW",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "OpenProcess",
            "WaitForSingleObject",
            "CreateFileA",
            "CreateFileW",
            "WriteFile",
            "ReadFile",
            "CloseHandle",
            "ExitProcess",
            "ExitThread",
            "Sleep",
            "GetCurrentProcess",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetTickCount",
            "GetLastError",
            "SetLastError",
            "TerminateProcess",
            "WinExec",
            "GetComputerNameA",
            "IsDebuggerPresent",
            "GetStartupInfoA",
            "HeapAlloc",
            "HeapFree",
            "GetProcessHeap",
            "GetTempPathA",
            "CreateMutexA",
            "FreeLibrary",
            "GetSystemDirectoryA",
            "GetWindowsDirectoryA",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "OpenThread",
            "ResumeThread",
            "SuspendThread",
            "QueueUserAPC",
            "GetThreadContext",
            "SetThreadContext",
            "MapViewOfFile",
            "CreateFileMappingA",
            "FlushInstructionCache",
            "GetModuleFileNameA",
        ],
    ),
    (
        "ntdll.dll",
        &[
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtCreateThreadEx",
            "NtQueueApcThread",
            "NtOpenProcess",
            "NtQuerySystemInformation",
            "NtQueryInformationProcess",
            "RtlCreateUserThread",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
            "RtlMoveMemory",
            "RtlAllocateHeap",
            "RtlZeroMemory",
            "NtClose",
        ],
    ),
    (
        "advapi32.dll",
        &[
            "RegOpenKeyExA",
            "RegSetValueExA",
            "RegQueryValueExA",
            "RegCreateKeyExA",
            "RegCloseKey",
            "OpenProcessToken",
            "AdjustTokenPrivileges",
            "LookupPrivilegeValueA",
            "CryptAcquireContextA",
            "CryptEncrypt",
            "CryptDecrypt",
            "CreateServiceA",
            "OpenSCManagerA",
            "StartServiceA",
        ],
    ),
    (
        "ws2_32.dll",
        &[
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "closesocket",
            "bind",
            "listen",
            "accept",
            "gethostbyname",
            "inet_addr",
            "htons",
            "WSASocketA",
        ],
    ),
    (
        "wininet.dll",
        &[
            "InternetOpenA",
            "InternetOpenUrlA",
            "InternetConnectA",
            "InternetReadFile",
            "HttpOpenRequestA",
            "HttpSendRequestA",
            "InternetCloseHandle",
        ],
    ),
    (
        "user32.dll",
        &[
            "MessageBoxA",
            "GetForegroundWindow",
            "GetWindowTextA",
            "FindWindowA",
            "SetWindowsHookExA",
            "GetAsyncKeyState",
            "GetKeyState",
            "wsprintfA",
        ],
    ),
    ("urlmon.dll", &["URLDownloadToFileA", "URLDownloadToFileW"]),
    (
        "shell32.dll",
        &["ShellExecuteA", "ShellExecuteExA", "SHGetFolderPathA"],
    ),
];

struct ReverseTable {
    by_family: BTreeMap<HashFamily, BTreeMap<u32, (&'static str, &'static str)>>,
}

fn reverse_table() -> &'static ReverseTable {
    static TABLE: OnceLock<ReverseTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut by_family: BTreeMap<HashFamily, BTreeMap<u32, (&'static str, &'static str)>> =
            BTreeMap::new();
        for family in HashFamily::all().iter().copied() {
            let map: &mut BTreeMap<u32, (&'static str, &'static str)> =
                by_family.entry(family).or_default();
            for (dll, names) in EXPORT_CORPUS.iter().copied() {
                for name in names.iter().copied() {
                    map.entry(family.hash(name.as_bytes(), false))
                        .or_insert((dll, name));
                    map.entry(family.hash(name.as_bytes(), true))
                        .or_insert((dll, name));
                }
            }
        }
        ReverseTable { by_family }
    })
}

#[must_use]
pub fn resolve_hash(hash: u32, family: HashFamily) -> Option<(String, String)> {
    reverse_table()
        .by_family
        .get(&family)
        .and_then(|map: &BTreeMap<u32, (&'static str, &'static str)>| map.get(&hash))
        .map(|(dll, name): &(&'static str, &'static str)| ((*dll).to_owned(), (*name).to_owned()))
}

#[must_use]
pub fn resolve_hash_any_family(hash: u32) -> Option<(HashFamily, String, String)> {
    for family in HashFamily::all().iter().copied() {
        if let Some((dll, name)) = resolve_hash(hash, family) {
            return Some((family, dll, name));
        }
    }
    None
}

#[must_use]
pub fn harvested_hash_constants(bitness: u32, base: u64, code: &[u8]) -> Vec<(u64, u32)> {
    let mut out: Vec<(u64, u32)> = Vec::new();
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);
    let mut insn: Instruction = Instruction::default();
    let mut count: usize = 0;
    while decoder.can_decode() {
        if count >= MAX_HARVEST_INSNS {
            break;
        }
        count += 1;
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if let Some(value) = compare_immediate(&insn)
            && let Ok(narrowed) = u32::try_from(value)
        {
            out.push((insn.ip(), narrowed));
        }
    }
    out
}

fn compare_immediate(insn: &Instruction) -> Option<u64> {
    use iced_x86::Mnemonic;
    if !matches!(
        insn.mnemonic(),
        Mnemonic::Cmp | Mnemonic::Sub | Mnemonic::Xor
    ) {
        return None;
    }
    for operand in 0..insn.op_count() {
        match insn.op_kind(operand) {
            OpKind::Immediate32 => return Some(u64::from(insn.immediate32())),
            OpKind::Immediate32to64 => return Some(insn.immediate32to64().cast_unsigned()),
            OpKind::Immediate8to32 => {
                return Some(u64::from(insn.immediate8to32().cast_unsigned()));
            }
            _ => {}
        }
    }
    None
}

#[must_use]
pub fn resolve_imports_by_hash(bitness: u32, base: u64, code: &[u8]) -> Vec<ApiHashHit> {
    let mut out: Vec<ApiHashHit> = Vec::new();
    let mut seen: std::collections::BTreeSet<(u64, u32)> = std::collections::BTreeSet::new();
    for (call_site, hash) in harvested_hash_constants(bitness, base, code) {
        if hash == 0 {
            continue;
        }
        let Some((family, dll, name)): Option<(HashFamily, String, String)> =
            resolve_hash_any_family(hash)
        else {
            continue;
        };
        if !seen.insert((call_site, hash)) {
            continue;
        }
        out.push(ApiHashHit {
            call_site,
            hash,
            family,
            resolved_name: Some(name),
            dll: Some(dll),
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
