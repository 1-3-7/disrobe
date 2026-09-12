use crate::feature::{Characteristic, Feature, Scope};
use crate::rule::{CountBound, Rule, RuleExpr};

fn api(name: &str) -> RuleExpr {
    RuleExpr::feature(Feature::Api(name.to_owned()))
}

const fn characteristic(value: Characteristic) -> RuleExpr {
    RuleExpr::feature(Feature::Characteristic(value))
}

fn mnemonic(name: &str) -> RuleExpr {
    RuleExpr::feature(Feature::Mnemonic(name.to_owned()))
}

fn string(value: &str) -> RuleExpr {
    RuleExpr::feature(Feature::StringSubstring(value.to_owned()))
}

const fn number(value: u64) -> RuleExpr {
    RuleExpr::feature(Feature::Number(value))
}

fn section(name: &str) -> RuleExpr {
    RuleExpr::feature(Feature::Section(name.to_owned()))
}

fn matches_rule(name: &str) -> RuleExpr {
    RuleExpr::matches_rule(name.to_owned())
}

pub const CANONICAL_NAMESPACES: &[&str] = &[
    "anti-analysis",
    "collection",
    "communication",
    "compiler",
    "credential-access",
    "data-manipulation",
    "executable",
    "host-interaction",
    "impact",
    "internal",
    "lib",
    "linking",
    "load-code",
    "malware-family",
    "nursery",
    "persistence",
    "privilege-escalation",
    "runtime",
    "targeting",
];

#[must_use]
pub fn namespace_is_canonical(namespace: &str) -> bool {
    let top: &str = namespace
        .split('/')
        .next()
        .map_or(namespace, |value: &str| value);
    CANONICAL_NAMESPACES.contains(&top)
}

#[must_use]
pub fn builtin_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "create process",
            namespace: "host-interaction/process/create",
            scope: Scope::Function,
            attack: &["T1106"],
            mbc: &["C0017"],
            description: "spawn a new process via a create-process / shell-execute API",
            expr: RuleExpr::or(vec![
                api("CreateProcess"),
                api("CreateProcessInternal"),
                api("ShellExecute"),
                api("ShellExecuteEx"),
                api("WinExec"),
                api("system"),
                api("execve"),
                api("posix_spawn"),
                api("popen"),
            ]),
        },
        Rule {
            name: "create or open file",
            namespace: "host-interaction/file-system",
            scope: Scope::Function,
            attack: &["T1106"],
            mbc: &["C0016"],
            description: "open or create a file handle",
            expr: RuleExpr::or(vec![
                api("CreateFile"),
                api("CreateFile2"),
                api("fopen"),
                api("open64"),
                api("openat"),
            ]),
        },
        Rule {
            name: "write file",
            namespace: "host-interaction/file-system/write",
            scope: Scope::Function,
            attack: &["T1105"],
            mbc: &["C0052"],
            description: "create or open a file and write bytes to it",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("CreateFile"),
                    api("CreateFile2"),
                    api("fopen"),
                    api("open64"),
                    api("openat"),
                ]),
                RuleExpr::or(vec![api("WriteFile"), api("fwrite"), api("fputs")]),
            ]),
        },
        Rule {
            name: "read file",
            namespace: "host-interaction/file-system/read",
            scope: Scope::Function,
            attack: &["T1005"],
            mbc: &["C0051"],
            description: "read bytes from an open file handle",
            expr: RuleExpr::or(vec![api("ReadFile"), api("fread"), api("MapViewOfFile")]),
        },
        Rule {
            name: "open network socket",
            namespace: "communication/socket",
            scope: Scope::Function,
            attack: &["T1095"],
            mbc: &["C0001"],
            description: "create a network socket",
            expr: RuleExpr::or(vec![api("socket"), api("WSASocket"), api("WSAStartup")]),
        },
        Rule {
            name: "connect to network resource",
            namespace: "communication/socket/connect",
            scope: Scope::Function,
            attack: &["T1071"],
            mbc: &["C0001.004"],
            description: "open a socket and connect it to a remote endpoint",
            expr: RuleExpr::or(vec![
                api("connect"),
                api("WSAConnect"),
                api("ConnectEx"),
                api("InternetConnect"),
            ]),
        },
        Rule {
            name: "make http request",
            namespace: "communication/http/client",
            scope: Scope::Function,
            attack: &["T1071.001"],
            mbc: &["C0002"],
            description: "issue an HTTP / HTTPS request through a high-level client API",
            expr: RuleExpr::or(vec![
                api("InternetOpen"),
                api("InternetOpenUrl"),
                api("HttpOpenRequest"),
                api("HttpSendRequest"),
                api("WinHttpOpen"),
                api("WinHttpConnect"),
                api("WinHttpSendRequest"),
                api("URLDownloadToFile"),
                api("curl_easy_perform"),
            ]),
        },
        Rule {
            name: "persist via registry run key",
            namespace: "persistence/registry/run",
            scope: Scope::Function,
            attack: &["T1547.001"],
            mbc: &["F0012"],
            description: "write an autostart entry under a CurrentVersion Run key",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("RegSetValue"),
                    api("RegSetValueEx"),
                    api("RegSetKeyValue"),
                    api("RegCreateKey"),
                    api("RegCreateKeyEx"),
                ]),
                string("CurrentVersion\\Run"),
            ]),
        },
        Rule {
            name: "modify registry",
            namespace: "host-interaction/registry",
            scope: Scope::Function,
            attack: &["T1112"],
            mbc: &["C0036"],
            description: "create or write a registry key or value",
            expr: RuleExpr::or(vec![
                api("RegOpenKey"),
                api("RegOpenKeyEx"),
                api("RegSetValue"),
                api("RegSetValueEx"),
                api("RegCreateKey"),
                api("RegCreateKeyEx"),
                api("RegDeleteKey"),
            ]),
        },
        Rule {
            name: "check for debugger",
            namespace: "anti-analysis/anti-debugging",
            scope: Scope::File,
            attack: &["T1622"],
            mbc: &["B0001"],
            description: "probe for a debugger or analysis environment",
            expr: RuleExpr::n_of(
                1,
                vec![
                    api("IsDebuggerPresent"),
                    api("CheckRemoteDebuggerPresent"),
                    api("NtQueryInformationProcess"),
                    api("OutputDebugString"),
                    string("\\\\.\\NTICE"),
                    string("SbieDll.dll"),
                ],
            ),
        },
        Rule {
            name: "resolve api dynamically",
            namespace: "linking/runtime-linking",
            scope: Scope::Function,
            attack: &["T1129"],
            mbc: &["C0017.002"],
            description: "resolve an API by loading a library and looking up an export at runtime",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("LoadLibrary"),
                    api("LoadLibraryEx"),
                    api("dlopen"),
                ]),
                RuleExpr::or(vec![api("GetProcAddress"), api("dlsym")]),
            ]),
        },
        Rule {
            name: "allocate or mark memory executable",
            namespace: "host-interaction/process/inject",
            scope: Scope::Function,
            attack: &["T1055"],
            mbc: &["C0007"],
            description: "allocate or re-protect memory to hold executable code",
            expr: RuleExpr::or(vec![
                api("VirtualAlloc"),
                api("VirtualAllocEx"),
                api("VirtualProtect"),
                api("VirtualProtectEx"),
                api("mprotect"),
            ]),
        },
        Rule {
            name: "encrypt or decrypt via crypto api",
            namespace: "data-manipulation/encryption",
            scope: Scope::Function,
            attack: &["T1573"],
            mbc: &["C0027"],
            description: "transform data through a platform cryptography API",
            expr: RuleExpr::or(vec![
                api("CryptEncrypt"),
                api("CryptDecrypt"),
                api("CryptAcquireContext"),
                api("BCryptEncrypt"),
                api("BCryptDecrypt"),
                api("EVP_EncryptUpdate"),
                api("EVP_DecryptUpdate"),
            ]),
        },
        Rule {
            name: "encode data using xor",
            namespace: "data-manipulation/encoding/xor",
            scope: Scope::BasicBlock,
            attack: &["T1027"],
            mbc: &["C0026.002"],
            description: "non-zeroing xor inside a tight loop, the classic string / payload decoder",
            expr: RuleExpr::and(vec![
                characteristic(Characteristic::NonZeroingXor),
                characteristic(Characteristic::TightLoop),
            ]),
        },
        Rule {
            name: "resolve api by hash",
            namespace: "linking/runtime-linking/hash",
            scope: Scope::BasicBlock,
            attack: &["T1027.007"],
            mbc: &["C0017.002"],
            description: "rotate-and-accumulate hashing inside a tight loop, the shellcode export-by-hash resolver",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![mnemonic("rol"), mnemonic("ror")]),
                characteristic(Characteristic::TightLoop),
            ]),
        },
        Rule {
            name: "reference cryptographic constant",
            namespace: "data-manipulation/encryption/constant",
            scope: Scope::File,
            attack: &["T1573"],
            mbc: &["C0027"],
            description: "embed a well-known crypto signature constant (RC4 ksa modulus, ChaCha sigma, AES sbox seed)",
            expr: RuleExpr::or(vec![string("expand 32-byte k"), string("expand 16-byte k")]),
        },
        Rule {
            name: "check for vm via cpuid",
            namespace: "anti-analysis/anti-vm/cpuid",
            scope: Scope::File,
            attack: &["T1497.001"],
            mbc: &["B0009"],
            description: "compare a cpuid hypervisor-vendor brand or read the hypervisor vendor leaf",
            expr: RuleExpr::or(vec![
                RuleExpr::n_of(
                    1,
                    vec![
                        string("VMwareVMware"),
                        string("VBoxVBoxVBox"),
                        string("KVMKVMKVM"),
                        string("XenVMMXenVMM"),
                        string("Microsoft Hv"),
                        string("prl hyperv"),
                        string("TCGTCGTCGTCG"),
                    ],
                ),
                RuleExpr::and(vec![mnemonic("cpuid"), number(0x4000_0000)]),
            ]),
        },
        Rule {
            name: "check for vm via descriptor tables",
            namespace: "anti-analysis/anti-vm/red-pill",
            scope: Scope::Function,
            attack: &["T1497.001"],
            mbc: &["B0009"],
            description: "store a descriptor-table register (sidt/sgdt/sldt/str/smsw) the classic red-pill probe",
            expr: RuleExpr::n_of(
                1,
                vec![
                    mnemonic("sidt"),
                    mnemonic("sgdt"),
                    mnemonic("sldt"),
                    mnemonic("str"),
                    mnemonic("smsw"),
                ],
            ),
        },
        Rule {
            name: "detect virtual machine artifacts",
            namespace: "anti-analysis/anti-vm/artifacts",
            scope: Scope::File,
            attack: &["T1497.001"],
            mbc: &["B0009"],
            description: "reference two or more vm guest driver / tool / sandbox artifact names",
            expr: RuleExpr::n_of(
                2,
                vec![
                    string("VBoxGuest"),
                    string("vmtoolsd"),
                    string("prl_tools"),
                    string("vmci.sys"),
                    string("SbieDll.dll"),
                ],
            ),
        },
        Rule {
            name: "timing check via rdtsc",
            namespace: "anti-analysis/anti-vm/timing",
            scope: Scope::BasicBlock,
            attack: &["T1497.003"],
            mbc: &["B0009"],
            description: "read the timestamp counter in a tight loop or sandwiched around cpuid",
            expr: RuleExpr::and(vec![
                mnemonic("rdtsc"),
                RuleExpr::or(vec![
                    characteristic(Characteristic::TightLoop),
                    mnemonic("cpuid"),
                ]),
            ]),
        },
        Rule {
            name: "check available system resources",
            namespace: "anti-analysis/anti-sandbox/resources",
            scope: Scope::Function,
            attack: &["T1497.001"],
            mbc: &["B0009"],
            description: "query memory / disk / processor / power floors to spot an undersized sandbox host",
            expr: RuleExpr::n_of(
                2,
                vec![
                    api("GlobalMemoryStatusEx"),
                    api("GetSystemInfo"),
                    api("GetDiskFreeSpaceEx"),
                    api("DeviceIoControl"),
                    api("GetSystemPowerStatus"),
                ],
            ),
        },
        Rule {
            name: "detect user interaction",
            namespace: "anti-analysis/anti-sandbox/interaction",
            scope: Scope::Function,
            attack: &["T1497.002"],
            mbc: &["B0009"],
            description: "poll mouse / idle / foreground-window / keystroke state to spot an unattended sandbox",
            expr: RuleExpr::n_of(
                1,
                vec![
                    api("GetCursorPos"),
                    api("GetLastInputInfo"),
                    api("GetForegroundWindow"),
                    api("GetAsyncKeyState"),
                ],
            ),
        },
        Rule {
            name: "hide thread from debugger",
            namespace: "anti-analysis/anti-debugging/hide-thread",
            scope: Scope::Function,
            attack: &["T1622"],
            mbc: &["B0001"],
            description: "call NtSetInformationThread with ThreadHideFromDebugger (0x11)",
            expr: RuleExpr::and(vec![api("NtSetInformationThread"), number(0x11)]),
        },
        Rule {
            name: "query debug port",
            namespace: "anti-analysis/anti-debugging/debug-port",
            scope: Scope::Function,
            attack: &["T1622"],
            mbc: &["B0001"],
            description: "call NtQueryInformationProcess with a debug-port / object / flags class (0x07/0x1e/0x1f)",
            expr: RuleExpr::and(vec![
                api("NtQueryInformationProcess"),
                RuleExpr::n_of(1, vec![number(0x07), number(0x1e), number(0x1f)]),
            ]),
        },
        Rule {
            name: "build string on the stack",
            namespace: "anti-analysis/obfuscation/string/stackstring",
            scope: Scope::BasicBlock,
            attack: &["T1027"],
            mbc: &["C0026"],
            description: "assemble a string from inlined immediate stores onto the stack, hiding it from a static string scan",
            expr: characteristic(Characteristic::StackString),
        },
        Rule {
            name: "access process environment block",
            namespace: "anti-analysis/anti-debugging/debugger-detection",
            scope: Scope::Instruction,
            attack: &["T1106"],
            mbc: &["C0044"],
            description: "read the PEB through the fs/gs segment, the classic in-memory check for a debugger flag or module list",
            expr: characteristic(Characteristic::PebAccess),
        },
        Rule {
            name: "contain an embedded pe",
            namespace: "executable/pe",
            scope: Scope::File,
            attack: &["T1027.009"],
            mbc: &["B0030"],
            description: "carry a second MZ/PE image at a non-zero offset, the hallmark of a dropper or self-extracting stub",
            expr: characteristic(Characteristic::EmbeddedPe),
        },
        Rule {
            name: "carry a known packer section",
            namespace: "anti-analysis/packer",
            scope: Scope::File,
            attack: &["T1027.002"],
            mbc: &["B0029"],
            description: "expose a section name written by a commodity packer or protector",
            expr: RuleExpr::or(vec![
                section("UPX0"),
                section("UPX1"),
                section(".vmp0"),
                section(".vmp1"),
                section(".themida"),
                section(".enigma1"),
                section(".aspack"),
                section(".petite"),
                section(".MPRESS1"),
            ]),
        },
        Rule {
            name: "decode data in a loop using xor",
            namespace: "data-manipulation/encoding/xor/loop",
            scope: Scope::Function,
            attack: &["T1027"],
            mbc: &["C0026.002"],
            description: "a function-level decode loop carrying repeated non-zeroing xor, the bulk string / payload decoder",
            expr: RuleExpr::and(vec![
                characteristic(Characteristic::Loop),
                RuleExpr::count(
                    Feature::Characteristic(Characteristic::NonZeroingXor),
                    CountBound::AtLeast(1),
                ),
            ]),
        },
        Rule {
            name: "write encrypted file",
            namespace: "impact/data-encrypted",
            scope: Scope::Function,
            attack: &["T1486"],
            mbc: &["C0027"],
            description: "a routine that both writes a file and drives a cryptography API, the ransomware encrypt-and-overwrite shape",
            expr: RuleExpr::and(vec![
                matches_rule("write file"),
                matches_rule("encrypt or decrypt via crypto api"),
            ]),
        },
        Rule {
            name: "enumerate files",
            namespace: "host-interaction/file-system/files/list",
            scope: Scope::Function,
            attack: &["T1083"],
            mbc: &["E1083"],
            description: "walk a directory listing via a find-first / find-next / readdir API",
            expr: RuleExpr::or(vec![
                api("FindFirstFile"),
                api("FindFirstFileEx"),
                api("FindNextFile"),
                api("NtQueryDirectoryFile"),
                api("readdir"),
                api("opendir"),
            ]),
        },
        Rule {
            name: "enumerate running processes",
            namespace: "host-interaction/process/list",
            scope: Scope::Function,
            attack: &["T1057"],
            mbc: &["E1057"],
            description: "take a process snapshot and walk the running-process list",
            expr: RuleExpr::or(vec![
                api("CreateToolhelp32Snapshot"),
                api("Process32First"),
                api("Process32Next"),
                api("EnumProcesses"),
            ]),
        },
        Rule {
            name: "get system information",
            namespace: "host-interaction/os/version",
            scope: Scope::Function,
            attack: &["T1082"],
            mbc: &["E1082"],
            description: "query the operating-system version or hardware configuration",
            expr: RuleExpr::or(vec![
                api("GetSystemInfo"),
                api("GetNativeSystemInfo"),
                api("GetVersionEx"),
                api("RtlGetVersion"),
                api("uname"),
            ]),
        },
        Rule {
            name: "get computer or user name",
            namespace: "host-interaction/session",
            scope: Scope::Function,
            attack: &["T1033"],
            mbc: &["E1033"],
            description: "read the host name or the current account name",
            expr: RuleExpr::or(vec![
                api("GetComputerName"),
                api("GetComputerNameEx"),
                api("GetUserName"),
                api("GetUserNameEx"),
                api("gethostname"),
            ]),
        },
        Rule {
            name: "query registry value",
            namespace: "host-interaction/registry/query",
            scope: Scope::Function,
            attack: &["T1012"],
            mbc: &["E1012"],
            description: "read or enumerate registry values and keys",
            expr: RuleExpr::or(vec![
                api("RegQueryValueEx"),
                api("RegGetValue"),
                api("RegEnumKeyEx"),
                api("RegEnumValue"),
                api("NtQueryValueKey"),
            ]),
        },
        Rule {
            name: "create or control a service",
            namespace: "persistence/service",
            scope: Scope::Function,
            attack: &["T1543.003"],
            mbc: &["C0036"],
            description: "open the service control manager and create or start a Windows service",
            expr: RuleExpr::and(vec![
                api("OpenSCManager"),
                RuleExpr::or(vec![
                    api("CreateService"),
                    api("StartService"),
                    api("ControlService"),
                ]),
            ]),
        },
        Rule {
            name: "create a scheduled task",
            namespace: "persistence/scheduled-task",
            scope: Scope::Function,
            attack: &["T1053.005"],
            mbc: &["E1053"],
            description: "register a scheduled task through the task scheduler interface or schtasks",
            expr: RuleExpr::or(vec![
                api("NetScheduleJobAdd"),
                string("ITaskScheduler"),
                string("ITaskService"),
                string("\\Microsoft\\Windows\\"),
                string("schtasks"),
            ]),
        },
        Rule {
            name: "access the clipboard",
            namespace: "collection/clipboard",
            scope: Scope::Function,
            attack: &["T1115"],
            mbc: &["E1115"],
            description: "open the clipboard and read or write its contents",
            expr: RuleExpr::and(vec![
                api("OpenClipboard"),
                RuleExpr::or(vec![api("GetClipboardData"), api("SetClipboardData")]),
            ]),
        },
        Rule {
            name: "log keystrokes",
            namespace: "collection/keylog",
            scope: Scope::Function,
            attack: &["T1056.001"],
            mbc: &["F0002"],
            description: "capture keystrokes via a keyboard hook or by polling key state",
            expr: RuleExpr::or(vec![
                api("SetWindowsHookEx"),
                api("GetAsyncKeyState"),
                api("GetKeyboardState"),
                string("WH_KEYBOARD"),
            ]),
        },
        Rule {
            name: "capture screen",
            namespace: "collection/screenshot",
            scope: Scope::Function,
            attack: &["T1113"],
            mbc: &["E1113"],
            description: "copy screen pixels into a bitmap via the GDI blit path",
            expr: RuleExpr::and(vec![
                api("BitBlt"),
                RuleExpr::or(vec![
                    api("GetDC"),
                    api("GetWindowDC"),
                    api("CreateCompatibleBitmap"),
                ]),
            ]),
        },
        Rule {
            name: "discover network configuration",
            namespace: "host-interaction/network/info",
            scope: Scope::Function,
            attack: &["T1016"],
            mbc: &["E1016"],
            description: "read the host network adapter or DNS configuration",
            expr: RuleExpr::or(vec![
                api("GetAdaptersInfo"),
                api("GetAdaptersAddresses"),
                api("GetNetworkParams"),
                api("getifaddrs"),
            ]),
        },
        Rule {
            name: "create a mutex",
            namespace: "host-interaction/mutex",
            scope: Scope::Function,
            attack: &["T1106"],
            mbc: &["C0042"],
            description: "create or open a named mutex, the common single-instance guard",
            expr: RuleExpr::or(vec![
                api("CreateMutex"),
                api("CreateMutexEx"),
                api("OpenMutex"),
            ]),
        },
        Rule {
            name: "execute code in another process",
            namespace: "load-code/remote",
            scope: Scope::Function,
            attack: &["T1055"],
            mbc: &["E1055"],
            description: "write into another process and start execution there, the cross-process code-execution shape",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![api("WriteProcessMemory"), api("NtWriteVirtualMemory")]),
                RuleExpr::or(vec![
                    api("CreateRemoteThread"),
                    api("NtCreateThreadEx"),
                    api("RtlCreateUserThread"),
                    api("QueueUserAPC"),
                ]),
            ]),
        },
        Rule {
            name: "hollow a process",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1055.012"],
            mbc: &["F0003.005"],
            description: "suspend a newly-spawned process, unmap its image, replace with foreign code: process hollowing",
            expr: RuleExpr::and(vec![
                api("NtUnmapViewOfSection"),
                RuleExpr::or(vec![api("WriteProcessMemory"), api("NtWriteVirtualMemory")]),
                RuleExpr::or(vec![api("SetThreadContext"), api("Wow64SetThreadContext")]),
                RuleExpr::or(vec![api("ResumeThread"), api("NtResumeThread")]),
            ]),
        },
        Rule {
            name: "inject via mapping",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1055.015"],
            mbc: &["F0003.004"],
            description: "create a shared section and map it into the target: mapping injection, no WriteProcessMemory",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![api("NtCreateSection"), api("CreateFileMapping")]),
                RuleExpr::or(vec![
                    api("NtMapViewOfSection"),
                    api("MapViewOfFile"),
                    api("MapViewOfFileEx"),
                ]),
            ]),
        },
        Rule {
            name: "inject via thread hijacking",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1055.003"],
            mbc: &["F0003.006"],
            description: "suspend an existing thread, overwrite its context to redirect execution, then resume",
            expr: RuleExpr::and(vec![
                api("OpenThread"),
                api("SuspendThread"),
                RuleExpr::or(vec![api("SetThreadContext"), api("Wow64SetThreadContext")]),
                api("ResumeThread"),
            ]),
        },
        Rule {
            name: "inject via asynchronous procedure call",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1055.004"],
            mbc: &["F0003.003"],
            description: "queue an APC pointing to shellcode on a thread of the target process: APC injection",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![api("OpenThread"), api("CreateToolhelp32Snapshot")]),
                api("QueueUserAPC"),
            ]),
        },
        Rule {
            name: "resolve exports by hash",
            namespace: "load-code/reflection",
            scope: Scope::Function,
            attack: &["T1055.001"],
            mbc: &["F0003.007"],
            description: "walk the PEB loader list to find exports without calling LoadLibrary or GetProcAddress: reflective loading / api hashing",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![number(0x60), number(0x30)]),
                RuleExpr::or(vec![
                    api("VirtualAlloc"),
                    api("VirtualAllocEx"),
                    api("NtAllocateVirtualMemory"),
                ]),
            ]),
        },
        Rule {
            name: "spoof parent process",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1134.004"],
            mbc: &["F0001.008"],
            description: "assign a spoofed parent to a spawned process via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            expr: RuleExpr::and(vec![
                api("InitializeProcThreadAttributeList"),
                api("UpdateProcThreadAttribute"),
                RuleExpr::or(vec![api("CreateProcess"), api("CreateProcessAsUser")]),
            ]),
        },
        Rule {
            name: "stomp a loaded module",
            namespace: "load-code/injection",
            scope: Scope::Function,
            attack: &["T1055.001"],
            mbc: &["F0003.009"],
            description: "overwrite the text section of a legitimately-loaded module with foreign code: module stomping",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("LoadLibrary"),
                    api("LoadLibraryEx"),
                    api("LdrLoadDll"),
                ]),
                api("VirtualProtect"),
                RuleExpr::or(vec![api("WriteProcessMemory"), api("NtWriteVirtualMemory")]),
                RuleExpr::or(vec![
                    api("CreateRemoteThread"),
                    api("NtCreateThreadEx"),
                    api("RtlCreateUserThread"),
                ]),
            ]),
        },
        Rule {
            name: "run shellcode in current process",
            namespace: "load-code/shellcode",
            scope: Scope::Function,
            attack: &["T1059.001"],
            mbc: &["E1059"],
            description: "allocate RWX memory, write shellcode, and transfer control: in-process shellcode runner",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("VirtualAlloc"),
                    api("VirtualAllocEx"),
                    api("HeapAlloc"),
                ]),
                RuleExpr::or(vec![api("VirtualProtect"), number(0x40)]),
                RuleExpr::or(vec![
                    api("CreateThread"),
                    api("CreateRemoteThread"),
                    api("NtCreateThreadEx"),
                    characteristic(Characteristic::IndirectCall),
                ]),
            ]),
        },
        Rule {
            name: "impersonate a user token",
            namespace: "privilege-escalation/token",
            scope: Scope::Function,
            attack: &["T1134.001"],
            mbc: &["F0006.003"],
            description: "duplicate or impersonate a security token to run code under another account",
            expr: RuleExpr::n_of(
                2,
                vec![
                    api("ImpersonateLoggedOnUser"),
                    api("ImpersonateNamedPipeClient"),
                    api("DuplicateTokenEx"),
                    api("SetThreadToken"),
                    api("CreateProcessWithTokenW"),
                    api("CreateProcessAsUser"),
                ],
            ),
        },
        Rule {
            name: "enable a privilege",
            namespace: "privilege-escalation/token",
            scope: Scope::Function,
            attack: &["T1134.001"],
            mbc: &["F0006.003"],
            description: "look up and enable a privilege by name, the standard precursor to privileged API calls",
            expr: RuleExpr::and(vec![
                api("AdjustTokenPrivileges"),
                RuleExpr::or(vec![
                    api("LookupPrivilegeValue"),
                    api("LookupPrivilegeName"),
                ]),
            ]),
        },
        Rule {
            name: "steal a process token",
            namespace: "privilege-escalation/token",
            scope: Scope::Function,
            attack: &["T1134.002"],
            mbc: &["F0006.001"],
            description: "open another process, read its token, and duplicate it for use in the current context",
            expr: RuleExpr::and(vec![
                api("OpenProcessToken"),
                RuleExpr::or(vec![
                    api("DuplicateTokenEx"),
                    api("CreateProcessWithTokenW"),
                ]),
            ]),
        },
        Rule {
            name: "read credentials from vault",
            namespace: "credential-access/credential-store",
            scope: Scope::Function,
            attack: &["T1555.004"],
            mbc: &["E1555"],
            description: "enumerate or read entries from the Windows credential store",
            expr: RuleExpr::or(vec![
                api("CredRead"),
                api("CredEnumerate"),
                api("CredFree"),
                api("WinCredRead"),
            ]),
        },
        Rule {
            name: "dump credentials from lsass",
            namespace: "credential-access/os-credentials",
            scope: Scope::Function,
            attack: &["T1003.001"],
            mbc: &["F0004"],
            description: "open lsass and dump its address space: classic credential-dump shape",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![api("MiniDumpWriteDump"), string("lsass")]),
                RuleExpr::or(vec![api("OpenProcess"), api("NtOpenProcess")]),
            ]),
        },
        Rule {
            name: "send data to network",
            namespace: "communication/socket/send",
            scope: Scope::Function,
            attack: &["T1041"],
            mbc: &["C0001"],
            description: "transmit bytes over a socket or URL session",
            expr: RuleExpr::or(vec![
                api("send"),
                api("WSASend"),
                api("sendto"),
                api("HttpSendRequest"),
                api("WinHttpSendRequest"),
                api("InternetWriteFile"),
            ]),
        },
        Rule {
            name: "receive data from network",
            namespace: "communication/socket/recv",
            scope: Scope::Function,
            attack: &["T1105"],
            mbc: &["C0002"],
            description: "receive bytes from a socket or URL session",
            expr: RuleExpr::or(vec![
                api("recv"),
                api("WSARecv"),
                api("recvfrom"),
                api("InternetReadFile"),
                api("WinHttpReadData"),
                api("HttpQueryInfo"),
            ]),
        },
        Rule {
            name: "steal browser saved credentials",
            namespace: "credential-access/browser",
            scope: Scope::Function,
            attack: &["T1555.003"],
            mbc: &["F0004.004"],
            description: "access Chrome or Firefox login stores and decrypt DPAPI-protected passwords",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    string("Login Data"),
                    string("logins.json"),
                    string("key4.db"),
                    string("Chrome\\User Data"),
                    string("Mozilla\\Firefox"),
                    string("Chromium\\User Data"),
                    string("Microsoft\\Edge"),
                ]),
                RuleExpr::or(vec![api("CryptUnprotectData"), api("NCryptDecrypt")]),
            ]),
        },
        Rule {
            name: "write registry run key",
            namespace: "persistence/registry-run-keys",
            scope: Scope::Function,
            attack: &["T1547.001"],
            mbc: &["F0012"],
            description: "write to a registry run key to survive reboot",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("RegSetValueEx"),
                    api("RegSetValue"),
                    api("NtSetValueKey"),
                ]),
                RuleExpr::or(vec![
                    string("CurrentVersion\\Run"),
                    string("CurrentVersion\\RunOnce"),
                    string("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                ]),
            ]),
        },
        Rule {
            name: "decrypt dpapi protected data",
            namespace: "credential-access/credential-store/dpapi",
            scope: Scope::Function,
            attack: &["T1555"],
            mbc: &["E1555"],
            description: "call CryptUnprotectData to decrypt DPAPI master-key protected blobs",
            expr: RuleExpr::or(vec![
                api("CryptUnprotectData"),
                api("CryptUnprotectMemory"),
                api("BCryptDecrypt"),
            ]),
        },
        Rule {
            name: "bypass uac via com object elevation",
            namespace: "privilege-escalation/bypass",
            scope: Scope::Function,
            attack: &["T1548.002"],
            mbc: &["F0006"],
            description: "invoke a known auto-elevating COM object to run code at high integrity without a UAC prompt",
            expr: RuleExpr::n_of(
                2,
                vec![
                    api("CoCreateInstance"),
                    string("Elevation:Administrator!"),
                    string("ICMLuaUtil"),
                    string("IFileOperation"),
                    string("CMSTPLUA"),
                ],
            ),
        },
        Rule {
            name: "export a certificate",
            namespace: "credential-access/certificate",
            scope: Scope::Function,
            attack: &["T1552.004"],
            mbc: &["E1552"],
            description: "open the Windows certificate store and export certificates or keys",
            expr: RuleExpr::and(vec![
                api("CertOpenStore"),
                RuleExpr::or(vec![
                    api("CertExportCertStore"),
                    api("PFXExportCertStoreEx"),
                    api("CertEnumCertificatesInStore"),
                ]),
            ]),
        },
        Rule {
            name: "compress data",
            namespace: "collection/compress",
            scope: Scope::Function,
            attack: &["T1560.002"],
            mbc: &["C0006"],
            description: "compress data using NTDLL RtlCompressBuffer or a zlib/deflate-style API",
            expr: RuleExpr::or(vec![
                api("RtlCompressBuffer"),
                api("compress"),
                api("CompressBlock"),
                api("CreateCompressor"),
                api("Compress"),
            ]),
        },
        Rule {
            name: "hide a file or directory",
            namespace: "host-interaction/file-system/hide",
            scope: Scope::Function,
            attack: &["T1564.001"],
            mbc: &["F0007"],
            description: "set FILE_ATTRIBUTE_HIDDEN on a file or directory to conceal it from directory listings",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![api("SetFileAttributes"), api("NtSetInformationFile")]),
                number(0x02),
            ]),
        },
        Rule {
            name: "execute via wmi",
            namespace: "host-interaction/process/create",
            scope: Scope::Function,
            attack: &["T1047"],
            mbc: &["E1047"],
            description: "create a process or run a method through WMI: Win32_Process.Create or IWbemServices::ExecMethod",
            expr: RuleExpr::n_of(
                2,
                vec![
                    string("Win32_Process"),
                    string("IWbemServices"),
                    string("IWbemLocator"),
                    api("CoCreateInstance"),
                    string("winmgmts:"),
                ],
            ),
        },
        Rule {
            name: "persist via wmi event subscription",
            namespace: "persistence/wmi",
            scope: Scope::Function,
            attack: &["T1546.003"],
            mbc: &["F0012"],
            description: "install a WMI event filter + consumer binding for persistent code execution on events",
            expr: RuleExpr::n_of(
                2,
                vec![
                    string("__EventFilter"),
                    string("__EventConsumer"),
                    string("__FilterToConsumerBinding"),
                    string("ActiveScriptEventConsumer"),
                    string("CommandLineEventConsumer"),
                ],
            ),
        },
        Rule {
            name: "hijack com object for persistence",
            namespace: "persistence/com-hijacking",
            scope: Scope::Function,
            attack: &["T1546.015"],
            mbc: &["F0012"],
            description: "write a CLSID InprocServer32 or LocalServer32 registry value to redirect COM object loading",
            expr: RuleExpr::and(vec![
                RuleExpr::or(vec![
                    api("RegSetValueEx"),
                    api("RegSetValue"),
                    api("NtSetValueKey"),
                ]),
                string("CLSID"),
                RuleExpr::or(vec![string("InprocServer32"), string("LocalServer32")]),
            ]),
        },
        Rule {
            name: "delete itself",
            namespace: "host-interaction/file-system/delete",
            scope: Scope::Function,
            attack: &["T1070.004"],
            mbc: &["F0007.003"],
            description: "move the module to a temp path and delete it, or use NtSetInformationFile FILE_DISPOSITION_INFO for self-delete",
            expr: RuleExpr::or(vec![
                RuleExpr::and(vec![
                    RuleExpr::or(vec![
                        api("MoveFile"),
                        api("MoveFileEx"),
                        api("NtSetInformationFile"),
                    ]),
                    RuleExpr::or(vec![
                        api("DeleteFile"),
                        api("NtDeleteFile"),
                        api("RemoveDirectory"),
                    ]),
                ]),
                RuleExpr::and(vec![api("NtSetInformationFile"), number(0x0D)]),
            ]),
        },
        Rule {
            name: "enumerate installed security products",
            namespace: "anti-analysis/anti-av",
            scope: Scope::Function,
            attack: &["T1518.001"],
            mbc: &["B0007"],
            description: "scan the running process list or the registry for known AV or EDR product names",
            expr: RuleExpr::n_of(
                1,
                vec![
                    string("avast"),
                    string("kaspersky"),
                    string("malwarebytes"),
                    string("windows defender"),
                    string("MsMpEng"),
                    string("WinDefend"),
                    string("SecurityCenter"),
                    string("AntiVirusProduct"),
                ],
            ),
        },
        Rule {
            name: "load driver",
            namespace: "privilege-escalation/driver",
            scope: Scope::Function,
            attack: &["T1543.003"],
            mbc: &["F0006"],
            description: "create a service pointing to a kernel driver and start it to load code into the kernel",
            expr: RuleExpr::and(vec![
                api("OpenSCManager"),
                api("CreateService"),
                RuleExpr::or(vec![api("StartService"), string("kernel")]),
            ]),
        },
    ]
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn rule_names_are_unique() {
        let rules: Vec<Rule> = builtin_rules();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for rule in &rules {
            assert!(seen.insert(rule.name), "duplicate rule name {}", rule.name);
        }
        assert!(rules.len() >= 52);
    }

    #[test]
    fn every_rule_tags_attack_and_mbc() {
        for rule in builtin_rules() {
            assert!(!rule.attack.is_empty(), "rule {} missing attack", rule.name);
            assert!(!rule.mbc.is_empty(), "rule {} missing mbc", rule.name);
            assert!(!rule.description.is_empty());
            assert!(!rule.namespace.is_empty());
        }
    }

    #[test]
    fn evasion_rules_are_present() {
        let names: BTreeSet<&str> = builtin_rules().into_iter().map(|r: Rule| r.name).collect();
        for expected in [
            "check for vm via cpuid",
            "check for vm via descriptor tables",
            "detect virtual machine artifacts",
            "timing check via rdtsc",
            "check available system resources",
            "detect user interaction",
            "hide thread from debugger",
            "query debug port",
        ] {
            assert!(names.contains(expected), "missing evasion rule {expected}");
        }
    }

    #[test]
    fn every_rule_uses_a_canonical_namespace() {
        for rule in builtin_rules() {
            assert!(
                namespace_is_canonical(rule.namespace),
                "rule {} has off-taxonomy namespace {}",
                rule.name,
                rule.namespace
            );
        }
    }

    #[test]
    fn cross_rule_match_targets_resolve_to_real_rules() {
        let rules: Vec<Rule> = builtin_rules();
        let names: BTreeSet<&str> = rules.iter().map(|r: &Rule| r.name).collect();
        for rule in &rules {
            collect_match_targets(&rule.expr, &names, rule.name);
        }
    }

    fn collect_match_targets(expr: &RuleExpr, names: &BTreeSet<&str>, owner: &str) {
        match expr {
            RuleExpr::Match(target) => assert!(
                names.contains(target.as_str()),
                "rule {owner} references unknown rule {target}"
            ),
            RuleExpr::Feature(_) | RuleExpr::Count { .. } => {}
            RuleExpr::Not(child) | RuleExpr::Optional(child) => {
                collect_match_targets(child, names, owner);
            }
            RuleExpr::And(children)
            | RuleExpr::Or(children)
            | RuleExpr::NOf { of: children, .. } => {
                for child in children {
                    collect_match_targets(child, names, owner);
                }
            }
        }
    }
}
