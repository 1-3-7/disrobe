use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Info,
    Low,
    Medium,
    High,
}

impl Confidence {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigClass {
    AntiDebug,
    AntiVm,
    Sandbox,
    Hypervisor,
    VmMacOui,
    Timing,
    AntiTool,
    ResourceFloor,
    Interaction,
    AntiDump,
    AntiAttach,
}

#[derive(Debug, Clone, Copy)]
pub struct StringSig {
    pub needle: &'static str,
    pub class: SigClass,
    pub confidence: Confidence,
    pub word_bounded: bool,
    pub note: &'static str,
}

pub static STRING_SIGS: &[StringSig] = &[
    StringSig {
        needle: "isdebuggerpresent",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "win32 debugger-presence query",
    },
    StringSig {
        needle: "checkremotedebuggerpresent",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "win32 remote-debugger query",
    },
    StringSig {
        needle: "ntqueryinformationprocess",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "process-debug-port query primitive",
    },
    StringSig {
        needle: "ntsetinformationthread",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "thread-hide-from-debugger primitive",
    },
    StringSig {
        needle: "outputdebugstring",
        class: SigClass::AntiDebug,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "debug-channel write, also benign logging",
    },
    StringSig {
        needle: "dbghelp.dll",
        class: SigClass::AntiDebug,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "debug-help library reference",
    },
    StringSig {
        needle: "ptrace",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "posix ptrace self-attach guard",
    },
    StringSig {
        needle: "/proc/self/status",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "linux tracerpid status probe path",
    },
    StringSig {
        needle: "tracerpid",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "linux tracerpid field name",
    },
    StringSig {
        needle: "vmware",
        class: SigClass::AntiVm,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "vmware vendor string",
    },
    StringSig {
        needle: "virtualbox",
        class: SigClass::AntiVm,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "virtualbox vendor string",
    },
    StringSig {
        needle: "vboxguest",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest driver name",
    },
    StringSig {
        needle: "vboxmouse",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox mouse driver name",
    },
    StringSig {
        needle: "vboxsf",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: true,
        note: "virtualbox shared-folder driver name",
    },
    StringSig {
        needle: "vboxvideo",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox video driver name",
    },
    StringSig {
        needle: "vmtoolsd",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware tools daemon process",
    },
    StringSig {
        needle: "vmwareuser",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware user process",
    },
    StringSig {
        needle: "vmwaretray",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware tray process",
    },
    StringSig {
        needle: "vmmouse.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware mouse driver file",
    },
    StringSig {
        needle: "vmhgfs.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware host-guest filesystem driver",
    },
    StringSig {
        needle: "vmmemctl",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware balloon memory-control driver",
    },
    StringSig {
        needle: "prl_cc.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "parallels control-center process",
    },
    StringSig {
        needle: "prl_tools",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "parallels tools process",
    },
    StringSig {
        needle: "vmci.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware virtual-machine communication driver",
    },
    StringSig {
        needle: "qemu",
        class: SigClass::Hypervisor,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "qemu vendor string",
    },
    StringSig {
        needle: "qemu-ga",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "qemu guest agent process",
    },
    StringSig {
        needle: "bochs",
        class: SigClass::Hypervisor,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "bochs emulator vendor string",
    },
    StringSig {
        needle: "virtualpc",
        class: SigClass::Hypervisor,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "microsoft virtual pc string",
    },
    StringSig {
        needle: "kvmkvmkvm",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "kvm cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "vmwarevmware",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "vboxvboxvbox",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "microsoft hv",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "hyper-v cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "xenvmmxenvmm",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "xen cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "prl hyperv",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "parallels cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "tcgtcgtcgtcg",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "qemu tcg cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "sbiedll.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "sandboxie injection dll",
    },
    StringSig {
        needle: "sbiesvc",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "sandboxie service process",
    },
    StringSig {
        needle: "cuckoomon",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "cuckoo monitor dll",
    },
    StringSig {
        needle: "cuckoo",
        class: SigClass::Sandbox,
        confidence: Confidence::Low,
        word_bounded: true,
        note: "cuckoo sandbox reference",
    },
    StringSig {
        needle: "dbghelp",
        class: SigClass::Sandbox,
        confidence: Confidence::Info,
        word_bounded: true,
        note: "debug-help reference, weak signal",
    },
    StringSig {
        needle: "wine_get_unix_file_name",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "wine emulation-layer export probe",
    },
    StringSig {
        needle: "sandboxie",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "sandboxie vendor string",
    },
    StringSig {
        needle: "dbgview",
        class: SigClass::Sandbox,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "debug viewer process probe",
    },
    StringSig {
        needle: "procmon",
        class: SigClass::Sandbox,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "process monitor analysis tool probe",
    },
    StringSig {
        needle: "wireshark",
        class: SigClass::Sandbox,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "packet capture analysis tool probe",
    },
    StringSig {
        needle: "x32dbg",
        class: SigClass::Sandbox,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "x64dbg 32-bit debugger process probe",
    },
    StringSig {
        needle: "x64dbg",
        class: SigClass::Sandbox,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "x64dbg debugger process probe",
    },
    StringSig {
        needle: "ollydbg",
        class: SigClass::Sandbox,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "ollydbg debugger process probe",
    },
    StringSig {
        needle: "joeboxserver",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "joe sandbox server process",
    },
    StringSig {
        needle: "joeboxcontrol",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "joe sandbox control process",
    },
    StringSig {
        needle: "00:05:69",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "vmware mac oui 00:05:69",
    },
    StringSig {
        needle: "00:0c:29",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "vmware mac oui 00:0c:29",
    },
    StringSig {
        needle: "00:1c:14",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "vmware mac oui 00:1c:14",
    },
    StringSig {
        needle: "00:50:56",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "vmware mac oui 00:50:56",
    },
    StringSig {
        needle: "08:00:27",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "virtualbox mac oui 08:00:27",
    },
    StringSig {
        needle: "00:16:3e",
        class: SigClass::VmMacOui,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "xen mac oui 00:16:3e",
    },
    StringSig {
        needle: "00:1c:42",
        class: SigClass::VmMacOui,
        confidence: Confidence::High,
        word_bounded: true,
        note: "parallels mac oui 00:1c:42",
    },
    StringSig {
        needle: "00:15:5d",
        class: SigClass::VmMacOui,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "hyper-v mac oui 00:15:5d",
    },
    StringSig {
        needle: "52:54:00",
        class: SigClass::VmMacOui,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "qemu/kvm mac oui 52:54:00",
    },
    StringSig {
        needle: "queryperformancecounter",
        class: SigClass::Timing,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "high-resolution timer query",
    },
    StringSig {
        needle: "gettickcount",
        class: SigClass::Timing,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "tick-count timer query",
    },
    StringSig {
        needle: "rdtsc",
        class: SigClass::Timing,
        confidence: Confidence::Low,
        word_bounded: true,
        note: "timestamp-counter mnemonic reference",
    },
    StringSig {
        needle: "wudfisanydebuggerpresent",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "umdf any-debugger-present query",
    },
    StringSig {
        needle: "wudfiskerneldebuggerpresent",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "umdf kernel-debugger-present query",
    },
    StringSig {
        needle: "ntqueryobject",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "debug-object type-information count primitive",
    },
    StringSig {
        needle: "dbgbreakpoint",
        class: SigClass::AntiAttach,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "ntdll breakpoint entry, anti-attach patch target",
    },
    StringSig {
        needle: "dbguiremotebreakin",
        class: SigClass::AntiAttach,
        confidence: Confidence::High,
        word_bounded: false,
        note: "ntdll remote-break-in entry, anti-attach patch target",
    },
    StringSig {
        needle: "blockinput",
        class: SigClass::AntiDebug,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "input-blocking guard during sensitive work",
    },
    StringSig {
        needle: "processdebugport",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "process-debug-port information class name",
    },
    StringSig {
        needle: "processdebugobject",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "process-debug-object information class name",
    },
    StringSig {
        needle: "processdebugflags",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "process-debug-flags information class name",
    },
    StringSig {
        needle: "threadhidefromdebugger",
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        word_bounded: false,
        note: "thread-hide-from-debugger information class name",
    },
    StringSig {
        needle: "getthreadcontext",
        class: SigClass::AntiDebug,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "thread context read, hardware-breakpoint inspection primitive",
    },
    StringSig {
        needle: "ntgetcontextthread",
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "native thread context read, debug-register inspection primitive",
    },
    StringSig {
        needle: "windbgframeclass",
        class: SigClass::AntiTool,
        confidence: Confidence::High,
        word_bounded: false,
        note: "windbg window class probe",
    },
    StringSig {
        needle: "immunitydebugger",
        class: SigClass::AntiTool,
        confidence: Confidence::High,
        word_bounded: false,
        note: "immunity debugger probe",
    },
    StringSig {
        needle: "idaq",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "ida 32-bit process probe",
    },
    StringSig {
        needle: "ida64",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: true,
        note: "ida 64-bit process probe",
    },
    StringSig {
        needle: "x96dbg",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "x64dbg launcher process probe",
    },
    StringSig {
        needle: "scyllahide",
        class: SigClass::AntiTool,
        confidence: Confidence::High,
        word_bounded: false,
        note: "scyllahide anti-anti-debug plugin probe",
    },
    StringSig {
        needle: "processhacker",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "process hacker analysis tool probe",
    },
    StringSig {
        needle: "procexp",
        class: SigClass::AntiTool,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "process explorer analysis tool probe",
    },
    StringSig {
        needle: "tcpview",
        class: SigClass::AntiTool,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "tcpview network analysis tool probe",
    },
    StringSig {
        needle: "autoruns",
        class: SigClass::AntiTool,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "autoruns persistence analysis tool probe",
    },
    StringSig {
        needle: "fiddler",
        class: SigClass::AntiTool,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "fiddler http proxy analysis tool probe",
    },
    StringSig {
        needle: "dumpcap",
        class: SigClass::AntiTool,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "wireshark dumpcap capture tool probe",
    },
    StringSig {
        needle: "sysanalyzer",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "sysanalyzer dynamic analysis tool probe",
    },
    StringSig {
        needle: "importrec",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "import reconstructor unpacking tool probe",
    },
    StringSig {
        needle: "lordpe",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "lordpe pe editor unpacking tool probe",
    },
    StringSig {
        needle: "pchunter",
        class: SigClass::AntiTool,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "pc hunter kernel inspection tool probe",
    },
    StringSig {
        needle: "vboxservice.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest service process",
    },
    StringSig {
        needle: "vboxtray.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest tray process",
    },
    StringSig {
        needle: "vboxcontrol.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest control process",
    },
    StringSig {
        needle: "vboxdisp.dll",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox display guest dll",
    },
    StringSig {
        needle: "vboxhook.dll",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox hook guest dll",
    },
    StringSig {
        needle: "vboxmrxnp.dll",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox network-provider guest dll",
    },
    StringSig {
        needle: "vboxtrayipc",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox tray ipc named pipe",
    },
    StringSig {
        needle: "vboxminirdrdn",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox mini redirector device",
    },
    StringSig {
        needle: "vboxtraytoolwndclass",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox tray tool window class",
    },
    StringSig {
        needle: "vboxguestadditions",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest additions install marker",
    },
    StringSig {
        needle: "vbox guest additions",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtualbox guest additions registry string",
    },
    StringSig {
        needle: "vm3dmp.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware svga 3d driver file",
    },
    StringSig {
        needle: "vmrawdsk.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware raw-disk driver file",
    },
    StringSig {
        needle: "vmusbmouse.sys",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware usb mouse driver file",
    },
    StringSig {
        needle: "vgauthservice.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware guest authentication service process",
    },
    StringSig {
        needle: "vmacthlp.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "vmware activation helper process",
    },
    StringSig {
        needle: "vmware tools",
        class: SigClass::AntiVm,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "vmware tools registry/install string",
    },
    StringSig {
        needle: "vmware, inc.",
        class: SigClass::AntiVm,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "vmware smbios manufacturer string",
    },
    StringSig {
        needle: "bhyve bhyve",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "bhyve cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "acrnacrnacrn",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "acrn cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: " lrpepyh vr",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "parallels byte-swapped cpuid hypervisor vendor leaf",
    },
    StringSig {
        needle: "kernel-vmdetection-private",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "ntquerylicensevalue vm-detection probe name",
    },
    StringSig {
        needle: "qemu-ga.exe",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "qemu guest agent process file",
    },
    StringSig {
        needle: "xenservice.exe",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "xen guest service process",
    },
    StringSig {
        needle: "vmsrvc.exe",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtual pc additions service process",
    },
    StringSig {
        needle: "vmusrvc.exe",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtual pc user service process",
    },
    StringSig {
        needle: "vmcheck.dll",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "virtual pc detection dll",
    },
    StringSig {
        needle: "prl_tools.exe",
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        word_bounded: false,
        note: "parallels tools process file",
    },
    StringSig {
        needle: "06/23/99",
        class: SigClass::Hypervisor,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "qemu default smbios bios date",
    },
    StringSig {
        needle: "virtual machine\\guest\\parameters",
        class: SigClass::Hypervisor,
        confidence: Confidence::High,
        word_bounded: false,
        note: "hyper-v guest parameters registry path",
    },
    StringSig {
        needle: "pstorec.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "sunbelt sandbox protected storage hook dll",
    },
    StringSig {
        needle: "api_log.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "idefense sandbox api log hook dll",
    },
    StringSig {
        needle: "dir_watch.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "idefense sandbox directory watch hook dll",
    },
    StringSig {
        needle: "wpespy.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "wpe pro packet editor hook dll",
    },
    StringSig {
        needle: "cmdvrt32.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "comodo sandbox virtualization hook dll",
    },
    StringSig {
        needle: "cmdvrt64.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "comodo sandbox virtualization hook dll",
    },
    StringSig {
        needle: "snxhk.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "avast sandbox hook dll",
    },
    StringSig {
        needle: "avghookx.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "avg behavior-shield hook dll",
    },
    StringSig {
        needle: "avghooka.dll",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "avg behavior-shield hook dll",
    },
    StringSig {
        needle: "frida-agent",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "frida instrumentation agent probe",
    },
    StringSig {
        needle: "frida-gadget",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "frida embedded gadget probe",
    },
    StringSig {
        needle: "gum-js-loop",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "frida gum javascript loop thread probe",
    },
    StringSig {
        needle: "\\\\.\\ntice",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "softice kernel-debugger device probe",
    },
    StringSig {
        needle: "\\\\.\\sice",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "softice device probe",
    },
    StringSig {
        needle: "\\\\.\\syser",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "syser kernel-debugger device probe",
    },
    StringSig {
        needle: "\\\\.\\trw",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "trw kernel-debugger device probe",
    },
    StringSig {
        needle: "software\\wine",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "wine emulation-layer registry probe",
    },
    StringSig {
        needle: "\\\\.\\winex11",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "wine x11 driver device probe",
    },
    StringSig {
        needle: "wine_get_version",
        class: SigClass::Sandbox,
        confidence: Confidence::High,
        word_bounded: false,
        note: "wine ntdll version export probe",
    },
    StringSig {
        needle: "globalmemorystatusex",
        class: SigClass::ResourceFloor,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "physical-memory floor query",
    },
    StringSig {
        needle: "getdiskfreespaceex",
        class: SigClass::ResourceFloor,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "disk-size floor query",
    },
    StringSig {
        needle: "getsystempowerstatus",
        class: SigClass::ResourceFloor,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "battery-presence sandbox query",
    },
    StringSig {
        needle: "ioctl_disk_get_length_info",
        class: SigClass::ResourceFloor,
        confidence: Confidence::Medium,
        word_bounded: false,
        note: "raw disk-length floor probe",
    },
    StringSig {
        needle: "getcursorpos",
        class: SigClass::Interaction,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "mouse-position interaction probe",
    },
    StringSig {
        needle: "getlastinputinfo",
        class: SigClass::Interaction,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "idle-time interaction probe",
    },
    StringSig {
        needle: "getforegroundwindow",
        class: SigClass::Interaction,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "foreground-window interaction probe",
    },
    StringSig {
        needle: "getasynckeystate",
        class: SigClass::Interaction,
        confidence: Confidence::Low,
        word_bounded: false,
        note: "keystroke interaction probe",
    },
];

#[derive(Debug, Clone, Copy)]
pub struct UsernameSig {
    pub needle: &'static str,
    pub note: &'static str,
}

pub static ANALYSIS_USERNAME_SIGS: &[UsernameSig] = &[
    UsernameSig {
        needle: "sandbox",
        note: "known sandbox account name",
    },
    UsernameSig {
        needle: "malware",
        note: "known analysis account name",
    },
    UsernameSig {
        needle: "maltest",
        note: "known analysis account name",
    },
    UsernameSig {
        needle: "virus",
        note: "known analysis account name",
    },
    UsernameSig {
        needle: "currentuser",
        note: "default sample-runner account name",
    },
    UsernameSig {
        needle: "john doe",
        note: "default sandbox profile account name",
    },
    UsernameSig {
        needle: "wdagutilityaccount",
        note: "windows defender application guard account",
    },
    UsernameSig {
        needle: "tequilaboomboom",
        note: "known sandbox hostname",
    },
    UsernameSig {
        needle: "klone_x64-pc",
        note: "known sandbox hostname",
    },
    UsernameSig {
        needle: "john-pc",
        note: "default sandbox profile hostname",
    },
    UsernameSig {
        needle: "systemit",
        note: "known sandbox hostname",
    },
    UsernameSig {
        needle: "7man2",
        note: "known sandbox account name",
    },
    UsernameSig {
        needle: "andy",
        note: "default sandbox profile account name",
    },
    UsernameSig {
        needle: "peter",
        note: "default sandbox profile account name",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberCorroboration {
    Standalone,
    Corroborated,
}

#[derive(Debug, Clone, Copy)]
pub struct NumberSig {
    pub value: u32,
    pub class: SigClass,
    pub confidence: Confidence,
    pub corroboration: NumberCorroboration,
    pub note: &'static str,
}

pub static NUMBER_SIGS: &[NumberSig] = &[
    NumberSig {
        value: 0x564d_5868,
        class: SigClass::AntiVm,
        confidence: Confidence::High,
        corroboration: NumberCorroboration::Standalone,
        note: "vmware vmxh backdoor magic in eax",
    },
    NumberSig {
        value: 0x0000_5658,
        class: SigClass::AntiVm,
        confidence: Confidence::Medium,
        corroboration: NumberCorroboration::Corroborated,
        note: "vmware backdoor io port vx",
    },
    NumberSig {
        value: 0xc000_0008,
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        corroboration: NumberCorroboration::Corroborated,
        note: "exception-invalid-handle close-trick code",
    },
    NumberSig {
        value: 0x4001_0006,
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        corroboration: NumberCorroboration::Standalone,
        note: "dbg-printexception-c output-debug-string trap code",
    },
    NumberSig {
        value: 0x4001_000a,
        class: SigClass::AntiDebug,
        confidence: Confidence::High,
        corroboration: NumberCorroboration::Standalone,
        note: "dbg-printexception-wide-c output-debug-string trap code",
    },
    NumberSig {
        value: 0x8000_0001,
        class: SigClass::AntiDebug,
        confidence: Confidence::Medium,
        corroboration: NumberCorroboration::Corroborated,
        note: "status-guard-page-violation page-guard trap code",
    },
    NumberSig {
        value: 0x000a_fe74,
        class: SigClass::ResourceFloor,
        confidence: Confidence::Medium,
        corroboration: NumberCorroboration::Standalone,
        note: "pafish 12-minute uptime floor in milliseconds",
    },
    NumberSig {
        value: 0x4000_0000,
        class: SigClass::Hypervisor,
        confidence: Confidence::Low,
        corroboration: NumberCorroboration::Corroborated,
        note: "cpuid hypervisor-vendor leaf selector",
    },
];

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_low_to_high() {
        assert!(Confidence::Info < Confidence::Low);
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn all_string_sig_needles_are_lowercase_and_nonempty() {
        for sig in STRING_SIGS {
            assert!(!sig.needle.is_empty(), "empty needle: {sig:?}");
            assert_eq!(
                sig.needle,
                sig.needle.to_ascii_lowercase(),
                "needle must be lowercase for case-insensitive matching: {sig:?}"
            );
        }
    }

    #[test]
    fn no_duplicate_string_sig_needles() {
        let mut seen: Vec<&'static str> =
            STRING_SIGS.iter().map(|s: &StringSig| s.needle).collect();
        let total: usize = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(total, seen.len(), "duplicate needle in STRING_SIGS");
    }

    #[test]
    fn number_sigs_are_nonzero_and_unique() {
        let mut seen: Vec<u32> = NUMBER_SIGS.iter().map(|s: &NumberSig| s.value).collect();
        let total: usize = seen.len();
        for sig in NUMBER_SIGS {
            assert_ne!(sig.value, 0, "zero number sig: {sig:?}");
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(total, seen.len(), "duplicate value in NUMBER_SIGS");
    }

    #[test]
    fn ubiquitous_constants_are_corroboration_gated() {
        for sig in NUMBER_SIGS
            .iter()
            .filter(|s: &&NumberSig| s.value == 0x4000_0000)
        {
            assert_eq!(
                sig.corroboration,
                NumberCorroboration::Corroborated,
                "cpuid-leaf selector is ubiquitous and must be corroboration gated"
            );
        }
    }

    #[test]
    fn mac_ouis_use_canonical_colon_form() {
        for sig in STRING_SIGS
            .iter()
            .filter(|s: &&StringSig| matches!(s.class, SigClass::VmMacOui))
        {
            assert_eq!(sig.needle.len(), 8, "mac oui prefix must be aa:bb:cc form");
            assert_eq!(sig.needle.as_bytes()[2], b':');
            assert_eq!(sig.needle.as_bytes()[5], b':');
            assert!(sig.word_bounded, "mac oui matches must be word bounded");
        }
    }
}
