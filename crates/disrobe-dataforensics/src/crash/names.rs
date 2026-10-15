pub(super) const EM_386: u16 = 3;
pub(super) const EM_MIPS: u16 = 8;
pub(super) const EM_PARISC: u16 = 15;
pub(super) const EM_SPARC: u16 = 2;
pub(super) const EM_SPARCV9: u16 = 43;
pub(super) const EM_ALPHA: u16 = 0x9026;
pub(super) const EM_ARM: u16 = 40;
pub(super) const EM_X86_64: u16 = 62;
pub(super) const EM_AARCH64: u16 = 183;
pub(super) const EM_RISCV: u16 = 243;

pub(super) const SIGILL: u32 = 4;
pub(super) const SIGTRAP: u32 = 5;
pub(super) const SIGBUS: u32 = 7;
pub(super) const SIGFPE: u32 = 8;
pub(super) const SIGSEGV: u32 = 11;
pub(super) const SIGSYS: u32 = 31;

pub(super) const fn generic_signal_numbers(machine: u16) -> bool {
    !matches!(
        machine,
        EM_MIPS | EM_SPARC | EM_SPARCV9 | EM_ALPHA | EM_PARISC
    )
}

pub(super) const fn signal_name(signal: u32) -> Option<&'static str> {
    Some(match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        _ => return None,
    })
}

pub(super) const fn signal_code_name(signal: u32, code: i32) -> Option<&'static str> {
    if code <= 0 || code == 0x80 {
        return Some(match code {
            0 => "SI_USER",
            0x80 => "SI_KERNEL",
            -1 => "SI_QUEUE",
            -2 => "SI_TIMER",
            -3 => "SI_MESGQ",
            -4 => "SI_ASYNCIO",
            -5 => "SI_SIGIO",
            -6 => "SI_TKILL",
            -7 => "SI_DETHREAD",
            -60 => "SI_ASYNCNL",
            _ => return None,
        });
    }
    Some(match (signal, code) {
        (SIGSEGV, 1) => "SEGV_MAPERR",
        (SIGSEGV, 2) => "SEGV_ACCERR",
        (SIGSEGV, 3) => "SEGV_BNDERR",
        (SIGSEGV, 4) => "SEGV_PKUERR",
        (SIGSEGV, 5) => "SEGV_ACCADI",
        (SIGSEGV, 6) => "SEGV_ADIDERR",
        (SIGSEGV, 7) => "SEGV_ADIPERR",
        (SIGSEGV, 8) => "SEGV_MTEAERR",
        (SIGSEGV, 9) => "SEGV_MTESERR",
        (SIGSEGV, 10) => "SEGV_CPERR",
        (SIGBUS, 1) => "BUS_ADRALN",
        (SIGBUS, 2) => "BUS_ADRERR",
        (SIGBUS, 3) => "BUS_OBJERR",
        (SIGBUS, 4) => "BUS_MCEERR_AR",
        (SIGBUS, 5) => "BUS_MCEERR_AO",
        (SIGILL, 1) => "ILL_ILLOPC",
        (SIGILL, 2) => "ILL_ILLOPN",
        (SIGILL, 3) => "ILL_ILLADR",
        (SIGILL, 4) => "ILL_ILLTRP",
        (SIGILL, 5) => "ILL_PRVOPC",
        (SIGILL, 6) => "ILL_PRVREG",
        (SIGILL, 7) => "ILL_COPROC",
        (SIGILL, 8) => "ILL_BADSTK",
        (SIGILL, 9) => "ILL_BADIADDR",
        (SIGFPE, 1) => "FPE_INTDIV",
        (SIGFPE, 2) => "FPE_INTOVF",
        (SIGFPE, 3) => "FPE_FLTDIV",
        (SIGFPE, 4) => "FPE_FLTOVF",
        (SIGFPE, 5) => "FPE_FLTUND",
        (SIGFPE, 6) => "FPE_FLTRES",
        (SIGFPE, 7) => "FPE_FLTINV",
        (SIGFPE, 8) => "FPE_FLTSUB",
        (SIGFPE, 14) => "FPE_FLTUNK",
        (SIGFPE, 15) => "FPE_CONDTRAP",
        (SIGTRAP, 1) => "TRAP_BRKPT",
        (SIGTRAP, 2) => "TRAP_TRACE",
        (SIGTRAP, 3) => "TRAP_BRANCH",
        (SIGTRAP, 4) => "TRAP_HWBKPT",
        (SIGTRAP, 5) => "TRAP_UNK",
        (SIGTRAP, 6) => "TRAP_PERF",
        (SIGSYS, 1) => "SYS_SECCOMP",
        (SIGSYS, 2) => "SYS_USER_DISPATCH",
        _ => return None,
    })
}

pub(super) const fn exception_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x4001_0006 => "DBG_PRINTEXCEPTION_C",
        0x4001_000A => "DBG_PRINTEXCEPTION_WIDE_C",
        0x406D_1388 => "MS_VC_SET_THREAD_NAME",
        0x8000_0002 => "EXCEPTION_DATATYPE_MISALIGNMENT",
        0x8000_0003 => "EXCEPTION_BREAKPOINT",
        0x8000_0004 => "EXCEPTION_SINGLE_STEP",
        0xC000_0005 => "EXCEPTION_ACCESS_VIOLATION",
        0xC000_0006 => "EXCEPTION_IN_PAGE_ERROR",
        0xC000_0008 => "EXCEPTION_INVALID_HANDLE",
        0xC000_001D => "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xC000_0025 => "EXCEPTION_NONCONTINUABLE_EXCEPTION",
        0xC000_0026 => "EXCEPTION_INVALID_DISPOSITION",
        0xC000_008C => "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
        0xC000_008D => "EXCEPTION_FLT_DENORMAL_OPERAND",
        0xC000_008E => "EXCEPTION_FLT_DIVIDE_BY_ZERO",
        0xC000_008F => "EXCEPTION_FLT_INEXACT_RESULT",
        0xC000_0090 => "EXCEPTION_FLT_INVALID_OPERATION",
        0xC000_0091 => "EXCEPTION_FLT_OVERFLOW",
        0xC000_0092 => "EXCEPTION_FLT_STACK_CHECK",
        0xC000_0093 => "EXCEPTION_FLT_UNDERFLOW",
        0xC000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xC000_0095 => "EXCEPTION_INT_OVERFLOW",
        0xC000_0096 => "EXCEPTION_PRIV_INSTRUCTION",
        0xC000_00FD => "EXCEPTION_STACK_OVERFLOW",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        0xC000_0139 => "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000_013A => "STATUS_CONTROL_C_EXIT",
        0xC000_0142 => "STATUS_DLL_INIT_FAILED",
        0xC000_0194 => "EXCEPTION_POSSIBLE_DEADLOCK",
        0xC000_0374 => "STATUS_HEAP_CORRUPTION",
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xC000_0417 => "STATUS_INVALID_CRUNTIME_PARAMETER",
        0xC000_0420 => "STATUS_ASSERTION_FAILURE",
        0xC000_0602 => "STATUS_FAIL_FAST_EXCEPTION",
        0xC000_041D => "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
        0xE043_4352 => "CLR_EXCEPTION",
        0xE043_4F4D => "CLR_EXCEPTION_COMPLUS",
        0xE06D_7363 => "CPP_EH_EXCEPTION",
        _ => return None,
    })
}

pub(super) const fn aux_name(key: u64) -> Option<&'static str> {
    Some(match key {
        0 => "AT_NULL",
        1 => "AT_IGNORE",
        2 => "AT_EXECFD",
        3 => "AT_PHDR",
        4 => "AT_PHENT",
        5 => "AT_PHNUM",
        6 => "AT_PAGESZ",
        7 => "AT_BASE",
        8 => "AT_FLAGS",
        9 => "AT_ENTRY",
        10 => "AT_NOTELF",
        11 => "AT_UID",
        12 => "AT_EUID",
        13 => "AT_GID",
        14 => "AT_EGID",
        15 => "AT_PLATFORM",
        16 => "AT_HWCAP",
        17 => "AT_CLKTCK",
        23 => "AT_SECURE",
        24 => "AT_BASE_PLATFORM",
        25 => "AT_RANDOM",
        26 => "AT_HWCAP2",
        27 => "AT_RSEQ_FEATURE_SIZE",
        28 => "AT_RSEQ_ALIGN",
        29 => "AT_HWCAP3",
        30 => "AT_HWCAP4",
        31 => "AT_EXECFN",
        32 => "AT_SYSINFO",
        33 => "AT_SYSINFO_EHDR",
        51 => "AT_MINSIGSTKSZ",
        _ => return None,
    })
}

pub(super) const AT_ENTRY: u64 = 9;
pub(super) const AT_PLATFORM: u64 = 15;
pub(super) const AT_BASE_PLATFORM: u64 = 24;
pub(super) const AT_EXECFN: u64 = 31;

pub(super) const NT_PRSTATUS: u32 = 1;
pub(super) const NT_PRPSINFO: u32 = 3;
pub(super) const NT_AUXV: u32 = 6;
pub(super) const NT_SIGINFO: u32 = 0x5349_4749;
pub(super) const NT_FILE: u32 = 0x4649_4C45;
pub(super) const NT_GNU_BUILD_ID: u32 = 3;

pub(super) fn note_name(owner: &[u8], kind: u32) -> String {
    let label: Option<&'static str> = match (owner, kind) {
        (b"CORE", 1) => Some("NT_PRSTATUS"),
        (b"CORE", 2) => Some("NT_PRFPREG"),
        (b"CORE", 3) => Some("NT_PRPSINFO"),
        (b"CORE", 4) => Some("NT_TASKSTRUCT"),
        (b"CORE", 6) => Some("NT_AUXV"),
        (b"CORE", NT_SIGINFO) => Some("NT_SIGINFO"),
        (b"CORE", NT_FILE) => Some("NT_FILE"),
        (b"LINUX", 0x46E6_2B7F) => Some("NT_PRXFPREG"),
        (b"LINUX", 0x200) => Some("NT_386_TLS"),
        (b"LINUX", 0x201) => Some("NT_386_IOPERM"),
        (b"LINUX", 0x202) => Some("NT_X86_XSTATE"),
        (b"LINUX", 0x204) => Some("NT_X86_SHSTK"),
        (b"LINUX", 0x400) => Some("NT_ARM_VFP"),
        (b"LINUX", 0x401) => Some("NT_ARM_TLS"),
        (b"LINUX", 0x402) => Some("NT_ARM_HW_BREAK"),
        (b"LINUX", 0x403) => Some("NT_ARM_HW_WATCH"),
        (b"LINUX", 0x404) => Some("NT_ARM_SYSTEM_CALL"),
        (b"LINUX", 0x405) => Some("NT_ARM_SVE"),
        (b"LINUX", 0x406) => Some("NT_ARM_PAC_MASK"),
        (b"LINUX", 0x409) => Some("NT_ARM_TAGGED_ADDR_CTRL"),
        (b"LINUX", 0x40A) => Some("NT_ARM_PAC_ENABLED_KEYS"),
        (b"LINUX", 0x40B) => Some("NT_ARM_SSVE"),
        (b"LINUX", 0x40C) => Some("NT_ARM_ZA"),
        (b"LINUX", 0x900) => Some("NT_RISCV_CSR"),
        (b"LINUX", 0x901) => Some("NT_RISCV_VECTOR"),
        _ => None,
    };
    label.map_or_else(
        || format!("{}/0x{kind:x}", String::from_utf8_lossy(owner)),
        str::to_owned,
    )
}

pub(super) fn stream_name(kind: u32) -> String {
    let label: Option<&'static str> = match kind {
        3 => Some("ThreadListStream"),
        4 => Some("ModuleListStream"),
        5 => Some("MemoryListStream"),
        6 => Some("ExceptionStream"),
        7 => Some("SystemInfoStream"),
        8 => Some("ThreadExListStream"),
        9 => Some("Memory64ListStream"),
        10 => Some("CommentStreamA"),
        11 => Some("CommentStreamW"),
        12 => Some("HandleDataStream"),
        13 => Some("FunctionTableStream"),
        14 => Some("UnloadedModuleListStream"),
        15 => Some("MiscInfoStream"),
        16 => Some("MemoryInfoListStream"),
        17 => Some("ThreadInfoListStream"),
        18 => Some("HandleOperationListStream"),
        19 => Some("TokenStream"),
        20 => Some("JavaScriptDataStream"),
        21 => Some("SystemMemoryInfoStream"),
        22 => Some("ProcessVmCountersStream"),
        23 => Some("IptTraceStream"),
        24 => Some("ThreadNamesStream"),
        0x4767_0001 => Some("BreakpadInfoStream"),
        0x4767_0002 => Some("BreakpadAssertionInfoStream"),
        0x4767_0003 => Some("LinuxCpuInfoStream"),
        0x4767_0004 => Some("LinuxProcStatusStream"),
        0x4767_0005 => Some("LinuxLsbReleaseStream"),
        0x4767_0006 => Some("LinuxCmdLineStream"),
        0x4767_0007 => Some("LinuxEnvironStream"),
        0x4767_0008 => Some("LinuxAuxvStream"),
        0x4767_0009 => Some("LinuxMapsStream"),
        0x4767_000A => Some("LinuxDsoDebugStream"),
        0x4350_0001 => Some("CrashpadInfoStream"),
        _ => None,
    };
    label.map_or_else(|| format!("stream/0x{kind:x}"), str::to_owned)
}

pub(super) const fn platform_name(platform: u32) -> &'static str {
    match platform {
        0 => "win32s",
        1 => "windows-9x",
        2 => "windows-nt",
        3 => "windows-ce",
        0x8000 => "unix",
        0x8101 => "macos",
        0x8102 => "ios",
        0x8201 => "linux",
        0x8202 => "solaris",
        0x8203 => "android",
        0x8204 => "ps3",
        0x8205 => "nacl",
        0x8206 => "fuchsia",
        _ => "unknown",
    }
}
