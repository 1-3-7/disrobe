# Crash records

`disrobe crash <file>` triages a crash record without a debugger: Linux ELF core files (32- and 64-bit, either byte order) and minidumps written by Windows (`MiniDumpWriteDump`, Task Manager, WER), Breakpad or Crashpad.

```sh
disrobe crash core.4242                 # fault, threads, modules, memory totals
disrobe crash app.dmp --registers       # also every thread's registers
disrobe crash core.4242 --json
```

## What it reports

- The fault. For a core: the signal with its name and `si_code` reason (`SIGSEGV SEGV_MAPERR`, `SIGBUS BUS_ADRALN`, `SIGFPE FPE_INTDIV`), the faulting data address for `SIGSEGV` and `SIGBUS`, the faulting instruction for `SIGILL`, `SIGFPE` and `SIGTRAP`, and the sending process and user for signals sent with `kill` or `tgkill`. For a minidump: the exception code with its name (`EXCEPTION_ACCESS_VIOLATION`, `STATUS_STACK_BUFFER_OVERRUN`, C++ and CLR exceptions), the faulting instruction, the access kind and data address of an access violation, and every exception parameter. Each address is placed in its module as `module+offset`.
- Threads, the faulting one marked. Registers are decoded for x86-64, x86, AArch64, 32-bit Arm and RISC-V 64 cores, and for x86-64, x86 and ARM64 minidump contexts; the faulting thread of a minidump shows the context saved with the exception, as a debugger's exception-context view does. Every thread's instruction pointer is placed as `module+offset`, and minidump thread names are shown.
- Return-address candidates: the words above each thread's stack pointer (64 KiB at most) that point into executable memory of a mapped module. This is a stack scan, not an unwound backtrace; frames can be missing or stale.
- Modules. A core's mapped files come from its `NT_FILE` note, each with the GNU build ID read from its in-memory ELF header when the core captured that page. A minidump's modules carry their PDB name and identity (GUID and age, the key a symbol server uses), timestamp and checksum.
- The process: PID, parent, user and group, name and command line from `NT_PRPSINFO`, the executable (the module holding `AT_ENTRY`, or `AT_EXECFN`), the auxiliary vector with `AT_EXECFN` and `AT_PLATFORM` read back as strings, and from a minidump the operating system version, processor count, PID and start time, plus the command line a Breakpad Linux minidump records.
- Memory totals (segments, bytes described, bytes captured, executable ranges) and a count of every note or stream by type.

## Evidence

`crates/disrobe-dataforensics/tests/crash_reference.rs` grades two ways.

- Minidumps written by Windows: a Python script starts three named threads, captures its own CPU context, plants marker values in fifteen registers and an instruction pointer 0x1234 bytes into the Python DLL, and asks `dbghelp!MiniDumpWriteDump` for a dump with that context as an access-violation exception and for a second dump without one. The report must match what the process itself recorded through Windows APIs: OS version and build (`RtlGetVersion`), PID and start time (`GetProcessTimes`), thread names, the faulting thread and its registers, the fault as `python3xx.dll+0x1234`, every module's path, base and size (`EnumProcessModulesEx`), and the PDB identity and timestamp of the Python DLL and `ntdll.dll` as `SymSrvGetFileIndexInfoW` computes them. Every waiting thread's instruction pointer must fall in a module. A changed exception code or register value must fail the comparison, and 300 corrupted dumps must produce a report or a typed error. This runs on Windows hosts.
- ELF cores: a Python script writes six cores byte by byte in the order the Linux kernel writes them (x86-64, the same with more than 65,535-header numbering through section 0, AArch64, i386, RISC-V 64 and big-endian PowerPC 64) and records what it wrote. GNU `readelf` must list the same notes, `NT_FILE` table and `PT_LOAD` count before the test trusts a core. The report must then match every register, thread, signal, reason, address, module with its build ID, auxiliary-vector entry and string, stack-scan candidate and memory total. A changed register, mapped path or build ID must fail the comparison, and 600 corrupted cores must produce a report or a typed error.

## Limits

- Stacks are scanned, not unwound: no CFI, `.pdata` or frame-pointer walking, and no symbol names.
- Core registers for other machines (MIPS, PowerPC, s390x, LoongArch) are not decoded; the report names this, and the rest of the core is still read.
- Signal names follow the generic Linux numbering; cores from MIPS, SPARC, Alpha and PA-RISC show signal numbers without names.
- 32-bit Arm minidump contexts are not decoded. The x86 and ARM64 minidump layouts follow the Windows SDK definitions but have no Windows-written dump in the grader.
- No real kernel-written core is in the grader; cores are authored and validated with `readelf`.
- Threads, modules, segments, notes, auxiliary-vector entries, the scan window and candidates per thread are bounded, and the report's `problems` list names every bound reached and every part it could not read.
