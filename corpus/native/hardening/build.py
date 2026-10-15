import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

ELF_FORTIFIED = ["__memcpy_chk", "__printf_chk"]
ELF_FORTIFIABLE_PLAIN = ["memcpy", "printf", "strcpy"]
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_NO_HEAP_EXECUTION = 0x1000000
LC_ENCRYPTION_INFO_64 = 0x2C
ARC_ENTRY_POINTS = {
    "_objc_autoreleaseReturnValue",
    "_objc_retainAutoreleaseReturnValue",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_storeStrong",
}


class BuildError(Exception):
    pass


@dataclass
class Tools:
    llvm: Path
    msvc: Path
    kits: Path
    sdk: str
    rcodesign: Path

    def llvm_tool(self, name):
        return str(self.llvm / f"{name}.exe") if os.name == "nt" else str(self.llvm / name)

    def resolve(self, key, arch):
        if key == "cl":
            return str(self.msvc / "bin" / "Hostx64" / arch / "cl.exe")
        if key == "link":
            return str(self.msvc / "bin" / "Hostx64" / arch / "link.exe")
        if key == "rcodesign":
            return str(self.rcodesign)
        return self.llvm_tool(key)

    def environment(self, arch):
        env = dict(os.environ)
        if arch is not None:
            env["INCLUDE"] = ";".join(
                str(p)
                for p in [
                    self.msvc / "include",
                    self.kits / "Include" / self.sdk / "ucrt",
                    self.kits / "Include" / self.sdk / "um",
                    self.kits / "Include" / self.sdk / "shared",
                ]
            )
            env["LIB"] = ";".join(
                str(p)
                for p in [
                    self.msvc / "lib" / arch,
                    self.kits / "Lib" / self.sdk / "ucrt" / arch,
                    self.kits / "Lib" / self.sdk / "um" / arch,
                ]
            )
        env["PATH"] = str(self.llvm) + os.pathsep + env.get("PATH", "")
        return env


@dataclass
class Step:
    tool: str
    args: list
    arch: str = None

    def display(self):
        return " ".join([self.tool] + [quote(a) for a in self.args])


@dataclass
class Patch:
    description: str
    apply: object

    def display(self):
        return f"patch: {self.description}"


@dataclass
class Fixture:
    name: str
    format: str
    source: list
    toolchain: str
    steps: list
    expect: dict
    output: str
    fortify: tuple = None
    description: str = ""
    observed: dict = field(default_factory=dict)
    reference: dict = field(default_factory=dict)


def quote(arg):
    return f'"{arg}"' if " " in arg else arg


def run(tools, step, work):
    argv = [tools.resolve(step.tool, step.arch)] + step.args
    completed = subprocess.run(
        argv,
        cwd=work,
        env=tools.environment(step.arch),
        capture_output=True,
        text=True,
        creationflags=NO_WINDOW,
        timeout=300,
    )
    if completed.returncode != 0:
        raise BuildError(f"{step.display()} exited {completed.returncode}\n{completed.stdout}\n{completed.stderr}")
    return completed.stdout


def capture(tools, tool, args, work, arch=None):
    return run(tools, Step(tool, args, arch), work)


def elf_fixture(name, target, description, *, canary, pie, relro, fortify, execstack, cet, rpath, strip, static_pie=False):
    compile_flags = ["--target=" + target, "-O2", "-fno-asynchronous-unwind-tables", "-Wno-builtin-requires-header"]
    compile_flags += ["-fstack-protector-strong"] if canary else ["-fno-stack-protector"]
    compile_flags += ["-D_FORTIFY_SOURCE=2"] if fortify else ["-U_FORTIFY_SOURCE"]
    if target.startswith("x86_64"):
        compile_flags += ["-fcf-protection=" + cet]
    else:
        compile_flags += ["-mbranch-protection=" + cet]
    link_flags = ["-nostdlib", "-fuse-ld=lld", "-Wl,--hash-style=gnu"]
    if static_pie:
        compile_flags += ["-fPIE"]
        link_flags += ["-static-pie"]
    elif pie:
        compile_flags += ["-fPIE"]
        link_flags += ["-pie"]
    else:
        compile_flags += ["-fno-pic"]
        link_flags += ["-no-pie"]
    if not static_pie:
        interpreter = "/lib64/ld-linux-x86-64.so.2" if target.startswith("x86_64") else "/lib/ld-linux-aarch64.so.1"
        link_flags += ["-Wl,--dynamic-linker=" + interpreter]
    link_flags += {
        "full": ["-Wl,-z,relro,-z,now"],
        "partial": ["-Wl,-z,relro,-z,lazy"],
        "none": ["-Wl,-z,norelro,-z,lazy"],
    }[relro]
    link_flags += ["-Wl,-z,execstack"] if execstack else ["-Wl,-z,noexecstack"]
    if rpath == "rpath":
        link_flags += ["-Wl,--disable-new-dtags,-rpath,/opt/hardening/lib"]
    elif rpath == "runpath":
        link_flags += ["-Wl,--enable-new-dtags,-rpath,/opt/hardening/lib"]
    if strip:
        link_flags += ["-Wl,--strip-all"]
    stub = f"libc-{target}.so.6"
    steps = []
    if static_pie:
        steps.append(
            Step(
                "clang",
                compile_flags
                + ["-ffreestanding", "-fno-builtin"]
                + link_flags
                + ["elf_prog.c", "elf_libc_stub.c", "-o", name],
            )
        )
    else:
        steps.append(
            Step(
                "clang",
                [
                    "--target=" + target,
                    "-O2",
                    "-fPIC",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-shared",
                    "-nostdlib",
                    "-fuse-ld=lld",
                    "-Wl,-soname,libc.so.6",
                    "elf_libc_stub.c",
                    "-o",
                    stub,
                ],
            )
        )
        steps.append(Step("clang", compile_flags + link_flags + ["elf_prog.c", stub, "-o", name]))
    arm = not target.startswith("x86_64")
    expect = {
        "nx": "absent" if execstack else "present",
        "pie": "present" if (pie or static_pie) else "absent",
        "relro": {"full": "present", "partial": "partial", "none": "absent"}[relro],
        "stack-canary": "present" if canary else "absent",
        "fortify": ("undetermined" if static_pie else ("present" if fortify else "absent")),
        "rpath": "present" if rpath == "rpath" else "absent",
        "runpath": "present" if rpath == "runpath" else "absent",
        "symbols": "absent" if strip else "present",
    }
    if arm:
        expect["bti"] = "present" if cet in ("standard", "bti") else "absent"
        expect["pac"] = "present" if cet in ("standard", "pac-ret") else "absent"
    else:
        expect["ibt"] = "present" if cet in ("full", "branch") else "absent"
        expect["shstk"] = "present" if cet in ("full", "return") else "absent"
    fortify_counts = None
    if not static_pie:
        fortify_counts = (2, 3) if fortify else (0, 3)
    return Fixture(
        name=name,
        format="elf",
        source=["src/elf_prog.c", "src/fortify_shim.h", "src/elf_libc_stub.c"],
        toolchain="clang 19.1.7, ld.lld 19.1.7",
        steps=steps,
        expect=expect,
        output=name,
        fortify=fortify_counts,
        description=description,
    )


def elf_dso_fixture():
    name = "elf-x86_64-dso.so"
    steps = [
        Step(
            "clang",
            [
                "--target=x86_64-linux-gnu",
                "-O2",
                "-fPIC",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-shared",
                "-nostdlib",
                "-fuse-ld=lld",
                "-Wl,-soname,libc.so.6",
                "-Wl,-z,relro,-z,now",
                "elf_libc_stub.c",
                "-o",
                name,
            ],
        )
    ]
    expect = {
        "nx": "present",
        "pie": "not-applicable",
        "relro": "present",
        "stack-canary": "absent",
        "fortify": "not-applicable",
        "rpath": "absent",
        "runpath": "absent",
        "symbols": "present",
        "ibt": "absent",
        "shstk": "absent",
    }
    return Fixture(
        name=name,
        format="elf",
        source=["src/elf_libc_stub.c"],
        toolchain="clang 19.1.7, ld.lld 19.1.7",
        steps=steps,
        expect=expect,
        output=name,
        fortify=(0, 0),
        description="the stub libc.so.6 the other ELF fixtures link against: a shared object that defines __stack_chk_fail and the fortified entry points and imports nothing",
    )


def macho_fixture(name, arch, description, *, objc, arc, canary, pie, adhoc, encryptable, restrict, runtime_sign, cryptid, exec_flags):
    target = f"{arch}-apple-macos11"
    base = ["--target=" + target, "-isysroot", "sdk", "-O2", "-fno-asynchronous-unwind-tables"]
    steps = [
        Step(
            "clang",
            base
            + ["-nostdlib", "-fuse-ld=lld", "-shared", "-Wl,-install_name,/usr/lib/libSystem.B.dylib"]
            + ["macho_libsystem_stub.c", "-o", "libSystem.B.dylib"],
        )
    ]
    inputs = ["macho_helper.c", "libSystem.B.dylib"]
    sources = ["src/macho_helper.c", "src/macho_libsystem_stub.c"]
    if objc:
        steps.append(
            Step(
                "clang",
                base
                + ["-nostdlib", "-fuse-ld=lld", "-shared", "-Wl,-install_name,/usr/lib/libobjc.A.dylib"]
                + ["macho_libobjc_stub.c", "-o", "libobjc.A.dylib"],
            )
        )
        inputs = ["-x", "objective-c", "macho_objc.m", "-x", "none"] + inputs + ["libobjc.A.dylib"]
        sources = ["src/macho_objc.m", "src/macho_libobjc_stub.c"] + sources
    else:
        inputs = ["macho_prog.c"] + inputs
        sources = ["src/macho_prog.c"] + sources
    compile_flags = list(base)
    compile_flags += ["-fstack-protector-strong"] if canary else ["-fno-stack-protector"]
    if objc:
        compile_flags += ["-fobjc-arc"] if arc else ["-fno-objc-arc"]
        compile_flags += ["-Wno-objc-root-class"]
    link_flags = ["-nostdlib", "-fuse-ld=lld"]
    link_flags += ["-Wl,-pie"] if pie else ["-Wl,-no_pie"]
    link_flags += ["-Wl,-adhoc_codesign"] if adhoc else ["-Wl,-no_adhoc_codesign"]
    if encryptable:
        link_flags += ["-Wl,-encryptable"]
    if restrict:
        link_flags += ["-Wl,-sectcreate,__RESTRICT,__restrict,restrict.empty"]
    linked = name if not (exec_flags or cryptid or runtime_sign) else name + ".linked"
    steps.append(Step("clang", compile_flags + link_flags + inputs + ["-o", linked]))
    current = linked
    if exec_flags:
        steps.append(
            Patch(
                f"{current} -> {name}: mach_header_64.flags |= MH_ALLOW_STACK_EXECUTION (0x20000) | MH_NO_HEAP_EXECUTION (0x1000000)",
                lambda work, src=current, dst=name: patch_macho_flags(work / src, work / dst),
            )
        )
        current = name
    if cryptid:
        patched = name + ".encrypted" if runtime_sign is not None else name
        steps.append(
            Patch(
                f"{current} -> {patched}: LC_ENCRYPTION_INFO_64.cryptid = 1",
                lambda work, src=current, dst=patched: patch_macho_cryptid(work / src, work / dst),
            )
        )
        current = patched
    if runtime_sign is not None:
        sign_args = ["sign", "--binary-identifier", "org.disrobe.hardening." + name]
        if runtime_sign:
            sign_args += ["--code-signature-flags", "runtime"]
        steps.append(Step("rcodesign", sign_args + [current, name]))
    signed = adhoc or runtime_sign is not None
    expect = {
        "pie": "present" if pie else "absent",
        "nx-heap": "present" if exec_flags else "absent",
        "nx-stack": "absent" if exec_flags else "present",
        "stack-canary": "present" if canary else "absent",
        "arc": ("present" if arc else "absent") if objc else "not-applicable",
        "code-signature": "present" if signed else "absent",
        "hardened-runtime": "present" if runtime_sign else "absent",
        "encrypted": "present" if cryptid else "absent",
        "restrict": "present" if restrict else "absent",
    }
    toolchain = "clang 19.1.7, ld64.lld 19.1.7"
    if runtime_sign is not None:
        toolchain += ", rcodesign 0.29.0"
    return Fixture(
        name=name,
        format="macho",
        source=sources,
        toolchain=toolchain,
        steps=steps,
        expect=expect,
        output=name,
        description=description,
    )


def patch_macho_flags(src, dst):
    data = bytearray(src.read_bytes())
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        raise BuildError(f"{src.name}: not a little-endian 64-bit Mach-O")
    flags = struct.unpack_from("<I", data, 24)[0]
    struct.pack_into("<I", data, 24, flags | MH_ALLOW_STACK_EXECUTION | MH_NO_HEAP_EXECUTION)
    dst.write_bytes(bytes(data))


def patch_macho_cryptid(src, dst):
    data = bytearray(src.read_bytes())
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == LC_ENCRYPTION_INFO_64:
            struct.pack_into("<I", data, offset + 16, 1)
            dst.write_bytes(bytes(data))
            return
        offset += cmdsize
    raise BuildError(f"{src.name}: no LC_ENCRYPTION_INFO_64 command to patch")


def pe_fixture(name, arch, toolchain, description, *, crt, gs, guard, xfg, dynamicbase, highentropy, nxcompat, cet, safeseh, integrity, appcontainer):
    obj = name.rsplit(".", 1)[0] + ".obj"
    source = "pe_crt.c" if crt else "pe_nocrt.c"
    msvc_arch = "x64" if arch == "x64" else "x86"
    if toolchain == "msvc":
        compile_tool = "cl"
        link_tool = "link"
        compile_args = ["/nologo", "/O2", "/Brepro", "/c", source, "/Fo" + obj]
    else:
        compile_tool = "clang-cl"
        link_tool = "lld-link"
        target = "x86_64-pc-windows-msvc" if arch == "x64" else "i686-pc-windows-msvc"
        compile_args = ["/nologo", "/O2", "/Brepro", "--target=" + target, "/c", source, "/Fo" + obj]
    compile_args.insert(2, "/GS" if gs else "/GS-")
    if crt:
        compile_args.insert(2, "/MD")
    else:
        compile_args.insert(2, "/Zl")
    if xfg:
        compile_args.insert(2, "/guard:xfg")
    elif guard:
        compile_args.insert(2, "/guard:cf")
    link_args = ["/nologo", "/Brepro", "/INCREMENTAL:NO", "/OUT:" + name, obj]
    if toolchain == "msvc":
        link_args.insert(3, "/MACHINE:" + ("X64" if arch == "x64" else "X86"))
    if crt:
        link_args += ["/SUBSYSTEM:CONSOLE"]
    else:
        link_args += ["/SUBSYSTEM:CONSOLE", "/ENTRY:entry", "/NODEFAULTLIB", "kernel32.lib"]
    link_args.append("/DYNAMICBASE" if dynamicbase else "/DYNAMICBASE:NO")
    if arch == "x64":
        link_args.append("/HIGHENTROPYVA" if highentropy else "/HIGHENTROPYVA:NO")
    link_args.append("/NXCOMPAT" if nxcompat else "/NXCOMPAT:NO")
    link_args.append("/CETCOMPAT" if cet else "/CETCOMPAT:NO")
    if arch == "x86":
        link_args.append("/SAFESEH" if safeseh else "/SAFESEH:NO")
    if xfg:
        link_args.append("/guard:xfg")
    elif guard:
        link_args.append("/guard:cf")
    else:
        link_args.append("/guard:no")
    if integrity:
        link_args.append("/INTEGRITYCHECK")
    if appcontainer:
        link_args.append("/APPCONTAINER")
    steps = [Step(compile_tool, compile_args, msvc_arch), Step(link_tool, link_args, msvc_arch)]
    handlerless = arch == "x86" and safeseh and not crt
    expect = {
        "dynamic-base": "present" if dynamicbase else "absent",
        "high-entropy-va": ("present" if highentropy else "absent") if arch == "x64" else "not-applicable",
        "nx-compat": "present" if nxcompat else "absent",
        "force-integrity": "present" if integrity else "absent",
        "no-seh": "present" if handlerless else "absent",
        "appcontainer": "present" if appcontainer else "absent",
        "safe-seh": ("not-applicable" if handlerless else ("present" if safeseh else "absent")) if arch == "x86" else "not-applicable",
        "gs": "present" if (gs or crt) else "absent",
        "cfg": "present" if (guard or xfg) else "absent",
        "xfg": "present" if xfg else "absent",
        "cet-shadow-stack": "present" if cet else "absent",
        "authenticode": "absent",
    }
    label = "MSVC 19.44.35229 (cl, link 14.44.35229)" if toolchain == "msvc" else "clang-cl 19.1.7, lld-link 19.1.7"
    label += ", Windows SDK 10.0.26100.0"
    if crt:
        label += ", dynamic CRT import libraries (/MD)"
    return Fixture(
        name=name,
        format="pe",
        source=["src/" + source],
        toolchain=label,
        steps=steps,
        expect=expect,
        output=name,
        description=description,
    )


def fixtures():
    return [
        elf_fixture(
            "elf-x86_64-full",
            "x86_64-linux-gnu",
            "every ELF mitigation on: stack protector, PIE, full RELRO, FORTIFY_SOURCE=2, non-executable stack, IBT and SHSTK",
            canary=True, pie=True, relro="full", fortify=True, execstack=False, cet="full", rpath=None, strip=False,
        ),
        elf_fixture(
            "elf-x86_64-none",
            "x86_64-linux-gnu",
            "every ELF mitigation off, a DT_RPATH, and the symbol table stripped",
            canary=False, pie=False, relro="none", fortify=False, execstack=True, cet="none", rpath="rpath", strip=True,
        ),
        elf_fixture(
            "elf-x86_64-partial",
            "x86_64-linux-gnu",
            "partial RELRO (lazy binding), IBT without SHSTK, a DT_RUNPATH, stripped",
            canary=True, pie=True, relro="partial", fortify=False, execstack=False, cet="branch", rpath="runpath", strip=True,
        ),
        elf_fixture(
            "elf-x86_64-static-pie",
            "x86_64-linux-gnu",
            "static PIE: ET_DYN with DF_1_PIE and no PT_INTERP, SHSTK without IBT, libc linked in",
            canary=True, pie=True, relro="full", fortify=True, execstack=False, cet="return", rpath=None, strip=False, static_pie=True,
        ),
        elf_dso_fixture(),
        elf_fixture(
            "elf-aarch64-full",
            "aarch64-linux-gnu",
            "AArch64 with stack protector (global __stack_chk_guard), PIE, full RELRO, FORTIFY_SOURCE=2, BTI and PAC",
            canary=True, pie=True, relro="full", fortify=True, execstack=False, cet="standard", rpath=None, strip=False,
        ),
        elf_fixture(
            "elf-aarch64-none",
            "aarch64-linux-gnu",
            "AArch64 with every mitigation off and a DT_RUNPATH, stripped",
            canary=False, pie=False, relro="none", fortify=False, execstack=True, cet="none", rpath="runpath", strip=True,
        ),
        pe_fixture(
            "pe-x64-msvc-full.exe", "x64", "msvc",
            "MSVC x64 with /GS, /guard:cf, /DYNAMICBASE, /HIGHENTROPYVA, /NXCOMPAT and /CETCOMPAT",
            crt=True, gs=True, guard=True, xfg=False, dynamicbase=True, highentropy=True, nxcompat=True, cet=True, safeseh=False, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x64-msvc-xfg.exe", "x64", "msvc",
            "MSVC x64 with /guard:xfg (XFG on top of CFG)",
            crt=True, gs=True, guard=True, xfg=True, dynamicbase=True, highentropy=True, nxcompat=True, cet=False, safeseh=False, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x64-msvc-off.exe", "x64", "msvc",
            "MSVC x64 with /GS- and every linker mitigation off; the CRT objects still register a security cookie",
            crt=True, gs=False, guard=False, xfg=False, dynamicbase=False, highentropy=False, nxcompat=False, cet=False, safeseh=False, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x86-msvc-full.exe", "x86", "msvc",
            "MSVC x86 with /SAFESEH, /GS, /guard:cf, /DYNAMICBASE, /NXCOMPAT and /CETCOMPAT",
            crt=True, gs=True, guard=True, xfg=False, dynamicbase=True, highentropy=False, nxcompat=True, cet=True, safeseh=True, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x86-msvc-off.exe", "x86", "msvc",
            "MSVC x86 with /SAFESEH:NO, /GS- and every linker mitigation off",
            crt=True, gs=False, guard=False, xfg=False, dynamicbase=False, highentropy=False, nxcompat=False, cet=False, safeseh=False, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x64-clang-integrity.exe", "x64", "clang",
            "clang-cl and lld-link x64 with /INTEGRITYCHECK, /APPCONTAINER, /guard:cf and /cetcompat",
            crt=True, gs=True, guard=True, xfg=False, dynamicbase=True, highentropy=True, nxcompat=True, cet=True, safeseh=False, integrity=True, appcontainer=True,
        ),
        pe_fixture(
            "pe-x64-clang-nocrt.exe", "x64", "clang",
            "clang-cl and lld-link x64 without a C runtime: no load configuration, so no security cookie and no CFG",
            crt=False, gs=False, guard=False, xfg=False, dynamicbase=True, highentropy=False, nxcompat=True, cet=False, safeseh=False, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x86-clang-safeseh.exe", "x86", "clang",
            "clang-cl and lld-link x86 with /safeseh, /GS and /guard:cf against the dynamic CRT",
            crt=True, gs=True, guard=True, xfg=False, dynamicbase=True, highentropy=False, nxcompat=True, cet=False, safeseh=True, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x86-msvc-noseh.exe", "x86", "msvc",
            "MSVC x86 without a C runtime, linked with /SAFESEH: no object registers an exception handler, so link.exe sets NO_SEH instead of writing a handler table",
            crt=False, gs=False, guard=False, xfg=False, dynamicbase=True, highentropy=False, nxcompat=True, cet=False, safeseh=True, integrity=False, appcontainer=False,
        ),
        pe_fixture(
            "pe-x86-clang-nocrt.exe", "x86", "clang",
            "clang-cl and lld-link x86 without a C runtime and without /safeseh",
            crt=False, gs=False, guard=False, xfg=False, dynamicbase=False, highentropy=False, nxcompat=False, cet=False, safeseh=False, integrity=False, appcontainer=False,
        ),
        macho_fixture(
            "macho-x86_64-full", "x86_64",
            "Mach-O x86-64 with stack protector, PIE and the linker's ad-hoc code signature",
            objc=False, arc=False, canary=True, pie=True, adhoc=True, encryptable=False, restrict=False, runtime_sign=None, cryptid=False, exec_flags=False,
        ),
        macho_fixture(
            "macho-x86_64-none", "x86_64",
            "Mach-O x86-64 without stack protector, PIE or code signature",
            objc=False, arc=False, canary=False, pie=False, adhoc=False, encryptable=False, restrict=False, runtime_sign=None, cryptid=False, exec_flags=False,
        ),
        macho_fixture(
            "macho-x86_64-execflags", "x86_64",
            "macho-x86_64-none with MH_ALLOW_STACK_EXECUTION and MH_NO_HEAP_EXECUTION set in the header (ld64.lld has no flag for either)",
            objc=False, arc=False, canary=False, pie=False, adhoc=False, encryptable=False, restrict=False, runtime_sign=None, cryptid=False, exec_flags=True,
        ),
        macho_fixture(
            "macho-x86_64-objc-arc", "x86_64",
            "Objective-C under ARC with a __RESTRICT segment, an LC_ENCRYPTION_INFO_64 with cryptid 0, and an ad-hoc signature carrying the hardened-runtime flag",
            objc=True, arc=True, canary=True, pie=True, adhoc=False, encryptable=True, restrict=True, runtime_sign=True, cryptid=False, exec_flags=False,
        ),
        macho_fixture(
            "macho-x86_64-objc-mrr-encrypted", "x86_64",
            "Objective-C under manual reference counting with cryptid set to 1 before an ad-hoc signature without the hardened-runtime flag",
            objc=True, arc=False, canary=False, pie=True, adhoc=False, encryptable=True, restrict=False, runtime_sign=False, cryptid=True, exec_flags=False,
        ),
        macho_fixture(
            "macho-arm64-full", "arm64",
            "Mach-O arm64 with stack protector, PIE and the linker's default ad-hoc signature",
            objc=False, arc=False, canary=True, pie=True, adhoc=True, encryptable=False, restrict=False, runtime_sign=None, cryptid=False, exec_flags=False,
        ),
    ]


def parse_gnu_readelf(text):
    facts = {"phdrs": {}, "dynamic": {}, "undefined": set(), "sections": set(), "properties": "", "type": None}
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Type:") and facts["type"] is None:
            facts["type"] = stripped.split()[1]
        if stripped.startswith("Program Headers:"):
            section = "phdr"
            continue
        if stripped.startswith("Section Headers:"):
            section = "shdr"
            continue
        if stripped.startswith("Dynamic section"):
            section = "dyn"
            continue
        if stripped.startswith("Symbol table '.dynsym'"):
            section = "dynsym"
            continue
        if section == "phdr":
            parts = stripped.split()
            if parts and parts[0] in ("GNU_STACK", "GNU_RELRO", "INTERP", "DYNAMIC", "GNU_PROPERTY", "LOAD"):
                flags = "".join(p for p in parts[6:-1] if p in ("R", "W", "E", "RW", "RE", "RWE"))
                facts["phdrs"].setdefault(parts[0], []).append(flags)
            if stripped.startswith("Section to Segment"):
                section = None
        elif section == "shdr":
            match = re.match(r"\[\s*\d+\]\s+(\S+)", stripped)
            if match:
                facts["sections"].add(match.group(1))
        elif section == "dyn":
            match = re.match(r"0x[0-9a-f]+\s+\((\w+)\)\s+(.*)", stripped)
            if match:
                facts["dynamic"].setdefault(match.group(1), []).append(match.group(2))
        elif section == "dynsym":
            parts = stripped.split()
            if len(parts) >= 8 and parts[6] == "UND" and parts[7]:
                facts["undefined"].add(parts[7].split("@")[0])
        if "feature:" in stripped:
            facts["properties"] += stripped + "\n"
    return facts


def observe_elf(tools, fixture, work):
    path = fixture.output
    text = capture(
        tools,
        "llvm-readobj",
        ["--elf-output-style=GNU", "--file-headers", "--program-headers", "--section-headers", "--dynamic-table", "--dyn-syms", "--notes", path],
        work,
    )
    facts = parse_gnu_readelf(text)
    observed = {}
    stack = facts["phdrs"].get("GNU_STACK")
    observed["nx"] = "absent" if (stack is None or "E" in stack[0]) else "present"
    flags_1 = " ".join(facts["dynamic"].get("FLAGS_1", [])).split()
    has_interp = "INTERP" in facts["phdrs"]
    shared_object = facts["type"] == "DYN" and not has_interp and "PIE" not in flags_1
    static_image = not has_interp and not shared_object
    if facts["type"] == "EXEC":
        observed["pie"] = "absent"
    elif shared_object:
        observed["pie"] = "not-applicable"
    else:
        observed["pie"] = "present"
    bind_now = "BIND_NOW" in facts["dynamic"] or "BIND_NOW" in " ".join(facts["dynamic"].get("FLAGS", [])) or "NOW" in flags_1
    if "GNU_RELRO" not in facts["phdrs"]:
        observed["relro"] = "absent"
    elif bind_now or "DYNAMIC" not in facts["phdrs"]:
        observed["relro"] = "present"
    else:
        observed["relro"] = "partial"
    canary_names = {"__stack_chk_fail", "__stack_chk_guard"}
    if static_image:
        symtab = capture(tools, "llvm-nm", ["--no-sort", path], work) if ".symtab" in facts["sections"] else ""
        symtab_names = {line.split()[-1] for line in symtab.splitlines() if line.strip()}
        observed["stack-canary"] = "present" if symtab_names & canary_names else "absent"
        observed["fortify"] = "undetermined"
    else:
        observed["stack-canary"] = "present" if facts["undefined"] & canary_names else "absent"
        fortified = sorted(facts["undefined"] & set(ELF_FORTIFIED))
        plain = sorted(facts["undefined"] & set(ELF_FORTIFIABLE_PLAIN))
        if fortified:
            observed["fortify"] = "present"
        elif plain:
            observed["fortify"] = "absent"
        else:
            observed["fortify"] = "not-applicable"
        if (len(fortified), len(fortified) + len(plain)) != fixture.fortify:
            raise BuildError(f"{fixture.name}: llvm-readobj reports fortified {fortified} and plain {plain}, expected counts {fixture.fortify}")
    observed["rpath"] = "present" if "RPATH" in facts["dynamic"] else "absent"
    observed["runpath"] = "present" if "RUNPATH" in facts["dynamic"] else "absent"
    for tag in ("RPATH", "RUNPATH"):
        for value in facts["dynamic"].get(tag, []):
            match = re.search(r"\[(.*)\]", value)
            if match:
                fixture.reference[tag.lower()] = match.group(1)
    observed["symbols"] = "present" if ".symtab" in facts["sections"] else "absent"
    props = facts["properties"]
    if "ibt" in fixture.expect:
        x86 = next((l for l in props.splitlines() if "x86 feature:" in l), "")
        observed["ibt"] = "present" if "IBT" in x86 else "absent"
        observed["shstk"] = "present" if "SHSTK" in x86 else "absent"
    else:
        arm = next((l for l in props.splitlines() if "aarch64 feature:" in l), "")
        observed["bti"] = "present" if "BTI" in arm else "absent"
        observed["pac"] = "present" if "PAC" in arm else "absent"
    return observed


def observe_pe(tools, fixture, work):
    text = capture(tools, "llvm-readobj", ["--file-headers", "--coff-load-config", "--coff-debug-directory", fixture.output], work)
    names = set(re.findall(r"IMAGE_DLL_CHARACTERISTICS_(\w+) \(0x", text))
    file_flags = set(re.findall(r"IMAGE_FILE_(\w+) \(0x", text))
    load_config_size = int(re.search(r"LoadConfigTableSize: (0x[0-9A-F]+)", text).group(1), 16)
    certificate_size = int(re.search(r"CertificateTableSize: (0x[0-9A-F]+)", text).group(1), 16)
    is_x86 = "IMAGE_FILE_MACHINE_I386" in text

    def field_value(label):
        match = re.search(rf"\b{label}: (0x[0-9A-F]+|\d+)", text)
        return int(match.group(1), 0) if match else 0

    guard_match = re.search(r"GuardFlags \[ \((0x[0-9A-F]+)\)", text)
    guard_flags = int(guard_match.group(1), 16) if guard_match else 0
    observed = {
        "dynamic-base": "present" if "DYNAMIC_BASE" in names and "RELOCS_STRIPPED" not in file_flags else "absent",
        "high-entropy-va": "not-applicable" if is_x86 else ("present" if "HIGH_ENTROPY_VA" in names else "absent"),
        "nx-compat": "present" if "NX_COMPAT" in names else "absent",
        "force-integrity": "present" if "FORCE_INTEGRITY" in names else "absent",
        "no-seh": "present" if "NO_SEH" in names else "absent",
        "appcontainer": "present" if "APPCONTAINER" in names else "absent",
        "gs": "present" if load_config_size and field_value("SecurityCookie") else "absent",
        "cfg": "present" if "GUARD_CF" in names and guard_flags & 0x100 else "absent",
        "xfg": "present" if guard_flags & 0x800000 else "absent",
        "cet-shadow-stack": "present" if "IMAGE_DLL_CHARACTERISTICS_EX_CET_COMPAT" in text else "absent",
        "authenticode": "present" if certificate_size else "absent",
    }
    if load_config_size:
        fixture.reference["security_cookie"] = hex(field_value("SecurityCookie"))
        fixture.reference["guard_flags"] = hex(guard_flags)
    if is_x86 and load_config_size:
        fixture.reference["se_handler_count"] = str(field_value("SEHandlerCount"))
    if is_x86 and "NO_SEH" in names:
        observed["safe-seh"] = "not-applicable"
    elif is_x86:
        observed["safe-seh"] = "present" if load_config_size and field_value("SEHandlerTable") and field_value("SEHandlerCount") else "absent"
    else:
        observed["safe-seh"] = "not-applicable"
    return observed


def observe_macho(tools, fixture, work):
    headers = capture(tools, "llvm-objdump", ["--macho", "--private-headers", fixture.output], work)
    header_line = next(l for l in headers.splitlines() if l.startswith("MH_MAGIC"))
    flags = set(header_line.split()[7:])
    undefined = {l.strip() for l in capture(tools, "llvm-nm", ["--undefined-only", "--just-symbol-name", fixture.output], work).splitlines() if l.strip()}
    cryptid = re.findall(r"cryptid (\d+)", headers)
    if cryptid:
        fixture.reference["cryptid"] = cryptid[0]
    observed = {
        "pie": "present" if "PIE" in flags else "absent",
        "nx-heap": "present" if "MH_NO_HEAP_EXECUTION" in flags else "absent",
        "nx-stack": "absent" if "ALLOW_STACK_EXECUTION" in flags else "present",
        "stack-canary": "present" if undefined & {"___stack_chk_fail", "___stack_chk_guard"} else "absent",
        "code-signature": "present" if "LC_CODE_SIGNATURE" in headers else "absent",
        "encrypted": "present" if any(c != "0" for c in cryptid) else "absent",
        "restrict": "present" if re.search(r"segname __RESTRICT", headers) else "absent",
    }
    objc = {name for name in undefined if name.startswith("_objc_")}
    if not objc:
        observed["arc"] = "not-applicable"
    else:
        observed["arc"] = "present" if objc & ARC_ENTRY_POINTS else "absent"
    if observed["code-signature"] == "present":
        info = capture(tools, "rcodesign", ["print-signature-info", fixture.output], work)
        flag_lines = [l for l in info.splitlines() if "flags:" in l.lower() and "CodeSignatureFlags" in l]
        fixture.observed["code_directory_flags"] = flag_lines
        observed["hardened-runtime"] = "present" if any("RUNTIME" in l for l in flag_lines) else "absent"
    else:
        observed["hardened-runtime"] = "absent"
    return observed


def build(tools, fixture, work):
    for step in fixture.steps:
        if isinstance(step, Patch):
            step.apply(work)
        else:
            run(tools, step, work)
    observe = {"elf": observe_elf, "pe": observe_pe, "macho": observe_macho}[fixture.format]
    observed = observe(tools, fixture, work)
    if observed != fixture.expect:
        diff = {k: (fixture.expect.get(k), observed.get(k)) for k in sorted(set(observed) | set(fixture.expect)) if fixture.expect.get(k) != observed.get(k)}
        raise BuildError(f"{fixture.name}: the reference readers disagree with the requested build (expected, observed): {diff}")


def toml_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_manifest(entries, versions):
    lines = [
        'schema = "disrobe.corpus.v1"',
        'crate = "disrobe-pass-native"',
        f'toolchain = {toml_string("; ".join(versions))}',
        'note = "self-authored exploit-mitigation matrix: each fixture is one build of our own C or Objective-C source with chosen hardening flags; the expected verdicts are what the build asked for, confirmed by llvm-readobj, llvm-objdump, llvm-nm and rcodesign print-signature-info before this manifest is written; no fixture is ever executed"',
        "",
        "[provenance]",
        'build = "python -I build.py --llvm <LLVM 19.1.7 bin> --msvc <MSVC 14.44.35207 root> --kits <Windows Kits 10 root> --rcodesign <rcodesign 0.29.0>; every command runs in an empty scratch directory holding copies of src/, with INCLUDE and LIB naming the MSVC and Windows SDK 10.0.26100.0 directories for the target architecture"',
        'cross_check = "python checksec_cross.py with pwntools 4.14.1 compares ELF.checksec with every present, partial and absent ELF verdict: 62 of 62 agree; the stack-canary verdict of the stub shared object differs by definition, because pwntools counts the __stack_chk_fail definition inside the stub and this report counts imports"',
        'stubs = "the ELF fixtures link against a stub libc.so.6 and the Mach-O fixtures against stub libSystem.B.dylib and libobjc.A.dylib, all built from src/ in the same scratch directory, so every import is a real dynamic import the fixtures never resolve at run time"',
        "",
    ]
    for fixture, digest in entries:
        lines.append("[[fixture]]")
        lines.append(f"name = {toml_string(fixture.name)}")
        lines.append(f"path = {toml_string(fixture.output)}")
        lines.append(f"format = {toml_string(fixture.format)}")
        lines.append('provenance = "self-authored"')
        lines.append(f"source = [{', '.join(toml_string(s) for s in fixture.source)}]")
        lines.append(f"toolchain = {toml_string(fixture.toolchain)}")
        lines.append("commands = [")
        for step in fixture.steps:
            lines.append(f"    {toml_string(step.display())},")
        lines.append("]")
        lines.append(f"sha256 = {toml_string(digest)}")
        lines.append(f"description = {toml_string(fixture.description)}")
        if fixture.fortify is not None:
            lines.append(f"fortified = {fixture.fortify[0]}")
            lines.append(f"fortifiable = {fixture.fortify[1]}")
        lines.append("")
        lines.append("[fixture.expect]")
        for key in sorted(fixture.expect):
            lines.append(f"{key} = {toml_string(fixture.expect[key])}")
        lines.append("")
        if fixture.reference:
            lines.append("[fixture.reference]")
            for key in sorted(fixture.reference):
                lines.append(f"{key} = {toml_string(fixture.reference[key])}")
            lines.append("")
    authenticode = [
        ("valid_untrusted.exe", "present", "an Authenticode-signed PE from the authenticode corpus (WIN_CERTIFICATE revision 2.0, PKCS#7 SignedData)"),
        ("unsigned.exe", "absent", "the same program before signing"),
    ]
    for name, verdict, description in authenticode:
        path = HERE.parents[2] / "crates" / "disrobe-pass-native" / "tests" / "fixtures" / "authenticode" / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append("[[reference]]")
        lines.append(f"name = {toml_string(name)}")
        lines.append(f"path = {toml_string('crates/disrobe-pass-native/tests/fixtures/authenticode/' + name)}")
        lines.append('format = "pe"')
        lines.append(f"sha256 = {toml_string(digest)}")
        lines.append(f"description = {toml_string(description)}")
        lines.append("")
        lines.append("[reference.expect]")
        lines.append(f"authenticode = {toml_string(verdict)}")
        lines.append("")
    (HERE / "MANIFEST.toml").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def tool_versions(tools, work):
    clang = capture(tools, "clang", ["--version"], work).splitlines()[0]
    sign = capture(tools, "rcodesign", ["--version"], work).strip()
    completed = subprocess.run([tools.resolve("cl", "x64")], cwd=work, env=tools.environment("x64"), capture_output=True, text=True, creationflags=NO_WINDOW, timeout=60)
    banner = completed.stderr.splitlines()[0].strip()
    return [clang, banner, sign]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--msvc", type=Path, required=True)
    parser.add_argument("--kits", type=Path, required=True)
    parser.add_argument("--sdk", default="10.0.26100.0")
    parser.add_argument("--rcodesign", type=Path, required=True)
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()
    tools = Tools(args.llvm, args.msvc, args.kits, args.sdk, args.rcodesign)
    selected = [f for f in fixtures() if not args.only or f.name in args.only]
    entries = []
    with tempfile.TemporaryDirectory(prefix="hardening-") as scratch:
        work = Path(scratch)
        for source in SRC.iterdir():
            shutil.copy2(source, work / source.name)
        (work / "sdk").mkdir()
        (work / "restrict.empty").write_bytes(b"")
        versions = tool_versions(tools, work)
        for fixture in selected:
            build(tools, fixture, work)
            data = (work / fixture.output).read_bytes()
            (HERE / fixture.output).write_bytes(data)
            entries.append((fixture, hashlib.sha256(data).hexdigest()))
            print(f"{fixture.name}: {len(data)} bytes, verdicts confirmed")
            for extra in fixture.observed.get("code_directory_flags", []):
                print(f"    {extra.strip()}")
    if not args.only:
        write_manifest(entries, versions)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as error:
        print(f"build.py: {error}", file=sys.stderr)
        sys.exit(1)
