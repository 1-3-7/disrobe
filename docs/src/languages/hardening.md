# Exploit-mitigation report

`disrobe native hardening` reports the exploit mitigations an ELF, PE or Mach-O image requests, and reports each slice of a universal Mach-O separately. Every verdict cites the header field, dynamic tag, load command, debug directory entry or import that decided it. The image is read, never run.

## Command

```sh
disrobe native hardening <binary>
disrobe native hardening <binary> --json
```

The text report prints one row per property: the property, its verdict, and the evidence as `field = value` lines. `--json` prints the same report as one JSON document with the schema `disrobe.native.hardening/v1`. The MCP `run_command` tool reaches the command as `["native", "hardening"]` and returns that document.

## Verdicts

| Verdict | Meaning |
|---|---|
| `present` | The image requests the mitigation. |
| `partial` | The image requests part of it: RELRO without immediate binding, `DYNAMIC_BASE` with the relocations stripped, `GUARD_CF` without an instrumented load configuration. |
| `absent` | The image does not request it. |
| `not-applicable` | The property does not exist for this image, for example SafeSEH on x86-64 or PIE on a shared library. |
| `undetermined` | The structure that decides the property is present but cannot be read, or holds no record of it. The evidence names the structure. |

An input that is not an ELF, PE or Mach-O image, or whose headers cannot be read, is refused with a typed error instead of a report:

| Code | Refusal |
|---|---|
| `DR-NATIVE-0260` | The input is not an ELF, PE or Mach-O image. |
| `DR-NATIVE-0261` | The input is a recognized container with no mitigation report: a static library archive, a dyld shared cache, or an MS-DOS executable without a PE header. |
| `DR-NATIVE-0262` | A header, program header table, PE section table, dynamic table or load command cannot be read or exceeds its bound. |
| `DR-NATIVE-0263` | The file is an object file, core dump or debug-symbol companion, not a linked image. |
| `DR-NATIVE-0264` | A universal Mach-O declares more than 64 slices. |
| `DR-NATIVE-0265` | The input file cannot be read. |

## ELF

| Property | Decided by |
|---|---|
| `nx` | `PT_GNU_STACK.p_flags`: present without `PF_X`. A missing `PT_GNU_STACK` is `absent`. |
| `pie` | `e_type`: `ET_EXEC` is `absent`; `ET_DYN` with `PT_INTERP`, or with `DF_1_PIE` in `DT_FLAGS_1` for a static PIE, is `present`; any other `ET_DYN` is a shared object and `not-applicable`. |
| `relro` | `PT_GNU_RELRO` with `DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW` is `present` (full RELRO); `PT_GNU_RELRO` alone is `partial`; no `PT_GNU_RELRO` is `absent`. |
| `stack-canary` | An undefined dynamic symbol `__stack_chk_fail`, `__stack_chk_guard` or `__intel_security_cookie`. A static image is read from `.symtab`; a stripped static image is `undetermined`. |
| `fortify` | Imported glibc `__*_chk` entry points. `fortify.fortified` counts them, `fortify.fortifiable` adds the imported plain functions that have a `_chk` variant. A static image is `undetermined`. |
| `rpath`, `runpath` | `DT_RPATH` and `DT_RUNPATH`, with the search path as evidence. |
| `ibt`, `shstk` | `GNU_PROPERTY_X86_FEATURE_1_AND` in the `NT_GNU_PROPERTY_TYPE_0` note, x86 and x86-64 only. |
| `bti`, `pac` | `GNU_PROPERTY_AARCH64_FEATURE_1_AND`, AArch64 only. |
| `symbols` | An `SHT_SYMTAB` section with at least one symbol; a missing one means the image is stripped. |

## PE

| Property | Decided by |
|---|---|
| `dynamic-base` | `DllCharacteristics.DYNAMIC_BASE`; `partial` when `IMAGE_FILE_RELOCS_STRIPPED` is also set. |
| `high-entropy-va` | `DllCharacteristics.HIGH_ENTROPY_VA`; `not-applicable` for PE32. |
| `nx-compat`, `force-integrity`, `no-seh`, `appcontainer` | The `DllCharacteristics` flag of the same name. |
| `safe-seh` | x86 only: a nonzero `SEHandlerTable` in the load configuration. `not-applicable` when `NO_SEH` is set, because the image registers no handler. |
| `gs` | A nonzero `SecurityCookie` in the load configuration. |
| `cfg` | `DllCharacteristics.GUARD_CF` together with `IMAGE_GUARD_CF_INSTRUMENTED` in `GuardFlags`; the evidence adds `GuardCFFunctionCount`. |
| `xfg` | `IMAGE_GUARD_XFG_ENABLED` in `GuardFlags` with a nonzero `GuardXFGCheckFunctionPointer`. |
| `cet-shadow-stack` | `CET_COMPAT` in the `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` debug directory entry, x86 and x86-64 only. |
| `authenticode` | A `WIN_CERTIFICATE` in the security directory. The report states presence; it does not verify the signature. |

The load configuration is read up to its own `Size` field, so a field the image's load configuration does not reach counts as missing and the evidence says so.

## Mach-O

| Property | Decided by |
|---|---|
| `pie` | `MH_PIE` in `mach_header.flags`; `not-applicable` for libraries and bundles. |
| `nx-heap` | `MH_NO_HEAP_EXECUTION`. |
| `nx-stack` | `present` unless `MH_ALLOW_STACK_EXECUTION` is set. |
| `stack-canary` | An undefined `___stack_chk_fail` or `___stack_chk_guard`. |
| `arc` | An ARC-only runtime import such as `_objc_retainAutoreleasedReturnValue` or `_objc_storeStrong`; `absent` when the image imports the Objective-C runtime without one, `not-applicable` when it imports none. |
| `code-signature` | `LC_CODE_SIGNATURE`. |
| `hardened-runtime` | `CS_RUNTIME` in the flags of the signature's CodeDirectory. The signature itself is not verified. |
| `encrypted` | A nonzero `cryptid` in `LC_ENCRYPTION_INFO` or `LC_ENCRYPTION_INFO_64`. |
| `restrict` | A `__RESTRICT` segment holding a `__restrict` section. |

## JSON shape

```json
{
  "schema": "disrobe.native.hardening/v1",
  "images": [
    {
      "format": "elf",
      "machine": "x86-64",
      "bits": 64,
      "kind": "executable",
      "checks": [
        {
          "property": "runpath",
          "status": "present",
          "evidence": [{ "field": "DT_RUNPATH", "value": "/opt/hardening/lib" }]
        }
      ],
      "fortify": {
        "fortified": 0,
        "fortifiable": 3,
        "fortified_functions": [],
        "unfortified_functions": ["memcpy", "printf", "strcpy"]
      }
    }
  ]
}
```

`format` is `elf`, `pe` or `macho`. `kind` is `executable` or `shared-library`. `slice_offset` appears on each slice of a universal Mach-O. `fortify` appears on dynamically linked ELF images.

The library entry point is `disrobe_pass_native::hardening::analyze`. It returns a `HardeningReport` or a `HardeningError` carrying the same codes, and `ImageHardening::check(Property::StackCanary)` returns one verdict with its evidence.

## Grading

The matrix in `corpus/native/hardening` holds images built from repository C and Objective-C sources, each with one set of hardening flags: clang 19.1.7 with ld.lld for ELF x86-64 and AArch64, MSVC 19.44 and clang-cl 19.1.7 with lld-link for PE x86 and x86-64, and clang 19.1.7 with ld64.lld for Mach-O x86-64 and arm64. The Mach-O hardened-runtime flag comes from rcodesign 0.29.0. Two Mach-O images carry a documented patch: one sets the stack and heap execution header flags, which ld64.lld cannot set, and one sets `cryptid` to 1 before signing, which only an encrypting store writes. `MANIFEST.toml` records each source, toolchain, command and SHA-256.

The expected verdict of every property is what the build command asked for. The build script refuses to write the manifest unless llvm-readobj, llvm-objdump, llvm-nm and rcodesign report the same verdict from the bytes. `checksec_cross.py` also compares the ELF verdicts with pwntools 4.14.1 `ELF.checksec`; the only difference is the stub shared object's canary, because pwntools counts a definition of `__stack_chk_fail` and this report counts imports. Two images from the Authenticode corpus grade the signature check. The test compares every expected verdict and every cited value the reference readers report, such as the security cookie address, `GuardFlags`, `SEHandlerCount`, the search paths and `cryptid`. Every property has a `present` and an `absent` image. Flipping any one expectation turns the grade red, and setting `PF_X` on one `PT_GNU_STACK` changes exactly the `nx` verdict.

## Limits

- FORTIFY counts the glibc `_chk` entry points; musl has none, and Bionic-only names such as `__strlen_chk` are not counted.
- `nx-heap` reports the `MH_NO_HEAP_EXECUTION` header flag, not the heap policy of the running system.
- ARC detection reads imports; an ARC image whose code never calls an ARC-only entry point reads as `absent`.
