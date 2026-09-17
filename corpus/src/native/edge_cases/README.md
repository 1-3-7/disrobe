# Native edge-case playground

Small source files for cross-platform native binaries that exercise the binary-format passes (`disrobe-binfmt`) & stress the layout edges (stripping, TLS callbacks, RTTI, PIE, visibility, custom sections, static linkage).

## Coverage

| source | build recipe | target | edge case |
|--------|--------------|--------|-----------|
| `stripped_elf.c` | `stripped_elf.build.sh` | ELF | static-linked, fully stripped via `-s` + `strip --strip-all`. |
| `stripped_macho.c` | `stripped_macho.build.sh` | Mach-O | `clang -target x86_64-apple-darwin` + `strip -S -x`. |
| `pe_tls_callback.c` | `pe_tls_callback.build.ps1` | PE | TLS callback inserted via `.CRT$XLB` section with `IsDebuggerPresent` anti-debug check. |
| `go_hello.go` | `go_hello.build.sh` | ELF/PE (static) | static-linked Go binary (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`). |
| `rust_hello.rs` | `rust_hello.build.sh` | ELF/PE | release Rust binary with `-C strip=symbols -C codegen-units=1`. |
| `cxx_virtual_inheritance.cpp` | `cxx_virtual_inheritance.build.sh` | ELF | virtual inheritance vtable layout (`Whale : Mammal, Swimmer` with `virtual Animal`). |
| `cxx_rtti_dyncast.cpp` | `cxx_rtti_dyncast.build.sh` | ELF | RTTI / `dynamic_cast` (forces `typeinfo` & vtable retention). |
| `pie_binary.c` | `pie_binary.build.sh` | ELF | position-independent executable (`-fPIE -pie`). |
| `custom_section.c` | `custom_section.build.sh` | ELF | `__attribute__((section(".disrobe_marker")))` injects custom section with magic. |
| `hidden_visibility.c` | `hidden_visibility.build.sh` | ELF | `-fvisibility=hidden` with explicit `default` on public entry; restricted dynsym. |

## Validation

The build scripts write their binaries to `corpus/generated/native/`. Run each script on a host
with the toolchain for its target: Bash, `go`, `rustc`, and `file` for the host-native Go and
Rust recipes; Bash, `gcc`/`g++`, `strip`, and `file` for the ELF recipes; an Apple SDK and
`clang` for Mach-O; or a Visual Studio Developer PowerShell with `cl.exe` for the PE fixture.

From a Visual Studio Developer PowerShell, build the Windows PE fixture:

```powershell
.\pe_tls_callback.build.ps1
```

On a Bash host with Go and Rust, run the host-native recipes:

```sh
bash ./go_hello.build.sh
bash ./rust_hello.build.sh
```

On a POSIX host with the ELF prerequisites, run:

```sh
bash ./stripped_elf.build.sh
bash ./cxx_virtual_inheritance.build.sh
bash ./cxx_rtti_dyncast.build.sh
bash ./pie_binary.build.sh
bash ./custom_section.build.sh
bash ./hidden_visibility.build.sh
```

On macOS with the Apple SDK, run:

```sh
bash ./stripped_macho.build.sh
```

For source-only validation on a compiler host, use `gcc -fsyntax-only` for the C fixtures and
`g++ -std=c++17 -fsyntax-only` for the C++ fixtures. Go and Rust require `go` and `rustc`;
their matching scripts above perform the release builds with the recorded flags.
