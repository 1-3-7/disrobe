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

In this workspace `clang`, `gcc`, `g++`, & the MSVC `cl.exe` are NOT on PATH. Go (`go`) & Rust (`rustc`) ARE on PATH & both `go_hello.go` & `rust_hello.rs` compile cleanly:

```powershell
go build -o $env:TEMP\go_hello.exe .\go_hello.go
rustc --edition 2021 -o $env:TEMP\rust_hello.exe .\rust_hello.rs
```

For the other recipes install the relevant toolchain (`build-essential` / `xcode-cli` / MSVC build tools) & run the matching `*.build.sh` or `*.build.ps1`. Each recipe writes into `corpus/generated/native/`.
