# Edge comparison, unproven matchups

Every row here is a matchup disrobe does NOT yet grade against the named tool on the same input
under a shared reference. They are tracked so the gap stays visible, not published as results.

A row leaves this file only when a same-input runner exists and its numbers move into the
head-to-head table in the README, which carries only matchups measured on committed input with
pinned tool versions. A missing row here is not an implied win, and nothing in this file should be
read as a measured comparison.

| Surface | Current proof | Leading tool(s) | Next proof |
|---|---|---|---|
| Python `.pyc` | <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> full CPython 3.14 stdlib; <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> pinned corpus, both recompile-equivalence | pycdc, pylingual, uncompyle6, decompyle3 | same `.pyc` corpus, same recompile oracle |
| Python freezers | PyInstaller and freezer chains extract `.pyc` payloads before the Python gate | pyinstxtractor-ng, pydecipher | shared onefile corpus, byte-exact `.pyc` carve, then source gate |
| PyArmor | <!-- m:pyarmor_frac -->72 / 72<!-- /m --> static free-mode samples recover locally | Pyarmor-Static-Unpack-1shot | public subset or SHA-pinned external corpus |
| Pickle safety | 102 / 102 fixtures disassemble, trace, and classify by pickletools semantics | fickling | same malicious and benign corpus, safety-label agreement |
| JavaScript and source maps | obfuscator and bundler recovery is pass-gated; <!-- m:js_bundlers -->11<!-- /m --> bundler families are cataloged | webcrack, wakaru, synchrony, REstringer, sourcemapper | same deployed bundle set, recovered-tree diff |
| WebAssembly | 1034 / 1034 opcodes lowered on a `wasm-tools` instruction inventory; 57 / 57 execution-eligible functions match under wasmtime | wabt `wasm-decompile`, Binaryen | same module set, parse plus wasmtime differential |
| JVM `.class` | 131 / 131 methods recompile; CFR row is proven above | CFR, Vineflower, Procyon, Fernflower | add the missing decompilers to the `javac` gate |
| Android DEX/APK | 118 / 118 presentable committed classes verify; JADX row is proven above | JADX, apktool, androguard, dex2jar | verifier-attested FOSS APK set, SHA-pinned |
| .NET CIL/protectors | Eazfuscator VM, KoiVM, and ConfuserEx2 are recovered on committed samples | ILSpy, dnSpyEx, de4dot | same assemblies, CIL diff plus compile/run gate |
| Native unpacking | UPX and seven packer families recover bytes against committed originals | `upx -d`, unipacker, Detect It Easy plugins | same packer corpus, section-byte identity |
| Native deobfuscation | OLLVM, stack strings, MBA, path predicates, and VM handler lifting have real or exhaustive gates | Ghidra, IDA, Binary Ninja plus deobfuscation scripts | same binaries, emulator or trace-equivalence gate |
| Go | <!-- m:go_typename_count -->838 of 838<!-- /m --> stripped type names; garble literals rebuilt from init-thunk emulation | GoReSym, redress, gore | same stripped binaries, type-name and literal recall |
| Swift / ObjC | 37 / 37 Swift symbols recover against the binary's own symbol table and `swift-demangle` | `swift-demangle`, class-dump, jtool2 | ObjC record recall against class-dump |
| Lua | real IronBrew2 2.7.0 output runs equal under `lua` after devirt | unluac, luadec, LuaDec51 | same `.luac` and VM-obfuscated set, execution differential |
| Ruby YARV | greeter <!-- m:ruby_greeter_pct -->100%<!-- /m -->, megafile <!-- m:ruby_megafile_pct -->98.67%<!-- /m --> of 23966 opcodes under MRI recompile | MRI disasm, ruby_decompiler | same `.iseq` set, opcode multiset gate |
| PHP | recursive eval-chain and encoded-container lifts have pass gates and length guards | php-decoder, de4php, php-malware-finder | same encoded corpus, parser plus runtime-output gate |
| Shell / VBA | PowerShell, bash, batch, and VBA deobfuscation have pass gates over recursive decoders | PowerDecode, flare tools, olevba | same script corpus, AST and execution-output gate |
| BEAM / AS3 | BEAM and ABC parsers lift bytecode to typed intermediate forms | `beam_disasm`, rabcdasm | same bytecode set, assembler round-trip gate |
| Hermes / React Native | HBC v96 sample lifts <!-- m:hermes_opcoverage_count -->8 of 8<!-- /m --> functions at zero fallback ops; <!-- m:hermes_functions -->122,633<!-- /m -->-function bundle parses locally | hermes-dec, hbctool | same HBC set, bytecode-to-source and parse gates |
| Flutter / Dart AOT | snapshot structure and cluster tags are parsed without fabricating names | reFlutter, Darter, blutter | same `libapp.so`, object-body name and field oracle |
| Containers and firmware | <!-- m:containers_frac -->100 / 100<!-- /m --> detected formats write member bytes in-tree | binwalk, unblob, 7-Zip | same archive and firmware set, member-byte diff |
| Recon and secrets | apkleaks row is proven above; planted non-secret IOC recall is 6 / 6 | trufflehog, gitleaks, apkleaks, LinkFinder | same recovered tree, shared ground truth |
| Format / packer / compiler ID | multi-signal ID tolerates damaged magic and renamed sections | Detect It Easy, TrID, PEiD, binwalk | same mutated corpus, ID accuracy plus extraction |
| Capabilities and taint | ATT&CK/MBC mapping and source-to-sink paths run over normalized IR | capa, Ghidra scripts, Joern | same samples, rule-match and flow-path agreement |
