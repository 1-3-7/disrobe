# Switch reference listings

`tests/switch_successors.rs` grades the successors of every lifted switch block against these
listings. Each listing comes from a tool outside this project, run on a committed fixture; the
filter only keeps the switch lines. Rerun a command from the repository root to regenerate its
file.

| File | Fixture | Tool and version | Command |
| --- | --- | --- | --- |
| `SwitchDispatch.javap-switch.txt` | `corpus/jvm/evalshapes/SwitchDispatch.class` | javap 25.0.4 | `javap -c -p <class> \| awk '/: (table\|lookup)switch/{p=1} p{print} p && /^ *}$/{p=0}'` |
| `uh.javap-switch.txt` | `corpus/jvm/stringer/uh.class` | javap 25.0.4 | same as above |
| `EdgeCases.baseline.ilspy-switch.txt` | `corpus/dotnet/megafile/EdgeCases.baseline.dll` | ilspycmd 9.1.0.7988 (`.config/dotnet-tools.json`) | `dotnet tool run ilspycmd -- -il <dll> \| grep -E '^\s*IL_[0-9a-f]+: switch \(' \| sed 's/^[[:space:]]*//'` |
| `EdgeCases.dexdump-switch.txt` | `corpus/jvm/dex/EdgeCases.dex` | dexdump, Android build-tools 36.1 | `dexdump -d <dex> \| grep -E '\|[0-9a-f]{4}: (packed\|sparse)-switch'` |
| `EdgeCases.jadx-switch.txt` | `corpus/jvm/dex/EdgeCases.dex` | jadx 1.5.5 | `jadx --decompilation-mode fallback --no-res -d <out> <dex>`, then every `switch(...) { ... }` block of `<out>/sources/**/*.java` in path order, leading whitespace removed |
| `edge_cases.case_dispatch.txt` | `corpus/ruby/mri/yarv/edge_cases.rb.yarvc` | Ruby 3.4.10 | `ruby case_dispatch_reference.rb corpus/ruby/megafile/edge_cases.rb` |

Semantics the test applies on top of the listings:

- CIL `switch` falls through to the next instruction when the index is out of range; the test adds
  that offset, `offset + 1 + 4 + 4 * n` by ECMA-335 III.3.66.
- dexdump gives the position of each Dalvik switch and jadx its case and default labels (hex code
  units); a packed or sparse switch falls through to the next instruction, which jadx prints as
  `default`.
- `case_dispatch_reference.rb` walks `RubyVM::InstructionSequence#to_a` of the source the YARV
  fixture was compiled from (the fixture used Ruby 3.4.9; both releases emit the same case
  dispatch). Positions are iseq slots, `label_N` is slot N, and the script checks every label
  against its running slot count. `opt_case_dispatch` reaches every hash label, the else label,
  and the next instruction (taken when `===` is redefined).
- AVM2 is graded against the committed JPEXS listings in `corpus/flash/avm2_disasm_oracle/`
  (see its `MANIFEST.toml`). Those listings omit bodies reachable only through `newfunction`, so
  the test grades the switch in each printed method.
