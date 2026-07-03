# Lua IronBrew2 2.7.0 devirtualization, real-Lua execution differential

- id: `lua-ironbrew`
- ecosystem: lua
- claim: disrobe devirtualizes real IronBrew2 2.7.0 obfuscator output back to runnable Lua whose execution under the real Lua interpreter matches the original, in both standard and MAX mode.
- measured: 2 families
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real Lua interpreter execution differential (recovered output executed under real Lua, asserted equal to the original)
- reproduce: `cargo test -p disrobe-pass-lua --test ironbrew2_real_oracle`
- gate source: crates/disrobe-pass-lua/tests/ironbrew2_real_oracle.rs - IronBrew2 2.7.0 is reversed on REAL committed output (corpus/lua/ironbrew2/obfuscated/*.{min,max}.lua carry the genuine 'IronBrew:tm: obfuscation; Version 2.7.0' bootstrap), graded by a real-Lua execution differential (recover_runnable output executed under real Lua, asserted equal to the original) across hello/arith/control/tables/edge in standard and MAX mode, run in the execution-differentials CI job; MoonSec-shape recovery remains synthetic-bootstrap-only (vm_devirt_ironbrew.rs DVM1 self-authored fixture) pending a real public sample
