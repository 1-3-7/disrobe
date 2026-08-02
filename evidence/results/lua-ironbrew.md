# Lua IronBrew2 2.7.0 devirtualization, real-Lua execution differential

- id: `lua-ironbrew`
- ecosystem: lua
- claim: disrobe devirtualizes real IronBrew2 2.7.0 obfuscator output back to runnable Lua whose execution under the real Lua interpreter matches the original, in both standard and MAX mode.
- measured: 1 family
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real Lua interpreter execution differential (recovered output executed under real Lua, asserted equal to the original)
- reproduce: `cargo test -p disrobe-pass-lua --test ironbrew2_real_oracle`
- gate source: IronBrew2 2.7.0 is the one Lua VM-devirtualization family graded on committed output from the real obfuscator. The real-Lua execution differential runs the recovered output against the original across hello, arith, control, tables, and edge samples in standard and MAX mode.
