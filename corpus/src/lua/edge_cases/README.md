# Lua / LuaJIT edge-case playground

Lua 5.4 & LuaJIT sources exercising coroutines, metatables, closures, FFI, bit ops, patterns, gotos, dynamic environments. They feed any future Lua bytecode pass.

## Coverage

| file | category | flavor | what it exercises |
|------|----------|--------|-------------------|
| `coroutines.lua` | coroutine | 5.4 / LuaJIT | producer coroutine with `yield`/`resume` cycle, terminal return value. |
| `metatable_chain.lua` | metatable | 5.4 / LuaJIT | `__index` lookup walking 6 levels of parent tables. |
| `closure_upvalue.lua` | closure | 5.4 / LuaJIT | two closures sharing one upvalue with mutation + reset. |
| `multi_return.lua` | calls | 5.4 / LuaJIT | multi-return + `select` + integer division `//`. |
| `luajit_ffi.lua` | ffi | LuaJIT-only | `ffi.cdef` + `ffi.metatype` + operator overload + libc call. |
| `luajit_bitops.lua` | bit | LuaJIT-only | `require("bit")` with `band`/`bor`/`bxor`/`lshift`/`rshift`/`rol`. |
| `string_pattern_magic.lua` | pattern | 5.4 / LuaJIT | character-class `%w`, anchored / escape, capture, `%b()` balanced match. |
| `goto_label.lua` | control | 5.4 / LuaJIT | `goto skip` + `::skip::` continue-style label. |
| `require_cycle.lua` | module | 5.4 / LuaJIT | resolve cycle via pre-population of `package.loaded`. |
| `sandboxed_env.lua` | dynamic | 5.4 | `load(code, name, "t", env)` with explicit environment table. |
| `table_ops.lua` | table | 5.4 / LuaJIT | deep copy preserving metatable, `table.pack` with holes, variadic unpack. |

## Validation

Prerequisite: a Lua 5.4 `luac` compiler. From this directory, validate every fixture without
executing it:

```powershell
[System.IO.FileInfo[]]$files = @(Get-ChildItem -LiteralPath . -Filter '*.lua' -File)
foreach ($file in $files) {
    & luac -p $file.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "luac rejected $($file.Name)"
    }
}
```

`luajit_ffi.lua` and `luajit_bitops.lua` parse under Lua 5.4; validating their `ffi` and `bit`
dependencies requires LuaJIT.
