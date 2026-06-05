# JavaScript edge-case playground

Hand-authored ES2022+ sources that exercise the wild edges of real-world JavaScript input. All files parse cleanly via `node --check` (Node 24). They feed `disrobe-pass-js-deob` & provide upstream input for any future JS bundler/protector wrappers.

## Coverage

| file | category | pass crate(s) | what it exercises |
|------|----------|---------------|-------------------|
| `tagged_template_raw.js` | template | js-deob | tagged template literal with `.raw` access. |
| `generators_async.js` | iterator | js-deob | sync generator + async generator producing BigInts. |
| `symbol_iterator_custom.js` | iterator | js-deob | custom `[Symbol.iterator]` with cleanup `return` hook. |
| `optional_nullish_chaining.js` | syntax-2020 | js-deob | optional chaining + nullish coalescing, falsy-zero / empty-string. |
| `new_target.js` | constructor | js-deob | `new.target` direct vs subclassed vs `Reflect.construct`. |
| `private_fields.js` | class | js-deob | `#fields`, static private, private static method, brand check via `#x in obj`. |
| `dynamic_import_meta.js` | module | js-deob | dynamic `import()` of a node builtin + `import.meta.url`. |
| `top_level_await.mjs` | module | js-deob | top-level `await` (requires ESM). |
| `weakref_finalization.js` | gc | js-deob | `WeakRef` + `FinalizationRegistry`. |
| `atomics_sab.js` | concurrent | js-deob | `SharedArrayBuffer` + `Atomics` ops + `waitAsync` feature detect. |
| `bigint_arith.js` | numeric | js-deob | BigInt literals (`n` suffix), shifts, masks, mixed conversion. |
| `regex_backrefs.js` | regex | js-deob | named groups, backreferences, lookbehind, replacer callback, full flag matrix. |
| `json_replacer_reviver.js` | serde | js-deob | `JSON.stringify` replacer + `JSON.parse` reviver, BigInt round-trip. |
| `proxy_all_traps.js` | proxy | js-deob | every Proxy trap wired with `Reflect.*` forwarding + apply/construct on function target. |
| `reflect_api.js` | reflect | js-deob | `Reflect.construct/get/set/ownKeys/getPrototypeOf/apply`. |
| `eval_strict.js` | dynamic | js-deob | direct vs indirect `eval` scope isolation under `"use strict"`. |
| `circular_module_safe.js` | module | js-deob | mutual references resolved post-construction. |
| `try_finally_return.js` | control-flow | js-deob | inner throw + outer catch + finally that returns; async `.finally`. |
| `numeric_separators.js` | literals | js-deob | `_` separators across decimal, hex, binary, octal, fraction, BigInt, exponent. |
| `mixed_line_endings.js` | encoding | js-deob | CRLF + LF + U+2028 + U+2029 in templates & runtime regex. |
| `whitespace_categories.js` | unicode | js-deob | every Unicode whitespace category covered by `\s`. |
| `object_literal_computed.js` | literal | js-deob | computed keys, spread, shorthand, generator iterator, accessor in object literal. |
| `destructuring_advanced.js` | pattern | js-deob | nested rename + default + `...rest` in both object & array patterns. |
| `for_await_of.js` | async | js-deob | `for await` over async iterable with early `break`. |
| `class_fields_self_ref.js` | class | js-deob | class fields that reference `this`, arrow methods bound at init. |
| `promise_combinators.js` | async | js-deob | `Promise.all/allSettled/race/any` + `AggregateError`. |
| `typed_arrays.js` | binary | js-deob | aliased `Uint32Array` / `Float64Array` / `DataView` over one `ArrayBuffer`, little-endian BigInt. |
| `getter_setter_dyn.js` | accessor | js-deob | object getter/setter + dynamic `Object.defineProperty` accessor. |
| `sloppy_with.js` | sloppy | js-deob | `with` statement (only valid in sloppy mode) + dynamically compiled `Function` host. |
| `labelled_break_continue.js` | control-flow | js-deob | labelled `break outer` / `continue outer` across nested loops. |
| `map_set_weak.js` | collection | js-deob | `Map` / `Set` / `WeakMap` / `WeakSet` + `Map.groupBy` (ES2024). |
| `throw_async.js` | error | js-deob | sync throw vs reject vs delayed reject in async function. |

## Validation

```powershell
foreach ($f in Get-ChildItem *.js, *.mjs) { node --check $f }
```

All 32 files pass `node --check` (Node 24).
