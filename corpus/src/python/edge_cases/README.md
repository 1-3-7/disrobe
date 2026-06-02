# Python edge-case playground

Hand-authored CPython sources that exercise the wild edges of real-world Python input. Every file is real syntactically valid Python (CPython 3.12+); most also execute. They feed `disrobe-pass-py-disasm` & `disrobe-pass-py-deob`, plus the wrapper passes (`pyarmor`, `pyinstaller`, `nuitka`, `sourcedefender`) once their generators wrap these sources.

## Coverage

| file | category | pass crate(s) | what it exercises |
|------|----------|---------------|-------------------|
| `_invisible_RTL.py` | unicode | py-disasm, py-deob | CVE-2021-42574 bidi-override identifier smuggling. Source contains U+202E / U+2066 / U+2069. |
| `fstring_deep.py` | syntax-3.12 | py-disasm, py-deob | f-string nested-quote relaxation, mixed triple/single quoting, format-spec interpolation. |
| `match_case_patterns.py` | syntax-3.10 | py-disasm | class / mapping / sequence / OR / guard patterns; non-exhaustive matches. |
| `walrus_comprehensions.py` | syntax-3.8 | py-disasm | walrus in list/dict/nested comprehensions & while loops. |
| `pep695_aliases.py` | syntax-3.12 | py-disasm | PEP 695 `type` alias statement, generic-syntax functions, recursive aliases. |
| `empty_module.py` | trivial | py-disasm | zero-byte module bytecode round-trip. |
| `docstring_only.py` | trivial | py-disasm | module with only a docstring (CONST_KEY co_consts only). |
| `comments_only.py` | trivial | py-disasm | module whose payload is `pass`; original comments stripped per project rules. |
| `recursion_decorators.py` | decorator | py-disasm | nested decorators, memoization through chained `@wraps`. |
| `slots_property_cached.py` | descriptor | py-disasm | `__slots__` + property setter + `functools.cached_property`. |
| `async_for_with_comp.py` | async-syntax | py-disasm | async comprehension over async generator inside async context manager. |
| `exception_groups.py` | syntax-3.11 | py-disasm | `ExceptionGroup` + `except*` multi-arm handling. |
| `decorator_chains.py` | decorator | py-disasm | parameterised decorators, class decorator, `@wraps` chain. |
| `metaclass.py` | metaclass | py-disasm | custom metaclass with keyword class args, registry side-effects. |
| `future_imports.py` | future | py-disasm | `__future__` permutations (`annotations`, `division`) + `TYPE_CHECKING`. |
| `fstring_with_comments.py` | syntax-3.12 | py-disasm | multi-line f-string with embedded newlines & complex interpolations. |
| `bytes_and_raw.py` | literals | py-disasm | raw bytes / raw f-strings / format-spec mini-language / multi-line bytes literal. |
| `init_subclass_abstract.py` | hooks | py-disasm | `__init_subclass__` + ABC + abstract method enforcement + registry. |
| `typeddict_unpack.py` | typing-3.12 | py-disasm | PEP 692 `TypedDict` + `typing.Unpack` kwarg shape. |
| `genexpr_mutates.py` | semantics | py-disasm | generator expression mutating outer scope, late-binding capture workaround. |
| `diamond_mro.py` | inheritance | py-disasm | diamond MRO with cooperative `super()` chain. |
| `generators_send.py` | generator | py-disasm | `gen.send` round-tripping, `StopIteration.value`. |
| `descriptors.py` | descriptor | py-disasm | `__set_name__` / `__get__` / `__set__` validator descriptor. |
| `context_managers_nested.py` | resource | py-disasm | `ExitStack` + `@contextmanager` + ordered teardown log. |
| `dataclass_kwonly_frozen.py` | dataclass | py-disasm | `dataclass(frozen, kw_only, slots, order)` + `compare=False`. |
| `walrus_lambda.py` | walrus | py-disasm | walrus inside lambda default + `take_until` pattern. |
| `async_gen_send_throw.py` | async-generator | py-disasm | async generator `asend` + close lifecycle. |
| `positional_only.py` | signature | py-disasm | positional-only `/` + keyword-only `*` markers mixed. |
| `try_else_finally_return.py` | control-flow | py-disasm | nested try/except/else/finally with returns in finally (SyntaxWarning intentional). |
| `unicode_identifiers.py` | unicode | py-disasm | non-ASCII identifiers (Greek, Japanese, accented Latin). |
| `star_unpack.py` | unpack | py-disasm | starred targets in assignment, dict-merge `{**a, **b}`, nested star patterns. |
| `type_params_bounds.py` | syntax-3.12 | py-disasm | generic class syntax `Stack[T]`, generic function syntax. |
| `large_dispatch.py` | dispatch | py-disasm | `functools.singledispatch` with overload registration & recursive dispatch. |
| `protocol_runtime.py` | typing | py-disasm | `runtime_checkable` Protocol + `isinstance` structural check. |
| `overload_dispatch.py` | typing | py-disasm | `typing.overload` signature stack + runtime dispatch fallback. |
| `circular_import_safe.py` | import | py-disasm | dynamic `importlib.import_module` + `sys.modules` aliasing. |
| `large_int_arith.py` | numeric | py-disasm | arbitrary-precision int arithmetic, bit manipulation, popcount. |
| `walrus_while.py` | walrus | py-disasm | classic `while chunk := stream.read(size)` chunk loop. |

## Validation

All 38 files parse & bytecode-compile under CPython 3.14. Three intentional `SyntaxWarning`s in `try_else_finally_return.py` (`return` in `finally` block) are part of the fixture's purpose.

```powershell
python -m py_compile *.py
```
