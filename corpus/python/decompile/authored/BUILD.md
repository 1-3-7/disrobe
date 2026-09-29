# Authored Python fixtures

Every `.py` file in this directory is written for this repository. Each source is compiled by the pinned CPython of every band below with a hash-based header (`UNCHECKED_HASH`), so a rebuild is byte-identical. The command runs from the repository root with the relative source path, so `co_filename` is `corpus/python/decompile/authored/<name>.py`, and with `PYTHONHASHSEED=0`:

```
PYTHONHASHSEED=0 python3.X -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)" corpus/python/decompile/authored/<name>.py corpus/python/decompile/authored/compiled/<name>.3.X.pyc
```

| file | interpreter |
|------|-------------|
| `compiled/*.3.8.pyc` | CPython 3.8.20 |
| `compiled/*.3.9.pyc` | CPython 3.9.25 |
| `compiled/*.3.10.pyc` | CPython 3.10.20 |
| `compiled/*.3.11.pyc` | CPython 3.11.15 |
| `compiled/*.3.12.pyc` | CPython 3.12.13 |
| `compiled/*.3.13.pyc` | CPython 3.13.14 |
| `compiled/*.3.14.pyc` | CPython 3.14.6 |

All sources except `header_probe.py` are compiled for all seven bands; `header_probe.py` is compiled for 3.12 only. The sources use syntax valid on 3.8 through 3.14 (no `match`, no PEP 695 or PEP 701 syntax) and define functions, classes and constants without side effects beyond the four small print samples.

| source | covers |
|--------|--------|
| `binary_ops.py` | arithmetic, bitwise and shift operators |
| `simple_const.py` | module constants and a conditional return |
| `slices.py` | slice reads, slice assignment |
| `hello.py` | an f-string function and a loop over a tuple |
| `header_probe.py` | a checksum loop; header-coincidence fixture (below) |
| `if_elif_chains.py` | `if`/`elif`/`else` chains, nested conditions |
| `loops_break_else.py` | `for`/`while` with `break`, `continue` and `else` |
| `while_retry_loops.py` | `while` loops, retry with `try`/`continue`, binary search |
| `nested_loops_grid.py` | nested loops over grids, flood fill, matrix product |
| `try_nested_handlers.py` | named and bare handlers, nested `try`, `raise ... from` |
| `try_finally_cleanup.py` | `try`/`finally` around `return`, `break` and `continue`; nested cleanup with re-raise |
| `with_context_managers.py` | single, multiple-item and nested `with`, `contextmanager` |
| `class_inheritance_super.py` | inheritance, `super()`, `__init_subclass__`, mixins |
| `class_properties_dunders.py` | properties, `staticmethod`, `classmethod`, `__slots__`, dunders |
| `closures_nonlocal_global.py` | closures, `nonlocal`, `global`, default-argument capture |
| `decorators_stacked.py` | decorator factories, stacked and class decorators |
| `generators_yield_from.py` | generators, `send`, `yield from`, `yield` in `finally` |
| `async_await_flow.py` | `async def`, `await`, `async for`, `async with`, async generators |
| `comprehensions_nested.py` | list, set, dict and generator comprehensions |
| `lambdas_sort_keys.py` | lambdas as keys, dispatch tables, composition |
| `parameters_kinds.py` | positional-only, keyword-only, varargs, call unpacking |
| `annotations_typing.py` | module, class, local and parameter annotations |
| `fstring_format_specs.py` | f-string specs, conversions, `=`, nested specs |
| `walrus_conditions.py` | assignment expressions in `if`, `while` and filters |
| `starred_unpacking.py` | starred targets, nested unpacking, `*` and `**` displays |
| `comparisons_boolean.py` | chained comparisons, `and`/`or`/`not` short-circuit |
| `conditional_expressions.py` | nested conditional expressions |
| `subscripts_slicing.py` | extended slices, slice deletion, tuple keys |
| `augmented_assign_del_assert.py` | augmented assignment on names, attributes and items; `del`; `assert` |
| `literal_constants.py` | big ints, floats, complex, bytes, nested tuples, constant sets |
| `string_methods_parsing.py` | string methods, header and query parsing, wrapping |
| `recursion_algorithms.py` | recursion, mutual recursion, expression trees |
| `sorting_algorithms.py` | insertion, merge, quick, heap and counting sort |
| `state_machine_tokenizer.py` | a tokenizer written as a state machine |
| `dataclass_records.py` | dataclasses with `field`, frozen and ordered classes |
| `collections_counting.py` | `Counter`, `defaultdict`, `deque`, `OrderedDict`, `namedtuple` |
| `itertools_pipelines.py` | `itertools` pipelines |
| `exception_hierarchy.py` | exception classes, `from None`, cause chains |
| `iterator_protocol.py` | `__iter__`/`__next__`, `StopIteration`, a peekable iterator |
| `bank_account_ledger.py` | a `Decimal` ledger class with `try`/`except`/`else`/`finally` |
| `expression_evaluator.py` | a shunting-yard parser and postfix evaluator |

`playground/public/samples/hello.pyc` is a copy of `compiled/hello.3.12.pyc`, and `crates/disrobe-wasm/tests/fixtures/sample.pyc` is a copy of `compiled/slices.3.12.pyc`.

`header_probe.py` ends in a comment whose number was searched for so that the first 16 bytes of `compiled/header_probe.3.12.pyc` (magic, flags and source hash) decrypt to the gzip prefix `1f 8b` under the D-Link DAP-1720 Alpha v1 key, and the string literal is sized so the file is a whole number of 16-byte blocks. `crates/disrobe-binfmt/tests/firmware_vendor.rs` uses it to check that the firmware detector does not claim CPython bytecode on that two-byte coincidence.
