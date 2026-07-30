# Python pickle

`disrobe` analyzes pickles statically so you can audit what a stream would do on load before it ever touches a real interpreter. It never unpickles, never calls `__reduce__`, never executes a `REDUCE` opcode.

Pickle is a code-execution format wearing a data format's clothes. Unpickling a crafted stream runs arbitrary code through `__reduce__` / `REDUCE`, which makes weaponized `.pkl` and `.pt` files a recurring ML supply-chain vector.

## At a glance

| Layer | Coverage |
|---|---|
| Protocols | 0 through 5 |
| Symbolic VM | Full object graph, memo, stack, and `STOP` result reconstructed with nothing executed |
| Reconstruction | Graph rendered back to re-executable Python assignments, including the `listitems` and `dictitems` extension streams |
| Safety grading | Three severity tiers, each finding tagged with a confidence tier |
| Containers | PyTorch, TorchScript, and numpy model files; zip, zip64, and tar polyglots |
| Bindings | The same static suite is available as a Python library |

## Commands

```sh
disrobe pickle disasm model.pkl --out trace.txt
disrobe pickle decompile model.pkl --out graph.py
disrobe pickle safety model.pkl
disrobe pickle trace model.pkl
disrobe pickle polyglot suspicious.bin
disrobe pickle ml-detect model.bin
```

`trace` walks the opcode stream and reconstructs the object graph the same way a real unpickler would build it, but every operation is symbolic. A `GLOBAL` records a `(module, name)` reference without importing the module; a `REDUCE` records "this callable would be applied to these arguments" without calling it; the memo, stack, and `STOP` result are all inert values. The output is the full graph (objects, memo, resolved globals, reduce count) with nothing executed. `decompile` renders that graph back to equivalent Python assignments.

`polyglot` catches the trick of hiding a malicious pickle inside a zip, zip64, or tar that a model loader will open as an archive and then unpickle. `ml-detect` recognizes PyTorch, TorchScript, and numpy containers and lists every embedded pickle stream, so a multi-file `.pt` archive is enumerated rather than treated as one opaque blob.

The same static suite is available as a library. Nothing is ever unpickled.

```python
import disrobe
from disrobe import PickleSafety

with open("model.pkl", "rb") as fh:
    payload: bytes = fh.read()

safety: PickleSafety = disrobe.pickle_safety(payload)

severity: str | None = safety.severity          # "benign" | "suspicious" | "overtly_malicious"
finding_count: int   = safety.finding_count
reduce_count: int    = safety.reduce_count
listing: str         = disrobe.pickle_disasm(payload)
```

## Coverage and fidelity

The graph the symbolic VM builds is rendered back to re-executable Python, and the reduce protocol's `listitems` and `dictitems` extension streams are modeled, not dropped. That is what lets `collections.deque`, `OrderedDict`, and `defaultdict` reconstruct: a `REDUCE` that builds the container is followed by the item stream, which `disrobe` re-emits through `extend`/`__setitem__` helpers so the rebuilt object is populated exactly as the original was, without ever running the pickle.

A committed differential oracle proves this against real CPython. It pickles a corpus spanning primitives, containers, cyclic and shared references, `__reduce__` objects, and the collection types above across every protocol (0 through 5), reconstructs each with `disrobe`, and re-executes the reconstruction under a real interpreter to check it rebuilds a deep-equal object. Every case that is not a proven information-theoretic ceiling re-executes equivalently, a 100% floor a CI gate enforces wherever a CPython interpreter is present.

`disrobe pickle safety` grades a stream into one of three severity tiers. Each finding is tagged with a confidence tier so a reviewer can tell a certain hit from an inference.

| Severity | Meaning |
|---|---|
| `benign` | No dangerous import, no reduce against a risky callable, no memo abuse |
| `suspicious` | A pattern that can be malicious in context (unusual import, opaque reduce, memo manipulation) |
| `overtly_malicious` | A reduce against a known code-execution sink (`os.system`, `subprocess.Popen`, `builtins.eval` / `exec`, `__import__`) |

| Confidence | Meaning |
|---|---|
| `signature_certain` | The finding follows directly from the opcodes (a `GLOBAL os system` then `REDUCE`) |
| `pattern_inferred` | A heuristic shape, not a literal signature match |
| `context_dependent` | Risky only depending on how the loader uses it |

The report also surfaces the resolved import list, the `REDUCE` count, and the unused-memo count (a common obfuscation tell), so a triage decision does not require reading the raw opcodes.

## Limits

- Nothing is executed, by design: a `GLOBAL` records a reference without importing the module and a `REDUCE` records an application without calling it. The report tells you what a load would do; it is not the loaded object.
- The cases outside the differential corpus's 100% floor are proven information-theoretic ceilings: what they need in order to rebuild is not in the stream.
- A `pattern_inferred` or `context_dependent` finding is a shape, not a signature match. Treat it as a lead for review rather than a verdict.
