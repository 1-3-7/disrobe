# disrobe for Ghidra (report import)

`DisrobeImport` (`disrobe_import.py`) ingests a disrobe recovery report and
applies it to the open program: recovered function names at their addresses,
labels for non-code symbols, plate and EOL comments for findings, indicator
strings, and the recovered image base. It either shells out to the disrobe CLI
on the program's backing file or reads a report you saved earlier.

Unlike the console-only `editors/ghidra` script, this one parses `disrobe`
JSON and writes annotations into the listing through the FlatProgramAPI and
`ghidra.program.model.symbol.SymbolTable`.

## Ingestion contract

The importer dispatches on the report `schema` field. These are the exact
schemas the disrobe CLI emits today:

| disrobe command | schema | applied as |
|---|---|---|
| `disrobe native export --format json` | `disrobe.native.symbol-map/v1` | recovered functions + labels at addresses, image base, `note` as EOL comment |
| `disrobe native symbols` | `disrobe.native.symbols/v0` | `.text` exports as named functions, other symbols as labels, section as EOL comment |
| `disrobe native disasm --emit json` | `disrobe.native.disasm/v2` | discovered functions named at their entry, instruction count + cyclomatic complexity as plate comment |
| `disrobe --json ioc` | `disrobe.ioc/v0` | each indicator as an EOL comment + ASCII string at its file offset |

A report whose schema is none of these fails fast with a clear error rather
than silently applying nothing.

## Requirements

- Ghidra 10.3 or later (Script Manager, Python/Jython script support).
- `disrobe` on PATH (only for the shell-out mode), or edit `DISROBE_BINARY`.

## Installation

Copy `disrobe_import.py` into a directory on Ghidra's Script Manager search
path (`Window > Script Manager > Manage Script Directories`), refresh the list,
and run `DisrobeImport`.

## Usage

- In the GUI: run the script, pick one of `native symbols`, `native disasm
  (json)`, or `ioc`; it runs disrobe on the current program and applies the
  result.
- Headless / pre-saved report: pass the report path as a script argument, e.g.
  `analyzeHeadless <proj> <name> -process <file> -postScript disrobe_import.py report.json`.

## Architecture

`parse_report` and `build_annotations` are pure: JSON text in, a
Ghidra-independent `AnnotationSet` out. `apply_annotations` drives a
`GhidraApplier` adapter; `_FlatApiApplier` is the only part that touches the
Ghidra API (`createFunction`, `getSymbolTable().createLabel`,
`Listing.setComment` with `PLATE`/`EOL`, `createAsciiString`). This split is
what makes the parse/map core testable off a Ghidra runtime.

## Tests

`tests/test_disrobe_import.py` (stdlib `unittest`) runs the parse + map layer
over real disrobe reports captured in `tests/reports/` and asserts the produced
annotation set is faithful to the report: every text export becomes a named
function at its reported address, indicator offsets/values/kinds survive into
comments and strings, the image base is carried through, malformed reports
raise, and skipped applications are accounted for. The reports are genuine CLI
output (`native symbols` / `native disasm` / `ioc` on `corpus/native/discovery/
disc.unstripped.elf`, and `native export` on the UPX fixture), so the test
grades against real ground truth, not a self-generated fixture.

Run:

```sh
python -m unittest discover -s plugins/ghidra/tests -p 'test_*.py'
```

## Verification status

The parse and map layers are unit-tested green against real reports. The
in-Ghidra application path (the actual `_FlatApiApplier` calls) cannot be
exercised here because there is no Ghidra runtime on this machine; it is
manually verifiable when Ghidra is installed and is not claimed as verified.
