# disrobe for Ghidra (report import)

`DisrobeImport` (`disrobe_import.py`) ingests a disrobe recovery report and
applies it to the open program: recovered function names at their addresses,
labels for non-code symbols, plate and EOL comments for findings, indicator
strings. It either shells out to the disrobe CLI
on the program's backing file or reads a report you saved earlier.

Unlike the console-only `editors/ghidra` script, this one parses `disrobe`
JSON and writes annotations into the listing through the FlatProgramAPI and
`ghidra.program.model.symbol.SymbolTable`.

## Ingestion contract

The importer dispatches on the report `schema` field. These are the exact
schemas the disrobe CLI emits today:

| disrobe command | schema | applied as |
|---|---|---|
| `disrobe native export --format json` | `disrobe.native.symbol-map/v1` | recovered functions + labels at addresses, `note` as EOL comment |
| `disrobe native symbols` | `disrobe.native.symbols/v0` | `.text` exports as named functions, other symbols as labels, section as EOL comment |
| `disrobe native disasm --emit json` | `disrobe.native.disasm/v2` | discovered functions named at their entry, instruction count + cyclomatic complexity as plate comment |
| `disrobe --json ioc` | `disrobe.ioc/v0` | each indicator as an EOL comment + ASCII or UTF-8 string at the loaded address corresponding to its file offset |

A report whose schema is none of these fails fast with a clear error rather
than silently applying nothing.

Native report addresses must match the program's load addresses. The importer
preserves image-base metadata when parsing a symbol map but does not rebase the
program. IOC offsets must map to exactly one loaded address; unmapped or
ambiguous offsets raise an error. String creation can be skipped when existing
listing data overlaps the requested range.

## Requirements

- Ghidra 12.0 or later with PyGhidra 3.1 and CPython 3.10 or later.
- A JDK supported by the installed Ghidra release.
- `disrobe` on PATH (only for the shell-out mode), or edit `DISROBE_BINARY`.

## Installation

Set up [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
and start Ghidra through `support/pyghidraRun.bat` on Windows or
`support/pyghidraRun` on Linux and macOS. The script uses Python 3; Ghidra's
Jython runtime cannot run it.

Copy `disrobe_import.py` into a directory on Ghidra's Script Manager search
path (`Window > Script Manager > Manage Script Directories`), refresh the list,
and run `disrobe_import.py`.

## Usage

- In the GUI: run the script, pick one of `native symbols`, `native disasm
  (json)`, or `ioc`; it runs disrobe on the current program and applies the
  result.
- Headless: use the PyGhidra Python environment and pass the binary, script,
  and saved report paths:

```sh
python -m pyghidra --install-dir "<ghidra>" --project-path "<projects>" --project-name disrobe-import --skip-analysis "<binary>" plugins/ghidra/disrobe_import.py report.json
```

This imports the binary into a Ghidra project and applies the report without
running automatic analysis. Omit `--skip-analysis` to analyze the program first.
Use a project directory whose path components do not start with a dot.

The shell-out mode reads the JSON files produced by native commands and the
JSON stdout produced by `ioc`. CLI calls have a five-minute timeout; saved and
generated reports are limited to 32 MiB.

## Architecture

`parse_report` and `build_annotations` are pure: JSON text in, a
Ghidra-independent `AnnotationSet` out. `apply_annotations` drives a
`GhidraApplier` adapter; `_FlatApiApplier` is the only part that touches the
Ghidra API (`createFunction`, `getSymbolTable().createLabel`,
`Listing.setComment` with `PLATE`/`EOL`, `createAsciiString`, and `Listing.createData`
with `StringUTF8DataType`). This split is
what makes the parse/map core testable off a Ghidra runtime.

## Tests

`tests/test_disrobe_import.py` (stdlib `unittest`) runs the parse + map layer
over real disrobe reports captured in `tests/reports/` and asserts the produced
annotation set is faithful to the report: every text export becomes a named
function at its reported address, indicator offsets/values/kinds survive into
comments and strings, the image base is carried through, malformed reports
raise, and skipped applications are accounted for. The reports were captured
with `native symbols`, `native disasm`, and `ioc` on
`corpus/native/discovery/disc.unstripped.elf`, and `native export` on the UPX fixture.

Run:

```sh
python -m unittest discover -s plugins/ghidra/tests -p 'test_*.py'
```

These tests cover report parsing and annotation mapping. Checking changes to a
Ghidra program through `_FlatApiApplier` requires the Ghidra runtime.
The runtime-contract tests also check PyGhidra context selection, native report
files, stdout reports, file-offset mapping, and report-size limits using adapters.
