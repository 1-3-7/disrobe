# PE resources

`disrobe resources <file>` lists every resource in a Windows PE image (type, name, language, size, SHA-256) and decodes the ones an analyst reads first. Embedded blobs are named by their content, so a payload hidden as `RCDATA` shows up as a PE, ZIP, CAB, 7z, RAR, PDF, PNG, gzip or bzip2 file.

```sh
disrobe resources setup.exe
disrobe resources setup.exe --extract res/     # every blob, named TYPE-NAME-LANGUAGE.<kind>
disrobe resources setup.exe --json
```

## What it decodes

- Version information (`VS_VERSIONINFO`): file and product versions, flags, target OS and file type from the fixed block, the translations, and every string (company, description, original file name, product name and the rest) in each language table.
- String tables: every string with its numeric id, per language.
- Manifests: the assembly name, `requestedExecutionLevel` and `uiAccess`, DPI awareness and dependent assemblies, plus the full text.
- Icon groups: the size and bit depth of each image and the icon resource it points to.
- Every other resource as a listed blob with its content kind and hash; `--extract` writes them all.

## Evidence

`crates/disrobe-binfmt/tests/pe_resources_reference.rs` reads `corpus/native/resources/resources.exe`, built with llvm-rc and clang from `src/resources.rc` (version info in two languages, string tables in two languages across four blocks, a manifest, an icon group, two `RCDATA` blobs and a custom type), and compares the result with what Windows itself reports for the same file (`make_reference.py`, output committed as `reference.json`): the resource tree from `EnumResourceTypesW`/`NamesW`/`LanguagesW` with sizes and hashes of the bytes `LockResource` returns, version information from `GetFileVersionInfoW` and `VerQueryValueW`, and strings from `LoadStringW` under each UI language (with the loader's fall back to English for blocks missing in German). A changed version string, string-table entry or payload byte must fail the comparison, and 400 corrupted copies must produce a report or an error. `crates/disrobe-cli/tests/resources_cli.rs` checks the command's JSON and that `--extract` writes the payload byte for byte.

## Limits

- Dialogs, menus, accelerators and message tables are listed as blobs, not decoded.
- Icons are not converted to `.ico` files; the group lists which `ICON` resources form each icon.
- Manifest fields are read by element and attribute name, not with a full XML parser.
