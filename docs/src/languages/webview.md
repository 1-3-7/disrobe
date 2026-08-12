# Webview desktop frontends

`disrobe webview` statically recovers the frontend files embedded in Electron, Tauri, and Wails desktop applications. It writes HTML, JavaScript, CSS, source maps, fonts, images, WebAssembly modules, and other asset bytes under an output directory without starting the application.

```sh
disrobe webview desktop.exe --out frontend/
disrobe --json webview desktop.exe --out frontend/ > webview.json
```

The text result names the detected family and each recovered path, byte size, and compression method. JSON output uses the `disrobe.webview.carve/v1` schema and includes the input path, family, output directory, asset count, externally unpacked paths, and per-asset records.

## Supported layouts

| Family | Static input | Recovery |
|---|---|---|
| Electron | A standalone ASAR or an ASAR concatenated into a larger executable | Parse the ASAR pickle header and file tree, recover file bytes, verify integrity metadata when present, and preserve safe relative paths. |
| Tauri v1 and v2 | A generated embedded asset map in the native image | Resolve the table through PE, ELF, or Mach-O mappings and relocations, decode each entry, and recover the original asset tree. |
| Wails v2 | A Go embedded filesystem in the native image | Locate the embedded records and recover the original frontend tree. |

The embedded-map decoder handles uncompressed entries plus Brotli, zstd, and gzip. Mixed encodings are decoded per entry. It bounds the number of scan candidates, table probes, paths, recursion depth, output bytes, and compression expansion before allocating or writing output.

Recovered paths pass through the same path sanitizer used by the container layer. A single leading `/` on a non-empty key is treated as bundle-root-relative. Traversal components, UNC paths, drive prefixes, and other escaping names fail instead of writing outside `--out`.

## Packages and auto reachability

`webview` accepts one file. If the application image is still inside an archive, installer, disk image, or application bundle, extract that container first and pass the recovered executable to `webview`:

```sh
disrobe extract desktop-package.bin --out package/
disrobe webview package/path/to/application.exe --out frontend/
```

The standard CLI exposes webview recovery as a direct command. Its `chain` feature does not enable `webview.carve`, so `disrobe auto` does not list that pass in the standard build. Confirm the binary's auto surface with `disrobe passes`.

## Evidence and limits

Committed Tauri v1, Tauri v2, and Wails v2 builds are compared against their complete source asset trees in `crates/disrobe-pass-webview/tests/real_toolchain.rs`. The gate compares both the full path set and every file's bytes, so a plausible subset cannot pass. Electron parsing has committed structural and CLI integration coverage; a conditional parity test also packs a source tree with the real `@electron/asar` CLI when that tool is available.

The graded host-format matrix covers PE32+, 32-bit and 64-bit ELF in both byte orders, thin Mach-O, and universal Mach-O. PE32 remains declared but unobserved; the shared 32-bit read path is graded on ELF32 in both byte orders. Real committed desktop builds cover the current Tauri and Wails layouts; constructed fixtures exercise the wider host and compression matrix.

Static recovery cannot return assets that a development build reads from disk or a server at run time because those bytes are absent from the executable. Wails v3 remains ungraded while it is prerelease. Tauri resource-section storage is also ungraded because the tested released toolchains emit record arrays instead. These cases are not included in the byte-identity claim.
