# NSIS installers

`tide_viewer.nsi` and the files under `payload/` were written for this repository. `crates/disrobe-binfmt/tests/real_nsis_solid.rs` compiles the script with the real NSIS compiler at test time, parses each installer, recovers every file it carries and compares each file's SHA-256 with the input's. No installer is committed and none is ever run.

The script takes its compressor, solid mode, string encoding and output path as defines. `empty.txt` is the first file on purpose: an installer whose first file is empty has no data block to probe, so solid mode has to be read from the header block. The repository does not keep zero-byte files, so `tests/real_nsis_solid.rs` copies the script and payload into a scratch tree and creates `payload/empty.txt` there before each build.

| Build | Defines |
| --- | --- |
| solid LZMA, Unicode | `-DCOMPRESSOR=lzma -DSOLID -DUNICODE_STRINGS` |
| solid LZMA, ANSI | `-DCOMPRESSOR=lzma -DSOLID` |
| solid zlib, Unicode | `-DCOMPRESSOR=zlib -DSOLID -DUNICODE_STRINGS` |
| solid BZip2, Unicode | `-DCOMPRESSOR=bzip2 -DSOLID -DUNICODE_STRINGS` |
| non-solid LZMA, Unicode | `-DCOMPRESSOR=lzma -DUNICODE_STRINGS` |
| non-solid zlib, Unicode | `-DCOMPRESSOR=zlib -DUNICODE_STRINGS` |
| non-solid BZip2, Unicode | `-DCOMPRESSOR=bzip2 -DUNICODE_STRINGS` |

Each build is one command; makensis changes into the script's directory, so the `File` paths resolve here wherever it is started from:

```sh
makensis -V2 -DCOMPRESSOR=lzma -DSOLID -DUNICODE_STRINGS -DOUTFILE=/tmp/setup.exe corpus/installers/nsis/tide_viewer.nsi
```

Toolchain: NSIS 3.11 for Windows, `nsis-3.11.zip` from the project's SourceForge release directory (2,361,546 bytes, sha256 `c7d27f780ddb6cffb4730138cd1591e841f4b7edb155856901cdf5f214394fa1`, the sum SourceForge publishes), unpacked without an installer; `makensis /VERSION` prints `v3.11`. The test finds `makensis` on `PATH` or in the standard `Program Files` install directories. A missing compiler fails the run by name unless `tests/optional.toml` lists `disrobe-binfmt::makensis` for the platform, as it does for macOS, where CI installs no NSIS; the case then writes a not-measured record.

| Input | Bytes | sha256 |
| --- | --- | --- |
| `tide_viewer.nsi` | 679 | `dce8f294a85ab5f05456aeb8a2de4c8f917d9cc35c56963ec87e3df7c5df761e` |
| `payload/empty.txt` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `payload/readme.txt` | 1428 | `f6fe7073810fc8bc57daf6f5285b09f289dddf49c7e4f3835e647b740f42a7c4` |
| `payload/stations.csv` | 786 | `692fc21e130d1cd1a1048f263f5b1ec46fee69012e216b2388ddaf321a3d4df8` |
| `payload/docs/changes.txt` | 554 | `2fa2ec4deb6b1d9b3d986df28298bf66c997dc41eba68d41edacf6984c1bbaf9` |
