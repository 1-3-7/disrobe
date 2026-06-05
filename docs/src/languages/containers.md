# Containers and archives

Before **disrobe** can decompile anything, it often has to get inside a container. The `disrobe-binfmt` layer detects 45 archive and installer formats, fully extracting 26 in-tree (the rest external-tool or metadata-only), with auto-detection, recursive chaining through nested layers, and shared zip-slip and decompression-bomb guards.

## Supported formats

| Category | Formats |
|---|---|
| Archives | ZIP (incl. ZIP64 + AES), tar.gz / tar.bz2 / tar.xz / tar.zst, 7z, RAR |
| Linux packages | `.deb`, `.rpm` (metadata), AppImage, Flatpak, Snap |
| Disk / filesystem images | `.iso` (ISO 9660 + Joliet + Rock Ridge + UDF), squashfs, cramfs, ext4 |
| Apple | `.dmg`, `.pkg` |
| Windows installers | MSI, NSIS, Inno Setup, InstallShield, `.cab`, MSIX / APPX |
| App / runtime | Electron `.asar`, Docker image tarball, OCI image manifest + layers |

## Extraction

Most extraction happens implicitly inside `disrobe auto`, which detects a container, extracts it, and recurses into the contents. Container extraction is also available through the Python `extract` command for archive-shaped inputs:

```sh
disrobe py extract package.whl --out extracted/    # wheel / sdist / egg / .whl / .zip / any archive
disrobe auto installer.msi --out extracted/         # detect, extract, recurse
```

## Safety guards

Every extractor shares the quota machinery in `crates/disrobe-binfmt/src/quota.rs`:

- **Per-entry size cap** and **aggregate size cap** - defuse decompression bombs.
- **Recursion-depth cap** - defuse container-in-container bombs.
- **Zip-slip path sanitization** (`sanitize_entry_path`) - every entry path is sanitized so no extraction can escape the output directory, on every format.

Bypasses of any of these are treated as security issues; see the [security policy](../security.md).
