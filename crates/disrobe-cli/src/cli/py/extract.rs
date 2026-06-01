use std::ffi::OsStr;
use std::path::PathBuf;

pub(super) fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0070: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("py-extract")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-extracted")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0071: cannot create out dir: {e}"))?;
    let kind: disrobe_binfmt::ContainerKind =
        disrobe_binfmt::detect_container_with_hint(&bytes, Some(&input)).ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0072: input {} is not a recognized archive (.whl/.zip/.tar/.tar.gz/.7z/.asar/...)",
                input.display()
            )
        })?;
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(kind, &bytes, &out_dir)
            .map_err(|e| miette::miette!("DR-CLI-0073: extract failed: {e}"))?;
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.py.extract/v0",
        "input": input.display().to_string(),
        "container": result.kind.label(),
        "entries_extracted": result.entries.len(),
        "bytes_uncompressed": result.quota.total_uncompressed_bytes,
        "bytes_compressed": result.quota.total_compressed_bytes,
        "entries": result.entries.iter().map(|e| serde_json::json!({
            "name": e.name,
            "uncompressed_size": e.uncompressed_size,
            "compressed_size": e.compressed_size,
            "disk_path": e.disk_path.as_ref().map(|p| p.display().to_string()),
            "executable": e.is_executable,
        })).collect::<Vec<_>>(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0074: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0075: cannot write manifest: {e}"))?;
    println!("py extract: OK");
    println!("  input:        {}", input.display());
    println!("  container:    {}", result.kind.label());
    println!("  entries:      {}", result.entries.len());
    println!(
        "  bytes:        {} uncompressed / {} compressed",
        result.quota.total_uncompressed_bytes, result.quota.total_compressed_bytes
    );
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

pub(super) fn sourcedefender(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0034: cannot read input: {e}"))?;
    let filename: &str = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("module.pye");
    let result: disrobe_pass_sourcedefender::DecryptedPye =
        disrobe_pass_sourcedefender::decrypt_pye(&bytes, filename)
            .map_err(|e| miette::miette!("{e}"))?;
    let out_path: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("sourcedefender");
        PathBuf::from(format!("./out/{stem}.decrypted.bin"))
    });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0035: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &result.plaintext_msgpack)
        .map_err(|e| miette::miette!("DR-CLI-0036: cannot write output: {e}"))?;
    println!("sourcedefender decrypt: OK");
    println!("  filename:     {}", result.filename);
    println!("  key:          {}", result.key_hex);
    println!("  iv:           {}", result.iv_hex);
    println!(
        "  plaintext:    {} bytes (msgpack envelope)",
        result.plaintext_msgpack.len()
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}
