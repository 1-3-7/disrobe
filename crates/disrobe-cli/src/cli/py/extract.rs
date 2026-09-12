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

const SOURCEDEFENDER_PASSWORD_ENV: &str = "SOURCEDEFENDER_PASSWORD";

pub(super) fn sourcedefender(
    input: PathBuf,
    out: Option<PathBuf>,
    key: Option<String>,
    password: Option<String>,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0034: cannot read input: {e}"))?;
    let filename: &str = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("module.pye");
    let variant: Option<disrobe_pass_sourcedefender::ContainerVariant> =
        disrobe_pass_sourcedefender::classify_container(&bytes);

    let effective_password: Option<String> = password.or_else(|| {
        std::env::var(SOURCEDEFENDER_PASSWORD_ENV)
            .ok()
            .filter(|p: &String| !p.is_empty())
    });
    let modern_key: Option<[u8; 32]> = match key.as_deref() {
        Some(hex) => Some(parse_hex32_key(hex)?),
        None => None,
    };

    if matches!(
        variant,
        Some(disrobe_pass_sourcedefender::ContainerVariant::ModernHex)
    ) || modern_key.is_some()
    {
        return sourcedefender_modern(
            &input,
            &bytes,
            filename,
            out,
            modern_key,
            effective_password.as_deref(),
        );
    }

    let result: disrobe_pass_sourcedefender::DecryptedPye =
        disrobe_pass_sourcedefender::decrypt_pye(&bytes, filename)
            .map_err(|e| miette::miette!("{e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sourcedefender")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.decrypted.bin")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0035: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &result.plaintext_msgpack)
        .map_err(|e| miette::miette!("DR-CLI-0036: cannot write output: {e}"))?;

    let plaintext_source: Option<String> = recover_plaintext_source(&result);
    let py_path: Option<PathBuf> = match &plaintext_source {
        Some(source) => {
            let out_dir: &std::path::Path = out_path
                .parent()
                .filter(|p: &&std::path::Path| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let path: PathBuf = out_dir.join(format!("{stem}.py"));
            std::fs::write(&path, source.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0037: cannot write source: {e}"))?;
            Some(path)
        }
        None => None,
    };

    println!("sourcedefender decrypt: OK");
    println!("  variant:      legacy-armored");
    println!("  filename:     {}", result.filename);
    println!("  key:          {}", result.key_hex);
    println!("  iv:           {}", result.iv_hex);
    println!(
        "  plaintext:    {} bytes (msgpack envelope)",
        result.plaintext_msgpack.len()
    );
    println!("  wrote:        {}", out_path.display());
    match &py_path {
        Some(path) => println!(
            "  source:       {} (envelope wrapped plaintext source)",
            path.display()
        ),
        None => println!(
            "  source:       envelope wraps a compiled marshal code object, not plaintext source; run `disrobe py disasm`/`py decompile` on {}",
            out_path.display()
        ),
    }
    Ok(())
}

fn parse_hex32_key(hex: &str) -> miette::Result<[u8; 32]> {
    let trimmed: &str = hex.trim();
    let trimmed: &str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let raw: Vec<u8> = disrobe_pass_sourcedefender::hex_decode(trimmed.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0038: --key is not valid hex: {e}"))?;
    let array: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        miette::miette!(
            "DR-CLI-0039: --key must decode to exactly 32 bytes (aes-256), got {}",
            v.len()
        )
    })?;
    Ok(array)
}

fn sourcedefender_modern(
    input: &std::path::Path,
    bytes: &[u8],
    filename: &str,
    out: Option<PathBuf>,
    modern_key: Option<[u8; 32]>,
    password: Option<&str>,
) -> miette::Result<()> {
    let recovery: disrobe_pass_sourcedefender::LayeredRecovery = match &modern_key {
        Some(k) => disrobe_pass_sourcedefender::recover_layered_with_modern_key(bytes, filename, k)
            .map_err(|e| miette::miette!("{e}"))?,
        None => disrobe_pass_sourcedefender::recover_layered(bytes, filename)
            .map_err(|e| miette::miette!("{e}"))?,
    };

    let stem: String = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("sourcedefender")
        .to_owned();

    println!("sourcedefender decrypt: OK");
    println!("  variant:      {}", recovery.variant.tag());
    println!("  layers peeled: {}", recovery.layers.len());
    for layer in &recovery.layers {
        println!(
            "    - {:?}: {} ({} bytes)",
            layer.kind, layer.detail, layer.output_len
        );
    }

    if let Some(source) = recovery.recovered_source.as_deref() {
        let py_path: PathBuf = write_sidecar(out.as_ref(), &stem, "py", source.as_bytes())?;
        println!("  key:          supplied (aes-256-gcm body decrypted statically)");
        println!(
            "  source:       {} (recovered plaintext source)",
            py_path.display()
        );
        return Ok(());
    }
    if let Some(marshal) = recovery.recovered_marshal.as_deref() {
        let bin_path: PathBuf = write_sidecar(out.as_ref(), &stem, "marshal.bin", marshal)?;
        println!("  key:          supplied (aes-256-gcm body decrypted statically)");
        println!(
            "  source:       envelope wraps a marshalled code object; run `disrobe py disasm`/`py decompile` on {}",
            bin_path.display()
        );
        return Ok(());
    }

    let Some(wall) = recovery.wall.as_ref() else {
        return Err(miette::miette!(
            "DR-CLI-0040: modern .pye produced neither a recovered body nor a wall"
        ));
    };
    println!("  wall reason:  {}", wall.reason.tag());
    println!(
        "  ciphertext:   {} bytes (aes-256-gcm sealed)",
        wall.ciphertext_len
    );
    if modern_key.is_some() {
        println!(
            "  note:         the supplied --key did not authenticate this body; check the key bytes"
        );
    } else if password.is_some() {
        println!(
            "  note:         a custom-mode password was supplied, but the upstream password->key derivation runs inside the closed-source Cython engine (_build_password_derivation_secret / _secure_hkdf_derive) and is not present in the artifact; derive the 32-byte aes-256-gcm key with the upstream engine and re-run with --key <hex64>"
        );
    } else {
        println!("  note:         {}", wall.detail);
    }
    Err(miette::miette!(
        "DR-CLI-0041: modern v16 body is an aes-256-gcm wall ({}); supply the 32-byte key via --key to decrypt statically",
        wall.reason.tag()
    ))
}

fn write_sidecar(
    out: Option<&PathBuf>,
    stem: &str,
    ext: &str,
    body: &[u8],
) -> miette::Result<PathBuf> {
    let dest: PathBuf = out.map_or_else(
        || PathBuf::from(format!("./out/{stem}.{ext}")),
        Clone::clone,
    );
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0042: cannot create dir: {e}"))?;
    }
    std::fs::write(&dest, body)
        .map_err(|e| miette::miette!("DR-CLI-0043: cannot write {}: {e}", dest.display()))?;
    Ok(dest)
}

fn recover_plaintext_source(
    decrypted: &disrobe_pass_sourcedefender::DecryptedPye,
) -> Option<String> {
    use disrobe_pass_sourcedefender::{PyeCodePayload, parse_array_envelope};
    if let Some(envelope) = decrypted.envelope.as_ref()
        && let PyeCodePayload::Source(source) = &envelope.original_code
    {
        return Some(source.clone());
    }
    let parsed: disrobe_pass_sourcedefender::ParsedPyeArrayEnvelope =
        parse_array_envelope(&decrypted.plaintext_msgpack).ok()?;
    let text: &str = std::str::from_utf8(&parsed.marshal_payload).ok()?;
    if looks_like_python_source(text) {
        Some(text.to_owned())
    } else {
        None
    }
}

fn looks_like_python_source(text: &str) -> bool {
    const MARKERS: [&str; 6] = ["import ", "def ", "class ", "print(", "from ", "#"];
    if text.is_empty() || !text.is_ascii() {
        return false;
    }
    MARKERS.iter().any(|m: &&str| text.contains(m))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn hello_pye_fixture() -> Option<PathBuf> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("sourcedefender")
            .join("hello.pye");
        if path.is_file() { Some(path) } else { None }
    }

    #[test]
    fn sourcedefender_emits_inner_py_when_envelope_wraps_plaintext_source() {
        let Some(input): Option<PathBuf> = hello_pye_fixture() else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("sourcedefender-extract-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let out_bin: PathBuf = scratch.join("hello.decrypted.bin");

        sourcedefender(input, Some(out_bin.clone()), None, None).expect("sourcedefender ok");

        assert!(out_bin.is_file(), "decrypted msgpack envelope must land");
        let py_path: PathBuf = scratch.join("hello.py");
        assert!(
            py_path.is_file(),
            "the free-version envelope wraps plaintext source, so an inner .py must be emitted"
        );
        let source: String = std::fs::read_to_string(&py_path).expect("read inner py");
        assert!(
            source.contains("print(\"Hello World!\")"),
            "inner .py must be the byte-exact unwrapped source: {source}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
