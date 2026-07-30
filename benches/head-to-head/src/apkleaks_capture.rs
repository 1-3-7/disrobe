use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::tool::{MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, read_bounded_file, read_bounded_string};

const CAPTURE_FILE: &str = "apkleaks-2.6.3-planted-secrets.json";
const PROVENANCE_FILE: &str = "apkleaks-2.6.3-planted-secrets.provenance.json";

#[derive(Debug, Clone)]
pub struct FrozenApkleaks {
    pub raw: String,
    pub version_line: String,
    pub decompiler: String,
    pub decompiler_version: String,
    pub command: String,
    pub output_sha256: String,
}

impl FrozenApkleaks {
    pub fn attribution(&self) -> String {
        format!(
            "replayed from the committed capture of `{command}` run against the same committed apk \
             with {decompiler} {decompiler_version}; \
             evidence/competitors/{CAPTURE_FILE} sha256 {output_sha256}",
            command = self.command,
            decompiler = self.decompiler,
            decompiler_version = self.decompiler_version,
            output_sha256 = self.output_sha256,
        )
    }
}

pub fn capture_path(root: &Path) -> PathBuf {
    competitors_dir(root).join(CAPTURE_FILE)
}

pub fn provenance_path(root: &Path) -> PathBuf {
    competitors_dir(root).join(PROVENANCE_FILE)
}

fn competitors_dir(root: &Path) -> PathBuf {
    root.join("evidence").join("competitors")
}

pub fn load(root: &Path, apk: &Path) -> Result<FrozenApkleaks, String> {
    let provenance_file: PathBuf = provenance_path(root);
    let provenance_raw: String = read_bounded_string(&provenance_file, MAX_TEXT_BYTES)
        .map_err(|e| format!("{} unreadable: {e}", provenance_file.display()))?;
    let provenance: Value = serde_json::from_str(&provenance_raw)
        .map_err(|e| format!("{} is not JSON: {e}", provenance_file.display()))?;

    let apk_bytes: Vec<u8> = read_bounded_file(apk, MAX_FIXTURE_BYTES)
        .map_err(|e| format!("{} unreadable: {e}", apk.display()))?;
    let recorded_input: String = text_field(&provenance, "input_sha256", &provenance_file)?;
    let measured_input: String = sha256_hex(&apk_bytes);
    if measured_input != recorded_input {
        return Err(format!(
            "{apk} hashes {measured_input} but {provenance} records the capture was taken over \
             {recorded_input}. The frozen apkleaks result describes a different file than the one \
             committed here, so re-run the capture in {provenance} rather than grading against it",
            apk = apk.display(),
            provenance = provenance_file.display(),
        ));
    }

    let capture_file: PathBuf = capture_path(root);
    let capture_bytes: Vec<u8> = read_bounded_file(&capture_file, MAX_FIXTURE_BYTES)
        .map_err(|e| format!("{} unreadable: {e}", capture_file.display()))?;
    let recorded_output: String = text_field(&provenance, "output_sha256", &provenance_file)?;
    let measured_output: String = sha256_hex(&capture_bytes);
    if measured_output != recorded_output {
        return Err(format!(
            "{capture} hashes {measured_output} but {provenance} records {recorded_output}. The \
             committed third-party output no longer matches the capture it is published under, so \
             it cannot stand in for what apkleaks produced",
            capture = capture_file.display(),
            provenance = provenance_file.display(),
        ));
    }

    let raw: String = String::from_utf8(capture_bytes)
        .map_err(|e| format!("{} is not UTF-8: {e}", capture_file.display()))?;

    Ok(FrozenApkleaks {
        raw,
        version_line: text_field(&provenance, "tool_version_line", &provenance_file)?,
        decompiler: text_field(&provenance, "decompiler", &provenance_file)?,
        decompiler_version: text_field(&provenance, "decompiler_version", &provenance_file)?,
        command: text_field(&provenance, "command", &provenance_file)?,
        output_sha256: recorded_output,
    })
}

fn text_field(document: &Value, field: &str, path: &Path) -> Result<String, String> {
    document
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value: &String| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "{} must carry a non-empty `{field}`; without it the capture has no provenance a \
                 stranger can re-run",
                path.display()
            )
        })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: sha2::digest::Output<Sha256> = Sha256::digest(bytes);
    let mut out: String = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published::checked_workspace_root;

    fn planted_apk(root: &Path) -> PathBuf {
        root.join("corpus")
            .join("recon")
            .join("apk")
            .join("planted-secrets.apk")
    }

    #[test]
    fn sha256_hex_matches_the_published_empty_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_committed_capture_matches_its_recorded_provenance() {
        let root: PathBuf = checked_workspace_root();
        let loaded: Result<FrozenApkleaks, String> = load(&root, &planted_apk(&root));
        assert!(
            loaded.is_ok(),
            "the committed apkleaks capture is what the published comparison row grades, so it must \
             load and match its recorded hashes: {:?}",
            loaded.as_ref().err()
        );
    }

    #[test]
    fn a_capture_taken_over_a_different_input_is_refused() {
        let root: PathBuf = checked_workspace_root();
        let decoy: PathBuf = std::env::temp_dir().join(format!(
            "disrobe_h2h_capture_decoy_{}.apk",
            std::process::id()
        ));
        let written: std::io::Result<()> = std::fs::write(&decoy, b"not the planted apk");
        assert!(written.is_ok(), "{:?}", written.as_ref().err());
        let refused: Result<FrozenApkleaks, String> = load(&root, &decoy);
        let _ = std::fs::remove_file(&decoy);
        let message: String = refused.err().unwrap_or_default();
        assert!(
            message.contains("describes a different file"),
            "a capture taken over another input must be refused rather than graded, got: {message}"
        );
    }
}
