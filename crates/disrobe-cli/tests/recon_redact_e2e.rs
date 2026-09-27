#![cfg(all(feature = "mobile", feature = "chain"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};

use common::{Run, run_disrobe, temp_dir};
use disrobe_core::scratch::ScratchDir;
use serde_json::Value;

struct Planted {
    aws: String,
    context: String,
}

impl Planted {
    fn new() -> Self {
        Self {
            aws: format!("{}{}", "AKIA", "3KFTG2KQ4WXYZ7AB"),
            context: format!("{}{}", "q7x2m9k4", "w1z8p3v6"),
        }
    }

    fn config_text(&self) -> String {
        format!(
            "aws_access_key_id={}\nconfluent_access_token = \"{}\"\n",
            self.aws, self.context
        )
    }

    fn assert_absent(&self, output: &str, label: &str) {
        assert!(
            !output.contains(self.aws.as_str()),
            "{label} leaked the AWS key id:\n{output}"
        );
        assert!(
            !output.contains(self.context.as_str()),
            "{label} leaked the keyword-context value:\n{output}"
        );
    }
}

fn build_apk(planted: &Planted) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("assets/config.properties", options)
        .expect("start config entry");
    zip.write_all(planted.config_text().as_bytes())
        .expect("write config entry");
    zip.finish().expect("finish apk").into_inner()
}

fn build_pe(payload: &[u8]) -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_SIZE: usize = 0xE0;
    const RAW_OFFSET: usize = 0x200;
    const RAW_SIZE: usize = 0x200;
    assert!(payload.len() <= RAW_SIZE, "payload must fit the section");
    let mut image: Vec<u8> = vec![0u8; RAW_OFFSET + RAW_SIZE];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3C..0x40].copy_from_slice(&u32::try_from(PE_OFFSET).unwrap().to_le_bytes());
    image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    let coff: usize = PE_OFFSET + 4;
    image[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    image[coff + 16..coff + 18]
        .copy_from_slice(&u16::try_from(OPTIONAL_SIZE).unwrap().to_le_bytes());
    image[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
    let optional: usize = coff + 20;
    image[optional..optional + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    image[optional + 28..optional + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    let section: usize = optional + OPTIONAL_SIZE;
    image[section..section + 8].copy_from_slice(b".data\0\0\0");
    image[section + 8..section + 12]
        .copy_from_slice(&u32::try_from(RAW_SIZE).unwrap().to_le_bytes());
    image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section + 16..section + 20]
        .copy_from_slice(&u32::try_from(RAW_SIZE).unwrap().to_le_bytes());
    image[section + 20..section + 24]
        .copy_from_slice(&u32::try_from(RAW_OFFSET).unwrap().to_le_bytes());
    image[section + 36..section + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());
    image[RAW_OFFSET..RAW_OFFSET + payload.len()].copy_from_slice(payload);
    image
}

fn write_apk(scratch: &ScratchDir, planted: &Planted) -> PathBuf {
    let apk: PathBuf = scratch.path().join("app.apk");
    std::fs::write(&apk, build_apk(planted)).expect("write apk");
    apk
}

fn recon(apk: &Path, extra: &[&str]) -> String {
    let mut args: Vec<&str> = vec!["mobile", "recon", apk.to_str().expect("apk path")];
    args.extend_from_slice(extra);
    let run: Run = run_disrobe(&args);
    assert_eq!(
        run.code, 0,
        "mobile recon {extra:?} failed; stderr={}",
        run.stderr
    );
    run.stdout
}

fn surfaced_secret_count(text: &str) -> usize {
    text.lines()
        .find_map(|line: &str| line.trim().strip_prefix("secrets:"))
        .map(str::trim)
        .and_then(|count: &str| count.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("no surfaced secret count in:\n{text}"))
}

fn assert_redacted_recon(planted: &Planted, text: &str, json: &str) {
    planted.assert_absent(text, "text recon");
    planted.assert_absent(json, "JSON recon");
    let count: usize = surfaced_secret_count(text);
    assert!(count >= 2, "both planted secrets must be surfaced:\n{text}");
    assert_eq!(
        text.matches("[REDACTED:").count(),
        count,
        "each surfaced secret carries one token in text output:\n{text}"
    );
    let report: Value = serde_json::from_str(json).expect("recon JSON");
    let secrets: &Vec<Value> = report["secrets"].as_array().expect("secrets array");
    assert_eq!(
        secrets.len(),
        count,
        "text and JSON surface the same secrets"
    );
    let codes: Vec<&str> = secrets
        .iter()
        .map(|secret: &Value| secret["code"].as_str().expect("secret code"))
        .collect();
    assert!(codes.contains(&"DR-SEC-AWS-AKID"), "codes: {codes:?}");
    assert!(codes.contains(&"DR-SEC-CONFLUENT"), "codes: {codes:?}");
    for secret in secrets {
        let value: &str = secret["value"].as_str().expect("secret value");
        assert!(
            value.starts_with("[REDACTED:") && value.ends_with(']'),
            "secret value is not a redaction token: {secret}"
        );
    }
}

#[test]
fn mobile_recon_redact_flag_replaces_every_surfaced_secret() {
    let planted: Planted = Planted::new();
    let scratch: ScratchDir = temp_dir("mobile-recon-redact");
    let apk: PathBuf = write_apk(&scratch, &planted);

    let text: String = recon(&apk, &["--redact"]);
    let json: String = recon(&apk, &["--json", "--redact"]);

    assert_redacted_recon(&planted, &text, &json);
}

#[test]
fn mobile_recon_honours_output_redact_in_configuration() {
    let planted: Planted = Planted::new();
    let scratch: ScratchDir = temp_dir("mobile-recon-redact-config");
    let apk: PathBuf = write_apk(&scratch, &planted);
    let config: PathBuf = scratch.path().join("disrobe.toml");
    std::fs::write(&config, "[output]\nredact = true\n").expect("write config");
    let config: &str = config.to_str().expect("config path");

    let text: String = recon(&apk, &["--config", config]);
    let json: String = recon(&apk, &["--json", "--config", config]);

    assert_redacted_recon(&planted, &text, &json);
    assert_eq!(text, recon(&apk, &["--redact"]));
    assert_eq!(json, recon(&apk, &["--json", "--redact"]));
}

#[test]
fn mobile_recon_without_redaction_still_shows_both_values() {
    let planted: Planted = Planted::new();
    let scratch: ScratchDir = temp_dir("mobile-recon-plain");
    let apk: PathBuf = write_apk(&scratch, &planted);

    for output in [recon(&apk, &[]), recon(&apk, &["--json"])] {
        assert!(output.contains(planted.aws.as_str()), "{output}");
        assert!(output.contains(planted.context.as_str()), "{output}");
        assert!(!output.contains("[REDACTED:"), "{output}");
    }
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read output dir") {
            let path: PathBuf = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn run_auto(input: &Path, out: &Path, redact: bool) -> Vec<PathBuf> {
    let mut args: Vec<&str> = vec![
        "auto",
        input.to_str().expect("input path"),
        "--out",
        out.to_str().expect("output path"),
    ];
    if redact {
        args.push("--redact");
    }
    let run: Run = run_disrobe(&args);
    assert_eq!(run.code, 0, "auto failed; stderr={}", run.stderr);
    files_under(out)
}

#[test]
fn auto_redact_leaves_no_raw_secret_in_any_written_file() {
    let planted: Planted = Planted::new();
    let scratch: ScratchDir = temp_dir("auto-redact-sidecars");
    let input: PathBuf = scratch.path().join("sample.exe");
    std::fs::write(&input, build_pe(planted.config_text().as_bytes())).expect("write pe");

    let plain_files: Vec<PathBuf> = run_auto(&input, &scratch.path().join("plain"), false);
    let plain_recon: Option<&PathBuf> = plain_files.iter().find(|path: &&PathBuf| {
        path.file_name()
            .and_then(|name: &std::ffi::OsStr| name.to_str())
            == Some("recon.json")
            && path
                .components()
                .any(|part: std::path::Component<'_>| part.as_os_str() == "extracted")
    });
    let plain_recon: &PathBuf = plain_recon
        .unwrap_or_else(|| panic!("auto wrote no extracted recon.json: {plain_files:?}"));
    let plain_text: String = std::fs::read_to_string(plain_recon).expect("read plain recon");
    assert!(plain_text.contains(planted.aws.as_str()), "{plain_text}");
    assert!(
        plain_text.contains(planted.context.as_str()),
        "{plain_text}"
    );

    let redacted_files: Vec<PathBuf> = run_auto(&input, &scratch.path().join("redacted"), true);
    assert!(
        redacted_files.len() >= plain_files.len(),
        "redaction must not drop output files: {redacted_files:?}"
    );
    for path in &redacted_files {
        let bytes: Vec<u8> = std::fs::read(path).expect("read output file");
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        planted.assert_absent(&text, &path.display().to_string());
        if path
            .extension()
            .and_then(|ext: &std::ffi::OsStr| ext.to_str())
            == Some("json")
        {
            serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|error: serde_json::Error| {
                panic!("{} invalid JSON: {error}", path.display())
            });
        }
    }
    let redacted_recon: PathBuf = scratch.path().join("redacted").join(
        plain_recon
            .strip_prefix(scratch.path().join("plain"))
            .expect("relative recon"),
    );
    let redacted_text: String =
        std::fs::read_to_string(&redacted_recon).expect("read redacted recon");
    assert!(redacted_text.contains("[REDACTED:"), "{redacted_text}");
}
