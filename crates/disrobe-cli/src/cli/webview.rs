use std::path::{Path, PathBuf};

use disrobe_binfmt::sanitize_entry_path;
use disrobe_pass_webview::{CarveReport, carve_report};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};
use crate::cli::progress_ui::StageSpinner;

pub(crate) fn run(input: PathBuf, out: Option<PathBuf>, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input).map_err(|e| {
        miette::miette!(
            "DR-WEBVIEW-0050: cannot read input {}: {e}",
            input.display()
        )
    })?;
    let out_dir: PathBuf = out.unwrap_or_else(|| default_out_dir(&input));
    let label: String = input.display().to_string();
    let spinner: StageSpinner = StageSpinner::start(
        &label,
        &format!("carving webview frontend from {} bytes", bytes.len()),
    );
    let report: CarveReport =
        carve_report(&bytes).map_err(|e| miette::miette!("DR-WEBVIEW-0051: {e}"))?;
    spinner.finish(&format!(
        "{} family, {} asset(s)",
        report.family.label(),
        report.assets.len()
    ));

    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-WEBVIEW-0052: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;

    let mut assets: Vec<WebviewAssetOut> = Vec::with_capacity(report.assets.len());
    for asset in &report.assets {
        let safe: String = sanitize_entry_path(&asset.path).map_err(|e| {
            miette::miette!("DR-WEBVIEW-0053: unsafe asset path `{}`: {e}", asset.path)
        })?;
        let disk_path: PathBuf = out_dir.join(&safe);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                miette::miette!("DR-WEBVIEW-0054: cannot create {}: {e}", parent.display())
            })?;
        }
        std::fs::write(&disk_path, &asset.bytes).map_err(|e| {
            miette::miette!("DR-WEBVIEW-0055: cannot write {}: {e}", disk_path.display())
        })?;
        assets.push(WebviewAssetOut {
            path: safe,
            bytes: asset.bytes.len() as u64,
            compression: asset.compression.label(),
        });
    }

    let summary: WebviewSummary = WebviewSummary {
        schema: "disrobe.webview.carve/v1",
        input: input.display().to_string(),
        family: report.family.label(),
        out_dir: out_dir.display().to_string(),
        asset_count: assets.len(),
        external_unpacked: report.external_unpacked,
        assets,
    };
    output::emit(fmt, &summary, || render(&summary))
}

#[derive(Debug, Serialize)]
struct WebviewAssetOut {
    path: String,
    bytes: u64,
    compression: &'static str,
}

#[derive(Debug, Serialize)]
struct WebviewSummary {
    schema: &'static str,
    input: String,
    family: &'static str,
    out_dir: String,
    asset_count: usize,
    external_unpacked: Vec<String>,
    assets: Vec<WebviewAssetOut>,
}

fn render(summary: &WebviewSummary) {
    println!("webview carve: OK");
    println!("  input:        {}", summary.input);
    println!("  family:       {}", summary.family);
    println!("  output:       {}", summary.out_dir);
    println!("  assets:       {}", summary.asset_count);
    for asset in &summary.assets {
        println!(
            "    {} ({} bytes, {})",
            asset.path, asset.bytes, asset.compression
        );
    }
    if !summary.external_unpacked.is_empty() {
        println!(
            "  external (unpacked, not carved): {}",
            summary.external_unpacked.len()
        );
        for path in &summary.external_unpacked {
            println!("    ! {path}");
        }
    }
}

fn default_out_dir(input: &Path) -> PathBuf {
    let stem: &str = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("webview");
    PathBuf::from(format!("./out/{stem}-webview"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn align_up(value: usize, align: usize) -> usize {
        value.div_ceil(align) * align
    }

    fn pickle_wrap(json: &[u8], data: &[u8]) -> Vec<u8> {
        let json_len: u32 = u32::try_from(json.len()).unwrap();
        let aligned: usize = align_up(json.len(), 4);
        let payload_size: u32 = u32::try_from(aligned).unwrap() + 4;
        let header_buf_len: u32 = payload_size + 4;
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&header_buf_len.to_le_bytes());
        out.extend_from_slice(&payload_size.to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(json);
        out.extend(std::iter::repeat_n(0u8, aligned - json.len()));
        out.extend_from_slice(data);
        out
    }

    fn build_genuine_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let mut root: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        for (name, body) in files {
            let offset: usize = data.len();
            data.extend_from_slice(body);
            let mut leaf: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            leaf.insert("size".to_owned(), serde_json::Value::from(body.len()));
            leaf.insert(
                "offset".to_owned(),
                serde_json::Value::from(offset.to_string()),
            );
            root.insert((*name).to_owned(), serde_json::Value::Object(leaf));
        }
        let mut header: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        header.insert("files".to_owned(), serde_json::Value::Object(root));
        let json: Vec<u8> = serde_json::to_vec(&serde_json::Value::Object(header)).unwrap();
        pickle_wrap(&json, &data)
    }

    #[test]
    fn carves_a_genuine_electron_asar_and_writes_sanitized_assets() {
        let files: [(&str, &[u8]); 2] = [
            ("index.html", b"<html><body>hi</body></html>"),
            ("app.js", br#"console.log("app");"#),
        ];
        let bytes: Vec<u8> = build_genuine_asar(&files);
        let scratch: PathBuf =
            std::env::temp_dir().join(format!("disrobe-webview-cli-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let asar_path: PathBuf = scratch.join("app.asar");
        std::fs::write(&asar_path, &bytes).expect("write asar");
        let out_dir: PathBuf = scratch.join("out");

        run(asar_path, Some(out_dir.clone()), OutputFormat::Text).expect("webview run ok");

        let html: String =
            std::fs::read_to_string(out_dir.join("index.html")).expect("read index.html");
        assert!(html.contains("hi"), "recovered html must be byte-exact");
        let js: String = std::fs::read_to_string(out_dir.join("app.js")).expect("read app.js");
        assert!(js.contains("console.log"));
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
