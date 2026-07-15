#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_webview::{
    CarveReport, Compression, RecoveredAsset, WebviewFamily, carve, carve_report, detect_family,
};
use serde_json::{Map, Value};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn sample_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("index.html", b"<html><body>hi</body></html>".to_vec()),
        ("app.js", br#"console.log("app");"#.to_vec()),
        ("style.css", b"body{margin:0}".to_vec()),
        ("empty.txt", Vec::new()),
        (
            "logo.png",
            vec![
                0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03,
            ],
        ),
        ("assets/deep/x.js", b"export const x=42;".to_vec()),
    ]
}

fn unique_dir(tag: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{pid}-{seq}"));
    fs::create_dir_all(&base).unwrap();
    base
}

fn write_tree(root: &Path, files: &[(&str, Vec<u8>)]) {
    for (rel, data) in files {
        let path: PathBuf = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, data).unwrap();
    }
}

fn recovered_map(assets: &[RecoveredAsset]) -> BTreeMap<String, Vec<u8>> {
    assets
        .iter()
        .map(|asset: &RecoveredAsset| (asset.path.clone(), asset.bytes.clone()))
        .collect()
}

const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn build_genuine_asar(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let mut root: Map<String, Value> = Map::new();
    for (rel, body) in files {
        let offset: usize = data.len();
        data.extend_from_slice(body);
        insert_leaf(&mut root, rel, body.len(), offset);
    }
    let mut header: Map<String, Value> = Map::new();
    header.insert("files".to_owned(), Value::Object(root));
    let json: Vec<u8> = serde_json::to_vec(&Value::Object(header)).unwrap();
    pickle_wrap(&json, &data)
}

fn insert_leaf(root: &mut Map<String, Value>, rel: &str, size: usize, offset: usize) {
    let components: Vec<&str> = rel.split('/').collect();
    let mut cursor: &mut Map<String, Value> = root;
    for name in &components[..components.len() - 1] {
        let entry: &mut Value = cursor.entry((*name).to_owned()).or_insert_with(|| {
            Value::Object(Map::from_iter([(
                "files".to_owned(),
                Value::Object(Map::new()),
            )]))
        });
        let files: &mut Value = entry.as_object_mut().unwrap().get_mut("files").unwrap();
        cursor = files.as_object_mut().unwrap();
    }
    let leaf_name: &str = components[components.len() - 1];
    let mut leaf: Map<String, Value> = Map::new();
    leaf.insert("size".to_owned(), Value::from(size));
    leaf.insert("offset".to_owned(), Value::from(offset.to_string()));
    cursor.insert(leaf_name.to_owned(), Value::Object(leaf));
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

fn run_asar_pack(src: &Path, out: &Path) -> bool {
    let mut command: Command = if cfg!(windows) {
        let mut c: Command = Command::new("cmd");
        c.args(["/C", "npx", "--yes", "@electron/asar", "pack"]);
        c.arg(src).arg(out);
        c
    } else {
        let mut c: Command = Command::new("npx");
        c.args(["--yes", "@electron/asar", "pack"]);
        c.arg(src).arg(out);
        c
    };
    match command.output() {
        Ok(output) => output.status.success() && out.exists(),
        Err(_) => false,
    }
}

fn tricky_tree() -> Vec<(&'static str, Vec<u8>)> {
    let mut url_js: Vec<u8> = Vec::new();
    url_js.extend_from_slice(
        "const endpoint = \"https://\u{4f8b}\u{3048}.\u{30c6}\u{30b9}\u{30c8}/p?q=caf\u{e9}&x=1#frag\";\n"
            .as_bytes(),
    );
    url_js.extend_from_slice(br#"const meta = {"path":"C:\\Users\\a","tab":"x\ty"};"#);
    url_js.extend_from_slice(&[0x00, 0xff, 0x80, 0xc0]);

    let mut html: Vec<u8> = b"<!doctype html><title>".to_vec();
    html.extend_from_slice("\u{2713}".as_bytes());
    html.extend_from_slice(b"</title>");

    vec![
        ("index.html", html),
        ("\u{65e5}\u{672c}\u{8a9e}/\u{6982}\u{8981}.js", url_js),
        (
            "\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}.css",
            "body{content:\"\u{2713}\"}".as_bytes().to_vec(),
        ),
        ("emoji \u{1f600}.txt", vec![0x00, 0x01, 0x02, 0xfe, 0xff]),
        ("a+b@c#d.json", br#"{"ok":true}"#.to_vec()),
    ]
}

fn assert_round_trip(bytes: &[u8], expected: &[(&str, Vec<u8>)]) {
    let assets: Vec<RecoveredAsset> = carve(bytes).unwrap();
    let recovered: BTreeMap<String, Vec<u8>> = recovered_map(&assets);
    let want: BTreeMap<String, Vec<u8>> = expected
        .iter()
        .map(|(path, body): &(&str, Vec<u8>)| ((*path).to_owned(), body.clone()))
        .collect();
    assert_eq!(
        recovered.keys().collect::<Vec<&String>>(),
        want.keys().collect::<Vec<&String>>(),
        "recovered name set must equal the source tree"
    );
    for (path, body) in &want {
        assert_eq!(
            recovered.get(path),
            Some(body),
            "content mismatch for {path}"
        );
    }
    for asset in &assets {
        assert_eq!(asset.compression, Compression::None);
    }
}

fn assert_matches_sample(assets: &[RecoveredAsset]) {
    let recovered: BTreeMap<String, Vec<u8>> = recovered_map(assets);
    let expected: BTreeMap<String, Vec<u8>> = sample_tree()
        .into_iter()
        .map(|(path, body): (&str, Vec<u8>)| (path.to_owned(), body))
        .collect();
    assert_eq!(
        recovered.keys().collect::<Vec<&String>>(),
        expected.keys().collect::<Vec<&String>>(),
        "recovered path set must equal the source tree"
    );
    for (path, body) in &expected {
        assert_eq!(
            recovered.get(path),
            Some(body),
            "byte content mismatch for {path}"
        );
    }
    for asset in assets {
        assert_eq!(asset.compression, Compression::None);
    }
}

#[test]
fn carves_real_electron_asar_from_cli() {
    let workdir: PathBuf = unique_dir("webview-cli");
    let dist: PathBuf = workdir.join("dist");
    write_tree(&dist, &sample_tree());
    let asar_path: PathBuf = workdir.join("app.asar");
    if !run_asar_pack(&dist, &asar_path) {
        eprintln!(
            "CORPUS: @electron/asar CLI unavailable (node/npx not on PATH); skipping real-toolchain grade"
        );
        return;
    }
    let bytes: Vec<u8> = fs::read(&asar_path).unwrap();
    assert_eq!(detect_family(&bytes), Some(WebviewFamily::Electron));
    let assets: Vec<RecoveredAsset> = carve(&bytes).unwrap();
    assert_matches_sample(&assets);
    let _ = fs::remove_dir_all(&workdir);
}

#[test]
fn carves_genuine_hand_built_asar() {
    let bytes: Vec<u8> = build_genuine_asar(&sample_tree());
    assert_eq!(detect_family(&bytes), Some(WebviewFamily::Electron));
    let report: CarveReport = carve_report(&bytes).unwrap();
    assert_eq!(report.family, WebviewFamily::Electron);
    assert!(report.external_unpacked.is_empty());
    assert_matches_sample(&report.assets);
}

#[test]
fn locates_asar_embedded_inside_a_larger_binary() {
    let asar: Vec<u8> = build_genuine_asar(&sample_tree());
    let mut host: Vec<u8> = vec![0x4d, 0x5a, 0x90, 0x00];
    host.extend(std::iter::repeat_n(0xCCu8, 4096));
    host.extend_from_slice(&asar);
    host.extend(std::iter::repeat_n(0x00u8, 512));
    let assets: Vec<RecoveredAsset> = carve(&host).unwrap();
    assert_matches_sample(&assets);
}

#[test]
fn single_byte_regression_is_detected() {
    let mut bytes: Vec<u8> = build_genuine_asar(&sample_tree());
    let pristine: BTreeMap<String, Vec<u8>> = recovered_map(&carve(&bytes).unwrap());
    let last: usize = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let tampered: BTreeMap<String, Vec<u8>> = recovered_map(&carve(&bytes).unwrap());
    assert_ne!(
        pristine, tampered,
        "a one-byte perturbation of the blob must surface in the carved tree"
    );
}

#[test]
fn hostile_path_never_escapes_output_root() {
    let files: Vec<(&str, Vec<u8>)> =
        vec![("ok.js", b"safe".to_vec()), ("../evil.js", b"pwn".to_vec())];
    let bytes: Vec<u8> = build_genuine_asar(&files);
    let assets: Vec<RecoveredAsset> = carve(&bytes).unwrap();
    for asset in &assets {
        assert!(!asset.path.contains(".."), "path {} escaped", asset.path);
        assert!(!asset.path.starts_with('/'), "path {} absolute", asset.path);
    }
    assert!(
        assets
            .iter()
            .any(|asset: &RecoveredAsset| asset.path == "ok.js")
    );
    assert!(
        !assets
            .iter()
            .any(|asset: &RecoveredAsset| asset.path.ends_with("evil.js"))
    );
}

#[test]
fn recovers_non_ascii_names_and_binary_content_byte_identically() {
    let tree: Vec<(&str, Vec<u8>)> = tricky_tree();
    assert_round_trip(&build_genuine_asar(&tree), &tree);

    let workdir: PathBuf = unique_dir("webview-nonascii");
    let dist: PathBuf = workdir.join("dist");
    write_tree(&dist, &tree);
    let asar_path: PathBuf = workdir.join("app.asar");
    if run_asar_pack(&dist, &asar_path) {
        let bytes: Vec<u8> = fs::read(&asar_path).unwrap();
        assert_eq!(detect_family(&bytes), Some(WebviewFamily::Electron));
        assert_round_trip(&bytes, &tree);
    } else {
        eprintln!(
            "CORPUS: @electron/asar CLI unavailable (node/npx not on PATH); graded the hand-built asar only"
        );
    }
    let _ = fs::remove_dir_all(&workdir);
}

#[test]
fn no_frontend_is_reported() {
    let bytes: Vec<u8> = vec![0u8; 2048];
    assert!(detect_family(&bytes).is_none());
    assert!(carve(&bytes).is_err());
}
