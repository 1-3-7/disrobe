#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_webview::{
    CarveConfig, CarveReport, Compression, EntryRefusal, IntegrityStatus, RecoveredAsset,
    WebviewFamily, carve_with_config, detect_family,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const ASAR_NAME: &str = "@electron/asar";
const ASAR_VERSION: &str = "4.3.1";
const ASAR_PACKAGE: &str = "@electron/asar@4.3.1";
const ASAR_INTEGRITY: &str = "sha512-6pI64z/tMSBkUTZLQFYhs2YiB7fS9sKA6gy7/2nH1Ju7GGwT32UPsj4Mxsws5NMmtR6C0zYdXVxEU/rGqJRCJA==";
const UNPACK_GLOB: &str = "*.dat";
const APP_MEMBERS: usize = 10;

fn app_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.extend(["corpus", "webview", "electron", "asar_app"]);
    assert!(
        root.join("package.json").is_file(),
        "missing corpus fixture {}: the committed app the grader packs is absent",
        root.display()
    );
    root
}

fn node_tool(tool: &str) -> Command {
    let mut command: Command = if cfg!(windows) {
        let mut shell: Command = Command::new("cmd");
        shell.args(["/C", tool]);
        shell
    } else {
        Command::new(tool)
    };
    command.env_remove("FORCE_COLOR");
    command
}

fn run_asar<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command: Command = node_tool("npx");
    command.args(["--yes", ASAR_PACKAGE]).args(args);
    command.output().unwrap_or_else(|error: std::io::Error| {
        panic!("required tool missing: npx cannot be spawned to run {ASAR_PACKAGE}: {error}")
    })
}

fn pack(source: &Path, archive: &Path) {
    let output: Output = run_asar([
        OsStr::new("pack"),
        source.as_os_str(),
        archive.as_os_str(),
        OsStr::new("--unpack"),
        OsStr::new(UNPACK_GLOB),
    ]);
    assert!(
        output.status.success() && archive.is_file(),
        "required tool missing: `npx --yes {ASAR_PACKAGE} pack` exited with {} and wrote no \
         archive at {}\nstdout: {}\nstderr: {}",
        output.status,
        archive.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn extract(archive: &Path, destination: &Path) {
    let output: Output = run_asar([
        OsStr::new("extract"),
        archive.as_os_str(),
        destination.as_os_str(),
    ]);
    assert!(
        output.status.success() && destination.is_dir(),
        "required tool missing: `npx --yes {ASAR_PACKAGE} extract` exited with {} and wrote \
         nothing at {}\nstdout: {}\nstderr: {}",
        output.status,
        destination.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    let hex: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte: &u8| [hex[usize::from(byte >> 4)], hex[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

fn tree_digests(root: &Path) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative: String = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(relative, sha256_hex(&fs::read(&path).unwrap()));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Discrepancy {
    Missing(String),
    Extra(String),
    Differs(String),
}

fn grade(
    recovered: &BTreeMap<String, String>,
    reference: &BTreeMap<String, String>,
) -> Vec<Discrepancy> {
    let mut out: Vec<Discrepancy> = Vec::new();
    for (path, digest) in reference {
        match recovered.get(path) {
            None => out.push(Discrepancy::Missing(path.clone())),
            Some(found) if found != digest => out.push(Discrepancy::Differs(path.clone())),
            Some(_) => {}
        }
    }
    for path in recovered.keys() {
        if !reference.contains_key(path) {
            out.push(Discrepancy::Extra(path.clone()));
        }
    }
    out
}

fn asset_digests(assets: &[RecoveredAsset]) -> BTreeMap<String, String> {
    assets
        .iter()
        .map(|asset: &RecoveredAsset| (asset.path.clone(), sha256_hex(&asset.bytes)))
        .collect()
}

struct Archive {
    scratch: ScratchDir,
    bytes: Vec<u8>,
    packed_reference: BTreeMap<String, String>,
    unpacked_reference: BTreeSet<String>,
}

fn pack_and_extract(source: &Path, purpose: &str) -> Archive {
    let scratch: ScratchDir = ScratchDir::create(purpose).unwrap();
    let archive: PathBuf = scratch.path().join("app.asar");
    pack(source, &archive);
    let reference_root: PathBuf = scratch.path().join("reference");
    extract(&archive, &reference_root);
    let mut packed_reference: BTreeMap<String, String> = tree_digests(&reference_root);
    let sidecar: PathBuf = scratch.path().join("app.asar.unpacked");
    let unpacked_reference: BTreeSet<String> = if sidecar.is_dir() {
        tree_digests(&sidecar).into_keys().collect()
    } else {
        BTreeSet::new()
    };
    for name in &unpacked_reference {
        packed_reference.remove(name);
    }
    let bytes: Vec<u8> = fs::read(&archive).unwrap();
    Archive {
        scratch,
        bytes,
        packed_reference,
        unpacked_reference,
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry: fs::DirEntry = entry.unwrap();
        let target: PathBuf = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn pack_app() -> Archive {
    let staged: ScratchDir = ScratchDir::create("webview-asar-staged-app").unwrap();
    copy_tree(&app_root(), staged.path());
    fs::write(staged.path().join("assets").join("empty.txt"), b"").unwrap();
    let archive: Archive = pack_and_extract(staged.path(), "webview-asar-reference");
    assert_eq!(
        archive.packed_reference.len() + archive.unpacked_reference.len(),
        APP_MEMBERS,
        "`{ASAR_PACKAGE} extract` must reproduce every member of the committed app"
    );
    assert_eq!(
        archive.unpacked_reference,
        BTreeSet::from(["native/blob.dat".to_owned()]),
        "`--unpack {UNPACK_GLOB}` must move exactly the one binary blob beside the archive"
    );
    archive
}

fn unpacked_set(report: &CarveReport) -> BTreeSet<String> {
    report.external_unpacked.iter().cloned().collect()
}

#[test]
fn the_pinned_package_carries_the_recorded_integrity() {
    let mut command: Command = node_tool("npm");
    command.args(["view", ASAR_PACKAGE, "version", "dist.integrity", "--json"]);
    let output: Output = command.output().unwrap_or_else(|error: std::io::Error| {
        panic!("required tool missing: npm cannot be spawned to look up {ASAR_PACKAGE}: {error}")
    });
    assert!(
        output.status.success(),
        "required tool missing: `npm view {ASAR_PACKAGE}` exited with {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "`npm view {ASAR_PACKAGE} --json` printed no json ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    let record: &Value = match &printed {
        Value::Array(records) if records.len() == 1 => &records[0],
        other => other,
    };
    assert_eq!(
        record.get("version").and_then(Value::as_str),
        Some(ASAR_VERSION),
        "{ASAR_NAME} resolved to another version than the pin"
    );
    assert_eq!(
        record.get("dist.integrity").and_then(Value::as_str),
        Some(ASAR_INTEGRITY),
        "{ASAR_PACKAGE} no longer carries the integrity recorded with the pin"
    );
    let ran: Output = run_asar(["--version"]);
    assert_eq!(
        String::from_utf8_lossy(&ran.stdout).trim(),
        format!("v{ASAR_VERSION}"),
        "required tool missing: npx did not run {ASAR_PACKAGE}\nstderr: {}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

#[test]
fn every_packed_member_matches_asar_extract_by_sha256() {
    let archive: Archive = pack_app();
    assert_eq!(detect_family(&archive.bytes), Some(WebviewFamily::Electron));
    let report: CarveReport =
        carve_with_config(&archive.bytes, &CarveConfig::default()).expect("pristine archive");
    assert_eq!(report.family, WebviewFamily::Electron);
    assert_eq!(
        grade(&asset_digests(&report.assets), &archive.packed_reference),
        Vec::new(),
        "every packed member must equal `{ASAR_PACKAGE} extract` output by sha256"
    );
    assert_eq!(unpacked_set(&report), archive.unpacked_reference);
    assert!(report.symlinks.is_empty());
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    assert_eq!(report.declared, APP_MEMBERS);
    assert_eq!(report.recovered, APP_MEMBERS);
    for asset in &report.assets {
        assert_eq!(asset.compression, Compression::None);
        assert_eq!(
            asset.integrity,
            IntegrityStatus::Verified,
            "{ASAR_PACKAGE} writes a sha256 integrity block for {}",
            asset.path
        );
    }
    archive.scratch.close().unwrap();
}

#[test]
fn a_flipped_byte_in_one_member_turns_the_grade_red() {
    let archive: Archive = pack_app();
    let mut report: CarveReport =
        carve_with_config(&archive.bytes, &CarveConfig::default()).expect("pristine archive");
    let Some(victim) = report
        .assets
        .iter_mut()
        .find(|asset: &&mut RecoveredAsset| asset.path == "assets/data/ramp.bin")
    else {
        panic!("the binary asset was not recovered")
    };
    victim.bytes[7] ^= 0x01;
    assert_eq!(
        grade(&asset_digests(&report.assets), &archive.packed_reference),
        vec![Discrepancy::Differs("assets/data/ramp.bin".to_owned())]
    );
    report
        .assets
        .retain(|asset: &RecoveredAsset| asset.path != "index.html");
    assert!(
        grade(&asset_digests(&report.assets), &archive.packed_reference)
            .contains(&Discrepancy::Missing("index.html".to_owned()))
    );
    archive.scratch.close().unwrap();
}

fn pickle_wrap(json: &[u8], data: &[u8]) -> Vec<u8> {
    let json_len: u32 = u32::try_from(json.len()).unwrap();
    let aligned: usize = json.len().div_ceil(4) * 4;
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

fn split_asar(bytes: &[u8]) -> (Map<String, Value>, Vec<u8>) {
    let field =
        |at: usize| -> usize { u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize };
    assert_eq!(field(0), 4, "unexpected asar pickle wrapper size");
    let json_end: usize = 16 + field(12);
    let root: Value = serde_json::from_slice(&bytes[16..json_end]).unwrap();
    let files: Map<String, Value> = root["files"].as_object().unwrap().clone();
    (files, bytes[8 + field(4)..].to_vec())
}

fn rebuild_asar(files: Map<String, Value>, data: &[u8]) -> Vec<u8> {
    let json: Vec<u8> = serde_json::to_vec(&json!({ "files": files })).unwrap();
    pickle_wrap(&json, data)
}

struct HostileCase {
    name: &'static str,
    tamper: fn(&mut Map<String, Value>, usize),
    refused: &'static [&'static str],
    lost: &'static [&'static str],
    added: usize,
    aggregate_ratio: Option<u64>,
}

const HOSTILE_CASES: [HostileCase; 6] = [
    HostileCase {
        name: "unsafe name",
        tamper: |files: &mut Map<String, Value>, _: usize| {
            let copy: Value = files["main.js"].clone();
            files.insert("..".to_owned(), json!({ "files": { "x": copy } }));
        },
        refused: &["../x"],
        lost: &[],
        added: 1,
        aggregate_ratio: None,
    },
    HostileCase {
        name: "missing offset",
        tamper: |files: &mut Map<String, Value>, _: usize| {
            let mut copy: Value = files["main.js"].clone();
            copy.as_object_mut().unwrap().remove("offset");
            files.insert("nooffset.js".to_owned(), copy);
        },
        refused: &["nooffset.js"],
        lost: &[],
        added: 1,
        aggregate_ratio: None,
    },
    HostileCase {
        name: "escaping link",
        tamper: |files: &mut Map<String, Value>, _: usize| {
            files.insert(
                "escape.js".to_owned(),
                json!({ "link": "../../outside.txt" }),
            );
        },
        refused: &["escape.js"],
        lost: &[],
        added: 1,
        aggregate_ratio: None,
    },
    HostileCase {
        name: "out-of-range entry",
        tamper: |files: &mut Map<String, Value>, data_len: usize| {
            files.insert(
                "range.bin".to_owned(),
                json!({ "size": 16, "offset": (data_len - 8).to_string() }),
            );
        },
        refused: &["range.bin"],
        lost: &[],
        added: 1,
        aggregate_ratio: None,
    },
    HostileCase {
        name: "asset over the ratio cap",
        tamper: |files: &mut Map<String, Value>, data_len: usize| {
            files.insert(
                "zz-alias.bin".to_owned(),
                json!({ "size": data_len, "offset": "0" }),
            );
        },
        refused: &["zz-alias.bin"],
        lost: &[],
        added: 1,
        aggregate_ratio: Some(1),
    },
    HostileCase {
        name: "case-colliding pair",
        tamper: |files: &mut Map<String, Value>, _: usize| {
            let copy: Value = files["index.html"].clone();
            files.insert("INDEX.HTML".to_owned(), copy);
        },
        refused: &["INDEX.HTML", "index.html"],
        lost: &["index.html"],
        added: 1,
        aggregate_ratio: None,
    },
];

fn judge_hostile(case: &HostileCase, archive: &Archive) -> Vec<String> {
    let (mut files, data): (Map<String, Value>, Vec<u8>) = split_asar(&archive.bytes);
    (case.tamper)(&mut files, data.len());
    let tampered: Vec<u8> = rebuild_asar(files, &data);
    let mut cfg: CarveConfig = CarveConfig::default();
    if let Some(ratio) = case.aggregate_ratio {
        cfg.quota.max_aggregate_ratio = ratio;
    }
    let report: CarveReport = match carve_with_config(&tampered, &cfg) {
        Ok(report) => report,
        Err(error) => return vec![format!("the carve aborted: {error}")],
    };
    let mut failures: Vec<String> = Vec::new();
    let mut refused: Vec<&str> = report
        .refusals
        .iter()
        .map(|refusal: &EntryRefusal| refusal.path.as_str())
        .collect();
    refused.sort_unstable();
    if refused != case.refused {
        failures.push(format!(
            "refusals {:?}, expected one each for {:?}",
            report.refusals, case.refused
        ));
    }
    let mut expected_assets: BTreeMap<String, String> = archive.packed_reference.clone();
    for lost in case.lost {
        expected_assets.remove(*lost);
    }
    let discrepancies: Vec<Discrepancy> = grade(&asset_digests(&report.assets), &expected_assets);
    if !discrepancies.is_empty() {
        failures.push(format!(
            "the entries that are not bad differ from asar extract: {discrepancies:?}"
        ));
    }
    if unpacked_set(&report) != archive.unpacked_reference {
        failures.push(format!(
            "unpacked members {:?}, expected {:?}",
            report.external_unpacked, archive.unpacked_reference
        ));
    }
    if !report.symlinks.is_empty() {
        failures.push(format!("symlinks {:?} were accepted", report.symlinks));
    }
    let declared: usize = APP_MEMBERS + case.added;
    let recovered: usize = declared - case.refused.len();
    if report.declared != declared || report.recovered != recovered {
        failures.push(format!(
            "coverage {}/{} = {:.4}, expected {recovered}/{declared}",
            report.recovered,
            report.declared,
            report.coverage()
        ));
    }
    failures
}

#[test]
fn each_hostile_entry_is_refused_alone_while_the_rest_match_asar_extract() {
    let archive: Archive = pack_app();
    let mut verdicts: Vec<String> = Vec::new();
    for case in &HOSTILE_CASES {
        for failure in judge_hostile(case, &archive) {
            verdicts.push(format!("{}: {failure}", case.name));
        }
    }
    assert!(
        verdicts.is_empty(),
        "hostile archives derived from the {ASAR_PACKAGE} build were not handled entry by \
         entry:\n{}",
        verdicts.join("\n")
    );
    archive.scratch.close().unwrap();
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

#[test]
fn non_ascii_names_and_binary_content_match_asar_extract_by_sha256() {
    let source: ScratchDir = ScratchDir::create("webview-asar-nonascii-src").unwrap();
    for (relative, body) in tricky_tree() {
        let path: PathBuf = source.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
    }
    let archive: Archive = pack_and_extract(source.path(), "webview-asar-nonascii");
    let expected: BTreeMap<String, String> = tricky_tree()
        .into_iter()
        .map(|(path, body): (&str, Vec<u8>)| (path.to_owned(), sha256_hex(&body)))
        .collect();
    assert_eq!(
        grade(&archive.packed_reference, &expected),
        Vec::new(),
        "`{ASAR_PACKAGE} extract` must reproduce the written tree"
    );
    let report: CarveReport =
        carve_with_config(&archive.bytes, &CarveConfig::default()).expect("pristine archive");
    assert_eq!(
        grade(&asset_digests(&report.assets), &archive.packed_reference),
        Vec::new()
    );
    archive.scratch.close().unwrap();
    source.close().unwrap();
}
