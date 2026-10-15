#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchFile;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_mobile::{
    ApkReconReport, HermesModule, RnAsset, RnAssetFile, RnPackagedAsset, analyze_apk_recon,
    hermes_react_native_assets, parse_hermes_module, react_native_source_assets,
};
use serde_json::Value;
use zip::ZipArchive;
use zip::write::SimpleFileOptions;

const NODE_BACKSTOP: Duration = Duration::from_mins(2);
const NODE_CAPTURE: usize = 1 << 20;
const BUNDLE: &str = "assets/index.android.bundle";
const IOS_BUNDLE: &str = "Payload/RnAssets.app/main.jsbundle";
const MISSING: &str = "res/drawable-xxxhdpi/node_modules_scope_icons_assets_iconback.webp";
const IOS_MISSING: &str = "assets/node_modules/@scope/icons/assets/Icon-Back@3x.webp";
const BYTECODE: [(&str, u32); 6] = [
    ("bands/rnassets.hbc.v85", 85),
    ("behaviour/rnassets.hbc", 89),
    ("bands/rnassets.hbc.v90", 90),
    ("bands/rnassets.hbc.v94", 94),
    ("modern/rnassets.hbc.v98", 98),
    ("modern/rnassets.hbc.v99", 99),
];
const SOURCES: [&str; 2] = [
    "mobile/hermes/behaviour/rnassets.js",
    "apk/react-native/rnassets.min.js",
];
const RUNNER: &str = "globalThis.print = function () { \
console.log(Array.prototype.map.call(arguments, String).join(' ')); }; \
require('vm').runInThisContext(require('fs').readFileSync(process.argv[1], 'utf8'));";

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
        panic!("{} is a committed fixture: {error}", path.display())
    })
}

fn hermes_assets(relative: &str, version: u32) -> Vec<RnAsset> {
    let bytes: Vec<u8> = read(&corpus().join("mobile").join("hermes").join(relative));
    let module: HermesModule = parse_hermes_module(&bytes).expect("hermes module parse");
    assert_eq!(module.header.version, version, "{relative}");
    hermes_react_native_assets(&module)
}

fn number(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |n: f64| format!("{n}"))
}

fn canonical(asset: &RnAsset) -> String {
    let scales: Vec<String> = asset.scales.iter().map(|s: &f64| format!("{s}")).collect();
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        asset.http_server_location,
        asset.name,
        asset.file_type,
        asset.hash.as_deref().unwrap_or("-"),
        number(asset.width),
        number(asset.height),
        scales.join(",")
    )
}

fn canonical_record(record: &Value) -> String {
    let text = |key: &str| -> String {
        record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    let scales: Vec<String> = record
        .get("scales")
        .and_then(Value::as_array)
        .expect("every packager record carries scales")
        .iter()
        .map(|s: &Value| format!("{}", s.as_f64().expect("numeric scale")))
        .collect();
    assert_eq!(record.get("__packager_asset"), Some(&Value::Bool(true)));
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        text("httpServerLocation"),
        text("name"),
        text("type"),
        text("hash"),
        number(record.get("width").and_then(Value::as_f64)),
        number(record.get("height").and_then(Value::as_f64)),
        scales.join(",")
    )
}

fn interpreter_output() -> String {
    let path: PathBuf = corpus()
        .join("mobile")
        .join("hermes")
        .join("behaviour")
        .join("rnassets.hermes-stdout.txt");
    String::from_utf8(read(&path)).expect("utf-8 interpreter output")
}

fn registered_records() -> Vec<String> {
    let printed: String = interpreter_output();
    let line: &str = printed
        .lines()
        .nth(1)
        .expect("the second printed line is the registry as JSON");
    let records: Vec<Value> = serde_json::from_str(line).expect("registry JSON");
    records.iter().map(canonical_record).collect()
}

#[test]
fn the_asset_table_matches_the_records_the_reference_interpreter_registered() {
    let want: Vec<String> = registered_records();
    assert_eq!(want.len(), 4, "rnassets.js registers four packager assets");
    for (relative, version) in BYTECODE {
        let assets: Vec<RnAsset> = hermes_assets(relative, version);
        let got: Vec<String> = assets.iter().map(canonical).collect();
        assert_eq!(
            got, want,
            "{relative}: the recovered asset table must equal what the hermes interpreter \
             registered when it ran the bundle"
        );
        let modules: Vec<Option<u64>> = assets.iter().map(|a: &RnAsset| a.metro_module).collect();
        assert_eq!(
            modules,
            vec![Some(1), Some(2), Some(3), Some(4)],
            "{relative}: rnassets.js defines the asset modules as __d ids 1 to 4"
        );
        assert!(
            assets
                .iter()
                .all(|a: &RnAsset| a.hermes_function.is_some() && a.source_offset.is_none())
        );
    }
}

#[test]
fn the_asset_table_grader_rejects_a_bundle_without_the_packager_marker() {
    let path: PathBuf = corpus()
        .join("mobile")
        .join("hermes")
        .join("behaviour")
        .join("rnassets.hbc");
    let mut bytes: Vec<u8> = read(&path);
    let marker: &[u8] = b"__packager_asset";
    let at: usize = bytes
        .windows(marker.len())
        .position(|window: &[u8]| window == marker)
        .expect("the marker key is in the string storage");
    bytes[at + marker.len() - 1] = b'z';
    let module: HermesModule =
        parse_hermes_module(&bytes).expect("renaming a key keeps the module");
    let got: Vec<String> = hermes_react_native_assets(&module)
        .iter()
        .map(canonical)
        .collect();
    assert_ne!(
        got,
        registered_records(),
        "an object literal without the packager marker is not an asset record, so the grader \
         must see the table go empty"
    );
    assert!(got.is_empty());
}

fn node_binary() -> PathBuf {
    let candidate: PathBuf = PathBuf::from("node");
    let probe: Option<CapturedOutput> = run_captured(
        candidate.as_path(),
        &["--version"],
        NODE_BACKSTOP,
        NODE_CAPTURE,
    )
    .unwrap_or_else(|error: std::io::Error| {
        panic!(
            "node runs React Native's own asset copy step for this grader and it could not be \
             launched: {error}. Install Node.js; the grader fails rather than skips"
        )
    });
    let out: CapturedOutput =
        probe.unwrap_or_else(|| panic!("node --version did not finish inside {NODE_BACKSTOP:?}"));
    assert_eq!(out.exit_code, Some(0), "node --version must succeed");
    candidate
}

fn node(args: &[&str]) -> String {
    let captured: CapturedOutput =
        run_captured(node_binary().as_path(), args, NODE_BACKSTOP, NODE_CAPTURE)
            .expect("spawn node")
            .unwrap_or_else(|| panic!("node must finish inside {NODE_BACKSTOP:?}"));
    assert_eq!(
        captured.exit_code,
        Some(0),
        "node {args:?} failed: {}",
        String::from_utf8_lossy(&captured.stderr)
    );
    String::from_utf8(captured.stdout)
        .expect("utf-8 output")
        .replace("\r\n", "\n")
}

#[test]
fn the_javascript_bundles_print_what_the_interpreter_printed() {
    for relative in SOURCES {
        let path: PathBuf = corpus().join(relative);
        assert!(path.is_file(), "{relative} is committed");
        let printed: String = node(&["-e", RUNNER, path.to_str().expect("utf-8 path")]);
        assert_eq!(
            printed,
            interpreter_output(),
            "{relative}: an authored bundle is only a reference for the asset table while it \
             registers the same records the Hermes interpreter printed"
        );
    }
}

#[test]
fn the_asset_table_is_read_from_plain_javascript_bundles() {
    let want: Vec<String> = registered_records();
    for relative in SOURCES {
        let source: Vec<u8> = read(&corpus().join(relative));
        let assets: Vec<RnAsset> = react_native_source_assets(&source);
        let got: Vec<String> = assets.iter().map(canonical).collect();
        assert_eq!(got, want, "{relative}");
        let modules: Vec<Option<u64>> = assets.iter().map(|a: &RnAsset| a.metro_module).collect();
        assert_eq!(
            modules,
            vec![Some(1), Some(2), Some(3), Some(4)],
            "{relative}"
        );
        for asset in &assets {
            let offset: usize = asset.source_offset.expect("a source offset");
            assert_eq!(
                source[offset], b'{',
                "{relative}: the offset is the record's brace"
            );
        }
        let renamed: Vec<u8> = String::from_utf8(source.clone())
            .expect("utf-8 source")
            .replace("__packager_asset", "__packager_assez")
            .into_bytes();
        assert!(
            react_native_source_assets(&renamed).is_empty(),
            "{relative}: without the marker no object literal is an asset record"
        );
    }
}

fn react_native_paths(platform: &str, assets: &[RnAsset]) -> Vec<Vec<String>> {
    let records: Vec<Value> = assets
        .iter()
        .map(|asset: &RnAsset| {
            serde_json::json!({
                "__packager_asset": true,
                "httpServerLocation": asset.http_server_location,
                "name": asset.name,
                "type": asset.file_type,
                "scales": asset.scales,
            })
        })
        .collect();
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_rn_asset_paths", "json").expect("scratch file");
    file.write_all(serde_json::to_string(&records).expect("json").as_bytes())
        .expect("write records");
    drop(file);
    let script: PathBuf = corpus()
        .join("apk")
        .join("react-native")
        .join("asset_paths.js");
    node(&[
        script.to_str().expect("utf-8 path"),
        platform,
        scratch.path().to_str().expect("utf-8 path"),
    ])
    .lines()
    .map(|line: &str| serde_json::from_str(line).expect("one JSON array per record"))
    .collect()
}

fn authored(location: &str, name: &str, file_type: &str, scales: &[f64]) -> RnAsset {
    RnAsset {
        hermes_function: None,
        source_offset: None,
        metro_module: None,
        http_server_location: location.to_owned(),
        name: name.to_owned(),
        file_type: file_type.to_owned(),
        hash: None,
        width: None,
        height: None,
        scales: scales.to_vec(),
    }
}

fn edge_assets() -> Vec<RnAsset> {
    vec![
        authored(
            "/assets/?unstable_path=.%2Fassets%2Fimages",
            "Icon",
            "png",
            &[1.0, 2.0, 3.0],
        ),
        authored(
            "/assets/../../Weird Dir/\u{fc}ber",
            "Mixed.Case-Name",
            "png",
            &[0.5, 1.25, 1.0, 1.0],
        ),
        authored(
            "/assets/\u{212a}elvin/\u{130}stanbul",
            "\u{3a3}igma",
            "webp",
            &[1.000_000_1, 3.5, 0.75],
        ),
        authored("assets/no-leading-slash", "vector", "xml", &[1.0, 1.5]),
        authored("/assets/photos", "shot", "heic", &[2.0, 4.0, 0.3]),
        authored("/assets/sounds", "click", "mp3", &[1.0, 2.0]),
        authored("/assetsunstable_path/x", "y", "svg", &[1.0]),
        authored("/assets/empty", "nothing", "png", &[]),
        authored("/static", "assets", "gif", &[1.003_125]),
        authored("/assets/high", "only", "png", &[0.5, 4.0, 5.0]),
        authored("/assets/low", "only", "png", &[0.5, 0.75]),
        authored("/assets/./a//b/../c", "dots", "png", &[2.0]),
        authored("/assets/up/..", "parent", "png", &[1.0]),
        authored("/assets/x/../../../escape", "out", "png", &[3.0]),
    ]
}

fn joined(paths: &[String]) -> String {
    paths.join("|")
}

#[test]
fn resource_paths_follow_react_natives_own_asset_copy_step() {
    let mut assets: Vec<RnAsset> = hermes_assets("behaviour/rnassets.hbc", 89);
    assets.extend(edge_assets());
    let android: Vec<Vec<String>> = react_native_paths("android", &assets);
    let ios: Vec<Vec<String>> = react_native_paths("ios", &assets);
    assert_eq!(android.len(), assets.len());
    assert_eq!(ios.len(), assets.len());
    for ((asset, android), ios) in assets.iter().zip(&android).zip(&ios) {
        assert_eq!(
            joined(&asset.android_resource_paths()),
            joined(android),
            "{} {}: Android paths",
            asset.http_server_location,
            asset.name
        );
        assert_eq!(
            joined(&asset.ios_resource_paths()),
            joined(ios),
            "{} {}: iOS paths",
            asset.http_server_location,
            asset.name
        );
    }
    let flat: Vec<&String> = android.iter().chain(&ios).flatten().collect();
    assert!(
        flat.iter()
            .any(|path: &&String| path.contains("drawable-160dpi"))
    );
    assert!(
        flat.iter()
            .any(|path: &&String| path.ends_with("only@4x.png"))
    );
    assert!(
        flat.iter()
            .any(|path: &&String| path.ends_with("only@0.75x.png"))
    );
    let unstripped: Vec<String> = assets
        .iter()
        .map(|asset: &RnAsset| {
            let mut kept: RnAsset = asset.clone();
            kept.http_server_location = format!("/x{}", asset.http_server_location);
            joined(&kept.android_resource_paths())
        })
        .collect();
    let want: Vec<String> = android
        .iter()
        .map(|paths: &Vec<String>| joined(paths))
        .collect();
    assert_ne!(
        unstripped, want,
        "keeping the assets_ prefix in the identifier must turn the comparison red"
    );
}

#[test]
fn an_unusable_scale_yields_no_drawable_path() {
    let asset: RnAsset = authored("/assets/a", "b", "png", &[-1.0, f64::NAN, f64::INFINITY]);
    assert!(asset.android_resource_paths().is_empty());
    let raw: RnAsset = authored("/assets/a", "b", "otf", &[f64::NAN]);
    assert_eq!(raw.android_resource_paths(), vec!["res/raw/a_b.otf"]);
}

fn rn_dir() -> PathBuf {
    corpus().join("apk").join("react-native")
}

fn zip_entries(bytes: &[u8]) -> BTreeSet<String> {
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(bytes)).expect("fixture zip");
    (0..archive.len())
        .map(|index: usize| archive.by_index(index).expect("entry").name().to_owned())
        .collect()
}

fn shortening_map() -> BTreeMap<String, String> {
    let text: String =
        String::from_utf8(read(&rn_dir().join("rnassets-short.map.txt"))).expect("utf-8 map");
    text.lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| {
            let (from, to): (&str, &str) = line
                .trim()
                .split_once(" -> ")
                .expect("aapt2 writes <path> -> <short path>");
            (from.to_owned(), to.to_owned())
        })
        .collect()
}

fn linked_path(resource_path: &str, map: &BTreeMap<String, String>) -> Option<String> {
    map.keys()
        .find(|linked: &&String| linked.replace("-v4/", "/") == resource_path)
        .cloned()
}

fn located(report: &ApkReconReport) -> BTreeMap<String, Option<String>> {
    report
        .react_native_assets
        .iter()
        .flat_map(|packaged: &RnPackagedAsset| packaged.files.iter())
        .map(|file: &RnAssetFile| (file.path.clone(), file.entry.clone()))
        .collect()
}

fn recon(name: &str) -> (ApkReconReport, BTreeSet<String>) {
    let bytes: Vec<u8> = read(&rn_dir().join(name));
    let report: ApkReconReport = analyze_apk_recon(&bytes).expect("apk recon");
    (report, zip_entries(&bytes))
}

fn records_of(report: &ApkReconReport, bundle: &str) -> Vec<String> {
    report
        .react_native_assets
        .iter()
        .map(|packaged: &RnPackagedAsset| {
            assert_eq!(packaged.bundle, bundle);
            canonical(&packaged.asset)
        })
        .collect()
}

#[test]
fn recon_links_each_packaged_asset_to_the_file_aapt2_linked() {
    let map: BTreeMap<String, String> = shortening_map();
    assert_eq!(map.len(), 10, "aapt2 linked ten asset files");
    let want_records: Vec<String> = registered_records();
    for (name, shortened) in [
        ("rnassets.apk", false),
        ("rnassets-js.apk", false),
        ("rnassets-short.apk", true),
    ] {
        let (report, entries): (ApkReconReport, BTreeSet<String>) = recon(name);
        assert_eq!(records_of(&report, BUNDLE), want_records, "{name}");
        let files: BTreeMap<String, Option<String>> = located(&report);
        assert_eq!(files.len(), 11, "{name}: ten linked files and one left out");
        for (resource_path, entry) in &files {
            let linked: Option<String> = linked_path(resource_path, &map);
            let want: Option<String> = if shortened {
                linked.as_ref().map(|path: &String| map[path].clone())
            } else {
                linked
            };
            assert_eq!(
                entry, &want,
                "{name}: {resource_path} must point at the entry aapt2 wrote for it"
            );
            if let Some(entry) = entry {
                assert!(entries.contains(entry), "{name}: {entry} is in the zip");
            }
        }
        assert_eq!(
            files.get(MISSING),
            Some(&None),
            "{name}: the split density is missing"
        );
    }
}

#[test]
fn recon_finds_ios_assets_beside_the_bundle_in_an_ipa() {
    let (report, entries): (ApkReconReport, BTreeSet<String>) = recon("rnassets.ipa");
    assert_eq!(records_of(&report, IOS_BUNDLE), registered_records());
    let files: BTreeMap<String, Option<String>> = located(&report);
    let ios: Vec<Vec<String>> = react_native_paths(
        "ios",
        &report
            .react_native_assets
            .iter()
            .map(|packaged: &RnPackagedAsset| packaged.asset.clone())
            .collect::<Vec<RnAsset>>(),
    );
    let want: BTreeSet<String> = ios.into_iter().flatten().collect();
    assert_eq!(
        files.keys().cloned().collect::<BTreeSet<String>>(),
        want,
        "every path React Native's iOS copy step writes is looked up"
    );
    for (path, entry) in &files {
        let packaged: String = format!("Payload/RnAssets.app/{path}");
        if path == IOS_MISSING {
            assert_eq!(entry, &None, "the left-out @3x icon is missing");
        } else {
            assert_eq!(entry.as_deref(), Some(packaged.as_str()), "{path}");
            assert!(entries.contains(&packaged));
        }
    }
    assert_eq!(files.len(), 8);
}

#[test]
fn shortened_paths_resolve_only_through_the_resource_table() {
    let bytes: Vec<u8> = read(&rn_dir().join("rnassets-short.apk"));
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(bytes.as_slice())).expect("fixture zip");
    let mut stripped: Vec<u8> = Vec::new();
    {
        let mut writer: zip::ZipWriter<Cursor<&mut Vec<u8>>> =
            zip::ZipWriter::new(Cursor::new(&mut stripped));
        let options: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for index in 0..archive.len() {
            let mut entry: zip::read::ZipFile<'_> = archive.by_index(index).expect("entry");
            let name: String = entry.name().to_owned();
            if name == "resources.arsc" {
                continue;
            }
            let mut data: Vec<u8> = Vec::new();
            entry.read_to_end(&mut data).expect("read entry");
            writer.start_file(name.as_str(), options).expect("start");
            writer.write_all(&data).expect("write");
        }
        writer.finish().expect("finish");
    }
    let report: ApkReconReport = analyze_apk_recon(&stripped).expect("apk recon");
    let files: BTreeMap<String, Option<String>> = located(&report);
    assert_eq!(files.len(), 11);
    assert!(
        files.values().all(Option::is_none),
        "without resources.arsc a shortened file name says nothing about its resource, so no \
         file may be claimed: {files:?}"
    );
}

struct Noise(u64);

impl Noise {
    const fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn mutate(&mut self, original: &[u8], round: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = original.to_vec();
        if round % 10 == 9 {
            let keep: usize = (self.next() as usize) % bytes.len();
            bytes.truncate(keep);
        }
        for _ in 0..=(self.next() % 6) {
            if bytes.is_empty() {
                break;
            }
            let at: usize = (self.next() as usize) % bytes.len();
            bytes[at] = self.next() as u8;
        }
        bytes
    }
}

#[test]
fn hostile_bytecode_never_panics_the_asset_scan() {
    let mut noise: Noise = Noise(0x9e37_79b9_7f4a_7c15);
    let mut scanned: usize = 0;
    for (relative, _) in BYTECODE {
        let original: Vec<u8> = read(&corpus().join("mobile").join("hermes").join(relative));
        for round in 0..300 {
            let bytes: Vec<u8> = noise.mutate(&original, round);
            if let Ok(module) = parse_hermes_module(&bytes) {
                let assets: Vec<RnAsset> = hermes_react_native_assets(&module);
                for asset in &assets {
                    assert!(asset.scales.len() <= 16);
                    let _: Vec<String> = asset.android_resource_paths();
                    let _: Vec<String> = asset.ios_resource_paths();
                }
                scanned += 1;
            }
        }
    }
    assert!(scanned > 100, "only {scanned} mutated modules parsed");
}

#[test]
fn hostile_javascript_never_panics_the_asset_scan() {
    let mut noise: Noise = Noise(0x2545_f491_4f6c_dd1d);
    let mut found: usize = 0;
    for relative in SOURCES {
        let original: Vec<u8> = read(&corpus().join(relative));
        for round in 0..400 {
            let bytes: Vec<u8> = noise.mutate(&original, round);
            for asset in react_native_source_assets(&bytes) {
                assert!(asset.scales.len() <= 16);
                let _: Vec<String> = asset.ios_resource_paths();
                found += 1;
            }
        }
    }
    let deep: Vec<u8> = format!(
        "{{__packager_asset:!0,x:{}1{},name:\"n\",type:\"png\",httpServerLocation:\"/a\"}}",
        "[".repeat(100_000),
        "]".repeat(100_000)
    )
    .into_bytes();
    assert!(react_native_source_assets(&deep).is_empty());
    let many: Vec<u8> = "{__packager_asset:!0,".repeat(50_000).into_bytes();
    assert!(react_native_source_assets(&many).is_empty());
    assert!(found > 100, "only {found} records survived the mutations");
}
