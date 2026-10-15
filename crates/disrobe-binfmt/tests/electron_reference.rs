#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_binfmt::electron::{
    ArchiveIntegrity, DeclaredIntegrity, ExecutableReport, FileStatus, FuseState, FuseWire,
    IntegritySource, check_archive, declared_integrity_from_plist, fuse_wires, inspect_executable,
};
use serde_json::Value;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/electron-app")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn reference() -> Value {
    serde_json::from_slice(&fixture("reference.json")).expect("reference JSON")
}

fn wire_matches(wire: &FuseWire, expected: &Value) -> bool {
    let fuses: &serde_json::Map<String, Value> = expected.as_object().expect("fuse config");
    let declared: usize = fuses
        .keys()
        .filter(|key| key.parse::<usize>().is_ok())
        .count();
    Some(wire.version.to_string().as_str()) == expected["version"].as_str()
        && usize::from(wire.declared_length) == declared
        && wire.complete
        && wire
            .fuses
            .iter()
            .all(|fuse| expected[fuse.index.to_string()].as_u64() == Some(u64::from(fuse.raw)))
}

#[test]
fn fuse_wires_match_electron_fuses_after_every_flip() {
    let reference: Value = reference();
    for name in ["fake_electron.exe", "fuses_hardened.exe", "fuses_mixed.exe"] {
        let wires: Vec<FuseWire> = fuse_wires(&fixture(name));
        assert_eq!(wires.len(), 1, "{name}");
        assert!(
            wire_matches(&wires[0], &reference["fuses"][name]),
            "{name}: {:?} != {}",
            wires[0],
            reference["fuses"][name]
        );
        assert_eq!(wires[0].fuses[0].name, Some("RunAsNode"));
        assert_eq!(wires[0].fuses[8].name, Some("WasmTrapHandlers"));
    }
    let hardened: Vec<FuseWire> = fuse_wires(&fixture("fuses_hardened.exe"));
    let states: Vec<FuseState> = hardened[0].fuses.iter().map(|fuse| fuse.state).collect();
    assert_eq!(states[0], FuseState::Disabled);
    assert_eq!(states[4], FuseState::Enabled);

    let universal: Vec<FuseWire> = fuse_wires(&fixture("universal.bin"));
    let slices: Vec<Option<&str>> = universal.iter().map(|wire| wire.slice.as_deref()).collect();
    assert_eq!(slices, vec![Some("x86_64"), Some("arm64")]);
    for wire in &universal {
        assert!(
            wire_matches(wire, &reference["fuses"]["universal.bin"]),
            "{wire:?}"
        );
    }
}

#[test]
fn declared_integrity_and_archive_hashes_match_electron_asar() {
    let reference: Value = reference();
    let archive_reference: &Value = &reference["archive"];
    let report: ExecutableReport = inspect_executable(&fixture("fake_electron.exe"));
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(
        report.declared_integrity,
        vec![DeclaredIntegrity {
            file: "resources\\app.asar".to_owned(),
            algorithm: "SHA256".to_owned(),
            hash: archive_reference["header_sha256"]
                .as_str()
                .expect("hash")
                .to_owned(),
            source: IntegritySource::PeResource,
        }]
    );

    let archive: ArchiveIntegrity = check_archive(&fixture("app.asar")).expect("archive parses");
    assert_eq!(
        Some(archive.header_sha256.as_str()),
        archive_reference["header_sha256"].as_str()
    );
    assert_eq!(
        archive.header_size as u64,
        archive_reference["header_size"].as_u64().expect("size")
    );
    let expected: BTreeMap<String, &Value> = archive_reference["files"]
        .as_object()
        .expect("files")
        .iter()
        .map(|(name, entry)| (name.clone(), entry))
        .collect();
    let packed: usize = expected
        .values()
        .filter(|entry| entry["unpacked"] == Value::Bool(false))
        .count();
    assert_eq!(archive.files.len(), packed);
    for file in &archive.files {
        let entry: &Value = expected
            .get(&file.path)
            .expect("file listed by @electron/asar");
        assert_eq!(Some(file.size), entry["size"].as_u64(), "{}", file.path);
        assert_eq!(file.status, FileStatus::Match, "{}", file.path);
    }
    assert_eq!(archive.unpacked, vec!["addon.node".to_owned()]);
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    let at: usize = bytes
        .windows(from.len())
        .position(|window: &[u8]| window == from)
        .expect("pattern present");
    bytes[at..at + to.len()].copy_from_slice(to);
}

#[test]
fn changed_fuses_files_and_headers_are_caught() {
    let reference: Value = reference();
    let mut flipped: Vec<u8> = fixture("fake_electron.exe");
    let sentinel: usize = flipped
        .windows(32)
        .position(|window: &[u8]| window == disrobe_binfmt::electron::FUSE_SENTINEL)
        .expect("sentinel");
    flipped[sentinel + 34] ^= 0x01;
    assert!(!wire_matches(
        &fuse_wires(&flipped)[0],
        &reference["fuses"]["fake_electron.exe"]
    ));

    let mut content: Vec<u8> = fixture("app.asar");
    replace_once(&mut content, b"hello, ${name}", b"hello, ${user}");
    let archive: ArchiveIntegrity = check_archive(&content).expect("still parses");
    let util = archive
        .files
        .iter()
        .find(|file| file.path == "lib/util.js")
        .expect("util.js");
    assert_eq!(util.status, FileStatus::Mismatch);
    assert_eq!(util.mismatched_blocks, vec![0]);

    let mut header: Vec<u8> = fixture("app.asar");
    replace_once(&mut header, b"\"main.js\"", b"\"maim.js\"");
    let archive: ArchiveIntegrity = check_archive(&header).expect("still parses");
    assert_ne!(
        Some(archive.header_sha256.as_str()),
        reference["archive"]["header_sha256"].as_str()
    );
}

#[test]
fn info_plist_integrity_declarations_are_read() {
    let plist: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>Sample</string>
  <key>ElectronAsarIntegrity</key>
  <dict>
    <key>Resources/app.asar</key>
    <dict>
      <key>algorithm</key><string>SHA256</string>
      <key>hash</key><string>c2754b2d135d4894715d64fa790a1f1b55124b9f88299a82a6bc8dc7c1f78c4e</string>
    </dict>
  </dict>
</dict>
</plist>
"#;
    let declared: Vec<DeclaredIntegrity> =
        declared_integrity_from_plist(plist).expect("plist parses");
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0].file, "Resources/app.asar");
    assert_eq!(declared[0].source, IntegritySource::InfoPlist);
    assert_eq!(declared[0].algorithm, "SHA256");
}

#[test]
fn corrupted_executables_and_archives_never_panic() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for name in ["fake_electron.exe", "universal.bin", "app.asar"] {
        let original: Vec<u8> = fixture(name);
        for round in 0..200 {
            let mut bytes: Vec<u8> = original.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for flip in 0..=(state % 8) {
                let at: usize = ((state >> (flip * 3)) % bytes.len() as u64) as usize;
                bytes[at] = (state >> (flip % 8 * 8)) as u8;
            }
            if round % 6 == 0 {
                bytes.truncate((state % bytes.len() as u64) as usize);
            }
            let _ = inspect_executable(&bytes);
            let _ = check_archive(&bytes);
        }
    }
}
