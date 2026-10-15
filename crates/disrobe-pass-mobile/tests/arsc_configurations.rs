#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::io::{Cursor, Read as _};
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{ArscEntry, ArscResources, parse_arsc};
use zip::ZipArchive;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("apk")
        .join("res-configs")
}

fn read_text(name: &str) -> String {
    let path: PathBuf = fixture_dir().join(name);
    String::from_utf8(std::fs::read(&path).expect("committed reference"))
        .expect("utf-8 reference")
        .replace("\r\n", "\n")
}

fn table_bytes() -> Vec<u8> {
    let apk: Vec<u8> = std::fs::read(fixture_dir().join("configs.apk")).expect("configs.apk");
    let mut archive: ZipArchive<Cursor<&[u8]>> =
        ZipArchive::new(Cursor::new(apk.as_slice())).expect("fixture zip");
    let mut entry: zip::read::ZipFile<'_> =
        archive.by_name("resources.arsc").expect("resource table");
    let mut bytes: Vec<u8> = Vec::new();
    entry.read_to_end(&mut bytes).expect("read table");
    bytes
}

fn labels(table: &ArscResources) -> BTreeSet<(String, String)> {
    table
        .packages
        .iter()
        .flat_map(|package| package.entries.iter())
        .filter(|entry: &&ArscEntry| entry.type_name == "string" && entry.key_name == "label")
        .map(|entry: &ArscEntry| {
            (
                entry.config.clone(),
                entry.value.clone().expect("a string value"),
            )
        })
        .collect()
}

fn dumped_labels() -> BTreeSet<(String, String)> {
    read_text("configs.apk.resources.txt")
        .lines()
        .filter_map(|line: &str| {
            let rest: &str = line.trim().strip_prefix('(')?;
            let (config, value): (&str, &str) = rest.split_once(") ")?;
            let value: &str = value.strip_prefix('"')?.strip_suffix('"')?;
            Some((config.to_owned(), value.to_owned()))
        })
        .collect()
}

#[test]
fn every_configuration_reads_back_as_aapt2_names_it() {
    let table: ArscResources = parse_arsc(&table_bytes()).expect("arsc parse");
    let want: BTreeSet<(String, String)> = dumped_labels();
    assert_eq!(
        want.len(),
        62,
        "aapt2 dump resources lists one label per values directory"
    );
    assert_eq!(
        labels(&table),
        want,
        "each value must sit under the configuration aapt2 reports for it"
    );
    let configurations: BTreeSet<String> = read_text("configs.apk.configurations.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    let read_back: BTreeSet<String> = table
        .packages
        .iter()
        .flat_map(|package| package.entries.iter())
        .map(|entry: &ArscEntry| entry.config.clone())
        .collect();
    assert_eq!(read_back, configurations);
}

#[test]
fn a_changed_density_byte_turns_the_comparison_red() {
    let mut bytes: Vec<u8> = table_bytes();
    let hits: Vec<usize> = (0..bytes.len().saturating_sub(36))
        .filter(|at: &usize| {
            bytes[*at..*at + 2] == [0x01, 0x02]
                && u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) >= 48
                && u16::from_le_bytes([bytes[at + 34], bytes[at + 35]]) == 120
        })
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "one type chunk carries the ldpi configuration"
    );
    bytes[hits[0] + 34] = 160;
    let table: ArscResources = parse_arsc(&bytes).expect("arsc parse");
    let got: BTreeSet<(String, String)> = labels(&table);
    assert_ne!(got, dumped_labels());
    assert!(got.contains(&("mdpi-v4".to_owned(), "values-ldpi".to_owned())));
}
