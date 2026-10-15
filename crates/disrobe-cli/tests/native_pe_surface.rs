#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;
use serde_json::Value as Json;

const HEADERS: usize = 0x400;
const FILE_ALIGNMENT: usize = 0x200;
const CODE: u32 = 0x6000_0020;
const DATA: u32 = 0x4000_0040;

struct Section {
    name: [u8; 8],
    rva: u32,
    virtual_size: u32,
    raw: Vec<u8>,
    characteristics: u32,
}

fn pe64(sections: &[Section], entry: u32, dll: bool, directories: &[(usize, u32, u32)]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; HEADERS];
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff: usize = 0x84;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    let characteristics: u16 = if dll { 0x2022 } else { 0x0022 };
    buf[coff + 18..coff + 20].copy_from_slice(&characteristics.to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&entry.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
    let image_end: u32 = sections
        .iter()
        .map(|s: &Section| s.rva + s.virtual_size)
        .max()
        .unwrap();
    buf[opt + 56..opt + 60].copy_from_slice(&image_end.next_multiple_of(0x1000).to_le_bytes());
    buf[opt + 60..opt + 64].copy_from_slice(&(HEADERS as u32).to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
    buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    for &(index, rva, size) in directories {
        let at: usize = opt + 112 + index * 8;
        buf[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    }
    let table: usize = opt + 0xF0;
    for (index, section) in sections.iter().enumerate() {
        let row: usize = table + index * 40;
        let raw_size: usize = section.raw.len().next_multiple_of(FILE_ALIGNMENT);
        let raw_pointer: usize = if raw_size == 0 { 0 } else { buf.len() };
        buf[row..row + 8].copy_from_slice(&section.name);
        buf[row + 8..row + 12].copy_from_slice(&section.virtual_size.to_le_bytes());
        buf[row + 12..row + 16].copy_from_slice(&section.rva.to_le_bytes());
        buf[row + 16..row + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        buf[row + 20..row + 24].copy_from_slice(&(raw_pointer as u32).to_le_bytes());
        buf[row + 36..row + 40].copy_from_slice(&section.characteristics.to_le_bytes());
        if raw_size != 0 {
            buf.extend_from_slice(&section.raw);
            buf.resize(raw_pointer + raw_size, 0);
        }
    }
    buf
}

fn export_directory(rva: u32, dll: &str, functions: &[(&str, u32)]) -> Vec<u8> {
    let count: u32 = functions.len() as u32;
    let functions_at: u32 = rva + 40;
    let names_at: u32 = functions_at + 4 * count;
    let ordinals_at: u32 = names_at + 4 * count;
    let mut strings_at: u32 = ordinals_at + 2 * count;
    let mut body: Vec<u8> = vec![0u8; 40];
    body[12..16].copy_from_slice(&strings_at.to_le_bytes());
    body[16..20].copy_from_slice(&1u32.to_le_bytes());
    body[20..24].copy_from_slice(&count.to_le_bytes());
    body[24..28].copy_from_slice(&count.to_le_bytes());
    body[28..32].copy_from_slice(&functions_at.to_le_bytes());
    body[32..36].copy_from_slice(&names_at.to_le_bytes());
    body[36..40].copy_from_slice(&ordinals_at.to_le_bytes());
    let mut strings: Vec<u8> = dll.as_bytes().to_vec();
    strings.push(0);
    strings_at += strings.len() as u32;
    let mut names: Vec<u8> = Vec::new();
    let mut ordinals: Vec<u8> = Vec::new();
    for (index, (name, target)) in functions.iter().enumerate() {
        body.extend_from_slice(&target.to_le_bytes());
        names.extend_from_slice(&strings_at.to_le_bytes());
        ordinals.extend_from_slice(&(index as u16).to_le_bytes());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        strings_at += name.len() as u32 + 1;
    }
    body.extend_from_slice(&names);
    body.extend_from_slice(&ordinals);
    body.extend_from_slice(&strings);
    body
}

fn noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn disrobe(args: &[&str], input: &Path, tail: &[&Path]) -> Output {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command.args(args).arg(input);
    for path in tail {
        command.arg(path);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe {args:?}: {error}"))
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path: PathBuf = dir.join(name);
    std::fs::write(&path, bytes).expect("write synthetic image");
    path
}

#[test]
fn native_symbols_lists_the_export_directory_of_a_dll() {
    let scratch: ScratchDir = ScratchDir::create("native-pe-exports").expect("scratch");
    let mut text: Vec<u8> = vec![0xCC; 0x40];
    text[0x00] = 0xC3;
    text[0x10] = 0xC3;
    let directory: Vec<u8> = export_directory(
        0x2000,
        "plain.dll",
        &[("alpha_entry", 0x1000), ("beta_entry", 0x1010)],
    );
    let size: u32 = directory.len() as u32;
    let image: Vec<u8> = pe64(
        &[
            Section {
                name: *b".text\0\0\0",
                rva: 0x1000,
                virtual_size: 0x40,
                raw: text,
                characteristics: CODE,
            },
            Section {
                name: *b".rdata\0\0",
                rva: 0x2000,
                virtual_size: size,
                raw: directory,
                characteristics: DATA,
            },
        ],
        0,
        true,
        &[(0, 0x2000, size)],
    );
    let input: PathBuf = write(scratch.path(), "plain.dll", &image);
    let out: PathBuf = scratch.path().join("symbols.json");
    let run: Output = disrobe(&["native", "symbols"], &input, &[Path::new("--out"), &out]);
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let dump: Json = serde_json::from_slice(&std::fs::read(&out).expect("symbols.json")).unwrap();
    let exports: Vec<(String, u64)> = dump["exports"]
        .as_array()
        .expect("exports array")
        .iter()
        .map(|row: &Json| {
            (
                row["name"].as_str().unwrap().to_owned(),
                row["address"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        exports,
        vec![
            ("alpha_entry".to_owned(), 0x1_8000_1000),
            ("beta_entry".to_owned(), 0x1_8000_1010),
        ]
    );
}

#[test]
fn native_symbols_lists_delay_load_imports() {
    let scratch: ScratchDir = ScratchDir::create("native-pe-delay-imports").expect("scratch");
    let mut rdata: Vec<u8> = vec![0u8; 0x100];
    let descriptor: [u32; 8] = [1, 0x2080, 0x2100, 0x2110, 0x2040, 0, 0, 0];
    for (index, field) in descriptor.iter().enumerate() {
        rdata[index * 4..index * 4 + 4].copy_from_slice(&field.to_le_bytes());
    }
    rdata[0x40..0x48].copy_from_slice(&0x2090u64.to_le_bytes());
    rdata[0x80..0x89].copy_from_slice(b"lazy.dll\0");
    rdata[0x92..0xA1].copy_from_slice(b"deferred_entry\0");
    let image: Vec<u8> = pe64(
        &[
            Section {
                name: *b".text\0\0\0",
                rva: 0x1000,
                virtual_size: 0x10,
                raw: vec![0xC3; 0x10],
                characteristics: CODE,
            },
            Section {
                name: *b".rdata\0\0",
                rva: 0x2000,
                virtual_size: 0x100,
                raw: rdata,
                characteristics: DATA,
            },
        ],
        0x1000,
        false,
        &[(13, 0x2000, 0x40)],
    );
    let input: PathBuf = write(scratch.path(), "lazy-user.exe", &image);
    let out: PathBuf = scratch.path().join("symbols.json");
    let run: Output = disrobe(&["native", "symbols"], &input, &[Path::new("--out"), &out]);
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let dump: Json = serde_json::from_slice(&std::fs::read(&out).expect("symbols.json")).unwrap();
    let delayed: Vec<(String, String)> = dump["imports"]
        .as_array()
        .expect("imports array")
        .iter()
        .filter(|row: &&Json| row["delay_load"] == true)
        .map(|row: &Json| {
            (
                row["name"].as_str().unwrap().to_owned(),
                row["library"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        delayed,
        vec![("deferred_entry".to_owned(), "lazy.dll".to_owned())]
    );
}

#[test]
fn native_decompile_refuses_a_runtime_decrypted_image_by_name() {
    let scratch: ScratchDir = ScratchDir::create("native-runtime-decrypted").expect("scratch");
    let image: Vec<u8> = pe64(
        &[
            Section {
                name: *b".text\0\0\0",
                rva: 0x1000,
                virtual_size: 0x10_0000,
                raw: Vec::new(),
                characteristics: CODE,
            },
            Section {
                name: *b".sealed\0",
                rva: 0x10_1000,
                virtual_size: 0x2_0000,
                raw: noise(0x2_0000),
                characteristics: CODE,
            },
        ],
        0x10_1000,
        false,
        &[],
    );
    let input: PathBuf = write(scratch.path(), "sealed.exe", &image);
    let out: PathBuf = scratch.path().join("decompiled");
    let run: Output = disrobe(
        &["native", "decompile"],
        &input,
        &[Path::new("--out"), &out],
    );
    let stderr: String = String::from_utf8_lossy(&run.stderr)
        .replace('\u{2502}', " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    assert!(
        !run.status.success(),
        "decompile must refuse; stderr: {stderr}"
    );
    assert!(stderr.contains("DR-NATIVE-0225"), "stderr: {stderr}");
    assert!(
        stderr.contains("runtime-decrypted image"),
        "stderr: {stderr}"
    );
    assert!(
        !out.join("manifest.json").exists(),
        "no decompilation of encrypted bytes is written"
    );
    let listing: Output = disrobe(&["native", "disasm"], &input, &[]);
    let listing_stderr: String = String::from_utf8_lossy(&listing.stderr)
        .replace('\u{2502}', " ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    assert!(
        !listing.status.success() && listing_stderr.contains("DR-NATIVE-0225"),
        "disasm must refuse the encrypted image too; stderr: {listing_stderr}"
    );
    let identify: Output = disrobe(&["--json", "identify"], &input, &[]);
    assert!(identify.status.success());
    let report: Json = serde_json::from_slice(&identify.stdout).expect("identify json");
    let finding: &Json = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f: &&Json| f["family"] == "runtime-decrypted")
        .unwrap_or_else(|| panic!("identify names the image: {report}"));
    assert_eq!(finding["support"], "runtime-only");
}
