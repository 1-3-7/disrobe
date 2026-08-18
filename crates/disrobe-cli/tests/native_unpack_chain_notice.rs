#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;

const UPX_MARKER: &[u8] = b"UPX!";
const ASPACK_MARKER: &[u8] = b".aspack";

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn pe_with_section_markers(markers: &[&[u8]]) -> Vec<u8> {
    let section_names: Vec<&[u8]> = markers
        .iter()
        .copied()
        .filter(|m: &&[u8]| m.len() <= 8)
        .collect();
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let header_end: usize = sec_table + section_names.len().max(1) * 40;
    let mut buf: Vec<u8> = vec![0u8; header_end + 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x80 + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4]
        .copy_from_slice(&u16::try_from(section_names.len()).unwrap().to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&u16::try_from(opt_size).unwrap().to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    for (index, name) in section_names.iter().enumerate() {
        let entry: usize = sec_table + index * 40;
        buf[entry..entry + name.len()].copy_from_slice(name);
    }
    for marker in markers {
        let cursor: usize = buf.len();
        buf.extend_from_slice(marker);
        buf.resize(cursor + marker.len() + 16, 0);
    }
    buf
}

fn run_unpack(image: &[u8]) -> (bool, String) {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli --bin disrobe` first",
        binary.display()
    );
    let scratch: ScratchDir = ScratchDir::create("native-unpack-chain").expect("scratch dir");
    let input: PathBuf = scratch.path().join("layered.exe");
    std::fs::write(&input, image).expect("write layered image");
    let output: Output = Command::new(&binary)
        .arg("native")
        .arg("unpack")
        .arg(&input)
        .arg("--out")
        .arg(scratch.path().join("recovered.bin"))
        .env_remove("RUST_LOG")
        .output()
        .expect("native unpack must run");
    let mut combined: String = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

#[test]
fn a_layered_image_is_named_as_layered_even_when_the_unpack_cannot_finish() {
    let image: Vec<u8> = pe_with_section_markers(&[UPX_MARKER, ASPACK_MARKER]);
    let (_succeeded, out): (bool, String) = run_unpack(&image);
    assert!(
        out.contains("layered image"),
        "a double-packed image must be reported as layered before anything else, saw:\n{out}"
    );
    assert!(
        out.contains("UPX") && out.to_lowercase().contains("aspack"),
        "the notice must name both layers, saw:\n{out}"
    );
    assert!(
        out.contains("double-pack") || out.contains("defeat naive"),
        "the notice must carry the chain's own explanation, saw:\n{out}"
    );
}

#[test]
fn a_single_packer_image_is_not_called_layered() {
    let image: Vec<u8> = pe_with_section_markers(&[UPX_MARKER]);
    let (_succeeded, out): (bool, String) = run_unpack(&image);
    assert!(
        !out.contains("layered image"),
        "one packer is not a chain; the notice must stay silent, saw:\n{out}"
    );
}
