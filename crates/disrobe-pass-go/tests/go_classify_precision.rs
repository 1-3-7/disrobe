#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_go::{GoImage, LocatedPclntab, Result as GoResult, locate_pclntab};

const NON_GO_IMAGES: [&str; 8] = [
    "corpus/native/packers/aspack/AccessEnum.original.exe",
    "corpus/native/packers/aspack/Clockres.original.exe",
    "corpus/native/packers/fsg/Hash.original.exe",
    "corpus/native/packers/mew/AccessEnum.original.exe",
    "corpus/native/packers/mew/Autologon.original.exe",
    "corpus/native/packers/mew/Clockres.original.exe",
    "corpus/native/packers/nspack/hash.original.exe",
    "corpus/native/packers/pecompact/Clockres.original.exe",
];

const GO_IMAGES: [&str; 2] = [
    "crates/disrobe-pass-go/tests/fixtures/hello_embed.exe",
    "corpus/webview/wails/wvfix.exe",
];

fn repository_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn required_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "required corpus image {} is unreadable: {error}. This test decides whether the Go \
             detector fires on a binary that is not Go and cannot report a result without it.",
            path.display()
        ),
    }
}

fn go_build_marker(bytes: &[u8]) -> bool {
    const BUILDINFO: &[u8] = b"\xff Go buildinf:";
    const RUNTIME: &[u8] = b"runtime.morestack";
    bytes
        .windows(BUILDINFO.len())
        .any(|window: &[u8]| window == BUILDINFO)
        || bytes
            .windows(RUNTIME.len())
            .any(|window: &[u8]| window == RUNTIME)
}

#[test]
fn no_committed_non_go_image_reports_a_located_pclntab() {
    let root: PathBuf = repository_root();
    let mut fired: Vec<String> = Vec::new();
    let mut examined: usize = 0;

    for relative in NON_GO_IMAGES {
        let path: PathBuf = root.join(relative);
        let bytes: Vec<u8> = required_bytes(&path);
        assert!(
            !go_build_marker(&bytes),
            "{relative} carries a Go runtime marker, so it is not a valid negative case for this \
             test and the roster above is wrong"
        );
        examined += 1;
        let Ok(image): std::result::Result<GoImage<'_>, _> = GoImage::parse(&bytes) else {
            continue;
        };
        let located: GoResult<LocatedPclntab<'_>> = locate_pclntab(&image);
        if let Ok(found) = located {
            fired.push(format!("{relative} reported {:?}", found.header.version));
        }
    }

    assert_eq!(
        examined,
        NON_GO_IMAGES.len(),
        "every roster entry must be read, not skipped"
    );
    assert!(
        fired.is_empty(),
        "the pclntab locator fired on {} of {} committed images that carry no Go runtime marker: \
         {fired:?}",
        fired.len(),
        NON_GO_IMAGES.len()
    );
}

#[test]
fn every_committed_go_image_still_reports_a_located_pclntab() {
    let root: PathBuf = repository_root();
    let mut located_count: usize = 0;
    for relative in GO_IMAGES {
        let path: PathBuf = root.join(relative);
        let bytes: Vec<u8> = required_bytes(&path);
        assert!(
            go_build_marker(&bytes),
            "{relative} must carry a Go runtime marker to be a valid positive case"
        );
        let image: GoImage<'_> = GoImage::parse(&bytes)
            .unwrap_or_else(|error| panic!("{relative} must parse as an image: {error}"));
        match locate_pclntab(&image) {
            Ok(_) => located_count += 1,
            Err(error) => panic!(
                "{relative} is a real Go binary and its pclntab must still be located: {error}"
            ),
        }
    }
    assert_eq!(
        located_count,
        GO_IMAGES.len(),
        "tightening the locator must not drop a true positive"
    );
}

fn located_header_file_offset(bytes: &[u8]) -> usize {
    const MAGICS: [u32; 4] = [0xffff_fffb, 0xffff_fffa, 0xffff_fff0, 0xffff_fff1];
    let mut hits: Vec<usize> = Vec::new();
    for magic in MAGICS {
        let needle: [u8; 4] = magic.to_le_bytes();
        let mut index: usize = 0;
        while index + 8 <= bytes.len() {
            if bytes[index..index + 4] == needle
                && bytes[index + 4] == 0
                && bytes[index + 5] == 0
                && matches!(bytes[index + 6], 1 | 2 | 4)
                && matches!(bytes[index + 7], 4 | 8)
            {
                hits.push(index);
            }
            index += 1;
        }
    }
    assert_eq!(
        hits.len(),
        1,
        "the tracked Go image must carry exactly one header-shaped magic run so a mutation targets \
         the real pclntab; found {}",
        hits.len()
    );
    hits[0]
}

fn tracked_go_image() -> Vec<u8> {
    required_bytes(&repository_root().join("crates/disrobe-pass-go/tests/fixtures/hello_embed.exe"))
}

fn locates(bytes: &[u8]) -> bool {
    let Ok(image): std::result::Result<GoImage<'_>, _> = GoImage::parse(bytes) else {
        return false;
    };
    locate_pclntab(&image).is_ok()
}

#[test]
fn a_header_declaring_an_impossible_pointer_size_is_refused() {
    let baseline: Vec<u8> = tracked_go_image();
    assert!(
        locates(&baseline),
        "the unmutated tracked image must locate, otherwise the mutations below prove nothing"
    );
    let offset: usize = located_header_file_offset(&baseline);

    for impossible in [0u8, 3, 5, 16] {
        let mut mutated: Vec<u8> = baseline.clone();
        mutated[offset + 7] = impossible;
        assert!(
            !locates(&mutated),
            "a pclntab header declaring pointer size {impossible} is not something the Go linker \
             emits, so it must be refused rather than parsed"
        );
    }
}

#[test]
fn a_header_declaring_an_impossible_instruction_quantum_is_refused() {
    let baseline: Vec<u8> = tracked_go_image();
    let offset: usize = located_header_file_offset(&baseline);
    for impossible in [0u8, 3, 5, 8] {
        let mut mutated: Vec<u8> = baseline.clone();
        mutated[offset + 6] = impossible;
        assert!(
            !locates(&mutated),
            "a pclntab header declaring instruction quantum {impossible} is not something the Go \
             linker emits, so it must be refused"
        );
    }
}

#[test]
fn a_header_whose_reserved_bytes_are_not_zero_is_refused() {
    let baseline: Vec<u8> = tracked_go_image();
    let offset: usize = located_header_file_offset(&baseline);
    for reserved in [4usize, 5] {
        let mut mutated: Vec<u8> = baseline.clone();
        mutated[offset + reserved] = 0x41;
        assert!(
            !locates(&mutated),
            "byte {reserved} of a pclntab header is reserved and zero in every release, so a \
             nonzero value must be refused"
        );
    }
}

fn write_header_word(bytes: &mut [u8], header: usize, word_index: usize, value: u64) {
    let pointer_size: usize = usize::from(bytes[header + 7]);
    let at: usize = header + 8 + word_index * pointer_size;
    if pointer_size == 8 {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    } else {
        let narrowed: u32 = u32::try_from(value).unwrap_or(u32::MAX);
        bytes[at..at + 4].copy_from_slice(&narrowed.to_le_bytes());
    }
}

fn read_header_word(bytes: &[u8], header: usize, word_index: usize) -> u64 {
    let pointer_size: usize = usize::from(bytes[header + 7]);
    let at: usize = header + 8 + word_index * pointer_size;
    if pointer_size == 8 {
        let raw: [u8; 8] = bytes[at..at + 8].try_into().expect("eight bytes");
        u64::from_le_bytes(raw)
    } else {
        let raw: [u8; 4] = bytes[at..at + 4].try_into().expect("four bytes");
        u64::from(u32::from_le_bytes(raw))
    }
}

const WORD_FUNCNAME_OFF: usize = 3;
const WORD_FUNCDATA_OFF: usize = 7;

#[test]
fn a_header_whose_name_table_starts_after_its_funcdata_table_is_refused() {
    let baseline: Vec<u8> = tracked_go_image();
    let offset: usize = located_header_file_offset(&baseline);
    let funcdata_off: u64 = read_header_word(&baseline, offset, WORD_FUNCDATA_OFF);

    let mut mutated: Vec<u8> = baseline.clone();
    write_header_word(&mut mutated, offset, WORD_FUNCNAME_OFF, funcdata_off);
    assert!(
        !locates(&mutated),
        "the Go linker always lays the name table before the funcdata table, so a header claiming          they start at the same offset must be refused"
    );
}
