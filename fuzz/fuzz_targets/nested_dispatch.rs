#![no_main]

use core::hint::black_box;
use std::path::Path;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use disrobe_binfmt::{
    ContainerKind, classify_input, detect_container, detect_container_with_hint,
    identify_by_structure,
};
use disrobe_fuzz::MAX_INPUT_BYTES;

const MAX_NESTING_DEPTH: usize = 12;
const MAX_LAYER_BYTES: usize = 64 * 1024;

#[derive(Debug, Arbitrary)]
enum Wrapper {
    Gzip,
    Zlib,
    Zstd,
    Bzip2,
    Xz,
    SevenZip,
    Zip,
    Tar,
    Cab,
    Rar,
    Ar,
    Cpio,
}

impl Wrapper {
    const fn magic(&self) -> &'static [u8] {
        match self {
            Self::Gzip => &[0x1F, 0x8B, 0x08, 0x00],
            Self::Zlib => &[0x78, 0x9C],
            Self::Zstd => &[0x28, 0xB5, 0x2F, 0xFD],
            Self::Bzip2 => b"BZh9",
            Self::Xz => &[0xFD, b'7', b'z', b'X', b'Z', 0x00],
            Self::SevenZip => &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C],
            Self::Zip => b"PK\x03\x04",
            Self::Tar => b"ustar\0",
            Self::Cab => b"MSCF",
            Self::Rar => b"Rar!\x1A\x07\x00",
            Self::Ar => b"!<arch>\n",
            Self::Cpio => b"070701",
        }
    }
}

#[derive(Debug, Arbitrary)]
struct NestedInput {
    layers: Vec<Wrapper>,
    core: Vec<u8>,
    hint_name: String,
}

fn build(nested: &NestedInput) -> Vec<u8> {
    let core_len: usize = nested.core.len().min(MAX_LAYER_BYTES);
    let mut image: Vec<u8> = nested.core.get(..core_len).unwrap_or(&[]).to_vec();
    for wrapper in nested.layers.iter().take(MAX_NESTING_DEPTH) {
        let magic: &[u8] = wrapper.magic();
        let mut layered: Vec<u8> = Vec::with_capacity(magic.len() + image.len());
        layered.extend_from_slice(magic);
        layered.extend_from_slice(&image);
        image = layered;
        if image.len() > MAX_INPUT_BYTES {
            break;
        }
    }
    image
}

fuzz_target!(|nested: NestedInput| {
    let image: Vec<u8> = build(&nested);
    if image.len() > MAX_INPUT_BYTES {
        return;
    }
    let hint: &Path = Path::new(nested.hint_name.as_str());
    let kind: Option<ContainerKind> = detect_container(&image);
    let hinted: Option<ContainerKind> = detect_container_with_hint(&image, Some(hint));
    if kind.is_some() {
        assert!(
            hinted.is_some(),
            "a path hint made the container dispatcher forget a format it detects without one"
        );
    }
    let _ = black_box(identify_by_structure(&image));
    let _ = black_box(classify_input(hint, &image));
});
