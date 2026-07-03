#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_ruby::{Flavor, OcraFile, OcraImage, RubyAnalysis, WrapperKind, analyze_bytes};

mod common;

const OCRA_SIGNATURE: [u8; 4] = [0x41, 0xb6, 0xba, 0x4e];
const OP_END: u32 = 0;
const OP_CREATE_DIRECTORY: u32 = 1;
const OP_CREATE_FILE: u32 = 2;
const OP_DECOMPRESS_LZMA: u32 = 4;
const OP_CREATE_INST_DIRECTORY: u32 = 8;

#[test]
fn real_committed_ocra_stream_recovers_embedded_source() {
    let bytes: &[u8] = include_bytes!("../../../corpus/ruby/ocra/tmpin");
    let reference: &[u8] = include_bytes!("../../../corpus/ruby/ocra/hello.rb");

    let analysis: RubyAnalysis = analyze_bytes(bytes, "tmpin").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::Ocra);
    let wrapper = analysis.wrapper.expect("wrapper");
    assert_eq!(wrapper.kind, WrapperKind::Ocra);
    assert_eq!(wrapper.container_format, "raw-opcode-stream");

    let image: OcraImage = wrapper.ocra.expect("ocra image");
    assert_eq!(image.directories, vec!["src".to_owned()]);
    assert_eq!(image.files.len(), 1);
    let recovered: &OcraFile = &image.files[0];
    assert_eq!(recovered.path, "src\\hello.rb");
    assert_eq!(recovered.size, 19);
    assert_eq!(recovered.data, reference);
}

#[test]
fn synthetic_lzma_wrapped_ocra_exe_round_trips() {
    let mut inner: Vec<u8> = Vec::new();
    inner.extend_from_slice(&OP_CREATE_INST_DIRECTORY.to_le_bytes());
    inner.extend_from_slice(&0u32.to_le_bytes());
    inner.extend_from_slice(&1u32.to_le_bytes());
    inner.extend_from_slice(&0u32.to_le_bytes());
    inner.extend_from_slice(&OP_CREATE_DIRECTORY.to_le_bytes());
    inner.extend_from_slice(b"src\x00");
    inner.extend_from_slice(&OP_CREATE_FILE.to_le_bytes());
    inner.extend_from_slice(b"src\\main.rb\x00");
    let payload: &[u8] = b"puts \"packed\"\n";
    inner.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    inner.extend_from_slice(payload);
    inner.extend_from_slice(&OP_END.to_le_bytes());

    let mut compressed: Vec<u8> = Vec::new();
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(inner.as_slice());
    lzma_rs::lzma_compress(&mut reader, &mut compressed).expect("lzma compress");

    let mut exe: Vec<u8> = b"MZ".to_vec();
    exe.extend_from_slice(&[0u8; 96]);
    let opcode_offset: u32 = u32::try_from(exe.len()).expect("offset fits");
    exe.extend_from_slice(&OP_DECOMPRESS_LZMA.to_le_bytes());
    exe.extend_from_slice(
        &u32::try_from(compressed.len())
            .expect("size fits")
            .to_le_bytes(),
    );
    exe.extend_from_slice(&compressed);
    exe.extend_from_slice(&OP_END.to_le_bytes());
    exe.extend_from_slice(&opcode_offset.to_le_bytes());
    exe.extend_from_slice(&OCRA_SIGNATURE);

    let analysis: RubyAnalysis = analyze_bytes(&exe, "packed.exe").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::Ocra);
    let image: OcraImage = analysis.wrapper.expect("wrapper").ocra.expect("image");
    assert_eq!(image.lzma_chunks, 1);
    assert_eq!(image.directories, vec!["src".to_owned()]);
    assert_eq!(image.files.len(), 1);
    assert_eq!(image.files[0].path, "src\\main.rb");
    assert_eq!(image.files[0].data, payload);
}

#[test]
fn rubyscript2exe_marker_classifies_as_ruby2exe() {
    let mut bytes: Vec<u8> = b"MZ".to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(b"\n  require \"rubyscript2exe\"\n");
    bytes.extend_from_slice(b"appended-tar-payload");
    let analysis: RubyAnalysis = analyze_bytes(&bytes, "wrapped.exe").expect("analyze");
    assert_eq!(analysis.flavor, Flavor::Ruby2Exe);
    let wrapper = analysis.wrapper.expect("wrapper");
    assert_eq!(wrapper.kind, WrapperKind::Ruby2Exe);
    assert_eq!(wrapper.container_format, "pe");
    assert!(wrapper.ocra.is_none());
}
