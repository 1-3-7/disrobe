#![allow(clippy::expect_used)]

use disrobe_nir::{
    FileSourceOffset, NirArtifact, NirFunction, NirInstr, NirModule, NirOp, SourceBytes,
    SourceBytesRef, SourceLang, SourceOffset, SourceOffsetUnavailable, SourceRef, SourceUnit,
    SourceUnitRef, decode_nir_artifact, encode_nir_artifact,
};

fn instruction(address: u64, mnemonic: &str) -> NirInstr {
    NirInstr {
        address,
        op: NirOp::Nop,
        mnemonic: mnemonic.to_owned(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn module() -> NirModule {
    NirModule {
        source_hash: [0x42; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "probe".to_owned(),
            address: 0x1000,
            end: 0x1003,
            is_export: false,
            instructions: vec![
                instruction(0x1000, "COPY"),
                instruction(0x1000, "INT_ADD"),
                instruction(0x1002, "RETURN"),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        }],
        symbols: Vec::new(),
    }
}

#[test]
fn source_units_share_bytes_across_lowered_operations_and_round_trip() {
    let units: Vec<SourceUnit> = vec![
        SourceUnit::new(
            0,
            0..2,
            SourceBytes::Original(vec![0x48, 0x01]),
            SourceOffset::File(FileSourceOffset::new(0x220, 0x223).expect("bounded file offset")),
        )
        .expect("valid first source unit"),
        SourceUnit::new(
            0,
            2..3,
            SourceBytes::Original(vec![0xc3]),
            SourceOffset::File(FileSourceOffset::new(0x222, 0x223).expect("bounded file offset")),
        )
        .expect("valid second source unit"),
    ];
    let artifact: NirArtifact = NirArtifact::new(module(), units).expect("valid provenance");

    assert_eq!(artifact.source_unit(0, 0), artifact.source_unit(0, 1));
    assert_ne!(artifact.source_unit(0, 1), artifact.source_unit(0, 2));
    assert_eq!(
        artifact.reemit_original_bytes(0).expect("complete bytes"),
        [0x48, 0x01, 0xc3]
    );

    let encoded: Vec<u8> = encode_nir_artifact(&artifact).expect("encode artifact");
    let decoded: NirArtifact = decode_nir_artifact(&encoded).expect("decode artifact");
    assert_eq!(decoded, artifact);
}

#[test]
fn invalid_ranges_and_unavailable_bytes_fail_closed() {
    assert!(
        SourceUnit::new(
            0,
            std::ops::Range { start: 2, end: 1 },
            SourceBytes::Original(vec![0x90]),
            SourceOffset::MemoryImage(0x1000),
        )
        .is_err()
    );
    let overlapping: Vec<SourceUnit> = vec![
        SourceUnit::new(
            0,
            0..2,
            SourceBytes::Original(vec![0x90]),
            SourceOffset::MemoryImage(0x1000),
        )
        .expect("valid unit"),
        SourceUnit::new(
            0,
            1..3,
            SourceBytes::Original(vec![0xc3]),
            SourceOffset::MemoryImage(0x1001),
        )
        .expect("valid unit"),
    ];
    assert!(NirArtifact::new(module(), overlapping).is_err());

    let synthesized: SourceUnit = SourceUnit::new(
        0,
        0..3,
        SourceBytes::Synthesized,
        SourceOffset::Unavailable(SourceOffsetUnavailable::Synthesized),
    )
    .expect("typed unavailable source");
    let artifact: NirArtifact =
        NirArtifact::new(module(), vec![synthesized]).expect("valid absence");
    assert!(artifact.reemit_original_bytes(0).is_err());
    assert!(artifact.reemit_original_bytes(1).is_err());
}

#[test]
fn file_offsets_cannot_escape_the_original_file() {
    let offset: FileSourceOffset =
        FileSourceOffset::new(0x222, 0x223).expect("offset starts inside file");
    assert!(
        SourceUnit::new(
            0,
            0..1,
            SourceBytes::Original(vec![0x90, 0x90]),
            SourceOffset::File(offset),
        )
        .is_err()
    );
    assert!(FileSourceOffset::new(u64::MAX, 1).is_err());
    assert!(
        SourceUnit::new(
            0,
            0..1,
            SourceBytes::Synthesized,
            SourceOffset::Unavailable(SourceOffsetUnavailable::Decompressed),
        )
        .is_err()
    );
}

#[test]
fn borrowed_source_units_copy_only_at_the_owned_boundary() {
    let bytes: [u8; 2] = [0x90, 0xc3];
    let borrowed: SourceUnitRef<'_> = SourceUnitRef::new(
        0,
        0..3,
        SourceBytesRef::Original(&bytes),
        SourceOffset::MemoryImage(0x1000),
    )
    .expect("borrowed source unit");
    assert_eq!(borrowed.original_bytes(), Some(bytes.as_slice()));
    let owned: SourceUnit = borrowed.into_owned().expect("owned serialization boundary");
    assert_eq!(owned.bytes(), &SourceBytes::Original(bytes.to_vec()));
}

#[test]
fn borrowed_source_units_reject_oversized_ownership_before_copying() {
    let bytes: Vec<u8> = vec![0x90; 64 * 1024 * 1024 + 1];
    let borrowed: SourceUnitRef<'_> = SourceUnitRef::new(
        0,
        0..1,
        SourceBytesRef::Original(&bytes),
        SourceOffset::MemoryImage(0x1000),
    )
    .expect("borrowed validation does not own bytes");
    assert!(borrowed.into_owned().is_err());
}

#[test]
fn borrowed_artifacts_reject_aggregate_source_bytes_before_copying() {
    let first_bytes: Vec<u8> = vec![0x90; 32 * 1024 * 1024 + 1];
    let second_bytes: Vec<u8> = vec![0xc3; 32 * 1024 * 1024];
    let units: [SourceUnitRef<'_>; 2] = [
        SourceUnitRef::new(
            0,
            0..1,
            SourceBytesRef::Original(&first_bytes),
            SourceOffset::MemoryImage(0x1000),
        )
        .expect("first borrowed unit"),
        SourceUnitRef::new(
            0,
            1..3,
            SourceBytesRef::Original(&second_bytes),
            SourceOffset::MemoryImage(0x1001),
        )
        .expect("second borrowed unit"),
    ];
    assert!(NirArtifact::from_borrowed(module(), &units).is_err());
}

#[test]
fn empty_functions_retain_ordered_zero_output_source_units() {
    let empty_module: NirModule = NirModule {
        source_hash: [0x24; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "empty".to_owned(),
            address: 0x1000,
            end: 0x1001,
            is_export: false,
            instructions: Vec::new(),
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        }],
        symbols: Vec::new(),
    };
    let unit: SourceUnit = SourceUnit::new(
        0,
        0..0,
        SourceBytes::Original(vec![0x90]),
        SourceOffset::MemoryImage(0x1000),
    )
    .expect("zero-output source unit");
    let artifact: NirArtifact =
        NirArtifact::new(empty_module, vec![unit]).expect("empty function artifact");

    assert_eq!(artifact.source_units()[0].instruction_count(), 0);
    assert_eq!(
        artifact.reemit_original_bytes(0).expect("original bytes"),
        [0x90]
    );
}
