use disrobe_dart::{
    DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES, DART_SNAPSHOT_MAGIC, Error, SnapshotHeader,
    SnapshotKind, SupportStatus, parse_snapshot_header, support_status,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn snapshot_header(
    snapshot_compatibility_hash: &str,
    features: &str,
) -> std::result::Result<Vec<u8>, std::num::TryFromIntError> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&DART_SNAPSHOT_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&0_i64.to_le_bytes());
    bytes.extend_from_slice(&(SnapshotKind::FullAot as i64).to_le_bytes());
    bytes.extend_from_slice(snapshot_compatibility_hash.as_bytes());
    bytes.extend_from_slice(features.as_bytes());
    bytes.push(0);
    let stored_length: i64 = i64::try_from(bytes.len() - 4)?;
    bytes[4..12].copy_from_slice(&stored_length.to_le_bytes());
    Ok(bytes)
}

#[test]
fn parses_pinned_full_aot_header() -> TestResult {
    let bytes: Vec<u8> = snapshot_header(
        "ace654289f5abc240509fc941453ebc5",
        DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    )?;
    let header: SnapshotHeader = parse_snapshot_header(&bytes)?;
    assert_eq!(header.kind, SnapshotKind::FullAot);
    assert_eq!(header.declared_length, bytes.len());
    assert_eq!(
        header.snapshot_compatibility_hash,
        "ace654289f5abc240509fc941453ebc5"
    );
    assert_eq!(header.features, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES);
    assert_eq!(support_status(&header), SupportStatus::Supported);
    Ok(())
}

#[test]
fn rejects_unknown_version_before_layout_reads() -> TestResult {
    let bytes: Vec<u8> = snapshot_header(
        "0123456789abcdef0123456789abcdef",
        "product arm64 android compressed-pointers",
    )?;
    let header: SnapshotHeader = parse_snapshot_header(&bytes)?;
    assert_eq!(support_status(&header), SupportStatus::UnsupportedVersion);
    Ok(())
}

#[test]
fn rejects_non_hex_snapshot_compatibility_hash() -> TestResult {
    let bytes: Vec<u8> = snapshot_header(
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "product arm64 android compressed-pointers",
    )?;
    let result: disrobe_dart::Result<SnapshotHeader> = parse_snapshot_header(&bytes);
    assert!(matches!(
        result,
        Err(Error::InvalidSnapshotCompatibilityHash)
    ));
    Ok(())
}

#[test]
fn rejects_unterminated_features() -> TestResult {
    let mut bytes: Vec<u8> = snapshot_header(
        "ace654289f5abc240509fc941453ebc5",
        "product arm64 android compressed-pointers",
    )?;
    let removed: Option<u8> = bytes.pop();
    assert_eq!(removed, Some(0));
    let stored_length: i64 = i64::try_from(bytes.len() - 4)?;
    bytes[4..12].copy_from_slice(&stored_length.to_le_bytes());
    let result: disrobe_dart::Result<SnapshotHeader> = parse_snapshot_header(&bytes);
    assert!(matches!(result, Err(Error::UnterminatedFeatures)));
    Ok(())
}

#[test]
fn rejects_declared_length_outside_input() -> TestResult {
    let mut bytes: Vec<u8> = snapshot_header(
        "ace654289f5abc240509fc941453ebc5",
        "product arm64 android compressed-pointers",
    )?;
    bytes[4..12].copy_from_slice(&4096_i64.to_le_bytes());
    let result: disrobe_dart::Result<SnapshotHeader> = parse_snapshot_header(&bytes);
    assert!(matches!(
        result,
        Err(Error::DeclaredLengthOutOfBounds { .. })
    ));
    Ok(())
}

#[test]
fn rejects_every_truncated_fixed_header() {
    let bytes: [u8; 52] = [0; 52];
    for length in 0..52 {
        let result: disrobe_dart::Result<SnapshotHeader> = parse_snapshot_header(&bytes[..length]);
        assert!(matches!(result, Err(Error::InputTooSmall { .. })));
    }
}
