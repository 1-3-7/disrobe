use disrobe_pass_native::packers::{
    ByteRegion, DonutCompression, DonutEntropy, DonutModuleType, LoaderArchitecture, LoaderConfig,
    LoaderFamily, LoaderFingerprint, LoaderRecovery, LoaderVariant, Packer, RecoveredImage,
    RecoveryField, WrappedModuleFormat, detect, fingerprint_loader, recover_detected,
    recover_loader,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

type TestResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

const KNOWN_DLL: &[u8] = include_bytes!("fixtures/loader_generators/known.dll");
const KNOWN_DONUT: &[u8] = include_bytes!("fixtures/loader_generators/known.go-donut.bin");
const KNOWN_SRDI: &[u8] = include_bytes!("fixtures/loader_generators/known.srdi.bin");

fn failure(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn known<T>(field: &RecoveryField<T>) -> TestResult<&T> {
    match field {
        RecoveryField::Known { value } => Ok(value),
        RecoveryField::Unknown { reason } => {
            Err(failure(format!("expected known field, got {reason}")))
        }
    }
}

fn recovered_module(recovery: &LoaderRecovery) -> TestResult<&[u8]> {
    match &recovery.module {
        RecoveryField::Known { value } => Ok(value),
        RecoveryField::Unknown { reason } => {
            Err(failure(format!("expected recovered module, got {reason}")))
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output: String = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    output
}

#[test]
fn fixture_manifest_matches_committed_files() -> TestResult<()> {
    let manifest_bytes: &[u8] = include_bytes!("fixtures/loader_generators/manifest.json");
    let manifest: Value = serde_json::from_slice(manifest_bytes)?;
    assert_eq!(manifest["input"]["bytes"], KNOWN_DLL.len());
    assert_eq!(manifest["input"]["sha256"], sha256_hex(KNOWN_DLL));
    assert_eq!(manifest["input"]["source"], "known.c");

    let artifacts: &Vec<Value> = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| failure("fixture artifact list missing"))?;
    assert_eq!(artifacts.len(), 2);
    for artifact in artifacts {
        let path: &str = artifact["path"]
            .as_str()
            .ok_or_else(|| failure("fixture path missing"))?;
        let bytes: &[u8] = match path {
            "known.srdi.bin" => KNOWN_SRDI,
            "known.go-donut.bin" => KNOWN_DONUT,
            _ => return Err(failure(format!("unexpected fixture path {path}"))),
        };
        assert_eq!(artifact["bytes"], bytes.len());
        assert_eq!(artifact["sha256"], sha256_hex(bytes));
    }
    assert!(include_str!("fixtures/loader_generators/known.c").contains("SayHello"));
    assert!(!include_bytes!("fixtures/loader_generators/go-donut.LICENSE").is_empty());
    assert!(!include_bytes!("fixtures/loader_generators/srdi.LICENSE").is_empty());
    Ok(())
}

#[test]
fn real_srdi_recovers_original_dll_and_metadata() -> TestResult<()> {
    assert_eq!(KNOWN_SRDI.len(), 21_795);
    assert_eq!(KNOWN_DLL.len(), 18_944);

    let recovery: LoaderRecovery = recover_loader(KNOWN_SRDI)?;
    assert_eq!(recovered_module(&recovery)?, KNOWN_DLL);
    assert_eq!(recovery.inspection.family, LoaderFamily::Srdi);
    assert_eq!(recovery.inspection.variant, LoaderVariant::SrdiV1);
    assert_eq!(recovery.inspection.architecture, LoaderArchitecture::X64);
    assert_eq!(
        recovery.inspection.config_region,
        ByteRegion {
            offset: 0,
            length: 69,
        }
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.region)?,
        ByteRegion {
            offset: 2_841,
            length: 18_944,
        }
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.format)?,
        WrappedModuleFormat::Pe32Plus
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.stored_size)?,
        18_944
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.original_size)?,
        18_944
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.entry_point_rva)?,
        0x1292
    );

    let LoaderConfig::Srdi(config) = &recovery.inspection.config else {
        return Err(failure("expected sRDI config"));
    };
    assert_eq!(config.function_hash, 0x3062_7745);
    assert_eq!(config.flags, 0);
    assert_eq!(
        *known(&config.user_data_region)?,
        ByteRegion {
            offset: 21_785,
            length: 10,
        }
    );
    Ok(())
}

#[test]
fn real_go_donut_recovers_original_dll_and_metadata() -> TestResult<()> {
    assert_eq!(KNOWN_DONUT.len(), 46_160);
    assert_eq!(KNOWN_DLL.len(), 18_944);

    let recovery: LoaderRecovery = recover_loader(KNOWN_DONUT)?;
    assert_eq!(recovered_module(&recovery)?, KNOWN_DLL);
    assert_eq!(recovery.inspection.family, LoaderFamily::Donut);
    assert_eq!(recovery.inspection.variant, LoaderVariant::GoDonutV1);
    assert_eq!(recovery.inspection.architecture, LoaderArchitecture::X64);
    assert_eq!(
        recovery.inspection.config_region,
        ByteRegion {
            offset: 5,
            length: 23_936,
        }
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.region)?,
        ByteRegion {
            offset: 3_661,
            length: 18_944,
        }
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.format)?,
        WrappedModuleFormat::Pe32Plus
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.stored_size)?,
        18_944
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.original_size)?,
        18_944
    );
    assert_eq!(
        *known(&recovery.inspection.wrapped_module.entry_point_rva)?,
        0x1292
    );

    let LoaderConfig::Donut(config) = &recovery.inspection.config else {
        return Err(failure("expected Donut config"));
    };
    assert_eq!(config.entropy, DonutEntropy::Encrypted);
    assert_eq!(*known(&config.api_hash_count)?, 52);
    assert_eq!(*known(&config.module_type)?, DonutModuleType::NativeDll);
    assert_eq!(*known(&config.compression)?, DonutCompression::None);
    assert_eq!(
        *known(&config.module_header_region)?,
        ByteRegion {
            offset: 2_341,
            length: 1_320,
        }
    );
    Ok(())
}

#[test]
fn raw_loader_blobs_are_detected_before_native_container_gating() -> TestResult<()> {
    let srdi_hits: Vec<disrobe_pass_native::PackerDetection> = detect(KNOWN_SRDI);
    let donut_hits: Vec<disrobe_pass_native::PackerDetection> = detect(KNOWN_DONUT);
    assert!(srdi_hits.iter().any(|hit| hit.packer == Packer::Srdi));
    assert!(donut_hits.iter().any(|hit| hit.packer == Packer::Donut));

    let srdi_fingerprint: LoaderFingerprint =
        fingerprint_loader(KNOWN_SRDI).ok_or_else(|| failure("sRDI fingerprint missing"))?;
    let donut_fingerprint: LoaderFingerprint =
        fingerprint_loader(KNOWN_DONUT).ok_or_else(|| failure("Donut fingerprint missing"))?;
    assert_eq!(srdi_fingerprint.family, LoaderFamily::Srdi);
    assert_eq!(donut_fingerprint.family, LoaderFamily::Donut);
    assert_eq!(
        srdi_fingerprint.wrapped_module_region,
        ByteRegion {
            offset: 2_841,
            length: 18_944,
        }
    );
    assert_eq!(
        donut_fingerprint.wrapped_module_region,
        ByteRegion {
            offset: 3_661,
            length: 18_944,
        }
    );
    for (wrapper, packer) in [(KNOWN_SRDI, Packer::Srdi), (KNOWN_DONUT, Packer::Donut)] {
        let detections: Vec<disrobe_pass_native::PackerDetection> = detect(wrapper);
        let recovered: Vec<RecoveredImage> = recover_detected(wrapper, &detections);
        let image: &RecoveredImage = recovered
            .iter()
            .find(|item: &&RecoveredImage| item.packer == packer.label())
            .ok_or_else(|| failure(format!("{} recovery missing", packer.label())))?;
        assert_eq!(image.image, KNOWN_DLL);
    }
    Ok(())
}

#[test]
fn damaged_regions_and_transforms_are_explicitly_unknown() -> TestResult<()> {
    let mut srdi: Vec<u8> = KNOWN_SRDI.to_vec();
    srdi[17..21].copy_from_slice(&u32::MAX.to_le_bytes());
    let srdi_recovery: LoaderRecovery = recover_loader(&srdi)?;
    let RecoveryField::Unknown {
        reason: region_reason,
    } = srdi_recovery.inspection.wrapped_module.region
    else {
        return Err(failure("damaged sRDI region was reported known"));
    };
    assert!(region_reason.contains("user data region"));
    let RecoveryField::Unknown {
        reason: module_reason,
    } = srdi_recovery.module
    else {
        return Err(failure("damaged sRDI module was recovered"));
    };
    assert!(module_reason.contains("user data region"));

    let mut wrong_machine: Vec<u8> = KNOWN_SRDI.to_vec();
    wrong_machine[2_841 + 0x84..2_841 + 0x86].copy_from_slice(&0xAA64u16.to_le_bytes());
    let wrong_machine_recovery: LoaderRecovery = recover_loader(&wrong_machine)?;
    let RecoveryField::Unknown { reason } = wrong_machine_recovery.module else {
        return Err(failure("wrong-machine sRDI module was recovered"));
    };
    assert!(reason.contains("machine"));
    assert!(fingerprint_loader(&wrong_machine).is_none());

    let mut invalid_span: Vec<u8> = KNOWN_SRDI.to_vec();
    invalid_span[2_841 + 0x198..2_841 + 0x19C].copy_from_slice(&u32::MAX.to_le_bytes());
    let invalid_span_recovery: LoaderRecovery = recover_loader(&invalid_span)?;
    let RecoveryField::Unknown { reason } = invalid_span_recovery.module else {
        return Err(failure("out-of-range PE section was recovered"));
    };
    assert!(reason.contains("section raw span"));
    assert!(fingerprint_loader(&invalid_span).is_none());

    let mut donut: Vec<u8> = KNOWN_DONUT.to_vec();
    donut[9] ^= 0x80;
    let donut_recovery: LoaderRecovery = recover_loader(&donut)?;
    let RecoveryField::Unknown { reason } = donut_recovery.module else {
        return Err(failure("damaged Donut module was recovered"));
    };
    assert!(reason.contains("module header"));
    assert!(fingerprint_loader(&donut).is_none());
    Ok(())
}

#[test]
fn truncation_and_oversized_declarations_are_bounded() -> TestResult<()> {
    for end in [
        0usize, 1, 4, 5, 9, 20, 36, 48, 68, 69, 571, 572, 575, 576, 2_340, 2_341, 3_660, 3_661,
        18_944, 21_794, 23_940, 46_159,
    ] {
        let donut_end: usize = end.min(KNOWN_DONUT.len());
        let srdi_end: usize = end.min(KNOWN_SRDI.len());
        let _donut_fingerprint: Option<LoaderFingerprint> =
            fingerprint_loader(&KNOWN_DONUT[..donut_end]);
        let _srdi_fingerprint: Option<LoaderFingerprint> =
            fingerprint_loader(&KNOWN_SRDI[..srdi_end]);
        let _donut_recovery: core::result::Result<LoaderRecovery, disrobe_pass_native::Error> =
            recover_loader(&KNOWN_DONUT[..donut_end]);
        let _srdi_recovery: core::result::Result<LoaderRecovery, disrobe_pass_native::Error> =
            recover_loader(&KNOWN_SRDI[..srdi_end]);
    }

    let mut oversized: Vec<u8> = KNOWN_DONUT[..128].to_vec();
    let declared: u32 = 64 * 1024 * 1024 + 1;
    oversized[1..5].copy_from_slice(&declared.to_le_bytes());
    oversized[5..9].copy_from_slice(&declared.to_le_bytes());
    let error: disrobe_pass_native::Error = match recover_loader(&oversized) {
        Ok(_) => return Err(failure("oversized instance was accepted")),
        Err(value) => value,
    };
    assert!(error.to_string().contains("64 MiB"));
    Ok(())
}

#[cfg(feature = "chain")]
mod chain {
    use super::{KNOWN_DLL, KNOWN_DONUT, KNOWN_SRDI, TestResult, Value, failure};
    use disrobe_core::chain::{ChildArtifact, DetectContext, DetectVerdict, Detector};
    use disrobe_core::{Artifact, Pass, Rung};
    use disrobe_pass_native::chain_detector::{PACKER_PASS, PackerDetector};

    fn verify_chain_recovery(wrapper: &[u8], expected_tag: &str) -> TestResult<()> {
        let context: DetectContext<'_> = DetectContext {
            bytes: wrapper,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let verdict: DetectVerdict = Detector::detect(&PackerDetector, &context)
            .ok_or_else(|| failure("loader detection missing"))?;
        assert_eq!(verdict.format_tag, expected_tag);

        let artifact: Artifact = Artifact::new(Rung::Raw, wrapper.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = PACKER_PASS.extract_children(&artifact)?;
        let recovered: &ChildArtifact = children
            .iter()
            .find(|child| child.handle.relative_path == "recovered-image.bin")
            .ok_or_else(|| failure("recovered module child missing"))?;
        assert_eq!(recovered.bytes, KNOWN_DLL);

        let manifest: &ChildArtifact = children
            .iter()
            .find(|child| child.handle.relative_path == "packer-unpack.manifest.json")
            .ok_or_else(|| failure("loader manifest child missing"))?;
        let value: Value = serde_json::from_slice(&manifest.bytes)?;
        assert_eq!(value["packer"], expected_tag);
        assert_eq!(
            value["loader"]["wrapped_module"]["original_size"]["value"],
            18_944
        );
        Ok(())
    }

    #[test]
    fn packer_detector_and_pass_recover_both_real_wrappers() -> TestResult<()> {
        verify_chain_recovery(KNOWN_SRDI, "srdi")?;
        verify_chain_recovery(KNOWN_DONUT, "donut")?;
        Ok(())
    }
}
