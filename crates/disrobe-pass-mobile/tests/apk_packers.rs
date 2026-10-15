#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    AnchorKind, ApkPacker, PackerAnchor, PackerFinding, PayloadState, detect_packers,
};
use sha2::{Digest, Sha256};

struct Fixture {
    apk: &'static str,
    sha256: &'static str,
    packer: ApkPacker,
    payload: PayloadState,
    recovered: &'static [&'static str],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        apk: "jiagu-legacy.apk",
        sha256: "bc7b9ec865c5dd64b4bad6a81947b00f707e9b15c4b6a60446ee2da372bae469",
        packer: ApkPacker::Jiagu360,
        payload: PayloadState::EncryptedStaticKeyUnknown,
        recovered: &[],
    },
    Fixture {
        apk: "jiagu.apk",
        sha256: "b9a50ad1230881158e134e6e871e5b2eb242e525fa0f39bb1a108194a27ce379",
        packer: ApkPacker::Jiagu360,
        payload: PayloadState::EncryptedStaticKeyUnknown,
        recovered: &[],
    },
    Fixture {
        apk: "bangcle.apk",
        sha256: "c45b5c933676bd46a9e3004f29e67e6b93c1aa8960101bb06a9460a2addf8c7a",
        packer: ApkPacker::Bangcle,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "dexhelper.apk",
        sha256: "1ba1b618fe1394fa13867747360a16a60ad2391ec94c7386461a81f1d45f18f0",
        packer: ApkPacker::SecneoDexHelper,
        payload: PayloadState::Recovered,
        recovered: &["large.dex"],
    },
    Fixture {
        apk: "ijiami.apk",
        sha256: "f20cbd52d4e81642365f20556a6f2b8c223e5e7409e0f62578123e96d03b593d",
        packer: ApkPacker::Ijiami,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "legu.apk",
        sha256: "c29d4450a8a7336959c348418482d5f536a7477659f8f06e448ac8b83d8bf871",
        packer: ApkPacker::TencentLegu,
        payload: PayloadState::EncryptedStaticKeyUnknown,
        recovered: &[],
    },
    Fixture {
        apk: "baidu.apk",
        sha256: "ad2622049d3120c0c2f8ccb0c7af2313855fced2b870be188c1b69a70b1a153c",
        packer: ApkPacker::BaiduProtect,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "alibaba.apk",
        sha256: "2a39a355ce53d42e868e393cac9634c1ca616954c942a338f15fc60928f9edc7",
        packer: ApkPacker::AliMobisec,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "dexprotector.apk",
        sha256: "e14c6002fa8d20fc0ffe7aca34dac83d8fd16c1cef41ef76c074744b5f56c03e",
        packer: ApkPacker::DexProtector,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "appguard.apk",
        sha256: "ccecbd7164c16060047964f071b66ee0108ccf4318f17a464d818e57a6e261ab",
        packer: ApkPacker::AppGuardInca,
        payload: PayloadState::EncryptedRuntimeKey,
        recovered: &[],
    },
    Fixture {
        apk: "promon.apk",
        sha256: "5b4b494179f04f9dc79e083e54acc63add976a25307895e479ffd1666c64864a",
        packer: ApkPacker::PromonShield,
        payload: PayloadState::NotADexPacker,
        recovered: &[],
    },
    Fixture {
        apk: "pangxie.apk",
        sha256: "b06a44df6fa752bc4cc5fc1970a4d9bd333dc3a6e7bfe36c577c71fc48005bfe",
        packer: ApkPacker::Pangxie,
        payload: PayloadState::Recovered,
        recovered: &["original.dex"],
    },
    Fixture {
        apk: "open-source-jiagu.apk",
        sha256: "c7a74412ae41d0baeaea1da62429960375320cb5b2112ca76c6465cfe0afd57f",
        packer: ApkPacker::OpenSourceJiagu,
        payload: PayloadState::Recovered,
        recovered: &["original.dex", "second.dex"],
    },
];

const PLAIN_APKS: &[&str] = &[
    "fixture-res.apk",
    "fixture-rich.apk",
    "fixture-v1-signed.apk",
    "fixture-v2v3-signed.apk",
];

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("apk")
        .join(name)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is committed, so a run that cannot read it grades nothing: {error}",
            path.display()
        )
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    disrobe_core::codec::hex_encode(&Sha256::digest(bytes))
}

fn packed(fixture: &Fixture) -> Vec<u8> {
    let bytes: Vec<u8> = read(&corpus(&format!("packers/{}", fixture.apk)));
    assert_eq!(
        sha256_hex(&bytes),
        fixture.sha256,
        "{} must be the bytes corpus/apk/packers/build.py wrote",
        fixture.apk
    );
    bytes
}

#[test]
fn each_mimic_is_named_once_by_its_own_packer() {
    for fixture in FIXTURES {
        let findings: Vec<PackerFinding> = detect_packers(&packed(fixture)).expect("scan");
        let named: Vec<ApkPacker> = findings.iter().map(|f: &PackerFinding| f.packer).collect();
        assert_eq!(
            named,
            vec![fixture.packer],
            "{}: exactly its own packer must be named; findings {:?}",
            fixture.apk,
            findings
        );
        let finding: &PackerFinding = &findings[0];
        assert_eq!(
            finding.payload, fixture.payload,
            "{}: {:?}",
            fixture.apk, finding
        );
        assert!(
            finding
                .anchors
                .iter()
                .any(|a: &PackerAnchor| a.kind != AnchorKind::AppendedPayload),
            "{}: a finding carries the anchors it rests on",
            fixture.apk
        );
        assert!(!finding.note.is_empty(), "{}", fixture.apk);
    }
}

#[test]
fn a_recoverable_payload_yields_the_original_dex_bytes() {
    let mut recovered_total: usize = 0;
    for fixture in FIXTURES {
        let findings: Vec<PackerFinding> = detect_packers(&packed(fixture)).expect("scan");
        let finding: &PackerFinding = &findings[0];
        let got: Vec<&[u8]> = finding
            .recovered
            .iter()
            .map(|dex| dex.bytes.as_slice())
            .collect();
        let want: Vec<Vec<u8>> = fixture
            .recovered
            .iter()
            .map(|name: &&str| read(&corpus(&format!("packers/{name}"))))
            .collect();
        assert_eq!(
            got.len(),
            want.len(),
            "{}: recovered {} dex files, the build put {} in",
            fixture.apk,
            got.len(),
            want.len()
        );
        for (got, want) in got.iter().zip(&want) {
            assert!(
                *got == want.as_slice(),
                "{}: a recovered dex must equal the dex the build packed, byte for byte",
                fixture.apk
            );
        }
        for dex in &finding.recovered {
            assert_eq!(dex.sha256, sha256_hex(&dex.bytes));
        }
        recovered_total += got.len();
    }
    assert_eq!(recovered_total, 4);
}

#[test]
fn plain_packages_name_no_packer() {
    for name in PLAIN_APKS {
        let findings: Vec<PackerFinding> = detect_packers(&read(&corpus(name))).expect("scan");
        assert!(findings.is_empty(), "{name}: {findings:?}");
    }
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    {
        let mut writer: zip::ZipWriter<&mut Cursor<Vec<u8>>> = zip::ZipWriter::new(&mut out);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer.start_file(*name, options).expect("start");
            writer.write_all(data).expect("write");
        }
        writer.finish().expect("finish");
    }
    out.into_inner()
}

#[test]
fn a_payload_under_the_wrong_key_is_located_but_never_recovered() {
    let original: Vec<u8> = read(&corpus("packers/original.dex"));
    let wrong: Vec<u8> = original.iter().map(|b: &u8| b ^ 0x55).collect();
    let right: Vec<u8> = original.iter().map(|b: &u8| b ^ 0x54).collect();
    let rejected: Vec<PackerFinding> = detect_packers(&zip_of(&[
        ("lib/armeabi/libnsecure.so", b"\x7fELF"),
        ("assets/packed.dex", &wrong),
    ]))
    .expect("scan");
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert!(rejected[0].recovered.is_empty(), "{rejected:?}");
    assert_ne!(rejected[0].payload, PayloadState::Recovered);
    let accepted: Vec<PackerFinding> = detect_packers(&zip_of(&[
        ("lib/armeabi/libnsecure.so", b"\x7fELF"),
        ("assets/packed.dex", &right),
    ]))
    .expect("scan");
    assert_eq!(accepted[0].recovered.len(), 1);
    assert!(accepted[0].recovered[0].bytes == original);
}

#[test]
fn a_dex_whose_checksum_breaks_is_not_reported_as_recovered() {
    let mut original: Vec<u8> = read(&corpus("packers/original.dex"));
    let last: usize = original.len() - 1;
    original[last] ^= 0x01;
    let packed: Vec<u8> = original.iter().map(|b: &u8| b ^ 0x54).collect();
    let findings: Vec<PackerFinding> = detect_packers(&zip_of(&[
        ("lib/armeabi/libnsecure.so", b"\x7fELF"),
        ("assets/packed.dex", &packed),
    ]))
    .expect("scan");
    assert!(findings[0].recovered.is_empty(), "{findings:?}");
}

#[test]
fn hostile_archives_end_in_a_typed_result() {
    let fixture: Vec<u8> = packed(&FIXTURES[12]);
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for round in 0..400usize {
        let mut bytes: Vec<u8> = fixture.clone();
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at: usize = (state as usize) % bytes.len();
            bytes[at] = (state >> 32) as u8;
        }
        if round % 5 == 0 {
            bytes.truncate((state as usize) % bytes.len());
        }
        let _ = detect_packers(&bytes);
    }
    assert!(detect_packers(b"not a zip").is_err());
    assert!(detect_packers(&[]).is_err());
}

#[test]
fn recovered_dex_files_reach_the_children_the_chain_reads() {
    let fixture: &Fixture = &FIXTURES[12];
    let children: Vec<(String, Vec<u8>)> =
        disrobe_pass_mobile::extract_android_dex_children(&packed(fixture)).expect("children");
    for name in fixture.recovered {
        let want: Vec<u8> = read(&corpus(&format!("packers/{name}")));
        assert!(
            children
                .iter()
                .any(|(_, bytes): &(String, Vec<u8>)| *bytes == want),
            "{name} must be handed to the dex pass; children {:?}",
            children
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<&str>>()
        );
    }
    let report: disrobe_pass_mobile::ApkReconReport =
        disrobe_pass_mobile::analyze_apk_recon(&packed(fixture)).expect("recon");
    assert_eq!(report.packers.len(), 1);
    assert_eq!(report.packers[0].packer, ApkPacker::OpenSourceJiagu);
}

#[test]
fn a_recovered_payload_lifts_the_shield_wall_it_explains() {
    let fixture_named = |apk: &str| -> &Fixture {
        FIXTURES
            .iter()
            .find(|f: &&Fixture| f.apk == apk)
            .expect("fixture")
    };
    let recovered: disrobe_pass_mobile::ApkReconReport =
        disrobe_pass_mobile::analyze_apk_recon(&packed(fixture_named("dexhelper.apk")))
            .expect("recon");
    assert!(!recovered.protector_walls.is_empty());
    for wall in &recovered.protector_walls {
        assert!(
            wall.recoverable,
            "the DexHelper payload is recovered, so no wall may still claim run-time key \
             material: {wall:?}"
        );
    }
    let located: disrobe_pass_mobile::ApkReconReport =
        disrobe_pass_mobile::analyze_apk_recon(&packed(fixture_named("jiagu.apk"))).expect("recon");
    assert!(
        located
            .protector_walls
            .iter()
            .any(|wall: &disrobe_pass_mobile::ProtectorWall| !wall.recoverable),
        "a payload that is only located keeps its wall: {:?}",
        located.protector_walls
    );
}
