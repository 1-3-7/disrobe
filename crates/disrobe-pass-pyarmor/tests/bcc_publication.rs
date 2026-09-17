#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_pyarmor::{
    BccArch, BccBlob, BccLiftOutput, BccLiftRefusal, BccLiftRefusalReason, BccLinkOutput,
    BccPublication, BccPublicationLimits, BccPublicationResource, Error, UnpackOptions,
    UnpackOutput, lift_bcc_native, link_bcc_from_unpack, publish_bcc_recovery,
    publish_bcc_recovery_with_limits, unpack_wrapper_text_with_options,
};

const BCC_WRAPPER: &str = "corpus/python/pyarmor/v9-bcc/default/known_plaintext.py";
const RECORD_STRIDE: usize = 32;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

fn descriptor_object(text: &[u8], entries: &[(u64, String)]) -> Vec<u8> {
    let text_addr: u64 = 0x1000;
    let names_addr: u64 = 0x20_000;
    let table_addr: u64 = 0x40_000;
    let mut names: Vec<u8> = Vec::new();
    let mut name_ptrs: Vec<u64> = Vec::with_capacity(entries.len());
    for (_, name) in entries {
        name_ptrs
            .push(names_addr + u64::try_from(names.len()).expect("name table length must fit u64"));
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let mut table: Vec<u8> = Vec::new();
    for (index, (offset, _)) in entries.iter().enumerate() {
        table.extend_from_slice(&name_ptrs[index].to_le_bytes());
        table.extend_from_slice(&(text_addr + offset).to_le_bytes());
        table.extend_from_slice(&1u64.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
    }
    table.resize(table.len() + RECORD_STRIDE, 0);
    let header_len: usize = 64;
    let shentsize: usize = 64;
    let sections: [(u64, u64, &[u8]); 3] = [
        (text_addr, SHF_ALLOC | SHF_EXECINSTR, text),
        (names_addr, 0, names.as_slice()),
        (table_addr, 0, table.as_slice()),
    ];
    let mut body: Vec<u8> = Vec::new();
    let mut placed: Vec<(u64, u64, usize, usize)> = Vec::new();
    for (address, flags, data) in &sections {
        let offset: usize = header_len + body.len();
        body.extend_from_slice(data);
        placed.push((*address, *flags, offset, data.len()));
    }
    let shoff: usize = header_len + body.len();
    let mut blob: Vec<u8> = vec![0u8; header_len];
    blob[..4].copy_from_slice(&ELF_MAGIC);
    blob[4] = 2;
    blob[5] = 1;
    blob[0x28..0x30].copy_from_slice(
        &u64::try_from(shoff)
            .expect("section offset must fit u64")
            .to_le_bytes(),
    );
    blob[0x3a..0x3c].copy_from_slice(
        &u16::try_from(shentsize)
            .expect("section header size must fit u16")
            .to_le_bytes(),
    );
    blob[0x3c..0x3e].copy_from_slice(
        &u16::try_from(placed.len())
            .expect("section count must fit u16")
            .to_le_bytes(),
    );
    blob.extend_from_slice(&body);
    for (address, flags, offset, size) in placed {
        let mut header: Vec<u8> = vec![0u8; shentsize];
        header[4..8].copy_from_slice(&1u32.to_le_bytes());
        header[8..16].copy_from_slice(&flags.to_le_bytes());
        header[16..24].copy_from_slice(&address.to_le_bytes());
        header[24..32].copy_from_slice(
            &u64::try_from(offset)
                .expect("section data offset must fit u64")
                .to_le_bytes(),
        );
        header[32..40].copy_from_slice(
            &u64::try_from(size)
                .expect("section data size must fit u64")
                .to_le_bytes(),
        );
        blob.extend_from_slice(&header);
    }
    blob
}

fn dispatch_lift(entries: Vec<(u64, String)>, text: Vec<u8>) -> BccLiftOutput {
    let blob: Vec<u8> = descriptor_object(&text, &entries);
    lift_bcc_native(&blob, BccArch::WinX64).expect("descriptor object must lift")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pass crate must be in crates")
        .parent()
        .expect("crates must be in workspace")
        .to_path_buf()
}

fn fixture() -> (UnpackOutput, BccLinkOutput) {
    let wrapper_path: PathBuf = workspace_root().join(BCC_WRAPPER);
    let wrapper_text: String =
        std::fs::read_to_string(&wrapper_path).expect("tracked BCC wrapper must be UTF-8");
    let options: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked: UnpackOutput =
        unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &options)
            .expect("tracked BCC wrapper must unpack");
    let linked: BccLinkOutput = link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path)
        .expect("tracked BCC wrapper must link");
    (unpacked, linked)
}

fn assert_quota(
    unpacked: &UnpackOutput,
    linked: &BccLinkOutput,
    limits: BccPublicationLimits,
    expected: BccPublicationResource,
) {
    let error: Error = publish_bcc_recovery_with_limits(unpacked, linked, limits)
        .expect_err("limit plus one must refuse the publication");
    assert!(
        matches!(
            error,
            Error::BccPublicationQuotaExceeded { resource, .. } if resource == expected
        ),
        "unexpected quota error: {error}"
    );
}

#[test]
fn recovery_document_embeds_the_existing_map_and_all_native_functions() {
    let (unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    let publication: BccPublication =
        publish_bcc_recovery(&unpacked, &linked).expect("real BCC fixture must publish");
    let document: serde_json::Value =
        serde_json::from_slice(&publication.recovery_json).expect("publication JSON must parse");

    assert_eq!(document["schema"], "disrobe.pyarmor.bcc.recovery/v1");
    assert_eq!(
        document["function_map"]["schema"],
        "disrobe.pyarmor.bcc.function_map/1"
    );
    assert_eq!(
        document["summary"]["function_count"],
        publication.summary.function_count
    );
    assert_eq!(document["summary"]["modeled_count"], 0);
    assert_eq!(document["summary"]["unmodeled_count"], 4);
    let functions: &Vec<serde_json::Value> = document["blobs"][0]["functions"]
        .as_array()
        .expect("first blob must list every function");
    assert_eq!(functions.len(), 4);
    assert!(functions.iter().all(|function: &serde_json::Value| {
        function["identity"]
            .as_str()
            .is_some_and(|identity: &str| identity.starts_with("bcc-image[0] win-x64@0x"))
            && function["entry"].as_str().is_some_and(|entry: &str| {
                entry.starts_with("0x")
                    && entry
                        .chars()
                        .all(|character: char| !character.is_ascii_uppercase())
            })
            && function["status"] == "unmodeled"
            && function["reason"]["code"] == "native_recovery_declined"
            && function["reason"]["message"]
                .as_str()
                .is_some_and(|message: &str| !message.is_empty())
            && function["body"]["status"] == "included"
    }));
    assert!(
        String::from_utf8_lossy(&publication.pseudo_c).contains("in-crate pseudo-C lift declined")
    );
    assert!(
        String::from_utf8_lossy(&publication.recovered_python).contains("disrobe BCC skeleton")
    );
}

#[test]
fn every_publication_limit_is_inclusive_and_rejects_the_next_value() {
    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    if unpacked
        .bcc_lifts
        .iter()
        .all(|lift| lift.strings.is_empty())
    {
        unpacked.bcc_lifts[0]
            .strings
            .push("quota-string".to_owned());
    }
    let baseline: BccPublication =
        publish_bcc_recovery_with_limits(&unpacked, &linked, BccPublicationLimits::unbounded())
            .expect("unbounded publication must establish exact sizes");
    let function_count: usize = unpacked
        .bcc_lifts
        .iter()
        .map(|lift| lift.functions.len())
        .sum();
    let native_body_bytes: usize = unpacked
        .bcc_lifts
        .iter()
        .flat_map(|lift| lift.functions.values())
        .map(|function| usize::try_from(function.size).expect("u32 fits usize"))
        .sum();
    let largest_body: usize = unpacked
        .bcc_lifts
        .iter()
        .flat_map(|lift| lift.functions.values())
        .map(|function| usize::try_from(function.size).expect("u32 fits usize"))
        .max()
        .expect("real BCC fixture has functions");
    let string_count: usize = unpacked
        .bcc_lifts
        .iter()
        .map(|lift| lift.strings.len())
        .sum();
    let string_bytes: usize = unpacked
        .bcc_lifts
        .iter()
        .flat_map(|lift| lift.strings.iter())
        .map(String::len)
        .sum();
    let exact: BccPublicationLimits = BccPublicationLimits {
        functions: function_count,
        total_native_body_bytes: native_body_bytes,
        body_bytes: largest_body,
        strings: string_count,
        total_string_bytes: string_bytes,
        json_bytes: baseline.recovery_json.len(),
        pseudo_c_bytes: baseline.pseudo_c.len(),
        recovered_python_bytes: baseline.recovered_python.len(),
    };
    publish_bcc_recovery_with_limits(&unpacked, &linked, exact)
        .expect("every exact limit must be inclusive");

    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            functions: function_count - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::Functions,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            total_native_body_bytes: native_body_bytes - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::NativeBodyBytes,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            strings: string_count - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::Strings,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            total_string_bytes: string_bytes - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::StringBytes,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            json_bytes: baseline.recovery_json.len() - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::JsonBytes,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            pseudo_c_bytes: baseline.pseudo_c.len() - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::PseudoCBytes,
    );
    assert_quota(
        &unpacked,
        &linked,
        BccPublicationLimits {
            recovered_python_bytes: baseline.recovered_python.len() - 1,
            ..BccPublicationLimits::unbounded()
        },
        BccPublicationResource::RecoveredPythonBytes,
    );

    let omitted: BccPublication = publish_bcc_recovery_with_limits(
        &unpacked,
        &linked,
        BccPublicationLimits {
            body_bytes: largest_body - 1,
            ..BccPublicationLimits::unbounded()
        },
    )
    .expect("a per-body overflow retains a typed function record");
    let omitted_json: serde_json::Value =
        serde_json::from_slice(&omitted.recovery_json).expect("omission JSON must parse");
    assert!(
        omitted_json["blobs"][0]["functions"]
            .as_array()
            .expect("functions array")
            .iter()
            .any(|function: &serde_json::Value| {
                function["body"]["status"] == "omitted"
                    && function["body"]["reason"]["code"] == "body_limit_exceeded"
            })
    );
}

#[test]
fn default_limits_match_the_v1_publication_contract() {
    let limits: BccPublicationLimits = BccPublicationLimits::default();
    assert_eq!(limits.functions, 4_096);
    assert_eq!(limits.total_native_body_bytes, 32 * 1024 * 1024);
    assert_eq!(limits.body_bytes, 1024 * 1024);
    assert_eq!(limits.strings, 4_096);
    assert_eq!(limits.total_string_bytes, 1024 * 1024);
    assert_eq!(limits.json_bytes, 64 * 1024 * 1024);
    assert_eq!(limits.pseudo_c_bytes, 32 * 1024 * 1024);
    assert_eq!(limits.recovered_python_bytes, 8 * 1024 * 1024);
}

#[test]
fn duplicate_native_identities_are_refused_but_equal_offsets_in_two_blobs_survive() {
    let (unpacked, mut duplicated_link): (UnpackOutput, BccLinkOutput) = fixture();
    let duplicate = duplicated_link
        .map
        .records
        .iter()
        .find(|record| record.native.is_some())
        .expect("real BCC map has a native record")
        .clone();
    duplicated_link.map.records.push(duplicate.clone());
    let error: Error = publish_bcc_recovery(&unpacked, &duplicated_link)
        .expect_err("same container and offset must be refused");
    assert!(matches!(
        error,
        Error::BccPublicationDuplicateNativeIdentity { .. }
    ));

    let (mut two_blobs, mut two_blob_link): (UnpackOutput, BccLinkOutput) = fixture();
    two_blobs.bcc_blobs.push(two_blobs.bcc_blobs[0].clone());
    two_blobs.bcc_lifts.push(two_blobs.bcc_lifts[0].clone());
    let mut second_record = duplicate;
    second_record
        .native
        .as_mut()
        .expect("cloned record remains native")
        .container = "bcc-image[1] win-x64".to_owned();
    two_blob_link.map.records.push(second_record);
    let publication: BccPublication = publish_bcc_recovery(&two_blobs, &two_blob_link)
        .expect("equal offsets in separate containers are distinct");
    let document: serde_json::Value =
        serde_json::from_slice(&publication.recovery_json).expect("publication JSON must parse");
    assert_eq!(document["blobs"].as_array().expect("blobs").len(), 2);
    assert!(String::from_utf8_lossy(&publication.recovery_json).contains("bcc-image[0] win-x64"));
    assert!(String::from_utf8_lossy(&publication.recovery_json).contains("bcc-image[1] win-x64"));
}

#[test]
fn inconsistent_lift_accounting_is_a_typed_refusal() {
    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    unpacked.bcc_lifts[0].modeled_count += 1;
    let error: Error = publish_bcc_recovery(&unpacked, &linked)
        .expect_err("modeled plus unmodeled must equal the function count");
    assert!(matches!(
        error,
        Error::BccPublicationAccountingMismatch { .. }
    ));
}

#[test]
fn producer_preserves_the_inclusive_function_limit_and_rejects_limit_plus_one() {
    let entries: Vec<(u64, String)> = (0..=4_096usize)
        .map(|index: usize| {
            (
                u64::try_from(index).expect("test index must fit u64"),
                format!("bcc_{index}"),
            )
        })
        .collect();
    let lift: BccLiftOutput = dispatch_lift(entries, vec![0xc3; 4_097]);
    assert_eq!(lift.function_records.len(), 4_097);

    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    unpacked.bcc_lifts[0] = lift;
    let error: Error = publish_bcc_recovery(&unpacked, &linked)
        .expect_err("the 4097th exact producer record must reach the publisher quota");
    assert!(matches!(
        error,
        Error::BccPublicationQuotaExceeded {
            resource: BccPublicationResource::Functions,
            actual: 4_097,
            limit: 4_096,
        }
    ));

    let entries_at_limit: Vec<(u64, String)> = (0..4_096usize)
        .map(|index: usize| {
            (
                u64::try_from(index).expect("test index must fit u64"),
                format!("bcc_{index}"),
            )
        })
        .collect();
    let lift_at_limit: BccLiftOutput = dispatch_lift(entries_at_limit, vec![0xc3; 4_096]);
    assert_eq!(lift_at_limit.function_records.len(), 4_096);
}

#[test]
fn producer_preserves_duplicate_native_addresses_with_distinct_names_for_typed_refusal() {
    let lift: BccLiftOutput = dispatch_lift(
        vec![(0, "bcc_7".to_owned()), (0, "alias_7".to_owned())],
        vec![0xc3],
    );
    assert_eq!(lift.function_records.len(), 2);
    assert_eq!(
        lift.function_records[0].id.entry_va,
        lift.function_records[1].id.entry_va
    );
    assert_ne!(
        lift.function_records[0].id.name,
        lift.function_records[1].id.name
    );
    let duplicate_entry: u64 = lift.function_records[0].id.entry_va;

    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    unpacked.bcc_lifts[0] = lift;
    let error: Error = publish_bcc_recovery(&unpacked, &linked)
        .expect_err("duplicate exact producer records must reach typed publisher validation");
    assert!(
        matches!(
            &error,
            Error::BccPublicationDuplicateNativeIdentity { offset, .. }
                if *offset == duplicate_entry
        ),
        "{error:?}"
    );
}

#[test]
fn publisher_refuses_a_zero_length_unique_native_record_after_identity_validation() {
    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    unpacked.bcc_lifts[0].function_records[0].size = 0;
    let error: Error = publish_bcc_recovery(&unpacked, &linked)
        .expect_err("zero-length unique record must reach typed publisher validation");
    assert!(matches!(
        error,
        Error::BccPublicationZeroLengthFunction { .. }
    ));
}

#[test]
fn a_refused_blob_remains_in_the_publication_with_a_typed_reason() {
    let (mut unpacked, linked): (UnpackOutput, BccLinkOutput) = fixture();
    let blob_index: usize = unpacked.bcc_blobs.len();
    unpacked.bcc_blobs.push(BccBlob {
        architecture: BccArch::Other(0xdead),
        bytes: vec![0u8; 64],
    });
    unpacked.bcc_lift_refusals.push(BccLiftRefusal {
        blob_index,
        architecture: BccArch::Other(0xdead),
        reason: BccLiftRefusalReason::UnsupportedArchitecture { id: 0xdead },
    });
    let publication: BccPublication = publish_bcc_recovery(&unpacked, &linked)
        .expect("a refused blob is a complete typed outcome");
    let document: serde_json::Value =
        serde_json::from_slice(&publication.recovery_json).expect("publication JSON must parse");
    assert_eq!(document["summary"]["refused_blob_count"], 1);
    assert_eq!(document["blobs"][blob_index]["status"], "refused");
    assert_eq!(
        document["blobs"][blob_index]["refusal"]["code"],
        "unsupported_architecture"
    );
    assert_eq!(
        document["blobs"][blob_index]["refusal"]["architecture_id"],
        "0xdead"
    );
}
