use std::collections::BTreeSet;

use disrobe_core::artifact_ledger::{
    ARTIFACT_LEDGER_FORMAT_VERSION, ArtifactEdgeKind, ArtifactEdgeRecord, ArtifactLedgerError,
    ArtifactLedgerRecord, ArtifactNodeId, ArtifactNodeKind, ArtifactNodeRecord, CommandInvocation,
    ConfigurationArgument, EdgeInvocation, Endianness, MAX_ARTIFACT_LEDGER_RECORD_BYTES,
    PassIdentity, PassInvocation, Platform, RunStartRecord, WallClockDuration, append_record,
    parse_ledger,
};
use disrobe_core::{Capability, Rung};

fn pass() -> PassIdentity {
    PassIdentity {
        id: "native.disasm".to_owned(),
        version: "0.10.5".to_owned(),
    }
}

fn settings() -> Vec<ConfigurationArgument> {
    vec![
        ConfigurationArgument::Flag {
            name: "allow-dynamic".to_owned(),
            enabled: false,
        },
        ConfigurationArgument::Unsigned {
            name: "jobs".to_owned(),
            value: 4,
        },
        ConfigurationArgument::Text {
            name: "profile".to_owned(),
            value: "release".to_owned(),
        },
    ]
}

fn run_start() -> ArtifactLedgerRecord {
    ArtifactLedgerRecord::RunStart(RunStartRecord {
        tool_version: "0.10.5".to_owned(),
        configuration: settings(),
        input_hash: [0x11; 32],
        platform: Platform {
            operating_system: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            endianness: Endianness::Little,
        },
    })
}

fn node(id: u64, kind: ArtifactNodeKind, rung: Rung) -> ArtifactLedgerRecord {
    let capabilities: BTreeSet<Capability> =
        BTreeSet::from([Capability::produces("disrobe.native.disasm", 1)]);
    ArtifactLedgerRecord::Node(ArtifactNodeRecord {
        id: ArtifactNodeId(id),
        kind,
        root_hash: [u8::try_from(id).unwrap_or(u8::MAX); 32],
        rung,
        capabilities,
        producing_pass: (id != 1).then(pass),
        wall_clock: WallClockDuration::from_millis(7),
        byte_len: 4096,
    })
}

fn pass_invocation() -> EdgeInvocation {
    EdgeInvocation::Pass(PassInvocation {
        pass: pass(),
        configuration: settings(),
    })
}

fn edge(
    id: u64,
    kind: ArtifactEdgeKind,
    invocation: Option<EdgeInvocation>,
) -> ArtifactLedgerRecord {
    ArtifactLedgerRecord::Edge(ArtifactEdgeRecord {
        id,
        inputs: vec![ArtifactNodeId(1)],
        outputs: vec![ArtifactNodeId(2), ArtifactNodeId(3)],
        invocation,
        kind,
    })
}

fn all_records() -> Vec<ArtifactLedgerRecord> {
    vec![
        run_start(),
        node(1, ArtifactNodeKind::Input, Rung::Raw),
        node(2, ArtifactNodeKind::Intermediate, Rung::Disasm),
        node(3, ArtifactNodeKind::Child, Rung::Mir),
        node(4, ArtifactNodeKind::Final, Rung::Surface),
        edge(1, ArtifactEdgeKind::PassApplied, Some(pass_invocation())),
        edge(
            2,
            ArtifactEdgeKind::ContainerMemberExtracted {
                member_name: "payload.bin".to_owned(),
            },
            Some(EdgeInvocation::Command(CommandInvocation {
                program: "disrobe".to_owned(),
                arguments: vec!["extract".to_owned(), "payload.bin".to_owned()],
            })),
        ),
        edge(3, ArtifactEdgeKind::ChainBranch, Some(pass_invocation())),
        edge(4, ArtifactEdgeKind::ChainJoin, Some(pass_invocation())),
        edge(
            5,
            ArtifactEdgeKind::Refusal {
                pass: pass(),
                reason: "encrypted input requires a key".to_owned(),
            },
            Some(pass_invocation()),
        ),
        edge(
            6,
            ArtifactEdgeKind::Wall {
                pass: Some(pass()),
                reason: "dynamic execution is disabled".to_owned(),
            },
            Some(pass_invocation()),
        ),
    ]
}

#[test]
fn every_node_and_edge_kind_round_trips_through_framed_records() -> Result<(), ArtifactLedgerError>
{
    let expected: Vec<ArtifactLedgerRecord> = all_records();
    let mut ledger: Vec<u8> = Vec::new();
    for record in &expected {
        append_record(&mut ledger, record)?;
    }

    let actual: Vec<ArtifactLedgerRecord> = parse_ledger(&ledger)?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn an_incomplete_final_frame_preserves_every_complete_record() -> Result<(), ArtifactLedgerError> {
    let first: ArtifactLedgerRecord = run_start();
    let second: ArtifactLedgerRecord = node(1, ArtifactNodeKind::Input, Rung::Raw);
    let mut ledger: Vec<u8> = Vec::new();
    append_record(&mut ledger, &first)?;
    let complete_len: usize = ledger.len();
    append_record(&mut ledger, &second)?;
    ledger.truncate(ledger.len() - 3);

    let parsed: Vec<ArtifactLedgerRecord> = parse_ledger(&ledger)?;
    assert_eq!(parsed, vec![first]);
    assert!(complete_len < ledger.len());
    Ok(())
}

#[test]
fn corruption_in_a_complete_record_is_rejected() -> Result<(), ArtifactLedgerError> {
    let mut ledger: Vec<u8> = Vec::new();
    append_record(&mut ledger, &run_start())?;
    let first_frame_len: usize = ledger.len();
    append_record(&mut ledger, &node(1, ArtifactNodeKind::Input, Rung::Raw))?;
    let corrupt_index: usize = first_frame_len - 1;
    ledger[corrupt_index] ^= 0x80;

    let result: Result<Vec<ArtifactLedgerRecord>, ArtifactLedgerError> = parse_ledger(&ledger);
    assert!(matches!(
        result,
        Err(ArtifactLedgerError::ChecksumMismatch { record_index: 0 })
    ));
    Ok(())
}

#[test]
fn corrupt_length_cannot_hide_a_later_complete_record() -> Result<(), ArtifactLedgerError> {
    let mut ledger: Vec<u8> = Vec::new();
    append_record(&mut ledger, &run_start())?;
    append_record(&mut ledger, &node(1, ArtifactNodeKind::Input, Rung::Raw))?;
    let corrupt_length: u32 = u32::try_from(ledger.len()).unwrap_or(u32::MAX);
    assert!((corrupt_length as usize) < MAX_ARTIFACT_LEDGER_RECORD_BYTES);
    ledger[6..10].copy_from_slice(&corrupt_length.to_le_bytes());

    let result: Result<Vec<ArtifactLedgerRecord>, ArtifactLedgerError> = parse_ledger(&ledger);
    assert!(matches!(
        result,
        Err(ArtifactLedgerError::HeaderChecksumMismatch { record_index: 0 })
    ));
    Ok(())
}

#[test]
fn unknown_versions_return_a_typed_error() -> Result<(), ArtifactLedgerError> {
    let mut ledger: Vec<u8> = Vec::new();
    append_record(&mut ledger, &run_start())?;
    let unknown_version: u16 = ARTIFACT_LEDGER_FORMAT_VERSION + 1;
    ledger[4..6].copy_from_slice(&unknown_version.to_le_bytes());

    let result: Result<Vec<ArtifactLedgerRecord>, ArtifactLedgerError> = parse_ledger(&ledger);
    assert!(matches!(
        result,
        Err(ArtifactLedgerError::UnknownVersion {
            record_index: 0,
            version
        }) if version == unknown_version
    ));
    Ok(())
}

#[test]
fn oversized_frame_headers_return_a_typed_error() -> Result<(), ArtifactLedgerError> {
    let mut ledger: Vec<u8> = Vec::new();
    append_record(&mut ledger, &run_start())?;
    let oversized: u32 = u32::try_from(MAX_ARTIFACT_LEDGER_RECORD_BYTES + 1).unwrap_or(u32::MAX);
    ledger[6..10].copy_from_slice(&oversized.to_le_bytes());
    let header_checksum: u32 = crc32fast::hash(&ledger[..10]);
    ledger[10..14].copy_from_slice(&header_checksum.to_le_bytes());

    let result: Result<Vec<ArtifactLedgerRecord>, ArtifactLedgerError> = parse_ledger(&ledger);
    assert!(matches!(
        result,
        Err(ArtifactLedgerError::RecordTooLarge {
            record_index: Some(0),
            length,
            maximum,
            buffered
        }) if length == oversized as usize
            && maximum == MAX_ARTIFACT_LEDGER_RECORD_BYTES
            && buffered == 0
    ));
    Ok(())
}

#[test]
fn oversized_records_are_rejected_before_writing() {
    let oversized_text: String = "x".repeat(MAX_ARTIFACT_LEDGER_RECORD_BYTES * 3);
    let record: ArtifactLedgerRecord = ArtifactLedgerRecord::RunStart(RunStartRecord {
        tool_version: "0.10.5".to_owned(),
        configuration: vec![ConfigurationArgument::Text {
            name: "oversized".to_owned(),
            value: oversized_text,
        }],
        input_hash: [0x11; 32],
        platform: Platform {
            operating_system: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            endianness: Endianness::Little,
        },
    });
    let mut ledger: Vec<u8> = Vec::new();

    let result: Result<(), ArtifactLedgerError> = append_record(&mut ledger, &record);
    assert!(matches!(
        result,
        Err(ArtifactLedgerError::RecordTooLarge {
            record_index: None,
            length,
            maximum,
            buffered
        }) if length > maximum
            && maximum == MAX_ARTIFACT_LEDGER_RECORD_BYTES
            && buffered <= maximum
    ));
    assert!(ledger.is_empty());
}
