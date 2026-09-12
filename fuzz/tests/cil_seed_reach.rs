use std::fs;
use std::path::{Path, PathBuf};

use disrobe_fuzz::cil_metadata;
use disrobe_fuzz::seed_reach::{
    ReplayObservations, ReplayOptions, ReplayTarget, ReplayTrace, SeedContract, SeedReachError,
    SeedReplayFragment, TargetReplay, assemble_target_replay, replay_target, replay_target_seed,
    replay_target_with_options,
};
use disrobe_pass_dotnet::{
    CaptureError, Captured, MetadataRoot, ObservationPhase, PeImage, SemanticEntryPoint,
    StreamHeader, capture_observations, decompress_uint, disassemble, parse, parse_clr_header,
    parse_metadata_root, parse_method_body, parse_table_stream, read_strings_heap,
    read_us_heap_strings,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovedRoute {
    Pe,
    Clr,
    MetadataRoot,
    TableStream,
    StringsHeap,
    UserStringsHeap,
    CompressedUint,
    MethodBody,
    Instructions,
}

const REMOVED_ROUTES: [RemovedRoute; 9] = [
    RemovedRoute::Pe,
    RemovedRoute::Clr,
    RemovedRoute::MetadataRoot,
    RemovedRoute::TableStream,
    RemovedRoute::StringsHeap,
    RemovedRoute::UserStringsHeap,
    RemovedRoute::CompressedUint,
    RemovedRoute::MethodBody,
    RemovedRoute::Instructions,
];

#[derive(Debug)]
struct RemovedRouteReplay {
    capture: Captured<()>,
}

impl ReplayTrace for RemovedRouteReplay {
    fn observations(&self) -> ReplayObservations<'_> {
        ReplayObservations::Dotnet(self.capture.observations())
    }
}

fn method_code(method: &[u8]) -> Option<&[u8]> {
    let first: u8 = *method.first()?;
    if first & 0x03 == 0x02 {
        let length: usize = usize::from(first >> 2);
        return method.get(1..1usize.checked_add(length)?);
    }
    let header_bytes: [u8; 2] = method.get(..2)?.try_into().ok()?;
    let flags: u16 = u16::from_le_bytes(header_bytes);
    let header_size: usize = usize::from(flags >> 12).checked_mul(4)?;
    let length_bytes: [u8; 4] = method.get(4..8)?.try_into().ok()?;
    let length: usize = usize::try_from(u32::from_le_bytes(length_bytes)).ok()?;
    method.get(header_size..header_size.checked_add(length)?)
}

fn authentic_compressed_slice(metadata: &[u8], header: StreamHeader) -> Option<&[u8]> {
    let start: usize = usize::try_from(header.offset).ok()?.checked_add(1)?;
    let end: usize = usize::try_from(header.offset)
        .ok()?
        .checked_add(usize::try_from(header.size).ok()?)?
        .min(metadata.len());
    metadata
        .get(start..end)
        .filter(|slice: &&[u8]| !slice.is_empty())
}

fn replay_without_route(
    data: &[u8],
    removed: RemovedRoute,
) -> Result<RemovedRouteReplay, CaptureError> {
    let pe: Option<PeImage> = parse(data).ok();
    let clr = pe
        .as_ref()
        .and_then(|image: &PeImage| parse_clr_header(data, image).ok());
    let root: Option<MetadataRoot> = pe.as_ref().and_then(|image: &PeImage| {
        clr.as_ref()
            .and_then(|header| parse_metadata_root(data, image, header).ok())
    });
    let metadata: Option<&[u8]> = pe.as_ref().and_then(|image: &PeImage| {
        clr.as_ref().and_then(|header| {
            root.as_ref().and_then(|metadata_root: &MetadataRoot| {
                disrobe_pass_dotnet::metadata::metadata_slice(data, image, header, metadata_root)
                    .ok()
            })
        })
    });
    let table_header: Option<StreamHeader> =
        root.as_ref().and_then(|metadata_root: &MetadataRoot| {
            metadata_root
                .streams
                .get("#~")
                .or_else(|| metadata_root.streams.get("#-"))
                .copied()
        });
    let strings_header: Option<StreamHeader> = root
        .as_ref()
        .and_then(|metadata_root: &MetadataRoot| metadata_root.streams.get("#Strings").copied());
    let user_strings_header: Option<StreamHeader> = root
        .as_ref()
        .and_then(|metadata_root: &MetadataRoot| metadata_root.streams.get("#US").copied());
    let method_bytes: Option<&[u8]> = pe.as_ref().and_then(|image: &PeImage| {
        clr.as_ref().and_then(|header| {
            root.as_ref().and_then(|metadata_root: &MetadataRoot| {
                disrobe_pass_dotnet::Resolver::build(data, image, header, metadata_root)
                    .ok()
                    .and_then(|resolver| {
                        resolver
                            .methods_with_bodies()
                            .first()
                            .map(|(_token, _name, rva)| *rva)
                    })
                    .and_then(|rva: u32| image.slice_at_rva_to_end(data, rva).ok())
            })
        })
    });
    let capture: Captured<()> = capture_observations(|| {
        if removed != RemovedRoute::Pe {
            let _ = parse(data);
        }
        if removed != RemovedRoute::Clr
            && let Some(image) = pe.as_ref()
        {
            let _ = parse_clr_header(data, image);
        }
        if removed != RemovedRoute::MetadataRoot
            && let (Some(image), Some(header)) = (pe.as_ref(), clr.as_ref())
        {
            let _ = parse_metadata_root(data, image, header);
        }
        if removed != RemovedRoute::TableStream
            && let (Some(bytes), Some(header)) = (metadata, table_header)
        {
            let _ = parse_table_stream(bytes, header);
        }
        if removed != RemovedRoute::StringsHeap
            && let (Some(bytes), Some(header)) = (metadata, strings_header)
        {
            let _ = read_strings_heap(bytes, header);
        }
        if removed != RemovedRoute::CompressedUint && removed != RemovedRoute::UserStringsHeap {
            if let (Some(bytes), Some(header)) = (metadata, user_strings_header) {
                let _ = read_us_heap_strings(bytes, header);
            }
        } else if removed == RemovedRoute::UserStringsHeap
            && let (Some(bytes), Some(header)) = (metadata, user_strings_header)
            && let Some(compressed) = authentic_compressed_slice(bytes, header)
        {
            let _ = decompress_uint(compressed);
        }
        if removed != RemovedRoute::MethodBody && removed != RemovedRoute::Instructions {
            if let Some(bytes) = method_bytes {
                let _ = parse_method_body(bytes);
            }
        } else if removed == RemovedRoute::MethodBody
            && let Some(code) = method_bytes.and_then(method_code)
        {
            let _ = disassemble(code);
        }
    })?;
    Ok(RemovedRouteReplay { capture })
}

fn contract_context() -> core::result::Result<(PathBuf, SeedContract), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    Ok((workspace_root.to_path_buf(), contract))
}

#[test]
fn committed_cil_contract_replays_nine_positive_routes_and_one_refusal()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let (workspace_root, contract): (PathBuf, SeedContract) = contract_context()?;
    let replay: TargetReplay = replay_target(
        &workspace_root,
        &contract,
        ReplayTarget::CilMetadata,
        cil_metadata::replay,
    )?;
    assert_eq!(replay.seed_count(), 2);
    assert_eq!(replay.satisfied_obligations(), 10);
    assert_eq!(replay.declared_obligations(), 10);
    assert_eq!(replay.positive_witnesses(), 9);
    assert_eq!(replay.expected_rejection_witnesses(), 1);
    Ok(())
}

#[test]
fn cil_replay_is_byte_identical_at_one_and_four_jobs()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let (workspace_root, contract): (PathBuf, SeedContract) = contract_context()?;
    let sequential: TargetReplay = replay_target_with_options(
        &workspace_root,
        &contract,
        ReplayTarget::CilMetadata,
        cil_metadata::replay,
        ReplayOptions {
            jobs: 1,
            order_seed: 0,
        },
    )?;
    let parallel: TargetReplay = replay_target_with_options(
        &workspace_root,
        &contract,
        ReplayTarget::CilMetadata,
        cil_metadata::replay,
        ReplayOptions {
            jobs: 4,
            order_seed: 0x5445_5354_0004,
        },
    )?;
    assert_eq!(sequential.canonical_json()?, parallel.canonical_json()?);
    Ok(())
}

#[test]
fn full_seed_reaches_compressed_uint_only_after_metadata_acceptance()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let bytes: &[u8] = include_bytes!("../../corpus/dotnet/cil/CilProbe.dll");
    let replay = cil_metadata::replay(&bytes[..4096])?;
    let metadata_index: usize = replay
        .observations()
        .iter()
        .position(|observation| {
            observation.phase() == ObservationPhase::Accepted
                && observation.entry_point() == SemanticEntryPoint::ParseMetadataRoot
        })
        .ok_or("metadata root was not accepted")?;
    let compressed_index: usize = replay
        .observations()
        .iter()
        .position(|observation| {
            observation.phase() == ObservationPhase::Accepted
                && observation.entry_point() == SemanticEntryPoint::DecompressUint
                && observation.bytes_consumed() > 0
                && observation.items() > 0
        })
        .ok_or("compressed uint was not accepted")?;
    assert!(compressed_index > metadata_index);
    Ok(())
}

#[test]
fn failed_managed_parse_emits_no_positive_parser_observation()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let bytes: &[u8] = include_bytes!("../../corpus/dotnet/cil/CilProbe.dll");
    let replay = cil_metadata::replay(&bytes[..2])?;
    let accepted: Vec<SemanticEntryPoint> = replay
        .observations()
        .iter()
        .filter(|observation| observation.phase() == ObservationPhase::Accepted)
        .map(|observation| observation.entry_point())
        .collect();
    assert!(accepted.is_empty(), "raw fallback recorded {accepted:?}");
    Ok(())
}

#[test]
fn contract_rejects_a_positive_surface_name_outside_the_canonical_route()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let root: PathBuf =
        std::env::temp_dir().join(format!("disrobe-cil-route-contract-{}", std::process::id()));
    fs::create_dir_all(&root)?;
    let contract_path: PathBuf = root.join("seed_reach.toml");
    fs::write(
        &contract_path,
        "schema = 3\n\n[[surface]]\ntarget = \"cil_metadata\"\nid = \"dotnet.raw.compressed-uint\"\nentry_point = \"disrobe-pass-dotnet/src/metadata.rs::decompress_uint\"\n\n[[seed]]\ntarget = \"cil_metadata\"\nsource = \"corpus/sample.bin\"\noffset = 0\nlength = 1\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n\n[[seed.obligation]]\nsurface = \"dotnet.raw.compressed-uint\"\noutcome = \"accepted\"\nminimum_bytes = 1\nminimum_items = 1\n",
    )?;
    let result: Result<SeedContract, SeedReachError> = SeedContract::read(&contract_path);
    assert!(
        matches!(result, Err(SeedReachError::Invalid(message)) if message.contains("canonical route"))
    );
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn removing_any_public_route_breaks_its_committed_obligation()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let (workspace_root, contract): (PathBuf, SeedContract) = contract_context()?;
    for removed in REMOVED_ROUTES {
        let result: Result<TargetReplay, SeedReachError> = replay_target(
            &workspace_root,
            &contract,
            ReplayTarget::CilMetadata,
            |data: &[u8]| replay_without_route(data, removed),
        );
        assert!(
            result.is_err(),
            "removed route {removed:?} still satisfied the contract"
        );
    }
    Ok(())
}

fn append_complete_event(
    fragment: &mut serde_json::Value,
    surface: &str,
    entry_point: &str,
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let trace = fragment["replay"]["trace"]
        .as_array_mut()
        .ok_or("fragment trace is not an array")?;
    let span: u64 = trace
        .iter()
        .filter_map(|event: &serde_json::Value| event["span"].as_u64())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    trace.push(serde_json::json!({
        "span": span,
        "surface": surface,
        "entry_point": entry_point,
        "phase": "entered",
        "bytes_consumed": 0,
        "items": 0
    }));
    trace.push(serde_json::json!({
        "span": span,
        "surface": surface,
        "entry_point": entry_point,
        "phase": "rejected",
        "bytes_consumed": 0,
        "items": 0
    }));
    Ok(())
}

#[test]
fn assembled_fragments_reject_foreign_and_undeclared_trace_events()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let (workspace_root, contract): (PathBuf, SeedContract) = contract_context()?;
    let first: SeedReplayFragment = replay_target_seed(
        &workspace_root,
        &contract,
        ReplayTarget::CilMetadata,
        6,
        cil_metadata::replay,
    )?;
    let second: SeedReplayFragment = replay_target_seed(
        &workspace_root,
        &contract,
        ReplayTarget::CilMetadata,
        7,
        cil_metadata::replay,
    )?;
    let mutations: [(&str, &str); 3] = [
        ("dotnet.pe.image", "disrobe-py-marshal/src/pyc.rs::read_pyc"),
        ("dotnet.undeclared", "disrobe-pass-dotnet/src/pe.rs::parse"),
        (
            "dotnet.pe.image",
            "disrobe-pass-dotnet/src/pe.rs::parse_clr_header",
        ),
    ];
    for (surface, entry_point) in mutations {
        let mut value: serde_json::Value = serde_json::from_str(&first.canonical_json()?)?;
        append_complete_event(&mut value, surface, entry_point)?;
        let bytes: Vec<u8> = serde_json::to_vec(&value)?;
        let mutated: SeedReplayFragment = SeedReplayFragment::from_json(&bytes)?;
        let result: Result<TargetReplay, SeedReachError> = assemble_target_replay(
            &contract,
            ReplayTarget::CilMetadata,
            vec![mutated, second.clone()],
        );
        assert!(
            matches!(result, Err(SeedReachError::Invalid(message)) if message.contains("trace event")),
            "fragment accepted {surface} with {entry_point}"
        );
    }
    Ok(())
}
