use std::collections::BTreeSet;

use disrobe_pass_dotnet::{
    ObservationPhase, Resolver, SemanticEntryPoint, SemanticSurface, capture_observations, parse,
    parse_clr_header, parse_metadata_root, parse_method_body, parse_table_stream,
    read_strings_heap, read_us_heap_strings,
};

const REAL_CIL: &[u8] = include_bytes!("../../../corpus/dotnet/cil/CilProbe.dll");

#[test]
fn real_cil_probe_reaches_every_dotnet_parser_boundary()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let capture = capture_observations(|| {
        let pe = parse(REAL_CIL)?;
        let clr = parse_clr_header(REAL_CIL, &pe)?;
        let root = parse_metadata_root(REAL_CIL, &pe, &clr)?;
        let metadata: &[u8] =
            disrobe_pass_dotnet::metadata::metadata_slice(REAL_CIL, &pe, &clr, &root)?;
        let table_header = root
            .streams
            .get("#~")
            .or_else(|| root.streams.get("#-"))
            .copied()
            .ok_or_else(|| std::io::Error::other("missing table stream"))?;
        let strings_header = root
            .streams
            .get("#Strings")
            .copied()
            .ok_or_else(|| std::io::Error::other("missing strings heap"))?;
        let user_strings_header = root
            .streams
            .get("#US")
            .copied()
            .ok_or_else(|| std::io::Error::other("missing user strings heap"))?;
        let _table_stream = parse_table_stream(metadata, table_header)?;
        let _strings = read_strings_heap(metadata, strings_header);
        let _user_strings = read_us_heap_strings(metadata, user_strings_header);
        let resolver = Resolver::build(REAL_CIL, &pe, &clr, &root)?;
        let methods: Vec<(u32, String, u32)> = resolver.methods_with_bodies();
        let method_rva: u32 = methods
            .first()
            .ok_or_else(|| std::io::Error::other("missing method body"))?
            .2;
        let method_bytes: &[u8] = pe.slice_at_rva_to_end(REAL_CIL, method_rva)?;
        let _method = parse_method_body(method_bytes)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    if let Err(error) = capture.value() {
        return Err(error.to_string().into());
    }
    let accepted: BTreeSet<(SemanticSurface, SemanticEntryPoint)> = capture
        .observations()
        .iter()
        .filter(|observation| {
            observation.phase() == ObservationPhase::Accepted
                && observation.bytes_consumed() > 0
                && observation.items() > 0
        })
        .map(|observation| (observation.surface(), observation.entry_point()))
        .collect();
    let expected: BTreeSet<(SemanticSurface, SemanticEntryPoint)> = BTreeSet::from([
        (SemanticSurface::PeImage, SemanticEntryPoint::ParsePe),
        (
            SemanticSurface::ClrHeader,
            SemanticEntryPoint::ParseClrHeader,
        ),
        (
            SemanticSurface::MetadataRoot,
            SemanticEntryPoint::ParseMetadataRoot,
        ),
        (
            SemanticSurface::TableStream,
            SemanticEntryPoint::ParseTableStream,
        ),
        (
            SemanticSurface::StringsHeap,
            SemanticEntryPoint::ReadStringsHeap,
        ),
        (
            SemanticSurface::UserStringsHeap,
            SemanticEntryPoint::ReadUserStringsHeap,
        ),
        (
            SemanticSurface::CompressedUint,
            SemanticEntryPoint::DecompressUint,
        ),
        (
            SemanticSurface::MethodBody,
            SemanticEntryPoint::ParseMethodBody,
        ),
        (
            SemanticSurface::Instructions,
            SemanticEntryPoint::Disassemble,
        ),
    ]);
    assert_eq!(accepted, expected);
    Ok(())
}

#[test]
fn mz_prefix_records_only_the_expected_pe_rejection()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let capture = capture_observations(|| parse(&REAL_CIL[..2]))?;
    assert!(capture.value().is_err());
    let observations = capture.observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].surface(), SemanticSurface::PeImage);
    assert_eq!(observations[0].entry_point(), SemanticEntryPoint::ParsePe);
    assert_eq!(observations[0].phase(), ObservationPhase::Entered);
    assert_eq!(observations[1].surface(), SemanticSurface::PeImage);
    assert_eq!(observations[1].entry_point(), SemanticEntryPoint::ParsePe);
    assert_eq!(observations[1].phase(), ObservationPhase::Rejected);
    assert_eq!(observations[1].bytes_consumed(), 0);
    assert_eq!(observations[1].items(), 0);
    Ok(())
}

#[test]
fn table_stream_observation_counts_rows_instead_of_table_kinds()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let pe = parse(REAL_CIL)?;
    let clr = parse_clr_header(REAL_CIL, &pe)?;
    let root = parse_metadata_root(REAL_CIL, &pe, &clr)?;
    let metadata: &[u8] =
        disrobe_pass_dotnet::metadata::metadata_slice(REAL_CIL, &pe, &clr, &root)?;
    let table_header = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or("missing metadata table stream")?;
    let capture = capture_observations(|| parse_table_stream(metadata, table_header))?;
    let stream = match capture.value() {
        Ok(value) => value,
        Err(error) => return Err(error.to_string().into()),
    };
    let expected_rows: usize = stream
        .row_counts
        .values()
        .map(|count: &u32| usize::try_from(*count))
        .collect::<Result<Vec<usize>, _>>()?
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or("metadata row count overflow")?;
    let observed_rows: usize = capture
        .observations()
        .iter()
        .find(|observation| observation.phase() == ObservationPhase::Accepted)
        .map(disrobe_pass_dotnet::Observation::items)
        .ok_or("missing accepted table-stream observation")?;
    assert_eq!(observed_rows, expected_rows);
    assert!(expected_rows > stream.row_counts.len());
    Ok(())
}
