use disrobe_py_marshal::{
    ObservationPhase, SemanticSurface, capture_observations, dump_reftable, read_pyc,
};

const REAL_PYC: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyc_zipper/original.pyc.bin");

#[test]
fn real_pyc_distinguishes_parser_owned_semantic_surfaces()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let pyc_capture = capture_observations(|| read_pyc(REAL_PYC))?;
    let parsed = match pyc_capture.value() {
        Ok(value) => value,
        Err(error) => return Err(error.to_string().into()),
    };
    let header_accepted: bool = pyc_capture.observations().iter().any(|observation| {
        observation.surface() == SemanticSurface::PycHeader
            && observation.phase() == ObservationPhase::Accepted
            && observation.bytes_consumed() == parsed.header.header_len()
            && observation.items() == 1
    });
    let marshal_accepted: bool = pyc_capture.observations().iter().any(|observation| {
        observation.surface() == SemanticSurface::MarshalRoot
            && observation.phase() == ObservationPhase::Accepted
            && observation.bytes_consumed() > 0
            && observation.items() == 1
    });
    let reference_table_claimed: bool = pyc_capture
        .observations()
        .iter()
        .any(|observation| observation.surface() == SemanticSurface::ReferenceTable);
    assert!(header_accepted);
    assert!(marshal_accepted);
    assert!(!reference_table_claimed);

    let header_len: usize = parsed.header.header_len();
    let version = parsed.header.version;
    let reference_capture =
        capture_observations(|| dump_reftable(&REAL_PYC[header_len..], version))?;
    assert!(reference_capture.value().is_ok());
    let reference_accepted: bool = reference_capture.observations().iter().any(|observation| {
        observation.surface() == SemanticSurface::ReferenceTable
            && observation.phase() == ObservationPhase::Accepted
            && observation.bytes_consumed() > 0
            && observation.items() > 0
    });
    assert!(reference_accepted);
    Ok(())
}

#[test]
fn valid_pyc_header_is_accepted_before_marshal_rejection()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let header_length: usize = 16;
    let capture = capture_observations(|| read_pyc(&REAL_PYC[..header_length]))?;
    assert!(capture.value().is_err());
    let header_accepted: bool = capture.observations().iter().any(|observation| {
        observation.surface() == SemanticSurface::PycHeader
            && observation.phase() == ObservationPhase::Accepted
            && observation.bytes_consumed() == header_length
            && observation.items() == 1
    });
    let marshal_rejected: bool = capture.observations().iter().any(|observation| {
        observation.surface() == SemanticSurface::MarshalRoot
            && observation.phase() == ObservationPhase::Rejected
    });
    assert!(header_accepted);
    assert!(marshal_rejected);
    Ok(())
}
