use std::cell::Cell;

use disrobe_fuzz::cil_metadata::{self, CilExerciseOutcome};
use disrobe_pass_dotnet::{ObservationPhase, SemanticEntryPoint};

const REAL_CIL: &[u8] = include_bytes!("../../corpus/dotnet/cil/CilProbe.dll");

#[test]
fn fuzz_adapter_calls_the_cil_exercise_once() {
    let calls: Cell<usize> = Cell::new(0);
    let outcome: CilExerciseOutcome = cil_metadata::run_fuzz_input(REAL_CIL, |data: &[u8]| {
        calls.set(calls.get().saturating_add(1));
        cil_metadata::exercise(data)
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(outcome, cil_metadata::exercise(REAL_CIL));
}

#[test]
fn replay_capture_does_not_change_the_cil_outcome()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let replay = cil_metadata::replay(REAL_CIL)?;
    assert_eq!(replay.outcome(), &cil_metadata::exercise(REAL_CIL));
    let accepted_routes: usize = replay
        .observations()
        .iter()
        .filter(|observation| {
            observation.phase() == ObservationPhase::Accepted
                && observation.entry_point() == SemanticEntryPoint::DecompressUint
                && observation.bytes_consumed() > 0
                && observation.items() > 0
        })
        .count();
    assert!(accepted_routes > 0);
    Ok(())
}

#[test]
fn every_in_budget_input_invokes_the_dotnet_lift_once() {
    let inputs: [&[u8]; 3] = [&[], &REAL_CIL[..2], REAL_CIL];
    for input in inputs {
        let calls: Cell<usize> = Cell::new(0);
        let _outcome: CilExerciseOutcome =
            cil_metadata::exercise_with_lift(input, |_data: &[u8]| {
                calls.set(calls.get().saturating_add(1));
                false
            });
        assert_eq!(
            calls.get(),
            1,
            "lift count differed for {} bytes",
            input.len()
        );
    }
}

#[test]
fn cil_outcome_counts_metadata_rows_instead_of_table_kinds()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let pe = disrobe_pass_dotnet::parse(REAL_CIL)?;
    let clr = disrobe_pass_dotnet::parse_clr_header(REAL_CIL, &pe)?;
    let root = disrobe_pass_dotnet::parse_metadata_root(REAL_CIL, &pe, &clr)?;
    let metadata: &[u8] =
        disrobe_pass_dotnet::metadata::metadata_slice(REAL_CIL, &pe, &clr, &root)?;
    let table_header = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or("missing metadata table stream")?;
    let table_stream = disrobe_pass_dotnet::parse_table_stream(metadata, table_header)?;
    let expected_rows: usize = table_stream
        .row_counts
        .values()
        .map(|count: &u32| usize::try_from(*count))
        .collect::<Result<Vec<usize>, _>>()?
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or("metadata row count overflow")?;
    let outcome: CilExerciseOutcome = cil_metadata::exercise(REAL_CIL);
    assert_eq!(outcome.metadata_rows(), expected_rows);
    assert!(expected_rows > table_stream.row_counts.len());
    Ok(())
}

#[test]
fn raw_mutation_checks_preserve_compressed_width_and_instruction_bounds() {
    let compressed = cil_metadata::check_raw_properties(&[0x80, 0x01]);
    assert!(compressed.compressed_width_checked());
    let method = cil_metadata::check_raw_properties(&[0x06, 0x2A]);
    assert!(method.method_instruction_bounds_checked());
}
