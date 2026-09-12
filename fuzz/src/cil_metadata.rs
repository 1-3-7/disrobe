use core::fmt;
use core::hint::black_box;

use disrobe_nir_lift::lift_dotnet_pe as lift_pe;
use disrobe_pass_dotnet::{
    Captured, Instruction, MetadataRoot, PeImage, Resolver, capture_observations, decompress_uint,
    disassemble, parse, parse_clr_header, parse_metadata_root, parse_method_body,
    parse_table_stream, read_strings_heap, read_us_heap_strings, without_observations,
};

use crate::over_input_budget;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CilExerciseOutcome {
    over_budget: bool,
    pe_accepted: bool,
    clr_accepted: bool,
    metadata_accepted: bool,
    metadata_rows: usize,
    strings: usize,
    user_strings: usize,
    method_bodies: usize,
    instructions: usize,
    lift_accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawPropertyOutcome {
    compressed_width_checked: bool,
    method_instruction_bounds_checked: bool,
}

impl RawPropertyOutcome {
    #[must_use]
    pub const fn compressed_width_checked(self) -> bool {
        self.compressed_width_checked
    }

    #[must_use]
    pub const fn method_instruction_bounds_checked(self) -> bool {
        self.method_instruction_bounds_checked
    }
}

#[derive(Debug)]
pub struct CilReplay {
    outcome: CilExerciseOutcome,
    capture: Captured<CilExerciseOutcome>,
}

impl CilExerciseOutcome {
    #[must_use]
    pub const fn metadata_rows(&self) -> usize {
        self.metadata_rows
    }
}

impl CilReplay {
    #[must_use]
    pub const fn outcome(&self) -> &CilExerciseOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn observations(&self) -> &[disrobe_pass_dotnet::Observation] {
        self.capture.observations()
    }
}

#[derive(Debug)]
pub enum CilReplayError {
    Capture(disrobe_pass_dotnet::CaptureError),
    OutcomeMismatch,
}

impl fmt::Display for CilReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => write!(formatter, "{error}"),
            Self::OutcomeMismatch => {
                formatter.write_str("recorded and unrecorded CIL exercise outcomes differ")
            }
        }
    }
}

impl std::error::Error for CilReplayError {}

impl From<disrobe_pass_dotnet::CaptureError> for CilReplayError {
    fn from(error: disrobe_pass_dotnet::CaptureError) -> Self {
        Self::Capture(error)
    }
}

fn drive_raw_mutations(data: &[u8]) {
    without_observations(|| {
        let _ = black_box(check_raw_properties(data));
    });
}

#[must_use]
pub fn check_raw_properties(data: &[u8]) -> RawPropertyOutcome {
    let compressed_width_checked: bool = if let Some((_value, width)) = decompress_uint(data) {
        assert!(
            width > 0 && width <= data.len(),
            "a compressed integer reported a width the input cannot hold"
        );
        true
    } else {
        false
    };
    let _ = black_box(disassemble(data));
    let method_instruction_bounds_checked: bool = if let Ok(body) = parse_method_body(data) {
        let instructions: &[Instruction] = &body.instructions;
        for instruction in instructions {
            assert!(
                (instruction.offset as usize) <= data.len(),
                "a decoded method-body instruction sits past the end of the input"
            );
        }
        true
    } else {
        false
    };
    RawPropertyOutcome {
        compressed_width_checked,
        method_instruction_bounds_checked,
    }
}

fn drive_managed_image(data: &[u8]) -> CilExerciseOutcome {
    let Ok(pe): disrobe_pass_dotnet::Result<PeImage> = parse(data) else {
        drive_raw_mutations(data);
        return CilExerciseOutcome::default();
    };
    let Ok(clr) = parse_clr_header(data, &pe) else {
        drive_raw_mutations(data);
        return CilExerciseOutcome {
            pe_accepted: true,
            ..CilExerciseOutcome::default()
        };
    };
    let Ok(root): disrobe_pass_dotnet::Result<MetadataRoot> = parse_metadata_root(data, &pe, &clr)
    else {
        drive_raw_mutations(data);
        return CilExerciseOutcome {
            pe_accepted: true,
            clr_accepted: true,
            ..CilExerciseOutcome::default()
        };
    };
    let Ok(metadata): disrobe_pass_dotnet::Result<&[u8]> =
        disrobe_pass_dotnet::metadata::metadata_slice(data, &pe, &clr, &root)
    else {
        drive_raw_mutations(data);
        return CilExerciseOutcome {
            pe_accepted: true,
            clr_accepted: true,
            metadata_accepted: true,
            ..CilExerciseOutcome::default()
        };
    };
    let metadata_rows: usize = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .and_then(|header| parse_table_stream(metadata, *header).ok())
        .map_or(0, |stream| {
            stream
                .row_counts
                .values()
                .fold(0usize, |total: usize, count: &u32| {
                    total.saturating_add(
                        usize::try_from(*count).map_or(usize::MAX, |value: usize| value),
                    )
                })
        });
    let strings: usize = root
        .streams
        .get("#Strings")
        .map_or(0, |header| read_strings_heap(metadata, *header).len());
    let user_strings: usize = root
        .streams
        .get("#US")
        .map_or(0, |header| read_us_heap_strings(metadata, *header).len());
    let mut method_bodies: usize = 0;
    let mut instructions: usize = 0;
    if let Ok(resolver) = Resolver::build(data, &pe, &clr, &root) {
        for (_token, _name, rva) in resolver.methods_with_bodies() {
            let Ok(method_bytes): disrobe_pass_dotnet::Result<&[u8]> =
                pe.slice_at_rva_to_end(data, rva)
            else {
                continue;
            };
            let Ok(body) = parse_method_body(method_bytes) else {
                continue;
            };
            method_bodies = method_bodies.saturating_add(1);
            instructions = instructions.saturating_add(body.instructions.len());
        }
    }
    CilExerciseOutcome {
        over_budget: false,
        pe_accepted: true,
        clr_accepted: true,
        metadata_accepted: true,
        metadata_rows,
        strings,
        user_strings,
        method_bodies,
        instructions,
        lift_accepted: false,
    }
}

#[must_use]
pub fn exercise(data: &[u8]) -> CilExerciseOutcome {
    exercise_with_lift(data, |input: &[u8]| lift_pe(input).is_ok())
}

#[must_use]
pub fn exercise_with_lift(data: &[u8], lift: impl FnOnce(&[u8]) -> bool) -> CilExerciseOutcome {
    if over_input_budget(data) {
        return CilExerciseOutcome {
            over_budget: true,
            ..CilExerciseOutcome::default()
        };
    }
    let mut outcome: CilExerciseOutcome = drive_managed_image(data);
    outcome.lift_accepted = lift(data);
    outcome
}

pub fn run_fuzz_input<'a, T, F>(data: &'a [u8], exercise_input: F) -> T
where
    F: FnOnce(&'a [u8]) -> T,
{
    exercise_input(data)
}

pub fn replay(data: &[u8]) -> Result<CilReplay, CilReplayError> {
    let outcome: CilExerciseOutcome = exercise(data);
    let capture: Captured<CilExerciseOutcome> = capture_observations(|| exercise(data))?;
    if outcome != *capture.value() {
        return Err(CilReplayError::OutcomeMismatch);
    }
    Ok(CilReplay { outcome, capture })
}

impl crate::seed_reach::ReplayTrace for CilReplay {
    fn observations(&self) -> crate::seed_reach::ReplayObservations<'_> {
        crate::seed_reach::ReplayObservations::Dotnet(self.observations())
    }
}
