use super::CodeEntry;

mod cli_a;
mod cli_b;
mod misc;
mod python_a;
mod python_b;

pub(super) const CODE_SLICES: &[&[CodeEntry]] = &[
    cli_a::CLI_A,
    cli_b::CLI_B,
    python_a::PYTHON_A,
    python_b::PYTHON_B,
    misc::MISC,
];
