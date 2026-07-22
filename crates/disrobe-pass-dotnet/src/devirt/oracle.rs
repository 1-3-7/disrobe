mod lower;
mod model_ref;

pub use lower::dvir_to_method_body;

use std::collections::{BTreeMap, BTreeSet};

use crate::cil::MethodBody;
use crate::cil_emulator::{
    EmulationError, ExecCapture, StubInput, StubOutput, emulate_capture, validate_stub_body,
};

use super::{
    BinOp, Budget, DvIr, IrInstruction, Reject, SyntheticVmModel, Terminator, ValueId, devirtualize,
};

const MAX_SAMPLES: usize = 16;
const FIXED_SEED: u64 = 0x7a4d_93c1_e26f_b805;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipCause {
    UnsupportedOp,
    I8Arithmetic,
    ReferenceUnavailable,
    OpaqueEffect,
    ModelReferenceUnavailable,
    NonterminatingUnderBudget,
    BranchCoverageUnavailable,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Equivalent { samples: usize },
    Rejected(Reject),
    Skipped(SkipCause),
    Failed(Divergence),
    FailedHalting(HaltingAsymmetry),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirstDiff {
    ReturnValue,
    ArgumentArrayByte {
        argument_index: usize,
        byte_offset: usize,
    },
    ArgumentArrayLength {
        argument_index: usize,
    },
    ArgumentArrayCount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observable {
    pub return_value: StubOutput,
    pub arg_arrays_final: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Divergence {
    pub input: StubInput,
    pub seed: u64,
    pub recovered: Observable,
    pub reference: Observable,
    pub first_diff: FirstDiff,
}

#[derive(Clone, Debug)]
pub struct HaltingAsymmetry {
    pub input: StubInput,
    pub seed: u64,
    pub recovered_exhausted: bool,
    pub model_exhausted: bool,
}

#[derive(Clone, Debug)]
pub struct OracleReport {
    pub outcome: Outcome,
    pub equivalent: u64,
    pub failed: u64,
    pub skipped: u64,
    pub rejected: u64,
}

impl OracleReport {
    #[must_use]
    pub const fn equivalent_rate(&self) -> Option<f64> {
        let compared: u64 = self.equivalent + self.failed;
        if compared == 0 {
            None
        } else {
            Some(self.equivalent as f64 / compared as f64)
        }
    }
}

#[derive(Clone, Debug)]
struct InputCase {
    input: StubInput,
    seed: u64,
}

#[derive(Clone, Debug)]
struct ModelSample {
    case: InputCase,
    run: model_ref::ModelRun,
}

#[derive(Clone, Debug)]
enum ModelSchedule {
    Samples(Vec<ModelSample>),
    Skipped(SkipCause),
}

#[derive(Clone, Copy, Debug)]
enum InputSource {
    Argument(u16),
    Constant(i64),
}

pub fn check_against_reference(
    model: &SyntheticVmModel,
    reference_body: &MethodBody,
    budget: &mut Budget,
) -> OracleReport {
    let ir: DvIr = match devirtualize(model, budget) {
        Ok(value) => value,
        Err(reject) => return rejected_report(reject),
    };
    let recovered_body: MethodBody = dvir_to_method_body(&ir);
    let inputs: Vec<InputCase> = match input_schedule(model, Some(&ir), budget) {
        Ok(value) => value,
        Err(reject) => return rejected_report(reject),
    };
    check_bodies(&recovered_body, reference_body, inputs)
}

pub fn check_against_model(model: &SyntheticVmModel, budget: &mut Budget) -> OracleReport {
    if model_ref::contains_opaque_effect(model) {
        return skipped_report(SkipCause::OpaqueEffect);
    }
    let ir: DvIr = match devirtualize(model, budget) {
        Ok(value) => value,
        Err(reject) => return rejected_report(reject),
    };
    let recovered_body: MethodBody = dvir_to_method_body(&ir);
    check_lowered_against_model(model, &recovered_body, budget)
}

pub fn check_lowered_against_model(
    model: &SyntheticVmModel,
    recovered_body: &MethodBody,
    budget: &mut Budget,
) -> OracleReport {
    if model_ref::contains_opaque_effect(model) {
        return skipped_report(SkipCause::OpaqueEffect);
    }
    let schedule: ModelSchedule = match model_input_schedule(model, budget) {
        Ok(value) => value,
        Err(reject) => return rejected_report(reject),
    };
    let samples: Vec<ModelSample> = match schedule {
        ModelSchedule::Samples(samples) => samples,
        ModelSchedule::Skipped(cause) => return skipped_report(cause),
    };
    check_body_against_model(recovered_body, samples)
}

pub fn check_lowered_against_reference(
    model: &SyntheticVmModel,
    recovered_body: &MethodBody,
    reference_body: &MethodBody,
    budget: &mut Budget,
) -> OracleReport {
    let inputs: Vec<InputCase> = match input_schedule(model, None, budget) {
        Ok(value) => value,
        Err(reject) => return rejected_report(reject),
    };
    check_bodies(recovered_body, reference_body, inputs)
}

fn check_bodies(
    recovered_body: &MethodBody,
    reference_body: &MethodBody,
    inputs: Vec<InputCase>,
) -> OracleReport {
    if requires_i8_arithmetic(recovered_body) || requires_i8_arithmetic(reference_body) {
        return skipped_report(SkipCause::I8Arithmetic);
    }
    if validate_stub_body(recovered_body).is_err() || validate_stub_body(reference_body).is_err() {
        return skipped_report(SkipCause::ReferenceUnavailable);
    }
    let samples: usize = inputs.len();
    let mut first_divergence: Option<Divergence> = None;
    let mut first_skip: Option<SkipCause> = None;
    for case in inputs {
        let recovered_capture: ExecCapture = emulate_capture(recovered_body, &case.input);
        let reference_capture: ExecCapture = emulate_capture(reference_body, &case.input);
        let recovered: Result<Observable, EmulationError> = observable(recovered_capture);
        let reference: Result<Observable, EmulationError> = observable(reference_capture);
        match (recovered, reference) {
            (Ok(recovered), Ok(reference)) => {
                if recovered != reference && first_divergence.is_none() {
                    let first_diff: FirstDiff = first_difference(&recovered, &reference);
                    first_divergence = Some(Divergence {
                        input: case.input,
                        seed: case.seed,
                        recovered,
                        reference,
                        first_diff,
                    });
                }
            }
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => {
                record_skip(&mut first_skip, error);
            }
            (Err(recovered_error), Err(reference_error)) => {
                record_skip(&mut first_skip, recovered_error);
                record_skip(&mut first_skip, reference_error);
            }
        }
    }
    if let Some(cause) = first_skip {
        return skipped_report(cause);
    }
    if let Some(divergence) = first_divergence {
        return failed_report(divergence);
    }
    equivalent_report(samples)
}

fn check_body_against_model(
    recovered_body: &MethodBody,
    samples: Vec<ModelSample>,
) -> OracleReport {
    if validate_stub_body(recovered_body).is_err() {
        return skipped_report(SkipCause::ReferenceUnavailable);
    }
    let sample_count: usize = samples.len();
    let mut first_divergence: Option<Divergence> = None;
    let mut first_skip: Option<SkipCause> = None;
    let mut both_exhausted: bool = false;
    for sample in samples {
        let recovered: Result<Observable, EmulationError> =
            observable(emulate_capture(recovered_body, &sample.case.input));
        match (recovered, sample.run) {
            (Ok(recovered), model_ref::ModelRun::Returned(reference)) => {
                if recovered.return_value != reference.value && first_divergence.is_none() {
                    first_divergence = Some(Divergence {
                        input: sample.case.input,
                        seed: sample.case.seed,
                        recovered,
                        reference: return_observable(reference.value),
                        first_diff: FirstDiff::ReturnValue,
                    });
                }
            }
            (Err(EmulationError::StepLimitExceeded), model_ref::ModelRun::StepLimit) => {
                both_exhausted = true;
            }
            (Err(EmulationError::StepLimitExceeded), model_ref::ModelRun::Returned(_)) => {
                return failed_halting_report(HaltingAsymmetry {
                    input: sample.case.input,
                    seed: sample.case.seed,
                    recovered_exhausted: true,
                    model_exhausted: false,
                });
            }
            (Ok(_), model_ref::ModelRun::StepLimit) => {
                return failed_halting_report(HaltingAsymmetry {
                    input: sample.case.input,
                    seed: sample.case.seed,
                    recovered_exhausted: false,
                    model_exhausted: true,
                });
            }
            (Err(error), model_ref::ModelRun::Returned(_) | model_ref::ModelRun::StepLimit) => {
                record_skip(&mut first_skip, error);
            }
            (_, model_ref::ModelRun::Skipped(cause)) => {
                if first_skip.is_none() {
                    first_skip = Some(cause);
                }
            }
        }
    }
    if let Some(cause) = first_skip {
        return skipped_report(cause);
    }
    if both_exhausted {
        return skipped_report(SkipCause::NonterminatingUnderBudget);
    }
    if let Some(divergence) = first_divergence {
        return failed_report(divergence);
    }
    equivalent_report(sample_count)
}

const fn return_observable(return_value: StubOutput) -> Observable {
    Observable {
        return_value,
        arg_arrays_final: Vec::new(),
    }
}

fn observable(capture: ExecCapture) -> Result<Observable, EmulationError> {
    std::mem::drop(capture.locals_final);
    capture.output.map(|return_value: StubOutput| Observable {
        return_value,
        arg_arrays_final: capture.arg_arrays_final,
    })
}

fn first_difference(recovered: &Observable, reference: &Observable) -> FirstDiff {
    if recovered.return_value != reference.return_value {
        return FirstDiff::ReturnValue;
    }
    for (argument_index, (recovered_array, reference_array)) in recovered
        .arg_arrays_final
        .iter()
        .zip(&reference.arg_arrays_final)
        .enumerate()
    {
        for (byte_offset, (recovered_byte, reference_byte)) in
            recovered_array.iter().zip(reference_array).enumerate()
        {
            if recovered_byte != reference_byte {
                return FirstDiff::ArgumentArrayByte {
                    argument_index,
                    byte_offset,
                };
            }
        }
        if recovered_array.len() != reference_array.len() {
            return FirstDiff::ArgumentArrayLength { argument_index };
        }
    }
    FirstDiff::ArgumentArrayCount
}

fn requires_i8_arithmetic(body: &MethodBody) -> bool {
    body.instructions.iter().any(|instruction| {
        matches!(
            instruction.name.as_str(),
            "ldc.i8" | "conv.i8" | "conv.u8" | "ldelem.i8" | "stelem.i8"
        )
    })
}

fn skip_cause(error: EmulationError) -> SkipCause {
    match error {
        EmulationError::UnsupportedOpcode(_) | EmulationError::ExternalCall => {
            SkipCause::UnsupportedOp
        }
        EmulationError::StackUnderflow
        | EmulationError::BadLocal(_)
        | EmulationError::BadArgument(_)
        | EmulationError::StepLimitExceeded
        | EmulationError::BadShape
        | EmulationError::OutOfBounds
        | EmulationError::DivideByZero
        | EmulationError::NoResult => SkipCause::ReferenceUnavailable,
    }
}

fn record_skip(first_skip: &mut Option<SkipCause>, error: EmulationError) {
    let cause: SkipCause = skip_cause(error);
    if cause == SkipCause::UnsupportedOp || first_skip.is_none() {
        *first_skip = Some(cause);
    }
}

fn input_schedule(
    model: &SyntheticVmModel,
    ir: Option<&DvIr>,
    budget: &mut Budget,
) -> Result<Vec<InputCase>, Reject> {
    let mut inputs: Vec<InputCase> = Vec::new();
    let edge_scalars: [i64; 5] = [0, 1, -1, i64::from(i32::MIN), i64::from(i32::MAX)];
    for scalar in edge_scalars {
        append_input_case(&mut inputs, model, None, scalar, budget)?;
    }
    if let Some(ir) = ir {
        for (argument, scalar) in branch_inversion_values(ir) {
            append_input_case(&mut inputs, model, Some(argument), scalar, budget)?;
        }
    }
    if inputs.is_empty() {
        append_input_case(&mut inputs, model, None, 0, budget)?;
    }
    Ok(inputs)
}

fn model_input_schedule(
    model: &SyntheticVmModel,
    budget: &mut Budget,
) -> Result<ModelSchedule, Reject> {
    let mut inputs: Vec<InputCase> = input_schedule(model, None, budget)?;
    append_argument_separation_case(&mut inputs, model, budget)?;
    append_operator_separating_cases(&mut inputs, model, budget)?;
    append_targeted_edge_cases(&mut inputs, model, budget)?;
    let mut branch_outcomes: BTreeMap<usize, BTreeSet<bool>> = BTreeMap::new();
    let mut samples: Vec<ModelSample> = Vec::with_capacity(inputs.len());
    for case in inputs {
        let run: model_ref::ModelRun = model_ref::run(model, &case.input, budget)?;
        match &run {
            model_ref::ModelRun::Returned(reference) => {
                merge_branch_outcomes(&mut branch_outcomes, &reference.branch_outcomes);
            }
            model_ref::ModelRun::StepLimit => {}
            model_ref::ModelRun::Skipped(cause) => {
                return Ok(ModelSchedule::Skipped(*cause));
            }
        }
        samples.push(ModelSample { case, run });
    }
    if branch_outcomes
        .values()
        .any(|outcomes: &BTreeSet<bool>| outcomes.len() != 2)
    {
        return Ok(ModelSchedule::Skipped(SkipCause::BranchCoverageUnavailable));
    }
    Ok(ModelSchedule::Samples(samples))
}

fn append_argument_separation_case(
    inputs: &mut Vec<InputCase>,
    model: &SyntheticVmModel,
    budget: &mut Budget,
) -> Result<(), Reject> {
    let mut values: Vec<i64> = Vec::with_capacity(usize::from(model.argument_count));
    for argument in 0..usize::from(model.argument_count) {
        let offset: i64 = match i64::try_from(argument) {
            Ok(value) => value,
            Err(_) => {
                return Err(Reject::new(
                    "argument index cannot be represented by the input schedule",
                    Vec::new(),
                ));
            }
        };
        let value: i64 = match i64::from(i32::MIN).checked_add(offset) {
            Some(value) => value,
            None => {
                return Err(Reject::new(
                    "argument-separation input overflows the scalar range",
                    Vec::new(),
                ));
            }
        };
        values.push(value);
    }
    append_input_values(inputs, values, budget)
}

fn append_operator_separating_cases(
    inputs: &mut Vec<InputCase>,
    model: &SyntheticVmModel,
    budget: &mut Budget,
) -> Result<(), Reject> {
    let patterns: [[i64; 2]; 4] = [
        [3, 5],
        [5, 3],
        [i64::from(i32::MIN), 1],
        [i64::from(i32::MAX), -1],
    ];
    for pattern in patterns {
        let mut values: Vec<i64> = Vec::with_capacity(usize::from(model.argument_count));
        for argument in 0..usize::from(model.argument_count) {
            values.push(pattern[argument % pattern.len()]);
        }
        append_input_values(inputs, values, budget)?;
    }
    Ok(())
}

fn append_targeted_edge_cases(
    inputs: &mut Vec<InputCase>,
    model: &SyntheticVmModel,
    budget: &mut Budget,
) -> Result<(), Reject> {
    let edge_scalars: [i64; 5] = [0, 1, -1, i64::from(i32::MIN), i64::from(i32::MAX)];
    for argument in 0..model.argument_count {
        for scalar in edge_scalars {
            let mut values: Vec<i64> = vec![0; usize::from(model.argument_count)];
            if let Some(slot) = values.get_mut(usize::from(argument)) {
                *slot = scalar;
            }
            append_input_values(inputs, values, budget)?;
        }
    }
    Ok(())
}

fn merge_branch_outcomes(
    all_outcomes: &mut BTreeMap<usize, BTreeSet<bool>>,
    sample_outcomes: &BTreeMap<usize, BTreeSet<bool>>,
) {
    for (pc, outcomes) in sample_outcomes {
        all_outcomes
            .entry(*pc)
            .or_default()
            .extend(outcomes.iter().copied());
    }
}

fn append_input_case(
    inputs: &mut Vec<InputCase>,
    model: &SyntheticVmModel,
    targeted_argument: Option<u16>,
    scalar: i64,
    budget: &mut Budget,
) -> Result<(), Reject> {
    if inputs.len() >= MAX_SAMPLES {
        return Ok(());
    }
    let mut int_args: Vec<i64> = match targeted_argument {
        Some(_) => vec![0; usize::from(model.argument_count)],
        None => vec![scalar; usize::from(model.argument_count)],
    };
    if let Some(argument) = targeted_argument
        && let Some(slot) = int_args.get_mut(usize::from(argument))
    {
        *slot = scalar;
    }
    append_input_values(inputs, int_args, budget)
}

fn append_input_values(
    inputs: &mut Vec<InputCase>,
    int_args: Vec<i64>,
    budget: &mut Budget,
) -> Result<(), Reject> {
    if inputs.len() >= MAX_SAMPLES {
        return Ok(());
    }
    budget.spend(1).map_err(Reject::from_budget_error)?;
    let index: u64 = match u64::try_from(inputs.len()) {
        Ok(value) => value,
        Err(_) => {
            return Err(Reject::new(
                "input schedule index is unavailable",
                Vec::new(),
            ));
        }
    };
    let seed: u64 = FIXED_SEED.wrapping_add(index);
    inputs.push(InputCase {
        input: StubInput {
            int_args,
            byte_array_args: seeded_byte_arrays(seed),
            char_array_args: seeded_char_arrays(seed),
        },
        seed,
    });
    Ok(())
}

fn branch_inversion_values(ir: &DvIr) -> Vec<(u16, i64)> {
    let mut sources: BTreeMap<ValueId, InputSource> = BTreeMap::new();
    let mut values: Vec<(u16, i64)> = Vec::new();
    for block in &ir.blocks {
        for instruction in &block.instructions {
            match instruction {
                IrInstruction::LoadArgument { destination, index } => {
                    sources.insert(*destination, InputSource::Argument(*index));
                }
                IrInstruction::Const { destination, value } => {
                    sources.insert(*destination, InputSource::Constant(*value));
                }
                IrInstruction::Binary {
                    destination,
                    op,
                    left,
                    right,
                } if op.is_comparison() && is_branch_condition(block, *destination) => {
                    if let Some((argument, constant, argument_is_left)) =
                        comparison_sources(&sources, *left, *right)
                    {
                        values.extend(inversion_values(*op, argument, constant, argument_is_left));
                    }
                }
                IrInstruction::Binary { .. }
                | IrInstruction::StoreArgument { .. }
                | IrInstruction::LoadLocal { .. }
                | IrInstruction::StoreLocal { .. } => {}
            }
        }
    }
    values
}

fn is_branch_condition(block: &crate::devirt::BasicBlock, destination: ValueId) -> bool {
    matches!(
        &block.terminator,
        Terminator::CondBr { condition, .. } if *condition == destination
    )
}

fn comparison_sources(
    sources: &BTreeMap<ValueId, InputSource>,
    left: ValueId,
    right: ValueId,
) -> Option<(u16, i64, bool)> {
    match (sources.get(&left), sources.get(&right)) {
        (Some(InputSource::Argument(argument)), Some(InputSource::Constant(constant))) => {
            Some((*argument, *constant, true))
        }
        (Some(InputSource::Constant(constant)), Some(InputSource::Argument(argument))) => {
            Some((*argument, *constant, false))
        }
        _ => None,
    }
}

fn inversion_values(
    op: BinOp,
    argument: u16,
    constant: i64,
    argument_is_left: bool,
) -> Vec<(u16, i64)> {
    match op {
        BinOp::Ceq => vec![(argument, constant), (argument, alternate_value(constant))],
        BinOp::Clt if argument_is_left => {
            vec![(argument, constant.saturating_sub(1)), (argument, constant)]
        }
        BinOp::Clt => vec![(argument, constant.saturating_add(1)), (argument, constant)],
        BinOp::Cgt if argument_is_left => {
            vec![(argument, constant.saturating_add(1)), (argument, constant)]
        }
        BinOp::Cgt => vec![(argument, constant.saturating_sub(1)), (argument, constant)],
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor => Vec::new(),
    }
}

const fn alternate_value(value: i64) -> i64 {
    if value == i64::MAX {
        value.saturating_sub(1)
    } else {
        value.saturating_add(1)
    }
}

fn seeded_byte_arrays(seed: u64) -> Vec<Vec<u8>> {
    let mut state: u64 = seed;
    let first: Vec<u8> = (0..8).map(|_| next_byte(&mut state)).collect();
    let second: Vec<u8> = (0..3).map(|_| next_byte(&mut state)).collect();
    vec![first, second]
}

fn seeded_char_arrays(seed: u64) -> Vec<Vec<u16>> {
    let mut state: u64 = seed.rotate_left(17);
    let chars: Vec<u16> = (0..3)
        .map(|_| u16::from_le_bytes([next_byte(&mut state), next_byte(&mut state)]))
        .collect();
    vec![chars]
}

const fn next_byte(state: &mut u64) -> u8 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    state.to_le_bytes()[7]
}

const fn equivalent_report(samples: usize) -> OracleReport {
    OracleReport {
        outcome: Outcome::Equivalent { samples },
        equivalent: 1,
        failed: 0,
        skipped: 0,
        rejected: 0,
    }
}

const fn rejected_report(reject: Reject) -> OracleReport {
    OracleReport {
        outcome: Outcome::Rejected(reject),
        equivalent: 0,
        failed: 0,
        skipped: 0,
        rejected: 1,
    }
}

const fn skipped_report(cause: SkipCause) -> OracleReport {
    OracleReport {
        outcome: Outcome::Skipped(cause),
        equivalent: 0,
        failed: 0,
        skipped: 1,
        rejected: 0,
    }
}

const fn failed_report(divergence: Divergence) -> OracleReport {
    OracleReport {
        outcome: Outcome::Failed(divergence),
        equivalent: 0,
        failed: 1,
        skipped: 0,
        rejected: 0,
    }
}

const fn failed_halting_report(asymmetry: HaltingAsymmetry) -> OracleReport {
    OracleReport {
        outcome: Outcome::FailedHalting(asymmetry),
        equivalent: 0,
        failed: 1,
        skipped: 0,
        rejected: 0,
    }
}
