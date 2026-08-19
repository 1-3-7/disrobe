#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
mod common;

use std::time::{Duration, Instant};

use common::{CRYSTAL_PE, D_PE, NIM_ELF, ZIG_ELF, fixture_or_fail};
use disrobe_pass_nativelang::{
    BodyRecovery, BodySkip, BodyStatus, FunctionOrigin, MAX_BODY_CARVE_BYTES, MAX_BODY_CODE_BYTES,
    MAX_BODY_FUNCTIONS, MAX_RETAINED_SOURCE_BYTES, NativeImage, NativeLang, NativeLangAnalysis,
    RecoveredFunction, RustBody, Section, analyze, recover_bodies,
};

const OVERFLOW: usize = 512;
const HOSTILE_WALL_CLOCK: Duration = Duration::from_secs(90);

fn text_extent(image: &NativeImage<'_>) -> (u64, u64) {
    let text: &Section<'_> = image
        .sections
        .iter()
        .find(|section: &&Section<'_>| section.name == ".text")
        .expect("the graded fixture maps a .text section");
    (text.address, text.data.len() as u64)
}

fn synthesised(start: u64, len: u64, index: usize) -> RecoveredFunction {
    RecoveredFunction {
        name: format!("crafted_{index:05}"),
        demangled: None,
        signature: None,
        start,
        end: Some(start.saturating_add(len)),
        source_lines: None,
        params: Vec::new(),
        origin: FunctionOrigin::SymbolTable,
        address_assigned: true,
    }
}

fn emitted_bytes(recovery: &BodyRecovery) -> u64 {
    recovery
        .bodies
        .iter()
        .map(|body| match &body.status {
            BodyStatus::Recovered {
                pseudo_c,
                pseudo_rust,
            } => {
                let rust: u64 = match pseudo_rust {
                    RustBody::Emitted(text) => text.len() as u64,
                    RustBody::NotEmitted | RustBody::Rejected(_) => 0,
                };
                pseudo_c.len() as u64 + rust
            }
            BodyStatus::RecoveredElided { .. }
            | BodyStatus::Rejected { .. }
            | BodyStatus::NotAttempted { .. } => 0,
        })
        .sum()
}

fn drive(functions: &[RecoveredFunction], bytes: &[u8]) -> (BodyRecovery, Duration) {
    let image: NativeImage<'_> = NativeImage::parse(bytes).expect("the fixture must parse");
    let start: Instant = Instant::now();
    let recovery: BodyRecovery = recover_bodies(&image, NativeLang::Zig, functions);
    (recovery, start.elapsed())
}

#[test]
fn a_function_list_at_the_budget_is_bounded_in_retained_bytes_and_wall_clock() {
    let bytes: Vec<u8> = fixture_or_fail(ZIG_ELF);
    let (base, span): (u64, u64) = {
        let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse");
        text_extent(&image)
    };
    let declared: usize = MAX_BODY_FUNCTIONS + OVERFLOW;
    let stride: u64 = 64;
    assert!(
        span >= stride * declared as u64,
        "the graded .text spans {span} bytes, too small to lay {declared} functions at {stride}"
    );
    let functions: Vec<RecoveredFunction> = (0..declared)
        .map(|index: usize| synthesised(base + stride * index as u64, stride, index))
        .collect();

    let (recovery, elapsed): (BodyRecovery, Duration) = drive(&functions, &bytes);

    assert_eq!(recovery.function_count as usize, declared);
    let total: u32 =
        recovery.recovered + recovery.recovered_elided + recovery.rejected + recovery.not_attempted;
    assert_eq!(
        total, recovery.function_count,
        "every function at the budget must still carry exactly one outcome"
    );
    let exhausted: usize = recovery
        .bodies
        .iter()
        .filter(|body| {
            matches!(
                body.status,
                BodyStatus::NotAttempted {
                    reason: BodySkip::FunctionBudgetExhausted
                }
            )
        })
        .count();
    assert_eq!(
        exhausted, OVERFLOW,
        "the {OVERFLOW} functions past the {MAX_BODY_FUNCTIONS} budget must be refused by the \
         budget, not silently lifted"
    );
    assert!(
        recovery.retained_source_bytes <= MAX_RETAINED_SOURCE_BYTES,
        "retained {} bytes of emitted source, above the {MAX_RETAINED_SOURCE_BYTES} ceiling",
        recovery.retained_source_bytes
    );
    assert_eq!(
        emitted_bytes(&recovery),
        recovery.retained_source_bytes,
        "the retained-bytes counter must equal the source actually held"
    );
    println!(
        "at the budget: {declared} declared, {} attempted, {} recovered, {} elided, {} rejected, \
         {} not attempted, {} retained source bytes, {:?} elapsed",
        MAX_BODY_FUNCTIONS,
        recovery.recovered,
        recovery.recovered_elided,
        recovery.rejected,
        recovery.not_attempted,
        recovery.retained_source_bytes,
        elapsed
    );
}

#[test]
fn overlapping_oversized_carves_cannot_grow_the_copy_beyond_the_declared_ceiling() {
    let bytes: Vec<u8> = fixture_or_fail(ZIG_ELF);
    let (base, span): (u64, u64) = {
        let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse");
        text_extent(&image)
    };
    let window: u64 = MAX_BODY_CODE_BYTES.min(span / 2);
    let declared: usize = MAX_BODY_FUNCTIONS + OVERFLOW;
    let functions: Vec<RecoveredFunction> = (0..declared)
        .map(|index: usize| synthesised(base, window, index))
        .collect();

    let (recovery, elapsed): (BodyRecovery, Duration) = drive(&functions, &bytes);

    assert_eq!(recovery.function_count as usize, declared);
    let total: u32 =
        recovery.recovered + recovery.recovered_elided + recovery.rejected + recovery.not_attempted;
    assert_eq!(total, recovery.function_count);
    assert!(
        recovery.retained_source_bytes <= MAX_RETAINED_SOURCE_BYTES,
        "retained {} bytes, above the ceiling",
        recovery.retained_source_bytes
    );

    let attempted: u64 = recovery
        .bodies
        .iter()
        .filter(|body| {
            !matches!(
                body.status,
                BodyStatus::NotAttempted {
                    reason: BodySkip::CodeBudgetExhausted
                        | BodySkip::FunctionBudgetExhausted
                        | BodySkip::OversizedBody
                }
            )
        })
        .map(|body| body.byte_len)
        .sum();
    assert!(
        attempted <= MAX_BODY_CARVE_BYTES,
        "the pass carved {attempted} bytes from a {} byte input, above the \
         {MAX_BODY_CARVE_BYTES} aggregate ceiling; the per-function cap alone lets a crafted \
         symbol table multiply {MAX_BODY_CODE_BYTES} by {MAX_BODY_FUNCTIONS}",
        bytes.len()
    );
    let refused: usize = recovery
        .bodies
        .iter()
        .filter(|body| {
            matches!(
                body.status,
                BodyStatus::NotAttempted {
                    reason: BodySkip::CodeBudgetExhausted
                }
            )
        })
        .count();
    assert!(
        refused > 0,
        "a crafted list of {declared} carves over the same window must exhaust the aggregate \
         budget, refusing the remainder with a named reason"
    );
    assert!(
        elapsed < HOSTILE_WALL_CLOCK,
        "{declared} overlapping {window}-byte carves took {elapsed:?}, above the \
         {HOSTILE_WALL_CLOCK:?} bound"
    );
    println!(
        "{declared} carves all covering the same {window}-byte window: {} attempted carve bytes, \
         {refused} refused by the aggregate budget, {} rejected, {:?} elapsed",
        attempted, recovery.rejected, elapsed
    );
}

#[test]
fn no_committed_fixture_is_clipped_by_the_aggregate_carve_budget() {
    for relative in [ZIG_ELF, NIM_ELF, CRYSTAL_PE, D_PE] {
        let bytes: Vec<u8> = fixture_or_fail(relative);
        let analysis: NativeLangAnalysis = analyze(&bytes).expect("analyze a committed fixture");
        let clipped: usize = analysis
            .bodies
            .bodies
            .iter()
            .filter(|body| {
                matches!(
                    body.status,
                    BodyStatus::NotAttempted {
                        reason: BodySkip::CodeBudgetExhausted
                    }
                )
            })
            .count();
        let attempted: u64 = analysis
            .bodies
            .bodies
            .iter()
            .filter(|body| !matches!(body.status, BodyStatus::NotAttempted { .. }))
            .map(|body| body.byte_len)
            .sum();
        assert_eq!(
            clipped, 0,
            "{relative} carves {attempted} bytes and must sit under the \
             {MAX_BODY_CARVE_BYTES} aggregate ceiling; the ceiling exists for crafted input, not \
             for real builds"
        );
        println!("{relative}: {attempted} attempted carve bytes, {clipped} clipped");
    }
}
