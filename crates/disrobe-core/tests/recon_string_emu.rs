#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_core::recon::string_emu::{
    ArgumentError, ArgumentRegister, ArgumentSlot, CallConvention, CallSiteState, DecodedString,
    EmulationBound, EmulationBudget, EmulationLimits, MemoryDelta, RunLimits, SandboxWindow,
    StringEncoding, argument_slot, extract_arguments, harvest_memory_delta, text_runs,
};

const C2: &str = "http://evil.example/c2";
const RAW_NON_UTF8: &[u8] = &[0x80, 0xFF, 0xFE, 0x41, 0x42, 0x43, 0x44, 0x90, 0x81];

const fn tiny_limits() -> EmulationLimits {
    EmulationLimits {
        steps: 8,
        wall_clock: Duration::from_millis(50),
        delta_bytes: 32,
        decoder_calls: 3,
    }
}

const fn roomy_limits() -> EmulationLimits {
    EmulationLimits {
        steps: 1_000_000,
        wall_clock: Duration::from_secs(30),
        delta_bytes: 1 << 20,
        decoder_calls: 1024,
    }
}

fn log_from(base: u64, bytes: &[u8]) -> Vec<(u64, u8)> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| (base.wrapping_add(i as u64), *b))
        .collect()
}

fn utf16be(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn utf32le(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for ch in text.chars() {
        out.extend_from_slice(&u32::from(ch).to_le_bytes());
    }
    out
}

fn utf32be(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for ch in text.chars() {
        out.extend_from_slice(&u32::from(ch).to_be_bytes());
    }
    out
}

fn window_over(base: u64, len: u64) -> SandboxWindow {
    let mut window: SandboxWindow = SandboxWindow::default();
    window.allow(base, len).expect("region within ceiling");
    window
}

#[test]
fn the_step_bound_is_named_and_no_other_bound_is_blamed() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(tiny_limits(), started);
    for _ in 0..8u32 {
        budget.tick(1, started).expect("within the step budget");
    }
    let hit: EmulationBound = budget
        .tick(1, started)
        .expect_err("the ninth step must exceed a budget of eight");
    assert_eq!(
        hit,
        EmulationBound::Steps,
        "the step budget must blame the step bound, not another limit"
    );
    assert_eq!(budget.bound_hit(), Some(EmulationBound::Steps));
    assert_eq!(budget.steps_remaining(), 0);
}

#[test]
fn the_wall_clock_bound_is_named_without_sleeping() {
    let started: Instant = Instant::now();
    let limits: EmulationLimits = tiny_limits();
    let mut budget: EmulationBudget = EmulationBudget::new(limits, started);
    budget
        .tick(1, started + Duration::from_millis(49))
        .expect("inside the wall-clock budget");
    let hit: EmulationBound = budget
        .tick(1, started + Duration::from_millis(51))
        .expect_err("a tick past the deadline must fail");
    assert_eq!(
        hit,
        EmulationBound::WallClock,
        "an expired deadline must blame the wall-clock bound, not the step bound"
    );
    assert_eq!(budget.bound_hit(), Some(EmulationBound::WallClock));
    assert!(
        budget.steps_remaining() > 0,
        "the step budget must still have room, proving the clock stopped the run"
    );
}

#[test]
fn the_per_decoder_call_bound_is_named() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(tiny_limits(), started);
    for _ in 0..3u32 {
        budget.enter_decoder().expect("within the call budget");
    }
    let hit: EmulationBound = budget
        .enter_decoder()
        .expect_err("the fourth decoder call must exceed a budget of three");
    assert_eq!(
        hit,
        EmulationBound::DecoderCalls,
        "an over-called decoder must blame the decoder-call bound"
    );
    assert_eq!(budget.decoder_calls_remaining(), 0);
    assert!(
        budget.steps_remaining() > 0,
        "the step budget must be untouched by a decoder-call refusal"
    );
}

#[test]
fn the_memory_delta_byte_bound_is_named_and_truncates_the_harvest() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(tiny_limits(), started);
    let payload: Vec<u8> = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL".to_vec();
    let base: u64 = 0x2000;
    let delta: MemoryDelta = harvest_memory_delta(
        &log_from(base, &payload),
        &window_over(base, payload.len() as u64),
        &mut budget,
        started,
    );
    assert_eq!(
        delta.bound,
        Some(EmulationBound::DeltaBytes),
        "a {}-byte write log against a 32-byte delta budget must blame the delta bound",
        payload.len()
    );
    assert!(
        delta.bytes_recorded <= 32,
        "the harvest must stop at the delta budget, recorded {}",
        delta.bytes_recorded
    );
    let harvested: usize = delta
        .strings
        .iter()
        .map(|s: &DecodedString| s.bytes.len())
        .sum();
    assert!(
        harvested <= 32,
        "harvested bytes must not exceed the delta budget: {harvested}"
    );
}

#[test]
fn an_out_of_sandbox_write_is_recorded_and_never_allocates_host_memory() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let base: u64 = 0x4000;
    let inside: Vec<(u64, u8)> = log_from(base, C2.as_bytes());
    let mut log: Vec<(u64, u8)> = inside.clone();
    log.extend_from_slice(&log_from(u64::MAX - 3, b"WXYZ"));
    log.extend_from_slice(&log_from(0, b"NULLPAGE"));
    log.push((u64::MAX, b'!'));
    log.push((0x8000_0000_0000_0000, b'@'));

    let begin: Instant = Instant::now();
    let delta: MemoryDelta = harvest_memory_delta(
        &log,
        &window_over(base, C2.len() as u64),
        &mut budget,
        started,
    );
    let elapsed: Duration = begin.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "a write log straddling the whole address space must be rejected immediately, took {elapsed:?}"
    );
    assert_eq!(
        delta.writes_outside_sandbox,
        (log.len() - inside.len()) as u64,
        "every write outside the mapped window must be counted, not silently dropped"
    );
    let values: Vec<&str> = delta
        .strings
        .iter()
        .filter_map(|s: &DecodedString| s.text.as_deref())
        .collect();
    assert!(
        values.contains(&C2),
        "the in-sandbox string must still be recovered: {values:?}"
    );
    for recovered in &delta.strings {
        assert!(
            recovered.address >= base && recovered.address < base + C2.len() as u64,
            "no harvested string may originate outside the mapped window: {recovered:?}"
        );
    }
    assert!(
        !values
            .iter()
            .any(|v: &&str| v.contains("WXYZ") || v.contains("NULLPAGE")),
        "out-of-bounds emulated writes must not reach the harvest: {values:?}"
    );
}

#[test]
fn a_wrapped_span_between_two_mapped_ends_cannot_be_read_as_one_run() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let mut window: SandboxWindow = SandboxWindow::default();
    window.allow(0, 8).expect("low region");
    window.allow(u64::MAX - 7, 8).expect("high region");
    let mut log: Vec<(u64, u8)> = log_from(u64::MAX - 7, b"TAILTAIL");
    log.extend_from_slice(&log_from(0, b"HEADHEAD"));

    let begin: Instant = Instant::now();
    let delta: MemoryDelta = harvest_memory_delta(&log, &window, &mut budget, started);
    assert!(
        begin.elapsed() < Duration::from_millis(500),
        "a wrapped address span must never drive a host allocation"
    );
    for recovered in &delta.strings {
        assert!(
            recovered.bytes.len() <= 8,
            "a run must never be joined across the address-space wrap: {recovered:?}"
        );
    }
}

#[test]
fn a_utf16be_delta_recovers_the_known_original_with_its_encoding() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let encoded: Vec<u8> = utf16be(C2);
    let base: u64 = 0x3000;
    let delta: MemoryDelta = harvest_memory_delta(
        &log_from(base, &encoded),
        &window_over(base, encoded.len() as u64),
        &mut budget,
        started,
    );
    let hit: &DecodedString = delta
        .strings
        .iter()
        .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .unwrap_or_else(|| panic!("utf-16be original not recovered: {:?}", delta.strings));
    assert_eq!(
        hit.encoding,
        StringEncoding::Utf16Be,
        "a big-endian run must record big-endian, not little-endian"
    );
    assert_eq!(hit.address, base);
    assert_eq!(
        hit.bytes, encoded,
        "the on-the-wire bytes must survive alongside the decoded text"
    );
}

#[test]
fn a_utf16le_delta_records_little_endian_and_not_big_endian() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let encoded: Vec<u8> = utf16le(C2);
    let base: u64 = 0x3000;
    let delta: MemoryDelta = harvest_memory_delta(
        &log_from(base, &encoded),
        &window_over(base, encoded.len() as u64),
        &mut budget,
        started,
    );
    let hit: &DecodedString = delta
        .strings
        .iter()
        .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .unwrap_or_else(|| panic!("utf-16le original not recovered: {:?}", delta.strings));
    assert_eq!(hit.encoding, StringEncoding::Utf16Le);
}

#[test]
fn utf32_runs_in_both_endiannesses_record_their_encoding() {
    for (encoded, expected) in [
        (utf32le(C2), StringEncoding::Utf32Le),
        (utf32be(C2), StringEncoding::Utf32Be),
    ] {
        let runs: Vec<DecodedString> = text_runs(&encoded, 0, expected, &RunLimits::default());
        let hit: &DecodedString = runs
            .iter()
            .find(|s: &&DecodedString| s.text.as_deref() == Some(C2))
            .unwrap_or_else(|| panic!("{expected:?} original not recovered: {runs:?}"));
        assert_eq!(hit.encoding, expected);
        assert_eq!(hit.address, 0);
    }
}

#[test]
fn a_wide_run_is_not_recovered_by_the_opposite_endianness() {
    let encoded: Vec<u8> = utf16be(C2);
    let wrong: Vec<DecodedString> =
        text_runs(&encoded, 0, StringEncoding::Utf16Le, &RunLimits::default());
    assert!(
        !wrong
            .iter()
            .any(|s: &DecodedString| s.text.as_deref() == Some(C2)),
        "a big-endian buffer must not decode as little-endian: {wrong:?}"
    );
}

#[test]
fn non_utf8_results_survive_as_bytes_and_are_never_lossily_converted() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let base: u64 = 0x5000;
    let delta: MemoryDelta = harvest_memory_delta(
        &log_from(base, RAW_NON_UTF8),
        &window_over(base, RAW_NON_UTF8.len() as u64),
        &mut budget,
        started,
    );
    let raw_hit: &DecodedString = delta
        .strings
        .iter()
        .find(|s: &&DecodedString| s.encoding == StringEncoding::Bytes)
        .unwrap_or_else(|| panic!("non-utf-8 bytes were dropped: {:?}", delta.strings));
    assert_eq!(
        raw_hit.bytes, RAW_NON_UTF8,
        "the exact emulated bytes must survive without substitution"
    );
    assert_eq!(
        raw_hit.text, None,
        "undecodable bytes must not carry a lossily converted text form"
    );
    for recovered in &delta.strings {
        assert!(
            !recovered
                .text
                .as_deref()
                .is_some_and(|t: &str| t.contains('\u{FFFD}')),
            "no harvested string may contain a replacement character: {recovered:?}"
        );
    }
}

#[test]
fn deduplication_is_by_value_and_offset_together() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let base: u64 = 0x6000;
    let far: u64 = 0x6100;
    let mut log: Vec<(u64, u8)> = log_from(base, C2.as_bytes());
    log.extend_from_slice(&log_from(base, C2.as_bytes()));
    log.extend_from_slice(&log_from(far, C2.as_bytes()));
    let mut window: SandboxWindow = SandboxWindow::default();
    window.allow(base, 0x400).expect("region within ceiling");

    let delta: MemoryDelta = harvest_memory_delta(&log, &window, &mut budget, started);
    let addresses: Vec<u64> = delta
        .strings
        .iter()
        .filter(|s: &&DecodedString| s.text.as_deref() == Some(C2))
        .map(|s: &DecodedString| s.address)
        .collect();
    assert_eq!(
        addresses,
        vec![base, far],
        "the same value at two offsets is two findings and at one offset is one: {:?}",
        delta.strings
    );
}

#[test]
fn a_transient_string_overwritten_in_place_is_still_harvested() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let base: u64 = 0x7000;
    let first: &[u8] = b"stage-one-key-material";
    let second: &[u8] = b"stage-two-payload-text";
    let mut log: Vec<(u64, u8)> = log_from(base, first);
    log.extend_from_slice(&log_from(base, second));

    let delta: MemoryDelta =
        harvest_memory_delta(&log, &window_over(base, 0x100), &mut budget, started);
    let values: Vec<&str> = delta
        .strings
        .iter()
        .filter_map(|s: &DecodedString| s.text.as_deref())
        .collect();
    assert!(
        values.contains(&"stage-one-key-material"),
        "a string overwritten in place must still be harvested: {values:?}"
    );
    assert!(
        values.contains(&"stage-two-payload-text"),
        "the surviving string must also be harvested: {values:?}"
    );
}

#[test]
fn a_truncated_write_log_still_yields_the_strings_that_are_present() {
    let started: Instant = Instant::now();
    let mut budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let base: u64 = 0x8000;
    let full: Vec<(u64, u8)> = log_from(base, b"https://short.example/beacon-path-truncated-here");
    let cut: &[(u64, u8)] = &full[..20];
    let delta: MemoryDelta =
        harvest_memory_delta(cut, &window_over(base, 0x100), &mut budget, started);
    let values: Vec<&str> = delta
        .strings
        .iter()
        .filter_map(|s: &DecodedString| s.text.as_deref())
        .collect();
    assert!(
        values.iter().any(|v: &&str| v.starts_with("https://short")),
        "a truncated log must still yield the prefix present: {values:?}"
    );
}

#[test]
fn two_harvests_of_the_same_log_are_identical() {
    let started: Instant = Instant::now();
    let base: u64 = 0x9000;
    let mut log: Vec<(u64, u8)> = log_from(base, C2.as_bytes());
    log.extend_from_slice(&log_from(base + 0x40, &utf16be("wss://beacon.example/ws")));
    log.extend_from_slice(&log_from(base + 0x90, &[0x80, 0x81, 0x82, 0x83, 0x84]));
    let window: SandboxWindow = window_over(base, 0x200);

    let mut first_budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let first: MemoryDelta = harvest_memory_delta(&log, &window, &mut first_budget, started);
    let mut second_budget: EmulationBudget = EmulationBudget::new(roomy_limits(), started);
    let second: MemoryDelta = harvest_memory_delta(&log, &window, &mut second_budget, started);
    assert_eq!(
        first.strings, second.strings,
        "two runs over the same write log must be byte-identical"
    );
}

#[test]
fn the_wall_clock_bound_stops_a_harvest() {
    let started: Instant = Instant::now();
    let limits: EmulationLimits = roomy_limits();
    let mut budget: EmulationBudget = EmulationBudget::new(limits, started);
    let base: u64 = 0xA000;
    let delta: MemoryDelta = harvest_memory_delta(
        &log_from(base, C2.as_bytes()),
        &window_over(base, 0x100),
        &mut budget,
        started + limits.wall_clock + Duration::from_millis(1),
    );
    assert_eq!(
        delta.bound,
        Some(EmulationBound::WallClock),
        "a harvest started past its deadline must blame the wall-clock bound"
    );
}

#[test]
fn sysv64_arguments_follow_the_published_register_order() {
    let expected: [ArgumentRegister; 6] = [
        ArgumentRegister::Rdi,
        ArgumentRegister::Rsi,
        ArgumentRegister::Rdx,
        ArgumentRegister::Rcx,
        ArgumentRegister::R8,
        ArgumentRegister::R9,
    ];
    for (index, register) in expected.iter().enumerate() {
        assert_eq!(
            argument_slot(CallConvention::SysV64, index).expect("register slot"),
            ArgumentSlot::Register(*register),
            "System V AMD64 integer argument {index} is {register:?}"
        );
    }
    assert_eq!(
        argument_slot(CallConvention::SysV64, 6).expect("stack slot"),
        ArgumentSlot::Stack { offset: 8 },
        "the seventh System V argument sits just above the return address"
    );
}

#[test]
fn win64_arguments_use_four_registers_then_the_slot_above_the_shadow_space() {
    let expected: [ArgumentRegister; 4] = [
        ArgumentRegister::Rcx,
        ArgumentRegister::Rdx,
        ArgumentRegister::R8,
        ArgumentRegister::R9,
    ];
    for (index, register) in expected.iter().enumerate() {
        assert_eq!(
            argument_slot(CallConvention::Win64, index).expect("register slot"),
            ArgumentSlot::Register(*register)
        );
    }
    assert_eq!(
        argument_slot(CallConvention::Win64, 4).expect("stack slot"),
        ArgumentSlot::Stack { offset: 0x28 },
        "the fifth Microsoft x64 argument sits above the return address and 32-byte shadow space"
    );
    assert_eq!(
        argument_slot(CallConvention::Win64, 5).expect("stack slot"),
        ArgumentSlot::Stack { offset: 0x30 }
    );
}

#[test]
fn aapcs64_arguments_use_x0_through_x7_then_the_stack_at_zero() {
    let expected: [ArgumentRegister; 8] = [
        ArgumentRegister::X0,
        ArgumentRegister::X1,
        ArgumentRegister::X2,
        ArgumentRegister::X3,
        ArgumentRegister::X4,
        ArgumentRegister::X5,
        ArgumentRegister::X6,
        ArgumentRegister::X7,
    ];
    for (index, register) in expected.iter().enumerate() {
        assert_eq!(
            argument_slot(CallConvention::Aapcs64, index).expect("register slot"),
            ArgumentSlot::Register(*register)
        );
    }
    assert_eq!(
        argument_slot(CallConvention::Aapcs64, 8).expect("stack slot"),
        ArgumentSlot::Stack { offset: 0 },
        "AAPCS64 keeps the return address in x30, so stack arguments start at the stack pointer"
    );
}

#[test]
fn the_32_bit_conventions_match_their_published_slots() {
    assert_eq!(
        argument_slot(CallConvention::Cdecl32, 0).expect("stack slot"),
        ArgumentSlot::Stack { offset: 4 }
    );
    assert_eq!(
        argument_slot(CallConvention::Cdecl32, 1).expect("stack slot"),
        ArgumentSlot::Stack { offset: 8 }
    );
    assert_eq!(
        argument_slot(CallConvention::Stdcall32, 0).expect("stack slot"),
        ArgumentSlot::Stack { offset: 4 }
    );
    assert_eq!(
        argument_slot(CallConvention::Fastcall32, 0).expect("register slot"),
        ArgumentSlot::Register(ArgumentRegister::Ecx)
    );
    assert_eq!(
        argument_slot(CallConvention::Fastcall32, 1).expect("register slot"),
        ArgumentSlot::Register(ArgumentRegister::Edx)
    );
    assert_eq!(
        argument_slot(CallConvention::Fastcall32, 2).expect("stack slot"),
        ArgumentSlot::Stack { offset: 4 }
    );
    assert_eq!(
        argument_slot(CallConvention::Thiscall32, 0).expect("register slot"),
        ArgumentSlot::Register(ArgumentRegister::Ecx),
        "the MSVC thiscall receiver arrives in ecx"
    );
    assert_eq!(
        argument_slot(CallConvention::Thiscall32, 1).expect("stack slot"),
        ArgumentSlot::Stack { offset: 4 }
    );
    assert!(
        CallConvention::Stdcall32.callee_cleans_stack(),
        "stdcall is callee-cleaned"
    );
    assert!(
        !CallConvention::Cdecl32.callee_cleans_stack(),
        "cdecl is caller-cleaned"
    );
}

#[test]
fn extraction_reads_the_convention_it_is_given_and_not_a_guess() {
    let mut stack: Vec<u8> = Vec::new();
    stack.extend_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
    stack.extend_from_slice(&0x1111_1111_u64.to_le_bytes());
    stack.extend_from_slice(&0x2222_2222_u64.to_le_bytes());
    stack.extend_from_slice(&0x3333_3333_u64.to_le_bytes());
    stack.extend_from_slice(&0x4444_4444_u64.to_le_bytes());
    stack.extend_from_slice(&0x5555_5555_u64.to_le_bytes());
    stack.extend_from_slice(&0x6666_6666_u64.to_le_bytes());

    let mut state: CallSiteState = CallSiteState::new(0x1000, stack);
    state.set_register(ArgumentRegister::Rdi, 0xA0);
    state.set_register(ArgumentRegister::Rsi, 0xA1);
    state.set_register(ArgumentRegister::Rdx, 0xA2);
    state.set_register(ArgumentRegister::Rcx, 0xA3);
    state.set_register(ArgumentRegister::R8, 0xA4);
    state.set_register(ArgumentRegister::R9, 0xA5);

    let sysv: Vec<u64> =
        extract_arguments(&state, CallConvention::SysV64, 7).expect("seven System V arguments");
    assert_eq!(
        sysv,
        vec![0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x1111_1111],
        "System V takes rdi first and reads its seventh argument at sp+8"
    );

    let win: Vec<u64> =
        extract_arguments(&state, CallConvention::Win64, 5).expect("five Microsoft arguments");
    assert_eq!(
        win,
        vec![0xA3, 0xA2, 0xA4, 0xA5, 0x5555_5555],
        "Microsoft x64 takes rcx first and reads its fifth argument at sp+0x28"
    );
}

#[test]
fn a_stack_argument_beyond_the_captured_image_is_rejected_by_name() {
    let state: CallSiteState = CallSiteState::new(0x1000, vec![0u8; 16]);
    let err: ArgumentError = extract_arguments(&state, CallConvention::Cdecl32, 8)
        .expect_err("a short stack image cannot satisfy eight cdecl arguments");
    match err {
        ArgumentError::StackOutOfRange {
            convention,
            index,
            offset,
            available,
        } => {
            assert_eq!(convention, CallConvention::Cdecl32);
            assert_eq!(
                index, 3,
                "the fourth cdecl argument is the first unreadable one"
            );
            assert_eq!(offset, 16);
            assert_eq!(available, 16);
        }
        other => panic!("expected a named stack-range rejection, got {other:?}"),
    }
}

#[test]
fn a_missing_argument_register_is_rejected_rather_than_read_as_zero() {
    let state: CallSiteState = CallSiteState::new(0x1000, vec![0u8; 64]);
    let err: ArgumentError = extract_arguments(&state, CallConvention::SysV64, 1)
        .expect_err("an unseeded register must not be reported as zero");
    match err {
        ArgumentError::MissingRegister {
            convention,
            register,
            index,
        } => {
            assert_eq!(convention, CallConvention::SysV64);
            assert_eq!(register, ArgumentRegister::Rdi);
            assert_eq!(index, 0);
        }
        other => panic!("expected a named missing-register rejection, got {other:?}"),
    }
}

#[test]
fn an_argument_index_past_the_supported_ceiling_is_rejected() {
    let err: ArgumentError = argument_slot(CallConvention::SysV64, 4096)
        .expect_err("a hostile argument index must be refused");
    match err {
        ArgumentError::UnsupportedIndex {
            convention, index, ..
        } => {
            assert_eq!(convention, CallConvention::SysV64);
            assert_eq!(index, 4096);
        }
        other => panic!("expected a named index rejection, got {other:?}"),
    }
}

#[test]
fn a_sandbox_region_that_overflows_the_address_space_is_refused() {
    let mut window: SandboxWindow = SandboxWindow::default();
    window
        .allow(u64::MAX - 4, 16)
        .expect_err("a region wrapping past u64::MAX must be refused");
    assert_eq!(
        window.region_count(),
        0,
        "a refused region must not be recorded"
    );
}
