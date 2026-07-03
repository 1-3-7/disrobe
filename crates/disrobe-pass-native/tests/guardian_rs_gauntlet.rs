#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::{Artifact, Capability, LegacyPass, Rung};
use disrobe_ir::{Envelope, RawPayload, encode_raw};
use disrobe_pass_native::vm_devirt::detect::Bitness;
use disrobe_pass_native::vm_devirt::evaluate;
use disrobe_pass_native::{
    NativePass, NativePassReport, ObfuscatorFamily, ObfuscatorHit, PASS_INPUT_PATH_CAP,
    decode_pass_report, detect_obfuscators, devirtualize_vm,
};

const VIRT: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.virtualized.exe");
const CLEAN: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");

#[test]
fn real_guardian_virtualized_binary_detected() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(VIRT);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::GuardianRs),
        "real guardian-rs-virtualized binary must be detected as GuardianRs (embedded .vm + \
         .byte VM sections); got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_guardian() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::GuardianRs),
        "the clean pre-virtualization baseline has no embedded VM and must NOT flag GuardianRs: \
         {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn virtualized_classify_body_is_a_vm_entry_redirect() {
    let pos: usize = find_subsequence(VIRT, b"PE\0\0").expect("PE header");
    let opt_size: usize = u16::from_le_bytes([VIRT[pos + 20], VIRT[pos + 21]]) as usize;
    let nsec: usize = u16::from_le_bytes([VIRT[pos + 6], VIRT[pos + 7]]) as usize;
    let sec_off: usize = pos + 24 + opt_size;
    let mut names: Vec<String> = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let o: usize = sec_off + i * 40;
        let end: usize = VIRT[o..o + 8]
            .iter()
            .position(|b: &u8| *b == 0)
            .unwrap_or(8);
        names.push(String::from_utf8_lossy(&VIRT[o..o + end]).into_owned());
    }
    assert!(
        names.iter().any(|n: &String| n == ".vm") && names.iter().any(|n: &String| n == ".byte"),
        "guardian-rs embeds both a .vm interpreter section and a .byte bytecode section; got {names:?}"
    );
}

#[test]
fn virtualized_classify_devirtualizes_to_reexecuted_ir() {
    let (report, lifted, _cfg, _semantics): (
        disrobe_pass_native::DevirtReport,
        disrobe_pass_native::LiftedProgram,
        disrobe_pass_native::VmCfg,
        Vec<disrobe_pass_native::HandlerSemantics>,
    ) = devirtualize_vm(VIRT, Bitness::Bits64).expect("guardian-rs devirtualizes");
    assert_eq!(
        report.detection.dispatch_kind,
        disrobe_pass_native::DispatchKind::SwitchJumpTable
    );
    assert!(
        report.residual.contains("guardian-rs static lifter"),
        "{}",
        report.residual
    );
    assert!(
        lifted.unresolved_opcodes.is_empty(),
        "guardian-rs fixture must decode every VM opcode: {:?}",
        lifted.unresolved_opcodes
    );
    assert!(
        report.recovered_listing.contains("mul")
            && report.recovered_listing.contains("push.imm 3")
            && report.recovered_listing.contains("push.imm 90")
            && report.recovered_listing.contains("xor")
            && report.recovered_listing.contains("sub")
            && report.recovered_listing.contains("ret"),
        "{}",
        report.recovered_listing
    );
    let inputs: [i64; 5] = [-31, -1, 0, 7, 1024];
    for input in inputs {
        let recovered: i64 = evaluate(&lifted, &[input], 16)
            .expect("re-execute lifted guardian-rs IR")
            .return_value;
        let expected: i64 = i64::from(expected_classify(input as i32));
        assert_eq!(
            recovered, expected,
            "devirtualized guardian-rs classify({input}) must match the clean source oracle"
        );
    }
}

#[test]
fn clean_baseline_does_not_devirtualize() {
    assert!(
        devirtualize_vm(CLEAN, Bitness::Bits64).is_err(),
        "clean baseline has no GuardianRs .vm/.byte redirect and must not devirtualize"
    );
}

#[test]
fn native_pass_surfaces_guardian_devirtualization_summary() {
    let report: NativePassReport = run_pass(VIRT);
    let vm: &disrobe_pass_native::pass::VmDevirtSummary = report
        .vm_devirt
        .as_ref()
        .expect("pass surfaces guardian VM summary");
    assert_eq!(vm.dispatch_kind, "SwitchJumpTable");
    assert!(vm.recovered_listing.contains("push.imm 90"));
    assert!(vm.recovered_listing.contains("ret"));
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

const fn expected_classify(n: i32) -> i32 {
    let r: i32 = n.wrapping_add(1).wrapping_mul(3) ^ 0x5a;
    r.wrapping_sub(n)
}

fn run_pass(bytes: &[u8]) -> NativePassReport {
    let raw: RawPayload = RawPayload {
        source_path: "sample.virtualized.exe".to_owned(),
        source_bytes: bytes.to_vec(),
        source_hash: blake3::hash(bytes).into(),
        detected_format: Some("native".to_owned()),
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
    let envelope: Vec<u8> = Envelope::new(Rung::Raw, hot, vec![])
        .encode()
        .expect("encode envelope");
    let input: Artifact = Artifact::with_capabilities(
        Rung::Raw,
        envelope,
        [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
        [0u8; 32],
    );
    let out: Artifact = NativePass.run(&input).expect("native pass run");
    decode_pass_report(&out.envelope).expect("decode native pass report")
}
