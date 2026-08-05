#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use disrobe_pass_native::packers::section_recovery::{GranuleRecovery, SectionRole};
use disrobe_pass_native::packers::yodas_protector_phase2::{
    ForcedRc4Replay, HashInputSource, StubProgress, YodasProtectorPhase2,
    unpack_yodas_protector_phase2,
};
use packer_fixture::{PackerFixture, load_fixture};

struct PeakTrackingAlloc;

static PEAK_SINGLE_ALLOC: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for PeakTrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size: usize = layout.size();
        let mut observed: usize = PEAK_SINGLE_ALLOC.load(Ordering::Relaxed);
        while size > observed {
            match PEAK_SINGLE_ALLOC.compare_exchange_weak(
                observed,
                size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakTrackingAlloc = PeakTrackingAlloc;

const STUB_WALL_CLOCK_BUDGET: Duration = Duration::from_mins(2);
const STUB_ALLOC_CEILING: usize = 16 * 1024 * 1024;

fn corpus(name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder: "Yoda's Protector",
        family: "yodas_protector",
        name,
    })
}

fn run(packed_n: &str, orig_n: &str) -> Option<(YodasProtectorPhase2, Vec<u8>)> {
    let (packed, orig): (Vec<u8>, Vec<u8>) = (corpus(packed_n)?, corpus(orig_n)?);
    let out: YodasProtectorPhase2 =
        unpack_yodas_protector_phase2(&packed, Some(&orig)).expect("yp phase2 must run");
    Some((out, orig))
}

const CASES: &[(&str, &str, f64)] = &[
    (
        "Clockres.packed.yodasprotector.exe",
        "Clockres.original.exe",
        99.9,
    ),
    (
        "AccessEnum.packed.yodasprotector.exe",
        "AccessEnum.original.exe",
        97.0,
    ),
];

#[test]
fn yp_resource_directory_recovers_in_place_against_real_original() {
    let mut tested: usize = 0;
    for (packed_n, orig_n, rsrc_floor) in CASES {
        let Some((out, _orig)): Option<(YodasProtectorPhase2, Vec<u8>)> = run(packed_n, orig_n)
        else {
            eprintln!("skip {packed_n}: fixture missing");
            continue;
        };
        println!(
            "YP {packed_n}: rsrc={:.2}% content={:?}% mutated={}",
            out.resource_recovery_pct, out.content_recovery_pct, out.content_bytes_mutated_by_stub
        );
        assert!(
            out.resource_recovery_pct >= *rsrc_floor,
            "{packed_n}: Yoda's Protector keeps resources in place; .rsrc must recover >= {rsrc_floor:.1}% byte-identical to the real original, got {:.2}%",
            out.resource_recovery_pct,
        );
        tested += 1;
    }
    assert!(tested > 0, "no Yoda's Protector fixtures present");
}

#[test]
fn yp_int3_sled_is_bypassed_but_content_cipher_stays_walled() {
    let mut tested: usize = 0;
    for (packed_n, orig_n, _f) in CASES {
        let Some((out, _orig)): Option<(YodasProtectorPhase2, Vec<u8>)> = run(packed_n, orig_n)
        else {
            continue;
        };
        println!(
            "YP-WALL {packed_n}: {:?} mutated={}",
            out.stub_progress, out.content_bytes_mutated_by_stub
        );
        assert_eq!(
            out.content_bytes_mutated_by_stub, 0,
            "{packed_n}: the honest claim is that the .text/.rdata/.data RC4 decryptor never runs \
             before the anti-emulation gate; a nonzero mutation count would mean the wall narrative \
             is wrong and must be re-measured, not asserted away",
        );
        match out.stub_progress {
            StubProgress::HaltedInAntiEmulationGuard {
                anti_debug_int3_in_stub,
                int3_gauntlet_cleared,
                apis_resolved,
                content_key_derived,
                content_cipher_invoked,
                hash_inputs,
                static_decrypt_refutation,
                ..
            } => {
                assert!(
                    anti_debug_int3_in_stub >= 8,
                    "{packed_n}: the .yP stub must carry a real INT3 anti-debug gauntlet (>=8 traps); got {anti_debug_int3_in_stub}",
                );
                assert!(
                    int3_gauntlet_cleared,
                    "{packed_n}: the INT3 sled must be bypassed (the emulator must drive past the \
                     0xCC gauntlet into the import-resolution stage), not halt inside it",
                );
                assert!(
                    apis_resolved >= 40,
                    "{packed_n}: past the sled the stub must reach real import resolution; expected \
                     >= 40 emulated GetProcAddress lookups, got {apis_resolved}",
                );
                assert!(
                    content_key_derived,
                    "{packed_n}: the stub must reach CryptDeriveKey (RC4) for the content key",
                );
                assert!(
                    !content_cipher_invoked,
                    "{packed_n}: the content RC4 cipher (CryptDecrypt) must provably NOT run - the \
                     anti-emulation accumulator self-terminates the stub first; a true invocation \
                     would contradict the wall and demand re-measurement",
                );
                assert!(
                    !hash_inputs.is_empty(),
                    "{packed_n}: CryptHashData must be traced before claiming a content-key wall",
                );
                assert!(
                    hash_inputs
                        .iter()
                        .all(|trace| trace.source == HashInputSource::Image),
                    "{packed_n}: this oracle currently proves the seed is image-resident; if a \
                     runtime seed appears, remeasure the wall note instead of asserting the old one",
                );
                assert!(static_decrypt_refutation.rc4_key_derived);
                assert_eq!(static_decrypt_refutation.image_resident_seed_bytes, 31);
                assert!(!static_decrypt_refutation.crypt_decrypt_target_observed);
            }
            StubProgress::ReachedOriginalEntry { oep_rva } => {
                panic!(
                    "{packed_n}: stub_progress reports OEP reached at 0x{oep_rva:x} but content \
                     mutation is 0 - contradictory; investigate before claiming recovery",
                );
            }
        }
        assert!(
            out.wall_note.contains("control-flow wall")
                && out.wall_note.contains("never faked")
                && out.wall_note.contains("INT3 anti-debug sled is bypassed")
                && out.wall_note.contains("SoftICE/NTICE device probe")
                && out.wall_note.contains("PEB->Ldr loader walk")
                && out.wall_note.contains("CryptHashData provenance")
                && out.wall_note.contains("Static RC4 refutation")
                && out.wall_note.contains("image-resident")
                && !out.wall_note.contains("not a static datum"),
            "{packed_n}: the wall must document the measured truth (sled bypassed, SoftICE+PEB \
             gates cleared, cipher gated behind a deeper transfer)",
        );
        tested += 1;
    }
    assert!(tested > 0, "no Yoda's Protector fixtures present");
}

#[test]
fn yp_forced_rc4_replay_with_derived_key_yields_garbage_not_recovery() {
    let mut tested: usize = 0;
    for (packed_n, orig_n, _f) in CASES {
        let Some((out, _orig)): Option<(YodasProtectorPhase2, Vec<u8>)> = run(packed_n, orig_n)
        else {
            continue;
        };
        let replay: &ForcedRc4Replay = out
            .forced_rc4_replay
            .as_ref()
            .expect("the image-resident RC4 key is derived, so a forced replay must be graded");
        println!(
            "YP-REPLAY {packed_n}: key={:02x?} content={:.2}% best={:.2}% ent={:.2}",
            replay.derived_key,
            replay.content_recovery_pct,
            replay.best_section_recovery_pct,
            replay.post_decrypt_mean_entropy
        );
        assert_eq!(
            replay.derived_key.len(),
            16,
            "{packed_n}: the RC4 key is the 16-byte MD5 of the 31 image-resident seed bytes",
        );
        assert!(
            replay.content_recovery_pct < 2.0 && replay.best_section_recovery_pct < 2.0,
            "{packed_n}: replaying the fully-derived RC4 key directly over the carved content \
             sections must NOT recover the original (it yields chance-level ~0.4% because the \
             content is RC4 over a compressed stream, not a flat ciphertext); a high match here \
             would mean the flat-decrypt path is real and the wall is wrong, got content={:.2}% \
             best={:.2}%",
            replay.content_recovery_pct,
            replay.best_section_recovery_pct,
        );
        assert!(
            replay.post_decrypt_mean_entropy > 7.5,
            "{packed_n}: after the forced RC4 decrypt the sections stay near-maximal entropy \
             ({:.2}), confirming no plaintext/structure emerged - the decrypt is honestly refuted, \
             not faked",
            replay.post_decrypt_mean_entropy,
        );
        tested += 1;
    }
    assert!(tested > 0, "no Yoda's Protector fixtures present");
}

#[test]
fn yp_encrypted_content_is_not_falsely_claimed_recovered() {
    let mut tested: usize = 0;
    for (packed_n, orig_n, _f) in CASES {
        let Some((out, _orig)): Option<(YodasProtectorPhase2, Vec<u8>)> = run(packed_n, orig_n)
        else {
            continue;
        };
        let report = out.section_report.as_ref().expect("section report present");
        let text: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".text")
            .expect(".text row present");
        assert_eq!(text.role, SectionRole::Content);
        assert!(
            text.recovery_pct() < 20.0,
            "{packed_n}: .text is stream-encrypted behind the .yP stub; static recovery must stay \
             low and honest (no fabricated decryption), got {:.2}%",
            text.recovery_pct(),
        );
        let rsrc: &GranuleRecovery = report
            .sections
            .iter()
            .find(|s: &&GranuleRecovery| s.name == ".rsrc")
            .expect(".rsrc row present");
        assert!(
            rsrc.recovery_pct() >= 97.0,
            "{packed_n}: .rsrc (in-place resources) must recover, got {:.2}%",
            rsrc.recovery_pct(),
        );
        tested += 1;
    }
    assert!(tested > 0, "no Yoda's Protector fixtures present");
}

#[test]
fn yp_stub_emulation_terminates_under_a_wall_clock_and_allocation_bound() {
    let mut tested: usize = 0;
    for (packed_n, orig_n, _f) in CASES {
        let (Some(packed), Some(orig)): (Option<Vec<u8>>, Option<Vec<u8>>) =
            (corpus(packed_n), corpus(orig_n))
        else {
            continue;
        };
        PEAK_SINGLE_ALLOC.store(0, Ordering::Relaxed);
        let (sender, receiver) = channel::<StubProgress>();
        let worker: thread::JoinHandle<()> = thread::spawn(move || {
            if let Ok(out) = unpack_yodas_protector_phase2(&packed, Some(&orig)) {
                let _ = sender.send(out.stub_progress);
            }
        });
        let progress: StubProgress = match receiver.recv_timeout(STUB_WALL_CLOCK_BUDGET) {
            Ok(progress) => progress,
            Err(RecvTimeoutError::Timeout) => panic!(
                "{packed_n}: the .yP stub emulation did not terminate within {STUB_WALL_CLOCK_BUDGET:?}. \
                 The emulator interprets hostile code, so a change that drives it further can also \
                 drive it into a loop it never leaves; that is a defect, not a slow machine",
            ),
            Err(RecvTimeoutError::Disconnected) => {
                panic!("{packed_n}: the stub emulation ended without reporting progress")
            }
        };
        let peak: usize = PEAK_SINGLE_ALLOC.load(Ordering::Relaxed);
        let _ = worker.join();
        println!("YP-BOUND {packed_n}: {progress:?} peak_single_alloc={peak}");
        assert!(
            peak < STUB_ALLOC_CEILING,
            "{packed_n}: emulating the stub forced a {peak}-byte single allocation, past the \
             {STUB_ALLOC_CEILING}-byte ceiling; a size field inside the sample must never size an \
             allocation directly",
        );
        tested += 1;
    }
    assert!(tested > 0, "no Yoda's Protector fixtures present");
}

#[test]
fn yp_rejects_non_yodas_image() {
    let mut buf: Vec<u8> = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    assert!(unpack_yodas_protector_phase2(&buf, None).is_err());
}
