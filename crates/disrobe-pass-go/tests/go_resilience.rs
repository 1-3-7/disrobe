#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{Error, analyze};

#[test]
fn rejects_empty_and_tiny_inputs() {
    assert!(matches!(analyze(&[]), Err(Error::InputTooSmall(0))));
    assert!(matches!(analyze(&[0u8; 8]), Err(Error::InputTooSmall(8))));
    assert!(matches!(
        analyze(&[0xffu8; 63]),
        Err(Error::InputTooSmall(63))
    ));
}

#[test]
fn rejects_non_container_64_bytes() {
    let junk: Vec<u8> = vec![0x5au8; 4096];
    assert!(analyze(&junk).is_err());
}

#[test]
fn random_bytes_never_panic() {
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for case in 0..256u32 {
        let len: usize = 64 + (case as usize % 8192);
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            buf.push((state >> 33) as u8);
        }
        let _ = analyze(&buf);
    }
}

#[test]
fn oversized_func_count_does_not_oom_or_panic() {
    let Some(bytes): Option<Vec<u8>> =
        common::fixture_with_patched_pclntab(common::HELLO_NORMAL, |tab: &mut [u8]| {
            tab[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        })
    else {
        return;
    };
    let result = analyze(&bytes);
    assert!(
        result.is_ok(),
        "oversized count must degrade gracefully, not error-storm"
    );
    let funcs: usize = result.unwrap().symbols.funcs.len();
    assert_eq!(
        funcs, 0,
        "oversized func count must be rejected, yielding zero funcs"
    );
}

#[test]
fn all_ones_offset_fields_are_clamped() {
    let Some(bytes): Option<Vec<u8>> =
        common::fixture_with_patched_pclntab(common::HELLO_NORMAL, |tab: &mut [u8]| {
            for slot in tab.iter_mut().skip(8).take(64) {
                *slot = 0xff;
            }
        })
    else {
        return;
    };
    let _ = analyze(&bytes);
}

#[test]
fn near_max_func_count_at_boundary_no_overflow() {
    let Some(bytes): Option<Vec<u8>> =
        common::fixture_with_patched_pclntab(common::HELLO_NORMAL, |tab: &mut [u8]| {
            tab[8..16].copy_from_slice(&(16_u64 * 1024 * 1024 + 1).to_le_bytes());
        })
    else {
        return;
    };
    let funcs: usize = analyze(&bytes).expect("graceful").symbols.funcs.len();
    assert_eq!(
        funcs, 0,
        "count above MAX_PLAUSIBLE_FUNCS must clamp to zero"
    );
}

#[test]
fn corrupt_text_start_does_not_panic() {
    let Some(bytes): Option<Vec<u8>> =
        common::fixture_with_patched_pclntab(common::HELLO_NORMAL, |tab: &mut [u8]| {
            tab[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        })
    else {
        return;
    };
    let _ = analyze(&bytes);
}
