#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_cextract::test_support::{active_buffer_addr, reconfigure_then_count};

#[test]
fn active_buffer_is_leaked_exactly_once() {
    let first: usize = active_buffer_addr();
    for _ in 0..10_000usize {
        assert_eq!(
            active_buffer_addr(),
            first,
            "active_buffer must return the same singleton across calls (no per-call leak)"
        );
    }
}

#[test]
fn reconfigure_resets_capture_state_each_cycle() {
    for cycle in 0..5_000usize {
        let tag: u8 = u8::try_from(cycle % 256).map_or(0, |value: u8| value);
        let count: usize = reconfigure_then_count(
            PathBuf::from(format!("/tmp/disrobe_cycle_{cycle}")),
            format!("stem_{cycle}"),
            [b'C', b'Y', b'C', tag],
        )
        .expect("reconfigure + count succeed");
        assert_eq!(
            count, 0,
            "cycle {cycle}: captured state must be cleared on reconfigure"
        );
    }
}
