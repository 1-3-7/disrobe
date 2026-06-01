#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_path, write_bytes};
use disrobe_core::progress::{CapturingProgress, Progress, ProgressEvent};

#[test]
fn progress_trait_fires_under_simulated_pipeline() {
    let p: CapturingProgress = CapturingProgress::new();
    p.set_total(3);
    p.set_message("starting");
    for i in 0..3u64 {
        p.set_pos(i + 1);
        p.tick();
    }
    p.finish("done");
    let snap: Vec<ProgressEvent> = p.snapshot();
    assert!(
        !snap.is_empty(),
        "progress events MUST be recorded; got empty snapshot"
    );
    assert!(
        snap.len() >= 5,
        "expected at least set_total + set_message + 3 ticks; got {} events",
        snap.len()
    );
    assert_eq!(snap[0], ProgressEvent::SetTotal(3));
    let tick_count: usize = snap
        .iter()
        .filter(|e| matches!(e, ProgressEvent::Tick))
        .count();
    assert_eq!(tick_count, 3, "expected exactly 3 ticks");
}

#[test]
fn cli_accepts_progress_flag_without_crashing() {
    let src: PathBuf = temp_path("progress-cli", "py");
    write_bytes(&src, b"k = 9\n");
    let r: Run = run_disrobe(&["--progress", "always", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(
        r.code, 0,
        "--progress always must succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
}
