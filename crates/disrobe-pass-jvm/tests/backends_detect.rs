#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{BackendCapability, detect_available};

#[test]
fn detect_does_not_panic_in_clean_env() {
    let caps: BackendCapability = detect_available();
    let _ = caps.jvm.len();
    let _ = caps.android.len();
}
