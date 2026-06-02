#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

mod common;

use disrobe_pass_dotnet::r2r::R2rReport;

#[test]
#[ignore = "FIXTURE PENDING: real CrossGen2 ReadyToRun image; synth path covered by unit tests"]
fn r2r_real_crossgen2_image() {
    let _: R2rReport = R2rReport {
        present: false,
        header: None,
        crossgen2_native_aot: false,
        composite_image: false,
    };
    panic!("FIXTURE PENDING");
}
