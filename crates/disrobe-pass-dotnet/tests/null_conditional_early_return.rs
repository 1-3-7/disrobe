#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const EVENT_SOURCE_TICK_TOKEN: u32 = 0x0600_0106;

fn baseline() -> DecompiledAssembly {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(EDGECASES_BASELINE_REL);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn event_source_tick(assembly: &DecompiledAssembly) -> &StructuredMethod {
    assembly
        .methods
        .iter()
        .find(|method: &&StructuredMethod| method.token == EVENT_SOURCE_TICK_TOKEN)
        .unwrap_or_else(|| {
            panic!("EventSource.Tick token 0x{EVENT_SOURCE_TICK_TOKEN:08x} must be present")
        })
}

#[test]
fn event_source_tick_recovers_null_conditional_pulse_invocation() {
    let assembly: DecompiledAssembly = baseline();
    let method: &StructuredMethod = event_source_tick(&assembly);

    assert!(
        method.signature.contains("Tick") && method.signature.contains("beat"),
        "0x{EVENT_SOURCE_TICK_TOKEN:08x} must remain EventSource.Tick; got:\n{}",
        method.signature
    );
    assert!(
        method.body.contains("Pulse?.Invoke(this, beat);"),
        "EventSource.Tick must recover the guarded event invocation; got:\n{}",
        method.body
    );
    assert!(
        !method.body.contains("__stack_underflow"),
        "EventSource.Tick must not fabricate a stack-underflow expression; got:\n{}",
        method.body
    );
}
