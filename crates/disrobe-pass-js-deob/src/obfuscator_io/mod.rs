mod control_flow_object;
mod control_flow_switch;
mod controls;
mod detection;
mod dispatch;
mod normalize_strings;
mod presets;
mod scope_proxy;

pub use controls::ObfControl;
pub use detection::{ObfuscatorIoDetection, detect};
pub use dispatch::{DEFAULT_PASSES, MAX_PASS_CEILING, Options, Output, deobfuscate};
pub use presets::Preset;

use crate::error::Result;

pub fn deobfuscate_preset(source: &str, preset: Preset) -> Result<Output> {
    let opts: Options = Options::for_preset(preset);
    deobfuscate(source, &opts)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscate_preset_low_returns_output() {
        let src: &str = "var x = 1;";
        let out: Output = deobfuscate_preset(src, Preset::Low).expect("ok");
        assert!(out.source.contains("var x"));
    }

    #[test]
    fn deobfuscate_preset_medium_returns_output() {
        let src: &str = "var x = 1;";
        let out: Output = deobfuscate_preset(src, Preset::Medium).expect("ok");
        assert!(out.source.contains("var x"));
    }

    #[test]
    fn deobfuscate_preset_high_returns_output() {
        let src: &str = "var x = 1;";
        let out: Output = deobfuscate_preset(src, Preset::High).expect("ok");
        assert!(out.source.contains("var x"));
    }
}
