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
