#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod constant;
mod features;
mod matcher;

pub use constant::{SMALL_INTEGER_CEILING, is_discriminating_constant};
pub use features::{AnchorStrength, DataReference, FunctionFeatures, FunctionId, anchor_strength};
pub use matcher::{FunctionVerdict, MatchReport, UnmatchedCause, Verdict, match_functions};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
