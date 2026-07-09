#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod align;
mod reader;

pub use align::{
    align_down_u32, align_down_u64, align_down_usize, align_up_u32, align_up_u64, align_up_usize,
};
pub use reader::{ByteReadError, ByteReader};
