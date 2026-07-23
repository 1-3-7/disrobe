#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod align;
mod at;
mod capacity;
mod leb128;
mod reader;

pub use align::{
    align_down_u32, align_down_u64, align_down_usize, align_up_u32, align_up_u64, align_up_usize,
};
pub use at::{
    read_bytes_at, read_i8_at, read_i16_be_at, read_i16_le_at, read_i32_be_at, read_i32_le_at,
    read_i64_be_at, read_i64_le_at, read_i128_be_at, read_i128_le_at, read_u8_at, read_u16_be_at,
    read_u16_le_at, read_u24_be_at, read_u24_le_at, read_u32_be_at, read_u32_le_at, read_u64_be_at,
    read_u64_le_at, read_u128_be_at, read_u128_le_at,
};
pub use capacity::bounded_element_capacity;
pub use leb128::{LebError, read_sleb128_at, read_uleb128_at};
pub use reader::{ByteReadError, ByteReader};
