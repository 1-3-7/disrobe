#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod address;
mod align;
mod at;
mod capacity;
mod cstr;
mod leb128;
mod reader;
mod section_map;

pub use address::{AddressError, FileOffset, Rva, Size, Va};
pub use align::{
    align_down_u32, align_down_u64, align_down_usize, align_up_u32, align_up_u64, align_up_usize,
};
pub use at::{
    read_bytes_at, read_f32_be_at, read_f32_be_at_or, read_f32_be_at_zero_pad_tail, read_f32_le_at,
    read_f32_le_at_or, read_f32_le_at_zero_pad_tail, read_f64_be_at, read_f64_be_at_or,
    read_f64_be_at_zero_pad_tail, read_f64_le_at, read_f64_le_at_or, read_f64_le_at_zero_pad_tail,
    read_i8_at, read_i8_at_or, read_i8_at_zero_pad_tail, read_i16_be_at, read_i16_be_at_or,
    read_i16_be_at_zero_pad_tail, read_i16_le_at, read_i16_le_at_or, read_i16_le_at_zero_pad_tail,
    read_i24_be_at, read_i24_be_at_or, read_i24_be_at_zero_pad_tail, read_i24_le_at,
    read_i24_le_at_or, read_i24_le_at_zero_pad_tail, read_i32_be_at, read_i32_be_at_or,
    read_i32_be_at_zero_pad_tail, read_i32_le_at, read_i32_le_at_or, read_i32_le_at_zero_pad_tail,
    read_i64_be_at, read_i64_be_at_or, read_i64_be_at_zero_pad_tail, read_i64_le_at,
    read_i64_le_at_or, read_i64_le_at_zero_pad_tail, read_i128_be_at, read_i128_be_at_or,
    read_i128_be_at_zero_pad_tail, read_i128_le_at, read_i128_le_at_or,
    read_i128_le_at_zero_pad_tail, read_u8_at, read_u8_at_or, read_u8_at_zero_pad_tail,
    read_u16_be_at, read_u16_be_at_or, read_u16_be_at_zero_pad_tail, read_u16_le_at,
    read_u16_le_at_or, read_u16_le_at_zero_pad_tail, read_u24_be_at, read_u24_be_at_or,
    read_u24_be_at_zero_pad_tail, read_u24_le_at, read_u24_le_at_or, read_u24_le_at_zero_pad_tail,
    read_u32_be_at, read_u32_be_at_or, read_u32_be_at_zero_pad_tail, read_u32_le_at,
    read_u32_le_at_or, read_u32_le_at_zero_pad_tail, read_u64_be_at, read_u64_be_at_or,
    read_u64_be_at_zero_pad_tail, read_u64_le_at, read_u64_le_at_or, read_u64_le_at_zero_pad_tail,
    read_u128_be_at, read_u128_be_at_or, read_u128_be_at_zero_pad_tail, read_u128_le_at,
    read_u128_le_at_or, read_u128_le_at_zero_pad_tail,
};
pub use capacity::bounded_element_capacity;
pub use cstr::{
    CStrOptions, CStrRun, CStrRuns, CStrSpan, cstr_runs, read_cstr_at, read_cstr_span_at,
};
pub use leb128::{LebError, read_sleb128_at, read_uleb128_at};
pub use reader::{ByteReadError, ByteReader, Endian, sign_extend_24};
pub use section_map::{SectionMap, SectionSpan};
