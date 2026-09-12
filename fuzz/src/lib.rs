#![forbid(unsafe_code)]

pub mod cil_metadata;
pub mod dex_jvm_classfile;
pub mod python_bytecode;
pub mod seed_reach;

use disrobe_bytes::{ByteReadError, ByteReader};

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MEMORY_LIMIT_MEGABYTES: u32 = 2048;
pub const PER_INPUT_TIMEOUT_SECONDS: u32 = 25;
pub const MAX_DECLARED_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

#[must_use]
pub fn over_input_budget(data: &[u8]) -> bool {
    data.len() > MAX_INPUT_BYTES
}

#[must_use]
pub fn selector(data: &[u8]) -> u32 {
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    match reader.read_u32_le() {
        Ok(value) => value,
        Err(_) => data.len() as u32,
    }
}

#[must_use]
pub fn declared_output_size(data: &[u8]) -> usize {
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    let raw: Result<u32, ByteReadError> = reader.read_u32_le();
    let requested: usize = raw.map_or(0, |value: u32| value as usize);
    requested % (MAX_DECLARED_OUTPUT_BYTES + 1)
}

#[must_use]
pub fn entry_name(data: &[u8]) -> String {
    let mut reader: ByteReader<'_> = ByteReader::new(data);
    let taken: usize = data.len().min(512);
    let slice: &[u8] = reader.read_bytes(taken).unwrap_or(&[]);
    String::from_utf8_lossy(slice).into_owned()
}
