use disrobe_bytes::ByteReader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EazMethodInfo {
    pub name: String,
    pub return_type_code: i32,
    pub local_type_codes: Vec<i32>,
    pub parameter_type_codes: Vec<i32>,
    pub returns_void: bool,
    pub local_count: u32,
    pub param_count: u32,
    pub exception_handler_count: u32,
    pub code: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    Truncated,
    BadVersion(u8),
    BadString,
    TooManySlots,
}

struct Reader<'a> {
    reader: ByteReader<'a>,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(data),
        }
    }

    fn u8(&mut self) -> Result<u8, StreamError> {
        self.reader.read_u8().map_err(|_| StreamError::Truncated)
    }

    fn bool(&mut self) -> Result<bool, StreamError> {
        Ok(self.u8()? != 0)
    }

    fn i16(&mut self) -> Result<i16, StreamError> {
        self.reader
            .read_i16_le()
            .map_err(|_| StreamError::Truncated)
    }

    fn i32(&mut self) -> Result<i32, StreamError> {
        self.reader
            .read_i32_le()
            .map_err(|_| StreamError::Truncated)
    }

    fn seven_bit_len(&mut self) -> Result<usize, StreamError> {
        const MAX_SEVEN_BIT_LENGTH_BYTES: usize = 6;
        if self.reader.remaining() >= MAX_SEVEN_BIT_LENGTH_BYTES {
            let prefix: &[u8] = self
                .reader
                .peek_bytes(MAX_SEVEN_BIT_LENGTH_BYTES)
                .map_err(|_| StreamError::Truncated)?;
            if prefix.iter().all(|byte: &u8| *byte & 0x80 != 0) {
                return Err(StreamError::BadString);
            }
        }
        let value: u64 = self
            .reader
            .read_uleb128()
            .map_err(|_| StreamError::Truncated)?;
        usize::try_from(value).map_err(|_| StreamError::BadString)
    }

    fn dotnet_string(&mut self) -> Result<String, StreamError> {
        let len: usize = self.seven_bit_len()?;
        let slice: &[u8] = self
            .reader
            .read_bytes(len)
            .map_err(|_| StreamError::Truncated)?;
        Ok(String::from_utf8_lossy(slice).into_owned())
    }

    fn skip(&mut self, n: usize) -> Result<(), StreamError> {
        self.reader.skip(n).map_err(|_| StreamError::Truncated)
    }
}

pub fn parse_method_info(region: &[u8]) -> Result<EazMethodInfo, StreamError> {
    const MAX_METHOD_SLOTS: u32 = 1_024;
    let mut r: Reader<'_> = Reader::new(region);

    let version: u8 = r.u8()?;
    if version != 0 {
        return Err(StreamError::BadVersion(version));
    }

    let local_count: i16 = r.i16()?;
    let local_n: u32 = u32::try_from(local_count.max(0)).unwrap_or(0);
    if local_n > MAX_METHOD_SLOTS {
        return Err(StreamError::TooManySlots);
    }
    let mut local_type_codes: Vec<i32> = Vec::new();
    local_type_codes
        .try_reserve_exact(local_n as usize)
        .map_err(|_| StreamError::BadString)?;
    for _ in 0..local_n {
        local_type_codes.push(r.i32()?);
    }

    let return_type_code: i32 = r.i32()?;
    let _unknown1: bool = r.bool()?;
    let _unknown3: i32 = r.i32()?;

    let param_count: i16 = r.i16()?;
    let param_n: u32 = u32::try_from(param_count.max(0)).unwrap_or(0);
    if param_n > MAX_METHOD_SLOTS {
        return Err(StreamError::TooManySlots);
    }
    let mut parameter_type_codes: Vec<i32> = Vec::new();
    parameter_type_codes
        .try_reserve_exact(param_n as usize)
        .map_err(|_| StreamError::BadString)?;
    for _ in 0..param_n {
        parameter_type_codes.push(r.i32()?);
        r.skip(1)?;
    }

    let name: String = r.dotnet_string()?;

    let eh_count: i16 = r.i16()?;
    let eh_n: u32 = u32::try_from(eh_count.max(0)).unwrap_or(0);
    r.skip(eh_n as usize * 17)?;

    let code_size: i32 = r.i32()?;
    let size: usize = usize::try_from(code_size.max(0)).unwrap_or(0);
    let code: Vec<u8> = r
        .reader
        .read_bytes(size)
        .map_err(|_| StreamError::Truncated)?
        .to_vec();

    Ok(EazMethodInfo {
        name,
        return_type_code,
        local_type_codes,
        parameter_type_codes,
        returns_void: return_type_code == 0,
        local_count: local_n,
        param_count: param_n,
        exception_handler_count: eh_n,
        code,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{EazMethodInfo, Reader, StreamError, parse_method_info};

    #[test]
    fn short_string_length_ignores_later_continuation_byte() {
        let data: [u8; 6] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut reader: Reader<'_> = Reader::new(&data);

        assert_eq!(reader.seven_bit_len(), Ok(1));
    }

    #[test]
    fn six_continuation_bytes_in_string_length_are_bad_string() {
        let mut region: Vec<u8> = Vec::new();
        region.push(0);
        region.extend_from_slice(&0i16.to_le_bytes());
        region.extend_from_slice(&0i32.to_le_bytes());
        region.push(0);
        region.extend_from_slice(&0i32.to_le_bytes());
        region.extend_from_slice(&0i16.to_le_bytes());
        region.extend_from_slice(&[0x80; 6]);

        assert_eq!(parse_method_info(&region), Err(StreamError::BadString));
    }

    #[test]
    fn non_utf8_method_name_preserves_surrounding_method_info() {
        let mut region: Vec<u8> = Vec::new();
        region.push(0);
        region.extend_from_slice(&0i16.to_le_bytes());
        region.extend_from_slice(&7i32.to_le_bytes());
        region.push(0);
        region.extend_from_slice(&0i32.to_le_bytes());
        region.extend_from_slice(&0i16.to_le_bytes());

        let name_bytes: [u8; 3] = [0x61, 0xff, 0x62];
        region.push(name_bytes.len() as u8);
        region.extend_from_slice(&name_bytes);

        region.extend_from_slice(&0i16.to_le_bytes());
        let code: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        region.extend_from_slice(&(code.len() as i32).to_le_bytes());
        region.extend_from_slice(&code);

        let info: EazMethodInfo =
            parse_method_info(&region).expect("bad name byte must not abort the method info");

        assert_eq!(info.return_type_code, 7);
        assert_eq!(info.code, code.to_vec());
        assert!(info.name.contains('\u{fffd}'));
        assert!(info.name.starts_with('a'));
        assert!(info.name.ends_with('b'));
    }
}
