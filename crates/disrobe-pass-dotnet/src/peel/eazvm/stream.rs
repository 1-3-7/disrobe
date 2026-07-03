#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EazMethodInfo {
    pub name: String,
    pub return_type_code: i32,
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
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, StreamError> {
        let b: u8 = *self.data.get(self.pos).ok_or(StreamError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn bool(&mut self) -> Result<bool, StreamError> {
        Ok(self.u8()? != 0)
    }

    fn i16(&mut self) -> Result<i16, StreamError> {
        let end: usize = self.pos.checked_add(2).ok_or(StreamError::Truncated)?;
        let slice: &[u8] = self.data.get(self.pos..end).ok_or(StreamError::Truncated)?;
        self.pos = end;
        Ok(i16::from_le_bytes([slice[0], slice[1]]))
    }

    fn i32(&mut self) -> Result<i32, StreamError> {
        let end: usize = self.pos.checked_add(4).ok_or(StreamError::Truncated)?;
        let slice: &[u8] = self.data.get(self.pos..end).ok_or(StreamError::Truncated)?;
        self.pos = end;
        Ok(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn seven_bit_len(&mut self) -> Result<usize, StreamError> {
        let mut value: usize = 0;
        let mut shift: u32 = 0;
        loop {
            let b: u8 = self.u8()?;
            value |= usize::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return Err(StreamError::BadString);
            }
        }
        Ok(value)
    }

    fn dotnet_string(&mut self) -> Result<String, StreamError> {
        let len: usize = self.seven_bit_len()?;
        let end: usize = self.pos.checked_add(len).ok_or(StreamError::Truncated)?;
        let slice: &[u8] = self.data.get(self.pos..end).ok_or(StreamError::Truncated)?;
        self.pos = end;
        Ok(String::from_utf8_lossy(slice).into_owned())
    }

    fn skip(&mut self, n: usize) -> Result<(), StreamError> {
        let end: usize = self.pos.checked_add(n).ok_or(StreamError::Truncated)?;
        if end > self.data.len() {
            return Err(StreamError::Truncated);
        }
        self.pos = end;
        Ok(())
    }
}

pub fn parse_method_info(region: &[u8]) -> Result<EazMethodInfo, StreamError> {
    let mut r: Reader<'_> = Reader::new(region);

    let version: u8 = r.u8()?;
    if version != 0 {
        return Err(StreamError::BadVersion(version));
    }

    let local_count: i16 = r.i16()?;
    let local_n: u32 = u32::try_from(local_count.max(0)).unwrap_or(0);
    r.skip(local_n as usize * 4)?;

    let return_type_code: i32 = r.i32()?;
    let _unknown1: bool = r.bool()?;
    let _unknown3: i32 = r.i32()?;

    let param_count: i16 = r.i16()?;
    let param_n: u32 = u32::try_from(param_count.max(0)).unwrap_or(0);
    r.skip(param_n as usize * 5)?;

    let name: String = r.dotnet_string()?;

    let eh_count: i16 = r.i16()?;
    let eh_n: u32 = u32::try_from(eh_count.max(0)).unwrap_or(0);
    r.skip(eh_n as usize * 17)?;

    let code_size: i32 = r.i32()?;
    let size: usize = usize::try_from(code_size.max(0)).unwrap_or(0);
    let end: usize = r.pos.checked_add(size).ok_or(StreamError::Truncated)?;
    let code: Vec<u8> = region
        .get(r.pos..end)
        .ok_or(StreamError::Truncated)?
        .to_vec();

    Ok(EazMethodInfo {
        name,
        return_type_code,
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
    use super::{EazMethodInfo, parse_method_info};

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
