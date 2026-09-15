use disrobe_bytes::Endian;

#[derive(Debug)]
pub(crate) struct FieldWriter<'out> {
    out: &'out mut Vec<u8>,
    endian: Endian,
}

impl<'out> FieldWriter<'out> {
    pub(crate) const fn new(out: &'out mut Vec<u8>, endian: Endian) -> Self {
        Self { out, endian }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        match self.endian {
            Endian::Little => self.out.extend_from_slice(&value.to_le_bytes()),
            Endian::Big => self.out.extend_from_slice(&value.to_be_bytes()),
        }
    }

    pub(crate) fn u32(&mut self, value: u32) {
        match self.endian {
            Endian::Little => self.out.extend_from_slice(&value.to_le_bytes()),
            Endian::Big => self.out.extend_from_slice(&value.to_be_bytes()),
        }
    }

    pub(crate) fn u64(&mut self, value: u64) {
        match self.endian {
            Endian::Little => self.out.extend_from_slice(&value.to_le_bytes()),
            Endian::Big => self.out.extend_from_slice(&value.to_be_bytes()),
        }
    }

    pub(crate) fn i32(&mut self, value: i32) {
        self.u32(value as u32);
    }

    pub(crate) fn u16_slice(&mut self, values: &[u16]) {
        for value in values {
            self.u16(*value);
        }
    }

    pub(crate) fn u32_slice(&mut self, values: &[u32]) {
        for value in values {
            self.u32(*value);
        }
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }
}
