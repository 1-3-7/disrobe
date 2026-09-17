use crate::reader::{ByteReadError, ByteReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CStrOptions {
    pub max_len: usize,
    pub require_terminator: bool,
}

impl CStrOptions {
    pub const UNBOUNDED: Self = Self {
        max_len: usize::MAX,
        require_terminator: true,
    };

    pub const LENIENT: Self = Self {
        max_len: usize::MAX,
        require_terminator: false,
    };

    #[inline]
    #[must_use]
    pub const fn new(max_len: usize, require_terminator: bool) -> Self {
        Self {
            max_len,
            require_terminator,
        }
    }

    #[inline]
    #[must_use]
    pub const fn terminated(max_len: usize) -> Self {
        Self {
            max_len,
            require_terminator: true,
        }
    }

    #[inline]
    #[must_use]
    pub const fn fixed_field(width: usize) -> Self {
        Self {
            max_len: width,
            require_terminator: false,
        }
    }
}

impl Default for CStrOptions {
    #[inline]
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CStrSpan {
    pub offset: usize,
    pub len: usize,
    pub terminated: bool,
}

impl CStrSpan {
    #[inline]
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.len.saturating_add(self.terminated as usize)
    }

    #[inline]
    #[must_use]
    pub const fn end(self) -> usize {
        self.offset.saturating_add(self.consumed())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CStrRun<'a> {
    pub offset: usize,
    pub bytes: &'a [u8],
    pub terminated: bool,
}

pub fn read_cstr_span_at(
    bytes: &[u8],
    offset: usize,
    options: CStrOptions,
) -> Result<CStrSpan, ByteReadError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    let window_len: usize = options.max_len.min(reader.remaining());
    let window: &[u8] = reader.peek_bytes(window_len)?;
    if let Some(index) = window.iter().position(|byte: &u8| *byte == 0) {
        return Ok(CStrSpan {
            offset,
            len: index,
            terminated: true,
        });
    }
    if options.require_terminator {
        return Err(ByteReadError {
            offset,
            needed: window_len.saturating_add(1),
            available: window_len,
        });
    }
    Ok(CStrSpan {
        offset,
        len: window_len,
        terminated: false,
    })
}

pub fn read_cstr_at(
    bytes: &[u8],
    offset: usize,
    options: CStrOptions,
) -> Result<&[u8], ByteReadError> {
    let span: CStrSpan = read_cstr_span_at(bytes, offset, options)?;
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    reader.seek(offset)?;
    reader.read_bytes(span.len)
}

#[must_use]
pub const fn cstr_runs(bytes: &[u8], options: CStrOptions) -> CStrRuns<'_> {
    CStrRuns {
        bytes,
        pos: 0,
        options,
        finished: false,
    }
}

#[derive(Debug, Clone)]
pub struct CStrRuns<'a> {
    bytes: &'a [u8],
    pos: usize,
    options: CStrOptions,
    finished: bool,
}

impl<'a> CStrRuns<'a> {
    #[must_use]
    pub const fn starting_at(bytes: &'a [u8], offset: usize, options: CStrOptions) -> Self {
        Self {
            bytes,
            pos: offset,
            options,
            finished: false,
        }
    }
}

impl<'a> Iterator for CStrRuns<'a> {
    type Item = CStrRun<'a>;

    fn next(&mut self) -> Option<CStrRun<'a>> {
        if self.finished || self.pos >= self.bytes.len() {
            return None;
        }
        let scan: CStrOptions = CStrOptions::new(self.options.max_len, false);
        let span: CStrSpan = read_cstr_span_at(self.bytes, self.pos, scan).ok()?;
        if !span.terminated {
            self.finished = true;
            if self.options.require_terminator {
                return None;
            }
        }
        let end: usize = self.pos.checked_add(span.len)?;
        let run: &'a [u8] = self.bytes.get(self.pos..end)?;
        let item: CStrRun<'a> = CStrRun {
            offset: self.pos,
            bytes: run,
            terminated: span.terminated,
        };
        self.pos = span.end();
        Some(item)
    }
}

impl<'a> ByteReader<'a> {
    pub fn read_cstr(&mut self, options: CStrOptions) -> Result<&'a [u8], ByteReadError> {
        let span: CStrSpan = read_cstr_span_at(self.as_slice(), self.position(), options)?;
        let value: &'a [u8] = self.read_bytes(span.len)?;
        if span.terminated {
            self.skip(1)?;
        }
        Ok(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CStrOptions, CStrRun, CStrSpan, cstr_runs, read_cstr_at, read_cstr_span_at};
    use crate::reader::{ByteReadError, ByteReader};

    fn reference_ascii_split(bytes: &[u8]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut start: usize = 0;
        for (i, b) in bytes.iter().enumerate() {
            if *b == 0 {
                if i > start {
                    let chunk: &[u8] = &bytes[start..i];
                    if chunk
                        .iter()
                        .all(|c: &u8| c.is_ascii_graphic() || *c == b' ')
                    {
                        out.push(String::from_utf8_lossy(chunk).into_owned());
                    }
                }
                start = i + 1;
            }
        }
        out
    }

    fn reference_utf8_split(bytes: &[u8]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut start: usize = 0;
        for (i, b) in bytes.iter().enumerate() {
            if *b == 0 {
                if i > start {
                    let chunk: &[u8] = &bytes[start..i];
                    if let Ok(s) = std::str::from_utf8(chunk) {
                        out.push(s.to_owned());
                    }
                }
                start = i + 1;
            }
        }
        out
    }

    fn ascii_split_via_runs(bytes: &[u8]) -> Vec<String> {
        cstr_runs(bytes, CStrOptions::UNBOUNDED)
            .filter(|run: &CStrRun<'_>| run.terminated && !run.bytes.is_empty())
            .filter(|run: &CStrRun<'_>| {
                run.bytes
                    .iter()
                    .all(|c: &u8| c.is_ascii_graphic() || *c == b' ')
            })
            .map(|run: CStrRun<'_>| String::from_utf8_lossy(run.bytes).into_owned())
            .collect()
    }

    fn utf8_split_via_runs(bytes: &[u8]) -> Vec<String> {
        cstr_runs(bytes, CStrOptions::UNBOUNDED)
            .filter(|run: &CStrRun<'_>| run.terminated && !run.bytes.is_empty())
            .filter_map(|run: CStrRun<'_>| std::str::from_utf8(run.bytes).ok().map(str::to_owned))
            .collect()
    }

    #[test]
    fn reads_a_terminated_string_without_the_terminator() {
        let data: &[u8] = b"objc_msgSend\0next";
        assert_eq!(
            read_cstr_at(data, 0, CStrOptions::UNBOUNDED).unwrap(),
            b"objc_msgSend"
        );
        assert_eq!(
            read_cstr_span_at(data, 0, CStrOptions::UNBOUNDED).unwrap(),
            CStrSpan {
                offset: 0,
                len: 12,
                terminated: true,
            }
        );
    }

    #[test]
    fn an_offset_at_the_end_is_not_a_panic() {
        let data: &[u8] = b"abc";
        assert_eq!(read_cstr_at(data, 3, CStrOptions::LENIENT).unwrap(), b"");
        let err: ByteReadError = read_cstr_at(data, 3, CStrOptions::UNBOUNDED).unwrap_err();
        assert_eq!(err.needed, 1);
        assert_eq!(err.available, 0);
    }

    #[test]
    fn an_offset_past_the_end_is_a_typed_error() {
        let data: &[u8] = b"abc";
        let err: ByteReadError = read_cstr_at(data, 4, CStrOptions::LENIENT).unwrap_err();
        assert_eq!(err.offset, 4);
        assert_eq!(err.available, 3);
        assert!(read_cstr_at(data, usize::MAX, CStrOptions::LENIENT).is_err());
    }

    #[test]
    fn an_empty_input_yields_an_empty_result_or_an_error() {
        let data: &[u8] = b"";
        assert_eq!(read_cstr_at(data, 0, CStrOptions::LENIENT).unwrap(), b"");
        assert!(read_cstr_at(data, 0, CStrOptions::UNBOUNDED).is_err());
        assert_eq!(cstr_runs(data, CStrOptions::LENIENT).count(), 0);
    }

    #[test]
    fn a_missing_terminator_is_an_error_only_when_required() {
        let data: &[u8] = b"unterminated";
        assert_eq!(
            read_cstr_at(data, 0, CStrOptions::LENIENT).unwrap(),
            b"unterminated"
        );
        let err: ByteReadError = read_cstr_at(data, 0, CStrOptions::UNBOUNDED).unwrap_err();
        assert_eq!(err.needed, 13);
        assert_eq!(err.available, 12);
    }

    #[test]
    fn a_full_fixed_width_field_is_accepted() {
        let header: &[u8] = b"usr/bin/tarname";
        assert_eq!(
            read_cstr_at(header, 0, CStrOptions::fixed_field(8)).unwrap(),
            b"usr/bin/"
        );
        assert!(read_cstr_at(header, 0, CStrOptions::terminated(8)).is_err());
    }

    #[test]
    fn a_terminator_just_past_the_cap_is_rejected() {
        let data: &[u8] = b"abcd\0";
        assert!(read_cstr_at(data, 0, CStrOptions::terminated(4)).is_err());
        assert_eq!(
            read_cstr_at(data, 0, CStrOptions::terminated(5)).unwrap(),
            b"abcd"
        );
        assert_eq!(
            read_cstr_at(data, 0, CStrOptions::fixed_field(4)).unwrap(),
            b"abcd"
        );
    }

    #[test]
    fn a_zero_cap_yields_an_empty_run_or_an_error() {
        let data: &[u8] = b"abc\0";
        assert_eq!(
            read_cstr_at(data, 0, CStrOptions::fixed_field(0)).unwrap(),
            b""
        );
        assert!(read_cstr_at(data, 0, CStrOptions::terminated(0)).is_err());
    }

    #[test]
    fn a_terminator_at_offset_zero_is_a_legal_empty_string() {
        let data: &[u8] = b"\0abc\0";
        assert_eq!(read_cstr_at(data, 0, CStrOptions::UNBOUNDED).unwrap(), b"");
        let runs: Vec<CStrRun<'_>> = cstr_runs(data, CStrOptions::UNBOUNDED).collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].bytes, b"");
        assert_eq!(runs[1].bytes, b"abc");
        assert!(runs.iter().all(|run: &CStrRun<'_>| run.terminated));
    }

    #[test]
    fn consecutive_terminators_yield_empty_runs() {
        let data: &[u8] = b"a\0\0\0b\0";
        let runs: Vec<&[u8]> = cstr_runs(data, CStrOptions::UNBOUNDED)
            .map(|run: CStrRun<'_>| run.bytes)
            .collect();
        assert_eq!(runs, vec![&b"a"[..], &b""[..], &b""[..], &b"b"[..]]);
    }

    #[test]
    fn an_all_nul_field_yields_only_empty_runs() {
        let data: &[u8] = &[0u8; 4];
        let runs: Vec<CStrRun<'_>> = cstr_runs(data, CStrOptions::UNBOUNDED).collect();
        assert_eq!(runs.len(), 4);
        assert!(runs.iter().all(|run: &CStrRun<'_>| run.bytes.is_empty()));
    }

    #[test]
    fn a_cap_larger_than_the_buffer_stops_at_the_buffer() {
        let data: &[u8] = b"abc";
        assert_eq!(
            read_cstr_span_at(data, 1, CStrOptions::fixed_field(usize::MAX)).unwrap(),
            CStrSpan {
                offset: 1,
                len: 2,
                terminated: false,
            }
        );
    }

    #[test]
    fn an_offset_plus_cap_overflow_cannot_wrap_the_guard() {
        let data: &[u8] = b"abc\0def";
        assert_eq!(
            read_cstr_at(data, 2, CStrOptions::new(usize::MAX, true)).unwrap(),
            b"c"
        );
        assert_eq!(
            read_cstr_at(data, 4, CStrOptions::new(usize::MAX - 1, false)).unwrap(),
            b"def"
        );
    }

    #[test]
    fn a_long_unterminated_section_stops_at_the_cap() {
        let data: Vec<u8> = vec![b'A'; 1 << 20];
        let span: CStrSpan = read_cstr_span_at(&data, 0, CStrOptions::fixed_field(64)).unwrap();
        assert_eq!(span.len, 64);
        assert!(!span.terminated);
    }

    #[test]
    fn an_unterminated_tail_ends_the_run_iterator_when_a_terminator_is_required() {
        let data: &[u8] = b"one\0two";
        let strict: Vec<&[u8]> = cstr_runs(data, CStrOptions::UNBOUNDED)
            .map(|run: CStrRun<'_>| run.bytes)
            .collect();
        assert_eq!(strict, vec![&b"one"[..]]);
        let lenient: Vec<&[u8]> = cstr_runs(data, CStrOptions::LENIENT)
            .map(|run: CStrRun<'_>| run.bytes)
            .collect();
        assert_eq!(lenient, vec![&b"one"[..], &b"two"[..]]);
    }

    #[test]
    fn the_run_iterator_reports_its_own_offsets() {
        let data: &[u8] = b"ab\0cd\0";
        let offsets: Vec<usize> = cstr_runs(data, CStrOptions::UNBOUNDED)
            .map(|run: CStrRun<'_>| run.offset)
            .collect();
        assert_eq!(offsets, vec![0, 3]);
    }

    #[test]
    fn a_run_iterator_can_start_past_zero() {
        let data: &[u8] = b"skip\0keep\0";
        let runs: Vec<&[u8]> = super::CStrRuns::starting_at(data, 5, CStrOptions::UNBOUNDED)
            .map(|run: CStrRun<'_>| run.bytes)
            .collect();
        assert_eq!(runs, vec![&b"keep"[..]]);
    }

    #[test]
    fn the_reader_companion_advances_past_the_terminator() {
        let data: &[u8] = b"first\0second\0";
        let mut reader: ByteReader<'_> = ByteReader::new(data);
        assert_eq!(reader.read_cstr(CStrOptions::UNBOUNDED).unwrap(), b"first");
        assert_eq!(reader.position(), 6);
        assert_eq!(reader.read_cstr(CStrOptions::UNBOUNDED).unwrap(), b"second");
        assert_eq!(reader.position(), 13);
        assert!(reader.read_cstr(CStrOptions::UNBOUNDED).is_err());
        assert_eq!(reader.position(), 13);
    }

    #[test]
    fn the_reader_companion_stops_at_an_unterminated_tail() {
        let data: &[u8] = b"tail";
        let mut reader: ByteReader<'_> = ByteReader::new(data);
        assert_eq!(reader.read_cstr(CStrOptions::LENIENT).unwrap(), b"tail");
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn the_run_iterator_reproduces_both_decode_policies() {
        let fixtures: [&[u8]; 6] = [
            b"",
            b"\0",
            b"alloc\0init\0",
            b"has space\0tab\there\0",
            b"trailing",
            &[0x80, 0x00, b'o', b'k', 0x00, 0xFF, 0xFE],
        ];
        for fixture in fixtures {
            assert_eq!(
                ascii_split_via_runs(fixture),
                reference_ascii_split(fixture)
            );
            assert_eq!(utf8_split_via_runs(fixture), reference_utf8_split(fixture));
        }
    }
}
