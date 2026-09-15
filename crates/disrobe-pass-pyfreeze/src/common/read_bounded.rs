use std::io::Read;

const MAX_PREALLOC: usize = 1024 * 1024;

#[must_use]
pub fn prealloc_for(declared_size: u64) -> usize {
    usize::try_from(declared_size)
        .unwrap_or(MAX_PREALLOC)
        .min(MAX_PREALLOC)
}

pub fn read_to_vec_bounded<R: Read>(
    reader: &mut R,
    declared_size: u64,
) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(prealloc_for(declared_size));
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn read_to_vec_limited<R: Read>(
    reader: &mut R,
    declared_size: u64,
    max_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    let prealloc_hint: u64 = declared_size.min(max_bytes);
    let mut buf: Vec<u8> = Vec::with_capacity(prealloc_for(prealloc_hint));
    let read_limit: u64 = max_bytes.saturating_add(1);
    let mut limited: std::io::Take<&mut R> = reader.take(read_limit);
    limited.read_to_end(&mut buf)?;
    let over_limit: bool = usize::try_from(max_bytes).is_ok_and(|max: usize| buf.len() > max);
    if over_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("entry expanded past {max_bytes} bytes"),
        ));
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn prealloc_never_exceeds_cap_for_huge_declared_size() {
        assert_eq!(prealloc_for(500 * 1024 * 1024), MAX_PREALLOC);
        assert_eq!(prealloc_for(u64::MAX), MAX_PREALLOC);
    }

    #[test]
    fn prealloc_honors_small_declared_size() {
        assert_eq!(prealloc_for(0), 0);
        assert_eq!(prealloc_for(4096), 4096);
    }

    #[test]
    fn read_grows_to_actual_data_regardless_of_small_declared_size() {
        let data: Vec<u8> = vec![0xABu8; 8192];
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(data.as_slice());
        let out: Vec<u8> = read_to_vec_bounded(&mut cursor, 0).expect("read");
        assert_eq!(out.len(), 8192);
        assert_eq!(out, data);
    }

    #[test]
    fn read_does_not_overallocate_on_lying_declared_size() {
        let data: &[u8] = b"AAAA";
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(data);
        let out: Vec<u8> = read_to_vec_bounded(&mut cursor, 500 * 1024 * 1024).expect("read");
        assert_eq!(out.len(), 4);
        assert!(out.capacity() <= MAX_PREALLOC);
    }

    #[test]
    fn read_rejects_actual_data_over_limit() {
        let data: Vec<u8> = vec![0xAB; 17];
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(data.as_slice());
        let err: std::io::Error =
            read_to_vec_limited(&mut cursor, 4, 16).expect_err("must reject actual overrun");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn limited_read_does_not_overallocate_on_lying_declared_size() {
        let data: &[u8] = b"AAAA";
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(data);
        let out: Vec<u8> = read_to_vec_limited(&mut cursor, u64::MAX, 256 * 1024 * 1024)
            .expect("truncated body under the cap must still recover");
        assert_eq!(out.len(), 4);
        assert!(
            out.capacity() <= MAX_PREALLOC,
            "a header claiming u64::MAX must never drive preallocation, got capacity {}",
            out.capacity()
        );
    }
}
