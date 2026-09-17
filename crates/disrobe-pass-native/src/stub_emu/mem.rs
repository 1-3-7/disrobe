use std::collections::BTreeMap;

use crate::error::{Error, Result};

pub const PAGE_SIZE: usize = 0x1000;

pub const MAX_WRITE_LOG_ENTRIES: usize = 1 << 19;

pub const PAGE_BITS: u32 = 12;

const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;

const NULL_RESERVED_REGION: u64 = PAGE_SIZE as u64;

pub const MAX_MAP_BYTES: u64 = 256 * 1024 * 1024;

const MAX_MAP_PAGES: u64 = MAX_MAP_BYTES / (PAGE_SIZE as u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perm {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Perm {
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

#[derive(Debug, Clone)]
struct Page {
    data: Box<[u8; PAGE_SIZE]>,
    perm: Perm,
}

#[derive(Debug, Clone, Default)]
pub struct Memory {
    pages: BTreeMap<u64, Page>,
    lazy_budget: Option<u32>,
    lazy_used: u32,
    block_null_page: bool,
    write_log: Option<Vec<(u64, u8)>>,
    write_log_truncated: bool,
}

impl Memory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_lazy_commit(&mut self, max_pages: u32) {
        self.lazy_budget = Some(max_pages);
    }

    pub fn block_null_page(&mut self) {
        self.block_null_page = true;
    }

    pub fn enable_write_log(&mut self) {
        self.write_log = Some(Vec::new());
        self.write_log_truncated = false;
    }

    #[must_use]
    pub fn write_log(&self) -> &[(u64, u8)] {
        self.write_log.as_deref().unwrap_or(&[])
    }

    #[must_use]
    pub fn write_log_truncated(&self) -> bool {
        self.write_log_truncated
    }

    fn lazy_commit(&mut self, addr: u64) -> bool {
        let Some(budget): Option<u32> = self.lazy_budget else {
            return false;
        };
        if self.block_null_page && addr < NULL_RESERVED_REGION {
            return false;
        }
        let key: u64 = addr >> PAGE_BITS;
        if self.pages.contains_key(&key) {
            return true;
        }
        if self.lazy_used >= budget {
            return false;
        }
        self.pages.insert(
            key,
            Page {
                data: Box::new([0u8; PAGE_SIZE]),
                perm: Perm::RW,
            },
        );
        self.lazy_used += 1;
        true
    }

    pub fn map(&mut self, addr: u64, size: u64, perm: Perm) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        if size > MAX_MAP_BYTES {
            return Err(Error::GoblinParse(format!(
                "emu: refusing map of {size} bytes (exceeds {MAX_MAP_BYTES}-byte ceiling)"
            )));
        }
        let start: u64 = addr & !PAGE_MASK;
        let raw_end: u64 = addr.checked_add(size).ok_or_else(|| {
            Error::GoblinParse(format!(
                "emu: refusing map at 0x{addr:016x} of {size} bytes (address overflow)"
            ))
        })?;
        let end: u64 = raw_end.checked_add(PAGE_MASK).ok_or_else(|| {
            Error::GoblinParse(format!(
                "emu: refusing map at 0x{addr:016x} of {size} bytes (page alignment overflow)"
            ))
        })? & !PAGE_MASK;
        let requested_pages: u64 = end.checked_sub(start).ok_or_else(|| {
            Error::GoblinParse(format!(
                "emu: refusing map at 0x{addr:016x} of {size} bytes (address range inverted)"
            ))
        })? >> PAGE_BITS;
        if requested_pages > MAX_MAP_PAGES {
            return Err(Error::GoblinParse(format!(
                "emu: refusing map of {size} bytes spanning {requested_pages} pages (exceeds {MAX_MAP_PAGES}-page ceiling)"
            )));
        }
        for page_index in 0..requested_pages {
            let p: u64 = start.wrapping_add(page_index << PAGE_BITS);
            self.pages
                .entry(p >> PAGE_BITS)
                .or_insert_with(|| Page {
                    data: Box::new([0u8; PAGE_SIZE]),
                    perm,
                })
                .perm = perm;
        }
        Ok(())
    }

    #[must_use]
    pub fn perm_at(&self, addr: u64) -> Option<Perm> {
        self.pages.get(&(addr >> PAGE_BITS)).map(|p: &Page| p.perm)
    }

    pub fn protect(&mut self, addr: u64, size: u64, perm: Perm) -> Result<u64> {
        if size == 0 {
            return Ok(0);
        }
        if size > MAX_MAP_BYTES {
            return Err(Error::GoblinParse(format!(
                "emu: refusing protect of {size} bytes (exceeds {MAX_MAP_BYTES}-byte ceiling)"
            )));
        }
        let start: u64 = addr & !PAGE_MASK;
        let raw_end: u64 = addr.checked_add(size).ok_or_else(|| {
            Error::GoblinParse(format!(
                "emu: refusing protect at 0x{addr:016x} of {size} bytes (address overflow)"
            ))
        })?;
        let end: u64 = raw_end.checked_add(PAGE_MASK).ok_or_else(|| {
            Error::GoblinParse(format!(
                "emu: refusing protect at 0x{addr:016x} of {size} bytes (page alignment overflow)"
            ))
        })? & !PAGE_MASK;
        let pages: u64 = (end.saturating_sub(start)) >> PAGE_BITS;
        if pages > MAX_MAP_PAGES {
            return Err(Error::GoblinParse(format!(
                "emu: refusing protect spanning {pages} pages (exceeds {MAX_MAP_PAGES}-page ceiling)"
            )));
        }
        let mut changed: u64 = 0;
        for page_index in 0..pages {
            let p: u64 = start.wrapping_add(page_index << PAGE_BITS);
            let Some(page) = self.pages.get_mut(&(p >> PAGE_BITS)) else {
                continue;
            };
            page.perm = perm;
            changed += 1;
        }
        Ok(changed)
    }

    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        for (i, b) in bytes.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u64), *b)?;
        }
        Ok(())
    }

    pub fn write_unchecked(&mut self, addr: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let _ = self.poke_u8(addr.wrapping_add(i as u64), *b);
        }
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        if len > MAX_MAP_BYTES as usize {
            return Err(Error::GoblinParse(format!(
                "emu: refusing read of {len} bytes (exceeds {MAX_MAP_BYTES}-byte ceiling)"
            )));
        }
        let mut out: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            out.push(self.read_u8(addr.wrapping_add(i as u64))?);
        }
        Ok(out)
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8> {
        let key: u64 = addr >> PAGE_BITS;
        let off: usize = (addr & PAGE_MASK) as usize;
        let Some(page): Option<&Page> = self.pages.get(&key) else {
            if self.lazy_budget.is_some() {
                return Ok(0);
            }
            return Err(Error::GoblinParse(format!(
                "emu: read from unmapped 0x{addr:016x}"
            )));
        };
        if !page.perm.read {
            return Err(Error::GoblinParse(format!(
                "emu: read perm denied at 0x{addr:016x}"
            )));
        }
        Ok(page.data[off])
    }

    pub fn write_u8(&mut self, addr: u64, value: u8) -> Result<()> {
        let key: u64 = addr >> PAGE_BITS;
        let off: usize = (addr & PAGE_MASK) as usize;
        if !self.pages.contains_key(&key) && !self.lazy_commit(addr) {
            return Err(Error::GoblinParse(format!(
                "emu: write to unmapped 0x{addr:016x}"
            )));
        }
        {
            let page: &mut Page = self.pages.get_mut(&key).ok_or_else(|| {
                Error::GoblinParse(format!("emu: write to unmapped 0x{addr:016x}"))
            })?;
            if !page.perm.write {
                return Err(Error::GoblinParse(format!(
                    "emu: write perm denied at 0x{addr:016x}"
                )));
            }
            page.data[off] = value;
        }
        if let Some(log) = self.write_log.as_mut() {
            if log.len() < MAX_WRITE_LOG_ENTRIES {
                log.push((addr, value));
            } else {
                self.write_log_truncated = true;
            }
        }
        Ok(())
    }

    fn poke_u8(&mut self, addr: u64, value: u8) -> Result<()> {
        let key: u64 = addr >> PAGE_BITS;
        let off: usize = (addr & PAGE_MASK) as usize;
        let page: &mut Page = self
            .pages
            .get_mut(&key)
            .ok_or_else(|| Error::GoblinParse(format!("emu: poke unmapped 0x{addr:016x}")))?;
        page.data[off] = value;
        Ok(())
    }

    pub fn read_u16(&self, addr: u64) -> Result<u16> {
        Ok(u16::from_le_bytes([
            self.read_u8(addr)?,
            self.read_u8(addr.wrapping_add(1))?,
        ]))
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32> {
        Ok(u32::from_le_bytes([
            self.read_u8(addr)?,
            self.read_u8(addr.wrapping_add(1))?,
            self.read_u8(addr.wrapping_add(2))?,
            self.read_u8(addr.wrapping_add(3))?,
        ]))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64> {
        let lo: u32 = self.read_u32(addr)?;
        let hi: u32 = self.read_u32(addr.wrapping_add(4))?;
        Ok(u64::from(lo) | (u64::from(hi) << 32))
    }

    pub fn write_u16(&mut self, addr: u64, value: u16) -> Result<()> {
        let b: [u8; 2] = value.to_le_bytes();
        self.write_u8(addr, b[0])?;
        self.write_u8(addr.wrapping_add(1), b[1])
    }

    pub fn write_u32(&mut self, addr: u64, value: u32) -> Result<()> {
        let b: [u8; 4] = value.to_le_bytes();
        for (i, byte) in b.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u64), *byte)?;
        }
        Ok(())
    }

    pub fn write_u64(&mut self, addr: u64, value: u64) -> Result<()> {
        let b: [u8; 8] = value.to_le_bytes();
        for (i, byte) in b.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u64), *byte)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn read_lossy(&self, addr: u64, len: usize) -> Vec<u8> {
        let bounded: usize = len.min(MAX_MAP_BYTES as usize);
        let mut out: Vec<u8> = Vec::with_capacity(bounded);
        self.read_lossy_into(addr, bounded, &mut out);
        out
    }

    #[inline]
    pub fn read_lossy_into(&self, addr: u64, len: usize, out: &mut Vec<u8>) {
        let bounded: usize = len.min(MAX_MAP_BYTES as usize);
        out.clear();
        out.reserve(bounded);
        for i in 0..bounded {
            out.push(self.read_u8(addr.wrapping_add(i as u64)).unwrap_or(0));
        }
    }

    #[must_use]
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.pages.contains_key(&(addr >> PAGE_BITS))
    }

    pub fn page_keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.pages.keys().copied()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn map_and_rw_roundtrip() {
        let mut m: Memory = Memory::new();
        m.map(0x1000, 0x2000, Perm::RW).expect("map within ceiling");
        m.write(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(m.read(0x1000, 4).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        m.write_u32(0x2000, 0x1234_5678).unwrap();
        assert_eq!(m.read_u32(0x2000).unwrap(), 0x1234_5678);
    }

    #[test]
    fn unmapped_read_errors() {
        let m: Memory = Memory::new();
        assert!(m.read_u8(0x4000).is_err());
    }

    #[test]
    fn read_lossy_returns_zero_for_holes() {
        let mut m: Memory = Memory::new();
        m.map(0x1000, 0x1000, Perm::R).expect("map within ceiling");
        m.write_unchecked(0x1000, &[1, 2, 3, 4]);
        let snapshot: Vec<u8> = m.read_lossy(0x0FFE, 6);
        assert_eq!(snapshot, vec![0, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn lazy_commit_maps_on_write_and_zero_reads_when_enabled() {
        let mut m: Memory = Memory::new();
        m.enable_lazy_commit(2);
        assert_eq!(
            m.read_u8(0x5000).unwrap(),
            0,
            "unmapped read is lossy in lazy mode"
        );
        m.write_u8(0x5000, 0x42).unwrap();
        assert_eq!(
            m.read_u8(0x5000).unwrap(),
            0x42,
            "lazy-committed write must persist"
        );
    }

    #[test]
    fn lazy_commit_budget_is_a_hard_ceiling() {
        let mut m: Memory = Memory::new();
        m.enable_lazy_commit(1);
        m.write_u8(0x5000, 1).unwrap();
        let second: Result<()> = m.write_u8(0x9000, 1);
        assert!(
            second.is_err(),
            "a second distinct page beyond the budget must fault, not allocate unbounded"
        );
    }

    #[test]
    fn unmapped_write_without_lazy_still_faults() {
        let mut m: Memory = Memory::new();
        assert!(m.write_u8(0x4000, 1).is_err());
    }

    #[test]
    fn write_log_is_opt_in_ordered_and_decomposes_wide_stores() {
        let mut m: Memory = Memory::new();
        m.map(0x1000, 0x1000, Perm::RW).expect("map within ceiling");
        m.write_unchecked(0x1000, &[9, 9, 9, 9]);
        assert!(
            m.write_log().is_empty(),
            "logging is opt-in: writes before enable_write_log are not recorded"
        );
        m.enable_write_log();
        m.write_u8(0x1000, 0xAA).unwrap();
        m.write_u32(0x1004, 0x4433_2211).unwrap();
        assert_eq!(
            m.write_log(),
            &[
                (0x1000, 0xAA),
                (0x1004, 0x11),
                (0x1005, 0x22),
                (0x1006, 0x33),
                (0x1007, 0x44),
            ],
            "a wide store decomposes into ordered per-byte log entries little-endian"
        );
        assert!(!m.write_log_truncated());
    }

    #[test]
    fn map_above_ceiling_errors_without_allocating() {
        let mut m: Memory = Memory::new();
        let start: std::time::Instant = std::time::Instant::now();
        let hostile: Result<()> = m.map(0, 0xFFFF_F000, Perm::RWX);
        assert!(
            hostile.is_err(),
            "a near-4 GiB map must fault, never page-allocate gigabytes"
        );
        assert!(
            m.page_keys().next().is_none(),
            "a rejected oversize map must commit zero pages"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "rejection must be immediate"
        );
    }

    #[test]
    fn map_at_ceiling_is_page_bounded() {
        let mut m: Memory = Memory::new();
        m.map(0, MAX_MAP_BYTES, Perm::RW)
            .expect("a map exactly at the ceiling is allowed");
        let committed: usize = m.page_keys().count();
        assert_eq!(
            committed as u64,
            MAX_MAP_BYTES / (PAGE_SIZE as u64),
            "map must commit at most the ceiling's worth of pages"
        );
    }

    #[test]
    fn map_near_u64_max_rejects_address_wrap_without_allocating() {
        let mut m: Memory = Memory::new();
        let err: Error = m
            .map(u64::MAX - 0x800, 0x1000, Perm::RWX)
            .expect_err("wrapped map must fail");
        assert!(
            err.to_string().contains("address overflow"),
            "unexpected error: {err}"
        );
        assert!(
            m.page_keys().next().is_none(),
            "a wrapped map must commit zero pages"
        );
    }

    #[test]
    fn read_lossy_clamps_hostile_length() {
        let m: Memory = Memory::new();
        let out: Vec<u8> = m.read_lossy(0, usize::MAX);
        assert_eq!(
            out.len(),
            MAX_MAP_BYTES as usize,
            "read_lossy must clamp a hostile length to the ceiling, never allocate usize::MAX"
        );
    }

    #[test]
    fn read_rejects_hostile_length_in_lazy_mode_without_oom() {
        let mut m: Memory = Memory::new();
        m.enable_lazy_commit(1024);
        let start: std::time::Instant = std::time::Instant::now();
        let hostile: Result<Vec<u8>> = m.read(0, usize::MAX);
        assert!(
            hostile.is_err(),
            "a hostile read length must fault before pushing billions of lazy zero bytes"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "rejection must be immediate, never an unbounded push loop"
        );
        m.map(0x1000, 0x1000, Perm::R).expect("map within ceiling");
        m.write_unchecked(0x1000, &[1, 2, 3, 4]);
        assert_eq!(
            m.read(0x1000, 4).unwrap(),
            vec![1, 2, 3, 4],
            "a valid bounded read must still recover the bytes"
        );
    }
}
