//! Paged virtual address space for the stub emulator.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Page size in bytes (4 KiB, matching the smallest meaningful Windows page).
pub const PAGE_SIZE: usize = 0x1000;

/// `log2(PAGE_SIZE)` - used for page-index arithmetic.
pub const PAGE_BITS: u32 = 12;

const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;

/// The null page is never lazily committed: an SEH-driven packer (PECompact
/// 2.x) relies on a deliberate write to address 0 faulting to enter its
/// decompressor via the SEH chain, and silently committing that page would mask
/// the transfer. Kept to a single 4 KiB page so legitimate lazy scratch writes
/// just above the null guard still commit on demand.
const NULL_RESERVED_REGION: u64 = PAGE_SIZE as u64;

/// Per-page permission bits. Packer stubs frequently allocate RWX so we keep
/// the model coarse: each page either is or is not readable / writeable /
/// executable.
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

/// Virtual address space backed by sparse 4 KiB pages.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    pages: BTreeMap<u64, Page>,
    lazy_budget: Option<u32>,
    lazy_used: u32,
    block_null_page: bool,
}

impl Memory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable bounded lazy commit of zero-filled `RW` pages on demand.
    ///
    /// When enabled, a write to an unmapped page commits that single 4 KiB page
    /// (counted against `max_pages`), and a read from an unmapped page yields
    /// `0` instead of faulting. This models the on-demand committal a live
    /// Windows loader performs for a packer wrapper's scratch regions (notably
    /// Petite's outer SEH bootstrap, which scribbles below `ImageBase`). The
    /// `max_pages` ceiling is a hard DoS guard: once exhausted, unmapped writes
    /// fault as before, so a hostile input cannot drive unbounded allocation.
    /// Instruction fetch and control-flow targets are unaffected - they consult
    /// [`Self::is_mapped`] directly, so an unmapped branch still surfaces as the
    /// OEP transfer rather than being lazily committed.
    pub fn enable_lazy_commit(&mut self, max_pages: u32) {
        self.lazy_budget = Some(max_pages);
    }

    /// Refuse to lazily commit the null page so a deliberate write to address 0
    /// faults instead of silently succeeding. SEH-driven packers (PECompact 2.x)
    /// rely on that fault to enter their decompressor via the SEH chain; without
    /// it the transfer is masked and the stub runs off into the marker data.
    /// Enabled automatically by [`super::cpu::Cpu::enable_seh_dispatch`].
    pub fn block_null_page(&mut self) {
        self.block_null_page = true;
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

    pub fn map(&mut self, addr: u64, size: u64, perm: Perm) {
        if size == 0 {
            return;
        }
        let start: u64 = addr & !PAGE_MASK;
        let end: u64 = (addr.wrapping_add(size).wrapping_add(PAGE_MASK)) & !PAGE_MASK;
        let mut p: u64 = start;
        while p < end {
            self.pages.entry(p >> PAGE_BITS).or_insert_with(|| Page {
                data: Box::new([0u8; PAGE_SIZE]),
                perm,
            });
            if let Some(existing) = self.pages.get_mut(&(p >> PAGE_BITS)) {
                existing.perm = perm;
            }
            p = p.wrapping_add(PAGE_SIZE as u64);
        }
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
        let page: &mut Page = self
            .pages
            .get_mut(&key)
            .ok_or_else(|| Error::GoblinParse(format!("emu: write to unmapped 0x{addr:016x}")))?;
        if !page.perm.write {
            return Err(Error::GoblinParse(format!(
                "emu: write perm denied at 0x{addr:016x}"
            )));
        }
        page.data[off] = value;
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

    /// Read a contiguous range across pages, returning zero for any unmapped
    /// or unreadable byte. Used by callers that want to snapshot the entire
    /// post-emulation image without aborting on holes.
    #[must_use]
    pub fn read_lossy(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            out.push(self.read_u8(addr.wrapping_add(i as u64)).unwrap_or(0));
        }
        out
    }

    #[must_use]
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.pages.contains_key(&(addr >> PAGE_BITS))
    }

    /// Return every mapped page key, ascending.
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
        m.map(0x1000, 0x2000, Perm::RW);
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
        m.map(0x1000, 0x1000, Perm::R);
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
}
