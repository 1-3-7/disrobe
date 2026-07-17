use std::collections::BTreeSet;

use oxiz::TermId;

use super::explore::SymexecBudget;
use super::solver::{Feasible, Guard, SymSolver};
use super::value::{BitWidth, CmpOp, Sym};

const MAX_TABLE_ENTRIES: u64 = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Perms {
    #[must_use]
    pub const fn ro() -> Self {
        Self {
            read: true,
            write: false,
            exec: false,
        }
    }

    #[must_use]
    pub const fn code() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
        }
    }

    #[must_use]
    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub perms: Perms,
    pub constant: bool,
    pub insn_starts: Option<BTreeSet<u64>>,
}

impl Section {
    #[must_use]
    pub const fn new(base: u64, bytes: Vec<u8>, perms: Perms, constant: bool) -> Self {
        Self {
            base,
            bytes,
            perms,
            constant,
            insn_starts: None,
        }
    }

    #[must_use]
    pub fn with_insn_starts(mut self, starts: BTreeSet<u64>) -> Self {
        self.insn_starts = Some(starts);
        self
    }

    const fn end(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOutcome {
    Value(u64),
    NotConstant,
    OutOfImage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecOutcome {
    Valid,
    NotExecutable,
    DecodeInvalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionMap {
    sections: Vec<Section>,
}

impl SectionMap {
    #[must_use]
    pub const fn new(sections: Vec<Section>) -> Self {
        Self { sections }
    }

    pub fn push(&mut self, section: Section) {
        self.sections.push(section);
    }

    fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section: &&Section| section.base <= addr && addr < section.end())
    }

    fn read_constant(&self, addr: u64, len: u64, endian: Endian) -> ReadOutcome {
        let Some(top): Option<u64> = addr.checked_add(len) else {
            return ReadOutcome::OutOfImage;
        };
        let Some(section): Option<&Section> = self
            .sections
            .iter()
            .find(|section: &&Section| section.base <= addr && top <= section.end())
        else {
            return ReadOutcome::OutOfImage;
        };
        if !section.constant || section.perms.write {
            return ReadOutcome::NotConstant;
        }
        let offset: usize = (addr - section.base) as usize;
        let width: usize = len as usize;
        let Some(slice): Option<&[u8]> = section.bytes.get(offset..offset + width) else {
            return ReadOutcome::OutOfImage;
        };
        ReadOutcome::Value(read_uint(slice, endian))
    }

    fn exec_check(&self, addr: u64) -> ExecOutcome {
        let Some(section): Option<&Section> = self.section_at(addr) else {
            return ExecOutcome::NotExecutable;
        };
        if !section.perms.exec {
            return ExecOutcome::NotExecutable;
        }
        match &section.insn_starts {
            Some(starts) if !starts.contains(&addr) => ExecOutcome::DecodeInvalid,
            Some(_) | None => ExecOutcome::Valid,
        }
    }

    fn table_region_writable(&self, addr: u64) -> bool {
        self.section_at(addr)
            .is_some_and(|section: &Section| section.perms.write || !section.constant)
    }
}

fn read_uint(bytes: &[u8], endian: Endian) -> u64 {
    let mut acc: u64 = 0;
    match endian {
        Endian::Little => {
            for (index, byte) in bytes.iter().enumerate() {
                acc |= u64::from(*byte) << (8 * index as u32);
            }
        }
        Endian::Big => {
            for byte in bytes {
                acc = (acc << 8) | u64::from(*byte);
            }
        }
    }
    acc
}

const fn sign_extend(raw: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 {
        return raw;
    }
    let shift: u32 = 64 - bits;
    (((raw << shift) as i64) >> shift) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    AbsolutePointer,
    RelativeOffset {
        addend_base: u64,
        signed: bool,
        shift: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableForm {
    pub table_base: u64,
    pub stride: u32,
    pub entry_bytes: u32,
    pub endian: Endian,
    pub entry: EntryKind,
    pub case_base: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexBound {
    UnsignedAtMost(u64),
    UnsignedLessThan(u64),
    UnsignedAtLeast(u64),
    Mask(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interval {
    Range { lo: u64, hi: u64 },
    Empty,
    Unbounded,
    Unsupported,
}

const fn is_contiguous_low_mask(mask: u64) -> bool {
    match mask.checked_add(1) {
        Some(next) => next & mask == 0,
        None => false,
    }
}

fn feasible_interval(bounds: &[IndexBound], ceiling: u64) -> Interval {
    let mut lo: u64 = 0;
    let mut hi: u64 = ceiling;
    let mut bounded_above: bool = false;
    for bound in bounds {
        match bound {
            IndexBound::UnsignedAtMost(value) => {
                hi = hi.min(*value);
                bounded_above = true;
            }
            IndexBound::UnsignedLessThan(value) => {
                let Some(top): Option<u64> = value.checked_sub(1) else {
                    return Interval::Empty;
                };
                hi = hi.min(top);
                bounded_above = true;
            }
            IndexBound::UnsignedAtLeast(value) => {
                lo = lo.max(*value);
            }
            IndexBound::Mask(mask) => {
                if !is_contiguous_low_mask(*mask) {
                    return Interval::Unsupported;
                }
                hi = hi.min(*mask);
                bounded_above = true;
            }
        }
    }
    if !bounded_above {
        return Interval::Unbounded;
    }
    if lo > hi {
        return Interval::Empty;
    }
    Interval::Range { lo, hi }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConstraint {
    pub index_bytes: u32,
    pub bounds: Vec<IndexBound>,
}

impl PathConstraint {
    #[must_use]
    pub const fn new(index_bytes: u32, bounds: Vec<IndexBound>) -> Self {
        Self {
            index_bytes,
            bounds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectSite {
    pub form: TableForm,
    pub path: PathConstraint,
    pub default_target: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessorKind {
    Case,
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Successor {
    pub table_index: u64,
    pub case_value: u64,
    pub target: u64,
    pub kind: SuccessorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCause {
    NotConstant,
    OutOfImage,
    NotExecutable,
    DecodeInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpTableAbstain {
    StructureInvalid,
    UnsupportedConstraint,
    IndexUnbounded,
    WritableTable,
    EmptyFeasibleSet,
    SolverBoundMismatch,
    IncompleteRecovery { rejected: Vec<(u64, RejectCause)> },
    SolverUnknown,
    SolverBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    pub table_base: u64,
    pub bound_lo: u64,
    pub bound_hi: u64,
    pub entry_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpTableResolution {
    Resolved {
        successors: Vec<Successor>,
        provenance: Provenance,
    },
    Abstain(JumpTableAbstain),
}

impl JumpTableResolution {
    #[must_use]
    pub const fn is_abstain(&self) -> bool {
        matches!(self, Self::Abstain(_))
    }

    #[must_use]
    pub fn successors(&self) -> &[Successor] {
        match self {
            Self::Resolved { successors, .. } => successors,
            Self::Abstain(_) => &[],
        }
    }

    #[must_use]
    pub fn cases(&self) -> Vec<Successor> {
        self.successors()
            .iter()
            .copied()
            .filter(|successor: &Successor| successor.kind == SuccessorKind::Case)
            .collect()
    }
}

#[must_use]
pub fn resolve_jump_table(site: &IndirectSite, sections: &SectionMap) -> JumpTableResolution {
    resolve_jump_table_with(site, sections, SymexecBudget::bounded_default())
}

#[must_use]
pub fn resolve_jump_table_with(
    site: &IndirectSite,
    sections: &SectionMap,
    budget: SymexecBudget,
) -> JumpTableResolution {
    let form: TableForm = site.form;
    if form.stride == 0 || BitWidth::from_bytes(form.entry_bytes).is_none() {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    }
    let Some(width): Option<BitWidth> = BitWidth::from_bytes(site.path.index_bytes) else {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    };
    if sections.table_region_writable(form.table_base) {
        return JumpTableResolution::Abstain(JumpTableAbstain::WritableTable);
    }
    let cap: u64 = MAX_TABLE_ENTRIES.saturating_sub(1).min(width.mask());
    let (lo, hi): (u64, u64) = match feasible_interval(&site.path.bounds, width.mask()) {
        Interval::Range { lo, hi } => (lo, hi),
        Interval::Empty => return JumpTableResolution::Abstain(JumpTableAbstain::EmptyFeasibleSet),
        Interval::Unbounded => {
            return JumpTableResolution::Abstain(JumpTableAbstain::IndexUnbounded);
        }
        Interval::Unsupported => {
            return JumpTableResolution::Abstain(JumpTableAbstain::UnsupportedConstraint);
        }
    };
    if hi > cap || hi.saturating_sub(lo) >= MAX_TABLE_ENTRIES {
        return JumpTableResolution::Abstain(JumpTableAbstain::IndexUnbounded);
    }
    let mut resolver: Resolver = Resolver::new(width, budget);
    if resolver.assert_bounds(&site.path.bounds).is_err() {
        return JumpTableResolution::Abstain(JumpTableAbstain::StructureInvalid);
    }
    resolver.resolve(site, sections, lo, hi)
}

struct Resolver {
    solver: SymSolver,
    index: Sym,
    width: BitWidth,
    pi: Vec<TermId>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resolver")
            .field("width", &self.width)
            .field("pi_len", &self.pi.len())
            .finish_non_exhaustive()
    }
}

impl Resolver {
    fn new(width: BitWidth, budget: SymexecBudget) -> Self {
        let mut solver: SymSolver = SymSolver::new(budget.solver());
        let index: Sym = solver.fresh_havoc(width);
        Self {
            solver,
            index,
            width,
            pi: Vec::new(),
        }
    }

    fn assert_bounds(&mut self, bounds: &[IndexBound]) -> Result<(), ()> {
        for bound in bounds {
            let predicate: Sym = self.bound_predicate(*bound);
            let Some(term): Option<TermId> = pred_of(predicate) else {
                return Err(());
            };
            self.pi.push(term);
        }
        Ok(())
    }

    fn bound_predicate(&mut self, bound: IndexBound) -> Sym {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        match bound {
            IndexBound::UnsignedAtMost(value) | IndexBound::Mask(value) => self.solver.compare(
                CmpOp::Ule,
                index,
                Sym::constant(width, value),
                BitWidth::BYTE,
            ),
            IndexBound::UnsignedLessThan(value) => self.solver.compare(
                CmpOp::Ult,
                index,
                Sym::constant(width, value),
                BitWidth::BYTE,
            ),
            IndexBound::UnsignedAtLeast(value) => self.solver.compare(
                CmpOp::Ule,
                Sym::constant(width, value),
                index,
                BitWidth::BYTE,
            ),
        }
    }

    fn sat(&mut self, predicate: Sym) -> Feasible {
        let Some(term): Option<TermId> = pred_of(predicate) else {
            return Feasible::Unknown;
        };
        self.solver.feasible(&self.pi, Guard::Term(term))
    }

    fn index_gt(&mut self, bound: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Ult,
            Sym::constant(width, bound),
            index,
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn index_lt(&mut self, bound: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Ult,
            index,
            Sym::constant(width, bound),
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn index_eq(&mut self, value: u64) -> Feasible {
        let width: BitWidth = self.width;
        let index: Sym = self.index;
        let predicate: Sym = self.solver.compare(
            CmpOp::Eq,
            index,
            Sym::constant(width, value),
            BitWidth::BYTE,
        );
        self.sat(predicate)
    }

    fn confirm_bounds(&mut self, lo: u64, hi: u64) -> Option<JumpTableAbstain> {
        match self.index_gt(hi) {
            Feasible::Unsat => {}
            Feasible::Sat => return Some(JumpTableAbstain::SolverBoundMismatch),
            Feasible::Unknown => return Some(JumpTableAbstain::SolverUnknown),
        }
        if lo > 0 {
            match self.index_lt(lo) {
                Feasible::Unsat => {}
                Feasible::Sat => return Some(JumpTableAbstain::SolverBoundMismatch),
                Feasible::Unknown => return Some(JumpTableAbstain::SolverUnknown),
            }
        }
        None
    }

    fn resolve(
        &mut self,
        site: &IndirectSite,
        sections: &SectionMap,
        lo: u64,
        hi: u64,
    ) -> JumpTableResolution {
        if self.solver.cumulative_exhausted() {
            return JumpTableResolution::Abstain(JumpTableAbstain::SolverBudget);
        }
        if let Some(reason) = self.confirm_bounds(lo, hi) {
            return JumpTableResolution::Abstain(reason);
        }
        self.enumerate(site, sections, lo, hi)
    }

    fn enumerate(
        &mut self,
        site: &IndirectSite,
        sections: &SectionMap,
        lo: u64,
        hi: u64,
    ) -> JumpTableResolution {
        let mut successors: Vec<Successor> = Vec::new();
        let mut rejected: Vec<(u64, RejectCause)> = Vec::new();
        let mut index: u64 = lo;
        while index <= hi {
            if self.solver.cumulative_exhausted() {
                return JumpTableResolution::Abstain(JumpTableAbstain::SolverBudget);
            }
            match self.index_eq(index) {
                Feasible::Sat => match read_table_target(&site.form, sections, index) {
                    Ok(target) => successors.push(Successor {
                        table_index: index,
                        case_value: index.wrapping_add(site.form.case_base),
                        target,
                        kind: SuccessorKind::Case,
                    }),
                    Err(cause) => rejected.push((index, cause)),
                },
                Feasible::Unsat => {
                    return JumpTableResolution::Abstain(JumpTableAbstain::SolverBoundMismatch);
                }
                Feasible::Unknown => {
                    return JumpTableResolution::Abstain(JumpTableAbstain::SolverUnknown);
                }
            }
            let Some(next): Option<u64> = index.checked_add(1) else {
                break;
            };
            index = next;
        }
        if !rejected.is_empty() {
            return JumpTableResolution::Abstain(JumpTableAbstain::IncompleteRecovery { rejected });
        }
        if let Some(default) = site.default_target
            && sections.exec_check(default) == ExecOutcome::Valid
        {
            successors.push(Successor {
                table_index: u64::MAX,
                case_value: u64::MAX,
                target: default,
                kind: SuccessorKind::Default,
            });
        }
        JumpTableResolution::Resolved {
            successors,
            provenance: Provenance {
                table_base: site.form.table_base,
                bound_lo: lo,
                bound_hi: hi,
                entry_count: hi - lo + 1,
            },
        }
    }
}

fn read_table_target(
    form: &TableForm,
    sections: &SectionMap,
    index: u64,
) -> Result<u64, RejectCause> {
    let offset: u64 = index.wrapping_mul(u64::from(form.stride));
    let addr: u64 = form.table_base.wrapping_add(offset);
    let raw: u64 = match sections.read_constant(addr, u64::from(form.entry_bytes), form.endian) {
        ReadOutcome::Value(value) => value,
        ReadOutcome::NotConstant => return Err(RejectCause::NotConstant),
        ReadOutcome::OutOfImage => return Err(RejectCause::OutOfImage),
    };
    let target: u64 = match form.entry {
        EntryKind::AbsolutePointer => raw,
        EntryKind::RelativeOffset {
            addend_base,
            signed,
            shift,
        } => {
            let bits: u32 = form.entry_bytes.saturating_mul(8);
            let extended: u64 = if signed { sign_extend(raw, bits) } else { raw };
            addend_base.wrapping_add(extended.wrapping_shl(shift))
        }
    };
    match sections.exec_check(target) {
        ExecOutcome::Valid => Ok(target),
        ExecOutcome::NotExecutable => Err(RejectCause::NotExecutable),
        ExecOutcome::DecodeInvalid => Err(RejectCause::DecodeInvalid),
    }
}

const fn pred_of(value: Sym) -> Option<TermId> {
    match value {
        Sym::Bool { pred, .. } => Some(pred),
        Sym::Const { .. } | Sym::Bv { .. } => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    const TEXT_BASE: u64 = 0x1000;
    const RODATA_BASE: u64 = 0x4000;

    fn code_section(starts: &[u64]) -> Section {
        let set: BTreeSet<u64> = starts.iter().copied().collect();
        Section::new(TEXT_BASE, vec![0x90; 0x400], Perms::code(), false).with_insn_starts(set)
    }

    fn le32(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value: &u32| value.to_le_bytes())
            .collect()
    }

    fn le64(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value: &u64| value.to_le_bytes())
            .collect()
    }

    fn rodata(bytes: Vec<u8>) -> Section {
        Section::new(RODATA_BASE, bytes, Perms::ro(), true)
    }

    fn targets(resolution: &JumpTableResolution) -> Vec<u64> {
        let mut out: Vec<u64> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| successor.target)
            .collect();
        out.sort_unstable();
        out
    }

    #[test]
    fn absolute_eight_byte_table_recovers_exact_target_set() {
        let bodies: [u64; 4] = [0x1100, 0x1140, 0x1180, 0x1120];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1120, 0x1140, 0x1180, 0x1200]),
            rodata(le64(&bodies)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: Some(0x1200),
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(targets(&resolution), vec![0x1100, 0x1120, 0x1140, 0x1180]);
        assert_eq!(resolution.cases().len(), 4);
        let default: Vec<&Successor> = resolution
            .successors()
            .iter()
            .filter(|successor: &&Successor| successor.kind == SuccessorKind::Default)
            .collect();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].target, 0x1200);
    }

    #[test]
    fn relative_signed_four_byte_pic_table_recovers_targets() {
        let bodies: [u64; 4] = [0x1100, 0x1180, 0x1200, 0x1140];
        let offsets: Vec<u32> = bodies
            .iter()
            .map(|body: &u64| (body.wrapping_sub(RODATA_BASE)) as u32)
            .collect();
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1140, 0x1180, 0x1200, 0x1300]),
            rodata(le32(&offsets)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 4,
                entry_bytes: 4,
                endian: Endian::Little,
                entry: EntryKind::RelativeOffset {
                    addend_base: RODATA_BASE,
                    signed: true,
                    shift: 0,
                },
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: Some(0x1300),
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(targets(&resolution), vec![0x1100, 0x1140, 0x1180, 0x1200]);
    }

    #[test]
    fn sublow_normalization_reports_shifted_case_values() {
        let bodies: [u64; 3] = [0x1100, 0x1140, 0x1180];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1140, 0x1180, 0x1200]),
            rodata(le64(&bodies)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 5,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(2)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        let mut cases: Vec<(u64, u64)> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| (successor.case_value, successor.target))
            .collect();
        cases.sort_unstable();
        assert_eq!(cases, vec![(5, 0x1100), (6, 0x1140), (7, 0x1180)]);
    }

    #[test]
    fn bound_comes_from_the_solver_not_the_physical_extent() {
        let bodies: [u64; 8] = [
            0x1100, 0x1108, 0x1110, 0x1118, 0x1120, 0x1128, 0x1130, 0x1138,
        ];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(targets(&resolution), vec![0x1100, 0x1108, 0x1110, 0x1118]);
        assert!(
            resolution
                .cases()
                .iter()
                .all(|successor: &Successor| successor.table_index <= 3),
            "no in-image-but-out-of-bound entry may be fabricated"
        );
    }

    #[test]
    fn unbounded_computed_goto_abstains() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, Vec::new()),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::IndexUnbounded)
        );
    }

    #[test]
    fn writable_table_abstains() {
        let bodies: [u64; 2] = [0x1100, 0x1108];
        let writable: Section = Section::new(RODATA_BASE, le64(&bodies), Perms::rw(), false);
        let sections: SectionMap = SectionMap::new(vec![code_section(&bodies), writable]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(1)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::WritableTable)
        );
    }

    #[test]
    fn decoy_table_pointing_out_of_code_abstains_via_the_canary() {
        let data_base: u64 = 0x8000;
        let decoys: [u64; 4] = [0x8010, 0x8020, 0x8030, 0x8040];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1108]),
            Section::new(data_base, vec![0u8; 0x100], Perms::rw(), false),
            rodata(le64(&decoys)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(3)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        let JumpTableResolution::Abstain(JumpTableAbstain::IncompleteRecovery { rejected }) =
            resolution
        else {
            panic!("a table whose entries leave executable memory must abstain: {resolution:?}");
        };
        assert_eq!(rejected.len(), 4);
        assert!(
            rejected
                .iter()
                .all(|(_, cause): &(u64, RejectCause)| *cause == RejectCause::NotExecutable)
        );
    }

    #[test]
    fn canary_fires_when_a_feasible_entry_is_unreadable() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(4)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        let JumpTableResolution::Abstain(JumpTableAbstain::IncompleteRecovery { rejected }) =
            resolution
        else {
            panic!("index 4 is feasible but its entry is out of the table: {resolution:?}");
        };
        assert_eq!(rejected, vec![(4, RejectCause::OutOfImage)]);
    }

    #[test]
    fn decode_invalid_target_inside_an_instruction_abstains() {
        let bodies: [u64; 3] = [0x1100, 0x1108, 0x1111];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1108, 0x1110]),
            rodata(le64(&bodies)),
        ]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(2)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        let JumpTableResolution::Abstain(JumpTableAbstain::IncompleteRecovery { rejected }) =
            resolution
        else {
            panic!("a mid-instruction target is not a valid decode: {resolution:?}");
        };
        assert_eq!(rejected, vec![(2, RejectCause::DecodeInvalid)]);
    }

    #[test]
    fn valid_dense_table_passes_the_completeness_canary() {
        let bodies: [u64; 5] = [0x1100, 0x1108, 0x1110, 0x1118, 0x1120];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(4)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert!(!resolution.is_abstain());
        if let JumpTableResolution::Resolved { provenance, .. } = resolution {
            assert_eq!(provenance.entry_count, 5);
            assert_eq!(provenance.bound_lo, 0);
            assert_eq!(provenance.bound_hi, 4);
        }
    }

    #[test]
    fn mask_bounded_index_recovers_the_masked_range() {
        let bodies: [u64; 8] = [
            0x1100, 0x1108, 0x1110, 0x1118, 0x1120, 0x1128, 0x1130, 0x1138,
        ];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(4, vec![IndexBound::Mask(0x7)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(resolution.cases().len(), 8);
        assert_eq!(targets(&resolution), bodies.to_vec());
    }

    #[test]
    fn empty_feasible_set_abstains() {
        let bodies: [u64; 2] = [0x1100, 0x1108];
        let sections: SectionMap =
            SectionMap::new(vec![code_section(&bodies), rodata(le64(&bodies))]);
        let site: IndirectSite = IndirectSite {
            form: TableForm {
                table_base: RODATA_BASE,
                stride: 8,
                entry_bytes: 8,
                endian: Endian::Little,
                entry: EntryKind::AbsolutePointer,
                case_base: 0,
            },
            path: PathConstraint::new(
                4,
                vec![
                    IndexBound::UnsignedAtMost(1),
                    IndexBound::UnsignedAtLeast(5),
                ],
            ),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::EmptyFeasibleSet)
        );
    }
}
