#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for these crate-internal jump-table helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped across the workspace"
)]

use std::collections::BTreeSet;

mod vsa;

#[cfg(feature = "smt-solver")]
mod solver;

pub(crate) use vsa::ValueSet;
use vsa::{VsaResult, index_value_set};

#[cfg(feature = "smt-solver")]
pub use solver::{resolve_jump_table, resolve_jump_table_with};

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
    NotEqual(u64),
}

const fn is_contiguous_low_mask(mask: u64) -> bool {
    match mask.checked_add(1) {
        Some(next) => next & mask == 0,
        None => false,
    }
}

const fn index_bit_mask(index_bytes: u32) -> Option<u64> {
    match index_bytes {
        1..=8 => {
            let bits: u32 = index_bytes * 8;
            Some(if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            })
        }
        _ => None,
    }
}

const fn entry_bytes_valid(entry_bytes: u32) -> bool {
    matches!(entry_bytes, 1..=8)
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
    SolverRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    pub table_base: u64,
    pub bound_lo: u64,
    pub bound_hi: u64,
    pub entry_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveTier {
    CheapVsa,
    Solver,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VsaOutcome {
    Decided(JumpTableResolution),
    SolverRequired,
}

#[must_use]
pub fn resolve_jump_table_vsa(site: &IndirectSite, sections: &SectionMap) -> JumpTableResolution {
    match try_resolve_vsa(site, sections) {
        VsaOutcome::Decided(resolution) => resolution,
        VsaOutcome::SolverRequired => {
            JumpTableResolution::Abstain(JumpTableAbstain::SolverRequired)
        }
    }
}

pub(crate) fn try_resolve_vsa(site: &IndirectSite, sections: &SectionMap) -> VsaOutcome {
    let form: TableForm = site.form;
    if form.stride == 0 || !entry_bytes_valid(form.entry_bytes) {
        return VsaOutcome::Decided(JumpTableResolution::Abstain(
            JumpTableAbstain::StructureInvalid,
        ));
    }
    let Some(ceiling): Option<u64> = index_bit_mask(site.path.index_bytes) else {
        return VsaOutcome::Decided(JumpTableResolution::Abstain(
            JumpTableAbstain::StructureInvalid,
        ));
    };
    if sections.table_region_writable(form.table_base) {
        return VsaOutcome::Decided(JumpTableResolution::Abstain(
            JumpTableAbstain::WritableTable,
        ));
    }
    if site
        .path
        .bounds
        .iter()
        .any(|bound: &IndexBound| matches!(bound, IndexBound::NotEqual(_)))
        && site.default_target.is_none()
    {
        return VsaOutcome::Decided(JumpTableResolution::Abstain(
            JumpTableAbstain::UnsupportedConstraint,
        ));
    }
    let set: ValueSet = match index_value_set(&site.path.bounds, ceiling) {
        VsaResult::Exact(set) => set,
        VsaResult::Empty => {
            return VsaOutcome::Decided(JumpTableResolution::Abstain(
                JumpTableAbstain::EmptyFeasibleSet,
            ));
        }
        VsaResult::Unbounded => {
            return VsaOutcome::Decided(JumpTableResolution::Abstain(
                JumpTableAbstain::IndexUnbounded,
            ));
        }
        VsaResult::Unsupported => {
            return VsaOutcome::Decided(JumpTableResolution::Abstain(
                JumpTableAbstain::UnsupportedConstraint,
            ));
        }
        VsaResult::SolverRequired => return VsaOutcome::SolverRequired,
    };
    if set.max() > MAX_TABLE_ENTRIES - 1 || set.count() > MAX_TABLE_ENTRIES {
        return VsaOutcome::Decided(JumpTableResolution::Abstain(
            JumpTableAbstain::IndexUnbounded,
        ));
    }
    VsaOutcome::Decided(enumerate_value_set(&set, site, sections))
}

fn enumerate_value_set(
    set: &ValueSet,
    site: &IndirectSite,
    sections: &SectionMap,
) -> JumpTableResolution {
    let mut successors: Vec<Successor> = Vec::new();
    let mut rejected: Vec<(u64, RejectCause)> = Vec::new();
    for index in set.iter() {
        match read_table_target(&site.form, sections, index) {
            Ok(target) => successors.push(Successor {
                table_index: index,
                case_value: index.wrapping_add(site.form.case_base),
                target,
                kind: SuccessorKind::Case,
            }),
            Err(cause) => rejected.push((index, cause)),
        }
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
            bound_lo: set.min(),
            bound_hi: set.max(),
            entry_count: set.count(),
        },
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

    fn ground_truth_targets(
        site: &IndirectSite,
        sections: &SectionMap,
        indices: &[u64],
    ) -> Vec<u64> {
        let mut out: Vec<u64> = indices
            .iter()
            .filter_map(|index: &u64| read_table_target(&site.form, sections, *index).ok())
            .collect();
        out.sort_unstable();
        out.dedup();
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        let mut cases: Vec<(u64, u64)> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| (successor.case_value, successor.target))
            .collect();
        cases.sort_unstable();
        assert_eq!(cases, vec![(5, 0x1100), (6, 0x1140), (7, 0x1180)]);
    }

    #[test]
    fn bound_comes_from_the_constraint_not_the_physical_extent() {
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        assert_eq!(resolution.cases().len(), 8);
        assert_eq!(targets(&resolution), bodies.to_vec());
    }

    #[test]
    fn strided_mask_recovers_the_even_index_progression() {
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
            path: PathConstraint::new(4, vec![IndexBound::Mask(0x6)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        let indices: Vec<u64> = resolution
            .cases()
            .iter()
            .map(|successor: &Successor| successor.table_index)
            .collect();
        assert_eq!(indices, vec![0, 2, 4, 6]);
        let expected: Vec<u64> = ground_truth_targets(&site, &sections, &[0, 2, 4, 6]);
        assert_eq!(targets(&resolution), expected);
    }

    #[test]
    fn non_strided_mask_abstains_as_unsupported() {
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
            path: PathConstraint::new(4, vec![IndexBound::Mask(0xA)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::UnsupportedConstraint)
        );
    }

    #[test]
    fn vsa_resolved_set_is_a_superset_of_the_reachable_targets() {
        let bodies: [u64; 6] = [0x1100, 0x1108, 0x1110, 0x1118, 0x1120, 0x1128];
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
            path: PathConstraint::new(4, vec![IndexBound::UnsignedAtMost(5)]),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        let reachable: Vec<u64> = ground_truth_targets(&site, &sections, &[0, 1, 2, 3, 4, 5]);
        let recovered: Vec<u64> = targets(&resolution);
        assert!(
            reachable
                .iter()
                .all(|target: &u64| recovered.contains(target)),
            "every reachable target must appear in the recovered set"
        );
    }

    #[test]
    fn disequality_without_default_is_unsupported() {
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
            path: PathConstraint::new(
                4,
                vec![IndexBound::UnsignedAtMost(3), IndexBound::NotEqual(2)],
            ),
            default_target: None,
        };
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::UnsupportedConstraint)
        );
    }

    #[test]
    fn disequality_hole_defers_to_the_solver_tier() {
        let bodies: [u64; 4] = [0x1100, 0x1108, 0x1110, 0x1118];
        let sections: SectionMap = SectionMap::new(vec![
            code_section(&[0x1100, 0x1108, 0x1110, 0x1118, 0x1200]),
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
            path: PathConstraint::new(
                4,
                vec![IndexBound::UnsignedAtMost(3), IndexBound::NotEqual(2)],
            ),
            default_target: Some(0x1200),
        };
        assert_eq!(
            try_resolve_vsa(&site, &sections),
            VsaOutcome::SolverRequired
        );
        assert_eq!(
            resolve_jump_table_vsa(&site, &sections),
            JumpTableResolution::Abstain(JumpTableAbstain::SolverRequired)
        );
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
        let resolution: JumpTableResolution = resolve_jump_table_vsa(&site, &sections);
        assert_eq!(
            resolution,
            JumpTableResolution::Abstain(JumpTableAbstain::EmptyFeasibleSet)
        );
    }
}
