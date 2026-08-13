use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::moduledata::build_minor;
use crate::pclntab::{LocatedPclntab, PclntabHeader, PclntabVersion, read_u32};
use crate::symbols::{FuncTabEntry, GoFunc, GoSymbols, func_table, read_word};

const MAX_PCDATA_ENTRIES: u32 = 64;
const MAX_LISTED_DEFER_FUNCS: usize = 1 << 16;

const RUNTIME_DEFER_SYMBOLS: [&str; 9] = [
    "runtime.deferproc",
    "runtime.deferprocStack",
    "runtime.deferprocat",
    "runtime.deferrangefunc",
    "runtime.deferreturn",
    "runtime.gopanic",
    "runtime.gorecover",
    "runtime.panicwrap",
    "runtime.sigpanic",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeferLowering {
    OpenCoded,
    CallBased,
}

impl DeferLowering {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenCoded => "open-coded",
            Self::CallBased => "call-based",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferFunc {
    pub name: String,
    pub entry: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
    pub lowering: DeferLowering,
    pub deferreturn_offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferreturn_va: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDeferHook {
    pub name: String,
    pub entry: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum DeferSupport {
    Recovered,
    PclntabAbsent,
    LayoutUnsupported {
        pclntab: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build_version: Option<String>,
    },
    LayoutRejected {
        pclntab: String,
        open_coded_without_deferreturn: usize,
    },
    FuncTableUnreadable {
        pclntab: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferReport {
    pub support: DeferSupport,
    pub scanned_functions: usize,
    pub open_coded_functions: usize,
    pub call_based_functions: usize,
    pub unreadable_functions: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    pub functions: Vec<DeferFunc>,
    pub runtime_hooks: Vec<RuntimeDeferHook>,
}

impl DeferReport {
    const fn empty(support: DeferSupport) -> Self {
        Self {
            support,
            scanned_functions: 0,
            open_coded_functions: 0,
            call_based_functions: 0,
            unreadable_functions: 0,
            truncated: false,
            functions: Vec::new(),
            runtime_hooks: Vec::new(),
        }
    }

    #[must_use]
    pub const fn pclntab_absent() -> Self {
        Self::empty(DeferSupport::PclntabAbsent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuncdataSlots {
    GofuncOffsets,
    AbsolutePointers,
}

#[derive(Debug, Clone, Copy)]
struct FuncLayout {
    deferreturn_off: usize,
    npcdata_off: usize,
    nfuncdata_off: usize,
    struct_size: usize,
    slots: FuncdataSlots,
    open_coded_index: u8,
}

const fn layout_for(
    version: PclntabVersion,
    ptr_size: usize,
    build_minor_version: Option<u32>,
) -> Option<FuncLayout> {
    let layout: FuncLayout = match version {
        PclntabVersion::Go120 => FuncLayout {
            deferreturn_off: 12,
            npcdata_off: 28,
            nfuncdata_off: 43,
            struct_size: 44,
            slots: FuncdataSlots::GofuncOffsets,
            open_coded_index: 4,
        },
        PclntabVersion::Go118 => FuncLayout {
            deferreturn_off: 12,
            npcdata_off: 28,
            nfuncdata_off: 39,
            struct_size: 40,
            slots: FuncdataSlots::GofuncOffsets,
            open_coded_index: 4,
        },
        PclntabVersion::Go116 => FuncLayout {
            deferreturn_off: ptr_size + 8,
            npcdata_off: ptr_size + 24,
            nfuncdata_off: ptr_size + 35,
            struct_size: ptr_size + 36,
            slots: FuncdataSlots::AbsolutePointers,
            open_coded_index: 4,
        },
        PclntabVersion::Go12 => match build_minor_version {
            Some(13..=15) => FuncLayout {
                deferreturn_off: ptr_size + 8,
                npcdata_off: ptr_size + 24,
                nfuncdata_off: ptr_size + 31,
                struct_size: ptr_size + 32,
                slots: FuncdataSlots::AbsolutePointers,
                open_coded_index: 5,
            },
            _ => return None,
        },
    };
    Some(layout)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FuncDeferView {
    deferreturn: u32,
    open_coded: bool,
}

fn funcdata_array_base(
    header: &PclntabHeader,
    layout: FuncLayout,
    struct_off: usize,
    npcdata: u32,
) -> Option<usize> {
    let base: usize = struct_off
        .checked_add(layout.struct_size)?
        .checked_add((npcdata as usize).checked_mul(4)?)?;
    let realign: bool = layout.slots == FuncdataSlots::AbsolutePointers
        && header.ptr_size == 8
        && !header
            .section_addr
            .wrapping_add(base as u64)
            .is_multiple_of(8);
    if realign {
        base.checked_add(4)
    } else {
        Some(base)
    }
}

fn read_func_defer_view(
    header: &PclntabHeader,
    body: &[u8],
    layout: FuncLayout,
    struct_off: usize,
) -> Option<FuncDeferView> {
    let deferreturn_at: usize = struct_off.checked_add(layout.deferreturn_off)?;
    let deferreturn: u32 = read_u32(body, deferreturn_at, header.endian).ok()?;
    let npcdata_at: usize = struct_off.checked_add(layout.npcdata_off)?;
    let npcdata: u32 = read_u32(body, npcdata_at, header.endian).ok()?;
    if npcdata > MAX_PCDATA_ENTRIES {
        return None;
    }
    let nfuncdata_at: usize = struct_off.checked_add(layout.nfuncdata_off)?;
    let nfuncdata: u8 = *body.get(nfuncdata_at)?;
    if nfuncdata <= layout.open_coded_index {
        return Some(FuncDeferView {
            deferreturn,
            open_coded: false,
        });
    }
    let base: usize = funcdata_array_base(header, layout, struct_off, npcdata)?;
    let index: usize = layout.open_coded_index as usize;
    let open_coded: bool = match layout.slots {
        FuncdataSlots::GofuncOffsets => {
            let at: usize = base.checked_add(index.checked_mul(4)?)?;
            read_u32(body, at, header.endian).ok()? != u32::MAX
        }
        FuncdataSlots::AbsolutePointers => {
            let stride: usize = header.ptr_size as usize;
            let at: usize = base.checked_add(index.checked_mul(stride)?)?;
            read_word(body, at, header).ok()? != 0
        }
    };
    Some(FuncDeferView {
        deferreturn,
        open_coded,
    })
}

fn collect_runtime_hooks(symbols: &GoSymbols) -> Vec<RuntimeDeferHook> {
    let by_name: BTreeMap<&str, &GoFunc> = symbols
        .funcs
        .iter()
        .map(|f: &GoFunc| (f.name.as_str(), f))
        .collect();
    RUNTIME_DEFER_SYMBOLS
        .iter()
        .filter_map(|name: &&str| {
            by_name.get(*name).map(|f: &&GoFunc| RuntimeDeferHook {
                name: (*name).to_owned(),
                entry: f.entry,
                va: f.va,
            })
        })
        .collect()
}

#[must_use]
pub fn recover_defers(
    located: &LocatedPclntab<'_>,
    symbols: &GoSymbols,
    build_version: Option<&str>,
) -> DeferReport {
    let header: &PclntabHeader = &located.header;
    let body: &[u8] = located.data;
    let pclntab: String = header.version.label().to_owned();
    let Some(layout): Option<FuncLayout> = layout_for(
        header.version,
        header.ptr_size as usize,
        build_minor(build_version),
    ) else {
        return DeferReport::empty(DeferSupport::LayoutUnsupported {
            pclntab,
            build_version: build_version.map(str::to_owned),
        });
    };
    let Ok(table): crate::error::Result<Vec<FuncTabEntry>> = func_table(header, body) else {
        return DeferReport::empty(DeferSupport::FuncTableUnreadable { pclntab });
    };

    let by_entry: BTreeMap<u64, &GoFunc> = symbols
        .funcs
        .iter()
        .map(|f: &GoFunc| (f.entry, f))
        .collect();
    let mut functions: Vec<DeferFunc> = Vec::new();
    let mut unreadable: usize = 0;
    let mut violations: usize = 0;
    let mut truncated: bool = false;

    for slot in &table {
        let Some(view): Option<FuncDeferView> =
            read_func_defer_view(header, body, layout, slot.struct_off)
        else {
            unreadable += 1;
            continue;
        };
        if view.open_coded && view.deferreturn == 0 {
            violations += 1;
            continue;
        }
        if view.deferreturn == 0 {
            continue;
        }
        let Some(func): Option<&&GoFunc> = by_entry.get(&slot.entry) else {
            unreadable += 1;
            continue;
        };
        if functions.len() >= MAX_LISTED_DEFER_FUNCS {
            truncated = true;
            break;
        }
        functions.push(DeferFunc {
            name: func.name.clone(),
            entry: slot.entry,
            va: func.va,
            lowering: if view.open_coded {
                DeferLowering::OpenCoded
            } else {
                DeferLowering::CallBased
            },
            deferreturn_offset: view.deferreturn,
            deferreturn_va: func
                .va
                .and_then(|va: u64| va.checked_add(u64::from(view.deferreturn))),
        });
    }

    if violations > 0 {
        return DeferReport::empty(DeferSupport::LayoutRejected {
            pclntab,
            open_coded_without_deferreturn: violations,
        });
    }

    functions.sort_by(|a: &DeferFunc, b: &DeferFunc| {
        a.entry.cmp(&b.entry).then_with(|| a.name.cmp(&b.name))
    });
    functions.dedup();
    let open_coded_functions: usize = functions
        .iter()
        .filter(|f: &&DeferFunc| f.lowering == DeferLowering::OpenCoded)
        .count();
    let call_based_functions: usize = functions.len().saturating_sub(open_coded_functions);

    DeferReport {
        support: DeferSupport::Recovered,
        scanned_functions: table.len(),
        open_coded_functions,
        call_based_functions,
        unreadable_functions: unreadable,
        truncated,
        functions,
        runtime_hooks: collect_runtime_hooks(symbols),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::binary::Endian;

    fn header(version: PclntabVersion, ptr_size: u8, section_addr: u64) -> PclntabHeader {
        PclntabHeader {
            version,
            quantum: 1,
            ptr_size,
            endian: Endian::Little,
            n_funcs: 0,
            n_files: 0,
            text_start: 0,
            funcname_off: 0,
            cu_off: 0,
            filetab_off: 0,
            pctab_off: 0,
            funcdata_off: 0,
            section_addr,
            section_len: 0,
        }
    }

    #[test]
    fn go12_layout_needs_a_build_version_in_the_verified_band() {
        assert!(layout_for(PclntabVersion::Go12, 8, None).is_none());
        assert!(layout_for(PclntabVersion::Go12, 8, Some(11)).is_none());
        assert!(layout_for(PclntabVersion::Go12, 8, Some(16)).is_none());
        let layout: FuncLayout = layout_for(PclntabVersion::Go12, 8, Some(15)).unwrap();
        assert_eq!(layout.open_coded_index, 5);
        assert_eq!(layout.struct_size, 40);
    }

    #[test]
    fn modern_layouts_use_funcdata_index_four() {
        for version in [
            PclntabVersion::Go116,
            PclntabVersion::Go118,
            PclntabVersion::Go120,
        ] {
            let layout: FuncLayout = layout_for(version, 8, Some(20)).unwrap();
            assert_eq!(layout.open_coded_index, 4);
        }
    }

    #[test]
    fn pointer_slots_realign_to_the_pointer_width() {
        let layout: FuncLayout = layout_for(PclntabVersion::Go116, 8, None).unwrap();
        assert_eq!(layout.struct_size, 44);
        let aligned: PclntabHeader = header(PclntabVersion::Go116, 8, 0x1000);
        assert_eq!(funcdata_array_base(&aligned, layout, 0, 1), Some(48));
        assert_eq!(funcdata_array_base(&aligned, layout, 0, 2), Some(56));
        assert_eq!(funcdata_array_base(&aligned, layout, 4, 1), Some(56));
        let shifted: PclntabHeader = header(PclntabVersion::Go116, 8, 0x1004);
        assert_eq!(funcdata_array_base(&shifted, layout, 0, 1), Some(52));
        let narrow: FuncLayout = layout_for(PclntabVersion::Go12, 4, Some(15)).unwrap();
        assert_eq!(narrow.struct_size, 36);
        let narrow_header: PclntabHeader = header(PclntabVersion::Go12, 4, 0x1000);
        assert_eq!(funcdata_array_base(&narrow_header, narrow, 0, 1), Some(40));
        assert_eq!(funcdata_array_base(&narrow_header, narrow, 0, 2), Some(44));
    }

    #[test]
    fn implausible_pcdata_count_refuses_the_function() {
        let layout: FuncLayout = layout_for(PclntabVersion::Go120, 8, None).unwrap();
        let head: PclntabHeader = header(PclntabVersion::Go120, 8, 0);
        let mut body: Vec<u8> = vec![0u8; 512];
        body[12..16].copy_from_slice(&4u32.to_le_bytes());
        body[28..32].copy_from_slice(&(MAX_PCDATA_ENTRIES + 1).to_le_bytes());
        body[43] = 8;
        assert_eq!(read_func_defer_view(&head, &body, layout, 0), None);
    }

    #[test]
    fn truncated_func_struct_refuses_instead_of_panicking() {
        let layout: FuncLayout = layout_for(PclntabVersion::Go120, 8, None).unwrap();
        let head: PclntabHeader = header(PclntabVersion::Go120, 8, 0);
        for len in 0..64usize {
            let body: Vec<u8> = vec![0xffu8; len];
            let _ignored: Option<FuncDeferView> = read_func_defer_view(&head, &body, layout, 0);
        }
        let body: Vec<u8> = vec![0xffu8; 48];
        assert_eq!(read_func_defer_view(&head, &body, layout, usize::MAX), None);
    }

    #[test]
    fn absent_open_coded_slot_reads_as_call_based() {
        let layout: FuncLayout = layout_for(PclntabVersion::Go120, 8, None).unwrap();
        let head: PclntabHeader = header(PclntabVersion::Go120, 8, 0);
        let mut body: Vec<u8> = vec![0u8; 128];
        body[12..16].copy_from_slice(&0x20u32.to_le_bytes());
        body[28..32].copy_from_slice(&2u32.to_le_bytes());
        body[43] = 6;
        let slot: usize = 44 + 2 * 4 + 4 * 4;
        body[slot..slot + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            read_func_defer_view(&head, &body, layout, 0),
            Some(FuncDeferView {
                deferreturn: 0x20,
                open_coded: false,
            })
        );
        body[slot..slot + 4].copy_from_slice(&0x40u32.to_le_bytes());
        assert_eq!(
            read_func_defer_view(&head, &body, layout, 0),
            Some(FuncDeferView {
                deferreturn: 0x20,
                open_coded: true,
            })
        );
    }
}
