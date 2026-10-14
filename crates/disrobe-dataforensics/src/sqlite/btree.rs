use std::collections::BTreeSet;

use super::format::{
    PAGE_INTERIOR_INDEX, PAGE_INTERIOR_TABLE, PAGE_LEAF_INDEX, PAGE_LEAF_TABLE, be16, be32,
    local_payload, varint,
};
use super::pager::Pager;
use super::{Limits, SqliteError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TreeKind {
    Table,
    Index,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PageHeader {
    pub(super) kind: u8,
    pub(super) first_freeblock: usize,
    pub(super) cell_count: usize,
    pub(super) content_start: usize,
    pub(super) header_start: usize,
    pub(super) header_len: usize,
    pub(super) right_child: u32,
}

impl PageHeader {
    pub(super) fn parse(page: &[u8], number: u32) -> Option<Self> {
        let header_start: usize = Pager::header_offset(number);
        let kind: u8 = *page.get(header_start)?;
        let header_len: usize = match kind {
            PAGE_LEAF_TABLE | PAGE_LEAF_INDEX => 8,
            PAGE_INTERIOR_TABLE | PAGE_INTERIOR_INDEX => 12,
            _ => return None,
        };
        if page.len() < header_start + header_len {
            return None;
        }
        let raw_content: usize = usize::from(be16(page, header_start + 5));
        let content_start: usize = if raw_content == 0 {
            65_536
        } else {
            raw_content
        };
        let cell_count: usize = usize::from(be16(page, header_start + 3));
        if header_start + header_len + cell_count * 2 > page.len() {
            return None;
        }
        Some(Self {
            kind,
            first_freeblock: usize::from(be16(page, header_start + 1)),
            cell_count,
            content_start,
            header_start,
            header_len,
            right_child: if header_len == 12 {
                be32(page, header_start + 8)
            } else {
                0
            },
        })
    }

    pub(super) const fn pointer_array_end(&self) -> usize {
        self.header_start + self.header_len + self.cell_count * 2
    }

    pub(super) fn cell_offsets(&self, page: &[u8]) -> Vec<usize> {
        (0..self.cell_count)
            .map(|index: usize| {
                usize::from(be16(page, self.header_start + self.header_len + index * 2))
            })
            .filter(|offset: &usize| *offset >= self.pointer_array_end() && *offset < page.len())
            .collect()
    }
}

#[derive(Debug, Default)]
pub(super) struct WalkOutcome {
    pub(super) leaf_pages: Vec<u32>,
    pub(super) problems: Vec<String>,
}

pub(super) struct Entry {
    pub(super) rowid: Option<i64>,
    pub(super) payload: Vec<u8>,
}

pub(super) fn walk(
    pager: &Pager<'_>,
    root: u32,
    kind: TreeKind,
    limits: &Limits,
    budget: &mut u64,
    visit: &mut dyn FnMut(Entry) -> bool,
) -> WalkOutcome {
    let mut outcome: WalkOutcome = WalkOutcome::default();
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<Work> = vec![Work::Page(root, 0)];
    while let Some(work) = stack.pop() {
        let (number, depth): (u32, usize) = match work {
            Work::Page(number, depth) => (number, depth),
            Work::Emit(entry) => {
                if !visit(entry) {
                    return outcome;
                }
                continue;
            }
        };
        if depth > limits.depth {
            outcome.problems.push(format!(
                "b-tree rooted at page {root} is deeper than {}",
                limits.depth
            ));
            continue;
        }
        if !visited.insert(number) {
            outcome
                .problems
                .push(format!("page {number} is reached twice under root {root}"));
            continue;
        }
        if *budget == 0 {
            outcome
                .problems
                .push(format!("page budget exhausted while walking root {root}"));
            break;
        }
        *budget -= 1;
        let page: &[u8] = match pager.page(number) {
            Ok(page) => page,
            Err(error) => {
                outcome.problems.push(error.to_string());
                continue;
            }
        };
        let Some(header) = PageHeader::parse(page, number) else {
            outcome.problems.push(format!(
                "page {number} under root {root} is not a b-tree page"
            ));
            continue;
        };
        let expected: (u8, u8) = match kind {
            TreeKind::Table => (PAGE_LEAF_TABLE, PAGE_INTERIOR_TABLE),
            TreeKind::Index => (PAGE_LEAF_INDEX, PAGE_INTERIOR_INDEX),
        };
        if header.kind != expected.0 && header.kind != expected.1 {
            outcome.problems.push(format!(
                "page {number} has page type {} inside a {kind:?} tree",
                header.kind
            ));
            continue;
        }
        let interior: bool = header.kind == expected.1;
        if !interior {
            outcome.leaf_pages.push(number);
        }
        let mut ordered: Vec<Work> = Vec::new();
        for offset in header.cell_offsets(page) {
            match read_cell(pager, page, offset, header.kind, limits) {
                Ok(cell) => {
                    if let Some(child) = cell.left_child {
                        ordered.push(Work::Page(child, depth + 1));
                    }
                    if let Some(payload) = cell.payload {
                        ordered.push(Work::Emit(Entry {
                            rowid: cell.rowid,
                            payload,
                        }));
                    }
                }
                Err(error) => outcome.problems.push(format!("page {number}: {error}")),
            }
        }
        if interior {
            ordered.push(Work::Page(header.right_child, depth + 1));
        }
        stack.extend(ordered.into_iter().rev());
    }
    outcome
}

enum Work {
    Page(u32, usize),
    Emit(Entry),
}

pub(super) struct Cell {
    pub(super) left_child: Option<u32>,
    pub(super) rowid: Option<i64>,
    pub(super) payload: Option<Vec<u8>>,
}

pub(super) fn read_cell(
    pager: &Pager<'_>,
    page: &[u8],
    offset: usize,
    kind: u8,
    limits: &Limits,
) -> Result<Cell, SqliteError> {
    let bad = |reason: &str| SqliteError::BadCell {
        offset,
        reason: reason.to_owned(),
    };
    let mut at: usize = offset;
    let left_child: Option<u32> = if kind == PAGE_INTERIOR_TABLE || kind == PAGE_INTERIOR_INDEX {
        let child: u32 = be32(page, at);
        at += 4;
        Some(child)
    } else {
        None
    };
    if kind == PAGE_INTERIOR_TABLE {
        let _: (u64, usize) =
            varint(page.get(at..).unwrap_or_default()).ok_or_else(|| bad("truncated key"))?;
        return Ok(Cell {
            left_child,
            rowid: None,
            payload: None,
        });
    }
    let (total, used): (u64, usize) = varint(page.get(at..).unwrap_or_default())
        .ok_or_else(|| bad("truncated payload length"))?;
    at += used;
    let total: usize = usize::try_from(total).map_err(|_| bad("payload length overflows"))?;
    if total > limits.record_bytes {
        return Err(bad("payload larger than the record limit"));
    }
    let rowid: Option<i64> = if kind == PAGE_LEAF_TABLE {
        let (raw, used): (u64, usize) =
            varint(page.get(at..).unwrap_or_default()).ok_or_else(|| bad("truncated rowid"))?;
        at += used;
        Some(raw as i64)
    } else {
        None
    };
    let local: usize = local_payload(total, pager.usable, kind == PAGE_LEAF_TABLE);
    let local_bytes: &[u8] = page
        .get(at..at + local)
        .ok_or_else(|| bad("local payload runs past the page"))?;
    let mut payload: Vec<u8> = local_bytes.to_vec();
    if local < total {
        let mut next: u32 = be32(page, at + local);
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        let chunk: usize = pager.usable - 4;
        while payload.len() < total {
            if next == 0 || !seen.insert(next) || seen.len() > limits.overflow_pages {
                return Err(bad(
                    "overflow chain is broken, cyclic or longer than the limit",
                ));
            }
            let overflow: &[u8] = pager.page(next)?;
            let take: usize = chunk.min(total - payload.len());
            payload.extend_from_slice(
                overflow
                    .get(4..4 + take)
                    .ok_or_else(|| bad("overflow page too short"))?,
            );
            next = be32(overflow, 0);
        }
    }
    Ok(Cell {
        left_child,
        rowid,
        payload: Some(payload),
    })
}
