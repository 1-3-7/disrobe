use std::collections::BTreeMap;

use serde::Serialize;

use super::SqliteError;
use super::format::{SqliteHeader, be32};

const WAL_HEADER_LEN: usize = 32;
const WAL_FRAME_HEADER_LEN: usize = 24;
const WAL_MAGIC_LITTLE: u32 = 0x377f_0682;
const WAL_MAGIC_BIG: u32 = 0x377f_0683;
const WAL_FORMAT_VERSION: u32 = 3_007_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WalReport {
    pub frames: u32,
    pub valid_frames: u32,
    pub committed_frames: u32,
    pub commits: u32,
    pub pages_overlaid: u32,
    pub checkpoint_sequence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
}

#[derive(Debug)]
pub(super) struct Pager<'a> {
    db: &'a [u8],
    page_size: usize,
    pub(super) usable: usize,
    pub(super) page_count: u32,
    overlay: BTreeMap<u32, &'a [u8]>,
}

impl<'a> Pager<'a> {
    pub(super) fn new(
        db: &'a [u8],
        header: &SqliteHeader,
        wal: Option<&'a [u8]>,
    ) -> Result<(Self, Option<WalReport>), SqliteError> {
        let page_size: usize = header.page_size as usize;
        let file_pages: u32 = u32::try_from(db.len() / page_size).unwrap_or(u32::MAX);
        let header_valid: bool =
            header.header_page_count != 0 && header.change_counter == header.version_valid_for;
        let mut page_count: u32 = if header_valid {
            header.header_page_count.min(file_pages.max(1))
        } else {
            file_pages
        };
        let mut overlay: BTreeMap<u32, &'a [u8]> = BTreeMap::new();
        let report: Option<WalReport> = match wal {
            None => None,
            Some(bytes) => {
                let (report, pages, committed_count): (
                    WalReport,
                    BTreeMap<u32, &'a [u8]>,
                    Option<u32>,
                ) = read_wal(bytes, header.page_size)?;
                overlay = pages;
                if let Some(count) = committed_count {
                    page_count = count;
                }
                Some(report)
            }
        };
        Ok((
            Self {
                db,
                page_size,
                usable: header.usable_size(),
                page_count,
                overlay,
            },
            report,
        ))
    }

    pub(super) fn page(&self, number: u32) -> Result<&'a [u8], SqliteError> {
        if number == 0 || number > self.page_count {
            return Err(SqliteError::PageOutOfRange {
                page: number,
                pages: self.page_count,
            });
        }
        if let Some(page) = self.overlay.get(&number) {
            return Ok(page);
        }
        let start: usize = (number as usize - 1) * self.page_size;
        self.db
            .get(start..start + self.page_size)
            .ok_or(SqliteError::PageOutOfRange {
                page: number,
                pages: self.page_count,
            })
    }

    pub(super) const fn header_offset(number: u32) -> usize {
        if number == 1 { 100 } else { 0 }
    }
}

type WalOverlay<'a> = (WalReport, BTreeMap<u32, &'a [u8]>, Option<u32>);

fn read_wal(bytes: &[u8], page_size: u32) -> Result<WalOverlay<'_>, SqliteError> {
    let header: &[u8] = bytes.get(..WAL_HEADER_LEN).ok_or_else(|| {
        SqliteError::Wal("the file is shorter than the 32-byte WAL header".to_owned())
    })?;
    let magic: u32 = be32(header, 0);
    let big_endian: bool = match magic {
        WAL_MAGIC_BIG => true,
        WAL_MAGIC_LITTLE => false,
        _ => {
            return Err(SqliteError::Wal(format!(
                "magic {magic:#010x} is not a WAL"
            )));
        }
    };
    if be32(header, 4) != WAL_FORMAT_VERSION {
        return Err(SqliteError::Wal(format!(
            "format version {} is not {WAL_FORMAT_VERSION}",
            be32(header, 4)
        )));
    }
    if be32(header, 8) != page_size {
        return Err(SqliteError::Wal(format!(
            "page size {} differs from the database's {page_size}",
            be32(header, 8)
        )));
    }
    let salt: (u32, u32) = (be32(header, 16), be32(header, 20));
    let (mut s0, mut s1): (u32, u32) = checksum(&header[..24], (0, 0), big_endian);
    let mut report: WalReport = WalReport {
        checkpoint_sequence: be32(header, 12),
        ..WalReport::default()
    };
    if (s0, s1) != (be32(header, 24), be32(header, 28)) {
        report.stopped = Some("the WAL header checksum does not match".to_owned());
        return Ok((report, BTreeMap::new(), None));
    }
    let frame_len: usize = WAL_FRAME_HEADER_LEN + page_size as usize;
    let total_frames: usize = (bytes.len() - WAL_HEADER_LEN) / frame_len;
    report.frames = u32::try_from(total_frames).unwrap_or(u32::MAX);
    let mut pending: BTreeMap<u32, &[u8]> = BTreeMap::new();
    let mut committed: BTreeMap<u32, &[u8]> = BTreeMap::new();
    let mut committed_count: Option<u32> = None;
    for index in 0..total_frames {
        let start: usize = WAL_HEADER_LEN + index * frame_len;
        let frame: &[u8] = &bytes[start..start + frame_len];
        if (be32(frame, 8), be32(frame, 12)) != salt {
            report.stopped = Some(format!(
                "frame {index} carries salts from an earlier WAL generation"
            ));
            break;
        }
        let after_header: (u32, u32) = checksum(&frame[..8], (s0, s1), big_endian);
        let after_page: (u32, u32) =
            checksum(&frame[WAL_FRAME_HEADER_LEN..], after_header, big_endian);
        if after_page != (be32(frame, 16), be32(frame, 20)) {
            report.stopped = Some(format!("frame {index} fails its cumulative checksum"));
            break;
        }
        (s0, s1) = after_page;
        report.valid_frames += 1;
        let page_number: u32 = be32(frame, 0);
        if page_number == 0 {
            report.stopped = Some(format!("frame {index} names page 0"));
            break;
        }
        pending.insert(page_number, &frame[WAL_FRAME_HEADER_LEN..]);
        let database_pages: u32 = be32(frame, 4);
        if database_pages != 0 {
            report.commits += 1;
            report.committed_frames = report.valid_frames;
            committed.append(&mut pending);
            committed_count = Some(database_pages);
        }
    }
    report.pages_overlaid = u32::try_from(committed.len()).unwrap_or(u32::MAX);
    Ok((report, committed, committed_count))
}

fn checksum(bytes: &[u8], seed: (u32, u32), big_endian: bool) -> (u32, u32) {
    let (mut s0, mut s1): (u32, u32) = seed;
    for pair in bytes.chunks_exact(8) {
        let read = |slice: &[u8]| -> u32 {
            let raw: [u8; 4] = <[u8; 4]>::try_from(slice).unwrap_or([0; 4]);
            if big_endian {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            }
        };
        s0 = s0.wrapping_add(read(&pair[..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(read(&pair[4..])).wrapping_add(s0);
    }
    (s0, s1)
}
