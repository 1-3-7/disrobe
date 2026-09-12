use super::biff::{BiffRecord, read_short_xlunicode, read_u32};
use super::limits::MAX_SHEETS;

pub const REC_BOF: u32 = 0x0809;
pub const REC_EOF: u32 = 0x000A;
pub const REC_BOUNDSHEET: u32 = 0x0085;

pub const BOF_DT_GLOBALS: u16 = 0x0005;
pub const BOF_DT_WORKSHEET: u16 = 0x0010;
pub const BOF_DT_CHART: u16 = 0x0020;
pub const BOF_DT_MACRO: u16 = 0x0040;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheetKind {
    Worksheet,
    Macro,
    Chart,
    VbModule,
    Unknown,
}

impl SheetKind {
    pub fn from_boundsheet_dt(dt: u8) -> Self {
        match dt {
            0x00 => Self::Worksheet,
            0x01 => Self::Macro,
            0x02 => Self::Chart,
            0x06 => Self::VbModule,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Worksheet => "worksheet",
            Self::Macro => "macro",
            Self::Chart => "chart",
            Self::VbModule => "vbmodule",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SheetEntry {
    pub name: String,
    pub kind: SheetKind,
    pub bof_pos: usize,
}

pub fn enumerate_sheets(records: &[BiffRecord]) -> Vec<SheetEntry> {
    let mut sheets: Vec<SheetEntry> = Vec::new();
    for rec in records {
        if rec.rt == REC_EOF {
            break;
        }
        if rec.rt != REC_BOUNDSHEET {
            continue;
        }
        let data: &[u8] = &rec.data;
        let Some(lb): Option<u32> = read_u32(data, 0) else {
            continue;
        };
        let Some(dt_byte): Option<&u8> = data.get(5) else {
            continue;
        };
        let Some((name, _consumed)): Option<(String, usize)> = read_short_xlunicode(data, 6) else {
            continue;
        };
        sheets.push(SheetEntry {
            name,
            kind: SheetKind::from_boundsheet_dt(*dt_byte),
            bof_pos: lb as usize,
        });
        if sheets.len() >= MAX_SHEETS {
            break;
        }
    }
    sheets
}
