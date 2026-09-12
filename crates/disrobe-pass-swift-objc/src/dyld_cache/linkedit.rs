use std::collections::BTreeMap;

use disrobe_bytes::{ByteReadError, align_up_u64, read_u32_le_at, read_u64_le_at};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::macho::{
    Bitness, LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_SYMTAB, LinkeditData,
    LoadCommand, ParsedSlice,
};

pub const NLIST_64_SIZE: usize = 16;
pub const NLIST_32_SIZE: usize = 12;
pub const MAX_LINKEDIT_SYMBOLS: usize = 4_000_000;
pub const MAX_LINKEDIT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_INDIRECT_SYMBOLS: usize = 8_000_000;
pub const LINKEDIT_ALIGN: u64 = 8;

const SYMTAB_SYMOFF: usize = 8;
const SYMTAB_NSYMS: usize = 12;
const SYMTAB_STROFF: usize = 16;
const SYMTAB_STRSIZE: usize = 20;
const DYSYMTAB_TOCOFF: usize = 32;
const DYSYMTAB_MODTABOFF: usize = 40;
const DYSYMTAB_EXTREFSYMOFF: usize = 48;
const DYSYMTAB_INDIRECTSYMOFF: usize = 56;
const DYSYMTAB_NINDIRECTSYMS: usize = 60;
const DYSYMTAB_EXTRELOFF: usize = 64;
const DYSYMTAB_LOCRELOFF: usize = 72;
const LINKEDIT_DATA_OFF: usize = 8;
const LINKEDIT_DATA_SIZE: usize = 12;
const DYLD_INFO_FIELD_COUNT: usize = 5;
const DYLD_INFO_FIRST_FIELD: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchValue {
    LinkeditOffset(u64),
    Literal(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPatch {
    pub at: usize,
    pub value: PatchValue,
}

impl FieldPatch {
    #[must_use]
    pub const fn resolve(self, linkedit_base: u64) -> u64 {
        match self.value {
            PatchValue::LinkeditOffset(offset) => linkedit_base.wrapping_add(offset),
            PatchValue::Literal(literal) => literal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkeditSummary {
    pub symbols: u32,
    pub local_symbols: u32,
    pub indirect_symbols: u32,
    pub string_table_bytes: u32,
    pub dropped_code_signature: bool,
}

#[derive(Debug, Clone)]
pub struct LinkeditPlan {
    pub bytes: Vec<u8>,
    pub patches: Vec<FieldPatch>,
    pub summary: LinkeditSummary,
}

#[derive(Debug, Clone, Copy)]
pub struct LocalSymbolRun<'a> {
    pub nlist: &'a [u8],
    pub strings: &'a [u8],
    pub count: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SymbolNames {
    pub image_symbols: usize,
    pub local_symbols: usize,
}

struct Builder<'a> {
    image: &'a [u8],
    linkedit_file: &'a [u8],
    parsed: &'a ParsedSlice,
    entry_size: usize,
    out: Vec<u8>,
    patches: Vec<FieldPatch>,
    strings: Vec<u8>,
    string_offsets: BTreeMap<Vec<u8>, u32>,
    summary: LinkeditSummary,
}

pub fn build(
    image: &[u8],
    linkedit_file: &[u8],
    parsed: &ParsedSlice,
    locals: Option<LocalSymbolRun<'_>>,
) -> Result<LinkeditPlan> {
    let entry_size: usize = match parsed.header.bitness {
        Bitness::Bits64 => NLIST_64_SIZE,
        Bitness::Bits32 => NLIST_32_SIZE,
    };
    let mut builder: Builder<'_> = Builder {
        image,
        linkedit_file,
        parsed,
        entry_size,
        out: Vec::new(),
        patches: Vec::new(),
        strings: vec![b'\0'],
        string_offsets: BTreeMap::new(),
        summary: LinkeditSummary {
            symbols: 0,
            local_symbols: 0,
            indirect_symbols: 0,
            string_table_bytes: 0,
            dropped_code_signature: false,
        },
    };
    builder.run(locals)?;
    if builder.out.len() as u64 > MAX_LINKEDIT_BYTES {
        return Err(Error::BadDyldCache(format!(
            "synthesized linkedit is {} bytes, which exceeds the {MAX_LINKEDIT_BYTES}-byte cap",
            builder.out.len()
        )));
    }
    Ok(LinkeditPlan {
        bytes: builder.out,
        patches: builder.patches,
        summary: builder.summary,
    })
}

impl Builder<'_> {
    fn run(&mut self, locals: Option<LocalSymbolRun<'_>>) -> Result<()> {
        self.copy_dyld_info()?;
        self.copy_simple_blob(LC_DYLD_CHAINED_FIXUPS)?;
        self.copy_simple_blob(LC_DYLD_EXPORTS_TRIE)?;
        self.copy_simple_blob(LC_FUNCTION_STARTS)?;
        self.copy_simple_blob(LC_DATA_IN_CODE)?;
        self.write_symbol_table(locals)?;
        self.write_indirect_symbols()?;
        self.write_string_table()?;
        self.clear_code_signature();
        self.zero_absent_dysymtab_tables();
        Ok(())
    }

    fn command(&self, cmd: u32) -> Option<&LoadCommand> {
        self.parsed
            .load_commands
            .iter()
            .find(|lc: &&LoadCommand| lc.cmd == cmd)
    }

    fn align(&mut self) -> Result<u64> {
        let padded: u64 = align_up_u64(self.out.len() as u64, LINKEDIT_ALIGN);
        if padded > MAX_LINKEDIT_BYTES {
            return Err(Error::BadDyldCache(format!(
                "synthesized linkedit exceeds the {MAX_LINKEDIT_BYTES}-byte cap"
            )));
        }
        self.out.resize(padded as usize, 0);
        Ok(padded)
    }

    fn take_blob(&self, location: LinkeditData) -> Result<&[u8]> {
        let start: usize = location.offset as usize;
        let size: usize = location.size as usize;
        let end: usize = start
            .checked_add(size)
            .ok_or_else(|| Error::BadDyldCache("linkedit blob end overflows".to_owned()))?;
        self.linkedit_file.get(start..end).ok_or_else(|| {
            Error::BadDyldCache(format!(
                "linkedit blob [{start}, {end}) exceeds the {}-byte cache file that holds it",
                self.linkedit_file.len()
            ))
        })
    }

    fn copy_simple_blob(&mut self, cmd: u32) -> Result<()> {
        let Some(command): Option<&LoadCommand> = self.command(cmd) else {
            return Ok(());
        };
        let data_offset: usize = command.data_offset;
        let offset: u32 = u32_field(self.image, data_offset, LINKEDIT_DATA_OFF)?;
        let size: u32 = u32_field(self.image, data_offset, LINKEDIT_DATA_SIZE)?;
        if size == 0 {
            self.patches.push(FieldPatch {
                at: data_offset + LINKEDIT_DATA_OFF,
                value: PatchValue::Literal(0),
            });
            return Ok(());
        }
        let blob: Vec<u8> = self.take_blob(LinkeditData { offset, size })?.to_vec();
        let at: u64 = self.align()?;
        self.out.extend_from_slice(&blob);
        self.patches.push(FieldPatch {
            at: data_offset + LINKEDIT_DATA_OFF,
            value: PatchValue::LinkeditOffset(at),
        });
        Ok(())
    }

    fn copy_dyld_info(&mut self) -> Result<()> {
        let Some(command): Option<&LoadCommand> = self
            .command(LC_DYLD_INFO_ONLY)
            .or_else(|| self.command(LC_DYLD_INFO))
        else {
            return Ok(());
        };
        let data_offset: usize = command.data_offset;
        for field in 0..DYLD_INFO_FIELD_COUNT {
            let off_field: usize = DYLD_INFO_FIRST_FIELD + field * 8;
            let size_field: usize = off_field + 4;
            let offset: u32 = u32_field(self.image, data_offset, off_field)?;
            let size: u32 = u32_field(self.image, data_offset, size_field)?;
            if size == 0 {
                self.patches.push(FieldPatch {
                    at: data_offset + off_field,
                    value: PatchValue::Literal(0),
                });
                continue;
            }
            let blob: Vec<u8> = self.take_blob(LinkeditData { offset, size })?.to_vec();
            let at: u64 = self.align()?;
            self.out.extend_from_slice(&blob);
            self.patches.push(FieldPatch {
                at: data_offset + off_field,
                value: PatchValue::LinkeditOffset(at),
            });
        }
        Ok(())
    }

    fn intern(&mut self, name: &[u8]) -> Result<u32> {
        if name.is_empty() {
            return Ok(0);
        }
        if let Some(found) = self.string_offsets.get(name) {
            return Ok(*found);
        }
        let at: u32 = u32::try_from(self.strings.len()).map_err(|_| {
            Error::BadDyldCache("synthesized string table exceeds the 4 GiB index range".to_owned())
        })?;
        self.strings.extend_from_slice(name);
        self.strings.push(0);
        if self.strings.len() as u64 > MAX_LINKEDIT_BYTES {
            return Err(Error::BadDyldCache(format!(
                "synthesized string table exceeds the {MAX_LINKEDIT_BYTES}-byte cap"
            )));
        }
        self.string_offsets.insert(name.to_vec(), at);
        Ok(at)
    }

    fn rewrite_entries(
        &mut self,
        nlist: &[u8],
        strings: &[u8],
        count: usize,
        into: &mut Vec<u8>,
    ) -> Result<()> {
        for index in 0..count {
            let at: usize = index
                .checked_mul(self.entry_size)
                .ok_or_else(|| Error::BadDyldCache("nlist index overflows".to_owned()))?;
            let entry: &[u8] = nlist.get(at..at + self.entry_size).ok_or_else(|| {
                Error::BadDyldCache(format!(
                    "symbol {index} leaves the {}-byte symbol table",
                    nlist.len()
                ))
            })?;
            let strx: u32 = read_u32_le_at(entry, 0).map_err(|error: ByteReadError| {
                Error::BadDyldCache(format!("symbol {index} name index: {error}"))
            })?;
            let name: &[u8] = cstr_at(strings, strx as usize);
            let new_strx: u32 = self.intern(name)?;
            into.extend_from_slice(&new_strx.to_le_bytes());
            into.extend_from_slice(&entry[4..]);
        }
        Ok(())
    }

    fn write_symbol_table(&mut self, locals: Option<LocalSymbolRun<'_>>) -> Result<()> {
        let Some(command): Option<&LoadCommand> = self.command(LC_SYMTAB) else {
            return Ok(());
        };
        let data_offset: usize = command.data_offset;
        let symoff: u32 = u32_field(self.image, data_offset, SYMTAB_SYMOFF)?;
        let nsyms: u32 = u32_field(self.image, data_offset, SYMTAB_NSYMS)?;
        let stroff: u32 = u32_field(self.image, data_offset, SYMTAB_STROFF)?;
        let strsize: u32 = u32_field(self.image, data_offset, SYMTAB_STRSIZE)?;

        let image_count: usize = nsyms as usize;
        let local_count: usize = locals.map_or(0, |run: LocalSymbolRun<'_>| run.count);
        let total: usize = image_count
            .checked_add(local_count)
            .ok_or_else(|| Error::BadDyldCache("symbol count overflows".to_owned()))?;
        if total > MAX_LINKEDIT_SYMBOLS {
            return Err(Error::BadDyldCache(format!(
                "image declares {total} symbols, which exceeds the {MAX_LINKEDIT_SYMBOLS} symbol cap"
            )));
        }

        let table_bytes: usize = image_count
            .checked_mul(self.entry_size)
            .ok_or_else(|| Error::BadDyldCache("symbol table size overflows".to_owned()))?;
        let nlist_start: usize = symoff as usize;
        let nlist: Vec<u8> = self
            .linkedit_file
            .get(nlist_start..nlist_start.checked_add(table_bytes).ok_or_else(|| {
                Error::BadDyldCache("symbol table end overflows".to_owned())
            })?)
            .ok_or_else(|| {
                Error::BadDyldCache(format!(
                    "symbol table [{nlist_start}, +{table_bytes}) exceeds the {}-byte cache file that holds the linkedit",
                    self.linkedit_file.len()
                ))
            })?
            .to_vec();
        let str_start: usize = stroff as usize;
        let str_end: usize = str_start
            .checked_add(strsize as usize)
            .ok_or_else(|| Error::BadDyldCache("string table end overflows".to_owned()))?;
        let strings: Vec<u8> = self
            .linkedit_file
            .get(str_start..str_end.min(self.linkedit_file.len()))
            .ok_or_else(|| {
                Error::BadDyldCache(format!(
                    "string table starts at {str_start}, past the {}-byte cache file that holds the linkedit",
                    self.linkedit_file.len()
                ))
            })?
            .to_vec();

        let mut entries: Vec<u8> = Vec::with_capacity(total.saturating_mul(self.entry_size));
        self.rewrite_entries(&nlist, &strings, image_count, &mut entries)?;
        if let Some(run) = locals {
            let local_bytes: Vec<u8> = run.nlist.to_vec();
            let local_strings: Vec<u8> = run.strings.to_vec();
            self.rewrite_entries(&local_bytes, &local_strings, local_count, &mut entries)?;
        }

        let at: u64 = self.align()?;
        self.out.extend_from_slice(&entries);
        self.patches.push(FieldPatch {
            at: data_offset + SYMTAB_SYMOFF,
            value: PatchValue::LinkeditOffset(at),
        });
        self.patches.push(FieldPatch {
            at: data_offset + SYMTAB_NSYMS,
            value: PatchValue::Literal(total as u64),
        });
        self.summary.symbols = u32::try_from(total).unwrap_or(u32::MAX);
        self.summary.local_symbols = u32::try_from(local_count).unwrap_or(u32::MAX);
        Ok(())
    }

    fn write_indirect_symbols(&mut self) -> Result<()> {
        let Some(command): Option<&LoadCommand> = self.command(LC_DYSYMTAB) else {
            return Ok(());
        };
        let data_offset: usize = command.data_offset;
        let offset: u32 = u32_field(self.image, data_offset, DYSYMTAB_INDIRECTSYMOFF)?;
        let count: u32 = u32_field(self.image, data_offset, DYSYMTAB_NINDIRECTSYMS)?;
        if count == 0 {
            self.patches.push(FieldPatch {
                at: data_offset + DYSYMTAB_INDIRECTSYMOFF,
                value: PatchValue::Literal(0),
            });
            return Ok(());
        }
        if count as usize > MAX_INDIRECT_SYMBOLS {
            return Err(Error::BadDyldCache(format!(
                "image declares {count} indirect symbols, which exceeds the {MAX_INDIRECT_SYMBOLS} cap"
            )));
        }
        let size: u32 = count.checked_mul(4).ok_or_else(|| {
            Error::BadDyldCache("indirect symbol table size overflows".to_owned())
        })?;
        let blob: Vec<u8> = self.take_blob(LinkeditData { offset, size })?.to_vec();
        let at: u64 = self.align()?;
        self.out.extend_from_slice(&blob);
        self.patches.push(FieldPatch {
            at: data_offset + DYSYMTAB_INDIRECTSYMOFF,
            value: PatchValue::LinkeditOffset(at),
        });
        self.summary.indirect_symbols = count;
        Ok(())
    }

    fn write_string_table(&mut self) -> Result<()> {
        let Some(command): Option<&LoadCommand> = self.command(LC_SYMTAB) else {
            return Ok(());
        };
        let data_offset: usize = command.data_offset;
        let padded: u64 = align_up_u64(self.strings.len() as u64, LINKEDIT_ALIGN);
        self.strings.resize(padded as usize, 0);
        let at: u64 = self.align()?;
        let table: Vec<u8> = core::mem::take(&mut self.strings);
        self.out.extend_from_slice(&table);
        self.patches.push(FieldPatch {
            at: data_offset + SYMTAB_STROFF,
            value: PatchValue::LinkeditOffset(at),
        });
        self.patches.push(FieldPatch {
            at: data_offset + SYMTAB_STRSIZE,
            value: PatchValue::Literal(table.len() as u64),
        });
        self.summary.string_table_bytes = u32::try_from(table.len()).unwrap_or(u32::MAX);
        Ok(())
    }

    fn clear_code_signature(&mut self) {
        let Some(command): Option<&LoadCommand> = self.command(LC_CODE_SIGNATURE) else {
            return;
        };
        let data_offset: usize = command.data_offset;
        self.patches.push(FieldPatch {
            at: data_offset + LINKEDIT_DATA_OFF,
            value: PatchValue::Literal(0),
        });
        self.patches.push(FieldPatch {
            at: data_offset + LINKEDIT_DATA_SIZE,
            value: PatchValue::Literal(0),
        });
        self.summary.dropped_code_signature = true;
    }

    fn zero_absent_dysymtab_tables(&mut self) {
        let Some(command): Option<&LoadCommand> = self.command(LC_DYSYMTAB) else {
            return;
        };
        let data_offset: usize = command.data_offset;
        for field in [
            DYSYMTAB_TOCOFF,
            DYSYMTAB_MODTABOFF,
            DYSYMTAB_EXTREFSYMOFF,
            DYSYMTAB_EXTRELOFF,
            DYSYMTAB_LOCRELOFF,
        ] {
            self.patches.push(FieldPatch {
                at: data_offset + field,
                value: PatchValue::Literal(0),
            });
        }
    }
}

fn cstr_at(strings: &[u8], at: usize) -> &[u8] {
    let Some(window): Option<&[u8]> = strings.get(at..) else {
        return &[];
    };
    let stop: usize = window
        .iter()
        .position(|byte: &u8| *byte == 0)
        .unwrap_or(window.len());
    &window[..stop]
}

fn u32_field(bytes: &[u8], data_offset: usize, field: usize) -> Result<u32> {
    let at: usize = data_offset
        .checked_add(field)
        .ok_or_else(|| Error::BadDyldCache("load-command field offset overflows".to_owned()))?;
    read_u32_le_at(bytes, at).map_err(|error: ByteReadError| {
        Error::BadDyldCache(format!("load-command field at {at}: {error}"))
    })
}

pub fn u64_field(bytes: &[u8], data_offset: usize, field: usize) -> Result<u64> {
    let at: usize = data_offset
        .checked_add(field)
        .ok_or_else(|| Error::BadDyldCache("load-command field offset overflows".to_owned()))?;
    read_u64_le_at(bytes, at).map_err(|error: ByteReadError| {
        Error::BadDyldCache(format!("load-command field at {at}: {error}"))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_interned_once_and_keeps_its_first_offset() {
        let parsed: ParsedSlice = ParsedSlice::default();
        let mut builder: Builder<'_> = Builder {
            image: &[],
            linkedit_file: &[],
            parsed: &parsed,
            entry_size: NLIST_64_SIZE,
            out: Vec::new(),
            patches: Vec::new(),
            strings: vec![b'\0'],
            string_offsets: BTreeMap::new(),
            summary: LinkeditSummary {
                symbols: 0,
                local_symbols: 0,
                indirect_symbols: 0,
                string_table_bytes: 0,
                dropped_code_signature: false,
            },
        };
        let first: u32 = builder.intern(b"_main").expect("intern");
        let again: u32 = builder.intern(b"_main").expect("intern");
        let other: u32 = builder.intern(b"_other").expect("intern");
        assert_eq!(first, 1);
        assert_eq!(again, first);
        assert_eq!(other, 7);
        assert_eq!(builder.intern(b"").expect("empty name"), 0);
    }

    #[test]
    fn a_patch_resolves_a_linkedit_offset_against_its_base_and_leaves_a_literal_alone() {
        let offset: FieldPatch = FieldPatch {
            at: 0,
            value: PatchValue::LinkeditOffset(0x40),
        };
        let literal: FieldPatch = FieldPatch {
            at: 0,
            value: PatchValue::Literal(0x40),
        };
        assert_eq!(offset.resolve(0x1000), 0x1040);
        assert_eq!(literal.resolve(0x1000), 0x40);
    }

    #[test]
    fn a_name_index_past_the_string_table_reads_as_empty() {
        assert_eq!(cstr_at(b"\0_main\0", 1), b"_main");
        assert_eq!(cstr_at(b"\0_main\0", 64), b"");
    }
}
