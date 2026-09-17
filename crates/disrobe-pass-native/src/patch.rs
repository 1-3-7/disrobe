use object::{Object, ObjectSection, ObjectSegment};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchEdit {
    pub virtual_address: u64,
    pub bytes: Vec<u8>,
}

impl PatchEdit {
    #[must_use]
    pub const fn new(virtual_address: u64, bytes: Vec<u8>) -> Self {
        Self {
            virtual_address,
            bytes,
        }
    }

    #[must_use]
    pub fn nop_range(start_va: u64, end_va: u64, fill: u8) -> Option<Self> {
        if end_va <= start_va {
            return None;
        }
        let len: usize = usize::try_from(end_va - start_va).ok()?;
        Some(Self {
            virtual_address: start_va,
            bytes: vec![fill; len],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedEdit {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub length: usize,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchReport {
    pub format: String,
    pub image_base: u64,
    pub edits: Vec<AppliedEdit>,
    pub bytes_changed: usize,
}

const NOP_X86: u8 = 0x90;

#[must_use]
pub const fn default_nop_fill() -> u8 {
    NOP_X86
}

#[derive(Debug, Clone, Copy)]
struct MappedRange {
    virtual_address: u64,
    virtual_size: u64,
    file_offset: u64,
    file_size: u64,
}

impl MappedRange {
    fn resolve(&self, va: u64, len: usize) -> Option<(u64, u64)> {
        let end_va: u64 = va.checked_add(len as u64)?;
        let range_end: u64 = self.virtual_address.checked_add(self.virtual_size)?;
        if va < self.virtual_address || end_va > range_end {
            return None;
        }
        let delta: u64 = va - self.virtual_address;
        if delta >= self.file_size {
            return None;
        }
        let avail: u64 = self.file_size - delta;
        if (len as u64) > avail {
            return None;
        }
        Some((self.file_offset + delta, len as u64))
    }
}

fn mapped_ranges(file: &object::File<'_>) -> Result<Vec<MappedRange>> {
    let mut ranges: Vec<MappedRange> = Vec::new();
    match file.format() {
        object::BinaryFormat::Pe => {
            for section in file.sections() {
                let Some((file_offset, file_size)): Option<(u64, u64)> = section.file_range()
                else {
                    continue;
                };
                if file_size == 0 {
                    continue;
                }
                ranges.push(MappedRange {
                    virtual_address: section.address(),
                    virtual_size: section.size().max(file_size),
                    file_offset,
                    file_size,
                });
            }
        }
        _ => {
            for segment in file.segments() {
                let (file_offset, file_size): (u64, u64) = segment.file_range();
                if file_size == 0 {
                    continue;
                }
                ranges.push(MappedRange {
                    virtual_address: segment.address(),
                    virtual_size: segment.size().max(file_size),
                    file_offset,
                    file_size,
                });
            }
            if ranges.is_empty() {
                for section in file.sections() {
                    let Some((file_offset, file_size)): Option<(u64, u64)> = section.file_range()
                    else {
                        continue;
                    };
                    if file_size == 0 || section.address() == 0 {
                        continue;
                    }
                    ranges.push(MappedRange {
                        virtual_address: section.address(),
                        virtual_size: section.size().max(file_size),
                        file_offset,
                        file_size,
                    });
                }
            }
        }
    }
    if ranges.is_empty() {
        return Err(Error::Export {
            stage: "patch-map",
            detail: format!(
                "{:?} object exposes no file-backed mapped range to host a virtual-address patch",
                file.format()
            ),
        });
    }
    Ok(ranges)
}

fn resolve_va(ranges: &[MappedRange], va: u64, len: usize) -> Result<(u64, u64)> {
    for range in ranges {
        if let Some(hit) = range.resolve(va, len) {
            return Ok(hit);
        }
    }
    Err(Error::Export {
        stage: "patch-resolve",
        detail: format!(
            "virtual address {va:#x} (len {len}) is not inside any file-backed mapped range; \
             a patch must target bytes that exist on disk, not a bss/zero-fill region"
        ),
    })
}

pub fn apply_patches(bytes: &[u8], edits: &[PatchEdit]) -> Result<Vec<u8>> {
    apply_patches_reported(bytes, edits).map(|(image, _report): (Vec<u8>, PatchReport)| image)
}

pub fn apply_patches_reported(bytes: &[u8], edits: &[PatchEdit]) -> Result<(Vec<u8>, PatchReport)> {
    if edits.is_empty() {
        return Err(Error::Export {
            stage: "patch-empty",
            detail: "no edits supplied; nothing to patch".to_owned(),
        });
    }
    let file: object::File<'_> = object::File::parse(bytes).map_err(|e| Error::Export {
        stage: "patch-parse",
        detail: e.to_string(),
    })?;
    let file_format: object::BinaryFormat = file.format();
    let image_base: u64 = file.relative_address_base();
    let ranges: Vec<MappedRange> = mapped_ranges(&file)?;
    drop(file);

    let mut resolved: Vec<(usize, u64, Vec<u8>)> = Vec::with_capacity(edits.len());
    for edit in edits {
        if edit.bytes.is_empty() {
            return Err(Error::Export {
                stage: "patch-empty-edit",
                detail: format!("edit at {:#x} carries zero bytes", edit.virtual_address),
            });
        }
        let (file_offset, _len): (u64, u64) =
            resolve_va(&ranges, edit.virtual_address, edit.bytes.len())?;
        let offset_usize: usize = usize::try_from(file_offset).map_err(|_| Error::Export {
            stage: "patch-offset",
            detail: format!("resolved file offset {file_offset:#x} exceeds usize"),
        })?;
        resolved.push((offset_usize, edit.virtual_address, edit.bytes.clone()));
    }

    resolved.sort_by_key(|(off, _, _): &(usize, u64, Vec<u8>)| *off);
    for window in resolved.windows(2) {
        let (a_off, a_va, a_bytes): &(usize, u64, Vec<u8>) = &window[0];
        let (b_off, b_va, _): &(usize, u64, Vec<u8>) = &window[1];
        if a_off + a_bytes.len() > *b_off {
            return Err(Error::Export {
                stage: "patch-overlap",
                detail: format!(
                    "edit at {a_va:#x} overlaps the edit at {b_va:#x} in the file image"
                ),
            });
        }
    }

    let mut out: Vec<u8> = bytes.to_vec();
    let mut applied: Vec<AppliedEdit> = Vec::with_capacity(resolved.len());
    let mut bytes_changed: usize = 0;
    for (offset, va, replacement) in &resolved {
        let end: usize = offset + replacement.len();
        if end > out.len() {
            return Err(Error::Export {
                stage: "patch-bounds",
                detail: format!("patch at {va:#x} runs past the end of the file image"),
            });
        }
        let original: Vec<u8> = out[*offset..end].to_vec();
        out[*offset..end].copy_from_slice(replacement);
        bytes_changed += replacement.len();
        applied.push(AppliedEdit {
            virtual_address: *va,
            file_offset: *offset as u64,
            length: replacement.len(),
            original,
            replacement: replacement.clone(),
        });
    }

    let reparsed: object::File<'_> =
        object::File::parse(out.as_slice()).map_err(|e| Error::Export {
            stage: "patch-reparse",
            detail: format!("patched image no longer parses as a valid object: {e}"),
        })?;
    if reparsed.format() != file_format {
        return Err(Error::Export {
            stage: "patch-reparse-format",
            detail: "patched image changed binary format".to_owned(),
        });
    }

    let report: PatchReport = PatchReport {
        format: format_label(file_format),
        image_base,
        edits: applied,
        bytes_changed,
    };
    Ok((out, report))
}

fn format_label(format: object::BinaryFormat) -> String {
    match format {
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::Coff => "coff",
        object::BinaryFormat::MachO => "macho",
        object::BinaryFormat::Wasm => "wasm",
        object::BinaryFormat::Xcoff => "xcoff",
        _ => "unknown",
    }
    .to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use object::ObjectSection;

    use super::*;
    use crate::test_support::pe64_with_text;

    const TEXT_VA: u64 = 0x1_4000_1000;

    fn sample_image() -> Vec<u8> {
        let text: Vec<u8> = vec![
            0x55, 0x48, 0x89, 0xE5, 0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3,
        ];
        pe64_with_text(&text, 0x1000)
    }

    fn text_section_va_and_offset(bytes: &[u8]) -> (u64, u64, u64) {
        let file: object::File<'_> = object::File::parse(bytes).expect("parse pe");
        let text: object::Section<'_, '_> = file
            .sections()
            .find(|s: &object::Section<'_, '_>| s.name().ok() == Some(".text"))
            .expect(".text section");
        let (off, size): (u64, u64) = text.file_range().expect("text file range");
        (text.address(), off, size)
    }

    #[test]
    fn patch_changes_byte_and_stays_loadable() {
        let image: Vec<u8> = sample_image();
        let (text_va, text_off, text_size): (u64, u64, u64) = text_section_va_and_offset(&image);
        assert_eq!(text_va, TEXT_VA);
        assert!(text_size >= 1, ".text must hold bytes");
        let original_byte: u8 = image[text_off as usize];
        let new_byte: u8 = original_byte ^ 0xFF;

        let edit: PatchEdit = PatchEdit::new(text_va, vec![new_byte]);
        let (patched, report): (Vec<u8>, PatchReport) =
            apply_patches_reported(&image, std::slice::from_ref(&edit)).expect("patch");

        assert_eq!(patched.len(), image.len(), "byte patch must not resize");
        assert_eq!(
            patched[text_off as usize], new_byte,
            "the targeted byte must change"
        );
        assert_ne!(
            patched, image,
            "the patched image must differ from the original"
        );
        assert!(
            object::File::parse(patched.as_slice()).is_ok(),
            "the patched image must still parse as a valid object"
        );
        assert_eq!(report.bytes_changed, 1);
        assert_eq!(report.edits[0].original, vec![original_byte]);
        assert_eq!(report.edits[0].replacement, vec![new_byte]);
    }

    #[test]
    fn re_patching_to_original_is_idempotent() {
        let image: Vec<u8> = sample_image();
        let (text_va, text_off, _): (u64, u64, u64) = text_section_va_and_offset(&image);
        let original_byte: u8 = image[text_off as usize];
        let new_byte: u8 = original_byte.wrapping_add(7);

        let forward: PatchEdit = PatchEdit::new(text_va, vec![new_byte]);
        let patched: Vec<u8> =
            apply_patches(&image, std::slice::from_ref(&forward)).expect("patch");

        let restore: PatchEdit = PatchEdit::new(text_va, vec![original_byte]);
        let restored: Vec<u8> =
            apply_patches(&patched, std::slice::from_ref(&restore)).expect("re-patch");
        assert_eq!(
            restored, image,
            "patching back to the original byte must reproduce the input image exactly"
        );
    }

    #[test]
    fn nop_range_fills_span() {
        let image: Vec<u8> = sample_image();
        let (text_va, text_off, _): (u64, u64, u64) = text_section_va_and_offset(&image);
        let edit: PatchEdit =
            PatchEdit::nop_range(text_va, text_va + 4, default_nop_fill()).expect("nop range");
        let patched: Vec<u8> = apply_patches(&image, std::slice::from_ref(&edit)).expect("patch");
        assert_eq!(
            &patched[text_off as usize..text_off as usize + 4],
            &[0x90, 0x90, 0x90, 0x90],
            "a nop-range must lay down 0x90 fill across the requested span"
        );
        assert!(object::File::parse(patched.as_slice()).is_ok());
    }

    #[test]
    fn unmapped_va_is_rejected() {
        let image: Vec<u8> = sample_image();
        let edit: PatchEdit = PatchEdit::new(0xFFFF_FFFF_0000, vec![0x90]);
        let err: Error = apply_patches(&image, std::slice::from_ref(&edit)).expect_err("reject");
        assert!(matches!(err, Error::Export { .. }));
    }

    #[test]
    fn overlapping_edits_are_rejected() {
        let image: Vec<u8> = sample_image();
        let (text_va, _, _): (u64, u64, u64) = text_section_va_and_offset(&image);
        let a: PatchEdit = PatchEdit::new(text_va, vec![0x90, 0x90]);
        let b: PatchEdit = PatchEdit::new(text_va + 1, vec![0x90, 0x90]);
        let err: Error = apply_patches(&image, &[a, b]).expect_err("overlap reject");
        assert!(matches!(
            err,
            Error::Export {
                stage: "patch-overlap",
                ..
            }
        ));
    }

    #[test]
    fn empty_edits_rejected() {
        let image: Vec<u8> = sample_image();
        let err: Error = apply_patches(&image, &[]).expect_err("empty reject");
        assert!(matches!(
            err,
            Error::Export {
                stage: "patch-empty",
                ..
            }
        ));
    }
}
