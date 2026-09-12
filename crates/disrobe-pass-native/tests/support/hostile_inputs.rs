use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct HostileInput {
    pub(crate) label: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) const HEADER_WINDOW: usize = 256;
pub(crate) const HEADER_MUTATION_STRIDE: usize = 8;
pub(crate) const BODY_MUTATION_SAMPLES: usize = 16;
pub(crate) const FIELD_EXTREME_SLOTS: usize = 8;

pub(crate) const SAMPLING_RULE: &str = "per base image: truncation at every power-of-two boundary \
     up to the length plus the quarter, half, three-quarter and last-byte boundaries; a 0xFF flip \
     at every eighth offset of the first 256 bytes; a 0xFF flip at 16 offsets spaced evenly through \
     the remainder; and 0x00000000, 0x80000000 and 0xFFFFFFFF written over eight four-byte-aligned \
     slots spaced evenly through the first 256 bytes. Exhaustive single-byte mutation is not \
     claimed and is not performed. On top of that, every base that parses as a PE, an ELF or a \
     Mach-O gets a structure-aware rewrite of its own section, segment or load-command table: \
     zero-raw-size sections with a large virtual span, zero-length sections, sections forced to \
     overlap, section addresses and file pointers pushed off alignment, sizes and counts inflated \
     to the format's own limit, raw pointers past the end of file, a size-of-headers past the end \
     of file, a PE offset that points at itself, the section table reversed, ELF program headers \
     placed over the ELF header, a zero program-header entry size, and a Mach-O load command of \
     zero size, which are the self-referential shapes each format allows. Every structural variant \
     runs in both sweeps and none is sampled out. The core sweep takes every sixth mutation \
     variant of each base; the deep sweep takes every variant. Entry points marked expensive, \
     which are the unpackers, the stub \
     emulator, the decompiler and the whole-image analyses, receive only inputs of 8192 bytes or \
     fewer, because one of them needs 103 seconds on a 22 kilobyte image and would otherwise turn \
     the suite into a benchmark; every truncation of a committed fixture below that cap still \
     reaches them.";

fn truncation_boundaries(len: usize) -> Vec<usize> {
    let mut cuts: Vec<usize> = vec![0];
    let mut step: usize = 1;
    while step < len {
        cuts.push(step);
        step = step.saturating_mul(2);
    }
    cuts.push(len / 4);
    cuts.push(len / 2);
    cuts.push(len.saturating_mul(3) / 4);
    cuts.push(len.saturating_sub(1));
    cuts.retain(|cut: &usize| *cut <= len);
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

fn push_variant(out: &mut Vec<HostileInput>, label: String, bytes: Vec<u8>) {
    out.push(HostileInput { label, bytes });
}

pub(crate) fn variants_of(name: &str, base: &[u8]) -> Vec<HostileInput> {
    let mut out: Vec<HostileInput> = Vec::new();
    push_variant(out.as_mut(), format!("{name}/whole"), base.to_vec());

    for cut in truncation_boundaries(base.len()) {
        push_variant(
            &mut out,
            format!("{name}/truncated@{cut}"),
            base[..cut].to_vec(),
        );
    }

    let header_end: usize = HEADER_WINDOW.min(base.len());
    for offset in (0..header_end).step_by(HEADER_MUTATION_STRIDE) {
        let mut mutated: Vec<u8> = base.to_vec();
        if let Some(slot) = mutated.get_mut(offset) {
            *slot ^= 0xFF;
        }
        push_variant(&mut out, format!("{name}/flip@{offset}"), mutated);
    }

    if base.len() > header_end {
        let span: usize = base.len() - header_end;
        let stride: usize = (span / BODY_MUTATION_SAMPLES).max(1);
        for index in 0..BODY_MUTATION_SAMPLES {
            let offset: usize = header_end + index * stride;
            if offset >= base.len() {
                break;
            }
            let mut mutated: Vec<u8> = base.to_vec();
            if let Some(slot) = mutated.get_mut(offset) {
                *slot ^= 0xFF;
            }
            push_variant(&mut out, format!("{name}/body-flip@{offset}"), mutated);
        }
    }

    let slot_stride: usize = (header_end / FIELD_EXTREME_SLOTS).max(4) & !3;
    for slot in 0..FIELD_EXTREME_SLOTS {
        let offset: usize = slot * slot_stride;
        if offset + 4 > base.len() {
            break;
        }
        for (tag, value) in [
            ("zero", 0u32),
            ("high", 0x8000_0000u32),
            ("max", 0xFFFF_FFFFu32),
        ] {
            let mut mutated: Vec<u8> = base.to_vec();
            if let Some(window) = mutated.get_mut(offset..offset + 4) {
                window.copy_from_slice(&value.to_le_bytes());
            }
            push_variant(&mut out, format!("{name}/{tag}@{offset}"), mutated);
        }
    }

    out
}

const PE_SECTION_ENTRY: usize = 40;
const PE_SECTION_VIRTUAL_SIZE: usize = 8;
const PE_SECTION_VIRTUAL_ADDRESS: usize = 12;
const PE_SECTION_RAW_SIZE: usize = 16;
const PE_SECTION_RAW_POINTER: usize = 20;
const PE_OPTIONAL_SIZE_OF_HEADERS: usize = 60;
const HOSTILE_VIRTUAL_SPAN: u32 = 0x0100_0000;
const HOSTILE_NEAR_MAX: u32 = 0xFFFF_FFF0;
const ELF_PROGRAM_HEADER_REWRITE_CAP: usize = 4096;

fn put_u16_le(buf: &mut [u8], at: usize, value: u16) -> bool {
    let Some(end): Option<usize> = at.checked_add(2) else {
        return false;
    };
    buf.get_mut(at..end).is_some_and(|window: &mut [u8]| {
        window.copy_from_slice(&value.to_le_bytes());
        true
    })
}

fn put_u32(buf: &mut [u8], at: usize, value: u32, little_endian: bool) -> bool {
    let Some(end): Option<usize> = at.checked_add(4) else {
        return false;
    };
    let raw: [u8; 4] = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    buf.get_mut(at..end).is_some_and(|window: &mut [u8]| {
        window.copy_from_slice(&raw);
        true
    })
}

fn put_u64(buf: &mut [u8], at: usize, value: u64, little_endian: bool) -> bool {
    let Some(end): Option<usize> = at.checked_add(8) else {
        return false;
    };
    let raw: [u8; 8] = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    buf.get_mut(at..end).is_some_and(|window: &mut [u8]| {
        window.copy_from_slice(&raw);
        true
    })
}

fn read_u16_at(buf: &[u8], at: usize, little_endian: bool) -> Option<u16> {
    let end: usize = at.checked_add(2)?;
    let raw: [u8; 2] = buf.get(at..end)?.try_into().ok()?;
    Some(if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_u16_le(buf: &[u8], at: usize) -> Option<u16> {
    read_u16_at(buf, at, true)
}

fn read_u32_at(buf: &[u8], at: usize, little_endian: bool) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let raw: [u8; 4] = buf.get(at..end)?.try_into().ok()?;
    Some(if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

type SectionRewrite = fn(&mut Vec<u8>, usize, u32);

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    coff: usize,
    optional_header: usize,
    section_table: usize,
    section_count: usize,
}

fn pe_layout(base: &[u8]) -> Option<PeLayout> {
    if base.get(..2)? != b"MZ" {
        return None;
    }
    let e_lfanew: usize = read_u32_at(base, 0x3C, true)? as usize;
    if base.get(e_lfanew..e_lfanew.checked_add(4)?)? != b"PE\x00\x00" {
        return None;
    }
    let coff: usize = e_lfanew.checked_add(4)?;
    let section_count: usize = usize::from(read_u16_le(base, coff.checked_add(2)?)?);
    let optional_size: usize = usize::from(read_u16_le(base, coff.checked_add(16)?)?);
    let optional_header: usize = coff.checked_add(20)?;
    let section_table: usize = optional_header.checked_add(optional_size)?;
    let span: usize = section_count.checked_mul(PE_SECTION_ENTRY)?;
    if section_table.checked_add(span)? > base.len() || section_count == 0 {
        return None;
    }
    Some(PeLayout {
        coff,
        optional_header,
        section_table,
        section_count,
    })
}

fn pe_structural_variants(name: &str, base: &[u8], out: &mut Vec<HostileInput>) {
    let Some(layout): Option<PeLayout> = pe_layout(base) else {
        return;
    };
    let entry_at = |index: usize| -> usize { layout.section_table + index * PE_SECTION_ENTRY };
    let first_virtual_address: u32 =
        read_u32_at(base, entry_at(0) + PE_SECTION_VIRTUAL_ADDRESS, true).unwrap_or_default();

    let per_section: [(&str, SectionRewrite); 6] = [
        ("blank-sections", |buf: &mut Vec<u8>, at: usize, _: u32| {
            put_u32(buf, at + PE_SECTION_RAW_SIZE, 0, true);
            put_u32(
                buf,
                at + PE_SECTION_VIRTUAL_SIZE,
                HOSTILE_VIRTUAL_SPAN,
                true,
            );
        }),
        (
            "zero-length-sections",
            |buf: &mut Vec<u8>, at: usize, _: u32| {
                put_u32(buf, at + PE_SECTION_RAW_SIZE, 0, true);
                put_u32(buf, at + PE_SECTION_VIRTUAL_SIZE, 0, true);
            },
        ),
        (
            "overlapping-sections",
            |buf: &mut Vec<u8>, at: usize, first: u32| {
                put_u32(buf, at + PE_SECTION_VIRTUAL_ADDRESS, first, true);
                put_u32(
                    buf,
                    at + PE_SECTION_VIRTUAL_SIZE,
                    HOSTILE_VIRTUAL_SPAN,
                    true,
                );
            },
        ),
        (
            "unaligned-sections",
            |buf: &mut Vec<u8>, at: usize, _: u32| {
                for field in [PE_SECTION_VIRTUAL_ADDRESS, PE_SECTION_RAW_POINTER] {
                    let bumped: u32 = read_u32_at(buf, at + field, true)
                        .unwrap_or_default()
                        .wrapping_add(1);
                    put_u32(buf, at + field, bumped, true);
                }
            },
        ),
        (
            "inflated-section-sizes",
            |buf: &mut Vec<u8>, at: usize, _: u32| {
                put_u32(buf, at + PE_SECTION_RAW_SIZE, HOSTILE_NEAR_MAX, true);
                put_u32(buf, at + PE_SECTION_VIRTUAL_SIZE, HOSTILE_NEAR_MAX, true);
            },
        ),
        (
            "raw-pointer-past-eof",
            |buf: &mut Vec<u8>, at: usize, _: u32| {
                put_u32(buf, at + PE_SECTION_RAW_POINTER, HOSTILE_NEAR_MAX, true);
            },
        ),
    ];
    for (tag, rewrite) in per_section {
        let mut mutated: Vec<u8> = base.to_vec();
        for index in 0..layout.section_count {
            rewrite(&mut mutated, entry_at(index), first_virtual_address);
        }
        push_variant(out, format!("{name}/{tag}"), mutated);
    }

    let mut inflated_count: Vec<u8> = base.to_vec();
    put_u16_le(&mut inflated_count, layout.coff + 2, u16::MAX);
    push_variant(
        out,
        format!("{name}/inflated-section-count"),
        inflated_count,
    );

    let mut headers_past_eof: Vec<u8> = base.to_vec();
    put_u32(
        &mut headers_past_eof,
        layout.optional_header + PE_OPTIONAL_SIZE_OF_HEADERS,
        u32::MAX,
        true,
    );
    push_variant(out, format!("{name}/headers-past-eof"), headers_past_eof);

    let mut self_referential: Vec<u8> = base.to_vec();
    put_u32(&mut self_referential, 0x3C, 0x3C, true);
    push_variant(
        out,
        format!("{name}/pe-offset-points-at-itself"),
        self_referential,
    );

    let mut descending: Vec<u8> = base.to_vec();
    for index in 0..layout.section_count {
        let source: usize = entry_at(layout.section_count - 1 - index);
        let Some(entry): Option<Vec<u8>> = base
            .get(source..source + PE_SECTION_ENTRY)
            .map(<[u8]>::to_vec)
        else {
            continue;
        };
        let target: usize = entry_at(index);
        if let Some(window) = descending.get_mut(target..target + PE_SECTION_ENTRY) {
            window.copy_from_slice(&entry);
        }
    }
    push_variant(out, format!("{name}/descending-section-order"), descending);
}

fn elf_structural_variants(name: &str, base: &[u8], out: &mut Vec<HostileInput>) {
    if base.get(..4) != Some(b"\x7FELF".as_slice()) {
        return;
    }
    let Some(&class): Option<&u8> = base.get(4) else {
        return;
    };
    let Some(&data): Option<&u8> = base.get(5) else {
        return;
    };
    let bits64: bool = class == 2;
    let little_endian: bool = data != 2;
    let (phoff_at, phentsize_at, phnum_at, shnum_at): (usize, usize, usize, usize) = if bits64 {
        (32, 54, 56, 60)
    } else {
        (28, 42, 44, 48)
    };

    for (tag, at, value) in [
        ("elf-phnum-max", phnum_at, u16::MAX),
        ("elf-shnum-max", shnum_at, u16::MAX),
        ("elf-phentsize-zero", phentsize_at, 0),
    ] {
        let mut mutated: Vec<u8> = base.to_vec();
        let raw: u16 = if little_endian {
            value
        } else {
            value.swap_bytes()
        };
        if put_u16_le(&mut mutated, at, raw) {
            push_variant(out, format!("{name}/{tag}"), mutated);
        }
    }

    let mut phoff_self: Vec<u8> = base.to_vec();
    let wrote: bool = if bits64 {
        put_u64(&mut phoff_self, phoff_at, 0, little_endian)
    } else {
        put_u32(&mut phoff_self, phoff_at, 0, little_endian)
    };
    if wrote {
        push_variant(
            out,
            format!("{name}/elf-program-headers-overlap-the-elf-header"),
            phoff_self,
        );
    }

    let phentsize: usize =
        usize::from(read_u16_at(base, phentsize_at, little_endian).unwrap_or_default());
    let phnum: usize = usize::from(read_u16_at(base, phnum_at, little_endian).unwrap_or_default())
        .min(ELF_PROGRAM_HEADER_REWRITE_CAP);
    let phoff: usize = if bits64 {
        base.get(phoff_at..phoff_at + 8)
            .and_then(|raw: &[u8]| <[u8; 8]>::try_from(raw).ok())
            .map(|raw: [u8; 8]| {
                if little_endian {
                    u64::from_le_bytes(raw)
                } else {
                    u64::from_be_bytes(raw)
                }
            })
            .and_then(|value: u64| usize::try_from(value).ok())
            .unwrap_or_default()
    } else {
        read_u32_at(base, phoff_at, little_endian).unwrap_or_default() as usize
    };
    if phentsize == 0 || phnum == 0 {
        return;
    }
    let (vaddr_at, filesz_at, memsz_at): (usize, usize, usize) =
        if bits64 { (16, 32, 40) } else { (8, 16, 20) };
    for (tag, vaddr, sizes) in [
        ("elf-segments-overlap", 0u64, u64::from(u32::MAX)),
        ("elf-segments-zero-length", 0u64, 0u64),
    ] {
        let mut mutated: Vec<u8> = base.to_vec();
        let mut wrote_any: bool = false;
        for index in 0..phnum {
            let Some(entry): Option<usize> = index
                .checked_mul(phentsize)
                .and_then(|delta: usize| phoff.checked_add(delta))
            else {
                break;
            };
            let mut ok: bool = true;
            for (field, value) in [(vaddr_at, vaddr), (filesz_at, sizes), (memsz_at, sizes)] {
                let target: usize = entry + field;
                ok &= if bits64 {
                    put_u64(&mut mutated, target, value, little_endian)
                } else {
                    put_u32(
                        &mut mutated,
                        target,
                        u32::try_from(value).unwrap_or(u32::MAX),
                        little_endian,
                    )
                };
            }
            wrote_any |= ok;
        }
        if wrote_any {
            push_variant(out, format!("{name}/{tag}"), mutated);
        }
    }
}

fn macho_structural_variants(name: &str, base: &[u8], out: &mut Vec<HostileInput>) {
    let Some(magic): Option<u32> = read_u32_at(base, 0, true) else {
        return;
    };
    if magic == 0xBEBA_FECA {
        for (tag, at, value) in [
            ("macho-fat-nfat-max", 4usize, u32::MAX),
            ("macho-fat-slice-offset-zero", 16usize, 0u32),
            ("macho-fat-slice-offset-max", 16usize, u32::MAX),
        ] {
            let mut mutated: Vec<u8> = base.to_vec();
            if put_u32(&mut mutated, at, value, false) {
                push_variant(out, format!("{name}/{tag}"), mutated);
            }
        }
        return;
    }
    let bits64: bool = magic == 0xFEED_FACF;
    if !bits64 && magic != 0xFEED_FACE {
        return;
    }
    let first_command: usize = if bits64 { 32 } else { 28 };
    for (tag, at, value) in [
        ("macho-ncmds-max", 16usize, u32::MAX),
        ("macho-first-cmdsize-zero", first_command + 4, 0u32),
        ("macho-first-cmdsize-max", first_command + 4, u32::MAX),
    ] {
        let mut mutated: Vec<u8> = base.to_vec();
        if put_u32(&mut mutated, at, value, true) {
            push_variant(out, format!("{name}/{tag}"), mutated);
        }
    }
}

pub(crate) fn structural_variants_of(name: &str, base: &[u8]) -> Vec<HostileInput> {
    let mut out: Vec<HostileInput> = Vec::new();
    pe_structural_variants(name, base, &mut out);
    elf_structural_variants(name, base, &mut out);
    macho_structural_variants(name, base, &mut out);
    out
}

pub(crate) fn crafted_pe32_plus() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    buf[0x98..0x9A].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[0x98 + 24..0x98 + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    buf[0x98 + 56..0x98 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    buf[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
    let section: usize = 0x98 + 0xF0;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    buf
}

pub(crate) fn crafted_pe32() -> Vec<u8> {
    let mut buf: Vec<u8> = crafted_pe32_plus();
    buf[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf
}

pub(crate) fn crafted_elf(bits64: bool, little_endian: bool) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 512];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = if bits64 { 2 } else { 1 };
    buf[5] = if little_endian { 1 } else { 2 };
    buf[6] = 1;
    let put16 = |buf: &mut Vec<u8>, at: usize, value: u16| {
        let raw: [u8; 2] = if little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        buf[at..at + 2].copy_from_slice(&raw);
    };
    put16(&mut buf, 16, 2);
    if bits64 {
        put16(&mut buf, 18, 0x3E);
        put16(&mut buf, 52, 64);
        put16(&mut buf, 54, 56);
        put16(&mut buf, 56, 1);
        let phoff: [u8; 8] = if little_endian {
            64u64.to_le_bytes()
        } else {
            64u64.to_be_bytes()
        };
        buf[32..40].copy_from_slice(&phoff);
    } else {
        put16(&mut buf, 18, 3);
        put16(&mut buf, 40, 52);
        put16(&mut buf, 42, 32);
        put16(&mut buf, 44, 1);
        let phoff: [u8; 4] = if little_endian {
            52u32.to_le_bytes()
        } else {
            52u32.to_be_bytes()
        };
        buf[28..32].copy_from_slice(&phoff);
    }
    buf
}

pub(crate) fn crafted_macho_thin() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    buf[12..16].copy_from_slice(&2u32.to_le_bytes());
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    buf[20..24].copy_from_slice(&72u32.to_le_bytes());
    buf[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    buf[36..40].copy_from_slice(&72u32.to_le_bytes());
    buf
}

pub(crate) fn crafted_macho_fat() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
    buf[20..24].copy_from_slice(&128u32.to_be_bytes());
    buf[24..28].copy_from_slice(&64u32.to_be_bytes());
    buf[128..132].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf
}

pub(crate) fn crafted_flat_image() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0x90u8; 4096];
    buf[0..8].copy_from_slice(&0xFFFF_FFFB_0000_0000u64.to_le_bytes());
    buf
}

pub(crate) fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root: &Path| root.join("corpus").join("native"))
        .unwrap_or_default()
}

pub(crate) fn committed_image(relative: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_root().join(relative)).ok()
}

pub(crate) const COMPILED_VM_PROBE: &str = "<a virtual machine probe compiled by clang>";

fn clang_path() -> Option<String> {
    ["clang", "clang-18", "clang-17"]
        .into_iter()
        .find(|candidate: &&str| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|out: std::process::Output| out.status.success())
        })
        .map(str::to_owned)
}

pub(crate) fn compiled_vm_probe() -> Option<Vec<u8>> {
    let clang: String = clang_path()?;
    let fixture: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("vm_oracle.c");
    let template: String = std::fs::read_to_string(&fixture).ok()?;
    let out_dir: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("resilience_vm_probe");
    std::fs::create_dir_all(&out_dir).ok()?;

    let mut inc: String = String::new();
    for index in 0..256u32 {
        if index % 16 == 0 {
            inc.push_str("\n    ");
        }
        let byte: u8 = index as u8;
        let _ = write!(inc, "0x{byte:02x}, ");
    }
    inc.push('\n');
    let inc_path: PathBuf = out_dir.join("resilience_bytecode.inc");
    std::fs::write(&inc_path, inc).ok()?;

    let source_path: PathBuf = out_dir.join("resilience_vm.c");
    let patched: String = template.replace(
        "#include \"vm_oracle_bytecode.inc\"",
        "#include \"resilience_bytecode.inc\"",
    );
    std::fs::write(&source_path, patched).ok()?;

    let binary: PathBuf = out_dir.join(if cfg!(windows) {
        "resilience_vm.exe"
    } else {
        "resilience_vm"
    });
    let built: std::process::Output = std::process::Command::new(&clang)
        .args(["-O1", "-fno-inline"])
        .arg(&source_path)
        .arg("-o")
        .arg(&binary)
        .output()
        .ok()?;
    if !built.status.success() {
        return None;
    }
    std::fs::read(&binary).ok()
}
