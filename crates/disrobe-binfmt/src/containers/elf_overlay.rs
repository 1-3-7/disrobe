use crate::error::{Error, Result};

const ELF_MAGIC: &[u8; 4] = &[0x7f, b'E', b'L', b'F'];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfOverlay {
    pub image_end: u64,
    pub overlay_start: u64,
    pub overlay_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfOverlayCarve {
    pub overlay: ElfOverlay,
    pub appended_kind: Option<crate::container::ContainerKind>,
}

struct ElfShape {
    is_64: bool,
    little: bool,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
}

fn parse_shape(bytes: &[u8]) -> Result<ElfShape> {
    if bytes.len() < 64 || !bytes.starts_with(ELF_MAGIC) {
        return Err(Error::ElfOverlay("elf: not an ELF image".to_owned()));
    }
    let class: u8 = bytes[4];
    let data: u8 = bytes[5];
    let is_64: bool = match class {
        1 => false,
        2 => true,
        other => {
            return Err(Error::ElfOverlay(format!("elf: bad EI_CLASS {other}")));
        }
    };
    let little: bool = match data {
        1 => true,
        2 => false,
        other => {
            return Err(Error::ElfOverlay(format!("elf: bad EI_DATA {other}")));
        }
    };
    let rd16 = |off: usize| -> u16 {
        let b: [u8; 2] = [bytes[off], bytes[off + 1]];
        if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let rd32 = |off: usize| -> u32 {
        let b: [u8; 4] = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    let rd64 = |off: usize| -> u64 {
        let mut b: [u8; 8] = [0u8; 8];
        b.copy_from_slice(&bytes[off..off + 8]);
        if little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        }
    };
    if is_64 {
        Ok(ElfShape {
            is_64,
            little,
            phoff: rd64(32),
            phentsize: rd16(54),
            phnum: rd16(56),
            shoff: rd64(40),
            shentsize: rd16(58),
            shnum: rd16(60),
        })
    } else {
        Ok(ElfShape {
            is_64,
            little,
            phoff: u64::from(rd32(28)),
            phentsize: rd16(42),
            phnum: rd16(44),
            shoff: u64::from(rd32(32)),
            shentsize: rd16(46),
            shnum: rd16(48),
        })
    }
}

fn segment_extents(bytes: &[u8], shape: &ElfShape) -> u64 {
    let mut max_end: u64 = 0;
    let entry: usize = shape.phentsize as usize;
    for i in 0..shape.phnum as usize {
        let base: usize = match usize::try_from(shape.phoff).ok().and_then(|o: usize| {
            let start: usize = o.checked_add(i.checked_mul(entry)?)?;
            (start + entry <= bytes.len()).then_some(start)
        }) {
            Some(b) => b,
            None => continue,
        };
        let (p_offset, p_filesz): (u64, u64) = if shape.is_64 {
            (
                read_at(bytes, base + 8, shape.little),
                read_at(bytes, base + 32, shape.little),
            )
        } else {
            (
                u64::from(read32_at(bytes, base + 4, shape.little)),
                u64::from(read32_at(bytes, base + 16, shape.little)),
            )
        };
        max_end = max_end.max(p_offset.saturating_add(p_filesz));
    }
    max_end
}

fn read_at(bytes: &[u8], off: usize, little: bool) -> u64 {
    let mut b: [u8; 8] = [0u8; 8];
    if let Some(s) = bytes.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    if little {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

fn read32_at(bytes: &[u8], off: usize, little: bool) -> u32 {
    let mut b: [u8; 4] = [0u8; 4];
    if let Some(s) = bytes.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    if little {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

pub fn elf_image_end(bytes: &[u8]) -> Result<u64> {
    let shape: ElfShape = parse_shape(bytes)?;
    let sh_end: u64 = if shape.shnum > 0 {
        shape
            .shoff
            .saturating_add(u64::from(shape.shnum).saturating_mul(u64::from(shape.shentsize)))
    } else {
        0
    };
    let ph_end: u64 = if shape.phnum > 0 {
        shape
            .phoff
            .saturating_add(u64::from(shape.phnum).saturating_mul(u64::from(shape.phentsize)))
    } else {
        0
    };
    let seg_end: u64 = segment_extents(bytes, &shape);
    Ok(sh_end.max(ph_end).max(seg_end))
}

pub fn detect_elf_overlay(bytes: &[u8]) -> Option<ElfOverlay> {
    let image_end: u64 = elf_image_end(bytes).ok()?;
    let total: u64 = bytes.len() as u64;
    if image_end == 0 || image_end >= total {
        return None;
    }
    let overlay_len: u64 = total - image_end;
    if overlay_len < 4 {
        return None;
    }
    Some(ElfOverlay {
        image_end,
        overlay_start: image_end,
        overlay_len,
    })
}

pub fn carve_elf_overlay(bytes: &[u8]) -> Result<ElfOverlayCarve> {
    let overlay: ElfOverlay = detect_elf_overlay(bytes)
        .ok_or_else(|| Error::ElfOverlay("elf: no appended overlay beyond image end".to_owned()))?;
    let start: usize = usize::try_from(overlay.overlay_start)
        .map_err(|_| Error::ElfOverlay("elf: overlay offset overflow".to_owned()))?;
    let slice: &[u8] = bytes
        .get(start..)
        .ok_or_else(|| Error::ElfOverlay("elf: overlay slice out of bounds".to_owned()))?;
    let appended_kind: Option<crate::container::ContainerKind> =
        crate::container::detect_container(slice);
    Ok(ElfOverlayCarve {
        overlay,
        appended_kind,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn minimal_elf64(extra_after_image: &[u8]) -> Vec<u8> {
        let mut e: Vec<u8> = vec![0u8; 64];
        e[..4].copy_from_slice(ELF_MAGIC);
        e[4] = 2;
        e[5] = 1;
        e[6] = 1;
        e[16..18].copy_from_slice(&2u16.to_le_bytes());
        e[18..20].copy_from_slice(&62u16.to_le_bytes());
        e[40..48].copy_from_slice(&0u64.to_le_bytes());
        e[58..60].copy_from_slice(&0u16.to_le_bytes());
        e[60..62].copy_from_slice(&0u16.to_le_bytes());
        e[54..56].copy_from_slice(&56u16.to_le_bytes());
        e[56..58].copy_from_slice(&1u16.to_le_bytes());
        e[32..40].copy_from_slice(&64u64.to_le_bytes());
        let mut ph: Vec<u8> = vec![0u8; 56];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes());
        ph[8..16].copy_from_slice(&0u64.to_le_bytes());
        ph[32..40].copy_from_slice(&(64u64 + 56).to_le_bytes());
        e.extend_from_slice(&ph);
        e.extend_from_slice(extra_after_image);
        e
    }

    #[test]
    fn finds_appended_cpio_overlay() {
        let cpio: &[u8] = b"070701appended-initramfs-marker-bytes-padding-here-XX";
        let elf: Vec<u8> = minimal_elf64(cpio);
        let carve: ElfOverlayCarve = carve_elf_overlay(&elf).expect("carve overlay");
        assert_eq!(carve.overlay.overlay_start, 64 + 56);
        let start: usize = carve.overlay.overlay_start as usize;
        assert_eq!(&elf[start..start + 6], b"070701");
        assert_eq!(carve.overlay.overlay_len as usize, cpio.len());
    }

    #[test]
    fn bare_elf_has_no_overlay() {
        let elf: Vec<u8> = minimal_elf64(&[]);
        assert!(detect_elf_overlay(&elf).is_none());
    }
}
