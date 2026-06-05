#[must_use]
pub fn minimal_elf64() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_elf32() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..4].copy_from_slice(b"\x7FELF");
    buf[4] = 1;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&0x03u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_elf_relocatable_kmod() -> Vec<u8> {
    let mut buf: Vec<u8> = minimal_elf64();
    buf[16..18].copy_from_slice(&1u16.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_pe32() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x200];
    buf[0..2].copy_from_slice(b"MZ");
    let pe_off: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    buf[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[0x84 + 16..0x84 + 18].copy_from_slice(&0xE0u16.to_le_bytes());
    buf[0x84 + 20..0x84 + 22].copy_from_slice(&0x010Bu16.to_le_bytes());
    let subsystem_off: usize = 0x84 + 20 + 0x44;
    buf[subsystem_off..subsystem_off + 2].copy_from_slice(&3u16.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_efi_pe() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x200];
    buf[0..2].copy_from_slice(b"MZ");
    let pe_off: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[0x84 + 16..0x84 + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    buf[0x84 + 20..0x84 + 22].copy_from_slice(&0x020Bu16.to_le_bytes());
    let subsystem_off: usize = 0x84 + 20 + 0x5C;
    buf[subsystem_off..subsystem_off + 2].copy_from_slice(&10u16.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_macho64() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    buf[8..12].copy_from_slice(&0x0000_0003u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0x0000_0002u32.to_le_bytes());
    buf
}

#[must_use]
pub fn minimal_macho_fat() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x40];
    buf[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf
}

#[must_use]
pub fn tiny_coff_x64() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x40];
    buf[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    buf
}

#[must_use]
pub fn packed_upx_elf64_marker() -> Vec<u8> {
    let mut buf: Vec<u8> = minimal_elf64();
    buf.resize(0x400, 0);
    buf[0x200..0x204].copy_from_slice(b"UPX!");
    buf[0x210..0x214].copy_from_slice(b"UPX0");
    buf[0x220..0x224].copy_from_slice(b"UPX1");
    buf
}

#[must_use]
pub fn minimal_ne() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..2].copy_from_slice(b"MZ");
    let off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&off.to_le_bytes());
    buf[0x40..0x42].copy_from_slice(b"NE");
    buf
}

#[must_use]
pub fn minimal_lx() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..2].copy_from_slice(b"MZ");
    let off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&off.to_le_bytes());
    buf[0x40..0x42].copy_from_slice(b"LX");
    buf
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::format::{DetectedFormat, NativeFormat, detect};
    use crate::packers::{Detection, Packer};

    #[test]
    fn fixture_elf64_classified() {
        let d: DetectedFormat = detect(&minimal_elf64()).expect("elf64");
        assert_eq!(d.kind, NativeFormat::Elf64);
    }

    #[test]
    fn fixture_elf32_classified() {
        let d: DetectedFormat = detect(&minimal_elf32()).expect("elf32");
        assert_eq!(d.kind, NativeFormat::Elf32);
    }

    #[test]
    fn fixture_kmod_classified() {
        let d: DetectedFormat = detect(&minimal_elf_relocatable_kmod()).expect("kmod");
        assert_eq!(d.kind, NativeFormat::KernelModule);
    }

    #[test]
    fn fixture_pe32_classified() {
        let d: DetectedFormat = detect(&minimal_pe32()).expect("pe");
        assert!(matches!(d.kind, NativeFormat::Pe32 | NativeFormat::EfiPe));
    }

    #[test]
    fn fixture_efi_pe_classified() {
        let d: DetectedFormat = detect(&minimal_efi_pe()).expect("efi");
        assert_eq!(d.kind, NativeFormat::EfiPe);
    }

    #[test]
    fn fixture_macho64_classified() {
        let d: DetectedFormat = detect(&minimal_macho64()).expect("macho");
        assert_eq!(d.kind, NativeFormat::MachO64);
    }

    #[test]
    fn fixture_macho_fat_classified() {
        let d: DetectedFormat = detect(&minimal_macho_fat()).expect("fat");
        assert_eq!(d.kind, NativeFormat::MachOFat);
    }

    #[test]
    fn fixture_coff_classified() {
        let d: DetectedFormat = detect(&tiny_coff_x64()).expect("coff");
        assert_eq!(d.kind, NativeFormat::Coff);
    }

    #[test]
    fn fixture_ne_classified() {
        let d: DetectedFormat = detect(&minimal_ne()).expect("ne");
        assert_eq!(d.kind, NativeFormat::Ne);
    }

    #[test]
    fn fixture_lx_classified() {
        let d: DetectedFormat = detect(&minimal_lx()).expect("lx");
        assert_eq!(d.kind, NativeFormat::Lx);
    }

    #[test]
    fn upx_packed_elf_yields_packer_hits() {
        let buf: Vec<u8> = packed_upx_elf64_marker();
        let hits: Vec<Detection> = crate::packers::detect(&buf);
        assert!(hits.iter().any(|h| h.packer == Packer::Upx));
    }
}
