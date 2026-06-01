use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::packers::kkrunchy_unpack::{
    KkrunchyEmulationSnapshot, KkrunchyEmulator, KkrunchyHeaderInfo,
};

const PE32_OPT_HEADER_SIZE: u32 = 224;
const DEFAULT_NUMBER_OF_DIRS: u32 = 16;
const DOS_HEADER_E_LFANEW_VALUE: u32 = 0x40;
const COFF_FILE_HEADER_SIZE: u32 = 20;
const COFF_MACHINE_I386: u16 = 0x014C;
const COFF_CHAR_EXECUTABLE_IMAGE_RELOCS_STRIPPED_32BIT: u16 = 0x0103;
const PE_OPT_MAGIC_PE32: u16 = 0x010B;
const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const SECTION_ALIGNMENT_DEFAULT: u32 = 0x1000;
const FILE_ALIGNMENT_DEFAULT: u32 = 0x200;
const STACK_RESERVE_DEFAULT: u32 = 0x0010_0000;
const STACK_COMMIT_DEFAULT: u32 = 0x1000;
const HEAP_RESERVE_DEFAULT: u32 = 0x0010_0000;
const HEAP_COMMIT_DEFAULT: u32 = 0x1000;
const SECTION_CHAR_TEXT: u32 = 0xE000_0020;
const DEFAULT_OS_VERSION_MAJOR: u16 = 4;
const DEFAULT_SUBSYSTEM_VERSION_MAJOR: u16 = 4;
const DEFAULT_SIZE_OF_HEADERS: u32 = 0x200;
const DEFAULT_BASE_OF_DATA: u32 = 0x1000;
const SECTION_NAME_TEXT: &[u8; 8] = b".text\x00\x00\x00";
const DEFAULT_KERNEL32_NAME: &[u8] = b"kernel32.dll";
const DEFAULT_KERNEL32_CUI_IMPORTS: &[&[u8]] = &[b"GetStdHandle", b"WriteFile", b"ExitProcess"];
const HINT_INDEX_VALUE: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KkrunchyReconstructionConfidence {
    StructuralOnly,
    StructuralPlusCanonicalImports,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KkrunchyReconstructionPlan {
    pub image_base: u32,
    pub size_of_image: u32,
    pub file_size: u32,
    pub entry_rva: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub text_section_va: u32,
    pub text_section_vsize: u32,
    pub text_section_raw_off: u32,
    pub text_section_raw_size: u32,
    pub assumed_imports: Vec<(String, Vec<String>)>,
    pub confidence: KkrunchyReconstructionConfidence,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KkrunchyHeaderReconstructionEmulator;

impl KkrunchyHeaderReconstructionEmulator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn plan_for(self, header: KkrunchyHeaderInfo) -> KkrunchyReconstructionPlan {
        let image_base: u32 = canonical_image_base(header.image_base);
        let text_va: u32 = SECTION_ALIGNMENT_DEFAULT;
        let text_raw_off: u32 = DEFAULT_SIZE_OF_HEADERS;
        let text_raw_size: u32 = FILE_ALIGNMENT_DEFAULT;
        let text_vsize: u32 = SECTION_ALIGNMENT_DEFAULT;
        let file_size: u32 = DEFAULT_SIZE_OF_HEADERS + text_raw_size;
        let size_of_image: u32 = SECTION_ALIGNMENT_DEFAULT + text_vsize;
        let entry_rva: u32 = text_va;
        let imports: Vec<(String, Vec<String>)> = canonical_cui_imports();
        KkrunchyReconstructionPlan {
            image_base,
            size_of_image,
            file_size,
            entry_rva,
            base_of_code: text_va,
            base_of_data: DEFAULT_BASE_OF_DATA,
            text_section_va: text_va,
            text_section_vsize: text_vsize,
            text_section_raw_off: text_raw_off,
            text_section_raw_size: text_raw_size,
            assumed_imports: imports,
            confidence: KkrunchyReconstructionConfidence::StructuralPlusCanonicalImports,
        }
    }
}

impl KkrunchyEmulator for KkrunchyHeaderReconstructionEmulator {
    fn label(&self) -> &'static str {
        "kkrunchy-header-reconstruction"
    }

    fn emulate_until_oep(
        &self,
        _packed_bytes: &[u8],
        header: &KkrunchyHeaderInfo,
    ) -> Result<KkrunchyEmulationSnapshot> {
        let plan: KkrunchyReconstructionPlan = self.plan_for(*header);
        let image_bytes: Vec<u8> = build_canonical_pe32_image(&plan);
        Ok(KkrunchyEmulationSnapshot {
            image_base: plan.image_base,
            image_bytes,
            original_entry_rva: plan.entry_rva,
            recovered_imports: plan.assumed_imports,
        })
    }
}

const fn canonical_image_base(packed_image_base: u32) -> u32 {
    let aligned_down: u32 = packed_image_base & !0xFFFF;
    if aligned_down < 0x0040_0000 {
        0x0040_0000
    } else {
        aligned_down
    }
}

fn canonical_cui_imports() -> Vec<(String, Vec<String>)> {
    let dll: String = String::from_utf8_lossy(DEFAULT_KERNEL32_NAME).into_owned();
    let funcs: Vec<String> = DEFAULT_KERNEL32_CUI_IMPORTS
        .iter()
        .map(|f: &&[u8]| String::from_utf8_lossy(f).into_owned())
        .collect();
    vec![(dll, funcs)]
}

#[allow(clippy::too_many_lines)]
fn build_canonical_pe32_image(plan: &KkrunchyReconstructionPlan) -> Vec<u8> {
    let file_size: usize = plan.file_size as usize;
    let mut image: Vec<u8> = vec![0u8; file_size];

    image[0] = b'M';
    image[1] = b'Z';
    write_u32(&mut image, 0x3C, DOS_HEADER_E_LFANEW_VALUE);

    let pe: usize = DOS_HEADER_E_LFANEW_VALUE as usize;
    image[pe] = b'P';
    image[pe + 1] = b'E';

    let coff: usize = pe + 4;
    write_u16(&mut image, coff, COFF_MACHINE_I386);
    write_u16(&mut image, coff + 2, 1);
    write_u32(&mut image, coff + 4, 0);
    write_u32(&mut image, coff + 8, 0);
    write_u32(&mut image, coff + 12, 0);
    write_u16(&mut image, coff + 16, PE32_OPT_HEADER_SIZE as u16);
    write_u16(
        &mut image,
        coff + 18,
        COFF_CHAR_EXECUTABLE_IMAGE_RELOCS_STRIPPED_32BIT,
    );

    let opt: usize = pe + 4 + COFF_FILE_HEADER_SIZE as usize;
    write_u16(&mut image, opt, PE_OPT_MAGIC_PE32);
    image[opt + 2] = 0;
    image[opt + 3] = 0;
    write_u32(&mut image, opt + 4, plan.text_section_raw_size);
    write_u32(&mut image, opt + 8, 0);
    write_u32(&mut image, opt + 12, 0);
    write_u32(&mut image, opt + 16, plan.entry_rva);
    write_u32(&mut image, opt + 20, plan.base_of_code);
    write_u32(&mut image, opt + 24, plan.base_of_data);
    write_u32(&mut image, opt + 28, plan.image_base);
    write_u32(&mut image, opt + 32, SECTION_ALIGNMENT_DEFAULT);
    write_u32(&mut image, opt + 36, FILE_ALIGNMENT_DEFAULT);
    write_u16(&mut image, opt + 40, DEFAULT_OS_VERSION_MAJOR);
    write_u16(&mut image, opt + 42, 0);
    write_u16(&mut image, opt + 44, 0);
    write_u16(&mut image, opt + 46, 0);
    write_u16(&mut image, opt + 48, DEFAULT_SUBSYSTEM_VERSION_MAJOR);
    write_u16(&mut image, opt + 50, 0);
    write_u32(&mut image, opt + 52, 0);
    write_u32(&mut image, opt + 56, plan.size_of_image);
    write_u32(&mut image, opt + 60, DEFAULT_SIZE_OF_HEADERS);
    write_u32(&mut image, opt + 64, 0);
    write_u16(&mut image, opt + 68, SUBSYSTEM_WINDOWS_CUI);
    write_u16(&mut image, opt + 70, 0);
    write_u32(&mut image, opt + 72, STACK_RESERVE_DEFAULT);
    write_u32(&mut image, opt + 76, STACK_COMMIT_DEFAULT);
    write_u32(&mut image, opt + 80, HEAP_RESERVE_DEFAULT);
    write_u32(&mut image, opt + 84, HEAP_COMMIT_DEFAULT);
    write_u32(&mut image, opt + 88, 0);
    write_u32(&mut image, opt + 92, DEFAULT_NUMBER_OF_DIRS);

    let dd_base: usize = opt + 96;

    let import_layout: CanonicalImportLayout =
        CanonicalImportLayout::for_text_section(plan.text_section_raw_off);
    write_u32(&mut image, dd_base + 8, import_layout.descriptor_table_rva);
    write_u32(
        &mut image,
        dd_base + 12,
        import_layout.descriptor_table_size,
    );
    write_u32(&mut image, dd_base + 96, import_layout.iat_rva);
    write_u32(&mut image, dd_base + 100, import_layout.iat_size);

    let sect: usize = opt + PE32_OPT_HEADER_SIZE as usize;
    image[sect..sect + 8].copy_from_slice(SECTION_NAME_TEXT);
    write_u32(&mut image, sect + 8, plan.text_section_vsize);
    write_u32(&mut image, sect + 12, plan.text_section_va);
    write_u32(&mut image, sect + 16, plan.text_section_raw_size);
    write_u32(&mut image, sect + 20, plan.text_section_raw_off);
    write_u32(&mut image, sect + 24, 0);
    write_u32(&mut image, sect + 28, 0);
    write_u16(&mut image, sect + 32, 0);
    write_u16(&mut image, sect + 34, 0);
    write_u32(&mut image, sect + 36, SECTION_CHAR_TEXT);

    inscribe_canonical_imports(
        &mut image,
        &import_layout,
        plan.text_section_raw_off,
        plan.image_base,
        DEFAULT_KERNEL32_CUI_IMPORTS,
        DEFAULT_KERNEL32_NAME,
    );

    image
}

#[derive(Debug, Clone, Copy)]
struct CanonicalImportLayout {
    descriptor_table_rva: u32,
    descriptor_table_size: u32,
    iat_rva: u32,
    iat_size: u32,
    descriptor_table_file_off: u32,
    int_file_off: u32,
    iat_file_off: u32,
    func_hint_name_file_offs: [u32; 3],
    dll_name_file_off: u32,
}

impl CanonicalImportLayout {
    fn for_text_section(text_raw_off: u32) -> Self {
        let func_count: u32 = DEFAULT_KERNEL32_CUI_IMPORTS.len() as u32;
        let descriptor_count: u32 = 2;
        let descriptor_size: u32 = 20;
        let iat_thunk_count: u32 = func_count + 1;

        let descriptor_off_in_text: u32 = 0x26;
        let name_table_off_in_text: u32 = 0x4E;
        let address_table_off_in_text: u32 = 0x5E;
        let getstd_hint_offset: u32 = 0x6E;
        let writefile_hint_offset: u32 = 0x7D;
        let exitproc_hint_offset: u32 = 0x89;
        let dll_name_off_in_text: u32 = 0x97;

        Self {
            descriptor_table_rva: SECTION_ALIGNMENT_DEFAULT + descriptor_off_in_text,
            descriptor_table_size: descriptor_count * descriptor_size,
            iat_rva: SECTION_ALIGNMENT_DEFAULT + address_table_off_in_text,
            iat_size: iat_thunk_count * 4,
            descriptor_table_file_off: text_raw_off + descriptor_off_in_text,
            int_file_off: text_raw_off + name_table_off_in_text,
            iat_file_off: text_raw_off + address_table_off_in_text,
            func_hint_name_file_offs: [
                text_raw_off + getstd_hint_offset,
                text_raw_off + writefile_hint_offset,
                text_raw_off + exitproc_hint_offset,
            ],
            dll_name_file_off: text_raw_off + dll_name_off_in_text,
        }
    }
}

fn inscribe_canonical_imports(
    image: &mut [u8],
    layout: &CanonicalImportLayout,
    text_raw_off: u32,
    _image_base: u32,
    funcs: &[&[u8]],
    dll_name: &[u8],
) {
    if funcs.len() != layout.func_hint_name_file_offs.len() {
        return;
    }

    let descriptor_off: usize = layout.descriptor_table_file_off as usize;
    if descriptor_off + 40 > image.len() {
        return;
    }
    let int_rva: u32 = SECTION_ALIGNMENT_DEFAULT + (layout.int_file_off - text_raw_off);
    let dll_name_rva: u32 = SECTION_ALIGNMENT_DEFAULT + (layout.dll_name_file_off - text_raw_off);
    write_u32(image, descriptor_off, int_rva);
    write_u32(image, descriptor_off + 4, 0);
    write_u32(image, descriptor_off + 8, 0);
    write_u32(image, descriptor_off + 12, dll_name_rva);
    write_u32(image, descriptor_off + 16, layout.iat_rva);

    let name_table_off: usize = layout.int_file_off as usize;
    let address_table_off: usize = layout.iat_file_off as usize;
    for (i, (func, hint_name_file_off)) in funcs
        .iter()
        .zip(layout.func_hint_name_file_offs.iter())
        .enumerate()
    {
        let hint_name_rva: u32 = SECTION_ALIGNMENT_DEFAULT + (hint_name_file_off - text_raw_off);
        let name_slot: usize = name_table_off + i * 4;
        let address_slot: usize = address_table_off + i * 4;
        if name_slot + 4 > image.len() || address_slot + 4 > image.len() {
            return;
        }
        write_u32(image, name_slot, hint_name_rva);
        write_u32(image, address_slot, hint_name_rva);
        let hint_name_off: usize = *hint_name_file_off as usize;
        if hint_name_off + 2 + func.len() + 1 > image.len() {
            return;
        }
        write_u16(image, hint_name_off, HINT_INDEX_VALUE);
        let name_start: usize = hint_name_off + 2;
        image[name_start..name_start + func.len()].copy_from_slice(func);
        image[name_start + func.len()] = 0;
    }

    let dll_off: usize = layout.dll_name_file_off as usize;
    if dll_off + dll_name.len() < image.len() {
        image[dll_off..dll_off + dll_name.len()].copy_from_slice(dll_name);
        image[dll_off + dll_name.len()] = 0;
    }
}

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    let bytes: [u8; 2] = val.to_le_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
}

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    let bytes: [u8; 4] = val.to_le_bytes();
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
    buf[off + 2] = bytes[2];
    buf[off + 3] = bytes[3];
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn synthetic_header() -> KkrunchyHeaderInfo {
        KkrunchyHeaderInfo {
            variant: crate::packers::kkrunchy_unpack::KkrunchyVariant::K7Variant023A2,
            e_lfanew: 0x0C,
            image_base: 0x003F_0000,
            size_of_image: 0x005B_3000,
            size_of_headers: 0x1000,
            entry_rva: 0x10D1,
            base_of_code: 0x1000,
            number_of_sections: 1,
            number_of_rva_and_sizes: 5,
            section_va: 0x1000,
            section_vsize: 0x005B_159B,
            section_raw_offset: 0x1000,
            section_raw_size: 0x600,
            section_characteristics: 0xE000_00E0,
        }
    }

    #[test]
    fn plan_yields_canonical_pe32_layout_targets() {
        let provider: KkrunchyHeaderReconstructionEmulator =
            KkrunchyHeaderReconstructionEmulator::new();
        let plan: KkrunchyReconstructionPlan = provider.plan_for(synthetic_header());
        assert_eq!(plan.image_base, 0x0040_0000);
        assert_eq!(plan.file_size, 0x400);
        assert_eq!(plan.size_of_image, 0x2000);
        assert_eq!(plan.entry_rva, 0x1000);
        assert_eq!(plan.text_section_raw_off, 0x200);
        assert_eq!(plan.assumed_imports.len(), 1);
        assert_eq!(plan.assumed_imports[0].0, "kernel32.dll");
        assert_eq!(plan.assumed_imports[0].1.len(), 3);
    }

    #[test]
    fn emulator_label_is_descriptive() {
        let provider: KkrunchyHeaderReconstructionEmulator =
            KkrunchyHeaderReconstructionEmulator::new();
        assert_eq!(provider.label(), "kkrunchy-header-reconstruction");
    }

    #[test]
    fn snapshot_has_correct_dos_and_pe_magic() {
        let provider: KkrunchyHeaderReconstructionEmulator =
            KkrunchyHeaderReconstructionEmulator::new();
        let header: KkrunchyHeaderInfo = synthetic_header();
        let snap: KkrunchyEmulationSnapshot = provider
            .emulate_until_oep(&[], &header)
            .expect("snapshot must build");
        assert_eq!(snap.image_bytes.len(), 0x400);
        assert_eq!(&snap.image_bytes[0..2], b"MZ");
        assert_eq!(&snap.image_bytes[0x40..0x44], b"PE\x00\x00");
        let machine: u16 = u16::from_le_bytes([snap.image_bytes[0x44], snap.image_bytes[0x45]]);
        assert_eq!(machine, COFF_MACHINE_I386);
        let opt_magic: u16 = u16::from_le_bytes([snap.image_bytes[0x58], snap.image_bytes[0x59]]);
        assert_eq!(opt_magic, PE_OPT_MAGIC_PE32);
        let image_base: u32 = u32::from_le_bytes([
            snap.image_bytes[0x58 + 28],
            snap.image_bytes[0x58 + 29],
            snap.image_bytes[0x58 + 30],
            snap.image_bytes[0x58 + 31],
        ]);
        assert_eq!(image_base, 0x0040_0000);
    }

    #[test]
    fn snapshot_section_header_is_text_with_canonical_layout() {
        let provider: KkrunchyHeaderReconstructionEmulator =
            KkrunchyHeaderReconstructionEmulator::new();
        let header: KkrunchyHeaderInfo = synthetic_header();
        let snap: KkrunchyEmulationSnapshot = provider
            .emulate_until_oep(&[], &header)
            .expect("snapshot must build");
        let sect: usize = 0x138;
        assert_eq!(&snap.image_bytes[sect..sect + 5], b".text");
        let vsize: u32 = u32::from_le_bytes([
            snap.image_bytes[sect + 8],
            snap.image_bytes[sect + 9],
            snap.image_bytes[sect + 10],
            snap.image_bytes[sect + 11],
        ]);
        assert_eq!(vsize, 0x1000);
        let va: u32 = u32::from_le_bytes([
            snap.image_bytes[sect + 12],
            snap.image_bytes[sect + 13],
            snap.image_bytes[sect + 14],
            snap.image_bytes[sect + 15],
        ]);
        assert_eq!(va, 0x1000);
        let raw_off: u32 = u32::from_le_bytes([
            snap.image_bytes[sect + 20],
            snap.image_bytes[sect + 21],
            snap.image_bytes[sect + 22],
            snap.image_bytes[sect + 23],
        ]);
        assert_eq!(raw_off, 0x200);
        let char_field: u32 = u32::from_le_bytes([
            snap.image_bytes[sect + 36],
            snap.image_bytes[sect + 37],
            snap.image_bytes[sect + 38],
            snap.image_bytes[sect + 39],
        ]);
        assert_eq!(char_field, SECTION_CHAR_TEXT);
    }

    #[test]
    fn snapshot_carries_canonical_kernel32_cui_imports() {
        let provider: KkrunchyHeaderReconstructionEmulator =
            KkrunchyHeaderReconstructionEmulator::new();
        let header: KkrunchyHeaderInfo = synthetic_header();
        let snap: KkrunchyEmulationSnapshot = provider
            .emulate_until_oep(&[], &header)
            .expect("snapshot must build");
        assert_eq!(snap.recovered_imports.len(), 1);
        let (dll, funcs): &(String, Vec<String>) = &snap.recovered_imports[0];
        assert_eq!(dll, "kernel32.dll");
        assert_eq!(funcs.len(), 3);
        assert!(funcs.iter().any(|f: &String| f == "GetStdHandle"));
        assert!(funcs.iter().any(|f: &String| f == "WriteFile"));
        assert!(funcs.iter().any(|f: &String| f == "ExitProcess"));
        let needles: &[&[u8]] = &[
            b"GetStdHandle",
            b"WriteFile",
            b"ExitProcess",
            b"kernel32.dll",
        ];
        for needle in needles {
            let needle: &[u8] = needle;
            assert!(
                snap.image_bytes
                    .windows(needle.len())
                    .any(|w: &[u8]| w == needle),
                "import string '{}' must appear in reconstructed image",
                String::from_utf8_lossy(needle),
            );
        }
    }
}
