#![allow(clippy::expect_used)]
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_binfmt::containers::{
    ApfsContainer, AppImageLayout, ArArchive, BlazorBoot, BtrfsSendHeader, BtrfsSendReplay,
    BunOffsets, BunStandalone, CramfsWalk, CythonIdentity, CythonModule, DmgSummary, DotnetBundle,
    ElfOverlay, ElfOverlayCarve, ErofsSuperblock, EszipArchive, Ext4Walk, FatBpb, FatVolume,
    FirmwareKind, FlatpakExtraction, FvExtraction, FvHeader, GptTable, HfsVolume, InnoSetupInfo,
    InstallShieldHeader, Jffs2Endian, Jffs2Walk, KolyTrailer, MbrTable, MinidumpFile,
    MinixSuperblock, MinixWalk, MsiExtractable, MsiSummary, MsixManifest, NsisHeader, NtfsVolume,
    NtfsWalk, OciManifest, PartcloneImage, QnxKind, QnxStartup, RomfsHeader, RomfsWalk,
    SparseHeader, SquashfsSuperblock, SquashfsWalk, SquirrelLayout, StuffItKind, UbifsWalk,
    VhdFooter, VhdImage, VhdxImage, WebcilHeader, WimArchive, XarArchive, Yaffs2Endian, Yaffs2Walk,
    cab_uses_lzms, carve_elf_overlay, carve_wim_resources, detect_apfs, detect_ar,
    detect_blazor_boot, detect_btrfs_send, detect_bun, detect_cramfs, detect_cython, detect_dmg,
    detect_dotnet_bundle, detect_elf_overlay, detect_erofs, detect_eszip, detect_ext4, detect_fat,
    detect_firmware, detect_flatpak_bundle, detect_gzip, detect_hfsplus, detect_innosetup,
    detect_installshield, detect_iso, detect_jffs2, detect_minidump, detect_minixfs, detect_nsis,
    detect_ntfs, detect_par2, detect_partclone, detect_qnx, detect_romfs, detect_snap,
    detect_sparse, detect_squirrel, detect_stuffit, detect_ubi, detect_ubifs, detect_uefi_fv,
    detect_unityfs, detect_xar, detect_yaffs2, elf_image_end, extract_cab_lzms,
    extract_flatpak_bundle, extract_uefi_fv, locate_embedded_nupkg, locate_hfsplus_volumes,
    minidump_extent, parse_apfs, parse_appimage, parse_appx_manifest, parse_ar, parse_blazor_boot,
    parse_bpb, parse_bun, parse_docker_manifest, parse_dotnet_bundle, parse_eszip, parse_fv_header,
    parse_gpt, parse_hfsplus, parse_koly, parse_lzop, parse_mbr, parse_minidump, parse_msi_minimal,
    parse_oci_index, parse_oci_manifest, parse_reshdr_at, parse_squashfs_superblock, parse_vhd,
    parse_vhd_footer, parse_vhdx, parse_webcil_header, parse_wim, parse_xar, qnx_parse_startup,
    read_msi_extractable, reconstruct_image, reconstruct_partclone, recover_cython,
    replay_btrfs_send, unsparse, unwrap_webcil, vhd_materialize_logical_disk,
    vhdx_materialize_logical_disk, walk_cramfs, walk_ext4, walk_fat, walk_installshield,
    walk_jffs2, walk_minixfs, walk_ntfs, walk_romfs, walk_squashfs, walk_ubifs, walk_yaffs2,
};
use disrobe_binfmt::coverage::{ByteCoverage, file_byte_coverage};
use disrobe_binfmt::error::Result;
use disrobe_binfmt::structural::{
    locate_zip_central_directory, validate_dex, validate_elf, validate_java_class, validate_macho,
    validate_macho_fat, validate_pe, validate_wasm, validate_zip,
};
use disrobe_binfmt::{
    CarveConfig, CarveReport, ContainerKind, ElfDynamic, ExtractionQuota, ExtractionResult,
    InputClassification, NativeFile, StructuralFormat, asar, carve_recursive, classify_input,
    detect_and_extract_with_hint, detect_container, detect_container_with_hint,
    extract_to_with_quota, identify_by_structure, import_graph_dot, is_skip_magic,
    locate_pe_header, native_lang_fingerprint, parse_elf_dynamic, parse_native,
    sanitize_entry_path, skip_magic_label,
};
use disrobe_testkit::{BATCH_ENV, CorpusEntry, StressCase, StressConfig, XorShift64};

const CASES_PER_INPUT: usize = 224;
const BATCH_SIZE: usize = 448;
const CASE_BUDGET: Duration = Duration::from_millis(250);
const SUITE_BUDGET: Duration = Duration::from_mins(4);

const CORPUS_ENTRIES: usize = 30;
const MIN_TOTAL_CASES: usize = 5_000;
const MIN_ENTRY_POINTS_PER_CASE: u32 = 100;

const SATURATION_DOMAIN: u64 = 0x4249_4E46_0001_0002;
const PATH_DOMAIN: u64 = 0x4249_4E46_0001_0003;
const ENTROPY_SPAN_SEED: u64 = 0x4249_4E46_0001_0004;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 48;

const RANDOM_SPAN_BYTES: usize = 4096;
const WALK_CAP: u64 = 1024 * 1024;
const CARVE_DEPTH: u32 = 2;

const PATH_ALPHABET: &[u8] = b"abcXYZ019._-/\\:%$ \t\r\n\0..~*?\"<>|";
const MAX_PATH_BYTES: usize = 96;
const PATH_ALPHABET_SPARSITY: u32 = 1;
const PATH_EXTENSIONS: [&str; 8] = [
    ".zip", ".tar.gz", ".exe", ".so", ".apk", ".asar", ".unknown", "",
];

const SCRATCH_DIRECTORY: &str = "binfmt-extraction-entrypoints";
const WORKER_SCRATCH_TAG: &str = "worker";
const UNMUTATED_SCRATCH_TAG: &str = "unmutated-seeds";
const FINISHES_SCRATCH_TAG: &str = "unmutated-finishes";
const QUOTA_SCRATCH_TAG: &str = "hostile-partition-quota";
const SUMMARY_ENTRIES: usize = 1;
const SCRATCH_OUT: &str = "out";
const TRUNCATION_SWEEP_BYTES: usize = 640;
const MIN_TRUNCATION_PREFIXES: usize = 8_000;
const DEFAULT_SAFE_TOTAL: u64 = 4 * 1024 * 1024 * 1024;
const SHAPELESS_SEEDS: [&str; 3] = ["empty", "entropy-span", "zero-span"];

#[derive(Debug)]
struct Scratch {
    directory: PathBuf,
    out: PathBuf,
}

impl Scratch {
    fn create(base: &Path, tag: &str) -> Self {
        let directory: PathBuf =
            base.join(format!("{SCRATCH_DIRECTORY}-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&directory)
            .expect("the stress worker can create its scratch directory");
        Self {
            out: directory.join(SCRATCH_OUT),
            directory,
        }
    }

    fn fresh_out_dir(&self) -> &Path {
        if self.out.exists() {
            std::fs::remove_dir_all(&self.out)
                .expect("the stress worker can clear its scratch output directory");
        }
        std::fs::create_dir_all(&self.out)
            .expect("the stress worker can create its scratch output directory");
        &self.out
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.directory);
    }
}

fn batch_workspace() -> PathBuf {
    std::env::var_os(BATCH_ENV)
        .map(PathBuf::from)
        .as_deref()
        .and_then(Path::parent)
        .map_or_else(std::env::temp_dir, Path::to_path_buf)
}

fn worker_scratch() -> &'static Scratch {
    static SCRATCH: OnceLock<Scratch> = OnceLock::new();
    SCRATCH.get_or_init(|| Scratch::create(&batch_workspace(), WORKER_SCRATCH_TAG))
}

const fn test_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_entries: 24,
        max_total_uncompressed: 128 * 1024,
        max_per_entry_uncompressed: 32 * 1024,
        max_per_entry_ratio: 24,
        max_aggregate_ratio: 12,
    }
}

fn entropy_span(len: usize) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(ENTROPY_SPAN_SEED);
    let mut out: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_byte());
    }
    out
}

fn pe64_seed() -> Vec<u8> {
    const PE_OFFSET: usize = 0x40;
    const OPTIONAL_HEADER_SIZE: u16 = 240;
    let mut bytes: Vec<u8> = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"MZ");
    bytes.resize(0x3C, 0);
    bytes.extend_from_slice(&(PE_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(b"PE\0\0");
    bytes.extend_from_slice(&0x8664u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0x6000_0000u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&OPTIONAL_HEADER_SIZE.to_le_bytes());
    bytes.extend_from_slice(&0x0022u16.to_le_bytes());
    bytes.extend_from_slice(&0x020Bu16.to_le_bytes());
    bytes.extend_from_slice(&[14, 0]);
    bytes.extend_from_slice(&0x200u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x1000u32.to_le_bytes());
    bytes.extend_from_slice(&0x1000u32.to_le_bytes());
    bytes.extend_from_slice(&0x0001_4000_0000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u32.to_le_bytes());
    bytes.extend_from_slice(&0x200u32.to_le_bytes());
    bytes.extend_from_slice(&6u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&6u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x2000u32.to_le_bytes());
    bytes.extend_from_slice(&0x200u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&3u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for _ in 0..4 {
        bytes.extend_from_slice(&0x0010_0000u64.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    for _ in 0..16 {
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }
    bytes.extend_from_slice(b".text\0\0\0");
    bytes.extend_from_slice(&0x100u32.to_le_bytes());
    bytes.extend_from_slice(&0x1000u32.to_le_bytes());
    bytes.extend_from_slice(&0x200u32.to_le_bytes());
    bytes.extend_from_slice(&0x200u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    bytes.resize(0x200, 0);
    bytes.resize(0x400, 0x90);
    bytes
}

fn elf64_dynamic_seed() -> Vec<u8> {
    const PROGRAM_HEADER_OFFSET: u64 = 64;
    const DYNAMIC_OFFSET: u64 = 176;
    const DYNAMIC_SIZE: u64 = 80;
    const STRTAB_OFFSET: u64 = 256;
    const TOTAL: usize = 512;
    const STRTAB: &[u8] = b"\0libc.so.6\0libsample.so.1\0";

    let mut bytes: Vec<u8> = Vec::with_capacity(TOTAL);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
    bytes.resize(16, 0);
    bytes.extend_from_slice(&3u16.to_le_bytes());
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&PROGRAM_HEADER_OFFSET.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());

    push_program_header(&mut bytes, 1, 5, 0, TOTAL as u64, 0x1000);
    push_program_header(&mut bytes, 2, 6, DYNAMIC_OFFSET, DYNAMIC_SIZE, 8);

    push_dynamic_entry(&mut bytes, 1, 1);
    push_dynamic_entry(&mut bytes, 14, 11);
    push_dynamic_entry(&mut bytes, 5, STRTAB_OFFSET);
    push_dynamic_entry(&mut bytes, 10, STRTAB.len() as u64);
    push_dynamic_entry(&mut bytes, 0, 0);

    bytes.resize(STRTAB_OFFSET as usize, 0);
    bytes.extend_from_slice(STRTAB);
    bytes.resize(TOTAL, 0);
    bytes
}

fn push_program_header(
    bytes: &mut Vec<u8>,
    kind: u32,
    flags: u32,
    offset: u64,
    size: u64,
    align: u64,
) {
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&align.to_le_bytes());
}

fn push_dynamic_entry(bytes: &mut Vec<u8>, tag: u64, value: u64) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn macho64_seed() -> Vec<u8> {
    const SEGMENT_COMMAND_SIZE: u32 = 72;
    let mut bytes: Vec<u8> = Vec::with_capacity(256);
    bytes.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_0007u32.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&SEGMENT_COMMAND_SIZE.to_le_bytes());
    bytes.extend_from_slice(&0x0020_0085u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes.extend_from_slice(&SEGMENT_COMMAND_SIZE.to_le_bytes());
    bytes.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    bytes.extend_from_slice(&0x0001_0000_0000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&104u64.to_le_bytes());
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn macho_fat_seed() -> Vec<u8> {
    const HEADER: usize = 28;
    let inner: Vec<u8> = macho64_seed();
    let mut bytes: Vec<u8> = Vec::with_capacity(HEADER + inner.len());
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0x0100_0007u32.to_be_bytes());
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(&(HEADER as u32).to_be_bytes());
    bytes.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&12u32.to_be_bytes());
    bytes.resize(HEADER, 0);
    bytes.extend_from_slice(&inner);
    bytes
}

fn wasm_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    bytes.extend_from_slice(b"\0asm");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    bytes.extend_from_slice(&[0x07, 0x08, 0x01, 0x04, b'm', b'a', b'i', b'n', 0x00, 0x00]);
    bytes.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);
    bytes
}

fn dex_seed() -> Vec<u8> {
    const TOTAL: usize = 256;
    const HEADER_SIZE: u32 = 0x70;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(0..8, b"dex\n035\0".iter().copied());
    write_u32_le(&mut bytes, 32, TOTAL as u32);
    write_u32_le(&mut bytes, 36, HEADER_SIZE);
    write_u32_le(&mut bytes, 40, 0x1234_5678);
    write_u32_le(&mut bytes, 56, 1);
    write_u32_le(&mut bytes, 60, HEADER_SIZE);
    write_u32_le(&mut bytes, 64, 1);
    write_u32_le(&mut bytes, 68, HEADER_SIZE + 4);
    bytes
}

fn java_class_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&52u16.to_be_bytes());
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(b"main");
    bytes.resize(64, 0);
    bytes
}

fn zip_seed() -> Vec<u8> {
    const NAME: &[u8] = b"a.txt";
    const DATA: &[u8] = b"hello";
    const CRC32_OF_HELLO: u32 = 0x3610_A686;
    let mut bytes: Vec<u8> = Vec::with_capacity(128);
    bytes.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0x21u16.to_le_bytes());
    bytes.extend_from_slice(&CRC32_OF_HELLO.to_le_bytes());
    bytes.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(NAME.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(NAME);
    bytes.extend_from_slice(DATA);

    let central_offset: u32 = bytes.len() as u32;
    bytes.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0x21u16.to_le_bytes());
    bytes.extend_from_slice(&CRC32_OF_HELLO.to_le_bytes());
    bytes.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(NAME.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(NAME);

    let central_size: u32 = bytes.len() as u32 - central_offset;
    bytes.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&central_size.to_le_bytes());
    bytes.extend_from_slice(&central_offset.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn tar_seed() -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut header: Vec<u8> = vec![0u8; BLOCK];
    header.splice(0..7, b"a.txt\0\0".iter().copied());
    header.splice(100..108, b"0000644\0".iter().copied());
    header.splice(108..116, b"0000000\0".iter().copied());
    header.splice(116..124, b"0000000\0".iter().copied());
    header.splice(124..136, b"00000000005\0".iter().copied());
    header.splice(136..148, b"00000000000\0".iter().copied());
    header.splice(148..156, [b' '; 8].iter().copied());
    header[156] = b'0';
    header.splice(257..265, b"ustar\x0000".iter().copied());
    let checksum: u32 = header.iter().map(|byte: &u8| u32::from(*byte)).sum();
    let rendered: String = format!("{checksum:06o}\0 ");
    header.splice(148..156, rendered.bytes());

    let mut bytes: Vec<u8> = header;
    let mut payload: Vec<u8> = vec![0u8; BLOCK];
    payload.splice(0..5, b"hello".iter().copied());
    bytes.extend_from_slice(&payload);
    bytes.resize(BLOCK * 5, 0);
    bytes
}

fn gzip_seed() -> Vec<u8> {
    const DATA: &[u8] = b"hello";
    const CRC32_OF_HELLO: u32 = 0x3610_A686;
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    bytes.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0x00, 0xFF]);
    bytes.push(0x01);
    bytes.extend_from_slice(&(DATA.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(!(DATA.len() as u16)).to_le_bytes());
    bytes.extend_from_slice(DATA);
    bytes.extend_from_slice(&CRC32_OF_HELLO.to_le_bytes());
    bytes.extend_from_slice(&(DATA.len() as u32).to_le_bytes());
    bytes
}

fn ar_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(128);
    bytes.extend_from_slice(b"!<arch>\n");
    bytes.extend_from_slice(b"a.txt/          ");
    bytes.extend_from_slice(b"0           ");
    bytes.extend_from_slice(b"0     ");
    bytes.extend_from_slice(b"0     ");
    bytes.extend_from_slice(b"100644  ");
    bytes.extend_from_slice(b"5         ");
    bytes.extend_from_slice(b"`\n");
    bytes.extend_from_slice(b"hello\n");
    bytes
}

fn cpio_newc_seed() -> Vec<u8> {
    fn push_entry(bytes: &mut Vec<u8>, name: &str, payload: &[u8]) {
        let name_size: usize = name.len().saturating_add(1);
        bytes.extend_from_slice(b"070701");
        for field in [
            1u32,
            0o100_644,
            0,
            0,
            1,
            0,
            payload.len() as u32,
            0,
            0,
            0,
            0,
            name_size as u32,
            0,
        ] {
            bytes.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes.extend_from_slice(payload);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(512);
    push_entry(&mut bytes, "a.txt", b"hello");
    push_entry(&mut bytes, "TRAILER!!!", b"");
    bytes
}

fn iso9660_seed() -> Vec<u8> {
    const SYSTEM_AREA: usize = 32 * 1024;
    const SECTOR: usize = 2048;
    let mut bytes: Vec<u8> = vec![0u8; SYSTEM_AREA + SECTOR * 2];
    bytes[SYSTEM_AREA] = 1;
    bytes.splice(SYSTEM_AREA + 1..SYSTEM_AREA + 6, b"CD001".iter().copied());
    bytes[SYSTEM_AREA + 6] = 1;
    write_u32_le(&mut bytes, SYSTEM_AREA + 80, 4);
    write_u32_le(&mut bytes, SYSTEM_AREA + 128, 2048);
    bytes[SYSTEM_AREA + SECTOR] = 0xFF;
    bytes.splice(
        SYSTEM_AREA + SECTOR + 1..SYSTEM_AREA + SECTOR + 6,
        b"CD001".iter().copied(),
    );
    bytes
}

fn cfb_seed() -> Vec<u8> {
    const TOTAL: usize = 1024;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(
        0..8,
        [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
            .iter()
            .copied(),
    );
    write_u16_le(&mut bytes, 26, 0x003E);
    write_u16_le(&mut bytes, 28, 0xFFFE);
    write_u16_le(&mut bytes, 30, 9);
    write_u16_le(&mut bytes, 32, 6);
    write_u32_le(&mut bytes, 44, 1);
    write_u32_le(&mut bytes, 48, 1);
    bytes
}

fn squashfs_seed() -> Vec<u8> {
    const TOTAL: usize = 512;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    write_u32_le(&mut bytes, 0, 0x7371_7368);
    write_u32_le(&mut bytes, 4, 2);
    write_u32_le(&mut bytes, 8, 0);
    write_u32_le(&mut bytes, 12, 131_072);
    write_u32_le(&mut bytes, 16, 0);
    write_u16_le(&mut bytes, 20, 1);
    write_u16_le(&mut bytes, 22, 17);
    write_u16_le(&mut bytes, 24, 0);
    write_u16_le(&mut bytes, 26, 1);
    write_u16_le(&mut bytes, 28, 4);
    write_u16_le(&mut bytes, 30, 0);
    write_u64_le(&mut bytes, 40, u64::from(TOTAL as u32));
    bytes
}

fn cab_seed() -> Vec<u8> {
    const TOTAL: usize = 256;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(0..4, b"MSCF".iter().copied());
    write_u32_le(&mut bytes, 8, TOTAL as u32);
    write_u32_le(&mut bytes, 16, 44);
    bytes[24] = 3;
    bytes[25] = 1;
    write_u16_le(&mut bytes, 26, 1);
    write_u16_le(&mut bytes, 28, 1);
    bytes
}

fn minidump_seed() -> Vec<u8> {
    const TOTAL: usize = 128;
    const DIRECTORY_RVA: u32 = 32;
    const MODULE_LIST_RVA: u32 = 44;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(0..4, b"MDMP".iter().copied());
    write_u32_le(&mut bytes, 4, 0x0000_A793);
    write_u32_le(&mut bytes, 8, 1);
    write_u32_le(&mut bytes, 12, DIRECTORY_RVA);
    write_u32_le(&mut bytes, DIRECTORY_RVA as usize, 4);
    write_u32_le(&mut bytes, DIRECTORY_RVA as usize + 4, 4);
    write_u32_le(&mut bytes, DIRECTORY_RVA as usize + 8, MODULE_LIST_RVA);
    write_u32_le(&mut bytes, MODULE_LIST_RVA as usize, 0);
    bytes
}

fn gpt_disk_seed() -> Vec<u8> {
    const SECTOR: usize = 512;
    const TOTAL: usize = SECTOR * 40;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes[446] = 0x00;
    bytes[450] = 0xEE;
    write_u32_le(&mut bytes, 454, 1);
    write_u32_le(&mut bytes, 458, 39);
    write_u16_le(&mut bytes, 510, 0xAA55);
    bytes.splice(SECTOR..SECTOR + 8, b"EFI PART".iter().copied());
    write_u32_le(&mut bytes, SECTOR + 8, 0x0001_0000);
    write_u32_le(&mut bytes, SECTOR + 12, 92);
    write_u64_le(&mut bytes, SECTOR + 72, 2);
    write_u32_le(&mut bytes, SECTOR + 80, 4);
    write_u32_le(&mut bytes, SECTOR + 84, 128);
    bytes
}

fn ext4_seed() -> Vec<u8> {
    const SUPERBLOCK: usize = 1024;
    const TOTAL: usize = SUPERBLOCK * 4;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    write_u32_le(&mut bytes, SUPERBLOCK, 64);
    write_u32_le(&mut bytes, SUPERBLOCK + 4, 64);
    write_u32_le(&mut bytes, SUPERBLOCK + 24, 0);
    write_u32_le(&mut bytes, SUPERBLOCK + 32, 64);
    write_u32_le(&mut bytes, SUPERBLOCK + 40, 64);
    write_u16_le(&mut bytes, SUPERBLOCK + 56, 0xEF53);
    write_u16_le(&mut bytes, SUPERBLOCK + 88, 256);
    bytes
}

const WIM_SEED_XML: &str = "<WIM><TOTALBYTES>4096</TOTALBYTES>\
<IMAGE INDEX=\"1\"><NAME>seed</NAME><DIRCOUNT>3</DIRCOUNT><FILECOUNT>9</FILECOUNT>\
<TOTALBYTES>2048</TOTALBYTES></IMAGE>\
<IMAGE INDEX=\"2\"><NAME>seed alt</NAME><TOTALBYTES>1024</TOTALBYTES></IMAGE></WIM>";

fn wim_seed() -> Vec<u8> {
    const HEADER_LEN: usize = 208;
    let mut xml: Vec<u8> = vec![0xffu8, 0xfeu8];
    for unit in WIM_SEED_XML.encode_utf16() {
        xml.extend_from_slice(&unit.to_le_bytes());
    }
    let mut bytes: Vec<u8> = vec![0u8; HEADER_LEN];
    bytes.splice(0..8, b"MSWIM\0\0\0".iter().copied());
    write_u32_le(&mut bytes, 8, 208);
    write_u32_le(&mut bytes, 12, 0x0001_0D00);
    write_u32_le(&mut bytes, 16, 0x0002_0000);
    write_u32_le(&mut bytes, 20, 32_768);
    write_u16_le(&mut bytes, 40, 1);
    write_u16_le(&mut bytes, 42, 1);
    write_u32_le(&mut bytes, 44, 2);
    let xml_size: u64 = xml.len() as u64;
    write_u64_le(&mut bytes, 72, xml_size);
    write_u64_le(&mut bytes, 80, HEADER_LEN as u64);
    write_u64_le(&mut bytes, 88, xml_size);
    bytes.extend_from_slice(&xml);
    bytes
}

fn uefi_fv_seed() -> Vec<u8> {
    const TOTAL: usize = 1024;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(40..44, b"_FVH".iter().copied());
    write_u64_le(&mut bytes, 32, TOTAL as u64);
    write_u16_le(&mut bytes, 48, 0x48);
    write_u16_le(&mut bytes, 54, 2);
    bytes
}

fn xar_seed() -> Vec<u8> {
    const TOTAL: usize = 256;
    let mut bytes: Vec<u8> = vec![0u8; TOTAL];
    bytes.splice(0..4, b"xar!".iter().copied());
    write_u16_be(&mut bytes, 4, 28);
    write_u16_be(&mut bytes, 6, 1);
    write_u64_be(&mut bytes, 8, 64);
    write_u64_be(&mut bytes, 16, 128);
    write_u32_be(&mut bytes, 24, 1);
    bytes
}

fn asar_seed() -> Vec<u8> {
    const PAYLOAD: &[u8] = b"hello";
    let header: String =
        r#"{"files":{"a.txt":{"offset":"0","size":5},"nested":{"files":{"b.bin":{"offset":"5","size":0}}}}}"#
            .to_owned();
    let json_len: usize = header.len();
    let string_pickle_size: usize = json_len.saturating_add(4);
    let header_pickle_size: usize = string_pickle_size.saturating_add(4);
    let mut bytes: Vec<u8> = Vec::with_capacity(16 + json_len + PAYLOAD.len());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&(header_pickle_size as u32).to_le_bytes());
    bytes.extend_from_slice(&(string_pickle_size as u32).to_le_bytes());
    bytes.extend_from_slice(&(json_len as u32).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(PAYLOAD);
    bytes
}

fn oci_index_seed() -> Vec<u8> {
    br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":424,"platform":{"architecture":"amd64","os":"linux"}}]}"#
        .to_vec()
}

fn docker_manifest_seed() -> Vec<u8> {
    br#"[{"Config":"config.json","RepoTags":["sample:latest"],"Layers":["layer0/layer.tar","layer1/layer.tar"]}]"#
        .to_vec()
}

fn write_u16_le(bytes: &mut [u8], offset: usize, value: u16) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(2)) {
        window.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(4)) {
        window.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64_le(bytes: &mut [u8], offset: usize, value: u64) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(8)) {
        window.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u16_be(bytes: &mut [u8], offset: usize, value: u16) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(2)) {
        window.copy_from_slice(&value.to_be_bytes());
    }
}

fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(4)) {
        window.copy_from_slice(&value.to_be_bytes());
    }
}

fn write_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
    if let Some(window) = bytes.get_mut(offset..offset.saturating_add(8)) {
        window.copy_from_slice(&value.to_be_bytes());
    }
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("ar-archive", ar_seed()),
        CorpusEntry::new("asar-package", asar_seed()),
        CorpusEntry::new("cfb-compound-file", cfb_seed()),
        CorpusEntry::new("cpio-newc", cpio_newc_seed()),
        CorpusEntry::new("docker-manifest-json", docker_manifest_seed()),
        CorpusEntry::new("elf64-dynamic", elf64_dynamic_seed()),
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("entropy-span", entropy_span(RANDOM_SPAN_BYTES)),
        CorpusEntry::new("ext4-superblock", ext4_seed()),
        CorpusEntry::new("gpt-disk", gpt_disk_seed()),
        CorpusEntry::new("gzip-stored", gzip_seed()),
        CorpusEntry::new("iso9660-volume", iso9660_seed()),
        CorpusEntry::new("java-class", java_class_seed()),
        CorpusEntry::new("macho-fat", macho_fat_seed()),
        CorpusEntry::new("macho64", macho64_seed()),
        CorpusEntry::new("minidump", minidump_seed()),
        CorpusEntry::new("ms-cabinet", cab_seed()),
        CorpusEntry::new(
            "new-executable",
            include_bytes!("../../../corpus/native/formats/hello_ne.exe").to_vec(),
        ),
        CorpusEntry::new(
            "os2-new-executable",
            include_bytes!("../../../corpus/native/formats/hello_os2_ne.exe").to_vec(),
        ),
        CorpusEntry::new("oci-index-json", oci_index_seed()),
        CorpusEntry::new("pe64", pe64_seed()),
        CorpusEntry::new("squashfs-superblock", squashfs_seed()),
        CorpusEntry::new("tar-ustar", tar_seed()),
        CorpusEntry::new("uefi-firmware-volume", uefi_fv_seed()),
        CorpusEntry::new("wasm-module", wasm_seed()),
        CorpusEntry::new("wim-archive", wim_seed()),
        CorpusEntry::new("xar-archive", xar_seed()),
        CorpusEntry::new("zero-span", vec![0u8; RANDOM_SPAN_BYTES]),
        CorpusEntry::new("zip-stored", zip_seed()),
        CorpusEntry::new("dex-classes", dex_seed()),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let pick: usize = rng.below_usize(SATURATION_PATTERNS.len().saturating_add(1));
    let Some(&(value, sparsity)): Option<&(u8, u32)> = SATURATION_PATTERNS.get(pick) else {
        let changes: usize = rng.below_usize(MAX_SCATTERED_OVERWRITES);
        for _ in 0..changes {
            let index: usize = rng.below_usize(out.len());
            if let Some(byte) = out.get_mut(index) {
                *byte = rng.next_byte();
            }
        }
        return out;
    };
    for byte in &mut out {
        if rng.next_u64().trailing_zeros() >= sparsity {
            *byte = value;
        }
    }
    out
}

fn path_from_seed(case_seed: u64) -> PathBuf {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ PATH_DOMAIN);
    let len: usize = rng.below_usize(MAX_PATH_BYTES);
    let mut raw: Vec<u8> = Vec::with_capacity(len);
    for _ in 0..len {
        if rng.next_u64().trailing_zeros() >= PATH_ALPHABET_SPARSITY {
            raw.push(rng.next_byte());
        } else {
            let pick: usize = rng.below_usize(PATH_ALPHABET.len());
            raw.push(PATH_ALPHABET.get(pick).copied().unwrap_or(b'_'));
        }
    }
    let mut text: String = String::from_utf8_lossy(&raw).into_owned();
    let extension: usize = rng.below_usize(PATH_EXTENSIONS.len());
    text.push_str(PATH_EXTENSIONS.get(extension).copied().unwrap_or(""));
    PathBuf::from(text)
}

fn consume<T>(_: T) {}

trait Recognized {
    fn recognized(&self) -> bool;
}

impl Recognized for bool {
    fn recognized(&self) -> bool {
        *self
    }
}

impl<T: Recognized> Recognized for Option<T> {
    fn recognized(&self) -> bool {
        self.as_ref().is_some_and(Recognized::recognized)
    }
}

impl<T: Recognized, E> Recognized for std::result::Result<T, E> {
    fn recognized(&self) -> bool {
        self.as_ref().is_ok_and(Recognized::recognized)
    }
}

impl<T> Recognized for Vec<T> {
    fn recognized(&self) -> bool {
        !self.is_empty()
    }
}

impl Recognized for () {
    fn recognized(&self) -> bool {
        false
    }
}

impl Recognized for &[u8] {
    fn recognized(&self) -> bool {
        !self.is_empty()
    }
}

impl<A: Recognized, B> Recognized for (A, B) {
    fn recognized(&self) -> bool {
        self.0.recognized()
    }
}

macro_rules! reached_when_not_empty {
    ($($payload:ty => $collection:ident),+ $(,)?) => {
        $(impl Recognized for $payload {
            fn recognized(&self) -> bool {
                !self.$collection.is_empty()
            }
        })+
    };
}

macro_rules! reached_when_the_header_validates {
    ($($payload:ty),+ $(,)?) => {
        $(impl Recognized for $payload {
            fn recognized(&self) -> bool {
                true
            }
        })+
    };
}

reached_when_not_empty! {
    ApfsContainer => volume_oids,
    ArArchive => members,
    BlazorBoot => assemblies,
    BtrfsSendReplay => files,
    BunStandalone => modules,
    CramfsWalk => files,
    CythonModule => functions,
    DotnetBundle => files,
    ElfDynamic => needed,
    disrobe_binfmt::containers::squirrel::EmbeddedNupkg => nuspec_names,
    EszipArchive => modules,
    Ext4Walk => files,
    disrobe_binfmt::extract::ExtractionResult => entries,
    FatVolume => files,
    FlatpakExtraction => files,
    FvExtraction => files,
    GptTable => partitions,
    HfsVolume => files,
    disrobe_binfmt::containers::InstallShieldArchive => files,
    Jffs2Walk => files,
    MbrTable => partitions,
    MinidumpFile => streams,
    MinixWalk => files,
    MsiExtractable => cabs,
    MsiSummary => tables,
    disrobe_binfmt::native::NativeFile => sections,
    ByteCoverage => regions,
    NtfsWalk => files,
    disrobe_binfmt::containers::oci::OciIndex => manifests,
    OciManifest => layers,
    RomfsWalk => files,
    SquashfsWalk => files,
    SquirrelLayout => nuspec_names,
    UbifsWalk => volumes,
    VhdImage => allocated_block_sectors,
    VhdxImage => regions,
    WebcilHeader => sections,
    WimArchive => images,
    XarArchive => files,
    Yaffs2Walk => files,
}

reached_when_the_header_validates! {
    AppImageLayout,
    BtrfsSendHeader,
    BunOffsets,
    ContainerKind,
    disrobe_binfmt::containers::cramfs::CramfsHeader,
    CythonIdentity,
    ElfOverlay,
    ElfOverlayCarve,
    ErofsSuperblock,
    disrobe_binfmt::containers::ext4::Ext4SuperblockSummary,
    FatBpb,
    FirmwareKind,
    FvHeader,
    InnoSetupInfo,
    InstallShieldHeader,
    Jffs2Endian,
    KolyTrailer,
    MinixSuperblock,
    MsixManifest,
    disrobe_binfmt::classify::NativeLangHint,
    NsisHeader,
    NtfsVolume,
    PartcloneImage,
    QnxKind,
    QnxStartup,
    RomfsHeader,
    SparseHeader,
    SquashfsSuperblock,
    StructuralFormat,
    StuffItKind,
    VhdFooter,
    Yaffs2Endian,
}

impl Recognized for usize {
    fn recognized(&self) -> bool {
        *self > 0usize
    }
}

impl Recognized for u64 {
    fn recognized(&self) -> bool {
        *self > 0u64
    }
}

impl Recognized for String {
    fn recognized(&self) -> bool {
        !self.is_empty()
    }
}
#[derive(Debug, Default, Clone, Copy)]
struct Hits {
    driven: u32,
    recognized: u32,
}

impl Hits {
    fn record<T: Recognized>(&mut self, outcome: T) {
        self.driven = self.driven.saturating_add(1);
        if outcome.recognized() {
            self.recognized = self.recognized.saturating_add(1);
        }
    }

    const fn merge(self, other: Self) -> Self {
        Self {
            driven: self.driven.saturating_add(other.driven),
            recognized: self.recognized.saturating_add(other.recognized),
        }
    }
}

fn probe_detectors(bytes: &[u8]) -> Hits {
    let mut hits: Hits = Hits::default();
    hits.record(detect_apfs(bytes));
    hits.record(detect_ar(bytes));
    hits.record(detect_blazor_boot(bytes));
    hits.record(detect_btrfs_send(bytes));
    hits.record(detect_bun(bytes));
    hits.record(detect_cramfs(bytes));
    hits.record(detect_cython(bytes));
    hits.record(detect_dmg(bytes));
    hits.record(detect_dotnet_bundle(bytes));
    hits.record(detect_elf_overlay(bytes));
    hits.record(detect_erofs(bytes));
    hits.record(detect_eszip(bytes));
    hits.record(detect_ext4(bytes));
    hits.record(detect_fat(bytes));
    hits.record(detect_firmware(bytes));
    hits.record(detect_flatpak_bundle(bytes));
    hits.record(detect_gzip(bytes));
    hits.record(detect_hfsplus(bytes));
    hits.record(detect_innosetup(bytes));
    hits.record(detect_installshield(bytes));
    hits.record(detect_iso(bytes));
    hits.record(detect_jffs2(bytes));
    hits.record(detect_minidump(bytes));
    hits.record(detect_minixfs(bytes));
    hits.record(detect_nsis(bytes));
    hits.record(detect_ntfs(bytes));
    hits.record(detect_par2(bytes));
    hits.record(detect_partclone(bytes));
    hits.record(detect_qnx(bytes));
    hits.record(detect_romfs(bytes));
    hits.record(detect_snap(bytes));
    hits.record(detect_sparse(bytes));
    hits.record(detect_squirrel(bytes));
    hits.record(detect_stuffit(bytes));
    hits.record(detect_ubi(bytes));
    hits.record(detect_ubifs(bytes));
    hits.record(detect_uefi_fv(bytes));
    hits.record(detect_unityfs(bytes));
    hits.record(detect_xar(bytes));
    hits.record(detect_yaffs2(bytes));
    hits.record(detect_container(bytes));
    hits
}

fn probe_structural(bytes: &[u8]) -> Hits {
    let mut hits: Hits = Hits::default();
    hits.record(validate_pe(bytes));
    hits.record(validate_elf(bytes));
    hits.record(validate_macho(bytes));
    hits.record(validate_macho_fat(bytes));
    hits.record(validate_wasm(bytes));
    hits.record(validate_dex(bytes));
    hits.record(validate_java_class(bytes));
    hits.record(validate_zip(bytes));
    hits.record(locate_pe_header(bytes));
    hits.record(locate_zip_central_directory(bytes));
    hits.record(identify_by_structure(bytes));

    let native: Result<NativeFile> = parse_native(bytes);
    if let Ok(file) = &native {
        consume(import_graph_dot(file));
    }
    hits.record(native);
    hits.record(parse_elf_dynamic(bytes));
    hits.record(native_lang_fingerprint(bytes));
    hits.record(probe_byte_coverage(bytes));
    hits
}

fn probe_byte_coverage(bytes: &[u8]) -> Result<ByteCoverage> {
    let coverage: ByteCoverage = file_byte_coverage(bytes)?;
    let mut cursor: u64 = 0;
    for region in &coverage.regions {
        assert_eq!(
            region.start, cursor,
            "a mutated input must still produce a tiling of the file"
        );
        assert!(
            region.end > region.start,
            "a mutated input must never produce a zero width region"
        );
        cursor = region.end;
    }
    assert_eq!(
        cursor, coverage.file_len,
        "a mutated input must still be accounted for to its last byte"
    );
    assert_eq!(
        coverage.claimed_bytes + coverage.slack_bytes + coverage.unclaimed_bytes,
        coverage.file_len,
        "a mutated input must never inflate or lose its totals"
    );

    Ok(coverage)
}

fn probe_container_parsers(bytes: &[u8]) -> Hits {
    let quota: ExtractionQuota = test_quota();
    let mut hits: Hits = Hits::default();

    hits.record(parse_apfs(bytes));
    hits.record(parse_ar(bytes));
    hits.record(parse_appimage(bytes));
    hits.record(parse_blazor_boot(bytes));
    hits.record(parse_webcil_header(bytes));
    hits.record(unwrap_webcil(bytes));
    hits.record(replay_btrfs_send(bytes, WALK_CAP));
    hits.record(parse_bun(bytes));
    hits.record(cab_uses_lzms(bytes));
    hits.record(extract_cab_lzms(bytes, WALK_CAP));
    hits.record(walk_cramfs(bytes, WALK_CAP));
    hits.record(recover_cython(bytes));
    hits.record(parse_koly(bytes));
    hits.record(reconstruct_image(bytes));
    hits.record(parse_docker_manifest(bytes));
    hits.record(parse_dotnet_bundle(bytes));
    hits.record(carve_elf_overlay(bytes));
    hits.record(elf_image_end(bytes));
    hits.record(parse_eszip(bytes));
    hits.record(walk_ext4(bytes, WALK_CAP));
    hits.record(parse_bpb(bytes));
    hits.record(walk_fat(bytes, WALK_CAP));
    hits.record(extract_flatpak_bundle(bytes));
    hits.record(locate_hfsplus_volumes(bytes));
    hits.record(parse_hfsplus(bytes));
    hits.record(walk_installshield(bytes, quota));
    hits.record(walk_jffs2(bytes, WALK_CAP));
    hits.record(parse_mbr(bytes));
    hits.record(parse_gpt(bytes));
    hits.record(parse_minidump(bytes));
    hits.record(minidump_extent(bytes));
    hits.record(walk_minixfs(bytes, WALK_CAP));
    hits.record(parse_msi_minimal(bytes));
    hits.record(read_msi_extractable(bytes));
    hits.record(parse_appx_manifest(bytes));
    hits.record(walk_ntfs(bytes, WALK_CAP));
    hits.record(parse_oci_manifest(bytes));
    hits.record(parse_oci_index(bytes));
    hits.record(reconstruct_partclone(bytes, WALK_CAP));
    hits.record(qnx_parse_startup(bytes));
    hits.record(walk_romfs(bytes, WALK_CAP));
    hits.record(unsparse(bytes, u64::MAX));
    hits.record(locate_embedded_nupkg(bytes));
    hits.record(parse_squashfs_superblock(bytes, 0));
    hits.record(walk_squashfs(bytes, 0, WALK_CAP));
    hits.record(walk_ubifs(bytes, WALK_CAP));
    hits.record(parse_fv_header(bytes));
    hits.record(extract_uefi_fv(bytes, quota));
    hits.record(parse_xar(bytes));
    hits.record(walk_yaffs2(bytes, WALK_CAP));
    hits.merge(probe_disk_images(bytes))
}

fn probe_disk_images(bytes: &[u8]) -> Hits {
    let mut hits: Hits = Hits::default();

    hits.record(parse_reshdr_at(bytes, 0).size > 0);
    let wim: Result<WimArchive> = parse_wim(bytes);
    if let Ok(archive) = &wim {
        consume(carve_wim_resources(bytes, &archive.header, WALK_CAP));
    }
    hits.record(wim);

    hits.record(parse_vhd_footer(bytes));
    let vhd: Result<VhdImage> = parse_vhd(bytes);
    if let Ok(image) = &vhd {
        consume(vhd_materialize_logical_disk(bytes, image, WALK_CAP));
    }
    hits.record(vhd);

    let vhdx: Result<VhdxImage> = parse_vhdx(bytes);
    if let Ok(image) = &vhdx {
        consume(vhdx_materialize_logical_disk(bytes, image, WALK_CAP));
    }
    hits.record(vhdx);
    hits
}

fn probe_asar(bytes: &[u8]) -> Hits {
    let mut hits: Hits = Hits::default();
    let layout: Result<asar::AsarLayout> = asar::parse(bytes);
    let Ok(layout) = layout else {
        hits.record(false);
        return hits;
    };
    for entry in &layout.entries {
        hits.record(asar::read_entry(bytes, &layout, entry));
        hits.record(sanitize_entry_path(&entry.path));
    }
    hits.record(true);
    hits
}

fn probe_carve(bytes: &[u8], source: &str) -> Hits {
    let config: CarveConfig = CarveConfig {
        max_depth: CARVE_DEPTH,
        quota: test_quota(),
    };
    let mut hits: Hits = Hits::default();
    let report: CarveReport = carve_recursive(bytes, source, config, None);
    hits.record(report.chunks_total > 0);
    hits.record(is_skip_magic(bytes));
    consume(skip_magic_label(bytes));
    hits
}

fn probe_paths(bytes: &[u8], case_seed: u64) -> Hits {
    let mut hits: Hits = Hits::default();
    let path: PathBuf = path_from_seed(case_seed);
    let classification: InputClassification = classify_input(&path, bytes);
    consume(classification.primary_action);
    hits.record(classification.native);
    hits.record(detect_container_with_hint(bytes, Some(&path)));
    hits.record(sanitize_entry_path(&path.to_string_lossy()));
    hits
}

fn probe_extraction(bytes: &[u8], case_seed: u64, scratch: &Scratch) -> Hits {
    let mut hits: Hits = Hits::default();
    let Some(kind): Option<ContainerKind> = detect_container(bytes) else {
        return hits;
    };
    let out_dir: &Path = scratch.fresh_out_dir();
    let extracted: Result<ExtractionResult> =
        extract_to_with_quota(kind, bytes, out_dir, test_quota());
    if let Ok(result) = &extracted {
        for entry in &result.entries {
            consume(sanitize_entry_path(&entry.name));
        }
    }
    hits.record(extracted);
    let hint: PathBuf = path_from_seed(case_seed);
    hits.record(detect_and_extract_with_hint(
        bytes,
        Some(&hint),
        scratch.fresh_out_dir(),
    ));
    hits
}

fn probe(bytes: &[u8], case_seed: u64, source: &str, scratch: &Scratch) -> Hits {
    probe_detectors(bytes)
        .merge(probe_structural(bytes))
        .merge(probe_container_parsers(bytes))
        .merge(probe_asar(bytes))
        .merge(probe_carve(bytes, source))
        .merge(probe_paths(bytes, case_seed))
        .merge(probe_extraction(bytes, case_seed, scratch))
}

fn check(case: &StressCase<'_>) {
    let scratch: &Scratch = worker_scratch();
    consume(probe(case.bytes(), case.case_seed(), case.entry(), scratch));
    let saturated: Vec<u8> = saturate(case.bytes(), case.case_seed());
    consume(probe(&saturated, case.case_seed(), case.entry(), scratch));
}

fn config() -> StressConfig {
    StressConfig {
        cases_per_input: CASES_PER_INPUT,
        batch_size: BATCH_SIZE,
        case_budget: CASE_BUDGET,
        suite_budget: SUITE_BUDGET,
        ..StressConfig::default()
    }
}

mod resilience {
    disrobe_testkit::stress_suite!(
        check: super::check,
        corpus: super::corpus,
        config: super::config
    );
}

#[test]
fn the_configured_run_drives_every_seed_thousands_of_times() {
    let entries: Vec<CorpusEntry> = corpus();
    let config: StressConfig = config();
    assert_eq!(
        entries.len(),
        CORPUS_ENTRIES,
        "the corpus size moved, so the executed case count moved with it"
    );
    let total: usize = config.total_cases(entries.len());
    assert!(
        total >= MIN_TOTAL_CASES,
        "the configured run covers only {total} case(s)"
    );
}

#[test]
fn every_shaped_seed_is_recognized_by_at_least_one_public_entry_point() {
    let guard: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-extraction-entrypoints-unmutated-seeds")
            .expect("create scratch directory");
    let scratch: Scratch = Scratch::create(guard.path(), UNMUTATED_SCRATCH_TAG);
    for entry in corpus() {
        let hits: Hits = probe(entry.bytes(), 0, entry.name(), &scratch);
        assert!(
            hits.driven >= MIN_ENTRY_POINTS_PER_CASE,
            "only {} entry point(s) ran for `{}`",
            hits.driven,
            entry.name()
        );
        if SHAPELESS_SEEDS.contains(&entry.name()) {
            println!(
                "  {:<28} shapeless, {} entry point(s) driven",
                entry.name(),
                hits.driven
            );
            continue;
        }
        println!(
            "  {:<28} {} of {} entry point(s) produced a structure",
            entry.name(),
            hits.recognized,
            hits.driven
        );
        assert!(
            hits.recognized > 0,
            "the `{}` seed is inert: every entry point either refused it or returned a structure \
             carrying nothing",
            entry.name()
        );
    }
}

#[test]
fn the_saturation_probe_rewrites_the_bytes_it_is_handed_and_replays_from_its_seed() {
    const SAMPLE: usize = 512;
    let original: Vec<u8> = vec![0x33u8; SAMPLE];
    let mut untouched: usize = 0;
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    for case_seed in 0..SAMPLE as u64 {
        let probed: Vec<u8> = saturate(&original, case_seed);
        assert_eq!(probed, saturate(&original, case_seed));
        if probed == original {
            untouched = untouched.saturating_add(1);
        }
        if !distinct.contains(&probed) {
            distinct.push(probed);
        }
    }
    assert!(
        untouched < SAMPLE / 16,
        "{untouched} of {SAMPLE} probe outputs came back unchanged"
    );
    assert!(
        distinct.len() > SAMPLE / 2,
        "only {} distinct probe outputs",
        distinct.len()
    );
}

#[test]
fn the_path_probe_replays_from_its_seed_and_does_not_collapse() {
    const SAMPLE: u64 = 512;
    let mut distinct: Vec<PathBuf> = Vec::new();
    for case_seed in 0..SAMPLE {
        let path: PathBuf = path_from_seed(case_seed);
        assert_eq!(path, path_from_seed(case_seed));
        if !distinct.contains(&path) {
            distinct.push(path);
        }
    }
    assert!(
        distinct.len() > usize::try_from(SAMPLE).unwrap_or(usize::MAX) / 2,
        "only {} distinct probe paths",
        distinct.len()
    );
}

#[test]
fn the_seeded_elf_surfaces_the_dynamic_entries_it_encodes() {
    let bytes: Vec<u8> = elf64_dynamic_seed();
    let dynamic: ElfDynamic =
        parse_elf_dynamic(&bytes).expect("the constructed elf must carry a dynamic segment");
    assert_eq!(dynamic.needed, vec!["libc.so.6".to_owned()]);
    assert_eq!(dynamic.soname.as_deref(), Some("libsample.so.1"));
}

#[test]
fn the_seeded_asar_package_reads_back_the_payload_it_encodes() {
    let bytes: Vec<u8> = asar_seed();
    let layout: asar::AsarLayout =
        asar::parse(&bytes).expect("the constructed asar package must parse");
    let entry: &asar::AsarEntry = layout
        .entries
        .iter()
        .find(|entry: &&asar::AsarEntry| entry.path.ends_with("a.txt"))
        .expect("the constructed asar package lists a.txt");
    let payload: &[u8] =
        asar::read_entry(&bytes, &layout, entry).expect("the a.txt entry reads back");
    assert_eq!(payload, b"hello");
}

#[test]
fn the_seeded_wim_carries_an_xml_body_so_mutation_reaches_the_image_walk() {
    let bytes: Vec<u8> = wim_seed();
    let archive: WimArchive = parse_wim(&bytes).expect("the constructed wim must parse");
    assert_eq!(
        archive.images.len(),
        2,
        "a wim seed whose xml the image walk never reads leaves that walk unmutated, which is how \
         an unterminated IMAGE element survived this suite: {:?}",
        archive.images
    );
    assert_eq!(archive.images[0].name.as_deref(), Some("seed"));
    assert_eq!(archive.images[1].index, 2);
}

#[test]
fn the_seeded_archives_are_detected_as_the_containers_they_encode() {
    assert_eq!(detect_container(&zip_seed()), Some(ContainerKind::Zip));
    assert_eq!(detect_container(&tar_seed()), Some(ContainerKind::Tar));
    assert_eq!(detect_container(&gzip_seed()), Some(ContainerKind::Gzip));
}

#[test]
fn the_seeded_native_images_identify_by_structure() {
    assert_eq!(
        identify_by_structure(&pe64_seed()),
        Some(StructuralFormat::Pe)
    );
    assert_eq!(
        identify_by_structure(&elf64_dynamic_seed()),
        Some(StructuralFormat::Elf)
    );
    assert_eq!(
        identify_by_structure(&macho64_seed()),
        Some(StructuralFormat::MachO)
    );
    assert_eq!(
        identify_by_structure(&macho_fat_seed()),
        Some(StructuralFormat::MachOFat)
    );
    assert_eq!(
        identify_by_structure(&wasm_seed()),
        Some(StructuralFormat::Wasm)
    );
    assert_eq!(
        identify_by_structure(&dex_seed()),
        Some(StructuralFormat::Dex)
    );
    assert_eq!(
        identify_by_structure(&java_class_seed()),
        Some(StructuralFormat::JavaClass)
    );
}

#[test]
fn a_hostile_partition_table_honours_the_quota_the_caller_asked_for() {
    const SECTOR: usize = 512;
    const ENTRIES: u32 = 4096;
    let mut bytes: Vec<u8> = vec![0u8; SECTOR * 40];
    bytes[450] = 0xEE;
    write_u16_le(&mut bytes, 510, 0xAA55);
    bytes.splice(SECTOR..SECTOR + 8, b"EFI PART".iter().copied());
    write_u32_le(&mut bytes, SECTOR + 8, 0x0001_0000);
    write_u32_le(&mut bytes, SECTOR + 12, 92);
    write_u64_le(&mut bytes, SECTOR + 72, 2);
    write_u32_le(&mut bytes, SECTOR + 80, ENTRIES);
    write_u32_le(&mut bytes, SECTOR + 84, 128);
    for index in 0..ENTRIES as usize {
        let entry: usize = SECTOR * 2 + index * 128;
        if entry + 128 > bytes.len() {
            break;
        }
        write_u64_le(&mut bytes, entry, 0x0102_0304_0506_0708);
        write_u64_le(&mut bytes, entry + 32, 0);
        write_u64_le(&mut bytes, entry + 40, 1);
    }

    let guard: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        "binfmt-extraction-entrypoints-hostile-partition-quota",
    )
    .expect("create scratch directory");
    let scratch: Scratch = Scratch::create(guard.path(), QUOTA_SCRATCH_TAG);
    let quota: ExtractionQuota = test_quota();
    let result: ExtractionResult =
        extract_to_with_quota(ContainerKind::Gpt, &bytes, scratch.fresh_out_dir(), quota)
            .expect("a gpt table inside the disk view extracts");
    let admitted: usize = result.entries.len().saturating_sub(SUMMARY_ENTRIES);
    assert!(
        admitted <= quota.max_entries,
        "extraction admitted {admitted} partition(s) against a {} entry quota, so the caller's quota was discarded",
        quota.max_entries
    );
    assert!(
        result.quota.entries_accepted <= quota.max_entries,
        "the quota report counts {} accepted entries, past the {} it was given",
        result.quota.entries_accepted,
        quota.max_entries
    );
}

#[test]
fn every_unmutated_seed_finishes() {
    let guard: disrobe_core::scratch::ScratchDir = disrobe_core::scratch::ScratchDir::create(
        "binfmt-extraction-entrypoints-unmutated-finishes",
    )
    .expect("create scratch directory");
    let scratch: Scratch = Scratch::create(guard.path(), FINISHES_SCRATCH_TAG);
    for entry in corpus() {
        consume(probe(entry.bytes(), 1, entry.name(), &scratch));
    }
}

#[test]
fn every_header_prefix_of_every_seed_is_refused_rather_than_panicking() {
    let mut prefixes: usize = 0;
    for entry in corpus() {
        let ceiling: usize = entry.bytes().len().min(TRUNCATION_SWEEP_BYTES);
        for keep in 0..=ceiling {
            let prefix: &[u8] = entry.bytes().get(..keep).unwrap_or_else(|| entry.bytes());
            consume(probe_detectors(prefix));
            consume(probe_structural(prefix));
            consume(probe_container_parsers(prefix));
            prefixes = prefixes.saturating_add(1);
        }
    }
    println!("truncation sweep: {prefixes} header prefix(es) refused");
    assert!(
        prefixes >= MIN_TRUNCATION_PREFIXES,
        "the truncation sweep only drove {prefixes} prefix(es)"
    );
}

#[test]
fn malformed_ne_table_and_resource_mutations_return_typed_errors_without_panicking() {
    const WINDOWS_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
    const OS2_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_os2_ne.exe");
    let mut dos_overlap: Vec<u8> = WINDOWS_NE.to_vec();
    write_u16_le(&mut dos_overlap, 0x08, 9);
    let mut table_inside_header: Vec<u8> = WINDOWS_NE.to_vec();
    write_u16_le(&mut table_inside_header, 0x80 + 0x22, 2);
    let mut os2_count_exceeds_segments: Vec<u8> = OS2_NE.to_vec();
    write_u16_le(&mut os2_count_exceeds_segments, 0x80 + 0x34, 3);
    let mut os2_table_is_truncated: Vec<u8> = OS2_NE.to_vec();
    write_u16_le(&mut os2_table_is_truncated, 0x80 + 0x34, 1);
    for bytes in [
        dos_overlap,
        table_inside_header,
        os2_count_exceeds_segments,
        os2_table_is_truncated,
    ] {
        let outcome: std::thread::Result<Result<NativeFile>> =
            std::panic::catch_unwind(|| parse_native(&bytes));
        assert!(matches!(outcome, Ok(Err(disrobe_binfmt::Error::Ne(_)))));
    }
}

#[test]
fn an_lzop_block_declaring_four_gibibytes_is_refused_by_size_not_by_allocating_it() {
    const DECLARED: u32 = u32::MAX;
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    bytes.extend_from_slice(&[0x89, b'L', b'Z', b'O', 0x00, 0x0D, 0x0A, 0x1A, 0x0A]);
    bytes.extend_from_slice(&0x1030u16.to_be_bytes());
    bytes.extend_from_slice(&0x2050u16.to_be_bytes());
    bytes.extend_from_slice(&0x0940u16.to_be_bytes());
    bytes.push(2);
    bytes.push(1);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&DECLARED.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(0);

    let refusal: disrobe_binfmt::Error = parse_lzop(&bytes, DEFAULT_SAFE_TOTAL)
        .expect_err("a block declaring u32::MAX bytes must be refused, never allocated");
    let rendered: String = refusal.to_string();
    assert!(
        rendered.contains("block limit") || rendered.contains("quota"),
        "the refusal must name the limit it enforced, got: {rendered}"
    );
    assert!(
        bytes.len() < 64,
        "the refusing input is {} bytes, so the refusal cannot be a size artifact",
        bytes.len()
    );
}

fn dmg_declaring_sectors(sector_count: u64) -> Vec<u8> {
    const KOLY_LEN: usize = 512;
    const PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>resource-fork</key><dict><key>blkx</key><array/></dict></dict></plist>"#;
    let mut bytes: Vec<u8> = PLIST.to_vec();
    let xml_length: u64 = bytes.len() as u64;
    let base: usize = bytes.len();
    bytes.resize(base.saturating_add(KOLY_LEN), 0);
    bytes.splice(base..base + 4, b"koly".iter().copied());
    write_u64_be(&mut bytes, base + 216, 0);
    write_u64_be(&mut bytes, base + 224, xml_length);
    write_u64_be(&mut bytes, base + 492, sector_count);
    bytes
}

#[test]
fn a_dmg_declaring_an_image_past_the_limit_is_refused_by_size_before_it_is_allocated() {
    const SECTOR: u64 = 512;
    const OVERSIZED_SECTORS: u64 = (16 * 1024 * 1024 * 1024) / SECTOR;
    let bytes: Vec<u8> = dmg_declaring_sectors(OVERSIZED_SECTORS);

    let refusal: disrobe_binfmt::Error = reconstruct_image(&bytes)
        .map(|(image, _): (Vec<u8>, DmgSummary)| image.len())
        .expect_err("a dmg declaring a 16 GiB image from a 612 byte file must be refused");
    let rendered: String = refusal.to_string();
    assert!(
        rendered.contains("past the") && rendered.contains("byte limit"),
        "the refusal must come from the size check naming its limit, not from an earlier parse failure, got: {rendered}"
    );
}

#[test]
fn the_dmg_size_refusal_is_reached_only_by_the_declared_size() {
    let bytes: Vec<u8> = dmg_declaring_sectors(2);
    let (image, summary): (Vec<u8>, DmgSummary) = reconstruct_image(&bytes)
        .expect("a dmg declaring a two sector image must parse, or the refusal test is vacuous");
    assert_eq!(image.len(), 1024);
    assert_eq!(summary.image_len, 1024);
}

#[test]
fn a_declared_size_far_past_the_input_is_refused_rather_than_allocated() {
    for entry in corpus() {
        for offset in (0..entry.bytes().len().min(TRUNCATION_SWEEP_BYTES)).step_by(4) {
            let mut hostile: Vec<u8> = entry.bytes().to_vec();
            if let Some(window) = hostile.get_mut(offset..offset.saturating_add(8)) {
                window.fill(0xFF);
            }
            consume(probe_container_parsers(&hostile));
            consume(probe_structural(&hostile));
        }
    }
}
