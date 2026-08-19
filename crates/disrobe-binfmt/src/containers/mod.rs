pub mod apfs;
pub mod appimage;
pub mod ar;
pub mod arc;
pub mod arc_codec;
pub mod arj;
pub mod bare_stream;
pub mod blazor_webcil;
pub mod btrfs_send;
pub mod bun;
pub mod cab_lzms;
pub mod cpio;
pub mod cramfs;
pub mod cython;
pub mod dmg;
pub mod docker;
pub mod dotnet_bundle;
pub mod elf_overlay;
pub mod erofs;
pub mod eszip;
pub mod ext4;
pub mod fat;
pub mod firmware;
pub mod flatpak;
pub mod hfsplus;
pub mod innosetup;
pub mod installshield;
pub mod iso;
pub mod jffs2;
pub mod legacy_detect;
pub mod lha_dyn;
pub mod lha_huff;
pub mod lz4_block;
pub mod lzh;
pub mod lzms;
pub mod lzop;
pub mod minidump;
pub mod minixfs;
pub mod msi;
pub mod msix;
pub mod nsis;
pub mod nsis_bzip2;
pub mod ntfs;
pub mod oci;
pub mod ostree;
pub mod par2;
pub mod partclone;
pub mod partition;
pub mod pmarc;
pub mod qnx;
pub mod rar;
pub(crate) mod rar_filters;
pub mod rar_ppmd;
pub mod rar_unpack3;
pub mod rar_unpack5;
pub mod romfs;
pub mod rpm;
pub mod snap;
pub mod sparse;
pub mod squashfs;
pub mod squirrel;
pub mod stuffit;
pub mod stuffit5;
pub mod ubifs;
pub mod ucl;
pub mod uefi_fv;
pub mod unityfs;
pub mod uzip;
pub mod vhd;
pub mod vhdx;
pub mod wim;
pub mod wim_codec;
pub mod wim_image;
pub mod wim_lzx;
pub mod xalz;
pub mod xar;
pub mod yaffs;

pub(super) const MAX_CONTAINER_METADATA_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn admit_metadata_bytes(
    total: &mut usize,
    additional: usize,
    cap: usize,
    subject: &str,
) -> crate::error::Result<()> {
    let next: usize =
        total
            .checked_add(additional)
            .ok_or_else(|| crate::error::Error::QuotaExceeded {
                entry: subject.to_owned(),
                reason: "container metadata allocation overflow".to_owned(),
            })?;
    if next > cap {
        return Err(crate::error::Error::QuotaExceeded {
            entry: subject.to_owned(),
            reason: format!("container metadata exceeds cap {cap}"),
        });
    }
    *total = next;
    Ok(())
}

pub use apfs::{
    ApfsContainer, ApfsExtractedFile, ApfsFsRecord, ApfsVolume, apfs_file_bytes, detect_apfs,
    drec_name, extract_apfs_files, is_file_extent_record, is_inode_record, parse_apfs,
    resolve_omap_tree, walk_fs_tree_leaf,
};
pub use appimage::{
    AppImageFormat, AppImageLayout, AppImagePayloadLayout, detect_appimage, parse_appimage,
};
pub use ar::{ArArchive, ArMember, detect_ar, member_bytes as ar_member_bytes, parse_ar};
pub use arc::{
    ArcArchive, ArcEntry, detect_arc, entry_bytes as arc_entry_bytes,
    entry_is_stored as arc_entry_is_stored, parse_arc,
};
pub use arj::{
    ArjArchive, ArjEntry, detect_arj, entry_bytes as arj_entry_bytes,
    entry_is_stored as arj_entry_is_stored, parse_arj,
};
pub use bare_stream::{
    GzipMember, Lz4Layout, decompress_brotli, decompress_bzip2, decompress_compress,
    decompress_gzip_members, decompress_lz4, decompress_lzip, decompress_lzma_alone,
    decompress_lznt1, decompress_zstd, detect_brotli, detect_bzip2, detect_compress, detect_gzip,
    detect_lz4, detect_lzip, detect_lzma_alone, detect_lznt1, detect_zlib, detect_zstd,
    inflate_zlib_verified, lzma_alone_header_is_valid, try_decompress_brotli_oracle,
    try_decompress_lznt1_oracle,
};
pub use blazor_webcil::{
    BlazorAssemblyKind, BlazorAssemblyRef, BlazorBoot, BlazorFile, BlazorIntegrity, WebcilHeader,
    WebcilSection, detect_blazor_boot, detect_blazor_bundle, extract_blazor_bundle,
    parse_blazor_boot, parse_webcil_header, unwrap_webcil,
};
pub use btrfs_send::{
    BtrfsSendFile, BtrfsSendHeader, BtrfsSendReplay, detect_btrfs_send, replay_btrfs_send,
};
pub use bun::{
    BunModule, BunOffsets, BunStandalone, detect_bun, module_contents, parse_bun, sanitize_bun_name,
};
pub use cab_lzms::{CabLzmsFile, build_lzms_cab, cab_uses_lzms, extract_cab_lzms};
pub use cpio::{CpioArchive, CpioEntry, CpioVariant, detect_cpio_variant, parse_cpio};
pub use cramfs::{CramfsFile, CramfsWalk, detect_cramfs, walk_cramfs};
pub use cython::{
    CythonClass, CythonFunction, CythonIdentity, CythonModule, RecoverySource, detect_cython,
    recover_cython,
};
pub use dmg::{DmgSummary, KolyTrailer, detect_dmg, parse_koly, reconstruct_image};
pub use docker::{DockerManifest, parse_docker_manifest};
pub use dotnet_bundle::{
    BundleFileType, BundleLocation, DepsLibrary, DepsManifest, DepsRuntimeTarget,
    DepsTargetLibrary, DotnetBundle, DotnetBundleEntry, DotnetBundleFile, bundle_deps_manifest,
    bundle_file_bytes, detect_dotnet_bundle, extract_dotnet_bundle, parse_deps_manifest,
    parse_dotnet_bundle, write_bundle_file,
};
pub use elf_overlay::{
    ElfOverlay, ElfOverlayCarve, carve_elf_overlay, detect_elf_overlay, elf_image_end,
};
pub use erofs::{ErofsFile, ErofsSuperblock, ErofsWalk, detect_erofs, walk_erofs};
pub use eszip::{
    EszipArchive, EszipChecksum, EszipExtractedModule, EszipModuleEntry, EszipModuleKind,
    EszipNpmSpecifier, EszipRedirect, EszipVersion, detect_eszip, extract_eszip, module_source,
    module_source_map, parse_eszip, parse_eszip_at, sanitize_eszip_specifier,
};
pub use ext4::{Ext4File, Ext4Walk, detect_ext4, walk_ext4};
pub use fat::{
    FatBpb, FatFile, FatKind, FatVolume, detect_fat, file_data as fat_file_data, parse_bpb,
    walk_fat,
};
pub use firmware::{
    FirmwareExtraction, FirmwareKind, FirmwareMember, detect_firmware, extract_firmware,
};
pub use flatpak::{
    FlatpakBundleInfo, FlatpakExtraction, FlatpakSource, detect_flatpak_bundle,
    detect_flatpak_repo, extract_flatpak_bundle, extract_flatpak_repo, flatpak_external_hint,
};
pub use hfsplus::{
    HfsFile, HfsFolder, HfsVolume, detect_hfsplus, file_data as hfsplus_file_data,
    locate_hfsplus_volumes, parse_hfsplus, parse_hfsplus_at,
};
pub use innosetup::{
    InnoCompression, InnoFilter, InnoNamedRecovery, InnoRecoveredFile, InnoSetupInfo,
    SetupLoaderOffsets, detect_innosetup, extract_inno_block_stream, recover_inno_named_files,
    recover_inno_named_files_with_limits, unfilter_instructions,
};
pub use installshield::{
    InstallShieldArchive, InstallShieldCompression, InstallShieldFile, InstallShieldFileGroup,
    InstallShieldHeader, InstallShieldLayout, InstallShieldMemberState, InstallShieldVolume,
    deobfuscate_installshield, detect_installshield, installshield_display_name,
    installshield_layout, installshield_major_version, parse_installshield_header,
    walk_installshield,
};
pub use iso::{
    IsoEntry, IsoEntryKind, IsoExtent, IsoImage, ZisofsInfo, detect_iso,
    file_data as iso_file_data, parse_iso, read_file_data as read_iso_file_data,
};
pub use jffs2::{Jffs2Endian, Jffs2File, Jffs2Walk, detect_jffs2, walk_jffs2};
pub use legacy_detect::{
    PartcloneImage, QnxKind, StuffItKind, detect_partclone, detect_qnx, detect_stuffit,
};
pub use lzh::{LzhArchive, LzhFile, detect_lzh, parse_lzh};
pub use lzms::{lzms_compress, lzms_decompress};
pub use lzop::{LzopFile, detect_lzop, parse_lzop};
pub use minidump::{
    AbsentRange, AbsentReason, CarvedModule, CoverageReport, CvKind, CvRecord, MemorySource,
    MinidumpFile, MinidumpMemoryRegion, MinidumpModule, PeEmitReport, ProcessorArch,
    StreamDirEntry, carve_module, detect_minidump, minidump_extent, parse_minidump,
};
pub use minixfs::{
    MinixFile, MinixSuperblock, MinixVersion, MinixWalk, detect_minixfs, walk_minixfs,
};
pub use msi::{
    MsiEmbeddedCab, MsiExtractable, MsiSummary, parse_msi_minimal, read_msi_extractable,
};
pub use msix::{MsixManifest, parse_appx_manifest};
pub use nsis::{
    NsisArchive, NsisBlock, NsisCompression, NsisFileEntry, NsisHeader, decompress_file,
    detect_nsis, parse_nsis_archive,
};
pub use ntfs::{NtfsFileEntry, NtfsVolume, NtfsWalk, detect_ntfs, walk_ntfs};
pub use oci::{OciManifest, parse_oci_index, parse_oci_manifest};
pub use ostree::{
    DiskStore, MemoryStore, ObjectSource, OstreeFile, OstreeRef, OstreeRepoLayout,
    detect_ostree_repo, extract_commit, ostree_external_hint, parse_repo_config,
};
pub use par2::{Par2Packet, Par2ProtectedFile, Par2RecoverySet, detect_par2, parse_par2};
pub use partclone::{
    PartcloneV2, parse_v2 as parse_partclone_v2, reconstruct as reconstruct_partclone,
};
pub use partition::{
    GptHeader, GptPartition, GptTable, MbrPartition, MbrTable, parse_gpt, parse_gpt_header,
    parse_mbr,
};
pub use qnx::{
    QnxCompress, QnxStartup, decompress_ucl_segments as qnx_decompress_ucl_segments,
    inflate_startup_zlib as qnx_inflate_startup_zlib, parse_startup_header as qnx_parse_startup,
};
pub use rar::{
    RarArchive, RarEntry, RarMethod, detect_rar, entry_bytes as rar_entry_bytes,
    file_data as rar_file_data, parse_rar, parse_rar4, parse_rar5,
};
pub use romfs::{RomfsFile, RomfsHeader, RomfsWalk, detect_romfs, walk_romfs};
pub use rpm::{RecoveredRpm, RpmCompression, RpmEntry, RpmFormat, RpmSignatureBlob, recover_rpm};
pub use snap::detect_snap;
pub use sparse::{SparseHeader, detect_sparse, unsparse};
pub use squashfs::{
    SquashfsFile, SquashfsSuperblock, SquashfsWalk, parse_squashfs_superblock, walk_squashfs,
};
pub use squirrel::{SquirrelLayout, detect_squirrel, locate_embedded_nupkg};
pub use stuffit::{
    SitArchive, SitCompression, SitEntry, SitFork, fork_bytes_bounded as sit_fork_bytes_bounded,
    fork_is_stored as sit_fork_is_stored, parse_classic as parse_sit_classic,
};
pub use stuffit5::{
    Sit5Archive, Sit5Compression, Sit5Entry, Sit5Fork, Sit5Metadata,
    fork_bytes_bounded as sit5_fork_bytes_bounded, parse_sit5,
};
pub use ubifs::{UbiVolume, UbifsFile, UbifsWalk, detect_ubi, detect_ubifs, walk_ubifs};
pub use ucl::{NrvVariant, decompress as ucl_decompress};
pub use uefi_fv::{
    FvCodecOutcome, FvCompressionCodec, FvExtraction, FvFileRecord, FvFileSystemKind, FvFileType,
    FvHeader, FvPeImage, FvSectionRecord, detect_uefi_fv, extract_uefi_fv, guid_to_string,
    parse_fv_header,
};
pub use unityfs::{
    UnityBlockInfo, UnityCompression, UnityExtractedNode, UnityFsArchive, UnityFsHeader, UnityNode,
    UnityTextAsset, assemble_data as unityfs_assemble_data,
    build_bundle_uncompressed as unityfs_build_bundle_uncompressed,
    build_serialized_textasset as unityfs_build_serialized_textasset, detect_unityfs,
    extract_nodes as unityfs_extract_nodes, extract_text_assets as unityfs_extract_text_assets,
    parse as parse_unityfs, parse_header as parse_unityfs_header,
};
pub use uzip::{UzipCompressor, UzipImage, detect_uzip, parse_uzip};
pub use vhd::{
    VhdDiskType, VhdDynamicHeader, VhdFooter, VhdGeometry, VhdImage,
    materialize_logical_disk as vhd_materialize_logical_disk, parse_vhd, parse_vhd_footer,
};
pub use vhdx::{
    VhdxHeader, VhdxImage, VhdxMetadata, VhdxRegion,
    materialize_logical_disk as vhdx_materialize_logical_disk, parse_vhdx,
};
pub use wim::{
    WimArchive, WimCarvedResource, WimCompression, WimHeader, WimImageEntry, WimResource,
    carve_wim_resources, parse_reshdr_at, parse_wim,
};
pub use wim_codec::{codec_is_implemented, decompress_named_resource, decompress_wim_resource};
pub use wim_image::{WimExtractedFile, WimImageExtraction, extract_wim_files};
pub use wim_lzx::{lzx_build_resource_body, lzx_compress_chunk};
pub use xalz::{XalzAssembly, detect_xalz, parse_xalz};
pub use xar::{
    XarArchive, XarEncoding, XarFile, detect_xar, file_data as xar_file_data, parse_xar,
};
pub use yaffs::{Yaffs2Endian, Yaffs2File, Yaffs2Walk, detect_yaffs2, walk_yaffs2};
