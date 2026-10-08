#![allow(clippy::duplicate_mod)]

#[path = "../appimage_type1.rs"]
mod appimage_type1;

#[path = "../arc_distilled.rs"]
mod arc_distilled;

#[path = "../byte_coverage.rs"]
mod byte_coverage;

#[path = "../byte_coverage_wasm.rs"]
mod byte_coverage_wasm;

#[path = "../caller_offset_bounds.rs"]
mod caller_offset_bounds;

#[path = "../carve_recursive.rs"]
mod carve_recursive;

#[path = "../container_appimage_snap.rs"]
mod container_appimage_snap;

#[path = "../container_disk_images.rs"]
mod container_disk_images;

#[path = "../container_embedded_fs.rs"]
mod container_embedded_fs;

#[path = "../container_fs_walker.rs"]
mod container_fs_walker;

#[path = "../container_msix_msi.rs"]
mod container_msix_msi;

#[path = "../container_nsis_external.rs"]
mod container_nsis_external;

#[path = "../container_oci_docker.rs"]
mod container_oci_docker;

#[path = "../container_roster.rs"]
mod container_roster;

#[path = "../corpus_image_sweep.rs"]
mod corpus_image_sweep;

#[path = "../cython_stub_reference.rs"]
mod cython_stub_reference;

#[path = "../debug_framework.rs"]
mod debug_framework;

#[path = "../elf_dynamic.rs"]
mod elf_dynamic;

#[path = "../enigma.rs"]
mod enigma;

#[path = "../erofs_real_images.rs"]
mod erofs_real_images;

#[path = "../firmware_vendor.rs"]
mod firmware_vendor;

#[path = "../image_roundtrip.rs"]
mod image_roundtrip;

#[path = "../import_graph_dot.rs"]
mod import_graph_dot;

#[path = "../minidump_real_pe.rs"]
mod minidump_real_pe;

#[path = "../native_image.rs"]
mod native_image;

#[path = "../negative_corpus.rs"]
mod negative_corpus;

#[path = "../partial_archive_parity.rs"]
mod partial_archive_parity;

#[path = "../real_appimage.rs"]
mod real_appimage;

#[path = "../real_appimage_type1.rs"]
mod real_appimage_type1;

#[path = "../real_archive_reference_graders.rs"]
mod real_archive_reference_graders;

#[path = "../real_arj.rs"]
mod real_arj;

#[path = "../real_bare_stream.rs"]
mod real_bare_stream;

#[path = "../real_bun_compile.rs"]
mod real_bun_compile;

#[path = "../real_cab.rs"]
mod real_cab;

#[path = "../real_cramfs.rs"]
mod real_cramfs;

#[path = "../real_cython.rs"]
mod real_cython;

#[path = "../real_deb_lzma.rs"]
mod real_deb_lzma;

#[path = "../real_deno_compile.rs"]
mod real_deno_compile;

#[path = "../real_disk_fat.rs"]
mod real_disk_fat;

#[path = "../real_disk_partition_fs.rs"]
mod real_disk_partition_fs;

#[path = "../real_dmg.rs"]
mod real_dmg;

#[path = "../real_docker.rs"]
mod real_docker;

#[path = "../real_dotnet_single_file.rs"]
mod real_dotnet_single_file;

#[path = "../real_elf_overlay.rs"]
mod real_elf_overlay;

#[path = "../real_ext4.rs"]
mod real_ext4;

#[path = "../real_fat.rs"]
mod real_fat;

#[path = "../real_innosetup.rs"]
mod real_innosetup;

#[path = "../real_installshield.rs"]
mod real_installshield;

#[path = "../real_iso.rs"]
mod real_iso;

#[path = "../real_legacy_archives.rs"]
mod real_legacy_archives;

#[path = "../real_luks1.rs"]
mod real_luks1;

#[path = "../real_lzh_level3.rs"]
mod real_lzh_level3;

#[path = "../real_lzh_pmarc.rs"]
mod real_lzh_pmarc;

#[path = "../real_msi.rs"]
mod real_msi;

#[path = "../real_msi_extract.rs"]
mod real_msi_extract;

#[path = "../real_msix.rs"]
mod real_msix;

#[path = "../real_nsis.rs"]
mod real_nsis;

#[path = "../real_nsis_bzip2.rs"]
mod real_nsis_bzip2;

#[path = "../real_nsis_solid.rs"]
mod real_nsis_solid;

#[path = "../real_oci.rs"]
mod real_oci;

#[path = "../real_par2.rs"]
mod real_par2;

#[path = "../real_rar.rs"]
mod real_rar;

#[path = "../real_rpm.rs"]
mod real_rpm;

#[path = "../real_sevenz.rs"]
mod real_sevenz;

#[path = "../real_snap.rs"]
mod real_snap;

#[path = "../real_squashfs.rs"]
mod real_squashfs;

#[path = "../real_squashfs_comp.rs"]
mod real_squashfs_comp;

#[path = "../real_squashfs_lzo.rs"]
mod real_squashfs_lzo;

#[path = "../real_uzip.rs"]
mod real_uzip;

#[path = "../real_wim_files.rs"]
mod real_wim_files;

#[path = "../real_wim_lzms.rs"]
mod real_wim_lzms;

#[path = "../real_xalz.rs"]
mod real_xalz;

#[path = "../real_xar.rs"]
mod real_xar;

#[path = "../signature_defeat.rs"]
mod signature_defeat;

#[path = "../stuffit_method13.rs"]
mod stuffit_method13;

#[path = "../stuffit_method2.rs"]
mod stuffit_method2;

#[path = "../stuffit_method5.rs"]
mod stuffit_method5;

#[path = "../stuffit_method8.rs"]
mod stuffit_method8;

#[path = "../stuffit5_arsenic.rs"]
mod stuffit5_arsenic;

#[path = "../synthetic_oci_docker.rs"]
mod synthetic_oci_docker;

#[path = "../tool_requirement_gate.rs"]
mod tool_requirement_gate;

#[path = "../uefi_fv_dispatch.rs"]
mod uefi_fv_dispatch;

#[path = "../wim_lzx_roundtrip.rs"]
mod wim_lzx_roundtrip;

#[path = "../zip_refusal_reasons.rs"]
mod zip_refusal_reasons;
