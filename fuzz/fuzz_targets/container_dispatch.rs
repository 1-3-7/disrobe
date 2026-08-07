#![no_main]

use core::hint::black_box;
use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;

use disrobe_binfmt::containers::{
    apfs, ar, arc, arj, bare_stream, blazor_webcil, btrfs_send, bun, cpio, cramfs, cython, dmg,
    dotnet_bundle, elf_overlay, erofs, eszip, ext4, fat, firmware, flatpak, hfsplus, innosetup,
    installshield, iso, jffs2, legacy_detect, lzh, lzop, minidump, minixfs, nsis, ntfs, par2,
    partition, rar, romfs, snap, sparse, squirrel, ubifs, uefi_fv, unityfs, uzip, xalz, xar, yaffs,
};
use disrobe_binfmt::{
    ExtractionQuota, QuotaGuard, classify_input, detect_container, detect_container_with_hint,
    identify_by_structure, is_skip_magic, native_lang_fingerprint, sanitize_entry_path,
    skip_magic_label,
};
use disrobe_fuzz::{entry_name, over_input_budget};

const RATIO_BOMB_COMPRESSED_BYTES: u64 = 1;

fn drive_dispatch(data: &[u8]) {
    let _ = black_box(detect_container(data));
    let _ = black_box(identify_by_structure(data));
    let _ = black_box(native_lang_fingerprint(data));
    let _ = black_box(is_skip_magic(data));
    let _ = black_box(skip_magic_label(data));
}

fn drive_hinted_dispatch(data: &[u8], hint: &Path) {
    let _ = black_box(detect_container_with_hint(data, Some(hint)));
    let _ = black_box(detect_container_with_hint(data, None));
    let _ = black_box(classify_input(hint, data));
}

fn drive_container_detectors(data: &[u8]) {
    let _ = black_box(apfs::detect_apfs(data));
    let _ = black_box(ar::detect_ar(data));
    let _ = black_box(arc::detect_arc(data));
    let _ = black_box(arj::detect_arj(data));
    let _ = black_box(bare_stream::detect_brotli(data));
    let _ = black_box(bare_stream::detect_bzip2(data));
    let _ = black_box(bare_stream::detect_compress(data));
    let _ = black_box(bare_stream::detect_gzip(data));
    let _ = black_box(bare_stream::detect_lz4(data));
    let _ = black_box(bare_stream::detect_lzip(data));
    let _ = black_box(bare_stream::detect_lzma_alone(data));
    let _ = black_box(bare_stream::detect_lznt1(data));
    let _ = black_box(bare_stream::detect_zlib(data));
    let _ = black_box(bare_stream::detect_zstd(data));
    let _ = black_box(blazor_webcil::detect_blazor_boot(data));
    let _ = black_box(btrfs_send::detect_btrfs_send(data));
    let _ = black_box(bun::detect_bun(data));
    let _ = black_box(cpio::detect_cpio_variant(data));
    let _ = black_box(cramfs::detect_cramfs(data));
    let _ = black_box(cython::detect_cython(data));
    let _ = black_box(dmg::detect_dmg(data));
    let _ = black_box(dotnet_bundle::detect_dotnet_bundle(data));
    let _ = black_box(elf_overlay::detect_elf_overlay(data));
    let _ = black_box(erofs::detect_erofs(data));
    let _ = black_box(eszip::detect_eszip(data));
    let _ = black_box(ext4::detect_ext4(data));
    let _ = black_box(fat::detect_fat(data));
    let _ = black_box(firmware::detect_firmware(data));
    let _ = black_box(flatpak::detect_flatpak_bundle(data));
    let _ = black_box(hfsplus::detect_hfsplus(data));
    let _ = black_box(innosetup::detect_innosetup(data));
    let _ = black_box(installshield::detect_installshield(data));
    let _ = black_box(iso::detect_iso(data));
    let _ = black_box(jffs2::detect_jffs2(data));
    let _ = black_box(legacy_detect::detect_partclone(data));
    let _ = black_box(legacy_detect::detect_qnx(data));
    let _ = black_box(legacy_detect::detect_stuffit(data));
    let _ = black_box(lzh::detect_lzh(data));
    let _ = black_box(lzop::detect_lzop(data));
    let _ = black_box(minidump::detect_minidump(data));
    let _ = black_box(minixfs::detect_minixfs(data));
    let _ = black_box(nsis::detect_nsis(data));
    let _ = black_box(ntfs::detect_ntfs(data));
    let _ = black_box(par2::detect_par2(data));
    let _ = black_box(partition::detect_gpt_logical_sector_size(data));
    let _ = black_box(rar::detect_rar(data));
    let _ = black_box(romfs::detect_romfs(data));
    let _ = black_box(snap::detect_snap(data));
    let _ = black_box(sparse::detect_sparse(data));
    let _ = black_box(squirrel::detect_squirrel(data));
    let _ = black_box(ubifs::detect_ubi(data));
    let _ = black_box(ubifs::detect_ubifs(data));
    let _ = black_box(uefi_fv::detect_uefi_fv(data));
    let _ = black_box(unityfs::detect_unityfs(data));
    let _ = black_box(uzip::detect_uzip(data));
    let _ = black_box(xalz::detect_xalz(data));
    let _ = black_box(xar::detect_xar(data));
    let _ = black_box(yaffs::detect_yaffs2(data));
}

fn sanitized_path_cannot_escape(name: &str) {
    let Ok(clean): disrobe_binfmt::Result<String> = sanitize_entry_path(name) else {
        return;
    };
    let path: &Path = Path::new(&clean);
    assert!(
        !path.is_absolute(),
        "sanitize_entry_path returned an absolute path"
    );
    assert!(
        path.components()
            .all(|part: Component<'_>| matches!(part, Component::Normal(_))),
        "sanitize_entry_path returned a path with a non-normal component"
    );
    assert!(
        !clean.is_empty(),
        "sanitize_entry_path returned an empty path"
    );
}

fn quota_refuses_a_declared_bomb(name: &str, declared_uncompressed: u64) {
    let quota: ExtractionQuota = ExtractionQuota::default_safe();
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let admitted: disrobe_binfmt::Result<()> =
        guard.admit_entry(name, declared_uncompressed, RATIO_BOMB_COMPRESSED_BYTES);
    if declared_uncompressed > guard.max_per_entry_uncompressed() {
        assert!(
            admitted.is_err(),
            "the quota admitted an entry declaring more than its per-entry cap"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    let name: String = entry_name(data);
    let hint: &Path = Path::new(name.as_str());

    drive_dispatch(data);
    drive_hinted_dispatch(data, hint);
    drive_container_detectors(data);
    sanitized_path_cannot_escape(&name);
    quota_refuses_a_declared_bomb(
        &name,
        u64::from(data.len() as u32).wrapping_mul(u64::MAX / 3),
    );
    quota_refuses_a_declared_bomb(&name, u64::MAX);
});
