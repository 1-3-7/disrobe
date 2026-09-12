#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    GradedBy(&'static str),
    OutOfScope(&'static str),
    Unobserved(&'static str),
}

const SOURCES: [(&str, &str); 4] = [
    ("real_toolchain.rs", include_str!("real_toolchain.rs")),
    ("embedded_oracle.rs", include_str!("embedded_oracle.rs")),
    ("electron_oracle.rs", include_str!("electron_oracle.rs")),
    ("fuzz_resilience.rs", include_str!("fuzz_resilience.rs")),
];

const EMBEDDING_MODES: [(&str, Coverage); 8] = [
    (
        "tauri v2, frontend compiled into the image as a generated asset map",
        Coverage::GradedBy("a_real_tauri_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "tauri v1, frontend compiled into the image as a generated asset map",
        Coverage::GradedBy("a_real_tauri_v1_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "tauri, frontend placed in a platform resource section",
        Coverage::Unobserved(
            "no released tauri version emits the frontend into a PE resource or a Mach-O section; \
             both major versions emit a record array of byte-string constants",
        ),
    ),
    (
        "tauri dev build, frontend read from disk at run time",
        Coverage::OutOfScope(
            "the assets are not in the image at all, so no static reader can recover them",
        ),
    ),
    (
        "wails v2, frontend embedded through the go embedded filesystem",
        Coverage::GradedBy("a_real_wails_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "wails v3, frontend embedded through the go embedded filesystem",
        Coverage::Unobserved(
            "v3 is pre-release; it embeds through the same go directive and record layout that the \
             v2 grade exercises",
        ),
    ),
    (
        "go embedded filesystem with no wails marker",
        Coverage::GradedBy("carves_go_embed_native_pe"),
    ),
    (
        "electron archive, standalone and concatenated into a larger image",
        Coverage::GradedBy("locates_asar_embedded_inside_a_larger_binary"),
    ),
];

const HOST_CONTAINERS: [(&str, Coverage); 10] = [
    (
        "pe32+ little endian",
        Coverage::GradedBy("a_real_tauri_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "pe32 little endian",
        Coverage::Unobserved(
            "the pointer width comes from the image header and the 32-bit read path is graded on \
             elf32 in both byte orders",
        ),
    ),
    (
        "elf64 little endian, position independent, pointers supplied by relocations",
        Coverage::GradedBy("carves_go_embed_linux_pie_elf"),
    ),
    (
        "elf64 little endian, static position independent, compiler emitted",
        Coverage::GradedBy("carves_clang_static_pie_elf_via_relocations"),
    ),
    (
        "elf64 big endian",
        Coverage::GradedBy("carves_go_embed_in_both_endiannesses"),
    ),
    (
        "elf32 little endian and big endian",
        Coverage::GradedBy("carves_go_embed_in_both_endiannesses"),
    ),
    (
        "mach-o thin, x86-64 and aarch64",
        Coverage::GradedBy("carves_thin_and_universal_macho_go_embed"),
    ),
    (
        "mach-o universal, 32-bit and 64-bit fat headers",
        Coverage::GradedBy("carves_thin_and_universal_macho_go_embed"),
    ),
    (
        "mach-o 32-bit",
        Coverage::OutOfScope(
            "no current toolchain target emits it and no webview desktop toolchain ships it",
        ),
    ),
    (
        "image with many sections, so the span index rather than a linear walk resolves a pointer",
        Coverage::GradedBy("many_section_binary_recovers_exact_tree"),
    ),
];

const PACKAGED_FORMS: [(&str, Coverage); 7] = [
    (
        "archive carrying the application image",
        Coverage::GradedBy("a_package_is_named_then_carved_once_its_member_is_extracted"),
    ),
    (
        "windows installer database",
        Coverage::OutOfScope(
            "the reader lives in the binary format crate; this pass names the container and carves \
             the member the container pass hands it",
        ),
    ),
    (
        "windows scripted installer executable",
        Coverage::OutOfScope(
            "the reader lives in the binary format crate; this pass names the container and carves \
             the member the container pass hands it",
        ),
    ),
    (
        "linux self-mounting application image",
        Coverage::OutOfScope(
            "the reader lives in the binary format crate; this pass names the container and carves \
             the member the container pass hands it",
        ),
    ),
    (
        "debian package",
        Coverage::OutOfScope(
            "the reader lives in the binary format crate; this pass names the container and carves \
             the member the container pass hands it",
        ),
    ),
    (
        "apple disk image",
        Coverage::OutOfScope(
            "the reader lives in the binary format crate; this pass names the container and carves \
             the member the container pass hands it",
        ),
    ),
    (
        "apple application bundle",
        Coverage::OutOfScope(
            "a bundle is a directory rather than a byte stream, so the caller walks it and hands \
             each image to this pass",
        ),
    ),
];

const ENCODINGS: [(&str, Coverage); 10] = [
    (
        "uncompressed asset",
        Coverage::GradedBy("a_real_wails_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "brotli asset, which carries no frame magic",
        Coverage::GradedBy("a_real_tauri_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "whole map encoded with brotli, so only the map-wide anchor can decode any of it",
        Coverage::GradedBy(
            "tauri_style_brotli_map_recovers_the_original_tree_without_a_frame_to_detect",
        ),
    ),
    (
        "zero-length member of a brotli map, which holds no stream to inflate",
        Coverage::GradedBy(
            "tauri_style_brotli_map_recovers_the_original_tree_without_a_frame_to_detect",
        ),
    ),
    (
        "stored member inside an otherwise brotli map",
        Coverage::GradedBy(
            "a_raw_member_of_a_brotli_map_is_withheld_rather_than_reported_as_bytes_it_never_held",
        ),
    ),
    (
        "brotli stream that expands past the quota",
        Coverage::GradedBy("a_brotli_decompression_bomb_is_refused_by_the_quota"),
    ),
    (
        "zstd asset",
        Coverage::GradedBy("tauri_style_zstd_map_recovers_the_original_tree"),
    ),
    (
        "gzip asset",
        Coverage::GradedBy("gzip_embedded_assets_decode_to_what_the_encoder_was_given"),
    ),
    (
        "one map holding several encodings at once",
        Coverage::GradedBy("a_mixed_encoding_map_recovers_each_entry_under_its_own_codec"),
    ),
    (
        "compressed asset that expands past the quota",
        Coverage::GradedBy("a_decompression_bomb_is_refused_by_the_quota"),
    ),
];

const ASSET_KINDS: [(&str, Coverage); 6] = [
    (
        "markup, style sheet, script, source map, manifest and plain text",
        Coverage::GradedBy("a_real_tauri_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "webassembly module, raster image and web font",
        Coverage::GradedBy("a_real_wails_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "zero-length asset",
        Coverage::GradedBy("a_real_tauri_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "symbolic link, and one whose target leaves the tree",
        Coverage::GradedBy("recovers_symlink_executable_and_verifies_integrity"),
    ),
    (
        "asset marked executable",
        Coverage::GradedBy("recovers_symlink_executable_and_verifies_integrity"),
    ),
    (
        "asset name outside ascii",
        Coverage::GradedBy("recovers_non_ascii_names_and_binary_content_byte_identically"),
    ),
];

const SIZE_CLASSES: [(&str, Coverage); 3] = [
    (
        "one-byte asset",
        Coverage::GradedBy(
            "tauri_style_brotli_map_recovers_the_original_tree_without_a_frame_to_detect",
        ),
    ),
    (
        "asset whose decoded size lands exactly on the per-entry cap",
        Coverage::GradedBy("an_asset_whose_decoded_size_equals_the_per_entry_cap_is_admitted"),
    ),
    (
        "asset whose decoded size passes the per-entry cap by one byte",
        Coverage::GradedBy("an_asset_one_byte_past_the_per_entry_cap_is_refused_by_the_quota"),
    ),
];

const FAMILY_DETECTION: [(&str, Coverage); 6] = [
    (
        "tauri v2 named through the public detection surface rather than through a carve",
        Coverage::GradedBy("a_real_tauri_build_is_named_tauri_by_the_public_detection_surface"),
    ),
    (
        "tauri v1 named through the public detection surface, whose marker set differs from v2",
        Coverage::GradedBy("a_real_tauri_v1_build_is_named_tauri_by_the_public_detection_surface"),
    ),
    (
        "wails named through the public detection surface",
        Coverage::GradedBy("a_real_wails_build_is_named_wails_by_the_public_detection_surface"),
    ),
    (
        "real build of one family raising no evidence for another family",
        Coverage::GradedBy("a_real_build_raises_no_evidence_for_a_family_it_is_not"),
    ),
    (
        "archive header scan run across a real image that holds no archive",
        Coverage::GradedBy("no_real_embedded_build_is_mistaken_for_an_archive"),
    ),
    (
        "committed build whose identity is pinned to a recorded digest",
        Coverage::GradedBy("every_committed_build_matches_its_recorded_digest"),
    ),
];

const INTEGRITY: [(&str, Coverage); 3] = [
    (
        "integrity metadata absent",
        Coverage::GradedBy("a_real_tauri_build_reports_every_asset_without_integrity_metadata"),
    ),
    (
        "integrity metadata present and matching",
        Coverage::GradedBy("recovers_symlink_executable_and_verifies_integrity"),
    ),
    (
        "integrity metadata present and not matching",
        Coverage::GradedBy("recovers_symlink_executable_and_verifies_integrity"),
    ),
];

const HOSTILE_SHAPES: [(&str, Coverage); 9] = [
    (
        "key that escapes the output root by traversal, absolute prefix or drive letter",
        Coverage::GradedBy("a_traversal_key_is_dropped_while_the_rest_of_the_map_survives"),
    ),
    (
        "two output paths that differ only by ASCII case",
        Coverage::GradedBy("ascii_case_collisions_are_rejected_before_a_report_escapes"),
    ),
    (
        "two output paths whose Unicode uppercase mapping collides through scalar expansion",
        Coverage::GradedBy(
            "unicode_case_expansion_collisions_are_rejected_before_a_report_escapes",
        ),
    ),
    (
        "the same output path repeated exactly",
        Coverage::GradedBy("an_exact_duplicate_keeps_the_first_record"),
    ),
    (
        "directory paths retained by collision preflight beyond the configured entry cap",
        Coverage::GradedBy("directory_paths_consume_the_collision_preflight_entry_quota"),
    ),
    (
        "pointer-shaped array that is not an asset map",
        Coverage::GradedBy("decoy_pointer_array_never_locks_a_table"),
    ),
    (
        "flat name table inside a real image, such as an import or media type list",
        Coverage::GradedBy("a_real_wails_build_recovers_its_frontend_byte_identically"),
    ),
    (
        "declared length or offset that runs past the image",
        Coverage::GradedBy("a_truncated_image_yields_a_typed_error_rather_than_a_panic"),
    ),
    (
        "mutated image, which must yield a typed error rather than a panic",
        Coverage::GradedBy("every_unmutated_seed_finishes"),
    ),
];

fn all_members() -> Vec<(&'static str, Coverage)> {
    let mut members: Vec<(&'static str, Coverage)> = Vec::new();
    members.extend(EMBEDDING_MODES);
    members.extend(HOST_CONTAINERS);
    members.extend(PACKAGED_FORMS);
    members.extend(ENCODINGS);
    members.extend(ASSET_KINDS);
    members.extend(SIZE_CLASSES);
    members.extend(FAMILY_DETECTION);
    members.extend(INTEGRITY);
    members.extend(HOSTILE_SHAPES);
    members
}

#[test]
fn every_declared_input_space_member_names_a_live_test_or_a_reason() {
    let mut graded: usize = 0;
    let mut named: usize = 0;
    for (member, coverage) in all_members() {
        match coverage {
            Coverage::GradedBy(test_name) => {
                let needle: String = format!("fn {test_name}(");
                let found: bool = SOURCES
                    .iter()
                    .any(|(_, body): &(&str, &str)| body.contains(&needle));
                assert!(
                    found,
                    "`{member}` claims the grade `{test_name}`, which no test in this crate \
                     defines, so the claim describes nothing"
                );
                graded += 1;
            }
            Coverage::OutOfScope(reason) | Coverage::Unobserved(reason) => {
                assert!(
                    reason.len() > 40,
                    "`{member}` is excluded without a reason a reader can check"
                );
                named += 1;
            }
        }
    }
    assert_eq!(graded + named, all_members().len());
    assert!(
        graded > named,
        "the declared input space must be mostly graded, not mostly excused: {graded} graded \
         against {named} excluded"
    );
}

#[test]
fn no_input_space_member_is_declared_twice() {
    let members: Vec<(&'static str, Coverage)> = all_members();
    let unique: BTreeSet<&'static str> = members
        .iter()
        .map(|(member, _): &(&'static str, Coverage)| *member)
        .collect();
    assert_eq!(
        unique.len(),
        members.len(),
        "a duplicated member would let one grade appear to cover two cases"
    );
}
