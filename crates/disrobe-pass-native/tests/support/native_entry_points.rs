use std::path::Path;

use disrobe_pass_native::error::{Error, Result};
use disrobe_pass_native::packers::overlay::ArchiveKind;
use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::patch::PatchEdit;
use disrobe_pass_native::pseudo_c::Abi;
use disrobe_pass_native::sigmaker::SigmakerOptions;
use disrobe_pass_native::vm_devirt::detect::Bitness;
use disrobe_pass_native::*;

pub(crate) struct Ctx<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) other: &'a [u8],
    pub(crate) scratch: &'a Path,
    pub(crate) label: &'a str,
}

pub(crate) enum Verdict {
    Ok,
    Failed(String),
    NotFallible,
    Reached,
    Unreached,
}

pub(crate) struct Entry {
    pub(crate) path: &'static str,
    pub(crate) cheap: bool,
    pub(crate) drive: fn(&Ctx<'_>) -> Verdict,
}

const RESULT_BOUND_SLACK: usize = 4096;
const BOUNDED_OUTPUT: usize = 1 << 20;

pub(crate) fn from_result<T>(value: Result<T>) -> Verdict {
    match value {
        Ok(_) => Verdict::Ok,
        Err(error) => Verdict::Failed(error.to_string()),
    }
}

pub(crate) fn from_foreign<T, E>(value: core::result::Result<T, E>) -> Verdict {
    drop(value);
    Verdict::Reached
}

pub(crate) fn bounded_len(len: usize, ctx: &Ctx<'_>) -> Verdict {
    assert!(
        len <= ctx.bytes.len() + RESULT_BOUND_SLACK,
        "{} produced {len} items from {} bytes, which is more output than the input can justify",
        ctx.label,
        ctx.bytes.len()
    );
    Verdict::NotFallible
}

fn parsed_pe(ctx: &Ctx<'_>) -> Option<PeImage> {
    parse_pe_image(ctx.bytes).ok()
}

pub(crate) const ENTRY_POINTS: &[Entry] = &[
    Entry {
        path: "authenticode::verify",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = authenticode::verify(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "backend_export::rebuild_passthrough",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(backend_export::rebuild_passthrough(ctx.bytes)),
    },
    Entry {
        path: "backend_export::collect_recovered_symbols",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(backend_export::collect_recovered_symbols(ctx.bytes)),
    },
    Entry {
        path: "crypto_consts::detect_crypto_constants",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(crypto_consts::detect_crypto_constants(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "cxx_recovery::recover_cxx_hierarchy",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = cxx_recovery::recover_cxx_hierarchy(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "cxx_recovery::parse_itanium_lsda",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(cxx_recovery::parse_itanium_lsda(ctx.bytes)),
    },
    Entry {
        path: "cxx_recovery::parse_windows_seh_scope_table",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(cxx_recovery::parse_windows_seh_scope_table(ctx.bytes)),
    },
    Entry {
        path: "debug_info::summarize_pdb",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(debug_info::summarize_pdb(ctx.bytes)),
    },
    Entry {
        path: "debug_info::recover_pdb",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(debug_info::recover_pdb(ctx.bytes)),
    },
    Entry {
        path: "delphi::recover_delphi_classes",
        cheap: false,
        drive: |ctx: &Ctx<'_>| bounded_len(delphi::recover_delphi_classes(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "delphi::recover_delphi_strings",
        cheap: false,
        drive: |ctx: &Ctx<'_>| bounded_len(delphi::recover_delphi_strings(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "delphi::decode_dfm",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = delphi::decode_dfm(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "delphi::recover_dfm_resources",
        cheap: false,
        drive: |ctx: &Ctx<'_>| bounded_len(delphi::recover_dfm_resources(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "delphi::detect_delphi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = delphi::detect_delphi(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "delphi::analyze",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = delphi::analyze(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "deobf::cff::detect_flattening",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = deobf::cff::detect_flattening(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "disasm_ir::build_disasm_payload",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(disasm_ir::build_disasm_payload(ctx.bytes)),
    },
    Entry {
        path: "disasm_ir::seh_scope_function_starts",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(disasm_ir::seh_scope_function_starts(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "disasm_ir::image_arch",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = disasm_ir::image_arch(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "disasm_ir::text_section_window",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = disasm_ir::text_section_window(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "dwarf_sourcemap::synthesize_dwarf_sourcemap",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(dwarf_sourcemap::synthesize_dwarf_sourcemap(ctx.bytes)),
    },
    Entry {
        path: "dwarf_sourcemap::reconstruct_dwarf_types",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(dwarf_sourcemap::reconstruct_dwarf_types(ctx.bytes)),
    },
    Entry {
        path: "elf::analyze",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = elf::analyze(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "emu_strings::emulate_string_decoders",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(emu_strings::emulate_string_decoders(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "entropy_viz::byte_histogram",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = entropy_viz::byte_histogram(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "fileid::identify",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = fileid::identify(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "flirt::parse_flirt",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(flirt::parse_flirt(ctx.bytes)),
    },
    Entry {
        path: "flirt::crc16_flirt",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = flirt::crc16_flirt(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "format::detect",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(format::detect(ctx.bytes)),
    },
    Entry {
        path: "identify::detect",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = identify::detect(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "lang::detect",
        cheap: true,
        drive: |ctx: &Ctx<'_>| bounded_len(lang::detect(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "obfuscators::detect",
        cheap: false,
        drive: |ctx: &Ctx<'_>| bounded_len(obfuscators::detect(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "obfuscators::recover_obfuscxx_strings",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(obfuscators::recover_obfuscxx_strings(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "obfuscators::recover_amice_xor_strings",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(obfuscators::recover_amice_xor_strings(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "obfuscators::recover_single_byte_xor_strings",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(
                obfuscators::recover_single_byte_xor_strings(ctx.bytes).len(),
                ctx,
            )
        },
    },
    Entry {
        path: "packers::aspack_unpack::unpack_aspack",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::aspack_unpack::unpack_aspack(ctx.bytes)),
    },
    Entry {
        path: "packers::asprotect_unpack::asprotect_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::asprotect_unpack::asprotect_layout(ctx.bytes)),
    },
    Entry {
        path: "packers::asprotect_unpack::unpack_asprotect",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::asprotect_unpack::unpack_asprotect(ctx.bytes)),
    },
    Entry {
        path: "packers::chain_sigs::detect_packer_chain",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(
                packers::chain_sigs::detect_packer_chain(ctx.bytes).len(),
                ctx,
            )
        },
    },
    Entry {
        path: "packers::fsg_unpack::unpack_fsg",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::fsg_unpack::unpack_fsg(ctx.bytes)),
    },
    Entry {
        path: "packers::kkrunchy_k7_phase2::unpack_kkrunchy_k7_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_k7_phase2::unpack_kkrunchy_k7_emulated(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_phase2::unpack_kkrunchy_phase2_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_phase2::unpack_kkrunchy_phase2_emulated(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::looks_like_kkrunchy",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::kkrunchy_unpack::looks_like_kkrunchy(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::parse_kkrunchy_header",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_unpack::parse_kkrunchy_header(ctx.bytes))
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::unpack_kkrunchy",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::kkrunchy_unpack::unpack_kkrunchy(ctx.bytes)),
    },
    Entry {
        path: "packers::loader_generators::fingerprint_loader",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::loader_generators::fingerprint_loader(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::loader_generators::recover_loader",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::loader_generators::recover_loader(ctx.bytes)),
    },
    Entry {
        path: "packers::mew_unpack::unpack_mew",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::mew_unpack::unpack_mew(ctx.bytes)),
    },
    Entry {
        path: "packers::mew_unpack::unpack_mew_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::mew_unpack::unpack_mew_emulated(ctx.bytes)),
    },
    Entry {
        path: "packers::mew_unpack::unpack_mew_rebuilt",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::mew_unpack::unpack_mew_rebuilt(ctx.bytes)),
    },
    Entry {
        path: "packers::detect",
        cheap: true,
        drive: |ctx: &Ctx<'_>| bounded_len(packers::detect(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "packers::fingerprint_chain",
        cheap: true,
        drive: |ctx: &Ctx<'_>| bounded_len(packers::fingerprint_chain(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "packers::morphine_unpack::morphine_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::morphine_unpack::morphine_layout(ctx.bytes)),
    },
    Entry {
        path: "packers::morphine_unpack::unpack_morphine",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::morphine_unpack::unpack_morphine(ctx.bytes)),
    },
    Entry {
        path: "packers::mpress_unpack::unpack_mpress",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::mpress_unpack::unpack_mpress(ctx.bytes)),
    },
    Entry {
        path: "packers::neolite_unpack::neolite_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::neolite_unpack::neolite_layout(ctx.bytes)),
    },
    Entry {
        path: "packers::neolite_unpack::unpack_neolite",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::neolite_unpack::unpack_neolite(ctx.bytes)),
    },
    Entry {
        path: "packers::npack_unpack::npack_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::npack_unpack::npack_layout(ctx.bytes)),
    },
    Entry {
        path: "packers::npack_unpack::unpack_npack",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::npack_unpack::unpack_npack(ctx.bytes)),
    },
    Entry {
        path: "packers::nspack_unpack::unpack_nspack",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::nspack_unpack::unpack_nspack(ctx.bytes)),
    },
    Entry {
        path: "packers::nspack_unpack::unpack_nspack_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::nspack_unpack::unpack_nspack_emulated(ctx.bytes))
        },
    },
    Entry {
        path: "packers::nspack_unpack::parse_nspack_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::nspack_unpack::parse_nspack_layout(ctx.bytes)),
    },
    Entry {
        path: "packers::overlay::analyze_pe_overlay",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(packers::overlay::analyze_pe_overlay(ctx.bytes)),
    },
    Entry {
        path: "packers::overlay::carve_overlay",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::overlay::carve_overlay(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::overlay::normalize_pe",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(packers::overlay::normalize_pe(ctx.bytes)),
    },
    Entry {
        path: "packers::pe_sections::parse_pe_image",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(packers::pe_sections::parse_pe_image(ctx.bytes)),
    },
    Entry {
        path: "packers::pecompact_unpack::unpack_pecompact",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::pecompact_unpack::unpack_pecompact(ctx.bytes)),
    },
    Entry {
        path: "packers::petite_phase2::unpack_petite_phase2_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::petite_phase2::unpack_petite_phase2_emulated(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "packers::petite_unpack::unpack_petite",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::petite_unpack::unpack_petite(ctx.bytes)),
    },
    Entry {
        path: "packers::petite_unpack::unpack_petite_with_report",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::petite_unpack::unpack_petite_with_report(ctx.bytes))
        },
    },
    Entry {
        path: "packers::polycryptor_unpack::polycryptor_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::polycryptor_unpack::polycryptor_layout(ctx.bytes))
        },
    },
    Entry {
        path: "packers::polycryptor_unpack::unpack_polycryptor",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::polycryptor_unpack::unpack_polycryptor(ctx.bytes))
        },
    },
    Entry {
        path: "packers::themida_carve::carve_themida",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::themida_carve::carve_themida(ctx.bytes)),
    },
    Entry {
        path: "packers::upx_decoder::unpack_upx",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::upx_decoder::unpack_upx(ctx.bytes)),
    },
    Entry {
        path: "packers::upx_go_chain::scan_go_runtime",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::upx_go_chain::scan_go_runtime(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::upx_go_chain::unpack_upx_go_chain",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::upx_go_chain::unpack_upx_go_chain(ctx.bytes)),
    },
    Entry {
        path: "packers::upx_go_chain::detect_upx_packed_go",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::upx_go_chain::detect_upx_packed_go(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::vmprotect_carve::carve_vmprotect",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::vmprotect_carve::carve_vmprotect(ctx.bytes)),
    },
    Entry {
        path: "packers::warzone_crypter_unpack::warzone_crypter_layout",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::warzone_crypter_unpack::warzone_crypter_layout(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "packers::warzone_crypter_unpack::unpack_warzone_crypter",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::warzone_crypter_unpack::unpack_warzone_crypter(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "packers::yodas_crypter::recover_yodas_crypter_carve",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::yodas_crypter::recover_yodas_crypter_carve(
                ctx.bytes,
            ))
        },
    },
    Entry {
        path: "pass::analyze_deobf_report",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = pass::analyze_deobf_report(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "pdb_cxx::reconstruct_pdb_cxx",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(pdb_cxx::reconstruct_pdb_cxx(ctx.bytes)),
    },
    Entry {
        path: "plt_resolve::resolve_elf_plt_imports",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(plt_resolve::resolve_elf_plt_imports(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "plt_resolve::resolve_pe_iat_imports",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(plt_resolve::resolve_pe_iat_imports(ctx.bytes).len(), ctx)
        },
    },
    Entry {
        path: "pseudo_c::recover_aarch64_program",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = pseudo_c::recover_aarch64_program(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "rust_recovery::parse_auditable_section",
        cheap: true,
        drive: |ctx: &Ctx<'_>| from_result(rust_recovery::parse_auditable_section(ctx.bytes)),
    },
    Entry {
        path: "sig_engine::detect_format",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let _ = sig_engine::detect_format(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "sig_engine::analyze",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = sig_engine::analyze(ctx.bytes);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "sig_engine::struct_findings",
        cheap: false,
        drive: |ctx: &Ctx<'_>| bounded_len(sig_engine::struct_findings(ctx.bytes).len(), ctx),
    },
    Entry {
        path: "similarity::extract_function_features",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(similarity::extract_function_features(ctx.bytes)),
    },
    Entry {
        path: "backend_export::rebuild_unpacked_pe",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(backend_export::rebuild_unpacked_pe(
                ctx.bytes,
                ctx.other,
                Some(0x1000),
            ))
        },
    },
    Entry {
        path: "backend_export::collect_recovered_symbols_with_oep",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(backend_export::collect_recovered_symbols_with_oep(
                ctx.bytes,
                Some(0x1000),
            ))
        },
    },
    Entry {
        path: "bindiff::diff",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(bindiff::diff(ctx.bytes, ctx.other)),
    },
    Entry {
        path: "debug_info::parse_stabs",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(debug_info::parse_stabs(ctx.bytes, ctx.other)),
    },
    Entry {
        path: "ebpf::recover_ebpf_program",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(ebpf::recover_ebpf_program(ctx.bytes, "main")),
    },
    Entry {
        path: "entropy::windowed_entropy",
        cheap: true,
        drive: |ctx: &Ctx<'_>| bounded_len(entropy::windowed_entropy(ctx.bytes, 256).len(), ctx),
    },
    Entry {
        path: "entropy::locate_high_entropy",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(entropy::locate_high_entropy(ctx.bytes, 256, 7.0).len(), ctx)
        },
    },
    Entry {
        path: "fingerprint::extract_ascii_xrefs",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(fingerprint::extract_ascii_xrefs(ctx.bytes, 4).len(), ctx)
        },
    },
    Entry {
        path: "packers::aspack_phase2::unpack_aspack_phase2_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::aspack_phase2::unpack_aspack_phase2_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::asprotect_unpack::unpack_asprotect_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::asprotect_unpack::unpack_asprotect_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::emulated_unpack::emulate_unpack_stub",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let Some(image): Option<PeImage> = parsed_pe(ctx) else {
                return Verdict::Unreached;
            };
            let config: packers::emulated_unpack::EmulationConfig<'_> =
                packers::emulated_unpack::EmulationConfig {
                    stub_section_names: &[b".text"],
                    content_exclude: &[],
                    step_cap: 200_000,
                };
            from_result(packers::emulated_unpack::emulate_unpack_stub(
                ctx.bytes, &image, 0x1000, None, &config,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_cca::decompress_kkrunchy_classic",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_cca::decompress_kkrunchy_classic(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_cca::locate_classic_stream",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let Ok(header) = packers::kkrunchy_unpack::parse_kkrunchy_header(ctx.bytes) else {
                return Verdict::Unreached;
            };
            from_result(packers::kkrunchy_cca::locate_classic_stream(
                ctx.bytes, &header,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_k7_cm::rangecoder_depack",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_k7_cm::rangecoder_depack(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::unpack_kkrunchy_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_unpack::unpack_kkrunchy_emulated(
                ctx.bytes, None,
            ))
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::compute_byte_recovery",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = packers::kkrunchy_unpack::compute_byte_recovery(ctx.bytes, ctx.other);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::kkrunchy_unpack::dis_filter",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(packers::kkrunchy_unpack::dis_filter(ctx.bytes, 0x1000)),
    },
    Entry {
        path: "packers::kkrunchy_unpack::dis_unfilter",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::kkrunchy_unpack::dis_unfilter(
                ctx.bytes,
                BOUNDED_OUTPUT,
                0x1000,
            ))
        },
    },
    Entry {
        path: "packers::mew_unpack::decode_compressed_payload",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::mew_unpack::decode_compressed_payload(
                ctx.bytes,
                0,
                ctx.bytes.len() as u32,
                BOUNDED_OUTPUT as u32,
            ))
        },
    },
    Entry {
        path: "packers::mew_unpack::aplib_decode_bytetagged",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::mew_unpack::aplib_decode_bytetagged(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::mew_unpack::aplib_decode_bytetagged_partial",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::mew_unpack::aplib_decode_bytetagged_partial(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::mew_unpack::aplib_decode_bytetagged_lossy",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let (out, _, error): (Vec<u8>, u64, Option<Error>) =
                packers::mew_unpack::aplib_decode_bytetagged_lossy(ctx.bytes, BOUNDED_OUTPUT);
            assert!(
                out.len() <= BOUNDED_OUTPUT,
                "{} decoded past its own cap",
                ctx.label
            );
            error.map_or(Verdict::Reached, |error: Error| {
                Verdict::Failed(error.to_string())
            })
        },
    },
    Entry {
        path: "packers::mew_unpack::aplib_decode_bytetagged_lossy_with",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let (out, _, error): (Vec<u8>, u64, Option<Error>) =
                packers::mew_unpack::aplib_decode_bytetagged_lossy_with(
                    ctx.bytes,
                    BOUNDED_OUTPUT,
                    packers::mew_unpack::AplibInitialState::default(),
                );
            assert!(
                out.len() <= BOUNDED_OUTPUT,
                "{} decoded past its own cap",
                ctx.label
            );
            error.map_or(Verdict::Reached, |error: Error| {
                Verdict::Failed(error.to_string())
            })
        },
    },
    Entry {
        path: "packers::morphine_unpack::unpack_morphine_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::morphine_unpack::unpack_morphine_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::mpress_lzma::decode_mpress_lzma",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::mpress_lzma::decode_mpress_lzma(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::neolite_unpack::unpack_neolite_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::neolite_unpack::unpack_neolite_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::npack_unpack::unpack_npack_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::npack_unpack::unpack_npack_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::nspack_unpack::unpack_nspack_emulated_with_baseline_raw",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(
                packers::nspack_unpack::unpack_nspack_emulated_with_baseline_raw(
                    ctx.bytes,
                    Some(ctx.other),
                ),
            )
        },
    },
    Entry {
        path: "packers::nspack_unpack::unpack_nspack_emulated_with_baseline",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(
                packers::nspack_unpack::unpack_nspack_emulated_with_baseline(
                    ctx.bytes,
                    Some(ctx.other),
                ),
            )
        },
    },
    Entry {
        path: "packers::overlay::route_overlay_archive",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::overlay::route_overlay_archive(
                ctx.bytes,
                ctx.scratch,
                disrobe_binfmt::ExtractionQuota::default_safe(),
            ))
        },
    },
    Entry {
        path: "packers::overlay_extent::archive_true_extent",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            for kind in [
                ArchiveKind::Zip,
                ArchiveKind::Cab,
                ArchiveKind::SevenZ,
                ArchiveKind::Rar,
                ArchiveKind::Gzip,
                ArchiveKind::Xz,
                ArchiveKind::Bzip2,
                ArchiveKind::Zstd,
                ArchiveKind::Tar,
            ] {
                if let Some(extent) = packers::overlay_extent::archive_true_extent(ctx.bytes, kind)
                {
                    assert!(
                        extent <= ctx.bytes.len(),
                        "{} reported an archive extent past the end of the window",
                        ctx.label
                    );
                }
            }
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::pe_resource::parse_resource_tree",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::pe_resource::parse_resource_tree(
                ctx.bytes,
                0,
                0x1000,
                ctx.bytes.len(),
            ))
        },
    },
    Entry {
        path: "packers::pe_sections::read_u16",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            for offset in [0usize, 1, ctx.bytes.len(), usize::MAX] {
                let _ = packers::pe_sections::read_u16(ctx.bytes, offset);
            }
            from_result(packers::pe_sections::read_u16(ctx.bytes, 0))
        },
    },
    Entry {
        path: "packers::pe_sections::read_u32",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            for offset in [0usize, 1, ctx.bytes.len(), usize::MAX] {
                let _ = packers::pe_sections::read_u32(ctx.bytes, offset);
            }
            from_result(packers::pe_sections::read_u32(ctx.bytes, 0))
        },
    },
    Entry {
        path: "packers::pe_sections::read_u64",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            for offset in [0usize, 1, ctx.bytes.len(), usize::MAX] {
                let _ = packers::pe_sections::read_u64(ctx.bytes, offset);
            }
            from_result(packers::pe_sections::read_u64(ctx.bytes, 0))
        },
    },
    Entry {
        path: "packers::pe_sections::find_subsequence",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            for needle in [b"MZ".as_slice(), b"".as_slice(), ctx.other] {
                if let Some(at) = packers::pe_sections::find_subsequence(ctx.bytes, needle) {
                    assert!(
                        at <= ctx.bytes.len(),
                        "{} reported a match past the end of the haystack",
                        ctx.label
                    );
                }
            }
            Verdict::NotFallible
        },
    },
    Entry {
        path: "packers::pe_resource::recover_resource_directory",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let Ok(tree) =
                packers::pe_resource::parse_resource_tree(ctx.bytes, 0, 0x1000, ctx.bytes.len())
            else {
                return Verdict::Unreached;
            };
            let mut image: Vec<u8> = ctx.other.to_vec();
            let resolve = |rva: u32| -> Option<usize> { usize::try_from(rva).ok() };
            from_result(packers::pe_resource::recover_resource_directory(
                ctx.bytes, &tree, 0x1000, 0x1000, 0x1000, &resolve, &mut image,
            ))
        },
    },
    Entry {
        path: "packers::pecompact_phase2::unpack_pecompact_phase2_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::pecompact_phase2::unpack_pecompact_phase2_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::polycryptor_unpack::unpack_polycryptor_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::polycryptor_unpack::unpack_polycryptor_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::recovered_image::recover_detected",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let detections: Vec<packers::Detection> = packers::detect(ctx.bytes);
            bounded_len(
                packers::recovered_image::recover_detected(ctx.bytes, &detections).len(),
                ctx,
            )
        },
    },
    Entry {
        path: "packers::section_recovery::build_loaded_image",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::section_recovery::build_loaded_image(
                ctx.bytes,
                BOUNDED_OUTPUT,
            ))
        },
    },
    Entry {
        path: "packers::section_recovery::section_recovery_report",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::section_recovery::section_recovery_report(
                ctx.bytes,
                ctx.other,
                &[b".text"],
            ))
        },
    },
    Entry {
        path: "packers::section_recovery::file_image_section_report",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::section_recovery::file_image_section_report(
                ctx.bytes,
                ctx.other,
                0x200,
                &[b".text"],
            ))
        },
    },
    Entry {
        path: "packers::warzone_crypter_unpack::unpack_warzone_crypter_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(
                packers::warzone_crypter_unpack::unpack_warzone_crypter_emulated(
                    ctx.bytes,
                    Some(ctx.other),
                ),
            )
        },
    },
    Entry {
        path: "packers::yodas_crypter::unpack_yodas_crypter",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::yodas_crypter::unpack_yodas_crypter(
                ctx.bytes, ctx.other,
            ))
        },
    },
    Entry {
        path: "packers::yodas_emulated_unpack::unpack_yodas_emulated",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::yodas_emulated_unpack::unpack_yodas_emulated(
                ctx.bytes,
                Some(ctx.other),
            ))
        },
    },
    Entry {
        path: "packers::yodas_protector::carve_yodas_protector",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(packers::yodas_protector::carve_yodas_protector(
                ctx.bytes, ctx.other,
            ))
        },
    },
    Entry {
        path: "packers::yodas_protector_phase2::unpack_yodas_protector_phase2",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(
                packers::yodas_protector_phase2::unpack_yodas_protector_phase2(
                    ctx.bytes,
                    Some(ctx.other),
                ),
            )
        },
    },
    Entry {
        path: "patch::apply_patches",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let edits: [PatchEdit; 2] = [
                PatchEdit::new(0x1000, vec![0x90, 0x90]),
                PatchEdit::new(u64::MAX - 1, vec![0xCC]),
            ];
            from_result(patch::apply_patches(ctx.bytes, &edits))
        },
    },
    Entry {
        path: "patch::apply_patches_reported",
        cheap: true,
        drive: |ctx: &Ctx<'_>| {
            let edits: [PatchEdit; 2] = [
                PatchEdit::new(0x1000, vec![0x90, 0x90]),
                PatchEdit::new(u64::MAX - 1, vec![0xCC]),
            ];
            from_result(patch::apply_patches_reported(ctx.bytes, &edits))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(pseudo_c::recover_leaf_function(ctx.bytes, 0x1000)),
    },
    Entry {
        path: "pseudo_c::recover_aarch64_function",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_result(pseudo_c::recover_aarch64_function(ctx.bytes, 0x1000)),
    },
    Entry {
        path: "pseudo_c::recover_aarch64_function_with_calls",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_aarch64_function_with_calls(
                ctx.bytes,
                0x1000,
                &[],
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_abi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            for abi in [Abi::MsX64, Abi::SysV, Abi::Aapcs64] {
                let _ = pseudo_c::recover_leaf_function_abi(ctx.bytes, 0x1000, abi);
            }
            from_result(pseudo_c::recover_leaf_function_abi(
                ctx.bytes,
                0x1000,
                Abi::MsX64,
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_const_abi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_const_abi(
                ctx.bytes,
                0x1000,
                Abi::SysV,
                &[],
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_with_calls",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_with_calls(
                ctx.bytes,
                0x1000,
                Abi::MsX64,
                &[],
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_vectorized_reduction",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_vectorized_reduction(
                ctx.bytes,
                0x1000,
                Abi::Aapcs64,
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_in_object",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_in_object(
                ctx.bytes,
                ctx.other,
                0x1000,
                Abi::MsX64,
                &[],
            ))
        },
    },
    Entry {
        path: "pseudo_c::callee_int_arity",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = pseudo_c::callee_int_arity(ctx.bytes, 0x1000, Abi::SysV);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "pseudo_c::resolved_int_arity_in_object",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let _ = pseudo_c::resolved_int_arity_in_object(ctx.bytes, ctx.other, 0x1000, Abi::SysV);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "pseudo_c::recover_program",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let functions: [pseudo_c::ProgramFunction; 1] = [pseudo_c::ProgramFunction {
                name: "probe".to_owned(),
                address: 0x1000,
                code: ctx.bytes.to_vec(),
            }];
            let recovered: pseudo_c::RecoveredProgram =
                pseudo_c::recover_program(ctx.bytes, &functions, Abi::MsX64);
            bounded_len(recovered.recovered.len() + recovered.unrecovered.len(), ctx)
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_rust_abi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_rust_abi(
                ctx.bytes,
                0x1000,
                Abi::SysV,
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_switch_abi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_switch_abi(
                ctx.bytes,
                0x1000,
                Abi::MsX64,
                &[],
            ))
        },
    },
    Entry {
        path: "pseudo_c::recover_leaf_function_switch_const_abi",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(pseudo_c::recover_leaf_function_switch_const_abi(
                ctx.bytes,
                0x1000,
                Abi::MsX64,
                &[],
                &[],
            ))
        },
    },
    Entry {
        path: "sigmaker::make_signature",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            from_result(sigmaker::make_signature(
                ctx.bytes,
                0x1000,
                SigmakerOptions::default(),
            ))
        },
    },
    Entry {
        path: "stream_disasm::scan_rip_relative_refs",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            bounded_len(
                stream_disasm::scan_rip_relative_refs(ctx.bytes, 0x1000, BOUNDED_OUTPUT).len(),
                ctx,
            )
        },
    },
    Entry {
        path: "vm_devirt::detect::detect_vm",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            for bitness in [Bitness::Bits32, Bitness::Bits64] {
                let _ = vm_devirt::detect::detect_vm(ctx.bytes, bitness);
            }
            Verdict::NotFallible
        },
    },
    Entry {
        path: "vm_devirt::detect::recover_structure",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let Some(detection) = vm_devirt::detect::detect_vm(ctx.bytes, Bitness::Bits64) else {
                return Verdict::Unreached;
            };
            let _ = vm_devirt::detect::recover_structure(ctx.bytes, Bitness::Bits64, &detection);
            Verdict::NotFallible
        },
    },
    Entry {
        path: "vm_devirt::detect::recover_structure_codescan_only",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            for bitness in [Bitness::Bits32, Bitness::Bits64] {
                let _ = vm_devirt::detect::recover_structure_codescan_only(ctx.bytes, bitness);
            }
            Verdict::NotFallible
        },
    },
    Entry {
        path: "vm_devirt::fingerprint::fingerprint_handlers",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let Some(structure) =
                vm_devirt::detect::recover_structure_codescan_only(ctx.bytes, Bitness::Bits64)
            else {
                return Verdict::Unreached;
            };
            from_foreign(vm_devirt::fingerprint::fingerprint_handlers(
                ctx.bytes,
                Bitness::Bits64,
                &structure,
            ))
        },
    },
    Entry {
        path: "vm_devirt::lift::lift_bytecode",
        cheap: false,
        drive: |ctx: &Ctx<'_>| {
            let Some(structure) =
                vm_devirt::detect::recover_structure_codescan_only(ctx.bytes, Bitness::Bits64)
            else {
                return Verdict::Unreached;
            };
            from_foreign(vm_devirt::lift::lift_bytecode(ctx.bytes, &structure, &[]))
        },
    },
    Entry {
        path: "vm_devirt::devirtualize",
        cheap: false,
        drive: |ctx: &Ctx<'_>| from_foreign(vm_devirt::devirtualize(ctx.bytes, Bitness::Bits64)),
    },
];

pub(crate) const PRECONDITION_GATED: &[(&str, &str)] = &[
    (
        "packers::kkrunchy_cca::locate_classic_stream",
        "packers/kkrunchy/hello.packed.kkrunchy_classic.exe",
    ),
    (
        "vm_devirt::detect::recover_structure",
        crate::hostile_inputs::COMPILED_VM_PROBE,
    ),
    (
        "vm_devirt::fingerprint::fingerprint_handlers",
        crate::hostile_inputs::COMPILED_VM_PROBE,
    ),
    (
        "vm_devirt::lift::lift_bytecode",
        crate::hostile_inputs::COMPILED_VM_PROBE,
    ),
];
