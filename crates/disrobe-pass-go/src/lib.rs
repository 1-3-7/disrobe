#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![allow(clippy::redundant_pub_crate)]
pub mod binary;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub(crate) mod debug;
pub mod dwarf;
pub mod embed_fs;
pub mod error;
pub mod format_wire;
pub mod garble;
mod garble_literals;
mod garble_thunk;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod moduledata;
pub mod pclntab;
pub mod provenance_header;
pub mod redress;
pub mod symbols;
pub mod types;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_enabled, dbg_hex, dbg_kv, dbg_line, dbg_section};

pub use binary::{Endian, GoImage, ImageKind, Section};
pub use dwarf::{DwarfFunction, DwarfReport, recover_dwarf};
pub use embed_fs::{EmbedFile, EmbedReport, extract_embed};
pub use error::{Error, Result};
pub use format_wire::format_go;
pub use garble::{
    GarbleQuality, GarbleReport, GarbleResidual, LiteralRecoveryStats, NameRecoveryStats,
    analyze as analyze_garble, probe_simple_literals, probe_thunk_literals,
};
#[cfg(feature = "llm-metadata")]
pub use llm::{GoLlmFn, GoLlmInput, METADATA_CAPABILITY as GO_METADATA_CAPABILITY};
pub use moduledata::{
    GoBuildInfo, GoModule, Moduledata, ModuledataSource, extract_build_info, extract_buildversion,
    extract_modulename, locate_moduledata,
};
pub use pclntab::{LocatedPclntab, PclntabHeader, PclntabVersion, locate_pclntab};
pub use provenance_header::{
    go_decompiled_header, go_extracted_header, render_go_decompiled_with_header,
};
pub use redress::{StrippedReport, analyze_stripped, synth_main_candidates};
pub use symbols::{GoFunc, GoSymbols, package_histogram, package_path, parse_symbols};
pub use types::{
    GoGenericInstantiation, GoInterfaceMethod, GoItab, GoItabSlot, GoMethod, GoStructField,
    GoTypeMeta, GoTypeRef, disambiguate_generics, extract_typemeta, harvest_concrete_args,
    link_method_functions, parse_generic_name, parse_generic_type_info, type_kind_label,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoAnalysis {
    pub image_kind: String,
    pub ptr_size: u8,
    pub pclntab_version: String,
    pub buildversion: Option<String>,
    pub symbols: GoSymbols,
    pub moduledata: Moduledata,
    pub typemeta: GoTypeMeta,
    pub stripped: StrippedReport,
    pub garble: GarbleReport,
    pub embed: EmbedReport,
    pub dwarf: DwarfReport,
}

pub fn analyze(bytes: &[u8]) -> Result<GoAnalysis> {
    dbg_section("go.analyze");
    dbg_kv("input_len", || bytes.len().to_string());
    if dbg_enabled() {
        dbg_hex("input_head", bytes, 32);
    }
    let image: GoImage<'_> = GoImage::parse(bytes)?;
    dbg_kv("image_kind", || image_kind_label(image.kind));
    dbg_kv("ptr_size", || image.ptr_size.to_string());
    dbg_kv("endian", || format!("{:?}", image.endian));
    dbg_kv("flat_image", || image.flat.to_string());
    dbg_kv("section_count", || image.sections.len().to_string());
    dbg_kv("symbol_addr_count", || image.symbol_addrs.len().to_string());
    if image.flat
        && let Some(base) = image.sections.first().map(|s: &Section<'_>| s.address)
    {
        dbg_kv("flat_base_inferred", || format!("{base:#x}"));
    }
    let located_result: Result<LocatedPclntab<'_>> = locate_pclntab(&image);
    let (pclntab_version, symbols, moduledata, typemeta): (
        String,
        GoSymbols,
        Moduledata,
        GoTypeMeta,
    ) = match located_result {
        Ok(located) => {
            dbg_kv("pclntab_version", || {
                located.header.version.label().to_owned()
            });
            dbg_kv("pclntab_va", || {
                format!("{:#x}", located.header.section_addr)
            });
            dbg_kv("pclntab_n_funcs", || located.header.n_funcs.to_string());
            let symbols: GoSymbols = parse_symbols(&image, &located)?;
            dbg_kv("func_count", || symbols.funcs.len().to_string());
            dbg_kv("func_start_line_count", || {
                symbols
                    .funcs
                    .iter()
                    .filter(|f: &&GoFunc| f.start_line.is_some())
                    .count()
                    .to_string()
            });
            dbg_kv("package_count", || symbols.package_set.len().to_string());
            dbg_kv("source_file_count", || {
                symbols.source_files.len().to_string()
            });
            if let (Some(first), Some(last)) = (symbols.funcs.first(), symbols.funcs.last()) {
                dbg_line(|| {
                    format!(
                        "func-boundaries: first={} @ {:#x} last={} @ {:#x}",
                        first.name, first.entry, last.name, last.entry
                    )
                });
            }
            let moduledata: Moduledata = locate_moduledata(&image, &located);
            dbg_kv("moduledata_via", || format!("{:?}", moduledata.via));
            dbg_kv("modulename", || format!("{:?}", moduledata.modulename));
            let mut typemeta: GoTypeMeta = extract_typemeta(&image, &moduledata);
            let func_vas: Vec<(u64, &str)> = symbols
                .funcs
                .iter()
                .map(|f: &GoFunc| (f.entry, f.name.as_str()))
                .collect();
            link_method_functions(&mut typemeta, &func_vas, moduledata.text_va);
            dbg_kv("typemeta_types", || typemeta.types.len().to_string());
            dbg_kv("typemeta_itabs", || typemeta.itabs.len().to_string());
            dbg_kv("typemeta_methods", || {
                typemeta
                    .types
                    .iter()
                    .map(|t: &GoTypeRef| t.methods.len())
                    .sum::<usize>()
                    .to_string()
            });
            dbg_kv("typemeta_imethods", || {
                typemeta
                    .types
                    .iter()
                    .map(|t: &GoTypeRef| t.imethods.len())
                    .sum::<usize>()
                    .to_string()
            });
            dbg_kv("typemeta_itab_slots", || {
                typemeta
                    .itabs
                    .iter()
                    .map(|i: &GoItab| i.fun.len())
                    .sum::<usize>()
                    .to_string()
            });
            let generics_pre: usize = typemeta.generics.len();
            merge_function_generics(&mut typemeta, &symbols);
            dbg_kv("generic_instantiations", || {
                format!(
                    "{} (typemeta={generics_pre} + function-derived={})",
                    typemeta.generics.len(),
                    typemeta.generics.len().saturating_sub(generics_pre)
                )
            });
            (
                located.header.version.label().to_owned(),
                symbols,
                moduledata,
                typemeta,
            )
        }
        Err(Error::PclntabMissing) => {
            dbg_line(|| "pclntab missing: falling back to empty symbols/moduledata".to_owned());
            let empty_syms: GoSymbols = GoSymbols {
                version_label: "unknown".to_owned(),
                ptr_size: image.ptr_size,
                funcs: Vec::new(),
                source_files: Vec::new(),
                package_set: Vec::new(),
            };
            let bi: Option<GoBuildInfo> = extract_build_info(&image);
            let empty_md: Moduledata = Moduledata {
                pclntab_va: 0,
                typelinks_va: 0,
                typelinks_len: 0,
                itablinks_va: 0,
                itablinks_len: 0,
                types_va: 0,
                etypes_va: 0,
                text_va: 0,
                etext_va: 0,
                modulename: extract_modulename(&image),
                buildversion: extract_buildversion(&image),
                build_info: bi,
                via: ModuledataSource::None,
            };
            let empty_tm: GoTypeMeta = GoTypeMeta {
                types: Vec::new(),
                itabs: Vec::new(),
                strings: Vec::new(),
                generics: Vec::new(),
            };
            ("pclntab-absent".to_owned(), empty_syms, empty_md, empty_tm)
        }
        Err(other) => return Err(other),
    };
    let buildversion: Option<String> = moduledata
        .build_info
        .as_ref()
        .and_then(|b: &GoBuildInfo| b.go_version.clone())
        .or_else(|| moduledata.buildversion.clone());
    dbg_kv("buildversion", || format!("{buildversion:?}"));
    let stripped: StrippedReport = analyze_stripped(&image, &symbols, buildversion.clone());
    dbg_kv("stripped", || stripped.stripped.to_string());
    let garble: GarbleReport = analyze_garble(&image, &symbols);
    dbg_kv("garble_quality", || format!("{:?}", garble.quality));
    dbg_kv("garble_detection_score", || {
        garble.detection_score.to_string()
    });
    dbg_kv("garble_seed_recoverable", || {
        garble.seed_recoverable.to_string()
    });
    dbg_kv("garble_residual", || format!("{:?}", garble.residual));
    let embed: EmbedReport = extract_embed(&image);
    dbg_kv("embed_files", || embed.files.len().to_string());
    let dwarf: DwarfReport = recover_dwarf(&image);
    dbg_kv("dwarf_present", || dwarf.present.to_string());
    dbg_kv("dwarf_functions", || dwarf.functions.len().to_string());
    Ok(GoAnalysis {
        image_kind: image_kind_label(image.kind),
        ptr_size: image.ptr_size,
        pclntab_version,
        buildversion,
        symbols,
        moduledata,
        typemeta,
        stripped,
        garble,
        embed,
        dwarf,
    })
}

fn image_kind_label(k: ImageKind) -> String {
    match k {
        ImageKind::Pe => "pe".to_owned(),
        ImageKind::Elf => "elf".to_owned(),
        ImageKind::MachO => "macho".to_owned(),
    }
}

fn merge_function_generics(typemeta: &mut GoTypeMeta, symbols: &GoSymbols) {
    use std::collections::BTreeSet;

    let func_names: Vec<&str> = symbols
        .funcs
        .iter()
        .map(|f: &GoFunc| f.name.as_str())
        .collect();
    let from_funcs: Vec<GoGenericInstantiation> =
        parse_generic_type_info(func_names.iter().copied(), std::iter::empty::<&str>());
    let mut combined: BTreeSet<GoGenericInstantiation> = typemeta.generics.drain(..).collect();
    combined.extend(from_funcs);
    let mut list: Vec<GoGenericInstantiation> = combined.into_iter().collect();

    let type_names: Vec<&str> = typemeta
        .types
        .iter()
        .filter_map(|t: &GoTypeRef| t.name.as_deref())
        .collect();
    disambiguate_generics(
        &mut list,
        func_names.iter().copied().chain(type_names.iter().copied()),
    );

    let deduped: BTreeSet<GoGenericInstantiation> = list.into_iter().collect();
    typemeta.generics = deduped.into_iter().collect();
}
