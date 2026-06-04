#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]

pub mod binary;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod dwarf;
pub mod embed_fs;
pub mod error;
pub mod format_wire;
pub mod garble;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod moduledata;
pub mod pass;
pub mod pclntab;
pub mod provenance_header;
pub mod redress;
pub mod symbols;
pub mod types;

use serde::{Deserialize, Serialize};

pub use binary::{Endian, GoImage, ImageKind, Section};
pub use dwarf::{DwarfFunction, DwarfReport, recover_dwarf};
pub use embed_fs::{EmbedFile, EmbedReport, extract_embed};
pub use error::{Error, Result};
pub use format_wire::format_go;
pub use garble::{GarbleQuality, GarbleReport, analyze as analyze_garble};
#[cfg(feature = "llm-metadata")]
pub use llm::{GoLlmFn, GoLlmInput, METADATA_CAPABILITY as GO_METADATA_CAPABILITY};
pub use moduledata::{Moduledata, ModuledataSource, extract_buildversion, locate_moduledata};
pub use pass::{GoPass, GoPassReport, PASS_INPUT_PATH_CAP, PassInput, decode_pass_input};
pub use pclntab::{LocatedPclntab, PclntabHeader, PclntabVersion, locate_pclntab};
pub use provenance_header::{
    go_decompiled_header, go_extracted_header, render_go_decompiled_with_header,
};
pub use redress::{StrippedReport, analyze_stripped, synth_main_candidates};
pub use symbols::{GoFunc, GoSymbols, package_histogram, parse_symbols};
pub use types::{
    GoGenericInstantiation, GoItab, GoTypeMeta, GoTypeRef, extract_typemeta, parse_generic_name,
    parse_generic_type_info, type_kind_label,
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
    let image: GoImage<'_> = GoImage::parse(bytes)?;
    let located_result: Result<LocatedPclntab<'_>> = locate_pclntab(&image);
    let (pclntab_version, symbols, moduledata, typemeta): (
        String,
        GoSymbols,
        Moduledata,
        GoTypeMeta,
    ) = match located_result {
        Ok(located) => {
            let symbols: GoSymbols = parse_symbols(&image, &located)?;
            let moduledata: Moduledata = locate_moduledata(&image, &located);
            let mut typemeta: GoTypeMeta = extract_typemeta(&image, &moduledata);
            merge_function_generics(&mut typemeta, &symbols);
            (
                located.header.version.label().to_owned(),
                symbols,
                moduledata,
                typemeta,
            )
        }
        Err(Error::PclntabMissing) => {
            let empty_syms: GoSymbols = GoSymbols {
                version_label: "unknown".to_owned(),
                ptr_size: image.ptr_size,
                funcs: Vec::new(),
                source_files: Vec::new(),
                package_set: Vec::new(),
            };
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
                modulename: None,
                buildversion: extract_buildversion(&image),
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
    let buildversion: Option<String> = moduledata.buildversion.clone();
    let stripped: StrippedReport = analyze_stripped(&image, &symbols, buildversion.clone());
    let garble: GarbleReport = analyze_garble(&image, &symbols);
    let embed: EmbedReport = extract_embed(&image);
    let dwarf: DwarfReport = recover_dwarf(&image);
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

/// Fold generic instantiations recovered from the pclntab funcname table into the
/// typemeta's `generics`, deduping against the type-derived ones already present.
fn merge_function_generics(typemeta: &mut GoTypeMeta, symbols: &GoSymbols) {
    use std::collections::BTreeSet;

    let func_names = symbols.funcs.iter().map(|f| f.name.as_str());
    let from_funcs: Vec<GoGenericInstantiation> =
        parse_generic_type_info(func_names, std::iter::empty::<&str>());
    let mut combined: BTreeSet<GoGenericInstantiation> = typemeta.generics.drain(..).collect();
    combined.extend(from_funcs);
    typemeta.generics = combined.into_iter().collect();
}
