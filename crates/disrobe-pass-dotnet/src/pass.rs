use serde::{Deserialize, Serialize};

use crate::aot::{AotReport, detect as detect_aot};
use crate::cil;
use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::metadata::{MetadataRoot, RuntimeLabel, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::{ConfuserConstantsRecovery, peel_confuserex_constants};
use crate::protectors::{DetectionReport, Protector, detect_all};
use crate::r2r::{R2rReport, detect as detect_r2r};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassSummary {
    pub pe_bitness: String,
    pub machine: u16,
    pub clr_runtime_version: String,
    pub runtime_label: RuntimeLabel,
    pub stream_names: Vec<String>,
    pub r2r_present: bool,
    pub native_aot: bool,
    pub primary_protector: Option<Protector>,
    pub protectors_detected: Vec<Protector>,
    pub opcode_table_size: u32,
    pub opcode_spec_coverage_pct: u32,
    pub recovered_constants: Vec<String>,
    pub koivm: Option<KoiVmSummary>,
    pub eazvm: Option<EazVmSummary>,
    pub control_flow_flattening: Option<crate::peel::deflatten::DeflattenSummary>,
    pub inlined_literals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KoiVmSummary {
    pub koi_stream_present: bool,
    pub koi_stream_size: u32,
    pub virtualized_methods: u32,
    pub devirtualized_methods: u32,
    pub undecoded_export_ids: Vec<u32>,
    pub recovered_method_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EazVmSummary {
    pub embedded_resource_present: bool,
    pub dispatch_table_present: bool,
    pub identified_opcodes: u32,
    pub virtualized_methods: u32,
    pub devirtualized_methods: u32,
    pub undecoded_methods: Vec<String>,
    pub recovered_method_names: Vec<String>,
}

pub fn analyze(image: &[u8]) -> crate::error::Result<PassSummary> {
    dbg_section("dotnet.analyze");
    dbg_kv("input_len", || image.len().to_string());
    let pe: PeImage = parse(image)?;
    dbg_kv("pe", || {
        format!(
            "bitness={:?} machine=0x{:04x} sections={}",
            pe.bitness,
            pe.machine,
            pe.sections.len()
        )
    });
    let clr: ClrHeader = match parse_clr_header(image, &pe) {
        Ok(header) => header,
        Err(managed_error) => {
            let aot: AotReport = detect_aot(image);
            if !aot.is_native_aot {
                return Err(managed_error);
            }
            dbg_kv("native_aot_only", || {
                aot.ready_to_run.as_ref().map_or_else(
                    || "no ready-to-run header".to_owned(),
                    |header: &crate::aot::ReadyToRunHeader| {
                        format!(
                            "ready-to-run {}.{} with {} section(s)",
                            header.major_version,
                            header.minor_version,
                            header.sections.len()
                        )
                    },
                )
            });
            return Ok(native_aot_summary(&pe, &aot));
        }
    };
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let runtime: RuntimeLabel = root.runtime_label();
    dbg_kv("runtime", || {
        format!("{runtime:?} version={} streams={:?}", root.version, {
            let names: Vec<&String> = root.streams.keys().collect();
            names
        })
    });
    let r2r: R2rReport = detect_r2r(image, &pe, &clr);
    let aot: AotReport = detect_aot(image);
    dbg_kv("native_layers", || {
        format!("r2r={} native_aot={}", r2r.present, aot.is_native_aot)
    });
    let mut detection: DetectionReport = detect_all(image);
    dbg_kv("primary_protector", || format!("{:?}", detection.primary));
    let stream_names: Vec<String> = root.streams.keys().cloned().collect();
    let koivm: Option<KoiVmSummary> = analyze_koivm(image, &mut detection);
    dbg_kv("koivm_recovered", || {
        koivm.as_ref().map_or_else(
            || "no".to_string(),
            |k: &KoiVmSummary| {
                format!(
                    "yes virtualized={} devirtualized={} undecoded={}",
                    k.virtualized_methods,
                    k.devirtualized_methods,
                    k.undecoded_export_ids.len()
                )
            },
        )
    });
    let eazvm: Option<EazVmSummary> = analyze_eazvm(image, &mut detection);
    dbg_kv("eazvm_recovered", || {
        eazvm.as_ref().map_or_else(
            || "no".to_string(),
            |e: &EazVmSummary| {
                format!(
                    "yes opcodes={} virtualized={} devirtualized={} undecoded={}",
                    e.identified_opcodes,
                    e.virtualized_methods,
                    e.devirtualized_methods,
                    e.undecoded_methods.len()
                )
            },
        )
    });
    let mut protectors: Vec<Protector> = detection.matches.keys().copied().collect();
    protectors.sort();
    dbg_kv("protectors_detected", || protectors.len().to_string());
    let recovered_constants: Vec<String> = peel_confuserex_constants(image)
        .ok()
        .flatten()
        .map(|r: ConfuserConstantsRecovery| {
            r.strings_recovered
                .into_iter()
                .map(|s: crate::peel::RecoveredString| s.text)
                .collect()
        })
        .unwrap_or_default();
    dbg_kv("recovered_constants", || {
        recovered_constants.len().to_string()
    });
    let control_flow_flattening: Option<crate::peel::deflatten::DeflattenSummary> =
        crate::peel::deflatten::analyze(image);
    dbg_kv("control_flow_flattening", || {
        control_flow_flattening.as_ref().map_or_else(
            || "none".to_string(),
            |d: &crate::peel::deflatten::DeflattenSummary| {
                format!(
                    "flattened={} deflattened={}",
                    d.flattened_methods, d.deflattened_methods
                )
            },
        )
    });
    let inlined_literals: Vec<String> = crate::peel::deflatten::decrypt::inline_decryptors(image)
        .map(|r: crate::peel::deflatten::decrypt::DecryptInlineReport| {
            r.call_sites
                .into_iter()
                .filter_map(
                    |c: crate::peel::deflatten::decrypt::CallSite| match c.literal {
                        crate::peel::deflatten::decrypt::InlinedLiteral::Text(s) => Some(s),
                        _ => None,
                    },
                )
                .collect()
        })
        .unwrap_or_default();
    dbg_line(|| {
        format!(
            "analyze done: opcodes={} spec_coverage={}% inlined_literals={}",
            cil::total_opcode_count(),
            cil::coverage_percent(),
            inlined_literals.len()
        )
    });
    Ok(PassSummary {
        pe_bitness: format!("{:?}", pe.bitness),
        machine: pe.machine,
        clr_runtime_version: root.version,
        runtime_label: runtime,
        stream_names,
        r2r_present: r2r.present,
        native_aot: aot.is_native_aot,
        primary_protector: detection.primary,
        protectors_detected: protectors,
        opcode_table_size: u32::try_from(cil::total_opcode_count()).unwrap_or(u32::MAX),
        opcode_spec_coverage_pct: cil::coverage_percent(),
        recovered_constants,
        koivm,
        eazvm,
        control_flow_flattening,
        inlined_literals,
    })
}

fn native_aot_summary(pe: &PeImage, aot: &AotReport) -> PassSummary {
    PassSummary {
        pe_bitness: format!("{:?}", pe.bitness),
        machine: pe.machine,
        clr_runtime_version: String::new(),
        runtime_label: RuntimeLabel::Unknown,
        stream_names: Vec::new(),
        r2r_present: false,
        native_aot: aot.is_native_aot,
        primary_protector: None,
        protectors_detected: Vec::new(),
        opcode_table_size: 0,
        opcode_spec_coverage_pct: 0,
        recovered_constants: Vec::new(),
        koivm: None,
        eazvm: None,
        control_flow_flattening: None,
        inlined_literals: Vec::new(),
    }
}

fn analyze_koivm(image: &[u8], detection: &mut DetectionReport) -> Option<KoiVmSummary> {
    use crate::peel::koivm::{KoiVmDetection, KoiVmMethod, KoiVmRecovery, detect, devirtualize};

    let probe: KoiVmDetection = detect(image);
    if !probe.koi_stream_present {
        return None;
    }

    detection
        .matches
        .entry(Protector::KoiVm)
        .or_insert_with(|| {
            probe
                .watermark_offset
                .map(|o: u32| vec![o])
                .unwrap_or_default()
        });
    if detection.primary.is_none() {
        detection.primary = Some(Protector::KoiVm);
    }

    let recovery: KoiVmRecovery = devirtualize(image).ok()?;
    let recovered_method_names: Vec<String> = recovery
        .methods
        .iter()
        .map(|m: &KoiVmMethod| m.method_name.clone())
        .collect();
    Some(KoiVmSummary {
        koi_stream_present: true,
        koi_stream_size: probe.koi_stream_size,
        virtualized_methods: probe.virtualized_method_count,
        devirtualized_methods: u32::try_from(recovery.methods.len()).unwrap_or(u32::MAX),
        undecoded_export_ids: recovery.undecoded_ids,
        recovered_method_names,
    })
}

fn analyze_eazvm(image: &[u8], detection: &mut DetectionReport) -> Option<EazVmSummary> {
    use crate::peel::eazvm::{EazVmMethod, EazVmRecovery, detect, devirtualize};

    let probe: crate::peel::eazvm::EazVmDetection = detect(image);
    if !probe.dispatch_table_present || probe.stub_count == 0 {
        return None;
    }

    let recovery: EazVmRecovery = devirtualize(image).ok()?;
    if recovery.methods.is_empty() {
        return None;
    }

    detection
        .matches
        .entry(Protector::EazfuscatorNet)
        .or_default();
    if detection.primary.is_none() {
        detection.primary = Some(Protector::EazfuscatorNet);
    }

    let recovered_method_names: Vec<String> = recovery
        .methods
        .iter()
        .map(|m: &EazVmMethod| m.name.clone())
        .collect();
    Some(EazVmSummary {
        embedded_resource_present: recovery.detection.embedded_resource_present,
        dispatch_table_present: recovery.detection.dispatch_table_present,
        identified_opcodes: recovery.detection.identified_opcodes,
        virtualized_methods: probe.stub_count,
        devirtualized_methods: u32::try_from(recovery.methods.len()).unwrap_or(u32::MAX),
        undecoded_methods: recovery.undecoded,
        recovered_method_names,
    })
}
