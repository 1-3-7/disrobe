pub mod descriptors;
pub mod disasm;
pub mod grade;
pub mod koistream;
pub mod lift;
pub mod opcodes;
pub mod random;
pub mod stub;

use serde::{Deserialize, Serialize};

use crate::cil::parse_method_body;
use crate::metadata::{MetadataRoot, StreamHeader, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

use descriptors::KoiDescriptors;
use disasm::{KoiMethodDisasm, disassemble_method};
use koistream::{KoiSig, KoiStream, parse_koistream};
use lift::{LiftedMethod, lift_method};
use stub::{VmStub, find_vm_stubs};

pub const DEFAULT_KOIVM_SEED: i32 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KoiVmDetection {
    pub koi_stream_present: bool,
    pub koi_stream_size: u32,
    pub vm_entry_runtime: Option<String>,
    pub virtualized_method_count: u32,
    pub watermark_offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct KoiVmMethod {
    pub export_id: u32,
    pub metadata_token: u32,
    pub method_name: String,
    pub entry_offset: u32,
    pub disasm: KoiMethodDisasm,
    pub lifted: LiftedMethod,
}

#[derive(Debug, Clone)]
pub struct KoiVmRecovery {
    pub detection: KoiVmDetection,
    pub seed: i32,
    pub methods: Vec<KoiVmMethod>,
    pub undecoded_ids: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KoiVmError {
    NotKoiVm,
    NoKoiStream,
    BadKoiStream,
}

#[must_use]
pub fn detect(image: &[u8]) -> KoiVmDetection {
    let parsed: Option<(PeImage, ClrHeader, MetadataRoot)> = parse_image(image);
    let Some((pe, clr, root)) = parsed else {
        return KoiVmDetection {
            koi_stream_present: false,
            koi_stream_size: 0,
            vm_entry_runtime: None,
            virtualized_method_count: 0,
            watermark_offset: None,
        };
    };
    let koi_header: Option<&StreamHeader> = root.streams.get("#Koi");
    let (present, size): (bool, u32) =
        koi_header.map_or((false, 0), |h: &StreamHeader| (true, h.size));
    let stubs: Vec<VmStub> = find_vm_stubs(image, &pe, &clr, &root).unwrap_or_default();
    let runtime: Option<String> = scan_runtime_marker(image);
    let watermark: Option<u32> = find_koi_marker(image);
    KoiVmDetection {
        koi_stream_present: present,
        koi_stream_size: size,
        vm_entry_runtime: runtime,
        virtualized_method_count: u32::try_from(stubs.len()).unwrap_or(u32::MAX),
        watermark_offset: watermark,
    }
}

pub fn devirtualize(image: &[u8]) -> Result<KoiVmRecovery, KoiVmError> {
    devirtualize_with_seed(image, DEFAULT_KOIVM_SEED)
}

pub fn devirtualize_with_seed(image: &[u8], seed: i32) -> Result<KoiVmRecovery, KoiVmError> {
    let (pe, clr, root): (PeImage, ClrHeader, MetadataRoot) =
        parse_image(image).ok_or(KoiVmError::NotKoiVm)?;
    let koi_header: &StreamHeader = root.streams.get("#Koi").ok_or(KoiVmError::NoKoiStream)?;
    let koi_bytes: Vec<u8> =
        read_stream(image, &pe, &clr, *koi_header).ok_or(KoiVmError::NoKoiStream)?;
    let stream: KoiStream = parse_koistream(&koi_bytes).map_err(|_| KoiVmError::BadKoiStream)?;

    let descriptors: KoiDescriptors = KoiDescriptors::from_seed(seed);
    let stubs: Vec<VmStub> = find_vm_stubs(image, &pe, &clr, &root).unwrap_or_default();

    let detection: KoiVmDetection = detect(image);

    let mut methods: Vec<KoiVmMethod> = Vec::new();
    let mut undecoded_ids: Vec<u32> = Vec::new();

    for stub in &stubs {
        let Some(sig): Option<&KoiSig> = stream.sig_by_id(stub.export_id) else {
            undecoded_ids.push(stub.export_id);
            continue;
        };
        if !sig.is_export {
            undecoded_ids.push(stub.export_id);
            continue;
        }
        match disassemble_method(&stream.raw, sig.entry_offset, sig.entry_key, &descriptors) {
            Ok(disasm) => {
                let lifted: LiftedMethod =
                    lift_method(&disasm, stub.param_count, &descriptors, &stream);
                methods.push(KoiVmMethod {
                    export_id: stub.export_id,
                    metadata_token: stub.metadata_token,
                    method_name: stub.method_name.clone(),
                    entry_offset: sig.entry_offset,
                    disasm,
                    lifted,
                });
            }
            Err(_) => undecoded_ids.push(stub.export_id),
        }
    }

    methods.sort_by_key(|m: &KoiVmMethod| m.export_id);
    undecoded_ids.sort_unstable();

    Ok(KoiVmRecovery {
        detection,
        seed,
        methods,
        undecoded_ids,
    })
}

fn parse_image(image: &[u8]) -> Option<(PeImage, ClrHeader, MetadataRoot)> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    Some((pe, clr, root))
}

fn read_stream(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    header: StreamHeader,
) -> Option<Vec<u8>> {
    let metadata: &[u8] = pe
        .slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
        .ok()?;
    let start: usize = header.offset as usize;
    let end: usize = start.checked_add(header.size as usize)?;
    metadata.get(start..end).map(<[u8]>::to_vec)
}

fn scan_runtime_marker(image: &[u8]) -> Option<String> {
    const MARKERS: [&[u8]; 3] = [b"VMEntry", b"VMDispatcher", b"KoiVM"];
    for marker in MARKERS {
        if window_find(image, marker).is_some() {
            return Some(String::from_utf8_lossy(marker).into_owned());
        }
    }
    None
}

fn find_koi_marker(image: &[u8]) -> Option<u32> {
    window_find(image, b"#Koi").map(|p: usize| u32::try_from(p).unwrap_or(u32::MAX))
}

fn window_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[must_use]
pub fn parse_method_body_at(
    image: &[u8],
    pe: &PeImage,
    rva: u32,
) -> Option<crate::cil::MethodBody> {
    let off: usize = pe.rva_to_offset(rva)?;
    parse_method_body(image.get(off..)?).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn virtualized_exe() -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koivm.exe");
        std::fs::read(path).unwrap()
    }

    fn clean_exe() -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.clean.exe");
        std::fs::read(path).unwrap()
    }

    #[test]
    fn detects_koivm_in_real_sample() {
        let image: Vec<u8> = virtualized_exe();
        let d: KoiVmDetection = detect(&image);
        assert!(
            d.koi_stream_present,
            "real KoiVM sample must carry a #Koi stream"
        );
        assert!(d.koi_stream_size > 0);
        assert_eq!(
            d.virtualized_method_count, 6,
            "six methods were virtualized; detection found {}",
            d.virtualized_method_count
        );
    }

    #[test]
    fn clean_exe_is_not_detected_as_koivm() {
        let image: Vec<u8> = clean_exe();
        let d: KoiVmDetection = detect(&image);
        assert!(
            !d.koi_stream_present,
            "the unobfuscated baseline must not carry a #Koi stream"
        );
        assert_eq!(d.virtualized_method_count, 0);
    }

    #[test]
    fn devirtualizes_all_six_methods() {
        let image: Vec<u8> = virtualized_exe();
        let recovery: KoiVmRecovery = devirtualize(&image).expect("devirtualize real sample");
        assert_eq!(
            recovery.methods.len(),
            6,
            "all six virtualized methods must be recovered; undecoded={:?}",
            recovery.undecoded_ids
        );
        assert!(recovery.undecoded_ids.is_empty());
        for m in &recovery.methods {
            assert!(
                !m.lifted.ops.is_empty(),
                "method {} (id {}) lifted to no ops",
                m.method_name,
                m.export_id
            );
        }
    }

    #[test]
    fn recovered_method_names_match_originals() {
        let image: Vec<u8> = virtualized_exe();
        let recovery: KoiVmRecovery = devirtualize(&image).expect("devirtualize");
        let names: Vec<String> = recovery
            .methods
            .iter()
            .map(|m: &KoiVmMethod| m.method_name.clone())
            .collect();
        for expected in ["Add", "Square", "SumTo", "Classify", "Factorial", "Max3"] {
            assert!(
                names.iter().any(|n: &String| n == expected),
                "expected recovered method {expected}; got {names:?}"
            );
        }
    }
}
