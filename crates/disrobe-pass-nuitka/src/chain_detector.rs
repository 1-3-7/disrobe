#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_PACKER_ARCHIVE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::decompile::{NuitkaDecompilation, decompile_bytes};
use crate::detect::{Detection, NuitkaFlavor, detect_in_bytes};
use crate::extract::VariantExtraction;
use crate::onefile::{OnefilePayload, extract_onefile};

pub const PASS_ID: PassId = "nuitka.extract";

const TAG_STANDALONE: &str = "nuitka-standalone";
const TAG_ONEFILE_UNCOMPRESSED: &str = "nuitka-onefile-uncompressed";
const TAG_ONEFILE_ZSTD: &str = "nuitka-onefile-zstd";
const TAG_WHEEL: &str = "nuitka-wheel";

#[derive(Debug)]
pub struct NuitkaDetector;

impl Detector for NuitkaDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let detection: Detection = detect_in_bytes(ctx.bytes).ok()?;
        if matches!(detection.flavor, NuitkaFlavor::Standalone) && !is_native_image(ctx.bytes) {
            return None;
        }
        Some(verdict_for(&detection))
    }
}

#[derive(Debug)]
pub struct NuitkaPass;

impl Pass for NuitkaPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &NuitkaDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let manifest: String = render_manifest_light(bytes);
        Ok(Artifact::new(
            Rung::Disasm,
            manifest.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let detection: Detection = detect_in_bytes(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-NUITKA-0904: nuitka detect: {e}"))
        })?;
        let Some(offset): Option<usize> = detection.onefile_payload_offset else {
            return decompile_children(bytes, None);
        };
        let mut children: Vec<ChildArtifact> = Vec::new();
        let mut main_module: Option<(String, Vec<u8>)> = None;
        let walk: Result<crate::onefile::StreamedPayload, crate::error::Error> =
            crate::onefile::extract_onefile_streaming(bytes, offset, &mut |entry| {
                if entry.symlink_target.is_some() {
                    return Ok(());
                }
                if main_module.is_none()
                    && is_main_module_name(&entry.filename)
                    && is_native_image(entry.data)
                    && entry.data.len() <= MAX_ONEFILE_MAIN_DECOMPILE_BYTES
                {
                    main_module = Some((entry.filename.clone(), entry.data.to_vec()));
                }
                let native: bool = is_native_extension(&entry.filename);
                let relative_path: String = if native {
                    format!("libs/{}", entry.filename)
                } else {
                    format!("data/{}", entry.filename)
                };
                let index: u32 = u32::try_from(children.len()).unwrap_or(u32::MAX);
                children.push(ChildArtifact {
                    handle: ChildHandle {
                        artifact_index: index,
                        relative_path,
                        hint: Some(TERMINAL_HINT.to_string()),
                    },
                    bytes: entry.data.to_vec(),
                });
                Ok(())
            });
        if walk.is_err() {
            return decompile_children(bytes, None);
        }

        if let Some((filename, data)) = main_module {
            let stem: &str = filename
                .strip_suffix(".dll")
                .or_else(|| filename.strip_suffix(".DLL"))
                .unwrap_or(&filename);
            for recovered in decompile_children(&data, Some(stem))? {
                let index: u32 = u32::try_from(children.len()).unwrap_or(u32::MAX);
                children.push(ChildArtifact {
                    handle: ChildHandle {
                        artifact_index: index,
                        relative_path: recovered.handle.relative_path,
                        hint: Some(TERMINAL_HINT.to_string()),
                    },
                    bytes: recovered.bytes,
                });
            }
        }
        Ok(children)
    }
}

const RUNTIME_DLL_PREFIXES: [&str; 6] = [
    "python",
    "vcruntime",
    "libcrypto",
    "libssl",
    "libffi",
    "api-ms",
];

const MAX_ONEFILE_MAIN_DECOMPILE_BYTES: usize = 1024 * 1024;

fn is_native_extension(filename: &str) -> bool {
    std::path::Path::new(filename)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .is_some_and(|ext: &str| {
            ext.eq_ignore_ascii_case("dll")
                || ext.eq_ignore_ascii_case("pyd")
                || ext.eq_ignore_ascii_case("so")
        })
}

fn is_main_module_name(filename: &str) -> bool {
    let lower: String = filename.to_ascii_lowercase();
    let is_dll: bool = std::path::Path::new(&lower)
        .extension()
        .is_some_and(|e: &std::ffi::OsStr| e.eq_ignore_ascii_case("dll"));
    if filename.contains('/') || filename.contains('\\') || !is_dll {
        return false;
    }
    !RUNTIME_DLL_PREFIXES
        .iter()
        .any(|p: &&str| lower.starts_with(p))
}

fn is_native_image(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some(
            [b'M', b'Z', _, _]
                | [0x7F, b'E', b'L', b'F']
                | [0xFE, 0xED, 0xFA, 0xCE | 0xCF]
                | [0xCE | 0xCF, 0xFA, 0xED, 0xFE]
                | [0xCA, 0xFE, 0xBA, 0xBE]
                | [0xBE, 0xBA, 0xFE, 0xCA]
        )
    )
}

fn decompile_children(bytes: &[u8], app_stem: Option<&str>) -> CoreResult<Vec<ChildArtifact>> {
    if !is_native_image(bytes) {
        return Ok(Vec::new());
    }
    let decompilation: NuitkaDecompilation =
        decompile_bytes(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-NUITKA-0906: nuitka decompile: {e}"))
        })?;
    let mut children: Vec<ChildArtifact> = Vec::new();

    if let Some(surface) = decompilation.surface.as_ref()
        && !surface.python_source.is_empty()
    {
        let name: String = sanitize_component(&surface.module_name);
        children.push(child(
            format!("{name}.surface.py"),
            surface.python_source.clone().into_bytes(),
        ));
    }

    if let Some(table) = decompilation.bytecode.as_ref() {
        for module in &table.modules {
            let name: String = sanitize_component(&module.module_name);
            if module.recovered_directly && !module.source.is_empty() {
                children.push(child(
                    format!("{name}.py"),
                    module.source.clone().into_bytes(),
                ));
            } else if !module.disassembly.is_empty() {
                children.push(child(
                    format!("{name}.dis.txt"),
                    module.disassembly.clone().into_bytes(),
                ));
            }
        }
    }

    if let Some(skeleton) = decompilation.skeleton.as_ref() {
        let names: Vec<String> = skeleton
            .modules
            .iter()
            .map(|m: &crate::skeleton::SkeletonModule| m.name.clone())
            .collect();
        let app_packages: Vec<String> = crate::origin::infer_app_packages(app_stem, &names);
        for module in &skeleton.modules {
            if module.python.is_empty() {
                continue;
            }
            let origin: crate::origin::ModuleOrigin = crate::origin::classify_with_filename(
                &module.name,
                module.filename.as_deref(),
                &app_packages,
            );
            let name: String = sanitize_component(&module.name);
            children.push(child(
                format!("skeleton/{}/{name}.py", origin.dir()),
                module.python.clone().into_bytes(),
            ));
        }
    }

    if let Some(frozen) = decompilation.frozen_modules.as_ref() {
        for module in &frozen.modules {
            let name: String = sanitize_component(&module.module_name);
            if module.recovered_directly && !module.source.is_empty() {
                children.push(child(
                    format!("frozen/{name}.py"),
                    module.source.clone().into_bytes(),
                ));
            } else if !module.disassembly.is_empty() {
                children.push(child(
                    format!("frozen/{name}.dis.txt"),
                    module.disassembly.clone().into_bytes(),
                ));
            }
        }
    }

    if let Some(disasm) = decompilation.native_disasm.as_ref()
        && !disasm.is_empty()
    {
        let module_name: String = disasm.module_name.clone();
        if let Some((_, asm)) = crate::native_disasm::disassemble_module_to_vec(&module_name, bytes)
            && !asm.is_empty()
        {
            let name: String = sanitize_component(&module_name);
            children.push(child(format!("native/{name}.asm"), asm));
        }
    }

    if let Some(name_map) = decompilation.name_map.as_ref()
        && !name_map.is_empty()
        && let Ok(json) = serde_json::to_vec_pretty(name_map)
    {
        children.push(child("native/name-map.json".to_string(), json));
    }

    if let Ok(manifest) = serde_json::to_vec_pretty(&recovery_manifest(&decompilation)) {
        children.push(child("recovery-manifest.json".to_string(), manifest));
    }

    let constants_json: Vec<u8> =
        serde_json::to_vec_pretty(&decompilation).map_err(|e: serde_json::Error| {
            CoreError::PassFailure(format!("DR-NUITKA-0907: serialize decompilation: {e}"))
        })?;
    children.push(child("nuitka-constants.json".to_string(), constants_json));

    Ok(children)
}

fn recovery_manifest(decompilation: &NuitkaDecompilation) -> serde_json::Value {
    let frozen: usize = decompilation
        .frozen_modules
        .as_ref()
        .map_or(0, |f: &crate::frozen::FrozenModules| f.modules.len());
    let skeleton: usize = decompilation
        .skeleton
        .as_ref()
        .map_or(0, |s: &crate::skeleton::NuitkaSkeleton| s.modules.len());
    let (instructions, functions): (u64, u64) = decompilation
        .native_disasm
        .as_ref()
        .map_or((0, 0), |d: &crate::native_disasm::NativeDisasm| {
            (d.instruction_count, d.function_count)
        });
    let identifiers: usize = decompilation
        .name_map
        .as_ref()
        .map_or(0, |m: &crate::name_map::NativeNameMap| m.entries.len());
    serde_json::json!({
        "schema": "disrobe.nuitka.recovery-manifest/v1",
        "outputs": {
            "frozen/": { "what": "REAL python source recovered from frozen bytecode", "count": frozen },
            "skeleton/app/, skeleton/libs/": { "what": "typed signatures of native-compiled modules, app/ vs bundled libs/", "count": skeleton },
            "native/": { "what": "x86 disassembly of the compiled image .text", "instructions": instructions, "functions": functions },
            "native/name-map.json": { "what": "recovered python identifiers correlated to referencing .text functions", "identifiers": identifiers },
            "libs/": { "what": "bundled DLL/.pyd extension modules carved as child artifacts for native follow-up passes" },
            "data/": { "what": "bundled non-code data files" }
        }
    })
}

fn child(relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: u32::MAX,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: &str = cleaned.trim_matches(['.', '/', '\\', ' ']);
    if trimmed.is_empty() {
        "module".to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub static NUITKA_PASS: NuitkaPass = NuitkaPass;

const MANIFEST_BANNER: &str = "nuitka.extract";
const MANIFEST_ENTRY_EXTRACT_CAP: usize = 64 * 1024 * 1024;

fn render_manifest_light(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(256);
    push_line(&mut out, MANIFEST_BANNER);
    let detection: Detection = match detect_in_bytes(bytes) {
        Ok(d) => d,
        Err(e) => {
            let line: String = format!("variant=not-extractable reason={e}");
            push_line(&mut out, &line);
            return out;
        }
    };
    if let Some(offset) = detection.onefile_payload_offset {
        let line: String = format!(
            "variant=onefile payload_offset={offset} image_size={}",
            bytes.len()
        );
        push_line(&mut out, &line);
        if bytes.len() <= MANIFEST_ENTRY_EXTRACT_CAP {
            append_onefile_entries(&mut out, bytes);
        } else {
            push_line(
                &mut out,
                "entries: (large payload; full carved list written to the extracted/ output)",
            );
        }
    } else {
        let line: String = format!("variant=standalone image_size={}", bytes.len());
        push_line(&mut out, &line);
    }
    out
}

#[allow(dead_code)]
fn render_manifest(bytes: &[u8], extraction: &VariantExtraction) -> String {
    let mut out: String = String::with_capacity(256);
    push_line(&mut out, MANIFEST_BANNER);
    match extraction {
        VariantExtraction::Onefile(onefile) => {
            let line: String = format!(
                "variant=onefile compressed={comp} payload_offset={off} payload_size={size} entries={n}",
                comp = onefile.compressed,
                off = onefile.payload_offset,
                size = onefile.payload_size,
                n = onefile.entry_count,
            );
            push_line(&mut out, &line);
            append_onefile_entries(&mut out, bytes);
        }
        VariantExtraction::Standalone(surface) => {
            let line: String = format!("variant=standalone image_size={}", surface.image_size);
            push_line(&mut out, &line);
            push_line(&mut out, &surface.note);
        }
        VariantExtraction::Module(surface) => {
            let line: String = format!("variant=module image_size={}", surface.image_size);
            push_line(&mut out, &line);
            push_line(&mut out, &surface.note);
        }
        VariantExtraction::SignedPe(signed) => {
            let line: String = format!("variant=signed-pe stripped_size={}", signed.stripped_size);
            push_line(&mut out, &line);
        }
        VariantExtraction::NotExtractable { reason } => {
            let line: String = format!("variant=not-extractable reason={reason}");
            push_line(&mut out, &line);
        }
    }
    out
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn append_onefile_entries(out: &mut String, bytes: &[u8]) {
    let detection: Detection = match detect_in_bytes(bytes) {
        Ok(d) => d,
        Err(_) => return,
    };
    let Some(offset): Option<usize> = detection.onefile_payload_offset else {
        return;
    };
    let payload: OnefilePayload = match extract_onefile(bytes, offset) {
        Ok(p) => p,
        Err(_) => return,
    };
    out.push_str("entries:\n");
    for entry in &payload.entries {
        let entry: &crate::onefile::OnefileEntry = entry;
        if let Some(target) = entry.symlink_target.as_deref() {
            let line: String = format!("  {name} -> {target}", name = entry.filename);
            push_line(out, &line);
        } else {
            let line: String = format!(
                "  {name} ({size} bytes)",
                name = entry.filename,
                size = entry.data.len(),
            );
            push_line(out, &line);
        }
    }
}

fn verdict_for(d: &Detection) -> DetectVerdict {
    let (tag, marker, confidence): (&'static str, &'static str, f32) = match d.flavor {
        NuitkaFlavor::Standalone => (
            TAG_STANDALONE,
            "nuitka_module_loader",
            standalone_confidence(d),
        ),
        NuitkaFlavor::OnefileUncompressed => (TAG_ONEFILE_UNCOMPRESSED, "KA-onefile", 0.95),
        NuitkaFlavor::OnefileZstd => (TAG_ONEFILE_ZSTD, "KA-onefile-zstd", 0.95),
        NuitkaFlavor::Wheel => (TAG_WHEEL, "dist-info-WHEEL", 0.88),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_PACKER_ARCHIVE,
        confidence,
        20,
        vec![marker],
        format!("nuitka flavor={tag} hits={n}", n = d.hits.len()),
    )
}

fn standalone_confidence(d: &Detection) -> f32 {
    let strong_markers: usize = d
        .hits
        .iter()
        .filter(|h: &&String| {
            matches!(
                h.as_str(),
                "__nuitka_version__"
                    | "nuitka_module_loader"
                    | "nuitka_distribution"
                    | "nuitka_resource_reader"
                    | "Nuitka_Err_NormalizeException"
            )
        })
        .count();
    if strong_markers >= 2 {
        0.97
    } else if strong_markers == 1 {
        0.93
    } else {
        0.85
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(NuitkaDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_standalone_signature() {
        let mut bytes: Vec<u8> = b"MZ\x90\x00".to_vec();
        bytes.extend_from_slice(b"nuitka_module_loader\x00nuitka_distribution\x00");
        bytes.extend_from_slice(b"__compiled__\x00suffix");
        let v: DetectVerdict = NuitkaDetector.detect(&ctx(&bytes)).expect("must detect");
        assert!(v.format_tag.starts_with("nuitka-"));
        assert_eq!(v.specificity, 20);
    }

    #[test]
    fn detect_refuses_non_native_standalone_markers() {
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        bytes.extend_from_slice(b"prefix\x00nuitka_module_loader\x00__compiled__\x00");
        assert!(
            NuitkaDetector.detect(&ctx(&bytes)).is_none(),
            "marker strings outside a native image (e.g. inside a recovered json) must not detect"
        );
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0u8; 64];
        assert!(NuitkaDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match NUITKA_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn pass_run_on_non_nuitka_bytes_reports_not_extractable() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let out: Artifact = NUITKA_PASS
            .run(&a)
            .expect("run produces a manifest, not an error");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 manifest");
        assert!(
            s.contains("not-extractable") || s.contains("variant="),
            "non-nuitka input must yield a manifest noting it is not extractable, got {s:?}"
        );
    }

    #[test]
    fn pass_run_emits_text_manifest_not_json() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join("onefile")
            .join("hello.exe");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
            eprintln!("SKIP: nuitka onefile fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out: Artifact = NUITKA_PASS.run(&a).expect("nuitka run must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 manifest");
        assert!(
            !s.trim_start().starts_with('{') && !s.contains("\"kind\""),
            "nuitka run must emit a readable manifest, not the extraction json; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(
            s.starts_with(MANIFEST_BANNER) && s.contains("variant=onefile"),
            "manifest must name the variant; got {:?}",
            s.chars().take(160).collect::<String>(),
        );
        assert!(
            s.contains("entries:") && s.contains("bytes)"),
            "onefile manifest must list the carved entries; got first 400: {:?}",
            s.chars().take(400).collect::<String>(),
        );
    }

    #[test]
    fn extract_children_surfaces_real_onefile_entries() {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join("onefile")
            .join("hello.exe");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
            eprintln!(
                "SKIP: nuitka onefile fixture missing at {}",
                fixture.display()
            );
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = NUITKA_PASS
            .extract_children(&a)
            .expect("onefile children extraction must succeed");
        assert!(
            !children.is_empty(),
            "nuitka onefile must surface at least one embedded file as a real child"
        );
        let any_pe: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.bytes.starts_with(b"MZ"));
        assert!(
            any_pe,
            "at least one extracted child must be real recovered PE bytes (MZ header)"
        );
    }

    fn real_standalone_fixture() -> Option<Vec<u8>> {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join("real")
            .join("sample_app-standalone.exe");
        std::fs::read(&fixture).ok()
    }

    #[test]
    fn auto_chain_emits_frozen_real_source_and_skeleton() {
        let Some(bytes): Option<Vec<u8>> = real_standalone_fixture() else {
            eprintln!("SKIP: real standalone fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = NUITKA_PASS
            .extract_children(&a)
            .expect("standalone decompile must succeed");
        let frozen: Vec<&ChildArtifact> = children
            .iter()
            .filter(|c: &&ChildArtifact| c.handle.relative_path.starts_with("frozen/"))
            .collect();
        assert!(
            frozen.len() >= 50,
            "auto chain must emit many frozen real-source modules, got {}",
            frozen.len()
        );
        let future: &ChildArtifact = frozen
            .iter()
            .find(|c: &&&ChildArtifact| c.handle.relative_path.ends_with("__future__.py"))
            .copied()
            .expect("__future__.py frozen source must be emitted");
        let source: &str = std::str::from_utf8(&future.bytes).expect("utf8 source");
        assert!(
            source.contains("all_feature_names"),
            "frozen __future__ child must carry real recovered source"
        );
        assert!(
            children
                .iter()
                .any(|c: &ChildArtifact| c.handle.relative_path.starts_with("skeleton/")),
            "auto chain must emit typed skeletons"
        );
    }

    fn compiled_module_fixture() -> Option<Vec<u8>> {
        let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("nuitka")
            .join("module")
            .join("hello.cp314-win_amd64.pyd");
        std::fs::read(&fixture).ok()
    }

    #[test]
    fn extract_children_decompiles_compiled_module_to_constants_child() {
        let Some(bytes): Option<Vec<u8>> = compiled_module_fixture() else {
            eprintln!("SKIP: compiled nuitka module fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = NUITKA_PASS
            .extract_children(&a)
            .expect("compiled module decompile must succeed");
        let constants: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with("nuitka-constants.json"))
            .expect("a compiled module must surface a nuitka-constants.json child");
        let json: &str =
            std::str::from_utf8(&constants.bytes).expect("constants child must be utf8 json");
        assert!(
            json.contains("\"embedded-standalone\""),
            "constants child must carry the embedded-standalone decompilation"
        );
        assert!(
            json.contains("hello, ") && json.contains("greet"),
            "constants child must carry the real recovered user literals from the data-composer blob"
        );
    }

    #[test]
    fn recovered_constants_child_does_not_re_detect_as_nuitka() {
        let Some(bytes): Option<Vec<u8>> = compiled_module_fixture() else {
            eprintln!("SKIP: compiled nuitka module fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = NUITKA_PASS
            .extract_children(&a)
            .expect("compiled module decompile must succeed");
        let constants: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with("nuitka-constants.json"))
            .expect("a constants child");
        assert!(
            NuitkaDetector.detect(&ctx(&constants.bytes)).is_none(),
            "the recovered constants json carries marker strings but is not a native image; \
             the detector must refuse it so the chain does not recurse"
        );
    }

    #[test]
    fn standalone_confidence_beats_native_packer_high() {
        let Some(bytes): Option<Vec<u8>> = compiled_module_fixture() else {
            eprintln!("SKIP: compiled nuitka module fixture missing");
            return;
        };
        let v: DetectVerdict = NuitkaDetector
            .detect(&ctx(&bytes))
            .expect("compiled module must detect as nuitka");
        assert!(
            v.confidence > 0.96,
            "a strongly-marked nuitka standalone must outrank a native-packer High (0.96) pick; got {}",
            v.confidence
        );
    }
}
