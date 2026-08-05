#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, FAMILY_INTERPRETER_BYTECODE,
    FAMILY_SOURCE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use serde::Serialize;

use crate::error::Result as ScriptResult;
use crate::lang::haxe::{HaxeFingerprint, HaxeTarget};
use crate::lang::perl_decompile::DecompileWalker;
use crate::lang::r_rds::{RdsContainer, RdsEncoding, RdsObject};
use crate::lang::rcpp::RcppFingerprint;
use crate::lang::tcl::{StarkitContainer, StarkitEntry};
use crate::lang::winscript::WinScriptRecovery;
use crate::lang::{ScriptArtifact, ScriptLang, analyze, analyze_r, analyze_rcpp, classify};

pub const PASS_ID: PassId = "scriptlang.classify";

const TAG_PERL: &str = "perl-concise";
const TAG_R: &str = "r-rds";
const TAG_TCL: &str = "tcl-starkit";
const TAG_HAXE_JS: &str = "haxe-js";
const TAG_HAXE_SWF: &str = "haxe-swf";
const TAG_HAXE_HL: &str = "haxe-hl";
const TAG_HAXE_NEKO: &str = "haxe-neko";
const TAG_WIN_SCRIPT: &str = "win-script";

const SCRIPT_REPORT_TAG: &str = "scriptlang-report";
const TCL_BANNER: &str = "# tcl starkit container";
const R_BANNER: &str = "# r rds object";
const HAXE_BANNER: &str = "// haxe cross-target output";
const WIN_SCRIPT_BANNER: &str = "# recovered windows script";
const RCPP_NATIVE_IMAGE_MARKER: &str = "rcpp-native-image ";
const RCPP_ANALYSIS_SIDECAR: &str = "rcpp-analysis.json";
const RCPP_NATIVE_ROOT: &str = "rcpp-native";

#[derive(Debug)]
pub struct ScriptLangDetector;

impl Detector for ScriptLangDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        let lang: ScriptLang = classify(bytes)?;
        Some(verdict_for(bytes, lang))
    }
}

#[derive(Debug)]
pub struct ScriptLangPass;

impl Pass for ScriptLangPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ScriptLangDetector
    }

    fn output_kind(&self, output: &Artifact) -> OutputKind {
        if output.envelope.starts_with(TCL_BANNER.as_bytes())
            || contains_bytes(&output.envelope, RCPP_NATIVE_IMAGE_MARKER.as_bytes())
        {
            OutputKind::Mixed {
                children: Vec::new(),
            }
        } else {
            OutputKind::Bytes {
                format_tag: SCRIPT_REPORT_TAG,
                family: FAMILY_SOURCE,
            }
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        if ScriptLangDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-SCRIPT-0902: scriptlang.classify: input is not a perl/r/tcl/haxe artifact"
                    .to_string(),
            ));
        }
        let art: ScriptArtifact = analyze(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-SCRIPT-0903: scriptlang analyze: {e}"))
        })?;
        let rcpp: Option<RcppFingerprint> = if matches!(art, ScriptArtifact::R(_)) {
            analyze_rcpp(bytes).ok().filter(RcppFingerprint::is_rcpp)
        } else {
            None
        };
        let report: String = render_report(&art, rcpp.as_ref());
        Ok(Artifact::new(
            Rung::Surface,
            report.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        match classify(bytes) {
            Some(ScriptLang::Tcl) => extract_tcl_children(bytes),
            Some(ScriptLang::R) => Ok(extract_rcpp_children(bytes)),
            _ => Ok(Vec::new()),
        }
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Shell,
    disrobe_core::chain::SupportQuality::DetectOnly,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static SCRIPTLANG_PASS: ScriptLangPass = ScriptLangPass;

fn child_index(index: usize) -> u32 {
    u32::try_from(index).map_or(u32::MAX, |value: u32| value)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window: &[u8]| window == needle)
}

fn extract_tcl_children(bytes: &[u8]) -> CoreResult<Vec<ChildArtifact>> {
    let art: ScriptArtifact = analyze(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-SCRIPT-0905: scriptlang tcl analyze: {e}"))
    })?;
    let ScriptArtifact::Tcl(container): ScriptArtifact = art else {
        return Ok(Vec::new());
    };
    let mut children: Vec<ChildArtifact> = Vec::with_capacity(container.entries.len());
    for (index, entry) in container.entries.into_iter().enumerate() {
        let entry: StarkitEntry = entry;
        if entry.contents.is_empty() {
            continue;
        }
        children.push(ChildArtifact {
            handle: ChildHandle {
                artifact_index: child_index(index),
                relative_path: entry.path,
                hint: Some("tcl-starkit-entry".to_string()),
            },
            bytes: entry.contents,
        });
    }
    Ok(children)
}

#[derive(Debug, Serialize)]
struct RcppSidecar {
    uses_rcpp: bool,
    linking_to_rcpp: bool,
    class_markers: Vec<String>,
    native_images: Vec<RcppSidecarImage>,
}

#[derive(Debug, Serialize)]
struct RcppSidecarImage {
    format: &'static str,
    offset: usize,
    length: usize,
    route_pass_id: &'static str,
}

impl From<&RcppFingerprint> for RcppSidecar {
    fn from(fp: &RcppFingerprint) -> Self {
        Self {
            uses_rcpp: fp.uses_rcpp,
            linking_to_rcpp: fp.linking_to_rcpp,
            class_markers: fp.class_markers.clone(),
            native_images: fp
                .embedded_images
                .iter()
                .map(
                    |image: &crate::lang::rcpp::EmbeddedNativeImage| RcppSidecarImage {
                        format: image.format.label(),
                        offset: image.offset,
                        length: image.length,
                        route_pass_id: image.route_pass_id,
                    },
                )
                .collect(),
        }
    }
}

fn extract_rcpp_children(bytes: &[u8]) -> Vec<ChildArtifact> {
    let Some(fp): Option<RcppFingerprint> =
        analyze_rcpp(bytes).ok().filter(RcppFingerprint::is_rcpp)
    else {
        return Vec::new();
    };
    if fp.embedded_images.is_empty() {
        return Vec::new();
    }
    let mut children: Vec<ChildArtifact> = Vec::with_capacity(fp.embedded_images.len() + 1);
    let mut index: u32 = 0;
    let sidecar: RcppSidecar = RcppSidecar::from(&fp);
    if let Ok(json) = serde_json::to_vec_pretty(&sidecar) {
        children.push(terminal_child(
            index,
            RCPP_ANALYSIS_SIDECAR.to_string(),
            json,
        ));
        index += 1;
    }
    for image in fp.embedded_images {
        let relative_path: String = format!("{RCPP_NATIVE_ROOT}/{index}.{}", image.format.label());
        children.push(terminal_child(index, relative_path, image.bytes));
        index += 1;
    }
    children
}

fn terminal_child(index: u32, relative_path: String, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: index,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    }
}

fn render_report(art: &ScriptArtifact, rcpp: Option<&RcppFingerprint>) -> String {
    match art {
        ScriptArtifact::Tcl(container) => render_tcl(container),
        ScriptArtifact::Perl(tree) => DecompileWalker::new(tree).decompile().rendered,
        ScriptArtifact::R(obj) => render_r(obj, rcpp),
        ScriptArtifact::Haxe(fp) => render_haxe(fp),
        ScriptArtifact::WinScript(recovery) => render_winscript(recovery),
    }
}

fn render_r(obj: &RdsObject, rcpp: Option<&RcppFingerprint>) -> String {
    let mut out: String = String::new();
    let header: String = format!(
        "{R_BANNER} v{version} root={root} len={len:?} nodes={nodes} names={names} class={class:?} closures={closures} raw_vectors={raw_vectors} complex_vectors={complex_vectors} s4_objects={s4_objects} environments={environments} altrep={altrep} extptr={extptr} weakref={weakref}",
        version = obj.header.version,
        root = obj.root_type,
        len = obj.root_length,
        nodes = obj.node_count,
        names = obj.names.len(),
        class = obj.class,
        closures = obj.closures.len(),
        raw_vectors = obj.raw_vectors.len(),
        complex_vectors = obj.complex_vectors.len(),
        s4_objects = obj.s4_objects.len(),
        environments = obj.environments.len(),
        altrep = obj.altrep_objects.len(),
        extptr = obj.external_pointers.len(),
        weakref = obj.weak_references.len(),
    );
    push_line(&mut out, &header);
    for name in &obj.names {
        push_line(&mut out, &format!("name {name}"));
    }
    for sym in &obj.symbols {
        push_line(&mut out, &format!("symbol {sym}"));
    }
    for closure in &obj.closures {
        push_line(&mut out, &format!("closure {}", closure.rendered));
    }
    for s4 in &obj.s4_objects {
        if let Some(class_name) = s4.class.as_deref() {
            push_line(&mut out, &format!("s4 {class_name}"));
        }
    }
    for env in &obj.environments {
        for binding in &env.bindings {
            push_line(&mut out, &format!("env {binding}"));
        }
    }
    for alt in &obj.altrep_objects {
        if let (Some(class_name), Some(materialized)) =
            (alt.class.as_deref(), alt.materialized.as_deref())
        {
            push_line(&mut out, &format!("altrep {class_name}={materialized}"));
        }
    }
    if let Some(fp) = rcpp {
        push_line(
            &mut out,
            &format!(
                "rcpp uses_rcpp={} linking_to_rcpp={} markers={:?} native_images={} route={}",
                fp.uses_rcpp,
                fp.linking_to_rcpp,
                fp.class_markers,
                fp.embedded_images.len(),
                crate::lang::rcpp::NATIVE_ROUTE_PASS_ID,
            ),
        );
        for image in &fp.embedded_images {
            push_line(
                &mut out,
                &format!(
                    "{RCPP_NATIVE_IMAGE_MARKER}format={} offset={} length={} route={}",
                    image.format.label(),
                    image.offset,
                    image.length,
                    image.route_pass_id,
                ),
            );
        }
    }
    out
}

fn render_haxe(fp: &HaxeFingerprint) -> String {
    let mut out: String = String::new();
    let header: String = format!(
        "{HAXE_BANNER} target={target:?} routes_to={route} confirmed={confirmed} recovered=(classes={classes},methods={methods},source_files={source_files},std_modules={std_modules},strings={strings})",
        target = fp.target,
        route = fp.route_pass_id,
        confirmed = fp.haxe_confirmed,
        classes = fp.recovered.classes.len(),
        methods = fp.recovered.methods.len(),
        source_files = fp.recovered.source_files.len(),
        std_modules = fp.recovered.std_modules.len(),
        strings = fp.recovered.string_literals.len(),
    );
    push_line(&mut out, &header);
    if let Some(ver) = fp.compiler_version.as_deref() {
        push_line(&mut out, &format!("// haxe compiler {ver}"));
    }
    for class_name in &fp.recovered.classes {
        push_line(&mut out, &format!("class {class_name}"));
    }
    for method_name in &fp.recovered.methods {
        push_line(&mut out, &format!("method {method_name}"));
    }
    for source_file in &fp.recovered.source_files {
        push_line(&mut out, &format!("source-file {source_file}"));
    }
    for std_module in &fp.recovered.std_modules {
        push_line(&mut out, &format!("std-module {std_module}"));
    }
    for literal in &fp.recovered.string_literals {
        push_line(&mut out, &format!("string {literal}"));
    }
    if let Some(hl) = fp.hashlink.as_ref() {
        push_line(
            &mut out,
            &format!(
                "hashlink v{} types={} globals={} natives={} functions={} opcodes={} constants={} fully_parsed={}",
                hl.version,
                hl.num_types,
                hl.num_globals,
                hl.num_natives,
                hl.num_functions,
                hl.num_opcodes,
                hl.num_constants,
                hl.fully_parsed,
            ),
        );
    }
    out
}

fn render_winscript(recovery: &WinScriptRecovery) -> String {
    let mut out: String = String::new();
    let header: String = format!(
        "{WIN_SCRIPT_BANNER} lang={lang} layers={layers} techniques={techniques} obfuscated={obfuscated}",
        lang = recovery.language.tag(),
        layers = recovery.layers.len(),
        techniques = recovery.techniques.len(),
        obfuscated = recovery.is_obfuscated(),
    );
    push_line(&mut out, &header);
    for technique in &recovery.techniques {
        push_line(&mut out, &format!("technique {}", technique.tag()));
    }
    for layer in &recovery.layers {
        let line: String = format!("# layer {}", layer.technique.tag());
        push_line(&mut out, &line);
    }
    for wall in &recovery.walls {
        let line: String = format!("# wall {}: {}", wall.technique.tag(), wall.reason.tag());
        push_line(&mut out, &line);
    }
    out.push_str(&recovery.recovered_text);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn render_tcl(container: &StarkitContainer) -> String {
    let mut out: String = String::with_capacity(160 + 48 * container.entries.len());
    let header: String = format!(
        "{TCL_BANNER} format={fmt:?} entries={n} tcl_files={tcl} obfuscated={obf} obf_hits=(indirect={indirect},dynamic-proc={dynamic_proc},subst={subst}) completeness={completeness:.2}",
        fmt = container.format,
        n = container.entries.len(),
        tcl = container.tcl_source_files.len(),
        obf = container.obfuscation.obfuscated,
        indirect = container.obfuscation.indirect_call_hits,
        dynamic_proc = container.obfuscation.dynamic_proc_hits,
        subst = container.obfuscation.subst_hits,
        completeness = container.completeness.ratio(),
    );
    push_line(&mut out, &header);
    for entry in &container.entries {
        let line: String = format!(
            "{path} ({size} bytes)",
            path = entry.path,
            size = entry.size
        );
        push_line(&mut out, &line);
    }
    out
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn rds_marker(bytes: &[u8]) -> &'static str {
    let Ok(object): ScriptResult<RdsObject> = analyze_r(bytes) else {
        return "rds-magic";
    };
    match (object.header.container, object.header.encoding) {
        (RdsContainer::Rda, _) => "rda-workspace-magic",
        (_, RdsEncoding::Xdr) => "rds-xdr-magic",
        (_, RdsEncoding::Binary) => "rds-native-magic",
        (_, RdsEncoding::Ascii) => "rds-ascii-magic",
    }
}

fn verdict_for(bytes: &[u8], lang: ScriptLang) -> DetectVerdict {
    let (tag, family, confidence, specificity, marker, explain): (
        &'static str,
        &'static str,
        f32,
        u16,
        &'static str,
        String,
    ) = match lang {
        ScriptLang::Perl => (
            TAG_PERL,
            FAMILY_INTERPRETER_BYTECODE,
            0.90,
            30,
            "b-concise-optree",
            "perl B::Concise op-tree dump".to_string(),
        ),
        ScriptLang::R => (
            TAG_R,
            FAMILY_INTERPRETER_BYTECODE,
            0.94,
            32,
            rds_marker(bytes),
            "r RDS (saveRDS) serialized object".to_string(),
        ),
        ScriptLang::Tcl => (
            TAG_TCL,
            FAMILY_CONTAINER,
            0.93,
            35,
            "starkit-header",
            "tcl starkit / tclkit container".to_string(),
        ),
        ScriptLang::Haxe => haxe_meta(bytes),
        ScriptLang::WinScript => (
            TAG_WIN_SCRIPT,
            FAMILY_SOURCE,
            0.85,
            26,
            "win-script-obfuscation",
            "windows script obfuscation (powershell/batch/vbscript layered recovery)".to_string(),
        ),
    };
    DetectVerdict::new(
        PASS_ID,
        tag,
        family,
        confidence,
        specificity,
        vec![marker],
        explain,
    )
}

fn haxe_meta(bytes: &[u8]) -> (&'static str, &'static str, f32, u16, &'static str, String) {
    let tag: &'static str = match crate::lang::haxe::detect(bytes).map(|fp| fp.target) {
        Some(HaxeTarget::JavaScript) => TAG_HAXE_JS,
        Some(HaxeTarget::SwfFlash) => TAG_HAXE_SWF,
        Some(HaxeTarget::HashLink) => TAG_HAXE_HL,
        Some(HaxeTarget::Neko) => TAG_HAXE_NEKO,
        None => TAG_HAXE_JS,
    };
    (
        tag,
        FAMILY_SOURCE,
        0.88,
        28,
        "haxe-emitted-target",
        "haxe cross-target output (routes to matching target pass)".to_string(),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

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
        assert_eq!(ScriptLangDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_haxe_js() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        let v: DetectVerdict = ScriptLangDetector.detect(&ctx(js)).expect("detect");
        assert_eq!(v.format_tag, TAG_HAXE_JS);
    }

    #[test]
    fn detect_misses_random_bytes() {
        let bytes: Vec<u8> = vec![0x33u8; 64];
        assert!(ScriptLangDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_run_rejects_unknown() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0x33u8; 64], [0u8; 32]);
        let err: CoreError = SCRIPTLANG_PASS.run(&a).expect_err("must reject");
        assert!(format!("{err}").contains("DR-SCRIPT-0902"));
    }

    #[test]
    fn child_index_saturates() {
        assert_eq!(child_index(9usize), 9u32);
        assert_eq!(child_index(usize::MAX), u32::MAX);
    }

    #[test]
    fn pass_run_haxe_is_bytes_report_not_source() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        let a: Artifact = Artifact::new(Rung::Raw, js.to_vec(), [0u8; 32]);
        let out: Artifact = SCRIPTLANG_PASS.run(&a).expect("classify");
        assert_eq!(out.rung, Rung::Surface);
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 report");
        assert!(
            !s.trim_start().starts_with('{'),
            "haxe report must not be json; got {s:?}",
        );
        assert!(
            s.starts_with(HAXE_BANNER),
            "haxe report must lead with banner"
        );
        match SCRIPTLANG_PASS.output_kind(&out) {
            OutputKind::Bytes { format_tag, .. } => assert_eq!(format_tag, SCRIPT_REPORT_TAG),
            other => panic!("haxe is emitted output, not recoverable source; got {other:?}"),
        }
    }

    fn build_zip_starkit(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write as _};
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"#!/bin/sh\n# \\\nexec tclkit \"$0\" ${1+\"$@\"}\n");
        out.extend_from_slice(b"package require starkit\nstarkit::header mk4 -readonly\n");
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zip: zip::ZipWriter<Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (path, data) in files {
                zip.start_file(*path, opts).expect("start");
                zip.write_all(data).expect("write");
            }
            zip.finish().expect("finish");
        }
        out.extend_from_slice(&buf);
        out
    }

    #[test]
    fn tcl_starkit_run_renders_listing_and_extract_children_carves_members() {
        let main_tcl: &[u8] = b"package require Tcl 8.6\nputs {hello from disrobe}\n";
        let util_tcl: &[u8] = b"proc add {a b} { return [expr {$a + $b}] }\n";
        let kit: Vec<u8> =
            build_zip_starkit(&[("app/main.tcl", main_tcl), ("app/util.tcl", util_tcl)]);
        let a: Artifact = Artifact::new(Rung::Raw, kit, [0u8; 32]);

        let out: Artifact = SCRIPTLANG_PASS.run(&a).expect("tcl run must succeed");
        let listing: &str = std::str::from_utf8(&out.envelope).expect("utf8 listing");
        assert!(
            listing.starts_with(TCL_BANNER) && !listing.trim_start().starts_with('{'),
            "tcl run must emit the readable listing, not json; got {:?}",
            listing.chars().take(160).collect::<String>(),
        );
        assert!(
            matches!(SCRIPTLANG_PASS.output_kind(&out), OutputKind::Mixed { .. }),
            "tcl starkit is a container; output_kind must be Mixed",
        );

        let children: Vec<ChildArtifact> = SCRIPTLANG_PASS
            .extract_children(&a)
            .expect("starkit children must carve");
        assert_eq!(children.len(), 2, "both starkit members must be carved");
        let main_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "app/main.tcl")
            .expect("main.tcl member present");
        assert_eq!(
            main_child.bytes, main_tcl,
            "carved member must be the real recovered file bytes, not metadata",
        );
    }

    const PERL_CONCISE: &[u8] = include_bytes!("../tests/fixtures/hello.concise.txt");

    #[test]
    fn chain_perl_emits_decompiled_source_matching_cli_walker_not_a_banner() {
        use crate::lang::perl::{PerlOpTree, read_concise};

        let a: Artifact = Artifact::new(Rung::Raw, PERL_CONCISE.to_vec(), [0u8; 32]);
        let out: Artifact = SCRIPTLANG_PASS
            .run(&a)
            .expect("perl chain run must succeed");
        assert_eq!(out.rung, Rung::Surface);
        let chained: String = String::from_utf8(out.envelope).expect("utf8 source");

        let tree: PerlOpTree = read_concise(PERL_CONCISE).expect("parse concise");
        let cli_equivalent: String = DecompileWalker::new(&tree).decompile().rendered;
        assert_eq!(
            chained, cli_equivalent,
            "chain must emit the same reconstructed Perl the CLI DecompileWalker produces"
        );

        assert!(
            !chained.contains("# perl B::Concise op-tree"),
            "chain must no longer emit the op-tree banner; got {chained:?}"
        );
        for token in [
            "sub greet",
            "sub add",
            "my ($name) = @_;",
            "return",
            "$name",
        ] {
            assert!(
                chained.contains(token),
                "reconstructed Perl source must contain '{token}'; got:\n{chained}"
            );
        }
    }

    fn rcpp_module_rds() -> Vec<u8> {
        const NILVALUE_SXP: u32 = 254u32;
        const SYMSXP: u32 = 1u32;
        const LISTSXP: u32 = 2u32;
        const CHARSXP: u32 = 9u32;
        const STRSXP: u32 = 16u32;
        const RAWSXP: u32 = 24u32;
        const VECSXP: u32 = 19u32;
        const HAS_ATTR_BIT: u32 = 1u32 << 9;
        const HAS_TAG_BIT: u32 = 1u32 << 10;
        let char_sxp = |out: &mut Vec<u8>, s: &str| {
            out.extend_from_slice(&CHARSXP.to_be_bytes());
            out.extend_from_slice(&(s.len() as i32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        };
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"X\n");
        out.extend_from_slice(&3i32.to_be_bytes());
        out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
        out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
        out.extend_from_slice(&5i32.to_be_bytes());
        out.extend_from_slice(b"UTF-8");
        out.extend_from_slice(&(VECSXP | HAS_ATTR_BIT).to_be_bytes());
        out.extend_from_slice(&2i32.to_be_bytes());
        out.extend_from_slice(&STRSXP.to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        char_sxp(&mut out, "RcppExports");
        let mut so: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        so.extend_from_slice(&[0u8; 56]);
        out.extend_from_slice(&RAWSXP.to_be_bytes());
        out.extend_from_slice(&(so.len() as i32).to_be_bytes());
        out.extend_from_slice(&so);
        out.extend_from_slice(&(LISTSXP | HAS_TAG_BIT).to_be_bytes());
        out.extend_from_slice(&SYMSXP.to_be_bytes());
        char_sxp(&mut out, "names");
        out.extend_from_slice(&STRSXP.to_be_bytes());
        out.extend_from_slice(&2i32.to_be_bytes());
        char_sxp(&mut out, "exports");
        char_sxp(&mut out, "dll");
        out.extend_from_slice(&NILVALUE_SXP.to_be_bytes());
        out
    }

    #[test]
    fn run_surfaces_rcpp_native_image_routing_in_report_text() {
        let body: Vec<u8> = rcpp_module_rds();
        let a: Artifact = Artifact::new(Rung::Raw, body, [0u8; 32]);
        let out: Artifact = SCRIPTLANG_PASS.run(&a).expect("rcpp r run must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 report");
        assert!(s.starts_with(R_BANNER), "r report must lead with banner");
        assert!(s.contains("rcpp uses_rcpp=true"), "report={s}");
        assert!(
            s.contains("rcpp-native-image format=elf"),
            "carved native image must appear in the report text: {s}"
        );
        assert!(
            s.contains(crate::lang::rcpp::NATIVE_ROUTE_PASS_ID),
            "report must name the routing target pass: {s}"
        );
        assert!(
            matches!(SCRIPTLANG_PASS.output_kind(&out), OutputKind::Mixed { .. }),
            "an rcpp module with an embedded native image must fan out as Mixed",
        );
    }

    #[test]
    fn extract_children_carves_rcpp_native_image_and_analysis_sidecar() {
        let body: Vec<u8> = rcpp_module_rds();
        let a: Artifact = Artifact::new(Rung::Raw, body, [0u8; 32]);
        let children: Vec<ChildArtifact> = SCRIPTLANG_PASS
            .extract_children(&a)
            .expect("rcpp children must carve");
        assert_eq!(
            children.len(),
            2,
            "one analysis sidecar plus one carved native image expected: {children:?}"
        );
        let sidecar: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == RCPP_ANALYSIS_SIDECAR)
            .expect("rcpp analysis sidecar present");
        let value: serde_json::Value =
            serde_json::from_slice(&sidecar.bytes).expect("sidecar must be valid json");
        assert_eq!(value["uses_rcpp"], serde_json::Value::Bool(true));
        assert_eq!(value["native_images"][0]["format"], "elf");
        assert_eq!(
            value["native_images"][0]["route_pass_id"],
            crate::lang::rcpp::NATIVE_ROUTE_PASS_ID
        );

        let image: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.starts_with(RCPP_NATIVE_ROOT))
            .expect("carved native image present");
        assert_eq!(&image.bytes[..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(
            image.handle.hint.as_deref(),
            Some(TERMINAL_HINT),
            "carved native image must be terminal, no further chain re-detection expected",
        );
    }

    #[test]
    fn extract_children_on_non_rcpp_r_is_empty() {
        let plain: Vec<u8> = {
            const NILVALUE_SXP: u32 = 254u32;
            let mut out: Vec<u8> = Vec::new();
            out.extend_from_slice(b"X\n");
            out.extend_from_slice(&3i32.to_be_bytes());
            out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
            out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
            out.extend_from_slice(&5i32.to_be_bytes());
            out.extend_from_slice(b"UTF-8");
            out.extend_from_slice(&NILVALUE_SXP.to_be_bytes());
            out
        };
        let a: Artifact = Artifact::new(Rung::Raw, plain, [0u8; 32]);
        let children: Vec<ChildArtifact> = SCRIPTLANG_PASS
            .extract_children(&a)
            .expect("plain r extract_children must not error");
        assert!(children.is_empty(), "non-rcpp r object carves nothing");
    }

    #[test]
    fn render_r_carries_root_length() {
        let body: Vec<u8> = rcpp_module_rds();
        let a: Artifact = Artifact::new(Rung::Raw, body, [0u8; 32]);
        let out: Artifact = SCRIPTLANG_PASS.run(&a).expect("r run must succeed");
        let s: &str = std::str::from_utf8(&out.envelope).expect("utf8 report");
        assert!(
            s.contains("len=Some(2)"),
            "r report must carry the root object's declared length: {s}"
        );
    }
}
