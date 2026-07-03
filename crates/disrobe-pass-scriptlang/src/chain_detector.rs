#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle};
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, FAMILY_INTERPRETER_BYTECODE,
    FAMILY_SOURCE, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

use crate::lang::perl_decompile::DecompileWalker;
use crate::lang::tcl::{StarkitContainer, StarkitEntry};
use crate::lang::{ScriptArtifact, ScriptLang, analyze, classify, haxe::HaxeTarget};

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
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ScriptLangDetector
    }

    fn output_kind(&self, output: &Artifact) -> OutputKind {
        if output.envelope.starts_with(TCL_BANNER.as_bytes()) {
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
        let report: String = render_report(&art);
        Ok(Artifact::new(
            Rung::Surface,
            report.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        if !matches!(classify(bytes), Some(ScriptLang::Tcl)) {
            return Ok(Vec::new());
        }
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
}

pub static SCRIPTLANG_PASS: ScriptLangPass = ScriptLangPass;

fn child_index(index: usize) -> u32 {
    u32::try_from(index).map_or(u32::MAX, |value: u32| value)
}

fn render_report(art: &ScriptArtifact) -> String {
    match art {
        ScriptArtifact::Tcl(container) => render_tcl(container),
        ScriptArtifact::Perl(tree) => DecompileWalker::new(tree).decompile().rendered,
        ScriptArtifact::R(obj) => {
            let mut out: String = String::new();
            let header: String = format!(
                "{R_BANNER} root={root} nodes={nodes} names={names}",
                root = obj.root_type,
                nodes = obj.node_count,
                names = obj.names.len(),
            );
            push_line(&mut out, &header);
            for name in &obj.names {
                let line: String = format!("name {name}");
                push_line(&mut out, &line);
            }
            for sym in &obj.symbols {
                let line: String = format!("symbol {sym}");
                push_line(&mut out, &line);
            }
            out
        }
        ScriptArtifact::Haxe(fp) => {
            let mut out: String = String::new();
            let header: String = format!(
                "{HAXE_BANNER} target={target:?} routes_to={route}",
                target = fp.target,
                route = fp.route_pass_id,
            );
            push_line(&mut out, &header);
            if let Some(ver) = fp.compiler_version.as_deref() {
                let line: String = format!("// haxe compiler {ver}");
                push_line(&mut out, &line);
            }
            out
        }
        ScriptArtifact::WinScript(recovery) => {
            let mut out: String = String::new();
            let header: String = format!(
                "{WIN_SCRIPT_BANNER} lang={lang} layers={layers}",
                lang = recovery.language.tag(),
                layers = recovery.layers.len(),
            );
            push_line(&mut out, &header);
            for layer in &recovery.layers {
                let line: String = format!("# layer {}", layer.technique.tag());
                push_line(&mut out, &line);
            }
            for wall in &recovery.walls {
                let line: String =
                    format!("# wall {}: {}", wall.technique.tag(), wall.reason.tag());
                push_line(&mut out, &line);
            }
            out.push_str(&recovery.recovered_text);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out
        }
    }
}

fn render_tcl(container: &StarkitContainer) -> String {
    let mut out: String = String::with_capacity(128 + 48 * container.entries.len());
    let header: String = format!(
        "{TCL_BANNER} format={fmt:?} entries={n} tcl_files={tcl} obfuscated={obf}",
        fmt = container.format,
        n = container.entries.len(),
        tcl = container.tcl_source_files.len(),
        obf = container.obfuscation.obfuscated,
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
            "rds-xdr-magic",
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
}
