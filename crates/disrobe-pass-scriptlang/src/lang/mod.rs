pub mod hashlink;
pub mod haxe;
pub mod perl;
pub mod perl_bytecode;
pub mod perl_decompile;
pub mod r_rds;
pub mod rcpp;
pub mod tcl;
pub mod winscript;

use std::borrow::Cow;
use std::io::Read;

use serde::Serialize;

use crate::debug::{dbg_enabled, dbg_hex, dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptLang {
    Perl,
    R,
    Tcl,
    Haxe,
    WinScript,
}

impl ScriptLang {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Perl => "perl-concise",
            Self::R => "r-rds",
            Self::Tcl => "tcl-starkit",
            Self::Haxe => "haxe-target",
            Self::WinScript => "win-script",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "lang", rename_all = "kebab-case")]
pub enum ScriptArtifact {
    Perl(perl::PerlOpTree),
    R(Box<r_rds::RdsObject>),
    Tcl(tcl::StarkitContainer),
    Haxe(haxe::HaxeFingerprint),
    WinScript(winscript::WinScriptRecovery),
}

impl ScriptArtifact {
    #[must_use]
    pub const fn lang(&self) -> ScriptLang {
        match self {
            Self::Perl(_) => ScriptLang::Perl,
            Self::R(_) => ScriptLang::R,
            Self::Tcl(_) => ScriptLang::Tcl,
            Self::Haxe(_) => ScriptLang::Haxe,
            Self::WinScript(_) => ScriptLang::WinScript,
        }
    }
}

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

#[must_use]
pub fn classify(bytes: &[u8]) -> Option<ScriptLang> {
    if haxe::detect(bytes).is_some() {
        return Some(ScriptLang::Haxe);
    }
    if tcl::is_starkit(bytes) {
        return Some(ScriptLang::Tcl);
    }
    if rds_detectable(bytes) {
        return Some(ScriptLang::R);
    }
    if perl_bytecode::is_bytecode(bytes) || perl::is_concise(bytes) {
        return Some(ScriptLang::Perl);
    }
    if may_be_text_script(bytes)
        && !is_native_binary_format(bytes)
        && winscript::looks_like_winscript(&winscript::decode_text(bytes))
    {
        return Some(ScriptLang::WinScript);
    }
    None
}

pub fn analyze(bytes: &[u8]) -> Result<ScriptArtifact> {
    dbg_section("scriptlang analyze");
    if dbg_enabled() {
        dbg_kv("input_len", || bytes.len().to_string());
        dbg_hex("input_head", bytes, 16);
    }
    if let Some(fp) = haxe::detect(bytes) {
        dbg_kv("classify", || "haxe".to_owned());
        dbg_kv("haxe.target", || fp.target.target_label().to_owned());
        dbg_kv("haxe.route", || fp.route_pass_id.to_owned());
        dbg_kv("haxe.confirmed", || fp.haxe_confirmed.to_string());
        dbg_kv("haxe.recovered", || {
            format!(
                "classes={} methods={} source_files={} std_modules={} strings={}",
                fp.recovered.classes.len(),
                fp.recovered.methods.len(),
                fp.recovered.source_files.len(),
                fp.recovered.std_modules.len(),
                fp.recovered.string_literals.len()
            )
        });
        if !matches!(fp.target, haxe::HaxeTarget::JavaScript) {
            dbg_line(|| {
                format!(
                    "wall: haxe target {} recovered by route to {} (no in-pass devirtualization)",
                    fp.target.target_label(),
                    fp.route_pass_id
                )
            });
        }
        return Ok(ScriptArtifact::Haxe(fp));
    }
    if tcl::is_starkit(bytes) {
        dbg_kv("classify", || "tcl-starkit".to_owned());
        let container: tcl::StarkitContainer = tcl::extract(bytes)?;
        dbg_kv("tcl.format", || format!("{:?}", container.format));
        dbg_kv("tcl.entries", || container.entries.len().to_string());
        dbg_kv("tcl.tcl_source_files", || {
            container.tcl_source_files.len().to_string()
        });
        dbg_kv("tcl.obfuscated", || {
            container.obfuscation.obfuscated.to_string()
        });
        dbg_kv("tcl.completeness", || {
            format!("{:.2}", container.completeness.ratio())
        });
        if matches!(container.format, tcl::StarkitFormat::Metakit)
            && container.completeness.recovered_with_contents == 0
            && !container.entries.is_empty()
        {
            dbg_line(|| {
                format!(
                    "wall: metakit b-tree payload not decoded, recovered {} filenames only (no contents)",
                    container.entries.len()
                )
            });
        }
        return Ok(ScriptArtifact::Tcl(container));
    }
    if let Some(rds_bytes) = maybe_gunzip_rds(bytes)? {
        dbg_kv("classify", || "r-rds".to_owned());
        if dbg_enabled() && rds_bytes.len() != bytes.len() {
            dbg_kv("rds.gunzip_len", || rds_bytes.len().to_string());
        }
        let obj: r_rds::RdsObject = r_rds::read_rds(rds_bytes.as_ref())?;
        dbg_kv("rds.version", || obj.header.version.to_string());
        dbg_kv("rds.root_type", || obj.root_type.clone());
        dbg_kv("rds.recovered", || {
            format!(
                "closures={} environments={} s4_objects={} altrep={} symbols={} names={}",
                obj.closures.len(),
                obj.environments.len(),
                obj.s4_objects.len(),
                obj.altrep_objects.len(),
                obj.symbols.len(),
                obj.names.len()
            )
        });
        for (idx, closure) in obj.closures.iter().enumerate() {
            dbg_kv(&format!("rds.closure[{idx}]"), || {
                closure
                    .rendered
                    .lines()
                    .next()
                    .map_or("", |value: &str| value)
                    .to_owned()
            });
        }
        return Ok(ScriptArtifact::R(Box::new(obj)));
    }
    if perl_bytecode::is_bytecode(bytes) {
        dbg_kv("classify", || "perl-bytecode".to_owned());
        let tree: perl::PerlOpTree = perl_bytecode::read_bytecode(bytes)?;
        debug_perl_tree("perl-bytecode", &tree);
        return Ok(ScriptArtifact::Perl(tree));
    }
    if perl::is_concise(bytes) {
        dbg_kv("classify", || "perl-concise".to_owned());
        let tree: perl::PerlOpTree = perl::read_concise(bytes)?;
        debug_perl_tree("perl-concise", &tree);
        return Ok(ScriptArtifact::Perl(tree));
    }
    if may_be_text_script(bytes)
        && !is_native_binary_format(bytes)
        && let Ok(recovery) = winscript::analyze(bytes)
    {
        dbg_kv("classify", || "win-script".to_owned());
        dbg_kv("winscript.lang", || recovery.language.tag().to_owned());
        dbg_kv("winscript.layers", || recovery.layers.len().to_string());
        dbg_kv("winscript.techniques", || {
            recovery.techniques.len().to_string()
        });
        dbg_kv("winscript.walls", || recovery.walls.len().to_string());
        return Ok(ScriptArtifact::WinScript(recovery));
    }
    dbg_line(|| "no recognized perl/r/tcl/haxe/winscript artifact".to_owned());
    Err(Error::Unrecognized)
}

fn debug_perl_tree(tag: &str, tree: &perl::PerlOpTree) {
    if !dbg_enabled() {
        return;
    }
    dbg_kv("perl.format", || tag.to_owned());
    dbg_kv("perl.optree", || {
        format!("subs={} ops={}", tree.subs.len(), tree.op_count)
    });
    let source: perl_decompile::PerlSource = perl_decompile::DecompileWalker::new(tree).decompile();
    dbg_kv("perl.recovery", || {
        format!(
            "statements={}/{} ratio={:.2}",
            source.statements_recovered,
            source.statements_total,
            source.recovery_ratio()
        )
    });
    let lexicals: usize = tree
        .subs
        .iter()
        .map(|s: &perl::PerlSub| s.pad_vars.len())
        .sum();
    dbg_kv("perl.lexical_pads", || lexicals.to_string());
    let unrecovered: usize = source
        .subs
        .iter()
        .flat_map(|s: &perl_decompile::PerlSubSource| s.statements.iter())
        .filter(|st: &&perl_decompile::PerlStatement| !st.recovered)
        .count();
    if unrecovered > 0 {
        dbg_line(|| {
            format!(
                "wall: {unrecovered} statement(s) reference package-global intermediate temporaries not named in the op-tree"
            )
        });
    }
}

fn is_native_binary_format(bytes: &[u8]) -> bool {
    matches!(
        disrobe_core::structural::identify_by_structure(bytes),
        Some(
            disrobe_core::structural::StructuralFormat::Pe
                | disrobe_core::structural::StructuralFormat::Elf
                | disrobe_core::structural::StructuralFormat::MachO
                | disrobe_core::structural::StructuralFormat::MachOFat
        )
    )
}

fn may_be_text_script(bytes: &[u8]) -> bool {
    const SAMPLE: usize = 8192;
    if bytes.is_empty() {
        return false;
    }
    if bytes.starts_with(&[0xff, 0xfe]) {
        return true;
    }
    let sample: &[u8] = &bytes[..bytes.len().min(SAMPLE)];
    if looks_like_utf16le_sample(sample) {
        return true;
    }
    let controls: usize = sample
        .iter()
        .filter(|b| matches!(**b, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f))
        .count();
    let printable: usize = sample
        .iter()
        .filter(|b| matches!(**b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    controls * 100 <= sample.len() * 5 && printable * 100 >= sample.len() * 75
}

fn looks_like_utf16le_sample(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let sampled: usize = bytes.iter().skip(1).step_by(2).take(64).count();
    let zeros: usize = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .take(64)
        .filter(|b| **b == 0)
        .count();
    sampled > 0 && zeros * 2 >= sampled
}

pub fn analyze_r(bytes: &[u8]) -> Result<r_rds::RdsObject> {
    let rds_bytes: Cow<'_, [u8]> = maybe_gunzip_rds(bytes)?.ok_or(Error::Unrecognized)?;
    r_rds::read_rds(rds_bytes.as_ref())
}

pub fn analyze_rcpp(bytes: &[u8]) -> Result<rcpp::RcppFingerprint> {
    let rds_bytes: Cow<'_, [u8]> = maybe_gunzip_rds(bytes)?.ok_or(Error::Unrecognized)?;
    let obj: r_rds::RdsObject = r_rds::read_rds(rds_bytes.as_ref())?;
    Ok(rcpp::fingerprint(&obj, rds_bytes.as_ref()))
}

fn rds_detectable(bytes: &[u8]) -> bool {
    maybe_gunzip_rds(bytes)
        .ok()
        .flatten()
        .is_some_and(|b: Cow<'_, [u8]>| r_rds::is_rds(b.as_ref()))
}

const MAX_RDS_BYTES: usize = 1usize << 29;

fn maybe_gunzip_rds(bytes: &[u8]) -> Result<Option<Cow<'_, [u8]>>> {
    maybe_gunzip_rds_with_limit(bytes, MAX_RDS_BYTES)
}

const BZIP2_MAGIC: [u8; 3] = [b'B', b'Z', b'h'];
const XZ_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0x00];

fn read_limit(max_bytes: usize) -> Result<u64> {
    u64::try_from(max_bytes)
        .map_err(|source: std::num::TryFromIntError| Error::RdsGzip {
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        })
        .map(|value: u64| value.saturating_add(1u64))
}

fn read_bounded(
    reader: impl Read,
    max_bytes: usize,
    wrap: fn(std::io::Error) -> Error,
) -> Result<Option<Vec<u8>>> {
    let mut out: Vec<u8> = Vec::new();
    let mut limited: std::io::Take<_> = reader.take(read_limit(max_bytes)?);
    let _: usize = limited.read_to_end(&mut out).map_err(wrap)?;
    if out.len() > max_bytes {
        return Ok(None);
    }
    Ok(Some(out))
}

fn maybe_gunzip_rds_with_limit(bytes: &[u8], max_bytes: usize) -> Result<Option<Cow<'_, [u8]>>> {
    if r_rds::is_rds(bytes) {
        if bytes.len() > max_bytes {
            return Ok(None);
        }
        return Ok(Some(Cow::Borrowed(bytes)));
    }
    let plain: Option<Vec<u8>> = if bytes.starts_with(&GZIP_MAGIC) {
        read_bounded(
            flate2::read::GzDecoder::new(bytes),
            max_bytes,
            |source: std::io::Error| Error::RdsGzip { source },
        )?
    } else if bytes.starts_with(&BZIP2_MAGIC) {
        read_bounded(
            bzip2_rs::DecoderReader::new(bytes),
            max_bytes,
            |source: std::io::Error| Error::RdsBzip2 { source },
        )?
    } else if bytes.starts_with(&XZ_MAGIC) {
        read_bounded(
            liblzma::read::XzDecoder::new(bytes),
            max_bytes,
            |source: std::io::Error| Error::RdsXz { source },
        )?
    } else {
        None
    };
    match plain {
        Some(out) if r_rds::is_rds(&out) => Ok(Some(Cow::Owned(out))),
        _ => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn classify_haxe_js() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        assert_eq!(classify(js), Some(ScriptLang::Haxe));
    }

    #[test]
    fn classify_rejects_random() {
        assert!(classify(b"random bytes with no recognizable script signature here").is_none());
    }

    #[test]
    fn classify_rejects_binary_blob_with_embedded_script_marker() {
        let mut bytes: Vec<u8> = Vec::with_capacity(8192);
        bytes.extend_from_slice(b"hsqs");
        bytes.extend(std::iter::repeat_n(0u8, 2048));
        bytes.extend_from_slice(b"powershell.exe -encodedcommand");
        bytes.extend(std::iter::repeat_n(0xffu8, 2048));
        assert!(classify(&bytes).is_none());
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p: &std::path::Path| p.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn classify_rejects_a_real_native_pe_whose_strings_incidentally_read_as_script_markers() {
        let path: std::path::PathBuf = workspace_root()
            .join("corpus")
            .join("binfmt")
            .join("dotnet-single-file")
            .join("expected")
            .join("libcustom.dll");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: {} missing", path.display());
            return;
        };
        assert!(
            classify(&bytes).is_none(),
            "a real native pe dll must not classify as a windows script just because its \
             string table happens to contain short powershell-verb-shaped substrings",
        );
    }

    #[test]
    fn is_native_binary_format_rejects_plain_text() {
        assert!(!is_native_binary_format(b"not a native binary at all"));
    }

    #[test]
    fn is_native_binary_format_recognizes_a_real_elf() {
        let path: std::path::PathBuf = workspace_root()
            .join("corpus")
            .join("native")
            .join("discovery")
            .join("disc.unstripped.elf");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: {} missing", path.display());
            return;
        };
        assert!(is_native_binary_format(&bytes));
    }

    #[test]
    fn rds_direct_rejects_over_limit_before_clone() {
        let bytes: &[u8] = b"X\n123456789";
        assert!(
            maybe_gunzip_rds_with_limit(bytes, 4usize)
                .expect("direct rds probe succeeds")
                .is_none()
        );
    }

    #[test]
    fn rds_direct_detection_borrows_input() {
        let bytes: &[u8] = b"X\n123456789";
        assert!(matches!(
            maybe_gunzip_rds_with_limit(bytes, 16usize).expect("direct rds probe succeeds"),
            Some(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn rds_gzip_rejects_over_limit_after_sentinel() {
        let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"X\n12345").expect("gzip write");
        let compressed: Vec<u8> = encoder.finish().expect("gzip finish");
        assert!(
            maybe_gunzip_rds_with_limit(&compressed, 4usize)
                .expect("gzip rds probe succeeds")
                .is_none()
        );
    }

    #[test]
    fn rds_gzip_decode_error_surfaces_in_analysis() {
        let bytes: [u8; 4] = [0x1f, 0x8b, 0x08, 0xff];
        assert_eq!(classify(&bytes), None);
        let err: Error = analyze_rcpp(&bytes).expect_err("bad gzip must be explicit");
        assert!(matches!(err, Error::RdsGzip { .. }));
    }

    #[test]
    fn analyze_haxe_returns_fingerprint() {
        let js: &[u8] = b"// Generated by Haxe 4.3.6\n();\n";
        let art: ScriptArtifact = analyze(js).expect("analyze");
        assert_eq!(art.lang(), ScriptLang::Haxe);
    }
}
