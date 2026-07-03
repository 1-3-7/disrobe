mod abyss;
mod cipher;
mod loader;
mod recover;
mod reinsert;
mod value;

use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeObject, Object, PyVersion, read_pyc};
use ruff_python_ast::ModModule;

use self::loader::{LazyBlob, LoaderPeel, extract_lazy_blobs, parse_module, peel_loader_source};
use self::recover::{RecoverStats, reverse_source_transforms};
use self::reinsert::{ReinsertReport, reinsert_lazy_blobs};
use crate::error::{Error, Result};
use crate::marshal::{decompile_code_object, load_code_from_marshal};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};
use crate::source_cleanup::cleanup_source;

const STAGE1_MODULES: [&str; 7] = [
    "sys", "os", "marshal", "zlib", "base64", "hashlib", "random",
];

#[derive(Debug, Clone, Copy)]
pub struct PatchworkPass;

#[derive(Debug, Default, Clone)]
struct LoaderSignature {
    imports_full_module_set: bool,
    has_keystream: bool,
    has_decoder_chain: bool,
    has_b85decode: bool,
    has_marshal_loads: bool,
    has_exec: bool,
    has_anti_debug: bool,
}

impl LoaderSignature {
    fn score(&self) -> f32 {
        let mut score: f32 = 0.0;
        if self.imports_full_module_set {
            score += 0.3;
        }
        if self.has_keystream {
            score += 0.2;
        }
        if self.has_decoder_chain {
            score += 0.2;
        }
        if self.has_b85decode {
            score += 0.1;
        }
        if self.has_marshal_loads {
            score += 0.1;
        }
        if self.has_exec {
            score += 0.05;
        }
        if self.has_anti_debug {
            score += 0.05;
        }
        score
    }

    const fn confident(&self) -> bool {
        self.imports_full_module_set
            && self.has_b85decode
            && self.has_marshal_loads
            && (self.has_keystream || self.has_decoder_chain)
    }

    fn markers(&self) -> Vec<String> {
        let mut markers: Vec<String> = Vec::new();
        if self.imports_full_module_set {
            markers.push("patchwork-stdlib-import-set".to_owned());
        }
        if self.has_keystream {
            markers.push("patchwork-sha256-keystream".to_owned());
        }
        if self.has_decoder_chain {
            markers.push("patchwork-cipher-chain".to_owned());
        }
        if self.has_b85decode {
            markers.push("patchwork-b85-payload".to_owned());
        }
        if self.has_anti_debug {
            markers.push("patchwork-anti-debug".to_owned());
        }
        markers
    }
}

fn loader_source_signature(source: &str) -> LoaderSignature {
    let mut sig: LoaderSignature = LoaderSignature::default();
    let imported: usize = STAGE1_MODULES
        .iter()
        .filter(|m: &&&str| {
            source.contains(&format!("__import__('{m}')"))
                || source.contains(&format!("__import__(\"{m}\")"))
        })
        .count();
    sig.imports_full_module_set = imported >= STAGE1_MODULES.len();
    sig.has_keystream = source.contains("sha256") && source.contains("to_bytes(8");
    sig.has_decoder_chain =
        source.contains("for i, b in enumerate") || source.contains("for _i, _b in enumerate");
    sig.has_b85decode = source.contains("b85decode");
    sig.has_marshal_loads = source.contains(".loads(");
    sig.has_exec = source.contains("exec(");
    sig.has_anti_debug = source.contains("gettrace()") || source.contains("addaudithook");
    sig
}

fn looks_like_pyc(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    bytes[2] == 0x0d && bytes[3] == 0x0a
}

fn loader_source_from_bytes(bytes: &[u8]) -> Option<(String, Option<PyVersion>)> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let sig: LoaderSignature = loader_source_signature(text);
        if sig.confident() || sig.score() >= 0.6 {
            return Some((text.to_owned(), None));
        }
    }
    let pyc: disrobe_py_marshal::PycFile = read_pyc(bytes).ok()?;
    let Object::Code(code): Object = pyc.code else {
        return None;
    };
    let version: PyVersion = pyc.header.version;
    let source: String = decompile_code_object(&code, version).ok()?;
    let sig: LoaderSignature = loader_source_signature(&source);
    if sig.confident() || sig.score() >= 0.6 {
        return Some((source, Some(version)));
    }
    None
}

struct PeeledModule {
    code: CodeObject,
    version: PyVersion,
    lazy_restored: usize,
    stage_count: usize,
    cipher_layers: usize,
}

fn peel_to_user_module(loader_source: &str) -> Result<PeeledModule> {
    let stage1: LoaderPeel = peel_loader_source(loader_source)?;
    let (stage2_code, stage2_version): (CodeObject, PyVersion) =
        load_code_from_marshal(&stage1.marshal_blob)
            .ok_or_else(|| Error::Marshal("stage2 marshal blob did not load".to_owned()))?;
    let stage2_source: String = decompile_code_object(&stage2_code, stage2_version)?;

    let stage2_module: ModModule = parse_module(&stage2_source)?;
    let lazy_blobs: Vec<LazyBlob> = extract_lazy_blobs(&stage2_module);

    let user_peel: LoaderPeel = peel_loader_source(&stage2_source)?;
    let (mut user_code, user_version): (CodeObject, PyVersion) =
        load_code_from_marshal(&user_peel.marshal_blob)
            .ok_or_else(|| Error::Marshal("user marshal blob did not load".to_owned()))?;

    let report: ReinsertReport = reinsert_lazy_blobs(&mut user_code, &lazy_blobs, user_version)?;
    Ok(PeeledModule {
        code: user_code,
        version: user_version,
        lazy_restored: report.restored,
        stage_count: 2,
        cipher_layers: stage1.chain.len() + user_peel.chain.len(),
    })
}

struct FinalizeResult {
    source: String,
    stats: RecoverStats,
    cleaned: bool,
    abyss: abyss::DevirtReport,
}

fn finalize_source(code: &CodeObject, version: PyVersion) -> Result<FinalizeResult> {
    let raw: String = decompile_code_object(code, version)?;
    let (devirted, abyss_report): (String, abyss::DevirtReport) = abyss::devirtualize(&raw)
        .unwrap_or_else(|_| {
            (
                raw.clone(),
                abyss::DevirtReport {
                    lifted: 0,
                    refused: 0,
                },
            )
        });
    let mut current: String = devirted;
    let mut totals: RecoverStats = RecoverStats::default();
    let mut cleaned_any: bool = false;
    for _ in 0..6 {
        let (reversed, stats): (String, RecoverStats) = reverse_source_transforms(&current)
            .unwrap_or_else(|_| (current.clone(), RecoverStats::default()));
        totals.tautologies_folded += stats.tautologies_folded;
        totals.pool_literals_inlined += stats.pool_literals_inlined;
        totals.runtime_defs_removed += stats.runtime_defs_removed;
        let cleaned: String = match cleanup_source(&reversed) {
            Ok((clean, _stats)) => {
                cleaned_any = true;
                clean
            }
            Err(_) => reversed,
        };
        if cleaned == current {
            current = cleaned;
            break;
        }
        current = cleaned;
    }
    Ok(FinalizeResult {
        source: current,
        stats: totals,
        cleaned: cleaned_any,
        abyss: abyss_report,
    })
}

impl ObfuscatorPass for PatchworkPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Patchwork
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        if let Ok(text) = std::str::from_utf8(source) {
            let sig: LoaderSignature = loader_source_signature(text);
            let matched: bool = sig.confident();
            let confidence: f32 = if matched { sig.score().min(0.97) } else { 0.0 };
            return DetectReport {
                obfuscator: self.id(),
                matched,
                confidence,
                markers: sig.markers(),
            };
        }
        if looks_like_pyc(source)
            && let Some((loader_source, _version)) = loader_source_from_bytes(source)
        {
            let sig: LoaderSignature = loader_source_signature(&loader_source);
            if sig.confident() {
                let mut markers: Vec<String> = sig.markers();
                markers.push("patchwork-pyc-loader".to_owned());
                return DetectReport {
                    obfuscator: self.id(),
                    matched: true,
                    confidence: sig.score().min(0.95),
                    markers,
                };
            }
        }
        DetectReport {
            obfuscator: self.id(),
            matched: false,
            confidence: 0.0,
            markers: Vec::new(),
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let (loader_source, _version): (String, Option<PyVersion>) =
            loader_source_from_bytes(source).ok_or(Error::NoFamilyMatched)?;
        let peeled: PeeledModule = peel_to_user_module(&loader_source)?;
        let finalized: FinalizeResult = finalize_source(&peeled.code, peeled.version)?;
        let final_source: String = finalized.source;
        let recover_stats: RecoverStats = finalized.stats;
        let cleaned: bool = finalized.cleaned;

        let mut stages: Vec<String> = vec![
            "stage1-loader".to_owned(),
            "stage2-loader".to_owned(),
            "marshal-demarshal".to_owned(),
        ];
        if peeled.lazy_restored > 0 {
            stages.push(format!("lazy-reinsert:{}", peeled.lazy_restored));
        }
        stages.push("decompile".to_owned());
        if finalized.abyss.lifted > 0 {
            stages.push(format!("abyss-devirt:{}", finalized.abyss.lifted));
        }
        if recover_stats.tautologies_folded > 0 {
            stages.push("opaque-fold".to_owned());
        }
        if recover_stats.pool_literals_inlined > 0 {
            stages.push("string-pool-inline".to_owned());
        }
        if cleaned {
            stages.push("source-cleanup".to_owned());
        }

        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("stages".to_owned(), peeled.stage_count.to_string());
        diagnostics.insert("cipher_layers".to_owned(), peeled.cipher_layers.to_string());
        diagnostics.insert(
            "lazy_functions_restored".to_owned(),
            peeled.lazy_restored.to_string(),
        );
        diagnostics.insert(
            "python_version".to_owned(),
            format!("{}.{}", peeled.version.major, peeled.version.minor),
        );
        diagnostics.insert(
            "tautologies_folded".to_owned(),
            recover_stats.tautologies_folded.to_string(),
        );
        diagnostics.insert(
            "string_pool_literals_inlined".to_owned(),
            recover_stats.pool_literals_inlined.to_string(),
        );
        diagnostics.insert(
            "runtime_defs_removed".to_owned(),
            recover_stats.runtime_defs_removed.to_string(),
        );
        diagnostics.insert(
            "abyss_functions_devirtualized".to_owned(),
            finalized.abyss.lifted.to_string(),
        );
        diagnostics.insert(
            "abyss_functions_refused".to_owned(),
            finalized.abyss.refused.to_string(),
        );

        let mut lossy_notes: Vec<String> = vec![
            "patchwork discards original identifier names; recovered source is bytecode-equivalent with mangled names unless built with --no-rename".to_owned(),
        ];
        if finalized.abyss.refused > 0 {
            lossy_notes.push(format!(
                "{} abyss-virtualized function(s) used control flow outside the linear/structured shapes the lifter reconstructs; their dispatch wrappers were left intact",
                finalized.abyss.refused
            ));
        }

        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: final_source,
            confidence: 0.9,
            quality: Quality::Full,
            lossy_notes,
            diagnostics,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_source() {
        let report: DetectReport = PatchworkPass.detect(b"def f():\n    return 1\n");
        assert!(!report.matched);
    }

    #[test]
    fn rejects_unrelated_dropper() {
        let report: DetectReport =
            PatchworkPass.detect(b"import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n");
        assert!(
            !report.matched,
            "generic dropper must not look like patchwork"
        );
    }

    #[test]
    fn signature_requires_full_module_set() {
        let partial: &str = "_a = __import__('sys')\n_b = __import__('os')\nexec(b85decode(b''))\n";
        let sig: LoaderSignature = loader_source_signature(partial);
        assert!(!sig.confident());
    }
}
