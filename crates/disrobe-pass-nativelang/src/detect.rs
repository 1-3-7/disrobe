use serde::{Deserialize, Serialize};

use crate::debug;
use crate::image::NativeImage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLang {
    Nim,
    Zig,
    Crystal,
    D,
}

impl NativeLang {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nim => "nim",
            Self::Zig => "zig",
            Self::Crystal => "crystal",
            Self::D => "d",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LangFingerprint {
    pub lang: NativeLang,
    pub confidence: f32,
    pub markers: Vec<String>,
}

const NIM_RUNTIME_MARKERS: &[&[u8]] = &[
    b"NimMainModule",
    b"NimMainInner",
    b"NimMain",
    b"PreMainInner",
    b"PreMain",
    b"nimFrame",
    b"nimZeroMem",
    b"nimToCStringConv",
];

const ZIG_RUNTIME_MARKERS: &[&[u8]] = &[
    b".buildid",
    b"RtlExitUserProcess",
    b"__zig_probe_stack",
    b"__zig_tag_name_",
    b"attempt to unwrap error: ",
    b"builtin.zig",
    b"compiler_rt",
    b"heap.PageAllocator",
    b"mem.Allocator.",
    b"panicOutOfBounds",
    b"panicUnwrap",
    b"reached unreachable code",
    b"start.callMain",
    b"start.main",
    b"start.posixCallMainAndExit",
];

const CRYSTAL_RUNTIME_MARKERS: &[&[u8]] = &[
    b"__crystal_main",
    b"__crystal_raise",
    b"__crystal_once",
    b"Crystal::EventLoop",
    b"Crystal::System",
    b"Crystal::Hasher",
    b"Fiber::StackPool",
    b"raise_overflow",
];

const D_RUNTIME_MARKERS: &[&[u8]] = &[
    b"_Dmain",
    b"_d_run_main",
    b"_d_throw_exception",
    b"_d_arraybounds",
    b"_d_assert",
    b"rt.dmain2",
    b"rt.minfo",
    b"rt.lifetime",
    b"rt.sections",
    b"rt.monitor_",
    b"core.runtime",
    b"core.exception",
    b"TypeInfo_Class",
    b"ModuleInfo",
];

const NIM_CONFIDENCE_EVIDENCE_UNITS: u32 = 8;
const ZIG_CONFIDENCE_EVIDENCE_UNITS: u32 = 15;
const CRYSTAL_CONFIDENCE_EVIDENCE_UNITS: u32 = 8;
const D_CONFIDENCE_EVIDENCE_UNITS: u32 = 14;

#[must_use]
pub const fn runtime_markers(lang: NativeLang) -> &'static [&'static [u8]] {
    match lang {
        NativeLang::Nim => NIM_RUNTIME_MARKERS,
        NativeLang::Zig => ZIG_RUNTIME_MARKERS,
        NativeLang::Crystal => CRYSTAL_RUNTIME_MARKERS,
        NativeLang::D => D_RUNTIME_MARKERS,
    }
}

#[must_use]
pub fn marker_hits(image: &NativeImage<'_>, lang: NativeLang) -> Vec<String> {
    score(image, runtime_markers(lang)).1
}

const fn confidence_evidence_units(lang: NativeLang) -> u32 {
    match lang {
        NativeLang::Nim => NIM_CONFIDENCE_EVIDENCE_UNITS,
        NativeLang::Zig => ZIG_CONFIDENCE_EVIDENCE_UNITS,
        NativeLang::Crystal => CRYSTAL_CONFIDENCE_EVIDENCE_UNITS,
        NativeLang::D => D_CONFIDENCE_EVIDENCE_UNITS,
    }
}

fn confidence_for(lang: NativeLang, hits: u32) -> f32 {
    let evidence_units: u32 = confidence_evidence_units(lang);
    let ratio: f32 = hits as f32 / evidence_units as f32;
    0.4_f32.mul_add(ratio.min(1.0), 0.55)
}

#[must_use]
pub fn fingerprint(image: &NativeImage<'_>) -> Option<LangFingerprint> {
    debug::dbg_section("fingerprint");
    let nim: (u32, Vec<String>) = score(image, NIM_RUNTIME_MARKERS);
    let zig: (u32, Vec<String>) = score(image, ZIG_RUNTIME_MARKERS);
    let crystal: (u32, Vec<String>) = score(image, CRYSTAL_RUNTIME_MARKERS);
    let d: (u32, Vec<String>) = score(image, D_RUNTIME_MARKERS);
    if debug::dbg_enabled() {
        debug::dbg_kv("score-nim", || {
            format!(
                "{}/{} {}",
                nim.0,
                NIM_RUNTIME_MARKERS.len(),
                nim.1.join(",")
            )
        });
        debug::dbg_kv("score-zig", || {
            format!(
                "{}/{} {}",
                zig.0,
                ZIG_RUNTIME_MARKERS.len(),
                zig.1.join(",")
            )
        });
        debug::dbg_kv("score-crystal", || {
            format!(
                "{}/{} {}",
                crystal.0,
                CRYSTAL_RUNTIME_MARKERS.len(),
                crystal.1.join(",")
            )
        });
        debug::dbg_kv("score-d", || {
            format!("{}/{} {}", d.0, D_RUNTIME_MARKERS.len(), d.1.join(","))
        });
    }

    let mut best: Option<(NativeLang, u32, Vec<String>)> = None;
    for (lang, (hits, markers)) in [
        (NativeLang::Nim, nim),
        (NativeLang::Zig, zig),
        (NativeLang::Crystal, crystal),
        (NativeLang::D, d),
    ] {
        if hits == 0 {
            continue;
        }
        let take: bool = best.as_ref().is_none_or(|(_, h, _)| hits > *h);
        if take {
            best = Some((lang, hits, markers));
        }
    }

    if best.is_none() {
        debug::dbg_line(|| "no runtime markers matched any language".to_owned());
    }

    best.map(|(lang, hits, markers)| {
        let total: usize = runtime_markers(lang).len();
        let evidence_units: u32 = confidence_evidence_units(lang);
        let confidence: f32 = confidence_for(lang, hits);
        debug::dbg_kv("winner", || {
            format!(
                "{} hits={hits}/{total} evidence-units={evidence_units} \
                 confidence={confidence:.3}",
                lang.label()
            )
        });
        LangFingerprint {
            lang,
            confidence,
            markers,
        }
    })
}

fn score(image: &NativeImage<'_>, markers: &[&[u8]]) -> (u32, Vec<String>) {
    let mut hits: u32 = 0;
    let mut found: Vec<String> = Vec::new();
    for marker in markers {
        if image.raw_contains(marker) {
            hits += 1;
            found.push(String::from_utf8_lossy(marker).into_owned());
        }
    }
    (hits, found)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn read_corpus_fixture(relative: &str) -> Vec<u8> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("corpus/native")
            .join(relative);
        std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "committed fixture {} is the graded reference for this test and could not be read \
                 ({error}); restore it from git rather than skipping the measurement",
                path.display()
            )
        })
    }

    #[test]
    fn lang_labels() {
        assert_eq!(NativeLang::Nim.label(), "nim");
        assert_eq!(NativeLang::Zig.label(), "zig");
        assert_eq!(NativeLang::Crystal.label(), "crystal");
        assert_eq!(NativeLang::D.label(), "d");
    }

    #[test]
    fn fixture_confidence_uses_stable_all_language_evidence_scales() {
        let cases: [(NativeLang, &str, u32, f32); 4] = [
            (NativeLang::Nim, "nim/hello.nim.elf", 7, 0.9000),
            (NativeLang::Zig, "zig/hello.zig.elf", 12, 0.8700),
            (NativeLang::Crystal, "crystal/hello.cr.exe", 4, 0.7500),
            (NativeLang::D, "d/hello.d.exe", 9, 0.807_142_85),
        ];
        for (lang, relative, expected_hits, expected_confidence) in cases {
            let bytes: Vec<u8> = read_corpus_fixture(relative);
            let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("fixture must parse");
            let fp: LangFingerprint = fingerprint(&image).expect("fixture must fingerprint");
            assert_eq!(fp.lang, lang, "{relative}");
            assert_eq!(fp.markers.len(), expected_hits as usize, "{relative}");
            let confidence: f32 = confidence_for(lang, expected_hits);
            assert!(
                (confidence - expected_confidence).abs() < 0.000_1,
                "{relative}: calibrated confidence moved to {confidence}"
            );
            assert!(
                (fp.confidence - confidence).abs() < f32::EPSILON,
                "{relative}: caller returned {} instead of {confidence}",
                fp.confidence
            );
        }
        for lang in [
            NativeLang::Nim,
            NativeLang::Zig,
            NativeLang::Crystal,
            NativeLang::D,
        ] {
            assert!(
                confidence_for(lang, 4) < 0.95,
                "{} must retain evidence headroom after four hits",
                lang.label()
            );
        }
        let marginal_zig: f32 = confidence_for(NativeLang::Zig, 2);
        assert!(
            marginal_zig > 0.60,
            "two independent zig markers must stay above the chain floor, got {marginal_zig}"
        );
    }
}
