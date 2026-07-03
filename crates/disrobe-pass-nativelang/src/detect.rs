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
    b"start.posixCallMainAndExit",
    b"start.callMain",
    b"__zig_probe_stack",
    b"panicOutOfBounds",
    b"panicUnwrap",
    b"compiler_rt",
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
        let total: usize = match lang {
            NativeLang::Nim => NIM_RUNTIME_MARKERS.len(),
            NativeLang::Zig => ZIG_RUNTIME_MARKERS.len(),
            NativeLang::Crystal => CRYSTAL_RUNTIME_MARKERS.len(),
            NativeLang::D => D_RUNTIME_MARKERS.len(),
        };
        let ratio: f32 = hits as f32 / total as f32;
        let confidence: f32 = 0.4_f32.mul_add(ratio.min(1.0), 0.55);
        debug::dbg_kv("winner", || {
            format!(
                "{} hits={hits}/{total} confidence={confidence:.3}",
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

    #[test]
    fn lang_labels() {
        assert_eq!(NativeLang::Nim.label(), "nim");
        assert_eq!(NativeLang::Zig.label(), "zig");
        assert_eq!(NativeLang::Crystal.label(), "crystal");
        assert_eq!(NativeLang::D.label(), "d");
    }
}
