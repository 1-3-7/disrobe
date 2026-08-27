use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLanguage {
    Nim,
    Zig,
    Crystal,
    Haxe,
    Perl,
    R,
    Tcl,
}

impl NativeLanguage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nim => "nim",
            Self::Zig => "zig",
            Self::Crystal => "crystal",
            Self::Haxe => "haxe",
            Self::Perl => "perl",
            Self::R => "r",
            Self::Tcl => "tcl",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageHit {
    pub lang: NativeLanguage,
    pub matched_offset: u64,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionNameConfidence {
    High,
    Medium,
    Low,
}

impl FunctionNameConfidence {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionNameEvidenceSource {
    ExportedName,
    ImportThunk,
}

impl FunctionNameEvidenceSource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExportedName => "exported-name",
            Self::ImportThunk => "import-thunk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InputByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FunctionNameEvidence {
    pub confidence: FunctionNameConfidence,
    pub source: FunctionNameEvidenceSource,
    pub input_bytes: InputByteRange,
    pub identity: String,
    pub target_address: u64,
    pub target_is_indirect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecoveredFunctionName {
    pub function_address: u64,
    pub name: String,
    pub evidence: FunctionNameEvidence,
}

#[must_use]
pub fn sanitize_function_name(raw: &str) -> Option<String> {
    let mut out: String = String::with_capacity(raw.len());
    let mut previous_underscore: bool = false;
    for character in raw.chars() {
        let sanitized: char = if character.is_ascii_alphanumeric() || character == '_' {
            character
        } else {
            '_'
        };
        if sanitized == '_' && previous_underscore {
            continue;
        }
        previous_underscore = sanitized == '_';
        out.push(sanitized);
    }
    while out.ends_with('_') {
        let _: Option<char> = out.pop();
    }
    if out.is_empty() {
        return None;
    }
    if out.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        out.insert(0, '_');
    }
    Some(out)
}

#[derive(Debug, Clone, Copy)]
struct LangSignature {
    lang: NativeLanguage,
    pattern: &'static [u8],
    evidence: &'static str,
}

const LANGUAGE_SIGNATURES: &[LangSignature] = &[
    LangSignature {
        lang: NativeLanguage::Nim,
        pattern: b"NimMainModule",
        evidence: "Nim runtime entry symbol NimMainModule",
    },
    LangSignature {
        lang: NativeLanguage::Nim,
        pattern: b"nimFrameVar",
        evidence: "Nim stack-frame runtime symbol nimFrame",
    },
    LangSignature {
        lang: NativeLanguage::Nim,
        pattern: b"NimStringDesc",
        evidence: "Nim string-type RTTI descriptor NimStringDesc",
    },
    LangSignature {
        lang: NativeLanguage::Zig,
        pattern: b"reached unreachable code",
        evidence: "Zig default panic-handler message",
    },
    LangSignature {
        lang: NativeLanguage::Zig,
        pattern: b"__zig_probe_stack",
        evidence: "Zig compiler-rt stack-probe symbol",
    },
    LangSignature {
        lang: NativeLanguage::Zig,
        pattern: b".debug_zig",
        evidence: "Zig debug section name .debug_zig",
    },
    LangSignature {
        lang: NativeLanguage::Crystal,
        pattern: b"__crystal_main",
        evidence: "Crystal program entry symbol __crystal_main",
    },
    LangSignature {
        lang: NativeLanguage::Crystal,
        pattern: b"__crystal_malloc_atomic",
        evidence: "Crystal GC allocator symbol __crystal_malloc_atomic",
    },
    LangSignature {
        lang: NativeLanguage::Crystal,
        pattern: b"__crystal_personality",
        evidence: "Crystal exception personality symbol",
    },
    LangSignature {
        lang: NativeLanguage::Haxe,
        pattern: b"HX_STACK_FRAME",
        evidence: "hxcpp stack-trace macro string HX_STACK_FRAME",
    },
    LangSignature {
        lang: NativeLanguage::Haxe,
        pattern: b"_hx_alloc_obj",
        evidence: "hxcpp runtime allocator symbol _hx_alloc_obj",
    },
    LangSignature {
        lang: NativeLanguage::Haxe,
        pattern: b"HLB\x00",
        evidence: "HashLink bytecode magic HLB\\0",
    },
    LangSignature {
        lang: NativeLanguage::Perl,
        pattern: b"perl_parse",
        evidence: "libperl interpreter-construction symbol perl_parse",
    },
    LangSignature {
        lang: NativeLanguage::Perl,
        pattern: b"Perl_sv_setpv",
        evidence: "libperl SV API symbol Perl_sv_setpv",
    },
    LangSignature {
        lang: NativeLanguage::Perl,
        pattern: b"PerlIO_stdout",
        evidence: "PerlIO layer symbol PerlIO_stdout",
    },
    LangSignature {
        lang: NativeLanguage::R,
        pattern: b"R_registerRoutines",
        evidence: "R native-routine registration symbol",
    },
    LangSignature {
        lang: NativeLanguage::R,
        pattern: b"RDX2\n",
        evidence: "R serialized .RData XDR magic RDX2",
    },
    LangSignature {
        lang: NativeLanguage::R,
        pattern: b"RDX3\n",
        evidence: "R serialized .RData XDR magic RDX3",
    },
    LangSignature {
        lang: NativeLanguage::Tcl,
        pattern: b"Tcl_CreateInterp",
        evidence: "Tcl interpreter-creation symbol Tcl_CreateInterp",
    },
    LangSignature {
        lang: NativeLanguage::Tcl,
        pattern: b"Tcl_FindExecutable",
        evidence: "Tcl runtime bootstrap symbol Tcl_FindExecutable",
    },
    LangSignature {
        lang: NativeLanguage::Tcl,
        pattern: b"tclStubsPtr",
        evidence: "Tcl stubs-table pointer symbol tclStubsPtr",
    },
];

#[must_use]
pub fn detect(bytes: &[u8]) -> Vec<LanguageHit> {
    let mut out: Vec<LanguageHit> = Vec::new();
    for sig in LANGUAGE_SIGNATURES {
        if let Some(offset) = memmem(bytes, sig.pattern) {
            out.push(LanguageHit {
                lang: sig.lang,
                matched_offset: offset as u64,
                evidence: sig.evidence.to_owned(),
            });
        }
    }
    out
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn plant(pattern: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[200..200 + pattern.len()].copy_from_slice(pattern);
        buf
    }

    #[test]
    fn nim_runtime_symbol_detected() {
        let buf: Vec<u8> = plant(b"NimMainModule");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Nim && h.matched_offset == 200)
        );
    }

    #[test]
    fn zig_panic_message_detected() {
        let buf: Vec<u8> = plant(b"reached unreachable code");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Zig && h.matched_offset == 200)
        );
    }

    #[test]
    fn crystal_entry_symbol_detected() {
        let buf: Vec<u8> = plant(b"__crystal_main");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Crystal && h.matched_offset == 200)
        );
    }

    #[test]
    fn haxe_stack_frame_detected() {
        let buf: Vec<u8> = plant(b"HX_STACK_FRAME");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Haxe && h.matched_offset == 200)
        );
    }

    #[test]
    fn perl_parse_symbol_detected() {
        let buf: Vec<u8> = plant(b"perl_parse");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Perl && h.matched_offset == 200)
        );
    }

    #[test]
    fn r_register_routines_detected() {
        let buf: Vec<u8> = plant(b"R_registerRoutines");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::R && h.matched_offset == 200)
        );
    }

    #[test]
    fn tcl_create_interp_detected() {
        let buf: Vec<u8> = plant(b"Tcl_CreateInterp");
        let hits: Vec<LanguageHit> = detect(&buf);
        assert!(
            hits.iter()
                .any(|h: &LanguageHit| h.lang == NativeLanguage::Tcl && h.matched_offset == 200)
        );
    }

    #[test]
    fn zero_buffer_yields_no_hits() {
        let hits: Vec<LanguageHit> = detect(&vec![0u8; 4096]);
        assert!(hits.is_empty());
    }

    #[test]
    fn unrelated_ascii_yields_no_hits() {
        let mut buf: Vec<u8> = vec![0u8; 4096];
        let noise: &[u8] = b"the quick brown fox jumps over";
        buf[512..512 + noise.len()].copy_from_slice(noise);
        assert!(detect(&buf).is_empty());
    }
}
