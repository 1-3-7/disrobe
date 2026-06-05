use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CommentStyle {
    Hash,
    DoubleSlash,
    DoubleDash,
    SemiSemi,
    SlashStar,
    Pound,
    HtmlComment,
}

impl CommentStyle {
    #[inline]
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Hash => "#",
            Self::DoubleSlash => "//",
            Self::DoubleDash => "--",
            Self::SemiSemi => ";;",
            Self::SlashStar => "/*",
            Self::Pound => "%",
            Self::HtmlComment => "<!--",
        }
    }

    #[inline]
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::SlashStar => " */",
            Self::HtmlComment => " -->",
            _ => "",
        }
    }
}

#[inline]
#[must_use]
pub const fn comment_prefix(style: CommentStyle) -> &'static str {
    style.prefix()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protocol {
    Decompiled,
    Disassembled,
    Deobfuscated,
    Unpacked,
    Lifted,
    Extracted,
    Decoded,
}

impl Protocol {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Decompiled => "Decompiled",
            Self::Disassembled => "Disassembled",
            Self::Deobfuscated => "Deobfuscated",
            Self::Unpacked => "Unpacked",
            Self::Lifted => "Lifted",
            Self::Extracted => "Extracted",
            Self::Decoded => "Decoded",
        }
    }
}

pub const REPO_URL: &str = "https://github.com/1-3-7/disrobe";
pub const PROVENANCE_JSON_KEY: &str = "disrobe_provenance";
pub const PROVENANCE_SCHEMA: &str = "disrobe.provenance/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceHeader {
    pub protocol: Protocol,
    pub duration: Duration,
    pub language: &'static str,
    pub version: String,
    pub style: CommentStyle,
}

impl ProvenanceHeader {
    #[inline]
    #[must_use]
    pub const fn new(
        protocol: Protocol,
        duration: Duration,
        language: &'static str,
        version: String,
        style: CommentStyle,
    ) -> Self {
        Self {
            protocol,
            duration,
            language,
            version,
            style,
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        let prefix: &'static str = self.style.prefix();
        let suffix: &'static str = self.style.suffix();
        let pretty: String = pretty_duration(self.duration);
        let protocol: &'static str = self.protocol.label();
        let version: &str = self.version.as_str();
        let language: &'static str = self.language;
        let mut out: String = String::with_capacity(
            prefix.len() * 2
                + suffix.len() * 2
                + protocol.len()
                + pretty.len()
                + REPO_URL.len()
                + language.len()
                + version.len()
                + 64,
        );
        out.push_str(prefix);
        out.push(' ');
        out.push_str(protocol);
        out.push_str(" in ");
        out.push_str(&pretty);
        out.push_str(" with Disrobe (");
        out.push_str(REPO_URL);
        out.push(')');
        out.push_str(suffix);
        out.push('\n');
        out.push_str(prefix);
        out.push(' ');
        out.push_str(language);
        if !version.is_empty() {
            out.push(' ');
            out.push_str(version);
        }
        out.push_str(suffix);
        out.push('\n');
        out
    }

    #[must_use]
    pub fn prepend_to(&self, body: &str) -> String {
        let header: String = self.render();
        let mut out: String = String::with_capacity(header.len() + body.len() + 1);
        out.push_str(&header);
        out.push_str(body);
        out
    }

    #[must_use]
    pub fn prepend_to_bytes(&self, body: &[u8]) -> Vec<u8> {
        let header: String = self.render();
        let mut out: Vec<u8> = Vec::with_capacity(header.len() + body.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        out
    }

    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": PROVENANCE_SCHEMA,
            "protocol": self.protocol.label(),
            "duration_ms": duration_ms_u128(self.duration),
            "duration_pretty": pretty_duration(self.duration),
            "language": self.language,
            "version": self.version,
            "repo": REPO_URL,
            "tool": "disrobe",
            "tool_version": env!("CARGO_PKG_VERSION"),
        })
    }

    #[must_use]
    pub fn inject_into_json(&self, value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(mut map) => {
                map.insert(PROVENANCE_JSON_KEY.to_owned(), self.to_json_value());
                serde_json::Value::Object(map)
            }
            other => serde_json::json!({
                PROVENANCE_JSON_KEY: self.to_json_value(),
                "value": other,
            }),
        }
    }
}

const MS_PER_S: u128 = 1_000;
const MS_PER_M: u128 = 60 * MS_PER_S;
const MS_PER_H: u128 = 60 * MS_PER_M;
const MS_PER_D: u128 = 24 * MS_PER_H;
const MS_CAP: u128 = 5 * MS_PER_D;

#[inline]
const fn duration_ms_u128(d: Duration) -> u128 {
    d.as_millis()
}

#[inline]
const fn round_to_tenth(numerator: u128, denominator: u128) -> (u128, u128) {
    let tenths: u128 = (numerator * 10 + denominator / 2) / denominator;
    (tenths / 10, tenths % 10)
}

#[must_use]
pub fn pretty_duration(d: Duration) -> String {
    let ms: u128 = d.as_millis();
    if ms == 0 {
        return "0ms".to_owned();
    }
    if ms >= MS_CAP {
        return "5d+".to_owned();
    }
    if ms < MS_PER_S {
        return format!("{ms}ms");
    }
    if ms < MS_PER_M {
        let (whole, frac): (u128, u128) = round_to_tenth(ms, MS_PER_S);
        return format!("{whole}.{frac}s");
    }
    if ms < MS_PER_H {
        let (whole, frac): (u128, u128) = round_to_tenth(ms, MS_PER_M);
        return format!("{whole}.{frac}m");
    }
    if ms < MS_PER_D {
        let (whole, frac): (u128, u128) = round_to_tenth(ms, MS_PER_H);
        return format!("{whole}.{frac}h");
    }
    let (whole, frac): (u128, u128) = round_to_tenth(ms, MS_PER_D);
    format!("{whole}.{frac}d")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Wat,
    Rust,
    C,
    Cpp,
    Java,
    Kotlin,
    Scala,
    Groovy,
    Smali,
    CSharp,
    VbNet,
    FSharp,
    Cil,
    Ruby,
    Lua,
    PowerShell,
    Bash,
    Batch,
    Vba,
    Php,
    Erlang,
    Elixir,
    CoreErlang,
    Go,
    Swift,
    ObjectiveC,
    ActionScript3,
    Dart,
    Haskell,
    CommonLisp,
    Matlab,
    R,
    Html,
    Xml,
    Hermes,
    V8Bytecode,
    JvmBytecode,
    Perl,
    Tcl,
    Haxe,
}

impl Language {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::TypeScript => "TypeScript",
            Self::Wat => "WebAssembly",
            Self::Rust => "Rust",
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Java => "Java",
            Self::Kotlin => "Kotlin",
            Self::Scala => "Scala",
            Self::Groovy => "Groovy",
            Self::Smali => "Smali",
            Self::CSharp => "C#",
            Self::VbNet => "VB.NET",
            Self::FSharp => "F#",
            Self::Cil => "CIL",
            Self::Ruby => "Ruby",
            Self::Lua => "Lua",
            Self::PowerShell => "PowerShell",
            Self::Bash => "Bash",
            Self::Batch => "Batch",
            Self::Vba => "VBA",
            Self::Php => "PHP",
            Self::Erlang => "Erlang",
            Self::Elixir => "Elixir",
            Self::CoreErlang => "Core Erlang",
            Self::Go => "Go",
            Self::Swift => "Swift",
            Self::ObjectiveC => "Objective-C",
            Self::ActionScript3 => "ActionScript",
            Self::Dart => "Dart",
            Self::Haskell => "Haskell",
            Self::CommonLisp => "Common Lisp",
            Self::Matlab => "MATLAB",
            Self::R => "R",
            Self::Html => "HTML",
            Self::Xml => "XML",
            Self::Hermes => "Hermes",
            Self::V8Bytecode => "V8 Bytecode",
            Self::JvmBytecode => "JVM Bytecode",
            Self::Perl => "Perl",
            Self::Tcl => "Tcl",
            Self::Haxe => "Haxe",
        }
    }

    #[inline]
    #[must_use]
    pub const fn style(self) -> CommentStyle {
        match self {
            Self::Python
            | Self::PowerShell
            | Self::Bash
            | Self::Ruby
            | Self::Php
            | Self::Elixir
            | Self::Batch
            | Self::Perl
            | Self::Tcl
            | Self::Vba => CommentStyle::Hash,
            Self::JavaScript
            | Self::TypeScript
            | Self::C
            | Self::Cpp
            | Self::Rust
            | Self::Java
            | Self::Kotlin
            | Self::Scala
            | Self::Groovy
            | Self::Smali
            | Self::Swift
            | Self::ObjectiveC
            | Self::CSharp
            | Self::VbNet
            | Self::FSharp
            | Self::Cil
            | Self::ActionScript3
            | Self::Dart
            | Self::Go
            | Self::V8Bytecode
            | Self::JvmBytecode
            | Self::Haxe
            | Self::Hermes => CommentStyle::DoubleSlash,
            Self::Lua | Self::Haskell => CommentStyle::DoubleDash,
            Self::Wat | Self::CommonLisp => CommentStyle::SemiSemi,
            Self::Html | Self::Xml => CommentStyle::HtmlComment,
            Self::Matlab | Self::R | Self::Erlang | Self::CoreErlang => CommentStyle::Pound,
        }
    }
}

#[inline]
#[must_use]
pub fn header_for(
    protocol: Protocol,
    duration: Duration,
    language: Language,
    version: impl Into<String>,
) -> ProvenanceHeader {
    ProvenanceHeader::new(
        protocol,
        duration,
        language.label(),
        version.into(),
        language.style(),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pretty_duration_zero_is_zero_ms() {
        assert_eq!(pretty_duration(Duration::from_millis(0)), "0ms");
    }

    #[test]
    fn pretty_duration_sub_second_uses_ms() {
        assert_eq!(pretty_duration(Duration::from_millis(340)), "340ms");
        assert_eq!(pretty_duration(Duration::from_millis(1)), "1ms");
        assert_eq!(pretty_duration(Duration::from_millis(999)), "999ms");
    }

    #[test]
    fn pretty_duration_seconds_with_one_decimal() {
        assert_eq!(pretty_duration(Duration::from_millis(1200)), "1.2s");
        assert_eq!(pretty_duration(Duration::from_millis(5100)), "5.1s");
        assert_eq!(pretty_duration(Duration::from_secs(59)), "59.0s");
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "from_mins is unstable (duration_constructors, rust#120301); composed seconds keep the unit arithmetic explicit"
    )]
    fn pretty_duration_minutes_with_one_decimal() {
        assert_eq!(pretty_duration(Duration::from_secs(90)), "1.5m");
        assert_eq!(pretty_duration(Duration::from_secs(60 * 30)), "30.0m");
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "from_mins is unstable (duration_constructors, rust#120301); composed seconds keep the unit arithmetic explicit"
    )]
    fn pretty_duration_hours_with_one_decimal() {
        assert_eq!(
            pretty_duration(Duration::from_secs(60 * 60 * 3 + 60 * 12)),
            "3.2h"
        );
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "from_hours is unstable (duration_constructors, rust#120301); composed seconds keep the unit arithmetic explicit"
    )]
    fn pretty_duration_days_with_one_decimal() {
        let d: Duration = Duration::from_secs(60 * 60 * 24 * 2 + 60 * 60 * 2);
        assert_eq!(pretty_duration(d), "2.1d");
    }

    #[test]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "from_days is unstable (duration_constructors, rust#120301); composed seconds keep the unit arithmetic explicit"
    )]
    fn pretty_duration_caps_at_five_days() {
        let d: Duration = Duration::from_secs(60 * 60 * 24 * 99);
        assert_eq!(pretty_duration(d), "5d+");
    }

    #[test]
    fn header_render_python_hash_style() {
        let h: ProvenanceHeader = header_for(
            Protocol::Disassembled,
            Duration::from_millis(1200),
            Language::Python,
            "3.13",
        );
        let s: String = h.render();
        assert_eq!(
            s,
            "# Disassembled in 1.2s with Disrobe (https://github.com/1-3-7/disrobe)\n# Python 3.13\n"
        );
    }

    #[test]
    fn header_render_javascript_double_slash_style() {
        let h: ProvenanceHeader = header_for(
            Protocol::Deobfuscated,
            Duration::from_millis(340),
            Language::JavaScript,
            "ES2024",
        );
        let s: String = h.render();
        assert_eq!(
            s,
            "// Deobfuscated in 340ms with Disrobe (https://github.com/1-3-7/disrobe)\n// JavaScript ES2024\n"
        );
    }

    #[test]
    fn header_render_wat_semisemi_style() {
        let h: ProvenanceHeader = header_for(
            Protocol::Decompiled,
            Duration::from_millis(5100),
            Language::Wat,
            "1.0",
        );
        let s: String = h.render();
        assert_eq!(
            s,
            ";; Decompiled in 5.1s with Disrobe (https://github.com/1-3-7/disrobe)\n;; WebAssembly 1.0\n"
        );
    }

    #[test]
    fn header_render_lua_double_dash_style() {
        let h: ProvenanceHeader = header_for(
            Protocol::Deobfuscated,
            Duration::from_millis(800),
            Language::Lua,
            "5.4",
        );
        let s: String = h.render();
        assert!(s.starts_with("-- Deobfuscated"));
        assert!(s.contains("\n-- Lua 5.4\n"));
    }

    #[test]
    fn header_render_html_uses_paired_comment_markers() {
        let h: ProvenanceHeader = header_for(
            Protocol::Extracted,
            Duration::from_millis(15),
            Language::Html,
            "5",
        );
        let s: String = h.render();
        assert!(s.starts_with("<!-- Extracted"));
        assert!(s.contains(" -->\n<!-- HTML 5 -->\n"));
    }

    #[test]
    fn header_render_matlab_uses_percent() {
        let h: ProvenanceHeader = header_for(
            Protocol::Decoded,
            Duration::from_millis(420),
            Language::Matlab,
            "R2024a",
        );
        let s: String = h.render();
        assert!(s.starts_with("% Decoded"));
        assert!(s.contains("\n% MATLAB R2024a\n"));
    }

    #[test]
    fn prepend_to_inserts_header_and_preserves_body() {
        let h: ProvenanceHeader = header_for(
            Protocol::Unpacked,
            Duration::from_millis(0),
            Language::Python,
            "3.12",
        );
        let body: &str = "print('hello')\n";
        let out: String = h.prepend_to(body);
        assert!(out.starts_with("# Unpacked in 0ms"));
        assert!(out.ends_with("print('hello')\n"));
    }

    #[test]
    fn prepend_to_bytes_is_byte_safe() {
        let h: ProvenanceHeader = header_for(
            Protocol::Disassembled,
            Duration::from_millis(50),
            Language::V8Bytecode,
            "12.0",
        );
        let body: &[u8] = &[0xCAu8, 0xFE, 0xBA, 0xBE];
        let out: Vec<u8> = h.prepend_to_bytes(body);
        let header: String = h.render();
        assert!(out.starts_with(header.as_bytes()));
        assert_eq!(&out[header.len()..], body);
    }

    #[test]
    fn json_injection_preserves_existing_fields_and_adds_provenance() {
        let h: ProvenanceHeader = header_for(
            Protocol::Decompiled,
            Duration::from_millis(120),
            Language::Wat,
            "1.0",
        );
        let v: serde_json::Value = serde_json::json!({"foo": 1, "bar": [1, 2, 3]});
        let injected: serde_json::Value = h.inject_into_json(v);
        let obj: &serde_json::Map<String, serde_json::Value> =
            injected.as_object().expect("object");
        assert!(obj.contains_key("foo"));
        assert!(obj.contains_key("bar"));
        assert!(obj.contains_key(PROVENANCE_JSON_KEY));
        let prov: &serde_json::Value = obj.get(PROVENANCE_JSON_KEY).expect("provenance present");
        assert_eq!(
            prov.get("protocol").and_then(|x| x.as_str()),
            Some("Decompiled")
        );
        assert_eq!(
            prov.get("language").and_then(|x| x.as_str()),
            Some("WebAssembly")
        );
        assert_eq!(prov.get("version").and_then(|x| x.as_str()), Some("1.0"));
        assert_eq!(
            prov.get("schema").and_then(|x| x.as_str()),
            Some(PROVENANCE_SCHEMA)
        );
    }

    #[test]
    fn json_injection_wraps_non_object_value() {
        let h: ProvenanceHeader = header_for(
            Protocol::Decoded,
            Duration::from_millis(7),
            Language::Python,
            "3.12",
        );
        let v: serde_json::Value = serde_json::Value::Array(vec![serde_json::json!(1)]);
        let out: serde_json::Value = h.inject_into_json(v);
        assert!(out.is_object());
        assert!(out.get("value").is_some());
        assert!(out.get(PROVENANCE_JSON_KEY).is_some());
    }

    #[test]
    fn comment_prefix_accessor_matches_enum() {
        assert_eq!(comment_prefix(CommentStyle::Hash), "#");
        assert_eq!(comment_prefix(CommentStyle::DoubleSlash), "//");
        assert_eq!(comment_prefix(CommentStyle::DoubleDash), "--");
        assert_eq!(comment_prefix(CommentStyle::SemiSemi), ";;");
        assert_eq!(comment_prefix(CommentStyle::Pound), "%");
        assert_eq!(comment_prefix(CommentStyle::HtmlComment), "<!--");
        assert_eq!(comment_prefix(CommentStyle::SlashStar), "/*");
    }

    #[test]
    fn language_style_mapping_is_sensible() {
        assert_eq!(Language::Python.style(), CommentStyle::Hash);
        assert_eq!(Language::JavaScript.style(), CommentStyle::DoubleSlash);
        assert_eq!(Language::Lua.style(), CommentStyle::DoubleDash);
        assert_eq!(Language::Wat.style(), CommentStyle::SemiSemi);
        assert_eq!(Language::Html.style(), CommentStyle::HtmlComment);
        assert_eq!(Language::Matlab.style(), CommentStyle::Pound);
        assert_eq!(Language::R.style(), CommentStyle::Pound);
    }
}
