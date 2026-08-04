use serde::{Deserialize, Serialize};

use crate::pass::PassId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    Python,
    JavaScript,
    Wasm,
    Jvm,
    Dotnet,
    Native,
    Go,
    Lua,
    Php,
    Ruby,
    Beam,
    As3,
    Mobile,
    Swift,
    Shell,
    Container,
    Other,
}

impl Ecosystem {
    #[inline]
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Wasm => "wasm",
            Self::Jvm => "jvm",
            Self::Dotnet => "dotnet",
            Self::Native => "native",
            Self::Go => "go",
            Self::Lua => "lua",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Beam => "beam",
            Self::As3 => "as3",
            Self::Mobile => "mobile",
            Self::Swift => "swift",
            Self::Shell => "shell",
            Self::Container => "container",
            Self::Other => "other",
        }
    }

    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript / TypeScript",
            Self::Wasm => "WebAssembly",
            Self::Jvm => "JVM / Android",
            Self::Dotnet => ".NET / CLR",
            Self::Native => "Native (PE / ELF / Mach-O)",
            Self::Go => "Go",
            Self::Lua => "Lua",
            Self::Php => "PHP",
            Self::Ruby => "Ruby",
            Self::Beam => "BEAM (Erlang / Elixir)",
            Self::As3 => "ActionScript 3",
            Self::Mobile => "Mobile (React Native / Flutter)",
            Self::Swift => "Swift / Objective-C",
            Self::Shell => "Shell / PowerShell / VBA",
            Self::Container => "Container / Archive",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Python,
            Self::JavaScript,
            Self::Wasm,
            Self::Jvm,
            Self::Dotnet,
            Self::Native,
            Self::Go,
            Self::Lua,
            Self::Php,
            Self::Ruby,
            Self::Beam,
            Self::As3,
            Self::Mobile,
            Self::Swift,
            Self::Shell,
            Self::Container,
            Self::Other,
        ]
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let needle: String = raw.trim().to_ascii_lowercase();
        match needle.as_str() {
            "python" | "py" | "py3" | "cpython" => Some(Self::Python),
            "javascript" | "js" | "ts" | "typescript" | "node" | "nodejs" => Some(Self::JavaScript),
            "wasm" | "webassembly" | "wat" => Some(Self::Wasm),
            "jvm" | "java" | "android" | "dalvik" | "dex" | "kotlin" => Some(Self::Jvm),
            "dotnet" | ".net" | "net" | "clr" | "csharp" | "cs" | "il" => Some(Self::Dotnet),
            "native" | "pe" | "elf" | "macho" | "mach-o" | "packer" | "binary" => {
                Some(Self::Native)
            }
            "go" | "golang" => Some(Self::Go),
            "lua" | "luau" | "luajit" | "glua" => Some(Self::Lua),
            "php" => Some(Self::Php),
            "ruby" | "rb" | "yarv" | "mruby" => Some(Self::Ruby),
            "beam" | "erlang" | "elixir" => Some(Self::Beam),
            "as3" | "actionscript" | "swf" | "flash" => Some(Self::As3),
            "mobile" | "reactnative" | "react-native" | "hermes" | "flutter" => Some(Self::Mobile),
            "swift" | "objc" | "objective-c" | "ios" => Some(Self::Swift),
            "shell" | "powershell" | "ps1" | "bash" | "batch" | "vba" | "cmd" => Some(Self::Shell),
            "container" | "archive" | "firmware" | "binfmt" => Some(Self::Container),
            "other" | "misc" => Some(Self::Other),
            _ => None,
        }
    }
}

#[must_use]
pub fn ecosystem_for(pass_id: PassId) -> Ecosystem {
    let family: &str = pass_id.split_once('.').map_or(pass_id, |(head, _)| head);
    match family {
        "py" | "pyarmor" | "pyinstaller" | "pyfreeze" | "nuitka" | "sourcedefender" => {
            Ecosystem::Python
        }
        "js" => Ecosystem::JavaScript,
        "wasm" => Ecosystem::Wasm,
        "jvm" => Ecosystem::Jvm,
        "dotnet" => Ecosystem::Dotnet,
        "native" | "nativelang" => Ecosystem::Native,
        "go" => Ecosystem::Go,
        "lua" => Ecosystem::Lua,
        "php" => Ecosystem::Php,
        "ruby" => Ecosystem::Ruby,
        "beam" => Ecosystem::Beam,
        "as3" => Ecosystem::As3,
        "mobile" => Ecosystem::Mobile,
        "swift-objc" | "swift" => Ecosystem::Swift,
        "shell" | "scriptlang" => Ecosystem::Shell,
        "binfmt" => Ecosystem::Container,
        "pickle" => Ecosystem::Python,
        _ => Ecosystem::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_common_aliases() {
        assert_eq!(Ecosystem::parse("python"), Some(Ecosystem::Python));
        assert_eq!(Ecosystem::parse("PY"), Some(Ecosystem::Python));
        assert_eq!(Ecosystem::parse("js"), Some(Ecosystem::JavaScript));
        assert_eq!(Ecosystem::parse("typescript"), Some(Ecosystem::JavaScript));
        assert_eq!(Ecosystem::parse(".net"), Some(Ecosystem::Dotnet));
        assert_eq!(Ecosystem::parse("golang"), Some(Ecosystem::Go));
        assert_eq!(Ecosystem::parse("boguslang"), None);
    }

    #[test]
    fn pass_id_maps_to_expected_ecosystem() {
        assert_eq!(ecosystem_for("pyarmor.unpack"), Ecosystem::Python);
        assert_eq!(ecosystem_for("py.deob"), Ecosystem::Python);
        assert_eq!(ecosystem_for("js.deob"), Ecosystem::JavaScript);
        assert_eq!(ecosystem_for("native.packer-unpack"), Ecosystem::Native);
        assert_eq!(ecosystem_for("nativelang.classify"), Ecosystem::Native);
        assert_eq!(ecosystem_for("dotnet.classify"), Ecosystem::Dotnet);
        assert_eq!(ecosystem_for("shell.deob"), Ecosystem::Shell);
        assert_eq!(ecosystem_for("binfmt.container"), Ecosystem::Container);
        assert_eq!(ecosystem_for("mystery.pass"), Ecosystem::Other);
    }

    #[test]
    fn slug_round_trips_through_parse() {
        for eco in Ecosystem::all() {
            assert_eq!(Ecosystem::parse(eco.slug()), Some(*eco));
        }
    }
}
