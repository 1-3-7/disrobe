use std::io::IsTerminal as _;
use std::sync::OnceLock;

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    out.push(LOWER_HEX[(byte >> 4) as usize] as char);
    out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
}

fn push_lower_hex_fixed(out: &mut String, code: u32, digits: usize) {
    for nibble in (0..digits).rev() {
        let shift: usize = nibble * 4;
        let index: usize = ((code >> shift) & 0x0f) as usize;
        out.push(LOWER_HEX[index] as char);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    Text,
    Json,
}

#[derive(Debug, Clone, Copy)]
pub struct DebugLog {
    scope: &'static str,
    mode: Mode,
    color: bool,
}

struct EnvSpec {
    spec: String,
    json: bool,
    color: bool,
}

fn env_spec() -> &'static EnvSpec {
    static SPEC: OnceLock<EnvSpec> = OnceLock::new();
    SPEC.get_or_init(|| {
        let spec: String = std::env::var("DISROBE_DEBUG").unwrap_or_default();
        let json: bool = std::env::var("DISROBE_DEBUG_FORMAT")
            .is_ok_and(|v: String| v.eq_ignore_ascii_case("json"));
        let color: bool = resolve_color();
        EnvSpec { spec, json, color }
    })
}

fn resolve_color() -> bool {
    match std::env::var("DISROBE_DEBUG_COLOR") {
        Ok(v) if v.eq_ignore_ascii_case("always") || v == "1" => true,
        Ok(v) if v.eq_ignore_ascii_case("never") || v == "0" => false,
        _ => std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal(),
    }
}

fn spec_enables(spec: &str, scope: &str) -> bool {
    if spec.is_empty() {
        return false;
    }
    spec.split(',').map(str::trim).any(|tok: &str| {
        tok.eq_ignore_ascii_case("1")
            || tok.eq_ignore_ascii_case("all")
            || tok.eq_ignore_ascii_case("true")
            || tok.eq_ignore_ascii_case(scope)
    })
}

impl DebugLog {
    #[must_use]
    pub fn for_scope(scope: &'static str) -> Self {
        let env: &EnvSpec = env_spec();
        let mode: Mode = if !spec_enables(&env.spec, scope) {
            Mode::Off
        } else if env.json {
            Mode::Json
        } else {
            Mode::Text
        };
        Self {
            scope,
            mode,
            color: env.color,
        }
    }

    #[must_use]
    pub const fn disabled(scope: &'static str) -> Self {
        Self {
            scope,
            mode: Mode::Off,
            color: false,
        }
    }

    #[must_use]
    #[inline]
    pub const fn on(self) -> bool {
        !matches!(self.mode, Mode::Off)
    }

    #[must_use]
    #[inline]
    pub const fn is_tty(self) -> bool {
        self.color
    }

    pub fn section(self, name: &str) {
        match self.mode {
            Mode::Off => {}
            Mode::Text if self.color => {
                eprintln!("\x1b[1;36m[debug:{}] === {name} ===\x1b[0m", self.scope);
            }
            Mode::Text => eprintln!("[debug:{}] === {name} ===", self.scope),
            Mode::Json => self.json_event(&[("kind", "section"), ("name", name)]),
        }
    }

    pub fn line(self, f: impl FnOnce() -> String) {
        match self.mode {
            Mode::Off => {}
            Mode::Text => eprintln!("[debug:{}] {}", self.scope, f()),
            Mode::Json => self.json_event(&[("kind", "line"), ("msg", &f())]),
        }
    }

    pub fn kv(self, key: &str, f: impl FnOnce() -> String) {
        match self.mode {
            Mode::Off => {}
            Mode::Text => eprintln!("[debug:{}] {key} = {}", self.scope, f()),
            Mode::Json => self.json_event(&[("kind", "kv"), ("key", key), ("value", &f())]),
        }
    }

    pub fn hex(self, label: &str, bytes: &[u8], max: usize) {
        if matches!(self.mode, Mode::Off) {
            return;
        }
        let take: usize = bytes.len().min(max);
        let mut hex: String = String::with_capacity(take * 2);
        for &byte in &bytes[..take] {
            push_lower_hex_byte(&mut hex, byte);
        }
        match self.mode {
            Mode::Off => {}
            Mode::Text => {
                let ascii: String = bytes[..take]
                    .iter()
                    .map(|&b: &u8| {
                        if (0x20..=0x7e).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                eprintln!(
                    "[debug:{}] {label}: len={} shown={take}",
                    self.scope,
                    bytes.len()
                );
                eprintln!("[debug:{}]   hex {hex}", self.scope);
                eprintln!("[debug:{}]   asc {ascii}", self.scope);
            }
            Mode::Json => self.json_event(&[
                ("kind", "hex"),
                ("label", label),
                ("len", &bytes.len().to_string()),
                ("shown", &take.to_string()),
                ("hex", &hex),
            ]),
        }
    }

    pub fn secret(self, label: &str, byte_len: usize) {
        self.line(|| format!("{label}: <redacted, {byte_len} bytes>"));
    }

    pub fn kv_guarded(self, key: &str, f: impl FnOnce() -> String) {
        if matches!(self.mode, Mode::Off) {
            return;
        }
        let raw: String = f();
        let value: String = guard_secret_shaped(&raw);
        self.kv(key, || value);
    }

    fn json_event(self, fields: &[(&str, &str)]) {
        let mut out: String = String::from("{\"scope\":");
        json_str(&mut out, self.scope);
        for (key, value) in fields {
            out.push(',');
            json_str(&mut out, key);
            out.push(':');
            json_str(&mut out, value);
        }
        out.push('}');
        eprintln!("{out}");
    }
}

#[must_use]
pub fn guard_secret_shaped(value: &str) -> String {
    let trimmed: &str = value.trim();
    let len: usize = trimmed.chars().count();
    if len < 20 {
        return value.to_owned();
    }
    let all_token: bool = trimmed
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'));
    if !all_token {
        return value.to_owned();
    }
    let digits: usize = trimmed.chars().filter(char::is_ascii_digit).count();
    let uppers: usize = trimmed.chars().filter(char::is_ascii_uppercase).count();
    let lowers: usize = trimmed.chars().filter(char::is_ascii_lowercase).count();
    let classes: usize =
        usize::from(digits > 0) + usize::from(uppers > 0) + usize::from(lowers > 0);
    if classes < 2 {
        return value.to_owned();
    }
    let head: String = trimmed.chars().take(4).collect();
    format!("{head}\u{2026}<redacted {len} chars>")
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                push_lower_hex_fixed(out, c as u32, 4);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn disabled_scope_is_off_and_cheap() {
        let log: DebugLog = DebugLog::disabled("nuitka");
        assert!(!log.on());
        log.line(|| panic!("closure must not run when disabled"));
        log.kv("k", || panic!("closure must not run when disabled"));
    }

    #[test]
    fn spec_matching() {
        assert!(spec_enables("nuitka", "nuitka"));
        assert!(spec_enables("all", "nuitka"));
        assert!(spec_enables("1", "anything"));
        assert!(spec_enables("jvm,nuitka,native", "nuitka"));
        assert!(!spec_enables("jvm,native", "nuitka"));
        assert!(!spec_enables("", "nuitka"));
    }

    #[test]
    fn json_escaping() {
        let mut out: String = String::new();
        json_str(&mut out, "a\"b\\c\nd");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn guard_masks_secret_shaped_tokens() {
        let key: &str = "AKIA1234567890ABCDEFqwertyZXCV";
        let masked: String = guard_secret_shaped(key);
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains("redacted"));
        assert!(!masked.contains("qwertyZXCV"));
    }

    #[test]
    fn guard_passes_prose_and_short_or_single_class() {
        assert_eq!(
            guard_secret_shaped("offset 0x40 size 12"),
            "offset 0x40 size 12"
        );
        assert_eq!(guard_secret_shaped("deadbeef"), "deadbeef");
        let lowered: &str = "abcdefghijklmnopqrstuvwxyz";
        assert_eq!(guard_secret_shaped(lowered), lowered);
    }

    #[test]
    fn disabled_log_is_not_tty() {
        let log: DebugLog = DebugLog::disabled("nuitka");
        assert!(!log.is_tty());
    }
}
