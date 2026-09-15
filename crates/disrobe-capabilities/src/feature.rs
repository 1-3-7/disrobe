use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    File,
    Function,
    BasicBlock,
    Instruction,
}

impl Scope {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Function => "function",
            Self::BasicBlock => "basic-block",
            Self::Instruction => "instruction",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Characteristic {
    NonZeroingXor,
    TightLoop,
    IndirectCall,
    StackString,
    PebAccess,
    FsAccess,
    GsAccess,
    CrossSectionFlow,
    Loop,
    RecursiveCall,
    EmbeddedPe,
}

impl Characteristic {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NonZeroingXor => "non-zeroing-xor",
            Self::TightLoop => "tight-loop",
            Self::IndirectCall => "indirect-call",
            Self::StackString => "stack-string",
            Self::PebAccess => "peb-access",
            Self::FsAccess => "fs-access",
            Self::GsAccess => "gs-access",
            Self::CrossSectionFlow => "cross-section-flow",
            Self::Loop => "loop",
            Self::RecursiveCall => "recursive-call",
            Self::EmbeddedPe => "embedded-pe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandFeature {
    Number(u64),
    Offset(u64),
}

impl OperandFeature {
    fn render(self) -> String {
        match self {
            Self::Number(n) => format!("number({n:#x})"),
            Self::Offset(o) => format!("offset({o:#x})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feature {
    Api(String),
    Number(u64),
    StringSubstring(String),
    StringExact(String),
    StringRegex(String),
    Bytes(Vec<u8>),
    Mnemonic(String),
    Offset(u64),
    Characteristic(Characteristic),
    Operand { index: u8, inner: OperandFeature },
    Os(String),
    Arch(String),
    Format(String),
    Import(String),
    Export(String),
    Section(String),
}

impl Feature {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Api(_) => "api",
            Self::Number(_) => "number",
            Self::StringSubstring(_) | Self::StringExact(_) | Self::StringRegex(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::Mnemonic(_) => "mnemonic",
            Self::Offset(_) => "offset",
            Self::Characteristic(_) => "characteristic",
            Self::Operand { .. } => "operand",
            Self::Os(_) => "os",
            Self::Arch(_) => "arch",
            Self::Format(_) => "format",
            Self::Import(_) => "import",
            Self::Export(_) => "export",
            Self::Section(_) => "section",
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Api(name) => format!("api({name})"),
            Self::Number(n) => format!("number({n:#x})"),
            Self::StringSubstring(s) => format!("string({s:?})"),
            Self::StringExact(s) => format!("string-exact({s:?})"),
            Self::StringRegex(s) => format!("string-regex(/{s}/)"),
            Self::Bytes(b) => format!("bytes({})", render_bytes(b)),
            Self::Mnemonic(m) => format!("mnemonic({m})"),
            Self::Offset(o) => format!("offset({o:#x})"),
            Self::Characteristic(c) => format!("characteristic({})", c.label()),
            Self::Operand { index, inner } => format!("operand[{index}].{}", inner.render()),
            Self::Os(o) => format!("os({o})"),
            Self::Arch(a) => format!("arch({a})"),
            Self::Format(f) => format!("format({f})"),
            Self::Import(i) => format!("import({i})"),
            Self::Export(e) => format!("export({e})"),
            Self::Section(s) => format!("section({s})"),
        }
    }

    #[allow(clippy::match_same_arms)]
    fn matches_hit(&self, hit: &FeatureHit) -> bool {
        match (self, &hit.value) {
            (Self::Api(want), FeatureValue::Api(have)) => api_matches(want, have),
            (Self::StringSubstring(want), FeatureValue::String(have)) => have
                .to_ascii_lowercase()
                .contains(&want.to_ascii_lowercase()),
            (Self::StringExact(want), FeatureValue::String(have)) => want == have,
            (Self::StringRegex(want), FeatureValue::String(have)) => regex_matches(want, have),
            (Self::Bytes(want), FeatureValue::Bytes(have)) => have
                .windows(want.len().max(1))
                .any(|w: &[u8]| !want.is_empty() && w == want.as_slice()),
            (Self::Mnemonic(want), FeatureValue::Mnemonic(have)) => want.eq_ignore_ascii_case(have),
            (Self::Number(want), FeatureValue::Number(have)) => want == have,
            (Self::Offset(want), FeatureValue::Offset(have)) => want == have,
            (Self::Characteristic(want), FeatureValue::Characteristic(have)) => want == have,
            (
                Self::Operand { index, inner },
                FeatureValue::Operand {
                    index: have_index,
                    inner: have_inner,
                },
            ) => index == have_index && inner == have_inner,
            (Self::Os(want), FeatureValue::Os(have)) => want.eq_ignore_ascii_case(have),
            (Self::Arch(want), FeatureValue::Arch(have)) => want.eq_ignore_ascii_case(have),
            (Self::Format(want), FeatureValue::Format(have)) => want.eq_ignore_ascii_case(have),
            (Self::Import(want), FeatureValue::Import(have)) => api_matches(want, have),
            (Self::Export(want), FeatureValue::Export(have)) => want.eq_ignore_ascii_case(have),
            (Self::Section(want), FeatureValue::Section(have)) => want == have,
            _ => false,
        }
    }
}

fn regex_matches(pattern: &str, have: &str) -> bool {
    regex::Regex::new(pattern).is_ok_and(|re: regex::Regex| re.is_match(have))
}

fn api_matches(want: &str, have: &str) -> bool {
    let want_norm: String = normalize_api(want);
    let have_norm: String = normalize_api(have);
    if want_norm == have_norm {
        return true;
    }
    let have_func: &str = have_norm
        .rsplit('!')
        .next()
        .map_or(have_norm.as_str(), |value: &str| value);
    let want_func: &str = want_norm
        .rsplit('!')
        .next()
        .map_or(want_norm.as_str(), |value: &str| value);
    have_func == want_func || decorated_match(have_func, want_func)
}

fn decorated_match(have_func: &str, want_func: &str) -> bool {
    let stripped: &str = have_func
        .strip_suffix('w')
        .or_else(|| have_func.strip_suffix('a'))
        .map_or(have_func, |value: &str| value);
    stripped == want_func
}

fn normalize_api(name: &str) -> String {
    name.trim_start_matches('_')
        .trim_start_matches("imp_")
        .trim_start_matches("__")
        .to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum FeatureValue {
    Api(String),
    Number(u64),
    String(String),
    Bytes(Vec<u8>),
    Mnemonic(String),
    Offset(u64),
    Characteristic(Characteristic),
    Operand { index: u8, inner: OperandValue },
    Os(String),
    Arch(String),
    Format(String),
    Import(String),
    Export(String),
    Section(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperandValue {
    Number(u64),
    Offset(u64),
}

impl OperandValue {
    #[must_use]
    const fn as_feature(self) -> OperandFeature {
        match self {
            Self::Number(n) => OperandFeature::Number(n),
            Self::Offset(o) => OperandFeature::Offset(o),
        }
    }
}

impl PartialEq<OperandFeature> for OperandValue {
    fn eq(&self, other: &OperandFeature) -> bool {
        self.as_feature() == *other
    }
}

impl PartialEq<OperandValue> for OperandFeature {
    fn eq(&self, other: &OperandValue) -> bool {
        *self == other.as_feature()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FeatureHit {
    #[serde(flatten)]
    pub value: FeatureValue,
    pub address: u64,
}

impl FeatureHit {
    #[must_use]
    pub const fn new(value: FeatureValue, address: u64) -> Self {
        Self { value, address }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FeatureSet {
    hits: Vec<FeatureHit>,
}

impl FeatureSet {
    #[must_use]
    pub const fn new() -> Self {
        Self { hits: Vec::new() }
    }

    pub fn push(&mut self, hit: FeatureHit) {
        self.hits.push(hit);
    }

    #[must_use]
    pub fn hits(&self) -> &[FeatureHit] {
        &self.hits
    }

    #[must_use]
    pub fn matches(&self, feature: &Feature) -> Vec<u64> {
        let mut addrs: Vec<u64> = match feature {
            Feature::StringSubstring(want) => {
                let want_lower: String = want.to_ascii_lowercase();
                self.hits
                    .iter()
                    .filter(|hit: &&FeatureHit| {
                        matches!(
                            &hit.value,
                            FeatureValue::String(have)
                                if have.to_ascii_lowercase().contains(&want_lower)
                        )
                    })
                    .map(|hit: &FeatureHit| hit.address)
                    .collect()
            }
            Feature::StringRegex(pattern) => {
                let Ok(compiled): Result<regex::Regex, regex::Error> = regex::Regex::new(pattern)
                else {
                    return Vec::new();
                };
                self.hits
                    .iter()
                    .filter(|hit: &&FeatureHit| {
                        matches!(&hit.value, FeatureValue::String(have) if compiled.is_match(have))
                    })
                    .map(|hit: &FeatureHit| hit.address)
                    .collect()
            }
            _ => self
                .hits
                .iter()
                .filter(|hit: &&FeatureHit| feature.matches_hit(hit))
                .map(|hit: &FeatureHit| hit.address)
                .collect(),
        };
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    #[must_use]
    pub fn count(&self, feature: &Feature) -> usize {
        self.matches(feature).len()
    }
}

fn render_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b: &u8| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn api_match_is_decoration_and_prefix_insensitive() {
        let want: Feature = Feature::Api("CreateFile".to_owned());
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Api("KERNEL32.dll!CreateFileW".to_owned()),
            0x1031,
        ));
        assert_eq!(set.matches(&want), vec![0x1031]);
    }

    #[test]
    fn api_exact_with_module_matches() {
        let want: Feature = Feature::Api("kernel32!WriteFile".to_owned());
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Api("KERNEL32.dll!WriteFile".to_owned()),
            0x1098,
        ));
        assert_eq!(set.matches(&want), vec![0x1098]);
    }

    #[test]
    fn count_deduplicates_addresses_like_matches() {
        let want: Feature = Feature::Mnemonic("push".to_owned());
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("push".to_owned()),
            0x10,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("PUSH".to_owned()),
            0x10,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("push".to_owned()),
            0x20,
        ));
        assert_eq!(set.matches(&want), vec![0x10, 0x20]);
        assert_eq!(set.count(&want), 2);
    }

    #[test]
    fn number_and_mnemonic_and_offset_match_exactly() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(FeatureValue::Number(0x5a), 0x18));
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("xor".to_owned()),
            0x18,
        ));
        set.push(FeatureHit::new(FeatureValue::Offset(0x10), 0x10));
        assert_eq!(set.matches(&Feature::Number(0x5a)), vec![0x18]);
        assert_eq!(
            set.matches(&Feature::Mnemonic("XOR".to_owned())),
            vec![0x18]
        );
        assert_eq!(set.matches(&Feature::Offset(0x10)), vec![0x10]);
        assert!(set.matches(&Feature::Number(0x5b)).is_empty());
    }

    #[test]
    fn string_substring_is_case_insensitive() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::String("Software\\Microsoft\\Windows".to_owned()),
            0x4000,
        ));
        assert_eq!(
            set.matches(&Feature::StringSubstring("microsoft\\windows".to_owned())),
            vec![0x4000]
        );
    }

    #[test]
    fn string_exact_is_case_and_whole_value_sensitive() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::String("cmd.exe".to_owned()),
            0x5000,
        ));
        assert_eq!(
            set.matches(&Feature::StringExact("cmd.exe".to_owned())),
            vec![0x5000]
        );
        assert!(
            set.matches(&Feature::StringExact("CMD.EXE".to_owned()))
                .is_empty()
        );
        assert!(
            set.matches(&Feature::StringExact("cmd".to_owned()))
                .is_empty()
        );
    }

    #[test]
    fn string_regex_matches_pattern() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::String("https://198.51.100.23/gate.php".to_owned()),
            0x6000,
        ));
        assert_eq!(
            set.matches(&Feature::StringRegex(
                r"https?://\d{1,3}(\.\d{1,3}){3}/".to_owned()
            )),
            vec![0x6000]
        );
        assert!(
            set.matches(&Feature::StringRegex(r"^ftp://".to_owned()))
                .is_empty()
        );
        assert!(
            set.matches(&Feature::StringRegex("(".to_owned()))
                .is_empty()
        );
    }

    #[test]
    fn operand_indexed_number_matches_only_its_slot() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Operand {
                index: 1,
                inner: OperandValue::Number(0x60),
            },
            0x10,
        ));
        assert_eq!(
            set.matches(&Feature::Operand {
                index: 1,
                inner: OperandFeature::Number(0x60),
            }),
            vec![0x10]
        );
        assert!(
            set.matches(&Feature::Operand {
                index: 0,
                inner: OperandFeature::Number(0x60),
            })
            .is_empty()
        );
    }

    #[test]
    fn global_os_arch_format_match_case_insensitively() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(FeatureValue::Os("windows".to_owned()), 0x0));
        set.push(FeatureHit::new(
            FeatureValue::Arch("x86_64".to_owned()),
            0x0,
        ));
        set.push(FeatureHit::new(FeatureValue::Format("pe".to_owned()), 0x0));
        assert_eq!(set.matches(&Feature::Os("Windows".to_owned())), vec![0x0]);
        assert_eq!(set.matches(&Feature::Arch("X86_64".to_owned())), vec![0x0]);
        assert_eq!(set.matches(&Feature::Format("PE".to_owned())), vec![0x0]);
        assert!(set.matches(&Feature::Os("linux".to_owned())).is_empty());
    }

    #[test]
    fn import_export_section_features_match() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Import("kernel32!CreateFileW".to_owned()),
            0x1000,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Export("Run".to_owned()),
            0x2000,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Section(".vmp0".to_owned()),
            0x3000,
        ));
        assert_eq!(
            set.matches(&Feature::Import("CreateFile".to_owned())),
            vec![0x1000]
        );
        assert_eq!(
            set.matches(&Feature::Export("run".to_owned())),
            vec![0x2000]
        );
        assert_eq!(
            set.matches(&Feature::Section(".vmp0".to_owned())),
            vec![0x3000]
        );
    }

    #[test]
    fn count_tallies_every_matching_hit() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("push".to_owned()),
            0x1,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("push".to_owned()),
            0x2,
        ));
        set.push(FeatureHit::new(
            FeatureValue::Mnemonic("push".to_owned()),
            0x3,
        ));
        assert_eq!(set.count(&Feature::Mnemonic("push".to_owned())), 3);
        assert_eq!(set.count(&Feature::Mnemonic("pop".to_owned())), 0);
    }

    #[test]
    fn bytes_feature_matches_window() {
        let mut set: FeatureSet = FeatureSet::new();
        set.push(FeatureHit::new(
            FeatureValue::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44]),
            0x2000,
        ));
        assert_eq!(set.matches(&Feature::Bytes(vec![0x22, 0x33])), vec![0x2000]);
        assert!(set.matches(&Feature::Bytes(vec![0x22, 0x44])).is_empty());
    }
}
