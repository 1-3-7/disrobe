use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawFile {
    pub(super) rule: RawRule,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRule {
    pub(super) meta: RawMeta,
    pub(super) features: Vec<RawNode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawMeta {
    pub(super) name: String,
    #[serde(default)]
    pub(super) namespace: String,
    pub(super) scope: String,
    #[serde(default)]
    pub(super) attack: Vec<String>,
    #[serde(default)]
    pub(super) mbc: Vec<String>,
    #[serde(default)]
    pub(super) description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawNOf {
    pub(super) n: usize,
    pub(super) of: Vec<RawNode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawScope {
    pub(super) at: String,
    pub(super) of: Vec<RawNode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct RawCount {
    pub(super) feature: Box<RawNode>,
    #[serde(default)]
    pub(super) exact: Option<usize>,
    #[serde(default)]
    pub(super) at_least: Option<usize>,
    #[serde(default)]
    pub(super) at_most: Option<usize>,
    #[serde(default)]
    pub(super) range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawOperand {
    pub(super) index: u8,
    #[serde(default)]
    pub(super) number: Option<u64>,
    #[serde(default)]
    pub(super) offset: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(super) enum RawNode {
    And {
        and: Vec<Self>,
    },
    Or {
        or: Vec<Self>,
    },
    Not {
        not: Vec<Self>,
    },
    NOf {
        #[serde(rename = "n-of")]
        n_of: RawNOf,
    },
    Optional {
        optional: Vec<Self>,
    },
    Scope {
        scope: RawScope,
    },
    Count {
        count: RawCount,
    },
    Match {
        #[serde(rename = "match")]
        rule_name: String,
    },
    Api {
        api: String,
    },
    Number {
        number: u64,
    },
    String {
        string: String,
    },
    StringExact {
        #[serde(rename = "string-exact")]
        string_exact: String,
    },
    StringRegex {
        #[serde(rename = "string-regex")]
        string_regex: String,
    },
    Bytes {
        bytes: String,
    },
    Mnemonic {
        mnemonic: String,
    },
    Offset {
        offset: u64,
    },
    Characteristic {
        characteristic: String,
    },
    Operand {
        operand: RawOperand,
    },
    Os {
        os: String,
    },
    Arch {
        arch: String,
    },
    Format {
        format: String,
    },
    Import {
        import: String,
    },
    Export {
        export: String,
    },
    Section {
        section: String,
    },
    CallsTo {
        #[serde(rename = "calls-to")]
        calls_to: String,
    },
    CallsFrom {
        #[serde(rename = "calls-from")]
        calls_from: String,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn kebab_case_tags_round_trip_the_intended_keys() {
        let src: &str =
            "- n-of:\n    n: 2\n    of:\n      - api: tag-alpha\n      - api: tag-beta\n";
        let nodes: Vec<RawNode> = serde_yaml_ng::from_str(src).expect("n-of parses");
        assert!(matches!(
            nodes.as_slice(),
            [RawNode::NOf {
                n_of: RawNOf { n: 2, .. }
            }]
        ));

        let src: &str = "- calls-to: tag-alpha\n";
        let nodes: Vec<RawNode> = serde_yaml_ng::from_str(src).expect("calls-to parses");
        assert!(matches!(nodes.as_slice(), [RawNode::CallsTo { .. }]));

        let src: &str = "- string-regex: \"^tag-.*$\"\n";
        let nodes: Vec<RawNode> = serde_yaml_ng::from_str(src).expect("string-regex parses");
        assert!(matches!(nodes.as_slice(), [RawNode::StringRegex { .. }]));
    }

    #[test]
    fn unknown_key_is_rejected_by_the_strict_schema() {
        let src: &str =
            "rule:\n  meta:\n    name: x\n    scope: file\n    bogus-field: 1\n  features: []\n";
        let result: Result<RawFile, serde_yaml_ng::Error> = serde_yaml_ng::from_str(src);
        assert!(result.is_err());
    }

    #[test]
    fn feature_node_with_extraneous_key_is_rejected() {
        let src: &str = "- api: tag-alpha\n  bogus: 1\n";
        let result: Result<Vec<RawNode>, serde_yaml_ng::Error> = serde_yaml_ng::from_str(src);
        assert!(result.is_err());
    }

    #[test]
    fn ambiguous_two_key_node_is_rejected() {
        let src: &str = "- api: tag-alpha\n  mnemonic: mov\n";
        let result: Result<Vec<RawNode>, serde_yaml_ng::Error> = serde_yaml_ng::from_str(src);
        assert!(result.is_err());
    }
}
