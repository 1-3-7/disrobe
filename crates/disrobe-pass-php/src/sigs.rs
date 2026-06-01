use memchr::memmem;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignatureFamily {
    Blackbird,
    Smuggler,
    WebShell,
    PhpEncoderOnline,
    ObfuscationInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHit {
    pub family: SignatureFamily,
    pub label: String,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub hits: Vec<SignatureHit>,
    pub families: BTreeMap<SignatureFamily, u32>,
}

const BLACKBIRD_NEEDLES: &[(&[u8], &str)] = &[
    (b"$_GLOBALS[\"blackbird\"", "global-handle"),
    (b"blackbird_loader", "loader"),
    (b"<<<blackbird>>>", "marker"),
];

const SMUGGLER_NEEDLES: &[(&[u8], &str)] = &[
    (b"smuggler::decode", "static-decode"),
    (b"SMG_PAYLOAD_", "payload-const"),
    (b"/*SMG-BEGIN*/", "marker"),
];

const WEBSHELL_NEEDLES: &[(&[u8], &str)] = &[
    (b"r57shell", "r57"),
    (b"c99shell", "c99"),
    (b"FilesMan", "filesman"),
    (b"WSO ", "wso"),
    (b"b374k", "b374k"),
    (b"<?php @eval($_POST", "post-eval"),
    (b"assert($_REQUEST", "req-assert"),
    (b"system($_GET", "get-system"),
    (b"shell_exec($_REQUEST", "req-shellexec"),
];

const PHP_ENCODER_ONLINE_NEEDLES: &[(&[u8], &str)] = &[
    (b"// PHP Encoder online", "comment-banner"),
    (b"phpencoderonline.com", "vendor-url"),
    (b"$_=\"\\x65\\x76\\x61\\x6c\"", "eval-hex-alias"),
];

const OBFUSCATION_INFO_NEEDLES: &[(&[u8], &str)] = &[
    (b"obfuscation.info", "vendor-url"),
    (b"//OI-WRAP-START", "marker-start"),
    (b"//OI-WRAP-END", "marker-end"),
];

pub fn scan(bytes: &[u8]) -> ScanReport {
    let mut hits: Vec<SignatureHit> = Vec::new();
    let mut families: BTreeMap<SignatureFamily, u32> = BTreeMap::new();
    scan_family(
        bytes,
        BLACKBIRD_NEEDLES,
        SignatureFamily::Blackbird,
        &mut hits,
        &mut families,
    );
    scan_family(
        bytes,
        SMUGGLER_NEEDLES,
        SignatureFamily::Smuggler,
        &mut hits,
        &mut families,
    );
    scan_family(
        bytes,
        WEBSHELL_NEEDLES,
        SignatureFamily::WebShell,
        &mut hits,
        &mut families,
    );
    scan_family(
        bytes,
        PHP_ENCODER_ONLINE_NEEDLES,
        SignatureFamily::PhpEncoderOnline,
        &mut hits,
        &mut families,
    );
    scan_family(
        bytes,
        OBFUSCATION_INFO_NEEDLES,
        SignatureFamily::ObfuscationInfo,
        &mut hits,
        &mut families,
    );
    ScanReport { hits, families }
}

fn scan_family(
    bytes: &[u8],
    needles: &[(&[u8], &str)],
    family: SignatureFamily,
    hits: &mut Vec<SignatureHit>,
    families: &mut BTreeMap<SignatureFamily, u32>,
) {
    for (needle, label) in needles {
        let mut start: usize = 0;
        while let Some(idx) = memmem::find(&bytes[start..], needle) {
            let absolute: usize = start + idx;
            hits.push(SignatureHit {
                family,
                label: (*label).to_string(),
                offset: absolute,
            });
            *families.entry(family).or_insert(0) += 1;
            start = absolute + needle.len();
        }
    }
}
