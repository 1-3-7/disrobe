use std::collections::BTreeSet;
use std::io::Cursor;

use disrobe_core::codec::cipher::rc4_apply;
use disrobe_core::codec::{CbcPadding, adler32, aes_cbc_decrypt, hex_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::axml::{self, AxmlDocument, AxmlElement};

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
const MAX_ENTRY_BYTES: u64 = 64 << 20;
const MAX_ENTRIES: usize = 1 << 16;
const MAX_RECOVERED_DEX: usize = 64;
const DEX_HEADER_LEN: usize = 0x70;
const OPEN_SOURCE_JIAGU_KEY: &[u8; 16] = b"bajk3b4j3bvuoa3h";
const OPEN_SOURCE_JIAGU_IV: &[u8; 16] = b"mers46ha35ga23hn";
const OPEN_SOURCE_JIAGU_SEALED: usize = 528;
const OPEN_SOURCE_JIAGU_HEADER_XOR: u8 = 0x66;
const DEXHELPER_RC4_KEY: [u8; 16] = [
    0x66, 0x97, 0x6c, 0xe8, 0x6d, 0x46, 0x38, 0xb0, 0x09, 0x5a, 0xa5, 0xd7, 0x0f, 0xcb, 0x9a, 0xa0,
];
const DEXHELPER_RC4_SPAN: usize = 0x2_0000;
const DEXHELPER_TAIL_XOR: u8 = 0xac;
const PANGXIE_XOR: u8 = 0x54;
const JIAGU_TAIL_MAGIC: [u8; 4] = [0x71, 0x68, 0x00, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApkPacker {
    Jiagu360,
    Bangcle,
    SecneoDexHelper,
    Ijiami,
    TencentLegu,
    BaiduProtect,
    AliMobisec,
    DexProtector,
    AppGuardInca,
    AppGuardNhn,
    PromonShield,
    ApkProtect,
    NqShield,
    Naga,
    Liapp,
    Pangxie,
    OpenSourceJiagu,
}

impl ApkPacker {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Jiagu360 => "Qihoo 360 Jiagu",
            Self::Bangcle => "Bangcle",
            Self::SecneoDexHelper => "SecNeo DexHelper",
            Self::Ijiami => "ijiami",
            Self::TencentLegu => "Tencent Legu",
            Self::BaiduProtect => "Baidu protect",
            Self::AliMobisec => "Alibaba mobisec",
            Self::DexProtector => "DexProtector",
            Self::AppGuardInca => "AppGuard (INCA nProtect)",
            Self::AppGuardNhn => "AppGuard (NHN)",
            Self::PromonShield => "Promon SHIELD",
            Self::ApkProtect => "APKProtect",
            Self::NqShield => "NQ Shield",
            Self::Naga => "Naga",
            Self::Liapp => "LIAPP",
            Self::Pangxie => "Pangxie",
            Self::OpenSourceJiagu => "open-source Jiagu (Frezrik)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorKind {
    Entry,
    ApplicationClass,
    DexClass,
    AppendedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackerAnchor {
    pub kind: AnchorKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadState {
    Recovered,
    EncryptedStaticKeyUnknown,
    EncryptedRuntimeKey,
    NotADexPacker,
    Undocumented,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredDex {
    pub source: String,
    pub size: usize,
    pub sha256: String,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerFinding {
    pub packer: ApkPacker,
    pub label: String,
    pub anchors: Vec<PackerAnchor>,
    pub payload_path: Option<String>,
    pub payload: PayloadState,
    pub note: String,
    pub recovered: Vec<RecoveredDex>,
}

#[derive(Debug, Clone, Copy)]
enum PathRule {
    Exact(&'static str),
    Lib(&'static str),
    LibPrefixSuffix(&'static str, &'static str),
    Prefix(&'static str),
}

impl PathRule {
    fn matches(self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => path == exact,
            Self::Lib(name) => lib_name(path) == Some(name),
            Self::LibPrefixSuffix(prefix, suffix) => {
                lib_name(path).is_some_and(|n: &str| n.starts_with(prefix) && n.ends_with(suffix))
            }
            Self::Prefix(prefix) => path.starts_with(prefix) && path.len() > prefix.len(),
        }
    }
}

fn lib_name(path: &str) -> Option<&str> {
    let rest: &str = path.strip_prefix("lib/")?;
    let (abi, name): (&str, &str) = rest.split_once('/')?;
    (!abi.is_empty() && !name.contains('/')).then_some(name)
}

struct Rule {
    packer: ApkPacker,
    strong: &'static [PathRule],
    weak: &'static [PathRule],
    applications: &'static [&'static str],
    classes: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        packer: ApkPacker::Jiagu360,
        strong: &[
            PathRule::Exact("assets/libjiagu.so"),
            PathRule::Exact("assets/libjiagu_art.so"),
            PathRule::Exact("assets/libjiagu_a64.so"),
            PathRule::Exact("assets/libjiagu_x86.so"),
            PathRule::Exact("assets/libjiagu_x64.so"),
            PathRule::Exact("assets/libprotectClass.so"),
            PathRule::Exact("assets/libprotectClass_x86.so"),
            PathRule::Exact("assets/libqupc.so"),
        ],
        weak: &[],
        applications: &["com.stub.StubApp", "com.qihoo.util.StubApplication"],
        classes: &[
            "Lcom/stub/StubApp;",
            "Lcom/qihoo/util/StubApplication;",
            "Lcom/qihoo/util/DefenceReport;",
        ],
    },
    Rule {
        packer: ApkPacker::Bangcle,
        strong: &[
            PathRule::Lib("libsecexe.so"),
            PathRule::Lib("libsecmain.so"),
            PathRule::Exact("assets/libsecexe.x86.so"),
            PathRule::Exact("assets/libsecmain.x86.so"),
            PathRule::Exact("assets/bangcle_classes.jar"),
            PathRule::Prefix("assets/bangcleplugin/"),
        ],
        weak: &[PathRule::Prefix("assets/meta-data/")],
        applications: &[
            "com.bangcle.protect.ApplicationWrapper",
            "com.bangcle.protect.FirstApplication",
        ],
        classes: &[
            "Lcom/bangcle/protect/ApplicationWrapper;",
            "Lcom/bangcle/protect/ACall;",
        ],
    },
    Rule {
        packer: ApkPacker::SecneoDexHelper,
        strong: &[
            PathRule::Lib("libDexHelper.so"),
            PathRule::Lib("libDexHelper-x86.so"),
            PathRule::Lib("libSecShell.so"),
            PathRule::Exact("assets/secData0.jar"),
        ],
        weak: &[
            PathRule::Exact("assets/classes0.jar"),
            PathRule::Exact("assets/classes.dgc"),
        ],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::Ijiami,
        strong: &[
            PathRule::Exact("assets/ijiami.dat"),
            PathRule::Lib("libexecmain.so"),
            PathRule::Prefix("assets/ijm_lib/"),
        ],
        weak: &[
            PathRule::Lib("libexec.so"),
            PathRule::Exact("META-INF/signed.bin"),
            PathRule::Exact("META-INF/af.bin"),
            PathRule::Exact("META-INF/sdata.bin"),
        ],
        applications: &["com.shell.SuperApplication", "com.shell.NativeApplication"],
        classes: &[
            "Lcom/shell/SuperApplication;",
            "Lcom/shell/NativeApplication;",
        ],
    },
    Rule {
        packer: ApkPacker::TencentLegu,
        strong: &[
            PathRule::LibPrefixSuffix("libshella-", ".so"),
            PathRule::LibPrefixSuffix("libshellx-", ".so"),
            PathRule::Lib("libshell-super.2019.so"),
            PathRule::Exact("assets/0OO00l111l1l"),
            PathRule::Exact("assets/0OO00oo01l1l"),
            PathRule::Exact("assets/o0oooOO0ooOo.dat"),
        ],
        weak: &[
            PathRule::Exact("assets/tosversion"),
            PathRule::Lib("libshell.so"),
        ],
        applications: &["com.tencent.StubShell.TxAppEntry"],
        classes: &[
            "Lcom/tencent/StubShell/TxAppEntry;",
            "Lcom/tencent/StubShell/ProxyShell;",
        ],
    },
    Rule {
        packer: ApkPacker::BaiduProtect,
        strong: &[
            PathRule::Lib("libbaiduprotect.so"),
            PathRule::Exact("assets/baiduprotect.jar"),
            PathRule::Exact("assets/baiduprotect1.jar"),
            PathRule::Exact("assets/libbaiduprotect_x86.so"),
        ],
        weak: &[],
        applications: &["com.baidu.protect.StubApplication"],
        classes: &["Lcom/baidu/protect/StubApplication;"],
    },
    Rule {
        packer: ApkPacker::AliMobisec,
        strong: &[
            PathRule::Lib("libmobisec.so"),
            PathRule::LibPrefixSuffix("libmobisecx", ".so"),
            PathRule::LibPrefixSuffix("libmobisecy", ".so"),
            PathRule::LibPrefixSuffix("libmobisecz", ".so"),
        ],
        weak: &[],
        applications: &["com.ali.mobisecenhance.StubApplication"],
        classes: &["Lcom/ali/mobisecenhance/StubApplication;"],
    },
    Rule {
        packer: ApkPacker::DexProtector,
        strong: &[
            PathRule::LibPrefixSuffix("libdexprotector", ".so"),
            PathRule::Exact("assets/classes.dex.dat"),
            PathRule::Exact("assets/dp.mp3"),
        ],
        weak: &[
            PathRule::Lib("libalice.so"),
            PathRule::Exact("assets/resources.dat"),
            PathRule::Exact("assets/ic.dat"),
        ],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::AppGuardInca,
        strong: &[PathRule::Prefix("assets/appguard/")],
        weak: &[PathRule::Lib("libcompatible.so")],
        applications: &[],
        classes: &[
            "Lcom/inca/security/Core/AppGuardEngine;",
            "Lcom/inca/security/Core/UnsafeDexLoader;",
        ],
    },
    Rule {
        packer: ApkPacker::AppGuardNhn,
        strong: &[PathRule::Lib("libdiresu.so")],
        weak: &[PathRule::Lib("libloader.so")],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::PromonShield,
        strong: &[
            PathRule::Lib("libshield.so"),
            PathRule::LibPrefixSuffix("libshield.", ".so"),
            PathRule::Exact("assets/pbi.bin"),
            PathRule::Exact("assets/config-encrypt.txt"),
        ],
        weak: &[PathRule::Exact("assets/mappings.bin")],
        applications: &[],
        classes: &["Lno/promon/shield/"],
    },
    Rule {
        packer: ApkPacker::ApkProtect,
        strong: &[
            PathRule::Lib("libapkprotect2.so"),
            PathRule::Lib("libAPKProtect.so"),
        ],
        weak: &[],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::NqShield,
        strong: &[PathRule::Lib("libnqshield.so")],
        weak: &[],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::Naga,
        strong: &[PathRule::Lib("libchaosvmp.so")],
        weak: &[PathRule::Lib("libddog.so"), PathRule::Lib("libfdog.so")],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::Liapp,
        strong: &[PathRule::Exact("assets/LIAPP.ini")],
        weak: &[PathRule::Exact("LIAPPEgg")],
        applications: &[],
        classes: &[],
    },
    Rule {
        packer: ApkPacker::Pangxie,
        strong: &[PathRule::Lib("libnsecure.so")],
        weak: &[],
        applications: &["com.merry.wapper.WapperApplication"],
        classes: &["Lcom/merry/wapper/WapperApplication;"],
    },
    Rule {
        packer: ApkPacker::OpenSourceJiagu,
        strong: &[],
        weak: &[],
        applications: &["com.frezrik.jiagu.StubApp"],
        classes: &["Lcom/frezrik/jiagu/StubApp;"],
    },
];

struct ApkView {
    names: Vec<String>,
    application: Option<String>,
    dex: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackerScanError {
    #[error("the archive is not a readable zip: {0}")]
    Zip(String),
    #[error("the archive holds {count} entries, above the {MAX_ENTRIES} entry bound")]
    TooManyEntries { count: usize },
}

pub fn detect_packers(apk: &[u8]) -> Result<Vec<PackerFinding>, PackerScanError> {
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(Cursor::new(apk))
        .map_err(|error: zip::result::ZipError| PackerScanError::Zip(error.to_string()))?;
    if archive.len() > MAX_ENTRIES {
        return Err(PackerScanError::TooManyEntries {
            count: archive.len(),
        });
    }
    let view: ApkView = read_view(&mut archive);
    let mut findings: Vec<PackerFinding> = Vec::new();
    for rule in RULES {
        let anchors: Vec<PackerAnchor> = anchors_for(rule, &view);
        let strong: usize = anchors
            .iter()
            .filter(|a: &&PackerAnchor| {
                a.kind == AnchorKind::Entry
                    && rule.strong.iter().any(|r: &PathRule| r.matches(&a.value))
            })
            .count();
        let corroborating: usize = anchors.len() - strong;
        let open_source: bool = rule.packer == ApkPacker::OpenSourceJiagu;
        let appended: Option<(String, Vec<RecoveredDex>)> = if open_source {
            open_source_jiagu_payload(&view)
        } else {
            None
        };
        let detected: bool = if open_source {
            appended.is_some() && corroborating > 0
        } else {
            strong >= 1 || corroborating >= 2
        };
        if !detected {
            continue;
        }
        let mut anchors: Vec<PackerAnchor> = anchors;
        if let Some((source, _)) = &appended {
            anchors.push(PackerAnchor {
                kind: AnchorKind::AppendedPayload,
                value: source.clone(),
            });
        }
        findings.push(payload_finding(
            rule.packer,
            anchors,
            &view,
            &mut archive,
            appended,
        ));
    }
    Ok(findings)
}

fn read_view(archive: &mut ZipArchive<Cursor<&[u8]>>) -> ApkView {
    let mut names: Vec<String> = Vec::with_capacity(archive.len());
    let mut application: Option<String> = None;
    let mut dex: Vec<(String, Vec<u8>)> = Vec::new();
    for index in 0..archive.len() {
        let Ok(file) = archive.by_index(index) else {
            continue;
        };
        let name: String = file.name().to_owned();
        drop(file);
        if name == "AndroidManifest.xml"
            && let Some(raw) = read_entry(archive, &name)
            && let Ok(doc) = axml::parse(&raw)
        {
            application = application_class(&doc);
        }
        if crate::pass::is_top_level_dex_name(&name)
            && dex.len() < MAX_RECOVERED_DEX
            && let Some(raw) = read_entry(archive, &name)
        {
            dex.push((name.clone(), raw));
        }
        names.push(name);
    }
    names.sort();
    ApkView {
        names,
        application,
        dex,
    }
}

fn read_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let file: zip::read::ZipFile<'_> = archive.by_name(name).ok()?;
    if file.size() > MAX_ENTRY_BYTES {
        return None;
    }
    crate::read_zip_file_bounded(file, name).ok()
}

fn application_class(doc: &AxmlDocument) -> Option<String> {
    let package: Option<&str> = attribute(&doc.root, "package", false);
    let application: &AxmlElement = doc
        .root
        .descendants()
        .find(|el: &&AxmlElement| el.name == "application")?;
    let name: &str = attribute(application, "name", true)?;
    Some(match (name.strip_prefix('.'), package) {
        (Some(relative), Some(package)) => format!("{package}.{relative}"),
        _ => name.to_owned(),
    })
}

fn attribute<'a>(el: &'a AxmlElement, name: &str, android: bool) -> Option<&'a str> {
    el.attributes
        .iter()
        .find(|a: &&crate::axml::AxmlAttribute| {
            a.name == name
                && if android {
                    a.namespace
                        .as_deref()
                        .is_none_or(|ns: &str| ns == ANDROID_NS)
                } else {
                    a.namespace.is_none()
                }
        })
        .map(|a: &crate::axml::AxmlAttribute| a.value.as_str())
}

fn anchors_for(rule: &Rule, view: &ApkView) -> Vec<PackerAnchor> {
    let mut anchors: BTreeSet<PackerAnchor> = BTreeSet::new();
    for name in &view.names {
        if rule
            .strong
            .iter()
            .chain(rule.weak)
            .any(|r: &PathRule| r.matches(name))
        {
            anchors.insert(PackerAnchor {
                kind: AnchorKind::Entry,
                value: name.clone(),
            });
        }
    }
    if let Some(application) = &view.application
        && rule.applications.contains(&application.as_str())
    {
        anchors.insert(PackerAnchor {
            kind: AnchorKind::ApplicationClass,
            value: application.clone(),
        });
    }
    for class in rule.classes {
        if view
            .dex
            .iter()
            .any(|(_, bytes): &(String, Vec<u8>)| contains(bytes, class.as_bytes()))
        {
            anchors.insert(PackerAnchor {
                kind: AnchorKind::DexClass,
                value: (*class).to_owned(),
            });
        }
    }
    anchors.into_iter().collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn payload_finding(
    packer: ApkPacker,
    anchors: Vec<PackerAnchor>,
    view: &ApkView,
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    appended: Option<(String, Vec<RecoveredDex>)>,
) -> PackerFinding {
    let first_present = |candidates: &[&str]| -> Option<String> {
        candidates
            .iter()
            .find(|c: &&&str| view.names.iter().any(|n: &String| n == **c))
            .map(|c: &&str| (*c).to_owned())
    };
    let (payload_path, payload, note, recovered): (
        Option<String>,
        PayloadState,
        &str,
        Vec<RecoveredDex>,
    ) = match packer {
        ApkPacker::OpenSourceJiagu => {
            let (path, dex): (String, Vec<RecoveredDex>) = appended.unwrap_or_default();
            (
                Some(path),
                PayloadState::Recovered,
                "the original dex files sit after the stub dex: the first 528 bytes are AES-128-CBC \
                 under the key and IV in the packer's public source, later dex headers are xored \
                 with 0x66",
                dex,
            )
        }
        ApkPacker::SecneoDexHelper => {
            let recovered: Vec<RecoveredDex> = dexhelper_payload(archive);
            if recovered.is_empty() {
                (
                    first_present(&["assets/classes0.jar", "assets/secData0.jar"]),
                    PayloadState::EncryptedStaticKeyUnknown,
                    "the payload did not open with the one published RC4 key; that key differs \
                     between releases",
                    recovered,
                )
            } else {
                (
                    Some("assets/classes0.jar".to_owned()),
                    PayloadState::Recovered,
                    "the first 128 KiB of the jar's dex entry are RC4 under the published key and \
                     the rest is xored with 0xAC",
                    recovered,
                )
            }
        }
        ApkPacker::Pangxie => {
            let recovered: Vec<RecoveredDex> =
                xor_asset_payloads(archive, &view.names, PANGXIE_XOR);
            let state: PayloadState = if recovered.is_empty() {
                PayloadState::EncryptedStaticKeyUnknown
            } else {
                PayloadState::Recovered
            };
            (
                recovered.first().map(|r: &RecoveredDex| r.source.clone()),
                state,
                "the original dex is an asset xored with the single byte 0x54",
                recovered,
            )
        }
        ApkPacker::Jiagu360 => (
            jiagu_tail(view),
            PayloadState::EncryptedStaticKeyUnknown,
            "the payload is the tail of the stub classes.dex after its declared size; one \
             published sample decrypts it with RC4 under a constant key and then a second stage \
             whose format is not documented, so it is located and not recovered",
            Vec::new(),
        ),
        ApkPacker::TencentLegu => (
            first_present(&["assets/0OO00l111l1l", "assets/0OO00oo01l1l"]),
            PayloadState::EncryptedStaticKeyUnknown,
            "the container holds NRV-compressed dex files and method bodies under XTEA with a key \
             derived from assets/tosversion; recovery is not implemented",
            Vec::new(),
        ),
        ApkPacker::Bangcle => (
            first_present(&["assets/bangcle_classes.jar"]),
            PayloadState::EncryptedRuntimeKey,
            "the encrypted dex is decrypted by the native runtime with a key that is not present \
             in the package",
            Vec::new(),
        ),
        ApkPacker::Ijiami => (
            first_present(&["assets/ijiami.dat"]),
            PayloadState::EncryptedRuntimeKey,
            "the encrypted application is checked and decrypted by libexec.so at run time",
            Vec::new(),
        ),
        ApkPacker::BaiduProtect => (
            first_present(&["assets/baiduprotect1.jar", "assets/baiduprotect.jar"]),
            PayloadState::EncryptedRuntimeKey,
            "method bodies are restored at run time; no static key is published",
            Vec::new(),
        ),
        ApkPacker::AliMobisec => (
            None,
            PayloadState::EncryptedRuntimeKey,
            "the dex is decrypted with RC4 and LZMA by the native library at run time; the key is \
             not published",
            Vec::new(),
        ),
        ApkPacker::DexProtector => (
            first_present(&["assets/classes.dex.dat"]),
            PayloadState::EncryptedRuntimeKey,
            "the container key mixes run-time linker state, signing material and an image hash",
            Vec::new(),
        ),
        ApkPacker::AppGuardInca => (
            view.names
                .iter()
                .find(|n: &&String| n.starts_with("assets/appguard/") && n.ends_with(".sox"))
                .cloned(),
            PayloadState::EncryptedRuntimeKey,
            "the .sox engine files are wrapped with RSA and AES and unwrapped at run time",
            Vec::new(),
        ),
        ApkPacker::PromonShield => (
            first_present(&["assets/pbi.bin"]),
            PayloadState::NotADexPacker,
            "strings and constants move into native calls and pbi.bin under white-box AES; the dex \
             itself is not packed",
            Vec::new(),
        ),
        ApkPacker::AppGuardNhn
        | ApkPacker::ApkProtect
        | ApkPacker::NqShield
        | ApkPacker::Naga
        | ApkPacker::Liapp => (
            None,
            PayloadState::Undocumented,
            "no public description of the payload format exists",
            Vec::new(),
        ),
    };
    PackerFinding {
        packer,
        label: packer.label().to_owned(),
        anchors,
        payload_path,
        payload,
        note: note.to_owned(),
        recovered,
    }
}

fn read_u32_be(bytes: &[u8], at: usize) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(raw)).ok()
}

fn declared_dex_size(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"dex\n") {
        return None;
    }
    let raw: [u8; 4] = bytes.get(32..36)?.try_into().ok()?;
    usize::try_from(u32::from_le_bytes(raw)).ok()
}

fn valid_dex(bytes: &[u8]) -> bool {
    let Some(declared) = declared_dex_size(bytes) else {
        return false;
    };
    if declared != bytes.len() || bytes.len() < DEX_HEADER_LEN {
        return false;
    }
    let stored: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    adler32(1, &bytes[12..]) == stored
}

fn recovered(source: String, bytes: Vec<u8>) -> RecoveredDex {
    let digest: String = hex_encode(&Sha256::digest(&bytes));
    RecoveredDex {
        source,
        size: bytes.len(),
        sha256: digest,
        bytes,
    }
}

fn open_source_jiagu_payload(view: &ApkView) -> Option<(String, Vec<RecoveredDex>)> {
    let (name, bytes): &(String, Vec<u8>) =
        view.dex.iter().find(|(name, _)| name == "classes.dex")?;
    let shell: usize = declared_dex_size(bytes)?;
    let trailer: usize = bytes.len().checked_sub(4)?;
    if read_u32_be(bytes, trailer)? != shell || shell >= trailer {
        return None;
    }
    let sealed: &[u8] = bytes.get(shell..shell.checked_add(OPEN_SOURCE_JIAGU_SEALED)?)?;
    let mut block: Vec<u8> = aes_cbc_decrypt(
        OPEN_SOURCE_JIAGU_KEY,
        OPEN_SOURCE_JIAGU_IV,
        sealed,
        CbcPadding::Pkcs7,
    )
    .ok()?;
    block.extend_from_slice(bytes.get(shell + OPEN_SOURCE_JIAGU_SEALED..trailer)?);
    let name_len: usize = usize::from(*block.first()?);
    let mut cursor: usize = 1 + name_len;
    let mut out: Vec<RecoveredDex> = Vec::new();
    while cursor < block.len() && out.len() < MAX_RECOVERED_DEX {
        let length: usize = read_u32_be(&block, cursor)?;
        cursor += 4;
        let end: usize = cursor.checked_add(length)?;
        let mut dex: Vec<u8> = block.get(cursor..end)?.to_vec();
        if !out.is_empty() {
            for byte in dex.iter_mut().take(DEX_HEADER_LEN) {
                *byte ^= OPEN_SOURCE_JIAGU_HEADER_XOR;
            }
        }
        if !valid_dex(&dex) {
            return None;
        }
        out.push(recovered(format!("{name}@{cursor}"), dex));
        cursor = end;
    }
    (!out.is_empty()).then(|| (name.clone(), out))
}

fn dexhelper_payload(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Vec<RecoveredDex> {
    let Some(jar) = read_entry(archive, "assets/classes0.jar") else {
        return Vec::new();
    };
    let Ok(mut inner) = ZipArchive::new(Cursor::new(jar.as_slice())) else {
        return Vec::new();
    };
    if inner.is_empty() {
        return Vec::new();
    }
    let Ok(first) = inner.by_index(0) else {
        return Vec::new();
    };
    let entry: String = first.name().to_owned();
    drop(first);
    let Some(sealed) = read_entry(&mut inner, &entry) else {
        return Vec::new();
    };
    let split: usize = sealed.len().min(DEXHELPER_RC4_SPAN);
    let mut dex: Vec<u8> = rc4_apply(&DEXHELPER_RC4_KEY, &sealed[..split]);
    dex.extend(sealed[split..].iter().map(|b: &u8| b ^ DEXHELPER_TAIL_XOR));
    if valid_dex(&dex) {
        vec![recovered(format!("assets/classes0.jar!{entry}"), dex)]
    } else {
        Vec::new()
    }
}

fn xor_asset_payloads(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    names: &[String],
    key: u8,
) -> Vec<RecoveredDex> {
    let mut out: Vec<RecoveredDex> = Vec::new();
    for name in names.iter().filter(|n: &&String| n.starts_with("assets/")) {
        if out.len() >= MAX_RECOVERED_DEX {
            break;
        }
        let Some(raw) = read_entry(archive, name) else {
            continue;
        };
        if raw.len() < DEX_HEADER_LEN || raw[..4].iter().map(|b: &u8| b ^ key).ne(*b"dex\n") {
            continue;
        }
        let dex: Vec<u8> = raw.iter().map(|b: &u8| b ^ key).collect();
        if valid_dex(&dex) {
            out.push(recovered(name.clone(), dex));
        }
    }
    out
}

fn jiagu_tail(view: &ApkView) -> Option<String> {
    let (name, bytes): &(String, Vec<u8>) =
        view.dex.iter().find(|(name, _)| name == "classes.dex")?;
    let declared: usize = declared_dex_size(bytes)?;
    let tail: &[u8] = bytes.get(declared..)?;
    tail.starts_with(&JIAGU_TAIL_MAGIC)
        .then(|| format!("{name}@{declared}+{}", tail.len()))
}
