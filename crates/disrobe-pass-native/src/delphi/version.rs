use serde::{Deserialize, Serialize};

use super::DelphiEra;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelphiSignalKind {
    VmtEra,
    RuntimePackage,
    UnitScopeNames,
    ToolchainPath,
    ProductLicenseResource,
}

impl DelphiSignalKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VmtEra => "virtual method table layout",
            Self::RuntimePackage => "linked runtime package name",
            Self::UnitScopeNames => "dotted unit scope names in RTTI",
            Self::ToolchainPath => "build toolchain path string",
            Self::ProductLicenseResource => "DVCLAL product license resource",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiVersionSignal {
    pub kind: DelphiSignalKind,
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_package: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_package: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiVersion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    pub signals: Vec<DelphiVersionSignal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Release {
    package: u16,
    product: &'static str,
    ver_symbol: &'static str,
}

const RELEASES: &[Release] = &[
    Release {
        package: 30,
        product: "Delphi 3",
        ver_symbol: "VER100",
    },
    Release {
        package: 40,
        product: "Delphi 4",
        ver_symbol: "VER120",
    },
    Release {
        package: 50,
        product: "Delphi 5",
        ver_symbol: "VER130",
    },
    Release {
        package: 60,
        product: "Delphi 6",
        ver_symbol: "VER140",
    },
    Release {
        package: 70,
        product: "Delphi 7",
        ver_symbol: "VER150",
    },
    Release {
        package: 80,
        product: "Delphi 8",
        ver_symbol: "VER160",
    },
    Release {
        package: 90,
        product: "Delphi 2005",
        ver_symbol: "VER170",
    },
    Release {
        package: 100,
        product: "Delphi 2006",
        ver_symbol: "VER180",
    },
    Release {
        package: 110,
        product: "Delphi 2007",
        ver_symbol: "VER185",
    },
    Release {
        package: 120,
        product: "Delphi 2009",
        ver_symbol: "VER200",
    },
    Release {
        package: 140,
        product: "Delphi 2010",
        ver_symbol: "VER210",
    },
    Release {
        package: 150,
        product: "Delphi XE",
        ver_symbol: "VER220",
    },
    Release {
        package: 160,
        product: "Delphi XE2",
        ver_symbol: "VER230",
    },
    Release {
        package: 161,
        product: "Delphi XE2",
        ver_symbol: "VER230",
    },
    Release {
        package: 170,
        product: "Delphi XE3",
        ver_symbol: "VER240",
    },
    Release {
        package: 180,
        product: "Delphi XE4",
        ver_symbol: "VER250",
    },
    Release {
        package: 190,
        product: "Delphi XE5",
        ver_symbol: "VER260",
    },
    Release {
        package: 200,
        product: "Delphi XE6",
        ver_symbol: "VER270",
    },
    Release {
        package: 210,
        product: "Delphi XE7",
        ver_symbol: "VER280",
    },
    Release {
        package: 220,
        product: "Delphi XE8",
        ver_symbol: "VER290",
    },
    Release {
        package: 230,
        product: "Delphi 10 Seattle",
        ver_symbol: "VER300",
    },
    Release {
        package: 240,
        product: "Delphi 10.1 Berlin",
        ver_symbol: "VER310",
    },
    Release {
        package: 250,
        product: "Delphi 10.2 Tokyo",
        ver_symbol: "VER320",
    },
    Release {
        package: 260,
        product: "Delphi 10.3 Rio",
        ver_symbol: "VER330",
    },
    Release {
        package: 270,
        product: "Delphi 10.4 Sydney",
        ver_symbol: "VER340",
    },
    Release {
        package: 280,
        product: "Delphi 11 Alexandria",
        ver_symbol: "VER350",
    },
    Release {
        package: 290,
        product: "Delphi 12 Athens",
        ver_symbol: "VER360",
    },
    Release {
        package: 370,
        product: "Delphi 13 Florence",
        ver_symbol: "VER370",
    },
];

const STUDIO_DIRS: &[(&str, u16)] = &[
    ("2.0", 80),
    ("3.0", 90),
    ("4.0", 100),
    ("5.0", 110),
    ("6.0", 120),
    ("7.0", 140),
    ("8.0", 150),
    ("9.0", 160),
    ("10.0", 170),
    ("11.0", 180),
    ("12.0", 190),
    ("14.0", 200),
    ("15.0", 210),
    ("16.0", 220),
    ("17.0", 230),
    ("18.0", 240),
    ("19.0", 250),
    ("20.0", 260),
    ("21.0", 270),
    ("22.0", 280),
    ("23.0", 290),
    ("37.0", 370),
];

const BORLAND_DIRS: &[(&str, u16)] = &[
    ("3.0", 30),
    ("4.0", 40),
    ("5.0", 50),
    ("6.0", 60),
    ("7.0", 70),
];

const UNIT_SCOPES: &[&str] = &[
    "System.",
    "Vcl.",
    "Winapi.",
    "Data.",
    "Datasnap.",
    "Soap.",
    "Xml.",
    "Web.",
    "Bde.",
    "FireDAC.",
    "FMX.",
    "IBX.",
    "Posix.",
    "REST.",
];

const STUDIO_PREFIXES: &[&str] = &[
    "Embarcadero\\Studio\\",
    "Embarcadero\\RAD Studio\\",
    "CodeGear\\RAD Studio\\",
];

const BORLAND_PREFIXES: &[&str] = &["Borland\\Delphi\\"];

const SCAN_LIMIT: usize = 8 * 1024 * 1024;
const MAX_PATH_TAIL: usize = 16;

fn release_for(package: u16) -> Option<&'static Release> {
    RELEASES.iter().find(|r: &&Release| r.package == package)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, w): (usize, &[u8])| (w == needle).then_some(i))
        .collect()
}

fn ascii_digits_at(bytes: &[u8], start: usize, max: usize) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    let mut len: usize = 0;
    while len < max {
        let Some(&b): Option<&u8> = bytes.get(start + len) else {
            break;
        };
        if !b.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
        len += 1;
    }
    if len == 0 {
        return None;
    }
    u16::try_from(value).ok().map(|v: u16| (v, len))
}

fn scan_runtime_packages(window: &[u8]) -> Vec<(String, u16)> {
    const STEMS: [&[u8; 3]; 2] = [b"rtl", b"vcl"];
    const SUFFIXES: [&[u8; 4]; 2] = [b".bpl", b".dpl"];
    let mut hits: Vec<(String, u16)> = Vec::new();
    for stem in STEMS {
        let lower: Vec<usize> = find_all(window, stem);
        let upper_stem: [u8; 3] = [
            stem[0].to_ascii_uppercase(),
            stem[1].to_ascii_uppercase(),
            stem[2].to_ascii_uppercase(),
        ];
        let upper: Vec<usize> = find_all(window, &upper_stem);
        for start in lower.into_iter().chain(upper) {
            let digits_at: usize = start + stem.len();
            let Some((package, digit_len)): Option<(u16, usize)> =
                ascii_digits_at(window, digits_at, 4)
            else {
                continue;
            };
            let tail_at: usize = digits_at + digit_len;
            let Some(tail): Option<&[u8]> = window.get(tail_at..tail_at + 4) else {
                continue;
            };
            let matches_suffix: bool = SUFFIXES
                .iter()
                .any(|s: &&[u8; 4]| tail.eq_ignore_ascii_case(*s));
            if !matches_suffix {
                continue;
            }
            let Some(text): Option<&[u8]> = window.get(start..tail_at + 4) else {
                continue;
            };
            let evidence: String = String::from_utf8_lossy(text).into_owned();
            if !hits.iter().any(|h: &(String, u16)| h.0 == evidence) {
                hits.push((evidence, package));
            }
        }
    }
    hits.sort_by(|a: &(String, u16), b: &(String, u16)| a.0.cmp(&b.0));
    hits
}

type PathFamily = (&'static [&'static str], &'static [(&'static str, u16)]);

fn scan_toolchain_paths(window: &[u8]) -> Vec<(String, u16)> {
    let mut hits: Vec<(String, u16)> = Vec::new();
    let families: [PathFamily; 2] = [
        (STUDIO_PREFIXES, STUDIO_DIRS),
        (BORLAND_PREFIXES, BORLAND_DIRS),
    ];
    for (prefixes, dirs) in families {
        for prefix in prefixes {
            for start in find_all(window, prefix.as_bytes()) {
                let tail_at: usize = start + prefix.len();
                let Some(tail): Option<&[u8]> =
                    window.get(tail_at..(tail_at + MAX_PATH_TAIL).min(window.len()))
                else {
                    continue;
                };
                for (dir, package) in dirs {
                    if !tail.starts_with(dir.as_bytes()) {
                        continue;
                    }
                    let evidence: String = format!("{prefix}{dir}");
                    if !hits.iter().any(|h: &(String, u16)| h.0 == evidence) {
                        hits.push((evidence, *package));
                    }
                }
            }
        }
    }
    hits.sort_by(|a: &(String, u16), b: &(String, u16)| a.0.cmp(&b.0));
    hits
}

fn era_signal(era: DelphiEra) -> DelphiVersionSignal {
    let (min, max): (Option<u16>, Option<u16>) = match era {
        DelphiEra::Legacy32 => (None, Some(110)),
        DelphiEra::Modern32 => (Some(120), None),
        DelphiEra::Modern64 => (Some(160), None),
    };
    DelphiVersionSignal {
        kind: DelphiSignalKind::VmtEra,
        evidence: era.label().to_owned(),
        product: None,
        min_package: min,
        max_package: max,
    }
}

fn unit_scope_signal(unit_names: &[String]) -> Option<DelphiVersionSignal> {
    let hit: &String = unit_names.iter().find(|name: &&String| {
        UNIT_SCOPES
            .iter()
            .any(|scope: &&str| name.starts_with(scope))
    })?;
    Some(DelphiVersionSignal {
        kind: DelphiSignalKind::UnitScopeNames,
        evidence: hit.clone(),
        product: None,
        min_package: Some(160),
        max_package: None,
    })
}

pub(super) fn identify(
    bytes: &[u8],
    era: Option<DelphiEra>,
    unit_names: &[String],
    license_resource: Option<&str>,
) -> DelphiVersion {
    let window: &[u8] = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let mut signals: Vec<DelphiVersionSignal> = Vec::new();

    if let Some(era) = era {
        signals.push(era_signal(era));
    }
    for (evidence, package) in scan_runtime_packages(window) {
        signals.push(DelphiVersionSignal {
            kind: DelphiSignalKind::RuntimePackage,
            product: release_for(package).map(|r: &Release| r.product.to_owned()),
            evidence,
            min_package: Some(package),
            max_package: Some(package),
        });
    }
    if let Some(signal) = unit_scope_signal(unit_names) {
        signals.push(signal);
    }
    for (evidence, package) in scan_toolchain_paths(window) {
        signals.push(DelphiVersionSignal {
            kind: DelphiSignalKind::ToolchainPath,
            product: release_for(package).map(|r: &Release| r.product.to_owned()),
            evidence,
            min_package: Some(package),
            max_package: Some(package),
        });
    }
    if let Some(license) = license_resource {
        signals.push(DelphiVersionSignal {
            kind: DelphiSignalKind::ProductLicenseResource,
            evidence: license.to_owned(),
            product: None,
            min_package: None,
            max_package: None,
        });
    }

    resolve(signals)
}

fn resolve(signals: Vec<DelphiVersionSignal>) -> DelphiVersion {
    let mut low: u16 = u16::MIN;
    let mut high: u16 = u16::MAX;
    let mut bounded: bool = false;
    for signal in &signals {
        if let Some(min) = signal.min_package {
            low = low.max(min);
            bounded = true;
        }
        if let Some(max) = signal.max_package {
            high = high.min(max);
            bounded = true;
        }
    }
    if !bounded {
        return DelphiVersion {
            product: None,
            ver_symbol: None,
            package_version: None,
            candidates: Vec::new(),
            signals,
            conflicts: Vec::new(),
        };
    }

    let mut conflicts: Vec<String> = Vec::new();
    if low > high {
        conflicts.push(format!(
            "signals disagree: a lower bound of package {low} cannot hold with an upper bound of package {high}"
        ));
        return DelphiVersion {
            product: None,
            ver_symbol: None,
            package_version: None,
            candidates: Vec::new(),
            signals,
            conflicts,
        };
    }

    let matching: Vec<&'static Release> = RELEASES
        .iter()
        .filter(|r: &&Release| r.package >= low && r.package <= high)
        .collect();

    let mut products: Vec<String> = Vec::new();
    for release in &matching {
        let name: String = release.product.to_owned();
        if !products.contains(&name) {
            products.push(name);
        }
    }

    if products.len() == 1
        && let Some(release) = matching.first()
    {
        return DelphiVersion {
            product: Some(release.product.to_owned()),
            ver_symbol: Some(release.ver_symbol.to_owned()),
            package_version: Some(release.package),
            candidates: Vec::new(),
            signals,
            conflicts,
        };
    }

    if products.is_empty() {
        conflicts.push(format!(
            "no known release has a package version between {low} and {high}"
        ));
    }

    DelphiVersion {
        product: None,
        ver_symbol: None,
        package_version: None,
        candidates: products,
        signals,
        conflicts,
    }
}
