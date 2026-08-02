use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_enabled, dbg_kv, dbg_line};
use crate::pe::{ClrHeader, DataDirectory, PeImage};

const METADATA_ROOT_SIGNATURE: [u8; 4] = [0x42, 0x53, 0x4A, 0x42];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protector {
    ConfuserEx,
    ConfuserEx2,
    Dotfuscator,
    DotfuscatorCe,
    SmartAssembly,
    BabelDotnet,
    DeepSea,
    SpicesNet,
    Goliath,
    Skater,
    DotnetReactor,
    EazfuscatorNet,
    CryptoObfuscator,
    ArmDot,
    AgileNet,
    DotNetPatcher,
    NetCryptor,
    Obfuscar,
    ThemidaDotnet,
    Ilprotector,
    MaxToCode,
    KoiVm,
    BitMono,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GreyZone {
    Green,
    AmberLeaningGreen,
    Amber,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Handling {
    NativeStrip,
    De4dotDelegate,
    GatedDe4dotDelegate,
    Devirtualize,
    DetectOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEvidence {
    NotClaimed,
    RealSample(&'static str),
    ModelledAlgorithm,
    RuntimeKeyed,
}

impl StringEvidence {
    #[must_use]
    pub const fn committed_sample(self) -> Option<&'static str> {
        match self {
            Self::RealSample(path) => Some(path),
            Self::NotClaimed | Self::ModelledAlgorithm | Self::RuntimeKeyed => None,
        }
    }

    #[must_use]
    pub const fn decrypts_strings(self) -> bool {
        matches!(self, Self::RealSample(_) | Self::ModelledAlgorithm)
    }
}

impl Protector {
    pub const ALL: [Self; 23] = [
        Self::ConfuserEx,
        Self::ConfuserEx2,
        Self::Dotfuscator,
        Self::DotfuscatorCe,
        Self::SmartAssembly,
        Self::BabelDotnet,
        Self::DeepSea,
        Self::SpicesNet,
        Self::Goliath,
        Self::Skater,
        Self::DotnetReactor,
        Self::EazfuscatorNet,
        Self::CryptoObfuscator,
        Self::ArmDot,
        Self::AgileNet,
        Self::DotNetPatcher,
        Self::NetCryptor,
        Self::Obfuscar,
        Self::ThemidaDotnet,
        Self::Ilprotector,
        Self::MaxToCode,
        Self::KoiVm,
        Self::BitMono,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConfuserEx => "ConfuserEx",
            Self::ConfuserEx2 => "ConfuserEx2",
            Self::Dotfuscator => "Dotfuscator",
            Self::DotfuscatorCe => "Dotfuscator CE",
            Self::SmartAssembly => "SmartAssembly",
            Self::BabelDotnet => "Babel",
            Self::DeepSea => "DeepSea",
            Self::SpicesNet => "Spices.Net",
            Self::Goliath => "Goliath",
            Self::Skater => "Skater",
            Self::DotnetReactor => ".NET Reactor",
            Self::EazfuscatorNet => "Eazfuscator.NET",
            Self::CryptoObfuscator => "CryptoObfuscator",
            Self::ArmDot => "ArmDot",
            Self::AgileNet => "Agile.NET",
            Self::DotNetPatcher => "DotNetPatcher",
            Self::NetCryptor => "NetCryptor",
            Self::Obfuscar => "Obfuscar",
            Self::ThemidaDotnet => "Themida (.NET wrapper)",
            Self::Ilprotector => "ILProtector",
            Self::MaxToCode => "MaxToCode",
            Self::KoiVm => "KoiVM (ConfuserEx VM)",
            Self::BitMono => "BitMono",
        }
    }

    #[must_use]
    pub const fn grey_zone(self) -> GreyZone {
        match self {
            Self::ConfuserEx
            | Self::ConfuserEx2
            | Self::Dotfuscator
            | Self::DotfuscatorCe
            | Self::SmartAssembly
            | Self::BabelDotnet
            | Self::DeepSea
            | Self::SpicesNet
            | Self::Goliath
            | Self::Skater
            | Self::Obfuscar
            | Self::BitMono => GreyZone::Green,
            Self::DotnetReactor
            | Self::EazfuscatorNet
            | Self::CryptoObfuscator
            | Self::ArmDot
            | Self::AgileNet
            | Self::DotNetPatcher
            | Self::NetCryptor
            | Self::KoiVm => GreyZone::AmberLeaningGreen,
            Self::ThemidaDotnet | Self::Ilprotector | Self::MaxToCode => GreyZone::Amber,
        }
    }

    #[must_use]
    pub const fn handling(self) -> Handling {
        match self {
            Self::ConfuserEx | Self::ConfuserEx2 | Self::DotNetPatcher | Self::NetCryptor => {
                Handling::De4dotDelegate
            }
            Self::Obfuscar
            | Self::Dotfuscator
            | Self::DotfuscatorCe
            | Self::SmartAssembly
            | Self::BabelDotnet
            | Self::DeepSea
            | Self::SpicesNet
            | Self::Goliath
            | Self::Skater
            | Self::BitMono => Handling::NativeStrip,
            Self::DotnetReactor
            | Self::EazfuscatorNet
            | Self::CryptoObfuscator
            | Self::ArmDot
            | Self::AgileNet => Handling::GatedDe4dotDelegate,
            Self::KoiVm => Handling::Devirtualize,
            Self::ThemidaDotnet | Self::Ilprotector | Self::MaxToCode => Handling::DetectOnly,
        }
    }

    #[must_use]
    pub const fn requires_authorization(self) -> bool {
        matches!(
            self,
            Self::DotnetReactor
                | Self::EazfuscatorNet
                | Self::CryptoObfuscator
                | Self::ArmDot
                | Self::AgileNet
        )
    }

    #[must_use]
    pub const fn string_evidence(self) -> StringEvidence {
        match self {
            Self::ConfuserEx2 => {
                StringEvidence::RealSample("corpus/dotnet/SampleConstants.confuserex2.dll")
            }
            Self::Obfuscar => StringEvidence::RealSample(
                "corpus/dotnet/obfuscators/obfuscar/gauntlet/GauntletSample.obfuscar.dll",
            ),
            Self::BitMono => StringEvidence::RealSample(
                "corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll",
            ),
            Self::SmartAssembly
            | Self::BabelDotnet
            | Self::SpicesNet
            | Self::Skater
            | Self::DotnetReactor
            | Self::EazfuscatorNet
            | Self::CryptoObfuscator => StringEvidence::ModelledAlgorithm,
            Self::ThemidaDotnet | Self::Ilprotector | Self::MaxToCode => {
                StringEvidence::RuntimeKeyed
            }
            Self::ConfuserEx
            | Self::Dotfuscator
            | Self::DotfuscatorCe
            | Self::DeepSea
            | Self::Goliath
            | Self::ArmDot
            | Self::AgileNet
            | Self::DotNetPatcher
            | Self::NetCryptor
            | Self::KoiVm => StringEvidence::NotClaimed,
        }
    }

    #[must_use]
    pub const fn signatures(self) -> &'static [&'static [u8]] {
        match self {
            Self::ConfuserEx => &[b"ConfuserEx v", b"ConfusedByAttribute"],
            Self::ConfuserEx2 => &[b"ConfuserEx2", b"ConfusedByAttribute", b"_CoreModule"],
            Self::Dotfuscator => &[b"DotfuscatorAttribute", b"DotfuscatorEnhanced"],
            Self::DotfuscatorCe => &[b"DotfuscatorCE", b"DotfuscatorAttribute"],
            Self::SmartAssembly => &[
                b"SmartAssembly.Attributes",
                b"PoweredByAttribute",
                b"{smartassembly}",
            ],
            Self::BabelDotnet => &[b"BabelAttribute", b"BabelObfuscatorAttribute"],
            Self::DeepSea => &[b"DeepSea", b"DeepSeaObfuscator"],
            Self::SpicesNet => &[b"9rays.Net", b"Spices.Net"],
            Self::Goliath => &[b"Goliath.NET"],
            Self::Skater => &[b"RustemSoft.Skater", b"SkaterObfuscator"],
            Self::DotnetReactor => &[b"Eziriz", b".NET Reactor", b"protect_resource"],
            Self::EazfuscatorNet => &[b"Eazfuscator.NET", b"GetWebRequest", b"<Module>{"],
            Self::CryptoObfuscator => &[b"CryptoObfuscator", b"LogicNP"],
            Self::ArmDot => &[b"ArmDot", b"_ArmDotMutator"],
            Self::AgileNet => &[b"AgileDotNet", b"CliSecure"],
            Self::DotNetPatcher => &[b"DNPatcher", b"DotNetPatcher"],
            Self::NetCryptor => &[b"NETCryptor", b"NetCryptor"],
            Self::Obfuscar => &[b"Obfuscar.Obfuscator", b"<Obfuscar>"],
            Self::ThemidaDotnet => &[b".vmp0", b".themida", b"WinLicense", b"Themida"],
            Self::Ilprotector => &[b"Protect32.dll", b"Protect64.dll", b"ILProtector"],
            Self::MaxToCode => &[b"MaxtoCode", b"NetSafe"],
            Self::KoiVm => &[b"KoiVM", b"#Koi", b"VMDispatcher"],
            Self::BitMono => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionReport {
    pub matches: BTreeMap<Protector, Vec<u32>>,
    pub primary: Option<Protector>,
}

#[must_use]
pub fn is_dotnet_assembly(image: &[u8]) -> bool {
    let Ok(pe): crate::error::Result<PeImage> = crate::pe::parse(image) else {
        return false;
    };
    let Some(dir): Option<DataDirectory> = pe.clr_directory() else {
        return false;
    };
    if dir.rva == 0 {
        return false;
    }
    let Ok(clr): crate::error::Result<ClrHeader> = crate::pe::parse_clr_header(image, &pe) else {
        return false;
    };
    if clr.metadata.rva == 0 {
        return false;
    }
    let Ok(root): crate::error::Result<&[u8]> = pe.slice_at_rva(image, clr.metadata.rva, 4) else {
        return false;
    };
    root == METADATA_ROOT_SIGNATURE
}

#[must_use]
pub fn detect_all(image: &[u8]) -> DetectionReport {
    if !is_dotnet_assembly(image) {
        return DetectionReport {
            matches: BTreeMap::new(),
            primary: None,
        };
    }
    let mut matches: BTreeMap<Protector, Vec<u32>> = BTreeMap::new();
    for protector in Protector::ALL {
        let mut offsets: Vec<u32> = Vec::new();
        for needle in protector.signatures() {
            let mut cursor: usize = 0;
            while let Some(p) = window_find(&image[cursor..], needle) {
                offsets.push(u32::try_from(cursor + p).unwrap_or(u32::MAX));
                cursor += p + 1;
                if offsets.len() > 32 {
                    break;
                }
            }
        }
        if !offsets.is_empty() {
            matches.insert(protector, offsets);
        }
    }
    augment_with_obfuscar_heuristic(image, &mut matches);
    augment_with_bitmono_structural(image, &mut matches);
    let decoys: Vec<DecoyRange> = if matches.contains_key(&Protector::BitMono) {
        antide4dot_decoy_ranges(image)
    } else {
        Vec::new()
    };
    let suppressed: Vec<Protector> = drop_decoy_only_matches(&mut matches, &decoys);
    let primary: Option<Protector> = pick_primary(&matches);
    if dbg_enabled() {
        for (protector, offsets) in &matches {
            dbg_kv("protector-match", || {
                format!(
                    "{} grey={:?} handling={:?} evidence={} first_offset={}",
                    protector.label(),
                    protector.grey_zone(),
                    protector.handling(),
                    offsets.len(),
                    offsets
                        .first()
                        .map_or_else(|| "none".to_string(), |o: &u32| format!("0x{o:x}"))
                )
            });
        }
        for protector in &suppressed {
            dbg_kv("protector-decoy-suppressed", || {
                format!(
                    "{} matched only inside BitMono AntiDe4dot decoy type references",
                    protector.label()
                )
            });
        }
        dbg_line(|| {
            primary.map_or_else(
                || "primary=none (no protector signature matched)".to_string(),
                |p: Protector| {
                    format!(
                        "primary={} (max-evidence pick over {} candidate(s), requires_auth={})",
                        p.label(),
                        matches.len(),
                        p.requires_authorization()
                    )
                },
            )
        });
    }
    DetectionReport { matches, primary }
}

fn nt_signature_antiildasm(image: &[u8]) -> Option<u32> {
    let lfanew: usize =
        usize::try_from(u32::from_le_bytes(image.get(0x3C..0x40)?.try_into().ok()?)).ok()?;
    let sig: u32 = u32::from_le_bytes(image.get(lfanew..lfanew + 4)?.try_into().ok()?);
    (sig & 0x0000_FFFF == 0x0000_4550 && sig != 0x0000_4550).then_some(sig)
}

fn augment_with_bitmono_structural(image: &[u8], matches: &mut BTreeMap<Protector, Vec<u32>>) {
    if matches.contains_key(&Protector::BitMono) {
        return;
    }
    let antiildasm: bool = nt_signature_antiildasm(image).is_some();
    let clr_size_zeroed: bool = crate::pe::parse(image).is_ok_and(|pe: crate::pe::PeImage| {
        pe.clr_directory()
            .is_some_and(|d: crate::pe::DataDirectory| d.rva != 0 && d.size == 0)
    });
    if antiildasm && clr_size_zeroed {
        matches.insert(
            Protector::BitMono,
            vec![u32::from(antiildasm), u32::from(clr_size_zeroed)],
        );
    }
}

fn augment_with_obfuscar_heuristic(image: &[u8], matches: &mut BTreeMap<Protector, Vec<u32>>) {
    if matches.contains_key(&Protector::Obfuscar) {
        return;
    }
    let evidence: crate::peel::obfuscar::ObfuscarEvidence = match crate::peel::read_heaps(image) {
        Ok(heaps) => crate::peel::obfuscar::classify_obfuscar_naming(&heaps.strings),
        Err(_) => return,
    };
    if evidence.is_obfuscar {
        matches.insert(
            Protector::Obfuscar,
            vec![evidence.odometer_members, evidence.longest_run],
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecoyRange {
    start: u32,
    end: u32,
}

impl DecoyRange {
    const fn holds(self, offset: u32) -> bool {
        offset >= self.start && offset < self.end
    }
}

fn drop_decoy_only_matches(
    matches: &mut BTreeMap<Protector, Vec<u32>>,
    decoys: &[DecoyRange],
) -> Vec<Protector> {
    if decoys.is_empty() {
        return Vec::new();
    }
    let suppressed: Vec<Protector> = matches
        .iter()
        .filter(|(protector, offsets): &(&Protector, &Vec<u32>)| {
            **protector != Protector::BitMono
                && !offsets.is_empty()
                && offsets.iter().all(|offset: &u32| {
                    decoys.iter().any(|decoy: &DecoyRange| decoy.holds(*offset))
                })
        })
        .map(|(protector, _): (&Protector, &Vec<u32>)| *protector)
        .collect();
    for protector in &suppressed {
        matches.remove(protector);
    }
    suppressed
}

fn antide4dot_decoy_ranges(image: &[u8]) -> Vec<DecoyRange> {
    let Ok(pe): crate::error::Result<PeImage> = crate::pe::parse(image) else {
        return Vec::new();
    };
    let Ok(clr): crate::error::Result<ClrHeader> = crate::pe::parse_clr_header(image, &pe) else {
        return Vec::new();
    };
    let Ok(root): crate::error::Result<crate::metadata::MetadataRoot> =
        crate::metadata::parse_metadata_root(image, &pe, &clr)
    else {
        return Vec::new();
    };
    let Ok(metadata): crate::error::Result<&[u8]> =
        crate::metadata::metadata_slice(image, &pe, &clr, &root)
    else {
        return Vec::new();
    };
    let Some(strings_header): Option<&crate::metadata::StreamHeader> = root.streams.get("#Strings")
    else {
        return Vec::new();
    };
    let Some(table_header): Option<&crate::metadata::StreamHeader> =
        root.streams.get("#~").or_else(|| root.streams.get("#-"))
    else {
        return Vec::new();
    };
    let Ok(tables): crate::error::Result<crate::tables::Tables> =
        crate::tables::parse_tables(metadata, *table_header)
    else {
        return Vec::new();
    };
    let Some(metadata_offset): Option<usize> = pe.rva_to_offset(clr.metadata.rva) else {
        return Vec::new();
    };
    let heap_base: usize = metadata_offset.saturating_add(strings_header.offset as usize);
    let strings: BTreeMap<u32, String> =
        crate::metadata::read_strings_heap(metadata, *strings_header);
    let defined: std::collections::BTreeSet<(u32, u32)> = tables
        .type_defs
        .iter()
        .map(|row: &crate::tables::TypeDefRow| (row.namespace, row.name))
        .collect();
    let mut ranges: Vec<DecoyRange> = Vec::new();
    for row in &tables.type_refs {
        let module_scoped: bool =
            row.resolution_scope
                .is_none_or(|scope: crate::tables::RowRef| {
                    matches!(
                        scope.table,
                        crate::tables::TableId::Module | crate::tables::TableId::ModuleRef
                    )
                });
        if !module_scoped || defined.contains(&(row.namespace, row.name)) {
            continue;
        }
        for index in [row.namespace, row.name] {
            let Some(text): Option<&String> = strings.get(&index) else {
                continue;
            };
            let Ok(start): std::result::Result<u32, _> =
                u32::try_from(heap_base.saturating_add(index as usize))
            else {
                continue;
            };
            let Ok(len): std::result::Result<u32, _> = u32::try_from(text.len()) else {
                continue;
            };
            ranges.push(DecoyRange {
                start,
                end: start.saturating_add(len),
            });
        }
    }
    ranges
}

fn pick_primary(matches: &BTreeMap<Protector, Vec<u32>>) -> Option<Protector> {
    if matches.contains_key(&Protector::BitMono) {
        return Some(Protector::BitMono);
    }
    matches
        .iter()
        .max_by_key(|(_, offsets): &(&Protector, &Vec<u32>)| offsets.len())
        .map(|(p, _): (&Protector, &Vec<u32>)| *p)
}

fn window_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteOptions {
    pub authorization_granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    Detected { handling: Handling },
    DelegatedToDe4dot,
    Devirtualized,
    GatedAndBlocked { reason: &'static str },
    DetectOnly { reason: &'static str },
}

#[must_use]
pub const fn plan_execution(protector: Protector, options: ExecuteOptions) -> ExecutionOutcome {
    if protector.requires_authorization() && !options.authorization_granted {
        return ExecutionOutcome::GatedAndBlocked {
            reason: protector.label(),
        };
    }
    match protector.handling() {
        Handling::De4dotDelegate | Handling::GatedDe4dotDelegate => {
            ExecutionOutcome::DelegatedToDe4dot
        }
        Handling::Devirtualize => ExecutionOutcome::Devirtualized,
        Handling::NativeStrip => ExecutionOutcome::Detected {
            handling: Handling::NativeStrip,
        },
        Handling::DetectOnly => ExecutionOutcome::DetectOnly {
            reason: protector.label(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("xtask")
            .join("data")
            .join("recovery.json");
        let raw: String =
            std::fs::read_to_string(&path).expect("xtask/data/recovery.json is readable");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("xtask/data/recovery.json parses as JSON");
        let mut found: Vec<serde_json::Value> = Vec::new();
        for group in doc["groups"].as_array().expect("groups array") {
            let heading_matches: bool = group["heading"]
                .as_str()
                .is_some_and(|h: &str| h.contains(heading_needle));
            if !heading_matches {
                continue;
            }
            for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
                if bar["label"].as_str() == Some(label) {
                    found.push(bar.clone());
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a \
             heading containing `{heading_needle}`, found {}",
            found.len()
        );
        found.remove(0)
    }

    #[test]
    fn published_dotnet_protector_roster_count_matches_this_enum() {
        const BAR: &str = ".NET protectors";
        let bar: serde_json::Value = published_bar("Detection and routing rosters", BAR);
        let count: u64 = bar["value"]
            .as_u64()
            .expect("the .NET protectors bar must carry a roster count");
        assert_eq!(
            usize::try_from(count).expect("roster count fits usize"),
            Protector::ALL.len(),
            "xtask/data/recovery.json publishes {count} .NET protectors in its routing roster and \
             every document renders that number, but the roster detect_all walks carries {}",
            Protector::ALL.len()
        );
        assert_eq!(
            Protector::ALL.len(),
            Protector::ALL
                .iter()
                .collect::<std::collections::BTreeSet<&Protector>>()
                .len(),
            "the walked roster must not repeat a protector, or the published count is inflated"
        );
    }

    fn native_pe_with_marker(marker: &[u8]) -> Vec<u8> {
        let mut img: Vec<u8> = vec![0u8; 0x400];
        img[0] = b'M';
        img[1] = b'Z';
        let pe_off: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        let p: usize = pe_off as usize;
        img[p..p + 4].copy_from_slice(b"PE\0\0");
        img[p + 4..p + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        img[p + 6..p + 8].copy_from_slice(&1u16.to_le_bytes());
        let opt_size: u16 = 0xF0;
        img[p + 20..p + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt_start: usize = p + 24;
        img[opt_start..opt_start + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        img[opt_start + 108..opt_start + 112].copy_from_slice(&16u32.to_le_bytes());
        let at: usize = 0x300;
        img[at..at + marker.len()].copy_from_slice(marker);
        img
    }

    fn managed_pe_with_marker(marker: &[u8]) -> Vec<u8> {
        let mut img: Vec<u8> = vec![0u8; 0x600];
        img[0] = b'M';
        img[1] = b'Z';
        let pe_off: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
        let p: usize = pe_off as usize;
        img[p..p + 4].copy_from_slice(b"PE\0\0");
        img[p + 4..p + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
        img[p + 6..p + 8].copy_from_slice(&1u16.to_le_bytes());
        let opt_size: u16 = 0xE0;
        img[p + 20..p + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt_start: usize = p + 24;
        img[opt_start..opt_start + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        img[opt_start + 92..opt_start + 96].copy_from_slice(&16u32.to_le_bytes());
        let dirs: usize = opt_start + 96;
        let clr_rva: u32 = 0x2008;
        let clr_dir: usize = dirs + 14 * 8;
        img[clr_dir..clr_dir + 4].copy_from_slice(&clr_rva.to_le_bytes());
        img[clr_dir + 4..clr_dir + 8].copy_from_slice(&72u32.to_le_bytes());
        let sect: usize = opt_start + opt_size as usize;
        img[sect..sect + 8].copy_from_slice(b".text\0\0\0");
        img[sect + 8..sect + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        img[sect + 12..sect + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        img[sect + 16..sect + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        let raw_ptr: u32 = 0x200;
        img[sect + 20..sect + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        img[sect + 36..sect + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let clr_off: usize = (raw_ptr + (clr_rva - 0x2000)) as usize;
        img[clr_off..clr_off + 4].copy_from_slice(&72u32.to_le_bytes());
        let md_rva: u32 = 0x2100;
        img[clr_off + 8..clr_off + 12].copy_from_slice(&md_rva.to_le_bytes());
        img[clr_off + 12..clr_off + 16].copy_from_slice(&0x80u32.to_le_bytes());
        let md_off: usize = (raw_ptr + (md_rva - 0x2000)) as usize;
        img[md_off..md_off + 4].copy_from_slice(&METADATA_ROOT_SIGNATURE);
        let at: usize = 0x500;
        img[at..at + marker.len()].copy_from_slice(marker);
        img
    }

    #[test]
    fn detect_confuserex2_signature_present() {
        let img: Vec<u8> = managed_pe_with_marker(b"ConfuserEx2");
        assert!(
            is_dotnet_assembly(&img),
            "carrier must be a valid managed PE"
        );
        let r: DetectionReport = detect_all(&img);
        assert!(r.matches.contains_key(&Protector::ConfuserEx2));
    }

    #[test]
    fn native_binary_with_themida_marker_is_not_applicable() {
        let img: Vec<u8> = native_pe_with_marker(b"Themida\0.themida\0.vmp0\0WinLicense");
        assert!(
            !is_dotnet_assembly(&img),
            "a native PE with no CLI header must not be classified as a .NET assembly"
        );
        let r: DetectionReport = detect_all(&img);
        assert!(
            r.matches.is_empty() && r.primary.is_none(),
            "native binary must yield zero .NET-protector classifications; got {:?}",
            r.matches.keys().collect::<Vec<&Protector>>()
        );
    }

    #[test]
    fn non_pe_blob_is_not_applicable() {
        let img: Vec<u8> = vec![0x90u8; 4096];
        assert!(!is_dotnet_assembly(&img));
        assert!(detect_all(&img).matches.is_empty());
    }

    #[test]
    fn obfuscar_is_green_zone() {
        assert_eq!(Protector::Obfuscar.grey_zone(), GreyZone::Green);
    }

    #[test]
    fn reactor_requires_authorization() {
        assert!(Protector::DotnetReactor.requires_authorization());
    }

    #[test]
    fn themida_dotnet_is_detect_only() {
        let outcome: ExecutionOutcome =
            plan_execution(Protector::ThemidaDotnet, ExecuteOptions::default());
        assert!(matches!(outcome, ExecutionOutcome::DetectOnly { .. }));
    }

    #[test]
    fn gated_protector_blocks_without_authorization() {
        let outcome: ExecutionOutcome =
            plan_execution(Protector::EazfuscatorNet, ExecuteOptions::default());
        assert!(matches!(outcome, ExecutionOutcome::GatedAndBlocked { .. }));
    }

    #[test]
    fn gated_protector_unblocks_with_authorization() {
        let outcome: ExecutionOutcome = plan_execution(
            Protector::EazfuscatorNet,
            ExecuteOptions {
                authorization_granted: true,
            },
        );
        assert!(matches!(outcome, ExecutionOutcome::DelegatedToDe4dot));
    }

    #[test]
    fn confuserex2_delegates_to_de4dot() {
        let outcome: ExecutionOutcome =
            plan_execution(Protector::ConfuserEx2, ExecuteOptions::default());
        assert!(matches!(outcome, ExecutionOutcome::DelegatedToDe4dot));
    }

    #[test]
    fn obfuscar_uses_native_strip() {
        let outcome: ExecutionOutcome =
            plan_execution(Protector::Obfuscar, ExecuteOptions::default());
        assert!(matches!(
            outcome,
            ExecutionOutcome::Detected {
                handling: Handling::NativeStrip
            }
        ));
    }

    #[test]
    fn all_protectors_have_nonempty_label_and_signatures() {
        let all: [Protector; 22] = [
            Protector::ConfuserEx,
            Protector::ConfuserEx2,
            Protector::Dotfuscator,
            Protector::DotfuscatorCe,
            Protector::SmartAssembly,
            Protector::BabelDotnet,
            Protector::DeepSea,
            Protector::SpicesNet,
            Protector::Goliath,
            Protector::Skater,
            Protector::DotnetReactor,
            Protector::EazfuscatorNet,
            Protector::CryptoObfuscator,
            Protector::ArmDot,
            Protector::AgileNet,
            Protector::DotNetPatcher,
            Protector::NetCryptor,
            Protector::Obfuscar,
            Protector::ThemidaDotnet,
            Protector::Ilprotector,
            Protector::MaxToCode,
            Protector::KoiVm,
        ];
        for p in all {
            assert!(!p.label().is_empty());
            assert!(!p.signatures().is_empty());
        }
    }
}
