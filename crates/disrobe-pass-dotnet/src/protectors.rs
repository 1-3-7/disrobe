use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_enabled, dbg_kv, dbg_line};

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

impl Protector {
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
pub fn detect_all(image: &[u8]) -> DetectionReport {
    let mut matches: BTreeMap<Protector, Vec<u32>> = BTreeMap::new();
    let all: [Protector; 23] = [
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
        Protector::BitMono,
    ];
    for protector in all {
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

    #[test]
    fn detect_confuserex2_signature_present() {
        let mut img: Vec<u8> = vec![0u8; 1024];
        let sig: &[u8] = b"ConfuserEx2";
        img[100..100 + sig.len()].copy_from_slice(sig);
        let r: DetectionReport = detect_all(&img);
        assert!(r.matches.contains_key(&Protector::ConfuserEx2));
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
