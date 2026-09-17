use serde::{Deserialize, Serialize};

use super::{Confidence, Detection, Packer, detect};

#[derive(Debug, Clone, Copy)]
pub struct ChainSignature {
    pub layers: &'static [Packer],
    pub note: &'static str,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainDetection {
    pub layers: Vec<Packer>,
    pub note: String,
    pub confidence: Confidence,
    pub witnesses: Vec<Detection>,
}

impl ChainDetection {
    #[must_use]
    pub fn confidence_score(&self) -> ChainConfidenceScore {
        let stages: Vec<StageConfidence> = self
            .witnesses
            .iter()
            .zip(self.layers.iter())
            .map(|(w, layer): (&Detection, &Packer)| StageConfidence {
                packer: *layer,
                probability: stage_probability(w.confidence),
            })
            .collect();
        let overall: f64 = stages
            .iter()
            .map(|s: &StageConfidence| s.probability)
            .product();
        ChainConfidenceScore { stages, overall }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainConfidenceScore {
    pub stages: Vec<StageConfidence>,
    pub overall: f64,
}

impl ChainConfidenceScore {
    #[must_use]
    pub fn overall_pct(&self) -> u8 {
        (self.overall * 100.0).round().clamp(0.0, 100.0) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StageConfidence {
    pub packer: Packer,
    pub probability: f64,
}

const fn stage_probability(c: Confidence) -> f64 {
    match c {
        Confidence::High => 0.96,
        Confidence::Medium => 0.80,
        Confidence::Low => 0.60,
    }
}

pub const CHAIN_SIGNATURES: &[ChainSignature] = &[
    ChainSignature {
        layers: &[Packer::Upx, Packer::AsPack],
        note: "UPX inner + ASPack outer (classic double-pack to defeat naive UPX -d)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Petite],
        note: "UPX inner + Petite outer (size-first then loader-obfuscation re-pack)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Mpress],
        note: "UPX inner + MPRESS outer (re-pack to alter section entropy fingerprint)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Fsg],
        note: "UPX inner + FSG outer (minimal-loader re-pack)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::VmProtect],
        note: "UPX inner + VMProtect outer (compress then virtualize the loader)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Themida],
        note: "UPX inner + Themida outer (compress then wrap in protector VM)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Petite, Packer::VmProtect],
        note: "Petite inner + VMProtect outer (loader-pack then virtualize)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::AsPack, Packer::AsProtect],
        note: "ASPack inner + ASProtect outer (same vendor compress-then-protect stack)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::AsPack, Packer::VmProtect],
        note: "ASPack inner + VMProtect outer (cheap pack then virtualization)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::AsPack, Packer::Themida],
        note: "ASPack inner + Themida outer",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Mpress, Packer::VmProtect],
        note: "MPRESS inner + VMProtect outer (LZMA compress then virtualize)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Fsg, Packer::Mew],
        note: "FSG inner + MEW outer (tiny-packer stack on small droppers)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::PeCompact],
        note: "UPX inner + PECompact outer (re-pack to swap loader stub)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::PeCompact, Packer::Armadillo],
        note: "PECompact inner + Armadillo outer (compress then licensing protector)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Nspack, Packer::AsProtect],
        note: "NSPack inner + ASProtect outer",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::YodasCrypter, Packer::YodasProtector],
        note: "Yoda's Crypter inner + Yoda's Protector outer (same-family escalation)",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::EnigmaProtector],
        note: "UPX inner + Enigma Protector outer (compress then licensing/anti-RE wrap)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Petite, Packer::Themida],
        note: "Petite inner + Themida outer",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Obsidium],
        note: "UPX inner + Obsidium outer (pack then commercial protector)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Mew, Packer::AsPack],
        note: "MEW inner + ASPack outer (tiny-packer then mainstream packer)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::PeLock],
        note: "UPX inner + PELock outer (compress then anti-debug protector)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::WinLicense],
        note: "UPX inner + WinLicense outer (compress then Oreans licensing VM)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::AsProtect, Packer::Themida],
        note: "ASProtect inner + Themida outer (protector-over-protector stack)",
        confidence: Confidence::Low,
    },
    ChainSignature {
        layers: &[Packer::WarzoneCrypter, Packer::Upx],
        note: "Warzone RAT crypter inner + UPX outer (malware crypter then compress)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::NetCryptor, Packer::DotNetPatcher],
        note: ".NET cryptor inner + DotNetPatcher outer (managed double-protect)",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::AsPack, Packer::VmProtect],
        note: "triple stack: UPX inner + ASPack mid + VMProtect outer",
        confidence: Confidence::High,
    },
    ChainSignature {
        layers: &[Packer::Upx, Packer::Petite, Packer::Themida],
        note: "triple stack: UPX inner + Petite mid + Themida outer",
        confidence: Confidence::Medium,
    },
    ChainSignature {
        layers: &[Packer::Fsg, Packer::Upx, Packer::AsPack],
        note: "triple stack: FSG inner + UPX mid + ASPack outer",
        confidence: Confidence::Medium,
    },
];

#[must_use]
pub fn detect_packer_chain(bytes: &[u8]) -> Vec<ChainDetection> {
    let singles: Vec<Detection> = detect(bytes);
    if singles.len() < 2 {
        return Vec::new();
    }

    let mut chains: Vec<ChainDetection> = Vec::new();
    for sig in CHAIN_SIGNATURES {
        let witnesses: Option<Vec<Detection>> = sig
            .layers
            .iter()
            .map(|layer: &Packer| {
                singles
                    .iter()
                    .find(|d: &&Detection| d.packer == *layer)
                    .cloned()
            })
            .collect();
        let Some(witnesses): Option<Vec<Detection>> = witnesses else {
            continue;
        };
        chains.push(ChainDetection {
            layers: sig.layers.to_vec(),
            note: sig.note.to_owned(),
            confidence: sig.confidence,
            witnesses,
        });
    }

    chains.sort_by(|a: &ChainDetection, b: &ChainDetection| {
        b.layers
            .len()
            .cmp(&a.layers.len())
            .then_with(|| confidence_rank(b.confidence).cmp(&confidence_rank(a.confidence)))
    });
    chains
}

const fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn buf_with_markers(markers: &[&[u8]]) -> Vec<u8> {
        let sections: Vec<&[u8]> = markers
            .iter()
            .copied()
            .filter(|m: &&[u8]| m.len() <= 8)
            .collect();
        let opt_size: usize = 0xE0;
        let sec_table: usize = 0x80 + 4 + 20 + opt_size;
        let header_end: usize = sec_table + sections.len().max(1) * 40;
        let mut buf: Vec<u8> = vec![0u8; header_end + 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        let coff: usize = 0x80 + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        for (i, name) in sections.iter().enumerate() {
            let entry: usize = sec_table + i * 40;
            buf[entry..entry + name.len()].copy_from_slice(name);
        }
        for marker in markers {
            let cursor: usize = buf.len();
            buf.extend_from_slice(marker);
            buf.resize(cursor + marker.len() + 32, 0);
        }
        buf
    }

    #[test]
    fn single_layer_buffer_yields_no_chain() {
        let buf: Vec<u8> = buf_with_markers(&[b"UPX!"]);
        assert!(
            detect_packer_chain(&buf).is_empty(),
            "a single packer marker must never fabricate a chain",
        );
    }

    #[test]
    fn upx_plus_aspack_detects_two_layer_chain() {
        let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack"]);
        let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
        let found: &ChainDetection = chains
            .iter()
            .find(|c: &&ChainDetection| c.layers == vec![Packer::Upx, Packer::AsPack])
            .expect("UPX inner + ASPack outer chain must be detected from independent markers");
        assert_eq!(found.witnesses.len(), 2);
        assert!(
            found
                .witnesses
                .iter()
                .any(|w: &Detection| w.packer == Packer::Upx),
        );
        assert!(
            found
                .witnesses
                .iter()
                .any(|w: &Detection| w.packer == Packer::AsPack),
        );
    }

    #[test]
    fn petite_plus_vmprotect_detects_protector_over_packer() {
        let buf: Vec<u8> = buf_with_markers(&[b".petite", b".vmp0"]);
        let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
        assert!(
            chains
                .iter()
                .any(|c: &ChainDetection| c.layers == vec![Packer::Petite, Packer::VmProtect]),
            "Petite + VMProtect chain must be detected",
        );
    }

    #[test]
    fn triple_stack_ranks_above_subset_two_layer_chain() {
        let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack", b".vmp0"]);
        let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
        let triple: &ChainDetection = chains
            .first()
            .expect("at least one chain must be detected for a triple-marker buffer");
        assert_eq!(
            triple.layers,
            vec![Packer::Upx, Packer::AsPack, Packer::VmProtect],
            "the 3-layer chain must rank ahead of any 2-layer subset chain",
        );
        assert!(
            chains
                .iter()
                .any(|c: &ChainDetection| c.layers == vec![Packer::Upx, Packer::AsPack]),
            "the 2-layer subset chains are still reported, just ranked lower",
        );
    }

    #[test]
    fn unrelated_two_markers_without_curated_chain_yields_nothing() {
        let buf: Vec<u8> = buf_with_markers(&[b"DNPatcher", b"yC2.0"]);
        assert!(
            detect_packer_chain(&buf).is_empty(),
            "two packers with no curated chain entry must not invent a chain",
        );
    }

    #[test]
    fn random_buffer_yields_no_chain() {
        let buf: Vec<u8> = vec![0x42u8; 4096];
        assert!(detect_packer_chain(&buf).is_empty());
    }

    #[test]
    fn every_curated_chain_has_at_least_two_layers() {
        for sig in CHAIN_SIGNATURES {
            assert!(
                sig.layers.len() >= 2,
                "a chain signature with fewer than 2 layers is meaningless: {:?}",
                sig.note,
            );
        }
    }

    #[test]
    fn ledger_has_between_twenty_and_thirty_chains() {
        let n: usize = CHAIN_SIGNATURES.len();
        assert!(
            (20..=30).contains(&n),
            "the chain ledger must carry 20-30 curated fingerprints, got {n}",
        );
    }

    #[test]
    fn confidence_score_is_product_of_stage_probabilities() {
        let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack"]);
        let chains: Vec<ChainDetection> = detect_packer_chain(&buf);
        let found: &ChainDetection = chains
            .iter()
            .find(|c: &&ChainDetection| c.layers == vec![Packer::Upx, Packer::AsPack])
            .expect("UPX + ASPack chain");
        let score: ChainConfidenceScore = found.confidence_score();
        assert_eq!(score.stages.len(), 2);
        let expected: f64 = 0.96 * 0.96;
        assert!(
            (score.overall - expected).abs() < 1e-9,
            "two High stages must multiply to {expected}, got {}",
            score.overall,
        );
        assert_eq!(score.overall_pct(), 92);
    }

    #[test]
    fn longer_chain_scores_lower_than_its_high_confidence_prefix() {
        let triple_buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack", b".vmp0"]);
        let chains: Vec<ChainDetection> = detect_packer_chain(&triple_buf);
        let triple: &ChainDetection = chains
            .iter()
            .find(|c: &&ChainDetection| c.layers.len() == 3)
            .expect("triple chain");
        let two: &ChainDetection = chains
            .iter()
            .find(|c: &&ChainDetection| c.layers == vec![Packer::Upx, Packer::AsPack])
            .expect("two-layer subset");
        assert!(
            triple.confidence_score().overall < two.confidence_score().overall,
            "a longer chain's joint probability must be strictly lower than its prefix's",
        );
    }

    #[test]
    fn every_stage_probability_is_a_valid_probability() {
        let buf: Vec<u8> = buf_with_markers(&[b"UPX!", b".aspack", b".vmp0"]);
        for chain in detect_packer_chain(&buf) {
            let score: ChainConfidenceScore = chain.confidence_score();
            for stage in &score.stages {
                assert!(
                    (0.0..=1.0).contains(&stage.probability),
                    "stage probability for {:?} out of range: {}",
                    stage.packer,
                    stage.probability,
                );
            }
            assert!((0.0..=1.0).contains(&score.overall));
        }
    }
}
