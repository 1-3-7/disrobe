//! Multi-layer packer-chain fingerprinting.
//!
//! [`super::detect`] proves the single-signature matrix: each known packer
//! contributes one or more byte signatures and a buffer is classified by which
//! signatures it contains. Real-world malware and crackme protections rarely
//! stop at one layer — a sample is frequently packed by tool A, then the result
//! re-packed by tool B (and sometimes a protector C). The resulting binary
//! carries the byte markers of *every* layer simultaneously, because each layer
//! prepends its own loader stub / section names while leaving the inner layer's
//! markers intact inside the still-compressed payload.
//!
//! This module curates a ledger of known multi-layer combinations
//! ([`CHAIN_SIGNATURES`]) and exposes [`detect_packer_chain`], which layers on
//! top of the single-signature [`super::detect`] matrix: it asks which packers
//! the single-sig matrix found, then reports every curated chain whose full
//! ordered membership is a subset of that set.
//!
//! The detector makes no claim about decompiling a chain — it identifies the
//! layering so the orchestrator can route to the correct outermost unpacker
//! first. The oracle in tests is non-circular: a chain is asserted only when an
//! input independently carries each layer's *real, published* section marker
//! (e.g. `UPX!` + `.aspack`), never by re-emitting the detector's own output.

use serde::{Deserialize, Serialize};

use super::{Confidence, Detection, Packer, detect};

/// A curated multi-layer packer chain.
///
/// `layers` is ordered inner-to-outer: the first element is the packer applied
/// first (closest to the original program), the last element is the packer
/// applied last (the outermost loader, which a runtime/unpacker peels first).
#[derive(Debug, Clone, Copy)]
pub struct ChainSignature {
    pub layers: &'static [Packer],
    pub note: &'static str,
    pub confidence: Confidence,
}

/// A detected packer chain for a concrete input buffer.
///
/// Carries the matched layer order plus the single-signature [`Detection`] that
/// witnessed each layer (so callers can see *which* byte marker, at which
/// offset, proved each layer present — the anti-circular evidence trail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainDetection {
    pub layers: Vec<Packer>,
    pub note: String,
    pub confidence: Confidence,
    pub witnesses: Vec<Detection>,
}

/// Curated ledger of multi-layer packer/protector chains.
///
/// Observed in the wild (malware crypter stacks, nested-packer crackmes,
/// protector-over-packer loaders). Each entry's `layers` is ordered
/// inner-to-outer.
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

/// Detect multi-layer packer chains in `bytes`.
///
/// Layers on top of the single-signature [`super::detect`] matrix: a curated
/// [`ChainSignature`] is reported only when *every* packer in its ordered
/// `layers` is independently witnessed by the single-sig matrix in the same
/// input. The returned [`ChainDetection`] carries the witnessing [`Detection`]
/// for each layer so the evidence is auditable. Results are sorted most-layers
/// first (the most specific chain leads), then by confidence.
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
        let mut buf: Vec<u8> = vec![0u8; 2048];
        let mut cursor: usize = 64;
        for marker in markers {
            buf[cursor..cursor + marker.len()].copy_from_slice(marker);
            cursor += marker.len() + 32;
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
}
