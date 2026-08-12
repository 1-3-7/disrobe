use std::path::PathBuf;

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, DetectorOutput};

use super::catalog_registry::{display_name_for, registry};

#[derive(Debug)]
struct Hit {
    pass_id: &'static str,
    display_name: &'static str,
    confidence: f32,
    markers: Vec<String>,
}

fn detect_hits(bytes: &[u8], file_name: Option<&str>) -> Vec<Hit> {
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: file_name,
        parent_hint: None,
        depth: 0,
    };

    let mut hits: Vec<Hit> = Vec::new();
    for catalog in registry() {
        let Some(output): Option<DetectorOutput> = catalog.detect(&ctx) else {
            continue;
        };
        let display_name: &'static str = display_name_for(catalog, output.entry_id);
        hits.push(Hit {
            pass_id: catalog.pass_id(),
            display_name,
            confidence: output.confidence,
            markers: output.markers,
        });
    }
    if let Some(verdict) = disrobe_binfmt::chain_detector::NeDetector.detect(&ctx) {
        let verdict: DetectVerdict = verdict;
        hits.push(Hit {
            pass_id: verdict.pass_id,
            display_name: "Windows and OS/2 New Executable",
            confidence: verdict.confidence,
            markers: verdict.markers.into_iter().map(str::to_owned).collect(),
        });
    }
    hits.sort_by(|a: &Hit, b: &Hit| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.pass_id.cmp(b.pass_id))
    });
    hits
}

pub(crate) fn run(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0600: cannot read input: {e}"))?;
    let file_name: Option<&str> = input.file_name().and_then(|s| s.to_str());
    let hits: Vec<Hit> = detect_hits(&bytes, file_name);

    println!("disrobe detect: {}", input.display());
    if hits.is_empty() {
        println!("  no known obfuscator/packer detected");
        return Ok(());
    }
    for hit in &hits {
        let markers: String = if hit.markers.is_empty() {
            "-".to_owned()
        } else {
            hit.markers.join(", ")
        };
        println!(
            "  {} | {} | {:.2} | {markers}",
            hit.pass_id, hit.display_name, hit.confidence
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_win16_ne_reaches_the_detect_command() {
        const REAL_NE: &[u8] = include_bytes!("../../../../corpus/native/formats/hello_ne.exe");
        let hits: Vec<Hit> = detect_hits(REAL_NE, Some("hello_ne.exe"));
        assert!(hits.iter().any(|hit: &Hit| {
            hit.pass_id == disrobe_binfmt::chain_detector::NE_PASS_ID
                && hit.confidence.to_bits() == 1.0f32.to_bits()
                && hit.markers == ["mz-ne-header+validated-tables"]
        }));
    }
}
