use std::path::{Path, PathBuf};

use disrobe_pass_native::hardening::{
    Check, Evidence, FortifyCounts, HardeningError, HardeningReport, ImageHardening, analyze,
};

use crate::cli::output::{self, OutputFormat};

const PROPERTY_WIDTH: usize = 18;
const STATUS_WIDTH: usize = 16;

pub(crate) fn run(input: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input).map_err(|error: std::io::Error| {
        miette::miette!("DR-NATIVE-0265: cannot read {}: {error}", input.display())
    })?;
    let report: HardeningReport =
        analyze(&bytes).map_err(|error: HardeningError| miette::miette!("{error}"))?;
    output::emit(fmt, &report, || render_text(&input, &report))
}

fn render_text(input: &Path, report: &HardeningReport) {
    println!("native hardening: {}", input.display());
    for image in &report.images {
        println!();
        render_image(image);
    }
}

fn render_image(image: &ImageHardening) {
    let slice: String = image
        .slice_offset
        .map(|offset: u64| format!(", slice at {offset:#x}"))
        .unwrap_or_default();
    println!(
        "{} {} {} ({}-bit{slice})",
        image.format, image.machine, image.kind, image.bits
    );
    for check in &image.checks {
        render_check(check);
    }
    if let Some(counts) = &image.fortify {
        render_fortify(counts);
    }
}

fn render_check(check: &Check) {
    let mut evidence: std::slice::Iter<'_, Evidence> = check.evidence.iter();
    let first: String = evidence
        .next()
        .map(|item: &Evidence| format!("{} = {}", item.field, item.value))
        .unwrap_or_default();
    println!(
        "  {:<PROPERTY_WIDTH$} {:<STATUS_WIDTH$} {first}",
        check.property.as_str(),
        check.status.as_str()
    );
    for item in evidence {
        println!(
            "  {:<PROPERTY_WIDTH$} {:<STATUS_WIDTH$} {} = {}",
            "", "", item.field, item.value
        );
    }
}

fn render_fortify(counts: &FortifyCounts) {
    println!(
        "  fortify counts: {} fortified of {} fortifiable libc calls",
        counts.fortified, counts.fortifiable
    );
}
