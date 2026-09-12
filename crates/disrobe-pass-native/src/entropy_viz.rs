use std::fmt::Write as _;

use serde::Serialize;

use crate::entropy::{EntropyBlock, HIGH_ENTROPY_THRESHOLD};

const MAX_ENTROPY_BITS: f64 = 8.0;

const SPARK_RAMP: [char; 9] = [
    ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
    '\u{2588}',
];

const HEAT_RAMP: [char; 5] = ['.', ':', '+', '*', '#'];

const HISTOGRAM_BAR_CELLS: usize = 40;
const HISTOGRAM_BAR_FULL: char = '\u{2588}';

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionSpan {
    pub name: String,
    pub file_offset: u64,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct HighEntropyRun {
    pub start_block: usize,
    pub end_block: usize,
    pub offset_start: usize,
    pub offset_end: usize,
    pub block_count: usize,
    pub mean_entropy: f64,
    pub max_entropy: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByteHistogram {
    pub total: u64,
    pub counts: Vec<u64>,
    pub max_count: u64,
    pub distinct: usize,
}

#[inline]
fn normalized_entropy(entropy: f64) -> f64 {
    (entropy / MAX_ENTROPY_BITS).clamp(0.0, 1.0)
}

#[inline]
fn ramp_index(fraction: f64, ramp_len: usize) -> usize {
    debug_assert!(ramp_len > 0);
    let last: usize = ramp_len - 1;
    let scaled: f64 = (fraction.clamp(0.0, 1.0) * last as f64).round();
    (scaled as usize).min(last)
}

#[must_use]
pub fn entropy_sparkline(blocks: &[EntropyBlock]) -> String {
    let mut out: String = String::with_capacity(blocks.len());
    for block in blocks {
        let idx: usize = ramp_index(normalized_entropy(block.entropy), SPARK_RAMP.len());
        out.push(SPARK_RAMP[idx]);
    }
    out
}

#[must_use]
pub fn entropy_heat_strip(blocks: &[EntropyBlock]) -> String {
    let mut out: String = String::with_capacity(blocks.len());
    for block in blocks {
        let idx: usize = ramp_index(normalized_entropy(block.entropy), HEAT_RAMP.len());
        out.push(HEAT_RAMP[idx]);
    }
    out
}

#[must_use]
pub fn high_entropy_runs(blocks: &[EntropyBlock]) -> Vec<HighEntropyRun> {
    let mut runs: Vec<HighEntropyRun> = Vec::new();
    let mut current: Option<(usize, usize)> = None;
    for (i, block) in blocks.iter().enumerate() {
        if block.entropy >= HIGH_ENTROPY_THRESHOLD {
            current = Some(current.map_or((i, i), |(start, _)| (start, i)));
        } else if let Some((start, end)) = current.take() {
            runs.push(summarize_run(blocks, start, end));
        }
    }
    if let Some((start, end)) = current {
        runs.push(summarize_run(blocks, start, end));
    }
    runs
}

fn summarize_run(blocks: &[EntropyBlock], start: usize, end: usize) -> HighEntropyRun {
    let span: &[EntropyBlock] = &blocks[start..=end];
    let block_count: usize = span.len();
    let sum: f64 = span.iter().map(|b: &EntropyBlock| b.entropy).sum();
    let max_entropy: f64 = span
        .iter()
        .map(|b: &EntropyBlock| b.entropy)
        .fold(0.0_f64, f64::max);
    HighEntropyRun {
        start_block: start,
        end_block: end,
        offset_start: span[0].offset_start,
        offset_end: span[block_count - 1].offset_end,
        block_count,
        mean_entropy: sum / block_count as f64,
        max_entropy,
    }
}

#[must_use]
pub fn byte_histogram(bytes: &[u8]) -> ByteHistogram {
    let mut counts: Vec<u64> = vec![0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let max_count: u64 = counts.iter().copied().max().unwrap_or(0);
    let distinct: usize = counts.iter().filter(|&&c: &&u64| c > 0).count();
    ByteHistogram {
        total: bytes.len() as u64,
        counts,
        max_count,
        distinct,
    }
}

#[must_use]
pub fn histogram_ascii_16(hist: &ByteHistogram) -> String {
    let mut buckets: [u64; 16] = [0u64; 16];
    for (value, &count) in hist.counts.iter().enumerate() {
        buckets[value >> 4] += count;
    }
    let max_bucket: u64 = buckets.iter().copied().max().unwrap_or(0);
    let mut out: String = String::new();
    for (i, &count) in buckets.iter().enumerate() {
        let lo: usize = i << 4;
        let hi: usize = lo + 0x0F;
        let mut bar: String = bar_cells(count, max_bucket, HISTOGRAM_BAR_CELLS);
        while bar.chars().count() < HISTOGRAM_BAR_CELLS {
            bar.push(' ');
        }
        let pct: f64 = if hist.total == 0 {
            0.0
        } else {
            count as f64 / hist.total as f64 * 100.0
        };
        let _: Result<(), std::fmt::Error> =
            writeln!(out, "0x{lo:02X}-0x{hi:02X} {bar} {count:>10} ({pct:5.1}%)");
    }
    out
}

fn bar_cells(count: u64, max: u64, cells: usize) -> String {
    if max == 0 || cells == 0 {
        return String::new();
    }
    let filled: usize = ((count as f64 / max as f64) * cells as f64).round() as usize;
    let filled: usize = filled.min(cells);
    let mut bar: String = String::with_capacity(filled);
    for _ in 0..filled {
        bar.push(HISTOGRAM_BAR_FULL);
    }
    bar
}

#[derive(Debug, Clone)]
pub struct EntropySvgOptions {
    pub title: String,
    pub block_px: u32,
    pub strip_height: u32,
    pub sections: Vec<SectionSpan>,
    pub show_legend: bool,
}

impl Default for EntropySvgOptions {
    fn default() -> Self {
        Self {
            title: "disrobe entropy map".to_owned(),
            block_px: 3,
            strip_height: 120,
            sections: Vec::new(),
            show_legend: true,
        }
    }
}

const SVG_BG: &str = "#0a0a0a";
const SVG_PANEL: &str = "#101010";
const SVG_TEXT: &str = "#ededed";
const SVG_TEXT2: &str = "#a1a1a1";
const SVG_MUTED: &str = "#828282";
const SVG_GRID: &str = "#262626";
const SVG_HAIRLINE: &str = "#333333";
const SVG_ACCENT: &str = "#8fb3d9";
const SVG_FONT_MONO: &str = "'JetBrains Mono',ui-monospace,'Fira Code',\
'SFMono-Regular',Menlo,Consolas,monospace";
const SVG_FONT_SANS: &str = "system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const SVG_MARGIN: u32 = 18;
const SVG_TITLE_BAND: u32 = 34;
const SVG_LEGEND_HEIGHT: u32 = 34;
const SVG_LABEL_BAND: u32 = 18;
const SVG_MIN_WIDTH: u32 = 360;

#[inline]
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    (b - a).mul_add(t, a)
}

#[must_use]
pub fn entropy_color(fraction: f64) -> String {
    let t: f64 = fraction.clamp(0.0, 1.0);
    let (r, g, b): (f64, f64, f64) = if t < 0.5 {
        let k: f64 = t / 0.5;
        (
            lerp(130.0, 201.0, k),
            lerp(130.0, 169.0, k),
            lerp(130.0, 142.0, k),
        )
    } else {
        let k: f64 = (t - 0.5) / 0.5;
        (
            lerp(201.0, 208.0, k),
            lerp(169.0, 140.0, k),
            lerp(142.0, 140.0, k),
        )
    };
    format!(
        "#{:02x}{:02x}{:02x}",
        r.round() as u8,
        g.round() as u8,
        b.round() as u8
    )
}

fn svg_escape(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c.is_control() && c != '\t') => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[must_use]
pub fn render_entropy_svg(
    blocks: &[EntropyBlock],
    total_bytes: u64,
    opts: &EntropySvgOptions,
) -> String {
    let block_px: u32 = opts.block_px.max(1);
    let strip_w: u32 = (blocks.len() as u32).saturating_mul(block_px).max(1);
    let inner_w: u32 = strip_w.max(SVG_MIN_WIDTH);
    let width: u32 = inner_w + SVG_MARGIN * 2;

    let legend_band: u32 = if opts.show_legend {
        SVG_LEGEND_HEIGHT
    } else {
        0
    };
    let section_band: u32 = if opts.sections.is_empty() {
        0
    } else {
        SVG_LABEL_BAND
    };
    let strip_top: u32 = SVG_MARGIN + SVG_TITLE_BAND;
    let strip_h: u32 = opts.strip_height.max(16);
    let height: u32 = strip_top + strip_h + section_band + legend_band + SVG_MARGIN;

    let mut out: String = String::with_capacity(4096 + blocks.len() * 48);
    let title: String = svg_escape(&opts.title);
    let nblocks: usize = blocks.len();
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{title}\" \
font-family=\"{SVG_FONT_SANS}\">"
    );
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<rect x=\"0\" y=\"0\" width=\"{width}\" height=\"{height}\" fill=\"{SVG_BG}\"/>"
    );

    render_header(&mut out, &title, total_bytes, nblocks, width);

    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<rect x=\"{SVG_MARGIN}\" y=\"{strip_top}\" width=\"{inner_w}\" height=\"{strip_h}\" \
fill=\"{SVG_PANEL}\" stroke=\"{SVG_GRID}\" stroke-width=\"1\" rx=\"3\"/>"
    );

    for (i, block) in blocks.iter().enumerate() {
        let x: u32 = SVG_MARGIN + (i as u32) * block_px;
        let color: String = entropy_color(normalized_entropy(block.entropy));
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<rect x=\"{x}\" y=\"{strip_top}\" width=\"{block_px}\" height=\"{strip_h}\" \
fill=\"{color}\"/>"
        );
    }

    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<rect x=\"{SVG_MARGIN}\" y=\"{strip_top}\" width=\"{inner_w}\" height=\"{strip_h}\" \
fill=\"none\" stroke=\"{SVG_GRID}\" stroke-width=\"1\" rx=\"3\"/>"
    );

    render_section_overlays(&mut out, total_bytes, opts, inner_w, strip_top, strip_h);

    if opts.show_legend {
        render_legend(&mut out, strip_top + strip_h + section_band, inner_w);
    }

    out.push_str("</svg>");
    out
}

fn render_header(out: &mut String, title: &str, total_bytes: u64, nblocks: usize, width: u32) {
    let accent_y: u32 = SVG_MARGIN - 4;
    let title_x: u32 = SVG_MARGIN + 14;
    let title_y: u32 = SVG_MARGIN + 8;
    let meta_y: u32 = SVG_MARGIN + 24;
    let rule_y: u32 = SVG_MARGIN + SVG_TITLE_BAND - 6;
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<rect x=\"{SVG_MARGIN}\" y=\"{accent_y}\" width=\"4\" height=\"14\" rx=\"1\" fill=\"{SVG_ACCENT}\"/>"
    );
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<text x=\"{title_x}\" y=\"{title_y}\" fill=\"{SVG_TEXT}\" font-size=\"13\" \
font-weight=\"600\" letter-spacing=\".01em\">{title}</text>"
    );
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<text x=\"{SVG_MARGIN}\" y=\"{meta_y}\" fill=\"{SVG_TEXT2}\" \
font-family=\"{SVG_FONT_MONO}\" font-size=\"11\">{total_bytes} bytes \u{2022} {nblocks} blocks \
\u{2022} 4 KiB window</text>"
    );
    let rule_x2: u32 = width - SVG_MARGIN;
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<line x1=\"{SVG_MARGIN}\" y1=\"{rule_y}\" x2=\"{rule_x2}\" y2=\"{rule_y}\" \
stroke=\"{SVG_HAIRLINE}\" stroke-width=\"1\"/>"
    );
}

fn offset_to_x(offset: u64, total_bytes: u64, inner_w: u32) -> u32 {
    if total_bytes == 0 {
        return SVG_MARGIN;
    }
    let frac: f64 = (offset as f64 / total_bytes as f64).clamp(0.0, 1.0);
    SVG_MARGIN + (frac * inner_w as f64).round() as u32
}

fn render_section_overlays(
    out: &mut String,
    total_bytes: u64,
    opts: &EntropySvgOptions,
    inner_w: u32,
    strip_top: u32,
    strip_h: u32,
) {
    if opts.sections.is_empty() {
        return;
    }
    let label_y: u32 = strip_top + strip_h + 13;
    let line_y2: u32 = strip_top + strip_h;
    for (i, sec) in opts.sections.iter().enumerate() {
        let x: u32 = offset_to_x(sec.file_offset, total_bytes, inner_w);
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<line x1=\"{x}\" y1=\"{strip_top}\" x2=\"{x}\" y2=\"{line_y2}\" stroke=\"{SVG_TEXT}\" \
stroke-width=\"1\" stroke-dasharray=\"2,3\" opacity=\"0.55\"/>"
        );
        if i % 2 == 0 {
            let tx: u32 = x + 3;
            let name: String = svg_escape(&sec.name);
            let _: Result<(), std::fmt::Error> = write!(
                out,
                "<text x=\"{tx}\" y=\"{label_y}\" fill=\"{SVG_TEXT2}\" \
font-family=\"{SVG_FONT_MONO}\" font-size=\"9.5\">{name}</text>"
            );
        }
    }
}

const LEGEND_STEPS: u32 = 64;

fn render_legend(out: &mut String, top: u32, inner_w: u32) {
    let label_w: u32 = 64;
    let ramp_x: u32 = SVG_MARGIN + label_w;
    let ramp_w: u32 = inner_w.saturating_sub(label_w).max(LEGEND_STEPS);
    let swatch_h: u32 = 8;
    let y: u32 = top + 8;
    let mid_y: u32 = y + swatch_h - 1;
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<text x=\"{SVG_MARGIN}\" y=\"{mid_y}\" fill=\"{SVG_MUTED}\" \
font-size=\"10\" font-weight=\"600\" letter-spacing=\".06em\">ENTROPY</text>"
    );
    for i in 0..LEGEND_STEPS {
        let frac: f64 = f64::from(i) / f64::from(LEGEND_STEPS - 1);
        let color: String = entropy_color(frac);
        let x0: u32 = ramp_x + (i * ramp_w) / LEGEND_STEPS;
        let x1: u32 = ramp_x + ((i + 1) * ramp_w) / LEGEND_STEPS;
        let seg_w: u32 = (x1 - x0).max(1);
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<rect x=\"{x0}\" y=\"{y}\" width=\"{seg_w}\" height=\"{swatch_h}\" fill=\"{color}\"/>"
        );
    }
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<rect x=\"{ramp_x}\" y=\"{y}\" width=\"{ramp_w}\" height=\"{swatch_h}\" fill=\"none\" \
stroke=\"{SVG_HAIRLINE}\" stroke-width=\"1\" rx=\"2\"/>"
    );
    let label_y: u32 = y + swatch_h + 12;
    let right_x: u32 = ramp_x + ramp_w;
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<text x=\"{ramp_x}\" y=\"{label_y}\" fill=\"{SVG_MUTED}\" \
font-family=\"{SVG_FONT_MONO}\" font-size=\"9.5\">0.0 calm</text>"
    );
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<text x=\"{right_x}\" y=\"{label_y}\" fill=\"{SVG_MUTED}\" text-anchor=\"end\" \
font-family=\"{SVG_FONT_MONO}\" font-size=\"9.5\">8.0 packed</text>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::windowed_entropy;

    fn blocks_from(bytes: &[u8]) -> Vec<EntropyBlock> {
        windowed_entropy(bytes, 4096)
    }

    #[test]
    fn sparkline_low_high_glyph_ordering() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes.extend((0..4096).map(|i: usize| (i & 0xff) as u8));
        let blocks: Vec<EntropyBlock> = blocks_from(&bytes);
        let spark: String = entropy_sparkline(&blocks);
        let chars: Vec<char> = spark.chars().collect();
        assert_eq!(chars.len(), 2);
        assert_eq!(chars[0], ' ');
        assert_eq!(chars[1], '\u{2588}');
    }

    #[test]
    fn heat_strip_maps_extremes() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes.extend((0..4096).map(|i: usize| (i & 0xff) as u8));
        let strip: String = entropy_heat_strip(&blocks_from(&bytes));
        assert_eq!(strip, ".#");
    }

    #[test]
    fn high_entropy_runs_are_maximal_and_contiguous() {
        let high: Vec<u8> = (0..4096).map(|i: usize| (i & 0xff) as u8).collect();
        let zero: Vec<u8> = vec![0u8; 4096];
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&high);
        bytes.extend_from_slice(&high);
        bytes.extend_from_slice(&zero);
        bytes.extend_from_slice(&high);
        let runs: Vec<HighEntropyRun> = high_entropy_runs(&blocks_from(&bytes));
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].start_block, 0);
        assert_eq!(runs[0].end_block, 1);
        assert_eq!(runs[0].block_count, 2);
        assert_eq!(runs[1].start_block, 3);
        assert_eq!(runs[1].end_block, 3);
        assert!(runs[0].max_entropy >= HIGH_ENTROPY_THRESHOLD);
    }

    #[test]
    fn byte_histogram_counts_and_distinct() {
        let bytes: [u8; 6] = [0x00, 0x00, 0x01, 0xff, 0xff, 0xff];
        let hist: ByteHistogram = byte_histogram(&bytes);
        assert_eq!(hist.total, 6);
        assert_eq!(hist.counts[0x00], 2);
        assert_eq!(hist.counts[0x01], 1);
        assert_eq!(hist.counts[0xff], 3);
        assert_eq!(hist.max_count, 3);
        assert_eq!(hist.distinct, 3);
    }

    #[test]
    fn ascii_16_buckets_fold_and_total() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let hist: ByteHistogram = byte_histogram(&bytes);
        let chart: String = histogram_ascii_16(&hist);
        let rows: Vec<&str> = chart.lines().collect();
        assert_eq!(rows.len(), 16);
        assert!(rows[0].starts_with("0x00-0x0F"));
        assert!(rows[15].starts_with("0xF0-0xFF"));
        assert!(rows[0].contains("16"));
    }

    #[test]
    fn empty_inputs_are_safe() {
        assert!(entropy_sparkline(&[]).is_empty());
        assert!(entropy_heat_strip(&[]).is_empty());
        assert!(high_entropy_runs(&[]).is_empty());
        let hist: ByteHistogram = byte_histogram(&[]);
        assert_eq!(hist.total, 0);
        assert_eq!(hist.max_count, 0);
        assert_eq!(hist.distinct, 0);
    }

    #[test]
    fn entropy_color_ramp_endpoints_and_midpoint() {
        assert_eq!(entropy_color(0.0), "#828282", "calm gray low-end anchor");
        assert_eq!(
            entropy_color(1.0),
            "#d08c8c",
            "packed danger anchor (graphite)"
        );
        assert_eq!(
            entropy_color(0.5),
            "#c9a98e",
            "partial warn anchor (graphite)"
        );
    }

    #[test]
    fn svg_is_well_formed_and_deterministic() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes.extend((0..4096).map(|i: usize| (i & 0xff) as u8));
        let blocks: Vec<EntropyBlock> = blocks_from(&bytes);
        let opts: EntropySvgOptions = EntropySvgOptions {
            sections: vec![SectionSpan {
                name: ".text".to_owned(),
                file_offset: 0,
                file_size: 4096,
            }],
            ..EntropySvgOptions::default()
        };
        let a: String = render_entropy_svg(&blocks, bytes.len() as u64, &opts);
        let b: String = render_entropy_svg(&blocks, bytes.len() as u64, &opts);
        assert_eq!(a, b, "svg must be deterministic");
        assert!(a.starts_with("<svg "));
        assert!(a.trim_end().ends_with("</svg>"));
        assert_eq!(a.matches("<svg ").count(), 1);
        assert_eq!(a.matches("</svg>").count(), 1);
        let opens: usize = a.matches("<rect").count();
        assert!(opens >= blocks.len(), "one rect per block plus chrome");
        assert!(a.contains(".text"));
        assert!(a.contains("8192 bytes"));
    }

    #[test]
    fn svg_uses_canonical_palette_and_system_fonts() {
        let blocks: Vec<EntropyBlock> = blocks_from(&vec![0u8; 8192]);
        let svg: String = render_entropy_svg(&blocks, 8192, &EntropySvgOptions::default());
        for token in [
            SVG_BG, SVG_PANEL, SVG_TEXT, SVG_TEXT2, SVG_MUTED, SVG_GRID, SVG_ACCENT,
        ] {
            assert!(
                svg.contains(token),
                "missing canonical palette token {token}"
            );
        }
        assert_eq!(SVG_BG, "#0a0a0a", "graphite canvas anchor");
        assert_eq!(SVG_PANEL, "#101010", "graphite inset anchor");
        assert_eq!(SVG_TEXT, "#ededed", "graphite ink anchor");
        assert_eq!(SVG_TEXT2, "#a1a1a1", "graphite ink-muted anchor");
        assert_eq!(SVG_MUTED, "#828282", "graphite ink-faint anchor");
        assert_eq!(SVG_GRID, "#262626", "graphite hairline anchor");
        assert_eq!(SVG_HAIRLINE, "#333333", "graphite hairline-strong anchor");
        assert_eq!(SVG_ACCENT, "#8fb3d9", "graphite accent anchor");
        for stale in [
            "#121212", "#1c1c1c", "#dbd7ca", "#aaa79b", "#758575", "#2a2a2a", "#252525", "#4d9375",
            "#0d1117", "#0f141a", "58a6ff", "388bc4", "#30363d",
        ] {
            assert!(
                !svg.contains(stale),
                "no stale vitesse / github-dark token may survive: {stale}"
            );
        }
        assert!(
            svg.contains("system-ui"),
            "system sans stack must drive the title"
        );
        assert!(
            svg.contains("'JetBrains Mono',ui-monospace"),
            "JetBrains Mono must lead the monospace stack"
        );
        assert!(svg.contains("ENTROPY"), "legend micro-label must render");
        assert!(svg.contains("packed"), "legend high-end label must render");
        assert!(
            !svg.to_lowercase().contains("googleapis"),
            "no external/CDN font references"
        );
    }

    #[test]
    fn svg_escapes_hostile_section_names() {
        let blocks: Vec<EntropyBlock> = blocks_from(&vec![0u8; 4096]);
        let opts: EntropySvgOptions = EntropySvgOptions {
            sections: vec![SectionSpan {
                name: "<script>\"&'".to_owned(),
                file_offset: 0,
                file_size: 10,
            }],
            ..EntropySvgOptions::default()
        };
        let svg: String = render_entropy_svg(&blocks, 4096, &opts);
        assert!(!svg.contains("<script>"));
        assert!(svg.contains("&lt;script&gt;"));
        assert!(svg.contains("&quot;&amp;&apos;"));
    }

    #[test]
    fn svg_empty_blocks_still_valid() {
        let svg: String = render_entropy_svg(&[], 0, &EntropySvgOptions::default());
        assert!(svg.starts_with("<svg "));
        assert!(svg.trim_end().ends_with("</svg>"));
    }
}
