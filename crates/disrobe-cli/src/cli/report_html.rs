use std::fmt::Write as _;

use disrobe_core::behavior::{self, BehaviorReport, Category, CategoryFinding};
use disrobe_core::ioc::{self, IocReport};

use super::report::{BatchReport, InputIdentity, SingleReport, tier_label};
#[cfg(test)]
use super::report::{EvidenceItem, EvidenceRole, HashSource, Reproduction, WallKind, WallView};

const MAX_IOC_ROWS: usize = 200;
const MAX_BEHAVIOR_EVIDENCE: usize = 6;
const SHARED_THEME_TOKENS: &str = include_str!("../../../../docs/theme/tokens.css");

#[derive(Debug, Default)]
pub(crate) struct Enrichment {
    pub(crate) ioc: Option<IocReport>,
    pub(crate) behavior: Option<BehaviorReport>,
}

#[must_use]
pub(crate) fn html_escape(input: &str) -> String {
    let mut out: String = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn native_import_tokens(bytes: &[u8]) -> Vec<String> {
    match disrobe_binfmt::native::parse_native(bytes) {
        Ok(native) => {
            let mut tokens: Vec<String> = Vec::with_capacity(native.imports.len());
            for i in &native.imports {
                tokens.push(format!("{}!{}", i.library, i.name));
                tokens.push(i.name.clone());
            }
            for s in &native.symbols {
                tokens.push(s.name.clone());
            }
            tokens
        }
        Err(_) => Vec::new(),
    }
}

#[must_use]
pub(crate) fn enrich_single(report: &SingleReport) -> Enrichment {
    let Some(path): Option<&String> = report.input.path.as_ref() else {
        return Enrichment::default();
    };
    let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
        return Enrichment::default();
    };
    let imports: Vec<String> = native_import_tokens(&bytes);
    let import_refs: Vec<&str> = imports.iter().map(String::as_str).collect();
    let ioc_report: IocReport = ioc::report_with_extra(&bytes, Some(path), &import_refs);
    let behavior_report: BehaviorReport = behavior::analyze_with_uri(&bytes, &imports, Some(path));
    Enrichment {
        ioc: Some(ioc_report),
        behavior: Some(behavior_report),
    }
}

fn tier_color(tier: &str) -> &'static str {
    match tier {
        "exact" => COLOR_GREEN,
        "semantic" => COLOR_SEMANTIC,
        "partial" => COLOR_AMBER,
        _ => COLOR_RED,
    }
}

const COLOR_BG: &str = "var(--card-canvas)";
const COLOR_SURFACE: &str = "var(--card-surface)";
const COLOR_INSET: &str = "var(--card-panel)";
const COLOR_HAIRLINE: &str = "var(--card-hairline)";
const COLOR_BORDER_SUBTLE: &str = "var(--card-subtle)";
const COLOR_TEXT: &str = "var(--card-text)";
const COLOR_TEXT2: &str = "var(--card-text2)";
const COLOR_MUTED: &str = "var(--card-faint)";
const COLOR_SEMANTIC: &str = "var(--card-keyword)";
const COLOR_GREEN: &str = "var(--card-green)";
const COLOR_AMBER: &str = "var(--card-amber)";
const COLOR_RED: &str = "var(--card-red)";
const COLOR_VIOLET: &str = "var(--card-blue)";

const FONT_SANS: &str = "var(--card-sans)";
const FONT_MONO: &str = "var(--card-mono)";

fn icon(body: &str) -> String {
    format!(
        "<svg class=\"icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"1.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">{body}</svg>"
    )
}

const ICON_SHIELD: &str = "<path d=\"M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z\"/>";
const ICON_FILE: &str = "<path d=\"M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z\"/><path d=\"M14 3v5h5\"/>";
const ICON_FLOW: &str = "<circle cx=\"5\" cy=\"12\" r=\"2\"/><circle cx=\"19\" cy=\"12\" r=\"2\"/>\
<circle cx=\"12\" cy=\"12\" r=\"2\"/><path d=\"M7 12h3\"/><path d=\"M14 12h3\"/>";
const ICON_LAYERS: &str = "<path d=\"M12 4l8 4-8 4-8-4 8-4z\"/><path d=\"M4 12l8 4 8-4\"/>\
<path d=\"M4 16l8 4 8-4\"/>";
const ICON_CHART: &str = "<path d=\"M4 4v16h16\"/><rect x=\"7\" y=\"11\" width=\"3\" height=\"6\"/>\
<rect x=\"12\" y=\"7\" width=\"3\" height=\"10\"/><rect x=\"17\" y=\"13\" width=\"3\" height=\"4\"/>";
const ICON_BOX: &str = "<path d=\"M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z\"/><path d=\"M4 7.5l8 4.5 8-4.5\"/>\
<path d=\"M12 12v9\"/>";
const ICON_NETWORK: &str = "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18\"/>\
<path d=\"M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18z\"/>";
const ICON_TARGET: &str = "<circle cx=\"12\" cy=\"12\" r=\"8\"/><circle cx=\"12\" cy=\"12\" r=\"4\"/>\
<circle cx=\"12\" cy=\"12\" r=\"1\"/>";
const ICON_NOTE: &str =
    "<path d=\"M5 4h11l3 3v13H5z\"/><path d=\"M8 9h8\"/><path d=\"M8 13h8\"/><path d=\"M8 17h5\"/>";
const ICON_FOLDER: &str = "<path d=\"M4 6h6l2 2h8v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6z\"/>";
const ICON_HDD: &str = "<rect x=\"4\" y=\"5\" width=\"16\" height=\"6\" rx=\"1\"/>\
<rect x=\"4\" y=\"13\" width=\"16\" height=\"6\" rx=\"1\"/><path d=\"M7 8h.01\"/><path d=\"M7 16h.01\"/>";
const ICON_TERMINAL: &str = "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><path d=\"M7 9l3 3-3 3\"/><path d=\"M13 15h4\"/>";
const ICON_KEY: &str = "<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M11 12l8-8\"/>\
<path d=\"M16 7l3 3\"/><path d=\"M19 4l1 1\"/>";
const ICON_LOCK: &str = "<rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/>\
<path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/>";
const ICON_EYE_OFF: &str = "<path d=\"M3 3l18 18\"/>\
<path d=\"M10.6 6.1A9 9 0 0 1 21 12a16 16 0 0 1-2.3 3.1\"/>\
<path d=\"M6.5 7.5A16 16 0 0 0 3 12a9 9 0 0 0 12.5 4.2\"/>";
const ICON_CODE: &str = "<path d=\"M9 8l-4 4 4 4\"/><path d=\"M15 8l4 4-4 4\"/>";

const fn category_icon(cat: Category) -> &'static str {
    match cat {
        Category::Network => ICON_NETWORK,
        Category::Filesystem => ICON_HDD,
        Category::ProcessExec => ICON_TERMINAL,
        Category::RegistryPersistence => ICON_KEY,
        Category::Crypto => ICON_LOCK,
        Category::AntiAnalysis => ICON_EYE_OFF,
        Category::DynamicCode => ICON_CODE,
    }
}

fn style_block() -> String {
    format!(
        "{SHARED_THEME_TOKENS}\
:root{{color-scheme:dark}}\
*{{box-sizing:border-box}}\
html{{-webkit-text-size-adjust:100%}}\
body{{margin:0;background:{COLOR_BG};color:{COLOR_TEXT};\
font-family:{FONT_SANS};font-size:14px;line-height:1.5;\
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;padding:0 24px 64px}}\
body::before{{content:\"\";position:fixed;top:0;left:0;right:0;height:1px;\
background:linear-gradient(90deg,transparent,color-mix(in srgb,{COLOR_GREEN} 25%,transparent) 35%,color-mix(in srgb,{COLOR_GREEN} 25%,transparent) 65%,transparent);\
z-index:10;pointer-events:none}}\
.wrap{{max-width:1120px;margin:0 auto}}\
.mono{{font-family:{FONT_MONO};font-variant-ligatures:none}}\
.num{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums}}\
a{{color:{COLOR_GREEN};text-decoration:none}}\
a:hover{{text-decoration:underline}}\
:focus-visible{{outline:2px solid {COLOR_GREEN};outline-offset:2px;border-radius:4px}}\
.icon{{width:1em;height:1em;flex:none}}\
header.topbar{{display:flex;align-items:center;gap:16px;flex-wrap:wrap;\
padding:18px 0 16px;margin-bottom:24px;border-bottom:1px solid {COLOR_HAIRLINE}}}\
.brand{{display:flex;align-items:center;gap:9px;font-family:{FONT_MONO};\
font-size:13px;font-weight:600;letter-spacing:.02em;color:{COLOR_TEXT}}}\
.brand .mark{{display:flex;color:{COLOR_GREEN};font-size:18px}}\
.brand .dim{{color:{COLOR_MUTED};font-weight:500}}\
.topbar .target{{font-family:{FONT_MONO};font-size:13px;color:{COLOR_TEXT2};\
overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:46ch}}\
.topbar .spacer{{flex:1 1 auto}}\
.topbar .metric{{display:flex;flex-direction:column;align-items:flex-end;gap:1px}}\
.topbar .metric .val{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums;\
font-size:22px;font-weight:600;line-height:1}}\
.topbar .metric .cap{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:{COLOR_MUTED}}}\
.lede{{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin:0 0 18px}}\
.lede h1{{font-size:20px;line-height:1.3;font-weight:600;margin:0;letter-spacing:-.01em}}\
.lede .schema{{font-family:{FONT_MONO};font-size:12px;color:{COLOR_MUTED}}}\
section{{margin:28px 0 0}}\
.sec-head{{display:flex;align-items:center;gap:8px;margin:0 0 12px;\
padding-bottom:8px;border-bottom:1px solid {COLOR_BORDER_SUBTLE}}}\
.sec-head .ico{{display:flex;color:{COLOR_TEXT2};font-size:15px}}\
.sec-head h2{{font-size:12px;font-weight:600;text-transform:uppercase;\
letter-spacing:.06em;color:{COLOR_TEXT2};margin:0}}\
.sec-head .count{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums;\
font-size:11px;color:{COLOR_MUTED};margin-left:auto}}\
.panel{{background:{COLOR_SURFACE};border:1px solid {COLOR_HAIRLINE};\
border-radius:6px;overflow:hidden}}\
.panel.pad{{padding:16px}}\
.strip{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));\
background:{COLOR_HAIRLINE};gap:1px;border:1px solid {COLOR_HAIRLINE};border-radius:6px;overflow:hidden}}\
.cell{{background:{COLOR_SURFACE};padding:11px 14px;display:flex;flex-direction:column;gap:4px;min-width:0}}\
.cell .k{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:{COLOR_MUTED}}}\
.cell .v{{font-size:13px;color:{COLOR_TEXT};overflow-wrap:anywhere;word-break:break-word}}\
.cell .v.mono{{font-family:{FONT_MONO};font-size:12.5px}}\
.fmt-arrow{{color:{COLOR_MUTED};margin:0 6px}}\
table{{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}}\
thead th{{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;\
letter-spacing:.06em;color:{COLOR_MUTED};padding:9px 14px;\
border-bottom:1px solid {COLOR_HAIRLINE};background:{COLOR_INSET};white-space:nowrap}}\
tbody td{{padding:10px 14px;border-bottom:1px solid {COLOR_BORDER_SUBTLE};\
vertical-align:top;overflow-wrap:anywhere;word-break:break-word;color:{COLOR_TEXT}}}\
tbody tr:nth-child(even) td{{background:rgba(255,255,255,.015)}}\
tbody tr:last-child td{{border-bottom:none}}\
td.r,th.r{{text-align:right}}\
td.num{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums;color:{COLOR_TEXT2};white-space:nowrap}}\
td .mono{{font-family:{FONT_MONO};word-break:break-all}}\
.idx{{color:{COLOR_MUTED};font-family:{FONT_MONO};font-variant-numeric:tabular-nums}}\
td.nowrap{{white-space:nowrap;word-break:normal}}\
.chip{{display:inline-flex;align-items:center;gap:6px;height:20px;padding:0 8px;\
border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;\
letter-spacing:.04em;line-height:1;white-space:nowrap;border:1px solid}}\
.chip .dot{{width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}}\
.flow{{display:flex;align-items:center;gap:0;flex-wrap:wrap;padding:14px 16px;row-gap:10px}}\
.stage{{display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 11px;\
background:{COLOR_INSET};border:1px solid {COLOR_HAIRLINE};border-radius:6px;\
font-family:{FONT_MONO};font-size:12px;color:{COLOR_TEXT};white-space:nowrap}}\
.stage .dot{{width:6px;height:6px;border-radius:50%;flex:none}}\
.conn{{width:22px;height:1px;background:{COLOR_HAIRLINE};flex:none;position:relative}}\
.conn::after{{content:\"\";position:absolute;right:0;top:-2px;border:3px solid transparent;\
border-left-color:{COLOR_HAIRLINE}}}\
.track{{position:relative;height:6px;border-radius:3px;background:{COLOR_INSET};\
border:1px solid {COLOR_BORDER_SUBTLE};overflow:hidden;min-width:80px}}\
.track .fill{{position:absolute;left:0;top:0;bottom:0;border-radius:3px}}\
.scorecell{{display:flex;align-items:center;gap:10px}}\
.scorecell .pct{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums;\
font-size:12px;color:{COLOR_TEXT2};min-width:34px;text-align:right}}\
.histo{{display:flex;height:10px;border-radius:3px;overflow:hidden;\
border:1px solid {COLOR_BORDER_SUBTLE};background:{COLOR_INSET}}}\
.histo .seg{{height:100%}}\
.legend{{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:14px}}\
.legend .item{{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:{COLOR_TEXT2}}}\
.legend .sw{{width:9px;height:9px;border-radius:2px;flex:none}}\
.legend .n{{font-family:{FONT_MONO};font-variant-numeric:tabular-nums;color:{COLOR_MUTED}}}\
.tags{{display:flex;flex-wrap:wrap;gap:6px;padding:14px 16px 4px}}\
.tag{{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:4px;\
font-family:{FONT_MONO};font-size:11px;letter-spacing:.02em;\
border:1px solid {COLOR_BORDER_SUBTLE};background:{COLOR_INSET}}}\
.cat{{display:flex;align-items:flex-start;gap:8px}}\
.cat .ci{{display:flex;color:{COLOR_TEXT2};font-size:15px;margin-top:1px}}\
.cat .lbl{{font-weight:600;color:{COLOR_TEXT}}}\
.cat .desc{{font-size:12px;color:{COLOR_MUTED};margin-top:2px;font-weight:400}}\
.sig{{display:flex;flex-direction:column;gap:3px}}\
.sig .row{{display:flex;gap:8px;align-items:baseline}}\
.sig .src{{font-size:11px;color:{COLOR_MUTED};text-transform:uppercase;letter-spacing:.04em;flex:none}}\
.sig .more{{font-size:12px;color:{COLOR_MUTED}}}\
.empty{{padding:16px;color:{COLOR_MUTED};font-size:13px}}\
.note-list{{list-style:none;margin:0;padding:6px 0}}\
.note-list li{{display:flex;gap:10px;align-items:flex-start;padding:7px 16px;\
border-bottom:1px solid {COLOR_BORDER_SUBTLE};font-size:13px;color:{COLOR_TEXT2}}}\
.note-list li:last-child{{border-bottom:none}}\
.note-list li::before{{content:\"\";width:5px;height:5px;border-radius:50%;\
background:{COLOR_MUTED};margin-top:8px;flex:none}}\
footer{{margin-top:40px;padding-top:16px;border-top:1px solid {COLOR_BORDER_SUBTLE};\
display:flex;gap:8px;align-items:center;color:{COLOR_MUTED};font-size:12px}}\
footer .mono{{font-family:{FONT_MONO}}}\
footer .sep{{color:{COLOR_BORDER_SUBTLE}}}\
@media (prefers-reduced-motion:no-preference){{\
a,.chip,.stage{{transition:color .15s ease,opacity .15s ease}}}}"
    )
}

fn doc_open(title: &str, out: &mut String) {
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"color-scheme\" content=\"dark\">\
<meta name=\"generator\" content=\"disrobe report\">\
<title>{title}</title><style>{style}</style></head><body><main class=\"wrap\">",
        title = html_escape(title),
        style = style_block()
    );
}

fn doc_close(tool_version: &str, out: &mut String) {
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<footer>{mark}<span class=\"mono\">disrobe {ver}</span>\
<span class=\"sep\">/</span><span>deterministic</span>\
<span class=\"sep\">/</span><span>offline</span>\
<span class=\"sep\">/</span><span>self-contained</span></footer></main></body></html>",
        mark = icon(ICON_SHIELD),
        ver = html_escape(tool_version)
    );
}

fn brand_mark() -> String {
    format!(
        "<span class=\"brand\"><span class=\"mark\">{ico}</span>\
disrobe<span class=\"dim\">/report</span></span>",
        ico = icon(ICON_SHIELD)
    )
}

fn section_open(out: &mut String, icon_body: &str, title: &str, count: Option<String>) {
    let count_html: String = count.map_or_else(String::new, |c: String| {
        format!("<span class=\"count num\">{}</span>", html_escape(&c))
    });
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<section><div class=\"sec-head\"><span class=\"ico\">{ico}</span>\
<h2>{title}</h2>{count}</div>",
        ico = icon(icon_body),
        title = html_escape(title),
        count = count_html
    );
}

fn track(score: f64, color: &str) -> String {
    let pct: f64 = (score * 100.0).clamp(0.0, 100.0);
    format!(
        "<div class=\"track\" role=\"img\" aria-label=\"{pct:.0} percent recovered\">\
<span class=\"fill\" style=\"width:{pct:.2}%;background:{color}\"></span></div>"
    )
}

fn score_cell(score: f64, color: &str) -> String {
    let pct: f64 = (score * 100.0).clamp(0.0, 100.0);
    format!(
        "<div class=\"scorecell\">{track}<span class=\"pct\">{pct:.0}%</span></div>",
        track = track(score, color)
    )
}

fn status_chip(label: &str, color: &str) -> String {
    format!(
        "<span class=\"chip\" style=\"color:{color};background:color-mix(in srgb,{color} 10%,transparent);border-color:color-mix(in srgb,{color} 25%,transparent)\">\
<span class=\"dot\"></span>{label}</span>",
        label = html_escape(label)
    )
}

fn fmt_pair(input: Option<&str>, output: Option<&str>) -> String {
    match (input, output) {
        (Some(i), Some(o)) => format!(
            "{}<span class=\"fmt-arrow\">\u{2192}</span>{}",
            html_escape(i),
            html_escape(o)
        ),
        (Some(i), None) => html_escape(i),
        (None, Some(o)) => html_escape(o),
        (None, None) => format!("<span style=\"color:{COLOR_MUTED}\">\u{2014}</span>"),
    }
}

fn render_identity(id: &InputIdentity, out: &mut String) {
    out.push_str("<div class=\"strip\">");
    let name: String = id
        .path
        .as_deref()
        .map_or_else(|| "(unknown)".to_owned(), html_escape);
    cell(out, "input", &format!("<span class=\"mono\">{name}</span>"));
    cell(
        out,
        "size",
        &format!("<span class=\"num\">{}</span> bytes", id.size),
    );
    cell(
        out,
        "blake3",
        &format!("<span class=\"mono\">{}</span>", html_escape(&id.blake3)),
    );
    let detected: String = if id.detected.is_empty() {
        format!("<span style=\"color:{COLOR_MUTED}\">\u{2014}</span>")
    } else {
        id.detected
            .iter()
            .map(|d: &String| html_escape(d))
            .collect::<Vec<String>>()
            .join("<span class=\"fmt-arrow\">\u{2192}</span>")
    };
    let final_fmt: String = id
        .final_format
        .as_deref()
        .map_or_else(|| "\u{2014}".to_owned(), html_escape);
    cell(
        out,
        "detected \u{2192} final",
        &format!(
            "<span class=\"mono\">{detected}</span> <span class=\"fmt-arrow\">\u{2192}</span> <span class=\"mono\">{final_fmt}</span>"
        ),
    );
    out.push_str("</div>");
}

fn cell(out: &mut String, key: &str, value_html: &str) {
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<div class=\"cell\"><span class=\"k\">{k}</span><span class=\"v\">{v}</span></div>",
        k = html_escape(key),
        v = value_html
    );
}

fn render_flow(report: &SingleReport, out: &mut String) {
    section_open(out, ICON_FLOW, "Chain topology", None);
    out.push_str("<div class=\"panel\"><div class=\"flow\">");
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<span class=\"stage\"><span class=\"dot\" style=\"background:{COLOR_MUTED}\"></span>{}</span>",
        report
            .input
            .detected
            .first()
            .map_or_else(|| "input".to_owned(), |d: &String| html_escape(d))
    );
    for stage in &report.stages {
        let tier: &str = tier_label(stage.recovery_score);
        let color: &str = tier_color(tier);
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<span class=\"conn\"></span>\
<span class=\"stage\"><span class=\"dot\" style=\"background:{color}\"></span>{pass}</span>",
            pass = html_escape(&stage.pass)
        );
    }
    if let Some(ff) = report.input.final_format.as_deref() {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<span class=\"conn\"></span>\
<span class=\"stage\"><span class=\"dot\" style=\"background:{COLOR_GREEN}\"></span>{}</span>",
            html_escape(ff)
        );
    }
    out.push_str("</div></div></section>");
}

fn render_stage_table(report: &SingleReport, out: &mut String) {
    section_open(
        out,
        ICON_LAYERS,
        "Per-stage recovery",
        Some(format!("{} stages", report.stages.len())),
    );
    out.push_str(
        "<div class=\"panel\"><table><colgroup><col style=\"width:3ch\">\
<col><col style=\"width:13ch\"><col style=\"width:26%\"><col><col style=\"width:9ch\">\
</colgroup><thead><tr>\
<th class=\"r\">#</th><th>pass</th><th>tier</th><th>recovery</th>\
<th>format</th><th class=\"r\">time</th></tr></thead><tbody>",
    );
    for stage in &report.stages {
        let tier: &str = tier_label(stage.recovery_score);
        let color: &str = tier_color(tier);
        let dur: String = stage
            .duration_ms
            .map_or_else(|| "\u{2014}".to_owned(), |d: u128| format!("{d} ms"));
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td class=\"r idx\">{idx}</td><td><span class=\"mono\">{pass}</span></td>\
<td>{chip}</td><td>{score}</td>\
<td><span class=\"mono\">{fmt_cell}</span></td><td class=\"r num\">{dur}</td></tr>",
            idx = stage.index,
            pass = html_escape(&stage.pass),
            chip = status_chip(tier, color),
            score = score_cell(stage.recovery_score, color),
            fmt_cell = fmt_pair(stage.format_in.as_deref(), stage.format_out.as_deref()),
        );
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_tier_histogram(report: &SingleReport, out: &mut String) {
    let total: u32 = report.tiers.total;
    section_open(
        out,
        ICON_CHART,
        "Recovery-tier distribution",
        Some(format!("{total} scored")),
    );
    let segments: [(&str, u32, &str); 4] = [
        ("exact", report.tiers.exact, COLOR_GREEN),
        ("semantic", report.tiers.semantic, COLOR_SEMANTIC),
        ("partial", report.tiers.partial, COLOR_AMBER),
        ("skeleton", report.tiers.skeleton, COLOR_RED),
    ];
    if total == 0 {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no scored stages</div></div></section>",
        );
        return;
    }
    out.push_str("<div class=\"panel pad\"><div class=\"histo\" role=\"img\" aria-label=\"recovery tier distribution\">");
    for (label, count, color) in segments {
        if count == 0 {
            continue;
        }
        let pct: f64 = f64::from(count) / f64::from(total) * 100.0;
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<span class=\"seg\" style=\"width:{pct:.3}%;background:{color}\" \
title=\"{label}: {count}\"></span>"
        );
    }
    out.push_str("</div><div class=\"legend\">");
    for (label, count, color) in segments {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<span class=\"item\"><span class=\"sw\" style=\"background:{color}\"></span>\
{label}<span class=\"n\">{count}</span></span>"
        );
    }
    out.push_str("</div></div></section>");
}

fn render_artifacts(report: &SingleReport, out: &mut String) {
    section_open(
        out,
        ICON_BOX,
        "Recovered artifacts",
        Some(report.artifacts.len().to_string()),
    );
    if report.artifacts.is_empty() {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no artifacts recovered</div></div></section>",
        );
        return;
    }
    out.push_str(
        "<div class=\"panel\"><table><colgroup><col style=\"width:4ch\"><col></colgroup>\
<thead><tr><th class=\"r\">#</th><th>artifact</th></tr></thead><tbody>",
    );
    for (i, artifact) in report.artifacts.iter().enumerate() {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td class=\"r idx\">{n}</td><td><span class=\"mono\">{a}</span></td></tr>",
            n = i + 1,
            a = html_escape(artifact)
        );
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_capabilities(report: &SingleReport, out: &mut String) {
    let count: Option<String> = report
        .capabilities
        .report
        .as_ref()
        .filter(|_| report.capabilities.available)
        .map(|capabilities| capabilities.matched_rules.to_string());
    section_open(out, ICON_SHIELD, "Capabilities", count);
    let Some(capabilities) = report
        .capabilities
        .report
        .as_ref()
        .filter(|_| report.capabilities.available)
    else {
        let reason: &str = report
            .capabilities
            .reason
            .as_deref()
            .unwrap_or("no capability report was produced");
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<div class=\"panel\"><div class=\"empty\">{}</div></div></section>",
            html_escape(reason)
        );
        return;
    };
    if capabilities.capabilities.is_empty() {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no capabilities matched</div></div></section>",
        );
        return;
    }
    out.push_str(
        "<div class=\"panel\"><table><thead><tr><th class=\"r\">address</th><th>rule</th>\
<th>scope</th><th>description</th></tr></thead><tbody>",
    );
    for capability in &capabilities.capabilities {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td class=\"r num\">{:#x}</td><td><span class=\"mono\">{}</span></td>\
<td>{}</td><td>{}</td></tr>",
            capability.address,
            html_escape(&capability.rule),
            html_escape(capability.scope.label()),
            html_escape(&capability.description)
        );
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_ioc(ioc_report: &IocReport, out: &mut String) {
    section_open(
        out,
        ICON_NETWORK,
        "Indicators of compromise",
        Some(ioc_report.total.to_string()),
    );
    if ioc_report.indicators.is_empty() {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no indicators found</div></div></section>",
        );
        return;
    }
    out.push_str(
        "<div class=\"panel\"><table><colgroup><col style=\"width:14ch\">\
<col style=\"width:11ch\"><col style=\"width:11ch\"><col></colgroup><thead><tr>\
<th>kind</th><th>encoding</th><th class=\"r\">offset</th>\
<th>value <span style=\"color:var(--card-faint);font-weight:400;text-transform:none;letter-spacing:0\">(defanged)</span></th></tr></thead><tbody>",
    );
    for ind in ioc_report.indicators.iter().take(MAX_IOC_ROWS) {
        let defanged: String = ioc::defang(&ind.value, ind.kind);
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td class=\"nowrap\">{kind}</td><td><span style=\"color:var(--card-text2)\">{enc}</span></td>\
<td class=\"r num\">{off}</td><td><span class=\"mono\">{val}</span></td></tr>",
            kind = html_escape(ind.kind.label()),
            enc = html_escape(ind.encoding.label()),
            off = ind.offset,
            val = html_escape(&defanged)
        );
    }
    out.push_str("</tbody></table>");
    if ioc_report.indicators.len() > MAX_IOC_ROWS {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<div class=\"empty\">\u{2026} {} more indicator(s) omitted</div>",
            ioc_report.indicators.len() - MAX_IOC_ROWS
        );
    }
    out.push_str("</div></section>");
}

fn render_behavior(report: &BehaviorReport, out: &mut String) {
    section_open(
        out,
        ICON_TARGET,
        "Behavior \u{2022} ATT&CK",
        Some(format!("{} categories", report.categories.len())),
    );
    if report.categories.is_empty() {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no notable behaviors detected</div></div></section>",
        );
        return;
    }
    out.push_str("<div class=\"panel\">");
    if !report.attack_ids.is_empty() {
        out.push_str("<div class=\"tags\">");
        for id in &report.attack_ids {
            let _: Result<(), std::fmt::Error> = write!(
                out,
                "<span class=\"tag\" style=\"color:{COLOR_VIOLET};border-color:color-mix(in srgb,{COLOR_VIOLET} 25%,transparent)\">{}</span>",
                html_escape(id)
            );
        }
        out.push_str("</div>");
    }
    out.push_str(
        "<table><colgroup><col style=\"width:32%\"><col><col style=\"width:18ch\"></colgroup>\
<thead><tr><th>category</th><th>signals</th><th>att&amp;ck</th></tr></thead><tbody>",
    );
    for finding in &report.categories {
        render_behavior_row(finding, out);
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_behavior_row(finding: &CategoryFinding, out: &mut String) {
    let mut signals: String = String::new();
    for ev in finding.evidence.iter().take(MAX_BEHAVIOR_EVIDENCE) {
        let signal: String = trim_signal(&ev.signal);
        let _: Result<(), std::fmt::Error> = write!(
            signals,
            "<div class=\"row\"><span class=\"mono\">{sig}</span>\
<span class=\"src\">{src}</span></div>",
            sig = html_escape(&signal),
            src = html_escape(ev.source)
        );
    }
    if finding.evidence.len() > MAX_BEHAVIOR_EVIDENCE {
        let _: Result<(), std::fmt::Error> = write!(
            signals,
            "<div class=\"more\">\u{2026} {} more</div>",
            finding.evidence.len() - MAX_BEHAVIOR_EVIDENCE
        );
    }
    let attack: String = if finding.attack_ids.is_empty() {
        format!("<span style=\"color:{COLOR_MUTED}\">\u{2014}</span>")
    } else {
        finding
            .attack_ids
            .iter()
            .map(|a: &&str| html_escape(a))
            .collect::<Vec<String>>()
            .join(", ")
    };
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<tr><td><div class=\"cat\"><span class=\"ci\">{ico}</span>\
<div><div class=\"lbl\">{cat}</div><div class=\"desc\">{desc}</div></div></div></td>\
<td><div class=\"sig\">{signals}</div></td><td class=\"mono\">{attack}</td></tr>",
        ico = icon(category_icon(finding.category)),
        cat = html_escape(finding.category.label()),
        desc = html_escape(finding.description),
    );
}

fn trim_signal(signal: &str) -> String {
    const MAX: usize = 90;
    let cleaned: String = signal.replace(['\n', '\r', '\t'], " ");
    if cleaned.chars().count() <= MAX {
        cleaned
    } else {
        let head: String = cleaned.chars().take(MAX).collect();
        format!("{head}\u{2026}")
    }
}

fn render_walls(report: &SingleReport, out: &mut String) {
    let total: usize = report.walls.len().saturating_add(report.failures.len());
    section_open(
        out,
        ICON_LOCK,
        "Walls and failures",
        Some(total.to_string()),
    );
    if total == 0 {
        out.push_str(
            "<div class=\"panel\"><div class=\"empty\">no layer stopped short and no layer failed</div></div></section>",
        );
        return;
    }
    out.push_str(
        "<div class=\"panel\"><table><thead><tr><th>kind</th><th class=\"r\">node</th>\
<th>pass</th><th>missing input</th></tr></thead><tbody>",
    );
    for wall in &report.walls {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td>{k}</td><td class=\"r idx\">{n}</td><td><span class=\"mono\">{p}</span></td><td>{m}</td></tr>",
            k = status_chip(wall.kind.label(), "var(--warn)"),
            n = wall.node_id,
            p = html_escape(wall.pass.as_deref().unwrap_or("terminal")),
            m = html_escape(&wall.missing)
        );
    }
    for failure in &report.failures {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td>{k}</td><td class=\"r idx\">{n}</td><td><span class=\"mono\">{p}</span></td><td>{m}</td></tr>",
            k = status_chip("failure", "var(--bad)"),
            n = failure.node_id,
            p = html_escape(failure.pass.as_deref().unwrap_or("terminal")),
            m = html_escape(&failure.message)
        );
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_evidence(report: &SingleReport, out: &mut String) {
    section_open(
        out,
        ICON_KEY,
        "Evidence",
        Some(report.evidence.len().to_string()),
    );
    out.push_str(
        "<div class=\"panel\"><table><thead><tr><th>role</th><th>artifact</th>\
<th class=\"r\">offset</th><th class=\"r\">length</th><th>blake3</th><th>digest source</th></tr></thead><tbody>",
    );
    for item in &report.evidence {
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td>{role}</td><td><span class=\"mono\">{uri}</span></td>\
<td class=\"r num\">{off}</td><td class=\"r num\">{len}</td>\
<td><span class=\"mono\">{hash}</span></td><td>{src}</td></tr>",
            role = html_escape(item.role.label()),
            uri = html_escape(&item.uri),
            off = item.byte_offset,
            len = item
                .byte_length
                .map_or_else(|| "\u{2014}".to_owned(), |l: u64| l.to_string()),
            hash = html_escape(item.blake3.as_deref().unwrap_or("\u{2014}")),
            src = html_escape(
                item.unavailable_reason
                    .as_deref()
                    .unwrap_or_else(|| item.hash_source.label())
            )
        );
    }
    out.push_str("</tbody></table></div></section>");
}

fn render_reproduction(report: &SingleReport, out: &mut String) {
    section_open(out, ICON_TERMINAL, "Reproduction", None);
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<div class=\"panel\"><pre class=\"mono\">{}</pre><ul class=\"note-list\">",
        html_escape(&report.reproduction.command)
    );
    for step in &report.reproduction.steps {
        let _: Result<(), std::fmt::Error> = write!(out, "<li>{}</li>", html_escape(step));
    }
    out.push_str("</ul></div></section>");
}

fn render_notes(report: &SingleReport, out: &mut String) {
    if report.notes.is_empty() {
        return;
    }
    section_open(out, ICON_NOTE, "Notes", None);
    out.push_str("<div class=\"panel\"><ul class=\"note-list\">");
    for note in &report.notes {
        let _: Result<(), std::fmt::Error> = write!(out, "<li>{}</li>", html_escape(note));
    }
    out.push_str("</ul></div></section>");
}

#[must_use]
pub(crate) fn render_single_html(report: &SingleReport, enrichment: &Enrichment) -> String {
    let title: String = report.input.path.as_deref().map_or_else(
        || "disrobe report".to_owned(),
        |p: &str| format!("disrobe report \u{2014} {p}"),
    );
    let mut out: String = String::with_capacity(16384);
    doc_open(&title, &mut out);

    let tier: &str = tier_label(report.recovery_score);
    let color: &str = tier_color(tier);

    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<header class=\"topbar\">{mark}<span class=\"target\">{target}</span>\
<span class=\"spacer\"></span>{chip}\
<div class=\"metric\"><span class=\"val\" style=\"color:{color}\">{pct:.0}%</span>\
<span class=\"cap\">recovery</span></div></header>",
        mark = brand_mark(),
        target = report
            .input
            .path
            .as_deref()
            .map_or_else(|| "(unknown input)".to_owned(), html_escape),
        chip = status_chip(&report.verdict, color),
        pct = report.recovery_score * 100.0,
    );

    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<div class=\"lede\"><h1>Forensic recovery summary</h1>\
<span class=\"schema\">schema {schema}</span></div>",
        schema = html_escape(&report.schema)
    );

    section_open(&mut out, ICON_FILE, "Input identity", None);
    render_identity(&report.input, &mut out);
    out.push_str("</section>");

    render_flow(report, &mut out);
    render_stage_table(report, &mut out);
    render_tier_histogram(report, &mut out);
    render_walls(report, &mut out);
    render_capabilities(report, &mut out);
    render_artifacts(report, &mut out);
    render_evidence(report, &mut out);
    render_reproduction(report, &mut out);

    if let Some(ioc_report) = enrichment.ioc.as_ref() {
        render_ioc(ioc_report, &mut out);
    }
    if let Some(behavior_report) = enrichment.behavior.as_ref() {
        render_behavior(behavior_report, &mut out);
    }

    render_notes(report, &mut out);

    doc_close(&report.tool_version, &mut out);
    out
}

#[must_use]
pub(crate) fn render_batch_html(report: &BatchReport) -> String {
    let mut out: String = String::with_capacity(16384);
    doc_open("disrobe report (batch)", &mut out);

    let mean: f64 = report.mean_recovery_score.unwrap_or(0.0);
    let mean_color: &str = tier_color(tier_label(mean));
    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<header class=\"topbar\">{mark}<span class=\"target\">{root}</span>\
<span class=\"spacer\"></span>\
<div class=\"metric\"><span class=\"val\" style=\"color:{mean_color}\">{mean_txt}</span>\
<span class=\"cap\">mean recovery</span></div></header>",
        mark = brand_mark(),
        root = html_escape(&report.root),
        mean_txt = report.mean_recovery_score.map_or_else(
            || "\u{2014}".to_owned(),
            |m: f64| format!("{:.0}%", m * 100.0)
        ),
    );

    let _: Result<(), std::fmt::Error> = write!(
        out,
        "<div class=\"lede\"><h1>Batch recovery summary</h1>\
<span class=\"schema\">schema {schema}</span></div>",
        schema = html_escape(&report.schema)
    );

    section_open(&mut out, ICON_FOLDER, "Run", None);
    out.push_str("<div class=\"strip\">");
    cell(
        &mut out,
        "chain",
        &format!("<span class=\"mono\">{}</span>", html_escape(&report.chain)),
    );
    cell(
        &mut out,
        "processed",
        &format!("<span class=\"num\">{}</span>", report.processed),
    );
    cell(
        &mut out,
        "recovered",
        &format!(
            "<span class=\"num\" style=\"color:{COLOR_GREEN}\">{}</span>",
            report.recovered
        ),
    );
    cell(
        &mut out,
        "detect-only",
        &format!(
            "<span class=\"num\" style=\"color:{COLOR_AMBER}\">{}</span>",
            report.detect_only
        ),
    );
    cell(
        &mut out,
        "errors",
        &format!(
            "<span class=\"num\" style=\"color:{COLOR_RED}\">{}</span>",
            report.errors
        ),
    );
    out.push_str("</div></section>");

    section_open(
        &mut out,
        ICON_LAYERS,
        "Per-file results",
        Some(format!("{} files", report.files.len())),
    );
    out.push_str(
        "<div class=\"panel\"><table><colgroup><col><col style=\"width:14ch\">\
<col style=\"width:26%\"><col style=\"width:15ch\"></colgroup><thead><tr>\
<th>file</th><th>format</th><th>recovery</th><th>status</th></tr></thead><tbody>",
    );
    for file in &report.files {
        let (status_label, status_color): (&str, &str) = if file.error.is_some() {
            ("error", COLOR_RED)
        } else if file.chain.is_empty() {
            ("detect-only", COLOR_AMBER)
        } else {
            ("recovered", COLOR_GREEN)
        };
        let score: String = file.recovery_score.map_or_else(
            || format!("<span style=\"color:{COLOR_MUTED}\">\u{2014}</span>"),
            |s: f64| score_cell(s, tier_color(tier_label(s))),
        );
        let detail: String = file.error.as_deref().map_or_else(
            || html_escape(file.detected_format.as_deref().unwrap_or("\u{2014}")),
            |e: &str| {
                format!(
                    "<span style=\"color:{COLOR_RED}\">{}</span>",
                    html_escape(e)
                )
            },
        );
        let _: Result<(), std::fmt::Error> = write!(
            out,
            "<tr><td><span class=\"mono\">{rel}</span></td>\
<td><span class=\"mono\">{detail}</span></td><td>{score}</td><td>{chip}</td></tr>",
            rel = html_escape(&file.relative),
            chip = status_chip(status_label, status_color)
        );
    }
    out.push_str("</tbody></table></div></section>");

    doc_close(&report.tool_version, &mut out);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_capabilities::{
        CapabilitiesReport, CapabilityMatch, Evidence as CapabilityEvidence, Scope,
    };
    use disrobe_core::behavior::{Category, Evidence};

    use super::super::report::{CapabilitySection, StageView};

    fn populated_capabilities() -> CapabilitySection {
        CapabilitySection {
            available: true,
            report: Some(CapabilitiesReport {
                schema: disrobe_capabilities::CAPABILITIES_SCHEMA,
                uri: Some("app.pyc".to_owned()),
                byte_len: 128,
                matched_rules: 1,
                attack: vec!["T1059".to_owned()],
                mbc: vec!["B0001".to_owned()],
                capabilities: vec![CapabilityMatch {
                    rule: "execution/shell".to_owned(),
                    namespace: "execution".to_owned(),
                    scope: Scope::File,
                    function: None,
                    function_address: None,
                    address: 0x40,
                    attack: vec!["T1059".to_owned()],
                    mbc: vec!["B0001".to_owned()],
                    description: "launches a shell".to_owned(),
                    evidence: vec![CapabilityEvidence {
                        feature: "api:ShellExecuteW".to_owned(),
                        address: 0x40,
                    }],
                }],
            }),
            reason: None,
        }
    }

    fn sample_single() -> SingleReport {
        SingleReport {
            kind: "single",
            schema: "disrobe.report/v1".to_owned(),
            tool_version: "0.9.0".to_owned(),
            source_dir: None,
            input: InputIdentity {
                path: Some("app.pyc".to_owned()),
                size: 128,
                blake3: "abcd1234".to_owned(),
                detected: vec!["pyc-3.11".to_owned()],
                final_format: Some("Python".to_owned()),
            },
            topology: "Linear".to_owned(),
            verdict: "Complete".to_owned(),
            total_ms: 7,
            recovery_score: 0.6666,
            tiers: super::super::report::tier_totals_for_test(0, 1, 0, 0),
            stages: vec![StageView {
                index: 1,
                node_id: 1,
                pass: "py.decompile".to_owned(),
                verdict: "Complete".to_owned(),
                confidence: "semantic",
                recovery_score: 0.6666,
                duration_ms: Some(7),
                format_in: Some("pyc-3.11".to_owned()),
                format_out: Some("Python".to_owned()),
                artifacts: vec!["app.py".to_owned()],
            }],
            walls: vec![WallView {
                kind: WallKind::DepthCapReached,
                node_id: 1,
                stage_index: Some(1),
                pass: Some("py.decompile".to_owned()),
                format_in: Some("pyc-3.11".to_owned()),
                missing: "the chain reached its depth cap of 8 layers at depth 1".to_owned(),
                artifact_blake3: "abcd1234".to_owned(),
                artifact_size: 128,
            }],
            capabilities: populated_capabilities(),
            failures: Vec::new(),
            evidence: vec![EvidenceItem {
                role: EvidenceRole::AnalysisTarget,
                uri: "app.pyc".to_owned(),
                display: "app.pyc".to_owned(),
                blake3: Some("abcd1234".to_owned()),
                hash_source: HashSource::ChainDocument,
                byte_offset: 0,
                byte_length: Some(128),
                stage_index: None,
                node_id: Some(0),
                unavailable_reason: None,
            }],
            reproduction: Reproduction {
                command: "disrobe report out/app-auto".to_owned(),
                steps: vec!["hash the analysis target with blake3".to_owned()],
            },
            artifacts: vec!["app.py".to_owned()],
            notes: vec!["semantic-tier recovery".to_owned()],
        }
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        let raw: &str = "<script>alert(\"x&y\")</script>'";
        let escaped: String = html_escape(raw);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;&#39;"
        );
    }

    #[test]
    fn single_html_is_self_contained_and_structured() {
        let report: SingleReport = sample_single();
        let html: String = render_single_html(&report, &Enrichment::default());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("<script"));
        assert!(!html.to_lowercase().contains("http://"));
        assert!(
            !html.to_lowercase().contains("https://"),
            "no external/CDN URLs may appear"
        );
        assert!(!html.contains("cdn"));
        assert!(html.contains("py.decompile"));
        assert!(html.contains("app.py"));
        assert!(html.contains("abcd1234"));
        assert!(html.contains("Input identity"));
        assert!(html.contains("Chain topology"));
        assert!(html.contains("Recovery-tier distribution"));
        assert!(html.contains("Capabilities"));
        assert!(html.contains("execution/shell"));
        assert!(html.contains("<svg"));
    }

    #[test]
    fn design_tokens_and_system_fonts_present() {
        let report: SingleReport = sample_single();
        let html: String = render_single_html(&report, &Enrichment::default());
        assert!(
            html.contains(SHARED_THEME_TOKENS.trim()),
            "report html must inline the shared docs theme token source"
        );
        for token in [
            "--card-canvas",
            "--card-surface",
            "--card-panel",
            "--card-hairline",
            "--card-subtle",
            "--card-text",
            "--card-text2",
            "--card-faint",
            "--card-green",
            "--card-keyword",
            "--card-amber",
            "--card-red",
            "--card-sans",
            "--card-mono",
        ] {
            assert!(html.contains(token), "missing shared theme token {token}");
        }
        assert_eq!(COLOR_BG, "var(--card-canvas)");
        assert_eq!(COLOR_SURFACE, "var(--card-surface)");
        assert_eq!(COLOR_INSET, "var(--card-panel)");
        assert_eq!(COLOR_HAIRLINE, "var(--card-hairline)");
        assert_eq!(COLOR_BORDER_SUBTLE, "var(--card-subtle)");
        assert_eq!(COLOR_TEXT, "var(--card-text)");
        assert_eq!(COLOR_TEXT2, "var(--card-text2)");
        assert_eq!(COLOR_MUTED, "var(--card-faint)");
        assert_eq!(COLOR_GREEN, "var(--card-green)");
        assert_eq!(COLOR_AMBER, "var(--card-amber)");
        assert_eq!(COLOR_RED, "var(--card-red)");
        assert_eq!(COLOR_SEMANTIC, "var(--card-keyword)");
        assert_eq!(COLOR_VIOLET, "var(--card-blue)");
        assert_eq!(FONT_SANS, "var(--card-sans)");
        assert_eq!(FONT_MONO, "var(--card-mono)");
        for stale in [
            "#121212", "#4d9375", "#dbd7ca", "#aaa79b", "#758575", "#cb7676", "#d4976c", "#d3869b",
            "#0d1117", "#161b22", "58a6ff", "388bc4", "#0f141a", "#30363d",
        ] {
            assert!(
                !html.contains(stale),
                "no stale vitesse / github-dark token may survive: {stale}"
            );
        }
        assert!(html.contains("system-ui"), "system sans stack must be used");
        assert!(
            html.contains("\"JetBrains Mono\", ui-monospace"),
            "JetBrains Mono must lead the monospace stack"
        );
        assert!(
            !html.contains("fonts.googleapis"),
            "no google fonts allowed"
        );
        assert!(
            !html.to_lowercase().contains("box-shadow"),
            "elevation must be flat: no drop shadows"
        );
        assert!(
            !html.contains("radial-gradient"),
            "no radial gradients in the flat system"
        );
        assert_eq!(
            html.matches("linear-gradient").count(),
            1,
            "the only permitted gradient is the single 1px top-edge highlight line"
        );
    }

    #[test]
    fn status_chips_are_dot_plus_label_not_color_alone() {
        let report: SingleReport = sample_single();
        let html: String = render_single_html(&report, &Enrichment::default());
        assert!(html.contains("class=\"chip\""), "status chips must render");
        assert!(
            html.contains("class=\"dot\""),
            "chips must carry a color dot for non-color status encoding"
        );
        assert!(
            html.contains(">semantic<"),
            "tier label text must accompany the dot"
        );
        assert!(
            html.contains("class=\"fill\""),
            "score bars must render an inset fill"
        );
    }

    #[test]
    fn single_html_escapes_hostile_fields() {
        let mut report: SingleReport = sample_single();
        report.input.path = Some("<img src=x onerror=alert(1)>".to_owned());
        report.stages[0].pass = "<b>evil</b>".to_owned();
        report.artifacts = vec!["a\"><script>".to_owned()];
        let html: String = render_single_html(&report, &Enrichment::default());
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<b>evil</b>"));
        assert!(!html.contains("\"><script>"));
        assert!(html.contains("&lt;img src=x"));
        assert!(html.contains("&lt;b&gt;evil&lt;/b&gt;"));
    }

    #[test]
    fn single_html_is_deterministic() {
        let report: SingleReport = sample_single();
        let a: String = render_single_html(&report, &Enrichment::default());
        let b: String = render_single_html(&report, &Enrichment::default());
        assert_eq!(a, b);
    }

    #[test]
    fn html_keeps_an_empty_capability_report_distinct_from_an_unavailable_one() {
        let mut report: SingleReport = sample_single();
        report
            .capabilities
            .report
            .as_mut()
            .expect("report")
            .capabilities = Vec::new();
        report
            .capabilities
            .report
            .as_mut()
            .expect("report")
            .matched_rules = 0;
        let empty: String = render_single_html(&report, &Enrichment::default());
        assert!(empty.contains("no capabilities matched"), "got: {empty}");

        report.capabilities = CapabilitySection {
            available: false,
            report: None,
            reason: Some("target is unavailable".to_owned()),
        };
        let unavailable: String = render_single_html(&report, &Enrichment::default());
        assert!(
            unavailable.contains("target is unavailable"),
            "got: {unavailable}"
        );
    }

    #[test]
    fn enrichment_renders_ioc_and_behavior() {
        let report: SingleReport = sample_single();
        let ioc_report: IocReport = ioc::report(
            b"reach http://c2.evil.example/ and 8.8.8.8",
            Some("app.pyc"),
        );
        let behavior_report: BehaviorReport =
            behavior::analyze(b"connect to host", &["ws2_32.dll!connect".to_owned()]);
        let enrichment: Enrichment = Enrichment {
            ioc: Some(ioc_report),
            behavior: Some(behavior_report),
        };
        let html: String = render_single_html(&report, &enrichment);
        assert!(html.contains("Indicators of compromise"));
        assert!(html.contains("Behavior"));
        assert!(html.contains("[.]"), "ioc values must be defanged");
        assert!(!html.contains("http://c2.evil.example/"));
        let net: bool = html.contains("network");
        assert!(net, "behavior network category should render");
    }

    #[test]
    fn behavior_evidence_is_escaped_and_capped() {
        let mut finding: CategoryFinding = CategoryFinding {
            category: Category::DynamicCode,
            description: "dynamic code / loader",
            evidence: Vec::new(),
            attack_ids: vec!["T1059"],
        };
        for i in 0..20 {
            finding.evidence.push(Evidence {
                signal: format!("<x>{i}</x>"),
                source: "string",
                attack_id: None,
            });
        }
        let mut out: String = String::new();
        render_behavior_row(&finding, &mut out);
        assert!(!out.contains("<x>0</x>"));
        assert!(out.contains("&lt;x&gt;0&lt;/x&gt;"));
        assert!(out.contains("more"));
    }

    #[test]
    fn batch_html_renders_rows_and_status() {
        use super::super::report::batch_report_for_test;
        let report: BatchReport = batch_report_for_test();
        let html: String = render_batch_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("Per-file results"));
        assert!(html.contains("recovered"));
        assert!(html.contains("error"));
        assert!(!html.contains("<script"));
        assert!(
            html.contains("class=\"chip\""),
            "batch status chips must render"
        );
    }
}
