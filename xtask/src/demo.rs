use std::fmt::Arguments;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

use crate::fileio::{read_bytes_bounded, read_text_bounded};

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

const CANVAS: &str = "#0a0a0a";
const SURFACE: &str = "#161616";
const HAIRLINE: &str = "#262626";
const TEXT: &str = "#ededed";
const TEXT_MUTED: &str = "#a1a1a1";
const TEXT_FAINT: &str = "#828282";
const ACCENT_BLUE: &str = "#8fb3d9";
const ACCENT_AMBER: &str = "#c9a98e";
const ACCENT_RED: &str = "#d08c8c";

const MONO: &str =
    "'JetBrains Mono', ui-monospace, 'Fira Code', SFMono-Regular, Menlo, Consolas, monospace";

const SVG_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

const PROMPT: &str = "user@disrobe:~$ ";
const HOST_TOKEN: &str = "user@disrobe";
const TAIL_HOLD: f64 = 2.6;

const CELL_W: f64 = 8.0;
const CELL_H: f64 = 19.0;
const FONT_SIZE: f64 = 13.0;
const PAD_X: f64 = 20.0;
const TITLE_H: f64 = 34.0;
const BODY_TOP: f64 = TITLE_H + 14.0;
const BODY_PAD_BOTTOM: f64 = 12.0;

const MAX_CAST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SVG_BYTES: usize = 8 * 1024 * 1024;
const MAX_SVG_BYTES_U64: u64 = MAX_SVG_BYTES as u64;
const MAX_LINES: usize = 4_096;

#[derive(Debug, Deserialize)]
struct CastHeader {
    version: u32,
    width: u32,
    height: u32,
}

#[derive(Debug, Clone)]
struct CastEvent {
    time: f64,
    data: String,
}

#[derive(Debug)]
struct Cast {
    cols: usize,
    rows: usize,
    events: Vec<CastEvent>,
    duration: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    Static,
    Typed,
    Bar,
    RestingPrompt,
}

#[derive(Debug, Clone)]
struct Line {
    index: usize,
    appear: f64,
    end_change: f64,
    states: Vec<(f64, String)>,
    kind: LineKind,
}

#[derive(Debug, Clone)]
struct Cursor {
    line: usize,
    steps: Vec<(f64, f64)>,
    start: f64,
    end: f64,
}

#[derive(Debug)]
struct Model {
    lines: Vec<Line>,
    cursors: Vec<Cursor>,
    scroll: Vec<(f64, usize)>,
    rows: usize,
    cols: usize,
    duration: f64,
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let cast_path: PathBuf = root.join("docs").join("demo").join("disrobe.cast");
    let svg_path: PathBuf = root
        .join("docs")
        .join("src")
        .join("demo")
        .join("disrobe-demo.svg");

    let cast: Cast = parse_cast(&cast_path)?;
    let model: Model = build_model(&cast)?;
    let svg: String = render(&model)?;

    if check {
        match read_bytes_bounded(&svg_path, MAX_SVG_BYTES_U64) {
            Ok(on_disk) if on_disk == svg.as_bytes() => {
                println!(
                    "xtask demo --check: {} matches regeneration",
                    svg_path.display()
                );
                Ok(())
            }
            Ok(_) => bail!(
                "committed demo SVG is stale; run `cargo run -p xtask -- demo`:\n  {} differs from regenerated output",
                svg_path.display()
            ),
            Err(err) => bail!("{} unreadable: {err}", svg_path.display()),
        }
    } else {
        fs::create_dir_all(svg_path.parent().unwrap_or(root))
            .wrap_err_with(|| format!("creating parent of {}", svg_path.display()))?;
        fs::write(&svg_path, svg.as_bytes())
            .wrap_err_with(|| format!("writing {}", svg_path.display()))?;
        println!(
            "xtask demo: wrote {} ({} lines)",
            svg_path.display(),
            model.lines.len()
        );
        Ok(())
    }
}

fn parse_cast(path: &Path) -> Result<Cast> {
    let raw: String = read_text_bounded(path, MAX_CAST_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let mut lines: std::str::Lines<'_> = raw.lines();
    let Some(header_line): Option<&str> = lines.next() else {
        bail!("cast {} is empty", path.display());
    };
    let header: CastHeader = serde_json::from_str(header_line)
        .wrap_err_with(|| format!("parsing cast header in {}", path.display()))?;
    if header.version != 2 {
        bail!("cast {} is not asciinema v2", path.display());
    }
    let mut events: Vec<CastEvent> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: (f64, String, String) = serde_json::from_str(line)
            .wrap_err_with(|| format!("parsing cast event `{line}` in {}", path.display()))?;
        let (time, code, data): (f64, String, String) = parsed;
        if code != "o" {
            continue;
        }
        events.push(CastEvent { time, data });
    }
    if events.is_empty() {
        bail!("cast {} has no output events", path.display());
    }
    let duration: f64 = events.last().map_or(0.0, |e: &CastEvent| e.time) + TAIL_HOLD;
    Ok(Cast {
        cols: header.width as usize,
        rows: header.height as usize,
        events,
        duration,
    })
}

struct Terminal {
    cols: usize,
    rows: usize,
    lines: Vec<String>,
    histories: Vec<Vec<(f64, String)>>,
    cur_line: usize,
    cur_col: usize,
    max_line: usize,
    scroll: Vec<(f64, usize)>,
}

impl Terminal {
    fn new(cols: usize, rows: usize) -> Self {
        Self {
            cols,
            rows,
            lines: vec![String::new()],
            histories: vec![Vec::new()],
            cur_line: 0,
            cur_col: 0,
            max_line: 0,
            scroll: vec![(0.0, 0)],
        }
    }

    fn grow_to(&mut self, index: usize) {
        while self.lines.len() <= index {
            self.lines.push(String::new());
            self.histories.push(Vec::new());
        }
    }

    fn newline(&mut self, time: f64) {
        self.cur_line += 1;
        self.cur_col = 0;
        self.grow_to(self.cur_line);
        if self.cur_line > self.max_line {
            self.max_line = self.cur_line;
            let offset: usize = (self.max_line + 1).saturating_sub(self.rows);
            let last: usize = self.scroll.last().map_or(0, |&(_, o): &(f64, usize)| o);
            if offset != last {
                self.scroll.push((time, offset));
            }
        }
    }

    fn put(&mut self, ch: char) {
        self.grow_to(self.cur_line);
        let line: &mut String = &mut self.lines[self.cur_line];
        let mut chars: Vec<char> = line.chars().collect();
        if self.cur_col < chars.len() {
            chars[self.cur_col] = ch;
        } else {
            while chars.len() < self.cur_col {
                chars.push(' ');
            }
            chars.push(ch);
        }
        *line = chars.into_iter().collect();
        self.cur_col += 1;
        if self.cur_col >= self.cols {
            self.cur_col = self.cols - 1;
        }
    }

    fn apply(&mut self, event: &CastEvent) {
        let chars: Vec<char> = event.data.chars().collect();
        let mut dirty: Vec<usize> = Vec::new();
        let mut i: usize = 0;
        while i < chars.len() {
            let ch: char = chars[i];
            match ch {
                '\u{1b}' => {
                    i += 1;
                    if chars.get(i) == Some(&'[') {
                        i += 1;
                        while i < chars.len() && !chars[i].is_ascii_alphabetic() {
                            i += 1;
                        }
                    }
                }
                '\r' => self.cur_col = 0,
                '\n' => {
                    self.newline(event.time);
                }
                '\t' => {
                    let stop: usize = (self.cur_col / 8 + 1) * 8;
                    while self.cur_col < stop && self.cur_col < self.cols {
                        self.put(' ');
                    }
                    dirty.push(self.cur_line);
                }
                c if (c as u32) < 0x20 => {}
                c => {
                    self.put(c);
                    dirty.push(self.cur_line);
                }
            }
            i += 1;
        }
        dirty.sort_unstable();
        dirty.dedup();
        for idx in dirty {
            let snapshot: String = self.lines[idx].clone();
            let hist: &mut Vec<(f64, String)> = &mut self.histories[idx];
            if hist.last().map(|(_, s): &(f64, String)| s.as_str()) != Some(snapshot.as_str()) {
                hist.push((event.time, snapshot));
            }
        }
    }
}

fn build_model(cast: &Cast) -> Result<Model> {
    let mut term: Terminal = Terminal::new(cast.cols, cast.rows);
    for event in &cast.events {
        term.apply(event);
        if term.lines.len() > MAX_LINES {
            bail!("cast expands past {MAX_LINES} physical lines");
        }
    }

    let mut lines: Vec<Line> = Vec::new();
    for (index, hist) in term.histories.iter().enumerate() {
        if hist.is_empty() {
            continue;
        }
        let final_text: &str = hist.last().map_or("", |(_, s): &(f64, String)| s.as_str());
        if final_text.trim().is_empty() {
            continue;
        }
        let appear: f64 = hist.first().map_or(0.0, |&(t, _): &(f64, String)| t);
        let end_change: f64 = hist.last().map_or(appear, |&(t, _): &(f64, String)| t);
        let kind: LineKind = classify(hist, final_text);
        lines.push(Line {
            index,
            appear,
            end_change,
            states: hist.clone(),
            kind,
        });
    }

    let cursors: Vec<Cursor> = build_cursors(&lines, cast.duration);

    Ok(Model {
        lines,
        cursors,
        scroll: term.scroll,
        rows: cast.rows,
        cols: cast.cols,
        duration: cast.duration,
    })
}

fn classify(hist: &[(f64, String)], final_text: &str) -> LineKind {
    let is_bar: bool = hist
        .iter()
        .any(|(_, s): &(f64, String)| s.contains('\u{2588}') || s.contains('\u{2591}'));
    if is_bar {
        return LineKind::Bar;
    }
    if let Some(typed) = final_text.strip_prefix(PROMPT) {
        if typed.trim().is_empty() {
            return LineKind::RestingPrompt;
        }
        if hist.len() > 1 {
            return LineKind::Typed;
        }
    }
    LineKind::Static
}

fn build_cursors(lines: &[Line], duration: f64) -> Vec<Cursor> {
    let mut cursors: Vec<Cursor> = Vec::new();
    for (pos, line) in lines.iter().enumerate() {
        match line.kind {
            LineKind::Typed => {
                let cmd_x: f64 = PROMPT.chars().count() as f64 * CELL_W;
                let mut steps: Vec<(f64, f64)> = Vec::new();
                for (t, text) in &line.states {
                    let typed_len: usize =
                        text.chars().count().saturating_sub(PROMPT.chars().count());
                    let x: f64 = (typed_len as f64).mul_add(CELL_W, cmd_x);
                    steps.push((*t, x));
                }
                let next_appear: f64 = lines
                    .get(pos + 1)
                    .map_or(line.end_change + 0.3, |n: &Line| n.appear);
                cursors.push(Cursor {
                    line: line.index,
                    steps,
                    start: line.appear,
                    end: next_appear,
                });
            }
            LineKind::RestingPrompt => {
                let x: f64 = PROMPT.chars().count() as f64 * CELL_W;
                cursors.push(Cursor {
                    line: line.index,
                    steps: vec![(line.appear, x)],
                    start: line.appear,
                    end: duration,
                });
            }
            _ => {}
        }
    }
    cursors
}

#[derive(Debug, Clone)]
struct Run {
    col: usize,
    text: String,
    fill: &'static str,
}

fn esc(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn coalesce_runs(colors: &[&'static str], chars: &[char]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    let mut idx: usize = 0;
    while idx < chars.len() {
        let fill: &'static str = colors[idx];
        let start: usize = idx;
        let mut text: String = String::new();
        while idx < chars.len() && colors[idx] == fill {
            text.push(chars[idx]);
            idx += 1;
        }
        if !text.trim().is_empty() {
            runs.push(Run {
                col: start,
                text,
                fill,
            });
        }
    }
    runs
}

fn set_range(colors: &mut [&'static str], start: usize, len: usize, fill: &'static str) {
    for slot in colors.iter_mut().skip(start).take(len) {
        *slot = fill;
    }
}

fn overlay_all(colors: &mut [&'static str], chars: &[char], needle: &str, fill: &'static str) {
    let hay: String = chars.iter().collect();
    let needle_len: usize = needle.chars().count();
    let mut from: usize = 0;
    while let Some(byte_pos) = hay[from..].find(needle) {
        let abs: usize = from + byte_pos;
        let char_start: usize = hay[..abs].chars().count();
        set_range(colors, char_start, needle_len, fill);
        from = abs + needle.len();
    }
}

fn colorize(text: &str, kind: LineKind) -> Vec<Run> {
    let chars: Vec<char> = text.chars().collect();
    let n: usize = chars.len();
    if kind == LineKind::Bar {
        return bar_runs(&chars);
    }
    if kind == LineKind::Typed || kind == LineKind::RestingPrompt || text.starts_with(PROMPT) {
        return prompt_runs(&chars);
    }
    let mut colors: Vec<&'static str> = vec![TEXT; n];

    let trimmed: &str = text.trim_start();
    let indent: usize = n - trimmed.chars().count();
    if trimmed.starts_with("- [") {
        colors.fill(TEXT_FAINT);
    } else {
        colors.fill(TEXT_MUTED);
    }

    if let Some(colon) = key_value_split(text) {
        set_range(&mut colors, 0, colon + 1, TEXT_MUTED);
        set_range(&mut colors, colon + 1, n - (colon + 1), TEXT);
    } else if !trimmed.starts_with("- [") {
        overlay_first_token(&mut colors, &chars, indent);
    }

    overlay_percent(&mut colors, &chars);
    overlay_arrow(&mut colors, &chars);
    overlay_all(&mut colors, &chars, "OvertlyMalicious", ACCENT_RED);
    overlay_all(&mut colors, &chars, "Malicious", ACCENT_RED);
    overlay_all(&mut colors, &chars, "Suspicious", ACCENT_AMBER);
    overlay_all(&mut colors, &chars, "warning", ACCENT_AMBER);
    overlay_all(&mut colors, &chars, "onion", ACCENT_RED);
    overlay_ok(&mut colors, &chars);

    coalesce_runs(&colors, &chars)
}

fn key_value_split(text: &str) -> Option<usize> {
    let trimmed: &str = text.trim_start();
    if !trimmed.starts_with(char::is_alphabetic) {
        return None;
    }
    let colon: usize = text.find(':')?;
    let key: &str = text[..colon].trim();
    if key.is_empty() || key.len() > 16 || key.contains(' ') {
        return None;
    }
    Some(text[..colon].chars().count())
}

fn overlay_first_token(colors: &mut [&'static str], chars: &[char], indent: usize) {
    let mut end: usize = indent;
    while end < chars.len() && !chars[end].is_whitespace() {
        end += 1;
    }
    if end > indent {
        set_range(colors, indent, end - indent, ACCENT_BLUE);
    }
}

fn overlay_percent(colors: &mut [&'static str], chars: &[char]) {
    let mut i: usize = 0;
    while i < chars.len() {
        if chars[i] == '(' {
            let mut j: usize = i + 1;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '%') {
                j += 1;
            }
            if j < chars.len() && chars[j] == ')' && j > i + 1 && chars[j - 1] == '%' {
                set_range(colors, i, j - i + 1, ACCENT_AMBER);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
}

fn overlay_arrow(colors: &mut [&'static str], chars: &[char]) {
    let hay: String = chars.iter().collect();
    if let Some(byte_pos) = hay.find("-> ") {
        let char_start: usize = hay[..byte_pos].chars().count();
        set_range(colors, char_start, chars.len() - char_start, ACCENT_BLUE);
    }
}

fn overlay_ok(colors: &mut [&'static str], chars: &[char]) {
    let hay: String = chars.iter().collect();
    if let Some(byte_pos) = hay.find(": OK") {
        let char_start: usize = hay[..byte_pos].chars().count();
        set_range(colors, char_start + 2, 2, ACCENT_BLUE);
    }
}

fn bar_runs(chars: &[char]) -> Vec<Run> {
    let n: usize = chars.len();
    let mut colors: Vec<&'static str> = vec![TEXT; n];
    for (i, ch) in chars.iter().enumerate() {
        colors[i] = match ch {
            '\u{2588}' => ACCENT_BLUE,
            '\u{2591}' => TEXT_FAINT,
            _ => TEXT,
        };
    }
    let hay: String = chars.iter().collect();
    if let Some(pos) = hay.find("disrobe auto") {
        let start: usize = hay[..pos].chars().count();
        set_range(
            &mut colors,
            start,
            "disrobe auto".chars().count(),
            TEXT_MUTED,
        );
    }
    coalesce_runs(&colors, chars)
}

fn prompt_runs(chars: &[char]) -> Vec<Run> {
    let n: usize = chars.len();
    let mut colors: Vec<&'static str> = vec![TEXT; n];
    let prompt_len: usize = PROMPT.chars().count();
    let host_len: usize = HOST_TOKEN.chars().count();
    set_range(&mut colors, 0, host_len, ACCENT_BLUE);
    set_range(&mut colors, host_len, prompt_len - host_len, TEXT_MUTED);

    let mut token_start: usize = prompt_len;
    let mut first: bool = true;
    let mut i: usize = prompt_len;
    while i <= n {
        let at_end: bool = i == n;
        if at_end || chars[i] == ' ' {
            if i > token_start {
                let token: String = chars[token_start..i].iter().collect();
                let fill: &'static str = if first {
                    ACCENT_BLUE
                } else if token.starts_with('-') {
                    TEXT_FAINT
                } else if token.contains('/') || token.contains('.') {
                    TEXT_MUTED
                } else {
                    TEXT
                };
                set_range(&mut colors, token_start, i - token_start, fill);
                first = false;
            }
            token_start = i + 1;
        }
        i += 1;
    }
    coalesce_runs(&colors, chars)
}

fn kt(t: f64, dur: f64) -> f64 {
    (t / dur).clamp(0.000_001, 0.999_998)
}

fn line_baseline(index: usize) -> f64 {
    (index as f64).mul_add(CELL_H, FONT_SIZE * 0.76)
}

fn render(model: &Model) -> Result<String> {
    let width: f64 = CELL_W.mul_add(model.cols as f64, 2.0 * PAD_X);
    let height: f64 = CELL_H.mul_add(model.rows as f64, BODY_TOP + BODY_PAD_BOTTOM);
    let width_u: u32 = width.ceil() as u32;
    let height_u: u32 = height.ceil() as u32;
    let dur: f64 = model.duration;

    let mut body: String = String::with_capacity(96 * 1024);
    push_line!(
        body,
        "{SVG_HEADER}<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width_u}\" height=\"{height_u}\" viewBox=\"0 0 {width_u} {height_u}\" font-family=\"{MONO}\" font-size=\"{FONT_SIZE}\">"
    );
    render_chrome(&mut body, width, width_u, height_u);

    let screen_top: f64 = BODY_TOP - 3.0;
    let screen_h: f64 = height - screen_top;
    push_line!(
        body,
        "  <clipPath id=\"screen\"><rect x=\"1\" y=\"{screen_top:.1}\" width=\"{}\" height=\"{screen_h:.1}\"/></clipPath>",
        width_u - 2
    );
    push_line!(body, "  <g clip-path=\"url(#screen)\">");

    render_scroll_group_open(&mut body, model, dur);

    for line in &model.lines {
        render_line(&mut body, line, dur);
        ensure_svg_budget(&body)?;
    }
    for cursor in &model.cursors {
        render_cursor(&mut body, cursor, dur);
    }

    push_line!(body, "    </g>");
    push_line!(body, "  </g>");
    body.push_str("</svg>\n");
    ensure_svg_budget(&body)?;
    Ok(body)
}

fn render_chrome(mut body: &mut String, width: f64, width_u: u32, height_u: u32) {
    push_line!(
        body,
        "  <rect x=\"0\" y=\"0\" width=\"{width_u}\" height=\"{height_u}\" rx=\"10\" fill=\"{CANVAS}\"/>"
    );
    push_line!(
        body,
        "  <rect x=\"0.5\" y=\"0.5\" width=\"{}\" height=\"{}\" rx=\"9.5\" fill=\"none\" stroke=\"{HAIRLINE}\"/>",
        width_u - 1,
        height_u - 1
    );
    push_line!(
        body,
        "  <rect x=\"0.5\" y=\"0.5\" width=\"{}\" height=\"{TITLE_H:.1}\" rx=\"9.5\" fill=\"{SURFACE}\"/>",
        width_u - 1
    );
    push_line!(
        body,
        "  <rect x=\"0.5\" y=\"{:.1}\" width=\"{}\" height=\"12\" fill=\"{SURFACE}\"/>",
        TITLE_H - 12.0,
        width_u - 1
    );
    push_line!(
        body,
        "  <line x1=\"0.5\" y1=\"{TITLE_H:.1}\" x2=\"{:.1}\" y2=\"{TITLE_H:.1}\" stroke=\"{HAIRLINE}\"/>",
        width - 0.5
    );
    let dots: [&str; 3] = [ACCENT_RED, ACCENT_AMBER, ACCENT_BLUE];
    for (i, color) in dots.iter().enumerate() {
        let cx: f64 = (i as f64).mul_add(16.0, PAD_X);
        push_line!(
            body,
            "  <circle cx=\"{cx:.1}\" cy=\"{:.1}\" r=\"4.5\" fill=\"{color}\" opacity=\"0.85\"/>",
            TITLE_H / 2.0
        );
    }
    let title_y: f64 = TITLE_H / 2.0 + 4.5;
    push_line!(
        body,
        "  <text x=\"{:.1}\" y=\"{title_y:.1}\" font-size=\"12.5\" fill=\"{TEXT_MUTED}\" text-anchor=\"middle\" font-weight=\"600\" letter-spacing=\"0.5\">disrobe</text>",
        width / 2.0
    );
}

fn render_scroll_group_open(mut body: &mut String, model: &Model, dur: f64) {
    let mut values: Vec<String> = Vec::new();
    let mut key_times: Vec<String> = Vec::new();
    let base_y: f64 = BODY_TOP;
    for (i, (t, offset)) in model.scroll.iter().enumerate() {
        let y: f64 = (*offset as f64).mul_add(-CELL_H, base_y);
        values.push(format!("{PAD_X:.1},{y:.1}"));
        let time_key: f64 = if i == 0 { 0.0 } else { kt(*t, dur) };
        key_times.push(format!("{time_key:.6}"));
    }
    if values.len() == 1 {
        let y: f64 = base_y;
        push_line!(body, "    <g transform=\"translate({PAD_X:.1},{y:.1})\">");
        return;
    }
    push_line!(body, "    <g>");
    push_line!(
        body,
        "      <animateTransform attributeName=\"transform\" type=\"translate\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"{}\" keyTimes=\"{}\"/>",
        values.join(";"),
        key_times.join(";")
    );
}

fn render_line(body: &mut String, line: &Line, dur: f64) {
    match line.kind {
        LineKind::Bar => render_bar_line(body, line, dur),
        LineKind::Typed => render_typed_line(body, line, dur),
        LineKind::Static | LineKind::RestingPrompt => render_static_line(body, line, dur),
    }
}

fn emit_runs(mut body: &mut String, runs: &[Run], base_x: f64, y: f64) {
    for run in runs {
        let x: f64 = (run.col as f64).mul_add(CELL_W, base_x);
        let text_len: f64 = run.text.chars().count() as f64 * CELL_W;
        push_line!(
            body,
            "        <text x=\"{x:.2}\" y=\"{y:.2}\" fill=\"{}\" xml:space=\"preserve\" textLength=\"{text_len:.2}\" lengthAdjust=\"spacing\">{}</text>",
            run.fill,
            esc(&run.text)
        );
    }
}

fn render_static_line(mut body: &mut String, line: &Line, dur: f64) {
    let text: &str = line
        .states
        .last()
        .map_or("", |(_, s): &(f64, String)| s.as_str());
    let runs: Vec<Run> = colorize(text, line.kind);
    let y: f64 = line_baseline(line.index);
    push_line!(body, "      <g opacity=\"0\">");
    push_line!(
        body,
        "        <animate attributeName=\"opacity\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"0;1\" keyTimes=\"0;{:.6}\"/>",
        kt(line.appear, dur)
    );
    emit_runs(body, &runs, 0.0, y);
    push_line!(body, "      </g>");
}

fn render_bar_line(mut body: &mut String, line: &Line, dur: f64) {
    let y: f64 = line_baseline(line.index);
    let states: &[(f64, String)] = &line.states;
    for (idx, (t, text)) in states.iter().enumerate() {
        let next_t: f64 = states
            .get(idx + 1)
            .map_or(dur, |&(nt, _): &(f64, String)| nt);
        let runs: Vec<Run> = colorize(text, LineKind::Bar);
        let end_key: f64 = if idx + 1 == states.len() {
            0.999_999
        } else {
            kt(next_t, dur)
        };
        push_line!(body, "      <g opacity=\"0\">");
        push_line!(
            body,
            "        <animate attributeName=\"opacity\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"0;1;0\" keyTimes=\"0;{:.6};{end_key:.6}\"/>",
            kt(*t, dur)
        );
        emit_runs(body, &runs, 0.0, y);
        push_line!(body, "      </g>");
    }
}

fn render_typed_line(mut body: &mut String, line: &Line, dur: f64) {
    let final_text: &str = line
        .states
        .last()
        .map_or("", |(_, s): &(f64, String)| s.as_str());
    let prompt_len: usize = PROMPT.chars().count();
    let full: Vec<char> = final_text.chars().collect();
    let prompt_text: String = full[..prompt_len.min(full.len())].iter().collect();

    let y: f64 = line_baseline(line.index);
    let prompt_runs: Vec<Run> = prompt_runs(&prompt_text.chars().collect::<Vec<char>>());

    push_line!(body, "      <g opacity=\"0\">");
    push_line!(
        body,
        "        <animate attributeName=\"opacity\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"0;1\" keyTimes=\"0;{:.6}\"/>",
        kt(line.appear, dur)
    );
    emit_runs(body, &prompt_runs, 0.0, y);
    push_line!(body, "      </g>");

    let cmd_x: f64 = prompt_len as f64 * CELL_W;
    let clip_id: String = format!("type{}", line.index);
    let (values, key_times): (Vec<String>, Vec<String>) = clip_keyframes(line, prompt_len, dur);
    push_line!(
        body,
        "      <clipPath id=\"{clip_id}\" clipPathUnits=\"userSpaceOnUse\"><rect x=\"{cmd_x:.2}\" y=\"{:.2}\" height=\"{CELL_H:.1}\" width=\"0\">",
        (line.index as f64).mul_add(CELL_H, -1.0)
    );
    push_line!(
        body,
        "        <animate attributeName=\"width\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"{}\" keyTimes=\"{}\"/>",
        values.join(";"),
        key_times.join(";")
    );
    push_line!(body, "      </rect></clipPath>");

    let full_runs: Vec<Run> = prompt_runs_full(final_text);
    let cmd_runs: Vec<Run> = full_runs
        .into_iter()
        .filter(|r: &Run| r.col >= prompt_len)
        .map(|r: Run| Run {
            col: r.col - prompt_len,
            text: r.text,
            fill: r.fill,
        })
        .collect();
    push_line!(
        body,
        "      <g clip-path=\"url(#{clip_id})\" opacity=\"0\">"
    );
    push_line!(
        body,
        "        <animate attributeName=\"opacity\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"0;1\" keyTimes=\"0;{:.6}\"/>",
        kt(line.appear, dur)
    );
    emit_runs(body, &cmd_runs, cmd_x, y);
    push_line!(body, "      </g>");
}

fn prompt_runs_full(text: &str) -> Vec<Run> {
    prompt_runs(&text.chars().collect::<Vec<char>>())
}

fn clip_keyframes(line: &Line, prompt_len: usize, dur: f64) -> (Vec<String>, Vec<String>) {
    let mut values: Vec<String> = Vec::new();
    let mut key_times: Vec<String> = Vec::new();
    values.push("0".to_owned());
    key_times.push("0".to_owned());
    let mut last_width: f64 = 0.0;
    for (t, text) in &line.states {
        let typed: usize = text.chars().count().saturating_sub(prompt_len);
        let width: f64 = typed as f64 * CELL_W;
        let key: f64 = kt(*t, dur);
        let prev_key: f64 = key_times
            .last()
            .and_then(|s: &String| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if key <= prev_key {
            continue;
        }
        values.push(format!("{width:.2}"));
        key_times.push(format!("{key:.6}"));
        last_width = width;
    }
    values.push(format!("{last_width:.2}"));
    key_times.push("1".to_owned());
    (values, key_times)
}

fn render_cursor(mut body: &mut String, cursor: &Cursor, dur: f64) {
    let y: f64 = (cursor.line as f64).mul_add(CELL_H, 2.5);
    let start_key: f64 = kt(cursor.start, dur);
    let end_key: f64 = kt(cursor.end, dur).max(start_key + 0.000_001);
    push_line!(body, "      <g opacity=\"0\">");
    push_line!(
        body,
        "        <animate attributeName=\"opacity\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"0;1;0\" keyTimes=\"0;{start_key:.6};{end_key:.6}\"/>",
    );
    push_line!(body, "        <g opacity=\"1\">");
    push_line!(
        body,
        "          <animate attributeName=\"opacity\" dur=\"1.06s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"1;1;0;0\" keyTimes=\"0;0.5;0.5;1\"/>"
    );
    let (values, key_times): (Vec<String>, Vec<String>) = cursor_x_keyframes(cursor, dur);
    push_line!(
        body,
        "          <rect x=\"0\" y=\"{y:.2}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"1\" fill=\"{TEXT}\" opacity=\"0.75\">",
        CELL_W,
        CELL_H - 4.0
    );
    if values.len() == 1 {
        push_line!(
            body,
            "            <animate attributeName=\"x\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" values=\"{};{}\" keyTimes=\"0;1\"/>",
            values[0],
            values[0]
        );
    } else {
        push_line!(
            body,
            "            <animate attributeName=\"x\" dur=\"{dur:.3}s\" repeatCount=\"indefinite\" calcMode=\"discrete\" values=\"{}\" keyTimes=\"{}\"/>",
            values.join(";"),
            key_times.join(";")
        );
    }
    push_line!(body, "          </rect>");
    push_line!(body, "        </g>");
    push_line!(body, "      </g>");
}

fn cursor_x_keyframes(cursor: &Cursor, dur: f64) -> (Vec<String>, Vec<String>) {
    if cursor.steps.len() == 1 {
        return (
            vec![format!("{:.2}", cursor.steps[0].1)],
            vec!["0".to_owned()],
        );
    }
    let mut values: Vec<String> = Vec::new();
    let mut key_times: Vec<String> = Vec::new();
    let mut prev_key: f64 = -1.0;
    for (i, (t, x)) in cursor.steps.iter().enumerate() {
        let key: f64 = if i == 0 { 0.0 } else { kt(*t, dur) };
        if key <= prev_key {
            continue;
        }
        values.push(format!("{x:.2}"));
        key_times.push(format!("{key:.6}"));
        prev_key = key;
    }
    (values, key_times)
}

fn ensure_svg_budget(body: &str) -> Result<()> {
    if body.len() > MAX_SVG_BYTES {
        bail!("demo SVG exceeds {MAX_SVG_BYTES}-byte render cap");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cast_from(events: &[(f64, &str)]) -> Cast {
        Cast {
            cols: 128,
            rows: 24,
            events: events
                .iter()
                .map(|&(time, data): &(f64, &str)| CastEvent {
                    time,
                    data: data.to_owned(),
                })
                .collect(),
            duration: events.last().map_or(0.0, |&(t, _): &(f64, &str)| t) + TAIL_HOLD,
        }
    }

    #[test]
    fn demo_rejects_cast_that_expands_past_line_cap() {
        let events: Vec<(f64, &str)> = (0..MAX_LINES + 4)
            .map(|_| (0.0_f64, "x\r\n"))
            .collect::<Vec<(f64, &str)>>();
        let cast: Cast = cast_from(&events);
        let err: eyre::Report = build_model(&cast).expect_err("oversized cast must fail");
        assert!(
            err.to_string().contains("physical lines"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn typed_command_line_is_detected_and_reveals_by_character() {
        let mut events: Vec<(f64, &str)> = vec![(0.5, PROMPT)];
        events.push((0.6, "d"));
        events.push((0.7, "i"));
        events.push((0.8, "r"));
        events.push((0.9, "\r\n"));
        events.push((1.0, "done\r\n"));
        let cast: Cast = cast_from(&events);
        let model: Model = build_model(&cast).expect("model");
        let typed: &Line = model
            .lines
            .iter()
            .find(|l: &&Line| l.kind == LineKind::Typed)
            .expect("a typed line");
        assert!(
            typed.states.len() >= 3,
            "typing must record per-char states"
        );
        assert!(
            !model.cursors.is_empty(),
            "typed line must produce a cursor"
        );
    }

    #[test]
    fn bar_line_is_classified_and_swaps() {
        let events: Vec<(f64, &str)> = vec![
            (0.5, PROMPT),
            (0.6, "x\r\n"),
            (0.7, "\r  disrobe auto \u{2591}\u{2591}   0/2  a"),
            (0.9, "\r  disrobe auto \u{2588}\u{2588}   1/2  b"),
            (
                1.1,
                "\r  disrobe auto \u{2588}\u{2588}\u{2588}\u{2588}   2/2  done\r\n",
            ),
        ];
        let cast: Cast = cast_from(&events);
        let model: Model = build_model(&cast).expect("model");
        let bar: &Line = model
            .lines
            .iter()
            .find(|l: &&Line| l.kind == LineKind::Bar)
            .expect("a bar line");
        assert!(bar.states.len() >= 3, "bar must record redraw states");
    }

    #[test]
    fn render_emits_well_formed_svg_within_budget() {
        let events: Vec<(f64, &str)> = vec![
            (0.5, PROMPT),
            (0.6, "d"),
            (0.7, "i"),
            (0.8, "\r\n"),
            (0.9, "native unpack: OK\r\n"),
            (1.0, "  input:        a.exe\r\n"),
        ];
        let cast: Cast = cast_from(&events);
        let model: Model = build_model(&cast).expect("model");
        let svg: String = render(&model).expect("render");
        assert!(svg.starts_with(SVG_HEADER), "svg header present");
        assert!(svg.trim_end().ends_with("</svg>"), "svg closed");
        assert!(svg.contains("repeatCount=\"indefinite\""), "loops");
        assert!(svg.len() < MAX_SVG_BYTES, "within budget");
    }

    #[test]
    fn colorize_highlights_severity_and_ok() {
        let runs: Vec<Run> = colorize("pickle safety: OvertlyMalicious", LineKind::Static);
        assert!(
            runs.iter()
                .any(|r: &Run| r.fill == ACCENT_RED && r.text.contains("OvertlyMalicious")),
            "severity must be red: {runs:?}"
        );
        let ok: Vec<Run> = colorize("native unpack: OK", LineKind::Static);
        assert!(
            ok.iter()
                .any(|r: &Run| r.fill == ACCENT_BLUE && r.text.trim() == "OK"),
            "OK must be accented: {ok:?}"
        );
    }
}
