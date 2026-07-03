#![allow(dead_code)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use disrobe_core::progress::{NoopProgress, Progress};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::globals;

const SPINNER_TICK: Duration = Duration::from_millis(120);
const SPINNER_FRAMES: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ";

#[derive(Debug)]
pub(crate) struct IndicatifProgress {
    bar: ProgressBar,
}

impl IndicatifProgress {
    pub(crate) fn new(label: &str) -> Self {
        let bar: ProgressBar = ProgressBar::with_draw_target(Some(0), spinner_draw_target());
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{prefix:>14} {bar:30} {pos:>7}/{len:7} {msg}";
        let style: ProgressStyle =
            ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_bar());
        bar.set_style(style);
        bar.set_prefix(label.to_owned());
        Self { bar }
    }
}

impl Progress for IndicatifProgress {
    fn set_total(&self, total: u64) {
        self.bar.set_length(total);
    }
    fn set_pos(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    fn tick(&self) {
        self.bar.inc(1);
    }
    fn set_message(&self, message: &str) {
        self.bar.set_message(message.to_owned());
    }
    fn finish(&self, message: &str) {
        self.bar.finish_with_message(message.to_owned());
    }
}

#[derive(Debug)]
pub(crate) enum ActiveProgress {
    Noop(NoopProgress),
    Indicatif(IndicatifProgress),
}

impl Progress for ActiveProgress {
    fn set_total(&self, total: u64) {
        match self {
            Self::Noop(n) => n.set_total(total),
            Self::Indicatif(i) => i.set_total(total),
        }
    }
    fn set_pos(&self, pos: u64) {
        match self {
            Self::Noop(n) => n.set_pos(pos),
            Self::Indicatif(i) => i.set_pos(pos),
        }
    }
    fn tick(&self) {
        match self {
            Self::Noop(n) => n.tick(),
            Self::Indicatif(i) => i.tick(),
        }
    }
    fn set_message(&self, message: &str) {
        match self {
            Self::Noop(n) => n.set_message(message),
            Self::Indicatif(i) => i.set_message(message),
        }
    }
    fn finish(&self, message: &str) {
        match self {
            Self::Noop(n) => n.finish(message),
            Self::Indicatif(i) => i.finish(message),
        }
    }
}

pub(crate) fn make_progress(label: &str) -> ActiveProgress {
    if progress_visible() {
        ActiveProgress::Indicatif(IndicatifProgress::new(label))
    } else {
        ActiveProgress::Noop(NoopProgress)
    }
}

#[derive(Debug)]
pub(crate) struct IndicatifSpinner {
    bar: ProgressBar,
}

impl IndicatifSpinner {
    pub(crate) fn new(label: &str) -> Self {
        let bar: ProgressBar = ProgressBar::with_draw_target(None, spinner_draw_target());
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [step {pos}] [{hms}] {msg}{dots}";
        let style: ProgressStyle = ProgressStyle::with_template(template)
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_chars(SPINNER_FRAMES)
            .with_key(
                "hms",
                |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                    let _ = write!(w, "{}", format_elapsed(state.elapsed()));
                },
            )
            .with_key(
                "dots",
                |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                    let phase: u128 = state.elapsed().as_millis() / 400 % 3 + 1;
                    let _ = write!(w, "{}", ".".repeat(phase as usize));
                },
            );
        bar.set_style(style);
        bar.set_prefix(label.to_owned());
        bar.set_position(1);
        bar.enable_steady_tick(SPINNER_TICK);
        Self { bar }
    }
}

impl Progress for IndicatifSpinner {
    fn set_total(&self, total: u64) {
        self.bar.set_length(total);
    }
    fn set_pos(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    fn tick(&self) {
        self.bar.inc(1);
    }
    fn set_message(&self, message: &str) {
        self.bar.set_message(message.to_owned());
    }
    fn finish(&self, message: &str) {
        let prefix: String = self.bar.prefix();
        self.bar.finish_and_clear();
        self.bar.println(format!("[{prefix}] done: {message}"));
    }
}

#[derive(Debug)]
pub(crate) enum ActiveSpinner {
    Noop(NoopProgress),
    Indicatif(IndicatifSpinner),
}

impl Progress for ActiveSpinner {
    fn set_total(&self, total: u64) {
        match self {
            Self::Noop(n) => n.set_total(total),
            Self::Indicatif(i) => i.set_total(total),
        }
    }
    fn set_pos(&self, pos: u64) {
        match self {
            Self::Noop(n) => n.set_pos(pos),
            Self::Indicatif(i) => i.set_pos(pos),
        }
    }
    fn tick(&self) {
        match self {
            Self::Noop(n) => n.tick(),
            Self::Indicatif(i) => i.tick(),
        }
    }
    fn set_message(&self, message: &str) {
        match self {
            Self::Noop(n) => n.set_message(message),
            Self::Indicatif(i) => i.set_message(message),
        }
    }
    fn finish(&self, message: &str) {
        match self {
            Self::Noop(n) => n.finish(message),
            Self::Indicatif(i) => i.finish(message),
        }
    }
}

#[derive(Debug)]
enum ChainRender {
    Noop,
    Spinner(ActiveSpinner),
    Plain { label: String, started: Instant },
}

#[derive(Debug)]
pub(crate) struct ChainProgress {
    render: ChainRender,
    steps: AtomicU64,
    last_phase: Mutex<Option<String>>,
}

impl ChainProgress {
    pub(crate) fn active(label: &str) -> Self {
        Self {
            render: ChainRender::Spinner(ActiveSpinner::Indicatif(IndicatifSpinner::new(label))),
            steps: AtomicU64::new(0),
            last_phase: Mutex::new(None),
        }
    }

    pub(crate) const fn noop() -> Self {
        Self {
            render: ChainRender::Noop,
            steps: AtomicU64::new(0),
            last_phase: Mutex::new(None),
        }
    }

    fn plain(label: &str) -> Self {
        Self {
            render: ChainRender::Plain {
                label: label.to_owned(),
                started: Instant::now(),
            },
            steps: AtomicU64::new(0),
            last_phase: Mutex::new(None),
        }
    }

    pub(crate) fn for_chain(label: &str) -> Self {
        if !progress_visible() {
            Self::noop()
        } else if globals::is_tty_stderr() {
            Self::active(label)
        } else {
            Self::plain(label)
        }
    }

    pub(crate) fn step(&self, pass_label: &str) {
        if self.is_repeat_phase(pass_label) {
            return;
        }
        let n: u64 = self.steps.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let detail: &str = pass_detail(pass_label);
        match &self.render {
            ChainRender::Noop => {}
            ChainRender::Spinner(spinner) => {
                spinner.set_pos(n);
                spinner.set_message(&format!("{pass_label}: {detail}"));
            }
            ChainRender::Plain { label, started } => {
                eprintln!(
                    "[{label}] [step {n}] [{}] {pass_label}: {detail}...",
                    format_elapsed(started.elapsed())
                );
            }
        }
    }

    fn is_repeat_phase(&self, pass_label: &str) -> bool {
        let mut guard: std::sync::MutexGuard<'_, Option<String>> = match self.last_phase.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.as_deref() == Some(pass_label) {
            return true;
        }
        *guard = Some(pass_label.to_owned());
        false
    }

    pub(crate) fn finish(&self, message: &str) {
        match &self.render {
            ChainRender::Noop => {}
            ChainRender::Spinner(spinner) => spinner.finish(message),
            ChainRender::Plain { label, .. } => eprintln!("[{label}] done: {message}"),
        }
    }

    pub(crate) fn steps(&self) -> u64 {
        self.steps.load(Ordering::Relaxed)
    }
}

fn format_elapsed(d: Duration) -> String {
    let total: u64 = d.as_secs();
    let hours: u64 = total / 3600;
    let minutes: u64 = total % 3600 / 60;
    let seconds: u64 = total % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn pass_detail(pass_id: &str) -> &'static str {
    match pass_id {
        id if id.contains("extract") || id.contains("onefile") => "extracting bundled files",
        id if id.contains("decompile") => "decompiling recovered modules",
        id if id.contains("disasm") => "disassembling",
        id if id.contains("deob") => "deobfuscating",
        id if id.contains("unpack") => "unpacking",
        id if id.contains("strings") || id.contains("frisk") => "scanning for secrets",
        id if id.contains("nuitka") => "scanning constants and frozen bytecode",
        _ => "working",
    }
}

#[derive(Debug)]
pub(crate) struct StageSpinner {
    bar: Option<ProgressBar>,
}

impl StageSpinner {
    pub(crate) fn start(label: &str, message: &str) -> Self {
        if !progress_visible() {
            return Self { bar: None };
        }
        let bar: ProgressBar = ProgressBar::with_draw_target(None, spinner_draw_target());
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [{hms}] {msg}";
        let style: ProgressStyle = ProgressStyle::with_template(template)
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_chars(SPINNER_FRAMES)
            .with_key(
                "hms",
                |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                    let _ = write!(w, "{}", format_elapsed(state.elapsed()));
                },
            );
        bar.set_style(style);
        bar.set_prefix(label.to_owned());
        bar.set_message(message.to_owned());
        bar.enable_steady_tick(SPINNER_TICK);
        Self { bar: Some(bar) }
    }

    pub(crate) fn set_message(&self, message: &str) {
        if let Some(bar) = self.bar.as_ref() {
            bar.set_message(message.to_owned());
        }
    }

    pub(crate) fn finish(self, message: &str) {
        if let Some(bar) = self.bar.as_ref() {
            bar.finish_with_message(message.to_owned());
        }
    }
}

impl Drop for StageSpinner {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.as_ref()
            && !bar.is_finished()
        {
            bar.finish_and_clear();
        }
    }
}

fn progress_visible() -> bool {
    globals::current().progress_enabled()
}

const SPINNER_HZ: u8 = 8;

fn spinner_draw_target() -> ProgressDrawTarget {
    if globals::current().progress_forced() {
        ProgressDrawTarget::stderr_with_hz(SPINNER_HZ)
    } else {
        ProgressDrawTarget::stderr()
    }
}

static RAYON_INIT: OnceLock<()> = OnceLock::new();

pub(crate) fn install_rayon_pool(explicit_threads: Option<u32>) {
    let _: &() = RAYON_INIT.get_or_init(|| {
        if let Some(n) = explicit_threads {
            let threads: usize = usize::try_from(n.max(1)).unwrap_or(1);
            let _: Result<(), rayon::ThreadPoolBuildError> = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global();
        }
    });
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn noop_chain_progress_counts_steps_without_drawing() {
        let p: ChainProgress = ChainProgress::noop();
        assert_eq!(p.steps(), 0);
        p.step("pyarmor.unpack");
        p.step("py.decompile");
        p.step("py.deob");
        assert_eq!(p.steps(), 3);
        p.finish("done");
        assert_eq!(p.steps(), 3);
    }

    #[test]
    fn noop_progress_swallows_all_calls() {
        let p: ActiveProgress = ActiveProgress::Noop(NoopProgress);
        p.set_total(10);
        p.set_pos(5);
        p.tick();
        p.set_message("writing");
        p.finish("done");
    }

    #[test]
    fn spinner_template_compiles_with_our_tokens() {
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [step {pos}] [{hms}] {msg}{dots}";
        let style: Result<ProgressStyle, indicatif::style::TemplateError> =
            ProgressStyle::with_template(template).map(|s: ProgressStyle| {
                s.with_key(
                    "hms",
                    |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                        let _ = write!(w, "{}", format_elapsed(state.elapsed()));
                    },
                )
                .with_key(
                    "dots",
                    |_state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                        let _ = write!(w, ".");
                    },
                )
            });
        assert!(style.is_ok(), "spinner template must be valid");
    }

    #[test]
    fn spinner_renders_hms_elapsed_rolling_past_a_minute() {
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [step {pos}] [{hms}] {msg}";
        let style: ProgressStyle = ProgressStyle::with_template(template)
            .expect("template")
            .tick_chars(SPINNER_FRAMES)
            .with_key(
                "hms",
                |_state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                    let _ = write!(w, "{}", format_elapsed(Duration::from_secs(75)));
                },
            );
        let term: indicatif::InMemoryTerm = indicatif::InMemoryTerm::new(2, 120);
        let bar: ProgressBar = ProgressBar::with_draw_target(
            None,
            ProgressDrawTarget::term_like(Box::new(term.clone())),
        );
        bar.set_style(style);
        bar.set_prefix("disrobe auto");
        bar.set_position(2);
        bar.set_message("nuitka.decompile: decompiling recovered modules");
        bar.tick();
        let rendered: String = term.contents();
        assert!(
            rendered.contains("[1m15s]"),
            "elapsed must roll past 60s into compact h/m/s, got: {rendered:?}"
        );
        assert!(
            !rendered.contains("[75s]") && !rendered.contains("75 seconds"),
            "elapsed must never show raw seconds beyond 60, got: {rendered:?}"
        );
    }

    #[test]
    fn pass_detail_maps_phases_to_human_text() {
        assert_eq!(pass_detail("nuitka.extract"), "extracting bundled files");
        assert_eq!(
            pass_detail("nuitka.decompile"),
            "decompiling recovered modules"
        );
        assert_eq!(pass_detail("unknown.pass"), "working");
    }

    #[test]
    fn step_starts_at_one() {
        let p: ChainProgress = ChainProgress::noop();
        p.step("nuitka.extract");
        assert_eq!(p.steps(), 1, "step numbering must start at 1");
    }

    #[test]
    fn plain_chain_counts_steps_for_non_tty() {
        let p: ChainProgress = ChainProgress::plain("disrobe auto");
        p.step("nuitka.extract");
        p.step("nuitka.decompile");
        assert_eq!(p.steps(), 2);
        p.finish("2 pass(es) run");
    }

    #[test]
    fn elapsed_formats_seconds_then_minutes() {
        assert_eq!(format_elapsed(Duration::from_secs(0)), "0s");
        assert_eq!(format_elapsed(Duration::from_secs(45)), "45s");
        assert_eq!(format_elapsed(Duration::from_secs(59)), "59s");
        assert_eq!(format_elapsed(Duration::from_mins(1)), "1m00s");
        assert_eq!(format_elapsed(Duration::from_secs(75)), "1m15s");
        assert_eq!(format_elapsed(Duration::from_secs(3_599)), "59m59s");
        assert_eq!(format_elapsed(Duration::from_hours(1)), "1h00m00s");
        assert_eq!(format_elapsed(Duration::from_secs(3_723)), "1h02m03s");
    }

    #[test]
    fn step_dedupes_consecutive_identical_phases() {
        let p: ChainProgress = ChainProgress::noop();
        p.step("nuitka.extract");
        p.step("nuitka.extract");
        p.step("nuitka.extract");
        assert_eq!(p.steps(), 1, "repeated identical phase must not re-count");
        p.step("nuitka.decompile");
        assert_eq!(p.steps(), 2, "a new phase must advance the step counter");
    }

    #[test]
    fn spinner_renders_exact_bracketed_shape() {
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [step {pos}] {msg}";
        let style: ProgressStyle = ProgressStyle::with_template(template)
            .expect("template")
            .tick_chars(SPINNER_FRAMES);
        let term: indicatif::InMemoryTerm = indicatif::InMemoryTerm::new(2, 120);
        let bar: ProgressBar = ProgressBar::with_draw_target(
            None,
            ProgressDrawTarget::term_like(Box::new(term.clone())),
        );
        bar.set_style(style);
        bar.set_prefix("disrobe auto");
        bar.set_position(1);
        bar.set_message("nuitka.extract: extracting bundled files..");
        bar.tick();
        let rendered: String = term.contents();
        assert!(
            rendered.contains("[disrobe auto] [step 1] nuitka.extract: extracting bundled files.."),
            "spinner must render the bracketed shape with no padding, got: {rendered:?}"
        );
        assert!(
            !rendered.contains("step   0") && !rendered.contains("step 0"),
            "step numbering must not show 0, got: {rendered:?}"
        );
    }

    #[test]
    fn chain_progress_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ChainProgress>();
        assert_send_sync::<ActiveProgress>();
        assert_send_sync::<ActiveSpinner>();
    }

    #[test]
    fn stage_spinner_template_compiles_with_our_tokens() {
        #[allow(clippy::literal_string_with_formatting_args)]
        let template: &'static str = "{spinner} [{prefix}] [{elapsed}] {msg}";
        let style: Result<ProgressStyle, indicatif::style::TemplateError> =
            ProgressStyle::with_template(template);
        assert!(style.is_ok(), "stage spinner template must be valid");
    }

    #[test]
    fn stage_spinner_lifecycle_never_panics() {
        let s: StageSpinner = StageSpinner::start("native unpack", "detecting packer");
        s.set_message("recovering image");
        s.finish("done");
    }

    #[test]
    fn stage_spinner_drop_without_finish_is_safe() {
        let s: StageSpinner = StageSpinner::start("py decompile", "lifting bytecode");
        drop(s);
    }
}
