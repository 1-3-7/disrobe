#![allow(dead_code)]

use std::sync::OnceLock;

use disrobe_core::progress::{NoopProgress, Progress};
use indicatif::{ProgressBar, ProgressStyle};

use super::globals;

#[derive(Debug)]
pub(crate) struct IndicatifProgress {
    bar: ProgressBar,
}

impl IndicatifProgress {
    pub(crate) fn new(label: &str) -> Self {
        let bar: ProgressBar = ProgressBar::new(0);
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
    if globals::current().progress_enabled() {
        ActiveProgress::Indicatif(IndicatifProgress::new(label))
    } else {
        ActiveProgress::Noop(NoopProgress)
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
