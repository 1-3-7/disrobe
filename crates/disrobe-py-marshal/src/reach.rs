use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticSurface {
    PycHeader,
    MarshalRoot,
    ReferenceTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemanticEntryPoint {
    #[serde(rename = "disrobe-py-marshal/src/pyc.rs::read_pyc")]
    ReadPyc,
    #[serde(rename = "disrobe-py-marshal/src/reader.rs::load")]
    Load,
    #[serde(rename = "disrobe-py-marshal/src/reader.rs::load_with_reftable")]
    LoadWithRefTable,
    #[serde(rename = "disrobe-py-marshal/src/reftable.rs::dump_reftable")]
    DumpRefTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationPhase {
    Entered,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    span: u64,
    surface: SemanticSurface,
    entry_point: SemanticEntryPoint,
    phase: ObservationPhase,
    bytes_consumed: usize,
    items: usize,
}

impl Observation {
    #[must_use]
    pub const fn span(&self) -> u64 {
        self.span
    }

    #[must_use]
    pub const fn surface(&self) -> SemanticSurface {
        self.surface
    }

    #[must_use]
    pub const fn entry_point(&self) -> SemanticEntryPoint {
        self.entry_point
    }

    #[must_use]
    pub const fn phase(&self) -> ObservationPhase {
        self.phase
    }

    #[must_use]
    pub const fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    #[must_use]
    pub const fn items(&self) -> usize {
        self.items
    }
}

#[derive(Debug)]
pub struct Captured<T> {
    value: T,
    observations: Vec<Observation>,
}

impl<T> Captured<T> {
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    #[error("a parser observation capture is already active on this thread")]
    Nested,
    #[error("the parser observation capture ended without a recorder")]
    MissingRecorder,
}

#[derive(Debug, Default)]
struct Recorder {
    next_span: u64,
    observations: Vec<Observation>,
}

thread_local! {
    static ACTIVE_RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

#[derive(Debug)]
struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        ACTIVE_RECORDER.with(|slot: &RefCell<Option<Recorder>>| {
            let _: Option<Recorder> = slot.borrow_mut().take();
        });
    }
}

pub fn capture_observations<T>(operation: impl FnOnce() -> T) -> Result<Captured<T>, CaptureError> {
    let installed: bool = ACTIVE_RECORDER.with(|slot: &RefCell<Option<Recorder>>| {
        let mut recorder: std::cell::RefMut<'_, Option<Recorder>> = slot.borrow_mut();
        if recorder.is_some() {
            false
        } else {
            *recorder = Some(Recorder::default());
            true
        }
    });
    if !installed {
        return Err(CaptureError::Nested);
    }
    let guard: CaptureGuard = CaptureGuard;
    let value: T = operation();
    let recorder: Recorder = ACTIVE_RECORDER
        .with(|slot: &RefCell<Option<Recorder>>| slot.borrow_mut().take())
        .ok_or(CaptureError::MissingRecorder)?;
    drop(guard);
    Ok(Captured {
        value,
        observations: recorder.observations,
    })
}

#[derive(Debug)]
pub(crate) struct ObservationToken {
    span: Option<u64>,
    surface: SemanticSurface,
    entry_point: SemanticEntryPoint,
}

impl ObservationToken {
    pub(crate) fn accepted(self, bytes_consumed: usize, items: usize) {
        finish(self, ObservationPhase::Accepted, bytes_consumed, items);
    }

    pub(crate) fn rejected(self) {
        finish(self, ObservationPhase::Rejected, 0, 0);
    }
}

pub(crate) fn enter(surface: SemanticSurface, entry_point: SemanticEntryPoint) -> ObservationToken {
    let span: Option<u64> = ACTIVE_RECORDER.with(|slot: &RefCell<Option<Recorder>>| {
        let mut recorder_slot: std::cell::RefMut<'_, Option<Recorder>> = slot.borrow_mut();
        let recorder: &mut Recorder = recorder_slot.as_mut()?;
        let current: u64 = recorder.next_span;
        recorder.next_span = recorder.next_span.saturating_add(1);
        recorder.observations.push(Observation {
            span: current,
            surface,
            entry_point,
            phase: ObservationPhase::Entered,
            bytes_consumed: 0,
            items: 0,
        });
        Some(current)
    });
    ObservationToken {
        span,
        surface,
        entry_point,
    }
}

fn finish(token: ObservationToken, phase: ObservationPhase, bytes_consumed: usize, items: usize) {
    let Some(span): Option<u64> = token.span else {
        return;
    };
    ACTIVE_RECORDER.with(|slot: &RefCell<Option<Recorder>>| {
        let mut recorder_slot: std::cell::RefMut<'_, Option<Recorder>> = slot.borrow_mut();
        let Some(recorder): Option<&mut Recorder> = recorder_slot.as_mut() else {
            return;
        };
        recorder.observations.push(Observation {
            span,
            surface: token.surface,
            entry_point: token.entry_point,
            phase,
            bytes_consumed,
            items,
        });
    });
}
