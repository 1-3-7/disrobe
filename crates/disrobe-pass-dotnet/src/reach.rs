use std::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticSurface {
    PeImage,
    ClrHeader,
    MetadataRoot,
    TableStream,
    StringsHeap,
    UserStringsHeap,
    CompressedUint,
    MethodBody,
    Instructions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemanticEntryPoint {
    #[serde(rename = "disrobe-pass-dotnet/src/pe.rs::parse")]
    ParsePe,
    #[serde(rename = "disrobe-pass-dotnet/src/pe.rs::parse_clr_header")]
    ParseClrHeader,
    #[serde(rename = "disrobe-pass-dotnet/src/metadata.rs::parse_metadata_root")]
    ParseMetadataRoot,
    #[serde(rename = "disrobe-pass-dotnet/src/metadata.rs::parse_table_stream")]
    ParseTableStream,
    #[serde(rename = "disrobe-pass-dotnet/src/metadata.rs::read_strings_heap")]
    ReadStringsHeap,
    #[serde(rename = "disrobe-pass-dotnet/src/metadata.rs::read_us_heap_strings")]
    ReadUserStringsHeap,
    #[serde(rename = "disrobe-pass-dotnet/src/metadata.rs::decompress_uint")]
    DecompressUint,
    #[serde(rename = "disrobe-pass-dotnet/src/cil.rs::parse_method_body")]
    ParseMethodBody,
    #[serde(rename = "disrobe-pass-dotnet/src/cil.rs::disassemble")]
    Disassemble,
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
    static SUPPRESSION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug)]
struct CaptureGuard;

#[derive(Debug)]
struct SuppressionGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        ACTIVE_RECORDER.with(|slot: &RefCell<Option<Recorder>>| {
            let _: Option<Recorder> = slot.borrow_mut().take();
        });
    }
}

impl Drop for SuppressionGuard {
    fn drop(&mut self) {
        SUPPRESSION_DEPTH.with(|depth: &Cell<usize>| {
            depth.set(depth.get().saturating_sub(1));
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

pub fn without_observations<T>(operation: impl FnOnce() -> T) -> T {
    SUPPRESSION_DEPTH.with(|depth: &Cell<usize>| {
        depth.set(depth.get().saturating_add(1));
    });
    let guard: SuppressionGuard = SuppressionGuard;
    let value: T = operation();
    drop(guard);
    value
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
    let suppressed: bool = SUPPRESSION_DEPTH.with(|depth: &Cell<usize>| depth.get() != 0);
    if suppressed {
        return ObservationToken {
            span: None,
            surface,
            entry_point,
        };
    }
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
