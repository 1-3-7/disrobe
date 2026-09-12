use core::fmt;
use core::hint::black_box;

use disrobe_py_marshal::{
    Captured, CodeObject, Object, Observation, PyVersion, PycFile, RefTableDump,
    capture_observations, dump, dump_reftable, load, load_with_reftable, pyversion_from_magic,
    read_pyc, validate_roundtrip, write_pyc,
};

use crate::{over_input_budget, selector};

const REPRESENTATIVE_VERSIONS: [PyVersion; 6] = [
    PyVersion::PY10,
    PyVersion::PY27,
    PyVersion::PY36,
    PyVersion::PY311,
    PyVersion::PY314,
    PyVersion::PY315,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionOutcome {
    version: PyVersion,
    marshal_accepted: bool,
    reference_table_accepted: bool,
    reference_load_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonExerciseOutcome {
    over_budget: bool,
    pyc_accepted: bool,
    pyc_reference_table_accepted: bool,
    versions: Vec<VersionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonExerciseError {
    ReferenceRangeOverflow,
    ReferenceRangePastInput,
}

impl fmt::Display for PythonExerciseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceRangeOverflow => {
                formatter.write_str("a reference-table entry range overflows usize")
            }
            Self::ReferenceRangePastInput => {
                formatter.write_str("a reference-table entry claims bytes past the marshal stream")
            }
        }
    }
}

impl std::error::Error for PythonExerciseError {}

#[derive(Debug)]
pub struct PythonReplay {
    outcome: PythonExerciseOutcome,
    capture: Captured<core::result::Result<PythonExerciseOutcome, PythonExerciseError>>,
}

impl PythonReplay {
    #[must_use]
    pub const fn outcome(&self) -> &PythonExerciseOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn observations(&self) -> &[Observation] {
        self.capture.observations()
    }
}

#[derive(Debug)]
pub enum PythonReplayError {
    Capture(disrobe_py_marshal::CaptureError),
    Exercise(PythonExerciseError),
    OutcomeMismatch,
}

impl fmt::Display for PythonReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => write!(formatter, "{error}"),
            Self::Exercise(error) => write!(formatter, "{error}"),
            Self::OutcomeMismatch => {
                formatter.write_str("recorded and unrecorded Python exercise outcomes differ")
            }
        }
    }
}

impl std::error::Error for PythonReplayError {}

impl From<disrobe_py_marshal::CaptureError> for PythonReplayError {
    fn from(error: disrobe_py_marshal::CaptureError) -> Self {
        Self::Capture(error)
    }
}

fn versions_for(data: &[u8]) -> Vec<PyVersion> {
    let mut versions: Vec<PyVersion> = Vec::with_capacity(REPRESENTATIVE_VERSIONS.len() + 1);
    if let Some(from_magic) = pyversion_from_magic(selector(data)) {
        versions.push(from_magic);
    }
    versions.extend_from_slice(&REPRESENTATIVE_VERSIONS);
    versions
}

fn drive_pyc_container(data: &[u8]) -> Option<(usize, PyVersion)> {
    let Ok(file): disrobe_py_marshal::Result<PycFile> = read_pyc(data) else {
        return None;
    };
    let _ = black_box(write_pyc(&file));
    if let Object::Code(boxed) = &file.code {
        let code: &CodeObject = boxed.as_ref();
        let _ = black_box(code.names.len());
        let _ = black_box(code.consts.len());
    }
    Some((file.header.header_len(), file.header.version))
}

fn drive_marshal_stream(data: &[u8], version: PyVersion) -> bool {
    let Ok(object): disrobe_py_marshal::Result<Object> = load(data, version) else {
        return false;
    };
    let _ = black_box(dump(&object, version));
    let _ = black_box(validate_roundtrip(&object, version));
    true
}

fn drive_reftable(data: &[u8], version: PyVersion) -> Result<bool, PythonExerciseError> {
    let Ok((object, table)): disrobe_py_marshal::Result<(Object, RefTableDump)> =
        dump_reftable(data, version)
    else {
        return Ok(false);
    };
    let _ = black_box(&object);
    for entry in &table.entries {
        let Some(end): Option<usize> = entry.byte_offset.checked_add(entry.byte_length) else {
            return Err(PythonExerciseError::ReferenceRangeOverflow);
        };
        if end > data.len() {
            return Err(PythonExerciseError::ReferenceRangePastInput);
        }
    }
    Ok(true)
}

pub fn exercise(data: &[u8]) -> Result<PythonExerciseOutcome, PythonExerciseError> {
    if over_input_budget(data) {
        return Ok(PythonExerciseOutcome {
            over_budget: true,
            pyc_accepted: false,
            pyc_reference_table_accepted: false,
            versions: Vec::new(),
        });
    }
    let pyc: Option<(usize, PyVersion)> = drive_pyc_container(data);
    let pyc_reference_table_accepted: bool = if let Some((header_len, version)) = pyc {
        let Some(body): Option<&[u8]> = data.get(header_len..) else {
            return Err(PythonExerciseError::ReferenceRangePastInput);
        };
        drive_reftable(body, version)?
    } else {
        false
    };
    let mut versions: Vec<VersionOutcome> = Vec::new();
    for version in versions_for(data) {
        let marshal_accepted: bool = drive_marshal_stream(data, version);
        let reference_table_accepted: bool = drive_reftable(data, version)?;
        let reference_load_accepted: bool = load_with_reftable(data, version).is_ok();
        versions.push(VersionOutcome {
            version,
            marshal_accepted,
            reference_table_accepted,
            reference_load_accepted,
        });
    }
    Ok(PythonExerciseOutcome {
        over_budget: false,
        pyc_accepted: pyc.is_some(),
        pyc_reference_table_accepted,
        versions,
    })
}

pub fn run_fuzz_input<T, E, F>(data: &[u8], exercise_input: F) -> Result<(), E>
where
    F: FnOnce(&[u8]) -> Result<T, E>,
{
    let _: T = exercise_input(data)?;
    Ok(())
}

pub fn replay(data: &[u8]) -> Result<PythonReplay, PythonReplayError> {
    let unrecorded: Result<PythonExerciseOutcome, PythonExerciseError> = exercise(data);
    let capture: Captured<Result<PythonExerciseOutcome, PythonExerciseError>> =
        capture_observations(|| exercise(data))?;
    if unrecorded != *capture.value() {
        return Err(PythonReplayError::OutcomeMismatch);
    }
    let outcome: PythonExerciseOutcome = match unrecorded {
        Ok(value) => value,
        Err(error) => return Err(PythonReplayError::Exercise(error)),
    };
    Ok(PythonReplay { outcome, capture })
}

impl crate::seed_reach::ReplayTrace for PythonReplay {
    fn observations(&self) -> crate::seed_reach::ReplayObservations<'_> {
        crate::seed_reach::ReplayObservations::Python(self.observations())
    }
}
