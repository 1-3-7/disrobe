use disrobe_pass_shell::{
    BatchDeobReport, ObfuscatorDetection, ReverseReport, deobfuscate_batch, obfuscator_detect,
    reverse_ast, reverse_string, reverse_token,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::llm::null_bundled_value;
use crate::typed::{
    BatchDeobReport as PyBatchDeobReport, PowershellDeobfuscation, PowershellDetection,
};

#[pyfunction]
#[pyo3(signature = (script, *, args = None))]
#[pyo3(text_signature = "(script, *, args=None)")]
fn batch_deobfuscate(script: &str, args: Option<Vec<String>>) -> PyResult<PyBatchDeobReport> {
    let argv: Vec<String> = args.unwrap_or_else(|| Vec::with_capacity(0));
    let report: BatchDeobReport = deobfuscate_batch(script, &argv);
    Ok(PyBatchDeobReport::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(script)")]
fn powershell_detect(script: &str) -> PyResult<PowershellDetection> {
    let detection: ObfuscatorDetection = obfuscator_detect(script);
    Ok(PowershellDetection::from_value(null_bundled_value(
        &detection,
    )?))
}

#[derive(Debug, Clone, Serialize)]
struct PowershellReverseReport {
    level: String,
    transformations: Vec<String>,
    output: String,
}

#[pyfunction]
#[pyo3(text_signature = "(script)")]
fn powershell_deobfuscate(script: &str) -> PyResult<PowershellDeobfuscation> {
    let token_pass: ReverseReport = reverse_token(script);
    let string_pass: ReverseReport = reverse_string(&token_pass.output);
    let ast_pass: ReverseReport = reverse_ast(&string_pass.output);
    let mut transformations: Vec<String> = token_pass.transformations;
    transformations.extend(string_pass.transformations);
    transformations.extend(ast_pass.transformations);
    let report: PowershellReverseReport = PowershellReverseReport {
        level: format!("{:?}", ast_pass.level),
        transformations,
        output: ast_pass.output,
    };
    Ok(PowershellDeobfuscation::from_value(null_bundled_value(
        &report,
    )?))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(batch_deobfuscate, m)?)?;
    m.add_function(wrap_pyfunction!(powershell_detect, m)?)?;
    m.add_function(wrap_pyfunction!(powershell_deobfuscate, m)?)?;
    Ok(())
}
