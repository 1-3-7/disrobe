#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::elidable_lifetime_names)]
#![allow(clippy::format_push_string)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unnecessary_wraps)]

use pyo3::prelude::*;
use pyo3::types::PyModule;

mod auto;
mod convert;
mod dispatch;
mod dotnet;
mod envelope;
mod err;
mod hermes;
mod js;
mod jvm;
mod llm;
mod macho;
mod native;
mod nuitka;
mod py_decompile;
mod py_deob;
mod pyarmor;
mod pyinstaller;
mod wasm;

#[pymodule]
fn disrobe(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__doc__",
        "disrobe \u{2014} deobfuscator + decompiler suite, programmatic Python API.",
    )?;
    err::register(py, m)?;
    auto::register(m)?;
    py_decompile::register(m)?;
    py_deob::register(m)?;
    pyarmor::register(m)?;
    pyinstaller::register(m)?;
    nuitka::register(m)?;
    hermes::register(m)?;
    macho::register(m)?;
    jvm::register(m)?;
    dotnet::register(m)?;
    wasm::register(m)?;
    js::register(m)?;
    native::register(m)?;
    envelope::register(m)?;
    dispatch::register(m)?;
    Ok(())
}
