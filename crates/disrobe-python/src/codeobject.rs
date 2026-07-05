use std::collections::BTreeMap;

use disrobe_core::{Capability, Rung};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, decode_disasm,
    decode_raw, encode_disasm,
};
use disrobe_ir::{Envelope, Sidecar};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyModule};

use crate::err::{DisrobeError, map};

const PRODUCED_BY_DEFAULT: &str = "disrobe-python";

#[inline]
fn hex32(bytes: &[u8; 32]) -> String {
    crate::llm::hex_lower(bytes)
}

#[inline]
fn flow_label(flow: InsnFlow) -> &'static str {
    match flow {
        InsnFlow::Sequential => "sequential",
        InsnFlow::Call => "call",
        InsnFlow::IndirectCall => "indirect-call",
        InsnFlow::ConditionalBranch => "conditional-branch",
        InsnFlow::UnconditionalBranch => "unconditional-branch",
        InsnFlow::IndirectBranch => "indirect-branch",
        InsnFlow::Return => "return",
        InsnFlow::Interrupt => "interrupt",
    }
}

#[inline]
fn symbol_kind_label(kind: DisasmSymbolKind) -> &'static str {
    match kind {
        DisasmSymbolKind::Function => "function",
        DisasmSymbolKind::Data => "data",
        DisasmSymbolKind::Label => "label",
        DisasmSymbolKind::Export => "export",
        DisasmSymbolKind::Import => "import",
    }
}

#[inline]
fn parse_symbol_kind(label: &str) -> PyResult<DisasmSymbolKind> {
    match label {
        "function" => Ok(DisasmSymbolKind::Function),
        "data" => Ok(DisasmSymbolKind::Data),
        "label" => Ok(DisasmSymbolKind::Label),
        "export" => Ok(DisasmSymbolKind::Export),
        "import" => Ok(DisasmSymbolKind::Import),
        other => Err(DisrobeError::new_err(format!(
            "unknown symbol kind `{other}`; expected function | data | label | export | import"
        ))),
    }
}

#[doc = "A single recovered disassembly instruction with editable fields."]
#[pyclass(module = "disrobe", name = "Instruction", from_py_object)]
#[derive(Debug, Clone)]
pub(crate) struct Instruction {
    inner: DisasmInstruction,
}

#[pymethods]
impl Instruction {
    #[new]
    #[pyo3(signature = (offset, mnemonic, operands = None, bytes = None))]
    fn new(
        offset: u64,
        mnemonic: String,
        operands: Option<Vec<String>>,
        bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner: DisasmInstruction {
                offset,
                bytes: bytes.unwrap_or_else(|| Vec::with_capacity(0)),
                mnemonic,
                operands: operands.unwrap_or_else(|| Vec::with_capacity(0)),
                ..DisasmInstruction::default()
            },
        }
    }

    #[getter]
    fn offset(&self) -> u64 {
        self.inner.offset
    }

    #[setter]
    fn set_offset(&mut self, value: u64) {
        self.inner.offset = value;
    }

    #[getter]
    fn mnemonic(&self) -> String {
        self.inner.mnemonic.clone()
    }

    #[setter]
    fn set_mnemonic(&mut self, value: String) {
        self.inner.mnemonic = value;
    }

    #[getter]
    fn operands(&self) -> Vec<String> {
        self.inner.operands.clone()
    }

    #[setter]
    fn set_operands(&mut self, value: Vec<String>) {
        self.inner.operands = value;
    }

    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    #[setter]
    fn set_bytes(&mut self, value: Vec<u8>) {
        self.inner.bytes = value;
    }

    #[getter]
    fn flow(&self) -> String {
        flow_label(self.inner.flow).to_owned()
    }

    #[getter]
    fn branch_target(&self) -> Option<u64> {
        self.inner.branch_target
    }

    #[setter]
    fn set_branch_target(&mut self, value: Option<u64>) {
        self.inner.branch_target = value;
    }

    fn text(&self) -> String {
        if self.inner.operands.is_empty() {
            self.inner.mnemonic.clone()
        } else {
            format!("{} {}", self.inner.mnemonic, self.inner.operands.join(", "))
        }
    }

    fn __repr__(&self) -> String {
        format!("Instruction(0x{:x}: {})", self.inner.offset, self.text())
    }
}

#[doc = "A single recovered symbol with editable address, name, and kind."]
#[pyclass(module = "disrobe", name = "Symbol", from_py_object)]
#[derive(Debug, Clone)]
pub(crate) struct Symbol {
    inner: DisasmSymbol,
}

#[pymethods]
impl Symbol {
    #[new]
    #[pyo3(signature = (address, name, kind = "function"))]
    fn new(address: u64, name: String, kind: &str) -> PyResult<Self> {
        Ok(Self {
            inner: DisasmSymbol {
                address,
                name,
                kind: parse_symbol_kind(kind)?,
            },
        })
    }

    #[getter]
    fn address(&self) -> u64 {
        self.inner.address
    }

    #[setter]
    fn set_address(&mut self, value: u64) {
        self.inner.address = value;
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[setter]
    fn set_name(&mut self, value: String) {
        self.inner.name = value;
    }

    #[getter]
    fn kind(&self) -> String {
        symbol_kind_label(self.inner.kind).to_owned()
    }

    #[setter]
    fn set_kind(&mut self, value: &str) -> PyResult<()> {
        self.inner.kind = parse_symbol_kind(value)?;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "Symbol(0x{:x} {} {})",
            self.inner.address,
            symbol_kind_label(self.inner.kind),
            self.inner.name
        )
    }
}

#[doc = "A mutable, re-serializable recovered code object backed by a .dr envelope.\n\nLoad an existing Disasm-rung .dr envelope, edit its instructions, symbols,\nprovenance metadata, capabilities, or attached LLM sidecar, then call\n`to_dr()` to produce a fresh, integrity-hashed .dr envelope."]
#[pyclass(module = "disrobe", name = "CodeObject")]
#[derive(Debug)]
pub(crate) struct CodeObject {
    payload: DisasmPayload,
    produced_by: String,
    produced_by_version: String,
    capabilities: Vec<Capability>,
    provenance: BTreeMap<String, String>,
    llm: Option<serde_json::Value>,
}

impl CodeObject {
    fn empty() -> Self {
        Self {
            payload: DisasmPayload {
                source_hash: [0u8; 32],
                instructions: Vec::new(),
                symbol_table: Vec::new(),
            },
            produced_by: PRODUCED_BY_DEFAULT.to_owned(),
            produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: vec![Capability::produces("disasm", 1)],
            provenance: BTreeMap::new(),
            llm: None,
        }
    }
}

#[pymethods]
impl CodeObject {
    #[new]
    fn new() -> Self {
        Self::empty()
    }

    #[staticmethod]
    #[pyo3(text_signature = "(dr_bytes)")]
    fn from_dr(dr_bytes: &[u8]) -> PyResult<Self> {
        let env: Envelope =
            Envelope::decode(dr_bytes).map_err(map("codeobject decode envelope"))?;
        let sidecar: Sidecar =
            Sidecar::decode(&env.cold).map_err(map("codeobject decode sidecar"))?;
        let payload: DisasmPayload = match env.rung {
            Rung::Disasm => decode_disasm(&env.hot).map_err(map("codeobject decode disasm"))?,
            Rung::Raw => {
                let raw: disrobe_ir::RawPayload =
                    decode_raw(&env.hot).map_err(map("codeobject decode raw"))?;
                DisasmPayload {
                    source_hash: raw.source_hash,
                    instructions: Vec::new(),
                    symbol_table: Vec::new(),
                }
            }
            other => {
                return Err(DisrobeError::new_err(format!(
                    "codeobject expects a Disasm or Raw rung .dr envelope; got {other:?}"
                )));
            }
        };
        let llm: Option<serde_json::Value> = sidecar
            .provenance
            .get("llm")
            .and_then(|s: &String| serde_json::from_str(s).ok());
        Ok(Self {
            payload,
            produced_by: sidecar.produced_by,
            produced_by_version: sidecar.produced_by_version,
            capabilities: sidecar.capabilities,
            provenance: sidecar.provenance,
            llm,
        })
    }

    #[getter]
    fn instructions(&self) -> Vec<Instruction> {
        self.payload
            .instructions
            .iter()
            .map(|i: &DisasmInstruction| Instruction { inner: i.clone() })
            .collect()
    }

    fn set_instructions(&mut self, instructions: Vec<Instruction>) {
        self.payload.instructions = instructions
            .into_iter()
            .map(|i: Instruction| i.inner)
            .collect();
    }

    fn add_instruction(&mut self, instruction: &Instruction) {
        self.payload.instructions.push(instruction.inner.clone());
    }

    #[getter]
    fn symbols(&self) -> Vec<Symbol> {
        self.payload
            .symbol_table
            .iter()
            .map(|s: &DisasmSymbol| Symbol { inner: s.clone() })
            .collect()
    }

    fn set_symbols(&mut self, symbols: Vec<Symbol>) {
        self.payload.symbol_table = symbols.into_iter().map(|s: Symbol| s.inner).collect();
    }

    fn add_symbol(&mut self, symbol: &Symbol) {
        self.payload.symbol_table.push(symbol.inner.clone());
    }

    #[getter]
    fn instruction_count(&self) -> usize {
        self.payload.instructions.len()
    }

    #[getter]
    fn symbol_count(&self) -> usize {
        self.payload.symbol_table.len()
    }

    #[getter]
    fn source_hash(&self) -> String {
        hex32(&self.payload.source_hash)
    }

    #[setter]
    fn set_source_hash(&mut self, hex: &str) -> PyResult<()> {
        self.payload.source_hash = decode_hex32(hex)?;
        Ok(())
    }

    #[getter]
    fn produced_by(&self) -> String {
        self.produced_by.clone()
    }

    #[setter]
    fn set_produced_by(&mut self, value: String) {
        self.produced_by = value;
    }

    #[getter]
    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict: Bound<'py, PyDict> = PyDict::new(py);
        for (key, value) in &self.provenance {
            dict.set_item(key, value)?;
        }
        Ok(dict)
    }

    fn set_metadata(&mut self, key: String, value: String) {
        self.provenance.insert(key, value);
    }

    fn clear_metadata(&mut self) {
        self.provenance.clear();
    }

    #[getter]
    fn capabilities(&self) -> Vec<String> {
        self.capabilities
            .iter()
            .map(|c: &Capability| c.name.clone())
            .collect()
    }

    fn add_capability(&mut self, name: String, major: u32) {
        self.capabilities.push(Capability::produces(name, major));
    }

    #[getter]
    fn llm<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.llm {
            Some(value) => Ok(Some(crate::convert::value_to_py(py, value)?)),
            None => Ok(None),
        }
    }

    fn set_llm(&mut self, sidecar: &Bound<'_, PyAny>) -> PyResult<()> {
        if sidecar.is_none() {
            self.llm = None;
            return Ok(());
        }
        self.llm = Some(crate::convert::from_py(sidecar)?);
        Ok(())
    }

    #[pyo3(text_signature = "()")]
    fn to_dr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let hot: Vec<u8> = encode_disasm(&self.payload).map_err(map("codeobject encode disasm"))?;
        let mut provenance: BTreeMap<String, String> = self.provenance.clone();
        if let Some(llm) = &self.llm {
            let serialized: String =
                serde_json::to_string(llm).map_err(|e: serde_json::Error| {
                    DisrobeError::new_err(format!("llm serialize: {e}"))
                })?;
            provenance.insert("llm".to_owned(), serialized);
        }
        let sidecar: Sidecar = Sidecar {
            produced_by: self.produced_by.clone(),
            produced_by_version: self.produced_by_version.clone(),
            capabilities: self.capabilities.clone(),
            provenance,
        };
        let cold: Vec<u8> = sidecar.encode().map_err(map("codeobject encode sidecar"))?;
        let env: Envelope = Envelope::new(Rung::Disasm, hot, cold);
        let bytes: Vec<u8> = env.encode().map_err(map("codeobject encode envelope"))?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!(
            "CodeObject(instructions={}, symbols={}, produced_by={})",
            self.payload.instructions.len(),
            self.payload.symbol_table.len(),
            self.produced_by
        )
    }
}

#[inline]
fn decode_hex32(hex: &str) -> PyResult<[u8; 32]> {
    let trimmed: &str = hex.trim();
    let bytes: &[u8] = trimmed.as_bytes();
    if bytes.len() != 64 {
        return Err(DisrobeError::new_err(format!(
            "source_hash must be 64 hex chars (32 bytes); got {} chars",
            trimmed.chars().count()
        )));
    }
    let mut out: [u8; 32] = [0u8; 32];
    for (slot, chunk) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let byte_hex: &str = core::str::from_utf8(chunk)
            .map_err(|e: core::str::Utf8Error| DisrobeError::new_err(format!("hex: {e}")))?;
        *slot = u8::from_str_radix(byte_hex, 16)
            .map_err(|e: std::num::ParseIntError| DisrobeError::new_err(format!("hex: {e}")))?;
    }
    Ok(out)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Instruction>()?;
    m.add_class::<Symbol>()?;
    m.add_class::<CodeObject>()?;
    Ok(())
}
