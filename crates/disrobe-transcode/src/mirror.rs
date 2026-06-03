use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct RawPayloadMirror {
    pub source_path: String,
    pub source_bytes: Vec<u8>,
    pub source_hash: [u8; 32],
    pub detected_format: Option<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmPayloadMirror {
    pub source_hash: [u8; 32],
    pub instructions: Vec<DisasmInstructionMirror>,
    pub symbol_table: Vec<DisasmSymbolMirror>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmInstructionMirror {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct DisasmSymbolMirror {
    pub address: u64,
    pub name: String,
    pub kind: DisasmSymbolKindMirror,
}

#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub enum DisasmSymbolKindMirror {
    Function,
    Data,
    Label,
    Export,
    Import,
}
