use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirInstr, NirOp, SourceLang, SourceRef};
use disrobe_sleigh::pcode::{Space, Varnode};

use crate::error::{LiftError, Result};

use super::valid_identifier;

const MAX_REGISTER_CELLS: usize = 4096;
const MAX_VARNODE_BYTES: u32 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterCell {
    pub offset: u64,
    pub size: u32,
    pub name: String,
    pub zero_upper_write_size: Option<u32>,
}

impl RegisterCell {
    #[must_use]
    pub fn new(
        offset: u64,
        size: u32,
        name: impl Into<String>,
        zero_upper_write_size: Option<u32>,
    ) -> Self {
        Self {
            offset,
            size,
            name: name.into(),
            zero_upper_write_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingOutput {
    pub value: String,
    pub destination: OutputDestination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OutputDestination {
    Direct,
    Register {
        cell: String,
        offset: u32,
        size: u32,
        cell_size: u32,
        zero_upper: bool,
    },
    Ram {
        addr: String,
        size: u32,
    },
}

#[derive(Clone, Copy, Debug)]
struct RegisterView<'a> {
    cell: &'a RegisterCell,
    relative_offset: u32,
}

#[derive(Debug)]
pub(super) struct VarnodeLowerer<'a> {
    lang: SourceLang,
    registers: &'a [RegisterCell],
    unique_names: BTreeMap<(u64, u32), String>,
    known_constants: BTreeMap<Varnode, u64>,
    next_name: u64,
}

impl<'a> VarnodeLowerer<'a> {
    pub(super) fn new(lang: SourceLang, registers: &'a [RegisterCell]) -> Result<Self> {
        validate_registers(registers)?;
        Ok(Self {
            lang,
            registers,
            unique_names: BTreeMap::new(),
            known_constants: BTreeMap::new(),
            next_name: 0,
        })
    }

    pub(super) fn read(
        &mut self,
        varnode: Varnode,
        address: u64,
        operation: &str,
        instructions: &mut Vec<NirInstr>,
    ) -> Result<String> {
        validate_varnode(varnode, address, operation)?;
        match varnode.space {
            Space::Constant => Ok(format_constant(varnode.offset, varnode.size_bytes)),
            Space::Unique => self.unique(varnode, false, address, operation),
            Space::Register => self.read_register(varnode, address, operation, instructions),
            Space::Ram => {
                let addr: String = format_constant(varnode.offset, 8);
                let temporary: String = self.fresh_name();
                let mut instruction: NirInstr = self.instruction(
                    address,
                    NirOp::RawLoad {
                        addr: addr.clone(),
                        size: varnode.size_bytes,
                    },
                    "LOAD",
                    vec![temporary.clone(), addr],
                );
                instruction.reads_memory = true;
                instruction.byte_width = varnode.size_bytes == 1;
                instructions.push(instruction);
                Ok(temporary)
            }
        }
    }

    pub(super) fn begin_instruction(&mut self, clear_registers: bool) {
        if clear_registers {
            self.known_constants.clear();
        } else {
            self.known_constants
                .retain(|varnode: &Varnode, _value: &mut u64| varnode.space == Space::Register);
        }
    }

    pub(super) fn output(
        &mut self,
        varnode: Varnode,
        address: u64,
        operation: &str,
    ) -> Result<PendingOutput> {
        validate_varnode(varnode, address, operation)?;
        self.forget(varnode);
        match varnode.space {
            Space::Unique => Ok(PendingOutput {
                value: self.unique(varnode, true, address, operation)?,
                destination: OutputDestination::Direct,
            }),
            Space::Register => self.register_output(varnode, address, operation),
            Space::Constant => Err(invalid(
                address,
                operation,
                "constant varnode cannot be an output",
            )),
            Space::Ram => Ok(PendingOutput {
                value: self.fresh_name(),
                destination: OutputDestination::Ram {
                    addr: format_constant(varnode.offset, 8),
                    size: varnode.size_bytes,
                },
            }),
        }
    }

    pub(super) fn finish(
        &self,
        output: PendingOutput,
        address: u64,
        instructions: &mut Vec<NirInstr>,
    ) {
        if let OutputDestination::Register {
            cell,
            offset,
            size,
            cell_size,
            zero_upper,
        } = output.destination
        {
            instructions.push(NirInstr {
                address,
                op: NirOp::Deposit {
                    cell,
                    value: output.value,
                    offset,
                    size,
                    cell_size,
                    zero_upper,
                },
                mnemonic: "DEPOSIT".to_owned(),
                operands: Vec::new(),
                reads_memory: false,
                writes_memory: false,
                byte_width: size == 1,
                source: SourceRef::new(self.lang, address),
            });
        } else if let OutputDestination::Ram { addr, size } = output.destination {
            instructions.push(NirInstr {
                address,
                op: NirOp::RawStore {
                    addr: addr.clone(),
                    value: output.value,
                    size,
                },
                mnemonic: "STORE".to_owned(),
                operands: vec![addr],
                reads_memory: false,
                writes_memory: true,
                byte_width: size == 1,
                source: SourceRef::new(self.lang, address),
            });
        }
    }

    pub(super) fn instruction(
        &self,
        address: u64,
        op: NirOp,
        mnemonic: &str,
        operands: Vec<String>,
    ) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands,
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(self.lang, address),
        }
    }

    pub(super) fn resolved_constant(&self, varnode: Varnode) -> Option<u64> {
        match varnode.space {
            Space::Constant => Some(mask_value(varnode.offset, varnode.size_bytes)),
            Space::Register | Space::Unique => self.known_constants.get(&varnode).copied(),
            Space::Ram => None,
        }
    }

    pub(super) fn record_constant(&mut self, varnode: Varnode, value: Option<u64>) {
        self.forget(varnode);
        if let Some(value) = value {
            self.known_constants
                .insert(varnode, mask_value(value, varnode.size_bytes));
        }
    }

    pub(super) fn invalidate_register_constants(&mut self) {
        self.known_constants
            .retain(|varnode: &Varnode, _value: &mut u64| varnode.space != Space::Register);
    }

    pub(super) fn control_target(
        &mut self,
        varnode: Varnode,
        address: u64,
        operation: &str,
        instructions: &mut Vec<NirInstr>,
    ) -> Result<(String, Option<u64>)> {
        validate_varnode(varnode, address, operation)?;
        let resolved: Option<u64> = match varnode.space {
            Space::Ram => Some(mask_value(varnode.offset, varnode.size_bytes)),
            Space::Constant | Space::Register | Space::Unique => self.resolved_constant(varnode),
        };
        let value: String = match varnode.space {
            Space::Constant | Space::Ram => format_constant(varnode.offset, varnode.size_bytes),
            Space::Register | Space::Unique => {
                self.read(varnode, address, operation, instructions)?
            }
        };
        Ok((value, resolved))
    }

    fn read_register(
        &mut self,
        varnode: Varnode,
        address: u64,
        operation: &str,
        instructions: &mut Vec<NirInstr>,
    ) -> Result<String> {
        let view: RegisterView<'_> = self.register_view(varnode, address, operation)?;
        if view.relative_offset == 0 && varnode.size_bytes == view.cell.size {
            return Ok(view.cell.name.clone());
        }
        let source: String = view.cell.name.clone();
        let relative_offset: u32 = view.relative_offset;
        let temporary: String = self.fresh_name();
        instructions.push(self.instruction(
            address,
            NirOp::Subpiece {
                src: source,
                offset: relative_offset,
                size: varnode.size_bytes,
            },
            "SUBPIECE",
            vec![temporary.clone()],
        ));
        Ok(temporary)
    }

    fn register_output(
        &mut self,
        varnode: Varnode,
        address: u64,
        operation: &str,
    ) -> Result<PendingOutput> {
        let view: RegisterView<'_> = self.register_view(varnode, address, operation)?;
        if view.relative_offset == 0 && varnode.size_bytes == view.cell.size {
            return Ok(PendingOutput {
                value: view.cell.name.clone(),
                destination: OutputDestination::Direct,
            });
        }
        let cell: String = view.cell.name.clone();
        let cell_size: u32 = view.cell.size;
        let relative_offset: u32 = view.relative_offset;
        let zero_upper: bool =
            relative_offset == 0 && view.cell.zero_upper_write_size == Some(varnode.size_bytes);
        Ok(PendingOutput {
            value: self.fresh_name(),
            destination: OutputDestination::Register {
                cell,
                offset: relative_offset,
                size: varnode.size_bytes,
                cell_size,
                zero_upper,
            },
        })
    }

    fn register_view(
        &self,
        varnode: Varnode,
        address: u64,
        operation: &str,
    ) -> Result<RegisterView<'_>> {
        let varnode_end: u64 = varnode
            .offset
            .checked_add(u64::from(varnode.size_bytes))
            .ok_or_else(|| invalid(address, operation, "register varnode range overflow"))?;
        for cell in self.registers {
            let cell_end: u64 = cell
                .offset
                .checked_add(u64::from(cell.size))
                .ok_or_else(|| invalid(address, operation, "register cell range overflow"))?;
            if varnode.offset >= cell.offset && varnode_end <= cell_end {
                let relative: u64 = varnode.offset.saturating_sub(cell.offset);
                let relative_offset: u32 = u32::try_from(relative).map_err(|_| {
                    invalid(address, operation, "register relative offset exceeds u32")
                })?;
                return Ok(RegisterView {
                    cell,
                    relative_offset,
                });
            }
        }
        Err(invalid(
            address,
            operation,
            "register varnode has no containing canonical cell",
        ))
    }

    fn unique(
        &mut self,
        varnode: Varnode,
        define: bool,
        address: u64,
        operation: &str,
    ) -> Result<String> {
        let key: (u64, u32) = (varnode.offset, varnode.size_bytes);
        if define {
            let name: String = self.fresh_name();
            self.unique_names.insert(key, name.clone());
            return Ok(name);
        }
        self.unique_names.get(&key).cloned().ok_or_else(|| {
            invalid(
                address,
                operation,
                "unique varnode is read before definition",
            )
        })
    }

    fn fresh_name(&mut self) -> String {
        loop {
            let name: String = format!("t{}", self.next_name);
            self.next_name = self.next_name.saturating_add(1);
            if !self
                .registers
                .iter()
                .any(|cell: &RegisterCell| cell.name.eq_ignore_ascii_case(&name))
            {
                return name;
            }
        }
    }

    fn forget(&mut self, varnode: Varnode) {
        match varnode.space {
            Space::Register => {
                let start: u64 = varnode.offset;
                let end: u64 = start.saturating_add(u64::from(varnode.size_bytes));
                self.known_constants
                    .retain(|known: &Varnode, _value: &mut u64| {
                        if known.space != Space::Register {
                            return true;
                        }
                        let known_end: u64 =
                            known.offset.saturating_add(u64::from(known.size_bytes));
                        end <= known.offset || known_end <= start
                    });
            }
            Space::Unique => {
                self.known_constants.remove(&varnode);
            }
            Space::Constant | Space::Ram => {}
        }
    }
}

fn validate_registers(registers: &[RegisterCell]) -> Result<()> {
    if registers.len() > MAX_REGISTER_CELLS {
        return Err(invalid(
            0,
            "REGISTER_MAP",
            "register cell count exceeds limit",
        ));
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (index, cell) in registers.iter().enumerate() {
        if cell.size == 0 || cell.size > MAX_VARNODE_BYTES {
            return Err(invalid(
                0,
                "REGISTER_MAP",
                "register cell size is outside limits",
            ));
        }
        if !valid_identifier(&cell.name) {
            return Err(invalid(0, "REGISTER_MAP", "register cell name is invalid"));
        }
        if !names.insert(cell.name.to_ascii_lowercase()) {
            return Err(invalid(
                0,
                "REGISTER_MAP",
                "canonical register names are not unique",
            ));
        }
        let cell_end: u64 = cell
            .offset
            .checked_add(u64::from(cell.size))
            .ok_or_else(|| invalid(0, "REGISTER_MAP", "register cell range overflow"))?;
        if cell
            .zero_upper_write_size
            .is_some_and(|size: u32| size == 0 || size >= cell.size)
        {
            return Err(invalid(
                0,
                "REGISTER_MAP",
                "zero-upper width must be smaller than its register cell",
            ));
        }
        for other in registers.iter().skip(index.saturating_add(1)) {
            let other_end: u64 = other
                .offset
                .checked_add(u64::from(other.size))
                .ok_or_else(|| invalid(0, "REGISTER_MAP", "register cell range overflow"))?;
            if cell.offset < other_end && other.offset < cell_end {
                return Err(invalid(
                    0,
                    "REGISTER_MAP",
                    "canonical register cells overlap",
                ));
            }
        }
    }
    Ok(())
}

fn validate_varnode(varnode: Varnode, address: u64, operation: &str) -> Result<()> {
    if varnode.size_bytes == 0 || varnode.size_bytes > MAX_VARNODE_BYTES {
        return Err(invalid(
            address,
            operation,
            "varnode size is outside limits",
        ));
    }
    Ok(())
}

fn invalid(address: u64, operation: &str, reason: &str) -> LiftError {
    LiftError::InvalidPcode {
        address,
        operation: operation.to_owned(),
        reason: reason.to_owned(),
    }
}

fn format_constant(value: u64, size: u32) -> String {
    let masked: u64 = mask_value(value, size);
    format!("0x{masked:x}")
}

pub(super) const fn mask_value(value: u64, size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    if bits >= 64 {
        value
    } else {
        let mask: u64 = match 1_u64.checked_shl(bits) {
            Some(shifted) => shifted.saturating_sub(1),
            None => 0,
        };
        value & mask
    }
}
