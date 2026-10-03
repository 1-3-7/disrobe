use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_py_disasm::{ExceptionEntry, Instruction, decode_exception_table, disassemble};
use disrobe_py_marshal::{CodeEra, CodeObject, LocalKind, Object, PyVersion};

const MAX_CODE_DEPTH: usize = 64;
const MAX_STORE_DISTANCE: usize = 64;
const JUNK_RETURN_BYTES: usize = 2;

const TERMINATORS: [&str; 10] = [
    "RETURN_VALUE",
    "RETURN_CONST",
    "RAISE_VARARGS",
    "RERAISE",
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "JUMP_FORWARD",
    "JUMP_ABSOLUTE",
    "JUMP",
    "JUMP_NO_INTERRUPT",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    Local,
}

impl Scope {
    const fn prefix(self) -> char {
        match self {
            Self::Global => 'g',
            Self::Local => 'l',
        }
    }

    fn is_placeholder(self, name: &str) -> bool {
        name.strip_prefix(self.prefix())
            .is_some_and(|digits: &str| {
                !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
            })
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ObfuscationReversal {
    pub junk_returns_stripped: usize,
    pub names_restored: BTreeMap<String, String>,
    pub placeholders_left: BTreeSet<String>,
}

pub(super) fn is_obfuscated(code: &CodeObject, version: PyVersion) -> bool {
    version.is_wordcode()
        && text(&code.filename) == Some("")
        && code.firstlineno == 1
        && code.linetable.is_empty()
        && code.lnotab.is_empty()
        && junk_return_offset(code, version).is_some()
}

pub(super) fn reverse(code: &mut CodeObject, version: PyVersion) -> ObfuscationReversal {
    let mut reversal: ObfuscationReversal = ObfuscationReversal::default();
    strip_junk_returns(code, version, 0, &mut reversal);
    if code.era == CodeEra::Py311Plus {
        let globals: BTreeMap<String, String> = def_name_map(code, version, Scope::Global);
        rename_globals(code, &globals, 0);
        restore_local_scopes(code, version, &BTreeMap::new(), 0, &mut reversal);
        reversal.names_restored.extend(globals);
    }
    collect_placeholders(code, 0, &mut reversal.placeholders_left);
    reversal
}

fn junk_return_offset(code: &CodeObject, version: PyVersion) -> Option<usize> {
    let instructions: Vec<Instruction> = disassemble(code, version);
    let [.., previous, last] = instructions.as_slice() else {
        return None;
    };
    let is_return: bool = matches!(last.opname.as_str(), "RETURN_VALUE" | "RETURN_CONST");
    let dead: bool = TERMINATORS.contains(&previous.opname.as_str()) && !last.is_jump_target;
    let trailing: bool = last.offset.checked_add(JUNK_RETURN_BYTES) == Some(code.code.len());
    let handled: bool =
        decode_exception_table(&code.exceptiontable).is_ok_and(|entries: Vec<ExceptionEntry>| {
            entries
                .iter()
                .any(|entry: &ExceptionEntry| entry.target_offset as usize == last.offset)
        });
    (is_return && dead && trailing && !handled).then_some(last.offset)
}

fn strip_junk_returns(
    code: &mut CodeObject,
    version: PyVersion,
    depth: usize,
    reversal: &mut ObfuscationReversal,
) {
    if depth >= MAX_CODE_DEPTH {
        return;
    }
    if let Some(offset) = junk_return_offset(code, version) {
        code.code.truncate(offset);
        reversal.junk_returns_stripped += 1;
    }
    for konst in &mut code.consts {
        if let Object::Code(inner) = konst {
            strip_junk_returns(inner, version, depth + 1, reversal);
        }
    }
}

fn def_name_map(code: &CodeObject, version: PyVersion, scope: Scope) -> BTreeMap<String, String> {
    let instructions: Vec<Instruction> = disassemble(code, version);
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicting: BTreeSet<String> = BTreeSet::new();
    for (index, window) in instructions.windows(2).enumerate() {
        let [load, make] = window else {
            continue;
        };
        if load.opname != "LOAD_CONST" || make.opname != "MAKE_FUNCTION" {
            continue;
        }
        let Some(Object::Code(defined)) =
            load.arg.and_then(|arg: u32| code.consts.get(arg as usize))
        else {
            continue;
        };
        let Some(original) = defined_name(defined) else {
            continue;
        };
        let Some(target) = store_target(code, &instructions[index + 2..], scope) else {
            continue;
        };
        if !scope.is_placeholder(target) || target == original {
            continue;
        }
        match found.get(target) {
            Some(previous) if previous != original => {
                conflicting.insert(target.to_owned());
            }
            _ => {
                found.insert(target.to_owned(), original.to_owned());
            }
        }
    }
    found.retain(|placeholder: &String, _| !conflicting.contains(placeholder));
    found
}

fn defined_name(defined: &CodeObject) -> Option<&str> {
    let qualname: &str = text(&defined.qualname)?;
    let last: &str = qualname.rsplit('.').next()?;
    is_identifier(last).then_some(last)
}

fn store_target<'c>(code: &'c CodeObject, rest: &[Instruction], scope: Scope) -> Option<&'c str> {
    for instruction in rest.iter().take(MAX_STORE_DISTANCE) {
        let opname: &str = instruction.opname.as_str();
        if matches!(opname, "MAKE_FUNCTION" | "LOAD_BUILD_CLASS") {
            return None;
        }
        if !opname.starts_with("STORE_") {
            continue;
        }
        let arg: usize = instruction.arg? as usize;
        return match (scope, opname) {
            (Scope::Global, "STORE_NAME" | "STORE_GLOBAL") => code.names.get(arg).and_then(text),
            (Scope::Local, "STORE_FAST" | "STORE_DEREF") => {
                code.localsplusnames.get(arg).and_then(text)
            }
            _ => None,
        };
    }
    None
}

fn rename_globals(code: &mut CodeObject, globals: &BTreeMap<String, String>, depth: usize) {
    if depth >= MAX_CODE_DEPTH || globals.is_empty() {
        return;
    }
    rename_unique(&mut code.names, globals);
    restore_code_name(code);
    for konst in &mut code.consts {
        if let Object::Code(inner) = konst {
            rename_globals(inner, globals, depth + 1);
        }
    }
}

fn restore_code_name(code: &mut CodeObject) {
    let placeholder: bool = text(&code.name).is_some_and(|name: &str| {
        Scope::Global.is_placeholder(name) || Scope::Local.is_placeholder(name)
    });
    if !placeholder {
        return;
    }
    if let Some(original) = defined_name(code).map(str::to_owned) {
        code.name = renamed(&code.name, &original);
    }
}

fn restore_local_scopes(
    code: &mut CodeObject,
    version: PyVersion,
    inherited: &BTreeMap<String, String>,
    depth: usize,
    reversal: &mut ObfuscationReversal,
) {
    if depth >= MAX_CODE_DEPTH {
        return;
    }
    let own: BTreeMap<String, String> = def_name_map(code, version, Scope::Local);
    let mut visible: BTreeMap<String, String> = inherited.clone();
    visible.extend(
        own.iter()
            .map(|(k, v): (&String, &String)| (k.clone(), v.clone())),
    );
    let kinds: Vec<Option<LocalKind>> = code
        .localspluskinds
        .iter()
        .map(|kind: &u8| LocalKind::from_byte(*kind))
        .collect();
    let taken: BTreeSet<String> = code
        .localsplusnames
        .iter()
        .filter_map(text)
        .map(str::to_owned)
        .collect();
    for (slot, kind) in code.localsplusnames.iter_mut().zip(kinds) {
        let Some(name) = text(slot) else {
            continue;
        };
        let map: &BTreeMap<String, String> = match kind {
            Some(LocalKind::Free) => inherited,
            Some(LocalKind::Local | LocalKind::Cell) => &own,
            None => continue,
        };
        if let Some(original) = map.get(name)
            && !taken.contains(original)
        {
            *slot = renamed(slot, original);
        }
    }
    reversal.names_restored.extend(own);
    for konst in &mut code.consts {
        if let Object::Code(inner) = konst {
            restore_local_scopes(inner, version, &visible, depth + 1, reversal);
        }
    }
}

fn rename_unique(slots: &mut [Object], map: &BTreeMap<String, String>) {
    let taken: BTreeSet<String> = slots.iter().filter_map(text).map(str::to_owned).collect();
    for slot in slots {
        if let Some(original) = text(slot).and_then(|name: &str| map.get(name))
            && !taken.contains(original)
        {
            *slot = renamed(slot, original);
        }
    }
}

fn collect_placeholders(code: &CodeObject, depth: usize, out: &mut BTreeSet<String>) {
    if depth >= MAX_CODE_DEPTH {
        return;
    }
    for name in code.names.iter().filter_map(text) {
        if Scope::Global.is_placeholder(name) {
            out.insert(name.to_owned());
        }
    }
    for name in code
        .localsplusnames
        .iter()
        .chain(&code.varnames)
        .filter_map(text)
    {
        if Scope::Local.is_placeholder(name) {
            out.insert(name.to_owned());
        }
    }
    for konst in &code.consts {
        if let Object::Code(inner) = konst {
            collect_placeholders(inner, depth + 1, out);
        }
    }
}

const fn text(obj: &Object) -> Option<&str> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

fn renamed(slot: &Object, value: &str) -> Object {
    let interned: bool = match slot {
        Object::String { interned, .. }
        | Object::Unicode { interned, .. }
        | Object::ShortAscii { interned, .. } => *interned,
        _ => true,
    };
    if value.is_ascii() && u8::try_from(value.len()).is_ok() {
        Object::ShortAscii {
            value: value.to_owned(),
            interned,
        }
    } else {
        Object::Unicode {
            value: value.to_owned(),
            interned,
        }
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first: char| first == '_' || first.is_alphabetic())
        && chars.all(|c: char| c == '_' || c.is_alphanumeric())
}
