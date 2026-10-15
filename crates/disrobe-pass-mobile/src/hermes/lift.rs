use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::decompile::{
    BasicBlock, BlockStmt, Cfg, Instruction, LiftedBlock, OperandValue, switch_table_entries,
};
use super::literals::{BufferKind, LiteralFormat, LiteralValue, decode_literals_in};
use super::{HermesExceptionEntry, HermesModule, SmallFunctionHeader};

pub(crate) const CALL_FRAME_THIS_SLOT: u32 = 7;
const MAX_CALL_ARGS: u64 = 4096;
const MAX_TRACKED_REGISTERS: u32 = 1 << 16;
const MAX_EXPR_BYTES: usize = 1 << 14;
const MAX_ENV_SLOTS: u32 = 1 << 16;
const MAX_LITERAL_ELEMENTS: u64 = 1 << 16;
const MAX_REACHING_BITS: usize = 1 << 28;
pub(crate) const CLOSURE_MARK: char = '\u{1}';

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Helper {
    Empty,
    Tdz,
    SilentSetPrototypeOf,
    TemplateObject,
    EnsureObject,
    GetMethod,
    ThrowTypeError,
    ThrowReferenceError,
    SetFunctionName,
    CopyDataProperties,
    ArraySpread,
    ExportAll,
    CoerceThis,
    SpawnAsync,
    YieldResume,
    CreateGenerator,
    TypeOfIs,
    StringCase,
    Class,
    Private,
    ToPropertyKey,
    FunctionPrototype,
    Unrecovered,
}

impl Helper {
    pub(crate) const fn definition(self) -> &'static str {
        match self {
            Self::Empty => "var $empty = { \"uninitialized binding\": true };",
            Self::Tdz => {
                "function $tdz(value) { if (value === $empty) throw new ReferenceError(\"accessing an uninitialized variable\"); return value; }"
            }
            Self::SilentSetPrototypeOf => {
                "function $silentSetPrototypeOf(object, parent) { try { Object.setPrototypeOf(object, parent); } catch (error) {} return undefined; }"
            }
            Self::TemplateObject => {
                "var $templateCache = {}; function $getTemplateObject(id, dup) { if (Object.prototype.hasOwnProperty.call($templateCache, id)) return $templateCache[id]; var rest = Array.prototype.slice.call(arguments, 2); var count = dup ? rest.length : rest.length / 2; var raw = rest.slice(0, count); var cooked = dup ? raw.slice() : rest.slice(count); Object.defineProperty(cooked, \"raw\", { value: Object.freeze(raw) }); Object.freeze(cooked); $templateCache[id] = cooked; return cooked; }"
            }
            Self::EnsureObject => {
                "function $ensureObject(value, message) { if (Object(value) !== value) throw new TypeError(message); return undefined; }"
            }
            Self::GetMethod => {
                "function $getMethod(object, key) { var method = object[key]; if (method === undefined || method === null) return undefined; if (typeof method !== \"function\") throw new TypeError(\"not a function\"); return method; }"
            }
            Self::ThrowTypeError => {
                "function $throwTypeError(message) { throw new TypeError(message); }"
            }
            Self::ThrowReferenceError => {
                "function $throwReferenceError(message) { throw new ReferenceError(message); }"
            }
            Self::SetFunctionName => {
                "function $setFunctionName(fn, key, prefix) { var name = typeof key === \"symbol\" ? (key.description === undefined ? \"\" : \"[\" + key.description + \"]\") : String(key); if (prefix === 1) name = \"get \" + name; else if (prefix === 2) name = \"set \" + name; Object.defineProperty(fn, \"name\", { value: name, writable: false, enumerable: false, configurable: true }); return undefined; }"
            }
            Self::CopyDataProperties => {
                "function $copyDataProperties(target, source, excluded) { if (source === null || source === undefined) return target; var from = Object(source); var keys = Reflect.ownKeys(from); for (var i = 0; i < keys.length; i++) { var key = keys[i]; if (excluded !== undefined && Object.prototype.hasOwnProperty.call(excluded, key)) continue; var desc = Object.getOwnPropertyDescriptor(from, key); if (desc && desc.enumerable) Object.defineProperty(target, key, { value: from[key], writable: true, enumerable: true, configurable: true }); } return target; }"
            }
            Self::ArraySpread => {
                "function $arraySpread(target, source, nextIndex) { for (var value of source) { Object.defineProperty(target, nextIndex, { value: value, writable: true, enumerable: true, configurable: true }); nextIndex++; } return nextIndex; }"
            }
            Self::ExportAll => {
                "function $exportAll(exports, source) { var keys = Object.keys(source); for (var i = 0; i < keys.length; i++) { var key = keys[i]; if (key === \"default\" || Object.prototype.hasOwnProperty.call(exports, key)) continue; Object.defineProperty(exports, key, { value: source[key], enumerable: true, writable: true, configurable: false }); } return undefined; }"
            }
            Self::CoerceThis => {
                "function $coerceThis(value) { return value === undefined || value === null ? globalThis : Object(value); }"
            }
            Self::SpawnAsync => {
                "var $spawnAsync = (function (PromiseCtor) { var resolveWith = PromiseCtor.resolve.bind(PromiseCtor); return function (makeGenerator, self, args) { return new PromiseCtor(function (resolve, reject) { var generator = makeGenerator.apply(self, args); function step(advance) { var next; try { next = advance(); } catch (error) { reject(error); return; } if (next.done) { resolve(next.value); return; } resolveWith(next.value).then(function (value) { step(function () { return generator.next(value); }); }, function (error) { step(function () { return generator.throw(error); }); }); } step(function () { return generator.next(undefined); }); }); }; })(globalThis.Promise);"
            }
            Self::YieldResume => {
                "function $YieldReturn(value) { this.value = value; } function $yieldResume(value, delegated) { var first = true; var iterator = { next: function (sent) { if (first) { first = false; return delegated ? value : { value: value, done: false }; } return { value: sent, done: true }; }, throw: function (error) { throw error; }, return: function (sent) { throw new $YieldReturn(sent); } }; iterator[Symbol.iterator] = function () { return iterator; }; return iterator; }"
            }
            Self::CreateGenerator => {
                "var $generatorInner = new WeakMap(); var $GeneratorPrototype = (function () { function resume(generator, action, value) { var inner = $generatorInner.get(generator); if (inner === undefined) throw new TypeError(\"Generator functions must be called on generators\"); return inner.call(inner, action, value); } var proto = { next: function (value) { return resume(this, 0, value); }, return: function (value) { return resume(this, 2, value); }, throw: function (value) { return resume(this, 1, value); } }; proto[Symbol.iterator] = function () { return this; }; Object.defineProperty(proto, Symbol.toStringTag, { value: \"Generator\", configurable: true }); return proto; })(); function $createGenerator(inner) { var generator = Object.create($GeneratorPrototype); $generatorInner.set(generator, inner); return generator; }"
            }
            Self::TypeOfIs => {
                "function $typeOfIs(value, mask) { var kind = value === null ? 8 : { undefined: 0, object: 1, string: 2, symbol: 3, boolean: 4, number: 5, bigint: 6, function: 7 }[typeof value]; return (mask >> kind & 1) === 1; }"
            }
            Self::Class => {
                "function $baseClass(constructor) { Object.defineProperty(constructor, \"prototype\", { writable: false }); return constructor; } function $derivedClass(constructor, parent) { var parentPrototype; if (parent === null) { parentPrototype = null; } else { if (typeof parent !== \"function\") throw new TypeError(\"Class extends value is not a constructor or null\"); parentPrototype = parent.prototype; if (parentPrototype !== null && Object(parentPrototype) !== parentPrototype) throw new TypeError(\"Class extends value does not have valid prototype property\"); } Object.setPrototypeOf(constructor, parent === null ? Function.prototype : parent); Object.defineProperty(constructor, \"prototype\", { value: Object.create(parentPrototype, { constructor: { value: constructor, writable: true, configurable: true } }), writable: false }); return constructor; }"
            }
            Self::Private => {
                "function $privateHas(object, name) { return Object(object) === object && Object.prototype.hasOwnProperty.call(object, name); } function $privateAdd(object, value, name) { if ($privateHas(object, name)) throw new TypeError(\"Cannot initialize private field twice.\"); Object.defineProperty(object, name, { value: value, writable: true, enumerable: false, configurable: false }); return undefined; } function $privateGet(object, name) { if (!$privateHas(object, name)) throw new TypeError(\"Cannot read private field \" + String(name.description)); return object[name]; } function $privateSet(object, value, name) { if (!$privateHas(object, name)) throw new TypeError(\"Cannot write private field \" + String(name.description)); object[name] = value; return undefined; }"
            }
            Self::StringCase => {
                "function $stringCase(value, labels) { return typeof value === \"string\" ? labels.indexOf(value) : -1; }"
            }
            Self::ToPropertyKey => {
                "function $toPropertyKey(value) { return Reflect.ownKeys({ [value]: 0 })[0]; }"
            }
            Self::FunctionPrototype => {
                "var $functionPrototypeCall = Function.prototype.call, $functionPrototypeApply = Function.prototype.apply;"
            }
            Self::Unrecovered => {
                "function $unrecovered(operation) { throw new Error(\"disrobe: hermes operation \" + operation + \" was not recovered\"); }"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Ident,
    Literal,
    Number,
    Member,
    Call,
    Paren,
    Unary,
    Function,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Plain,
    Global,
    BareGlobal,
    HermesInternal,
    HermesInternalMethod(String),
    Builtin(String),
    Member {
        object: Box<Value>,
        key: String,
    },
    FreshArray {
        elems: Vec<Option<String>>,
        len: u64,
    },
    FreshObject {
        props: Vec<String>,
    },
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Value {
    text: String,
    form: Form,
    call_free: bool,
    duplicable: bool,
    deps: BTreeSet<u32>,
    effects: Vec<u64>,
    shape: Shape,
    origin: Option<u32>,
}

impl Value {
    fn new(text: String, form: Form) -> Self {
        Self {
            call_free: !matches!(form, Form::Call),
            text,
            form,
            duplicable: false,
            deps: BTreeSet::new(),
            effects: Vec::new(),
            shape: Shape::Plain,
            origin: None,
        }
    }

    fn constant(text: String, form: Form) -> Self {
        let mut value: Self = Self::new(text, form);
        value.duplicable = true;
        value
    }

    fn effectful(&self) -> bool {
        !self.effects.is_empty()
    }

    fn min_effect(&self) -> Option<u64> {
        self.effects.first().copied()
    }

    fn max_effect(&self) -> Option<u64> {
        self.effects.last().copied()
    }

    fn object_text(&self) -> String {
        match self.form {
            Form::Ident | Form::Literal | Form::Member | Form::Call | Form::Paren => {
                self.text.clone()
            }
            Form::Number | Form::Unary | Form::Function => format!("({})", self.text),
        }
    }

    fn operand_text(&self) -> String {
        match self.form {
            Form::Ident
            | Form::Literal
            | Form::Member
            | Form::Call
            | Form::Paren
            | Form::Number => self.text.clone(),
            Form::Unary | Form::Function => format!("({})", self.text),
        }
    }

    fn new_callee_text(&self) -> String {
        match self.form {
            Form::Ident => self.text.clone(),
            Form::Member if self.call_free => self.text.clone(),
            _ => format!("({})", self.text),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegState {
    Pending(Value),
    Const(Value),
    Var,
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvRef {
    Owned(u32),
    Unknown(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvOrigin {
    Own,
    Up(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetroModule {
    pub id: u64,
    pub factory: u32,
    pub dependencies: Vec<u64>,
    pub name: Option<String>,
}

const METRO_FACTORY_PARAMS: [&str; 7] = [
    "global",
    "require",
    "importDefault",
    "importAll",
    "module",
    "exports",
    "dependencyMap",
];
const METRO_LEGACY_FACTORY_PARAMS: [&str; 5] =
    ["global", "require", "module", "exports", "dependencyMap"];

#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleScope {
    pub(crate) declared_globals: BTreeSet<String>,
    pub(crate) global_index: u32,
    sites: BTreeMap<u32, Vec<(u32, Option<EnvOrigin>)>>,
    chains: BTreeMap<u32, Option<Vec<u32>>>,
    pub(crate) prefix: String,
    pub(crate) metro_modules: Vec<MetroModule>,
    param_overrides: BTreeMap<u32, Vec<String>>,
    pub(crate) async_bodies: BTreeSet<u32>,
    env_slot_envs: BTreeMap<(u32, u64), u32>,
    env_hosts: BTreeMap<u32, u32>,
    pub(crate) env_sizes: BTreeMap<u32, u32>,
    boxed_envs: BTreeSet<u32>,
    pub(crate) structuring: super::structure::Structuring,
}

impl ModuleScope {
    pub(crate) fn analyze(
        module: &HermesModule,
        decode: &dyn Fn(usize) -> Vec<Instruction>,
        whole_module: bool,
    ) -> Self {
        let mut scope: Self = Self {
            global_index: module.header.global_code_index,
            ..Self::default()
        };
        if module
            .identifiers
            .iter()
            .chain(module.strings.iter())
            .any(|name: &String| collides(name))
        {
            "$".clone_into(&mut scope.prefix);
        }
        let scanned: Vec<usize> = if whole_module {
            (0..module.functions.len()).collect()
        } else {
            vec![scope.global_index as usize]
        };
        let mut bare_names: BTreeSet<String> = BTreeSet::new();
        let mut stored_envs: Vec<(u32, EnvOrigin, u64)> = Vec::new();
        for index in scanned {
            let Ok(parent): Result<u32, _> = u32::try_from(index) else {
                break;
            };
            let instructions: Vec<Instruction> = decode(index);
            let frame_size: u32 = module
                .functions
                .get(index)
                .map_or(0, |h: &SmallFunctionHeader| call_frame_size(module, h));
            if parent == scope.global_index {
                scope.metro_modules = metro_registrations(module, &instructions, frame_size);
            }
            for wrapper in spawned_generator_wrappers(module, &instructions, frame_size) {
                if let Some(body) = generator_body(&decode(wrapper as usize)) {
                    scope.async_bodies.insert(body);
                }
            }
            let mut origins: BTreeMap<u32, EnvOrigin> = BTreeMap::new();
            let loops: Vec<(usize, usize)> = backward_jumps(&instructions);
            for inst in &instructions {
                let name: &str = &inst.name;
                match name {
                    "DeclareGlobalVar" if parent == scope.global_index => {
                        if let Some(OperandValue::StringId(id)) = inst.operands.first()
                            && let Some(text) = module.string_by_global_id(*id)
                        {
                            scope.declared_globals.insert(text.to_owned());
                        }
                    }
                    "CreateEnvironment" => {
                        origins.insert(reg_at(inst, 0), EnvOrigin::Own);
                        if loops.iter().any(|(target, jump): &(usize, usize)| {
                            *target <= inst.offset && inst.offset < *jump
                        }) {
                            scope.boxed_envs.insert(parent);
                        }
                        if let Some(OperandValue::UInt(size)) = inst.operands.get(1) {
                            let size: u32 = u32::try_from(*size).unwrap_or(u32::MAX);
                            scope.env_sizes.insert(parent, size);
                        }
                    }
                    "GetEnvironment" => {
                        let level: u32 = u32::try_from(uint_at(inst, 1)).unwrap_or(u32::MAX);
                        origins.insert(reg_at(inst, 0), EnvOrigin::Up(level));
                    }
                    "StoreToEnvironment"
                    | "StoreToEnvironmentL"
                    | "StoreNPToEnvironment"
                    | "StoreNPToEnvironmentL" => {
                        if origins.get(&reg_at(inst, 2)) == Some(&EnvOrigin::Own)
                            && let Some(target) = origins.get(&reg_at(inst, 0)).copied()
                        {
                            stored_envs.push((parent, target, uint_at(inst, 1)));
                        }
                    }
                    "Mov" | "MovLong" => {
                        let source: u32 = reg_at(inst, 1);
                        match origins.get(&source).copied() {
                            Some(origin) => {
                                origins.insert(reg_at(inst, 0), origin);
                            }
                            None => {
                                origins.remove(&reg_at(inst, 0));
                            }
                        }
                    }
                    "TryGetById" | "TryGetByIdLong" | "TryPutById" | "TryPutByIdLong" => {
                        if let Some(text) = module.string_by_global_id(string_at(inst, 3)) {
                            bare_names.insert(text.to_owned());
                        }
                        for written in roles(inst, u32::MAX).writes {
                            origins.remove(&written);
                        }
                    }
                    _ if class_creation(inst).is_some() => {
                        if let Some((env, child)) = class_creation(inst) {
                            scope
                                .sites
                                .entry(child)
                                .or_default()
                                .push((parent, origins.get(&env).copied()));
                        }
                        for written in roles(inst, u32::MAX).writes {
                            origins.remove(&written);
                        }
                    }
                    _ if is_closure_creation(name) => {
                        let env: u32 = reg_at(inst, 1);
                        if let Some(OperandValue::FunctionId(child)) = inst.operands.get(2) {
                            scope
                                .sites
                                .entry(*child)
                                .or_default()
                                .push((parent, origins.get(&env).copied()));
                        }
                        origins.remove(&reg_at(inst, 0));
                    }
                    _ => {
                        for written in roles(inst, u32::MAX).writes {
                            origins.remove(&written);
                        }
                    }
                }
            }
        }
        let mut chains: BTreeMap<u32, Option<Vec<u32>>> = BTreeMap::new();
        chains.insert(scope.global_index, Some(Vec::new()));
        for fid in scope.sites.keys() {
            let mut visiting: BTreeSet<u32> = BTreeSet::new();
            resolve_chain(*fid, &scope.sites, &mut chains, &mut visiting);
        }
        scope.chains = chains;
        for (stored, target, slot) in stored_envs {
            let owner: Option<u32> = match target {
                EnvOrigin::Own => Some(stored),
                EnvOrigin::Up(level) => scope
                    .chain(stored)
                    .and_then(|chain: &Vec<u32>| chain.get(level as usize).copied()),
            };
            if let Some(owner) = owner
                && owner != stored
            {
                scope.env_slot_envs.insert((owner, slot), stored);
                scope.env_hosts.insert(stored, owner);
            }
        }
        let hosts: BTreeMap<u32, u32> = scope.env_hosts.clone();
        scope
            .boxed_envs
            .retain(|fid: &u32| !hosts.contains_key(fid));
        let factories: Vec<u32> = scope
            .metro_modules
            .iter()
            .map(|m: &MetroModule| m.factory)
            .collect();
        for factory in factories {
            let Some(header) = module.functions.get(factory as usize) else {
                continue;
            };
            let names: &[&str] = match header.param_count {
                8 => &METRO_FACTORY_PARAMS,
                6 => &METRO_LEGACY_FACTORY_PARAMS,
                _ => continue,
            };
            let chosen: Vec<String> = names
                .iter()
                .enumerate()
                .map(|(position, name): (usize, &&str)| {
                    if bare_names.contains(*name) || scope.declared_globals.contains(*name) {
                        scope.param_name(u32::try_from(position).unwrap_or(u32::MAX))
                    } else {
                        (*name).to_owned()
                    }
                })
                .collect();
            scope.param_overrides.insert(factory, chosen);
        }
        scope
    }

    fn chain(&self, fid: u32) -> Option<&Vec<u32>> {
        self.chains.get(&fid).and_then(Option::as_ref)
    }

    pub(crate) fn env_held_in(&self, owner: u32, slot: u64) -> Option<u32> {
        self.env_slot_envs.get(&(owner, slot)).copied()
    }

    pub(crate) fn hosted_by(&self, host: u32) -> Vec<u32> {
        self.env_hosts
            .iter()
            .filter(|(_, owner): &(&u32, &u32)| **owner == host)
            .map(|(hosted, _): (&u32, &u32)| *hosted)
            .collect()
    }

    pub(crate) fn is_hosted_elsewhere(&self, fid: u32) -> bool {
        self.env_hosts.contains_key(&fid)
    }

    pub(crate) fn reg_name(&self, reg: u32) -> String {
        format!("{}r{reg}", self.prefix)
    }

    pub(crate) fn param_name(&self, index: u32) -> String {
        format!("{}arg{index}", self.prefix)
    }

    pub(crate) fn param_name_of(&self, function: usize, index: u32) -> String {
        u32::try_from(function)
            .ok()
            .and_then(|fid: u32| self.param_overrides.get(&fid))
            .and_then(|names: &Vec<String>| names.get(index as usize))
            .cloned()
            .unwrap_or_else(|| self.param_name(index))
    }

    pub(crate) fn is_boxed(&self, fid: u32) -> bool {
        self.boxed_envs.contains(&fid)
    }

    pub(crate) fn boxed_env_name(fid: u32) -> String {
        format!("$e{fid}")
    }

    pub(crate) fn env_name(&self, env: EnvRefName, slot: u64) -> String {
        match env {
            EnvRefName::Owned(owner) if self.is_boxed(owner) => {
                format!("{}.s{slot}", Self::boxed_env_name(owner))
            }
            EnvRefName::Owned(owner) => format!("{}c{owner}_{slot}", self.prefix),
            EnvRefName::Unknown(level) => format!("$envUp{level}_{slot}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvRefName {
    Owned(u32),
    Unknown(u32),
}

fn collides(name: &str) -> bool {
    let rest: &str = if let Some(stripped) = name.strip_prefix("arg") {
        stripped
    } else if let Some(stripped) = name.strip_prefix('r') {
        stripped
    } else if let Some(stripped) = name.strip_prefix('c') {
        stripped
    } else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c: char| c.is_ascii_digit() || c == '_')
}

fn backward_jumps(instructions: &[Instruction]) -> Vec<(usize, usize)> {
    instructions
        .iter()
        .flat_map(|inst: &Instruction| {
            inst.operands
                .iter()
                .filter_map(move |operand: &OperandValue| match operand {
                    OperandValue::Target(target) if *target <= inst.offset => {
                        Some((*target, inst.offset))
                    }
                    _ => None,
                })
        })
        .collect()
}

fn spawned_generator_wrappers(
    module: &HermesModule,
    instructions: &[Instruction],
    frame_size: u32,
) -> Vec<u32> {
    let mut spawners: BTreeSet<u32> = BTreeSet::new();
    let mut closures: BTreeMap<u32, (u32, usize)> = BTreeMap::new();
    let mut wrappers: Vec<u32> = Vec::new();
    for (position, inst) in instructions.iter().enumerate() {
        let name: &str = &inst.name;
        if matches!(name, "Call4" | "Call" | "CallLong") && spawners.contains(&reg_at(inst, 1)) {
            let first: Option<u32> = if name == "Call4" {
                Some(reg_at(inst, 3))
            } else {
                call_window(frame_size, uint_at(inst, 2))
                    .and_then(|window: Vec<u32>| window.get(1).copied())
            };
            if let Some(argument) = first
                && let Some((wrapper, created)) = closures.get(&argument).copied()
                && sole_straight_read(instructions, frame_size, created, position, argument)
            {
                wrappers.push(wrapper);
            }
        }
        let builtin_spawn: bool = name == "GetBuiltinClosure"
            && private_builtin(&super::builtins::builtin_name(
                module.header.version,
                uint_at(inst, 1),
            )) == Some("spawnAsync");
        let generator_closure: Option<u32> = match (name, inst.operands.get(2)) {
            (
                "CreateGeneratorClosure" | "CreateGeneratorClosureLongIndex",
                Some(OperandValue::FunctionId(fid)),
            ) => Some(*fid),
            _ => None,
        };
        for written in roles(inst, frame_size).writes {
            spawners.remove(&written);
            closures.remove(&written);
        }
        if builtin_spawn {
            spawners.insert(reg_at(inst, 0));
        }
        if let Some(fid) = generator_closure {
            closures.insert(reg_at(inst, 0), (fid, position));
        }
    }
    wrappers
}

fn sole_straight_read(
    instructions: &[Instruction],
    frame_size: u32,
    created: usize,
    call: usize,
    reg: u32,
) -> bool {
    let between_clean: bool = instructions[created + 1..call]
        .iter()
        .all(|inst: &Instruction| {
            !inst.name.starts_with('J')
                && !matches!(&*inst.name, "Ret" | "Throw" | "SwitchImm")
                && !roles(inst, frame_size).reads.contains(&reg)
        });
    let call_reads: usize = roles(&instructions[call], frame_size)
        .reads
        .iter()
        .filter(|r: &&u32| **r == reg)
        .count();
    let after_clean: bool = instructions[call + 1..]
        .iter()
        .map(|inst: &Instruction| roles(inst, frame_size))
        .take_while(|role: &Roles| !role.writes.contains(&reg) || role.reads.contains(&reg))
        .all(|role: Roles| !role.reads.contains(&reg));
    between_clean && call_reads == 1 && after_clean
}

fn generator_body(instructions: &[Instruction]) -> Option<u32> {
    let mut found: Option<u32> = None;
    for inst in instructions {
        if matches!(&*inst.name, "CreateGenerator" | "CreateGeneratorLongIndex") {
            let Some(OperandValue::FunctionId(fid)) = inst.operands.get(2) else {
                return None;
            };
            if found.is_some() {
                return None;
            }
            found = Some(*fid);
        }
    }
    found
}

fn resolve_chain(
    fid: u32,
    sites: &BTreeMap<u32, Vec<(u32, Option<EnvOrigin>)>>,
    chains: &mut BTreeMap<u32, Option<Vec<u32>>>,
    visiting: &mut BTreeSet<u32>,
) -> Option<Vec<u32>> {
    if let Some(known) = chains.get(&fid) {
        return known.clone();
    }
    if !visiting.insert(fid) || visiting.len() > 4096 {
        return None;
    }
    let mut resolved: Option<Vec<u32>> = None;
    let mut conflict: bool = false;
    for (parent, origin) in sites.get(&fid).map_or(&[][..], Vec::as_slice) {
        let parent_chain: Option<Vec<u32>> = resolve_chain(*parent, sites, chains, visiting);
        let candidate: Option<Vec<u32>> = match (origin, parent_chain) {
            (Some(EnvOrigin::Own), Some(chain)) => {
                let mut next: Vec<u32> = Vec::with_capacity(chain.len() + 1);
                next.push(*parent);
                next.extend(chain);
                Some(next)
            }
            (Some(EnvOrigin::Own), None) => Some(vec![*parent]),
            (Some(EnvOrigin::Up(level)), Some(chain)) => {
                let skip: usize = usize::try_from(*level).unwrap_or(usize::MAX);
                chain.get(skip..).map(<[u32]>::to_vec)
            }
            _ => None,
        };
        match (&resolved, candidate) {
            (None, Some(candidate)) if !conflict => resolved = Some(candidate),
            (Some(existing), Some(candidate)) if *existing == candidate => {}
            _ => {
                conflict = true;
                resolved = None;
            }
        }
    }
    visiting.remove(&fid);
    chains.insert(fid, resolved.clone());
    resolved
}

#[derive(Debug, Clone)]
enum MetroValue {
    Global,
    Define,
    Closure(u32),
    Number(u64),
    Numbers(Vec<u64>),
    Text(String),
}

pub(crate) fn metro_registrations(
    module: &HermesModule,
    instructions: &[Instruction],
    frame_size: u32,
) -> Vec<MetroModule> {
    let mut known: BTreeMap<u32, MetroValue> = BTreeMap::new();
    let mut out: Vec<MetroModule> = Vec::new();
    for inst in instructions {
        let name: &str = &inst.name;
        let dest: u32 = reg_at(inst, 0);
        let value: Option<MetroValue> = match name {
            "GetGlobalObject" => Some(MetroValue::Global),
            "TryGetById" | "TryGetByIdLong" | "GetById" | "GetByIdShort" | "GetByIdLong" => {
                let global: bool = matches!(known.get(&reg_at(inst, 1)), Some(MetroValue::Global));
                (global && module.string_by_global_id(string_at(inst, 3)) == Some("__d"))
                    .then_some(MetroValue::Define)
            }
            _ if is_closure_creation(name) => match inst.operands.get(2) {
                Some(OperandValue::FunctionId(fid)) => Some(MetroValue::Closure(*fid)),
                _ => None,
            },
            "LoadConstZero" => Some(MetroValue::Number(0)),
            "LoadConstUInt8" => Some(MetroValue::Number(uint_at(inst, 1))),
            "LoadConstInt" => match inst.operands.get(1) {
                Some(OperandValue::Imm(i)) => u64::try_from(*i).ok().map(MetroValue::Number),
                _ => None,
            },
            "LoadConstDouble" => match inst.operands.get(1) {
                Some(OperandValue::Float(bits)) => {
                    let v: f64 = f64::from_bits(*bits);
                    (v.fract() == 0.0 && (0.0..9.007_199_254_740_992e15).contains(&v))
                        .then_some(MetroValue::Number(v as u64))
                }
                _ => None,
            },
            "LoadConstString" | "LoadConstStringLongIndex" => module
                .string_by_global_id(string_at(inst, 1))
                .map(|s: &str| MetroValue::Text(s.to_owned())),
            "NewArray" if uint_at(inst, 1) == 0 => Some(MetroValue::Numbers(Vec::new())),
            "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
                let count: usize = uint_at(inst, 2).min(MAX_LITERAL_ELEMENTS) as usize;
                let values: Vec<LiteralValue> = decode_literals_in(
                    LiteralFormat::for_version(module.header.version),
                    &module.array_buffer,
                    uint_at(inst, 3) as usize,
                    count,
                    BufferKind::Value,
                );
                let numbers: Option<Vec<u64>> = values
                    .iter()
                    .map(|v: &LiteralValue| match v {
                        LiteralValue::Integer(i) => u64::try_from(*i).ok(),
                        LiteralValue::Number(n) if n.fract() == 0.0 && *n >= 0.0 => Some(*n as u64),
                        _ => None,
                    })
                    .collect();
                numbers
                    .filter(|n: &Vec<u64>| n.len() == count)
                    .map(MetroValue::Numbers)
            }
            "Mov" | "MovLong" => known.get(&reg_at(inst, 1)).cloned(),
            "Call4" | "Call" | "CallLong" => {
                let callee: u32 = reg_at(inst, 1);
                if matches!(known.get(&callee), Some(MetroValue::Define)) {
                    let args: Vec<u32> = if name == "Call4" {
                        (3..6).map(|i: usize| reg_at(inst, i)).collect()
                    } else {
                        call_window(frame_size, uint_at(inst, 2))
                            .map(|w: Vec<u32>| w.into_iter().skip(1).collect())
                            .unwrap_or_default()
                    };
                    if let Some(registration) = metro_registration(&known, &args) {
                        out.push(registration);
                    }
                }
                None
            }
            _ => None,
        };
        for written in roles(inst, frame_size).writes {
            known.remove(&written);
        }
        if let Some(value) = value {
            known.insert(dest, value);
        }
    }
    out
}

fn metro_registration(known: &BTreeMap<u32, MetroValue>, args: &[u32]) -> Option<MetroModule> {
    let (Some(MetroValue::Closure(factory)), Some(MetroValue::Number(id))) =
        (known.get(args.first()?), known.get(args.get(1)?))
    else {
        return None;
    };
    let dependencies: Vec<u64> = match args.get(2).and_then(|r: &u32| known.get(r)) {
        Some(MetroValue::Numbers(deps)) => deps.clone(),
        _ => return None,
    };
    let name: Option<String> = match args.get(3).and_then(|r: &u32| known.get(r)) {
        Some(MetroValue::Text(text)) => Some(text.clone()),
        _ => None,
    };
    Some(MetroModule {
        id: *id,
        factory: *factory,
        dependencies,
        name,
    })
}

pub(crate) fn is_closure_creation(name: &str) -> bool {
    matches!(
        name,
        "CreateClosure"
            | "CreateClosureLongIndex"
            | "CreateGeneratorClosure"
            | "CreateGeneratorClosureLongIndex"
            | "CreateAsyncClosure"
            | "CreateAsyncClosureLongIndex"
            | "CreateGenerator"
            | "CreateGeneratorLongIndex"
            | "CreateGeneratorObject"
            | "CreateGeneratorObjectLongIndex"
    )
}

pub(crate) fn class_creation(inst: &Instruction) -> Option<(u32, u32)> {
    let fid_at: usize = match &*inst.name {
        "CreateBaseClass" | "CreateBaseClassLongIndex" => 3,
        "CreateDerivedClass" | "CreateDerivedClassLongIndex" => 4,
        _ => return None,
    };
    match inst.operands.get(fid_at) {
        Some(OperandValue::FunctionId(fid)) => Some((reg_at(inst, 2), *fid)),
        _ => None,
    }
}

fn reg_at(inst: &Instruction, index: usize) -> u32 {
    match inst.operands.get(index) {
        Some(OperandValue::Reg(r)) => *r,
        _ => u32::MAX,
    }
}

fn uint_at(inst: &Instruction, index: usize) -> u64 {
    match inst.operands.get(index) {
        Some(OperandValue::UInt(u)) => *u,
        _ => 0,
    }
}

fn string_at(inst: &Instruction, index: usize) -> u32 {
    match inst.operands.get(index) {
        Some(OperandValue::StringId(s)) => *s,
        _ => u32::MAX,
    }
}

fn target_at(inst: &Instruction, index: usize) -> Option<usize> {
    match inst.operands.get(index) {
        Some(OperandValue::Target(t)) => Some(*t),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Roles {
    pub(crate) reads: Vec<u32>,
    pub(crate) writes: Vec<u32>,
}

#[must_use]
pub(crate) fn call_frame_size(module: &HermesModule, header: &SmallFunctionHeader) -> u32 {
    if super::modern::uses_modern_instructions(module.header.version) {
        header.frame_size.saturating_sub(1)
    } else {
        header.frame_size
    }
}

pub(crate) fn call_window(frame_size: u32, argc_with_this: u64) -> Option<Vec<u32>> {
    if argc_with_this == 0 || argc_with_this > MAX_CALL_ARGS {
        return None;
    }
    let this_reg: u32 = frame_size.checked_sub(CALL_FRAME_THIS_SLOT)?;
    let count: u32 = u32::try_from(argc_with_this).ok()?;
    if this_reg + 1 < count {
        return None;
    }
    Some((0..count).map(|offset: u32| this_reg - offset).collect())
}

fn all_regs(inst: &Instruction, skip_first: bool) -> Vec<u32> {
    inst.operands
        .iter()
        .enumerate()
        .filter_map(|(index, operand): (usize, &OperandValue)| match operand {
            OperandValue::Reg(r) if !(skip_first && index == 0) => Some(*r),
            _ => None,
        })
        .collect()
}

pub(crate) fn roles(inst: &Instruction, frame_size: u32) -> Roles {
    let name: &str = &inst.name;
    let op = |index: usize| -> u32 { reg_at(inst, index) };
    match name {
        "Call" | "CallLong" | "Construct" | "ConstructLong" | "ConstructWithNewTarget" => {
            let mut reads: Vec<u32> = vec![op(1)];
            if let Some(window) = call_window(frame_size, uint_at(inst, 2)) {
                reads.extend(window);
            }
            if name == "ConstructWithNewTarget" {
                reads.push(op(3));
            }
            Roles {
                reads,
                writes: vec![op(0)],
            }
        }
        "CreateBaseClass" | "CreateBaseClassLongIndex" => Roles {
            reads: vec![op(2)],
            writes: vec![op(0), op(1)],
        },
        "CreateDerivedClass" | "CreateDerivedClassLongIndex" => Roles {
            reads: vec![op(2), op(3)],
            writes: vec![op(0), op(1)],
        },
        "CallDirect" | "CallDirectLongIndex" | "CallBuiltin" | "CallBuiltinLong" => Roles {
            reads: call_window(frame_size, uint_at(inst, 2)).unwrap_or_default(),
            writes: vec![op(0)],
        },
        "IteratorBegin" => Roles {
            reads: vec![op(1)],
            writes: vec![op(0), op(1)],
        },
        "IteratorNext" => Roles {
            reads: vec![op(1), op(2)],
            writes: vec![op(0), op(1)],
        },
        "IteratorClose" | "Ret" | "Throw" | "ThrowIfUndefinedInst" => Roles {
            reads: vec![op(0)],
            writes: Vec::new(),
        },
        "GetPNameList" => Roles {
            reads: vec![op(1)],
            writes: vec![op(0), op(2), op(3)],
        },
        "GetNextPName" => Roles {
            reads: vec![op(1), op(2), op(3), op(4)],
            writes: vec![op(0), op(3)],
        },
        "ResumeGenerator" => Roles {
            reads: Vec::new(),
            writes: vec![op(0), op(1)],
        },
        "ReifyArguments" => Roles {
            reads: vec![op(0)],
            writes: vec![op(0)],
        },
        "SwitchImm" | "StringSwitchImm" => Roles {
            reads: vec![op(0)],
            writes: Vec::new(),
        },
        "CacheNewObject" => Roles {
            reads: vec![op(0), op(1)],
            writes: Vec::new(),
        },
        "CallWithNewTarget" | "CallWithNewTargetLong" => {
            let mut reads: Vec<u32> = vec![op(1), op(2)];
            if let Some(window) = call_window(frame_size, uint_at(inst, 3)) {
                reads.extend(window);
            }
            Roles {
                reads,
                writes: vec![op(0)],
            }
        }
        "AddOwnPrivateBySym"
        | "FastArrayStore"
        | "FastArrayPush"
        | "FastArrayAppend"
        | "ThrowIfThisInitialized" => Roles {
            reads: all_regs(inst, false),
            writes: Vec::new(),
        },
        _ if name.starts_with("Put")
            || name.starts_with("Store")
            || name.starts_with("Jmp")
            || (name.starts_with('J') && name.len() > 1) =>
        {
            Roles {
                reads: all_regs(inst, false),
                writes: Vec::new(),
            }
        }
        _ => {
            let writes_first: bool = matches!(inst.operands.first(), Some(OperandValue::Reg(_)));
            Roles {
                reads: all_regs(inst, writes_first),
                writes: if writes_first {
                    vec![op(0)]
                } else {
                    Vec::new()
                },
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RegSet {
    words: Vec<u64>,
}

impl RegSet {
    fn new(size: u32) -> Self {
        Self {
            words: vec![0; (size as usize).div_ceil(64)],
        }
    }

    fn insert(&mut self, reg: u32) -> bool {
        let (word, bit): (usize, u64) = ((reg / 64) as usize, 1u64 << (reg % 64));
        match self.words.get_mut(word) {
            Some(slot) => {
                let fresh: bool = *slot & bit == 0;
                *slot |= bit;
                fresh
            }
            None => false,
        }
    }

    fn contains(&self, reg: u32) -> bool {
        self.words
            .get((reg / 64) as usize)
            .is_some_and(|slot: &u64| slot & (1u64 << (reg % 64)) != 0)
    }

    fn union_with(&mut self, other: &Self) -> bool {
        let mut changed: bool = false;
        for (mine, theirs) in self.words.iter_mut().zip(&other.words) {
            let merged: u64 = *mine | *theirs;
            if merged != *mine {
                *mine = merged;
                changed = true;
            }
        }
        changed
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(index, word): (usize, &u64)| {
                (0..64u32).filter_map(move |bit: u32| {
                    (word & (1u64 << bit) != 0).then_some(index as u32 * 64 + bit)
                })
            })
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DefInfo {
    uses: u32,
    live_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MethodCall {
    object: u32,
}

#[derive(Debug, Default)]
struct Patterns {
    absorbed: BTreeSet<(usize, u32)>,
    skipped: BTreeSet<usize>,
    method_calls: BTreeMap<usize, MethodCall>,
    method_loads: BTreeMap<usize, u32>,
    constructs: BTreeSet<usize>,
    selects: BTreeSet<usize>,
    builders: BTreeSet<usize>,
    builder_last: BTreeMap<usize, usize>,
    plain_returns: BTreeSet<usize>,
    delegated_resumes: BTreeSet<usize>,
    delegate_marks: BTreeSet<usize>,
}

struct Analysis {
    env_in: Vec<BTreeMap<u32, EnvRef>>,
    roles: Vec<Roles>,
    first_handler: Vec<Option<usize>>,
    pinned: Vec<RegSet>,
    defs: BTreeMap<(usize, u32), DefInfo>,
    const_uses: BTreeMap<(usize, u32), usize>,
    needed: BTreeSet<(usize, u32)>,
    patterns: Patterns,
    env_regs: BTreeMap<u32, EnvRef>,
    env_sites: BTreeMap<usize, EnvRef>,
}

pub(crate) struct FunctionInput<'a> {
    pub(crate) module: &'a HermesModule,
    pub(crate) scope: &'a ModuleScope,
    pub(crate) index: usize,
    pub(crate) header: &'a SmallFunctionHeader,
    pub(crate) instructions: &'a [Instruction],
    pub(crate) cfg: &'a Cfg,
    pub(crate) exceptions: &'a [HermesExceptionEntry],
    pub(crate) code_base: usize,
    pub(crate) merged_generator: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Reconstructed,
    Declined,
}

#[derive(Debug, Clone)]
pub(crate) struct LiftedFunction {
    pub(crate) blocks: Vec<LiftedBlock>,
    pub(crate) var_regs: BTreeSet<u32>,
    pub(crate) env_slots: u32,
    pub(crate) helpers: BTreeSet<Helper>,
    pub(crate) outcomes: Vec<Outcome>,
    pub(crate) handler_of_block: Vec<Option<usize>>,
}

fn handler_blocks(input: &FunctionInput<'_>) -> (Vec<Vec<usize>>, Vec<Option<usize>>) {
    let blocks: &[BasicBlock] = &input.cfg.blocks;
    let mut all: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    let mut first: Vec<Option<usize>> = vec![None; blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for entry in input.exceptions {
            let (Ok(start), Ok(end), Ok(target)): (
                Result<usize, _>,
                Result<usize, _>,
                Result<usize, _>,
            ) = (
                usize::try_from(entry.start),
                usize::try_from(entry.end),
                usize::try_from(entry.target),
            ) else {
                continue;
            };
            if start <= block.start
                && block.start < end
                && let Some(handler) = input.cfg.offset_to_block.get(&target)
            {
                if first[index].is_none() {
                    first[index] = Some(*handler);
                }
                if !all[index].contains(handler) {
                    all[index].push(*handler);
                }
            }
        }
    }
    (all, first)
}

fn successors_with_handlers(cfg: &Cfg, handlers: &[Vec<usize>], block: usize) -> Vec<usize> {
    let mut out: Vec<usize> = cfg.blocks[block].successors.clone();
    for handler in &handlers[block] {
        if !out.contains(handler) {
            out.push(*handler);
        }
    }
    out
}

fn is_const_producer(name: &str) -> bool {
    matches!(
        name,
        "LoadConstUInt8"
            | "LoadConstInt"
            | "LoadConstDouble"
            | "LoadConstZero"
            | "LoadConstString"
            | "LoadConstStringLongIndex"
            | "LoadConstUndefined"
            | "LoadConstNull"
            | "LoadConstTrue"
            | "LoadConstFalse"
            | "LoadConstEmpty"
            | "LoadConstBigInt"
            | "LoadConstBigIntLongIndex"
            | "LoadParam"
            | "LoadParamLong"
            | "LoadThisNS"
            | "GetGlobalObject"
            | "GetNewTarget"
    )
}

fn const_key(inst: &Instruction, param_count: u32) -> Option<String> {
    let name: &str = &inst.name;
    match name {
        "CreateEnvironment" => return Some("env:own".to_owned()),
        "GetEnvironment" => return Some(format!("env:{}", uint_at(inst, 1))),
        _ => {}
    }
    if !is_const_producer(name) {
        return None;
    }
    Some(match name {
        "LoadConstUInt8" => format!("n{}", (uint_at(inst, 1) as f64).to_bits()),
        "LoadConstZero" => format!("n{}", 0f64.to_bits()),
        "LoadConstInt" => match inst.operands.get(1) {
            Some(OperandValue::Imm(i)) => format!("n{}", (*i as f64).to_bits()),
            _ => return None,
        },
        "LoadConstDouble" => match inst.operands.get(1) {
            Some(OperandValue::Float(f)) => format!("n{f}"),
            _ => return None,
        },
        "LoadConstString" | "LoadConstStringLongIndex" => format!("s{}", string_at(inst, 1)),
        "LoadConstBigInt" | "LoadConstBigIntLongIndex" => match inst.operands.get(1) {
            Some(OperandValue::BigIntId(b)) => format!("b{b}"),
            _ => return None,
        },
        "LoadParam" | "LoadParamLong" => {
            let index: u64 = uint_at(inst, 1);
            if index == 0 || index < u64::from(param_count) {
                format!("p{index}")
            } else {
                return None;
            }
        }
        "LoadThisNS" => "p0".to_owned(),
        other => other.to_owned(),
    })
}

type ConstResolution = (BTreeMap<(usize, u32), usize>, BTreeSet<(usize, u32)>);

fn reaching_constants(
    instructions: &[Instruction],
    roles: &[Roles],
    cfg: &Cfg,
    handlers: &[Vec<usize>],
    patterns: &Patterns,
    param_count: u32,
    env_sites: &BTreeMap<usize, EnvRef>,
) -> ConstResolution {
    let mut defs: Vec<(usize, u32)> = Vec::new();
    let mut def_index: BTreeMap<(usize, u32), usize> = BTreeMap::new();
    let mut read_regs: BTreeSet<u32> = BTreeSet::new();
    for (position, role) in roles.iter().enumerate() {
        for read in &role.reads {
            read_regs.insert(*read);
        }
        for write in &role.writes {
            def_index.insert((position, *write), defs.len());
            defs.push((position, *write));
        }
    }
    let real_defs: usize = defs.len();
    let mut defs_of: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (id, (_, reg)) in defs.iter().enumerate() {
        defs_of.entry(*reg).or_default().push(id);
    }
    let mut entry_defs: Vec<usize> = Vec::with_capacity(read_regs.len());
    for reg in &read_regs {
        let id: usize = real_defs + entry_defs.len();
        defs_of.entry(*reg).or_default().push(id);
        entry_defs.push(id);
    }
    let total: usize = real_defs + entry_defs.len();
    let count: usize = cfg.blocks.len();
    if count == 0 || total.saturating_mul(count) > MAX_REACHING_BITS {
        return (BTreeMap::new(), defs.iter().copied().collect());
    }
    let bound: u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let mut gen_sets: Vec<RegSet> = vec![RegSet::new(bound); count];
    let mut kill_sets: Vec<RegSet> = vec![RegSet::new(bound); count];
    let mut block_defs: Vec<RegSet> = vec![RegSet::new(bound); count];
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut last: BTreeMap<u32, usize> = BTreeMap::new();
        for (offset, role) in roles[block.instr_range.0..block.instr_range.1]
            .iter()
            .enumerate()
        {
            let position: usize = block.instr_range.0 + offset;
            for write in &role.writes {
                if let Some(id) = def_index.get(&(position, *write)) {
                    last.insert(*write, *id);
                    block_defs[block_index].insert(*id as u32);
                    for other in defs_of.get(write).map_or(&[][..], Vec::as_slice) {
                        kill_sets[block_index].insert(*other as u32);
                    }
                }
            }
        }
        for id in last.values() {
            gen_sets[block_index].insert(*id as u32);
        }
    }
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut exception_preds: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        for succ in &block.successors {
            if *succ < count {
                preds[*succ].push(block_index);
            }
        }
        for handler in &handlers[block_index] {
            if *handler < count {
                exception_preds[*handler].push(block_index);
            }
        }
    }
    let mut entry_set: RegSet = RegSet::new(bound);
    for id in &entry_defs {
        entry_set.insert(*id as u32);
    }
    let mut ins: Vec<RegSet> = vec![RegSet::new(bound); count];
    let mut outs: Vec<RegSet> = vec![RegSet::new(bound); count];
    let mut changed: bool = true;
    let mut rounds: usize = 0;
    while changed && rounds < 10_000 {
        changed = false;
        rounds += 1;
        for block_index in 0..count {
            let mut inn: RegSet = if block_index == 0 {
                entry_set.clone()
            } else {
                RegSet::new(bound)
            };
            for pred in &preds[block_index] {
                inn.union_with(&outs[*pred]);
            }
            for pred in &exception_preds[block_index] {
                inn.union_with(&ins[*pred]);
                inn.union_with(&block_defs[*pred]);
            }
            let mut out: RegSet = gen_sets[block_index].clone();
            for (word, (incoming, killed)) in out
                .words
                .iter_mut()
                .zip(inn.words.iter().zip(&kill_sets[block_index].words))
            {
                *word |= incoming & !killed;
            }
            if inn.words != ins[block_index].words {
                ins[block_index] = inn;
                changed = true;
            }
            if out.words != outs[block_index].words {
                outs[block_index] = out;
                changed = true;
            }
        }
    }
    let keys: Vec<Option<String>> = defs
        .iter()
        .map(
            |(position, _): &(usize, u32)| match env_sites.get(position) {
                Some(env) => Some(format!("env:{env:?}")),
                None => const_key(&instructions[*position], param_count),
            },
        )
        .collect();
    let mut const_uses: BTreeMap<(usize, u32), usize> = BTreeMap::new();
    let mut needed: BTreeSet<(usize, u32)> = BTreeSet::new();
    for (block_index, block) in cfg.blocks.iter().enumerate() {
        let mut current: BTreeMap<u32, usize> = BTreeMap::new();
        for (offset, role) in roles[block.instr_range.0..block.instr_range.1]
            .iter()
            .enumerate()
        {
            let position: usize = block.instr_range.0 + offset;
            for read in &role.reads {
                let reaching: Vec<usize> = match current.get(read) {
                    Some(id) => vec![*id],
                    None => defs_of
                        .get(read)
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .copied()
                        .filter(|id: &usize| ins[block_index].contains(*id as u32))
                        .collect(),
                };
                let key: Option<&String> = reaching
                    .first()
                    .and_then(|id: &usize| keys.get(*id))
                    .and_then(Option::as_ref);
                let resolved: bool = key.is_some()
                    && reaching.iter().all(|id: &usize| {
                        *id < real_defs && keys.get(*id).and_then(Option::as_ref) == key
                    });
                if resolved {
                    if let Some((def_position, _)) =
                        reaching.first().and_then(|id: &usize| defs.get(*id))
                    {
                        const_uses.insert((position, *read), *def_position);
                    }
                } else if !patterns.absorbed.contains(&(position, *read)) {
                    for id in &reaching {
                        if let Some(def) = defs.get(*id) {
                            needed.insert(*def);
                        }
                    }
                }
            }
            for write in &role.writes {
                if let Some(id) = def_index.get(&(position, *write)) {
                    current.insert(*write, *id);
                }
            }
        }
    }
    (const_uses, needed)
}

fn is_property_load(name: &str) -> bool {
    matches!(
        name,
        "GetByIdShort" | "GetById" | "GetByIdLong" | "TryGetById" | "TryGetByIdLong" | "GetByVal"
    )
}

fn is_builder_put(name: &str) -> bool {
    matches!(
        name,
        "PutOwnByIndex"
            | "PutOwnByIndexL"
            | "PutNewOwnById"
            | "PutNewOwnByIdShort"
            | "PutNewOwnByIdLong"
            | "PutOwnByVal"
    )
}

fn is_fresh_allocation(name: &str) -> bool {
    matches!(
        name,
        "NewArray"
            | "NewArrayWithBuffer"
            | "NewArrayWithBufferLong"
            | "NewObject"
            | "NewObjectWithBuffer"
            | "NewObjectWithBufferLong"
    )
}

fn last_write_before(roles: &[Roles], from: usize, to: usize, reg: u32) -> Option<usize> {
    (from..to)
        .rev()
        .find(|index: &usize| roles[*index].writes.contains(&reg))
}

fn written_between(roles: &[Roles], from: usize, to: usize, reg: u32) -> bool {
    (from..to).any(|index: usize| roles[index].writes.contains(&reg))
}

fn read_count_between(roles: &[Roles], from: usize, to: usize, reg: u32) -> usize {
    (from..to)
        .map(|index: usize| {
            roles[index]
                .reads
                .iter()
                .filter(|r: &&u32| **r == reg)
                .count()
        })
        .sum()
}

fn this_register(inst: &Instruction, frame_size: u32) -> Option<u32> {
    match &*inst.name {
        "Call1" | "Call2" | "Call3" | "Call4" => Some(reg_at(inst, 2)),
        "Call" | "CallLong" | "Construct" | "ConstructLong" | "ConstructWithNewTarget" => {
            call_window(frame_size, uint_at(inst, 2)).and_then(|w: Vec<u32>| w.first().copied())
        }
        _ => None,
    }
}

fn find_patterns(
    instructions: &[Instruction],
    roles: &[Roles],
    cfg: &Cfg,
    handlers: &[Vec<usize>],
    frame_size: u32,
    version: u32,
) -> Patterns {
    let mut patterns: Patterns = Patterns::default();
    for block in &cfg.blocks {
        let (start, end): (usize, usize) = block.instr_range;
        for j in start..end {
            let inst: &Instruction = &instructions[j];
            let name: &str = &inst.name;
            if matches!(
                name,
                "Call1" | "Call2" | "Call3" | "Call4" | "Call" | "CallLong"
            ) {
                find_method_call(instructions, roles, start, j, frame_size, &mut patterns);
            }
            if matches!(
                name,
                "Construct" | "ConstructLong" | "ConstructWithNewTarget"
            ) {
                find_construct(
                    instructions,
                    roles,
                    start,
                    end,
                    j,
                    frame_size,
                    &mut patterns,
                );
            }
            if name == "ResumeGenerator" && resume_returns_plainly(instructions, cfg, j) {
                patterns.plain_returns.insert(j);
            }
            if matches!(name, "SaveGenerator" | "SaveGeneratorLong")
                && let Some(mark) = (start..j).rev().find(|k: &usize| {
                    matches!(&*instructions[*k].name, "CallBuiltin" | "CallBuiltinLong")
                        && uint_at(&instructions[*k], 2) == 1
                        && private_builtin(&super::builtins::builtin_name(
                            version,
                            uint_at(&instructions[*k], 1),
                        )) == Some("generatorSetDelegated")
                })
                && let Some(target) = target_at(inst, 0)
                && let Ok(resume) = instructions
                    .binary_search_by_key(&target, |candidate: &Instruction| candidate.offset)
            {
                patterns.delegate_marks.insert(mark);
                patterns.delegated_resumes.insert(resume);
            }
            if is_builder_put(name) {
                let object: u32 = reg_at(inst, 0);
                if let Some(def) = last_write_before(roles, start, j, object)
                    && is_fresh_allocation(&instructions[def].name)
                {
                    patterns.builders.insert(j);
                    patterns.absorbed.insert((j, object));
                }
            }
            if is_fresh_allocation(name) {
                let object: u32 = reg_at(inst, 0);
                let mut last: Option<usize> = None;
                for k in j + 1..end {
                    let later: &Instruction = &instructions[k];
                    if is_builder_put(&later.name) && reg_at(later, 0) == object {
                        last = Some(k);
                        if roles[k]
                            .reads
                            .iter()
                            .filter(|r: &&u32| **r == object)
                            .count()
                            > 1
                        {
                            break;
                        }
                        continue;
                    }
                    if roles[k].reads.contains(&object) || roles[k].writes.contains(&object) {
                        break;
                    }
                }
                if let Some(last) = last {
                    patterns.builder_last.insert(j, last);
                }
            }
        }
    }
    find_shared_constructs(
        instructions,
        roles,
        cfg,
        handlers,
        frame_size,
        &mut patterns,
    );
    patterns
}

const ENTRY_DEF: usize = usize::MAX;

struct ReachCache<'a> {
    roles: &'a [Roles],
    cfg: &'a Cfg,
    handlers: &'a [Vec<usize>],
    reads: BTreeMap<u32, BTreeMap<usize, Vec<usize>>>,
}

impl ReachCache<'_> {
    fn of(&mut self, reg: u32) -> &BTreeMap<usize, Vec<usize>> {
        let (roles, cfg, handlers): (&[Roles], &Cfg, &[Vec<usize>]) =
            (self.roles, self.cfg, self.handlers);
        self.reads
            .entry(reg)
            .or_insert_with(|| reaching_definitions(roles, cfg, handlers, reg))
    }

    fn at(&mut self, position: usize, reg: u32) -> Vec<usize> {
        self.of(reg).get(&position).cloned().unwrap_or_default()
    }

    fn uses_of(&mut self, def: usize, reg: u32) -> Vec<usize> {
        self.of(reg)
            .iter()
            .filter(|(_, defs): &(&usize, &Vec<usize>)| defs.contains(&def))
            .map(|(position, _): (&usize, &Vec<usize>)| *position)
            .collect()
    }
}

fn reaching_definitions(
    roles: &[Roles],
    cfg: &Cfg,
    handlers: &[Vec<usize>],
    reg: u32,
) -> BTreeMap<usize, Vec<usize>> {
    let count: usize = cfg.blocks.len();
    let mut block_in: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); count];
    if let Some(entry) = block_in.first_mut() {
        entry.insert(ENTRY_DEF);
    }
    let mut changed: bool = true;
    let mut rounds: usize = 0;
    while changed && rounds < 10_000 {
        changed = false;
        rounds += 1;
        for (index, block) in cfg.blocks.iter().enumerate() {
            let (start, end): (usize, usize) = block.instr_range;
            let mut current: BTreeSet<usize> = block_in[index].clone();
            let mut anywhere: BTreeSet<usize> = current.clone();
            for (offset, role) in roles[start..end].iter().enumerate() {
                if role.writes.contains(&reg) {
                    current.clear();
                    current.insert(start + offset);
                    anywhere.insert(start + offset);
                }
            }
            for succ in &block.successors {
                if let Some(target) = block_in.get_mut(*succ) {
                    let before: usize = target.len();
                    target.extend(current.iter().copied());
                    changed |= target.len() != before;
                }
            }
            for handler in handlers.get(index).map_or(&[][..], Vec::as_slice) {
                if let Some(target) = block_in.get_mut(*handler) {
                    let before: usize = target.len();
                    target.extend(anywhere.iter().copied());
                    changed |= target.len() != before;
                }
            }
        }
    }
    let mut out: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, block) in cfg.blocks.iter().enumerate() {
        let (start, end): (usize, usize) = block.instr_range;
        let mut current: BTreeSet<usize> = block_in[index].clone();
        for (offset, role) in roles[start..end].iter().enumerate() {
            if role.reads.contains(&reg) {
                out.insert(start + offset, current.iter().copied().collect());
            }
            if role.writes.contains(&reg) {
                current.clear();
                current.insert(start + offset);
            }
        }
    }
    out
}

fn reads_of(role: &Roles, reg: u32) -> usize {
    role.reads.iter().filter(|r: &&u32| **r == reg).count()
}

fn find_shared_constructs(
    instructions: &[Instruction],
    roles: &[Roles],
    cfg: &Cfg,
    handlers: &[Vec<usize>],
    frame_size: u32,
    patterns: &mut Patterns,
) {
    let mut reach: ReachCache<'_> = ReachCache {
        roles,
        cfg,
        handlers,
        reads: BTreeMap::new(),
    };
    for (create, inst) in instructions.iter().enumerate() {
        if inst.name != "CreateThis" || patterns.skipped.contains(&create) {
            continue;
        }
        let this_value: u32 = reg_at(inst, 0);
        let proto: u32 = reg_at(inst, 1);
        let callee: u32 = reg_at(inst, 2);
        let callee_defs: Vec<usize> = reach.at(create, callee);
        if this_value == callee || callee_defs.len() != 1 || callee_defs.contains(&ENTRY_DEF) {
            continue;
        }
        let mut constructs: Vec<(usize, u32)> = Vec::new();
        let mut selects: Vec<usize> = Vec::new();
        let mut movs: Vec<usize> = Vec::new();
        let mut sound: bool = true;
        for site in reach.uses_of(create, this_value) {
            let reader: &Instruction = &instructions[site];
            let only_create: bool =
                reach.at(site, this_value) == [create] && reads_of(&roles[site], this_value) == 1;
            match &*reader.name {
                "Mov" | "MovLong" if only_create && reg_at(reader, 1) == this_value => {
                    movs.push(site);
                }
                "SelectObject"
                    if only_create
                        && reg_at(reader, 1) == this_value
                        && reg_at(reader, 2) != this_value =>
                {
                    selects.push(site);
                }
                "Construct" | "ConstructLong" | "ConstructWithNewTarget"
                    if only_create && this_register(reader, frame_size) == Some(this_value) =>
                {
                    constructs.push((site, this_value));
                }
                _ => sound = false,
            }
        }
        for mov in &movs {
            let slot: u32 = reg_at(&instructions[*mov], 0);
            match reach.uses_of(*mov, slot).as_slice() {
                [j] if matches!(
                    &*instructions[*j].name,
                    "Construct" | "ConstructLong" | "ConstructWithNewTarget"
                ) && slot != this_value
                    && this_register(&instructions[*j], frame_size) == Some(slot)
                    && reads_of(&roles[*j], slot) == 1
                    && reach.at(*j, slot) == [*mov] =>
                {
                    constructs.push((*j, slot));
                }
                _ => sound = false,
            }
        }
        if !sound || constructs.is_empty() {
            continue;
        }
        let callee_matches: bool = constructs.iter().all(|(j, _): &(usize, u32)| {
            reg_at(&instructions[*j], 1) == callee && reach.at(*j, callee) == callee_defs
        });
        let selects_pair: bool = selects.iter().all(|select: &usize| {
            let result: u32 = reg_at(&instructions[*select], 2);
            match reach.at(*select, result).as_slice() {
                [j] => {
                    constructs
                        .iter()
                        .any(|(construct, _): &(usize, u32)| construct == j)
                        && reg_at(&instructions[*j], 0) == result
                        && reach.uses_of(*j, result) == [*select]
                }
                _ => false,
            }
        });
        if !callee_matches || !selects_pair {
            continue;
        }
        patterns.skipped.insert(create);
        patterns.absorbed.insert((create, callee));
        patterns.absorbed.insert((create, proto));
        for mov in &movs {
            patterns.skipped.insert(*mov);
            patterns.absorbed.insert((*mov, this_value));
        }
        for (j, slot) in &constructs {
            patterns.constructs.insert(*j);
            patterns.absorbed.insert((*j, *slot));
        }
        for select in &selects {
            patterns.selects.insert(*select);
            patterns.absorbed.insert((*select, this_value));
        }
        if let [proto_def] = reach.at(create, proto).as_slice()
            && *proto_def != ENTRY_DEF
            && matches!(
                &*instructions[*proto_def].name,
                "GetByIdShort" | "GetById" | "GetByIdLong"
            )
            && reg_at(&instructions[*proto_def], 1) == callee
            && reach.at(*proto_def, callee) == callee_defs
            && reach.uses_of(*proto_def, proto) == [create]
        {
            patterns.skipped.insert(*proto_def);
            patterns.absorbed.insert((*proto_def, callee));
        }
    }
}

pub(crate) fn resume_returns_plainly(
    instructions: &[Instruction],
    cfg: &Cfg,
    resume: usize,
) -> bool {
    resume_return_path(instructions, cfg, resume).is_some()
}

pub(crate) fn resume_return_offset(instructions: &[Instruction], resume: usize) -> Option<usize> {
    let mut flags: BTreeSet<u32> = BTreeSet::from([reg_at(instructions.get(resume)?, 1)]);
    let mut cursor: usize = resume + 1;
    loop {
        let inst: &Instruction = instructions.get(cursor)?;
        let name: &str = &inst.name;
        if flags.contains(&reg_at(inst, 1)) {
            match name {
                "JmpTrue" | "JmpTrueLong" => return target_at(inst, 0),
                "JmpFalse" | "JmpFalseLong" => return Some(inst.offset + inst.size),
                _ => {}
            }
        }
        if matches!(name, "Mov" | "MovLong") {
            if flags.contains(&reg_at(inst, 1)) {
                flags.insert(reg_at(inst, 0));
            } else {
                flags.remove(&reg_at(inst, 0));
            }
            if flags.is_empty() {
                return None;
            }
            cursor += 1;
            continue;
        }
        let touches_flag: bool = inst.operands.iter().any(|operand: &OperandValue| {
            matches!(operand, OperandValue::Reg(reg) if flags.contains(reg))
        });
        if touches_flag || name.starts_with('J') || matches!(name, "Ret" | "Throw") {
            return None;
        }
        cursor += 1;
    }
}

pub(crate) fn resume_return_path(
    instructions: &[Instruction],
    cfg: &Cfg,
    resume: usize,
) -> Option<usize> {
    let value: u32 = reg_at(instructions.get(resume)?, 0);
    let return_offset: usize = resume_return_offset(instructions, resume)?;
    let first: &BasicBlock = cfg
        .offset_to_block
        .get(&return_offset)
        .and_then(|b: &usize| cfg.blocks.get(*b))?;
    let start: usize = first.instr_range.0;
    let end: usize = (start + 2).min(instructions.len());
    let body: &[Instruction] = match instructions.get(start) {
        Some(inst) if inst.name == "CompleteGenerator" => &instructions[start..end],
        Some(_) => &instructions[start..=start],
        None => return None,
    };
    let plain: bool = match body {
        [complete, ret] => {
            complete.name == "CompleteGenerator" && ret.name == "Ret" && reg_at(ret, 0) == value
        }
        [ret] => ret.name == "Ret" && reg_at(ret, 0) == value,
        _ => false,
    };
    plain.then_some(return_offset)
}

fn find_method_call(
    instructions: &[Instruction],
    roles: &[Roles],
    start: usize,
    j: usize,
    frame_size: u32,
    patterns: &mut Patterns,
) {
    let inst: &Instruction = &instructions[j];
    let callee: u32 = reg_at(inst, 1);
    let Some(this_reg) = this_register(inst, frame_size) else {
        return;
    };
    let Some(load) = last_write_before(roles, start, j, callee) else {
        return;
    };
    let load_inst: &Instruction = &instructions[load];
    if !is_property_load(&load_inst.name) || load_inst.name.starts_with("Try") {
        return;
    }
    if read_count_between(roles, load + 1, j, callee) != 0 {
        return;
    }
    let object: u32 = reg_at(load_inst, 1);
    if object == callee && this_reg != callee {
        return;
    }
    if written_between(roles, load + 1, j, object) {
        return;
    }
    if this_reg == object {
        if object == callee {
            return;
        }
        patterns.absorbed.insert((j, this_reg));
        patterns.method_calls.insert(j, MethodCall { object });
        patterns.method_loads.insert(load, object);
        return;
    }
    let Some(mov) = last_write_before(roles, start, j, this_reg) else {
        return;
    };
    let mov_inst: &Instruction = &instructions[mov];
    if !matches!(&*mov_inst.name, "Mov" | "MovLong") || reg_at(mov_inst, 1) != object {
        return;
    }
    let low: usize = mov.min(load);
    if written_between(roles, low + 1, j, object) || object == callee {
        return;
    }
    if read_count_between(roles, mov + 1, j, this_reg) != 0 {
        return;
    }
    patterns.absorbed.insert((j, this_reg));
    patterns.absorbed.insert((mov, object));
    patterns.skipped.insert(mov);
    patterns.method_calls.insert(j, MethodCall { object });
    patterns.method_loads.insert(load, object);
}

fn find_construct(
    instructions: &[Instruction],
    roles: &[Roles],
    start: usize,
    end: usize,
    j: usize,
    frame_size: u32,
    patterns: &mut Patterns,
) {
    let inst: &Instruction = &instructions[j];
    let callee: u32 = reg_at(inst, 1);
    let result: u32 = reg_at(inst, 0);
    let Some(this_slot) = this_register(inst, frame_size) else {
        return;
    };
    let Some(slot_def) = last_write_before(roles, start, j, this_slot) else {
        return;
    };
    let (create, this_value, mov): (usize, u32, Option<usize>) = match &*instructions[slot_def].name
    {
        "CreateThis" => (slot_def, this_slot, None),
        "Mov" | "MovLong" => {
            let source: u32 = reg_at(&instructions[slot_def], 1);
            let Some(create) = last_write_before(roles, start, slot_def, source) else {
                return;
            };
            if instructions[create].name != "CreateThis" {
                return;
            }
            (create, source, Some(slot_def))
        }
        _ => return,
    };
    let create_inst: &Instruction = &instructions[create];
    if reg_at(create_inst, 2) != callee || written_between(roles, create, j, callee) {
        return;
    }
    let Some(select) = (j + 1..end).find(|index: &usize| {
        instructions[*index].name == "SelectObject"
            && reg_at(&instructions[*index], 1) == this_value
            && reg_at(&instructions[*index], 2) == result
    }) else {
        return;
    };
    if written_between(roles, create + 1, select, this_value)
        || written_between(roles, j + 1, select, result)
        || read_count_between(roles, j + 1, select, result) != 0
    {
        return;
    }
    let expected_this_reads: usize = 1 + usize::from(mov.is_some()) + usize::from(mov.is_none());
    if read_count_between(roles, create + 1, select + 1, this_value) != expected_this_reads {
        return;
    }
    if let Some(mov) = mov {
        if read_count_between(roles, mov + 1, j, this_slot) != 0 {
            return;
        }
        patterns.skipped.insert(mov);
        patterns.absorbed.insert((mov, this_value));
    }
    patterns.absorbed.insert((j, this_slot));
    patterns.absorbed.insert((select, this_value));
    patterns.absorbed.insert((create, callee));
    let proto: u32 = reg_at(create_inst, 1);
    patterns.absorbed.insert((create, proto));
    patterns.skipped.insert(create);
    if let Some(proto_def) = last_write_before(roles, start, create, proto) {
        let proto_inst: &Instruction = &instructions[proto_def];
        if matches!(
            &*proto_inst.name,
            "GetByIdShort" | "GetById" | "GetByIdLong"
        ) && reg_at(proto_inst, 1) == callee
            && !written_between(roles, proto_def + 1, create, callee)
            && {
                let next_write: usize = (proto_def + 1..end)
                    .find(|index: &usize| roles[*index].writes.contains(&proto))
                    .unwrap_or(end);
                read_count_between(roles, proto_def + 1, (next_write + 1).min(end), proto) == 1
            }
        {
            patterns.skipped.insert(proto_def);
            patterns.absorbed.insert((proto_def, callee));
        }
    }
    patterns.constructs.insert(j);
    patterns.selects.insert(select);
}

fn analyze(input: &FunctionInput<'_>, register_count: u32) -> Analysis {
    let instructions: &[Instruction] = input.instructions;
    let cfg: &Cfg = input.cfg;
    let frame_size: u32 = input.header.frame_size;
    let roles: Vec<Roles> = instructions
        .iter()
        .map(|inst: &Instruction| roles(inst, frame_size))
        .collect();
    let (handlers, first_handler): (Vec<Vec<usize>>, Vec<Option<usize>>) = handler_blocks(input);
    let patterns: Patterns = find_patterns(
        instructions,
        &roles,
        cfg,
        &handlers,
        frame_size,
        input.module.header.version,
    );

    let count: usize = cfg.blocks.len();
    let mut gen_sets: Vec<RegSet> = vec![RegSet::new(register_count); count];
    let mut kill_sets: Vec<RegSet> = vec![RegSet::new(register_count); count];
    for (index, block) in cfg.blocks.iter().enumerate() {
        for (offset, role) in roles[block.instr_range.0..block.instr_range.1]
            .iter()
            .enumerate()
        {
            let position: usize = block.instr_range.0 + offset;
            for read in &role.reads {
                if !kill_sets[index].contains(*read) {
                    gen_sets[index].insert(*read);
                }
            }
            for write in &roles[position].writes {
                kill_sets[index].insert(*write);
            }
        }
    }
    let mut live_in: Vec<RegSet> = gen_sets.clone();
    let mut live_out: Vec<RegSet> = vec![RegSet::new(register_count); count];
    let mut changed: bool = true;
    let mut rounds: usize = 0;
    while changed && rounds < 10_000 {
        changed = false;
        rounds += 1;
        for index in (0..count).rev() {
            let mut out: RegSet = RegSet::new(register_count);
            for succ in successors_with_handlers(cfg, &handlers, index) {
                if let Some(set) = live_in.get(succ) {
                    out.union_with(set);
                }
            }
            let mut inn: RegSet = gen_sets[index].clone();
            for reg in out.iter() {
                if !kill_sets[index].contains(reg) {
                    inn.insert(reg);
                }
            }
            if live_in[index].union_with(&inn) {
                changed = true;
            }
            live_out[index] = out;
        }
    }
    let mut pinned: Vec<RegSet> = vec![RegSet::new(register_count); count];
    for (index, handler_list) in handlers.iter().enumerate() {
        for handler in handler_list {
            let handler_live: RegSet = live_in[*handler].clone();
            pinned[index].union_with(&handler_live);
        }
    }

    let mut defs: BTreeMap<(usize, u32), DefInfo> = BTreeMap::new();
    for (index, block) in cfg.blocks.iter().enumerate() {
        let mut current: BTreeMap<u32, usize> = BTreeMap::new();
        for (offset, role) in roles[block.instr_range.0..block.instr_range.1]
            .iter()
            .enumerate()
        {
            let position: usize = block.instr_range.0 + offset;
            for read in &role.reads {
                if patterns.absorbed.contains(&(position, *read)) {
                    continue;
                }
                if let Some(def) = current.get(read)
                    && let Some(info) = defs.get_mut(&(*def, *read))
                {
                    info.uses = info.uses.saturating_add(1);
                }
            }
            for write in &roles[position].writes {
                current.insert(*write, position);
                defs.insert((position, *write), DefInfo::default());
            }
        }
        for (reg, def) in current {
            if live_out[index].contains(reg)
                && let Some(info) = defs.get_mut(&(def, reg))
            {
                info.live_out = true;
            }
        }
    }

    let mut env_votes: BTreeMap<u32, Option<EnvRef>> = BTreeMap::new();
    let chain: Option<&Vec<u32>> = input
        .scope
        .chain(u32::try_from(input.index).unwrap_or(u32::MAX));
    let own: u32 = u32::try_from(input.index).unwrap_or(u32::MAX);
    for (position, inst) in instructions.iter().enumerate() {
        let produced: Option<EnvRef> = match &*inst.name {
            "CreateEnvironment" => Some(EnvRef::Owned(own)),
            "GetEnvironment" => {
                let level: u32 = u32::try_from(uint_at(inst, 1)).unwrap_or(u32::MAX);
                Some(
                    chain
                        .and_then(|c: &Vec<u32>| c.get(level as usize).copied())
                        .map_or(EnvRef::Unknown(level), EnvRef::Owned),
                )
            }
            _ => None,
        };
        for write in &roles[position].writes {
            let vote: Option<EnvRef> = if *write == reg_at(inst, 0) {
                produced
            } else {
                None
            };
            match env_votes.get(write) {
                None => {
                    env_votes.insert(*write, vote);
                }
                Some(existing) if *existing != vote => {
                    env_votes.insert(*write, None);
                }
                Some(_) => {}
            }
        }
    }
    let env_regs: BTreeMap<u32, EnvRef> = env_votes
        .into_iter()
        .filter_map(|(reg, vote): (u32, Option<EnvRef>)| vote.map(|env: EnvRef| (reg, env)))
        .collect();
    let env_sites: BTreeMap<usize, EnvRef> = instructions
        .iter()
        .enumerate()
        .filter_map(|(position, inst): (usize, &Instruction)| {
            let env: EnvRef = match &*inst.name {
                "CreateEnvironment" => EnvRef::Owned(own),
                "GetEnvironment" => {
                    let level: u32 = u32::try_from(uint_at(inst, 1)).unwrap_or(u32::MAX);
                    chain
                        .and_then(|c: &Vec<u32>| c.get(level as usize).copied())
                        .map_or(EnvRef::Unknown(level), EnvRef::Owned)
                }
                "LoadFromEnvironment" | "LoadFromEnvironmentL" => {
                    match env_regs.get(&reg_at(inst, 1)) {
                        Some(EnvRef::Owned(owner)) => {
                            EnvRef::Owned(input.scope.env_held_in(*owner, uint_at(inst, 2))?)
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            };
            Some((position, env))
        })
        .collect();
    let (const_uses, needed): ConstResolution = reaching_constants(
        instructions,
        &roles,
        cfg,
        &handlers,
        &patterns,
        input.header.param_count,
        &env_sites,
    );

    let env_in: Vec<EnvState> = EnvFlow {
        input,
        roles: &roles,
        chain,
        own,
    }
    .entry_states(&handlers);

    Analysis {
        env_in,
        roles,
        first_handler,
        pinned,
        defs,
        const_uses,
        needed,
        patterns,
        env_regs,
        env_sites,
    }
}

type EnvState = BTreeMap<u32, EnvRef>;

struct EnvFlow<'a> {
    input: &'a FunctionInput<'a>,
    roles: &'a [Roles],
    chain: Option<&'a Vec<u32>>,
    own: u32,
}

impl EnvFlow<'_> {
    fn produced(&self, state: &EnvState, inst: &Instruction) -> Option<EnvRef> {
        match &*inst.name {
            "CreateEnvironment" => Some(EnvRef::Owned(self.own)),
            "GetEnvironment" => {
                let level: u32 = u32::try_from(uint_at(inst, 1)).unwrap_or(u32::MAX);
                Some(
                    self.chain
                        .and_then(|c: &Vec<u32>| c.get(level as usize).copied())
                        .map_or(EnvRef::Unknown(level), EnvRef::Owned),
                )
            }
            "Mov" | "MovLong" => state.get(&reg_at(inst, 1)).copied(),
            "LoadFromEnvironment" | "LoadFromEnvironmentL" => match state.get(&reg_at(inst, 1)) {
                Some(EnvRef::Owned(owner)) => self
                    .input
                    .scope
                    .env_held_in(*owner, uint_at(inst, 2))
                    .map(EnvRef::Owned),
                _ => None,
            },
            _ => None,
        }
    }

    fn step(&self, state: &mut EnvState, position: usize) {
        let inst: &Instruction = &self.input.instructions[position];
        let produced: Option<EnvRef> = self.produced(state, inst);
        for written in &self.roles[position].writes {
            state.remove(written);
        }
        if let Some(env) = produced {
            state.insert(reg_at(inst, 0), env);
        }
    }

    fn meet(into: &mut Option<EnvState>, incoming: &EnvState) -> bool {
        match into {
            None => {
                *into = Some(incoming.clone());
                true
            }
            Some(current) => {
                let before: usize = current.len();
                current.retain(|reg: &u32, env: &mut EnvRef| incoming.get(reg) == Some(env));
                current.len() != before
            }
        }
    }

    fn entry_states(&self, handlers: &[Vec<usize>]) -> Vec<EnvState> {
        let cfg: &Cfg = self.input.cfg;
        let count: usize = cfg.blocks.len();
        let mut ins: Vec<Option<EnvState>> = vec![None; count];
        if let Some(first) = ins.first_mut() {
            *first = Some(EnvState::new());
        }
        let mut changed: bool = true;
        let mut rounds: usize = 0;
        while changed && rounds < 10_000 {
            changed = false;
            rounds += 1;
            for (index, block) in cfg.blocks.iter().enumerate() {
                let Some(mut state) = ins[index].clone() else {
                    continue;
                };
                let mut seen: Vec<EnvState> = vec![state.clone()];
                for position in block.instr_range.0..block.instr_range.1 {
                    self.step(&mut state, position);
                    seen.push(state.clone());
                }
                for succ in &block.successors {
                    if let Some(slot) = ins.get_mut(*succ) {
                        changed |= Self::meet(slot, &state);
                    }
                }
                for handler in handlers.get(index).map_or(&[][..], Vec::as_slice) {
                    if let Some(slot) = ins.get_mut(*handler) {
                        for observed in &seen {
                            changed |= Self::meet(slot, observed);
                        }
                    }
                }
            }
        }
        ins.into_iter().map(Option::unwrap_or_default).collect()
    }
}

fn register_bound(input: &FunctionInput<'_>) -> Option<u32> {
    let mut highest: u32 = input.header.frame_size;
    for inst in input.instructions {
        for operand in &inst.operands {
            if let OperandValue::Reg(r) = operand {
                highest = highest.max(r.saturating_add(1));
            }
        }
    }
    (highest <= MAX_TRACKED_REGISTERS).then_some(highest)
}

struct Lifter<'a> {
    input: &'a FunctionInput<'a>,
    analysis: Analysis,
    regs: BTreeMap<u32, RegState>,
    envs: BTreeMap<u32, EnvRef>,
    next_effect: u64,
    out: Vec<BlockStmt>,
    block: usize,
    position: usize,
    deferred: BTreeMap<u32, usize>,
    pending_yield: Option<usize>,
    vars: BTreeSet<u32>,
    helpers: BTreeSet<Helper>,
    outcomes: Vec<Outcome>,
}

pub(crate) fn lift_function(input: &FunctionInput<'_>) -> Option<LiftedFunction> {
    let register_count: u32 = register_bound(input)?;
    let analysis: Analysis = analyze(input, register_count);
    let mut lifter: Lifter<'_> = Lifter {
        input,
        analysis,
        regs: BTreeMap::new(),
        envs: BTreeMap::new(),
        next_effect: 1,
        out: Vec::new(),
        block: 0,
        position: 0,
        deferred: BTreeMap::new(),
        pending_yield: None,
        vars: BTreeSet::new(),
        helpers: BTreeSet::new(),
        outcomes: vec![Outcome::Reconstructed; input.instructions.len()],
    };
    let mut blocks: Vec<LiftedBlock> = Vec::with_capacity(input.cfg.blocks.len());
    for (index, block) in input.cfg.blocks.iter().enumerate() {
        blocks.push(lifter.lift_block(index, block));
    }
    let env_slots: u32 = if input
        .instructions
        .iter()
        .any(|inst: &Instruction| inst.name == "CreateEnvironment")
    {
        input.header.env_size.min(MAX_ENV_SLOTS)
    } else {
        0
    };
    let handler_of_block: Vec<Option<usize>> = lifter.analysis.first_handler.clone();
    Some(LiftedFunction {
        blocks,
        var_regs: lifter.vars,
        env_slots,
        helpers: lifter.helpers,
        outcomes: lifter.outcomes,
        handler_of_block,
    })
}

impl Lifter<'_> {
    fn scope(&self) -> &ModuleScope {
        self.input.scope
    }

    fn module(&self) -> &HermesModule {
        self.input.module
    }

    fn lift_block(&mut self, index: usize, block: &BasicBlock) -> LiftedBlock {
        self.regs.clear();
        self.deferred.clear();
        self.pending_yield = None;
        self.envs.clone_from(&self.analysis.env_regs);
        if let Some(entry) = self.analysis.env_in.get(index) {
            for (reg, env) in entry {
                self.envs.insert(*reg, *env);
            }
        }
        self.out = Vec::new();
        self.block = index;
        let (start, end): (usize, usize) = block.instr_range;
        for position in start..end {
            self.lift_instruction(position);
        }
        let terminated: bool = self.out.last().is_some_and(|stmt: &BlockStmt| {
            matches!(
                stmt,
                BlockStmt::Return(_)
                    | BlockStmt::Throw(_)
                    | BlockStmt::Jump(_)
                    | BlockStmt::CondJump { .. }
                    | BlockStmt::Switch { .. }
            )
        });
        if !terminated {
            self.finish_block();
        }
        LiftedBlock {
            stmts: std::mem::take(&mut self.out),
        }
    }

    fn finish_block(&mut self) {
        for (_, reg) in self.pending_effectful() {
            if let Some(RegState::Pending(value)) = self.regs.get(&reg).cloned() {
                self.regs.insert(reg, RegState::Consumed);
                self.push_expression(&value.text);
            }
        }
    }

    fn effect(&mut self) -> u64 {
        let id: u64 = self.next_effect;
        self.next_effect += 1;
        id
    }

    fn is_pinned(&self, reg: u32) -> bool {
        self.analysis
            .pinned
            .get(self.block)
            .is_some_and(|set: &RegSet| set.contains(reg))
    }

    fn var_value(&mut self, reg: u32) -> Value {
        self.vars.insert(reg);
        let mut value: Value = Value::new(self.scope().reg_name(reg), Form::Ident);
        value.deps.insert(reg);
        value.origin = Some(reg);
        value
    }

    fn read(&mut self, reg: u32) -> Value {
        match self.regs.get(&reg).cloned() {
            Some(RegState::Pending(mut value)) => {
                self.regs.insert(reg, RegState::Consumed);
                value.origin = Some(reg);
                value
            }
            Some(RegState::Const(mut value)) => {
                value.origin = Some(reg);
                value
            }
            Some(RegState::Var | RegState::Consumed) => self.var_value(reg),
            None => match self.analysis.const_uses.get(&(self.position, reg)).copied() {
                Some(site) => {
                    let mut value: Value = self.const_value(site);
                    value.origin = Some(reg);
                    value
                }
                None => self.var_value(reg),
            },
        }
    }

    fn read_at(&mut self, position: usize, reg: u32) -> Option<Value> {
        if self.analysis.patterns.absorbed.contains(&(position, reg)) {
            return None;
        }
        Some(self.read(reg))
    }

    fn skip_env_read(&mut self, position: usize, reg: u32) {
        if self.env_of(reg).is_none() {
            let _ = self.read_at(position, reg);
        }
    }

    fn env_of(&self, reg: u32) -> Option<EnvRef> {
        if let Some(env) = self.envs.get(&reg) {
            return Some(*env);
        }
        if matches!(
            self.regs.get(&reg),
            Some(RegState::Pending(_) | RegState::Const(_) | RegState::Var)
        ) {
            return None;
        }
        let site: usize = *self.analysis.const_uses.get(&(self.position, reg))?;
        self.analysis.env_sites.get(&site).copied()
    }

    fn read_stable(&mut self, reg: u32) -> Value {
        if let Some(RegState::Pending(_)) = self.regs.get(&reg) {
            self.flush_reg(reg);
        }
        self.read(reg)
    }

    fn pending_effectful(&self) -> Vec<(u64, u32)> {
        let mut out: Vec<(u64, u32)> = self
            .regs
            .iter()
            .filter_map(|(reg, state): (&u32, &RegState)| match state {
                RegState::Pending(value) => value.min_effect().map(|e: u64| (e, *reg)),
                _ => None,
            })
            .collect();
        out.sort_unstable();
        out
    }

    fn flush_outstanding(&mut self) {
        for (_, reg) in self.pending_effectful() {
            self.flush_reg(reg);
        }
    }

    fn flush_older_than(&mut self, bound: u64) {
        for (effect, reg) in self.pending_effectful() {
            if effect < bound {
                self.flush_reg(reg);
            }
        }
    }

    fn flush_dependents(&mut self, reg: u32) {
        let dependents: Vec<u32> = self
            .regs
            .iter()
            .filter_map(|(other, state): (&u32, &RegState)| match state {
                RegState::Pending(value) if *other != reg && value.deps.contains(&reg) => {
                    Some(*other)
                }
                _ => None,
            })
            .collect();
        for other in dependents {
            self.flush_reg(other);
        }
    }

    fn flush_reg(&mut self, reg: u32) {
        let Some(RegState::Pending(value)) = self.regs.get(&reg).cloned() else {
            return;
        };
        if let Some(first) = value.min_effect() {
            self.flush_older_than(first);
        }
        let Some(RegState::Pending(value)) = self.regs.remove(&reg) else {
            return;
        };
        self.deferred.remove(&reg);
        self.flush_dependents(reg);
        let text: String = match &value.shape {
            Shape::Member { object, key } => match object.origin {
                Some(object_reg)
                    if !object.duplicable && object.text != self.scope().reg_name(object_reg) =>
                {
                    self.flush_dependents(object_reg);
                    self.vars.insert(object_reg);
                    let object_name: String = self.scope().reg_name(object_reg);
                    self.push_expression(&format!("{object_name} = {}", object.text));
                    self.regs.insert(object_reg, RegState::Var);
                    format!("{object_name}{key}")
                }
                _ => value.text.clone(),
            },
            _ => value.text.clone(),
        };
        self.vars.insert(reg);
        let name: String = self.scope().reg_name(reg);
        self.push_expression(&format!("{name} = {text}"));
        self.regs.insert(reg, RegState::Var);
    }

    fn flush_operand(&mut self, value: &mut Value) {
        if !value.effectful() {
            return;
        }
        let Some(reg) = value.origin else {
            return;
        };
        self.flush_dependents(reg);
        self.vars.insert(reg);
        let name: String = self.scope().reg_name(reg);
        self.push_expression(&format!("{name} = {}", value.text));
        self.regs.insert(reg, RegState::Var);
        *value = self.var_value(reg);
    }

    fn order(&mut self, operands: &mut [Value], effectful: bool) {
        let mut combined: Vec<u64> = Vec::new();
        for operand in operands.iter() {
            combined.extend(operand.effects.iter().copied());
        }
        let increasing: bool = combined.windows(2).all(|pair: &[u64]| pair[0] < pair[1]);
        let lowest: Option<u64> = combined
            .first()
            .copied()
            .or_else(|| effectful.then_some(self.next_effect));
        let outstanding_ok: bool = lowest.is_none_or(|low: u64| {
            self.regs.values().all(|state: &RegState| match state {
                RegState::Pending(value) => value.max_effect().is_none_or(|high: u64| high < low),
                _ => true,
            })
        });
        if increasing && outstanding_ok {
            return;
        }
        let mut items: Vec<(u64, Option<u32>, Option<usize>)> = Vec::new();
        for (effect, reg) in self.pending_effectful() {
            items.push((effect, Some(reg), None));
        }
        for (position, operand) in operands.iter().enumerate() {
            if let Some(effect) = operand.min_effect() {
                items.push((effect, None, Some(position)));
            }
        }
        items.sort_unstable();
        for (_, reg, position) in items {
            if let Some(reg) = reg {
                self.flush_reg(reg);
            }
            if let Some(position) = position {
                let mut operand: Value = operands[position].clone();
                self.flush_operand(&mut operand);
                operands[position] = operand;
            }
        }
    }

    fn compose(&mut self, operands: &mut [Value], effectful: bool) -> Vec<u64> {
        self.order(operands, effectful);
        let mut effects: Vec<u64> = Vec::new();
        for operand in operands.iter() {
            effects.extend(operand.effects.iter().copied());
        }
        if effectful {
            effects.push(self.effect());
        }
        effects
    }

    fn finish(text: String, form: Form, operands: &[Value], effects: Vec<u64>) -> Value {
        let mut value: Value = Value::new(text, form);
        for operand in operands {
            value.deps.extend(operand.deps.iter().copied());
            value.call_free = value.call_free && operand.call_free;
        }
        value.effects = effects;
        value
    }

    fn statement(&mut self, operands: &mut [Value]) {
        self.order(operands, true);
        self.flush_outstanding();
        self.effect();
    }

    fn push_expression(&mut self, text: &str) {
        let trimmed: &str = text.trim_start();
        let hazard: bool = trimmed.starts_with('{')
            || trimmed.starts_with("function")
            || trimmed.starts_with("async function")
            || trimmed.starts_with("class")
            || trimmed.starts_with("let [")
            || trimmed.starts_with(CLOSURE_MARK);
        if hazard {
            self.out.push(BlockStmt::Line(format!("({text});")));
        } else {
            self.out.push(BlockStmt::Line(format!("{text};")));
        }
    }

    fn push_raw(&mut self, text: String) {
        self.out.push(BlockStmt::Line(text));
    }

    fn define(&mut self, position: usize, reg: u32, value: Value) {
        self.envs.remove(&reg);
        if matches!(
            value.shape,
            Shape::FreshArray { .. } | Shape::FreshObject { .. }
        ) && self.analysis.patterns.builder_last.contains_key(&position)
            && !self.is_pinned(reg)
        {
            if let Some(RegState::Pending(old)) = self.regs.get(&reg).cloned()
                && old.effectful()
            {
                self.flush_older_than(old.min_effect().unwrap_or(0));
                self.push_expression(&old.text);
            }
            self.deferred.insert(reg, position);
            self.regs.insert(reg, RegState::Pending(value));
            return;
        }
        self.define_now(position, reg, value);
    }

    fn settle(&mut self, reg: u32) {
        let Some(def_position) = self.deferred.remove(&reg) else {
            return;
        };
        let Some(RegState::Pending(value)) = self.regs.remove(&reg) else {
            return;
        };
        self.define_now(def_position, reg, value);
    }

    fn define_now(&mut self, position: usize, reg: u32, value: Value) {
        if let Some(RegState::Pending(old)) = self.regs.get(&reg).cloned() {
            self.regs.insert(reg, RegState::Consumed);
            if old.effectful() {
                self.flush_older_than(old.min_effect().unwrap_or(0));
                self.push_expression(&old.text);
            }
        }
        let info: DefInfo = self
            .analysis
            .defs
            .get(&(position, reg))
            .copied()
            .unwrap_or(DefInfo {
                uses: 2,
                live_out: true,
            });
        let pinned: bool = self.is_pinned(reg);
        let needs_var: bool = if value.duplicable {
            (pinned || info.live_out) && self.analysis.needed.contains(&(position, reg))
        } else {
            pinned || info.live_out || info.uses >= 2 || value.text.len() > MAX_EXPR_BYTES
        };
        if needs_var {
            self.assign(reg, value, pinned);
            return;
        }
        if info.uses == 0 {
            if value.effectful() {
                let mut operands: [Value; 1] = [value];
                self.statement(&mut operands);
                let [value] = operands;
                self.push_expression(&value.text);
            }
            self.regs.insert(reg, RegState::Consumed);
            return;
        }
        if value.duplicable {
            self.regs.insert(reg, RegState::Const(value));
        } else {
            self.regs.insert(reg, RegState::Pending(value));
        }
    }

    fn assign(&mut self, reg: u32, value: Value, ordered: bool) {
        let duplicable: bool = value.duplicable;
        let mut operands: [Value; 1] = [value];
        if operands[0].effectful() || ordered {
            self.statement(&mut operands);
        }
        let [value] = operands;
        self.flush_dependents(reg);
        self.vars.insert(reg);
        let name: String = self.scope().reg_name(reg);
        self.push_expression(&format!("{name} = {}", value.text));
        if duplicable {
            self.regs.insert(reg, RegState::Const(value));
        } else {
            self.regs.insert(reg, RegState::Var);
        }
    }

    fn force_var(&mut self, reg: u32) -> String {
        self.envs.remove(&reg);
        self.flush_dependents(reg);
        self.vars.insert(reg);
        self.regs.insert(reg, RegState::Var);
        self.scope().reg_name(reg)
    }

    fn decline(&mut self, position: usize) {
        self.outcomes[position] = Outcome::Declined;
    }

    fn string(&self, id: u32) -> Option<String> {
        self.module().string_by_global_id(id).map(str::to_owned)
    }

    fn string_literal(&self, id: u32) -> String {
        self.string(id)
            .map_or_else(|| "undefined".to_owned(), |s: String| js_string_literal(&s))
    }

    fn const_value(&self, site: usize) -> Value {
        let inst: &Instruction = &self.input.instructions[site];
        self.constant_of(inst)
            .unwrap_or_else(|| Value::constant("undefined".to_owned(), Form::Ident))
    }

    fn constant_of(&self, inst: &Instruction) -> Option<Value> {
        let name: &str = &inst.name;
        Some(match name {
            "LoadConstUInt8" => Value::constant(uint_at(inst, 1).to_string(), Form::Number),
            "LoadConstInt" => {
                let v: i64 = match inst.operands.get(1) {
                    Some(OperandValue::Imm(i)) => *i,
                    _ => 0,
                };
                number_value(v as f64)
            }
            "LoadConstDouble" => {
                let bits: u64 = match inst.operands.get(1) {
                    Some(OperandValue::Float(f)) => *f,
                    _ => 0,
                };
                number_value(f64::from_bits(bits))
            }
            "LoadConstZero" => Value::constant("0".to_owned(), Form::Number),
            "LoadConstString" | "LoadConstStringLongIndex" => {
                Value::constant(self.string_literal(string_at(inst, 1)), Form::Literal)
            }
            "LoadConstUndefined" => Value::constant("undefined".to_owned(), Form::Ident),
            "LoadConstNull" => Value::constant("null".to_owned(), Form::Ident),
            "LoadConstTrue" => Value::constant("true".to_owned(), Form::Ident),
            "LoadConstFalse" => Value::constant("false".to_owned(), Form::Ident),
            "LoadConstEmpty" => {
                let mut value: Value = Value::constant("$empty".to_owned(), Form::Ident);
                value.shape = Shape::Empty;
                value
            }
            "LoadConstBigInt" | "LoadConstBigIntLongIndex" => {
                let id: u32 = match inst.operands.get(1) {
                    Some(OperandValue::BigIntId(b)) => *b,
                    _ => u32::MAX,
                };
                let text: String = self.bigint_text(id)?;
                let form: Form = if text.starts_with('-') {
                    Form::Unary
                } else {
                    Form::Number
                };
                Value::constant(text, form)
            }
            "LoadParam" | "LoadParamLong" => {
                let index: u64 = uint_at(inst, 1);
                if index == 0 {
                    Value::constant("this".to_owned(), Form::Ident)
                } else if index < u64::from(self.input.header.param_count) {
                    let param: u32 = u32::try_from(index - 1).unwrap_or(0);
                    Value::constant(
                        self.scope().param_name_of(self.input.index, param),
                        Form::Ident,
                    )
                } else {
                    Value::constant(format!("arguments[{}]", index - 1), Form::Member)
                }
            }
            "LoadThisNS" => Value::constant("this".to_owned(), Form::Ident),
            "GetGlobalObject" => {
                let mut value: Value = Value::constant("globalThis".to_owned(), Form::Ident);
                value.shape = Shape::Global;
                value
            }
            "GetNewTarget" => Value::constant("new.target".to_owned(), Form::Member),
            _ => return None,
        })
    }

    fn bigint_text(&self, id: u32) -> Option<String> {
        let entry: &super::BigIntTableEntry = self.module().big_int_table.get(id as usize)?;
        let start: usize = usize::try_from(entry.offset).ok()?;
        let end: usize = start.checked_add(usize::try_from(entry.length).ok()?)?;
        let slice: &[u8] = self.module().big_int_storage.get(start..end)?;
        Some(super::bigint::bigint_literal(slice))
    }

    fn uses_helper(&mut self, helper: Helper) {
        self.helpers.insert(helper);
        if helper == Helper::Tdz {
            self.helpers.insert(Helper::Empty);
        }
    }

    fn unrecovered(&mut self, position: usize) {
        self.decline(position);
        self.uses_helper(Helper::Unrecovered);
        let inst: &Instruction = &self.input.instructions[position];
        let label: String = js_string_literal(&inst.name);
        let role: Roles = self.analysis.roles[position].clone();
        let mut operands: Vec<Value> = Vec::new();
        for reg in &role.reads {
            if self.env_of(*reg).is_some() {
                continue;
            }
            if let Some(value) = self.read_at(position, *reg) {
                operands.push(value);
            }
        }
        let effects: Vec<u64> = self.compose(&mut operands, true);
        let args: Vec<String> = std::iter::once(label)
            .chain(operands.iter().map(|v: &Value| v.text.clone()))
            .collect();
        let value: Value = Self::finish(
            format!("$unrecovered({})", args.join(", ")),
            Form::Call,
            &operands,
            effects,
        );
        let mut writes: std::slice::Iter<'_, u32> = role.writes.iter();
        match writes.next() {
            Some(first) => {
                self.envs.remove(first);
                self.define(position, *first, value);
                for other in writes {
                    self.envs.remove(other);
                    let name: String = self.force_var(*other);
                    self.push_expression(&format!("{name} = undefined"));
                }
            }
            None => {
                let mut operands: [Value; 1] = [value];
                self.statement(&mut operands);
                let [value] = operands;
                self.push_expression(&value.text);
            }
        }
    }

    fn unary(&mut self, position: usize, inst: &Instruction, prefix: &str, effectful: bool) {
        let mut operands: [Value; 1] = [self.read(reg_at(inst, 1))];
        let effects: Vec<u64> = self.compose(&mut operands, effectful);
        let operand_text: String = if prefix == "typeof " && operands[0].shape == Shape::BareGlobal
        {
            format!("(0, {})", operands[0].text)
        } else {
            operands[0].operand_text()
        };
        let value: Value = Self::finish(
            format!("{prefix}{operand_text}"),
            Form::Unary,
            &operands,
            effects,
        );
        self.define(position, reg_at(inst, 0), value);
    }

    fn lift_instruction(&mut self, position: usize) {
        self.position = position;
        if self.analysis.patterns.skipped.contains(&position) {
            return;
        }
        let inst: Instruction = self.input.instructions[position].clone();
        let name: &str = &inst.name;
        if let Some(value) = self.constant_of(&inst) {
            self.envs.remove(&reg_at(&inst, 0));
            self.define(position, reg_at(&inst, 0), value);
            return;
        }
        if let Some((symbol, pure)) = binary_operator(name) {
            let mut operands: [Value; 2] =
                [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 2))];
            let effects: Vec<u64> = self.compose(&mut operands, !pure);
            let text: String = format!(
                "({} {symbol} {})",
                operands[0].operand_text(),
                operands[1].operand_text()
            );
            let value: Value = Self::finish(text, Form::Paren, &operands, effects);
            self.define(position, reg_at(&inst, 0), value);
            return;
        }
        if let Some((symbol, negate)) = jump_condition(name) {
            let mut operands: [Value; 2] =
                [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 2))];
            self.statement(&mut operands);
            let raw: String = format!(
                "{} {symbol} {}",
                operands[0].operand_text(),
                operands[1].operand_text()
            );
            let text: String = if negate { format!("!({raw})") } else { raw };
            self.push_cond_jump(position, target_at(&inst, 0), text);
            return;
        }
        match name {
            "Mov" | "MovLong" => {
                let source: u32 = reg_at(&inst, 1);
                let dest: u32 = reg_at(&inst, 0);
                if let Some(env) = self.env_of(source) {
                    self.envs.insert(dest, env);
                    self.regs.remove(&dest);
                    return;
                }
                self.envs.remove(&dest);
                if let Some(value) = self.read_at(position, source) {
                    self.define(position, dest, value);
                }
            }
            "Not" => self.unary(position, &inst, "!", false),
            "TypeOf" => self.unary(position, &inst, "typeof ", false),
            "Negate" => self.unary(position, &inst, "-", true),
            "BitNot" => self.unary(position, &inst, "~", true),
            "ToNumber" => self.unary(position, &inst, "+", true),
            "ToNumeric" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("-(-{})", operands[0].operand_text());
                let value: Value = Self::finish(text, Form::Unary, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "ToInt32" | "AddEmptyString" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = if name == "ToInt32" {
                    format!("({} | 0)", operands[0].operand_text())
                } else {
                    format!("(\"\" + {})", operands[0].operand_text())
                };
                let value: Value = Self::finish(text, Form::Paren, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "Inc" | "Dec" => {
                let dest: u32 = reg_at(&inst, 0);
                let operator: &str = if name == "Inc" { "++" } else { "--" };
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let [operand] = operands;
                let dest_name: String = self.scope().reg_name(dest);
                let same: bool = operand.text == dest_name;
                let target: String = self.force_var(dest);
                if !same {
                    self.push_expression(&format!("{target} = {}", operand.text));
                }
                self.push_expression(&format!("{operator}{target}"));
            }
            "CoerceThisNS" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                if operands[0].text == "this" {
                    let value: Value = Value::constant("this".to_owned(), Form::Ident);
                    self.define(position, reg_at(&inst, 0), value);
                } else {
                    self.uses_helper(Helper::CoerceThis);
                    let effects: Vec<u64> = self.compose(&mut operands, false);
                    let text: String = format!("$coerceThis({})", operands[0].text);
                    let value: Value = Self::finish(text, Form::Call, &operands, effects);
                    self.define(position, reg_at(&inst, 0), value);
                }
            }
            "CreateEnvironment" => {
                let own: u32 = u32::try_from(self.input.index).unwrap_or(u32::MAX);
                if self.scope().is_boxed(own) {
                    self.statement(&mut []);
                    self.push_raw(format!("{} = {{}};", ModuleScope::boxed_env_name(own)));
                }
                self.envs.insert(reg_at(&inst, 0), EnvRef::Owned(own));
                self.regs.insert(reg_at(&inst, 0), RegState::Consumed);
            }
            "GetEnvironment" => {
                let level: u32 = u32::try_from(uint_at(&inst, 1)).unwrap_or(u32::MAX);
                let own: u32 = u32::try_from(self.input.index).unwrap_or(u32::MAX);
                let env: EnvRef = self
                    .scope()
                    .chain(own)
                    .and_then(|c: &Vec<u32>| c.get(level as usize).copied())
                    .map_or(EnvRef::Unknown(level), EnvRef::Owned);
                self.envs.insert(reg_at(&inst, 0), env);
                self.regs.insert(reg_at(&inst, 0), RegState::Consumed);
            }
            "LoadFromEnvironment" | "LoadFromEnvironmentL" => {
                let env_reg: u32 = reg_at(&inst, 1);
                let dest: u32 = reg_at(&inst, 0);
                if let Some(EnvRef::Owned(owner)) = self.env_of(env_reg)
                    && let Some(held) = self.scope().env_held_in(owner, uint_at(&inst, 2))
                {
                    self.regs.remove(&dest);
                    self.envs.insert(dest, EnvRef::Owned(held));
                    return;
                }
                match self.env_var(env_reg, uint_at(&inst, 2)) {
                    Some(text) => {
                        let mut value: Value = Value::new(text, Form::Ident);
                        value.effects.push(self.effect());
                        self.envs.remove(&reg_at(&inst, 0));
                        self.define(position, reg_at(&inst, 0), value);
                    }
                    None => self.unrecovered(position),
                }
            }
            "StoreToEnvironment"
            | "StoreToEnvironmentL"
            | "StoreNPToEnvironment"
            | "StoreNPToEnvironmentL" => {
                let env_reg: u32 = reg_at(&inst, 0);
                if let Some(EnvRef::Owned(owner)) = self.env_of(env_reg)
                    && let Some(held) = self.scope().env_held_in(owner, uint_at(&inst, 1))
                    && self.env_of(reg_at(&inst, 2)) == Some(EnvRef::Owned(held))
                {
                    return;
                }
                let Some(target) = self.env_var(env_reg, uint_at(&inst, 1)) else {
                    self.unrecovered(position);
                    return;
                };
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 2))];
                self.statement(&mut operands);
                self.push_expression(&format!("{target} = {}", operands[0].text));
            }
            "CreateInnerEnvironment" => self.unrecovered(position),
            "DeclareGlobalVar" | "ThrowIfHasRestrictedGlobalProperty" | "AsyncBreakCheck" => {}
            "ProfilePoint" => self.decline(position),
            "Debugger" => {
                self.statement(&mut []);
                self.push_raw("debugger;".to_owned());
            }
            "Unreachable" => {
                self.decline(position);
                self.statement(&mut []);
                self.out.push(BlockStmt::Throw(
                    "new Error(\"hermes: unreachable code was reached\")".to_owned(),
                ));
            }
            "GetByIdShort" | "GetById" | "GetByIdLong" | "TryGetById" | "TryGetByIdLong" => {
                self.lift_get_by_id(position, &inst);
            }
            "GetByVal" => {
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 2))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let key: String = format!("[{}]", operands[1].text);
                let text: String = format!("{}{key}", operands[0].object_text());
                let mut value: Value = Self::finish(text, Form::Member, &operands, effects);
                if self.analysis.patterns.method_loads.contains_key(&position) {
                    value.shape = Shape::Member {
                        object: Box::new(operands[0].clone()),
                        key,
                    };
                }
                self.define(position, reg_at(&inst, 0), value);
            }
            "PutById" | "PutByIdLong" | "TryPutById" | "TryPutByIdLong" => {
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 0)), self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let target: String =
                    self.global_target(&operands[0], string_at(&inst, 3), name.starts_with("Try"));
                self.push_expression(&format!("{target} = {}", operands[1].text));
            }
            "PutNewOwnById" | "PutNewOwnByIdShort" | "PutNewOwnByIdLong" => {
                let key: String = self.string(string_at(&inst, 2)).unwrap_or_default();
                self.lift_builder_put(position, &inst, BuilderKey::Named(key));
            }
            "PutOwnByIndex" | "PutOwnByIndexL" => {
                let index: u64 = uint_at(&inst, 2);
                self.lift_builder_put(position, &inst, BuilderKey::Index(index));
            }
            "PutOwnByVal" => {
                if uint_at(&inst, 3) != 0 {
                    self.lift_builder_put(position, &inst, BuilderKey::Computed);
                } else {
                    let object: Value = self.read_builder_object(position, reg_at(&inst, 0));
                    let mut operands: [Value; 3] = [
                        object,
                        self.read(reg_at(&inst, 1)),
                        self.read(reg_at(&inst, 2)),
                    ];
                    self.statement(&mut operands);
                    self.push_expression(&format!(
                        "Object.defineProperty({}, {}, {{ value: {}, writable: true, enumerable: false, configurable: true }})",
                        operands[0].text, operands[2].text, operands[1].text
                    ));
                }
            }
            "PutNewOwnNEById" | "PutNewOwnNEByIdLong" => {
                let key: String =
                    js_string_literal(&self.string(string_at(&inst, 2)).unwrap_or_default());
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 0)), self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                self.push_expression(&format!(
                    "Object.defineProperty({}, {key}, {{ value: {}, writable: true, enumerable: false, configurable: true }})",
                    operands[0].text, operands[1].text
                ));
            }
            "PutByVal" => {
                let mut operands: [Value; 3] = [
                    self.read(reg_at(&inst, 0)),
                    self.read(reg_at(&inst, 1)),
                    self.read(reg_at(&inst, 2)),
                ];
                self.statement(&mut operands);
                self.push_expression(&format!(
                    "{}[{}] = {}",
                    operands[0].object_text(),
                    operands[1].text,
                    operands[2].text
                ));
            }
            "PutOwnGetterSetterByVal" => {
                let mut operands: [Value; 4] = [
                    self.read(reg_at(&inst, 0)),
                    self.read(reg_at(&inst, 1)),
                    self.read(reg_at(&inst, 2)),
                    self.read(reg_at(&inst, 3)),
                ];
                self.statement(&mut operands);
                let enumerable: bool = uint_at(&inst, 4) != 0;
                self.push_expression(&format!(
                    "Object.defineProperty({}, {}, {{ get: {}, set: {}, enumerable: {enumerable}, configurable: true }})",
                    operands[0].text, operands[1].text, operands[2].text, operands[3].text
                ));
            }
            "DelById" | "DelByIdLong" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let suffix: String =
                    property_suffix(&self.string(string_at(&inst, 2)).unwrap_or_default());
                let text: String = format!("delete {}{suffix}", operands[0].object_text());
                let value: Value = Self::finish(text, Form::Unary, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "DelByVal" => {
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 2))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String =
                    format!("delete {}[{}]", operands[0].object_text(), operands[1].text);
                let value: Value = Self::finish(text, Form::Unary, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "NewObject" => {
                let mut value: Value = Value::new("{}".to_owned(), Form::Literal);
                value.shape = Shape::FreshObject { props: Vec::new() };
                self.define(position, reg_at(&inst, 0), value);
            }
            "NewObjectWithShape" | "NewObjectWithShapeAndParent" => {
                let with_parent: bool = inst.name == "NewObjectWithShapeAndParent";
                let (shape_at, values_at): (usize, usize) =
                    if with_parent { (2, 3) } else { (1, 2) };
                let Some(keys) = super::modern::shape_keys(self.module(), uint_at(&inst, shape_at))
                else {
                    self.unrecovered(position);
                    return;
                };
                let mut props: Vec<String> =
                    self.keyed_props(&keys, uint_at(&inst, values_at) as usize);
                if with_parent {
                    let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                    self.statement(&mut operands);
                    let [parent] = operands;
                    props.insert(0, format!("__proto__: {}", parent.text));
                }
                let mut value: Value = Value::new(render_object(&props), Form::Literal);
                value.shape = Shape::FreshObject { props };
                self.define(position, reg_at(&inst, 0), value);
            }
            "GetByIndex" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("{}[{}]", operands[0].object_text(), uint_at(&inst, 2));
                let value: Value = Self::finish(text, Form::Member, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "CallRequire" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let callee: String = if operands[0].form == Form::Member {
                    format!("(0, {})", operands[0].text)
                } else {
                    operands[0].object_text()
                };
                let text: String = format!("{callee}({})", uint_at(&inst, 2));
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "CreateBaseClass"
            | "CreateBaseClassLongIndex"
            | "CreateDerivedClass"
            | "CreateDerivedClassLongIndex" => {
                let Some((env, fid)) = class_creation(&inst) else {
                    self.unrecovered(position);
                    return;
                };
                self.skip_env_read(position, env);
                self.uses_helper(Helper::Class);
                let marker: Value = self.closure_value(env, closure_marker(fid));
                let mut operands: Vec<Value> = vec![marker];
                let derived: bool = inst.name.starts_with("CreateDerivedClass");
                if derived {
                    operands.push(self.read(reg_at(&inst, 3)));
                }
                self.statement(&mut operands);
                let constructor: String = self.force_var(reg_at(&inst, 0));
                let text: String = if derived {
                    format!(
                        "{constructor} = $derivedClass({}, {});",
                        operands[0].text, operands[1].text
                    )
                } else {
                    format!("{constructor} = $baseClass({});", operands[0].text)
                };
                self.push_raw(text);
                let home: String = self.force_var(reg_at(&inst, 1));
                self.push_raw(format!("{home} = {constructor}.prototype;"));
            }
            "CreatePrivateName" => {
                let text: String = format!("Symbol({})", self.string_literal(string_at(&inst, 1)));
                let value: Value = Value::new(text, Form::Call);
                self.define(position, reg_at(&inst, 0), value);
            }
            "AddOwnPrivateBySym" | "PutOwnPrivateBySym" => {
                self.uses_helper(Helper::Private);
                let name_at: usize = if inst.name == "AddOwnPrivateBySym" {
                    2
                } else {
                    3
                };
                let mut operands: [Value; 3] = [
                    self.read(reg_at(&inst, 0)),
                    self.read(reg_at(&inst, 1)),
                    self.read(reg_at(&inst, name_at)),
                ];
                self.statement(&mut operands);
                let helper: &str = if inst.name == "AddOwnPrivateBySym" {
                    "$privateAdd"
                } else {
                    "$privateSet"
                };
                self.push_expression(&format!(
                    "{helper}({}, {}, {})",
                    operands[0].text, operands[1].text, operands[2].text
                ));
            }
            "GetOwnPrivateBySym" => {
                self.uses_helper(Helper::Private);
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 3))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String =
                    format!("$privateGet({}, {})", operands[0].text, operands[1].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "PrivateIsIn" => {
                self.uses_helper(Helper::Private);
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 2)), self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String =
                    format!("$privateHas({}, {})", operands[0].text, operands[1].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "ThrowIfThisInitialized" => {
                self.uses_helper(Helper::Empty);
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 0))];
                self.statement(&mut operands);
                self.push_raw(format!(
                    "if ({} !== $empty) throw new ReferenceError(\"Super constructor may only be called once\");",
                    operands[0].text
                ));
            }
            "CacheNewObject" => {
                for reg in all_regs(&inst, false) {
                    let _ = self.read_at(position, reg);
                }
            }
            "CreateGeneratorObject" | "CreateGeneratorObjectLongIndex" => {
                self.skip_env_read(position, reg_at(&inst, 1));
                let Some(OperandValue::FunctionId(fid)) = inst.operands.get(2).copied() else {
                    self.unrecovered(position);
                    return;
                };
                self.uses_helper(Helper::CreateGenerator);
                let inner: Value = self.closure_value(reg_at(&inst, 1), closure_marker(fid));
                let value: Value =
                    Value::new(format!("$createGenerator({})", inner.text), Form::Call);
                self.define(position, reg_at(&inst, 0), value);
            }
            "TypeOfIs" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = self.type_of_is(&operands[0], uint_at(&inst, 2));
                let value: Value = Self::finish(text, Form::Paren, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "JmpTypeOfIs" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let cond: String = self.type_of_is(&operands[0], uint_at(&inst, 2));
                self.push_cond_jump(position, target_at(&inst, 0), cond);
            }
            "StringSwitchImm" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 0))];
                self.statement(&mut operands);
                let [scrutinee] = operands;
                let entries: Vec<(u32, usize)> = super::decompile::string_switch_entries(
                    &self.module().raw_image,
                    self.input.code_base,
                    &inst,
                );
                let labels: Vec<String> = entries
                    .iter()
                    .map(|(id, _): &(u32, usize)| self.string_literal(*id))
                    .collect();
                let cases: Vec<(i64, usize)> = entries
                    .iter()
                    .enumerate()
                    .map(|(index, (_, target)): (usize, &(u32, usize))| {
                        (i64::try_from(index).unwrap_or(i64::MAX), *target)
                    })
                    .collect();
                self.uses_helper(Helper::StringCase);
                let default: usize = target_at(&inst, 3).unwrap_or(usize::MAX);
                self.out.push(BlockStmt::Switch {
                    scrutinee: format!("$stringCase({}, [{}])", scrutinee.text, labels.join(", ")),
                    cases,
                    default,
                });
            }
            "LoadParentNoTraps" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("Object.getPrototypeOf({})", operands[0].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "ThrowIfUndefined" => {
                let mut operands: [Value; 1] = [self.read_stable(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let [checked] = operands;
                self.push_raw(format!(
                    "if ({} === undefined) throw new ReferenceError(\"accessing an uninitialized variable\");",
                    checked.text
                ));
                self.define(position, reg_at(&inst, 0), checked);
            }
            "ToPropertyKey" => {
                self.uses_helper(Helper::ToPropertyKey);
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("$toPropertyKey({})", operands[0].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "GetByIdWithReceiverLong" => {
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 3))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!(
                    "Reflect.get({}, {}, {})",
                    operands[0].text,
                    self.string_literal(string_at(&inst, 4)),
                    operands[1].text
                );
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "GetByValWithReceiver" => {
                let mut operands: [Value; 3] = [
                    self.read(reg_at(&inst, 1)),
                    self.read(reg_at(&inst, 2)),
                    self.read(reg_at(&inst, 3)),
                ];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!(
                    "Reflect.get({}, {}, {})",
                    operands[0].text, operands[1].text, operands[2].text
                );
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "PutByValWithReceiver" => {
                let mut operands: [Value; 4] = [
                    self.read(reg_at(&inst, 0)),
                    self.read(reg_at(&inst, 1)),
                    self.read(reg_at(&inst, 2)),
                    self.read(reg_at(&inst, 3)),
                ];
                self.statement(&mut operands);
                let call: String = format!(
                    "Reflect.set({}, {}, {}, {})",
                    operands[0].text, operands[1].text, operands[2].text, operands[3].text
                );
                if uint_at(&inst, 4) == 0 {
                    self.push_expression(&call);
                } else {
                    self.push_raw(format!(
                        "if (!{call}) throw new TypeError(\"Cannot assign to read-only property\");"
                    ));
                }
            }
            "JmpBuiltinIs" | "JmpBuiltinIsLong" | "JmpBuiltinIsNot" | "JmpBuiltinIsNotLong" => {
                let mut builtin: String =
                    super::builtins::builtin_name(self.module().header.version, uint_at(&inst, 1));
                match private_builtin(&builtin) {
                    Some("functionPrototypeCall") => {
                        self.uses_helper(Helper::FunctionPrototype);
                        "$functionPrototypeCall".clone_into(&mut builtin);
                    }
                    Some("functionPrototypeApply") => {
                        self.uses_helper(Helper::FunctionPrototype);
                        "$functionPrototypeApply".clone_into(&mut builtin);
                    }
                    Some(_) => {
                        self.unrecovered(position);
                        return;
                    }
                    None if builtin.starts_with('$') => {
                        self.unrecovered(position);
                        return;
                    }
                    None => {}
                }
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 2))];
                self.statement(&mut operands);
                let negate: bool = inst.name.starts_with("JmpBuiltinIsNot");
                let cond: String = format!(
                    "{} {} {builtin}",
                    operands[0].text,
                    if negate { "!==" } else { "===" }
                );
                self.push_cond_jump(position, target_at(&inst, 0), cond);
            }
            "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
                let count: u64 = uint_at(&inst, 2).min(MAX_LITERAL_ELEMENTS);
                let props: Vec<String> = self.buffer_object_props(
                    count as usize,
                    uint_at(&inst, 3) as usize,
                    uint_at(&inst, 4) as usize,
                );
                let mut value: Value = Value::new(render_object(&props), Form::Literal);
                value.shape = Shape::FreshObject { props };
                self.define(position, reg_at(&inst, 0), value);
            }
            "NewObjectWithParent" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, false);
                let text: String = format!("{{ __proto__: {} }}", operands[0].text);
                let value: Value = Self::finish(text, Form::Literal, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "NewArray" => {
                let len: u64 = uint_at(&inst, 1);
                let elems: Vec<Option<String>> = Vec::new();
                let mut value: Value = Value::new(render_array(&elems, len), Form::Literal);
                value.shape = Shape::FreshArray { elems, len };
                self.define(position, reg_at(&inst, 0), value);
            }
            "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
                let count: u64 = uint_at(&inst, 2).min(MAX_LITERAL_ELEMENTS);
                let elems: Vec<Option<String>> = self
                    .buffer_values(
                        count as usize,
                        uint_at(&inst, 3) as usize,
                        BufferSource::Array,
                    )
                    .into_iter()
                    .map(Some)
                    .collect();
                let len: u64 = elems.len() as u64;
                let mut value: Value = Value::new(render_array(&elems, len), Form::Literal);
                value.shape = Shape::FreshArray { elems, len };
                self.define(position, reg_at(&inst, 0), value);
            }
            "CreateClosure"
            | "CreateClosureLongIndex"
            | "CreateGeneratorClosure"
            | "CreateGeneratorClosureLongIndex"
            | "CreateAsyncClosure"
            | "CreateAsyncClosureLongIndex" => {
                self.skip_env_read(position, reg_at(&inst, 1));
                let Some(OperandValue::FunctionId(fid)) = inst.operands.get(2).copied() else {
                    self.unrecovered(position);
                    return;
                };
                let value: Value = self.closure_value(reg_at(&inst, 1), closure_marker(fid));
                self.envs.remove(&reg_at(&inst, 0));
                self.define(position, reg_at(&inst, 0), value);
            }
            "CreateRegExp" => {
                let text: String = self.regexp_literal(
                    string_at(&inst, 1),
                    string_at(&inst, 2),
                    uint_at(&inst, 3),
                );
                let value: Value = Value::new(text, Form::Literal);
                self.define(position, reg_at(&inst, 0), value);
            }
            "Catch" => {
                let value: Value = Value::new("$exc".to_owned(), Form::Ident);
                self.envs.remove(&reg_at(&inst, 0));
                self.define(position, reg_at(&inst, 0), value);
            }
            "ReifyArguments" => {
                let _ = self.read_at(position, reg_at(&inst, 0));
                let value: Value = Value::constant("arguments".to_owned(), Form::Ident);
                self.define(position, reg_at(&inst, 0), value);
            }
            "GetArgumentsLength" => {
                let _ = self.read_at(position, reg_at(&inst, 1));
                let mut value: Value = Value::new("arguments.length".to_owned(), Form::Member);
                value.effects.push(self.effect());
                self.define(position, reg_at(&inst, 0), value);
            }
            "GetArgumentsPropByVal" => {
                let key: Value = self.read(reg_at(&inst, 1));
                let _ = self.read_at(position, reg_at(&inst, 2));
                let mut operands: [Value; 1] = [key];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("arguments[{}]", operands[0].text);
                let value: Value = Self::finish(text, Form::Member, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "DirectEval" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("(0, eval)({})", operands[0].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "ThrowIfEmpty" => {
                self.uses_helper(Helper::Tdz);
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                let effects: Vec<u64> = self.compose(&mut operands, true);
                let text: String = format!("$tdz({})", operands[0].text);
                let value: Value = Self::finish(text, Form::Call, &operands, effects);
                self.define(position, reg_at(&inst, 0), value);
            }
            "ThrowIfUndefinedInst" => {
                let mut operands: [Value; 1] = [self.read_stable(reg_at(&inst, 0))];
                self.statement(&mut operands);
                self.push_raw(format!(
                    "if ({} === undefined) throw new ReferenceError(\"this is not initialized\");",
                    operands[0].text
                ));
            }
            "GetBuiltinClosure" => {
                let id: u64 = uint_at(&inst, 1);
                let builtin: String =
                    super::builtins::builtin_name(self.module().header.version, id);
                let value: Value = match private_builtin(&builtin) {
                    Some("spawnAsync") => {
                        self.uses_helper(Helper::SpawnAsync);
                        Value::constant("$spawnAsync".to_owned(), Form::Ident)
                    }
                    Some(private) => {
                        self.uses_helper(Helper::Unrecovered);
                        self.decline(position);
                        let mut value: Value =
                            Value::new(format!("$unrecovered(\"{builtin}\")"), Form::Call);
                        value.shape = Shape::Builtin(private.to_owned());
                        value
                    }
                    None if builtin.starts_with('$') => {
                        self.uses_helper(Helper::Unrecovered);
                        self.decline(position);
                        Value::new(format!("$unrecovered(\"{builtin}\")"), Form::Call)
                    }
                    None => Value::constant(builtin, Form::Member),
                };
                self.define(position, reg_at(&inst, 0), value);
            }
            "Call1" | "Call2" | "Call3" | "Call4" | "Call" | "CallLong" => {
                self.lift_call(position, &inst);
            }
            "CreateThis" => {
                let dest: u32 = reg_at(&inst, 0);
                let unused: bool = self
                    .analysis
                    .defs
                    .get(&(position, dest))
                    .is_some_and(|info: &DefInfo| info.uses == 0 && !info.live_out);
                if !unused {
                    self.unrecovered(position);
                    return;
                }
                let mut operands: [Value; 2] =
                    [self.read(reg_at(&inst, 1)), self.read(reg_at(&inst, 2))];
                self.statement(&mut operands);
                for operand in &operands {
                    if operand.effectful() {
                        self.push_expression(&operand.text);
                    }
                }
            }
            "Construct" | "ConstructLong" | "ConstructWithNewTarget" => {
                if self.analysis.patterns.constructs.contains(&position)
                    || self.constructs_with_undefined_this(&inst)
                {
                    self.lift_new(position, &inst);
                } else {
                    self.unrecovered(position);
                }
            }
            "SelectObject" => {
                if self.analysis.patterns.selects.contains(&position) {
                    let _ = self.read_at(position, reg_at(&inst, 1));
                    let value: Value = self.read(reg_at(&inst, 2));
                    self.define(position, reg_at(&inst, 0), value);
                } else {
                    self.unrecovered(position);
                }
            }
            "CallBuiltin" | "CallBuiltinLong" => self.lift_call_builtin(position, &inst),
            "IteratorBegin" => {
                let source_reg: u32 = reg_at(&inst, 1);
                let dest: u32 = reg_at(&inst, 0);
                let mut operands: [Value; 1] = [self.read(source_reg)];
                self.statement(&mut operands);
                let iterator: String = self.force_var(dest);
                self.push_expression(&format!(
                    "{iterator} = {}[Symbol.iterator]()",
                    operands[0].object_text()
                ));
                let mut next: Value = Value::new(format!("{iterator}.next"), Form::Member);
                next.deps.insert(dest);
                next.effects.push(self.effect());
                self.define(position, source_reg, next);
            }
            "IteratorNext" => {
                let dest: u32 = reg_at(&inst, 0);
                let iterator_reg: u32 = reg_at(&inst, 1);
                let iterator: Value = self.read_stable(iterator_reg);
                let next: Value = self.read_stable(reg_at(&inst, 2));
                let mut operands: [Value; 2] = [iterator, next];
                self.statement(&mut operands);
                let iterator_name: String = self.force_var(iterator_reg);
                let dest_name: String = self.force_var(dest);
                self.push_raw(format!(
                    "if ({iterator_name} === undefined) {dest_name} = undefined; else {{ {dest_name} = {}.call({iterator_name}); if (Object({dest_name}) !== {dest_name}) throw new TypeError(\"iterator result is not an object\"); if ({dest_name}.done) {iterator_name} = {dest_name} = undefined; else {dest_name} = {dest_name}.value; }}",
                    operands[1].object_text()
                ));
            }
            "IteratorClose" => {
                let mut operands: [Value; 1] = [self.read_stable(reg_at(&inst, 0))];
                self.statement(&mut operands);
                let ignore: bool = uint_at(&inst, 1) != 0;
                let iterator: &str = &operands[0].text;
                let close: String = format!(
                    "var $close = {iterator}.return; if ($close !== undefined && $close !== null) {{ var $closed = $close.call({iterator}); if (Object($closed) !== $closed) throw new TypeError(\"iterator result is not an object\"); }}"
                );
                let text: String = if ignore {
                    format!(
                        "if (Object({iterator}) === {iterator}) {{ try {{ {close} }} catch ($ignored) {{}} }}"
                    )
                } else {
                    format!("if (Object({iterator}) === {iterator}) {{ {close} }}")
                };
                self.push_raw(text);
            }
            "GetPNameList" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let list: String = self.force_var(reg_at(&inst, 0));
                self.push_raw(format!(
                    "{list} = []; for (var $key in {}) {list}.push($key);",
                    operands[0].text
                ));
                let index: String = self.force_var(reg_at(&inst, 2));
                self.push_expression(&format!("{index} = 0"));
                let size: String = self.force_var(reg_at(&inst, 3));
                self.push_expression(&format!("{size} = {list}.length"));
            }
            "GetNextPName" => {
                let props: Value = self.read_stable(reg_at(&inst, 1));
                let object: Value = self.read_stable(reg_at(&inst, 2));
                let index: Value = self.read_stable(reg_at(&inst, 3));
                let size: Value = self.read_stable(reg_at(&inst, 4));
                let mut operands: [Value; 4] = [props, object, index, size];
                self.statement(&mut operands);
                let index_name: String = self.force_var(reg_at(&inst, 3));
                let dest: String = self.force_var(reg_at(&inst, 0));
                self.push_raw(format!(
                    "for (;;) {{ if (!({index_name} < {})) {{ {dest} = undefined; break; }} {dest} = {}[{index_name}]; {index_name} = {index_name} + 1; if ({dest} in {}) break; }}",
                    operands[3].text, operands[0].text, operands[1].text
                ));
            }
            "StartGenerator" | "CompleteGenerator" => {}
            "SaveGenerator" | "SaveGeneratorLong" => match target_at(&inst, 0) {
                Some(target) => self.pending_yield = Some(target),
                None => self.unrecovered(position),
            },
            "ResumeGenerator" => self.lift_resume(position, &inst),
            "CreateGenerator" | "CreateGeneratorLongIndex" => {
                let fid: Option<u32> = match inst.operands.get(2) {
                    Some(OperandValue::FunctionId(fid)) => Some(*fid),
                    _ => None,
                };
                match fid {
                    Some(fid) if Some(fid) == self.input.merged_generator => {
                        self.skip_env_read(position, reg_at(&inst, 1));
                        let value: Value = Value::new(closure_marker(fid), Form::Function);
                        self.define(position, reg_at(&inst, 0), value);
                    }
                    Some(fid) => {
                        self.skip_env_read(position, reg_at(&inst, 1));
                        let mut value: Value = Value::new(
                            format!("({}).apply(this, arguments)", closure_marker(fid)),
                            Form::Call,
                        );
                        value.effects.push(self.effect());
                        self.define(position, reg_at(&inst, 0), value);
                    }
                    None => self.unrecovered(position),
                }
            }
            "Ret" if self.pending_yield.is_some() => self.lift_yield(position, &inst),
            "Ret" | "Throw" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 0))];
                self.statement(&mut operands);
                let [value] = operands;
                if name == "Ret" {
                    self.out.push(BlockStmt::Return(value.text));
                } else {
                    self.out.push(BlockStmt::Throw(value.text));
                }
            }
            "Jmp" | "JmpLong" => {
                self.statement(&mut []);
                match target_at(&inst, 0) {
                    Some(target) => self.out.push(BlockStmt::Jump(target)),
                    None => self.decline(position),
                }
            }
            "JmpTrue" | "JmpTrueLong" | "JmpFalse" | "JmpFalseLong" | "JmpUndefined"
            | "JmpUndefinedLong" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 1))];
                self.statement(&mut operands);
                let [operand] = operands;
                if operand.duplicable && matches!(operand.text.as_str(), "true" | "false") {
                    let taken: bool = (operand.text == "true") == name.starts_with("JmpTrue");
                    let end: usize = inst.offset + inst.size;
                    let next: Option<usize> = if taken {
                        target_at(&inst, 0)
                    } else {
                        Some(end)
                    };
                    match next {
                        Some(next) => self.out.push(BlockStmt::Jump(next)),
                        None => self.decline(position),
                    }
                    return;
                }
                let text: String = if name.starts_with("JmpTrue") {
                    operand.text
                } else if name.starts_with("JmpFalse") {
                    format!("!{}", operand.operand_text())
                } else {
                    format!("{} === undefined", operand.operand_text())
                };
                self.push_cond_jump(position, target_at(&inst, 0), text);
            }
            "SwitchImm" => {
                let mut operands: [Value; 1] = [self.read(reg_at(&inst, 0))];
                self.statement(&mut operands);
                let [scrutinee] = operands;
                let cases: Vec<(i64, usize)> = switch_table_entries(
                    &self.module().raw_image,
                    self.input.code_base,
                    inst.offset,
                    uint_at(&inst, 1),
                    uint_at(&inst, 3),
                    uint_at(&inst, 4),
                );
                let default: usize = target_at(&inst, 2).unwrap_or(usize::MAX);
                self.out.push(BlockStmt::Switch {
                    scrutinee: scrutinee.text,
                    cases,
                    default,
                });
            }
            _ => self.unrecovered(position),
        }
    }

    fn resume_point(&self, target: usize) -> Option<(usize, &Instruction)> {
        let block: usize = *self.input.cfg.offset_to_block.get(&target)?;
        let first: usize = self.input.cfg.blocks.get(block)?.instr_range.0;
        let inst: &Instruction = self.input.instructions.get(first)?;
        (inst.name == "ResumeGenerator").then_some((first, inst))
    }

    fn lift_yield(&mut self, position: usize, inst: &Instruction) {
        let Some(target) = self.pending_yield.take() else {
            return;
        };
        let Some((resume, dest, flag_reg)) = self
            .resume_point(target)
            .map(|(at, resume): (usize, &Instruction)| (at, reg_at(resume, 0), reg_at(resume, 1)))
        else {
            self.unrecovered(position);
            return;
        };
        let info: DefInfo = self
            .analysis
            .defs
            .get(&(resume, dest))
            .copied()
            .unwrap_or(DefInfo {
                uses: 1,
                live_out: true,
            });
        let mut operands: [Value; 1] = [self.read(reg_at(inst, 0))];
        self.statement(&mut operands);
        let [value] = operands;
        let delegated: bool = self.analysis.patterns.delegated_resumes.contains(&resume);
        let plain: bool = self.returns_plainly(resume);
        if !delegated && plain {
            let yielded: String = if value.text == "undefined" && value.duplicable {
                "yield".to_owned()
            } else {
                format!("yield {}", value.text)
            };
            if info.uses == 0 && !info.live_out {
                self.push_expression(&yielded);
            } else {
                let name: String = self.force_var(dest);
                self.push_expression(&format!("{name} = {yielded}"));
            }
            self.out.push(BlockStmt::Jump(target));
            return;
        }
        self.uses_helper(Helper::YieldResume);
        let resumed: String = format!("yield* $yieldResume({}, {delegated})", value.text);
        let caught: &str =
            "catch ($signal) { if (!($signal instanceof $YieldReturn)) throw $signal;";
        let text: String = if plain {
            let body: String = if info.uses == 0 && !info.live_out {
                format!("{resumed};")
            } else {
                format!("{} = {resumed};", self.force_var(dest))
            };
            format!("try {{ {body} }} {caught} return $signal.value; }}")
        } else {
            let name: String = self.force_var(dest);
            let flag: String = self.force_var(flag_reg);
            format!(
                "try {{ {name} = {resumed}; {flag} = false; }} {caught} {name} = $signal.value; {flag} = true; }}"
            )
        };
        self.push_raw(text);
        self.out.push(BlockStmt::Jump(target));
    }

    fn returns_plainly(&self, resume: usize) -> bool {
        self.analysis.patterns.plain_returns.contains(&resume)
            || u32::try_from(self.input.index)
                .is_ok_and(|fid: u32| self.scope().async_bodies.contains(&fid))
    }

    fn lift_resume(&mut self, position: usize, inst: &Instruction) {
        let flag: u32 = reg_at(inst, 1);
        let block_start: usize = self
            .input
            .cfg
            .blocks
            .get(self.block)
            .map_or(position, |b: &BasicBlock| b.instr_range.0);
        let after_start: bool = self.input.instructions[block_start..position]
            .iter()
            .any(|inst: &Instruction| inst.name == "StartGenerator");
        if after_start {
            let undefined: Value = Value::constant("undefined".to_owned(), Form::Ident);
            self.define(position, reg_at(inst, 0), undefined);
        }
        if self.returns_plainly(position) {
            let flag_value: Value = Value::constant("false".to_owned(), Form::Ident);
            self.define(position, flag, flag_value);
        } else if after_start {
            self.decline(position);
        }
    }

    fn push_cond_jump(&mut self, position: usize, target: Option<usize>, cond: String) {
        let Some(target) = target else {
            self.decline(position);
            return;
        };
        let inst: &Instruction = &self.input.instructions[position];
        let end: usize = inst.offset + inst.size;
        let fallthrough: Option<usize> = self
            .input
            .cfg
            .offset_to_block
            .contains_key(&end)
            .then_some(end);
        self.out.push(BlockStmt::CondJump {
            cond,
            target,
            fallthrough,
        });
    }

    fn env_var(&self, env_reg: u32, slot: u64) -> Option<String> {
        let env: EnvRef = self.env_of(env_reg)?;
        Some(match env {
            EnvRef::Owned(owner) => self.scope().env_name(EnvRefName::Owned(owner), slot),
            EnvRef::Unknown(level) => self.scope().env_name(EnvRefName::Unknown(level), slot),
        })
    }

    fn global_binding(&self, object: &Value, name: &str, is_try: bool) -> bool {
        object.shape == Shape::Global
            && is_binding_identifier(name)
            && (is_try || self.scope().declared_globals.contains(name))
    }

    fn global_target(&self, object: &Value, id: u32, is_try: bool) -> String {
        let name: String = self.string(id).unwrap_or_default();
        if self.global_binding(object, &name, is_try) {
            return name;
        }
        format!("{}{}", object.object_text(), property_suffix(&name))
    }

    fn lift_get_by_id(&mut self, position: usize, inst: &Instruction) {
        let object: Value = self.read(reg_at(inst, 1));
        let name: String = self.string(string_at(inst, 3)).unwrap_or_default();
        let is_try: bool = inst.name.starts_with("Try");
        if self.global_binding(&object, &name, is_try) {
            let mut value: Value = Value::new(name.clone(), Form::Ident);
            if name == "HermesInternal" {
                value.shape = Shape::HermesInternal;
            } else {
                value.effects.push(self.effect());
                value.shape = Shape::BareGlobal;
            }
            self.define(position, reg_at(inst, 0), value);
            return;
        }
        let internal: bool = object.shape == Shape::HermesInternal;
        let global_internal: bool = object.shape == Shape::Global && name == "HermesInternal";
        let mut operands: [Value; 1] = [object];
        let effects: Vec<u64> = self.compose(&mut operands, !(internal || global_internal));
        let suffix: String = property_suffix(&name);
        let text: String = format!("{}{suffix}", operands[0].object_text());
        let mut value: Value = Self::finish(text, Form::Member, &operands, effects);
        if internal {
            value.shape = Shape::HermesInternalMethod(name);
        } else if global_internal {
            value.shape = Shape::HermesInternal;
        } else if self.analysis.patterns.method_loads.contains_key(&position) {
            let [object] = operands;
            value.shape = Shape::Member {
                object: Box::new(object),
                key: suffix,
            };
        }
        self.define(position, reg_at(inst, 0), value);
    }

    fn read_builder_object(&mut self, position: usize, reg: u32) -> Value {
        if !self.analysis.patterns.builders.contains(&position) {
            return self.read(reg);
        }
        if let Some(RegState::Pending(_)) = self.regs.get(&reg) {
            self.flush_reg(reg);
        }
        match self.regs.get(&reg).cloned() {
            Some(RegState::Const(value)) => value,
            _ => self.var_value(reg),
        }
    }

    fn lift_builder_put(&mut self, position: usize, inst: &Instruction, key: BuilderKey) {
        let object_reg: u32 = reg_at(inst, 0);
        let foldable: bool = self.analysis.patterns.builders.contains(&position)
            && matches!(
                self.regs.get(&object_reg),
                Some(RegState::Pending(Value {
                    shape: Shape::FreshArray { .. } | Shape::FreshObject { .. },
                    ..
                }))
            );
        if foldable {
            let Some(RegState::Pending(mut object)) = self.regs.remove(&object_reg) else {
                return;
            };
            object.origin = Some(object_reg);
            let mut operands: Vec<Value> = vec![object];
            if matches!(key, BuilderKey::Computed) {
                operands.push(self.read(reg_at(inst, 2)));
            }
            operands.push(self.read(reg_at(inst, 1)));
            let effects: Vec<u64> = self.compose(&mut operands, false);
            let value_text: String = operands[operands.len() - 1].text.clone();
            let key_text: Option<String> =
                matches!(key, BuilderKey::Computed).then(|| operands[1].text.clone());
            let mut object: Value = operands[0].clone();
            let appended: bool = match (&mut object.shape, &key) {
                (Shape::FreshArray { elems, len }, BuilderKey::Index(index)) => {
                    let index: u64 = *index;
                    if index >= elems.len() as u64 && index < MAX_LITERAL_ELEMENTS {
                        while (elems.len() as u64) < index {
                            elems.push(None);
                        }
                        elems.push(Some(value_text.clone()));
                        *len = (*len).max(index + 1);
                        true
                    } else {
                        false
                    }
                }
                (Shape::FreshObject { props }, BuilderKey::Named(name)) => {
                    props.push(format!("{}: {value_text}", object_key(name)));
                    true
                }
                (Shape::FreshObject { props }, BuilderKey::Computed) => {
                    props.push(format!(
                        "[{}]: {value_text}",
                        key_text.clone().unwrap_or_default()
                    ));
                    true
                }
                _ => false,
            };
            if appended {
                object.text = match &object.shape {
                    Shape::FreshArray { elems, len } => render_array(elems, *len),
                    Shape::FreshObject { props } => render_object(props),
                    _ => object.text.clone(),
                };
                for operand in &operands[1..] {
                    object.deps.extend(operand.deps.iter().copied());
                }
                object.effects = effects;
                self.regs.insert(object_reg, RegState::Pending(object));
                if self
                    .deferred
                    .get(&object_reg)
                    .and_then(|def: &usize| self.analysis.patterns.builder_last.get(def))
                    == Some(&position)
                {
                    self.settle(object_reg);
                }
                return;
            }
            self.deferred.remove(&object_reg);
            if matches!(
                operands[0].shape,
                Shape::FreshArray { .. } | Shape::FreshObject { .. }
            ) {
                self.regs
                    .insert(object_reg, RegState::Pending(operands[0].clone()));
                self.flush_reg(object_reg);
                operands[0] = self.var_value(object_reg);
            } else {
                self.regs.insert(object_reg, RegState::Var);
            }
            self.statement(&mut operands);
            self.push_define(&operands[0].text, &key, key_text.as_deref(), &value_text);
            return;
        }
        let object: Value = self.read_builder_object(position, object_reg);
        let mut operands: Vec<Value> = vec![object];
        if matches!(key, BuilderKey::Computed) {
            operands.push(self.read(reg_at(inst, 2)));
        }
        operands.push(self.read(reg_at(inst, 1)));
        self.statement(&mut operands);
        let value_text: String = operands[operands.len() - 1].text.clone();
        let key_text: Option<String> =
            matches!(key, BuilderKey::Computed).then(|| operands[1].text.clone());
        let object_text: String = operands[0].text.clone();
        self.push_define(&object_text, &key, key_text.as_deref(), &value_text);
    }

    fn push_define(&mut self, object: &str, key: &BuilderKey, computed: Option<&str>, value: &str) {
        let key_text: String = match (key, computed) {
            (BuilderKey::Index(index), _) => index.to_string(),
            (BuilderKey::Named(name), _) => js_string_literal(name),
            (BuilderKey::Computed, Some(text)) => text.to_owned(),
            (BuilderKey::Computed, None) => "undefined".to_owned(),
        };
        self.push_expression(&format!(
            "Object.defineProperty({object}, {key_text}, {{ value: {value}, writable: true, enumerable: true, configurable: true }})"
        ));
    }

    fn lift_call(&mut self, position: usize, inst: &Instruction) {
        let callee: Value = self.read(reg_at(inst, 1));
        let window: Option<(u32, Vec<u32>)> =
            if matches!(&*inst.name, "Call1" | "Call2" | "Call3" | "Call4") {
                Some((
                    reg_at(inst, 2),
                    (3..inst.operands.len())
                        .map(|i: usize| reg_at(inst, i))
                        .collect(),
                ))
            } else {
                call_window(self.input.header.frame_size, uint_at(inst, 2))
                    .map(|w: Vec<u32>| (w[0], w[1..].to_vec()))
            };
        let Some((this_reg, arg_regs)) = window else {
            self.unrecovered_call(position, callee);
            return;
        };
        let method: Option<MethodCall> =
            self.analysis.patterns.method_calls.get(&position).copied();
        let this_value: Option<Value> = self.read_at(position, this_reg);
        let mut args: Vec<Value> = arg_regs.iter().map(|r: &u32| self.read(*r)).collect();
        if matches!(&callee.shape, Shape::HermesInternalMethod(n) if n == "concat")
            && let Some(first) = this_value.clone()
        {
            let mut operands: Vec<Value> = vec![callee, first];
            operands.append(&mut args);
            let effects: Vec<u64> = self.compose(&mut operands, true);
            let text: String = template_literal(&operands[1..]);
            let value: Value = Self::finish(text, Form::Literal, &operands, effects);
            self.define(position, reg_at(inst, 0), value);
            return;
        }
        let method_form: bool = method.is_some()
            && matches!(
                callee.shape,
                Shape::Member { .. } | Shape::HermesInternalMethod(_)
            );
        let explicit_this: Option<Value> = match (this_value, method) {
            (Some(value), _) => Some(value),
            (None, Some(MethodCall { object })) if !method_form => Some(self.read(object)),
            (None, _) => None,
        };
        let this_undefined: bool = explicit_this
            .as_ref()
            .is_some_and(|v: &Value| v.text == "undefined" && v.duplicable);
        let mut operands: Vec<Value> = vec![callee];
        let with_this: bool = explicit_this.is_some() && !this_undefined;
        if let Some(this_value) = explicit_this.filter(|_| with_this) {
            operands.push(this_value);
        }
        operands.append(&mut args);
        let effects: Vec<u64> = self.compose(&mut operands, true);
        let arg_start: usize = if with_this { 2 } else { 1 };
        let arg_texts: Vec<String> = operands[arg_start..]
            .iter()
            .map(|v: &Value| v.text.clone())
            .collect();
        let callee_value: &Value = &operands[0];
        let callee_is_member: bool = callee_value.form == Form::Member;
        let text: String = if method_form && callee_is_member {
            format!("{}({})", callee_value.text, arg_texts.join(", "))
        } else if with_this {
            let mut all: Vec<String> = vec![operands[1].text.clone()];
            all.extend(arg_texts);
            format!("{}.call({})", callee_value.object_text(), all.join(", "))
        } else if callee_is_member {
            format!("(0, {})({})", callee_value.text, arg_texts.join(", "))
        } else {
            format!("{}({})", callee_value.object_text(), arg_texts.join(", "))
        };
        let value: Value = Self::finish(text, Form::Call, &operands, effects);
        self.define(position, reg_at(inst, 0), value);
    }

    fn unrecovered_call(&mut self, position: usize, callee: Value) {
        self.decline(position);
        self.uses_helper(Helper::Unrecovered);
        let mut operands: [Value; 1] = [callee];
        let effects: Vec<u64> = self.compose(&mut operands, true);
        let text: String = format!("$unrecovered(\"call\", {})", operands[0].text);
        let value: Value = Self::finish(text, Form::Call, &operands, effects);
        let dest: u32 = reg_at(&self.input.instructions[position], 0);
        self.define(position, dest, value);
    }

    fn lift_new(&mut self, position: usize, inst: &Instruction) {
        let callee: Value = self.read(reg_at(inst, 1));
        let Some(window) = call_window(self.input.header.frame_size, uint_at(inst, 2)) else {
            self.unrecovered_call(position, callee);
            return;
        };
        let mut operands: Vec<Value> = vec![callee];
        for reg in &window[1..] {
            operands.push(self.read(*reg));
        }
        if inst.name == "ConstructWithNewTarget" {
            operands.push(self.read(reg_at(inst, 3)));
        }
        let effects: Vec<u64> = self.compose(&mut operands, true);
        let joined = |args: &[Value]| -> String {
            args.iter()
                .map(|v: &Value| v.text.clone())
                .collect::<Vec<String>>()
                .join(", ")
        };
        let text: String = match (inst.name == "ConstructWithNewTarget", operands.as_slice()) {
            (true, [callee, args @ .., new_target]) => format!(
                "Reflect.construct({}, [{}], {})",
                callee.text,
                joined(args),
                new_target.text
            ),
            (_, [callee, args @ ..]) => {
                format!("new {}({})", callee.new_callee_text(), joined(args))
            }
            (_, []) => {
                self.unrecovered(position);
                return;
            }
        };
        let mut value: Value = Self::finish(text, Form::Member, &operands, effects);
        value.call_free = false;
        self.define(position, reg_at(inst, 0), value);
    }

    fn lift_call_builtin(&mut self, position: usize, inst: &Instruction) {
        if self.analysis.patterns.delegate_marks.contains(&position) {
            if let Some(this) = call_window(self.input.header.frame_size, uint_at(inst, 2))
                .and_then(|window: Vec<u32>| window.first().copied())
            {
                let _ = self.read_at(position, this);
            }
            let undefined: Value = Value::constant("undefined".to_owned(), Form::Ident);
            self.define(position, reg_at(inst, 0), undefined);
            return;
        }
        let id: u64 = uint_at(inst, 1);
        let builtin: String = super::builtins::builtin_name(self.module().header.version, id);
        let Some(window) = call_window(self.input.header.frame_size, uint_at(inst, 2)) else {
            self.unrecovered(position);
            return;
        };
        let _ = self.read_at(position, window[0]);
        let mut operands: Vec<Value> = window[1..].iter().map(|r: &u32| self.read(*r)).collect();
        let effects: Vec<u64> = self.compose(&mut operands, true);
        let args: Vec<String> = operands.iter().map(|v: &Value| v.text.clone()).collect();
        let joined: String = args.join(", ");
        let helper_call = |helper: Helper, name: &str| -> (Option<Helper>, Option<String>) {
            (Some(helper), Some(format!("{name}({joined})")))
        };
        let (helper, text): (Option<Helper>, Option<String>) = match private_builtin(&builtin) {
            None if builtin.starts_with('$') => (None, None),
            None => (None, Some(format!("{builtin}({joined})"))),
            Some("silentSetPrototypeOf") => {
                helper_call(Helper::SilentSetPrototypeOf, "$silentSetPrototypeOf")
            }
            Some("getTemplateObject") => helper_call(Helper::TemplateObject, "$getTemplateObject"),
            Some("ensureObject") => helper_call(Helper::EnsureObject, "$ensureObject"),
            Some("getMethod") => helper_call(Helper::GetMethod, "$getMethod"),
            Some("throwTypeError") => helper_call(Helper::ThrowTypeError, "$throwTypeError"),
            Some("throwReferenceError") => {
                helper_call(Helper::ThrowReferenceError, "$throwReferenceError")
            }
            Some("setFunctionName") => helper_call(Helper::SetFunctionName, "$setFunctionName"),
            Some("applyArguments") => match operands.as_slice() {
                [callee, this_value, new_target]
                    if new_target.duplicable && new_target.text == "undefined" =>
                {
                    (
                        None,
                        Some(format!(
                            "Reflect.apply({}, {}, arguments)",
                            callee.text, this_value.text
                        )),
                    )
                }
                _ => (None, None),
            },
            Some("copyDataProperties") => {
                helper_call(Helper::CopyDataProperties, "$copyDataProperties")
            }
            Some("arraySpread") => helper_call(Helper::ArraySpread, "$arraySpread"),
            Some("exportAll") => helper_call(Helper::ExportAll, "$exportAll"),
            Some("copyRestArgs") => (
                None,
                Some(format!("Array.prototype.slice.call(arguments, {joined})")),
            ),
            Some("apply") => match args.as_slice() {
                [callee, list] => (None, Some(format!("Reflect.construct({callee}, {list})"))),
                [callee, list, this_value, ..] => (
                    None,
                    Some(format!("Reflect.apply({callee}, {this_value}, {list})")),
                ),
                _ => (None, None),
            },
            Some("exponentiationOperator") => match operands.as_slice() {
                [base, exponent] => (
                    None,
                    Some(format!(
                        "({} ** {})",
                        exponent_operand(base),
                        exponent_operand(exponent)
                    )),
                ),
                _ => (None, None),
            },
            Some(_) => (None, None),
        };
        if let Some(helper) = helper {
            self.uses_helper(helper);
        }
        let value: Value = match text {
            Some(text) => {
                let form: Form = if text.starts_with('(') {
                    Form::Paren
                } else {
                    Form::Call
                };
                Self::finish(text, form, &operands, effects)
            }
            None => {
                self.decline(position);
                self.uses_helper(Helper::Unrecovered);
                let text: String = format!(
                    "$unrecovered({}{}{joined})",
                    js_string_literal(&builtin),
                    if joined.is_empty() { "" } else { ", " }
                );
                Self::finish(text, Form::Call, &operands, effects)
            }
        };
        self.define(position, reg_at(inst, 0), value);
    }

    fn constructs_with_undefined_this(&self, inst: &Instruction) -> bool {
        let Some(this) = this_register(inst, self.input.header.frame_size) else {
            return false;
        };
        match self.regs.get(&this) {
            Some(RegState::Const(value) | RegState::Pending(value)) => {
                value.duplicable && value.text == "undefined"
            }
            Some(_) => false,
            None => self
                .analysis
                .const_uses
                .get(&(self.position, this))
                .and_then(|site: &usize| self.input.instructions.get(*site))
                .is_some_and(|def: &Instruction| def.name == "LoadConstUndefined"),
        }
    }

    fn closure_value(&self, env_reg: u32, marker: String) -> Value {
        let own: u32 = u32::try_from(self.input.index).unwrap_or(u32::MAX);
        if self.env_of(env_reg) == Some(EnvRef::Owned(own)) && self.scope().is_boxed(own) {
            let name: String = ModuleScope::boxed_env_name(own);
            return Value::new(
                format!("(function ({name}) {{ return {marker}; }})({name})"),
                Form::Call,
            );
        }
        Value::new(marker, Form::Function)
    }

    fn literal_format(&self) -> LiteralFormat {
        LiteralFormat::for_version(self.module().header.version)
    }

    fn type_of_is(&mut self, value: &Value, mask: u64) -> String {
        const NAMES: [(u64, &str); 7] = [
            (0, "undefined"),
            (2, "string"),
            (3, "symbol"),
            (4, "boolean"),
            (5, "number"),
            (6, "bigint"),
            (7, "function"),
        ];
        for (bit, name) in NAMES {
            if mask == 1 << bit {
                return format!("typeof {} === \"{name}\"", value.operand_text());
            }
        }
        if mask == 1 << 8 {
            return format!("{} === null", value.operand_text());
        }
        self.uses_helper(Helper::TypeOfIs);
        format!("$typeOfIs({}, {mask})", value.text)
    }

    fn keyed_props(&self, keys: &[LiteralValue], value_index: usize) -> Vec<String> {
        let values: Vec<String> = self.buffer_values(keys.len(), value_index, BufferSource::Array);
        self.render_props(keys, &values)
    }

    fn buffer_object_props(
        &self,
        count: usize,
        key_index: usize,
        value_index: usize,
    ) -> Vec<String> {
        let keys: Vec<LiteralValue> = decode_literals_in(
            self.literal_format(),
            &self.module().obj_key_buffer,
            key_index,
            count,
            BufferKind::Key,
        );
        let values: Vec<String> =
            self.buffer_values(count, value_index, BufferSource::ObjectValues);
        self.render_props(&keys, &values)
    }

    fn render_props(&self, keys: &[LiteralValue], values: &[String]) -> Vec<String> {
        keys.iter()
            .enumerate()
            .map(|(index, key): (usize, &LiteralValue)| {
                let key_text: String = match key {
                    LiteralValue::StringId(id) => object_key(&self.string(*id).unwrap_or_default()),
                    LiteralValue::Integer(i) => i.to_string(),
                    LiteralValue::Number(n) => js_string_literal(&js_number_key(*n)),
                    LiteralValue::Bool(b) => b.to_string(),
                    LiteralValue::Null | LiteralValue::PrivateName => "null".to_owned(),
                    LiteralValue::Undefined => "undefined".to_owned(),
                };
                let value: String = values
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| "undefined".to_owned());
                format!("{key_text}: {value}")
            })
            .collect()
    }

    fn buffer_values(&self, count: usize, index: usize, source: BufferSource) -> Vec<String> {
        let buffer: &[u8] = match source {
            BufferSource::Array => &self.module().array_buffer,
            BufferSource::ObjectValues => &self.module().obj_value_buffer,
        };
        decode_literals_in(
            self.literal_format(),
            buffer,
            index,
            count,
            BufferKind::Value,
        )
        .iter()
        .map(|value: &LiteralValue| match value {
            LiteralValue::Null => "null".to_owned(),
            LiteralValue::PrivateName | LiteralValue::Undefined => "undefined".to_owned(),
            LiteralValue::Bool(b) => b.to_string(),
            LiteralValue::Number(n) => js_number(*n),
            LiteralValue::Integer(i) => i.to_string(),
            LiteralValue::StringId(id) => self.string_literal(*id),
        })
        .collect()
    }

    fn regexp_literal(&self, pattern_id: u32, flags_id: u32, index: u64) -> String {
        let recovered: Option<super::regex::RecoveredRegExp> =
            usize::try_from(index).ok().and_then(|index: usize| {
                super::regex::recover_regexp(
                    &self.module().reg_exp_table,
                    &self.module().reg_exp_storage,
                    index,
                )
            });
        let stored: String = self.string(pattern_id).unwrap_or_default();
        let pattern: String = if stored.is_empty() {
            recovered
                .as_ref()
                .map(|r: &super::regex::RecoveredRegExp| r.pattern.clone())
                .unwrap_or_default()
        } else {
            stored
        };
        let flags: String = self
            .string(flags_id)
            .filter(|f: &String| !f.is_empty())
            .unwrap_or_else(|| {
                recovered
                    .map(|r: super::regex::RecoveredRegExp| r.flags)
                    .unwrap_or_default()
            });
        let body: String = if pattern.is_empty() {
            "(?:)".to_owned()
        } else {
            escape_regexp_source(&pattern)
        };
        format!("/{body}/{flags}")
    }
}

#[derive(Debug, Clone, Copy)]
enum BufferSource {
    Array,
    ObjectValues,
}

#[derive(Debug, Clone)]
enum BuilderKey {
    Named(String),
    Index(u64),
    Computed,
}

fn private_builtin(name: &str) -> Option<&str> {
    name.strip_prefix("HermesBuiltin.")
        .or_else(|| name.strip_prefix("HermesInternal."))
}

fn exponent_operand(value: &Value) -> String {
    match value.form {
        Form::Unary | Form::Function => format!("({})", value.text),
        _ => value.text.clone(),
    }
}

fn binary_operator(name: &str) -> Option<(&'static str, bool)> {
    Some(match name {
        "Add" => ("+", false),
        "AddN" => ("+", true),
        "Sub" => ("-", false),
        "SubN" => ("-", true),
        "Mul" => ("*", false),
        "MulN" => ("*", true),
        "Div" => ("/", false),
        "DivN" => ("/", true),
        "Mod" => ("%", false),
        "Eq" => ("==", false),
        "Neq" => ("!=", false),
        "StrictEq" => ("===", true),
        "StrictNeq" => ("!==", true),
        "Less" => ("<", false),
        "LessEq" => ("<=", false),
        "Greater" => (">", false),
        "GreaterEq" => (">=", false),
        "LShift" => ("<<", false),
        "RShift" => (">>", false),
        "URshift" => (">>>", false),
        "BitAnd" => ("&", false),
        "BitOr" => ("|", false),
        "BitXor" => ("^", false),
        "InstanceOf" => ("instanceof", false),
        "IsIn" => ("in", false),
        _ => return None,
    })
}

pub(crate) fn jump_condition(name: &str) -> Option<(&'static str, bool)> {
    let base: &str = name.trim_end_matches("Long").trim_end_matches('N');
    Some(match base {
        "JLess" => ("<", false),
        "JNotLess" => ("<", true),
        "JLessEqual" => ("<=", false),
        "JNotLessEqual" => ("<=", true),
        "JGreater" => (">", false),
        "JNotGreater" => (">", true),
        "JGreaterEqual" => (">=", false),
        "JNotGreaterEqual" => (">=", true),
        "JEqual" => ("==", false),
        "JNotEqual" => ("==", true),
        "JStrictEqual" => ("===", false),
        "JStrictNotEqual" => ("===", true),
        _ => return None,
    })
}

pub(crate) fn closure_marker(fid: u32) -> String {
    format!("{CLOSURE_MARK}F{fid}{CLOSURE_MARK}")
}

fn number_value(n: f64) -> Value {
    let text: String = js_number(n);
    let form: Form = if text.starts_with('-') {
        Form::Unary
    } else if text.chars().all(|c: char| c.is_ascii_alphabetic()) {
        Form::Ident
    } else {
        Form::Number
    };
    Value::constant(text, form)
}

pub(crate) fn js_number(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_owned();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if n == 0.0 {
        return if n.is_sign_negative() { "-0" } else { "0" }.to_owned();
    }
    if n.fract() == 0.0 && n.abs() < 1e16 {
        return format!("{}", n as i64);
    }
    format!("{n:?}")
}

fn js_number_key(n: f64) -> String {
    if n == 0.0 {
        return "0".to_owned();
    }
    js_number(n)
}

pub(crate) fn js_string_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _: std::fmt::Result = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn escape_regexp_source(pattern: &str) -> String {
    let mut out: String = String::with_capacity(pattern.len());
    let mut escaped: bool = false;
    let mut in_class: bool = false;
    for c in pattern.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                out.push(c);
            }
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' => {
                in_class = false;
                out.push(c);
            }
            '/' if !in_class => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let _: std::fmt::Result = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn template_literal(parts: &[Value]) -> String {
    let mut out: String = String::from("`");
    for part in parts {
        if let Some(raw) = string_literal_contents(&part.text) {
            for c in raw.chars() {
                match c {
                    '`' => out.push_str("\\`"),
                    '$' => out.push_str("\\$"),
                    c => out.push(c),
                }
            }
        } else {
            out.push_str("${");
            out.push_str(&part.text);
            out.push('}');
        }
    }
    out.push('`');
    out
}

fn string_literal_contents(text: &str) -> Option<&str> {
    let inner: &str = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut escaped: bool = false;
    for c in inner.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return None,
            _ => {}
        }
    }
    Some(inner)
}

pub(crate) fn is_identifier_name(s: &str) -> bool {
    let mut chars: core::str::Chars<'_> = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c == '$' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c: char| c == '_' || c == '$' || c.is_ascii_alphanumeric())
}

pub(crate) fn is_binding_identifier(s: &str) -> bool {
    is_identifier_name(s) && !is_reserved_word(s)
}

fn is_reserved_word(s: &str) -> bool {
    matches!(
        s,
        "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "new"
            | "null"
            | "return"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
            | "let"
            | "static"
            | "implements"
            | "interface"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "await"
            | "arguments"
            | "eval"
    )
}

fn property_suffix(name: &str) -> String {
    if is_identifier_name(name) {
        format!(".{name}")
    } else {
        format!("[{}]", js_string_literal(name))
    }
}

fn object_key(name: &str) -> String {
    if name == "__proto__" {
        return "[\"__proto__\"]".to_owned();
    }
    if is_identifier_name(name) {
        name.to_owned()
    } else {
        js_string_literal(name)
    }
}

fn render_object(props: &[String]) -> String {
    if props.is_empty() {
        "{}".to_owned()
    } else {
        format!("{{ {} }}", props.join(", "))
    }
}

fn render_array(elems: &[Option<String>], len: u64) -> String {
    let mut parts: Vec<&str> = elems
        .iter()
        .map(|e: &Option<String>| e.as_deref().unwrap_or(""))
        .collect();
    let holes: u64 = len
        .saturating_sub(elems.len() as u64)
        .min(MAX_LITERAL_ELEMENTS);
    parts.extend(std::iter::repeat_n("", holes as usize));
    let mut text: String = format!("[{}", parts.join(", "));
    if parts.last().is_some_and(|last: &&str| last.is_empty()) {
        text.push(',');
    }
    text.push(']');
    text
}

pub(crate) fn render_dispatcher(
    blocks: &[LiftedBlock],
    cfg: &Cfg,
    handler_of_block: &[Option<usize>],
    indent: &str,
) -> String {
    let mut out: String = String::new();
    let has_handlers: bool = handler_of_block.iter().any(Option::is_some);
    let block_of = |offset: usize| -> Option<usize> { cfg.offset_to_block.get(&offset).copied() };
    let inner: String = format!("{indent}  ");
    let case_indent: String = if has_handlers {
        format!("{inner}  ")
    } else {
        inner.clone()
    };
    let body_indent: String = format!("{case_indent}  ");
    out.push_str(indent);
    out.push_str("var $pc = 0;\n");
    out.push_str(indent);
    out.push_str("for (;;) {\n");
    if has_handlers {
        out.push_str(&inner);
        out.push_str("try {\n");
    }
    out.push_str(&case_indent);
    out.push_str("switch ($pc) {\n");
    for (index, block) in blocks.iter().enumerate() {
        let _: std::fmt::Result = writeln!(out, "{case_indent}case {index}:");
        let mut terminated: bool = false;
        for stmt in &block.stmts {
            match stmt {
                BlockStmt::Line(text) => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}{text}");
                }
                BlockStmt::Return(value) => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}return {value};");
                    terminated = true;
                }
                BlockStmt::Throw(value) => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}throw {value};");
                    terminated = true;
                }
                BlockStmt::Jump(target) => {
                    let _: std::fmt::Result =
                        writeln!(out, "{body_indent}{}", goto(block_of(*target)));
                    terminated = true;
                }
                BlockStmt::CondJump {
                    cond,
                    target,
                    fallthrough,
                } => {
                    let _: std::fmt::Result = writeln!(
                        out,
                        "{body_indent}if ({cond}) {{ {} }}",
                        goto(block_of(*target))
                    );
                    let next: Option<usize> = fallthrough.and_then(block_of);
                    let _: std::fmt::Result = writeln!(out, "{body_indent}{}", goto(next));
                    terminated = true;
                }
                BlockStmt::Switch {
                    scrutinee,
                    cases,
                    default,
                } => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}switch ({scrutinee}) {{");
                    for (value, target) in cases {
                        let _: std::fmt::Result = writeln!(
                            out,
                            "{body_indent}  case {value}: {}",
                            goto(block_of(*target))
                        );
                    }
                    let _: std::fmt::Result =
                        writeln!(out, "{body_indent}  default: {}", goto(block_of(*default)));
                    let _: std::fmt::Result = writeln!(out, "{body_indent}}}");
                    terminated = true;
                }
            }
        }
        if !terminated {
            let next: Option<usize> = cfg
                .blocks
                .get(index)
                .and_then(|b: &BasicBlock| b.successors.first().copied());
            match next {
                Some(next) => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}$pc = {next}; continue;");
                }
                None => {
                    let _: std::fmt::Result = writeln!(out, "{body_indent}return;");
                }
            }
        }
    }
    let _: std::fmt::Result = writeln!(
        out,
        "{case_indent}default:\n{body_indent}throw new Error(\"hermes: control reached an unknown block\");"
    );
    out.push_str(&case_indent);
    out.push_str("}\n");
    if has_handlers {
        let _: std::fmt::Result = writeln!(out, "{inner}}} catch ($caught) {{");
        let _: std::fmt::Result = writeln!(out, "{inner}  switch ($pc) {{");
        for (index, handler) in handler_of_block.iter().enumerate() {
            if let Some(handler) = handler {
                let _: std::fmt::Result = writeln!(
                    out,
                    "{inner}    case {index}: $exc = $caught; $pc = {handler}; continue;"
                );
            }
        }
        let _: std::fmt::Result = writeln!(out, "{inner}  }}\n{inner}  throw $caught;\n{inner}}}");
    }
    out.push_str(indent);
    out.push_str("}\n");
    out
}

fn goto(block: Option<usize>) -> String {
    match block {
        Some(block) => format!("$pc = {block}; continue;"),
        None => "throw new Error(\"hermes: jump to an undecoded offset\");".to_owned(),
    }
}
