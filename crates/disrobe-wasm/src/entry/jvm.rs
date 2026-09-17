use disrobe_pass_jvm::{
    ClassFile, CodeAttribute, ConstantPoolEntry, DecompiledClass, ExceptionEntry, Instruction,
    MethodInfo, Operands, decompile_class_named, parse_classfile, parse_code_attribute,
    resolve_ref, validate_code_attribute,
};
use serde::Serialize;

const INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_METHODS: usize = 1024;
const MAX_FIELDS: usize = 4096;
const MAX_CONSTANT_POOL_SLOTS: usize = 16_384;
const MAX_INSTRUCTIONS: usize = 65_536;
const MAX_METHOD_INSTRUCTIONS: usize = 16_384;
const MAX_METHOD_EDGES: usize = 2048;

#[derive(Debug, Serialize)]
struct Field {
    name: String,
    descriptor: String,
    access_flags: u16,
}

#[derive(Debug, Serialize)]
struct Bytecode {
    pc: u32,
    mnemonic: &'static str,
    operands: Operands,
    reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum MethodCode {
    Available {
        max_stack: u16,
        max_locals: u16,
        instructions: Vec<Bytecode>,
        exceptions: Vec<ExceptionEntry>,
        dropped_exceptions: usize,
    },
    Absent,
    Invalid {
        error: String,
    },
}

#[derive(Debug, Serialize)]
struct Method {
    name: String,
    descriptor: String,
    access_flags: u16,
    code: MethodCode,
}

#[derive(Debug, Serialize)]
pub struct JvmClassResult {
    ok: bool,
    format: &'static str,
    name: String,
    superclass: Option<String>,
    source_filename: String,
    interfaces: Vec<String>,
    major_version: u16,
    minor_version: u16,
    access_flags: u16,
    constant_pool_entries: usize,
    fields: Vec<Field>,
    methods: Vec<Method>,
    decompiled: DecompiledClass,
}

fn method_code(
    class: &ClassFile,
    method: &MethodInfo,
    remaining: &mut usize,
) -> Result<MethodCode, String> {
    let mut code_bytes: Option<&[u8]> = None;
    for attribute in &method.attributes {
        let name: &str = match class.utf8_at(attribute.name_index) {
            Ok(name) => name,
            Err(error) => {
                return Ok(MethodCode::Invalid {
                    error: error.to_string(),
                });
            }
        };
        if name == "Code" {
            if code_bytes.is_some() {
                return Ok(MethodCode::Invalid {
                    error: "duplicate Code attribute".to_owned(),
                });
            }
            code_bytes = Some(&attribute.info);
        }
    }
    let Some(info) = code_bytes else {
        return Ok(MethodCode::Absent);
    };
    let code: CodeAttribute = match parse_code_attribute(info) {
        Ok(code) => code,
        Err(error) => {
            return Ok(MethodCode::Invalid {
                error: error.to_string(),
            });
        }
    };
    if code.exception_table.len() > 256 {
        return Err("A JVM method exceeds the browser limit of 256 exception handlers.".to_owned());
    }
    let instructions: Vec<Instruction> = match validate_code_attribute(class, &code) {
        Ok(instructions) => instructions,
        Err(error) => {
            return Ok(MethodCode::Invalid {
                error: error.to_string(),
            });
        }
    };
    if instructions.len() > MAX_METHOD_INSTRUCTIONS || instructions.len() > *remaining {
        return Err("JVM bytecode exceeds the browser limit of 16,384 instructions per method or 65,536 per class.".to_owned());
    }
    *remaining -= instructions.len();
    let edges: usize = instructions
        .iter()
        .map(|instruction: &Instruction| match &instruction.operands {
            Operands::Branch(_) => 1,
            Operands::TableSwitch { offsets, .. } => offsets.len() + 1,
            Operands::LookupSwitch { pairs, .. } => pairs.len() + 1,
            _ => 0,
        })
        .sum();
    if edges > MAX_METHOD_EDGES {
        return Err("A JVM method exceeds the browser limit of 2048 branch targets.".to_owned());
    }
    let listing: Vec<Bytecode> = instructions
        .into_iter()
        .map(|instruction: Instruction| {
            let reference: Option<String> = match instruction.operands {
                Operands::ConstPool(index)
                | Operands::InvokeDynamic(index)
                | Operands::InvokeInterface { index, .. }
                | Operands::MultiANewArray { index, .. } => resolve_ref(class, index),
                _ => None,
            };
            Bytecode {
                pc: instruction.pc,
                mnemonic: instruction.mnemonic,
                operands: instruction.operands,
                reference,
            }
        })
        .collect();
    Ok(MethodCode::Available {
        max_stack: code.max_stack,
        max_locals: code.max_locals,
        instructions: listing,
        exceptions: code.exception_table,
        dropped_exceptions: code.dropped_exception_entries,
    })
}

pub fn analyze(bytes: &[u8]) -> Result<JvmClassResult, String> {
    if bytes.len() > INPUT_BYTES {
        return Err("JVM class recovery accepts files up to 8 MiB.".to_owned());
    }
    let class: ClassFile = parse_classfile(bytes).map_err(|error| error.to_string())?;
    if class.methods.len() > MAX_METHODS
        || class.fields.len() > MAX_FIELDS
        || class.constant_pool.len() > MAX_CONSTANT_POOL_SLOTS
    {
        return Err("JVM class metadata exceeds the browser limits of 1024 methods, 4096 fields or 16,384 constant-pool slots.".to_owned());
    }
    let name: String = class
        .this_class_name()
        .map_err(|error| error.to_string())?
        .to_owned();
    let superclass: Option<String> = if class.super_class == 0 {
        None
    } else {
        Some(
            class
                .class_name(class.super_class)
                .map_err(|error| error.to_string())?
                .to_owned(),
        )
    };
    let interfaces: Vec<String> = class
        .interfaces
        .iter()
        .map(|&index| {
            class
                .class_name(index)
                .map(str::to_owned)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<_, _>>()?;
    let fields: Vec<Field> = class
        .fields
        .iter()
        .map(|field| {
            Ok(Field {
                name: class
                    .utf8_at(field.name_index)
                    .map_err(|error| error.to_string())?
                    .to_owned(),
                descriptor: class
                    .utf8_at(field.descriptor_index)
                    .map_err(|error| error.to_string())?
                    .to_owned(),
                access_flags: field.access_flags,
            })
        })
        .collect::<Result<_, String>>()?;
    let mut remaining: usize = MAX_INSTRUCTIONS;
    let mut methods: Vec<Method> = Vec::with_capacity(class.methods.len());
    for method in &class.methods {
        methods.push(Method {
            name: class
                .utf8_at(method.name_index)
                .map_err(|error| error.to_string())?
                .to_owned(),
            descriptor: class
                .utf8_at(method.descriptor_index)
                .map_err(|error| error.to_string())?
                .to_owned(),
            access_flags: method.access_flags,
            code: method_code(&class, method, &mut remaining)?,
        });
    }
    let (source_filename, decompiled): (String, DecompiledClass) = decompile_class_named(&class);
    if decompiled.source.len() > 8 * 1024 * 1024 {
        return Err("Recovered Java source exceeds the 8 MiB output limit.".to_owned());
    }
    Ok(JvmClassResult {
        ok: true,
        format: "jvm-class",
        name,
        superclass,
        source_filename,
        interfaces,
        major_version: class.major_version,
        minor_version: class.minor_version,
        access_flags: class.access_flags,
        constant_pool_entries: class
            .constant_pool
            .iter()
            .filter(|entry| !matches!(entry, ConstantPoolEntry::Placeholder))
            .count(),
        fields,
        methods,
        decompiled,
    })
}

#[cfg(test)]
mod tests {
    use super::{INPUT_BYTES, JvmClassResult, MAX_INSTRUCTIONS, MethodCode, analyze, method_code};
    use disrobe_pass_jvm::{
        ClassFile, ConstantPoolEntry, decompile_class, decompile_class_named, parse_classfile,
    };

    const DIRECT: &[u8] = include_bytes!(
        "../../../disrobe-pass-jvm/tests/fixtures/implementors/classes/Direct.class"
    );
    const SHAPES: &[u8] = include_bytes!(
        "../../../disrobe-pass-jvm/tests/fixtures/browser_shapes/BrowserShapes.class"
    );

    #[test]
    fn real_constants_and_bodyless_methods_match_javap() -> Result<(), String> {
        let result: JvmClassResult = analyze(SHAPES)?;
        assert_eq!(result.constant_pool_entries, 43);
        assert_eq!(result.fields.len(), 2);
        assert_eq!(result.methods.len(), 5);
        for name in ["absent", "nativeCall"] {
            let method = result
                .methods
                .iter()
                .find(|method| method.name == name)
                .ok_or("missing bodyless method")?;
            assert!(matches!(method.code, MethodCode::Absent));
        }
        assert!(result.decompiled.source.contains("9007199254740993L"));
        assert!(result.decompiled.source.contains("1.25e0"));
        assert_eq!(result.decompiled.fully_lifted_methods, 3);
        assert_eq!(result.decompiled.fallback_methods, 0);
        assert_eq!(result.decompiled.decode_error_count, 0);
        Ok(())
    }

    #[test]
    fn source_filename_matches_rewritten_class_identifier() -> Result<(), String> {
        for replacement in ["keyword/class", "unicode/Δelta", "illegal/12-start"] {
            let mut class: ClassFile =
                parse_classfile(DIRECT).map_err(|error| error.to_string())?;
            let entry: &mut ConstantPoolEntry = class.constant_pool.iter_mut().find(|entry| matches!(entry, ConstantPoolEntry::Utf8(name) if name == "implementors/Direct")).ok_or("missing class name")?;
            *entry = ConstantPoolEntry::Utf8(replacement.to_owned());
            let (filename, decompiled) = decompile_class_named(&class);
            let stem: &str = filename
                .strip_suffix(".java")
                .ok_or("missing Java extension")?;
            assert!(!stem.contains('/'));
            assert!(decompiled.source.contains(&format!("class {stem} ")));
        }
        Ok(())
    }

    #[test]
    fn real_class_matches_original_hierarchy_and_constructor() -> Result<(), String> {
        let result = analyze(DIRECT)?;
        assert_eq!(result.name, "implementors/Direct");
        assert_eq!(result.interfaces, ["implementors/Root"]);
        assert_eq!(result.superclass.as_deref(), Some("java/lang/Object"));
        assert_ne!(result.access_flags & 0x0010, 0);
        assert_eq!(result.methods.len(), 1);
        assert_eq!(result.methods[0].name, "<init>");
        assert_eq!(result.methods[0].descriptor, "()V");
        let MethodCode::Available { instructions, .. } = &result.methods[0].code else {
            return Err("constructor has no bytecode".to_owned());
        };
        assert!(instructions.iter().any(|instruction| {
            instruction.mnemonic == "invokespecial"
                && instruction
                    .reference
                    .as_deref()
                    .is_some_and(|reference| reference.contains("java/lang/Object"))
        }));
        assert!(result.decompiled.source.contains("class Direct"));
        assert!(result.decompiled.source.contains("Root"));
        assert_eq!(result.decompiled.decode_error_count, 0);
        Ok(())
    }

    #[test]
    fn jvm_input_checks_preserve_valid_followup() -> Result<(), String> {
        assert!(analyze(&[]).is_err());
        assert!(analyze(&DIRECT[..DIRECT.len() - 1]).is_err());
        assert!(analyze(&vec![0; INPUT_BYTES + 1]).is_err());
        assert_eq!(analyze(DIRECT)?.name, "implementors/Direct");
        Ok(())
    }

    #[test]
    fn java_class_route_requires_class_structure() {
        assert_eq!(
            crate::entry::auto_route(DIRECT).candidates[0].mode,
            "jvm_class"
        );
        assert!(
            !crate::entry::auto_route(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1])
                .candidates
                .iter()
                .any(|route| route.mode == "jvm_class")
        );
    }

    #[test]
    fn duplicate_code_attributes_are_invalid_in_both_views() -> Result<(), String> {
        let mut class: ClassFile = parse_classfile(DIRECT).map_err(|error| error.to_string())?;
        let duplicate = class.methods[0].attributes[0].clone();
        class.methods[0].attributes.push(duplicate);
        let mut remaining: usize = MAX_INSTRUCTIONS;
        assert!(matches!(
            method_code(&class, &class.methods[0], &mut remaining)?,
            MethodCode::Invalid { .. }
        ));
        assert_eq!(decompile_class(&class).decode_error_count, 1);
        Ok(())
    }

    #[test]
    fn invalid_later_attribute_names_are_invalid_in_both_views() -> Result<(), String> {
        let mut class: ClassFile = parse_classfile(DIRECT).map_err(|error| error.to_string())?;
        let mut invalid = class.methods[0].attributes[0].clone();
        invalid.name_index = 0;
        class.methods[0].attributes.push(invalid);
        let mut remaining: usize = MAX_INSTRUCTIONS;
        assert!(matches!(
            method_code(&class, &class.methods[0], &mut remaining)?,
            MethodCode::Invalid { .. }
        ));
        assert_eq!(decompile_class(&class).decode_error_count, 1);
        Ok(())
    }
}
