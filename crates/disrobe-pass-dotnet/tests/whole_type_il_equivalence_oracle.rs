#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{
    AssemblyModel, FieldConstant, FieldModel, MethodModel, Resolver, TypeModel,
};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::structurize::{StructuredMethod, csharp_escape_identifier, field_name};

const NAMESPACE: &str = "Sample";

#[derive(Debug, Clone, Copy)]
struct Target {
    dll: &'static str,
    origin_namespace: &'static str,
    type_name: &'static str,
    is_static: bool,
}

const TARGETS: &[Target] = &[
    Target {
        dll: "../../corpus/dotnet/constructs/Constructs.dll",
        origin_namespace: NAMESPACE,
        type_name: "Constructs",
        is_static: true,
    },
    Target {
        dll: "../../corpus/dotnet/shapes/Shapes.dll",
        origin_namespace: NAMESPACE,
        type_name: "Shapes",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/guards/Guards.dll",
        origin_namespace: NAMESPACE,
        type_name: "Guards",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/ranges/Ranges.dll",
        origin_namespace: NAMESPACE,
        type_name: "Ranges",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/patterns/Patterns.dll",
        origin_namespace: NAMESPACE,
        type_name: "Patterns",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/typepat/TypeMatch.dll",
        origin_namespace: NAMESPACE,
        type_name: "TypeMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/proppat/PropMatch.dll",
        origin_namespace: NAMESPACE,
        type_name: "PropMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/typerel/TypeRel.dll",
        origin_namespace: NAMESPACE,
        type_name: "TypeRel",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/listpat/ListMatch.dll",
        origin_namespace: NAMESPACE,
        type_name: "ListMatch",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/branches/Branches.dll",
        origin_namespace: NAMESPACE,
        type_name: "Branches",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "Cat",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "Dog",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "StaticFinalizationKit",
        is_static: true,
    },
    Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "TraceableAttribute",
        is_static: false,
    },
    Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "Pipeline",
        is_static: false,
    },
];

fn manifest(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    path
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repository root")
}

fn checked_output(command: &mut Command, label: &str) -> Result<Output, String> {
    let output: Output = command
        .output()
        .map_err(|error: std::io::Error| format!("{label} could not start: {error}"))?;
    if output.status.success() {
        return Ok(output);
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    Err(format!(
        "{label} exited {}. stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    ))
}

fn ilspy_command() -> Command {
    let mut command: Command = Command::new("dotnet");
    command.current_dir(repository_root()).args([
        "tool",
        "run",
        "ilspycmd",
        "--allow-roll-forward",
        "--",
    ]);
    command
}

fn require_dotnet() -> Result<(), String> {
    let mut command: Command = Command::new("dotnet");
    command.arg("--version");
    checked_output(&mut command, "dotnet --version").map(|_: Output| ())
}

fn require_ilspy() -> Result<(), String> {
    let mut command: Command = ilspy_command();
    command.arg("--version");
    let output: Output = checked_output(&mut command, "pinned ilspycmd --version").map_err(
        |error: String| {
            format!(
                "{error}\nrestore the pinned comparator with: dotnet tool restore --tool-manifest .config/dotnet-tools.json"
            )
        },
    )?;
    if output.stdout.is_empty() {
        return Err(
            "pinned ilspycmd --version produced no output. restore the pinned comparator with: dotnet tool restore --tool-manifest .config/dotnet-tools.json"
                .to_owned(),
        );
    }
    Ok(())
}

fn require_whole_type_tools() -> Result<(), String> {
    require_dotnet()?;
    require_ilspy()
}

fn declaring_type_of(body: &str) -> Option<String> {
    let first: &str = body.lines().next()?;
    let rest: &str = first.trim_start().strip_prefix("//")?.trim();
    let name: &str = rest.split_whitespace().next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn is_compiler_generated_type(full_name: &str) -> bool {
    let short: &str = full_name.rsplit('.').next().unwrap_or(full_name);
    short.contains('<') || short.contains(">d__") || short.starts_with("<>")
}

fn signature_line(body: &str) -> Option<(usize, String)> {
    body.lines().enumerate().find_map(|(i, l): (usize, &str)| {
        let t: &str = l.trim_start();
        let is_decl: bool = !t.starts_with("//")
            && t.contains('(')
            && (t.starts_with("public")
                || t.starts_with("private")
                || t.starts_with("protected")
                || t.starts_with("internal")
                || t.starts_with("static"));
        is_decl.then(|| (i, l.to_owned()))
    })
}

fn method_name_of(decl: &str) -> Option<String> {
    let ident: &str = declaration_identifier_of(decl)?;
    (!ident.is_empty()
        && ident
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| ident.to_owned())
}

fn declaration_identifier_of(decl: &str) -> Option<&str> {
    let ident: &str = raw_declaration_identifier_of(decl)?;
    let ident: &str = ident.split('<').next()?;
    (!ident.is_empty()).then_some(ident)
}

fn raw_declaration_identifier_of(decl: &str) -> Option<&str> {
    let before_paren: &str = decl.split('(').next()?;
    let ident: &str = before_paren.split_whitespace().next_back()?;
    (!ident.is_empty()).then_some(ident)
}

fn promote_visibility_to_public(decl: &str) -> String {
    let trimmed: &str = decl.trim_start();
    let mut rest: &str = trimmed;
    for kw in [
        "public ",
        "private protected ",
        "protected internal ",
        "private ",
        "protected ",
        "internal ",
    ] {
        if let Some(r) = rest.strip_prefix(kw) {
            rest = r;
            break;
        }
    }
    format!("public {rest}")
}

#[derive(Debug, Clone)]
struct UserMethod {
    name: String,
    source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstructorPolicy {
    Refuse,
    ValueType,
}

#[test]
fn user_method_admits_a_safe_instance_constructor() {
    let body: &str =
        "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    this.Pennies = pennies;\n}";
    let method: UserMethod = user_method_for(
        body,
        "EdgeCases.Money",
        "Money",
        ConstructorPolicy::ValueType,
    )
    .unwrap_or_else(|| panic!("the safe constructor should be admitted"));
    assert_eq!(method.name, ".ctor");
    assert_eq!(
        method.source,
        "    public Money(long pennies)\n{\n    this.Pennies = pennies;\n}\n"
    );
}

#[test]
fn user_method_refuses_unsafe_constructor_forms() {
    let body: &str =
        "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    this.Pennies = pennies;\n}";
    assert!(user_method_for(body, "EdgeCases.Money", "Money", ConstructorPolicy::Refuse).is_none());

    let static_ctor: &str = "// EdgeCases.Money\npublic static void .ctor()\n{\n}";
    assert!(
        user_method_for(
            static_ctor,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let generic_ctor: &str = "// EdgeCases.Money\npublic void .ctor<T>(long pennies)\n{\n}";
    assert!(
        user_method_for(
            generic_ctor,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let non_void_ctor: &str = "// EdgeCases.Money\npublic int .ctor(long pennies)\n{\n}";
    assert!(
        user_method_for(
            non_void_ctor,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let static_initializer: &str = "// EdgeCases.Money\nstatic void .cctor()\n{\n}";
    assert!(
        user_method_for(
            static_initializer,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let chaining_ctor: &str =
        "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    base.ctor(pennies);\n}";
    assert!(
        user_method_for(
            chaining_ctor,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let class_initializer_call: &str =
        "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    this.cctor();\n}";
    assert!(
        user_method_for(
            class_initializer_call,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let unsupported_modifier: &str =
        "// EdgeCases.Money\npublic virtual void .ctor(long pennies)\n{\n}";
    assert!(
        user_method_for(
            unsupported_modifier,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let comment_tail: &str =
        "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    // call unresolved\n}";
    assert!(
        user_method_for(
            comment_tail,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );

    let unreconstructed_tail: &str = "// EdgeCases.Money\npublic void .ctor(long pennies)\n{\n    __unreconstructed_runtime_handle;\n}";
    assert!(
        user_method_for(
            unreconstructed_tail,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );
}

#[test]
fn user_methods_refuse_same_short_name_from_another_namespace() {
    let body: &str =
        "// Decoy.Money\npublic void .ctor(long pennies)\n{\n    this.Pennies = pennies;\n}";
    assert!(
        user_method_for(
            body,
            "EdgeCases.Money",
            "Money",
            ConstructorPolicy::ValueType
        )
        .is_none()
    );
}

#[test]
fn constructor_recovery_requires_exactly_one_admitted_definition() {
    let no_methods: Vec<UserMethod> = Vec::new();
    assert!(!constructor_recovery_is_complete(
        ConstructorPolicy::ValueType,
        &no_methods
    ));
    assert!(constructor_recovery_is_complete(
        ConstructorPolicy::Refuse,
        &no_methods
    ));

    let one_constructor: Vec<UserMethod> = vec![UserMethod {
        name: ".ctor".to_owned(),
        source: String::new(),
    }];
    assert!(constructor_recovery_is_complete(
        ConstructorPolicy::ValueType,
        &one_constructor
    ));

    let two_constructors: Vec<UserMethod> = vec![
        UserMethod {
            name: ".ctor".to_owned(),
            source: String::new(),
        },
        UserMethod {
            name: ".ctor".to_owned(),
            source: String::new(),
        },
    ];
    assert!(!constructor_recovery_is_complete(
        ConstructorPolicy::ValueType,
        &two_constructors
    ));
}

#[test]
fn constructor_policy_counts_all_metadata_definitions() {
    let target: Target = Target {
        dll: EDGECASES_DLL,
        origin_namespace: "EdgeCases",
        type_name: "Money",
        is_static: false,
    };
    let path: PathBuf = manifest(target.dll)
        .canonicalize()
        .expect("canonicalize fixture");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile fixture");
    let money: TypeModel = target_type_model(&bytes, target)
        .unwrap_or_else(|| panic!("find EdgeCases.Money metadata"));
    assert_eq!(money.base_type.as_deref(), Some("System.ValueType"));
    assert_eq!(
        constructor_policy_for_type(&money),
        ConstructorPolicy::ValueType
    );
    let admitted: Vec<UserMethod> = user_methods_for(
        &asm.methods,
        &target_full_name(target),
        target.type_name,
        constructor_policy_for_type(&money),
    );
    assert!(constructor_recovery_is_complete(
        ConstructorPolicy::ValueType,
        &admitted
    ));

    let mut incomplete: TypeModel = money.clone();
    let mut omitted: MethodModel = incomplete
        .methods
        .iter()
        .find(|method: &&MethodModel| method.name == ".ctor")
        .cloned()
        .unwrap_or_else(|| panic!("find Money constructor"));
    omitted.rva = 0;
    incomplete.methods.push(omitted);
    assert_eq!(
        constructor_policy_for_type(&incomplete),
        ConstructorPolicy::Refuse
    );
    let refused: Vec<UserMethod> = user_methods_for(
        &asm.methods,
        &target_full_name(target),
        target.type_name,
        constructor_policy_for_type(&incomplete),
    );
    assert!(
        refused
            .iter()
            .all(|method: &UserMethod| method.name != ".ctor")
    );

    let mut spoofed: TypeModel = money.clone();
    spoofed.base_type = Some("Fake.System.ValueType".to_owned());
    assert_eq!(
        constructor_policy_for_type(&spoofed),
        ConstructorPolicy::Refuse
    );

    let mut reference: TypeModel = money.clone();
    reference.base_type = Some("System.Object".to_owned());
    assert_eq!(
        constructor_policy_for_type(&reference),
        ConstructorPolicy::Refuse
    );

    let mut without_constructor: TypeModel = money;
    without_constructor
        .methods
        .retain(|method: &MethodModel| method.name != ".ctor");
    assert_eq!(
        constructor_policy_for_type(&without_constructor),
        ConstructorPolicy::Refuse
    );
}

fn safe_value_type_constructor_header(
    decl: &str,
    target_type: &str,
    tail: &str,
    constructor_policy: ConstructorPolicy,
) -> Option<String> {
    if !matches!(constructor_policy, ConstructorPolicy::ValueType) {
        return None;
    }
    let raw_ident: &str = raw_declaration_identifier_of(decl)?;
    if raw_ident != ".ctor"
        || tail.contains(".ctor(")
        || tail.contains(".cctor(")
        || constructor_tail_states_refusal(tail)
    {
        return None;
    }
    let promoted: String = promote_visibility_to_public(decl);
    let open: usize = promoted.find('(')?;
    let before_paren: &str = promoted[..open].trim_end();
    let promoted_ident: &str = raw_declaration_identifier_of(&promoted)?;
    let before_ident: &str = before_paren.strip_suffix(promoted_ident)?.trim_end();
    let return_type: &str = before_ident.split_whitespace().next_back()?;
    if return_type != "void" {
        return None;
    }
    let modifiers: &str = before_ident.strip_suffix(return_type)?.trim_end();
    if modifiers != "public" {
        return None;
    }
    Some(format!("{modifiers} {target_type}{}", &promoted[open..]))
}

fn constructor_tail_states_refusal(tail: &str) -> bool {
    tail.lines()
        .any(|line: &str| line.trim_start().starts_with("//"))
        || tail
            .contains(disrobe_pass_dotnet::iterator_reverse::UNRECONSTRUCTED_STATE_MACHINE_MARKER)
        || tail.contains("__unrecovered_")
        || tail.contains("__unreconstructed_")
}

fn is_target_owned_body(body: &str, target_full_name: &str) -> bool {
    let Some(declaring_type): Option<String> = declaring_type_of(body) else {
        return false;
    };
    if is_compiler_generated_type(&declaring_type) {
        return false;
    }
    declaring_type == target_full_name
}

fn user_method_for(
    body: &str,
    target_full_name: &str,
    target_type: &str,
    constructor_policy: ConstructorPolicy,
) -> Option<UserMethod> {
    if !is_target_owned_body(body, target_full_name) {
        return None;
    }
    let first_line: &str = body.lines().next().unwrap_or_default();
    if first_line.contains("compiler-generated") || first_line.contains("[record") {
        return None;
    }
    let (decl_line, decl): (usize, String) = signature_line(body)?;
    let tail: String = body
        .lines()
        .skip(decl_line + 1)
        .collect::<Vec<&str>>()
        .join("\n");
    let (name, promoted): (String, String) = if let Some(header) =
        safe_value_type_constructor_header(&decl, target_type, &tail, constructor_policy)
    {
        (".ctor".to_owned(), header)
    } else {
        (method_name_of(&decl)?, promote_visibility_to_public(&decl))
    };
    let source: String = format!("    {promoted}\n{tail}\n");
    Some(UserMethod { name, source })
}

fn user_methods_for(
    structured_methods: &[StructuredMethod],
    target_full_name: &str,
    target_type: &str,
    constructor_policy: ConstructorPolicy,
) -> Vec<UserMethod> {
    structured_methods
        .iter()
        .filter_map(|method: &StructuredMethod| {
            user_method_for(
                &method.body,
                target_full_name,
                target_type,
                constructor_policy,
            )
        })
        .collect()
}

fn constructor_recovery_is_complete(
    constructor_policy: ConstructorPolicy,
    methods: &[UserMethod],
) -> bool {
    match constructor_policy {
        ConstructorPolicy::Refuse => true,
        ConstructorPolicy::ValueType => {
            methods
                .iter()
                .filter(|method: &&UserMethod| method.name == ".ctor")
                .count()
                == 1
        }
    }
}

const PREAMBLE: &str = "using System;\nusing System.Text;\nusing System.Collections.Generic;\nusing System.Linq;\nusing System.Threading.Tasks;\nusing System.Runtime.CompilerServices;\n\n";

const FIELD_ACCESS_MASK: u16 = 0x0007;
const FIELD_STATIC: u16 = 0x0010;
const FIELD_INIT_ONLY: u16 = 0x0020;
const FIELD_LITERAL: u16 = 0x0040;

const ELEMENT_TYPE_BOOLEAN: u8 = 0x02;
const ELEMENT_TYPE_CHAR: u8 = 0x03;
const ELEMENT_TYPE_I1: u8 = 0x04;
const ELEMENT_TYPE_U1: u8 = 0x05;
const ELEMENT_TYPE_I2: u8 = 0x06;
const ELEMENT_TYPE_U2: u8 = 0x07;
const ELEMENT_TYPE_I4: u8 = 0x08;
const ELEMENT_TYPE_U4: u8 = 0x09;
const ELEMENT_TYPE_I8: u8 = 0x0A;
const ELEMENT_TYPE_U8: u8 = 0x0B;
const ELEMENT_TYPE_R4: u8 = 0x0C;
const ELEMENT_TYPE_R8: u8 = 0x0D;
const ELEMENT_TYPE_STRING: u8 = 0x0E;
const ELEMENT_TYPE_CLASS: u8 = 0x12;

fn field_declarations(bytes: &[u8], target: Target) -> Vec<String> {
    let pe: PeImage = parse(bytes).expect("parse fixture PE");
    let clr: ClrHeader = parse_clr_header(bytes, &pe).expect("parse fixture CLR header");
    let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr).expect("parse fixture metadata");
    let resolver: Resolver = Resolver::build(bytes, &pe, &clr, &root).expect("build fixture model");
    let full_name: String = format!("{}.{}", target.origin_namespace, target.type_name);
    let model: AssemblyModel = resolver.model();
    let ty: &TypeModel = model
        .types
        .iter()
        .find(|candidate: &&TypeModel| candidate.full_name == full_name)
        .expect("locate target type metadata");
    ty.fields
        .iter()
        .map(|field: &FieldModel| csharp_field_declaration(&resolver, field))
        .collect()
}

fn target_full_name(target: Target) -> String {
    format!("{}.{}", target.origin_namespace, target.type_name)
}

fn target_type_model(bytes: &[u8], target: Target) -> Option<TypeModel> {
    let pe: PeImage = parse(bytes).expect("parse fixture PE");
    let clr: ClrHeader = parse_clr_header(bytes, &pe).expect("parse fixture CLR header");
    let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr).expect("parse fixture metadata");
    let resolver: Resolver = Resolver::build(bytes, &pe, &clr, &root).expect("build fixture model");
    let full_name: String = target_full_name(target);
    resolver
        .model()
        .types
        .iter()
        .find(|candidate: &&TypeModel| candidate.full_name == full_name)
        .cloned()
}

fn is_value_type_model(ty: &TypeModel) -> bool {
    ty.base_type
        .as_deref()
        .is_some_and(|base: &str| base == "System.ValueType")
}

fn is_value_type(bytes: &[u8], target: Target) -> bool {
    target_type_model(bytes, target).is_some_and(|ty: TypeModel| is_value_type_model(&ty))
}

fn constructor_policy_for_type(ty: &TypeModel) -> ConstructorPolicy {
    let constructor_count: usize = ty
        .methods
        .iter()
        .filter(|method: &&MethodModel| method.name == ".ctor")
        .count();
    if is_value_type_model(ty) && constructor_count == 1 {
        ConstructorPolicy::ValueType
    } else {
        ConstructorPolicy::Refuse
    }
}

fn constructor_policy_for(bytes: &[u8], target: Target) -> ConstructorPolicy {
    target_type_model(bytes, target).map_or(ConstructorPolicy::Refuse, |ty: TypeModel| {
        constructor_policy_for_type(&ty)
    })
}

fn csharp_fixed_buffer_element_keyword(clr_name: &str) -> Option<&'static str> {
    Some(match clr_name {
        "System.Boolean" => "bool",
        "System.Byte" => "byte",
        "System.SByte" => "sbyte",
        "System.Char" => "char",
        "System.Int16" => "short",
        "System.UInt16" => "ushort",
        "System.Int32" => "int",
        "System.UInt32" => "uint",
        "System.Int64" => "long",
        "System.UInt64" => "ulong",
        "System.Single" => "float",
        "System.Double" => "double",
        _ => return None,
    })
}

fn csharp_field_declaration(resolver: &Resolver, field: &FieldModel) -> String {
    let accessibility: &str = match field.flags & FIELD_ACCESS_MASK {
        0x0002 => "private protected ",
        0x0003 => "internal ",
        0x0004 => "protected ",
        0x0005 => "protected internal ",
        0x0006 => "public ",
        _ => "private ",
    };
    let is_literal: bool = field.flags & FIELD_LITERAL != 0;
    let fixed_buffer: Option<(&'static str, u32)> = resolver
        .field_fixed_buffer_info(field.token)
        .and_then(|(clr_name, length): (String, u32)| {
            let simple_name: &str = clr_name.split(',').next().unwrap_or(&clr_name).trim();
            csharp_fixed_buffer_element_keyword(simple_name).map(|kw: &'static str| (kw, length))
        });
    let mut modifiers: Vec<&str> = Vec::new();
    if is_literal {
        modifiers.push("const");
    } else {
        if field.flags & FIELD_STATIC != 0 {
            modifiers.push("static");
        }
        if fixed_buffer.is_some() {
            modifiers.push("unsafe");
        }
        if field.flags & FIELD_INIT_ONLY != 0 {
            modifiers.push("readonly");
        }
        if field.is_volatile {
            modifiers.push("volatile");
        }
    }
    let modifiers: String = if modifiers.is_empty() {
        String::new()
    } else {
        format!("{} ", modifiers.join(" "))
    };
    let recovered_name: String = field_name(&field.name);
    let name: String = csharp_escape_identifier(&recovered_name);
    if let Some((element_keyword, length)) = fixed_buffer {
        return format!("    {accessibility}{modifiers}fixed {element_keyword} {name}[{length}];");
    }
    let field_type: String = resolver.resolve_type_tokens(&field.field_type.render());
    let initializer: String = if is_literal {
        let constant: &FieldConstant = field
            .constant
            .as_ref()
            .expect("literal metadata field must carry a Constant-table value");
        format!(" = {}", csharp_constant(constant))
    } else {
        String::new()
    };
    format!("    {accessibility}{modifiers}{field_type} {name}{initializer};")
}

fn csharp_constant(constant: &FieldConstant) -> String {
    match constant.element_type {
        ELEMENT_TYPE_BOOLEAN => match constant.value.as_slice() {
            [0] => "false".to_owned(),
            [1] => "true".to_owned(),
            _ => panic!("invalid Boolean Constant-table value"),
        },
        ELEMENT_TYPE_CHAR => {
            let value: u16 = u16::from_le_bytes(constant_bytes(constant));
            csharp_char_literal(value)
        }
        ELEMENT_TYPE_I1 => i8::from_le_bytes(constant_bytes(constant)).to_string(),
        ELEMENT_TYPE_U1 => u8::from_le_bytes(constant_bytes(constant)).to_string(),
        ELEMENT_TYPE_I2 => i16::from_le_bytes(constant_bytes(constant)).to_string(),
        ELEMENT_TYPE_U2 => u16::from_le_bytes(constant_bytes(constant)).to_string(),
        ELEMENT_TYPE_I4 => i32::from_le_bytes(constant_bytes(constant)).to_string(),
        ELEMENT_TYPE_U4 => format!("{}u", u32::from_le_bytes(constant_bytes(constant))),
        ELEMENT_TYPE_I8 => format!("{}L", i64::from_le_bytes(constant_bytes(constant))),
        ELEMENT_TYPE_U8 => format!("{}UL", u64::from_le_bytes(constant_bytes(constant))),
        ELEMENT_TYPE_R4 => csharp_float_literal(f32::from_le_bytes(constant_bytes(constant))),
        ELEMENT_TYPE_R8 => csharp_double_literal(f64::from_le_bytes(constant_bytes(constant))),
        ELEMENT_TYPE_STRING => {
            let chunks: std::slice::ChunksExact<'_, u8> = constant.value.chunks_exact(2);
            assert!(
                chunks.remainder().is_empty(),
                "String Constant-table value must contain UTF-16 code units"
            );
            let code_units: Vec<u16> = chunks
                .map(|chunk: &[u8]| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            csharp_string_literal(&code_units)
        }
        ELEMENT_TYPE_CLASS if constant.value.is_empty() => "null".to_owned(),
        _ => panic!("unsupported Constant-table element type"),
    }
}

fn constant_bytes<const LENGTH: usize>(constant: &FieldConstant) -> [u8; LENGTH] {
    constant
        .value
        .as_slice()
        .try_into()
        .expect("Constant-table value has the expected width")
}

fn csharp_char_literal(value: u16) -> String {
    let escaped: String = match value {
        0x0027 => "\\'".to_owned(),
        0x005C => "\\\\".to_owned(),
        0x0020..=0x007E => csharp_ascii_code_unit(value),
        _ => format!("\\u{value:04X}"),
    };
    format!("'{escaped}'")
}

fn csharp_string_literal(code_units: &[u16]) -> String {
    let escaped: String = code_units
        .iter()
        .map(|code_unit: &u16| csharp_string_code_unit(*code_unit))
        .collect();
    format!("\"{escaped}\"")
}

fn csharp_string_code_unit(value: u16) -> String {
    match value {
        0x0022 => "\\\"".to_owned(),
        0x005C => "\\\\".to_owned(),
        0x0020..=0x007E => csharp_ascii_code_unit(value),
        _ => format!("\\u{value:04X}"),
    }
}

fn csharp_ascii_code_unit(value: u16) -> String {
    let character: Option<char> = char::from_u32(u32::from(value));
    character.map_or_else(
        || format!("\\u{value:04X}"),
        |character: char| character.to_string(),
    )
}

fn csharp_float_literal(value: f32) -> String {
    if value.is_nan() {
        "float.NaN".to_owned()
    } else if value == f32::INFINITY {
        "float.PositiveInfinity".to_owned()
    } else if value == f32::NEG_INFINITY {
        "float.NegativeInfinity".to_owned()
    } else {
        format!("{value:?}f")
    }
}

fn csharp_double_literal(value: f64) -> String {
    if value.is_nan() {
        "double.NaN".to_owned()
    } else if value == f64::INFINITY {
        "double.PositiveInfinity".to_owned()
    } else if value == f64::NEG_INFINITY {
        "double.NegativeInfinity".to_owned()
    } else {
        format!("{value:?}d")
    }
}

fn base_called_members(bodies: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut rest: &str = bodies;
    while let Some(pos) = rest.find("base.") {
        let after: &str = &rest[pos + "base.".len()..];
        let name: &str = after
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        if !name.is_empty() {
            out.insert(name.to_owned());
        }
        rest = after;
    }
    out
}

fn base_support(bytes: &[u8], target: Target, bodies: &str) -> Option<(String, String)> {
    let called: BTreeSet<String> = base_called_members(bodies);
    if called.is_empty() {
        return None;
    }
    let pe: PeImage = parse(bytes).expect("parse fixture PE");
    let clr: ClrHeader = parse_clr_header(bytes, &pe).expect("parse fixture CLR header");
    let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr).expect("parse fixture metadata");
    let resolver: Resolver = Resolver::build(bytes, &pe, &clr, &root).expect("build fixture model");
    let model: AssemblyModel = resolver.model();
    let full_name: String = format!("{}.{}", target.origin_namespace, target.type_name);
    let base_name: String = model
        .types
        .iter()
        .find(|candidate: &&TypeModel| candidate.full_name == full_name)
        .and_then(|ty: &TypeModel| ty.base_type.clone())?;
    let base: &TypeModel = model
        .types
        .iter()
        .find(|candidate: &&TypeModel| base_name.ends_with(&candidate.full_name))?;
    let short_base: &str = base.full_name.rsplit('.').next().unwrap_or(&base.full_name);
    let members: Vec<String> = base
        .methods
        .iter()
        .filter(|m: &&MethodModel| called.contains(m.name.rsplit("::").next().unwrap_or(&m.name)))
        .map(|m: &MethodModel| {
            let resolved: String = resolver.resolve_type_tokens(&m.csharp_signature());
            let promoted: String = promote_visibility_to_public(&resolved);
            let header: &str = promoted.strip_prefix("public ").unwrap_or(&promoted);
            format!("    public virtual {header}\n    {{\n        throw new System.NotSupportedException();\n    }}")
        })
        .collect();
    if members.len() != called.len() {
        return None;
    }
    let stub: String = format!(
        "    public class {short_base}\n    {{\n{}\n    }}\n\n",
        members.join("\n")
    );
    Some((format!(" : {short_base}"), stub))
}

fn whole_type_source(
    bytes: &[u8],
    fields: &[String],
    methods: &[UserMethod],
    target: Target,
) -> String {
    let declarations: String = fields.join("\n");
    let bodies: String = methods
        .iter()
        .map(|m: &UserMethod| m.source.clone())
        .collect::<Vec<String>>()
        .join("\n");
    let kind: &str = if target.is_static {
        "public static class"
    } else if is_value_type(bytes, target) {
        "public struct"
    } else {
        "public class"
    };
    let (base_clause, base_stub): (String, String) =
        base_support(bytes, target, &bodies).unwrap_or_else(|| (String::new(), String::new()));
    let type_name: &str = target.type_name;
    let namespace: &str = target.origin_namespace;
    format!(
        "{PREAMBLE}namespace {namespace}\n{{\n{base_stub}    {kind} {type_name}{base_clause}\n    {{\n{declarations}\n{bodies}\n    }}\n}}\n"
    )
}

fn write_project(dir: &Path, type_name: &str) {
    let csproj: String = format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <AssemblyName>{type_name}</AssemblyName>\n    <Deterministic>true</Deterministic>\n    <Optimize>true</Optimize>\n    <DebugType>none</DebugType>\n    <NoWarn>CS0168;CS0219;CS0162;CS0164;CS0649;CS1998;CS4014;CS0660;CS0661</NoWarn>\n  </PropertyGroup>\n</Project>\n"
    );
    std::fs::write(dir.join("oracle.csproj"), csproj).expect("write csproj");
}

fn compile_whole_type(dir: &Path, src: &str, type_name: &str) -> (Vec<String>, Option<PathBuf>) {
    std::fs::write(dir.join("host.cs"), src).expect("write source");
    let out: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("dotnet build");
    let errors: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&out.stderr).lines())
        .filter(|l: &&str| l.contains(": error "))
        .map(|l: &str| l.trim().to_owned())
        .collect();
    let dll: PathBuf = dir.join(format!("bin/Release/net9.0/{type_name}.dll"));
    let produced: Option<PathBuf> = dll.exists().then_some(dll);
    (errors, produced)
}

fn ilspy_il(dll: &Path, namespace: &str, type_name: &str) -> String {
    let mut command: Command = ilspy_command();
    command
        .args(["-il", "-t"])
        .arg(format!("{namespace}.{type_name}"))
        .arg(dll);
    let out: Output = checked_output(&mut command, "pinned ilspycmd IL comparison")
        .unwrap_or_else(|error: String| panic!("{error}"));
    assert!(
        !out.stdout.is_empty(),
        "pinned ilspycmd produced no IL for {}.{} from {}",
        namespace,
        type_name,
        dll.display()
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

const TARGET_PREFIX: &str = "L#";
const OFF_BODY_PREFIX: &str = "X#";

fn erase_assembly_refs(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let mut rest: &str = line;
    while let Some(open) = rest.find('[') {
        let after: &str = &rest[open + 1..];
        let Some(close): Option<usize> = after.find(']') else {
            break;
        };
        let name: &str = &after[..close];
        let is_assembly_ref: bool = name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.');
        out.push_str(&rest[..open]);
        if !is_assembly_ref {
            out.push('[');
            out.push_str(name);
            out.push(']');
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn normalize_op(line: &str) -> String {
    let mut normalized: String = erase_assembly_refs(line);
    for pat in ["'<>9__", "'<>9'", ">b__", "'<>c'", "'<>c__"] {
        if normalized.contains(pat) {
            normalized = mask_generated_idents(&normalized);
            break;
        }
    }
    normalized
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn branch_target_name(
    offset: u32,
    ordinals: &BTreeMap<u32, usize>,
    off_body: &mut Vec<u32>,
) -> String {
    if let Some(index) = ordinals.get(&offset) {
        return format!("{TARGET_PREFIX}{index}");
    }
    let slot: usize = off_body
        .iter()
        .position(|known: &u32| *known == offset)
        .unwrap_or(off_body.len());
    if slot == off_body.len() {
        off_body.push(offset);
    }
    format!("{OFF_BODY_PREFIX}{slot}")
}

fn rewrite_branch_targets(
    line: &str,
    ordinals: &BTreeMap<u32, usize>,
    off_body: &mut Vec<u32>,
) -> String {
    let mut out: String = String::new();
    let mut rest: &str = line;
    while let Some(pos) = rest.find("IL_") {
        out.push_str(&rest[..pos]);
        let after: &str = &rest[pos + "IL_".len()..];
        let hex_len: usize = after
            .bytes()
            .take_while(|b: &u8| b.is_ascii_hexdigit())
            .count();
        let hex: &str = &after[..hex_len];
        if let Ok(offset) = u32::from_str_radix(hex, 16) {
            out.push_str(&branch_target_name(offset, ordinals, off_body));
        } else {
            out.push_str("IL_");
            out.push_str(hex);
        }
        rest = &after[hex_len..];
    }
    out.push_str(rest);
    out
}

fn finalize_method_ops(instructions: &[(u32, String)]) -> Vec<String> {
    let ordinals: BTreeMap<u32, usize> = instructions
        .iter()
        .enumerate()
        .map(|(index, (offset, _)): (usize, &(u32, String))| (*offset, index))
        .collect();
    let mut off_body: Vec<u32> = Vec::new();
    instructions
        .iter()
        .map(|(_, text): &(u32, String)| {
            normalize_op(&rewrite_branch_targets(text, &ordinals, &mut off_body))
        })
        .collect()
}

fn mask_generated_idents(line: &str) -> String {
    let mut out: String = String::new();
    let mut rest: &str = line;
    while let Some(open) = rest.find('\'') {
        out.push_str(&rest[..open]);
        let after: &str = &rest[open + 1..];
        let Some(close): Option<usize> = after.find('\'') else {
            out.push('\'');
            rest = after;
            continue;
        };
        let token: &str = &after[..close];
        if token.contains("<>") || token.contains(">b__") {
            out.push_str("GEN");
        } else {
            out.push('\'');
            out.push_str(token);
            out.push('\'');
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn method_il_ops(il: &str, method: &str, type_name: &str) -> Option<Vec<String>> {
    let mut in_method: bool = false;
    let mut ops: Vec<(u32, String)> = Vec::new();
    let needle_open: String = format!(" {method} (");
    let needle_open_tight: String = format!(" {method}(");
    let needle_open_generic: String = format!(" {method}<");
    let needle_close: String = format!("end of method {type_name}::{method}");
    for line in il.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with(".method") {
            in_method = false;
        }
        if !in_method
            && (line.contains(&needle_open)
                || line.contains(&needle_open_tight)
                || line.contains(&needle_open_generic))
            && line.contains(method)
            && looks_like_method_header(line, method)
        {
            in_method = true;
            ops.clear();
        }
        if in_method && let Some((offset, rest)) = il_instruction(trimmed) {
            ops.push((offset, rest.to_owned()));
        }
        if in_method && line.contains(&needle_close) {
            return Some(finalize_method_ops(&ops));
        }
    }
    None
}

fn looks_like_method_header(line: &str, method: &str) -> bool {
    let Some((_, after)): Option<(&str, &str)> = line.split_once(method) else {
        return false;
    };
    let after: &str = match after.split_once('>') {
        Some((generics, rest)) if after.starts_with('<') && !generics.contains('(') => rest,
        _ => after,
    };
    after.trim_start().starts_with('(')
}

fn il_instruction(trimmed: &str) -> Option<(u32, &str)> {
    let (label, after_label): (&str, &str) = trimmed.split_once(':')?;
    let offset: u32 = u32::from_str_radix(label.strip_prefix("IL_")?, 16).ok()?;
    let op: &str = after_label.trim_start();
    (!op.is_empty()).then_some((offset, op))
}

struct Outcome {
    label: String,
    compiled: bool,
    compile_errors: Vec<String>,
    equivalent: Vec<String>,
    mismatched: Vec<String>,
    missing: Vec<String>,
    branching: Vec<String>,
    divergence: Vec<String>,
}

impl Outcome {
    const fn compared(&self) -> usize {
        self.equivalent.len() + self.mismatched.len() + self.missing.len()
    }
}

fn first_divergence(name: &str, original: &[String], recompiled: &[String]) -> String {
    let at: usize = original
        .iter()
        .zip(recompiled.iter())
        .position(|(o, r): (&String, &String)| o != r)
        .unwrap_or_else(|| original.len().min(recompiled.len()));
    let shown: &str = "(body ends)";
    let o: &str = original.get(at).map_or(shown, String::as_str);
    let r: &str = recompiled.get(at).map_or(shown, String::as_str);
    format!(
        "{name}: {} vs {} ops, first difference at {at}: original `{o}`, recovered `{r}`",
        original.len(),
        recompiled.len()
    )
}

fn qualify(target: Target, method: &str) -> String {
    format!("{}.{method}", target.type_name)
}

fn carries_branch_target(ops: &[String]) -> bool {
    ops.iter().any(|op: &String| op.contains(TARGET_PREFIX))
}

fn run_target(target: Target) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let policy: ConstructorPolicy = constructor_policy_for(&bytes, target);
    let full_name: String = target_full_name(target);
    let methods: Vec<UserMethod> =
        user_methods_for(&asm.methods, &full_name, target.type_name, policy);
    if !constructor_recovery_is_complete(policy, &methods) {
        return Outcome {
            label: target.type_name.to_owned(),
            compiled: false,
            compile_errors: vec!["constructor recovery is incomplete".to_owned()],
            equivalent: Vec::new(),
            mismatched: Vec::new(),
            missing: vec![qualify(target, ".ctor")],
            branching: Vec::new(),
            divergence: Vec::new(),
        };
    }
    assert!(
        !methods.is_empty(),
        "expected recovered user methods for {}",
        target.type_name
    );

    let purpose: String = format!("disrobe_whole_type_il_oracle_{}", target.type_name);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp, target.type_name);
    let fields: Vec<String> = field_declarations(&bytes, target);
    let src: String = whole_type_source(&bytes, &fields, &methods, target);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut branching: Vec<String> = Vec::new();
    let mut divergence: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, target.origin_namespace, target.type_name);
        let recomp_il: String = ilspy_il(recompiled, target.origin_namespace, target.type_name);
        let orig_ops: BTreeMap<String, Vec<String>> = methods
            .iter()
            .filter_map(|m: &UserMethod| {
                method_il_ops(&orig_il, &m.name, target.type_name)
                    .map(|ops: Vec<String>| (m.name.clone(), ops))
            })
            .collect();
        for m in &methods {
            let recomp: Option<Vec<String>> = method_il_ops(&recomp_il, &m.name, target.type_name);
            match (orig_ops.get(&m.name), recomp) {
                (Some(o), Some(r)) if *o == r => {
                    if carries_branch_target(o) {
                        branching.push(qualify(target, &m.name));
                    }
                    equivalent.push(qualify(target, &m.name));
                }
                (Some(o), Some(r)) => {
                    divergence.push(first_divergence(&qualify(target, &m.name), o, &r));
                    mismatched.push(qualify(target, &m.name));
                }
                _ => missing.push(qualify(target, &m.name)),
            }
        }
    }
    Outcome {
        label: target.type_name.to_owned(),
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
        branching,
        divergence,
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordTarget {
    dll: &'static str,
    type_name: &'static str,
}

const RECORD_TARGETS: &[RecordTarget] = &[RecordTarget {
    dll: "../../corpus/dotnet/constructs/Constructs.dll",
    type_name: "Point",
}];

#[derive(Debug, Clone)]
struct RecordComponent {
    ty: String,
    name: String,
}

fn signature_only(body: &str) -> Option<&str> {
    body.lines()
        .find(|l: &&str| !l.trim_start().starts_with("//") && l.contains('('))
}

fn record_member_bodies<'a>(asm: &'a DecompiledAssembly, type_name: &str) -> Vec<&'a str> {
    let needle: String = format!(".{type_name} [record");
    asm.methods
        .iter()
        .filter_map(|m: &'a StructuredMethod| {
            let first: &str = m.body.lines().next().unwrap_or_default();
            first.contains(&needle).then_some(m.body.as_str())
        })
        .collect()
}

fn parse_ctor_components(decl: &str) -> Option<Vec<RecordComponent>> {
    let open: usize = decl.find(".ctor(")? + ".ctor(".len();
    let rest: &str = &decl[open..];
    let close: usize = rest.find(')')?;
    let inner: &str = rest[..close].trim();
    if inner.is_empty() {
        return None;
    }
    let mut out: Vec<RecordComponent> = Vec::new();
    for part in inner.split(',') {
        let part: &str = part.trim();
        let (ty, name): (&str, &str) = part.rsplit_once(' ')?;
        let ty: String = ty.trim().rsplit('.').next().unwrap_or(ty).to_owned();
        let name: &str = name.trim();
        if ty.is_empty() || name.is_empty() {
            return None;
        }
        out.push(RecordComponent {
            ty,
            name: name.to_owned(),
        });
    }
    Some(out)
}

fn reconstruct_record_decl(asm: &DecompiledAssembly, type_name: &str) -> Option<String> {
    let members: Vec<&str> = record_member_bodies(asm, type_name);
    if members.is_empty() {
        return None;
    }
    let qualified: String = format!(".{type_name}");
    let primary: Vec<RecordComponent> = members
        .iter()
        .filter_map(|body: &&str| signature_only(body))
        .filter(|decl: &&str| {
            decl.contains(".ctor(") && !decl.contains(&format!("{qualified} original)"))
        })
        .find_map(parse_ctor_components)?;
    let params: String = primary
        .iter()
        .map(|c: &RecordComponent| format!("{} {}", c.ty, c.name))
        .collect::<Vec<String>>()
        .join(", ");
    Some(format!("public record {type_name}({params});"))
}

fn record_source(decl: &str) -> String {
    format!("{PREAMBLE}namespace {NAMESPACE}\n{{\n    {decl}\n}}\n")
}

fn il_method_blocks(il: &str, type_name: &str) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut blocks: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    let close_prefix: String = format!("end of method {type_name}::");
    let mut in_method: bool = false;
    let mut ops: Vec<(u32, String)> = Vec::new();
    for line in il.lines() {
        let trimmed: &str = line.trim_start();
        if trimmed.starts_with(".method") {
            in_method = true;
            ops.clear();
        }
        if in_method && let Some((offset, rest)) = il_instruction(trimmed) {
            ops.push((offset, rest.to_owned()));
        }
        if in_method && let Some(pos) = line.find(&close_prefix) {
            let name: &str = line[pos + close_prefix.len()..].trim();
            blocks
                .entry(name.to_owned())
                .or_default()
                .push(finalize_method_ops(&ops));
            in_method = false;
            ops.clear();
        }
    }
    blocks
}

fn run_record_target(target: RecordTarget) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let Some(decl): Option<String> = reconstruct_record_decl(&asm, target.type_name) else {
        return Outcome {
            label: target.type_name.to_owned(),
            compiled: false,
            compile_errors: vec![format!(
                "could not reconstruct record declaration for {}",
                target.type_name
            )],
            equivalent: Vec::new(),
            mismatched: Vec::new(),
            missing: vec![target.type_name.to_owned()],
            branching: Vec::new(),
            divergence: Vec::new(),
        };
    };

    let purpose: String = format!("disrobe_whole_type_il_oracle_record_{}", target.type_name);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp, target.type_name);
    let src: String = record_source(&decl);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut branching: Vec<String> = Vec::new();
    let mut divergence: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, NAMESPACE, target.type_name);
        let recomp_il: String = ilspy_il(recompiled, NAMESPACE, target.type_name);
        let orig_blocks: BTreeMap<String, Vec<Vec<String>>> =
            il_method_blocks(&orig_il, target.type_name);
        let recomp_blocks: BTreeMap<String, Vec<Vec<String>>> =
            il_method_blocks(&recomp_il, target.type_name);
        for (name, orig_ops) in &orig_blocks {
            let qualified: String = format!("{}.{name}", target.type_name);
            match recomp_blocks.get(name) {
                Some(recomp_ops) if multiset_eq(orig_ops, recomp_ops) => {
                    if orig_ops
                        .iter()
                        .any(|ops: &Vec<String>| carries_branch_target(ops))
                    {
                        branching.push(qualified.clone());
                    }
                    equivalent.push(qualified);
                }
                Some(recomp_ops) => {
                    divergence.push(format!(
                        "{qualified}: {} vs {} overload bodies compared as a multiset and no assignment matched",
                        orig_ops.len(),
                        recomp_ops.len()
                    ));
                    mismatched.push(qualified);
                }
                None => missing.push(qualified),
            }
        }
    }
    Outcome {
        label: target.type_name.to_owned(),
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
        branching,
        divergence,
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordMethodTarget {
    dll: &'static str,
    record_type: &'static str,
    class_type: &'static str,
}

const RECORD_METHOD_TARGETS: &[RecordMethodTarget] = &[
    RecordMethodTarget {
        dll: "../../corpus/dotnet/records/Records.dll",
        record_type: "Vec",
        class_type: "Records",
    },
    RecordMethodTarget {
        dll: "../../corpus/dotnet/pospat/PosMatch.dll",
        record_type: "Point",
        class_type: "PosMatch",
    },
];

fn record_method_source(record_decl: &str, methods: &[UserMethod], class_type: &str) -> String {
    let bodies: String = methods
        .iter()
        .map(|m: &UserMethod| m.source.clone())
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        "{PREAMBLE}namespace {NAMESPACE}\n{{\n    {record_decl}\n\n    public class {class_type}\n    {{\n{bodies}\n    }}\n}}\n"
    )
}

fn run_record_method_target(target: RecordMethodTarget) -> Outcome {
    let dll_path: PathBuf = manifest(target.dll).canonicalize().expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&dll_path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let Some(record_decl): Option<String> = reconstruct_record_decl(&asm, target.record_type)
    else {
        return Outcome {
            label: target.class_type.to_owned(),
            compiled: false,
            compile_errors: vec![format!(
                "could not reconstruct record declaration for {}",
                target.record_type
            )],
            equivalent: Vec::new(),
            mismatched: Vec::new(),
            missing: vec![target.class_type.to_owned()],
            branching: Vec::new(),
            divergence: Vec::new(),
        };
    };
    let full_name: String = format!("{NAMESPACE}.{}", target.class_type);
    let methods: Vec<UserMethod> = user_methods_for(
        &asm.methods,
        &full_name,
        target.class_type,
        ConstructorPolicy::Refuse,
    );
    assert!(
        !methods.is_empty(),
        "expected recovered user methods for {}",
        target.class_type
    );

    let purpose: String = format!("disrobe_whole_type_il_oracle_recmeth_{}", target.class_type);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp, target.class_type);
    let src: String = record_method_source(&record_decl, &methods, target.class_type);
    let (compile_errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.class_type);

    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut branching: Vec<String> = Vec::new();
    let mut divergence: Vec<String> = Vec::new();
    if let Some(recompiled) = produced.as_ref() {
        let orig_il: String = ilspy_il(&dll_path, NAMESPACE, target.class_type);
        let recomp_il: String = ilspy_il(recompiled, NAMESPACE, target.class_type);
        let orig_ops: BTreeMap<String, Vec<String>> = methods
            .iter()
            .filter_map(|m: &UserMethod| {
                method_il_ops(&orig_il, &m.name, target.class_type)
                    .map(|ops: Vec<String>| (m.name.clone(), ops))
            })
            .collect();
        for m in &methods {
            let qualified: String = format!("{}.{}", target.class_type, m.name);
            let recomp: Option<Vec<String>> = method_il_ops(&recomp_il, &m.name, target.class_type);
            match (orig_ops.get(&m.name), recomp) {
                (Some(o), Some(r)) if *o == r => {
                    if carries_branch_target(o) {
                        branching.push(qualified.clone());
                    }
                    equivalent.push(qualified);
                }
                (Some(o), Some(r)) => {
                    divergence.push(first_divergence(&qualified, o, &r));
                    mismatched.push(qualified);
                }
                _ => missing.push(qualified),
            }
        }
    }
    Outcome {
        label: target.class_type.to_owned(),
        compiled: produced.is_some(),
        compile_errors,
        equivalent,
        mismatched,
        missing,
        branching,
        divergence,
    }
}

fn multiset_eq(a: &[Vec<String>], b: &[Vec<String>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut remaining: Vec<&Vec<String>> = b.iter().collect();
    for item in a {
        if let Some(pos) = remaining.iter().position(|c: &&Vec<String>| *c == item) {
            remaining.swap_remove(pos);
        } else {
            return false;
        }
    }
    remaining.is_empty()
}

fn run_oracle() -> Result<Vec<Outcome>, String> {
    require_whole_type_tools()?;
    let mut outcomes: Vec<Outcome> = TARGETS.iter().map(|t: &Target| run_target(*t)).collect();
    outcomes.extend(
        RECORD_TARGETS
            .iter()
            .map(|t: &RecordTarget| run_record_target(*t)),
    );
    outcomes.extend(
        RECORD_METHOD_TARGETS
            .iter()
            .map(|t: &RecordMethodTarget| run_record_method_target(*t)),
    );
    Ok(outcomes)
}

fn probe_il(back_edge: &str, arm_order: [&str; 3]) -> String {
    let [first, second, third]: [&str; 3] = arm_order;
    format!(
        "\t.method public hidebysig static \n\t\tint32 Probe (\n\t\t\tint32 n\n\t\t) cil managed \n\t{{\n\t\t.maxstack 2\n\t\t.locals init (\n\t\t\t[0] int32 i\n\t\t)\n\n\t\tIL_0000: ldc.i4.0\n\t\tIL_0001: stloc.0\n\t\tIL_0002: br.s IL_0008\n\t\tIL_0004: ldloc.0\n\t\tIL_0005: ldc.i4.1\n\t\tIL_0006: add\n\t\tIL_0007: stloc.0\n\t\tIL_0008: ldloc.0\n\t\tIL_0009: ldarg.0\n\t\tIL_000a: blt.s {back_edge}\n\t\tIL_000c: ldarg.0\n\t\tIL_000d: switch ({first}, {second}, {third})\n\t\tIL_001e: ldloc.0\n\t\tIL_001f: ret\n\t}} // end of method Probe::Probe\n"
    )
}

fn erase_branch_targets(ops: &[String]) -> Vec<String> {
    ops.iter()
        .map(|op: &String| {
            let mut out: String = String::new();
            let mut rest: &str = op.as_str();
            while let Some(pos) = rest.find(TARGET_PREFIX) {
                out.push_str(&rest[..pos]);
                out.push('L');
                let after: &str = &rest[pos + TARGET_PREFIX.len()..];
                let digits: usize = after
                    .bytes()
                    .take_while(|b: &u8| b.is_ascii_digit())
                    .count();
                rest = &after[digits..];
            }
            out.push_str(rest);
            out
        })
        .collect()
}

#[test]
fn branch_target_identity_survives_normalization() {
    let inner: Vec<String> = method_il_ops(
        &probe_il("IL_0004", ["IL_0000", "IL_0004", "IL_001e"]),
        "Probe",
        "Probe",
    )
    .expect("inner-back-edge probe parses");
    let outer: Vec<String> = method_il_ops(
        &probe_il("IL_0000", ["IL_0000", "IL_0004", "IL_001e"]),
        "Probe",
        "Probe",
    )
    .expect("outer-back-edge probe parses");
    let permuted: Vec<String> = method_il_ops(
        &probe_il("IL_0004", ["IL_0004", "IL_0000", "IL_001e"]),
        "Probe",
        "Probe",
    )
    .expect("permuted-switch probe parses");

    for other in [&outer, &permuted] {
        assert_eq!(
            erase_branch_targets(&inner),
            erase_branch_targets(other),
            "these bodies differ only in branch targets, so collapsing every target to one token makes them identical, which is what a target-erasing comparison scores as equivalent"
        );
    }
    assert_ne!(
        inner, outer,
        "a loop back-edge that jumps to a different block must not compare equal"
    );
    assert_ne!(
        inner, permuted,
        "a switch whose arms are permuted must not compare equal"
    );
    assert!(
        inner.iter().any(|op: &String| op.contains("blt.s L#3")),
        "the back-edge must resolve to the ordinal of the instruction it targets; got {inner:?}"
    );
    assert!(
        inner
            .iter()
            .any(|op: &String| op.contains("switch (L#0, L#3, L#12)")),
        "every switch arm must keep its own target identity; got {inner:?}"
    );
    assert_eq!(
        normalize_op("newarr [netstandard]System.Byte"),
        normalize_op("newarr [System.Runtime]System.Byte"),
        "the reference assembly a type resolves through is a property of the compilation target, not of the recovered source, so it must not count as a difference"
    );
    assert_ne!(
        normalize_op("newarr [netstandard]System.Byte"),
        normalize_op("newarr [netstandard]System.SByte"),
        "erasing the reference assembly must not erase the type it qualifies"
    );
    assert_eq!(
        normalize_op("ldelem [netstandard]System.Int32[0...5]"),
        "ldelem System.Int32[0...5]",
        "array bounds are not an assembly reference and must survive"
    );
}

const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

const EDGECASES_TYPES: &[(&str, bool)] = &[
    ("AnimalBase", false),
    ("AsyncDisposableScope", false),
    ("AsyncPlayground", true),
    ("Cat", false),
    ("CollectionPlayground", true),
    ("ConditionalCompilation", true),
    ("ConfigParser", true),
    ("DeconstructPlayground", true),
    ("DisposableScope", false),
    ("DisposalPlayground", true),
    ("Dog", false),
    ("EntryPoint", true),
    ("EventSource", false),
    ("ExceptionPlayground", true),
    ("ExpressionPlayground", true),
    ("FileSystemPlayground", true),
    ("FixedBufferHolder", false),
    ("IteratorPlayground", true),
    ("JsonLite", true),
    ("LinqPlayground", true),
    ("Money", false),
    ("PackedHeader", false),
    ("PatternKit", true),
    ("Pipeline", false),
    ("PinvokePlayground", true),
    ("PrimaryCtorService", false),
    ("RefPlayground", true),
    ("SpanPlayground", true),
    ("StaticFinalizationKit", true),
    ("StringPlayground", true),
    ("TargetTypedNewPlayground", true),
    ("TplPlayground", true),
    ("TraceableAttribute", false),
    ("UnionLike", false),
    ("WithExpressionPlayground", true),
];

const EDGECASES_RECOMPILE_MEMBERS: &[&str] = &[
    "AsyncDisposableScope",
    "Cat",
    "CollectionPlayground",
    "ConditionalCompilation",
    "ConfigParser",
    "DeconstructPlayground",
    "DisposableScope",
    "Dog",
    "EventSource",
    "FixedBufferHolder",
    "JsonLite",
    "Money",
    "PackedHeader",
    "Pipeline",
    "StaticFinalizationKit",
    "TargetTypedNewPlayground",
    "TraceableAttribute",
    "UnionLike",
];

fn states_refusal(methods: &[UserMethod]) -> bool {
    methods.iter().any(|m: &UserMethod| {
        m.source
            .contains(disrobe_pass_dotnet::iterator_reverse::UNRECONSTRUCTED_STATE_MACHINE_MARKER)
            || m.source.contains(
                disrobe_pass_dotnet::iterator_reverse::UNLOWERED_COMPILER_CONSTRUCT_MARKER,
            )
    })
}

fn error_code(line: &str) -> Option<&str> {
    let start: usize = line.find(": error ")? + ": error ".len();
    let rest: &str = line.get(start..)?;
    rest.split(':').next()
}

#[test]
fn edgecases_whole_type_recompile_fraction_is_published_as_measured() {
    require_dotnet().unwrap_or_else(|error: String| panic!("{error}"));
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let mut compiled: Vec<&str> = Vec::new();
    let mut refused: Vec<&str> = Vec::new();
    let mut constructor_refused: Vec<&str> = Vec::new();
    let mut residual: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (type_name, is_static) in EDGECASES_TYPES {
        let target: Target = Target {
            dll: EDGECASES_DLL,
            origin_namespace: "EdgeCases",
            type_name,
            is_static: *is_static,
        };
        let policy: ConstructorPolicy = constructor_policy_for(&bytes, target);
        let full_name: String = target_full_name(target);
        let methods: Vec<UserMethod> =
            user_methods_for(&asm.methods, &full_name, type_name, policy);
        if !constructor_recovery_is_complete(policy, &methods) {
            constructor_refused.push(type_name);
            continue;
        }
        let fields: Vec<String> = field_declarations(&bytes, target);
        if methods.is_empty() && fields.is_empty() {
            residual
                .entry("no member recovered".to_owned())
                .or_default()
                .push(type_name);
            continue;
        }
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(&format!("disrobe_wt_{type_name}"))
                .expect("mk tmp");
        let tmp: PathBuf = scratch.path().to_path_buf();
        write_project(&tmp, type_name);
        let src: String = whole_type_source(&bytes, &fields, &methods, target);
        let (errors, produced): (Vec<String>, Option<PathBuf>) =
            compile_whole_type(&tmp, &src, type_name);
        if produced.is_some() {
            if states_refusal(&methods) {
                refused.push(type_name);
            } else {
                compiled.push(type_name);
            }
            continue;
        }
        let first: String = errors
            .first()
            .and_then(|line: &String| error_code(line))
            .unwrap_or("no diagnostic")
            .to_owned();
        residual.entry(first).or_default().push(type_name);
    }
    eprintln!(
        "EDGECASES WHOLE-TYPE RECOMPILE: {}/{} types whose recovered source csc accepts standalone",
        compiled.len(),
        EDGECASES_TYPES.len()
    );
    eprintln!("  recompiled: {compiled:?}");
    eprintln!(
        "  parses but carries a stated refusal for at least one member, a state machine that was not reconstructed or a compiler-generated construct that was not lowered, so it does not count as recovered: {refused:?}"
    );
    eprintln!(
        "  withheld because metadata requires one recovered value-type constructor: {constructor_refused:?}"
    );
    for (code, types) in &residual {
        eprintln!("  first-error {code}: {types:?}");
    }
    let missing: Vec<&&str> = EDGECASES_RECOMPILE_MEMBERS
        .iter()
        .filter(|name: &&&str| !compiled.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "EdgeCases whole-type recompile regressed: {missing:?} no longer recompile without a stated refusal. compiled={compiled:?} refused={refused:?} residual={residual:?}"
    );
}

fn published_recovery_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = repository_root().join("xtask/data/recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|h: &str| h.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading \
         containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

#[test]
fn published_edgecases_whole_type_recompile_bar_matches_the_floor_this_gate_enforces() {
    let bar: serde_json::Value =
        published_recovery_bar("Dotnet whole-type recompile", "whole-type recompile");
    let num: u64 = bar["num"]
        .as_u64()
        .expect("the whole-type recompile bar must carry a numerator");
    let den: u64 = bar["den"]
        .as_u64()
        .expect("the whole-type recompile bar must carry a denominator");
    let value: f64 = bar["value"]
        .as_f64()
        .expect("the whole-type recompile bar must carry a numeric value");
    assert_eq!(
        num,
        u64::try_from(EDGECASES_RECOMPILE_MEMBERS.len()).expect("count fits u64"),
        "xtask/data/recovery.json publishes {num} EdgeCases types recompiling clean, but this \
         gate enforces the {}-name floor in EDGECASES_RECOMPILE_MEMBERS",
        EDGECASES_RECOMPILE_MEMBERS.len()
    );
    assert_eq!(
        den,
        u64::try_from(EDGECASES_TYPES.len()).expect("count fits u64"),
        "recovery.json publishes a denominator of {den} EdgeCases types; this gate pins {}, \
         and edgecases_whole_type_recompile_fraction_is_published_as_measured fails if the \
         corpus drifts from it",
        EDGECASES_TYPES.len()
    );
    let derived: f64 = 100.0 * num as f64 / den as f64;
    assert!(
        (derived - value).abs() < 0.001,
        "the published value {value} disagrees with its own {num}/{den} = {derived}"
    );
}

fn declared_own_lines(body: &str, needle: &str) -> bool {
    body.lines()
        .any(|l: &str| l.trim_start().starts_with(needle))
}

#[test]
fn patternkit_classify_carries_a_goto_between_sibling_if_branches_and_is_abstained() {
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let classify: &StructuredMethod = asm
        .methods
        .iter()
        .find(|m: &&StructuredMethod| {
            declaring_type_of(&m.body).as_deref() == Some("EdgeCases.PatternKit")
                && m.body.contains("Classify(object value)")
        })
        .expect("EdgeCases.PatternKit.Classify is present in the baseline fixture");
    assert!(
        classify
            .body
            .contains(disrobe_pass_dotnet::structure_emit::UNSTRUCTURED_CONTROL_FLOW_MARKER),
        "Classify's recovered body used to leave a goto IL_01EB whose label sits inside a \
         sibling if-branch, which real csc rejects with CS0159; it must abstain instead of \
         emitting that goto. got:\n{}",
        classify.body
    );
    assert!(
        !declared_own_lines(&classify.body, "goto IL_"),
        "an abstained body must never leave a live goto behind; got:\n{}",
        classify.body
    );
}

#[test]
fn with_expression_playground_promote_recovers_a_with_expression_not_a_raw_clone_call() {
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let promote: &StructuredMethod = asm
        .methods
        .iter()
        .find(|m: &&StructuredMethod| {
            declaring_type_of(&m.body).as_deref() == Some("EdgeCases.WithExpressionPlayground")
                && m.body.contains("Promote(EdgeCases.User u)")
        })
        .expect("EdgeCases.WithExpressionPlayground.Promote is present in the baseline fixture");
    assert!(
        !promote.body.contains("<Clone>$"),
        "Promote used to call the compiler's mangled record clone method directly, which csc \
         rejects as an invalid expression term; it must recover a with expression instead. \
         got:\n{}",
        promote.body
    );
    assert!(
        promote.body.contains(" with { "),
        "expected a with expression recovering the record clone; got:\n{}",
        promote.body
    );
}

#[test]
fn whole_type_recompile_check_rejects_deliberately_broken_source() {
    require_dotnet().unwrap_or_else(|error: String| panic!("{error}"));
    let target: Target = Target {
        dll: EDGECASES_DLL,
        origin_namespace: "EdgeCases",
        type_name: "ConditionalCompilation",
        is_static: true,
    };
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let policy: ConstructorPolicy = constructor_policy_for(&bytes, target);
    let full_name: String = target_full_name(target);
    let methods: Vec<UserMethod> =
        user_methods_for(&asm.methods, &full_name, target.type_name, policy);
    let fields: Vec<String> = field_declarations(&bytes, target);
    let src: String = whole_type_source(&bytes, &fields, &methods, target);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wt_mutation_control").expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp, target.type_name);
    let (clean_errors, clean_dll): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);
    assert!(
        clean_dll.is_some(),
        "the unmutated recovered source must still compile, otherwise this control proves nothing. csc errors:\n{}",
        clean_errors.join("\n")
    );
    if let Some(dll) = clean_dll.as_ref() {
        std::fs::remove_file(dll).expect("remove the clean build output");
    }

    let broken: String = src.replacen(
        "public static class",
        "public static class\n    <SumAsync>d__0 local0;\n    (&local0).<>t__builder = Create();\n    public static class",
        1,
    );
    assert_ne!(
        broken, src,
        "the mutation must actually change the source it grades"
    );
    let (broken_errors, broken_dll): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &broken, target.type_name);
    assert!(
        broken_dll.is_none() && !broken_errors.is_empty(),
        "csc accepted recovered source carrying raw state-machine plumbing, so this check cannot separate recovered C# from builder plumbing"
    );
}

#[test]
fn fixed_buffer_field_recompiles_as_a_real_fixed_size_buffer() {
    require_dotnet().unwrap_or_else(|error: String| panic!("{error}"));
    let target: Target = Target {
        dll: EDGECASES_DLL,
        origin_namespace: "EdgeCases",
        type_name: "FixedBufferHolder",
        is_static: false,
    };
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let fields: Vec<String> = field_declarations(&bytes, target);
    let data_field: &String = fields
        .iter()
        .find(|f: &&String| f.contains(" Data;") || f.contains(" Data["))
        .expect("FixedBufferHolder declares a Data field");
    assert!(
        !data_field.contains("e__FixedBuffer"),
        "the compiler's mangled fixed-buffer backing type must never reach a field declaration; got: {data_field}"
    );
    assert!(
        data_field.contains("fixed byte Data["),
        "expected a real fixed-size buffer declaration; got: {data_field}"
    );

    let src: String = whole_type_source(&bytes, &fields, &[], target);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wt_fixed_buffer").expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_project(&tmp, target.type_name);
    let (errors, produced): (Vec<String>, Option<PathBuf>) =
        compile_whole_type(&tmp, &src, target.type_name);
    assert!(
        produced.is_some(),
        "recovered FixedBufferHolder source must recompile standalone; csc errors:\n{}\nsource:\n{src}",
        errors.join("\n")
    );
}

fn write_collection_runner_project(dir: &Path) {
    let project: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <Deterministic>true</Deterministic>\n    <Optimize>true</Optimize>\n    <DebugType>none</DebugType>\n  </PropertyGroup>\n</Project>\n";
    std::fs::write(dir.join("oracle.csproj"), project).expect("write runner project");
}

fn run_field_rva_arrays(dir: &Path, head: &str, tail: &str) -> std::process::Output {
    let runner: String = format!(
        "{PREAMBLE}public static class Program\n{{\n    public static void Main()\n    {{\n        int[] head = {head};\n        int[] tail = {tail};\n        System.IO.File.WriteAllText(\"collection-output.txt\", string.Join(\",\", head.Concat(tail)));\n    }}\n}}\n"
    );
    std::fs::write(dir.join("host.cs"), runner).expect("write runner source");
    let build: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(dir)
        .output()
        .expect("build recovered collection program");
    if !build.status.success() {
        return build;
    }
    Command::new("dotnet")
        .arg(dir.join("bin/Release/net9.0/oracle.dll"))
        .current_dir(dir)
        .output()
        .expect("run recovered collection program")
}

fn fixed_int32_array_initializers(source: &str) -> Vec<String> {
    let mut initializers: Vec<String> = Vec::new();
    let mut remaining: &str = source;
    while let Some(start) = remaining.find("new System.Int32[3]") {
        let candidate: &str = &remaining[start..];
        let Some(end): Option<usize> = candidate.find('}') else {
            break;
        };
        initializers.push(candidate[..=end].to_owned());
        remaining = &candidate[end + 1..];
    }
    initializers
}

#[test]
fn collection_field_rva_recovery_recompiles_and_preserves_runtime_values() {
    require_dotnet().unwrap_or_else(|error: String| panic!("{error}"));
    let path: PathBuf = manifest(EDGECASES_DLL)
        .canonicalize()
        .expect("canonicalize");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let methods: Vec<UserMethod> = user_methods_for(
        &asm.methods,
        "EdgeCases.CollectionPlayground",
        "CollectionPlayground",
        ConstructorPolicy::Refuse,
    )
    .into_iter()
    .filter(|method: &UserMethod| method.name == "CollectionExpression")
    .collect();
    assert_eq!(
        methods.len(),
        1,
        "recover CollectionExpression exactly once"
    );
    let initializers: Vec<String> = fixed_int32_array_initializers(&methods[0].source);
    assert_eq!(
        initializers,
        vec![
            "new System.Int32[3] { 1, 2, 3 }".to_owned(),
            "new System.Int32[3] { 9, 10, 11 }".to_owned(),
        ],
        "the runner must compile the recovered FieldRVA expressions"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_collection_field_rva").expect("mk tmp");
    let tmp: PathBuf = scratch.path().to_path_buf();
    write_collection_runner_project(&tmp);
    let clean: std::process::Output =
        run_field_rva_arrays(&tmp, &initializers[0], &initializers[1]);
    assert!(
        clean.status.success(),
        "recovered CollectionExpression must compile and run:\n{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(tmp.join("collection-output.txt"))
            .expect("read collection runtime output"),
        "1,2,3,9,10,11",
        "the recovered collection must retain both initialized FieldRVA spans"
    );
    let mutated_head: String = initializers[0].replacen("1, 2, 3", "2, 2, 3", 1);
    assert_ne!(
        mutated_head, initializers[0],
        "the element mutation must change recovered source"
    );
    let mutated_run: std::process::Output =
        run_field_rva_arrays(&tmp, &mutated_head, &initializers[1]);
    assert!(
        mutated_run.status.success(),
        "the one-element mutation must stay compilable:\n{}",
        String::from_utf8_lossy(&mutated_run.stderr)
    );
    assert_ne!(
        std::fs::read_to_string(tmp.join("collection-output.txt"))
            .expect("read mutated collection runtime output"),
        "1,2,3,9,10,11",
        "the runtime oracle must reject a changed FieldRVA element"
    );
}

const IL_EQUIVALENCE_FLOOR: usize = 66;
const IL_BRANCHING_FLOOR: usize = 45;

const IL_RESIDUAL: &[&str] = &[
    "Dog.Describe",
    "Dog.get_Breed",
    "Pipeline.RunSteps",
    "TraceableAttribute.get_Category",
    "TraceableAttribute.get_Priority",
    "TraceableAttribute.set_Priority",
];

fn percent(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = numerator as f64 / denominator as f64;
    ratio * 100.0
}

#[test]
fn external_command_requirement_rejects_a_missing_command() {
    let missing: String = format!("disrobe_missing_tool_{}", std::process::id());
    let mut command: Command = Command::new(&missing);
    command.arg("--version");
    let error: String = checked_output(&mut command, &missing)
        .expect_err("a missing external command must not satisfy the whole-type prerequisites");
    assert!(
        error.contains(&missing),
        "the missing command error must identify the unavailable prerequisite: {error}"
    );
}

#[test]
fn dog_recompiles_when_its_metadata_fields_are_emitted() {
    require_whole_type_tools().unwrap_or_else(|error: String| panic!("{error}"));
    let target: Target = Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "Dog",
        is_static: false,
    };
    let outcome: Outcome = run_target(target);
    assert!(
        outcome.compiled,
        "recovered Dog source did not recompile. csc errors:\n{}",
        outcome.compile_errors.join("\n")
    );
}

#[test]
fn metadata_constant_fields_render_csharp_literals() {
    let target: Target = Target {
        dll: "../../corpus/dotnet/megafile/EdgeCases.baseline.dll",
        origin_namespace: "EdgeCases",
        type_name: "ConditionalCompilation",
        is_static: true,
    };
    let path: PathBuf = manifest(target.dll);
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let fields: Vec<String> = field_declarations(&bytes, target);
    assert_eq!(
        fields,
        vec![
            "    public const string BuildKind = \"release\";".to_owned(),
            "    public const string Tfm = \"netstandard2.0\";".to_owned(),
        ]
    );
}

#[test]
fn metadata_constant_literals_escape_utf16_edge_cases() {
    let apostrophe: FieldConstant = FieldConstant {
        element_type: ELEMENT_TYPE_CHAR,
        value: vec![0x27, 0x00],
    };
    let surrogate: FieldConstant = FieldConstant {
        element_type: ELEMENT_TYPE_STRING,
        value: vec![0x00, 0xD8, 0x61, 0x00],
    };
    assert_eq!(
        (csharp_constant(&apostrophe), csharp_constant(&surrogate)),
        ("'\\''".to_owned(), "\"\\uD800a\"".to_owned())
    );
}

#[test]
fn whole_type_recompiles_to_equivalent_il() {
    let outcomes: Vec<Outcome> = run_oracle().unwrap_or_else(|error: String| panic!("{error}"));
    let mut equivalent: Vec<String> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut branching: Vec<String> = Vec::new();
    let mut divergence: Vec<String> = Vec::new();
    for outcome in &outcomes {
        assert!(
            outcome.compiled,
            "recovered whole-type source did not recompile. csc errors:\n{}",
            outcome.compile_errors.join("\n")
        );
        equivalent.extend(outcome.equivalent.iter().cloned());
        mismatched.extend(outcome.mismatched.iter().cloned());
        missing.extend(outcome.missing.iter().cloned());
        branching.extend(outcome.branching.iter().cloned());
        divergence.extend(outcome.divergence.iter().cloned());
    }
    let matched: usize = equivalent.len();
    let compared: usize = matched + mismatched.len() + missing.len();
    eprintln!(
        "WHOLE-TYPE IL EQUIVALENCE: matched={matched} compared={compared} ({:.2}%) across {} graded types, after standalone csc recompile and an ilspycmd compare against the original assembly",
        percent(matched, compared),
        outcomes.len(),
    );
    for outcome in &outcomes {
        eprintln!(
            "  {}: matched={} compared={} ({:.2}%)",
            outcome.label,
            outcome.equivalent.len(),
            outcome.compared(),
            percent(outcome.equivalent.len(), outcome.compared()),
        );
    }
    eprintln!("  equivalent: {equivalent:?}");
    eprintln!(
        "  of those, {} carry at least one branch or switch target whose destination block had to match: {branching:?}",
        branching.len()
    );
    if !mismatched.is_empty() {
        eprintln!(
            "  not equivalent, recovered shape differs: matched=0 compared={} {mismatched:?}",
            mismatched.len()
        );
        for line in &divergence {
            eprintln!("    {line}");
        }
    }
    if !missing.is_empty() {
        eprintln!("  not located in one assembly: {missing:?}");
    }
    let unpinned: Vec<&String> = mismatched
        .iter()
        .filter(|name: &&String| !IL_RESIDUAL.contains(&name.as_str()))
        .collect();
    assert!(
        unpinned.is_empty(),
        "these methods are not IL-equivalent and are not in the pinned residual: {unpinned:?}. \
         a new divergence must be fixed or added deliberately, never absorbed by a count that still clears its floor. \
         divergences: {divergence:?}"
    );
    let recovered: Vec<&&str> = IL_RESIDUAL
        .iter()
        .filter(|name: &&&str| !mismatched.iter().any(|m: &String| m == *name))
        .collect();
    assert!(
        recovered.is_empty(),
        "these methods now match and must leave the pinned residual, which only ever shrinks: {recovered:?}"
    );
    assert_eq!(
        compared,
        matched + mismatched.len() + missing.len(),
        "the graded population must partition into equivalent, mismatched and missing, so neither the numerator nor the denominator can move quietly"
    );
    assert!(
        equivalent.len() >= IL_EQUIVALENCE_FLOOR,
        "whole-type IL-equivalence regressed below the floor: matched={matched} compared={compared} (floor {IL_EQUIVALENCE_FLOOR}). mismatched={mismatched:?} missing={missing:?}",
    );
    assert!(
        branching.len() >= IL_BRANCHING_FLOOR,
        "only {} of the {} equivalent methods compared a real branch target (floor {IL_BRANCHING_FLOOR}); \
         if this collapses, label normalization has stopped preserving branch destinations and the \
         comparison no longer separates two methods that differ only in where they jump",
        branching.len(),
        equivalent.len(),
    );
}
