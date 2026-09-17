use core::fmt;

use disrobe_binfmt::structural::{validate_dex, validate_java_class};
use disrobe_nir_lift::{lift_classfile, lift_dex};
use disrobe_pass_jvm::bytecode::{
    CodeAttribute, Instruction, disassemble, parse_code_attribute, validate_code_attribute,
};
use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo, parse as parse_classfile};
use disrobe_pass_jvm::dex::{
    CodeItemsReport, DexFile, extract_native_methods, parse as parse_dex, parse_code_items,
    parse_header,
};
use disrobe_pass_jvm::{Captured, arsc, axml, capture_observations};

use crate::over_input_budget;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClassExerciseOutcome {
    structural_accepted: bool,
    parser_accepted: bool,
    code_attributes: usize,
    parsed_code_attributes: usize,
    disassembled_code_attributes: usize,
    validated_code_attributes: usize,
    instructions: usize,
    lift_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DexExerciseOutcome {
    structural_accepted: bool,
    header_accepted: bool,
    parser_accepted: bool,
    code_items_accepted: bool,
    decoded_code_items: usize,
    methods: usize,
    native_methods: usize,
    lift_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceExerciseOutcome {
    axml_accepted: bool,
    arsc_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JvmExerciseOutcome {
    over_budget: bool,
    class: ClassExerciseOutcome,
    dex: DexExerciseOutcome,
    resources: ResourceExerciseOutcome,
}

#[derive(Debug)]
pub struct JvmReplay {
    outcome: JvmExerciseOutcome,
    capture: Captured<JvmExerciseOutcome>,
}

impl JvmReplay {
    #[must_use]
    pub const fn outcome(&self) -> &JvmExerciseOutcome {
        &self.outcome
    }
}

#[derive(Debug)]
pub enum JvmReplayError {
    Capture(disrobe_pass_jvm::CaptureError),
    OutcomeMismatch,
}

impl fmt::Display for JvmReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => write!(formatter, "{error}"),
            Self::OutcomeMismatch => {
                formatter.write_str("recorded and unrecorded JVM exercise outcomes differ")
            }
        }
    }
}

impl std::error::Error for JvmReplayError {}

impl From<disrobe_pass_jvm::CaptureError> for JvmReplayError {
    fn from(error: disrobe_pass_jvm::CaptureError) -> Self {
        Self::Capture(error)
    }
}

fn exercise_class(data: &[u8]) -> ClassExerciseOutcome {
    let structural_accepted: bool = validate_java_class(data);
    let Ok(class): disrobe_pass_jvm::Result<ClassFile> = parse_classfile(data) else {
        return ClassExerciseOutcome {
            structural_accepted,
            ..ClassExerciseOutcome::default()
        };
    };
    let mut code_attributes: usize = 0;
    let mut parsed_code_attributes: usize = 0;
    let mut disassembled_code_attributes: usize = 0;
    let mut validated_code_attributes: usize = 0;
    let mut instructions: usize = 0;
    for method in &class.methods {
        collect_method_code(
            &class,
            method,
            &mut code_attributes,
            &mut parsed_code_attributes,
            &mut disassembled_code_attributes,
            &mut validated_code_attributes,
            &mut instructions,
        );
    }
    ClassExerciseOutcome {
        structural_accepted,
        parser_accepted: true,
        code_attributes,
        parsed_code_attributes,
        disassembled_code_attributes,
        validated_code_attributes,
        instructions,
        lift_accepted: lift_classfile(data).is_ok(),
    }
}

fn collect_method_code(
    class: &ClassFile,
    method: &MethodInfo,
    code_attributes: &mut usize,
    parsed_code_attributes: &mut usize,
    disassembled_code_attributes: &mut usize,
    validated_code_attributes: &mut usize,
    instructions: &mut usize,
) {
    for attribute in &method.attributes {
        let Attribute { name_index, info }: &Attribute = attribute;
        let Ok(name): disrobe_pass_jvm::Result<&str> = class.utf8_at(*name_index) else {
            continue;
        };
        if name != "Code" {
            continue;
        }
        *code_attributes = code_attributes.saturating_add(1);
        let Ok(code): disrobe_pass_jvm::Result<CodeAttribute> = parse_code_attribute(info) else {
            continue;
        };
        *parsed_code_attributes = parsed_code_attributes.saturating_add(1);
        if let Ok(decoded) = disassemble(&code.code) {
            let decoded_instructions: Vec<Instruction> = decoded;
            *disassembled_code_attributes = disassembled_code_attributes.saturating_add(1);
            *instructions = instructions.saturating_add(decoded_instructions.len());
        }
        if validate_code_attribute(class, &code).is_ok() {
            *validated_code_attributes = validated_code_attributes.saturating_add(1);
        }
    }
}

fn exercise_dex(data: &[u8]) -> DexExerciseOutcome {
    let structural_accepted: bool = validate_dex(data);
    let header_accepted: bool = parse_header(data).is_ok();
    let Ok(dex): disrobe_pass_jvm::Result<DexFile> = parse_dex(data) else {
        return DexExerciseOutcome {
            structural_accepted,
            header_accepted,
            ..DexExerciseOutcome::default()
        };
    };
    let report: CodeItemsReport = parse_code_items(&dex, data);
    DexExerciseOutcome {
        structural_accepted,
        header_accepted,
        parser_accepted: true,
        code_items_accepted: report.unrecovered_tail().is_none(),
        decoded_code_items: report.decoded().len(),
        methods: report.methods().len(),
        native_methods: extract_native_methods(&dex, data)
            .map_or(0usize, |methods: Vec<disrobe_pass_jvm::NativeMethod>| {
                methods.len()
            }),
        lift_accepted: lift_dex(data).is_ok(),
    }
}

fn exercise_resources(data: &[u8]) -> ResourceExerciseOutcome {
    ResourceExerciseOutcome {
        axml_accepted: axml::parse(data).is_ok(),
        arsc_accepted: arsc::parse_arsc(data).is_ok(),
    }
}

#[must_use]
pub fn exercise(data: &[u8]) -> JvmExerciseOutcome {
    if over_input_budget(data) {
        return JvmExerciseOutcome {
            over_budget: true,
            ..JvmExerciseOutcome::default()
        };
    }
    JvmExerciseOutcome {
        over_budget: false,
        class: exercise_class(data),
        dex: exercise_dex(data),
        resources: exercise_resources(data),
    }
}

pub fn run_fuzz_input<'a, T, F>(data: &'a [u8], exercise_input: F) -> T
where
    F: FnOnce(&'a [u8]) -> T,
{
    exercise_input(data)
}

pub fn replay(data: &[u8]) -> Result<JvmReplay, JvmReplayError> {
    let outcome: JvmExerciseOutcome = exercise(data);
    let capture: Captured<JvmExerciseOutcome> = capture_observations(|| exercise(data))?;
    if outcome != *capture.value() {
        return Err(JvmReplayError::OutcomeMismatch);
    }
    Ok(JvmReplay { outcome, capture })
}

impl crate::seed_reach::ReplayTrace for JvmReplay {
    fn observations(&self) -> crate::seed_reach::ReplayObservations<'_> {
        crate::seed_reach::ReplayObservations::Jvm(self.capture.observations())
    }
}
