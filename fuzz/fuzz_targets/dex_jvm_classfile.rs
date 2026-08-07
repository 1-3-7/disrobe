#![no_main]

use core::hint::black_box;

use libfuzzer_sys::fuzz_target;

use disrobe_binfmt::structural::{validate_dex, validate_java_class};
use disrobe_fuzz::over_input_budget;
use disrobe_nir_lift::{lift_classfile, lift_dex};
use disrobe_pass_jvm::bytecode::{
    CodeAttribute, Instruction, disassemble, parse_code_attribute, validate_code_attribute,
};
use disrobe_pass_jvm::classfile::{ClassFile, parse as parse_classfile};
use disrobe_pass_jvm::dex::{CodeItemsReport, DexFile, parse as parse_dex, parse_header};
use disrobe_pass_jvm::{arsc, axml, dex};

fn drive_classfile(data: &[u8]) {
    let _ = black_box(validate_java_class(data));
    let _ = black_box(disassemble(data));
    let _ = black_box(parse_code_attribute(data));
    let Ok(class): disrobe_pass_jvm::Result<ClassFile> = parse_classfile(data) else {
        return;
    };
    if let Ok(code) = parse_code_attribute(data) {
        let attribute: CodeAttribute = code;
        let _ = black_box(validate_code_attribute(&class, &attribute));
    }
    let _ = black_box(&class.constant_pool);
    let _ = black_box(lift_classfile(data));
}

fn drive_dex(data: &[u8]) {
    let _ = black_box(validate_dex(data));
    let _ = black_box(parse_header(data));
    let Ok(parsed): disrobe_pass_jvm::Result<DexFile> = parse_dex(data) else {
        return;
    };
    let report: CodeItemsReport = dex::parse_code_items(&parsed, data);
    let _ = black_box(&report);
    let _ = black_box(dex::extract_native_methods(&parsed, data));
    let _ = black_box(lift_dex(data));
}

fn drive_android_resources(data: &[u8]) {
    let _ = black_box(axml::parse(data));
    let _ = black_box(arsc::parse_arsc(data));
}

fn disassembly_offsets_stay_inside_the_code(data: &[u8]) {
    let Ok(instructions): disrobe_pass_jvm::Result<Vec<Instruction>> = disassemble(data) else {
        return;
    };
    for instruction in &instructions {
        assert!(
            (instruction.pc as usize) < data.len(),
            "a disassembled instruction sits past the end of the code array"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if over_input_budget(data) {
        return;
    }
    drive_classfile(data);
    drive_dex(data);
    drive_android_resources(data);
    disassembly_offsets_stay_inside_the_code(data);
});
