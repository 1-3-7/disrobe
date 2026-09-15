#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{IntegrityStripStats, strip_integrity_imports};
use walrus::{FunctionBuilder, FunctionId, Module, TypeId};

fn synth_module_with_jscrambler_import() -> Vec<u8> {
    let mut module: Module = Module::default();
    let ty: TypeId = module.types.add(&[], &[]);
    let (imp_fid, _): (FunctionId, walrus::ImportId) =
        module.add_import_func("env", "__jscrambler_integrity", ty);
    let mut builder: FunctionBuilder = FunctionBuilder::new(&mut module.types, &[], &[]);
    builder.func_body().call(imp_fid);
    let main_fid: FunctionId = builder.finish(Vec::new(), &mut module.funcs);
    module.exports.add("main", main_fid);
    module.emit_wasm()
}

#[test]
fn integrity_strip_removes_jscrambler_import() {
    let bytes: Vec<u8> = synth_module_with_jscrambler_import();
    let pre: Module = Module::from_buffer(&bytes).expect("parse pre");
    assert!(
        pre.imports.find("env", "__jscrambler_integrity").is_some(),
        "synth module must expose the jscrambler import"
    );

    let (out_bytes, stats): (Vec<u8>, IntegrityStripStats) =
        strip_integrity_imports(&bytes, &["__jscrambler_", "__integrity_"])
            .expect("strip succeeds");

    assert_eq!(stats.imports_removed, 1);
    assert_eq!(stats.call_sites_rewritten, 1);

    let post: Module = Module::from_buffer(&out_bytes).expect("parse post");
    assert!(
        post.imports.find("env", "__jscrambler_integrity").is_none(),
        "jscrambler import must be gone post-strip"
    );
    assert!(
        post.imports.iter().all(|imp| {
            !imp.name.starts_with("__jscrambler_") && !imp.name.starts_with("__integrity_")
        }),
        "no targeted prefix may survive in the import section"
    );
}

#[test]
fn integrity_strip_preserves_unmatched_imports() {
    let mut module: Module = Module::default();
    let ty: TypeId = module.types.add(&[], &[]);
    let (good_fid, _): (FunctionId, walrus::ImportId) =
        module.add_import_func("env", "normal_helper", ty);
    let (bad_fid, _): (FunctionId, walrus::ImportId) =
        module.add_import_func("env", "__jscrambler_check", ty);
    let mut b: FunctionBuilder = FunctionBuilder::new(&mut module.types, &[], &[]);
    b.func_body().call(good_fid).call(bad_fid);
    let main: FunctionId = b.finish(Vec::new(), &mut module.funcs);
    module.exports.add("main", main);
    let bytes: Vec<u8> = module.emit_wasm();

    let (out_bytes, stats): (Vec<u8>, IntegrityStripStats) =
        strip_integrity_imports(&bytes, &["__jscrambler_"]).expect("strip");

    assert_eq!(stats.imports_removed, 1);
    assert_eq!(stats.call_sites_rewritten, 1);
    let post: Module = Module::from_buffer(&out_bytes).expect("parse post");
    assert!(post.imports.find("env", "normal_helper").is_some());
    assert!(post.imports.find("env", "__jscrambler_check").is_none());
}

#[test]
fn integrity_strip_empty_prefix_list_is_noop() {
    let bytes: Vec<u8> = synth_module_with_jscrambler_import();
    let (out_bytes, stats): (Vec<u8>, IntegrityStripStats) =
        strip_integrity_imports(&bytes, &[]).expect("noop strip");
    assert_eq!(stats.imports_removed, 0);
    assert_eq!(stats.call_sites_rewritten, 0);
    let post: Module = Module::from_buffer(&out_bytes).expect("parse post-noop");
    assert!(post.imports.find("env", "__jscrambler_integrity").is_some());
}
