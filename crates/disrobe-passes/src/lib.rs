use disrobe_core::chain::{Ecosystem, PassRegistry, ecosystem_for};
use disrobe_core::pass::PassId;

#[must_use]
pub fn build_registry() -> PassRegistry {
    let mut r: PassRegistry = PassRegistry::new();
    #[cfg(feature = "pyarmor")]
    r.register(&disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS);
    #[cfg(feature = "native")]
    r.register(&disrobe_pass_native::chain_detector::PACKER_PASS);
    #[cfg(feature = "py-deob")]
    r.register(&disrobe_pass_py_deob::chain_detector::PY_DEOB_PASS);
    #[cfg(feature = "container")]
    r.register(&disrobe_binfmt::chain_detector::CONTAINER_PASS);
    #[cfg(feature = "sourcedefender")]
    r.register(&disrobe_pass_sourcedefender::chain_detector::SOURCEDEFENDER_PASS);
    #[cfg(feature = "pyfreeze")]
    r.register(&disrobe_pass_pyfreeze::chain_detector::PYFREEZE_PASS);
    #[cfg(feature = "nuitka")]
    r.register(&disrobe_pass_nuitka::chain_detector::NUITKA_PASS);
    #[cfg(feature = "py-disasm")]
    r.register(&disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS);
    #[cfg(feature = "py-decompile")]
    r.register(&disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS);
    #[cfg(feature = "pyinstaller")]
    r.register(&disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS);
    #[cfg(feature = "pickle")]
    r.register(&disrobe_pass_pickle::chain_detector::PICKLE_PASS);
    #[cfg(feature = "js")]
    r.register(&disrobe_pass_js_deob::chain_detector::JS_OBF_PASS);
    #[cfg(feature = "wasm")]
    r.register(&disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS);
    #[cfg(feature = "php")]
    r.register(&disrobe_pass_php::chain_detector::PHP_PASS);
    #[cfg(feature = "ruby")]
    r.register(&disrobe_pass_ruby::chain_detector::RUBY_PASS);
    #[cfg(feature = "shell")]
    r.register(&disrobe_pass_shell::chain_detector::SHELL_PASS);
    #[cfg(feature = "mobile")]
    r.register(&disrobe_pass_mobile::chain_detector::MOBILE_PASS);
    #[cfg(feature = "lua")]
    r.register(&disrobe_pass_lua::chain_detector::LUA_PASS);
    #[cfg(feature = "swift")]
    r.register(&disrobe_pass_swift_objc::chain_detector::SWIFT_OBJC_PASS);
    #[cfg(feature = "jvm")]
    r.register(&disrobe_pass_jvm::chain_detector::JVM_PASS);
    #[cfg(feature = "dotnet")]
    r.register(&disrobe_pass_dotnet::chain_detector::DOTNET_PASS);
    #[cfg(feature = "go")]
    r.register(&disrobe_pass_go::chain_detector::GO_PASS);
    #[cfg(feature = "beam")]
    r.register(&disrobe_pass_beam::chain_detector::BEAM_PASS);
    #[cfg(feature = "as3")]
    r.register(&disrobe_pass_as3::chain_detector::AS3_PASS);
    #[cfg(feature = "scriptlang")]
    r.register(&disrobe_pass_scriptlang::chain_detector::SCRIPTLANG_PASS);
    #[cfg(feature = "nativelang")]
    r.register(&disrobe_pass_nativelang::chain_detector::NATIVELANG_PASS);
    r
}

#[must_use]
#[allow(
    clippy::vec_init_then_push,
    reason = "each push sits under its own cfg gate, so a vec! literal cannot express the conditional membership"
)]
pub fn expected_pass_ids() -> Vec<PassId> {
    let mut ids: Vec<PassId> = Vec::new();
    #[cfg(feature = "pyarmor")]
    ids.push(disrobe_pass_pyarmor::chain_detector::PASS_ID);
    #[cfg(feature = "native")]
    ids.push(disrobe_pass_native::chain_detector::PASS_ID);
    #[cfg(feature = "py-deob")]
    ids.push(disrobe_pass_py_deob::chain_detector::PASS_ID);
    #[cfg(feature = "container")]
    ids.push(disrobe_binfmt::chain_detector::PASS_ID);
    #[cfg(feature = "sourcedefender")]
    ids.push(disrobe_pass_sourcedefender::chain_detector::PASS_ID);
    #[cfg(feature = "pyfreeze")]
    ids.push(disrobe_pass_pyfreeze::chain_detector::PASS_ID);
    #[cfg(feature = "nuitka")]
    ids.push(disrobe_pass_nuitka::chain_detector::PASS_ID);
    #[cfg(feature = "py-disasm")]
    ids.push(disrobe_pass_py_disasm::chain_detector::PASS_ID);
    #[cfg(feature = "py-decompile")]
    ids.push(disrobe_pass_py_decompile::chain_detector::PASS_ID);
    #[cfg(feature = "pyinstaller")]
    ids.push(disrobe_pass_pyinstaller::chain_detector::PASS_ID);
    #[cfg(feature = "pickle")]
    ids.push(disrobe_pass_pickle::chain_detector::PASS_ID);
    #[cfg(feature = "js")]
    ids.push(disrobe_pass_js_deob::chain_detector::PASS_ID);
    #[cfg(feature = "wasm")]
    ids.push(disrobe_pass_wasm_deob::chain_detector::PASS_ID);
    #[cfg(feature = "php")]
    ids.push(disrobe_pass_php::chain_detector::PASS_ID);
    #[cfg(feature = "ruby")]
    ids.push(disrobe_pass_ruby::chain_detector::PASS_ID);
    #[cfg(feature = "shell")]
    ids.push(disrobe_pass_shell::chain_detector::PASS_ID);
    #[cfg(feature = "mobile")]
    ids.push(disrobe_pass_mobile::chain_detector::PASS_ID);
    #[cfg(feature = "lua")]
    ids.push(disrobe_pass_lua::chain_detector::PASS_ID);
    #[cfg(feature = "swift")]
    ids.push(disrobe_pass_swift_objc::chain_detector::PASS_ID);
    #[cfg(feature = "jvm")]
    ids.push(disrobe_pass_jvm::chain_detector::PASS_ID);
    #[cfg(feature = "dotnet")]
    ids.push(disrobe_pass_dotnet::chain_detector::PASS_ID);
    #[cfg(feature = "go")]
    ids.push(disrobe_pass_go::chain_detector::PASS_ID);
    #[cfg(feature = "beam")]
    ids.push(disrobe_pass_beam::chain_detector::PASS_ID);
    #[cfg(feature = "as3")]
    ids.push(disrobe_pass_as3::chain_detector::PASS_ID);
    #[cfg(feature = "scriptlang")]
    ids.push(disrobe_pass_scriptlang::chain_detector::PASS_ID);
    #[cfg(feature = "nativelang")]
    ids.push(disrobe_pass_nativelang::chain_detector::PASS_ID);
    ids.sort_unstable();
    ids
}

#[must_use]
pub fn registered_pass_ids() -> Vec<PassId> {
    build_registry()
        .iter_passes()
        .map(disrobe_core::chain::Pass::id)
        .collect()
}

pub fn assert_meta_coherent(r: &PassRegistry) -> Result<(), String> {
    for pass in r.iter_passes() {
        let id: PassId = pass.id();
        let meta: disrobe_core::chain::PassMeta = pass.meta();
        if meta.id != id {
            return Err(format!(
                "pass {id} reports meta id {reported}",
                reported = meta.id
            ));
        }
        if meta.ecosystem == Ecosystem::Other {
            return Err(format!("pass {id} reports ecosystem other"));
        }
        let expected: Ecosystem = ecosystem_for(id);
        if meta.ecosystem != expected {
            return Err(format!(
                "pass {id} meta ecosystem {got} disagrees with ecosystem_for {want}",
                got = meta.ecosystem.slug(),
                want = expected.slug()
            ));
        }
    }
    Ok(())
}
