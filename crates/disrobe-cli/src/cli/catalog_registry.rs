use disrobe_core::chain::{CatalogEntry, ObfuscatorCatalog};

pub(crate) fn registry() -> Vec<&'static dyn ObfuscatorCatalog> {
    vec![
        &disrobe_pass_native::chain_detector::PackerDetector,
        &disrobe_pass_py_deob::chain_detector::PyDeobDetector,
        &disrobe_pass_pyarmor::chain_detector::PyarmorDetector,
        #[cfg(feature = "wasm")]
        &disrobe_pass_wasm_deob::chain_detector::WasmDetectorImpl,
        #[cfg(feature = "js")]
        &disrobe_pass_js_deob::chain_detector::JsObfDetector,
        #[cfg(feature = "lua")]
        &disrobe_pass_lua::chain_detector::LuaDetector,
        #[cfg(feature = "php")]
        &disrobe_pass_php::chain_detector::PhpDetectorImpl,
        #[cfg(feature = "dotnet")]
        &disrobe_pass_dotnet::chain_detector::DotnetDetector,
        #[cfg(feature = "shell")]
        &disrobe_pass_shell::chain_detector::ShellDetector,
        #[cfg(feature = "jvm")]
        &disrobe_pass_jvm::chain_detector::JvmDetector,
        #[cfg(feature = "go")]
        &disrobe_pass_go::chain_detector::GoDetector,
        #[cfg(feature = "ruby")]
        &disrobe_pass_ruby::chain_detector::RubyDetector,
        #[cfg(feature = "beam")]
        &disrobe_pass_beam::chain_detector::BeamDetector,
        #[cfg(feature = "as3")]
        &disrobe_pass_as3::chain_detector::As3Detector,
        #[cfg(feature = "mobile")]
        &disrobe_pass_mobile::chain_detector::MobileDetector,
        #[cfg(feature = "swift")]
        &disrobe_pass_swift_objc::chain_detector::SwiftObjcDetector,
    ]
}

pub(crate) fn display_name_for(catalog: &dyn ObfuscatorCatalog, entry_id: &str) -> &'static str {
    catalog
        .catalog()
        .into_iter()
        .find(|e: &&'static dyn CatalogEntry| e.id() == entry_id)
        .map_or("(unknown entry)", CatalogEntry::display_name)
}
