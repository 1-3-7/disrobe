#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/swift_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod swift_toolchain;

use disrobe_pass_swift_objc::demangle;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use swift_toolchain::{
    ReferenceDemangler, provenance_note, reference_demangle, resolve_reference_demangler,
    resolve_swift_compiler,
};

const GRADED: &str =
    "byte-exact agreement with swift-demangle on the FEAT-023 named-arm fixture corpus";

const COMPILED: &str = "the pinned arm symbols being emitted by a real Swift compiler";
const FREESTANDING_MACRO_SYMBOL: &str =
    "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX4_4_6expectfMf_.swift";

#[derive(Debug, Clone, Copy)]
struct ArmFixture {
    arm: &'static str,
    mangled: &'static str,
    expected: &'static str,
}

const ARM_FIXTURES: &[ArmFixture] = &[
    ArmFixture {
        arm: "opaque_return_type",
        mangled: "$s4Arms11makeGreeterQryF",
        expected: "Arms.makeGreeter() -> some",
    },
    ArmFixture {
        arm: "opaque_type_descriptor",
        mangled: "$s4Arms11makeGreeterQryFQOMQ",
        expected: "opaque type descriptor for <<opaque return type of Arms.makeGreeter() -> some>>",
    },
    ArmFixture {
        arm: "async_function",
        mangled: "$s4Arms10asyncGreetSSyYaF",
        expected: "Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "async_function_pointer",
        mangled: "$s4Arms10asyncGreetSSyYaFTu",
        expected: "async function pointer to Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "async_resume_partial",
        mangled: "$s4Arms10asyncGreetSSyYaFTQ0_",
        expected: "(1) await resume partial function for Arms.asyncGreet() async -> Swift.String",
    },
    ArmFixture {
        arm: "actor_entity",
        mangled: "$s4Arms7CounterC9incrementSiyF",
        expected: "Arms.Counter.increment() -> Swift.Int",
    },
    ArmFixture {
        arm: "distributed_actor_entity",
        mangled: "$s5Arms36WorkerC11Distributed0C5ActorAAMc",
        expected: "protocol conformance descriptor for Arms3.Worker : Distributed.DistributedActor in Arms3",
    },
    ArmFixture {
        arm: "distributed_thunk",
        mangled: "$s5Arms36WorkerC4pingSiyYaKFTE",
        expected: "distributed thunk Arms3.Worker.ping() async throws -> Swift.Int",
    },
    ArmFixture {
        arm: "distributed_accessor",
        mangled: "$s5Arms36WorkerC4pingSiyYaKFTETF",
        expected: "distributed accessor for distributed thunk Arms3.Worker.ping() async throws -> Swift.Int",
    },
    ArmFixture {
        arm: "global_actor_annotation",
        mangled: "$s4Arms7MyActorVs06GlobalC0AAMcMK",
        expected: "metadata instantiation cache for protocol conformance descriptor for Arms.MyActor : Swift.GlobalActor in Arms",
    },
    ArmFixture {
        arm: "isolated_parameter",
        mangled: "$s7IsoTest5touchySiAA5StoreCYiF",
        expected: "IsoTest.touch(isolated IsoTest.Store) -> Swift.Int",
    },
    ArmFixture {
        arm: "task_local_accessor",
        mangled: "$s5Arms39RequestIDO8$currents9TaskLocalCySiSgGvau",
        expected: "Arms3.RequestID.$current.unsafeMutableAddressor : Swift.TaskLocal<Swift.Int?>",
    },
    ArmFixture {
        arm: "sendable_closure",
        mangled: "$s4Arms15sendableClosureyyyyYbXEF",
        expected: "Arms.sendableClosure(@Sendable () -> ()) -> ()",
    },
    ArmFixture {
        arm: "attached_macro_expansion",
        mangled: "$s4Arms7CounterC9increment3FoofMm0_",
        expected: "member macro @Foo expansion #2 of increment in Arms.Counter",
    },
    ArmFixture {
        arm: "freestanding_macro_expansion",
        mangled: FREESTANDING_MACRO_SYMBOL,
        expected: "freestanding macro expansion #1 of expect in module MacroProbe file macro_probe.swift line 5 column 5 with unmangled suffix \".swift\"",
    },
    ArmFixture {
        arm: "partial_apply_forwarder",
        mangled: "$s5Arms215genericIdentityyxxlFTA",
        expected: "partial apply forwarder for Arms2.genericIdentity<A>(A) -> A",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sypypIgnn_S2iIegyy_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@in_guaranteed Any, @in_guaranteed Any) -> () to @escaping @callee_guaranteed (@unowned Swift.Int, @unowned Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sS2iSbIegnnd_S2iSbIegyyd_TR",
        expected: "reabstraction thunk helper from @escaping @callee_guaranteed (@in_guaranteed Swift.Int, @in_guaranteed Swift.Int) -> (@unowned Swift.Bool) to @escaping @callee_guaranteed (@unowned Swift.Int, @unowned Swift.Int) -> (@unowned Swift.Bool)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$ss5UInt8VIxr_ABIxd_TR",
        expected: "reabstraction thunk helper from @callee_owned () -> (@out Swift.UInt8) to @callee_owned () -> (@unowned Swift.UInt8)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sxIeghHr_xs5Error_pIegHrzo_s8SendableRzs5NeverORs_r0_lTR",
        expected: "reabstraction thunk helper <A, B where A: Swift.Sendable, B == Swift.Never> from @escaping @callee_guaranteed @Sendable @async () -> (@out A) to @escaping @callee_guaranteed @async () -> (@out A, @error @owned Swift.Error)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$s4null16NonSendableKlassCIegHo_ACs5Error_pIegHTrzo_TR",
        expected: "reabstraction thunk helper from @escaping @callee_guaranteed @async () -> (@owned null.NonSendableKlass) to @escaping @callee_guaranteed @async () -> sending (@out null.NonSendableKlass, @error @owned Swift.Error)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sxySilySbIsIgn_xySilySbIsIgn_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @substituted <A> (@in_guaranteed A) -> () for <Swift.Bool> for <Swift.Int> to @callee_guaranteed @substituted <A> (@in_guaranteed A) -> () for <Swift.Bool> for <Swift.Int>",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sxlIgn_xlIgn_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed <A> (@in_guaranteed A) -> () to @callee_guaranteed <A> (@in_guaranteed A) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIAg_IAg_TR",
        expected: "reabstraction thunk helper from @isolated(any) @callee_guaranteed () -> () to @isolated(any) @callee_guaranteed () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sS5fIertyyywddw_S5fIertyyywddw_TR",
        expected: "reabstraction thunk helper from @escaping @differentiable(reverse) @convention(thin) (@unowned Swift.Float, @unowned Swift.Float, @unowned @noDerivative Swift.Float) -> (@unowned Swift.Float, @unowned @noDerivative Swift.Float) to @escaping @differentiable(reverse) @convention(thin) (@unowned Swift.Float, @unowned Swift.Float, @unowned @noDerivative Swift.Float) -> (@unowned Swift.Float, @unowned @noDerivative Swift.Float)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIdg_Ilg_TR",
        expected: "reabstraction thunk helper from @differentiable @callee_guaranteed () -> () to @differentiable(_linear) @callee_guaranteed () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIfg_Irg_TR",
        expected: "reabstraction thunk helper from @differentiable(_forward) @callee_guaranteed () -> () to @differentiable(reverse) @callee_guaranteed () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIgzB3abc_IgzC3def_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @convention(block, mangledCType: \"abc\") () -> () to @callee_guaranteed @convention(c, mangledCType: \"def\") () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIgA_IgI_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @yield_once () -> () to @callee_guaranteed @yield_once_2 () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIgG_IgG_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @yield_many () -> () to @callee_guaranteed @yield_many () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIgM_IgO_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @convention(method) () -> () to @callee_guaranteed @convention(objc_method) () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sIgK_IgW_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed @convention(closure) () -> () to @callee_guaranteed @convention(witness_method) () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgiw_SiIgiT_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@in @noDerivative Swift.Int) -> () to @callee_guaranteed (@in sending Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgiI_SiIgiL_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@in isolated Swift.Int) -> () to @callee_guaranteed (@in sil_implicit_leading_param Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgiwTIL_SiIgiwTIL_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@in Swift.Int) -> () to @callee_guaranteed (@in Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgYi_SiIgzo_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed () -> (@yields @in Swift.Int) to @callee_guaranteed () -> (@error @owned Swift.Int)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$ss5UInt8VIxk_ABIxd_TR",
        expected: "reabstraction thunk helper from @callee_owned () -> (@pack_out Swift.UInt8) to @callee_owned () -> (@unowned Swift.UInt8)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "_T0Ix_IyB_Tr",
        expected: "reabstraction thunk from @callee_owned () -> () to @callee_unowned @convention(block) () -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$s12dynamic_self22FunctionConversionTestCIgg_ACIegn_ACXMTTy",
        expected: "reabstraction thunk from @callee_guaranteed (@guaranteed dynamic_self.FunctionConversionTest) -> () to @escaping @callee_guaranteed (@in_guaranteed dynamic_self.FunctionConversionTest) -> () self @thick dynamic_self.FunctionConversionTest.Type",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sxIgr_xIgr_lTRScMTU",
        expected: "reabstraction thunk helper <A> from @callee_guaranteed () -> (@out A) to @callee_guaranteed () -> (@out A) with global actor constraint Swift.MainActor",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$s12dynamic_self22FunctionConversionTestCIgg_ACIegn_ACXMtTy",
        expected: "reabstraction thunk from @callee_guaranteed (@guaranteed dynamic_self.FunctionConversionTest) -> () to @escaping @callee_guaranteed (@in_guaranteed dynamic_self.FunctionConversionTest) -> () self @thin dynamic_self.FunctionConversionTest.Type",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$s12dynamic_self22FunctionConversionTestCIgg_ACIegn_ACXMoTy",
        expected: "reabstraction thunk from @callee_guaranteed (@guaranteed dynamic_self.FunctionConversionTest) -> () to @escaping @callee_guaranteed (@in_guaranteed dynamic_self.FunctionConversionTest) -> () self @objc_metatype dynamic_self.FunctionConversionTest.Type",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sxlIPgn_xlIPgn_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed <A> (@in_guaranteed A) -> () to @callee_guaranteed <A> (@in_guaranteed A) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sS4iIgblce_S4iIgvpmx_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@inout_aliasable Swift.Int, @inout Swift.Int, @in_constant Swift.Int, @deallocating Swift.Int) -> () to @callee_guaranteed (@pack_owned Swift.Int, @pack_guaranteed Swift.Int, @pack_inout Swift.Int, @owned Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sS2iIggX_S2iIgXg_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed (@guaranteed Swift.Int, @in_cxx Swift.Int) -> () to @callee_guaranteed (@in_cxx Swift.Int, @guaranteed Swift.Int) -> ()",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sS2iIgua_S2iIgdk_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed () -> (@unowned_inner_pointer Swift.Int, @autoreleased Swift.Int) to @callee_guaranteed () -> (@unowned Swift.Int, @pack_out Swift.Int)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgzl_SiIgzo_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed () -> (@error @guaranteed_address Swift.Int) to @callee_guaranteed () -> (@error @owned Swift.Int)",
    },
    ArmFixture {
        arm: "reabstraction_thunk",
        mangled: "$sSiIgzg_SiIgzm_TR",
        expected: "reabstraction thunk helper from @callee_guaranteed () -> (@error @guaranteed Swift.Int) to @callee_guaranteed () -> (@error @inout Swift.Int)",
    },
    ArmFixture {
        arm: "autodiff_function",
        mangled: "$s13AutoDiffProbe21differentiateMultiplyyS2fFTJfSpSr",
        expected: "forward-mode derivative of AutoDiffProbe.differentiateMultiply(Swift.Float) -> Swift.Float with respect to parameters {0} and results {0}",
    },
    ArmFixture {
        arm: "autodiff_function",
        mangled: "$s13AutoDiffProbe21differentiateMultiplyyS2fFTJrSpSr",
        expected: "reverse-mode derivative of AutoDiffProbe.differentiateMultiply(Swift.Float) -> Swift.Float with respect to parameters {0} and results {0}",
    },
    ArmFixture {
        arm: "autodiff_function",
        mangled: "$s13AutoDiffProbe21differentiateMultiplyyS2fFTJpSpSr",
        expected: "pullback of AutoDiffProbe.differentiateMultiply(Swift.Float) -> Swift.Float with respect to parameters {0} and results {0}",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$s13AutoDiffProbe8multiplyyxx_xtSjRzlFS5fIegnr_Iegnnro_TJSfSSpSrSUP",
        expected: "autodiff subset parameters thunk for forward-mode derivative from AutoDiffProbe.multiply<A where A: Swift.Numeric>(A, A) -> A with respect to parameters {0, 1} and results {0} to parameters {0} of type @escaping @callee_guaranteed (@in_guaranteed Swift.Float, @in_guaranteed Swift.Float) -> (@out Swift.Float, @owned @escaping @callee_guaranteed (@in_guaranteed Swift.Float) -> (@out Swift.Float))",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$s13AutoDiffProbe8multiplyyxx_xtSjRzlFS5fIegnr_Iegnnro_TJSrSSpSrSUP",
        expected: "autodiff subset parameters thunk for reverse-mode derivative from AutoDiffProbe.multiply<A where A: Swift.Numeric>(A, A) -> A with respect to parameters {0, 1} and results {0} to parameters {0} of type @escaping @callee_guaranteed (@in_guaranteed Swift.Float, @in_guaranteed Swift.Float) -> (@out Swift.Float, @owned @escaping @callee_guaranteed (@in_guaranteed Swift.Float) -> (@out Swift.Float))",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$sS3fIegnnr_TJSdSSpSrSUP",
        expected: "autodiff subset parameters thunk for differential from @escaping @callee_guaranteed (@in_guaranteed Swift.Float, @in_guaranteed Swift.Float) -> (@out Swift.Float) with respect to parameters {0, 1} and results {0} to parameters {0}",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$sS3fIegnrr_TJSpSSpSrSUP",
        expected: "autodiff subset parameters thunk for pullback from @escaping @callee_guaranteed (@in_guaranteed Swift.Float) -> (@out Swift.Float, @out Swift.Float) with respect to parameters {0, 1} and results {0} to parameters {0}",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$s6vtable5SuperC6methodyS2f_SftFTJVfSUUpSr",
        expected: "vtable thunk for forward-mode derivative of vtable.Super.method(Swift.Float, Swift.Float) -> Swift.Float with respect to parameters {0} and results {0}",
    },
    ArmFixture {
        arm: "autodiff_thunk",
        mangled: "$sS2f8mangling3FooV13TangentVectorVIegydd_SfAESfIegydd_TJOp",
        expected: "autodiff self-reordering reabstraction thunk for pullback from @escaping @callee_guaranteed (@unowned Swift.Float) -> (@unowned Swift.Float, @unowned mangling.Foo.TangentVector) to @escaping @callee_guaranteed (@unowned Swift.Float) -> (@unowned mangling.Foo.TangentVector, @unowned Swift.Float)",
    },
    ArmFixture {
        arm: "protocol_witness_thunk",
        mangled: "$s4Arms14EnglishGreeterVAA0C0A2aDP5greetSSyFTW",
        expected: "protocol witness for Arms.Greeter.greet() -> Swift.String in conformance Arms.EnglishGreeter : Arms.Greeter in Arms",
    },
    ArmFixture {
        arm: "objc_bridging_thunk",
        mangled: "$s4Arms7CounterC9incrementSiyFTo",
        expected: "@objc Arms.Counter.increment() -> Swift.Int",
    },
    ArmFixture {
        arm: "method_descriptor",
        mangled: "$s4Arms7CounterCACycfCTq",
        expected: "method descriptor for Arms.Counter.__allocating_init() -> Arms.Counter",
    },
    ArmFixture {
        arm: "dispatch_thunk",
        mangled: "$sSQ2eeoiySbx_xtFZTj",
        expected: "dispatch thunk of static Swift.Equatable.== infix(A, A) -> Swift.Bool",
    },
    ArmFixture {
        arm: "keypath_getter_thunk",
        mangled: "$s5Arms27WrapperV8computedSivpACTK",
        expected: "key path getter for Arms2.Wrapper.computed : Swift.Int : Arms2.Wrapper",
    },
    ArmFixture {
        arm: "keypath_setter_thunk",
        mangled: "$s5Arms27WrapperV8computedSivpACTk",
        expected: "key path setter for Arms2.Wrapper.computed : Swift.Int : Arms2.Wrapper",
    },
    ArmFixture {
        arm: "generic_signature_with_requirements",
        mangled: "$s4Arms10GenericBoxV6isLess4thanSbx_tqd__RszlF",
        expected: "Arms.GenericBox.isLess<A where A == A1>(than: A) -> Swift.Bool",
    },
    ArmFixture {
        arm: "associated_type_descriptor",
        mangled: "$s7Element4Arms8HasAssocPTl",
        expected: "associated type descriptor for Arms.HasAssoc.Element",
    },
    ArmFixture {
        arm: "protocol_conformance_descriptor",
        mangled: "$sSi8OtherMod0A5Proto4ArmsMc",
        expected: "protocol conformance descriptor for Swift.Int : OtherMod.OtherProto in Arms",
    },
    ArmFixture {
        arm: "protocol_witness_table",
        mangled: "$sSi8OtherMod0A5Proto4ArmsWP",
        expected: "protocol witness table for Swift.Int : OtherMod.OtherProto in Arms",
    },
    ArmFixture {
        arm: "lazy_witness_table_accessor",
        mangled: "$s9MacroTest8Counter2CAC11Observation10ObservableAAWl",
        expected: "lazy protocol witness table accessor for type MacroTest.Counter2 and conformance MacroTest.Counter2 : Observation.Observable in MacroTest",
    },
];

const OPEN_ARMS: &[&str] = &[];

fn windows_sdk(swiftc: &Path) -> Option<PathBuf> {
    let swift_root: &Path = swiftc.ancestors().nth(5)?;
    let toolchain: &str = swiftc.ancestors().nth(3)?.file_name()?.to_str()?;
    let version: &str = toolchain.split_once('+').map_or(toolchain, |pair| pair.0);
    let sdk: PathBuf = swift_root
        .join("Platforms")
        .join(version)
        .join("Windows.platform")
        .join("Developer")
        .join("SDKs")
        .join("Windows.sdk");
    sdk.is_dir().then_some(sdk)
}

#[derive(Debug, Clone, Copy)]
struct CompiledFixture {
    source: &'static str,
    module: &'static str,
    symbol: &'static str,
}

const COMPILED_FIXTURES: &[CompiledFixture] = &[
    CompiledFixture {
        source: "reabstraction_thunk.swift",
        module: "Arms",
        symbol: "$sypypIgnn_S2iIegyy_TR",
    },
    CompiledFixture {
        source: "dynamic_self_reabstraction.swift",
        module: "dynamic_self",
        symbol: "$s12dynamic_self22FunctionConversionTestCIgg_ACIegn_ACXMTTy",
    },
    CompiledFixture {
        source: "autodiff_thunk.swift",
        module: "AutoDiffProbe",
        symbol: "$s13AutoDiffProbe8multiplyyxx_xtSjRzlFS5fIegnr_Iegnnro_TJSfSSpSrSUP",
    },
];

fn sibling_tool(swiftc: &Path, stem: &str) -> PathBuf {
    let exe: String = if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    };
    swiftc
        .parent()
        .map(|parent: &Path| parent.join(&exe))
        .filter(|tool: &PathBuf| tool.is_file())
        .unwrap_or_else(|| {
            panic!(
                "{stem} does not sit beside {}; a Swift toolchain that is present and incomplete \
                 is never a skip",
                swiftc.display()
            )
        })
}

fn compiled_symbol_table(swiftc: &Path, fixture: CompiledFixture) -> String {
    let source: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(fixture.source);
    let output_dir: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join(fixture.module);
    fs::create_dir_all(&output_dir).expect("create the compiled fixture output directory");
    let object: PathBuf = output_dir.join(format!(
        "{}.{}",
        fixture.module,
        if cfg!(windows) { "obj" } else { "o" }
    ));
    let mut command: Command = Command::new(swiftc);
    if cfg!(windows) {
        let sdk: PathBuf = windows_sdk(swiftc).unwrap_or_else(|| {
            panic!(
                "no Windows SDK sits beside {}; a Swift toolchain that is present and unusable is \
                 never a skip",
                swiftc.display()
            )
        });
        command.arg("-sdk").arg(sdk);
    }
    let compiled: Output = command
        .arg("-emit-object")
        .arg("-module-name")
        .arg(fixture.module)
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("run swiftc for the compiled fixture");
    assert!(
        compiled.status.success(),
        "{} failed to compile {}: {}",
        swiftc.display(),
        source.display(),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let llvm_nm: PathBuf = sibling_tool(swiftc, "llvm-nm");
    let listed: Output = Command::new(&llvm_nm)
        .arg(&object)
        .output()
        .expect("run llvm-nm on the compiled fixture");
    assert!(
        listed.status.success(),
        "{} failed to read {}: {}",
        llvm_nm.display(),
        object.display(),
        String::from_utf8_lossy(&listed.stderr)
    );
    String::from_utf8(listed.stdout).expect("llvm-nm emits a UTF-8 symbol table")
}

#[test]
fn a_real_compiler_emits_every_pinned_reabstraction_thunk_symbol() {
    let Some(swiftc): Option<PathBuf> = resolve_swift_compiler(COMPILED) else {
        return;
    };
    for fixture in COMPILED_FIXTURES {
        assert!(
            ARM_FIXTURES
                .iter()
                .any(|f: &ArmFixture| f.mangled == fixture.symbol),
            "{} is compiled for provenance but no arm fixture grades it, so compiling it proves \
             nothing about recovery",
            fixture.symbol
        );
        let table: String = compiled_symbol_table(&swiftc, *fixture);
        assert!(
            table
                .lines()
                .any(|line: &str| line.split(' ').next_back() == Some(fixture.symbol)),
            "{} compiled {} without emitting {}, so the pinned mangling is not what this \
             compiler produces",
            swiftc.display(),
            fixture.source,
            fixture.symbol
        );
    }
}

fn closed_arm_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ARM_FIXTURES.iter().map(|f: &ArmFixture| f.arm).collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[test]
fn arm_fixture_mangled_names_are_unique() {
    let mut mangled: Vec<&'static str> = ARM_FIXTURES
        .iter()
        .map(|f: &ArmFixture| f.mangled)
        .collect();
    let before: usize = mangled.len();
    mangled.sort_unstable();
    mangled.dedup();
    assert_eq!(
        mangled.len(),
        before,
        "the fixture corpus must not grade the same mangled symbol under two arm names"
    );
}

#[test]
fn arm_fixtures_demangle_to_pinned_text() {
    for fixture in ARM_FIXTURES {
        let rendered: String = demangle::demangle(fixture.mangled).unwrap_or_else(|e| {
            panic!(
                "arm {} ({}) must demangle, got {e:?}",
                fixture.arm, fixture.mangled
            )
        });
        assert_eq!(
            rendered, fixture.expected,
            "arm {} regressed for {}",
            fixture.arm, fixture.mangled
        );
    }
}

#[test]
fn arm_fixtures_match_live_swift_demangle() {
    let Some(demangler): Option<ReferenceDemangler> = resolve_reference_demangler(GRADED) else {
        return;
    };
    let symbols: Vec<&str> = ARM_FIXTURES
        .iter()
        .map(|f: &ArmFixture| f.mangled)
        .collect();
    let live: Vec<String> = reference_demangle(&demangler, &symbols);
    for (fixture, actual) in ARM_FIXTURES.iter().zip(live.iter()) {
        assert_eq!(
            fixture.expected,
            actual,
            "the pinned text for arm {} drifted from what {} produces for {}. {}",
            fixture.arm,
            demangler.tool.display(),
            fixture.mangled,
            provenance_note(&demangler.identity)
        );
    }
}

#[test]
fn named_arm_coverage_is_measured_by_the_gate() {
    let closed: Vec<&'static str> = closed_arm_names();
    for arm in &closed {
        assert!(
            !OPEN_ARMS.contains(arm),
            "{arm} is listed as both closed (has a fixture) and open (documented gap)"
        );
    }
    let total: usize = closed.len() + OPEN_ARMS.len();
    let ratio: f64 = closed.len() as f64 / total as f64;
    eprintln!(
        "FEAT-023 named-arm coverage: {}/{} = {:.1}% closed with a real-compiler-graded fixture. \
         still open: {OPEN_ARMS:?}",
        closed.len(),
        total,
        ratio * 100.0
    );
    assert!(
        ratio > 0.75,
        "named-arm coverage must exceed the recorded 0.75 baseline, measured {}/{} = {:.3}",
        closed.len(),
        total,
        ratio
    );
}

const CROSS_CUTTING_FORMS: &[(&str, &str)] = &[
    (
        "generic_signature_with_requirements",
        "generic_signature_with_requirements",
    ),
    ("associated_types", "associated_type_descriptor"),
    ("substitution_back_references", "protocol_witness_thunk"),
    (
        "protocol_conformance_descriptors",
        "protocol_conformance_descriptor",
    ),
    ("compressed_identifiers", "protocol_witness_thunk"),
];

#[test]
fn every_cross_cutting_form_is_exercised_inside_a_closed_arm() {
    let closed: Vec<&'static str> = closed_arm_names();
    for (form, arm) in CROSS_CUTTING_FORMS {
        assert!(
            closed.contains(arm),
            "cross-cutting form {form} is claimed to be exercised inside arm {arm}, but that \
             arm has no closed, real-compiler-graded fixture"
        );
    }
}

#[test]
fn mangling_prefixes_across_swift_releases_are_all_accepted() {
    let body: &str = "4Arms7GreeterP";
    let expected: &str = "Arms.Greeter (protocol)";
    for prefix in ["_$s", "$s", "_$S", "$S", "_T0", "T0"] {
        let symbol: String = format!("{prefix}{body}");
        let rendered: String = demangle::demangle(&symbol)
            .unwrap_or_else(|e| panic!("prefix {prefix} must be accepted, got {e:?}"));
        assert_eq!(rendered, expected, "prefix {prefix} rendered differently");
    }
    assert!(
        demangle::demangle("_$t4Arms7GreeterP").is_err(),
        "an unrecognized prefix must abstain rather than guess"
    );
}

#[test]
fn swift_macro_filename_prefix_and_suffix_are_bounded() {
    let symbol: &str = FREESTANDING_MACRO_SYMBOL
        .strip_suffix(".swift")
        .expect("the compiler-emitted fixture must carry its unmangled suffix");
    assert!(demangle::looks_like_swift_mangled(symbol));
    assert_eq!(
        demangle::demangle(symbol).expect("the compiler-emitted macro filename must demangle"),
        "freestanding macro expansion #1 of expect in module MacroProbe file macro_probe.swift line 5 column 5"
    );
    for malformed in [
        "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX4_4_6expectfMf",
        "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX4_4_6expectfMf_bad",
    ] {
        assert!(
            demangle::demangle(malformed).is_err(),
            "a truncated or non-suffix macro filename must abstain: {malformed}"
        );
    }
}

#[test]
fn swift_macro_suffixes_use_swift_byte_escaping() {
    let stem: &str = FREESTANDING_MACRO_SYMBOL
        .strip_suffix(".swift")
        .expect("the compiler-emitted fixture must carry its unmangled suffix");
    assert_eq!(
        demangle::demangle(&format!("{stem}.é")).expect("a UTF-8 suffix must demangle"),
        r#"freestanding macro expansion #1 of expect in module MacroProbe file macro_probe.swift line 5 column 5 with unmangled suffix ".\xC3\xA9""#
    );
    assert_eq!(
        demangle::demangle(&format!("{stem}.\t\n\r\"\\\0\u{1f}"))
            .expect("a suffix with escaped bytes must demangle"),
        r#"freestanding macro expansion #1 of expect in module MacroProbe file macro_probe.swift line 5 column 5 with unmangled suffix ".\t\n\r\"\\\0\x1F""#
    );
}

#[test]
fn swift_macro_locations_match_swift_signed_index_boundaries() {
    let symbol: &str =
        "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX2147483647_4_6expectfMf_.swift";
    assert_eq!(
        demangle::demangle(symbol).expect("Swift accepts the maximum signed line operand"),
        "freestanding macro expansion #1 of expect in module MacroProbe file macro_probe.swift line 18446744071562067968 column 5 with unmangled suffix \".swift\""
    );
    assert!(
        demangle::demangle(
            "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX2147483648_4_6expectfMf_.swift"
        )
        .is_err(),
        "Swift refuses a line operand beyond its signed parser boundary"
    );
    assert_eq!(
        demangle::demangle(
            "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX4_4_6expectfMf2147483646_.swift"
        )
        .expect("Swift accepts the maximum nonnegative discriminator"),
        "freestanding macro expansion # of expect in module MacroProbe file macro_probe.swift line 5 column 5 with unmangled suffix \".swift\""
    );
    assert!(
        demangle::demangle(
            "@__swiftmacro_10MacroProbe0022macro_probeswift_tiAIefMX4_4_6expectfMf2147483647_.swift"
        )
        .is_err(),
        "Swift refuses a discriminator whose decoded index is negative"
    );
}

#[test]
fn a_real_compiler_emits_the_pinned_freestanding_macro_filename() {
    let Some(swiftc): Option<PathBuf> = resolve_swift_compiler(COMPILED) else {
        return;
    };
    let source: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("macro_probe.swift");
    let output_dir: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join("MacroProbe");
    fs::create_dir_all(&output_dir).expect("create the macro fixture output directory");
    let object: PathBuf = output_dir.join(if cfg!(windows) {
        "MacroProbe.obj"
    } else {
        "MacroProbe.o"
    });
    let mut command: Command = Command::new(&swiftc);
    if cfg!(windows) {
        let sdk: PathBuf = windows_sdk(&swiftc).unwrap_or_else(|| {
            panic!(
                "no Windows SDK sits beside {}; a present Swift compiler must be usable",
                swiftc.display()
            )
        });
        let swift_root: &Path = swiftc
            .ancestors()
            .nth(5)
            .expect("the Windows Swift compiler must sit under its installation root");
        let toolchain: &str = swiftc
            .ancestors()
            .nth(3)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .expect("the Windows Swift toolchain directory must carry its version");
        let version: &str = toolchain
            .split_once('+')
            .map_or(toolchain, |pair: (&str, &str)| pair.0);
        let testing: PathBuf = swift_root
            .join("Platforms")
            .join(version)
            .join("Windows.platform")
            .join("Developer")
            .join("Library")
            .join(format!("Testing-{version}"))
            .join("usr")
            .join("lib")
            .join("swift")
            .join("windows");
        command.arg("-sdk").arg(sdk).arg("-I").arg(testing);
    }
    let compiled: Output = command
        .arg("-g")
        .arg("-parse-as-library")
        .arg("-emit-object")
        .arg("-module-name")
        .arg("MacroProbe")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("run swiftc for the freestanding macro fixture");
    assert!(
        compiled.status.success(),
        "{} failed to compile {}: {}",
        swiftc.display(),
        source.display(),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes: Vec<u8> = fs::read(&object).expect("read the compiled macro fixture object");
    assert!(
        bytes
            .windows(FREESTANDING_MACRO_SYMBOL.len())
            .any(|window: &[u8]| window == FREESTANDING_MACRO_SYMBOL.as_bytes()),
        "{} did not emit the pinned macro filename",
        object.display()
    );
}

#[test]
fn a_symbolic_reference_that_cannot_resolve_abstains() {
    assert!(
        demangle::demangle_type("\u{1}").is_none(),
        "a control byte standing in for an unresolved symbolic reference must abstain, not guess"
    );
    assert!(
        demangle::demangle("$s\u{1}").is_err(),
        "a symbol carrying a raw symbolic-reference byte must abstain rather than echo it back"
    );
}

#[test]
fn a_substitution_index_beyond_the_table_abstains() {
    assert!(
        demangle::demangle("$sAB").is_err(),
        "the first substitution reference in a symbol has nothing to resolve against and must \
         abstain, not panic or guess"
    );
}

#[test]
fn a_punycode_identifier_that_fails_to_decode_abstains() {
    assert!(
        demangle::demangle("$s004fooP").is_err(),
        "a malformed punycode-prefixed identifier must abstain rather than emit garbage text"
    );
}

#[test]
fn a_mangled_name_over_the_length_bound_is_rejected() {
    let oversized: String = format!("$s4Arms{}P", "A".repeat(1 << 17));
    assert!(
        demangle::demangle(&oversized).is_err(),
        "a mangled name far past any real symbol's length must be capped and rejected"
    );
}

#[test]
fn a_truncated_mangled_name_yields_a_typed_error_not_a_panic() {
    let full: &str = ARM_FIXTURES[0].mangled;
    for end in 1..full.len() {
        let _: Result<String, _> = demangle::demangle(&full[..end]);
    }
}
