use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_dotnet::cil::{FlowControl, MethodBody, OperandValue, parse_method_body};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::Resolver;
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

const FIXTURE_DIR: &str = "tests/fixtures/cha_devirtualization";

struct FixtureProject {
    _scratch: Option<ScratchDir>,
    assembly: PathBuf,
}

fn manifest_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn dotnet_9_sdk_available() -> bool {
    Command::new("dotnet")
        .arg("--list-sdks")
        .output()
        .is_ok_and(|output: Output| {
            output.status.success()
                && sdk_list_has_dotnet_9(&String::from_utf8_lossy(&output.stdout))
        })
}

fn sdk_list_has_dotnet_9(sdk_list: &str) -> bool {
    sdk_list
        .lines()
        .filter_map(|line: &str| line.split_whitespace().next())
        .any(|version: &str| version.split('.').next() == Some("9"))
}

fn build_fixture() -> Result<FixtureProject, String> {
    if !dotnet_9_sdk_available() {
        return committed_fixture("ChaDevirtualization.dll");
    }
    let scratch: ScratchDir = ScratchDir::create("disrobe-dotnet-cha")
        .map_err(|error: std::io::Error| format!("create temporary fixture project: {error}"))?;
    let root: PathBuf = scratch.path().to_path_buf();
    for name in ["ChaDevirtualization.csproj", "Calls.cs"] {
        let source: PathBuf = manifest_path(FIXTURE_DIR).join(name);
        let destination: PathBuf = root.join(name);
        std::fs::copy(&source, &destination)
            .map_err(|error: std::io::Error| format!("copy fixture source {name}: {error}"))?;
    }
    let project: PathBuf = root.join("ChaDevirtualization.csproj");
    let output_dir: PathBuf = root.join("out");
    let output: Output = Command::new("dotnet")
        .arg("build")
        .arg(&project)
        .arg("-c")
        .arg("Release")
        .arg("-nologo")
        .arg("-o")
        .arg(&output_dir)
        .output()
        .map_err(|error: std::io::Error| format!("run dotnet build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "dotnet build failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(FixtureProject {
        _scratch: Some(scratch),
        assembly: output_dir.join("ChaDevirtualization.dll"),
    })
}

fn build_duplicate_fixture() -> Result<FixtureProject, String> {
    if !dotnet_9_sdk_available() {
        return committed_fixture("DuplicateDispatch.dll");
    }
    let scratch: ScratchDir = ScratchDir::create("disrobe-dotnet-cha")
        .map_err(|error: std::io::Error| format!("create duplicate fixture project: {error}"))?;
    let root: PathBuf = scratch.path().to_path_buf();
    for name in [
        "DuplicateDispatchEmitter.csproj",
        "DuplicateDispatchEmitter.cs",
    ] {
        let source: PathBuf = manifest_path(FIXTURE_DIR).join(name);
        let destination: PathBuf = root.join(name);
        std::fs::copy(&source, &destination).map_err(|error: std::io::Error| {
            format!("copy duplicate fixture source {name}: {error}")
        })?;
    }
    let project: PathBuf = root.join("DuplicateDispatchEmitter.csproj");
    let assembly: PathBuf = root.join("DuplicateDispatch.dll");
    let output: Output = Command::new("dotnet")
        .arg("run")
        .arg("-c")
        .arg("Release")
        .arg("--project")
        .arg(&project)
        .arg("--")
        .arg(&assembly)
        .output()
        .map_err(|error: std::io::Error| format!("run duplicate fixture emitter: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "duplicate fixture emitter failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    if !stdout.contains(
        "duplicate-methods=2; duplicate-methodimpls=0; duplicate-interface-result=1; explicit-methodimpls=1; explicit-interface-result=3",
    ) {
        return Err(format!("unexpected duplicate fixture oracle output: {stdout}"));
    }
    if !assembly.is_file() {
        return Err("duplicate fixture emitter produced no assembly".to_owned());
    }
    Ok(FixtureProject {
        _scratch: Some(scratch),
        assembly,
    })
}

fn committed_fixture(name: &str) -> Result<FixtureProject, String> {
    let assembly: PathBuf = manifest_path(FIXTURE_DIR).join(name);
    if !assembly.is_file() {
        return Err("CORPUS-BLOCKED: dotnet SDK and committed fixture are unavailable".to_owned());
    }
    Ok(FixtureProject {
        _scratch: None,
        assembly,
    })
}

fn resolver_for(image: &[u8]) -> Result<(Resolver, PeImage), String> {
    let pe: PeImage = parse(image).map_err(|error| format!("parse fixture PE: {error}"))?;
    let clr: ClrHeader = parse_clr_header(image, &pe)
        .map_err(|error| format!("parse fixture CLR header: {error}"))?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)
        .map_err(|error| format!("parse fixture metadata: {error}"))?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)
        .map_err(|error| format!("build resolver: {error}"))?;
    Ok((resolver, pe))
}

fn method_body(
    resolver: &Resolver,
    pe: &PeImage,
    image: &[u8],
    method_name: &str,
) -> Result<MethodBody, String> {
    let (_, _, rva): (u32, String, u32) = resolver
        .methods_with_bodies()
        .into_iter()
        .find(|(_, name, _): &(u32, String, u32)| name.ends_with(method_name))
        .ok_or_else(|| format!("missing fixture method {method_name}"))?;
    let offset: usize = pe
        .rva_to_offset(rva)
        .ok_or_else(|| format!("fixture method {method_name} has no file offset"))?;
    parse_method_body(&image[offset..])
        .map_err(|error| format!("parse fixture method body {method_name}: {error}"))
}

fn call_sites(resolver: &Resolver, body: &MethodBody) -> Vec<(String, String)> {
    body.instructions
        .iter()
        .filter_map(|instruction: &disrobe_pass_dotnet::cil::Instruction| {
            let OperandValue::Token(token) = instruction.operand else {
                return None;
            };
            matches!(instruction.name.as_str(), "call" | "callvirt")
                .then(|| (instruction.name.clone(), resolver.resolve_token(token)))
        })
        .collect()
}

fn assert_site(calls: &[(String, String)], opcode: &str, target: &str) {
    assert!(
        calls
            .iter()
            .any(|(actual_opcode, actual_target): &(String, String)| {
                actual_opcode == opcode && actual_target == target
            }),
        "missing {opcode} {target}; calls={calls:?}"
    );
}

fn site_count(calls: &[(String, String)], opcode: &str, target: &str) -> usize {
    calls
        .iter()
        .filter(|(actual_opcode, actual_target): &&(String, String)| {
            actual_opcode == opcode && actual_target == target
        })
        .count()
}

#[test]
fn dotnet_9_sdk_detection_requires_major_9() {
    assert!(!sdk_list_has_dotnet_9(
        "8.0.419 [C:\\Program Files\\dotnet\\sdk]"
    ));
    assert!(sdk_list_has_dotnet_9(
        "8.0.419 [C:\\Program Files\\dotnet\\sdk]\n9.0.314 [C:\\Program Files\\dotnet\\sdk]"
    ));
}

#[test]
fn devirtualizes_only_compiler_grounded_monomorphic_callvirt_sites() -> Result<(), String> {
    let fixture: FixtureProject = build_fixture()?;
    let image: Vec<u8> = std::fs::read(&fixture.assembly)
        .map_err(|error: std::io::Error| format!("read compiled fixture: {error}"))?;
    let (resolver, pe): (Resolver, PeImage) = resolver_for(&image)?;

    let base_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallBaseViaNewObject")?;
    let unique_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallUniqueInterface")?;
    let unique_exact_original: MethodBody = method_body(
        &resolver,
        &pe,
        &image,
        "Calls::CallUniqueInterfaceViaNewObject",
    )?;
    let constrained_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallConstrainedGeneric")?;
    let polymorphic_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallPolymorphicInterface")?;
    let inherited_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallInheritedInterface")?;
    let shadowed_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallShadowedVirtualSlot")?;
    let non_immediate_original: MethodBody = method_body(
        &resolver,
        &pe,
        &image,
        "Calls::CallNonImmediateVirtualOverride",
    )?;
    let exact_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallExactNewObject")?;
    let nullable_sealed_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallNullableSealed")?;
    let branch_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallAcrossBranch")?;
    let static_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallSealedStaticField")?;
    let mutable_static_original: MethodBody =
        method_body(&resolver, &pe, &image, "Calls::CallMutableStaticField")?;

    assert_site(
        &call_sites(&resolver, &base_original),
        "callvirt",
        "ChaOracle.BaseGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &unique_original),
        "callvirt",
        "ChaOracle.IOnly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &unique_exact_original),
        "callvirt",
        "ChaOracle.IOnly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &constrained_original),
        "callvirt",
        "ChaOracle.IOnly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &polymorphic_original),
        "callvirt",
        "ChaOracle.IPoly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &inherited_original),
        "callvirt",
        "ChaOracle.IInherited::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &shadowed_original),
        "callvirt",
        "ChaOracle.SlotBase::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &non_immediate_original),
        "callvirt",
        "ChaOracle.SlotHider::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &exact_original),
        "callvirt",
        "ChaOracle.IExactGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &nullable_sealed_original),
        "callvirt",
        "ChaOracle.ExactGreeter::Greet",
    );
    assert!(branch_original.instructions.iter().any(
        |instruction: &disrobe_pass_dotnet::cil::Instruction| {
            instruction.flow == FlowControl::CondBranch
        }
    ));
    assert_eq!(
        site_count(
            &call_sites(&resolver, &branch_original),
            "callvirt",
            "ChaOracle.IExactGreeter::Greet",
        ),
        2
    );
    assert_site(
        &call_sites(&resolver, &static_original),
        "callvirt",
        "ChaOracle.IExactGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &mutable_static_original),
        "callvirt",
        "ChaOracle.IExactGreeter::Greet",
    );

    let base: MethodBody = resolver.devirtualize_callvirt(&base_original);
    let unique: MethodBody = resolver.devirtualize_callvirt(&unique_original);
    let unique_exact: MethodBody = resolver.devirtualize_callvirt(&unique_exact_original);
    let constrained: MethodBody = resolver.devirtualize_callvirt(&constrained_original);
    let polymorphic: MethodBody = resolver.devirtualize_callvirt(&polymorphic_original);
    let inherited: MethodBody = resolver.devirtualize_callvirt(&inherited_original);
    let shadowed: MethodBody = resolver.devirtualize_callvirt(&shadowed_original);
    let non_immediate: MethodBody = resolver.devirtualize_callvirt(&non_immediate_original);
    let exact: MethodBody = resolver.devirtualize_callvirt(&exact_original);
    let nullable_sealed: MethodBody = resolver.devirtualize_callvirt(&nullable_sealed_original);
    let branch: MethodBody = resolver.devirtualize_callvirt(&branch_original);
    let static_call: MethodBody = resolver.devirtualize_callvirt(&static_original);
    let mutable_static: MethodBody = resolver.devirtualize_callvirt(&mutable_static_original);

    assert_site(
        &call_sites(&resolver, &base),
        "call",
        "ChaOracle.SealedGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &unique),
        "callvirt",
        "ChaOracle.IOnly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &unique_exact),
        "call",
        "ChaOracle.OnlyImplementation::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &constrained),
        "callvirt",
        "ChaOracle.IOnly::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &exact),
        "call",
        "ChaOracle.ExactGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &nullable_sealed),
        "callvirt",
        "ChaOracle.ExactGreeter::Greet",
    );
    assert_eq!(
        site_count(
            &call_sites(&resolver, &branch),
            "call",
            "ChaOracle.ExactGreeter::Greet",
        ),
        2
    );
    assert_site(
        &call_sites(&resolver, &inherited),
        "call",
        "ChaOracle.InheritedDerived::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &shadowed),
        "call",
        "ChaOracle.SlotBase::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &non_immediate),
        "call",
        "ChaOracle.SlotGapDerived::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &static_call),
        "callvirt",
        "ChaOracle.IExactGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &mutable_static),
        "callvirt",
        "ChaOracle.IExactGreeter::Greet",
    );
    assert_site(
        &call_sites(&resolver, &polymorphic),
        "callvirt",
        "ChaOracle.IPoly::Invoke",
    );
    Ok(())
}

#[test]
fn retains_callvirt_for_duplicate_and_explicit_interface_metadata() -> Result<(), String> {
    let fixture: FixtureProject = build_duplicate_fixture()?;
    let image: Vec<u8> = std::fs::read(&fixture.assembly)
        .map_err(|error: std::io::Error| format!("read duplicate fixture: {error}"))?;
    let (resolver, pe): (Resolver, PeImage) = resolver_for(&image)?;
    let duplicate_original: MethodBody = method_body(&resolver, &pe, &image, "Calls::Call")?;
    let explicit_original: MethodBody = method_body(&resolver, &pe, &image, "Calls::CallExplicit")?;

    assert_site(
        &call_sites(&resolver, &duplicate_original),
        "callvirt",
        "ChaDuplicateDispatch.I::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &explicit_original),
        "callvirt",
        "ChaDuplicateDispatch.I::Invoke",
    );

    let duplicate: MethodBody = resolver.devirtualize_callvirt(&duplicate_original);
    let explicit: MethodBody = resolver.devirtualize_callvirt(&explicit_original);

    assert_site(
        &call_sites(&resolver, &duplicate),
        "callvirt",
        "ChaDuplicateDispatch.I::Invoke",
    );
    assert_site(
        &call_sites(&resolver, &explicit),
        "callvirt",
        "ChaDuplicateDispatch.I::Invoke",
    );
    Ok(())
}
