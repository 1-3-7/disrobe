#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_yaml_ng::Value;

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root
}

fn workflow(name: &str) -> Value {
    let path: PathBuf = workspace_root()
        .join(".github")
        .join("workflows")
        .join(name);
    yaml_file(path)
}

fn yaml_file(path: PathBuf) -> Value {
    let source: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    serde_yaml_ng::from_str(&source)
        .unwrap_or_else(|error: serde_yaml_ng::Error| panic!("parse {}: {error}", path.display()))
}

fn rust_toolchain_action() -> String {
    let path: PathBuf = workspace_root().join("rust-toolchain.toml");
    let source: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let config: toml::Value = toml::from_str(&source)
        .unwrap_or_else(|error: toml::de::Error| panic!("parse {}: {error}", path.display()));
    let channel: &str = config
        .get("toolchain")
        .and_then(|value: &toml::Value| value.get("channel"))
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml toolchain channel");
    format!("dtolnay/rust-toolchain@{channel}")
}

fn command_packages(command: &str, selector: &str) -> BTreeSet<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    words
        .windows(2)
        .filter(|pair: &&[&str]| pair[0] == selector)
        .map(|pair: &[&str]| pair[1].to_owned())
        .collect()
}

fn integration_targets(package: &str) -> BTreeSet<String> {
    let tests: PathBuf = workspace_root().join("crates").join(package).join("tests");
    let mut targets: BTreeSet<String> = std::fs::read_dir(&tests)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", tests.display()))
        .map(|entry: Result<std::fs::DirEntry, std::io::Error>| {
            entry.unwrap_or_else(|error: std::io::Error| {
                panic!("read {} entry: {error}", tests.display())
            })
        })
        .filter_map(|entry: std::fs::DirEntry| {
            let path: PathBuf = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
                path.file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .map(str::to_owned)
            } else if path.join("main.rs").is_file() {
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .map(str::to_owned)
            } else {
                None
            }
        })
        .collect();
    let manifest_path: PathBuf = workspace_root()
        .join("crates")
        .join(package)
        .join("Cargo.toml");
    let manifest_source: String =
        std::fs::read_to_string(&manifest_path).unwrap_or_else(|error: std::io::Error| {
            panic!("read {}: {error}", manifest_path.display())
        });
    let manifest: toml::Value =
        toml::from_str(&manifest_source).unwrap_or_else(|error: toml::de::Error| {
            panic!("parse {}: {error}", manifest_path.display())
        });
    for test in manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let name: &str = test
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("explicit integration test must have a name");
        assert!(
            targets.insert(name.to_owned()),
            "explicit {package} test {name} duplicates an automatically discovered target"
        );
    }
    targets
}

fn test_step<'a>(steps: &'a [Value], name: &str) -> &'a Value {
    steps
        .iter()
        .find(|step: &&Value| step.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("ci.yml test step {name}"))
}

fn test_step_command<'a>(steps: &'a [Value], name: &str) -> &'a str {
    test_step(steps, name)
        .get("run")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("ci.yml test step {name} command"))
}

#[test]
fn javascript_profiles_keep_the_complete_integration_inventory() {
    let action: Value =
        yaml_file(workspace_root().join(".github/actions/javascript-tests/action.yml"));
    assert_eq!(action["runs"]["using"].as_str(), Some("composite"));
    let steps: &Vec<Value> = action["runs"]["steps"].as_sequence().expect("action steps");
    assert_eq!(steps.len(), 1);
    let step: &Value = &steps[0];
    assert_eq!(step["shell"].as_str(), Some("pwsh"));
    let release: &str = step["env"]["RELEASE_TEST_TARGETS"]
        .as_str()
        .expect("high-preset corpus recovery targets");
    let release_names: Vec<&str> = release.split_whitespace().collect();
    let release_targets: BTreeSet<&str> = release_names.iter().copied().collect();
    assert_eq!(release_names.len(), release_targets.len());
    assert_eq!(
        release_targets,
        BTreeSet::from([
            "obfuscator_io_e2e",
            "obfuscator_io_differential_oracle",
            "reeval_corpus_oracle",
        ])
    );
    let mut debug_targets: BTreeSet<String> = integration_targets("disrobe-pass-js-deob");
    for target in release_targets {
        assert!(
            debug_targets.remove(target),
            "release recovery oracle {target} must exist in the integration inventory"
        );
    }
    for retained in ["sandbox_overflow_resilience", "source_map_limits"] {
        assert!(
            debug_targets.contains(retained),
            "debug coverage lost {retained}"
        );
    }
    let command: &str = step["run"].as_str().expect("JavaScript test command");
    for forbidden in [
        "--skip",
        "--exclude",
        "--ignored",
        "CARGO_PROFILE_",
        "RUSTFLAGS",
    ] {
        assert!(
            !command.contains(forbidden),
            "JavaScript coverage override: {forbidden}"
        );
    }
}

#[test]
fn ci_routes_full_coverage_to_scheduled_and_tag_runs() {
    let ci: Value = workflow("ci.yml");
    let on: &Value = ci
        .get("on")
        .or_else(|| ci.get(Value::Bool(true)))
        .expect("ci.yml on block");
    let push: &Value = on.get("push").expect("ci.yml push trigger");
    let branches: &Vec<Value> = push
        .get("branches")
        .and_then(Value::as_sequence)
        .expect("ci.yml push branches");
    assert_eq!(branches, &vec![Value::String("main".to_owned())]);
    let tags: &Vec<Value> = push
        .get("tags")
        .and_then(Value::as_sequence)
        .expect("ci.yml push tags");
    assert_eq!(
        tags,
        &vec![Value::String("v[0-9]+.[0-9]+.[0-9]*".to_owned())]
    );
    let schedule: &Vec<Value> = on
        .get("schedule")
        .and_then(Value::as_sequence)
        .expect("ci.yml schedule");
    assert_eq!(
        schedule
            .first()
            .and_then(|value: &Value| value.get("cron"))
            .and_then(Value::as_str),
        Some("0 6 * * 1")
    );
    assert_eq!(schedule.len(), 1);
    let dispatch: &Value = on
        .get("workflow_dispatch")
        .expect("ci.yml workflow_dispatch trigger");
    let scope: &Value = dispatch
        .get("inputs")
        .and_then(|value: &Value| value.get("scope"))
        .expect("ci.yml workflow_dispatch scope input");
    assert_eq!(
        scope.get("type").and_then(Value::as_str),
        Some("choice"),
        "manual CI scope must stay selectable"
    );
    assert_eq!(
        scope.get("default").and_then(Value::as_str),
        Some("full"),
        "a manual CI run without a selection must retain full coverage"
    );
    assert_eq!(
        scope.get("options").and_then(Value::as_sequence),
        Some(&vec![
            Value::String("full".to_owned()),
            Value::String("clippy".to_owned()),
            Value::String("tests".to_owned()),
        ]),
        "manual CI must expose only the full, clippy, and tests scopes"
    );
    for (name, options) in [
        (
            "os",
            vec!["all", "ubuntu-latest", "macos-latest", "windows-latest"],
        ),
        (
            "shard",
            vec!["all", "one", "two", "three", "nativelang", "javascript"],
        ),
    ] {
        let selector: &Value = dispatch
            .get("inputs")
            .and_then(|value: &Value| value.get(name))
            .unwrap_or_else(|| panic!("ci.yml workflow_dispatch {name} input"));
        assert_eq!(
            selector.get("type").and_then(Value::as_str),
            Some("choice"),
            "manual CI {name} selector must stay selectable"
        );
        assert_eq!(
            selector.get("default").and_then(Value::as_str),
            Some("all"),
            "manual CI {name} selector must retain the complete matrix by default"
        );
        assert_eq!(
            selector.get("options").and_then(Value::as_sequence),
            Some(
                &options
                    .into_iter()
                    .map(|value: &str| Value::String(value.to_owned()))
                    .collect::<Vec<Value>>(),
            ),
            "manual CI {name} selector options"
        );
    }
    let jobs: &Value = ci.get("jobs").expect("ci.yml jobs");
    let default_route: &str = "github.event_name != 'workflow_dispatch' || (github.event.inputs.scope != 'clippy' && github.event.inputs.scope != 'tests')";
    let full_route: &str = "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.ref_type == 'tag') && (github.event_name != 'workflow_dispatch' || (github.event.inputs.scope != 'clippy' && github.event.inputs.scope != 'tests'))";
    let test_route: &str = "((github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.ref_type == 'tag') && (github.event_name != 'workflow_dispatch' || (github.event.inputs.scope != 'clippy' && github.event.inputs.scope != 'tests'))) || (github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && github.event.inputs.shard != 'javascript')";
    let determinism_route: &str = "((github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.ref_type == 'tag') && (github.event_name != 'workflow_dispatch' || (github.event.inputs.scope != 'clippy' && github.event.inputs.scope != 'tests'))) || (github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && github.event.inputs.os == 'all' && github.event.inputs.shard == 'all')";
    assert!(
        !full_route.contains("push"),
        "the full route must never admit a push to main; that is what keeps the main-push \
         legs fast and is the reason these jobs are gated at all"
    );
    for job in [
        "beam-otp28-long-atu8",
        "py-recompile-gate",
        "execution-differentials",
    ] {
        let configured: &str = jobs
            .get(job)
            .and_then(|value: &Value| value.get("if"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("ci.yml {job} full-route condition"));
        assert_eq!(configured, full_route, "ci.yml {job} full-route condition");
    }
    assert_eq!(
        jobs.get("test")
            .and_then(|value: &Value| value.get("if"))
            .and_then(Value::as_str),
        Some(test_route),
        "ci.yml test must retain the full matrix while permitting an explicit scoped matrix selection"
    );
    assert_eq!(
        jobs.get("determinism-cross-platform")
            .and_then(|value: &Value| value.get("if"))
            .and_then(Value::as_str),
        Some(determinism_route),
        "ci.yml determinism proof must not run for a partial manual test matrix"
    );
    let javascript: &Value = jobs.get("javascript").expect("ci.yml javascript job");
    assert_eq!(
        javascript.get("if").and_then(Value::as_str),
        Some(
            "github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && github.event.inputs.shard == 'javascript'"
        )
    );
    assert_eq!(javascript["env"]["RUST_TEST_THREADS"].as_str(), Some("1"));
    assert!(
        javascript["env"]
            .get("DISROBE_PROBE_PHASE_TIMING")
            .is_none(),
        "temporary JavaScript phase timing must not remain in CI"
    );
    let javascript_steps: &Vec<Value> = javascript["steps"]
        .as_sequence()
        .expect("ci.yml javascript steps");
    assert_eq!(
        test_step(
            javascript_steps,
            "JavaScript recovery and execution differentials"
        )
        .get("uses")
        .and_then(Value::as_str),
        Some("./.github/actions/javascript-tests")
    );
    let fixtures: &str = test_step_command(javascript_steps, "Require JavaScript fixtures");
    for job in ["javascript", "test"] {
        let steps: &Vec<Value> = jobs[job]["steps"].as_sequence().expect("test job steps");
        assert!(
            steps.iter().any(|step: &Value| {
                step.get("uses").and_then(Value::as_str)
                    == Some("./.github/actions/javascript-oracles")
            }),
            "{job} must provision the pinned JavaScript reference toolchains"
        );
    }
    for prerequisite in [
        "test -d corpus/js/javascript-obfuscator",
        "test -d corpus/js/jsconfuser",
        "test -d corpus/src/javascript/obfuscator-io-samples/controls",
        "test -s corpus/src/javascript/obfuscator-io-high.js",
        "for preset in low medium high",
        "test -s \"corpus/src/javascript/obfuscator-io-samples/presets/$preset.js\"",
    ] {
        assert!(fixtures.contains(prerequisite), "missing {prerequisite}");
    }
    for job in [
        "check",
        "fmt",
        "process-containment",
        "graphs",
        "py-band-gate",
        "deny",
        "typos",
        "hygiene",
        "msrv",
        "slim",
    ] {
        assert_eq!(
            jobs.get(job)
                .unwrap_or_else(|| panic!("ci.yml {job} required job"))
                .get("if")
                .and_then(Value::as_str),
            Some(default_route),
            "ci.yml {job} must run for pushes and full manual runs, and skip only manual clippy runs"
        );
    }
    assert_eq!(
        jobs.get("clippy")
            .expect("ci.yml clippy required job")
            .get("if")
            .and_then(Value::as_str),
        Some("github.event_name != 'workflow_dispatch' || github.event.inputs.scope != 'tests'"),
        "ci.yml clippy must run for full and clippy scopes, and skip the manual tests scope"
    );
    let py_band: &Value = jobs.get("py-band-gate").expect("ci.yml py-band-gate job");
    let py_band_environment: &Value = py_band.get("env").expect("ci.yml py-band-gate environment");
    assert_eq!(
        py_band_environment
            .get("CARGO_PROFILE_RELEASE_LTO")
            .and_then(Value::as_str),
        Some("false"),
        "the push-critical Python band gate must not pay for release LTO"
    );
    assert_eq!(
        py_band_environment
            .get("CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
            .and_then(Value::as_str),
        Some("16"),
        "the push-critical Python band gate must compile release code in parallel"
    );
    let py_band_steps: &Vec<Value> = py_band
        .get("steps")
        .and_then(Value::as_sequence)
        .expect("ci.yml py-band-gate steps");
    assert_eq!(
        test_step_command(py_band_steps, "build the disrobe cli the harness drives"),
        "cargo build --release -p disrobe-cli --bin disrobe",
        "the Python band gate must still exercise an optimized release CLI"
    );
    for (name, requirement, target) in [
        (
            "per-code-object recompile-equivalence floor (>= 95.76% on the 3.10 band)",
            "DISROBE_REQUIRE_PY_310",
            "arbitrary_recompile_gate_310",
        ),
        (
            "per-code-object recompile-equivalence floor (>= 95.77% on the 3.12 band)",
            "DISROBE_REQUIRE_PY_312",
            "arbitrary_recompile_gate_312",
        ),
        (
            "per-code-object recompile-equivalence floor (>= 96.06% on the 3.13 band)",
            "DISROBE_REQUIRE_PY_313",
            "arbitrary_recompile_gate_313",
        ),
    ] {
        let step: &Value = test_step(py_band_steps, name);
        assert_eq!(
            step.get("env")
                .and_then(|value: &Value| value.get(requirement))
                .and_then(Value::as_str),
            Some("1"),
            "{name} must fail instead of skipping its required interpreter band"
        );
        let expected_command: String =
            format!("cargo test --release -p disrobe-pass-py-decompile --test {target} -- --nocapture");
        assert_eq!(
            step.get("run").and_then(Value::as_str),
            Some(expected_command.as_str()),
            "{name} must retain its exact independent recovery grader and reuse the release artifacts the CLI build produced"
        );
    }
    let concurrency: &Value = ci.get("concurrency").expect("ci.yml concurrency");
    let group: &str = concurrency
        .get("group")
        .and_then(Value::as_str)
        .expect("ci.yml concurrency group");
    assert_eq!(
        group,
        "${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'schedule' && 'schedule' || github.ref }}${{ github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'clippy' && '-clippy' || github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && format('-tests-{0}-{1}', github.event.inputs.os, github.event.inputs.shard) || '' }}",
        "ci.yml must keep clippy-only and scoped-test dispatches out of matching full-run cancellation groups"
    );
    assert_eq!(
        concurrency
            .get("cancel-in-progress")
            .and_then(Value::as_bool),
        Some(true),
        "ci.yml must cancel obsolete runs within each event route"
    );
    let test_matrix: &Value = jobs
        .get("test")
        .and_then(|value: &Value| value.get("strategy"))
        .and_then(|value: &Value| value.get("matrix"))
        .expect("ci.yml test matrix");
    assert_eq!(
        test_matrix.get("os").and_then(Value::as_str),
        Some(
            "${{ fromJSON(github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && github.event.inputs.os != 'all' && format('[\"{0}\"]', github.event.inputs.os) || '[\"ubuntu-latest\",\"macos-latest\",\"windows-latest\"]') }}"
        ),
        "test scope must select one requested OS while full/default runs retain all operating systems"
    );
    assert_eq!(
        test_matrix.get("shard").and_then(Value::as_str),
        Some(
            "${{ fromJSON(github.event_name == 'workflow_dispatch' && github.event.inputs.scope == 'tests' && github.event.inputs.shard != 'all' && (github.event.inputs.shard == 'one' && '[\"one\",\"nativelang-bodies\",\"nativelang-remainder\"]' || github.event.inputs.shard == 'nativelang' && '[\"nativelang-bodies\",\"nativelang-remainder\"]' || format('[\"{0}\"]', github.event.inputs.shard)) || '[\"one\",\"two\",\"three\",\"nativelang-bodies\",\"nativelang-remainder\"]') }}"
        ),
        "manual shard one must retain native-language coverage; native-language selection and full/default runs retain both native groups"
    );
    let test_steps: &Vec<Value> = jobs
        .get("test")
        .and_then(|value: &Value| value.get("steps"))
        .and_then(Value::as_sequence)
        .expect("ci.yml test steps");
    let windows_one: BTreeSet<String> =
        command_packages(test_step_command(test_steps, "workspace shard one"), "-p");
    let windows_two: BTreeSet<String> =
        command_packages(test_step_command(test_steps, "workspace shard two"), "-p");
    assert!(!windows_one.is_empty());
    assert!(!windows_two.is_empty());
    assert!(windows_one.is_disjoint(&windows_two));
    let native_body: &str =
        test_step_command(test_steps, "native language body recovery differentials");
    let native_remainder: &str = test_step_command(
        test_steps,
        "native language unit and remaining integration coverage",
    );
    let native_docs: &str = test_step_command(test_steps, "native language documentation coverage");
    let native_package: BTreeSet<String> = BTreeSet::from(["disrobe-pass-nativelang".to_owned()]);
    assert!(windows_one.is_disjoint(&native_package));
    assert!(windows_two.is_disjoint(&native_package));
    for (name, command, group) in [
        (
            "native language body recovery differentials",
            native_body,
            "nativelang-bodies",
        ),
        (
            "native language unit and remaining integration coverage",
            native_remainder,
            "nativelang-remainder",
        ),
        (
            "native language documentation coverage",
            native_docs,
            "nativelang-remainder",
        ),
    ] {
        assert_eq!(command_packages(command, "-p"), native_package);
        assert!(command.contains("--all-features"));
        assert!(command.contains("--no-fail-fast"));
        assert_eq!(
            test_step(test_steps, name)
                .get("if")
                .and_then(Value::as_str),
            Some(format!("matrix.shard == '{group}'").as_str()),
        );
    }
    let body_targets: BTreeSet<String> = command_packages(native_body, "--test");
    let remainder_targets: BTreeSet<String> = command_packages(native_remainder, "--test");
    assert_eq!(
        body_targets,
        BTreeSet::from([
            "body_equivalence".to_owned(),
            "body_recovery_oracle".to_owned()
        ])
    );
    assert!(body_targets.is_disjoint(&remainder_targets));
    assert!(native_remainder.contains("--lib"));
    assert!(!native_remainder.contains("--doc"));
    assert!(native_docs.contains("--doc"));
    assert!(!native_docs.contains("--lib"));
    let selected_native_targets: BTreeSet<String> =
        body_targets.union(&remainder_targets).cloned().collect();
    assert_eq!(
        selected_native_targets,
        integration_targets("disrobe-pass-nativelang"),
        "every native-language integration target must be assigned exactly once; a new target must update this routing contract"
    );
    let dedicated_steps: [(&str, &str, &str); 4] = [
        (
            "elixir recompile differential, printing the graded export count",
            "disrobe-pass-beam",
            "matrix.shard == 'two'",
        ),
        (
            "R serialization differential, printing the graded object count",
            "disrobe-pass-scriptlang",
            "matrix.shard == 'three'",
        ),
        (
            "XLM formula differential against an independent deobfuscator, printing the graded cell count",
            "disrobe-pass-shell",
            "matrix.shard == 'two'",
        ),
        (
            "JavaScript differentials within the Boa CPU budget",
            "disrobe-pass-js-deob",
            "matrix.shard == 'three'",
        ),
    ];
    let dedicated_packages: BTreeSet<String> = dedicated_steps
        .iter()
        .map(|(_, package, _): &(&str, &str, &str)| (*package).to_owned())
        .collect();
    assert!(windows_one.is_disjoint(&dedicated_packages));
    assert!(windows_two.is_disjoint(&dedicated_packages));
    for (name, package, condition) in dedicated_steps {
        if package == "disrobe-pass-js-deob" {
            assert_eq!(
                test_step(test_steps, name)
                    .get("uses")
                    .and_then(Value::as_str),
                Some("./.github/actions/javascript-tests")
            );
        } else {
            let command: &str = test_step_command(test_steps, name);
            assert_eq!(
                command_packages(command, "-p"),
                BTreeSet::from([package.to_owned()])
            );
            assert!(command.contains("--all-features"));
            assert!(command.contains("--no-fail-fast"));
            assert!(command.ends_with("-- --nocapture"));
        }
        assert_eq!(
            test_step(test_steps, name)
                .get("if")
                .and_then(Value::as_str),
            Some(condition),
            "{name} must run once per operating system"
        );
    }
    assert_eq!(
        test_step(
            test_steps,
            "JavaScript differentials within the Boa CPU budget"
        )
        .get("env")
        .and_then(|env: &Value| env.get("RUST_TEST_THREADS"))
        .and_then(Value::as_str),
        Some("1"),
        "Boa reference evaluations must not contend with the recovery probe deadline"
    );
    let selected: BTreeSet<String> = windows_one
        .union(&windows_two)
        .cloned()
        .chain(native_package.iter().cloned())
        .chain(dedicated_packages.iter().cloned())
        .collect();
    let complement_command: &str = test_step_command(test_steps, "workspace shard three");
    assert!(complement_command.contains("cargo test --workspace --all-features --no-fail-fast"));
    assert_eq!(
        command_packages(complement_command, "--exclude"),
        selected,
        "the complement shard must exclude every package owned by an explicit or dedicated command"
    );
    let singleton_condition: &str = "matrix.shard == 'one'";
    assert_eq!(
        test_step(test_steps, "build the CLI used by workspace caller tests")
            .get("if")
            .and_then(Value::as_str),
        Some("matrix.shard == 'one' || matrix.shard == 'two'")
    );
    for (name, shard) in [
        (
            "batch worker-pool determinism (--jobs 1 vs --jobs 4, same fixtures, one leg only)",
            "one",
        ),
        (
            "aarch64 decompiler recompile-execution differential (one leg only)",
            "two",
        ),
        (
            "aarch64 rust recompile-execution differential (one leg only)",
            "two",
        ),
        (
            "aarch64 c against rust rendering cross-check (one leg only)",
            "two",
        ),
        (
            "aarch64 floating-point helper semantics on directed vectors (one leg only)",
            "two",
        ),
        (
            "aarch64 dense-switch CLI differential (one explicitly provisioned leg)",
            "one",
        ),
    ] {
        assert_eq!(
            test_step(test_steps, name)
                .get("if")
                .and_then(Value::as_str),
            Some(format!("matrix.os == 'ubuntu-latest' && matrix.shard == '{shard}'").as_str()),
            "{name} must run exactly once"
        );
    }
    let determinism_step: &str = "stage this OS leg's cross-platform determinism hash file";
    assert_eq!(
        test_step(test_steps, determinism_step)
            .get("if")
            .and_then(Value::as_str),
        Some(singleton_condition),
        "{determinism_step} must run once per operating system"
    );
    let artifact_upload: &Value = test_steps
        .iter()
        .find(|step: &&Value| {
            step.get("uses").and_then(Value::as_str) == Some("actions/upload-artifact@v7")
                && step
                    .get("with")
                    .and_then(|value: &Value| value.get("name"))
                    .and_then(Value::as_str)
                    == Some("determinism-hashes-${{ matrix.os }}")
        })
        .expect("determinism artifact upload");
    assert_eq!(
        artifact_upload.get("if").and_then(Value::as_str),
        Some(singleton_condition)
    );
    assert_eq!(
        jobs.get("test")
            .and_then(|value: &Value| value.get("timeout-minutes"))
            .and_then(Value::as_u64),
        Some(180)
    );
    for (name, shard) in [
        ("workspace shard one", "one"),
        ("workspace shard two", "two"),
        ("workspace shard three", "three"),
        (
            "native language body recovery differentials",
            "nativelang-bodies",
        ),
        (
            "native language unit and remaining integration coverage",
            "nativelang-remainder",
        ),
        (
            "native language documentation coverage",
            "nativelang-remainder",
        ),
    ] {
        let command: &str = test_step_command(test_steps, name);
        assert!(command.contains("--all-features"));
        assert!(command.contains("--no-fail-fast"));
        assert_eq!(
            test_step(test_steps, name)
                .get("if")
                .and_then(Value::as_str),
            Some(format!("matrix.shard == '{shard}'").as_str())
        );
        assert_eq!(
            test_step(test_steps, name)
                .get("env")
                .and_then(|value: &Value| value.get("DISROBE_TYPEREC_CC"))
                .and_then(Value::as_str),
            Some("${{ matrix.os != 'ubuntu-latest' && 'optional' || '' }}"),
            "Linux must retain its required type-recovery compiler oracle"
        );
        assert_eq!(
            test_step(test_steps, name)
                .get("timeout-minutes")
                .and_then(Value::as_u64),
            Some(160),
            "{name} must leave time for setup and teardown inside the job cap"
        );
    }
    let java_setup_index: usize = test_steps
        .iter()
        .position(|step: &Value| {
            step.get("uses").and_then(Value::as_str) == Some("actions/setup-java@v4")
        })
        .expect("ci.yml Java setup step");
    let jvm_requirement_index: usize = test_steps
        .iter()
        .position(|step: &Value| {
            step.get("name").and_then(Value::as_str)
                == Some("require the JVM conversion-frame verifier")
        })
        .expect("ci.yml JVM requirement step");
    assert!(
        java_setup_index < jvm_requirement_index,
        "ci.yml must provision Java before requiring the JVM conversion-frame gate"
    );
    assert!(
        test_steps[jvm_requirement_index]
            .get("run")
            .and_then(Value::as_str)
            .is_some_and(|run: &str| run.contains("DISROBE_REQUIRE_JVM=1")),
        "ci.yml must fail the JVM conversion-frame gate instead of skipping when Java is absent"
    );
    let differential_steps: &Vec<Value> = jobs
        .get("execution-differentials")
        .and_then(|value: &Value| value.get("steps"))
        .and_then(Value::as_sequence)
        .expect("ci.yml execution differential steps");
    assert_eq!(
        jobs.get("execution-differentials")
            .and_then(|value: &Value| value.get("runs-on"))
            .and_then(Value::as_str),
        Some("ubuntu-latest")
    );
    let php_setup_index: usize = differential_steps
        .iter()
        .position(|step: &Value| {
            step.get("uses").and_then(Value::as_str) == Some("shivammathur/setup-php@v2")
        })
        .expect("ci.yml PHP setup step");
    let php_setup: &Value = &differential_steps[php_setup_index];
    assert_eq!(
        php_setup
            .get("with")
            .and_then(|value: &Value| value.get("php-version"))
            .and_then(Value::as_str),
        Some("8.4")
    );
    assert_eq!(
        php_setup
            .get("with")
            .and_then(|value: &Value| value.get("extensions"))
            .and_then(Value::as_str),
        Some("opcache")
    );
    let php_oparray_index: usize = differential_steps
        .iter()
        .position(|step: &Value| {
            step.get("name").and_then(Value::as_str) == Some("php op_array behavioral differential")
        })
        .expect("ci.yml php op_array behavioral differential step");
    assert!(
        php_setup_index < php_oparray_index,
        "ci.yml must provision PHP before the op_array differential"
    );
    let opcache_locator_index: usize = differential_steps
        .iter()
        .position(|step: &Value| {
            step.get("name").and_then(Value::as_str)
                == Some("locate the opcache zend_extension the op_array emitter loads")
        })
        .expect("ci.yml opcache locator step");
    assert!(
        php_setup_index < opcache_locator_index && opcache_locator_index < php_oparray_index,
        "ci.yml must locate opcache after PHP setup and before the op_array differential"
    );
    assert!(
        differential_steps[opcache_locator_index]
            .get("run")
            .and_then(Value::as_str)
            .is_some_and(|run: &str| run.contains("DZOA_OPCACHE_DLL=${dll}")),
        "ci.yml opcache locator must export DZOA_OPCACHE_DLL"
    );
    let php_oparray: &Value = &differential_steps[php_oparray_index];
    let php_environment: &Value = php_oparray
        .get("env")
        .expect("ci.yml php op_array behavioral differential environment");
    assert_eq!(
        php_environment
            .get("DISROBE_REQUIRE_PHP")
            .and_then(Value::as_str),
        Some("1")
    );
    assert_eq!(
        php_environment
            .get("DISROBE_REQUIRE_PHP_OPCACHE")
            .and_then(Value::as_str),
        Some("1")
    );
    assert_eq!(
        php_oparray.get("run").and_then(Value::as_str),
        Some("cargo test -p disrobe-pass-php --test oparray_behavioral -- --nocapture")
    );
    let release: Value = workflow("release.yml");
    let release_on: &Value = release
        .get("on")
        .or_else(|| release.get(Value::Bool(true)))
        .expect("release.yml on block");
    let release_tags: &Vec<Value> = release_on
        .get("push")
        .and_then(|value: &Value| value.get("tags"))
        .and_then(Value::as_sequence)
        .expect("release.yml tag trigger");
    assert_eq!(
        tags, release_tags,
        "CI and release must use the same tag filter"
    );
    let release_jobs: &Value = release.get("jobs").expect("release.yml jobs");
    assert!(release_jobs.get("full-ci").is_none());
    for job in ["build", "sbom"] {
        assert!(
            release_jobs
                .get(job)
                .and_then(|value: &Value| value.get("needs"))
                .is_none(),
            "release.yml {job} must stay independent from CI completion"
        );
    }
    let needs: &Vec<Value> = release_jobs
        .get("release")
        .and_then(|value: &Value| value.get("needs"))
        .and_then(Value::as_sequence)
        .expect("release.yml release needs");
    assert_eq!(
        needs,
        &vec![
            Value::String("build".to_owned()),
            Value::String("sbom".to_owned())
        ]
    );
    let build_steps: &Vec<Value> = release_jobs
        .get("build")
        .and_then(|value: &Value| value.get("steps"))
        .and_then(Value::as_sequence)
        .expect("release.yml build steps");
    let expected_toolchain: String = rust_toolchain_action();
    let toolchain: &Value = build_steps
        .iter()
        .find(|step: &&Value| {
            step.get("uses").and_then(Value::as_str) == Some(expected_toolchain.as_str())
        })
        .unwrap_or_else(|| panic!("release.yml must install {expected_toolchain}"));
    assert_eq!(
        toolchain
            .get("with")
            .and_then(|value: &Value| value.get("targets"))
            .and_then(Value::as_str),
        Some("${{ matrix.target }}"),
        "release.yml must install each build matrix target on Rust 1.96.1"
    );
}
