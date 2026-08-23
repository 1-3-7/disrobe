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
    let jobs: &Value = ci.get("jobs").expect("ci.yml jobs");
    let full_route: &str = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.ref_type == 'tag'";
    assert!(
        !full_route.contains("push"),
        "the full route must never admit a push to main; that is what keeps the main-push \
         legs fast and is the reason these jobs are gated at all"
    );
    for job in [
        "test",
        "beam-otp28-long-atu8",
        "determinism-cross-platform",
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
    for job in [
        "check", "fmt", "clippy", "graphs", "deny", "typos", "hygiene", "msrv", "slim",
    ] {
        assert!(
            jobs.get(job)
                .and_then(|value: &Value| value.get("if"))
                .is_none(),
            "ci.yml {job} must remain on the fast main route"
        );
    }
    let concurrency: &Value = ci.get("concurrency").expect("ci.yml concurrency");
    let group: &str = concurrency
        .get("group")
        .and_then(Value::as_str)
        .expect("ci.yml concurrency group");
    assert_eq!(
        group,
        "${{ github.workflow }}-${{ github.event_name == 'schedule' && 'schedule' || github.ref }}",
        "ci.yml must keep scheduled full coverage out of the main-push cancellation group"
    );
    assert_eq!(
        concurrency
            .get("cancel-in-progress")
            .and_then(Value::as_bool),
        Some(true),
        "ci.yml must cancel obsolete runs within each event route"
    );
    let test_matrix: &Vec<Value> = jobs
        .get("test")
        .and_then(|value: &Value| value.get("strategy"))
        .and_then(|value: &Value| value.get("matrix"))
        .and_then(|value: &Value| value.get("include"))
        .and_then(Value::as_sequence)
        .expect("ci.yml test matrix entries");
    let test_routes: Vec<(&str, &str)> = test_matrix
        .iter()
        .map(|entry: &Value| {
            (
                entry
                    .get("os")
                    .and_then(Value::as_str)
                    .expect("test matrix os"),
                entry
                    .get("shard")
                    .and_then(Value::as_str)
                    .expect("test matrix shard"),
            )
        })
        .collect();
    assert_eq!(
        test_routes,
        vec![
            ("ubuntu-latest", "all"),
            ("macos-latest", "all"),
            ("windows-latest", "one"),
            ("windows-latest", "two"),
            ("windows-latest", "three"),
        ]
    );
    let test_steps: &Vec<Value> = jobs
        .get("test")
        .and_then(|value: &Value| value.get("steps"))
        .and_then(Value::as_sequence)
        .expect("ci.yml test steps");
    let windows_one: BTreeSet<String> = command_packages(
        test_step_command(test_steps, "Windows workspace shard one"),
        "-p",
    );
    let windows_two: BTreeSet<String> = command_packages(
        test_step_command(test_steps, "Windows workspace shard two"),
        "-p",
    );
    assert!(!windows_one.is_empty());
    assert!(!windows_two.is_empty());
    assert!(windows_one.is_disjoint(&windows_two));
    let dedicated_steps: [(&str, &str, &str); 3] = [
        (
            "elixir recompile differential, printing the graded export count",
            "disrobe-pass-beam",
            "matrix.shard == 'all' || matrix.shard == 'two'",
        ),
        (
            "R serialization differential, printing the graded object count",
            "disrobe-pass-scriptlang",
            "matrix.shard == 'all' || matrix.shard == 'three'",
        ),
        (
            "XLM formula differential against an independent deobfuscator, printing the graded cell count",
            "disrobe-pass-shell",
            "matrix.shard == 'all' || matrix.shard == 'two'",
        ),
    ];
    let dedicated_packages: BTreeSet<String> = dedicated_steps
        .iter()
        .map(|(_, package, _): &(&str, &str, &str)| (*package).to_owned())
        .collect();
    assert!(windows_one.is_disjoint(&dedicated_packages));
    assert!(windows_two.is_disjoint(&dedicated_packages));
    for (name, package, condition) in dedicated_steps {
        let command: &str = test_step_command(test_steps, name);
        assert_eq!(
            command_packages(command, "-p"),
            BTreeSet::from([package.to_owned()])
        );
        assert!(command.contains("--all-features"));
        assert!(command.contains("--no-fail-fast"));
        assert!(command.ends_with("-- --nocapture"));
        assert_eq!(
            test_step(test_steps, name)
                .get("if")
                .and_then(Value::as_str),
            Some(condition),
            "{name} must run once per operating system"
        );
    }
    let unix_command: &str = test_step_command(test_steps, "Full workspace suite on Unix");
    assert!(unix_command.contains("cargo test --workspace --all-features --no-fail-fast"));
    assert_eq!(
        command_packages(unix_command, "--exclude"),
        dedicated_packages
    );
    let selected: BTreeSet<String> = windows_one
        .union(&windows_two)
        .cloned()
        .chain(dedicated_packages.iter().cloned())
        .collect();
    let complement_command: &str = test_step_command(test_steps, "Windows workspace shard three");
    assert!(complement_command.contains("cargo test --workspace --all-features --no-fail-fast"));
    assert_eq!(
        command_packages(complement_command, "--exclude"),
        selected,
        "the complement shard must exclude every package owned by an explicit or dedicated command"
    );
    let singleton_condition: &str = "matrix.shard == 'all' || matrix.shard == 'one'";
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
    assert_eq!(
        test_step(test_steps, "Full workspace suite on Unix")
            .get("timeout-minutes")
            .and_then(Value::as_u64),
        Some(100)
    );
    for name in [
        "Windows workspace shard one",
        "Windows workspace shard two",
        "Windows workspace shard three",
    ] {
        let command: &str = test_step_command(test_steps, name);
        assert!(command.contains("--all-features"));
        assert!(command.contains("--no-fail-fast"));
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
        Some("8.3")
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
