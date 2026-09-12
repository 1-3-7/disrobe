use std::ffi::{OsStr, OsString};

pub(crate) const REQUIRE_SOLVER_VAR: &str = "DISROBE_REQUIRE_SOLVER";

pub(crate) fn requirement_is_truthy(value: Option<&OsStr>) -> bool {
    let Some(raw): Option<&OsStr> = value else {
        return false;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    !matches!(text.as_str(), "" | "0" | "false" | "no" | "off")
}

pub(crate) fn solver_is_required() -> bool {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_SOLVER_VAR);
    requirement_is_truthy(raw.as_deref())
}

pub(crate) fn enforce_solver_requirement<S>(solver: Option<&S>, required: bool) {
    assert!(
        !required || solver.is_some(),
        "{REQUIRE_SOLVER_VAR} is set, so an external bitvector solver is mandatory for this run, but neither `z3` nor `bitwuzla` was executable on PATH"
    );
}

#[test]
fn absent_solver_is_fatal_when_the_requirement_is_set() {
    let outcome: std::thread::Result<()> =
        std::panic::catch_unwind(|| enforce_solver_requirement(Option::<&()>::None, true));
    let Err(payload): std::thread::Result<()> = outcome else {
        panic!("a missing solver was tolerated while {REQUIRE_SOLVER_VAR} was set");
    };
    let message: &str = payload
        .downcast_ref::<String>()
        .map_or("", |text: &String| text.as_str());
    assert!(
        message.contains(REQUIRE_SOLVER_VAR),
        "the panic must name the variable that caused it, got {message:?}"
    );
}

#[test]
fn absent_solver_still_skips_when_the_requirement_is_unset() {
    enforce_solver_requirement(Option::<&()>::None, false);
}

#[test]
fn a_present_solver_satisfies_the_requirement() {
    enforce_solver_requirement(Some(&()), true);
}

#[test]
fn requirement_truthiness_matches_the_documented_spellings() {
    assert!(!requirement_is_truthy(None));
    for falsey in ["", " ", "0", "false", "FALSE", "no", "off"] {
        assert!(
            !requirement_is_truthy(Some(OsStr::new(falsey))),
            "{falsey:?} must not enable the requirement"
        );
    }
    for truthy in ["1", "true", "yes", "on", "required"] {
        assert!(
            requirement_is_truthy(Some(OsStr::new(truthy))),
            "{truthy:?} must enable the requirement"
        );
    }
}
