#[cfg(feature = "auto")]
use std::any::Any;
use std::cell::{Cell, RefCell};
use std::panic::PanicHookInfo;
#[cfg(feature = "auto")]
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(feature = "auto")]
pub(crate) const PANIC_CODE: &str = "DR-CLI-0877";

thread_local! {
    static ISOLATED: Cell<bool> = const { Cell::new(false) };
    static LOCATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub(crate) fn inside_isolation() -> bool {
    ISOLATED.with(Cell::get)
}

pub(crate) fn record_location(info: &PanicHookInfo<'_>) {
    let location: Option<String> = info
        .location()
        .map(|at: &std::panic::Location<'_>| format!("{}:{}", at.file(), at.line()));
    LOCATION.with(|slot: &RefCell<Option<String>>| *slot.borrow_mut() = location);
}

#[cfg(feature = "auto")]
fn payload_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text: &&str| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a non-text payload".to_owned())
}

#[cfg(feature = "auto")]
pub(crate) fn isolate<T>(what: &str, work: impl FnOnce() -> T) -> Result<T, String> {
    let previous: bool = ISOLATED.with(|flag: &Cell<bool>| flag.replace(true));
    let outcome: std::thread::Result<T> = catch_unwind(AssertUnwindSafe(work));
    ISOLATED.with(|flag: &Cell<bool>| flag.set(previous));
    outcome.map_err(|payload: Box<dyn Any + Send>| {
        let location: String = LOCATION
            .with(|slot: &RefCell<Option<String>>| slot.borrow_mut().take())
            .unwrap_or_else(|| "an unknown location".to_owned());
        format!(
            "{PANIC_CODE}: {what} panicked at {location}: {}",
            payload_message(payload.as_ref())
        )
    })
}

#[cfg(all(test, feature = "auto"))]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{PANIC_CODE, inside_isolation, isolate};

    #[test]
    fn a_panic_inside_isolation_becomes_a_coded_error_and_the_flag_is_restored() {
        let result: Result<u32, String> = isolate("the probe pass", || -> u32 {
            assert!(inside_isolation());
            panic!("probe failure")
        });
        let message: String = result.expect_err("the probe panics");
        assert!(message.starts_with(PANIC_CODE), "{message}");
        assert!(message.contains("the probe pass panicked"), "{message}");
        assert!(message.contains("probe failure"), "{message}");
        assert!(!inside_isolation());
        assert_eq!(isolate("a quiet pass", || 7), Ok(7));
    }
}
