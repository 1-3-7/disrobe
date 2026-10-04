pub(crate) fn init_tracing(verbose: u8, quiet: bool) {
    use tracing_subscriber::EnvFilter;

    let level: &'static str = if quiet {
        "error"
    } else {
        match verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let filter: EnvFilter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
}

pub(crate) fn source_date() -> miette::Result<Option<disrobe_core::time::SourceDate>> {
    disrobe_core::time::source_date().map_err(invalid_source_date)
}

pub(crate) fn now_secs() -> miette::Result<u64> {
    disrobe_core::time::now_secs().map_err(invalid_source_date)
}

fn invalid_source_date(error: disrobe_core::time::SourceDateError) -> miette::Report {
    miette::miette!("DR-CLI-0318: {error}")
}

pub(crate) fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[inline]
#[cfg(any(feature = "auto", feature = "py"))]
pub(crate) fn hex_bytes(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(32);
    for b in bytes {
        let upper: usize = usize::from(b >> 4);
        let lower: usize = usize::from(b & 0x0f);
        s.push(char::from(HEX[upper]));
        s.push(char::from(HEX[lower]));
    }
    s
}
