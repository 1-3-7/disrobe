use std::fmt::Write;

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
        .compact()
        .init();
}

#[allow(dead_code)]
pub(crate) fn not_yet_impl(area: &str, detail: &str) -> miette::Result<()> {
    Err(miette::miette!(
        "DR-CLI-0000: `{area}` not yet implemented (v0.1 scaffold). detail: {detail}"
    ))
}

#[inline]
pub(crate) fn hex_bytes(bytes: [u8; 16]) -> String {
    let mut s: String = String::with_capacity(32);
    for b in &bytes {
        let _: std::fmt::Result = write!(s, "{b:02x}");
    }
    s
}
