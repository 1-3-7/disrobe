#[cfg(feature = "prowl")]
mod harvest;

#[cfg(feature = "prowl")]
pub(crate) use harvest::{ProwlArgs, run, run_keyring_argv};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProwlFormat {
    #[default]
    Text,
    Json,
}
