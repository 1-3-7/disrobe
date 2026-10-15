const RUSTC_RELEASES: &str = include_str!("rustc_releases.tsv");

pub fn stable_releases() -> impl Iterator<Item = (&'static str, &'static str)> {
    RUSTC_RELEASES
        .lines()
        .filter(|line: &&str| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line: &str| line.split_once('\t'))
}

pub fn release_for_commit(commit: &str) -> Option<&'static str> {
    stable_releases()
        .find(|(_, release_commit): &(&str, &str)| *release_commit == commit)
        .map(|(version, _): (&str, &str)| version)
}
