use std::sync::OnceLock;

const JDK25_PUBLIC_INTERFACES: &str = include_str!("../data/jdk25-public-interfaces.txt");

fn table() -> &'static [&'static str] {
    static TABLE: OnceLock<Vec<&'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut names: Vec<&'static str> = JDK25_PUBLIC_INTERFACES
            .lines()
            .map(str::trim)
            .filter(|line: &&str| !line.is_empty())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    })
}

#[must_use]
pub(crate) fn is_jdk_public_interface(internal_name: &str) -> bool {
    table().binary_search(&internal_name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_interfaces_and_classes_classify() {
        assert!(is_jdk_public_interface("java/lang/foreign/Arena"));
        assert!(is_jdk_public_interface("java/util/List"));
        assert!(is_jdk_public_interface("java/util/function/Function"));
        assert!(!is_jdk_public_interface("java/lang/String"));
        assert!(!is_jdk_public_interface("java/util/stream/Collectors"));
        assert!(!is_jdk_public_interface(""));
        assert!(table().len() > 1_000);
    }
}
