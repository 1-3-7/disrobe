use std::collections::BTreeMap;
use std::str::FromStr;

pub mod keys {
    pub const ANTI_RECOVERED_TECHNIQUES: &str = "anti.recovered_techniques";
}

#[must_use]
pub fn get<'m>(metadata: &'m BTreeMap<String, String>, key: &str) -> Option<&'m str> {
    metadata.get(key).map(String::as_str)
}

pub fn get_parsed<T: FromStr>(
    metadata: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<T>, T::Err> {
    metadata
        .get(key)
        .map(|value: &String| value.parse::<T>())
        .transpose()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> BTreeMap<String, String> {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert(
            keys::ANTI_RECOVERED_TECHNIQUES.to_string(),
            "cff,opaque".to_string(),
        );
        m.insert("count".to_string(), "42".to_string());
        m.insert("bad".to_string(), "not-a-number".to_string());
        m
    }

    #[test]
    fn get_returns_str_for_present_key_and_none_for_absent() {
        let m: BTreeMap<String, String> = sample();
        assert_eq!(get(&m, keys::ANTI_RECOVERED_TECHNIQUES), Some("cff,opaque"));
        assert_eq!(get(&m, "missing"), None);
    }

    #[test]
    fn get_parsed_distinguishes_absent_present_and_unparseable() {
        let m: BTreeMap<String, String> = sample();
        let present: Option<u32> = get_parsed::<u32>(&m, "count").expect("count parses");
        assert_eq!(present, Some(42));
        let absent: Option<u32> = get_parsed::<u32>(&m, "missing").expect("absent is Ok(None)");
        assert_eq!(absent, None);
        assert!(get_parsed::<u32>(&m, "bad").is_err());
    }
}
