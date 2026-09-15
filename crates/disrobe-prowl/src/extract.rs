use disrobe_core::ioc::{self, IocKind as CoreIocKind};

use crate::filter::host_of;
use crate::model::{HarvestedUrl, Ioc, IocKind, Source};

const MD5_LEN: usize = 32;
const SHA1_LEN: usize = 40;
const SHA256_LEN: usize = 64;

#[must_use]
fn split_subdomain_or_domain(host: &str) -> (IocKind, String) {
    let host: String = host.trim_matches('.').to_ascii_lowercase();
    let labels: usize = host.split('.').filter(|l: &&str| !l.is_empty()).count();
    if labels >= 3 {
        (IocKind::Subdomain, host)
    } else {
        (IocKind::Domain, host)
    }
}

#[must_use]
fn classify_hash(token: &str) -> Option<IocKind> {
    if token.is_empty() || !token.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return None;
    }
    match token.len() {
        MD5_LEN => Some(IocKind::Md5),
        SHA1_LEN => Some(IocKind::Sha1),
        SHA256_LEN => Some(IocKind::Sha256),
        _ => None,
    }
}

fn push_hashes_and_asns(text: &str, source: Source, out: &mut Vec<Ioc>) {
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if let Some(kind) = classify_hash(raw) {
            out.push(Ioc {
                kind,
                value: raw.to_ascii_lowercase(),
                source,
            });
        } else if let Some(asn) = parse_asn(raw) {
            out.push(Ioc {
                kind: IocKind::Asn,
                value: asn,
                source,
            });
        }
    }
}

#[must_use]
fn parse_asn(token: &str) -> Option<String> {
    let upper: String = token.to_ascii_uppercase();
    let digits: &str = upper.strip_prefix("AS")?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    Some(format!("AS{digits}"))
}

fn push_network_iocs(text: &str, source: Source, out: &mut Vec<Ioc>) {
    for indicator in ioc::extract(text.as_bytes()) {
        let mapped: Option<IocKind> = match indicator.kind {
            CoreIocKind::Ipv4 => Some(IocKind::Ipv4),
            CoreIocKind::Ipv6 => Some(IocKind::Ipv6),
            CoreIocKind::Email => Some(IocKind::Email),
            CoreIocKind::Domain => Some(split_subdomain_or_domain(&indicator.value).0),
            _ => None,
        };
        if let Some(kind) = mapped {
            let value: String = if matches!(kind, IocKind::Subdomain | IocKind::Domain) {
                indicator.value.to_ascii_lowercase()
            } else {
                indicator.value
            };
            out.push(Ioc {
                kind,
                value,
                source,
            });
        }
    }
}

#[must_use]
pub fn extract_iocs(urls: &[HarvestedUrl], texts: &[(Source, String)]) -> Vec<Ioc> {
    let mut out: Vec<Ioc> = Vec::new();
    for entry in urls {
        if let Some(host) = host_of(&entry.url) {
            let (kind, value): (IocKind, String) = split_subdomain_or_domain(&host);
            out.push(Ioc {
                kind,
                value,
                source: entry.source,
            });
        }
    }
    for (source, text) in texts {
        push_network_iocs(text, *source, out.as_mut());
        push_hashes_and_asns(text, *source, out.as_mut());
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn url_hosts_become_subdomains_and_domains() {
        let urls: Vec<HarvestedUrl> = vec![
            HarvestedUrl::plain("https://api.example.com/x".to_owned(), Source::Wayback),
            HarvestedUrl::plain("https://example.com/y".to_owned(), Source::Otx),
        ];
        let iocs: Vec<Ioc> = extract_iocs(&urls, &[]);
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Subdomain && i.value == "api.example.com")
        );
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Domain && i.value == "example.com")
        );
    }

    #[test]
    fn hashes_classified_by_length() {
        let md5: String = "d41d8cd98f00b204e9800998ecf8427e".to_owned();
        let sha1: String = "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned();
        let sha256: String =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned();
        let text: String = format!("payload {md5} {sha1} {sha256}");
        let iocs: Vec<Ioc> = extract_iocs(&[], &[(Source::Urlhaus, text)]);
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Md5 && i.value == md5)
        );
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Sha1 && i.value == sha1)
        );
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Sha256 && i.value == sha256)
        );
    }

    #[test]
    fn asn_and_ip_extracted() {
        let text: String = "host 203.0.113.7 announced by AS64500".to_owned();
        let iocs: Vec<Ioc> = extract_iocs(&[], &[(Source::Threatfox, text)]);
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Ipv4 && i.value == "203.0.113.7")
        );
        assert!(
            iocs.iter()
                .any(|i: &Ioc| i.kind == IocKind::Asn && i.value == "AS64500")
        );
    }

    #[test]
    fn asn_rejects_non_numeric() {
        assert!(parse_asn("ASDF").is_none());
        assert!(parse_asn("AS").is_none());
        assert_eq!(parse_asn("as12").as_deref(), Some("AS12"));
    }
}
