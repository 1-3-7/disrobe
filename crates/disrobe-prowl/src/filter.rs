use std::collections::BTreeSet;

use crate::model::{HarvestedUrl, Ioc, IocKind};

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub blacklist_extensions: Vec<String>,
    pub subs: bool,
    pub from: Option<String>,
    pub to: Option<String>,
    pub match_status: Vec<u16>,
    pub exclude_status: Vec<u16>,
    pub match_mime: Vec<String>,
    pub exclude_mime: Vec<String>,
    pub collapse_params: bool,
    pub ioc_kinds: Vec<IocKind>,
}

#[must_use]
fn url_extension(url: &str) -> Option<String> {
    let path: &str = url
        .split_once("://")
        .map_or(url, |(_, rest): (&str, &str)| rest);
    let path: &str = path
        .split(['?', '#'])
        .next()
        .map_or(path, |value: &str| value);
    let last: &str = path.rsplit('/').next().map_or(path, |value: &str| value);
    last.rsplit_once('.')
        .map(|(_, ext): (&str, &str)| ext.to_ascii_lowercase())
        .filter(|ext: &String| !ext.is_empty() && ext.len() <= 12)
}

#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let after: &str = url.split_once("://")?.1;
    let authority: &str = after
        .split(['/', '?', '#'])
        .next()
        .map_or(after, |value: &str| value);
    let host: &str = authority
        .rsplit('@')
        .next()
        .map_or(authority, |value: &str| value);
    let host: &str = host.split(':').next().map_or(host, |value: &str| value);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[must_use]
fn host_matches(host: &str, target: &str, subs: bool) -> bool {
    let target: String = target.trim().trim_end_matches('/').to_ascii_lowercase();
    if host == target {
        return true;
    }
    subs && host.ends_with(&format!(".{target}"))
}

#[must_use]
fn param_collapsed_key(url: &str) -> String {
    let (base, query): (&str, &str) = url
        .split_once('?')
        .map_or((url, ""), |value: (&str, &str)| value);
    if query.is_empty() {
        return base.to_owned();
    }
    let mut names: Vec<&str> = query
        .split('&')
        .map(|kv: &str| kv.split_once('=').map_or(kv, |(k, _): (&str, &str)| k))
        .collect();
    names.sort_unstable();
    names.dedup();
    format!("{base}?{}", names.join("&"))
}

#[must_use]
fn target_scopes_url(host: &str, targets: &[String], subs: bool) -> bool {
    targets.is_empty() || targets.iter().any(|t: &String| host_matches(host, t, subs))
}

/// Applies the URL filters, scopes each URL to one of `targets`, and de-duplicates.
#[must_use]
pub fn apply_url_filters(
    urls: Vec<HarvestedUrl>,
    targets: &[String],
    filter: &Filter,
) -> Vec<HarvestedUrl> {
    let blacklist: BTreeSet<String> = filter
        .blacklist_extensions
        .iter()
        .map(|e: &String| e.trim_start_matches('.').to_ascii_lowercase())
        .collect();
    let match_mime: Vec<String> = filter
        .match_mime
        .iter()
        .map(|m: &String| m.to_ascii_lowercase())
        .collect();
    let exclude_mime: Vec<String> = filter
        .exclude_mime
        .iter()
        .map(|m: &String| m.to_ascii_lowercase())
        .collect();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<HarvestedUrl> = Vec::with_capacity(urls.len());

    for entry in urls {
        let Some(host): Option<String> = host_of(&entry.url) else {
            continue;
        };
        if !target_scopes_url(&host, targets, filter.subs) {
            continue;
        }
        if let Some(ext) = url_extension(&entry.url)
            && blacklist.contains(&ext)
        {
            continue;
        }
        if !filter.match_status.is_empty()
            && !entry
                .status
                .is_some_and(|s: u16| filter.match_status.contains(&s))
        {
            continue;
        }
        if let Some(s) = entry.status
            && filter.exclude_status.contains(&s)
        {
            continue;
        }
        if let Some(mime) = entry.mime.as_deref().map(str::to_ascii_lowercase) {
            if !match_mime.is_empty()
                && !match_mime
                    .iter()
                    .any(|m: &String| mime.contains(m.as_str()))
            {
                continue;
            }
            if exclude_mime
                .iter()
                .any(|m: &String| mime.contains(m.as_str()))
            {
                continue;
            }
        } else if !match_mime.is_empty() {
            continue;
        }

        let key: String = if filter.collapse_params {
            param_collapsed_key(&entry.url)
        } else {
            entry.url.clone()
        };
        if seen.insert(key) {
            out.push(entry);
        }
    }

    out.sort_by(|a: &HarvestedUrl, b: &HarvestedUrl| a.url.cmp(&b.url));
    out
}

/// De-duplicates indicators (by `kind`+`value`), keeps the first-seen source, applies any requested `ioc_kinds` allow-list, and sorts for stable output.
#[must_use]
pub fn apply_ioc_filters(iocs: Vec<Ioc>, filter: &Filter) -> Vec<Ioc> {
    let allow: BTreeSet<IocKind> = filter.ioc_kinds.iter().copied().collect();
    let mut seen: BTreeSet<(IocKind, String)> = BTreeSet::new();
    let mut out: Vec<Ioc> = Vec::with_capacity(iocs.len());
    for ioc in iocs {
        if !allow.is_empty() && !allow.contains(&ioc.kind) {
            continue;
        }
        if seen.insert((ioc.kind, ioc.value.clone())) {
            out.push(ioc);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::Source;

    fn mk(url: &str) -> HarvestedUrl {
        HarvestedUrl::plain(url.to_owned(), Source::Wayback)
    }

    fn mk_status(url: &str, status: u16) -> HarvestedUrl {
        HarvestedUrl {
            status: Some(status),
            ..mk(url)
        }
    }

    fn urls_only(urls: &[HarvestedUrl]) -> Vec<&str> {
        urls.iter().map(|u: &HarvestedUrl| u.url.as_str()).collect()
    }

    #[test]
    fn blacklist_extension_and_dedup() {
        let urls: Vec<HarvestedUrl> = vec![
            mk("https://example.com/a.png"),
            mk("https://example.com/a.png"),
            mk("https://example.com/app.js"),
        ];
        let f: Filter = Filter {
            blacklist_extensions: vec!["png".to_owned()],
            ..Filter::default()
        };
        let out: Vec<HarvestedUrl> = apply_url_filters(urls, &["example.com".to_owned()], &f);
        assert_eq!(urls_only(&out), vec!["https://example.com/app.js"]);
    }

    #[test]
    fn subs_scopes_host() {
        let urls: Vec<HarvestedUrl> = vec![
            mk("https://example.com/a"),
            mk("https://api.example.com/b"),
            mk("https://evil.com/c"),
        ];
        let targets: Vec<String> = vec!["example.com".to_owned()];
        let no_subs: Vec<HarvestedUrl> =
            apply_url_filters(urls.clone(), &targets, &Filter::default());
        assert_eq!(urls_only(&no_subs), vec!["https://example.com/a"]);
        let with_subs: Vec<HarvestedUrl> = apply_url_filters(
            urls,
            &targets,
            &Filter {
                subs: true,
                ..Filter::default()
            },
        );
        assert_eq!(
            urls_only(&with_subs),
            vec!["https://api.example.com/b", "https://example.com/a"]
        );
    }

    #[test]
    fn empty_targets_skip_host_scoping() {
        let urls: Vec<HarvestedUrl> = vec![mk("https://evil.example/payload.bin")];
        let out: Vec<HarvestedUrl> = apply_url_filters(urls, &[], &Filter::default());
        assert_eq!(urls_only(&out), vec!["https://evil.example/payload.bin"]);
    }

    #[test]
    fn status_match_and_filter() {
        let urls: Vec<HarvestedUrl> = vec![
            mk_status("https://example.com/ok", 200),
            mk_status("https://example.com/gone", 404),
        ];
        let only200: Vec<HarvestedUrl> = apply_url_filters(
            urls.clone(),
            &["example.com".to_owned()],
            &Filter {
                match_status: vec![200],
                ..Filter::default()
            },
        );
        assert_eq!(urls_only(&only200), vec!["https://example.com/ok"]);
        let no404: Vec<HarvestedUrl> = apply_url_filters(
            urls,
            &["example.com".to_owned()],
            &Filter {
                exclude_status: vec![404],
                ..Filter::default()
            },
        );
        assert_eq!(urls_only(&no404), vec!["https://example.com/ok"]);
    }

    #[test]
    fn collapse_params_dedups_endpoint() {
        let urls: Vec<HarvestedUrl> = vec![
            mk("https://example.com/p?id=1"),
            mk("https://example.com/p?id=2"),
            mk("https://example.com/p?id=3&x=9"),
        ];
        let collapsed: Vec<HarvestedUrl> = apply_url_filters(
            urls,
            &["example.com".to_owned()],
            &Filter {
                collapse_params: true,
                ..Filter::default()
            },
        );
        assert_eq!(collapsed.len(), 2);
    }

    #[test]
    fn ioc_dedup_and_kind_filter() {
        let iocs: Vec<Ioc> = vec![
            Ioc {
                kind: IocKind::Ipv4,
                value: "1.2.3.4".to_owned(),
                source: Source::Threatfox,
            },
            Ioc {
                kind: IocKind::Ipv4,
                value: "1.2.3.4".to_owned(),
                source: Source::Urlhaus,
            },
            Ioc {
                kind: IocKind::Domain,
                value: "evil.test".to_owned(),
                source: Source::Crtsh,
            },
        ];
        let all: Vec<Ioc> = apply_ioc_filters(iocs.clone(), &Filter::default());
        assert_eq!(all.len(), 2);
        let only_ip: Vec<Ioc> = apply_ioc_filters(
            iocs,
            &Filter {
                ioc_kinds: vec![IocKind::Ipv4],
                ..Filter::default()
            },
        );
        assert_eq!(only_ip.len(), 1);
        assert_eq!(only_ip[0].value, "1.2.3.4");
    }
}
