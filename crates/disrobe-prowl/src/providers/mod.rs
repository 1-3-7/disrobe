pub mod threat_intel;
pub mod url_archive;

use crate::model::Source;
use crate::provider::Provider;

#[must_use]
pub fn build(source: Source) -> Box<dyn Provider> {
    build_with_key(source, None)
}

#[must_use]
pub fn build_with_key(source: Source, api_key: Option<String>) -> Box<dyn Provider> {
    match source {
        Source::Wayback => Box::new(url_archive::Wayback),
        Source::CommonCrawl => Box::new(url_archive::CommonCrawl::default()),
        Source::Otx => Box::new(url_archive::Otx::with_key(api_key)),
        Source::Urlscan => Box::new(url_archive::Urlscan::with_key(api_key)),
        Source::Virustotal => Box::new(url_archive::Virustotal::with_key(api_key)),
        Source::Crtsh => Box::new(threat_intel::Crtsh),
        Source::Urlhaus => Box::new(threat_intel::Urlhaus::with_key(api_key)),
        Source::Threatfox => Box::new(threat_intel::Threatfox::with_key(api_key)),
    }
}
