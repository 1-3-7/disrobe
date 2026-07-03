use async_trait::async_trait;

use crate::filter::Filter;
use crate::model::{HarvestedUrl, Ioc, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub body: Option<String>,
    pub content_type: Option<&'static str>,
    pub headers: Vec<(String, String)>,
    pub page: u32,
}

impl Request {
    #[must_use]
    pub const fn get(url: String) -> Self {
        Self {
            method: Method::Get,
            url,
            body: None,
            content_type: None,
            headers: Vec::new(),
            page: 0,
        }
    }

    #[must_use]
    pub const fn post(url: String, body: String, content_type: &'static str) -> Self {
        Self {
            method: Method::Post,
            url,
            body: Some(body),
            content_type: Some(content_type),
            headers: Vec::new(),
            page: 0,
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    pub const fn at_page(mut self, page: u32) -> Self {
        self.page = page;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Yield {
    pub urls: Vec<HarvestedUrl>,
    pub iocs: Vec<Ioc>,
    pub next_cursor: Option<String>,
}

impl Yield {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.urls.is_empty() && self.iocs.is_empty()
    }
}

/// A single OSINT data source.
///
/// `seed_requests` are issued first; if a source paginates, it returns the next page's
/// request from `next_request` until that yields `None` or the page budget is exhausted.
/// Parsing is pure so it can be graded offline against fixtures.
#[async_trait]
pub trait Provider: Send + Sync + std::fmt::Debug {
    fn source(&self) -> Source;

    fn seed_requests(&self, target: &str, filter: &Filter) -> Vec<Request>;

    fn parse(&self, body: &str) -> Yield;

    fn next_request(
        &self,
        target: &str,
        filter: &Filter,
        previous: &Request,
        last_yield: &Yield,
    ) -> Option<Request> {
        let _ = (target, filter, previous, last_yield);
        None
    }
}
