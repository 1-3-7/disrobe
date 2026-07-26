use std::time::{Duration, Instant};

use disrobe_core::codec::alphabets::base62_decode;
use disrobe_core::codec::web_escape::html_entity_decode;
use disrobe_core::recon::ioc;
use disrobe_core::recon::malware_config::{darkcomet_config_decode, quasar_config_decode};
use disrobe_core::recon::secret_scan::scan_bytes;

const MEGABYTE: usize = 1 << 20;

fn timed<T, F: FnOnce() -> T>(label: &str, body: F) -> Duration {
    let start: Instant = Instant::now();
    let value: T = body();
    let elapsed: Duration = start.elapsed();
    drop(value);
    println!("{label}: {elapsed:?}");
    elapsed
}

fn unterminated_entity_soup(len: usize) -> String {
    "&".repeat(len)
}

fn hex_text(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i: usize| b"abcdef123456789"[i % 15])
        .collect()
}

fn domain_rich_text(target_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(target_len + 128);
    let mut i: usize = 0;
    while out.len() < target_len {
        out.extend_from_slice(
            format!(
                "beacon https://node{i}.example.com/p{i} owner user{i}@corp{i}.example.org peer cdn{i}.example.net\n"
            )
            .as_bytes(),
        );
        i += 1;
    }
    out
}

fn claim_heavy_secret_text(claims: usize, runs: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(claims * 24 + runs * 32);
    for i in 0..claims {
        out.extend_from_slice(format!("ssh-rsa AAAA{i:08}\n").as_bytes());
    }
    for i in 0..runs {
        out.extend_from_slice(format!("q7Wm{i:08}Zx4Rt9Kv2Bn6Lp3Hd\n").as_bytes());
    }
    out
}

fn darkcomet_marker_soup(markers: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(markers * 32);
    for i in 0..markers {
        out.extend_from_slice(b"DarkComet");
        out.extend_from_slice(format!("{i:016}").as_bytes());
    }
    out
}

fn quasar_password_soup(len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut i: usize = 0;
    while out.len() < len {
        out.extend_from_slice(format!("pass{i:08}word ").as_bytes());
        i += 1;
    }
    out
}

#[test]
fn unterminated_entity_scan_stays_linear() {
    let input: String = unterminated_entity_soup(MEGABYTE);
    let elapsed: Duration = timed("html_entity_decode 1MiB unterminated", || {
        html_entity_decode(&input)
    });
    assert!(
        elapsed < Duration::from_secs(5),
        "entity scan must not rescan the tail per ampersand, took {elapsed:?}"
    );
}

#[test]
fn radix_decode_rejects_oversized_input_fast() {
    let input: Vec<u8> = hex_text(MEGABYTE / 4);
    let elapsed: Duration = timed("base62_decode 256KiB hex", || base62_decode(&input));
    assert!(
        elapsed < Duration::from_secs(5),
        "radix decode must reject past its cap instead of running the quadratic loop, took {elapsed:?}"
    );
}

#[test]
fn domain_collection_stays_bounded_on_url_rich_text() {
    let input: Vec<u8> = domain_rich_text(MEGABYTE + MEGABYTE / 2);
    let elapsed: Duration = timed("ioc::extract 1.5MiB url-rich", || ioc::extract(&input));
    assert!(
        elapsed < Duration::from_secs(30),
        "domain collection must use span containment, took {elapsed:?}"
    );
}

#[test]
fn entropy_scan_stays_bounded_against_many_claims() {
    let input: Vec<u8> = claim_heavy_secret_text(40_000, 40_000);
    let elapsed: Duration = timed("scan_bytes 40k claims / 40k runs", || {
        scan_bytes(&input, None)
    });
    assert!(
        elapsed < Duration::from_secs(30),
        "entropy scan must binary-search the claim set, took {elapsed:?}"
    );
}

#[test]
fn darkcomet_candidate_collection_is_capped() {
    let input: Vec<u8> = darkcomet_marker_soup(50_000);
    let elapsed: Duration = timed("darkcomet_config_decode 50k markers", || {
        darkcomet_config_decode(&input, 0)
    });
    assert!(
        elapsed < Duration::from_secs(10),
        "darkcomet candidates must be capped and borrowed, took {elapsed:?}"
    );
}

#[test]
fn quasar_decode_skips_input_without_its_salt() {
    let input: Vec<u8> = quasar_password_soup(MEGABYTE);
    let elapsed: Duration = timed("quasar_config_decode 1MiB no salt", || {
        quasar_config_decode(&input, 0)
    });
    assert!(
        elapsed < Duration::from_secs(2),
        "quasar decode must gate on its salt before deriving keys, took {elapsed:?}"
    );
}
