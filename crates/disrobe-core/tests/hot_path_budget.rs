use std::time::{Duration, Instant};

use disrobe_core::codec::alphabets::base62_decode;
use disrobe_core::codec::web_escape::html_entity_decode;
use disrobe_core::recon::ioc;
use disrobe_core::recon::malware_config::{
    ConfigDecode, MalwareConfigWall, asyncrat_lineage_decode, darkcomet_config_decode,
    quasar_config_decode, xworm_config_decode,
};
use disrobe_core::recon::secret_scan::scan_bytes;

const MEGABYTE: usize = 1 << 20;

const QUASAR_SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
const ASYNCRAT_SALT: [u8; 16] = [
    0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B, 0xB2, 0x19, 0x02, 0x24, 0x30, 0xA5, 0x78, 0x43,
];
const XWORM_MARKER: &[u8] = b"XWorm";
const KEYED_DECODE_CEILING: Duration = Duration::from_secs(5);

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

fn amplification_carrier(marker: &[u8], target_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(target_len + 16 * 1024);
    out.extend_from_slice(marker);
    out.push(0x00);
    for i in 0..512u32 {
        out.extend_from_slice(format!("pw{i:06}candidate").as_bytes());
        out.push(0x00);
    }
    let mut state: u32 = 0x1234_5678;
    while out.len() < target_len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

fn assert_budgeted(label: &str, decode: &ConfigDecode, elapsed: Duration) {
    println!("{label}: truncated={} in {elapsed:?}", decode.truncated);
    assert!(
        decode.truncated,
        "{label} must report that the declared work bound stopped the sweep, not a clean empty answer"
    );
    assert!(
        decode.fields.is_empty(),
        "{label} carrier holds no real config, so no field may be reported"
    );
    assert!(
        elapsed < KEYED_DECODE_CEILING,
        "{label} must stay inside the declared work bound, took {elapsed:?}"
    );
}

#[test]
fn quasar_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(&QUASAR_SALT, 160 * 1024);
    let start: Instant = Instant::now();
    let decode: ConfigDecode = quasar_config_decode(&input, 0);
    let elapsed: Duration = start.elapsed();
    assert_budgeted("quasar max passwords x max blobs", &decode, elapsed);
}

#[test]
fn xworm_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(XWORM_MARKER, 160 * 1024);
    let start: Instant = Instant::now();
    let decode: ConfigDecode = xworm_config_decode(&input, 0);
    let elapsed: Duration = start.elapsed();
    assert_budgeted("xworm max keys x max blobs", &decode, elapsed);
}

#[test]
fn asyncrat_lineage_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(&ASYNCRAT_SALT, 160 * 1024);
    let start: Instant = Instant::now();
    let decoded: Result<ConfigDecode, MalwareConfigWall> = asyncrat_lineage_decode(&input, 0);
    let elapsed: Duration = start.elapsed();
    println!("asyncrat lineage worst case: {elapsed:?}");
    assert!(
        elapsed < KEYED_DECODE_CEILING,
        "asyncrat lineage must stay inside the declared work bound, took {elapsed:?}"
    );
    match decoded {
        Ok(decode) => assert_budgeted(
            "asyncrat lineage max passwords x max blobs",
            &decode,
            elapsed,
        ),
        Err(wall) => assert!(
            wall.static_key_absent,
            "a carrier with no recoverable key must report the reason it stopped"
        ),
    }
}
