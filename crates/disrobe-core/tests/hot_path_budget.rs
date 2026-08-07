use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use disrobe_core::codec::alphabets::base62_decode;
use disrobe_core::codec::web_escape::html_entity_decode;
use disrobe_core::recon::ioc;
use disrobe_core::recon::malware_config::{
    ConfigDecode, MalwareConfigWall, WorkBudget, asyncrat_lineage_decode, darkcomet_config_decode,
    quasar_config_decode, xworm_config_decode,
};
use disrobe_core::recon::secret_scan::scan_bytes;
use disrobe_core::recon::{ReconConfig, ReconFinding, scan_bytes as recon_scan_bytes};

const MEGABYTE: usize = 1 << 20;

const SWEEP_CEILING: Duration = Duration::from_mins(1);

type Measured<T> = (T, Duration);

fn run_bounded<T: Send + 'static>(
    ceiling: Duration,
    body: impl FnOnce() -> T + Send + 'static,
) -> Option<Measured<T>> {
    let (tx, rx): (SyncSender<Measured<T>>, Receiver<Measured<T>>) = sync_channel(1);
    let worker: JoinHandle<()> = std::thread::spawn(move || {
        let start: Instant = Instant::now();
        let value: T = body();
        let elapsed: Duration = start.elapsed();
        drop(tx.send((value, elapsed)));
    });
    match rx.recv_timeout(ceiling) {
        Ok(measured) => {
            drop(worker.join());
            Some(measured)
        }
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
    }
}

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
        darkcomet_config_decode(&input, 0, &mut WorkBudget::default())
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
        quasar_config_decode(&input, 0, &mut WorkBudget::default())
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

const COBALT_XOR_KEY: u8 = 0x2e;

fn cobalt_tlv_record(index: u16, field_type: u16, payload: [u8; 2]) -> [u8; 8] {
    let mut record: [u8; 8] = [0u8; 8];
    record[..2].copy_from_slice(&index.to_be_bytes());
    record[2..4].copy_from_slice(&field_type.to_be_bytes());
    record[4..6].copy_from_slice(&2u16.to_be_bytes());
    record[6..].copy_from_slice(&payload);
    record
}

fn cobalt_probe_soup(target_len: usize) -> Vec<u8> {
    let mut plain: Vec<u8> = Vec::with_capacity(target_len + 24);
    while plain.len() < target_len {
        plain.extend_from_slice(&cobalt_tlv_record(1, 1, [0x41, 0x42]));
        plain.extend_from_slice(&cobalt_tlv_record(2, 1, [0x43, 0x44]));
        plain.extend_from_slice(&cobalt_tlv_record(3, 0, [0x45, 0x46]));
    }
    plain
        .iter()
        .map(|&b: &u8| b ^ COBALT_XOR_KEY)
        .collect::<Vec<u8>>()
}

fn njrat_field_soup(filler_len: usize, fields: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(filler_len + fields * 16);
    while out.len() < filler_len {
        out.extend_from_slice(b"0123456789abcdef0123456789abcdef\n");
    }
    for index in 0..fields {
        if index > 0 {
            out.extend_from_slice(b"|'|'|");
        }
        out.extend_from_slice(b"YWJjZA==");
    }
    out.push(b'\n');
    out
}

fn recon_findings_of(label: &str, input: Vec<u8>) -> Option<Measured<Vec<ReconFinding>>> {
    let measured: Option<Measured<Vec<ReconFinding>>> = run_bounded(SWEEP_CEILING, move || {
        let config: ReconConfig = ReconConfig::default();
        let (findings, _valid): (Vec<ReconFinding>, bool) = recon_scan_bytes(&input, None, &config);
        findings
    });
    assert!(
        measured.is_some(),
        "{label} did not finish inside {SWEEP_CEILING:?}"
    );
    measured
}

fn truncation_rule_ids(findings: &[ReconFinding]) -> Vec<&str> {
    findings
        .iter()
        .filter(|f: &&ReconFinding| f.rule_id.ends_with("-TRUNCATED"))
        .map(|f: &ReconFinding| f.rule_id.as_str())
        .collect()
}

const COBALT_SWEEP_FITS_BYTES: usize = 4 * MEGABYTE;
const COBALT_SWEEP_EXCEEDS_BYTES: usize = 12 * MEGABYTE;

#[test]
fn cobalt_strike_probe_sweep_stays_inside_its_bound() {
    let input: Vec<u8> = cobalt_probe_soup(COBALT_SWEEP_FITS_BYTES);
    let Some((findings, elapsed)): Option<Measured<Vec<ReconFinding>>> =
        recon_findings_of("cobalt probe sweep 4MiB", input)
    else {
        return;
    };
    println!(
        "cobalt probe sweep 4MiB: {} finding(s) in {elapsed:?}",
        findings.len()
    );
    assert!(
        elapsed < SWEEP_CEILING,
        "the sliding cobalt probe must not allocate a decoded copy per offset, took {elapsed:?}"
    );
    assert!(
        truncation_rule_ids(&findings).is_empty(),
        "an ordinary binary of this size fits the declared bound, so nothing may report truncation"
    );
}

#[test]
fn cobalt_strike_sweep_reports_the_bound_that_stopped_it() {
    let input: Vec<u8> = cobalt_probe_soup(COBALT_SWEEP_EXCEEDS_BYTES);
    let Some((findings, elapsed)): Option<Measured<Vec<ReconFinding>>> =
        recon_findings_of("cobalt probe sweep 12MiB", input)
    else {
        return;
    };
    let stops: Vec<&str> = truncation_rule_ids(&findings);
    println!("cobalt probe sweep 12MiB: {stops:?} in {elapsed:?}");
    assert!(
        stops.contains(&"DR-RECON-MALCFG-COBALT-STRIKE-TRUNCATED"),
        "a sweep past the declared bound must say so instead of reading as a clean miss, got {stops:?}"
    );
}

const NJRAT_FILLER_BYTES: usize = MEGABYTE;
const NJRAT_FIELDS: usize = 5000;
const NJRAT_MEASURE_ROUNDS: usize = 3;
const NJRAT_RESCAN_RATIO_NUMERATOR: u32 = 3;
const NJRAT_RESCAN_RATIO_DENOMINATOR: u32 = 2;

#[test]
fn njrat_field_offsets_do_not_rescan_the_file_per_field() {
    let mut baseline: Duration = Duration::MAX;
    let mut loaded: Duration = Duration::MAX;
    let mut njrat_fields: usize = 0;
    for _ in 0..NJRAT_MEASURE_ROUNDS {
        let plain: Vec<u8> = njrat_field_soup(NJRAT_FILLER_BYTES, 1);
        let Some((_plain_findings, plain_elapsed)): Option<Measured<Vec<ReconFinding>>> =
            recon_findings_of("njrat baseline", plain)
        else {
            return;
        };
        baseline = baseline.min(plain_elapsed);

        let dense: Vec<u8> = njrat_field_soup(NJRAT_FILLER_BYTES, NJRAT_FIELDS);
        let Some((findings, dense_elapsed)): Option<Measured<Vec<ReconFinding>>> =
            recon_findings_of("njrat field sweep", dense)
        else {
            return;
        };
        loaded = loaded.min(dense_elapsed);
        njrat_fields = findings
            .iter()
            .filter(|f: &&ReconFinding| f.rule_id.starts_with("DR-RECON-MALCFG-NJRAT-FIELD"))
            .count();
    }
    let ceiling: Duration =
        baseline * NJRAT_RESCAN_RATIO_NUMERATOR / NJRAT_RESCAN_RATIO_DENOMINATOR;
    println!(
        "njrat 1MiB baseline {baseline:?}, {NJRAT_FIELDS} fields {loaded:?}, ceiling {ceiling:?}, {njrat_fields} njrat field(s)"
    );
    assert!(
        njrat_fields >= 4096,
        "the crafted line must reach the field cap, got {njrat_fields}"
    );
    assert!(
        loaded < ceiling,
        "resolving a field position must not rescan the file per field, {loaded:?} against a {baseline:?} baseline"
    );
}

#[test]
fn quasar_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(&QUASAR_SALT, 160 * 1024);
    let start: Instant = Instant::now();
    let decode: ConfigDecode = quasar_config_decode(&input, 0, &mut WorkBudget::default());
    let elapsed: Duration = start.elapsed();
    assert_budgeted("quasar max passwords x max blobs", &decode, elapsed);
}

#[test]
fn xworm_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(XWORM_MARKER, 160 * 1024);
    let start: Instant = Instant::now();
    let decode: ConfigDecode = xworm_config_decode(&input, 0, &mut WorkBudget::default());
    let elapsed: Duration = start.elapsed();
    assert_budgeted("xworm max keys x max blobs", &decode, elapsed);
}

#[test]
fn asyncrat_lineage_worst_case_is_bounded_and_reports_truncation() {
    let input: Vec<u8> = amplification_carrier(&ASYNCRAT_SALT, 160 * 1024);
    let start: Instant = Instant::now();
    let decoded: Result<ConfigDecode, MalwareConfigWall> =
        asyncrat_lineage_decode(&input, 0, &mut WorkBudget::default());
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

#[test]
fn the_declared_bound_is_what_stops_the_sweep_not_a_fixed_flag() {
    let input: Vec<u8> = amplification_carrier(&QUASAR_SALT, 160 * 1024);
    let mut declared: WorkBudget = WorkBudget::default();
    let stopped: ConfigDecode = quasar_config_decode(&input, 0, &mut declared);
    assert!(
        stopped.truncated,
        "the declared bound must stop this carrier"
    );
    assert_eq!(
        declared.remaining(),
        0,
        "a stopped sweep must have spent the whole bound"
    );

    let mut raised: WorkBudget = WorkBudget::new(u64::MAX);
    let carried: ConfigDecode = quasar_config_decode(&input[..2048], 0, &mut raised);
    assert!(
        !carried.truncated,
        "raised past what this carrier demands, the same decoder must report no truncation"
    );
    let spent: u64 = u64::MAX - raised.remaining();
    println!("quasar 2KiB carrier spent {spent} work unit(s) of an unbounded budget");
    assert!(
        spent > 0,
        "the counter must charge real work, not report a fixed value"
    );

    let mut starved: WorkBudget = WorkBudget::new(spent - 1);
    let refused: ConfigDecode = quasar_config_decode(&input[..2048], 0, &mut starved);
    assert!(
        refused.truncated,
        "one unit below what the carrier demands, the same input must be refused"
    );
}
