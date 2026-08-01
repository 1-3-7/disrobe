use std::collections::BTreeSet;

use disrobe_pass_native::{
    Bitness, DesyncReport, NoreturnInferenceOutcome, NoreturnInferenceTermination,
    resolve_desync_with_noreturn_status,
};

#[test]
fn public_noreturn_status_api_round_trips_through_json() {
    let seeds: BTreeSet<u64> = BTreeSet::new();
    let outcome: NoreturnInferenceOutcome<DesyncReport> =
        resolve_desync_with_noreturn_status(Bitness::Bits64, 0, &[0xC3], &[0], &seeds)
            .expect("resolve a one-byte return");
    assert_eq!(
        outcome.termination(),
        NoreturnInferenceTermination::Complete
    );
    let value: serde_json::Value = serde_json::to_value(&outcome).expect("serialize status");
    assert_eq!(value["termination"], "complete");
    let decoded: NoreturnInferenceOutcome<DesyncReport> =
        serde_json::from_value(value).expect("deserialize status");
    assert_eq!(
        decoded.termination(),
        NoreturnInferenceTermination::Complete
    );
    assert_eq!(decoded.value().recovered.len(), 1);
    assert_eq!(decoded.value().recovered[0].address, 0);
}
