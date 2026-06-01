#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::complexity::{
    Cfg, FunctionComplexity, cyclomatic_complexity, from_decision_points,
};

struct ConnectedFixture {
    name: &'static str,
    cfg: Cfg,
    decision_points: u32,
    expected: u32,
}

const CONNECTED: &[ConnectedFixture] = &[
    ConnectedFixture {
        name: "straight_line",
        cfg: Cfg::from_counts(1, 0),
        decision_points: 0,
        expected: 1,
    },
    ConnectedFixture {
        name: "single_if",
        cfg: Cfg::from_counts(4, 4),
        decision_points: 1,
        expected: 2,
    },
    ConnectedFixture {
        name: "if_else",
        cfg: Cfg::from_counts(4, 4),
        decision_points: 1,
        expected: 2,
    },
    ConnectedFixture {
        name: "single_loop",
        cfg: Cfg::from_counts(3, 3),
        decision_points: 1,
        expected: 2,
    },
    ConnectedFixture {
        name: "nested_if_in_loop",
        cfg: Cfg::from_counts(5, 6),
        decision_points: 2,
        expected: 3,
    },
    ConnectedFixture {
        name: "three_sequential_ifs",
        cfg: Cfg::from_counts(7, 9),
        decision_points: 3,
        expected: 4,
    },
    ConnectedFixture {
        name: "switch_4_arms",
        cfg: Cfg::from_counts(6, 8),
        decision_points: 3,
        expected: 4,
    },
];

#[test]
fn connected_fixtures_hit_exact_complexity_via_both_paths() {
    for f in CONNECTED {
        assert_eq!(
            cyclomatic_complexity(&f.cfg),
            f.expected,
            "graph path mismatch for {}",
            f.name
        );
        assert_eq!(
            from_decision_points(f.decision_points),
            f.expected,
            "decision-point path mismatch for {}",
            f.name
        );
        assert_eq!(
            cyclomatic_complexity(&f.cfg),
            from_decision_points(f.decision_points),
            "dual-path disagreement for {}",
            f.name
        );
    }
}

#[test]
fn n_sequential_ifs_equal_n_plus_one() {
    for k in 1u32..=3 {
        let nodes: u32 = 2 * k + 1;
        let edges: u32 = 3 * k;
        let cfg: Cfg = Cfg::from_counts(nodes, edges);
        assert_eq!(cyclomatic_complexity(&cfg), k + 1);
        assert_eq!(from_decision_points(k), k + 1);
        assert_eq!(cyclomatic_complexity(&cfg), from_decision_points(k));
    }
}

#[test]
fn k_arm_switch_convention_is_pinned() {
    let switch_arms: u32 = 4;
    assert_eq!(from_decision_points(switch_arms - 1), switch_arms);
    let cfg: Cfg = Cfg::from_counts(6, 8);
    assert_eq!(cyclomatic_complexity(&cfg), switch_arms);
}

#[test]
fn two_components_use_full_mccabe() {
    let cfg: Cfg = Cfg::new(6, 4, 2);
    assert_eq!(cyclomatic_complexity(&cfg), 2);
}

#[test]
fn function_complexity_round_trips_through_serde() {
    let cfg: Cfg = Cfg::from_counts(5, 6);
    let fc: FunctionComplexity = FunctionComplexity::from_cfg("nested_if_in_loop", &cfg);
    assert_eq!(fc.complexity, 3);

    let json: String = serde_json::to_string(&fc).expect("serialize");
    let back: FunctionComplexity = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, fc);

    let dp_fc: FunctionComplexity = FunctionComplexity::from_decision_points("ast_walk", 2);
    assert_eq!(dp_fc.complexity, 3);
    let dp_json: String = serde_json::to_string(&dp_fc).expect("serialize dp");
    let dp_back: FunctionComplexity = serde_json::from_str(&dp_json).expect("deserialize dp");
    assert_eq!(dp_back, dp_fc);
}
