use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cfg {
    pub nodes: u32,
    pub edges: u32,
    pub connected_components: u32,
}

impl Cfg {
    #[inline]
    #[must_use]
    pub const fn from_counts(nodes: u32, edges: u32) -> Self {
        Self {
            nodes,
            edges,
            connected_components: 1,
        }
    }

    #[inline]
    #[must_use]
    pub const fn new(nodes: u32, edges: u32, components: u32) -> Self {
        Self {
            nodes,
            edges,
            connected_components: if components == 0 { 1 } else { components },
        }
    }
}

impl Default for Cfg {
    #[inline]
    fn default() -> Self {
        Self {
            nodes: 1,
            edges: 0,
            connected_components: 1,
        }
    }
}

#[inline]
#[must_use]
pub fn cyclomatic_complexity(cfg: &Cfg) -> u32 {
    let two_p: u32 = cfg.connected_components.saturating_mul(2);
    cfg.edges
        .saturating_add(two_p)
        .saturating_sub(cfg.nodes)
        .max(1)
}

#[inline]
#[must_use]
pub const fn from_decision_points(decision_points: u32) -> u32 {
    decision_points.saturating_add(1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionComplexity {
    pub function: String,
    pub nodes: u32,
    pub edges: u32,
    pub components: u32,
    pub complexity: u32,
}

impl FunctionComplexity {
    #[must_use]
    pub fn from_cfg(function: impl Into<String>, cfg: &Cfg) -> Self {
        Self {
            function: function.into(),
            nodes: cfg.nodes,
            edges: cfg.edges,
            components: cfg.connected_components,
            complexity: cyclomatic_complexity(cfg),
        }
    }

    #[must_use]
    pub fn from_decision_points(function: impl Into<String>, decision_points: u32) -> Self {
        Self {
            function: function.into(),
            nodes: 0,
            edges: 0,
            components: 1,
            complexity: from_decision_points(decision_points),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cfg, FunctionComplexity, cyclomatic_complexity, from_decision_points};

    #[test]
    fn from_counts_sets_single_component() {
        let cfg: Cfg = Cfg::from_counts(4, 4);
        assert_eq!(cfg.connected_components, 1);
        assert_eq!(cfg.nodes, 4);
        assert_eq!(cfg.edges, 4);
    }

    #[test]
    fn new_clamps_zero_components_to_one() {
        let cfg: Cfg = Cfg::new(3, 3, 0);
        assert_eq!(cfg.connected_components, 1);
    }

    #[test]
    fn default_is_single_node_no_edges() {
        let cfg: Cfg = Cfg::default();
        assert_eq!(cfg, Cfg::from_counts(1, 0));
        assert_eq!(cyclomatic_complexity(&cfg), 1);
    }

    #[test]
    fn raw_mccabe_math_two_components() {
        let cfg: Cfg = Cfg::new(6, 4, 2);
        assert_eq!(cyclomatic_complexity(&cfg), 2);
    }

    #[test]
    fn decision_point_dual() {
        assert_eq!(from_decision_points(0), 1);
        assert_eq!(from_decision_points(3), 4);
    }

    #[test]
    fn clamp_floors_at_one_on_overcounted_nodes() {
        let cfg: Cfg = Cfg::from_counts(10, 0);
        assert_eq!(cyclomatic_complexity(&cfg), 1);
    }

    #[test]
    fn saturation_does_not_panic_on_extremes() {
        let cfg: Cfg = Cfg::new(0, u32::MAX, u32::MAX);
        let _m: u32 = cyclomatic_complexity(&cfg);
    }

    #[test]
    fn function_complexity_from_cfg_carries_counts() {
        let cfg: Cfg = Cfg::from_counts(5, 6);
        let fc: FunctionComplexity = FunctionComplexity::from_cfg("loop_with_if", &cfg);
        assert_eq!(fc.function, "loop_with_if");
        assert_eq!(fc.nodes, 5);
        assert_eq!(fc.edges, 6);
        assert_eq!(fc.components, 1);
        assert_eq!(fc.complexity, 3);
    }

    #[test]
    fn function_complexity_from_decision_points_zeroes_graph() {
        let fc: FunctionComplexity = FunctionComplexity::from_decision_points("ast_fn", 2);
        assert_eq!(fc.nodes, 0);
        assert_eq!(fc.edges, 0);
        assert_eq!(fc.components, 1);
        assert_eq!(fc.complexity, 3);
    }
}
