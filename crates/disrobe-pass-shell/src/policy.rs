use serde::{Deserialize, Serialize};

/// Maximum number of nested `eval` / `Execute` layers peeled when static-only.
pub const STATIC_EVAL_DEPTH_CAP: usize = 2;

/// Controls how aggressively nested dynamic-dispatch layers (`eval`, `Execute`,
/// `Invoke-Expression`) are unwound during static recovery.
///
/// disrobe never *runs* a sample; "dynamic" here means following more than
/// [`STATIC_EVAL_DEPTH_CAP`] layers of self-decoding indirection, which on adversarial
/// input can expand combinatorially. The default is [`DynamicPolicy::StaticOnly`]; the
/// caller opts into deeper peeling with `--allow-dynamic`, which maps to
/// [`DynamicPolicy::AllowDynamic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DynamicPolicy {
    StaticOnly,
    AllowDynamic,
}

impl Default for DynamicPolicy {
    #[inline]
    fn default() -> Self {
        Self::StaticOnly
    }
}

impl DynamicPolicy {
    /// Map the `--allow-dynamic` CLI flag onto a policy.
    #[inline]
    #[must_use]
    pub fn from_allow_dynamic_flag(allow_dynamic: bool) -> Self {
        if allow_dynamic {
            Self::AllowDynamic
        } else {
            Self::StaticOnly
        }
    }

    /// The maximum eval/Execute peel depth permitted under this policy.
    ///
    /// Static-only stops at [`STATIC_EVAL_DEPTH_CAP`]; dynamic peeling is bounded only by a
    /// generous hard ceiling so adversarial nesting still terminates.
    #[inline]
    #[must_use]
    pub fn max_eval_depth(self) -> usize {
        match self {
            Self::StaticOnly => STATIC_EVAL_DEPTH_CAP,
            Self::AllowDynamic => 64,
        }
    }

    /// Whether a peel at `current_depth` (1-based) is allowed before exceeding the policy cap.
    #[inline]
    #[must_use]
    pub fn permits_depth(self, current_depth: usize) -> bool {
        current_depth <= self.max_eval_depth()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_static_only() {
        assert_eq!(DynamicPolicy::default(), DynamicPolicy::StaticOnly);
        assert_eq!(
            DynamicPolicy::default().max_eval_depth(),
            STATIC_EVAL_DEPTH_CAP
        );
    }

    #[test]
    fn flag_maps_to_policy() {
        assert_eq!(
            DynamicPolicy::from_allow_dynamic_flag(false),
            DynamicPolicy::StaticOnly
        );
        assert_eq!(
            DynamicPolicy::from_allow_dynamic_flag(true),
            DynamicPolicy::AllowDynamic
        );
    }

    #[test]
    fn static_only_caps_at_two() {
        let p: DynamicPolicy = DynamicPolicy::StaticOnly;
        assert!(p.permits_depth(1));
        assert!(p.permits_depth(2));
        assert!(!p.permits_depth(3));
    }

    #[test]
    fn allow_dynamic_permits_deeper() {
        let p: DynamicPolicy = DynamicPolicy::AllowDynamic;
        assert!(p.permits_depth(3));
        assert!(p.permits_depth(64));
        assert!(!p.permits_depth(65));
    }
}
