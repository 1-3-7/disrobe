use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use crate::artifact::Artifact;
use crate::capability::{Capability, CapabilityKind};
use crate::error::{CoreError, Result};
use crate::pass::{LegacyPass, PassMetadata};

pub type ShimTransform = Arc<dyn Fn(&Artifact) -> Result<Artifact> + Send + Sync>;

#[derive(Clone)]
pub struct MigrationShim {
    pub id: &'static str,
    pub from: Capability,
    pub to: Capability,
    pub transform: ShimTransform,
}

impl std::fmt::Debug for MigrationShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationShim")
            .field("id", &self.id)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("transform", &"<fn>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ShimStep {
    pub id: &'static str,
    pub from: Capability,
    pub to: Capability,
}

#[derive(Default, Clone)]
pub struct MigrationShimRegistry {
    by_from: BTreeMap<Capability, Vec<MigrationShim>>,
    all: BTreeMap<&'static str, MigrationShim>,
}

impl std::fmt::Debug for MigrationShimRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationShimRegistry")
            .field("by_from", &self.by_from.keys().collect::<Vec<_>>())
            .field("len", &self.all.len())
            .finish()
    }
}

impl MigrationShimRegistry {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, shim: MigrationShim) {
        let from_key: Capability = produces_form(&shim.from);
        self.by_from.entry(from_key).or_default().push(shim.clone());
        self.all.insert(shim.id, shim);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.all.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    pub fn shim_by_id(&self, id: &str) -> Option<&MigrationShim> {
        self.all.get(id)
    }

    fn shims_from(&self, cap: &Capability) -> &[MigrationShim] {
        self.by_from
            .get(&produces_form(cap))
            .map_or(&[][..], Vec::as_slice)
    }

    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.all.keys().copied()
    }

    #[must_use]
    pub fn default_shims_for_workspace() -> Self {
        let mut registry: Self = Self::new();
        for builder in WORKSPACE_SHIMS {
            registry.register(builder());
        }
        registry
    }
}

type ShimBuilder = fn() -> MigrationShim;

const WORKSPACE_SHIMS: &[ShimBuilder] = &[
    pyarmor_unwrapped_to_disasm_python_shim,
    pyarmor_unwrapped_to_raw_bytes_shim,
    pyarmor_unwrapped_self_identity_shim,
    disasm_python_self_identity_shim,
];

fn passthrough_transform() -> ShimTransform {
    Arc::new(|artifact: &Artifact| Ok(artifact.clone()))
}

fn promote_rung_transform(target: crate::rung::Rung) -> ShimTransform {
    Arc::new(move |artifact: &Artifact| {
        let mut next: Artifact = artifact.clone();
        next.rung = target;
        Ok(next)
    })
}

fn pyarmor_unwrapped_to_disasm_python_shim() -> MigrationShim {
    MigrationShim {
        id: "shim.pyarmor.unwrapped@1->disasm.python@1",
        from: Capability::produces("pyarmor.unwrapped", 1),
        to: Capability::produces("disasm.python", 1),
        transform: promote_rung_transform(crate::rung::Rung::Disasm),
    }
}

fn pyarmor_unwrapped_to_raw_bytes_shim() -> MigrationShim {
    MigrationShim {
        id: "shim.pyarmor.unwrapped@1->raw.bytes@1",
        from: Capability::produces("pyarmor.unwrapped", 1),
        to: Capability::produces("raw.bytes", 1),
        transform: passthrough_transform(),
    }
}

fn pyarmor_unwrapped_self_identity_shim() -> MigrationShim {
    MigrationShim {
        id: "shim.pyarmor.unwrapped@1->pyarmor.unwrapped@1",
        from: Capability::produces("pyarmor.unwrapped", 1),
        to: Capability::produces("pyarmor.unwrapped", 1),
        transform: passthrough_transform(),
    }
}

fn disasm_python_self_identity_shim() -> MigrationShim {
    MigrationShim {
        id: "shim.disasm.python@1->disasm.python@1",
        from: Capability::produces("disasm.python", 1),
        to: Capability::produces("disasm.python", 1),
        transform: passthrough_transform(),
    }
}

#[derive(Debug)]
pub struct CapabilityResolver<'a> {
    registry: &'a MigrationShimRegistry,
}

impl<'a> CapabilityResolver<'a> {
    #[inline]
    #[must_use]
    pub const fn new(registry: &'a MigrationShimRegistry) -> Self {
        Self { registry }
    }

    pub fn resolve<P: LegacyPass>(&self, pass: &P, artifact: &Artifact) -> Result<Vec<ShimStep>> {
        let available: BTreeSet<Capability> = artifact
            .capabilities
            .iter()
            .filter(|c| matches!(c.kind, CapabilityKind::Produces))
            .cloned()
            .collect();
        let required: Vec<Capability> = pass.required_capabilities();

        let mut plan: Vec<ShimStep> = Vec::new();
        let mut working: BTreeSet<Capability> = available;

        for req in required {
            if matches!(req.kind, CapabilityKind::Produces) {
                continue;
            }
            let needed: Capability = produces_form(&req);
            if working.contains(&needed) {
                continue;
            }
            let path: Vec<ShimStep> = self.path_to(&working, &needed)?;
            for step in &path {
                working.insert(produces_form(&step.to));
            }
            plan.extend(path);
        }

        Ok(plan)
    }

    fn path_to(
        &self,
        available: &BTreeSet<Capability>,
        target: &Capability,
    ) -> Result<Vec<ShimStep>> {
        if available.contains(target) {
            return Ok(Vec::new());
        }

        let mut frontier: VecDeque<Capability> = VecDeque::new();
        let mut visited: BTreeSet<Capability> = BTreeSet::new();
        let mut predecessor: BTreeMap<Capability, (Capability, &'static str)> = BTreeMap::new();

        for start in available {
            frontier.push_back(start.clone());
            visited.insert(start.clone());
        }

        while let Some(current) = frontier.pop_front() {
            for shim in self.registry.shims_from(&current) {
                let next: Capability = produces_form(&shim.to);
                if visited.contains(&next) {
                    continue;
                }
                visited.insert(next.clone());
                predecessor.insert(next.clone(), (current.clone(), shim.id));
                if &next == target {
                    return Ok(reconstruct_path(&predecessor, &next, self.registry));
                }
                frontier.push_back(next);
            }
        }

        Err(CoreError::UnsatisfiableRequirement {
            required: requires_form(target),
        })
    }
}

fn reconstruct_path(
    predecessor: &BTreeMap<Capability, (Capability, &'static str)>,
    target: &Capability,
    registry: &MigrationShimRegistry,
) -> Vec<ShimStep> {
    let mut reverse: Vec<ShimStep> = Vec::new();
    let mut node: Capability = target.clone();
    while let Some((prev, shim_id)) = predecessor.get(&node) {
        let shim_ref: &MigrationShim = match registry.shim_by_id(shim_id) {
            Some(s) => s,
            None => break,
        };
        reverse.push(ShimStep {
            id: shim_id,
            from: shim_ref.from.clone(),
            to: shim_ref.to.clone(),
        });
        node = prev.clone();
    }
    reverse.reverse();
    reverse
}

#[inline]
fn produces_form(cap: &Capability) -> Capability {
    Capability {
        name: cap.name.clone(),
        major: cap.major,
        kind: CapabilityKind::Produces,
    }
}

#[inline]
fn requires_form(cap: &Capability) -> Capability {
    Capability {
        name: cap.name.clone(),
        major: cap.major,
        kind: CapabilityKind::Requires,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pass::{LegacyPass, PassId};
    use crate::rung::Rung;

    #[derive(Debug)]
    struct NeedsMir;

    impl LegacyPass for NeedsMir {
        const CONSUMES: &'static [Rung] = &[Rung::Mir];
        const EMITS: &'static [Rung] = &[Rung::Hir];
        const REQUIRES: &'static [fn() -> Capability] = &[|| Capability::requires("mir.core", 2)];
        const PRODUCES: &'static [fn() -> Capability] = &[|| Capability::produces("hir.core", 1)];

        fn id(&self) -> PassId {
            "test.needs_mir"
        }

        fn run(&self, _artifact: &Artifact) -> Result<Artifact> {
            unreachable!("resolver test only")
        }
    }

    fn identity_shim(id: &'static str, from: Capability, to: Capability) -> MigrationShim {
        MigrationShim {
            id,
            from,
            to,
            transform: Arc::new(|a: &Artifact| Ok(a.clone())),
        }
    }

    #[test]
    fn empty_shim_happy_path_when_caps_present() {
        let registry: MigrationShimRegistry = MigrationShimRegistry::new();
        let resolver: CapabilityResolver<'_> = CapabilityResolver::new(&registry);
        let artifact: Artifact = Artifact::with_capabilities(
            Rung::Mir,
            vec![],
            [Capability::produces("mir.core", 2)],
            [0u8; 32],
        );
        let plan: Vec<ShimStep> = resolver
            .resolve(&NeedsMir, &artifact)
            .expect("must resolve");
        assert!(plan.is_empty());
    }

    #[test]
    fn missing_cap_hard_fail() {
        let registry: MigrationShimRegistry = MigrationShimRegistry::new();
        let resolver: CapabilityResolver<'_> = CapabilityResolver::new(&registry);
        let artifact: Artifact = Artifact::new(Rung::Mir, vec![], [0u8; 32]);
        let err: CoreError = resolver
            .resolve(&NeedsMir, &artifact)
            .expect_err("must fail");
        assert!(matches!(err, CoreError::UnsatisfiableRequirement { .. }));
    }

    #[test]
    fn transitive_shim_multi_hop() {
        let mut registry: MigrationShimRegistry = MigrationShimRegistry::new();
        registry.register(identity_shim(
            "mir.v1->v1_5",
            Capability::produces("mir.core", 1),
            Capability::produces("mir.core", 1),
        ));
        registry.register(identity_shim(
            "mir.v1_5->v2",
            Capability::produces("mir.core", 1),
            Capability::produces("mir.core", 2),
        ));
        let resolver: CapabilityResolver<'_> = CapabilityResolver::new(&registry);
        let artifact: Artifact = Artifact::with_capabilities(
            Rung::Mir,
            vec![],
            [Capability::produces("mir.core", 1)],
            [0u8; 32],
        );
        let plan: Vec<ShimStep> = resolver
            .resolve(&NeedsMir, &artifact)
            .expect("must resolve");
        assert!(!plan.is_empty());
        let final_step: &ShimStep = plan.last().expect("non-empty");
        assert_eq!(final_step.to.name, "mir.core");
        assert_eq!(final_step.to.major, 2);
    }

    #[test]
    fn registry_dedupes_by_id() {
        let mut registry: MigrationShimRegistry = MigrationShimRegistry::new();
        registry.register(identity_shim(
            "x",
            Capability::produces("a", 1),
            Capability::produces("b", 1),
        ));
        registry.register(identity_shim(
            "x",
            Capability::produces("a", 1),
            Capability::produces("c", 1),
        ));
        assert_eq!(registry.len(), 1);
    }

    #[derive(Debug)]
    struct NeedsPythonDisasm;

    impl LegacyPass for NeedsPythonDisasm {
        const CONSUMES: &'static [Rung] = &[Rung::Disasm];
        const EMITS: &'static [Rung] = &[Rung::Mir];
        const REQUIRES: &'static [fn() -> Capability] =
            &[|| Capability::requires("disasm.python", 1)];
        const PRODUCES: &'static [fn() -> Capability] = &[|| Capability::produces("mir.python", 1)];

        fn id(&self) -> PassId {
            "test.needs_python_disasm"
        }

        fn run(&self, _artifact: &Artifact) -> Result<Artifact> {
            unreachable!("resolver test only")
        }
    }

    #[derive(Debug)]
    struct NeedsUnknownCap;

    impl LegacyPass for NeedsUnknownCap {
        const CONSUMES: &'static [Rung] = &[Rung::Raw];
        const EMITS: &'static [Rung] = &[Rung::Disasm];
        const REQUIRES: &'static [fn() -> Capability] =
            &[|| Capability::requires("nothing.exists", 9)];
        const PRODUCES: &'static [fn() -> Capability] = &[];

        fn id(&self) -> PassId {
            "test.needs_unknown"
        }

        fn run(&self, _artifact: &Artifact) -> Result<Artifact> {
            unreachable!("resolver test only")
        }
    }

    #[test]
    fn default_shims_for_workspace_is_non_empty() {
        let registry: MigrationShimRegistry = MigrationShimRegistry::default_shims_for_workspace();
        assert!(registry.len() >= 4);
        let ids: BTreeSet<&'static str> = registry.ids().collect();
        assert!(ids.contains("shim.pyarmor.unwrapped@1->disasm.python@1"));
        assert!(ids.contains("shim.pyarmor.unwrapped@1->raw.bytes@1"));
        assert!(ids.contains("shim.pyarmor.unwrapped@1->pyarmor.unwrapped@1"));
        assert!(ids.contains("shim.disasm.python@1->disasm.python@1"));
    }

    #[test]
    fn workspace_resolver_finds_pyarmor_unwrapped_to_disasm_python() {
        let registry: MigrationShimRegistry = MigrationShimRegistry::default_shims_for_workspace();
        let resolver: CapabilityResolver<'_> = CapabilityResolver::new(&registry);
        let artifact: Artifact = Artifact::with_capabilities(
            Rung::Disasm,
            vec![],
            [Capability::produces("pyarmor.unwrapped", 1)],
            [0u8; 32],
        );
        let plan: Vec<ShimStep> = resolver
            .resolve(&NeedsPythonDisasm, &artifact)
            .expect("path exists via workspace shims");
        assert!(!plan.is_empty(), "expected at least one shim step");
        let final_step: &ShimStep = plan.last().expect("non-empty plan");
        assert_eq!(final_step.to.name, "disasm.python");
        assert_eq!(final_step.to.major, 1);
    }

    #[test]
    fn workspace_resolver_hard_fails_for_unregistered_cap() {
        let registry: MigrationShimRegistry = MigrationShimRegistry::default_shims_for_workspace();
        let resolver: CapabilityResolver<'_> = CapabilityResolver::new(&registry);
        let artifact: Artifact = Artifact::with_capabilities(
            Rung::Raw,
            vec![],
            [Capability::produces("pyarmor.unwrapped", 1)],
            [0u8; 32],
        );
        let err: CoreError = resolver
            .resolve(&NeedsUnknownCap, &artifact)
            .expect_err("unknown cap must hard-fail");
        assert!(matches!(err, CoreError::UnsatisfiableRequirement { .. }));
    }
}
