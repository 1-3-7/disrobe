

from __future__ import absolute_import

import itertools
import os
import site
import sys
from collections import OrderedDict, defaultdict

from pex import dist_metadata, pex_warnings, targets
from pex.common import pluralize
from pex.dependency_configuration import DependencyConfiguration
from pex.dist_metadata import Distribution, Requirement, is_wheel
from pex.fingerprinted_distribution import FingerprintedDistribution
from pex.inherit_path import InheritPath
from pex.installed_wheel import InstalledWheel
from pex.interpreter import PythonInterpreter
from pex.layout import ensure_installed, identify_layout
from pex.orderedset import OrderedSet
from pex.pep_425 import TagRank
from pex.pep_503 import ProjectName
from pex.pex_info import PexInfo
from pex.requirement_key import RequirementKey
from pex.targets import Target
from pex.third_party.packaging import specifiers
from pex.third_party.packaging.tags import Tag
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING
from pex.whl import repacked_whl

if TYPE_CHECKING:
    from typing import (
        DefaultDict,
        Dict,
        FrozenSet,
        Iterable,
        Iterator,
        List,
        MutableMapping,
        Optional,
        Text,
        Tuple,
        Union,
    )

    import attr

    from pex.pep_427 import InstallableType
else:
    from pex.third_party import attr


def _import_pkg_resources():
    try:
        import pkg_resources

        return pkg_resources, False
    except ImportError:
        from pex import third_party

        third_party.install(expose_if_available=["setuptools"])
        try:
            import pkg_resources

            return pkg_resources, True
        except ImportError:
            return None, False


def _fd_lt(
    self,
    other,
):
    # type: (...) -> bool
    if self.project_name.normalized < other.project_name.normalized:
        return True


    if self.distribution.metadata.version >= other.distribution.metadata.version:
        return True

    return self.fingerprint < other.fingerprint


@attr.s(frozen=True)
class _RankedDistribution(object):


    _fd_cmp = attr.cmp_using(
        eq=FingerprintedDistribution.__eq__,
        lt=_fd_lt,
    )

    @classmethod
    def highest_rank(cls, fingerprinted_distribution):
        # type: (FingerprintedDistribution) -> _RankedDistribution
        return cls(
            rank=TagRank.highest_natural().higher(),
            fingerprinted_distribution=fingerprinted_distribution,
        )

    rank = attr.ib()
    fingerprinted_distribution = attr.ib(
        eq=_fd_cmp, order=_fd_cmp
    )

    @property
    def distribution(self):
        # type: () -> Distribution
        return self.fingerprinted_distribution.distribution

    @property
    def fingerprint(self):
        # type: () -> str
        return self.fingerprinted_distribution.fingerprint

    def satisfies(self, requirement):
        # type: (Requirement) -> bool
        return self.distribution in requirement


@attr.s(frozen=True)
class _UnrankedDistribution(object):
    fingerprinted_distribution = attr.ib()

    @property
    def dist(self):
        # type: () -> Distribution
        return self.fingerprinted_distribution.distribution

    def render_message(self, target):
        # type: (Target) -> str
        return "The distribution {dist} cannot be used by {target}.".format(
            dist=self.dist, target=target
        )


@attr.s(frozen=True)
class _InvalidWheelName(_UnrankedDistribution):
    filename = attr.ib()

    def render_message(self, _target):
        # type: (Target) -> str
        return (
            "The filename of {dist} is not a valid wheel file name that can be parsed for "
            "tags.".format(dist=self.dist)
        )


@attr.s(frozen=True)
class _TagMismatch(_UnrankedDistribution):
    wheel_tags = attr.ib()

    def render_message(self, target):
        # type: (Target) -> str
        return (
            "The wheel tags for {dist} are {wheel_tags} which do not match the supported tags of "
            "{target}:\n{tag}\n... {count} more ...".format(
                dist=self.dist,
                wheel_tags=", ".join(map(str, self.wheel_tags)),
                target=target,
                tag=target.supported_tags[0],
                count=len(target.supported_tags) - 1,
            )
        )


@attr.s(frozen=True)
class _PythonRequiresMismatch(_UnrankedDistribution):
    python_requires = attr.ib()

    def render_message(self, target):
        # type: (Target) -> str
        return (
            "The distribution has a python requirement of {python_requires} which does not match "
            "the python version of {python_version} for {target}.".format(
                python_requires=self.python_requires,
                python_version=target.python_version_str,
                target=target,
            )
        )


@attr.s(frozen=True)
class _QualifiedRequirement(object):
    requirement = attr.ib()
    required = attr.ib(default=True)

    def with_extras(self, extras):
        # type: (FrozenSet[str]) -> _QualifiedRequirement
        return attr.evolve(self, requirement=attr.evolve(self.requirement, extras=extras))


@attr.s(frozen=True)
class _DistributionNotFound(object):
    requirement = attr.ib()
    required_by = attr.ib(default=None)


if TYPE_CHECKING:
    QualifiedRequirementOrNotFound = Union[_QualifiedRequirement, _DistributionNotFound]


class ResolveError(Exception):


class PEXEnvironment(object):
    _CACHE = {}

    @classmethod
    def mount(
        cls,
        pex,
        pex_info=None,
        target=None,
    ):
        # type: (...) -> PEXEnvironment
        pex_file = os.path.realpath(pex)
        if not pex_info:
            pex_info = PexInfo.from_pex(pex_file)
            pex_info.update(PexInfo.from_env())
        pex_hash = pex_info.pex_hash
        if pex_hash is None:
            raise AssertionError(
                "There was no pex_hash stored in {} for {}.".format(PexInfo.PATH, pex)
            )
        target = target or targets.current()
        key = (pex_file, pex_hash, target)
        mounted = cls._CACHE.get(key)
        if mounted is None:
            pex_root = pex_info.pex_root
            installed_pex = ensure_installed(pex=pex, pex_root=pex_root, pex_hash=pex_hash)
            mounted = cls(pex=installed_pex, pex_info=pex_info, target=target, source_pex=pex)
            cls._CACHE[key] = mounted
        return mounted

    def __init__(
        self,
        pex,
        pex_info=None,
        target=None,
        source_pex=None,
    ):
        # type: (...) -> None
        self._pex = os.path.realpath(pex)
        self._pex_info = pex_info or PexInfo.from_pex(pex)
        self._target = target or targets.current()
        self._source_pex = os.path.realpath(source_pex) if source_pex else None

        self._available_ranked_dists_by_project_name = defaultdict(
            list
        )
        self._unavailable_dists_by_project_name = defaultdict(
            list
        )
        self._resolved_dists = None
        self._activated_dists = None

    @property
    def path(self):
        # type: () -> str
        return self._pex

    @property
    def pex_info(self):
        # type: () -> PexInfo
        return self._pex_info

    @property
    def source_pex(self):
        # type: () -> str
        return self._source_pex or self._pex

    def iter_distributions(self, result_type_wheel_file=False):
        # type: (bool) -> Iterator[FingerprintedDistribution]
        if result_type_wheel_file and self._pex_info.deps_are_wheel_files:
            with TRACER.timed(
                "Searching dependency cache: {cache}".format(
                    cache=os.path.join(self.source_pex, self._pex_info.internal_cache)
                ),
                V=2,
            ):
                with identify_layout(self.source_pex) as layout:
                    for distribution_name, fingerprint in self._pex_info.distributions.items():
                        yield FingerprintedDistribution(
                            distribution=Distribution.load(
                                layout.wheel_file_path(
                                    (self._pex_info.internal_cache, distribution_name)
                                )
                            ),
                            fingerprint=fingerprint,
                        )
        else:
            internal_cache = os.path.join(self._pex, self._pex_info.internal_cache)
            with TRACER.timed(
                "Searching dependency cache: {cache}".format(cache=internal_cache), V=2
            ):
                for distribution_name, fingerprint in self._pex_info.distributions.items():
                    dist_path = os.path.join(internal_cache, distribution_name)
                    if result_type_wheel_file:
                        yield repacked_whl(
                            installed_wheel=dist_path,
                            distribution_name=distribution_name,
                            fingerprint=fingerprint,
                            use_system_time=True,
                        )
                    else:
                        yield FingerprintedDistribution(
                            distribution=Distribution.load(dist_path), fingerprint=fingerprint
                        )

    def _update_candidate_distributions(self, distribution_iter):
        # type: (Iterable[FingerprintedDistribution]) -> None
        for fingerprinted_dist in distribution_iter:
            ranked_dist = self._can_add(fingerprinted_dist)
            project_name = fingerprinted_dist.project_name
            if isinstance(ranked_dist, _RankedDistribution):
                with TRACER.timed("Adding %s" % fingerprinted_dist.distribution, V=2):
                    self._available_ranked_dists_by_project_name[project_name].append(ranked_dist)
            else:
                self._unavailable_dists_by_project_name[project_name].append(ranked_dist)

    def _can_add(self, fingerprinted_dist):
        # type: (FingerprintedDistribution) -> Union[_RankedDistribution, _UnrankedDistribution]
        filename = os.path.basename(fingerprinted_dist.location)
        if not is_wheel(filename):


            return _RankedDistribution.highest_rank(fingerprinted_dist)

        try:
            wheel_eval = self._target.wheel_applies(fingerprinted_dist.distribution)
        except ValueError:
            return _InvalidWheelName(fingerprinted_dist, filename)

        if not wheel_eval.best_match:
            return _TagMismatch(fingerprinted_dist, wheel_eval.tags)
        if not wheel_eval.applies:
            assert wheel_eval.requires_python
            return _PythonRequiresMismatch(fingerprinted_dist, wheel_eval.requires_python)

        return _RankedDistribution(wheel_eval.best_match.rank, fingerprinted_dist)

    def activate(self):
        # type: () -> Iterable[Distribution]
        if self._activated_dists is None:
            with TRACER.timed("Activating PEX virtual environment from %s" % self._pex):
                self._activated_dists = self._activate()
        return self._activated_dists

    def _evaluate_marker(
        self,
        requirement,
        extras=(),
    ):
        # type: (...) -> bool
        applies = self._target.requirement_applies(requirement, extras=extras)
        if not applies:
            TRACER.log(
                "Skipping activation of `{}` due to environment marker de-selection".format(
                    requirement
                ),
                V=3,
            )
        return applies

    def _resolve_requirement(
        self,
        requirement,
        dependency_configuration,
        resolved_dists_by_key,
        required,
        required_by=None,
    ):
        # type: (...) -> Iterator[_DistributionNotFound]

        excluded_by = dependency_configuration.excluded_by(requirement)
        if excluded_by:
            TRACER.log(
                "Skipping resolving {requirement}: excluded by {excludes}".format(
                    requirement=requirement,
                    excludes=" and ".join(map(str, excluded_by)),
                )
            )
            return

        requirement_key = RequirementKey.create(requirement)
        if requirement_key in resolved_dists_by_key:
            return
        if any(key.satisfies(requirement_key) for key in resolved_dists_by_key):
            return

        available_distributions = [
            ranked_dist
            for ranked_dist in self._available_ranked_dists_by_project_name[
                requirement.project_name
            ]
            if ranked_dist.satisfies(requirement)
        ]
        if not available_distributions:
            if required:
                yield _DistributionNotFound(requirement, required_by=required_by)
            return

        resolved_distribution = sorted(available_distributions)[0].fingerprinted_distribution
        if len(available_distributions) > 1:
            TRACER.log(
                "Resolved {req} to {dist} and discarded {discarded}.".format(
                    req=requirement,
                    dist=resolved_distribution.distribution,
                    discarded=", ".join(
                        str(ranked_dist.distribution) for ranked_dist in available_distributions[1:]
                    ),
                ),
                V=9,
            )

        resolved_dists_by_key[requirement_key] = resolved_distribution

        for dep_requirement in dist_metadata.requires_dists(resolved_distribution.distribution):
            override = dependency_configuration.overridden_by(dep_requirement, target=self._target)
            if override:
                TRACER.log(
                    "Resolving {override}: overrides {requirement} from {dist}".format(
                        override=override,
                        requirement=dep_requirement,
                        dist=os.path.basename(resolved_distribution.distribution.location),
                    )
                )
                dep_requirement = override


            required = self._evaluate_marker(dep_requirement, extras=requirement.extras)
            if not required:
                continue

            for not_found in self._resolve_requirement(
                dep_requirement,
                dependency_configuration,
                resolved_dists_by_key,
                required,
                required_by=resolved_distribution.distribution,
            ):
                yield not_found

    def _root_requirements_iter(
        self,
        reqs,
        dependency_configuration,
    ):
        # type: (...) -> Iterator[QualifiedRequirementOrNotFound]


        qualified_reqs_by_project_name = (
            OrderedDict()
        )
        for req in reqs:
            excluded_by = dependency_configuration.excluded_by(req)
            if excluded_by:
                TRACER.log(
                    "Skipping resolving {requirement}: excluded by {excludes}".format(
                        requirement=req,
                        excludes=" and ".join(map(str, excluded_by)),
                    )
                )
                continue

            required = self._evaluate_marker(req)
            if not required:
                continue
            project_name = req.project_name
            requirements = qualified_reqs_by_project_name.get(project_name)
            if requirements is None:
                qualified_reqs_by_project_name[project_name] = requirements = []
            requirements.append(_QualifiedRequirement(req, required=required))


        for project_name, qualified_requirements in qualified_reqs_by_project_name.items():
            ranked_dists = self._available_ranked_dists_by_project_name.get(project_name)
            if ranked_dists is None:


                message = (
                    "A distribution for {project_name} could not be resolved for {target}.".format(
                        project_name=project_name, target=self._target
                    )
                )
                unavailable_dists = self._unavailable_dists_by_project_name.get(project_name)
                if unavailable_dists:
                    message += "\nFound {count} {distributions} for {project_name} that {does} not apply:\n" "{unavailable_dists}".format(
                        count=len(unavailable_dists),
                        distributions=pluralize(unavailable_dists, "distribution"),
                        project_name=project_name,
                        does="does" if len(unavailable_dists) == 1 else "do",
                        unavailable_dists="\n".join(
                            "{index}.) {message}".format(
                                index=index,
                                message=unavailable_dist.render_message(self._target),
                            )
                            for index, unavailable_dist in enumerate(unavailable_dists, start=1)
                        ),
                    )
                raise ResolveError(message)
            candidates = [
                (ranked_dist, qualified_requirement)
                for qualified_requirement in qualified_requirements
                for ranked_dist in ranked_dists
                if ranked_dist.satisfies(qualified_requirement.requirement)
            ]
            if not candidates:
                for qualified_requirement in qualified_requirements:
                    yield _DistributionNotFound(qualified_requirement.requirement)
                continue

            ranked_dist, qualified_requirement = sorted(candidates, key=lambda tup: tup[0])[0]
            if len(candidates) > 1:
                TRACER.log(
                    "Selected {dist} via {req} and discarded {discarded}.".format(
                        req=qualified_requirement.requirement,
                        dist=ranked_dist.distribution,
                        discarded=", ".join(
                            "{dist} via {req}".format(
                                req=qualified_req.requirement, dist=ranked_dist.distribution
                            )
                            for ranked_dist, qualified_req in candidates[1:]
                        ),
                    ),
                    V=9,
                )


            yield qualified_requirement.with_extras(
                frozenset(
                    itertools.chain.from_iterable(
                        candidate[1].requirement.extras for candidate in candidates
                    )
                )
            )

    def resolve(self):
        # type: () -> Iterable[Distribution]
        if self._resolved_dists is None:
            all_reqs = [Requirement.parse(req) for req in self._pex_info.requirements]
            dependency_configuration = DependencyConfiguration.from_pex_info(self._pex_info)
            self._resolved_dists = tuple(
                fingerprinted_distribution.distribution
                for fingerprinted_distribution in self.resolve_dists(
                    all_reqs, dependency_configuration=dependency_configuration
                )
            )
        return self._resolved_dists

    def resolve_dists(
        self,
        reqs,
        dependency_configuration=DependencyConfiguration(),
        result_type=None,
    ):
        # type: (...) -> Iterable[FingerprintedDistribution]

        result_type_wheel_file = False
        if result_type is not None:
            from pex.pep_427 import InstallableType

            result_type_wheel_file = result_type is InstallableType.WHEEL_FILE

        self._update_candidate_distributions(
            self.iter_distributions(result_type_wheel_file=result_type_wheel_file)
        )

        unresolved_reqs = OrderedDict()

        def record_unresolved(dist_not_found):
            # type: (_DistributionNotFound) -> None
            TRACER.log("Failed to resolve a requirement: {}".format(dist_not_found.requirement))
            requirers = unresolved_reqs.get(dist_not_found.requirement)
            if requirers is None:
                requirers = OrderedSet()
                unresolved_reqs[dist_not_found.requirement] = requirers
            if dist_not_found.required_by:
                requirers.add(dist_not_found.required_by)

        resolved_dists_by_key = (
            OrderedDict()
        )
        for qualified_req_or_not_found in self._root_requirements_iter(
            reqs, dependency_configuration
        ):
            if isinstance(qualified_req_or_not_found, _DistributionNotFound):
                record_unresolved(qualified_req_or_not_found)
                continue

            with TRACER.timed("Resolving {}".format(qualified_req_or_not_found.requirement), V=2):
                for not_found in self._resolve_requirement(
                    requirement=qualified_req_or_not_found.requirement,
                    dependency_configuration=dependency_configuration,
                    required=qualified_req_or_not_found.required,
                    resolved_dists_by_key=resolved_dists_by_key,
                ):
                    record_unresolved(not_found)

        if unresolved_reqs:
            TRACER.log("Unresolved requirements:")
            for req in unresolved_reqs:
                TRACER.log("  - {}".format(req))

            TRACER.log("Distributions contained within this pex:")
            if not self._pex_info.distributions:
                TRACER.log("  None")
            else:
                for dist_name in self._pex_info.distributions:
                    TRACER.log("  - {}".format(dist_name))

            if not self._pex_info.ignore_errors:
                items = []
                for index, (requirement, requirers) in enumerate(unresolved_reqs.items()):
                    rendered_requirers = ""
                    if requirers:
                        rendered_requirers = "\n    Required by:" "\n      {requirers}".format(
                            requirers="\n      ".join(map(str, requirers))
                        )
                    contains = self._available_ranked_dists_by_project_name[
                        requirement.project_name
                    ]
                    if contains:
                        rendered_contains = (
                            "\n    But this pex only contains:"
                            "\n      {distributions}".format(
                                distributions="\n      ".join(
                                    os.path.basename(ranked_dist.distribution.location)
                                    for ranked_dist in contains
                                ),
                            )
                        )
                    else:
                        rendered_contains = (
                            "\n    But this pex had no {project_name!r} distributions.".format(
                                project_name=requirement.project_name.raw
                            )
                        )
                    items.append(
                        "{index: 2d}: {requirement}"
                        "{rendered_requirers}"
                        "{rendered_contains}".format(
                            index=index + 1,
                            requirement=requirement,
                            rendered_requirers=rendered_requirers,
                            rendered_contains=rendered_contains,
                        )
                    )

                raise ResolveError(
                    "Failed to resolve requirements from PEX environment @ {pex}.\n"
                    "Needed {platform} compatible dependencies for:\n"
                    "{items}".format(
                        pex=self.source_pex,
                        platform=self._target.platform.tag,
                        items="\n".join(items),
                    )
                )

        return OrderedSet(resolved_dists_by_key.values())

    @classmethod
    def _get_namespace_packages(cls, dist):
        # type: (Distribution) -> Tuple[Text, ...]
        return tuple(dist.iter_metadata_lines("namespace_packages.txt"))

    @classmethod
    def _declare_namespace_packages(cls, resolved_dists):
        # type: (Iterable[Distribution]) -> None
        namespace_packages_by_dist = (
            OrderedDict()
        )
        for dist in resolved_dists:
            namespace_packages = cls._get_namespace_packages(dist)


            if namespace_packages:
                namespace_packages_by_dist[dist] = namespace_packages

        if not namespace_packages_by_dist:
            return


        pkg_resources, vendored = _import_pkg_resources()
        if not pkg_resources or vendored:
            dists = "\n".join(
                "\n{index}. {dist} namespace packages:\n  {ns_packages}".format(
                    index=index + 1,
                    dist=dist.as_requirement(),
                    ns_packages="\n  ".join(ns_packages),
                )
                for index, (dist, ns_packages) in enumerate(namespace_packages_by_dist.items())
            )
            if not pkg_resources:
                current_interpreter = PythonInterpreter.get()
                pex_warnings.warn(
                    "The legacy `pkg_resources` package cannot be imported by the "
                    "{implementation} {version} interpreter at {path}.\n"
                    "The following distributions need `pkg_resources` to load some legacy "
                    "namespace packages and may fail to work properly:\n{dists}".format(
                        implementation=current_interpreter.identity.implementation,
                        version=current_interpreter.python,
                        path=current_interpreter.binary,
                        dists=dists,
                    )
                )
                return

            pex_warnings.warn(
                "The `pkg_resources` package was loaded from a pex vendored version when "
                "declaring namespace packages defined by:\n{dists}\n\nThese distributions "
                "should fix their `install_requires` to include `setuptools`".format(dists=dists)
            )

        for pkg in itertools.chain(*namespace_packages_by_dist.values()):
            if pkg in sys.modules:
                pkg_resources.declare_namespace(pkg)

    def _activate(self):
        # type: () -> Iterable[Distribution]

        if not any(self._pex == os.path.realpath(path) for path in sys.path):
            TRACER.log("Adding pex environment to the head of sys.path: {}".format(self._pex))
            sys.path.insert(0, self._pex)

        resolved = self.resolve()
        for dist in resolved:


            if dist.location in sys.path:
                continue
            with TRACER.timed("Activating %s" % dist, V=2):
                for entry in InstalledWheel.load(dist.location).iter_sys_path_entries():
                    if self._pex_info.inherit_path == InheritPath.FALLBACK:


                        sys.path.insert(0, entry)
                    else:
                        sys.path.append(entry)

                    with TRACER.timed("Adding sitedir", V=2):
                        site.addsitedir(entry)
        return resolved
