from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from .errors import _ErrorCollector
from .requirements import Requirement

__all__ = [
    "CyclicDependencyGroup",
    "DependencyGroupInclude",
    "DependencyGroupResolver",
    "DuplicateGroupNames",
    "InvalidDependencyGroupObject",
    "resolve_dependency_groups",
]


def __dir__() -> list[str]:
    return __all__


class DuplicateGroupNames(ValueError):


class CyclicDependencyGroup(ValueError):

    def __init__(self, requested_group: str, group: str, include_group: str) -> None:
        self.requested_group = requested_group
        self.group = group
        self.include_group = include_group

        if include_group == group:
            reason = f"{group} includes itself"
        else:
            reason = f"{include_group} -> {group}, {group} -> {include_group}"
        super().__init__(
            "Cyclic dependency group include while resolving "
            f"{requested_group}: {reason}"
        )


class InvalidDependencyGroupObject(ValueError):


class DependencyGroupInclude:
    __slots__ = ("include_group",)

    def __init__(self, include_group: str) -> None:
        self.include_group = include_group

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.include_group!r})"


class DependencyGroupResolver:

    def __init__(
        self,
        dependency_groups: Mapping[str, Sequence[str | Mapping[str, str]]],
    ) -> None:
        errors = _ErrorCollector()

        self.dependency_groups = _normalize_group_names(dependency_groups, errors)


        self._parsed_groups: dict[
            str, tuple[Requirement | DependencyGroupInclude, ...]
        ] = {}

        self._include_graph_ancestors: dict[str, tuple[str, ...]] = {}

        self._resolve_cache: dict[str, tuple[Requirement, ...]] = {}

        errors.finalize("[dependency-groups] data was invalid")

    def lookup(self, group: str) -> tuple[Requirement | DependencyGroupInclude, ...]:
        group = _normalize_name(group)

        with _ErrorCollector().on_exit(
            f"[dependency-groups] data for {group!r} was malformed"
        ) as errors:
            return self._parse_group(group, errors)

    def resolve(self, group: str) -> tuple[Requirement, ...]:
        group = _normalize_name(group)

        with _ErrorCollector().on_exit(
            f"[dependency-groups] data for {group!r} was malformed"
        ) as errors:
            return self._resolve(group, group, errors)

    def _resolve(
        self, group: str, requested_group: str, errors: _ErrorCollector
    ) -> tuple[Requirement, ...]:
        if group in self._resolve_cache:
            return self._resolve_cache[group]

        parsed = self._parse_group(group, errors)

        resolved_group = []

        for item in parsed:
            if isinstance(item, Requirement):
                resolved_group.append(item)
            elif isinstance(item, DependencyGroupInclude):
                include_group = _normalize_name(item.include_group)


                if include_group in self._include_graph_ancestors.get(group, ()):
                    errors.error(
                        CyclicDependencyGroup(
                            requested_group, group, item.include_group
                        )
                    )
                else:
                    self._include_graph_ancestors[include_group] = (
                        *self._include_graph_ancestors.get(group, ()),
                        group,
                    )
                    resolved_group.extend(
                        self._resolve(include_group, requested_group, errors)
                    )
            else:
                raise NotImplementedError(
                    f"Invalid dependency group item after parse: {item}"
                )


        if errors.errors:
            return ()

        self._resolve_cache[group] = tuple(resolved_group)
        return self._resolve_cache[group]

    def _parse_group(
        self, group: str, errors: _ErrorCollector
    ) -> tuple[Requirement | DependencyGroupInclude, ...]:

        if group in self._parsed_groups:
            return self._parsed_groups[group]

        if group not in self.dependency_groups:
            errors.error(LookupError(f"Dependency group '{group}' not found"))
            return ()

        raw_group = self.dependency_groups[group]
        if isinstance(raw_group, str):
            errors.error(
                TypeError(
                    f"Dependency group {group!r} contained a string rather than a list."
                )
            )
            return ()

        if not isinstance(raw_group, Sequence):
            errors.error(
                TypeError(f"Dependency group {group!r} is not a sequence type.")
            )
            return ()

        elements: list[Requirement | DependencyGroupInclude] = []
        for item in raw_group:
            if isinstance(item, str):


                elements.append(Requirement(item))
            elif isinstance(item, Mapping):
                if tuple(item.keys()) != ("include-group",):
                    errors.error(
                        InvalidDependencyGroupObject(
                            f"Invalid dependency group item: {item!r}"
                        )
                    )
                else:
                    include_group = item["include-group"]
                    elements.append(DependencyGroupInclude(include_group=include_group))
            else:
                errors.error(TypeError(f"Invalid dependency group item: {item!r}"))

        self._parsed_groups[group] = tuple(elements)
        return self._parsed_groups[group]


def resolve_dependency_groups(
    dependency_groups: Mapping[str, Sequence[str | Mapping[str, str]]], /, *groups: str
) -> tuple[str, ...]:
    resolver = DependencyGroupResolver(dependency_groups)
    return tuple(str(r) for group in groups for r in resolver.resolve(group))


_NORMALIZE_PATTERN = re.compile(r"[-_.]+")


def _normalize_name(name: str) -> str:
    return _NORMALIZE_PATTERN.sub("-", name).lower()


def _normalize_group_names(
    dependency_groups: Mapping[str, Sequence[str | Mapping[str, str]]],
    errors: _ErrorCollector,
) -> dict[str, Sequence[str | Mapping[str, str]]]:
    original_names: dict[str, list[str]] = {}
    normalized_groups: dict[str, Sequence[str | Mapping[str, str]]] = {}

    for group_name, value in dependency_groups.items():
        normed_group_name = _normalize_name(group_name)
        original_names.setdefault(normed_group_name, []).append(group_name)
        normalized_groups[normed_group_name] = value

    for normed_name, names in original_names.items():
        if len(names) > 1:
            errors.error(
                DuplicateGroupNames(
                    "Duplicate dependency group names: "
                    f"{normed_name} ({', '.join(names)})"
                )
            )

    return normalized_groups
