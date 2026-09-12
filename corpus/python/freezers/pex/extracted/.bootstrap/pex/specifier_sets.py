

from __future__ import absolute_import

import functools

from pex.pep_440 import Version
from pex.third_party.packaging.specifiers import SpecifierSet
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator, List, Optional, Tuple, Union

    import attr

else:
    from pex.third_party import attr


def _ensure_specifier_set(specifier_set):
    # type: (Union[str, SpecifierSet]) -> SpecifierSet
    return specifier_set if isinstance(specifier_set, SpecifierSet) else SpecifierSet(specifier_set)


@attr.s(frozen=True)
class UnsatisfiableSpecifierSet(object):
    specifier_set = attr.ib(converter=_ensure_specifier_set)


@attr.s(frozen=True)
class ArbitraryEquality(object):
    version = attr.ib()


@functools.total_ordering
@attr.s(frozen=True, order=False)
class _Bound(object):
    version = attr.ib()
    inclusive = attr.ib()
    symbol = attr.ib(init=False, eq=False, repr=False)
    rank = attr.ib(init=False, eq=False, repr=False)

    def __attrs_post_init__(self):
        raise NotImplementedError(
            "_Bound must be subclassed and __attrs_post_init__ implemented to initialize symbol"
            "and rank."
        )

    def __lt__(self, other):
        # type: (Any) -> bool
        if type(self) != type(other):
            return NotImplemented
        return (self.version, self.rank) < (other.version, other.rank)

    def __str__(self):
        # type: () -> str
        parts = [self.symbol]
        if self.inclusive:
            parts.append("=")
        parts.append(str(self.version))
        return "".join(parts)


class LowerBound(_Bound):
    def __attrs_post_init__(self):
        # type: () -> None
        object.__setattr__(self, "symbol", ">")

        object.__setattr__(self, "rank", 0 if self.inclusive else 1)


class UpperBound(_Bound):
    def __attrs_post_init__(self):
        # type: () -> None
        object.__setattr__(self, "symbol", "<")

        object.__setattr__(self, "rank", 1 if self.inclusive else 0)


@attr.s(frozen=True)
class ExcludedRange(object):
    lower = attr.ib()
    upper = attr.ib()

    def intersects(self, other):
        # type: (Range) -> bool


        if other.upper:
            if self.lower.version > other.upper.version:
                return False
            elif (
                self.lower.version == other.upper.version
                and self.lower.inclusive
                and other.upper.inclusive
            ):
                return True


        if other.lower:
            if self.upper.version < other.lower.version:
                return False
            elif (
                self.upper.version == other.lower.version
                and self.upper.inclusive
                and other.lower.inclusive
            ):
                return True


        excluded_range = Range(lower=self.lower, upper=self.upper)
        return other in excluded_range or excluded_range in other

    def __str__(self):
        return ",".join(map(str, (self.lower, self.upper)))


@attr.s(frozen=True)
class Range(object):
    lower = attr.ib(default=None)
    upper = attr.ib(default=None)
    excludes = attr.ib(default=())

    def __contains__(self, other):
        # type: (Any) -> bool
        if Range is not type(other):
            return NotImplemented
        return self.contains(other)

    def contains(self, other):
        # type: (Range) -> bool

        if self.lower:
            if not other.lower:
                return False
            elif self.lower.version > other.lower.version:
                return False
            elif (
                self.lower.version == other.lower.version
                and not self.lower.inclusive
                and other.lower.inclusive
            ):
                return False

        if self.upper:
            if not other.upper:
                return False
            elif self.upper.version < other.upper.version:
                return False
            elif (
                self.upper.version == other.upper.version
                and not self.upper.inclusive
                and other.upper.inclusive
            ):
                return False

        for excluded_range in self.excludes:
            if excluded_range.intersects(other):
                return False

        return True

    def __str__(self):
        # type: () -> str
        parts = []
        if self.lower:
            parts.append(str(self.lower))
        for excluded_range in self.excludes:
            parts.append("!({})".format(excluded_range))
        if self.upper:
            parts.append(str(self.upper))
        return ",".join(parts)


def _increment_release(
    version,
    index,
):
    # type: (...) -> Version

    parsed_version = version.parsed_version

    parts = []
    if parsed_version.epoch != 0:
        parts.append(str(parsed_version.epoch))
        parts.append("!")
    if parsed_version.release:
        ceiling_release = list(parsed_version.release[:index])
        ceiling_release.append(parsed_version.release[index] + 1)
        parts.append(".".join(str(x) for x in ceiling_release))

    return Version("".join(parts))


def _bounds(specifier_set):
    # type: (SpecifierSet) -> Iterator[Union[ArbitraryEquality, ExcludedRange, LowerBound, UpperBound]]

    for spec in specifier_set:
        if "===" == spec.operator:
            yield ArbitraryEquality(spec.version)
            continue

        if spec.version.endswith(".*"):
            version = Version(spec.version[:-2])
            if spec.operator in ("==", "!="):
                lower = LowerBound(version, inclusive=True)


                ceiling = _increment_release(version, index=-1)
                upper = UpperBound(ceiling, inclusive=False)
                if "==" == spec.operator:
                    yield lower
                    yield upper
                else:
                    yield ExcludedRange(lower=lower, upper=upper)
                continue


        else:
            version = Version(spec.version)

        if "==" == spec.operator:
            yield LowerBound(version, inclusive=True)
            yield UpperBound(version, inclusive=True)
        elif "!=" == spec.operator:
            yield ExcludedRange(
                lower=LowerBound(version, inclusive=True),
                upper=UpperBound(version, inclusive=True),
            )
        elif ">=" == spec.operator:
            yield LowerBound(version, inclusive=True)
        elif ">" == spec.operator:
            yield LowerBound(version, inclusive=False)
        elif "<=" == spec.operator:
            yield UpperBound(version, inclusive=True)
        elif "<" == spec.operator:
            yield UpperBound(version, inclusive=False)
        elif "~=" == spec.operator:
            yield LowerBound(version, inclusive=True)


            ceiling = _increment_release(version, -2)
            yield UpperBound(ceiling, inclusive=False)


def as_range(specifier_set):
    # type: (Union[str, SpecifierSet]) -> Union[ArbitraryEquality, Range, UnsatisfiableSpecifierSet]

    lower_bounds = []
    upper_bounds = []
    excludes = []
    for bound in _bounds(
        specifier_set if isinstance(specifier_set, SpecifierSet) else SpecifierSet(specifier_set)
    ):
        if isinstance(bound, ArbitraryEquality):
            return bound
        elif isinstance(bound, ExcludedRange):
            excludes.append(bound)
        elif isinstance(bound, LowerBound):
            lower_bounds.append(bound)
        else:
            upper_bounds.append(bound)


    lower = sorted(lower_bounds)[-1] if lower_bounds else None
    upper = sorted(upper_bounds)[0] if upper_bounds else None


    if lower:
        for exclude in sorted(excludes, key=lambda ex: ex.lower):


            if exclude.lower <= lower:
                new_lower = LowerBound(exclude.upper.version, inclusive=not exclude.upper.inclusive)
                if new_lower > lower:
                    lower = new_lower
                excludes.remove(exclude)
    if upper:
        for exclude in sorted(excludes, key=lambda ex: ex.upper, reverse=True):


            if exclude.upper >= upper:
                new_upper = UpperBound(exclude.lower.version, inclusive=not exclude.lower.inclusive)
                if new_upper < upper:
                    upper = new_upper
                excludes.remove(exclude)


    if lower and upper:
        if lower.version > upper.version:
            return UnsatisfiableSpecifierSet(specifier_set)
        if lower.version == upper.version and (not lower.inclusive or not upper.inclusive):
            return UnsatisfiableSpecifierSet(specifier_set)

    return Range(
        lower=lower,
        upper=upper,
        excludes=tuple(sorted(excludes, key=lambda ex: (ex.lower, ex.upper))),
    )


def includes(
    specifier,
    candidate,
):
    # type: (...) -> bool

    included_range = as_range(specifier)
    if isinstance(included_range, UnsatisfiableSpecifierSet):
        return False

    candidate_range = as_range(candidate)
    if isinstance(candidate_range, UnsatisfiableSpecifierSet):
        return False

    if isinstance(included_range, ArbitraryEquality) or isinstance(
        candidate_range, ArbitraryEquality
    ):
        return included_range == candidate_range

    return candidate_range in included_range
