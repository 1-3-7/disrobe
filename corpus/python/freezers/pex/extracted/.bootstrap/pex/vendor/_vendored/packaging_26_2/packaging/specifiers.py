

from __future__ import annotations

import abc
import enum
import functools
import itertools
import re
import sys
import typing
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Final,
    Iterable,
    Iterator,
    Sequence,
    TypeVar,
    Union,
)

from .utils import canonicalize_version
from .version import InvalidVersion, Version

if sys.version_info >= (3, 10):
    from typing import TypeGuard
elif TYPE_CHECKING:
    from typing_extensions import TypeGuard

__all__ = [
    "BaseSpecifier",
    "InvalidSpecifier",
    "Specifier",
    "SpecifierSet",
]


def __dir__() -> list[str]:
    return __all__


def _validate_spec(spec: object, /) -> TypeGuard[tuple[str, str]]:
    return (
        isinstance(spec, tuple)
        and len(spec) == 2
        and isinstance(spec[0], str)
        and isinstance(spec[1], str)
    )


def _validate_pre(pre: object, /) -> TypeGuard[bool | None]:
    return pre is None or isinstance(pre, bool)


T = TypeVar("T")
UnparsedVersion = Union[Version, str]
UnparsedVersionVar = TypeVar("UnparsedVersionVar", bound=UnparsedVersion)
CallableOperator = Callable[[Version, str], bool]


_MIN_VERSION: Final[Version] = Version("0.dev0")


def _trim_release(release: tuple[int, ...]) -> tuple[int, ...]:
    end = len(release)
    while end > 1 and release[end - 1] == 0:
        end -= 1
    return release if end == len(release) else release[:end]


class _BoundaryKind(enum.Enum):

    AFTER_LOCALS = enum.auto()
    AFTER_POSTS = enum.auto()


@functools.total_ordering
class _BoundaryVersion:

    __slots__ = ("_kind", "_trimmed_release", "version")

    def __init__(self, version: Version, kind: _BoundaryKind) -> None:
        self.version = version
        self._kind = kind
        self._trimmed_release = _trim_release(version.release)

    def _is_family(self, other: Version) -> bool:
        v = self.version
        if not (
            other.epoch == v.epoch
            and _trim_release(other.release) == self._trimmed_release
            and other.pre == v.pre
        ):
            return False
        if self._kind == _BoundaryKind.AFTER_LOCALS:

            return other.post == v.post and other.dev == v.dev

        return other.dev == v.dev or other.post is not None

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _BoundaryVersion):
            return self.version == other.version and self._kind == other._kind
        return NotImplemented

    def __lt__(self, other: _BoundaryVersion | Version) -> bool:
        if isinstance(other, _BoundaryVersion):
            if self.version != other.version:
                return self.version < other.version
            return self._kind.value < other._kind.value
        return not self._is_family(other) and self.version < other

    def __hash__(self) -> int:
        return hash((self.version, self._kind))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.version!r}, {self._kind.name})"


@functools.total_ordering
class _LowerBound:

    __slots__ = ("inclusive", "version")

    def __init__(self, version: _VersionOrBoundary, inclusive: bool) -> None:
        self.version = version
        self.inclusive = inclusive

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _LowerBound):
            return NotImplemented
        return self.version == other.version and self.inclusive == other.inclusive

    def __lt__(self, other: _LowerBound) -> bool:
        if not isinstance(other, _LowerBound):
            return NotImplemented

        if self.version is None:
            return other.version is not None
        if other.version is None:
            return False
        if self.version != other.version:
            return self.version < other.version

        return self.inclusive and not other.inclusive

    def __hash__(self) -> int:
        return hash((self.version, self.inclusive))

    def __repr__(self) -> str:
        bracket = "[" if self.inclusive else "("
        return f"<{self.__class__.__name__} {bracket}{self.version!r}>"


@functools.total_ordering
class _UpperBound:

    __slots__ = ("inclusive", "version")

    def __init__(self, version: _VersionOrBoundary, inclusive: bool) -> None:
        self.version = version
        self.inclusive = inclusive

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _UpperBound):
            return NotImplemented
        return self.version == other.version and self.inclusive == other.inclusive

    def __lt__(self, other: _UpperBound) -> bool:
        if not isinstance(other, _UpperBound):
            return NotImplemented

        if self.version is None:
            return False
        if other.version is None:
            return True
        if self.version != other.version:
            return self.version < other.version

        return not self.inclusive and other.inclusive

    def __hash__(self) -> int:
        return hash((self.version, self.inclusive))

    def __repr__(self) -> str:
        bracket = "]" if self.inclusive else ")"
        return f"<{self.__class__.__name__} {self.version!r}{bracket}>"


if typing.TYPE_CHECKING:
    _VersionOrBoundary = Union[Version, _BoundaryVersion, None]


    _VersionRange = tuple[_LowerBound, _UpperBound]

_NEG_INF = _LowerBound(None, False)
_POS_INF = _UpperBound(None, False)
_FULL_RANGE: tuple[_VersionRange] = ((_NEG_INF, _POS_INF),)


def _range_is_empty(lower: _LowerBound, upper: _UpperBound) -> bool:
    if lower.version is None or upper.version is None:
        return False
    if lower.version == upper.version:
        return not (lower.inclusive and upper.inclusive)
    return lower.version > upper.version


def _intersect_ranges(
    left: Sequence[_VersionRange],
    right: Sequence[_VersionRange],
) -> list[_VersionRange]:
    result: list[_VersionRange] = []
    left_index = right_index = 0
    while left_index < len(left) and right_index < len(right):
        left_lower, left_upper = left[left_index]
        right_lower, right_upper = right[right_index]

        lower = max(left_lower, right_lower)
        upper = min(left_upper, right_upper)

        if not _range_is_empty(lower, upper):
            result.append((lower, upper))


        if left_upper < right_upper:
            left_index += 1
        else:
            right_index += 1

    return result


def _next_prefix_dev0(version: Version) -> Version:
    release = (*version.release[:-1], version.release[-1] + 1)
    return Version.from_parts(epoch=version.epoch, release=release, dev=0)


def _base_dev0(version: Version) -> Version:
    return Version.from_parts(epoch=version.epoch, release=version.release, dev=0)


def _coerce_version(version: UnparsedVersion) -> Version | None:
    if not isinstance(version, Version):
        try:
            version = Version(version)
        except InvalidVersion:
            return None
    return version


def _public_version(version: Version) -> Version:
    if version.local is None:
        return version
    return version.__replace__(local=None)


def _post_base(version: Version) -> Version:
    return version.__replace__(post=None, dev=None, local=None)


def _earliest_prerelease(version: Version) -> Version:
    return version.__replace__(dev=0, local=None)


def _nearest_non_prerelease(
    v: _VersionOrBoundary,
) -> Version | None:
    if v is None:
        return None
    if isinstance(v, _BoundaryVersion):
        inner = v.version
        if inner.is_prerelease:

            return inner.__replace__(pre=None, dev=None, local=None)


        k = (inner.post + 1) if inner.post is not None else 0
        return inner.__replace__(post=k, local=None)
    if not v.is_prerelease:
        return v

    return v.__replace__(pre=None, dev=None, local=None)


class InvalidSpecifier(ValueError):


class BaseSpecifier(metaclass=abc.ABCMeta):
    __slots__ = ()
    __match_args__ = ("_str",)

    @property
    def _str(self) -> str:
        return str(self)

    @abc.abstractmethod
    def __str__(self) -> str:

    @abc.abstractmethod
    def __hash__(self) -> int:

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:

    @property
    @abc.abstractmethod
    def prereleases(self) -> bool | None:

    @prereleases.setter
    def prereleases(self, value: bool) -> None:

    @abc.abstractmethod
    def contains(self, item: str, prereleases: bool | None = None) -> bool:

    @typing.overload
    def filter(
        self,
        iterable: Iterable[UnparsedVersionVar],
        prereleases: bool | None = None,
        key: None = ...,
    ) -> Iterator[UnparsedVersionVar]: ...

    @typing.overload
    def filter(
        self,
        iterable: Iterable[T],
        prereleases: bool | None = None,
        key: Callable[[T], UnparsedVersion] = ...,
    ) -> Iterator[T]: ...

    @abc.abstractmethod
    def filter(
        self,
        iterable: Iterable[Any],
        prereleases: bool | None = None,
        key: Callable[[Any], UnparsedVersion] | None = None,
    ) -> Iterator[Any]:


class Specifier(BaseSpecifier):

    __slots__ = (
        "_prereleases",
        "_ranges",
        "_spec",
        "_spec_version",
        "_wildcard_split",
    )

    _specifier_regex_str = r"""
        (?:
            (?:
                # The identity operators allow for an escape hatch that will
                # do an exact string match of the version you wish to install.
                # This will not be parsed by PEP 440 and we cannot determine
                # any semantic meaning from it. This operator is discouraged
                # but included entirely as an escape hatch.
                ===  # Only match for the identity operator
                \s*
                [^\s;)]*  # The arbitrary version can be just about anything,
                          # we match everything except for whitespace, a
                          # semi-colon for marker support, and a closing paren
                          # since versions can be enclosed in them.
            )
            |
            (?:
                # The (non)equality operators allow for wild card and local
                # versions to be specified so we have to define these two
                # operators separately to enable that.
                (?:==|!=)            # Only match for equals and not equals

                \s*
                v?
                (?:[0-9]+!)?          # epoch
                [0-9]+(?:\.[0-9]+)*   # release

                # You cannot use a wild card and a pre-release, post-release, a dev or
                # local version together so group them with a | and make them optional.
                (?:
                    \.\*  # Wild card syntax of .*
                    |
                    (?a:                                  # pre release
                        [-_\.]?
                        (alpha|beta|preview|pre|a|b|c|rc)
                        [-_\.]?
                        [0-9]*
                    )?
                    (?a:                                  # post release
                        (?:-[0-9]+)|(?:[-_\.]?(post|rev|r)[-_\.]?[0-9]*)
                    )?
                    (?a:[-_\.]?dev[-_\.]?[0-9]*)?         # dev release
                    (?a:\+[a-z0-9]+(?:[-_\.][a-z0-9]+)*)? # local
                )?
            )
            |
            (?:
                # The compatible operator requires at least two digits in the
                # release segment.
                (?:~=)               # Only match for the compatible operator

                \s*
                v?
                (?:[0-9]+!)?          # epoch
                [0-9]+(?:\.[0-9]+)+   # release  (We have a + instead of a *)
                (?:                   # pre release
                    [-_\.]?
                    (alpha|beta|preview|pre|a|b|c|rc)
                    [-_\.]?
                    [0-9]*
                )?
                (?:                                   # post release
                    (?:-[0-9]+)|(?:[-_\.]?(post|rev|r)[-_\.]?[0-9]*)
                )?
                (?:[-_\.]?dev[-_\.]?[0-9]*)?          # dev release
            )
            |
            (?:
                # All other operators only allow a sub set of what the
                # (non)equality operators do. Specifically they do not allow
                # local versions to be specified nor do they allow the prefix
                # matching wild cards.
                (?:<=|>=|<|>)

                \s*
                v?
                (?:[0-9]+!)?          # epoch
                [0-9]+(?:\.[0-9]+)*   # release
                (?a:                   # pre release
                    [-_\.]?
                    (alpha|beta|preview|pre|a|b|c|rc)
                    [-_\.]?
                    [0-9]*
                )?
                (?a:                                   # post release
                    (?:-[0-9]+)|(?:[-_\.]?(post|rev|r)[-_\.]?[0-9]*)
                )?
                (?a:[-_\.]?dev[-_\.]?[0-9]*)?          # dev release
            )
        )
        """

    _regex = re.compile(
        r"\s*" + _specifier_regex_str + r"\s*", re.VERBOSE | re.IGNORECASE
    )

    _operators: Final = {
        "~=": "compatible",
        "==": "equal",
        "!=": "not_equal",
        "<=": "less_than_equal",
        ">=": "greater_than_equal",
        "<": "less_than",
        ">": "greater_than",
        "===": "arbitrary",
    }

    def __init__(self, spec: str = "", prereleases: bool | None = None) -> None:
        if not self._regex.fullmatch(spec):
            raise InvalidSpecifier(f"Invalid specifier: {spec!r}")

        spec = spec.strip()
        if spec.startswith("==="):
            operator, version = spec[:3], spec[3:].strip()
        elif spec.startswith(("~=", "==", "!=", "<=", ">=")):
            operator, version = spec[:2], spec[2:].strip()
        else:
            operator, version = spec[:1], spec[1:].strip()

        self._spec: tuple[str, str] = (operator, version)


        self._prereleases = prereleases


        self._spec_version: tuple[str, Version] | None = None


        self._wildcard_split: tuple[list[str], int] | None = None


        self._ranges: Sequence[_VersionRange] | None = None

    def _get_spec_version(self, version: str) -> Version | None:
        if self._spec_version is not None and self._spec_version[0] == version:
            return self._spec_version[1]

        version_specifier = _coerce_version(version)
        if version_specifier is None:
            return None

        self._spec_version = (version, version_specifier)
        return version_specifier

    def _require_spec_version(self, version: str) -> Version:
        spec_version = self._get_spec_version(version)
        assert spec_version is not None
        return spec_version

    def _to_ranges(self) -> Sequence[_VersionRange]:
        if self._ranges is not None:
            return self._ranges

        op = self.operator
        ver_str = self.version

        if op == "===":
            self._ranges = _FULL_RANGE
            return _FULL_RANGE

        if ver_str.endswith(".*"):
            result = self._wildcard_ranges(op, ver_str)
        else:
            result = self._standard_ranges(op, ver_str)

        self._ranges = result
        return result

    def _wildcard_ranges(self, op: str, ver_str: str) -> list[_VersionRange]:

        base = self._require_spec_version(ver_str[:-2])
        lower = _base_dev0(base)
        upper = _next_prefix_dev0(base)
        if op == "==":
            return [(_LowerBound(lower, True), _UpperBound(upper, False))]

        return [
            (_NEG_INF, _UpperBound(lower, False)),
            (_LowerBound(upper, True), _POS_INF),
        ]

    def _standard_ranges(self, op: str, ver_str: str) -> list[_VersionRange]:
        v = self._require_spec_version(ver_str)

        if op == ">=":
            return [(_LowerBound(v, True), _POS_INF)]

        if op == "<=":
            return [
                (
                    _NEG_INF,
                    _UpperBound(_BoundaryVersion(v, _BoundaryKind.AFTER_LOCALS), True),
                )
            ]

        if op == ">":
            if v.dev is not None:


                lower_ver = v.__replace__(dev=v.dev + 1, local=None)
                return [(_LowerBound(lower_ver, True), _POS_INF)]
            if v.post is not None:

                lower_ver = v.__replace__(post=v.post + 1, dev=0, local=None)
                return [(_LowerBound(lower_ver, True), _POS_INF)]

            return [
                (
                    _LowerBound(_BoundaryVersion(v, _BoundaryKind.AFTER_POSTS), False),
                    _POS_INF,
                )
            ]

        if op == "<":


            bound = v if v.is_prerelease else v.__replace__(dev=0, local=None)
            if bound <= _MIN_VERSION:
                return []
            return [(_NEG_INF, _UpperBound(bound, False))]


        has_local = "+" in ver_str
        after_locals = _BoundaryVersion(v, _BoundaryKind.AFTER_LOCALS)
        upper = v if has_local else after_locals

        if op == "==":
            return [(_LowerBound(v, True), _UpperBound(upper, True))]

        if op == "!=":
            return [
                (_NEG_INF, _UpperBound(v, False)),
                (_LowerBound(upper, False), _POS_INF),
            ]

        if op == "~=":
            prefix = v.__replace__(release=v.release[:-1])
            return [
                (_LowerBound(v, True), _UpperBound(_next_prefix_dev0(prefix), False))
            ]

        raise ValueError(f"Unknown operator: {op!r}")

    @property
    def prereleases(self) -> bool | None:


        if self._prereleases is not None:
            return self._prereleases


        operator, version_str = self._spec
        if operator == "!=":
            return False


        if operator == "==" and version_str.endswith(".*"):
            return False


        version = self._get_spec_version(version_str)
        if version is None:
            return None


        return version.is_prerelease

    @prereleases.setter
    def prereleases(self, value: bool | None) -> None:
        self._prereleases = value

    def __getstate__(self) -> tuple[tuple[str, str], bool | None]:


        return (self._spec, self._prereleases)

    def __setstate__(self, state: object) -> None:

        self._spec_version = None
        self._wildcard_split = None
        self._ranges = None

        if isinstance(state, tuple):
            if len(state) == 2:

                spec, prereleases = state
                if _validate_spec(spec) and _validate_pre(prereleases):
                    self._spec = spec
                    self._prereleases = prereleases
                    return
            if len(state) == 2 and isinstance(state[1], dict):

                _, slot_dict = state
                spec = slot_dict.get("_spec")
                prereleases = slot_dict.get("_prereleases", "invalid")
                if _validate_spec(spec) and _validate_pre(prereleases):
                    self._spec = spec
                    self._prereleases = prereleases
                    return
        if isinstance(state, dict):

            spec = state.get("_spec")
            prereleases = state.get("_prereleases", "invalid")
            if _validate_spec(spec) and _validate_pre(prereleases):
                self._spec = spec
                self._prereleases = prereleases
                return

        raise TypeError(f"Cannot restore Specifier from {state!r}")

    @property
    def operator(self) -> str:
        return self._spec[0]

    @property
    def version(self) -> str:
        return self._spec[1]

    def __repr__(self) -> str:
        pre = (
            f", prereleases={self.prereleases!r}"
            if self._prereleases is not None
            else ""
        )

        return f"<{self.__class__.__name__}({str(self)!r}{pre})>"

    def __str__(self) -> str:
        return "{}{}".format(*self._spec)

    @property
    def _canonical_spec(self) -> tuple[str, str]:
        operator, version = self._spec
        if operator == "===" or version.endswith(".*"):
            return operator, version

        spec_version = self._require_spec_version(version)

        canonical_version = canonicalize_version(
            spec_version, strip_trailing_zero=(operator != "~=")
        )

        return operator, canonical_version

    def __hash__(self) -> int:
        return hash(self._canonical_spec)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            try:
                other = self.__class__(str(other))
            except InvalidSpecifier:
                return NotImplemented
        elif not isinstance(other, self.__class__):
            return NotImplemented

        return self._canonical_spec == other._canonical_spec

    def _get_operator(self, op: str) -> CallableOperator:
        operator_callable: CallableOperator = getattr(
            self, f"_compare_{self._operators[op]}"
        )
        return operator_callable

    def _compare_compatible(self, prospective: Version, spec: str) -> bool:


        prefix = _version_join(
            list(itertools.takewhile(_is_not_suffix, _version_split(spec)))[:-1]
        )


        prefix += ".*"

        return (self._compare_greater_than_equal(prospective, spec)) and (
            self._compare_equal(prospective, prefix)
        )

    def _get_wildcard_split(self, spec: str) -> tuple[list[str], int]:
        wildcard_split = self._wildcard_split
        if wildcard_split is None:
            normalized = canonicalize_version(spec[:-2], strip_trailing_zero=False)
            split_spec = _version_split(normalized)
            wildcard_split = (split_spec, _numeric_prefix_len(split_spec))
            self._wildcard_split = wildcard_split
        return wildcard_split

    def _compare_equal(self, prospective: Version, spec: str) -> bool:

        if spec.endswith(".*"):
            split_spec, spec_numeric_len = self._get_wildcard_split(spec)


            normalized_prospective = canonicalize_version(
                _public_version(prospective), strip_trailing_zero=False
            )


            split_prospective = _version_split(normalized_prospective)


            padded_prospective = _left_pad(split_prospective, spec_numeric_len)


            shortened_prospective = padded_prospective[: len(split_spec)]

            return shortened_prospective == split_spec
        else:

            spec_version = self._require_spec_version(spec)


            if not spec_version.local:
                prospective = _public_version(prospective)

            return prospective == spec_version

    def _compare_not_equal(self, prospective: Version, spec: str) -> bool:
        return not self._compare_equal(prospective, spec)

    def _compare_less_than_equal(self, prospective: Version, spec: str) -> bool:


        return _public_version(prospective) <= self._require_spec_version(spec)

    def _compare_greater_than_equal(self, prospective: Version, spec: str) -> bool:


        return _public_version(prospective) >= self._require_spec_version(spec)

    def _compare_less_than(self, prospective: Version, spec_str: str) -> bool:


        spec = self._require_spec_version(spec_str)


        if not prospective < spec:
            return False


        if (
            not spec.is_prerelease
            and prospective.is_prerelease
            and prospective >= _earliest_prerelease(spec)
        ):
            return False


        return True

    def _compare_greater_than(self, prospective: Version, spec_str: str) -> bool:


        spec = self._require_spec_version(spec_str)


        if not prospective > spec:
            return False


        if (
            not spec.is_postrelease
            and prospective.is_postrelease
            and _post_base(prospective) == spec
        ):
            return False


        if prospective.local is not None and _public_version(prospective) == spec:
            return False


        return True

    def _compare_arbitrary(self, prospective: Version | str, spec: str) -> bool:
        return str(prospective).lower() == str(spec).lower()

    def __contains__(self, item: str | Version) -> bool:
        return self.contains(item)

    def contains(self, item: UnparsedVersion, prereleases: bool | None = None) -> bool:

        return bool(list(self.filter([item], prereleases=prereleases)))

    @typing.overload
    def filter(
        self,
        iterable: Iterable[UnparsedVersionVar],
        prereleases: bool | None = None,
        key: None = ...,
    ) -> Iterator[UnparsedVersionVar]: ...

    @typing.overload
    def filter(
        self,
        iterable: Iterable[T],
        prereleases: bool | None = None,
        key: Callable[[T], UnparsedVersion] = ...,
    ) -> Iterator[T]: ...

    def filter(
        self,
        iterable: Iterable[Any],
        prereleases: bool | None = None,
        key: Callable[[Any], UnparsedVersion] | None = None,
    ) -> Iterator[Any]:
        prereleases_versions = []
        found_non_prereleases = False


        include_prereleases = (
            prereleases if prereleases is not None else self.prereleases
        )


        operator_callable = self._get_operator(self.operator)


        for version in iterable:
            parsed_version = _coerce_version(version if key is None else key(version))
            match = False
            if parsed_version is None:

                if self.operator == "===" and self._compare_arbitrary(
                    version, self.version
                ):
                    yield version
            elif self.operator == "===":
                match = self._compare_arbitrary(
                    version if key is None else key(version), self.version
                )
            else:
                match = operator_callable(parsed_version, self.version)

            if match and parsed_version is not None:

                if not parsed_version.is_prerelease or include_prereleases:
                    found_non_prereleases = True
                    yield version

                elif prereleases is None and self._prereleases is not False:
                    prereleases_versions.append(version)


        if (
            not found_non_prereleases
            and prereleases is None
            and self._prereleases is not False
        ):
            yield from prereleases_versions


_prefix_regex = re.compile(r"([0-9]+)((?:a|b|c|rc)[0-9]+)")


def _pep440_filter_prereleases(
    iterable: Iterable[Any], key: Callable[[Any], UnparsedVersion] | None
) -> Iterator[Any]:


    all_nonfinal: list[Any] = []
    arbitrary_strings: list[Any] = []

    found_final = False
    for item in iterable:
        parsed = _coerce_version(item if key is None else key(item))

        if parsed is None:


            if found_final:
                yield item
            else:
                arbitrary_strings.append(item)
                all_nonfinal.append(item)
            continue

        if not parsed.is_prerelease:

            if not found_final:
                yield from arbitrary_strings
                found_final = True
            yield item
            continue


        if not found_final:
            all_nonfinal.append(item)


    if not found_final:
        yield from all_nonfinal


def _version_split(version: str) -> list[str]:
    result: list[str] = []

    epoch, _, rest = version.rpartition("!")
    result.append(epoch or "0")

    for item in rest.split("."):
        match = _prefix_regex.fullmatch(item)
        if match:
            result.extend(match.groups())
        else:
            result.append(item)
    return result


def _version_join(components: list[str]) -> str:
    epoch, *rest = components
    return f"{epoch}!{'.'.join(rest)}"


def _is_not_suffix(segment: str) -> bool:
    return not any(
        segment.startswith(prefix) for prefix in ("dev", "a", "b", "rc", "post")
    )


def _numeric_prefix_len(split: list[str]) -> int:
    count = 0
    for segment in split:
        if not segment.isdigit():
            break
        count += 1
    return count


def _left_pad(split: list[str], target_numeric_len: int) -> list[str]:
    numeric_len = _numeric_prefix_len(split)
    pad_needed = target_numeric_len - numeric_len
    if pad_needed <= 0:
        return split
    return [*split[:numeric_len], *(["0"] * pad_needed), *split[numeric_len:]]


def _operator_cost(op_entry: tuple[CallableOperator, str, str]) -> int:
    _, ver, op = op_entry
    if op == "==":
        return 0 if not ver.endswith(".*") else 2
    if op in (">=", "<=", ">", "<"):
        return 1
    if op == "~=":
        return 2
    if op == "!=":
        return 3 if not ver.endswith(".*") else 4
    if op == "===":
        return 0

    raise ValueError(f"Unknown operator: {op!r}")


class SpecifierSet(BaseSpecifier):

    __slots__ = (
        "_canonicalized",
        "_has_arbitrary",
        "_is_unsatisfiable",
        "_prereleases",
        "_resolved_ops",
        "_specs",
    )

    def __init__(
        self,
        specifiers: str | Iterable[Specifier] = "",
        prereleases: bool | None = None,
    ) -> None:

        if isinstance(specifiers, str):


            split_specifiers = [s.strip() for s in specifiers.split(",") if s.strip()]

            self._specs: tuple[Specifier, ...] = tuple(map(Specifier, split_specifiers))

            self._has_arbitrary = "===" in specifiers
        else:
            self._specs = tuple(specifiers)


            self._has_arbitrary = any("===" in str(s) for s in self._specs)

        self._canonicalized = len(self._specs) <= 1
        self._resolved_ops: list[tuple[CallableOperator, str, str]] | None = None


        self._prereleases = prereleases

        self._is_unsatisfiable: bool | None = None

    def _canonical_specs(self) -> tuple[Specifier, ...]:
        if not self._canonicalized:
            self._specs = tuple(dict.fromkeys(sorted(self._specs, key=str)))
            self._canonicalized = True
            self._resolved_ops = None
            self._is_unsatisfiable = None
        return self._specs

    @property
    def prereleases(self) -> bool | None:


        if self._prereleases is not None:
            return self._prereleases


        if not self._specs:
            return None


        if any(s.prereleases for s in self._specs):
            return True

        return None

    @prereleases.setter
    def prereleases(self, value: bool | None) -> None:
        self._prereleases = value
        self._is_unsatisfiable = None

    def __getstate__(self) -> tuple[tuple[Specifier, ...], bool | None]:


        return (self._specs, self._prereleases)

    def __setstate__(self, state: object) -> None:

        self._resolved_ops = None
        self._is_unsatisfiable = None

        if isinstance(state, tuple):
            if len(state) == 2:

                specs, prereleases = state
                if (
                    isinstance(specs, tuple)
                    and all(isinstance(s, Specifier) for s in specs)
                    and _validate_pre(prereleases)
                ):
                    self._specs = specs
                    self._prereleases = prereleases
                    self._canonicalized = len(specs) <= 1
                    self._has_arbitrary = any("===" in str(s) for s in specs)
                    return
            if len(state) == 2 and isinstance(state[1], dict):

                _, slot_dict = state
                specs = slot_dict.get("_specs", ())
                prereleases = slot_dict.get("_prereleases")

                if isinstance(specs, frozenset):
                    specs = tuple(sorted(specs, key=str))
                if (
                    isinstance(specs, tuple)
                    and all(isinstance(s, Specifier) for s in specs)
                    and _validate_pre(prereleases)
                ):
                    self._specs = specs
                    self._prereleases = prereleases
                    self._canonicalized = len(self._specs) <= 1
                    self._has_arbitrary = any("===" in str(s) for s in self._specs)
                    return
        if isinstance(state, dict):

            specs = state.get("_specs", ())
            prereleases = state.get("_prereleases")

            if isinstance(specs, frozenset):
                specs = tuple(sorted(specs, key=str))
            if (
                isinstance(specs, tuple)
                and all(isinstance(s, Specifier) for s in specs)
                and _validate_pre(prereleases)
            ):
                self._specs = specs
                self._prereleases = prereleases
                self._canonicalized = len(self._specs) <= 1
                self._has_arbitrary = any("===" in str(s) for s in self._specs)
                return

        raise TypeError(f"Cannot restore SpecifierSet from {state!r}")

    def __repr__(self) -> str:
        pre = (
            f", prereleases={self.prereleases!r}"
            if self._prereleases is not None
            else ""
        )

        return f"<{self.__class__.__name__}({str(self)!r}{pre})>"

    def __str__(self) -> str:
        return ",".join(str(s) for s in self._canonical_specs())

    def __hash__(self) -> int:
        return hash(self._canonical_specs())

    def __and__(self, other: SpecifierSet | str) -> SpecifierSet:
        if isinstance(other, str):
            other = SpecifierSet(other)
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        specifier = SpecifierSet()
        specifier._specs = self._specs + other._specs
        specifier._canonicalized = len(specifier._specs) <= 1
        specifier._has_arbitrary = self._has_arbitrary or other._has_arbitrary
        specifier._resolved_ops = None


        if self._prereleases is None or self._prereleases == other._prereleases:
            specifier._prereleases = other._prereleases
        elif other._prereleases is None:
            specifier._prereleases = self._prereleases
        else:
            raise ValueError(
                "Cannot combine SpecifierSets with True and False prerelease overrides."
            )

        return specifier

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (str, Specifier)):
            other = SpecifierSet(str(other))
        elif not isinstance(other, SpecifierSet):
            return NotImplemented

        return self._canonical_specs() == other._canonical_specs()

    def __len__(self) -> int:
        return len(self._specs)

    def __iter__(self) -> Iterator[Specifier]:
        return iter(self._specs)

    def _get_ranges(self) -> Sequence[_VersionRange]:
        specs = self._specs

        result: Sequence[_VersionRange] | None = None
        for s in specs:
            if result is None:
                result = s._to_ranges()
            else:
                result = _intersect_ranges(result, s._to_ranges())
                if not result:
                    break

        if result is None:
            raise RuntimeError("_get_ranges called with no specs")
        return result

    def is_unsatisfiable(self) -> bool:
        cached = self._is_unsatisfiable
        if cached is not None:
            return cached

        if not self._specs:
            self._is_unsatisfiable = False
            return False

        result = not self._get_ranges()

        if not result:
            result = self._check_arbitrary_unsatisfiable()

        if not result and self.prereleases is False:
            result = self._check_prerelease_only_ranges()

        self._is_unsatisfiable = result
        return result

    def _check_prerelease_only_ranges(self) -> bool:
        for lower, upper in self._get_ranges():
            nearest = _nearest_non_prerelease(lower.version)
            if nearest is None:
                return False
            if upper.version is None or nearest < upper.version:
                return False
            if nearest == upper.version and upper.inclusive:
                return False
        return True

    def _check_arbitrary_unsatisfiable(self) -> bool:
        arbitrary = [s for s in self._specs if s.operator == "==="]
        if not arbitrary:
            return False


        first = arbitrary[0].version.lower()
        if any(s.version.lower() != first for s in arbitrary[1:]):
            return True


        candidate = _coerce_version(arbitrary[0].version)


        if (
            self.prereleases is False
            and candidate is not None
            and candidate.is_prerelease
        ):
            return True

        standard = [s for s in self._specs if s.operator != "==="]
        if not standard:
            return False

        if candidate is None:

            return True

        return not all(s.contains(candidate) for s in standard)

    def __contains__(self, item: UnparsedVersion) -> bool:
        return self.contains(item)

    def contains(
        self,
        item: UnparsedVersion,
        prereleases: bool | None = None,
        installed: bool | None = None,
    ) -> bool:
        version = _coerce_version(item)

        if version is not None and installed and version.is_prerelease:
            prereleases = True


        if version is None or (self._has_arbitrary and not isinstance(item, Version)):
            check_item = item
        else:
            check_item = version
        return bool(list(self.filter([check_item], prereleases=prereleases)))

    @typing.overload
    def filter(
        self,
        iterable: Iterable[UnparsedVersionVar],
        prereleases: bool | None = None,
        key: None = ...,
    ) -> Iterator[UnparsedVersionVar]: ...

    @typing.overload
    def filter(
        self,
        iterable: Iterable[T],
        prereleases: bool | None = None,
        key: Callable[[T], UnparsedVersion] = ...,
    ) -> Iterator[T]: ...

    def filter(
        self,
        iterable: Iterable[Any],
        prereleases: bool | None = None,
        key: Callable[[Any], UnparsedVersion] | None = None,
    ) -> Iterator[Any]:


        if prereleases is None and self.prereleases is not None:
            prereleases = self.prereleases


        if self._specs:


            if len(self._specs) == 1:
                filtered = self._specs[0].filter(
                    iterable,
                    prereleases=True if prereleases is None else prereleases,
                    key=key,
                )
            else:
                filtered = self._filter_versions(
                    iterable,
                    key,
                    prereleases=True if prereleases is None else prereleases,
                )

            if prereleases is not None:
                return filtered

            return _pep440_filter_prereleases(filtered, key)


        if prereleases is True:
            return iter(iterable)

        if prereleases is False:
            return (
                item
                for item in iterable
                if (
                    (version := _coerce_version(item if key is None else key(item)))
                    is None
                    or not version.is_prerelease
                )
            )


        return _pep440_filter_prereleases(iterable, key)

    def _filter_versions(
        self,
        iterable: Iterable[Any],
        key: Callable[[Any], UnparsedVersion] | None,
        prereleases: bool | None = None,
    ) -> Iterator[Any]:

        if self._resolved_ops is None:
            self._resolved_ops = sorted(
                (
                    (spec._get_operator(spec.operator), spec.version, spec.operator)
                    for spec in self._specs
                ),
                key=_operator_cost,
            )
        ops = self._resolved_ops
        exclude_prereleases = prereleases is False

        for item in iterable:
            parsed = _coerce_version(item if key is None else key(item))

            if parsed is None:

                if all(
                    op == "===" and str(item).lower() == ver.lower()
                    for _, ver, op in ops
                ):
                    yield item
            elif exclude_prereleases and parsed.is_prerelease:
                pass
            elif all(
                str(item if key is None else key(item)).lower() == ver.lower()
                if op == "==="
                else op_fn(parsed, ver)
                for op_fn, ver, op in ops
            ):

                yield item
