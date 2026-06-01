

from __future__ import annotations

import re
import sys
import typing
from typing import (
    Any,
    Callable,
    Literal,
    NamedTuple,
    SupportsInt,
    Tuple,
    TypedDict,
    Union,
)

if typing.TYPE_CHECKING:
    from typing_extensions import Self, Unpack

if sys.version_info >= (3, 13):
    from warnings import deprecated as _deprecated
elif typing.TYPE_CHECKING:
    from typing_extensions import deprecated as _deprecated
else:
    import functools
    import warnings

    def _deprecated(message: str) -> object:
        def decorator(func: Callable[[...], object]) -> object:
            @functools.wraps(func)
            def wrapper(*args: object, **kwargs: object) -> object:
                warnings.warn(
                    message,
                    category=DeprecationWarning,
                    stacklevel=2,
                )
                return func(*args, **kwargs)

            return wrapper

        return decorator


_LETTER_NORMALIZATION = {
    "alpha": "a",
    "beta": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
    "rev": "post",
    "r": "post",
}

__all__ = ["VERSION_PATTERN", "InvalidVersion", "Version", "normalize_pre", "parse"]


def __dir__() -> list[str]:
    return __all__


LocalType = Tuple[Union[int, str], ...]

CmpLocalType = Tuple[Tuple[int, str], ...]
CmpSuffix = Tuple[int, int, int, int, int, int]
CmpKey = Union[
    Tuple[int, Tuple[int, ...], CmpSuffix],
    Tuple[int, Tuple[int, ...], CmpSuffix, CmpLocalType],
]
VersionComparisonMethod = Callable[[CmpKey, CmpKey], bool]


class _VersionReplace(TypedDict, total=False):
    epoch: int | None
    release: tuple[int, ...] | None
    pre: tuple[str, int] | None
    post: int | None
    dev: int | None
    local: str | None


def normalize_pre(letter: str, /) -> str:
    letter = letter.lower()
    return _LETTER_NORMALIZATION.get(letter, letter)


def parse(version: str) -> Version:
    return Version(version)


class InvalidVersion(ValueError):


class _BaseVersion:
    __slots__ = ()


    if typing.TYPE_CHECKING:

        @property
        def _key(self) -> tuple[Any, ...]: ...

    def __hash__(self) -> int:
        return hash(self._key)


    def __lt__(self, other: _BaseVersion) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key < other._key

    def __le__(self, other: _BaseVersion) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key <= other._key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key == other._key

    def __ge__(self, other: _BaseVersion) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key >= other._key

    def __gt__(self, other: _BaseVersion) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key > other._key

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return self._key != other._key


_VERSION_PATTERN = r"""
    v?+                                                   # optional leading v
    (?a:
        (?:(?P<epoch>[0-9]+)!)?+                          # epoch
        (?P<release>[0-9]+(?:\.[0-9]+)*+)                 # release segment
        (?P<pre>                                          # pre-release
            [._-]?+
            (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
            [._-]?+
            (?P<pre_n>[0-9]+)?
        )?+
        (?P<post>                                         # post release
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [._-]?
                (?P<post_l>post|rev|r)
                [._-]?
                (?P<post_n2>[0-9]+)?
            )
        )?+
        (?P<dev>                                          # dev release
            [._-]?+
            (?P<dev_l>dev)
            [._-]?+
            (?P<dev_n>[0-9]+)?
        )?+
    )
    (?a:\+
        (?P<local>                                        # local version
            [a-z0-9]+
            (?:[._-][a-z0-9]+)*+
        )
    )?+
"""

_VERSION_PATTERN_OLD = _VERSION_PATTERN.replace("*+", "*").replace("?+", "?")


VERSION_PATTERN = (
    _VERSION_PATTERN_OLD
    if (sys.implementation.name == "cpython" and sys.version_info < (3, 11, 5))
    or (sys.implementation.name == "pypy" and sys.version_info < (3, 11, 13))
    or sys.version_info < (3, 11)
    else _VERSION_PATTERN
)
"""
A string containing the regular expression used to match a valid version.

The pattern is not anchored at either end, and is intended for embedding in larger
expressions (for example, matching a version number as part of a file name). The
regular expression should be compiled with the ``re.VERBOSE`` and ``re.IGNORECASE``
flags set.

.. versionchanged:: 26.0

   The regex now uses possessive qualifiers on Python 3.11 if they are
   supported (CPython 3.11.5+, PyPy 3.11.13+).

:meta hide-value:
"""


_LOCAL_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", re.IGNORECASE | re.ASCII)


_SIMPLE_VERSION_INDICATORS = frozenset(".0123456789")


def _validate_epoch(value: object, /) -> int:
    epoch = value or 0
    if isinstance(epoch, int) and epoch >= 0:
        return epoch
    msg = f"epoch must be non-negative integer, got {epoch}"
    raise InvalidVersion(msg)


def _validate_release(value: object, /) -> tuple[int, ...]:
    release = (0,) if value is None else value
    if (
        isinstance(release, tuple)
        and len(release) > 0
        and all(isinstance(i, int) and i >= 0 for i in release)
    ):
        return release
    msg = f"release must be a non-empty tuple of non-negative integers, got {release}"
    raise InvalidVersion(msg)


def _validate_pre(value: object, /) -> tuple[Literal["a", "b", "rc"], int] | None:
    if value is None:
        return value
    if isinstance(value, tuple) and len(value) == 2:
        letter, number = value
        letter = normalize_pre(letter)
        if letter in {"a", "b", "rc"} and isinstance(number, int) and number >= 0:

            return (letter, number)
    msg = f"pre must be a tuple of ('a'|'b'|'rc', non-negative int), got {value}"
    raise InvalidVersion(msg)


def _validate_post(value: object, /) -> tuple[Literal["post"], int] | None:
    if value is None:
        return value
    if isinstance(value, int) and value >= 0:
        return ("post", value)
    msg = f"post must be non-negative integer, got {value}"
    raise InvalidVersion(msg)


def _validate_dev(value: object, /) -> tuple[Literal["dev"], int] | None:
    if value is None:
        return value
    if isinstance(value, int) and value >= 0:
        return ("dev", value)
    msg = f"dev must be non-negative integer, got {value}"
    raise InvalidVersion(msg)


def _validate_local(value: object, /) -> LocalType | None:
    if value is None:
        return value
    if isinstance(value, str) and _LOCAL_PATTERN.fullmatch(value):
        return _parse_local_version(value)
    msg = f"local must be a valid version string, got {value!r}"
    raise InvalidVersion(msg)


class _Version(NamedTuple):
    epoch: int
    release: tuple[int, ...]
    dev: tuple[Literal["dev"], int] | None
    pre: tuple[Literal["a", "b", "rc"], int] | None
    post: tuple[Literal["post"], int] | None
    local: LocalType | None


class Version(_BaseVersion):

    __slots__ = (
        "_dev",
        "_epoch",
        "_hash_cache",
        "_key_cache",
        "_local",
        "_post",
        "_pre",
        "_release",
    )
    __match_args__ = ("_str",)
    """
    Pattern matching is supported on Python 3.10+.

    .. versionadded:: 26.0

    :meta hide-value:
    """

    _regex = re.compile(r"\s*" + VERSION_PATTERN + r"\s*", re.VERBOSE | re.IGNORECASE)

    _epoch: int
    _release: tuple[int, ...]
    _dev: tuple[Literal["dev"], int] | None
    _pre: tuple[Literal["a", "b", "rc"], int] | None
    _post: tuple[Literal["post"], int] | None
    _local: LocalType | None

    _hash_cache: int | None
    _key_cache: CmpKey | None

    def __init__(self, version: str) -> None:
        if _SIMPLE_VERSION_INDICATORS.issuperset(version):
            try:
                self._release = tuple(map(int, version.split(".")))
            except ValueError:


                if "" in version.split("."):
                    raise InvalidVersion(f"Invalid version: {version!r}") from None

                raise

            self._epoch = 0
            self._pre = None
            self._post = None
            self._dev = None
            self._local = None
            self._key_cache = None
            self._hash_cache = None
            return


        match = self._regex.fullmatch(version)
        if not match:
            raise InvalidVersion(f"Invalid version: {version!r}")
        self._epoch = int(match.group("epoch")) if match.group("epoch") else 0
        self._release = tuple(map(int, match.group("release").split(".")))


        self._pre = _parse_letter_version(match.group("pre_l"), match.group("pre_n"))
        self._post = _parse_letter_version(
            match.group("post_l"), match.group("post_n1") or match.group("post_n2")
        )
        self._dev = _parse_letter_version(match.group("dev_l"), match.group("dev_n"))
        self._local = _parse_local_version(match.group("local"))


        self._key_cache = None
        self._hash_cache = None

    @classmethod
    def from_parts(
        cls,
        *,
        epoch: int = 0,
        release: tuple[int, ...],
        pre: tuple[str, int] | None = None,
        post: int | None = None,
        dev: int | None = None,
        local: str | None = None,
    ) -> Self:
        _epoch = _validate_epoch(epoch)
        _release = _validate_release(release)
        _pre = _validate_pre(pre) if pre is not None else None
        _post = _validate_post(post) if post is not None else None
        _dev = _validate_dev(dev) if dev is not None else None
        _local = _validate_local(local) if local is not None else None

        new_version = cls.__new__(cls)
        new_version._key_cache = None
        new_version._hash_cache = None
        new_version._epoch = _epoch
        new_version._release = _release
        new_version._pre = _pre
        new_version._post = _post
        new_version._dev = _dev
        new_version._local = _local

        return new_version

    def __replace__(self, **kwargs: Unpack[_VersionReplace]) -> Self:
        epoch = _validate_epoch(kwargs["epoch"]) if "epoch" in kwargs else self._epoch
        release = (
            _validate_release(kwargs["release"])
            if "release" in kwargs
            else self._release
        )
        pre = _validate_pre(kwargs["pre"]) if "pre" in kwargs else self._pre
        post = _validate_post(kwargs["post"]) if "post" in kwargs else self._post
        dev = _validate_dev(kwargs["dev"]) if "dev" in kwargs else self._dev
        local = _validate_local(kwargs["local"]) if "local" in kwargs else self._local

        if (
            epoch == self._epoch
            and release == self._release
            and pre == self._pre
            and post == self._post
            and dev == self._dev
            and local == self._local
        ):
            return self

        new_version = self.__class__.__new__(self.__class__)
        new_version._key_cache = None
        new_version._hash_cache = None
        new_version._epoch = epoch
        new_version._release = release
        new_version._pre = pre
        new_version._post = post
        new_version._dev = dev
        new_version._local = local

        return new_version

    @property
    def _key(self) -> CmpKey:
        if self._key_cache is None:
            self._key_cache = _cmpkey(
                self._epoch,
                self._release,
                self._pre,
                self._post,
                self._dev,
                self._local,
            )
        return self._key_cache


    def __hash__(self) -> int:
        if (cached_hash := self._hash_cache) is not None:
            return cached_hash

        if (key := self._key_cache) is None:
            self._key_cache = key = _cmpkey(
                self._epoch,
                self._release,
                self._pre,
                self._post,
                self._dev,
                self._local,
            )
        self._hash_cache = cached_hash = hash(key)
        return cached_hash


    def __lt__(self, other: _BaseVersion) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache < other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__lt__(other)

    def __le__(self, other: _BaseVersion) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache <= other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__le__(other)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache == other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__eq__(other)

    def __ge__(self, other: _BaseVersion) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache >= other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__ge__(other)

    def __gt__(self, other: _BaseVersion) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache > other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__gt__(other)

    def __ne__(self, other: object) -> bool:
        if isinstance(other, Version):
            if self._key_cache is None:
                self._key_cache = _cmpkey(
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                )
            if other._key_cache is None:
                other._key_cache = _cmpkey(
                    other._epoch,
                    other._release,
                    other._pre,
                    other._post,
                    other._dev,
                    other._local,
                )
            return self._key_cache != other._key_cache

        if not isinstance(other, _BaseVersion):
            return NotImplemented

        return super().__ne__(other)

    def __getstate__(
        self,
    ) -> tuple[
        int,
        tuple[int, ...],
        tuple[str, int] | None,
        tuple[str, int] | None,
        tuple[str, int] | None,
        LocalType | None,
    ]:


        return (
            self._epoch,
            self._release,
            self._pre,
            self._post,
            self._dev,
            self._local,
        )

    def __setstate__(self, state: object) -> None:


        self._key_cache = None
        self._hash_cache = None

        if isinstance(state, tuple):
            if len(state) == 6:

                (
                    self._epoch,
                    self._release,
                    self._pre,
                    self._post,
                    self._dev,
                    self._local,
                ) = state
                return
            if len(state) == 2:

                _, slot_dict = state
                if isinstance(slot_dict, dict):
                    self._epoch = slot_dict["_epoch"]
                    self._release = slot_dict["_release"]
                    self._pre = slot_dict.get("_pre")
                    self._post = slot_dict.get("_post")
                    self._dev = slot_dict.get("_dev")
                    self._local = slot_dict.get("_local")
                    return
        if isinstance(state, dict):


            version_nt = state.get("_version")
            if version_nt is not None:
                self._epoch = version_nt.epoch
                self._release = version_nt.release
                self._pre = version_nt.pre
                self._post = version_nt.post
                self._dev = version_nt.dev
                self._local = version_nt.local
                return

        raise TypeError(f"Cannot restore Version from {state!r}")

    @property
    @_deprecated("Version._version is private and will be removed soon")
    def _version(self) -> _Version:
        return _Version(
            self._epoch, self._release, self._dev, self._pre, self._post, self._local
        )

    @_version.setter
    @_deprecated("Version._version is private and will be removed soon")
    def _version(self, value: _Version) -> None:
        self._epoch = value.epoch
        self._release = value.release
        self._dev = value.dev
        self._pre = value.pre
        self._post = value.post
        self._local = value.local
        self._key_cache = None
        self._hash_cache = None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({str(self)!r})>"

    def __str__(self) -> str:

        version = ".".join(map(str, self.release))


        if self.epoch:
            version = f"{self.epoch}!{version}"


        if self.pre is not None:
            version += "".join(map(str, self.pre))


        if self.post is not None:
            version += f".post{self.post}"


        if self.dev is not None:
            version += f".dev{self.dev}"


        if self.local is not None:
            version += f"+{self.local}"

        return version

    @property
    def _str(self) -> str:
        return str(self)

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def release(self) -> tuple[int, ...]:
        return self._release

    @property
    def pre(self) -> tuple[Literal["a", "b", "rc"], int] | None:
        return self._pre

    @property
    def post(self) -> int | None:
        return self._post[1] if self._post else None

    @property
    def dev(self) -> int | None:
        return self._dev[1] if self._dev else None

    @property
    def local(self) -> str | None:
        if self._local:
            return ".".join(str(x) for x in self._local)
        else:
            return None

    @property
    def public(self) -> str:
        return str(self).split("+", 1)[0]

    @property
    def base_version(self) -> str:
        release_segment = ".".join(map(str, self.release))
        return f"{self.epoch}!{release_segment}" if self.epoch else release_segment

    @property
    def is_prerelease(self) -> bool:
        return self.dev is not None or self.pre is not None

    @property
    def is_postrelease(self) -> bool:
        return self.post is not None

    @property
    def is_devrelease(self) -> bool:
        return self.dev is not None

    @property
    def major(self) -> int:
        return self.release[0] if len(self.release) >= 1 else 0

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) >= 2 else 0

    @property
    def micro(self) -> int:
        return self.release[2] if len(self.release) >= 3 else 0


class _TrimmedRelease(Version):
    __slots__ = ()

    def __init__(self, version: str | Version) -> None:
        if isinstance(version, Version):
            self._epoch = version._epoch
            self._release = version._release
            self._dev = version._dev
            self._pre = version._pre
            self._post = version._post
            self._local = version._local
            self._key_cache = version._key_cache
            return
        super().__init__(version)

    @property
    def release(self) -> tuple[int, ...]:

        rel = super().release
        len_release = len(rel)
        i = len_release
        while i > 1 and rel[i - 1] == 0:
            i -= 1
        return rel if i == len_release else rel[:i]


def _parse_letter_version(
    letter: str | None, number: str | bytes | SupportsInt | None
) -> tuple[str, int] | None:
    if letter:

        letter = letter.lower()


        letter = _LETTER_NORMALIZATION.get(letter, letter)


        return letter, int(number or 0)

    if number:


        return "post", int(number)

    return None


_local_version_separators = re.compile(r"[\._-]")


def _parse_local_version(local: str | None) -> LocalType | None:
    if local is not None:
        return tuple(
            part.lower() if not part.isdigit() else int(part)
            for part in _local_version_separators.split(local)
        )
    return None


_PRE_RANK = {"a": 0, "b": 1, "rc": 2}
_PRE_RANK_DEV_ONLY = -1
_PRE_RANK_STABLE = 3


_LOCAL_STR_RANK = -1


_STABLE_SUFFIX = (_PRE_RANK_STABLE, 0, 0, 0, 1, 0)


def _cmpkey(
    epoch: int,
    release: tuple[int, ...],
    pre: tuple[str, int] | None,
    post: tuple[str, int] | None,
    dev: tuple[str, int] | None,
    local: LocalType | None,
) -> CmpKey:

    len_release = len(release)
    i = len_release
    while i and release[i - 1] == 0:
        i -= 1
    trimmed = release if i == len_release else release[:i]


    if pre is None and post is None and dev is None and local is None:
        return epoch, trimmed, _STABLE_SUFFIX

    if pre is None and post is None and dev is not None:

        pre_rank, pre_n = _PRE_RANK_DEV_ONLY, 0
    elif pre is None:
        pre_rank, pre_n = _PRE_RANK_STABLE, 0
    else:
        pre_rank, pre_n = _PRE_RANK[pre[0]], pre[1]

    post_rank = 0 if post is None else 1
    post_n = 0 if post is None else post[1]

    dev_rank = 1 if dev is None else 0
    dev_n = 0 if dev is None else dev[1]

    suffix = (pre_rank, pre_n, post_rank, post_n, dev_rank, dev_n)

    if local is None:
        return epoch, trimmed, suffix

    cmp_local: CmpLocalType = tuple(
        (seg, "") if isinstance(seg, int) else (_LOCAL_STR_RANK, seg) for seg in local
    )
    return epoch, trimmed, suffix, cmp_local
