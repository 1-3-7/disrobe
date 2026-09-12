

from __future__ import absolute_import

import functools

from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Any, Optional, Text, Union

    import attr
    from packaging import utils as packaging_utils
    from packaging import version as packaging_version
    from packaging.version import InvalidVersion

    ParsedVersion = Union[packaging_version.LegacyVersion, packaging_version.Version]
else:
    from pex.third_party import attr
    from pex.third_party.packaging import utils as packaging_utils
    from pex.third_party.packaging import version as packaging_version
    from pex.third_party.packaging.version import InvalidVersion


def _ensure_ascii_str(text):
    # type: (Text) -> str


    return str(text)


@functools.total_ordering
@attr.s(frozen=True, order=False)
class Version(object):

    raw = attr.ib(eq=False, converter=_ensure_ascii_str)
    normalized = attr.ib(init=False)
    _parsed_version = attr.ib(
        default=None, init=False, eq=False, repr=False
    )

    def __attrs_post_init__(self):
        # type: () -> None


        object.__setattr__(
            self,
            "normalized",
            cast(str, packaging_utils.canonicalize_version(self.raw)).replace("-", "_"),
        )

    @property
    def parsed_version(self):
        # type: () -> ParsedVersion
        if self._parsed_version is not None:
            return self._parsed_version

        parsed_version = packaging_version.parse(self.raw)
        object.__setattr__(self, "_parsed_version", parsed_version)
        return parsed_version

    def __lt__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, Version):
            return NotImplemented
        return self.parsed_version < other.parsed_version

    def __ge__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, Version):
            return NotImplemented
        return self.parsed_version >= other.parsed_version

    @property
    def is_legacy(self):
        # type: () -> bool
        try:
            return self.parsed_version is None
        except InvalidVersion:
            return True

    def __str__(self):
        # type: () -> str
        return self.normalized
