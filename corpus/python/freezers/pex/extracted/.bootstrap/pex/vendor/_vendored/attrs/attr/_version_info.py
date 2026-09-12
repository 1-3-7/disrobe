

from __future__ import absolute_import, division, print_function

from functools import total_ordering

from ._funcs import astuple
from ._make import attrib, attrs


@total_ordering
@attrs(eq=False, order=False, slots=True, frozen=True)
class VersionInfo(object):

    year = attrib(type=int)
    minor = attrib(type=int)
    micro = attrib(type=int)
    releaselevel = attrib(type=str)

    @classmethod
    def _from_version_string(cls, s):
        v = s.split(".")
        if len(v) == 3:
            v.append("final")

        return cls(
            year=int(v[0]), minor=int(v[1]), micro=int(v[2]), releaselevel=v[3]
        )

    def _ensure_tuple(self, other):

        if self.__class__ is other.__class__:
            other = astuple(other)

        if not isinstance(other, tuple):
            raise NotImplementedError

        if not (1 <= len(other) <= 4):
            raise NotImplementedError

        return astuple(self)[: len(other)], other

    def __eq__(self, other):
        try:
            us, them = self._ensure_tuple(other)
        except NotImplementedError:
            return NotImplemented

        return us == them

    def __lt__(self, other):
        try:
            us, them = self._ensure_tuple(other)
        except NotImplementedError:
            return NotImplemented


        return us < them
