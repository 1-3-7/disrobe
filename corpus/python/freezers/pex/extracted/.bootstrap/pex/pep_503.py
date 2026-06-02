

from __future__ import absolute_import

import re

from pex.third_party.packaging.utils import canonicalize_name
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Text

    import attr
else:
    from pex.third_party import attr


def _ensure_ascii_str(text):
    # type: (Text) -> str


    return str(text)


@attr.s(frozen=True)
class ProjectName(object):

    class InvalidError(ValueError):


    _VALID_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)

    raw = attr.ib(eq=False, converter=_ensure_ascii_str)
    validated = attr.ib(eq=False, default=False)
    normalized = attr.ib(init=False)

    def __attrs_post_init__(self):
        if self.validated and not self._VALID_RE.match(self.raw):
            raise self.InvalidError(
                "The given project name {value!r} is not a valid. It must conform to the regex "
                "{pattern!r} as specified in https://peps.python.org/pep-0508/#names".format(
                    value=self.raw, pattern=self._VALID_RE.pattern
                )
            )
        object.__setattr__(self, "normalized", canonicalize_name(self.raw))

    def __str__(self):
        # type: () -> str
        return self.normalized
