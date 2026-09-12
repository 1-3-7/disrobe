

from __future__ import absolute_import

from pex.dist_metadata import Requirement
from pex.pep_503 import ProjectName
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import FrozenSet

    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class RequirementKey(object):
    @classmethod
    def create(cls, requirement):
        # type: (Requirement) -> RequirementKey
        return cls(requirement.project_name, requirement.extras)

    project_name = attr.ib()
    extras = attr.ib()

    def satisfies(self, requested):
        # type: (RequirementKey) -> bool


        return self.project_name == requested.project_name and requested.extras <= self.extras
