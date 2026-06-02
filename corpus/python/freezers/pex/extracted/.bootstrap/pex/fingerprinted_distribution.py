

from __future__ import absolute_import

from pex.dist_metadata import Distribution
from pex.pep_503 import ProjectName
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class FingerprintedDistribution(object):
    distribution = attr.ib()
    fingerprint = attr.ib()

    @property
    def location(self):
        # type: () -> str
        return self.distribution.location

    @property
    def project_name(self):
        # type: () -> ProjectName
        return self.distribution.metadata.project_name
