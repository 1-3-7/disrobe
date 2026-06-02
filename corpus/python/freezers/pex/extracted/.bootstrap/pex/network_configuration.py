# coding=utf-8


from __future__ import absolute_import

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class NetworkConfiguration(object):

    retries = attr.ib(default=5)
    resume_retries = attr.ib(default=3)
    timeout = attr.ib(default=15)
    proxy = attr.ib(default=None)
    cert = attr.ib(default=None)
    client_cert = attr.ib(default=None)

    @retries.validator
    @resume_retries.validator
    def _validate_gte_zero(self, attribute, value):
        if value < 0:
            raise ValueError(
                "The {} parameter should be >= 0; given: {}".format(attribute.name, value)
            )

    @timeout.validator
    def _validate_gt_zero(self, attribute, value):
        if value <= 0:
            raise ValueError(
                "The {} parameter should be > 0; given: {}".format(attribute.name, value)
            )
