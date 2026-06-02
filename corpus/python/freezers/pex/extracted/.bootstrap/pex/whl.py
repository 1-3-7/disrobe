

from __future__ import absolute_import

import hashlib
import os

from pex.atomic_directory import atomic_directory
from pex.cache.dirs import CacheDir
from pex.dist_metadata import Distribution
from pex.fingerprinted_distribution import FingerprintedDistribution
from pex.installed_wheel import InstalledWheel
from pex.pep_427 import repack
from pex.typing import TYPE_CHECKING
from pex.util import CacheHelper

if TYPE_CHECKING:
    from typing import Optional, Union


def repacked_whl(
    installed_wheel,
    fingerprint,
    distribution_name=None,
    use_system_time=False,
):
    # type: (...) -> FingerprintedDistribution

    installed_wheel = (
        installed_wheel
        if isinstance(installed_wheel, InstalledWheel)
        else InstalledWheel.load(installed_wheel)
    )

    repack_dir = CacheDir.REPACKED_WHEELS.path(fingerprint)
    with atomic_directory(target_dir=repack_dir) as atomic_dir:
        if not atomic_dir.is_finalized():
            whl = repack(
                installed_wheel=installed_wheel,
                dest_dir=atomic_dir.work_dir,


                override_wheel_file_name=distribution_name,
                use_system_time=use_system_time,
            )
            with open(os.path.join(atomic_dir.work_dir, "FINGERPRINT"), "w") as fp:
                fp.write(CacheHelper.hash(whl, hasher=hashlib.sha256))

    with open(os.path.join(repack_dir, "FINGERPRINT")) as fp:
        fingerprint = fp.read()

    return FingerprintedDistribution(
        distribution=Distribution.load(
            os.path.join(repack_dir, distribution_name or installed_wheel.wheel_file_name())
        ),
        fingerprint=fingerprint,
    )
